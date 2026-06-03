//! Bridge-verification family (second wave, T2-only): `BridgeVerification`.
//!
//! A forged-message acceptance test. The protocol's message struct isn't in the
//! IR, so this is a compiling skeleton: it pranks an attacker submitting an
//! unverified message and asserts the call did NOT revert (a proper verifier
//! would reject it) — the `/* FILL */` is the message encoding the user supplies.

use super::{header, PocTemplate};
use crate::context::{PocContext, Tier};
use sluice_findings::Category;

pub struct BridgeTemplate;

impl PocTemplate for BridgeTemplate {
    fn applies(&self, cat: Category) -> bool {
        matches!(cat, Category::BridgeVerification)
    }

    fn tier(&self, _cx: &PocContext) -> Tier {
        Tier::T2
    }

    fn render(&self, cx: &PocContext) -> String {
        let tier = self.tier(cx);
        let mut s = header(cx, tier);

        let target = &cx.contract_ident;
        let func = &cx.function_ident;
        let call_args = cx.call_args_str();

        let ctor = format!(
            "        // {ctor_comment}\n        target = new {target}({ctor_args});",
            ctor_comment = cx.ctor_comment(),
            ctor_args = cx.ctor_args_str(),
        );

        s.push_str(&format!(
            "contract {target}_bridge_verification_PoC is Test {{\n\
             \x20   {target} target;\n\
             \x20   address attacker = makeAddr(\"attacker\");\n\n\
             \x20   function setUp() public {{\n\
             {ctor}\n\
             \x20   }}\n\n\
             \x20   /// A forged / unverified message is accepted by `{target}.{func}`.\n\
             \x20   function test_forged_message_accepted() public {{\n\
             \x20       // FILL: construct an unverified message the real verifier should reject\n\
             \x20       // (the protocol's message struct / proof is not in the IR).\n\
             \x20       vm.prank(attacker);\n\
             \x20       target.{func}({call_args});   // a sound verifier would revert here — it does NOT\n\
             \x20       // EXPLOIT HYPOTHESIS: the message was processed without valid proof/quorum.\n\
             \x20       // FILL: assert the spoofed effect (minted/released funds, marked-processed root).\n\
             \x20   }}\n\
             }}\n",
        ));

        s
    }
}
