//! Access-control family (family 2): `AccessControl` / `UnprotectedInitializer`
//! / `TxOriginAuth`.
//!
//! The most mechanical family: usually no attacker contract, no mocks. We
//! `vm.prank(attacker)` an unprivileged address, call the flagged function with
//! typed args, and assert the privileged var changed (when it's publicly
//! readable) — the absence of a revert under the prank is itself the proof that
//! no guard fired.

use super::{header, PocTemplate};
use crate::context::{PocContext, Tier};
use sluice_findings::Category;

pub struct AccessControlTemplate;

impl PocTemplate for AccessControlTemplate {
    fn applies(&self, cat: Category) -> bool {
        matches!(
            cat,
            Category::AccessControl | Category::UnprotectedInitializer | Category::TxOriginAuth
        )
    }

    fn tier(&self, cx: &PocContext) -> Tier {
        if cx.has_fill() {
            Tier::T2
        } else {
            Tier::T1
        }
    }

    fn render(&self, cx: &PocContext) -> String {
        let tier = self.tier(cx);
        let mut s = header(cx, tier);

        let target = &cx.contract_ident;
        let func = &cx.function_ident;
        let call_args = cx.call_args_str();
        let is_init = cx.finding.category == Category::UnprotectedInitializer;

        let priv_var = cx
            .privileged_var
            .clone()
            .or_else(|| cx.owner_var.clone())
            .unwrap_or_else(|| "the privileged state".to_string());

        // Assertion: if the privileged var is publicly readable AND the call's
        // first arg is what gets written (the common `setOwner(addr)` shape),
        // assert equality; otherwise the no-revert is the proof.
        let assert_block = if let (true, Some(pv)) =
            (cx.privileged_var_public, cx.privileged_var.as_ref())
        {
            let expected = first_address_arg(cx);
            match expected {
                Some(arg) => format!(
                    "        // `{pv}` is publicly readable — assert the unprivileged call mutated it.\n\
                     \x20       assertEq(target.{pv}(), {arg}, \"privileged var unchanged -> call had no effect / was guarded\");\n"
                ),
                None => format!(
                    "        // `{pv}` is publicly readable. Inspect it after the call: a guarded\n\
                     \x20       // function would have reverted on the prank above instead of reaching here.\n\
                     \x20       emit log_named_uint(\"post-call sentinel (no revert == unguarded)\", uint256(uint160(address(this))));\n"
                ),
            }
        } else {
            format!(
                "        // `{priv_var}` is not externally readable — the ABSENCE of a revert under the\n\
                 \x20       // prank above is itself the proof: a properly guarded function would have\n\
                 \x20       // reverted for a non-owner caller before reaching this line.\n"
            )
        };

        let ctor = format!(
            "        // {ctor_comment}\n        target = new {target}({ctor_args});",
            ctor_comment = cx.ctor_comment(),
            ctor_args = cx.ctor_args_str(),
        );

        // For unprotected initializers we additionally show a second call that a
        // re-init guard *should* have blocked.
        let extra = if is_init {
            format!(
                "\n        // An `initializer`-guarded function should revert on a second call;\n\
                 \x20       // its absence means the implementation can be (re-)initialized by anyone.\n\
                 \x20       vm.prank(attacker);\n\
                 \x20       target.{func}({call_args});\n"
            )
        } else {
            String::new()
        };

        s.push_str(&format!(
            "contract {target}_access_control_PoC is Test {{\n\
             \x20   {target} target;\n\
             \x20   address attacker = makeAddr(\"attacker\");   // NOT the owner / admin\n\n\
             \x20   function setUp() public {{\n\
             {ctor}\n\
             \x20   }}\n\n\
             \x20   /// An unprivileged caller reaches `{target}.{func}` and mutates `{priv_var}`.\n\
             \x20   function test_unauthorized_can_call_{func}() public {{\n\
             \x20       vm.prank(attacker);\n\
             \x20       target.{func}({call_args});   // must revert if guarded — it does NOT\n\
             {assert_block}\
             {extra}\
             \x20   }}\n\
             }}\n",
        ));

        s
    }
}

/// The first `makeAddr(...)` address argument in the call list (the value most
/// `setX(addr)` privileged setters write), for an equality assertion.
fn first_address_arg(cx: &PocContext) -> Option<String> {
    cx.call_args
        .iter()
        .find(|a| a.literal.starts_with("makeAddr("))
        .map(|a| a.literal.clone())
}
