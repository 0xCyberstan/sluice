//! Oracle / price-manipulation family (second wave, T2-only):
//! `OracleManipulation` / `PriceManipulation` / `TwapManipulation` /
//! `BackingSpotInflation`.
//!
//! Pool address, decimals, and the flash-loan provider are unknowable
//! statically, so this is a compiling skeleton: it `vm.mockCall`s the exact spot
//! read method the detector found and asserts the over-valuation hypothesis the
//! user completes.

use super::{header, PocTemplate};
use crate::context::{PocContext, Tier};
use sluice_findings::Category;

pub struct OracleTemplate;

impl PocTemplate for OracleTemplate {
    fn applies(&self, cat: Category) -> bool {
        matches!(
            cat,
            Category::OracleManipulation
                | Category::PriceManipulation
                | Category::TwapManipulation
                | Category::BackingSpotInflation
        )
    }

    fn tier(&self, _cx: &PocContext) -> Tier {
        // Oracle PoCs cannot be T1 from static info (no pool address / decimals /
        // flash-loan provider) — always a compiling skeleton + asserted hypothesis.
        Tier::T2
    }

    fn render(&self, cx: &PocContext) -> String {
        let tier = self.tier(cx);
        let mut s = header(cx, tier);

        let target = &cx.contract_ident;
        let func = &cx.function_ident;
        let call_args = cx.call_args_str();
        let spot = cx.spot_method.clone().unwrap_or_else(|| "latestAnswer".to_string());

        let ctor = format!(
            "        // {ctor_comment}\n        target = new {target}({ctor_args});",
            ctor_comment = cx.ctor_comment(),
            ctor_args = cx.ctor_args_str(),
        );

        s.push_str(&format!(
            "contract {target}_oracle_manipulation_PoC is Test {{\n\
             \x20   {target} target;\n\
             \x20   address attacker = makeAddr(\"attacker\");\n\n\
             \x20   /// Move the spot source the detector flagged (`{spot}`) without a live pool.\n\
             \x20   function _setSpotPrice(uint256 p) internal {{\n\
             \x20       vm.mockCall(\n\
             \x20           /* FILL: address of the spot source the target reads */ address(0),\n\
             \x20           abi.encodeWithSignature(\"{spot}()\"),\n\
             \x20           abi.encode(p)\n\
             \x20       );\n\
             \x20   }}\n\n\
             \x20   function setUp() public {{\n\
             {ctor}\n\
             \x20   }}\n\n\
             \x20   function test_spot_price_skew_mints_at_false_valuation() public {{\n\
             \x20       uint256 fair = 1e18;\n\
             \x20       _setSpotPrice(fair);\n\
             \x20       // 1. (flash-loan elided) skew the spot source upward within the tx.\n\
             \x20       _setSpotPrice(fair * 100);\n\
             \x20       vm.prank(attacker);\n\
             \x20       target.{func}({call_args});   // values collateral/shares at the false price\n\
             \x20       // EXPLOIT HYPOTHESIS: the target credited/minted using the skewed price.\n\
             \x20       // FILL: assert the attacker over-borrowed / minted excess vs the fair baseline,\n\
             \x20       // e.g. assertGt(<attacker credited>, <fair-price expectation>, \"no over-valuation\");\n\
             \x20   }}\n\
             }}\n",
        ));

        s
    }
}
