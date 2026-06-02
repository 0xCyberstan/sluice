//! Spot-price oracle manipulation: a manipulable price (`balanceOf`,
//! `getReserves`, `pricePerShare`, ...) feeds protocol accounting with no robust
//! oracle / TWAP. The Cream / Harvest / bZx class.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::detectors::{find_spot_price, is_accounting_name};
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};

pub struct OracleDetector;

impl Detector for OracleDetector {
    fn id(&self) -> &'static str {
        "oracle-manipulation"
    }
    fn category(&self) -> Category {
        Category::OracleManipulation
    }
    fn description(&self) -> &'static str {
        "Manipulable spot price (balanceOf/getReserves/pricePerShare) used for value"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || !f.is_externally_reachable() {
                continue;
            }
            // Robust oracle present → suppress (Chainlink staleness is a separate class).
            if cx.uses_robust_oracle(f) {
                continue;
            }
            let Some(price_span) = find_spot_price(f) else {
                continue;
            };
            // The price must influence accounting: a write to an accounting var,
            // or the function mints/borrows/values something.
            let writes_accounting = f.effects.written_vars().iter().any(|v| is_accounting_name(v));
            let valuation_name = {
                let l = f.name.to_ascii_lowercase();
                l.contains("price")
                    || l.contains("value")
                    || l.contains("collateral")
                    || l.contains("mint")
                    || l.contains("borrow")
                    || l.contains("deposit")
                    || l.contains("redeem")
                    || l.contains("liquidat")
            };
            if !writes_accounting && !valuation_name {
                continue;
            }

            let b = FindingBuilder::new(self.id(), Category::OracleManipulation)
                .title("Manipulable spot price used for valuation")
                .severity(Severity::High)
                .confidence(0.55)
                .dimension(Dimension::ValueFlow)
                .dimension(Dimension::Frontier)
                .message(format!(
                    "`{}` derives a value from an instantaneous on-chain price (a `balanceOf` / \
                     `getReserves` / `pricePerShare`-style read). An attacker can move that source \
                     within one transaction (flash-loan-assisted) to mint, borrow, or liquidate at a \
                     false valuation — the Cream/Harvest/bZx class.",
                    f.name
                ))
                .recommendation(
                    "Price via a manipulation-resistant source: a Chainlink feed with staleness + \
                     deviation checks, or a sufficiently long TWAP; never a single spot reserve / \
                     `balanceOf`.",
                );
            out.push(cx.finish(b, f.id, price_span));
        }
        out
    }
}
