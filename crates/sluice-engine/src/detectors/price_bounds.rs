//! Chainlink-style price consumed without min/max sanity bounds: the
//! `minAnswer`/`maxAnswer` circuit-breaker class.
//!
//! Chainlink aggregators have a baked-in `minAnswer`/`maxAnswer` circuit breaker.
//! When the real market price moves outside that band, the feed does **not**
//! return the true price — it returns the clamped bound and keeps reporting it.
//! `latestRoundData()`/`latestAnswer()` still look perfectly "fresh" (a recent
//! `updatedAt`, a valid round), so a staleness check does *not* catch this. An
//! integration that trusts the clamped value misprices the asset at the pinned
//! floor/ceiling — the Venus/Blizz "LUNA → ~0, feed stuck at `minAnswer`"
//! collapse, and the broader bridge/lending class where a depegged or crashed
//! asset is valued at its frozen circuit-breaker bound.
//!
//! This is the *value-bounds* dual of `oracle_staleness.rs` (which covers
//! *freshness*). The two are orthogonal: a feed read can be fresh-checked yet
//! never bounded, or bounded yet never fresh-checked. A wholly-unchecked feed
//! legitimately trips both detectors.
//!
//! Safe pattern: after reading the feed, clamp the answer against the feed's own
//! aggregator bounds (or a configured band) and revert out-of-band, e.g.
//! ```solidity
//! (, int256 price, , , ) = feed.latestRoundData();
//! require(price > minAnswer && price < maxAnswer, "out of bounds");
//! ```
//! A bare `require(price > 0)` is only a *sign* check — it does **not** bound the
//! value and does not suppress this finding.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{ExprKind, Function, Lit};

pub struct PriceBoundsDetector;

/// Source substrings that evidence a min/max sanity bound on the answer. If any
/// appears in the function (or its surrounding contract) we assume the price is
/// validated against a band and suppress. `minanswer`/`maxanswer` are the
/// aggregator's own circuit-breaker bounds; the `min*`/`max*price`/`bound`/
/// `clamp` markers cover hand-rolled bands.
const BOUND_MARKERS: &[&str] = &[
    "minanswer",
    "maxanswer",
    "minprice",
    "maxprice",
    "min_price",
    "max_price",
    "lowerbound",
    "upperbound",
    "lower_bound",
    "upper_bound",
    "pricebound",
    "price_bound",
    "outofbound",
    "out_of_bound",
];

impl Detector for PriceBoundsDetector {
    fn id(&self) -> &'static str {
        "price-bounds"
    }
    fn category(&self) -> Category {
        Category::PriceBounds
    }
    fn description(&self) -> &'static str {
        "Chainlink price consumed without min/max sanity bounds (minAnswer/maxAnswer circuit-breaker)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // The feed read can sit in a `view` price-getter, so — like
            // `oracle_staleness` — we require only external reachability, not
            // state mutation.
            if !f.is_externally_reachable() {
                continue;
            }
            // Pure feed-interface declarations carry no consumer risk.
            if cx.contract_of(f.id).map(|c| c.is_interface()).unwrap_or(false) {
                continue;
            }

            let src = cx.scir.span_text(f.span).to_ascii_lowercase();

            // Must actually read a Chainlink-style robust feed.
            let uses_feed = src.contains("latestrounddata")
                || src.contains("latestanswer")
                || src.contains("getrounddata");
            if !uses_feed {
                continue;
            }

            // --- false-positive suppression (precision is the priority) ---
            // (1) A textual min/max-bound marker anywhere in the function or the
            //     surrounding contract (a shared `_sanityCheck`, a bounds
            //     library, the aggregator's `minAnswer`/`maxAnswer`).
            let has_marker = |text: &str| BOUND_MARKERS.iter().any(|m| text.contains(m));
            if has_marker(&src) {
                continue;
            }
            if let Some(c) = cx.contract_of(f.id) {
                let csrc = cx.scir.span_text(c.span).to_ascii_lowercase();
                if has_marker(&csrc) {
                    continue;
                }
            }
            // (2) A structural bounds check: an ordering comparison (`<`, `>`,
            //     `<=`, `>=`) against a *non-zero* operand. A bare `price > 0`
            //     is only a sign check and must NOT suppress; a comparison
            //     against a constant/variable bound does.
            if has_value_bound(f) {
                continue;
            }

            let b = FindingBuilder::new(self.id(), Category::PriceBounds)
                .title("Oracle price used without min/max sanity bounds")
                .severity(Severity::Medium)
                .confidence(0.5)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` consumes a Chainlink-style feed price but never bounds it against a \
                     min/max sanity band. Chainlink aggregators clamp to a built-in \
                     `minAnswer`/`maxAnswer` circuit breaker: if the real price moves outside that \
                     band the feed keeps returning the clamped bound (still `fresh`, so a staleness \
                     check does not catch it). A crashed or depegged asset is then valued at its \
                     frozen floor/ceiling — the Venus/BNB-bridge `minAnswer` collapse class.",
                    f.name
                ))
                .recommendation(
                    "After reading the feed, bound the answer and revert out-of-band, e.g. \
                     `require(price > minPrice && price < maxPrice)` using the aggregator's own \
                     `minAnswer`/`maxAnswer` (or a configured band). A `require(price > 0)` sign \
                     check is not sufficient.",
                );
            out.push(cx.finish(b, f.id, f.span));
        }
        out
    }
}

/// True if the function body contains an *ordering* comparison (`<`, `>`, `<=`,
/// `>=`) that looks like a real value bound: one operand is a price-like /
/// numeric name and the other side is **not** the literal `0`. A `price > 0`
/// sign check is therefore not counted; `price > minPrice`, `price < CAP`, or a
/// comparison against a state-variable bound is.
fn has_value_bound(f: &Function) -> bool {
    let mut bounded = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if bounded {
                return;
            }
            if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
                if op.is_ordering() {
                    // A bound is meaningful only if it compares against a
                    // non-zero operand on at least one side.
                    if !is_zero_literal(&lhs.kind) && !is_zero_literal(&rhs.kind) {
                        bounded = true;
                    }
                }
            }
        });
        if bounded {
            break;
        }
    }
    bounded
}

/// True if an expression kind is the numeric/hex literal `0`.
fn is_zero_literal(k: &ExprKind) -> bool {
    match k {
        ExprKind::Lit(Lit::Number(n)) | ExprKind::Lit(Lit::HexNumber(n)) => {
            let t = n.trim();
            t == "0" || t == "0x0" || t == "0x00" || t.trim_start_matches('0').is_empty()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: reads `latestRoundData()` and uses the price, with only a
    // `price > 0` sign check — never bounded against a min/max band, so a feed
    // clamped at its `minAnswer` circuit breaker is trusted.
    const VULN: &str = r#"
        interface AggregatorV3Interface {
            function latestRoundData()
                external view
                returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
        }
        contract LendingPool {
            AggregatorV3Interface internal feed;
            function collateralValue(uint256 amount) external view returns (uint256) {
                (, int256 price, , , ) = feed.latestRoundData();
                require(price > 0, "price");
                return amount * uint256(price);
            }
        }
    "#;

    // Safe: same feed, but the integration clamps the answer against the
    // aggregator's min/max circuit-breaker bounds before trusting it.
    const SAFE: &str = r#"
        interface AggregatorV3Interface {
            function latestRoundData()
                external view
                returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
        }
        contract LendingPool {
            AggregatorV3Interface internal feed;
            int256 internal minPrice;
            int256 internal maxPrice;
            function collateralValue(uint256 amount) external view returns (uint256) {
                (, int256 price, , , ) = feed.latestRoundData();
                require(price > 0, "price");
                require(price > minPrice && price < maxPrice, "out of bounds");
                return amount * uint256(price);
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "price-bounds"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "price-bounds"));
    }
}
