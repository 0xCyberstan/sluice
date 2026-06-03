//! L2 Sequencer uptime: a Chainlink price is consumed on an L2 (Arbitrum,
//! Optimism, Base, ...) without first checking the Chainlink **L2 Sequencer
//! Uptime Feed**.
//!
//! On an optimistic / centralized-sequencer L2, when the sequencer goes down
//! users cannot submit transactions through it, but the underlying Chainlink
//! price feed keeps its last answer with a fresh-looking `updatedAt`. A
//! staleness check alone therefore *passes* — the answer is recent — yet the
//! price is effectively frozen from before the outage. When the sequencer comes
//! back, a backlog of transactions executes against this stale price, which is a
//! known way to perform unfair liquidations or borrow against mispriced
//! collateral in the recovery window.
//!
//! Chainlink's recommended pattern reads the dedicated sequencer-uptime feed and
//! reverts if the sequencer is down or has only just recovered (within a
//! `GRACE_PERIOD`):
//! ```solidity
//! (, int256 answer, uint256 startedAt, , ) = sequencerUptimeFeed.latestRoundData();
//! require(answer == 0, "L2 sequencer down");                 // 1 == down
//! require(block.timestamp - startedAt > GRACE_PERIOD, "grace period not over");
//! // ... only now read and use the price feed ...
//! ```
//!
//! This detector is the L2-specific complement of `oracle_staleness.rs`. The
//! staleness detector fires on the missing freshness check; this one fires on a
//! Chainlink read that *shows L2 intent* (the contract mentions Arbitrum /
//! Optimism / Base / "sequencer" / "L2") yet performs no sequencer-uptime check.
//! Crucially, a contract with **no** L2 intent at all is out of scope here — that
//! is plain oracle-staleness territory, not a sequencer bug — so this detector
//! only fires when the L2 context is present but the sequencer guard is absent.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};

pub struct L2SequencerDetector;

/// Substrings that evidence the contract is intended to run on an L2 where a
/// Chainlink sequencer-uptime feed matters. The presence of any of these is what
/// distinguishes a sequencer bug from a generic oracle-staleness finding.
const L2_INTENT_MARKERS: &[&str] = &["arbitrum", "optimism", "base", "sequencer", "l2"];

/// Substrings that evidence the integration already consults the L2 sequencer
/// uptime feed (a `sequencerUptimeFeed` handle, or a `require` / guard mentioning
/// the sequencer, its uptime, or the recovery grace period). Any of these means
/// the safe pattern is present and we suppress.
const SEQUENCER_CHECK_MARKERS: &[&str] = &["sequenceruptimefeed", "uptime", "graceperiod", "grace_period"];

impl Detector for L2SequencerDetector {
    fn id(&self) -> &'static str {
        "l2-sequencer-uptime"
    }
    fn category(&self) -> Category {
        Category::SequencerUptime
    }
    fn description(&self) -> &'static str {
        "Chainlink price consumed on an L2 without checking the L2 Sequencer Uptime feed"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // The feed read commonly sits in a `view` price-getter, so — like
            // `oracle_staleness` — we require only external reachability, not
            // state mutation.
            if !f.is_externally_reachable() {
                continue;
            }
            // Pure feed-interface declarations carry no consumer and no risk.
            if cx.contract_of(f.id).map(|c| c.is_interface()).unwrap_or(false) {
                continue;
            }

            // Comment-stripped, lowercased source for the function. Using
            // `source_text` (not raw `span_text`) means commentary such as
            // "// remember to add the sequencer check" can never trip suppression.
            let fsrc = cx.source_text(f.span);

            // The function must actually consume a Chainlink price for pricing.
            let prices = fsrc.contains("latestrounddata") || fsrc.contains("latestanswer");
            if !prices {
                continue;
            }

            // Build the combined (function + whole contract) source view once.
            // L2 intent and the sequencer-uptime check frequently live outside the
            // pricing function — a `sequencerUptimeFeed` state variable, a shared
            // `_requireSequencerUp()` helper, a base, or a contract-level NatSpec
            // naming the chain — so both the gate and the suppression consult the
            // contract source as well.
            let csrc = cx.contract_of(f.id).map(|c| cx.source_text(c.span)).unwrap_or_default();
            let has = |needle: &str| fsrc.contains(needle) || csrc.contains(needle);

            // --- gate: L2 intent must be present ---
            // Without any L2 marker this is generic oracle-staleness territory,
            // not a sequencer bug; stay silent so we don't double-report there.
            let l2_intent = L2_INTENT_MARKERS.iter().any(|m| has(m));
            if !l2_intent {
                continue;
            }

            // --- false-positive suppression (precision first) ---
            // A sequencer-uptime feed handle, or a require/guard mentioning the
            // sequencer's uptime or recovery grace period, means the safe pattern
            // is already implemented — suppress.
            if SEQUENCER_CHECK_MARKERS.iter().any(|m| has(m)) {
                continue;
            }

            let b = FindingBuilder::new(self.id(), Category::SequencerUptime)
                .title("L2 Chainlink price used without an L2 Sequencer Uptime check")
                .severity(Severity::Medium)
                // Honest: a heuristic keyed on L2 intent and the absence of a
                // sequencer-feed marker. We cannot prove the deployment target is
                // an affected L2, nor that no out-of-band guard exists, so a single
                // value-flow dimension at modest confidence.
                .confidence(0.45)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` reads a Chainlink price (`latestRoundData`/`latestAnswer`) and the contract is \
                     intended for an L2 (Arbitrum/Optimism/Base), but it never consults the Chainlink L2 \
                     Sequencer Uptime feed. While the sequencer is down the price feed keeps a recent-looking \
                     answer, so an ordinary staleness check still passes even though the price is frozen. When \
                     the sequencer restarts, the backlog executes against this stale price, enabling unfair \
                     liquidations or borrows against mispriced collateral during the recovery window.",
                    f.name
                ))
                .recommendation(
                    "Before reading the price feed, query the Chainlink L2 Sequencer Uptime feed via \
                     `latestRoundData()`, `require` the sequencer is up (`answer == 0`), and `require` that \
                     `block.timestamp - startedAt` exceeds a `GRACE_PERIOD` so freshly-recovered, still-stale \
                     prices are rejected.",
                );
            out.push(cx.finish(b, f.id, f.span));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: an Arbitrum lending pool reads the Chainlink price feed and even
    // validates freshness, but never checks the L2 sequencer uptime feed, so a
    // frozen-during-outage price is accepted as live.
    const VULN: &str = r#"
        interface AggregatorV3Interface {
            function latestRoundData()
                external view
                returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
        }
        contract ArbitrumLendingPool {
            AggregatorV3Interface internal priceFeed;
            uint256 internal constant MAX_DELAY = 3600;
            function collateralValue(uint256 amount) external view returns (uint256) {
                (uint80 roundId, int256 price, , uint256 updatedAt, uint80 answeredInRound) = priceFeed.latestRoundData();
                require(price > 0, "price");
                require(answeredInRound >= roundId, "round");
                require(block.timestamp - updatedAt <= MAX_DELAY, "delay");
                return amount * uint256(price);
            }
        }
    "#;

    // Safe: same Arbitrum pool, but it first reads the L2 sequencer uptime feed
    // and reverts if the sequencer is down or still inside the recovery window.
    const SAFE: &str = r#"
        interface AggregatorV3Interface {
            function latestRoundData()
                external view
                returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
        }
        contract ArbitrumLendingPool {
            AggregatorV3Interface internal priceFeed;
            AggregatorV3Interface internal sequencerUptimeFeed;
            uint256 internal constant GRACE_PERIOD = 3600;
            function collateralValue(uint256 amount) external view returns (uint256) {
                (, int256 up, uint256 startedAt, , ) = sequencerUptimeFeed.latestRoundData();
                require(up == 0, "sequencer down");
                require(block.timestamp - startedAt > GRACE_PERIOD, "grace");
                (, int256 price, , , ) = priceFeed.latestRoundData();
                require(price > 0, "price");
                return amount * uint256(price);
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "l2-sequencer-uptime"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "l2-sequencer-uptime"));
    }
}
