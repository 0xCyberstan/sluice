//! Chainlink-style oracle freshness: a robust price feed (`latestRoundData` /
//! `latestAnswer` / `getRoundData`) is consumed without validating staleness.
//!
//! This is the dual of `oracle.rs`. The spot-price detector fires on
//! *manipulable* reads (`balanceOf` / `getReserves`) and explicitly suppresses
//! itself when a robust feed is present, leaving this class to us: the feed
//! itself is trustworthy, but the integration forgets to reject a stale answer.
//!
//! The canonical safe pattern around `latestRoundData`:
//! ```solidity
//! (uint80 roundId, int256 price, , uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
//! require(price > 0, "bad price");
//! require(updatedAt != 0, "round not complete");
//! require(answeredInRound >= roundId, "stale");
//! require(block.timestamp - updatedAt <= MAX_DELAY, "stale");
//! ```
//! `latestAnswer()` returns no timestamp whatsoever, so a missing freshness
//! check there can never be remediated in-line — it is always suspect (High).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::FunctionId;

pub struct OracleStalenessDetector;

/// Substrings that evidence a freshness / round-completeness check. If any of
/// these appears in the function (or its contract) source, we assume the
/// integration validates the answer and suppress.
const FRESHNESS_MARKERS: &[&str] = &["updatedat", "answeredinround", "staleness", "stale"];

impl Detector for OracleStalenessDetector {
    fn id(&self) -> &'static str {
        "oracle-staleness"
    }
    fn category(&self) -> Category {
        Category::OracleStaleness
    }
    fn description(&self) -> &'static str {
        "Chainlink feed (latestRoundData/latestAnswer) consumed without a staleness/round check"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // The feed read can sit in a `view` price-getter, so unlike most
            // detectors we do not require `is_state_mutating()`. We require only
            // that the read is on the *integration surface* an external actor can
            // drive: either the function is itself externally reachable, or it is
            // an `internal`/`private` helper transitively called from a public /
            // external entry point (e.g. Stader's `updateERFromPORFeed` ->
            // `getPORFeedData`, which performs the `latestRoundData` read). A
            // helper that no entry point reaches is dead code and carries no risk.
            if !f.is_externally_reachable() && !reachable_from_entrypoint(cx, f.id) {
                continue;
            }
            // Pure feed-interface declarations (no concrete consumer) carry no risk.
            if cx.contract_of(f.id).map(|c| c.is_interface()).unwrap_or(false) {
                continue;
            }

            let src = cx.source_text(f.span);

            // Which robust feed accessor(s) does this function call?
            let uses_latest_answer = src.contains("latestanswer");
            let uses_rounddata = src.contains("latestrounddata") || src.contains("getrounddata");
            if !uses_latest_answer && !uses_rounddata {
                continue;
            }

            // --- false-positive suppression (precision is the priority) ---
            // A freshness/round check anywhere in the function, or anywhere in the
            // surrounding contract (a shared `_validate(...)` helper, a staleness
            // wrapper, a base library), means the answer is being vetted.
            let has_freshness = |text: &str| FRESHNESS_MARKERS.iter().any(|m| text.contains(m));
            if has_freshness(&src) {
                continue;
            }
            if let Some(c) = cx.contract_of(f.id) {
                let csrc = cx.source_text(c.span);
                if has_freshness(&csrc) {
                    continue;
                }
                // A dedicated staleness-checking oracle wrapper in the inheritance
                // chain (e.g. `ChainlinkOracleWithStaleCheck`) handles it.
                if c.inherits_like("stale") || c.inherits_like("staleness") {
                    continue;
                }
            }

            // `latestAnswer` has no timestamp in its return at all, so a missing
            // check is strictly worse (and not remediable inline) — High. A bare
            // `latestRoundData`/`getRoundData` with the timestamp discarded is the
            // common Medium-severity integration bug.
            let (sev, what, detail) = if uses_latest_answer {
                (
                    Severity::High,
                    "latestAnswer",
                    "`latestAnswer()` returns only the price — it carries no `updatedAt` timestamp \
                     or round id, so freshness cannot be verified at all. A frozen or paused feed \
                     keeps returning its last value, which the contract treats as live.",
                )
            } else {
                (
                    Severity::Medium,
                    "latestRoundData",
                    "the returned `updatedAt` / `answeredInRound` are never checked, so a stale or \
                     incomplete round (frozen feed, paused sequencer, carried-over answer) is \
                     accepted as the current price.",
                )
            };

            let b = FindingBuilder::new(self.id(), Category::OracleStaleness)
                .title("Oracle price used without a staleness check")
                .severity(sev)
                .confidence(0.6)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` reads a Chainlink-style price via `{}` but never validates freshness: \
                     {} Consuming a stale price can misprice collateral, enabling under-collateralized \
                     borrows or unfair liquidations.",
                    f.name, what, detail
                ))
                .recommendation(
                    "After reading the feed, enforce `require(price > 0)`, \
                     `require(answeredInRound >= roundId)`, and \
                     `require(block.timestamp - updatedAt <= maxStaleness)`; prefer `latestRoundData` \
                     over `latestAnswer` so a timestamp is available.",
                );
            out.push(cx.finish(b, f.id, f.span));
        }
        out
    }
}

/// True if `start` is transitively invoked by some externally-reachable
/// (`public`/`external`/fallback/receive) function, walking the resolved
/// caller graph (`Function::callers`, populated by `sluice-parse`).
///
/// This lets the detector follow a Chainlink read from a public entry point
/// down into an `internal`/`private` helper that actually performs it. The walk
/// is bounded by the visited set, so cycles (mutually-recursive helpers)
/// terminate. We stop and return `true` the moment any reachable function is
/// itself externally reachable. Unresolved/indirect calls simply mean a helper
/// looks unreachable and is conservatively skipped (no false positive).
fn reachable_from_entrypoint(cx: &AnalysisContext, start: FunctionId) -> bool {
    use rustc_hash::FxHashSet;
    let mut seen: FxHashSet<FunctionId> = FxHashSet::default();
    let mut stack: Vec<FunctionId> = vec![start];
    while let Some(fid) = stack.pop() {
        if !seen.insert(fid) {
            continue;
        }
        let Some(f) = cx.scir.function(fid) else { continue };
        // A direct caller that is externally reachable proves the chain. We skip
        // `start` itself: this helper is only consulted when `start` is *not*
        // externally reachable, so reaching it again proves nothing.
        if fid != start && f.is_externally_reachable() {
            return true;
        }
        for &caller in &f.callers {
            if !seen.contains(&caller) {
                stack.push(caller);
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: reads `latestRoundData()` and uses the price, but discards
    // `updatedAt` / `answeredInRound` — no freshness validation at all.
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

    // Safe: same feed, but the integration enforces round completeness and a
    // maximum staleness window before trusting the answer.
    const SAFE: &str = r#"
        interface AggregatorV3Interface {
            function latestRoundData()
                external view
                returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
        }
        contract LendingPool {
            AggregatorV3Interface internal feed;
            uint256 internal constant MAX_DELAY = 3600;
            function collateralValue(uint256 amount) external view returns (uint256) {
                (uint80 roundId, int256 price, , uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
                require(price > 0, "price");
                require(answeredInRound >= roundId, "stale round");
                require(block.timestamp - updatedAt <= MAX_DELAY, "stale price");
                return amount * uint256(price);
            }
        }
    "#;

    // Vulnerable (Stader M-14 shape): the Chainlink `latestRoundData` read lives
    // in an `internal view` helper (`getPORFeedData`) that discards
    // `updatedAt`/`answeredInRound`; the helper is reached from an `external`
    // entry point (`updateERFromPORFeed`). The read is on the integration
    // surface even though it is not directly external.
    const VULN_INTERNAL_HELPER: &str = r#"
        interface AggregatorV3Interface {
            function latestRoundData()
                external view
                returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
        }
        contract Oracle {
            AggregatorV3Interface internal feed;
            uint256 public rate;
            function updateRate() external {
                rate = getPORFeedData();
            }
            function getPORFeedData() internal view returns (uint256) {
                (, int256 answer, , , ) = feed.latestRoundData();
                return uint256(answer);
            }
        }
    "#;

    // Safe: same internal-helper-reached-from-external shape, but the helper
    // enforces round completeness and a freshness window before trusting it.
    const SAFE_INTERNAL_HELPER: &str = r#"
        interface AggregatorV3Interface {
            function latestRoundData()
                external view
                returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
        }
        contract Oracle {
            AggregatorV3Interface internal feed;
            uint256 internal constant MAX_DELAY = 3600;
            uint256 public rate;
            function updateRate() external {
                rate = getPORFeedData();
            }
            function getPORFeedData() internal view returns (uint256) {
                (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
                require(answer > 0, "price");
                require(answeredInRound >= roundId, "stale round");
                require(block.timestamp - updatedAt <= MAX_DELAY, "stale price");
                return uint256(answer);
            }
        }
    "#;

    // A `latestRoundData` read in an internal helper that NO entry point reaches
    // (dead code) must stay silent — it is not on any attacker-drivable surface.
    const UNREACHABLE_HELPER: &str = r#"
        interface AggregatorV3Interface {
            function latestRoundData()
                external view
                returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
        }
        contract Oracle {
            AggregatorV3Interface internal feed;
            function _dead() private view returns (uint256) {
                (, int256 answer, , , ) = feed.latestRoundData();
                return uint256(answer);
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "oracle-staleness"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "oracle-staleness"));
    }

    // Stader M-14 regression: read in an internal helper reached from an
    // external entry point fires.
    #[test]
    fn fires_on_internal_helper_reached_from_entrypoint() {
        let fs = run(VULN_INTERNAL_HELPER);
        assert!(
            fs.iter().any(|f| f.detector == "oracle-staleness"),
            "expected oracle-staleness on the internal-helper read, got {:?}",
            fs
        );
    }

    // The same internal-helper shape stays silent when the helper validates
    // freshness — confirms the broadening did not drop the precision guard.
    #[test]
    fn silent_on_safe_internal_helper() {
        let fs = run(SAFE_INTERNAL_HELPER);
        assert!(!fs.iter().any(|f| f.detector == "oracle-staleness"), "{:?}", fs);
    }

    // A genuinely unreachable internal helper must not fire (precision).
    #[test]
    fn silent_on_unreachable_helper() {
        let fs = run(UNREACHABLE_HELPER);
        assert!(!fs.iter().any(|f| f.detector == "oracle-staleness"), "{:?}", fs);
    }
}
