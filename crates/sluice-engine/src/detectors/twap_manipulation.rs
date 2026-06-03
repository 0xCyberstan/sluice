//! "TWAP" in name only: a price that *looks* time-averaged but is derived from a
//! single observation or an attacker-chosen short window, and is therefore still
//! spot-manipulable within one (flash-loan-assisted) transaction.
//!
//! Uniswap-V3 exposes two very different reads:
//!   * `slot0()` — the *instantaneous* tick/price of the current block.
//!   * `observe(secondsAgos)` / a periphery `consult(pool, secondsAgo)` — a true
//!     time-weighted average, but **only** if `secondsAgo` is a meaningful, fixed
//!     minimum (the canonical mitigation is a window on the order of 30 min).
//!
//! The bug this detector targets is an integration that *believes* it has a TWAP
//! but reads `slot0` for valuation, or calls `observe`/`consult` with a window
//! that is `0`, a caller-supplied parameter with no enforced lower bound, or a
//! tiny literal. An attacker then moves the pool tick inside the block (or over a
//! a couple of blocks for a short window) and the "average" tracks the spot —
//! the Rari/Inverse-Finance/Mango oracle class.
//!
//! Relationship to `oracle.rs`: the spot-price detector already fires on a bare
//! `slot0()` (it is in `SPOT_PRICE_FUNCS`). To avoid double-reporting the same
//! line, when our anchor is exactly the line `oracle-manipulation` already flags
//! we defer to it. Our distinct contribution is the `observe`/`consult` /
//! cumulative-difference "fake TWAP" shape, which the spot detector does not see.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::detectors::{find_spot_price, is_accounting_name};
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};

pub struct TwapManipulationDetector;

/// Minimum number of seconds we consider a "meaningful" TWAP window. A fixed
/// period constant at or above this (e.g. `1800`, `3600`) is treated as a real,
/// non-manipulable averaging window and suppresses the finding.
const MIN_TWAP_WINDOW: u64 = 600;

/// Keywords that introduce a TWAP averaging window. A numeric literal adjacent to
/// one of these is interpreted as the configured window length.
const WINDOW_KEYWORDS: &[&str] = &["secondsago", "twapinterval", "twapperiod", "period", "window", "lookback", "interval", "twap"];

/// Markers that a robust Chainlink feed is in use (handled by `oracle-staleness`,
/// and never a fake-TWAP source).
const CHAINLINK_MARKERS: &[&str] = &["latestrounddata", "latestanswer", "getrounddata", "aggregatorv3"];

impl Detector for TwapManipulationDetector {
    fn id(&self) -> &'static str {
        "twap-manipulation"
    }
    fn category(&self) -> Category {
        Category::TwapManipulation
    }
    fn description(&self) -> &'static str {
        "\"TWAP\" derived from slot0 / a single observation / an unbounded-short window — still spot-manipulable"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // A price getter is frequently `view`, so (like the staleness
            // detector) we require external reachability but not state mutation.
            if !f.is_externally_reachable() {
                continue;
            }
            // Pure interface/abstract declarations carry no integration risk.
            if cx.contract_of(f.id).map(|c| c.is_interface()).unwrap_or(false) {
                continue;
            }

            let src = cx.scir.span_text(f.span).to_ascii_lowercase();

            // --- (1) Does this function read a Uniswap-V3-style price at all? ---
            let uses_slot0 = src.contains("slot0");
            let uses_observe = src.contains("observe") || src.contains("consult") || src.contains("observesingle");
            // A raw cumulative-price difference (the V2 `price0CumulativeLast`
            // pattern, or a V3 `tickCumulative` delta) is a hand-rolled TWAP.
            let uses_cumulative = src.contains("price0cumulative")
                || src.contains("price1cumulative")
                || src.contains("tickcumulative")
                || src.contains("cumulativeprice");
            if !uses_slot0 && !uses_observe && !uses_cumulative {
                continue;
            }

            // --- (2) Is the price actually used for valuation? ---
            let writes_accounting = f.effects.written_vars().iter().any(|v| is_accounting_name(v));
            let name_l = f.name.to_ascii_lowercase();
            let valuation_name = ["price", "value", "collateral", "quote", "amount", "convert", "rate", "twap", "oracle", "mint", "borrow", "liquidat"]
                .iter()
                .any(|k| name_l.contains(k));
            // A view function that returns a number off one of these reads is a
            // price getter even if its name is generic.
            let returns_number = f.is_view_or_pure() && !f.returns.is_empty();
            if !writes_accounting && !valuation_name && !returns_number {
                continue;
            }

            // --- (3) False-positive suppression (precision first) ---

            // 3a. A robust Chainlink feed → not a fake TWAP (separate class).
            if cx.uses_robust_oracle(f) || CHAINLINK_MARKERS.iter().any(|m| src.contains(m)) {
                continue;
            }

            // 3b. A fixed averaging-window constant >= MIN_TWAP_WINDOW anywhere
            //     (function source, or a contract-level `PERIOD`/`window` constant)
            //     means a real TWAP window is enforced.
            if has_meaningful_window_constant(&src) {
                continue;
            }
            if let Some(c) = cx.contract_of(f.id) {
                let csrc = cx.scir.span_text(c.span).to_ascii_lowercase();
                if has_meaningful_window_constant(&csrc) {
                    continue;
                }
            }

            // 3c. The window is bound from below by a `require`/`if` comparison
            //     (`require(secondsAgo >= MIN_PERIOD)`, `window > x`). Enforcing a
            //     lower bound on a caller-supplied window is the correct mitigation.
            if enforces_window_lower_bound(&src) {
                continue;
            }

            // 3d. Two observations at *different, non-zero* timestamps: a genuine
            //     `observe([t1, t2])` with t1 != t2 (and not the degenerate `[0]`)
            //     is a real interval average. Heuristic: a `secondsAgos` array with
            //     two distinct entries, at least one non-zero.
            if uses_two_distinct_observations(&src) {
                continue;
            }

            // --- (4) Positive evidence that the "TWAP" collapses to spot ---
            //
            // We only fire when something concretely points at a single/zero
            // window: a `slot0` read (instantaneous by definition), an explicit
            // `secondsAgo == 0` / `secondsAgos = [0, ...]`, an `observeSingle`,
            // or an `observe`/`consult`/cumulative read with no surviving window
            // signal (no array of two timestamps, no enforced bound, no constant).
            let zero_window = mentions_zero_window(&src);
            let single_observation = src.contains("observesingle")
                // a 1-element secondsAgos array is a single sample
                || src.contains("secondsagos[0]") && !src.contains("secondsagos[1]");
            let unbounded_param_window = uses_observe && reads_window_param(f) && !enforces_window_lower_bound(&src);

            let collapses_to_spot = uses_slot0 || zero_window || single_observation || unbounded_param_window
                // a cumulative/observe read that reached here survived every
                // window suppression above, so its averaging window is unproven.
                || uses_cumulative
                || uses_observe;
            if !collapses_to_spot {
                continue;
            }

            // --- (5) Anchor span + don't double-fire with oracle-manipulation ---
            //
            // Prefer the `slot0`/observe call expression as the anchor. If that
            // exact line is the one `oracle-manipulation` already flags (its
            // `find_spot_price` hit — `slot0` is in its set), defer to it.
            let anchor = price_read_span(f).unwrap_or(f.span);
            if let Some(spot_span) = find_spot_price(f) {
                if cx.scir.line_of(spot_span) == cx.scir.line_of(anchor) {
                    continue;
                }
            }

            // Describe the concrete reason the average is fake.
            let why = if uses_slot0 {
                "reads `slot0()` — the *current-block* tick, not a time-weighted average"
            } else if zero_window {
                "passes a `secondsAgo` of `0`, so the \"average\" interval is empty and equals the spot tick"
            } else if single_observation {
                "samples a single observation, so no averaging actually occurs"
            } else if unbounded_param_window {
                "takes the averaging window as a caller-supplied parameter with no enforced minimum, so a caller can request a 1-second (≈spot) window"
            } else if uses_cumulative {
                "diffs cumulative prices over an interval that is never bounded to a meaningful minimum"
            } else {
                "calls `observe`/`consult` without enforcing a meaningful minimum window"
            };

            let b = FindingBuilder::new(self.id(), Category::TwapManipulation)
                .title("\"TWAP\" price is single-observation / short-window and still spot-manipulable")
                .severity(Severity::High)
                .confidence(0.5)
                .dimension(Dimension::ValueFlow)
                .dimension(Dimension::Frontier)
                .message(format!(
                    "`{}` derives a price that is presented as a TWAP but {}. Such a price tracks the \
                     instantaneous pool state, so an attacker can move the pool tick within a single \
                     (flash-loan-assisted) transaction — or over the few blocks of a tiny window — and \
                     mint/borrow/liquidate at a false valuation. A name containing \"TWAP\" or \"observe\" \
                     does not by itself make a price manipulation-resistant.",
                    f.name, why
                ))
                .recommendation(
                    "Read the average over a fixed, meaningful window (e.g. `observe([1800, 0])` / \
                     `consult(pool, 1800)`), enforce `require(secondsAgo >= MIN_PERIOD)` on any \
                     caller-supplied window, and never feed `slot0()` or a zero-length interval into \
                     valuation; cross-check against a Chainlink feed where possible.",
                );
            out.push(cx.finish(b, f.id, anchor));
        }
        out
    }
}

// ------------------------------------------------------------------ heuristics

/// True if a numeric literal adjacent to a TWAP-window keyword is at least
/// [`MIN_TWAP_WINDOW`] (e.g. `secondsAgo = 1800`, `uint32 PERIOD = 3600`). A
/// configured window of >= 10 minutes is treated as a real averaging window.
fn has_meaningful_window_constant(src: &str) -> bool {
    for kw in WINDOW_KEYWORDS {
        let mut from = 0usize;
        while let Some(rel) = src[from..].find(kw) {
            let after = from + rel + kw.len();
            if let Some(n) = first_number_within(&src[after..], 64) {
                if n >= MIN_TWAP_WINDOW {
                    return true;
                }
            }
            from = after;
        }
    }
    false
}

/// Scan up to `budget` bytes for the first run of ASCII digits and parse it. We
/// skip over the usual assignment/declaration punctuation so that
/// `secondsAgo = 1800` and `uint32 public period = 1800` both resolve. Stops at a
/// statement terminator so we don't drift into the next line.
fn first_number_within(s: &str, budget: usize) -> Option<u64> {
    let bytes = s.as_bytes();
    let end = bytes.len().min(budget);
    let mut i = 0usize;
    while i < end {
        let c = bytes[i] as char;
        if c.is_ascii_digit() {
            let start = i;
            while i < end && (bytes[i] as char).is_ascii_digit() {
                i += 1;
            }
            return s[start..i].parse::<u64>().ok();
        }
        // Stop scanning at a clear statement/expression boundary before any digit.
        if c == ';' || c == '{' || c == '}' || c == ')' {
            return None;
        }
        i += 1;
    }
    None
}

/// True if a TWAP window is bound from below by a comparison, e.g.
/// `require(secondsAgo >= MIN_PERIOD)`, `if (window < MIN) revert`, `period > 0`
/// is *not* enough on its own — we require a `>=`/`>` against the window keyword
/// (or a `<`/`<=` revert guard) so a meaningful floor is plausibly enforced.
fn enforces_window_lower_bound(src: &str) -> bool {
    for kw in WINDOW_KEYWORDS {
        let mut from = 0usize;
        while let Some(rel) = src[from..].find(kw) {
            let after = from + rel + kw.len();
            // `<keyword> >= x` / `<keyword> > x`
            let tail = src[after..].trim_start();
            if tail.starts_with(">=") || tail.starts_with('>') {
                // exclude `> 0` / `>= 0`, which is not a meaningful floor.
                let cmp_tail = tail.trim_start_matches(['>', '=', ' ']);
                if first_number_within(cmp_tail, 8) != Some(0) {
                    return true;
                }
            }
            // `x <= <keyword>` / `x < <keyword>` (keyword on the RHS of a floor)
            let before = &src[..from + rel];
            let bt = before.trim_end();
            if bt.ends_with("<=") || bt.ends_with('<') {
                return true;
            }
            from = after;
        }
    }
    false
}

/// True if the source samples two distinct, non-degenerate observation
/// timestamps — a genuine interval average, e.g. `observe([1800, 0])` or a
/// `secondsAgos` array assigned two different non-zero-only entries.
fn uses_two_distinct_observations(src: &str) -> bool {
    // `observe([a, b])` literal with two entries where they are not both the same
    // and not `[0, 0]`.
    if let Some(rel) = src.find("observe(") {
        let tail = &src[rel..];
        if let (Some(lb), Some(rb)) = (tail.find('['), tail.find(']')) {
            if rb > lb {
                let inside = &tail[lb + 1..rb];
                let parts: Vec<&str> = inside.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()).collect();
                if parts.len() >= 2 {
                    // distinct, and at least one strictly positive numeric entry.
                    let distinct = parts[0] != parts[1];
                    let has_positive = parts.iter().any(|p| p.parse::<u64>().map(|n| n > 0).unwrap_or(false));
                    if distinct && has_positive {
                        return true;
                    }
                }
            }
        }
    }
    // NOTE: an *indexed* `secondsAgos[0] = ...; secondsAgos[1] = ...` pair is NOT
    // treated as safe here — `secondsAgos[1] = 0` (window end = now) is the norm
    // and says nothing about whether the *start* `secondsAgos[0]` is a meaningful,
    // bounded window. That safety signal is covered precisely by the window-
    // constant (3b) and lower-bound (3c) checks instead.
    false
}

/// True if the source explicitly passes a zero-length averaging interval.
fn mentions_zero_window(src: &str) -> bool {
    // `secondsAgo = 0`, `secondsAgo == 0`, `consult(pool, 0)`, `observe([0])`,
    // `secondsAgos = [0]`.
    for kw in ["secondsago = 0", "secondsago=0", "secondsago == 0", "secondsago==0", "[0]", "observe([0", ", 0)", ",0)"] {
        if src.contains(kw) {
            // guard the broad `[0]`/`, 0)` forms behind an observe/consult context.
            if kw == "[0]" || kw == ", 0)" || kw == ",0)" {
                if src.contains("observe") || src.contains("consult") {
                    return true;
                }
            } else {
                return true;
            }
        }
    }
    false
}

/// True if the function takes a parameter that names the averaging window — a
/// caller-supplied window that we must check is bounded.
fn reads_window_param(f: &sluice_ir::Function) -> bool {
    f.params.iter().any(|p| {
        p.name
            .as_deref()
            .map(|n| {
                let l = n.to_ascii_lowercase();
                l.contains("secondsago") || l.contains("period") || l.contains("window") || l.contains("twap") || l.contains("interval") || l.contains("lookback")
            })
            .unwrap_or(false)
    })
}

/// Span of the first Uniswap-V3-style price read in the body (the `slot0` /
/// `observe` / `consult` call), used as the finding anchor.
fn price_read_span(f: &sluice_ir::Function) -> Option<sluice_ir::Span> {
    use sluice_ir::ExprKind;
    let mut found: Option<sluice_ir::Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                let name = c.func_name.as_deref().unwrap_or("").to_ascii_lowercase();
                if matches!(name.as_str(), "slot0" | "observe" | "observesingle" | "consult") {
                    found = Some(e.span);
                    return;
                }
            }
            // Fall back to any identifier/member that names a cumulative price.
            if let Some(n) = e.simple_name() {
                if n.to_ascii_lowercase().contains("cumulative") {
                    found = Some(e.span);
                }
            }
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: an oracle that advertises a TWAP but reads `observe` with a
    // caller-supplied `secondsAgo` that is never bounded — and the demo path uses
    // a zero window. `observe` is NOT in the spot-price set, so this is purely our
    // class (no double-fire with oracle-manipulation).
    const VULN: &str = r#"
        interface IUniswapV3Pool {
            function observe(uint32[] calldata secondsAgos)
                external view returns (int56[] memory tickCumulatives, uint160[] memory);
        }
        contract FakeTwapOracle {
            IUniswapV3Pool public pool;
            function getTwapPrice(uint32 secondsAgo) external view returns (uint256 price) {
                uint32[] memory secondsAgos = new uint32[](2);
                secondsAgos[0] = secondsAgo;
                secondsAgos[1] = 0;
                (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);
                int56 delta = tickCumulatives[1] - tickCumulatives[0];
                price = uint256(uint56(delta));
            }
        }
    "#;

    // Safe: same pool, but the averaging window is a fixed 1800-second constant
    // (>= MIN_TWAP_WINDOW), so it is a genuine TWAP and must not fire.
    const SAFE: &str = r#"
        interface IUniswapV3Pool {
            function observe(uint32[] calldata secondsAgos)
                external view returns (int56[] memory tickCumulatives, uint160[] memory);
        }
        contract RealTwapOracle {
            IUniswapV3Pool public pool;
            uint32 public constant TWAP_PERIOD = 1800;
            function getTwapPrice() external view returns (uint256 price) {
                uint32[] memory secondsAgos = new uint32[](2);
                secondsAgos[0] = TWAP_PERIOD;
                secondsAgos[1] = 0;
                (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);
                int56 delta = tickCumulatives[1] - tickCumulatives[0];
                price = uint256(uint56(delta)) / TWAP_PERIOD;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "twap-manipulation"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "twap-manipulation"));
    }
}
