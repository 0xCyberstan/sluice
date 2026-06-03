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

            let src = cx.source_text(f.span);

            // --- (0) Pump / oracle reserve-reader surface (the Basin MultiFlowPump
            //         class) ---
            //
            // Beyond the Uniswap-v2/v3 vocabulary handled below, a whole family of
            // AMM *Pumps* expose their own oracle surface as a `read*Reserves` /
            // `readInstantaneous*` getter that hands back the pool's geometric-mean
            // reserves. Downstream integrators consume these as a price. The
            // last-stored reserves (`readLastReserves`) are written by a single
            // `update`/seeded `_init`, and the "instantaneous" EMA collapses toward
            // the live `getReserves()` for a short elapsed window — so a single large
            // swap in the same/adjacent block before the read moves the reported
            // reserves. This shape calls none of `slot0`/`observe`/`consult`/a
            // cumulative getter, so step (1) below never sees it. Recognize it here,
            // tightly scoped so we do not fire on every `getReserves`.
            if let Some(finding) = pump_reserve_reader_finding(self, cx, f, &src) {
                out.push(finding);
                continue;
            }

            // --- (1) Does this function actually *call* a Uniswap-style oracle read? ---
            //
            // Precision-critical: we classify the body by its CALL EXPRESSIONS, not by
            // a substring of the source. A bare identifier / parameter / function name
            // that merely *contains* "observe" (the event-`observer` pattern —
            // `removeObserver`/`observers`/`_observerIndex`), or a local variable
            // spelled `tickCumulatives`, is NOT an oracle read and must never trip this
            // detector. We require a call expression whose resolved method is a genuine
            // TWAP/oracle primitive (`observe`/`observeSingle`/`consult` /
            // `getTimeWeightedAverage`, an ambiguous `current`/`quote` only *on a
            // receiver handle*, or a `slot0` read), or a cumulative-price getter
            // (`price0CumulativeLast`/`price1CumulativeLast`/`tickCumulative`) read off a
            // pool/pair handle.
            let reads = classify_oracle_reads(f);
            let uses_slot0 = reads.slot0;
            let uses_observe = reads.observe;
            let uses_cumulative = reads.cumulative;
            if !uses_slot0 && !uses_observe && !uses_cumulative {
                continue;
            }

            // --- (2) Is the price actually *consumed* for a financial decision? ---
            //
            // The vulnerability is a manipulable price feeding a *financial* action
            // (swap / borrow / mint / liquidation / collateral valuation) or being
            // persisted to state. A function that merely *reads* a slot0/observe
            // value and hands it back — a pure view passthrough getter
            // (`StateView.getSlot0` → `return poolManager.getSlot0(id)`) — or that
            // uses the tick only to render display metadata (`PositionDescriptor.
            // tokenURI` building an NFT data-URI string) is NOT a price *consumer*:
            // nothing downstream of it makes a value decision here, so a manipulated
            // tick has no in-contract financial effect to exploit. Such functions
            // are suppressed.

            // 2a. Metadata / display getters: a `tokenURI`/`uri`/`name`/`symbol`/…
            //     function, or any function that returns a `string` (a human-readable
            //     label, not a quantity used in math). The read feeds presentation,
            //     not a financial decision.
            if is_metadata_or_string_returning(f) {
                continue;
            }

            let writes_accounting = f.effects.written_vars().iter().any(|v| is_accounting_name(v));
            let name_l = f.name.to_ascii_lowercase();
            let valuation_name = ["price", "value", "collateral", "quote", "amount", "convert", "rate", "twap", "oracle", "mint", "borrow", "liquidat"]
                .iter()
                .any(|k| name_l.contains(k));
            // 2b. The price flows into a financial *use*: a valuation calculation
            //     (arithmetic on the read — `price = sqrtP * sqrtP / Q96`, a
            //     cumulative-tick `delta = c[1] - c[0]`) or a swap / borrow / mint /
            //     liquidation / deposit / settlement *sink* call. A `view`/`pure`
            //     getter that does none of these is a pure passthrough (it just
            //     forwards the read), which is the `StateView.getSlot0` false
            //     positive — suppress it. (A state write is itself a consuming use.)
            let flows_into_financial_use = body_has_valuation_or_sink(f);
            if !writes_accounting && !valuation_name && !flows_into_financial_use {
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
                let csrc = cx.source_text(c.span);
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

/// The Basin-`MultiFlowPump` class: a Pump/oracle contract whose oracle surface is
/// a `read*Reserves` / `readInstantaneous*` getter returning the pool's geometric-
/// mean reserves, where the returned value reflects the **last-stored** or
/// **instantaneous** reserves (movable by a same/adjacent-block swap) and there is
/// no enforced minimum averaging window. Returns a finding anchored on `f` when the
/// shape matches, else `None`.
///
/// Scoped tightly to avoid the "every `getReserves`" false positive (precision is
/// make-or-break here):
///   * the owning contract must be **pump/oracle-like** (its name, or one of its
///     bases/implemented interfaces, contains `pump` or `oracle`) — a plain money-
///     market `Comet.getReserves()` returning protocol-treasury reserves is on a
///     contract with neither marker and is therefore never matched;
///   * the function name must be a **reserve/price reader** (`read*reserves`,
///     `readinstantaneous*`, or exactly `getreserves`);
///   * it must be a **last-stored / instantaneous** reader, NOT a true cumulative
///     or time-weighted-average reader — a name containing `cumulative` or `twa`
///     (Basin's `readLastCumulativeReserves` / `readCumulativeReserves` /
///     `readTwaReserves`) is the genuine TWA surface and is left silent;
///   * it must **return a numeric quantity** (`uint*`/`int*`, incl. arrays) — a
///     `bytes`/`string` encoder return is not a directly-consumed price;
///   * no meaningful min-window / lower-bound guard is present (the same window
///     suppressions used for the Uniswap path).
fn pump_reserve_reader_finding(
    det: &TwapManipulationDetector,
    cx: &AnalysisContext,
    f: &sluice_ir::Function,
    src: &str,
) -> Option<Finding> {
    use crate::detector::Detector;

    // (a) Owning contract must look like a pump / oracle (by its own name or by a
    //     base/implemented-interface name). This is the key precision gate.
    let contract = cx.contract_of(f.id)?;
    let cname = contract.name.to_ascii_lowercase();
    let contract_is_pump_or_oracle = is_pump_or_oracle_marker(&cname)
        || contract.bases.iter().any(|b| is_pump_or_oracle_marker(&b.to_ascii_lowercase()));
    if !contract_is_pump_or_oracle {
        return None;
    }

    // (b) Function name must be a reserve/price reader surface.
    let fname = f.name.to_ascii_lowercase();
    let is_reserve_reader =
        (fname.starts_with("read") && fname.contains("reserves")) || fname == "getreserves";
    if !is_reserve_reader {
        return None;
    }

    // (c) Must be a last-stored / instantaneous reader — NOT the genuine cumulative
    //     / time-weighted-average surface, which is the protocol's correct
    //     manipulation-resistant read and must stay silent.
    if fname.contains("cumulative") || fname.contains("twa") {
        return None;
    }

    // (d) Must return a numeric reserves/price quantity (a `bytes`/`string` encoder
    //     return such as `readCumulativeReserves`'s `abi.encode(...)` is excluded by
    //     (c) already; this also drops any non-quantity getter that slipped through).
    if !f.returns.iter().any(|r| ty_is_numeric_quantity(&r.ty)) {
        return None;
    }

    // (e) Window suppression: if a meaningful fixed window constant, or an enforced
    //     lower bound on a caller-supplied window, is present (in the function or
    //     anywhere on the contract), this is a properly time-guarded reader.
    if has_meaningful_window_constant(src) || enforces_window_lower_bound(src) {
        return None;
    }
    let csrc = cx.source_text(contract.span);
    if has_meaningful_window_constant(&csrc) {
        return None;
    }

    // Positive description of why the read is single-update / spot-manipulable.
    let why = if fname.contains("instantaneous") {
        "returns an \"instantaneous\" geometric-mean reserve whose EMA collapses toward the \
         live pool reserves over a short elapsed window"
    } else if fname.contains("last") {
        "returns the *last-stored* reserves, which are written by a single `update` (and the \
         seeded first update skips the per-block change cap entirely)"
    } else {
        "returns reserves that reflect the current/last-stored pool state"
    };

    let b = FindingBuilder::new(det.id(), Category::TwapManipulation)
        .title("Pump/oracle reserve reader is single-update / spot-manipulable (no min averaging window)")
        // Medium, matching the calibrated severity for this class: a raw pump reader
        // is a manipulable SURFACE (a consumer footgun), directly exploitable only
        // when a downstream integrator trusts it as a price feed without adding its
        // own averaging — so absent a proven on-chain consumer it is not a standalone
        // Crit/High. (Single ValueFlow dimension keeps the corroboration scorer from
        // promoting it past Medium on the reader alone.)
        .severity(Severity::Medium)
        .confidence(0.5)
        .dimension(Dimension::ValueFlow)
        .message(format!(
            "`{}` on `{}` is a pump/oracle reserve reader that {}. Downstream integrators consume \
             this getter as a price feed, but the returned reserves track the current/last-stored \
             pool state with no enforced minimum averaging window, so an attacker can move the pool \
             with a single large swap in the same/adjacent block (optionally flash-loan-assisted) \
             right before the read and mint/borrow/liquidate against a manipulated reserve ratio. A \
             geometric-mean / EMA over a per-block cap does not by itself bound a single-update or \
             same-block move.",
            f.name, contract.name, why
        ))
        .recommendation(
            "Consume the time-weighted-average surface instead (read cumulative reserves at a \
             stored checkpoint and divide by a meaningful elapsed window — Basin's \
             `readTwaReserves`/`readCumulativeReserves`), enforce a minimum elapsed window between \
             the start and end observations, and never feed a last-stored / instantaneous reserve \
             read into valuation; cross-check against an independent oracle where possible.",
        );
    Some(cx.finish(b, f.id, f.span))
}

/// True if a (lowercased) name contains a pump/oracle marker — used to scope the
/// pump-reserve-reader class to contracts that actually expose an oracle surface.
fn is_pump_or_oracle_marker(name: &str) -> bool {
    name.contains("pump") || name.contains("oracle")
}

/// True if a return type denotes a numeric quantity (`uint*` / `int*`), including a
/// dynamic/fixed array of one (`uint256[]`). A `bytes`/`string`/`bool`/`address`
/// return is not a directly-consumed numeric price.
fn ty_is_numeric_quantity(ty: &str) -> bool {
    // Strip any storage-location/keyword suffix, array brackets, and whitespace to
    // get the element base, e.g. `uint256[] memory` -> `uint256`.
    let base = ty.trim().split([' ', '[']).next().unwrap_or("").trim();
    base.starts_with("uint") || base.starts_with("int")
}

/// Which Uniswap-style oracle reads a function body actually *calls*.
#[derive(Default)]
struct OracleReads {
    /// A `slot0()` / `getSlot0(...)` read — the instantaneous current-block tick.
    slot0: bool,
    /// A true-TWAP primitive call: `observe`/`observeSingle`/`consult` /
    /// `getTimeWeightedAverage`, or an ambiguous `current`/`quote` *on a receiver
    /// handle*. (The averaging window may still be fake — that is decided later.)
    observe: bool,
    /// A hand-rolled cumulative-price read: a `price0CumulativeLast` /
    /// `price1CumulativeLast` / `tickCumulative*` getter read off a pool/pair handle.
    cumulative: bool,
}

/// Unambiguous TWAP/oracle primitives: seeing a *call* with one of these resolved
/// method names is conclusive evidence of an oracle read, whether the call is bare
/// (`consult(...)`, an in-repo wrapper) or a member call (`pool.observe(...)`).
const OBSERVE_METHODS: &[&str] = &["observe", "observesingle", "consult", "gettimeweightedaverage"];

/// Ambiguous read methods (`current()` on an OZ `Counter`, a generic `quote(...)`)
/// that count as an oracle read ONLY when called on a *receiver handle*
/// (`twapOracle.current(...)`, `pair.quote(...)`), never as a bare local call.
const OBSERVE_METHODS_RECEIVER_ONLY: &[&str] = &["current", "quote"];

/// Classify a function body by the Uniswap-style oracle reads it actually *calls*.
///
/// This replaces the previous `source.contains("observe")` substring test, which
/// false-fired on the event-observer pattern (`removeObserver`/`observers`/
/// `_observerIndex` on Lido's `TokenRateNotifier`): those are identifiers / a
/// function name, not an `observe` oracle call. We match on the resolved CALL name
/// (exact for the TWAP primitives) and on cumulative-price getters read off a
/// receiver handle — a bare local identifier such as `tickCumulatives` (the result
/// of an `observe`) is deliberately NOT a trigger on its own.
fn classify_oracle_reads(f: &sluice_ir::Function) -> OracleReads {
    use sluice_ir::ExprKind;
    let mut r = OracleReads::default();
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            match &e.kind {
                ExprKind::Call(c) => {
                    let name = c.func_name.as_deref().unwrap_or("").to_ascii_lowercase();
                    if name.is_empty() {
                        return;
                    }
                    // `slot0()` / `getSlot0(...)` — instantaneous price.
                    if name == "slot0" || name == "getslot0" {
                        r.slot0 = true;
                    }
                    // Unambiguous TWAP primitives (bare or member call).
                    if OBSERVE_METHODS.contains(&name.as_str()) {
                        r.observe = true;
                    }
                    // Ambiguous read methods only count on a receiver handle.
                    if c.receiver.is_some() && OBSERVE_METHODS_RECEIVER_ONLY.contains(&name.as_str()) {
                        r.observe = true;
                    }
                    // A cumulative-price *getter* called on a receiver handle
                    // (`pair.price0CumulativeLast()`).
                    if c.receiver.is_some() && is_cumulative_price_name(&name) {
                        r.cumulative = true;
                    }
                }
                // A cumulative-price public-getter read written as a member access
                // without call parens (`pair.price0CumulativeLast`). Requires the
                // `member` form (a `.field` off a handle), so a bare local
                // `tickCumulatives` identifier is excluded.
                ExprKind::Member { member, .. } => {
                    if is_cumulative_price_name(&member.to_ascii_lowercase()) {
                        r.cumulative = true;
                    }
                }
                _ => {}
            }
        });
    }
    r
}

/// True if a (lowercased) method/member name is a canonical Uniswap cumulative-
/// price getter (`price0CumulativeLast`, `price1CumulativeLast`, `tickCumulatives`,
/// `secondsPerLiquidityCumulativeX128`, …). Matched on the handle-qualified name so
/// it never trips on an unrelated local variable of the same spelling.
fn is_cumulative_price_name(name: &str) -> bool {
    (name.contains("price0cumulative")
        || name.contains("price1cumulative")
        || name.contains("tickcumulative")
        || name.contains("cumulativeprice"))
        // `secondsPerLiquidityCumulative*` is the other V3 cumulative accumulator.
        || name.contains("cumulativex")
}

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

/// True if this is a metadata / display function whose price read feeds a
/// human-readable label rather than a financial decision: a `tokenURI` / `uri` /
/// `name` / `symbol` / `metadata` / `description` / `render` / `svg` / `image`
/// function (the ERC-721/1155 metadata surface — `PositionDescriptor.tokenURI`),
/// or **any** function that returns a `string` (a label, not a quantity used in
/// math). Such a read never drives a swap/borrow/mint/valuation, so a manipulated
/// tick has no in-contract financial effect here — it is not a price *consumer*.
fn is_metadata_or_string_returning(f: &sluice_ir::Function) -> bool {
    let l = f.name.to_ascii_lowercase();
    // Substring markers: the metadata/display surface (`tokenURI`, `contractURI`,
    // `*Metadata`, `renderSVG`, …).
    const METADATA_SUBSTR: &[&str] = &["tokenuri", "contracturi", "metadata", "description", "svg"];
    if METADATA_SUBSTR.iter().any(|m| l.contains(m)) {
        return true;
    }
    // Exact-match label getters (kept exact so they don't shadow a real consumer
    // whose name merely *contains* one of these tokens, e.g. `renameVault`).
    const METADATA_EXACT: &[&str] = &["uri", "name", "symbol", "render", "image"];
    if METADATA_EXACT.iter().any(|m| l == *m) {
        return true;
    }
    // A `string`-returning function yields a label, not a quantity for math.
    f.returns.iter().any(|r| {
        let t = r.ty.trim();
        t.starts_with("string")
    })
}

/// True if the body uses a price for a financial decision: it performs a
/// **valuation calculation** (an arithmetic operation — the manipulable tick is
/// scaled / differenced / multiplied into a value, e.g. `price = sqrtP * sqrtP /
/// Q96` or a cumulative-tick `delta = c[1] - c[0]`), or it calls a financial
/// **sink** (`swap` / `borrow` / `mint` / `liquidate` / `deposit` / `redeem` /
/// `repay` / `withdraw` / `settle` / `quote` / `convert` / `value` / `collateral`
/// / `price`). A `view`/`pure` getter that does **none** of these is a pure
/// passthrough that merely forwards the read (the `StateView.getSlot0` shape) and
/// is therefore not a price consumer.
fn body_has_valuation_or_sink(f: &sluice_ir::Function) -> bool {
    use sluice_ir::ExprKind;
    const SINK_CALLS: &[&str] = &[
        "swap", "borrow", "mint", "liquidat", "deposit", "redeem", "repay", "withdraw", "settle",
        "quote", "convert", "value", "collateral", "price", "exchange", "getamount", "calculate",
    ];
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            match &e.kind {
                // A valuation calculation: arithmetic that scales / differences the
                // price into a derived value.
                ExprKind::Binary { op, .. } if op.is_arithmetic() => {
                    found = true;
                }
                // A financial-sink call (by best-effort callee name).
                ExprKind::Call(c) => {
                    let name = c
                        .func_name
                        .as_deref()
                        .or_else(|| c.callee.simple_name())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    if SINK_CALLS.iter().any(|k| name.contains(k)) {
                        found = true;
                    }
                }
                _ => {}
            }
        });
        if found {
            break;
        }
    }
    found
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

    // ---- Fix A regressions: view passthrough / metadata are NOT price consumers ----

    // Real shape (Uniswap v4-periphery `StateView.getSlot0`): a pure `view`
    // passthrough that just forwards `poolManager.getSlot0(id)` to its return. It
    // reads slot0 but does NOT consume it for any swap/borrow/mint/valuation, so a
    // manipulated tick has no in-contract financial effect — must be SILENT.
    const VIEW_PASSTHROUGH_GETSLOT0: &str = r#"
        interface IPoolManager {
            function getSlot0(bytes32 id)
                external view returns (uint160 sqrtPriceX96, int24 tick, uint24 protocolFee, uint24 lpFee);
        }
        contract StateView {
            IPoolManager public poolManager;
            function getSlot0(bytes32 poolId)
                external view returns (uint160 sqrtPriceX96, int24 tick, uint24 protocolFee, uint24 lpFee)
            {
                return poolManager.getSlot0(poolId);
            }
        }
    "#;

    #[test]
    fn view_passthrough_getslot0_is_silent() {
        let fs = run(VIEW_PASSTHROUGH_GETSLOT0);
        assert!(
            !fs.iter().any(|f| f.detector == "twap-manipulation"),
            "a pure view slot0 passthrough getter must not fire (not a price consumer): {:?}",
            fs.iter().filter(|f| f.detector == "twap-manipulation").collect::<Vec<_>>()
        );
    }

    // Real shape (Uniswap v4-periphery `PositionDescriptor.tokenURI`): reads slot0
    // for the current `tick`, but the tick is only used to render an NFT metadata
    // data-URI *string*. Display, not a financial decision — must be SILENT.
    const TOKENURI_METADATA: &str = r#"
        interface IPoolManager {
            function getSlot0(bytes32 id) external view returns (uint160, int24, uint24, uint24);
        }
        library Descriptor { function build(int24 tick) internal pure returns (string memory) {} }
        contract PositionDescriptor {
            IPoolManager public poolManager;
            function tokenURI(bytes32 poolId, uint256 tokenId) external view returns (string memory) {
                (, int24 tick,,) = poolManager.getSlot0(poolId);
                return Descriptor.build(tick);
            }
        }
    "#;

    #[test]
    fn tokenuri_metadata_is_silent() {
        let fs = run(TOKENURI_METADATA);
        assert!(
            !fs.iter().any(|f| f.detector == "twap-manipulation"),
            "a tokenURI metadata getter (string return) must not fire: {:?}",
            fs.iter().filter(|f| f.detector == "twap-manipulation").collect::<Vec<_>>()
        );
    }

    // Over-suppression guard: a *consuming* `view` getter with a generic name that
    // actually derives a value from slot0 (a valuation calculation `sqrtP * sqrtP`)
    // is a genuine spot-price consumer and MUST still fire — the passthrough
    // suppression must not silence a real spot-price valuation.
    const VIEW_CONSUMER_VALUES_SLOT0: &str = r#"
        interface IPoolManager {
            function getSlot0(bytes32 id) external view returns (uint160 sqrtPriceX96, int24 tick, uint24, uint24);
        }
        contract Lending {
            IPoolManager public poolManager;
            function check(bytes32 poolId) external view returns (uint256 collateralValue) {
                (uint160 sqrtP,,,) = poolManager.getSlot0(poolId);
                // derive a price from the *instantaneous* sqrtPrice — manipulable
                collateralValue = (uint256(sqrtP) * uint256(sqrtP)) >> 96;
            }
        }
    "#;

    #[test]
    fn view_consumer_that_values_slot0_still_fires() {
        let fs = run(VIEW_CONSUMER_VALUES_SLOT0);
        assert!(
            fs.iter().any(|f| f.detector == "twap-manipulation"),
            "a view getter that derives a value from slot0 must still fire: {:?}",
            fs
        );
    }

    // ---- Lexical-FP fix: oracle reads are matched by CALL, not by substring ----

    // Real shape (Lido `TokenRateNotifier.removeObserver`): a pure `onlyOwner`
    // array `pop()` that maintains an event-`observers` list. It contains the
    // SUBSTRING "observe" in the identifiers `removeObserver`/`observers`/
    // `_observerIndex`, but computes NO price and never calls `observe`/`consult`
    // /`slot0`/a cumulative getter. The old `source.contains("observe")` gate
    // false-fired High here; with call-based classification it must be SILENT.
    const EVENT_OBSERVER_REMOVE: &str = r#"
        interface ITokenRatePusher { function pushTokenRate() external; }
        contract TokenRateNotifier {
            address[] public observers;
            uint256 public constant INDEX_NOT_FOUND = type(uint256).max;
            function _observerIndex(address observer_) internal view returns (uint256) {
                uint256 len = observers.length;
                for (uint256 i = 0; i < len; i++) {
                    if (observers[i] == observer_) return i;
                }
                return INDEX_NOT_FOUND;
            }
            function removeObserver(address observer_) external {
                uint256 idx = _observerIndex(observer_);
                require(idx != INDEX_NOT_FOUND, "no observer");
                if (idx != observers.length - 1) {
                    observers[idx] = observers[observers.length - 1];
                }
                observers.pop();
            }
        }
    "#;

    #[test]
    fn event_observer_remove_is_silent() {
        let fs = run(EVENT_OBSERVER_REMOVE);
        assert!(
            !fs.iter().any(|f| f.detector == "twap-manipulation"),
            "an event-observer `removeObserver` array pop with no oracle call must \
             not fire (substring \"observe\" is not an oracle read): {:?}",
            fs.iter().filter(|f| f.detector == "twap-manipulation").collect::<Vec<_>>()
        );
    }

    // Real shape (Uniswap-V2 cumulative TWAP, the Mango/cumulative class): a
    // genuine `price0CumulativeLast` read off a pair handle, differenced over an
    // unbounded interval and used as a price. This is a real, hand-rolled TWAP
    // oracle read (a CALL on a handle, not an identifier substring) and MUST fire.
    const V2_CUMULATIVE_TWAP: &str = r#"
        interface IUniswapV2Pair {
            function price0CumulativeLast() external view returns (uint256);
        }
        contract V2Oracle {
            IUniswapV2Pair public pair;
            uint256 public lastCumulative;
            uint32 public lastTimestamp;
            function consultPrice() external view returns (uint256 price) {
                uint256 current = pair.price0CumulativeLast();
                uint256 elapsed = block.timestamp - lastTimestamp;
                price = (current - lastCumulative) / elapsed;
            }
        }
    "#;

    #[test]
    fn v2_cumulative_price_read_fires() {
        let fs = run(V2_CUMULATIVE_TWAP);
        assert!(
            fs.iter().any(|f| f.detector == "twap-manipulation"),
            "a genuine price0CumulativeLast TWAP read used for a price must still fire: {:?}",
            fs
        );
    }

    // ---- Pump/oracle reserve-reader class (the Basin MultiFlowPump shape) ----

    // Vulnerable (real shape: Basin `MultiFlowPump.readLastReserves`): a Pump/oracle
    // contract whose oracle surface is a `read*Reserves` getter handing back the
    // *last-stored* geometric-mean reserves (written by a single `update`). It calls
    // none of slot0/observe/consult/a cumulative getter — the Uniswap path never sees
    // it — yet integrators consume it as a price, and a single same/adjacent-block
    // swap before the read moves the reported reserves. MUST fire.
    const PUMP_LAST_RESERVES: &str = r#"
        interface IPump {}
        interface IInstantaneousPump {}
        library LibLastReserveBytes {
            function readLastReserves(bytes32 slot) internal pure returns (uint8, uint40, bytes16[] memory) {}
        }
        contract MultiFlowPump is IPump, IInstantaneousPump {
            using LibLastReserveBytes for bytes32;
            function readLastReserves(address well) public view returns (uint256[] memory reserves) {
                bytes32 slot = bytes32(bytes20(well));
                (uint8 n,, bytes16[] memory bytesReserves) = slot.readLastReserves();
                reserves = new uint256[](n);
                for (uint256 i; i < n; ++i) {
                    reserves[i] = uint256(uint128(bytesReserves[i]));
                }
            }
        }
    "#;

    #[test]
    fn pump_last_reserves_reader_fires() {
        let fs = run(PUMP_LAST_RESERVES);
        let hit: Vec<_> = fs.iter().filter(|f| f.detector == "twap-manipulation").collect();
        assert!(
            hit.iter().any(|f| f.function == "readLastReserves"),
            "a pump/oracle last-reserves reader (single-update-manipulable, no window) must fire: {:?}",
            fs
        );
    }

    // Safe (the genuine TWA surface on the SAME pump): a `readTwaReserves` reader that
    // takes a caller-supplied start checkpoint + `startTimestamp` and divides the
    // cumulative-reserve delta by a non-zero elapsed window (reverting on zero). This
    // is the protocol's correct manipulation-resistant read; its name contains `twa`
    // and it is a cumulative consumer — MUST stay silent.
    const PUMP_TWA_RESERVES: &str = r#"
        interface ICumulativePump {}
        contract MultiFlowPump is ICumulativePump {
            error NoTimePassed();
            function _readCumulativeReserves(address) internal view returns (bytes16[] memory) {}
            function readTwaReserves(
                address well,
                bytes calldata startCumulativeReserves,
                uint256 startTimestamp,
                bytes memory
            ) public view returns (uint256[] memory twaReserves) {
                bytes16[] memory cum = _readCumulativeReserves(well);
                bytes16[] memory startCum = abi.decode(startCumulativeReserves, (bytes16[]));
                uint256 deltaTimestamp = block.timestamp - startTimestamp;
                if (deltaTimestamp == 0) revert NoTimePassed();
                twaReserves = new uint256[](cum.length);
                for (uint256 i; i < cum.length; ++i) {
                    twaReserves[i] = uint256(uint128(cum[i]) - uint128(startCum[i])) / deltaTimestamp;
                }
            }
        }
    "#;

    #[test]
    fn pump_twa_reserves_reader_is_silent() {
        let fs = run(PUMP_TWA_RESERVES);
        assert!(
            !fs.iter().any(|f| f.detector == "twap-manipulation"),
            "the genuine time-weighted-average (`readTwaReserves`) surface must not fire: {:?}",
            fs.iter().filter(|f| f.detector == "twap-manipulation").collect::<Vec<_>>()
        );
    }

    // Safe (the Comet false-positive guard): a money-market `getReserves()` returning
    // a single `int` of *protocol-treasury* reserves — NOT a pool oracle. The owning
    // contract carries no `pump`/`oracle` marker, so the pump-reader class must not
    // claim it. MUST stay silent (this is the precision gate the dogfood relies on).
    const NON_ORACLE_GETRESERVES: &str = r#"
        interface IERC20 { function balanceOf(address) external view returns (uint256); }
        contract Comet {
            address public baseToken;
            uint256 public totalSupplyBase;
            uint256 public totalBorrowBase;
            function getReserves() public view returns (int) {
                uint256 balance = IERC20(baseToken).balanceOf(address(this));
                return int(balance) - int(totalSupplyBase) + int(totalBorrowBase);
            }
        }
    "#;

    #[test]
    fn non_oracle_getreserves_is_silent() {
        let fs = run(NON_ORACLE_GETRESERVES);
        assert!(
            !fs.iter().any(|f| f.detector == "twap-manipulation"),
            "a money-market getReserves (no pump/oracle contract marker) must not fire: {:?}",
            fs.iter().filter(|f| f.detector == "twap-manipulation").collect::<Vec<_>>()
        );
    }

    // Over-suppression guard within the pump class: a pump reserve reader that DOES
    // enforce a meaningful minimum averaging window (a `>= 1800` lower bound on a
    // caller-supplied window) is properly guarded and MUST stay silent — the window
    // suppression must apply to the pump-reader path too.
    const PUMP_RESERVES_WINDOWED: &str = r#"
        interface IPump {}
        contract WindowedPump is IPump {
            function readReserves(address well, uint256 window) public view returns (uint256[] memory reserves) {
                require(window >= 1800, "window too short");
                reserves = new uint256[](2);
                reserves[0] = window;
            }
        }
    "#;

    #[test]
    fn pump_reserves_reader_with_window_bound_is_silent() {
        let fs = run(PUMP_RESERVES_WINDOWED);
        assert!(
            !fs.iter().any(|f| f.detector == "twap-manipulation"),
            "a pump reserve reader enforcing a >= 1800s window must not fire: {:?}",
            fs.iter().filter(|f| f.detector == "twap-manipulation").collect::<Vec<_>>()
        );
    }
}
