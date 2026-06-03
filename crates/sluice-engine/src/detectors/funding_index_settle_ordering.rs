//! Funding-index settle ordering: a state-mutating path realizes a position's
//! funding payment — or makes a solvency / liquidation decision — against the
//! **global cumulative-funding index without first advancing it** through the
//! interval-gated settle routine.
//!
//! A perpetuals venue tracks a *global* cumulative-funding index
//! (`cumulativeFundingIndex` / `cumulativeFunding` / a `fundingIndex`) that the
//! protocol advances on a time/interval cadence via a settle routine
//! (`settleFunding()` / `_settleFunding()` / `updateFunding()`), which is gated
//! (`assertFundingIntervalElapsed` → `FundingIntervalNotElapsed`) and writes the
//! freshness marker (`lastFundingTime = block.timestamp`) plus the new index back
//! to storage. A position's owed funding is
//!
//! ```text
//! payment = posAmount * (globalCumulativeFunding − position.lastCumulativeFunding)
//! ```
//!
//! so the *global* index must be brought current before that payment is realized
//! and before any margin / liquidation verdict is taken against the resulting
//! equity. This is the funding analog of the lending **interest-index-desync**
//! class — but on a time/interval-gated index rather than a per-block accumulator.
//!
//! When a **state-mutating, externally-reachable** path realizes funding (calls a
//! `realizeFundingPayment` / `getFundingPayment` helper, or reads the global
//! `*cumulativeFunding*` / `*fundingIndex*` state) **and** on the same path makes a
//! liquidation / solvency decision (`isLiquidatable` / `assertLiquidatable` /
//! `hasBadDebt` / a `minMargin`-style comparison) — *without* first calling the
//! interval-gated settle routine (or itself persisting the global index /
//! `lastFundingTime` before the decision) — the funding payment and the verdict
//! are computed against a **stale** global index: the delta since the last settle
//! is dropped on this call and re-accrued on the next interaction, so a position
//! that is in fact liquidatable can read as solvent (or vice-versa) for the
//! duration of the un-advanced interval.
//!
//! This is the GTE-perps shape: `LiquidatorPanel.liquidate` /
//! `backstopLiquidate` / `delistClose` / `deleverage` reach
//! `_setupAccountAndValidateLiquidation` (and friends), which do
//! `margin -= realizeFundingPayment(...)` then `assertLiquidatable(...)` against
//! `FundingRateEngine.getCumulativeFunding()` — the *current* index — while the
//! only routine that advances that index, `FundingRateEngine.settleFunding`
//! (gated on the funding interval), is invoked elsewhere on a keeper cadence
//! (`AdminPanel.settleFunding`). The SlowMist "Funding Fee Accumulation Check".
//!
//! Precision (false-positive suppression) — every one of these must hold:
//!   * the owning contract declares a **funding-index construct** — a state var /
//!     struct field matching `*cumulativeFunding*` / `*fundingIndex*`, or the file
//!     calls a `realizeFundingPayment` / `getFundingPayment` helper (so this is a
//!     perps funding venue, not an arbitrary contract);
//!   * the function is externally reachable AND **state-mutating** (a `view` /
//!     `pure` quote — `getPendingFundingPayment`, `getAccountValue`,
//!     `ClearingHouse.isLiquidatable(view)` — is correct and stays silent);
//!   * the path (the function body, or a resolved same-contract internal callee)
//!     realizes funding or reads the global cumulative-funding index, AND makes a
//!     liquidation / solvency decision (or writes a position field);
//!   * the path does **not** advance + persist the global index first — neither
//!     the function nor a resolved callee calls a `settleFunding` / `updateFunding`
//!     routine, and it does not itself write a global `cumulativeFundingIndex` /
//!     `lastFundingTime` before the decision. A path that settles first is the
//!     safe shape and is suppressed.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::Function;

use super::prelude::*;

pub struct FundingIndexSettleOrderingDetector;

/// Internal-call / source markers that the path **realizes a position's funding
/// payment** — the read of the global index netted against the per-position
/// `lastCumulativeFunding` checkpoint.
const REALIZE_FUNDING_MARKERS: &[&str] = &[
    "realizefundingpayment",
    "getfundingpayment",
    "_realizefunding",
    "applyfunding",
    "_applyfunding",
    "settlefundingpayment",
];

/// Internal-call / source markers, and state-var name fragments, that evidence a
/// read of the **global cumulative-funding index** itself.
const CUMULATIVE_FUNDING_READ_MARKERS: &[&str] = &[
    "getcumulativefunding",
    "cumulativefunding",
    "cumulativefundingindex",
    "fundingindex",
    "globalfunding",
];

/// Internal-call / source markers that the path makes a **liquidation / solvency
/// decision** — the verdict that must not be priced on a stale funding index.
const LIQUIDATION_DECISION_MARKERS: &[&str] = &[
    "isliquidatable",
    "assertliquidatable",
    "assertnotliquidatable",
    "hasbaddebt",
    "minmargin",
    "minopenmargin",
    "isopenmarginrequirementmet",
    "assertopenmarginrequired",
    "assertpostwithdrawalmarginrequired",
    "maintenancemargin",
];

/// Position-field write markers — the §1 "(b) writes a position field" arm. A
/// path that realizes funding and then mutates one of these has committed a
/// position update priced on the (possibly stale) index.
const POSITION_FIELD_MARKERS: &[&str] = &[
    "opennotional",
    "lastcumulativefunding",
];

/// Internal-call / source markers for the **interval-gated settle routine** that
/// advances + persists the global funding index. Presence of any of these on the
/// path (function or resolved callee) is the safe shape → suppress.
const SETTLE_FUNDING_MARKERS: &[&str] = &[
    "settlefunding",
    "_settlefunding",
    "updatefunding",
    "_updatefunding",
    "pokefunding",
    "_pokefunding",
    "accruefunding",
    "_accruefunding",
];

/// Does `contract` declare a funding-index construct — a state variable (or, by
/// name, a struct field surfaced as a state var) matching `*cumulativeFunding*`
/// / `*fundingIndex*`? This is the per-contract gate that makes the path a perps
/// funding venue rather than an arbitrary contract. Kept LOCAL to this module.
fn declares_funding_index_var(contract: &sluice_ir::Contract) -> bool {
    contract.state_vars.iter().any(|v| {
        let l = v.name.to_ascii_lowercase();
        (l.contains("cumulativefunding") || l.contains("fundingindex"))
            // exclude the *per-position* checkpoint field name on its own
            && l != "lastcumulativefunding"
    })
}

/// True if any marker in `markers` appears as a resolved internal-call name (in
/// `lc_internal`) or as a substring of `src` (comment-stripped, lowercased).
fn path_mentions(lc_internal: &[String], src: &str, markers: &[&str]) -> bool {
    lc_internal.iter().any(|n| markers.iter().any(|m| n.contains(m)))
        || markers.iter().any(|m| src.contains(m))
}

impl Detector for FundingIndexSettleOrderingDetector {
    fn id(&self) -> &'static str {
        "funding-index-settle-ordering"
    }
    fn category(&self) -> Category {
        Category::FundingIndexSettleOrdering
    }
    fn description(&self) -> &'static str {
        "State-mutating funding realization / liquidation decision priced on the global cumulative-funding index without first advancing it via the interval-gated settle routine"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || !f.is_externally_reachable() {
                continue;
            }
            // A `view` / `pure` quote that realizes funding / reads the index is
            // the intended use (the pending-funding / account-value getters,
            // `isLiquidatable(view)`) and is correct — only a *state-mutating*
            // decision is priced wrong.
            if !f.is_state_mutating() {
                continue;
            }
            // Interface / abstract declarations have no body shape to price.
            let Some(contract) = cx.contract_of(f.id) else { continue };
            if contract.is_interface() {
                continue;
            }

            // ---- per-contract gate: a funding-index construct must be declared,
            //      or a funding-realize helper used somewhere in this contract ----
            if !contract_is_funding_venue(cx, contract) {
                continue;
            }

            // Collect the path's internal-call names + the source text of the
            // function and of every resolved same-contract internal callee with a
            // body. The cross-library `using L for T` helpers (`realizeFundingPayment`,
            // `assertLiquidatable`, `settleFunding`) surface as internal-call NAMES
            // here; the same-contract private helpers (`_setupAccountAndValidate…`,
            // `_liquidate`) surface as resolved `callees` whose own internal-calls /
            // source we fold in.
            let lc_internal = path_internal_calls(cx, f);
            let src = path_source(cx, f);

            // ---- the safe shape: the path advances + persists the global index
            //      first (a settle routine, or a global index / lastFundingTime
            //      write) → suppress ----
            let settles_first = path_mentions(&lc_internal, &src, SETTLE_FUNDING_MARKERS)
                || persists_global_funding_index(cx, f);
            if settles_first {
                continue;
            }

            // ---- (a) realizes funding OR reads the global cumulative-funding index ----
            let realizes_funding = path_mentions(&lc_internal, &src, REALIZE_FUNDING_MARKERS);
            let reads_cumulative_funding =
                path_mentions(&lc_internal, &src, CUMULATIVE_FUNDING_READ_MARKERS)
                    || reads_funding_index_var(cx, f);
            if !realizes_funding && !reads_cumulative_funding {
                continue;
            }

            // ---- (b) makes a liquidation / solvency decision OR writes a position
            //          field on the same path ----
            let makes_liq_decision = path_mentions(&lc_internal, &src, LIQUIDATION_DECISION_MARKERS);
            let writes_position_field =
                path_mentions(&lc_internal, &src, POSITION_FIELD_MARKERS) || writes_position_field_var(cx, f);
            if !makes_liq_decision && !writes_position_field {
                continue;
            }

            // Report at the funding-realize / decision call site if we can place it
            // precisely, else the function span.
            let span = decision_or_realize_span(f).unwrap_or(f.span);

            let b = report!(self, Category::FundingIndexSettleOrdering,
                title = "Funding realized / liquidation decided on the global funding index without first advancing it",
                severity = Severity::High,
                confidence = 0.55,
                dimensions = [Dimension::Invariant, Dimension::ValueFlow],
                message = format!(
                    "`{}` is state-mutating and externally reachable: on this path it realizes a \
                     position's funding payment (or reads the global cumulative-funding index) and \
                     makes a solvency / liquidation decision against it, but does NOT first advance \
                     that index through the interval-gated settle routine \
                     (`settleFunding()` / `updateFunding()`) — nor does it persist the global \
                     `cumulativeFundingIndex` / `lastFundingTime` before the decision. The funding \
                     payment, and the margin/liquidation verdict taken from it, are therefore priced \
                     against a STALE global index: the funding accrued since the last settle is \
                     dropped on this call and re-accrued on the next interaction, so an account that \
                     is actually liquidatable can read as solvent (or be over-charged) for the \
                     un-advanced interval. The funding analog of the interest-index-desync class \
                     (`payment = amount * (globalCumulativeFunding − position.lastCumulativeFunding)`).",
                    f.name
                ),
                recommendation =
                    "On any state-mutating path that realizes funding or decides solvency / \
                     liquidation, advance the global funding index first — call the interval-gated \
                     settle routine (`settleFunding()` / `updateFunding()`) which writes the new \
                     `cumulativeFundingIndex` and `lastFundingTime = block.timestamp` — and read the \
                     freshly-settled index, so the per-position funding delta and the resulting \
                     margin/liquidation verdict are computed against a current index. Reserve the \
                     un-advanced read for `view` quotes.",
            );
            out.push(finish_at(cx, b, f.id, span));
        }
        out
    }
}

// ------------------------------------------------------------------- helpers

/// Is the owning contract a perps **funding venue** — does it declare a
/// funding-index state var, or does it (or this function) use a funding-realize
/// helper? We accept either the structural state-var gate or a textual marker in
/// the contract span (a `using FundingLib`-bound contract may keep the index in a
/// library struct rather than a direct state var).
fn contract_is_funding_venue(cx: &AnalysisContext, contract: &sluice_ir::Contract) -> bool {
    if declares_funding_index_var(contract) {
        return true;
    }
    // Textual fallback over the (comment-stripped, lowercased) contract source:
    // a funding-index field, a realize/get-funding helper, or a settle routine
    // mentioned anywhere in this contract marks it as a funding venue.
    let csrc = cx.source_text(contract.span);
    CUMULATIVE_FUNDING_READ_MARKERS.iter().any(|m| csrc.contains(m))
        || REALIZE_FUNDING_MARKERS.iter().any(|m| csrc.contains(m))
        || SETTLE_FUNDING_MARKERS.iter().any(|m| csrc.contains(m))
}

/// The `Function`s on `f`'s path: `f` itself plus every **transitively** resolved
/// same-contract internal callee with a body, collected by a bounded, cycle-safe
/// BFS over `Function::callees`. The realize/decision markers in the GTE
/// liquidation entries live two hops down (`liquidate` → `_liquidate` →
/// `_setupAccountAndValidateLiquidation`; `deleverage` → `_deleveragePair` →
/// `_validateDeleveragePair`), so a one-level fold is not enough. The walk is
/// bounded (depth + node cap) so it stays cheap and order-independent.
fn path_bodies<'a>(cx: &'a AnalysisContext, f: &'a Function) -> Vec<&'a Function> {
    use std::collections::HashSet;
    const MAX_NODES: usize = 64;
    const MAX_DEPTH: u32 = 6;
    let mut seen: HashSet<sluice_ir::FunctionId> = HashSet::new();
    let mut out: Vec<&Function> = Vec::new();
    let mut stack: Vec<(sluice_ir::FunctionId, u32)> = vec![(f.id, 0)];
    seen.insert(f.id);
    while let Some((id, depth)) = stack.pop() {
        let Some(g) = cx.scir.function(id) else { continue };
        out.push(g);
        if out.len() >= MAX_NODES || depth >= MAX_DEPTH {
            continue;
        }
        for &c in &g.callees {
            if seen.insert(c) {
                stack.push((c, depth + 1));
            }
        }
    }
    out
}

/// The lowercased internal-call names on the path: the union over [`path_bodies`]
/// of each function's `internal_calls`. (`using L for T` library helpers surface
/// as names here; same-contract private helpers are folded in transitively.)
fn path_internal_calls(cx: &AnalysisContext, f: &Function) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for g in path_bodies(cx, f) {
        out.extend(g.effects.internal_calls.iter().map(|n| n.to_ascii_lowercase()));
    }
    out
}

/// The path source text: the (comment-stripped, lowercased) source of every
/// function in [`path_bodies`], concatenated. Lets a marker that lives in a
/// transitive private helper (`_setupAccountAndValidateLiquidation`) be seen from
/// the externally-reachable entry that reaches it.
fn path_source(cx: &AnalysisContext, f: &Function) -> String {
    let mut s = String::new();
    for g in path_bodies(cx, f) {
        s.push('\n');
        s.push_str(&cx.source_text(g.span));
    }
    s
}

/// Does any function on the path **read** a state var whose name matches the
/// global funding index? (the structural twin of the `*cumulativeFunding*` source
/// marker.)
fn reads_funding_index_var(cx: &AnalysisContext, f: &Function) -> bool {
    let is_idx = |name: &str| {
        let l = name.to_ascii_lowercase();
        (l.contains("cumulativefunding") || l.contains("fundingindex")) && l != "lastcumulativefunding"
    };
    path_bodies(cx, f).iter().any(|g| g.effects.storage_reads.iter().any(|a| is_idx(&a.var)))
}

/// Does any function on the path **write** a position field (`openNotional` /
/// `lastCumulativeFunding`) — the §1 "(b) writes a position field" structural arm?
/// `amount` / `margin` are intentionally NOT matched as bare state-var names (too
/// generic); the textual markers cover the member-write forms.
fn writes_position_field_var(cx: &AnalysisContext, f: &Function) -> bool {
    let is_pos = |name: &str| {
        let l = name.to_ascii_lowercase();
        l.contains("opennotional") || l.contains("lastcumulativefunding")
    };
    path_bodies(cx, f).iter().any(|g| g.effects.storage_writes.iter().any(|w| is_pos(&w.var)))
}

/// Does any function on the path itself persist the **global** funding index — a
/// write to a `cumulativeFundingIndex` / `cumulativeFunding` / `fundingIndex` /
/// `lastFundingTime` state var? Such a function *is* (or contains) the settle, so
/// it must not be flagged. The per-position checkpoint (`lastCumulativeFunding`)
/// is excluded — writing it is the *symptom* being detected, not the global
/// advance.
fn persists_global_funding_index(cx: &AnalysisContext, f: &Function) -> bool {
    let is_global_index_write = |name: &str| {
        let l = name.to_ascii_lowercase();
        if l.contains("lastcumulativefunding") {
            return false; // per-position checkpoint, not the global index
        }
        l.contains("cumulativefundingindex")
            || l.contains("cumulativefunding")
            || l.contains("fundingindex")
            || l.contains("lastfundingtime")
    };
    path_bodies(cx, f).iter().any(|g| g.effects.storage_writes.iter().any(|w| is_global_index_write(&w.var)))
}

/// Best-effort span of the funding-realize / liquidation-decision call site, so
/// the finding points at the stale-priced operation rather than the whole
/// function. Prefers a realize/decision call in the function body; falls back to
/// `None` (caller uses the function span).
fn decision_or_realize_span(f: &Function) -> Option<sluice_ir::Span> {
    first_call_where(f, |c| {
        c.func_name
            .as_deref()
            .map(|n| {
                let l = n.to_ascii_lowercase();
                REALIZE_FUNDING_MARKERS.iter().any(|m| l.contains(m))
                    || LIQUIDATION_DECISION_MARKERS.iter().any(|m| l.contains(m))
                    || CUMULATIVE_FUNDING_READ_MARKERS.iter().any(|m| l.contains(m))
            })
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // VULN — the GTE-shaped liquidation path: a state-mutating, externally
    // reachable `liquidate` realizes the position's funding payment
    // (`realizeFundingPayment`, which reads the global `cumulativeFunding`) and
    // then makes a liquidation verdict (`assertLiquidatable`) — without first
    // advancing the global index via `settleFunding`. The index is only moved by
    // the separate keeper entry `settleFunding(asset)`.
    const VULN: &str = r#"
        pragma solidity 0.8.27;
        contract PerpEngine {
            struct Position { uint256 amount; uint256 openNotional; int256 lastCumulativeFunding; }
            int256 public cumulativeFundingIndex;
            uint256 public lastFundingTime;
            mapping(address => Position) position;

            function getCumulativeFunding() internal view returns (int256) { return cumulativeFundingIndex; }

            function realizeFundingPayment(address acct) internal returns (int256 p) {
                Position storage pos = position[acct];
                int256 g = getCumulativeFunding();
                p = int256(pos.amount) * (g - pos.lastCumulativeFunding) / 1e18;
                pos.lastCumulativeFunding = g;
            }

            function isLiquidatable(address acct, int256 margin) internal view returns (bool) {
                Position storage pos = position[acct];
                uint256 minMargin = pos.openNotional / 10;
                return margin < int256(minMargin);
            }
            function assertLiquidatable(address acct, int256 margin) internal view {
                require(isLiquidatable(acct, margin), "not liquidatable");
            }

            // VULNERABLE: realizes funding + liquidation decision on the un-advanced index.
            function liquidate(address acct, int256 margin) external {
                margin -= realizeFundingPayment(acct);
                assertLiquidatable(acct, margin);
                delete position[acct];
            }

            // The ONLY routine that advances the global index — interval gated,
            // invoked on a keeper cadence, NOT on the liquidation path.
            function settleFunding(int256 fundingIndexDelta) external {
                require(block.timestamp > lastFundingTime + 1 hours, "interval");
                lastFundingTime = block.timestamp;
                cumulativeFundingIndex += fundingIndexDelta;
            }
        }
    "#;

    // SAFE — same protocol, but `liquidate` advances + persists the global index
    // (`settleFunding()`) BEFORE realizing funding and deciding. This is the
    // corrected ordering and must stay silent.
    const SAFE_SETTLED: &str = r#"
        pragma solidity 0.8.27;
        contract PerpEngine {
            struct Position { uint256 amount; uint256 openNotional; int256 lastCumulativeFunding; }
            int256 public cumulativeFundingIndex;
            uint256 public lastFundingTime;
            mapping(address => Position) position;

            function getCumulativeFunding() internal view returns (int256) { return cumulativeFundingIndex; }

            function _settleFunding(int256 fundingIndexDelta) internal {
                lastFundingTime = block.timestamp;
                cumulativeFundingIndex += fundingIndexDelta;
            }

            function realizeFundingPayment(address acct) internal returns (int256 p) {
                Position storage pos = position[acct];
                int256 g = getCumulativeFunding();
                p = int256(pos.amount) * (g - pos.lastCumulativeFunding) / 1e18;
                pos.lastCumulativeFunding = g;
            }

            function isLiquidatable(address acct, int256 margin) internal view returns (bool) {
                Position storage pos = position[acct];
                uint256 minMargin = pos.openNotional / 10;
                return margin < int256(minMargin);
            }
            function assertLiquidatable(address acct, int256 margin) internal view {
                require(isLiquidatable(acct, margin), "not liquidatable");
            }

            // SAFE: advances the index first, THEN realizes + decides.
            function liquidate(address acct, int256 margin, int256 fundingIndexDelta) external {
                _settleFunding(fundingIndexDelta);
                margin -= realizeFundingPayment(acct);
                assertLiquidatable(acct, margin);
                delete position[acct];
            }
        }
    "#;

    // SAFE — a pure VIEW quote that realizes funding (in-memory) and computes a
    // liquidation verdict is correct (no state decision is committed). Must stay
    // silent on the `view` gate.
    const SAFE_VIEW_QUOTE: &str = r#"
        pragma solidity 0.8.27;
        contract PerpEngine {
            struct Position { uint256 amount; uint256 openNotional; int256 lastCumulativeFunding; }
            int256 public cumulativeFundingIndex;
            uint256 public lastFundingTime;
            mapping(address => Position) position;

            function getCumulativeFunding() internal view returns (int256) { return cumulativeFundingIndex; }

            function getFundingPayment(address acct) internal view returns (int256 p) {
                Position storage pos = position[acct];
                int256 g = getCumulativeFunding();
                p = int256(pos.amount) * (g - pos.lastCumulativeFunding) / 1e18;
            }

            function isLiquidatable(address acct, int256 margin) public view returns (bool) {
                int256 fundingPayment = getFundingPayment(acct);
                Position storage pos = position[acct];
                uint256 minMargin = pos.openNotional / 10;
                return (margin - fundingPayment) < int256(minMargin);
            }
        }
    "#;

    // SAFE-ish (out of scope) — a funding venue, but this state-mutating entry is
    // the SETTLE routine itself: it advances the global index and makes no
    // liquidation decision. Must stay silent.
    const SAFE_SETTLE_ENTRY: &str = r#"
        pragma solidity 0.8.27;
        contract PerpEngine {
            int256 public cumulativeFundingIndex;
            uint256 public lastFundingTime;
            function realizeFundingPayment(address acct) internal returns (int256) { return 0; }
            function settleFunding(int256 fundingIndexDelta) external {
                require(block.timestamp > lastFundingTime + 1 hours, "interval");
                lastFundingTime = block.timestamp;
                cumulativeFundingIndex += fundingIndexDelta;
            }
        }
    "#;

    // NEGATIVE — not a funding venue at all (no funding-index construct, no
    // realize helper). A liquidation-shaped lending function must NOT trip this
    // perps detector (that is interest-index-desync's job).
    const NEG_NOT_PERPS: &str = r#"
        pragma solidity 0.8.15;
        contract Lender {
            mapping(address => uint256) debt;
            uint256 public borrowIndex;
            function isLiquidatable(address u) internal view returns (bool) { return debt[u] > 0; }
            function liquidate(address u) external {
                require(isLiquidatable(u), "healthy");
                delete debt[u];
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(
            fs.iter().any(|f| f.detector == "funding-index-settle-ordering" && f.function == "liquidate"),
            "expected a finding on liquidate; got {:#?}",
            fs.iter().map(|f| (&f.detector, &f.function)).collect::<Vec<_>>()
        );
        // The keeper settle entry must NOT be flagged.
        assert!(
            !fs.iter().any(|f| f.detector == "funding-index-settle-ordering" && f.function == "settleFunding"),
            "settleFunding (the advance routine) should be silent"
        );
    }

    #[test]
    fn silent_when_settled_first() {
        let fs = run(SAFE_SETTLED);
        assert!(
            !fs.iter().any(|f| f.detector == "funding-index-settle-ordering"),
            "{:#?}",
            fs.iter().map(|f| (&f.detector, &f.function)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn silent_on_view_quote() {
        let fs = run(SAFE_VIEW_QUOTE);
        assert!(
            !fs.iter().any(|f| f.detector == "funding-index-settle-ordering"),
            "{:#?}",
            fs.iter().map(|f| (&f.detector, &f.function)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn silent_on_settle_entry() {
        let fs = run(SAFE_SETTLE_ENTRY);
        assert!(!fs.iter().any(|f| f.detector == "funding-index-settle-ordering"), "{:#?}", fs);
    }

    #[test]
    fn silent_on_non_perps_lender() {
        let fs = run(NEG_NOT_PERPS);
        assert!(
            !fs.iter().any(|f| f.detector == "funding-index-settle-ordering"),
            "perps detector must not fire on a lending contract; {:#?}",
            fs.iter().map(|f| (&f.detector, &f.function)).collect::<Vec<_>>()
        );
    }
}
