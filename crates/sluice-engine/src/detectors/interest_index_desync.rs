//! Interest-index desync: a state-mutating lending decision (borrow / repay /
//! withdraw / liquidate) prices a position on a **stale interest accumulator**.
//!
//! A lending market tracks each account's debt as a checkpoint plus an interest
//! *accumulator* (a monotonically-growing index — `interestAccumulatorRay` /
//! `borrowIndex` / `rewardPerToken`). The account's live debt is
//! `debtCheckpoint * globalAccumulator / accountAccumulator`, so the *global*
//! accumulator must be brought current — its freshness timestamp written
//! (`interestAccumulatorUpdatedAt = block.timestamp`) by an accrue/sync routine
//! (`accrueInterest()` / `_globalStateRW()`) — before any solvency decision is
//! made against it. The protocol therefore exposes two readers of the global
//! state:
//!
//!   * a **read-write** accessor (`_globalStateRW()`) that compounds the
//!     accumulator to `block.timestamp` *and writes it back to storage* — the
//!     one a state-mutating path must use; and
//!   * a **read-only / cached** accessor (`_globalStateRO()` / a
//!     `GlobalStateCache`) that compounds *in memory only* and never persists
//!     the freshness write — intended for `view` quotes.
//!
//! When a **state-mutating** borrow/repay/withdraw/liquidate path reads the
//! debt / LTV / health / maxDebt from the **read-only / cached** accessor and
//! gates a `require` / branch / transfer on it *without* a preceding accrue/sync
//! of that accumulator in the same function, the decision is priced on a stale
//! index. Because the cached accessor compounds in memory it can even read
//! *correctly for this call* yet leave `interestAccumulatorUpdatedAt` behind, so
//! the very next interaction re-compounds interest over an overlapping window —
//! double-counting (over-charge) — or, symmetrically, a withdraw/borrow that
//! caches a not-yet-persisted index lets the account's snapshot diverge from the
//! global one, under-pricing debt and letting the position exceed the
//! origination/liquidation LTV. The fix is to call the read-write
//! accrue/checkpoint (`_globalStateRW()` / `accrueInterest()`) on this path, as
//! the borrow/repay siblings do.
//!
//! This is the Olympus **MonoCooler** `withdrawCollateral` shape: it reads
//! `_globalStateRO()` and then validates the new LTV against
//! `gStateCache.maxOriginationLtv` and a `_currentAccountDebt(...)` derived from
//! the un-synced accumulator, whereas `borrow` / `repay` /
//! `applyUnhealthyDelegations` / `batchLiquidate` all use `_globalStateRW()`.
//!
//! Precision (false-positive suppression) — every one of these must hold:
//!   * the function is externally reachable AND **state-mutating** (a `view`
//!     quote that reads the RO accessor is correct and stays silent);
//!   * it reads an interest **accumulator / cached global state** through a
//!     read-only accessor (or reads an interest-index state var) AND uses it for
//!     an **LTV / health / maxDebt / collateralization** decision keyed on a
//!     debt read derived from that accumulator;
//!   * it does **not** also call the read-write accrue/sync (`_globalStateRW` /
//!     `accrueInterest` / `checkpoint` / `_accrue` / `updateState` / `touch`),
//!     and does not itself persist the freshness write
//!     (`...UpdatedAt = block.timestamp`).
//!
//! A path that accrues/syncs first is the safe borrow/repay shape and is
//! suppressed.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::Function;

use super::prelude::*;

pub struct InterestIndexDesyncDetector;

/// Internal-call / source markers for a **read-only / cached** global-state or
/// accumulator accessor — the one that compounds in memory but does NOT persist
/// the freshness write. Reading debt/LTV through one of these on a
/// state-mutating path is the desync signal.
const RO_ACCESSOR_MARKERS: &[&str] = &[
    "_globalstatero",
    "globalstatero",
    "_globalstate_ro",
    "globalstatecache",
    "_loadglobalstatero",
    "_cachedglobalstate",
    "_readonlyglobalstate",
    "_accruedcached",
];

/// Internal-call / source markers for the **read-write** accrue/sync that
/// compounds the accumulator AND writes it (and its freshness timestamp) back to
/// storage. Presence of any of these on the path is the safe shape → suppress.
const RW_SYNC_MARKERS: &[&str] = &[
    "_globalstaterw",
    "globalstaterw",
    "_globalstate_rw",
    "accrueinterest",
    "_accrueinterest",
    "accrue(",
    "_accrue(",
    "_accruestate",
    "checkpointdebt",
    "_checkpoint",
    "updatestate",
    "_updatestate",
    "_updateindex",
    "updateborrowindex",
    "_syncinterest",
    "syncinterest",
    "_touch",
    "_poke",
];

/// Markers that the function reads a **debt** derived from the interest
/// accumulator (the quantity that goes stale): an internal call to a
/// debt-current reader, or a source mention of such a read.
const DEBT_READ_MARKERS: &[&str] = &[
    "_currentaccountdebt",
    "currentaccountdebt",
    "_computeliquidity",
    "computeliquidity",
    "_latestdebt",
    "latestdebt",
    "_accountdebt",
    "_debtof",
    "_currentdebt",
];

/// Markers that the function makes an **LTV / health / maxDebt /
/// collateralization** decision — the solvency check that must not be priced on
/// a stale index. Internal-call names or source substrings.
const LTV_DECISION_MARKERS: &[&str] = &[
    "_validateoriginationltv",
    "validateoriginationltv",
    "maxoriginationltv",
    "liquidationltv",
    "_calculatecurrentltv",
    "calculatecurrentltv",
    "_maxdebt",
    "_mincollateral",
    "healthfactor",
    "_checkhealth",
    "isliquidatable",
    "exceededliquidationltv",
    "collateralization",
    "_requirehealthy",
];

/// The interest-accumulator state-variable / index names. A read of one of these
/// (without a RO accessor) is an alternative way to evidence "this path reads the
/// interest index".
fn is_interest_accumulator_var(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // Must look like an interest/borrow *index/accumulator*, not just any var.
    (l.contains("accumulator") || l.contains("index") || l.contains("pertoken") || l.contains("pershare"))
        && (l.contains("interest")
            || l.contains("borrow")
            || l.contains("debt")
            || l.contains("ray")
            || l.contains("rate")
            || l.contains("reward"))
}

impl Detector for InterestIndexDesyncDetector {
    fn id(&self) -> &'static str {
        "interest-index-desync"
    }
    fn category(&self) -> Category {
        Category::InterestIndexDesync
    }
    fn description(&self) -> &'static str {
        "State-mutating LTV/health/debt decision priced on a read-only/cached interest accumulator with no preceding accrue/sync"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || !f.is_externally_reachable() {
                continue;
            }
            // A `view` / `pure` quote that reads the RO accessor is exactly the
            // intended use and is correct — only a *state-mutating* decision is
            // priced wrong. This single gate suppresses every view quote
            // (`accountPosition`, `accountDebt`, `globalState`,
            // `debtDeltaForMaxOriginationLtv`, `computeLiquidity`).
            if !f.is_state_mutating() {
                continue;
            }
            // Interface / abstract declarations have no body shape to price.
            if cx.contract_of(f.id).map(|c| c.is_interface()).unwrap_or(false) {
                continue;
            }

            let lc_internal: Vec<String> =
                f.effects.internal_calls.iter().map(|n| n.to_ascii_lowercase()).collect();
            let src = cx.source_text(f.span);

            // ---- the safe shape: accrue/sync is on this path → suppress ----
            // (a) an internal call to a read-write accrue/sync routine, or
            // (b) a source marker for one, or
            // (c) it persists the freshness write itself
            //     (`...UpdatedAt = block.timestamp`).
            let calls_rw_sync = lc_internal.iter().any(|n| RW_SYNC_MARKERS.iter().any(|m| n.contains(m)))
                || RW_SYNC_MARKERS.iter().any(|m| src.contains(m))
                || persists_accumulator_freshness(f, &src);
            if calls_rw_sync {
                continue;
            }

            // ---- (1) reads the interest accumulator via a read-only/cached
            //          accessor, or reads an interest-index state var ----
            let reads_ro_accessor = lc_internal
                .iter()
                .any(|n| RO_ACCESSOR_MARKERS.iter().any(|m| n.contains(m)))
                || RO_ACCESSOR_MARKERS.iter().any(|m| src.contains(m));
            let reads_index_var = f
                .effects
                .storage_reads
                .iter()
                .any(|a| is_interest_accumulator_var(&a.var));
            if !reads_ro_accessor && !reads_index_var {
                continue;
            }

            // ---- (2) the read feeds a debt-priced LTV/health/maxDebt decision.
            //          Require BOTH a debt read AND an LTV/health/solvency
            //          decision marker, so a function that merely reads an index
            //          (without making a solvency decision) stays silent. ----
            let has_debt_read = lc_internal.iter().any(|n| DEBT_READ_MARKERS.iter().any(|m| n.contains(m)))
                || DEBT_READ_MARKERS.iter().any(|m| src.contains(m));
            let has_ltv_decision = lc_internal.iter().any(|n| LTV_DECISION_MARKERS.iter().any(|m| n.contains(m)))
                || LTV_DECISION_MARKERS.iter().any(|m| src.contains(m));
            if !(has_debt_read && has_ltv_decision) {
                continue;
            }

            // Report at the RO-accessor read site if we can place it precisely
            // (the cached-state load), else the function span.
            let span = ro_accessor_span(f).unwrap_or(f.span);

            let b = report!(self, Category::InterestIndexDesync,
                title = "State-mutating LTV/debt decision priced on a stale (un-accrued) interest accumulator",
                severity = Severity::High,
                confidence = 0.6,
                dimensions = [Dimension::Invariant, Dimension::ValueFlow],
                message = format!(
                    "`{}` is state-mutating yet reads the interest accumulator through a \
                     read-only / cached accessor (a `_globalStateRO()`-style load / `GlobalStateCache`) \
                     and then prices an LTV / health / maxDebt solvency decision (and a \
                     `_currentAccountDebt`-style debt read) on it — without first calling the \
                     read-write accrue/sync (`_globalStateRW()` / `accrueInterest()`) that compounds \
                     the accumulator to `block.timestamp` and persists \
                     `interestAccumulatorUpdatedAt`. The decision is therefore made against a stale \
                     index: debt is under/over-priced and the position can be pushed past the \
                     origination/liquidation LTV, or the next interaction re-compounds interest over \
                     an overlapping window. The sibling borrow/repay/liquidate paths sync first; this \
                     one does not — the interest-index-desync class.",
                    f.name
                ),
                recommendation =
                    "On any state-mutating path that prices debt/LTV/health, accrue the global \
                     interest accumulator first by calling the read-write checkpoint \
                     (`_globalStateRW()` / `accrueInterest()`) — which compounds to `block.timestamp` \
                     and writes back `interestAccumulatorUpdatedAt` — and read the freshly-synced \
                     cache, exactly as the borrow/repay siblings do. Reserve the read-only \
                     (`_globalStateRO()`) accessor for `view` quotes.",
            );
            out.push(finish_at(cx, b, f.id, span));
        }
        out
    }
}

// ------------------------------------------------------------------- helpers

/// Best-effort span of the read-only-accessor *call site* (the cached-state
/// load), so the finding points at the stale read rather than the whole
/// function. Falls back to `None` (caller uses the function span).
fn ro_accessor_span(f: &Function) -> Option<sluice_ir::Span> {
    first_call_where(f, |c| {
        c.func_name
            .as_deref()
            .map(|n| {
                let l = n.to_ascii_lowercase();
                RO_ACCESSOR_MARKERS.iter().any(|m| l.contains(m))
            })
            .unwrap_or(false)
    })
}

/// Does the function itself persist the accumulator's freshness — a write to a
/// `*UpdatedAt` / `*Timestamp` accumulator var, or a source `...UpdatedAt =
/// block.timestamp`? Such a function *is* the accrue/sync (or contains it
/// inline), so it must not be flagged as reading a stale index.
fn persists_accumulator_freshness(f: &Function, src: &str) -> bool {
    // Structural: a storage write whose var names an accumulator-freshness field.
    let writes_freshness = f.effects.storage_writes.iter().any(|w| {
        let l = w.var.to_ascii_lowercase();
        (l.contains("updatedat") || l.contains("lastaccrual") || l.contains("lastupdate") || l.contains("accrualtimestamp"))
            && (l.contains("interest") || l.contains("accumulator") || l.contains("index") || l.contains("accrual") || l.contains("debt"))
    });
    if writes_freshness {
        return true;
    }
    // Textual: an `...updatedat = block.timestamp` / `...accumulatorupdatedat =`
    // assignment (with comments stripped & lowercased by `source_text`).
    mentions_freshness_write(src)
}

/// Best-effort scan for an accumulator-freshness assignment in lowercased,
/// comment-stripped function source: an identifier containing `updatedat`
/// immediately (modulo an index/member tail + whitespace) followed by a single
/// `=` that is not `==`.
fn mentions_freshness_write(src: &str) -> bool {
    for needle in ["updatedat", "lastaccrual", "accrualtimestamp"] {
        let bytes = src.as_bytes();
        let mut from = 0;
        while let Some(rel) = src[from..].find(needle) {
            let start = from + rel;
            let mut i = start + needle.len();
            if i < bytes.len() && bytes[i] == b'[' {
                while i < bytes.len() && bytes[i] != b']' {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
            }
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'=' {
                let is_eq_eq = i + 1 < bytes.len() && bytes[i + 1] == b'=';
                if !is_eq_eq {
                    return true;
                }
            }
            from = start + needle.len();
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

    // VULN — MonoCooler `withdrawCollateral` shape: a state-mutating withdraw
    // reads the interest accumulator through the READ-ONLY accessor
    // (`_globalStateRO`), then prices the new LTV (`_validateOriginationLtv` on
    // `maxOriginationLtv`) against a `_currentAccountDebt` derived from the
    // un-synced index. `borrow`/`repay` use `_globalStateRW`; this one does not.
    const VULN: &str = r#"
        pragma solidity ^0.8.15;
        contract MonoCooler {
            struct GlobalStateCache { uint256 interestAccumulatorRay; uint96 maxOriginationLtv; }
            struct AccountState { uint128 collateral; uint128 debtCheckpoint; uint256 interestAccumulatorRay; }
            mapping(address => AccountState) allAccountState;
            uint256 public interestAccumulatorRay;
            uint40 public interestAccumulatorUpdatedAt;
            uint128 public totalCollateral;

            function _globalStateRW() private returns (GlobalStateCache memory g) {
                interestAccumulatorUpdatedAt = uint40(block.timestamp);
                interestAccumulatorRay = g.interestAccumulatorRay;
            }
            function _globalStateRO() private view returns (GlobalStateCache memory g) {
                g.interestAccumulatorRay = interestAccumulatorRay;
            }
            function _currentAccountDebt(uint128 cp, uint256 a, uint256 b) private pure returns (uint128) {
                return cp;
            }
            function _validateOriginationLtv(uint128 ltv, uint256 maxOriginationLtv) private pure {
                if (ltv > maxOriginationLtv) revert();
            }
            function _calculateCurrentLtv(uint128 d, uint128 c) private pure returns (uint128) { return d; }

            // BORROW — safe sibling: syncs via _globalStateRW first.
            function borrow(uint128 amt, address onBehalfOf) external {
                GlobalStateCache memory g = _globalStateRW();
                AccountState storage a = allAccountState[onBehalfOf];
                uint128 debt = _currentAccountDebt(a.debtCheckpoint, a.interestAccumulatorRay, g.interestAccumulatorRay);
                uint128 ltv = _calculateCurrentLtv(debt + amt, a.collateral);
                _validateOriginationLtv(ltv, g.maxOriginationLtv);
                a.debtCheckpoint = debt + amt;
            }

            // WITHDRAW — VULNERABLE: prices LTV on the READ-ONLY accumulator.
            function withdrawCollateral(uint128 amt, address onBehalfOf) external returns (uint128) {
                GlobalStateCache memory g = _globalStateRO();
                AccountState storage a = allAccountState[onBehalfOf];
                uint128 debt = _currentAccountDebt(a.debtCheckpoint, a.interestAccumulatorRay, g.interestAccumulatorRay);
                a.collateral -= amt;
                totalCollateral -= amt;
                uint128 newLtv = _calculateCurrentLtv(debt, a.collateral);
                _validateOriginationLtv(newLtv, g.maxOriginationLtv);
                return amt;
            }
        }
    "#;

    // SAFE — same protocol, but `withdrawCollateral` calls `_globalStateRW()`
    // (accrues + persists the freshness write) before pricing the LTV. This is
    // the corrected shape and must stay silent.
    const SAFE_SYNCED: &str = r#"
        pragma solidity ^0.8.15;
        contract MonoCooler {
            struct GlobalStateCache { uint256 interestAccumulatorRay; uint96 maxOriginationLtv; }
            struct AccountState { uint128 collateral; uint128 debtCheckpoint; uint256 interestAccumulatorRay; }
            mapping(address => AccountState) allAccountState;
            uint256 public interestAccumulatorRay;
            uint40 public interestAccumulatorUpdatedAt;
            uint128 public totalCollateral;

            function _globalStateRW() private returns (GlobalStateCache memory g) {
                interestAccumulatorUpdatedAt = uint40(block.timestamp);
                interestAccumulatorRay = g.interestAccumulatorRay;
            }
            function _currentAccountDebt(uint128 cp, uint256 a, uint256 b) private pure returns (uint128) { return cp; }
            function _validateOriginationLtv(uint128 ltv, uint256 maxOriginationLtv) private pure {
                if (ltv > maxOriginationLtv) revert();
            }
            function _calculateCurrentLtv(uint128 d, uint128 c) private pure returns (uint128) { return d; }

            function withdrawCollateral(uint128 amt, address onBehalfOf) external returns (uint128) {
                GlobalStateCache memory g = _globalStateRW();
                AccountState storage a = allAccountState[onBehalfOf];
                uint128 debt = _currentAccountDebt(a.debtCheckpoint, a.interestAccumulatorRay, g.interestAccumulatorRay);
                a.collateral -= amt;
                totalCollateral -= amt;
                uint128 newLtv = _calculateCurrentLtv(debt, a.collateral);
                _validateOriginationLtv(newLtv, g.maxOriginationLtv);
                return amt;
            }
        }
    "#;

    // SAFE — a pure VIEW quote that reads `_globalStateRO()` and computes an LTV
    // is correct (no state decision is committed). Must stay silent.
    const SAFE_VIEW_QUOTE: &str = r#"
        pragma solidity ^0.8.15;
        contract MonoCooler {
            struct GlobalStateCache { uint256 interestAccumulatorRay; uint96 maxOriginationLtv; }
            struct AccountState { uint128 collateral; uint128 debtCheckpoint; uint256 interestAccumulatorRay; }
            mapping(address => AccountState) allAccountState;
            uint256 public interestAccumulatorRay;

            function _globalStateRO() private view returns (GlobalStateCache memory g) {
                g.interestAccumulatorRay = interestAccumulatorRay;
            }
            function _currentAccountDebt(uint128 cp, uint256 a, uint256 b) private pure returns (uint128) { return cp; }
            function _calculateCurrentLtv(uint128 d, uint128 c) private pure returns (uint128) { return d; }

            function accountDebt(address account) external view returns (uint128) {
                AccountState storage a = allAccountState[account];
                GlobalStateCache memory g = _globalStateRO();
                return _currentAccountDebt(a.debtCheckpoint, a.interestAccumulatorRay, g.interestAccumulatorRay);
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(
            fs.iter().any(|f| f.detector == "interest-index-desync" && f.function == "withdrawCollateral"),
            "{:#?}",
            fs.iter().map(|f| (&f.detector, &f.function)).collect::<Vec<_>>()
        );
        // The synced sibling `borrow` must NOT be flagged.
        assert!(
            !fs.iter().any(|f| f.detector == "interest-index-desync" && f.function == "borrow"),
            "borrow (synced) should be silent"
        );
    }

    #[test]
    fn silent_when_synced() {
        let fs = run(SAFE_SYNCED);
        assert!(!fs.iter().any(|f| f.detector == "interest-index-desync"), "{:#?}", fs);
    }

    #[test]
    fn silent_on_view_quote() {
        let fs = run(SAFE_VIEW_QUOTE);
        assert!(!fs.iter().any(|f| f.detector == "interest-index-desync"), "{:#?}", fs);
    }
}
