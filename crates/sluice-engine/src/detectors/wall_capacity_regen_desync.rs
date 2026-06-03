//! Wall-capacity / regen desync — an algorithmic-stability range-band ("wall")
//! whose **capacity** is *debited* by ordinary user flow on one path and
//! *credited / reset* by a separate keeper `regenerate` path, where the debit path
//! drops one of the co-updates the regen path performs together (the threshold /
//! active-flag recompute **or** the paired mint / withdraw-approval delta).
//!
//! This is the **Olympus V3 RBS `Operator` / `OlympusRange`** shape. The protocol
//! runs a two-sided price "wall": each side has a `capacity` (how much the wall can
//! still absorb), a `threshold` / `active` flag (the wall switches off once capacity
//! falls under the threshold), and a paired *approval* (the wall may mint OHM up to
//! capacity via `MINTR.mintApproval`, or withdraw reserves up to capacity via
//! `TRSRY.withdrawApproval`). Every market swap that hits the wall **debits**
//! capacity:
//!
//! ```solidity
//! // Operator.sol
//! function _updateCapacity(bool high_, uint256 reduceBy_) internal {
//!     // Decrement capacity if a reduceBy amount is provided
//!     RANGE.updateCapacity(high_, RANGE.capacity(high_) - reduceBy_);
//! }
//! ```
//!
//! The keeper **regen** path resets the whole wall *atomically* — capacity,
//! threshold/active, **and** the approval, all in lockstep:
//!
//! ```solidity
//! // Operator.sol
//! function _regenerate(bool high_) internal {
//!     _deactivate(high_);
//!     ...
//!     uint256 capacity = fullCapacity(high_);
//!     // re-sync the mint/withdraw approval to the new capacity
//!     MINTR.increaseMintApproval(address(this), capacity - currentApproval);   // (or decrease / TRSRY)
//!     RANGE.regenerate(high_, capacity);  // resets capacity + threshold + active together
//! }
//! ```
//!
//! The debit path `_updateCapacity` only lowers capacity. It does **not** also lower
//! the matching mint / withdraw approval, and it does not itself recompute the
//! threshold/active flag. So after a sequence of wall hits the *approval* the policy
//! holds can sit **above** the wall's remaining capacity: the wall reports e.g.
//! 100 capacity but the policy still carries a 1000-OHM mint approval (or reserve
//! withdraw approval) granted at the last regen. The two figures the keeper resets
//! together have **desynced** on the debit path, leaving spare approval that the
//! capacity accounting believes is gone — an over-mint / over-withdraw surface and a
//! broken `capacity ⇔ approval` invariant.
//!
//! ## What the detector matches
//!
//! Per contract (across its inheritance chain), it requires both halves of the
//! debit/regen split:
//!
//!   1. **A regen anchor** — a sibling whose name is `regenerate` / `_regenerate`
//!      that *resets the wall together*: it writes/sets a capacity figure (a
//!      `capacity`-named SSTORE, or a `regenerate(...)` call) **and** co-updates the
//!      paired surface — the threshold/active flag (writes an `active`/`threshold`
//!      var) **or** the mint/withdraw approval (`*mintApproval` / `*withdrawApproval`
//!      / `increase*Approval` / `decrease*Approval`). This is the structural proof
//!      that the protocol treats {capacity, threshold/active, approval} as a unit.
//!
//!   2. **A debit outlier** — a *different* state-mutating function carrying a
//!      **capacity debit**: a `Sub` `capacity(..) - reduceBy` whose left operand
//!      root-resolves to a `capacity`-named read/call, *and* that debit flows into a
//!      capacity write (an `updateCapacity(...)` call or a `capacity`-named SSTORE)
//!      — while the function **neither** recomputes the threshold/active flag **nor**
//!      touches the paired approval.
//!
//! ## Precision (single Invariant dimension)
//!
//!   * **SUPPRESS when the debit path co-updates the flag.** If the same function
//!     that debits capacity also writes an `active`/`threshold` var (the
//!     `if (capacity_ < threshold && active) active = false` recompute) *or* touches
//!     the approval, the co-update is present and there is no desync — silent. This
//!     is exactly `OlympusRange.updateCapacity`, which recomputes `active` inline, so
//!     the module-side write is correctly *not* flagged; only the policy-side
//!     `Operator._updateCapacity`, which drops the approval delta, fires.
//!   * **Require the `capacity(..) - reduceBy` debit shape**, not a bare
//!     `capacity = x` setter (that is an admin set, not a flow debit) — the LHS of
//!     the subtraction must root into a `capacity`-named figure.
//!   * **Require a real `regenerate` sibling that resets together.** A contract with
//!     no `regenerate` path, or one whose regen does not co-update a paired surface,
//!     is not this class (rate-limiter `refill`/`consume` libraries that never
//!     `regenerate` a wall stay silent).
//!   * Pure interfaces / bodiless declarations host neither half.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use rustc_hash::FxHashSet;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Contract, Expr, ExprKind, Function};

use super::prelude::*;

pub struct WallCapacityRegenDesyncDetector;

impl Detector for WallCapacityRegenDesyncDetector {
    fn id(&self) -> &'static str {
        "wall-capacity-regen-desync"
    }
    fn category(&self) -> Category {
        Category::WallCapacityRegenDesync
    }
    fn description(&self) -> &'static str {
        "A range-band wall capacity is debited by user flow on one path but credited/reset \
         (with its threshold/active flag and paired mint/withdraw approval) by a separate keeper \
         regenerate path — the debit path drops a co-update, desyncing capacity from the approval"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for c in cx.scir.iter_contracts() {
            if c.is_interface() {
                continue;
            }

            // Functions sharing this contract's storage namespace (own + bases),
            // de-duplicated by id — the regen anchor and the debit outlier may live
            // in the same contract or in an inherited base.
            let funcs = visible_functions(cx, c);
            if funcs.is_empty() {
                continue;
            }

            // (1) The regen anchor: a `regenerate`/`_regenerate` sibling that resets
            // a capacity figure AND co-updates a paired surface (threshold/active or
            // approval). Without it this is not the wall-capacity/regen class.
            let Some(regen) = funcs.iter().copied().find(|f| is_regen_anchor(f)) else {
                continue;
            };

            // (2) Walk the remaining state-mutating functions for a capacity-debit
            // outlier that drops a co-update the regen path performs together.
            for &f in &funcs {
                if f.id == regen.id || !f.has_body || f.is_view_or_pure() {
                    continue;
                }

                let Some(debit_span) = capacity_debit_site(f) else {
                    continue;
                };

                // SUPPRESS: the debit path itself recomputes the threshold/active
                // flag or touches the paired approval — the co-update is present, so
                // there is no desync (this is OlympusRange.updateCapacity).
                if recomputes_flag(f) || touches_approval(f) {
                    continue;
                }

                let b = report!(self, Category::WallCapacityRegenDesync,
                    title = "Wall capacity debited without the regen path's paired co-update (capacity/approval desync)",
                    severity = Severity::Medium,
                    confidence = 0.6,
                    dimensions = [Dimension::Invariant],
                    message = format!(
                        "`{debit}` debits a range-band wall capacity (`capacity(..) - reduceBy`) and \
                         writes it back, but does **not** also recompute the wall's threshold/active \
                         flag or re-sync the paired mint/withdraw approval. Its sibling `{regen}` resets \
                         the wall *atomically* — capacity, threshold/active, **and** the approval move \
                         together there — establishing that these figures are meant to stay in lockstep. \
                         Because the debit path lowers only capacity, the approval the contract holds can \
                         remain **above** the wall's remaining capacity after a run of debits, so the \
                         capacity accounting believes spare allowance is gone while the approval still \
                         permits it — an over-mint / over-withdraw surface and a broken \
                         `capacity ⇔ approval` invariant (Olympus RBS `Operator._updateCapacity` vs \
                         `_regenerate`).",
                        debit = f.name,
                        regen = regen.name,
                    ),
                    recommendation = format!(
                        "Make the debit path co-update the same surface the regen path resets: after \
                         lowering capacity, also reduce the paired mint/withdraw approval by the same \
                         `reduceBy` (and re-evaluate the threshold/active flag), so `{debit}` keeps the \
                         `capacity ⇔ approval` relation the keeper `{regen}` enforces — or route all \
                         capacity changes through a single function that updates both.",
                        debit = f.name,
                        regen = regen.name,
                    ),
                );
                out.push(finish_at(cx, b, f.id, debit_span));
            }
        }

        out
    }
}

// ------------------------------------------------------------------ helpers

/// Transitive inheritance chain of `c` (itself plus every direct/indirect base),
/// resolved by base-name match. Wall state + its writers are spread across the
/// chain (RANGE-module figures, policy approvals), so single-level resolution is
/// not enough.
fn inheritance_chain<'a>(cx: &'a AnalysisContext, c: &'a Contract) -> Vec<&'a Contract> {
    let mut out: Vec<&Contract> = Vec::new();
    let mut seen: FxHashSet<sluice_ir::ContractId> = FxHashSet::default();
    let mut stack: Vec<&Contract> = vec![c];
    while let Some(cur) = stack.pop() {
        if !seen.insert(cur.id) {
            continue;
        }
        out.push(cur);
        for base_name in &cur.bases {
            if let Some(base) = cx.scir.contract_named(base_name) {
                if !seen.contains(&base.id) {
                    stack.push(base);
                }
            }
        }
    }
    out
}

/// Functions visible to `c`'s storage namespace — every function across `c`'s full
/// inheritance chain, de-duplicated by id.
fn visible_functions<'a>(cx: &'a AnalysisContext, c: &'a Contract) -> Vec<&'a Function> {
    let mut out: Vec<&Function> = Vec::new();
    let mut have: FxHashSet<sluice_ir::FunctionId> = FxHashSet::default();
    for k in inheritance_chain(cx, c) {
        for f in cx.scir.functions_of(k.id) {
            if have.insert(f.id) {
                out.push(f);
            }
        }
    }
    out
}

/// Is `f` the regen anchor — a `regenerate`/`_regenerate`-named function that resets
/// a capacity figure AND co-updates a paired surface (threshold/active or approval)?
/// This is the structural witness that the protocol resets {capacity, flag,
/// approval} together, so a debit path that drops one of them is the desync.
fn is_regen_anchor(f: &Function) -> bool {
    if !f.has_body {
        return false;
    }
    let l = f.name.to_ascii_lowercase();
    // Name gate: the keeper reset path. `regenerate` is the wall-reset verb; a
    // generic `refill`/`replenish` rate-limiter is deliberately *not* matched.
    if !(l == "regenerate" || l == "_regenerate" || l.ends_with("regenerate")) {
        return false;
    }
    // Resets a capacity figure: writes a `capacity`-named var, or calls a
    // `regenerate(...)` that takes the new capacity.
    let resets_capacity = writes_capacity(f) || calls_named(f, "regenerate");
    if !resets_capacity {
        return false;
    }
    // Co-updates a paired surface in the same reset: threshold/active flag or the
    // mint/withdraw approval. (`_regenerate` does both — approval delta + the
    // `RANGE.regenerate` that re-inits threshold/active.)
    recomputes_flag(f) || touches_approval(f)
}

/// A capacity-debit site in `f`: a `Sub` `capacity(..) - reduceBy` whose LHS roots
/// into a `capacity`-named read/call, where that subtraction flows into a capacity
/// write (an `updateCapacity(...)` call argument, or a `capacity`-named SSTORE).
/// Returns the span of the debit. The `capacity(..) - reduceBy` shape is the strong
/// anchor: a bare `capacity = x` setter (no subtraction) is an admin set, not a
/// flow debit, and is not matched.
fn capacity_debit_site(f: &Function) -> Option<sluice_ir::Span> {
    for s in &f.body {
        let mut hit: Option<sluice_ir::Span> = None;
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            // A capacity-debit subtraction whose LHS is a capacity figure.
            if !is_capacity_minus(e) {
                return;
            }
            // It must flow into a capacity write: either it is an argument to an
            // `updateCapacity(...)`-style call, or it is the value of a
            // `capacity`-named SSTORE. We approximate "flows into a write" by
            // requiring the *enclosing function* to perform a capacity write — the
            // subtraction and the write are the same statement in this class.
            hit = Some(e.span);
        });
        if let Some(span) = hit {
            // Confirm the function actually writes capacity (SSTORE) or calls
            // updateCapacity — the subtraction is the value being stored.
            if writes_capacity(f) || calls_update_capacity(f) {
                return Some(span);
            }
        }
    }
    None
}

/// Is `e` a subtraction `capacity(..) - X` whose left operand root-resolves to a
/// `capacity`-named figure (a `capacity(side)` call, a `_range.high.capacity` member
/// read, or a bare `capacity`)?
fn is_capacity_minus(e: &Expr) -> bool {
    let ExprKind::Binary { op: BinOp::Sub, lhs, .. } = &e.kind else {
        return false;
    };
    lhs_is_capacity(lhs)
}

/// Does `e` denote a `capacity`-named figure — a call `capacity(..)`, a member chain
/// ending in `.capacity`, or a bare `capacity` identifier (casts peeled)?
fn lhs_is_capacity(e: &Expr) -> bool {
    let e = peel_casts(e);
    match &e.kind {
        // `RANGE.capacity(high_)` — a call whose method/func name is `capacity`.
        ExprKind::Call(c) => c
            .func_name
            .as_deref()
            .is_some_and(|n| n.eq_ignore_ascii_case("capacity")),
        // `_range.high.capacity` — a member access ending in `capacity`.
        ExprKind::Member { member, .. } => member.eq_ignore_ascii_case("capacity"),
        // bare `capacity`
        ExprKind::Ident(n) => n.eq_ignore_ascii_case("capacity"),
        _ => false,
    }
}

/// Does `f` write a `capacity`-named state figure (a `*.capacity = ..` SSTORE or a
/// bare `capacity = ..`)?
fn writes_capacity(f: &Function) -> bool {
    // Effect summary first (cheap), then a body scan for `*.capacity = ..` member
    // assignments that the summary records under the root var (`_range`).
    if f.effects.storage_writes.iter().any(|w| {
        w.var.to_ascii_lowercase().contains("capacity")
            || w.path.to_ascii_lowercase().contains(".capacity")
    }) {
        return true;
    }
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Assign { target, .. } = &e.kind {
                if assign_target_is_capacity(target) {
                    found = true;
                }
            }
        });
    }
    found
}

/// Is an assignment target a `capacity`-named lvalue (`x.capacity`, `capacity`)?
fn assign_target_is_capacity(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Member { member, .. } => member.eq_ignore_ascii_case("capacity"),
        ExprKind::Ident(n) => n.eq_ignore_ascii_case("capacity"),
        ExprKind::Index { base, .. } => assign_target_is_capacity(base),
        _ => false,
    }
}

/// Does `f` call a method/function named exactly `name` (case-insensitive)?
fn calls_named(f: &Function, name: &str) -> bool {
    any_call_where(f, |c| {
        c.func_name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(name))
    })
}

/// Does `f` call an `updateCapacity(...)`-style capacity setter?
fn calls_update_capacity(f: &Function) -> bool {
    any_call_where(f, |c| {
        c.func_name
            .as_deref()
            .is_some_and(|n| n.to_ascii_lowercase().contains("updatecapacity"))
    })
}

/// Does `f` recompute the wall's threshold / active flag — write an `active`- or
/// `threshold`-named state var (the `if (cap < threshold && active) active = false`
/// recompute, or the regen `active = true; threshold = ..`)?
fn recomputes_flag(f: &Function) -> bool {
    // Effect-summary writes.
    if f.effects.storage_writes.iter().any(|w| is_flag_name(&w.var) || is_flag_path(&w.path)) {
        return true;
    }
    // Body scan for `*.active = ..` / `*.threshold = ..` member assignments
    // (the summary records these under the root struct var, not the member).
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Assign { target, .. } = &e.kind {
                if assign_target_is_flag(target) {
                    found = true;
                }
            }
        });
    }
    found
}

fn is_flag_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("active") || l.contains("threshold")
}
fn is_flag_path(path: &str) -> bool {
    let l = path.to_ascii_lowercase();
    l.contains(".active") || l.contains(".threshold")
}
fn assign_target_is_flag(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Member { member, .. } => is_flag_name(member),
        ExprKind::Ident(n) => is_flag_name(n),
        ExprKind::Index { base, .. } => assign_target_is_flag(base),
        _ => false,
    }
}

/// Does `f` touch the paired mint / withdraw approval — call a `*mintApproval`,
/// `*withdrawApproval`, `increase*Approval`, or `decrease*Approval`? This is the
/// other half of the regen co-update; a debit path that calls it is not the desync.
fn touches_approval(f: &Function) -> bool {
    any_call_where(f, |c| {
        let Some(n) = c.func_name.as_deref() else { return false };
        let l = n.to_ascii_lowercase();
        l.contains("mintapproval")
            || l.contains("withdrawapproval")
            || ((l.starts_with("increase") || l.starts_with("decrease")) && l.contains("approval"))
    })
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "wall-capacity-regen-desync")
    }

    // VULN — Olympus RBS Operator shape: `_updateCapacity` debits the wall capacity
    // (`RANGE.capacity(high_) - reduceBy_`) and writes it back via
    // `RANGE.updateCapacity`, but does NOT re-sync the paired mint/withdraw approval
    // or recompute the flag. Its sibling `_regenerate` resets the wall atomically —
    // capacity (`RANGE.regenerate`) + approval (`increaseMintApproval`) together.
    const VULN: &str = r#"
        interface IRange {
            function capacity(bool high_) external view returns (uint256);
            function updateCapacity(bool high_, uint256 capacity_) external;
            function regenerate(bool high_, uint256 capacity_) external;
        }
        interface IMinter {
            function mintApproval(address who) external view returns (uint256);
            function increaseMintApproval(address who, uint256 amount) external;
            function decreaseMintApproval(address who, uint256 amount) external;
        }
        contract Operator {
            IRange RANGE;
            IMinter MINTR;

            function fullCapacity(bool high_) public view returns (uint256) {
                return high_ ? 1000 : 500;
            }

            // DEBIT OUTLIER: lowers capacity only, drops the approval co-update.
            function _updateCapacity(bool high_, uint256 reduceBy_) internal {
                RANGE.updateCapacity(high_, RANGE.capacity(high_) - reduceBy_);
            }

            // REGEN ANCHOR: resets capacity + approval together.
            function _regenerate(bool high_) internal {
                uint256 capacity = fullCapacity(high_);
                uint256 currentApproval = MINTR.mintApproval(address(this));
                if (currentApproval < capacity) {
                    MINTR.increaseMintApproval(address(this), capacity - currentApproval);
                } else if (currentApproval > capacity) {
                    MINTR.decreaseMintApproval(address(this), currentApproval - capacity);
                }
                RANGE.regenerate(high_, capacity);
            }
        }
    "#;

    // VULN (direct-SSTORE debit form): the debit path writes `*.capacity` directly
    // from a `capacity - reduceBy` subtraction and never touches the flag/approval,
    // while a `_regenerate` sibling resets capacity + threshold/active together.
    const VULN_DIRECT_SSTORE: &str = r#"
        contract Wall {
            struct Band { uint256 capacity; uint256 threshold; bool active; }
            Band high;
            uint256 public approvalHigh;

            // DEBIT OUTLIER: capacity = capacity - reduceBy, no flag/approval co-update.
            function takeDown(uint256 reduceBy_) external {
                high.capacity = high.capacity - reduceBy_;
            }

            // REGEN ANCHOR: resets capacity + threshold + active together.
            function _regenerate(uint256 newCapacity) internal {
                high.capacity = newCapacity;
                high.threshold = newCapacity / 10;
                high.active = true;
                approvalHigh = newCapacity;
            }
        }
    "#;

    // SAFE — the debit path itself recomputes the threshold/active flag inline (the
    // `OlympusRange.updateCapacity` shape): `capacity = capacity_; if (capacity_ <
    // threshold && active) active = false`. The co-update is present, so no desync.
    const SAFE_DEBIT_RECOMPUTES_FLAG: &str = r#"
        contract RangeModule {
            struct Band { uint256 capacity; uint256 threshold; bool active; uint48 lastActive; }
            Band high;
            uint256 thresholdFactor = 1000;

            // Capacity setter that ALSO recomputes the active flag — the co-update.
            function updateCapacity(uint256 capacity_) external {
                high.capacity = capacity_;
                if (capacity_ < high.threshold && high.active) {
                    high.active = false;
                    high.lastActive = uint48(block.timestamp);
                }
            }

            // REGEN ANCHOR present (resets capacity + threshold + active together).
            function regenerate(uint256 capacity_) external {
                uint256 threshold = (capacity_ * thresholdFactor) / 100000;
                high.active = true;
                high.capacity = capacity_;
                high.threshold = threshold;
            }
        }
    "#;

    // SAFE — the debit path re-syncs the approval (the OTHER co-update). A debit that
    // lowers capacity AND lowers the paired approval is not the desync.
    const SAFE_DEBIT_SYNCS_APPROVAL: &str = r#"
        interface IRange {
            function capacity(bool high_) external view returns (uint256);
            function updateCapacity(bool high_, uint256 capacity_) external;
            function regenerate(bool high_, uint256 capacity_) external;
        }
        interface IMinter {
            function mintApproval(address who) external view returns (uint256);
            function increaseMintApproval(address who, uint256 amount) external;
            function decreaseMintApproval(address who, uint256 amount) external;
        }
        contract Operator {
            IRange RANGE;
            IMinter MINTR;
            function fullCapacity(bool high_) public view returns (uint256) { return 1000; }

            // Debit path lowers capacity AND the paired approval — co-update present.
            function _updateCapacity(bool high_, uint256 reduceBy_) internal {
                RANGE.updateCapacity(high_, RANGE.capacity(high_) - reduceBy_);
                MINTR.decreaseMintApproval(address(this), reduceBy_);
            }
            function _regenerate(bool high_) internal {
                uint256 capacity = fullCapacity(high_);
                MINTR.increaseMintApproval(address(this), capacity);
                RANGE.regenerate(high_, capacity);
            }
        }
    "#;

    // SAFE — no regen anchor: a rate-limiter that `consume`s capacity but never has a
    // `regenerate` sibling resetting the wall together. Nothing establishes the
    // co-update contract, so the debit is not a desync outlier.
    const SAFE_NO_REGEN_ANCHOR: &str = r#"
        interface IRange {
            function capacity(bool high_) external view returns (uint256);
            function updateCapacity(bool high_, uint256 capacity_) external;
        }
        contract Limiter {
            IRange RANGE;
            function consume(bool high_, uint256 reduceBy_) external {
                RANGE.updateCapacity(high_, RANGE.capacity(high_) - reduceBy_);
            }
            function setRefillRate(uint256 r) external {}
        }
    "#;

    // SAFE — the regen sibling exists but does NOT co-update a paired surface (it only
    // sets capacity, no threshold/active and no approval). There is no lockstep
    // contract to violate, so a capacity-only debit is consistent with it.
    const SAFE_REGEN_NO_COUPDATE: &str = r#"
        contract Wall {
            struct Band { uint256 capacity; }
            Band high;
            function takeDown(uint256 reduceBy_) external {
                high.capacity = high.capacity - reduceBy_;
            }
            function _regenerate(uint256 newCapacity) internal {
                high.capacity = newCapacity;
            }
        }
    "#;

    // SAFE — admin capacity setter (no `capacity - reduceBy` subtraction). A plain
    // `capacity = x` set is not a flow debit even with a regen anchor present.
    const SAFE_PLAIN_SETTER: &str = r#"
        contract Wall {
            struct Band { uint256 capacity; uint256 threshold; bool active; }
            Band high;
            function setCapacity(uint256 x) external {
                high.capacity = x;
            }
            function _regenerate(uint256 newCapacity) internal {
                high.capacity = newCapacity;
                high.threshold = newCapacity / 10;
                high.active = true;
            }
        }
    "#;

    #[test]
    fn fires_on_operator_updatecapacity_shape() {
        let fs = run(VULN);
        assert!(
            fs.iter()
                .any(|f| f.detector == "wall-capacity-regen-desync" && f.function == "_updateCapacity"),
            "{:#?}",
            fs
        );
    }

    #[test]
    fn fires_on_direct_sstore_debit() {
        assert!(fires(VULN_DIRECT_SSTORE), "{:#?}", run(VULN_DIRECT_SSTORE));
    }

    #[test]
    fn silent_when_debit_recomputes_flag() {
        assert!(!fires(SAFE_DEBIT_RECOMPUTES_FLAG), "{:#?}", run(SAFE_DEBIT_RECOMPUTES_FLAG));
    }

    #[test]
    fn silent_when_debit_syncs_approval() {
        assert!(!fires(SAFE_DEBIT_SYNCS_APPROVAL), "{:#?}", run(SAFE_DEBIT_SYNCS_APPROVAL));
    }

    #[test]
    fn silent_without_regen_anchor() {
        assert!(!fires(SAFE_NO_REGEN_ANCHOR), "{:#?}", run(SAFE_NO_REGEN_ANCHOR));
    }

    #[test]
    fn silent_when_regen_has_no_coupdate() {
        assert!(!fires(SAFE_REGEN_NO_COUPDATE), "{:#?}", run(SAFE_REGEN_NO_COUPDATE));
    }

    #[test]
    fn silent_on_plain_setter() {
        assert!(!fires(SAFE_PLAIN_SETTER), "{:#?}", run(SAFE_PLAIN_SETTER));
    }
}
