//! Re-register cooldown / bitmap residue — deregistration clears ONE membership
//! structure (a quorum `bitmap`, an `isRegistered` flag, an operator `status`) but
//! leaves **residue** in a *parallel* lifecycle structure (a
//! `lastDeregistered`/`lastEjection` cooldown timestamp, an apk entry, a per-quorum
//! count), and a **re-registration** path then reads that stale residue.
//!
//! ## The shape
//!
//! A registry tracks membership in two places that must move together but are
//! written by different functions. The classic instance is EigenLayer's
//! `SlashingRegistryCoordinator`:
//!
//! ```solidity
//! // register: gates re-registration on a cooldown keyed on a residue timestamp
//! function _registerOperator(...) internal {
//!     ...
//!     require(
//!         lastEjectionTimestamp[operator] + ejectionCooldown < block.timestamp,
//!         CannotReregisterYet()                                  // <-- cooldown gate on B
//!     );
//!     _updateOperatorBitmap({operatorId: operatorId, newBitmap: newBitmap});  // sets A
//!     ...
//! }
//! // deregister: clears the membership bitmap + status (A) ...
//! function _deregisterOperator(...) internal {
//!     ...
//!     _updateOperatorBitmap({operatorId: operatorId, newBitmap: newBitmap});  // clears A
//!     _operatorInfo[operator].status = OperatorStatus.DEREGISTERED;           // clears A
//!     // ... but NEVER resets lastEjectionTimestamp[operator]  (B)
//! }
//! // the cooldown timestamp B is written only on the eject lifecycle, not on deregister
//! function ejectOperator(...) { lastEjectionTimestamp[operator] = block.timestamp; ... }
//! ```
//!
//! Deregister resets the **membership** view `A` (`bitmap` / `status`) but the
//! **cooldown residue** `B` (`lastEjectionTimestamp`) is left untouched, while the
//! re-register path reads `B` in a `CannotReregisterYet` cooldown gate. The two are
//! advanced/cleared from unrelated functions with no joint invariant, so a re-register
//! reads a *stale* `B`: depending on which lifecycle wrote `B`, an operator can be
//! gated (or un-gated) on a cooldown that no longer reflects their true membership
//! state — a deregistered-then-re-register path reading residue that deregister
//! didn't reset.
//!
//! ## What the detector matches (all required)
//!
//! Per contract (over its full inheritance scope, since the register / deregister /
//! cooldown writers are routinely split across a `*Storage` base + the coordinator):
//!
//!   1. a **register** function (name reads `register` but not `deregister`) whose
//!      body holds a **cooldown gate** — a `require(...)` / `if (...) revert` whose
//!      condition is a *time comparison* (`B[..] + period </> block.timestamp`, or a
//!      bare `block.timestamp </> B[..]`) reading a **residue state var `B`**, AND the
//!      gate reads as a re-register cooldown (the guard's error/reason name contains
//!      `reregister`/`cooldown`/`tooearly`/`notexpired`, OR the compared deadline is a
//!      `B + period` form). `B` is the residue var the gate keys on;
//!   2. a **deregister** function (name reads `deregister`/`unregister`) in scope that
//!      **clears a membership structure `A`** — it writes (or `delete`s / updates via
//!      an `*bitmap*` helper) a var whose name reads as membership
//!      (`bitmap`/`registered`/`status`/`operatorInfo`/`membership`) — but does **NOT**
//!      write `B`;
//!   3. `B` is a **real, written** state var (some function in scope writes it), so the
//!      gate keys on genuine *residue*, not an always-zero field.
//!
//! ## SUPPRESS
//!
//!   * **both reset together** — if the deregister function also writes `B`
//!     (`delete B[id]` / `B[id] = 0` / `B[id] = ...`), the cooldown residue is cleared
//!     alongside the membership view and there is no stale read. This is the dominant
//!     safe shape (e.g. EigenLayer `ECDSAStakeRegistry._deregisterOperator`, which
//!     resets `_operatorRegistered` **and** `_totalOperators` in lockstep, and whose
//!     register reads exactly those two — no unreset residue var).
//!   * the register gate keys on a var the deregister path *does* clear, or on a var
//!     that is never written (a constant-ish read), or on no membership/cooldown
//!     structure at all.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{
    BinOp, Builtin, CallKind, Contract, Expr, ExprKind, Function, FunctionId, Span, Stmt, StmtKind,
    UnOp,
};

use super::prelude::*;

pub struct ReregisterCooldownBitmapResidueDetector;

/// A cooldown-gate discovered in a register function: the residue var `B` it keys
/// on, plus the span of the guard for reporting.
struct CooldownGate {
    /// Residue state-var name the gate reads (`lastEjectionTimestamp`).
    residue_var: String,
    /// Span of the `require` / `if-revert` guard.
    span: Span,
    /// Source text of the guard condition, for the message.
    cond_text: String,
}

impl Detector for ReregisterCooldownBitmapResidueDetector {
    fn id(&self) -> &'static str {
        "reregister-cooldown-bitmap-residue"
    }
    fn category(&self) -> Category {
        Category::ReregisterCooldownBitmapResidue
    }
    fn description(&self) -> &'static str {
        "Deregistration clears one membership structure (a quorum bitmap / isRegistered / status) \
         but leaves residue in a parallel cooldown/count/apk structure that a re-registration path \
         reads stale (EigenLayer SlashingRegistryCoordinator lastEjectionTimestamp class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for c in cx.scir.iter_contracts() {
            // Interfaces declare no bodies; libraries don't host this membership
            // lifecycle. The class lives in stateful coordinator/registry contracts.
            if c.is_interface() || c.is_library() {
                continue;
            }

            // Functions visible to this contract's storage namespace: own + every
            // (transitive) base. The register / deregister / cooldown-writer trio is
            // routinely split across a `*Storage` base and the coordinator.
            let funcs = visible_functions(cx, c);
            if funcs.is_empty() {
                continue;
            }

            // The set of state vars `B` that *some* visible function writes — a residue
            // var must be genuinely written somewhere (not an always-default read).
            let written_vars = vars_written_anywhere(&funcs);

            // Deregister functions in scope (name reads deregister/unregister, with a
            // body). Precompute each one's clears-membership flag + written-var set.
            let deregs: Vec<&&Function> = funcs
                .iter()
                .filter(|f| f.has_body && is_deregister_name(&f.name))
                .collect();
            if deregs.is_empty() {
                continue;
            }

            // De-dup reports by (register fn, residue var) so one finding per stale-read
            // pair is emitted even if multiple deregister siblings match.
            let mut reported: std::collections::HashSet<(FunctionId, String)> =
                std::collections::HashSet::default();

            for r in &funcs {
                if !r.has_body || !is_register_name(&r.name) {
                    continue;
                }
                // (1) the cooldown gate in the register body, keyed on residue var B.
                let Some(gate) = find_cooldown_gate(cx, r) else { continue };

                // (3) B must be a real, written state var (genuine residue).
                if !written_vars.contains(gate.residue_var.as_str()) {
                    continue;
                }

                // (2) a deregister sibling that clears a membership structure A but does
                // NOT write B. Also serves as the (SUPPRESS) check: any deregister that
                // *does* write B means the residue is reset in lockstep — skip the pair.
                let mut clearing_dereg: Option<&Function> = None;
                let mut any_dereg_clears_residue = false;
                for d in &deregs {
                    if d.effects.writes_var(&gate.residue_var) {
                        any_dereg_clears_residue = true;
                        break;
                    }
                    if clearing_dereg.is_none() && clears_membership(d) {
                        clearing_dereg = Some(d);
                    }
                }
                // SUPPRESS: some deregister path resets the residue var alongside
                // membership — both move together, no stale read.
                if any_dereg_clears_residue {
                    continue;
                }
                let Some(dereg) = clearing_dereg else { continue };

                let key = (r.id, gate.residue_var.clone());
                if !reported.insert(key) {
                    continue;
                }

                let b = report!(self, Category::ReregisterCooldownBitmapResidue,
                    title = "Re-registration reads a cooldown/residue field that deregistration does not reset",
                    severity = Severity::Medium,
                    // Multi-anchor structural fingerprint: a time-keyed cooldown gate on
                    // a residue var B in a register fn, a deregister sibling that clears a
                    // *different* membership structure A but not B, and B is genuinely
                    // written elsewhere — with the both-reset-together suppression. The
                    // gate-shape + name discipline keeps this off ordinary register flows.
                    confidence = 0.6,
                    dimensions = [Dimension::Invariant],
                    message = format!(
                        "`{reg}` gates re-registration on a cooldown keyed on `{b}` (`{cond}`), but the \
                         deregister path `{dereg}` clears the operator's *membership* structure (its \
                         bitmap / registration status) WITHOUT resetting `{b}`. The membership view and \
                         the cooldown residue `{b}` are written by different functions with no joint \
                         invariant: deregister resets one, the eject/cooldown lifecycle writes the other. \
                         So a re-registration reads a **stale** `{b}` — a residue value left over from a \
                         prior lifecycle that no longer reflects the operator's true membership state — \
                         and admits or rejects the re-register on a cooldown deregister never cleared. \
                         This is the re-register cooldown / bitmap-residue class (EigenLayer \
                         `SlashingRegistryCoordinator` `lastEjectionTimestamp` vs the operator bitmap).",
                        reg = r.name,
                        dereg = dereg.name,
                        b = gate.residue_var,
                        cond = gate.cond_text,
                    ),
                    recommendation = format!(
                        "Reset the cooldown/residue field on every membership transition that clears the \
                         operator's bitmap/status: have `{dereg}` (and any force-deregister path) also \
                         clear `{b}` for that operator, or move the `{b}` write and the bitmap/status \
                         write into a single accounting function so they are guaranteed to move in \
                         lockstep. Alternatively, gate re-registration on a field that deregister provably \
                         resets, so the cooldown check cannot read residue from a stale prior lifecycle.",
                        dereg = dereg.name,
                        b = gate.residue_var,
                    ),
                );
                out.push(finish_at(cx, b, r.id, gate.span));
            }
        }
        out
    }
}

// ------------------------------------------------------------------ scope helpers

/// `c` plus every (transitive) base, resolved by exact base-name match. The
/// register / deregister / cooldown-writer trio is spread across this whole chain.
fn inheritance_chain<'a>(cx: &'a AnalysisContext, c: &'a Contract) -> Vec<&'a Contract> {
    let mut out: Vec<&Contract> = Vec::new();
    let mut seen: std::collections::HashSet<sluice_ir::ContractId> =
        std::collections::HashSet::default();
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
/// inheritance chain, de-duplicated by function id.
fn visible_functions<'a>(cx: &'a AnalysisContext, c: &'a Contract) -> Vec<&'a Function> {
    let mut out: Vec<&Function> = Vec::new();
    let mut have: std::collections::HashSet<FunctionId> = std::collections::HashSet::default();
    for k in inheritance_chain(cx, c) {
        for f in cx.scir.functions_of(k.id) {
            if have.insert(f.id) {
                out.push(f);
            }
        }
    }
    out
}

/// Every state-var name that *some* visible function writes (direct writes recorded
/// in the effect summary). A residue var must be in this set to be genuine residue.
fn vars_written_anywhere<'a>(funcs: &[&'a Function]) -> std::collections::HashSet<&'a str> {
    let mut s: std::collections::HashSet<&str> = std::collections::HashSet::default();
    for f in funcs {
        for w in &f.effects.storage_writes {
            s.insert(w.var.as_str());
        }
    }
    s
}

// --------------------------------------------------------------- name classifiers

/// A register function name: contains `register` but not `deregister`/`unregister`.
fn is_register_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("register") && !l.contains("deregister") && !l.contains("unregister")
}

/// A deregister function name: `deregister` / `unregister` (the membership-clear path).
fn is_deregister_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("deregister") || l.contains("unregister")
}

/// A state-var name that reads as a **membership** structure — the thing a deregister
/// clears (`bitmap` / `registered` / `status` / `operatorInfo` / `membership`).
fn is_membership_var(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("bitmap")
        || l.contains("registered")
        || l.contains("operatorinfo")
        || l.ends_with("status")
        || l.contains("membership")
        || l.contains("isregistered")
}

/// A state-var name that reads as a **cooldown / lifecycle-residue** structure — the
/// parallel field deregister forgets to reset. A `last*` lifecycle timestamp
/// (`lastEjectionTimestamp`, `lastDeregistered`), an explicit cooldown/apk field, or a
/// per-entity count.
fn is_residue_var(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    (l.starts_with("last") && (l.contains("timestamp") || l.contains("time") || l.contains("block") || l.contains("ejection") || l.contains("deregist") || l.contains("regist")))
        || l.contains("cooldown")
        || l.contains("ejection")
        || (l.contains("apk") )
        || l.contains("lastderegist")
}

/// An internal-call / helper name that *clears a membership bitmap or deletes a
/// membership entry* — `updateOperatorBitmap`, `*bitmap*`, a membership `delete`.
fn is_membership_clearing_call(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("bitmap") || l.contains("updateoperator") || l.contains("removeoperator")
}

/// Does the guard's error/reason text read as a **re-register cooldown** gate?
fn reason_reads_reregister_cooldown(text: &str) -> bool {
    let l = text.to_ascii_lowercase();
    l.contains("reregister")
        || l.contains("re-register")
        || l.contains("cooldown")
        || l.contains("tooearly")
        || l.contains("notexpired")
        || l.contains("cannotregisteryet")
        || l.contains("cannotreregister")
}

// ----------------------------------------------------------------- membership clear

/// Does deregister function `d` clear a **membership** structure `A` — write a
/// membership-named state var (`bitmap`/`status`/`registered`/`operatorInfo`), or
/// `delete` such a var, or invoke a membership-clearing helper
/// (`updateOperatorBitmap` / `*bitmap*`)?
fn clears_membership(d: &Function) -> bool {
    // Direct effect-summary write of a membership-named var.
    if d.effects.storage_writes.iter().any(|w| is_membership_var(&w.var)) {
        return true;
    }
    // Reads a membership-named var AND calls a bitmap/membership-clearing helper —
    // the `_updateOperatorBitmap(operatorId, newBitmap)` indirection (the bitmap clear
    // is performed inside a library, so it surfaces as an internal call + a read of
    // the history/membership var, not a direct write attributed to `d`).
    let calls_clear = d.effects.internal_calls.iter().any(|n| is_membership_clearing_call(n));
    if calls_clear {
        return true;
    }
    // A `delete <membershipVar>[..]` in the body (delete lowers to a Unary::Delete).
    let mut deletes_membership = false;
    for s in &d.body {
        s.visit_exprs(&mut |e| {
            if deletes_membership {
                return;
            }
            if let ExprKind::Unary { op: UnOp::Delete, operand } = &e.kind {
                if root_ident_str(operand).is_some_and(is_membership_var) {
                    deletes_membership = true;
                }
            }
        });
        if deletes_membership {
            break;
        }
    }
    deletes_membership
}

// ----------------------------------------------------------------- cooldown gate

/// Find the first **cooldown gate** in register function `r`: a `require(cond, err)`
/// or `if (cond) revert/return` whose `cond` is a *time comparison* reading a residue
/// state var `B`, where the gate reads as a re-register cooldown. Returns `B` (the
/// residue var) and the guard span.
fn find_cooldown_gate(cx: &AnalysisContext, r: &Function) -> Option<CooldownGate> {
    let mut hit: Option<CooldownGate> = None;
    for top in &r.body {
        top.visit(&mut |st| {
            if hit.is_some() {
                return;
            }
            match &st.kind {
                // `require(cond, ErrOrReason)` / `assert(cond)`.
                StmtKind::Expr(e) => {
                    e.visit(&mut |sub| {
                        if hit.is_some() {
                            return;
                        }
                        let ExprKind::Call(call) = &sub.kind else { return };
                        if !matches!(
                            call.kind,
                            CallKind::Builtin(Builtin::Require) | CallKind::Builtin(Builtin::Assert)
                        ) {
                            return;
                        }
                        let Some(cond) = call.args.first() else { return };
                        // Reason / error text = the *other* require args (an error call
                        // or a string literal).
                        let reason_text: String = call
                            .args
                            .iter()
                            .skip(1)
                            .map(|a| cx.source_text(a.span))
                            .collect::<Vec<_>>()
                            .join(" ");
                        if let Some((b, has_period_form)) = time_gate_residue_var(cond) {
                            // Accept iff the gate reads as a re-register cooldown: an
                            // explicit reason/error name, OR a `B + period` deadline form
                            // (the precomputed cooldown deadline), OR the var name itself
                            // reads as a cooldown/lifecycle residue.
                            if reason_reads_reregister_cooldown(&reason_text)
                                || has_period_form
                                || is_residue_var(&b)
                            {
                                hit = Some(CooldownGate {
                                    residue_var: b,
                                    span: sub.span,
                                    cond_text: clip(&cx.source_text(cond.span)),
                                });
                            }
                        }
                    });
                }
                // `if (cond) revert E;` / `if (cond) return;` — bare guard form.
                StmtKind::If { cond, then_branch, else_branch } => {
                    if !else_branch.is_empty() {
                        return;
                    }
                    let reason_text = branch_revert_reason(then_branch);
                    let Some(reason_text) = reason_text else { return };
                    if let Some((b, has_period_form)) = time_gate_residue_var(cond) {
                        if reason_reads_reregister_cooldown(&reason_text)
                            || has_period_form
                            || is_residue_var(&b)
                        {
                            hit = Some(CooldownGate {
                                residue_var: b,
                                span: st.span,
                                cond_text: clip(&cx.source_text(cond.span)),
                            });
                        }
                    }
                }
                _ => {}
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// If `cond` is a **time comparison** that reads a residue state var `B`, return
/// `(B, has_period_form)`. Accepted forms (the cooldown-deadline boundary):
///   * `B[..] + period </> block.timestamp`  (`has_period_form = true`)
///   * `block.timestamp </> B[..] + period`   (`has_period_form = true`)
///   * `block.timestamp </> B[..]`            (`has_period_form = false`)
///   * `B[..] </> block.timestamp`            (`has_period_form = false`)
///
/// `B` is the *indexed/base* state var on the non-`block.timestamp` side (the residue
/// field the cooldown keys on). The `+ period` form additionally witnesses a cooldown
/// deadline even when the var/error names are generic.
fn time_gate_residue_var(cond: &Expr) -> Option<(String, bool)> {
    let ExprKind::Binary { op, lhs, rhs } = &cond.kind else { return None };
    if !matches!(op, BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge) {
        return None;
    }
    // Identify the `block.timestamp`/`now` side and the deadline side.
    let (deadline, _now_on_left) = if expr_is_now(lhs) {
        (rhs.as_ref(), true)
    } else if expr_is_now(rhs) {
        (lhs.as_ref(), false)
    } else {
        return None;
    };
    // Deadline is `B + period` or a bare `B`.
    if let ExprKind::Binary { op: BinOp::Add, lhs: dl, rhs: dr } = &deadline.kind {
        // Pick the side that is a (indexed) state-var read as B; the other is the period.
        if let Some(b) = leaf_state_var(dl) {
            return Some((b, true));
        }
        if let Some(b) = leaf_state_var(dr) {
            return Some((b, true));
        }
        return None;
    }
    // Bare `block.timestamp </> B[..]` — B is the deadline directly.
    leaf_state_var(deadline).map(|b| (b, false))
}

/// Root identifier of an index/member chain if it is a plausible *state-var* read
/// `var[..]` / `var.field` / `var` (we return the root name). Casts are peeled.
fn leaf_state_var(e: &Expr) -> Option<String> {
    match &peel_casts(e).kind {
        ExprKind::Index { base, .. } => leaf_state_var(base),
        ExprKind::Member { base, .. } => leaf_state_var(base),
        ExprKind::Ident(n) => Some(n.clone()),
        _ => None,
    }
}

/// Is `e` `block.timestamp` / `block.number` / a bare `now`?
fn expr_is_now(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Member { base, member } => {
            let m = member.to_ascii_lowercase();
            (m == "timestamp" || m == "number")
                && matches!(&base.kind, ExprKind::Ident(b) if b == "block")
        }
        ExprKind::Ident(n) => n == "now",
        _ => false,
    }
}

/// If `branch` is a single bare `revert`/`return`, return its reason label (the error
/// name when present, else empty so the var-name/period signals can still apply).
fn branch_revert_reason(branch: &[Stmt]) -> Option<String> {
    if branch.len() != 1 {
        return None;
    }
    match &branch[0].kind {
        StmtKind::Revert { error, .. } => Some(error.clone().unwrap_or_default()),
        StmtKind::Return(_) => Some(String::new()),
        _ => None,
    }
}

/// Trim a source snippet for inclusion in a message (single line, length-bounded).
fn clip(s: &str) -> String {
    let one = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.len() > 100 {
        format!("{}…", &one[..100])
    } else {
        one
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    // Run ONLY this detector against `src`, building the analysis context directly so
    // the unit tests are independent of the sibling-detector registry.
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        let parsed = sluice_parse::parse_sources(vec![("t.sol".into(), src.into())]);
        let scir = parsed.scir;
        let dataflow = sluice_dataflow::DataflowFacts::analyze(&scir);
        let invariants = sluice_invariant::InvariantFacts::mine(&scir);
        let frontier = sluice_frontier::FrontierFacts::analyze(&scir);
        let cfg = Config::default();
        let cx = AnalysisContext::new(&scir, &dataflow, &invariants, &frontier, &cfg);
        ReregisterCooldownBitmapResidueDetector.run(&cx)
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "reregister-cooldown-bitmap-residue")
    }

    // VULN — the exact EigenLayer SlashingRegistryCoordinator shape: register gates on
    // `lastEjectionTimestamp[op] + ejectionCooldown < block.timestamp` (CannotReregisterYet),
    // deregister clears the bitmap + status but never resets lastEjectionTimestamp, and
    // the cooldown var is written by the eject lifecycle.
    const VULN: &str = r#"
        library Lib { function update(mapping(bytes32 => uint256) storage h, bytes32 id, uint192 b) internal {} }
        contract Coord {
            mapping(bytes32 => uint256) operatorBitmap;      // membership A
            mapping(address => uint8) operatorStatus;        // membership A
            mapping(address => uint256) lastEjectionTimestamp; // cooldown residue B
            uint256 ejectionCooldown;

            function _registerOperator(address operator, bytes32 operatorId, uint192 newBitmap) internal {
                require(
                    lastEjectionTimestamp[operator] + ejectionCooldown < block.timestamp,
                    "CannotReregisterYet"
                );
                Lib.update(operatorBitmap, operatorId, newBitmap);
                operatorStatus[operator] = 1;
            }

            function _deregisterOperator(address operator, bytes32 operatorId) internal {
                Lib.update(operatorBitmap, operatorId, 0);
                operatorStatus[operator] = 2;  // clears membership, NOT lastEjectionTimestamp
            }

            function ejectOperator(address operator) external {
                lastEjectionTimestamp[operator] = block.timestamp;  // residue B written on eject
            }
        }
    "#;

    // VULN variant — register/deregister/cooldown split across an inherited *Storage*
    // base; deregister clears the bitmap via an `_updateOperatorBitmap` helper call;
    // the cooldown gate is an `if (...) revert`.
    const VULN_INHERITED: &str = r#"
        abstract contract Storage {
            mapping(bytes32 => uint256) internal _operatorBitmapHistory; // membership A
            mapping(address => uint256) public lastEjectionTimestamp;    // residue B
            uint256 public ejectionCooldown;
        }
        contract Coordinator is Storage {
            function _updateOperatorBitmap(bytes32 id, uint192 b) internal {}
            function ejectOperator(address op) external { lastEjectionTimestamp[op] = block.timestamp; }

            function _registerOperator(address operator, bytes32 id, uint192 nb) internal {
                if (lastEjectionTimestamp[operator] + ejectionCooldown >= block.timestamp) {
                    revert CannotReregisterYet();
                }
                _updateOperatorBitmap(id, nb);
            }
            function _deregisterOperator(address operator, bytes32 id) internal {
                _updateOperatorBitmap(id, 0);  // clears bitmap A, not residue B
            }
        }
    "#;

    // SAFE (both reset together) — the EigenLayer `ECDSAStakeRegistry` shape: deregister
    // resets BOTH `_operatorRegistered` (membership) AND `_totalOperators` (count) in
    // lockstep, and register reads exactly those — there is no unreset residue var.
    const SAFE_BOTH_RESET: &str = r#"
        contract Registry {
            mapping(address => bool) _operatorRegistered;  // membership A
            uint256 _totalOperators;                       // count B (but reset on deregister)
            uint256 registrationCooldown;

            function _registerOperator(address operator) internal {
                require(_totalOperators + registrationCooldown < block.timestamp, "TooEarly");
                _operatorRegistered[operator] = true;
                _totalOperators += 1;
            }
            function _deregisterOperator(address operator) internal {
                _operatorRegistered[operator] = false;
                _totalOperators -= 1;   // residue ALSO reset here -> SUPPRESS
            }
        }
    "#;

    // SAFE (no cooldown gate) — deregister clears the bitmap, register sets it, but the
    // register has no time/cooldown gate keyed on a residue var at all.
    const SAFE_NO_GATE: &str = r#"
        contract Reg {
            mapping(bytes32 => uint256) operatorBitmap;
            mapping(address => uint256) lastEjectionTimestamp;
            function _registerOperator(bytes32 id, uint192 nb) internal { operatorBitmap[id] = nb; }
            function _deregisterOperator(bytes32 id) internal { operatorBitmap[id] = 0; }
            function eject(address op) external { lastEjectionTimestamp[op] = block.timestamp; }
        }
    "#;

    // SAFE (residue var never written) — the register gates on a cooldown var, but no
    // function ever writes it (an always-default read), so it cannot carry residue.
    const SAFE_RESIDUE_NEVER_WRITTEN: &str = r#"
        contract Reg {
            mapping(bytes32 => uint256) operatorBitmap;
            mapping(address => uint256) lastEjectionTimestamp; // never written anywhere
            uint256 ejectionCooldown;
            function _registerOperator(address op, bytes32 id, uint192 nb) internal {
                require(lastEjectionTimestamp[op] + ejectionCooldown < block.timestamp, "CannotReregisterYet");
                operatorBitmap[id] = nb;
            }
            function _deregisterOperator(bytes32 id) internal { operatorBitmap[id] = 0; }
        }
    "#;

    // SAFE (no deregister clears membership) — there is a cooldown-gated register and a
    // written residue var, but no deregister function clears any membership structure
    // (the only deregister touches an unrelated scalar), so there is no
    // clears-A-but-not-B pairing.
    const SAFE_NO_MEMBERSHIP_CLEAR: &str = r#"
        contract Reg {
            mapping(address => uint256) lastEjectionTimestamp;
            uint256 ejectionCooldown;
            uint256 somethingElse;
            function _registerOperator(address op) internal {
                require(lastEjectionTimestamp[op] + ejectionCooldown < block.timestamp, "CannotReregisterYet");
            }
            function eject(address op) external { lastEjectionTimestamp[op] = block.timestamp; }
            function _deregisterOperator() internal { somethingElse = 1; }
        }
    "#;

    #[test]
    fn fires_on_eigenlayer_last_ejection_residue() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_inherited_bitmap_helper_shape() {
        assert!(fires(VULN_INHERITED), "{:#?}", run(VULN_INHERITED));
    }

    #[test]
    fn silent_when_both_reset_together() {
        assert!(!fires(SAFE_BOTH_RESET), "{:#?}", run(SAFE_BOTH_RESET));
    }

    #[test]
    fn silent_without_cooldown_gate() {
        assert!(!fires(SAFE_NO_GATE), "{:#?}", run(SAFE_NO_GATE));
    }

    #[test]
    fn silent_when_residue_never_written() {
        assert!(!fires(SAFE_RESIDUE_NEVER_WRITTEN), "{:#?}", run(SAFE_RESIDUE_NEVER_WRITTEN));
    }

    #[test]
    fn silent_without_membership_clearing_deregister() {
        assert!(!fires(SAFE_NO_MEMBERSHIP_CLEAR), "{:#?}", run(SAFE_NO_MEMBERSHIP_CLEAR));
    }
}
