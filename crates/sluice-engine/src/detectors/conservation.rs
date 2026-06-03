//! **Conservation / accounting-invariant** — an obligation amount is capped to a
//! *partial* fund source inside a coverage check, while a recovery action in the
//! same branch is expected to make the obligation whole — yet the recovered value
//! never increases the coverage, so the shortfall is silently dropped (the Stader
//! `ValidatorWithdrawalVault.settleFunds` M-12 class).
//!
//! ## The class
//!
//! When a protocol settles a debt / penalty / obligation `P` against a balance
//! component `B`, conservation requires that the *full* obligation be covered —
//! either from `B` plus the other funds the protocol can draw on, or by carrying
//! the uncovered shortfall (`P − B`) forward. A common, subtly-broken pattern
//! instead does:
//!
//! ```solidity
//! uint256 penaltyAmount = getUpdatedPenaltyAmount(...);          // obligation P
//! if (operatorShare < penaltyAmount) {                           // B < P
//!     ISDCollateral(...).slashValidatorSD(validatorId, poolId);  // RECOVERY (external)
//!     penaltyAmount = operatorShare;                             // clamp P := B
//! }
//! uint256 userShare = userSharePrelim + penaltyAmount;           // uses the *capped* P
//! operatorShare = operatorShare - penaltyAmount;
//! ```
//!
//! `B` (`operatorShare`) is only **one component** of the value the obligation
//! should be settled against, and the branch fires a *recovery* action
//! (`slashValidatorSD` — it slashes the operator's SD collateral elsewhere to make
//! the protocol whole). But the obligation is then clamped to `B` regardless of
//! what the recovery yields: the slashed collateral never flows back into
//! `penaltyAmount`, so the coverage applied here is capped at `B` and the
//! shortfall `P − B` is **conserved away** — the operator is under-charged (or the
//! protocol under-collects) by exactly that residual. This is the Stader M-12
//! accounting-error finding (`settleFunds` ignores the operator's other
//! attributable funds when computing penalty coverage).
//!
//! ## What fires (structural, no provenance dependency)
//!
//! An `if` statement whose:
//!   1. condition is an ordering compare `B < P` / `B <= P` where the **larger
//!      side `P`** is a local whose name reads like an **obligation**
//!      (`penalty`/`debt`/`owed`/`slash`/`fine`/`deficit`/`shortfall`/`due`…); and
//!   2. then-branch contains a **down-clamp** `P = B` (assigns the obligation to
//!      the smaller operand of its own coverage check); and
//!   3. that same branch makes a **recovery external call** — the action that is
//!      *supposed* to make the obligation whole from another fund source — whose
//!      result is never folded back into `P`.
//!
//! ## Suppressions (precision first)
//!
//!   * **S1 — shortfall conserved / carried forward.** If the clamped-off residual
//!     is preserved — a state-var ledger is credited the *pre-clamp* obligation
//!     (`owed[x] += P` before the clamp), or the function records a separate
//!     shortfall/deficit variable — the value is not dropped and nothing fires.
//!   * **S2 — no recovery call in the branch.** A plain `P = min(P, B)` clamp with
//!     no recovery action is an ordinary saturating cap (the disfavored party is
//!     *meant* to bear it); without the in-branch recovery there is no evidence the
//!     protocol expected to cover the shortfall, so it stays silent.
//!   * **S3 — obligation not actually consumed after the clamp.** If `P` is not
//!     read again after the guard (e.g. it was only logged), there is no downstream
//!     under-credit and nothing fires.
//!
//! The detector emits a single Invariant-dimension finding anchored at the clamp;
//! the corroboration scorer (`score.rs`) routes a lone Invariant heuristic to
//! Low/Info and only promotes it when another dimension agrees — inheriting the
//! precision waves' discipline exactly as PHASE B1 did.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{AssignOp, BinOp, CallKind, Expr, ExprKind, Function, Span, Stmt, StmtKind};

use super::prelude::*;

pub struct ConservationDetector;

/// Words that mark a local as an **obligation** — a debt/penalty the protocol must
/// collect or cover in full. Matched as a case-insensitive substring of the local
/// name. Deliberately narrow: an obligation is a quantity whose *shortfall matters*
/// (under-collecting it loses the protocol value), as opposed to a generic
/// `amount`/`balance`/`share`.
const OBLIGATION_WORDS: &[&str] = &[
    "penalty", "penalties", "debt", "owed", "slash", "fine", "deficit",
    "shortfall", "due", "obligation", "liability", "liabilities", "arrears",
];

/// Words on the residual-carry side that mark a write as **conserving** the
/// shortfall (S1): a ledger / accrual the dropped remainder would be recorded
/// into. If the function credits one of these with the *pre-clamp* obligation, the
/// value is not lost.
const CARRY_WORDS: &[&str] = &[
    "shortfall", "deficit", "owed", "debt", "arrears", "outstanding",
    "uncovered", "remaining", "carry", "pending", "unpaid",
];

impl Detector for ConservationDetector {
    fn id(&self) -> &'static str {
        "conservation"
    }
    fn category(&self) -> Category {
        Category::Conservation
    }
    fn description(&self) -> &'static str {
        "An obligation (penalty / debt / owed amount) is clamped down to a partial fund \
         component inside its coverage check while a recovery action in the same branch is \
         expected to make it whole — the recovered value never folds back, so the shortfall is \
         silently dropped (the Stader settleFunds M-12 accounting class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || f.is_view_or_pure() {
                continue;
            }
            // Interface/abstract declarations carry no implementation.
            if cx.contract_of(f.id).map(|c| c.is_interface()).unwrap_or(false) {
                continue;
            }
            if let Some(hit) = find_dropped_shortfall(cx, f) {
                let b = report!(self, Category::Conservation,
                    title = "Obligation clamped to a partial fund source; recovery does not cover the dropped shortfall",
                    severity = Severity::Medium,
                    confidence = 0.55,
                    dimensions = [Dimension::Invariant],
                    message = format!(
                        "`{fname}` settles an obligation (`{p}`) against only the balance component \
                         `{b}`: inside the coverage check `if ({b} < {p})` it performs a recovery \
                         action (an external call meant to make the obligation whole from another \
                         fund source) and then clamps `{p} = {b}`. Because the recovered value is \
                         never folded back into `{p}`, the obligation is capped at the single \
                         component `{b}` regardless of what the recovery yields, so the shortfall \
                         (`{p} − {b}`) is silently dropped — the protocol under-collects (or the \
                         charged party is under-debited) by exactly that residual. This is the \
                         conservation/accounting-invariant class (Stader `settleFunds` ignoring the \
                         operator's other attributable funds when computing penalty coverage).",
                        fname = f.name,
                        p = hit.obligation,
                        b = hit.cap,
                    ),
                    recommendation = "Settle the obligation against the *complete* set of funds the \
                         protocol can draw on (include every attributable balance / reward source, \
                         and fold the recovery action's proceeds back into the covered amount), or \
                         carry the uncovered shortfall (`obligation − available`) forward as an \
                         explicit debt/deficit so it is not silently written off.",
                );
                out.push(finish_at(cx, b, f.id, hit.anchor));
            }
        }
        out
    }
}

// ------------------------------------------------------------------- internals

/// A located dropped-shortfall hit.
struct ShortfallHit {
    /// Span to anchor (the clamp assignment `P = B`).
    anchor: Span,
    /// Obligation local name (`penaltyAmount`).
    obligation: String,
    /// Cap component name (`operatorShare`).
    cap: String,
}

/// Scan `f` for the dropped-shortfall conservation shape: an `if (B < P)` /
/// `if (B <= P)` guard with an obligation-named `P`, whose then-branch both
/// down-clamps `P = B` and fires a recovery external call, and where the
/// pre-clamp shortfall is not conserved.
fn find_dropped_shortfall(cx: &AnalysisContext, f: &Function) -> Option<ShortfallHit> {
    let mut hit: Option<ShortfallHit> = None;
    walk_stmts(&f.body, &mut |s| {
        if hit.is_some() {
            return;
        }
        let StmtKind::If { cond, then_branch, .. } = &s.kind else { return };
        // (1) condition `B < P` / `B <= P` — the obligation `P` is the *larger* side.
        let Some((cap_expr, obl_expr)) = coverage_compare(cond) else { return };
        let Some(obligation) = root_ident_str(obl_expr) else { return };
        if !is_obligation_name(obligation) {
            return;
        }
        let Some(cap) = root_ident_str(cap_expr) else { return };
        // `B` and `P` must be distinct locals.
        if cap == obligation {
            return;
        }

        // (2) then-branch down-clamps `P = B` (assigns obligation to the cap operand).
        if !branch_clamps(then_branch, obligation, cap) {
            return;
        }

        // (3) then-branch fires a recovery external call (the action expected to
        // make the obligation whole from another source). A bare `min`-style clamp
        // with NO recovery is an ordinary saturating cap (S2) and is ignored.
        if !branch_has_recovery_call(then_branch) {
            return;
        }

        // S1 — the pre-clamp shortfall is conserved (carried into a ledger / a
        // shortfall var). If so, nothing is dropped.
        if shortfall_conserved(cx, f, &obligation) {
            return;
        }

        // S3 — the obligation must actually be consumed after the clamp (read into a
        // payout / accounting write downstream), else the under-credit cannot occur.
        let clamp_span = clamp_assignment_span(then_branch, &obligation, &cap);
        if !obligation_consumed_after(f, &obligation, clamp_span) {
            return;
        }

        hit = Some(ShortfallHit {
            anchor: clamp_span.unwrap_or(s.span),
            obligation: obligation.to_string(),
            cap: cap.to_string(),
        });
    });
    hit
}

/// If `cond` is an ordering comparison whose smaller side is `B` and larger side
/// is `P` (`B < P`, `B <= P`, or the mirror `P > B` / `P >= B`), return
/// `(B_expr, P_expr)`. The "larger" side is the obligation being capped.
fn coverage_compare(cond: &Expr) -> Option<(&Expr, &Expr)> {
    let ExprKind::Binary { op, lhs, rhs } = &cond.kind else { return None };
    match op {
        // `B < P` / `B <= P` → (B, P) = (lhs, rhs)
        BinOp::Lt | BinOp::Le => Some((lhs, rhs)),
        // `P > B` / `P >= B` → (B, P) = (rhs, lhs)
        BinOp::Gt | BinOp::Ge => Some((rhs, lhs)),
        _ => None,
    }
}

/// Does `name` read like an obligation (a debt/penalty the protocol must collect
/// in full)?
fn is_obligation_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    OBLIGATION_WORDS.iter().any(|w| l.contains(w))
}

/// Does `branch` contain a **down-clamp** `obligation = cap` — a plain assignment
/// of the obligation local to the cap operand (the truncation of `P` to `B`)?
/// Also accepts `obligation = min(obligation, cap)` / `min(cap, obligation)`.
fn branch_clamps(branch: &[Stmt], obligation: &str, cap: &str) -> bool {
    let mut found = false;
    walk_stmts(branch, &mut |s| {
        if found {
            return;
        }
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind else { return };
            if root_ident_str(target) != Some(obligation) {
                return;
            }
            // Direct `P = B`.
            if root_ident_str(value) == Some(cap) {
                found = true;
                return;
            }
            // `P = min(P, B)` / `P = min(B, P)`.
            if let ExprKind::Call(c) = &value.kind {
                let n = c.func_name.as_deref().unwrap_or("").to_ascii_lowercase();
                if n == "min" {
                    let names: Vec<&str> = c.args.iter().filter_map(|a| root_ident_str(a)).collect();
                    if names.contains(&cap) && names.contains(&obligation) {
                        found = true;
                    }
                }
            }
        });
    });
    found
}

/// Span of the clamp assignment `obligation = cap` (or `= min(...)`) within
/// `branch`, for precise anchoring.
fn clamp_assignment_span(branch: &[Stmt], obligation: &str, cap: &str) -> Option<Span> {
    let mut span: Option<Span> = None;
    walk_stmts(branch, &mut |s| {
        if span.is_some() {
            return;
        }
        s.visit_exprs(&mut |e| {
            if span.is_some() {
                return;
            }
            let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind else { return };
            if root_ident_str(target) != Some(obligation) {
                return;
            }
            let is_clamp = root_ident_str(value) == Some(cap)
                || matches!(&value.kind, ExprKind::Call(c)
                    if c.func_name.as_deref().map(|n| n.eq_ignore_ascii_case("min")).unwrap_or(false));
            if is_clamp {
                span = Some(e.span);
            }
        });
    });
    span
}

/// Does `branch` make a **recovery external call** — an external / low-level call
/// (a slash, a pull-from-elsewhere, a top-up) that is the action expected to make
/// the obligation whole from another fund source? A pure internal helper or a
/// `require`/event is not a recovery.
fn branch_has_recovery_call(branch: &[Stmt]) -> bool {
    let mut found = false;
    walk_stmts(branch, &mut |s| {
        if found {
            return;
        }
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if matches!(c.kind, CallKind::External | CallKind::LowLevelCall) {
                    found = true;
                }
            }
        });
    });
    found
}

/// S1 — is the pre-clamp shortfall conserved? True if anywhere in `f` a write
/// credits a **carry/shortfall ledger** (a state var, or an indexed write, whose
/// name reads like `shortfall`/`owed`/`debt`/…) using the *obligation* value — i.e.
/// the dropped remainder is recorded rather than lost. Conservative: any `+=`/`=`
/// whose target name matches a carry word and whose RHS mentions the obligation.
fn shortfall_conserved(cx: &AnalysisContext, f: &Function, obligation: &str) -> bool {
    let mut conserved = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if conserved {
                return;
            }
            let ExprKind::Assign { op, target, value } = &e.kind else { return };
            // A carry is an accrual (`+=`) or a fresh record (`=`) into a carry-named slot.
            if !matches!(op, AssignOp::Add | AssignOp::Assign) {
                return;
            }
            let Some(root) = root_ident_str(target) else { return };
            let rl = root.to_ascii_lowercase();
            if !CARRY_WORDS.iter().any(|w| rl.contains(w)) {
                return;
            }
            // The target should be real bookkeeping the residual is preserved in: a
            // state var (a persistent ledger) — not just any local. (A local named
            // `remaining` that is never persisted does not conserve value.)
            let persists = root_is_settable_state_var(cx, f, target)
                || matches!(&target.kind, ExprKind::Index { .. } | ExprKind::Member { .. });
            if persists && expr_mentions_ident(value, obligation) {
                conserved = true;
            }
        });
        if conserved {
            break;
        }
    }
    conserved
}

/// S3 — is `obligation` read again *after* the clamp (so the under-credit can
/// actually propagate)? We approximate "after" by: the obligation appears as a
/// read (an identifier not on the LHS of its own clamp) in a statement whose span
/// starts at/after the clamp span. If we cannot locate the clamp span, require any
/// read of the obligation in an arithmetic/accounting position.
fn obligation_consumed_after(f: &Function, obligation: &str, clamp_span: Option<Span>) -> bool {
    let after = clamp_span.map(|s| s.start).unwrap_or(0);
    let mut consumed = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if consumed {
                return;
            }
            // Only look at reads strictly after the clamp.
            if e.span.start <= after {
                return;
            }
            // A use of the obligation inside an Add/Sub binary, a VarDecl init, a
            // call arg, or a `{value:}` operand is a downstream consumption.
            match &e.kind {
                ExprKind::Binary { op: BinOp::Add | BinOp::Sub, lhs, rhs } => {
                    if expr_mentions_ident(lhs, obligation) || expr_mentions_ident(rhs, obligation) {
                        consumed = true;
                    }
                }
                _ => {}
            }
        });
        if consumed {
            break;
        }
    }
    consumed
}

/// Walk a statement tree, invoking `visit` on every statement (including nested
/// branch/loop/try bodies). Unlike `Stmt::visit`, the callback sees each *statement*
/// (so an `If` node can be inspected as a whole), descending into sub-statements.
fn walk_stmts(stmts: &[Stmt], visit: &mut impl FnMut(&Stmt)) {
    for s in stmts {
        visit(s);
        match &s.kind {
            StmtKind::If { then_branch, else_branch, .. } => {
                walk_stmts(then_branch, visit);
                walk_stmts(else_branch, visit);
            }
            StmtKind::While { body, .. }
            | StmtKind::DoWhile { body, .. }
            | StmtKind::For { body, .. }
            | StmtKind::Block { stmts: body, .. } => {
                walk_stmts(body, visit);
            }
            StmtKind::Try { body, catches, .. } => {
                walk_stmts(body, visit);
                for c in catches {
                    walk_stmts(&c.body, visit);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    fn fired(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.detector == "conservation")
    }

    // VULN — the Stader `settleFunds` M-12 shape: `penaltyAmount` (obligation) is
    // capped to `operatorShare` (one balance component) inside `if (operatorShare <
    // penaltyAmount)`, the branch fires a recovery external call (`slashValidatorSD`),
    // and the capped penalty is then consumed downstream (`userShare = ... +
    // penaltyAmount`). The slashed funds never fold back, so the shortfall is dropped.
    const VULN: &str = r#"
        interface ISDCollateral { function slashValidatorSD(uint256 id, uint8 p) external; }
        interface ISink { function depositFor(address a) external payable; }
        contract Vault {
            function settleFunds(uint256 userSharePrelim, uint256 operatorShare, uint256 protocolShare) external {
                uint256 penaltyAmount = getPenalty();
                if (operatorShare < penaltyAmount) {
                    ISDCollateral(sd()).slashValidatorSD(1, 1);
                    penaltyAmount = operatorShare;
                }
                uint256 userShare = userSharePrelim + penaltyAmount;
                operatorShare = operatorShare - penaltyAmount;
                ISink(sink()).depositFor{value: operatorShare}(msg.sender);
            }
            function getPenalty() internal returns (uint256) { return 5; }
            function sd() internal view returns (address) { return address(0x1); }
            function sink() internal view returns (address) { return address(0x2); }
        }
    "#;

    // SAFE-NO-RECOVERY — an ordinary saturating cap `if (bal < penalty) penalty =
    // bal;` with NO recovery action in the branch (S2). A plain `min` of the penalty
    // to the available balance is a deliberate cap, not a dropped-shortfall bug.
    const SAFE_NO_RECOVERY: &str = r#"
        interface ISink { function depositFor(address a) external payable; }
        contract Vault {
            function settle(uint256 bal) external {
                uint256 penaltyAmount = getPenalty();
                if (bal < penaltyAmount) {
                    penaltyAmount = bal;
                }
                uint256 left = bal - penaltyAmount;
                ISink(sink()).depositFor{value: left}(msg.sender);
            }
            function getPenalty() internal returns (uint256) { return 5; }
            function sink() internal view returns (address) { return address(0x2); }
        }
    "#;

    // SAFE-CONSERVED — the shortfall IS carried forward: before the clamp the
    // pre-clamp obligation is recorded into an `owedDebt` ledger, so the residual is
    // not dropped (S1). Must stay silent even though it has a recovery call.
    const SAFE_CONSERVED: &str = r#"
        interface ISDCollateral { function slashValidatorSD(uint256 id, uint8 p) external; }
        contract Vault {
            mapping(address => uint256) public owedDebt;
            function settle(address op, uint256 operatorShare) external {
                uint256 penaltyAmount = getPenalty();
                if (operatorShare < penaltyAmount) {
                    ISDCollateral(sd()).slashValidatorSD(1, 1);
                    owedDebt[op] += penaltyAmount;
                    penaltyAmount = operatorShare;
                }
                uint256 charged = operatorShare - penaltyAmount;
                operatorShare = charged;
            }
            function getPenalty() internal returns (uint256) { return 5; }
            function sd() internal view returns (address) { return address(0x1); }
        }
    "#;

    // SAFE-NOT-OBLIGATION — the capped variable is a generic `amount` (not an
    // obligation-named quantity), so it is not the obligation-coverage class. A
    // recovery call and a clamp are present, but `amount` could be anything.
    const SAFE_NOT_OBLIGATION: &str = r#"
        interface IFoo { function pull(uint256 a) external; }
        contract Vault {
            function f(uint256 cap) external {
                uint256 amount = compute();
                if (cap < amount) {
                    IFoo(t()).pull(amount);
                    amount = cap;
                }
                uint256 used = amount + 1;
                consume(used);
            }
            function compute() internal returns (uint256) { return 5; }
            function consume(uint256 x) internal {}
            function t() internal view returns (address) { return address(0x1); }
        }
    "#;

    // SAFE-NOT-CONSUMED — the obligation is clamped with a recovery call but never
    // read after the clamp (only logged), so no downstream under-credit (S3).
    const SAFE_NOT_CONSUMED: &str = r#"
        interface ISDCollateral { function slashValidatorSD(uint256 id, uint8 p) external; }
        contract Vault {
            event Penalized(uint256 p);
            function settle(uint256 operatorShare) external {
                uint256 penaltyAmount = getPenalty();
                if (operatorShare < penaltyAmount) {
                    ISDCollateral(sd()).slashValidatorSD(1, 1);
                    penaltyAmount = operatorShare;
                }
                emit Penalized(penaltyAmount);
            }
            function getPenalty() internal returns (uint256) { return 5; }
            function sd() internal view returns (address) { return address(0x1); }
        }
    "#;

    #[test]
    fn fires_on_settlefunds_shape() {
        let fs = run(VULN);
        assert!(
            fs.iter().any(|f| f.detector == "conservation" && f.function == "settleFunds"),
            "expected conservation @ settleFunds; got {:?}",
            fs.iter().map(|f| (&f.detector, &f.function)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn silent_on_saturating_cap_without_recovery() {
        assert!(!fired(&run(SAFE_NO_RECOVERY)), "a plain min-cap with no recovery is not the class (S2)");
    }

    #[test]
    fn silent_when_shortfall_conserved() {
        assert!(!fired(&run(SAFE_CONSERVED)), "shortfall carried into owedDebt is not dropped (S1)");
    }

    #[test]
    fn silent_on_non_obligation_var() {
        assert!(!fired(&run(SAFE_NOT_OBLIGATION)), "a generic `amount` is not an obligation");
    }

    #[test]
    fn silent_when_obligation_not_consumed() {
        assert!(!fired(&run(SAFE_NOT_CONSUMED)), "obligation only logged, not consumed (S3)");
    }

    #[test]
    fn vuln_is_medium_or_low_band() {
        // A lone Invariant-dimension finding at base Medium / conf 0.55 lands in the
        // Low/Medium band via the scorer (no bespoke severity path) — the design's
        // conservative routing for an inference heuristic. It must NOT be Crit/High
        // on its own (precision: dogfood Crit/High delta stays 0).
        let fs = run(VULN);
        let f = fs.iter().find(|f| f.detector == "conservation").expect("fired");
        assert!(
            matches!(f.severity, sluice_findings::Severity::Low | sluice_findings::Severity::Medium | sluice_findings::Severity::Info),
            "expected Low/Medium/Info, got {:?} (score {})",
            f.severity, f.severity_score
        );
    }
}
