//! Churn / replace double-counted kick-threshold base — an operator-replacement
//! ("churn") path validates the kick/churn stake threshold against a quorum total
//! that was measured *after* the incoming operator already self-registered, so the
//! total it bases the threshold on **double-counts** both the newcomer *and* the
//! operator about to be kicked.
//!
//! ## The shape
//!
//! EigenLayer middleware's `SlashingRegistryCoordinator._registerOperatorWithChurn`
//! (and the `RegistryCoordinator` override) register the incoming operator *first*,
//! capturing the post-registration totals in a results struct, then loop over the
//! over-capacity quorums and validate the churn using those returned totals:
//!
//! ```solidity
//! function _registerOperatorWithChurn(...) internal {
//!     ...
//!     // (1) the newcomer self-registers; `results.totalStakes[i]` is the quorum
//!     //     total AFTER the newcomer's stake was added.
//!     RegisterResults memory results = _registerOperator({ ... });
//!
//!     for (uint256 i = 0; i < quorumNumbers.length; i++) {
//!         OperatorSetParam memory operatorSetParams = _quorumParams[...];
//!         if (results.numOperatorsPerQuorum[i] > operatorSetParams.maxOperatorCount) {
//!             // (2) the kick threshold is checked against the POST-registration total.
//!             _validateChurn({
//!                 quorumNumber:     uint8(quorumNumbers[i]),
//!                 totalQuorumStake: results.totalStakes[i],     // <-- double-counted base
//!                 newOperator:      operator,
//!                 newOperatorStake: results.operatorStakes[i],  // <-- also post-register
//!                 kickParams:       operatorKickParams[i],
//!                 setParams:        operatorSetParams
//!             });
//!             _kickOperator(operatorKickParams[i].operator, singleQuorumNumber);
//!         }
//!     }
//! }
//!
//! function _validateChurn(uint8 q, uint96 totalQuorumStake, address newOperator,
//!                         uint96 newOperatorStake, OperatorKickParam memory kickParams,
//!                         OperatorSetParam memory setParams) internal view {
//!     ...
//!     // the to-be-kicked operator's stake is read SEPARATELY ...
//!     uint96 operatorToKickStake = stakeRegistry.getCurrentStake(idToKick, q);
//!     // ... and compared against a fraction of the (double-counted) total.
//!     require(operatorToKickStake < _totalKickThreshold(totalQuorumStake, setParams),
//!             CannotKickOperatorAboveThreshold());
//! }
//! ```
//!
//! `totalQuorumStake` here includes the newcomer's just-added stake **and** the
//! to-be-kicked operator's stake (the latter is still registered at this point — it
//! is kicked only *after* `_validateChurn` returns). So `_totalKickThreshold` —
//! `totalQuorumStake * kickBIPsOfTotalStake / 10000` — is computed off an inflated
//! base, and the `operatorToKickStake < threshold` comparison reads the kicked
//! operator's stake against a total that already counts that same operator (and the
//! newcomer). The kick-eligibility test is therefore evaluated against a
//! double-counted denominator, weakening the "the kicked operator must be a small
//! enough fraction of the quorum" invariant.
//!
//! ## What the detector matches (all required)
//!
//!   * a **churn / replace entry** function — name contains `churn` or `replace` —
//!     with a body that mutates state;
//!   * a local **results variable** initialized from an internal **register-like**
//!     call (`_registerOperator` / `*register*`) — i.e. the newcomer self-registers
//!     and a *total* is returned into that variable;
//!   * a **later** (document-order) call to a **churn-validation** function
//!     (`_validateChurn` / `*validatechurn*` / `*churn*`) that passes, as one of its
//!     arguments, a value **rooted at that results variable** (`results.totalStakes`
//!     / `results.operatorStakes`) — the post-registration total feeding the kick
//!     threshold;
//!   * the validation callee (resolved by name) — or the entry itself — **separately
//!     reads the to-be-kicked operator's stake** (a `getCurrentStake`-style read) and
//!     **threshold-compares** it (a `*kickThreshold*` / `*kickBIPs*` proportion
//!     compare). This is the proof that a separately-read kicked-operator stake is
//!     measured against the double-counted base.
//!
//! ## Suppression (the EXEMPT correct shape)
//!
//!   * **Pre-registration snapshot.** If the value passed as the total/stake argument
//!     to the churn validation does *not* root-resolve to the post-registration
//!     results variable — e.g. the total was captured from a *separate*
//!     `getCurrentTotalStake(...)` read or a local snapshot taken *before* the
//!     `_registerOperator` call — then the threshold base is the pre-registration
//!     total and there is no double-count. The detector stays silent.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{Call, Expr, ExprKind, Function, Span, Stmt, StmtKind};

use super::prelude::*;

pub struct ChurnStaleStakeDoubleCountDetector;

impl Detector for ChurnStaleStakeDoubleCountDetector {
    fn id(&self) -> &'static str {
        "churn-stale-stake-double-count"
    }
    fn category(&self) -> Category {
        Category::ChurnStaleStakeDoubleCount
    }
    fn description(&self) -> &'static str {
        "Operator-churn/replace path validates the kick threshold against a quorum total measured AFTER \
         the newcomer self-registered (double-counting both the newcomer and the to-be-kicked operator) \
         rather than a pre-registration snapshot (EigenLayer middleware _registerOperatorWithChurn / \
         _validateChurn class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.functions() {
            if !f.has_body || !f.is_state_mutating() {
                continue;
            }
            // (1) Scope: a churn / replace entry function. This is the principled
            //     restriction that keeps the class to operator-replacement paths and
            //     off ordinary register/deposit code.
            if !is_churn_entry_name(&f.name) {
                continue;
            }

            // (2) The newcomer self-registers first: a local var initialized from an
            //     internal register-like call (`results = _registerOperator(...)`).
            let Some(reg) = register_result_var(f) else { continue };

            // (3) A LATER churn-validation call that bases its total/stake on that
            //     post-registration results var.
            let Some(val) = churn_validation_from_results(f, &reg) else { continue };

            // SUPPRESS: a churn validation whose total/stake arg is NOT the
            //           post-registration results var (a pre-registration snapshot)
            //           is handled inside `churn_validation_from_results` — it only
            //           returns a hit when the arg roots at `reg.var`.

            // (4) The validation callee (or the entry itself) separately reads the
            //     to-be-kicked operator's stake and threshold-compares it. This ties
            //     the double-counted base to a real kick-eligibility decision.
            if !double_count_compare_reachable(cx, f, &val.callee_name) {
                continue;
            }

            out.push(self.finding(cx, f, &reg, &val));
        }

        out
    }
}

impl ChurnStaleStakeDoubleCountDetector {
    fn finding(
        &self,
        cx: &AnalysisContext,
        f: &Function,
        reg: &RegResultVar,
        val: &ChurnValidationHit,
    ) -> Finding {
        let b = report!(self, Category::ChurnStaleStakeDoubleCount,
            title = "Churn kick-threshold validated against a post-registration (double-counted) quorum total",
            severity = Severity::Medium,
            confidence = 0.62,
            dimensions = [Dimension::Invariant],
            message = format!(
                "`{fname}` is an operator-churn/replace path that registers the incoming operator FIRST \
                 — `{var} = {reg_call}(...)` returns the quorum total AFTER the newcomer's stake is added \
                 — and then validates the kick/churn threshold against that post-registration total: it \
                 passes `{passed}` (rooted at `{var}`) into `{val_call}(...)`. At that point the quorum \
                 total counts BOTH the just-registered newcomer AND the operator about to be kicked (the \
                 kick happens only after the validation returns), so `{val_call}` reads the to-be-kicked \
                 operator's separately-fetched stake against a `kickBIPsOfTotalStake`/threshold fraction of \
                 a DOUBLE-COUNTED base. The kick-eligibility invariant (\"the operator being replaced is a \
                 small enough fraction of the quorum\") is therefore checked against an inflated \
                 denominator. This is the EigenLayer middleware `_registerOperatorWithChurn` / \
                 `_validateChurn` double-count class.",
                fname = f.name,
                var = reg.var,
                reg_call = reg.reg_call_name,
                passed = val.passed_display,
                val_call = val.callee_name,
            ),
            recommendation = format!(
                "Validate churn against a PRE-registration snapshot of the quorum total. Read the total \
                 (and, if needed, the incoming operator's prospective stake) BEFORE calling \
                 `{reg_call}`, and pass that snapshot into `{val_call}` — or subtract the newcomer's \
                 just-added stake from `{var}`'s total before deriving the kick threshold — so the \
                 `kickBIPsOfTotalStake` fraction is computed off the stake base that excludes the newcomer \
                 (and reflects the quorum as it was when the kick decision is made). Do not derive the kick \
                 threshold from a total captured after the newcomer has already self-registered.",
                reg_call = reg.reg_call_name,
                val_call = val.callee_name,
                var = reg.var,
            ),
        );
        finish_at(cx, b, f.id, val.span)
    }
}

// --------------------------------------------------------------------------- gates

/// A local variable initialized from an internal register-like call —
/// `RegisterResults memory results = _registerOperator(...)`. Captures the variable
/// name, the callee name, and the source position of the declaration (for the
/// pre-/post-registration ordering check).
struct RegResultVar {
    var: String,
    reg_call_name: String,
    decl_start: u32,
}

/// A churn-validation call that bases its total/stake argument on the
/// post-registration results variable.
struct ChurnValidationHit {
    /// Name of the validation callee (`_validateChurn`).
    callee_name: String,
    /// The argument expression text rooted at the results var (`results.totalStakes`).
    passed_display: String,
    /// Span of the validation call (where the finding is anchored).
    span: Span,
}

/// Is `name` a churn / replace entry — the operator-replacement surface? We match a
/// name containing `churn` (the EigenLayer `registerOperatorWithChurn` /
/// `_registerOperatorWithChurn` family) or `replace` (the generic replace-an-operator
/// spelling). Case-insensitive.
fn is_churn_entry_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("churn") || l.contains("replace")
}

/// Find the first local `VarDecl` whose initializer is an internal **register-like**
/// call. This is the newcomer self-registration whose return value carries the
/// post-registration total. Returns the variable name, the register callee name, and
/// the declaration's source start (for ordering).
fn register_result_var(f: &Function) -> Option<RegResultVar> {
    let mut hit: Option<RegResultVar> = None;
    for s in &f.body {
        visit_stmts(s, &mut |stmt| {
            if hit.is_some() {
                return;
            }
            let StmtKind::VarDecl { name: Some(var), init: Some(init), .. } = &stmt.kind else {
                return;
            };
            let ExprKind::Call(c) = &init.kind else { return };
            // Must be an internal call (not an external `x.register(...)`), resolving
            // to a register-like name. The real target registers via an internal
            // `_registerOperator`.
            let Some(callee) = resolved_call_name(c) else { return };
            if !is_register_call_name(&callee) {
                return;
            }
            hit = Some(RegResultVar {
                var: var.clone(),
                reg_call_name: callee,
                decl_start: stmt.span.start,
            });
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Find a churn-validation call, occurring **after** the register declaration, that
/// passes (as one of its arguments) a value rooted at the post-registration results
/// variable. This is the post-registration total feeding the kick threshold.
///
/// The pre-registration-snapshot suppression is *implicit*: we only return a hit when
/// an argument root-resolves to `reg.var`. A validation fed a separate
/// `getCurrentTotalStake(...)` read or a local captured before registration roots at
/// something else, so no hit is produced.
fn churn_validation_from_results(f: &Function, reg: &RegResultVar) -> Option<ChurnValidationHit> {
    let mut hit: Option<ChurnValidationHit> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            // Document order: the validation must come *after* the register decl.
            if e.span.start <= reg.decl_start {
                return;
            }
            let Some(callee) = resolved_call_name(c) else { return };
            if !is_churn_validation_name(&callee) {
                return;
            }
            // One of the arguments must be the post-registration **total** — rooted at
            // the results var AND accessing a total-like member (`results.totalStakes`).
            // This is the double-counted base. Matching specifically on the *total*
            // argument is what distinguishes the bug from the EXEMPT pre-registration
            // snapshot: in the safe shape the total comes from a separate pre-register
            // read while only the newcomer's OWN stake (`results.operatorStakes`, not a
            // total) is taken from the results var — so no total-rooted arg exists.
            for a in &c.args {
                if arg_is_results_total(a, &reg.var) {
                    hit = Some(ChurnValidationHit {
                        callee_name: callee.clone(),
                        passed_display: render_access(a).unwrap_or_else(|| reg.var.clone()),
                        span: e.span,
                    });
                    return;
                }
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Does the churn-validation callee `callee_name` — or, if it cannot be resolved, the
/// entry function `f` itself (inlined variant) — exhibit the double-count compare: a
/// **separately-read** to-be-kicked operator stake (a `getCurrentStake`-style read)
/// AND a **threshold proportion compare** (against a `*kickThreshold*` / `*kickBIPs*`
/// derived bound)? Resolving the callee body ties the post-registration total to the
/// actual kick-eligibility decision.
fn double_count_compare_reachable(cx: &AnalysisContext, f: &Function, callee_name: &str) -> bool {
    // Prefer the resolved validation callee(s) by name.
    let mut matched_callee = false;
    for g in cx.functions() {
        if g.name != callee_name || !g.has_body {
            continue;
        }
        matched_callee = true;
        if function_has_double_count_compare(g) {
            return true;
        }
    }
    // Inlined variant: the compare lives directly in the entry function.
    if !matched_callee {
        return function_has_double_count_compare(f);
    }
    false
}

/// The double-count compare anchor: a function that (a) **separately reads** the
/// to-be-kicked operator's current stake — a call whose name reads as a
/// `getCurrentStake`-style per-operator stake fetch — and (b) **threshold-compares** a
/// value, where the comparison or its operands are derived from a kick-threshold /
/// kick-BIPs proportion (`_totalKickThreshold` / `kickBIPsOfTotalStake`). Both must be
/// present so an unrelated stake getter or an unrelated compare does not trip it.
fn function_has_double_count_compare(g: &Function) -> bool {
    reads_kicked_operator_stake(g) && has_kick_threshold_compare(g)
}

/// Does `g` separately fetch a per-operator current stake — a `getCurrentStake` /
/// `*currentstake*` / `stakeof`-style read? This is the "separately-read kicked
/// operator stake" half.
fn reads_kicked_operator_stake(g: &Function) -> bool {
    // Internal-call names + resolved external call-site names.
    g.effects.internal_calls.iter().any(|n| is_current_stake_getter(n))
        || g.effects
            .call_sites
            .iter()
            .any(|cs| cs.func_name.as_deref().map(is_current_stake_getter).unwrap_or(false))
        || any_call_where(g, |c| {
            resolved_call_name(c).as_deref().map(is_current_stake_getter).unwrap_or(false)
        })
}

/// Does `g` contain a kick-threshold proportion comparison — either a direct ordering
/// compare against a `*kickThreshold*` / `*kickBIPs*`-derived operand, or a call to a
/// `*kickThreshold*` helper used inside a comparison? We accept (a) any call whose name
/// reads as a kick-threshold helper, OR (b) an ordering comparison one of whose
/// operands mentions a `kick`-threshold / `kickBIPs` identifier or member.
fn has_kick_threshold_compare(g: &Function) -> bool {
    // (a) a kick-threshold helper call anywhere (the real `_totalKickThreshold` /
    // `_individualKickThreshold`).
    let calls_kick_threshold = g.effects.internal_calls.iter().any(|n| is_kick_threshold_name(n))
        || any_call_where(g, |c| {
            resolved_call_name(c).as_deref().map(is_kick_threshold_name).unwrap_or(false)
        });
    if calls_kick_threshold {
        // Require that the function ALSO contains a comparison (the require/if that
        // gates on the threshold), so a function that merely *defines* a threshold
        // helper is not itself matched.
        if has_any_ordering_comparison(g) {
            return true;
        }
    }
    // (b) an ordering comparison whose operands reference a kick-threshold/BIPs ident.
    let mut found = false;
    for s in &g.body {
        s.visit_exprs(&mut |e: &Expr| {
            if found {
                return;
            }
            if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
                if op.is_ordering()
                    && (expr_mentions_kick_threshold(lhs) || expr_mentions_kick_threshold(rhs))
                {
                    found = true;
                }
            }
        });
        if found {
            break;
        }
    }
    found
}

/// Any ordering comparison (`<`/`>`/`<=`/`>=`) present in the body.
fn has_any_ordering_comparison(g: &Function) -> bool {
    let mut found = false;
    for s in &g.body {
        s.visit_exprs(&mut |e: &Expr| {
            if found {
                return;
            }
            if let ExprKind::Binary { op, .. } = &e.kind {
                if op.is_ordering() {
                    found = true;
                }
            }
        });
        if found {
            break;
        }
    }
    found
}

// --------------------------------------------------------------------------- name tests

/// A register-like call name — the newcomer-self-registration internal call whose
/// return carries the post-registration total. Matches `register` substring (covers
/// `_registerOperator`, `registerOperator`), but excludes the validation/threshold
/// names so we never treat the churn validator itself as the register call.
fn is_register_call_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    if is_churn_validation_name(name) || is_kick_threshold_name(name) {
        return false;
    }
    l.contains("register")
}

/// A churn-validation call name — `_validateChurn` / `*validatechurn*`, or a
/// `*churn*`-named validator. Tight enough that it never matches the register call.
fn is_churn_validation_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("validatechurn") || (l.contains("churn") && l.contains("validate"))
}

/// A per-operator current-stake getter — `getCurrentStake` / `*currentstake*` /
/// `stakeof`. The "separately-read kicked operator stake".
fn is_current_stake_getter(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("currentstake") || l == "stakeof" || l.ends_with("currentstake")
        || (l.contains("getstake") && !l.contains("total"))
}

/// A kick-threshold helper / proportion name — `_totalKickThreshold` /
/// `_individualKickThreshold` / `kickBIPsOfTotalStake` / `kickBIPsOfOperatorStake`.
fn is_kick_threshold_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("kickthreshold") || l.contains("kickbips")
}

/// Does `e` mention a kick-threshold / kick-BIPs identifier or member anywhere?
fn expr_mentions_kick_threshold(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        match &sub.kind {
            ExprKind::Ident(n) | ExprKind::Member { member: n, .. } if is_kick_threshold_name(n) => {
                found = true;
            }
            _ => {}
        }
    });
    found
}

// --------------------------------------------------------------------------- expr utils

/// Resolved callee name of a call (`func_name`, falling back to the callee's simple
/// name `a.b -> "b"`).
fn resolved_call_name(c: &Call) -> Option<String> {
    c.func_name.clone().or_else(|| c.callee.simple_name().map(|s| s.to_string()))
}

/// Does `e` represent the post-registration **total** taken from the results var —
/// i.e. it root-resolves (through member / index / cast chains) to `var` AND its
/// access path includes a *total*-like member (`results.totalStakes[i]`)? Requiring
/// the total-like member is the precision anchor that fires on the double-counted
/// `totalQuorumStake` argument while ignoring the benign `results.operatorStakes`
/// (the newcomer's own stake), and is exactly what lets the pre-registration-snapshot
/// shape suppress.
fn arg_is_results_total(e: &Expr, var: &str) -> bool {
    if root_ident_peeled(e).as_deref() != Some(var) {
        return false;
    }
    expr_has_total_member(e)
}

/// Does `e` access a member whose name reads as a quorum **total** stake
/// (`totalStakes` / `totalStake` / `*total*`)? Used to single out the total argument.
fn expr_has_total_member(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Member { member, .. } = &sub.kind {
            if is_total_name(member) {
                found = true;
            }
        }
    });
    found
}

/// A name denoting a quorum total stake.
fn is_total_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("total")
}

/// Render a member/index access to a compact textual form for the message
/// (`results.totalStakes`). Returns `None` for shapes we don't render.
fn render_access(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { base, member } => Some(format!("{}.{}", render_access(base)?, member)),
        ExprKind::Index { base, .. } => Some(render_access(base)?),
        _ => None,
    }
}

/// Visit a statement and all nested statements (pre-order). A thin wrapper over
/// `Stmt::visit` for readability at the call site.
fn visit_stmts<'a>(s: &'a Stmt, f: &mut impl FnMut(&'a Stmt)) {
    s.visit(f);
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "churn-stale-stake-double-count")
    }

    // VULN — the EigenLayer middleware `_registerOperatorWithChurn` / `_validateChurn`
    // shape, reduced. The newcomer self-registers first (`results = _registerOperator`),
    // the post-registration `results.totalStakes[i]` is passed as `totalQuorumStake`
    // into `_validateChurn`, which separately reads the kicked operator's stake
    // (`stakeRegistry.getCurrentStake`) and compares it against `_totalKickThreshold`.
    const VULN: &str = r#"
        pragma solidity ^0.8.27;
        contract SlashingRegistryCoordinator {
            struct RegisterResults { uint96[] operatorStakes; uint96[] totalStakes; uint32[] numOperatorsPerQuorum; }
            struct OperatorKickParam { uint8 quorumNumber; address operator; }
            struct OperatorSetParam { uint16 maxOperatorCount; uint16 kickBIPsOfOperatorStake; uint16 kickBIPsOfTotalStake; }
            mapping(uint8 => OperatorSetParam) internal _quorumParams;
            uint16 internal constant BIPS_DENOMINATOR = 10000;

            function _registerOperatorWithChurn(
                address operator,
                bytes memory quorumNumbers,
                OperatorKickParam[] memory operatorKickParams
            ) internal {
                RegisterResults memory results = _registerOperator(operator, quorumNumbers);
                for (uint256 i = 0; i < quorumNumbers.length; i++) {
                    OperatorSetParam memory operatorSetParams = _quorumParams[uint8(quorumNumbers[i])];
                    if (results.numOperatorsPerQuorum[i] > operatorSetParams.maxOperatorCount) {
                        _validateChurn({
                            quorumNumber: uint8(quorumNumbers[i]),
                            totalQuorumStake: results.totalStakes[i],
                            newOperator: operator,
                            newOperatorStake: results.operatorStakes[i],
                            kickParams: operatorKickParams[i],
                            setParams: operatorSetParams
                        });
                        _kickOperator(operatorKickParams[i].operator, quorumNumbers);
                    }
                }
            }

            function _registerOperator(address operator, bytes memory quorumNumbers)
                internal returns (RegisterResults memory results) {}

            function _validateChurn(
                uint8 quorumNumber,
                uint96 totalQuorumStake,
                address newOperator,
                uint96 newOperatorStake,
                OperatorKickParam memory kickParams,
                OperatorSetParam memory setParams
            ) internal view {
                address operatorToKick = kickParams.operator;
                uint96 operatorToKickStake = stakeRegistry.getCurrentStake(operatorToKick, quorumNumber);
                require(newOperatorStake > _individualKickThreshold(operatorToKickStake, setParams), "ind");
                require(operatorToKickStake < _totalKickThreshold(totalQuorumStake, setParams), "tot");
            }

            function _individualKickThreshold(uint96 s, OperatorSetParam memory p) internal pure returns (uint96) {
                return s * p.kickBIPsOfOperatorStake / BIPS_DENOMINATOR;
            }
            function _totalKickThreshold(uint96 t, OperatorSetParam memory p) internal pure returns (uint96) {
                return t * p.kickBIPsOfTotalStake / BIPS_DENOMINATOR;
            }
            function _kickOperator(address operator, bytes memory quorumNumbers) internal {}
        }
    "#;

    // VULN (public `registerOperatorWithChurn` entry calling the internal one is NOT
    // required) — variant where the validator is INLINED into the churn entry: the
    // post-registration total is compared directly in the loop. Must still fire.
    const VULN_INLINED: &str = r#"
        pragma solidity ^0.8.27;
        contract RegistryCoordinator {
            struct RegisterResults { uint96[] operatorStakes; uint96[] totalStakes; uint32[] numOperatorsPerQuorum; }
            struct OperatorSetParam { uint16 maxOperatorCount; uint16 kickBIPsOfTotalStake; }
            mapping(uint8 => OperatorSetParam) internal _quorumParams;
            uint16 constant BIPS = 10000;

            function replaceOperatorWithChurn(
                address operator,
                bytes memory quorumNumbers,
                address operatorToKick
            ) internal {
                RegisterResults memory results = _registerOperator(operator, quorumNumbers);
                for (uint256 i = 0; i < quorumNumbers.length; i++) {
                    OperatorSetParam memory p = _quorumParams[uint8(quorumNumbers[i])];
                    if (results.numOperatorsPerQuorum[i] > p.maxOperatorCount) {
                        _validateChurnInline(results.totalStakes[i], operatorToKick, uint8(quorumNumbers[i]), p);
                    }
                }
            }
            function _validateChurnInline(uint96 totalQuorumStake, address operatorToKick, uint8 q, OperatorSetParam memory p) internal view {
                uint96 operatorToKickStake = stakeRegistry.getCurrentStake(operatorToKick, q);
                require(operatorToKickStake < totalQuorumStake * p.kickBIPsOfTotalStake / BIPS, "tot");
            }
            function _registerOperator(address o, bytes memory q) internal returns (RegisterResults memory r) {}
        }
    "#;

    // SAFE (pre-registration snapshot): the quorum total is read from a SEPARATE
    // `getCurrentTotalStake(...)` snapshot taken BEFORE the newcomer registers, and
    // THAT snapshot (not the post-register results var) is passed to `_validateChurn`.
    // No double-count -> must stay silent.
    const SAFE_PRE_SNAPSHOT: &str = r#"
        pragma solidity ^0.8.27;
        contract SlashingRegistryCoordinator {
            struct RegisterResults { uint96[] operatorStakes; uint96[] totalStakes; uint32[] numOperatorsPerQuorum; }
            struct OperatorKickParam { uint8 quorumNumber; address operator; }
            struct OperatorSetParam { uint16 maxOperatorCount; uint16 kickBIPsOfTotalStake; }
            mapping(uint8 => OperatorSetParam) internal _quorumParams;
            uint16 constant BIPS = 10000;

            function _registerOperatorWithChurn(
                address operator,
                bytes memory quorumNumbers,
                OperatorKickParam[] memory operatorKickParams
            ) internal {
                // pre-registration snapshot of the total, BEFORE the newcomer registers
                uint96 preTotal = stakeRegistry.getCurrentTotalStake(uint8(quorumNumbers[0]));
                RegisterResults memory results = _registerOperator(operator, quorumNumbers);
                for (uint256 i = 0; i < quorumNumbers.length; i++) {
                    OperatorSetParam memory operatorSetParams = _quorumParams[uint8(quorumNumbers[i])];
                    if (results.numOperatorsPerQuorum[i] > operatorSetParams.maxOperatorCount) {
                        _validateChurn({
                            quorumNumber: uint8(quorumNumbers[i]),
                            totalQuorumStake: preTotal,
                            newOperator: operator,
                            newOperatorStake: results.operatorStakes[i],
                            kickParams: operatorKickParams[i],
                            setParams: operatorSetParams
                        });
                    }
                }
            }
            function _registerOperator(address o, bytes memory q) internal returns (RegisterResults memory r) {}
            function _validateChurn(uint8 q, uint96 totalQuorumStake, address newOperator, uint96 newOperatorStake, OperatorKickParam memory kickParams, OperatorSetParam memory setParams) internal view {
                uint96 operatorToKickStake = stakeRegistry.getCurrentStake(kickParams.operator, q);
                require(operatorToKickStake < totalQuorumStake * setParams.kickBIPsOfTotalStake / BIPS, "tot");
            }
        }
    "#;

    // SAFE (ordinary register, no churn): a plain register path that registers an
    // operator and stores results, but is NOT a churn/replace path and has no
    // kick-threshold validation. Out of scope by the churn/replace name anchor.
    const SAFE_PLAIN_REGISTER: &str = r#"
        pragma solidity ^0.8.27;
        contract RegistryCoordinator {
            struct RegisterResults { uint96[] operatorStakes; uint96[] totalStakes; uint32[] numOperatorsPerQuorum; }
            mapping(uint8 => uint16) internal _maxOps;
            function registerOperator(address operator, bytes memory quorumNumbers) external {
                RegisterResults memory results = _registerOperator(operator, quorumNumbers);
                for (uint256 i = 0; i < quorumNumbers.length; i++) {
                    require(results.numOperatorsPerQuorum[i] <= _maxOps[uint8(quorumNumbers[i])], "max");
                }
            }
            function _registerOperator(address o, bytes memory q) internal returns (RegisterResults memory r) {}
        }
    "#;

    // SAFE (churn path but no kicked-operator-stake / threshold compare): a churn
    // entry that registers + uses the results total, but the validator does NOT read a
    // separate kicked-operator stake against a kick threshold — it just checks the
    // count. The double-count compare anchor is absent -> silent.
    const SAFE_NO_KICK_COMPARE: &str = r#"
        pragma solidity ^0.8.27;
        contract SlashingRegistryCoordinator {
            struct RegisterResults { uint96[] operatorStakes; uint96[] totalStakes; uint32[] numOperatorsPerQuorum; }
            struct OperatorKickParam { uint8 quorumNumber; address operator; }
            struct OperatorSetParam { uint16 maxOperatorCount; }
            mapping(uint8 => OperatorSetParam) internal _quorumParams;
            function _registerOperatorWithChurn(
                address operator,
                bytes memory quorumNumbers,
                OperatorKickParam[] memory operatorKickParams
            ) internal {
                RegisterResults memory results = _registerOperator(operator, quorumNumbers);
                for (uint256 i = 0; i < quorumNumbers.length; i++) {
                    OperatorSetParam memory operatorSetParams = _quorumParams[uint8(quorumNumbers[i])];
                    if (results.numOperatorsPerQuorum[i] > operatorSetParams.maxOperatorCount) {
                        _validateChurn(uint8(quorumNumbers[i]), results.totalStakes[i], operatorSetParams);
                    }
                }
            }
            function _registerOperator(address o, bytes memory q) internal returns (RegisterResults memory r) {}
            function _validateChurn(uint8 q, uint96 totalQuorumStake, OperatorSetParam memory p) internal view {
                // only validates the count, never reads a kicked-operator stake vs a kick threshold
                require(totalQuorumStake > 0, "empty");
            }
        }
    "#;

    #[test]
    fn fires_on_registeroperatorwithchurn_shape() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_inlined_replace_churn() {
        assert!(fires(VULN_INLINED), "{:#?}", run(VULN_INLINED));
    }

    #[test]
    fn silent_on_pre_registration_snapshot() {
        assert!(!fires(SAFE_PRE_SNAPSHOT), "{:#?}", run(SAFE_PRE_SNAPSHOT));
    }

    #[test]
    fn silent_on_plain_register() {
        assert!(!fires(SAFE_PLAIN_REGISTER), "{:#?}", run(SAFE_PLAIN_REGISTER));
    }

    #[test]
    fn silent_on_churn_without_kick_threshold_compare() {
        assert!(!fires(SAFE_NO_KICK_COMPARE), "{:#?}", run(SAFE_NO_KICK_COMPARE));
    }
}
