//! Snapshot/redeem directional asymmetry — a two-step withdraw whose stored
//! redeem amount is re-derived from a *live* price at claim and clamped in **one
//! direction only**, while a reserve/accounting variable is decremented by the
//! **pre-clamp** stored value. The decrement and the payout disagree by
//! construction whenever the clamp fires — a directional value/accounting leak.
//!
//! Two-step (request → claim) withdrawal queues store, at *request* time, the
//! amount of the redeem asset the user is owed (`amountToRedeem`), and pre-fund a
//! per-asset reserve (`claimReserve[token] += amountToRedeem`). At *claim* time a
//! careful protocol re-derives the redeem amount from the **current** price/TVL
//! (the asset may have lost value since the request) and pays the *lesser* of the
//! two, so a user can never claim more than the live value of their position. The
//! bug is in **how the reserve is unwound** versus **how the stored amount is
//! clamped**:
//!
//!   1. the stored amount `S` (a struct field / local the function will pay out)
//!      is clamped **down-only** against a freshly re-derived live value `L`:
//!      `if (L < S) { S = L; }` — there is a branch that *lowers* `S` toward `L`
//!      but **no opposite branch** that ever *raises* `S` to `L`; and
//!   2. a reserve/accounting variable is decremented by the **pre-clamp** `S`:
//!      `reserve -= S;` placed **before** the clamp (so it subtracts the original,
//!      larger amount), while the user is later paid the **post-clamp** (smaller)
//!      `S`.
//!
//! When the live price has dropped (`L < S`), the reserve is debited by the old
//! `S` but only `L` leaves the contract — the reserve over-decrements relative to
//! the value actually paid. Because the clamp is one-directional, the asymmetry
//! only ever leaks in that single direction; it is never compensated by an
//! up-clamp on a price rise. This is exactly the shape of Renzo
//! `WithdrawQueue.claimETH` / `claimERC20`:
//!
//! ```solidity
//! (, uint256 claimAmountToRedeem) = calculateAmountToRedeem(ezETHLocked, asset);
//! claimReserve[asset] -= _withdrawRequest.amountToRedeem;          // pre-clamp debit
//! if (claimAmountToRedeem < _withdrawRequest.amountToRedeem) {     // DOWN-ONLY clamp
//!     _withdrawRequest.amountToRedeem = claimAmountToRedeem;       // S can only fall
//! }
//! ...
//! IERC20(asset).transfer(user, _withdrawRequest.amountToRedeem);   // pays post-clamp
//! ```
//!
//! Precision anchors (all required) so this stays quiet on symmetric / correct
//! unwinds:
//!   * a **down-only clamp**: an `if (L < S) { S = L; }` / `if (L <= S) …` (or the
//!     `S = L < S ? L : S` ternary) where the assignment target `S` is *also* the
//!     larger operand of the comparison — `S` is monotonically lowered toward `L`;
//!   * **no opposite-direction adjust**: the function must NOT also contain a
//!     raising branch for the same `S` (`if (L > S) S = L;` / `S = L > S ? L : S`),
//!     i.e. it is not a symmetric two-sided reconciliation;
//!   * a **reserve decrement by the pre-clamp `S`**: a state-var compound subtract
//!     (`reserve -= …`) whose subtracted amount references the *same* stored path
//!     `S`, occurring **lexically before** the clamp (so it uses the un-clamped
//!     value). If the decrement is placed *after* the clamp (post-clamp value) or
//!     subtracts the live `L` instead, there is no asymmetry and nothing fires.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{AssignOp, BinOp, Expr, ExprKind, Function, Span, Stmt, StmtKind};

pub struct SnapshotRedeemAsymmetryDetector;

impl Detector for SnapshotRedeemAsymmetryDetector {
    fn id(&self) -> &'static str {
        "snapshot-redeem-asymmetry"
    }
    fn category(&self) -> Category {
        Category::SnapshotRedeemAsymmetry
    }
    fn description(&self) -> &'static str {
        "Two-step withdraw clamps the stored redeem amount in one direction only while decrementing a reserve by the pre-clamp value (Renzo WithdrawQueue claim asymmetry)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // Only concrete, state-mutating bodies can both clamp a stored amount
            // and debit a reserve. View/pure helpers and bare declarations cannot.
            if !f.has_body || f.is_view_or_pure() {
                continue;
            }
            // Interfaces / libraries declare no claim logic.
            let Some(contract) = cx.contract_of(f.id) else { continue };
            if contract.is_interface() {
                continue;
            }

            let Some(hit) = analyze_function(cx, f) else { continue };
            out.push(self.finding(cx, f, &hit));
        }
        out
    }
}

impl SnapshotRedeemAsymmetryDetector {
    fn finding(&self, cx: &AnalysisContext, f: &Function, hit: &AsymHit) -> Finding {
        let b = FindingBuilder::new(self.id(), Category::SnapshotRedeemAsymmetry)
            .title("Reserve decremented by pre-clamp redeem amount, then the amount is clamped down-only")
            .severity(Severity::Medium)
            .confidence(0.62)
            .dimension(Dimension::Invariant)
            .message(format!(
                "`{fname}` debits the reserve `{reserve}` by the stored redeem amount `{stored}` and \
                 *then* clamps that same amount **downward only** against a freshly re-derived live \
                 value `{live}` (`if ({live} < {stored}) {{ {stored} = {live}; }}`, with no opposite \
                 branch that ever raises `{stored}`). The decrement therefore subtracts the *pre-clamp* \
                 (larger) amount, while the user is paid the *post-clamp* (smaller) amount — so whenever \
                 the live price has fallen the reserve over-decrements relative to the value that \
                 actually leaves the contract. Because the clamp is one-directional, the discrepancy \
                 only ever leaks in this single direction and is never offset by an up-adjust on a \
                 price rise. This is the Renzo `WithdrawQueue.claimETH` / `claimERC20` redeem-asymmetry \
                 shape (`claimReserve[token] -= _withdrawRequest.amountToRedeem` taken *before* the \
                 down-only clamp).",
                fname = f.name,
                reserve = hit.reserve_var,
                stored = hit.stored_path,
                live = hit.live_name,
            ))
            .recommendation(
                "Make the reserve unwind agree with the payout: decrement the reserve by the *post-clamp* \
                 amount (move the `reserve -= amount` below the clamp, or subtract the clamped/min value), \
                 or clamp symmetrically in both directions. Equivalently, compute the final redeem amount \
                 first, then debit the reserve and transfer using that single value so the accounting and \
                 the disbursement can never diverge.",
            );
        cx.finish(b, f.id, hit.span)
    }
}

// --------------------------------------------------------------------- analysis

/// A matched asymmetry in one function.
struct AsymHit {
    /// Reserve/accounting state var that is decremented (`claimReserve`).
    reserve_var: String,
    /// Normalized text of the stored redeem lvalue clamped down (`_withdrawrequest.amounttoredeem`).
    stored_path: String,
    /// Textual name of the live re-derived value the clamp compares against.
    live_name: String,
    /// Span of the down-only clamp `if`.
    span: Span,
}

/// A discovered down-only clamp of a stored amount toward a live value.
struct DownClamp {
    /// Normalized text of the clamped lvalue `S`.
    stored_path: String,
    /// Textual name of the live value `L` (best-effort identifier/member).
    live_name: String,
    /// Span of the clamp construct (the `if` or the ternary's statement).
    span: Span,
}

fn analyze_function(cx: &AnalysisContext, f: &Function) -> Option<AsymHit> {
    // Flatten the body into top-level-ordered statements so we can reason about
    // "the decrement comes before the clamp" by source position. (The clamp and
    // the `reserve -= S` both live at the function's top level in the target.)
    let clamps = collect_down_clamps(cx, f);
    if clamps.is_empty() {
        return None;
    }

    for clamp in &clamps {
        // SUPPRESS: a both-direction reconciliation — an opposite branch that
        // *raises* the same stored path toward a live value — is symmetric and
        // intended, never a directional leak.
        if has_opposite_raise(cx, f, &clamp.stored_path) {
            continue;
        }

        // Find a reserve decrement (`reserve -= …`) whose subtracted amount
        // references the SAME stored path and that occurs BEFORE the clamp (so it
        // uses the pre-clamp value). The pre-clamp ordering is the whole bug: a
        // decrement placed after the clamp would use the already-lowered amount
        // and there would be no asymmetry.
        let Some(reserve_var) = pre_clamp_reserve_decrement(cx, f, clamp) else {
            continue;
        };

        return Some(AsymHit {
            reserve_var,
            stored_path: clamp.stored_path.clone(),
            live_name: clamp.live_name.clone(),
            span: clamp.span,
        });
    }
    None
}

/// Collect every **down-only** clamp in `f`: an `if (L < S) { S = L; }` /
/// `if (L <= S) …` (or the equivalent `S = L < S ? L : S` ternary statement),
/// where the assignment target `S` is also the larger operand of the comparison.
fn collect_down_clamps(cx: &AnalysisContext, f: &Function) -> Vec<DownClamp> {
    let mut out = Vec::new();
    for top in &f.body {
        top.visit(&mut |st| match &st.kind {
            // `if (L < S) { S = L; }` — the canonical Renzo form.
            StmtKind::If { cond, then_branch, .. } => {
                if let Some((live, stored_cmp)) = lower_comparison_operands(cond) {
                    // The then-branch must assign `S = L` where the target equals
                    // the comparison's larger operand `S` and the value equals the
                    // smaller operand `L`.
                    if let Some(clamp) = then_branch_lowers(cx, then_branch, &live, &stored_cmp) {
                        out.push(DownClamp { span: st.span, ..clamp });
                    }
                }
            }
            // `S = (L < S) ? L : S;` ternary written as an assignment statement.
            StmtKind::Expr(e) => {
                if let Some(clamp) = ternary_down_clamp(cx, e) {
                    out.push(DownClamp { span: st.span, ..clamp });
                }
            }
            // `uint256 x = (L < S) ? L : S;` — a min into a local, then later used.
            // Not the Renzo storage-field shape; we only match assignment-to-`S`
            // forms above, so nothing to do here.
            _ => {}
        });
    }
    out
}

/// If `cond` is an ordering comparison `L < S` or `L <= S`, return `(L_text,
/// S_text)` as normalized source text of the *smaller* (`L`) and *larger* (`S`)
/// operands. Also accepts the mirrored `S > L` / `S >= L`, normalizing so the
/// first element is always the would-be-min operand. Returns `None` for `==`,
/// `!=`, or non-comparisons.
fn lower_comparison_operands(cond: &Expr) -> Option<(String, String)> {
    let ExprKind::Binary { op, lhs, rhs } = &cond.kind else { return None };
    match op {
        // `lhs < rhs` / `lhs <= rhs`: lhs is the min candidate (`L`), rhs is `S`.
        BinOp::Lt | BinOp::Le => Some((node_text(lhs), node_text(rhs))),
        // `lhs > rhs` / `lhs >= rhs`: rhs is the min candidate (`L`), lhs is `S`.
        BinOp::Gt | BinOp::Ge => Some((node_text(rhs), node_text(lhs))),
        _ => None,
    }
}

/// If the (single dominant) statement in `then_branch` is `S = L` where `S`
/// matches `stored_cmp` and `L` matches `live_cmp` (both by normalized text),
/// return the clamp. The assignment must be a plain `=` (not `+=` etc.) of the
/// live value into the stored lvalue — that is what "lower `S` to `L`" means.
fn then_branch_lowers(
    cx: &AnalysisContext,
    then_branch: &[Stmt],
    live_cmp: &str,
    stored_cmp: &str,
) -> Option<DownClamp> {
    let mut found: Option<DownClamp> = None;
    for s in then_branch {
        s.visit(&mut |st| {
            if found.is_some() {
                return;
            }
            let StmtKind::Expr(e) = &st.kind else { return };
            let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind else { return };
            let tgt = expr_path_text(cx, target);
            let val = expr_path_text(cx, value);
            // `S = L`: target is the larger comparison operand, value is the smaller.
            if paths_match(&tgt, stored_cmp) && paths_match(&val, live_cmp) {
                found = Some(DownClamp {
                    stored_path: tgt,
                    live_name: val,
                    span: e.span,
                });
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// Recognize `S = (L < S) ? L : S` (or the `>`-mirror) as a down-only clamp.
/// The assignment target `S` must equal both the larger comparison operand and
/// the ternary's *else* branch, and the *then* branch must be the smaller
/// operand `L` — i.e. "set `S` to `L` only when `L < S`, else keep `S`".
fn ternary_down_clamp(cx: &AnalysisContext, e: &Expr) -> Option<DownClamp> {
    let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind else { return None };
    let ExprKind::Ternary { cond, then_e, else_e } = &value.kind else { return None };
    let (live_cmp, stored_cmp) = lower_comparison_operands(cond)?;
    let tgt = expr_path_text(cx, target);
    let then_t = expr_path_text(cx, then_e);
    let else_t = expr_path_text(cx, else_e);
    // target == S (larger operand) == else branch (keep), then branch == L (min).
    if paths_match(&tgt, &stored_cmp) && paths_match(&else_t, &stored_cmp) && paths_match(&then_t, &live_cmp)
    {
        return Some(DownClamp { stored_path: tgt, live_name: live_cmp, span: e.span });
    }
    None
}

/// SUPPRESS gate: does `f` contain an **opposite-direction** adjust for the same
/// stored path — a branch/ternary that *raises* `stored_path` toward a live
/// value (`if (L > S) S = L;` setting `S` to a value that the guard says is the
/// *larger*)? Such a contract clamps symmetrically and is not a directional leak.
fn has_opposite_raise(cx: &AnalysisContext, f: &Function, stored_path: &str) -> bool {
    let mut raises = false;
    for top in &f.body {
        top.visit(&mut |st| {
            if raises {
                return;
            }
            match &st.kind {
                // `if (L > S) { S = L; }` — `S` set to the guard's *larger* operand.
                StmtKind::If { cond, then_branch, .. } => {
                    // Reuse lower_comparison_operands but interpret the OTHER way:
                    // we want a guard where the assigned target is the *smaller*
                    // operand (so the assignment raises it). lower_comparison_operands
                    // returns (min, max); a raise sets target == min to value == max.
                    if let Some((min_op, max_op)) = lower_comparison_operands(cond) {
                        for s in then_branch {
                            s.visit(&mut |inner| {
                                if raises {
                                    return;
                                }
                                if let StmtKind::Expr(e) = &inner.kind {
                                    if let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind
                                    {
                                        let tgt = expr_path_text(cx, target);
                                        let val = expr_path_text(cx, value);
                                        // target is the stored path AND it is the
                                        // smaller operand being set to the larger:
                                        // an up-clamp of `stored_path`.
                                        if paths_match(&tgt, stored_path)
                                            && paths_match(&tgt, &min_op)
                                            && paths_match(&val, &max_op)
                                        {
                                            raises = true;
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
                // `S = (L > S) ? L : S` raising ternary.
                StmtKind::Expr(e) => {
                    if let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind {
                        if let ExprKind::Ternary { cond, then_e, else_e } = &value.kind {
                            if let Some((min_op, max_op)) = lower_comparison_operands(cond) {
                                let tgt = expr_path_text(cx, target);
                                let then_t = expr_path_text(cx, then_e);
                                let else_t = expr_path_text(cx, else_e);
                                // target == S == else (keep), then == max → raise.
                                if paths_match(&tgt, stored_path)
                                    && paths_match(&tgt, &min_op)
                                    && paths_match(&else_t, &min_op)
                                    && paths_match(&then_t, &max_op)
                                {
                                    raises = true;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        });
        if raises {
            break;
        }
    }
    raises
}

/// Find a reserve/accounting decrement `reserve -= <expr-mentioning-S>` that
/// occurs **lexically before** `clamp` and whose `reserve` base is a state var of
/// the contract. Returns the reserve variable name. The "before the clamp" /
/// "mentions the stored path" pair is what proves the decrement uses the
/// *pre-clamp* value `S`.
fn pre_clamp_reserve_decrement(cx: &AnalysisContext, f: &Function, clamp: &DownClamp) -> Option<String> {
    let mut found: Option<String> = None;
    for top in &f.body {
        top.visit(&mut |st| {
            if found.is_some() {
                return;
            }
            let StmtKind::Expr(e) = &st.kind else { return };
            let ExprKind::Assign { op: AssignOp::Sub, target, value } = &e.kind else { return };
            // The decrement must be lexically before the clamp (same file).
            if !(st.span.file == clamp.span.file && st.span.start < clamp.span.start) {
                return;
            }
            // The subtracted amount must reference the SAME stored path `S` that
            // the clamp lowers (`claimReserve[...] -= _withdrawRequest.amountToRedeem`).
            let val_text = node_text(value);
            if !mentions_path(&val_text, &clamp.stored_path) {
                return;
            }
            // The decrement target's root must be a state variable (a reserve /
            // accounting store), not a plain local — that is what gives the leak
            // protocol-wide accounting impact.
            let root = root_ident(target);
            if let Some(r) = root {
                if is_contract_state_var(cx, f, &r) {
                    found = Some(r);
                }
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

// --------------------------------------------------------------------- helpers

/// Normalized (comment-stripped, lowercased) source text of an expression node —
/// used to compare lvalue paths (`_withdrawrequest.amounttoredeem`) and to scan
/// the subtracted amount of a `-=`.
fn node_text(e: &Expr) -> String {
    // Best-effort textual rendering from the IR for identifier/member/index
    // chains; this is robust enough to compare operand identity without source.
    render_path(e).unwrap_or_default()
}

/// Source-text path of an lvalue via the context (comment-stripped, lowercased),
/// falling back to a structural render when the span is unavailable. Trimmed.
fn expr_path_text(cx: &AnalysisContext, e: &Expr) -> String {
    let t = cx.source_text(e.span);
    let t = t.trim();
    if t.is_empty() {
        render_path(e).unwrap_or_default()
    } else {
        t.to_string()
    }
}

/// Render an identifier / member / index chain to a canonical lowercased string
/// (`a.b[c]` -> `a.b[c]`). Returns `None` for shapes we don't render.
fn render_path(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.to_ascii_lowercase()),
        ExprKind::Member { base, member } => {
            Some(format!("{}.{}", render_path(base)?, member.to_ascii_lowercase()))
        }
        ExprKind::Index { base, index } => {
            let b = render_path(base)?;
            let idx = index.as_ref().and_then(|i| render_path(i)).unwrap_or_default();
            Some(format!("{b}[{idx}]"))
        }
        _ => None,
    }
}

/// Two normalized path strings refer to the same lvalue. We compare on the
/// trimmed, lowercased text. To tolerate the context renderer including a
/// trailing token, require non-empty exact equality.
fn paths_match(a: &str, b: &str) -> bool {
    let a = a.trim();
    let b = b.trim();
    !a.is_empty() && a == b
}

/// Does the (already-lowercased) `haystack` contain `path` as a substring at an
/// identifier boundary? Used to decide whether `reserve -= <expr>` subtracts the
/// stored path. `path` is itself lowercased.
fn mentions_path(haystack: &str, path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let hay = haystack.to_ascii_lowercase();
    let hb = hay.as_bytes();
    let pb = path.as_bytes();
    let is_id = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'$' || c == b'.' || c == b'[' || c == b']';
    let mut from = 0usize;
    while let Some(rel) = hay[from..].find(path) {
        let i = from + rel;
        let before_ok = i == 0 || !is_id(hb[i - 1]);
        let after = i + pb.len();
        // Allow the path to be followed by a non-identifier char (or EOS); a
        // trailing `.`/`[` would mean a longer path, still a superset match we
        // accept since the stored field is referenced.
        let after_ok = after >= hb.len() || !hb[after].is_ascii_alphanumeric() && hb[after] != b'_';
        if before_ok && after_ok {
            return true;
        }
        from = i + 1;
    }
    false
}

/// Root identifier of an lvalue chain (`a.b[c]` -> `a`), lowercased.
fn root_ident(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.to_ascii_lowercase()),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root_ident(base),
        _ => None,
    }
}

/// True if `name` (lowercased) is the name of a state variable of `f`'s contract
/// **or any transitively-inherited base**. Distinguishes a reserve/accounting
/// store from a function-local of the same role. The transitive walk is essential
/// for the real Renzo target: `WithdrawQueue` declares `claimReserve` in the
/// far base `WithdrawQueueStorageV1`, reached through a V6→V5→…→V1 chain.
fn is_contract_state_var(cx: &AnalysisContext, f: &Function, name: &str) -> bool {
    let Some(c) = cx.contract_of(f.id) else { return false };
    let mut seen = std::collections::HashSet::new();
    contract_has_state_var(cx, c, name, &mut seen)
}

/// Recursive transitive-base scan for a state var named `name` (lowercased).
fn contract_has_state_var(
    cx: &AnalysisContext,
    contract: &sluice_ir::Contract,
    name: &str,
    seen: &mut std::collections::HashSet<String>,
) -> bool {
    if !seen.insert(contract.name.clone()) {
        return false;
    }
    if contract.state_vars.iter().any(|v| v.name.to_ascii_lowercase() == name) {
        return true;
    }
    for base in &contract.bases {
        if let Some(bc) = cx.scir.contract_named(base) {
            if contract_has_state_var(cx, bc, name, seen) {
                return true;
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
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "snapshot-redeem-asymmetry")
    }

    // VULN — the exact Renzo `WithdrawQueue.claimERC20` shape: the reserve is
    // debited by the stored `_withdrawRequest.amountToRedeem` *before* a DOWN-ONLY
    // clamp lowers that same field toward the freshly re-derived live value, and
    // the user is then paid the (smaller) post-clamp amount.
    const VULN: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract WithdrawQueue {
            struct WithdrawRequest { address collateralToken; uint256 amountToRedeem; uint256 ezETHLocked; }
            mapping(address => uint256) public claimReserve;
            function calculateAmountToRedeem(uint256 a, address t) public view returns (uint256, uint256) { return (a, a); }
            function claimERC20(WithdrawRequest memory _withdrawRequest, address user) internal {
                (, uint256 claimAmountToRedeem) = calculateAmountToRedeem(
                    _withdrawRequest.ezETHLocked,
                    _withdrawRequest.collateralToken
                );
                claimReserve[_withdrawRequest.collateralToken] -= _withdrawRequest.amountToRedeem;
                if (claimAmountToRedeem < _withdrawRequest.amountToRedeem) {
                    _withdrawRequest.amountToRedeem = claimAmountToRedeem;
                }
                IERC20(_withdrawRequest.collateralToken).transfer(user, _withdrawRequest.amountToRedeem);
            }
        }
    "#;

    // VULN (local-scalar form): a stored local redeem amount is debited from a
    // reserve, then clamped down-only against a live value. Same directional leak.
    const VULN_LOCAL: &str = r#"
        pragma solidity ^0.8.0;
        contract Queue {
            uint256 public reserve;
            function priceNow(uint256 a) public view returns (uint256) { return a; }
            function claim(uint256 stored, uint256 ezeth) external {
                uint256 live = priceNow(ezeth);
                reserve -= stored;
                if (live < stored) {
                    stored = live;
                }
                payable(msg.sender).transfer(stored);
            }
        }
    "#;

    // SAFE — symmetric reconciliation: the same stored field is clamped in BOTH
    // directions (down on a price fall, up on a price rise), so the reserve unwind
    // can never diverge in a single direction. Must stay silent.
    const SAFE_BOTH_DIRECTIONS: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract WithdrawQueue {
            struct WithdrawRequest { address collateralToken; uint256 amountToRedeem; uint256 ezETHLocked; }
            mapping(address => uint256) public claimReserve;
            function calculateAmountToRedeem(uint256 a, address t) public view returns (uint256, uint256) { return (a, a); }
            function claimERC20(WithdrawRequest memory _withdrawRequest, address user) internal {
                (, uint256 claimAmountToRedeem) = calculateAmountToRedeem(
                    _withdrawRequest.ezETHLocked,
                    _withdrawRequest.collateralToken
                );
                claimReserve[_withdrawRequest.collateralToken] -= _withdrawRequest.amountToRedeem;
                if (claimAmountToRedeem < _withdrawRequest.amountToRedeem) {
                    _withdrawRequest.amountToRedeem = claimAmountToRedeem;
                }
                if (claimAmountToRedeem > _withdrawRequest.amountToRedeem) {
                    _withdrawRequest.amountToRedeem = claimAmountToRedeem;
                }
                IERC20(_withdrawRequest.collateralToken).transfer(user, _withdrawRequest.amountToRedeem);
            }
        }
    "#;

    // SAFE — reserve decremented by the POST-clamp value: the `-=` is placed
    // AFTER the down-only clamp, so it subtracts the already-lowered amount and
    // the accounting matches the payout exactly. No asymmetry → silent.
    const SAFE_POST_CLAMP_DEBIT: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract WithdrawQueue {
            struct WithdrawRequest { address collateralToken; uint256 amountToRedeem; uint256 ezETHLocked; }
            mapping(address => uint256) public claimReserve;
            function calculateAmountToRedeem(uint256 a, address t) public view returns (uint256, uint256) { return (a, a); }
            function claimERC20(WithdrawRequest memory _withdrawRequest, address user) internal {
                (, uint256 claimAmountToRedeem) = calculateAmountToRedeem(
                    _withdrawRequest.ezETHLocked,
                    _withdrawRequest.collateralToken
                );
                if (claimAmountToRedeem < _withdrawRequest.amountToRedeem) {
                    _withdrawRequest.amountToRedeem = claimAmountToRedeem;
                }
                claimReserve[_withdrawRequest.collateralToken] -= _withdrawRequest.amountToRedeem;
                IERC20(_withdrawRequest.collateralToken).transfer(user, _withdrawRequest.amountToRedeem);
            }
        }
    "#;

    // SAFE — no reserve decrement at all: a down-only clamp exists but nothing is
    // debited from any accounting store, so there is no value/accounting leak.
    const SAFE_NO_RESERVE: &str = r#"
        pragma solidity ^0.8.0;
        contract Clamp {
            function priceNow(uint256 a) public view returns (uint256) { return a; }
            function quote(uint256 stored, uint256 ezeth) external view returns (uint256) {
                uint256 live = priceNow(ezeth);
                if (live < stored) {
                    stored = live;
                }
                return stored;
            }
        }
    "#;

    // SAFE — reserve subtracts the LIVE value, not the stored pre-clamp amount.
    // The decrement and payout agree; the down-only clamp is incidental.
    const SAFE_DEBIT_LIVE: &str = r#"
        pragma solidity ^0.8.0;
        contract Queue {
            uint256 public reserve;
            function priceNow(uint256 a) public view returns (uint256) { return a; }
            function claim(uint256 stored, uint256 ezeth) external {
                uint256 live = priceNow(ezeth);
                reserve -= live;
                if (live < stored) {
                    stored = live;
                }
                payable(msg.sender).transfer(stored);
            }
        }
    "#;

    #[test]
    fn fires_on_renzo_claim_shape() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_local_scalar_shape() {
        assert!(fires(VULN_LOCAL), "{:#?}", run(VULN_LOCAL));
    }

    #[test]
    fn silent_when_clamped_both_directions() {
        assert!(!fires(SAFE_BOTH_DIRECTIONS), "{:#?}", run(SAFE_BOTH_DIRECTIONS));
    }

    #[test]
    fn silent_when_reserve_debited_post_clamp() {
        assert!(!fires(SAFE_POST_CLAMP_DEBIT), "{:#?}", run(SAFE_POST_CLAMP_DEBIT));
    }

    #[test]
    fn silent_without_reserve_decrement() {
        assert!(!fires(SAFE_NO_RESERVE), "{:#?}", run(SAFE_NO_RESERVE));
    }

    #[test]
    fn silent_when_reserve_debits_live_value() {
        assert!(!fires(SAFE_DEBIT_LIVE), "{:#?}", run(SAFE_DEBIT_LIVE));
    }
}
