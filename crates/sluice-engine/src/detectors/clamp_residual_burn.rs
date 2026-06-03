//! Clamp-residual-burn sink — a value is clamped down (`min(...)` / `if (x > cap)
//! x = cap`) and the *clamped* amount is then routed into a burn / `address(0)` /
//! void / write-off sink, so the residual (`original - clamped`) is destroyed
//! rather than conserved. The disfavored party silently bears that asymmetric
//! value loss.
//!
//! ## The shape
//!
//! A "destruction" path (a slash, a sweep, a forfeiture) computes how much value
//! to take, but first **clamps it down** to some cap so the contract's own
//! bookkeeping cannot go negative:
//!
//! ```solidity
//! uint256 slashedWithdrawable = Math.min(node.withdrawableCreditedNodeETH, slashedAssets);
//! INativeNode(node.nodeAddress).withdraw(address(0), slashedWithdrawable);   // burn to 0x0
//! node.totalRestakedETH         -= slashedWithdrawable;
//! node.withdrawableCreditedNodeETH -= slashedWithdrawable;
//! ```
//!
//! The clamped amount `slashedWithdrawable` is sent to `address(0)` — irreversibly
//! destroyed. Whatever was clamped off (`slashedAssets - slashedWithdrawable`,
//! the part above the `withdrawableCreditedNodeETH` cap) is *not* swept and not
//! returned to anyone either: the value that does leave is burned, the value that
//! is clamped off is stranded, and in neither case does it flow back to a real
//! owner/treasury balance. This is the **Karak `NativeVault._burnSlashed`** shape,
//! and the sibling `Vault.slashAssets` (`Math.min(totalAssets(), totalAssetsToSlash)`
//! then a handler that `safeTransfer`s to `address(0)`).
//!
//! Burning a *clamped* quantity is the smell: a faithful destruction sends the
//! true computed amount (and reverts / queues a shortfall if the cap is hit); a
//! faithful redistribution returns the leftover to its owner. Sending `min(cap,
//! amount)` to `0x0` instead silently writes off the residual against whoever the
//! cap was protecting.
//!
//! ## Why this is a distinct class (vs. proportional-split-residual)
//!
//! `proportional-split-residual` is about *rounding dust* forced onto one bucket
//! after floor division. This detector is about a *clamp* whose result is routed
//! to a **burn / `address(0)` / void** sink — the disambiguator is the sink, not
//! the arithmetic. The residual here is the clamped-off remainder, destroyed (or
//! stranded) rather than conserved.
//!
//! ## Precision anchors (all required, so it stays quiet on ordinary clamps)
//!
//!   * a **down-clamp** that *names a value* `X` — `X = min(a, b)` /
//!     `T X = Math.min(a, b)`, or the explicit `if (orig > cap) orig = cap;`
//!     guard (`X = orig`). A bare `min(...)` whose result is never burned is fine;
//!   * that same `X` is then handed to a **burn / void sink** *in the same
//!     function* — a `burn`-named call carrying `X`, or a `transfer` / `withdraw`
//!     / `send` / `safeTransfer`-style call that has both an `address(0)` /
//!     literal-`0` recipient **and** `X` as the amount. The co-located clamp + 0x0
//!     sink is the structural proof of clamped-value destruction;
//!   * **SUPPRESS when conserved**: if the function also returns value to a real
//!     owner/treasury — credits an accounting balance (`bal[..] += …`) or
//!     `mint`/`transfer`s to a *non-zero* recipient — the leftover is not
//!     destroyed and nothing fires.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{AssignOp, BinOp, Call, CallKind, Expr, ExprKind, Function, Lit, Span, Stmt, StmtKind};

use super::prelude::*;

pub struct ClampResidualBurnDetector;

impl Detector for ClampResidualBurnDetector {
    fn id(&self) -> &'static str {
        "clamp-residual-burn"
    }
    fn category(&self) -> Category {
        Category::ClampResidualBurnSink
    }
    fn description(&self) -> &'static str {
        "A clamped value (min / down-clamp) is routed to a burn / address(0) / void sink so the \
         residual is destroyed rather than conserved (Karak NativeVault._burnSlashed class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // Only concrete, state-mutating bodies can clamp a value and then burn
            // it. View/pure helpers and bare interface declarations cannot.
            if !f.has_body || f.is_view_or_pure() {
                continue;
            }
            // Interfaces / pure libraries declare no destruction logic.
            let Some(contract) = cx.contract_of(f.id) else { continue };
            if contract.is_interface() {
                continue;
            }

            // (1) collect every named down-clamp `X = min(..)` / `if (o>c) o=c`.
            let clamps = collect_clamps(f);
            if clamps.is_empty() {
                continue;
            }
            // (2) collect every burn / void sink and the identifiers it carries.
            let sinks = collect_burn_sinks(f);
            if sinks.is_empty() {
                continue;
            }
            // (3) SUPPRESS: if the function conserves value back to a real
            //     owner/treasury (credit / mint / transfer to a non-zero party),
            //     the residual is not destroyed — nothing to report.
            if conserves_value(cx, f) {
                continue;
            }

            // (4) a clamped value that is carried into a burn/void sink is the hit.
            //     Match on the clamp's *leaf token* against the sink's carried
            //     tokens, so the SAME value (not merely the same struct base) must
            //     flow into the sink.
            let Some((clamp, sink)) = clamps.iter().find_map(|c| {
                sinks
                    .iter()
                    .find(|s| s.carries.iter().any(|n| n == &c.key))
                    .map(|s| (c, s))
            }) else {
                continue;
            };

            let b = report!(self, Category::ClampResidualBurnSink,
                title = "Clamped value routed to a burn / address(0) sink — residual is destroyed, not conserved",
                severity = Severity::Medium,
                confidence = 0.6,
                dimensions = [Dimension::Invariant],
                message = format!(
                    "`{fname}` clamps a value down to `{clamped}` (`{clamped} = {form}`) and then routes \
                     that clamped amount into a {sink_kind} (`{sink}`). The part that was clamped off — \
                     the residual `original - {clamped}` — is neither swept nor returned to its owner: the \
                     amount that leaves is burned/voided, and the leftover is silently written off against \
                     whoever the cap was protecting. This asymmetric value destruction is borne by the \
                     disfavored party. It is the Karak `NativeVault._burnSlashed` / `Vault.slashAssets` \
                     clamp-then-burn shape (`Math.min(...)` followed by a withdraw / transfer to \
                     `address(0)`).",
                    fname = f.name,
                    clamped = clamp.clamped,
                    form = clamp.form,
                    sink = sink.text,
                    sink_kind = sink.kind_label(),
                ),
                recommendation =
                    "Conserve the clamped-off residual instead of destroying it: either revert / queue a \
                     shortfall when the clamp actually binds (so the true computed amount is taken, never \
                     a silently smaller one), or credit `original - clamped` back to the affected owner / \
                     treasury balance. Burning or voiding only `min(cap, amount)` writes the difference off \
                     against the party the cap was meant to protect.",
            );
            out.push(finish_at(cx, b, f.id, clamp.span));
        }
        out
    }
}

// ----------------------------------------------------------------- clamp discovery

/// A named down-clamp: the identifier it binds, the source-ish form of the
/// right-hand side (for the message), and the span to report at.
struct Clamp {
    /// The display name of the clamped lvalue (`slashedWithdrawable`,
    /// `_withdrawRequest.amountToRedeem`).
    clamped: String,
    /// The **leaf token** used to test whether a sink carries this exact clamped
    /// value: the trailing segment of the lvalue path, lowercased
    /// (`slashedwithdrawable`, `amounttoredeem`). Matching on the leaf — not the
    /// struct base — is what stops a sink that carries a *different field of the
    /// same struct* (`_withdrawRequest.ezETHLocked`) from spuriously matching a
    /// clamp on `_withdrawRequest.amountToRedeem`.
    key: String,
    /// Best-effort rendering of the clamp expression (`Math.min(cap, amount)`).
    form: String,
    span: Span,
}

/// Collect every **named down-clamp** in `f`:
///   * `T X = min(a, b)` / `X = Math.min(a, b)` — the result of a `min`-family
///     call bound to a fresh identifier `X`;
///   * `if (orig > cap) orig = cap;` (and the `>=` / mirrored `cap < orig`
///     forms) — `orig` is monotonically lowered to `cap`, so `orig` is the
///     clamped name.
fn collect_clamps(f: &Function) -> Vec<Clamp> {
    let mut out = Vec::new();
    for top in &f.body {
        top.visit(&mut |st| match &st.kind {
            // `T X = min(a, b);`
            StmtKind::VarDecl { name: Some(name), init: Some(init), .. } if is_min_call(init) => {
                out.push(Clamp {
                    clamped: name.clone(),
                    key: name.to_ascii_lowercase(),
                    form: render_expr(init),
                    span: st.span,
                });
            }
            // `X = min(a, b);` (assignment, not a declaration).
            StmtKind::Expr(e) => {
                if let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind {
                    if is_min_call(value) {
                        if let Some(key) = leaf_token(target) {
                            out.push(Clamp {
                                clamped: render_expr(target),
                                key,
                                form: render_expr(value),
                                span: st.span,
                            });
                        }
                    }
                }
            }
            // `if (orig > cap) { orig = cap; }` — explicit down-clamp guard.
            StmtKind::If { cond, then_branch, .. } => {
                if let Some((bigger, smaller)) = gt_comparison_operands(cond) {
                    if let Some(clamp) = then_branch_clamps_down(then_branch, &bigger, &smaller, st.span)
                    {
                        out.push(clamp);
                    }
                }
            }
            _ => {}
        });
    }
    out
}

/// The **leaf token** of an lvalue path, lowercased: the trailing member of a
/// member chain (`_withdrawRequest.amountToRedeem` -> `amounttoredeem`), the index
/// base's leaf for an indexed access, or the identifier itself for a bare local
/// (`slashedWithdrawable` -> `slashedwithdrawable`). Returns `None` for shapes
/// that have no identifier leaf (a call, a literal). This is the granularity at
/// which we decide "the *same* value flows to the sink".
fn leaf_token(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.to_ascii_lowercase()),
        ExprKind::Member { member, .. } => Some(member.to_ascii_lowercase()),
        ExprKind::Index { base, .. } => leaf_token(base),
        _ => None,
    }
}

/// Is `e` a call to a `min`-family clamp helper (`min`, `Math.min`, `mulDivMin`,
/// `minOf`)? We match on the resolved `func_name`, so both the free
/// `min(a,b)` and the `Math.min(a,b)` / `x.min(y)` bound forms are caught.
fn is_min_call(e: &Expr) -> bool {
    if let ExprKind::Call(c) = &peel_casts(e).kind {
        if let Some(name) = c.func_name.as_deref() {
            let l = name.to_ascii_lowercase();
            // `min` / `Math.min` / `minOf`; require `min` to be a standalone token
            // start so we don't match `mint`, `minimumOut`, etc.
            return l == "min" || l == "minof" || l.ends_with(".min");
        }
    }
    false
}

/// If `cond` is `a > b` / `a >= b` (or the mirrored `b < a` / `b <= a`), return
/// `(bigger_text, smaller_text)` — the operand that is the larger of the two and
/// the one it is being compared against. Used to detect `if (orig > cap)`.
fn gt_comparison_operands(cond: &Expr) -> Option<(String, String)> {
    let ExprKind::Binary { op, lhs, rhs } = &cond.kind else { return None };
    match op {
        // `lhs > rhs` / `lhs >= rhs`: lhs is the bigger operand.
        BinOp::Gt | BinOp::Ge => Some((render_expr(lhs), render_expr(rhs))),
        // `lhs < rhs` / `lhs <= rhs`: rhs is the bigger operand.
        BinOp::Lt | BinOp::Le => Some((render_expr(rhs), render_expr(lhs))),
        _ => None,
    }
}

/// In `if (orig > cap)`, does the then-branch assign `orig = cap` (lower the
/// bigger operand to the cap)? If so return the clamp keyed on `orig`'s root.
fn then_branch_clamps_down(
    then_branch: &[Stmt],
    bigger: &str,
    smaller: &str,
    if_span: Span,
) -> Option<Clamp> {
    let mut found: Option<Clamp> = None;
    for s in then_branch {
        s.visit(&mut |st| {
            if found.is_some() {
                return;
            }
            let StmtKind::Expr(e) = &st.kind else { return };
            let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind else { return };
            let tgt = render_expr(target);
            let val = render_expr(value);
            // `orig = cap`: target is the bigger comparison operand, value the smaller.
            if !tgt.is_empty() && tgt == bigger && val == smaller {
                if let Some(key) = leaf_token(target) {
                    found = Some(Clamp {
                        clamped: render_expr(target),
                        key,
                        form: format!("{bigger} clamped to {smaller}"),
                        span: if_span,
                    });
                }
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

// ------------------------------------------------------------------ sink discovery

/// What kind of value-destruction sink a call is.
#[derive(Clone, Copy, PartialEq)]
enum SinkKind {
    /// A `burn`-named call (`burn`, `_burn`, `burnFrom`, `burnShares`).
    Burn,
    /// A transfer / withdraw / send carrying an `address(0)` / literal-0 recipient.
    Void,
}

/// A burn / void sink call: its kind, a rendering for the message, and the set of
/// bare identifiers it carries as arguments (so we can tell whether the clamped
/// value flows into it).
struct BurnSink {
    kind: SinkKind,
    text: String,
    carries: Vec<String>,
}

impl BurnSink {
    fn kind_label(&self) -> &'static str {
        match self.kind {
            SinkKind::Burn => "burn sink",
            SinkKind::Void => "transfer to address(0) / void sink",
        }
    }
}

/// Names of value-moving calls that, when paired with an `address(0)` / literal-0
/// recipient, route value to the void.
const VOID_MOVERS: &[&str] = &[
    "transfer",
    "transferfrom",
    "safetransfer",
    "safetransferfrom",
    "send",
    "withdraw",
    "sweep",
    "push",
];

/// Collect every burn / void sink in `f`.
fn collect_burn_sinks(f: &Function) -> Vec<BurnSink> {
    let mut out = Vec::new();
    for top in &f.body {
        top.visit_exprs(&mut |e| {
            let ExprKind::Call(c) = &e.kind else { return };
            // A type-cast "call" (`address(0)`, `IFoo(x)`) is never itself a sink.
            if matches!(c.kind, CallKind::TypeCast) {
                return;
            }
            let Some(name) = c.func_name.as_deref() else { return };
            let l = name.to_ascii_lowercase();

            // Sink A: a burn-named call that destroys value outright — `burn(amount)`
            // / `burnShares(amount)` with NO real-recipient argument (or whose only
            // address-like arg is `address(0)`). A routine ERC20 `_burn(account,
            // amount)` whose `account` is a real address is share *accounting* for a
            // withdrawal (the assets are returned to that account elsewhere), NOT a
            // value-to-void sink — excluding it keeps this off ordinary withdraw /
            // redeem burns (e.g. Karak `_decreaseBalance`'s `_burn(_of, shares)`).
            if is_burn_name(&l) && burn_destroys_value(c) {
                out.push(BurnSink {
                    kind: SinkKind::Burn,
                    text: render_call(c),
                    carries: carried_tokens(c),
                });
                return;
            }
            // Sink B: a value-mover with an `address(0)` / literal-0 recipient.
            if VOID_MOVERS.iter().any(|m| &l == m) && call_has_zero_recipient(c) {
                out.push(BurnSink {
                    kind: SinkKind::Void,
                    text: render_call(c),
                    carries: carried_tokens(c),
                });
            }
        });
    }
    out
}

/// Is `l` (lowercased) a burn-style destruction call? `burn`, `_burn`,
/// `burnfrom`, `burnshares`, `burnassets`, …
fn is_burn_name(l: &str) -> bool {
    let trimmed = l.trim_start_matches('_');
    trimmed == "burn" || trimmed.starts_with("burn")
}

/// Does this `burn`-named call destroy value outright, rather than do routine
/// share accounting for a withdrawal? A faithful value-destruction burn is the
/// `burn(amount)` / `burnShares(amount)` form (the holder is implicit / the
/// contract itself). By contrast, the ubiquitous ERC20 `_burn(account, amount)`
/// whose **first** argument is a genuine (non-zero) holder address burns *that
/// account's* shares as the bookkeeping half of a redeem — the assets are paid
/// back to the holder in the same or calling frame — so it is **not** asymmetric
/// value destruction.
///
/// The separator is the canonical `(holder, amount)` shape: a burn is treated as
/// routine accounting (NOT a sink) exactly when it has **two or more arguments
/// and the first is a non-zero recipient-like address**. A one-argument
/// `burn(amount)` (or one whose holder slot is `address(0)`) is a value sink.
/// This keeps the detector off normal withdraw/redeem paths (Karak
/// `_decreaseBalance`'s `_burn(_of, shares)`).
fn burn_destroys_value(c: &Call) -> bool {
    match c.args.first() {
        Some(first) if c.args.len() >= 2 => is_zero_address(first) || !is_recipient_like(first),
        _ => true, // 0- or 1-arg burn: the amount-only / implicit-holder form.
    }
}

/// Does any argument of `c` peel down to a literal `0` / `address(0)` — i.e. a
/// transfer to the zero/void address? `address(0)` parses as a one-argument
/// `TypeCast` call wrapping the number literal `0`, so peeling the cast leaves the
/// `0` literal.
fn call_has_zero_recipient(c: &Call) -> bool {
    c.args.iter().any(is_zero_address)
}

/// Is `e` `address(0)` / `0` / `0x0` (a literal zero, possibly cast)? We peel
/// casts first so `address(0)` and `payable(address(0))` both reduce to `0`.
fn is_zero_address(e: &Expr) -> bool {
    match &peel_casts(e).kind {
        ExprKind::Lit(Lit::Number(n)) => n.trim() == "0",
        ExprKind::Lit(Lit::HexNumber(h)) => {
            let s = h.trim().trim_start_matches("0x").trim_start_matches("0X");
            !s.is_empty() && s.bytes().all(|b| b == b'0')
        }
        _ => false,
    }
}

/// The set of matchable **tokens** appearing anywhere inside `c`'s arguments,
/// lowercased — every bare identifier **and** every member-access leaf name. We
/// collect the member leaf (not just the struct base) so that a sink carrying
/// `_withdrawRequest.ezETHLocked` contributes the token `ezethlocked` (which will
/// NOT match a clamp keyed on `amounttoredeem`), while a local-scalar amount like
/// `slashedWithdrawable` contributes `slashedwithdrawable` and matches its clamp.
/// Looking at the whole argument subtree finds the amount inside arithmetic
/// (`amount - fee`) and cast wrappers.
fn carried_tokens(c: &Call) -> Vec<String> {
    let mut names = Vec::new();
    let mut push = |t: String| {
        if !names.contains(&t) {
            names.push(t);
        }
    };
    for a in &c.args {
        a.visit(&mut |sub| match &sub.kind {
            ExprKind::Ident(n) => push(n.to_ascii_lowercase()),
            ExprKind::Member { member, .. } => push(member.to_ascii_lowercase()),
            _ => {}
        });
    }
    names
}

// ---------------------------------------------------------------- conservation gate

/// Does `f` **conserve** value back to a real owner / treasury — meaning the
/// clamped-off residual is not actually destroyed? Two conserving shapes:
///
///   * a compound credit `bal[..] += …` to an accounting-named state var (the
///     leftover is returned to a balance), or
///   * a `mint` / `transfer` / `safeTransfer` to a **non-zero** recipient (value
///     handed to a real party rather than the void).
///
/// Conservative by design: any such credit suppresses the finding.
fn conserves_value(cx: &AnalysisContext, f: &Function) -> bool {
    for top in &f.body {
        let mut conserves = false;
        top.visit(&mut |st| {
            if conserves {
                return;
            }
            // `accountingVar[..] += amount` — a balance credit.
            if let StmtKind::Expr(e) = &st.kind {
                if let ExprKind::Assign { op: AssignOp::Add, target, .. } = &e.kind {
                    if let Some(root) = root_ident(target) {
                        if is_accounting_name(&root) && root_is_state_var(cx, f, target) {
                            conserves = true;
                        }
                    }
                }
            }
        });
        if conserves {
            return true;
        }
    }
    // A mint/credit/transfer to a *non-zero* recipient also conserves value.
    for top in &f.body {
        let mut conserves = false;
        top.visit_exprs(&mut |e| {
            if conserves {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            let Some(name) = c.func_name.as_deref() else { return };
            let l = name.to_ascii_lowercase();
            let credit = l == "mint" || l == "safemint" || l.starts_with("mint") || l == "credit";
            let transfer = VOID_MOVERS.iter().any(|m| &l == m);
            if (credit || transfer) && c.args.iter().any(|a| !is_zero_address(a) && is_recipient_like(a)) {
                // A value-mover whose recipient is a real (non-zero) address, or a
                // mint to a real account, returns value to an owner — conserved.
                // (A transfer to `address(0)` is the *sink*, handled above, and is
                // explicitly NOT treated as conservation.)
                if transfer && call_has_zero_recipient(c) {
                    return; // this is the void sink, not a conserving transfer
                }
                conserves = true;
            }
        });
        if conserves {
            return true;
        }
    }
    false
}

/// Heuristic: could `e` be a recipient address — a bare identifier / member chain
/// (`nodeOwner`, `msg.sender`, `treasury`), or those wrapped in an `address(..)` /
/// `payable(..)` cast (`address(this)`, `payable(owner)`)? We peel casts first so
/// `address(this)` is recognized as a real recipient (an escrow / self burn is
/// share accounting, not a void). Literals and ordinary calls are not recipients,
/// so a numeric amount argument is never mistaken for one.
fn is_recipient_like(e: &Expr) -> bool {
    matches!(&peel_casts(e).kind, ExprKind::Ident(_) | ExprKind::Member { .. })
}

// ------------------------------------------------------------------------ rendering

/// Best-effort source-ish rendering of an expression for the diagnostic message.
fn render_expr(e: &Expr) -> String {
    match &e.kind {
        ExprKind::Ident(n) => n.clone(),
        ExprKind::Lit(Lit::Number(n)) => n.trim().to_string(),
        ExprKind::Lit(Lit::HexNumber(h)) => h.trim().to_string(),
        ExprKind::Member { base, member } => format!("{}.{}", render_expr(base), member),
        ExprKind::Index { base, index } => {
            let idx = index.as_ref().map(|i| render_expr(i)).unwrap_or_default();
            format!("{}[{}]", render_expr(base), idx)
        }
        ExprKind::Call(c) => render_call(c),
        ExprKind::Binary { op, lhs, rhs } => {
            format!("{} {} {}", render_expr(lhs), bin_op_str(*op), render_expr(rhs))
        }
        _ => String::new(),
    }
}

/// Render a call as `name(arg, arg)` (best-effort, for messages).
fn render_call(c: &Call) -> String {
    let name = c.func_name.clone().unwrap_or_else(|| "?".to_string());
    let args: Vec<String> = c.args.iter().map(render_expr).collect();
    format!("{}({})", name, args.join(", "))
}

fn bin_op_str(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::Div => "/",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "clamp-residual-burn")
    }

    // VULN — the exact Karak `NativeVault._burnSlashed` shape: the slashed amount
    // is clamped with `Math.min` to the node's credited-withdrawable cap, then the
    // clamped amount is withdrawn to `address(0)` (the void). The residual above
    // the cap is destroyed, not conserved.
    const VULN: &str = r#"
        pragma solidity ^0.8.0;
        interface INativeNode { function withdraw(address to, uint256 a) external; }
        library Math { function min(uint256 a, uint256 b) internal pure returns (uint256) { return a < b ? a : b; } }
        contract NativeVault {
            struct Node { address nodeAddress; uint256 totalRestakedETH; uint256 withdrawableCreditedNodeETH; }
            mapping(address => Node) public ownerToNode;
            uint256 public ts;
            function convertToAssets(uint256 s) public view returns (uint256) { return s; }
            function balanceOf(address) public view returns (uint256) { return ts; }
            function _burnSlashed(address nodeOwner) internal {
                Node storage node = ownerToNode[nodeOwner];
                uint256 slashedAssets;
                if (node.totalRestakedETH > convertToAssets(balanceOf(nodeOwner))) {
                    slashedAssets = node.totalRestakedETH - convertToAssets(balanceOf(nodeOwner));
                }
                uint256 slashedWithdrawable = Math.min(node.withdrawableCreditedNodeETH, slashedAssets);
                INativeNode(node.nodeAddress).withdraw(address(0), slashedWithdrawable);
                node.totalRestakedETH -= slashedWithdrawable;
                node.withdrawableCreditedNodeETH -= slashedWithdrawable;
            }
        }
    "#;

    // VULN (burn-named sink): a clamped amount is passed straight to a no-recipient
    // `burn(amount)` forfeiture — the value is destroyed outright, and the residual
    // above the cap is written off against the affected party.
    const VULN_BURN_CALL: &str = r#"
        pragma solidity ^0.8.0;
        interface IBurnableToken { function burn(uint256 amount) external; }
        library Math { function min(uint256 a, uint256 b) internal pure returns (uint256) { return a < b ? a : b; } }
        contract Forfeiter {
            address public token;
            mapping(address => uint256) public penalty;
            function forceForfeit(address user, uint256 requested) external {
                uint256 burnt = Math.min(requested, penalty[user]);
                IBurnableToken(token).burn(burnt);
            }
        }
    "#;

    // VULN (explicit if-down-clamp + address(0) transfer): `amount` is clamped
    // down by an `if (amount > cap) amount = cap;` guard, then transferred to 0x0.
    const VULN_IF_CLAMP: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract Slasher {
            uint256 public cap;
            address public token;
            function slash(uint256 amount) external {
                if (amount > cap) {
                    amount = cap;
                }
                IERC20(token).transfer(address(0), amount);
            }
        }
    "#;

    // SAFE — conserved: a value is clamped, but the residual is returned to a real
    // owner balance (`balanceOf[user] += residual`). Nothing is destroyed → silent.
    const SAFE_CONSERVED: &str = r#"
        pragma solidity ^0.8.0;
        library Math { function min(uint256 a, uint256 b) internal pure returns (uint256) { return a < b ? a : b; } }
        contract Refund {
            mapping(address => uint256) public balanceOf;
            function settle(address user, uint256 requested, uint256 cap) external {
                uint256 paid = Math.min(requested, cap);
                uint256 residual = requested - paid;
                balanceOf[user] += residual;
            }
        }
    "#;

    // SAFE — clamp, but the clamped amount is paid to a REAL recipient
    // (`msg.sender`), not burned. No void/burn sink → silent.
    const SAFE_REAL_PAYOUT: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        library Math { function min(uint256 a, uint256 b) internal pure returns (uint256) { return a < b ? a : b; } }
        contract Payout {
            address public token;
            uint256 public cap;
            function claim(uint256 requested) external {
                uint256 paid = Math.min(requested, cap);
                IERC20(token).transfer(msg.sender, paid);
            }
        }
    "#;

    // SAFE — a burn to address(0) exists, but the burned amount is NOT a clamped
    // value (it is the raw requested amount). No clamp feeds the sink → silent.
    const SAFE_BURN_NOT_CLAMPED: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract Burner {
            address public token;
            function burnExact(uint256 amount) external {
                IERC20(token).transfer(address(0), amount);
            }
        }
    "#;

    // SAFE — the Karak `_decreaseBalance` withdraw shape: a clamped `shares`
    // (`Math.min(convertToShares(assets), balanceOf(_of))`) is burned via the
    // routine ERC20 `_burn(_of, shares)` whose holder `_of` is a REAL address. This
    // is share accounting for a redeem (assets are returned to `_of` in the calling
    // frame), not value-to-void, so it must stay silent.
    const SAFE_REDEEM_BURN: &str = r#"
        pragma solidity ^0.8.0;
        library Math { function min(uint256 a, uint256 b) internal pure returns (uint256) { return a < b ? a : b; } }
        contract NativeVault {
            struct Node { uint256 totalRestakedETH; }
            mapping(address => Node) public ownerToNode;
            uint256 public totalAssets;
            function convertToShares(uint256 a) public view returns (uint256) { return a; }
            function convertToAssets(uint256 s) public view returns (uint256) { return s; }
            function balanceOf(address) public view returns (uint256) { return totalAssets; }
            function _burn(address from, uint256 shares) internal {}
            function _decreaseBalance(address _of, uint256 assets) internal {
                uint256 shares = Math.min(convertToShares(assets), balanceOf(_of));
                assets = convertToAssets(shares);
                _burn(_of, shares);
                totalAssets -= assets;
                ownerToNode[_of].totalRestakedETH -= assets;
            }
        }
    "#;

    // SAFE — the Renzo `WithdrawQueue.claimETH` shape (a *different* class —
    // snapshot-redeem-asymmetry, not clamp-residual-burn). A struct field
    // `_withdrawRequest.amountToRedeem` is down-clamped, and a burn
    // `ezETH.burn(address(this), _withdrawRequest.ezETHLocked)` destroys escrowed
    // shares — but (a) the burned token (`ezETHLocked`) is a DIFFERENT field from
    // the clamped one (`amountToRedeem`), and (b) the burn holder is `address(this)`
    // (escrow accounting), and the ETH is paid to the real `user`. Must stay silent
    // for THIS detector.
    const SAFE_RENZO_CLAIM: &str = r#"
        pragma solidity ^0.8.0;
        interface IEzETH { function burn(address from, uint256 amount) external; }
        contract WithdrawQueue {
            struct WithdrawRequest { uint256 amountToRedeem; uint256 ezETHLocked; }
            mapping(bool => uint256) public claimReserve;
            IEzETH public ezETH;
            bool constant IS_NATIVE = true;
            function calculateAmountToRedeem(uint256 a, bool) public view returns (uint256, uint256) { return (a, a); }
            function claimETH(WithdrawRequest memory _withdrawRequest, address user) internal {
                (, uint256 claimAmountToRedeem) = calculateAmountToRedeem(_withdrawRequest.ezETHLocked, IS_NATIVE);
                claimReserve[IS_NATIVE] -= _withdrawRequest.amountToRedeem;
                if (claimAmountToRedeem < _withdrawRequest.amountToRedeem) {
                    _withdrawRequest.amountToRedeem = claimAmountToRedeem;
                }
                ezETH.burn(address(this), _withdrawRequest.ezETHLocked);
                (bool ok, ) = payable(user).call{ value: _withdrawRequest.amountToRedeem }("");
                require(ok);
            }
        }
    "#;

    // SAFE — `min` is used and the result is returned to the caller (priced), no
    // burn/void sink in the function at all.
    const SAFE_MIN_NO_SINK: &str = r#"
        pragma solidity ^0.8.0;
        library Math { function min(uint256 a, uint256 b) internal pure returns (uint256) { return a < b ? a : b; } }
        contract Quote {
            uint256 public cap;
            function quote(uint256 requested) external view returns (uint256) {
                uint256 paid = Math.min(requested, cap);
                return paid;
            }
        }
    "#;

    #[test]
    fn fires_on_karak_burn_slashed_shape() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_burn_named_sink() {
        assert!(fires(VULN_BURN_CALL), "{:#?}", run(VULN_BURN_CALL));
    }

    #[test]
    fn fires_on_if_downclamp_then_zero_transfer() {
        assert!(fires(VULN_IF_CLAMP), "{:#?}", run(VULN_IF_CLAMP));
    }

    #[test]
    fn silent_when_residual_conserved_to_balance() {
        assert!(!fires(SAFE_CONSERVED), "{:#?}", run(SAFE_CONSERVED));
    }

    #[test]
    fn silent_when_paid_to_real_recipient() {
        assert!(!fires(SAFE_REAL_PAYOUT), "{:#?}", run(SAFE_REAL_PAYOUT));
    }

    #[test]
    fn silent_when_burned_amount_not_clamped() {
        assert!(!fires(SAFE_BURN_NOT_CLAMPED), "{:#?}", run(SAFE_BURN_NOT_CLAMPED));
    }

    #[test]
    fn silent_when_min_has_no_sink() {
        assert!(!fires(SAFE_MIN_NO_SINK), "{:#?}", run(SAFE_MIN_NO_SINK));
    }

    #[test]
    fn silent_on_redeem_share_burn_to_real_holder() {
        assert!(!fires(SAFE_REDEEM_BURN), "{:#?}", run(SAFE_REDEEM_BURN));
    }

    #[test]
    fn silent_on_renzo_claim_different_field_escrow_burn() {
        assert!(!fires(SAFE_RENZO_CLAIM), "{:#?}", run(SAFE_RENZO_CLAIM));
    }
}
