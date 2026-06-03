//! RFQ / signed-order fill accounting — the making/taking/fee split is never
//! reconciled to the signed amounts, or a partial-fill residual is written
//! without a `filled <= amount` bound.
//!
//! An intent / RFQ / limit-order protocol settles a *maker's signed order*: the
//! maker signs an order committing to a `makingAmount` (and an implied price),
//! and a taker/solver calls a `fill` entry that (1) verifies the maker's
//! ECDSA / EIP-712 signature, then (2) computes a `making` / `taking` / `fee`
//! split from the signed amounts and (3) moves tokens accordingly — maker pays
//! `making`, taker pays `taking`, protocol keeps `fee`. The whole construction
//! is a *zero-sum settlement*: every unit that leaves one party must arrive at
//! another, so the three legs must reconcile —
//! `actualMaking + totalFee == gross` (or `actualTaking == net + totalFee`).
//!
//! Two failure shapes let the filler/solver silently skim value:
//!
//!   * **(a) split not reconciled.** The fill computes the legs with `+` / `-`
//!     (`actualMaking = totalMaking - totalFee`, `actualTaking = totalTaking +
//!     totalFee`) but **never asserts the conservation identity**. There is no
//!     `require(actualMaking + totalFee == totalMaking)`. A wrong fee figure (or
//!     a rounding step that drops units) therefore goes undetected: the taker
//!     receives `actualMaking`, the makers are charged `taking`, and the
//!     difference — which should equal the fee — is whatever the arithmetic
//!     produced, with no check that it is conserved. The solver who controls the
//!     taker side keeps the delta.
//!
//!   * **(b) partial-fill residual unbounded.** A partially-fillable order tracks
//!     how much has been consumed (`filled[orderHash] += x`, `status.filledAmount
//!     = filled + x`). Without a `require(filled <= order.makingAmount)` bound
//!     (or an equivalent `min(...)` clamp on `x`), a taker can fill *more* than
//!     the maker signed for — replaying the residual — or the bookkeeping
//!     overflows the signed cap, again at the maker's expense.
//!
//! This is the shape behind the Pendle limit-order router
//! (`LimitRouterBase.fillTokenForPY` / `fillPYForToken`): after
//! `_checkSig_updMakingAndStatus` verifies each maker signature, the fill does
//! `(actualMaking, actualTaking, totalFee) = (out.totalMaking - out.totalFee,
//! out.totalTaking, out.totalFee)` (resp. `out.totalTaking + out.totalFee`) and
//! transfers all three legs — but the only `require` on the path is the taker's
//! `actualTaking <= maxTaking` slippage bound, never a conservation check tying
//! the fee to the gross/net split. The secondary target is Ethena
//! `EthenaMinting` (signed mint/redeem orders).
//!
//! Precision anchors (all required, so this stays quiet on ordinary swap / vote
//! / permit code):
//!   * the function (directly or through a transitive **internal** callee) reaches
//!     an ECDSA / EIP-712 **order-signature verification** primitive (`ecrecover`,
//!     `.recover(`, `isValidSignatureNow`, `SignatureChecker`, or a callee named
//!     `_checkSig` / `verifyOrder` / `verifySignature`). A vote/permit that
//!     verifies a signature but has no maker/taker *fill* split is excluded by the
//!     next anchor;
//!   * it is state-mutating and **moves tokens** (a `transfer*` / `mint` / `burn`
//!     / `_transferOut` / `_transferIn` call), so it is a real settlement, not a
//!     pure view quote;
//!   * **and** either (a) it computes a maker/taker/fee **split** — an `Add`/`Sub`
//!     combining a *fee*-named term with a *making/taking/gross/net*-named term —
//!     with **no conservation `require`** (`fee + net == gross`); or (b) it writes
//!     a **partial-fill residual** (`filled`/`filledAmount` `+=`) with **no
//!     `filled <= amount` bound and no `min(` clamp**.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use rustc_hash::FxHashSet;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{AssignOp, BinOp, Builtin, CallKind, Expr, ExprKind, Function};

use super::prelude::*;

pub struct RfqFillAccountingDetector;

impl Detector for RfqFillAccountingDetector {
    fn id(&self) -> &'static str {
        "rfq-fill-accounting"
    }
    fn category(&self) -> Category {
        Category::RfqFillAccounting
    }
    fn description(&self) -> &'static str {
        "Signed-order (RFQ/limit) fill whose making/taking/fee split is not reconciled to the signed amounts, or whose partial-fill residual is unbounded (Pendle LimitRouter class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || !f.is_state_mutating() {
                continue;
            }

            // --- anchor 1: this function settles a *signed order*. The signature
            // verification is frequently one or two internal helpers deep
            // (`fill` -> `fillTokenForPY` -> `_checkSig_updMakingAndStatus` ->
            // `_checkSig` -> `isValidSignatureNow`), so we resolve it transitively
            // over internal callees within the contract, not just in `f` itself. ---
            if !verifies_order_signature(cx, f) {
                continue;
            }

            // --- anchor 2: it actually moves tokens (a real settlement, not a
            // pure view quote or a signature-only gate like `permit`). We accept a
            // transfer-shaped call in `f` *or* in a transitive internal callee,
            // since the fill often delegates the leg transfers to helpers
            // (`_transferOut` / `_transferToMakers`). ---
            if !moves_tokens(cx, f) {
                continue;
            }

            // --- the bug: an unreconciled split (a) or an unbounded residual (b),
            // each anchored on the maker/taker/fee fill vocabulary so a plain
            // swap/vote never qualifies. Report the more specific one we find. ---
            if let Some(span) = unreconciled_fee_split(f) {
                out.push(finish_at(cx, build_split(self, f), f.id, span));
            } else if let Some(span) = unbounded_residual_write(f) {
                out.push(finish_at(cx, build_residual(self, f), f.id, span));
            }
        }
        out
    }
}

// ============================================================ finding builders

fn build_split(det: &RfqFillAccountingDetector, f: &Function) -> sluice_findings::FindingBuilder {
    report!(det, Category::RfqFillAccounting,
        title = "Signed-order fill computes a making/taking/fee split without a conservation check",
        severity = Severity::High,
        confidence = 0.6,
        dimensions = [Dimension::Invariant, Dimension::ValueFlow],
        message = format!(
            "`{}` verifies a maker's signed order and then computes a `making`/`taking`/`fee` split \
             (an `actual… = gross ± fee` arithmetic) and transfers all three legs, but never asserts \
             the conservation identity that ties them together — there is no \
             `require(actualMaking + totalFee == gross)` (or `actualTaking == net + totalFee`). The \
             only bound on the path is the taker's slippage check, which does not constrain how the \
             fee relates to the maker/taker amounts. If the fee figure is wrong (or a rounding step \
             drops units), the legs no longer sum to the signed amount and the solver controlling the \
             taker side silently keeps the delta. This is the Pendle `LimitRouterBase.fillTokenForPY` \
             / `fillPYForToken` (`actualMaking = out.totalMaking - out.totalFee`) RFQ-fill-accounting \
             shape.",
            f.name
        ),
        recommendation =
            "After computing the legs, assert the settlement is zero-sum against the signed amounts: \
             `require(actualMaking + totalFee == out.totalMaking)` (token-for-PY) and \
             `require(actualTaking == out.totalTaking + totalFee)` (PY-for-token), so any fee/rounding \
             discrepancy reverts instead of accruing to the filler.",
    )
}

fn build_residual(det: &RfqFillAccountingDetector, f: &Function) -> sluice_findings::FindingBuilder {
    report!(det, Category::RfqFillAccounting,
        title = "Partial-fill residual incremented without a `filled <= signed amount` bound",
        severity = Severity::High,
        confidence = 0.55,
        dimensions = [Dimension::Invariant, Dimension::ValueFlow],
        message = format!(
            "`{}` verifies a maker's signed order and increments a partial-fill residual \
             (`filled`/`filledAmount += …`) but never bounds it against the signed cap — there is no \
             `require(filled <= order.makingAmount)` and no `min(…)` clamp on the consumed amount. A \
             taker can therefore fill more than the maker signed for, or replay the residual, charging \
             the maker beyond their committed amount. This is the RFQ partial-fill-residual accounting \
             shape.",
            f.name
        ),
        recommendation =
            "Clamp the consumed amount to the remaining signed amount (`x = min(x, remaining)`) and/or \
             assert `require(filled + x <= order.makingAmount)` before writing the residual, so a fill \
             can never exceed the maker's signed cap.",
    )
}

// ====================================================== anchor 1: order signing

/// Tokens that name an ECDSA / EIP-712 *signature verification* primitive. These
/// are matched against (lowercased, comment-stripped) function source and against
/// internal-callee names.
const SIG_VERIFY_TOKENS: &[&str] = &[
    "ecrecover",
    ".recover(",
    "isvalidsignaturenow",
    "isvalidsignature",
    "signaturechecker",
];

/// Internal-callee names that *are* a signature/order verifier (so we don't need
/// to descend into them textually).
fn is_sig_verify_callee(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "_checksig"
        || l == "checksig"
        || l == "verifyorder"
        || l == "verifysignature"
        || l == "checksignature"
        || l == "_verifyorder"
        || (l.contains("checksig"))
        || (l.contains("verify") && l.contains("sig"))
        || (l.contains("verify") && l.contains("order"))
}

/// Does `f` — directly or through a transitive internal callee within its
/// contract — reach an ECDSA / EIP-712 order-signature verification? We BFS over
/// `effects.internal_calls`, resolving callee names to functions of the same
/// contract (the common case for a `LimitRouterBase` helper chain), and check
/// each visited function's source for a verify primitive. A callee *named* like a
/// verifier short-circuits the search.
fn verifies_order_signature(cx: &AnalysisContext, f: &Function) -> bool {
    // Fast path: the verify primitive (or a verifier-named direct callee) is right
    // here.
    if source_has_sig_verify(cx, f) {
        return true;
    }
    if f.effects.internal_calls.iter().any(|n| is_sig_verify_callee(n)) {
        return true;
    }

    // Resolve internal callees by name within the same contract and BFS, bounded.
    let Some(contract) = cx.contract_of(f.id) else { return false };
    let by_name: rustc_hash::FxHashMap<&str, &Function> = cx
        .scir
        .functions_of(contract.id)
        .map(|g| (g.name.as_str(), g))
        .collect();

    let mut seen: FxHashSet<&str> = FxHashSet::default();
    seen.insert(f.name.as_str());
    let mut stack: Vec<&str> =
        f.effects.internal_calls.iter().map(String::as_str).collect();
    let mut steps = 0usize;
    while let Some(name) = stack.pop() {
        if !seen.insert(name) {
            continue;
        }
        steps += 1;
        if steps > 256 {
            break; // bound the walk; deep chains are not the target shape
        }
        if is_sig_verify_callee(name) {
            return true;
        }
        if let Some(g) = by_name.get(name) {
            if source_has_sig_verify(cx, g) {
                return true;
            }
            for c in &g.effects.internal_calls {
                if !seen.contains(c.as_str()) {
                    stack.push(c.as_str());
                }
            }
        }
    }
    false
}

/// Does the (comment-stripped, lowercased) source of `g` mention a signature
/// verify primitive?
fn source_has_sig_verify(cx: &AnalysisContext, g: &Function) -> bool {
    let src = cx.source_text(g.span);
    SIG_VERIFY_TOKENS.iter().any(|t| src.contains(t))
}

// ========================================================= anchor 2: moves value

/// Transfer-shaped method names (the leg-moving calls a settlement performs).
fn is_transfer_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    matches!(
        l.as_str(),
        "transfer"
            | "transferfrom"
            | "safetransfer"
            | "safetransferfrom"
            | "mint"
            | "burn"
            | "burnfrom"
            | "_transferout"
            | "_transferin"
            | "_transfertomakers"
            | "_transferfrommakers"
            | "_transfercollateral"
            | "_transfertobeneficiary"
    ) || l.starts_with("_transfer")
        || l.contains("transferto")
        || l.contains("transferfrom")
}

/// Does `f` move tokens — directly or via a transitive internal callee? A
/// settlement routinely delegates the leg transfers to helpers
/// (`_transferOut(SY, receiver, actualMaking)`), so we look at both `f`'s own
/// call sites / internal calls and one level of internal callees.
fn moves_tokens(cx: &AnalysisContext, f: &Function) -> bool {
    if fn_has_transfer_call(f) {
        return true;
    }
    let Some(contract) = cx.contract_of(f.id) else { return false };
    let by_name: rustc_hash::FxHashMap<&str, &Function> = cx
        .scir
        .functions_of(contract.id)
        .map(|g| (g.name.as_str(), g))
        .collect();
    f.effects.internal_calls.iter().any(|n| {
        is_transfer_name(n) || by_name.get(n.as_str()).is_some_and(|g| fn_has_transfer_call(g))
    })
}

/// A transfer-shaped call site or internal call in `f` itself.
fn fn_has_transfer_call(f: &Function) -> bool {
    if f
        .effects
        .call_sites
        .iter()
        .any(|c| c.func_name.as_deref().is_some_and(is_transfer_name))
    {
        return true;
    }
    f.effects.internal_calls.iter().any(|n| is_transfer_name(n))
}

// ============================================== bug (a): unreconciled fee split

/// A fee-named term (`fee`, `totalFee`, `netFee`, `feeAmount`, …) — the protocol
/// leg of the split.
fn mentions_fee(e: &Expr) -> bool {
    expr_mentions_named(e, |n| {
        let l = n.to_ascii_lowercase();
        l == "fee" || l.contains("fee")
    })
}

/// A maker/taker/gross/net amount term — the party legs of the split. We require
/// the *fill* vocabulary (`making`/`taking`/`gross`/`net`) rather than a bare
/// `amount`, so an ordinary `x - fee` outside a fill does not qualify.
fn mentions_amount_leg(e: &Expr) -> bool {
    expr_mentions_named(e, |n| {
        let l = n.to_ascii_lowercase();
        l.contains("making")
            || l.contains("taking")
            || l.contains("gross")
            || l == "net"
            || l.starts_with("net")
            || l.contains("totalmaking")
            || l.contains("totaltaking")
    })
}

/// Does `e` contain an identifier *or member name* for which `pred` holds? The
/// split operands are members (`out.totalFee`, `out.totalMaking`), so we inspect
/// both `Ident` and the trailing `member` of `Member` nodes.
fn expr_mentions_named(e: &Expr, mut pred: impl FnMut(&str) -> bool) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        match &sub.kind {
            ExprKind::Ident(n) => {
                if pred(n) {
                    found = true;
                }
            }
            ExprKind::Member { member, .. } => {
                if pred(member) {
                    found = true;
                }
            }
            _ => {}
        }
    });
    found
}

/// The fill's split site: an `Add`/`Sub` binary one operand of which mentions a
/// *fee* leg and the other a *making/taking/gross/net* leg
/// (`out.totalMaking - out.totalFee`, `out.totalTaking + out.totalFee`). Returns
/// the span of the first such site if there is **no conservation `require`** in
/// the body, otherwise `None` (suppressed — the split is reconciled).
fn unreconciled_fee_split(f: &Function) -> Option<sluice_ir::Span> {
    let mut split: Option<sluice_ir::Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if split.is_some() {
                return;
            }
            if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
                if matches!(op, BinOp::Add | BinOp::Sub) {
                    let fee_l = mentions_fee(lhs);
                    let fee_r = mentions_fee(rhs);
                    let leg_l = mentions_amount_leg(lhs);
                    let leg_r = mentions_amount_leg(rhs);
                    // One side is the fee leg, the other a party amount leg.
                    if (fee_l && leg_r) || (fee_r && leg_l) {
                        split = Some(e.span);
                    }
                }
            }
        });
        if split.is_some() {
            break;
        }
    }
    let span = split?;
    if has_conservation_require(f) {
        return None;
    }
    Some(span)
}

/// A conservation assertion: a `require`/`assert` whose argument is an `==`/`!=`
/// comparison that simultaneously mentions a *fee* term and a *making/taking/
/// gross/net* term (`actualMaking + totalFee == out.totalMaking`). Any such check
/// means the split is reconciled to the signed amounts -> suppress.
fn has_conservation_require(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            if !matches!(
                c.kind,
                CallKind::Builtin(Builtin::Require) | CallKind::Builtin(Builtin::Assert)
            ) {
                return;
            }
            for a in &c.args {
                if expr_is_conservation_eq(a) {
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

/// Is `e` (an assertion argument) an equality/inequality comparison whose two
/// sides *together* mention both a fee leg and an amount leg — the conservation
/// identity `net + fee == gross`? We search the whole comparison subtree for a
/// fee mention and an amount-leg mention, so `a + fee == gross` and
/// `gross == net + fee` both qualify.
fn expr_is_conservation_eq(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Binary { op, lhs, rhs } = &sub.kind {
            if matches!(op, BinOp::Eq | BinOp::Ne) {
                let fee = mentions_fee(lhs) || mentions_fee(rhs);
                let leg = mentions_amount_leg(lhs) || mentions_amount_leg(rhs);
                if fee && leg {
                    found = true;
                }
            }
        }
    });
    found
}

// ========================================== bug (b): unbounded partial residual

/// A residual write: `filled[...] += x`, `status.filledAmount = … + x`, i.e. an
/// `AssignOp::Add` (or `Assign` of an `Add`) whose target names a *filled*
/// residual. Returns the span if there is **no `filled <= amount` bound and no
/// `min(` clamp** in the body, otherwise `None`.
fn unbounded_residual_write(f: &Function) -> Option<sluice_ir::Span> {
    let mut hit: Option<sluice_ir::Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            if let ExprKind::Assign { op, target, value } = &e.kind {
                let target_is_filled = mentions_filled(target);
                if !target_is_filled {
                    return;
                }
                // `filled += x` is an increment; `filled = old + x` (Assign of an
                // Add that re-mentions a filled term) is the desugared form.
                let is_increment = matches!(op, AssignOp::Add)
                    || (matches!(op, AssignOp::Assign) && value_is_self_add(value));
                if is_increment {
                    hit = Some(e.span);
                }
            }
        });
        if hit.is_some() {
            break;
        }
    }
    let span = hit?;
    if residual_is_bounded(f) {
        return None;
    }
    Some(span)
}

/// Target names a partial-fill residual (`filled`, `filledAmount`, `filledMaker…`).
fn mentions_filled(e: &Expr) -> bool {
    expr_mentions_named(e, |n| {
        let l = n.to_ascii_lowercase();
        l == "filled" || l.starts_with("filled")
    })
}

/// Is `value` an `Add` that itself re-mentions a filled term (the `filled = filled
/// + x` desugaring, incl. a struct-literal field `filledAmount: filled + x`)?
fn value_is_self_add(value: &Expr) -> bool {
    let mut found = false;
    value.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Binary { op: BinOp::Add, lhs, rhs } = &sub.kind {
            if mentions_filled(lhs) || mentions_filled(rhs) {
                found = true;
            }
        }
    });
    found
}

/// The residual is reconciled to the signed cap when the body either (1) bounds
/// it with an ordering comparison touching a *filled*/*remaining*/*making* term
/// (`require(filled <= order.makingAmount)`, `remaining - x`), or (2) clamps the
/// consumed amount with a `min(`. Either means the residual cannot exceed the
/// signed amount -> suppress.
fn residual_is_bounded(f: &Function) -> bool {
    // (2) a `min(` clamp anywhere (`PMath.min(makingAmount, remaining)`).
    let has_min = f.effects.call_sites.iter().any(|c| is_min_name(c.func_name.as_deref()))
        || f.effects.internal_calls.iter().any(|n| is_min_name(Some(n.as_str())))
        || body_has_min_call(f);
    if has_min {
        return true;
    }
    // (1) an ordering comparison (`<`/`<=`/`>`/`>=`) over a filled/remaining/making
    // term, or any subtraction of a remaining/making term (the `remaining - net`
    // reconciliation). Both indicate the residual is held within the signed cap.
    let mut bounded = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if bounded {
                return;
            }
            match &e.kind {
                ExprKind::Binary { op, lhs, rhs } if op.is_ordering() => {
                    if mentions_residual_bound_term(lhs) || mentions_residual_bound_term(rhs) {
                        bounded = true;
                    }
                }
                ExprKind::Binary { op: BinOp::Sub, lhs, rhs } => {
                    // `remaining - net` / `makingAmount - filled` reconciliation.
                    if mentions_remaining_or_making(lhs) || mentions_remaining_or_making(rhs) {
                        bounded = true;
                    }
                }
                _ => {}
            }
        });
        if bounded {
            break;
        }
    }
    bounded
}

fn is_min_name(name: Option<&str>) -> bool {
    name.is_some_and(|n| {
        let l = n.to_ascii_lowercase();
        l == "min" || l.ends_with(".min") || l == "_min"
    })
}

fn body_has_min_call(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if is_min_name(c.func_name.as_deref()) {
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

/// A term that, when compared, bounds the residual: a filled/remaining/making
/// amount.
fn mentions_residual_bound_term(e: &Expr) -> bool {
    expr_mentions_named(e, |n| {
        let l = n.to_ascii_lowercase();
        l.starts_with("filled")
            || l.contains("remaining")
            || l.contains("making")
            || l.contains("makeramount")
    })
}

/// A remaining/making amount term (for the subtraction-reconciliation form).
fn mentions_remaining_or_making(e: &Expr) -> bool {
    expr_mentions_named(e, |n| {
        let l = n.to_ascii_lowercase();
        l.contains("remaining") || l.contains("making") || l.contains("makeramount")
    })
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "rfq-fill-accounting")
    }

    // Pendle LimitRouterBase shape (case a): a signed-order fill verifies each
    // maker signature (transitively, via `_checkSig` -> `isValidSignatureNow`),
    // then computes `(actualMaking, actualTaking, totalFee) = (gross - fee, ...,
    // fee)` and transfers all three legs. The only require is the taker slippage
    // bound `actualTaking <= maxTaking` — NO conservation check. Fires.
    const VULN_SPLIT: &str = r#"
        interface IERC20 { function transfer(address to, uint256 a) external; }
        library SignatureChecker {
            function isValidSignatureNow(address s, bytes32 h, bytes memory sig) internal view returns (bool) { return true; }
        }
        contract LimitRouter {
            mapping(bytes32 => uint256) internal _status;
            IERC20 public sy;
            address public feeRecipient;
            struct Results { uint256 totalMaking; uint256 totalTaking; uint256 totalFee; }

            function _checkSig(bytes32 orderHash, bytes memory signature, address maker) internal view returns (uint256) {
                require(SignatureChecker.isValidSignatureNow(maker, orderHash, signature), "bad sig");
                return 1;
            }

            function _transferOut(address to, uint256 amt) internal {
                sy.transfer(to, amt);
            }

            function fill(bytes32 orderHash, bytes memory signature, address maker, address receiver, uint256 maxTaking, Results memory out) external {
                _checkSig(orderHash, signature, maker);
                uint256 actualMaking;
                uint256 actualTaking;
                uint256 totalFee;
                (actualMaking, actualTaking, totalFee) = (out.totalMaking - out.totalFee, out.totalTaking, out.totalFee);
                require(actualTaking <= maxTaking, "slippage");
                _transferOut(receiver, actualMaking);
                _transferOut(feeRecipient, totalFee);
            }
        }
    "#;

    // Same fill, WITH the conservation check: `require(actualMaking + totalFee ==
    // out.totalMaking)`. The split is reconciled to the signed amount -> suppressed.
    const SAFE_RECONCILED: &str = r#"
        interface IERC20 { function transfer(address to, uint256 a) external; }
        library SignatureChecker {
            function isValidSignatureNow(address s, bytes32 h, bytes memory sig) internal view returns (bool) { return true; }
        }
        contract LimitRouter {
            IERC20 public sy;
            address public feeRecipient;
            struct Results { uint256 totalMaking; uint256 totalTaking; uint256 totalFee; }

            function _checkSig(bytes32 orderHash, bytes memory signature, address maker) internal view returns (uint256) {
                require(SignatureChecker.isValidSignatureNow(maker, orderHash, signature), "bad sig");
                return 1;
            }
            function _transferOut(address to, uint256 amt) internal { sy.transfer(to, amt); }

            function fill(bytes32 orderHash, bytes memory signature, address maker, address receiver, uint256 maxTaking, Results memory out) external {
                _checkSig(orderHash, signature, maker);
                uint256 actualMaking;
                uint256 actualTaking;
                uint256 totalFee;
                (actualMaking, actualTaking, totalFee) = (out.totalMaking - out.totalFee, out.totalTaking, out.totalFee);
                require(actualMaking + totalFee == out.totalMaking, "conservation");
                require(actualTaking <= maxTaking, "slippage");
                _transferOut(receiver, actualMaking);
                _transferOut(feeRecipient, totalFee);
            }
        }
    "#;

    // Partial-fill residual (case b): a signed order's `filled` is incremented by
    // a caller-supplied fill amount with no `filled <= makingAmount` bound and no
    // min() clamp -> fires.
    const VULN_RESIDUAL: &str = r#"
        interface IERC20 { function safeTransferFrom(address f, address t, uint256 a) external; }
        contract Rfq {
            mapping(bytes32 => uint256) public filled;
            IERC20 public token;
            function fillOrder(bytes32 orderHash, address maker, bytes memory signature, uint256 fillAmount) external {
                require(ecrecover(orderHash, 27, bytes32(0), bytes32(0)) == maker, "bad sig");
                filled[orderHash] += fillAmount;
                token.safeTransferFrom(maker, msg.sender, fillAmount);
            }
        }
    "#;

    // Same residual but bounded: `require(filled[orderHash] <= order.makingAmount)`
    // after the increment -> the residual is reconciled -> suppressed.
    const SAFE_RESIDUAL_BOUNDED: &str = r#"
        interface IERC20 { function safeTransferFrom(address f, address t, uint256 a) external; }
        contract Rfq {
            mapping(bytes32 => uint256) public filled;
            IERC20 public token;
            function fillOrder(bytes32 orderHash, address maker, uint256 makingAmount, bytes memory signature, uint256 fillAmount) external {
                require(ecrecover(orderHash, 27, bytes32(0), bytes32(0)) == maker, "bad sig");
                filled[orderHash] += fillAmount;
                require(filled[orderHash] <= makingAmount, "overfill");
                token.safeTransferFrom(maker, msg.sender, fillAmount);
            }
        }
    "#;

    // Pendle `_checkSig_updMakingAndStatus` reconciliation shape: the consumed
    // amount is clamped with `min(makingAmount, remaining)` before the residual is
    // written (`filled = filledMakerAmount + netMaking`). The `min(` clamp means
    // the residual can never exceed the signed cap -> suppressed even though there
    // is no explicit `require(filled <= amount)`.
    const SAFE_RESIDUAL_MIN_CLAMP: &str = r#"
        interface IERC20 { function safeTransferFrom(address f, address t, uint256 a) external; }
        library PMath { function min(uint256 a, uint256 b) internal pure returns (uint256) { return a < b ? a : b; } }
        contract Rfq {
            using PMath for uint256;
            mapping(bytes32 => uint256) public filledAmount;
            IERC20 public token;
            function fillOrder(bytes32 orderHash, address maker, uint256 makingAmount, uint256 remaining, bytes memory signature, uint256 want) external {
                require(ecrecover(orderHash, 27, bytes32(0), bytes32(0)) == maker, "bad sig");
                uint256 netMaking = PMath.min(want, remaining);
                filledAmount[orderHash] = filledAmount[orderHash] + netMaking;
                token.safeTransferFrom(maker, msg.sender, netMaking);
            }
        }
    "#;

    // A signature-verifying function that is NOT a fill: a vote-by-sig. It
    // verifies an ECDSA signature but has no maker/taker/fee split and moves no
    // tokens -> must stay silent (the fill-vocabulary + transfer anchors).
    const SAFE_VOTE_BY_SIG: &str = r#"
        contract Governor {
            mapping(address => uint256) public votes;
            function castVoteBySig(uint256 proposalId, bool support, uint8 v, bytes32 r, bytes32 s) external {
                bytes32 digest = keccak256(abi.encode(proposalId, support));
                address signer = ecrecover(digest, v, r, s);
                votes[signer] += 1;
            }
        }
    "#;

    // An ordinary swap that subtracts a fee from an amount, but verifies NO
    // signature -> the order-signing anchor keeps it quiet.
    const SAFE_SWAP_NO_SIG: &str = r#"
        interface IERC20 { function transfer(address to, uint256 a) external; }
        contract Amm {
            IERC20 public token;
            address public feeTo;
            function swap(uint256 makingAmount, uint256 fee) external {
                uint256 net = makingAmount - fee;
                token.transfer(msg.sender, net);
                token.transfer(feeTo, fee);
            }
        }
    "#;

    #[test]
    fn fires_on_unreconciled_split() {
        assert!(fires(VULN_SPLIT), "{:#?}", run(VULN_SPLIT));
    }

    #[test]
    fn silent_when_split_reconciled() {
        assert!(!fires(SAFE_RECONCILED), "{:#?}", run(SAFE_RECONCILED));
    }

    #[test]
    fn fires_on_unbounded_residual() {
        assert!(fires(VULN_RESIDUAL), "{:#?}", run(VULN_RESIDUAL));
    }

    #[test]
    fn silent_when_residual_bounded() {
        assert!(!fires(SAFE_RESIDUAL_BOUNDED), "{:#?}", run(SAFE_RESIDUAL_BOUNDED));
    }

    #[test]
    fn silent_when_residual_min_clamped() {
        assert!(!fires(SAFE_RESIDUAL_MIN_CLAMP), "{:#?}", run(SAFE_RESIDUAL_MIN_CLAMP));
    }

    #[test]
    fn silent_on_vote_by_sig() {
        assert!(!fires(SAFE_VOTE_BY_SIG), "{:#?}", run(SAFE_VOTE_BY_SIG));
    }

    #[test]
    fn silent_on_swap_without_signature() {
        assert!(!fires(SAFE_SWAP_NO_SIG), "{:#?}", run(SAFE_SWAP_NO_SIG));
    }
}
