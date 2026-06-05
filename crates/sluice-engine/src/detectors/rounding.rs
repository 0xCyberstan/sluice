//! Rounding-direction hazard: a share/asset conversion in a mint/deposit or
//! withdraw/redeem path computes an amount with integer division but pins no
//! explicit rounding mode. Solidity integer division truncates toward zero, so a
//! conversion that should round *against* the user (down on mint, up on
//! withdraw) instead rounds in the user's favor — bleeding the protocol a few
//! wei per call until the buffer is gone. The ERC-4626 "rounding must favor the
//! vault" rule; this is the class behind a long tail of vault-accounting reports.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function};

pub struct RoundingDetector;

impl Detector for RoundingDetector {
    fn id(&self) -> &'static str {
        "rounding-direction"
    }
    fn category(&self) -> Category {
        Category::RoundingDirection
    }
    fn description(&self) -> &'static str {
        "Share/asset conversion (mint/deposit/withdraw) divides with no explicit rounding mode"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }

            // ---- Arm 1: conversion entry points (the original detector) ----
            // mint/deposit/issue (assets→shares) and withdraw/redeem/burn
            // (shares→assets). Requires the function be externally reachable and
            // state-mutating, contain an `a * b / c` mul-then-div, and pin no
            // rounding mode. Other arithmetic is out of scope here (major FP source).
            if f.is_externally_reachable()
                && f.is_state_mutating()
                && is_conversion_name(&f.name)
            {
                if let Some(span) = find_mul_div(f) {
                    if !uses_explicit_rounding(cx, f) {
                        out.push(self.conversion_finding(cx, f, span));
                        continue;
                    }
                }
            }

            // ---- Arm 2: solvency/collateral-gated price division ----
            // A value computed by integer division (`a * b / c` or `a / c`) that
            // is then used to gate a collateral/solvency comparison. Truncating it
            // the wrong way makes the invariant fail and reverts *legitimate*
            // actions (Frankencoin clone price `_mint * 1e18 / _coll` feeding
            // `collateralReserve * price < minted * 1e18`). Gated on the function
            // mentioning collateral/solvency vocabulary so we never flag generic
            // arithmetic.
            if let Some(span) = find_solvency_gated_division(cx, f) {
                if !uses_explicit_rounding(cx, f) {
                    out.push(self.solvency_finding(cx, f, span));
                    continue;
                }
            }

            // ---- Arm 4: caller-supplied price gated by a collateral check ----
            // A state-mutating entry point takes a caller-supplied `price`
            // parameter and passes it *unrounded* into a collateral-check helper
            // (`checkCollateral(collateralBalance(), newPrice)`) whose invariant is
            // `collateralReserve * price < minted * ONE_DEC18 => revert`. The
            // minimum acceptable price is `minted * ONE_DEC18 / collateral`, which
            // must be rounded *up*; a caller that computes it off-chain with the
            // ordinary truncating division supplies a price one wei too low and the
            // legitimate adjustment reverts (Frankencoin `adjustPrice`, M-09). Unlike
            // Arm 2, the division is off-chain — the on-chain hazard is the bare
            // comparison gating a parameter, so this arm anchors on the structural
            // shape rather than an in-body `/`.
            if f.is_externally_reachable() && f.is_state_mutating() {
                if let Some(span) = find_unrounded_price_collateral_gate(cx, f) {
                    if !uses_explicit_rounding(cx, f) {
                        out.push(self.price_gate_finding(cx, f, span));
                        continue;
                    }
                }
            }

            // ---- Arm 5: floored offset subtracted from a user payout ----
            // In a withdraw/decrease/claim/redeem path, a deduction term is
            // computed with a truncating division (`a * b / c` or `a / c`) and
            // then *subtracted* from a user-claimable/payout quantity. Because the
            // subtrahend is floored, the user receives MORE than the exact value —
            // the floor favors the claimer, the opposite of the protocol-favoring
            // direction. Salty `_decreaseUserShare` floors `virtualRewardsToRemove`
            // (a virtual-rewards offset) and then pays out
            // `rewardsForAmount - virtualRewardsToRemove`, so withdrawing in many
            // small increments lets a user over-claim (M-01). Unlike Arm 1 this
            // fires on internal helpers too (the offset is rarely in the external
            // entry point) but is gated on the subtracted-offset structure so a
            // floor that is *added* to a payout (favoring the protocol) or one that
            // is explicitly rounded does not trip it.
            if is_payout_path_name(&f.name) && f.is_state_mutating() {
                if let Some(span) = find_floored_offset_subtracted_from_payout(f) {
                    if !uses_explicit_rounding(cx, f) {
                        out.push(self.subtracted_offset_finding(cx, f, span));
                        continue;
                    }
                }
            }

            // ---- Arm 3: sqrt-based reserve recovery ----
            // A reserve/invariant value recovered through an integer square root
            // (`LibMath.sqrt(..)`, `x.sqrt()`) or its inverse `s ** 2 / b`. Integer
            // `sqrt` floors, so a reserve recovered this way can round in favor of
            // the swapper rather than the pool (Basin `calcReserve` /
            // `calcReserveAtRatioSwap`). The div-rounding helpers that Arm-2 honors
            // do NOT control the *sqrt* direction, so this arm checks for
            // sqrt-specific rounding control only.
            if is_reserve_calc_name(&f.name) {
                if let Some(span) = find_unrounded_sqrt_reserve(f) {
                    if !pins_sqrt_rounding(cx, f) {
                        out.push(self.sqrt_finding(cx, f, span));
                        continue;
                    }
                }
            }
        }
        out
    }
}

impl RoundingDetector {
    fn conversion_finding(
        &self,
        cx: &AnalysisContext,
        f: &Function,
        span: sluice_ir::Span,
    ) -> Finding {
        let b = FindingBuilder::new(self.id(), Category::RoundingDirection)
            .title("Share/asset conversion with unspecified rounding direction")
            .severity(Severity::Low)
            .confidence(0.4)
            .dimension(Dimension::ValueFlow)
            .message(format!(
                "`{}` converts between assets and shares with an integer `a * b / c` division but \
                 pins no explicit rounding mode. Solidity division truncates toward zero, so the \
                 conversion may round in the user's favor (e.g. minting too many shares or paying \
                 out too many assets) instead of the protocol's — draining the vault a few wei per \
                 call. ERC-4626 requires rounding to favor the vault.",
                f.name
            ))
            .recommendation(
                "Pin the rounding direction explicitly: round down on deposit/mint share issuance and \
                 round up on withdraw/redeem asset payout — e.g. OpenZeppelin `Math.mulDiv(a, b, c, \
                 Rounding.Floor/Ceil)` or a `mulDivUp`/`mulDivDown` helper.",
            );
        cx.finish(b, f.id, span)
    }

    fn solvency_finding(&self, cx: &AnalysisContext, f: &Function, span: sluice_ir::Span) -> Finding {
        let b = FindingBuilder::new(self.id(), Category::RoundingDirection)
            .title("Solvency-gating value computed by truncating division (rounds against caller)")
            .severity(Severity::Medium)
            .confidence(0.5)
            .dimension(Dimension::ValueFlow)
            .message(format!(
                "`{}` derives a price/collateral quantity with an integer division that pins no \
                 rounding mode, and that quantity then gates a collateral/solvency comparison. \
                 Solidity division truncates toward zero, so the rounded-down value can fail an \
                 invariant such as `collateral * price >= debt` and revert an action that is \
                 actually well-collateralized — e.g. a clone price `mint * 1e18 / collateral` that \
                 should round *up* to keep the collateral check satisfiable.",
                f.name
            ))
            .recommendation(
                "Round the solvency-gating quotient in the direction that keeps the invariant \
                 satisfiable for legitimate callers — typically round the price/required-collateral \
                 *up* (e.g. `Math.mulDiv(a, b, c, Rounding.Ceil)` or a `ceilDiv`/`roundUpDiv` helper) \
                 rather than relying on truncation.",
            );
        cx.finish(b, f.id, span)
    }

    fn sqrt_finding(&self, cx: &AnalysisContext, f: &Function, span: sluice_ir::Span) -> Finding {
        let b = FindingBuilder::new(self.id(), Category::RoundingDirection)
            .title("Reserve recovered via integer sqrt with unspecified rounding direction")
            .severity(Severity::Medium)
            .confidence(0.5)
            .dimension(Dimension::ValueFlow)
            .message(format!(
                "`{}` recovers a reserve/invariant quantity through an integer square root (or its \
                 `x ** 2` inverse) with no explicit rounding-direction control. Integer `sqrt` floors, \
                 so the recovered reserve can round in favor of the swapper rather than the pool: the \
                 LP-supply side floors `sqrt(b0*b1)` while the reserve side computes `s^2 / b`, and the \
                 two rounding directions must be reconciled so the pool never gives out more than the \
                 invariant allows.",
                f.name
            ))
            .recommendation(
                "Make the sqrt-based reserve recovery round in the pool's favor: round the recovered \
                 reserve *up* (and the forward LP-supply *down*) so the constant-product invariant can \
                 never be satisfied by a value that over-credits the swapper — e.g. add 1 to the floored \
                 sqrt when it is not exact, or use a ceil variant on the reserve side.",
            );
        cx.finish(b, f.id, span)
    }

    fn price_gate_finding(&self, cx: &AnalysisContext, f: &Function, span: sluice_ir::Span) -> Finding {
        let b = FindingBuilder::new(self.id(), Category::RoundingDirection)
            .title("Caller-supplied price gated by a truncating collateral check (legitimate adjustment reverts)")
            .severity(Severity::Medium)
            .confidence(0.5)
            .dimension(Dimension::ValueFlow)
            .message(format!(
                "`{}` passes a caller-supplied price parameter, unrounded, into a collateral check of \
                 the form `collateralReserve * price >= minted * ONE_DEC18` (revert otherwise). The \
                 minimum price that satisfies the invariant is `minted * ONE_DEC18 / collateral`, which \
                 must be rounded *up*; a caller computing it off-chain with ordinary truncating division \
                 supplies a value one wei too low, so the collateral check fails and a legitimate, \
                 well-collateralized adjustment reverts.",
                f.name
            ))
            .recommendation(
                "Do not require callers to hit an exact rounded-up price. Either compute the minimum \
                 acceptable price on-chain with a ceil division (round the required price *up*) before \
                 comparing, or relax the collateral check to tolerate the truncation (e.g. compare \
                 against `minted * ONE_DEC18` with a >= that accounts for the rounding direction).",
            );
        cx.finish(b, f.id, span)
    }

    fn subtracted_offset_finding(&self, cx: &AnalysisContext, f: &Function, span: sluice_ir::Span) -> Finding {
        let b = FindingBuilder::new(self.id(), Category::RoundingDirection)
            .title("Floored deduction subtracted from a user payout (rounds in the claimer's favor)")
            .severity(Severity::Medium)
            .confidence(0.5)
            .dimension(Dimension::ValueFlow)
            .message(format!(
                "`{}` is a withdraw/decrease/claim path that computes a deduction term with a \
                 truncating integer division (`a * b / c`) and then *subtracts* it from a \
                 user-claimable/payout quantity. Solidity division truncates toward zero, so the \
                 floored subtrahend is too small and the resulting payout is too large — the rounding \
                 favors the claimer instead of the protocol. By withdrawing/claiming in many small \
                 increments a user can repeatedly capture the per-call floor and over-claim (e.g. a \
                 virtual-rewards offset `virtualRewards * amount / userShare` floored and then \
                 subtracted from the claimable rewards).",
                f.name
            ))
            .recommendation(
                "Round a subtracted deduction/offset term *up* (against the claimer) so the payout can \
                 never exceed the exact value — e.g. `Math.mulDiv(a, b, c, Rounding.Ceil)` or a \
                 `mulDivUp`/`ceilDiv` helper for the offset that is later subtracted, rather than the \
                 default truncating division.",
            );
        cx.finish(b, f.id, span)
    }
}

/// A conversion entry point: assets→shares (`mint`/`deposit`/`issue`) or
/// shares→assets (`withdraw`/`redeem`/`burn`).
fn is_conversion_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    ["mint", "deposit", "issue", "withdraw", "redeem", "burn"]
        .iter()
        .any(|k| l.contains(k))
}

/// Detect a proportional conversion: an `a * b / c` (a `Mul` whose operand is a
/// `Div`, in either order) or a `mulDiv`-family call. Returns the span of the
/// offending expression. This is the inverse of the vault detector's
/// divide-before-multiply check (which looks for `(a / b) * c`); here we want
/// multiply-then-divide, the canonical share/asset formula.
fn find_mul_div(f: &Function) -> Option<sluice_ir::Span> {
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            match &e.kind {
                // `a * b / c` parses as `Div(Mul(a, b), c)`, and `c * (a / b)`
                // (or `(a / b) * c`) parses as a `Mul` with a `Div` operand. Both
                // are integer-division conversions; flag either shape.
                ExprKind::Binary { op: BinOp::Div, lhs, .. } => {
                    if contains_mul(lhs) {
                        found = Some(e.span);
                    }
                }
                ExprKind::Binary { op: BinOp::Mul, lhs, rhs } => {
                    if is_div(lhs) || is_div(rhs) {
                        found = Some(e.span);
                    }
                }
                // `mulDiv(a, b, c)` / `Math.mulDiv(...)` helper call.
                ExprKind::Call(c) => {
                    if c
                        .func_name
                        .as_deref()
                        .map(|n| n.eq_ignore_ascii_case("muldiv"))
                        .unwrap_or(false)
                    {
                        found = Some(e.span);
                    }
                }
                _ => {}
            }
        });
    }
    found
}

fn is_div(e: &Expr) -> bool {
    matches!(e.kind, ExprKind::Binary { op: BinOp::Div, .. })
}

/// True if `e` is a `Mul`, or transitively contains one (e.g. `(a * b) + d`).
fn contains_mul(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |n| {
        if let ExprKind::Binary { op: BinOp::Mul, .. } = &n.kind {
            found = true;
        }
    });
    found
}

// ---------------------------------------------------------------------------
// Arm 2: solvency/collateral-gated price division
// ---------------------------------------------------------------------------

/// Find an integer division whose result gates a collateral/solvency check.
///
/// Conservative gating, in order:
///   1. the function (or its source) must mention collateral/solvency vocabulary
///      *and* contain a relational comparison that mentions that vocabulary — the
///      `collateral * price >= debt` invariant shape;
///   2. there must be a plain integer division (`a * b / c` or `a / c`) outside a
///      `mulDiv` helper;
///   3. the division must plausibly feed the gated quantity (a `price`-like name
///      or an assignment to a state variable that the comparison reads).
///
/// Returns the span of the offending division. Restricted to functions that read
/// or write a `price`-like state variable so we never flag generic ratio math.
fn find_solvency_gated_division(cx: &AnalysisContext, f: &Function) -> Option<sluice_ir::Span> {
    // Whole-function source (comment-stripped, lowercased) for the cheap vocab gate.
    let src = cx.source_text(f.span);
    if !mentions_solvency_vocab(&src) {
        return None;
    }
    // Require an actual relational comparison touching the vocabulary — the
    // invariant check. Without it this is just arithmetic, not a gate.
    if !has_solvency_comparison(f) {
        return None;
    }
    // Find a bare integer division that assigns into / produces a price-like value.
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            // Assignment whose value is (or contains) a bare division: the canonical
            // `price = mint * 1e18 / coll;` shape. Prefer this so the reported span
            // is the offending statement and so we know the quotient is *kept*.
            if let ExprKind::Assign { target, value, .. } = &e.kind {
                if target_is_price_like(target) {
                    if let Some(sp) = first_bare_div_span(value) {
                        found = Some(sp);
                    }
                }
            }
        });
    }
    found
}

/// Vocabulary that marks a function as part of a collateral/solvency/liquidation
/// path (as opposed to generic arithmetic). Textual, over the comment-stripped,
/// lowercased function source.
fn mentions_solvency_vocab(src: &str) -> bool {
    // `price` alone is too broad; require it to co-occur with a collateralization
    // concept, or require an explicit collateral/solvency term.
    let has_collateral = src.contains("collateral");
    let has_solvency = src.contains("solven") || src.contains("undercollat") || src.contains("liqui");
    let has_debt = src.contains("minted") || src.contains("debt") || src.contains("borrow");
    let has_price = src.contains("price");
    has_collateral || has_solvency || (has_price && has_debt)
}

/// True if the function body contains a relational comparison (`<`, `>`, `<=`,
/// `>=`) whose source text mentions collateral/solvency vocabulary — the
/// `collateral * price >= debt` invariant shape that the division feeds.
fn has_solvency_comparison(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
                if op.is_ordering() {
                    // Cheap structural vocab check on the two operands.
                    let mut hit = false;
                    let mut probe = |n: &Expr| {
                        if let Some(name) = n.simple_name() {
                            let l = name.to_ascii_lowercase();
                            if l.contains("collateral")
                                || l.contains("minted")
                                || l.contains("debt")
                                || l.contains("price")
                                || l.contains("reserve")
                            {
                                hit = true;
                            }
                        }
                    };
                    lhs.visit(&mut |n| probe(n));
                    rhs.visit(&mut |n| probe(n));
                    if hit {
                        found = true;
                    }
                }
            }
        });
    }
    found
}

/// True if an assignment target names the liquidation/collateral *price* that a
/// solvency check gates on. Deliberately narrow: only `price`-like names, not
/// generic `rate`/`ratio` (which match unrelated interest-rate config scaling and
/// are pure FP noise). The collateral invariant this arm targets is
/// `collateral * price >= debt`, so the gated quantity is a price.
fn target_is_price_like(target: &Expr) -> bool {
    target
        .simple_name()
        .map(|n| n.to_ascii_lowercase().contains("price"))
        .unwrap_or(false)
}

/// Span of the first *bare* integer division (`a / b`, not a `mulDiv` helper)
/// found in `e`, if any. Used to point at the truncating quotient.
fn first_bare_div_span(e: &Expr) -> Option<sluice_ir::Span> {
    let mut found = None;
    e.visit(&mut |n| {
        if found.is_some() {
            return;
        }
        if let ExprKind::Binary { op: BinOp::Div, .. } = &n.kind {
            found = Some(n.span);
        }
    });
    found
}

// ---------------------------------------------------------------------------
// Arm 4: caller-supplied price gated by a collateral check
// ---------------------------------------------------------------------------

/// Find a caller-supplied `price` parameter that is passed, unrounded, into a
/// collateral-check helper whose invariant is `collateral * price >= minted * X`.
///
/// Conservative gating, all required:
///   1. the function declares a parameter whose name contains `price`;
///   2. the body calls a collateral-check function (callee name contains
///      `collateral`, e.g. `checkCollateral`) passing that price parameter as a
///      direct simple-name argument (so the caller-controlled price reaches the
///      check verbatim, not via an on-chain ceil);
///   3. the enclosing contract actually contains the `collateral * price < minted`
///      revert invariant (the `coll * price` product compared against a
///      `minted`/`debt` product), so we only flag where the truncation can bite.
///
/// Returns the span of the gating call. This is the M-09 `adjustPrice` shape; the
/// truncating division is performed off-chain by the caller, so unlike Arm 2 there
/// is no in-body `/` to anchor on — the call passing an unrounded price into the
/// product-comparison invariant is the signal.
fn find_unrounded_price_collateral_gate(
    cx: &AnalysisContext,
    f: &Function,
) -> Option<sluice_ir::Span> {
    // (1) a caller-supplied price parameter.
    let price_param = f.params.iter().find_map(|p| {
        p.name
            .as_deref()
            .filter(|n| n.to_ascii_lowercase().contains("price"))
            .map(|n| n.to_ascii_lowercase())
    })?;

    // (3) the contract must hold the `collateral * price < minted * X` invariant.
    let contract = cx.contract_of(f.id)?;
    if !contract_has_collateral_product_invariant(cx, contract) {
        return None;
    }

    // (2) a collateral-check call that receives the price parameter directly.
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                let is_coll_check = c
                    .func_name
                    .as_deref()
                    .map(|n| {
                        let l = n.to_ascii_lowercase();
                        l.contains("collateral") || l.contains("solven")
                    })
                    .unwrap_or(false);
                if is_coll_check
                    && c.args.iter().any(|a| {
                        a.simple_name()
                            .map(|n| n.to_ascii_lowercase() == price_param)
                            .unwrap_or(false)
                    })
                {
                    found = Some(e.span);
                }
            }
        });
    }
    found
}

/// True if the contract source contains the `collateral * price < minted * X`
/// solvency invariant: a `<`/`<=` ordering comparison whose source text mentions a
/// collateral product on one side and a `minted`/`debt` product on the other. The
/// comparison usually lives in a `checkCollateral` helper (the callee), so we scan
/// every function of the contract rather than just the gated entry point.
fn contract_has_collateral_product_invariant(cx: &AnalysisContext, contract: &sluice_ir::Contract) -> bool {
    let src = cx.source_text(contract.span);
    // Cheap textual co-occurrence prefilter: the product invariant references
    // collateral, a price, and a minted/debt quantity together.
    src.contains("collateral")
        && src.contains("price")
        && (src.contains("minted") || src.contains("debt") || src.contains("borrow"))
}

// ---------------------------------------------------------------------------
// Arm 5: floored offset subtracted from a user payout
// ---------------------------------------------------------------------------

/// A withdraw/decrease/claim/redeem/unstake path: the kind of function where a
/// deduction subtracted from a payout decides how much a user takes out. Kept to
/// payout-reducing verbs (not `mint`/`deposit`, where a floored *added* term
/// favors the protocol) so the arm only considers the favors-the-claimer shape.
fn is_payout_path_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "decrease", "withdraw", "redeem", "claim", "unstake", "unbond", "exit",
        "harvest", "payout", "cashout",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// Names that denote a user-claimable / payout quantity — the thing a floored,
/// subtracted offset bleeds into. Used to require the subtraction result actually
/// lands in a payout (so plain `a - b` bookkeeping does not trip the arm).
fn is_payout_quantity_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("claimable")
        || l.contains("reward")
        || l.contains("payout")
        || l.contains("payable")
        || l.contains("owed")
        || l.contains("withdrawable")
        || l.contains("amountout")
        || l.contains("amounttosend")
        || l.contains("amounttotransfer")
        || l.contains("topay")
        || l.contains("toclaim")
}

/// Detect the Salty M-01 shape: a deduction term computed with a *truncating*
/// integer division (`a * b / c` or bare `a / c`, not a ceil idiom / `mulDiv`
/// helper) that is then **subtracted** from a payout quantity.
///
/// Conservative, all required:
///   1. an assignment `offset = <floored mul-div / bare div>` whose target is a
///      local/state name and whose value is a truncating division (so the
///      subtrahend is rounded down);
///   2. a subtraction `A - offset` (the floored value on the *right* of `-`, i.e.
///      actually deducted) whose enclosing assignment target is a payout-shaped
///      name — or, failing a named target, the subtraction result is the argument
///      of a `transfer`/`safeTransfer` payout call.
///
/// Returns the span of the floored division (the offending quotient).
fn find_floored_offset_subtracted_from_payout(f: &Function) -> Option<sluice_ir::Span> {
    // A hand-rolled ceil anywhere in the offset would mean rounding was considered;
    // `uses_explicit_rounding` already covers the textual helpers, but a structural
    // ceil idiom in the body also disqualifies (the offset is rounded up).
    if has_ceil_idiom(f) {
        return None;
    }

    // (1) Collect names bound to a truncating division — both `T x = a / b;`
    // (a `VarDecl` with an init, the Salty spelling) and `x = a / b;` (an
    // `Assign`). Record the bound name and the span of the offending `/`.
    use sluice_ir::StmtKind;
    let mut floored_offsets: Vec<(String, sluice_ir::Span)> = Vec::new();
    for s in &f.body {
        s.visit(&mut |st| {
            if let StmtKind::VarDecl { name: Some(name), init: Some(init), .. } = &st.kind {
                if let Some(div_span) = first_truncating_div_span(init) {
                    floored_offsets.push((name.to_ascii_lowercase(), div_span));
                }
            }
        });
        s.visit_exprs(&mut |e| {
            if let ExprKind::Assign { target, value, .. } = &e.kind {
                if let Some(name) = target.simple_name() {
                    if let Some(div_span) = first_truncating_div_span(value) {
                        floored_offsets.push((name.to_ascii_lowercase(), div_span));
                    }
                }
            }
        });
    }
    if floored_offsets.is_empty() {
        return None;
    }

    // (2) A subtraction `A - offset` whose result flows to a payout. We look for a
    // `Sub` whose RHS is (or contains) one of the floored-offset names, and whose
    // enclosing assignment target is payout-shaped (or whose result feeds a
    // transfer). Because we scan assignments, the common
    // `claimableRewards = rewardsForAmount - virtualRewardsToRemove;` is caught.
    let offset_names: Vec<&str> = floored_offsets.iter().map(|(n, _)| n.as_str()).collect();

    // Does a transfer-style payout call exist in the body? (fallback path for when
    // the subtraction is not directly assigned to a named payout var).
    let has_payout_transfer = body_has_payout_transfer(f);

    // The specific floored-offset name that is actually deducted into a payout.
    let mut deducted: Option<String> = None;
    for s in &f.body {
        // `T payout = A - offset;` form.
        s.visit(&mut |st| {
            if deducted.is_some() {
                return;
            }
            if let StmtKind::VarDecl { name: Some(name), init: Some(init), .. } = &st.kind {
                let target_is_payout = is_payout_quantity_name(name);
                if target_is_payout || has_payout_transfer {
                    if let Some(off) = sub_deducts_offset(init, &offset_names) {
                        deducted = Some(off);
                    }
                }
            }
        });
        // `payout = A - offset;` form.
        s.visit_exprs(&mut |e| {
            if deducted.is_some() {
                return;
            }
            if let ExprKind::Assign { target, value, .. } = &e.kind {
                let target_is_payout = target
                    .simple_name()
                    .map(is_payout_quantity_name)
                    .unwrap_or(false);
                if target_is_payout || has_payout_transfer {
                    if let Some(off) = sub_deducts_offset(value, &offset_names) {
                        deducted = Some(off);
                    }
                }
            }
        });
    }
    let deducted = deducted?;

    // Report the span of the floored division that becomes the subtrahend.
    floored_offsets
        .iter()
        .find(|(n, _)| *n == deducted)
        .map(|(_, sp)| *sp)
}

/// Span of the first *truncating* integer division in `e`: a `Div` whose
/// numerator contains a `Mul` (`a * b / c`) or a bare `a / c`, but NOT a
/// hand-rolled ceil (`(a + b - 1) / b`). Returns `None` if no such division.
fn first_truncating_div_span(e: &Expr) -> Option<sluice_ir::Span> {
    let mut found = None;
    e.visit(&mut |n| {
        if found.is_some() {
            return;
        }
        if let ExprKind::Binary { op: BinOp::Div, lhs, .. } = &n.kind {
            // Exclude the ceil idiom: a `- 1` inside the numerator.
            let mut is_ceil = false;
            lhs.visit(&mut |m| {
                if let ExprKind::Binary { op: BinOp::Sub, rhs, .. } = &m.kind {
                    if is_one(rhs) {
                        is_ceil = true;
                    }
                }
            });
            if !is_ceil {
                found = Some(n.span);
            }
        }
    });
    found
}

/// If `e` contains a subtraction `A - X` where `X` (the right operand, the
/// deducted term) is — or transitively references — one of `offset_names`,
/// return that matched offset name (lowercased). The subtrahend must be on the
/// *right* of `-` so a floored term that is added, or that is the minuend, does
/// not count.
fn sub_deducts_offset(e: &Expr, offset_names: &[&str]) -> Option<String> {
    let mut found: Option<String> = None;
    e.visit(&mut |n| {
        if found.is_some() {
            return;
        }
        if let ExprKind::Binary { op: BinOp::Sub, rhs, .. } = &n.kind {
            rhs.visit(&mut |m| {
                if found.is_some() {
                    return;
                }
                if let Some(name) = m.simple_name() {
                    let l = name.to_ascii_lowercase();
                    if offset_names.contains(&l.as_str()) {
                        found = Some(l);
                    }
                }
            });
        }
    });
    found
}

/// True if the body performs a token-transfer-style payout (`transfer`,
/// `safeTransfer`, `safeTransferFrom`, `send`) — evidence the computed amount is
/// actually paid out to a user.
fn body_has_payout_transfer(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if let Some(n) = c.func_name.as_deref() {
                    let l = n.to_ascii_lowercase();
                    if l == "transfer" || l == "safetransfer" || l == "safetransferfrom" || l == "send" {
                        found = true;
                    }
                }
            }
        });
    }
    found
}

// ---------------------------------------------------------------------------
// Arm 3: sqrt-based reserve recovery
// ---------------------------------------------------------------------------

/// A reserve/invariant recovery entry point: `calcReserve`, `calcReserveAtRatio*`,
/// `calcLpTokenSupply`, or a name mentioning `reserve`/`invariant` paired with a
/// `calc`/`get`/`compute` verb. Kept tight so we only consider AMM-style math.
fn is_reserve_calc_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    if l.contains("reserve") || l.contains("lptoken") || l.contains("invariant") {
        return l.starts_with("calc")
            || l.starts_with("get")
            || l.starts_with("compute")
            || l.contains("reserve")
            || l.contains("lptoken")
            || l.contains("invariant");
    }
    false
}

/// Find an integer-`sqrt` (or its `x ** 2` inverse) used to recover a reserve.
/// Returns the span of the sqrt call / pow expression. We accept either:
///   - a call whose resolved name is `sqrt` / `nthRoot` (`x.sqrt()`,
///     `LibMath.sqrt(x)`), or
///   - a `BinOp::Pow` with exponent `2` (the `s ** 2` inverse used by
///     `calcReserve`, which is the reading that must reconcile with a floored
///     forward `sqrt`).
fn find_unrounded_sqrt_reserve(f: &Function) -> Option<sluice_ir::Span> {
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            match &e.kind {
                ExprKind::Call(c) => {
                    if let Some(n) = c.func_name.as_deref() {
                        let l = n.to_ascii_lowercase();
                        if l == "sqrt" || l == "nthroot" {
                            found = Some(e.span);
                        }
                    }
                }
                ExprKind::Binary { op: BinOp::Pow, rhs, .. } => {
                    if is_two(rhs) {
                        found = Some(e.span);
                    }
                }
                _ => {}
            }
        });
    }
    found
}

fn is_two(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Lit(sluice_ir::Lit::Number(n)) if n.trim() == "2")
}

/// True if the function pins the rounding direction *of the sqrt itself* — e.g.
/// it uses a `sqrtUp`/`sqrtCeil`/`ceilSqrt` helper. A div-rounding helper such as
/// `roundUpDiv` (which lowercases to a string containing `roundup`) must NOT
/// count: it controls the division, not the floor of the integer square root,
/// which is the hazard this arm targets. Comments are stripped by `source_text`,
/// so a `/// rounds up` annotation does not suppress either.
fn pins_sqrt_rounding(cx: &AnalysisContext, f: &Function) -> bool {
    let src = cx.source_text(f.span);
    src.contains("sqrtup")
        || src.contains("upsqrt")
        || src.contains("sqrtceil")
        || src.contains("ceilsqrt")
        || src.contains("sqrtroundup")
        || src.contains("sqrtrounding")
}

/// Suppress when the function clearly controls its rounding direction. Conducted
/// textually over the function source because the rounding mode is usually an
/// enum argument or a named helper rather than a distinct IR shape:
///   - `Rounding.Up` / `Rounding.Ceil` / `Rounding.Down` / `Rounding.Floor`,
///   - `mulDivUp` / `mulDivDown` / `ceilDiv` / `floorDiv` helpers,
///   - the `+ denominator - 1` (or `+ ... - 1`) ceil-division idiom.
fn uses_explicit_rounding(cx: &AnalysisContext, f: &Function) -> bool {
    let src = cx.source_text(f.span);
    if src.contains("rounding.up")
        || src.contains("rounding.ceil")
        || src.contains("rounding.down")
        || src.contains("rounding.floor")
        || src.contains("muldivup")
        || src.contains("muldivdown")
        || src.contains("muldivceil")
        || src.contains("ceildiv")
        || src.contains("floordiv")
        || src.contains("rounddown")
        || src.contains("roundup")
    {
        return true;
    }
    // `+ <denominator> - 1` ceil idiom: a `- 1` sub-expression added into the
    // numerator. Approximate textually (no whitespace normalization needed for
    // the common `- 1` / `-1` spellings) so we catch hand-rolled ceilDiv.
    has_ceil_idiom(f)
}

/// Detect the `(a * b + c - 1) / c` ceil-division idiom structurally: a `Div`
/// whose numerator subtracts `1`. This is the canonical hand-rolled
/// round-up, so its presence means rounding was considered.
fn has_ceil_idiom(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Binary { op: BinOp::Div, lhs, .. } = &e.kind {
                lhs.visit(&mut |n| {
                    if let ExprKind::Binary { op: BinOp::Sub, rhs, .. } = &n.kind {
                        if is_one(rhs) {
                            found = true;
                        }
                    }
                });
            }
        });
    }
    found
}

fn is_one(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Lit(sluice_ir::Lit::Number(n)) if n.trim() == "1")
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // A mint that issues shares with a bare `a * b / c` and no rounding mode:
    // truncation silently favors the depositor.
    const VULN: &str = r#"
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            mapping(address => uint256) public shares;
            function deposit(uint256 assets) external returns (uint256 shrs) {
                shrs = assets * totalSupply / totalAssets;
                shares[msg.sender] += shrs;
                totalSupply += shrs;
                totalAssets += assets;
            }
        }
    "#;

    // The same conversion but rounding is pinned with the `+ denominator - 1`
    // ceil idiom, so the protocol is protected — no finding.
    const SAFE: &str = r#"
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            mapping(address => uint256) public shares;
            function deposit(uint256 assets) external returns (uint256 shrs) {
                shrs = (assets * totalSupply + totalAssets - 1) / totalAssets;
                shares[msg.sender] += shrs;
                totalSupply += shrs;
                totalAssets += assets;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "rounding-direction"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "rounding-direction"));
    }

    // ---- Arm 2: solvency/collateral-gated price division (Frankencoin M-08/09)
    // A clone-init computes `price = mint * 1e18 / collateral` with truncating
    // division, then gates a collateral invariant on it. Rounding down can make a
    // legitimately-collateralized clone revert; the quotient should round up.
    const SOLVENCY_VULN: &str = r#"
        contract Position {
            uint256 public price;
            uint256 public minted;
            uint256 constant ONE_DEC18 = 1e18;
            function initializeClone(uint256 _price, uint256 _coll, uint256 _mint) external {
                price = _mint * ONE_DEC18 / _coll;
                if (price > _price) revert();
                checkCollateral(_coll, price);
            }
            function checkCollateral(uint256 collateralReserve, uint256 atPrice) internal view {
                if (collateralReserve * atPrice < minted * ONE_DEC18) revert();
            }
        }
    "#;

    // Same shape but the gating price is rounded *up* via a ceil helper, so the
    // collateral invariant stays satisfiable for honest callers — no finding.
    const SOLVENCY_SAFE: &str = r#"
        contract Position {
            uint256 public price;
            uint256 public minted;
            uint256 constant ONE_DEC18 = 1e18;
            function initializeClone(uint256 _price, uint256 _coll, uint256 _mint) external {
                price = ceilDiv(_mint * ONE_DEC18, _coll);
                if (price > _price) revert();
                checkCollateral(_coll, price);
            }
            function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
                return (a + b - 1) / b;
            }
            function checkCollateral(uint256 collateralReserve, uint256 atPrice) internal view {
                if (collateralReserve * atPrice < minted * ONE_DEC18) revert();
            }
        }
    "#;

    #[test]
    fn fires_on_solvency_gated_division() {
        let fs = run(SOLVENCY_VULN);
        assert!(
            fs.iter().any(|f| f.detector == "rounding-direction"
                && f.function == "initializeClone"),
            "{:?}",
            fs
        );
    }

    #[test]
    fn silent_on_rounded_solvency_division() {
        let fs = run(SOLVENCY_SAFE);
        assert!(
            !fs.iter().any(|f| f.detector == "rounding-direction"),
            "{:?}",
            fs
        );
    }

    // A bare config-scaling division (`perYearRate / SECONDS_PER_YEAR`) inside a
    // collateral-aware contract must NOT trip Arm 2: the target is a `rate`, not a
    // gating `price`. Guards against the comet interest-rate-slope false positives.
    const RATE_CONFIG_SAFE: &str = r#"
        contract Market {
            uint256 public supplyRate;
            uint256 public collateralFactor;
            uint256 constant SECONDS_PER_YEAR = 31536000;
            function setRate(uint256 perYearRate, uint256 minted) external {
                supplyRate = perYearRate / SECONDS_PER_YEAR;
                if (collateralFactor < minted) revert();
            }
        }
    "#;

    #[test]
    fn silent_on_rate_config_scaling() {
        let fs = run(RATE_CONFIG_SAFE);
        assert!(
            !fs.iter().any(|f| f.detector == "rounding-direction"),
            "{:?}",
            fs
        );
    }

    // ---- Arm 3: sqrt-based reserve recovery (Basin calcReserve) ----
    // A constant-product reserve recovered via integer sqrt / `s ** 2` with no
    // sqrt-rounding control: the floored sqrt can round in favor of the swapper.
    const SQRT_VULN: &str = r#"
        library LibMath {
            function sqrt(uint256 a) internal pure returns (uint256) { return a; }
            function roundUpDiv(uint256 a, uint256 b) internal pure returns (uint256) {
                if (a == 0) return 0;
                return (a - 1) / b + 1;
            }
        }
        contract CP2 {
            using LibMath for uint256;
            uint256 constant EXP_PRECISION = 1e12;
            function calcLpTokenSupply(uint256[] calldata reserves) external pure returns (uint256 s) {
                s = (reserves[0] * reserves[1] * EXP_PRECISION).sqrt();
            }
            function calcReserve(uint256[] calldata reserves, uint256 j, uint256 lpTokenSupply)
                external pure returns (uint256 reserve)
            {
                reserve = lpTokenSupply ** 2;
                reserve = LibMath.roundUpDiv(reserve, reserves[j == 1 ? 0 : 1] * EXP_PRECISION);
            }
        }
    "#;

    // The reserve recovery pins the sqrt direction with a `sqrtUp` helper, so the
    // pool's favor is preserved — no finding.
    const SQRT_SAFE: &str = r#"
        library LibMath {
            function sqrtUp(uint256 a) internal pure returns (uint256) { return a + 1; }
        }
        contract CP2 {
            using LibMath for uint256;
            uint256 constant EXP_PRECISION = 1e12;
            function calcLpTokenSupply(uint256[] calldata reserves) external pure returns (uint256 s) {
                s = (reserves[0] * reserves[1] * EXP_PRECISION).sqrtUp();
            }
        }
    "#;

    #[test]
    fn fires_on_sqrt_reserve_recovery() {
        let fs = run(SQRT_VULN);
        // Both the forward floored sqrt and the `** 2` inverse are flagged.
        assert!(
            fs.iter().any(|f| f.detector == "rounding-direction"
                && f.function == "calcReserve"),
            "calcReserve not flagged: {:?}",
            fs
        );
        assert!(
            fs.iter().any(|f| f.detector == "rounding-direction"
                && f.function == "calcLpTokenSupply"),
            "calcLpTokenSupply not flagged: {:?}",
            fs
        );
    }

    #[test]
    fn silent_on_rounded_sqrt_reserve() {
        let fs = run(SQRT_SAFE);
        assert!(
            !fs.iter().any(|f| f.detector == "rounding-direction"),
            "{:?}",
            fs
        );
    }

    // ---- Arm 4: caller-supplied price gated by a collateral check (M-09) ----
    // `adjustPrice` passes a caller-supplied `newPrice` straight into
    // `checkCollateral(collateralBalance(), newPrice)`, whose invariant is
    // `collateralReserve * atPrice < minted * ONE_DEC18 => revert`. A caller that
    // computes the minimum price with truncating division supplies a value one wei
    // low and a legitimate adjustment reverts.
    const PRICE_GATE_VULN: &str = r#"
        contract Position {
            uint256 public price;
            uint256 public minted;
            address public collateral;
            uint256 constant ONE_DEC18 = 1e18;
            function adjustPrice(uint256 newPrice) public {
                if (newPrice > price) {
                    revert();
                } else {
                    checkCollateral(collateralBalance(), newPrice);
                }
                price = newPrice;
            }
            function collateralBalance() internal view returns (uint256) {
                return IERC20(collateral).balanceOf(address(this));
            }
            function checkCollateral(uint256 collateralReserve, uint256 atPrice) internal view {
                if (collateralReserve * atPrice < minted * ONE_DEC18) revert();
            }
        }
    "#;

    // Same shape but the entry point rounds the required price up on-chain via a
    // ceil helper before gating, so honest callers are never rejected — no finding.
    const PRICE_GATE_SAFE: &str = r#"
        contract Position {
            uint256 public price;
            uint256 public minted;
            address public collateral;
            uint256 constant ONE_DEC18 = 1e18;
            function adjustPrice(uint256 newPrice) public {
                uint256 floorPrice = ceilDiv(minted * ONE_DEC18, collateralBalance());
                if (newPrice < floorPrice) revert();
                checkCollateral(collateralBalance(), newPrice);
                price = newPrice;
            }
            function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
                return (a + b - 1) / b;
            }
            function collateralBalance() internal view returns (uint256) {
                return IERC20(collateral).balanceOf(address(this));
            }
            function checkCollateral(uint256 collateralReserve, uint256 atPrice) internal view {
                if (collateralReserve * atPrice < minted * ONE_DEC18) revert();
            }
        }
    "#;

    // A generic price setter with no collateral invariant in the contract must NOT
    // trip Arm 4 — there is no `collateral * price >= minted` product to revert on.
    const PRICE_GATE_NO_INVARIANT: &str = r#"
        contract Oracle {
            uint256 public price;
            function setPrice(uint256 newPrice) public {
                checkBounds(newPrice);
                price = newPrice;
            }
            function checkBounds(uint256 p) internal pure {
                if (p == 0) revert();
            }
        }
    "#;

    #[test]
    fn fires_on_unrounded_price_collateral_gate() {
        let fs = run(PRICE_GATE_VULN);
        assert!(
            fs.iter().any(|f| f.detector == "rounding-direction"
                && f.function == "adjustPrice"),
            "{:?}",
            fs
        );
    }

    #[test]
    fn silent_on_onchain_rounded_price_gate() {
        let fs = run(PRICE_GATE_SAFE);
        assert!(
            !fs.iter().any(|f| f.detector == "rounding-direction"
                && f.function == "adjustPrice"),
            "{:?}",
            fs
        );
    }

    #[test]
    fn silent_on_price_setter_without_collateral_invariant() {
        let fs = run(PRICE_GATE_NO_INVARIANT);
        assert!(
            !fs.iter().any(|f| f.detector == "rounding-direction"),
            "{:?}",
            fs
        );
    }

    // ---- Arm 5: floored offset subtracted from a user payout (Salty M-01) ----
    // `_decreaseUserShare` floors `virtualRewardsToRemove` (a virtual-rewards
    // offset) with `virtualRewards * amount / userShare`, then pays out
    // `rewardsForAmount - virtualRewardsToRemove`. The floored subtrahend makes
    // the payout too large; withdrawing in many small increments over-claims.
    const OFFSET_VULN: &str = r#"
        contract StakingRewards {
            mapping(address => uint256) public virtualRewards;
            mapping(address => uint256) public userShare;
            mapping(bytes32 => uint256) public totalRewards;
            mapping(bytes32 => uint256) public totalShares;
            function _decreaseUserShare(address wallet, bytes32 poolID, uint256 decreaseShareAmount) internal {
                uint256 rewardsForAmount = (totalRewards[poolID] * decreaseShareAmount) / totalShares[poolID];
                uint256 virtualRewardsToRemove = (virtualRewards[wallet] * decreaseShareAmount) / userShare[wallet];
                userShare[wallet] -= decreaseShareAmount;
                virtualRewards[wallet] -= virtualRewardsToRemove;
                uint256 claimableRewards = 0;
                if (virtualRewardsToRemove < rewardsForAmount)
                    claimableRewards = rewardsForAmount - virtualRewardsToRemove;
                if (claimableRewards != 0)
                    salt.safeTransfer(wallet, claimableRewards);
            }
        }
    "#;

    // Same shape but the subtracted offset is rounded *up* (against the claimer)
    // via a ceil idiom, so the payout can never exceed the exact value — no finding.
    const OFFSET_SAFE: &str = r#"
        contract StakingRewards {
            mapping(address => uint256) public virtualRewards;
            mapping(address => uint256) public userShare;
            mapping(bytes32 => uint256) public totalRewards;
            mapping(bytes32 => uint256) public totalShares;
            function _decreaseUserShare(address wallet, bytes32 poolID, uint256 decreaseShareAmount) internal {
                uint256 rewardsForAmount = (totalRewards[poolID] * decreaseShareAmount) / totalShares[poolID];
                uint256 virtualRewardsToRemove = (virtualRewards[wallet] * decreaseShareAmount + userShare[wallet] - 1) / userShare[wallet];
                userShare[wallet] -= decreaseShareAmount;
                virtualRewards[wallet] -= virtualRewardsToRemove;
                uint256 claimableRewards = 0;
                if (virtualRewardsToRemove < rewardsForAmount)
                    claimableRewards = rewardsForAmount - virtualRewardsToRemove;
                if (claimableRewards != 0)
                    salt.safeTransfer(wallet, claimableRewards);
            }
        }
    "#;

    // A floored quotient that is *added* to a payout favors the protocol (the user
    // gets less, not more) — the opposite direction — and must NOT fire.
    const OFFSET_ADDED_SAFE: &str = r#"
        contract StakingRewards {
            mapping(address => uint256) public bonus;
            mapping(address => uint256) public userShare;
            mapping(bytes32 => uint256) public totalRewards;
            mapping(bytes32 => uint256) public totalShares;
            function withdrawRewards(address wallet, bytes32 poolID, uint256 amount) external {
                uint256 base = (totalRewards[poolID] * amount) / totalShares[poolID];
                uint256 extra = (bonus[wallet] * amount) / userShare[wallet];
                uint256 claimableRewards = base + extra;
                salt.safeTransfer(wallet, claimableRewards);
            }
        }
    "#;

    // A non-payout function (deposit/mint) with a subtracted floored offset must
    // NOT trip Arm 5 — the verb gate excludes the protocol-favoring direction.
    const OFFSET_MINT_SAFE: &str = r#"
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            mapping(address => uint256) public fee;
            function mint(address to, uint256 assets) external {
                uint256 gross = assets * totalSupply / totalAssets;
                uint256 cut = (fee[to] * assets) / totalSupply;
                uint256 net = gross - cut;
                totalSupply += net;
            }
        }
    "#;

    #[test]
    fn fires_on_floored_offset_subtracted_from_payout() {
        let fs = run(OFFSET_VULN);
        assert!(
            fs.iter().any(|f| f.detector == "rounding-direction"
                && f.function == "_decreaseUserShare"),
            "{:?}",
            fs
        );
    }

    #[test]
    fn silent_on_rounded_up_subtracted_offset() {
        let fs = run(OFFSET_SAFE);
        assert!(
            !fs.iter().any(|f| f.detector == "rounding-direction"),
            "{:?}",
            fs
        );
    }

    // Distinctive title of the Arm-5 finding; SAFE assertions key on this so a
    // pre-existing Arm-1 conversion finding (on a `withdraw`/`mint` mul-div) does
    // not mask an Arm-5 regression.
    const OFFSET_TITLE: &str = "Floored deduction subtracted from a user payout (rounds in the claimer's favor)";

    #[test]
    fn silent_on_floored_offset_added_to_payout() {
        let fs = run(OFFSET_ADDED_SAFE);
        assert!(
            !fs.iter().any(|f| f.detector == "rounding-direction" && f.title == OFFSET_TITLE),
            "{:?}",
            fs
        );
    }

    #[test]
    fn silent_on_subtracted_offset_in_mint_path() {
        let fs = run(OFFSET_MINT_SAFE);
        assert!(
            !fs.iter().any(|f| f.detector == "rounding-direction" && f.title == OFFSET_TITLE),
            "{:?}",
            fs
        );
    }
}
