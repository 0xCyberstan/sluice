//! Dangerous signed/unsigned integer casts that silently flip a value's sign.
//!
//! Solidity casts between integer types never revert; they reinterpret the
//! two's-complement bit pattern. That makes the sign boundary a sharp edge:
//!
//!   * `uint256(x)` where `x` is a *signed* `intN` that can be **negative**
//!     wraps to a huge positive (`-1` -> `2**256 - 1`). A subtraction that can
//!     underflow into the negatives — `int256(a) - int256(b)` cast back to
//!     `uint256` — is the canonical accounting-corruption shape: the "deficit"
//!     becomes an astronomically large credit.
//!   * `intN(x)` where `x` is a large *unsigned* value can flip **positive ->
//!     negative** (any `uint256` with the top bit set becomes a negative
//!     `int256`), defeating downstream `> 0` / signed-comparison checks.
//!   * The narrow-width special case of that direction: `int8(decimals())`. An
//!     ERC-20 `decimals()` returns a `uint8`, so a (malicious or misconfigured)
//!     token reporting `>= 128` decimals makes the `int8` reinterpret *negative*.
//!     The narrowed value is then typically used as a base-10 shift exponent, so
//!     the sign flip silently inverts the scaling direction (Reserve M-14). This
//!     fires even when the value is held in an `immutable` (one initialized from
//!     an *external* `decimals()` is not an author-fixed constant) and even when
//!     the cast is negated (`-int8(d)`: the wrap happens *inside* the `int8`,
//!     before the negate, so the negation cannot excuse it).
//!
//! Both directions corrupt accounting while passing the compiler's >=0.8
//! overflow checks (which do not look at casts at all). This is distinct from
//! the *narrowing* downcast that `integer_issues.rs` handles (`uint256 ->
//! uint128` truncation): here the width may be identical and the hazard is the
//! sign reinterpretation, not the dropped high bits.
//!
//! Heuristic (precision first, modest confidence):
//!   * A `TypeCast` to `uintN` whose argument is a subtraction `a - b` (can go
//!     negative) or an `intN`-typed parameter / state variable, **or**
//!   * a `TypeCast` to `intN` whose argument is a large/unsigned value (a
//!     `uintN`-typed parameter / state variable).
//!   * Suppressed for provably non-negative arguments (literals, `.length`, a
//!     `uint`-typed balance — which cannot flip sign on a cast *to* `uint`), and
//!     whenever the source leans on OpenZeppelin `SafeCast` / `toInt256` /
//!     `toUint256`, which bounds-check the conversion and revert on overflow.
//!
//! Width-safety (pre-empts the over-fire class the narrowing detector hit):
//!   * For the `uint -> int` direction, a *narrower* unsigned operand widened
//!     into a *wider* signed target cannot reach the sign bit — `int256(uint8 x)`
//!     spans `[0, 2**8)`, far inside `int256`'s positive range — so the cast is
//!     provably sign-stable and is suppressed when the target's signed bit-width
//!     strictly exceeds the operand's known unsigned width. (The `int -> uint`
//!     direction gets no such relief: a *negative* `int8` still wraps huge in any
//!     wider `uintN`, so widening never makes it safe.)
//!   * An operand bounded by a surrounding `require`/`if (...) revert` ordering
//!     check or a `min(...)`/`max(...)` clamp that *names that operand* can no
//!     longer take the out-of-range value the flip needs, so it is suppressed.
//!     The bound must reference the operand identifier — a guard on some other
//!     variable does not relax the cast.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Call, CallKind, Contract, Expr, ExprKind, Function, Stmt, StmtKind, UnOp};

pub struct SignedCastDetector;

impl Detector for SignedCastDetector {
    fn id(&self) -> &'static str {
        "signed-cast"
    }
    fn category(&self) -> Category {
        Category::SignedCast
    }
    fn description(&self) -> &'static str {
        "Signed<->unsigned integer cast that can silently flip sign (int->uint of a negative value, or uint->int of a large value)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            let contract = cx.contract_of(f.id);

            // Walk the *body* expression tree ourselves (rather than the shared
            // `visit_calls`) so we know each cast's immediate parent. This lets us
            // (a) guarantee we only ever inspect a real `CallKind::TypeCast`
            // expression and report *its own* span — never a return/parameter tuple
            // declaration — and (b) recognize when a `uint -> int` cast is the
            // operand of a negation or an argument to another call (idiomatic
            // signed-parameter construction), which is not the sign-flip hazard.
            for_each_cast(f, |c, span, ctx| {
                debug_assert!(c.kind == CallKind::TypeCast);
                // The textual target type of the cast.
                let Some(target) = cast_target_type(c) else { return };
                let target_signed = is_int_type(&target);
                let target_unsigned = is_uint_type(&target);
                if !target_signed && !target_unsigned {
                    return; // not an integer cast (e.g. `address(x)`, `IERC20(x)`)
                }

                // Single-argument cast only; the argument is the value reinterpreted.
                let Some(arg) = c.args.first() else { return };

                // --- false-positive suppression (precision is the priority) ---
                // A SafeCast / toIntN / toUintN conversion bounds-checks and reverts
                // on overflow, so the sign can never silently flip. Scope the check
                // to this call's span (comment-stripped, lowercased).
                if uses_safe_cast(cx, span) {
                    return;
                }

                // --- narrow signed reinterpret of a `decimals()` value (M-14) ---
                // `int8(decimals())` is the sharpest instance of the uint->int flip
                // and the one the generic gates below wrongly excuse: an ERC-20
                // `decimals()` is a `uint8`, so a token reporting `>= 128` decimals
                // wraps the `int8` *negative*, silently inverting the base-10 shift
                // exponent it feeds. We detect it up front — before the
                // `immutable`/negation/bound suppressions — because none of those
                // make it safe:
                //   * an `immutable` initialized from an *external* `decimals()` is
                //     not an author-fixed constant (the value comes from the token);
                //   * `-int8(d)` negates an *already-wrapped* `int8`, compounding the
                //     corruption rather than intending it.
                // It still respects `uses_safe_cast` above (a `SafeCast.toInt8`
                // reverts on the overflow) and is itself width-gated: it fires only
                // when the signed target is narrow enough that the unsigned source
                // can reach the sign bit (`int8(uint8 decimals)`: 8 <= 8), never on a
                // genuinely widening `int256(decimals())`.
                if target_signed {
                    if let Some(src_bits) = decimals_operand_width(f, contract, arg) {
                        if let Some(tgt_bits) = bit_width(&target) {
                            // Fire only when the narrowed signed target is small
                            // enough for the unsigned decimals value to reach the
                            // sign bit, and only when the operand is not already
                            // bounded by a `require`/`if` ordering guard or a
                            // `min`/`max` clamp that names it (`require(d < 128)`
                            // makes the flip unreachable). The immutable/negation
                            // suppressions are deliberately *not* consulted here —
                            // they are exactly what wrongly excuses M-14.
                            if tgt_bits <= src_bits && !operand_is_bounded(cx, f, arg) {
                                let b = self.decimals_finding(f, &target);
                                out.push(cx.finish(b, f.id, span));
                                return;
                            }
                        }
                    }
                }

                // Provably non-negative arguments cannot flip sign: a numeric/hex
                // literal, a `.length`, a `type(...)` expression, or a
                // constant/immutable state variable (a compile-time-fixed value the
                // author controls — `uint256(ONE_18)` is the prototypical case).
                if is_provably_nonneg(contract, arg) {
                    return;
                }
                // Width-safe widening into a signed target: a narrower unsigned
                // operand (`uint8(x)`, or a `uint8`-typed identifier) cast to a
                // wider `intN` never reaches the sign bit, so the value is provably
                // non-negative after the cast. Only the `uint -> int` direction
                // benefits — see `is_width_safe_widen`.
                if target_signed && is_width_safe_widen(f, contract, &target, arg) {
                    return;
                }
                // A `require` / `if (...) revert` ordering bound or a `min`/`max`
                // clamp that *names the operand* keeps it inside range, so the cast
                // can no longer take the out-of-range value the flip requires.
                if operand_is_bounded(cx, f, arg) {
                    return;
                }

                // Classify the dangerous shape.
                let kind = if target_unsigned {
                    // int -> uint: a negative value wraps to a huge positive. The
                    // wrap only happens if the *intermediate* is signed — an
                    // unsigned subtraction (`uint216 a - uint216 b`, `uint16 y - 1`)
                    // either stays non-negative or reverts under >=0.8 checked math,
                    // so widening it to `uint256` is sign-stable and is NOT a hazard.
                    // Require a demonstrably signed component before firing on a
                    // subtraction (an `intN`-typed operand or an explicit `intN(...)`
                    // cast); a value of unknown/unsigned signedness is not flagged.
                    if is_subtraction(arg) {
                        if subtraction_is_signed(f, contract, arg) {
                            Some(Hazard::SubToUint)
                        } else {
                            None
                        }
                    } else if arg_is_signed_typed(f, contract, arg) {
                        Some(Hazard::IntIdentToUint)
                    } else {
                        None
                    }
                } else {
                    // uint -> int: a large unsigned value flips to negative. Only
                    // flag when the source value is demonstrably unsigned-typed (a
                    // `uintN` parameter / state var); an arbitrary expression cast to
                    // `intN` is too weak a signal on its own.
                    //
                    // Two idiomatic, non-hazardous contexts are suppressed: a cast
                    // that is immediately negated (`-int256(amt)` deliberately builds
                    // a negative value — the sign change is the intent) and a cast
                    // handed as an argument to another call (`f(int256(amt))` fills a
                    // parameter the callee *declared* signed, so the signed
                    // representation is the agreed contract, not a defeated `> 0`
                    // check). A cast that becomes the function's own signed value —
                    // returned, assigned to a local, or fed into a comparison — is
                    // still flagged.
                    if matches!(ctx, CastCtx::Negated | CastCtx::CallArg) {
                        None
                    } else if arg_is_unsigned_typed(f, contract, arg) {
                        Some(Hazard::UintIdentToInt)
                    } else {
                        None
                    }
                };
                let Some(kind) = kind else { return };

                let (title, detail, rec) = match kind {
                    Hazard::SubToUint => (
                        "Subtraction result cast to an unsigned type can wrap to a huge value",
                        format!(
                            "casts a subtraction `a - b` to `{target}`. If the difference is negative \
                             (the signed intermediate underflows), the cast reinterprets it as a value \
                             near `type({target}).max` instead of reverting"
                        ),
                        "Compute the difference in an unsigned type so >=0.8 underflow checks apply, or \
                         `require(a >= b)` before subtracting; if a signed intermediate is intended, use \
                         OpenZeppelin `SafeCast.toUintN` (reverts on a negative input).",
                    ),
                    Hazard::IntIdentToUint => (
                        "Signed value cast to an unsigned type can wrap to a huge value",
                        format!(
                            "casts a signed (`int`) value to `{target}`. A negative input is reinterpreted \
                             as a value near `type({target}).max` (e.g. `-1` becomes `2**N - 1`) rather than \
                             reverting, corrupting any accounting that consumes it"
                        ),
                        "Guard the sign before converting (`require(x >= 0)`), or use OpenZeppelin \
                         `SafeCast.toUintN`, which reverts when the signed value is negative.",
                    ),
                    Hazard::UintIdentToInt => (
                        "Unsigned value cast to a signed type can flip positive to negative",
                        format!(
                            "casts an unsigned (`uint`) value to `{target}`. A value with the top bit set \
                             (e.g. a large balance) is reinterpreted as a negative `{target}`, so downstream \
                             `> 0` / signed comparisons can be defeated"
                        ),
                        "Bound the value before converting (`require(x <= uint256(type(intN).max))`), or use \
                         OpenZeppelin `SafeCast.toIntN`, which reverts when the unsigned value exceeds the \
                         signed range.",
                    ),
                };

                let b = FindingBuilder::new(self.id(), Category::SignedCast)
                    .title(title)
                    .severity(Severity::Medium)
                    // Honest: a structural smell. We match the cast shape and the
                    // operand's declared signedness, but cannot prove the value is
                    // actually out of range at runtime — single dimension, modest.
                    .confidence(0.45)
                    .dimension(Dimension::ValueFlow)
                    .message(format!(
                        "`{}` {detail}. Solidity integer casts never revert — they reinterpret the \
                         two's-complement bits — so this sign reinterpretation is silent.",
                        f.name
                    ))
                    .recommendation(rec);
                out.push(cx.finish(b, f.id, span));
            });
        }

        out
    }
}

impl SignedCastDetector {
    /// Build the finding for a narrow signed reinterpret of a `decimals()` value
    /// (`int8(decimals())`, the Reserve M-14 shape). Kept separate from the
    /// generic shapes because it intentionally fires through the `immutable` /
    /// negation / bound suppressions that those rely on.
    fn decimals_finding(&self, f: &Function, target: &str) -> FindingBuilder {
        FindingBuilder::new(self.id(), Category::SignedCast)
            .title("decimals() cast to a narrow signed type can flip positive to negative")
            .severity(Severity::Medium)
            .confidence(0.5)
            .dimension(Dimension::ValueFlow)
            .message(format!(
                "`{}` casts a token `decimals()` value to `{target}`. `decimals()` is a `uint8`, so a \
                 token reporting `>= 128` decimals is reinterpreted as a *negative* `{target}` — Solidity \
                 integer casts never revert, they reinterpret the two's-complement bits. The narrowed value \
                 is typically used as a base-10 shift exponent, so the silent sign flip inverts the scaling \
                 direction (e.g. shifting left instead of right). Holding the value in an `immutable` does \
                 not help when it was initialized from an external `decimals()`, and negating the result \
                 (`-int8(d)`) does not help because the wrap happens inside the cast.",
                f.name
            ))
            .recommendation(
                "Validate the decimals in range before narrowing — `require(d <= uint8(type(int8).max))` \
                 (i.e. `d < 128`) — or use OpenZeppelin `SafeCast.toInt8`, which reverts when the `uint8` \
                 exceeds the signed range. Reserve fixed M-14 by bounding `referenceERC20Decimals`.",
            )
    }
}

// ----------------------------------------------------------------- helpers

/// Which sign-flip shape we matched.
enum Hazard {
    /// `uintN(a - b)` — a subtraction that can underflow into the negatives.
    SubToUint,
    /// `uintN(x)` where `x` is an `intN`-typed parameter / state var.
    IntIdentToUint,
    /// `intN(x)` where `x` is a `uintN`-typed parameter / state var.
    UintIdentToInt,
}

/// The immediate syntactic context a cast expression sits in — enough to tell an
/// idiomatic signed-parameter construction from a value that becomes a function's
/// own signed quantity.
#[derive(Clone, Copy)]
enum CastCtx {
    /// The cast is the operand of a unary negation (`-int256(x)`).
    Negated,
    /// The cast is a positional argument to another (non-cast) call
    /// (`f(int256(x))`).
    CallArg,
    /// Anything else: returned, assigned, a comparison operand, a sub-expression
    /// of arithmetic, etc.
    Other,
}

/// Visit every `CallKind::TypeCast` expression in the function *body*, passing the
/// cast's own [`Call`], its own span, and its immediate-parent [`CastCtx`]. Walking
/// the tree here (instead of the shared `visit_calls`) guarantees two things:
///   * we only ever hand the detector a real cast expression, and the span we
///     report is exactly that cast — never a return / parameter tuple declaration
///     or a function-signature span; and
///   * we know whether the cast is negated or an argument to another call.
fn for_each_cast<'a>(f: &'a Function, mut visit: impl FnMut(&'a Call, sluice_ir::Span, CastCtx)) {
    fn walk<'a>(
        e: &'a Expr,
        parent: CastCtx,
        visit: &mut impl FnMut(&'a Call, sluice_ir::Span, CastCtx),
    ) {
        if let ExprKind::Call(c) = &e.kind {
            if c.kind == CallKind::TypeCast {
                visit(c, e.span, parent);
            }
        }
        // Determine the context each *child* sees: a child is `CallArg` only when
        // it is a positional argument of a non-cast call; the operand of a negate
        // is `Negated`. Everything else resets to `Other`.
        match &e.kind {
            ExprKind::Unary { op: UnOp::Negate, operand } => walk(operand, CastCtx::Negated, visit),
            ExprKind::Call(c) => {
                let is_cast = c.kind == CallKind::TypeCast;
                // The callee/receiver/value/gas are never "arguments".
                walk(&c.callee, CastCtx::Other, visit);
                if let Some(r) = &c.receiver {
                    walk(r, CastCtx::Other, visit);
                }
                if let Some(v) = &c.value {
                    walk(v, CastCtx::Other, visit);
                }
                if let Some(g) = &c.gas {
                    walk(g, CastCtx::Other, visit);
                }
                // A cast's *own* operand is the reinterpreted value, not a call
                // argument; only a real (non-cast) call confers `CallArg`.
                let arg_ctx = if is_cast { CastCtx::Other } else { CastCtx::CallArg };
                for a in &c.args {
                    walk(a, arg_ctx, visit);
                }
            }
            _ => {
                // Recurse into all other children with a neutral context.
                walk_children(e, visit);
            }
        }
    }

    // Recurse into every child of `e` with `CastCtx::Other` (used for node kinds
    // that do not themselves change a child's context).
    fn walk_children<'a>(e: &'a Expr, visit: &mut impl FnMut(&'a Call, sluice_ir::Span, CastCtx)) {
        match &e.kind {
            ExprKind::Member { base, .. } => walk(base, CastCtx::Other, visit),
            ExprKind::Index { base, index } => {
                walk(base, CastCtx::Other, visit);
                if let Some(i) = index {
                    walk(i, CastCtx::Other, visit);
                }
            }
            ExprKind::Unary { operand, .. } => walk(operand, CastCtx::Other, visit),
            ExprKind::Binary { lhs, rhs, .. } => {
                walk(lhs, CastCtx::Other, visit);
                walk(rhs, CastCtx::Other, visit);
            }
            ExprKind::Assign { target, value, .. } => {
                walk(target, CastCtx::Other, visit);
                walk(value, CastCtx::Other, visit);
            }
            ExprKind::Ternary { cond, then_e, else_e } => {
                walk(cond, CastCtx::Other, visit);
                walk(then_e, CastCtx::Other, visit);
                walk(else_e, CastCtx::Other, visit);
            }
            ExprKind::Tuple(items) | ExprKind::ArrayLit(items) => {
                for it in items.iter().flatten() {
                    walk(it, CastCtx::Other, visit);
                }
            }
            ExprKind::New(inner) => walk(inner, CastCtx::Other, visit),
            ExprKind::Ident(_)
            | ExprKind::Lit(_)
            | ExprKind::TypeName(_)
            | ExprKind::Call(_)
            | ExprKind::Unsupported => {}
        }
    }

    for s in &f.body {
        s.visit(&mut |st: &'a Stmt| {
            for_each_root_expr(st, &mut |e| walk(e, CastCtx::Other, &mut visit));
        });
    }
}

/// Invoke `g` on each *root* expression directly held by a single statement (not
/// recursing into nested statements — [`Stmt::visit`] already does that). Mirrors
/// the expression-bearing arms of [`Stmt::visit_exprs`].
fn for_each_root_expr<'a>(st: &'a Stmt, g: &mut impl FnMut(&'a Expr)) {
    match &st.kind {
        StmtKind::Expr(e) | StmtKind::Emit(e) => g(e),
        StmtKind::VarDecl { init: Some(e), .. } => g(e),
        StmtKind::Return(Some(e)) => g(e),
        StmtKind::If { cond, .. } | StmtKind::While { cond, .. } | StmtKind::DoWhile { cond, .. } => g(cond),
        StmtKind::For { cond, step, .. } => {
            if let Some(c) = cond {
                g(c);
            }
            if let Some(s) = step {
                g(s);
            }
        }
        StmtKind::Revert { args, .. } => {
            for a in args {
                g(a);
            }
        }
        StmtKind::Try { expr, .. } => g(expr),
        _ => {}
    }
}

/// The textual target type of a `TypeCast` call: `uint256(x)` lowers the callee
/// to `ExprKind::TypeName("uint256")`; a named cast carries it in `func_name`.
fn cast_target_type(c: &Call) -> Option<String> {
    if let ExprKind::TypeName(t) = &c.callee.kind {
        return Some(t.clone());
    }
    c.func_name.clone()
}

/// `intN` (signed), including the bare `int` alias for `int256`. Excludes
/// `uintN`.
fn is_int_type(ty: &str) -> bool {
    let t = ty.trim();
    if !t.starts_with("int") {
        return false;
    }
    let digits = &t["int".len()..];
    digits.is_empty() || digits.bytes().all(|b| b.is_ascii_digit())
}

/// `uintN` (unsigned), including the bare `uint` alias for `uint256`.
fn is_uint_type(ty: &str) -> bool {
    let t = ty.trim();
    if !t.starts_with("uint") {
        return false;
    }
    let digits = &t["uint".len()..];
    digits.is_empty() || digits.bytes().all(|b| b.is_ascii_digit())
}

/// True if the cast (by its span) goes through a bounds-checked conversion —
/// OZ `SafeCast`, or a `.toIntN()` / `.toUintN()` helper — which reverts rather
/// than silently flip sign. Uses comment-stripped, lowercased source so a
/// comment mentioning `safecast` cannot trip the suppression.
fn uses_safe_cast(cx: &AnalysisContext, span: sluice_ir::Span) -> bool {
    let src = cx.source_text(span);
    src.contains("safecast") || src.contains("touint") || src.contains("toint")
}

/// True if the argument is a subtraction `a - b` (whose signed intermediate can
/// be negative). Peels surrounding integer casts so `uint256(int256(a) - int256(b))`
/// still sees the `Sub`.
fn is_subtraction(e: &Expr) -> bool {
    matches!(&peel_int_casts(e).kind, ExprKind::Binary { op: BinOp::Sub, .. })
}

/// True if a subtraction's intermediate is *signed* and can therefore actually go
/// negative before the cast wraps it. The wrap hazard needs a signed intermediate:
/// an unsigned subtraction (`uint216 a - uint216 b`, `uint16 year - 1`) either
/// stays non-negative or reverts under >=0.8 checked arithmetic, so widening it to
/// `uint`/`uintN` never silently produces a huge value via sign reinterpretation.
///
/// We treat the subtraction as signed when it contains a demonstrably signed
/// component: an explicit `intN(...)` cast anywhere inside, or an operand
/// identifier that resolves to an `intN` parameter / state variable. An operand of
/// unknown signedness (a local we cannot resolve, an unresolved member / index)
/// does NOT count — precision first, mirroring the `UintIdentToInt` gate.
fn subtraction_is_signed(f: &Function, contract: Option<&Contract>, e: &Expr) -> bool {
    let sub = peel_int_casts(e);
    let ExprKind::Binary { op: BinOp::Sub, lhs, rhs } = &sub.kind else {
        return false;
    };
    expr_has_signed_component(f, contract, lhs) || expr_has_signed_component(f, contract, rhs)
}

/// Does `e` contain a provably signed value — an explicit `intN(...)` cast, or an
/// `intN`-typed identifier — anywhere in its subtree? An explicit `uintN(...)` cast
/// makes its result unsigned, so we stop there (a signed value re-cast to unsigned
/// is no longer a negative-producing intermediate). Recurses through arithmetic and
/// the bases of member / index accesses.
fn expr_has_signed_component(f: &Function, contract: Option<&Contract>, e: &Expr) -> bool {
    match &e.kind {
        // An explicit cast determines signedness outright: `intN(..)` is signed,
        // `uintN(..)` is unsigned (do not look inside it). A non-integer cast
        // (`address(..)`) is neither — fall through to its argument.
        ExprKind::Call(c) if c.kind == CallKind::TypeCast && c.args.len() == 1 => {
            match cast_target_type(c) {
                Some(t) if is_int_type(&t) => true,
                Some(t) if is_uint_type(&t) => false,
                _ => expr_has_signed_component(f, contract, &c.args[0]),
            }
        }
        ExprKind::Ident(_) => {
            resolve_decl_type(f, contract, e).map(|t| is_int_type(&t)).unwrap_or(false)
        }
        ExprKind::Binary { lhs, rhs, .. } => {
            expr_has_signed_component(f, contract, lhs) || expr_has_signed_component(f, contract, rhs)
        }
        ExprKind::Unary { operand, .. } => expr_has_signed_component(f, contract, operand),
        ExprKind::Member { base, .. } => expr_has_signed_component(f, contract, base),
        ExprKind::Index { base, .. } => expr_has_signed_component(f, contract, base),
        _ => false,
    }
}

/// True if the cast operand is a compile-time / author-fixed value, so a cast of
/// it cannot produce a *silent runtime* sign flip (the class this detector
/// targets):
///   * a numeric / hex literal,
///   * a `.length` member (array / bytes length is always a non-negative `uint`),
///   * a `type(...)` expression (`type(uint256).max` etc. — a fixed constant),
///   * a `constant` / `immutable` state variable — a value the author fixes at
///     compile / deploy time (`uint256(ONE_18)`). The value is visible in source,
///     not an attacker-influenced runtime quantity, so it is suppressed regardless
///     of the constant's declared signedness.
fn is_provably_nonneg(contract: Option<&Contract>, e: &Expr) -> bool {
    let e = peel_int_casts(e);
    match &e.kind {
        ExprKind::Lit(sluice_ir::Lit::Number(_)) | ExprKind::Lit(sluice_ir::Lit::HexNumber(_)) => true,
        ExprKind::Member { member, .. } => member == "length",
        // `type(uint256).max`, `type(int128).min`, etc. lower to a call on the
        // `type` builtin; any `type(...)` operand is a compile-time constant.
        ExprKind::Call(c) if is_type_call(c) => true,
        ExprKind::Ident(name) => is_constant_state_var(contract, name),
        _ => false,
    }
}

/// True if `c` is a `type(T)` expression (whose `.max`/`.min` are constants).
fn is_type_call(c: &Call) -> bool {
    matches!(&c.callee.kind, ExprKind::Ident(n) if n == "type")
        || c.func_name.as_deref() == Some("type")
}

/// True if `name` is a `constant` or `immutable` state variable of `contract`.
fn is_constant_state_var(contract: Option<&Contract>, name: &str) -> bool {
    contract
        .and_then(|c| c.state_vars.iter().find(|v| v.name == name))
        .map(|v| v.constant || v.immutable)
        .unwrap_or(false)
}

/// The argument resolves to an `intN`-typed parameter or state variable (a
/// signed value that can be negative).
fn arg_is_signed_typed(f: &Function, contract: Option<&Contract>, e: &Expr) -> bool {
    resolve_decl_type(f, contract, e).map(|t| is_int_type(&t)).unwrap_or(false)
}

/// The argument resolves to a `uintN`-typed parameter or state variable (a
/// value with no sign bit, which becomes negative when reinterpreted as `intN`).
/// A `uint` *balance* identifier is the prototypical case.
fn arg_is_unsigned_typed(f: &Function, contract: Option<&Contract>, e: &Expr) -> bool {
    resolve_decl_type(f, contract, e).map(|t| is_uint_type(&t)).unwrap_or(false)
}

/// Best-effort declared type of a bare-identifier argument: a function parameter
/// or a contract state variable of that name. Returns `None` for anything that
/// isn't a simple identifier we can resolve (a member/index/call expression),
/// keeping the signedness gate conservative.
fn resolve_decl_type(f: &Function, contract: Option<&Contract>, e: &Expr) -> Option<String> {
    let ExprKind::Ident(name) = &peel_int_casts(e).kind else {
        return None;
    };
    if let Some(p) = f.params.iter().find(|p| p.name.as_deref() == Some(name.as_str())) {
        return Some(p.ty.clone());
    }
    if let Some(c) = contract {
        if let Some(v) = c.state_vars.iter().find(|v| &v.name == name) {
            return Some(v.ty.clone());
        }
    }
    None
}

/// Peel single-argument integer (`uintN`/`intN`) type casts so we can inspect
/// the underlying value. `address`/interface casts are *not* peeled (they aren't
/// integer reinterpretations).
fn peel_int_casts(e: &Expr) -> &Expr {
    let mut cur = e;
    loop {
        match &cur.kind {
            ExprKind::Call(c) if c.kind == CallKind::TypeCast && c.args.len() == 1 => {
                match cast_target_type(c) {
                    Some(t) if is_int_type(&t) || is_uint_type(&t) => cur = &c.args[0],
                    _ => return cur,
                }
            }
            _ => return cur,
        }
    }
}

/// Bit-width of an integer type name. `uint`/`int` (no digits) is the 256-bit
/// alias; `uint128` -> 128, `int8` -> 8. `None` for a malformed width.
fn bit_width(ty: &str) -> Option<u32> {
    let t = ty.trim();
    let digits = if let Some(d) = t.strip_prefix("uint") {
        d
    } else if let Some(d) = t.strip_prefix("int") {
        d
    } else {
        return None;
    };
    if digits.is_empty() {
        return Some(256); // bare `uint` / `int`
    }
    digits.parse::<u32>().ok().filter(|w| *w >= 8 && *w <= 256 && w % 8 == 0)
}

/// The tightest unsigned bit-width that bounds `arg`, if known. An explicit
/// `uintM(...)` cast wrapper clamps the value to `[0, 2**M)` regardless of what
/// is inside it, so it dominates; otherwise a `uintM`-typed identifier carries
/// its declared width. Returns `None` when no unsigned bound is provable (e.g.
/// the operand is signed-typed, or an unresolved expression).
fn operand_unsigned_width(f: &Function, contract: Option<&Contract>, arg: &Expr) -> Option<u32> {
    // An outermost explicit unsigned cast `uintM(...)` bounds the value to uintM.
    if let ExprKind::Call(c) = &arg.kind {
        if c.kind == CallKind::TypeCast && c.args.len() == 1 {
            if let Some(t) = cast_target_type(c) {
                if is_uint_type(&t) {
                    return bit_width(&t);
                }
            }
        }
    }
    // Otherwise fall back to a `uintM`-typed identifier's declared width.
    let ty = resolve_decl_type(f, contract, arg)?;
    if is_uint_type(&ty) {
        bit_width(&ty)
    } else {
        None
    }
}

/// If `arg` is a token-`decimals()` value, the unsigned bit-width that bounds it;
/// otherwise `None`. A "decimals operand" is the externally-influenced value at
/// the heart of Reserve M-14:
///   * a `.decimals()` **call** (`func_name == "decimals"`) — by the ERC-20
///     interface this returns a `uint8`, so the value spans `[0, 2**8)` and the
///     bounding width is 8. The token chooses the value, so it can be `>= 128`;
///   * a `uintM`-typed identifier / parameter / state variable whose **name**
///     looks like a decimals field (`decimals`, `erc20Decimals`,
///     `referenceERC20Decimals`, …) — the width is its declared `M`. The name
///     gate keeps this from matching arbitrary `uintM` values (those remain the
///     job of the generic `UintIdentToInt` shape, which the width/negation/bound
///     gates still constrain).
///
/// Casts are peeled first so `int8(uint8(erc20.decimals()))` and a bare
/// `int8(erc20Decimals)` both resolve. A signed (`intM`) source is never a
/// decimals operand (it has already been given a sign).
fn decimals_operand_width(f: &Function, contract: Option<&Contract>, arg: &Expr) -> Option<u32> {
    let inner = peel_int_casts(arg);
    // A `decimals()` call: width is the ERC-20 `uint8`.
    if let ExprKind::Call(c) = &inner.kind {
        if c.func_name.as_deref() == Some("decimals") {
            return Some(8);
        }
    }
    // A decimals-named identifier of unsigned type: width is its declared width.
    if let ExprKind::Ident(name) = &inner.kind {
        if name_is_decimals(name) {
            let ty = resolve_decl_type(f, contract, inner)?;
            if is_uint_type(&ty) {
                return bit_width(&ty);
            }
        }
    }
    None
}

/// True if an identifier name reads as a token-decimals field: it contains the
/// whole word fragment `decimals` (case-insensitive). Matches `decimals`,
/// `erc20Decimals`, `referenceERC20Decimals`, `tokenDecimals`; does not match an
/// unrelated `decimal` typo or `decimalsRatio`-style derived values (we require
/// the fragment to end the name or be followed by a non-letter, so a value that
/// has already been *combined* with something else is not treated as the raw
/// decimals count).
fn name_is_decimals(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let frag = "decimals";
    let bytes = lower.as_bytes();
    let mut from = 0;
    while let Some(rel) = lower[from..].find(frag) {
        let start = from + rel;
        let end = start + frag.len();
        // The fragment must end the name or be followed by a non-letter, so
        // `decimals` / `erc20Decimals` match but `decimalsdelta` does not.
        let after_ok = end >= bytes.len() || !bytes[end].is_ascii_alphabetic();
        if after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// `uint -> int` widening that cannot flip sign: the operand is bounded to an
/// unsigned width strictly smaller than the signed target's width, so its max
/// value (`2**w - 1`) stays inside the target's positive range (`2**(N-1) - 1`).
/// `int256(uint8 x)` is safe (`8 < 256`); `int8(uint8 x)` is *not* (`8 == 8`, a
/// `uint8` of 200 becomes a negative `int8`); `int256(uint256 x)` is *not*
/// (`256 == 256`, the top bit flips). Only ever called for a signed target.
fn is_width_safe_widen(
    f: &Function,
    contract: Option<&Contract>,
    target: &str,
    arg: &Expr,
) -> bool {
    let Some(target_bits) = bit_width(target) else { return false };
    match operand_unsigned_width(f, contract, arg) {
        Some(op_bits) => op_bits < target_bits,
        None => false,
    }
}

/// Root identifiers appearing in `arg` (after peeling integer casts): the names a
/// surrounding bound would have to mention to actually constrain this operand.
/// Walks a subtraction `a - b` into both sides; ignores literals and `.length`.
fn operand_idents(arg: &Expr) -> Vec<String> {
    let mut out = Vec::new();
    collect_idents(peel_int_casts(arg), &mut out);
    out
}

fn collect_idents(e: &Expr, out: &mut Vec<String>) {
    match &e.kind {
        ExprKind::Ident(name) => out.push(name.clone()),
        ExprKind::Binary { lhs, rhs, .. } => {
            collect_idents(peel_int_casts(lhs), out);
            collect_idents(peel_int_casts(rhs), out);
        }
        ExprKind::Member { base, .. } => collect_idents(peel_int_casts(base), out),
        ExprKind::Index { base, .. } => collect_idents(peel_int_casts(base), out),
        ExprKind::Unary { operand, .. } => collect_idents(peel_int_casts(operand), out),
        _ => {}
    }
}

/// True if the function body bounds the operand so the sign flip can no longer
/// occur: a `min(...)`/`max(...)` clamp or a `require` / `if (...) revert`
/// *ordering* comparison (`<`, `>`, `<=`, `>=`) that names one of the operand's
/// identifiers. Keyed on the whole-function source (`f.span`) because the bound
/// lives in a sibling statement, not inside the cast's own span — but it must
/// reference the operand, so a guard on an unrelated variable does not relax the
/// cast (preserving genuine unbounded-downcast fires).
fn operand_is_bounded(cx: &AnalysisContext, f: &Function, arg: &Expr) -> bool {
    let idents = operand_idents(arg);
    if idents.is_empty() {
        return false;
    }
    // Comment-stripped, lowercased function text (so a comment cannot trip this).
    let src = cx.source_text(f.span);
    let names: Vec<String> = idents.iter().map(|n| n.to_ascii_lowercase()).collect();

    // A `min(... operand ...)` / `max(... operand ...)` clamp.
    for kw in ["min(", "max("] {
        let mut from = 0;
        while let Some(rel) = src[from..].find(kw) {
            let open = from + rel + kw.len();
            let end = matching_close(&src, open);
            let inner = &src[open..end];
            if names.iter().any(|n| mentions_ident(inner, n)) {
                return true;
            }
            from = open;
        }
    }

    // A `require(...)` / `revert`-guarded ordering comparison referencing the
    // operand. We scan each `require(` / `if (` clause head and require both an
    // ordering operator and one of the operand idents inside it. The clause is
    // bounded at the *matching* close paren (balancing nesting), so a guard like
    // `require(int256(shares) >= 0)` is read in full rather than truncated at the
    // inner cast's `)` — which would hide the `>=` from the ordering check.
    for kw in ["require(", "if(", "if ("] {
        let mut from = 0;
        while let Some(rel) = src[from..].find(kw) {
            let open = from + rel + kw.len();
            let end = matching_close(&src, open);
            let clause = &src[open..end];
            let has_order = clause.contains("<=")
                || clause.contains(">=")
                || clause.contains('<')
                || clause.contains('>');
            if has_order && names.iter().any(|n| mentions_ident(clause, n)) {
                return true;
            }
            from = open;
        }
    }
    false
}

/// Given a byte index `open` pointing just past an opening `(`, return the index
/// of the matching close `)` (exclusive of it), balancing nested parentheses. If
/// the parentheses are unbalanced (truncated source), returns the end of `src`.
fn matching_close(src: &str, open: usize) -> usize {
    let bytes = src.as_bytes();
    let mut depth: u32 = 1;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
        i += 1;
    }
    src.len()
}

/// Whole-identifier match of `name` in `hay` (both already lowercased): the
/// chars bordering the hit must not be identifier characters, so `amount` does
/// not match inside `amountIn` / `totalAmount`.
fn mentions_ident(hay: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let bytes = hay.as_bytes();
    let mut from = 0;
    while let Some(rel) = hay[from..].find(name) {
        let start = from + rel;
        let end = start + name.len();
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_ident_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: a signed difference that can go negative is cast straight to
    // `uint256`. If `b > a`, the intermediate is negative and the cast wraps it
    // to a value near `type(uint256).max`, corrupting the returned accounting.
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        contract Ledger {
            int256 public netFlow;
            function settle(int256 a, int256 b) external view returns (uint256) {
                return uint256(a - b);
            }
        }
    "#;

    // Safe: the conversion is bounds-checked via OpenZeppelin SafeCast, which
    // reverts on a negative input instead of silently wrapping. No sign flip is
    // possible, so the detector must stay silent.
    const SAFE: &str = r#"
        pragma solidity ^0.8.20;
        import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
        contract Ledger {
            using SafeCast for int256;
            function settle(int256 a, int256 b) external pure returns (uint256) {
                int256 diff = a - b;
                return diff.toUint256();
            }
        }
    "#;

    // Width-safe widening: a `uint8` operand widened into `int256` spans only
    // `[0, 2**8)`, far below `int256`'s positive max, so the sign can never flip.
    // Before width-safety this fired (a `uint`-typed value cast to `int` =>
    // `UintIdentToInt`); the detector must now stay silent.
    const WIDTH_SAFE_CAST: &str = r#"
        pragma solidity ^0.8.20;
        contract M {
            function f(uint256 x) external pure returns (int256) {
                return int256(uint8(x));
            }
        }
    "#;

    // Width-safe via the operand's *declared* width: a `uint8` parameter widened
    // into `int256` is likewise sign-stable. Also fired pre-change.
    const WIDTH_SAFE_DECL: &str = r#"
        pragma solidity ^0.8.20;
        contract M {
            function f(uint8 small) external pure returns (int256) {
                return int256(small);
            }
        }
    "#;

    // NOT width-safe: a full-width `uint256` cast to `int256` can have its top bit
    // set and flip negative — widths are equal, not strictly smaller. Must FIRE.
    const WIDTH_UNSAFE_FULL: &str = r#"
        pragma solidity ^0.8.20;
        contract M {
            function f(uint256 big) external pure returns (int256) {
                return int256(big);
            }
        }
    "#;

    // Guarded: `require(a >= b)` makes `a - b` provably non-negative before the
    // cast, so the int->uint wrap cannot occur. The same cast fires unguarded
    // (see VULN); the operand-named bound must suppress it here.
    const GUARDED_REQUIRE: &str = r#"
        pragma solidity ^0.8.20;
        contract Ledger {
            function settle(int256 a, int256 b) external pure returns (uint256) {
                require(a >= b, "underflow");
                return uint256(a - b);
            }
        }
    "#;

    // Clamped: `a = max(a, b)` forces `a >= b`, so `a - b` cannot go negative.
    // The `max(` clamp names the operand, so the cast is suppressed.
    const CLAMPED_MAX: &str = r#"
        pragma solidity ^0.8.20;
        library Math { function max(int256 p, int256 q) internal pure returns (int256) { return p > q ? p : q; } }
        contract Ledger {
            using Math for int256;
            function settle(int256 a, int256 b) external pure returns (uint256) {
                a = Math.max(a, b);
                return uint256(a - b);
            }
        }
    "#;

    // A guard on an *unrelated* variable must NOT relax the cast: `c` is bounded
    // but the dangerous operand is `a - b`, which stays unbounded. Must FIRE so a
    // real downcast bug is never silenced by a spurious nearby check.
    const GUARD_OTHER_VAR: &str = r#"
        pragma solidity ^0.8.20;
        contract Ledger {
            function settle(int256 a, int256 b, int256 c) external pure returns (uint256) {
                require(c >= 0, "bad c");
                return uint256(a - b);
            }
        }
    "#;

    // --- R5 dogfood false-positive regressions (pendle-core) ---------------

    // FP1 (pendle MarketApproxLibV1.calcSyIn shape): the destructuring assignment
    // `(int256 a, int256 b, int256 c) = ...` is a tuple of *local declarations*,
    // not a cast. The only cast on the line, `int256(netPtOut)`, is an argument to
    // another call (`calcTrade`), filling a parameter the callee declared `int256`
    // — the idiomatic, by-design signed representation. The detector must stay
    // silent: it must never attribute to the tuple declaration, and it must not
    // treat a call-argument `uint -> int` as a defeated `> 0` check.
    const FP_RETURN_TUPLE_CALLARG: &str = r#"
        pragma solidity ^0.8.20;
        interface IMkt { function calcTrade(uint256 a, uint256 b, int256 c) external returns (int256, int256, int256); }
        contract Approx {
            function calcSyIn(IMkt market, uint256 netPtOut) external returns (uint256 r) {
                (int256 _netSyIn, int256 _netSyFee, int256 _netSyToReserve) = market.calcTrade(1, 2, int256(netPtOut));
                r = uint256(-_netSyIn) + uint256(_netSyFee) + uint256(_netSyToReserve);
            }
        }
    "#;

    // FP1b (pendle calcSyOut shape): same, but the call argument is a *negated*
    // cast `-int256(netPtIn)` — the negation makes the negative value the explicit
    // intent, so the sign change is not a silent flip. Must stay silent.
    const FP_NEGATED_CALLARG: &str = r#"
        pragma solidity ^0.8.20;
        interface IMkt { function calcTrade(uint256 a, uint256 b, int256 c) external returns (int256, int256, int256); }
        contract Approx {
            function calcSyOut(IMkt market, uint256 netPtIn) external returns (uint256 r) {
                (int256 o, int256 f, int256 t) = market.calcTrade(1, 2, -int256(netPtIn));
                r = uint256(o) + uint256(f) + uint256(t);
            }
        }
    "#;

    // A function that merely *returns a tuple* of `int256` with NO cast in its body
    // must produce nothing — there is no `TypeCast` expression to flag, and the
    // return/parameter tuple is not a cast.
    const RETURN_TUPLE_NO_BODY_CAST: &str = r#"
        pragma solidity ^0.8.20;
        contract M {
            function split(int256 v) external pure returns (int256 a, int256 b) {
                a = v;
                b = v;
            }
        }
    "#;

    // FP2 (pendle LogExpMath.pow): the operand is a `constant` state variable, a
    // compile-time-fixed non-negative value — `uint256(ONE_18)` cannot flip sign.
    const FP_CONSTANT_OPERAND: &str = r#"
        pragma solidity ^0.8.20;
        library LogExpMath {
            int256 constant ONE_18 = 1_000_000_000_000_000_000;
            function pow(uint256 y) internal pure returns (uint256) {
                if (y == 0) {
                    return uint256(ONE_18);
                }
                return 0;
            }
        }
    "#;

    // FP3 (pendle ExpiryUtilsLib.getYear): `uint16(year - 1)` is an *unsigned*
    // subtraction (`year` is `uint16`) cast to `uint16`. Under >=0.8 it reverts on
    // underflow rather than wrapping, and widening an unsigned value never flips
    // sign — so there is no hazard. Must stay silent.
    const FP_UNSIGNED_SUB_BOUNDED: &str = r#"
        pragma solidity ^0.8.0;
        library ExpiryUtils {
            function isLeapYear(uint16 y) private pure returns (bool) { return y % 4 == 0; }
            function getYear(uint256 ts) private pure returns (uint16) {
                uint16 year = uint16(1970 + ts / 31536000);
                while (year > 1970) {
                    if (isLeapYear(uint16(year - 1))) { year -= 1; } else { year -= 1; }
                }
                return year;
            }
        }
    "#;

    // FP4 (pendle OracleLib.observeSingle): a subtraction of two *unsigned*
    // (`uint216`) values cast to `uint256` is a pure widening — sign-stable. The
    // `SubToUint` rule must require a signed intermediate, so this stays silent.
    const FP_UNSIGNED_SUB_MEMBERS: &str = r#"
        pragma solidity ^0.8.20;
        contract Oracle {
            struct Obs { uint216 cum; }
            function observeSingle(Obs memory beforeOrAt, Obs memory atOrAfter) external pure returns (uint256) {
                return uint256(atOrAfter.cum - beforeOrAt.cum);
            }
        }
    "#;

    // Positive guard: a `uint -> int` cast that becomes the function's own signed
    // value via a downstream `> 0` comparison is still the defeated-check hazard —
    // it is neither negated nor a call argument — so it must FIRE. Keeps the
    // call-argument/negation suppression from over-reaching.
    const FIRES_UINT_TO_INT_COMPARED: &str = r#"
        pragma solidity ^0.8.20;
        contract M {
            function f(uint256 bal) external pure returns (bool) {
                int256 s = int256(bal);
                return s > 0;
            }
        }
    "#;

    // --- R5 dogfood false-positive regressions (eigenlayer-contracts) -------

    // FP (eigenlayer EigenPodManager._addShares): the operand is itself sign-checked
    // by `require(int256(shares) >= 0, ...)`. The guard clause references `shares`
    // with an ordering operator, so both the cast inside the guard and the later
    // `int256(shares)` are provably non-negative and must stay silent. (The clause
    // extraction must balance the inner `int256(...)` parens to see the `>=`.)
    const FP_SIGN_CHECKED_OPERAND: &str = r#"
        pragma solidity ^0.8.20;
        contract M {
            error SharesNegative();
            function addShares(uint256 shares) external pure returns (int256) {
                require(int256(shares) >= 0, SharesNegative());
                int256 sharesToAdd = int256(shares);
                return sharesToAdd;
            }
        }
    "#;

    // FP (eigenlayer EigenPod._updateCheckpoint): `int256(GWEI_TO_WEI)` casts a
    // `constant` — a compile-time non-negative value — even though the result then
    // feeds signed arithmetic. Must stay silent.
    const FP_CONSTANT_IN_ARITH: &str = r#"
        pragma solidity ^0.8.20;
        contract M {
            uint256 constant GWEI_TO_WEI = 1_000_000_000;
            function f(int256 balanceDeltaGwei) external pure returns (int256) {
                return balanceDeltaGwei * int256(GWEI_TO_WEI);
            }
        }
    "#;

    // --- Reserve M-14: unsafe `int8(decimals())` reinterpret -----------------

    // M-14 (Reserve OracleLib.price): `-int8(chainlinkFeed.decimals())`. A
    // `decimals()` call returns a `uint8`; a feed reporting `>= 128` decimals
    // wraps the `int8` negative, inverting the shift exponent. The cast is
    // *negated*, so the old `Negated` suppression silenced it — it must now FIRE
    // because the wrap happens inside the cast, before the negate.
    const M14_DECIMALS_CALL_NEGATED: &str = r#"
        pragma solidity 0.8.9;
        interface IFeed { function decimals() external view returns (uint8); }
        contract Oracle {
            function price(IFeed feed) external view returns (uint256) {
                return shiftl(uint256(1e18), -int8(feed.decimals()));
            }
            function shiftl(uint256 x, int8 d) internal pure returns (uint256) { return x; }
        }
    "#;

    // M-14 (Reserve CTokenFiatCollateral.refPerTok): `int8(referenceERC20Decimals)`
    // where `referenceERC20Decimals` is a `uint8 immutable` initialized from the
    // underlying token's `decimals()`. The old `immutable`-is-non-negative
    // suppression silenced it; an immutable set from an *external* `decimals()` is
    // not author-fixed, so it must now FIRE.
    const M14_DECIMALS_IMMUTABLE_SUB: &str = r#"
        pragma solidity 0.8.9;
        contract CToken {
            uint8 public immutable referenceERC20Decimals;
            constructor(uint8 d) { referenceERC20Decimals = d; }
            function refPerTok() public view returns (uint256) {
                int8 shiftLeft = 8 - int8(referenceERC20Decimals) - 18;
                return shiftl(1, shiftLeft);
            }
            function shiftl(uint256 x, int8 d) internal pure returns (uint256) { return x; }
        }
    "#;

    // SAFE counterpart 1: widening a `decimals()` value into `int256` is sign-stable
    // — a `uint8` (0..255) is far inside `int256`'s positive range, so no flip is
    // possible. Must STAY SILENT (the rule is width-gated).
    const M14_DECIMALS_WIDENING_SAFE: &str = r#"
        pragma solidity 0.8.9;
        interface IFeed { function decimals() external view returns (uint8); }
        contract Oracle {
            function f(IFeed feed) external view returns (int256) {
                return int256(feed.decimals());
            }
        }
    "#;

    // SAFE counterpart 2: the decimals value is range-checked before narrowing —
    // `require(d < 128)` makes the sign flip unreachable. The operand-named bound
    // must suppress the cast. Must STAY SILENT.
    const M14_DECIMALS_BOUNDED_SAFE: &str = r#"
        pragma solidity 0.8.9;
        contract C {
            function f(uint8 erc20Decimals) external pure returns (int8) {
                require(erc20Decimals < 128, "too many decimals");
                return -int8(erc20Decimals);
            }
        }
    "#;

    // SAFE counterpart 3: `SafeCast.toInt8` reverts on a `uint8 >= 128`, so the
    // conversion can never silently flip. Must STAY SILENT.
    const M14_DECIMALS_SAFECAST: &str = r#"
        pragma solidity 0.8.9;
        import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
        contract C {
            using SafeCast for uint256;
            uint8 public immutable erc20Decimals;
            function f() external view returns (int8) {
                return SafeCast.toInt8(int256(uint256(erc20Decimals)));
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "signed-cast"));
    }

    #[test]
    fn silent_on_width_safe_cast() {
        let fs = run(WIDTH_SAFE_CAST);
        assert!(!fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn silent_on_width_safe_decl() {
        let fs = run(WIDTH_SAFE_DECL);
        assert!(!fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn fires_on_full_width_uint_to_int() {
        let fs = run(WIDTH_UNSAFE_FULL);
        assert!(fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn silent_when_operand_guarded() {
        let fs = run(GUARDED_REQUIRE);
        assert!(!fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn silent_when_operand_clamped() {
        let fs = run(CLAMPED_MAX);
        assert!(!fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn fires_when_guard_names_other_var() {
        let fs = run(GUARD_OTHER_VAR);
        assert!(fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    // --- R5 dogfood regressions ------------------------------------------

    #[test]
    fn silent_on_pendle_return_tuple_callarg() {
        let fs = run(FP_RETURN_TUPLE_CALLARG);
        assert!(!fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn silent_on_pendle_negated_callarg() {
        let fs = run(FP_NEGATED_CALLARG);
        assert!(!fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn silent_on_return_tuple_no_body_cast() {
        let fs = run(RETURN_TUPLE_NO_BODY_CAST);
        assert!(!fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn silent_on_constant_operand() {
        let fs = run(FP_CONSTANT_OPERAND);
        assert!(!fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn silent_on_unsigned_bounded_subtraction() {
        let fs = run(FP_UNSIGNED_SUB_BOUNDED);
        assert!(!fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn silent_on_unsigned_member_subtraction() {
        let fs = run(FP_UNSIGNED_SUB_MEMBERS);
        assert!(!fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn fires_on_uint_to_int_used_in_comparison() {
        let fs = run(FIRES_UINT_TO_INT_COMPARED);
        assert!(fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn silent_on_sign_checked_operand() {
        let fs = run(FP_SIGN_CHECKED_OPERAND);
        assert!(!fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn silent_on_constant_in_arithmetic() {
        let fs = run(FP_CONSTANT_IN_ARITH);
        assert!(!fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    // --- Reserve M-14 regressions ---------------------------------------

    #[test]
    fn fires_on_m14_decimals_call_negated() {
        let fs = run(M14_DECIMALS_CALL_NEGATED);
        assert!(fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn fires_on_m14_decimals_immutable_subtraction() {
        let fs = run(M14_DECIMALS_IMMUTABLE_SUB);
        assert!(fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn silent_on_m14_decimals_widening() {
        let fs = run(M14_DECIMALS_WIDENING_SAFE);
        assert!(!fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn silent_on_m14_decimals_bounded() {
        let fs = run(M14_DECIMALS_BOUNDED_SAFE);
        assert!(!fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }

    #[test]
    fn silent_on_m14_decimals_safecast() {
        let fs = run(M14_DECIMALS_SAFECAST);
        assert!(!fs.iter().any(|f| f.detector == "signed-cast"), "{:?}", fs);
    }
}
