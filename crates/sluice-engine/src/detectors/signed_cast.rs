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
use crate::detectors::visit_calls;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Call, CallKind, Contract, Expr, ExprKind, Function};

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

            visit_calls(f, |c, span| {
                if c.kind != CallKind::TypeCast {
                    return;
                }
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
                // Provably non-negative arguments cannot flip sign: a literal, a
                // `.length`, or a value already known unsigned/non-negative.
                if is_provably_nonneg(arg) {
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
                    // int -> uint: a negative value wraps to a huge positive.
                    if is_subtraction(arg) {
                        Some(Hazard::SubToUint)
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
                    if arg_is_unsigned_typed(f, contract, arg) {
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

/// True if the expression is provably non-negative and therefore safe to cast
/// to `uint` without a sign flip: a numeric/hex literal, or a `.length` member
/// (array/bytes length is always a non-negative `uint`).
fn is_provably_nonneg(e: &Expr) -> bool {
    let e = peel_int_casts(e);
    match &e.kind {
        ExprKind::Lit(sluice_ir::Lit::Number(_)) | ExprKind::Lit(sluice_ir::Lit::HexNumber(_)) => true,
        ExprKind::Member { member, .. } => member == "length",
        _ => false,
    }
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
            if let Some(end_rel) = src[open..].find(')') {
                let inner = &src[open..open + end_rel];
                if names.iter().any(|n| mentions_ident(inner, n)) {
                    return true;
                }
            }
            from = open;
        }
    }

    // A `require(...)` / `revert`-guarded ordering comparison referencing the
    // operand. We scan each `require(` / `if (` clause head and require both an
    // ordering operator and one of the operand idents inside it.
    for kw in ["require(", "if(", "if ("] {
        let mut from = 0;
        while let Some(rel) = src[from..].find(kw) {
            let open = from + rel + kw.len();
            // Bound the clause at the matching close (best-effort: first ')').
            let end = src[open..].find(')').map(|e| open + e).unwrap_or(src.len());
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
}
