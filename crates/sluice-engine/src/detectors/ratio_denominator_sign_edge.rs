//! Rate/ratio/proportion division whose **denominator is a subtraction**
//! (`r - 1`, `1 - x`, `(a - b)`) that can land exactly on `0` — or, for signed
//! math, flip sign — at a rate/proportion boundary, with no guard excluding that
//! boundary. The result is a div-by-zero revert (a griefing / liveness break) or
//! a sign inversion that silently corrupts the priced amount.
//!
//! ## The shape
//!
//! Pendle's YT/PT order math is the archetype. In `LimitMathCore` the PT↔YT
//! conversion divides by `r - 1`, where `r` is the per-order *exchange rate*
//! (`impliedRateToExchangeRate(...)`, scaled to `1e18 == PMath.ONE`):
//!
//! ```solidity
//! function calcSyForYt(uint256 makeSy, uint256 r, PYIndex index, uint256 f) ... {
//!     uint256 pt_yt_ratio = r - PMath.ONE;          // r - 1  → 0 when r == 1e18
//!     takeYt        = (index.syToAsset(makeSy) * r) / pt_yt_ratio;
//!     fee           = (makeSy * (f - PMath.ONE))   / pt_yt_ratio;
//!     notionalVolume = makeSy.divDown(pt_yt_ratio);
//! }
//! ```
//!
//! Nothing here excludes `r == PMath.ONE`. An implied rate of `0` produces
//! `r == 1e18` exactly, so `pt_yt_ratio == 0` and every one of these divisions
//! reverts — a maker can post such an order and brick the batch fill that touches
//! it. `MarketMathCore._logProportion` has the *same* `IONE - proportion`
//! denominator but is the negative control: it is preceded by
//! `if (proportion == PMath.IONE) revert ...`, so the boundary is excluded and we
//! must stay silent there.
//!
//! ## Why a dedicated detector
//!
//! `rounding-direction` / `internal-share-pricing-rounding` care about the
//! *rounding mode* of an `a * b / c`; they say nothing about whether the
//! denominator `c` can be zero. The `c = x - y` denominator is a distinct defect:
//! the hazard is the *value* of the denominator at a proportion/rate edge, not how
//! the quotient rounds. Solidity reverts on integer div-by-zero, and `unchecked`
//! signed division by a denominator that crosses zero inverts the result's sign —
//! both are silent unless a `require`/`if-revert` pins the rate away from the edge.
//!
//! ## Precision
//!
//! The gate is deliberately narrow so it fires on the genuine ratio math and
//! nothing else:
//!   * the divisor must be (directly, or via a local `x = a - b` binding) a
//!     **`Binary::Sub`** — a plain `total`/`supply` divisor never matches, which
//!     excludes every share/asset `mulDiv` in the FP corpus;
//!   * one operand of that subtraction must read like a **rate / ratio /
//!     proportion** (`rate`, `ratio`, `proportion`, `exchangeRate`, `impliedRate`,
//!     the `pt_yt`/`yt_pt` ratio, or Pendle's single-letter `r`/`f` rate operands)
//!     — a buffer/length subtraction (`recipients.length - i`,
//!     `bufferCapacity - drawDownLimit`) does not match;
//!   * we SUPPRESS when the boundary is provably unreachable: both operands are
//!     constants, or the function guards the rate/divisor against the edge with a
//!     `require`/`if(...revert)` (`== ONE`/`!= ONE`/`> ONE`/`>= ONE`, or
//!     `proportion == IONE` as in `_logProportion`), or a clamping safe-subtract
//!     (`subNoNeg`/`subMax0`) produced the value.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function, Span};

use super::prelude::*;

pub struct RatioDenominatorSignEdgeDetector;

/// Division-family helper method/free-function names whose **last** positional
/// argument is the divisor (`x.divDown(d)`, `Math.mulDiv(a, b, d)`,
/// `a.rawDivUp(d)`). A plain `a / b` binary is handled structurally.
const DIV_HELPERS: &[&str] = &[
    "divdown", "divup", "divwaddown", "divwadup", "divwad", "rawdivup", "rawdiv", "muldiv",
    "muldivdown", "muldivup", "divr", "div",
];

/// Boundary tokens a `rate - X` / `X - rate` subtraction trips over: the `1e18`
/// fixed-point one (`ONE`/`IONE`/`PMath.ONE`/`WAD`/`RAY`) or a literal `1`/`1e18`.
/// When the *other* operand of the subtraction is one of these, the subtraction is
/// the canonical `r - 1` / `1 - x` proportion edge.
fn is_one_boundary(e: &Expr) -> bool {
    match &e.kind {
        // `1` or `1e18` / `1E18` numeric literal.
        ExprKind::Lit(sluice_ir::Lit::Number(n)) => {
            let t = n.trim().to_ascii_lowercase();
            t == "1" || t == "1e18" || t == "1000000000000000000"
        }
        // `ONE` / `IONE` / `WAD` / `RAY` bare identifier.
        ExprKind::Ident(n) => is_one_name(&n.to_ascii_lowercase()),
        // `PMath.ONE` / `PMath.IONE` / `FixedPoint.ONE` member access.
        ExprKind::Member { member, .. } => is_one_name(&member.to_ascii_lowercase()),
        _ => false,
    }
}

fn is_one_name(l: &str) -> bool {
    matches!(l, "one" | "ione" | "wad" | "ray" | "unit" | "one_18" | "wad_int")
}

/// Does a lower-cased identifier read like a rate / ratio / proportion — the
/// quantity whose value near a boundary makes `x - boundary` collapse to zero or
/// flip sign? Substrings cover the descriptive names; the exact single letters
/// `r`/`f` are Pendle's `LimitMathCore` rate/fee operands.
fn is_rate_like_name(l: &str) -> bool {
    l == "r"
        || l == "f"
        || l.contains("rate")
        || l.contains("ratio")
        || l.contains("proportion")
        || l.contains("propor")
        || l.contains("pt_yt")
        || l.contains("yt_pt")
        || l.contains("ptyt")
        || l.contains("logitp")
        || l.contains("logit")
        || l.contains("exchange")
        || l.contains("implied")
}

/// True if any identifier / member name reachable in `e` is rate-like.
fn mentions_rate_like(e: &Expr) -> bool {
    let mut hit = false;
    e.visit(&mut |n| match &n.kind {
        ExprKind::Ident(s) if is_rate_like_name(&s.to_ascii_lowercase()) => hit = true,
        ExprKind::Member { member, .. } if is_rate_like_name(&member.to_ascii_lowercase()) => {
            hit = true
        }
        _ => {}
    });
    hit
}

/// Is `e` a compile-time-constant operand — a numeric/hex literal or a
/// `constant`/`immutable` state var (so a `const - const` subtraction is fixed)?
fn is_constant_operand(cx: &AnalysisContext, f: &Function, e: &Expr) -> bool {
    match &peel_casts(e).kind {
        ExprKind::Lit(sluice_ir::Lit::Number(_)) | ExprKind::Lit(sluice_ir::Lit::HexNumber(_)) => true,
        _ => root_is_const_or_immutable(cx, f, e),
    }
}

/// If `e` is a `Binary::Sub`, return its `(lhs, rhs)`. This is the canonical
/// `r - 1` / `1 - x` / `(a - b)` denominator.
fn as_sub(e: &Expr) -> Option<(&Expr, &Expr)> {
    match &e.kind {
        ExprKind::Binary { op: BinOp::Sub, lhs, rhs } => Some((lhs, rhs)),
        _ => None,
    }
}

/// The set of `(name -> Sub initializer)` local bindings of the form
/// `T x = a - b;` in `f`'s body, so an indirect divisor (`pt_yt_ratio` bound to
/// `r - PMath.ONE`, then divided by) can be resolved back to its subtraction.
fn sub_bindings(f: &Function) -> Vec<(String, &Expr)> {
    let mut out: Vec<(String, &Expr)> = Vec::new();
    for s in &f.body {
        s.visit(&mut |st| {
            if let sluice_ir::StmtKind::VarDecl { name: Some(name), init: Some(init), .. } = &st.kind {
                if as_sub(init).is_some() {
                    out.push((name.clone(), init));
                }
            }
        });
    }
    out
}

/// Resolve the divisor expression to its underlying subtraction `(lhs, rhs)`:
/// either the divisor is *itself* a `Sub`, or it is a bare identifier bound to a
/// `Sub` earlier in the body. Returns the operands so the caller can classify the
/// rate operand and the boundary.
fn resolve_sub_divisor<'a>(
    divisor: &'a Expr,
    bindings: &[(String, &'a Expr)],
) -> Option<(&'a Expr, &'a Expr)> {
    if let Some(s) = as_sub(divisor) {
        return Some(s);
    }
    if let ExprKind::Ident(name) = &divisor.kind {
        for (n, init) in bindings {
            if n == name {
                return as_sub(init);
            }
        }
    }
    None
}

/// All divisor expressions used in `f`'s body, each with the span of the
/// enclosing division. Covers the plain `a / b` binary (divisor = `b`) and the
/// div-family helper calls (`x.divDown(d)` → `d`, `Math.mulDiv(a, b, d)` → `d`).
fn divisors_of(f: &Function) -> Vec<(&Expr, Span)> {
    let mut out: Vec<(&Expr, Span)> = Vec::new();
    for s in &f.body {
        s.visit_exprs(&mut |e| match &e.kind {
            ExprKind::Binary { op: BinOp::Div, rhs, .. } => {
                out.push((rhs, e.span));
            }
            ExprKind::Call(c) => {
                let is_div_helper = c
                    .func_name
                    .as_deref()
                    .map(|n| {
                        let l = n.to_ascii_lowercase();
                        DIV_HELPERS.iter().any(|h| l == *h)
                    })
                    .unwrap_or(false);
                if is_div_helper {
                    if let Some(last) = c.args.last() {
                        out.push((last, e.span));
                    }
                }
            }
            _ => {}
        });
    }
    out
}

/// Textual guard check: does the function body guard `var` (the rate or the
/// divisor binding) against the `1`/`ONE` boundary with a `require`/`if-revert`
/// comparison? Mirrors the template detectors' comment-stripped, lowercased
/// `cx.source_text` keyword approach (`enforces_window_lower_bound`).
///
/// We look for `<var>` adjacent to a comparison operator whose other side is a
/// one-boundary token: `r == one`, `r != one`, `r > one`, `proportion == ione`,
/// `r - 1 == 0`, etc. Any of these excludes the div-by-zero / sign-flip edge.
fn guards_boundary(src: &str, var: &str) -> bool {
    let var = var.to_ascii_lowercase();
    if var.is_empty() {
        return false;
    }
    // Scan each position the var name appears; inspect a small window around it
    // for a comparison against a one-boundary token (or an explicit `== 0`).
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(&var) {
        let at = from + rel;
        // require a word boundary so `r` does not match inside `rate`/`reserve`.
        let prev_ok = at == 0 || !is_ident_char(src.as_bytes()[at - 1] as char);
        let after = at + var.len();
        let next_ok = after >= src.len() || !is_ident_char(src.as_bytes()[after] as char);
        if prev_ok && next_ok {
            // Window: ~48 bytes before and after the identifier.
            let lo = at.saturating_sub(48);
            let hi = (after + 48).min(src.len());
            let window = &src[lo..hi];
            if window_has_boundary_comparison(window) {
                return true;
            }
        }
        from = after;
    }
    false
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Does a source window contain a comparison against a one-boundary (`one`,
/// `ione`, `wad`, `ray`, `1`, `1e18`) or an explicit `== 0` / `!= 0`? This is the
/// "boundary is excluded" signal — `==`/`!=`/`<`/`>`/`<=`/`>=` all count, since any
/// of them lets the code branch away from the edge before dividing.
fn window_has_boundary_comparison(w: &str) -> bool {
    let has_cmp = w.contains("==")
        || w.contains("!=")
        || w.contains(">=")
        || w.contains("<=")
        || w.contains('>')
        || w.contains('<');
    if !has_cmp {
        return false;
    }
    // A boundary token must be present in the same window.
    w.contains("one")
        || w.contains("ione")
        || w.contains("wad")
        || w.contains("ray")
        || w.contains("1e18")
        || w.contains("== 0")
        || w.contains("==0")
        || w.contains("!= 0")
        || w.contains("!=0")
        // bare ` 1` boundary in a comparison (`> 1`, `== 1`); guarded behind the
        // has_cmp check above so it is not a blanket digit match.
        || w.contains(" 1)")
        || w.contains(" 1 ")
        || w.contains(" 1;")
}

impl Detector for RatioDenominatorSignEdgeDetector {
    fn id(&self) -> &'static str {
        "ratio-denominator-sign-edge"
    }
    fn category(&self) -> Category {
        Category::RatioDenominatorSignEdge
    }
    fn description(&self) -> &'static str {
        "Rate/ratio division by a subtraction (`r - 1` / `1 - x`) that can hit zero or flip sign at a proportion boundary with no guard"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || f.is_modifier() || f.is_constructor() {
                continue;
            }
            // Pure interface declarations carry no body math.
            if cx.contract_of(f.id).map(|c| c.is_interface()).unwrap_or(false) {
                continue;
            }

            let bindings = sub_bindings(f);
            let divisors = divisors_of(f);
            if divisors.is_empty() {
                continue;
            }

            // Resolve the function source once for the guard scan.
            let src = cx.source_text(f.span);

            // De-dup: at most one finding per function (the math lib helpers divide
            // by the same `r - 1` several times; one report per routine is enough).
            let mut fired = false;

            for (divisor, span) in &divisors {
                if fired {
                    break;
                }
                let Some((slhs, srhs)) = resolve_sub_divisor(divisor, &bindings) else {
                    continue;
                };

                // The subtraction must involve a rate/ratio/proportion operand.
                let lhs_rate = mentions_rate_like(slhs);
                let rhs_rate = mentions_rate_like(srhs);
                if !lhs_rate && !rhs_rate {
                    continue;
                }

                // --- SUPPRESS: provably non-zero / non-edge denominators ---

                // 1. Both operands are compile-time constants → fixed value.
                if is_constant_operand(cx, f, slhs) && is_constant_operand(cx, f, srhs) {
                    continue;
                }

                // 2. The rate is guarded against the boundary. Check a guard on the
                //    rate operand's root name AND on the divisor binding name (the
                //    `pt_yt_ratio == 0` / `if (proportion == IONE) revert` forms).
                let rate_operand = if lhs_rate { slhs } else { srhs };
                let rate_root = root_ident_str(rate_operand).map(str::to_owned);
                let divisor_name = if let ExprKind::Ident(n) = &divisor.kind {
                    Some(n.to_ascii_lowercase())
                } else {
                    None
                };
                let guarded = rate_root
                    .as_deref()
                    .map(|r| guards_boundary(&src, r))
                    .unwrap_or(false)
                    || divisor_name.as_deref().map(|d| guards_boundary(&src, d)).unwrap_or(false);
                if guarded {
                    continue;
                }

                // --- positive evidence: is it the canonical `r - 1` / `1 - x` edge? ---
                // A one-boundary on the *other* operand (`r - ONE`, `IONE - proportion`)
                // is the strongest signal; a general `(a - b)` of two rate-ish values
                // is weaker (still reportable but lower confidence).
                let one_boundary = is_one_boundary(slhs) || is_one_boundary(srhs);

                // Higher confidence when (a) the denominator is the textbook
                // `rate - 1` edge AND (b) the dividing op is a fixed-point/integer
                // division (already true — it is a Div / div-helper). Single
                // Invariant dimension; Medium needs conf >= 0.47.
                let confidence = if one_boundary { 0.6 } else { 0.5 };

                let why = if one_boundary {
                    "a `rate − 1` / `1 − proportion` subtraction that equals zero exactly when the \
                     rate/proportion hits its `1e18` boundary"
                } else {
                    "a subtraction of two rate/proportion quantities that can equal zero (or, for \
                     signed math, flip sign) at their crossover"
                };

                let b = report!(self, Category::RatioDenominatorSignEdge,
                    title = "Ratio/rate division by a subtraction that can hit zero or flip sign at a boundary",
                    severity = Severity::Medium,
                    confidence = confidence,
                    dimensions = [Dimension::Invariant],
                    message = format!(
                        "`{}` divides by {}, with no `require`/guard excluding that boundary. \
                         Solidity integer division by zero reverts (a liveness / griefing break — \
                         e.g. a single crafted order or proportion that drives the denominator to \
                         exactly zero bricks the calculation), and in `unchecked` signed math a \
                         denominator that crosses zero inverts the quotient's sign and silently \
                         corrupts the priced amount. This is Pendle's `LimitMathCore` PT↔YT math \
                         (`pt_yt_ratio = r - PMath.ONE; ... / pt_yt_ratio`) and the `r − 1` / \
                         `1 − proportion` denominators in `MarketMathCore` / `PYIndex` ratio code: \
                         the hazard is the *value* of the denominator at the rate/proportion edge, \
                         which the rounding-direction detectors do not consider.",
                        f.name, why
                    ),
                    recommendation =
                        "Before dividing, exclude the boundary explicitly: `require(r != PMath.ONE, ...)` \
                         (or `require(r > PMath.ONE)` / `if (proportion == PMath.IONE) revert ...`, as \
                         `MarketMathCore._logProportion` already does) so the `x - boundary` denominator \
                         can never be zero, and for signed math assert the subtraction keeps a fixed \
                         sign. Where a zero rate is legitimate, special-case it instead of letting the \
                         division revert.",
                );
                out.push(finish_at(cx, b, f.id, *span));
                fired = true;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fired(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.detector == "ratio-denominator-sign-edge")
    }

    // VULN — Pendle `LimitMathCore.calcSyForYt`: divides by `pt_yt_ratio = r - 1`
    // (rate exchange-rate minus the `1e18` one) with NO guard on `r == PMath.ONE`,
    // through both an indirect-binding `/ pt_yt_ratio` and a `.divDown(pt_yt_ratio)`.
    const VULN: &str = r#"
        library PMath { }
        library LimitMathCore {
            uint256 internal constant ONE = 1e18;
            function calcSyForYt(uint256 makeSy, uint256 r, uint256 f)
                internal pure returns (uint256 takeYt, uint256 fee, uint256 notionalVolume)
            {
                uint256 pt_yt_ratio = r - PMath.ONE;
                takeYt = (makeSy * r) / pt_yt_ratio;
                fee = (makeSy * (f - PMath.ONE)) / pt_yt_ratio;
                notionalVolume = makeSy.divDown(pt_yt_ratio);
            }
        }
    "#;

    // VULN — direct `1 - x` denominator in a method-call divisor with no guard.
    const VULN_DIRECT: &str = r#"
        library PMath { }
        library Lib {
            int256 internal constant IONE = 1e18;
            function logitNoGuard(int256 proportion) internal pure returns (int256) {
                int256 logitP = proportion.divDown(PMath.IONE - proportion);
                return logitP;
            }
        }
    "#;

    // SAFE — Pendle `MarketMathCore._logProportion`: SAME `IONE - proportion`
    // denominator, but the line above excludes the edge: `if (proportion == IONE)
    // revert`. The boundary is guarded → no finding.
    const SAFE_GUARDED: &str = r#"
        library PMath { }
        library MarketMathCore {
            int256 internal constant IONE = 1e18;
            function _logProportion(int256 proportion) internal pure returns (int256 res) {
                if (proportion == PMath.IONE) revert();
                int256 logitP = proportion.divDown(PMath.IONE - proportion);
                res = logitP;
            }
        }
    "#;

    // SAFE — explicit `require(r != ONE)` guard before the `r - 1` division.
    const SAFE_REQUIRE: &str = r#"
        library PMath { }
        library Lib {
            uint256 internal constant ONE = 1e18;
            function calc(uint256 makeSy, uint256 r) internal pure returns (uint256) {
                require(r != PMath.ONE, "rate one");
                uint256 pt_yt_ratio = r - PMath.ONE;
                return makeSy / pt_yt_ratio;
            }
        }
    "#;

    // SAFE (negative control) — denominator is a subtraction, but neither operand
    // is a rate/ratio/proportion (`recipients.length - i`): the Renzo
    // PaymentSplitter shape. Must stay silent.
    const SAFE_NOT_RATE: &str = r#"
        contract PaymentSplitter {
            function pay(uint256 amountLeftToPay, address[] memory recipients) internal pure returns (uint256) {
                uint256 acc;
                for (uint256 i = 0; i < recipients.length; i++) {
                    acc += amountLeftToPay / (recipients.length - i);
                }
                return acc;
            }
        }
    "#;

    // SAFE (negative control) — a plain pro-rata `shares * total / supply` divisor
    // (no subtraction at all). Must stay silent (it is the share-pricing class).
    const SAFE_SHARE: &str = r#"
        contract Vault {
            function conv(uint256 shares, uint256 totalAssets, uint256 totalSupply) internal pure returns (uint256) {
                return shares * totalAssets / totalSupply;
            }
        }
    "#;

    #[test]
    fn fires_on_pendle_pt_yt_ratio() {
        assert!(fired(&run(VULN)), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_direct_one_minus_x() {
        assert!(fired(&run(VULN_DIRECT)), "{:#?}", run(VULN_DIRECT));
    }

    #[test]
    fn silent_when_boundary_guarded_if_revert() {
        assert!(!fired(&run(SAFE_GUARDED)), "{:#?}", run(SAFE_GUARDED));
    }

    #[test]
    fn silent_when_require_guard() {
        assert!(!fired(&run(SAFE_REQUIRE)), "{:#?}", run(SAFE_REQUIRE));
    }

    #[test]
    fn silent_on_non_rate_subtraction() {
        assert!(!fired(&run(SAFE_NOT_RATE)), "{:#?}", run(SAFE_NOT_RATE));
    }

    #[test]
    fn silent_on_plain_share_pricing() {
        assert!(!fired(&run(SAFE_SHARE)), "{:#?}", run(SAFE_SHARE));
    }
}
