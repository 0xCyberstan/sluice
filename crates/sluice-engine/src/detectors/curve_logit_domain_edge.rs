//! AMM-curve logit/log-exp math evaluated at a proportion-domain singularity with
//! floor (`divDown`) rounding and no epsilon margin.
//!
//! Constant-product / yield-curve AMMs that price with a logarithmic invariant
//! express the marginal exchange rate through a **logit of the pool proportion**,
//! `logit(p) = ln(p / (1 - p))`, and feed it into `ln` / `exp`. The proportion
//! `p = totalPt / (totalPt + totalAsset)` is bounded above by `1.0` (the `1 - p`
//! denominator) and, in practice, by a `MAX_PROPORTION` constant just below `1.0`.
//! As `p -> 1`, `1 - p -> 0` and `ln(p/(1-p)) -> +inf`: the function is steepest
//! and least numerically stable **exactly at the boundary the protocol allows a
//! trade to push it to**.
//!
//! Two things make a near-boundary trade exploitable here:
//!   * the divisions are **floor** divisions (`divDown` — OZ-style "round toward
//!     zero"), so every step rounds the proportion / logit *down*, and the
//!     direction of that bias is fixed and predictable; and
//!   * the boundary guard is an **exact** comparison with no cushion — either
//!     `proportion == ONE` (revert only on the unreachable exact tie) or
//!     `proportion > MAX_PROPORTION` (reject only strictly past the constant). No
//!     `proportion < MAX_PROPORTION - eps` margin is kept, so a crafted trade can
//!     sit one wei inside the bound where the curve is near-vertical and the floor
//!     rounding misprices the swap in the attacker's favour.
//!
//! This is the **Pendle** rate-scalar / rate-anchor curve in
//! `core/Market/MarketMathCore.sol` (`_logProportion`, `_getExchangeRate`,
//! `_getRateAnchor`) on top of `LogExpMath` / `PMath.divDown`:
//!
//! ```solidity
//! function _logProportion(int256 proportion) internal pure returns (int256 res) {
//!     if (proportion == PMath.IONE) revert Errors.MarketProportionMustNotEqualOne();
//!     int256 logitP = proportion.divDown(PMath.IONE - proportion); // x / (ONE - x), floored
//!     res = logitP.ln();
//! }
//! ```
//!
//! ## Why this escapes the name-gated rounding detector
//!
//! `rounding-direction` only inspects externally-reachable, state-mutating
//! functions whose *name* is a conversion entry point
//! (`mint`/`deposit`/`withdraw`/`redeem`/`burn`). This curve math lives in
//! `internal pure` library helpers (`_logProportion`, `_getExchangeRate`,
//! `_getRateAnchor`) — none of those names match — so the rounding detector never
//! looks at them. It is also a *domain-edge precision* defect, not the plain
//! "unspecified rounding mode on a share/asset `a*b/c`" the rounding detectors
//! model: the bias comes from floor rounding a logit evaluated next to a `1.0` /
//! `MAX_PROPORTION` singularity, which neither rounding detector reasons about.
//!
//! ## Gate (all required to fire)
//!   1. a **floor division** is present — a `divDown`-family call (the named
//!      OZ-style floor; this is the exact rounding direction the defect rides on);
//!   2. **logit / log-exp curve math** is present — either the literal
//!      `x / (ONE - x)` logit shape (a `divDown` / `/` whose divisor is
//!      `ONE - dividend`), or a `ln` / `exp` / `LogExpMath` call, or a call into a
//!      `*logProportion*` / `*ExchangeRate*` curve helper / an `lnProportion`
//!      value; and
//!   3. a **proportion singularity anchor** nearby — the `x / (ONE - x)` shape
//!      itself, a `proportion` / `logProportion` identifier, or a
//!      `MAX_*PROPORTION` bound.
//!
//! ## Suppression (a deliberate margin / ceil was applied)
//!   * a **margin guard** — a comparison (`<`/`>`/`<=`/`>=`, in a `require` / `if`
//!     / `revert`) against a bound that is itself `MAX - eps` / `ONE - eps`
//!     (a subtraction off a MAX/ONE constant): the protocol keeps a cushion away
//!     from the singularity, so the edge is not reachable;
//!   * a **fractional safety margin** — the `* 999 / 1000` ("take 99.9% of the
//!     theoretical max to absorb precision") idiom (Pendle's `calcMaxPtOut`); or
//!   * **ceil rounding** — `divUp` / `rawDivUp` / `mulDivUp` / `Rounding.Ceil`
//!     / `Rounding.Up` / `ceilDiv` / the `+ ... - 1` ceil idiom — rounding was
//!     pinned in the protective direction.
//!
//! An **exact-equality** guard (`proportion == ONE`) is *not* a margin guard —
//! it only rejects the unreachable exact tie and leaves the near-boundary region
//! open — so it does not suppress.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function, Span};

use super::prelude::*;

pub struct CurveLogitDomainEdgeDetector;

impl Detector for CurveLogitDomainEdgeDetector {
    fn id(&self) -> &'static str {
        "curve-logit-domain-edge"
    }
    fn category(&self) -> Category {
        Category::CurveLogitDomainEdge
    }
    fn description(&self) -> &'static str {
        "AMM logit/log-exp curve math floored (divDown) at a 1.0 / MAX_PROPORTION singularity with no epsilon margin"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Curve math lives in pure helpers, not modifiers/constructors.
            if f.is_modifier() || f.is_constructor() {
                continue;
            }

            // (1) A floor division (`divDown`-family) — the rounding direction the
            // domain-edge bias rides on. The whole class is about flooring a logit
            // next to a singularity, so a named floor div is required.
            let Some(floor_span) = first_floor_div(f) else {
                continue;
            };

            // (2) Logit / log-exp curve math present, and (3) a proportion
            // singularity anchor nearby. The literal `x/(ONE-x)` logit shape
            // satisfies both at once and is also the strongest single signal.
            let logit = logit_shape_span(f);
            let has_curve = logit.is_some() || has_log_exp_call(f) || calls_curve_helper(f);
            let has_anchor = logit.is_some() || mentions_proportion_anchor(cx, f);
            if !has_curve || !has_anchor {
                continue;
            }

            // ---- suppression: a deliberate margin / ceil was applied ----
            if has_margin_or_ceil(cx, f) {
                continue;
            }

            // Report at the logit shape if we found it (most specific), else at
            // the floor-division site.
            let span = logit.unwrap_or(floor_span);

            let b = report!(self, Category::CurveLogitDomainEdge,
                title = "AMM logit/log-exp curve floored at a proportion singularity with no margin",
                severity = Severity::Medium,
                confidence = 0.6,
                dimensions = [Dimension::ValueFlow],
                message = format!(
                    "`{}` evaluates AMM curve math — a logit `ln(p/(1-p))` / a `ln`/`exp` over a pool \
                     proportion — with **floor** division (`divDown`, round toward zero) while the \
                     proportion can be pushed to its `1.0` / `MAX_PROPORTION` singularity. As `p -> 1` the \
                     `1 - p` denominator goes to zero and the logit goes to infinity, so the curve is \
                     near-vertical and least stable exactly at the boundary a trade is allowed to reach; \
                     the only guard is an exact comparison (`proportion == ONE` / `proportion > \
                     MAX_PROPORTION`) with no epsilon cushion. A crafted near-boundary trade exploits the \
                     fixed-direction floor rounding to misprice the swap a few wei in its own favour — the \
                     curve-logit domain-edge precision class (Pendle `MarketMathCore` rate-scalar / \
                     rate-anchor / `_logProportion` on `LogExpMath` + `PMath.divDown`). This internal \
                     `pure` curve helper is not a `mint`/`deposit`/`withdraw` conversion entry point, so \
                     the name-gated rounding-direction detector never inspects it.",
                    f.name
                ),
                recommendation =
                    "Keep an explicit margin away from the singularity — bound the proportion with \
                     `require(proportion < MAX_PROPORTION - eps)` (or take only `* 999 / 1000` of the \
                     theoretical max) so a trade cannot sit one wei inside the boundary — and round the \
                     logit/exchange-rate computation in the protocol-protective direction (round the \
                     proportion up toward the bound and the resulting cost up, e.g. a `divUp`/ceil on the \
                     amount the trader must pay) rather than flooring every step. Add fuzz/property tests \
                     that push the proportion to `MAX_PROPORTION` and assert the priced amount never \
                     favours the caller.",
            );
            out.push(finish_at(cx, b, f.id, span));
        }
        out
    }
}

// =================================================================== curve shapes

/// `divDown`-family floor-division call names (OZ / PMath "round toward zero").
fn is_floor_div_name(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    l == "divdown" || l == "rawdivdown" || l == "muldivdown" || l == "floordiv"
}

/// Span of the first `divDown`-family floor-division call in `f`, if any.
fn first_floor_div(f: &Function) -> Option<Span> {
    first_call_where(f, |c| {
        c.func_name.as_deref().is_some_and(is_floor_div_name)
    })
}

/// Is `e` a `ONE` / `IONE` / `WAD` constant or the `1e18` literal (the
/// fixed-point unit that the logit denominator `ONE - x` is built from)?
fn is_one_scale(e: &Expr) -> bool {
    match &peel_casts(e).kind {
        ExprKind::Member { member, .. } => is_one_token(member),
        ExprKind::Ident(n) => is_one_token(n),
        ExprKind::Lit(sluice_ir::Lit::Number(n)) => {
            let t = n.trim().replace('_', "");
            t == "1000000000000000000" || t.eq_ignore_ascii_case("1e18")
        }
        _ => false,
    }
}

fn is_one_token(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    l == "one" || l == "ione" || l == "wad" || l == "unit" || l == "ray"
}

/// The literal logit shape `x / (ONE - x)`: a floor-division (`divDown` call) or a
/// bare `/` whose **divisor** is `ONE - dividend`. The dividend is the `divDown`
/// receiver (or the `/` numerator); the subtrahend of the `ONE - …` must
/// root-resolve to that same dividend. Returns the span of the offending
/// expression.
fn logit_shape_span(f: &Function) -> Option<Span> {
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            match &e.kind {
                // `dividend.divDown(ONE - dividend)`
                ExprKind::Call(c) if c.func_name.as_deref().is_some_and(is_floor_div_name) => {
                    if let (Some(recv), Some(div)) = (c.receiver.as_deref(), c.args.first()) {
                        if is_one_minus_of(div, recv) {
                            found = Some(e.span);
                        }
                    }
                }
                // bare `dividend / (ONE - dividend)`
                ExprKind::Binary { op: BinOp::Div, lhs, rhs } => {
                    if is_one_minus_of(rhs, lhs) {
                        found = Some(e.span);
                    }
                }
                _ => {}
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// Is `divisor` the shape `ONE - dividend` — a subtraction whose minuend is a
/// `ONE`/`IONE`/`WAD` scale constant and whose subtrahend root-resolves to the
/// same root identifier as `dividend`? This is the `1 - p` logit denominator.
fn is_one_minus_of(divisor: &Expr, dividend: &Expr) -> bool {
    let ExprKind::Binary { op: BinOp::Sub, lhs, rhs } = &divisor.kind else {
        return false;
    };
    if !is_one_scale(lhs) {
        return false;
    }
    match (root_ident_peeled(dividend), root_ident_peeled(rhs)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Does `f` call a logarithm / exponential — `ln` / `exp` / `log2` / `log` as a
/// method (`x.ln()`) or a `LogExpMath.*` free call? These are the transcendental
/// curve primitives.
fn has_log_exp_call(f: &Function) -> bool {
    any_call_where(f, |c| {
        if let Some(n) = c.func_name.as_deref() {
            let l = n.to_ascii_lowercase();
            if l == "ln" || l == "exp" || l == "log2" || l == "log" || l == "pow" {
                return true;
            }
        }
        // `LogExpMath.exp(...)` style: a math-namespace receiver carrying the lib name.
        if let Some(recv) = c.receiver.as_deref() {
            if let ExprKind::Ident(r) = &recv.kind {
                if r.to_ascii_lowercase().contains("logexp") {
                    return true;
                }
            }
        }
        false
    })
}

/// Does `f` call a curve helper that itself computes the logit/exchange-rate —
/// `*logProportion*` / `*ExchangeRate*` / `*RateAnchor*` — or reference an
/// `lnProportion`-style value? This carries the curve math through one call hop
/// (e.g. `_getExchangeRate` -> `_logProportion`).
fn calls_curve_helper(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            match &e.kind {
                ExprKind::Call(c) => {
                    if let Some(n) = c.func_name.as_deref() {
                        let l = n.to_ascii_lowercase();
                        if l.contains("logproportion")
                            || l.contains("exchangerate")
                            || l.contains("rateanchor")
                        {
                            found = true;
                        }
                    }
                }
                ExprKind::Ident(n) => {
                    if n.to_ascii_lowercase().contains("lnproportion") {
                        found = true;
                    }
                }
                _ => {}
            }
        });
        if found {
            break;
        }
    }
    found
}

/// Does `f`'s source mention a proportion-singularity anchor — a
/// `proportion` / `logProportion` identifier or a `MAX_*PROPORTION` bound? Done
/// textually so it catches the bound constant, the local `proportion`, and the
/// `lnProportion` carry-through uniformly.
fn mentions_proportion_anchor(cx: &AnalysisContext, f: &Function) -> bool {
    let src = cx.source_text(f.span).to_ascii_lowercase();
    src.contains("proportion")
}

// =================================================================== suppression

/// Suppress when the function keeps a deliberate margin away from the singularity
/// or rounds in the protective (ceil) direction.
fn has_margin_or_ceil(cx: &AnalysisContext, f: &Function) -> bool {
    // Ceil rounding / explicit round-up: rounding was pinned protectively.
    let src = cx.source_text(f.span).to_ascii_lowercase();
    if src.contains("divup")
        || src.contains("rawdivup")
        || src.contains("muldivup")
        || src.contains("rounding.up")
        || src.contains("rounding.ceil")
        || src.contains("ceildiv")
        || src.contains("roundup")
    {
        return true;
    }
    // Structural margin / ceil shapes.
    has_margin_comparison(f) || has_fractional_margin(f) || has_ceil_idiom(f)
}

/// A **margin guard**: a comparison (`<`/`>`/`<=`/`>=`) where one side is a
/// `MAX - eps` / `ONE - eps` subtraction — i.e. the bound is pulled *below* the
/// MAX/ONE constant by a cushion (`require(proportion < MAX_PROPORTION - eps)`).
/// An exact comparison against a bare `MAX_PROPORTION` constant (no subtraction)
/// is **not** a margin — that is the defect, not the fix — so it does not match.
fn has_margin_comparison(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
                if matches!(op, BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge) {
                    if is_bound_minus_eps(lhs) || is_bound_minus_eps(rhs) {
                        found = true;
                    }
                }
            }
        });
        if found {
            break;
        }
    }
    found
}

/// Is `e` a `BOUND - eps` subtraction whose minuend is a `MAX*`/`*PROPORTION` or
/// `ONE`/`WAD` bound and whose subtrahend is a small/non-bound cushion? This is
/// the `MAX_PROPORTION - eps` margin off the singularity.
fn is_bound_minus_eps(e: &Expr) -> bool {
    let ExprKind::Binary { op: BinOp::Sub, lhs, .. } = &e.kind else {
        return false;
    };
    is_bound_token(lhs)
}

/// A boundary constant the margin is measured from: a `MAX*` / `*PROPORTION`
/// limit, or the `ONE`/`IONE`/`WAD` fixed-point unit (the `1 - p` ceiling).
fn is_bound_token(e: &Expr) -> bool {
    match &peel_casts(e).kind {
        ExprKind::Member { member, .. } => bound_name(member),
        ExprKind::Ident(n) => bound_name(n),
        _ => is_one_scale(e),
    }
}

fn bound_name(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    l.contains("max") || l.contains("proportion") || is_one_token(n) || l.contains("bound")
}

/// The `* N / M` fractional-margin idiom with `N` just below `M` (take 99.x% of a
/// theoretical max to absorb precision) — Pendle's `(maxPtOut * 999) / 1000`.
/// Matches a `Div` whose numerator contains a `Mul` by an integer literal and
/// whose divisor is an integer literal strictly greater than that factor, with
/// the factor at least 90% of the divisor (a near-1 scaling, not a unit
/// conversion like `/ 1e18`).
fn has_fractional_margin(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Binary { op: BinOp::Div, lhs, rhs } = &e.kind {
                let Some(denom) = int_lit_value(rhs) else { return };
                if denom == 0 {
                    return;
                }
                lhs.visit(&mut |n| {
                    if let ExprKind::Binary { op: BinOp::Mul, lhs: ml, rhs: mr } = &n.kind {
                        for factor in [int_lit_value(ml), int_lit_value(mr)].into_iter().flatten() {
                            // factor < denom and factor >= 90% of denom => a near-1 margin.
                            if factor < denom && factor.saturating_mul(100) >= denom.saturating_mul(90)
                            {
                                found = true;
                            }
                        }
                    }
                });
            }
        });
        if found {
            break;
        }
    }
    found
}

/// The `(a * b + c - 1) / c` ceil-division idiom: a `Div` whose numerator
/// subtracts `1`. Its presence means rounding was deliberately rounded up.
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
        if found {
            break;
        }
    }
    found
}

/// Decimal integer-literal value of `e`, if it is a plain integer literal.
fn int_lit_value(e: &Expr) -> Option<u128> {
    if let ExprKind::Lit(sluice_ir::Lit::Number(n)) = &peel_casts(e).kind {
        n.trim().replace('_', "").parse::<u128>().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fired(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.detector == "curve-logit-domain-edge")
    }

    // Vulnerable (Pendle `_logProportion` shape): the logit `x / (ONE - x)` is
    // computed with a floor `divDown` and fed to `ln`; the only guard is the
    // exact tie `proportion == IONE`, with no epsilon margin off the 1.0
    // singularity. This internal `pure` helper is not a conversion entry point,
    // so the name-gated rounding detector never inspects it.
    const VULN_LOGIT: &str = r#"
        library PMath { int256 internal constant IONE = 1e18; }
        library MarketMathCore {
            using PMath for int256;
            using LogExpMath for int256;
            function _logProportion(int256 proportion) internal pure returns (int256 res) {
                if (proportion == PMath.IONE) revert E.MarketProportionMustNotEqualOne();
                int256 logitP = proportion.divDown(PMath.IONE - proportion);
                res = logitP.ln();
            }
        }
    "#;

    // Vulnerable (Pendle `_getExchangeRate` shape): floor `divDown` of the
    // proportion, an EXACT `proportion > MAX_MARKET_PROPORTION` bound (no eps),
    // and the logit carried through `_logProportion` / `lnProportion`.
    const VULN_EXCHANGE_RATE: &str = r#"
        library PMath { int256 internal constant IONE = 1e18; }
        library MarketMathCore {
            using PMath for int256;
            int256 internal constant MAX_MARKET_PROPORTION = (1e18 * 96) / 100;
            function _logProportion(int256 proportion) internal pure returns (int256) {}
            function _getExchangeRate(
                int256 totalPt, int256 totalAsset, int256 rateScalar, int256 rateAnchor, int256 netPtToAccount
            ) internal pure returns (int256 exchangeRate) {
                int256 numerator = totalPt.subNoNeg(netPtToAccount);
                int256 proportion = (numerator.divDown(totalPt + totalAsset));
                if (proportion > MAX_MARKET_PROPORTION) {
                    revert E.MarketProportionTooHigh(proportion, MAX_MARKET_PROPORTION);
                }
                int256 lnProportion = _logProportion(proportion);
                exchangeRate = lnProportion.divDown(rateScalar) + rateAnchor;
            }
        }
    "#;

    // Safe: same curve, but a real MARGIN is kept off the boundary —
    // `require(proportion < MAX_PROPORTION - MARGIN)` pulls the bound below the
    // singularity, so the near-vertical region is unreachable.
    const SAFE_MARGIN: &str = r#"
        library PMath { int256 internal constant IONE = 1e18; }
        library MarketMathCore {
            using PMath for int256;
            using LogExpMath for int256;
            int256 internal constant MAX_PROPORTION = (1e18 * 96) / 100;
            int256 internal constant MARGIN = 1e15;
            function _logProportion(int256 proportion) internal pure returns (int256 res) {
                require(proportion < MAX_PROPORTION - MARGIN, "near edge");
                int256 logitP = proportion.divDown(PMath.IONE - proportion);
                res = logitP.ln();
            }
        }
    "#;

    // Safe (Pendle `calcMaxPtOut` shape): an inverse-logit `x/(x+ONE)` with `exp`,
    // but the result is deliberately shaved to 99.9% of the theoretical max
    // (`* 999 / 1000`) to absorb precision at the boundary.
    const SAFE_FRACTIONAL_MARGIN: &str = r#"
        library PMath { int256 internal constant IONE = 1e18; }
        library MarketApprox {
            using PMath for int256;
            using LogExpMath for int256;
            function calcMaxPtOut(int256 totalPt, int256 totalAsset, int256 rateScalar, int256 rateAnchor, int256 feeRate)
                internal pure returns (uint256)
            {
                int256 logitP = (feeRate - rateAnchor).mulDown(rateScalar).exp();
                int256 proportion = logitP.divDown(logitP + PMath.IONE);
                int256 numerator = proportion.mulDown(totalPt + totalAsset);
                int256 maxPtOut = totalPt - numerator;
                return (uint256(maxPtOut) * 999) / 1000;
            }
        }
    "#;

    // Safe (ceil rounding): the curve evaluates the proportion but rounds the
    // logit denominator up with a `rawDivUp`, the protective direction.
    const SAFE_CEIL: &str = r#"
        library PMath { int256 internal constant IONE = 1e18; }
        library MarketMathCore {
            using PMath for int256;
            using LogExpMath for int256;
            int256 internal constant MAX_PROPORTION = (1e18 * 96) / 100;
            function _logProportion(int256 proportion) internal pure returns (int256 res) {
                int256 logitP = proportion.divDown(PMath.IONE - proportion);
                int256 adj = proportion.rawDivUp(MAX_PROPORTION);
                res = logitP.ln() + adj;
            }
        }
    "#;

    // Negative control: a plain pro-rata share conversion with `divDown` — no
    // logit shape, no ln/exp, no proportion singularity. Must stay silent
    // (this is the territory of the rounding / internal-share-pricing detectors).
    const SAFE_PLAIN_DIVDOWN: &str = r#"
        library Math { }
        contract Vault {
            using PMath for uint256;
            function _toShares(uint256 amount, uint256 totalAssets, uint256 totalShares)
                internal pure returns (uint256)
            {
                return amount.divDown(totalAssets) * totalShares;
            }
        }
    "#;

    // Negative control: a `ln`-based implied-rate helper that divides by time, but
    // touches no pool proportion / 1.0 singularity (no `proportion`, no logit,
    // no MAX_PROPORTION). Must stay silent.
    const SAFE_LN_NO_PROPORTION: &str = r#"
        library M {
            using PMath for int256;
            using LogExpMath for int256;
            uint256 internal constant IMPLIED_RATE_TIME = 365 days;
            function _getLnImpliedRate(int256 exchangeRate, uint256 timeToExpiry)
                internal pure returns (uint256 lnImpliedRate)
            {
                uint256 lnRate = exchangeRate.ln().Uint();
                lnImpliedRate = (lnRate * IMPLIED_RATE_TIME) / timeToExpiry;
            }
        }
    "#;

    #[test]
    fn fires_on_logit_leaf() {
        let fs = run(VULN_LOGIT);
        assert!(fired(&fs), "{:#?}", fs);
    }

    #[test]
    fn fires_on_exchange_rate() {
        let fs = run(VULN_EXCHANGE_RATE);
        assert!(fired(&fs), "{:#?}", fs);
    }

    #[test]
    fn silent_with_margin_guard() {
        let fs = run(SAFE_MARGIN);
        assert!(!fired(&fs), "{:#?}", fs);
    }

    #[test]
    fn silent_with_fractional_margin() {
        let fs = run(SAFE_FRACTIONAL_MARGIN);
        assert!(!fired(&fs), "{:#?}", fs);
    }

    #[test]
    fn silent_with_ceil_rounding() {
        let fs = run(SAFE_CEIL);
        assert!(!fired(&fs), "{:#?}", fs);
    }

    #[test]
    fn silent_on_plain_divdown() {
        let fs = run(SAFE_PLAIN_DIVDOWN);
        assert!(!fired(&fs), "{:#?}", fs);
    }

    #[test]
    fn silent_on_ln_without_proportion() {
        let fs = run(SAFE_LN_NO_PROPORTION);
        assert!(!fired(&fs), "{:#?}", fs);
    }
}
