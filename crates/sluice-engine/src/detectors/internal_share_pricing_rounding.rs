//! Internal share/stake pro-rata pricing that floors with no rounding control —
//! the half of the rounding-direction class that lives **below** the public
//! conversion entry points and so escapes the `rounding-direction` detector.
//!
//! `rounding.rs` only inspects externally-reachable, state-mutating functions
//! whose *name* is a conversion entry point (`mint`/`deposit`/`withdraw`/
//! `redeem`/`burn`/`issue`). But in many real systems the pro-rata maths does
//! not live there: the entry point is a thin wrapper that delegates the actual
//! `stake * shares / totalShares` (or `amount * total / supply`) computation to
//! an **internal / private helper** with a name like `_stakeAt`, `_sharesOf`,
//! `_balanceAt`, `_valueOf`, `_activeStake`. Solidity integer division floors
//! toward zero, so a helper that floor-divides a stake/share quantity and pins
//! no rounding mode rounds *against the protocol* (or against whichever party
//! the floor disfavours) a few wei per call — and because the helper is private
//! and mis-named, the existing detector never looks at it.
//!
//! This is the shape behind Symbiotic's `NetworkRestakeDelegator._stakeAt` /
//! `_sharesAt` family: the public `stakeAt(...)` view forwards to an internal
//! `_stakeAt(...)` that computes `activeStake * activeSharesOf / activeShares`
//! with a bare floor division. The rounding direction there is load-bearing for
//! how slashing and withdrawals settle across operators, yet it is expressed in
//! an internal helper a name-gated detector cannot see.
//!
//! Precision (this MUST NOT flood ordinary maths):
//!   * we ONLY look at functions the `rounding-direction` detector cannot reach,
//!     i.e. functions that are *not* (externally-reachable AND state-mutating AND
//!     conversion-named). That is the exact complement, so we never double-report
//!     its cases;
//!   * the function must contain a literal `a * b / c` mul-then-div shape (not a
//!     `mulDiv(...)` helper call — that helper is precisely where a rounding-mode
//!     argument lives, and matching it would re-tread `rounding.rs`);
//!   * the maths must relate to stake/share/amount/balance/weight, evidenced by
//!     the function name OR a state variable / identifier the function touches;
//!   * we suppress when any rounding control is present nearby (`mulDivUp` /
//!     `mulDivDown` / `ceilDiv` / `Rounding.*` / the `+ c - 1` ceil idiom),
//!     exactly mirroring `rounding.rs`'s suppression so a deliberately-rounded
//!     helper stays quiet.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function};

pub struct InternalSharePricingRoundingDetector;

/// Name fragments that mark a quantity as pro-rata stake/share accounting — the
/// thing whose floor-rounding direction is load-bearing.
const PRORATA_MARKERS: &[&str] = &["stake", "share", "amount", "balance", "weight"];

/// The conversion entry-point names owned by `rounding-direction`. Mirrors that
/// detector's `is_conversion_name`; kept in sync so our reachability complement
/// is exact.
const CONVERSION_NAMES: &[&str] = &["mint", "deposit", "issue", "withdraw", "redeem", "burn"];

impl Detector for InternalSharePricingRoundingDetector {
    fn id(&self) -> &'static str {
        "internal-share-pricing-rounding"
    }
    fn category(&self) -> Category {
        Category::InternalSharePricingRounding
    }
    fn description(&self) -> &'static str {
        "Internal/private share or stake pro-rata helper floor-divides with no rounding control (escapes rounding-direction)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // A modifier/constructor isn't a pricing helper.
            if f.is_modifier() || f.is_constructor() {
                continue;
            }
            // ---- reachability complement of `rounding-direction` ----
            // `rounding.rs` fires exactly on (externally reachable && state
            // mutating && conversion-named). We deliberately take the COMPLEMENT
            // so we never double-report its cases: we only proceed for functions
            // that detector cannot reach — i.e. internal/private helpers, view
            // pricing getters, or oddly-named state-mutating functions.
            let owned_by_rounding =
                f.is_externally_reachable() && f.is_state_mutating() && is_conversion_name(&f.name);
            if owned_by_rounding {
                continue;
            }

            // The pro-rata mul-then-div shape (literal `a * b / c`, not a helper).
            let Some(span) = find_mul_div(f) else {
                continue;
            };

            // It must actually be stake/share/amount/balance/weight accounting,
            // evidenced by the function name or a variable/identifier it touches.
            if !relates_to_prorata(f) {
                continue;
            }

            // Suppress when a rounding direction is pinned (helper or ceil idiom).
            if uses_explicit_rounding(cx, f) {
                continue;
            }

            let b = FindingBuilder::new(self.id(), Category::InternalSharePricingRounding)
                .title("Internal share/stake pricing floor-divides with no rounding control")
                .severity(Severity::Low)
                .confidence(0.4)
                .dimension(Dimension::Invariant)
                .message(format!(
                    "`{}` computes a pro-rata stake/share quantity with a bare integer `a * b / c` \
                     division but pins no rounding mode, and it is not one of the externally-named \
                     conversion entry points (`deposit`/`withdraw`/`redeem`/`mint`/`burn`) that the \
                     `rounding-direction` detector inspects — it is an internal/private (or \
                     view-helper) pricing routine. Solidity division truncates toward zero, so the \
                     floored result rounds against the protocol a few wei per call; in restaking / \
                     pooled-stake systems (e.g. Symbiotic's `NetworkRestakeDelegator._stakeAt` / \
                     `_sharesAt`) this internal rounding direction governs how slashing and \
                     withdrawals settle and can be biased by repeated dust-sized interactions.",
                    f.name
                ))
                .recommendation(
                    "Pin the rounding direction in the helper to favor the protocol: use a \
                     `mulDivDown` / `mulDivUp` (or OpenZeppelin `Math.mulDiv(a, b, c, Rounding.*)`) \
                     with the direction chosen so the residual accrues to the pool, and assert the \
                     share/stake invariant (sum of parts <= whole) at the call sites. Treat the \
                     internal pricing helper with the same ERC-4626 \"rounding favors the vault\" \
                     discipline as the public conversion functions.",
                );
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

/// A conversion entry point name (mirrors `rounding::is_conversion_name`).
fn is_conversion_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    CONVERSION_NAMES.iter().any(|k| l.contains(k))
}

/// Detect a proportional `a * b / c`: a `Div` whose numerator contains a `Mul`,
/// or a `Mul` with a `Div` operand. We deliberately do NOT match a `mulDiv(...)`
/// helper call here — that helper is exactly where a `Rounding` argument lives,
/// and is `rounding.rs`'s territory. Returns the span of the offending division.
fn find_mul_div(f: &Function) -> Option<sluice_ir::Span> {
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            match &e.kind {
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
                _ => {}
            }
        });
    }
    found
}

fn is_div(e: &Expr) -> bool {
    matches!(e.kind, ExprKind::Binary { op: BinOp::Div, .. })
}

/// True if `e` is a `Mul`, or transitively contains one.
fn contains_mul(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |n| {
        if let ExprKind::Binary { op: BinOp::Mul, .. } = &n.kind {
            found = true;
        }
    });
    found
}

/// The maths must be stake/share/amount/balance/weight accounting. Evidence:
/// the function name, any state variable read or written, or any identifier /
/// member name appearing in the body. We keep this broad enough to catch
/// `_stakeAt`-style helpers but it is still gated behind the precise mul-div
/// shape, so it does not fire on unrelated arithmetic.
fn relates_to_prorata(f: &Function) -> bool {
    if name_is_prorata(&f.name) {
        return true;
    }
    // State variables touched by the function.
    let touches_state = f
        .effects
        .storage_reads
        .iter()
        .chain(f.effects.storage_writes.iter())
        .any(|a| name_is_prorata(&a.var));
    if touches_state {
        return true;
    }
    // Parameter names (`uint256 shares`, `uint256 stake`).
    if f.params.iter().any(|p| p.name.as_deref().map(name_is_prorata).unwrap_or(false)) {
        return true;
    }
    // Identifiers / member names referenced in the body.
    let mut hit = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit {
                return;
            }
            match &e.kind {
                ExprKind::Ident(n) => {
                    if name_is_prorata(n) {
                        hit = true;
                    }
                }
                ExprKind::Member { member, .. } => {
                    if name_is_prorata(member) {
                        hit = true;
                    }
                }
                _ => {}
            }
        });
        if hit {
            break;
        }
    }
    hit
}

fn name_is_prorata(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    PRORATA_MARKERS.iter().any(|m| l.contains(m))
}

/// Suppress when the function pins a rounding direction. Mirrors
/// `rounding::uses_explicit_rounding`: textual markers for a rounding-mode enum
/// or a directional helper, plus the structural `+ c - 1` ceil idiom.
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
    has_ceil_idiom(f)
}

/// The `(a * b + c - 1) / c` ceil-division idiom: a `Div` whose numerator
/// subtracts `1`. Its presence means rounding was deliberately considered.
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

    // Vulnerable (Symbiotic `_stakeAt` shape): the public entry points are thin,
    // and the pro-rata `activeStake * activeSharesOf / activeShares` floor
    // division lives in an INTERNAL helper named `_stakeAt` — exactly the place
    // the name-gated `rounding-direction` detector never inspects. No rounding
    // mode is pinned.
    const VULN: &str = r#"
        contract NetworkRestakeDelegator {
            uint256 internal activeStake;
            uint256 internal activeShares;
            mapping(address => uint256) internal activeSharesOf;

            function stakeAt(address operator) external view returns (uint256) {
                return _stakeAt(operator);
            }

            function _stakeAt(address operator) internal view returns (uint256) {
                return activeStake * activeSharesOf[operator] / activeShares;
            }
        }
    "#;

    // Safe: the same internal pro-rata helper, but the rounding direction is
    // pinned with the `+ activeShares - 1` ceil idiom, so rounding was clearly
    // considered and the protocol is protected — no finding.
    const SAFE: &str = r#"
        contract NetworkRestakeDelegator {
            uint256 internal activeStake;
            uint256 internal activeShares;
            mapping(address => uint256) internal activeSharesOf;

            function stakeAt(address operator) external view returns (uint256) {
                return _stakeAt(operator);
            }

            function _stakeAt(address operator) internal view returns (uint256) {
                return (activeStake * activeSharesOf[operator] + activeShares - 1) / activeShares;
            }
        }
    "#;

    // Negative control: an internal helper with the exact mul-div shape but whose
    // quantities are unrelated to stake/share accounting (a fee/time ratio). The
    // pro-rata gate must keep this silent.
    const SAFE_UNRELATED: &str = r#"
        contract Fees {
            uint256 internal feeBps;
            uint256 internal duration;
            uint256 internal period;

            function _accruedFee() internal view returns (uint256) {
                return feeBps * duration / period;
            }
        }
    "#;

    #[test]
    #[ignore = "detector quarantined pending R8 real-code tuning (see detectors/mod.rs); re-enable on activation"]
    fn fires_on_internal_helper() {
        let fs = run(VULN);
        assert!(
            fs.iter().any(|f| f.detector == "internal-share-pricing-rounding"),
            "{:#?}",
            fs
        );
    }

    #[test]
    fn silent_when_rounding_pinned() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "internal-share-pricing-rounding"));
    }

    #[test]
    fn silent_on_unrelated_math() {
        let fs = run(SAFE_UNRELATED);
        assert!(!fs.iter().any(|f| f.detector == "internal-share-pricing-rounding"));
    }
}
