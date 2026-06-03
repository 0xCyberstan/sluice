//! Liquidation abuse: a liquidation routine whose seize / bonus / close-factor
//! math is unbounded or self-liquidatable.
//!
//! A lending-protocol liquidation pays the liquidator the seized collateral
//! scaled by a *liquidation incentive* (a "bonus" / "incentive" multiplier),
//! capped by a *close factor* (the fraction of the debt a single call may
//! repay), and is only permitted once the borrower's position is actually
//! *unhealthy* (health factor < 1). Three things must hold for that to be safe:
//!
//!   1. **A health/solvency precondition** — the position must be below the
//!      liquidation threshold before any collateral is seized. Without it, a
//!      borrower (or anyone) can liquidate a perfectly healthy position, or
//!      *self-liquidate* to harvest the incentive at the protocol's expense.
//!   2. **A bounded seize amount** — the collateral handed out, after the bonus
//!      multiplier is applied, must be capped to the collateral actually backing
//!      the covered debt (`require(seize <= collateral)` / clamp to balance).
//!      An uncapped `seize = repay * price * (1 + bonus)` can exceed the
//!      position's collateral and drain other users' funds.
//!   3. **A close-factor cap** — a single liquidation may only cover up to
//!      `closeFactor * debt`; seizing more than the debt covered lets the
//!      liquidator over-seize.
//!
//! When a liquidation applies a bonus/incentive/close-factor multiplier to a
//! seize amount but enforces *neither* an upper bound on what is seized *nor* a
//! health-factor precondition, the incentive math is unbounded or
//! self-liquidatable. This is the bad-debt / over-seizure liquidation class
//! (e.g. mispriced or uncapped liquidation incentives draining a money market).
//!
//! Precision (false-positive suppression): we only consider a function that is
//! *clearly* a liquidation (named `liquidate*` / `seize*` / `liquidateBorrow`
//! and computing a seize/bonus quantity), and we **suppress** when the function
//! both (a) asserts a health-factor / liquidatable precondition AND (b) bounds
//! the seize amount (caps to collateral / close factor). A liquidation that
//! does both is the safe Compound/Aave shape and must stay silent.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Builtin, CallKind, Expr, ExprKind, Function};

pub struct LiquidationAbuseDetector;

/// Source substrings naming the liquidation-incentive multiplier — a "bonus" /
/// "incentive" applied to the seized collateral, or a "closeFactor" /
/// "liquidationFactor" governing how much debt a call may cover. Presence of one
/// of these is what marks the seize math as incentive-scaled (and thus
/// abusable if unbounded).
const INCENTIVE_MARKERS: &[&str] = &[
    "bonus",
    "incentive",
    "liquidationfactor",
    "liquidation_factor",
    "closefactor",
    "close_factor",
    "liquidationincentive",
    "liquidation_incentive",
];

/// Source substrings evidencing a health / solvency precondition — the position
/// must be liquidatable before collateral is seized. Any of these in the
/// function (or a guard it calls) means the "is the position underwater?" check
/// is present.
const HEALTH_MARKERS: &[&str] = &[
    "healthfactor",
    "health_factor",
    "ishealthy",
    "_checkhealth",
    "checkhealth",
    "isliquidatable",
    "liquidatable",
    "shortfall",
    "isundercollateralized",
    "undercollateralized",
    "belowthreshold",
    "_requirehealthy",
    "solvency",
    "collateralization",
    "liquidationthreshold",
    "liquidation_threshold",
];

/// Source substrings evidencing a bound that caps how much collateral may be
/// seized (clamp to collateral / balance / close factor). Used as a *textual*
/// corroboration of the structural bound check below.
const SEIZE_BOUND_MARKERS: &[&str] = &[
    "closefactor",
    "close_factor",
    "maxseize",
    "max_seize",
    "maxliquidat",
    "maxrepay",
    "maxclose",
    "min(", // `seize = min(seize, collateral)` clamp idiom
];

impl Detector for LiquidationAbuseDetector {
    fn id(&self) -> &'static str {
        "liquidation-abuse"
    }
    fn category(&self) -> Category {
        Category::LiquidationAbuse
    }
    fn description(&self) -> &'static str {
        "Liquidation with unbounded seize/bonus math or no health-factor precondition (self-liquidatable / bad-debt)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Liquidation is a state-mutating entry point; an interface/abstract
            // declaration has nothing to bound.
            if !f.is_externally_reachable() || !f.is_state_mutating() {
                continue;
            }
            if cx.contract_of(f.id).map(|c| c.is_interface()).unwrap_or(false) {
                continue;
            }

            // (A) The function must clearly be a liquidation.
            if !name_is_liquidation(&f.name) {
                continue;
            }

            let src = cx.scir.span_text(f.span).to_ascii_lowercase();

            // (B) and it must apply a liquidation-incentive / close-factor
            //     multiplier to the seize math — that is the quantity that, left
            //     unbounded, becomes abusable. (Without an incentive marker this
            //     is just a generic balance transfer, not the bonus class.)
            let incentive = INCENTIVE_MARKERS.iter().any(|m| src.contains(m));
            if !incentive {
                continue;
            }

            // --- the two safety properties ---
            //
            // (1) Health-factor / liquidatable precondition present?
            let has_health = HEALTH_MARKERS.iter().any(|m| src.contains(m))
                || f.effects
                    .internal_calls
                    .iter()
                    .any(|n| name_is_health_check(n));

            // (2) Seize amount bounded? Either a textual cap marker (closeFactor /
            //     maxSeize / a `min(...)` clamp) OR a structural `require`/guard
            //     that bounds a seize/collateral quantity with an ordering
            //     comparison (`seize <= collateral`, `repay <= debt * closeFactor`).
            let has_bound_marker = SEIZE_BOUND_MARKERS.iter().any(|m| src.contains(m));
            let has_structural_bound = bounds_seize_amount(f);
            let has_bound = has_bound_marker || has_structural_bound;

            // FP suppression (precision first): the safe Compound/Aave shape
            // asserts the position is liquidatable AND caps the seize amount.
            // Only when *both* hold do we stay silent.
            if has_health && has_bound {
                continue;
            }

            // Build the finding. The two evidence dimensions:
            //   * Invariant  — the liquidation skips a protocol solvency
            //     invariant (the liquidatable precondition and/or the
            //     seize<=collateral cap), letting state settle inconsistently.
            //   * ValueFlow  — collateral leaves the protocol scaled by an
            //     attacker-influenceable, unbounded incentive.
            let span = seize_span(f).unwrap_or(f.span);

            let (title, detail): (&str, String) = match (has_health, has_bound) {
                (false, false) => (
                    "Liquidation has no health precondition and no seize bound",
                    format!(
                        "`{}` applies a liquidation bonus/incentive to the seized collateral but \
                         neither requires the position to be liquidatable (no health-factor / \
                         shortfall / liquidation-threshold check) nor caps the seized amount \
                         (no `require(seize <= collateral)` / close-factor bound). A healthy \
                         position can be liquidated and self-liquidation harvests the incentive, \
                         while the uncapped `seize = repay * price * (1 + bonus)` can exceed the \
                         backing collateral and drain other users' funds.",
                        f.name
                    ),
                ),
                (true, false) => (
                    "Liquidation seize/bonus amount is unbounded",
                    format!(
                        "`{}` checks the position is liquidatable but applies the liquidation \
                         bonus/incentive to the seized collateral without an upper bound \
                         (no `require(seize <= collateral)` / close-factor cap). An uncapped \
                         `seize = repay * price * (1 + bonus)` can seize more collateral than the \
                         covered debt backs, over-seizing the borrower and draining the protocol.",
                        f.name
                    ),
                ),
                (false, true) => (
                    "Liquidation lacks a health-factor precondition (self-liquidatable)",
                    format!(
                        "`{}` caps the seized amount but never requires the position to be \
                         unhealthy before seizing (no health-factor / shortfall / \
                         liquidation-threshold check). A solvent position can be liquidated and a \
                         borrower can self-liquidate to harvest the liquidation bonus/incentive at \
                         the protocol's expense.",
                        f.name
                    ),
                ),
                (true, true) => unreachable!("suppressed above"),
            };

            // Both failure modes are at least High-impact (collateral drain /
            // bad debt); a liquidation missing *both* properties is the most
            // dangerous shape.
            let severity = if !has_health && !has_bound {
                Severity::High
            } else {
                Severity::Medium
            };

            let mut b = FindingBuilder::new(self.id(), Category::LiquidationAbuse)
                .title(title)
                .severity(severity)
                .confidence(0.45)
                .dimension(Dimension::Invariant)
                .message(detail)
                .recommendation(
                    "Gate the liquidation on a health-factor precondition \
                     (`require(healthFactor(borrower) < 1e18)` / a shortfall check) and bound the \
                     seized collateral — clamp the bonus-scaled seize amount to the position's \
                     collateral and limit the repaid debt to `closeFactor * debt`, as Compound \
                     `liquidateBorrow` / Aave do.",
                );
            // ValueFlow corroboration: the routine moves value out (transfers the
            // seized collateral), so the unbounded incentive is not merely
            // computed but paid out.
            if f.effects.call_sites.iter().any(|c| c.sends_value || c.kind.is_external_transfer_of_control()) {
                b = b.dimension(Dimension::ValueFlow);
            }
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

// ------------------------------------------------------------------- helpers

/// The function name denotes a liquidation / collateral-seizure routine.
fn name_is_liquidation(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // `liquidate`, `liquidateBorrow`, `liquidatePosition`, `seize`, `seizeCollateral`.
    l.contains("liquidate") || l.contains("seize")
}

/// An internal-call name that performs a health / liquidatable precondition.
fn name_is_health_check(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    HEALTH_MARKERS.iter().any(|m| l.contains(m))
}

/// True if the function body contains a guard that *bounds* a seize / collateral
/// / repay quantity: an ordering comparison (`<`, `<=`, `>`, `>=`) where at
/// least one operand names a seize/collateral/debt/repay quantity and the other
/// side is **not** the literal `0` (a `seize > 0` sign check is not a bound).
///
/// We look inside `require(...)` / `assert(...)` calls and bare comparison
/// expressions alike — a clamp such as `if (seize > collateral) seize =
/// collateral;` also counts because the comparison references the bounded
/// quantity against a non-zero operand.
fn bounds_seize_amount(f: &Function) -> bool {
    let mut bounded = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if bounded {
                return;
            }
            // Comparison directly bounding a seize/collateral quantity.
            if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
                if op.is_ordering()
                    && !is_zero_literal(lhs)
                    && !is_zero_literal(rhs)
                    && (mentions_seize_quantity(lhs) || mentions_seize_quantity(rhs))
                {
                    bounded = true;
                    return;
                }
            }
            // `seize = min(seize, collateral)` clamp: a builtin/plain `min` call
            // whose arguments reference the seize quantity.
            if let ExprKind::Call(c) = &e.kind {
                let is_min = c
                    .func_name
                    .as_deref()
                    .map(|n| n.eq_ignore_ascii_case("min"))
                    .unwrap_or(false)
                    && !matches!(c.kind, CallKind::Builtin(Builtin::Require) | CallKind::Builtin(Builtin::Assert));
                if is_min && c.args.iter().any(mentions_seize_quantity) {
                    bounded = true;
                }
            }
        });
        if bounded {
            break;
        }
    }
    bounded
}

/// An expression references a seize / collateral / debt / repay quantity (by the
/// name of any identifier or member it contains).
fn mentions_seize_quantity(e: &Expr) -> bool {
    let mut hit = false;
    e.visit(&mut |sub| {
        if hit {
            return;
        }
        if let Some(name) = sub.simple_name() {
            let l = name.to_ascii_lowercase();
            if l.contains("seize")
                || l.contains("collateral")
                || l.contains("debt")
                || l.contains("repay")
                || l.contains("borrow")
            {
                hit = true;
            }
        }
    });
    hit
}

/// True if an expression is the numeric/hex literal `0`.
fn is_zero_literal(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(sluice_ir::Lit::Number(n)) | ExprKind::Lit(sluice_ir::Lit::HexNumber(n)) => {
            let t = n.trim();
            t == "0" || t == "0x0" || t == "0x00" || t.trim_start_matches('0').is_empty()
        }
        _ => false,
    }
}

/// Best-effort report location: the first storage write to a seize/collateral
/// quantity, falling back to the function span.
fn seize_span(f: &Function) -> Option<sluice_ir::Span> {
    f.effects
        .storage_writes
        .iter()
        .filter(|w| {
            let l = w.var.to_ascii_lowercase();
            l.contains("seize") || l.contains("collateral") || l.contains("debt")
        })
        .min_by_key(|w| w.order)
        .map(|w| w.span)
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: `liquidate` applies a liquidation `bonus` to the seized
    // collateral with NO health-factor precondition and NO upper bound on the
    // seized amount. A healthy position can be liquidated, a borrower can
    // self-liquidate to harvest the bonus, and the uncapped seize can exceed the
    // backing collateral.
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        contract Lending {
            mapping(address => uint256) public collateral;
            mapping(address => uint256) public debt;
            uint256 public liquidationBonus = 1.1e18; // 10% incentive
            uint256 public price = 1e18;

            function liquidate(address borrower, uint256 repayAmount) external {
                debt[borrower] -= repayAmount;
                uint256 seizeAmount = repayAmount * price * liquidationBonus / 1e36;
                collateral[borrower] -= seizeAmount;
                payable(msg.sender).transfer(seizeAmount);
            }
        }
    "#;

    // Safe: `liquidateBorrow` first requires the position is liquidatable (health
    // factor below 1) AND caps the repaid debt to the close factor and the seized
    // collateral to the borrower's collateral balance.
    const SAFE: &str = r#"
        pragma solidity ^0.8.20;
        contract Lending {
            mapping(address => uint256) public collateral;
            mapping(address => uint256) public debt;
            uint256 public liquidationIncentive = 1.1e18;
            uint256 public closeFactor = 0.5e18;
            uint256 public price = 1e18;

            function healthFactor(address borrower) public view returns (uint256) {
                if (debt[borrower] == 0) return type(uint256).max;
                return collateral[borrower] * price / debt[borrower];
            }

            function liquidateBorrow(address borrower, uint256 repayAmount) external {
                require(healthFactor(borrower) < 1e18, "not liquidatable");
                uint256 maxRepay = debt[borrower] * closeFactor / 1e18;
                require(repayAmount <= maxRepay, "close factor");
                debt[borrower] -= repayAmount;
                uint256 seizeAmount = repayAmount * price * liquidationIncentive / 1e36;
                require(seizeAmount <= collateral[borrower], "over-seize");
                collateral[borrower] -= seizeAmount;
                payable(msg.sender).transfer(seizeAmount);
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "liquidation-abuse"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "liquidation-abuse"));
    }
}
