//! Fee-growth / liquidity-delta accounting — the concentrated-liquidity AMM
//! per-position owed-fee shape that relies on *intentional* unchecked underflow.
//!
//! In a Uniswap-V3-style concentrated-liquidity AMM, the fee a position has
//! accrued since it was last touched is computed as a **delta of two monotone
//! fee-growth accumulators multiplied by the position's liquidity**:
//!
//! ```solidity
//! // Position.update — Uniswap V3 core
//! unchecked {
//!     uint128 tokensOwed0 = uint128(
//!         FullMath.mulDiv(
//!             feeGrowthInside0X128 - _self.feeGrowthInside0LastX128,  // wraps on purpose
//!             _self.liquidity,
//!             FixedPoint128.Q128
//!         )
//!     );
//!     self.tokensOwed0 += tokensOwed0;
//! }
//! ```
//!
//! The subtraction `feeGrowthInside0X128 - feeGrowthInside0LastX128` is wrapped in
//! `unchecked { }` *deliberately*: the `feeGrowthInsideLast` snapshot can exceed
//! the current global-inside value (the accumulators are `uint256` ring counters
//! that overflow by design), and 2's-complement wrap makes the delta come out
//! correct **only as long as the true elapsed growth is < 2^256**. That invariant
//! is load-bearing and entirely implicit. The same shape appears in
//! `Tick.getFeeGrowthInside` (`feeGrowthGlobal - feeGrowthBelow - feeGrowthAbove`,
//! also unchecked).
//!
//! The hazard this detector flags is the *combination*: an **unchecked**
//! fee-growth-delta `(feeGrowthGlobal/Inside - feeGrowthInsideLast)` **multiplied
//! by a liquidity quantity** and accrued into a `tokensOwed`/owed-fee balance,
//! with **no bound** relating the two accumulators. If a fork/derivative gets the
//! tick-boundary fee-growth bookkeeping wrong (e.g. mis-orders the below/above
//! subtraction at a crossed tick, or double-counts liquidity when re-entering a
//! range), a position can *over-claim* fees / double-count liquidity at the
//! boundary — and because the subtraction is unchecked, the error silently wraps
//! into an enormous `tokensOwed` credit instead of reverting. This is the
//! fee-growth / liquidity-delta accounting class.
//!
//! Precision anchors (all required, so this stays silent on ordinary unchecked
//! increments, OZ allowance subtraction, reward-debt `MasterChef` math, and any
//! code that is not a concentrated-liquidity fee accumulator):
//!   * the offending subtraction lives inside an **`unchecked { }`** block (the
//!     intentional-wrap signal — a *checked* subtraction would revert on the very
//!     under-count this class exploits, so it is not the bug);
//!   * the subtraction's operands are **fee-growth accumulators** — at least one
//!     side names `feeGrowth*` (and the canonical shape has a `...Last` snapshot on
//!     the other side: `feeGrowthInside - feeGrowthInsideLast`);
//!   * that delta is **multiplied by a liquidity quantity** in the same block —
//!     either a textual `* liquidity` / `mulDiv(delta, liquidity, …)`, the V3
//!     `delta * liquidity / Q128` form;
//!   * the product accrues to a **`tokensOwed`-like owed-fee balance** (`tokensOwed`
//!     / `feesOwed` / `owed`), the per-position credit that an over-count inflates.
//!
//! SUPPRESS when bounded: if the function `require`/`assert`s an ordering on the
//! two accumulators (`require(feeGrowthInside >= feeGrowthInsideLast)`) the
//! subtraction cannot wrap and the over-claim is impossible, so we stay silent.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Builtin, CallKind, Expr, ExprKind, Function, Span, Stmt, StmtKind};

use super::prelude::*;

pub struct FeegrowthAccountingDetector;

impl Detector for FeegrowthAccountingDetector {
    fn id(&self) -> &'static str {
        "feegrowth-accounting"
    }
    fn category(&self) -> Category {
        Category::FeegrowthAccounting
    }
    fn description(&self) -> &'static str {
        "Concentrated-liquidity per-position owed-fee computed as an unchecked fee-growth delta × liquidity with no ordering bound (Uniswap-V3 Position.update / Tick.getFeeGrowthInside class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Quick gate: the function must do *some* unchecked arithmetic at all.
            // The fee-growth delta shape always lives inside an `unchecked { }`
            // (intentional 2's-complement wrap), so a function with no unchecked
            // math cannot be the target — this also drops almost every function in
            // a non-AMM codebase for free.
            if !f.effects.has_unchecked_math {
                continue;
            }

            // Find the offending unchecked fee-growth-delta × liquidity → owed
            // shape; returns the span of the subtraction expression to report at.
            let Some(span) = first_feegrowth_delta_mul(f) else { continue };

            // --- false-positive suppression: bounded subtraction ---
            // If the function asserts an ordering on the two fee-growth
            // accumulators (`require(inside >= insideLast)`), the unchecked
            // subtraction cannot underflow/wrap and the over-claim is impossible.
            if feegrowth_subtraction_is_bounded(f) {
                continue;
            }

            let b = report!(self, Category::FeegrowthAccounting,
                title = "Unchecked fee-growth delta × liquidity owed-fee accrual with no ordering bound",
                severity = Severity::Medium,
                confidence = 0.55,
                dimensions = [Dimension::Invariant],
                message = format!(
                    "`{}` computes a per-position owed fee as an `unchecked` fee-growth delta \
                     (`feeGrowthInside - feeGrowthInsideLast`) multiplied by a liquidity quantity and \
                     accrued into a `tokensOwed`-style balance, relying on intentional 2's-complement \
                     wrap of the subtraction with no bound relating the two accumulators. This is the \
                     Uniswap-V3 `Position.update` / `Tick.getFeeGrowthInside` fee-growth accounting \
                     shape: if the tick-boundary fee-growth bookkeeping is wrong (mis-ordered \
                     below/above subtraction at a crossed tick, or liquidity double-counted when a \
                     position re-enters its range), the position over-claims fees / double-counts \
                     liquidity at the boundary, and because the subtraction is unchecked the error \
                     silently wraps into a huge `tokensOwed` credit instead of reverting.",
                    f.name
                ),
                recommendation =
                    "Treat the fee-growth subtraction as an invariant, not a free wrap: confirm the \
                     accumulators are updated atomically with every tick crossing and liquidity change \
                     so `feeGrowthInside` is the true elapsed growth, and assert the per-position credit \
                     is bounded by the pool's collected fees (`require(tokensOwed <= feesCollected)`) \
                     before crediting. If a derivative changed the tick/sqrtPrice rounding or the \
                     below/above split, re-derive the wrap invariant rather than inheriting it.",
            );
            out.push(finish_at(cx, b, f.id, span));
        }
        out
    }
}

/// The span of the first `unchecked { }` subtraction of two fee-growth
/// accumulators whose delta is multiplied by a liquidity quantity and accrued
/// into a `tokensOwed`-style owed-fee balance, if any.
///
/// We require all three to co-occur **inside the same `unchecked` block**: (a) a
/// `feeGrowth*` subtraction, (b) a liquidity multiply, and (c) an owed-fee
/// accrual. That conjunction is what pins the detector to the concentrated-
/// liquidity fee accumulator and away from ordinary unchecked code.
fn first_feegrowth_delta_mul(f: &Function) -> Option<Span> {
    let mut hit: Option<Span> = None;
    for s in &f.body {
        s.visit(&mut |st| {
            if hit.is_some() {
                return;
            }
            let StmtKind::Block { unchecked: true, stmts } = &st.kind else { return };
            // The block must, taken together, (b) multiply by liquidity and (c)
            // accrue into a tokensOwed-like balance. (a) The subtraction itself we
            // find below and report at.
            if !block_multiplies_liquidity(stmts) || !block_accrues_owed(stmts) {
                return;
            }
            // (a) Locate the fee-growth-delta subtraction to anchor the finding.
            for inner in stmts {
                if hit.is_some() {
                    break;
                }
                inner.visit_exprs(&mut |e| {
                    if hit.is_some() {
                        return;
                    }
                    if is_feegrowth_delta(e) {
                        hit = Some(e.span);
                    }
                });
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Is `e` a subtraction `a - b` where at least one operand is a fee-growth
/// accumulator (`feeGrowth*`)? The canonical shape pairs a current
/// `feeGrowthInside` with a `...Last` snapshot, but we accept any `feeGrowth*`
/// operand because the tick-split form is `feeGrowthGlobal - feeGrowthBelow -
/// feeGrowthAbove` (nested subtractions of `feeGrowth*` terms).
fn is_feegrowth_delta(e: &Expr) -> bool {
    let ExprKind::Binary { op: BinOp::Sub, lhs, rhs } = &e.kind else { return false };
    expr_mentions_feegrowth(lhs) || expr_mentions_feegrowth(rhs)
}

/// Does `e` mention a fee-growth accumulator identifier/member (`feeGrowth*`)?
/// We match the `feegrowth` token in either a bare identifier or a member name
/// (`self.feeGrowthInside0LastX128`, `feeGrowthInside0X128`).
fn expr_mentions_feegrowth(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        match &sub.kind {
            ExprKind::Ident(n) if name_is_feegrowth(n) => found = true,
            ExprKind::Member { member, .. } if name_is_feegrowth(member) => found = true,
            _ => {}
        }
    });
    found
}

/// `feegrowth` substring (case-insensitive). Tight enough that ordinary
/// `growth`/`fee` names (`feeRate`, `growthRate`) do not match — both tokens must
/// be adjacent.
fn name_is_feegrowth(name: &str) -> bool {
    name.to_ascii_lowercase().contains("feegrowth")
}

/// Does the unchecked block multiply a (fee-growth) delta by a **liquidity**
/// quantity? Two recognized forms:
///   * a binary `*` one of whose operands mentions a `liquidity`-named value
///     (`delta * liquidity`, `liquidity * delta`); or
///   * a `mulDiv(..)` / `mulDivRoundingUp(..)` FullMath call whose arguments
///     include a `liquidity`-named value (the Uniswap V3 `FullMath.mulDiv(delta,
///     liquidity, Q128)` form).
fn block_multiplies_liquidity(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|s| {
        let mut found = false;
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            match &e.kind {
                // `delta * liquidity` / `liquidity * delta`.
                ExprKind::Binary { op: BinOp::Mul, lhs, rhs }
                    if expr_mentions_liquidity(lhs) || expr_mentions_liquidity(rhs) =>
                {
                    found = true;
                }
                // `FullMath.mulDiv(delta, liquidity, Q128)` / `mulDivRoundingUp(...)`.
                ExprKind::Call(c) if is_muldiv_call(c) && c.args.iter().any(expr_mentions_liquidity) => {
                    found = true;
                }
                _ => {}
            }
        });
        found
    })
}

/// Is `c` a `mulDiv` / `mulDivRoundingUp` (FullMath) call? These are the V3
/// fixed-point multiply-then-divide primitives the fee accrual uses.
fn is_muldiv_call(c: &sluice_ir::Call) -> bool {
    c.func_name
        .as_deref()
        .map(|n| {
            let l = n.to_ascii_lowercase();
            l == "muldiv" || l == "muldivroundingup"
        })
        .unwrap_or(false)
}

/// Does `e` mention a `liquidity`-named identifier/member? The per-position /
/// per-tick liquidity the fee delta is scaled by.
fn expr_mentions_liquidity(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        match &sub.kind {
            ExprKind::Ident(n) if name_is_liquidity(n) => found = true,
            ExprKind::Member { member, .. } if name_is_liquidity(member) => found = true,
            _ => {}
        }
    });
    found
}

/// `liquidity` substring (case-insensitive) — `liquidity`, `_self.liquidity`,
/// `liquidityDelta`.
fn name_is_liquidity(name: &str) -> bool {
    name.to_ascii_lowercase().contains("liquidity")
}

/// Does the unchecked block accrue into a `tokensOwed`-style owed-fee balance?
/// Either a compound `+=` to such a target, or a `VarDecl`/assignment whose name
/// is owed-like that is then added to one. We accept *any* mention of an owed-like
/// name as an assignment target / declared local in the block, since the V3 shape
/// declares `uint128 tokensOwed0 = …` then `self.tokensOwed0 += tokensOwed0`.
fn block_accrues_owed(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|s| {
        let mut found = false;
        s.visit(&mut |st| {
            if found {
                return;
            }
            match &st.kind {
                // `T tokensOwed0 = ...;`
                StmtKind::VarDecl { name: Some(n), .. } if name_is_owed(n) => found = true,
                // `self.tokensOwed0 += ...;` / `tokensOwed0 = ...;`
                StmtKind::Expr(e) => {
                    if let ExprKind::Assign { target, .. } = &e.kind {
                        if expr_mentions_owed(target) {
                            found = true;
                        }
                    }
                }
                _ => {}
            }
        });
        found
    })
}

/// Does `e` mention an owed-fee-named identifier/member as a write target?
fn expr_mentions_owed(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        match &sub.kind {
            ExprKind::Ident(n) if name_is_owed(n) => found = true,
            ExprKind::Member { member, .. } if name_is_owed(member) => found = true,
            _ => {}
        }
    });
    found
}

/// An owed-fee balance name: `tokensOwed*`, `feesOwed`, or a name ending/holding
/// `owed`. Kept to the `owed` token so ordinary balances (`balanceOf`) do not
/// match; the V3 spelling is `tokensOwed0` / `tokensOwed1`.
fn name_is_owed(name: &str) -> bool {
    name.to_ascii_lowercase().contains("owed")
}

/// SUPPRESSION: is the fee-growth subtraction *bounded* by an ordering assertion?
/// True when the function `require`/`assert`s `a >= b` / `a > b` where both names
/// look like fee-growth accumulators (`require(feeGrowthInside >=
/// feeGrowthInsideLast)`). Such a guard makes the unchecked subtraction provably
/// non-wrapping, so the over-claim cannot occur and we stay silent.
fn feegrowth_subtraction_is_bounded(f: &Function) -> bool {
    let mut bounded = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if bounded {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            if !matches!(
                c.kind,
                CallKind::Builtin(Builtin::Require) | CallKind::Builtin(Builtin::Assert)
            ) {
                return;
            }
            if let Some(cond) = c.args.first() {
                if cond_orders_feegrowth(cond) {
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

/// Does `cond` order two fee-growth accumulators with `>=`/`>` (recursing through
/// `&&`)? `feeGrowthInside >= feeGrowthInsideLast` proves the subtraction's
/// minuend dominates the subtrahend.
fn cond_orders_feegrowth(cond: &Expr) -> bool {
    match &cond.kind {
        ExprKind::Binary { op: BinOp::Ge | BinOp::Gt, lhs, rhs } => {
            expr_mentions_feegrowth(lhs) && expr_mentions_feegrowth(rhs)
        }
        ExprKind::Binary { op: BinOp::And, lhs, rhs } => {
            cond_orders_feegrowth(lhs) || cond_orders_feegrowth(rhs)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "feegrowth-accounting")
    }

    // Uniswap-V3 `Position.update` shape: the per-position owed fee is the
    // `unchecked` fee-growth delta `feeGrowthInside0X128 - feeGrowthInside0LastX128`
    // multiplied by `liquidity` via `FullMath.mulDiv`, accrued into `tokensOwed0`.
    // No bound relates the two accumulators — relies entirely on intentional wrap.
    const VULN: &str = r#"
        library FullMath {
            function mulDiv(uint256 a, uint256 b, uint256 d) internal pure returns (uint256) { return a; }
        }
        library Position {
            struct Info { uint128 liquidity; uint256 feeGrowthInside0LastX128; uint128 tokensOwed0; }
            function update(Info storage self, uint256 feeGrowthInside0X128) internal {
                Info memory _self = self;
                unchecked {
                    uint128 tokensOwed0 = uint128(
                        FullMath.mulDiv(
                            feeGrowthInside0X128 - _self.feeGrowthInside0LastX128,
                            _self.liquidity,
                            0x100000000000000000000000000000000
                        )
                    );
                    self.tokensOwed0 += tokensOwed0;
                }
            }
        }
    "#;

    // The Uniswap-V3 `Tick.getFeeGrowthInside` tick-split form: nested unchecked
    // subtractions of `feeGrowth*` terms, scaled by `liquidity` and accrued into a
    // `tokensOwed` credit. Same class, the `* liquidity` binary form (not mulDiv).
    const VULN_TICK_SPLIT: &str = r#"
        contract Pool {
            struct P { uint256 feeGrowthInsideLast; uint128 liquidity; uint128 tokensOwed; }
            function poke(P storage p, uint256 feeGrowthGlobal, uint256 feeGrowthBelow, uint256 feeGrowthAbove) internal {
                unchecked {
                    uint256 feeGrowthInside = feeGrowthGlobal - feeGrowthBelow - feeGrowthAbove;
                    uint256 delta = feeGrowthInside - p.feeGrowthInsideLast;
                    uint128 tokensOwed = uint128(delta * p.liquidity);
                    p.tokensOwed += tokensOwed;
                }
            }
        }
    "#;

    // SAFE (bounded): the same fee-growth delta but the function asserts an
    // ordering on the two accumulators before the unchecked subtraction, so it
    // cannot wrap — suppressed.
    const SAFE_BOUNDED: &str = r#"
        library FullMath {
            function mulDiv(uint256 a, uint256 b, uint256 d) internal pure returns (uint256) { return a; }
        }
        library Position {
            struct Info { uint128 liquidity; uint256 feeGrowthInside0LastX128; uint128 tokensOwed0; }
            function update(Info storage self, uint256 feeGrowthInside0X128) internal {
                Info memory _self = self;
                require(feeGrowthInside0X128 >= _self.feeGrowthInside0LastX128, "bound");
                unchecked {
                    uint128 tokensOwed0 = uint128(
                        FullMath.mulDiv(
                            feeGrowthInside0X128 - _self.feeGrowthInside0LastX128,
                            _self.liquidity,
                            0x100000000000000000000000000000000
                        )
                    );
                    self.tokensOwed0 += tokensOwed0;
                }
            }
        }
    "#;

    // SAFE (checked subtraction): identical naming/shape but NOT inside an
    // `unchecked` block. A checked subtraction reverts on the under-count this
    // class exploits, so it is not the bug — suppressed (no unchecked math).
    const SAFE_CHECKED: &str = r#"
        library FullMath {
            function mulDiv(uint256 a, uint256 b, uint256 d) internal pure returns (uint256) { return a; }
        }
        library Position {
            struct Info { uint128 liquidity; uint256 feeGrowthInside0LastX128; uint128 tokensOwed0; }
            function update(Info storage self, uint256 feeGrowthInside0X128) internal {
                Info memory _self = self;
                uint128 tokensOwed0 = uint128(
                    FullMath.mulDiv(
                        feeGrowthInside0X128 - _self.feeGrowthInside0LastX128,
                        _self.liquidity,
                        0x100000000000000000000000000000000
                    )
                );
                self.tokensOwed0 += tokensOwed0;
            }
        }
    "#;

    // SAFE (ordinary unchecked, not fee-growth): a MasterChef-style reward-debt
    // accrual in unchecked — a `rewardDebt` subtraction × `amount`, no fee-growth
    // accumulator and no `tokensOwed`. Must stay silent (the fee-growth + owed
    // anchors do their job).
    const SAFE_REWARD_DEBT: &str = r#"
        contract Chef {
            struct User { uint256 amount; uint256 rewardDebt; }
            uint256 public accRewardPerShare;
            function pending(User storage u) internal view returns (uint256 r) {
                unchecked {
                    r = u.amount * accRewardPerShare / 1e12 - u.rewardDebt;
                }
            }
        }
    "#;

    // SAFE (unchecked nonce/counter bump): the canonical bounded increment — no
    // fee-growth, no liquidity, no owed balance.
    const SAFE_NONCE: &str = r#"
        contract N {
            uint256 public nonce;
            function bump() external {
                unchecked { nonce = nonce + 1; }
            }
        }
    "#;

    // SAFE (fee-growth delta but no liquidity multiply / no owed accrual): a pure
    // view that returns the unchecked fee-growth delta without scaling it by
    // liquidity or crediting an owed balance. Missing two of the three anchors.
    const SAFE_DELTA_ONLY: &str = r#"
        contract Pool {
            function feeGrowthDelta(uint256 feeGrowthInside, uint256 feeGrowthInsideLast)
                external pure returns (uint256 d)
            {
                unchecked { d = feeGrowthInside - feeGrowthInsideLast; }
            }
        }
    "#;

    #[test]
    fn fires_on_v3_position_update() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_tick_split_form() {
        assert!(fires(VULN_TICK_SPLIT), "{:#?}", run(VULN_TICK_SPLIT));
    }

    #[test]
    fn silent_when_ordering_bounded() {
        assert!(!fires(SAFE_BOUNDED), "{:#?}", run(SAFE_BOUNDED));
    }

    #[test]
    fn silent_on_checked_subtraction() {
        assert!(!fires(SAFE_CHECKED), "{:#?}", run(SAFE_CHECKED));
    }

    #[test]
    fn silent_on_reward_debt_unchecked() {
        assert!(!fires(SAFE_REWARD_DEBT), "{:#?}", run(SAFE_REWARD_DEBT));
    }

    #[test]
    fn silent_on_nonce_increment() {
        assert!(!fires(SAFE_NONCE), "{:#?}", run(SAFE_NONCE));
    }

    #[test]
    fn silent_on_delta_only_no_liquidity_no_owed() {
        assert!(!fires(SAFE_DELTA_ONLY), "{:#?}", run(SAFE_DELTA_ONLY));
    }
}
