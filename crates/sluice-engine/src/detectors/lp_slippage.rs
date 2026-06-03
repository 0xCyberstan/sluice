//! LP-deposit/withdraw slippage: an `addLiquidity` / `removeLiquidity` (and the
//! ETH / single-sided / imbalanced variants) routed with a **zero** minimum-amount
//! bound (`amountAMin` / `amountBMin` / `minAmounts` / `minLpOut` == `0`).
//!
//! This is the liquidity-provision sibling of the swap-side `slippage` detector.
//! A Uniswap-style `addLiquidity(..., amountAMin, amountBMin, to, deadline)` or
//! `removeLiquidity(..., amountAMin, amountBMin, ...)` (and Curve's
//! `remove_liquidity(amount, min_amounts)` / `add_liquidity(amounts, min_mint)`)
//! takes per-token *minimum* bounds that protect the LP from an adverse pool
//! ratio. Passing a literal `0` there waives that protection entirely: a searcher
//! can skew the reserves in the same block (a sandwich), so the deposit mints
//! fewer LP shares than fair value, or the withdrawal returns dust — the
//! difference is extracted as MEV. The mins are the *only* on-chain defense, so a
//! hard-coded `0` is the canonical LP value-loss bug.
//!
//! Scope is deliberately narrow — only the LP add/remove method names below, and
//! only a **literal** `0` in an argument position. A min bound that is a function
//! parameter, a storage value, or a computed quote (`reserve * (1e4 - tol) / 1e4`)
//! is *not* a literal and is therefore correctly suppressed. Keeping to the LP
//! method names means we never overlap the swap-side `slippage` detector's
//! `swapExact*` / `exactInput*` surface.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Call, Expr, ExprKind, Lit};

pub struct LpSlippageDetector;

impl Detector for LpSlippageDetector {
    fn id(&self) -> &'static str {
        "lp-slippage"
    }
    fn category(&self) -> Category {
        Category::LpSlippage
    }
    fn description(&self) -> &'static str {
        "Liquidity add/remove routed with a zero minimum-amount bound (amountAMin/amountBMin/minAmounts == 0), sandwichable for value loss"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        // Attack surface: externally-reachable, state-mutating bodies — where an
        // LP router call lives.
        for f in cx.entry_points() {
            for s in &f.body {
                s.visit_exprs(&mut |e| {
                    let ExprKind::Call(c) = &e.kind else { return };
                    if !is_lp_liquidity_call(c) {
                        return;
                    }
                    if !has_zero_min_bound(c) {
                        return;
                    }

                    let method = c.func_name.as_deref().unwrap_or("addLiquidity");
                    let op = if is_remove(method) { "withdrawal" } else { "deposit" };

                    let b = FindingBuilder::new(self.id(), Category::LpSlippage)
                        .title("Liquidity add/remove with a zero minimum-amount bound")
                        .severity(Severity::Medium)
                        // Honest: a structural heuristic. A literal `0` in an LP
                        // add/remove arg list is overwhelmingly a waived min bound,
                        // but we cannot prove the LP value at risk, so a single
                        // value-flow dimension at 0.5.
                        .confidence(0.5)
                        .dimension(Dimension::ValueFlow)
                        .message(format!(
                            "`{}` calls `{method}` passing a literal `0` as a minimum-amount bound \
                             (`amountAMin` / `amountBMin` / `minAmounts` / `minLpOut`), so the liquidity \
                             {op} accepts any pool ratio. A searcher can sandwich the transaction — skewing \
                             the reserves within the same block — so the {op} mints fewer LP tokens (or \
                             returns less underlying) than fair value, and the shortfall is extracted as MEV.",
                            f.name
                        ))
                        .recommendation(
                            "Pass non-zero `amountAMin`/`amountBMin` (or `minAmounts`/`minLpOut`) derived \
                             from a fresh quote with a slippage tolerance, and revert if the realized amounts \
                             fall short; never hard-code `0`.",
                        );
                    out.push(cx.finish(b, f.id, e.span));
                });
            }
        }
        out
    }
}

// ----------------------------------------------------------------- helpers

/// LP add/remove router method names. Restricting to exactly these keeps the
/// detector off the swap-side surface (`swapExact*`, `exactInput*`) and off
/// arbitrary calls that merely carry a `0` argument.
fn is_lp_liquidity_call(c: &Call) -> bool {
    matches!(
        c.func_name.as_deref(),
        Some(
            "addLiquidity"
                | "addLiquidityETH"
                | "removeLiquidity"
                | "removeLiquidityETH"
                | "remove_liquidity"
                | "addLiquidityImbalance"
        )
    )
}

/// True for the withdrawal-side methods (for message phrasing only).
fn is_remove(method: &str) -> bool {
    method.starts_with("remove") || method.starts_with("remove_")
}

/// True if `e` is a literal numeric/hex zero (`0`, `0x0`, `0x00`, ...). Mirrors
/// the swap-side detector so the two stay consistent.
fn is_zero_literal(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(Lit::Number(n)) => is_zero_digits(n),
        ExprKind::Lit(Lit::HexNumber(n)) => {
            let hex = n.trim_start_matches("0x").trim_start_matches("0X");
            !hex.is_empty() && hex.chars().all(|ch| ch == '0')
        }
        _ => false,
    }
}

/// Numeric literals may carry separators (`1_000`) or unit suffixes; a zero
/// min-amount is just zero digits.
fn is_zero_digits(n: &str) -> bool {
    let s = n.trim();
    !s.is_empty() && s.chars().all(|ch| ch == '0' || ch == '_') && s.contains('0')
}

/// A literal `0` appearing as a minimum-amount bound. For these LP add/remove
/// signatures a bare zero literal in the argument list is the waived `amountMin`
/// / `min_amounts` bound: the desired amounts, `to`, `deadline`, and token
/// handles are never a literal `0` in real liquidity calls, while a parameter, a
/// storage read, or a computed quote is not a literal and is therefore
/// suppressed. We also peek one level into an array-literal / named-argument /
/// tuple form (`min_amounts: [0, 0]`, `{ amountAMin: 0, ... }`), still scoped to
/// LP calls, so precision holds.
fn has_zero_min_bound(c: &Call) -> bool {
    for a in &c.args {
        if is_zero_literal(a) {
            return true;
        }
        // `min_amounts: [0, 0, 0]` (Curve) or named-arg/struct-literal `{ amountAMin: 0 }`
        // lower to an array-literal / tuple of components; a zero component is a
        // zero min bound.
        match &a.kind {
            ExprKind::Tuple(items) | ExprKind::ArrayLit(items) => {
                if items.iter().flatten().any(is_zero_literal) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: a Uniswap-style `addLiquidity` routed from an external entry
    // point with both per-token minimums hard-coded to `0` — no slippage bound on
    // the deposit, so it can be sandwiched.
    const VULN: &str = r#"
        interface IRouter {
            function addLiquidity(
                address tokenA,
                address tokenB,
                uint256 amountADesired,
                uint256 amountBDesired,
                uint256 amountAMin,
                uint256 amountBMin,
                address to,
                uint256 deadline
            ) external returns (uint256, uint256, uint256);
        }
        contract LpManager {
            IRouter router;
            function provide(
                address tokenA,
                address tokenB,
                uint256 a,
                uint256 b,
                uint256 deadline
            ) external returns (uint256, uint256, uint256) {
                return router.addLiquidity(tokenA, tokenB, a, b, 0, 0, msg.sender, deadline);
            }
        }
    "#;

    // Safe: caller-supplied per-token minimums are passed through and enforced.
    // Nothing in the min positions is a literal 0.
    const SAFE: &str = r#"
        interface IRouter {
            function addLiquidity(
                address tokenA,
                address tokenB,
                uint256 amountADesired,
                uint256 amountBDesired,
                uint256 amountAMin,
                uint256 amountBMin,
                address to,
                uint256 deadline
            ) external returns (uint256, uint256, uint256);
        }
        contract LpManager {
            IRouter router;
            function provide(
                address tokenA,
                address tokenB,
                uint256 a,
                uint256 b,
                uint256 aMin,
                uint256 bMin,
                uint256 deadline
            ) external returns (uint256, uint256, uint256) {
                require(aMin > 0 && bMin > 0, "slippage");
                return router.addLiquidity(tokenA, tokenB, a, b, aMin, bMin, msg.sender, deadline);
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "lp-slippage"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "lp-slippage"));
    }
}
