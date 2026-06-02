//! Slippage / deadline protection: AMM swaps and liquidity operations that are
//! routed with no minimum-output bound (`amountOutMin: 0` / `minOut: 0`) or with
//! a no-op deadline (`block.timestamp` / `type(uint256).max`). This is the
//! pervasive MEV value-leak class — a router call with `minOut == 0` can be
//! sandwiched and drained to dust; a `block.timestamp` deadline is satisfied by
//! the very block the transaction lands in, so it provides no expiry guarantee.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Call, Expr, ExprKind, Lit, Span};

pub struct SlippageDetector;

impl Detector for SlippageDetector {
    fn id(&self) -> &'static str {
        "slippage"
    }
    fn category(&self) -> Category {
        Category::Slippage
    }
    fn description(&self) -> &'static str {
        "Swap/LP op with no minimum-output bound (minOut: 0) or a no-op deadline (block.timestamp / max)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        // Attack surface: externally-reachable, state-mutating bodies (the usual
        // place a router/LP call lives).
        for f in cx.entry_points() {
            // Walk the body; inspect the arguments of every swap/LP-like call.
            for s in &f.body {
                s.visit_exprs(&mut |e| {
                    let ExprKind::Call(c) = &e.kind else { return };
                    if !is_swap_like(c) {
                        return;
                    }

                    let zero_minout = has_zero_minout(c);
                    let noop_deadline = has_noop_deadline(cx, c);
                    if !zero_minout && !noop_deadline {
                        return;
                    }

                    let method = c.func_name.as_deref().unwrap_or("swap");
                    let (title, what, rec) = match (zero_minout, noop_deadline) {
                        (true, true) => (
                            "Swap/LP op with no slippage bound and a no-op deadline",
                            format!(
                                "passes a zero minimum-output to `{method}` *and* a deadline of \
                                 `block.timestamp` / `type(uint256).max`"
                            ),
                            "Pass a user-supplied `amountOutMin` derived from a quote with slippage \
                             tolerance, and a real future `deadline` (e.g. `block.timestamp + ttl`).",
                        ),
                        (true, false) => (
                            "Swap/LP op with no minimum-output bound",
                            format!(
                                "passes a literal `0` as the minimum-output to `{method}`, so the trade \
                                 accepts any execution price"
                            ),
                            "Pass and enforce a user-supplied `amountOutMin`/`minOut` computed from an \
                             off-chain quote with a slippage tolerance; never hard-code `0`.",
                        ),
                        (false, true) => (
                            "Swap/LP op with a no-op deadline",
                            format!(
                                "passes `block.timestamp` (or `type(uint256).max`) as the deadline to \
                                 `{method}`, which is satisfied by whatever block mines the transaction"
                            ),
                            "Pass a real future `deadline` supplied by the caller \
                             (e.g. `block.timestamp + ttl`); `block.timestamp`/`max` disables expiry.",
                        ),
                        (false, false) => return,
                    };

                    let mut b = FindingBuilder::new(self.id(), Category::Slippage)
                        .title(title)
                        .severity(Severity::Medium)
                        .confidence(0.55)
                        .dimension(Dimension::ValueFlow)
                        .message(format!(
                            "`{}` {what}. A searcher can sandwich the swap, moving the pool price within \
                             the same block to extract the entire slippage as MEV and return only dust to \
                             the caller. Both an unbounded `minOut` and a `block.timestamp` deadline remove \
                             the only on-chain protections against this.",
                            f.name
                        ))
                        .recommendation(rec);
                    // Sending native ETH into the router corroborates value at risk.
                    if c.value.is_some() {
                        b = b.dimension(Dimension::ValueFlow);
                    }
                    out.push(cx.finish(b, f.id, e.span));
                });
            }
        }
        out
    }
}

/// Swap / liquidity router method names worth inspecting. Restricting to these
/// keeps precision high — we never flag an arbitrary call that happens to carry
/// a `0` argument.
fn is_swap_like(c: &Call) -> bool {
    matches!(
        c.func_name.as_deref(),
        Some(
            "swap"
                | "swapExactTokensForTokens"
                | "swapExactETHForTokens"
                | "swapTokensForExactTokens"
                | "exactInput"
                | "exactInputSingle"
                | "exactOutputSingle"
                | "addLiquidity"
                | "removeLiquidity"
                | "mint"
                | "deposit"
                | "redeem"
        )
    )
}

/// True if `e` is a literal numeric/hex zero (`0`, `0x0`, `0x00`, ...).
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
/// min-out is just zero digits.
fn is_zero_digits(n: &str) -> bool {
    let s = n.trim();
    !s.is_empty() && s.chars().all(|ch| ch == '0' || ch == '_') && s.contains('0')
}

/// A literal `0` appearing in the min-out position. We treat any *direct*
/// argument that is a bare zero literal as an unbounded `minOut`. We also peek
/// one level into a named-argument / tuple form (`swap({amountOutMin: 0, ...})`)
/// — still constrained to swap-like calls, so precision holds.
///
/// A computed bound (`amountIn * 99 / 100`), a parameter, or an oracle-derived
/// value is *not* a literal and is therefore correctly suppressed.
fn has_zero_minout(c: &Call) -> bool {
    for a in &c.args {
        if is_zero_literal(a) {
            return true;
        }
        // Named-args / struct-literal style: `{ amountOutMin: 0 }` lowers to a
        // tuple of components; a zero component is a zero min-out.
        if let ExprKind::Tuple(items) = &a.kind {
            if items.iter().flatten().any(is_zero_literal) {
                return true;
            }
        }
    }
    false
}

/// `block.timestamp` as a `Member { base: Ident("block"), member: "timestamp" }`.
fn is_block_timestamp(e: &Expr) -> bool {
    if let ExprKind::Member { base, member } = &e.kind {
        if member == "timestamp" {
            if let ExprKind::Ident(n) = &base.kind {
                return n == "block";
            }
        }
    }
    false
}

/// `type(uint256).max` — a `Member { base: <type(...) cast>, member: "max" }`.
/// We match `.max`/`.min` on a `type(...)` expression; the base is a `TypeCast`
/// call whose callee is the `type` keyword.
fn is_type_max(e: &Expr) -> bool {
    let ExprKind::Member { base, member } = &e.kind else {
        return false;
    };
    if member != "max" {
        return false;
    }
    match &base.kind {
        // `type(uint256)` → a call classified as a TypeCast / Unknown whose
        // callee resolves to the `type` keyword.
        ExprKind::Call(inner) => callee_is_type(&inner.callee),
        _ => false,
    }
}

fn callee_is_type(callee: &Expr) -> bool {
    match &callee.kind {
        ExprKind::Ident(n) => n == "type",
        ExprKind::TypeName(n) => n == "type",
        _ => false,
    }
}

/// True if a *direct* argument of the call is exactly a no-op deadline:
/// `block.timestamp` or `type(uint256).max`. A deadline that is a parameter or a
/// future variable (e.g. `block.timestamp + ttl`, a `deadline` arg) is a
/// `Binary`/`Ident` and is therefore not flagged.
fn has_noop_deadline(cx: &AnalysisContext, c: &Call) -> bool {
    for a in &c.args {
        if is_block_timestamp(a) || is_type_max(a) {
            return true;
        }
        // Named-args / struct-literal: `{ deadline: block.timestamp }`.
        if let ExprKind::Tuple(items) = &a.kind {
            if items.iter().flatten().any(|it| is_block_timestamp(it) || is_type_max(it)) {
                return true;
            }
        }
    }
    // Textual fallback for `type(uint256).max` shapes the IR may fold into an
    // `Unsupported`/cast node we don't structurally match. Scoped to this call's
    // span and to swap-like calls only, so it cannot broaden false positives.
    let span = call_span_hint(c);
    if let Some(sp) = span {
        let txt = cx.scir.span_text(sp).to_ascii_lowercase().replace(' ', "");
        if txt.contains("deadline:block.timestamp") || txt.contains("type(uint256).max") || txt.contains("type(uint).max")
        {
            return true;
        }
    }
    false
}

/// Best-effort span covering the call (its callee), for the textual fallback.
fn call_span_hint(c: &Call) -> Option<Span> {
    let sp = c.callee.span;
    if sp == Span::dummy() {
        None
    } else {
        Some(sp)
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Unbounded min-out (`0`) AND a `block.timestamp` deadline on a Uniswap-style
    // router swap routed from an external entry point.
    const VULN: &str = r#"
        interface IRouter {
            function swapExactTokensForTokens(
                uint256 amountIn,
                uint256 amountOutMin,
                address[] calldata path,
                address to,
                uint256 deadline
            ) external returns (uint256[] memory);
        }
        contract Trader {
            IRouter router;
            function go(uint256 amountIn, address[] calldata path) external {
                router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, block.timestamp);
            }
        }
    "#;

    // Safe: a caller-supplied min-out is enforced and a real future deadline is
    // passed through. Nothing is a literal 0 / block.timestamp / max.
    const SAFE: &str = r#"
        interface IRouter {
            function swapExactTokensForTokens(
                uint256 amountIn,
                uint256 amountOutMin,
                address[] calldata path,
                address to,
                uint256 deadline
            ) external returns (uint256[] memory);
        }
        contract Trader {
            IRouter router;
            function go(
                uint256 amountIn,
                uint256 minOut,
                address[] calldata path,
                uint256 deadline
            ) external {
                require(minOut > 0, "slippage");
                router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, deadline);
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "slippage"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "slippage"));
    }
}
