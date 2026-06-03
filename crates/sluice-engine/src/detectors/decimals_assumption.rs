//! Hardcoded 18-decimal scaling applied to arbitrary-token amounts.
//!
//! A value/price/share conversion that multiplies or divides a token amount by a
//! fixed `1e18` factor (`1e18`, `10**18`, or the `1 ether` unit) silently assumes
//! every token it handles has 18 decimals. ERC-20 does **not** mandate 18: USDC
//! and USDT use 6, WBTC uses 8, and many others differ. When the contract is
//! written to handle arbitrary tokens (an `IERC20`/`IToken`-typed parameter or
//! state variable, or a caller-supplied token amount) but pins the scale to
//! `1e18` instead of reading the token's own `decimals()`, the conversion is off
//! by `10**(18-d)` — a 6-decimal token is mispriced by 10^12. In a lending /
//! AMM / vault valuation path that is a direct mispricing → fund-loss bug.
//!
//! Heuristic shape (precision over recall — this is a low-confidence class):
//!   * the function name reads like a value/price/share conversion
//!     (`price`, `value`, `worth`, `share`, `convert`, `quote`, `usd`, `amount`),
//!   * its body multiplies or divides by a `1e18`-style constant (`1e18`,
//!     `1000000000000000000`, `10**18`, or `... ether`),
//!   * the *other* operand of that `mul`/`div` is a token amount, not another
//!     literal (a parameter / state read / `balanceOf` / `transferFrom` result),
//!   * the contract handles arbitrary tokens (an `IERC20`/`IToken` param or var),
//!   * and **nothing** in the function or contract calls `.decimals()` to derive
//!     the scale from the real token.
//!
//! False-positive suppression:
//!   * any `.decimals()` use (function or contract) → the scale is derived, not
//!     assumed; suppress.
//!   * no arbitrary-token surface (no `IERC20`/`IToken` param or var) → the token
//!     set may be a single known 18-decimal asset (e.g. WETH-only); suppress.
//!   * a `1e27`/`1e36` RAY-style or other non-1e18 constant is pure fixed-point
//!     math, not a token-decimal assumption; only `1e18`/`10**18`/`ether` count.
//!   * the `1e18` must combine with a *non-literal* operand — a pure `1e18 * 1e18`
//!     or a bare WAD constant unrelated to a token amount is not flagged.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Contract, Expr, ExprKind, Function, Lit, Span};

pub struct DecimalsAssumptionDetector;

impl Detector for DecimalsAssumptionDetector {
    fn id(&self) -> &'static str {
        "decimals-assumption"
    }
    fn category(&self) -> Category {
        Category::DecimalsAssumption
    }
    fn description(&self) -> &'static str {
        "Value/price/share conversion hardcodes 1e18 scaling instead of the token's decimals() (breaks 6/8-decimal tokens)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Only value/price/share *conversion* paths. Arbitrary `1e18`
            // arithmetic elsewhere (timing, generic WAD math) is out of scope and
            // a major false-positive source.
            if !is_value_conversion_name(&f.name) {
                continue;
            }
            let Some(c) = cx.contract_of(f.id) else { continue };

            // Suppress as soon as the code derives the scale from the real token:
            // a `.decimals()` call anywhere in the function or the contract means
            // the scaling is not a blind 1e18 assumption.
            if uses_decimals(cx, f, c) {
                continue;
            }

            // The contract must actually handle *arbitrary* tokens — an
            // `IERC20`/`IToken`-typed parameter or state variable. Without that
            // surface the token set may be a single known 18-decimal asset
            // (WETH), for which a 1e18 constant is correct.
            if !handles_arbitrary_tokens(f, c) {
                continue;
            }

            // Find a `mul`/`div` where one operand is a `1e18`-style scale and the
            // other is a token *amount* (a non-literal: param / state / call
            // result), the signature of a decimal-scaling conversion.
            let Some(span) = find_token_amount_scaled_by_1e18(cx, f) else {
                continue;
            };

            let b = FindingBuilder::new(self.id(), Category::DecimalsAssumption)
                .title("Token value conversion hardcodes 1e18 scaling instead of decimals()")
                .severity(Severity::Medium)
                .confidence(0.45)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` scales a token amount by a hardcoded `1e18` factor (`1e18` / `10**18` / `1 ether`) \
                     in a mul/div used for value/price/share conversion, yet the contract handles arbitrary \
                     ERC-20 tokens and never reads the token's `decimals()`. ERC-20 does not mandate 18 \
                     decimals — USDC/USDT use 6, WBTC uses 8 — so for a non-18-decimal token the result is \
                     off by `10**(18 - decimals)` (a factor of 10^12 for a 6-decimal token), mispricing the \
                     position and risking fund loss.",
                    f.name
                ))
                .recommendation(
                    "Scale by the token's real precision: read `IERC20Metadata(token).decimals()` and use \
                     `10 ** decimals` (or normalize both amounts to a common precision) instead of a fixed \
                     `1e18`. If the asset is intentionally fixed to an 18-decimal token, document and assert \
                     that invariant.",
                );
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

// ----------------------------------------------------------------- helpers

/// A function whose name reads like a value / price / share conversion — the
/// only place a `1e18` decimal assumption causes a mispricing.
fn is_value_conversion_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "price", "value", "worth", "share", "convert", "quote", "usd", "amount", "rate",
        "valuation", "tousd", "toshares", "toassets", "exchangerate", "pricepershare",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// True if the function or its contract reads a token's `decimals()` — the scale
/// is then derived from the real token, not blindly assumed. Checked via the
/// call-site summary plus a textual fallback over the function and contract
/// source (the call may be nested inside a cast like `IERC20Metadata(t).decimals()`).
fn uses_decimals(cx: &AnalysisContext, f: &Function, c: &Contract) -> bool {
    if f.effects
        .call_sites
        .iter()
        .any(|cs| cs.func_name.as_deref() == Some("decimals"))
    {
        return true;
    }
    let fsrc = cx.source_text(f.span);
    if fsrc.contains(".decimals(") || fsrc.contains("decimals()") {
        return true;
    }
    // A contract-level decimals read (cached in a state var / set in the
    // constructor) also scales by the real value.
    let csrc = cx.source_text(c.span);
    csrc.contains(".decimals(") || csrc.contains("decimals()")
}

/// The contract handles arbitrary tokens: an `IERC20`/`IToken`/`erc20`-typed (or
/// `I…` interface-convention) parameter on the function, or a state variable of
/// such a type. This is the gate that distinguishes a generic multi-token
/// valuation (where a 1e18 assumption is a bug) from a fixed single-asset
/// contract (where it is fine).
fn handles_arbitrary_tokens(f: &Function, c: &Contract) -> bool {
    if f.params.iter().any(|p| is_token_type(&p.ty)) {
        return true;
    }
    c.state_vars.iter().any(|v| is_token_type(&v.ty))
}

/// A textual type that denotes an ERC-20-ish token handle (`IERC20`, `IERC777`,
/// `IToken`, `ERC20`, ...). The leading type word is inspected so a storage
/// location suffix (`IERC20 token`) does not interfere.
fn is_token_type(ty: &str) -> bool {
    let head = ty.split_whitespace().next().unwrap_or(ty);
    let lower = head.to_ascii_lowercase();
    if lower.contains("erc20") || lower.contains("erc777") || lower.contains("token") {
        return true;
    }
    // `IERC20`, `IToken`, `IAsset`, ... interface-convention names: a leading `I`
    // followed by an uppercase letter. The uppercase-second-char requirement
    // avoids matching value types like `int` / `int256` (lowercase second char).
    let b = head.as_bytes();
    b.len() >= 2 && b[0] == b'I' && b[1].is_ascii_uppercase()
}

/// Find a `mul`/`div` (binary or a `mulDiv`-family call) where one operand is a
/// `1e18`-style scale and another operand is a token *amount* — a non-literal
/// value (parameter, state read, member access, or call result such as
/// `balanceOf`/`transferFrom`). Returns the span of the offending expression.
fn find_token_amount_scaled_by_1e18(cx: &AnalysisContext, f: &Function) -> Option<Span> {
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            match &e.kind {
                ExprKind::Binary { op: BinOp::Mul | BinOp::Div, lhs, rhs } => {
                    // One side is the 1e18 scale, the other is a token amount.
                    let l_scale = is_1e18_scale(cx, lhs);
                    let r_scale = is_1e18_scale(cx, rhs);
                    if l_scale && is_token_amount(rhs) {
                        found = Some(e.span);
                    } else if r_scale && is_token_amount(lhs) {
                        found = Some(e.span);
                    }
                }
                // `mulDiv(amount, x, 1e18)` / `mulDiv(amount, 1e18, y)` — a 1e18
                // arg alongside a non-literal token amount arg.
                ExprKind::Call(call)
                    if call
                        .func_name
                        .as_deref()
                        .map(|n| n.eq_ignore_ascii_case("muldiv"))
                        .unwrap_or(false) =>
                {
                    let has_scale = call.args.iter().any(|a| is_1e18_scale(cx, a));
                    let has_amount = call.args.iter().any(is_token_amount);
                    if has_scale && has_amount {
                        found = Some(e.span);
                    }
                }
                _ => {}
            }
        });
    }
    found
}

/// True if `e` is a hardcoded 1e18 scaling factor: `1e18`, the integer
/// `1000000000000000000` (18 zeros), `10**18`, or `1 ether`.
///
/// Detection is driven primarily by the literal's **source text**
/// (`span_text`), because the IR collapses scientific / unit forms: `solang`
/// splits a number into `(mantissa, exponent, unit)` and `sluice`'s lowering
/// keeps only the mantissa — so `1e18` and `1 ether` both arrive as
/// `Lit::Number("1")`, with the `e18` / `ether` recoverable only from the span.
/// The structural `Pow(10, 18)` and the fully-written-out integer are also
/// matched directly as a backstop.
///
/// Deliberately excludes `1e27`/`1e36` RAY/WAD-squared constants and non-18
/// exponents — those are fixed-point math, not a token-decimal assumption.
fn is_1e18_scale(cx: &AnalysisContext, e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(Lit::Number(_)) => {
            // The span covers the original token (mantissa + exponent + any unit),
            // e.g. `1e18`, `1 ether`, `1000000000000000000`.
            let src = normalize_num(cx.scir.span_text(e.span));
            is_1e18_number_text(&src)
        }
        // `10 ** 18` — base 10 to an exponent of exactly 18 (the canonical
        // 18-decimal scale). A general `10 ** decimals` (variable exponent) is the
        // *safe* pattern; its exponent is not a literal, so it correctly fails.
        ExprKind::Binary { op: BinOp::Pow, lhs, rhs } => {
            is_number(lhs, "10") && is_number(rhs, "18")
        }
        _ => false,
    }
}

/// Lowercase a numeric literal's source text and strip digit-group underscores
/// and surrounding whitespace, so `1_000 ether` / `1E18` normalize cleanly.
fn normalize_num(src: &str) -> String {
    src.trim().chars().filter(|c| *c != '_').collect::<String>().to_ascii_lowercase()
}

/// True if a (normalized) numeric literal denotes 1e18: scientific `1e18`, the
/// `1 ether` unit (1 ether == 1e18 wei), or the fully-written
/// `1000000000000000000`.
fn is_1e18_number_text(s: &str) -> bool {
    if s == "1e18" {
        return true;
    }
    // `1 ether` == 10**18 wei, the 18-decimal scale. Collapse internal
    // whitespace so `1 ether` / `1  ether` / `1\tether` all match (the unit
    // follows the mantissa within the literal's span).
    let collapsed: String = s.split_whitespace().collect();
    if collapsed == "1ether" {
        return true;
    }
    // Fully written out: a leading `1` followed by exactly eighteen `0`s.
    s == "1000000000000000000"
}

/// True if `e` is the integer literal `lit` (e.g. `"10"`/`"18"`), underscores
/// ignored.
fn is_number(e: &Expr, lit: &str) -> bool {
    match &e.kind {
        ExprKind::Lit(Lit::Number(n)) => {
            let s: String = n.chars().filter(|c| *c != '_').collect();
            s.trim() == lit
        }
        _ => false,
    }
}

/// True if `e` looks like a *token amount* rather than another constant: any
/// non-literal value — an identifier (param/local), a state/member read, an
/// index (`balances[user]`), or a call result (`balanceOf(...)`,
/// `transferFrom(...)`, a price getter). A literal (number/hex/bool/etc.) is not
/// an amount, so a pure `1e18 * 1e18` or `1e18 / 2` does not qualify.
fn is_token_amount(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(_) => false,
        ExprKind::Ident(_) | ExprKind::Member { .. } | ExprKind::Index { .. } | ExprKind::Call(_) => true,
        // A parenthesized / casted amount (`uint256(r1)`) is still an amount; a
        // `TypeCast` is modeled as a `Call`, already handled above. For other
        // wrapping shapes, descend into the immediate sub-expression.
        ExprKind::Unary { operand, .. } => is_token_amount(operand),
        // A nested arithmetic sub-expression that itself contains a non-literal is
        // an amount (e.g. `(reserve0 * reserve1)`), but a sub-expression of only
        // literals is not.
        ExprKind::Binary { lhs, rhs, .. } => is_token_amount(lhs) || is_token_amount(rhs),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // A USD valuation that takes an arbitrary ERC-20 `token` and a caller-supplied
    // `amount`, multiplies by a spot price and divides by a hardcoded `1e18` — it
    // never reads `token.decimals()`, so a 6-decimal token (USDC) is mispriced by
    // 10^12.
    const VULN: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function balanceOf(address) external view returns (uint256); }
        interface IPriceFeed { function price(address t) external view returns (uint256); }
        contract Lending {
            IPriceFeed feed;
            function valueOf(IERC20 token, uint256 amount) external view returns (uint256) {
                uint256 p = feed.price(address(token));
                return amount * p / 1e18;
            }
        }
    "#;

    // The same valuation, but it derives the scale from the token's real
    // `decimals()` instead of assuming 18 — correct for USDC/WBTC, so no finding.
    const SAFE: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20Metadata {
            function balanceOf(address) external view returns (uint256);
            function decimals() external view returns (uint8);
        }
        interface IPriceFeed { function price(address t) external view returns (uint256); }
        contract Lending {
            IPriceFeed feed;
            function valueOf(IERC20Metadata token, uint256 amount) external view returns (uint256) {
                uint256 p = feed.price(address(token));
                uint256 scale = 10 ** token.decimals();
                return amount * p / scale;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "decimals-assumption"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "decimals-assumption"));
    }
}
