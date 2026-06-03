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
//!
//! ## Second shape — a `10**(18 ± decimals())` scaling *exponent*
//!
//! The path above keys on a *fixed* `1e18` constant and is suppressed the moment
//! the code reads `.decimals()`. But there is a distinct, equally damaging
//! pattern in which the code *does* read `decimals()` yet still bakes in the
//! 18-decimal assumption — by computing the scale as a power of ten whose
//! **exponent** is `18 - decimals()` (or `decimals() - 18`):
//!
//! ```solidity
//! uint mult = 10 ** (18 - ExtendedIERC20(token).decimals());  // Tigris Trading
//! amount / (10 ** (18 - ExtendedIERC20(token).decimals()));
//! ```
//!
//! This is wrong for any token whose `decimals()` exceeds 18: the subtraction
//! `18 - decimals()` underflows (in `uint`) to a near-`type(uint).max` exponent
//! and `10 ** that` reverts (or, in `unchecked`, mis-scales catastrophically),
//! and even for ≤18-decimal tokens it silently assumes the *base* asset is
//! exactly 18 decimals. The defining signature is a `Pow` with base `10` and an
//! exponent that is `literal ± decimals` — one operand a plain integer literal
//! (`18`), the other a `decimals()` call / a `…Decimals` variable.
//!
//! This path is deliberately **independent** of the function-name and
//! `uses_decimals` gates of the first path (here the `decimals()` read is part
//! of the bug, not a mitigation). Precision comes from two requirements that
//! distinguish it from correct decimal-normalization:
//!   * one exponent operand must be an **integer literal** — this excludes the
//!     `10 ** (decimalsA - decimalsB)` *price-feed* family (e.g. Compound's
//!     `ScalingPriceFeed`: `10 ** (decimals_ - underlyingPriceFeedDecimals)`),
//!     which scales between two feeds and is not a hardcoded-18 assumption;
//!   * a documented bound that makes the subtraction safe — a `require`/`if`
//!     comparing a decimals value against the literal (`decimals <= 18`,
//!     `decimals > 18 → revert`) — suppresses the finding (the underflow is
//!     ruled out and the scaling is intentional).

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
            let Some(c) = cx.contract_of(f.id) else { continue };

            // --- Path B: a `10**(18 ± decimals())` scaling *exponent*. ---
            //
            // Independent of the function-name / `uses_decimals` gates below: here
            // the `decimals()` read is *part of* the bug (the exponent assumes the
            // base asset is exactly 18 decimals and underflows for >18-decimal
            // tokens), not a mitigation. Run it for every function with a body.
            if let Some(span) = find_pow10_decimals_exponent(f) {
                if !has_decimals_le_18_guard(cx, f, c) {
                    out.push(cx.finish(self.pow_exponent_finding(f), f.id, span));
                }
            }

            // --- Path A: a fixed `1e18` constant scaling an arbitrary token. ---
            //
            // Only value/price/share *conversion* paths. Arbitrary `1e18`
            // arithmetic elsewhere (timing, generic WAD math) is out of scope and
            // a major false-positive source.
            if !is_value_conversion_name(&f.name) {
                continue;
            }

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

impl DecimalsAssumptionDetector {
    /// The finding for the `10**(18 ± decimals())` scaling-exponent shape.
    fn pow_exponent_finding(&self, f: &Function) -> FindingBuilder {
        FindingBuilder::new(self.id(), Category::DecimalsAssumption)
            .title("Scaling factor 10**(18 - decimals()) assumes an 18-decimal base and underflows for >18-decimal tokens")
            .severity(Severity::Medium)
            .confidence(0.5)
            .dimension(Dimension::ValueFlow)
            .message(format!(
                "`{}` derives a token-decimal scaling factor as a power of ten whose exponent is `18 ± \
                 token.decimals()` (e.g. `10 ** (18 - decimals())`). This hardcodes the assumption that the \
                 reference precision is 18: for any token whose `decimals()` exceeds 18 the unsigned \
                 subtraction `18 - decimals()` underflows to a near-`type(uint).max` exponent, so `10 ** …` \
                 reverts (or, inside an `unchecked` block, mis-scales by an astronomical factor). Even for \
                 ≤18-decimal tokens the scaling silently bakes in the 18-decimal base, so a token added later \
                 with a different precision is mispriced. ERC-20 does not cap decimals at 18.",
                f.name
            ))
            .recommendation(
                "Do not assume an 18-decimal reference. Compute the scale from the actual decimals of *both* \
                 sides (e.g. branch on `decimals() <= 18` and use `10 ** (18 - decimals())` vs \
                 `10 ** (decimals() - 18)`), or normalize via a checked helper, and assert the supported \
                 range with `require(decimals() <= 18)` so a >18-decimal token cannot silently underflow.",
            )
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

// -- Path B: the `10**(18 ± decimals())` scaling-exponent shape -------------

/// Find a `10 ** (literal ± decimals)` scaling factor in the function body and
/// return the span of the whole `Pow` expression.
///
/// The matched shape is `Pow(10, exponent)` where `exponent` is a `Sub`/`Add`
/// with **one operand a plain integer literal** (e.g. `18`) and **the other
/// involving a token's `decimals()`** (a `.decimals()` call, or a `…Decimals`
/// identifier/member fed from one). The integer-literal requirement is the key
/// precision lever: a `10 ** (decimalsA - decimalsB)` between two *variable*
/// decimals — Compound's `ScalingPriceFeed` family — has no literal operand and
/// is correctly skipped, whereas Tigris's `10 ** (18 - decimals())` matches.
fn find_pow10_decimals_exponent(f: &Function) -> Option<Span> {
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            if let ExprKind::Binary { op: BinOp::Pow, lhs, rhs } = &e.kind {
                if is_number(lhs, "10") && is_literal_vs_decimals_diff(rhs) {
                    found = Some(e.span);
                }
            }
        });
    }
    found
}

/// True if `e` is `int_literal ± decimals_expr` (in either operand order) under
/// a `Sub` or `Add`: exactly one side is a bare integer literal and the other
/// side mentions a token's decimals.
fn is_literal_vs_decimals_diff(e: &Expr) -> bool {
    let ExprKind::Binary { op: BinOp::Sub | BinOp::Add, lhs, rhs } = &e.kind else {
        return false;
    };
    let (l_lit, r_lit) = (is_int_literal(lhs), is_int_literal(rhs));
    // Exactly one operand a plain integer literal; the *other* must reference
    // decimals. (`literal ± literal` is pure constant math, not a token scale;
    // `decimals ± decimals` is the inter-feed rescale we deliberately skip.)
    if l_lit && !r_lit {
        mentions_decimals_value(rhs)
    } else if r_lit && !l_lit {
        mentions_decimals_value(lhs)
    } else {
        false
    }
}

/// True if `e` is a plain non-negative integer literal (`18`, `8`, ...). A
/// `1e18`-style or hex literal is not what an exponent diff uses, so only the
/// decimal `Lit::Number` with all-ASCII-digits (underscores allowed) counts.
fn is_int_literal(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(Lit::Number(n)) => {
            let s: String = n.chars().filter(|c| *c != '_').collect();
            let t = s.trim();
            !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit())
        }
        _ => false,
    }
}

/// True if `e` references a token's decimal count: a `decimals()` call (possibly
/// nested under a cast, e.g. `IERC20Metadata(t).decimals()`), a `.decimals`
/// member access, or an identifier/member whose name contains `decimals`
/// (a cached `…Decimals` variable fed from such a read).
fn mentions_decimals_value(e: &Expr) -> bool {
    let mut hit = false;
    e.visit(&mut |sub| {
        if hit {
            return;
        }
        hit = match &sub.kind {
            ExprKind::Call(call) => call
                .func_name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case("decimals")),
            ExprKind::Member { member, .. } => member.to_ascii_lowercase().contains("decimals"),
            ExprKind::Ident(name) => name.to_ascii_lowercase().contains("decimals"),
            _ => false,
        };
    });
    hit
}

/// True if the function or contract documents/asserts a `decimals <= 18` bound
/// (or the equivalent `decimals > 18 → revert`), which rules out the unsigned
/// underflow in `18 - decimals()` and makes the 18-decimal scaling intentional.
///
/// Detected textually over the (comment-stripped, lowercased) function and
/// contract source. The match is a **relational comparison against the
/// standalone literal `18`** — `… <= 18`, `… < 18`, `… > 18`, `… >= 18`, or any
/// of their mirrors (`18 >= …`). In a function that already computes
/// `10 ** (18 ± decimals())`, comparing the *literal 18* against a value is the
/// documented decimals bound (the compared value is the token's decimals, often
/// via a short local like `d`, so we do not require the word "decimals" beside
/// it). Conservative on purpose: this only *suppresses*, and only inside a
/// function whose body already matched the scaling-exponent shape.
fn has_decimals_le_18_guard(cx: &AnalysisContext, f: &Function, c: &Contract) -> bool {
    src_has_decimals_18_bound(&cx.source_text(f.span))
        || src_has_decimals_18_bound(&cx.source_text(c.span))
}

/// True if `src` contains a relational comparison directly against the
/// standalone literal `18` (`<=`/`<`/`>`/`>=` immediately adjacent to a `18`
/// token, on either side), e.g. `d <= 18`, `decimals > 18`, `18 >= x`. The `18`
/// must be standalone (not part of `180`, `1e18`, `0x18`, or an identifier).
fn src_has_decimals_18_bound(src: &str) -> bool {
    let b = src.as_bytes();
    for e in standalone_18_positions(src) {
        // Relational operator immediately to the left of `18` (skipping spaces):
        // `... <= 18`, `... < 18`, `... > 18`, `... >= 18`.
        let mut j = e;
        while j > 0 && b[j - 1] == b' ' {
            j -= 1;
        }
        if j > 0 && (b[j - 1] == b'<' || b[j - 1] == b'>' || b[j - 1] == b'=') {
            // `=` only counts as the tail of `<=`/`>=`, not a bare assignment.
            if b[j - 1] != b'=' || (j >= 2 && (b[j - 2] == b'<' || b[j - 2] == b'>')) {
                return true;
            }
        }
        // Relational operator immediately to the right of `18` (skipping
        // spaces): `18 >= ...`, `18 > ...`, `18 < ...`, `18 <= ...`.
        let mut k = e + 2;
        while k < b.len() && b[k] == b' ' {
            k += 1;
        }
        if k < b.len() && (b[k] == b'<' || b[k] == b'>') {
            return true;
        }
    }
    false
}

/// Byte offsets of every standalone `18` (not part of a longer number like
/// `180`, `1e18`, or `0x18`, nor glued to an identifier) in `src`.
fn standalone_18_positions(src: &str) -> Vec<usize> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == b'1' && b[i + 1] == b'8' {
            let before_ok = i == 0 || !is_num_char(b[i - 1]);
            let after_ok = i + 2 >= b.len() || !is_num_char(b[i + 2]);
            if before_ok && after_ok {
                out.push(i);
            }
        }
        i += 1;
    }
    out
}

fn is_num_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'.'
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

    // -- Path B: the `10**(18 ± decimals())` scaling-exponent shape ---------

    /// The Tigris `Trading` shape: a deposit/withdraw helper scales a token
    /// amount by `10 ** (18 - token.decimals())`. `decimals()` is read, so the
    /// first path is suppressed — but the *exponent* hardcodes the 18-decimal
    /// base and underflows for >18-decimal tokens. Path B must fire.
    const VULN_POW_EXP: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function transfer(address,uint256) external returns(bool); }
        interface ExtendedIERC20 is IERC20 { function decimals() external view returns (uint); }
        contract Trading {
            function _handleWithdraw(address _outputToken, uint _toMint) internal {
                uint got = _toMint / (10**(18-ExtendedIERC20(_outputToken).decimals()));
            }
            function _handleDeposit(address _marginAsset, uint256 _margin) internal {
                uint _marginDecMultiplier = 10**(18-ExtendedIERC20(_marginAsset).decimals());
                uint scaled = _margin / _marginDecMultiplier;
            }
        }
    "#;

    /// The mirror exponent `decimals() - 18` is the same assumption and must
    /// also fire.
    const VULN_POW_EXP_REVERSED: &str = r#"
        pragma solidity ^0.8.0;
        interface ExtendedIERC20 { function decimals() external view returns (uint); }
        contract Scaler {
            function normalize(address token, uint amount) internal view returns (uint) {
                return amount * (10 ** (ExtendedIERC20(token).decimals() - 18));
            }
        }
    "#;

    /// Same `10 ** (18 - decimals())` shape, but the contract documents and
    /// asserts the supported range with `require(decimals <= 18)`. The unsigned
    /// underflow is ruled out and the scaling is intentional → stay silent.
    const SAFE_POW_EXP_GUARDED: &str = r#"
        pragma solidity ^0.8.0;
        interface ExtendedIERC20 { function decimals() external view returns (uint8); }
        contract Trading {
            function _scale(address token, uint amount) internal view returns (uint) {
                uint8 d = ExtendedIERC20(token).decimals();
                require(d <= 18, "unsupported decimals");
                return amount / (10 ** (18 - d));
            }
        }
    "#;

    /// Compound's `ScalingPriceFeed` family: `10 ** (decimals_ -
    /// underlyingPriceFeedDecimals)` rescales between two feeds. Both exponent
    /// operands are *variable* decimals (no literal `18`), and a `<` guard picks
    /// the non-underflowing branch — this is correct normalization, not a
    /// hardcoded-18 assumption. Path B must stay silent.
    const SAFE_INTER_FEED_RESCALE: &str = r#"
        pragma solidity 0.8.15;
        interface AggregatorV3Interface { function decimals() external view returns (uint8); }
        contract ScalingPriceFeed {
            uint8 public immutable decimals;
            bool internal immutable shouldUpscale;
            int256 internal immutable rescaleFactor;
            constructor(address underlyingPriceFeed_, uint8 decimals_) {
                decimals = decimals_;
                uint8 underlyingPriceFeedDecimals = AggregatorV3Interface(underlyingPriceFeed_).decimals();
                shouldUpscale = underlyingPriceFeedDecimals < decimals_ ? true : false;
                rescaleFactor = (shouldUpscale
                    ? int256(10 ** (decimals_ - underlyingPriceFeedDecimals))
                    : int256(10 ** (underlyingPriceFeedDecimals - decimals_))
                );
            }
        }
    "#;

    fn fired_da(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.detector == "decimals-assumption")
    }

    #[test]
    fn fires_on_pow_exponent_18_minus_decimals() {
        let fs = run(VULN_POW_EXP);
        assert!(fired_da(&fs), "expected decimals-assumption; got {:?}",
            fs.iter().map(|f| (&f.detector, &f.function, f.line)).collect::<Vec<_>>());
        // Both helper functions should be implicated.
        let funcs: Vec<&str> = fs
            .iter()
            .filter(|f| f.detector == "decimals-assumption")
            .map(|f| f.function.as_str())
            .collect();
        assert!(funcs.contains(&"_handleWithdraw"), "withdraw not flagged: {funcs:?}");
        assert!(funcs.contains(&"_handleDeposit"), "deposit not flagged: {funcs:?}");
    }

    #[test]
    fn fires_on_pow_exponent_decimals_minus_18() {
        assert!(fired_da(&run(VULN_POW_EXP_REVERSED)));
    }

    #[test]
    fn silent_on_pow_exponent_with_le18_guard() {
        let fs = run(SAFE_POW_EXP_GUARDED);
        assert!(!fired_da(&fs), "guarded ≤18 form must stay silent; got {:?}",
            fs.iter().map(|f| (&f.detector, &f.function)).collect::<Vec<_>>());
    }

    #[test]
    fn silent_on_inter_feed_rescale() {
        let fs = run(SAFE_INTER_FEED_RESCALE);
        assert!(!fired_da(&fs), "inter-feed var-var rescale must stay silent; got {:?}",
            fs.iter().map(|f| (&f.detector, &f.function)).collect::<Vec<_>>());
    }

    // -- unit coverage of the shape predicates ------------------------------

    #[test]
    fn literal_vs_decimals_diff_predicate() {
        use sluice_ir::{BinOp, Expr, ExprKind, Lit};
        let num = |n: &str| Expr::dummy(ExprKind::Lit(Lit::Number(n.into())));
        let decimals_call = || {
            Expr::dummy(ExprKind::Call(sluice_ir::Call {
                callee: Box::new(Expr::dummy(ExprKind::Ident("decimals".into()))),
                receiver: None,
                func_name: Some("decimals".into()),
                args: vec![],
                value: None,
                gas: None,
                kind: sluice_ir::CallKind::External,
            }))
        };
        let sub = |l: Expr, r: Expr| {
            Expr::dummy(ExprKind::Binary { op: BinOp::Sub, lhs: Box::new(l), rhs: Box::new(r) })
        };
        // 18 - decimals()  → yes
        assert!(super::is_literal_vs_decimals_diff(&sub(num("18"), decimals_call())));
        // decimals() - 18  → yes
        assert!(super::is_literal_vs_decimals_diff(&sub(decimals_call(), num("18"))));
        // 18 - 6  (literal - literal) → no
        assert!(!super::is_literal_vs_decimals_diff(&sub(num("18"), num("6"))));
        // decimalsA - decimalsB (var - var, the inter-feed shape) → no
        let dvar = |n: &str| Expr::dummy(ExprKind::Ident(n.into()));
        assert!(!super::is_literal_vs_decimals_diff(&sub(
            dvar("decimalsA"),
            dvar("underlyingPriceFeedDecimals")
        )));
    }

    #[test]
    fn decimals_18_bound_textual_guard() {
        assert!(super::src_has_decimals_18_bound("require(d <= 18);"));
        assert!(super::src_has_decimals_18_bound("if (decimals > 18) revert();"));
        assert!(super::src_has_decimals_18_bound("require(18 >= tokendecimals);"));
        // No bound: a bare scaling with no comparison.
        assert!(!super::src_has_decimals_18_bound("return amount / (10 ** (18 - d));"));
        // `decimals` and `18` present but not in a comparison (different exprs).
        assert!(!super::src_has_decimals_18_bound("uint x = decimals; uint y = 18;"));
        // A longer number `180` must not be read as a standalone `18`.
        assert!(!super::src_has_decimals_18_bound("require(decimals <= 180);"));
    }
}
