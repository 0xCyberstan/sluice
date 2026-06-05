//! Slippage / deadline protection. Two value-leak shapes:
//!
//! 1. **Routed swap/LP op** with no minimum-output bound (`amountOutMin: 0` /
//!    `minOut: 0`) or a no-op deadline (`block.timestamp` / `type(uint256).max`).
//!    A router call with `minOut == 0` can be sandwiched and drained to dust; a
//!    `block.timestamp` deadline is satisfied by the very block the transaction
//!    lands in, so it provides no expiry guarantee.
//!
//! 2. **Self-priced mint/redeem with no slippage bound** — a public/external
//!    function that itself *mints* or *redeems/burns* tokens at a price derived
//!    from current pool/curve state (a bonding curve such as Frankencoin's cubic
//!    `calculateShares`/`calculateProceeds`, or an AMM/spot read), moving value
//!    to/from the caller, while taking **no** `minOut`/`maxIn`/`minShares`/
//!    `deadline`-style protection parameter and enforcing no such bound. The price
//!    moves with reserves/supply, so the trade can be sandwiched on the curve and
//!    the caller front-run for the full slippage. This is the same MEV class as a
//!    `minOut: 0` router swap, but the priced operation *is* the function rather
//!    than a downstream router call, so the arg-level check in (1) never sees it.
//!
//! 3. **Payable share-minting deposit with no min-shares bound** — a
//!    public/external **payable** function that takes the caller's native ETH,
//!    routes it through one or more external `deposit`/swap calls (each of which
//!    itself incurs AMM slippage), then computes a share amount from the values
//!    those calls *report back* and `_mint`s it to the caller — with **no**
//!    `minShares`/`minOut` parameter and no `require` bounding the minted amount.
//!    This is the Asymmetry `SafEth.stake()` shape: the per-derivative
//!    `deposit{value:}()` slippage is fully borne by the caller, the realized
//!    share count is unbounded, and a searcher can sandwich the deposit. It is the
//!    same value-leak as (2), but the price here is read implicitly from the
//!    return values of downstream value-bearing deposits rather than from a named
//!    curve/spot helper, so arm (2)'s curated-pricing gate never matches it.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Call, Expr, ExprKind, Function, Lit, Span};

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

            // Class 2: the function is *itself* a curve/pool-priced mint or
            // redeem with no slippage protection (see module docs).
            if let Some(finding) = self_priced_mint_redeem(cx, f) {
                out.push(finding);
            }

            // Class 3: payable share-minting deposit whose minted amount is sized
            // from downstream value-bearing deposit/swap returns, with no
            // min-shares bound (the Asymmetry `SafEth.stake()` shape). Suppressed
            // if Class 2 already covered the function.
            else if let Some(finding) = payable_mint_no_min_shares(cx, f) {
                out.push(finding);
            }
        }
        out
    }
}

/// Class 2 — a self-priced mint/redeem entry point that lacks any slippage
/// bound. Returns at most one finding for the function (anchored at its span).
///
/// Conservative by construction: it requires *all* of
///   (a) the body mints or burns shares (`_mint`/`mint`/`_burn`/`burn`),
///   (b) value moves to/from the caller — a token/ETH transfer out, a `{value:}`
///       send, or the function is an inbound value-receive hook (ERC677/777/1363),
///   (c) the sizing is derived from current pool/curve state — a bonding-curve /
///       share-pricing helper (`calculateShares`, `calculateProceeds`, `_power3`,
///       `price`, `previewMint`, ...) or a manipulable spot-price read, and
///   (d) the function neither takes nor enforces any min-out / max-in / min-shares
///       / deadline-style protection.
/// A plain router swap is unaffected: it forwards a `minOut`/`deadline` to a
/// downstream call (so (d) suppresses it) and does not itself mint/burn (so (a)
/// fails). A vault deposit/withdraw that already takes a `minShares`/`minAmountOut`
/// guard stays silent via (d).
fn self_priced_mint_redeem(cx: &AnalysisContext, f: &Function) -> Option<Finding> {
    let (mints, redeems) = mint_or_redeem_action(f);
    if !mints && !redeems {
        return None;
    }
    if !moves_value_to_or_from_caller(f) {
        return None;
    }
    if !priced_off_curve_or_pool(cx, f) {
        return None;
    }
    if has_slippage_protection(cx, f) {
        return None;
    }

    let (verb, action) = if mints && redeems {
        ("mint/redeem", "mints and redeems")
    } else if mints {
        ("mint", "mints")
    } else {
        ("redeem", "redeems")
    };

    let b = FindingBuilder::new("slippage", Category::Slippage)
        .title("Curve/pool-priced mint or redeem with no slippage bound")
        .severity(Severity::Medium)
        .confidence(0.55)
        .dimension(Dimension::ValueFlow)
        .message(format!(
            "`{}` {action} tokens at a price read from current pool/curve state \
             (a bonding curve or AMM/spot reserves) and moves value to/from the caller, \
             but takes no `minOut`/`minShares`/`maxIn` parameter and enforces no \
             minimum-output bound or deadline. Because the price moves with the pool's \
             reserves/supply within a block, a searcher can sandwich the {verb}: shift the \
             curve price just before the victim's transaction and back after it, capturing \
             the entire unbounded slippage as MEV and returning only dust to the caller. \
             This is the same value-leak class as a `minOut: 0` router swap — here the \
             priced operation is the function itself, so an argument-level `minOut` check \
             never applies.",
            f.name
        ))
        .recommendation(
            "Add a caller-supplied minimum-output (e.g. `minShares` on mint, `minProceeds`/\
             `minAmountOut` on redeem) computed off-chain with a slippage tolerance, and \
             `require` the realized amount meets it; a real future `deadline` further bounds \
             how long the quote stays valid. Never price a mint/redeem off live curve state \
             without a user-enforced bound.",
        );
    Some(cx.finish(b, f.id, f.span))
}

/// Class 3 — a **payable** share-minting deposit that bounds nothing on the
/// minted amount (the Asymmetry `SafEth.stake()` shape). Returns at most one
/// finding for the function (anchored at its span).
///
/// Requires *all* of:
///   (a) the function is `payable` (it takes the caller's native ETH directly),
///   (b) the body mints shares (`_mint`/`mint`),
///   (c) the caller's ETH is routed through at least one external value-bearing
///       deposit/swap call (`deposit{value:}` / `swap{value:}` / a `deposit`-named
///       call), each of which itself incurs AMM slippage the caller fully bears,
///   (d) the function neither takes nor enforces any min-out / min-shares /
///       deadline-style protection (the same suppressor as arm 2).
///
/// The `payable` + value-bearing-deposit gate is what keeps this tight: a plain
/// ERC4626 `deposit(assets, ...)` is non-payable (fails (a)); a router swap does
/// not `_mint` shares to the caller (fails (b)); a bounded staking deposit that
/// takes `minShares` is suppressed by (d). Arm 2 already fires when the price is
/// read from a *named* curve/spot helper — this arm covers the case where the
/// price is read implicitly from the deposits' return values, which arm 2 misses.
fn payable_mint_no_min_shares(cx: &AnalysisContext, f: &Function) -> Option<Finding> {
    if !f.is_payable() {
        return None;
    }
    let (mints, _redeems) = mint_or_redeem_action(f);
    if !mints {
        return None;
    }
    if !routes_value_through_deposit(f) {
        return None;
    }
    if has_mint_output_bound(cx, f) {
        return None;
    }

    let b = FindingBuilder::new("slippage", Category::Slippage)
        .title("Payable share-minting deposit with no minimum-shares bound")
        .severity(Severity::Medium)
        .confidence(0.55)
        .dimension(Dimension::ValueFlow)
        .message(format!(
            "`{}` is `payable`: it takes the caller's native ETH, routes it through one or more \
             external value-bearing `deposit`/swap calls (each of which itself incurs AMM \
             slippage), then mints shares whose amount is derived from the values those calls \
             report back — but it takes no `minShares`/`minOut` parameter and enforces no \
             `require` on the minted amount. The caller has no way to bound how few shares the \
             deposit returns, so a searcher can sandwich it: move the underlying pool price just \
             before the victim's transaction and back after it, forcing the downstream deposits \
             to mint at a worse rate and capturing the slippage as MEV. This is the same value-leak \
             class as a `minOut: 0` router swap.",
            f.name
        ))
        .recommendation(
            "Add a caller-supplied `minShares`/`minOut` (computed off-chain with a slippage \
             tolerance) and `require` the realized minted amount meets it before `_mint`; a real \
             future `deadline` further bounds how long the quote stays valid. Never mint shares \
             off the result of value-bearing deposits without a user-enforced lower bound.",
        );
    Some(cx.finish(b, f.id, f.span))
}

/// Arm-3-specific suppressor: true if the function bounds the *minted output*
/// amount. Deliberately narrower than [`has_slippage_protection`]: it does **not**
/// treat an input floor (`minAmount`/`minPrice` on the incoming ETH, as in
/// `require(msg.value >= minAmount)`) as a min-shares guard, because that bounds
/// the deposit *input*, not how few shares the caller receives. Only a bound that
/// names the *output* — `minShares`/`minOut`/`minReturn`/`minReceived`/
/// `minProceeds`/`minTokens`/`amountOutMin`/`slippage`/`maxSlippage` — counts.
fn has_mint_output_bound(cx: &AnalysisContext, f: &Function) -> bool {
    if f.params.iter().any(|p| {
        p.name
            .as_deref()
            .map(|n| MINT_OUTPUT_TOKENS.iter().any(|t| n.to_ascii_lowercase().contains(t)))
            .unwrap_or(false)
    }) {
        return true;
    }
    let body = cx.source_text(f.span);
    MINT_OUTPUT_TOKENS.iter().any(|t| body.contains(t))
}

/// Output-bound substrings for arm 3. A subset of [`PROTECTION_TOKENS`] minus the
/// input-floor tokens (`minamount`, `minprice`) and the standalone `deadline`,
/// which on a share mint does not bound the share count.
const MINT_OUTPUT_TOKENS: &[&str] = &[
    "minout",
    "minamountout",
    "amountoutmin",
    "minshares",
    "mintokens",
    "minreturn",
    "minreceived",
    "minproceeds",
    "maxslippage",
    "slippage",
];

/// True if the body routes the caller's value through an external deposit/swap
/// call site that itself moves native ETH (`{value:}`), or whose method name is a
/// deposit/swap primitive. This is the slippage-incurring leg whose return value
/// the mint is sized from. Requiring a `sends_value` deposit (rather than just any
/// transfer) keeps this distinct from arm 2's broader value-movement check and
/// matches the `derivative.deposit{value: ethAmount}()` shape exactly.
fn routes_value_through_deposit(f: &Function) -> bool {
    f.effects.call_sites.iter().any(|c| {
        // A value-bearing (`{value:}`) external call into a deposit/swap-style
        // primitive — the slippage-incurring leg whose return the mint sizes from.
        c.sends_value
            && matches!(
                c.func_name.as_deref().map(str::to_ascii_lowercase).as_deref(),
                Some("deposit" | "swap" | "swapexactethfortokens" | "mint" | "stake" | "wrap")
            )
    })
}

/// `(mints, redeems)` — does the body invoke a mint and/or a burn primitive?
/// Matches an internal call whose name (lowercased, leading `_` stripped) begins
/// with `mint` or `burn` — the OpenZeppelin/ERC20 convention (`_mint`, `_burn`,
/// `mint`, `burnFrom`, `_mintShares`, ...). A redeem path burns the caller's
/// shares, so `burn` is the redeem signal.
fn mint_or_redeem_action(f: &Function) -> (bool, bool) {
    let mut mints = false;
    let mut redeems = false;
    for n in &f.effects.internal_calls {
        let s = n.trim_start_matches('_').to_ascii_lowercase();
        if s.starts_with("mint") {
            mints = true;
        }
        if s.starts_with("burn") {
            redeems = true;
        }
    }
    (mints, redeems)
}

/// True if value (tokens or native ETH) moves to/from the caller: a `transfer`/
/// `transferFrom`/`safeTransfer*`/`send` call site, a `{value:}` ETH send, or the
/// function is an inbound value-*receive* hook (the caller is paying in by the
/// very act of calling it). The receive-hook arm is what catches an ERC677
/// `onTokenTransfer` mint, where the inbound ZCHF is the value being priced.
fn moves_value_to_or_from_caller(f: &Function) -> bool {
    if is_value_receive_hook(&f.name) {
        return true;
    }
    f.effects.call_sites.iter().any(|c| {
        if c.sends_value {
            return true;
        }
        matches!(
            c.func_name.as_deref().map(str::to_ascii_lowercase).as_deref(),
            Some("transfer" | "transferfrom" | "safetransfer" | "safetransferfrom" | "send")
        )
    })
}

/// ERC677 / ERC777 / ERC1363 inbound value-receive hooks. When a token is sent to
/// the contract, the token contract calls back into one of these with the inbound
/// `amount`; minting against that amount on a curve is the Frankencoin shape.
fn is_value_receive_hook(name: &str) -> bool {
    matches!(
        name,
        "onTokenTransfer"      // ERC677
            | "tokensReceived" // ERC777
            | "onTransferReceived" // ERC1363
            | "onERC1363Received"
    )
}

/// True if the operation is sized from *current* pool/curve state. Two signals:
/// an internal call to a bonding-curve / share-pricing helper (curated names
/// covering the cubic-curve and ERC4626-preview families), or a body
/// sub-expression the dataflow labels price-like (a manipulable spot read such as
/// `getReserves`/`slot0`/`balanceOf(pool)`). `price` is a pricing-helper name:
/// Frankencoin's `price()` is the curve spot
/// (`VALUATION_FACTOR * equity * 1e18 / totalSupply`).
fn priced_off_curve_or_pool(cx: &AnalysisContext, f: &Function) -> bool {
    if f.effects.internal_calls.iter().any(|n| is_curve_pricing_name(n)) {
        return true;
    }
    // Manipulable spot-price read anywhere in the body (e.g. `getReserves()`).
    let mut price_like = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if !price_like && matches!(&e.kind, ExprKind::Call(_)) && cx.is_price_like(f.id, e) {
                price_like = true;
            }
        });
        if price_like {
            break;
        }
    }
    price_like
}

/// Curated bonding-curve / share-pricing helper names (lowercased, `_` ignored).
/// Deliberately a fixed family — bonding-curve math (`cubicRoot`/`power3`), the
/// Frankencoin `calculateShares`/`calculateProceeds`/`price` curve, and the
/// ERC4626 `preview*`/`convertTo*` quote — rather than any function containing
/// "price", so an unrelated helper does not trip it.
fn is_curve_pricing_name(name: &str) -> bool {
    let n = name.trim_start_matches('_').to_ascii_lowercase();
    matches!(
        n.as_str(),
        "calculateshares"
            | "calculatesharesinternal"
            | "calculateproceeds"
            | "cubicroot"
            | "power3"
            | "price"
            | "currentprice"
            | "spotprice"
            | "getpriceperfullshare"
            | "pricepershare"
            | "previewmint"
            | "previewredeem"
            | "previewdeposit"
            | "previewwithdraw"
            | "converttoshares"
            | "converttoassets"
    )
}

/// True if the function takes *or* enforces any slippage/deadline protection.
/// This is a suppressor: if the author wired up any min-out / max-in / min-shares
/// / deadline machinery (a parameter so named, or the keyword anywhere in the
/// comment-stripped body), we assume the operation is bounded and stay silent —
/// trading a little recall for precision so bounded vault deposits/withdrawals do
/// not fire.
fn has_slippage_protection(cx: &AnalysisContext, f: &Function) -> bool {
    if f.params.iter().any(|p| {
        p.name
            .as_deref()
            .map(|n| is_protection_token(&n.to_ascii_lowercase()))
            .unwrap_or(false)
    }) {
        return true;
    }
    let body = cx.source_text(f.span);
    PROTECTION_TOKENS.iter().any(|t| body.contains(t))
}

/// Substrings that name a slippage / deadline guard. Kept specific (`minout`,
/// `minshares`, ...) so they don't match unrelated identifiers like Frankencoin's
/// `MINIMUM_EQUITY` (which contains "minimum" but none of these tokens).
const PROTECTION_TOKENS: &[&str] = &[
    "minout",
    "minamount",
    "minamountout",
    "amountoutmin",
    "minshares",
    "mintokens",
    "minreturn",
    "minreceived",
    "minproceeds",
    "minprice",
    "maxin",
    "maxamountin",
    "amountinmax",
    "maxslippage",
    "slippage",
    "deadline",
    "sqrtpricelimit",
];

fn is_protection_token(name: &str) -> bool {
    PROTECTION_TOKENS.iter().any(|t| name.contains(t))
}

/// Swap / liquidity router method names worth inspecting. Restricting to these
/// keeps precision high — we never flag an arbitrary call that happens to carry
/// a `0` argument.
///
/// Includes the bespoke "zapping" liquidity-deposit primitives (Salty's
/// `depositLiquidityAndIncreaseShare`, generic `depositLiquidity*`/`addLiquidity*`):
/// these add liquidity to an AMM and take a `minLiquidityReceived`/`amountOutMin`
/// argument plus a `deadline`, so a literal `0` min-liquidity or `block.timestamp`
/// deadline is the same sandwichable value-leak as a router swap.
fn is_swap_like(c: &Call) -> bool {
    let name = c.func_name.as_deref().unwrap_or("");
    if matches!(
        name,
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
    ) {
        return true;
    }
    // Prefix families for AMM add-liquidity / zap / swap primitives whose exact
    // method name varies by protocol but which all carry a min-output + deadline:
    //   `depositLiquidity*`  (Salty `depositLiquidityAndIncreaseShare`)
    //   `addLiquidity*`      (`addLiquidityETH`, `addLiquidityAndStake`, ...)
    //   `exactInput*` / `exactOutput*` (UniswapV3 router variants)
    //   `swapExact*` / `swapTokens*` / `swap*ForTokens` (router swap variants)
    name.starts_with("depositLiquidity")
        || name.starts_with("addLiquidity")
        || name.starts_with("exactInput")
        || name.starts_with("exactOutput")
        || name.starts_with("swapExact")
        || name.starts_with("swapTokens")
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
        let txt = cx.source_text(sp).replace(' ', "");
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

    // Salty M-26: protocol-owned-liquidity formation zaps into the AMM via a
    // bespoke `depositLiquidityAndIncreaseShare` with a literal `0`
    // `minLiquidityReceived` and a `block.timestamp` deadline — neither slippage
    // nor expiry protection, fully sandwichable.
    const LP_ZAP_VULN: &str = r#"
        interface ICollateralAndLiquidity {
            function depositLiquidityAndIncreaseShare(
                address tokenA, address tokenB,
                uint256 amountA, uint256 amountB,
                uint256 minLiquidityReceived, uint256 deadline, bool useZapping
            ) external returns (uint256, uint256, uint256);
        }
        contract DAO {
            ICollateralAndLiquidity collateralAndLiquidity;
            function formPOL(address tokenA, address tokenB, uint256 amountA, uint256 amountB) external {
                collateralAndLiquidity.depositLiquidityAndIncreaseShare(
                    tokenA, tokenB, amountA, amountB, 0, block.timestamp, true );
            }
        }
    "#;

    #[test]
    fn fires_on_lp_zap_zero_minliquidity() {
        let fs = run(LP_ZAP_VULN);
        assert!(
            fs.iter()
                .any(|f| f.detector == "slippage" && f.function == "formPOL"),
            "expected a slippage finding on the zero-minLiquidity LP zap: {:?}",
            fs
        );
    }

    // Same primitive, but with a real caller-supplied `minLiquidity` and a future
    // `deadline` — neither a literal 0 nor block.timestamp, so it must stay silent.
    #[test]
    fn silent_on_lp_zap_with_real_bounds() {
        let src = r#"
            interface ICollateralAndLiquidity {
                function depositLiquidityAndIncreaseShare(
                    address tokenA, address tokenB,
                    uint256 amountA, uint256 amountB,
                    uint256 minLiquidityReceived, uint256 deadline, bool useZapping
                ) external returns (uint256, uint256, uint256);
            }
            contract DAO {
                ICollateralAndLiquidity collateralAndLiquidity;
                function formPOL(
                    address tokenA, address tokenB,
                    uint256 amountA, uint256 amountB,
                    uint256 minLiquidity, uint256 deadline
                ) external {
                    collateralAndLiquidity.depositLiquidityAndIncreaseShare(
                        tokenA, tokenB, amountA, amountB, minLiquidity, deadline, true );
                }
            }
        "#;
        let fs = run(src);
        assert!(
            !fs.iter()
                .any(|f| f.detector == "slippage" && f.function == "formPOL"),
            "an LP zap with real min-liquidity and deadline must not fire: {:?}",
            fs
        );
    }

    // ---- Class 2: self-priced mint/redeem on a bonding curve ----

    // Frankencoin-shaped Equity: mint via the ERC677 `onTokenTransfer` hook and
    // redeem via `redeem`, both priced off a cubic bonding curve, neither taking a
    // min-out / deadline. Both must fire.
    const CURVE_VULN: &str = r#"
        interface IZCHF {
            function equity() external view returns (uint256);
            function transfer(address to, uint256 amount) external returns (bool);
        }
        contract Equity {
            IZCHF public zchf;
            uint256 public totalSupply;
            function _mint(address to, uint256 amt) internal { totalSupply += amt; }
            function _burn(address from, uint256 amt) internal { totalSupply -= amt; }
            function _cubicRoot(uint256 x) internal pure returns (uint256) { return x; }
            function _power3(uint256 x) internal pure returns (uint256) { return x; }
            function calculateSharesInternal(uint256 capital, uint256 inv) internal view returns (uint256) {
                return _cubicRoot(capital + inv);
            }
            function calculateProceeds(uint256 shares) public view returns (uint256) {
                return _power3(shares);
            }
            // ERC677 receive hook: mints FPS for inbound ZCHF, priced on the curve.
            function onTokenTransfer(address from, uint256 amount, bytes calldata) external returns (bool) {
                uint256 shares = calculateSharesInternal(zchf.equity() - amount, amount);
                _mint(from, shares);
                return true;
            }
            // Burns shares and pays out ZCHF, priced on the curve.
            function redeem(address target, uint256 shares) public returns (uint256) {
                uint256 proceeds = calculateProceeds(shares);
                _burn(msg.sender, shares);
                zchf.transfer(target, proceeds);
                return proceeds;
            }
        }
    "#;

    // Same redeem, but it now takes and enforces a caller `minProceeds` bound —
    // the operation is slippage-protected, so it must stay silent.
    const CURVE_SAFE: &str = r#"
        interface IZCHF {
            function equity() external view returns (uint256);
            function transfer(address to, uint256 amount) external returns (bool);
        }
        contract Equity {
            IZCHF public zchf;
            uint256 public totalSupply;
            function _burn(address from, uint256 amt) internal { totalSupply -= amt; }
            function _power3(uint256 x) internal pure returns (uint256) { return x; }
            function calculateProceeds(uint256 shares) public view returns (uint256) {
                return _power3(shares);
            }
            function redeem(address target, uint256 shares, uint256 minProceeds) public returns (uint256) {
                uint256 proceeds = calculateProceeds(shares);
                require(proceeds >= minProceeds, "slippage");
                _burn(msg.sender, shares);
                zchf.transfer(target, proceeds);
                return proceeds;
            }
        }
    "#;

    #[test]
    fn fires_on_curve_priced_mint_and_redeem() {
        let fs = run(CURVE_VULN);
        let slip: Vec<_> = fs
            .iter()
            .filter(|f| f.detector == "slippage" && f.category == sluice_findings::Category::Slippage)
            .collect();
        assert!(
            slip.iter().any(|f| f.function == "onTokenTransfer"),
            "expected a slippage finding on the curve mint hook: {:?}",
            fs
        );
        assert!(
            slip.iter().any(|f| f.function == "redeem"),
            "expected a slippage finding on the curve redeem: {:?}",
            fs
        );
    }

    #[test]
    fn silent_on_curve_redeem_with_minout() {
        let fs = run(CURVE_SAFE);
        assert!(
            !fs.iter()
                .any(|f| f.detector == "slippage" && f.function == "redeem"),
            "a redeem that enforces minProceeds must not fire: {:?}",
            fs
        );
    }

    // A bounded vault deposit (takes `minShares`) priced off a curve must stay
    // silent — guards the precision side of the broadening.
    #[test]
    fn silent_on_bounded_vault_deposit() {
        let src = r#"
            contract Vault {
                uint256 public totalSupply;
                function _mint(address to, uint256 amt) internal { totalSupply += amt; }
                function previewDeposit(uint256 assets) public view returns (uint256) { return assets; }
                function deposit(uint256 assets, uint256 minShares, address to) external returns (uint256) {
                    uint256 shares = previewDeposit(assets);
                    require(shares >= minShares, "slippage");
                    _mint(to, shares);
                    return shares;
                }
            }
        "#;
        let fs = run(src);
        assert!(
            !fs.iter()
                .any(|f| f.detector == "slippage" && f.function == "deposit"),
            "a deposit that enforces minShares must not fire: {:?}",
            fs
        );
    }

    // ---- Class 3: payable share-minting deposit with no min-shares bound ----

    // Asymmetry `SafEth.stake()` shape: a payable function routes the caller's ETH
    // through per-derivative `deposit{value:}()` calls (each incurring slippage),
    // then mints shares sized from the reported values, with no `minShares` bound.
    const STAKE_VULN: &str = r#"
        interface IDerivative {
            function deposit() external payable returns (uint256);
            function ethPerDerivative(uint256 amount) external view returns (uint256);
        }
        contract SafEth {
            uint256 public totalSupply;
            uint256 public derivativeCount;
            mapping(uint256 => IDerivative) public derivatives;
            mapping(uint256 => uint256) public weights;
            uint256 public totalWeight;
            function _mint(address to, uint256 amt) internal { totalSupply += amt; }
            function stake() external payable {
                uint256 preDepositPrice = 10 ** 18;
                uint256 totalStakeValueEth = 0;
                for (uint256 i = 0; i < derivativeCount; i++) {
                    uint256 ethAmount = (msg.value * weights[i]) / totalWeight;
                    uint256 depositAmount = derivatives[i].deposit{value: ethAmount}();
                    totalStakeValueEth +=
                        (derivatives[i].ethPerDerivative(depositAmount) * depositAmount) / 10 ** 18;
                }
                uint256 mintAmount = (totalStakeValueEth * 10 ** 18) / preDepositPrice;
                _mint(msg.sender, mintAmount);
            }
        }
    "#;

    #[test]
    fn fires_on_payable_mint_no_min_shares() {
        let fs = run(STAKE_VULN);
        assert!(
            fs.iter()
                .any(|f| f.detector == "slippage" && f.function == "stake"),
            "expected a slippage finding on the payable share-minting stake: {:?}",
            fs
        );
    }

    // Same stake, but it now takes and enforces a caller `minOut` on the minted
    // amount — the operation is bounded, so it must stay silent.
    #[test]
    fn silent_on_payable_mint_with_min_shares() {
        let src = r#"
            interface IDerivative {
                function deposit() external payable returns (uint256);
            }
            contract SafEth {
                uint256 public totalSupply;
                uint256 public derivativeCount;
                mapping(uint256 => IDerivative) public derivatives;
                function _mint(address to, uint256 amt) internal { totalSupply += amt; }
                function stake(uint256 minOut) external payable {
                    uint256 totalStakeValueEth = 0;
                    for (uint256 i = 0; i < derivativeCount; i++) {
                        totalStakeValueEth += derivatives[i].deposit{value: msg.value}();
                    }
                    uint256 mintAmount = totalStakeValueEth;
                    require(mintAmount >= minOut, "slippage");
                    _mint(msg.sender, mintAmount);
                }
            }
        "#;
        let fs = run(src);
        assert!(
            !fs.iter()
                .any(|f| f.detector == "slippage" && f.function == "stake"),
            "a stake that enforces minOut must not fire: {:?}",
            fs
        );
    }
}
