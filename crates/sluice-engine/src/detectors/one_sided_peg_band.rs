//! One-sided peg / price-band on a mint or redeem quote — a band check that
//! constrains **only one direction** of a price/ratio/amount, leaving the
//! protocol-unfavorable side unbounded.
//!
//! A mint/redeem flow that turns collateral into a pegged token (or vice versa)
//! should bound the conversion *symmetrically*: a price/ratio that drifts too
//! high **or** too low both let value leak. The bug class is a guard of the shape
//!
//! ```solidity
//! // only an UPPER bound — nothing stops the amount/ratio from going too LOW
//! if (mintedPerBlock[block.number] + mintAmount > maxMintPerBlock) revert MaxMintPerBlockExceeded();
//! // (or, symmetrically, only a `< min` lower bound with no `> max` cap)
//! ```
//!
//! where the same quantity (a mint/redeem amount, or a price/collateral ratio
//! used to quote the mint/redeem) is bounded on **one** side only and the
//! opposite bound is simply absent from the function. The unbounded direction is
//! the one an adversary (or a depeg / a stale signal) drives to extract value:
//! a per-block *cap* with no *floor* still lets a single block mint/redeem at any
//! arbitrarily small or unfavorable ratio; a `price <= max` slippage guard with
//! no `price >= min` lets the quote collapse.
//!
//! This is the Ethena `EthenaMinting` `belowMaxMintPerBlock` /
//! `belowMaxRedeemPerBlock` shape: the modifier enforces only
//! `mintedPerBlock[block.number] + mintAmount > maxMintPerBlock` (an upper cap on
//! the per-block mint/redeem quantity) and never a lower bound — the band is
//! one-sided.
//!
//! Precision anchors (all required, so this stays quiet on ordinary single
//! inequalities and on true two-sided bands):
//!   * the enclosing function is **mint/redeem context** — its own name, the
//!     name of a modifier it applies, or (when the function *is* a modifier) its
//!     own name reads as mint/redeem (`mint`, `redeem`, `belowMaxMintPerBlock`,
//!     ...);
//!   * there is a **band guard** — an `if (cmp) revert/return` or
//!     `require(cmp)` whose condition is a single **ordering** comparison
//!     (`<`/`<=`/`>`/`>=`, never `==`/`!=`);
//!   * that comparison bounds a **mint/redeem quantity or quote** — one operand
//!     references a function parameter (the `amount`/`usde_amount`/`ratio`) or an
//!     accounting/price/ratio-named quantity — **against a named cap/limit/floor
//!     bound** (`max…`/`min…`/`…limit`/`…cap`/`price`/`rate`/`ratio`), and the
//!     bound is **not the literal `0`** (a `> 0` non-zero/dust guard is not a
//!     band);
//!   * **single-sided** — the function applies a bound in exactly **one**
//!     ordering direction (only `>`/`>=`, or only `<`/`<=`) to that quantity.
//!
//! SUPPRESS when the function already contains the **opposite** ordering bound on
//! the same quantity (a genuine two-sided band `min <= x && x <= max`), and when
//! the lone bound is provably the only risky side — here, a comparison against a
//! literal `0` (a non-zero / dust check), which constrains nothing about the peg.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function, Lit, Span, Stmt, StmtKind};

use super::prelude::*;

pub struct OneSidedPegBandDetector;

impl Detector for OneSidedPegBandDetector {
    fn id(&self) -> &'static str {
        "one-sided-peg-band"
    }
    fn category(&self) -> Category {
        Category::OneSidedPegBand
    }
    fn description(&self) -> &'static str {
        "Mint/redeem price-band or slippage guard bounds only one direction of a price/ratio/amount, leaving the protocol-unfavorable side unbounded (Ethena belowMaxMintPerBlock class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.functions() {
            // Need a body to inspect; a `view`/`pure` helper books no mint/redeem.
            if !f.has_body || f.is_view_or_pure() {
                continue;
            }
            // The guard must live in a mint/redeem flow. We accept three carriers:
            // the function's own name, the name of any modifier it applies, or —
            // when the function *is* a modifier (the real Ethena carrier
            // `belowMaxMintPerBlock`) — its own modifier name.
            if !is_mint_redeem_context(f) {
                continue;
            }

            // Collect every enforced band bound (across `if/revert` and
            // `require` guards), then keep only a quantity that is bounded in
            // exactly ONE direction — i.e. its set of enforced directions is a
            // singleton. If both an upper and a lower bound exist for the same
            // quantity, it's a genuine two-sided band (suppress).
            let bounds = collect_bounds(f);
            let Some(hit) = pick_one_sided(&bounds) else { continue };

            // Fill the human-readable guard text from source (trimmed/truncated).
            let guard_text = guard_snippet(&cx.source_text(hit.guard_span));

            let dir_word = if hit.upper { "upper" } else { "lower" };
            let missing = if hit.upper { "lower" } else { "upper" };
            let b = report!(self, Category::OneSidedPegBand,
                title = "Mint/redeem band guard bounds only one direction of the price/ratio",
                severity = Severity::Medium,
                // Multi-anchor structural fingerprint (mint/redeem context + a single
                // ordering band guard on a named cap/limit/price bound over a
                // mint/redeem amount/quote + the opposite-bound-absent suppression),
                // tuned to 0 FP across the prior real-protocol codebases.
                confidence = 0.62,
                dimensions = [Dimension::Invariant],
                message = format!(
                    "`{}` validates the mint/redeem quote with a one-sided band: `{}` enforces only an \
                     {dir_word} bound on `{}` (against `{}`) and never a symmetric {missing} bound. The \
                     unconstrained {missing} direction is left open — a quote/ratio/amount that drifts to the \
                     {missing} extreme (an adversary, a depeg, or a stale signal driving it there) is not \
                     rejected, so value can leak on the side the band does not cover. This is the Ethena \
                     `EthenaMinting.belowMaxMintPerBlock` / `belowMaxRedeemPerBlock` shape, where only \
                     `mintedPerBlock[block.number] + amount > maxMintPerBlock` is enforced (an upper cap) \
                     with no lower bound.",
                    f.name,
                    guard_text,
                    hit.quantity_text,
                    hit.bound_text,
                ),
                recommendation =
                    "Bound the mint/redeem price/ratio/amount on BOTH sides — pair the existing \
                     `x <relop> bound` with the opposite inequality (`require(x >= min && x <= max)`), or \
                     derive the acceptable quote from a two-sided oracle band. A one-directional cap/floor \
                     leaves the opposite extreme exploitable; make the band symmetric (or document and gate \
                     why only one side is risky).",
            );
            out.push(finish_at(cx, b, f.id, hit.guard_span));
        }

        out
    }
}

/// One enforced band bound on a quantity, normalized so that `upper == true`
/// means "the guard rejects the quantity being ABOVE the bound" (an upper cap)
/// and `upper == false` means "rejects it being below" (a lower floor) —
/// regardless of whether the guard was an `if/revert` or a `require`.
struct EnforcedBound {
    upper: bool,
    /// Root identifier of the bounded quantity (lowercased), e.g. `price`,
    /// `mintamount`, `redeemratio`.
    quantity_root: String,
    /// Display text of the quantity operand (`price`).
    quantity_text: String,
    /// Display text of the bound operand (`maxPrice`).
    bound_text: String,
    /// Span of the enclosing guard (the `if`/`require` statement) for reporting.
    guard_span: Span,
}

/// Is `f` part of a mint/redeem flow? True when the function's own name, the name
/// of a modifier it applies, or (for a modifier function) its own name reads as
/// mint/redeem.
fn is_mint_redeem_context(f: &Function) -> bool {
    if name_is_mint_redeem(&f.name) {
        return true;
    }
    f.modifiers.iter().any(|m| name_is_mint_redeem(&m.name))
}

/// A name reads as a mint/redeem operation.
fn name_is_mint_redeem(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("mint") || l.contains("redeem")
}

/// Collect every **enforced band bound** in `f`'s body — both `if (cmp) revert`
/// guards and `require(cmp)` guards — normalized to the `upper`/`lower` "what does
/// the guard reject" convention. A single comparison contributes at most one bound.
fn collect_bounds(f: &Function) -> Vec<EnforcedBound> {
    let mut out: Vec<EnforcedBound> = Vec::new();
    for top in &f.body {
        // (a) `if (cmp) revert/return ...` — the band guard rejects when `cmp` is
        // TRUE, so the comparison's own direction is the enforced one.
        top.visit(&mut |st| {
            if let StmtKind::If { cond, then_branch, else_branch } = &st.kind {
                if branch_is_guard(then_branch) || branch_is_guard(else_branch) {
                    if let Some(mut b) = classify_band(cond, /*reject_when_true=*/ true) {
                        b.guard_span = st.span;
                        out.push(b);
                    }
                }
            }
        });
        // (b) `require(cmp, ...)` / `assert(cmp)` — rejects when `cmp` is FALSE, so
        // the enforced bound is the *negation* of the comparison's own direction.
        top.visit_exprs(&mut |e| {
            if let ExprKind::Call(c) = &e.kind {
                if is_require_or_assert(c) {
                    if let Some(arg0) = c.args.first() {
                        if let Some(mut b) = classify_band(arg0, /*reject_when_true=*/ false) {
                            b.guard_span = e.span;
                            out.push(b);
                        }
                    }
                }
            }
        });
    }
    out
}

/// From all enforced bounds, return the first one whose quantity is bounded in
/// **exactly one** direction across the whole function (a one-sided band). If a
/// quantity has both an upper and a lower bound it is a genuine two-sided band and
/// is skipped (suppressed).
fn pick_one_sided(bounds: &[EnforcedBound]) -> Option<&EnforcedBound> {
    bounds.iter().find(|b| {
        // No bound on the SAME quantity in the opposite direction.
        !bounds
            .iter()
            .any(|other| other.quantity_root == b.quantity_root && other.upper != b.upper)
    })
}

/// A branch body that is a single `revert`/`return` (an inline guard).
fn branch_is_guard(branch: &[Stmt]) -> bool {
    branch.len() == 1 && matches!(branch[0].kind, StmtKind::Revert { .. } | StmtKind::Return(_))
}

/// Classify `cond` as a band comparison: a single ordering comparison
/// (`<`/`<=`/`>`/`>=`) where exactly one operand is a **named cap/limit bound**
/// (`max…`/`min…`/`cap`/`limit`/…, not the literal `0`) and the other references a
/// **mint/redeem quantity** (an accounting or price/ratio-named identifier).
///
/// `reject_when_true` selects the guard semantics: an `if (cmp) revert` rejects
/// when `cmp` is true (so the enforced bound = the comparison's own direction); a
/// `require(cmp)` rejects when `cmp` is false (so the enforced bound is negated).
/// The returned `upper` is in the normalized "what the guard rejects" convention.
fn classify_band(cond: &Expr, reject_when_true: bool) -> Option<EnforcedBound> {
    let ExprKind::Binary { op, lhs, rhs } = &cond.kind else { return None };
    if !op.is_ordering() {
        return None;
    }
    // Find which side is the bound and which is the quantity.
    let l_is_bound = expr_is_named_bound(lhs);
    let r_is_bound = expr_is_named_bound(rhs);
    // Exactly one side must be a recognizable cap/limit bound; the other must read
    // as a quantity (so plain `a < b` between two unremarkable operands is ignored).
    let (bound, quantity, bound_on_right) = match (l_is_bound, r_is_bound) {
        (false, true) => (rhs, lhs, true),
        (true, false) => (lhs, rhs, false),
        _ => return None,
    };
    if !expr_is_quantity(quantity) {
        return None;
    }
    // A comparison against a literal `0` is a non-zero / dust check, not a peg
    // band — the only "risky direction" there is degenerate. Suppress.
    if expr_is_zero(bound) {
        return None;
    }
    // SUPPRESS the ERC4626 standard ceiling pattern — a comparison against
    // `maxRedeem(...)` / `maxWithdraw(...)` / `maxMint(...)` / `maxDeposit(...)`.
    // These are *balance/allowance* ceilings (the most you may redeem given your
    // share balance), not price/peg bands: redeeming FEWER shares is always safe,
    // so the unbounded lower direction is provably not the risky one. This is the
    // Karak `Vault.finishRedeem` `if (shares > maxRedeem(address(this)))` /
    // Ethena `cooldownShares` `if (shares > maxRedeem(msg.sender))` shape.
    if expr_calls_erc4626_max(bound) {
        return None;
    }

    // Does the *comparison as written* assert that the quantity is above the
    // bound? With `>`/`>=` the left operand is the larger; with `<`/`<=` the right
    // operand is. So "quantity is the larger side" is:
    let cmp_says_quantity_above = match op {
        BinOp::Gt | BinOp::Ge => bound_on_right, // quantity on left == larger
        BinOp::Lt | BinOp::Le => !bound_on_right, // quantity on right == larger
        _ => return None,
    };
    // The guard ENFORCES an upper bound when it *rejects* the quantity being above
    // the bound. For `if (cmp) revert`, it rejects exactly when `cmp` holds, so the
    // enforced "reject-above" == `cmp_says_quantity_above`. For `require(cmp)`, it
    // rejects when `cmp` is false, so it is the negation.
    let upper = if reject_when_true { cmp_says_quantity_above } else { !cmp_says_quantity_above };

    Some(EnforcedBound {
        upper,
        quantity_root: expr_root_text(quantity).to_ascii_lowercase(),
        quantity_text: expr_root_text(quantity),
        bound_text: expr_root_text(bound),
        guard_span: cond.span,
    })
}

/// Does `e` (the bound operand) call an ERC4626 `max*` ceiling view —
/// `maxRedeem` / `maxWithdraw` / `maxMint` / `maxDeposit`? Matched on the callee
/// method name of any call inside the operand (so `maxRedeem(x)` and
/// `vault.maxWithdraw(x)` both qualify). These are balance ceilings, not bands.
fn expr_calls_erc4626_max(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Call(c) = &sub.kind {
            let nm = c
                .func_name
                .clone()
                .or_else(|| c.callee.simple_name().map(|s| s.to_string()))
                .unwrap_or_default()
                .to_ascii_lowercase();
            if matches!(nm.as_str(), "maxredeem" | "maxwithdraw" | "maxmint" | "maxdeposit") {
                found = true;
            }
        }
    });
    found
}

/// True if `e` reads as a **named cap/limit bound** — any identifier inside it
/// is a `max…`/`min…`/`cap`/`limit`/`ceil`/`floor`/`threshold`/`bound` name. A
/// bare quantity like `amount` or a quote like `price` is *not* a bound (those
/// name the quantity being bounded; see [`expr_is_quantity`]).
fn expr_is_named_bound(e: &Expr) -> bool {
    // The bound is usually a state var / param identifier, possibly an
    // `arr[idx]`, `a.b`, or a `max*(...)` call. Inspect every identifier in the
    // (small) operand and accept if any reads as a bound name.
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Ident(n) = &sub.kind {
            if name_is_bound(n) {
                found = true;
            }
        }
    });
    found
}

/// A name reads as a **cap / limit / floor bound** — the threshold side of a band
/// comparison. Deliberately limited to cap/limit words (NOT price/rate/ratio/peg,
/// which name the *quantity* being bounded, not the bound itself); otherwise
/// `price <= maxPrice` would see both operands as "bounds" and fail to classify.
///
/// The short cap words (`max`/`min`/`cap`) are matched **token-wise** against the
/// identifier's camelCase / snake_case segments, never as raw substrings —
/// otherwise `min` would match inside `minted`/`mintAmount`. The longer,
/// unambiguous words (`limit`/`ceil`/`floor`/`threshold`/`bound`) are safe as
/// substrings.
fn name_is_bound(name: &str) -> bool {
    let tokens = id_tokens(name);
    // Short cap words: exact token match.
    if tokens.iter().any(|t| matches!(t.as_str(), "max" | "min" | "cap")) {
        return true;
    }
    let l = name.to_ascii_lowercase();
    l.contains("limit")
        || l.contains("ceil")
        || l.contains("floor")
        || l.contains("threshold")
        || l.contains("bound")
}

/// Split an identifier into lowercased camelCase / snake_case / digit-boundary
/// tokens: `maxMintPerBlock` -> `[max, mint, per, block]`,
/// `min_price` -> `[min, price]`, `mintedPerBlock` -> `[minted, per, block]`.
fn id_tokens(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for ch in name.chars() {
        if ch == '_' || ch == '$' {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        // A lower->Upper transition starts a new token (camelCase boundary).
        if ch.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        cur.push(ch.to_ascii_lowercase());
        prev_lower = ch.is_ascii_lowercase() || ch.is_ascii_digit();
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// True if `e` references a **mint/redeem quantity**: an accounting-named or
/// price/ratio-named identifier (`amount`, `usde_amount`, `collateral`,
/// `price`, `ratio`, a `…PerBlock` tally, ...). We reuse the shared accounting
/// classifier plus the quote names.
fn expr_is_quantity(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Ident(n) = &sub.kind {
            let l = n.to_ascii_lowercase();
            if is_accounting_name(n)
                || l.contains("price")
                || l.contains("ratio")
                || l.contains("rate")
                || l.contains("peg")
            {
                found = true;
            }
        }
    });
    found
}

/// Is `e` the integer literal `0`?
fn expr_is_zero(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Lit(Lit::Number(n)) if n.trim() == "0")
        || matches!(&e.kind, ExprKind::Lit(Lit::HexNumber(n)) if {
            let t = n.trim().trim_start_matches("0x").trim_start_matches('0');
            t.is_empty()
        })
}

/// A short, single-line snippet of a guard's (comment-stripped) source text for
/// the finding message — collapse whitespace and truncate.
fn guard_snippet(text: &str) -> String {
    let collapsed: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = collapsed.trim();
    if trimmed.is_empty() {
        return "the band guard".to_string();
    }
    if trimmed.len() > 90 {
        format!("{}…", &trimmed[..90])
    } else {
        trimmed.to_string()
    }
}

/// The root-identifier text of `e` for the message (`a.b[c]` -> `a`,
/// `arr[i] + amount` -> first ident). Falls back to a generic label.
fn expr_root_text(e: &Expr) -> String {
    if let Some(r) = root_ident(e) {
        return r;
    }
    // Otherwise grab the first identifier seen.
    let mut first: Option<String> = None;
    e.visit(&mut |sub| {
        if first.is_some() {
            return;
        }
        if let ExprKind::Ident(n) = &sub.kind {
            first = Some(n.clone());
        }
    });
    first.unwrap_or_else(|| "the quote".to_string())
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "one-sided-peg-band")
    }

    // VULN — the exact Ethena `belowMaxMintPerBlock` shape: a mint-context
    // modifier enforces only an UPPER per-block cap on the mint amount and never
    // a lower bound. One-sided band.
    const VULN_ETHENA: &str = r#"
        contract EthenaMinting {
            mapping(uint256 => uint256) public mintedPerBlock;
            uint256 public maxMintPerBlock;
            error MaxMintPerBlockExceeded();
            modifier belowMaxMintPerBlock(uint256 mintAmount) {
                if (mintedPerBlock[block.number] + mintAmount > maxMintPerBlock) revert MaxMintPerBlockExceeded();
                _;
            }
            function mint(uint256 amount) external belowMaxMintPerBlock(amount) {
                mintedPerBlock[block.number] += amount;
            }
        }
    "#;

    // VULN — a `require(price <= maxPrice)` slippage guard on a mint quote with
    // no `price >= minPrice` floor. Upper bound only.
    const VULN_PRICE_UPPER: &str = r#"
        contract Mint {
            uint256 public maxPrice;
            function mintAt(uint256 price, uint256 amount) external {
                require(price <= maxPrice, "slippage");
                // ... mint `amount` at `price` ...
            }
        }
    "#;

    // VULN — only a lower bound `redeemRatio >= minRatio`, no upper cap. Lower
    // bound only, redeem context.
    const VULN_RATIO_LOWER: &str = r#"
        contract Vault {
            uint256 public minRatio;
            function redeem(uint256 redeemRatio, uint256 shares) external {
                if (redeemRatio < minRatio) revert();
                // ... redeem `shares` at `redeemRatio` ...
            }
        }
    "#;

    // SAFE — a genuine TWO-SIDED band: both `price >= minPrice` and
    // `price <= maxPrice` are enforced in the mint function. Symmetric, suppress.
    const SAFE_TWO_SIDED: &str = r#"
        contract Mint {
            uint256 public minPrice;
            uint256 public maxPrice;
            function mintAt(uint256 price, uint256 amount) external {
                if (price < minPrice) revert();
                if (price > maxPrice) revert();
                // ... mint `amount` at `price` ...
            }
        }
    "#;

    // SAFE — two-sided band expressed as a single conjunction `require(min <= p && p <= max)`.
    const SAFE_TWO_SIDED_CONJ: &str = r#"
        contract Mint {
            uint256 public minPrice;
            uint256 public maxPrice;
            function mintShares(uint256 price, uint256 amount) external {
                require(price >= minPrice, "low");
                require(price <= maxPrice, "high");
            }
        }
    "#;

    // SAFE — a non-zero / dust guard `if (amount == 0) revert` and `if (collateral_amount > 0)`:
    // an equality and a `> 0` non-zero check, neither of which is a peg band.
    const SAFE_NONZERO: &str = r#"
        contract Mint {
            function mint(uint256 collateral_amount, uint256 usde_amount) external {
                if (collateral_amount == 0) revert();
                if (usde_amount == 0) revert();
            }
        }
    "#;

    // SAFE — not a mint/redeem context: an ordinary staking cap with a one-sided
    // bound but no mint/redeem naming on the function or its modifiers.
    const SAFE_NOT_MINT_CTX: &str = r#"
        contract Staking {
            uint256 public stakeLimit;
            function stake(uint256 amount) external {
                if (amount > stakeLimit) revert();
            }
        }
    "#;

    // SAFE — the ERC4626 standard ceiling: `if (shares > maxRedeem(address(this)))
    // revert`. `maxRedeem` is a balance ceiling, not a price/peg band — redeeming
    // fewer shares is always fine, so the lower direction is not risky. This is the
    // Karak `Vault.finishRedeem` shape and must be suppressed.
    const SAFE_ERC4626_CEILING: &str = r#"
        contract Vault {
            function maxRedeem(address a) public view returns (uint256) { return 1e18; }
            function finishRedeem(uint256 shares) external {
                if (shares > maxRedeem(address(this))) revert();
                // ... redeem `shares` ...
            }
        }
    "#;

    // SAFE — a deadline guard `block.timestamp > expiry` in a mint function: an
    // ordering comparison, but neither operand is a mint/redeem quantity (it's a
    // time check), and `expiry` is not a cap/price bound.
    const SAFE_DEADLINE: &str = r#"
        contract Mint {
            function mint(uint256 expiry, uint256 amount) external {
                if (block.timestamp > expiry) revert();
                // mint amount...
            }
        }
    "#;

    #[test]
    fn fires_on_ethena_per_block_cap() {
        assert!(fires(VULN_ETHENA), "{:#?}", run(VULN_ETHENA));
    }

    #[test]
    fn fires_on_upper_only_price_band() {
        assert!(fires(VULN_PRICE_UPPER), "{:#?}", run(VULN_PRICE_UPPER));
    }

    #[test]
    fn fires_on_lower_only_ratio_band() {
        assert!(fires(VULN_RATIO_LOWER), "{:#?}", run(VULN_RATIO_LOWER));
    }

    #[test]
    fn silent_on_two_sided_band() {
        assert!(!fires(SAFE_TWO_SIDED), "{:#?}", run(SAFE_TWO_SIDED));
    }

    #[test]
    fn silent_on_two_sided_conjunction() {
        assert!(!fires(SAFE_TWO_SIDED_CONJ), "{:#?}", run(SAFE_TWO_SIDED_CONJ));
    }

    #[test]
    fn silent_on_nonzero_dust_guard() {
        assert!(!fires(SAFE_NONZERO), "{:#?}", run(SAFE_NONZERO));
    }

    #[test]
    fn silent_when_not_mint_redeem_context() {
        assert!(!fires(SAFE_NOT_MINT_CTX), "{:#?}", run(SAFE_NOT_MINT_CTX));
    }

    #[test]
    fn silent_on_deadline_guard() {
        assert!(!fires(SAFE_DEADLINE), "{:#?}", run(SAFE_DEADLINE));
    }

    #[test]
    fn silent_on_erc4626_max_ceiling() {
        assert!(!fires(SAFE_ERC4626_CEILING), "{:#?}", run(SAFE_ERC4626_CEILING));
    }
}
