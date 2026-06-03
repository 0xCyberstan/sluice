//! Internal share/stake pro-rata pricing that floors with no rounding control —
//! the half of the rounding-direction class that lives **below** the public
//! conversion entry points and so escapes the `rounding-direction` detector.
//!
//! `rounding.rs` only inspects externally-reachable, state-mutating functions
//! whose *name* is a conversion entry point (`mint`/`deposit`/`withdraw`/
//! `redeem`/`burn`/`issue`). But in pooled-stake / restaking systems the
//! load-bearing pro-rata maths does not live there: the public entry point is a
//! thin wrapper that delegates the actual share→stake conversion to an
//! **internal / private helper** (a name like `_stakeAt`, `_stake`, `_sharesAt`),
//! and that helper expresses the conversion as a bare two-argument
//! `shares.mulDiv(stake, totalShares)` — OpenZeppelin `Math.mulDiv` **without**
//! the optional third `Math.Rounding` argument. With no rounding argument
//! `Math.mulDiv` floors toward zero, so the helper rounds against whichever party
//! the floor disfavours a few wei per call — and because the helper is private
//! and mis-named, the name-gated `rounding-direction` detector never looks at it.
//!
//! This is the exact shape behind Symbiotic's `NetworkRestakeDelegator._stakeAt`
//! / `_stake`:
//!
//! ```solidity
//! operatorNetworkShares(subnetwork, operator)
//!     .mulDiv(Math.min(IVault(vault).activeStake(), networkLimit(subnetwork)),
//!             totalOperatorNetworkShares_);
//! ```
//!
//! a share quantity (`operatorNetworkShares`) converted into a withdrawable stake
//! amount (`activeStake`) by dividing through the share total
//! (`totalOperatorNetworkShares_`), with no rounding mode pinned. The rounding
//! direction here governs how slashing and withdrawals settle across operators.
//!
//! Precision (this MUST NOT flood ordinary maths — the prior version fired on
//! every internal `a * b / c` and produced 52 false positives across four
//! codebases: slippage `bal * slippage / 1000`, decimals `amt * 1e9 / 1e18`,
//! reward-index `index * shares / 1e18`, fee/penalty `10000 * amt / prev`,
//! exchange-rate and points maths). The rebuilt gate is deliberately narrow:
//!   * we ONLY match a **bare `mulDiv` with no `Rounding` argument** — the
//!     two-arg method form `x.mulDiv(a, b)` or the three-arg free form
//!     `Math.mulDiv(a, b, c)`. We no longer match a literal `a * b / c`, because
//!     in real code that raw shape is overwhelmingly slippage / decimals / bps /
//!     reward-index maths, and the genuine share↔asset conversions that *do* use
//!     it (e.g. a vault's `sharesForAmount`) are indistinguishable from those by
//!     shape alone. A bare `mulDiv` missing its rounding argument is both the
//!     precise defect and a far stronger signal of deliberate proportional
//!     pricing;
//!   * the divisor (last operand) must be a **pooled aggregate of shares/stake/
//!     assets** — it must read like `totalShares` / `totalSupply` /
//!     `totalOperatorNetworkShares` / `totalPooledEther` / `totalAssets` (a
//!     `total`/`supply`/`pooled` marker **and** a share/stake/asset marker). This
//!     is the `amount * totalShares / totalAssets` denominator, and it alone
//!     excludes the prior 2-arg `mulDiv` false positives whose divisor is a
//!     scaling constant (`WAD`, `BASIS_POINT_SCALE`) or a same-kind ratio (a prior
//!     balance, `oldAmount`);
//!   * the operands must jointly span **both** a share quantity (`share`) **and**
//!     a stake/asset amount (`stake`/`asset`/`amount`/`pooled`/`ether`/
//!     `underlying`), i.e. the conversion really turns shares into a withdrawable
//!     asset/stake amount;
//!   * we exclude reward-index / exchange-rate / rate / bps / fee / penalty /
//!     discount / points / price / `1e18` / `WAD` contexts on the operand tokens;
//!   * we keep `rounding.rs`'s suppression (rounding-mode enum, directional
//!     helper, `+ c - 1` ceil idiom) so a deliberately-rounded helper stays quiet;
//!   * we still only look at functions the `rounding-direction` detector cannot
//!     reach (its exact complement), so we never double-report its cases.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function, Span};

pub struct InternalSharePricingRoundingDetector;

/// A pooled-share quantity — the thing being priced. Kept narrow: only `share`,
/// because broad markers (`amount`/`balance`) are what made the prior detector
/// flood.
fn is_share_token(t: &str) -> bool {
    t.contains("share")
}

/// A stake / asset amount the shares convert *into* (the withdrawable side).
fn is_asset_token(t: &str) -> bool {
    ["stake", "asset", "amount", "pooled", "ether", "underlying", "collateral", "liquidity"]
        .iter()
        .any(|m| t.contains(m))
}

/// A `total*` / `supply` / `pooled` aggregate marker. The divisor of a genuine
/// pro-rata share conversion is the *total* of the share (or asset) pool.
fn is_aggregate_token(t: &str) -> bool {
    t.contains("total") || t.contains("supply") || t.contains("pooled")
}

/// Tokens that mark the maths as something *other* than share→asset pricing:
/// reward-index, exchange-rate, generic ratios, fees/penalties, basis points,
/// fixed-point scaling. If any operand carries one of these we stay silent.
fn is_excluded_token(t: &str) -> bool {
    [
        "index", "rate", "exchange", "bps", "basispoint", "basis_point", "fee", "penalty",
        "discount", "points", "price", "ratio", "factor", "weight", "magnitude", "wad", "ray",
        "precision", "scale", "slippage", "bips", "watermark", "threshold", "proportion", "split",
        "percent", "denominator",
    ]
    .iter()
    .any(|m| t.contains(m))
}

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
        "Internal/private share→stake pro-rata helper uses a bare mulDiv (no rounding mode) to price a withdrawable amount (escapes rounding-direction)"
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
            // mutating && conversion-named). Take the COMPLEMENT so we never
            // double-report its cases: only proceed for functions it cannot reach
            // — internal/private helpers, view pricing getters, or oddly-named
            // state-mutating functions.
            let owned_by_rounding =
                f.is_externally_reachable() && f.is_state_mutating() && is_conversion_name(&f.name);
            if owned_by_rounding {
                continue;
            }

            // Find a bare `mulDiv(...)` with NO `Rounding` argument whose operands
            // describe a genuine share→stake/asset pro-rata conversion.
            let Some(span) = find_share_pricing_muldiv(f) else {
                continue;
            };

            // Suppress when a rounding direction is pinned (helper or ceil idiom).
            if uses_explicit_rounding(cx, f) {
                continue;
            }

            let b = FindingBuilder::new(self.id(), Category::InternalSharePricingRounding)
                .title("Internal share/stake pricing uses a bare mulDiv with no rounding control")
                .severity(Severity::Low)
                .confidence(0.4)
                .dimension(Dimension::Invariant)
                .message(format!(
                    "`{}` converts a share/stake quantity into a withdrawable stake/asset amount with a \
                     bare `mulDiv(value, total)` (OpenZeppelin `Math.mulDiv` with **no** `Math.Rounding` \
                     argument), and it is not one of the externally-named conversion entry points \
                     (`deposit`/`withdraw`/`redeem`/`mint`/`burn`) that the `rounding-direction` detector \
                     inspects — it is an internal/private (or view-helper) pricing routine. With no \
                     rounding argument `Math.mulDiv` floors toward zero, so the result rounds against the \
                     protocol (or the disfavoured party) a few wei per call; in restaking / pooled-stake \
                     systems (e.g. Symbiotic's `NetworkRestakeDelegator._stakeAt` / `_stake`, which \
                     compute `operatorNetworkShares.mulDiv(activeStake, totalOperatorNetworkShares)`) this \
                     internal rounding direction governs how slashing and withdrawals settle across \
                     operators and can be biased by repeated dust-sized interactions.",
                    f.name
                ))
                .recommendation(
                    "Pass an explicit rounding mode to the helper's `mulDiv` so the residual favors the \
                     protocol: `Math.mulDiv(value, total, divisor, Math.Rounding.Floor/Ceil)` (or a \
                     `mulDivDown`/`mulDivUp` helper) with the direction chosen so dust accrues to the \
                     pool, and assert the share/stake invariant (sum of parts <= whole) at the call \
                     sites. Treat the internal pricing helper with the same ERC-4626 \"rounding favors \
                     the vault\" discipline as the public conversion functions.",
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

/// True if a `mulDiv` receiver expression is a math-*library namespace*
/// (`Math.mulDiv(...)`, `FullMath.mulDiv(...)`), not a value operand. Matched on
/// the bare-identifier receiver against a small set of well-known fixed-point /
/// math library names, so `Math` is never mistaken for a numerator.
fn is_math_namespace(recv: &Expr) -> bool {
    let ExprKind::Ident(n) = &recv.kind else { return false };
    let l = n.to_ascii_lowercase();
    [
        "math", "fullmath", "safemath", "mathupgradeable", "fixedpointmathlib", "fixedpoint",
        "prbmath", "wadraymath", "ud60x18", "sd59x18",
    ]
    .iter()
    .any(|m| l == *m || l.ends_with("math"))
}

/// Find a bare share→stake/asset pro-rata `mulDiv` with no rounding argument.
///
/// Accepts both spellings of OZ `Math.mulDiv` *without* the optional `Rounding`:
///   * the bound/method form `value.mulDiv(a, b)` — a *value* receiver, exactly
///     2 args (operands = `[value, a, b]`, divisor = `b`);
///   * the free form `Math.mulDiv(a, b, c)` / `mulDiv(a, b, c)` — a library
///     *namespace* receiver (or none), exactly 3 args (operands = `[a, b, c]`,
///     divisor = `c`).
/// A *third* method-arg (`value.mulDiv(a, b, Rounding)`) or *fourth* free-arg
/// pins the rounding mode, so those arities are skipped here (and also by
/// `uses_explicit_rounding`).
///
/// The operands must describe a genuine conversion: the **divisor** is a pooled
/// aggregate of shares/stake/assets (`total*`/`supply`/`pooled` + a share/stake/
/// asset marker), the operands jointly reference **both** a share quantity and a
/// stake/asset amount, and no operand carries an excluded (index/rate/bps/fee/…)
/// marker.
fn find_share_pricing_muldiv(f: &Function) -> Option<Span> {
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            if !c.func_name.as_deref().map(|n| n.eq_ignore_ascii_case("muldiv")).unwrap_or(false) {
                return;
            }
            // Collect the numerator/divisor operand expressions for the bare
            // (no-rounding) forms only. A `mulDiv` reaches us in two spellings:
            //   * the bound/method form `value.mulDiv(a, b)` — the receiver is a
            //     *value* operand, so a bare call has 2 args (operands = recv,a,b)
            //     and `value.mulDiv(a, b, Rounding)` (3 args) pins rounding;
            //   * the free form `Math.mulDiv(a, b, c)` — the receiver, if any, is
            //     the library *namespace* (`Math`) and is not an operand, so a bare
            //     call has 3 args (operands = a,b,c) and a 4th arg pins rounding.
            // We must not mistake the `Math` namespace for a numerator, nor a
            // genuine value-receiver's 3rd arg for a 4th positional.
            let namespace_receiver = c
                .receiver
                .as_deref()
                .map(is_math_namespace)
                .unwrap_or(false);
            let operands: Vec<&Expr> = match (&c.receiver, namespace_receiver, c.args.len()) {
                // `value.mulDiv(a, b)` — value receiver, 2 args, no rounding.
                (Some(recv), false, 2) => vec![recv.as_ref(), &c.args[0], &c.args[1]],
                // `Math.mulDiv(a, b, c)` — namespace receiver, 3 args, no rounding.
                (Some(_), true, 3) => vec![&c.args[0], &c.args[1], &c.args[2]],
                // `mulDiv(a, b, c)` — no receiver, 3 args, no rounding.
                (None, _, 3) => vec![&c.args[0], &c.args[1], &c.args[2]],
                // Any other arity (a `Rounding` argument is present) pins rounding.
                _ => return,
            };
            let divisor = *operands.last().unwrap();
            if operands_are_share_pricing(&operands, divisor) {
                found = Some(e.span);
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// Decide whether the operand set of a bare `mulDiv` describes a share→asset
/// pro-rata conversion that yields a withdrawable amount.
fn operands_are_share_pricing(operands: &[&Expr], divisor: &Expr) -> bool {
    // Token sets.
    let all_tokens: Vec<String> = operands.iter().flat_map(|e| name_tokens(e)).collect();
    let divisor_tokens = name_tokens(divisor);

    // Any excluded marker anywhere among the operands disqualifies (reward index,
    // exchange rate, bps, fee, penalty, scaling constant, ...).
    if all_tokens.iter().any(|t| is_excluded_token(t)) {
        return false;
    }

    // Divisor must be a pooled aggregate of shares/stake/assets:
    // `total`/`supply`/`pooled` AND a share/stake/asset marker.
    let divisor_is_pool_total = divisor_tokens.iter().any(|t| is_aggregate_token(t))
        && divisor_tokens
            .iter()
            .any(|t| is_share_token(t) || is_asset_token(t));
    if !divisor_is_pool_total {
        return false;
    }

    // The conversion must span both worlds: a share quantity AND a stake/asset
    // amount must appear among the operands.
    let has_share = all_tokens.iter().any(|t| is_share_token(t));
    let has_asset = all_tokens.iter().any(|t| is_asset_token(t));
    has_share && has_asset
}

/// Lower-cased identifier / member / callee-name tokens reachable inside an
/// expression subtree (used to classify a `mulDiv` operand). Includes the names
/// of nested calls (e.g. `IVault(vault).activeStake()` contributes `activestake`)
/// so a conversion expressed through getters is still recognized.
fn name_tokens(e: &Expr) -> Vec<String> {
    let mut v = Vec::new();
    e.visit(&mut |n| match &n.kind {
        ExprKind::Ident(s) => v.push(s.to_ascii_lowercase()),
        ExprKind::Member { member, .. } => v.push(member.to_ascii_lowercase()),
        ExprKind::Call(c) => {
            if let Some(fname) = &c.func_name {
                v.push(fname.to_ascii_lowercase());
            }
        }
        _ => {}
    });
    v
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

    // Vulnerable (Symbiotic `_stake` shape): the public entry points are thin,
    // and the pro-rata `operatorNetworkShares.mulDiv(activeStake, totalShares)`
    // conversion lives in an INTERNAL helper named `_stake` — exactly the place
    // the name-gated `rounding-direction` detector never inspects. The `mulDiv`
    // carries no `Math.Rounding` argument, so it floors silently.
    const VULN: &str = r#"
        contract NetworkRestakeDelegator {
            using Math for uint256;
            function stake(bytes32 subnetwork, address operator) external view returns (uint256) {
                return _stake(subnetwork, operator);
            }
            function _stake(bytes32 subnetwork, address operator) internal view returns (uint256) {
                uint256 totalOperatorNetworkShares_ = totalOperatorNetworkShares(subnetwork);
                return totalOperatorNetworkShares_ == 0
                    ? 0
                    : operatorNetworkShares(subnetwork, operator)
                        .mulDiv(activeStake(), totalOperatorNetworkShares_);
            }
        }
    "#;

    // Safe: the same internal pro-rata helper, but a `Math.Rounding` argument is
    // passed to `mulDiv`, so rounding was clearly considered — no finding.
    const SAFE: &str = r#"
        contract NetworkRestakeDelegator {
            using Math for uint256;
            function _stake(bytes32 subnetwork, address operator) internal view returns (uint256) {
                uint256 totalOperatorNetworkShares_ = totalOperatorNetworkShares(subnetwork);
                return operatorNetworkShares(subnetwork, operator)
                    .mulDiv(activeStake(), totalOperatorNetworkShares_, Math.Rounding.Floor);
            }
        }
    "#;

    // Negative control: a bare 2-arg `mulDiv`, but it is WAD fixed-point scaling
    // (`x.mulDiv(y, WAD)`), not a share→asset conversion. The divisor is a scaling
    // constant, not a pooled total, so the gate must keep this silent.
    const SAFE_WAD: &str = r#"
        contract SlashingLib {
            using Math for uint256;
            function mulWad(uint256 x, uint256 y) internal pure returns (uint256) {
                return x.mulDiv(y, WAD);
            }
        }
    "#;

    // Negative control: a bare 2-arg `mulDiv` whose divisor is a share total, but
    // the numerator is a basis-points fee split — an excluded (fee/bps) context,
    // not a withdrawable-amount conversion. Must stay silent.
    const SAFE_FEE: &str = r#"
        contract Redeem {
            using Math for uint256;
            function feeShares(uint256 totalShares) internal pure returns (uint256) {
                return totalShares.mulDiv(exitFeeInBps, totalShareSupply);
            }
        }
    "#;

    // Negative control: a reward-index accrual `index * shares / 1e18` expressed
    // as a literal `a * b / c`. The rebuilt detector matches only bare `mulDiv`,
    // so literal reward-index maths is silent by construction.
    const SAFE_INDEX: &str = r#"
        contract Rewards {
            function _accrued(uint256 shares) internal view returns (uint256) {
                return rewardsGlobalIndex * shares / 1e18;
            }
        }
    "#;

    // Vulnerable, free-function form: `Math.mulDiv(shares, stake, totalShares)`
    // with the library *namespace* as the receiver and no `Rounding` argument.
    // The namespace must not be mistaken for a numerator, and the 3-arg shape
    // must be recognized as bare (not rounding-pinned).
    const VULN_FREE: &str = r#"
        contract Delegator {
            function _stake(address operator) internal view returns (uint256) {
                return Math.mulDiv(operatorShares(operator), activeStake(), totalOperatorShares);
            }
        }
    "#;

    #[test]
    fn fires_on_internal_helper() {
        let fs = run(VULN);
        assert!(
            fs.iter().any(|f| f.detector == "internal-share-pricing-rounding"),
            "{:#?}",
            fs
        );
    }

    #[test]
    fn fires_on_free_function_form() {
        let fs = run(VULN_FREE);
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
    fn silent_on_wad_scaling() {
        let fs = run(SAFE_WAD);
        assert!(!fs.iter().any(|f| f.detector == "internal-share-pricing-rounding"));
    }

    #[test]
    fn silent_on_fee_bps() {
        let fs = run(SAFE_FEE);
        assert!(!fs.iter().any(|f| f.detector == "internal-share-pricing-rounding"));
    }

    #[test]
    fn silent_on_reward_index() {
        let fs = run(SAFE_INDEX);
        assert!(!fs.iter().any(|f| f.detector == "internal-share-pricing-rounding"));
    }
}
