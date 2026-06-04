//! Spot-priced exchange-rate / price-per-share value getter (asymmetry H-04).
//!
//! A protocol's *price-per-share* / *exchange-rate* function (`ethPerDerivative`,
//! `*PerShare`, `exchangeRate`, `getRate`, `pricePer*`, …) is the canonical input
//! to mint/redeem share pricing. When it derives the share value from a
//! **manipulable on-chain spot source** — a Curve `price_oracle()` pool-state read,
//! an AMM `get_dy`/`getAmountsOut`/`getReserves`, a Uni-v3 `slot0`/`getSqrtRatioX96`,
//! a raw `spotPrice` — with NO averaging window (TWAP/`observe`/`consult`), NO
//! Chainlink feed cross-check with staleness validation, and NO min/max bound clamp,
//! an attacker can sandwich / flash-loan-move the source within one transaction and
//! mint or redeem shares at a mis-price.
//!
//! This is asymmetry H-04: `SfrxEth.ethPerDerivative` values the sfrxETH derivative
//! as `10**18 * convertToAssets(1e18) / IFrxEthEthPool(pool).price_oracle()`. The
//! `price_oracle()` divisor is a Curve pool-state read (manipulable), so the share
//! price moves with the pool — and `ethPerDerivative` drives `SafEth.stake`/`unstake`.
//!
//! ## Relationship to the existing oracle detectors (no double-fire intent)
//!
//! * `oracle-manipulation` (oracle.rs) fires on a generic *valuation* function that
//!   reads a `balanceOf`/`getReserves`/`slot0` spot — but it explicitly does NOT
//!   treat a `price_oracle()` pool getter as a manipulable spot source (it is not in
//!   the shared `is_spot_price_call` set, nor a `balanceOf`), so H-04's
//!   `price_oracle()` divisor slips past it. This detector adds the missing
//!   *price-per-share getter* surface: a function whose NAME is an exchange-rate /
//!   per-share getter and whose RETURN is computed from a manipulable spot source.
//! * `twap-manipulation` covers the `slot0`/`observe`-window "fake TWAP" read.
//! * `oracle-staleness` covers a Chainlink feed consumed without a freshness check.
//!
//! To protect precision the finding is **Medium** with a single corroborating
//! dimension; the corroboration scorer promotes it only when another dimension
//! agrees. We are deliberately CONSERVATIVE: we suppress when the value comes from a
//! Chainlink feed used with a staleness check, from a TWAP/observation window, or
//! from a redemption/`previewRedeem`-style call (a real share-value query, not a
//! spot price).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{ExprKind, Function, Span};

pub struct SpotPricedShareValueDetector;

/// Manipulable spot-source method names: a read of live pool/AMM state that an
/// attacker can move within one (flash-loan-assisted) transaction. These are NOT
/// push-feed answers and NOT time-averaged.
///   * `price_oracle` / `get_p` / `last_price` / `ema_price` — Curve pool getters
///     (each a pool-state read; Curve's `price_oracle` is an EMA over the *prior*
///     block but is still same-/adjacent-block movable and carries no staleness or
///     deviation guard — it is the H-04 source).
///   * `get_dy` / `get_dx` / `calc_withdraw_one_coin` — Curve quote functions
///     (instantaneous pool math).
///   * `getamountsout` / `getamountout` / `quote` — Uni-v2-style spot quotes.
///   * `getreserves` — raw pair reserves.
///   * `slot0` / `getsqrtratioatx96` / `getsqrtpricex96` — Uni-v3 instantaneous price.
///   * `spotprice` / `getspotprice` — Balancer-style spot price.
const SPOT_SOURCE_METHODS: &[&str] = &[
    "price_oracle",
    "get_p",
    "last_price",
    "lp_price",
    "get_dy",
    "get_dx",
    "calc_withdraw_one_coin",
    "getamountsout",
    "getamountout",
    "getreserves",
    "slot0",
    "getslot0",
    "spotprice",
    "getspotprice",
    "getsqrtpricex96",
    "getsqrtratioatx96",
];

/// Method names that, on an oracle/feed handle, denote a robust push-feed answer
/// (Chainlink) — these are an oracle-staleness concern, never a movable spot price.
const FEED_METHODS: &[&str] = &["latestrounddata", "latestanswer", "getrounddata", "getanswer"];

/// True-TWAP / averaging primitives — a price read through one of these has a
/// window (whose adequacy is `twap-manipulation`'s concern, not ours).
const TWAP_METHODS: &[&str] = &["observe", "observesingle", "consult", "gettimeweightedaverage"];

/// Redemption / preview methods that return a *real* share value from the share
/// token itself (ERC-4626) — not a spot price. `convertToAssets`/`previewRedeem`
/// query the vault's own accounting; only when COMBINED with a spot divisor (as in
/// H-04) is the result manipulable, and that spot divisor is what we key on.
const REDEMPTION_METHODS: &[&str] =
    &["previewredeem", "previewmint", "previewdeposit", "previewwithdraw", "redeem"];

impl Detector for SpotPricedShareValueDetector {
    fn id(&self) -> &'static str {
        "spot-priced-share-value"
    }
    fn category(&self) -> Category {
        Category::SpotPricedShareValue
    }
    fn description(&self) -> &'static str {
        "Price-per-share / exchange-rate getter derives share value from a manipulable on-chain spot source"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || !f.is_externally_reachable() {
                continue;
            }
            // Interface/abstract declarations carry no integration risk.
            if cx.contract_of(f.id).map(|c| c.is_interface()).unwrap_or(false) {
                continue;
            }
            // (1) The function NAME must read like a price-per-share / exchange-rate
            //     / value getter — the share-pricing surface, not an arbitrary fn.
            if !is_price_per_share_name(&f.name) {
                continue;
            }
            // (2) It must compute a *returned* numeric value (a quantity used in
            //     math downstream), not a string label / bool.
            if !f.returns.iter().any(|r| ty_is_numeric_quantity(&r.ty)) {
                continue;
            }

            // (3) The value must derive from a manipulable spot source.
            let Some(span) = find_spot_source(f) else { continue };

            // (4) Mitigation suppression (precision first):
            //   * a robust Chainlink feed (staleness is a separate class), OR
            //   * a true-TWAP / observation-window read,
            //   anywhere on this function — means the value is not a raw spot read.
            if cx.uses_robust_oracle(f) || uses_feed_or_twap(f) {
                continue;
            }
            //   * a min/max bound clamp on the computed value (a `require`/`min`/`max`
            //     / clamp guard) is a deliberate manipulation guard.
            if has_bound_clamp(cx, f) {
                continue;
            }

            let b = FindingBuilder::new(self.id(), Category::SpotPricedShareValue)
                .title("Price-per-share / exchange-rate derived from a manipulable on-chain spot source")
                // Medium by design: a manipulable share-price source is a real
                // mis-pricing vector, but to protect precision we base it Medium and
                // let the corroboration scorer promote it to High only when another
                // dimension (the mint/redeem ValueFlow, a frontier read) agrees. A
                // single Frontier dimension keeps the scorer from over-promoting on
                // the getter alone.
                .severity(Severity::Medium)
                .confidence(0.5)
                .dimension(Dimension::Frontier)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` is a price-per-share / exchange-rate getter that derives the share value \
                     from a manipulable on-chain spot source (a Curve `price_oracle()` pool read, an \
                     AMM `get_dy`/`getAmountsOut`/`getReserves` quote, a Uni-v3 `slot0`, or a raw \
                     `spotPrice`) with NO time-averaging (TWAP/`observe`/`consult`), NO Chainlink feed \
                     cross-check with a staleness guard, and NO min/max bound clamp. Because this \
                     value drives mint/redeem share pricing, an attacker can sandwich or flash-loan-move \
                     the source within one transaction and mint or redeem shares at a mis-price \
                     (the asymmetry H-04 `SfrxEth.ethPerDerivative` / Curve `price_oracle` class).",
                    f.name
                ))
                .recommendation(
                    "Price the share value via a manipulation-resistant source: a Chainlink feed with \
                     staleness + deviation checks, or a sufficiently long TWAP, and clamp the result \
                     to sane min/max bounds. Never derive a price-per-share / exchange-rate directly \
                     from an instantaneous pool read (`price_oracle()`, `get_dy`, `getReserves`, \
                     `slot0`).",
                );
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

// ------------------------------------------------------------------ heuristics

/// Does the function name read like a price-per-share / exchange-rate / value
/// getter? `ethPerDerivative`, `*PerShare`, `exchangeRate`, `getRate`, `pricePer*`,
/// `*Price`, `getPrice`, `sharePrice`, `convertToAssets`-style `*ToAssets`, …
fn is_price_per_share_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // `*per*` getters: `ethPerDerivative`, `pricePerShare`, `assetsPerShare`.
    if l.contains("per") && (l.contains("share") || l.contains("derivative") || l.contains("asset") || l.contains("token") || l.contains("price") || l.contains("eth")) {
        return true;
    }
    // exchange-rate / rate getters.
    if l.contains("exchangerate") || l == "getrate" || l == "rate" || l.ends_with("rate") {
        return true;
    }
    // price getters (a *price* getter is the share-pricing surface).
    if l.contains("price") {
        return true;
    }
    // value-per / per-value getters and `*ToAssets`/`*ToShares` conversions.
    if l.ends_with("toassets") || l.ends_with("toshares") {
        return true;
    }
    false
}

/// True if a return type denotes a numeric quantity (`uint*` / `int*`), incl. an
/// array of one. A `bytes`/`string`/`bool`/`address` return is not a price.
fn ty_is_numeric_quantity(ty: &str) -> bool {
    let base = ty.trim().split([' ', '[']).next().unwrap_or("").trim();
    base.starts_with("uint") || base.starts_with("int")
}

/// Find the first manipulable-spot-source read in `f`'s body, returning its span.
/// Matched on the resolved call method name (a CALL expression), so a bare
/// identifier that merely *contains* one of the tokens never trips it.
fn find_spot_source(f: &Function) -> Option<Span> {
    let mut found: Option<Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if let Some(name) = c.func_name.as_deref() {
                    let l = name.to_ascii_lowercase();
                    if SPOT_SOURCE_METHODS.iter().any(|m| l == *m) {
                        found = Some(e.span);
                    }
                }
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// Does `f` read a Chainlink feed (`latestRoundData`/…) or a true-TWAP primitive
/// (`observe`/`consult`/…)? Either means the value is not a raw spot read, so this
/// detector defers (Chainlink → oracle-staleness; TWAP window → twap-manipulation).
fn uses_feed_or_twap(f: &Function) -> bool {
    let mut hit = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if let Some(name) = c.func_name.as_deref() {
                    let l = name.to_ascii_lowercase();
                    if FEED_METHODS.contains(&l.as_str())
                        || TWAP_METHODS.contains(&l.as_str())
                        || REDEMPTION_METHODS.contains(&l.as_str())
                    {
                        hit = true;
                    }
                }
            }
        });
        if hit {
            break;
        }
    }
    hit
}

/// Does `f` clamp the computed value to a bound — a `require`/`assert` guard, or a
/// `min`/`max`/`clamp`/`bound` call? A deliberate manipulation bound suppresses the
/// finding (the integrator added a sanity band).
fn has_bound_clamp(cx: &AnalysisContext, f: &Function) -> bool {
    let src = cx.source_text(f.span).to_ascii_lowercase();
    // A min/max/clamp/bound helper call, or a require/assert that compares the
    // value (a sanity band). We keep this textual + conservative: any of these is
    // strong evidence the integrator bounded the result.
    src.contains("clamp")
        || src.contains(".min(")
        || src.contains(".max(")
        || src.contains("math.min")
        || src.contains("math.max")
        || src.contains("bound(")
        || src.contains("require(")
        || src.contains("revert ")
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn fired(src: &str) -> bool {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default())
            .findings
            .iter()
            .any(|f| f.detector == "spot-priced-share-value")
    }

    // TRUE-POSITIVE (asymmetry H-04): `SfrxEth.ethPerDerivative` derives the share
    // value from the Curve pool's `price_oracle()` (a manipulable pool-state read)
    // with no TWAP, no Chainlink cross-check, no bound clamp. MUST fire.
    const ASYMMETRY_H04: &str = r#"
        interface IsFrxEth { function convertToAssets(uint256 a) external view returns (uint256); }
        interface IFrxEthEthPool { function price_oracle() external view returns (uint256); }
        contract SfrxEth {
            address public constant SFRX_ETH_ADDRESS = address(0x1);
            address public constant FRX_ETH_CRV_POOL_ADDRESS = address(0x2);
            function ethPerDerivative(uint256 _amount) public view returns (uint256) {
                uint256 frxAmount = IsFrxEth(SFRX_ETH_ADDRESS).convertToAssets(10 ** 18);
                return ((10 ** 18 * frxAmount) /
                    IFrxEthEthPool(FRX_ETH_CRV_POOL_ADDRESS).price_oracle());
            }
        }
    "#;

    // TRUE-POSITIVE: a generic `pricePerShare` getter that derives the price from a
    // Uni-v2 `getReserves()` ratio — the canonical flash-manipulable spot read.
    const PRICE_PER_SHARE_RESERVES: &str = r#"
        interface IPair { function getReserves() external view returns (uint112, uint112, uint32); }
        contract Vault {
            IPair public pair;
            function pricePerShare() external view returns (uint256) {
                (uint112 r0, uint112 r1, ) = pair.getReserves();
                return (uint256(r1) * 1e18) / uint256(r0);
            }
        }
    "#;

    // FALSE-POSITIVE GUARD: a price getter reading a Chainlink feed WITH a staleness
    // check. A push-feed answer is not flash-movable within a tx — this is an
    // oracle-staleness concern, not a spot-price one. MUST stay silent.
    const CHAINLINK_WITH_STALENESS: &str = r#"
        interface AggregatorV3Interface {
            function latestRoundData() external view
                returns (uint80, int256, uint256, uint256, uint80);
        }
        contract Oracle {
            AggregatorV3Interface public feed;
            uint256 internal constant MAX_DELAY = 3600;
            function getPrice() external view returns (uint256) {
                (uint80 roundId, int256 price, , uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
                require(price > 0, "bad price");
                require(answeredInRound >= roundId, "stale round");
                require(block.timestamp - updatedAt <= MAX_DELAY, "stale");
                return uint256(price);
            }
        }
    "#;

    // FALSE-POSITIVE GUARD: a TWAP / `observe`-based exchange-rate getter with a
    // fixed averaging window. A time-weighted read is not a raw spot price — this is
    // twap-manipulation's domain. MUST stay silent.
    const TWAP_EXCHANGE_RATE: &str = r#"
        interface IUniswapV3Pool {
            function observe(uint32[] calldata secondsAgos)
                external view returns (int56[] memory, uint160[] memory);
        }
        contract RateOracle {
            IUniswapV3Pool public pool;
            uint32 public constant TWAP_PERIOD = 1800;
            function exchangeRate() external view returns (uint256 rate) {
                uint32[] memory secondsAgos = new uint32[](2);
                secondsAgos[0] = TWAP_PERIOD;
                secondsAgos[1] = 0;
                (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);
                int56 delta = tickCumulatives[1] - tickCumulatives[0];
                rate = uint256(uint56(delta)) / TWAP_PERIOD;
            }
        }
    "#;

    #[test]
    fn fires_on_asymmetry_h04() {
        assert!(
            fired(ASYMMETRY_H04),
            "ethPerDerivative deriving share value from Curve price_oracle() MUST fire (H-04)"
        );
    }

    #[test]
    fn fires_on_price_per_share_reserves() {
        assert!(
            fired(PRICE_PER_SHARE_RESERVES),
            "pricePerShare from getReserves() ratio is flash-manipulable — MUST fire"
        );
    }

    #[test]
    fn silent_on_chainlink_with_staleness() {
        assert!(
            !fired(CHAINLINK_WITH_STALENESS),
            "a Chainlink price getter with a staleness check is not a movable spot price"
        );
    }

    #[test]
    fn silent_on_twap_exchange_rate() {
        assert!(
            !fired(TWAP_EXCHANGE_RATE),
            "a TWAP/observe-based exchange-rate getter has an averaging window — not a spot price"
        );
    }
}
