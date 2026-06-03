//! Externally-sourced share-rate trusted with only a monotonic floor (`max`)
//! clamp — no **per-update jump bound** — before it drives pricing/state.
//!
//! A great many yield/restaking integrations read a share→asset *rate* from an
//! external contract they do not control: an SY/wrapper `exchangeRate()`, a
//! vault `pricePerShare()` / `convertToAssets()`, a rate-provider `getRate()`,
//! a Pendle `pyIndexCurrent()`. That number is then stored and/or fed straight
//! into pricing maths. The only sanity applied is a **monotonic floor** — the
//! `max(newRate, previousRate)` idiom that guarantees the index never decreases
//! — and/or a bare `require(rate > 0)`. Neither caps how far the rate may move
//! in a single update.
//!
//! The canonical shape is Pendle's `PendleYieldToken._pyIndexCurrent`:
//! ```solidity
//! uint128 index128 = PMath.max(IStandardizedYield(SY).exchangeRate(), _pyIndexStored).Uint128();
//! currentIndex = index128;
//! _pyIndexStored = index128;            // <- stored, and flows to MarketMathCore pricing
//! ```
//! and the same `PMath.max(SY.exchangeRate(), pyIndexStored)` appears in the
//! view rate-getters (`ActionMintRedeemStatic.pyIndexCurrentViewYt`,
//! `PendlePYOracleLib.getSYandPYIndexCurrent`) that feed the oracle / router.
//!
//! Why this is a value-flow hazard: `max(new, prev)` only stops the rate going
//! *down*. If the external SY (a third-party yield source whose `exchangeRate`
//! Pendle does not own) returns a wildly inflated value — a buggy/compromised
//! adapter, a donation/first-deposit inflation, a mis-scaled decimals upgrade —
//! the monotonic clamp happily *accepts the larger number* and pins it forever
//! (it can never come back down). The inflated index then misprices every
//! PT/YT/LP mint, redeem and oracle read. The correct guard is a per-update
//! **jump bound**: `require(new <= prev * MAX_FACTOR)`, a max-delta /
//! max-deviation check, or a `[min, max]` band — bounding the *magnitude* of a
//! single move, which `max`/`require(>0)` do not.
//!
//! ## Distinctness
//! * Not `price-bounds` (Chainlink `minAnswer`/`maxAnswer`): that fires only on
//!   `latestRoundData`/`latestAnswer` aggregator reads. We fire on share-rate
//!   getters and require the tell-tale monotonic `max` clamp.
//! * Not `crosschain-rate-staleness`: that is a *temporal* check (a bridge-
//!   supplied timestamp). This is a *magnitude* bound — orthogonal.
//! * Not `oracle-staleness` (freshness) — again temporal, not magnitude.
//!
//! ## Precision (aim: 0 FP on the 7 non-Pendle codebases)
//! The discriminating anchor is the **monotonic `max(rate, prev)` clamp on the
//! external rate**. Across the FP codebases the share-rate getter names are rare
//! (etherfi `cbEth.exchangeRate()` quote maths, renzo `getRate`/`exchangeRate`
//! passthroughs) and *none* wrap the rate in a `max(new, prev)` clamp, so they
//! never match. We additionally:
//!   * require the clamped result to reach state (a storage write) or be
//!     returned (the getter's whole purpose is to yield the pricing index);
//!   * suppress when any jump-bound marker (max-increase / max-deviation /
//!     delta / band / rate-cap …) appears, or a structural `min(rate, …)` upper
//!     clamp / `rate <op> prev * k` comparison bounds the magnitude.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, CallKind, Expr, ExprKind, Function, Span, StmtKind};

use super::prelude::*;

pub struct SyRateJumpTrustDetector;

/// Names of an *external* share→asset rate getter. The value these return is a
/// price/index that, unbounded, mis-scales every downstream conversion. Matched
/// case-insensitively against a call's resolved `func_name`.
const RATE_GETTER_NAMES: &[&str] = &[
    "exchangerate",
    "pricepershare",
    "getrate",
    "converttoassets",
    "pyindexcurrent",
];

/// Textual evidence that a *per-update jump / magnitude* bound is enforced
/// somewhere in the function or its contract. Any of these means the move size
/// is being constrained (a max-increase, a deviation cap, a delta, an explicit
/// band, a rate cap), so the monotonic-only pattern does not apply — suppress.
const JUMP_BOUND_MARKERS: &[&str] = &[
    "maxincrease",
    "maxrateincrease",
    "maxchange",
    "maxratechange",
    "maxdelta",
    "maxratedelta",
    "ratedelta",
    "maxdeviation",
    "deviation",
    "maxratepershare",
    "ratecap",
    "maxrate",
    "rateupperbound",
    "maxgrowth",
    "growthcap",
    "maxapr",
    "maxapy",
    "jump",
    "maxjump",
    "ratejump",
    "pctchange",
    "percentchange",
    "maxpct",
    "tolerance",
];

impl Detector for SyRateJumpTrustDetector {
    fn id(&self) -> &'static str {
        "sy-rate-jump-trust"
    }
    fn category(&self) -> Category {
        Category::SyRateJumpTrust
    }
    fn description(&self) -> &'static str {
        "External share-rate getter trusted with only a monotonic max() clamp / require(>0) — no per-update jump bound — before driving pricing/state"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || f.is_modifier() || f.is_constructor() {
                continue;
            }
            // We deliberately do NOT gate on visibility. The load-bearing
            // index/rate maths frequently lives in an `internal`/library view
            // helper (Pendle's `_pyIndexCurrent` is `internal`; the oracle's
            // `PendlePYOracleLib.getSYandPYIndexCurrent` is an `internal`
            // library fn). The discriminating anchor — an external rate getter
            // wrapped in a monotonic `max(rate, prev)` clamp whose result is
            // stored or returned (steps 1–3 below) — is specific enough that
            // visibility adds no precision (and would miss these real sites).
            //
            // A bare interface declaration has no body logic to bound.
            if cx.contract_of(f.id).map(|c| c.is_interface()).unwrap_or(false) {
                continue;
            }

            // (1) Find an EXTERNAL share-rate getter call in the body.
            let Some((rate_span, rate_local)) = first_rate_getter(f) else {
                continue;
            };

            // (2) The rate must be clamped with the monotonic `max(rate, prev)`
            //     idiom — the tell-tale "only a floor, no ceiling" signal — where
            //     the rate enters `max` either directly (Form A: the getter call
            //     is itself an argument) or via the local it was bound to
            //     (Form B: `local = SY.exchangeRate(); max(local, prev)`).
            if !rate_is_max_clamped(f, rate_local.as_deref()) {
                continue;
            }

            // (3) The clamped result must reach pricing/state: a storage write
            //     (the stored index) or a return (the getter yields the index
            //     that downstream pricing consumes).
            if !reaches_pricing_or_state(f) {
                continue;
            }

            // (4) Suppress when a per-update jump / magnitude bound is present:
            //     a textual marker, or a structural `min(rate, …)` upper clamp /
            //     `rate <op> prev * k` ratio comparison.
            if has_jump_bound(cx, f, rate_local.as_deref()) {
                continue;
            }

            let b = report!(self, Category::SyRateJumpTrust,
                title = "External share-rate trusted with only a monotonic clamp, no per-update jump bound",
                severity = Severity::High,
                confidence = 0.8,
                dimensions = [Dimension::ValueFlow],
                message = format!(
                    "`{}` reads a share/asset rate from an external contract it does not control (an \
                     `exchangeRate`/`pricePerShare`/`getRate`/`convertToAssets`/`pyIndexCurrent`-style \
                     getter) and trusts it after only a *monotonic* `max(newRate, previousRate)` clamp \
                     (and/or a `require(rate > 0)`), then lets the value drive pricing/state. `max(new, \
                     prev)` only prevents the rate from decreasing — it does NOT bound how far it may \
                     jump in a single update. If the external source returns a wildly inflated value (a \
                     buggy/compromised adapter, a donation/first-deposit inflation, a mis-scaled decimals \
                     change) the clamp accepts the larger number and pins it permanently, mispricing \
                     every downstream mint/redeem/oracle read. This is the Pendle \
                     `PendleYieldToken._pyIndexCurrent` shape (`PMath.max(SY.exchangeRate(), \
                     _pyIndexStored)` flowing into MarketMathCore).",
                    f.name
                ),
                recommendation =
                    "Bound the *magnitude* of a single rate update, not just its direction: enforce a \
                     per-update jump cap such as `require(newRate <= prevRate * MAX_FACTOR / ONE)` (and a \
                     symmetric floor), a max-deviation / max-delta check, or an explicit `[min, max]` \
                     band, in addition to the monotonic `max`. Reject or pause on an out-of-band rate \
                     rather than silently accepting and storing it.",
            );
            out.push(finish_at(cx, b, f.id, rate_span));
        }
        out
    }
}

/// The span of the first **external** share-rate getter call in `f`, plus the
/// name of the local variable it is bound to in a `T x = <getter>();` /
/// `x = <getter>();` statement, if any (Form B). For the direct form (Form A)
/// the local is `None`.
fn first_rate_getter(f: &Function) -> Option<(Span, Option<String>)> {
    // First pass: a `VarDecl`/`Assign` whose initializer is *exactly* an
    // external rate getter binds a local we must track for the `max` clamp.
    for s in &f.body {
        if let Some((span, local)) = stmt_binds_rate_getter(&s.kind) {
            return Some((span, Some(local)));
        }
    }
    // Otherwise, any external rate-getter call anywhere (Form A: it is wrapped
    // directly in `max(...)`).
    let span = first_call_where(f, is_rate_getter_call)?;
    Some((span, None))
}

/// If `kind` is `T x = recv.exchangeRate();` or `x = recv.exchangeRate();`
/// (the initializer being *directly* a rate getter), return `(call_span, x)`.
fn stmt_binds_rate_getter(kind: &StmtKind) -> Option<(Span, String)> {
    match kind {
        StmtKind::VarDecl { name: Some(name), init: Some(init), .. } => {
            rate_getter_span(init).map(|sp| (sp, name.clone()))
        }
        StmtKind::Expr(e) => {
            if let ExprKind::Assign { target, value, .. } = &e.kind {
                if let Some(name) = root_ident(target) {
                    return rate_getter_span(value).map(|sp| (sp, name));
                }
            }
            None
        }
        _ => None,
    }
}

/// If `e` is itself an external rate-getter call, its span.
fn rate_getter_span(e: &Expr) -> Option<Span> {
    let inner = peel_casts(e);
    if let ExprKind::Call(c) = &inner.kind {
        if is_rate_getter_call(c) {
            return Some(inner.span);
        }
    }
    None
}

/// Is `c` an **external** call to a share-rate getter (by resolved name)?
fn is_rate_getter_call(c: &sluice_ir::Call) -> bool {
    if c.kind != CallKind::External {
        return false;
    }
    c.func_name
        .as_deref()
        .map(|n| {
            let l = n.to_ascii_lowercase();
            RATE_GETTER_NAMES.iter().any(|g| l == *g)
        })
        .unwrap_or(false)
}

/// Does the function apply a monotonic `max(...)` clamp whose arguments carry
/// the external rate — directly (a rate-getter call inside the `max` args) or
/// through the bound local `rate_local` (`max(local, prev)`)?
fn rate_is_max_clamped(f: &Function, rate_local: Option<&str>) -> bool {
    any_call_where(f, |c| {
        if !is_max_call(c) {
            return false;
        }
        // Some argument must reference the rate: either an inner rate-getter
        // call (Form A) or the local the getter was bound to (Form B).
        c.args.iter().any(|a| {
            arg_contains_rate_getter(a) || rate_local.is_some_and(|l| expr_mentions_ident(a, l))
        })
    })
}

/// Is `c` a `max(...)` call (the monotonic clamp)? Matches the free/library form
/// `PMath.max(a, b)` / `Math.max(a, b)` and a bound `a.max(b)` — keyed on the
/// resolved `max` name. Requires at least two operands (receiver + arg, or two
/// args) so a unary helper named `max` is not mistaken for the two-sided clamp.
fn is_max_call(c: &sluice_ir::Call) -> bool {
    let is_max = c
        .func_name
        .as_deref()
        .map(|n| n.eq_ignore_ascii_case("max"))
        .unwrap_or(false);
    if !is_max {
        return false;
    }
    // `PMath.max(a, b)` → 2 args; `a.max(b)` → receiver + 1 arg. The receiver of
    // a *library* form (`PMath`/`Math`) is the namespace, not an operand, but in
    // either case "two operands" holds when args.len()>=2 OR (receiver && >=1).
    c.args.len() >= 2 || (c.receiver.is_some() && !c.args.is_empty())
}

/// Does `e` contain (anywhere in its subtree) an external rate-getter call?
/// Used to recognize Form A (`max(SY.exchangeRate(), prev)`).
fn arg_contains_rate_getter(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Call(c) = &sub.kind {
            if is_rate_getter_call(c) {
                found = true;
            }
        }
    });
    found
}

/// Does the function write a state variable (a stored rate/index) anywhere? Used
/// both as a reachability relaxation (an `internal` index updater still counts)
/// and as part of the "reaches pricing/state" check.
fn writes_rate_state(f: &Function) -> bool {
    !f.effects.storage_writes.is_empty()
}

/// The clamped rate reaches pricing/state if the function writes storage (the
/// stored index, e.g. `_pyIndexStored = …`) OR produces a value (a getter whose
/// whole purpose is to hand the index to downstream pricing). A value is
/// produced when the function declares any return parameter — covering both an
/// explicit `return <expr>;` and the named-return idiom Pendle uses
/// (`returns (uint256 pyIndex) { … pyIndex = PMath.max(…); }`, no `return`
/// keyword) — or has an explicit `return <expr>;` anywhere.
fn reaches_pricing_or_state(f: &Function) -> bool {
    if writes_rate_state(f) || !f.returns.is_empty() {
        return true;
    }
    let mut returns_value = false;
    for s in &f.body {
        s.visit(&mut |st| {
            if matches!(&st.kind, StmtKind::Return(Some(_))) {
                returns_value = true;
            }
        });
        if returns_value {
            break;
        }
    }
    returns_value
}

/// Suppress when a per-update jump / magnitude bound constrains the rate:
///   * a textual marker (max-increase / deviation / delta / band / rate-cap …)
///     in the function or its surrounding contract source; or
///   * a structural `min(rate, …)` *upper* clamp on the rate (caps the upside);
///     or
///   * an ordering comparison `rate <op> prev * k` / `rate <op> prev / k` where
///     one side multiplies/divides (a ratio bound on the move size).
fn has_jump_bound(cx: &AnalysisContext, f: &Function, rate_local: Option<&str>) -> bool {
    let src = cx.source_text(f.span);
    let marker = |text: &str| JUMP_BOUND_MARKERS.iter().any(|m| text.contains(m));
    if marker(&src) {
        return true;
    }
    if let Some(c) = cx.contract_of(f.id) {
        if marker(&cx.source_text(c.span)) {
            return true;
        }
    }
    // Structural: a `min(rate, …)` upper clamp bounds the magnitude from above.
    let min_clamps_rate = any_call_where(f, |c| {
        let is_min = c
            .func_name
            .as_deref()
            .map(|n| n.eq_ignore_ascii_case("min"))
            .unwrap_or(false);
        if !is_min {
            return false;
        }
        c.args.iter().any(|a| {
            arg_contains_rate_getter(a) || rate_local.is_some_and(|l| expr_mentions_ident(a, l))
        })
    });
    if min_clamps_rate {
        return true;
    }
    // Structural: an ordering comparison that bounds the rate against a *scaled*
    // operand (`prev * k`, `prev / k`) — i.e. one side of the comparison is a
    // Mul/Div. A bare `rate > 0` (no Mul/Div) is only a sign check and does NOT
    // suppress.
    rate_compared_against_scaled(f, rate_local)
}

/// True if some ordering comparison in the body has the rate (the getter call or
/// its bound local) on one side and a multiplicative expression (`* k` / `/ k`)
/// on the other — a magnitude/ratio bound on the move.
fn rate_compared_against_scaled(f: &Function, rate_local: Option<&str>) -> bool {
    let mentions_rate = |e: &Expr| -> bool {
        arg_contains_rate_getter(e) || rate_local.is_some_and(|l| expr_mentions_ident(e, l))
    };
    let mut bounded = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if bounded {
                return;
            }
            if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
                if op.is_ordering() {
                    let (rate_side, other) = if mentions_rate(lhs) {
                        (true, rhs.as_ref())
                    } else if mentions_rate(rhs) {
                        (true, lhs.as_ref())
                    } else {
                        (false, lhs.as_ref())
                    };
                    if rate_side && contains_mul_or_div(other) {
                        bounded = true;
                    }
                }
            }
        });
        if bounded {
            break;
        }
    }
    bounded
}

/// Does `e` contain a `Mul` or `Div` anywhere in its subtree?
fn contains_mul_or_div(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |n| {
        if let ExprKind::Binary { op: BinOp::Mul | BinOp::Div, .. } = &n.kind {
            found = true;
        }
    });
    found
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fired(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "sy-rate-jump-trust")
    }

    // Vulnerable (Pendle `_pyIndexCurrent` shape, Form A): the external SY
    // `exchangeRate()` is trusted after ONLY a monotonic `PMath.max(new, prev)`
    // clamp, and the result is stored (`_pyIndexStored`) and returned — there is
    // no per-update jump bound, so a wildly inflated SY rate is accepted and
    // pinned forever.
    const VULN: &str = r#"
        interface IStandardizedYield { function exchangeRate() external returns (uint256); }
        library PMath {
            function max(uint256 x, uint256 y) internal pure returns (uint256) { return x > y ? x : y; }
            function Uint128(uint256 x) internal pure returns (uint128) { return uint128(x); }
        }
        contract PendleYieldToken {
            using PMath for uint256;
            address public immutable SY;
            uint128 internal _pyIndexStored;
            uint128 public pyIndexLastUpdatedBlock;
            bool public immutable doCacheIndexSameBlock;
            function pyIndexCurrent() public returns (uint256 currentIndex) {
                if (doCacheIndexSameBlock && pyIndexLastUpdatedBlock == block.number) return _pyIndexStored;
                uint128 index128 = PMath.max(IStandardizedYield(SY).exchangeRate(), _pyIndexStored).Uint128();
                currentIndex = index128;
                _pyIndexStored = index128;
                pyIndexLastUpdatedBlock = uint128(block.number);
            }
        }
    "#;

    // Vulnerable (Form B): the rate getter result is bound to a local
    // (`uint256 syIndex = SY.exchangeRate();`) and THEN monotonic-clamped
    // (`PMath.max(syIndex, pyIndexStored)`) and returned — the
    // `PendlePYOracleLib.getSYandPYIndexCurrent` / `pyIndexCurrentViewYt` shape.
    const VULN_LOCAL: &str = r#"
        interface IStandardizedYield { function exchangeRate() external view returns (uint256); }
        interface IPYieldToken {
            function pyIndexStored() external view returns (uint256);
            function doCacheIndexSameBlock() external view returns (bool);
            function pyIndexLastUpdatedBlock() external view returns (uint256);
        }
        library PMath { function max(uint256 x, uint256 y) internal pure returns (uint256) { return x > y ? x : y; } }
        contract PendlePYOracleLib {
            function getSYandPYIndexCurrent(IStandardizedYield SY, IPYieldToken YT) internal view returns (uint256 pyIndex) {
                uint256 syIndex = SY.exchangeRate();
                uint256 pyIndexStored = YT.pyIndexStored();
                if (YT.doCacheIndexSameBlock() && YT.pyIndexLastUpdatedBlock() == block.number) {
                    pyIndex = pyIndexStored;
                } else {
                    pyIndex = PMath.max(syIndex, pyIndexStored);
                }
            }
        }
    "#;

    // Safe: the SAME monotonic clamp, but the function ALSO enforces a per-update
    // jump bound — `require(newRate <= prevRate * MAX_FACTOR / ONE)` — so an
    // inflated external rate is rejected. The Mul on the comparison's RHS is the
    // magnitude bound the detector looks for.
    const SAFE_JUMP_BOUND: &str = r#"
        interface IStandardizedYield { function exchangeRate() external returns (uint256); }
        library PMath { function max(uint256 x, uint256 y) internal pure returns (uint256) { return x > y ? x : y; } }
        contract BoundedYieldToken {
            using PMath for uint256;
            address public immutable SY;
            uint256 internal _stored;
            uint256 internal constant ONE = 1e18;
            uint256 internal constant MAX_FACTOR = 2e18;
            function indexCurrent() public returns (uint256 currentIndex) {
                uint256 newRate = IStandardizedYield(SY).exchangeRate();
                require(newRate <= _stored * MAX_FACTOR / ONE, "rate jump too large");
                currentIndex = PMath.max(newRate, _stored);
                _stored = currentIndex;
            }
        }
    "#;

    // Safe: the rate is clamped from ABOVE with a `min(rate, cap)` upper clamp —
    // an explicit magnitude ceiling — so the upside jump is bounded. No finding.
    const SAFE_MIN_CLAMP: &str = r#"
        interface IStandardizedYield { function exchangeRate() external returns (uint256); }
        library PMath {
            function max(uint256 x, uint256 y) internal pure returns (uint256) { return x > y ? x : y; }
            function min(uint256 x, uint256 y) internal pure returns (uint256) { return x < y ? x : y; }
        }
        contract CappedYieldToken {
            using PMath for uint256;
            address public immutable SY;
            uint256 internal _stored;
            uint256 internal rateCeiling;
            function indexCurrent() public returns (uint256 currentIndex) {
                uint256 newRate = PMath.min(IStandardizedYield(SY).exchangeRate(), rateCeiling);
                currentIndex = PMath.max(newRate, _stored);
                _stored = currentIndex;
            }
        }
    "#;

    // Negative control: a share-rate getter is read and used, but there is NO
    // monotonic `max(new, prev)` clamp — it is a plain `amount * exchangeRate /
    // 1e18` conversion quote (the etherfi `Liquifier` shape). The detector's
    // `max`-clamp anchor must keep this silent (it is not the monotonic-only
    // class; rounding/quote maths is another detector's concern).
    const SAFE_NO_MAX: &str = r#"
        interface ICbEth { function exchangeRate() external view returns (uint256); }
        contract Liquifier {
            ICbEth public cbEth;
            function quoteByFairValue(uint256 _amount) internal view returns (uint256) {
                return _amount * cbEth.exchangeRate() / 1e18;
            }
        }
    "#;

    // Negative control: `getRate()` passthrough with neither a clamp nor a state
    // write that is just forwarded (the renzo `L2RateProvider.getRate` shape).
    // No monotonic clamp -> silent.
    const SAFE_PASSTHROUGH: &str = r#"
        interface IRenzoDeposit { function getRate() external view returns (uint256); }
        contract L2RateProvider {
            IRenzoDeposit public newRenzoDeposit;
            function getRate() external view returns (uint256) {
                return newRenzoDeposit.getRate();
            }
        }
    "#;

    #[test]
    fn fires_on_pendle_direct_shape() {
        assert!(fired(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_local_bound_shape() {
        assert!(fired(VULN_LOCAL), "{:#?}", run(VULN_LOCAL));
    }

    #[test]
    fn silent_when_jump_bounded() {
        assert!(!fired(SAFE_JUMP_BOUND));
    }

    #[test]
    fn silent_when_min_clamped() {
        assert!(!fired(SAFE_MIN_CLAMP));
    }

    #[test]
    fn silent_without_monotonic_clamp() {
        assert!(!fired(SAFE_NO_MAX));
    }

    #[test]
    fn silent_on_passthrough_getter() {
        assert!(!fired(SAFE_PASSTHROUGH));
    }
}
