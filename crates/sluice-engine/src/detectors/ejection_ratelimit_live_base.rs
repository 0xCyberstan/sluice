//! Ejection / rate-limit budget computed from a **live** base — an automated
//! operator-ejection allowance (or any rate-limit budget) sized as a *percentage
//! of a live aggregate read at use time* (`budget = ratelimitBps * totalStake() /
//! BPS`) rather than a fixed/window-captured base, so a manipulated or shrunk live
//! base silently changes the budget.
//!
//! ## The shape
//!
//! A rate-limited ejection path asks "how much stake may I eject right now?" and
//! answers with a *fraction of the current total*:
//!
//! ```solidity
//! // EigenLayer middleware — EjectionManager.amountEjectableForQuorum
//! uint256 totalEjectable = uint256(quorumEjectionParams[quorumNumber].ejectableStakePercent)
//!     * uint256(stakeRegistry.getCurrentTotalStake(quorumNumber)) / uint256(BIPS_DENOMINATOR);
//! //  ^stored bps fraction                ^LIVE total-stake read at call time      ^BPS denom
//! ```
//!
//! `getCurrentTotalStake` returns the *latest* entry of the total-stake history —
//! a **live** read of the current aggregate, not the total captured at the start
//! of the rate-limit window. The budget is then consumed by the ejection loop
//! (`amountEjectable` gates `stakeForEjection + operatorStake > amountEjectable`).
//! Because the base is read live, the very ejections (or slashings /
//! deregistrations) that happen *inside* the window shrink `getCurrentTotalStake`,
//! which shrinks the remaining budget below the percentage that was supposed to
//! apply to the window's starting total; symmetrically, stake added during the
//! window inflates the budget. The realized allowance is `bps *
//! total_at_use_time / BPS`, not `bps * total_at_window_start / BPS` — the
//! rate-limit no longer caps the intended fraction of the population it was meant
//! to protect.
//!
//! ## Precision anchors (all required)
//!
//!   * **ejection / rate-limit budget context** — the enclosing function name OR
//!     the name of the variable the percentage product is assigned to reads as an
//!     *ejectable / ejection / ratelimit / budget / allowance / quota* quantity.
//!     This scopes the finding to the automated-ejection / rate-limit allowance and
//!     keeps it off ordinary `kickThreshold` / fee / reward percentage math (a
//!     plain `stake * kickBips / BIPS` churn threshold is a per-operator eligibility
//!     bound, not a *budget* sized off a live aggregate).
//!   * **percentage × live-aggregate / denominator** — a `bps * base / DENOM`
//!     (inline `Mul` under `Div`, casts peeled on each operand) where `base`
//!     **contains a live aggregate *call*** — `getCurrentTotalStake` / `totalStake`
//!     / `activeStake` / `totalSupply` / `totalAssets` / `getCurrentStake` … — that
//!     is NOT a historical/snapshot accessor, `bps` is a stored/parameter value
//!     (not itself a live read, not a literal), and `DENOM` reads as a
//!     `BIPS`/`BPS`/`DENOMINATOR`/`MAX`/`WAD`/`PRECISION` constant (or a numeric
//!     literal).
//!
//! ## Suppression (the base is captured / fixed)
//!
//!   * **historical `*At(ts)` / `getPast…` / snapshot / checkpoint accessor**: the
//!     base is the aggregate *at a captured block/timestamp* (e.g.
//!     `getTotalStakeAtBlockNumber(q, windowStart)`, `getPastTotalSupply(...)`), so
//!     it is window-captured, not live — suppressed.
//!   * **no live aggregate call in the base**: a fixed/configured capacity, a stored
//!     struct field, or a plain parameter (the churn `_totalKickThreshold(totalStake,
//!     …)` case, where `totalStake` is a *captured parameter*, not a live read) — the
//!     budget is not sized off a live aggregate, so nothing fires.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function, Lit, Span, StmtKind};

use super::prelude::*;

pub struct EjectionRatelimitLiveBaseDetector;

impl Detector for EjectionRatelimitLiveBaseDetector {
    fn id(&self) -> &'static str {
        "ejection-ratelimit-live-base"
    }
    fn category(&self) -> Category {
        Category::EjectionRatelimitLiveBase
    }
    fn description(&self) -> &'static str {
        "An automated-ejection / rate-limit budget is computed as a percentage of a LIVE aggregate \
         read at use time (`bps * totalStake() / BPS`) rather than a window-captured base, so a \
         manipulated/shrunk live base changes the allowance (EigenLayer EjectionManager \
         amountEjectableForQuorum class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.functions() {
            // The budget computation is commonly a `view` helper
            // (`amountEjectableForQuorum`), so — unlike the slash-finalize class —
            // view/pure functions are IN scope. We only need a real body.
            if !f.has_body {
                continue;
            }
            // Bare interface declarations host no computation.
            let Some(contract) = cx.contract_of(f.id) else { continue };
            if contract.is_interface() {
                continue;
            }

            // The function name itself may already read as an ejection/ratelimit
            // budget context (`amountEjectableForQuorum`); if so, the assignment's
            // LHS name is not additionally required.
            let fname_is_budget = name_is_ejection_budget(&f.name);

            let Some(hit) = find_pct_live_base(f, fname_is_budget) else { continue };

            let b = report!(self, Category::EjectionRatelimitLiveBase,
                title = "Ejection/rate-limit budget is a percentage of a live aggregate read at use time",
                // Two tight structural anchors (an ejection/ratelimit *budget* name
                // gate, plus a `bps × live-aggregate-call / DENOM` computation with the
                // captured/snapshot suppression) — a clean, specific match. Single
                // Invariant dimension, Medium label: 50 × (0.5 + 0.5·0.66) = 41.5.
                severity = Severity::Medium,
                confidence = 0.66,
                dimensions = [Dimension::Invariant],
                message = format!(
                    "`{fname}` sizes a {budget} as a **stored percentage** times a **live** aggregate \
                     read at use time (`{base}`), divided by a basis-point/precision denominator \
                     (`bps * {base} / DENOM`). The fraction is a configured rate-limit parameter, but the \
                     base is read *live* when the budget is computed — it is the current aggregate, not the \
                     total captured at the start of the rate-limit window. So the realized allowance is \
                     `bps * {base}_at_use_time / DENOM`, not `bps * total_at_window_start / DENOM`: the very \
                     ejections / slashings / deregistrations that occur during the window shrink `{base}` and \
                     thus shrink the remaining budget below the intended fraction, while stake added during \
                     the window inflates it. A manipulated or naturally-moving live base therefore changes \
                     the rate-limit budget out from under the parameter that was meant to cap a fixed \
                     fraction of the population. This is the EigenLayer middleware \
                     `EjectionManager.amountEjectableForQuorum` percentage-of-live-base shape \
                     (`ejectableStakePercent * stakeRegistry.getCurrentTotalStake(q) / BIPS_DENOMINATOR`).",
                    fname = f.name,
                    budget = hit.budget_word,
                    base = hit.live_name,
                ),
                recommendation =
                    "Size the rate-limit budget off a base **captured at the start of the window** rather \
                     than a live read at use time: snapshot the total aggregate when the window opens (or \
                     read a historical/checkpointed accessor such as `getTotalStakeAtBlockNumber(q, \
                     windowStart)` / `getPastTotalSupply(windowStart)`), so the allowance equals `bps * \
                     total_at_window_start / DENOM` and cannot be steered by ejections, slashings, \
                     deregistrations, or deposits that happen during the window.",
            );
            out.push(finish_at(cx, b, f.id, hit.span));
        }

        out
    }
}

// --------------------------------------------------------------------- analysis

/// A matched percentage-of-live-base budget computation.
struct LiveBudgetHit {
    /// Name of the live aggregate accessor feeding the base (`getcurrenttotalstake`).
    live_name: String,
    /// The matched budget word (for the message): the LHS var name or a generic label.
    budget_word: String,
    /// Span of the `pct * base / DENOM` division site.
    span: Span,
}

/// Scan `f`'s body for a `bps * <live aggregate call> / DENOM` budget computation.
/// `fname_is_budget` short-circuits the budget-context gate (the function name
/// already reads as an ejection/ratelimit budget); otherwise the LHS variable name
/// of the *same* assignment/declaration must supply that context.
///
/// We walk one statement node at a time and inspect only that statement's
/// **directly-owned** RHS expression for the division, so the division is paired
/// with *its own* statement's LHS name (not an enclosing statement's).
fn find_pct_live_base(f: &Function, fname_is_budget: bool) -> Option<LiveBudgetHit> {
    let mut hit: Option<LiveBudgetHit> = None;
    for top in &f.body {
        top.visit(&mut |st| {
            if hit.is_some() {
                return;
            }
            // The RHS expression this statement owns directly, plus its LHS context
            // name (for an assignment / declaration `uint256 totalEjectable = …`).
            let Some((rhs, lhs_name)) = stmt_rhs_and_lhs(st) else { return };
            // Search the owned RHS (and its sub-expressions) for the division shape.
            rhs.visit(&mut |e| {
                if hit.is_some() {
                    return;
                }
                if let Some((live_name, span)) = pct_live_base_div(e) {
                    // Budget-context gate: function name OR the LHS var name must read
                    // as an ejection / ratelimit / budget / allowance / quota quantity.
                    let budget_word = if fname_is_budget {
                        Some(budget_label(&f.name))
                    } else {
                        lhs_name.as_deref().filter(|n| name_is_ejection_budget(n)).map(budget_label)
                    };
                    if let Some(budget_word) = budget_word {
                        hit = Some(LiveBudgetHit { live_name, budget_word, span });
                    }
                }
            });
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// If `e` is an inline `pct * base / DENOM` (a `Div` whose lhs is a `Mul`), where
/// one `Mul` factor is a *live aggregate call* base, the other is a stored/param
/// percentage (not a live read, not a literal), and the divisor reads as a
/// bps/precision denominator — return the live accessor name + the division span.
fn pct_live_base_div(e: &Expr) -> Option<(String, Span)> {
    let ExprKind::Binary { op: BinOp::Div, lhs, rhs } = &e.kind else { return None };
    if !looks_like_denominator(peel_casts(rhs)) {
        return None;
    }
    let ExprKind::Binary { op: BinOp::Mul, lhs: a, rhs: b } = &peel_casts(lhs).kind else {
        return None;
    };
    // Either factor may be the live base and the other the percentage.
    for (pct, base) in [(a.as_ref(), b.as_ref()), (b.as_ref(), a.as_ref())] {
        let pct = peel_casts(pct);
        let base = peel_casts(base);
        if !is_percent_factor(pct) || is_live_aggregate_read(pct) {
            continue;
        }
        if let Some(live) = live_read_name(base) {
            return Some((live, e.span));
        }
    }
    None
}

/// The RHS expression a statement owns directly, together with its LHS context
/// name (for the budget-context gate):
///   * `uint256 totalEjectable = <init>;` -> `(<init>, Some("totalEjectable"))`
///   * `budget = <value>;`                 -> `(<value>, Some("budget"))`
///   * `return <e>;`                       -> `(<e>, None)` (function-name gate only)
/// Other statement kinds own no budget RHS.
fn stmt_rhs_and_lhs(st: &sluice_ir::Stmt) -> Option<(&Expr, Option<String>)> {
    match &st.kind {
        StmtKind::VarDecl { name, init: Some(e), .. } => Some((e, name.clone())),
        StmtKind::Return(Some(e)) => Some((e, None)),
        StmtKind::Expr(e) => {
            if let ExprKind::Assign { target, value, .. } = &e.kind {
                Some((value, root_ident(target)))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Does `name` read as an automated-ejection / rate-limit **budget / allowance /
/// quota** quantity? Deliberately narrow: the ejection or rate-limit domain plus a
/// budget/allowance sense (or the EigenLayer-specific `ejectable…` form). This is
/// what separates a live-base *budget* from a generic `kickThreshold` / fee /
/// reward percentage.
fn name_is_ejection_budget(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // EigenLayer's `ejectable…` / `amountEjectable…` / `…StakePercent`-budget forms.
    if l.contains("ejectable") || (l.contains("eject") && l.contains("amount")) {
        return true;
    }
    // The ejection or rate-limit domain combined with a budget/allowance/quota sense.
    let domain = l.contains("eject") || l.contains("ratelimit");
    let allowance = l.contains("budget")
        || l.contains("allowance")
        || l.contains("allowed")
        || l.contains("quota")
        || l.contains("capacity")
        || l.contains("limit");
    domain && allowance
}

/// A short human label for the budget, derived from the matched name.
fn budget_label(name: &str) -> String {
    let l = name.to_ascii_lowercase();
    if l.contains("eject") {
        "rate-limited ejection budget".to_string()
    } else {
        "rate-limit budget".to_string()
    }
}

/// Names of **live** aggregate accessors — read fresh from current state. A call
/// to one of these (and not a historical/snapshot accessor) is the live base.
const LIVE_AGGREGATE_NAMES: &[&str] = &[
    "getcurrenttotalstake",
    "getcurrentstake",
    "totalstake",
    "totalstakes",
    "activestake",
    "totalactivestake",
    "totalsupply",
    "totalassets",
    "totalshares",
    "totaldeposits",
    "totalpooledether",
    "gettotalpooledether",
    "getreserves",
    "totalliquidity",
];

/// Is `name` a **historical / snapshot / checkpoint** accessor — the
/// captured-at-a-point form whose presence SUPPRESSES the finding (the base is a
/// window-captured value, not live)? `…AtBlockNumber` / `…At(ts)` / `getPast…` /
/// `snapshot` / `checkpoint`.
fn is_historical_accessor(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.ends_with("at")
        || l.contains("atblock")
        || l.contains("atblocknumber")
        || l.contains("attimestamp")
        || l.contains("atindex")
        || l.starts_with("getpast")
        || l.contains("snapshot")
        || l.contains("checkpoint")
        || l.contains("past")
}

/// If `e` contains a *live* aggregate read (a call to a [`LIVE_AGGREGATE_NAMES`]
/// accessor that is NOT a historical/snapshot accessor), return that accessor's
/// (lowercased) name. `None` for a plain stored value (no call) or a historical
/// accessor.
fn live_read_name(e: &Expr) -> Option<String> {
    let mut found: Option<String> = None;
    e.visit(&mut |sub| {
        if found.is_some() {
            return;
        }
        let ExprKind::Call(c) = &sub.kind else { return };
        // A type cast is not an aggregate read; the visitor descends into its arg.
        if matches!(c.kind, sluice_ir::CallKind::TypeCast) {
            return;
        }
        let Some(name) = c.func_name.as_deref() else { return };
        let l = name.to_ascii_lowercase();
        if is_historical_accessor(&l) {
            return; // snapshot / window-captured accessor — not live
        }
        if LIVE_AGGREGATE_NAMES.iter().any(|n| l == *n) {
            found = Some(l);
        }
    });
    found
}

/// Does `e` (any sub-expr) contain a live aggregate *call* at all? Used to ensure
/// the *percentage* operand is not itself a live read.
fn is_live_aggregate_read(e: &Expr) -> bool {
    live_read_name(e).is_some()
}

/// Is `e` shaped like a stored *percentage* factor — a parameter / variable /
/// struct-field / indexed value (not a literal, not a live call)? The real
/// `ejectableStakePercent` is a `quorumEjectionParams[q].ejectableStakePercent`
/// struct-field read, so member/index leaves are accepted.
fn is_percent_factor(e: &Expr) -> bool {
    matches!(
        &e.kind,
        ExprKind::Ident(_) | ExprKind::Member { .. } | ExprKind::Index { .. }
    )
}

/// Does `e` look like a fixed bps / precision **denominator** — a
/// `BIPS`/`BPS`/`DENOMINATOR`/`MAX`/`WAD`/`PRECISION`/`PERCENT`/`SCALE` named
/// constant, or a numeric / hex literal (`10000`, `1e18`)?
fn looks_like_denominator(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(Lit::Number(_)) | ExprKind::Lit(Lit::HexNumber(_)) => true,
        ExprKind::Ident(n) => is_denominator_name(n),
        ExprKind::Member { member, .. } => is_denominator_name(member),
        ExprKind::Index { base, .. } => matches!(&base.kind, ExprKind::Ident(n) if is_denominator_name(n)),
        _ => false,
    }
}

fn is_denominator_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("bips")
        || l.contains("bps")
        || l.contains("denominator")
        || l.contains("denom")
        || l.contains("max")
        || l.contains("wad")
        || l.contains("ray")
        || l.contains("precision")
        || l.contains("percent")
        || l.contains("basis")
        || l.contains("scale")
        || l.contains("one")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::AnalysisContext;
    use crate::detector::Detector;
    use crate::Config;

    // Run ONLY this detector against `src`, building the analysis context directly so
    // the unit tests are independent of sibling detectors / the shared registry.
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        let parsed = sluice_parse::parse_sources(vec![("t.sol".into(), src.into())]);
        let scir = parsed.scir;
        let dataflow = sluice_dataflow::DataflowFacts::analyze(&scir);
        let invariants = sluice_invariant::InvariantFacts::mine(&scir);
        let frontier = sluice_frontier::FrontierFacts::analyze(&scir);
        let cfg = Config::default();
        let cx = AnalysisContext::new(&scir, &dataflow, &invariants, &frontier, &cfg);
        EjectionRatelimitLiveBaseDetector.run(&cx)
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "ejection-ratelimit-live-base")
    }

    // VULN — the exact EigenLayer `EjectionManager.amountEjectableForQuorum` shape:
    // `ejectableStakePercent * stakeRegistry.getCurrentTotalStake(q) / BIPS_DENOMINATOR`.
    // The live total-stake read at use time sizes the rate-limited ejection budget.
    const VULN_EIGEN: &str = r#"
        pragma solidity ^0.8.0;
        interface IStakeRegistry { function getCurrentTotalStake(uint8 q) external view returns (uint96); }
        contract EjectionManager {
            uint16 internal constant BIPS_DENOMINATOR = 10000;
            struct QuorumEjectionParams { uint32 rateLimitWindow; uint16 ejectableStakePercent; }
            mapping(uint8 => QuorumEjectionParams) public quorumEjectionParams;
            IStakeRegistry public stakeRegistry;
            function amountEjectableForQuorum(uint8 quorumNumber) public view returns (uint256) {
                uint256 totalEjectable = uint256(quorumEjectionParams[quorumNumber].ejectableStakePercent)
                    * uint256(stakeRegistry.getCurrentTotalStake(quorumNumber)) / uint256(BIPS_DENOMINATOR);
                return totalEjectable;
            }
        }
    "#;

    // VULN — same class, named via the assignment LHS (`ejectionBudget`) rather than
    // the function name, with a bare `totalStake()` live read and a numeric denom.
    const VULN_LHS_NAME: &str = r#"
        pragma solidity ^0.8.0;
        interface IReg { function totalStake() external view returns (uint256); }
        contract Ejector {
            uint256 public ratelimitBps;
            IReg public reg;
            function computeAllowance() public view returns (uint256) {
                uint256 ejectionBudget = ratelimitBps * reg.totalStake() / 10000;
                return ejectionBudget;
            }
        }
    "#;

    // SAFE — the base is a CAPTURED `*AtBlockNumber` snapshot taken at the window
    // start, not a live read. The budget tracks the window-start total, so the
    // rate-limit caps the intended fraction. Must stay silent.
    const SAFE_SNAPSHOT_AT: &str = r#"
        pragma solidity ^0.8.0;
        interface IStakeRegistry { function getTotalStakeAtBlockNumber(uint8 q, uint32 b) external view returns (uint96); }
        contract EjectionManager {
            uint16 internal constant BIPS_DENOMINATOR = 10000;
            struct QuorumEjectionParams { uint32 windowStartBlock; uint16 ejectableStakePercent; }
            mapping(uint8 => QuorumEjectionParams) public quorumEjectionParams;
            IStakeRegistry public stakeRegistry;
            function amountEjectableForQuorum(uint8 quorumNumber) public view returns (uint256) {
                uint256 totalEjectable = uint256(quorumEjectionParams[quorumNumber].ejectableStakePercent)
                    * uint256(stakeRegistry.getTotalStakeAtBlockNumber(quorumNumber, quorumEjectionParams[quorumNumber].windowStartBlock))
                    / uint256(BIPS_DENOMINATOR);
                return totalEjectable;
            }
        }
    "#;

    // SAFE — a generic churn `_totalKickThreshold(totalStake, …)`: `totalStake` is a
    // CAPTURED parameter (no live call), and the name reads as a kick *threshold*, not
    // an ejection *budget*. Both gates fail; must stay silent. (This is the real
    // SlashingRegistryCoordinator helper that must NOT fire.)
    const SAFE_KICK_THRESHOLD: &str = r#"
        pragma solidity ^0.8.0;
        contract SlashingRegistryCoordinator {
            uint256 internal constant BIPS_DENOMINATOR = 10000;
            struct OperatorSetParam { uint16 kickBIPsOfOperatorStake; uint16 kickBIPsOfTotalStake; }
            function _totalKickThreshold(uint96 totalStake, OperatorSetParam memory setParams)
                internal pure returns (uint96)
            {
                return totalStake * setParams.kickBIPsOfTotalStake / BIPS_DENOMINATOR;
            }
        }
    "#;

    // SAFE — a rate limiter sized by a FIXED, configured capacity (a stored value),
    // not `pct * live_aggregate / DENOM`. The EtherFi-style bucket limiter shape. No
    // live aggregate call in the base; must stay silent.
    const SAFE_FIXED_CAPACITY: &str = r#"
        pragma solidity ^0.8.0;
        contract RateLimiter {
            struct Limit { uint64 capacity; uint64 remaining; }
            mapping(bytes32 => Limit) public limits;
            uint256 constant BPS = 10000;
            uint256 public utilizationBps;
            function ejectionAllowance(bytes32 id) public view returns (uint256) {
                // budget is a fraction of a FIXED configured capacity, not a live aggregate
                uint256 budget = utilizationBps * limits[id].capacity / BPS;
                return budget;
            }
        }
    "#;

    // SAFE — an ordinary fee: `amount * feeBps / BIPS` where `amount` is a parameter,
    // not a live aggregate, and the name is a fee, not an ejection/ratelimit budget.
    const SAFE_FEE: &str = r#"
        pragma solidity ^0.8.0;
        contract Fees {
            uint256 constant BIPS = 10000;
            uint256 public feeBps;
            function feeOn(uint256 amount) public view returns (uint256) {
                uint256 fee = amount * feeBps / BIPS;
                return fee;
            }
        }
    "#;

    #[test]
    fn fires_on_eigenlayer_ejection_manager() {
        assert!(fires(VULN_EIGEN), "{:#?}", run(VULN_EIGEN));
    }

    #[test]
    fn fires_on_lhs_named_ejection_budget() {
        assert!(fires(VULN_LHS_NAME), "{:#?}", run(VULN_LHS_NAME));
    }

    #[test]
    fn silent_on_captured_snapshot_base() {
        assert!(!fires(SAFE_SNAPSHOT_AT), "{:#?}", run(SAFE_SNAPSHOT_AT));
    }

    #[test]
    fn silent_on_kick_threshold_captured_param() {
        assert!(!fires(SAFE_KICK_THRESHOLD), "{:#?}", run(SAFE_KICK_THRESHOLD));
    }

    #[test]
    fn silent_on_fixed_capacity_rate_limiter() {
        assert!(!fires(SAFE_FIXED_CAPACITY), "{:#?}", run(SAFE_FIXED_CAPACITY));
    }

    #[test]
    fn silent_on_ordinary_fee() {
        assert!(!fires(SAFE_FEE), "{:#?}", run(SAFE_FEE));
    }
}
