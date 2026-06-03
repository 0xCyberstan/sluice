//! Bad-debt socialization — on insolvency/liquidation, the loss is written off
//! against a **shared** pool total / index / exchange-rate (so *every* depositor
//! silently eats it), instead of being absorbed by an isolated
//! insurance/reserve bucket.
//!
//! ## The class
//!
//! A lending market tracks one global aggregate that prices every participant's
//! claim — `totalDebt` / `totalBorrows` / `totalAssets`, or a per-share index /
//! interest accumulator / exchange rate. A *borrower's* position is tracked
//! separately (a per-account mapping). When a position goes underwater the
//! seized collateral is worth **less** than the debt it backs (the insolvent
//! remainder is "bad debt"). There are two sound ways to handle that remainder:
//!
//!   1. draw it from an isolated **insurance / reserve / backstop** bucket
//!      earmarked for exactly this (a Aave `bridge`/reserve, a Compound reserve,
//!      a safety module), or
//!   2. leave it on the books as a recognised, isolated deficit.
//!
//! The hazardous shape is the third one: the liquidation **clears the borrower's
//! whole position** (deletes / zeroes their per-account debt) *and* **decrements
//! the global shared total / index by the borrower's full debt** — including the
//! insolvent remainder that was never recovered. Because that global figure is
//! what the protocol uses to price *everyone else's* claim (share price = assets
//! / total, debt index = total · accumulator), reducing it by an unrecovered
//! amount silently dilutes every other depositor: the loss is *socialized*. The
//! mirror failure is the same write *omitted* — the position is cleared but the
//! global total is never reduced, so the last redeemer is left holding a claim
//! the protocol can no longer back.
//!
//! ## Real instance — Olympus `MonoCooler.batchLiquidate`
//!
//! ```solidity
//! function batchLiquidate(address[] calldata accounts) external returns (...) {
//!     // for each account over the liquidation LTV:
//!     totalDebtWiped += status.currentDebt;     // the FULL debt
//!     delete allAccountState[account];          // clear the borrower position
//!     ...
//!     if (totalDebtWiped > 0) {
//!         _reduceTotalDebt(gState, totalDebtWiped);   // totalDebt -= full debt
//!         treasuryBorrower.writeOffDebt(totalDebtWiped);
//!     }
//! }
//! ```
//!
//! The liquidator only ever receives `status.currentIncentive` (capped to the
//! borrower's collateral); the seized collateral can be worth less than
//! `currentDebt`, yet `_reduceTotalDebt` removes the *whole* `currentDebt` from
//! the global `totalDebt`. `totalDebt` feeds the shared interest accumulator
//! (`updatedTotalDebt = prevTotalDebt · latestAccumulator / prevAccumulator`),
//! so wiping unrecovered debt against it writes the bad-debt loss into the index
//! that prices every remaining borrower — with no insurance/reserve bucket in
//! the path. `_reduceTotalDebt` is reached as an *internal call*, so the
//! detector follows resolved callees, not just the function's own writes.
//!
//! ## What the detector matches
//!
//! For an externally-reachable, state-mutating function that is a
//! liquidation / write-off / loss-socialization path (by name, or because it
//! deletes a per-account position under a liquidation/insolvency marker), it
//! fires when — across the function **and its resolved internal callees** — the
//! routine **reduces a global, scalar shared aggregate** (a `totalDebt` /
//! `totalBorrows` / `totalAssets` / index / accumulator / exchange-rate state
//! var, written by `-=` or a `g = … − x` reassignment) while clearing the
//! borrower's position.
//!
//! ## Precision (false-positive suppression)
//!
//!   * **Suppress when an isolated insurance/reserve bucket absorbs the loss** —
//!     if the path draws down or tops up a state var named like
//!     insurance / reserve / backstop / deficit / badDebt / safetyModule /
//!     coverage, or calls a `cover*` / `drawFromReserve` / `useReserves` routine,
//!     the loss is bucketed, not socialized.
//!   * **Only scalar global aggregates** count as the shared share-price input —
//!     a *per-key* reduction (`balances[user] -= x`, path contains `[`) is the
//!     borrower's own position, not the pool total.
//!   * **Liquidation/write-off gate** keeps ordinary `repay` / `redeem` /
//!     `withdraw` silent: those reduce `totalDebt` too, but they are not
//!     liquidations and do not clear a position under an insolvency trigger (the
//!     repaid value comes *in*).
//!   * Pure interfaces / body-less declarations are skipped.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{AssignOp, BinOp, Expr, ExprKind, Function, Span, StorageAccess, UnOp};

use super::prelude::*;

pub struct BadDebtSocializationDetector;

/// Function-name fragments that name a loss-realisation / write-off path. Their
/// presence marks the function as a place where insolvent debt is settled.
const WRITEOFF_NAME_MARKERS: &[&str] = &[
    "liquidate",
    "seize",
    "writeoff",
    "writedown",
    "writebaddebt",
    "socialize",
    "socialise",
    "absorbloss",
    "absorbdebt",
    "absorb",
    "coverloss",
    "coverdeficit",
    "handlebaddebt",
    "realizeloss",
    "realiseloss",
    "settlebaddebt",
];

/// Source markers evidencing a liquidation / insolvency trigger — used to
/// confirm that a position-clearing `delete`/zeroing happens *because the
/// position is underwater*, not as ordinary bookkeeping.
const LIQUIDATION_SOURCE_MARKERS: &[&str] = &[
    "liquidat",
    "incentive",
    "exceededliquidationltv",
    "liquidationltv",
    "shortfall",
    "underwater",
    "baddebt",
    "insolven",
    "seize",
    "writeoff",
];

/// State-variable name fragments for a **global, shared** aggregate that prices
/// every participant's claim: a pooled total, a per-share index, an interest
/// accumulator, or an exchange rate. Reducing one of these by an unrecovered
/// amount is what socializes a loss across all depositors.
const SHARED_AGGREGATE_MARKERS: &[&str] = &[
    "totaldebt",
    "totalborrow",
    "totalborrows",
    "totalliabilit",
    "totalassets",
    "totalprincipal",
    "totalowed",
    "totalsupplied",
    "exchangerate",
    "interestaccumulator",
    "rewardpershare",
    "accumulatorray",
    "indexray",
    "poolindex",
    "borrowindex",
    "liquidityindex",
    "pricepershare",
    "sharepershare",
    "persharestored",
];

/// State-variable / routine name fragments for an isolated loss-absorbing bucket.
/// If the path moves one of these, the bad debt is bucketed (sound) rather than
/// socialized — suppress.
const INSURANCE_BUCKET_MARKERS: &[&str] = &[
    "insurance",
    "reserve",
    "reserves",
    "backstop",
    "deficit",
    "baddebt",
    "safetymodule",
    "safetyfund",
    "coverage",
    "coverfund",
    "shortfallfund",
    "lossfund",
    "buffer",
];

/// Routine-name fragments for "draw the loss from the bucket" calls.
const INSURANCE_CALL_MARKERS: &[&str] = &[
    "coverloss",
    "coverdeficit",
    "coverbaddebt",
    "drawfromreserve",
    "drawreserve",
    "usereserves",
    "usereserve",
    "slashinsurance",
    "fromsafetymodule",
    "reimbursefromreserve",
];

impl Detector for BadDebtSocializationDetector {
    fn id(&self) -> &'static str {
        "bad-debt-socialization"
    }
    fn category(&self) -> Category {
        Category::BadDebtSocialization
    }
    fn description(&self) -> &'static str {
        "Insolvent debt written off against a shared pool total / index / exchange-rate (all depositors eat the loss) with no isolated insurance/reserve bucket"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.entry_points() {
            if cx.contract_of(f.id).map(|c| c.is_interface()).unwrap_or(false) {
                continue;
            }

            // Source of the whole function (comment-stripped, lowercased).
            let src = cx.source_text(f.span);

            // (A) Is this a liquidation / write-off / loss-socialization path?
            //     Either named like one, or it clears a per-account position
            //     under a liquidation/insolvency marker (the `batchLiquidate`
            //     shape: `delete allAccountState[account]`). This gate is what
            //     keeps ordinary `repay`/`redeem`/`withdraw` silent.
            let named_writeoff = name_is_writeoff(&f.name);
            let clears_position = clears_per_account_position(f);
            let has_liq_marker = LIQUIDATION_SOURCE_MARKERS.iter().any(|m| src.contains(m));
            let is_writeoff_path = named_writeoff || (clears_position && has_liq_marker);
            if !is_writeoff_path {
                continue;
            }

            // (B) Does the path reduce a GLOBAL, SCALAR shared aggregate — the
            //     figure that prices every participant's claim? Check the
            //     function's own writes *and* its resolved internal callees (the
            //     real reduction lives in `_reduceTotalDebt`, an internal call).
            let Some(agg) = reduces_shared_aggregate(cx, f) else { continue };

            // (C) Suppress when an isolated insurance/reserve bucket absorbs the
            //     loss instead of the shared pool — the sound shape.
            if absorbed_by_insurance_bucket(cx, f, &src) {
                continue;
            }

            // It must actually clear / zero the borrower's position somewhere on
            // this path (delete the per-account state, or zero a per-account
            // debt). For a name-only write-off that doesn't structurally clear a
            // position we still report, but require *some* position settlement so
            // a pure admin `writeOff(uint256)` of an aggregate alone (no per-user
            // clearing) doesn't trip — those are caught by the position-clear or
            // by the liquidation marker already gating (A).
            let position_settled = clears_position
                || zeroes_per_account_debt(f)
                || has_liq_marker; // a liquidation path settles a position by construction
            if !position_settled {
                continue;
            }

            let span = aggregate_reduction_span(cx, f, &agg).unwrap_or(f.span);

            let b = report!(self, Category::BadDebtSocialization,
                title = "Insolvent debt written off against a shared pool total/index (loss socialized to all depositors)",
                severity = Severity::High,
                confidence = 0.78,
                dimensions = [Dimension::Invariant, Dimension::ValueFlow],
                message = format!(
                    "`{fname}` clears a borrower's position on liquidation/write-off and reduces the \
                     global shared aggregate `{agg}` by the position's full debt — including any \
                     insolvent remainder the seized collateral did not cover — with no isolated \
                     insurance/reserve bucket in the path. `{agg}` is a pooled total / per-share index \
                     that prices *every* participant's claim (share price = assets / total, debt index = \
                     total · accumulator), so writing an unrecovered loss into it silently dilutes every \
                     other depositor: the bad debt is socialized rather than bucketed. (The mirror risk, \
                     if such a global reduction is ever skipped, is that the cleared debt is never \
                     removed from the total and the last redeemer is left holding the loss.) This is the \
                     bad-debt-socialization class — e.g. Olympus `MonoCooler.batchLiquidate` wiping the \
                     full `currentDebt` from `totalDebt` while the liquidator's payout is capped to the \
                     collateral.",
                    fname = f.name,
                    agg = agg,
                ),
                recommendation =
                    "Route the insolvent remainder (debt wiped beyond the value actually recovered) to a \
                     dedicated insurance/reserve/backstop bucket and draw it down explicitly, rather than \
                     decrementing the shared pool total / index directly. If no backstop exists, recognise \
                     the shortfall as an isolated, named deficit and socialize it only through an explicit, \
                     governed step — never as a silent side effect of clearing a liquidated position.",
            );
            out.push(finish_at(cx, b, f.id, span));
        }
        out
    }
}

// ------------------------------------------------------------------- helpers

/// The function name denotes a liquidation / write-off / loss-socialization path.
fn name_is_writeoff(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    WRITEOFF_NAME_MARKERS.iter().any(|m| l.contains(m))
}

/// True if `f` clears a per-account position: a `delete account[key]` on a
/// state-variable mapping (`delete allAccountState[account]`). This is the
/// structural "wipe the borrower" signal.
fn clears_per_account_position(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Unary { op: UnOp::Delete, operand } = &e.kind {
                // `delete x[k]` — an indexed (per-account) delete.
                if matches!(&operand.kind, ExprKind::Index { index: Some(_), .. }) {
                    found = true;
                }
            }
        });
        if found {
            break;
        }
    }
    found
}

/// True if `f` zeroes a per-account debt-like field: an assignment of `0` to an
/// indexed/member lvalue whose root or member names a debt/borrow quantity
/// (`aState.debtCheckpoint = 0`, `borrows[u] = 0`). A best-effort companion to
/// the `delete` signal for protocols that zero rather than delete.
fn zeroes_per_account_debt(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind {
                if is_int_lit(value, 0) && lvalue_is_per_account_debt(target) {
                    found = true;
                }
            }
        });
        if found {
            break;
        }
    }
    found
}

/// An lvalue that looks like a per-account debt field: it is an index/member
/// access (not a bare scalar) and some identifier/member in it names a
/// debt/borrow/loan quantity.
fn lvalue_is_per_account_debt(target: &Expr) -> bool {
    // Must be a member/index access (per-account), not a bare global scalar.
    if !matches!(&target.kind, ExprKind::Member { .. } | ExprKind::Index { .. }) {
        return false;
    }
    let mut hit = false;
    target.visit(&mut |sub| {
        if hit {
            return;
        }
        if let Some(name) = sub.simple_name() {
            let l = name.to_ascii_lowercase();
            if l.contains("debt") || l.contains("borrow") || l.contains("loan") || l.contains("owed")
            {
                hit = true;
            }
        }
    });
    hit
}

/// If the path (the function or any resolved internal callee) reduces a global,
/// scalar shared aggregate, return that aggregate's variable name. A "reduction"
/// is a `-=` write, or a reassignment `g = <expr containing a subtraction>` —
/// the `_reduceTotalDebt` shape `totalDebt = a > b ? 0 : b - a`.
fn reduces_shared_aggregate(cx: &AnalysisContext, f: &Function) -> Option<String> {
    if let Some(v) = reduces_shared_aggregate_in(f) {
        return Some(v);
    }
    // Follow resolved internal callees one level (the reducer is typically a
    // small private helper such as `_reduceTotalDebt`).
    for cid in &f.callees {
        if let Some(callee) = cx.scir.function(*cid) {
            if !callee.has_body {
                continue;
            }
            if let Some(v) = reduces_shared_aggregate_in(callee) {
                return Some(v);
            }
        }
    }
    None
}

/// As [`reduces_shared_aggregate`] but scoped to a single function body.
fn reduces_shared_aggregate_in(f: &Function) -> Option<String> {
    let mut hit: Option<String> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Assign { op, target, value } = &e.kind else { return };
            // Target must be a bare global scalar shared-aggregate (no `[` index:
            // a per-key mapping write is the borrower's own position, not the
            // pool total).
            let Some(name) = scalar_shared_aggregate_name(target) else { return };
            let reduces = match op {
                AssignOp::Sub => true,
                // Reassignment that subtracts (the `_reduceTotalDebt` ternary,
                // or `g = g - x`). Require a subtraction somewhere in the RHS.
                AssignOp::Assign => expr_contains_subtraction(value),
                _ => false,
            };
            if reduces {
                hit = Some(name);
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// If `target` is a **bare** (un-indexed) lvalue whose name (or the member of a
/// `gCache.totalDebt = …` style chained assignment's *root state var*) is a
/// shared-aggregate marker, return that name. We accept either a plain
/// `Ident("totalDebt")` or a `Member`/`Index`-free target; a target that indexes
/// into a mapping (`balances[u]`) is rejected.
fn scalar_shared_aggregate_name(target: &Expr) -> Option<String> {
    // Reject any indexed access anywhere in the lvalue (per-key write).
    let mut indexed = false;
    target.visit(&mut |sub| {
        if matches!(&sub.kind, ExprKind::Index { .. }) {
            indexed = true;
        }
    });
    if indexed {
        return None;
    }
    // The lvalue is a bare identifier or a member chain on a memory cache
    // (`gStateCache.totalDebt`). Take the *outermost* simple name and test it.
    let name = target.simple_name()?;
    let l = name.to_ascii_lowercase();
    if SHARED_AGGREGATE_MARKERS.iter().any(|m| l.contains(m)) {
        Some(name.to_string())
    } else {
        None
    }
}

/// Does `e` contain a subtraction `a - b` anywhere?
fn expr_contains_subtraction(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if matches!(&sub.kind, ExprKind::Binary { op: BinOp::Sub, .. }) {
            found = true;
        }
    });
    found
}

/// True if the loss is absorbed by an isolated insurance / reserve / backstop
/// bucket — a state var named like a bucket is read/written on the path, or a
/// `cover*` / `drawFromReserve` routine is invoked (own body, callees, or
/// source). Any of these means the bad debt is bucketed, not socialized.
fn absorbed_by_insurance_bucket(cx: &AnalysisContext, f: &Function, src: &str) -> bool {
    // Bucket-named state variable touched (read or written) by the function.
    let touches_bucket = |func: &Function| -> bool {
        func.effects
            .storage_writes
            .iter()
            .chain(func.effects.storage_reads.iter())
            .any(|a| {
                let l = a.var.to_ascii_lowercase();
                INSURANCE_BUCKET_MARKERS.iter().any(|m| l.contains(m))
            })
    };
    if touches_bucket(f) {
        return true;
    }
    // Bucket-draw routine called (resolved internal-call name / external call func).
    let calls_bucket_routine = f.effects.internal_calls.iter().any(|n| {
        let l = n.to_ascii_lowercase();
        INSURANCE_CALL_MARKERS.iter().any(|m| l.contains(m))
    }) || f.effects.call_sites.iter().any(|c| {
        c.func_name
            .as_deref()
            .map(|n| {
                let l = n.to_ascii_lowercase();
                INSURANCE_CALL_MARKERS.iter().any(|m| l.contains(m))
            })
            .unwrap_or(false)
    });
    if calls_bucket_routine {
        return true;
    }
    // Resolved callees that touch a bucket (the draw may be one helper deep).
    for cid in &f.callees {
        if let Some(callee) = cx.scir.function(*cid) {
            if callee.has_body && touches_bucket(callee) {
                return true;
            }
        }
    }
    // Textual fallback: a bucket marker in the function source (covers buckets
    // whose write the effect summary attributed elsewhere, e.g. inherited state).
    if INSURANCE_BUCKET_MARKERS.iter().any(|m| src.contains(m))
        || INSURANCE_CALL_MARKERS.iter().any(|m| src.contains(m))
    {
        return true;
    }
    false
}

/// Best-effort report location: the storage write to the shared aggregate, in
/// the function itself or a resolved callee, falling back to the function span.
fn aggregate_reduction_span(cx: &AnalysisContext, f: &Function, agg: &str) -> Option<Span> {
    let pick = |func: &Function| -> Option<Span> {
        func.effects
            .storage_writes
            .iter()
            .filter(|w: &&StorageAccess| w.var.eq_ignore_ascii_case(agg))
            .min_by_key(|w| w.order)
            .map(|w| w.span)
    };
    if let Some(s) = pick(f) {
        return Some(s);
    }
    for cid in &f.callees {
        if let Some(callee) = cx.scir.function(*cid) {
            if let Some(s) = pick(callee) {
                return Some(s);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // VULN (MonoCooler-shaped): `batchLiquidate` clears the borrower position
    // (`delete accountState[account]`) and reduces the GLOBAL `totalDebt` by the
    // full `currentDebt` via the `_reduceTotalDebt` internal call, while the
    // liquidator's payout is the (collateral-capped) incentive. The insolvent
    // remainder is written off against the shared total — socialized — with no
    // insurance/reserve bucket.
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        contract MonoCooler {
            struct AccountState { uint128 collateral; uint128 debtCheckpoint; }
            mapping(address => AccountState) private accountState;
            uint128 public totalCollateral;
            uint128 public totalDebt;

            function _reduceTotalDebt(uint128 amount) private {
                totalDebt = amount > totalDebt ? 0 : totalDebt - amount;
            }

            function batchLiquidate(address[] calldata accounts) external {
                uint128 totalDebtWiped;
                uint128 totalCollateralClaimed;
                for (uint256 i; i < accounts.length; ++i) {
                    address account = accounts[i];
                    AccountState memory s = accountState[account];
                    // assume over the liquidation LTV (incentive capped to collateral)
                    totalCollateralClaimed += s.collateral;
                    totalDebtWiped += s.debtCheckpoint;
                    delete accountState[account];
                }
                if (totalCollateralClaimed > 0) {
                    totalCollateral -= totalCollateralClaimed;
                }
                if (totalDebtWiped > 0) {
                    _reduceTotalDebt(totalDebtWiped);
                }
            }
        }
    "#;

    // SAFE: same liquidation, but the insolvent remainder (debt wiped beyond the
    // recovered collateral value) is drawn from an isolated `insuranceFund`
    // reserve bucket rather than socialized against the shared total.
    const SAFE_INSURANCE: &str = r#"
        pragma solidity ^0.8.20;
        contract MonoCoolerInsured {
            struct AccountState { uint128 collateral; uint128 debtCheckpoint; }
            mapping(address => AccountState) private accountState;
            uint128 public totalDebt;
            uint256 public insuranceFund;

            function _reduceTotalDebt(uint128 amount) private {
                totalDebt = amount > totalDebt ? 0 : totalDebt - amount;
            }

            function batchLiquidate(address[] calldata accounts, uint256 recovered) external {
                uint128 totalDebtWiped;
                for (uint256 i; i < accounts.length; ++i) {
                    address account = accounts[i];
                    AccountState memory s = accountState[account];
                    totalDebtWiped += s.debtCheckpoint;
                    delete accountState[account];
                }
                // The shortfall is absorbed by the insurance bucket, not the pool.
                if (totalDebtWiped > recovered) {
                    insuranceFund -= (totalDebtWiped - recovered);
                }
                if (totalDebtWiped > 0) {
                    _reduceTotalDebt(totalDebtWiped);
                }
            }
        }
    "#;

    // SAFE: a plain `repay` reduces `totalDebt` too, but it is not a liquidation
    // / write-off (no liquidation marker, no position clearing on insolvency) —
    // the repaid value comes in, so nothing is socialized. The liquidation/
    // write-off gate must keep this silent.
    const SAFE_REPAY: &str = r#"
        pragma solidity ^0.8.20;
        contract Market {
            mapping(address => uint256) public debtOf;
            uint256 public totalDebt;

            function _reduceTotalDebt(uint256 amount) private {
                totalDebt = amount > totalDebt ? 0 : totalDebt - amount;
            }

            function repay(uint256 amount) external {
                require(debtOf[msg.sender] >= amount, "too much");
                debtOf[msg.sender] -= amount;
                _reduceTotalDebt(amount);
                // pull `amount` of debt token from msg.sender ...
            }
        }
    "#;

    // SAFE: a liquidation that only seizes/transfers collateral and clears the
    // position, but never reduces any GLOBAL shared total / index (no pool
    // total touched). Without a shared-aggregate reduction there is no
    // socialization channel, so the detector stays silent.
    const SAFE_NO_SHARED_TOTAL: &str = r#"
        pragma solidity ^0.8.20;
        contract IsolatedVaults {
            struct Position { uint256 collateral; uint256 debt; }
            mapping(address => Position) public positions;

            function liquidate(address borrower) external {
                Position memory p = positions[borrower];
                require(p.debt > p.collateral, "healthy"); // underwater
                // seize collateral, clear position — no global total exists
                delete positions[borrower];
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(
            fs.iter().any(|f| f.detector == "bad-debt-socialization"
                && f.function == "batchLiquidate"),
            "{:#?}",
            fs
        );
    }

    #[test]
    fn silent_when_insurance_bucket_absorbs() {
        let fs = run(SAFE_INSURANCE);
        assert!(
            !fs.iter().any(|f| f.detector == "bad-debt-socialization"),
            "{:#?}",
            fs
        );
    }

    #[test]
    fn silent_on_plain_repay() {
        let fs = run(SAFE_REPAY);
        assert!(
            !fs.iter().any(|f| f.detector == "bad-debt-socialization"),
            "{:#?}",
            fs
        );
    }

    #[test]
    fn silent_without_shared_total() {
        let fs = run(SAFE_NO_SHARED_TOTAL);
        assert!(
            !fs.iter().any(|f| f.detector == "bad-debt-socialization"),
            "{:#?}",
            fs
        );
    }
}
