//! Emission / bond / mint payout **sized from an instantaneous price read**.
//!
//! ## The class
//!
//! A protocol that mints new tokens, emits an inflationary reward, or opens a
//! bond market routinely *sizes that payout from a price* — `emission =
//! supply * (price / backing)`, `bondInitialPrice = getLastPrice() * scale`, an
//! auction floor = `getCurrentPrice() * scalar`. When the price fed into that
//! sizing is an **instantaneous** read — the most-recent stored observation
//! (`getLastPrice()`), a live single-round feed (`getCurrentPrice()`), or a raw
//! pool spot (`getReserves`/`slot0`) — rather than a time-weighted / moving
//! average, an attacker who can nudge that spot for one block inflates the
//! payout. Unlike a manipulated *collateral valuation* (where the attacker
//! borrows against a fake-high mark), here the manipulated spot directly
//! enlarges how much the protocol *emits/mints/sells*, diluting holders or
//! handing the attacker an oversized bond/auction allocation.
//!
//! The motivating real instance is Olympus V3 `EmissionManager`:
//!   * `getPremium()` computes `premium = getLastPrice() / backing - 100%`, and
//!     `getNextEmission()` turns that premium straight into
//!     `emission = supply * emissionRate`. `getLastPrice()` returns a *single*
//!     stored observation (`observations[lastIndex]`), not the moving average.
//!   * `_createMarket()` sets the bond `formattedInitialPrice` to
//!     `PRICE.getLastPrice().mulDiv(bondScale, oracleScale)`.
//!   * `_getCurrentPrice()` sizes the auction floor off `PRICE.getCurrentPrice()`
//!     (a live Chainlink round, no smoothing).
//!
//! The same module exposes `getMovingAverage()` / `getTargetPrice()` — the
//! smoothed reads that *would* be safe here, and which this detector treats as a
//! suppressor.
//!
//! ## What fires
//! A function that (a) is in an emission / bond / mint / payout **sizing**
//! context (by name or by the sizing tokens it contains), (b) reads an
//! instantaneous spot price via a `getLastPrice` / `getCurrentPrice` /
//! `getSpotPrice` / `getReserves` / `slot0`-style call, and (c) folds that read
//! into a multiply/divide (`a * price`, `price / backing`, `price.mulDiv(..)`)
//! that scales the payout.
//!
//! ## What is suppressed (precision first — stays off the oracle detector's turf)
//!   * The sizing uses a **moving average / TWAP / target** read
//!     (`getMovingAverage`, `getTargetPrice`, `movingAverage`, `twap`,
//!     `observe`/`consult`) — the correct mitigation.
//!   * A **robust Chainlink feed** is consumed in the same function
//!     (`latestRoundData` + staleness), i.e. the value is not a raw spot.
//!   * The function is **not** a sizing context (generic collateral valuation,
//!     pricing a view, health-factor math) — that is the `oracle-manipulation`
//!     detector's class, not this one.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function, Span, StmtKind};
use std::collections::HashSet;

use super::prelude::*;

pub struct BackingSpotInflationDetector;

/// Instantaneous (un-smoothed) price reads. Method names whose semantics are a
/// *single* current/last observation or a raw pool spot — the manipulable input
/// when it sizes a payout. Compared case-insensitively as a whole `func_name`
/// (so `getLastPrice` matches but an averaged `getMovingAverage` does not).
const SPOT_READ_FUNCS: &[&str] = &[
    "getlastprice",
    "getcurrentprice",
    "getspotprice",
    "getprice",
    "latestprice",
    "spotprice",
    "getreserves",
    "slot0",
];

/// Tokens that mark a function as *sizing an emission / bond / mint / payout*
/// (as opposed to valuing collateral). Either the function name or its source
/// containing one of these admits it; the multiply/divide-by-spot check below is
/// what actually fires.
const SIZING_TOKENS: &[&str] = &[
    "emission",
    "emissionrate",
    "premium",
    "createmarket",
    "formattedinitialprice",
    "formattedminimumprice",
    "initialprice",
    "saleamount",
    "mintamount",
    "payout",
    "rewardamount",
    "bondmarket",
];

/// A smoothed / averaged / target price read in the same function means the
/// sizing is *not* off a raw spot — suppress. Substring match on the (stripped,
/// lowercased) source.
const SMOOTHED_MARKERS: &[&str] = &[
    "getmovingaverage",
    "movingaverage",
    "gettargetprice",
    "targetprice",
    "twap",
    "timeweighted",
    "time-weighted",
    "observe(",
    "consult(",
    "cumulative",
];

/// The `mulDiv` family — a multiply-then-divide that scales a payout. A spot read
/// appearing as the receiver or an argument of one of these is "folded into the
/// sizing math" just as much as a bare `*` / `/`.
const MULDIV_FUNCS: &[&str] = &["muldiv", "muldivup", "muldivdown", "mulwad", "mulwadup", "fullmuldiv"];

impl Detector for BackingSpotInflationDetector {
    fn id(&self) -> &'static str {
        "backing-spot-inflation"
    }
    fn category(&self) -> Category {
        Category::BackingSpotInflation
    }
    fn description(&self) -> &'static str {
        "Emission/bond/mint payout sized from an instantaneous spot price read (getLastPrice/getCurrentPrice) instead of a TWAP/moving-average"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Pure interface/abstract declarations carry no implementation risk.
            if cx.contract_of(f.id).map(|c| c.is_interface()).unwrap_or(false) {
                continue;
            }

            let src = cx.source_text(f.span);

            // --- (1) Is this a payout-SIZING context (not collateral valuation)? ---
            //
            // We require an emission/bond/mint/payout token by *name* or in the
            // body. This is the line that keeps us off `oracle-manipulation`'s
            // territory (which fires on valuation / collateral / borrow math).
            let name_l = f.name.to_ascii_lowercase();
            let sizing_context = SIZING_TOKENS.iter().any(|t| name_l.contains(t) || src.contains(t));
            if !sizing_context {
                continue;
            }

            // --- (2) Suppress when the price is smoothed / robust (precision) ---
            //
            // A moving-average / TWAP / target read in this function means the
            // sizing is done off an averaged price — the correct mitigation.
            if SMOOTHED_MARKERS.iter().any(|m| src.contains(m)) {
                continue;
            }
            // A robust Chainlink feed consumed *here* (with the staleness checks
            // `oracle-staleness` covers) is not a raw spot either.
            if cx.uses_robust_oracle(f) {
                continue;
            }

            // --- (3) Find an instantaneous spot read folded into multiply/divide ---
            //
            // The spot-read call must itself participate in a `*` / `/` (directly,
            // or as the receiver/arg of a `mulDiv`-family call). That is the
            // concrete "the spot SIZES the payout" evidence.
            let Some(anchor) = spot_read_in_scaling(f) else { continue };

            // The named read drives the message wording.
            let why = scaling_read_name(f).unwrap_or_else(|| "an instantaneous price".to_string());

            let b = report!(self, Category::BackingSpotInflation,
                title = "Emission/bond/mint payout sized from an instantaneous spot price (no TWAP)",
                severity = Severity::Medium,
                confidence = 0.62,
                dimensions = [Dimension::ValueFlow, Dimension::Frontier],
                message = format!(
                    "`{}` sizes an emission / bond / mint payout by multiplying or dividing by \
                     `{}` — an *instantaneous* price read (the most-recent stored observation or a \
                     single live feed round), not a moving average / TWAP. Because the payout scales \
                     with this spot, an attacker who nudges the underlying price for a single block \
                     (e.g. a flash-loan-assisted swap that moves the pool the feed/observation tracks) \
                     inflates the amount the protocol emits, mints, or offers in the bond/auction — \
                     diluting holders or capturing an oversized allocation. This is payout *sizing*, \
                     distinct from collateral valuation: the manipulated spot enlarges what is paid out \
                     rather than what can be borrowed.",
                    f.name, why
                ),
                recommendation = "Size emissions / bond capacity / mint amounts from a manipulation-resistant \
                     price: a moving average / TWAP over a meaningful window (e.g. the module's \
                     `getMovingAverage()` / `getTargetPrice()` rather than `getLastPrice()` / \
                     `getCurrentPrice()`), or a Chainlink feed with staleness + deviation bounds. Never \
                     let a single instantaneous observation or raw pool spot scale a payout.",
            );
            out.push(finish_at(cx, b, f.id, anchor));
        }
        out
    }
}

// ------------------------------------------------------------------- helpers

/// Is `c` a call to an instantaneous spot-price read (by resolved method name)?
fn is_spot_read_call(c: &sluice_ir::Call) -> bool {
    c.func_name
        .as_deref()
        .map(|n| {
            let l = n.to_ascii_lowercase();
            SPOT_READ_FUNCS.contains(&l.as_str())
        })
        .unwrap_or(false)
}

/// Is `c` a `mulDiv`-family scaling call (by resolved method name)?
fn is_muldiv_call(c: &sluice_ir::Call) -> bool {
    c.func_name
        .as_deref()
        .map(|n| MULDIV_FUNCS.contains(&n.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// Does `e` (transitively) contain an instantaneous spot-read call?
fn contains_spot_read(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if let ExprKind::Call(c) = &sub.kind {
            if is_spot_read_call(c) {
                found = true;
            }
        }
    });
    found
}

/// Does `e` "reach a spot price" — either it contains a spot-read call directly,
/// or it mentions a local identifier that was bound from a spot read (`tainted`)?
/// This is what lets us see the idiomatic two-statement shape
/// `uint256 price = getLastPrice(); ... price * scale / backing`.
fn reaches_spot(e: &Expr, tainted: &HashSet<String>) -> bool {
    if contains_spot_read(e) {
        return true;
    }
    let mut found = false;
    e.visit(&mut |sub| {
        if let ExprKind::Ident(n) = &sub.kind {
            if tainted.contains(n) {
                found = true;
            }
        }
    });
    found
}

/// Collect the set of local variable names that carry a spot price: a `VarDecl`
/// whose initializer reaches a spot read, or an `Assign` whose RHS reaches one.
/// Iterated to a small fixpoint so a value copied through an intermediate local
/// (`a = getLastPrice(); b = a;`) still counts.
fn spot_tainted_locals(f: &Function) -> HashSet<String> {
    let mut tainted: HashSet<String> = HashSet::new();
    // Up to 3 passes is ample for real bodies (a couple of copy hops).
    for _ in 0..3 {
        let before = tainted.len();
        // Collect (name, source-expr) binding pairs, then taint in a second step
        // so the borrow of `tainted` inside `reaches_spot` does not overlap the
        // mutable insert.
        let mut newly: Vec<String> = Vec::new();
        for s in &f.body {
            s.visit(&mut |st| {
                let binding: Option<(&str, &Expr)> = match &st.kind {
                    StmtKind::VarDecl { name: Some(name), init: Some(init), .. } => {
                        Some((name.as_str(), init))
                    }
                    StmtKind::Expr(Expr { kind: ExprKind::Assign { target, value, .. }, .. }) => {
                        match &target.kind {
                            ExprKind::Ident(name) => Some((name.as_str(), value)),
                            _ => None,
                        }
                    }
                    _ => None,
                };
                if let Some((name, src_expr)) = binding {
                    if reaches_spot(src_expr, &tainted) {
                        newly.push(name.to_string());
                    }
                }
            });
        }
        for n in newly {
            tainted.insert(n);
        }
        if tainted.len() == before {
            break;
        }
    }
    tainted
}

/// Find the first instantaneous spot-read call in `f` that is *folded into a
/// multiply/divide that scales a payout*, returning its span. The read counts as
/// scaling when an operand of a `Mul` / `Div` (or the receiver/arg of a
/// `mulDiv`-family call) reaches the spot price — directly, or through a local
/// variable bound from the read.
///
/// Returns the span of the spot-read call expression itself (the anchor).
fn spot_read_in_scaling(f: &Function) -> Option<Span> {
    // Pre-locate the spot-read call span so we can anchor on the read itself.
    let read_span = spot_read_span(f)?;
    let tainted = spot_tainted_locals(f);

    let mut scaled = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if scaled {
                return;
            }
            match &e.kind {
                // `a * price` / `price / backing` — either side reaches the read.
                ExprKind::Binary { op: BinOp::Mul | BinOp::Div, lhs, rhs } => {
                    scaled = reaches_spot(lhs, &tainted) || reaches_spot(rhs, &tainted);
                }
                // `price.mulDiv(scale, base)` — receiver is the read; or the read
                // appears among the args of a mulDiv-family call.
                ExprKind::Call(c) if is_muldiv_call(c) => {
                    scaled = c.receiver.as_deref().map(|r| reaches_spot(r, &tainted)).unwrap_or(false)
                        || c.args.iter().any(|a| reaches_spot(a, &tainted));
                }
                _ => {}
            }
        });
        if scaled {
            break;
        }
    }
    if scaled {
        Some(read_span)
    } else {
        None
    }
}

/// Span of the first instantaneous spot-read call in `f`'s body.
fn spot_read_span(f: &Function) -> Option<Span> {
    let mut found: Option<Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if is_spot_read_call(c) {
                    found = Some(e.span);
                }
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// Best-effort backtick-able name of the spot read for the message
/// (`getLastPrice()`, `getCurrentPrice()`, ...).
fn scaling_read_name(f: &Function) -> Option<String> {
    let mut name: Option<String> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if name.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if is_spot_read_call(c) {
                    if let Some(n) = &c.func_name {
                        name = Some(format!("{}()", n));
                    }
                }
            }
        });
        if name.is_some() {
            break;
        }
    }
    name
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // VULN — distilled from Olympus V3 EmissionManager: the premium (and thus the
    // emission) is sized from `getLastPrice()`, a *single* stored observation, with
    // no moving-average smoothing. An attacker who moves the spot for one block
    // inflates the premium -> inflates the OHM emission.
    const VULN: &str = r#"
        interface IPrice {
            function getLastPrice() external view returns (uint256);
            function getMovingAverage() external view returns (uint256);
        }
        contract EmissionManager {
            IPrice public PRICE;
            uint256 public backing;
            uint256 public baseEmissionRate;
            uint256 internal constant ONE = 1e18;

            function getPremium() public view returns (uint256) {
                uint256 price = PRICE.getLastPrice();
                uint256 pbr = (price * 1e18) / backing;
                return pbr > ONE ? pbr - ONE : 0;
            }

            function getNextEmission(uint256 supply) public view returns (uint256 emission) {
                uint256 premium = getPremium();
                uint256 emissionRate = (baseEmissionRate * (ONE + premium)) / ONE;
                emission = (supply * emissionRate) / 1e9;
            }
        }
    "#;

    // SAFE — same shape, but the emission is sized from `getMovingAverage()` (a
    // TWAP/moving-average). Must NOT fire (smoothed source is the mitigation).
    const SAFE: &str = r#"
        interface IPrice {
            function getLastPrice() external view returns (uint256);
            function getMovingAverage() external view returns (uint256);
        }
        contract EmissionManager {
            IPrice public PRICE;
            uint256 public backing;
            uint256 public baseEmissionRate;
            uint256 internal constant ONE = 1e18;

            function getPremium() public view returns (uint256) {
                uint256 price = PRICE.getMovingAverage();
                uint256 pbr = (price * 1e18) / backing;
                return pbr > ONE ? pbr - ONE : 0;
            }

            function getNextEmission(uint256 supply) public view returns (uint256 emission) {
                uint256 premium = getPremium();
                uint256 emissionRate = (baseEmissionRate * (ONE + premium)) / ONE;
                emission = (supply * emissionRate) / 1e9;
            }
        }
    "#;

    // SAFE-2 — a spot read, but in a collateral-VALUATION context (no sizing
    // tokens). This is the `oracle-manipulation` detector's class; ours must stay
    // silent to avoid overlap.
    const SAFE_VALUATION: &str = r#"
        interface IPrice {
            function getCurrentPrice() external view returns (uint256);
        }
        contract Lending {
            IPrice public PRICE;
            function collateralValue(uint256 amount) public view returns (uint256) {
                uint256 price = PRICE.getCurrentPrice();
                return (amount * price) / 1e18;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(
            fs.iter().any(|f| f.detector == "backing-spot-inflation"),
            "expected backing-spot-inflation, got {:?}",
            fs.iter().map(|f| &f.detector).collect::<Vec<_>>()
        );
    }

    #[test]
    fn silent_on_moving_average() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "backing-spot-inflation"));
    }

    #[test]
    fn silent_on_pure_valuation() {
        let fs = run(SAFE_VALUATION);
        assert!(!fs.iter().any(|f| f.detector == "backing-spot-inflation"));
    }
}
