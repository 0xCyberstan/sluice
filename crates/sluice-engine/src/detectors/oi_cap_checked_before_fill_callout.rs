//! OI-cap checked before a fill callout — a perpetuals open-interest / capacity
//! cap is asserted *before* a position-modifying external / cross-module callout
//! (a CLOB match/fill, a settlement hook), but the open-interest counters
//! (`longOI`/`shortOI`) are mutated only **after** the callout returns and the cap
//! is **not** re-checked on the post-update value. The fill therefore pushes OI
//! past the cap (the cap was measured against pre-fill OI), and — because the cap
//! gate ran before control left the contract — a re-entrant callout sees the cap
//! still satisfied.
//!
//! ## The shape (Synthetix-V3 `maxMarketSize` class)
//!
//! ```solidity
//! function fill(uint256 size, ...) external {
//!     // (a) OI / capacity cap asserted on the CURRENT (pre-fill) open interest
//!     require(longOI + size <= maxOpenInterest, "OI cap");
//!     // (b) external transfer of control: the CLOB match / settlement hook
//!     matcher.match(size, ...);            // may re-enter; runs while OI is stale
//!     // (c) OI counters mutated only AFTER the callout returns …
//!     longOI += size;                      // (or `MarketLib.updateOI(asset, d)`)
//!     // (d) … and the cap is NEVER re-checked against the new longOI.
//! }
//! ```
//!
//! Two distinct failure modes share this one ordering:
//!   * **Cap measured against stale OI.** The `longOI` read in the cap check is the
//!     pre-fill value; the fill can add to OI such that the post-fill total exceeds
//!     `maxOpenInterest`, yet nothing re-asserts it.
//!   * **Re-entrancy during the gap.** The callout hands control out *after* the
//!     cap passed but *before* the counters move, so a re-entrant fill is gated on
//!     an OI figure that does not yet reflect the in-flight fill.
//!
//! ## Why this is DISTINCT from generic reentrancy / CEI
//!
//! The classic-reentrancy detector keys on a *value/balance* SSTORE positioned
//! after any untrusted external call (the DAO/Curve drain). This detector is the
//! **OI / capacity-cap-recheck** class: it requires a *capacity-cap comparison*
//! (an ordering compare against an OI / `maxMarketSize` symbol) to exist **before**
//! the callout and to be **absent after** it. A fill that has no pre-call OI cap,
//! or that re-checks the cap after the callout, is not this class even when it
//! writes OI after an external call. The signal is the *missing post-callout cap
//! re-evaluation*, not a bare write-after-call.
//!
//! ## Precision
//!
//!   * **Require a genuine capacity cap, not an empty-market check.** The pre-call
//!     guard must be an *ordering* comparison (`<`/`<=`/`>`/`>=`) whose operands
//!     mention an OI / capacity symbol, OR a comparison that references an explicit
//!     cap-limit symbol (`oiCap`/`maxOpenInterest`/`maxMarketSize`). A bare
//!     `longOI == 0` / `longOI + shortOI > 0` non-empty check (the GTE
//!     `AdminPanel.relistMarket` shape) is *not* a capacity cap and does not arm the
//!     detector.
//!   * **SUPPRESS a post-callout recheck.** If an OI cap comparison also appears
//!     *after* the callout, the new OI is validated — silent.
//!   * **SUPPRESS OI-updated-before-the-callout.** If the only OI mutation precedes
//!     the callout (the cap then measures the already-updated OI), there is no
//!     stale-OI gap — silent.
//!   * **SUPPRESS reduce-only paths.** A `reduceOnly` fill only *lowers* OI, so a
//!     capacity cap cannot be breached — silent.
//!   * **SUPPRESS a reentrancy-guarded atomic pre-call check.** With a
//!     `nonReentrant`/lock guard the cap check and the fill are atomic (no re-entry
//!     during the gap), so the pre-call check is sound — silent.
//!
//! ## GTE corpus (anti-overfit)
//!
//! The real GTE `ClearingHouse.processMakerFill` / `_processTakerFill` push
//! `MarketLib.updateOI` *after* the CLOB fill (via `updateAccount`), so (b)+(c)
//! hold — but GTE has **no** open-interest *cap* (its pre-fill gate is the
//! `isLiquidatable` / `assertNotLiquidatable` margin/solvency check, not an OI
//! capacity bound), so predicate (a) is unsatisfied and the detector is correctly
//! **silent** on GTE. It fires on the Synthetix-style shape that *does* assert an
//! OI / `maxMarketSize` cap before the fill and mutates OI afterwards.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{Expr, ExprKind, Function, Span};

use super::prelude::*;

pub struct OICapCheckedBeforeFillCalloutDetector;

impl Detector for OICapCheckedBeforeFillCalloutDetector {
    fn id(&self) -> &'static str {
        "oi-cap-checked-before-fill-callout"
    }
    fn category(&self) -> Category {
        Category::OICapCheckedBeforeFillCallout
    }
    fn description(&self) -> &'static str {
        "An open-interest / capacity cap is asserted before a position-modifying external \
         fill callout, but the OI counters are mutated only after the callout returns and the \
         cap is not re-checked post-update (fill exceeds the cap / the callout re-enters)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.entry_points() {
            // (b) An external transfer of control — the fill / settlement callout.
            // No callout ⇒ nothing hands control out between the cap check and the
            // OI write ⇒ not this class.
            let Some(call) = f.effects.first_external_call() else {
                continue;
            };
            let call_at = call.span.start;

            // (a) A genuine OI / capacity-cap guard positioned BEFORE the callout.
            let Some(guard_span) = first_oi_cap_compare(f, |at| at < call_at) else {
                continue;
            };

            // (c) An OI mutation positioned AFTER the callout: an OI-named SSTORE, or
            //     an `updateOI(...)` internal call site, both later than the callout.
            let Some(oi_write_span) = first_oi_mutation_after(f, call_at) else {
                continue;
            };

            // (d) NO OI cap comparison after the callout — the new OI is never
            //     re-validated. A post-callout recheck makes the pre-call gate sound.
            if first_oi_cap_compare(f, |at| at > call_at).is_some() {
                continue;
            }

            // SUPPRESS — reduce-only fills only lower OI, so a capacity cap cannot be
            // breached. (`reduceOnly` arg / branch token anywhere in the body.)
            if mentions_reduce_only(cx, f) {
                continue;
            }

            // SUPPRESS — a reentrancy guard makes the pre-call cap check atomic with
            // the fill (no re-entry can slip into the stale-OI gap), so checking the
            // cap before the callout is sound.
            if cx.has_reentrancy_guard(f) {
                continue;
            }

            let b = report!(self, Category::OICapCheckedBeforeFillCallout,
                title = "Open-interest cap checked before the fill callout but OI updated after, without a post-callout recheck",
                severity = Severity::High,
                confidence = 0.6,
                dimensions = [Dimension::Frontier],
                message = format!(
                    "`{name}` asserts an open-interest / capacity cap (an OI bound) and then hands \
                     control to an external fill / settlement callout, but the open-interest counters \
                     (`longOI`/`shortOI` — written here or via `updateOI`) are mutated only **after** \
                     that callout returns, and the cap is **not** re-checked against the post-fill OI. \
                     The cap therefore gates on the pre-fill open interest: the fill can push OI past \
                     the cap, and because the gate ran before control left the contract, a re-entrant \
                     fill sees the cap still satisfied. (Synthetix-V3 `maxMarketSize` class — distinct \
                     from generic checks-effects reentrancy: the missing signal is the post-callout OI \
                     *cap re-evaluation*, not a bare value write-after-call.)",
                    name = f.name,
                ),
                recommendation =
                    "Update the open-interest counters before the fill callout, or re-assert the \
                     capacity cap against the new `longOI`/`shortOI` *after* the callout returns (and \
                     wrap the path in a `nonReentrant` guard). The cap must be evaluated on the \
                     open interest that already includes the in-flight fill.",
            );
            // Anchor the finding at the pre-call cap guard whose post-fill value is
            // never re-validated; fall back to the OI write if the guard span is
            // unavailable.
            let anchor = if guard_span.is_dummy() { oi_write_span } else { guard_span };
            out.push(finish_at(cx, b, f.id, anchor));
        }

        out
    }
}

// ------------------------------------------------------------------ helpers

/// Does `name` (a state-var / member / identifier name) read like an open-interest
/// counter or a capacity bound on it? Lower-cased substring match over the
/// perpetuals OI / capacity lexicon from the spec.
fn is_oi_symbol(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("openinterest")
        || l.contains("longoi")
        || l.contains("shortoi")
        || l.contains("oicap")
        || l.contains("maxopeninterest")
        || l.contains("maxmarketsize")
        || l.contains("skew")
}

/// Does `name` read like an explicit capacity *limit* symbol (the right-hand bound
/// of a cap, e.g. `maxOpenInterest`/`maxMarketSize`/`oiCap`)? A comparison that
/// references such a symbol is a capacity cap regardless of the comparison operator.
fn is_oi_cap_limit_symbol(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("oicap") || l.contains("maxopeninterest") || l.contains("maxmarketsize")
}

/// Does any bare identifier / member name inside `e` satisfy `pred`?
fn any_name_in_expr(e: &Expr, mut pred: impl FnMut(&str) -> bool) -> bool {
    let mut hit = false;
    e.visit(&mut |sub| {
        match &sub.kind {
            ExprKind::Ident(n) if pred(n) => hit = true,
            ExprKind::Member { member, .. } if pred(member) => hit = true,
            _ => {}
        }
    });
    hit
}

/// Is `e` a literal integer `0`? (To exclude `longOI > 0` / `== 0` empty-market
/// checks from counting as a capacity cap.)
fn is_zero_lit(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Lit(sluice_ir::Lit::Number(n)) if n.trim().trim_start_matches('-').parse::<u128>() == Ok(0))
}

/// Is `e` a *capacity-cap* comparison — a comparison whose operands mention an OI
/// symbol AND that expresses an actual bound, not a non-empty check?
///
///   * An ordering compare (`<`/`<=`/`>`/`>=`) with an OI symbol on either side is a
///     cap — **unless** it is `oi > 0` / `oi >= 0` against a literal zero (the
///     empty-market shape).
///   * Any comparison (incl. `==`/`!=`) that references an explicit cap-limit symbol
///     (`maxOpenInterest`/`maxMarketSize`/`oiCap`) is a cap.
fn is_oi_cap_compare(e: &Expr) -> bool {
    let ExprKind::Binary { op, lhs, rhs } = &e.kind else {
        return false;
    };
    if !op.is_comparison() {
        return false;
    }
    let mentions_oi = any_name_in_expr(lhs, is_oi_symbol) || any_name_in_expr(rhs, is_oi_symbol);
    if !mentions_oi {
        return false;
    }
    // An explicit cap-limit symbol on either side ⇒ a cap regardless of operator.
    if any_name_in_expr(lhs, is_oi_cap_limit_symbol) || any_name_in_expr(rhs, is_oi_cap_limit_symbol) {
        return true;
    }
    // Otherwise require an ordering compare, and exclude the `oi {>,>=} 0` /
    // `0 {<,<=} oi` empty-market non-cap checks.
    if !op.is_ordering() {
        return false;
    }
    let against_zero = is_zero_lit(lhs) || is_zero_lit(rhs);
    !against_zero
}

/// The span of the first capacity-cap comparison in `f`'s body whose start offset
/// satisfies `pos` (e.g. "before the callout" / "after the callout"). Comparisons
/// in `require`/`if`/`while` conditions are reached by the recursive expr visit.
fn first_oi_cap_compare(f: &Function, mut pos: impl FnMut(u32) -> bool) -> Option<Span> {
    let mut hit: Option<Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            if is_oi_cap_compare(e) && pos(e.span.start) {
                hit = Some(e.span);
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// The span of the first OI mutation in `f` positioned strictly after `call_at`:
/// either an OI-named storage write (SSTORE to a `longOI`/`shortOI`/`openInterest`
/// var or `.longOI`-style member path), or an `updateOI(...)` call site. Both carry
/// real spans, so ordering against the callout's span is exact.
fn first_oi_mutation_after(f: &Function, call_at: u32) -> Option<Span> {
    // (c1) An OI-named SSTORE after the callout (`longOI += size`, `metadata.longOI = x`).
    let write = f
        .effects
        .storage_writes
        .iter()
        .filter(|w| w.span.start > call_at && (is_oi_symbol(&w.var) || path_mentions_oi(&w.path)))
        .map(|w| w.span)
        .min_by_key(|s| s.start);

    // (c2) An `updateOI(...)` call site after the callout — the GTE-style indirection
    // `MarketLib.updateOI(asset, oiDelta)` that mutates OI inside a callee.
    let update = first_call_span_after(f, call_at, |c| {
        c.func_name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case("updateOI"))
    });

    match (write, update) {
        (Some(a), Some(b)) => Some(if a.start <= b.start { a } else { b }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Does a storage access *path* mention an OI symbol (`metadata.longOI`)? The effect
/// summary records member-write paths under the root struct var, so the OI member is
/// only visible in `path`, not `var`.
fn path_mentions_oi(path: &str) -> bool {
    let l = path.to_ascii_lowercase();
    l.contains("longoi") || l.contains("shortoi") || l.contains("openinterest")
}

/// Span of the first call expression satisfying `pred` whose start offset is strictly
/// greater than `after`.
fn first_call_span_after(f: &Function, after: u32, mut pred: impl FnMut(&sluice_ir::Call) -> bool) -> Option<Span> {
    let mut hit: Option<Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if let ExprKind::Call(c) = &e.kind {
                if e.span.start > after && pred(c) {
                    match hit {
                        Some(h) if h.start <= e.span.start => {}
                        _ => hit = Some(e.span),
                    }
                }
            }
        });
    }
    hit
}

/// Does `f` reference a `reduceOnly` token (a reduce-only fill arg / branch / field)?
/// Reduce-only fills only lower OI, so a capacity cap cannot be breached — these are
/// suppressed. Uses the comment-stripped, lowercased body text.
fn mentions_reduce_only(cx: &AnalysisContext, f: &Function) -> bool {
    cx.source_text(f.span).contains("reduceonly")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyze_sources, Config};
    use sluice_findings::Finding;

    fn findings(src: &str) -> Vec<Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default())
            .findings
            .into_iter()
            .filter(|f| f.detector == "oi-cap-checked-before-fill-callout")
            .collect()
    }
    fn fires(src: &str) -> bool {
        !findings(src).is_empty()
    }

    // ---------------------------------------------------------------- fires_on_*

    // VULN — Synthetix `maxMarketSize` class: the cap `longOI + size <=
    // maxOpenInterest` is asserted on the PRE-fill OI, control goes to an external
    // matcher (`matcher.matchOrder`), then `longOI`/`shortOI` are bumped AFTER the
    // callout with NO post-callout recheck.
    const VULN_DIRECT_OI_WRITE: &str = r#"
        interface IMatcher { function matchOrder(uint256 size, address taker) external returns (uint256); }
        contract Perp {
            uint256 public longOI;
            uint256 public shortOI;
            uint256 public maxOpenInterest;
            IMatcher matcher;
            function fill(uint256 size, address taker, bool isLong) external {
                require(longOI + size <= maxOpenInterest, "OI cap");   // (a) pre-call cap on stale OI
                matcher.matchOrder(size, taker);                       // (b) external transfer of control
                if (isLong) longOI += size; else shortOI += size;      // (c) OI mutated AFTER callout
                // (d) no recheck against the new longOI
            }
        }
    "#;

    // VULN — GTE-style indirection: OI is mutated through an `updateOI(asset, delta)`
    // call after the CLOB fill callout, while the cap was asserted before it.
    const VULN_UPDATEOI_CALL: &str = r#"
        interface IClob { function matchIncoming(bytes32 asset, uint256 base) external; }
        library MarketLib { function updateOI(bytes32 asset, int256 delta) internal {} }
        contract ClearingHouse {
            uint256 public longOI;
            uint256 public maxMarketSize;
            IClob clob;
            function processFill(bytes32 asset, uint256 base, int256 oiDelta) external {
                require(longOI + base <= maxMarketSize, "max market size");  // (a)
                clob.matchIncoming(asset, base);                             // (b)
                MarketLib.updateOI(asset, oiDelta);                          // (c) updateOI AFTER callout
            }
        }
    "#;

    // VULN — `skew` capacity bound (ordering compare on an OI/skew symbol), cap before
    // the settlement hook, OI write after.
    const VULN_SKEW_BOUND: &str = r#"
        interface ISettle { function settle(uint256 size) external; }
        contract Market {
            uint256 public longOI;
            uint256 public maxSkew;
            ISettle settlement;
            function open(uint256 size) external {
                uint256 skew = longOI + size;
                require(skew < maxSkew, "skew cap");      // (a) ordering compare on skew
                settlement.settle(size);                  // (b)
                longOI += size;                           // (c)
            }
        }
    "#;

    #[test]
    fn fires_on_direct_oi_write_after_callout() {
        assert!(fires(VULN_DIRECT_OI_WRITE), "{:#?}", findings(VULN_DIRECT_OI_WRITE));
    }

    #[test]
    fn fires_on_updateoi_call_after_callout() {
        assert!(fires(VULN_UPDATEOI_CALL), "{:#?}", findings(VULN_UPDATEOI_CALL));
    }

    #[test]
    fn fires_on_skew_capacity_bound() {
        assert!(fires(VULN_SKEW_BOUND), "{:#?}", findings(VULN_SKEW_BOUND));
    }

    #[test]
    fn fires_emits_correct_category() {
        let fs = findings(VULN_DIRECT_OI_WRITE);
        assert!(
            fs.iter().any(|f| f.category == Category::OICapCheckedBeforeFillCallout),
            "must emit the OICapCheckedBeforeFillCallout category"
        );
    }

    // --------------------------------------------------------------- silent_on_*

    // SAFE — the cap is re-checked AFTER the callout against the updated OI.
    const SAFE_POST_CALLOUT_RECHECK: &str = r#"
        interface IMatcher { function matchOrder(uint256 size, address taker) external; }
        contract Perp {
            uint256 public longOI;
            uint256 public maxOpenInterest;
            IMatcher matcher;
            function fill(uint256 size, address taker) external {
                require(longOI + size <= maxOpenInterest, "pre");
                matcher.matchOrder(size, taker);
                longOI += size;
                require(longOI <= maxOpenInterest, "post");   // re-checked on the NEW OI
            }
        }
    "#;

    // SAFE — OI is updated BEFORE the callout, so the cap (here re-derived after) and
    // the fill operate on the already-incremented OI; no stale-OI gap.
    const SAFE_OI_UPDATED_BEFORE_CALLOUT: &str = r#"
        interface IMatcher { function matchOrder(uint256 size) external; }
        contract Perp {
            uint256 public longOI;
            uint256 public maxOpenInterest;
            IMatcher matcher;
            function fill(uint256 size) external {
                require(longOI + size <= maxOpenInterest, "cap");
                longOI += size;                  // OI mutated BEFORE the callout
                matcher.matchOrder(size);
            }
        }
    "#;

    // SAFE — reduce-only fill: only lowers OI, a capacity cap cannot be breached.
    const SAFE_REDUCE_ONLY: &str = r#"
        interface IMatcher { function matchOrder(uint256 size) external; }
        contract Perp {
            uint256 public longOI;
            uint256 public maxOpenInterest;
            bool public reduceOnly;
            IMatcher matcher;
            function fill(uint256 size) external {
                require(longOI + size <= maxOpenInterest, "cap");
                matcher.matchOrder(size);
                if (reduceOnly) longOI -= size; else longOI += size;
            }
        }
    "#;

    // SAFE — reentrancy-guarded: the pre-call cap check is atomic with the fill, so no
    // re-entry can slip into the stale-OI window.
    const SAFE_REENTRANCY_GUARD: &str = r#"
        interface IMatcher { function matchOrder(uint256 size) external; }
        contract Perp {
            uint256 public longOI;
            uint256 public maxOpenInterest;
            uint256 private _lock = 1;
            IMatcher matcher;
            modifier nonReentrant() { require(_lock == 1); _lock = 2; _; _lock = 1; }
            function fill(uint256 size) external nonReentrant {
                require(longOI + size <= maxOpenInterest, "cap");
                matcher.matchOrder(size);
                longOI += size;
            }
        }
    "#;

    // SAFE — no OI cap at all: the pre-call gate is a margin/solvency check
    // (`isLiquidatable`), and the only OI compare is an empty-market `longOI +
    // shortOI > 0` check elsewhere. This is the GTE `_processTakerFill` shape: OI is
    // updated after the fill, but there is no capacity cap to re-check. MUST be silent.
    const SAFE_GTE_NO_OI_CAP: &str = r#"
        interface IClob { function matchIncoming(bytes32 asset, uint256 base) external; }
        library MarketLib { function updateOI(bytes32 asset, int256 delta) internal {} }
        contract ClearingHouse {
            uint256 public longOI;
            uint256 public shortOI;
            IClob clob;
            function isLiquidatable(int256 margin) internal pure returns (bool) { return margin < 0; }
            function processFill(bytes32 asset, uint256 base, int256 oiDelta, int256 margin) external {
                require(!isLiquidatable(margin), "liquidatable");  // margin gate, NOT an OI cap
                clob.matchIncoming(asset, base);
                MarketLib.updateOI(asset, oiDelta);                // OI updated after, but no cap exists
            }
        }
    "#;

    // SAFE — an empty-market check (`longOI + shortOI > 0`) is the only OI comparison
    // before the callout: not a capacity cap (the GTE `AdminPanel.relistMarket`
    // shape), so it does not arm the detector even though OI is written after.
    const SAFE_EMPTY_MARKET_CHECK: &str = r#"
        interface IClob { function matchIncoming(uint256 base) external; }
        contract Market {
            uint256 public longOI;
            uint256 public shortOI;
            IClob clob;
            function fill(uint256 base) external {
                require(longOI + shortOI > 0, "empty market");  // non-empty check, NOT a cap
                clob.matchIncoming(base);
                longOI += base;
            }
        }
    "#;

    // SAFE — no external callout between the cap and the OI write: nothing hands
    // control out, so neither stale-OI re-entry nor a missing recheck is exploitable.
    const SAFE_NO_CALLOUT: &str = r#"
        contract Perp {
            uint256 public longOI;
            uint256 public maxOpenInterest;
            function fill(uint256 size) external {
                require(longOI + size <= maxOpenInterest, "cap");
                longOI += size;
            }
        }
    "#;

    #[test]
    fn silent_on_post_callout_recheck() {
        assert!(!fires(SAFE_POST_CALLOUT_RECHECK), "{:#?}", findings(SAFE_POST_CALLOUT_RECHECK));
    }

    #[test]
    fn silent_on_oi_updated_before_callout() {
        assert!(!fires(SAFE_OI_UPDATED_BEFORE_CALLOUT), "{:#?}", findings(SAFE_OI_UPDATED_BEFORE_CALLOUT));
    }

    #[test]
    fn silent_on_reduce_only() {
        assert!(!fires(SAFE_REDUCE_ONLY), "{:#?}", findings(SAFE_REDUCE_ONLY));
    }

    #[test]
    fn silent_on_reentrancy_guard() {
        assert!(!fires(SAFE_REENTRANCY_GUARD), "{:#?}", findings(SAFE_REENTRANCY_GUARD));
    }

    #[test]
    fn silent_on_gte_no_oi_cap() {
        assert!(!fires(SAFE_GTE_NO_OI_CAP), "{:#?}", findings(SAFE_GTE_NO_OI_CAP));
    }

    #[test]
    fn silent_on_empty_market_check() {
        assert!(!fires(SAFE_EMPTY_MARKET_CHECK), "{:#?}", findings(SAFE_EMPTY_MARKET_CHECK));
    }

    #[test]
    fn silent_on_no_callout() {
        assert!(!fires(SAFE_NO_CALLOUT), "{:#?}", findings(SAFE_NO_CALLOUT));
    }

    // -------------------------------------------------- REAL GTE corpus (anti-overfit)

    /// Read the real GTE perps ClearingHouse + Market if the corpus is present;
    /// `None` skips on a machine without the checkout.
    fn gte_sources() -> Option<Vec<(String, String)>> {
        let root = "/home/stan/Data/corpus/gte-perps/contracts/perps/types";
        let paths = [
            format!("{root}/ClearingHouse.sol"),
            format!("{root}/Market.sol"),
        ];
        let mut out = Vec::new();
        for p in &paths {
            out.push((p.clone(), std::fs::read_to_string(p).ok()?));
        }
        Some(out)
    }

    // The real GTE fill path (`processMakerFill`/`_processTakerFill` → `updateAccount`
    // → `MarketLib.updateOI`) mutates OI after the CLOB fill, but GTE has NO OI
    // capacity cap (the pre-fill gate is `isLiquidatable`, not a `maxMarketSize`
    // bound). The detector MUST stay silent on the whole corpus.
    #[test]
    fn silent_on_real_gte_corpus() {
        let Some(sources) = gte_sources() else {
            eprintln!("GTE perps corpus absent — skipping the anti-overfit assertion");
            return;
        };
        let res = analyze_sources(sources, &Config::default());
        let hits: Vec<_> = res
            .findings
            .into_iter()
            .filter(|f| f.detector == "oi-cap-checked-before-fill-callout")
            .collect();
        assert!(
            hits.is_empty(),
            "OI-cap detector must be silent on the real GTE perps corpus (no OI capacity cap exists there); got {:#?}",
            hits
        );
    }
}
