//! Mark-vs-index price inconsistency on a perpetuals/derivatives venue — the
//! perpdex "Criteria Price Arbitrage" / "Extreme Price Selection" class.
//!
//! A perp venue typically maintains **two** prices for the same asset:
//!   * a *platform* `markPrice` / `markTwap` — the venue's own derived price
//!     (median of impact / basis / index, an order-book-influenced number), and
//!   * an *oracle* `indexPrice` / `indexTwap` (a.k.a. `oraclePrice`) — the
//!     external spot reference.
//!
//! Solvency must be evaluated *consistently*: whatever price decides whether a
//! position is liquidatable / margin-sufficient must be the same price the close /
//! settlement path realizes the position at. If the **liquidation/solvency CHECK**
//! reads one construct (say `indexPrice`) while the **close/PnL/settlement
//! EXECUTION** reads the other (`markPrice`), a position can be *solvent at the
//! check price yet realize a different value at execution* — a risk-free
//! arbitrage, or a liquidation that can be dodged / forced depending on the gap
//! between the two prices. The two feeds can be driven apart (the mark is
//! order-book-influenced; the index is the spot oracle), so the inconsistency is
//! exploitable, not merely cosmetic.
//!
//! ## What this detector is (and what it is NOT)
//!
//! This is the **two-named-construct-used-inconsistently** shape, deliberately
//! distinct from the existing single-feed / AMM price detectors:
//!   * `oracle.rs` / `twap_manipulation.rs` — a *single* manipulable spot/TWAP
//!     source feeding valuation (Cream/Harvest; fake-TWAP windows).
//!   * `oracle_staleness.rs` / `price_bounds.rs` — *freshness* and *min/max bound*
//!     of a single Chainlink-style feed.
//!
//! None of those reason about a venue carrying BOTH a mark and an index price and
//! reading *different ones* on the check vs the execution leg. That cross-feed
//! consistency property is this detector's sole contribution.
//!
//! ## Precision first (this is the highest-FP-risk perps class)
//!
//! The detector is intentionally **narrow** — it fires only on the strongest,
//! lowest-FP signal and is silent on every safe form:
//!
//!   * **Precondition.** The contract must reference BOTH a mark-construct
//!     (`markPrice`/`markTwap`) AND an index-construct
//!     (`indexPrice`/`indexTwap`/`oraclePrice`). A contract with only one price
//!     construct is a single-feed shape — deferred to the detectors above, never
//!     flagged here.
//!   * **Primary (the only) fire condition.** Within that contract, a
//!     *solvency/liquidation-surface* function (`liquidat*` / `isLiquidatable` /
//!     `*upnl*` / `*minMargin*` / `maintenanceMargin` / `marginRequirement` /
//!     bad-debt/underwater predicates) reads **one** construct, while a
//!     *close/settlement-surface* function (`close*` / `settle*` / `realizePnl` /
//!     `decreasePosition` / `processMakerFill` / `_processTakerFill` / ...) reads
//!     the **other**, and the two construct sets are **disjoint** (one side
//!     mark-only, the other index-only).
//!   * **Suppressed.** The same construct on both legs (the safe consistent-usage
//!     form — e.g. the GTE `Market` library, which uses `markPrice` uniformly for
//!     `getUpnl`/`getUpnlAndMinMargin`/`getNotionalValue`/`getMaintenanceMargin`);
//!     a conservative direction-selector on the solvency leg (`isLong ? lo : hi` /
//!     `min`/`max` over the two prices, which makes the asymmetry safe); the
//!     funding engine's legitimate `markTwap − indexTwap` premium (a funding fn is
//!     neither a solvency nor a close surface, so it never enters either set).
//!
//! The *secondary* §2 signal ("a lone liquidation comparison with no
//! direction-conditioned selection") is **deliberately not** a standalone fire
//! condition: a liquidation comparing a single price against a trigger with no
//! `isLong` selector is overwhelmingly benign (e.g. a TP/SL trigger check), so
//! using it to fire would flood false positives. A conservative selector is used
//! only to *suppress*. This keeps the detector precise at the cost of recall — the
//! R7 discipline (a precise narrow detector beats a noisy one).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Contract, Expr, ExprKind, Function, Span};

pub struct MarkVsIndexPriceInconsistencyDetector;

/// Mark-construct keywords (lowercased; matched as a substring of the
/// comment-stripped, lowercased function source).
const MARK_KEYWORDS: &[&str] = &["markprice", "marktwap"];

/// Index/oracle-construct keywords. `oracleprice` is the common alias for the
/// external spot reference on a perp venue.
const INDEX_KEYWORDS: &[&str] = &["indexprice", "indextwap", "oracleprice"];

/// Name fragments identifying a **solvency / liquidation** surface — the leg that
/// decides whether a position is liquidatable / sufficiently margined.
const SOLVENCY_FN_FRAGMENTS: &[&str] = &[
    "liquidat",            // liquidate / isLiquidatable / assertLiquidatable / liquidationPrice
    "upnl",                // getUpnl / getUpnlAndMinMargin
    "minmargin",           // getMinMargin / *MinMargin*
    "maintenancemargin",   // getMaintenanceMargin
    "marginrequirement",   // isOpenMarginRequirementMet / marginRequirement
    "solvenc",             // isSolvent / solvencyCheck
    "baddebt",             // hasBadDebt
    "underwater",          // isUnderwater
    "bankrupt",            // isBankrupt
];

/// Name fragments identifying a **close / settlement / PnL-realization** surface —
/// the leg that actually realizes a position's value.
const CLOSE_FN_FRAGMENTS: &[&str] = &[
    "close",            // close / closePosition
    "settle",           // settle / settlePnl   (NOTE: settleFunding is excluded below)
    "realizepnl",       // realizePnl / realizePnL
    "realizedpnl",
    "decreaseposition",
    "reduceposition",
    "processmakerfill",
    "processtakerfill", // _processTakerFill
    "fillorder",
    "executetrade",
];

impl Detector for MarkVsIndexPriceInconsistencyDetector {
    fn id(&self) -> &'static str {
        "mark-vs-index-price-inconsistency"
    }
    fn category(&self) -> Category {
        Category::MarkVsIndexPriceInconsistency
    }
    fn description(&self) -> &'static str {
        "Perp solvency CHECK and close/settlement EXECUTION read different price constructs (mark vs index)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        // Group functions by their owning contract so the precondition (BOTH
        // constructs present) and the two-surface comparison are contract-scoped.
        // `contract_of` resolves the IR contract for each function.
        let mut seen_contracts: Vec<sluice_ir::ContractId> = Vec::new();
        for f in cx.functions() {
            let Some(contract) = cx.contract_of(f.id) else { continue };
            if seen_contracts.contains(&contract.id) {
                continue;
            }
            seen_contracts.push(contract.id);

            // Pure interface declarations carry no implementation risk.
            if contract.is_interface() {
                continue;
            }

            if let Some(finding) = self.analyze_contract(cx, contract) {
                out.push(finding);
            }
        }
        out
    }
}

impl MarkVsIndexPriceInconsistencyDetector {
    /// Analyze one contract for the disjoint mark/index solvency-vs-close shape.
    /// Returns at most one finding per contract (anchored on the offending
    /// solvency-surface function).
    fn analyze_contract(&self, cx: &AnalysisContext, contract: &Contract) -> Option<Finding> {
        // The functions that belong to this contract, with their bodies.
        let fns: Vec<&Function> = cx
            .functions()
            .filter(|f| f.contract == contract.id && f.has_body)
            .collect();
        if fns.is_empty() {
            return None;
        }

        // ---- Precondition: the contract references BOTH constructs somewhere. ----
        //
        // We test the union of the (comment-stripped, lowercased) bodies, which is
        // exactly the text each per-function read scan also sees, so the
        // precondition can never be satisfied by text a per-function scan cannot
        // re-find. A single-construct contract is a single-feed shape and is left
        // entirely to the single-feed detectors.
        let mut any_mark = false;
        let mut any_index = false;
        let mut fn_src: Vec<(usize, String)> = Vec::with_capacity(fns.len());
        for (i, f) in fns.iter().enumerate() {
            let src = cx.source_text(f.span);
            any_mark |= mentions_any(&src, MARK_KEYWORDS);
            any_index |= mentions_any(&src, INDEX_KEYWORDS);
            fn_src.push((i, src));
        }
        if !(any_mark && any_index) {
            return None;
        }

        // ---- Classify each surface function by which construct(s) it reads. ----
        //
        // `solvency`: (fn index, reads_mark, reads_index, has_conservative_selector)
        // `close`:    (fn index, reads_mark, reads_index)
        let mut solvency: Vec<(usize, bool, bool, bool)> = Vec::new();
        let mut close: Vec<(usize, bool, bool)> = Vec::new();

        for (i, src) in &fn_src {
            let f = fns[*i];
            let reads_mark = mentions_any(src, MARK_KEYWORDS);
            let reads_index = mentions_any(src, INDEX_KEYWORDS);
            // A function that reads neither construct is irrelevant to the
            // cross-feed comparison.
            if !reads_mark && !reads_index {
                continue;
            }

            if is_solvency_surface(f) {
                let selector = has_conservative_selector(f);
                solvency.push((*i, reads_mark, reads_index, selector));
            }
            // A function can be both (rare); allow it to populate both sets.
            if is_close_surface(f) {
                close.push((*i, reads_mark, reads_index));
            }
        }

        if solvency.is_empty() || close.is_empty() {
            // Need *both* a price-reading solvency surface and a price-reading
            // close surface to compare them.
            return None;
        }

        // ---- Fire on a disjoint pairing (precision-first). ----
        //
        // Inconsistency = a solvency leg that reads exactly one construct and a
        // close leg that reads exactly the *other* construct (and not the first).
        // "Exactly one" on each side guarantees true disjointness; a leg that reads
        // BOTH constructs is internally hedged and never anchors a finding.
        for &(si, s_mark, s_index, selector) in &solvency {
            // A conservative direction-selector on the solvency leg makes the
            // asymmetry safe (it already picks the worse-case price per side).
            if selector {
                continue;
            }
            let solvency_mark_only = s_mark && !s_index;
            let solvency_index_only = s_index && !s_mark;
            if !(solvency_mark_only || solvency_index_only) {
                continue; // reads both (or neither) — not a one-sided check.
            }

            for &(ci, c_mark, c_index) in &close {
                if ci == si {
                    continue; // same function can't disagree with itself.
                }
                let close_mark_only = c_mark && !c_index;
                let close_index_only = c_index && !c_mark;
                if !(close_mark_only || close_index_only) {
                    continue;
                }

                let disagree = (solvency_mark_only && close_index_only)
                    || (solvency_index_only && close_mark_only);
                if !disagree {
                    continue;
                }

                // Build the finding, anchored on the solvency-surface function
                // (the security-relevant decision site).
                let s_fn = fns[si];
                let c_fn = fns[ci];
                let (s_label, c_label) = if solvency_mark_only {
                    ("mark price (`markPrice`/`markTwap`)", "index/oracle price (`indexPrice`/`indexTwap`/`oraclePrice`)")
                } else {
                    ("index/oracle price (`indexPrice`/`indexTwap`/`oraclePrice`)", "mark price (`markPrice`/`markTwap`)")
                };

                let anchor = price_read_span(s_fn).unwrap_or(s_fn.span);
                let b = FindingBuilder::new(self.id(), Category::MarkVsIndexPriceInconsistency)
                    .title("Liquidation/solvency check and settlement read different price constructs (mark vs index)")
                    .severity(Severity::High)
                    .confidence(0.55)
                    .dimension(Dimension::ValueFlow)
                    .dimension(Dimension::Frontier)
                    .message(format!(
                        "`{contract}.{s_name}` evaluates solvency/liquidation against the {s_label}, but the \
                         close/settlement path `{contract}.{c_name}` realizes the position at the {c_label}. \
                         Because the venue maintains both feeds and they can diverge (the mark is \
                         order-book-influenced; the index is the external spot), a position can be solvent at \
                         the check price yet realize a different value when closed/liquidated — a risk-free \
                         arbitrage or a liquidation that can be dodged or forced by widening the gap between \
                         the two prices (the perpdex \"Criteria Price Arbitrage\" / \"Extreme Price Selection\" \
                         class).",
                        contract = contract.name,
                        s_name = s_fn.name,
                        c_name = c_fn.name,
                        s_label = s_label,
                        c_label = c_label,
                    ))
                    .recommendation(
                        "Use one consistent price construct for the solvency CHECK and the close/settlement \
                         EXECUTION of a given leg, or — if both feeds must be consulted — select the \
                         conservative side per position direction (`isLong ? lower : higher`, or \
                         `min`/`max` over mark and index) so the realized value can never beat the value the \
                         solvency check was evaluated against.",
                    );
                return Some(cx.finish(b, s_fn.id, anchor));
            }
        }

        None
    }
}

// ----------------------------------------------------------------- classifiers

/// Does `src` (a comment-stripped, lowercased function body) contain any of the
/// given keyword substrings?
fn mentions_any(src: &str, keywords: &[&str]) -> bool {
    keywords.iter().any(|k| src.contains(k))
}

/// Is `f` a solvency / liquidation surface by name?
fn is_solvency_surface(f: &Function) -> bool {
    let n = f.name.to_ascii_lowercase();
    SOLVENCY_FN_FRAGMENTS.iter().any(|frag| n.contains(frag))
}

/// Is `f` a close / settlement / PnL-realization surface by name?
///
/// `settleFunding` (and any `*funding*` settle) is explicitly **excluded**: the
/// funding engine legitimately consumes BOTH `markTwap` and `indexTwap` to compute
/// the funding premium (`markTwap − indexTwap`), which is the *correct* dual use of
/// the two feeds, not a check-vs-execution inconsistency. Treating it as a close
/// surface would create a false positive against every well-formed funding engine.
fn is_close_surface(f: &Function) -> bool {
    let n = f.name.to_ascii_lowercase();
    if n.contains("funding") {
        return false;
    }
    CLOSE_FN_FRAGMENTS.iter().any(|frag| n.contains(frag))
}

/// Does `f` apply a *conservative direction-selector* over its prices — i.e. it
/// already picks the worse-case price for the position's side, so any mark/index
/// asymmetry is intentional and safe?
///
/// Recognized:
///   * a ternary whose condition mentions a direction flag (`isLong` / `isShort` /
///     a `side`/`long`/`short`-named value) — `isLong ? lower : higher`; or
///   * a `min(...)` / `max(...)` call (the worse-of-two-prices idiom), whether a
///     free function or a `.min(...)` / `.max(...)` library method.
fn has_conservative_selector(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            match &e.kind {
                ExprKind::Ternary { cond, .. } if expr_mentions_direction(cond) => {
                    found = true;
                }
                ExprKind::Call(c) if call_is_min_max(c) => {
                    found = true;
                }
                _ => {}
            }
        });
        if found {
            break;
        }
    }
    found
}

/// Does an expression mention a position-direction flag anywhere within it?
fn expr_mentions_direction(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        let name = match &sub.kind {
            ExprKind::Ident(n) => Some(n.as_str()),
            ExprKind::Member { member, .. } => Some(member.as_str()),
            _ => None,
        };
        if let Some(n) = name {
            let l = n.to_ascii_lowercase();
            if l == "islong" || l == "isshort" || l == "long" || l == "short" || l == "side" {
                found = true;
            }
        }
    });
    found
}

/// Is `c` a `min`/`max` selection call — a free `min(a,b)`/`max(a,b)` or a
/// library-method `x.min(y)` / `x.max(y)` (the trailing callee name is `min`/`max`)?
fn call_is_min_max(c: &sluice_ir::Call) -> bool {
    let name = c
        .func_name
        .as_deref()
        .map(str::to_ascii_lowercase)
        .or_else(|| callee_trailing_name(&c.callee).map(str::to_ascii_lowercase));
    matches!(name.as_deref(), Some("min") | Some("max"))
}

/// Trailing identifier/member of a callee expression (`min` for both `min` and
/// `FixedPointMathLib.min` / `a.min`).
fn callee_trailing_name(e: &Expr) -> Option<&str> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n),
        ExprKind::Member { member, .. } => Some(member),
        _ => None,
    }
}

/// Span of the first expression in `f` that reads a mark/index price construct —
/// used as the finding anchor so it points at the offending price read rather than
/// the whole function. Matches an identifier or a member access whose (lowercased)
/// name contains one of the construct keywords.
fn price_read_span(f: &Function) -> Option<Span> {
    let mut found: Option<Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            let name = match &e.kind {
                ExprKind::Ident(n) => Some(n.as_str()),
                ExprKind::Member { member, .. } => Some(member.as_str()),
                _ => None,
            };
            if let Some(n) = name {
                let l = n.to_ascii_lowercase();
                if MARK_KEYWORDS.iter().chain(INDEX_KEYWORDS).any(|k| l.contains(k)) {
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

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "mark-vs-index-price-inconsistency")
    }

    // ---- fires_on: the genuine inconsistency ----
    //
    // The liquidation check reads `indexPrice` while the close path realizes PnL at
    // `markPrice`. The two are disjoint → solvent-at-check / different-at-execution.
    const FIRES_DISJOINT: &str = r#"
        contract Perp {
            uint256 public markPrice;
            uint256 public indexPrice;
            mapping(address => uint256) openNotional;
            mapping(address => uint256) amount;
            mapping(address => uint256) margin;

            // Solvency CHECK against the INDEX price.
            function isLiquidatable(address acct) public view returns (bool) {
                uint256 notional = amount[acct] * indexPrice / 1e18;
                return margin[acct] < notional / 20;
            }

            // Close/settlement EXECUTION against the MARK price.
            function closePosition(address acct) external {
                uint256 notional = amount[acct] * markPrice / 1e18;
                int256 pnl = int256(notional) - int256(openNotional[acct]);
                margin[acct] = uint256(int256(margin[acct]) + pnl);
                amount[acct] = 0;
            }
        }
    "#;

    #[test]
    fn fires_on_disjoint_check_vs_execution() {
        assert!(fires(FIRES_DISJOINT), "{:?}", run(FIRES_DISJOINT));
    }

    // The mirror: solvency on MARK, settlement on INDEX — also fires.
    const FIRES_MIRROR: &str = r#"
        contract Perp2 {
            uint256 public markTwap;
            uint256 public indexTwap;
            mapping(address => uint256) amount;
            mapping(address => uint256) margin;
            mapping(address => uint256) openNotional;

            function getUpnlAndMinMargin(address acct) public view returns (int256 upnl, uint256 minMargin) {
                uint256 notional = amount[acct] * markTwap / 1e18;
                upnl = int256(notional) - int256(openNotional[acct]);
                minMargin = notional / 20;
            }

            function settlePnl(address acct) external {
                uint256 notional = amount[acct] * indexTwap / 1e18;
                margin[acct] = notional;
            }
        }
    "#;

    #[test]
    fn fires_on_mirror_direction() {
        assert!(fires(FIRES_MIRROR), "{:?}", run(FIRES_MIRROR));
    }

    // ---- silent_on: the safe / benign forms ----

    // Safe consistent usage — the GTE `Market` shape: every solvency + PnL helper
    // uses the SAME construct (`markPrice`); index appears only as a funding /
    // mark-construction input. MUST NOT fire.
    const SILENT_CONSISTENT: &str = r#"
        contract MarketLikeGTE {
            uint256 public markPrice;
            mapping(address => uint256) amount;
            mapping(address => uint256) openNotional;
            mapping(address => uint256) margin;
            int256 public cumulativeFundingIndex;

            // Solvency uses markPrice.
            function getUpnlAndMinMargin(address acct) public view returns (int256 upnl, uint256 minMargin) {
                uint256 notional = amount[acct] * markPrice / 1e18;
                upnl = int256(notional) - int256(openNotional[acct]);
                minMargin = notional / 20;
            }
            function isLiquidatable(address acct) public view returns (bool) {
                (int256 upnl, uint256 mm) = getUpnlAndMinMargin(acct);
                return int256(margin[acct]) + upnl < int256(mm);
            }
            // Close also uses markPrice — SAME construct, consistent.
            function closePosition(address acct) external {
                uint256 notional = amount[acct] * markPrice / 1e18;
                margin[acct] = notional;
                amount[acct] = 0;
            }
            // Funding legitimately consumes BOTH mark and index twaps — this is the
            // correct dual use, not a check-vs-execution mismatch.
            function settleFunding(uint256 markTwap, uint256 indexTwap) external {
                int256 premium = int256(markTwap) - int256(indexTwap);
                cumulativeFundingIndex += premium;
            }
        }
    "#;

    #[test]
    fn silent_on_consistent_markprice_usage() {
        assert!(!fires(SILENT_CONSISTENT), "{:?}", run(SILENT_CONSISTENT));
    }

    // Single-construct contract: only `markPrice` exists (no index construct). This
    // is a single-feed shape, deferred to the single-feed detectors. MUST NOT fire.
    const SILENT_SINGLE_CONSTRUCT: &str = r#"
        contract SingleFeed {
            uint256 public markPrice;
            mapping(address => uint256) amount;
            mapping(address => uint256) margin;
            mapping(address => uint256) openNotional;

            function isLiquidatable(address acct) public view returns (bool) {
                uint256 notional = amount[acct] * markPrice / 1e18;
                return margin[acct] < notional / 20;
            }
            function closePosition(address acct) external {
                uint256 notional = amount[acct] * markPrice / 1e18;
                margin[acct] = notional;
                amount[acct] = 0;
            }
        }
    "#;

    #[test]
    fn silent_on_single_construct() {
        assert!(!fires(SILENT_SINGLE_CONSTRUCT), "{:?}", run(SILENT_SINGLE_CONSTRUCT));
    }

    // Conservative selector present: the solvency leg picks the worse-case price by
    // direction (`isLong ? indexPrice : markPrice`), so the asymmetry is safe even
    // though the close leg reads a single construct. MUST NOT fire.
    const SILENT_CONSERVATIVE_SELECTOR: &str = r#"
        contract PerpSafeSelector {
            uint256 public markPrice;
            uint256 public indexPrice;
            mapping(address => uint256) amount;
            mapping(address => bool) isLong;
            mapping(address => uint256) margin;
            mapping(address => uint256) openNotional;

            function isLiquidatable(address acct) public view returns (bool) {
                // Worse-case price per side.
                uint256 px = isLong[acct] ? indexPrice : markPrice;
                uint256 notional = amount[acct] * px / 1e18;
                return margin[acct] < notional / 20;
            }
            function closePosition(address acct) external {
                uint256 notional = amount[acct] * markPrice / 1e18;
                margin[acct] = notional;
                amount[acct] = 0;
            }
        }
    "#;

    #[test]
    fn silent_on_conservative_selector() {
        assert!(!fires(SILENT_CONSERVATIVE_SELECTOR), "{:?}", run(SILENT_CONSERVATIVE_SELECTOR));
    }

    // min/max worse-of-two-prices on the solvency leg — also a conservative
    // selector. MUST NOT fire.
    const SILENT_MIN_MAX: &str = r#"
        contract PerpMinMax {
            uint256 public markPrice;
            uint256 public indexPrice;
            mapping(address => uint256) amount;
            mapping(address => uint256) margin;
            mapping(address => uint256) openNotional;

            function getUpnl(address acct) public view returns (int256) {
                uint256 px = markPrice < indexPrice ? markPrice : indexPrice;
                uint256 worse = px;
                uint256 m = max(markPrice, indexPrice);
                uint256 notional = amount[acct] * worse / 1e18;
                return int256(notional) - int256(openNotional[acct]) - int256(m * 0);
            }
            function closePosition(address acct) external {
                uint256 notional = amount[acct] * markPrice / 1e18;
                margin[acct] = notional;
                amount[acct] = 0;
            }
            function max(uint256 a, uint256 b) internal pure returns (uint256) { return a > b ? a : b; }
        }
    "#;

    #[test]
    fn silent_on_min_max_selector() {
        assert!(!fires(SILENT_MIN_MAX), "{:?}", run(SILENT_MIN_MAX));
    }

    // Both legs read BOTH constructs (internally hedged) — not a one-sided
    // disagreement. MUST NOT fire.
    const SILENT_BOTH_READ_BOTH: &str = r#"
        contract PerpHedged {
            uint256 public markPrice;
            uint256 public indexPrice;
            mapping(address => uint256) amount;
            mapping(address => uint256) margin;
            mapping(address => uint256) openNotional;

            function isLiquidatable(address acct) public view returns (bool) {
                uint256 p = (markPrice + indexPrice) / 2;
                uint256 notional = amount[acct] * p / 1e18;
                return margin[acct] < notional / 20;
            }
            function closePosition(address acct) external {
                uint256 p = (markPrice + indexPrice) / 2;
                uint256 notional = amount[acct] * p / 1e18;
                margin[acct] = notional;
                amount[acct] = 0;
            }
        }
    "#;

    #[test]
    fn silent_when_both_legs_read_both_constructs() {
        assert!(!fires(SILENT_BOTH_READ_BOTH), "{:?}", run(SILENT_BOTH_READ_BOTH));
    }
}
