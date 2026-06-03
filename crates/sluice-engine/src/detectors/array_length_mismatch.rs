//! Array-length-mismatch in batch / airdrop / multicall functions.
//!
//! A function that accepts **two or more dynamic-array parameters** and then
//! indexes more than one of them inside a loop (`a[i]`, `b[i]`) is unsafe unless
//! it first requires the arrays to be the same length. If a caller passes arrays
//! of different lengths the loop either:
//!   * silently truncates to the shorter array (the longer array's tail is
//!     dropped — e.g. recipients credited with no amount, or amounts paid to no
//!     one), or
//!   * indexes past the end of the shorter array and reverts out-of-bounds
//!     (griefing / wasted gas), or
//!   * mis-pairs data when one array is built from another with a stale length.
//!
//! This is the classic `airdrop(recipients, amounts)` / `batchTransfer(to, ids,
//! amounts)` footgun. The canonical fix is a single
//! `require(a.length == b.length)` at the top of the function.
//!
//! ## Detection
//! Flag a function with `>= 2` array-typed parameters (parameter `ty` contains
//! `"[]"`) whose body contains a loop that indexes **two or more distinct array
//! parameters** by a subscript (`param[expr]`), when the function source does
//! **not** contain a length-equality comparison (`.length ==` / `.length !=`) or
//! a `LengthMismatch` revert.
//!
//! ## False-positive suppression (precision first)
//!   * Suppress when **two or more array params are never co-indexed inside the
//!     *same* loop body** — arrays iterated in *separate, independent* loops
//!     (each loop touches only one array) cannot mismatch against each other.
//!     This is the `redeemDueInterestAndRewards(sys, yts, markets)` shape: three
//!     standalone `for` loops, no shared iteration.
//!   * Suppress when the function body carries a length-equality guard covering
//!     every co-indexed pair, scanning the **whole body** (not just the loop
//!     header). The guard may be written directly (`require(a.length ==
//!     b.length)`, `if (a.length != b.length) revert`) OR through a
//!     *length-alias* local (`uint256 len = a.length; require(len == b.length)`,
//!     the `LimitRouterBase.setLnFeeRateRoots` shape). A `LengthMismatch`-style
//!     custom error/revert is also treated as a guard.
//!   * Suppress when only one array parameter is actually indexed in a loop
//!     (single-array iteration cannot mismatch).
//!
//! Confidence is kept modest (0.5): this is a syntactic heuristic and the
//! equality guard could in principle be expressed in a form we don't recognize,
//! or the arrays could be independent (not co-indexed by the same index).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Builtin, CallKind, Expr, ExprKind, Function, Span, Stmt, StmtKind};
use std::collections::{HashMap, HashSet};

pub struct ArrayLengthMismatchDetector;

impl Detector for ArrayLengthMismatchDetector {
    fn id(&self) -> &'static str {
        "array-length-mismatch"
    }
    fn category(&self) -> Category {
        Category::ArrayLengthMismatch
    }
    fn description(&self) -> &'static str {
        "Batch/airdrop function co-indexes 2+ array params in a loop without requiring equal lengths"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Batch entry points are externally reachable and state-mutating;
            // a pure view that reads mismatched arrays is not a value bug.
            if !f.is_externally_reachable() || !f.is_state_mutating() {
                continue;
            }

            // (1) Collect the names of the dynamic-array parameters. We need two
            //     or more to even have a mismatch.
            let array_params: HashSet<&str> = f
                .params
                .iter()
                .filter(|p| p.ty.contains("[]"))
                .filter_map(|p| p.name.as_deref())
                .collect();
            if array_params.len() < 2 {
                continue;
            }

            // (2) The function must contain at least one loop whose body
            //     co-indexes two or more of those array parameters *together*.
            //     Arrays iterated in SEPARATE, independent loops (each loop body
            //     subscripting only one array) share no iteration index and cannot
            //     mismatch against one another — this is the `redeemDueInterest…`
            //     three-independent-loops shape, which we do NOT flag.
            let coindexed_groups = coindexed_groups_per_loop(f, &array_params);
            let Some(indexed) = coindexed_groups
                .iter()
                .max_by_key(|g| g.len())
                .filter(|g| g.len() >= 2)
            else {
                continue;
            };

            // (3) FP suppression: a length-equality guard (or a LengthMismatch
            //     revert) is present *anywhere in the body* covering every
            //     co-indexed pair. We scan the whole function — not just the loop
            //     header — and resolve length-alias locals (`len = a.length`) so a
            //     `require(len == b.length)` three lines above the loop still
            //     counts (the `LimitRouterBase.setLnFeeRateRoots` shape).
            if source_requires_equal_lengths(&cx.source_text(f.span))
                || coindexed_group_is_length_guarded(f, indexed)
            {
                continue;
            }

            // Locate the finding at the first co-indexing site inside a loop.
            let span = first_coindex_span(f, &array_params).unwrap_or(f.span);

            // Two or more *named* array parameters listed for the message.
            let mut names: Vec<&str> = indexed.iter().copied().collect();
            names.sort_unstable();
            let arrays = names.join("`, `");

            let b = FindingBuilder::new(self.id(), Category::ArrayLengthMismatch)
                .title("Parallel arrays indexed in a loop without an equal-length check")
                .severity(Severity::Medium)
                .confidence(0.5)
                // Invariant: the implicit "the parallel arrays are the same
                // length" precondition is never asserted before the loop.
                .dimension(Dimension::Invariant)
                .message(format!(
                    "`{}` takes multiple array parameters (`{}`) and indexes more than one of them \
                     together in a loop without first requiring their lengths to be equal. If a \
                     caller passes arrays of different lengths the loop silently truncates to the \
                     shorter one (dropping or mis-pairing the tail) or reverts out-of-bounds — the \
                     classic airdrop/batch-transfer length-mismatch footgun (CWE-129).",
                    f.name, arrays
                ))
                .recommendation(
                    "Add `require(a.length == b.length, \"length mismatch\")` (one check per extra \
                     array) at the top of the function so mismatched inputs revert deterministically.",
                );
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

// ------------------------------------------------------------------- helpers

/// For every loop body reachable in `f`, the set of array-parameter names
/// subscripted (`param[expr]`) *within that loop body*. One entry per loop. Only
/// names in `array_params` are counted. A loop whose body subscripts two or more
/// distinct array params is a genuine parallel-array (co-indexed) iteration; a
/// loop touching a single array, or arrays spread across *separate* loops, is
/// not. (Indexing must occur within a loop — a one-off `a[0]` outside a loop is
/// not the co-iteration pattern we target.)
fn coindexed_groups_per_loop<'a>(f: &'a Function, array_params: &HashSet<&'a str>) -> Vec<HashSet<&'a str>> {
    let mut groups: Vec<HashSet<&'a str>> = Vec::new();
    for s in &f.body {
        visit_loops(s, &mut |loop_body| {
            let mut found: HashSet<&'a str> = HashSet::new();
            for ls in loop_body {
                ls.visit_exprs(&mut |e| {
                    if let ExprKind::Index { base, index: Some(_) } = &e.kind {
                        if let Some(name) = base.simple_name() {
                            if let Some(p) = array_params.get(name) {
                                found.insert(*p);
                            }
                        }
                    }
                });
            }
            groups.push(found);
        });
    }
    groups
}

/// Span of the first subscript on an array parameter inside a loop (best-effort
/// location for the finding).
fn first_coindex_span(f: &Function, array_params: &HashSet<&str>) -> Option<Span> {
    let mut span: Option<Span> = None;
    for s in &f.body {
        visit_loops(s, &mut |loop_body| {
            for ls in loop_body {
                ls.visit_exprs(&mut |e| {
                    if span.is_some() {
                        return;
                    }
                    if let ExprKind::Index { base, index: Some(_) } = &e.kind {
                        if let Some(name) = base.simple_name() {
                            if array_params.contains(name) {
                                span = Some(e.span);
                            }
                        }
                    }
                });
            }
        });
    }
    span
}

/// Invoke `f` with the body of every loop (`for`/`while`/`do-while`) reachable
/// from `s`, including loops nested inside other statements.
fn visit_loops<'a>(s: &'a Stmt, f: &mut impl FnMut(&'a [Stmt])) {
    s.visit(&mut |inner| match &inner.kind {
        StmtKind::For { body, .. }
        | StmtKind::While { body, .. }
        | StmtKind::DoWhile { body, .. } => f(body),
        _ => {}
    });
}

/// True if the source text carries a length-equality guard (or a
/// `LengthMismatch`-style revert) that would make the mismatch revert. We strip
/// ASCII whitespace so both `a.length == b.length` and `a.length==b.length`
/// match, and lowercase so `LengthMismatch` / `lengthMismatch` are caught.
fn source_requires_equal_lengths(src: &str) -> bool {
    let lower = src.to_ascii_lowercase();
    if lower.contains("lengthmismatch") {
        return true;
    }
    let compact: String = lower.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    // `.length ==` / `length ==` / `.length !=` / `length !=`, with or without
    // spaces — the canonical parallel-array precondition.
    compact.contains("length==") || compact.contains("length!=")
}

// --------------------------------------------------- whole-body guard analysis

/// True if a length-equality guard somewhere in `f`'s body covers *every*
/// co-indexed array in `group` — i.e. the lengths are transitively forced equal,
/// so a mismatch reverts. The guard graph is built from the WHOLE body (not just
/// the loop header) and resolves *length-alias* locals: a local bound to
/// `arr.length` (`uint256 len = arr.length;`) stands in for `arr.length` in a
/// later comparison. `group` is "fully guarded" when, restricted to the group's
/// arrays, the guarded `==`/`!=` pairs connect them into a single component.
fn coindexed_group_is_length_guarded(f: &Function, group: &HashSet<&str>) -> bool {
    if group.len() < 2 {
        return true;
    }
    // (a) length-alias locals: `local -> array` for `local = array.length`.
    let mut alias: HashMap<String, String> = HashMap::new();
    collect_length_aliases(&f.body, &mut alias);

    // (b) guarded length-equality pairs harvested from guard positions only
    //     (`require`/`assert` args and `if`/loop conditions) so an incidental
    //     `a.length == b.length` *value* expression is not mistaken for a guard.
    let mut pairs: Vec<(String, String)> = Vec::new();
    collect_guard_length_pairs(&f.body, &alias, &mut pairs);
    if pairs.is_empty() {
        return false;
    }

    // (c) union-find connectivity over the group's array names.
    let names: Vec<&str> = group.iter().copied().collect();
    let idx = |n: &str| names.iter().position(|m| *m == n);
    let mut parent: Vec<usize> = (0..names.len()).collect();
    fn find(parent: &mut [usize], x: usize) -> usize {
        let mut r = x;
        while parent[r] != r {
            r = parent[r];
        }
        let mut c = x;
        while parent[c] != r {
            let n = parent[c];
            parent[c] = r;
            c = n;
        }
        r
    }
    for (a, b) in &pairs {
        if let (Some(ia), Some(ib)) = (idx(a), idx(b)) {
            let ra = find(&mut parent, ia);
            let rb = find(&mut parent, ib);
            parent[ra] = rb;
        }
    }
    let root0 = find(&mut parent, 0);
    (0..names.len()).all(|i| find(&mut parent, i) == root0)
}

/// Record `local -> array` for every `local = array.length` binding (a `VarDecl`
/// initializer or a plain `Assign`), scanning the whole statement tree.
fn collect_length_aliases(body: &[Stmt], out: &mut HashMap<String, String>) {
    for s in body {
        s.visit(&mut |inner| match &inner.kind {
            StmtKind::VarDecl { name: Some(local), init: Some(e), .. } => {
                if let Some(arr) = length_base(e) {
                    out.insert(local.clone(), arr.to_string());
                }
            }
            StmtKind::Expr(e) => {
                if let ExprKind::Assign { target, value, .. } = &e.kind {
                    if let (ExprKind::Ident(local), Some(arr)) = (&target.kind, length_base(value)) {
                        out.insert(local.clone(), arr.to_string());
                    }
                }
            }
            _ => {}
        });
    }
}

/// Harvest unordered array-name pairs from length-equality comparisons that sit
/// in a *guard* position: the argument of a `require`/`assert`, or the condition
/// of an `if`/`while`/`for`/`do-while`. Each comparison side must resolve to an
/// array length (`arr.length` directly, or a length-alias local).
fn collect_guard_length_pairs(body: &[Stmt], alias: &HashMap<String, String>, out: &mut Vec<(String, String)>) {
    // First collect the guard-position condition expressions, then harvest pairs
    // from each (avoids a closure double-borrowing `out`).
    let mut conds: Vec<&Expr> = Vec::new();
    for s in body {
        s.visit(&mut |inner| match &inner.kind {
            StmtKind::If { cond, .. } | StmtKind::While { cond, .. } | StmtKind::DoWhile { cond, .. } => {
                conds.push(cond)
            }
            StmtKind::For { cond: Some(cond), .. } => conds.push(cond),
            StmtKind::Expr(e) => {
                // `require(a.length == b.length, ...)` / `assert(...)`: take the
                // first argument (the predicate) as a guard condition.
                e.visit(&mut |sub| {
                    if let ExprKind::Call(c) = &sub.kind {
                        if matches!(
                            c.kind,
                            CallKind::Builtin(Builtin::Require) | CallKind::Builtin(Builtin::Assert)
                        ) {
                            if let Some(first) = c.args.first() {
                                conds.push(first);
                            }
                        }
                    }
                });
            }
            _ => {}
        });
    }
    for cond in conds {
        harvest_eq_pairs(cond, alias, out);
    }
}

/// Walk `e`, recording an unordered `(arr_a, arr_b)` pair for every `==`/`!=`
/// comparison whose two sides each resolve to an array length.
fn harvest_eq_pairs(e: &Expr, alias: &HashMap<String, String>, out: &mut Vec<(String, String)>) {
    e.visit(&mut |sub| {
        if let ExprKind::Binary { op: BinOp::Eq | BinOp::Ne, lhs, rhs } = &sub.kind {
            if let (Some(a), Some(b)) = (length_operand(lhs, alias), length_operand(rhs, alias)) {
                if a != b {
                    out.push((a, b));
                }
            }
        }
    });
}

/// If `e` is `arr.length`, return `arr`.
fn length_base(e: &Expr) -> Option<&str> {
    if let ExprKind::Member { base, member } = &e.kind {
        if member == "length" {
            return base.simple_name();
        }
    }
    None
}

/// Resolve a comparison operand to the underlying array name when it denotes an
/// array length: either `arr.length` directly, or a length-alias local
/// (`len` where `len = arr.length`).
fn length_operand(e: &Expr, alias: &HashMap<String, String>) -> Option<String> {
    if let Some(arr) = length_base(e) {
        return Some(arr.to_string());
    }
    if let ExprKind::Ident(name) = &e.kind {
        return alias.get(name).cloned();
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Airdrop co-indexes `recipients` and `amounts` in a loop with NO equal-length
    // check — mismatched arrays silently truncate or revert out-of-bounds.
    const VULN: &str = r#"
pragma solidity ^0.8.20;
contract Airdrop {
    mapping(address => uint256) public credited;
    function airdrop(address[] calldata recipients, uint256[] calldata amounts) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            credited[recipients[i]] += amounts[i];
        }
    }
}
"#;

    // Same shape, but a leading `require(... .length == ... .length)` enforces the
    // precondition, so a mismatch reverts deterministically.
    const SAFE: &str = r#"
pragma solidity ^0.8.20;
contract Airdrop {
    mapping(address => uint256) public credited;
    function airdrop(address[] calldata recipients, uint256[] calldata amounts) external {
        require(recipients.length == amounts.length, "len");
        for (uint256 i = 0; i < recipients.length; i++) {
            credited[recipients[i]] += amounts[i];
        }
    }
}
"#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "array-length-mismatch"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "array-length-mismatch"));
    }

    fn fired(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.detector == "array-length-mismatch")
    }

    // --- Fix 1a: whole-body guard via a length-alias local. The guard
    //     `require(len == lnFeeRateRoots.length)` sits three lines ABOVE the loop
    //     and references the local `len = YTs.length`, not `YTs.length` directly.
    //     The pre-fix detector only looked at the loop header and missed it.
    //     (Pendle `LimitRouterBase.setLnFeeRateRoots:476`.) ---
    const GUARDED_VIA_ALIAS_LOCAL: &str = r#"
contract LimitRouterBase {
    uint256 constant MAX = 100;
    mapping(address => uint256) __lnFeeRateRoot;
    function setLnFeeRateRoots(address[] memory YTs, uint256[] memory lnFeeRateRoots, bool allowZeroFees) public {
        uint256 len = YTs.length;
        require(len == lnFeeRateRoots.length, "length mismatch");
        for (uint256 i = 0; i < len; i++) {
            require(lnFeeRateRoots[i] > 0 || allowZeroFees, "zero");
            __lnFeeRateRoot[YTs[i]] = lnFeeRateRoots[i];
        }
    }
}
"#;

    #[test]
    fn silent_on_guarded_via_alias_local() {
        assert!(!fired(&run(GUARDED_VIA_ALIAS_LOCAL)), "alias-local length guard must suppress");
    }

    // Same body but with the alias guard REMOVED: now genuinely unguarded, so it
    // must fire (proves the suppression is the guard, not the shape).
    const GUARDED_VIA_ALIAS_LOCAL_NO_GUARD: &str = r#"
contract LimitRouterBase {
    mapping(address => uint256) __lnFeeRateRoot;
    function setLnFeeRateRoots(address[] memory YTs, uint256[] memory lnFeeRateRoots, bool allowZeroFees) public {
        uint256 len = YTs.length;
        for (uint256 i = 0; i < len; i++) {
            __lnFeeRateRoot[YTs[i]] = lnFeeRateRoots[i];
        }
    }
}
"#;

    #[test]
    fn fires_when_alias_guard_absent() {
        assert!(fired(&run(GUARDED_VIA_ALIAS_LOCAL_NO_GUARD)), "unguarded co-indexed loop must fire");
    }

    // --- Fix 1b: three INDEPENDENT loops, each iterating ONE array by its own
    //     `.length`; no two arrays share an iteration index, so no mismatch is
    //     possible. (Pendle `ActionMiscV3.redeemDueInterestAndRewards:79`.) ---
    const INDEPENDENT_LOOPS: &str = r#"
interface ISY { function claimRewards(address u) external; }
interface IYT { function redeem(address u) external; }
interface IMkt { function redeemRewards(address u) external; }
contract ActionMiscV3 {
    function redeemDueInterestAndRewards(
        address user,
        address[] calldata sys,
        address[] calldata yts,
        address[] calldata markets
    ) external {
        for (uint256 i = 0; i < sys.length; ++i) { ISY(sys[i]).claimRewards(user); }
        for (uint256 i = 0; i < yts.length; ++i) { IYT(yts[i]).redeem(user); }
        for (uint256 i = 0; i < markets.length; ++i) { IMkt(markets[i]).redeemRewards(user); }
    }
}
"#;

    #[test]
    fn silent_on_independent_loops() {
        assert!(!fired(&run(INDEPENDENT_LOOPS)), "independent single-array loops must not be flagged");
    }

    // --- Retained TP 1: three arrays co-indexed by the SAME `i` in ONE loop with
    //     no equal-length check. (EigenLayer `DelegationManager.completeQueuedWithdrawals:220`.) ---
    const TP_DELEGATIONMANAGER: &str = r#"
contract DelegationManager {
    function _complete(bytes32 w, address[] memory t, bool r) internal {}
    function completeQueuedWithdrawals(
        bytes32[] calldata withdrawals,
        address[][] calldata tokens,
        bool[] calldata receiveAsTokens
    ) external {
        uint256 n = withdrawals.length;
        for (uint256 i; i < n; ++i) {
            _complete(withdrawals[i], tokens[i], receiveAsTokens[i]);
        }
    }
}
"#;

    #[test]
    fn fires_on_coindexed_no_guard_delegationmanager() {
        // `n = withdrawals.length` is a bound, NOT a cross-array equality guard.
        assert!(fired(&run(TP_DELEGATIONMANAGER)), "co-indexed arrays w/o equal-length guard must fire");
    }

    // --- Retained TP 2: two arrays (`swaps`, `netSwaps`) co-indexed in a loop,
    //     with only an *allocation* `new uint256[](swaps.length)` (not a guard).
    //     (Pendle `ActionMiscV3.swapTokensToTokens:184`.) ---
    const TP_SWAPTOKENS: &str = r#"
struct SwapDataExtra { address tokenIn; }
contract ActionMiscV3 {
    function _transferIn(address t, address from, uint256 a) internal {}
    function swapTokensToTokens(
        SwapDataExtra[] calldata swaps,
        uint256[] calldata netSwaps
    ) external payable returns (uint256[] memory netOut) {
        netOut = new uint256[](swaps.length);
        for (uint256 i = 0; i < swaps.length; ++i) {
            _transferIn(swaps[i].tokenIn, msg.sender, netSwaps[i]);
        }
    }
}
"#;

    #[test]
    fn fires_on_coindexed_no_guard_swaptokens() {
        assert!(fired(&run(TP_SWAPTOKENS)), "allocation `new[](a.length)` is not an equal-length guard");
    }
}
