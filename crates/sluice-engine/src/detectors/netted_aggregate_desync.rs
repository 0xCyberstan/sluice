//! Netted-aggregate desync — a value/TVL quantity computed as the **subtraction
//! of two SEPARATE per-key storage aggregates** (`aggA[k] - aggB[k]`) whose two
//! sides are **written by different functions with no joint / ordered
//! invariant**, so the two totals can drift apart (or `aggB` overshoot `aggA`)
//! and the read either reports a wrong value or **underflows**.
//!
//! This is the **Renzo `OperatorDelegator` queued-shares-minus-slashing-delta**
//! shape. The contract tracks TVL-relevant shares with two independent mappings:
//! the shares queued for withdrawal (`queuedShares[token]`) and a running
//! slashing correction (`totalTokenQueuedSharesSlashedDelta[token]`). The TVL read
//! nets them:
//!
//! ```solidity
//! function _getQueuedSharesWithSlashing(address _underlying) internal view returns (uint256) {
//!     return queuedShares[_underlying] - totalTokenQueuedSharesSlashedDelta[_underlying];
//! }
//! ```
//!
//! Each side is mutated by a *different* entrypoint, and there is no single
//! function / invariant that keeps them ordered:
//!   * `queuedShares[token]` is grown by `queueWithdrawals` /
//!     `emergencyTrackQueuedWithdrawals` (passed by storage reference into a
//!     library that mutates it);
//!   * `totalTokenQueuedSharesSlashedDelta[token]` is grown by a *separate*
//!     admin path, `emergencyTrackSlashedQueuedWithdrawalDelta`.
//!
//! Because the two aggregates are advanced from unrelated call sites with no
//! enforced relation `aggB <= aggA`, the slashing-delta side can be tracked
//! ahead of (or out of step with) the queued-shares side, so the unchecked
//! subtraction can **revert on underflow** (DoSing every TVL read / rebase that
//! funnels through it) or, in the inflate direction, report a stale value. A
//! single `_reduceQueuedShares` that decrements *both* for the same key exists,
//! but that lone co-update does not immunise the class: the two have independent
//! writers elsewhere.
//!
//! ## What the detector matches
//!
//! At a **read site** it looks for a `Binary` subtraction `aggA[k] - aggB[k]`
//! where:
//!   * both operands are *indexed* reads of **distinct** state variables, and
//!   * both are indexed by the **same key** `k` (so they are per-key totals of the
//!     same thing, not two unrelated numbers); and
//!
//! across the functions of the enclosing contract it then proves the two
//! aggregates **desync** — i.e. they are *not* kept in lockstep:
//!   * `aggA` has at least one **mutator function** that does **not** mutate `aggB`,
//!     and `aggB` has at least one mutator function that does **not** mutate `aggA`.
//!
//! A "mutator" of an aggregate `v` is any function whose body either assigns to
//! `v[..]` (`=`, `+=`, `-=`, `++`/`--`/`delete`) **or passes `v` as a call
//! argument** — the latter because Solidity mappings are handed to library /
//! internal helpers *by storage reference*, and the real Renzo writers mutate
//! `queuedShares` exactly that way (`OperatorDelegatorLib.queueWithdrawal(...,
//! queuedShares, ...)`). This structural notion of a writer is also what makes the
//! detector robust to inherited state variables, whose direct `-=` writes are not
//! always attributed to the deriving contract's effect summary.
//!
//! ## Precision (single Invariant dimension)
//!
//!   * **Suppress the single-function co-update** (the accounting CoUpdate): if
//!     *every* function that mutates `aggA` also mutates `aggB` and vice-versa —
//!     i.e. the two only ever move together, in the same functions — there is no
//!     desync and the detector stays silent. Renzo is *not* this case: it has
//!     `aggA`-only and `aggB`-only writers in addition to the joint reducer.
//!   * **Require the matching index key.** `a[i] - b[j]` with different keys is not
//!     a single-pool netting and is ignored; a bare-scalar `a - b` is ignored.
//!   * **Require a real subtraction of two reads**, not `a[k] - literal` or
//!     `a[k] - localVar`: both sides must root-resolve to indexed state-variable
//!     reads.
//!   * Pure interfaces / functions without a body never host a read site.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use rustc_hash::{FxHashMap, FxHashSet};
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Contract, Expr, ExprKind, Function, Span, UnOp};

pub struct NettedAggregateDesyncDetector;

/// A netting read site discovered in a function: the two per-key aggregates being
/// subtracted (`aggA[k] - aggB[k]`) and the span of the subtraction.
struct NettingSite {
    agg_a: String,
    agg_b: String,
    span: Span,
}

impl Detector for NettedAggregateDesyncDetector {
    fn id(&self) -> &'static str {
        "netted-aggregate-desync"
    }
    fn category(&self) -> Category {
        Category::NettedAggregateDesync
    }
    fn description(&self) -> &'static str {
        "A value/TVL read netting two separate per-key storage aggregates (aggA[k] - aggB[k]) \
         that are written by different functions with no joint invariant — the two can desync / underflow"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for c in cx.scir.iter_contracts() {
            // A pure interface declares no bodies — no read site and no writers.
            if c.is_interface() {
                continue;
            }

            // Functions visible to this contract's storage namespace: the contract's
            // own functions plus those of any declared base (inherited writers of
            // the aggregates live alongside the netting read). De-dup by id.
            let funcs = visible_functions(cx, c);
            if funcs.is_empty() {
                continue;
            }

            // The set of state-variable names reachable from this contract (own +
            // bases). Used to confirm both netted operands are storage aggregates.
            let state_vars = visible_state_vars(cx, c);

            // Per-aggregate mutator sets, computed once across all visible functions.
            // `mutators[var]` = the set of function indices (into `funcs`) that
            // structurally mutate `var` (assign / inc-dec / pass-by-ref).
            let mut mutators: FxHashMap<&str, FxHashSet<usize>> = FxHashMap::default();
            for (fi, f) in funcs.iter().enumerate() {
                if !f.has_body {
                    continue;
                }
                for v in mutated_vars(f, &state_vars) {
                    mutators.entry(v).or_default().insert(fi);
                }
            }

            // Walk every function body for netting read sites and test the desync.
            let mut seen: FxHashSet<(String, String)> = FxHashSet::default();
            for f in &funcs {
                if !f.has_body {
                    continue;
                }
                for site in netting_sites(f, &state_vars) {
                    // De-dup identical (aggA, aggB) pairs across the contract — one
                    // report per netted pair is enough signal.
                    let key = (site.agg_a.clone(), site.agg_b.clone());
                    if seen.contains(&key) {
                        continue;
                    }

                    if !aggregates_desync(&mutators, &site.agg_a, &site.agg_b) {
                        continue;
                    }
                    seen.insert(key);

                    let b = FindingBuilder::new(self.id(), Category::NettedAggregateDesync)
                        .title("Value read nets two independently-written storage aggregates (can desync / underflow)")
                        .severity(Severity::High)
                        .confidence(0.8)
                        .dimension(Dimension::Invariant)
                        .message(format!(
                            "`{fname}` computes a value as `{a}[k] - {b}[k]`, subtracting two \
                             *separate* per-key storage aggregates. The two sides are written by \
                             **different** functions with no joint or ordered invariant keeping \
                             `{b}[k] <= {a}[k]`: `{a}` is advanced by one set of callers and `{b}` by \
                             another, independently. Because nothing couples them, `{b}[k]` can be \
                             tracked ahead of (or out of step with) `{a}[k]`, so this unchecked \
                             subtraction can **revert on underflow** — bricking every TVL / rebase \
                             read that funnels through it — or, in the other direction, report a stale, \
                             wrong value that misprices the protocol. This is the netted-aggregate \
                             desync class (Renzo `OperatorDelegator` queued-shares minus \
                             slashing-delta).",
                            fname = f.name,
                            a = site.agg_a,
                            b = site.agg_b,
                        ))
                        .recommendation(format!(
                            "Do not derive a value by subtracting two aggregates that are mutated by \
                             unrelated functions. Either (a) maintain a single source of truth and \
                             update both sides in lockstep within one accounting function so the \
                             relation `{b}[k] <= {a}[k]` is an enforced invariant, or (b) clamp the \
                             read (`{a}[k] > {b}[k] ? {a}[k] - {b}[k] : 0`) and add an explicit \
                             invariant check at every writer of `{b}` that it can never exceed \
                             `{a}` for the same key.",
                            a = site.agg_a,
                            b = site.agg_b,
                        ));
                    out.push(cx.finish(b, f.id, site.span));
                }
            }
        }
        out
    }
}

// ------------------------------------------------------------------ helpers

/// The transitive set of contracts in `c`'s inheritance chain — `c` itself plus
/// every (direct or indirect) base, resolved by exact base-name match through the
/// module's contract table. Solidity storage layouts and the writers of inherited
/// state are spread across this whole chain (in Renzo, `queuedShares` is declared
/// many `OperatorDelegatorStorageV{n}` levels up), so single-level base resolution
/// is not enough.
fn inheritance_chain<'a>(cx: &'a AnalysisContext, c: &'a Contract) -> Vec<&'a Contract> {
    // Resolve base names via the module's prebuilt name→contract index
    // (`contract_named`, last-declared-wins — identical to the local map this used
    // to rebuild per call). Rebuilding a `by_name` map over *every* contract on
    // each call made the enclosing per-contract loop O(contracts²); the shared
    // O(1) lookup removes that without changing which contracts are resolved.
    let mut out: Vec<&Contract> = Vec::new();
    let mut seen: FxHashSet<sluice_ir::ContractId> = FxHashSet::default();
    let mut stack: Vec<&Contract> = vec![c];
    while let Some(cur) = stack.pop() {
        if !seen.insert(cur.id) {
            continue;
        }
        out.push(cur);
        for base_name in &cur.bases {
            if let Some(base) = cx.scir.contract_named(base_name) {
                if !seen.contains(&base.id) {
                    stack.push(base);
                }
            }
        }
    }
    out
}

/// Functions whose writes share `c`'s storage namespace: every function across
/// `c`'s full inheritance chain. De-duplicated by function id.
fn visible_functions<'a>(cx: &'a AnalysisContext, c: &'a Contract) -> Vec<&'a Function> {
    let mut out: Vec<&Function> = Vec::new();
    let mut have: FxHashSet<sluice_ir::FunctionId> = FxHashSet::default();
    for k in inheritance_chain(cx, c) {
        for f in cx.scir.functions_of(k.id) {
            if have.insert(f.id) {
                out.push(f);
            }
        }
    }
    out
}

/// State-variable names reachable from `c`: its own declarations plus those of
/// every (transitive) base in the inheritance chain.
fn visible_state_vars(cx: &AnalysisContext, c: &Contract) -> FxHashSet<String> {
    let mut s: FxHashSet<String> = FxHashSet::default();
    for k in inheritance_chain(cx, c) {
        for v in &k.state_vars {
            s.insert(v.name.clone());
        }
    }
    s
}

/// Find every `aggA[k] - aggB[k]` netting site in `f`, where both operands are
/// indexed reads of *distinct* state variables keyed identically.
fn netting_sites(f: &Function, state_vars: &FxHashSet<String>) -> Vec<NettingSite> {
    let mut out = Vec::new();
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            let ExprKind::Binary { op: BinOp::Sub, lhs, rhs } = &e.kind else {
                return;
            };
            let Some((a_var, a_key)) = indexed_state_read(lhs, state_vars) else {
                return;
            };
            let Some((b_var, b_key)) = indexed_state_read(rhs, state_vars) else {
                return;
            };
            // Two *distinct* aggregates, indexed by the *same* key.
            if a_var == b_var {
                return;
            }
            if a_key.is_empty() || a_key != b_key {
                return;
            }
            out.push(NettingSite { agg_a: a_var, agg_b: b_var, span: e.span });
        });
    }
    out
}

/// If `e` is (or directly is) an indexed read `var[key]` whose `var` is a known
/// state variable, return `(var, rendered_key)`. The operand must be *exactly* an
/// index access (after stripping a leading cast like `uint256(x[k])`), not an
/// arbitrary subtree — we want the netted operands themselves, not any indexed
/// read buried inside a larger expression.
fn indexed_state_read(e: &Expr, state_vars: &FxHashSet<String>) -> Option<(String, String)> {
    let e = strip_cast(e);
    let ExprKind::Index { base, index: Some(idx) } = &e.kind else {
        return None;
    };
    let var = root_ident(base)?;
    if !state_vars.contains(&var) {
        return None;
    }
    Some((var, render_key(idx)))
}

/// Strip a surrounding type-cast call (`uint256(x)`, `int256(x)`) returning the
/// single inner argument, so `uint256(a[k]) - uint256(b[k])` still matches.
fn strip_cast(e: &Expr) -> &Expr {
    if let ExprKind::Call(c) = &e.kind {
        if matches!(c.kind, sluice_ir::CallKind::TypeCast) && c.args.len() == 1 {
            return strip_cast(&c.args[0]);
        }
    }
    e
}

/// The set of state variables that `f` **mutates**: assigns to (`=`/`+=`/`-=`),
/// increments/decrements/deletes, or passes by reference as a call argument
/// (Solidity hands storage mappings to library/internal helpers by reference).
fn mutated_vars<'a>(f: &Function, state_vars: &'a FxHashSet<String>) -> FxHashSet<&'a str> {
    // Collect raw mutated names first, then resolve against the state-var set; this
    // keeps the visitor closure free of the `'a` borrow (which would otherwise try
    // to escape the function body).
    let mut names: FxHashSet<String> = FxHashSet::default();
    for s in &f.body {
        s.visit_exprs(&mut |e| match &e.kind {
            ExprKind::Assign { target, .. } => {
                if let Some(n) = root_ident(target) {
                    names.insert(n);
                }
            }
            ExprKind::Unary { op, operand }
                if matches!(
                    op,
                    UnOp::PreInc | UnOp::PreDec | UnOp::PostInc | UnOp::PostDec | UnOp::Delete
                ) =>
            {
                if let Some(n) = root_ident(operand) {
                    names.insert(n);
                }
            }
            // Pass-by-reference into a helper: any call argument that root-resolves
            // to a state-var (mapping/array) is a storage-ref mutation channel.
            ExprKind::Call(c) => {
                for a in &c.args {
                    if let Some(n) = root_ident(a) {
                        names.insert(n);
                    }
                }
            }
            _ => {}
        });
    }
    names
        .iter()
        .filter_map(|n| state_vars.get(n).map(|s| s.as_str()))
        .collect()
}

/// True if `agg_a` and `agg_b` are NOT kept in lockstep — i.e. each has at least
/// one mutator function that does **not** also mutate the other. This is the
/// desync proof; a strict co-update (every mutator touches both) is suppressed.
fn aggregates_desync(
    mutators: &FxHashMap<&str, FxHashSet<usize>>,
    agg_a: &str,
    agg_b: &str,
) -> bool {
    let empty = FxHashSet::default();
    let ma = mutators.get(agg_a).unwrap_or(&empty);
    let mb = mutators.get(agg_b).unwrap_or(&empty);
    // Each side must actually be written by *some* function (a never-written
    // aggregate is a constant-ish read, not a desync risk).
    if ma.is_empty() || mb.is_empty() {
        return false;
    }
    let a_has_independent = ma.iter().any(|fi| !mb.contains(fi));
    let b_has_independent = mb.iter().any(|fi| !ma.contains(fi));
    a_has_independent && b_has_independent
}

/// Root identifier of an lvalue / member / index / cast chain
/// (`a.b[c]` -> `a`, `uint256(x)` -> name of `x`).
fn root_ident(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root_ident(base),
        ExprKind::Call(c) if matches!(c.kind, sluice_ir::CallKind::TypeCast) && c.args.len() == 1 => {
            root_ident(&c.args[0])
        }
        _ => None,
    }
}

/// Render an index expression to a stable, lowercased key string for the same-key
/// comparison: a bare ident, a member chain (`info.token`), or a numeric literal.
/// Anything else renders empty (and so will not match the other side).
fn render_key(e: &Expr) -> String {
    fn go(e: &Expr, buf: &mut String) -> bool {
        match &e.kind {
            ExprKind::Ident(n) => {
                buf.push_str(&n.to_ascii_lowercase());
                true
            }
            ExprKind::Member { base, member } => {
                if !go(base, buf) {
                    return false;
                }
                buf.push('.');
                buf.push_str(&member.to_ascii_lowercase());
                true
            }
            ExprKind::Index { base, index: Some(i) } => {
                if !go(base, buf) {
                    return false;
                }
                buf.push('[');
                if !go(i, buf) {
                    return false;
                }
                buf.push(']');
                true
            }
            ExprKind::Lit(sluice_ir::Lit::Number(n)) => {
                buf.push_str(n.trim());
                true
            }
            // `address(tokens[i])` style cast inside the key — render the inner.
            ExprKind::Call(c)
                if matches!(c.kind, sluice_ir::CallKind::TypeCast) && c.args.len() == 1 =>
            {
                go(&c.args[0], buf)
            }
            _ => false,
        }
    }
    let mut buf = String::new();
    if go(e, &mut buf) {
        buf
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // VULN (Renzo OperatorDelegator shape): two per-token aggregates netted in a
    // TVL read. `queuedShares` is mutated by `queueWithdrawals` (pass-by-ref into a
    // library) and `totalSlashedDelta` by a *separate* `trackSlashed` admin path;
    // a lone `reduce` decrements both (the co-update) but does not immunise the
    // class. The netting subtraction can underflow.
    const VULN: &str = r#"
        library Lib {
            function queue(mapping(address => uint256) storage q, address t, uint256 a) internal {
                q[t] += a;
            }
        }
        contract OperatorDelegator {
            mapping(address => uint256) public queuedShares;
            mapping(address => uint256) public totalSlashedDelta;

            function _getQueuedSharesWithSlashing(address u) internal view returns (uint256) {
                return queuedShares[u] - totalSlashedDelta[u];
            }

            function queueWithdrawals(address t, uint256 a) external {
                Lib.queue(queuedShares, t, a);
            }

            function emergencyTrackSlashed(address t, uint256 d) external {
                totalSlashedDelta[t] += d;
            }

            function reduce(address t, uint256 s, uint256 d) external {
                queuedShares[t] -= s;
                totalSlashedDelta[t] -= d;
            }
        }
    "#;

    // SAFE (pure co-update): the two aggregates are ONLY ever written together, in
    // the same functions, for the same key. They cannot desync, so the netting is
    // sound and the detector must stay silent.
    const SAFE_COUPDATE: &str = r#"
        contract Vault {
            mapping(address => uint256) public deposited;
            mapping(address => uint256) public withdrawn;

            function netBalance(address u) public view returns (uint256) {
                return deposited[u] - withdrawn[u];
            }

            function settle(address u, uint256 inAmt, uint256 outAmt) external {
                deposited[u] += inAmt;
                withdrawn[u] += outAmt;
            }
            function settleTwo(address u, uint256 inAmt, uint256 outAmt) external {
                deposited[u] += inAmt;
                withdrawn[u] += outAmt;
            }
        }
    "#;

    // SAFE (different keys): `a[i] - b[j]` indexes by different keys — not a single
    // per-key pool netting, so it is not the class even though writers differ.
    const SAFE_DIFFERENT_KEYS: &str = r#"
        contract Pools {
            mapping(uint256 => uint256) public credit;
            mapping(uint256 => uint256) public debit;

            function spread(uint256 i, uint256 j) public view returns (uint256) {
                return credit[i] - debit[j];
            }
            function addCredit(uint256 i, uint256 a) external { credit[i] += a; }
            function addDebit(uint256 j, uint256 a) external { debit[j] += a; }
        }
    "#;

    // SAFE (subtracting a constant / local, not a second aggregate): `a[k] - fee`
    // is ordinary arithmetic, not a two-aggregate netting.
    const SAFE_SCALAR_SUB: &str = r#"
        contract Fees {
            mapping(address => uint256) public balance;
            uint256 public fee;
            function payout(address u) public view returns (uint256) {
                uint256 f = fee;
                return balance[u] - f;
            }
            function setFee(uint256 x) external { fee = x; }
            function credit(address u, uint256 a) external { balance[u] += a; }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(
            fs.iter().any(|f| f.detector == "netted-aggregate-desync"
                && f.function == "_getQueuedSharesWithSlashing"),
            "{:#?}",
            fs
        );
    }

    #[test]
    fn silent_on_coupdate() {
        let fs = run(SAFE_COUPDATE);
        assert!(
            !fs.iter().any(|f| f.detector == "netted-aggregate-desync"),
            "{:#?}",
            fs
        );
    }

    #[test]
    fn silent_on_different_keys() {
        let fs = run(SAFE_DIFFERENT_KEYS);
        assert!(!fs.iter().any(|f| f.detector == "netted-aggregate-desync"));
    }

    #[test]
    fn silent_on_scalar_sub() {
        let fs = run(SAFE_SCALAR_SUB);
        assert!(!fs.iter().any(|f| f.detector == "netted-aggregate-desync"));
    }

    // VULN variant: the netting read lives in a DERIVED contract while the two
    // mappings are declared in an inherited storage base, and the `queuedShares`
    // writer mutates it by storage-reference through a library — the precise Renzo
    // layout. Exercises inherited-state-var resolution + pass-by-ref mutation.
    const VULN_INHERITED: &str = r#"
        library OperatorDelegatorLib {
            function queueWithdrawal(
                mapping(address => uint256) storage q, address t, uint256 a
            ) internal { q[t] += a; }
        }
        abstract contract Storage {
            mapping(address => uint256) public queuedShares;
            mapping(address => uint256) public totalTokenQueuedSharesSlashedDelta;
        }
        contract OperatorDelegator is Storage {
            function _getQueuedSharesWithSlashing(address _underlying) internal view returns (uint256) {
                return queuedShares[_underlying] - totalTokenQueuedSharesSlashedDelta[_underlying];
            }
            function queueWithdrawals(address t, uint256 a) external {
                OperatorDelegatorLib.queueWithdrawal(queuedShares, t, a);
            }
            function emergencyTrackSlashedQueuedWithdrawalDelta(address t, uint256 d) external {
                totalTokenQueuedSharesSlashedDelta[t] += d;
            }
        }
    "#;

    #[test]
    fn fires_on_inherited_passbyref_shape() {
        let fs = run(VULN_INHERITED);
        assert!(
            fs.iter().any(|f| f.detector == "netted-aggregate-desync"
                && f.contract == "OperatorDelegator"
                && f.function == "_getQueuedSharesWithSlashing"),
            "{:#?}",
            fs
        );
    }
}
