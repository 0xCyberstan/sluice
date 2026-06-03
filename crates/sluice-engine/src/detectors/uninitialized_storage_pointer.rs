//! Uninitialized / conditionally-bound local `storage` pointer (SWC-109, CWE-824).
//!
//! ## The bug
//! A local reference declared with the `storage` data location is a *pointer to a
//! storage slot*. If it is **not bound to a real slot before it is written
//! through**, it silently points at slot 0 — so `x.field = v` / `x[i] = v` /
//! `x.push(..)` clobbers whatever state variables occupy the first storage slots.
//! This is the classic SWC-109 footgun:
//!
//! ```solidity
//! struct Bid { uint256 amount; address bidder; }
//! function place() external {
//!     Bid storage b;          // <- points at slot 0, never bound
//!     b.amount = msg.value;   // <- clobbers the FIRST state variable
//! }
//! ```
//!
//! Since Solidity 0.5.0 the *truly* never-touched form is a hard compile error, so
//! in 0.8+ code the surviving, still-compilable variant is a **conditionally
//! bound** pointer: it is rebound only in *one* branch of an `if`/`else`, then
//! written through *unconditionally* — on the un-rebound path the write lands on
//! slot 0:
//!
//! ```solidity
//! Bid storage b;              // declared, not bound here
//! if (isNew) { b = bids[id]; }// bound only on the `isNew` path
//! b.amount += msg.value;      // on the else path this writes slot 0
//! ```
//!
//! ## What this detector fires on
//! A *local* `VarDecl` with
//!   * the `storage` data location (recovered from the declaration's source text —
//!     the normalized `ty` drops the location keyword), and
//!   * a **reference** type (a struct/array/`bytes`/`string` — value types cannot
//!     legally take a `storage` location), and
//!   * **no initializer** (`T storage x;`, not `T storage x = ...;`),
//!
//! that is later **written through** (`x.f = …`, `x[i] = …`, `delete x`,
//! `x.push(…)`, or a compound-assign to a member/element of `x`) on a path where
//! `x` has **not been provably rebound** (assigned `x = <slot>`) first.
//!
//! ## Precision (0-FP priority — this class is genuinely rare in 0.8+)
//!   * A pointer rebound **unconditionally** before the write-through is safe and
//!     never fires.
//!   * A pointer rebound in **every** arm of the controlling `if`/`else` before the
//!     write-through is safe (the real-world `ClaimData storage postState; if
//!     (_isAttack) { postState = parent; } else { postState = _find(...); }` shape
//!     in Optimism's `FaultDisputeGame.step` — bound on both paths and only read —
//!     must stay silent).
//!   * A storage pointer that is only **read** (`postState.claim`), never written
//!     through, never fires — reading a slot-0 alias is not the state-clobber bug.
//!   * `mapping(...)` locals and value-typed declarations are ignored (a `storage`
//!     value-type local does not compile; mappings are out of the targeted
//!     struct/array class).
//!
//! Confidence is high for the never-bound form (an unambiguous slot-0 clobber) and
//! a touch lower for the conditional-bind form (the un-rebound branch must be
//! reachable for the write to hit slot 0).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{AssignOp, Expr, ExprKind, Function, Span, Stmt, StmtKind, UnOp};

use super::prelude::*;

pub struct UninitializedStoragePointerDetector;

impl Detector for UninitializedStoragePointerDetector {
    fn id(&self) -> &'static str {
        "uninitialized-storage-pointer"
    }
    fn category(&self) -> Category {
        Category::UninitializedStoragePointer
    }
    fn description(&self) -> &'static str {
        "Local `storage` pointer written through before it is bound to a real slot (defaults to slot 0)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Walk the top-level statement list, threading a "this pointer is
            // provably bound on all paths" flag. We collect candidate VarDecls as
            // we meet them so that only statements *after* the declaration can
            // bind / write-through it (a declaration cannot be clobbered by code
            // that runs before it).
            scan_body(cx, f, &f.body, &mut out);
        }
        out
    }
}

// --------------------------------------------------------------------- core scan

/// A live, not-yet-proven-bound uninitialized storage pointer local.
struct Candidate<'a> {
    name: &'a str,
    ty: &'a str,
    /// Declaration span (where the finding is anchored / reported).
    decl_span: Span,
    /// Set once we observe a guaranteed (all-paths) rebind before any unsafe write.
    bound: bool,
    /// Latched if we ever saw a rebind on *some* (but not guaranteed-all) path —
    /// i.e. a conditional bind inside a branch/loop. Distinguishes the
    /// "conditionally bound" live variant from a never-bound pure slot-0 clobber.
    partial_bind: bool,
    /// Latched once a finding has been emitted for this pointer (dedupe).
    reported: bool,
}

/// Recursively scan a statement slice in document order. `actives` carries the
/// storage-pointer candidates declared in an enclosing scope that are still live
/// (so a write-through nested inside a later block is attributed correctly).
fn scan_body<'a>(
    cx: &AnalysisContext,
    f: &'a Function,
    stmts: &'a [Stmt],
    out: &mut Vec<Finding>,
) {
    let mut actives: Vec<Candidate<'a>> = Vec::new();
    walk(cx, f, stmts, &mut actives, out);
}

/// Process `stmts` **sequentially at one scope level**, mutating the shared
/// `actives` set:
///   * a qualifying `VarDecl` adds a new (unbound) candidate;
///   * an unconditional `name = <expr>` at this level marks that candidate bound
///     (a guaranteed rebind — every subsequent statement at this level runs after
///     it);
///   * an `if`/`else` whose *every* arm rebinds a candidate marks it bound after
///     the `if` (otherwise the candidate stays unbound — a partial bind);
///   * a write-through to a still-unbound candidate emits a finding (once).
///
/// Binding side-effects that happen **inside a conditional/loop sub-scope** are
/// *not* guaranteed on the path that leaves the sub-scope, so [`walk_subscope`]
/// reverts any `bound` flags the sub-scope flipped (the post-`if` all-arms rule
/// re-establishes them only when warranted). The `reported` dedupe latch always
/// persists.
fn walk<'a>(
    cx: &AnalysisContext,
    f: &'a Function,
    stmts: &'a [Stmt],
    actives: &mut Vec<Candidate<'a>>,
    out: &mut Vec<Finding>,
) {
    for s in stmts {
        match &s.kind {
            // (1) A new local declaration — is it an uninitialized storage pointer?
            StmtKind::VarDecl { name: Some(n), ty, init: None } => {
                if is_storage_ref_decl(cx, s.span, ty) {
                    actives.push(Candidate {
                        name: n,
                        ty,
                        decl_span: s.span,
                        bound: false,
                        partial_bind: false,
                        reported: false,
                    });
                }
                // (A storage local with an initializer is bound at the decl site
                //  and is therefore safe — not tracked.)
            }

            // (2) An expression statement at this level: an UNCONDITIONAL rebind
            //     marks the candidate bound; a write-through may hit slot 0.
            StmtKind::Expr(e) => {
                if let Some(name) = rebind_target(e) {
                    mark_bound(actives, name);
                }
                // After (possibly) recording a rebind, look for write-throughs.
                report_write_throughs(cx, f, e, actives, out);
            }

            // (3) `if`/`else`: each arm is a conditional sub-scope. A write-through
            //     to a still-unbound candidate inside an arm is reportable, and a
            //     rebind that *precedes* it within the same arm makes it safe
            //     *within that arm only* — so we walk each arm as a sub-scope and
            //     revert its binding side-effects afterward. The candidate becomes
            //     bound after the `if` only if BOTH arms rebind it.
            StmtKind::If { cond, then_branch, else_branch } => {
                // A rebind hidden in the condition (rare) still runs on entry.
                report_write_throughs(cx, f, cond, actives, out);

                let bound_in_then = arm_rebinds(then_branch);
                let bound_in_else = arm_rebinds(else_branch);

                walk_subscope(cx, f, then_branch, actives, out);
                walk_subscope(cx, f, else_branch, actives, out);

                // Post-if: a candidate is provably bound on the fall-through path
                // only when rebound on EVERY arm. An else-less `if` has an implicit
                // empty else arm that rebinds nothing, so a one-armed bind never
                // marks the candidate bound (the un-rebound path keeps slot 0).
                if !else_branch.is_empty() {
                    for c in actives.iter_mut() {
                        if !c.bound
                            && bound_in_then.contains(&c.name)
                            && bound_in_else.contains(&c.name)
                        {
                            c.bound = true;
                        }
                    }
                }
            }

            // (4) Loops: a rebind inside a loop body is not guaranteed (the body
            //     may run zero times), so its binding side-effects are reverted; we
            //     still surface a write-through that hits slot 0 inside the loop.
            StmtKind::While { cond, body } | StmtKind::DoWhile { body, cond } => {
                report_write_throughs(cx, f, cond, actives, out);
                walk_subscope(cx, f, body, actives, out);
            }
            StmtKind::For { init, cond, step, body } => {
                // The for-init runs unconditionally once, so it binds normally.
                if let Some(init_s) = init {
                    walk(cx, f, std::slice::from_ref(init_s.as_ref()), actives, out);
                }
                if let Some(c) = cond {
                    report_write_throughs(cx, f, c, actives, out);
                }
                if let Some(st) = step {
                    report_write_throughs(cx, f, st, actives, out);
                }
                walk_subscope(cx, f, body, actives, out);
            }
            // A bare `{ … }` block runs unconditionally, so bindings inside it
            // carry forward; only its locally-declared candidates are scoped out.
            StmtKind::Block { stmts: body, .. } => {
                let base = actives.len();
                walk(cx, f, body, actives, out);
                actives.truncate(base);
            }
            // `try`/`catch`: the body and catch clauses are conditional sub-scopes.
            StmtKind::Try { expr, body, catches, .. } => {
                report_write_throughs(cx, f, expr, actives, out);
                walk_subscope(cx, f, body, actives, out);
                for cl in catches {
                    walk_subscope(cx, f, &cl.body, actives, out);
                }
            }

            // Other statement kinds may still contain a write-through expression
            // (e.g. `return f(x.field = v)` is unusual but possible) — scan any
            // expressions they expose, but do not bind through them.
            _ => {
                s.visit_exprs(&mut |e| report_write_throughs_shallow(cx, f, e, actives, out));
            }
        }
    }
}

/// Walk a **conditional** sub-scope (an `if` arm, loop body, or `try`/`catch`
/// body). Side-effects are isolated so the parent scope's binding state is
/// unchanged on exit: `bound` flags flipped *inside* the sub-scope are reverted
/// (a bind on one path does not bind the fall-through path) and candidates
/// *declared* inside the sub-scope are dropped. The `reported` dedupe latch is
/// preserved across the revert so a pointer is never double-reported.
fn walk_subscope<'a>(
    cx: &AnalysisContext,
    f: &'a Function,
    stmts: &'a [Stmt],
    actives: &mut Vec<Candidate<'a>>,
    out: &mut Vec<Finding>,
) {
    let base = actives.len();
    // Remember which pre-existing candidates were still unbound on entry.
    let pre_unbound: Vec<bool> = actives.iter().map(|c| !c.bound).collect();
    walk(cx, f, stmts, actives, out);
    // Drop candidates declared inside the sub-scope.
    actives.truncate(base);
    // Revert conditional binds: anything unbound on entry is unbound on exit. If
    // the sub-scope DID bind it, record that as a (path-only) partial bind so the
    // report can distinguish the conditional-bind variant from a never-bound one.
    for (c, was_unbound) in actives.iter_mut().zip(pre_unbound) {
        if was_unbound && c.bound {
            c.partial_bind = true;
            c.bound = false;
        }
    }
}

/// Mark candidate `name` as provably bound (an unconditional `name = <expr>`).
fn mark_bound(actives: &mut [Candidate<'_>], name: &str) {
    for c in actives.iter_mut() {
        if c.name == name {
            c.bound = true;
        }
    }
}

/// Names rebound (`name = <expr>`, target is the bare identifier) somewhere
/// directly inside this arm's statements. Used to decide post-`if` binding.
fn arm_rebinds(stmts: &[Stmt]) -> Vec<&str> {
    let mut names = Vec::new();
    for s in stmts {
        if let StmtKind::Expr(e) = &s.kind {
            if let Some(n) = rebind_target(e) {
                names.push(n);
            }
        }
    }
    names
}

// ------------------------------------------------------------ predicate helpers

/// If `e` is an assignment whose target is a **bare identifier** (`x = …`),
/// return that identifier — this is a *rebind* of a storage pointer to a new
/// slot, which makes it safe. A compound assign (`x += …`) to a bare pointer is
/// not a valid rebind (you cannot `+=` a storage reference), so only `=` counts.
fn rebind_target(e: &Expr) -> Option<&str> {
    if let ExprKind::Assign { op: AssignOp::Assign, target, .. } = &e.kind {
        if let ExprKind::Ident(n) = &target.kind {
            return Some(n);
        }
    }
    None
}

/// Recursively scan `e` for write-throughs to any still-unbound candidate and
/// emit a finding for each (once per candidate). A *write-through* is:
///   * `x.field = …` / `x[i] = …` (incl. compound assigns), or
///   * `delete x` / `delete x.field`, or
///   * `x.push(…)` / `x.pop()`.
fn report_write_throughs<'a>(
    cx: &AnalysisContext,
    f: &'a Function,
    e: &'a Expr,
    actives: &mut [Candidate<'a>],
    out: &mut Vec<Finding>,
) {
    e.visit(&mut |sub| report_write_throughs_shallow(cx, f, sub, actives, out));
}

/// The per-node body of [`report_write_throughs`] (operates on a single node so
/// it can also be used directly from a `visit_exprs` walk).
fn report_write_throughs_shallow<'a>(
    cx: &AnalysisContext,
    f: &'a Function,
    sub: &Expr,
    actives: &mut [Candidate<'a>],
    out: &mut Vec<Finding>,
) {
    if let Some(name) = write_through_target(sub) {
        for c in actives.iter_mut() {
            if c.name == name && !c.bound && !c.reported() {
                // The never-bound form is an unambiguous slot-0 clobber on every
                // path (highest confidence); the conditionally-bound form requires
                // the un-rebound branch to be taken, so it is a touch lower. Both
                // land a High label (single Invariant dimension needs conf ≥ ~0.77).
                let (conf, path_note) = if c.partial_bind {
                    (
                        0.78,
                        "on a branch where it was not (re)assigned, the pointer still aliases slot 0, so \
                         the write",
                    )
                } else {
                    (
                        0.82,
                        "the pointer is never bound to a slot, so every write through it",
                    )
                };
                let b = report!(UninitializedStoragePointerDetector, Category::UninitializedStoragePointer,
                    title = "Local `storage` pointer written through before it is bound to a slot",
                    severity = Severity::High,
                    confidence = conf,
                    dimensions = [Dimension::Invariant],
                    message = format!(
                        "`{}` declares the local `storage` pointer `{} storage {}` without binding it to a \
                         state slot, then writes through it (`{}…`). {} clobbers the contract's first \
                         state variable(s) (slot 0) instead of the intended target (SWC-109 / CWE-824).",
                        f.name, c.ty, c.name, c.name, path_note,
                    ),
                    recommendation =
                        "Bind the storage pointer to a concrete slot at declaration (`T storage x = \
                         arr[i];` / `= map[key];`) on every path before writing through it, or hoist \
                         the binding above the branch so no execution path leaves it pointing at slot 0.",
                );
                out.push(finish_at(cx, b, f.id, c.decl_span));
                c.mark_reported();
            }
        }
    }
}

/// If `sub` writes *through* a reference root (a member/element store, a `delete`,
/// or a `push`/`pop`), return the root identifier the write goes through. Plain
/// `x = …` (a rebind) is NOT a write-through and returns `None`.
fn write_through_target(sub: &Expr) -> Option<&str> {
    match &sub.kind {
        // `x.field = …`, `x[i] = …`, and their compound forms. The target must be
        // a member/index chain (NOT a bare ident — that is a rebind).
        ExprKind::Assign { target, .. } => match &target.kind {
            ExprKind::Member { .. } | ExprKind::Index { .. } => root_ident_str(target),
            _ => None,
        },
        // `delete x` / `delete x.field` mutates the pointed-at slot.
        ExprKind::Unary { op: UnOp::Delete, operand } => root_ident_str(operand),
        // `x.push(v)` / `x.pop()` — a mutating array method on the alias.
        ExprKind::Call(c) => {
            let m = c.func_name.as_deref()?;
            if matches!(m, "push" | "pop") {
                c.receiver.as_deref().and_then(root_ident_str)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Is this `VarDecl` a *storage-located reference* local? We recover the data
/// location from the declaration's source text (the normalized `ty` strips the
/// `storage`/`memory`/`calldata` keyword) and require a **reference** type — the
/// only kind that can legally carry a `storage` location: a struct, an array
/// (`T[]` / `T[k]`), or `bytes`/`string`. Value types and `mapping(...)` are
/// excluded.
fn is_storage_ref_decl(cx: &AnalysisContext, decl_span: Span, ty: &str) -> bool {
    // `source_text` is comment-stripped + lowercased, so a trailing `// storage`
    // comment cannot fake the location, and the keyword match is case-insensitive.
    let src = cx.source_text(decl_span);
    if !has_storage_location(&src) {
        return false;
    }
    is_reference_type(ty)
}

/// Does the (comment-stripped, lowercased) declaration text carry the `storage`
/// data-location keyword as a standalone word? Matches `t storage x` but not an
/// identifier that merely contains the substring (e.g. `storagefoo`).
fn has_storage_location(src_lower: &str) -> bool {
    src_lower.split(|c: char| !c.is_ascii_alphanumeric() && c != '_').any(|w| w == "storage")
}

/// A reference type that can take a `storage` data location: a struct (a bare
/// type identifier), an array (`…[]` / `…[k]`), or `bytes`/`string`. Excludes
/// elementary value types (which cannot be `storage` locals) and `mapping(...)`.
fn is_reference_type(ty: &str) -> bool {
    let t = ty.trim();
    if t.is_empty() {
        return false;
    }
    // Arrays are reference types regardless of element kind.
    if t.ends_with(']') {
        return true;
    }
    // `bytes` / `string` dynamic byte arrays are reference types; `bytesN` is a
    // value type.
    if t == "bytes" || t == "string" {
        return true;
    }
    // Mapping locals are out of the targeted struct/array class.
    if t.starts_with("mapping(") || t.starts_with("mapping ") {
        return false;
    }
    // Elementary value types never take a `storage` location, so any *remaining*
    // bare identifier is a user-defined struct (the case we target). Reject the
    // obvious value-type spellings defensively.
    !is_value_type(t)
}

/// Recognize the elementary value-type spellings (`uint`, `uint256`, `int8`,
/// `bool`, `address`, `address payable`, `bytes1`..`bytes32`, fixed-point).
fn is_value_type(t: &str) -> bool {
    if matches!(t, "bool" | "address" | "address payable" | "payable") {
        return true;
    }
    let num_suffix = |p: &str| -> bool {
        t.strip_prefix(p)
            .map(|rest| rest.is_empty() || rest.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or(false)
    };
    // uint / uintN / int / intN / bytesN (fixed) / fixed / ufixed
    num_suffix("uint") || num_suffix("int") || num_suffix("bytes") && t != "bytes"
        || t.starts_with("fixed")
        || t.starts_with("ufixed")
}

impl Candidate<'_> {
    fn reported(&self) -> bool {
        self.reported
    }
    fn mark_reported(&mut self) {
        self.reported = true;
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    use sluice_findings::Finding;

    fn findings(src: &str) -> Vec<Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default())
            .findings
            .into_iter()
            .filter(|f| f.detector == "uninitialized-storage-pointer")
            .collect()
    }
    fn fires(src: &str) -> bool {
        !findings(src).is_empty()
    }

    // VULN A — never-bound storage pointer written through: pure slot-0 clobber.
    const VULN_NEVER_BOUND: &str = r#"
pragma solidity ^0.8.20;
contract Auction {
    struct Bid { uint256 amount; address bidder; }
    mapping(uint256 => Bid) public bids;
    function place(uint256 id) external payable {
        Bid storage b;            // never bound -> slot 0
        b.amount = msg.value;     // clobbers `bids` mapping base slot
        b.bidder = msg.sender;
    }
}
"#;

    // VULN B — conditionally bound (only the `isNew` arm) then written through
    // unconditionally: the else path writes slot 0.
    const VULN_COND_BOUND: &str = r#"
pragma solidity ^0.8.20;
contract Ledger {
    struct Acct { uint256 bal; uint256 nonce; }
    mapping(address => Acct) accts;
    function credit(address who, bool isNew, uint256 amt) external {
        Acct storage a;
        if (isNew) {
            a = accts[who];       // bound only on the isNew path
        }
        a.bal += amt;             // else path -> slot 0 clobber
    }
}
"#;

    // SAFE 1 — bound at declaration (the canonical correct form).
    const SAFE_BOUND_AT_DECL: &str = r#"
pragma solidity ^0.8.20;
contract Ledger {
    struct Acct { uint256 bal; }
    mapping(address => Acct) accts;
    function credit(address who, uint256 amt) external {
        Acct storage a = accts[who];   // bound at decl
        a.bal += amt;
    }
}
"#;

    // SAFE 2 — the real Optimism `FaultDisputeGame.step` shape: declared unbound,
    // but rebound on BOTH arms of the if/else, and only READ afterwards.
    const SAFE_BOTH_ARMS_READ_ONLY: &str = r#"
pragma solidity ^0.8.20;
contract FaultDisputeGame {
    struct ClaimData { uint256 claim; uint256 position; address counteredBy; }
    ClaimData[] claimData;
    function step(uint256 i, bool isAttack) external view returns (bool) {
        ClaimData storage postState;
        if (isAttack) {
            postState = claimData[i];
        } else {
            postState = claimData[i + 1];
        }
        bool ok = postState.claim == 1;      // READ only — no write-through
        return ok && postState.position == 0;
    }
}
"#;

    // SAFE 3 — unconditionally rebound before the write-through (hoisted bind).
    const SAFE_REBOUND_BEFORE_WRITE: &str = r#"
pragma solidity ^0.8.20;
contract Ledger {
    struct Acct { uint256 bal; }
    mapping(address => Acct) accts;
    function credit(address who, uint256 amt) external {
        Acct storage a;
        a = accts[who];          // unconditional rebind before any write
        a.bal += amt;
    }
}
"#;

    // SAFE 4 — a `memory` (not storage) struct local is heap-allocated, never an
    // alias of slot 0; writing through it is fine.
    const SAFE_MEMORY_LOCAL: &str = r#"
pragma solidity ^0.8.20;
contract C {
    struct P { uint256 x; }
    function f() external pure returns (uint256) {
        P memory p;
        p.x = 7;                 // memory, not storage
        return p.x;
    }
}
"#;

    #[test]
    fn fires_on_never_bound_write_through() {
        assert!(fires(VULN_NEVER_BOUND), "never-bound storage pointer write-through must fire");
        let fs = findings(VULN_NEVER_BOUND);
        assert_eq!(fs.len(), 1, "exactly one finding (deduped): {:?}", fs);
        assert_eq!(fs[0].severity, sluice_findings::Severity::High);
    }

    #[test]
    fn fires_on_conditionally_bound_write_through() {
        assert!(fires(VULN_COND_BOUND), "one-armed bind + unconditional write-through must fire");
    }

    #[test]
    fn silent_when_bound_at_declaration() {
        assert!(!fires(SAFE_BOUND_AT_DECL));
    }

    #[test]
    fn silent_on_both_arms_read_only() {
        assert!(
            !fires(SAFE_BOTH_ARMS_READ_ONLY),
            "rebound on both arms + read-only (the Optimism FaultDisputeGame.step shape) must stay silent"
        );
    }

    #[test]
    fn silent_when_rebound_before_write() {
        assert!(!fires(SAFE_REBOUND_BEFORE_WRITE));
    }

    #[test]
    fn silent_on_memory_local() {
        assert!(!fires(SAFE_MEMORY_LOCAL));
    }

    // SAFE 5 — bound, then written through, *inside the same branch* (the bind
    // precedes the write on every path that reaches the write). Must stay silent:
    // within the branch the pointer is no longer slot 0 when written.
    const SAFE_BIND_THEN_WRITE_SAME_BRANCH: &str = r#"
pragma solidity ^0.8.20;
contract Ledger {
    struct Acct { uint256 bal; }
    mapping(address => Acct) accts;
    function credit(address who, bool isNew, uint256 amt) external {
        Acct storage a;
        if (isNew) {
            a = accts[who];   // bound first...
            a.bal += amt;     // ...then written through — safe within this arm
        }
    }
}
"#;

    // VULN C — array storage pointer, never bound, mutated via `.push` (a
    // write-through that grows the slot-0 array's length / data).
    const VULN_ARRAY_PUSH: &str = r#"
pragma solidity ^0.8.20;
contract Reg {
    struct Item { uint256 v; }
    Item[] public items;
    Item[] public shadow;
    function add(uint256 v) external {
        Item[] storage bucket;   // never bound -> slot 0
        bucket.push();           // grows slot-0 array
        bucket[0].v = v;
    }
}
"#;

    // VULN D — never-bound struct pointer cleared via `delete` (zeroes slot 0).
    const VULN_DELETE: &str = r#"
pragma solidity ^0.8.20;
contract C {
    struct S { uint256 a; uint256 b; }
    mapping(uint256 => S) data;
    function wipe(uint256 i) external {
        S storage s;     // never bound
        delete s;        // delete-through writes slot 0
    }
}
"#;

    // SAFE 6 — a `storagefoo`-named identifier must not be mistaken for the
    // `storage` data location (word-boundary match).
    const SAFE_LOOKS_LIKE_STORAGE: &str = r#"
pragma solidity ^0.8.20;
contract C {
    struct S { uint256 a; }
    function f() external pure returns (uint256) {
        S memory storagefoo;   // `storage` only as a substring of the name
        storagefoo.a = 3;
        return storagefoo.a;
    }
}
"#;

    #[test]
    fn silent_when_bound_then_written_in_same_branch() {
        assert!(
            !fires(SAFE_BIND_THEN_WRITE_SAME_BRANCH),
            "a bind that precedes the write-through on the same path is safe and must stay silent"
        );
    }

    #[test]
    fn fires_on_array_push_through_unbound() {
        assert!(fires(VULN_ARRAY_PUSH), "`.push` through a never-bound array storage pointer must fire");
    }

    #[test]
    fn fires_on_delete_through_unbound() {
        assert!(fires(VULN_DELETE), "`delete` of a never-bound storage pointer must fire");
    }

    #[test]
    fn silent_on_identifier_containing_storage() {
        assert!(
            !fires(SAFE_LOOKS_LIKE_STORAGE),
            "an identifier merely containing the substring `storage` must not trip the location check"
        );
    }
}
