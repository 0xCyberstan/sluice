//! Hash-gated struct replay — a queued-tuple is authenticated by a hash of the
//! whole struct, but the *world state that struct indexes* is read **live** after
//! the guard and drives a transfer/burn/mint, so a stale-then-restaked replay
//! moves value against the wrong (current) state.
//!
//! ## The shape
//!
//! A function takes a **`struct memory`** parameter `s` (a snapshot of a queued
//! action) and gates on membership/equality of a hash of that whole struct —
//! `mapping[keccak256(abi.encode(s))]` or `mapping[calculateRoot(s)]`. The hash
//! proves the *tuple was queued*. But **after the guard** the function reads a
//! field `s.f` and uses it to **index OTHER, live storage** (or to drive a live
//! membership / balance query — `isStakedTo(s.operator, s.vault)`,
//! `balanceOf(s.account)`, `totalAssets()`), and that live read decides a
//! **transfer / burn / mint / slash**. The struct is never re-bound to canonical
//! storage by an id, so the value moved is computed against *today's* world state,
//! not the state at queue time.
//!
//! Because the gate only authenticates that *this exact tuple was once queued*,
//! the same tuple can be replayed after the indexed world state has changed
//! (unstake → re-stake, balance moved, position re-opened): the hash still
//! matches, the guard still passes, and the live index now points at a different
//! amount/owner than was intended — a stale-snapshot replay that mis-moves value.
//!
//! This is the **Karak `SlasherLib.finalizeSlashing`** shape:
//!
//! ```solidity
//! function finalizeSlashing(CoreLib.Storage storage self, QueuedSlashing memory queuedSlashing) internal {
//!     bytes32 slashRoot = calculateRoot(queuedSlashing);              // keccak256(abi.encode(s))
//!     if (!self.slashingRequests[slashRoot]) revert InvalidSlashingParams();   // hash gate
//!     ...
//!     for (uint256 i = 0; i < queuedSlashing.vaults.length; i++) {
//!         if (!self.operatorState[queuedSlashing.operator].isVaultStakedToDSS(  // LIVE index by s.operator
//!                 queuedSlashing.dss, queuedSlashing.vaults[i])) { ... continue; }
//!         uint256 slashAmount = computeSlashAmount(queuedSlashing.vaults[i], ...);  // reads totalAssets() LIVE
//!         IKarakBaseVault(queuedSlashing.vaults[i]).slashAssets(slashAmount, ...);  // burn driven by live state
//!     }
//! }
//! ```
//!
//! The hash authenticates the queued tuple; `operatorState[operator]` /
//! `totalAssets()` are read live, so an operator who unstaked-then-restaked a
//! vault (or whose vault's `totalAssets` moved) is slashed against the *current*
//! balance for an *old* request.
//!
//! ## Precision anchors (all required)
//!
//!   * the gated value is a **hash of a whole `struct memory` parameter** — either
//!     `keccak256(abi.encode(s))` inline, or a local bound to that / to a
//!     `*[Rr]oot(s)` / `hash*(s)` helper of the single struct arg;
//!   * the guard is a `require`/`assert`/`if(!…)revert` whose condition indexes a
//!     mapping by that struct-hash (membership / equality of the queued tuple);
//!   * **after the guard**, a field `s.f` of that same struct either indexes a
//!     *different* live storage variable than the gated mapping, **or** is fed to a
//!     live membership/balance query (`isStakedTo` / `balanceOf` / `totalAssets` /
//!     …) — i.e. the snapshot's field selects live world state;
//!   * **after the guard**, a **transfer / burn / mint / slash**-shaped call runs
//!     (the value movement the live read drives).
//!
//! ## Suppression
//!
//!   * the struct is **re-bound to canonical storage** after the guard (an
//!     assignment whose target root is `s`, or a reload `x = someStorage[s.id]`
//!     that re-fetches the record by id) — then the live read *is* the authoritative
//!     state and there is no stale replay;
//!   * **no post-guard live-state index** drives value (the gate-then-`delete`-then
//!     -bookkeeping shape, e.g. `cancelSlashing`, which only clears the gated
//!     mapping and adjusts a counter — no transfer/burn keyed off a struct field
//!     through other storage);
//!   * the function takes no struct `memory` parameter, or the only indexed
//!     storage after the guard is the gated mapping itself.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{Builtin, CallKind, Expr, ExprKind, Function, Span, Stmt, StmtKind};

use super::prelude::*;

pub struct HashGatedStructReplayDetector;

impl Detector for HashGatedStructReplayDetector {
    fn id(&self) -> &'static str {
        "hash-gated-replay"
    }
    fn category(&self) -> Category {
        Category::HashGatedStructReplay
    }
    fn description(&self) -> &'static str {
        "A whole-struct hash gates a queued action, but a field of that snapshot indexes live world state \
         to drive a transfer/burn/mint without re-binding to canonical storage (stale-then-restaked replay; \
         Karak SlasherLib.finalizeSlashing class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // Need a concrete, state-mutating body: a view/pure helper or a bare
            // interface decl cannot move value off a live read.
            if !f.has_body || f.is_view_or_pure() {
                continue;
            }
            // Interfaces declare no logic.
            if let Some(c) = cx.contract_of(f.id) {
                if c.is_interface() {
                    continue;
                }
            }
            if let Some(hit) = analyze(f) {
                out.push(self.finding(cx, f, &hit));
            }
        }
        out
    }
}

impl HashGatedStructReplayDetector {
    fn finding(&self, cx: &AnalysisContext, f: &Function, hit: &Hit) -> Finding {
        let b = report!(self, Category::HashGatedStructReplay,
            title = "Whole-struct hash gates a queued action, then a snapshot field indexes live state to move value",
            severity = Severity::High,
            confidence = 0.55,
            dimensions = [Dimension::Invariant],
            message = format!(
                "`{fname}` gates on a hash of the entire `{sty}` snapshot `{s}` \
                 (`mapping[{hash}]` membership) — which only proves the tuple was *queued* — and then, \
                 after the guard, reads the snapshot field `{field}` to index live world state \
                 (`{live}`) that decides a value-moving call (`{mover}`). The struct is never re-bound to \
                 canonical storage by id, so the amount/owner is computed against *current* state rather \
                 than the state at queue time. An attacker who changes the indexed world state after \
                 queuing but before finalizing (e.g. unstake-then-restake, move a balance, re-open a \
                 position) keeps the hash — and therefore the guard — valid while the live read now points \
                 at a different amount/recipient: a stale-snapshot replay that mis-moves value. This is the \
                 Karak `SlasherLib.finalizeSlashing` hash-gated-struct-replay class \
                 (`if (!self.slashingRequests[calculateRoot(s)]) revert;` then \
                 `self.operatorState[s.operator].isVaultStakedToDSS(...)` / `totalAssets()` driving \
                 `slashAssets`).",
                fname = f.name,
                sty = hit.struct_ty,
                s = hit.struct_param,
                hash = hit.hash_desc,
                field = hit.live_field,
                live = hit.live_desc,
                mover = hit.mover_desc,
            ),
            recommendation =
                "Bind the action to the live state it will act on, not just to the tuple's hash. Either \
                 re-load the authoritative record from canonical storage by a stable id at finalize time \
                 (and recompute amounts from that), or snapshot the *resolved* values (the exact owner, \
                 vault, and amount) into the queue and pay out those stored values rather than re-deriving \
                 them from live `balanceOf` / `totalAssets` / membership reads. Equivalently, invalidate \
                 the queued hash whenever the indexed world state changes (bump a per-account nonce into \
                 the hashed struct), so a stale snapshot can no longer pass the gate.",
        );
        finish_at(cx, b, f.id, hit.span)
    }
}

// --------------------------------------------------------------------- analysis

/// A matched hash-gated replay in one function.
struct Hit {
    /// The struct `memory` parameter name (`queuedSlashing`).
    struct_param: String,
    /// Its declared (struct) type (`QueuedSlashing`).
    struct_ty: String,
    /// Human description of the gated hash (`keccak256(abi.encode(s))` / `calculateRoot(s)`).
    hash_desc: String,
    /// The struct field read live after the guard (`operator`).
    live_field: String,
    /// Description of the live-state index/query (`operatorState[s.operator]` / `isVaultStakedToDSS(...)`).
    live_desc: String,
    /// Description of the value-moving call (`slashAssets` / `transfer` / `burn` / …).
    mover_desc: String,
    /// Report location (the guard).
    span: Span,
}

/// The hash gate: which mapping is indexed, by what struct-hash, and where the
/// guard sits (so we can scope "after the guard" by source position).
struct HashGate {
    /// Storage variable indexed by the struct hash (`slashingRequests`).
    gated_var: String,
    /// Human description of the hash key.
    hash_desc: String,
    /// Start source position of the guard statement.
    guard_start: u32,
    /// End source position of the guard statement — "after the guard" means a span
    /// at or past this, so a call nested *inside* the guard (e.g. the revert-error
    /// argument of `require(mapping[h], NotQueued())`) does not count as post-guard.
    guard_end: u32,
    guard_file: u32,
}

fn analyze(f: &Function) -> Option<Hit> {
    // (1) The struct `memory` parameter(s) — there must be at least one.
    let struct_params = struct_memory_params(f);
    if struct_params.is_empty() {
        return None;
    }

    for (sparam, sty) in &struct_params {
        // Names that *are* the hash of this whole struct: the struct itself fed to
        // keccak256(abi.encode(·)) inline, or a local bound to that / to a
        // `*root(s)` / `hash*(s)` helper of the single struct arg.
        let hash_roots = hash_root_names(f, sparam);

        // (2) The hash gate: a require/assert/if-revert indexing a mapping by one
        // of those hash names.
        let Some(gate) = find_hash_gate(f, &hash_roots) else {
            continue;
        };

        // (3) SUPPRESS: the struct (or a record reloaded by id) is re-bound to
        // canonical storage after the guard — then the live read is authoritative.
        if rebinds_from_storage(f, sparam, &gate) {
            continue;
        }

        // (4) After the guard: a value-moving call must run.
        let Some(mover_desc) = post_guard_value_mover(f, &gate) else {
            continue;
        };

        // (5) After the guard: a field of the snapshot must index *other* live
        // storage, or feed a live membership/balance query — the stale index.
        let Some((live_field, live_desc)) = post_guard_live_index(f, sparam, &gate) else {
            continue;
        };

        return Some(Hit {
            struct_param: sparam.clone(),
            struct_ty: sty.clone(),
            hash_desc: gate.hash_desc.clone(),
            live_field,
            live_desc,
            mover_desc,
            span: Span { file: gate.guard_file, start: gate.guard_start, end: gate.guard_start },
        });
    }
    None
}

// --------------------------------------------------- (1) struct memory params

/// Parameters declared `memory` whose type is a user **struct** (best-effort:
/// capitalized, not a primitive / `bytes*` / `string`, and not an array or
/// mapping). Returns `(name, type)`.
fn struct_memory_params(f: &Function) -> Vec<(String, String)> {
    f.params
        .iter()
        .filter_map(|p| {
            let name = p.name.as_deref()?;
            if p.location.as_deref() != Some("memory") {
                return None;
            }
            if !is_struct_type(&p.ty) {
                return None;
            }
            Some((name.to_string(), struct_type_name(&p.ty)))
        })
        .collect()
}

/// Heuristic: is `ty` a user-defined struct type (the thing whose hash is a tuple
/// commitment)? Exclude primitives, `bytes`/`string`, arrays (`[]`), and mappings.
/// A qualified type (`CoreLib.Storage`, `SlasherLib.QueuedSlashing`) is judged by
/// its last segment.
fn is_struct_type(ty: &str) -> bool {
    let t = ty.trim();
    if t.contains('[') || t.contains("mapping") {
        return false;
    }
    let last = t.rsplit('.').next().unwrap_or(t).trim();
    let Some(first) = last.chars().next() else { return false };
    if !first.is_ascii_uppercase() {
        return false;
    }
    // Exclude common non-struct capitalized-ish forms / value types.
    const NON_STRUCT: &[&str] = &[
        "bytes", "string", "uint", "int", "address", "bool", "bytes32", "bytes4",
    ];
    let ll = last.to_ascii_lowercase();
    if NON_STRUCT.iter().any(|n| ll == *n) {
        return false;
    }
    // An interface handle (`IERC20`) is not a memory struct; memory location on a
    // capitalized type that *is* `memory` is almost always a struct, but guard the
    // `I<Upper>` interface-naming convention out anyway.
    if last.len() >= 2 {
        let mut ch = last.chars();
        if ch.next() == Some('I') && ch.next().is_some_and(|c| c.is_ascii_uppercase()) {
            return false;
        }
    }
    true
}

/// Last path segment of a (possibly qualified) type name.
fn struct_type_name(ty: &str) -> String {
    ty.trim().rsplit('.').next().unwrap_or(ty).trim().to_string()
}

// ----------------------------------------------- hash-of-struct name discovery

/// The set of identifier names that denote *the hash of the whole struct* `s`:
/// always nothing-but-the-derived-locals (the struct itself is matched separately
/// inside [`expr_is_struct_hash`]). We collect locals `x` declared/assigned as
/// `x = keccak256(abi.encode(s))` or `x = calculateRoot(s)` (any `*root`/`hash*`
/// helper taking the single struct arg).
fn hash_root_names(f: &Function, sparam: &str) -> Vec<String> {
    let mut names = Vec::new();
    for top in &f.body {
        top.visit(&mut |st| match &st.kind {
            StmtKind::VarDecl { name: Some(n), init: Some(e), .. } => {
                if expr_is_struct_hash(e, sparam) {
                    names.push(n.clone());
                }
            }
            StmtKind::Expr(e) => {
                if let ExprKind::Assign { target, value, .. } = &e.kind {
                    if let Some(t) = root_ident(target) {
                        if expr_is_struct_hash(value, sparam) {
                            names.push(t);
                        }
                    }
                }
            }
            _ => {}
        });
    }
    names.sort();
    names.dedup();
    names
}

/// Is `e` a hash of the *whole* struct `sparam`? Recognizes:
///   * `keccak256(abi.encode(sparam))` (or `abi.encodePacked`), possibly nested;
///   * a call to a `*[Rr]oot` / `hash*` / `*hash` helper whose single argument
///     root-resolves to `sparam` (the `calculateRoot(queuedSlashing)` idiom).
fn expr_is_struct_hash(e: &Expr, sparam: &str) -> bool {
    match &e.kind {
        ExprKind::Call(c) => {
            // keccak256(abi.encode(s)) / keccak256(abi.encodePacked(s))
            if matches!(c.kind, CallKind::Builtin(Builtin::Keccak256)) {
                return c.args.iter().any(|a| arg_is_abi_encode_of(a, sparam));
            }
            // calculateRoot(s) / hashStruct(s) / <x>Root(s)
            if let Some(name) = c.func_name.as_deref() {
                if is_root_helper_name(name) && c.args.len() == 1 {
                    if root_ident_str(&c.args[0]) == Some(sparam) {
                        return true;
                    }
                }
            }
            // Descend (e.g. keccak256(abi.encode(s)) wrapped in a cast).
            c.args.iter().any(|a| expr_is_struct_hash(a, sparam))
        }
        _ => false,
    }
}

/// Is `a` an `abi.encode(s)` / `abi.encodePacked(s, …)` whose payload mentions the
/// whole struct `sparam` (as a bare argument, not just a field)?
fn arg_is_abi_encode_of(a: &Expr, sparam: &str) -> bool {
    let ExprKind::Call(c) = &a.kind else { return false };
    if !matches!(
        c.kind,
        CallKind::Builtin(Builtin::AbiEncode) | CallKind::Builtin(Builtin::AbiEncodePacked)
    ) {
        return false;
    }
    // The struct must be passed *whole* (a bare `s` argument), which is what makes
    // the hash a commitment to the entire tuple.
    c.args.iter().any(|arg| matches!(&arg.kind, ExprKind::Ident(n) if n == sparam))
}

/// Helper-name heuristic for a struct-hash function: ends in `root`, or contains
/// `hash`/`digest`, or is a `calculate*`/`compute*` that we treat as a hash when
/// it takes the lone struct (callers gate the result anyway).
fn is_root_helper_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.ends_with("root") || l.contains("hash") || l.contains("digest")
}

// ------------------------------------------------------------- (2) hash gate

/// Find a guard — `require(...)` / `assert(...)` / `if (...) revert` — whose
/// condition indexes a mapping by one of the struct-hash names (or by an inline
/// `keccak256(abi.encode(s))`). Returns the gated storage var + the guard position.
fn find_hash_gate(f: &Function, hash_roots: &[String]) -> Option<HashGate> {
    let mut found: Option<HashGate> = None;
    for top in &f.body {
        top.visit(&mut |st| {
            if found.is_some() {
                return;
            }
            match &st.kind {
                // `if (!mapping[key]) revert;`  /  `if (mapping[key] != ...) revert;`
                StmtKind::If { cond, then_branch, else_branch, .. } => {
                    if branch_reverts(then_branch) || branch_reverts(else_branch) {
                        if let Some(g) = gate_from_cond(cond, hash_roots, st.span) {
                            found = Some(g);
                        }
                    }
                }
                // `require(mapping[key], ...)` / `assert(mapping[key])`
                StmtKind::Expr(e) => {
                    if let ExprKind::Call(c) = &e.kind {
                        if is_require_or_assert(c) {
                            for a in &c.args {
                                if let Some(g) = gate_from_cond(a, hash_roots, st.span) {
                                    found = Some(g);
                                    break;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// Does a branch body contain a `revert`/`require(false)`-style abort? (used to
/// confirm an `if (...) { revert; }` is a guard).
fn branch_reverts(branch: &[Stmt]) -> bool {
    branch.iter().any(|s| {
        let mut reverts = false;
        s.visit(&mut |st| match &st.kind {
            StmtKind::Revert { .. } => reverts = true,
            StmtKind::Expr(e) => {
                if let ExprKind::Call(c) = &e.kind {
                    if matches!(c.kind, CallKind::Builtin(Builtin::Revert)) {
                        reverts = true;
                    }
                }
            }
            _ => {}
        });
        reverts
    })
}

/// If `cond` contains an indexed mapping access `mapping[key]` where `key` is a
/// struct-hash (a hash-root local, or an inline `keccak256(abi.encode(s))`),
/// return the gate. The indexed *storage var* (member or ident under the `Index`)
/// is what we record as the gated mapping.
fn gate_from_cond(cond: &Expr, hash_roots: &[String], guard_span: Span) -> Option<HashGate> {
    let mut hit: Option<HashGate> = None;
    cond.visit(&mut |sub| {
        if hit.is_some() {
            return;
        }
        let ExprKind::Index { base, index: Some(idx) } = &sub.kind else {
            return;
        };
        // The index key must be a struct-hash.
        let (is_hash, desc) = index_is_struct_hash(idx, hash_roots);
        if !is_hash {
            return;
        }
        // The gated storage var is the var immediately indexed.
        let Some(var) = indexed_storage_var(base) else { return };
        hit = Some(HashGate {
            gated_var: var,
            hash_desc: desc,
            guard_start: guard_span.start,
            guard_end: guard_span.end,
            guard_file: guard_span.file,
        });
    });
    hit
}

/// Is the index expression a struct-hash? Either a bare identifier that is one of
/// the hash-root locals, or an inline `keccak256(abi.encode(s))`. Returns a flag
/// and a human description.
fn index_is_struct_hash(idx: &Expr, hash_roots: &[String]) -> (bool, String) {
    if let ExprKind::Ident(n) = &idx.kind {
        if hash_roots.iter().any(|h| h == n) {
            return (true, n.clone());
        }
    }
    // Inline keccak256(abi.encode(s)) — only when there is at least one struct arg.
    if let ExprKind::Call(c) = &idx.kind {
        if matches!(c.kind, CallKind::Builtin(Builtin::Keccak256)) {
            // Any abi.encode(<ident>) payload qualifies as a whole-struct hash key.
            let has_struct = c.args.iter().any(|a| {
                if let ExprKind::Call(cc) = &a.kind {
                    matches!(
                        cc.kind,
                        CallKind::Builtin(Builtin::AbiEncode) | CallKind::Builtin(Builtin::AbiEncodePacked)
                    ) && cc.args.iter().any(|x| matches!(&x.kind, ExprKind::Ident(_)))
                } else {
                    false
                }
            });
            if has_struct {
                return (true, "keccak256(abi.encode(...))".to_string());
            }
        }
    }
    (false, String::new())
}

/// The storage variable immediately under an `Index` base: for `self.foo[k]` →
/// `foo`; for `foo[k]` → `foo`; for `self.foo[a][b]` (nested) the inner base is
/// itself an `Index`, so we descend to the var being indexed at this level.
fn indexed_storage_var(base: &Expr) -> Option<String> {
    match &base.kind {
        ExprKind::Member { member, .. } => Some(member.clone()),
        ExprKind::Ident(n) => Some(n.clone()),
        // `foo[a][b]`: this level's base is `foo[a]` (an Index) — resolve the var
        // being indexed (the member/ident at the innermost base).
        ExprKind::Index { base, .. } => indexed_storage_var(base),
        _ => None,
    }
}

// ------------------------------------------------- (3) canonical-rebind suppress

/// SUPPRESS gate: after the guard, the snapshot is re-bound to canonical storage
/// — either the struct param `s` itself is assigned to (`s = …` / `s.f = …`), or a
/// local is loaded from a storage mapping keyed by a *field of `s`* (`x =
/// store[s.id]`), i.e. the function re-fetches the authoritative record by id. In
/// either case the live read is the canonical state and there is no stale replay.
fn rebinds_from_storage(f: &Function, sparam: &str, gate: &HashGate) -> bool {
    let mut rebinds = false;
    for top in &f.body {
        top.visit(&mut |st| {
            if rebinds {
                return;
            }
            if !after_gate(st.span, gate) {
                return;
            }
            match &st.kind {
                // `s = …` or `s.field = …` — the snapshot is overwritten in place.
                StmtKind::Expr(e) => {
                    if let ExprKind::Assign { target, .. } = &e.kind {
                        if root_ident_str(target) == Some(sparam) {
                            rebinds = true;
                        }
                    }
                }
                // `Foo memory x = store[s.id];` — the *whole record* reloaded by an
                // id field. Only a STRUCT-typed reload keyed by an id-like field is
                // a canonical rebind; a scalar load `uint256 amt = bal[s.account]`
                // is the *stale live index* we want to flag, not a rebind.
                StmtKind::VarDecl { ty, init: Some(e), .. } => {
                    if is_struct_type(ty) && reloads_record_by_id(e, sparam) {
                        rebinds = true;
                    }
                }
                _ => {}
            }
        });
        if rebinds {
            break;
        }
    }
    rebinds
}

/// Is `e` a load of a storage record keyed by an **id-like** field of the snapshot
/// — `store[s.id]` / `store[s.requestId]` (an `Index` whose key is `s.<idField>`)?
/// Such a reload, into a struct local, re-binds to canonical state. We require the
/// key field to look like an id (not an arbitrary address/owner field) so that a
/// scalar balance read by `s.account` is not mistaken for a rebind.
fn reloads_record_by_id(e: &Expr, sparam: &str) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Index { index: Some(idx), .. } = &sub.kind {
            // key is `s.<field>` (a member rooted at the struct) with an id-like name
            if let ExprKind::Member { base, member } = &idx.kind {
                if root_ident_str(base) == Some(sparam) && is_id_like_field(member) {
                    found = true;
                }
            }
        }
    });
    found
}

/// Does a field name look like a stable record identifier (`id`, `requestId`,
/// `nonce`, `key`, `hash`, `index`)? Used to confirm a struct reload is a
/// canonical by-id fetch rather than a by-owner live read.
fn is_id_like_field(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "id"
        || l.ends_with("id")
        || l.ends_with("index")
        || l.ends_with("nonce")
        || l == "key"
        || l.ends_with("key")
        || l.ends_with("hash")
        || l.ends_with("root")
}

// ------------------------------------------------ (4) post-guard value mover

/// After the guard, does a **value-moving** call run — a transfer / burn / mint /
/// slash / withdraw / redeem-shaped method, or a native-value send? Returns a
/// description of the first such call.
fn post_guard_value_mover(f: &Function, gate: &HashGate) -> Option<String> {
    let mut desc: Option<String> = None;
    for top in &f.body {
        top.visit_exprs(&mut |e| {
            if desc.is_some() {
                return;
            }
            if !after_gate(e.span, gate) {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            // A native-value send is always a value move.
            let sends_value = c.value.is_some()
                || matches!(c.kind, CallKind::Transfer | CallKind::Send);
            if sends_value {
                desc = Some(c.func_name.clone().unwrap_or_else(|| "value send".into()));
                return;
            }
            // A name-matched mover must be an *invocation that moves value* — a
            // method/external/internal call — not a `revert Error()` / require-error
            // argument. Error constructors parse as calls too, so we additionally
            // reject error-style names (see `is_value_mover_name`).
            if !matches!(
                c.kind,
                CallKind::External | CallKind::LowLevelCall | CallKind::DelegateCall | CallKind::Internal
            ) {
                return;
            }
            if let Some(name) = c.func_name.as_deref() {
                if is_value_mover_name(name) {
                    desc = Some(name.to_string());
                }
            }
        });
        if desc.is_some() {
            break;
        }
    }
    desc
}

/// Method names that move value: token transfers, mint/burn, slash, withdraw,
/// redeem, seize. Deliberately a value-movement vocabulary (not generic verbs) so
/// the post-guard anchor stays a real disbursement, not bookkeeping.
///
/// Matching is **camelCase-boundary aware** to avoid swallowing revert-error
/// identifiers that merely begin with a verb: `withdrawSharesAsTokens` matches the
/// `withdraw` verb (next char is upper-case `S`), but `WithdrawalDelayNotElapsed` /
/// `WithdrawalNotQueued` do not (the verb is followed by lower-case `al`, and they
/// carry error tokens). A short denylist of error tokens is the backstop.
fn is_value_mover_name(name: &str) -> bool {
    // Reject obvious error/condition identifiers (revert reasons).
    let l = name.to_ascii_lowercase();
    const ERROR_TOKENS: &[&str] = &[
        "notqueued", "notelapsed", "notcaller", "mismatch", "invalid", "exceed",
        "breached", "zero", "empty", "duplicate", "already", "notpassed", "notstaked",
    ];
    if ERROR_TOKENS.iter().any(|t| l.contains(t)) {
        return false;
    }

    const MOVERS: &[&str] = &[
        "slash", "burn", "mint", "transfer", "withdraw", "redeem", "seize", "pay",
        "sweep", "release", "settle", "disburse", "payout", "claim",
    ];
    for m in MOVERS {
        // exact method name (`transfer`, `burn`, `slash`)
        if l == *m {
            return true;
        }
        // camelCase method (`slashAssets`, `withdrawSharesAsTokens`,
        // `safeTransferFrom` via the `transfer` token, `transferFrom`): the verb is
        // a prefix of the lowercased name AND, in the ORIGINAL name, the character
        // right after the verb is an upper-case letter — a real word boundary, not
        // a continuation like `withdrawal`.
        if let Some(rest) = l.strip_prefix(m) {
            if rest.is_empty() {
                return true;
            }
            // index of the boundary char in the original (same length, ASCII verbs)
            let boundary = name.as_bytes().get(m.len()).copied();
            if boundary.is_some_and(|b| b.is_ascii_uppercase()) {
                return true;
            }
        }
        // suffix method (`safeTransfer`, `_burn`, `_mint`, `safeTransferFrom`): the
        // verb appears at a boundary preceded by an upper-case or `_`.
        if let Some(pos) = l.rfind(m) {
            if pos > 0 {
                let before = name.as_bytes()[pos - 1];
                let ends_at_verb = pos + m.len() == l.len();
                if (before.is_ascii_uppercase() || before == b'_') && ends_at_verb {
                    return true;
                }
            }
        }
    }
    false
}

// ----------------------------------------- (5) post-guard live-state index

/// After the guard, is a field `s.f` of the snapshot used to index *other* live
/// storage (a different var than the gated mapping), or fed to a live
/// membership/balance query? Returns `(field, description)`.
///
/// Two recognized forms:
///   1. `otherStore[s.field]` — a storage var (≠ gated mapping) indexed by a
///      snapshot field (`operatorState[queuedSlashing.operator]`);
///   2. `liveQuery(…, s.field, …)` — a membership/balance/supply read whose name
///      is in [`is_live_query_name`] taking a snapshot field as an argument
///      (`isVaultStakedToDSS(s.dss, s.vaults[i])`, `balanceOf(s.account)`), or a
///      zero-arg pool read (`totalAssets()` / `totalSupply()`) reached on a
///      receiver indexed by a snapshot field.
fn post_guard_live_index(f: &Function, sparam: &str, gate: &HashGate) -> Option<(String, String)> {
    let mut hit: Option<(String, String)> = None;
    for top in &f.body {
        top.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            if !after_gate(e.span, gate) {
                return;
            }
            // Form 1: an Index `otherStore[s.field]` where otherStore != gated var.
            if let ExprKind::Index { base, index: Some(idx) } = &e.kind {
                if let Some(field) = struct_field_of(idx, sparam) {
                    if let Some(var) = indexed_storage_var(base) {
                        if var != gate.gated_var {
                            hit = Some((field.clone(), format!("{var}[{sparam}.{field}]")));
                            return;
                        }
                    }
                }
            }
            // Form 2: a live membership/balance query taking a snapshot field.
            if let ExprKind::Call(c) = &e.kind {
                if let Some(name) = c.func_name.as_deref() {
                    if is_live_query_name(name) {
                        // an argument is `s.field`
                        if let Some(field) = c.args.iter().find_map(|a| struct_field_in(a, sparam)) {
                            hit = Some((field.clone(), format!("{name}(… {sparam}.{field} …)")));
                            return;
                        }
                        // or the receiver is indexed by a snapshot field
                        if let Some(recv) = &c.receiver {
                            if let Some(field) = receiver_indexed_by_field(recv, sparam) {
                                hit = Some((field.clone(), format!("{sparam}.{field}-indexed {name}(...)")));
                            }
                        }
                    }
                }
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// If `idx` is exactly a field of the snapshot (`s.field` or `s.field[i]`),
/// return the field name.
fn struct_field_of(idx: &Expr, sparam: &str) -> Option<String> {
    match &idx.kind {
        ExprKind::Member { base, member } if root_ident_str(base) == Some(sparam) => {
            // direct `s.member`
            if matches!(&base.kind, ExprKind::Ident(n) if n == sparam) {
                Some(member.clone())
            } else {
                Some(member.clone())
            }
        }
        // `s.field[i]` — the index base is `s.field`.
        ExprKind::Index { base, .. } => struct_field_of_member(base, sparam),
        _ => None,
    }
}

/// `s.field` (a Member rooted at the struct) → field name.
fn struct_field_of_member(e: &Expr, sparam: &str) -> Option<String> {
    if let ExprKind::Member { base, member } = &e.kind {
        if root_ident_str(base) == Some(sparam) {
            return Some(member.clone());
        }
    }
    None
}

/// Find a snapshot-field reference `s.field` anywhere inside `e` (used to test a
/// call argument that may be `s.dss`, `s.vaults[i]`, `s.account`, …).
fn struct_field_in(e: &Expr, sparam: &str) -> Option<String> {
    let mut found: Option<String> = None;
    e.visit(&mut |sub| {
        if found.is_some() {
            return;
        }
        if let ExprKind::Member { base, member } = &sub.kind {
            if root_ident_str(base) == Some(sparam) {
                found = Some(member.clone());
            }
        }
    });
    found
}

/// If a call receiver is a storage access indexed by a snapshot field
/// (`self.operatorState[s.operator]`), return that field name.
fn receiver_indexed_by_field(recv: &Expr, sparam: &str) -> Option<String> {
    let mut found: Option<String> = None;
    recv.visit(&mut |sub| {
        if found.is_some() {
            return;
        }
        if let ExprKind::Index { index: Some(idx), .. } = &sub.kind {
            if let ExprKind::Member { base, member } = &idx.kind {
                if root_ident_str(base) == Some(sparam) {
                    found = Some(member.clone());
                }
            }
        }
    });
    found
}

/// Names of **live world-state queries** whose result depends on *current* state:
/// staking membership, balances, pool totals, ownership. A snapshot field feeding
/// one of these is reading today's world, not the queue-time world.
fn is_live_query_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    const QUERIES: &[&str] = &[
        "isstakedto", "isvaultstakedtodss", "stakedto", "isstaked", "isvaultstaked",
        "balanceof", "totalassets", "totalsupply", "sharesof", "balanceofunderlying",
        "convertto", "previewredeem", "previewwithdraw", "getstake", "stakeof",
        "ownerof", "totaldebt", "totalcollateral", "assetsof",
    ];
    QUERIES.iter().any(|q| l == *q || l.contains(q))
}

// ------------------------------------------------------------------- ordering

/// Is `span` past the *end* of the guard statement, in the same file? (source-
/// position scoping, the same lexical "after" used by the snapshot-redeem
/// detector). We compare against the guard's **end** so a call nested inside the
/// guard — e.g. the revert-error argument `NotQueued()` of
/// `require(mapping[h], NotQueued())` — is not mistaken for post-guard logic.
fn after_gate(span: Span, gate: &HashGate) -> bool {
    span.file == gate.guard_file && span.start >= gate.guard_end
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "hash-gated-replay")
    }

    // VULN — the Karak `finalizeSlashing` shape, reduced: a whole-struct hash
    // (`calculateRoot` = keccak256(abi.encode(s))) gates membership in
    // `slashingRequests`, then a snapshot field (`s.operator`) indexes the LIVE
    // `operatorState` mapping to decide a `slashAssets` burn — with no rebind.
    const VULN: &str = r#"
        pragma solidity ^0.8.25;
        interface IVault { function totalAssets() external view returns (uint256); function slashAssets(uint256 a, address h) external; }
        contract Slasher {
            struct QueuedSlashing { address operator; address dss; address[] vaults; uint96 timestamp; }
            mapping(bytes32 => bool) public slashingRequests;
            mapping(address => mapping(address => bool)) public operatorState; // operator => vault => staked (LIVE)
            mapping(address => address) public handler;
            function calculateRoot(QueuedSlashing memory q) internal pure returns (bytes32) {
                return keccak256(abi.encode(q));
            }
            function isVaultStakedToDSS(address operator, address dss, address vault) internal view returns (bool) {
                return operatorState[operator][vault];
            }
            function computeSlashAmount(address vault) internal view returns (uint256) {
                return IVault(vault).totalAssets() / 10;
            }
            function finalizeSlashing(QueuedSlashing memory queuedSlashing) external {
                bytes32 slashRoot = calculateRoot(queuedSlashing);
                if (!slashingRequests[slashRoot]) revert();
                delete slashingRequests[slashRoot];
                for (uint256 i = 0; i < queuedSlashing.vaults.length; i++) {
                    if (!isVaultStakedToDSS(queuedSlashing.operator, queuedSlashing.dss, queuedSlashing.vaults[i])) {
                        continue;
                    }
                    uint256 slashAmount = computeSlashAmount(queuedSlashing.vaults[i]);
                    IVault(queuedSlashing.vaults[i]).slashAssets(slashAmount, handler[queuedSlashing.vaults[i]]);
                }
            }
        }
    "#;

    // VULN (inline keccak + balanceOf form): the gate is an inline
    // `mapping[keccak256(abi.encode(req))]` require, and after it a snapshot field
    // `req.account` indexes the live `stakedBalance` mapping to size a transfer.
    const VULN_INLINE: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract Payouts {
            struct Claim { address account; address token; uint256 nonce; }
            mapping(bytes32 => bool) public queued;
            mapping(address => uint256) public stakedBalance; // LIVE
            function finalize(Claim memory req) external {
                require(queued[keccak256(abi.encode(req))], "not queued");
                delete queued[keccak256(abi.encode(req))];
                uint256 amt = stakedBalance[req.account];
                IERC20(req.token).transfer(req.account, amt);
            }
        }
    "#;

    // SAFE (cancelSlashing shape): identical hash gate on a whole-struct hash, but
    // after the guard it ONLY deletes the gated mapping and adjusts a counter —
    // there is no transfer/burn keyed off a snapshot field through other live
    // storage. No value mover + no live index ⇒ silent.
    const SAFE_CANCEL: &str = r#"
        pragma solidity ^0.8.25;
        contract Slasher {
            struct QueuedSlashing { address operator; address dss; address[] vaults; uint96 timestamp; }
            mapping(bytes32 => bool) public slashingRequests;
            mapping(address => uint256) public queuedCount;
            function calculateRoot(QueuedSlashing memory q) internal pure returns (bytes32) {
                return keccak256(abi.encode(q));
            }
            function adjustQueuedSlashingCount(address[] memory vaults, bool add) internal {
                for (uint256 i = 0; i < vaults.length; i++) {
                    if (add) queuedCount[vaults[i]] += 1; else queuedCount[vaults[i]] -= 1;
                }
            }
            function cancelSlashing(QueuedSlashing memory queuedSlashing) external {
                bytes32 slashRoot = calculateRoot(queuedSlashing);
                if (!slashingRequests[slashRoot]) revert();
                delete slashingRequests[slashRoot];
                adjustQueuedSlashingCount(queuedSlashing.vaults, false);
            }
        }
    "#;

    // SAFE (canonical rebind): the hash gate passes, but the function then RELOADS
    // the authoritative record from storage by an id field (`positions[req.id]`)
    // and pays from that — the live read IS canonical, so no stale-snapshot replay.
    const SAFE_REBIND: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract Payouts {
            struct Claim { uint256 id; address token; }
            struct Position { address account; uint256 amount; }
            mapping(bytes32 => bool) public queued;
            mapping(uint256 => Position) public positions; // canonical store keyed by id
            function finalize(Claim memory req) external {
                require(queued[keccak256(abi.encode(req))], "not queued");
                Position memory p = positions[req.id];          // reload by id (rebind)
                IERC20(req.token).transfer(p.account, p.amount);
            }
        }
    "#;

    // SAFE (snapshot pays stored values): no live world-state index — the function
    // pays out the amount/recipient carried *in the struct itself*, so there is
    // nothing stale to replay against.
    const SAFE_STORED_VALUES: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract Payouts {
            struct Claim { address account; address token; uint256 amount; }
            mapping(bytes32 => bool) public queued;
            function finalize(Claim memory req) external {
                require(queued[keccak256(abi.encode(req))], "not queued");
                delete queued[keccak256(abi.encode(req))];
                IERC20(req.token).transfer(req.account, req.amount);
            }
        }
    "#;

    // SAFE (no hash gate): a struct memory param drives a live-indexed transfer,
    // but the function is gated by a plain id check, not a whole-struct hash —
    // outside the class.
    const SAFE_NO_HASH: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract Payouts {
            struct Claim { address account; address token; uint256 nonce; }
            mapping(uint256 => bool) public usedNonce;
            mapping(address => uint256) public stakedBalance;
            function finalize(Claim memory req) external {
                require(!usedNonce[req.nonce], "used");
                usedNonce[req.nonce] = true;
                uint256 amt = stakedBalance[req.account];
                IERC20(req.token).transfer(req.account, amt);
            }
        }
    "#;

    // VULN (the EigenLayer `_completeQueuedWithdrawal` real-world shape, reduced):
    // a whole-`Withdrawal`-struct hash gates `pendingWithdrawals` membership; after
    // the guard a snapshot field (`withdrawal.staker`) indexes the LIVE `delegatedTo`
    // mapping to pick the *current* operator, and `withdrawSharesAsTokens` moves
    // value — with no rebind of the struct. A staker who re-delegated after queuing
    // keeps the hash valid while the live read points at a new operator. Note the
    // post-guard `require(..., WithdrawalDelayNotElapsed())`: the error name begins
    // with the `withdraw` verb but must NOT be mistaken for the value mover.
    const VULN_EIGEN: &str = r#"
        pragma solidity ^0.8.20;
        interface IShareManager { function withdrawSharesAsTokens(address s, address strat, uint256 sh) external; }
        contract DelegationManager {
            struct Withdrawal { address staker; address delegatedTo; address[] strategies; uint32 startBlock; uint256[] scaledShares; }
            mapping(bytes32 => bool) public pendingWithdrawals;
            mapping(address => address) public delegatedTo;        // LIVE: staker => operator
            mapping(address => uint256) public operatorShares;
            uint32 constant MIN_WITHDRAWAL_DELAY_BLOCKS = 100;
            function calculateWithdrawalRoot(Withdrawal memory w) public pure returns (bytes32) {
                return keccak256(abi.encode(w));
            }
            function shareManagerFor(address) internal pure returns (IShareManager) { return IShareManager(address(0)); }
            function _completeQueuedWithdrawal(Withdrawal memory withdrawal) internal {
                bytes32 withdrawalRoot = calculateWithdrawalRoot(withdrawal);
                require(pendingWithdrawals[withdrawalRoot], "not queued");
                uint32 slashableUntil = withdrawal.startBlock + MIN_WITHDRAWAL_DELAY_BLOCKS;
                require(uint32(block.number) > slashableUntil, "WithdrawalDelayNotElapsed");
                delete pendingWithdrawals[withdrawalRoot];
                address newOperator = delegatedTo[withdrawal.staker];      // LIVE index by snapshot field
                for (uint256 i = 0; i < withdrawal.strategies.length; i++) {
                    operatorShares[newOperator] += withdrawal.scaledShares[i];
                    shareManagerFor(withdrawal.strategies[i]).withdrawSharesAsTokens(
                        withdrawal.staker, withdrawal.strategies[i], withdrawal.scaledShares[i]
                    );
                }
            }
        }
    "#;

    // SAFE (value-mover precision): a hash gate + a snapshot-field live index, but
    // the ONLY post-guard calls are revert-error constructors whose names begin
    // with mover verbs (`WithdrawalNotQueued`, `RedeemTooEarly`). No real
    // disbursement runs, so the value-mover anchor must reject them ⇒ silent.
    const SAFE_ERROR_NAME_NOT_MOVER: &str = r#"
        pragma solidity ^0.8.20;
        contract Gate {
            struct Req { address account; uint256 nonce; }
            error WithdrawalNotQueued();
            error RedeemTooEarly();
            mapping(bytes32 => bool) public queued;
            mapping(address => uint256) public liveBalance;
            mapping(address => bool) public seen;
            function check(Req memory r) external {
                if (!queued[keccak256(abi.encode(r))]) revert WithdrawalNotQueued();
                uint256 bal = liveBalance[r.account];     // live index by snapshot field
                if (bal == 0) revert RedeemTooEarly();     // mover-verb error name, not a disbursement
                seen[r.account] = true;                    // bookkeeping, not a value move
            }
        }
    "#;

    #[test]
    fn fires_on_karak_finalize_shape() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_eigenlayer_complete_withdrawal_shape() {
        assert!(fires(VULN_EIGEN), "{:#?}", run(VULN_EIGEN));
    }

    #[test]
    fn silent_when_only_post_guard_calls_are_error_constructors() {
        assert!(!fires(SAFE_ERROR_NAME_NOT_MOVER), "{:#?}", run(SAFE_ERROR_NAME_NOT_MOVER));
    }

    #[test]
    fn fires_on_inline_keccak_balance_shape() {
        assert!(fires(VULN_INLINE), "{:#?}", run(VULN_INLINE));
    }

    #[test]
    fn silent_on_cancel_shape() {
        assert!(!fires(SAFE_CANCEL), "{:#?}", run(SAFE_CANCEL));
    }

    #[test]
    fn silent_on_canonical_rebind() {
        assert!(!fires(SAFE_REBIND), "{:#?}", run(SAFE_REBIND));
    }

    #[test]
    fn silent_when_paying_stored_values() {
        assert!(!fires(SAFE_STORED_VALUES), "{:#?}", run(SAFE_STORED_VALUES));
    }

    #[test]
    fn silent_without_hash_gate() {
        assert!(!fires(SAFE_NO_HASH), "{:#?}", run(SAFE_NO_HASH));
    }
}
