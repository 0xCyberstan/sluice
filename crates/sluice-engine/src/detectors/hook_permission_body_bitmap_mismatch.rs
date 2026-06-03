//! Uniswap v4 hook-permission **body-vs-bitmap** mismatch.
//!
//! A Uniswap v4 hook is a contract the PoolManager calls back into at specific
//! lifecycle points (`beforeSwap`, `afterAddLiquidity`, …). Which callbacks the
//! PoolManager will actually invoke is **not** inferred from the contract's code —
//! it is decided by the 14 low bits of the hook's deployment address, and the hook
//! author *declares* the intended bitmap by returning a `Hooks.Permissions` struct
//! from `getHookPermissions()`. `Hooks.validateHookPermissions`
//! (`v4-core/src/libraries/Hooks.sol:85-99`) enforces, at construction, that the
//! declared `Permissions` literal exactly matches the address bits. So
//! `getHookPermissions()` is the single, authoritative statement of *which
//! callbacks this hook participates in*.
//!
//! This detector adds a second axis the framework does **not** check: that the set
//! of callbacks the hook *implements* (has a real, non-stub body for) agrees with
//! the set it *declares*. It builds two 14-bit vectors keyed on the
//! `Hooks.Permissions` field order (`Hooks.sol:49-64`):
//!
//!   * **`DECL[i]`** — the i-th boolean of the `Permissions` literal returned by
//!     `getHookPermissions()`.
//!   * **`IMPL[i]`** — `true` iff callback `i` is implemented with a *non-stub*
//!     body: it writes storage, makes a call, or returns a non-constant value. A
//!     bare `return <selector>;` or a `revert`-only / empty body is **not** an
//!     implementation (it is the `BaseHook`/`BaseTestHooks` default).
//!
//! A disagreement on a real callback bit is a latent bug:
//!
//!   * **Implemented-but-undeclared (`IMPL[i] && !DECL[i]`)** — the hook contains
//!     real logic for callback `i`, but does not declare the bit. The address bits
//!     therefore do not include flag `i`, so the PoolManager **never calls** that
//!     callback: the logic is dead, and any invariant the author assumed it
//!     maintained (a fee taken, a position tracked, an access check) is silently
//!     never enforced. Reported **High**.
//!   * **Declared-but-empty (`DECL[i] && !IMPL[i]`)** — the hook declares the bit,
//!     so the PoolManager *will* call callback `i` on every matching pool action,
//!     but the body is a stub. A `return selector` stub is a wasted call/gas and a
//!     sign of an unfinished hook (**Medium**); a `revert`-only body is worse — the
//!     declared callback reverts on every pool action, **bricking** the pool for
//!     that operation (**escalated to High**).
//!
//! Only indices **0-9** (the ten action callbacks) are reported here. The four
//! `*ReturnDelta` bits (10-13) do not have their own callback function; their
//! body-vs-bitmap relationship (a callback returning a non-zero delta without the
//! matching `*ReturnDelta` bit) is owned by the separate
//! `HookReturnDeltaPermissionGap` detector, so this detector never reports them
//! (no double-report).
//!
//! ## Precision (the false-positive killer)
//!
//! The detector fires **only** when `getHookPermissions()` exists and its
//! `Permissions` literal is statically parseable into a concrete 14-bit vector. A
//! hook with no `getHookPermissions()` (every hook in the v4-core test corpus —
//! `BaseTestHooks`, `FeeTakingHook`, `CustomCurveHook`, …) produces no `DECL`, so
//! the detector is silent there by construction. An opaque literal (a field whose
//! value is not a boolean literal, an unrecognized construction shape) yields
//! `None` and also suppresses the contract — there is no declared baseline to
//! contrast against, so contrasting would be a guess. The `Hooks` library itself,
//! the `IHooks` interface, and abstract bases are excluded by the concrete-hook
//! gate.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use super::prelude::*;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{Contract, ContractKind, Expr, ExprKind, Function, Lit, Scir, StmtKind};

pub struct HookPermissionBodyBitmapMismatchDetector;

/// The canonical `getHookPermissions()` accessor every v4 hook declares.
const PERMISSIONS_ACCESSOR: &str = "getHookPermissions";
/// The struct type the accessor returns (`Hooks.Permissions` / `Permissions`).
const PERMISSIONS_TYPE: &str = "Permissions";

/// The 14 `Hooks.Permissions` fields in their **declaration order**
/// (`v4-core/src/libraries/Hooks.sol:49-64`). The index into this table IS the bit
/// position used by `validateHookPermissions`. Entry `i` carries the canonical
/// (camelCase) field name and the canonical *callback function* name that
/// implements bit `i` (or `None` for the four `*ReturnDelta` bits, which have no
/// own callback and are owned by `HookReturnDeltaPermissionGap`). Name comparisons
/// against parsed source / resolved functions are done case-insensitively.
const PERMISSION_FIELDS: [(&str, Option<&str>); 14] = [
    ("beforeInitialize", Some("beforeInitialize")),
    ("afterInitialize", Some("afterInitialize")),
    ("beforeAddLiquidity", Some("beforeAddLiquidity")),
    ("afterAddLiquidity", Some("afterAddLiquidity")),
    ("beforeRemoveLiquidity", Some("beforeRemoveLiquidity")),
    ("afterRemoveLiquidity", Some("afterRemoveLiquidity")),
    ("beforeSwap", Some("beforeSwap")),
    ("afterSwap", Some("afterSwap")),
    ("beforeDonate", Some("beforeDonate")),
    ("afterDonate", Some("afterDonate")),
    ("beforeSwapReturnDelta", None),
    ("afterSwapReturnDelta", None),
    ("afterAddLiquidityReturnDelta", None),
    ("afterRemoveLiquidityReturnDelta", None),
];

/// The highest index this detector reports on (exclusive). Indices `0..10` are the
/// action callbacks; `10..14` are the `*ReturnDelta` bits owned by the sibling
/// detector.
const REPORTABLE: usize = 10;

impl Detector for HookPermissionBodyBitmapMismatchDetector {
    fn id(&self) -> &'static str {
        "hook-permission-body-bitmap-mismatch"
    }
    fn category(&self) -> Category {
        Category::HookPermissionBodyBitmapMismatch
    }
    fn description(&self) -> &'static str {
        "A Uniswap v4 hook implements a callback body that its `getHookPermissions()` bitmap does \
         not declare (the PoolManager never calls it — dead logic), or declares a callback bit whose \
         body is an empty/revert-only stub (a wasted call, or a pool brick)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let scir = cx.scir;
        let mut out = Vec::new();

        for hook in scir.iter_contracts() {
            // Gate 1: a concrete hook contract. Libraries (`Hooks`), interfaces
            // (`IHooks`), and abstract bases never deploy as a hook and are skipped.
            if !matches!(hook.kind, ContractKind::Contract) {
                continue;
            }

            // Gate 2: the contract must declare `getHookPermissions()` with a body.
            // This is also the only place a `Permissions` literal lives, so a hook
            // that merely overrides callbacks (every v4-core test hook) has no DECL
            // and is silent — the precision anchor. We additionally accept the
            // is-a-hook shape (inherits an `IHooks`/`BaseHook`-like base) but it is
            // moot without a declaration, so we require the declaration outright.
            let Some(perm_fn) = own_function(scir, hook, PERMISSIONS_ACCESSOR) else {
                continue;
            };
            if !perm_fn.has_body {
                continue;
            }
            // Defensive: a contract called `getHookPermissions` on something that is
            // not a hook at all (no IHooks-like base and no callback overrides) is
            // not in scope. In practice the parse above already implies a hook.
            if !looks_like_hook(scir, hook) {
                continue;
            }

            // ---- DECL: parse the 14-bit declared bitmap. ----
            // Absent / opaque => no fire (the precision gate). We do not even emit
            // an Info when there is simply no `Permissions` literal; an Info is only
            // worth raising when the accessor exists but the literal is unparseable.
            let decl = match parse_permissions_literal(cx, perm_fn) {
                Some(d) => d,
                None => {
                    // The accessor exists but we could not recover a concrete bitmap
                    // (opaque/computed literal). Surface a single Info so the gap is
                    // visible without risking a false positive — no per-bit fire.
                    out.push(finish_at(
                        cx,
                        report!(self, Category::HookPermissionBodyBitmapMismatch,
                            title = "Hook getHookPermissions() bitmap could not be statically resolved",
                            severity = Severity::Info,
                            confidence = 0.3,
                            dimensions = [Dimension::Invariant],
                            message = format!(
                                "Hook `{hook}` declares `getHookPermissions()`, but its returned \
                                 `Hooks.Permissions` value is not a statically-resolvable boolean \
                                 literal, so the declared callback bitmap could not be reconstructed. \
                                 The body-vs-bitmap consistency of this hook (whether every implemented \
                                 callback is declared, and every declared callback is implemented) was \
                                 therefore not checked. Consider returning a plain `Permissions({{...}})` \
                                 literal so the declaration is auditable.",
                                hook = hook.name,
                            ),
                            recommendation = "Return the `Hooks.Permissions` struct as a literal with \
                                boolean field values (the canonical `getHookPermissions` form) so the \
                                declared callback set is statically auditable against the implemented one.",
                        ),
                        perm_fn.id,
                        perm_fn.span,
                    ));
                    continue;
                }
            };

            // ---- IMPL: which callbacks have a real, non-stub body. ----
            // Resolve each callback on the hook's own functions OR any inherited
            // override (a hook can implement `beforeSwap` directly or via a base it
            // extends); the most-derived non-stub body wins.
            let impl_bits = compute_impl_bits(scir, hook);

            // ---- Diff, reporting only the ten action callbacks (0..10). ----
            for i in 0..REPORTABLE {
                let (field, cb) = PERMISSION_FIELDS[i];
                let cb = cb.expect("indices 0..10 always have a callback");
                let declared = decl[i];
                let Some(impl_state) = impl_bits[i] else {
                    // No function of this name on the hook at all: cannot be an
                    // implemented-but-undeclared body, and a declared-but-missing
                    // callback is a different (compile-time) problem the framework
                    // already forces via the IHooks interface. Skip.
                    continue;
                };

                match (impl_state.implemented, declared) {
                    // Implemented but not declared: dead logic — the PoolManager
                    // never calls it because the address bits omit flag `i`.
                    (true, false) => {
                        out.push(finish_at(
                            cx,
                            report!(self, Category::HookPermissionBodyBitmapMismatch,
                                title = "Hook implements a callback it does not declare in getHookPermissions() (dead logic — never called)",
                                severity = Severity::High,
                                confidence = 0.75,
                                dimensions = [Dimension::Invariant],
                                message = format!(
                                    "Hook `{hook}` provides a real (non-stub) `{cb}` implementation, but \
                                     `getHookPermissions()` leaves `Permissions.{field}` **false**. The v4 \
                                     PoolManager decides which callbacks to invoke from the hook's address \
                                     bits, and `Hooks.validateHookPermissions` forces those bits to equal the \
                                     declared `Permissions` literal — so with `{field} = false`, the address \
                                     does not carry the `{cb}` flag and the PoolManager **never calls** \
                                     `{cb}`. The implemented logic is dead: any effect it performs (a fee, an \
                                     accounting update, an access check) is silently never applied on pool \
                                     actions. The implemented-callback set and the declared bitmap disagree.",
                                    hook = hook.name, cb = cb, field = field,
                                ),
                                recommendation = format!(
                                    "If `{cb}` is meant to run, set `Permissions.{field} = true` in \
                                     `getHookPermissions()` (and deploy the hook to an address whose bits \
                                     include the `{cb}` flag). If it is not meant to run, delete the unused \
                                     `{cb}` body so the contract's behavior matches its declaration.",
                                    cb = cb, field = field,
                                ),
                            ),
                            impl_state.fid,
                            impl_state.span,
                        ));
                    }
                    // Declared but the body is a stub: a wasted call (Medium), or a
                    // revert-only body that bricks the pool action (escalated High).
                    (false, true) => {
                        let (severity, confidence, brick) = if impl_state.revert_only {
                            (Severity::High, 0.75, true)
                        } else {
                            (Severity::Medium, 0.65, false)
                        };
                        let detail = if brick {
                            format!(
                                "Hook `{hook}` declares `Permissions.{field} = true`, so the PoolManager \
                                 invokes `{cb}` on **every** matching pool action — but the `{cb}` body \
                                 only reverts. The declared callback therefore reverts on every such \
                                 action, **bricking** that pool operation (swaps/liquidity/donate/initialize \
                                 fail) for as long as the hook is attached. The declared bitmap promises a \
                                 working callback the body does not provide.",
                                hook = hook.name, cb = cb, field = field,
                            )
                        } else {
                            format!(
                                "Hook `{hook}` declares `Permissions.{field} = true`, so the PoolManager \
                                 invokes `{cb}` on every matching pool action — but the `{cb}` body is an \
                                 empty/`return selector` stub with no effect. Every such pool action pays \
                                 the gas of an external hook call that does nothing, and the declared \
                                 intent (that this hook participates in `{cb}`) is not actually implemented. \
                                 The declared bitmap and the implemented-callback set disagree.",
                                hook = hook.name, cb = cb, field = field,
                            )
                        };
                        out.push(finish_at(
                            cx,
                            report!(self, Category::HookPermissionBodyBitmapMismatch,
                                title = "Hook declares a callback bit whose body is an empty / revert-only stub",
                                severity = severity,
                                confidence = confidence,
                                dimensions = [Dimension::Invariant],
                                message = detail,
                                recommendation = format!(
                                    "Either implement `{cb}` (the declared `Permissions.{field} = true` \
                                     promises a working callback the PoolManager will call), or set \
                                     `Permissions.{field} = false` so the PoolManager does not call the \
                                     stub. Keep the declared bitmap and the implemented callbacks in sync.",
                                    cb = cb, field = field,
                                ),
                            ),
                            impl_state.fid,
                            impl_state.span,
                        ));
                    }
                    // Agreement (both true or both false): nothing to report.
                    _ => {}
                }
            }
        }

        out
    }
}

// ============================================================ is-a-hook gate

/// Conservative "this contract is a Uniswap v4 hook" test: it inherits an
/// `IHooks` / `BaseHook` / `Hooks`-suffixed base **or** it overrides at least one
/// of the ten action callbacks. The `Hooks` library and the `IHooks` interface are
/// excluded by the concrete-contract gate at the call site, so a name like
/// `MyHooks` as a base is the hook-mixin signal, not the library.
fn looks_like_hook(scir: &Scir, c: &Contract) -> bool {
    if c.inherits_like("IHooks") || c.inherits_like("BaseHook") {
        return true;
    }
    // Inheriting any base that ends in `Hooks` (e.g. `BaseTestHooks`) is the v4
    // hook-mixin shape.
    if c.bases.iter().any(|b| {
        let l = b.to_ascii_lowercase();
        l.ends_with("hooks") || l == "hooks"
    }) {
        return true;
    }
    // Fallback: it overrides a callback by name (own or inherited).
    PERMISSION_FIELDS[..REPORTABLE]
        .iter()
        .filter_map(|(_, cb)| *cb)
        .any(|cb| resolve_callback(scir, c, cb).is_some())
}

// ============================================================ DECL: literal parse

/// Parse the `Hooks.Permissions` literal returned by `getHookPermissions()` into a
/// concrete 14-bit boolean vector. Returns `None` when no `Permissions`
/// construction is found, or when the construction's bits cannot be statically
/// resolved to boolean literals (opaque / computed) — both cases suppress the
/// contract (no fire), which is the detector's precision gate.
///
/// Supports the two real `getHookPermissions` shapes:
///   * **positional** — `Permissions(b0, b1, …, b13)` (14 positional booleans),
///     read straight from the IR `Call.args` by index.
///   * **named** — `Permissions({beforeSwap: true, …})`. The lowering drops the
///     field labels (it keeps only the value exprs in source order), so the field
///     names are recovered from the construction's source span text and matched
///     against [`PERMISSION_FIELDS`]. Fields not present default to `false`
///     (matching Solidity struct-literal semantics is not required — the canonical
///     literal always lists all 14 — but a partial literal is still resolvable).
fn parse_permissions_literal(cx: &AnalysisContext, f: &Function) -> Option<[bool; 14]> {
    let call = find_permissions_construction(f)?;

    // Positional form: exactly 14 positional boolean-literal args.
    if call.args.len() == 14 {
        let mut bits = [false; 14];
        for (i, a) in call.args.iter().enumerate() {
            bits[i] = bool_lit(a)?; // any non-literal arg => opaque => suppress.
        }
        return Some(bits);
    }

    // Named form: recover `field: value` pairs from the source text of the
    // construction span. The IR args are the values in source order; pairing them
    // positionally with the field names parsed from source keeps value resolution
    // on the (already-lowered) IR literal rather than re-lexing the value text.
    let names = parse_named_fields_from_source(cx, f, call)?;
    if names.is_empty() || names.len() != call.args.len() {
        return None;
    }
    let mut bits = [false; 14];
    for (name, value) in names.iter().zip(call.args.iter()) {
        // `name` is lowercased by `collect_field_labels`; match the table
        // case-insensitively.
        let idx = PERMISSION_FIELDS
            .iter()
            .position(|(fld, _)| fld.eq_ignore_ascii_case(name))?;
        bits[idx] = bool_lit(value)?;
    }
    Some(bits)
}

/// Find the `Permissions(...)` / `Hooks.Permissions(...)` construction call in the
/// accessor body (typically the returned expression). Returns the first such call.
fn find_permissions_construction(f: &Function) -> Option<&sluice_ir::Call> {
    let mut found: Option<&sluice_ir::Call> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if call_constructs_permissions(c) {
                    found = Some(c);
                }
            }
        });
    }
    found
}

/// Is `c` a construction of the `Permissions` struct — `Permissions(...)`,
/// `Hooks.Permissions(...)`, or the cast-shaped `Permissions({...})`? The callee
/// name (or its trailing member) must be exactly `Permissions`.
fn call_constructs_permissions(c: &sluice_ir::Call) -> bool {
    if c.func_name.as_deref() == Some(PERMISSIONS_TYPE) {
        return true;
    }
    // `Hooks.Permissions(...)` — the callee is a member chain ending in
    // `Permissions`; `receiver` is the `Hooks` library qualifier.
    callee_trailing_name(&c.callee) == Some(PERMISSIONS_TYPE)
}

/// The trailing identifier/member of a callee expression: `Permissions` for both
/// `Permissions` and `Hooks.Permissions`.
fn callee_trailing_name(e: &Expr) -> Option<&str> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n),
        ExprKind::Member { member, .. } => Some(member),
        _ => None,
    }
}

/// If `e` is a boolean literal, return its value; otherwise `None` (opaque).
fn bool_lit(e: &Expr) -> Option<bool> {
    match &e.kind {
        ExprKind::Lit(Lit::Bool(b)) => Some(*b),
        _ => None,
    }
}

/// Recover the lowercase field-name sequence of a named `Permissions({a: x, b: y})`
/// construction from its source span text (the lowering discards the labels). Each
/// `identifier :` immediately inside the struct-literal braces is a field name, in
/// source order. Returns `None` if the braces or any `name:` cannot be located.
fn parse_named_fields_from_source(
    cx: &AnalysisContext,
    f: &Function,
    call: &sluice_ir::Call,
) -> Option<Vec<String>> {
    // Use the *callee* span if it covers the construction; otherwise the whole
    // accessor source. We need the brace block, so prefer the widest reliable text:
    // the accessor body text, then locate the `Permissions` block within it.
    let text = cx.source_text(f.span);
    if text.is_empty() {
        return None;
    }
    // Locate the `permissions` keyword (lowercased by `source_text`) that opens the
    // construction, then the following `{ ... }`.
    let _ = call; // the call drives the value side; names come from the brace block.
    let open_kw = text.find("permissions")?;
    let brace_open = text[open_kw..].find('{')? + open_kw;
    let brace_close = matching_brace(&text, brace_open)?;
    let inner = &text[brace_open + 1..brace_close];
    Some(collect_field_labels(inner))
}

/// Given the inner text of a `{ ... }` struct literal, collect the field labels:
/// every `ident :` at brace-depth 0 (so nested braces / ternaries do not leak
/// inner identifiers). Names are returned lowercased, in source order.
fn collect_field_labels(inner: &str) -> Vec<String> {
    let bytes = inner.as_bytes();
    let mut labels = Vec::new();
    let mut depth: i32 = 0;
    let mut i = 0;
    // Track the start of the current top-level segment so we can extract its
    // leading `ident` when we hit the `:`.
    let mut seg_start = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'{' | b'(' | b'[' => depth += 1,
            b'}' | b')' | b']' => depth -= 1,
            b',' if depth == 0 => seg_start = i + 1,
            b':' if depth == 0 => {
                // Solidity has no `?:`-free top-level `:` other than the field
                // label; ternaries live inside value segments (after a label) and
                // are guarded by depth in practice because we reset `seg_start` on
                // each comma. Extract the leading identifier of this segment.
                let seg = &inner[seg_start..i];
                let name = seg.trim().trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_');
                if !name.is_empty() && name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
                    labels.push(name.to_ascii_lowercase());
                }
                // Advance segment start past this label so a ternary `a ? b : c` in
                // the value does not register `b` as a second label.
                seg_start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    labels
}

/// Index of the `}` matching the `{` at `open` in `text`. `None` if unbalanced.
fn matching_brace(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth: i32 = 0;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

// ============================================================ IMPL: body analysis

/// The implementation state of one callback on the hook.
#[derive(Clone, Copy)]
struct ImplState {
    /// True if the body is a real (non-stub) implementation.
    implemented: bool,
    /// True if the body's only effect is a `revert` (escalates a declared-but-empty
    /// finding to a pool-bricking High).
    revert_only: bool,
    fid: sluice_ir::FunctionId,
    span: sluice_ir::Span,
}

/// Compute `IMPL[0..14]`: for each permission field, the implementation state of
/// the callback that backs it (or `None` for the `*ReturnDelta` bits / a callback
/// the hook does not define at all).
fn compute_impl_bits(scir: &Scir, hook: &Contract) -> [Option<ImplState>; 14] {
    let mut bits: [Option<ImplState>; 14] = [None; 14];
    for (i, (_, cb)) in PERMISSION_FIELDS.iter().enumerate() {
        let Some(cb) = cb else { continue };
        if let Some(f) = resolve_callback(scir, hook, cb) {
            bits[i] = Some(ImplState {
                implemented: is_real_implementation(f),
                revert_only: is_revert_only(f),
                fid: f.id,
                span: f.span,
            });
        }
    }
    bits
}

/// Resolve callback `cb` (lowercase) on the hook: the most-derived function of that
/// name **with a body** found walking the hook's own functions then its inheritance
/// chain. A bodyless interface/abstract declaration is skipped so the resolved
/// function is the one whose body actually runs.
fn resolve_callback<'a>(scir: &'a Scir, hook: &Contract, cb: &str) -> Option<&'a Function> {
    let by_name: std::collections::HashMap<&str, &Contract> =
        scir.iter_contracts().map(|c| (c.name.as_str(), c)).collect();
    for anc in chain_names(&by_name, &hook.name) {
        if let Some(c) = by_name.get(anc) {
            if let Some(f) = scir
                .functions_of(c.id)
                .find(|f| f.has_body && f.name.eq_ignore_ascii_case(cb))
            {
                return Some(f);
            }
        }
    }
    None
}

/// Is `f` a **real** callback implementation (not a stub)? A real body writes
/// storage, makes any call (external/internal/low-level), or returns a value that
/// is more than the bare selector / a constant. The `BaseHook` default
/// (`return X.selector;`), a `revert`-only body, and an empty body are all stubs.
fn is_real_implementation(f: &Function) -> bool {
    // Storage writes are an unambiguous side effect.
    if !f.effects.storage_writes.is_empty() {
        return true;
    }
    // Any call site (external/internal/low-level/transfer) is real work — e.g.
    // `manager.take(...)`, `currency.settle(...)`, an internal helper.
    if !f.effects.call_sites.is_empty() || !f.effects.internal_calls.is_empty() {
        return true;
    }
    // A non-trivial return (anything other than a bare selector / constant tuple).
    if body_has_nonconstant_return(f) {
        return true;
    }
    false
}

/// True if the body's *only* meaningful statement(s) reduce to a `revert` — the
/// `BaseTestHooks` `revert HookNotImplemented();` shape — with no storage writes
/// and no calls. Used to escalate a declared-but-empty finding to a pool brick.
fn is_revert_only(f: &Function) -> bool {
    if !f.effects.storage_writes.is_empty() || !f.effects.call_sites.is_empty() {
        return false;
    }
    let mut saw_revert = false;
    let mut saw_other_effect = false;
    for s in &f.body {
        match &s.kind {
            StmtKind::Revert { .. } => saw_revert = true,
            // A `require(false)` / `assert(false)` style revert via builtin call is
            // captured as an Expr(Call Builtin Revert/Require); treat a lone such
            // statement as a revert too.
            StmtKind::Expr(e) if expr_is_revert_builtin(e) => saw_revert = true,
            // Declarations / placeholders / empty are inert; anything else is "real".
            StmtKind::VarDecl { .. } | StmtKind::Placeholder => {}
            _ => saw_other_effect = true,
        }
    }
    saw_revert && !saw_other_effect
}

/// Is `e` a `revert(...)` / `require(false, …)` builtin call?
fn expr_is_revert_builtin(e: &Expr) -> bool {
    if let ExprKind::Call(c) = &e.kind {
        return matches!(
            c.kind,
            sluice_ir::CallKind::Builtin(sluice_ir::Builtin::Revert)
        );
    }
    false
}

/// Does the body contain a `return` whose value is more than a bare selector or a
/// compile-time constant? `return X.selector;` and `return (X.selector, 0, 0);`
/// (the canonical no-op hook return) are **not** real implementations; a return
/// that mentions a parameter, a state read, or a computed expression is.
fn body_has_nonconstant_return(f: &Function) -> bool {
    let mut real = false;
    for s in &f.body {
        s.visit(&mut |st| {
            if let StmtKind::Return(Some(e)) = &st.kind {
                if return_value_is_nontrivial(e) {
                    real = true;
                }
            }
        });
    }
    real
}

/// A returned expression is "nontrivial" if any of its components is neither a
/// `*.selector` member, a numeric/bool/address literal, nor a zero-delta sentinel
/// construction (`toBalanceDelta(0,0)`, `*.wrap(0)`, `*.ZERO_DELTA`). A tuple is
/// nontrivial iff any element is. This deliberately treats the canonical
/// `(selector, ZERO_DELTA, 0)` no-op return as trivial (a stub), matching the
/// `BaseHook`/`BaseTestHooks` baseline.
fn return_value_is_nontrivial(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Tuple(items) => items.iter().flatten().any(return_value_is_nontrivial),
        // `X.selector` — the mandatory selector echo, not real logic.
        ExprKind::Member { member, .. } if member == "selector" => false,
        // Literals (incl. the `0` / `0,0` zero-delta args) are trivial.
        ExprKind::Lit(_) => false,
        // A zero-delta sentinel call: `toBalanceDelta(0,0)`, `BeforeSwapDelta.wrap(0)`,
        // `toBeforeSwapDelta(0,0)`. Treat as trivial iff every arg is a literal `0`.
        ExprKind::Call(c) if is_zero_delta_construction(c) => false,
        // A type-cast wrapping a trivial inner (`int128(0)`, `uint24(0)`).
        ExprKind::Call(c) if c.kind == sluice_ir::CallKind::TypeCast => {
            c.args.iter().any(return_value_is_nontrivial)
        }
        // A bare identifier that is a named constant cannot be distinguished here;
        // be conservative and treat a lone identifier as trivial only if it reads
        // like a zero/selector sentinel. Anything else (a param, a state read, a
        // computed call) is nontrivial.
        ExprKind::Ident(n) => {
            let l = n.to_ascii_lowercase();
            !(l.contains("zero") || l == "selector")
        }
        // Anything else — arithmetic, a parameter, a state/storage read, a
        // non-sentinel call — is real returned logic.
        _ => true,
    }
}

/// Is `c` a zero-delta sentinel construction whose every argument is a literal `0`?
/// (`toBalanceDelta(0,0)`, `toBeforeSwapDelta(0,0)`, `BeforeSwapDelta.wrap(0)`,
/// `BalanceDeltaLibrary.ZERO_DELTA` surfaces as a member, handled separately.)
fn is_zero_delta_construction(c: &sluice_ir::Call) -> bool {
    let name = c
        .func_name
        .as_deref()
        .or_else(|| callee_trailing_name(&c.callee))
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_delta_ctor = name.contains("delta") && (name.starts_with("to") || name == "wrap")
        || name == "wrap" && callee_mentions_delta(&c.callee);
    if !is_delta_ctor {
        return false;
    }
    !c.args.is_empty() && c.args.iter().all(|a| is_int_lit(a, 0))
}

/// Does the callee chain mention a `*Delta` type (so `.wrap(0)` is a delta wrap)?
fn callee_mentions_delta(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if let ExprKind::Ident(n) = &sub.kind {
            if n.to_ascii_lowercase().contains("delta") {
                found = true;
            }
        }
        if let ExprKind::Member { member, .. } = &sub.kind {
            if member.to_ascii_lowercase().contains("delta") {
                found = true;
            }
        }
    });
    found
}

// ============================================================ inheritance walk

/// The first function named `name` (case-sensitive exact) declared directly on
/// contract `c`.
fn own_function<'a>(scir: &'a Scir, c: &Contract, name: &str) -> Option<&'a Function> {
    scir.functions_of(c.id).find(|f| f.name == name)
}

/// All contract names in the inheritance chain rooted at `name` (itself + every
/// transitive base resolvable through `by_name`), most-derived first, de-duplicated.
fn chain_names<'a>(
    by_name: &std::collections::HashMap<&'a str, &'a Contract>,
    name: &str,
) -> Vec<&'a str> {
    let mut out: Vec<&'a str> = Vec::new();
    let mut seen: std::collections::HashSet<&'a str> = std::collections::HashSet::new();
    let mut stack: Vec<&'a str> = Vec::new();
    if let Some((k, _)) = by_name.get_key_value(name) {
        stack.push(k);
    }
    // BFS-ish in declaration order keeps the most-derived contract first.
    let mut idx = 0;
    while idx < stack.len() {
        let n = stack[idx];
        idx += 1;
        if !seen.insert(n) {
            continue;
        }
        out.push(n);
        if let Some(c) = by_name.get(n) {
            for b in &c.bases {
                if let Some((k, _)) = by_name.get_key_value(b.as_str()) {
                    stack.push(k);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::context::AnalysisContext;
    use crate::detector::Detector;
    use sluice_findings::{Finding, Severity};

    /// Run *only this detector* against `src`, bypassing the global registry
    /// (contended in the shared worktree). Mirrors `analyze_sources`' wiring.
    fn run(src: &str) -> Vec<Finding> {
        let cfg = crate::Config::default();
        let parsed = sluice_parse::parse_sources(vec![("t.sol".into(), src.into())]);
        let scir = parsed.scir;
        let dataflow = sluice_dataflow::DataflowFacts::analyze(&scir);
        let invariants = sluice_invariant::InvariantFacts::mine(&scir);
        let frontier = sluice_frontier::FrontierFacts::analyze(&scir);
        let cx = AnalysisContext::new(&scir, &dataflow, &invariants, &frontier, &cfg);
        super::HookPermissionBodyBitmapMismatchDetector.run(&cx)
    }

    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "hook-permission-body-bitmap-mismatch"
            && f.severity != Severity::Info)
    }

    /// Minimal v4 hook scaffold: an `IHooks` interface (bodyless callbacks), a
    /// `Hooks` library holding the `Permissions` struct, and a `BaseHook`-style base
    /// whose callbacks are `revert`-only stubs (the `BaseTestHooks` shape).
    const SCAFFOLD: &str = r#"
        interface IHooks {
            function beforeInitialize(address, uint160) external returns (bytes4);
            function afterInitialize(address, uint160, int24) external returns (bytes4);
            function beforeAddLiquidity(address, bytes calldata) external returns (bytes4);
            function afterAddLiquidity(address, bytes calldata) external returns (bytes4);
            function beforeRemoveLiquidity(address, bytes calldata) external returns (bytes4);
            function afterRemoveLiquidity(address, bytes calldata) external returns (bytes4);
            function beforeSwap(address, bytes calldata) external returns (bytes4, int256, uint24);
            function afterSwap(address, bytes calldata) external returns (bytes4, int128);
            function beforeDonate(address, bytes calldata) external returns (bytes4);
            function afterDonate(address, bytes calldata) external returns (bytes4);
        }
        library Hooks {
            struct Permissions {
                bool beforeInitialize;
                bool afterInitialize;
                bool beforeAddLiquidity;
                bool afterAddLiquidity;
                bool beforeRemoveLiquidity;
                bool afterRemoveLiquidity;
                bool beforeSwap;
                bool afterSwap;
                bool beforeDonate;
                bool afterDonate;
                bool beforeSwapReturnDelta;
                bool afterSwapReturnDelta;
                bool afterAddLiquidityReturnDelta;
                bool afterRemoveLiquidityReturnDelta;
            }
        }
        contract BaseTestHooks is IHooks {
            error HookNotImplemented();
            function beforeInitialize(address, uint160) external virtual returns (bytes4) { revert HookNotImplemented(); }
            function afterInitialize(address, uint160, int24) external virtual returns (bytes4) { revert HookNotImplemented(); }
            function beforeAddLiquidity(address, bytes calldata) external virtual returns (bytes4) { revert HookNotImplemented(); }
            function afterAddLiquidity(address, bytes calldata) external virtual returns (bytes4) { revert HookNotImplemented(); }
            function beforeRemoveLiquidity(address, bytes calldata) external virtual returns (bytes4) { revert HookNotImplemented(); }
            function afterRemoveLiquidity(address, bytes calldata) external virtual returns (bytes4) { revert HookNotImplemented(); }
            function beforeSwap(address, bytes calldata) external virtual returns (bytes4, int256, uint24) { revert HookNotImplemented(); }
            function afterSwap(address, bytes calldata) external virtual returns (bytes4, int128) { revert HookNotImplemented(); }
            function beforeDonate(address, bytes calldata) external virtual returns (bytes4) { revert HookNotImplemented(); }
            function afterDonate(address, bytes calldata) external virtual returns (bytes4) { revert HookNotImplemented(); }
        }
    "#;

    fn with_scaffold(hook: &str) -> String {
        format!("{SCAFFOLD}\n{hook}")
    }

    // VULN (implemented-but-undeclared): the named `Permissions` literal declares
    // `beforeSwap = true` only, but the hook implements BOTH `beforeSwap` (swaps++)
    // and `afterSwap` (swaps++). IMPL[afterSwap]=true, DECL[afterSwap]=false => the
    // PoolManager never calls `afterSwap` (dead logic) => High.
    const MISMATCH_HOOK: &str = r#"
        contract MismatchHook is BaseTestHooks {
            uint256 public swaps;
            function getHookPermissions() public pure returns (Hooks.Permissions memory) {
                return Hooks.Permissions({
                    beforeInitialize: false,
                    afterInitialize: false,
                    beforeAddLiquidity: false,
                    afterAddLiquidity: false,
                    beforeRemoveLiquidity: false,
                    afterRemoveLiquidity: false,
                    beforeSwap: true,
                    afterSwap: false,
                    beforeDonate: false,
                    afterDonate: false,
                    beforeSwapReturnDelta: false,
                    afterSwapReturnDelta: false,
                    afterAddLiquidityReturnDelta: false,
                    afterRemoveLiquidityReturnDelta: false
                });
            }
            function beforeSwap(address, bytes calldata) external override returns (bytes4, int256, uint24) {
                swaps++;
                return (IHooks.beforeSwap.selector, int256(0), uint24(0));
            }
            function afterSwap(address, bytes calldata) external override returns (bytes4, int128) {
                swaps++;                                  // <-- implemented but NOT declared
                return (IHooks.afterSwap.selector, int128(0));
            }
        }
    "#;

    // SAFE (matched table): declares EXACTLY the two callbacks it implements
    // (beforeSwap + afterSwap), and every other declared bit is false with a
    // revert-only inherited stub (not implemented). DECL == IMPL on 0..10 => silent.
    const MATCHED_HOOK: &str = r#"
        contract MatchedHook is BaseTestHooks {
            uint256 public swaps;
            function getHookPermissions() public pure returns (Hooks.Permissions memory) {
                return Hooks.Permissions({
                    beforeInitialize: false,
                    afterInitialize: false,
                    beforeAddLiquidity: false,
                    afterAddLiquidity: false,
                    beforeRemoveLiquidity: false,
                    afterRemoveLiquidity: false,
                    beforeSwap: true,
                    afterSwap: true,
                    beforeDonate: false,
                    afterDonate: false,
                    beforeSwapReturnDelta: false,
                    afterSwapReturnDelta: false,
                    afterAddLiquidityReturnDelta: false,
                    afterRemoveLiquidityReturnDelta: false
                });
            }
            function beforeSwap(address, bytes calldata) external override returns (bytes4, int256, uint24) {
                swaps++;
                return (IHooks.beforeSwap.selector, int256(0), uint24(0));
            }
            function afterSwap(address, bytes calldata) external override returns (bytes4, int128) {
                swaps++;
                return (IHooks.afterSwap.selector, int128(0));
            }
        }
    "#;

    // SAFE (stub overrides, NO getHookPermissions): a hook whose callbacks are the
    // inherited revert-only stubs and which declares NO permissions literal. With no
    // DECL there is no baseline to contrast => silent (the precision gate).
    const STUB_HOOK: &str = r#"
        contract StubHook is BaseTestHooks {
            // no getHookPermissions(); inherits revert-only callbacks only.
        }
    "#;

    // SAFE (declared-but-empty would fire — used as a POSITIVE control for the
    // Medium variant): declares afterSwap=true but the afterSwap body is the
    // inherited revert-only stub => declared-but-empty + revert-only => High brick.
    const DECLARED_REVERT_HOOK: &str = r#"
        contract DeclaredRevertHook is BaseTestHooks {
            function getHookPermissions() public pure returns (Hooks.Permissions memory) {
                return Hooks.Permissions({
                    beforeInitialize: false,
                    afterInitialize: false,
                    beforeAddLiquidity: false,
                    afterAddLiquidity: false,
                    beforeRemoveLiquidity: false,
                    afterRemoveLiquidity: false,
                    beforeSwap: false,
                    afterSwap: true,
                    beforeDonate: false,
                    afterDonate: false,
                    beforeSwapReturnDelta: false,
                    afterSwapReturnDelta: false,
                    afterAddLiquidityReturnDelta: false,
                    afterRemoveLiquidityReturnDelta: false
                });
            }
            // afterSwap inherited as revert-only => declared but not implemented.
        }
    "#;

    #[test]
    fn fires_on_impl_without_decl() {
        let src = with_scaffold(MISMATCH_HOOK);
        let fs = run(&src);
        assert!(
            fs.iter().any(|f| f.detector == "hook-permission-body-bitmap-mismatch"
                && f.severity == Severity::High
                && f.message.contains("afterSwap")
                && f.message.contains("never call")),
            "expected High implemented-but-undeclared finding for afterSwap, got: {:#?}",
            fs
        );
        // It must NOT flag beforeSwap (declared true AND implemented => agreement).
        assert!(
            !fs.iter().any(|f| f.detector == "hook-permission-body-bitmap-mismatch"
                && f.message.contains("beforeSwap")
                && f.severity != Severity::Info),
            "beforeSwap agrees (declared+implemented) and must not fire: {:#?}",
            fs
        );
    }

    #[test]
    fn silent_on_stub_overrides_no_decl() {
        let src = with_scaffold(STUB_HOOK);
        assert!(!fires(&src), "{:#?}", run(&src));
    }

    #[test]
    fn silent_on_matched_table() {
        let src = with_scaffold(MATCHED_HOOK);
        assert!(!fires(&src), "{:#?}", run(&src));
    }

    #[test]
    fn fires_high_on_declared_revert_only() {
        let src = with_scaffold(DECLARED_REVERT_HOOK);
        let fs = run(&src);
        assert!(
            fs.iter().any(|f| f.detector == "hook-permission-body-bitmap-mismatch"
                && f.severity == Severity::High
                && f.message.contains("afterSwap")
                && f.message.contains("brick")),
            "expected High pool-bricking finding for declared revert-only afterSwap, got: {:#?}",
            fs
        );
    }
}
