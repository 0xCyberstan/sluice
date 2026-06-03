//! Shared detector prelude — the SCIR query + false-positive-suppression building
//! blocks every detector re-implemented locally, gathered into one documented,
//! zero-cost layer.
//!
//! ## Why this exists
//!
//! Authoring a new detector used to mean re-deriving the same ~6 SCIR-walking
//! helpers from scratch: peel type-casts off a receiver, find the root identifier
//! of a `a.b[c]` chain, decide whether an expression is a parameter / a settable
//! state var / a constant, walk every call of a given [`CallKind`], and so on. The
//! same `fn root_ident` appeared in 11 detectors, `fn unwrap_casts` in 9, and an
//! ad-hoc `ExprKind::Call` visitor in ~40. Each copy was a chance to drift (some
//! returned `Option<String>`, some `Option<&str>`, some peeled casts first, some
//! did not), and every drift is a latent behavioral difference.
//!
//! This module is the single home for those primitives. It is deliberately a
//! **thin, behavior-preserving** layer: each helper is exactly the canonical form
//! that was already copy-pasted, just named, documented, and unit-tested once.
//! Nothing here performs analysis the detectors were not already doing.
//!
//! ## What's inside
//!
//! * **Expression shape** — [`peel_casts`], [`root_ident`], [`root_ident_str`],
//!   [`root_ident_peeled`], [`expr_mentions_ident`], [`expr_indexes_ident`],
//!   [`is_one`], [`is_int_lit`].
//! * **Parameter / state-var classification** — [`is_param`],
//!   [`root_is_param`], [`is_state_var`], [`is_settable_state_var`],
//!   [`root_is_state_var`], [`root_is_const_or_immutable`],
//!   [`root_is_settable_state_var`].
//! * **Call queries** — [`CallExt`] (an `ExprKind::Call`-shaped iterator over a
//!   body), [`calls_of_kind`], [`first_call_where`], [`any_call_where`] plus the
//!   pre-existing [`super::visit_calls`].
//! * **Name classifiers** — re-exports of [`is_accounting_name`],
//!   [`is_privileged_name`] and [`find_spot_price`] from [`super`], so a detector
//!   gets one import surface.
//! * **Reporting** — the [`report!`] macro: the `FindingBuilder::new(id, cat)
//!   .title(..).severity(..)…` boilerplate as a single declarative form, plus
//!   [`finish_at`] for the common `cx.finish(builder, f.id, span)` tail.
//!
//! ## Usage
//!
//! ```ignore
//! use super::prelude::*;
//!
//! for f in cx.entry_points() {
//!     if let Some(span) = first_call_where(f, |c| {
//!         matches!(c.kind, CallKind::External | CallKind::LowLevelCall)
//!     }) {
//!         out.push(finish_at(cx, report!(self, Category::Foo,
//!             title = "…", severity = Severity::High, confidence = 0.6,
//!             dimensions = [Dimension::ValueFlow],
//!             message = format!("`{}` …", f.name),
//!             recommendation = "…",
//!         ), f.id, span));
//!     }
//! }
//! ```

#![allow(dead_code)] // A shared toolbox: not every helper is used by every build.

use crate::context::AnalysisContext;
use sluice_findings::Finding;
use sluice_ir::{
    Builtin, Call, CallKind, Contract, Expr, ExprKind, Function, FunctionId, Lit, Span, StmtKind,
    ValueSource,
};

// Re-export the existing name-classifier / query helpers so a detector needs only
// `use super::prelude::*;` rather than reaching into `super::` for some and
// `prelude::` for others.
// Re-exported as a single import surface; not every detector uses every one.
#[allow(unused_imports)]
pub(crate) use super::{find_spot_price, is_accounting_name, is_privileged_name, visit_calls};

// ===================================================================== expr shape

/// Peel single-argument type casts off an expression, returning the innermost
/// operand. Handles the interface/address/payable wrapper idiom:
/// `IOldStaking(x)` -> `x`, `address(payable(y))` -> `y`, `uint256(z)` -> `z`.
///
/// This is the canonical body that was copy-pasted as `unwrap_casts` /
/// `peel_casts` across `untrusted_call_target`, `arbitrary_transfer`,
/// `gas_griefing`, `proportional_split_residual`, and others — identical in every
/// copy. A cast in the IR is a [`CallKind::TypeCast`] call with exactly one
/// argument, which is also how `(x)` parenthesization commonly surfaces.
pub fn peel_casts(e: &Expr) -> &Expr {
    let mut cur = e;
    loop {
        match &cur.kind {
            ExprKind::Call(c) if c.kind == CallKind::TypeCast && c.args.len() == 1 => {
                cur = &c.args[0];
            }
            _ => return cur,
        }
    }
}

/// Root identifier of an lvalue / member / index chain: `a.b[c].d` -> `"a"`.
/// Returns `None` for anything not rooted in a bare identifier (a literal, a call,
/// a cast). Does **not** peel casts — use [`root_ident_peeled`] if the receiver may
/// be wrapped (`IFoo(x).bar`).
///
/// This is the most-duplicated helper in the tree (11 copies, all returning
/// `Option<String>` with this exact arm set).
pub fn root_ident(e: &Expr) -> Option<String> {
    root_ident_str(e).map(str::to_owned)
}

/// Borrowing twin of [`root_ident`] — returns `Option<&str>` to avoid the
/// allocation when the caller only needs to compare or hand the name straight to
/// another `&str` API. `a.b[c]` -> `Some("a")`.
pub fn root_ident_str(e: &Expr) -> Option<&str> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root_ident_str(base),
        _ => None,
    }
}

/// [`root_ident`] that first [`peel_casts`]es the whole chain *and* descends
/// through casts at every level, so a cast-wrapped receiver such as
/// `IOldStaking(oldStaking).migrateWithdraw` resolves to `"oldStaking"`. This is
/// the form `double_entry_token` / `netted_aggregate_desync` inlined (they peeled
/// inside the recursion); it is the right default when resolving a *call receiver*.
pub fn root_ident_peeled(e: &Expr) -> Option<String> {
    match &peel_casts(e).kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root_ident_peeled(base),
        _ => None,
    }
}

/// Does `name` appear as a bare identifier anywhere inside `e`? (`balances`,
/// `oldStaking`, …). The copy-pasted `expr_mentions_ident`.
pub fn expr_mentions_ident(e: &Expr, name: &str) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if let ExprKind::Ident(n) = &sub.kind {
            if n == name {
                found = true;
            }
        }
    });
    found
}

/// Does some `base[name]` index where `name` is the *bare* index identifier appear
/// in `e`? (the whitelist-lookup shape `trusted[target]`). The copy-pasted
/// `expr_indexes_ident`.
pub fn expr_indexes_ident(e: &Expr, name: &str) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if let ExprKind::Index { index: Some(idx), .. } = &sub.kind {
            if matches!(&idx.kind, ExprKind::Ident(n) if n == name) {
                found = true;
            }
        }
    });
    found
}

/// Is `e` the integer literal `1`? (the `- 1` ceil-division / off-by-one probe).
/// The copy-pasted `is_one`, shared by 4 rounding/integer detectors.
pub fn is_one(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Lit(Lit::Number(n)) if n.trim() == "1")
}

/// Is `e` a numeric literal equal to `val` (decimal)? Generalizes [`is_one`] for
/// detectors probing other small constants.
pub fn is_int_lit(e: &Expr, val: u128) -> bool {
    matches!(&e.kind, ExprKind::Lit(Lit::Number(n)) if n.trim().parse::<u128>() == Ok(val))
}

// =================================================== parameter / state-var queries

/// Is `name` a (named) parameter of `f`? The copy-pasted `is_param`.
pub fn is_param(f: &Function, name: &str) -> bool {
    f.params.iter().any(|p| p.name.as_deref() == Some(name))
}

/// Does the *root identifier* of `e` (after peeling casts) name a parameter of
/// `f`? Convenience for the very common "is this call's receiver a caller-supplied
/// parameter" check.
pub fn root_is_param(f: &Function, e: &Expr) -> bool {
    root_ident_peeled(e).is_some_and(|r| is_param(f, &r))
}

/// Does `contract` declare a state variable named `name` (any mutability)?
pub fn is_state_var(contract: &Contract, name: &str) -> bool {
    contract.state_vars.iter().any(|v| v.name == name)
}

/// Does `contract` declare `name` as a **settable** state variable — present and
/// neither `constant` nor `immutable`? This is the "settable hook / mutable target"
/// precision anchor from `silenced_privileged_callback` (`is_settable_hook`). An
/// empty `name` is never a state var.
pub fn is_settable_state_var(contract: &Contract, name: &str) -> bool {
    !name.is_empty()
        && contract
            .state_vars
            .iter()
            .any(|v| v.name == name && !(v.constant || v.immutable))
}

/// Is `name` declared as a `constant` **or** `immutable` state variable of
/// `contract`? (the "fixed address" suppression — governance cannot repoint it).
pub fn is_const_or_immutable_var(contract: &Contract, name: &str) -> bool {
    contract
        .state_vars
        .iter()
        .any(|v| v.name == name && (v.constant || v.immutable))
}

/// Does the root of `e` resolve to a state variable of the function's contract?
/// Looks the contract up via `cx`. Casts are peeled first.
pub fn root_is_state_var(cx: &AnalysisContext, f: &Function, e: &Expr) -> bool {
    let Some(root) = root_ident_peeled(e) else { return false };
    cx.contract_of(f.id).is_some_and(|c| is_state_var(c, &root))
}

/// Does the root of `e` resolve to a `constant`/`immutable` state variable of the
/// function's contract? The standard "is this operand fixed" suppression — a
/// constant/immutable callee or bound cannot be attacker/governance-steered.
/// Casts are peeled first.
pub fn root_is_const_or_immutable(cx: &AnalysisContext, f: &Function, e: &Expr) -> bool {
    let Some(root) = root_ident_peeled(e) else { return false };
    cx.contract_of(f.id).is_some_and(|c| is_const_or_immutable_var(c, &root))
}

/// Does the root of `e` resolve to a **settable** (non-constant/immutable) state
/// variable of the function's contract? Casts are peeled first.
pub fn root_is_settable_state_var(cx: &AnalysisContext, f: &Function, e: &Expr) -> bool {
    let Some(root) = root_ident_peeled(e) else { return false };
    cx.contract_of(f.id).is_some_and(|c| is_settable_state_var(c, &root))
}

// ============================================================= call-walk queries

/// An iterator-style view over the `Call` expressions in a function body, paired
/// with each call's source [`Span`]. This is the
/// `for s in &f.body { s.visit_exprs(|e| if let ExprKind::Call(c) = &e.kind { … }) }`
/// boilerplate (~40 copies) collapsed into combinators.
pub trait CallExt {
    /// All call expressions in the body, each with its span, in document order.
    fn calls(&self) -> Vec<(&Call, Span)>;
}

impl CallExt for Function {
    fn calls(&self) -> Vec<(&Call, Span)> {
        let mut out: Vec<(&Call, Span)> = Vec::new();
        for s in &self.body {
            s.visit_exprs(&mut |e: &Expr| {
                if let ExprKind::Call(c) = &e.kind {
                    out.push((c, e.span));
                }
            });
        }
        out
    }
}

/// Every call in `f`'s body whose [`CallKind`] equals `kind`, with spans, in
/// document order. (`calls_of_kind(f, CallKind::External)`.)
pub fn calls_of_kind(f: &Function, kind: CallKind) -> Vec<(&Call, Span)> {
    f.calls().into_iter().filter(|(c, _)| c.kind == kind).collect()
}

/// Span of the **first** call in `f`'s body (document order) for which `pred`
/// holds, if any. The workhorse for "find an external/low-level call with shape X"
/// scans — short-circuits on the first match.
pub fn first_call_where(f: &Function, mut pred: impl FnMut(&Call) -> bool) -> Option<Span> {
    for s in &f.body {
        let mut hit: Option<Span> = None;
        s.visit_exprs(&mut |e: &Expr| {
            if hit.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if pred(c) {
                    hit = Some(e.span);
                }
            }
        });
        if hit.is_some() {
            return hit;
        }
    }
    None
}

/// Does **any** call in `f`'s body satisfy `pred`?
pub fn any_call_where(f: &Function, pred: impl FnMut(&Call) -> bool) -> bool {
    first_call_where(f, pred).is_some()
}

/// Is `c` a particular builtin (e.g. [`Builtin::Require`])? A tiny readability
/// shim over the nested `matches!(c.kind, CallKind::Builtin(b) if b == ..)`.
pub fn is_builtin(c: &Call, b: Builtin) -> bool {
    matches!(c.kind, CallKind::Builtin(x) if x == b)
}

/// Is `c` a `require(...)` or `assert(...)` builtin? (the assertion-shaped guards
/// detectors scan for when deciding a value is validated).
pub fn is_require_or_assert(c: &Call) -> bool {
    matches!(c.kind, CallKind::Builtin(Builtin::Require) | CallKind::Builtin(Builtin::Assert))
}

// ===================================================================== reporting

/// Finalize a [`sluice_findings::FindingBuilder`] at a function + span — the
/// ubiquitous `cx.finish(b, f.id, span)` tail, named so call sites read as one
/// step. Equivalent to (and implemented as) `cx.finish(builder, fid, span)`.
pub fn finish_at(
    cx: &AnalysisContext,
    builder: sluice_findings::FindingBuilder,
    fid: FunctionId,
    span: Span,
) -> Finding {
    cx.finish(builder, fid, span)
}

/// Build a [`sluice_findings::FindingBuilder`] from the standard fields in one
/// declarative form, cutting the repeated
/// `FindingBuilder::new(self.id(), Cat).title(..).severity(..).confidence(..)
///  .dimension(..)…` chain. Behaviorally identical to writing the chain by hand —
/// it expands to exactly those builder calls, in this order:
/// `title -> severity -> confidence -> dimensions -> message -> recommendation`.
///
/// `dimensions` takes a list and is applied via
/// [`FindingBuilder::dimension`](sluice_findings::FindingBuilder::dimension) per
/// element (so the de-dup semantics are unchanged). `confidence`, `message`, and
/// `recommendation` are optional.
///
/// ```ignore
/// let b = report!(self, Category::OracleStaleness,
///     title = "Oracle price used without a staleness check",
///     severity = Severity::Medium,
///     confidence = 0.6,
///     dimensions = [Dimension::ValueFlow],
///     message = format!("`{}` reads a feed …", f.name),
///     recommendation = "After reading the feed, enforce …",
/// );
/// out.push(finish_at(cx, b, f.id, f.span));
/// ```
#[macro_export]
macro_rules! report {
    (
        $det:expr, $category:expr,
        title = $title:expr,
        severity = $severity:expr
        $(, confidence = $confidence:expr)?
        $(, dimensions = [ $($dim:expr),* $(,)? ])?
        $(, message = $message:expr)?
        $(, recommendation = $recommendation:expr)?
        $(,)?
    ) => {{
        let b = $crate::detectors::prelude::__finding_builder($det.id(), $category)
            .title($title)
            .severity($severity);
        $( let b = b.confidence($confidence); )?
        $( let b = b $( .dimension($dim) )* ; )?
        $( let b = b.message($message); )?
        $( let b = b.recommendation($recommendation); )?
        b
    }};
}

/// Internal shim used by [`report!`] so the macro does not depend on the call site
/// importing `FindingBuilder`. Not part of the public API.
#[doc(hidden)]
pub fn __finding_builder(
    id: &str,
    category: sluice_findings::Category,
) -> sluice_findings::FindingBuilder {
    sluice_findings::FindingBuilder::new(id, category)
}

// =========================================================== Uniswap v4 hooks
//
// The v4 hook detectors (`hook_return_delta_permission_gap`,
// `hook_permission_body_bitmap_mismatch`, and the v4 path of `flashloan_callback`)
// independently re-derived three primitives:
//
//   * a parser for the `getHookPermissions()` `Hooks.Permissions` literal,
//   * a "is this callback body a stub (`return selector;` / `revert`-only)" test,
//   * a "does this `return` carry a provably non-zero hook delta" test.
//
// They are gathered here so a new v4-hook detector reuses one canonical, tested
// implementation. Each is a behavior-preserving lift of the form that was already
// copy-pasted — nothing new is analysed.

/// The 14 `Hooks.Permissions` fields in their **struct-declaration order**
/// (`v4-core/src/libraries/Hooks.sol:49-64`). The index of a field here is the bit
/// position used by `validateHookPermissions` and by [`parse_hook_permissions`] for
/// the parsed permission vector; it is also the positional-construction order.
pub const HOOK_PERMISSION_FIELDS: [&str; 14] = [
    "beforeInitialize",
    "afterInitialize",
    "beforeAddLiquidity",
    "afterAddLiquidity",
    "beforeRemoveLiquidity",
    "afterRemoveLiquidity",
    "beforeSwap",
    "afterSwap",
    "beforeDonate",
    "afterDonate",
    "beforeSwapReturnDelta",
    "afterSwapReturnDelta",
    "afterAddLiquidityReturnDelta",
    "afterRemoveLiquidityReturnDelta",
];

/// Parse the `Hooks.Permissions` literal returned by a hook's `getHookPermissions()`
/// body `f` into a `[Option<bool>; 14]` keyed on [`HOOK_PERMISSION_FIELDS`]. Returns
/// `None` when `f`'s body contains no `Permissions(...)` construction at all — the
/// precision gate the v4-hook detectors hinge on (no literal ⇒ no signal ⇒ silent).
/// A slot is `Some(bool)` when that field resolved to a boolean literal and `None`
/// when it could not (field absent, or a non-literal / computed value); callers
/// treat `None` conservatively.
///
/// Both real `getHookPermissions` shapes are handled:
///   * **named** — `Permissions({beforeSwap: true, …})` / `Hooks.Permissions({…})`.
///     The IR lowers the construction to positional value args and drops the field
///     labels, so the labels are recovered from the construction's source text and
///     each `field: true|false` pair is read by name (order-independent — Solidity
///     allows reordering named struct fields).
///   * **positional** — `Permissions(b0, b1, …, b13)`, read straight from the IR
///     `Call.args` by index.
pub fn parse_hook_permissions(cx: &AnalysisContext, f: &Function) -> Option<[Option<bool>; 14]> {
    let mut found: Option<[Option<bool>; 14]> = None;
    for s in &f.body {
        if found.is_some() {
            break;
        }
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            let ExprKind::Call(call) = &e.kind else { return };
            if !call_constructs_permissions(call) {
                return;
            }
            found = Some(parse_permissions_call(cx, e, &call.args));
        });
    }
    found
}

/// Is `c` a construction of the `Hooks.Permissions` struct — a bare
/// `Permissions(...)` or a qualified `Hooks.Permissions(...)`? The callee name (or
/// the trailing member of the callee chain) must be exactly `Permissions`.
fn call_constructs_permissions(c: &Call) -> bool {
    if c.func_name.as_deref() == Some("Permissions") {
        return true;
    }
    callee_trailing_name(&c.callee) == Some("Permissions")
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

/// Parse one `Permissions(...)` call into the 14-slot vector. The construction's
/// source text picks the form: a struct-key `:` ⇒ named (recover labels from text,
/// resolve each field by name); otherwise ⇒ bare positional (the IR args by index).
fn parse_permissions_call(cx: &AnalysisContext, call_expr: &Expr, args: &[Expr]) -> [Option<bool>; 14] {
    let text = cx.scir.span_text(call_expr.span);
    if text.contains(':') {
        parse_named_permissions(text)
    } else {
        parse_positional_permissions(args)
    }
}

/// Named-field form: scan the literal source text for `field: true|false` pairs
/// (robust to arbitrary field ordering). A field whose value is not a literal
/// `true`/`false` (or is absent) stays `None`.
fn parse_named_permissions(text: &str) -> [Option<bool>; 14] {
    let mut out = [None; 14];
    for (idx, field) in HOOK_PERMISSION_FIELDS.iter().enumerate() {
        if let Some(val) = permission_field_bool(text, field) {
            out[idx] = Some(val);
        }
    }
    out
}

/// Find `field` used as a struct-literal key (`field` followed, modulo whitespace,
/// by `:`) and return the literal bool that follows, if any. Matches on whole-token
/// boundaries so `afterSwap` does not match inside `afterSwapReturnDelta`.
fn permission_field_bool(text: &str, field: &str) -> Option<bool> {
    let bytes = text.as_bytes();
    let flen = field.len();
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find(field) {
        let start = search_from + rel;
        let end = start + flen;
        search_from = end;

        // Left boundary: previous non-space char must not be an identifier char, so
        // `afterSwap` does not match the tail of `XafterSwap`.
        let left_ok = bytes[..start]
            .iter()
            .rev()
            .find(|b| !b.is_ascii_whitespace())
            .map(|b| !is_ident_byte(*b))
            .unwrap_or(true);
        if !left_ok {
            continue;
        }

        // Right boundary: the field name must be followed by `:` (after optional
        // whitespace) with no further identifier chars in between — so `afterSwap`
        // followed by `ReturnDelta…` (next char `R`, an identifier byte) is rejected.
        let mut j = end;
        if j < bytes.len() && is_ident_byte(bytes[j]) {
            continue;
        }
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b':' {
            continue;
        }
        j += 1; // past ':'
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        // Read the value token.
        let vstart = j;
        while j < bytes.len() && is_ident_byte(bytes[j]) {
            j += 1;
        }
        let val = &text[vstart..j];
        return match val {
            "true" => Some(true),
            "false" => Some(false),
            _ => None, // a non-literal (a variable / expression) — unknown
        };
    }
    None
}

/// Positional form `Permissions(b0, b1, …, b13)`: read each IR arg as a literal bool
/// by index. A non-literal arg leaves that slot `None`.
fn parse_positional_permissions(args: &[Expr]) -> [Option<bool>; 14] {
    let mut out = [None; 14];
    for (i, slot) in out.iter_mut().enumerate() {
        if let Some(a) = args.get(i) {
            if let ExprKind::Lit(Lit::Bool(b)) = &a.kind {
                *slot = Some(*b);
            }
        }
    }
    out
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Is `f` a **stub** hook-callback body — i.e. NOT a real implementation? A real
/// (non-stub) body writes storage, makes any call (external/internal/low-level), or
/// returns a value that is more than the bare selector / a constant / a zero-delta
/// sentinel. The `BaseHook`/`BaseTestHooks` defaults — `return X.selector;`,
/// `revert HookNotImplemented();`, an empty body, or `(selector, ZERO_DELTA, 0)` —
/// are all stubs. (The complement, "is a real implementation", is simply
/// `!is_stub_body(f)`.)
pub fn is_stub_body(f: &Function) -> bool {
    !is_real_implementation(f)
}

/// Inverse of [`is_stub_body`]: does `f` have a real (non-stub) callback body?
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
    body_has_nonconstant_return(f)
}

/// Is the body's *only* meaningful effect a `revert` — the `BaseTestHooks`
/// `revert HookNotImplemented();` shape — with no storage writes and no calls? Used
/// to escalate a declared-but-empty hook callback to a pool brick.
pub fn is_revert_only_body(f: &Function) -> bool {
    if !f.effects.storage_writes.is_empty() || !f.effects.call_sites.is_empty() {
        return false;
    }
    let mut saw_revert = false;
    let mut saw_other_effect = false;
    for s in &f.body {
        match &s.kind {
            StmtKind::Revert { .. } => saw_revert = true,
            // A `require(false)` / `revert(...)` builtin call as a lone statement
            // counts as a revert too.
            StmtKind::Expr(e) if expr_is_revert_builtin(e) => saw_revert = true,
            // Declarations / placeholders / empty are inert; anything else is "real".
            StmtKind::VarDecl { .. } | StmtKind::Placeholder => {}
            _ => saw_other_effect = true,
        }
    }
    saw_revert && !saw_other_effect
}

/// Is `e` a `revert(...)` builtin call statement?
fn expr_is_revert_builtin(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Call(c) if matches!(c.kind, CallKind::Builtin(Builtin::Revert)))
}

/// Does the body contain a `return` whose value is more than a bare selector or a
/// compile-time constant? `return X.selector;` and `return (X.selector, 0, 0);` (the
/// canonical no-op hook return) are not real implementations; a return that mentions
/// a parameter, a state read, or a computed expression is.
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

/// A returned expression is "nontrivial" if any component is neither a `*.selector`
/// member, a numeric/bool/address literal, nor a zero-delta sentinel construction
/// (`toBalanceDelta(0,0)`, `*.wrap(0)`, `*.ZERO_DELTA`). A tuple is nontrivial iff
/// any element is. The canonical `(selector, ZERO_DELTA, 0)` no-op return is treated
/// as trivial (a stub), matching the `BaseHook`/`BaseTestHooks` baseline.
fn return_value_is_nontrivial(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Tuple(items) => items.iter().flatten().any(return_value_is_nontrivial),
        // `X.selector` — the mandatory selector echo, not real logic.
        ExprKind::Member { member, .. } if member == "selector" => false,
        // Literals (incl. the `0` / `0,0` zero-delta args) are trivial.
        ExprKind::Lit(_) => false,
        // A zero-delta sentinel call: `toBalanceDelta(0,0)`, `BeforeSwapDelta.wrap(0)`.
        ExprKind::Call(c) if is_zero_delta_construction(c) => false,
        // A type-cast wrapping a trivial inner (`int128(0)`, `uint24(0)`).
        ExprKind::Call(c) if c.kind == CallKind::TypeCast => {
            c.args.iter().any(return_value_is_nontrivial)
        }
        // A lone identifier is trivial only if it reads like a zero/selector
        // sentinel; anything else (a param, a state read, a computed call) is real.
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
/// (`toBalanceDelta(0,0)`, `toBeforeSwapDelta(0,0)`, `BeforeSwapDelta.wrap(0)`).
fn is_zero_delta_construction(c: &Call) -> bool {
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

/// Span of the first `return` in `f` whose tuple element at `delta_idx` is a
/// provably-non-zero hook delta (per [`is_provably_nonzero_delta_return`]), if any.
pub fn first_nonzero_delta_return(cx: &AnalysisContext, f: &Function, delta_idx: usize) -> Option<Span> {
    let mut hit: Option<Span> = None;
    for s in &f.body {
        s.visit(&mut |stmt| {
            if hit.is_some() {
                return;
            }
            if let StmtKind::Return(Some(e)) = &stmt.kind {
                if let Some(delta) = return_delta_element(e, delta_idx) {
                    if is_provably_nonzero_delta_return(cx, f, delta) {
                        hit = Some(delta.span);
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

/// The delta tuple element of a `return` expression: for a tuple `return (a, b, c)`
/// it is the element at `delta_idx`; for a single-value `return x` it is `x` when
/// `delta_idx == 0`. `None` if the element is absent.
fn return_delta_element(ret: &Expr, delta_idx: usize) -> Option<&Expr> {
    match &ret.kind {
        ExprKind::Tuple(items) => items.get(delta_idx).and_then(|o| o.as_ref()),
        _ if delta_idx == 0 => Some(ret),
        _ => None,
    }
}

/// Is `d` a provably non-zero hook delta returned from a delta-bearing callback?
///
///   * NOT a zero sentinel: not `*.ZERO_DELTA`, not `to*Delta(0[,0])`, not
///     `*.wrap(0)`, not a literal `0` (incl. `int128(0)` / `int256(0)`).
///   * AND positively non-zero by one of: a `to*Delta`/`*.wrap` construction whose
///     argument is non-literal or a non-zero literal; provenance ∈
///     {AttackerInput, StorageState}; or a cast-peeled root that is a function
///     parameter or a state variable of the contract.
pub fn is_provably_nonzero_delta_return(cx: &AnalysisContext, f: &Function, d: &Expr) -> bool {
    if is_zero_delta_sentinel(d) {
        return false;
    }

    // (a) A delta constructor / `.wrap` with a non-zero / computed argument.
    if let Some(args) = delta_constructor_args(d) {
        if args.iter().any(|a| !is_zero_literal(peel_casts(a))) {
            return true;
        }
        // All-zero constructor args ⇒ zero delta.
        return false;
    }

    // (b) Provenance-derived: attacker input or storage state flowing into the
    // returned delta is a real (non-constant) value.
    let prov = cx.provenance_of(f.id, d);
    if prov.contains(ValueSource::AttackerInput) || prov.contains(ValueSource::StorageState) {
        return true;
    }

    // (c) The delta's (cast-peeled) root is a parameter or a state variable.
    root_is_param(f, d) || root_is_state_var(cx, f, d)
}

/// True if `d` is a recognised ZERO-delta sentinel:
///   * `*.ZERO_DELTA`,
///   * `to*Delta(0)` / `to*Delta(0, 0)` / `*.wrap(0)` (every arg a literal `0`),
///   * a literal `0` (including `int128(0)` / `int256(0)` casts of `0`).
fn is_zero_delta_sentinel(d: &Expr) -> bool {
    if let ExprKind::Member { member, .. } = &d.kind {
        if member == "ZERO_DELTA" {
            return true;
        }
    }
    if is_zero_literal(peel_casts(d)) {
        return true;
    }
    if let Some(args) = delta_constructor_args(d) {
        if !args.is_empty() && args.iter().all(|a| is_zero_literal(peel_casts(a))) {
            return true;
        }
    }
    false
}

/// If `d` is a delta-constructing call — a free function `to*Delta(...)` (e.g.
/// `toBalanceDelta`, `toBeforeSwapDelta`) or a `Type.wrap(...)` — return its argument
/// list. `None` if `d` is not such a construction.
fn delta_constructor_args(d: &Expr) -> Option<&[Expr]> {
    let ExprKind::Call(call) = &d.kind else { return None };
    match call.func_name.as_deref() {
        Some(n) if n.starts_with("to") && n.ends_with("Delta") => Some(&call.args),
        Some("wrap") => Some(&call.args),
        _ => None,
    }
}

/// True if `e` is a literal integer `0` (decimal `0`, hex `0x0`/`0x00…`).
fn is_zero_literal(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(Lit::Number(n)) => n.trim().trim_start_matches('-').parse::<u128>() == Ok(0),
        ExprKind::Lit(Lit::HexNumber(h)) => {
            let s = h.trim().trim_start_matches("0x").trim_start_matches("0X");
            !s.is_empty() && s.bytes().all(|b| b == b'0')
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyze_sources as _analyze_sources, Config};
    use sluice_ir::AssignOp;

    /// Parse one source and hand back its `Scir` so we can exercise the helpers
    /// against real IR (not hand-built nodes).
    fn scir_of(src: &str) -> sluice_ir::Scir {
        sluice_parse::parse_sources(vec![("t.sol".to_string(), src.to_string())]).scir
    }

    const SRC: &str = r#"
        interface IStaking { function migrateWithdraw(address s, uint256 a) external; }
        contract Stax {
            mapping(address => uint256) public balanceOf;
            mapping(address => bool) public trusted;
            address public hook;                 // settable
            address public immutable FIXED;      // not settable
            uint256 public constant ONE = 1;
            constructor(address f) { FIXED = f; }
            function migrate(address oldStaking, uint256 amount) external {
                require(trusted[oldStaking], "x");
                IStaking(oldStaking).migrateWithdraw(msg.sender, amount);
                balanceOf[msg.sender] += amount;
            }
        }
    "#;

    fn func<'a>(scir: &'a sluice_ir::Scir, name: &str) -> &'a Function {
        scir.all_functions().find(|f| f.name == name).expect("function present")
    }

    #[test]
    fn peel_casts_unwraps_interface_wrapper() {
        let scir = scir_of(SRC);
        let f = func(&scir, "migrate");
        let (call, _) = f
            .calls()
            .into_iter()
            .find(|(c, _)| c.kind == CallKind::External)
            .expect("external call");
        let recv = call.receiver.as_deref().expect("receiver");
        assert!(matches!(&recv.kind, ExprKind::Call(c) if c.kind == CallKind::TypeCast));
        assert!(matches!(&peel_casts(recv).kind, ExprKind::Ident(n) if n == "oldStaking"));
    }

    #[test]
    fn root_ident_variants() {
        let scir = scir_of(SRC);
        let f = func(&scir, "migrate");
        let (call, _) = f
            .calls()
            .into_iter()
            .find(|(c, _)| c.kind == CallKind::External)
            .expect("external call");
        let recv = call.receiver.as_deref().unwrap();
        assert_eq!(root_ident(recv), None);
        assert_eq!(root_ident_str(recv), None);
        assert_eq!(root_ident_peeled(recv).as_deref(), Some("oldStaking"));
    }

    #[test]
    fn param_and_statevar_classifiers() {
        let scir = scir_of(SRC);
        let f = func(&scir, "migrate");
        let c = scir.contract_named("Stax").unwrap();
        assert!(is_param(f, "oldStaking"));
        assert!(is_param(f, "amount"));
        assert!(!is_param(f, "hook"));
        assert!(is_state_var(c, "hook"));
        assert!(is_settable_state_var(c, "hook"));
        assert!(!is_settable_state_var(c, "FIXED"));
        assert!(!is_settable_state_var(c, "ONE"));
        assert!(is_const_or_immutable_var(c, "FIXED"));
        assert!(is_const_or_immutable_var(c, "ONE"));
        assert!(!is_const_or_immutable_var(c, "hook"));
        assert!(!is_settable_state_var(c, ""));
    }

    #[test]
    fn root_state_var_helpers_resolve_via_cx() {
        let cfg = Config::default();
        let parsed = sluice_parse::parse_sources(vec![("t.sol".into(), SRC.into())]);
        let scir = parsed.scir;
        let dataflow = sluice_dataflow::DataflowFacts::analyze(&scir);
        let invariants = sluice_invariant::InvariantFacts::mine(&scir);
        let frontier = sluice_frontier::FrontierFacts::analyze(&scir);
        let cx = AnalysisContext::new(&scir, &dataflow, &invariants, &frontier, &cfg);
        let f = func(&scir, "migrate");
        let hook = Expr::dummy(ExprKind::Ident("hook".into()));
        let fixed = Expr::dummy(ExprKind::Ident("FIXED".into()));
        let param = Expr::dummy(ExprKind::Ident("oldStaking".into()));
        assert!(root_is_state_var(&cx, f, &hook));
        assert!(root_is_settable_state_var(&cx, f, &hook));
        assert!(!root_is_const_or_immutable(&cx, f, &hook));
        assert!(root_is_const_or_immutable(&cx, f, &fixed));
        assert!(!root_is_settable_state_var(&cx, f, &fixed));
        assert!(!root_is_state_var(&cx, f, &param));
        assert!(root_is_param(f, &param));
    }

    #[test]
    fn call_walk_combinators() {
        let scir = scir_of(SRC);
        let f = func(&scir, "migrate");
        assert_eq!(calls_of_kind(f, CallKind::External).len(), 1);
        assert!(any_call_where(f, is_require_or_assert));
        assert!(first_call_where(f, |c| c.kind == CallKind::External).is_some());
        assert!(!any_call_where(f, |c| c.kind == CallKind::DelegateCall));
    }

    #[test]
    fn ident_probes() {
        let scir = scir_of(SRC);
        let f = func(&scir, "migrate");
        let indexed = f.body.iter().any(|s| {
            let mut hit = false;
            s.visit_exprs(&mut |e| {
                if expr_indexes_ident(e, "oldStaking") {
                    hit = true;
                }
            });
            hit
        });
        assert!(indexed);
        let mentioned = f.body.iter().any(|s| {
            let mut hit = false;
            s.visit_exprs(&mut |e| {
                if expr_mentions_ident(e, "amount") {
                    hit = true;
                }
            });
            hit
        });
        assert!(mentioned);
    }

    #[test]
    fn literal_probes() {
        let one = Expr::dummy(ExprKind::Lit(Lit::Number("1".into())));
        let two = Expr::dummy(ExprKind::Lit(Lit::Number("2".into())));
        assert!(is_one(&one));
        assert!(!is_one(&two));
        assert!(is_int_lit(&two, 2));
        assert!(!is_int_lit(&two, 3));
    }

    #[test]
    fn assign_op_reexport_compiles() {
        let _ = AssignOp::Assign;
        let _ = _analyze_sources;
    }

    #[test]
    fn report_macro_matches_manual_builder() {
        use crate::detector::Detector;
        use sluice_findings::{Category, Dimension, Severity};
        struct D;
        impl crate::detector::Detector for D {
            fn id(&self) -> &'static str {
                "oracle-staleness"
            }
            fn category(&self) -> Category {
                Category::OracleStaleness
            }
            fn description(&self) -> &'static str {
                "x"
            }
            fn run(&self, _cx: &AnalysisContext) -> Vec<Finding> {
                vec![]
            }
        }
        let d = D;
        let via_macro = report!(d, Category::OracleStaleness,
            title = "T",
            severity = Severity::High,
            confidence = 0.6,
            dimensions = [Dimension::ValueFlow, Dimension::Frontier],
            message = "M",
            recommendation = "R",
        )
        .build();
        let manual = sluice_findings::FindingBuilder::new("oracle-staleness", Category::OracleStaleness)
            .title("T")
            .severity(Severity::High)
            .confidence(0.6)
            .dimension(Dimension::ValueFlow)
            .dimension(Dimension::Frontier)
            .message("M")
            .recommendation("R")
            .build();
        assert_eq!(via_macro.title, manual.title);
        assert_eq!(via_macro.detector, manual.detector);
        assert_eq!(via_macro.category, manual.category);
        assert_eq!(via_macro.severity, manual.severity);
        assert_eq!(via_macro.confidence, manual.confidence);
        assert_eq!(via_macro.dimensions, manual.dimensions);
        assert_eq!(via_macro.message, manual.message);
        assert_eq!(via_macro.recommendation, manual.recommendation);
        assert_eq!(via_macro.references, manual.references);
    }
}
