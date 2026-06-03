//! Post-expiry dual-index skim — a maturity-boundary value leak unique to
//! yield-tokenization / rate-bearing redemption math.
//!
//! Within a single redemption/settlement function, the **same** index→amount
//! conversion (`assetToSy` / `syToAsset` / a `*ToSy*` / `*ToAsset*` exchange-rate
//! conversion) is evaluated **twice on the same principal**, but with two
//! *different* index/rate operands, and the two readings are taken across an
//! `isExpired()` / `block.timestamp >= expiry` / `>= maturity` boundary:
//!
//!   * one conversion uses a **live** index (a function parameter / local that the
//!     caller passes in, or `*current*` index read this block); and
//!   * the other uses a **frozen / stored** index — a state field captured at the
//!     maturity boundary (`postExpiry.firstPYIndex`, a `first*Index`,
//!     `*Snapshot*`, `*Stored*`, `*AtExpiry*` member).
//!
//! Their **difference** (`assetToSy(stored, x) - assetToSy(live, x)`) is then
//! routed to a **treasury / fee sink** (accumulated into a `*treasury*` / `*fee*`
//! accumulator, or returned as an `*interest*ForTreasury*` quantity). Because the
//! frozen index is set **lazily on first-touch** post-expiry
//! (`_setPostExpiryData()` runs only when `firstPYIndex == 0`), an attacker who is
//! the *first* caller after expiry chooses the block at which the freeze point is
//! captured, and can therefore time/inflate the live-vs-frozen gap that the
//! treasury skims — a maturity-boundary dual-index skim.
//!
//! This is the shape of Pendle `PendleYieldToken._calcSyRedeemableFromPY`
//! (contracts/core/YieldContracts/PendleYieldToken.sol):
//!
//! ```solidity
//! syToUser = SYUtils.assetToSy(indexCurrent, amountPY);              // LIVE index
//! if (isExpired()) {
//!     uint256 totalSyRedeemable = SYUtils.assetToSy(postExpiry.firstPYIndex, amountPY); // FROZEN index
//!     syInterestPostExpiry = totalSyRedeemable - syToUser;           // difference -> treasury
//! }
//! ```
//! with `_setPostExpiryData()` capturing `firstPYIndex = _pyIndexCurrent()` lazily
//! on the first post-expiry touch; `syInterestPostExpiry` accumulates into
//! `postExpiry.totalSyInterestForTreasury`, later swept to `treasury`.
//!
//! Distinct from `snapshot-redeem-asymmetry` (which is about a *balance* clamped
//! one-directionally with a reserve debited at the pre-clamp value — no
//! expiry-index, no second conversion of the same principal). Here the two
//! readings are of the **same conversion of the same amount at two indices**,
//! gated by an *expiry/maturity* predicate, with the delta sent to a fee sink.
//!
//! Precision anchors (all required) so this stays quiet on ordinary code:
//!   * the function reads an **expiry/maturity predicate** (`isExpired()` or a
//!     `block.timestamp >= expiry/maturity` comparison);
//!   * there are **two calls to the same conversion-named function** whose **index
//!     argument differs**, one a **frozen/stored** index (a member / `first*` /
//!     `*stored*` / `*snapshot*` / `*atexpiry*` field) and the other a **live**
//!     index (a parameter / `*current*` value);
//!   * the protocol takes their **difference** (a `Sub` of the two conversion
//!     results, or the post-expiry branch computes a residual) and that residual
//!     reaches a **treasury / fee sink** (a `*treasury*` / `*fee*` /
//!     `*fortreasury*` accumulator or return).
//!
//! SUPPRESS when both indices are deterministic on-chain time (neither operand is
//! a stored/frozen snapshot — e.g. both are `block.timestamp`/`expiry` arithmetic),
//! since then there is no attacker-timeable freeze point.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function, Span};

use super::prelude::*;

pub struct PostExpiryDualIndexDetector;

impl Detector for PostExpiryDualIndexDetector {
    fn id(&self) -> &'static str {
        "post-expiry-dual-index"
    }
    fn category(&self) -> Category {
        Category::PostExpiryDualIndex
    }
    fn description(&self) -> &'static str {
        "Redemption converts the same principal at a frozen vs a live index across an expiry boundary and skims the difference to a treasury/fee sink (Pendle YT _calcSyRedeemableFromPY)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // Only concrete bodies can perform the dual conversion + skim. The
            // load-bearing math lives in an internal `view` helper
            // (`_calcSyRedeemableFromPY`), so we do NOT require state-mutating —
            // only a real body, and not a modifier/constructor.
            if !f.has_body || f.is_modifier() || f.is_constructor() {
                continue;
            }
            // Interfaces / libraries declare no redemption logic.
            if cx.contract_of(f.id).map(|c| c.is_interface()).unwrap_or(false) {
                continue;
            }

            let Some(hit) = analyze_function(f) else { continue };

            let b = report!(self, Category::PostExpiryDualIndex,
                title = "Post-expiry dual-index skim: same principal converted at a frozen vs live index, difference routed to treasury",
                severity = Severity::Medium,
                confidence = 0.6,
                dimensions = [Dimension::Invariant, Dimension::ValueFlow],
                message = format!(
                    "`{fname}` converts the same principal twice through `{conv}(...)` across an \
                     expiry/maturity boundary (`{guard}`): once with a **live** index (`{live}`) and once \
                     with a **frozen/stored** index (`{frozen}`), then takes their difference \
                     (`{conv}(frozen, x) - {conv}(live, x)`) and routes that residual to a treasury/fee \
                     sink (`{sink}`). This is a maturity-boundary dual-index skim (Pendle \
                     `PendleYieldToken._calcSyRedeemableFromPY`): the redeemer is paid at the live index \
                     while the treasury accrues the gap to the frozen index. Because the freeze point is \
                     set **lazily on first-touch** post-expiry (it is captured the first time the \
                     post-expiry data is set, i.e. when the stored index is still zero), the *first* \
                     caller after expiry chooses the block at which that index is frozen and can \
                     time/inflate the live-vs-frozen spread the treasury skims.",
                    fname = f.name,
                    conv = hit.conv_name,
                    guard = hit.guard_text,
                    live = hit.live_arg,
                    frozen = hit.frozen_arg,
                    sink = hit.sink,
                ),
                recommendation =
                    "Make the two index readings agree, or remove the attacker-timeable freeze point. \
                     Capture the post-expiry freeze index deterministically at the maturity timestamp \
                     (not lazily on the first post-expiry interaction), and compute the treasury's \
                     post-expiry interest from a single, time-anchored index rather than the difference \
                     between a live and a first-touch-frozen index. Equivalently, pay the redeemer and \
                     credit the treasury from one consistent index so the split cannot be steered by \
                     whoever transacts first after expiry.",
            );
            out.push(finish_at(cx, b, f.id, hit.span));
        }
        out
    }
}

// --------------------------------------------------------------------- analysis

/// A matched dual-index skim in one function.
struct Hit {
    /// Name of the conversion function called twice (`assetToSy`).
    conv_name: String,
    /// Textual expiry/maturity guard (`isexpired()` / `block.timestamp >= expiry`).
    guard_text: String,
    /// Textual live-index argument (`indexcurrent`).
    live_arg: String,
    /// Textual frozen/stored-index argument (`postexpiry.firstpyindex`).
    frozen_arg: String,
    /// Textual treasury/fee sink the difference reaches.
    sink: String,
    /// Span to anchor the finding (the frozen-index conversion call).
    span: Span,
}

/// A single conversion call `conv(index, amount)` we care about, with the index
/// operand classified.
struct ConvCall {
    /// Lowercased callee name (`assettosy`).
    name: String,
    /// Lowercased textual rendering of the index/rate operand — the first argument
    /// of the SYUtils-style conversion `conv(index, amount)`, or the receiver for a
    /// `index.convert(amount)` method form.
    index_text: String,
    span: Span,
}

fn analyze_function(f: &Function) -> Option<Hit> {
    // (1) The function must consult an expiry/maturity predicate. Without a
    //     maturity boundary this is not the post-expiry class (it would be an
    //     ordinary two-rate conversion).
    let guard_text = expiry_guard_text(f)?;

    // (2) Collect every conversion call (`*ToSy`/`*ToAsset`/`*Index*` convert) and
    //     classify its index operand as frozen-stored vs live.
    let calls = collect_conversion_calls(f);
    if calls.len() < 2 {
        return None;
    }

    // Find a pair: same conversion name, one FROZEN index, one LIVE index, with
    // distinct index operands.
    let mut pair: Option<(&ConvCall, &ConvCall)> = None;
    'outer: for a in &calls {
        for b in &calls {
            if a.span.start == b.span.start {
                continue;
            }
            if a.name != b.name {
                continue;
            }
            // a = frozen reading, b = live reading.
            if is_frozen_index(&a.index_text)
                && is_live_index(&b.index_text, f)
                && a.index_text != b.index_text
            {
                pair = Some((a, b));
                break 'outer;
            }
        }
    }
    let (frozen_call, live_call) = pair?;

    // SUPPRESS: if neither operand is a genuine stored/frozen snapshot (e.g. both
    // are block.timestamp/expiry arithmetic), there is no attacker-timeable freeze
    // point. `is_frozen_index` already requires a stored/snapshot marker, so a
    // deterministic-time pair never reaches here; this is the explicit guard.
    if is_deterministic_time(&frozen_call.index_text) && is_deterministic_time(&live_call.index_text) {
        return None;
    }

    // (3) The two conversions' results must feed a DIFFERENCE (`Sub`), and that
    //     residual must reach a treasury/fee sink.
    let sink = difference_routed_to_sink(f, frozen_call, live_call)?;

    Some(Hit {
        conv_name: frozen_call.name.clone(),
        guard_text,
        live_arg: live_call.index_text.clone(),
        frozen_arg: frozen_call.index_text.clone(),
        sink,
        span: frozen_call.span,
    })
}

/// Textual expiry/maturity predicate used by `f`, if any: an `isExpired()` /
/// `isCurrentlyExpired()` / `*expired*` call, or a `block.timestamp >=
/// expiry/maturity` ordering comparison. Returns the (lowercased) source text of
/// the matched construct for the message.
fn expiry_guard_text(f: &Function) -> Option<String> {
    // (a) a call to an `*expired*` predicate (`isExpired()`).
    let mut found: Option<String> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if let Some(n) = &c.func_name {
                    let l = n.to_ascii_lowercase();
                    if l.contains("expired") || l.contains("ismatured") || l.contains("aftermaturity") {
                        found = Some(l);
                    }
                }
            }
        });
        if found.is_some() {
            return found;
        }
    }
    // (b) a `block.timestamp >= expiry` / `... >= maturity` ordering comparison.
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
                if op.is_ordering() && mentions_block_time(e) && mentions_expiry(lhs, rhs) {
                    found = Some(render_path(e).unwrap_or_else(|| "block.timestamp >= expiry".into()));
                }
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// Does this expression subtree reference `block.timestamp` / `block.number`?
fn mentions_block_time(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |n| {
        if let ExprKind::Member { base, member } = &n.kind {
            let m = member.to_ascii_lowercase();
            if (m == "timestamp" || m == "number")
                && matches!(&base.kind, ExprKind::Ident(b) if b.eq_ignore_ascii_case("block"))
            {
                found = true;
            }
        }
    });
    found
}

/// Does either operand reference an `expiry` / `maturity` / `expir*` identifier?
fn mentions_expiry(lhs: &Expr, rhs: &Expr) -> bool {
    let has = |e: &Expr| {
        let mut f = false;
        e.visit(&mut |n| {
            let nm = match &n.kind {
                ExprKind::Ident(s) => Some(s.to_ascii_lowercase()),
                ExprKind::Member { member, .. } => Some(member.to_ascii_lowercase()),
                _ => None,
            };
            if let Some(nm) = nm {
                if nm.contains("expir") || nm.contains("maturity") {
                    f = true;
                }
            }
        });
        f
    };
    has(lhs) || has(rhs)
}

/// Collect every conversion call in `f`: a call whose name is an index→amount /
/// amount→index exchange-rate conversion (`assetToSy`, `syToAsset`, `*ToSy*`,
/// `*ToAsset*`, `convertToAssets`-style, or a `*Index*`/`*Rate*` convert), with
/// its **index operand** identified. We treat the *first positional argument* as
/// the index for the SYUtils form `conv(index, amount)`; if there is exactly one
/// argument and a receiver (the `index.convert(amount)` method form) the receiver
/// is the index.
fn collect_conversion_calls(f: &Function) -> Vec<ConvCall> {
    let mut out = Vec::new();
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            let ExprKind::Call(c) = &e.kind else { return };
            let Some(raw) = &c.func_name else { return };
            let name = raw.to_ascii_lowercase();
            if !is_conversion_name(&name) {
                return;
            }
            // Identify the index operand.
            let index: Option<&Expr> = if !c.args.is_empty() {
                // SYUtils form `assetToSy(index, amount)` — first arg is the index.
                Some(&c.args[0])
            } else {
                c.receiver.as_deref()
            };
            let Some(index) = index else { return };
            out.push(ConvCall {
                name,
                index_text: render_path(index).unwrap_or_default(),
                span: e.span,
            });
        });
    }
    out
}

/// Conversion-function names: SYUtils-style exchange-rate conversions between a
/// rate-bearing wrapper and its underlying asset. Deliberately narrow — these are
/// the names that carry an *index/rate* as their leading operand.
fn is_conversion_name(name: &str) -> bool {
    // `assetToSy`, `syToAsset`, `assetToSyUp`, `syToAssetUp`, and the generic
    // `*ToSy*` / `*ToAsset*` shapes; plus an explicit index/rate "apply"/"convert".
    name.contains("tosy")
        || name.contains("toasset")
        || name.contains("toshares")
        || name.contains("tounderlying")
        || name.contains("applyindex")
        || name.contains("applyrate")
        || ((name.contains("convert") || name.contains("calc")) && (name.contains("index") || name.contains("rate")))
}

/// A **frozen / stored** index operand: a snapshot of the index captured at (or
/// before) the maturity boundary. Recognized by name shape — a stored state field
/// such as `postExpiry.firstPYIndex`, or any `first*index`, `*stored*`,
/// `*snapshot*`, `*atexpiry*`, `*expiryindex*`, `*frozen*`, `*postexpiry*`
/// reference. Must NOT itself look like a deterministic-time value.
fn is_frozen_index(text: &str) -> bool {
    if text.is_empty() || is_deterministic_time(text) {
        return false;
    }
    let t = text;
    // `postExpiry.firstPYIndex` and friends.
    (t.contains("first") && t.contains("index"))
        || t.contains("firstpyindex")
        || t.contains("postexpiry")
        || t.contains("stored")
        || t.contains("snapshot")
        || t.contains("atexpiry")
        || t.contains("expiryindex")
        || t.contains("frozen")
        || t.contains("cachedindex")
        || (t.contains("expiry") && t.contains("index"))
}

/// A **live** index operand: a value supplied fresh this call — a function
/// parameter (the caller passes the current index), a `*current*` index, or a
/// `_pyIndexCurrent()`-style read. We accept "parameter" via the function's param
/// list, and otherwise a `*current*`/`*live*`/`*now*` name. Must not be a frozen
/// snapshot.
fn is_live_index(text: &str, f: &Function) -> bool {
    if text.is_empty() || is_frozen_index(text) {
        return false;
    }
    if text.contains("current") || text.contains("live") || text.contains("indexnow") {
        return true;
    }
    // A bare parameter name (`indexCurrent`, `index`) — the live index handed in.
    // Match the root identifier against the function's parameters.
    let root = text.split(['.', '[']).next().unwrap_or(text);
    is_param(f, root)
        || f.params
            .iter()
            .any(|p| p.name.as_deref().map(|n| n.eq_ignore_ascii_case(root)).unwrap_or(false))
}

/// Deterministic on-chain time arithmetic (suppression input): the operand reads
/// `block.timestamp` / `block.number` / a bare `expiry`/`maturity` constant — i.e.
/// it is derived from chain time, not a stored snapshot. Such a pair has no
/// attacker-timeable freeze point.
fn is_deterministic_time(text: &str) -> bool {
    text.contains("block.timestamp")
        || text.contains("block.number")
        || ((text.contains("expiry") || text.contains("maturity")) && !text.contains("index"))
}

/// The two conversion results feed a **difference** (`a - b`) and that residual
/// reaches a treasury/fee sink. We look for a `Sub` whose two operands each
/// reference (textually) one of the two conversion readings — either the inline
/// conversion-call text, or a local the reading was bound to. The residual is a
/// sink when EITHER:
///   * the function writes a treasury/fee accumulator or references a treasury/fee
///     address (the `_redeemPY` / direct-transfer shapes), OR
///   * the `Sub` is **assigned to a variable / return parameter whose name signals
///     a protocol residual** destined for the treasury — `*forTreasury*`,
///     `*Fee*`, or an `*interest*`/`*residual*`/`*skim*` quantity tied to the
///     expiry boundary (`syInterestPostExpiry`). This last case is the real Pendle
///     `_calcSyRedeemableFromPY`, where the helper *returns* the post-expiry
///     interest and the caller (`_redeemPY`) accumulates it into the treasury.
/// Returns the sink's textual marker.
fn difference_routed_to_sink(f: &Function, frozen: &ConvCall, live: &ConvCall) -> Option<String> {
    // Names of locals that each conversion reading is bound to (`syToUser`,
    // `totalSyRedeemable`), so the `Sub` can reference the locals rather than the
    // inline call. We approximate by scanning `VarDecl`/`Assign` whose initializer
    // contains the conversion call's span.
    let frozen_local = local_bound_to(f, frozen.span);
    let live_local = live_local_or_call(f, live.span);

    // A `Sub` whose lhs/rhs reference the frozen and live readings (in either
    // order — but the value-leak direction is frozen - live). Capture the span of
    // the matched `Sub` so we can find what it is assigned to.
    let mut sub_span: Option<Span> = None;
    let frozen_keys = keys_for(frozen, &frozen_local);
    let live_keys = keys_for(live, &live_local);
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if sub_span.is_some() {
                return;
            }
            if let ExprKind::Binary { op: BinOp::Sub, lhs, rhs } = &e.kind {
                let lt = render_path(lhs).unwrap_or_default();
                let rt = render_path(rhs).unwrap_or_default();
                // Frozen on the larger side (lhs), live subtracted (rhs) is the
                // canonical leak; also accept the mirror for robustness.
                let lhs_frozen = frozen_keys.iter().any(|k| text_refs(&lt, lhs, k));
                let rhs_live = live_keys.iter().any(|k| text_refs(&rt, rhs, k));
                let lhs_live = live_keys.iter().any(|k| text_refs(&lt, lhs, k));
                let rhs_frozen = frozen_keys.iter().any(|k| text_refs(&rt, rhs, k));
                if (lhs_frozen && rhs_live) || (lhs_live && rhs_frozen) {
                    sub_span = Some(e.span);
                }
            }
        });
        if sub_span.is_some() {
            break;
        }
    }
    let sub_span = sub_span?;

    // (a) a direct treasury/fee sink in this function (accumulator / transfer).
    if let Some(s) = treasury_sink(f) {
        return Some(s);
    }

    // (b) the residual is assigned to a variable / return param whose NAME marks it
    //     as a protocol residual for the treasury. The local the difference is
    //     bound to (`syInterestPostExpiry`) is the cross-function carrier.
    if let Some(name) = local_bound_to(f, sub_span) {
        if is_residual_sink_name(&name) {
            return Some(name);
        }
    }
    // Also accept when a RETURN PARAMETER of the function itself is residual-named
    // (the difference flows out as the named return), even if the binding wasn't a
    // direct assignment we resolved above.
    for p in &f.returns {
        if let Some(n) = &p.name {
            if is_residual_sink_name(&n.to_ascii_lowercase()) {
                return Some(n.to_ascii_lowercase());
            }
        }
    }
    None
}

/// A variable / return-parameter name that marks the residual as destined for the
/// protocol treasury rather than the user: an explicit `*treasury*`/`*fee*` name,
/// or a post-expiry/post-maturity **interest** / **residual** / **skim** quantity
/// (the cross-function carrier `syInterestPostExpiry`). Deliberately requires the
/// interest/residual term to co-occur with an expiry/maturity/post marker so an
/// ordinary `interest`/`fee` local elsewhere does not qualify.
fn is_residual_sink_name(name: &str) -> bool {
    let l = name;
    if is_treasury_name(l) {
        return true;
    }
    let has_residual_word =
        l.contains("interest") || l.contains("residual") || l.contains("skim") || l.contains("surplus");
    let has_boundary_word = l.contains("postexpiry")
        || l.contains("post_expiry")
        || l.contains("postmaturity")
        || l.contains("afterexpiry")
        || l.contains("atexpiry")
        || l.contains("expiry")
        || l.contains("maturity");
    has_residual_word && has_boundary_word
}

/// All textual keys that identify a conversion reading: the local it was bound to
/// (if any) plus the index-operand text (so the `Sub` operand can be matched
/// whether it references the local `syToUser` or the inline call).
fn keys_for(call: &ConvCall, local: &Option<String>) -> Vec<String> {
    let mut v = Vec::new();
    if let Some(l) = local {
        if !l.is_empty() {
            v.push(l.clone());
        }
    }
    // The index text is a strong inline discriminator (`postexpiry.firstpyindex`).
    if !call.index_text.is_empty() {
        v.push(call.index_text.clone());
    }
    v
}

/// Does the rendered text `t` (or the expr subtree `e`) reference key `k` as a
/// whole identifier path? `t` is already a render of `e`; we match `k` as a
/// substring on identifier boundaries.
fn text_refs(t: &str, e: &Expr, k: &str) -> bool {
    if k.is_empty() {
        return false;
    }
    if ident_substr(t, k) {
        return true;
    }
    // Fall back to a structural mention (handles the operand being a bare local).
    let mut found = false;
    e.visit(&mut |n| match &n.kind {
        ExprKind::Ident(s) if s.eq_ignore_ascii_case(k) => found = true,
        _ => {}
    });
    found
}

/// `k` appears in `t` at identifier boundaries (case-insensitive; `t`,`k` are
/// already lowercased renders).
fn ident_substr(t: &str, k: &str) -> bool {
    let tb = t.as_bytes();
    let kb = k.as_bytes();
    let is_id = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'[' || c == b']';
    let mut from = 0usize;
    while let Some(rel) = t[from..].find(k) {
        let i = from + rel;
        let before_ok = i == 0 || !is_id(tb[i - 1]);
        let after = i + kb.len();
        let after_ok = after >= tb.len() || !tb[after].is_ascii_alphanumeric() && tb[after] != b'_';
        if before_ok && after_ok {
            return true;
        }
        from = i + 1;
    }
    false
}

/// The local variable name a conversion reading at `call_span` is bound to, if the
/// reading appears as a `VarDecl`/`Assign` initializer (`uint256 totalSyRedeemable
/// = SYUtils.assetToSy(...)` → `"totalsyredeemable"`, `syToUser = SYUtils...` →
/// `"sytouser"`).
fn local_bound_to(f: &Function, call_span: Span) -> Option<String> {
    let mut name: Option<String> = None;
    for s in &f.body {
        s.visit(&mut |st| {
            if name.is_some() {
                return;
            }
            match &st.kind {
                sluice_ir::StmtKind::VarDecl { name: Some(n), init: Some(init), .. } => {
                    if span_contains(init, call_span) {
                        name = Some(n.to_ascii_lowercase());
                    }
                }
                sluice_ir::StmtKind::Expr(e) => {
                    if let ExprKind::Assign { target, value, .. } = &e.kind {
                        if span_contains(value, call_span) {
                            name = render_path(target);
                        }
                    }
                }
                _ => {}
            }
        });
        if name.is_some() {
            break;
        }
    }
    name
}

/// Like [`local_bound_to`] but for the live reading; identical logic (kept as a
/// separate name for call-site clarity).
fn live_local_or_call(f: &Function, call_span: Span) -> Option<String> {
    local_bound_to(f, call_span)
}

/// Does expression `e` (transitively) contain a node whose span starts at
/// `target.start` (same file)? Used to tie a conversion call to the local it
/// initializes.
fn span_contains(e: &Expr, target: Span) -> bool {
    let mut found = false;
    e.visit(&mut |n| {
        if n.span.file == target.file && n.span.start == target.start {
            found = true;
        }
    });
    found
}

/// A treasury / fee sink in `f`: a `*treasury*` / `*fee*` / `*fortreasury*`
/// identifier-or-member that the function writes to (compound `+=` accumulator or
/// a transfer target / returned quantity). Returns the matched textual marker.
fn treasury_sink(f: &Function) -> Option<String> {
    // (a) a state write whose var name looks like a treasury/fee accumulator
    //     (`postExpiry.totalSyInterestForTreasury`, `feeAccrued`, ...).
    for w in &f.effects.storage_writes {
        if is_treasury_name(&w.var) || is_treasury_name(&w.path) {
            return Some(w.path.to_ascii_lowercase());
        }
    }
    // (b) any treasury/fee identifier or member referenced in the body (a return
    //     of `*ForTreasury*`, a `treasury` transfer target).
    let mut sink: Option<String> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if sink.is_some() {
                return;
            }
            e.visit(&mut |n| {
                if sink.is_some() {
                    return;
                }
                let nm = match &n.kind {
                    ExprKind::Ident(s) => Some(s.to_ascii_lowercase()),
                    ExprKind::Member { member, .. } => Some(member.to_ascii_lowercase()),
                    _ => None,
                };
                if let Some(nm) = nm {
                    if is_treasury_name(&nm) {
                        sink = Some(nm);
                    }
                }
            });
        });
        if sink.is_some() {
            break;
        }
    }
    sink
}

/// A treasury / protocol-fee sink name.
fn is_treasury_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("treasury")
        || l.contains("fortreasury")
        || l.contains("protocolfee")
        || l.contains("feerecipient")
        || l.contains("feereceiver")
        || l.contains("feevault")
        || l.contains("interestfee")
        || (l.contains("fee") && (l.contains("accru") || l.contains("collect") || l.contains("owed")))
}

/// Render an identifier / member / index chain to a canonical lowercased string
/// (`a.b[c]` -> `a.b[c]`). Returns `None` for shapes we don't render (literals,
/// calls). Mirrors the helper used by sibling detectors.
fn render_path(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.to_ascii_lowercase()),
        ExprKind::Member { base, member } => {
            Some(format!("{}.{}", render_path(base)?, member.to_ascii_lowercase()))
        }
        ExprKind::Index { base, index } => {
            let b = render_path(base)?;
            let idx = index.as_ref().and_then(|i| render_path(i)).unwrap_or_default();
            Some(format!("{b}[{idx}]"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "post-expiry-dual-index")
    }

    // VULN — the exact Pendle `PendleYieldToken._calcSyRedeemableFromPY` shape:
    // the principal is converted at the LIVE `indexCurrent` for the user, and at
    // the FROZEN `postExpiry.firstPYIndex` for the total, under `isExpired()`, and
    // the difference accrues to `postExpiry.totalSyInterestForTreasury`.
    const VULN: &str = r#"
        pragma solidity ^0.8.17;
        library SYUtils {
            uint256 internal constant ONE = 1e18;
            function assetToSy(uint256 exchangeRate, uint256 assetAmount) internal pure returns (uint256) {
                return (assetAmount * ONE) / exchangeRate;
            }
        }
        contract PendleYieldToken {
            uint256 public immutable expiry;
            struct PostExpiryData { uint128 firstPYIndex; uint128 totalSyInterestForTreasury; }
            PostExpiryData public postExpiry;
            function isExpired() public view returns (bool) { return block.timestamp >= expiry; }
            function _calcSyRedeemableFromPY(uint256 amountPY, uint256 indexCurrent)
                internal
                view
                returns (uint256 syToUser, uint256 syInterestPostExpiry)
            {
                syToUser = SYUtils.assetToSy(indexCurrent, amountPY);
                if (isExpired()) {
                    uint256 totalSyRedeemable = SYUtils.assetToSy(postExpiry.firstPYIndex, amountPY);
                    syInterestPostExpiry = totalSyRedeemable - syToUser;
                }
            }
        }
    "#;

    // VULN variant — explicit `block.timestamp >= expiry` inline guard (no helper),
    // difference transferred to a `treasury` address rather than accumulated.
    const VULN_INLINE_GUARD: &str = r#"
        pragma solidity ^0.8.17;
        library Rate {
            function toAsset(uint256 idx, uint256 amt) internal pure returns (uint256) { return amt * idx / 1e18; }
        }
        contract YT {
            uint256 public expiry;
            uint256 public storedIndexAtExpiry;
            address public treasury;
            function settle(uint256 amount, uint256 indexNow) external returns (uint256 toUser) {
                toUser = Rate.toAsset(indexNow, amount);
                if (block.timestamp >= expiry) {
                    uint256 atFreeze = Rate.toAsset(storedIndexAtExpiry, amount);
                    uint256 fee = atFreeze - toUser;
                    payable(treasury).transfer(fee);
                }
            }
        }
    "#;

    // SAFE — both indices are deterministic on-chain time (no stored snapshot): the
    // conversion is evaluated at two block-derived rates, so there is no
    // attacker-timeable freeze point. Must stay silent.
    const SAFE_DETERMINISTIC_TIME: &str = r#"
        pragma solidity ^0.8.17;
        library SYUtils {
            function assetToSy(uint256 rate, uint256 amt) internal pure returns (uint256) { return amt * 1e18 / rate; }
        }
        contract Linear {
            uint256 public expiry;
            address public treasury;
            function calc(uint256 amount) external view returns (uint256 a, uint256 b) {
                a = SYUtils.assetToSy(block.timestamp, amount);
                if (block.timestamp >= expiry) {
                    uint256 c = SYUtils.assetToSy(expiry, amount);
                    b = c - a;
                }
            }
        }
    "#;

    // SAFE — no expiry/maturity boundary at all: a frozen vs live index conversion
    // exists and the difference goes to a fee, but it is not gated by maturity, so
    // it is an ordinary two-rate computation, not the post-expiry class.
    const SAFE_NO_EXPIRY: &str = r#"
        pragma solidity ^0.8.17;
        library SYUtils {
            function assetToSy(uint256 rate, uint256 amt) internal pure returns (uint256) { return amt * 1e18 / rate; }
        }
        contract NoExpiry {
            uint256 public storedIndex;
            uint256 public feeAccrued;
            function calc(uint256 amount, uint256 indexCurrent) external {
                uint256 a = SYUtils.assetToSy(indexCurrent, amount);
                uint256 b = SYUtils.assetToSy(storedIndex, amount);
                feeAccrued += b - a;
            }
        }
    "#;

    // SAFE — the difference is NOT routed to a treasury/fee sink: both readings are
    // paid back to the user (no protocol skim). Must stay silent.
    const SAFE_NO_TREASURY: &str = r#"
        pragma solidity ^0.8.17;
        library SYUtils {
            function assetToSy(uint256 rate, uint256 amt) internal pure returns (uint256) { return amt * 1e18 / rate; }
        }
        contract YT {
            uint256 public expiry;
            uint256 public firstPYIndex;
            function isExpired() public view returns (bool) { return block.timestamp >= expiry; }
            function calc(uint256 amount, uint256 indexCurrent) external view returns (uint256 userOut) {
                uint256 atLive = SYUtils.assetToSy(indexCurrent, amount);
                if (isExpired()) {
                    uint256 atFrozen = SYUtils.assetToSy(firstPYIndex, amount);
                    userOut = atFrozen - atLive;
                }
            }
        }
    "#;

    // SAFE — only ONE conversion call (no dual reading). A single conversion gated
    // by expiry with a treasury sink is not a dual-index skim.
    const SAFE_SINGLE_CONV: &str = r#"
        pragma solidity ^0.8.17;
        library SYUtils {
            function assetToSy(uint256 rate, uint256 amt) internal pure returns (uint256) { return amt * 1e18 / rate; }
        }
        contract YT {
            uint256 public expiry;
            uint256 public firstPYIndex;
            address public treasury;
            function isExpired() public view returns (bool) { return block.timestamp >= expiry; }
            function calc(uint256 amount) external view returns (uint256 out) {
                if (isExpired()) {
                    out = SYUtils.assetToSy(firstPYIndex, amount);
                }
            }
        }
    "#;

    #[test]
    fn fires_on_pendle_calcsyredeemable_shape() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_inline_guard_transfer_shape() {
        assert!(fires(VULN_INLINE_GUARD), "{:#?}", run(VULN_INLINE_GUARD));
    }

    #[test]
    fn silent_on_deterministic_time_indices() {
        assert!(!fires(SAFE_DETERMINISTIC_TIME), "{:#?}", run(SAFE_DETERMINISTIC_TIME));
    }

    #[test]
    fn silent_without_expiry_boundary() {
        assert!(!fires(SAFE_NO_EXPIRY), "{:#?}", run(SAFE_NO_EXPIRY));
    }

    #[test]
    fn silent_without_treasury_sink() {
        assert!(!fires(SAFE_NO_TREASURY), "{:#?}", run(SAFE_NO_TREASURY));
    }

    #[test]
    fn silent_on_single_conversion() {
        assert!(!fires(SAFE_SINGLE_CONV), "{:#?}", run(SAFE_SINGLE_CONV));
    }
}
