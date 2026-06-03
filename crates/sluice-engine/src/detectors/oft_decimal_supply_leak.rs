//! Asymmetric burn/mint in a cross-chain OFT send — a global-supply-conservation
//! leak through decimal-dust / decimal-scaling.
//!
//! ## The class
//!
//! An omnichain fungible token (LayerZero OFT) keeps a *single* global supply
//! spread across many chains. A `send()` debits (burns / escrows) some
//! `amountSentLD` on the **source** chain and emits a cross-chain message; the
//! **destination** chain credits (mints / releases) some `amountReceivedLD`. The
//! one invariant that keeps the mesh solvent is conservation:
//!
//! ```text
//!     burned_on_source  ==  minted_on_destination
//! ```
//!
//! That invariant breaks the moment the *received* amount is computed by a
//! different decimal path than the *sent* amount. OFTs unify denominations by a
//! "shared decimals" (SD) ↔ "local decimals" (LD) conversion with a
//! `decimalConversionRate = 10 ** (localDecimals - sharedDecimals)`, and dust is
//! stripped with `_removeDust(x) = (x / rate) * rate`. If the source debits a
//! dust-removed / SD-rounded value but the destination credits a *differently*
//! scaled value (`_toLD(amountSD)` re-expanded, a fee carved off only one side, a
//! child `_debit` override that returns `amountReceivedLD != amountSentLD`), then
//! burn ≠ mint: tokens are minted from nothing on the destination, or burned and
//! never re-minted on the source. Either direction is a supply leak.
//!
//! ## What we flag
//!
//! Two concrete shapes, both gated to an OFT-like contract:
//!
//!   * **(A) `send` debit/credit split.** An externally-reachable, state-mutating
//!     function destructures a `_debit*`-named call into a *(sent, received)* pair
//!     of locals, then feeds the **received** local (not the sent one) into the
//!     cross-chain message build / `_lzSend`, while never asserting
//!     `sent == received`. The destination is told to mint `amountReceivedLD`, but
//!     the source only burned `amountSentLD`; nothing pins them equal.
//!
//!   * **(B) `_debit`/`_credit` definition.** A `_debit*`-named function whose body
//!     returns a *(sent, received)* tuple where the **received** value is assigned
//!     from a *decimal-scaled / dust-removed* expression (`_removeDust(...)`,
//!     `* decimalConversionRate`, `/ decimalConversionRate`, `/ 10 ** (...)`) that
//!     is *not* the identical `sent` variable, and equality is never enforced.
//!
//! ## Suppression
//!
//! The default OFTCore implementation sets `amountReceivedLD = amountSentLD;` (the
//! same dust-removed value is both burned and minted) — burn == mint, no leak. We
//! suppress whenever the function pins the two equal: an `amountReceivedLD =
//! amountSentLD` assignment, or a `require(sent == received)` / `assert` of the
//! conservation. We also stay silent unless the contract genuinely looks like an
//! OFT (so a plain ERC-20 with a `debit`-ish helper never trips).
//!
//! Real target: LayerZero v2 `OFTCore.sol` (`_debit` / `_credit` / `_removeDust` /
//! `decimalConversionRate`, `send` / `_lzReceive`).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{AssignOp, BinOp, Expr, ExprKind, Function, Span};

use super::prelude::*;

pub struct OftDecimalSupplyLeakDetector;

impl Detector for OftDecimalSupplyLeakDetector {
    fn id(&self) -> &'static str {
        "oft-decimal-supply-leak"
    }
    fn category(&self) -> Category {
        Category::OftDecimalSupplyLeak
    }
    fn description(&self) -> &'static str {
        "Cross-chain OFT send burns amountSentLD but credits a differently decimal-scaled amountReceivedLD \
         without enforcing burn == mint (global-supply leak)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Both shapes require an OFT-like surrounding contract; this is the
            // single strongest precision anchor (keeps plain ERC-20s / vaults out).
            if !contract_is_oft_like(cx, f) {
                continue;
            }

            // ---- (A) send-side debit/credit split.
            if f.is_externally_reachable() && f.is_state_mutating() {
                if let Some(span) = find_send_split(cx, f) {
                    out.push(finish_at(
                        cx,
                        report!(self, Category::OftDecimalSupplyLeak,
                            title = "OFT send debits amountSentLD but messages amountReceivedLD without pinning burn == mint",
                            severity = Severity::Medium,
                            confidence = 0.6,
                            dimensions = [Dimension::Invariant],
                            message = format!(
                                "`{}` debits the source by `amountSentLD` via `_debit(...)` but forwards the \
                                 *received* amount (`amountReceivedLD`) into the cross-chain message / `_lzSend`, \
                                 telling the destination chain to credit (mint) `amountReceivedLD`. The two are \
                                 never pinned equal (`require(amountSentLD == amountReceivedLD)`), and `_debit` is \
                                 overridable — a child that decimal-scales or fee-adjusts the received amount \
                                 differently from the burned amount makes burn != mint, leaking the OFT's global \
                                 supply (mint-from-nothing on the destination, or burn-without-remint on the source).",
                                f.name
                            ),
                            recommendation =
                                "Conserve supply across the hop: either enforce `amountSentLD == amountReceivedLD` \
                                 for the default (no-fee) path, or ensure the exact amount burned/escrowed on the \
                                 source is the exact amount the destination is instructed to mint/release. Apply \
                                 the identical dust-removal / decimal scaling to both legs (a single \
                                 `_removeDust`/SD-round result reused for burn and mint), and account any fee as an \
                                 explicit on-chain transfer rather than a silent burn/mint asymmetry.",
                        ),
                        f.id,
                        span,
                    ));
                    continue; // one finding per function
                }
            }

            // ---- (B) the _debit / _credit definition itself.
            if let Some(span) = find_debit_def_split(cx, f) {
                out.push(finish_at(
                    cx,
                    report!(self, Category::OftDecimalSupplyLeak,
                        title = "OFT _debit/_credit returns a decimal-scaled received amount not pinned to the sent amount",
                        severity = Severity::Medium,
                        confidence = 0.55,
                        dimensions = [Dimension::Invariant],
                        message = format!(
                            "`{}` returns a (sent, received) pair where the *received* amount is assigned from a \
                             decimal-conversion / dust-removal expression (`_removeDust` / `* decimalConversionRate` \
                             / `/ decimalConversionRate` / `/ 10 ** (...)`) that is not the identical sent value, \
                             and the conservation `sent == received` is never asserted. On a cross-chain OFT the \
                             source burns the sent amount while the destination mints the received amount; an \
                             asymmetric decimal round between the two breaks global supply conservation.",
                            f.name
                        ),
                        recommendation =
                            "Burn and mint must move the same scaled quantity. Round once with `_removeDust` and \
                             reuse that single value for both the amount debited and the amount the message tells \
                             the remote to credit (the default OFTCore does `amountReceivedLD = amountSentLD;`). If \
                             a fee is intended, surface it explicitly instead of letting a decimal mismatch silently \
                             create or destroy supply.",
                    ),
                    f.id,
                    span,
                ));
            }
        }
        out
    }
}

// --------------------------------------------------------------------------
// Shape (A): send-side debit/credit split
// --------------------------------------------------------------------------

/// Detect the `send`-style split: a `_debit*`-named call destructured into a
/// (sent, received) pair, the *received* local forwarded to the cross-chain
/// message / `_lzSend`, with no `sent == received` guard. Returns the span of the
/// `_debit` destructuring statement.
fn find_send_split(cx: &AnalysisContext, f: &Function) -> Option<Span> {
    // Cheap gate: the body must call a `_debit*` function (the source-side burn)
    // and a message-dispatch (`_lzSend` / build-message). We read this from the
    // effect summary's internal-call list (names preserved verbatim there).
    let calls_debit = f
        .effects
        .internal_calls
        .iter()
        .any(|n| name_is_debit(n));
    if !calls_debit || !calls_cross_chain_dispatch(f) {
        return None;
    }

    // Find the `(sent, received) = _debit(...)` destructuring and recover the two
    // local names. The IR records a tuple-destructure assignment whose target is a
    // `Tuple([...])` and whose value is the `_debit` call; the destructured *local*
    // names are not in that tuple (they appear as `TypeName`s), so we recover them
    // from the source span of the assignment statement.
    let (sent, received, debit_span) = find_debit_destructure(cx, f)?;

    // The received local must actually feed the cross-chain message path. We look
    // for it being passed as an argument to a build-message / `_lzSend` style call
    // (i.e. `_buildMsgAndOptions(_sendParam, amountReceivedLD)` /
    // `_lzSend(..., message, ...)` fed from it). Using the *received* value here —
    // rather than the *sent* value — is the asymmetry signature.
    if !received_feeds_dispatch(f, &received) {
        return None;
    }

    // Suppress when the function pins the two equal anywhere (the default no-fee
    // path, or an explicit conservation assertion).
    if pins_equal(cx, f, &sent, &received) {
        return None;
    }

    // Suppress when the *concrete* `_debit` callee resolvable in scope provably
    // returns sent == received (its body pins them equal). In the real OFTCore,
    // `_debit` is abstract / overridable, so this never resolves and the leak
    // surface stands — which is exactly the point. But a deployment whose
    // in-scope `_debit` is the default no-fee shape (`amountReceivedLD =
    // amountSentLD;`) is genuinely safe.
    if resolved_debit_pins_equal(cx, f) {
        return None;
    }

    Some(debit_span)
}

/// Does a `_debit*`-named callee of `f`, resolvable in scope and with a body,
/// provably pin its returned (sent, received) equal? Looks through the resolved
/// internal callees; if any in-scope `_debit` with a body is a default no-fee
/// shape, the send conserves supply.
fn resolved_debit_pins_equal(cx: &AnalysisContext, f: &Function) -> bool {
    for &cid in &f.callees {
        let Some(callee) = cx.scir.function(cid) else { continue };
        if !callee.has_body || !name_is_debit(&callee.name) {
            continue;
        }
        if callee.returns.len() != 2 {
            continue;
        }
        let (Some(sent), Some(received)) =
            (callee.returns[0].name.clone(), callee.returns[1].name.clone())
        else {
            continue;
        };
        if pins_equal(cx, callee, &sent, &received) {
            return true;
        }
    }
    false
}

/// Locate the `(sent, received) = _debit(...)` statement and return
/// `(sent_name, received_name, span)`. The names are parsed from the source text
/// of the assignment (the IR tuple carries only the declared types).
fn find_debit_destructure(cx: &AnalysisContext, f: &Function) -> Option<(String, String, Span)> {
    let mut result: Option<(String, String, Span)> = None;
    for s in &f.body {
        if result.is_some() {
            break;
        }
        s.visit_exprs(&mut |e: &Expr| {
            if result.is_some() {
                return;
            }
            let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind else {
                return;
            };
            // Target must be a 2-element tuple destructure.
            let ExprKind::Tuple(items) = &target.kind else { return };
            if items.len() != 2 {
                return;
            }
            // Value must be a call to a `_debit*`-named function.
            let ExprKind::Call(call) = &value.kind else { return };
            if !call.func_name.as_deref().map(name_is_debit).unwrap_or(false) {
                return;
            }
            // Recover the two destructured local names from the source text of the
            // assignment target, e.g. `(uint256 amountSentLD, uint256 amountReceivedLD)`.
            if let Some((a, b)) = parse_two_destructured_names(&cx.source_text(target.span)) {
                // We only care about the canonical (sent, received) ordering: the
                // first should be a sent/burn-ish name, the second a received-ish
                // name. If the names don't classify, fall back to positional.
                let (sent, received) = canonical_sent_received(&a, &b);
                result = Some((sent, received, e.span));
            }
        });
    }
    result
}

/// Does the *received* local feed the cross-chain dispatch (build-message /
/// `_lzSend`)? We scan for a dispatch-shaped call that takes `received` as an
/// argument, or — covering the `_buildMsgAndOptions(_sendParam, amountReceivedLD)`
/// → `message` → `_lzSend(message)` chain — a build call that takes `received`.
fn received_feeds_dispatch(f: &Function, received: &str) -> bool {
    let mut hit = false;
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            if hit {
                return;
            }
            let ExprKind::Call(call) = &e.kind else { return };
            let is_dispatch = call
                .func_name
                .as_deref()
                .map(|n| name_is_cross_chain_dispatch(n) || name_is_build_msg(n))
                .unwrap_or(false);
            if !is_dispatch {
                return;
            }
            if call.args.iter().any(|a| expr_mentions_ident_ci(a, received)) {
                hit = true;
            }
        });
        if hit {
            break;
        }
    }
    hit
}

// --------------------------------------------------------------------------
// Shape (B): the _debit / _credit definition
// --------------------------------------------------------------------------

/// Detect a `_debit*` definition that returns a (sent, received) tuple where the
/// received return value is assigned from a *decimal-scaled* expression that is
/// not the identical sent value, with no equality enforced. Returns the span of
/// the offending received-assignment.
fn find_debit_def_split(cx: &AnalysisContext, f: &Function) -> Option<Span> {
    // Must be a `_debit*`-named function that returns exactly two values
    // (amountSentLD, amountReceivedLD).
    if !name_is_debit(&f.name) {
        return None;
    }
    if f.returns.len() != 2 {
        return None;
    }
    let sent = f.returns[0].name.clone()?;
    let received = f.returns[1].name.clone()?;
    // Both legs should look like the sent/received pair (defensive: skip odd
    // 2-tuples that aren't this shape).
    if !name_is_sent(&sent) || !name_is_received(&received) {
        return None;
    }

    // Suppress the default `amountReceivedLD = amountSentLD;` (and explicit
    // conservation assertions): burn == mint, no leak.
    if pins_equal(cx, f, &sent, &received) {
        return None;
    }

    // Find a write to the *received* return var whose RHS is a decimal
    // conversion / dust-removal that does NOT reduce to the sent var.
    let mut hit: Option<Span> = None;
    for s in &f.body {
        if hit.is_some() {
            break;
        }
        s.visit_exprs(&mut |e: &Expr| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind else {
                return;
            };
            if target.simple_name() != Some(received.as_str()) {
                return;
            }
            // RHS is the identical sent var → that's the safe (suppressed) form;
            // pins_equal already handled it, but be robust to ordering.
            if value.simple_name() == Some(sent.as_str()) {
                return;
            }
            // RHS must be a decimal-scaling / dust-removing expression.
            if expr_is_decimal_scaling(cx, value) {
                hit = Some(e.span);
            }
        });
    }
    hit
}

/// Is `e` a decimal-conversion / dust-removal expression — the asymmetric-scale
/// signature? Matches:
///   * a `_removeDust(...)` / `_toLD(...)` / `_toSD(...)`-style call,
///   * `x * decimalConversionRate` / `x / decimalConversionRate`,
///   * `x / 10 ** (...)` / `x * 10 ** (...)` (raw decimal power),
///   * `(x / rate) * rate` dust-removal.
fn expr_is_decimal_scaling(cx: &AnalysisContext, e: &Expr) -> bool {
    // Call form: `_removeDust(_amountLD)`, `_toLD(sd)`, `_toSD(ld)`, ...
    if let ExprKind::Call(c) = &e.kind {
        if c.func_name.as_deref().map(name_is_decimal_helper).unwrap_or(false) {
            return true;
        }
    }
    // Binary `*` / `/` with a decimal-conversion-rate or `10 ** (...)` operand.
    if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
        if matches!(op, BinOp::Mul | BinOp::Div)
            && (operand_is_decimal_factor(lhs) || operand_is_decimal_factor(rhs))
        {
            return true;
        }
    }
    // Textual fallback for nested `(x / rate) * rate` or `/ 10 ** (...)` that the
    // shallow structural checks above might split across nodes.
    let t = normalize_ws(&cx.source_text(e.span));
    t.contains("decimalconversionrate")
        || t.contains("/10**")
        || t.contains("*10**")
        || t.contains("removedust")
}

/// An operand that denotes a decimal conversion factor: the
/// `decimalConversionRate` state var, or a `10 ** (...)` power.
fn operand_is_decimal_factor(e: &Expr) -> bool {
    if let Some(r) = root_ident_str(e) {
        if r.eq_ignore_ascii_case("decimalConversionRate") || r.to_ascii_lowercase().contains("conversionrate")
        {
            return true;
        }
    }
    // `10 ** (...)`
    if let ExprKind::Binary { op: BinOp::Pow, lhs, .. } = &e.kind {
        if is_int_lit(lhs, 10) {
            return true;
        }
    }
    false
}

// --------------------------------------------------------------------------
// Shared suppression: burn == mint pinned
// --------------------------------------------------------------------------

/// True if the function pins `sent` and `received` equal — either an assignment
/// `received = sent` / `sent = received`, or a `require`/`assert` comparing them
/// with `==`. This is the documented safe form (`amountReceivedLD = amountSentLD;`)
/// and the explicit-conservation form.
fn pins_equal(cx: &AnalysisContext, f: &Function, sent: &str, received: &str) -> bool {
    let mut pinned = false;
    for s in &f.body {
        if pinned {
            break;
        }
        s.visit_exprs(&mut |e: &Expr| {
            if pinned {
                return;
            }
            // Names may originate from lowercased `source_text` (shape A) while IR
            // identifiers preserve original case — compare case-insensitively.
            match &e.kind {
                // received = sent  (or  sent = received)
                ExprKind::Assign { op: AssignOp::Assign, target, value } => {
                    let t = target.simple_name();
                    let v = value.simple_name();
                    if (opt_eq_ci(t, received) && opt_eq_ci(v, sent))
                        || (opt_eq_ci(t, sent) && opt_eq_ci(v, received))
                    {
                        pinned = true;
                    }
                }
                // sent == received  inside a require/assert/if
                ExprKind::Binary { op: BinOp::Eq, lhs, rhs } => {
                    let l = root_ident_str(lhs);
                    let r = root_ident_str(rhs);
                    if (opt_eq_ci(l, sent) && opt_eq_ci(r, received))
                        || (opt_eq_ci(l, received) && opt_eq_ci(r, sent))
                    {
                        pinned = true;
                    }
                }
                _ => {}
            }
        });
    }
    if pinned {
        return true;
    }
    // Textual fallback: an explicit conservation assertion the structural pass
    // might miss (e.g. names wrapped in casts).
    let src = normalize_ws(&cx.source_text(f.span));
    let s = sent.to_ascii_lowercase();
    let r = received.to_ascii_lowercase();
    src.contains(&format!("{s}=={r}")) || src.contains(&format!("{r}=={s}"))
}

// --------------------------------------------------------------------------
// Name classifiers + small parsers
// --------------------------------------------------------------------------

/// A `_debit`-style name (the source-side burn/escrow): `_debit`, `_debitView`,
/// `debit`, `debitFrom`, ...
fn name_is_debit(name: &str) -> bool {
    name.to_ascii_lowercase().contains("debit")
}

/// A "sent"/"burn"-side amount name.
fn name_is_sent(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("sent") || l.contains("burn") || l.contains("debit") || l.contains("amountld")
}

/// A "received"/"credit"-side amount name.
fn name_is_received(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("receiv") || l.contains("credit") || l.contains("mint")
}

/// Put the two destructured names into canonical (sent, received) order: prefer a
/// received-ish name in the second slot. If exactly one classifies as received,
/// it becomes `received`; otherwise keep positional (first=sent, second=received).
fn canonical_sent_received(a: &str, b: &str) -> (String, String) {
    let a_recv = name_is_received(a);
    let b_recv = name_is_received(b);
    if b_recv && !a_recv {
        (a.to_string(), b.to_string())
    } else if a_recv && !b_recv {
        (b.to_string(), a.to_string())
    } else {
        (a.to_string(), b.to_string())
    }
}

/// A cross-chain dispatch / send primitive name (`_lzSend`, `lzSend`, `_send`,
/// `sendCompose`, `endpoint.send`, ...).
fn name_is_cross_chain_dispatch(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("lzsend") || l == "_send" || l.contains("sendmessage") || l.contains("sendpacket")
}

/// Does the function dispatch a cross-chain message (build + send)? Read off the
/// internal-call list so it's cheap and name-faithful.
fn calls_cross_chain_dispatch(f: &Function) -> bool {
    f.effects
        .internal_calls
        .iter()
        .any(|n| name_is_cross_chain_dispatch(n) || name_is_build_msg(n))
}

/// A build-message helper name (`_buildMsgAndOptions`, `buildMessage`, `encode`).
fn name_is_build_msg(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("buildmsg") || l.contains("buildmessage") || l.contains("buildandoptions")
}

/// A decimal-conversion helper name (`_removeDust`, `_toLD`, `_toSD`,
/// `removeDust`, `toLocalDecimals`, ...).
fn name_is_decimal_helper(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("removedust") || l == "_told" || l == "_tosd" || l.contains("todecimals") || l.contains("scaledecimals")
}

/// Parse the two names from a destructured tuple target's source text,
/// `"(uint256 amountSentLD, uint256 amountReceivedLD)"` → `("amountSentLD",
/// "amountReceivedLD")`. Returns `None` if it does not look like a 2-element
/// declaration tuple. (The text is the already-lowercased, comment-stripped form
/// from `cx.source_text`.)
fn parse_two_destructured_names(src: &str) -> Option<(String, String)> {
    let inner = src.trim().trim_start_matches('(').trim_end_matches(')');
    let parts: Vec<&str> = inner.split(',').collect();
    if parts.len() != 2 {
        return None;
    }
    let name_of = |decl: &str| -> Option<String> {
        // Last whitespace-separated token of `uint256 amountSentLD` is the name.
        let tok = decl.split_whitespace().last()?;
        let tok = tok.trim();
        if tok.is_empty() || !tok.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
        // Guard against a slot that is only a type (`uint256`) with no name — a
        // bare type has no trailing identifier distinct from the type keyword.
        Some(tok.to_string())
    };
    let a = name_of(parts[0])?;
    let b = name_of(parts[1])?;
    Some((a, b))
}

/// Collapse all ASCII whitespace (so `sent == received` matches `sent==received`).
fn normalize_ws(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

/// `Option<&str>` equals `name`, case-insensitively. (Names recovered from the
/// lowercased `cx.source_text` must compare against the original-case IR idents.)
fn opt_eq_ci(opt: Option<&str>, name: &str) -> bool {
    opt.map(|s| s.eq_ignore_ascii_case(name)).unwrap_or(false)
}

/// Case-insensitive [`expr_mentions_ident`]: does `name` appear as a bare
/// identifier anywhere in `e`, ignoring ASCII case?
fn expr_mentions_ident_ci(e: &Expr, name: &str) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if let ExprKind::Ident(n) = &sub.kind {
            if n.eq_ignore_ascii_case(name) {
                found = true;
            }
        }
    });
    found
}

// --------------------------------------------------------------------------
// OFT-like contract gate
// --------------------------------------------------------------------------

/// True if the surrounding contract genuinely looks like a LayerZero OFT — by
/// name, by an OFT-shaped state var (`decimalConversionRate`, `msgInspector`,
/// `peers`), or by a sibling OFT-shaped function (`_debit`, `_credit`,
/// `_removeDust`, `sharedDecimals`, `_lzSend`, `_lzReceive`). This is the central
/// precision anchor: plain ERC-20s, vaults, and the FP corpora have none of these.
fn contract_is_oft_like(cx: &AnalysisContext, f: &Function) -> bool {
    let Some(c) = cx.contract_of(f.id) else { return false };

    let l = c.name.to_ascii_lowercase();
    if l.contains("oft") || l.contains("omnichain") {
        return true;
    }

    // OFT-shaped state.
    const STATEY: &[&str] = &["decimalconversionrate", "msginspector", "sharedlecimals"];
    if c.state_vars.iter().any(|v| {
        let vl = v.name.to_ascii_lowercase();
        STATEY.iter().any(|k| vl.contains(k)) || vl.contains("decimalconversion")
    }) {
        return true;
    }

    // OFT-shaped sibling functions: the conversion + debit/credit + LZ-messaging
    // surface. We require this combination (a debit/credit *and* a decimal/LZ
    // primitive) so a lone `debit`-named helper on an unrelated contract is not
    // enough.
    let mut has_debit_credit = false;
    let mut has_oft_primitive = false;
    for g in cx.scir.functions_of(c.id) {
        let gl = g.name.to_ascii_lowercase();
        if gl.contains("debit") || gl.contains("credit") {
            has_debit_credit = true;
        }
        if gl.contains("removedust")
            || gl.contains("shareddecimals")
            || gl == "_told"
            || gl == "_tosd"
            || gl.contains("lzreceive")
            || gl.contains("lzsend")
        {
            has_oft_primitive = true;
        }
    }
    has_debit_credit && has_oft_primitive
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fired(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.detector == "oft-decimal-supply-leak")
    }

    // VULN: an OFT whose `send` debits `amountSentLD` but forwards
    // `amountReceivedLD` into the cross-chain message, and a `_debit` override that
    // carves a fee off the *received* leg only (so burn != mint), with no
    // conservation guard. This is the asymmetric supply-leak shape.
    const VULN: &str = r#"
pragma solidity ^0.8.20;
abstract contract OFTCoreLike {
    uint256 public immutable decimalConversionRate;
    function sharedDecimals() public pure returns (uint8) { return 6; }
    function _removeDust(uint256 _amountLD) internal view returns (uint256) {
        return (_amountLD / decimalConversionRate) * decimalConversionRate;
    }
    function _buildMsgAndOptions(uint256 _amountLD) internal pure returns (bytes memory message) {
        message = abi.encode(_amountLD);
    }
    function _lzSend(bytes memory message) internal returns (bytes32) { return keccak256(message); }
    function send(uint256 amountLD, uint32 dstEid) external returns (bytes32 guid) {
        (uint256 amountSentLD, uint256 amountReceivedLD) = _debit(msg.sender, amountLD, dstEid);
        bytes memory message = _buildMsgAndOptions(amountReceivedLD);
        guid = _lzSend(message);
    }
    function _debit(address from, uint256 amountLD, uint32 dstEid)
        internal returns (uint256 amountSentLD, uint256 amountReceivedLD)
    {
        amountSentLD = _removeDust(amountLD);
        // BUG: received is a *different* decimal scaling of the input than what was burned.
        amountReceivedLD = (amountLD / decimalConversionRate) * decimalConversionRate - 1;
    }
}
"#;

    // SAFE: the default OFTCore shape — `amountReceivedLD = amountSentLD;` (burn ==
    // mint, identical dust-removed value used for both legs).
    const SAFE: &str = r#"
pragma solidity ^0.8.20;
abstract contract OFTCoreLike {
    uint256 public immutable decimalConversionRate;
    function sharedDecimals() public pure returns (uint8) { return 6; }
    function _removeDust(uint256 _amountLD) internal view returns (uint256) {
        return (_amountLD / decimalConversionRate) * decimalConversionRate;
    }
    function _buildMsgAndOptions(uint256 _amountLD) internal pure returns (bytes memory message) {
        message = abi.encode(_amountLD);
    }
    function _lzSend(bytes memory message) internal returns (bytes32) { return keccak256(message); }
    function send(uint256 amountLD, uint32 dstEid) external returns (bytes32 guid) {
        (uint256 amountSentLD, uint256 amountReceivedLD) = _debit(msg.sender, amountLD, dstEid);
        bytes memory message = _buildMsgAndOptions(amountReceivedLD);
        guid = _lzSend(message);
    }
    function _debit(address from, uint256 amountLD, uint32 dstEid)
        internal returns (uint256 amountSentLD, uint256 amountReceivedLD)
    {
        amountSentLD = _removeDust(amountLD);
        amountReceivedLD = amountSentLD; // burn == mint
    }
}
"#;

    // SAFE control: a non-OFT contract with a same-named `_debit` helper and a
    // decimal scaling — must stay silent (the OFT-contract gate excludes it).
    const SAFE_NON_OFT: &str = r#"
pragma solidity ^0.8.20;
contract Ledger {
    uint256 public rate;
    function withdraw(uint256 amountLD) external returns (uint256 a, uint256 b) {
        (a, b) = _debit(amountLD);
    }
    function _debit(uint256 amountLD) internal view returns (uint256 amountSentLD, uint256 amountReceivedLD) {
        amountSentLD = amountLD;
        amountReceivedLD = amountLD / rate;
    }
}
"#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fired(&fs), "expected oft-decimal-supply-leak, got {:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fired(&fs), "should be silent on burn==mint default, got {:?}", fs);
    }

    #[test]
    fn silent_on_non_oft() {
        let fs = run(SAFE_NON_OFT);
        assert!(!fired(&fs), "should be silent on non-OFT ledger, got {:?}", fs);
    }
}
