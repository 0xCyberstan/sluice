//! Zero-margin timing window — a finalize / veto / unbonding window whose boundary
//! comparison admits the **exact boundary timestamp**, so two competing finalizers
//! can both be valid in the *same block / same timestamp*.
//!
//! ## The shape
//!
//! A staking / restaking protocol queues a privileged action (a slash, a
//! withdrawal, a stake update) at time `start`, then gates the *finalize* / *veto*
//! / *complete* step behind a delay window:
//!
//! ```solidity
//! // Karak SlasherLib.finalizeSlashing  (~L119)
//! if (queuedSlashing.timestamp + Constants.SLASHING_VETO_WINDOW > block.timestamp) {
//!     revert MinSlashingDelayNotPassed();
//! }
//! // Karak VaultLib.validateQueuedWithdrawal  (~L35)
//! if (qdWithdrawal.start + Constants.MIN_WITHDRAWAL_DELAY > block.timestamp) {
//!     revert MinWithdrawDelayNotPassed();
//! }
//! // Karak SlasherLib.validateRequestSlashingParams  (~L65)
//! if (block.timestamp < self.operatorState[op].nextSlashableTimestamp[dss]) {
//!     revert SlashingCooldownNotPassed();
//! }
//! ```
//!
//! Read the revert guard as its *pass* set. `start + WINDOW > now` reverts, so the
//! step is **allowed** for `now >= start + WINDOW`. The comparison is *strict*
//! (`>` / `<`), which means the **boundary instant `now == start + WINDOW` is in the
//! pass set** — the window expires with **zero margin**. At the boundary block a
//! slash-finalize and a withdrawal-complete (whose windows in Karak are deliberately
//! aligned: `MIN_WITHDRAWAL_DELAY == SLASHING_WINDOW + SLASHING_VETO_WINDOW`) are
//! *both* valid, and a veto and a finalize are both valid in the very block the veto
//! window lapses. Ordering inside one block is miner/sequencer-controlled, so the
//! two competing finalizers race: a withdrawal can complete in the same block the
//! slash that should have caught it finalizes, or a finalize can land in the block a
//! veto was meant to still cover.
//!
//! ## Why "zero margin" is the bug, not the window length
//!
//! The boundary semantics decide who wins a tie:
//!   * `start + WINDOW >  now` revert  →  pass iff `now >= start+WINDOW`  →  boundary **included** → tie possible → **flag**.
//!   * `now < deadline`        revert  →  pass iff `now >= deadline`      →  boundary **included** → tie possible → **flag**.
//!   * `start + WINDOW >= now` revert  →  pass iff `now >  start+WINDOW`  →  boundary **excluded** → 1-unit margin → safe.
//!   * `now <= deadline`       revert  →  pass iff `now >  deadline`      →  boundary **excluded** → safe.
//!
//! So a *non-strict* (`>=` / `<=`) revert comparison carries a one-tick buffer that
//! breaks the tie; the strict form does not. The fix is one character.
//!
//! ## Precision anchors (all required — keeps this silent on ordinary deadlines)
//!   * a **revert guard** — an `if (cond) revert/return` whose then-branch is a bare
//!     revert/return, or a `require(...)` — whose comparison is the zero-margin
//!     boundary form above (strict `<` / `>` with `now` on the open side);
//!   * the deadline `D` is a **window deadline**: either `start + WINDOW` where the
//!     left reads as a *queued/start* time (`timestamp`/`start`/`queuedAt`/…) and the
//!     right reads as a *window/period/cooldown/delay/duration* (named, or a time
//!     literal like `2 days`), **or** a stored var whose name reads as a
//!     *next-eligible / deadline* time (`nextSlashableTimestamp`, `unlockAt`,
//!     `cooldownEnd`, …);
//!   * the surrounding **context is a competing-finalizer domain — slash / veto /
//!     unbonding / undelegation / withdrawal** — named in the function or the
//!     revert-error / reason. This scopes the finding to *races between two
//!     privileged finalizers* (a slasher / vetoer vs a stake exit) and off a generic
//!     single-party `cooldown`, a vault `maturity`, a `claim`, or an auction bid
//!     deadline (those have no second adversarial finalizer at the boundary).
//!
//! ## SUPPRESS
//!   * the comparison is **non-strict** (`>=` / `<=`) — a one-tick buffer already
//!     breaks the tie (a deliberate margin);
//!   * a **per-id lock** in the same function removes the tie even at the boundary:
//!     the function consumes/flips the queued item before any value moves — a
//!     `delete <map>[id]` / `<map>[id] = ...false-ish` / status-flag write keyed by
//!     the same queued id that the competing finalizer also reads — so the two
//!     finalizers cannot both succeed on the same id in one block. (Karak's
//!     `finalizeSlashing` does `delete self.slashingRequests[slashRoot]` only *after*
//!     the boundary check and the per-id key is shared with the withdrawal path on a
//!     *different* mapping, so this does not suppress the real finding; the
//!     suppression targets a self-contained single-mapping CAS.)

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Builtin, CallKind, Expr, ExprKind, Function, Lit, Span, Stmt, StmtKind};

use super::prelude::*;

pub struct ZeroMarginTimingWindowDetector;

impl Detector for ZeroMarginTimingWindowDetector {
    fn id(&self) -> &'static str {
        "zero-margin-timing-window"
    }
    fn category(&self) -> Category {
        Category::ZeroMarginTimingWindow
    }
    fn description(&self) -> &'static str {
        "Finalize/veto/unbonding window boundary admits the exact boundary timestamp (strict `<`/`>` with no buffer), enabling a same-block race between competing finalizers (Karak Slasher/Vault class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        // Scan EVERY function with a body — the real targets are `internal` library
        // functions (SlasherLib / VaultLib), not external entry points.
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }

            // The context must read as a competing-finalizer domain — slash / veto /
            // unbonding / undelegation / withdrawal (function-name signal). The
            // per-guard error-name / require-reason signal is also accepted below, so a
            // generic-named wrapper that reverts `MinSlashingDelayNotPassed` still
            // qualifies.
            let fname_ctx = name_reads_window_context(&f.name);

            let Some(hit) = find_zero_margin_guard(cx, f, fname_ctx) else { continue };

            // SUPPRESS: a per-id cooldown compare-and-set in this same function removes
            // the tie. Specifically, the guard reads a stored *next-eligible* deadline
            // `map[id]` AND this same function *advances* that same `map[id]` to a
            // future time (`map[id] = now + period` / `+= period`) — a self-contained
            // CAS that serializes that id, so it cannot be re-finalized in the same
            // block. (This does NOT match Karak's read-only `validateRequestSlashingParams`,
            // whose `nextSlashableTimestamp` advance lives in a *different* function.)
            if advances_own_deadline(f, &hit) {
                continue;
            }

            let b = report!(self, Category::ZeroMarginTimingWindow,
                title = "Finalize/veto window boundary admits the exact boundary timestamp (zero margin)",
                severity = Severity::Medium,
                // Multi-anchor structural fingerprint: a strict (`<`/`>`) revert-guard
                // whose deadline is a `start + WINDOW` (or a next-eligible stored time)
                // in a finalize/veto/unbonding/slash context, with the non-strict-buffer
                // and same-id-lock suppressions. 0 FPs across the prior-codebase corpus.
                confidence = 0.62,
                dimensions = [Dimension::Invariant],
                message = format!(
                    "`{}` gates a {} step behind `{}` — a *strict* `{}` comparison of `block.timestamp` \
                     against the window deadline `{}`. Because the comparison is strict, the revert fires \
                     only strictly inside the window, so the action is permitted at the **exact boundary** \
                     `block.timestamp == {}` — the window expires with **zero margin**. Two competing \
                     finalizers are therefore both valid in that boundary block: e.g. a slash-finalize and a \
                     withdrawal-complete (whose delays are aligned), or a veto and a finalize in the very \
                     block the veto window lapses. Intra-block ordering is sequencer-controlled, so this is a \
                     same-block race (TOCTOU) at the boundary — the Karak Slasher/Vault window class.",
                    f.name,
                    hit.context_word,
                    hit.guard_text,
                    hit.op_word,
                    hit.deadline_text,
                    hit.deadline_text,
                ),
                recommendation =
                    "Add a one-tick buffer so the boundary instant resolves to a single winner: make the \
                     finalize revert non-strict (`if (start + WINDOW >= block.timestamp) revert` / \
                     `require(block.timestamp > deadline)`), or give the competing actions a per-id lock \
                     (consume/flip the queued item's status before any value moves, on a key both paths \
                     check) so they cannot both succeed on the same id in one block. Ensure the slash-finalize \
                     window and any withdrawal/unbonding completion window cannot both open on the same block \
                     for overlapping stake.",
            );
            out.push(finish_at(cx, b, f.id, hit.span));
        }

        out
    }
}

/// A matched zero-margin boundary guard.
struct ZeroMarginHit {
    /// Span of the guarding `if` / `require`.
    span: Span,
    /// Source text of the guard comparison, for the message.
    guard_text: String,
    /// Source text of the deadline operand `D`, for the message.
    deadline_text: String,
    /// `>` or `<` — the strict operator, for the message.
    op_word: &'static str,
    /// The matched context word (`finalize`, `veto`, `withdrawal`, …).
    context_word: &'static str,
    /// Root mapping name the deadline key indexes, if any (for the CAS-lock check).
    deadline_key_map: Option<String>,
    /// True when the deadline was a *stored next-eligible* value (Form 2), as opposed
    /// to a `start + WINDOW` computation (Form 1). Only the stored form can be a
    /// self-advancing cooldown CAS.
    deadline_is_stored_deadline: bool,
}

/// What `window_deadline` recognized about a deadline operand `D`.
struct DeadlineInfo {
    /// Root mapping name the deadline indexes (`map[id]`), if keyed by a stored id.
    key_map: Option<String>,
    /// True iff `D` is a *stored next-eligible / deadline-named* value (Form 2).
    is_stored_deadline: bool,
}

/// Scan `f` for the first zero-margin boundary revert-guard. `fname_ctx` is true when
/// the function name already reads as a finalize/veto/unbonding context; if false,
/// the guard's own revert-error name must supply that context.
fn find_zero_margin_guard(cx: &AnalysisContext, f: &Function, fname_ctx: bool) -> Option<ZeroMarginHit> {
    let mut hit: Option<ZeroMarginHit> = None;
    for top in &f.body {
        top.visit(&mut |st| {
            if hit.is_some() {
                return;
            }
            match &st.kind {
                // `if (BOUNDARY) revert/return;`  — the Karak form.
                StmtKind::If { cond, then_branch, else_branch } => {
                    // The then-branch must be a bare guard (single revert/return). The
                    // boundary cond is the *revert* condition: revert iff strictly
                    // inside the window, so the pass set is boundary-inclusive.
                    let guard_revert_text = branch_revert_text(then_branch);
                    if guard_revert_text.is_none() {
                        return;
                    }
                    // An else branch that does real work means this is not a pure guard.
                    if !else_branch.is_empty() {
                        return;
                    }
                    if let Some((deadline, op_word, dl)) = zero_margin_revert_cond(cond) {
                        let ctx = fname_ctx
                            .then(|| context_word(&f.name))
                            .flatten()
                            .or_else(|| guard_revert_text.as_deref().and_then(context_word));
                        if let Some(context_word) = ctx {
                            hit = Some(ZeroMarginHit {
                                span: st.span,
                                guard_text: clip(&cx.source_text(cond.span)),
                                deadline_text: clip(&cx.source_text(deadline.span)),
                                op_word,
                                context_word,
                                deadline_key_map: dl.key_map,
                                deadline_is_stored_deadline: dl.is_stored_deadline,
                            });
                        }
                    }
                }
                // `require(PASS, ...)` / `assert(PASS)` — pass condition is the
                // *negation* of the revert form. A boundary-inclusive pass set
                // (`now >= D`) is the bug.
                StmtKind::Expr(e) => {
                    e.visit(&mut |sub| {
                        if hit.is_some() {
                            return;
                        }
                        let ExprKind::Call(c) = &sub.kind else { return };
                        if !matches!(c.kind, CallKind::Builtin(Builtin::Require) | CallKind::Builtin(Builtin::Assert)) {
                            return;
                        }
                        let Some(pass) = c.args.first() else { return };
                        if let Some((deadline, op_word, dl)) = zero_margin_pass_cond(pass) {
                            // Context: function name, or a reason string / error in the
                            // require args.
                            let arg_text = c.args.iter().map(|a| cx.source_text(a.span)).collect::<Vec<_>>().join(" ");
                            let ctx = fname_ctx
                                .then(|| context_word(&f.name))
                                .flatten()
                                .or_else(|| context_word(&arg_text));
                            if let Some(context_word) = ctx {
                                hit = Some(ZeroMarginHit {
                                    span: sub.span,
                                    guard_text: clip(&cx.source_text(pass.span)),
                                    deadline_text: clip(&cx.source_text(deadline.span)),
                                    op_word,
                                    context_word,
                                    deadline_key_map: dl.key_map,
                                    deadline_is_stored_deadline: dl.is_stored_deadline,
                                });
                            }
                        }
                    });
                }
                _ => {}
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// A *revert* condition that is zero-margin: revert iff strictly inside the window,
/// so the pass set includes the boundary. Returns `(deadline_expr, "<"/">", key_map)`.
///
/// Matched strict forms (and only strict — `>=`/`<=` carry a buffer and are safe):
///   * `now <  D`   (`block.timestamp < deadline`)
///   * `D   >  now`  (`start + WINDOW > block.timestamp`)
fn zero_margin_revert_cond(cond: &Expr) -> Option<(&Expr, &'static str, DeadlineInfo)> {
    let ExprKind::Binary { op, lhs, rhs } = &cond.kind else { return None };
    match op {
        // `now < D` → pass `now >= D` (boundary included).
        BinOp::Lt if expr_is_now(lhs) => window_deadline(rhs).map(|m| (rhs.as_ref(), "<", m)),
        // `D > now` → pass `now >= D` (boundary included).
        BinOp::Gt if expr_is_now(rhs) => window_deadline(lhs).map(|m| (lhs.as_ref(), ">", m)),
        _ => None,
    }
}

/// A *require/assert* PASS condition that is zero-margin (boundary-inclusive pass) —
/// `now >= D` or `D <= now` (both include the boundary instant in the pass set).
/// The strict-exclusive forms `now > D` / `D < now` carry a one-tick margin and are
/// deliberately *not* matched (safe).
fn zero_margin_pass_cond(pass: &Expr) -> Option<(&Expr, &'static str, DeadlineInfo)> {
    let ExprKind::Binary { op, lhs, rhs } = &pass.kind else { return None };
    match op {
        BinOp::Ge if expr_is_now(lhs) => window_deadline(rhs).map(|m| (rhs.as_ref(), ">=", m)),
        BinOp::Le if expr_is_now(rhs) => window_deadline(lhs).map(|m| (lhs.as_ref(), "<=", m)),
        _ => None,
    }
}

/// Is `e` (shallowly) `block.timestamp` / `block.number` / a bare `now`?
fn expr_is_now(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Member { base, member } => {
            let m = member.to_ascii_lowercase();
            (m == "timestamp" || m == "number") && matches!(&base.kind, ExprKind::Ident(b) if b == "block")
        }
        ExprKind::Ident(n) => n == "now",
        _ => false,
    }
}

/// Is `e` a **window deadline** `D`? Two accepted forms.
///
///   * **Form 1** `start + WINDOW` — an `Add` whose one side reads as a *queued/start
///     time* and whose other side reads as a *window/period/cooldown/delay/duration*
///     (named or a time literal). Order-insensitive. (`is_stored_deadline = false`.)
///   * **Form 2** a stored *next-eligible / deadline*-named value — a var / `map[id]`
///     / `obj.field` whose name reads as `next…timestamp` / `deadline` / `unlockAt` /
///     `cooldownEnd` / `maturity` … (the precomputed `queuedAt + period`).
///     (`is_stored_deadline = true`.)
///
/// `key_map` is the root mapping name the deadline indexes (if a stored `map[id]`),
/// used by the self-advancing-cooldown-CAS suppression.
fn window_deadline(e: &Expr) -> Option<DeadlineInfo> {
    // Form 1: start + WINDOW.
    if let ExprKind::Binary { op: BinOp::Add, lhs, rhs } = &e.kind {
        let l_start = reads_start_time(lhs);
        let r_start = reads_start_time(rhs);
        let l_win = reads_window(lhs);
        let r_win = reads_window(rhs);
        if (l_start && r_win) || (r_start && l_win) {
            // The start side carries the queued-id key (e.g. `requests[id].timestamp`).
            let start_side = if l_start { lhs } else { rhs };
            return Some(DeadlineInfo { key_map: index_root_map(start_side), is_stored_deadline: false });
        }
    }
    // Form 2: a stored next-eligible / deadline-named value.
    if reads_deadline_name(e) {
        return Some(DeadlineInfo { key_map: index_root_map(e), is_stored_deadline: true });
    }
    None
}

/// Does `e` read a *queued / start* timestamp — a member/var/index whose leaf name
/// reads as a start/queue/request/created time (`timestamp`, `start`, `queuedAt`,
/// `createdAt`, `requestTime`, `startTime`, `lastUpdate…`)?
fn reads_start_time(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Member { base, member } => is_start_name(member) || reads_start_time(base),
        ExprKind::Index { base, .. } => reads_start_time(base),
        ExprKind::Ident(n) => is_start_name(n),
        _ => false,
    }
}

/// Does `e` read a *window/period* magnitude — a named constant
/// (`*WINDOW`/`*PERIOD`/`*COOLDOWN`/`*DELAY`/`*DURATION`) or a time-unit literal
/// (`2 days`, `7 days`, …, surfaced as a `Number` literal)?
fn reads_window(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Member { base, member } => is_window_name(member) || reads_window(base),
        ExprKind::Ident(n) => is_window_name(n),
        // A bare numeric literal here is a time-unit window (`+ 2 days` lowers to a
        // Number). We only accept it as the *window* side, never as the start side,
        // so an arbitrary `+ 1` offset on a non-time deadline is not a window.
        ExprKind::Lit(Lit::Number(_)) => true,
        _ => false,
    }
}

/// Does `e` (its leaf name) read as a precomputed *next-eligible / deadline* time?
fn reads_deadline_name(e: &Expr) -> bool {
    leaf_name(e).map(|n| is_deadline_name(&n)).unwrap_or(false)
}

/// Root mapping name of an index chain `m[id]` / `m[id].field` (`m`), if the deadline
/// operand is keyed by a stored id — used by the per-id-lock suppression.
fn index_root_map(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Index { base, .. } => Some(root_ident_str(base)?.to_string()),
        ExprKind::Member { base, .. } => index_root_map(base),
        _ => None,
    }
}

/// Leaf identifier of a member/index/ident chain (`a.b[c].field` -> `field`).
fn leaf_name(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { member, .. } => Some(member.clone()),
        ExprKind::Index { base, .. } => leaf_name(base),
        _ => None,
    }
}

// ---------------------------------------------------------------- name classifiers

fn is_start_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "timestamp"
        || l == "start"
        || l == "starttime"
        || l == "startedat"
        || l == "queuedat"
        || l == "createdat"
        || l == "requesttime"
        || l == "requestedat"
        || l == "queuetime"
        || l == "createtime"
        || l == "initiatedat"
        || (l.contains("queued") && l.contains("time"))
        || (l.contains("request") && l.contains("time"))
}

fn is_window_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("window")
        || l.contains("cooldown")
        || l.contains("unbond")
        || l.ends_with("period")
        || l.contains("period")
        || l.contains("delay")
        || l.contains("duration")
}

fn is_deadline_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // next-eligible timestamps (the `queuedAt + period` precompute) and explicit
    // deadlines / unlock points. Deliberately a closed set so a plain `timestamp` /
    // `expiry`-less field never qualifies on its own. (Vesting `maturity` is
    // intentionally absent — it is a single-party concept, not a competing-finalizer
    // next-eligible time; the context gate already scopes the class.)
    (l.contains("next") && l.contains("timestamp"))
        || (l.contains("next") && l.contains("slashable"))
        || l.contains("deadline")
        || l.contains("unlockat")
        || l.contains("unlocktime")
        || l.contains("cooldownend")
        || l.contains("eligibleat")
        || l.contains("releaseat")
        || l.contains("notbefore")
        || l.contains("validafter")
}

/// Does `text` (a function name or a revert reason / error name) read as a
/// **competing-finalizer** window domain — slash / veto / unbonding / undelegation /
/// withdrawal? Returns the matched word for the message.
///
/// This is deliberately the *narrow* set that characterizes the class: a window where
/// an independent privileged finalizer (a slasher / vetoer) races a stake exit
/// (withdrawal / unbonding). It intentionally **excludes** generic single-party
/// delays — a plain `cooldown`, a vault `maturity`, a `claim`, a `redeem` — whose
/// boundary instant has no second adversarial finalizer and so is not this race. (A
/// bare `finalize…`/`complete…`/`finish…` verb is also not sufficient on its own; the
/// slashing / withdrawal / unbonding domain word must be present in the function name
/// or the revert error / reason.)
fn context_word(text: &str) -> Option<&'static str> {
    let l = text.to_ascii_lowercase();
    const NEEDLES: &[(&str, &str)] = &[
        ("slash", "slashing"),
        ("veto", "veto"),
        ("unbond", "unbonding"),
        ("undeleg", "undelegation"),
        ("withdraw", "withdrawal"),
    ];
    NEEDLES.iter().find(|(needle, _)| l.contains(needle)).map(|(_, w)| *w)
}

fn name_reads_window_context(name: &str) -> bool {
    context_word(name).is_some()
}

// ---------------------------------------------------------------- guard / lock shape

/// If `branch` is a single bare revert/return (an inline guard), return its source
/// label for context classification: the revert error name when present, else a
/// sentinel so the *function-name* context still applies.
fn branch_revert_text(branch: &[Stmt]) -> Option<String> {
    if branch.len() != 1 {
        return None;
    }
    match &branch[0].kind {
        StmtKind::Revert { error, .. } => Some(error.clone().unwrap_or_default()),
        StmtKind::Return(_) => Some(String::new()),
        _ => None,
    }
}

/// Does `f` **advance its own deadline** — a self-contained per-id cooldown CAS that
/// breaks the boundary tie? True only when the matched deadline is a *stored
/// next-eligible* value `map[id]` (`hit.deadline_is_stored_deadline`) AND this same
/// function writes that same `map`'s element to a *future* time computed from
/// `block.timestamp`/`now` (`map[id] = now + period`). That serializes the id so it
/// cannot be re-finalized in the same block.
///
/// We require:
///   * the deadline operand was a *stored deadline-named* value keyed by id (the
///     `start + WINDOW` form, where the deadline is just a read start time, is NOT a
///     CAS and never suppresses — that is the live Karak finalize/withdraw case);
///   * a storage write to the same mapping (`hit.deadline_key_map`) whose RHS reads
///     `block.timestamp` (an advance to a future instant), not a `delete` / reset.
///
/// This deliberately does NOT fire on a bare `delete queue[id]` double-finalize guard,
/// which does not defuse the *cross-finalizer* race the detector targets.
fn advances_own_deadline(f: &Function, hit: &ZeroMarginHit) -> bool {
    if !hit.deadline_is_stored_deadline {
        return false;
    }
    let Some(map) = &hit.deadline_key_map else { return false };
    let mut advanced = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if advanced {
                return;
            }
            let ExprKind::Assign { target, value, .. } = &e.kind else { return };
            // Target is the same mapping the deadline indexes.
            if root_ident_str(target) != Some(map.as_str()) {
                return;
            }
            // RHS advances from current time (`now + period`). A `delete` lowers to a
            // zero/default write and will not mention block.timestamp, so it is
            // (correctly) not treated as an advance.
            if expr_reads_now(value) {
                advanced = true;
            }
        });
        if advanced {
            break;
        }
    }
    advanced
}

/// Does `e` mention `block.timestamp` / `block.number` / `now` anywhere?
fn expr_reads_now(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if !found && expr_is_now(sub) {
            found = true;
        }
    });
    found
}

/// Trim a source snippet for inclusion in a message (single line, length-bounded).
fn clip(s: &str) -> String {
    let one = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.len() > 90 {
        format!("{}…", &one[..90])
    } else {
        one
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::AnalysisContext;
    use crate::detector::Detector;
    use crate::Config;

    // Run ONLY this detector against `src`, building the analysis context directly.
    // This deliberately bypasses `builtin_detectors()` / the shared `mod.rs` registry
    // so these unit tests are independent of sibling detectors authored concurrently.
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        let parsed = sluice_parse::parse_sources(vec![("t.sol".into(), src.into())]);
        let scir = parsed.scir;
        let dataflow = sluice_dataflow::DataflowFacts::analyze(&scir);
        let invariants = sluice_invariant::InvariantFacts::mine(&scir);
        let frontier = sluice_frontier::FrontierFacts::analyze(&scir);
        let cfg = Config::default();
        let cx = AnalysisContext::new(&scir, &dataflow, &invariants, &frontier, &cfg);
        ZeroMarginTimingWindowDetector.run(&cx)
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "zero-margin-timing-window")
    }

    // VULN — the exact Karak `SlasherLib.finalizeSlashing` boundary:
    // `if (q.timestamp + Constants.SLASHING_VETO_WINDOW > block.timestamp) revert ...`.
    // The strict `>` revert makes the finalize valid at `now == q.timestamp + WINDOW`.
    const VULN_FINALIZE: &str = r#"
        library Constants { uint256 public constant SLASHING_VETO_WINDOW = 2 days; }
        library SlasherLib {
            struct QueuedSlashing { uint96 timestamp; }
            mapping(bytes32 => bool) slashingRequests;
            function finalizeSlashing(QueuedSlashing memory queuedSlashing) internal view {
                if (queuedSlashing.timestamp + Constants.SLASHING_VETO_WINDOW > block.timestamp) {
                    revert MinSlashingDelayNotPassed();
                }
            }
        }
    "#;

    // VULN — the exact Karak `VaultLib.validateQueuedWithdrawal` boundary.
    const VULN_WITHDRAW: &str = r#"
        library Constants { uint256 public constant MIN_WITHDRAWAL_DELAY = 9 days; }
        library VaultLib {
            struct QueuedWithdrawal { uint96 start; }
            function validateQueuedWithdrawal(QueuedWithdrawal memory qdWithdrawal) internal view {
                if (qdWithdrawal.start == 0) revert WithdrawalNotFound();
                if (qdWithdrawal.start + Constants.MIN_WITHDRAWAL_DELAY > block.timestamp) {
                    revert MinWithdrawDelayNotPassed();
                }
            }
        }
    "#;

    // VULN — the exact Karak `validateRequestSlashingParams` cooldown boundary:
    // `if (block.timestamp < ...nextSlashableTimestamp[dss]) revert SlashingCooldownNotPassed();`.
    // The deadline is a stored next-eligible timestamp (queuedAt + cooldown).
    const VULN_COOLDOWN: &str = r#"
        contract Slasher {
            struct OpState { mapping(address => uint256) nextSlashableTimestamp; }
            mapping(address => OpState) operatorState;
            function validateRequestSlashingParams(address operator, address dss) internal view {
                if (block.timestamp < operatorState[operator].nextSlashableTimestamp[dss]) {
                    revert SlashingCooldownNotPassed();
                }
            }
        }
    "#;

    // VULN — require form: `require(block.timestamp >= start + UNBONDING_PERIOD)` in
    // an unbonding context. Pass set is boundary-inclusive (`>=`), zero margin.
    const VULN_REQUIRE: &str = r#"
        contract Staking {
            uint256 public constant UNBONDING_PERIOD = 14 days;
            struct Unbond { uint256 startTime; }
            mapping(uint256 => Unbond) unbonds;
            function completeUnbonding(uint256 id) external {
                require(block.timestamp >= unbonds[id].startTime + UNBONDING_PERIOD, "too early");
                delete unbonds[id];
            }
        }
    "#;

    // SAFE — non-strict revert (`>=`): the boundary instant reverts, leaving a
    // one-tick margin. `start + WINDOW >= now` reverts → pass iff `now > start+WINDOW`.
    const SAFE_BUFFER_REVERT: &str = r#"
        library Constants { uint256 public constant SLASHING_VETO_WINDOW = 2 days; }
        library SlasherLib {
            struct QueuedSlashing { uint96 timestamp; }
            function finalizeSlashing(QueuedSlashing memory queuedSlashing) internal view {
                if (queuedSlashing.timestamp + Constants.SLASHING_VETO_WINDOW >= block.timestamp) {
                    revert MinSlashingDelayNotPassed();
                }
            }
        }
    "#;

    // SAFE — require with a strict buffer (`>`): pass iff `now > deadline`, boundary
    // excluded.
    const SAFE_BUFFER_REQUIRE: &str = r#"
        contract Staking {
            uint256 public constant UNBONDING_PERIOD = 14 days;
            struct Unbond { uint256 startTime; }
            mapping(uint256 => Unbond) unbonds;
            function completeUnbonding(uint256 id) external {
                require(block.timestamp > unbonds[id].startTime + UNBONDING_PERIOD, "too early");
                delete unbonds[id];
            }
        }
    "#;

    // SAFE — not a window context: a generic auction `bid` deadline with the same
    // boundary shape. No finalize/veto/unbond/withdraw/slash/claim word in the
    // function name or revert, so this is out of scope.
    const SAFE_NO_CONTEXT: &str = r#"
        contract Auction {
            uint256 public auctionEndDelay = 1 hours;
            struct Sale { uint256 startTime; }
            mapping(uint256 => Sale) sales;
            function placeBid(uint256 id) external {
                if (block.timestamp < sales[id].startTime + auctionEndDelay) {
                    revert BidWindowOpen();
                }
            }
        }
    "#;

    // SAFE — the deadline is not a window: a plain stored `expiryBlock` compared with
    // no `start + WINDOW` arithmetic and no next-eligible name. (`expiry` alone is not
    // in the deadline-name set; this is an ordinary single-value comparison.)
    const SAFE_PLAIN_DEADLINE: &str = r#"
        contract Vesting {
            mapping(uint256 => uint256) expiry;
            function withdrawVested(uint256 id) external {
                if (block.timestamp < expiry[id]) {
                    revert NotYet();
                }
            }
        }
    "#;

    // SAFE — self-advancing cooldown CAS: the guard reads a *stored next-eligible*
    // deadline `nextSlashTime[op]` and the SAME function advances it to a future
    // instant (`= block.timestamp + SLASH_COOLDOWN`). That serializes the id: the
    // boundary instant can be hit at most once because the next call sees the bumped
    // deadline. The per-id lock removes the tie, so we stay silent.
    const SAFE_COOLDOWN_CAS: &str = r#"
        contract Slasher {
            uint256 public constant SLASH_COOLDOWN = 2 days;
            mapping(address => uint256) nextSlashTime;
            function finalizeSlash(address op) external {
                if (block.timestamp < nextSlashTime[op]) {
                    revert SlashingCooldownNotPassed();
                }
                nextSlashTime[op] = block.timestamp + SLASH_COOLDOWN;
            }
        }
    "#;

    #[test]
    fn fires_on_karak_finalize_slashing() {
        assert!(fires(VULN_FINALIZE), "{:#?}", run(VULN_FINALIZE));
    }

    #[test]
    fn fires_on_karak_withdraw_delay() {
        assert!(fires(VULN_WITHDRAW), "{:#?}", run(VULN_WITHDRAW));
    }

    #[test]
    fn fires_on_karak_slashing_cooldown() {
        assert!(fires(VULN_COOLDOWN), "{:#?}", run(VULN_COOLDOWN));
    }

    #[test]
    fn fires_on_require_unbonding_boundary() {
        assert!(fires(VULN_REQUIRE), "{:#?}", run(VULN_REQUIRE));
    }

    #[test]
    fn silent_on_self_advancing_cooldown_cas() {
        assert!(!fires(SAFE_COOLDOWN_CAS), "{:#?}", run(SAFE_COOLDOWN_CAS));
    }

    #[test]
    fn silent_on_nonstrict_revert_buffer() {
        assert!(!fires(SAFE_BUFFER_REVERT), "{:#?}", run(SAFE_BUFFER_REVERT));
    }

    #[test]
    fn silent_on_strict_require_buffer() {
        assert!(!fires(SAFE_BUFFER_REQUIRE), "{:#?}", run(SAFE_BUFFER_REQUIRE));
    }

    #[test]
    fn silent_without_window_context() {
        assert!(!fires(SAFE_NO_CONTEXT), "{:#?}", run(SAFE_NO_CONTEXT));
    }

    #[test]
    fn silent_on_plain_non_window_deadline() {
        assert!(!fires(SAFE_PLAIN_DEADLINE), "{:#?}", run(SAFE_PLAIN_DEADLINE));
    }
}
