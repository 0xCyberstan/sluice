//! Denial-of-service via loops. Three patterns:
//!
//! 1. **Unbounded loop** — a loop whose bound references a state-array `.length`
//!    that an external function can grow (`f.effects.has_unbounded_loop`). The
//!    array keeps growing until iterating it exceeds the block gas limit, and the
//!    function (and anything that calls it) is permanently bricked. Emitted as
//!    [`Category::UnboundedLoop`].
//!
//! 1b. **Unbounded loop with a per-iteration external call** — a loop whose bound
//!    references a state variable that some function in the contract grows
//!    *without an enforced cap* (a counter incremented `++`/`+=`, or an array
//!    `.push`ed to), where **each iteration makes an external call**. This is the
//!    SafEth-`unstake` shape (`for i < derivativeCount { derivatives[i].withdraw(...) }`,
//!    Asymmetry M-08): the growth path is privileged (owner-only `addDerivative`)
//!    but uncapped, so the per-element external-call gas multiplied by an
//!    ever-growing element count eventually exceeds the block gas limit and bricks
//!    the function — and a single reverting element bricks the whole loop too.
//!    Unlike pattern (1) the growth need not be *attacker*-reachable: an unbounded
//!    privileged add plus per-iteration external calls is sufficient. Conservative
//!    by construction — it requires (a) a genuine external transfer-of-control in
//!    the loop body (so pure-arithmetic and read-only loops stay silent), (b) the
//!    bound to be a *state* variable (calldata-array batches stay silent), and
//!    (c) the growth to be *uncapped* (a `require(count < MAX)` / `if (len >= MAX)`
//!    guard in the grower suppresses it, as do `.push`es that are length-capped).
//!    Emitted as [`Category::UnboundedLoop`].
//!
//! 2. **External call inside a loop** — a `for`/`while`/`do-while` whose body
//!    transfers control to an external party (`.transfer`/`.send`/low-level
//!    `.call`, an interface call). A single reverting / griefing recipient
//!    reverts the *entire* batch — the push-payment / Akutars / King-of-the-Ether
//!    class. Emitted as [`Category::DenialOfService`].
//!
//! 3. **Loop that grows a storage array** on attacker-reachable input (an
//!    in-loop `push` to contract storage), the supply side of pattern (1).
//!
//! Precision over recall: failures isolated by `try/catch`, pull-payment
//! patterns, owner-set/constant-bounded loops, and `view`/`pure` functions are
//! suppressed. Two further shapes are suppressed because the "one reverting
//! recipient bricks the batch" premise does not hold for them:
//!
//!   * **Fault-tolerant / `try`-style aggregators** — the loop captures each
//!     entry's `(bool success, …)` and stores the per-entry outcome (into a
//!     tuple or a `Result[]`) instead of unconditionally reverting; a failed
//!     entry is deliberately tolerated (any abort is gated behind a caller
//!     `requireSuccess`-style flag). `Multicall2.tryAggregate`,
//!     `PendleMulticallV{1,2}.tryAggregate` are of this kind.
//!   * **Read-only aggregator helpers** — a function in a contract/file named
//!     `*Multicall*`/`*aggregator*` whose in-loop call returns data and sends no
//!     native value (`Multicall2.aggregate`, `PendleMulticallV{1,2}.aggregate`).
//!     There are no stored recipients for an attacker to grief; the caller
//!     supplies its own call list.
//!
//! A genuine push-payment loop that sends native value and reverts the whole
//! batch on a single failure (`require(success)` / bubbled `if (!success) revert`)
//! is still reported.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{AssignOp, Builtin, CallKind, Expr, ExprKind, Function, Span, Stmt, StmtKind, UnOp};

pub struct DosDetector;

impl Detector for DosDetector {
    fn id(&self) -> &'static str {
        "denial-of-service"
    }
    fn category(&self) -> Category {
        Category::DenialOfService
    }
    fn description(&self) -> &'static str {
        "DoS via loops: external call in a loop (one reverting recipient bricks the batch) or an attacker-growable unbounded loop"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // Reading-only code can be re-tried for free off-chain; the gas-grief
            // / stuck-funds impact requires a state-mutating, reachable entry.
            if !f.has_body || f.is_view_or_pure() {
                continue;
            }

            // Arrays an unguarded external function can grow without bound — the
            // only ones whose iteration is an attacker-driven DoS. Admin-set /
            // bounded lists (operatorDelegators, collateralTokens, ...) are
            // excluded, which is what keeps this quiet on real protocols.
            let growable = growable_arrays(cx, f);
            let mut emitted = false;

            // ---- Pattern 2 & 3: walk the body for loop statements. ----
            for loop_stmt in loops_in(f) {
                let body = loop_body(loop_stmt);

                // (2) External transfer-of-control inside the loop body. We skip
                // calls that sit inside a `try { ... }` — there the failure of one
                // recipient is caught and the batch survives.
                if let Some(call_span) = external_call_in_loop(body) {
                    let pull_payment = uses_pull_payment(cx, f);
                    // The DoS-class pattern is a PUSH PAYMENT: a value-sending call
                    // to a recipient that can revert, bricking the batch; OR a loop
                    // over an ATTACKER-GROWABLE array. A loop over a caller-supplied
                    // calldata array, or an admin-bounded storage list, is not a DoS.
                    let sends_value = loop_sends_value(body);
                    let over_growable = loop_iterates_growable(loop_stmt, &growable);
                    // The "one reverting recipient bricks the batch" premise is FALSE
                    // for two shapes, so suppress them:
                    //  (A) a FAULT-TOLERANT / `try`-style aggregator — the per-entry
                    //      `(bool success, …)` is captured and stored (into a tuple or
                    //      a `Result[]`) and a failed entry does NOT unconditionally
                    //      revert the batch (no `require(success)`; any abort is gated
                    //      behind a caller `requireSuccess`-style bool knob), and
                    //  (B) a READ-ONLY aggregator helper — a function in a contract or
                    //      file named *Multicall*/*aggregator* whose in-loop call
                    //      returns data without sending native value (no `{value:}` /
                    //      `transfer` / `send`). Both intentionally tolerate, or never
                    //      expose, a failing recipient, so neither can be griefed.
                    let fault_tolerant = loop_is_fault_tolerant(cx, f, loop_stmt);
                    let readonly_aggregator = is_readonly_aggregator(cx, f, body);
                    if !pull_payment
                        && !fault_tolerant
                        && !readonly_aggregator
                        && (sends_value || over_growable)
                    {
                        let mut b = FindingBuilder::new(self.id(), Category::DenialOfService)
                            .title("External call inside a loop (one reverting recipient bricks the batch)")
                            .severity(Severity::Medium)
                            .confidence(0.5)
                            .dimension(Dimension::Frontier)
                            .message(format!(
                                "`{}` performs an external call (transfer/send/low-level call to an \
                                 untrusted address) inside a loop. A single recipient that reverts — a \
                                 contract with a reverting `receive`/`fallback`, or one that burns all \
                                 forwarded gas — reverts the whole iteration, permanently blocking every \
                                 other entry in the batch. This is the push-payment / Akutars / \
                                 King-of-the-Ether denial-of-service class.",
                                f.name
                            ))
                            .recommendation(
                                "Use the pull-payment pattern (record per-recipient credits and let each \
                                 party `withdraw()` independently) instead of pushing in a loop, or wrap \
                                 each external call in `try/catch` so one failure cannot revert the batch.",
                            );
                        if sends_value {
                            b = b.dimension(Dimension::ValueFlow);
                        }
                        out.push(cx.finish(b, f.id, call_span));
                        emitted = true;
                        // One DoS-in-loop finding per function is enough signal.
                        break;
                    }
                }

                // (3) The loop grows a storage array (an in-loop `push`). This is the
                // mechanism that *creates* an unbounded loop elsewhere; flag it when
                // the function is externally reachable (attacker-reachable growth).
                if f.is_externally_reachable() {
                    if let Some(push_span) = storage_growth_in_loop(body) {
                        let b = FindingBuilder::new(self.id(), Category::DenialOfService)
                            .title("Loop grows a storage array on attacker-reachable input")
                            .severity(Severity::Medium)
                            .confidence(0.45)
                            .dimension(Dimension::Invariant)
                            .message(format!(
                                "`{}` pushes onto a storage array inside a loop on an externally reachable \
                                 path, with no cap on the resulting length. An attacker can inflate the \
                                 array until any later loop over it exceeds the block gas limit, bricking \
                                 every function that iterates it.",
                                f.name
                            ))
                            .recommendation(
                                "Bound the array growth (enforce a maximum length) and avoid unbounded \
                                 iteration over caller-growable storage; prefer per-key mappings to arrays.",
                            );
                        out.push(cx.finish(b, f.id, push_span));
                        emitted = true;
                        break;
                    }
                }
            }

            // ---- Pattern 1: unbounded GAS loop over an attacker-growable array
            // (no external call needed — the gas to iterate it can exceed the block
            // limit). Gated on actual growability, not merely "a storage .length".
            if !emitted {
                let over_growable = loops_in(f).iter().any(|ls| loop_iterates_growable(ls, &growable));
                if over_growable {
                    let b = FindingBuilder::new(self.id(), Category::UnboundedLoop)
                        .title("Unbounded loop over an attacker-growable array")
                        .severity(Severity::Medium)
                        .confidence(0.5)
                        .dimension(Dimension::Invariant)
                        .message(format!(
                            "`{}` loops up to the length of a storage array that an external function can \
                             grow without bound. Once the array is large enough, the gas to iterate it \
                             exceeds the block limit and the function can never complete, freezing any logic \
                             (and any funds) that depend on it.",
                            f.name
                        ))
                        .recommendation(
                            "Cap the iteration count, paginate the work across transactions, or restructure \
                             so the gas cost cannot be driven past the block limit by an attacker.",
                        );
                    out.push(cx.finish(b, f.id, f.span));
                    emitted = true;
                }
            }

            // ---- Pattern 1b: unbounded loop whose bound is an UNCAPPED-GROWABLE
            // state variable AND whose body makes a per-iteration external call.
            // This is the SafEth-`unstake` / Asymmetry-M-08 shape: the bound
            // (`derivativeCount`) is grown by a privileged-but-uncapped path
            // (`addDerivative` does `derivativeCount++`, no max), and each iteration
            // calls `derivatives[i].withdraw(...)`. The growth need not be attacker-
            // reachable (so it is NOT covered by `growable_arrays`, which requires an
            // unguarded external push), but the per-element external-call gas times an
            // ever-growing count still bricks the function at the block gas limit.
            //
            // Three conservative gates keep this quiet on real protocols:
            //   * the loop body must contain a genuine external transfer-of-control
            //     call (reusing `external_call_in_loop`, which already skips
            //     `try`-wrapped calls) — pure-arithmetic weight sums and read-only
            //     accumulators have none, so they stay silent;
            //   * the loop bound must read a STATE variable (a calldata/memory array
            //     length is a caller's own concern, not a protocol DoS); and
            //   * that state variable must be grown WITHOUT an enforced cap — a
            //     `require(count < MAX)` / `if (len >= MAX) revert` guard in the
            //     grower, or a length-capped `.push`, suppresses it.
            if !emitted && f.is_state_mutating() {
                let uncapped = uncapped_growable_state(cx, f);
                if !uncapped.is_empty() {
                    let hit = loops_in(f).into_iter().find(|ls| {
                        external_call_in_loop(loop_body(ls)).is_some()
                            && loop_bound_reads_state(ls, &uncapped)
                    });
                    if let Some(ls) = hit {
                        let b = FindingBuilder::new(self.id(), Category::UnboundedLoop)
                            .title("Unbounded loop with a per-iteration external call over an uncapped-growable bound")
                            .severity(Severity::Medium)
                            .confidence(0.5)
                            .dimension(Dimension::Invariant)
                            .message(format!(
                                "`{}` loops up to a state variable that another function grows without an \
                                 enforced cap, and performs an external call on every iteration. As the bound \
                                 grows, the per-element external-call gas multiplied by the element count \
                                 eventually exceeds the block gas limit, so the function can never complete — \
                                 permanently freezing the logic (and any funds) that depend on it. A single \
                                 element whose external call reverts likewise bricks the entire loop.",
                                f.name
                            ))
                            .recommendation(
                                "Enforce a maximum on the growable bound, paginate the per-element work across \
                                 transactions, or remove the per-iteration external call (e.g. let each party \
                                 settle its own entry) so the gas cost cannot be driven past the block limit.",
                            );
                        out.push(cx.finish(b, f.id, ls.span));
                    }
                }
            }
        }
        out
    }
}

// ----------------------------------------------------------------- helpers

/// All loop statements (`for`/`while`/`do-while`) anywhere in the function body,
/// in pre-order.
fn loops_in(f: &Function) -> Vec<&Stmt> {
    let mut loops = Vec::new();
    for s in &f.body {
        s.visit(&mut |st| {
            if matches!(
                st.kind,
                StmtKind::While { .. } | StmtKind::For { .. } | StmtKind::DoWhile { .. }
            ) {
                loops.push(st);
            }
        });
    }
    loops
}

/// The statement list forming a loop's body (empty for non-loops).
fn loop_body(loop_stmt: &Stmt) -> &[Stmt] {
    match &loop_stmt.kind {
        StmtKind::While { body, .. }
        | StmtKind::For { body, .. }
        | StmtKind::DoWhile { body, .. } => body,
        _ => &[],
    }
}

/// Scan a loop body's statement subtree for a call that transfers control to an
/// external party, returning its span. Calls lexically inside a `try { ... }`
/// (whose `catch` isolates the failure) are *not* counted.
fn external_call_in_loop(body: &[Stmt]) -> Option<Span> {
    let mut found = None;
    for s in body {
        scan_for_external_call(s, &mut found);
        if found.is_some() {
            break;
        }
    }
    found
}

/// Recursive walk over a statement subtree looking for an external
/// transfer-of-control call. The body of a `try { ... }` is deliberately *not*
/// descended into: there a reverting recipient is caught and the batch survives,
/// so such a call must not count as a DoS.
fn scan_for_external_call(s: &Stmt, found: &mut Option<Span>) {
    if found.is_some() {
        return;
    }
    match &s.kind {
        // Failure-isolated by catch handlers — suppress (do not recurse).
        StmtKind::Try { .. } => {}
        StmtKind::If { cond, then_branch, else_branch } => {
            scan_exprs_for_external_call(cond, found);
            for st in then_branch.iter().chain(else_branch.iter()) {
                scan_for_external_call(st, found);
                if found.is_some() {
                    return;
                }
            }
        }
        StmtKind::While { cond, body } | StmtKind::DoWhile { body, cond } => {
            scan_exprs_for_external_call(cond, found);
            for st in body {
                scan_for_external_call(st, found);
                if found.is_some() {
                    return;
                }
            }
        }
        StmtKind::For { cond, step, body, .. } => {
            if let Some(c) = cond {
                scan_exprs_for_external_call(c, found);
            }
            if let Some(st) = step {
                scan_exprs_for_external_call(st, found);
            }
            for st in body {
                scan_for_external_call(st, found);
                if found.is_some() {
                    return;
                }
            }
        }
        StmtKind::Block { stmts, .. } => {
            for st in stmts {
                scan_for_external_call(st, found);
                if found.is_some() {
                    return;
                }
            }
        }
        StmtKind::Expr(e) | StmtKind::Emit(e) => scan_exprs_for_external_call(e, found),
        StmtKind::VarDecl { init: Some(e), .. } => scan_exprs_for_external_call(e, found),
        StmtKind::Return(Some(e)) => scan_exprs_for_external_call(e, found),
        StmtKind::Revert { args, .. } => {
            for a in args {
                scan_exprs_for_external_call(a, found);
                if found.is_some() {
                    return;
                }
            }
        }
        _ => {}
    }
}

/// Find an external transfer-of-control call within a single expression tree.
fn scan_exprs_for_external_call(e: &sluice_ir::Expr, found: &mut Option<Span>) {
    e.visit(&mut |x| {
        if found.is_some() {
            return;
        }
        if let ExprKind::Call(c) = &x.kind {
            if c.kind.is_external_transfer_of_control() {
                *found = Some(x.span);
            }
        }
    });
}

/// True if any external call in the loop body sends native value (push-payment).
fn loop_sends_value(body: &[Stmt]) -> bool {
    let mut sends = false;
    for s in body {
        s.visit_exprs(&mut |e| {
            if let ExprKind::Call(c) = &e.kind {
                if c.kind.can_send_value() || c.value.is_some() {
                    sends = true;
                }
            }
        });
        if sends {
            break;
        }
    }
    sends
}

/// True if any in-loop call sends **native ETH** — precisely (`{value:}` present,
/// `.transfer`, or `.send`). Unlike [`loop_sends_value`], a bare low-level
/// `.call(data)` with no `{value:}` does *not* count here: a read aggregator that
/// forwards calldata is not a value push, and we must not treat it as one.
fn loop_sends_native_value(body: &[Stmt]) -> bool {
    let mut sends = false;
    for s in body {
        s.visit_exprs(&mut |e| {
            if let ExprKind::Call(c) = &e.kind {
                if c.value.is_some() || matches!(c.kind, CallKind::Transfer | CallKind::Send) {
                    sends = true;
                }
            }
        });
        if sends {
            break;
        }
    }
    sends
}

/// (A) A FAULT-TOLERANT / `try`-style aggregator loop: each entry's
/// `(bool success, …)` is captured and the per-entry outcome is *stored* (an
/// indexed write `results[i] = …`, or a `Result(success, …)` construction), and a
/// failed entry does **not** unconditionally revert the batch.
///
/// The defining contrast with a real push-payment DoS is the failure path. A
/// loop that does `require(success)` / `if (!success) revert` aborts the whole
/// batch on any failure and is *not* tolerant. A loop that only reverts when a
/// caller-supplied `requireSuccess`-style `bool` knob is set — or that never
/// reverts and just records the result — tolerates a failing entry, so no single
/// recipient can brick it. We recognize the latter as: the outcome is stored, and
/// either the loop performs no `require`/`revert`/`assert` at all, or the function
/// exposes a `bool` success-knob parameter that gates the abort.
fn loop_is_fault_tolerant(cx: &AnalysisContext, f: &Function, loop_stmt: &Stmt) -> bool {
    // Comment-stripped, lowercased text of the whole loop (covers its body).
    let src = cx.source_text(loop_stmt.span);
    let compact: String = src.chars().filter(|c| !c.is_whitespace()).collect();

    // Must capture the call's success bit into a `(bool …)` tuple — the hallmark
    // of an aggregator that inspects per-entry success rather than relying on the
    // call to revert. (`"(boolok,)".contains("(bool")` holds after de-spacing.)
    let captures_success = compact.contains("(bool");
    if !captures_success {
        return false;
    }

    // Stores the per-entry outcome: an indexed assignment (`returnData[i] = …`,
    // `results[i] = ok`) or a `Result(...)` constructor. A loop that only reverts
    // on failure (and stores nothing) is a hard aggregator, not a tolerant one.
    // Neutralize `arr[i] == x` first so an element *comparison* is not mistaken
    // for an element *assignment*.
    let no_eq_cmp = compact.replace("]==", "]\u{1}");
    let stores_result = no_eq_cmp.contains("]=") || no_eq_cmp.contains("result(");
    if !stores_result {
        return false;
    }

    // Tolerant iff the failure path cannot, by itself, abort the batch: either no
    // abort statement exists, or the abort is gated behind a `bool` success-knob
    // parameter (`requireSuccess`-style), so a failed entry alone does not revert.
    let has_abort =
        compact.contains("require(") || compact.contains("revert") || compact.contains("assert(");
    let has_bool_knob = f.params.iter().any(|p| p.ty.trim().eq_ignore_ascii_case("bool"));
    !has_abort || has_bool_knob
}

/// (B) A READ-ONLY aggregator helper: a function whose contract OR source file is
/// named `*Multicall*`/`*aggregator*` and whose in-loop external call returns data
/// without sending native value. Such a helper forwards a caller-supplied call
/// list and has no stored recipients for an attacker to grief, so the push-payment
/// DoS premise does not apply — even when it bubbles up a failure via
/// `if (!success) revert`.
fn is_readonly_aggregator(cx: &AnalysisContext, f: &Function, body: &[Stmt]) -> bool {
    fn is_aggregator_name(s: &str) -> bool {
        let s = s.to_ascii_lowercase();
        s.contains("multicall") || s.contains("aggregator")
    }
    let contract_named =
        cx.contract_of(f.id).map(|c| is_aggregator_name(&c.name)).unwrap_or(false);
    let (path, _) = cx.scir.location(f.span);
    let basename = path.rsplit(['/', '\\']).next().unwrap_or(&path);
    if !contract_named && !is_aggregator_name(basename) {
        return false;
    }
    // A value-pushing batch (even in a *Multicall* contract, e.g. an owner-only
    // executor that forwards ETH and reverts on failure) is a real push-payment
    // loop and stays reported; only the no-value, data-returning helpers are FPs.
    !loop_sends_native_value(body)
}

/// Detect a `push(...)` (array growth) on a storage array inside a loop body.
/// Recognized either by the pre-classified `ArrayPushPop` builtin or by a member
/// call named `push`.
fn storage_growth_in_loop(body: &[Stmt]) -> Option<Span> {
    let mut found = None;
    for s in body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                let is_push = matches!(c.kind, CallKind::Builtin(Builtin::ArrayPushPop))
                    || c.func_name.as_deref() == Some("push");
                if is_push {
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

/// Heuristic: does the function use the pull-payment pattern (credit then let the
/// recipient withdraw), which neutralizes the in-loop-call DoS? We treat a
/// function that records balances/credits but whose external call is fronted by a
/// `withdraw`/`claim` idiom as pull-style. Conservative: only suppress when the
/// source clearly mentions a pull idiom together with a credit write.
fn uses_pull_payment(cx: &AnalysisContext, f: &Function) -> bool {
    let src = cx.source_text(f.span);
    let pull_name = {
        let n = f.name.to_ascii_lowercase();
        n.contains("withdraw") || n.contains("claim")
    };
    // A single-recipient pull (`withdraw()`/`claim()`) is not a batch push even if
    // it sends value, and a function that only credits a mapping (no transfer) is
    // the deposit half of pull-payment.
    pull_name || (src.contains("pending") && (src.contains("credit") || src.contains("balances[")))
}

/// State arrays that an externally-reachable, NON-access-controlled function can
/// `push` onto — i.e. arrays an attacker can grow without bound. Iterating one is
/// an attacker-driven gas/DoS risk; iterating an admin-bounded list is not.
fn growable_arrays(cx: &crate::context::AnalysisContext, f: &Function) -> std::collections::HashSet<String> {
    let mut g = std::collections::HashSet::new();
    let Some(c) = cx.contract_of(f.id) else {
        return g;
    };
    for fun in cx.scir.functions_of(c.id) {
        if fun.is_externally_reachable() && !cx.has_access_control(fun) {
            for w in &fun.effects.storage_writes {
                // The parser records `arr.push(...)` as a write with a "push" path.
                if w.path.contains("push") {
                    g.insert(w.var.clone());
                }
            }
        }
    }
    g
}

/// True if `loop_stmt` iterates over (the length of, or by indexing) an
/// attacker-growable array.
fn loop_iterates_growable(loop_stmt: &Stmt, growable: &std::collections::HashSet<String>) -> bool {
    if growable.is_empty() {
        return false;
    }
    let mut hit = false;
    loop_stmt.visit_exprs(&mut |e| match &e.kind {
        ExprKind::Member { base, member } if member == "length" => {
            if root_in(base, growable) {
                hit = true;
            }
        }
        ExprKind::Index { base, .. } => {
            if root_in(base, growable) {
                hit = true;
            }
        }
        _ => {}
    });
    hit
}

fn root_in(e: &sluice_ir::Expr, set: &std::collections::HashSet<String>) -> bool {
    fn root(e: &sluice_ir::Expr) -> Option<&str> {
        match &e.kind {
            ExprKind::Ident(n) => Some(n),
            ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root(base),
            _ => None,
        }
    }
    root(e).map(|r| set.contains(r)).unwrap_or(false)
}

/// State variables that some function in `f`'s contract grows **without an
/// enforced cap** — either a counter incremented (`++` / `+= k`) or an array
/// `.push`ed to — and where the growing function does NOT bound that variable
/// with an ordering comparison (a `require(count < MAX)` / `if (len >= MAX)`
/// guard). Iterating such a variable while doing per-element external calls is the
/// SafEth-`unstake` / Asymmetry-M-08 DoS shape.
///
/// Distinct from [`growable_arrays`]: that requires an *unguarded external* push
/// (attacker-growable). Here the grower may be privileged (owner-only) — an
/// uncapped privileged add is still an unbounded loop. We deliberately do NOT
/// exclude on access control, but we DO require the growth to be uncapped, which
/// is what keeps admin lists with an explicit `MAX` (e.g. a capped registry)
/// silent.
fn uncapped_growable_state(
    cx: &crate::context::AnalysisContext,
    f: &Function,
) -> std::collections::HashSet<String> {
    let mut g = std::collections::HashSet::new();
    let Some(c) = cx.contract_of(f.id) else {
        return g;
    };
    for fun in cx.scir.functions_of(c.id) {
        if !fun.has_body {
            continue;
        }
        // Vars this function grows (counter increment or array push).
        let grown = vars_grown_in(fun);
        if grown.is_empty() {
            continue;
        }
        // Vars this function bounds with an ordering comparison anywhere in its
        // body (the cap). A grower that compares the var against a limit before
        // growing it (`require(count < MAX)`, `if (len >= MAX) revert`) is capped.
        let capped = vars_ordering_compared_in(fun);
        for v in grown {
            if !capped.contains(&v) {
                g.insert(v);
            }
        }
    }
    g
}

/// State variables grown inside `fun`: a state counter incremented (`++`/`--`/
/// `+= k`) or a state array `.push`ed to. Returns the base state-variable names.
fn vars_grown_in(fun: &Function) -> std::collections::HashSet<String> {
    // `.push`/`.pop` array growth is pre-recorded by the parser as a storage write
    // whose path contains "push" (see `growable_arrays`).
    let mut grown: std::collections::HashSet<String> = fun
        .effects
        .storage_writes
        .iter()
        .filter(|w| w.path.contains("push"))
        .map(|w| w.var.clone())
        .collect();

    // Counter increments: `x++` / `++x` (UnOp) or `x += k` (AssignOp::Add) where
    // `x`'s root identifier is a state variable written by this function. We
    // intersect against the recorded storage-write roots so a purely-local loop
    // counter (`i++`) is not mistaken for state growth.
    let state_write_roots: std::collections::HashSet<&str> =
        fun.effects.storage_writes.iter().map(|w| w.var.as_str()).collect();
    for s in &fun.body {
        s.visit_exprs(&mut |e| match &e.kind {
            ExprKind::Unary { op, operand }
                if matches!(op, UnOp::PostInc | UnOp::PreInc) =>
            {
                if let Some(r) = ident_root(operand) {
                    if state_write_roots.contains(r) {
                        grown.insert(r.to_string());
                    }
                }
            }
            ExprKind::Assign { op: AssignOp::Add, target, .. } => {
                if let Some(r) = ident_root(target) {
                    if state_write_roots.contains(r) {
                        grown.insert(r.to_string());
                    }
                }
            }
            _ => {}
        });
    }
    grown
}

/// State/identifier roots a *guard* in `fun` bounds with an ordering comparison —
/// the syntactic signature of an enforced cap. A cap is an ordering comparison
/// (`<`,`<=`,`>`,`>=`) appearing in a guard context: a `require(...)`/`assert(...)`
/// argument, or an `if (...)` condition (whose branch typically reverts). Loop
/// **headers** (`for (...; i < count; ...)`, `while (i < count)`) are deliberately
/// excluded — a loop's own iteration bound is NOT a cap on the bound's growth, so
/// counting it would falsely mark a freely-growable counter (e.g. `derivativeCount`,
/// which appears in `for i < derivativeCount` weight-sum loops in its own grower)
/// as capped and suppress the finding. Conservatively over-approximates the capped
/// set within guard contexts, which only ever *suppresses* a finding.
fn vars_ordering_compared_in(fun: &Function) -> std::collections::HashSet<String> {
    let mut capped = std::collections::HashSet::new();
    // Collect ordering-comparison roots from an expression tree (used for guard
    // conditions and require/assert arguments).
    fn ordering_roots(e: &Expr, out: &mut std::collections::HashSet<String>) {
        e.visit(&mut |x| {
            if let ExprKind::Binary { op, lhs, rhs } = &x.kind {
                if op.is_ordering() {
                    if let Some(r) = ident_root(lhs) {
                        out.insert(r.to_string());
                    }
                    if let Some(r) = ident_root(rhs) {
                        out.insert(r.to_string());
                    }
                }
            }
        });
    }
    fn walk(s: &Stmt, capped: &mut std::collections::HashSet<String>) {
        match &s.kind {
            // `if (cond) { ... }` — `cond` is a guard context (cap check).
            StmtKind::If { cond, then_branch, else_branch } => {
                ordering_roots(cond, capped);
                for st in then_branch.iter().chain(else_branch.iter()) {
                    walk(st, capped);
                }
            }
            // `require(cond, ...)` / `assert(cond)` arguments are guard contexts.
            StmtKind::Expr(e) => {
                e.visit(&mut |x| {
                    if let ExprKind::Call(c) = &x.kind {
                        if matches!(
                            c.kind,
                            CallKind::Builtin(Builtin::Require) | CallKind::Builtin(Builtin::Assert)
                        ) {
                            if let Some(arg) = c.args.first() {
                                ordering_roots(arg, capped);
                            }
                        }
                    }
                });
            }
            // Descend into nested blocks/loops/try, but do NOT treat the loop
            // headers themselves as cap checks (we never inspect For/While `cond`).
            StmtKind::Block { stmts, .. } => {
                for st in stmts {
                    walk(st, capped);
                }
            }
            StmtKind::While { body, .. } | StmtKind::DoWhile { body, .. } => {
                for st in body {
                    walk(st, capped);
                }
            }
            StmtKind::For { body, .. } => {
                for st in body {
                    walk(st, capped);
                }
            }
            StmtKind::Try { body, catches, .. } => {
                for st in body {
                    walk(st, capped);
                }
                for cl in catches {
                    for st in &cl.body {
                        walk(st, capped);
                    }
                }
            }
            _ => {}
        }
    }
    for s in &fun.body {
        walk(s, &mut capped);
    }
    capped
}

/// The root identifier of an lvalue/expression chain (`a` for `a`, `a.b`,
/// `a[i]`, `a.b[i].c`), if any.
fn ident_root(e: &Expr) -> Option<&str> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => ident_root(base),
        _ => None,
    }
}

/// True if `loop_stmt`'s bound — its `for` condition/step (or `while`/`do-while`
/// condition) — reads a state variable in `state`. Only the loop's *header*
/// expressions are inspected (not the body): the bound is what governs the
/// iteration count. For-loop bodies are excluded so an in-body read of an
/// unrelated growable var does not count as the bound.
fn loop_bound_reads_state(loop_stmt: &Stmt, state: &std::collections::HashSet<String>) -> bool {
    if state.is_empty() {
        return false;
    }
    let mut hit = false;
    let mut check = |e: &Expr| {
        e.visit(&mut |x| {
            if !hit {
                if let Some(r) = ident_root(x) {
                    // `length` of a state array, or a bare state counter.
                    if state.contains(r) {
                        hit = true;
                    }
                }
            }
        });
    };
    match &loop_stmt.kind {
        StmtKind::For { cond, step, .. } => {
            if let Some(c) = cond {
                check(c);
            }
            if let Some(st) = step {
                check(st);
            }
        }
        StmtKind::While { cond, .. } | StmtKind::DoWhile { cond, .. } => check(cond),
        _ => {}
    }
    hit
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Push-payment: pays every recipient inside a loop. A single recipient with a
    // reverting `receive()` reverts the whole batch (Akutars-class DoS).
    const VULN: &str = r#"
        pragma solidity ^0.8.0;
        contract Airdrop {
            address[] public recipients;
            mapping(address => uint256) public owed;

            function addRecipient(address r, uint256 amt) external {
                recipients.push(r);
                owed[r] = amt;
            }

            function distribute() external {
                for (uint256 i = 0; i < recipients.length; i++) {
                    address r = recipients[i];
                    (bool ok, ) = r.call{value: owed[r]}("");
                    require(ok, "transfer failed");
                }
            }
        }
    "#;

    // Safe: pull-payment. Each recipient withdraws their own credit; no loop over
    // untrusted recipients, so one reverting recipient cannot brick anyone else.
    const SAFE: &str = r#"
        pragma solidity ^0.8.0;
        contract PullAirdrop {
            mapping(address => uint256) public credits;
            address public owner;

            constructor() { owner = msg.sender; }

            function allocate(address r, uint256 amt) external {
                require(msg.sender == owner, "auth");
                credits[r] += amt;
            }

            function withdraw() external {
                uint256 amt = credits[msg.sender];
                credits[msg.sender] = 0;
                (bool ok, ) = msg.sender.call{value: amt}("");
                require(ok, "transfer failed");
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "denial-of-service"), "{:?}", fs);
    }

    #[test]
    fn silent_on_calldata_batch() {
        // A batch over a CALLER-supplied array doing a token pull is the caller's
        // own concern, not a protocol DoS — must stay silent.
        let fs = run(r#"
            interface IERC20 { function transferFrom(address f, address t, uint256 a) external returns (bool); }
            contract Batch {
                function pull(address[] calldata tokens, uint256[] calldata amts) external {
                    for (uint256 i = 0; i < tokens.length; i++) {
                        IERC20(tokens[i]).transferFrom(msg.sender, address(this), amts[i]);
                    }
                }
            }
        "#);
        assert!(!fs.iter().any(|f| f.detector == "denial-of-service"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "denial-of-service"));
    }

    // ------------------------------------------------------------------
    // Regressions for the fault-tolerant / read-only-aggregator suppression
    // (the R5 pendle dogfood fired on these). Each asserts SILENT; the two
    // positives below assert the detector still FIRES on a real batch-bricking
    // push loop and on an unconditional `require(success)` loop.
    // ------------------------------------------------------------------

    // (A) FAULT-TOLERANT: the per-entry success is captured and stored; a failed
    // entry is tolerated (the loop never reverts on failure). Must stay silent.
    #[test]
    fn silent_on_fault_tolerant_store() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            contract TryBatch {
                function exec(address[] calldata targets, bytes[] calldata data)
                    external
                    returns (bool[] memory results)
                {
                    results = new bool[](targets.length);
                    for (uint256 i = 0; i < targets.length; i++) {
                        (bool ok, ) = targets[i].call(data[i]);
                        results[i] = ok;
                    }
                }
            }
        "#);
        assert!(
            !fs.iter().any(|f| f.detector == "denial-of-service"),
            "fault-tolerant store-the-result loop must not flag: {:?}",
            fs
        );
    }

    // (A) FAULT-TOLERANT with a `requireSuccess` knob: the abort is gated behind a
    // caller flag and the outcome is stored into a `Result[]` — the Multicall2 /
    // PendleMulticall `tryAggregate` shape. Must stay silent.
    #[test]
    fn silent_on_try_aggregate() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            contract Aggregator {
                struct Result { bool success; bytes returnData; }
                function tryAggregate(bool requireSuccess, address[] calldata targets, bytes[] calldata data)
                    external
                    returns (Result[] memory returnData)
                {
                    returnData = new Result[](targets.length);
                    for (uint256 i = 0; i < targets.length; i++) {
                        (bool success, bytes memory ret) = targets[i].call(data[i]);
                        if (requireSuccess) {
                            require(success, "call failed");
                        }
                        returnData[i] = Result(success, ret);
                    }
                }
            }
        "#);
        assert!(
            !fs.iter().any(|f| f.detector == "denial-of-service"),
            "flag-gated try-aggregate must not flag: {:?}",
            fs
        );
    }

    // (B) READ-ONLY aggregator helper: a `*Multicall*` contract whose loop forwards
    // calldata and returns data with no native value — even though it bubbles the
    // failure via `require(success)`. The caller supplies its own list; there are
    // no stored recipients to grief. Must stay silent.
    #[test]
    fn silent_on_readonly_multicall() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            contract ReadMulticall {
                function aggregate(address[] calldata targets, bytes[] calldata data)
                    external
                    returns (bytes[] memory returnData)
                {
                    returnData = new bytes[](targets.length);
                    for (uint256 i = 0; i < targets.length; i++) {
                        (bool success, bytes memory ret) = targets[i].call(data[i]);
                        require(success, "Multicall: call failed");
                        returnData[i] = ret;
                    }
                }
            }
        "#);
        assert!(
            !fs.iter().any(|f| f.detector == "denial-of-service"),
            "read-only multicall aggregator must not flag: {:?}",
            fs
        );
    }

    // POSITIVE: a value-PUSHING batch in a *Multicall*-named contract is NOT a
    // read-only helper — it forwards ETH and reverts the whole batch on one
    // failure. The aggregator-name suppression must NOT silence it.
    #[test]
    fn fires_on_value_pushing_multicall() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            contract OwnerMulticall {
                struct Call { address target; uint256 value; bytes callData; }
                function aggregate(Call[] calldata calls)
                    external
                    payable
                    returns (bytes[] memory rtnData)
                {
                    rtnData = new bytes[](calls.length);
                    for (uint256 i = 0; i < calls.length; i++) {
                        (bool success, bytes memory resp) =
                            calls[i].target.call{value: calls[i].value}(calls[i].callData);
                        require(success, "call failed");
                        rtnData[i] = resp;
                    }
                }
            }
        "#);
        assert!(
            fs.iter().any(|f| f.detector == "denial-of-service"),
            "value-pushing batch that reverts on failure must still flag: {:?}",
            fs
        );
    }

    // POSITIVE: an unconditional `require(success)` over an in-loop low-level call
    // (no `requireSuccess` flag, nothing stored) reverts the whole batch on one
    // failure — the kept DoS shape. Must still FIRE.
    #[test]
    fn fires_on_unconditional_require_loop() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            contract Caller {
                address[] public a;
                function pump() external {
                    for (uint256 i = 0; i < a.length; i++) {
                        (bool ok, ) = a[i].call("");
                        require(ok);
                    }
                }
            }
        "#);
        assert!(
            fs.iter().any(|f| f.detector == "denial-of-service"),
            "unconditional require(success) loop must still flag: {:?}",
            fs
        );
    }

    // ------------------------------------------------------------------
    // Pattern 1b: unbounded loop whose bound is an UNCAPPED-GROWABLE state var,
    // with a per-iteration external call (Asymmetry-M-08 / SafEth `unstake`).
    // ------------------------------------------------------------------

    // POSITIVE: the SafEth-`unstake` shape — bound is a state counter
    // (`derivativeCount`) grown by a privileged-but-uncapped `addDerivative`
    // (`derivativeCount++`, no max), each iteration calls into `derivatives[i]`.
    // The growth is owner-gated (so NOT attacker-growable), yet the loop is still
    // an unbounded-gas / one-reverting-element DoS. Must FIRE as UnboundedLoop.
    #[test]
    fn fires_on_uncapped_counter_loop_with_external_call() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            interface IDerivative {
                function balance() external view returns (uint256);
                function withdraw(uint256 amount) external;
            }
            contract Vault {
                address public owner;
                uint256 public derivativeCount;
                mapping(uint256 => IDerivative) public derivatives;
                modifier onlyOwner() { require(msg.sender == owner, "auth"); _; }

                function addDerivative(address d) external onlyOwner {
                    derivatives[derivativeCount] = IDerivative(d);
                    derivativeCount++;
                }

                function unstake(uint256 amt) external {
                    for (uint256 i = 0; i < derivativeCount; i++) {
                        uint256 bal = derivatives[i].balance();
                        if (bal == 0) continue;
                        derivatives[i].withdraw((bal * amt) / 1e18);
                    }
                }
            }
        "#);
        assert!(
            fs.iter().any(|f| {
                f.detector == "denial-of-service" && f.category == sluice_findings::Category::UnboundedLoop
            }),
            "uncapped-counter loop with per-iteration external call must fire as UnboundedLoop: {:?}",
            fs
        );
    }

    // NEGATIVE: identical loop shape, but `addDerivative` enforces a cap
    // (`require(derivativeCount < MAX)`). The bound can no longer grow without
    // limit, so Pattern 1b must stay SILENT.
    #[test]
    fn silent_on_capped_counter_loop() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            interface IDerivative {
                function balance() external view returns (uint256);
                function withdraw(uint256 amount) external;
            }
            contract CappedVault {
                address public owner;
                uint256 public derivativeCount;
                uint256 constant MAX = 10;
                mapping(uint256 => IDerivative) public derivatives;
                modifier onlyOwner() { require(msg.sender == owner, "auth"); _; }

                function addDerivative(address d) external onlyOwner {
                    require(derivativeCount < MAX, "too many");
                    derivatives[derivativeCount] = IDerivative(d);
                    derivativeCount++;
                }

                function unstake(uint256 amt) external {
                    for (uint256 i = 0; i < derivativeCount; i++) {
                        uint256 bal = derivatives[i].balance();
                        derivatives[i].withdraw((bal * amt) / 1e18);
                    }
                }
            }
        "#);
        assert!(
            !fs.iter().any(|f| {
                f.detector == "denial-of-service" && f.category == sluice_findings::Category::UnboundedLoop
            }),
            "capped-counter loop must not fire as UnboundedLoop: {:?}",
            fs
        );
    }

    // NEGATIVE: a loop bounded by an uncapped-growable state counter but with a
    // PURE-COMPUTATION body (no external call) — the SafEth `adjustWeight` /
    // weight-sum shape. The per-element gas is tiny, so this is not the gas-DoS
    // class. Must stay SILENT (the per-iteration external call is the load-bearing
    // discriminator).
    #[test]
    fn silent_on_uncapped_counter_pure_loop() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            contract Weights {
                address public owner;
                uint256 public count;
                uint256 public total;
                mapping(uint256 => uint256) public weights;
                modifier onlyOwner() { require(msg.sender == owner, "auth"); _; }

                function add(uint256 w) external onlyOwner {
                    weights[count] = w;
                    count++;
                }

                function recompute() external {
                    uint256 t = 0;
                    for (uint256 i = 0; i < count; i++) {
                        t += weights[i];
                    }
                    total = t;
                }
            }
        "#);
        assert!(
            !fs.iter().any(|f| {
                f.detector == "denial-of-service" && f.category == sluice_findings::Category::UnboundedLoop
            }),
            "pure-computation loop over a counter must not fire as UnboundedLoop: {:?}",
            fs
        );
    }

    // NEGATIVE: a small FIXED-bound loop with a per-iteration external call. The
    // bound is a literal, no growable state var is involved, so Pattern 1b must
    // stay SILENT (and the calldata/value gates keep pattern 2 silent too).
    #[test]
    fn silent_on_fixed_bound_external_loop() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            interface IOracle { function poke() external; }
            contract Fixed {
                IOracle[3] public oracles;
                function refresh() external {
                    for (uint256 i = 0; i < 3; i++) {
                        oracles[i].poke();
                    }
                }
            }
        "#);
        assert!(
            !fs.iter().any(|f| {
                f.detector == "denial-of-service" && f.category == sluice_findings::Category::UnboundedLoop
            }),
            "fixed-bound external-call loop must not fire as UnboundedLoop: {:?}",
            fs
        );
    }
}
