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
//! 1c. **Unbounded loop over an aggregate-growable list fetched from another
//!    contract** — a loop whose bound is `V.length` (or which indexes `V`) where
//!    `V` is a *local* variable initialized in the same function from an external
//!    getter that returns an array (`X.userGauges(user)`, `X.getPositions(...)`,
//!    …), and whose body does genuine per-iteration work (a call — internal or
//!    external — or a storage write). This is the EthereumCreditGuild
//!    `ProfitManager.claimRewards` shape (M-25): the loop iterates
//!    `GuildToken(guild).userGauges(user)` and calls `claimGaugeRewards` (which
//!    itself transfers CREDIT) on every element. The list of gauges a user is in
//!    grows permissionlessly (any holder can `incrementGauge` into more gauges),
//!    so as positions accumulate the per-element work multiplied by the count
//!    eventually exceeds the block gas limit and the claim path bricks. Unlike
//!    pattern (1) the growing array lives in *another* contract (so it is not in
//!    this contract's `growable_arrays`), and unlike (1b) the bound is a memory
//!    array (not a state counter) and the per-iteration work may be an *internal*
//!    call that fans out to external transfers. Conservative gates keep it quiet:
//!    the bound local must be sourced from an *external* call (a caller-supplied
//!    calldata/memory array, or a freshly `new`-allocated array, does NOT count),
//!    the loop body must do non-trivial work (a call or a storage write — pure
//!    read/arithmetic accumulators stay silent), and `try`-wrapped fault-tolerant
//!    loops are suppressed. Emitted as [`Category::UnboundedLoop`].
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
//!
//! 4. **Single-recipient push-payment that requires success** — a withdrawal /
//!    claim / unstake / redeem-shaped, state-mutating, externally-reachable
//!    function that pushes native ETH to a **caller- or recipient-controlled**
//!    address (`address(msg.sender).call{value:..}("")`, `payable(to).transfer(..)`,
//!    a `to`/`recipient`/`receiver`/`beneficiary` parameter) and then **requires
//!    the push succeeded** (`require(sent, ...)` / `if (!sent) revert`). A contract
//!    caller whose `receive`/`fallback` reverts — or any push failure — permanently
//!    blocks that withdrawal even though all the upstream accounting/derivative
//!    work already succeeded (Asymmetry M-06: `SafEth.unstake` ends with
//!    `(bool sent,) = address(msg.sender).call{value: ...}(""); require(sent, ...)`).
//!    The fix is pull-payment (credit a withdrawable balance) or to not hard-require
//!    the push. Emitted as [`Category::DenialOfService`]. Three conservative gates
//!    keep this quiet on real protocols:
//!      * SUPPRESS pull-payment shapes — a function that zeroes/credits a mapping
//!        balance for the recipient before pushing is the *correct* withdraw idiom,
//!        not the bug (the bricked party is only itself, and re-tryable).
//!      * SUPPRESS calls to trusted/immutable protocol addresses (the target is a
//!        state/immutable var, not `msg.sender` / a recipient parameter).
//!      * SUPPRESS the "refund excess to msg.sender" tail of a `payable` function —
//!        that is a refund of the caller's own overpayment, not the principal
//!        withdrawal, so a self-griefing caller only hurts itself on a refund it
//!        controls. Requires a withdrawal/claim/unstake/redeem-shaped name.

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

            // ---- Pattern 1c: unbounded loop over an aggregate-growable list that
            // was FETCHED from another contract via an external getter, with genuine
            // per-iteration work. This is the EthereumCreditGuild
            // `ProfitManager.claimRewards` shape (M-25):
            //   address[] memory gauges = GuildToken(guild).userGauges(user);
            //   for (uint i = 0; i < gauges.length; ) {
            //       creditEarned += claimGaugeRewards(user, gauges[i]); // internal, fans out to a CREDIT transfer
            //   }
            // The iterated list grows permissionlessly in the *other* contract (any
            // holder can `incrementGauge` into more gauges), so neither pattern (1)
            // (growable storage array in THIS contract) nor (1b) (a state counter
            // bound + in-loop external call) matches. We key on: a loop whose bound
            // reads a LOCAL whose initializer is an EXTERNAL call returning an array,
            // and whose body does non-trivial work (a call — internal or external —
            // or a storage write).
            //
            // Conservative gates that keep this quiet on real protocols:
            //   * the bound local must be sourced from an *external* call — a
            //     caller-supplied calldata/memory parameter, or a `new T[](n)`
            //     allocation, is NOT externally fetched and stays silent;
            //   * the loop body must do real per-element work (a call or a storage
            //     write); a pure read/arithmetic accumulator stays silent; and
            //   * `try`-wrapped fault-tolerant loops are suppressed (one failing
            //     element does not brick the batch).
            if !emitted {
                let fetched = locals_from_external_getter(f);
                if !fetched.is_empty() {
                    let hit = loops_in(f).into_iter().find(|ls| {
                        loop_bound_reads_state(ls, &fetched)
                            && loop_has_per_iteration_work(loop_body(ls))
                            && !loop_is_fault_tolerant(cx, f, ls)
                    });
                    if let Some(ls) = hit {
                        let b = FindingBuilder::new(self.id(), Category::UnboundedLoop)
                            .title("Unbounded loop over an aggregate-growable list fetched from another contract")
                            .severity(Severity::Medium)
                            .confidence(0.5)
                            .dimension(Dimension::Invariant)
                            .dimension(Dimension::Frontier)
                            .message(format!(
                                "`{}` loops up to the length of a list it fetches from another contract via an \
                                 external getter, and does per-element work (a call or storage write) on every \
                                 iteration. The fetched list grows as positions accumulate — and where any user \
                                 can permissionlessly add entries (e.g. voting into more gauges), it grows without \
                                 an enforced bound — so the per-element gas multiplied by the element count \
                                 eventually exceeds the block gas limit and the function can never complete, \
                                 permanently freezing the logic (and any funds) that depend on it.",
                                f.name
                            ))
                            .recommendation(
                                "Cap or paginate the per-element work, bound the number of positions a single \
                                 account can accumulate, or restructure so the gas cost cannot be driven past the \
                                 block limit as the fetched list grows.",
                            );
                        out.push(cx.finish(b, f.id, ls.span));
                        emitted = true;
                    }
                }
            }
            let _ = emitted;

            // ---- Pattern 4: single-recipient push-payment that requires success
            // (Asymmetry M-06 / SafEth `unstake`). A withdrawal/claim/unstake/redeem-
            // shaped, state-mutating, externally-reachable function pushes native ETH
            // to a caller- or recipient-controlled address and then REQUIRES the push
            // succeeded. A contract caller whose `receive`/`fallback` reverts bricks
            // the withdrawal even though all the upstream work already succeeded. The
            // fix is pull-payment or not hard-requiring the push. Independent of the
            // loop patterns above, so M-06 and M-08 both fire on `unstake`.
            if f.is_state_mutating()
                && f.is_externally_reachable()
                && is_withdrawal_shaped(&f.name)
                && !uses_pull_payment(cx, f)
            {
                if let Some(call_span) = push_payment_requiring_success(cx, f) {
                    let b = FindingBuilder::new(self.id(), Category::DenialOfService)
                        .title("Withdrawal pushes ETH to a caller-controlled address and requires the push to succeed")
                        .severity(Severity::Medium)
                        .confidence(0.5)
                        .dimension(Dimension::Frontier)
                        .dimension(Dimension::ValueFlow)
                        .message(format!(
                            "`{}` sends the withdrawn ETH to a caller- or recipient-controlled address with a \
                             low-level `call{{value:}}`/`transfer`/`send` and then `require`s the push \
                             succeeded. A contract caller whose `receive`/`fallback` reverts (or any push \
                             failure) permanently blocks this withdrawal even though every upstream step \
                             (burning shares, withdrawing from each derivative) already succeeded — a \
                             push-payment denial-of-service. If the recipient is shared or looped, one \
                             griefing party can brick the path for everyone.",
                            f.name
                        ))
                        .recommendation(
                            "Use the pull-payment pattern: credit a withdrawable balance the recipient \
                             claims in a separate call, so a reverting recipient only blocks itself. \
                             Alternatively do not hard-`require` the push to succeed (record the failure \
                             and let the recipient retry), or restrict pushes to addresses you trust.",
                        );
                    out.push(cx.finish(b, f.id, call_span));
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

/// Local variables declared in `f` whose initializer is (or contains) an EXTERNAL
/// call returning an array — i.e. a list FETCHED from another contract via a getter
/// (`address[] memory gauges = GuildToken(guild).userGauges(user)`). Iterating such
/// a list up to its `.length`, while doing per-element work, is the M-25 DoS shape:
/// the list lives in another contract and grows as positions accumulate (and where
/// any user can permissionlessly add entries, grows unbounded). Returns the local
/// variable names.
///
/// Conservative by construction: a local initialized from a calldata/memory
/// parameter, a `new T[](n)` allocation, or pure arithmetic does NOT qualify — only
/// a genuine cross-contract external call (`CallKind::External` / low-level / static)
/// is treated as an externally-fetched list. A `TypeCast` wrapper
/// (`GuildToken(guild)`) is the *receiver* of the external method call, so it is the
/// outer call (`.userGauges(...)`, classified External) that we match.
fn locals_from_external_getter(f: &Function) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    for s in &f.body {
        s.visit(&mut |st| {
            if let StmtKind::VarDecl { name: Some(name), init: Some(init), .. } = &st.kind {
                if init_is_external_array_fetch(init) {
                    out.insert(name.clone());
                }
            }
        });
    }
    out
}

/// True if an initializer expression is an external call that transfers control to
/// another contract AND is keyed by an ACCOUNT-shaped argument — the fetch of a
/// *per-account position list* from a getter (`GuildToken(guild).userGauges(user)`,
/// `X.getPositions(msg.sender)`, `X.listOf(address(this))`). The account argument is
/// the load-bearing discriminator: it is what makes the list grow as that account
/// accumulates positions, and what (where the add path is permissionless) lets the
/// aggregate grow without bound.
///
/// This deliberately EXCLUDES protocol *registry* getters that take no per-account
/// argument or are keyed by a protocol-config key: `pool.getReservesList()`,
/// `stakingRouter.getStakingModuleIds()`, `incentives.getRewardsByAsset(asset)`.
/// Those are admin-curated, bounded lists — iterating them is not an attacker-
/// driven DoS — so requiring an account-shaped argument keeps real protocols quiet.
fn init_is_external_array_fetch(init: &Expr) -> bool {
    // Find the outermost call that is an external transfer-of-control (the getter),
    // unwrapping any cast/member/index chain that wraps it.
    fn head_external_call(e: &Expr) -> Option<&sluice_ir::Call> {
        match &e.kind {
            ExprKind::Call(c) if c.kind.is_external_transfer_of_control() => Some(c),
            ExprKind::Call(c) if matches!(c.kind, CallKind::TypeCast) => {
                c.args.iter().find_map(head_external_call)
            }
            ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => head_external_call(base),
            _ => None,
        }
    }
    match head_external_call(init) {
        Some(c) => c.args.iter().any(expr_is_account_shaped),
        None => false,
    }
}

/// True if an expression denotes an account/holder — `msg.sender`, `address(this)`,
/// or an account-shaped identifier (`user`/`account`/`owner`/`staker`/`holder`/
/// `recipient`/`who`). Such an argument to a list getter is what makes the returned
/// list a *per-account* position list (the thing that grows as the account takes
/// positions), distinguishing it from a no-arg / config-keyed protocol registry.
fn expr_is_account_shaped(e: &Expr) -> bool {
    match &e.kind {
        // `msg.sender`
        ExprKind::Member { base, member } => {
            if member == "sender" {
                if let ExprKind::Ident(b) = &base.kind {
                    if b == "msg" {
                        return true;
                    }
                }
            }
            false
        }
        // `address(this)` / `payable(this)` casts wrap `this`.
        ExprKind::Call(c) if matches!(c.kind, CallKind::TypeCast) => {
            c.args.iter().any(expr_is_account_shaped)
        }
        ExprKind::Ident(n) => {
            if n == "this" {
                return true;
            }
            let n = n.trim_start_matches('_').to_ascii_lowercase();
            matches!(
                n.as_str(),
                "user" | "account" | "owner" | "staker" | "holder" | "recipient" | "who" | "from" | "beneficiary"
            )
        }
        _ => false,
    }
}

/// True if a loop body does genuine per-iteration work: it contains a call (of any
/// kind that transfers control — internal, external, or low-level) OR a storage
/// write (an indexed/member assignment, a compound assignment, or a `.push`). A
/// pure read/arithmetic accumulator into a *local* (`t += weights[i]`) is NOT
/// counted as protocol work — but an internal call that fans out to external
/// transfers (the M-25 `claimGaugeRewards(...)`) IS. We err toward requiring a
/// CALL: an internal/external/low-level call is the load-bearing per-element cost
/// that scales with the list length.
fn loop_has_per_iteration_work(body: &[Stmt]) -> bool {
    let mut work = false;
    for s in body {
        s.visit_exprs(&mut |e| {
            if work {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                // Any genuine function call (not a mere type cast / builtin like
                // `require`) is per-element work that scales with the bound.
                let is_real_call = matches!(
                    c.kind,
                    CallKind::Internal
                        | CallKind::External
                        | CallKind::LowLevelCall
                        | CallKind::DelegateCall
                        | CallKind::StaticCall
                        | CallKind::Send
                        | CallKind::Transfer
                );
                if is_real_call {
                    work = true;
                }
            }
        });
        if work {
            break;
        }
    }
    work
}

/// True if the function name is withdrawal/claim/unstake/redeem-shaped — the
/// principal-payout idioms where a hard-required push to a caller-controlled
/// address is a DoS. We deliberately exclude generic names (so a `pay`/`send`
/// refund helper, or a `payable` constructor, does not light up) and require one
/// of these payout verbs, matching the M-06 `unstake` shape.
fn is_withdrawal_shaped(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("withdraw")
        || n.contains("unstake")
        || n.contains("redeem")
        || n.contains("claim")
        || n.contains("exit")
        || n.contains("cashout")
        || n.contains("cash_out")
}

/// Find a single-recipient push-payment that requires success in `f`'s **top-level**
/// body (not inside a loop — that is Pattern 2). Returns the span of the value-
/// bearing call when:
///   * the call sends native ETH (`{value:}` present, `.transfer`, or `.send`),
///   * its target address is caller- or recipient-controlled (`msg.sender`,
///     `payable(msg.sender)`, `address(msg.sender)`, or a recipient-shaped
///     parameter such as `to`/`recipient`/`receiver`/`dst`/`beneficiary`), and
///   * the function `require`s/`assert`s the push succeeded, or reverts on its
///     failure (`if (!sent) revert`) — i.e. a failed push aborts the withdrawal.
///
/// A call to a state/immutable protocol address (not the caller/recipient) is not
/// matched. Calls lexically inside a loop are skipped (the loop is Pattern 2's job).
fn push_payment_requiring_success(cx: &AnalysisContext, f: &Function) -> Option<Span> {
    // Collect the spans of all loop bodies so we can exclude in-loop calls.
    let loop_spans: Vec<Span> = loops_in(f).iter().map(|ls| ls.span).collect();
    let in_a_loop = |sp: Span| {
        loop_spans
            .iter()
            .any(|ls| sp.start >= ls.start && sp.end <= ls.end && sp != *ls)
    };

    let mut hit: Option<Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                let sends_native =
                    c.value.is_some() || matches!(c.kind, CallKind::Transfer | CallKind::Send);
                if !sends_native {
                    return;
                }
                if in_a_loop(e.span) {
                    return;
                }
                if call_target_is_caller_controlled(c) {
                    hit = Some(e.span);
                }
            }
        });
        if hit.is_some() {
            break;
        }
    }
    let span = hit?;
    // The push must be hard-required to succeed (otherwise a failed push is
    // tolerated and there is no DoS). Recognized syntactically over the function's
    // comment-stripped source: a `require(`/`assert(` of the success bit, or a
    // bubbled `if (!ok) revert`. SafEth's tail is `require(sent, "Failed...")`.
    let src = cx.source_text(f.span);
    let compact: String = src.chars().filter(|c| !c.is_whitespace()).collect();
    let requires_success = compact.contains("require(")
        || compact.contains("assert(")
        || compact.contains(")revert")
        || compact.contains("{revert")
        || compact.contains(";revert");
    if requires_success {
        Some(span)
    } else {
        None
    }
}

/// True if a value-bearing call's **target address** is caller- or recipient-
/// controlled: `msg.sender` (incl. `payable(msg.sender)` / `address(msg.sender)`),
/// or a recipient-shaped identifier (a `to`/`recipient`/`receiver`/`dst`/
/// `beneficiary`/`account`/`user` parameter). A call to a state/immutable protocol
/// address (e.g. `address(weth).call{value:..}`, `treasury.transfer(..)`) is NOT
/// caller-controlled and stays silent.
fn call_target_is_caller_controlled(c: &sluice_ir::Call) -> bool {
    // The address the value is sent to is the call's receiver (`recv.transfer(..)`,
    // `recv.call{value:..}(..)`). For `address(msg.sender).call{...}` the receiver
    // is the `address(msg.sender)` cast.
    let target = c.receiver.as_deref().unwrap_or(&c.callee);
    expr_is_caller_controlled(target)
}

/// Recursively decide whether an address expression denotes the caller or a
/// recipient parameter. Unwraps `payable(x)` / `address(x)` casts and `.member`
/// chains down to a root identifier or a `msg.sender` access.
fn expr_is_caller_controlled(e: &Expr) -> bool {
    match &e.kind {
        // `msg.sender`
        ExprKind::Member { base, member } => {
            if member == "sender" {
                if let ExprKind::Ident(b) = &base.kind {
                    if b == "msg" {
                        return true;
                    }
                }
            }
            // unwrap `something.field` — still inspect the base for a recipient root
            expr_is_caller_controlled(base)
        }
        // `payable(x)` / `address(x)` casts wrap the real target in args[0].
        ExprKind::Call(c) if matches!(c.kind, CallKind::TypeCast) => {
            c.args.first().map(expr_is_caller_controlled).unwrap_or(false)
        }
        ExprKind::Ident(n) => is_recipient_name(n),
        _ => false,
    }
}

/// A parameter/identifier name that denotes a payment recipient (so a push to it
/// is caller-influenced). Conservative list of the common recipient idioms.
fn is_recipient_name(n: &str) -> bool {
    let n = n.trim_start_matches('_').to_ascii_lowercase();
    matches!(
        n.as_str(),
        "to" | "recipient" | "receiver" | "dst" | "destination" | "beneficiary" | "account" | "user"
    )
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

    // ------------------------------------------------------------------
    // Pattern 4: single-recipient push-payment that requires success
    // (Asymmetry-M-06 / SafEth `unstake`).
    // ------------------------------------------------------------------

    // POSITIVE: the SafEth-`unstake` shape — burns shares, then pushes the ETH to
    // `address(msg.sender).call{value:..}("")` and `require`s success. A contract
    // caller whose `receive` reverts bricks its own withdrawal. Must FIRE as
    // DenialOfService (and is independent of the M-08 unbounded-loop catch).
    #[test]
    fn fires_on_push_payment_requiring_success() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            interface IDerivative { function balance() external view returns (uint256); function withdraw(uint256 a) external; }
            contract SafEth {
                uint256 public derivativeCount;
                mapping(uint256 => IDerivative) public derivatives;
                function burn(address, uint256) internal {}
                function unstake(uint256 _safEthAmount) external {
                    uint256 ethBefore = address(this).balance;
                    for (uint256 i = 0; i < derivativeCount; i++) {
                        derivatives[i].withdraw(_safEthAmount);
                    }
                    uint256 toSend = address(this).balance - ethBefore;
                    (bool sent, ) = address(msg.sender).call{value: toSend}("");
                    require(sent, "Failed to send Ether");
                }
            }
        "#);
        assert!(
            fs.iter().any(|f| {
                f.detector == "denial-of-service"
                    && f.category == sluice_findings::Category::DenialOfService
                    && f.function == "unstake"
            }),
            "push-payment-requiring-success unstake must fire as DenialOfService: {:?}",
            fs
        );
    }

    // POSITIVE: a `claim`/`redeem` to a recipient PARAMETER (`to`) with a hard
    // `require(ok)`. Recipient-controlled target, so a reverting `to` bricks it.
    #[test]
    fn fires_on_push_to_recipient_param() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            contract Vault {
                mapping(address => uint256) public shares;
                function redeem(uint256 amt, address to) external {
                    shares[msg.sender] -= amt;
                    (bool ok, ) = payable(to).call{value: amt}("");
                    require(ok, "send failed");
                }
            }
        "#);
        assert!(
            fs.iter().any(|f| {
                f.detector == "denial-of-service"
                    && f.category == sluice_findings::Category::DenialOfService
                    && f.function == "redeem"
            }),
            "push to recipient param requiring success must fire: {:?}",
            fs
        );
    }

    // NEGATIVE: pull-payment withdraw — the recipient's credited balance is zeroed
    // before the push. A reverting recipient only blocks ITSELF and the call is
    // re-tryable; not the M-06 DoS class. Must stay SILENT for Pattern 4.
    #[test]
    fn silent_on_pull_payment_withdraw() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            contract PullVault {
                mapping(address => uint256) public credits;
                function withdraw() external {
                    uint256 amt = credits[msg.sender];
                    credits[msg.sender] = 0;
                    (bool ok, ) = msg.sender.call{value: amt}("");
                    require(ok, "transfer failed");
                }
            }
        "#);
        assert!(
            !fs.iter().any(|f| {
                f.detector == "denial-of-service"
                    && f.category == sluice_findings::Category::DenialOfService
            }),
            "pull-payment withdraw must not fire Pattern 4: {:?}",
            fs
        );
    }

    // NEGATIVE: a `payable` `deposit` that refunds excess to `msg.sender` at the
    // tail and requires success. Not a withdrawal-shaped name, so Pattern 4 must
    // stay SILENT (refund-excess is the caller's own overpayment).
    #[test]
    fn silent_on_payable_refund_excess_tail() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            contract Sale {
                uint256 public price;
                mapping(address => uint256) public bought;
                function buy(uint256 qty) external payable {
                    uint256 cost = qty * price;
                    require(msg.value >= cost, "underpaid");
                    bought[msg.sender] += qty;
                    uint256 refund = msg.value - cost;
                    if (refund > 0) {
                        (bool ok, ) = msg.sender.call{value: refund}("");
                        require(ok, "refund failed");
                    }
                }
            }
        "#);
        assert!(
            !fs.iter().any(|f| {
                f.detector == "denial-of-service"
                    && f.category == sluice_findings::Category::DenialOfService
            }),
            "payable refund-excess tail must not fire Pattern 4: {:?}",
            fs
        );
    }

    // ------------------------------------------------------------------
    // Pattern 1c: unbounded loop over an aggregate-growable list fetched from
    // another contract (EthereumCreditGuild `ProfitManager.claimRewards`, M-25).
    // ------------------------------------------------------------------

    // POSITIVE: the M-25 shape — `gauges` is a memory array fetched from another
    // contract's getter (`GuildToken(guild).userGauges(user)`), the loop iterates
    // `gauges.length` and does per-element work via an internal call
    // (`claimGaugeRewards`, which fans out to a CREDIT transfer). The gauge list
    // grows permissionlessly. Must FIRE as UnboundedLoop.
    #[test]
    fn fires_on_external_fetched_list_loop() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            interface GuildToken { function userGauges(address u) external view returns (address[] memory); }
            interface CreditToken { function transfer(address t, uint256 a) external returns (bool); }
            contract ProfitManager {
                address public guild;
                address public credit;
                mapping(address => mapping(address => uint256)) public userGaugeProfitIndex;
                mapping(address => uint256) public gaugeProfitIndex;

                function claimGaugeRewards(address user, address gauge) public returns (uint256 earned) {
                    earned = gaugeProfitIndex[gauge] - userGaugeProfitIndex[user][gauge];
                    userGaugeProfitIndex[user][gauge] = gaugeProfitIndex[gauge];
                    if (earned != 0) {
                        CreditToken(credit).transfer(user, earned);
                    }
                }

                function claimRewards(address user) external returns (uint256 creditEarned) {
                    address[] memory gauges = GuildToken(guild).userGauges(user);
                    for (uint256 i = 0; i < gauges.length; ) {
                        creditEarned += claimGaugeRewards(user, gauges[i]);
                        unchecked { ++i; }
                    }
                }
            }
        "#);
        assert!(
            fs.iter().any(|f| {
                f.detector == "denial-of-service"
                    && f.category == sluice_findings::Category::UnboundedLoop
                    && f.function == "claimRewards"
            }),
            "loop over an externally-fetched growable list with per-element work must fire as UnboundedLoop: {:?}",
            fs
        );
    }

    // NEGATIVE: same loop shape, but `ids` is a CALLER-supplied calldata array, not
    // a list fetched from another contract. A caller's own batch size is its own
    // concern, not a protocol DoS. Must stay SILENT for Pattern 1c.
    #[test]
    fn silent_on_calldata_array_loop_with_work() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            contract Batch {
                mapping(uint256 => uint256) public seen;
                function process(uint256[] calldata ids) external {
                    for (uint256 i = 0; i < ids.length; i++) {
                        seen[ids[i]] = block.timestamp;
                    }
                }
            }
        "#);
        assert!(
            !fs.iter().any(|f| {
                f.detector == "denial-of-service"
                    && f.category == sluice_findings::Category::UnboundedLoop
            }),
            "loop over a caller-supplied calldata array must not fire Pattern 1c: {:?}",
            fs
        );
    }

    // NEGATIVE: a list fetched from another contract, but the loop body is a PURE
    // read/arithmetic accumulator (no call, no storage write) — the gas per element
    // is tiny, off-chain re-readable. Must stay SILENT (per-element WORK gates 1c).
    #[test]
    fn silent_on_external_fetched_list_pure_loop() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            interface Registry { function listOf(address u) external view returns (uint256[] memory); }
            contract Reader {
                address public registry;
                uint256 public total;
                function sum(address u) external {
                    uint256[] memory xs = Registry(registry).listOf(u);
                    uint256 t = 0;
                    for (uint256 i = 0; i < xs.length; i++) {
                        t += xs[i];
                    }
                    total = t;
                }
            }
        "#);
        assert!(
            !fs.iter().any(|f| {
                f.detector == "denial-of-service"
                    && f.category == sluice_findings::Category::UnboundedLoop
            }),
            "pure-accumulator loop over a fetched list must not fire Pattern 1c: {:?}",
            fs
        );
    }

    // NEGATIVE: a loop over a list fetched from another contract via a NO-ARG /
    // config-keyed REGISTRY getter (`getReservesList()`, `getStakingModuleIds()`,
    // `getRewardsByAsset(asset)`), with a per-element external call. These are
    // admin-curated, bounded protocol registries — not a per-account position list
    // an attacker can grow — so Pattern 1c must stay SILENT (the account-shaped
    // argument is the load-bearing discriminator). Aave `setPoolPause` /
    // `refreshRewardTokens` and Lido `_checkCLBalanceDecrease` are of this kind.
    #[test]
    fn silent_on_registry_getter_loop() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            interface IPool {
                function getReservesList() external view returns (address[] memory);
                function setReservePause(address a, bool p) external;
            }
            contract Configurator {
                address public pool;
                function setPoolPause(bool p) external {
                    address[] memory reserves = IPool(pool).getReservesList();
                    for (uint256 i = 0; i < reserves.length; i++) {
                        IPool(pool).setReservePause(reserves[i], p);
                    }
                }
            }
        "#);
        assert!(
            !fs.iter().any(|f| {
                f.detector == "denial-of-service"
                    && f.category == sluice_findings::Category::UnboundedLoop
            }),
            "loop over a no-arg admin registry getter must not fire Pattern 1c: {:?}",
            fs
        );
    }

    // NEGATIVE: a withdrawal that pushes to a TRUSTED state/immutable protocol
    // address (a treasury), not to msg.sender / a recipient param. Not caller-
    // controlled, so Pattern 4 must stay SILENT.
    #[test]
    fn silent_on_push_to_trusted_address() {
        let fs = run(r#"
            pragma solidity ^0.8.0;
            contract Fees {
                address public treasury;
                function withdrawFees(uint256 amt) external {
                    (bool ok, ) = treasury.call{value: amt}("");
                    require(ok, "send failed");
                }
            }
        "#);
        assert!(
            !fs.iter().any(|f| {
                f.detector == "denial-of-service"
                    && f.category == sluice_findings::Category::DenialOfService
            }),
            "push to trusted treasury address must not fire Pattern 4: {:?}",
            fs
        );
    }
}
