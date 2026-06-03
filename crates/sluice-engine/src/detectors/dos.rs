//! Denial-of-service via loops. Three patterns:
//!
//! 1. **Unbounded loop** — a loop whose bound references a state-array `.length`
//!    that an external function can grow (`f.effects.has_unbounded_loop`). The
//!    array keeps growing until iterating it exceeds the block gas limit, and the
//!    function (and anything that calls it) is permanently bricked. Emitted as
//!    [`Category::UnboundedLoop`].
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
use sluice_ir::{Builtin, CallKind, ExprKind, Function, Span, Stmt, StmtKind};

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
}
