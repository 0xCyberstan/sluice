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
//! suppressed.

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

            // ---- Pattern 2 & 3: walk the body for loop statements. ----
            for loop_stmt in loops_in(f) {
                let body = loop_body(loop_stmt);

                // (2) External transfer-of-control inside the loop body. We skip
                // calls that sit inside a `try { ... }` — there the failure of one
                // recipient is caught and the batch survives.
                if let Some(call_span) = external_call_in_loop(body) {
                    let pull_payment = uses_pull_payment(cx, f);
                    // The DoS-class pattern is a PUSH PAYMENT: a value-sending call
                    // to a recipient that can revert, bricking the batch. A loop of
                    // ordinary external/token calls over a CALLER-SUPPLIED array is
                    // the caller's own concern, not a protocol DoS — flagging those
                    // produced large false-positive volume on real batch functions.
                    // Require either an ETH-sending call or iteration over a stored
                    // (shared) array.
                    let sends_value = loop_sends_value(body);
                    let over_storage = loop_iterates_storage(cx, f, loop_stmt);
                    if !pull_payment && (sends_value || over_storage) {
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
                        break;
                    }
                }
            }

            // ---- Pattern 1: unbounded loop bound (state-array length). ----
            // `has_unbounded_loop` is true precisely when a loop bound references a
            // state-array `.length` that an external function can grow, so this is a
            // structural signal (no separate "owner-set small array" to suppress —
            // those don't set the flag).
            if f.effects.has_unbounded_loop {
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
    let src = cx.scir.span_text(f.span).to_ascii_lowercase();
    let pull_name = {
        let n = f.name.to_ascii_lowercase();
        n.contains("withdraw") || n.contains("claim")
    };
    // A single-recipient pull (`withdraw()`/`claim()`) is not a batch push even if
    // it sends value, and a function that only credits a mapping (no transfer) is
    // the deposit half of pull-payment.
    pull_name || (src.contains("pending") && (src.contains("credit") || src.contains("balances[")))
}

/// True if `loop_stmt` iterates over (the length of, or by indexing) a *storage*
/// array — i.e. shared state, so one bad entry griefs everyone. This separates a
/// protocol push-loop over stored recipients from a caller-supplied calldata batch.
fn loop_iterates_storage(cx: &crate::context::AnalysisContext, f: &Function, loop_stmt: &Stmt) -> bool {
    let Some(c) = cx.contract_of(f.id) else {
        return false;
    };
    let state: std::collections::HashSet<&str> = c.state_vars.iter().map(|v| v.name.as_str()).collect();
    let mut hit = false;
    loop_stmt.visit_exprs(&mut |e| match &e.kind {
        ExprKind::Member { base, member } if member == "length" => {
            if root_in(base, &state) {
                hit = true;
            }
        }
        ExprKind::Index { base, .. } => {
            if root_in(base, &state) {
                hit = true;
            }
        }
        _ => {}
    });
    hit
}

fn root_in(e: &sluice_ir::Expr, state: &std::collections::HashSet<&str>) -> bool {
    fn root(e: &sluice_ir::Expr) -> Option<&str> {
        match &e.kind {
            ExprKind::Ident(n) => Some(n),
            ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root(base),
            _ => None,
        }
    }
    root(e).map(|r| state.contains(r)).unwrap_or(false)
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
}
