//! `msg.value` consumed inside a loop.
//!
//! `msg.value` is a single, transaction-wide constant: the caller pays it exactly
//! once for the whole transaction. Reading it *inside a loop* and treating each
//! iteration as if it carried fresh ETH lets one payment be counted N times — the
//! caller credits/refunds/forwards `msg.value` per element of a batch while having
//! sent it only once. This is the payable-multicall / batch-mint class
//! (`mint(qty)` priced at `qty * price` but paid against a per-call `msg.value`,
//! looped over an array; or a refund loop that returns `msg.value` to every
//! recipient). Emitted as [`Category::MsgValueInLoop`].
//!
//! Precision over recall. The safe idiom reads `msg.value` **once before** the
//! loop into a local accumulator that is then *decremented* per iteration (so the
//! loop spends the local, never `msg.value` directly). To stay silent on that
//! pattern we flag only a *direct* `msg.value` read lexically inside the loop
//! body: a loop that touches the pre-read local — but not `msg.value` itself — is
//! never reported. The loop's own `init`/`cond`/`step` are excluded; only the body
//! subtree is scanned.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Expr, Function, Span, Stmt, StmtKind};

pub struct MsgValueInLoopDetector;

impl Detector for MsgValueInLoopDetector {
    fn id(&self) -> &'static str {
        "msg-value-in-loop"
    }
    fn category(&self) -> Category {
        Category::MsgValueInLoop
    }
    fn description(&self) -> &'static str {
        "msg.value (a per-transaction constant) read inside a loop — lets one payment be spent N times (payable multicall)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // `msg.value` is only meaningful where ETH can be received. A function
            // that cannot be paid never carries a non-zero `msg.value`, so a read
            // inside its loop is harmless (and usually dead code). Restricting to
            // payable entries also keeps this off view/pure helpers.
            if !f.is_payable() {
                continue;
            }

            for loop_stmt in loops_in(f) {
                // Scan ONLY the body subtree for a direct `msg.value` read. The
                // loop's `init`/`cond`/`step` are intentionally not scanned, and a
                // body that uses a pre-read local instead of `msg.value` yields no
                // match — which is exactly the safe accumulator idiom.
                let Some(span) = msg_value_read_in_body(loop_body(loop_stmt)) else {
                    continue;
                };

                let b = FindingBuilder::new(self.id(), Category::MsgValueInLoop)
                    .title("msg.value used inside a loop (one payment spent per iteration)")
                    .severity(Severity::High)
                    .confidence(0.6)
                    .dimension(Dimension::ValueFlow)
                    .message(format!(
                        "`{}` reads `msg.value` inside a loop. `msg.value` is fixed for the entire \
                         transaction — the caller pays it once — yet the loop treats it as if it were \
                         supplied afresh on every iteration. A caller can batch N iterations and have the \
                         same single payment credited, refunded, or forwarded N times, draining the \
                         contract. This is the payable-multicall / batch-mint class.",
                        f.name
                    ))
                    .recommendation(
                        "Read `msg.value` once before the loop into a local, then debit that local each \
                         iteration and `require` it is fully consumed (e.g. `require(spent == msg.value)`); \
                         never re-read `msg.value` per element of a batch.",
                    );
                out.push(cx.finish(b, f.id, span));
                // One finding per function is enough signal; the fix is the same
                // for every in-loop read.
                break;
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

/// Scan a loop body's statement subtree for a *direct* `msg.value` member access,
/// returning the span of the first one found. Walks all nested expressions of
/// every body statement (including nested control flow), but is rooted at the body
/// — the loop's own header (`init`/`cond`/`step`) is never inspected.
fn msg_value_read_in_body(body: &[Stmt]) -> Option<Span> {
    let mut found = None;
    for s in body {
        s.visit_exprs(&mut |e: &Expr| {
            if found.is_some() {
                return;
            }
            // `ExprKind::Member { base: Ident("msg"), member: "value" }`.
            if e.mentions_member("msg", "value") {
                found = Some(e.span);
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: payable batch-mint that forwards `msg.value` to a payee on every
    // iteration. The caller pays once but the loop spends that single payment per
    // element of `tos`, so N-1 payments are conjured from nothing.
    const VULN: &str = r#"
        pragma solidity ^0.8.0;
        contract Payable {
            function distribute(address[] calldata tos) external payable {
                for (uint256 i = 0; i < tos.length; i++) {
                    (bool ok, ) = tos[i].call{value: msg.value}("");
                    require(ok, "send failed");
                }
            }
        }
    "#;

    // Safe: `msg.value` is read ONCE before the loop into `remaining`, which is
    // then decremented each iteration. The loop body never references `msg.value`
    // directly, so the spend cannot exceed the single payment.
    const SAFE: &str = r#"
        pragma solidity ^0.8.0;
        contract SafePayable {
            function distribute(address[] calldata tos, uint256[] calldata amts) external payable {
                uint256 remaining = msg.value;
                for (uint256 i = 0; i < tos.length; i++) {
                    remaining -= amts[i];
                    (bool ok, ) = tos[i].call{value: amts[i]}("");
                    require(ok, "send failed");
                }
                require(remaining == 0, "value mismatch");
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "msg-value-in-loop"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "msg-value-in-loop"));
    }
}
