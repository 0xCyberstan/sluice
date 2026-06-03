//! Delegatecall inside a loop: each iteration runs *foreign* code against THIS
//! contract's storage. A multicall-style loop of `delegatecall`s is a known
//! footgun — the body can clobber storage from one iteration into the next, and
//! `msg.value` is constant across the whole transaction, so a loop that forwards
//! `msg.value` (or lets the delegated code read it) lets a single payment be
//! "spent" by every iteration (the 2023 multicall + `delegatecall` /
//! `msg.value`-reuse class).
//!
//! This is the loop-specific sibling of `upgradeable.rs`. That detector flags a
//! *controlled* (non-constant) delegatecall target anywhere. Here the hazard is
//! structural: the delegatecall sits in a `for`/`while`/`do-while` body, so it is
//! executed an attacker-influenced number of times against shared storage.
//!
//! ## Precision
//! `delegatecall` to a hardcoded/`immutable`/`constant` library address is the
//! normal, safe diamond/library pattern (the same code, same storage layout,
//! deterministic). We suppress those: a finding only fires when the loop body
//! delegatecalls into a target whose receiver root is *not* a constant/immutable
//! state variable (e.g. a per-iteration array element, a calldata-supplied
//! address, or mutable storage). `staticcall` (read-only, cannot write storage)
//! is never flagged.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{CallKind, ExprKind, Span, Stmt, StmtKind};
use std::collections::HashSet;

pub struct DelegatecallLoopDetector;

impl Detector for DelegatecallLoopDetector {
    fn id(&self) -> &'static str {
        "delegatecall-loop"
    }
    fn category(&self) -> Category {
        Category::DelegatecallStorage
    }
    fn description(&self) -> &'static str {
        "delegatecall executed inside a loop (multicall + delegatecall / msg.value-reuse footgun)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Cheap pre-filter: no loop and no delegatecall anywhere → nothing to do.
            if !f.effects.has_loop {
                continue;
            }
            if !f
                .effects
                .call_sites
                .iter()
                .any(|c| c.kind == CallKind::DelegateCall)
            {
                continue;
            }

            // Targets that are safe to delegatecall to repeatedly: a constant or
            // immutable state variable (a fixed, audited library / facet). Same
            // suppression the controlled-delegatecall detector uses.
            let trusted: HashSet<String> = cx
                .scir
                .contract(f.contract)
                .map(|c| {
                    c.state_vars
                        .iter()
                        .filter(|v| v.constant || v.immutable)
                        .map(|v| v.name.clone())
                        .collect()
                })
                .unwrap_or_default();

            // Walk top-level statements; for each loop, scan its (transitive) body
            // for a delegatecall to a non-trusted target. Report at most once per
            // function, at the offending delegatecall.
            // Report at the LOOP's span (not the delegatecall's): semantically the
            // finding is "this loop contains a delegatecall", and using a distinct
            // line keeps it from being de-duplicated against the controlled-
            // delegatecall finding the `upgradeable` detector raises on the call line.
            let mut hit: Option<Span> = None;
            for s in &f.body {
                s.visit(&mut |st| {
                    if hit.is_some() {
                        return;
                    }
                    if is_loop(st) && has_untrusted_delegatecall_in(st, &trusted) {
                        hit = Some(st.span);
                    }
                });
                if hit.is_some() {
                    break;
                }
            }

            let Some(span) = hit else { continue };

            let forwards_value = f.effects.reads_msg_value;
            let mut b = FindingBuilder::new(self.id(), Category::DelegatecallStorage)
                .title("delegatecall inside a loop")
                .severity(Severity::High)
                .confidence(0.55)
                .dimension(Dimension::Frontier)
                .message(format!(
                    "`{}` performs a `delegatecall` inside a loop, so foreign code runs against \
                     THIS contract's storage once per iteration. A multicall-style loop of \
                     delegatecalls is a known footgun: each iteration can clobber storage set by \
                     the previous one, and because `msg.value` is fixed for the whole transaction, \
                     a loop that delegatecalls payable logic lets a single payment be re-counted by \
                     every iteration (the 2023 multicall + `delegatecall` / `msg.value`-reuse class).",
                    f.name
                ))
                .recommendation(
                    "Avoid delegatecalling in a loop. If a batch/multicall is required, delegatecall \
                     only to a fixed, audited `immutable`/`constant` library, never to a \
                     per-iteration or caller-supplied target, and never combine it with payable \
                     (`msg.value`) entry points — settle ETH explicitly per call rather than \
                     reusing `msg.value`.",
                );
            if forwards_value {
                // msg.value reuse is the value-flow leg of this bug.
                b = b.dimension(Dimension::ValueFlow);
            }
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

/// Is this statement a loop construct?
fn is_loop(s: &Stmt) -> bool {
    matches!(
        s.kind,
        StmtKind::For { .. } | StmtKind::While { .. } | StmtKind::DoWhile { .. }
    )
}

/// Within a loop statement (its transitive body, condition and step), is there a
/// `delegatecall` whose target root is *not* a trusted (constant/immutable) state
/// variable or a literal address?
fn has_untrusted_delegatecall_in(loop_stmt: &Stmt, trusted: &HashSet<String>) -> bool {
    let mut found = false;
    loop_stmt.visit_exprs(&mut |e| {
        if found {
            return;
        }
        if let ExprKind::Call(c) = &e.kind {
            if c.kind != CallKind::DelegateCall {
                return;
            }
            // Suppress a delegatecall to a hardcoded/immutable/constant library:
            // that is the normal, safe diamond/library pattern.
            let target_root = c
                .receiver
                .as_ref()
                .and_then(|r| r.simple_name())
                .unwrap_or("");
            let is_literal_target = c
                .receiver
                .as_ref()
                .map(|r| matches!(r.kind, ExprKind::Lit(_)))
                .unwrap_or(false);
            if is_literal_target || trusted.contains(target_root) {
                return;
            }
            found = true;
        }
    });
    found
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: a payable multicall that loops over caller-supplied targets and
    // `delegatecall`s each one. Foreign code runs per iteration against this
    // contract's storage, and `msg.value` is reused across every call.
    const VULN: &str = r#"
        contract Multicall {
            mapping(address => uint256) public credit;
            function multicall(address[] calldata impls, bytes[] calldata data) external payable {
                for (uint256 i = 0; i < impls.length; i++) {
                    (bool ok, ) = impls[i].delegatecall(data[i]);
                    require(ok, "call failed");
                }
            }
        }
    "#;

    // Safe: a single delegatecall to a fixed `immutable` library (no loop, the
    // normal proxy/library pattern). The detector must stay silent.
    const SAFE: &str = r#"
        contract Proxy {
            address public immutable logic;
            constructor(address _logic) { logic = _logic; }
            function exec(bytes calldata data) external returns (bool) {
                (bool ok, ) = logic.delegatecall(data);
                require(ok, "call failed");
                return ok;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "delegatecall-loop"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "delegatecall-loop"));
    }
}
