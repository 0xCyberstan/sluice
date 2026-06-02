//! Gas griefing via an uncapped low-level call in a relayer / keeper / batch
//! context (SWC-126).
//!
//! A `addr.call(...)` that forwards **all** remaining gas (no `{gas:}` stipend)
//! to an untrusted callee lets that callee grief the caller in two ways:
//!
//!   1. **Gas burn** — the callee consumes (almost) all forwarded gas, so even if
//!      its own work reverts, the relayer/keeper has already paid for it. In a
//!      meta-transaction relayer this lets a target burn the relayer's gas; in a
//!      `for`/`while` batch a single uncapped entry can drain the gas budget meant
//!      for the rest of the batch.
//!   2. **Return-bombing** — the callee returns enormous `returndata`; copying it
//!      back into the caller's memory costs the *caller* quadratic memory-expansion
//!      gas, again on the caller's dime.
//!
//! Either way the *caller* pays for the callee's behaviour. The danger is only
//! real when the gas the call burns is not the caller's own concern — i.e. the
//! caller is relaying/keeping on behalf of others (a relayer/keeper/multicall/
//! batch/process entry) or is iterating over many callees in a loop, where one
//! greedy callee harms the others.
//!
//! Precision over recall (this is a niche, low-confidence class):
//!   * A call that sets a `{gas:}` cap is **not** a finding — the cap is exactly
//!     the mitigation, so any capped call suppresses.
//!   * A call that explicitly bounds / ignores the returndata (an assembly block
//!     that uses `returndatasize`/`returndatacopy`, i.e. handles the return-bomb
//!     by hand) suppresses.
//!   * A plain single low-level call in a non-relayer function is *not* flagged:
//!     forwarding all gas to one trusted callee whose gas you are already paying
//!     for is normal and expected. The relayer/keeper/loop gate is what keeps this
//!     quiet on ordinary code.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{CallKind, ExprKind, Function, Span, Stmt, StmtKind};

pub struct GasGriefingDetector;

impl Detector for GasGriefingDetector {
    fn id(&self) -> &'static str {
        "gas-griefing"
    }
    fn category(&self) -> Category {
        Category::GasGriefing
    }
    fn description(&self) -> &'static str {
        "Uncapped low-level call (forwards all gas) to an untrusted callee in a relayer/keeper/batch context (gas burn / return-bomb)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // The grief costs the *caller* gas on a state-changing path; a
            // view/pure helper can be re-tried for free off-chain, and a body-less
            // declaration has nothing to analyse.
            if !f.has_body || f.is_view_or_pure() {
                continue;
            }

            // Does this function look like it relays/keeps/batches on behalf of
            // others? (relay / execute / forward / multicall / batch / process)
            let relayer_name = is_relayer_name(&f.name);
            // Spans of all low-level calls that sit lexically inside a loop body —
            // there one greedy callee can starve the rest of the batch.
            let in_loop = uncapped_calls_in_loops(f);

            // Only an uncapped low-level call in one of those two contexts is a
            // finding. A single uncapped call in an ordinary function is normal.
            if !relayer_name && in_loop.is_empty() {
                continue;
            }

            // Find every uncapped low-level call in the body (with its span), then
            // suppress capped / return-bounded ones.
            for (span, sends_value) in uncapped_low_level_calls(f) {
                // Suppress when the surrounding call expression already bounds the
                // return data by hand (assembly returndatasize/returndatacopy).
                if call_handles_returndata(cx, span) {
                    continue;
                }

                let looped = in_loop.contains(&span);
                // A call must be in *some* griefable context to count: either the
                // enclosing function is a relayer/keeper/batch entry, or this very
                // call is inside a loop.
                if !relayer_name && !looped {
                    continue;
                }

                // In a loop the impact is amplified (a single greedy callee bricks
                // the remaining iterations / the whole batch) → Medium; a single
                // relayer call is Low.
                let severity = if looped { Severity::Medium } else { Severity::Low };

                let mut b = FindingBuilder::new(self.id(), Category::GasGriefing)
                    .title("Uncapped low-level call forwards all gas to an untrusted callee")
                    .severity(severity)
                    .confidence(0.45)
                    .dimension(Dimension::Frontier)
                    .message(format!(
                        "`{}` makes a low-level `call` that forwards all remaining gas (no `{{gas:}}` cap) \
                         to an externally-controlled address {context}. A malicious callee can burn the \
                         forwarded gas or return an enormous `returndata` blob (a \"return bomb\"), and the \
                         {victim} pays for it — the gas-griefing class (SWC-126).",
                        f.name,
                        context = if looped {
                            "inside a loop, once per iteration"
                        } else {
                            "while relaying/executing on behalf of others"
                        },
                        victim = if looped { "rest of the batch" } else { "relayer/keeper" },
                    ))
                    .recommendation(
                        "Cap the gas forwarded to the callee with `addr.call{gas: STIPEND}(...)`, and avoid \
                         copying unbounded returndata back into memory (use assembly to read only the bytes \
                         you need, or ignore the return). In a batch, budget gas per entry so one greedy \
                         callee cannot starve the others.",
                    );
                if sends_value {
                    b = b.dimension(Dimension::ValueFlow);
                }
                out.push(cx.finish(b, f.id, span));
                // One finding per function is enough signal for this low-confidence
                // class; avoid spamming a multicall with N near-identical hits.
                break;
            }
        }
        out
    }
}

// ----------------------------------------------------------------- helpers

/// The function name suggests it relays / keeps / batches on behalf of others.
fn is_relayer_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    ["relay", "execute", "forward", "multicall", "batch", "process"]
        .iter()
        .any(|k| l.contains(k))
}

/// Every low-level call in the body that forwards all gas (no `{gas:}` cap),
/// paired with whether it also sends native value. Deduplicated by span.
fn uncapped_low_level_calls(f: &Function) -> Vec<(Span, bool)> {
    let mut out: Vec<(Span, bool)> = Vec::new();
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if let ExprKind::Call(c) = &e.kind {
                // `addr.call{...}(...)` with NO `{gas:}` clause forwards all gas.
                if c.kind == CallKind::LowLevelCall && c.gas.is_none() {
                    if !out.iter().any(|(sp, _)| *sp == e.span) {
                        out.push((e.span, c.value.is_some()));
                    }
                }
            }
        });
    }
    out
}

/// Spans of uncapped low-level calls that lie lexically inside a loop body.
fn uncapped_calls_in_loops(f: &Function) -> std::collections::HashSet<Span> {
    let mut set = std::collections::HashSet::new();
    for s in &f.body {
        s.visit(&mut |st| {
            let body: &[Stmt] = match &st.kind {
                StmtKind::While { body, .. }
                | StmtKind::For { body, .. }
                | StmtKind::DoWhile { body, .. } => body,
                _ => return,
            };
            for inner in body {
                inner.visit_exprs(&mut |e| {
                    if let ExprKind::Call(c) = &e.kind {
                        if c.kind == CallKind::LowLevelCall && c.gas.is_none() {
                            set.insert(e.span);
                        }
                    }
                });
            }
        });
    }
    set
}

/// True if the source text of the call site shows the returndata is bounded /
/// handled by hand (an assembly block reading `returndatasize` /
/// `returndatacopy`), which neutralizes the return-bomb vector. Conservative
/// substring check on the call's own span.
fn call_handles_returndata(cx: &AnalysisContext, span: Span) -> bool {
    let src = cx.scir.span_text(span).to_ascii_lowercase();
    src.contains("returndatasize") || src.contains("returndatacopy")
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Relayer that forwards ALL gas to a caller-supplied target inside a loop. A
    // malicious target can burn the forwarded gas or return-bomb the relayer,
    // griefing the rest of the batch (SWC-126).
    const VULN: &str = r#"
        pragma solidity ^0.8.0;
        contract Relayer {
            struct Call { address to; bytes data; }
            function relayBatch(Call[] calldata calls) external {
                for (uint256 i = 0; i < calls.length; i++) {
                    (bool ok, bytes memory ret) = calls[i].to.call(calls[i].data);
                    require(ok, "call failed");
                }
            }
        }
    "#;

    // Safe: the same relayer caps the gas it forwards with `{gas:}`, so a greedy
    // callee cannot burn the relayer's whole budget.
    const SAFE: &str = r#"
        pragma solidity ^0.8.0;
        contract CappedRelayer {
            struct Call { address to; bytes data; uint256 gasLimit; }
            function relayBatch(Call[] calldata calls) external {
                for (uint256 i = 0; i < calls.length; i++) {
                    (bool ok, ) = calls[i].to.call{gas: calls[i].gasLimit}(calls[i].data);
                    require(ok, "call failed");
                }
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "gas-griefing"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "gas-griefing"));
    }
}
