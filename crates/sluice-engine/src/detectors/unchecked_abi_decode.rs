//! `abi.decode` of attacker-controlled bytes into a fixed shape with no prior
//! length validation (CWE-20 / SWC-128).
//!
//! `abi.decode(data, (T1, T2, ...))` requires `data` to be at least the ABI head
//! size of the target tuple; the EVM ABI decoder **reverts** when `data` is
//! shorter (or otherwise malformed). When `data` is attacker-controlled and the
//! decode sits on an externally-reachable, state-mutating path, an attacker can
//! supply a too-short / malformed blob and force the revert. On a *relayer*,
//! *bridge*, or *batch* path — where one entry's revert bricks the whole call, or
//! where the message is delivered by a trusted relayer that has already paid gas —
//! that revert is a denial-of-service / griefing vector rather than a harmless
//! "your own call reverted". A related, subtler failure mode: bytes built with
//! `abi.encodePacked` (which drops length/offset framing) and then `abi.decode`-d
//! can *mis-decode* rather than revert, silently yielding attacker-chosen values.
//!
//! This is a niche, low-to-medium-confidence class, so precision is prioritized
//! over recall. We flag a `Builtin(AbiDecode)` whose first argument is
//! attacker-controlled (`cx.is_attacker_controlled`) in an externally-reachable
//! function, and suppress aggressively:
//!
//!   * **Length validated** — the function source checks the bytes' `.length`
//!     against a bound (`data.length == / >= / > / <= / <`) before decoding, which
//!     is exactly the mitigation (the decode can no longer be made to revert on a
//!     short blob).
//!   * **Not attacker-controlled** — value-flow says the bytes are not attacker
//!     input (e.g. they are the return of a trusted internal/external call, which
//!     carries `ExternalReturn`/`Unknown`, not `AttackerInput`), so there is no
//!     adversary to supply a malformed blob.
//!   * **Wrapped in try/catch** — a decode inside a `try { ... } catch { ... }`
//!     cannot DoS the caller: the revert is caught and handled.
//!
//! Dimensions: ValueFlow (attacker-controlled bytes reach the decode sink) +
//! Frontier (the decode is the trust frontier where an externally-supplied,
//! unvalidated blob is interpreted as a typed structure).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Builtin, CallKind, ExprKind, Function, Span, Stmt, StmtKind};

pub struct UncheckedAbiDecodeDetector;

impl Detector for UncheckedAbiDecodeDetector {
    fn id(&self) -> &'static str {
        "unchecked-abi-decode"
    }
    fn category(&self) -> Category {
        Category::UncheckedAbiDecode
    }
    fn description(&self) -> &'static str {
        "abi.decode of attacker-controlled bytes with no length validation (malformed input reverts → relayer/bridge DoS, or encodePacked mis-decode)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // The bytes must be reachable by an adversary, and the decode must be
            // able to abort a state-changing transaction to be a griefing/DoS
            // vector — a view/pure helper can be re-tried for free off-chain.
            if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
                continue;
            }

            // (1) Length already validated in this function → the decode can no
            //     longer be forced to revert on a short blob. Suppress wholesale.
            if validates_bytes_length(cx, f) {
                continue;
            }

            // Spans of decode calls that sit lexically inside a try/catch — a
            // caught revert cannot DoS the caller, so those are not findings.
            let decodes_in_try = abi_decode_spans_in_try(f);

            // Walk the body for the first qualifying `abi.decode(...)` call,
            // capturing only its span inside the closure (mirrors the seed
            // detectors). Reporting at most one per function is enough signal for
            // this low-confidence class and avoids spamming a router that decodes
            // the same blob repeatedly.
            let mut hit: Option<Span> = None;
            for s in &f.body {
                s.visit_exprs(&mut |e| {
                    if hit.is_some() {
                        return;
                    }
                    let ExprKind::Call(c) = &e.kind else { return };
                    if c.kind != CallKind::Builtin(Builtin::AbiDecode) {
                        return;
                    }
                    // First argument is the bytes blob being decoded.
                    let Some(bytes) = c.args.first() else { return };

                    // (2) Bytes must be attacker-controlled. The return of a
                    //     trusted call carries `ExternalReturn`/`Unknown` (not
                    //     `AttackerInput`), so trusted-source decodes don't fire.
                    if !cx.is_attacker_controlled(f.id, bytes) {
                        return;
                    }

                    // (3) Decode wrapped in try/catch → revert is handled.
                    if decodes_in_try.contains(&e.span) {
                        return;
                    }

                    hit = Some(e.span);
                });
                if hit.is_some() {
                    break;
                }
            }

            let Some(span) = hit else { continue };
            let (cname, fname) = cx.names(f.id);
            let b = FindingBuilder::new(self.id(), Category::UncheckedAbiDecode)
                .title("abi.decode of attacker-controlled bytes without length validation")
                .severity(Severity::Low)
                .confidence(0.4)
                .dimension(Dimension::ValueFlow)
                .dimension(Dimension::Frontier)
                .message(format!(
                    "`{cname}.{fname}` calls `abi.decode` on externally-controlled `bytes` \
                     without first validating their length. A too-short or malformed blob makes \
                     the ABI decoder revert; on a relayer/bridge/batch path this lets an attacker \
                     grief the trusted relayer (which has already paid gas) or brick an entire \
                     batch via one entry. If the bytes were produced with `abi.encodePacked` \
                     (which drops length/offset framing) the decode can instead silently \
                     mis-decode into attacker-chosen values.",
                ))
                .recommendation(
                    "Validate the blob before decoding (`require(data.length >= EXPECTED)`), \
                     decode inside a `try/catch` so a malformed message cannot abort the path, \
                     and never `abi.decode` data that was `abi.encodePacked` (use `abi.encode`, \
                     whose framing round-trips losslessly).",
                );
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

// ----------------------------------------------------------------- helpers

/// True if the function source validates a `bytes` value's `.length` against a
/// bound. The ABI decoder reverts on a too-short blob, so a prior length check is
/// exactly the mitigation — once present, an attacker can no longer force the
/// revert by truncating the input. Conservative substring scan over the function
/// source (mirrors the signature detector's `span_text` approach): we look for
/// `.length` adjacent to a comparison operator anywhere in the body.
fn validates_bytes_length(cx: &AnalysisContext, f: &Function) -> bool {
    let src = cx.source_text(f.span);
    // Find every occurrence of ".length" and check whether a comparison operator
    // sits nearby (either side), i.e. the length participates in a bound check.
    let bytes = src.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(".length") {
        let idx = from + rel;
        // Window around the match: a few chars before the `.length` token (to
        // catch `len <= data.length`) and after it (to catch `data.length >= n`).
        let lo = idx.saturating_sub(8);
        let hi = (idx + ".length".len() + 8).min(bytes.len());
        let window = &src[lo..hi];
        if window.contains("==")
            || window.contains(">=")
            || window.contains("<=")
            || window.contains('>')
            || window.contains('<')
        {
            return true;
        }
        from = idx + ".length".len();
    }
    false
}

/// Spans of every `abi.decode(...)` call expression that lies lexically inside a
/// `try { ... } catch { ... }` (either the try body or a catch body). A revert
/// from a decode there is caught, so it cannot DoS the caller.
fn abi_decode_spans_in_try(f: &Function) -> std::collections::HashSet<Span> {
    let mut set = std::collections::HashSet::new();
    for s in &f.body {
        s.visit(&mut |st| {
            let StmtKind::Try { body, catches, .. } = &st.kind else { return };
            collect_abi_decode_spans(body, &mut set);
            for cat in catches {
                collect_abi_decode_spans(&cat.body, &mut set);
            }
        });
    }
    set
}

/// Insert into `set` the span of every `abi.decode(...)` call expression found
/// (transitively) in the given statements.
fn collect_abi_decode_spans(stmts: &[Stmt], set: &mut std::collections::HashSet<Span>) {
    for inner in stmts {
        inner.visit_exprs(&mut |e| {
            if let ExprKind::Call(c) = &e.kind {
                if c.kind == CallKind::Builtin(Builtin::AbiDecode) {
                    set.insert(e.span);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Relayer/bridge entry point that `abi.decode`s an attacker-supplied `bytes`
    // payload into a typed tuple with no prior length validation. A malformed /
    // too-short blob reverts the decode, griefing the relayed path.
    const VULN: &str = r#"
        pragma solidity ^0.8.0;
        contract Bridge {
            mapping(address => uint256) public credited;
            function receiveMessage(bytes calldata message) external {
                (address to, uint256 amount) = abi.decode(message, (address, uint256));
                credited[to] += amount;
            }
        }
    "#;

    // Safe: the same path validates the payload length before decoding, so an
    // attacker cannot force the decoder to revert by truncating the input.
    const SAFE: &str = r#"
        pragma solidity ^0.8.0;
        contract Bridge {
            mapping(address => uint256) public credited;
            function receiveMessage(bytes calldata message) external {
                require(message.length >= 64, "short");
                (address to, uint256 amount) = abi.decode(message, (address, uint256));
                credited[to] += amount;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "unchecked-abi-decode"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "unchecked-abi-decode"));
    }
}
