//! Signature verification flaws: ecrecover→address(0), replay (missing nonce /
//! chainId), missing deadline, malleability.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};

pub struct SignatureDetector;

impl Detector for SignatureDetector {
    fn id(&self) -> &'static str {
        "signature"
    }
    fn category(&self) -> Category {
        Category::SignatureReplay
    }
    fn description(&self) -> &'static str {
        "ecrecover zero-address, signature replay (nonce/chainId), missing deadline, malleability"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Replay protection (nonce/deadline/chainId) is the responsibility of
            // the verification *entry point*, not of a pure recovery primitive.
            // Skip library helpers and non-entry functions (e.g. an `ECDSA.recover`
            // implementation legitimately has no nonce).
            if !f.is_externally_reachable() || !f.is_state_mutating() {
                continue;
            }
            if cx.contract_of(f.id).map(|c| c.is_library()).unwrap_or(false) {
                continue;
            }
            let src = cx.source_text(f.span);
            if !src.contains("ecrecover") {
                continue;
            }
            // OpenZeppelin ECDSA handles zero-address + malleability.
            let uses_ecdsa = src.contains(".recover(")
                || cx.scir.contract(f.contract).map(|c| c.uses_library_like("ecdsa")).unwrap_or(false);

            let mk = |cat: Category, title: &str, sev: Severity, conf: f32, msg: String, rec: &str| {
                FindingBuilder::new("signature", cat)
                    .title(title)
                    .severity(sev)
                    .confidence(conf)
                    .dimension(Dimension::ValueFlow)
                    .message(msg)
                    .recommendation(rec)
            };

            if !uses_ecdsa && !src.contains("address(0)") {
                out.push(cx.finish(
                    mk(
                        Category::EcrecoverZeroAddress,
                        "ecrecover result not checked against address(0)",
                        Severity::High,
                        0.7,
                        format!(
                            "`{}` calls `ecrecover` but never rejects `address(0)`. A malformed signature \
                             makes `ecrecover` return `address(0)`; if that can equal an expected signer, \
                             forgery passes.",
                            f.name
                        ),
                        "Use OpenZeppelin `ECDSA.recover` (reverts on bad sigs) or `require(signer != address(0))`.",
                    ),
                    f.id,
                    f.span,
                ));
            }
            if !src.contains("nonce") {
                out.push(cx.finish(
                    mk(
                        Category::SignatureReplay,
                        "Signed message lacks a nonce (replayable)",
                        Severity::High,
                        0.6,
                        format!(
                            "`{}` verifies a signature without a per-signer nonce, so a captured signature \
                             can be replayed.",
                            f.name
                        ),
                        "Include and consume a per-signer `nonce` in the signed digest.",
                    ),
                    f.id,
                    f.span,
                ));
            }
            if !src.contains("chainid") && !src.contains("domain_separator") {
                out.push(cx.finish(
                    mk(
                        Category::SignatureReplay,
                        "Signed digest omits chainId / EIP-712 domain separator",
                        Severity::Medium,
                        0.5,
                        format!(
                            "`{}` does not bind the signature to a chainId / domain separator, enabling \
                             cross-chain or cross-contract replay.",
                            f.name
                        ),
                        "Bind the digest to an EIP-712 domain separator that includes `block.chainid`.",
                    ),
                    f.id,
                    f.span,
                ));
            }
            if !src.contains("deadline") && !src.contains("expiry") && !src.contains("validuntil") {
                out.push(cx.finish(
                    mk(
                        Category::MissingDeadline,
                        "Signature has no deadline (valid forever)",
                        Severity::Low,
                        0.45,
                        format!("`{}` accepts a signature with no expiry, so stale signatures remain usable.", f.name),
                        "Include a `deadline` in the signed payload and `require(block.timestamp <= deadline)`.",
                    ),
                    f.id,
                    f.span,
                ));
            }
        }
        out
    }
}
