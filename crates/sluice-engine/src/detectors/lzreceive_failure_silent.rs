//! Silent cross-chain message loss on a reverting / under-gassed receive callback.
//!
//! ## The class
//!
//! A cross-chain message-receive entry point on a messaging endpoint (LayerZero's
//! `EndpointV2.lzReceive`, a generic `receiveMessage` / `onRecvPacket` / `execute`)
//! has to do two things: (1) **consume** the stored, verified message — delete the
//! stored `payloadHash`, mark the inbound nonce delivered, `clear()` the slot — so
//! the same message can never be executed twice, and (2) hand control to the
//! application by **calling the receiver's callback**. The ordering of those two
//! steps is a correctness invariant.
//!
//! The dangerous ordering is *consume-then-call*: the slot is cleared (or the
//! nonce advanced) **before** the external application callback runs, and the
//! callback is invoked **bare** — no `try/catch`, no "store-for-retry" fallback. A
//! reverting callback (a buggy receiver, a paused token, an out-of-gas inner call,
//! a malicious `revert`) then leaves the message *consumed but never delivered*:
//! the stored payload is gone, so the message can never be replayed, and the
//! cross-chain transfer / instruction is **permanently lost**. This is exactly the
//! ordering LayerZero `EndpointV2.lzReceive` uses (`_clearPayload(...)` then
//! `ILayerZeroReceiver(_receiver).lzReceive{value: msg.value}(...)`), justified by
//! a re-entrancy comment — but the comment addresses double-execution, not the
//! loss of a message whose callback reverts.
//!
//! The well-known mitigation (LayerZero V1's `NonblockingLzApp`) is to wrap the
//! callback in `try/catch` and, on failure, **store the payload in a
//! `failedMessages` / `storedPayload` mapping** so the recipient can call
//! `retryMessage` later. A receive path that does that is safe and is suppressed.
//!
//! ## What we flag
//!
//! On an externally-reachable, state-mutating receive handler we require, in
//! document order:
//!   1. a **consume** of the stored message — a `delete payloadHash[...]` /
//!      `delete inboundPayloadHash[...]`, an `inboundNonce++` / lazy-nonce
//!      assignment, or a call to a clear/consume helper (`_clearPayload`,
//!      `clearPayload`, `clearMessage`); ordered strictly **before**
//!   2. an **external transfer-of-control** call (the app callback / low-level /
//!      delegate call) that can revert.
//!
//! ## Suppression (≈0 FP)
//!
//!   * The callback is wrapped in `try/catch` (a `try` statement is present) — the
//!     failure can be handled, so the message is not silently lost.
//!   * A failure-retry store is present (`failedMessages` / `storedPayload` /
//!     `storeFailedMessage` / `retryMessage`) — the documented mitigation.
//!   * No consume happens before any external call (pull-mode `clear()` that only
//!     emits, verification paths that *store* a hash, admin skip/burn with no
//!     callback) — those never reach the consume-then-bare-call shape.

use super::prelude::*;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{AssignOp, Expr, ExprKind, Function, Span, StmtKind, UnOp};

pub struct LzReceiveFailureSilentDetector;

impl Detector for LzReceiveFailureSilentDetector {
    fn id(&self) -> &'static str {
        "lzreceive-failure-silent"
    }
    fn category(&self) -> Category {
        Category::LzReceiveFailureSilent
    }
    fn description(&self) -> &'static str {
        "Receive handler consumes/clears the stored message before a bare app callback — a reverting callback permanently loses the message (no replay)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.entry_points() {
            // Restrict to inbound cross-chain message handlers — by function name
            // or by the surrounding contract being a messaging endpoint. This keeps
            // the consume-then-call ordering check from firing on unrelated effect
            // orderings elsewhere in the codebase.
            if !is_receive_handler(f) && !contract_is_endpoint_like(cx, f) {
                continue;
            }

            // (1) First consume of the stored message (document order).
            let Some(consume) = first_consume(f) else { continue };

            // (2) First external transfer-of-control call (the app callback).
            let Some(call) = first_external_control_call(f) else { continue };

            // The dangerous ordering is consume strictly *before* the callback.
            if consume.start >= call.start {
                continue;
            }

            let src = cx.source_text(f.span);

            // Suppression: try/catch around the callback, or a failure-retry store.
            if has_try_catch(f) || has_failure_retry_store(&src) {
                continue;
            }

            let b = report!(self, Category::LzReceiveFailureSilent,
                title = "Receive handler clears the stored message before a bare callback — a reverting callback loses it permanently",
                severity = Severity::Medium,
                confidence = 0.62,
                dimensions = [Dimension::Invariant],
                message = format!(
                    "`{}` consumes the stored cross-chain message — it deletes the stored payload hash / \
                     advances the inbound nonce / clears the slot — and only then makes the external \
                     application callback, with no `try/catch` and no store-for-retry fallback. Because the \
                     payload is already gone, a callback that reverts (a buggy or paused receiver, an \
                     out-of-gas inner call, an attacker-supplied `revert`) leaves the message marked \
                     delivered but never executed: it can never be replayed and the cross-chain \
                     transfer/instruction is permanently lost. This is the LayerZero `EndpointV2.lzReceive` \
                     `_clearPayload`-then-callback ordering; the re-entrancy comment guards double-execution, \
                     not silent message loss.",
                    f.name
                ),
                recommendation =
                    "Make a failed delivery recoverable rather than silently lost. Wrap the application \
                     callback in `try { ... } catch { ... }` and, on failure, persist the payload to a \
                     `failedMessages` / `storedPayload` mapping keyed by (srcEid, sender, nonce) and emit a \
                     failure event, exposing a `retryMessage` / `lzReceiveRetry` path (the LayerZero \
                     `NonblockingLzApp` pattern). Only clear/consume the stored payload once the callback \
                     has succeeded (or after the retry slot is written).",
            );
            out.push(finish_at(cx, b, f.id, consume));
        }
        out
    }
}

// --------------------------------------------------------------------------
// Gating
// --------------------------------------------------------------------------

/// Function name denotes an inbound cross-chain message-receive entry point.
fn is_receive_handler(f: &Function) -> bool {
    let l = f.name.to_ascii_lowercase();
    const NAMES: &[&str] = &[
        "lzreceive",
        "receivemessage",
        "receivepayload",
        "onrecvpacket",
        "executemessage",
        "execute",
        "processmessage",
        "process",
        "deliver",
        "_credit",
        "handlemessage",
        "receive", // receiveFrom-style; bounded by entry_points() + consume shape
    ];
    NAMES.iter().any(|n| l.contains(n))
}

/// The surrounding contract looks like a LayerZero / messaging endpoint, by
/// contract name or by sibling functions that reveal the messaging role. This lets
/// the ordering check run on a `lzReceive` whose name we might otherwise miss while
/// still excluding ordinary application contracts.
fn contract_is_endpoint_like(cx: &AnalysisContext, f: &Function) -> bool {
    const ENDPOINTY: &[&str] = &[
        "endpoint",
        "messaging",
        "messagechannel",
        "messagingchannel",
        "layerzero",
        "lzendpoint",
        "mailbox",
        "relayer",
        "inbox",
        "channel",
    ];
    let Some(c) = cx.contract_of(f.id) else { return false };
    let cl = c.name.to_ascii_lowercase();
    if ENDPOINTY.iter().any(|k| cl.contains(k)) {
        return true;
    }
    // A sibling function name that screams "receive endpoint".
    cx.scir.functions_of(c.id).any(|g| {
        let gl = g.name.to_ascii_lowercase();
        gl.contains("lzreceive") || gl.contains("clearpayload") || gl.contains("_inbound")
    })
}

// --------------------------------------------------------------------------
// (1) Consume of the stored message
// --------------------------------------------------------------------------

/// Span of the first expression (document order, by `span.start`) that *consumes*
/// the stored inbound message: a `delete <payload/nonce slot>`, an
/// `inboundNonce++` / lazy-nonce assignment, or a call to a clear/consume helper.
fn first_consume(f: &Function) -> Option<Span> {
    let mut best: Option<Span> = None;
    let mut consider = |span: Span| {
        if best.map(|b| span.start < b.start).unwrap_or(true) {
            best = Some(span);
        }
    };
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            if is_consume_expr(e) {
                consider(e.span);
            }
        });
    }
    best
}

/// Is `e` a single consume operation on the stored-message channel?
fn is_consume_expr(e: &Expr) -> bool {
    match &e.kind {
        // `delete inboundPayloadHash[...][...]` / `delete payloadHash[...]`.
        ExprKind::Unary { op: UnOp::Delete, operand } => mentions_message_slot(operand),
        // A call to a clear/consume helper: `_clearPayload(...)`, `clearPayload(...)`.
        ExprKind::Call(c) => c
            .func_name
            .as_deref()
            .map(name_is_clear_consume)
            .unwrap_or(false),
        // `inboundNonce[...]++` / `--` (marking a nonce delivered).
        ExprKind::Unary { op: UnOp::PostInc | UnOp::PreInc | UnOp::PostDec | UnOp::PreDec, operand } => {
            mentions_nonce_slot(operand)
        }
        // `lazyInboundNonce[...] = nonce;` / `inboundNonce[...] += 1;` etc.
        ExprKind::Assign { op, target, .. } => {
            // A plain hash *store* (`inboundPayloadHash[...] = hash`) is verification,
            // not a consume; only nonce advancement counts here.
            mentions_nonce_slot(target)
                && matches!(op, AssignOp::Assign | AssignOp::Add | AssignOp::Sub)
        }
        _ => false,
    }
}

/// Does the lvalue root/path name the stored-payload slot of a message channel?
fn mentions_message_slot(e: &Expr) -> bool {
    path_name_matches(e, &["payloadhash", "inboundpayloadhash", "payload", "storedmessage", "messages"])
}

/// Does the lvalue root/path name an inbound-nonce slot?
fn mentions_nonce_slot(e: &Expr) -> bool {
    path_name_matches(e, &["inboundnonce", "lazyinboundnonce", "nonce"])
}

/// True if the root identifier of an lvalue chain (`a[b][c]` -> `a`) contains any
/// of `needles` (case-insensitive). Falls back to scanning every identifier in the
/// expression so a member-rooted slot (`channel.payloadHash[...]`) still matches.
fn path_name_matches(e: &Expr, needles: &[&str]) -> bool {
    if let Some(root) = root_ident_str(e) {
        let rl = root.to_ascii_lowercase();
        if needles.iter().any(|n| rl.contains(n)) {
            return true;
        }
    }
    let mut hit = false;
    e.visit(&mut |sub| {
        if let ExprKind::Ident(n) = &sub.kind {
            let nl = n.to_ascii_lowercase();
            if needles.iter().any(|nd| nl.contains(nd)) {
                hit = true;
            }
        }
    });
    hit
}

/// Helper-function name that performs a clear / consume of the stored message.
fn name_is_clear_consume(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "clear"
        || l.contains("clearpayload")
        || l.contains("clearmessage")
        || l.contains("consumepayload")
        || l.contains("consumemessage")
}

// --------------------------------------------------------------------------
// (2) External transfer-of-control call (the app callback)
// --------------------------------------------------------------------------

/// Span of the first external / low-level / delegate / send / transfer call in the
/// body (document order). This is the application callback that may revert.
fn first_external_control_call(f: &Function) -> Option<Span> {
    let mut best: Option<Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            let ExprKind::Call(c) = &e.kind else { return };
            if !c.kind.is_external_transfer_of_control() {
                return;
            }
            if best.map(|b| e.span.start < b.start).unwrap_or(true) {
                best = Some(e.span);
            }
        });
    }
    best
}

// --------------------------------------------------------------------------
// Suppression
// --------------------------------------------------------------------------

/// Any `try { ... } catch { ... }` in the body — the failure can be handled, so a
/// reverting callback is not silently lost.
fn has_try_catch(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit(&mut |st| {
            if matches!(st.kind, StmtKind::Try { .. }) {
                found = true;
            }
        });
        if found {
            break;
        }
    }
    found
}

/// Source mentions a store-for-retry mechanism (the `NonblockingLzApp` mitigation):
/// a `failedMessages` / `storedPayload` mapping, or a `retryMessage` path.
fn has_failure_retry_store(src_lower: &str) -> bool {
    const RETRY: &[&str] = &[
        "failedmessages",
        "failedmessage",
        "storedpayload",
        "storefailedmessage",
        "retrymessage",
        "failedpayload",
        "messagefailed",
        "failures[",
    ];
    RETRY.iter().any(|k| src_lower.contains(k))
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // VULN: the real LayerZero EndpointV2 shape — `_clearPayload(...)` consumes the
    // stored message and only THEN does the bare external callback, with no
    // try/catch and no failedMessages store. A reverting receiver loses the message.
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        interface ILayerZeroReceiver {
            function lzReceive(uint32 srcEid, bytes32 guid, bytes calldata message, address executor, bytes calldata extraData) external payable;
        }
        contract Endpoint {
            mapping(address => mapping(uint32 => mapping(bytes32 => mapping(uint64 => bytes32)))) public inboundPayloadHash;

            function _clearPayload(address receiver, uint32 srcEid, bytes32 sender, uint64 nonce, bytes memory payload) internal {
                bytes32 expected = inboundPayloadHash[receiver][srcEid][sender][nonce];
                require(expected == keccak256(payload), "bad hash");
                delete inboundPayloadHash[receiver][srcEid][sender][nonce];
            }

            function lzReceive(
                uint32 srcEid,
                bytes32 sender,
                uint64 nonce,
                address receiver,
                bytes32 guid,
                bytes calldata message,
                bytes calldata extraData
            ) external payable {
                // clear the payload first to prevent reentrancy, and then execute
                _clearPayload(receiver, srcEid, sender, nonce, abi.encodePacked(guid, message));
                ILayerZeroReceiver(receiver).lzReceive{ value: msg.value }(srcEid, guid, message, msg.sender, extraData);
            }
        }
    "#;

    // VULN2: inline delete-then-call (no helper), same hazard.
    const VULN2: &str = r#"
        pragma solidity ^0.8.20;
        interface IReceiver { function onMessage(bytes calldata m) external; }
        contract Mailbox {
            mapping(bytes32 => bytes32) public payloadHash;
            function executeMessage(bytes32 id, address to, bytes calldata m) external {
                require(payloadHash[id] == keccak256(m), "bad");
                delete payloadHash[id];
                IReceiver(to).onMessage(m);
            }
        }
    "#;

    // SAFE: the NonblockingLzApp mitigation — the callback is wrapped in try/catch
    // and on failure the payload is stored in `failedMessages` for retry.
    const SAFE_TRY_STORE: &str = r#"
        pragma solidity ^0.8.20;
        interface IReceiver { function onMessage(bytes calldata m) external; }
        contract Mailbox {
            mapping(bytes32 => bytes32) public payloadHash;
            mapping(bytes32 => bytes32) public failedMessages;
            function executeMessage(bytes32 id, address to, bytes calldata m) external {
                require(payloadHash[id] == keccak256(m), "bad");
                delete payloadHash[id];
                try IReceiver(to).onMessage(m) {
                    // delivered
                } catch {
                    failedMessages[id] = keccak256(m);
                }
            }
        }
    "#;

    // SAFE: pull-mode clear() that consumes the stored message but makes NO external
    // app callback (it only deletes + emits). The cleared message is intentionally
    // burnt; there is no callback to revert, so nothing is silently lost here.
    const SAFE_CLEAR_ONLY: &str = r#"
        pragma solidity ^0.8.20;
        contract Endpoint {
            mapping(bytes32 => bytes32) public inboundPayloadHash;
            event PacketDelivered(bytes32 id);
            function clear(bytes32 id, bytes calldata payload) external {
                require(inboundPayloadHash[id] == keccak256(payload), "bad");
                delete inboundPayloadHash[id];
                emit PacketDelivered(id);
            }
        }
    "#;

    // SAFE: verification path that STORES the hash before an (interface) call — it
    // does not consume/delete the stored message, so the consume-then-call shape is
    // absent.
    const SAFE_VERIFY: &str = r#"
        pragma solidity ^0.8.20;
        interface IReceiver { function allowInitializePath(uint32 srcEid) external view returns (bool); }
        contract Endpoint {
            mapping(bytes32 => bytes32) public inboundPayloadHash;
            function verify(uint32 srcEid, address receiver, bytes32 id, bytes32 hash) external {
                require(IReceiver(receiver).allowInitializePath(srcEid), "no");
                inboundPayloadHash[id] = hash;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln_clearpayload_helper() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "lzreceive-failure-silent"), "{:?}", fs);
    }

    #[test]
    fn fires_on_inline_delete_then_call() {
        let fs = run(VULN2);
        assert!(fs.iter().any(|f| f.detector == "lzreceive-failure-silent"), "{:?}", fs);
    }

    #[test]
    fn silent_on_try_catch_with_failed_store() {
        let fs = run(SAFE_TRY_STORE);
        assert!(!fs.iter().any(|f| f.detector == "lzreceive-failure-silent"), "{:?}", fs);
    }

    #[test]
    fn silent_on_clear_only_no_callback() {
        let fs = run(SAFE_CLEAR_ONLY);
        assert!(!fs.iter().any(|f| f.detector == "lzreceive-failure-silent"), "{:?}", fs);
    }

    #[test]
    fn silent_on_verify_store_path() {
        let fs = run(SAFE_VERIFY);
        assert!(!fs.iter().any(|f| f.detector == "lzreceive-failure-silent"), "{:?}", fs);
    }
}
