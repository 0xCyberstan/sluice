//! Cross-chain bridge message-verification gaps. Two flagship incidents anchor
//! this class: Nomad ($190M) — a message was validated against a Merkle root
//! mapping that, after a bad upgrade, treated the zero root as "proven", so any
//! message verified; and Poly Network ($611M) — a relayed cross-chain message
//! selected the call target/selector from attacker-decoded data, letting the
//! attacker call privileged functions on the destination chain.
//!
//! We flag bridge-like inbound handlers that exhibit one of three shapes:
//!   (a) Nomad zero-root: the handler validates against a root / proven-message
//!       store but the contract has no `!= bytes32(0)` / `!= 0` guard on it.
//!   (b) Poly arbitrary relay: a low-level / delegatecall whose target and/or
//!       selector is derived from attacker-controlled (decoded) message data.
//!   (c) Cross-chain sender trusted for auth without binding the source chain
//!       (uses a sender/origin field but never checks `srcChainId` / `origin`).
//!
//! Precision over recall: we only run on contracts that look bridge-like, and we
//! suppress when an explicit non-zero root guard, a call-target allowlist, or a
//! verified guardian/validator signature set is present.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{CallKind, Expr, ExprKind, Function, Span};

pub struct BridgeDetector;

impl Detector for BridgeDetector {
    fn id(&self) -> &'static str {
        "bridge-verification"
    }
    fn category(&self) -> Category {
        Category::BridgeVerification
    }
    fn description(&self) -> &'static str {
        "Cross-chain message verification gaps (Nomad zero-root, Poly arbitrary relay, unbound source chain)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
                continue;
            }
            // Only inbound message-handling entry points on bridge-like contracts.
            if !is_message_handler(f) || !contract_is_bridge_like(cx, f) {
                continue;
            }

            let src = cx.source_text(f.span);

            // ---- (a) Nomad zero-root: validates against a root/store but no zero guard.
            if mentions_root_store(&src) && !has_nonzero_root_guard(&src) {
                let b = FindingBuilder::new(self.id(), Category::BridgeVerification)
                    .title("Cross-chain root/proof checked without a non-zero guard (Nomad-class)")
                    .severity(Severity::High)
                    .confidence(0.5)
                    .dimension(Dimension::Frontier)
                    .message(format!(
                        "`{}` validates an inbound cross-chain message against a root / proven-message \
                         store (e.g. `roots` / `acceptableRoot` / `confirmAt` / `provenMessages`) but the \
                         contract never rejects the zero value (`!= bytes32(0)` / `!= 0`). If the store \
                         defaults to (or can be set to) the zero root, an unproven message with a zero \
                         root verifies — the Nomad $190M zero-root bug.",
                        f.name
                    ))
                    .recommendation(
                        "Reject the zero root before trusting it: `require(root != bytes32(0))` (and \
                         `require(confirmAt[root] != 0)`), and never seed the root mapping with a zeroed \
                         entry during initialization/upgrade.",
                    );
                out.push(cx.finish(b, f.id, f.span));
            }

            // ---- (b) Poly arbitrary relay: call target/selector from attacker message data.
            if !has_target_allowlist(&src) {
                if let Some((span, target_tainted)) = find_attacker_controlled_dispatch(cx, f) {
                    let sev = if target_tainted { Severity::Critical } else { Severity::High };
                    let conf = if target_tainted { 0.6 } else { 0.5 };
                    let mut b = FindingBuilder::new(self.id(), Category::BridgeVerification)
                        .title("Relayed message dispatches a call with attacker-derived target/selector (Poly-class)")
                        .severity(sev)
                        .confidence(conf)
                        .dimension(Dimension::Frontier)
                        .message(format!(
                            "`{}` performs a low-level / delegate call whose target and/or selector is \
                             derived from decoded cross-chain message data. An attacker who can submit a \
                             relayed message chooses what privileged function is invoked on this chain — \
                             the Poly Network $611M arbitrary-relay bug.",
                            f.name
                        ))
                        .recommendation(
                            "Never let message payload choose the call target or selector. Restrict \
                             dispatch to an explicit allowlist of (target, selector) pairs, and forbid \
                             `delegatecall` from relayed data.",
                        );
                    // Attacker value reaching the call sink is a genuine value-flow signal.
                    if target_tainted {
                        b = b.dimension(Dimension::ValueFlow);
                    }
                    out.push(cx.finish(b, f.id, span));
                }
            }

            // ---- (c) Trusts cross-chain sender for auth without binding the source chain.
            if uses_cross_chain_sender(&src) && !binds_source_chain(&src) && !has_guardian_sig_set(&src) {
                let b = FindingBuilder::new(self.id(), Category::BridgeVerification)
                    .title("Cross-chain sender trusted without binding the source chain")
                    .severity(Severity::High)
                    .confidence(0.45)
                    .dimension(Dimension::Frontier)
                    .message(format!(
                        "`{}` authorizes based on a cross-chain sender/origin field but never verifies the \
                         source chain id (`srcChainId` / `sourceChain` / `origin`). A message forged on (or \
                         replayed from) a different chain with the same trusted-sender address passes \
                         authorization.",
                        f.name
                    ))
                    .recommendation(
                        "Bind authorization to (sourceChainId, trustedRemote): verify the inbound source \
                         chain id against a configured trusted-remote map before acting on the sender.",
                    );
                out.push(cx.finish(b, f.id, f.span));
            }
        }
        out
    }
}

// --------------------------------------------------------------------------
// Heuristics
// --------------------------------------------------------------------------

/// Function name suggests inbound cross-chain message handling.
fn is_message_handler(f: &Function) -> bool {
    let l = f.name.to_ascii_lowercase();
    const NAMES: &[&str] = &[
        "process",
        "processmessage",
        "execute",
        "executemessage",
        "relay",
        "receivemessage",
        "lzreceive",
        "_credit",
        "credit",
        "handle",
        "verifyandexecute",
        "onrecvpacket",
        "receive", // receiveFrom / receivePayload-style
        "deliver",
        "submit",
    ];
    if NAMES.iter().any(|n| l.contains(n)) {
        return true;
    }
    // `mint` only counts when the surrounding contract is a bridge (checked
    // separately via `contract_is_bridge_like`); treat it as a candidate name.
    l.contains("mint")
}

/// Restrict to contracts that genuinely look like a bridge / messaging layer, by
/// contract name, a sibling function name, or bridge-shaped state variables.
fn contract_is_bridge_like(cx: &AnalysisContext, f: &Function) -> bool {
    const BRIDGEY: &[&str] = &[
        "bridge", "message", "messaging", "relay", "endpoint", "mailbox", "crosschain", "cross_chain",
        "lzapp", "layerzero", "teleport", "replica", "home", "inbox", "outbox", "gateway", "portal",
        "tunnel", "ccip", "wormhole", "axelar",
    ];
    let name_hit = |s: &str| {
        let l = s.to_ascii_lowercase();
        BRIDGEY.iter().any(|k| l.contains(k))
    };

    if let Some(c) = cx.contract_of(f.id) {
        if name_hit(&c.name) {
            return true;
        }
        // Bridge-shaped state: root stores, trusted remotes, source-chain maps.
        const STATEY: &[&str] = &[
            "root", "acceptableroot", "confirmat", "provenmessages", "trustedremote", "trustedremotes",
            "srcchainid", "sourcechain", "remotechain", "messages", "nonces",
        ];
        if c.state_vars.iter().any(|v| {
            let l = v.name.to_ascii_lowercase();
            STATEY.iter().any(|k| l.contains(k))
        }) {
            return true;
        }
        // A sibling function name reveals the messaging role.
        if cx.scir.functions_of(c.id).any(|g| {
            let l = g.name.to_ascii_lowercase();
            l.contains("relay") || l.contains("message") || l.contains("lzreceive") || l.contains("dispatch")
        }) {
            return true;
        }
    }
    false
}

/// Source mentions a root / proven-message verification store.
fn mentions_root_store(src: &str) -> bool {
    const STORES: &[&str] = &["acceptableroot", "confirmat", "provenmessages", "roots", "messages[", "root"];
    STORES.iter().any(|k| src.contains(k))
}

/// Source contains an explicit non-zero guard on a root/bytes32 value.
fn has_nonzero_root_guard(src: &str) -> bool {
    // `!= bytes32(0)`, `!= 0`, or `!= 0x0...` near the root — accept any of these
    // (with or without internal whitespace) as evidence the zero case is handled.
    src.contains("bytes32(0)")
        || normalize_ws(src).contains("!=0")
        || src.contains("!= 0x0")
        || src.contains("!=0x0")
        || src.contains("require(root")
}

/// Source has an allowlist of permitted call targets / selectors.
fn has_target_allowlist(src: &str) -> bool {
    const ALLOW: &[&str] = &[
        "allowedtargets",
        "whitelistedtargets",
        "allowedtarget",
        "whitelist",
        "allowlist",
        "approvedtarget",
        "iswhitelisted",
        "isallowed",
        "allowedselector",
    ];
    ALLOW.iter().any(|k| src.contains(k))
}

/// Authorization uses a cross-chain sender/origin field.
fn uses_cross_chain_sender(src: &str) -> bool {
    const SENDERS: &[&str] = &["sender", "origin", "fromaddress", "srcaddress", "remotesender", "trustedremote"];
    // Require it to look like an auth comparison, not just a parameter mention.
    let has_sender = SENDERS.iter().any(|k| src.contains(k));
    has_sender && (src.contains("require(") || src.contains("== ") || src.contains("==") || src.contains("revert"))
}

/// Authorization binds the source chain id / domain.
fn binds_source_chain(src: &str) -> bool {
    const CHAIN: &[&str] = &[
        "srcchainid",
        "sourcechain",
        "originchain",
        "remotechainid",
        "srcchain",
        "_origin",
        "origindomain",
        "sourcedomain",
        "chainid_",
    ];
    CHAIN.iter().any(|k| src.contains(k))
}

/// A verified guardian / validator signature set gates the message.
fn has_guardian_sig_set(src: &str) -> bool {
    const SIG: &[&str] = &[
        "guardian",
        "validatorset",
        "validators",
        "quorum",
        "verifysignatures",
        "verifyvaa",
        "ecrecover",
        ".recover(",
        "threshold",
    ];
    SIG.iter().any(|k| src.contains(k))
}

/// Collapse all ASCII whitespace so guards like `!=   0` match `!=0`.
fn normalize_ws(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Scan the body for a low-level / delegate call whose receiver or arguments are
/// attacker-controlled. Returns the call span and whether the *target* (receiver)
/// is the tainted part (→ Critical) vs. only the args/selector (→ High).
fn find_attacker_controlled_dispatch(cx: &AnalysisContext, f: &Function) -> Option<(Span, bool)> {
    let mut result: Option<(Span, bool)> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            if result.is_some() {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            if !matches!(c.kind, CallKind::LowLevelCall | CallKind::DelegateCall) {
                return;
            }
            // Target (receiver) tainted?
            let target_tainted = c
                .receiver
                .as_deref()
                .map(|r| cx.is_attacker_controlled(f.id, r))
                .unwrap_or(false);
            // Selector / payload (any argument) tainted?
            let arg_tainted = c.args.iter().any(|a| cx.is_attacker_controlled(f.id, a));
            if target_tainted || arg_tainted {
                result = Some((e.span, target_tainted));
            }
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Nomad-class: a Replica-style bridge proves a message against a root store
    // with NO non-zero guard, and relays it to a handler chosen by the message.
    const VULN: &str = r#"
        pragma solidity ^0.8.0;
        contract Replica {
            mapping(bytes32 => uint256) public confirmAt;
            mapping(bytes32 => bytes32) public messages;
            address public recipient;

            function acceptableRoot(bytes32 _root) public view returns (bool) {
                uint256 _time = confirmAt[_root];
                return _time != 0; // note: zero ROOT itself is never rejected
            }

            function process(bytes calldata _message) external returns (bool) {
                bytes32 _root = keccak256(_message);
                require(acceptableRoot(_root), "!proven");
                (address _to, bytes memory _data) = abi.decode(_message, (address, bytes));
                (bool _ok, ) = _to.call(_data);
                return _ok;
            }
        }
    "#;

    // Safe: explicit non-zero root guard, an allowlist for dispatch targets, and
    // it binds the source chain id for sender auth.
    const SAFE: &str = r#"
        pragma solidity ^0.8.0;
        contract Mailbox {
            mapping(bytes32 => bool) public roots;
            mapping(address => bool) public allowedTargets;
            mapping(uint32 => bytes32) public trustedRemote;

            function process(uint32 srcChainId, bytes32 root, address to, bytes calldata data, bytes32 sender)
                external
                returns (bool)
            {
                require(root != bytes32(0), "zero root");
                require(roots[root], "!proven");
                require(trustedRemote[srcChainId] == sender, "!trusted");
                require(allowedTargets[to], "!target");
                (bool ok, ) = to.call(data);
                return ok;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "bridge-verification"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "bridge-verification"));
    }
}
