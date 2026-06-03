//! Unset-peer default-trust on a cross-chain (OApp/OFT) receive/auth path.
//!
//! LayerZero-style OApps store the trusted remote for each source chain in a
//! `mapping(uint32 eid => bytes32 peer) peers`. An inbound message carries an
//! `Origin { srcEid, sender, nonce }`, and the receiver is supposed to accept a
//! message only when `sender` matches the *configured* peer for `srcEid`. The
//! reference-safe way to do this is `_getPeerOrRevert(srcEid)`, which reads
//! `peers[srcEid]` and **reverts if it is `bytes32(0)`** (an unconfigured
//! pathway) — so an unset EID can never be trusted.
//!
//! The bug this detector targets is an origin check that reads `peers[eid]`
//! *directly* and compares it to the inbound sender **without** the
//! revert-on-unset / `!= bytes32(0)` guard, e.g.
//!
//! ```solidity
//! function allowInitializePath(Origin calldata origin) public view returns (bool) {
//!     return peers[origin.srcEid] == origin.sender; // unset peer == 0
//! }
//! ```
//!
//! For an EID that has never been configured, `peers[eid]` defaults to
//! `bytes32(0)`. A counterparty that presents a zero `sender` on that
//! unconfigured pathway then satisfies `peers[eid] == sender` (`0 == 0`) and is
//! treated as a trusted peer — a message on a pathway the OApp never enabled is
//! accepted / its path initialized. This is the cross-chain analog of the Nomad
//! zero-root trust-by-default bug, specialized to the OApp `peers` mapping.
//!
//! Shape we flag: an externally reachable function on an OApp/OFT-like contract
//! that contains an **equality** comparison (`==` / `!=`) one side of which is a
//! direct `peers[...]` read, the other side a sender/origin value (not the zero
//! literal — that comparison *is* the guard), where the function neither routes
//! the peer through `_getPeerOrRevert` nor carries an explicit non-zero peer
//! guard. We deliberately gate on the contract actually owning a `peers`-style
//! mapping (or being OApp-named) so this stays a cross-chain-trust finding and
//! does not fire on ordinary `mapping == value` comparisons.

use super::prelude::*;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function, Span};

pub struct UnsetPeerDefaultTrustDetector;

impl Detector for UnsetPeerDefaultTrustDetector {
    fn id(&self) -> &'static str {
        "unset-peer-default-trust"
    }
    fn category(&self) -> Category {
        Category::UnsetPeerDefaultTrust
    }
    fn description(&self) -> &'static str {
        "OApp/OFT origin check trusts an unconfigured peer (peers[eid] == sender with no != bytes32(0) guard)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        // NOTE: cannot use `cx.entry_points()` — the canonical sink
        // (`allowInitializePath`) is a `view` function, which that helper filters
        // out. We iterate all functions and apply the externally-reachable gate.
        for f in cx.functions() {
            if !f.has_body || !f.is_externally_reachable() {
                continue;
            }
            // Find an equality comparison whose one operand is a *direct*
            // peer-mapping read (`peers[...]` / `trustedRemoteLookup[...]`) and
            // whose other operand is a sender/origin value (and is NOT the zero
            // literal — `peers[eid] == bytes32(0)` is itself the guard, not the
            // bug). This is recognized structurally, so an inherited `peers`
            // mapping (declared in a base such as `OAppCore`) is still matched.
            let Some((span, peer_var)) = find_unguarded_peer_eq(f) else { continue };

            // Gate on the contract genuinely being a peers-keyed OApp/OFT (by
            // name, an OApp-like base, a peer-mapping state var in the chain, or a
            // sibling OApp function), so an unrelated `someMapping[k] == v`
            // elsewhere is never a hit.
            if !contract_is_peer_oapp(cx, f) {
                continue;
            }

            let src = cx.source_text(f.span);

            // -------- FP suppression --------
            // (1) `_getPeerOrRevert(...)` is invoked in this function: that helper
            //     reverts on an unset (zero) peer, so the unset pathway can't be
            //     trusted. This is the reference-safe form — suppress.
            if calls_get_peer_or_revert(f) {
                continue;
            }
            // (2) An explicit non-zero peer guard is present in the function text
            //     (`peer != bytes32(0)`, `require(peer != 0)`, a `NoPeer` revert,
            //     `if (peer == bytes32(0)) revert`, ...). Suppress.
            if has_nonzero_peer_guard(&src) {
                continue;
            }

            let b = report!(self, Category::UnsetPeerDefaultTrust,
                title = "Cross-chain origin check trusts an unconfigured peer (unset `peers[eid]` == 0)",
                severity = Severity::High,
                confidence = 0.6,
                dimensions = [Dimension::Invariant, Dimension::Frontier],
                message = format!(
                    "`{}` validates an inbound cross-chain message origin by comparing `{peer_var}[eid]` \
                     directly against the message sender without rejecting an unconfigured peer. For an EID \
                     that was never set, `{peer_var}[eid]` defaults to `bytes32(0)`; a counterparty presenting \
                     a zero sender on that unconfigured pathway satisfies the equality (`0 == 0`) and is \
                     treated as the trusted peer, so a message on a pathway this OApp never enabled is \
                     accepted. Unlike `_getPeerOrRevert`, this read has no revert-on-unset / `!= bytes32(0)` \
                     guard — the OApp `peers` analog of the Nomad zero-root trust-by-default bug.",
                    f.name
                ),
                recommendation = format!(
                    "Reject the unset peer before trusting it: route the read through `_getPeerOrRevert(eid)` \
                     (which reverts when `{peer_var}[eid] == bytes32(0)`), or guard explicitly with \
                     `require({peer_var}[eid] != bytes32(0))` so an unconfigured pathway is never accepted."
                ),
            );
            out.push(finish_at(cx, b, f.id, span));
        }
        out
    }
}

// --------------------------------------------------------------------------
// Structural recognition
// --------------------------------------------------------------------------

/// Find an equality (`==` / `!=`) comparison in `f` where one operand is a direct
/// peer-mapping read (`peers[...]` / `trustedRemoteLookup[...]`) and the *other*
/// operand is a sender/origin-like value that is **not** the zero literal.
/// Returns the comparison's span paired with the peer-mapping identifier used (so
/// the report can name it). A comparison against `bytes32(0)` / `0` is the
/// non-zero guard itself, not the bug, so it is explicitly excluded here.
///
/// The peer read is recognized *structurally* (by the index-base identifier
/// name), so it matches even when `peers` is inherited from a base contract
/// (`OAppCore`) and is therefore not in the function-contract's own `state_vars`.
fn find_unguarded_peer_eq(f: &Function) -> Option<(Span, String)> {
    let mut hit: Option<(Span, String)> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Binary { op, lhs, rhs } = &e.kind else { return };
            if !matches!(op, BinOp::Eq | BinOp::Ne) {
                return;
            }
            let l_peer = peer_index_name(lhs);
            let r_peer = peer_index_name(rhs);
            // Exactly one side is the peer read; the other side is the value the
            // peer is compared against (the inbound sender).
            let (peer_var, other) = match (l_peer, r_peer) {
                (Some(name), None) => (name, rhs.as_ref()),
                (None, Some(name)) => (name, lhs.as_ref()),
                // neither, or `peers[a] == peers[b]` — not this origin-check shape.
                _ => return,
            };
            // `peers[eid] == bytes32(0)` / `== 0` is a guard, not the bug.
            if is_zero_value(other) {
                return;
            }
            // The other operand should look like an inbound sender/origin value:
            // a `.sender` member, an `origin`-rooted access, or a `sender`/`peer`-
            // named identifier. This keeps us on genuine origin-auth comparisons.
            if !is_sender_like(other) {
                return;
            }
            hit = Some((e.span, peer_var));
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// If `e` is a direct index read of a peer-like mapping (`<peerName>[...]`,
/// casts peeled so `bytes32(peers[x])` still counts), return the mapping's root
/// identifier; otherwise `None`. The base must be a bare/`this.`-rooted peer name
/// (e.g. `peers`, `trustedRemoteLookup`), not an arbitrary expression.
fn peer_index_name(e: &Expr) -> Option<String> {
    match &peel_casts(e).kind {
        ExprKind::Index { base, .. } => {
            let root = root_ident_str(base)?;
            if is_peer_var_name(root) {
                Some(root.to_owned())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Is `e` the zero value (`bytes32(0)`, `0`, `0x0`, `address(0)`)? Such a
/// comparison is the non-zero guard itself, so we must not treat it as the bug.
fn is_zero_value(e: &Expr) -> bool {
    use sluice_ir::Lit;
    let inner = peel_casts(e);
    match &inner.kind {
        // Numeric `0` / hex `0x0` / `0x000...0`.
        ExprKind::Lit(Lit::Number(n)) => n.trim().trim_start_matches('-').parse::<u128>() == Ok(0),
        ExprKind::Lit(Lit::HexNumber(h)) => {
            let t = h.trim().trim_start_matches("0x").trim_start_matches("0X");
            !t.is_empty() && t.chars().all(|c| c == '0')
        }
        // `bytes32(0)` / `address(0)` peel to the inner `0` (handled above); but a
        // bare `bytes32(0)` whose cast we did NOT peel (multi-arg edge) is rare.
        _ => false,
    }
}

/// Does `e` look like an inbound cross-chain sender / origin value — a `.sender`
/// member access, a member off an `origin`-rooted chain, or an identifier named
/// like a sender/peer? Used to confirm the comparison is an origin-auth check.
fn is_sender_like(e: &Expr) -> bool {
    match &peel_casts(e).kind {
        ExprKind::Member { base, member } => {
            let m = member.to_ascii_lowercase();
            if m.contains("sender") || m.contains("peer") {
                return true;
            }
            // `origin.<field>` (e.g. `_origin.sender`) — root names the origin.
            root_ident_str(base)
                .map(|r| {
                    let r = r.to_ascii_lowercase();
                    r.contains("origin") || r.contains("packet")
                })
                .unwrap_or(false)
        }
        ExprKind::Ident(n) => {
            let l = n.to_ascii_lowercase();
            l.contains("sender") || l.contains("peer") || l.contains("origin") || l.contains("remote")
        }
        _ => false,
    }
}

// --------------------------------------------------------------------------
// Contract / mapping classification
// --------------------------------------------------------------------------

/// True if the function's contract is a peers-keyed OApp/OFT-style messaging
/// contract. Any of: it (or a base it inherits) is named like an OApp/OFT/
/// LayerZero component; it (or a resolvable base) declares a peer-mapping state
/// variable; or a sibling function name reveals the OApp receive/peer role. This
/// keeps the detector cross-chain-scoped instead of firing on any
/// `mapping == value` comparison, while still matching OApps that inherit the
/// `peers` mapping from a base (`OAppCore`).
fn contract_is_peer_oapp(cx: &AnalysisContext, f: &Function) -> bool {
    let Some(c) = cx.contract_of(f.id) else { return false };

    // Contract name (or any inherited base name) reveals an OApp/OFT/LayerZero
    // role — `OAppReceiver`, `OAppCore`, `OFT`, `... is OApp, OAppPreCrime...`.
    if name_is_oapp(&c.name) || c.bases.iter().any(|b| name_is_oapp(b)) {
        return true;
    }

    // A peer-mapping state variable declared on this contract or a resolvable
    // base contract in the inheritance chain.
    if c.state_vars.iter().any(|v| is_peer_var_name(&v.name)) {
        return true;
    }
    if c.bases.iter().any(|b| {
        cx.scir
            .contract_named(b)
            .map(|bc| bc.state_vars.iter().any(|v| is_peer_var_name(&v.name)))
            .unwrap_or(false)
    }) {
        return true;
    }

    // A sibling function name reveals the OApp receive/peer role (e.g. an
    // override of `allowInitializePath` / `lzReceive` / `setPeer` / `isPeer`).
    cx.scir.functions_of(c.id).any(|g| {
        let l = g.name.to_ascii_lowercase();
        l.contains("allowinitializepath")
            || l.contains("lzreceive")
            || l.contains("setpeer")
            || l.contains("getpeerorrevert")
            || l == "ispeer"
    })
}

/// Is `name` a peer-mapping identifier? Matches the LayerZero `peers` mapping and
/// the v1 `trustedRemoteLookup` analog. Deliberately tight (`peers`/`peer` exact,
/// plus the `trustedRemote`/`trustedPeer`/`peerOf` substrings) so an unrelated
/// `peerCount`-style scalar or a generic mapping does not masquerade as one.
fn is_peer_var_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "peers" || l == "peer" || l.contains("trustedremote") || l.contains("trustedpeer") || l.contains("peerof")
}

/// Contract / base name denotes an OApp / OFT / LayerZero messaging component.
fn name_is_oapp(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    ["oapp", "oft", "layerzero", "lzapp", "onft"].iter().any(|k| l.contains(k))
}

// --------------------------------------------------------------------------
// Suppression
// --------------------------------------------------------------------------

/// Does the function invoke `_getPeerOrRevert(...)` (any casing/leading-underscore
/// variant)? That helper reverts when `peers[eid] == bytes32(0)`, so an unset
/// pathway is rejected — the reference-safe form. We match on the call's resolved
/// name so a plain internal call is recognized.
fn calls_get_peer_or_revert(f: &Function) -> bool {
    any_call_where(f, |c| {
        c.func_name
            .as_deref()
            .map(|n| n.to_ascii_lowercase().contains("getpeerorrevert"))
            .unwrap_or(false)
    })
}

/// Does the (comment-stripped, lowercased) source contain an explicit non-zero
/// peer guard? Covers `peer != bytes32(0)`, `require(peer != 0)`, an
/// `if (peer == bytes32(0)) revert`, or a `NoPeer` revert — any of which means
/// the unset (zero) peer is rejected before being trusted.
fn has_nonzero_peer_guard(src_lower: &str) -> bool {
    let compact: String = src_lower.chars().filter(|c| !c.is_whitespace()).collect();
    // A disequality/zero comparison co-located with a peer reference.
    let peer_zero_cmp = (compact.contains("!=bytes32(0)")
        || compact.contains("==bytes32(0)")
        || compact.contains("!=0")
        || compact.contains("==0")
        || compact.contains("!=0x0")
        || compact.contains("==0x0"))
        && (compact.contains("peer") || compact.contains("trustedremote"));
    // The canonical `_getPeerOrRevert` error name, or a textual no-peer revert.
    let no_peer_revert = compact.contains("nopeer") || compact.contains("revertnopeer");
    peer_zero_cmp || no_peer_revert
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // VULN: the real LayerZero `allowInitializePath` shape — `peers[eid]` compared
    // directly to the inbound sender with NO revert-on-unset / non-zero guard.
    // An unconfigured EID (`peers[eid] == 0`) plus a zero sender passes.
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        struct Origin { uint32 srcEid; bytes32 sender; uint64 nonce; }
        contract MyOApp {
            mapping(uint32 => bytes32) public peers;
            function setPeer(uint32 _eid, bytes32 _peer) external { peers[_eid] = _peer; }
            function allowInitializePath(Origin calldata origin) public view returns (bool) {
                return peers[origin.srcEid] == origin.sender;
            }
        }
    "#;

    // SAFE A: routes the origin check through `_getPeerOrRevert`, which reverts on
    // an unset (zero) peer. The reference-safe LayerZero `lzReceive` form.
    const SAFE_GETPEERORREVERT: &str = r#"
        pragma solidity ^0.8.20;
        struct Origin { uint32 srcEid; bytes32 sender; uint64 nonce; }
        contract SafeOApp {
            mapping(uint32 => bytes32) public peers;
            error NoPeer(uint32 eid);
            error OnlyPeer(uint32 eid, bytes32 sender);
            function _getPeerOrRevert(uint32 _eid) internal view returns (bytes32) {
                bytes32 peer = peers[_eid];
                if (peer == bytes32(0)) revert NoPeer(_eid);
                return peer;
            }
            function lzReceive(Origin calldata _origin, bytes calldata) external {
                if (_getPeerOrRevert(_origin.srcEid) != _origin.sender) revert OnlyPeer(_origin.srcEid, _origin.sender);
            }
        }
    "#;

    // SAFE B: explicit non-zero peer guard before trusting the comparison.
    const SAFE_EXPLICIT_GUARD: &str = r#"
        pragma solidity ^0.8.20;
        struct Origin { uint32 srcEid; bytes32 sender; uint64 nonce; }
        contract SafeOApp2 {
            mapping(uint32 => bytes32) public peers;
            function allowInitializePath(Origin calldata origin) public view returns (bool) {
                bytes32 peer = peers[origin.srcEid];
                require(peer != bytes32(0), "no peer");
                return peer == origin.sender;
            }
        }
    "#;

    // SAFE C: a non-OApp contract with an unrelated `mapping[k] == v` comparison.
    // Must not be scoped in — there is no peers mapping / OApp role.
    const SAFE_UNRELATED: &str = r#"
        pragma solidity ^0.8.20;
        contract Registry {
            mapping(address => address) public delegateOf;
            function isDelegate(address who, address d) external view returns (bool) {
                return delegateOf[who] == d;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "unset-peer-default-trust"), "{:?}", fs);
    }

    #[test]
    fn silent_on_get_peer_or_revert() {
        let fs = run(SAFE_GETPEERORREVERT);
        assert!(!fs.iter().any(|f| f.detector == "unset-peer-default-trust"), "{:?}", fs);
    }

    #[test]
    fn silent_on_explicit_guard() {
        let fs = run(SAFE_EXPLICIT_GUARD);
        assert!(!fs.iter().any(|f| f.detector == "unset-peer-default-trust"), "{:?}", fs);
    }

    #[test]
    fn silent_on_unrelated_mapping() {
        let fs = run(SAFE_UNRELATED);
        assert!(!fs.iter().any(|f| f.detector == "unset-peer-default-trust"), "{:?}", fs);
    }
}
