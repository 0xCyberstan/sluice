//! Cached EIP-712 `DOMAIN_SEPARATOR` that is not recomputed on a chainId change
//! (cross-fork signature replay).
//!
//! EIP-712 binds a signed message to a *domain*, and the domain includes
//! `block.chainid`. The canonical safe pattern (OpenZeppelin `EIP712`) caches the
//! separator at construction *but* re-derives it on demand whenever
//! `block.chainid` no longer matches the chainId captured at deploy time:
//!
//! ```solidity
//! function _domainSeparatorV4() internal view returns (bytes32) {
//!     if (block.chainid == _CACHED_CHAIN_ID) return _CACHED_DOMAIN_SEPARATOR;
//!     return _buildDomainSeparator();           // recompute with the new chainId
//! }
//! ```
//!
//! A contract that instead freezes the separator forever — declaring it
//! `immutable`/`constant`, or assigning it exactly once in the constructor — and
//! then feeds that frozen value into an `ecrecover`/`permit` digest *without* the
//! `block.chainid` re-check embeds the deploy-time chainId permanently. After a
//! hard fork (which changes `block.chainid` while preserving deployed state and
//! balances on the minority chain), the cached separator still carries the *old*
//! chainId, so an EIP-712 signature is valid on **both** forks and can be replayed
//! across the split (SWC-117 / CWE-347). This is the bug behind OZ's switch from a
//! plain immutable `DOMAIN_SEPARATOR` to the cached-with-recompute design.
//!
//! Precision over recall (this is a niche, low-confidence class):
//!   * If the contract re-derives the separator when `block.chainid` changes — a
//!     function whose body references `block.chainid` *and* (re)builds the
//!     separator, an OZ-style `_domainSeparatorV4`/`_buildDomainSeparator`, or
//!     inheritance of OpenZeppelin `EIP712`/`EIP712Upgradeable` — it is **not** a
//!     finding: that is exactly the mitigation.
//!   * If the separator is recomputed per call (a `DOMAIN_SEPARATOR()` getter that
//!     hashes the domain on every read, so nothing is frozen) it is **not** a
//!     finding.
//!   * The separator must actually reach a signature path (`ecrecover`/`.recover`/
//!     `permit`) in this contract; a stored-but-unused separator is not exploitable.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::Span;

pub struct CachedDomainSeparatorDetector;

impl Detector for CachedDomainSeparatorDetector {
    fn id(&self) -> &'static str {
        "cached-domain-separator"
    }
    fn category(&self) -> Category {
        Category::CachedDomainSeparator
    }
    fn description(&self) -> &'static str {
        "EIP-712 DOMAIN_SEPARATOR cached at construction and used in signature verification without recomputing on a chainId change (cross-fork replay)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for c in cx.scir.iter_contracts() {
            // Only concrete contracts hold a real, deployed cached separator;
            // interfaces/libraries/abstract bases don't deploy state of their own.
            if !c.is_concrete() {
                continue;
            }

            // (1) Is there an EIP-712 domain separator frozen at construction?
            //     Either a state var declared immutable/constant whose name looks
            //     like a domain separator, or one assigned exactly once in the
            //     constructor. Capture the var name + the span to report at.
            let cached = match find_cached_separator(cx, c) {
                Some(x) => x,
                None => continue,
            };

            // (2) Suppression — the contract handles the chainId-change case, so
            //     the cached value is never stale across a fork.
            //
            //   * OpenZeppelin EIP712 mixin (its `_domainSeparatorV4` already does
            //     the `block.chainid == _CACHED_CHAIN_ID ? cached : rebuild` dance).
            if c.inherits_like("eip712") {
                continue;
            }
            //   * The contract itself re-derives on a chainId change, or exposes the
            //     OZ-style recompute helpers, or recomputes the separator per call.
            if contract_handles_chainid(cx, c, &cached.var) {
                continue;
            }

            // (3) The frozen separator must actually feed a signature-verification
            //     path in this contract; a stored-but-unused value can't be
            //     replayed.
            if !contract_verifies_with_separator(cx, c, &cached.var) {
                continue;
            }

            let b = FindingBuilder::new(self.id(), Category::CachedDomainSeparator)
                .title("Cached EIP-712 domain separator not recomputed on chainId change")
                .severity(Severity::Medium)
                .confidence(0.45)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` freezes its EIP-712 domain separator `{}` at construction \
                     (immutable/constant or set once in the constructor) and uses it to verify \
                     signatures, but never recomputes it when `block.chainid` changes. The cached \
                     separator embeds the deploy-time chainId; after a hard fork the same EIP-712 \
                     signature stays valid on both chains, enabling cross-fork replay (SWC-117).",
                    c.name, cached.var
                ))
                .recommendation(
                    "Cache the chainId alongside the separator and recompute on mismatch (the \
                     OpenZeppelin `EIP712` pattern: `block.chainid == _cachedChainId ? _cached : \
                     _buildDomainSeparator()`), or inherit OpenZeppelin `EIP712`.",
                );
            out.push(cx.finish(b, cached.fid, cached.span));
        }

        out
    }
}

// ----------------------------------------------------------------- helpers

/// A domain separator frozen at construction, with where to report it.
struct Cached {
    /// The state-variable name (`DOMAIN_SEPARATOR`, `_domainSeparator`).
    var: String,
    /// Function id used for location resolution (the contract's constructor, or
    /// any function of the contract as a fallback anchor).
    fid: sluice_ir::FunctionId,
    /// Span to highlight (the state-var declaration, or the constructor).
    span: Span,
}

/// A state-variable name that looks like an EIP-712 domain separator.
fn looks_like_domain_separator(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // `DOMAIN_SEPARATOR`, `_domainSeparator`, `_CACHED_DOMAIN_SEPARATOR`, …
    (l.contains("domain") && l.contains("separator")) || l == "domain_separator"
}

/// Find a domain separator that is frozen at construction: declared
/// immutable/constant, or written exactly once and only inside the constructor.
fn find_cached_separator(cx: &AnalysisContext, c: &sluice_ir::Contract) -> Option<Cached> {
    // An anchor function id for location resolution — prefer the constructor.
    let ctor = cx.scir.functions_of(c.id).find(|f| f.is_constructor());

    // Case A: immutable / constant declaration with a separator-like name.
    if let Some(sv) = c
        .state_vars
        .iter()
        .find(|v| (v.immutable || v.constant) && looks_like_domain_separator(&v.name))
    {
        let fid = ctor
            .map(|f| f.id)
            .or_else(|| cx.scir.functions_of(c.id).next().map(|f| f.id))?;
        return Some(Cached { var: sv.name.clone(), fid, span: sv.span });
    }

    // Case B: a (mutable) separator-like state var assigned exactly once, only in
    // the constructor — functionally immutable. If any non-constructor function
    // writes it, it is intentionally refreshable and not a "frozen" cache.
    let sep_vars: Vec<&sluice_ir::StateVar> =
        c.state_vars.iter().filter(|v| looks_like_domain_separator(&v.name)).collect();
    if sep_vars.is_empty() {
        return None;
    }
    let ctor = ctor?;
    for sv in sep_vars {
        let written_in_ctor = ctor.effects.writes_var(&sv.name);
        let written_elsewhere = cx
            .scir
            .functions_of(c.id)
            .any(|f| !f.is_constructor() && f.is_state_mutating() && f.effects.writes_var(&sv.name));
        if written_in_ctor && !written_elsewhere {
            return Some(Cached { var: sv.name.clone(), fid: ctor.id, span: ctor.span });
        }
    }
    None
}

/// True if the contract re-derives the separator when `block.chainid` changes, or
/// recomputes it per call — either way the cache cannot go stale across a fork.
///
/// Heuristics (substring checks over function source, intentionally generous so we
/// stay quiet on the safe pattern):
///   * any function references `block.chainid` *and* (re)builds a separator
///     (`keccak256`/`_buildDomainSeparator`/an assignment to the separator var), or
///   * the contract defines an OZ-style recompute helper
///     (`_domainSeparatorV4`/`_buildDomainSeparator`), or
///   * a `DOMAIN_SEPARATOR()`-style getter recomputes (hashes) on every read.
fn contract_handles_chainid(cx: &AnalysisContext, c: &sluice_ir::Contract, var: &str) -> bool {
    let var_l = var.to_ascii_lowercase();
    for f in cx.scir.functions_of(c.id) {
        if !f.has_body {
            continue;
        }
        // The constructor BUILDS the cached separator once (necessarily using
        // `block.chainid` and the `EIP712Domain` type string) — that is precisely
        // the cached-at-deploy state, NOT handling a later chainId change. Only a
        // non-constructor rebuild/getter counts as handling a fork.
        if f.is_constructor() {
            continue;
        }
        let name_l = f.name.to_ascii_lowercase();
        // OZ-style recompute helpers are an explicit signal of the safe design.
        if name_l.contains("builddomainseparator") || name_l == "_domainseparatorv4" {
            return true;
        }
        let src = cx.source_text(f.span);
        let rebuilds_separator = src.contains("_builddomainseparator")
            || src.contains("eip712domain")
            // an assignment that recomputes the separator (`sep = keccak256(...)`).
            || (src.contains(&var_l) && src.contains("keccak256"));

        // (a) Re-derivation guarded by a chainId check: the canonical safe shape.
        if src.contains("block.chainid") && rebuilds_separator {
            return true;
        }
        // (b) A getter that recomputes on every call (no caching at all) — a
        //     view/pure separator builder that hashes the domain inline.
        if f.is_view_or_pure()
            && (name_l.contains("domainseparator") || name_l == "domain_separator")
            && src.contains("keccak256")
            && src.contains("block.chainid")
        {
            return true;
        }
    }
    false
}

/// True if some function in the contract uses the cached separator in a signature
/// verification path: it references `ecrecover` / `.recover(` / is a `permit`
/// entry, *and* the digest it verifies is derived from the cached separator
/// (the separator var appears in the same function body).
fn contract_verifies_with_separator(cx: &AnalysisContext, c: &sluice_ir::Contract, var: &str) -> bool {
    let var_l = var.to_ascii_lowercase();
    for f in cx.scir.functions_of(c.id) {
        if !f.has_body {
            continue;
        }
        let src = cx.source_text(f.span);
        let is_sig_path = src.contains("ecrecover")
            || src.contains(".recover(")
            || f.name.to_ascii_lowercase().contains("permit");
        if !is_sig_path {
            continue;
        }
        // The verified digest must be built from the cached separator. Either the
        // separator var is named directly in this body, or it is composed via the
        // EIP-712 `\x19\x01` prefix join (then the var typically appears too). We
        // require the var name to keep this tied to the actual cached value.
        if src.contains(&var_l) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: DOMAIN_SEPARATOR is immutable, set once in the constructor with
    // the deploy-time block.chainid, and used in `permit`'s ecrecover digest. It is
    // never recomputed on a chainId change, so after a hard fork the signature
    // replays across the split.
    const VULN: &str = r#"
        pragma solidity ^0.8.0;
        contract Token {
            bytes32 public immutable DOMAIN_SEPARATOR;
            mapping(address => uint256) public nonces;
            bytes32 public constant PERMIT_TYPEHASH =
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

            constructor() {
                DOMAIN_SEPARATOR = keccak256(
                    abi.encode(
                        keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                        keccak256(bytes("Token")),
                        block.chainid,
                        address(this)
                    )
                );
            }

            function permit(
                address owner, address spender, uint256 value, uint256 deadline,
                uint8 v, bytes32 r, bytes32 s
            ) external {
                require(deadline >= block.timestamp, "expired");
                bytes32 digest = keccak256(
                    abi.encodePacked(
                        "\x19\x01",
                        DOMAIN_SEPARATOR,
                        keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline))
                    )
                );
                address recovered = ecrecover(digest, v, r, s);
                require(recovered != address(0) && recovered == owner, "bad sig");
            }
        }
    "#;

    // Safe: the OpenZeppelin pattern — the separator is cached with the deploy
    // chainId but `_domainSeparator()` rebuilds it whenever block.chainid changes,
    // so the cache can never be stale across a fork.
    const SAFE: &str = r#"
        pragma solidity ^0.8.0;
        contract Token {
            bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
            uint256 private immutable _CACHED_CHAIN_ID;
            bytes32 private constant PERMIT_TYPEHASH =
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
            mapping(address => uint256) public nonces;

            constructor() {
                _CACHED_CHAIN_ID = block.chainid;
                _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator();
            }

            function _buildDomainSeparator() internal view returns (bytes32) {
                return keccak256(
                    abi.encode(
                        keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                        keccak256(bytes("Token")),
                        block.chainid,
                        address(this)
                    )
                );
            }

            function _domainSeparator() internal view returns (bytes32) {
                if (block.chainid == _CACHED_CHAIN_ID) {
                    return _CACHED_DOMAIN_SEPARATOR;
                }
                return _buildDomainSeparator();
            }

            function permit(
                address owner, address spender, uint256 value, uint256 deadline,
                uint8 v, bytes32 r, bytes32 s
            ) external {
                require(deadline >= block.timestamp, "expired");
                bytes32 digest = keccak256(
                    abi.encodePacked(
                        "\x19\x01",
                        _domainSeparator(),
                        keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline))
                    )
                );
                address recovered = ecrecover(digest, v, r, s);
                require(recovered != address(0) && recovered == owner, "bad sig");
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "cached-domain-separator"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "cached-domain-separator"));
    }
}
