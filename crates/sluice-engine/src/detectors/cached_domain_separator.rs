//! Cached EIP-712 `DOMAIN_SEPARATOR` that goes stale because a field baked into
//! it changes after the cache is built.
//!
//! EIP-712 binds a signed message to a *domain* — `(name, version, chainId,
//! verifyingContract)`. A contract that hashes the domain once and reuses the
//! frozen value is correct only as long as every field stays constant. Two ways
//! the cache can silently go stale, each handled below:
//!
//! ## Sub-case A — chainId change (cross-fork replay)
//!
//! The canonical safe pattern (OpenZeppelin `EIP712`) caches the separator at
//! construction *but* re-derives it on demand whenever `block.chainid` no longer
//! matches the chainId captured at deploy time:
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
//! ## Sub-case B — name/version change (stale cached domain)
//!
//! OpenZeppelin `EIP712`/`EIP712Upgradeable` caches the *name* and *version*
//! hashes at construction/`__EIP712_init` and never reads the live token name
//! again, so the cached separator is correct only while the name is immutable —
//! which it is for essentially every EIP-712 token, since they never rename. The
//! bug appears when a contract bolts a post-deployment `setName`/`setSymbol`
//! (or `setVersion`) governance mutator onto an `EIP712`-derived token: the call
//! changes the on-chain name *without* re-deriving the cached domain, so after a
//! rename every previously-issued `permit`/delegate-by-sig signature breaks and
//! the separator no longer matches what off-chain signers compute (Reserve StRSR
//! M-18). This needs no fork — a single governance call desynchronises the cache.
//!
//! The mutator must be *post-deployment* and *not itself recache*: a name set
//! inside the constructor/initializer (the universal `_setName(name_)` then build
//! the separator in the same `initialize`) is the safe norm and must stay silent.
//! We therefore require an **externally reachable, non-constructor,
//! non-initializer** name/version setter whose body does not rebuild the
//! separator. (Empirically: zero EIP-712 contracts across the precision corpus
//! expose such a setter, so this sub-case is FP-free by construction there.)
//!
//! Precision over recall (this is a niche, low-confidence class):
//!   * Sub-case A only: if the contract re-derives the separator when
//!     `block.chainid` changes — a function whose body references `block.chainid`
//!     *and* (re)builds the separator, an OZ-style
//!     `_domainSeparatorV4`/`_buildDomainSeparator`, or inheritance of OpenZeppelin
//!     `EIP712`/`EIP712Upgradeable` — it is **not** a chainId finding: that is
//!     exactly the mitigation. (OZ inheritance is instead the *trigger* for
//!     sub-case B, which is about a name/version mutator, not the chainId.)
//!   * If the separator is recomputed per call (a `DOMAIN_SEPARATOR()` getter that
//!     hashes the domain on every read, so nothing is frozen) it is **not** a
//!     finding under either sub-case.
//!   * The separator must actually reach a signature path (`ecrecover`/`.recover`/
//!     `permit`/`_hashTypedDataV4`) in this contract; a stored-but-unused separator
//!     is not exploitable.
//!   * Sub-case B only: the name/version setter must be externally reachable and
//!     *not* the constructor/initializer, and must not itself recompute the
//!     separator. A name fixed at init (the common safe pattern) stays silent.

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
            // --- Sub-case A: own cached separator not recomputed on chainId change.
            //     Only concrete contracts hold a real, deployed cached separator;
            //     interfaces/libraries/abstract bases don't deploy state of their own.
            if c.is_concrete() {
                if let Some(f) = self.chainid_finding(cx, c) {
                    out.push(f);
                }
            }

            // --- Sub-case B: a cached EIP-712 domain (OZ `EIP712`/`__EIP712_init`
            //     or a hand-rolled name-bearing separator) made stale by a
            //     post-deployment `setName`/`setSymbol`/`setVersion` mutator that
            //     never re-derives it. The owning contract may be `abstract` (the
            //     real bug site is often an upgradeable base such as Reserve's
            //     `StRSRP1`, deployed via a trivial concrete subclass), so this
            //     sub-case is *not* gated on `is_concrete()`. Its tight,
            //     externally-reachable-mutator guard keeps it false-positive-free.
            if let Some(f) = self.name_mutator_finding(cx, c) {
                out.push(f);
            }
        }

        out
    }
}

impl CachedDomainSeparatorDetector {
    /// Sub-case A — the contract's own cached separator embeds the deploy-time
    /// chainId and is never rebuilt on a fork. Returns the finding, or `None` if
    /// the contract has no frozen separator / handles the chainId / never uses it.
    fn chainid_finding(&self, cx: &AnalysisContext, c: &sluice_ir::Contract) -> Option<Finding> {
        // (1) An EIP-712 domain separator frozen at construction (immutable/constant
        //     name, or assigned exactly once in the constructor).
        let cached = find_cached_separator(cx, c)?;

        // (2) Suppression — the contract handles the chainId-change case, so the
        //     cached value is never stale across a fork.
        //   * OpenZeppelin EIP712 mixin (its `_domainSeparatorV4` already does the
        //     `block.chainid == _CACHED_CHAIN_ID ? cached : rebuild` dance).
        if c.inherits_like("eip712") {
            return None;
        }
        //   * The contract itself re-derives on a chainId change, or exposes the
        //     OZ-style recompute helpers, or recomputes the separator per call.
        if contract_handles_chainid(cx, c, &cached.var) {
            return None;
        }

        // (3) The frozen separator must actually feed a signature-verification path
        //     in this contract; a stored-but-unused value can't be replayed.
        if !contract_verifies_with_separator(cx, c, &cached.var) {
            return None;
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
        Some(cx.finish(b, cached.fid, cached.span))
    }

    /// Sub-case B — a cached EIP-712 domain is desynchronised by a post-deployment
    /// name/version mutator that never re-derives it (Reserve StRSR M-18).
    fn name_mutator_finding(&self, cx: &AnalysisContext, c: &sluice_ir::Contract) -> Option<Finding> {
        // Skip non-deployable shells: an interface/library has no domain to cache.
        // Abstract contracts ARE in scope (the bug site is frequently an
        // upgradeable base), but interfaces/libraries are not.
        if c.is_interface() || c.is_library() {
            return None;
        }

        // (1) The contract caches an EIP-712 domain that binds the token *name*
        //     (and/or version). Either it inherits OZ `EIP712`/`EIP712Upgradeable`
        //     / calls `__EIP712_init` (which hash the name once and never re-read
        //     the live token name), or it caches its own name-bearing separator.
        let cache_kind = domain_name_cache(cx, c)?;

        // (2) A post-deployment mutator changes a field that feeds the cached
        //     domain (name/symbol/version) WITHOUT re-deriving it. This is the
        //     whole bug, and the linchpin of precision (see helper).
        let mutator = find_stale_name_mutator(cx, c)?;

        // (3) The cached domain must actually reach a signature path; a token that
        //     caches a domain it never verifies against can't break a signature.
        if !contract_has_eip712_signature_path(cx, c) {
            return None;
        }

        // (4) Suppression — the contract overrides the domain/name derivation to
        //     recompute from the live name (e.g. a custom `_domainSeparatorV4` or
        //     `_buildDomainSeparator` that re-reads `name()`/`_HASHED_NAME`), so the
        //     rename is reflected and the cache is not stale.
        if contract_rederives_domain_from_live_name(cx, c) {
            return None;
        }

        let (cache_desc, recommendation): (String, &str) = match cache_kind {
            DomainCache::Oz => (
                "inherits OpenZeppelin `EIP712`/`EIP712Upgradeable`, which hashes the token name \
                 at `__EIP712_init` and caches it"
                    .to_string(),
                "Re-derive the EIP-712 domain after a rename: either forbid renaming once the \
                 domain is cached, or override `_EIP712Name`/`_domainSeparatorV4` (OZ v5) so the \
                 separator reads the live name, or re-run the name hashing inside `setName`/`setSymbol`.",
            ),
            DomainCache::HandRolled(var) => (
                format!(
                    "caches its EIP-712 domain separator `{var}` (which embeds the token name) at \
                     construction"
                ),
                "Re-derive the cached domain separator inside `setName`/`setSymbol`/`setVersion`, \
                 or recompute it per call, so a rename is reflected in issued signatures.",
            ),
        };

        let b = FindingBuilder::new(self.id(), Category::CachedDomainSeparator)
            .title("Cached EIP-712 domain separator goes stale when the token name/version is changed")
            .severity(Severity::Medium)
            .confidence(0.5)
            .dimension(Dimension::ValueFlow)
            .message(format!(
                "`{}` {cache_desc}, but `{}` lets the {} be changed after deployment without \
                 re-deriving the cached domain. The EIP-712 domain binds the token name, so once \
                 `{}` is called the cached separator no longer matches the live name: every \
                 previously-issued `permit`/sign-by-signature value breaks and off-chain signers \
                 (which derive the domain from the current name) sign against a separator the \
                 contract no longer recognises (cross-context signature mismatch / replay, \
                 SWC-117). Unlike the chainId case this needs no fork — a single governance call \
                 desynchronises the cache (cf. Reserve StRSR M-18).",
                c.name, mutator.func_name, mutator.field_kind, mutator.func_name
            ))
            .recommendation(recommendation);
        Some(cx.finish(b, mutator.fid, mutator.span))
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

// -------------------------------------------------- sub-case B (name/version)

/// How the contract caches the EIP-712 domain (which binds the token name).
enum DomainCache {
    /// Inherits OZ `EIP712`/`EIP712Upgradeable`, or calls `__EIP712_init` — the
    /// name+version hashes are computed once and the live name is never re-read.
    Oz,
    /// A hand-rolled separator state var (carries the var name for messaging).
    HandRolled(String),
}

/// True if a function (anywhere in the contract) calls the OZ upgradeable
/// `__EIP712_init` / `__EIP712_init_unchained` initializer.
fn calls_eip712_init(cx: &AnalysisContext, c: &sluice_ir::Contract) -> bool {
    cx.scir.functions_of(c.id).any(|f| {
        f.effects.internal_calls.iter().any(|n| {
            let n = n.to_ascii_lowercase();
            n == "__eip712_init" || n == "__eip712_init_unchained"
        })
    })
}

/// Detect a cached EIP-712 domain that binds the token name. Returns the kind of
/// cache, or `None` if the contract has no name-bearing cached domain.
///
/// We require the domain to actually involve the *name* (the field a rename
/// mutates):
///   * OZ `EIP712`/`EIP712Upgradeable` always hashes the name at init → `Oz`.
///   * A hand-rolled separator counts only if its cached construction references a
///     name field (so a chainId+address-only domain like Morpho's — which has no
///     name and thus cannot be desynchronised by a rename — is excluded).
fn domain_name_cache(cx: &AnalysisContext, c: &sluice_ir::Contract) -> Option<DomainCache> {
    // OZ EIP712 mixin (by inheritance or by the upgradeable init call).
    if c.inherits_like("eip712") || calls_eip712_init(cx, c) {
        return Some(DomainCache::Oz);
    }

    // Hand-rolled: a separator-named state var whose cached value embeds the name.
    // Reuse the chainId path's "frozen at construction" detection, then confirm the
    // domain actually carries a name field (otherwise a rename is irrelevant).
    let cached = find_cached_separator(cx, c)?;
    let domain_binds_name = cx.scir.functions_of(c.id).any(|f| {
        if !f.has_body {
            return false;
        }
        let src = cx.source_text(f.span);
        // The function that builds the separator and references a name field.
        let var_l = cached.var.to_ascii_lowercase();
        let builds = src.contains(&var_l) && src.contains("keccak256");
        builds && (src.contains("name") || src.contains("bytes(name") || src.contains("_hashed_name"))
    });
    if domain_binds_name {
        Some(DomainCache::HandRolled(cached.var))
    } else {
        None
    }
}

/// A post-deployment mutator that desynchronises the cached domain.
struct StaleMutator {
    /// The mutating function's name (`setName`, `setSymbol`).
    func_name: String,
    /// Which domain field it changes, for the message (`name`/`symbol`/`version`).
    field_kind: &'static str,
    fid: sluice_ir::FunctionId,
    span: Span,
}

/// A function name that looks like a setter for a domain field (name/symbol/
/// version). We match `set<Field>` and the OZ-internal `_set<Field>` spellings.
fn is_domain_field_setter(name: &str) -> Option<&'static str> {
    let l = name.to_ascii_lowercase();
    // Must be a setter, not a getter/`name()`/`symbol()` accessor.
    let is_set = l.starts_with("set") || l.starts_with("_set") || l.starts_with("update") || l.starts_with("change");
    if !is_set {
        return None;
    }
    if l.contains("name") {
        Some("name")
    } else if l.contains("symbol") {
        Some("symbol")
    } else if l.contains("version") {
        Some("version")
    } else {
        None
    }
}

/// A state-variable name that feeds the EIP-712 domain (name/symbol/version).
fn is_domain_field_var(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "name" || l == "_name" || l == "symbol" || l == "_symbol" || l == "version" || l == "_version"
}

/// Find a post-deployment mutator that changes a domain field (name/symbol/
/// version) without re-deriving the cached domain. This is the precision linchpin:
///
///   * **Externally reachable** (public/external). An `internal` helper such as
///     OZ/Aave's `_setName` is only callable from within the contract's own
///     `initialize`, where the separator is (re)built in the same call — that is
///     the safe norm, so an internal-only setter does NOT count.
///   * **Not** the constructor or an `initializer`/`reinitializer` — a name set at
///     construction is cached *together with* the domain, never stale.
///   * Writes a name/symbol/version state var.
///   * Its body does **not** itself rebuild/recache the domain (no `__EIP712_init`,
///     no `_buildDomainSeparator`, no assignment to a separator var, no keccak of
///     the domain) — if it re-derives, the cache stays fresh.
fn find_stale_name_mutator(cx: &AnalysisContext, c: &sluice_ir::Contract) -> Option<StaleMutator> {
    for f in cx.scir.functions_of(c.id) {
        if !f.has_body || f.is_constructor() {
            continue;
        }
        // Externally reachable + state-mutating: a real post-deployment entry point.
        if !f.is_externally_reachable() || !f.is_state_mutating() {
            continue;
        }
        // Initializers (re)build the domain in the same call — not a stale mutator.
        if cx.is_initializer(f)
            || f.has_modifier_like("initializer")
            || f.has_modifier_like("oninitializing")
        {
            continue;
        }
        let field_kind = match is_domain_field_setter(&f.name) {
            Some(k) => k,
            None => continue,
        };
        // It must actually write a domain field (not merely be named like one).
        if !f.effects.written_vars().iter().any(|v| is_domain_field_var(v)) {
            continue;
        }
        // If the setter re-derives the domain in its own body, the cache stays
        // fresh — not a finding. Check both the parsed call graph and the source.
        let recaches_calls = f.effects.internal_calls.iter().any(|n| {
            let n = n.to_ascii_lowercase();
            n.contains("eip712_init") || n.contains("builddomainseparator") || n.contains("domainseparator")
        });
        if recaches_calls {
            continue;
        }
        let src = cx.source_text(f.span);
        let recaches_src = src.contains("__eip712_init")
            || src.contains("builddomainseparator")
            || src.contains("eip712domain")
            // an assignment recomputing a separator inside the setter.
            || (src.contains("separator") && src.contains("keccak256"));
        if recaches_src {
            continue;
        }
        return Some(StaleMutator {
            func_name: f.name.clone(),
            field_kind,
            fid: f.id,
            span: f.span,
        });
    }
    None
}

/// True if the contract has an EIP-712 signature path that consumes the cached
/// domain: a `permit`, an OZ `_hashTypedDataV4`/`_domainSeparatorV4` use, a
/// `DOMAIN_SEPARATOR()`, or a raw `ecrecover`/`.recover(`.
fn contract_has_eip712_signature_path(cx: &AnalysisContext, c: &sluice_ir::Contract) -> bool {
    cx.scir.functions_of(c.id).any(|f| {
        if !f.has_body {
            return false;
        }
        let name_l = f.name.to_ascii_lowercase();
        if name_l.contains("permit") || name_l == "domain_separator" {
            return true;
        }
        // OZ EIP712 helpers reached via the parsed call graph.
        if f.effects.internal_calls.iter().any(|n| {
            let n = n.to_ascii_lowercase();
            n == "_hashtypeddatav4" || n == "_domainseparatorv4"
        }) {
            return true;
        }
        let src = cx.source_text(f.span);
        src.contains("ecrecover") || src.contains(".recover(") || src.contains("_hashtypeddatav4")
    })
}

/// True if the contract overrides the domain/name derivation to recompute it from
/// the *live* token name (so a rename is reflected and the cache is not stale).
/// This is the OZ-v5 mitigation: override `_EIP712Name()`/`name()`-backed
/// `_domainSeparatorV4`, or a custom `_buildDomainSeparator` that re-reads `name()`.
fn contract_rederives_domain_from_live_name(cx: &AnalysisContext, c: &sluice_ir::Contract) -> bool {
    cx.scir.functions_of(c.id).any(|f| {
        if !f.has_body {
            return false;
        }
        let name_l = f.name.to_ascii_lowercase();
        // An override of the OZ name/version hooks (v5 `_EIP712Name`) — these make
        // the separator track the live name.
        if name_l == "_eip712name" || name_l == "_eip712version" {
            return true;
        }
        // A `_buildDomainSeparator`/`_domainSeparatorV4` *defined in this contract*
        // (i.e. overridden, not the inherited OZ one) that re-reads the live name.
        if name_l.contains("builddomainseparator") || name_l == "_domainseparatorv4" {
            let src = cx.source_text(f.span);
            if src.contains("name()") || src.contains("name(") {
                return true;
            }
        }
        false
    })
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

    // ------------------------------------------- sub-case B (name mutator)

    // A minimal OpenZeppelin `EIP712Upgradeable` stub: it hashes + caches the name
    // at `__EIP712_init` and exposes `_hashTypedDataV4`, never re-reading the live
    // name afterwards (the real OZ semantics behind the bug).
    const EIP712_BASE: &str = r#"
        abstract contract EIP712Upgradeable {
            bytes32 private _HASHED_NAME;
            bytes32 private _HASHED_VERSION;
            function __EIP712_init(string memory name_, string memory version_) internal {
                _HASHED_NAME = keccak256(bytes(name_));
                _HASHED_VERSION = keccak256(bytes(version_));
            }
            function _domainSeparatorV4() internal view returns (bytes32) {
                return keccak256(abi.encode(_HASHED_NAME, _HASHED_VERSION, block.chainid, address(this)));
            }
            function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
                return keccak256(abi.encodePacked("\x19\x01", _domainSeparatorV4(), structHash));
            }
        }
    "#;

    // VULNERABLE (Reserve StRSR M-18 shape): inherits OZ EIP712Upgradeable, caches
    // the name at `__EIP712_init`, verifies signatures via `_hashTypedDataV4` in
    // `permit`, but exposes a post-deployment `setName` that mutates the name
    // WITHOUT re-deriving the cached domain. After `setName` the cached separator is
    // stale and previously-issued permits break.
    fn vuln_eip712_setname() -> String {
        format!(
            r#"
            pragma solidity ^0.8.0;
            {EIP712_BASE}
            contract StakedToken is EIP712Upgradeable {{
                string public name;
                string public symbol;
                mapping(address => uint256) public nonces;
                bytes32 private constant PERMIT_TYPEHASH = keccak256("Permit(address,address,uint256,uint256,uint256)");

                function init(string calldata name_, string calldata symbol_) external {{
                    __EIP712_init(name_, "1");
                    name = name_;
                    symbol = symbol_;
                }}

                function setName(string calldata name_) external {{
                    name = name_;
                }}

                function setSymbol(string calldata symbol_) external {{
                    symbol = symbol_;
                }}

                function permit(
                    address owner, address spender, uint256 value, uint256 deadline,
                    uint8 v, bytes32 r, bytes32 s
                ) external {{
                    require(block.timestamp <= deadline, "expired");
                    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
                    bytes32 digest = _hashTypedDataV4(structHash);
                    address signer = ecrecover(digest, v, r, s);
                    require(signer == owner, "bad sig");
                }}
            }}
        "#
        )
    }

    // SAFE: same OZ EIP712 cache + permit, but NO name/symbol mutator (the common
    // case — EIP-712 tokens essentially never rename). The cache can never go
    // stale, so the detector must stay silent.
    fn safe_eip712_no_mutator() -> String {
        format!(
            r#"
            pragma solidity ^0.8.0;
            {EIP712_BASE}
            contract StakedToken is EIP712Upgradeable {{
                string public name;
                string public symbol;
                mapping(address => uint256) public nonces;
                bytes32 private constant PERMIT_TYPEHASH = keccak256("Permit(address,address,uint256,uint256,uint256)");

                function init(string calldata name_, string calldata symbol_) external {{
                    __EIP712_init(name_, "1");
                    name = name_;
                    symbol = symbol_;
                }}

                function permit(
                    address owner, address spender, uint256 value, uint256 deadline,
                    uint8 v, bytes32 r, bytes32 s
                ) external {{
                    require(block.timestamp <= deadline, "expired");
                    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
                    bytes32 digest = _hashTypedDataV4(structHash);
                    address signer = ecrecover(digest, v, r, s);
                    require(signer == owner, "bad sig");
                }}
            }}
        "#
        )
    }

    // SAFE: the name is only ever set inside the `initializer` (`_setName(name_)`)
    // and the helper is INTERNAL — exactly the OZ/Aave pattern. There is no
    // externally-reachable post-deployment renamer, so the cache is built and the
    // name fixed together. Must stay silent.
    fn safe_eip712_init_only_setname() -> String {
        format!(
            r#"
            pragma solidity ^0.8.0;
            {EIP712_BASE}
            contract StakedToken is EIP712Upgradeable {{
                string private _name;
                string private _symbol;
                mapping(address => uint256) public nonces;
                bytes32 private constant PERMIT_TYPEHASH = keccak256("Permit(address,address,uint256,uint256,uint256)");

                function initialize(string calldata name_, string calldata symbol_) external {{
                    _setName(name_);
                    _setSymbol(symbol_);
                    __EIP712_init(name_, "1");
                }}

                function _setName(string calldata name_) internal {{
                    _name = name_;
                }}
                function _setSymbol(string calldata symbol_) internal {{
                    _symbol = symbol_;
                }}

                function permit(
                    address owner, address spender, uint256 value, uint256 deadline,
                    uint8 v, bytes32 r, bytes32 s
                ) external {{
                    require(block.timestamp <= deadline, "expired");
                    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
                    bytes32 digest = _hashTypedDataV4(structHash);
                    address signer = ecrecover(digest, v, r, s);
                    require(signer == owner, "bad sig");
                }}
            }}
        "#
        )
    }

    // SAFE: a post-deployment `setName` exists, but it RE-RUNS `__EIP712_init` to
    // re-derive the cached domain, so the cache is refreshed on every rename.
    fn safe_eip712_setname_recaches() -> String {
        format!(
            r#"
            pragma solidity ^0.8.0;
            {EIP712_BASE}
            contract StakedToken is EIP712Upgradeable {{
                string public name;
                mapping(address => uint256) public nonces;
                bytes32 private constant PERMIT_TYPEHASH = keccak256("Permit(address,address,uint256,uint256,uint256)");

                function init(string calldata name_) external {{
                    __EIP712_init(name_, "1");
                    name = name_;
                }}

                function setName(string calldata name_) external {{
                    name = name_;
                    __EIP712_init(name_, "1"); // re-derive the cached domain
                }}

                function permit(
                    address owner, address spender, uint256 value, uint256 deadline,
                    uint8 v, bytes32 r, bytes32 s
                ) external {{
                    require(block.timestamp <= deadline, "expired");
                    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
                    bytes32 digest = _hashTypedDataV4(structHash);
                    address signer = ecrecover(digest, v, r, s);
                    require(signer == owner, "bad sig");
                }}
            }}
        "#
        )
    }

    // SAFE: EIP712 cache + post-deployment `setName`, but the domain is NEVER used
    // in a signature path (no permit / no _hashTypedDataV4 / no ecrecover). A stale
    // separator that nothing verifies against can't break a signature.
    fn safe_eip712_setname_no_sig_path() -> String {
        format!(
            r#"
            pragma solidity ^0.8.0;
            {EIP712_BASE}
            contract NamedThing is EIP712Upgradeable {{
                string public name;
                function init(string calldata name_) external {{
                    __EIP712_init(name_, "1");
                    name = name_;
                }}
                function setName(string calldata name_) external {{
                    name = name_;
                }}
            }}
        "#
        )
    }

    #[test]
    fn fires_on_eip712_setname_no_recache() {
        let fs = run(&vuln_eip712_setname());
        let hit = fs.iter().find(|f| f.detector == "cached-domain-separator");
        assert!(hit.is_some(), "expected a cached-domain-separator finding: {fs:?}");
        let f = hit.unwrap();
        // Reported at the renaming mutator, in the token contract.
        assert_eq!(f.function, "setName", "should point at the rename mutator");
        assert_eq!(f.contract, "StakedToken");
        assert!(
            f.title.to_lowercase().contains("name"),
            "title should describe the name/version staleness: {}",
            f.title
        );
    }

    #[test]
    fn silent_on_eip712_no_name_mutator() {
        let fs = run(&safe_eip712_no_mutator());
        assert!(
            !fs.iter().any(|f| f.detector == "cached-domain-separator"),
            "no name mutator ⇒ cache can't go stale: {fs:?}"
        );
    }

    #[test]
    fn silent_on_eip712_internal_init_only_setname() {
        let fs = run(&safe_eip712_init_only_setname());
        assert!(
            !fs.iter().any(|f| f.detector == "cached-domain-separator"),
            "internal _setName called only from the initializer is the safe norm: {fs:?}"
        );
    }

    #[test]
    fn silent_on_eip712_setname_that_recaches() {
        let fs = run(&safe_eip712_setname_recaches());
        assert!(
            !fs.iter().any(|f| f.detector == "cached-domain-separator"),
            "a setName that re-runs __EIP712_init refreshes the cache: {fs:?}"
        );
    }

    #[test]
    fn silent_on_eip712_setname_without_signature_path() {
        let fs = run(&safe_eip712_setname_no_sig_path());
        assert!(
            !fs.iter().any(|f| f.detector == "cached-domain-separator"),
            "a cached domain that never feeds a signature path is not exploitable: {fs:?}"
        );
    }
}
