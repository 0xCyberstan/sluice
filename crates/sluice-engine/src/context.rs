//! The analysis context handed to every detector: the IR plus the three
//! prepared analysis dimensions, with convenience and false-positive-suppression
//! helpers.

use rayon::prelude::*;
use rustc_hash::FxHashMap;
use sluice_config::Config;
use sluice_dataflow::{DataflowFacts, ProvenanceSet};
use sluice_findings::{Category, Finding, FindingBuilder};
use sluice_frontier::FrontierFacts;
use sluice_invariant::InvariantFacts;
use sluice_ir::{Contract, ContractId, Expr, Function, FunctionId, GuardKind, Scir, Span};

/// Remove `//` line comments and `/* */` block comments from Solidity source so
/// keyword-based heuristics don't match commentary. String literals are left
/// intact (over-stripping comments only; rare keyword-in-string is acceptable).
fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            // line comment to end of line
            i += 2;
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            // block comment until */
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else {
            // copy this byte (char-safe: push the char starting here)
            let ch_len = utf8_len(b[i]);
            if let Some(s) = src.get(i..i + ch_len) {
                out.push_str(s);
            }
            i += ch_len;
        }
    }
    out
}

fn utf8_len(first: u8) -> usize {
    match first {
        b if b < 0x80 => 1,
        b if b >> 5 == 0b110 => 2,
        b if b >> 4 == 0b1110 => 3,
        _ => 4,
    }
}

pub struct AnalysisContext<'a> {
    pub scir: &'a Scir,
    pub dataflow: &'a DataflowFacts,
    pub invariants: &'a InvariantFacts,
    pub frontier: &'a FrontierFacts,
    pub config: &'a Config,
    /// Memoized comment-stripped, lowercased source text, keyed by span. Built
    /// once (in parallel) over every function and contract span — the spans the
    /// detectors overwhelmingly query — so the per-call `strip_comments` +
    /// `to_ascii_lowercase` (previously redone by *each* detector for the *same*
    /// function/contract) happens exactly once. A pure function of the span, so
    /// the cache is order-independent and preserves determinism. Spans not in the
    /// cache (statement/expr/operator spans) fall back to computing on the fly.
    source_cache: FxHashMap<Span, String>,
}

impl<'a> AnalysisContext<'a> {
    /// Build a context and precompute the per-span source-text cache in parallel.
    pub fn new(
        scir: &'a Scir,
        dataflow: &'a DataflowFacts,
        invariants: &'a InvariantFacts,
        frontier: &'a FrontierFacts,
        config: &'a Config,
    ) -> Self {
        // Collect the spans worth caching: every function body span and every
        // contract span (deduped — many functions in one file, etc.). These are
        // the spans `source_text` is called on by the bulk of detectors.
        let mut spans: Vec<Span> = Vec::with_capacity(scir.functions.len() + scir.contracts.len());
        for f in scir.all_functions() {
            spans.push(f.span);
        }
        for c in scir.contracts.values() {
            spans.push(c.span);
        }
        spans.sort_unstable_by_key(|s| (s.file, s.start, s.end));
        spans.dedup();

        // Strip + lowercase each once, in parallel. Pure per span ⇒ deterministic.
        let source_cache: FxHashMap<Span, String> = spans
            .into_par_iter()
            .map(|s| (s, strip_comments(scir.span_text(s)).to_ascii_lowercase()))
            .collect();

        Self { scir, dataflow, invariants, frontier, config, source_cache }
    }

    // -------- iteration helpers --------

    pub fn functions(&self) -> impl Iterator<Item = &Function> {
        self.scir.all_functions()
    }

    /// Externally-reachable, state-mutating functions with a body (the usual
    /// attack surface).
    pub fn entry_points(&self) -> impl Iterator<Item = &Function> {
        self.scir
            .all_functions()
            .filter(|f| f.has_body && f.is_externally_reachable() && f.is_state_mutating())
    }

    pub fn contract_of(&self, fid: FunctionId) -> Option<&Contract> {
        self.scir.function(fid).and_then(|f| self.scir.contract(f.contract))
    }

    /// `(contract_name, function_name)` for a function id.
    pub fn names(&self, fid: FunctionId) -> (String, String) {
        match self.scir.function(fid) {
            Some(f) => (
                self.scir.contract(f.contract).map(|c| c.name.clone()).unwrap_or_default(),
                f.name.clone(),
            ),
            None => (String::new(), String::new()),
        }
    }

    // -------- finding construction --------

    pub fn report(&self, detector: &dyn crate::detector::Detector, category: Category) -> FindingBuilder {
        FindingBuilder::new(detector.id(), category)
    }

    /// Finalize a builder, resolving location from a function id + span.
    pub fn finish(&self, b: FindingBuilder, fid: FunctionId, span: Span) -> Finding {
        let (c, f) = self.names(fid);
        // Thread the precise IR ids through so `sluice-verify` can recover the
        // full `Contract`/`Function` (source file, ctor, signature, effects)
        // without re-looking-up by name. `cid` is the function's owning contract.
        let cid = self.scir.function(fid).map(|func| func.contract);
        let mut b = b;
        if let Some(cid) = cid {
            b = b.with_ids(cid, fid);
        }
        b.at(self.scir, c, f, span).build()
    }

    /// Source text for a span with `//` and `/* */` comments stripped, lowercased.
    /// Detectors that key suppression/heuristics on keywords ("timelock", "vrf",
    /// "nonce", ...) MUST use this rather than raw `span_text`, otherwise a comment
    /// like `// no timelock here` falsely trips the keyword check.
    ///
    /// Function/contract spans are served from the precomputed cache (a cheap
    /// clone of an already-stripped string); any other span is computed on the
    /// fly. Either way the result is identical to recomputing every time.
    pub fn source_text(&self, span: Span) -> String {
        match self.source_cache.get(&span) {
            Some(s) => s.clone(),
            None => strip_comments(self.scir.span_text(span)).to_ascii_lowercase(),
        }
    }

    // -------- value-flow queries --------

    pub fn provenance_of(&self, fid: FunctionId, e: &Expr) -> ProvenanceSet {
        self.dataflow.provenance_of(self.scir, fid, e)
    }
    pub fn is_attacker_controlled(&self, fid: FunctionId, e: &Expr) -> bool {
        self.dataflow.is_attacker_controlled(self.scir, fid, e)
    }
    pub fn is_price_like(&self, fid: FunctionId, e: &Expr) -> bool {
        self.dataflow.is_price_like(self.scir, fid, e)
    }

    // -------- false-positive-suppression helpers --------

    /// True if a function is protected against reentrancy (lock modifier or the
    /// contract inherits a reentrancy-guard mixin).
    pub fn has_reentrancy_guard(&self, f: &Function) -> bool {
        if f.effects.guards.iter().any(|g| matches!(g.kind, GuardKind::ReentrancyLock)) {
            return true;
        }
        self.contract_inherits(f.contract, "reentrancyguard") || self.contract_inherits(f.contract, "reentrant")
    }

    /// True if a function enforces access control (auth modifier or msg.sender check).
    pub fn has_access_control(&self, f: &Function) -> bool {
        f.effects
            .guards
            .iter()
            .any(|g| matches!(g.kind, GuardKind::MsgSenderCheck))
    }

    pub fn is_initializer(&self, f: &Function) -> bool {
        f.effects.guards.iter().any(|g| matches!(g.kind, GuardKind::Initializer))
    }

    /// Contract (or any base, by name match) uses SafeERC20.
    pub fn uses_safe_erc20(&self, cid: ContractId) -> bool {
        match self.scir.contract(cid) {
            Some(c) => c.uses_library_like("safeerc20") || c.inherits_like("safeerc20"),
            None => false,
        }
    }

    /// Contract inherits a base whose name contains `needle` (case-insensitive).
    pub fn contract_inherits(&self, cid: ContractId, needle: &str) -> bool {
        self.scir.contract(cid).map(|c| c.inherits_like(needle)).unwrap_or(false)
    }

    /// True if the function (or contract) appears to use a robust oracle
    /// (Chainlink-style) — used to suppress spot-price oracle findings.
    pub fn uses_robust_oracle(&self, f: &Function) -> bool {
        f.effects.call_sites.iter().any(|c| {
            matches!(
                c.func_name.as_deref(),
                Some("latestRoundData") | Some("latestAnswer") | Some("getRoundData")
            )
        }) || f
            .effects
            .internal_calls
            .iter()
            .any(|n| n.to_ascii_lowercase().contains("chainlink") || n.to_ascii_lowercase().contains("oracle"))
    }
}
