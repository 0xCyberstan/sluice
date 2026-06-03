//! Checkpoint hint trust — a caller-supplied index/hint decides a checkpoint
//! value without re-validating that the resolved entry matches the request.
//!
//! A historical-value lookup (stake / shares / opt-in / resolver at a past
//! timestamp) is the heart of restaking accounting. To save gas, such lookups
//! often accept a **caller-supplied hint** — an array position the caller claims
//! points at the right checkpoint — and read `trace[hint]` (or `at(self, hint)`
//! / `_unsafeAccess(self, hint)`) instead of binary-searching. The returned
//! checkpoint value then flows straight to the function's **return** or to an
//! accounting decision.
//!
//! The hint is *only* trustworthy if the function re-checks that the resolved
//! entry actually corresponds to the requested key/timestamp — the canonical
//! bracketing re-validation in OpenZeppelin / Symbiotic `Checkpoints`:
//! ```solidity
//! Checkpoint208 memory ckpt = at(self, hint);
//! if (ckpt._key == key) return ckpt._value;                       // exact match
//! if (ckpt._key < key && (hint == length(self) - 1
//!         || at(self, hint + 1)._key > key)) return ckpt._value;  // bracketed
//! return upperLookupRecent(self, key);                            // fall back to search
//! ```
//! Drop those `ckpt._key == key` / `at(self, hint + 1)._key > key` guards and a
//! *wrong* hint silently returns the *wrong* checkpoint: a stake/shares/resolver
//! value for the wrong epoch, desyncing every downstream accounting figure
//! (slashable stake, vote weight, the active resolver). This is the shape behind
//! Symbiotic Core `Checkpoints.upperLookupRecent(self, key, hint)` and its
//! underlying by-position accessor `at(Trace*, pos)` — the latter resolves and
//! returns a checkpoint chosen solely by the caller-supplied `pos` with no
//! bracketing re-check, which is exactly what the detector flags on the real
//! `Checkpoints.sol` (the keyed `upperLookupRecent(self, key, hint_)` variants in
//! that file *do* re-check and are correctly suppressed).
//!
//! Precision anchors (all required, so this stays quiet on ordinary
//! index-a-parameter code such as `arr[i]` getters):
//!   * the lookup operates on a **checkpoint-`Trace` container** — a parameter
//!     whose type is the OpenZeppelin / Symbiotic `Trace*` family (`Trace208`,
//!     `Trace224`, `Trace256`) or a bare `Checkpoint*[]` array. The `Trace` family
//!     is *specifically* the append-only, binary-search/hint-indexed keyed log
//!     whose public API (`upperLookupRecent(self, key, hint)`) exposes a
//!     caller-supplied hint, which is exactly what makes by-position trust the
//!     live hazard. This anchor is what separates the real target from look-alike
//!     structures: EigenLayer's `Snapshots` (`DefaultWadHistory` / `Snapshot[]`),
//!     Pendle's `VeHistoryLib` (`History`/`Checkpoint[]`-wrapping) and its Uniswap
//!     `Observation[]` oracle ring buffer, and the cert-verifiers' nested
//!     `_operatorInfos[set][ts][index]` mappings — none of which is a `Trace`;
//!   * a parameter whose **name** is hint-like (`hint`/`index`/`idx`/`pos`/
//!     `checkpointIndex`) and whose **type is an unsigned integer**;
//!   * that parameter is used as an **index** `base[hint]` or as an **argument to
//!     a checkpoint accessor** (`at`/`_unsafeAccess`/`*lookup*`/`*checkpoint*`);
//!   * the produced value reaches a **`return`** or a **storage write**;
//!   * and there is **no bracketing re-check** — no comparison of a resolved
//!     entry's `_key`/`key`/`timestamp` against the requested key anywhere in the
//!     body (such a compare means the hint is verified, so we suppress).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Expr, ExprKind, Function};

pub struct CheckpointHintTrustDetector;

impl Detector for CheckpointHintTrustDetector {
    fn id(&self) -> &'static str {
        "checkpoint-hint-trust"
    }
    fn category(&self) -> Category {
        Category::CheckpointHintTrust
    }
    fn description(&self) -> &'static str {
        "Caller-supplied checkpoint hint/index drives a returned value with no re-check that the entry matches the requested key (Symbiotic upperLookupRecent class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // The lookup is usually a `view` getter (`resolverAt`) or an
            // `internal` library accessor (`upperLookupRecent`), so we must NOT
            // restrict to state-mutating entry points. We need either an
            // externally reachable surface or a library helper — both are real
            // value-deciders. Plain private one-offs with no return are skipped
            // via the value-flow anchor below.
            let in_library = cx
                .contract_of(f.id)
                .map(|c| c.is_library())
                .unwrap_or(false);
            if !f.is_externally_reachable() && !in_library {
                continue;
            }
            // The resolved value has to *go somewhere* that matters: a return, or
            // an accounting storage write. A function that returns nothing and
            // writes nothing cannot desync a value.
            let produces_value = !f.returns.is_empty() || !f.effects.storage_writes.is_empty();
            if !produces_value {
                continue;
            }

            // --- positive checkpoint anchor: the lookup must operate on a
            // `Trace`-family checkpoint container (or a bare `Checkpoint*[]`). This
            // is the principled discriminator that fires on the real Symbiotic
            // `Checkpoints.{at,upperLookupRecent}(Trace*, ...)` while staying silent
            // on look-alikes that index something else by position: the
            // cert-verifiers index nested `_operatorInfos` *mappings* and return
            // `*OperatorInfo` structs; Pendle's oracle indexes an `Observation[]`
            // ring buffer; EigenLayer's `Snapshots` / Pendle's `VeHistoryLib` use
            // `*History` wrappers and `Snapshot[]` / `Checkpoint[]` — none of which
            // is a `Trace`. Requiring the `Trace` container is what drops every one
            // of those to zero. ---
            if !indexes_checkpoint_trace(f) {
                continue;
            }

            // --- structural gate: a hint-like unsigned-int parameter ---
            let Some(hint) = hint_param(f) else { continue };

            // The hint must actually be *used* as a checkpoint index — either a
            // bare index `base[hint]` or an argument to a checkpoint accessor
            // (`at(self, hint)` / `_unsafeAccess(self, hint)` / `*lookup*` /
            // `*checkpoint*`). A hint that is never used this way is not a trust
            // sink (it might be a stride, a length, an unused optimisation arg).
            let (used_as_index, span) = hint_used_as_checkpoint_index(f, &hint);
            if !used_as_index {
                continue;
            }

            // --- false-positive suppression (precision is the priority) ---
            // The defining safe pattern re-validates the resolved entry: a
            // comparison of a `_key`/`key`/`timestamp` member against the
            // requested key, anywhere in the body. Presence of such a bracketing
            // re-check means the hint is verified — suppress.
            if has_key_recheck(f) {
                continue;
            }

            let b = FindingBuilder::new(self.id(), Category::CheckpointHintTrust)
                .title("Caller-supplied checkpoint hint trusted without re-validating the resolved entry")
                .severity(Severity::Medium)
                .confidence(0.5)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` operates on a `Trace`-family checkpoint log and resolves a checkpoint from the \
                     caller-supplied index/hint parameter `{hint}` (`base[{hint}]` / `at(self, {hint})`), \
                     letting the resolved entry's value flow to a return or accounting write, but never \
                     re-validates that the resolved entry actually corresponds to the requested \
                     key/timestamp (no `entry._key == key` / bracketing `at(self, {hint} + 1)._key > key` \
                     check). A caller who passes a wrong hint receives the checkpoint for the wrong epoch \
                     — the wrong stake / shares / opt-in / resolver value — desyncing downstream \
                     accounting. This is the Symbiotic Core `Checkpoints.upperLookupRecent(self, key, hint)` \
                     / `at(self, pos)` hint-trust shape.",
                    f.name,
                    hint = hint,
                ))
                .recommendation(
                    "Treat the hint as untrusted: after reading `entry = at(self, hint)`, require the \
                     entry to bracket the requested key — `if (entry._key == key) return entry._value;` \
                     and `if (entry._key < key && (hint == length - 1 || at(self, hint + 1)._key > key)) \
                     return entry._value;` — and otherwise fall back to a verified binary search \
                     (`upperLookupRecent(self, key)`). Never return a checkpoint value chosen solely by a \
                     caller-supplied index.",
                );
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

/// Hint-like parameter names. Kept tight (exact-ish) so ordinary numeric params
/// (`amount`, `id`, `count`, `length`) do not trip the gate.
const HINT_NAMES: &[&str] = &[
    "hint",
    "index",
    "idx",
    "pos",
    "position",
    "at",
    "checkpointindex",
    "checkpointidx",
    "checkpointpos",
];

/// A parameter whose name is hint-like *and* whose type is an unsigned integer.
/// Returns the parameter name. We match a name that equals a hint token or ends
/// with one in camelCase (`resolverHint`, `stakeIndex`), to catch the real
/// spellings without matching unrelated words that merely contain `at` as a
/// substring (`treasury`, `data`).
fn hint_param(f: &Function) -> Option<String> {
    f.params.iter().find_map(|p| {
        let name = p.name.as_deref()?;
        if !is_unsigned_int(&p.ty) {
            return None;
        }
        if is_hint_name(name) {
            Some(name.to_string())
        } else {
            None
        }
    })
}

/// Does `f` operate on a checkpoint-`Trace` container? True when any parameter's
/// declared type is the OpenZeppelin / Symbiotic `Trace*` family (its type name
/// contains `trace`, case-insensitive — `Trace208` / `Trace224` / `Trace256` /
/// `OZCheckpoints.Trace208`), or is a bare `Checkpoint*[]` array (`type` contains
/// `checkpoint` *and* is an array).
///
/// This is the positive anchor that pins the detector to the genuine Symbiotic
/// `Checkpoints` hint-lookup family and excludes the look-alikes:
///   * cert-verifiers take `OperatorSet` / `uint32` / `uint256` and index a
///     `mapping` — no `Trace`/`Checkpoint[]` param;
///   * Pendle's oracle takes `Observation[65535]` — not a `Trace`/`Checkpoint`;
///   * EigenLayer `Snapshots` takes `DefaultWadHistory` / `Snapshot[]`, and
///     Pendle's `VeHistoryLib` takes `History` — `History`/`Snapshot` are not
///     `Trace`, and neither exposes a `Checkpoint[]` *parameter*.
fn indexes_checkpoint_trace(f: &Function) -> bool {
    f.params.iter().any(|p| {
        let t = p.ty.to_ascii_lowercase();
        // `Trace*` family (the hint-exposing keyed checkpoint log).
        if t.contains("trace") {
            return true;
        }
        // A bare `Checkpoint*[]` storage array (the underlying positional store).
        if t.contains("checkpoint") && (t.contains("[]") || t.contains('[')) {
            return true;
        }
        false
    })
}

/// Case-insensitive: `name` is exactly a hint token, or is a camelCase
/// identifier whose trailing word is a hint token (`stakeHint`, `epochIndex`,
/// `checkpointPos`). The trailing-word rule avoids matching `attestation` /
/// `treasury` (which merely *contain* `at`) while still catching `...At`.
fn is_hint_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    if HINT_NAMES.iter().any(|h| l == *h) {
        return true;
    }
    // Trailing camelCase word: split on the last uppercase boundary.
    if let Some(tail) = last_camel_word(name) {
        let tl = tail.to_ascii_lowercase();
        return HINT_NAMES.iter().any(|h| tl == *h);
    }
    false
}

/// The trailing camelCase word of an identifier (`stakeHint` -> `Hint`,
/// `at` -> None because there is no internal boundary). Returns `None` when the
/// identifier has no internal uppercase boundary.
fn last_camel_word(name: &str) -> Option<&str> {
    let bytes = name.as_bytes();
    let mut start = None;
    for i in 1..bytes.len() {
        if bytes[i].is_ascii_uppercase() {
            start = Some(i);
        }
    }
    start.map(|i| &name[i..])
}

/// Textual type test for an unsigned integer (`uint`, `uint32`, `uint48`,
/// `uint256`, possibly with a `memory`/`calldata` location suffix). Anything
/// else (`bytes`, `address`, `int256`, a struct) is not an index.
fn is_unsigned_int(ty: &str) -> bool {
    let t = ty.trim().split_whitespace().next().unwrap_or("").to_ascii_lowercase();
    t == "uint" || (t.starts_with("uint") && t[4..].chars().all(|c| c.is_ascii_digit()))
}

/// Names of checkpoint accessor functions that resolve an entry *by position*.
/// `at` / `_unsafeAccess` are the OZ/Symbiotic primitives; `*lookup*` and
/// `*checkpoint*` cover the higher-level wrappers.
fn is_checkpoint_accessor(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "at" || l == "_unsafeaccess" || l == "unsafeaccess" || l.contains("lookup") || l.contains("checkpoint")
}

/// Does `hint` get used as a checkpoint index? Either:
///   * a bare index `base[hint]` (the index expression *is* `hint`), or
///   * an argument to a checkpoint accessor call (`at(self, hint)`,
///     `_unsafeAccess(arr, hint)`, `...lookup...(hint)`), including the common
///     `at(self, hint + 1)` bracket probe.
/// Returns `(true, span)` at the first such use (span of that expression), so the
/// finding points at the trust sink.
fn hint_used_as_checkpoint_index(f: &Function, hint: &str) -> (bool, sluice_ir::Span) {
    let mut hit: Option<sluice_ir::Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            match &e.kind {
                // `base[hint]` — the index expression mentions the hint.
                ExprKind::Index { index: Some(idx), .. } => {
                    if expr_mentions_ident(idx, hint) {
                        hit = Some(e.span);
                    }
                }
                // `at(self, hint)` / `_unsafeAccess(arr, hint)` / `lookup(hint)`.
                ExprKind::Call(c) => {
                    let is_accessor = c
                        .func_name
                        .as_deref()
                        .map(is_checkpoint_accessor)
                        .unwrap_or(false);
                    if is_accessor && c.args.iter().any(|a| expr_mentions_ident(a, hint)) {
                        hit = Some(e.span);
                    }
                }
                _ => {}
            }
        });
        if hit.is_some() {
            break;
        }
    }
    match hit {
        Some(s) => (true, s),
        None => (false, f.span),
    }
}

/// The bracketing re-check that makes a hint safe: a comparison (`==`/`<`/`>`/
/// `<=`/`>=`) one of whose operands is a member access named like the checkpoint
/// key (`_key`/`key`/`timestamp`/`time`/`ts`). This is exactly the
/// `checkpoint._key == key` / `at(self, hint + 1)._key > key` guard in the safe
/// `upperLookupRecent`. We err toward suppression: any such compare anywhere in
/// the body counts as the hint being validated.
fn has_key_recheck(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
                if op.is_comparison() && (mentions_key_member(lhs) || mentions_key_member(rhs)) {
                    found = true;
                }
            }
        });
        if found {
            break;
        }
    }
    found
}

/// Does `e` contain a member access whose member name looks like a checkpoint
/// key/timestamp (`_key`, `key`, `timestamp`, `time`, `ts`)?
fn mentions_key_member(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if let ExprKind::Member { member, .. } = &sub.kind {
            let m = member.to_ascii_lowercase();
            if m == "_key" || m == "key" || m == "timestamp" || m == "time" || m == "ts" {
                found = true;
            }
        }
    });
    found
}

/// Does `name` appear as an identifier anywhere in `e`?
fn expr_mentions_ident(e: &Expr, name: &str) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if let ExprKind::Ident(n) = &sub.kind {
            if n == name {
                found = true;
            }
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
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "checkpoint-hint-trust")
    }

    // Symbiotic upperLookupRecent shape, STRIPPED of the bracketing re-check:
    // the caller-supplied `hint` indexes the checkpoint array via `at(self, hint)`
    // and the resolved value is returned directly — a wrong hint returns the wrong
    // checkpoint. No `checkpoint._key == key` guard anywhere.
    const VULN: &str = r#"
        library Checkpoints {
            struct Checkpoint208 { uint48 _key; uint208 _value; }
            struct Trace208 { Checkpoint208[] _checkpoints; }
            function at(Trace208 storage self, uint32 pos) internal view returns (Checkpoint208 memory) {
                return self._checkpoints[pos];
            }
            function upperLookupRecent(Trace208 storage self, uint48 key, uint32 hint) internal view returns (uint208) {
                Checkpoint208 memory checkpoint = at(self, hint);
                return checkpoint._value;
            }
        }
    "#;

    // Same keyed lookup but WITH the bracketing re-check, and reading the entry
    // INLINE (`self._checkpoints[hint]`) so the only candidate function is the
    // keyed lookup itself: the resolved entry's `_key` is compared against the
    // requested `key` before its value is trusted, and a verified search is the
    // fallback. The hint is validated -> no finding. (This is the safe shape of
    // the real Symbiotic `upperLookupRecent(self, key, hint_)`.)
    const SAFE_RECHECK: &str = r#"
        library Checkpoints {
            struct Checkpoint208 { uint48 _key; uint208 _value; }
            struct Trace208 { Checkpoint208[] _checkpoints; }
            function search(Trace208 storage self, uint48 key) internal view returns (uint208) {
                return self._checkpoints[0]._value;
            }
            function upperLookupRecent(Trace208 storage self, uint48 key, uint32 hint) internal view returns (uint208) {
                Checkpoint208 memory checkpoint = self._checkpoints[hint];
                if (checkpoint._key == key) {
                    return checkpoint._value;
                }
                if (checkpoint._key < key && (hint == self._checkpoints.length - 1 || self._checkpoints[hint + 1]._key > key)) {
                    return checkpoint._value;
                }
                return search(self, key);
            }
        }
    "#;

    // Ordinary getter that indexes an array by a caller-supplied position but the
    // parameter is not hint-like (`amount`) — and even if it were, it is the raw
    // user-facing accessor with no checkpoint/key semantics. The hint-name gate
    // keeps this quiet. (Here the param is named `amount`, not a hint token.)
    const SAFE_NOT_A_HINT: &str = r#"
        contract Store {
            uint256[] public items;
            function valueAt(uint256 amount) external view returns (uint256) {
                return items[amount];
            }
        }
    "#;

    // EigenLayer cert-verifier shape: a caller-supplied `operatorIndex` indexes a
    // NESTED MAPPING (`_operatorInfos[set][ts][index]`) and returns an
    // `OperatorInfo` struct — NOT a `Trace`/`Checkpoint` container, and the value
    // is not a checkpoint stake/share. The `Trace`-container anchor suppresses it
    // even though it has a `*Timestamp` "key" and an `*Index` "hint". (Real FP:
    // BN254CertificateVerifier.getNonsignerOperatorInfo / ECDSA.getOperatorInfo.)
    const SAFE_CERT_VERIFIER: &str = r#"
        contract BN254CertificateVerifier {
            struct OperatorInfo { uint256 weight; uint256 pubkeyX; }
            mapping(bytes32 => mapping(uint32 => mapping(uint256 => OperatorInfo))) internal _operatorInfos;
            function getNonsignerOperatorInfo(bytes32 operatorSetKey, uint32 referenceTimestamp, uint256 operatorIndex)
                external view returns (OperatorInfo memory)
            {
                return _operatorInfos[operatorSetKey][referenceTimestamp][operatorIndex];
            }
        }
    "#;

    // Pendle `VeHistoryLib.Checkpoints.get` shape: a by-position accessor that
    // RETURNS a `Checkpoint memory` from a `History` container indexed by `index`,
    // with no re-check. Structurally identical to Symbiotic `at`, BUT the container
    // is `History`, not a `Trace` — so the `Trace`-container anchor keeps it quiet.
    // (Real FP risk: pendle VeHistoryLib.sol `get`.)
    const SAFE_HISTORY_GET: &str = r#"
        library Checkpoints {
            struct Checkpoint { uint128 timestamp; uint256 value; }
            struct History { Checkpoint[] _checkpoints; }
            function get(History storage self, uint256 index) internal view returns (Checkpoint memory) {
                return self._checkpoints[index];
            }
        }
    "#;

    // Pendle Uniswap-style oracle ring buffer: `Observation[65535]` indexed by a
    // caller `index`, returning an `Observation` value. Not a `Trace`/`Checkpoint`
    // container -> suppressed. (Real FP: OracleLib.observeSingle / write.)
    const SAFE_OBSERVATION_RING: &str = r#"
        library OracleLib {
            struct Observation { uint32 blockTimestamp; uint216 cum; bool initialized; }
            function observeSingle(Observation[65535] storage self, uint32 time, uint16 index)
                public view returns (uint216)
            {
                Observation memory last = self[index];
                return last.cum;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn silent_with_key_recheck() {
        assert!(!fires(SAFE_RECHECK), "{:#?}", run(SAFE_RECHECK));
    }

    #[test]
    fn silent_when_param_not_a_hint() {
        assert!(!fires(SAFE_NOT_A_HINT), "{:#?}", run(SAFE_NOT_A_HINT));
    }

    #[test]
    fn silent_on_cert_verifier_mapping_index() {
        assert!(!fires(SAFE_CERT_VERIFIER), "{:#?}", run(SAFE_CERT_VERIFIER));
    }

    #[test]
    fn silent_on_non_trace_history_accessor() {
        assert!(!fires(SAFE_HISTORY_GET), "{:#?}", run(SAFE_HISTORY_GET));
    }

    #[test]
    fn silent_on_observation_ring_buffer() {
        assert!(!fires(SAFE_OBSERVATION_RING), "{:#?}", run(SAFE_OBSERVATION_RING));
    }
}
