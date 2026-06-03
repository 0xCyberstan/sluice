//! Selector / hash collision: `abi.encodePacked` with two or more dynamic
//! arguments. Packed encoding does not insert length prefixes or padding, so
//! adjacent dynamic values share an ambiguous byte boundary
//! (`encodePacked("a","bc") == encodePacked("ab","c")`). When the result feeds a
//! `keccak256` digest — a signature payload, a merkle leaf, or a mapping key —
//! distinct logical inputs collapse to the same hash. This is the Poly-Network /
//! signature-collision class.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::detectors::visit_calls;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Builtin, CallKind, Expr, ExprKind, Function, Lit, Span};
use std::collections::{HashMap, HashSet};

pub struct SelectorCollisionDetector;

/// How a single `encodePacked` argument is classified for collision risk.
#[derive(PartialEq, Clone, Copy)]
enum ArgClass {
    /// Fixed-width / non-ambiguous (`uintN`, `intN`, `address`, `bool`,
    /// `bytes1..bytes32`, numeric/address/string/bytes literals, and any
    /// `string`/`bytes`/array whose length is pinned by a preceding
    /// `require(x.length == K)`). Cannot create an ambiguous byte boundary on its
    /// own: its length is known at the call site.
    Fixed,
    /// Variable-length (`string`, `bytes`, `T[]`) whose length is *not* pinned.
    /// Two of these adjacent in a packed buffer are the collision primitive.
    Dynamic,
    /// Type could not be resolved (nested expression, external-call result,
    /// unresolved identifier). Treated as "non-fixed" but not proof of dynamism.
    Unknown,
}

impl Detector for SelectorCollisionDetector {
    fn id(&self) -> &'static str {
        "selector-collision"
    }
    fn category(&self) -> Category {
        Category::SelectorCollision
    }
    fn description(&self) -> &'static str {
        "abi.encodePacked with multiple dynamic args (hash/selector collision)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.functions() {
            if !f.has_body {
                continue;
            }

            // Resolve identifier name -> declared textual type for this function:
            // parameters first, then the contract's state variables. Used to tell
            // a dynamic `string`/`bytes`/array argument from a fixed-width one.
            let mut types: HashMap<String, String> = HashMap::new();
            if let Some(c) = cx.contract_of(f.id) {
                for v in &c.state_vars {
                    types.insert(v.name.clone(), v.ty.clone());
                }
            }
            for p in &f.params {
                if let Some(n) = &p.name {
                    types.insert(n.clone(), p.ty.clone());
                }
            }

            // Names whose dynamic length is pinned to a constant by a
            // `require(x.length == K)` (either argument order) somewhere in the
            // function. Once the length is fixed, the value can no longer slide
            // the packed boundary, so such operands are treated as fixed-width.
            // This is the SSZ / fixed-pubkey idiom
            // (`require(pubkey.length == 48); abi.encodePacked(pubkey, bytes16(0))`).
            let length_pinned = length_pinned_names(f);

            // First pass: spans of every `encodePacked` call that sits inside a
            // hashing / signature-building builtin's argument subtree, i.e. the
            // packed bytes flow into a digest/selector. Higher confidence there.
            let hashed = encode_packed_spans_feeding_hash(f);

            // Main pass: inspect each `encodePacked` call directly.
            visit_calls(f, |c, span| {
                if c.kind != CallKind::Builtin(Builtin::AbiEncodePacked) {
                    return;
                }
                if c.args.len() < 2 {
                    return; // single arg can't produce an ambiguous boundary
                }

                // Hard allowlist: the canonical EIP-712 digest preamble
                // `abi.encodePacked("\x19\x01", domainSeparator, structHash)`.
                // The leading `\x19\x01` is a fixed two-byte literal and the
                // following operands are `bytes32`s, so there is no ambiguous
                // boundary — this is a correct, ubiquitous construction, not a bug.
                if is_eip712_prefixed(&c.args) {
                    return;
                }

                let classes: Vec<ArgClass> = c
                    .args
                    .iter()
                    .map(|a| classify_arg(a, &types, &length_pinned))
                    .collect();

                let dynamic_typed = classes.iter().filter(|k| **k == ArgClass::Dynamic).count();
                // Two adjacent args that are both not provably fixed.
                let consecutive_nonfixed = classes
                    .windows(2)
                    .any(|w| w[0] != ArgClass::Fixed && w[1] != ArgClass::Fixed);

                // Fire when at least two args could be dynamic:
                //  - two resolved dynamic-typed args, or
                //  - one resolved dynamic arg sitting next to another non-fixed arg.
                // Pure-`Unknown` noise alone (and all-fixed) is suppressed.
                let fire = dynamic_typed >= 2 || (dynamic_typed >= 1 && consecutive_nonfixed);
                if !fire {
                    return;
                }

                let feeds_hash = hashed.contains(&span);
                // Honest heuristic confidence: type inference is best-effort, and
                // a real collision still requires a meaningful pair of inputs.
                // Bump (still modest) when the packed bytes reach a hash/selector.
                let confidence = if feeds_hash { 0.6 } else { 0.45 };

                let sink = if feeds_hash {
                    " and the result feeds a `keccak256` digest (signature payload, merkle leaf, or mapping key), \
                     so two distinct inputs can forge the same hash"
                } else {
                    ""
                };

                let b = FindingBuilder::new(self.id(), Category::SelectorCollision)
                    .title("abi.encodePacked with multiple dynamic arguments (hash collision)")
                    .severity(Severity::Medium)
                    .confidence(confidence)
                    // ValueFlow: the (potentially attacker-supplied) packed values
                    // flow into a hash/selector sink where the boundary ambiguity
                    // becomes exploitable. That is the value-flow evidence; no
                    // invariant or trust-frontier claim is made here.
                    .dimension(Dimension::ValueFlow)
                    .message(format!(
                        "`{}` calls `abi.encodePacked` with {} dynamic-length arguments{}. Packed encoding omits \
                         length prefixes, so adjacent dynamic values share an ambiguous boundary \
                         (`encodePacked(\"a\",\"bc\") == encodePacked(\"ab\",\"c\")`).",
                        f.name,
                        dynamic_typed.max(2),
                        sink
                    ))
                    .recommendation(
                        "Use `abi.encode` (length-prefixed) instead of `abi.encodePacked`, or place a fixed-width \
                         separator / length field between dynamic arguments, so distinct inputs cannot collide.",
                    );
                out.push(cx.finish(b, f.id, span));
            });
        }

        out
    }
}

/// Classify one `encodePacked` argument as fixed-width, dynamic-length, or unknown.
///
/// `length_pinned` carries identifier names whose dynamic length was fixed by a
/// `require(x.length == K)` guard; such operands are demoted to [`ArgClass::Fixed`]
/// because their byte width is constant at the call site.
fn classify_arg(arg: &Expr, types: &HashMap<String, String>, length_pinned: &HashSet<String>) -> ArgClass {
    match &arg.kind {
        // Identifier: resolve its declared type (param or state var). A
        // dynamic-typed identifier whose length is pinned by a preceding
        // `require(name.length == K)` packs at a constant width, so it cannot
        // create an ambiguous boundary — treat it as fixed.
        ExprKind::Ident(name) => match types.get(name) {
            Some(ty) => {
                let class = classify_type(ty);
                if class == ArgClass::Dynamic && length_pinned.contains(name) {
                    ArgClass::Fixed
                } else {
                    class
                }
            }
            None => ArgClass::Unknown,
        },
        // Literals are fixed: a string/byte *literal* (e.g. the EIP-712
        // `"\x19\x01"` prefix, or a constant domain tag) has a known, constant
        // length and content. The collision primitive requires two *variable*
        // operands sharing a boundary; a constant cannot slide that boundary.
        ExprKind::Lit(lit) => match lit {
            Lit::String(_)
            | Lit::Number(_)
            | Lit::HexNumber(_)
            | Lit::Bool(_)
            | Lit::Address(_)
            | Lit::HexBytes(_) => ArgClass::Fixed,
            Lit::Other(_) => ArgClass::Unknown,
        },
        // A cast such as `uint256(x)`, `address(x)`, `bytes32(x)` yields a fixed
        // width; `bytes(x)` / `string(x)` are dynamic.
        ExprKind::Call(c) if c.kind == CallKind::TypeCast => c
            .func_name
            .as_deref()
            .map(classify_type)
            .unwrap_or(ArgClass::Unknown),
        // Anything else (member access, external call result, arithmetic, ...) is
        // not provably fixed, but not proof of dynamism either.
        _ => ArgClass::Unknown,
    }
}

/// True when `args` begin with the canonical EIP-712 byte preamble: either a
/// single `"\x19\x01"` literal, or the two adjacent literals `"\x19"` then
/// `"\x01"`. `solang-parser` keeps string-literal bodies as the raw,
/// still-escaped source slice, so the stored content is the textual
/// `\x19\x01` / `\x19` / `\x01`.
fn is_eip712_prefixed(args: &[Expr]) -> bool {
    let lit = |e: &Expr| -> Option<String> {
        match &e.kind {
            ExprKind::Lit(Lit::String(s)) => Some(s.clone()),
            _ => None,
        }
    };
    // Normalize a literal body to its EIP-712 prefix shape, tolerating the few
    // equivalent spellings of the same two bytes (`\x19\x01`, `\x19\u{01}`).
    let norm = |s: &str| -> String { s.replace("\\u{01}", "\\x01").replace("\\u{19}", "\\x19") };

    if let Some(first) = args.first().and_then(&lit) {
        let f = norm(&first);
        if f.starts_with("\\x19\\x01") {
            return true;
        }
        // Split spelling: `abi.encodePacked("\x19", "\x01", ...)`.
        if f == "\\x19" {
            if let Some(second) = args.get(1).and_then(&lit) {
                if norm(&second).starts_with("\\x01") {
                    return true;
                }
            }
        }
    }
    false
}

/// Collect identifier names pinned to a constant length by a
/// `require(name.length == K)` (or `require(K == name.length)`) call anywhere in
/// the function body. Such names pack at a fixed byte width regardless of the
/// caller's input, so they are not a collision boundary.
fn length_pinned_names(f: &Function) -> HashSet<String> {
    let mut pinned = HashSet::new();
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            let ExprKind::Call(c) = &e.kind else { return };
            if c.kind != CallKind::Builtin(Builtin::Require) && c.kind != CallKind::Builtin(Builtin::Assert) {
                return;
            }
            // The condition is the first argument; scan it (and any `&&`-joined
            // sub-conditions, reached by the recursive `visit`) for a
            // `<x>.length == <number>` equality.
            if let Some(cond) = c.args.first() {
                cond.visit(&mut |inner: &Expr| {
                    if let ExprKind::Binary { op: BinOp::Eq, lhs, rhs } = &inner.kind {
                        if let Some(name) = length_eq_name(lhs, rhs).or_else(|| length_eq_name(rhs, lhs)) {
                            pinned.insert(name);
                        }
                    }
                });
            }
        });
    }
    pinned
}

/// If `len_side` is `<name>.length` and `k_side` is a numeric literal, return
/// the pinned identifier name.
fn length_eq_name(len_side: &Expr, k_side: &Expr) -> Option<String> {
    // `k_side` must be a compile-time numeric constant.
    let k_is_const = matches!(&k_side.kind, ExprKind::Lit(Lit::Number(_) | Lit::HexNumber(_)));
    if !k_is_const {
        return None;
    }
    if let ExprKind::Member { base, member } = &len_side.kind {
        if member == "length" {
            if let ExprKind::Ident(name) = &base.kind {
                return Some(name.clone());
            }
        }
    }
    None
}

/// Map a textual Solidity type to its packing class.
fn classify_type(ty: &str) -> ArgClass {
    // Strip storage location / leading qualifiers and array suffixes for the base.
    let t = ty.trim();
    let base = t.split_whitespace().next().unwrap_or(t).trim();

    // Any array (`T[]`, `T[3]`, `uint256[] memory`) packs its elements without a
    // length prefix → dynamic boundary risk.
    if base.contains("[]") || t.contains("[]") {
        return ArgClass::Dynamic;
    }
    if base == "string" || base == "bytes" {
        return ArgClass::Dynamic;
    }
    // Fixed-width value types, including `bytes1`..`bytes32`.
    if base == "address"
        || base == "bool"
        || base.starts_with("uint")
        || base.starts_with("int")
        || is_fixed_bytes(base)
    {
        return ArgClass::Fixed;
    }
    // Mappings can't be encodePacked; structs/contracts/enums are atypical here.
    ArgClass::Unknown
}

/// `bytes1`..`bytes32` (fixed), but not the dynamic `bytes`.
fn is_fixed_bytes(base: &str) -> bool {
    match base.strip_prefix("bytes") {
        Some(n) if !n.is_empty() => n.parse::<u32>().map(|k| (1..=32).contains(&k)).unwrap_or(false),
        _ => false,
    }
}

/// Collect the spans of every `abi.encodePacked` call that appears inside the
/// argument subtree of a hashing / signature-building builtin (`keccak256`,
/// `sha256`, `abi.encodeWithSignature/Selector`). These are the high-signal
/// cases where the packed bytes become a digest, merkle leaf, or selector.
fn encode_packed_spans_feeding_hash(f: &Function) -> HashSet<Span> {
    let mut spans = HashSet::new();
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            if let ExprKind::Call(c) = &e.kind {
                let is_hash_sink = matches!(
                    c.kind,
                    CallKind::Builtin(Builtin::Keccak256)
                        | CallKind::Builtin(Builtin::Sha256)
                        | CallKind::Builtin(Builtin::AbiEncodeWithSignature)
                        | CallKind::Builtin(Builtin::AbiEncodeWithSelector)
                );
                if is_hash_sink {
                    for a in &c.args {
                        a.visit(&mut |inner: &Expr| {
                            if let ExprKind::Call(ic) = &inner.kind {
                                if ic.kind == CallKind::Builtin(Builtin::AbiEncodePacked) {
                                    spans.insert(inner.span);
                                }
                            }
                        });
                    }
                }
            }
        });
    }
    spans
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Two dynamic arguments (string + string) packed and hashed into a signature
    // digest — the classic ambiguous-boundary collision.
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        contract Sig {
            function digest(string memory a, string memory b) public pure returns (bytes32) {
                return keccak256(abi.encodePacked(a, b));
            }
        }
    "#;

    // Length-prefixed `abi.encode` (no packing) and a packed call with only a
    // single dynamic arg beside fixed-width values — both safe.
    const SAFE: &str = r#"
        pragma solidity ^0.8.20;
        contract Sig {
            function digest(string memory a, string memory b) public pure returns (bytes32) {
                return keccak256(abi.encode(a, b));
            }
            function leaf(address user, uint256 amount, string memory note) public pure returns (bytes32) {
                return keccak256(abi.encodePacked(user, amount, note));
            }
        }
    "#;

    // Canonical EIP-712 digest: `keccak256("\x19\x01" ++ domainSeparator ++
    // structHash)`. The `\x19\x01` prefix is a fixed two-byte literal and the
    // following operands are `bytes32`s, so there is no ambiguous boundary. This
    // is the F-011 / F-021 dogfood false positive — it must stay silent.
    const EIP712_DIGEST: &str = r#"
        pragma solidity ^0.8.20;
        contract Verifier {
            function hashTypedData(bytes32 sep, bytes32 structHash) public pure returns (bytes32) {
                return keccak256(abi.encodePacked("\x19\x01", sep, structHash));
            }
        }
    "#;

    // Same EIP-712 preamble, but split across two adjacent string literals
    // `"\x19"` then `"\x01"`. Still the canonical construction — must stay silent.
    const EIP712_SPLIT_PREFIX: &str = r#"
        pragma solidity ^0.8.20;
        contract Verifier {
            function hashTypedData(bytes32 sep, bytes32 structHash) public pure returns (bytes32) {
                return keccak256(abi.encodePacked("\x19", "\x01", sep, structHash));
            }
        }
    "#;

    // SSZ-style fixed-width hashing: a `bytes` pubkey whose length is pinned to a
    // constant by a preceding `require(pubkey.length == 48)`, packed beside a
    // fixed `bytes16(0)` pad. With the length pinned the value packs at a constant
    // width, so there is no ambiguous boundary. This is the F-012 dogfood false
    // positive — it must stay silent.
    const SSZ_PINNED_LENGTH: &str = r#"
        pragma solidity ^0.8.20;
        contract Deposit {
            function pubkeyRoot(bytes calldata pubkey) external pure returns (bytes32) {
                require(pubkey.length == 48, "bad pubkey");
                return sha256(abi.encodePacked(pubkey, bytes16(0)));
            }
        }
    "#;

    // Two *unpinned* dynamic `bytes` parameters packed together — a genuine
    // ambiguous boundary. The length pin / EIP-712 softening must NOT silence
    // this real collision.
    const TWO_UNPINNED_BYTES: &str = r#"
        pragma solidity ^0.8.20;
        contract Bad {
            function id(bytes calldata a, bytes calldata b) external pure returns (bytes32) {
                return keccak256(abi.encodePacked(a, b));
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "selector-collision"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "selector-collision"));
    }

    // Regression (F-011 / F-021): the canonical EIP-712 `\x19\x01` digest is a
    // correct construction and must not be flagged.
    #[test]
    fn silent_on_eip712_digest() {
        let fs = run(EIP712_DIGEST);
        assert!(!fs.iter().any(|f| f.detector == "selector-collision"), "{:?}", fs);
    }

    // Regression: the split `"\x19"`,`"\x01"` spelling of the same preamble is
    // likewise allow-listed.
    #[test]
    fn silent_on_eip712_split_prefix() {
        let fs = run(EIP712_SPLIT_PREFIX);
        assert!(!fs.iter().any(|f| f.detector == "selector-collision"), "{:?}", fs);
    }

    // Regression (F-012): a length-pinned `bytes` packs at a constant width, so
    // `abi.encodePacked(pubkey, bytes16(0))` after `require(pubkey.length == 48)`
    // has no ambiguous boundary.
    #[test]
    fn silent_on_ssz_pinned_length() {
        let fs = run(SSZ_PINNED_LENGTH);
        assert!(!fs.iter().any(|f| f.detector == "selector-collision"), "{:?}", fs);
    }

    // Positive: two unpinned dynamic `bytes` params still collide and must fire,
    // proving the softenings did not silence a real bug.
    #[test]
    fn fires_on_two_unpinned_bytes() {
        let fs = run(TWO_UNPINNED_BYTES);
        assert!(fs.iter().any(|f| f.detector == "selector-collision"), "{:?}", fs);
    }
}
