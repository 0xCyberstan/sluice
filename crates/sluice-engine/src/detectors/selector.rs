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
use sluice_ir::{Builtin, CallKind, Expr, ExprKind, Function, Span};
use std::collections::HashMap;

pub struct SelectorCollisionDetector;

/// How a single `encodePacked` argument is classified for collision risk.
#[derive(PartialEq, Clone, Copy)]
enum ArgClass {
    /// Fixed-width / non-ambiguous (`uintN`, `intN`, `address`, `bool`,
    /// `bytes1..bytes32`, numeric/address literals). Cannot create an ambiguous
    /// byte boundary on its own.
    Fixed,
    /// Variable-length (`string`, `bytes`, `T[]`). Two of these adjacent in a
    /// packed buffer are the collision primitive.
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

                let classes: Vec<ArgClass> = c.args.iter().map(|a| classify_arg(a, &types)).collect();

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
fn classify_arg(arg: &Expr, types: &HashMap<String, String>) -> ArgClass {
    match &arg.kind {
        // Identifier: resolve its declared type (param or state var).
        ExprKind::Ident(name) => match types.get(name) {
            Some(ty) => classify_type(ty),
            None => ArgClass::Unknown,
        },
        // A string literal is variable-length; numeric/address/bytes literals are fixed.
        ExprKind::Lit(lit) => {
            use sluice_ir::Lit;
            match lit {
                Lit::String(_) => ArgClass::Dynamic,
                Lit::Number(_) | Lit::HexNumber(_) | Lit::Bool(_) | Lit::Address(_) | Lit::HexBytes(_) => {
                    ArgClass::Fixed
                }
                Lit::Other(_) => ArgClass::Unknown,
            }
        }
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
fn encode_packed_spans_feeding_hash(f: &Function) -> std::collections::HashSet<Span> {
    use std::collections::HashSet;
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
}
