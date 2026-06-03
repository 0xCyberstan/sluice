//! Hash-id collision via `abi.encodePacked` with adjacent dynamic arguments
//! (SWC-133).
//!
//! `abi.encodePacked` concatenates its operands with **no length prefixes and no
//! padding**. When two *variable-length* operands (`string` / `bytes` /
//! dynamic array) sit **next to each other** in the packed buffer, the byte
//! boundary between them is ambiguous: moving a character from the end of the
//! first into the start of the second yields the identical byte string —
//! `encodePacked("a","bc") == encodePacked("ab","c")`. If those packed bytes are
//! then fed to a hash that is used as an **identity** — a `keccak256`/`sha256`
//! merkle leaf, a signature digest, or a mapping/id key — two logically distinct
//! inputs collapse to the same hash, which lets one input impersonate another
//! (the Poly-Network / signature-collision class).
//!
//! This is a deliberately narrow, lint-style (SWC-133) detector. It fires only
//! on the *hash-id* shape:
//!
//! * the packed result flows into a `keccak256` / `sha256` argument subtree, and
//! * the packed call has **two or more ADJACENT dynamic-typed operands**.
//!
//! ## Why "adjacent" and not just "two dynamic somewhere"
//!
//! The collision primitive is purely about a *shared boundary between two
//! variable operands*. A fixed-width operand placed between two dynamic ones
//! (`encodePacked(a, uint256(i), b)` / a constant separator) pins the boundary —
//! the bytes of `a` can no longer slide into `b` because the fixed field sits in
//! the way. So the detector keys off *adjacency*: a `windows(2)` pass that finds
//! two consecutive operands both proven dynamic. One dynamic operand, all-fixed
//! operands, or dynamic operands kept apart by a fixed-width delimiter are all
//! suppressed — those are the documented safe constructions for this class.
//!
//! ## Relationship to `selector-collision`
//!
//! `selector-collision` (`Category::SelectorCollision`, ValueFlow, Medium) covers
//! the broader "two not-provably-fixed operands packed, with the EIP-712
//! allow-list" angle and fires whether or not the bytes reach a hash. This
//! detector is the tighter SWC-133 lint: it demands **proven-dynamic adjacency**
//! *and* a hash-id sink, ships Low severity on the Invariant dimension (the
//! broken assumption is "this hash uniquely identifies its inputs"), and stays
//! silent on the fixed-width-separated and length-pinned safe forms.

use super::prelude::*;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Builtin, CallKind, Expr, ExprKind, Function, Lit};
use std::collections::{HashMap, HashSet};

pub struct EncodePackedCollisionDetector;

/// Packing class of a single `encodePacked` operand.
#[derive(PartialEq, Clone, Copy)]
enum ArgClass {
    /// Fixed-width / non-ambiguous (`uintN`, `intN`, `address`, `bool`,
    /// `bytes1..bytes32`, any literal, or a dynamic operand whose length is
    /// pinned by a preceding `require(x.length == K)`). Cannot slide a boundary.
    Fixed,
    /// Provably variable-length (`string` / `bytes` / `T[]`) and not length-pinned.
    /// Two of these *adjacent* are the collision primitive.
    Dynamic,
    /// Type could not be resolved. Not proof of dynamism — treated as not-Dynamic
    /// so it never *creates* an adjacency on its own (precision over recall).
    Unknown,
}

impl Detector for EncodePackedCollisionDetector {
    fn id(&self) -> &'static str {
        "encodepacked-collision"
    }
    fn category(&self) -> Category {
        Category::EncodePackedCollision
    }
    fn description(&self) -> &'static str {
        "abi.encodePacked with >=2 adjacent dynamic args feeding a keccak256/sha256 id, leaf, or digest (SWC-133)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.functions() {
            if !f.has_body {
                continue;
            }

            // Resolve identifier -> declared textual type for this function:
            // parameters first (caller-supplied), then the contract's state
            // variables. Used to tell a dynamic `string`/`bytes`/array operand
            // from a fixed-width one.
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
            // `require(x.length == K)` guard — those pack at a fixed width, so
            // they can no longer slide a boundary (the SSZ / fixed-pubkey idiom).
            let length_pinned = length_pinned_names(f);

            // The only sink we care about: an `abi.encodePacked` call sitting
            // inside the argument subtree of a `keccak256`/`sha256` hash. That is
            // the "result feeds a hash used as an id / merkle leaf / digest" shape.
            for (packed, span) in encode_packed_calls_feeding_hash(f) {
                if packed.args.len() < 2 {
                    continue; // a single operand has no internal boundary
                }

                let classes: Vec<ArgClass> = packed
                    .args
                    .iter()
                    .map(|a| classify_arg(a, &types, &length_pinned))
                    .collect();

                // The SWC-133 primitive: two *adjacent* operands, BOTH proven
                // dynamic. A fixed-width operand between two dynamic ones breaks
                // the adjacency (pins the boundary) and is correctly suppressed.
                let adjacent_dynamic =
                    classes.windows(2).any(|w| w[0] == ArgClass::Dynamic && w[1] == ArgClass::Dynamic);
                if !adjacent_dynamic {
                    continue;
                }

                let dynamic_count = classes.iter().filter(|k| **k == ArgClass::Dynamic).count();

                let b = report!(self, Category::EncodePackedCollision,
                    title = "abi.encodePacked with adjacent dynamic arguments feeds a hash used as an id",
                    severity = Severity::Low,
                    confidence = 0.5,
                    // Invariant: the broken assumption is that this `keccak256`/
                    // `sha256` value *uniquely identifies* its inputs. Adjacent
                    // packed dynamic operands violate that — distinct inputs map
                    // to one digest, so an id / merkle leaf / signature can be
                    // forged. (selector-collision carries the ValueFlow angle.)
                    dimensions = [Dimension::Invariant],
                    message = format!(
                        "`{}` hashes `abi.encodePacked(...)` containing {} adjacent dynamic-length arguments \
                         (string/bytes/dynamic array). Packed encoding omits length prefixes, so the boundary \
                         between two adjacent dynamic operands is ambiguous \
                         (`encodePacked(\"a\",\"bc\") == encodePacked(\"ab\",\"c\")`). Because the result is used \
                         as an id / merkle leaf / signature digest, two distinct inputs collapse to the same hash \
                         and one can impersonate the other (SWC-133).",
                        f.name, dynamic_count,
                    ),
                    recommendation =
                        "Hash with `abi.encode` (length-prefixed) instead of `abi.encodePacked`, or place a \
                         fixed-width separator / length field between the dynamic arguments so distinct inputs \
                         cannot produce the same packed bytes.",
                );
                out.push(finish_at(cx, b, f.id, span));
            }
        }

        out
    }
}

/// Classify one `encodePacked` operand as fixed-width, dynamic-length, or unknown.
///
/// `length_pinned` carries identifier names whose dynamic length was fixed by a
/// `require(x.length == K)` guard; such operands are demoted to [`ArgClass::Fixed`]
/// because their byte width is constant at the call site.
fn classify_arg(arg: &Expr, types: &HashMap<String, String>, length_pinned: &HashSet<String>) -> ArgClass {
    match &arg.kind {
        // Identifier: resolve its declared type (param or state var). A
        // dynamic-typed identifier whose length is pinned by a preceding
        // `require(name.length == K)` packs at a constant width → fixed.
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
        // Literals have a known, constant length and content (a string/byte
        // literal cannot slide a boundary), so they are fixed.
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
        ExprKind::Call(c) if c.kind == CallKind::TypeCast => {
            c.func_name.as_deref().map(classify_type).unwrap_or(ArgClass::Unknown)
        }
        // Member access, external-call result, arithmetic, … — not provably
        // fixed, but not proof of dynamism either.
        _ => ArgClass::Unknown,
    }
}

/// Map a textual Solidity type to its packing class.
fn classify_type(ty: &str) -> ArgClass {
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

/// Identifier names pinned to a constant length by a `require(name.length == K)`
/// (or `require(K == name.length)`) anywhere in the body. Such names pack at a
/// fixed byte width regardless of the caller's input, so they are not a boundary.
fn length_pinned_names(f: &Function) -> HashSet<String> {
    let mut pinned = HashSet::new();
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            let ExprKind::Call(c) = &e.kind else { return };
            if !is_require_or_assert(c) {
                return;
            }
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

/// If `len_side` is `<name>.length` and `k_side` is a numeric literal, return the
/// pinned identifier name.
fn length_eq_name(len_side: &Expr, k_side: &Expr) -> Option<String> {
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

/// Every `abi.encodePacked` call that appears inside the argument subtree of a
/// `keccak256` / `sha256` builtin, paired with the packed call's span. These are
/// the hash-id sinks: the packed bytes become a digest, merkle leaf, or id key.
/// Returns each inner `Call` so the caller can classify its operands.
fn encode_packed_calls_feeding_hash(f: &Function) -> Vec<(&sluice_ir::Call, sluice_ir::Span)> {
    let mut out: Vec<(&sluice_ir::Call, sluice_ir::Span)> = Vec::new();
    let mut seen: HashSet<sluice_ir::Span> = HashSet::new();
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            let ExprKind::Call(c) = &e.kind else { return };
            // Only keccak256/sha256 — the hashes used as on-chain identities. (The
            // selector-collision detector covers the abi.encodeWithSignature/
            // Selector preimage angle; this one is the keccak/sha id/leaf/digest.)
            if !matches!(c.kind, CallKind::Builtin(Builtin::Keccak256) | CallKind::Builtin(Builtin::Sha256)) {
                return;
            }
            for a in &c.args {
                a.visit(&mut |inner: &Expr| {
                    if let ExprKind::Call(ic) = &inner.kind {
                        if ic.kind == CallKind::Builtin(Builtin::AbiEncodePacked) && seen.insert(inner.span) {
                            out.push((ic, inner.span));
                        }
                    }
                });
            }
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fired(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.detector == "encodepacked-collision")
    }

    // FIRES: two adjacent dynamic `string` operands packed and hashed into a
    // keccak256 id — the canonical SWC-133 ambiguous-boundary collision.
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        contract Sig {
            function id(string memory a, string memory b) public pure returns (bytes32) {
                return keccak256(abi.encodePacked(a, b));
            }
        }
    "#;

    // FIRES: two adjacent dynamic `bytes` operands hashed with sha256 (merkle
    // leaf shape).
    const VULN_BYTES_SHA: &str = r#"
        pragma solidity ^0.8.20;
        contract Leaf {
            function leaf(bytes calldata a, bytes calldata b) external pure returns (bytes32) {
                return sha256(abi.encodePacked(a, b));
            }
        }
    "#;

    // FIRES: a dynamic array adjacent to a string, hashed.
    const VULN_ARRAY: &str = r#"
        pragma solidity ^0.8.20;
        contract Arr {
            function key(uint256[] memory xs, string memory tag) public pure returns (bytes32) {
                return keccak256(abi.encodePacked(xs, tag));
            }
        }
    "#;

    // SILENT (safe form 1): only ONE dynamic operand beside fixed-width values —
    // no adjacent-dynamic boundary.
    const SAFE_ONE_DYNAMIC: &str = r#"
        pragma solidity ^0.8.20;
        contract Ok {
            function leaf(address user, uint256 amount, string memory note) public pure returns (bytes32) {
                return keccak256(abi.encodePacked(user, amount, note));
            }
        }
    "#;

    // SILENT (safe form 2): two dynamic operands SEPARATED by a fixed-width
    // delimiter (`uint256(i)`). The fixed field pins the boundary, so distinct
    // inputs cannot collide — the documented mitigation.
    const SAFE_SEPARATED: &str = r#"
        pragma solidity ^0.8.20;
        contract Ok {
            function id(string memory a, uint256 sep, string memory b) public pure returns (bytes32) {
                return keccak256(abi.encodePacked(a, sep, b));
            }
        }
    "#;

    // SILENT (safe form 3): all operands fixed-width — no dynamic boundary at all.
    const SAFE_ALL_FIXED: &str = r#"
        pragma solidity ^0.8.20;
        contract Ok {
            function id(address a, uint256 b, bytes32 c) public pure returns (bytes32) {
                return keccak256(abi.encodePacked(a, b, c));
            }
        }
    "#;

    // SILENT (safe form 4): two dynamic operands packed but NOT fed to a hash —
    // out of this detector's hash-id scope.
    const SAFE_NO_HASH: &str = r#"
        pragma solidity ^0.8.20;
        contract Ok {
            function pack(string memory a, string memory b) public pure returns (bytes memory) {
                return abi.encodePacked(a, b);
            }
        }
    "#;

    // SILENT (safe form 5): length-pinned `bytes` packs at a constant width after
    // `require(pubkey.length == 48)`, so `abi.encodePacked(pubkey, sig)` beside a
    // pinned operand has no ambiguous boundary (SSZ idiom). Here both operands are
    // pinned to constant lengths.
    const SAFE_PINNED: &str = r#"
        pragma solidity ^0.8.20;
        contract Deposit {
            function root(bytes calldata pubkey, bytes calldata sig) external pure returns (bytes32) {
                require(pubkey.length == 48, "bad pubkey");
                require(sig.length == 96, "bad sig");
                return sha256(abi.encodePacked(pubkey, sig));
            }
        }
    "#;

    // SILENT (safe form 6): length-prefixed `abi.encode` (not packed) — never a
    // boundary collision regardless of dynamic args.
    const SAFE_ENCODE: &str = r#"
        pragma solidity ^0.8.20;
        contract Ok {
            function id(string memory a, string memory b) public pure returns (bytes32) {
                return keccak256(abi.encode(a, b));
            }
        }
    "#;

    #[test]
    fn fires_on_two_dynamic_strings() {
        assert!(fired(&run(VULN)));
    }

    #[test]
    fn fires_on_two_dynamic_bytes_sha256() {
        assert!(fired(&run(VULN_BYTES_SHA)));
    }

    #[test]
    fn fires_on_dynamic_array_plus_string() {
        assert!(fired(&run(VULN_ARRAY)));
    }

    #[test]
    fn silent_on_single_dynamic() {
        assert!(!fired(&run(SAFE_ONE_DYNAMIC)));
    }

    // The headline safe form: dynamic args separated by a fixed-width delimiter.
    #[test]
    fn silent_on_fixed_separated() {
        let fs = run(SAFE_SEPARATED);
        assert!(!fired(&fs), "{:?}", fs);
    }

    #[test]
    fn silent_on_all_fixed() {
        assert!(!fired(&run(SAFE_ALL_FIXED)));
    }

    #[test]
    fn silent_when_not_hashed() {
        assert!(!fired(&run(SAFE_NO_HASH)));
    }

    #[test]
    fn silent_on_length_pinned() {
        let fs = run(SAFE_PINNED);
        assert!(!fired(&fs), "{:?}", fs);
    }

    #[test]
    fn silent_on_abi_encode() {
        assert!(!fired(&run(SAFE_ENCODE)));
    }

    // The Low-severity lint must score into the Low/Info band, not higher.
    #[test]
    fn severity_is_low_or_info() {
        let fs = run(VULN);
        let f = fs.iter().find(|f| f.detector == "encodepacked-collision").expect("fired");
        assert!(
            matches!(f.severity, sluice_findings::Severity::Low | sluice_findings::Severity::Info),
            "expected Low/Info, got {:?}",
            f.severity
        );
    }
}
