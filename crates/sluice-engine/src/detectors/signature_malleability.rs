//! ECDSA signature malleability (EIP-2): a raw `ecrecover` call used as a
//! verification entry point *without* enforcing the low-`s` / canonical-`v`
//! constraint.
//!
//! ECDSA signatures are malleable: for a valid signature `(r, s, v)`, the
//! complementary signature `(r, n - s, v')` (with `n` the secp256k1 group
//! order and `v'` the flipped recovery id) recovers the *same* signer. So any
//! contract that treats a raw `(r,s,v)` signature — or its hash — as a unique
//! identifier (e.g. to dedupe, mark a signature as "used", or replay-guard by
//! signature rather than by digest/nonce) can be defeated: an attacker submits
//! the second, equally-valid representation and bypasses the dedupe.
//!
//! EIP-2 fixes this by requiring `s <= secp256k1n/2` (the "low-s" form) and
//! `v in {27, 28}`. OpenZeppelin's `ECDSA.recover` enforces both (and reverts
//! on `address(0)`), so contracts that route through it are safe.
//!
//! This detector flags an externally-reachable, state-mutating function whose
//! source calls `ecrecover` but shows **no** malleability protection: no
//! comparison of `s` against the secp256k1 half-order constant
//! (`0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0`), no
//! `"malleab"` / `"low-s"` mention, no `>`/`require` bound on `s`, and it is not
//! using OpenZeppelin ECDSA (`.recover(` / `using ECDSA for`). Libraries named
//! `ECDSA` (the canonical implementation themselves) are exempt.
//!
//! Heuristic by nature (we read source text for the guard, like the sibling
//! `signature` detector): confidence is held at 0.5.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};

pub struct SignatureMalleabilityDetector;

/// The secp256k1 half-order (`n/2`) — the EIP-2 low-`s` upper bound. Solidity
/// source that enforces low-`s` compares `s` against this exact constant.
/// Lowercased so a `to_ascii_lowercase()` source substring check matches any
/// hex casing.
const SECP256K1_HALF_ORDER: &str =
    "0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0";

impl Detector for SignatureMalleabilityDetector {
    fn id(&self) -> &'static str {
        "signature-malleability"
    }
    fn category(&self) -> Category {
        Category::SignatureMalleability
    }
    fn description(&self) -> &'static str {
        "Raw ecrecover used without EIP-2 low-s / canonical-v malleability protection"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        // Only verification *entry points*: externally-reachable, state-mutating
        // functions with a body. A pure recovery helper or a view check is not
        // where the dedupe/replay decision is settled.
        for f in cx.entry_points() {
            // The canonical `ECDSA` library is the fix, not a finding — never
            // flag the library that implements `recover` itself.
            if cx
                .contract_of(f.id)
                .map(|c| c.is_library() && c.name.to_ascii_lowercase().contains("ecdsa"))
                .unwrap_or(false)
            {
                continue;
            }

            let src = cx.source_text(f.span);
            if !src.contains("ecrecover") {
                continue;
            }

            // ---- false-positive suppression (precision first) ----

            // (a) OpenZeppelin ECDSA: `.recover(...)` reverts on bad sigs and
            //     rejects high-`s`, or a `using ECDSA for` / `using ECDSA`
            //     directive binds it.
            let uses_oz_ecdsa = src.contains(".recover(")
                || src.contains("using ecdsa")
                || cx
                    .contract_of(f.id)
                    .map(|c| c.uses_library_like("ecdsa"))
                    .unwrap_or(false);
            if uses_oz_ecdsa {
                continue;
            }

            // (b) Explicit low-`s` enforcement: the half-order constant appears,
            //     or the source mentions malleability / low-s, or there is an
            //     upper-bound (`>`) comparison / a `require` on the `s` value.
            if enforces_low_s(&src) {
                continue;
            }

            let b = FindingBuilder::new(self.id(), Category::SignatureMalleability)
                .title("ecrecover without EIP-2 low-s / canonical-v check (malleable signature)")
                .severity(Severity::Medium)
                // Heuristic: a source-text guard scan, not a proven dataflow fact.
                .confidence(0.5)
                // Value-flow: an attacker-supplied (r,s,v) reaches a verification
                // sink whose malleable second form is accepted as equally valid.
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` recovers a signer with raw `ecrecover` but never enforces the EIP-2 low-`s` \
                     bound (`s <= secp256k1n/2`) or `v in {{27,28}}`. ECDSA signatures are malleable: \
                     `(r, s, v)` and `(r, n - s, v')` recover the SAME signer, so a contract that \
                     dedupes/replay-guards by signature (or treats the signature as a unique id) can be \
                     bypassed by submitting the complementary signature. (SWC-117 / SWC-121, CWE-347.)",
                    f.name
                ))
                .recommendation(
                    "Use OpenZeppelin `ECDSA.recover` (enforces low-`s`, canonical `v`, and rejects \
                     `address(0)`), or `require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)` \
                     and `require(v == 27 || v == 28)` before/after `ecrecover`. Replay-guard by the \
                     signed digest or a nonce, never by the raw signature.",
                );
            out.push(cx.finish(b, f.id, f.span));
        }
        out
    }
}

/// True if the (already-lowercased) function source shows EIP-2 low-`s`
/// protection. Conservative — any plausible signal suppresses the finding.
fn enforces_low_s(src: &str) -> bool {
    // The exact half-order upper bound (the standard low-s check).
    if src.contains(SECP256K1_HALF_ORDER) {
        return true;
    }
    // An explicit malleability / low-s mention (a comment or a helper name).
    if src.contains("malleab") || src.contains("low-s") || src.contains("lows") {
        return true;
    }
    // A bound on the `s` value: an upper-bound comparison (`s >`, `> s`) or a
    // `require`/`if` that constrains `s`. We look for `s` as a delimited token
    // adjacent to a `>` to avoid matching unrelated identifiers.
    s_is_bounded(src)
}

/// Heuristic: the source contains a `>` comparison whose operand token is `s`
/// (the signature scalar), i.e. an `s > ...` / `... > s` low-`s` bound.
fn s_is_bounded(src: &str) -> bool {
    // Scan for `>` and inspect the adjacent non-space token on each side for a
    // standalone `s` (or `uint256(s)`-style cast).
    let bytes = src.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        if c != b'>' {
            continue;
        }
        // `>>` (shift) is not a comparison.
        if bytes.get(i + 1) == Some(&b'>') || (i > 0 && bytes[i - 1] == b'>') {
            continue;
        }
        // `>=` still a valid ordering bound on s, keep it.
        let lhs = token_before(src, i);
        let rhs = token_after(src, i);
        if is_s_token(&lhs) || is_s_token(&rhs) {
            return true;
        }
    }
    false
}

/// The identifier token immediately to the left of byte index `i` (skipping a
/// `>=`'s `=` is not needed here since we read left of `>`). Skips whitespace.
fn token_before(src: &str, i: usize) -> String {
    let bytes = src.as_bytes();
    let mut j = i;
    while j > 0 && bytes[j - 1].is_ascii_whitespace() {
        j -= 1;
    }
    let end = j;
    while j > 0 && is_ident_byte(bytes[j - 1]) {
        j -= 1;
    }
    src[j..end].to_string()
}

/// The identifier token immediately to the right of byte index `i`. Skips a
/// leading `=` (for `>=`) and whitespace.
fn token_after(src: &str, i: usize) -> String {
    let bytes = src.as_bytes();
    let mut j = i + 1;
    if bytes.get(j) == Some(&b'=') {
        j += 1;
    }
    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    let start = j;
    while j < bytes.len() && is_ident_byte(bytes[j]) {
        j += 1;
    }
    src[start..j].to_string()
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The token denotes the signature scalar `s` — either bare `s` or a cast like
/// `uint256(s)` reduces (via tokenization) to a trailing `s`. We accept exactly
/// `s` so unrelated names (`status`, `shares`) don't match.
fn is_s_token(tok: &str) -> bool {
    tok == "s"
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Raw ecrecover used to authorize a withdrawal, with the signature hash used
    // as a replay-dedupe key and NO low-s / v check — classic malleability.
    const VULN: &str = r#"
pragma solidity ^0.8.20;
contract Claim {
    address public signer;
    mapping(bytes32 => bool) public usedSig;
    function claim(bytes32 hash, uint8 v, bytes32 r, bytes32 s, address to, uint256 amt) external {
        bytes32 sigId = keccak256(abi.encodePacked(r, s, v));
        require(!usedSig[sigId], "replayed");
        usedSig[sigId] = true;
        address recovered = ecrecover(hash, v, r, s);
        require(recovered == signer, "bad sig");
        payable(to).transfer(amt);
    }
}
"#;

    // Same shape but enforces EIP-2 low-s and canonical v before recovery — safe.
    const SAFE: &str = r#"
pragma solidity ^0.8.20;
contract Claim {
    address public signer;
    mapping(bytes32 => bool) public usedSig;
    function claim(bytes32 hash, uint8 v, bytes32 r, bytes32 s, address to, uint256 amt) external {
        require(
            uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "malleable s"
        );
        require(v == 27 || v == 28, "bad v");
        bytes32 sigId = keccak256(abi.encodePacked(r, s, v));
        require(!usedSig[sigId], "replayed");
        usedSig[sigId] = true;
        address recovered = ecrecover(hash, v, r, s);
        require(recovered == signer, "bad sig");
        payable(to).transfer(amt);
    }
}
"#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "signature-malleability"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "signature-malleability"));
    }
}
