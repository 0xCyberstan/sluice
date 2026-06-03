//! APK / membership history desync — a BLS aggregate-signature verifier that
//! reads **two parallel, per-key, block-indexed histories** through **two
//! different by-position accessors** and folds them into one pairing check, with
//! **no single mutator** writing both histories and **no assertion** tying the
//! apk-update count to the bitmap-update count — so a forged aggregate signature
//! can be accepted.
//!
//! ## The shape (EigenLayer `BLSSignatureChecker.checkSignatures`)
//!
//! Operator membership and the aggregate public key (apk) of a quorum are each
//! recorded as an **append-only, block-indexed history**, but in **two separate
//! registries / state mappings**:
//!
//!   * the **apk history** — element is an aggregate cryptographic point/hash
//!     (`apkHash` / `G1Point`), one entry per block in which the quorum apk
//!     changed (`BLSApkRegistry.apkHistory[quorum]`, written by
//!     `_processQuorumApkUpdate`);
//!   * the **membership history** — element is a per-operator quorum `bitmap`
//!     (`isSet` membership), one entry per block in which the operator's quorum
//!     set changed (`SlashingRegistryCoordinator._operatorBitmapHistory[id]`,
//!     written by a *different* update path).
//!
//! `checkSignatures` then reconstructs the signing apk by reading **both**
//! histories *by caller-supplied index*, through **two different
//! `*AtBlockNumber*Index` accessors**:
//!
//! ```solidity
//! // membership history, by (blockNumber, index):
//! nonSigners.quorumBitmaps[j] = registryCoordinator.getQuorumBitmapAtBlockNumberByIndex({
//!     operatorId: ..., blockNumber: referenceBlockNumber, index: params.nonSignerQuorumBitmapIndices[j] });
//! ...
//! // apk-point history, by (blockNumber, index):
//! require(bytes24(params.quorumApks[i].hashG1Point())
//!         == blsApkRegistry.getApkHashAtBlockNumberAndIndex({
//!             quorumNumber: ..., blockNumber: referenceBlockNumber, index: params.quorumApkIndices[i] }));
//! apk = apk.plus(params.quorumApks[i]);          // combine point + membership-derived negation
//! ...
//! // pairing sink (reached via trySignatureAndApkVerification -> BN254.safePairing):
//! (pairingSuccessful, signatureIsValid) = trySignatureAndApkVerification(msgHash, apk, params.apkG2, params.sigma);
//! ```
//!
//! The membership bitmap selects *which* non-signers are subtracted from the apk
//! (`apk.plus(pubkey.scalar_mul_tiny(countNumOnes(bitmap & signingQuorumBitmap)))`,
//! then `apk.negate()`), and the apk-point history supplies the per-quorum
//! aggregate that is added back. The two histories are advanced by **different
//! functions in different contracts**, and **nothing asserts that an operator's
//! membership-history entry at `referenceBlockNumber` is consistent with the
//! apk-history entry used for the same block** — there is no invariant tying the
//! apk-update count to the bitmap-update count for a key. A caller who can present
//! a `(blockNumber, index)` pair into one history that does not correspond to the
//! membership state actually reflected in the other can reconstruct an apk that
//! omits a real signer (or includes a phantom one) while still matching the stored
//! `apkHash`, forging an aggregate signature that the pairing accepts.
//!
//! ## What the detector matches (the dual-history + two-accessor + pairing shape)
//!
//! A single function whose body:
//!   1. calls **two distinct** *by-position, block-indexed history* accessors —
//!      i.e. a method whose name is block-indexed (`...AtBlockNumber...` + an
//!      index idiom `AndIndex` / `ByIndex` / `AtIndex` / `FromIndex`) — where
//!      one accessor is **apk/point-history-shaped** (`apk` / `apkhash` /
//!      `pubkey`+`agg` / `g1point`) and the *other* is
//!      **membership/bitmap-history-shaped** (`bitmap` / `membership` / `isset`);
//!   2. **combines** values with BLS/EC point arithmetic — a `.plus` / `.negate`
//!      / `.scalar_mul` (`scalar_mul_tiny`) member call (the apk reconstruction);
//!   3. reaches a **pairing sink** — a `pairing` / `safePairing` / `ecPairing`
//!      call, **either in this body or in an internal function it calls** (the
//!      real target reaches `BN254.safePairing` through
//!      `trySignatureAndApkVerification`).
//!
//! ## Precision (Frontier dimension) — why it is ~0 FP off the AVS middleware
//!
//! The discriminator is the **pair of by-position block-indexed history
//! accessors, one apk-shaped and one bitmap-shaped**. That shape is unique to the
//! AVS-middleware apk+membership reconstruction:
//!   * EigenLayer **core** `BN254SignatureVerifier.verifySignature` and
//!     `BN254CertificateVerifier._verifySignature` do `.plus`/`.negate`/`scalar_mul`
//!     and reach `BN254.safePairing`, **but read no block-indexed history at all**
//!     — the apk comes from a struct field / Merkle-proved operator info, not from
//!     two `*AtBlockNumber*Index` accessors. They are correctly suppressed.
//!   * a generic checkpoint/Trace `*AtBlockNumber*Index` getter that is *not* paired
//!     with a second, differently-shaped history accessor, or that never reaches a
//!     pairing, is not this class.
//! SUPPRESS unless **both** an apk-history accessor **and** a membership-history
//! accessor are read in the same function, their values feed a point-arithmetic
//! combine, **and** the combine reaches a pairing sink. A lone history read, a
//! pairing with no dual history, or two histories with no pairing are all silent.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use rustc_hash::FxHashSet;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{Call, Expr, ExprKind, Function, Span};

use super::prelude::*;

pub struct ApkMembershipDesyncDetector;

impl Detector for ApkMembershipDesyncDetector {
    fn id(&self) -> &'static str {
        "apk-membership-desync"
    }
    fn category(&self) -> Category {
        Category::ApkMembershipDesync
    }
    fn description(&self) -> &'static str {
        "BLS aggregate-signature verifier reconstructs the signing apk from two parallel block-indexed \
         histories (an apk/point history and a membership/bitmap history) read via two different \
         by-position accessors, then folds them into a pairing check with no invariant tying the two \
         histories together — a forged aggregate signature can be accepted (EigenLayer \
         BLSSignatureChecker.checkSignatures class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        // Names of internal functions whose body itself reaches a pairing sink. The
        // real target reaches `BN254.safePairing` through the internal
        // `trySignatureAndApkVerification`, so a verifier that *calls* such a helper
        // (rather than inlining the pairing) must still match.
        let pairing_helpers = pairing_helper_names(cx);

        for f in cx.functions() {
            if !f.has_body {
                continue;
            }

            // (1) The dual-history, two-accessor read: one apk/point-history accessor
            //     AND one membership/bitmap-history accessor, both by-position +
            //     block-indexed, with *distinct* names.
            let Some(accessors) = dual_history_accessors(f) else { continue };

            // (2) The apk reconstruction: a BLS/EC point-arithmetic combine
            //     (`.plus` / `.negate` / `.scalar_mul*`) somewhere in the body.
            if !has_point_combine(f) {
                continue;
            }

            // (3) The pairing sink: a `pairing`/`safePairing`/`ecPairing` call in this
            //     body, OR a call to an internal helper whose body reaches one.
            let Some(pairing_site) = pairing_sink_site(f, &pairing_helpers) else {
                continue;
            };

            // Anchor the finding at the apk-point accessor (the verified history read
            // whose desync from the membership history is the bug), falling back to
            // the pairing site.
            let span = accessors.apk_span;

            let b = report!(self, Category::ApkMembershipDesync,
                title = "BLS apk reconstruction reads two unlinked block-indexed histories (apk + membership) into one pairing — forgeable aggregate signature",
                severity = Severity::High,
                confidence = 0.8,
                dimensions = [Dimension::Frontier],
                message = format!(
                    "`{fname}` reconstructs the signing aggregate public key from TWO parallel, per-key, \
                     block-indexed histories read by-position through TWO DIFFERENT accessors — the \
                     apk/point history via `{apk_acc}(...)` and the operator membership/bitmap history via \
                     `{mem_acc}(...)` — then folds them together with BLS point arithmetic \
                     (`.plus`/`.negate`/`.scalar_mul`) and verifies the result with a pairing \
                     (`{pairing}`). The membership bitmap selects which non-signers are subtracted from \
                     the apk, while the apk-point history supplies the per-quorum aggregate added back, \
                     but the two histories are advanced by DIFFERENT functions (in different registries) \
                     and NOTHING asserts that the membership-history entry used for `referenceBlockNumber` \
                     is consistent with the apk-history entry for the same block — there is no invariant \
                     tying the apk-update count to the bitmap-update count for a key, and no single \
                     mutator writes both. A caller who supplies a `(blockNumber, index)` pair into one \
                     history that does not match the membership actually reflected in the other can \
                     reconstruct an apk that omits a real signer (or admits a phantom one) while still \
                     matching the stored `apkHash`, forging an aggregate signature the pairing accepts. \
                     This is the EigenLayer `BLSSignatureChecker.checkSignatures` apk/membership-desync \
                     class.",
                    fname = f.name,
                    apk_acc = accessors.apk_name,
                    mem_acc = accessors.mem_name,
                    pairing = pairing_site.name,
                ),
                recommendation =
                    "Do not reconstruct an aggregate key from two independently-indexed histories that \
                     are not bound to one another. Tie the membership-history read to the apk-history \
                     read for the same key and block — e.g. derive both the operator's quorum bitmap and \
                     the per-quorum apk from a single checkpointed snapshot, or assert at the point of \
                     verification that the apk-update index and the bitmap-update index resolve to the \
                     same block-consistent state (the apk-update count for a quorum must move in lockstep \
                     with the membership changes that produced it). At minimum, validate that every \
                     caller-supplied history index brackets `referenceBlockNumber` AND that the resolved \
                     membership is the membership that the resolved apk was computed from, before \
                     admitting the reconstructed apk into the pairing.",
            );
            out.push(finish_at(cx, b, f.id, span));
        }

        out
    }
}

// --------------------------------------------------------------------------- shape

/// The two matched by-position, block-indexed history accessors found in a verify
/// function: an apk/point-history accessor and a membership/bitmap-history one.
struct DualAccessors {
    apk_name: String,
    mem_name: String,
    /// Span to anchor the finding at (the apk-point history read).
    apk_span: Span,
}

/// A pairing sink found for a verify function.
struct PairingSite {
    name: String,
}

/// Find, in `f`, a pair of **distinct** by-position block-indexed history
/// accessors — one apk/point-history-shaped and one membership/bitmap-shaped.
/// Returns the matched names + the apk read span (the finding anchor). Both must
/// be present, with different names, or there is no dual-history shape.
fn dual_history_accessors(f: &Function) -> Option<DualAccessors> {
    let mut apk: Option<(String, Span)> = None;
    let mut mem: Option<(String, Span)> = None;

    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            let ExprKind::Call(c) = &e.kind else { return };
            let Some(name) = resolved_call_name(c) else { return };
            // The accessor must read a *block-indexed history by position*: its name
            // is the `...AtBlockNumber...<Index idiom>` shape. This is the structural
            // tell that pins us to a checkpointed-history read and excludes plain
            // point arithmetic / Merkle-proof verifiers (which read no such history).
            if !is_block_indexed_history_accessor(&name) {
                return;
            }
            if apk.is_none() && accessor_is_apk_point(&name) {
                apk = Some((name.clone(), e.span));
            } else if mem.is_none() && accessor_is_membership(&name) {
                mem = Some((name.clone(), e.span));
            }
        });
    }

    let (apk_name, apk_span) = apk?;
    let (mem_name, _mem_span) = mem?;
    // Distinct accessors (an apk accessor and a membership accessor are already
    // distinct by classification, but guard against a degenerate name overlap).
    if apk_name == mem_name {
        return None;
    }
    Some(DualAccessors { apk_name, mem_name, apk_span })
}

/// Is `name` a **by-position, block-indexed history accessor**? The canonical
/// EigenLayer idiom: a name that is block-indexed (`atblocknumber`) AND resolves an
/// entry by a caller-supplied position (`andindex` / `byindex` / `atindex` /
/// `fromindex`). Requiring *both* tokens is what keeps this off ordinary getters.
fn is_block_indexed_history_accessor(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    let block_indexed = l.contains("atblocknumber") || l.contains("atblock");
    let by_position = l.contains("andindex")
        || l.contains("byindex")
        || l.contains("atindex")
        || l.contains("fromindex");
    block_indexed && by_position
}

/// Is the accessor name **apk / aggregate-point-history-shaped**? It reads an
/// aggregate cryptographic point/hash element: `apk` / `apkhash`, a `g1point`
/// history, or an aggregate-pubkey history (`agg`+`pubkey` / `aggregatepubkey`).
fn accessor_is_apk_point(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("apk")
        || l.contains("g1point")
        || l.contains("aggregatepubkey")
        || (l.contains("agg") && l.contains("pubkey"))
        || (l.contains("agg") && l.contains("key"))
}

/// Is the accessor name **membership / bitmap-history-shaped**? It reads a
/// per-key membership element: `bitmap`, `membership`, or an `isset`-style flag.
fn accessor_is_membership(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("bitmap") || l.contains("membership") || l.contains("isset")
}

/// Does `f`'s body combine values with BLS/EC **point arithmetic** — a member
/// call `.plus(...)` / `.negate(...)` / `.scalar_mul(...)` / `.scalar_mul_tiny(...)`
/// (the apk reconstruction in `checkSignatures`)? We match the *method name* of a
/// call so it fires whether the receiver is `apk`, a struct field, or a library.
fn has_point_combine(f: &Function) -> bool {
    any_call_where(f, |c| {
        resolved_call_name(c).as_deref().map(is_point_combine_name).unwrap_or(false)
    })
}

/// A method name denoting elliptic-curve point arithmetic used to fold an apk.
fn is_point_combine_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "plus" || l == "negate" || l == "scalar_mul" || l == "scalar_mul_tiny" || l == "add_points"
}

/// Find a **pairing sink** reachable from `f`: a `pairing`/`safePairing`/`ecPairing`
/// call directly in `f`'s body, or a call to an internal helper (`pairing_helpers`)
/// whose own body reaches one. Returns the pairing call's name (for the message).
fn pairing_sink_site(f: &Function, pairing_helpers: &FxHashSet<String>) -> Option<PairingSite> {
    // (a) Direct pairing call in this body.
    let mut direct: Option<String> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            if direct.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if let Some(n) = resolved_call_name(c) {
                    if is_pairing_name(&n) {
                        direct = Some(n);
                    }
                }
            }
        });
        if direct.is_some() {
            break;
        }
    }
    if let Some(n) = direct {
        return Some(PairingSite { name: n });
    }

    // (b) A call to an internal helper whose body reaches a pairing. The real target
    //     reaches `BN254.safePairing` via `trySignatureAndApkVerification`. We match
    //     on the resolved-call name being a known pairing helper, and report the
    //     helper as the pairing site (the sink the apk flows into).
    for s in &f.body {
        let mut hit: Option<String> = None;
        s.visit_exprs(&mut |e: &Expr| {
            if hit.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if let Some(n) = resolved_call_name(c) {
                    if pairing_helpers.contains(&n) {
                        hit = Some(n);
                    }
                }
            }
        });
        if let Some(n) = hit {
            return Some(PairingSite { name: n });
        }
    }
    // Also consult the effect summary's internal-call list (covers helpers whose
    // call node the body walk classified as `Internal` without a member receiver).
    for n in &f.effects.internal_calls {
        if pairing_helpers.contains(n) {
            return Some(PairingSite { name: n.clone() });
        }
    }

    None
}

/// Names of internal functions in the program whose body directly contains a
/// pairing call (`pairing`/`safePairing`/`ecPairing`). Used so a verifier that
/// reaches the pairing through a helper (EigenLayer's `trySignatureAndApkVerification`)
/// still matches.
fn pairing_helper_names(cx: &AnalysisContext) -> FxHashSet<String> {
    let mut out: FxHashSet<String> = FxHashSet::default();
    for f in cx.functions() {
        if !f.has_body {
            continue;
        }
        let has_pairing = any_call_where(f, |c| {
            resolved_call_name(c).as_deref().map(is_pairing_name).unwrap_or(false)
        });
        if has_pairing {
            out.insert(f.name.clone());
        }
    }
    out
}

/// A call name denoting a BN254 / BLS **pairing** check (the verification sink).
fn is_pairing_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "pairing" || l == "safepairing" || l == "ecpairing" || l.ends_with("pairing")
}

/// Resolved callee name of a call (`func_name`, falling back to the callee's simple
/// member name `a.b -> "b"`).
fn resolved_call_name(c: &Call) -> Option<String> {
    c.func_name
        .clone()
        .or_else(|| c.callee.simple_name().map(|s| s.to_string()))
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "apk-membership-desync")
    }

    // VULN — the EigenLayer `BLSSignatureChecker.checkSignatures` shape, reduced:
    // a verifier reads the membership/bitmap history (`getQuorumBitmapAtBlockNumberByIndex`)
    // and the apk-point history (`getApkHashAtBlockNumberAndIndex`) by-position,
    // folds them with `.plus`/`.negate`/`.scalar_mul_tiny`, and reaches the pairing
    // sink through the internal `trySignatureAndApkVerification` helper. The two
    // histories are written by different registries with no joint invariant.
    const VULN: &str = r#"
        library BN254 {
            struct G1Point { uint256 X; uint256 Y; }
            struct G2Point { uint256[2] X; uint256[2] Y; }
            function plus(G1Point memory a, G1Point memory b) internal view returns (G1Point memory) {}
            function negate(G1Point memory a) internal pure returns (G1Point memory) {}
            function scalar_mul(G1Point memory a, uint256 s) internal view returns (G1Point memory) {}
            function scalar_mul_tiny(G1Point memory a, uint256 s) internal view returns (G1Point memory) {}
            function safePairing(G1Point memory a, G2Point memory b, G1Point memory c, G2Point memory d, uint256 g)
                internal view returns (bool, bool) {}
            function negGeneratorG2() internal pure returns (G2Point memory) {}
            function hashG1Point(G1Point memory a) internal pure returns (bytes32) {}
        }
        interface IRegistryCoordinator {
            function getQuorumBitmapAtBlockNumberByIndex(bytes32 id, uint32 bn, uint256 idx) external view returns (uint192);
        }
        interface IBLSApkRegistry {
            function getApkHashAtBlockNumberAndIndex(uint8 q, uint32 bn, uint256 idx) external view returns (bytes24);
        }
        contract BLSSignatureChecker {
            using BN254 for BN254.G1Point;
            IRegistryCoordinator public registryCoordinator;
            IBLSApkRegistry public blsApkRegistry;

            struct Params {
                BN254.G1Point[] quorumApks;
                BN254.G2Point apkG2;
                BN254.G1Point sigma;
                uint256[] quorumApkIndices;
                uint256[] nonSignerBitmapIndices;
                BN254.G1Point[] nonSignerPubkeys;
            }

            function checkSignatures(bytes32 msgHash, bytes calldata quorumNumbers, uint32 referenceBlockNumber, Params memory params)
                public view returns (bool)
            {
                BN254.G1Point memory apk = BN254.G1Point(0, 0);
                for (uint256 j = 0; j < params.nonSignerPubkeys.length; j++) {
                    uint192 bm = registryCoordinator.getQuorumBitmapAtBlockNumberByIndex(
                        bytes32(0), referenceBlockNumber, params.nonSignerBitmapIndices[j]);
                    apk = apk.plus(params.nonSignerPubkeys[j].scalar_mul_tiny(uint256(bm)));
                }
                apk = apk.negate();
                for (uint256 i = 0; i < quorumNumbers.length; i++) {
                    require(
                        bytes24(params.quorumApks[i].hashG1Point())
                            == blsApkRegistry.getApkHashAtBlockNumberAndIndex(
                                uint8(quorumNumbers[i]), referenceBlockNumber, params.quorumApkIndices[i]),
                        "bad apk"
                    );
                    apk = apk.plus(params.quorumApks[i]);
                }
                (bool ok, bool valid) = trySignatureAndApkVerification(msgHash, apk, params.apkG2, params.sigma);
                require(ok, "pairing");
                return valid;
            }

            function trySignatureAndApkVerification(
                bytes32 msgHash, BN254.G1Point memory apk, BN254.G2Point memory apkG2, BN254.G1Point memory sigma
            ) public view returns (bool, bool) {
                uint256 gamma = uint256(msgHash);
                return BN254.safePairing(
                    sigma.plus(apk.scalar_mul(gamma)), BN254.negGeneratorG2(),
                    apk, apkG2, 350000);
            }
        }
    "#;

    // VULN (inline pairing): same dual-history reconstruction, but the pairing is
    // called directly in the verifier body (no helper indirection).
    const VULN_INLINE: &str = r#"
        library BN254 {
            struct G1Point { uint256 X; uint256 Y; }
            struct G2Point { uint256[2] X; uint256[2] Y; }
            function plus(G1Point memory a, G1Point memory b) internal view returns (G1Point memory) {}
            function negate(G1Point memory a) internal pure returns (G1Point memory) {}
            function scalar_mul(G1Point memory a, uint256 s) internal view returns (G1Point memory) {}
            function pairing(G1Point memory a, G2Point memory b, G1Point memory c, G2Point memory d)
                internal view returns (bool) {}
            function negGeneratorG2() internal pure returns (G2Point memory) {}
        }
        interface IRC {
            function getMembershipBitmapAtBlockNumberByIndex(bytes32 id, uint32 bn, uint256 idx) external view returns (uint192);
            function getApkAtBlockNumberAndIndex(uint8 q, uint32 bn, uint256 idx) external view returns (bytes24);
        }
        contract Verifier {
            using BN254 for BN254.G1Point;
            IRC public rc;
            function verify(bytes32 h, uint8 q, uint32 bn, uint256 ai, uint256 bi, BN254.G1Point memory qApk, BN254.G2Point memory g2)
                external view returns (bool)
            {
                uint192 bm = rc.getMembershipBitmapAtBlockNumberByIndex(bytes32(0), bn, bi);
                bytes24 ah = rc.getApkAtBlockNumberAndIndex(q, bn, ai);
                require(bytes24(0) == ah, "x");
                BN254.G1Point memory apk = qApk.scalar_mul(uint256(bm)).negate().plus(qApk);
                return BN254.pairing(apk, g2, apk, g2);
            }
        }
    "#;

    #[test]
    fn fires_on_checksignatures_shape() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_inline_pairing_shape() {
        assert!(fires(VULN_INLINE), "{:#?}", run(VULN_INLINE));
    }

    #[test]
    fn anchors_on_verifier_function() {
        assert!(
            run(VULN)
                .iter()
                .any(|f| f.detector == "apk-membership-desync" && f.function == "checkSignatures"),
            "{:#?}",
            run(VULN)
        );
    }

    // SAFE (single history only): a verifier reads ONLY the apk-point history
    // (`getApkHashAtBlockNumberAndIndex`), combines with point arithmetic, and
    // pairs — but there is no SECOND membership/bitmap history accessor, so there
    // is no dual-history desync. Must stay silent.
    const SAFE_SINGLE_HISTORY: &str = r#"
        library BN254 {
            struct G1Point { uint256 X; uint256 Y; }
            struct G2Point { uint256[2] X; uint256[2] Y; }
            function plus(G1Point memory a, G1Point memory b) internal view returns (G1Point memory) {}
            function negate(G1Point memory a) internal pure returns (G1Point memory) {}
            function pairing(G1Point memory a, G2Point memory b, G1Point memory c, G2Point memory d)
                internal view returns (bool) {}
        }
        interface IApk { function getApkHashAtBlockNumberAndIndex(uint8 q, uint32 bn, uint256 idx) external view returns (bytes24); }
        contract OneHistory {
            using BN254 for BN254.G1Point;
            IApk public reg;
            function verify(uint8 q, uint32 bn, uint256 ai, BN254.G1Point memory apk, BN254.G2Point memory g2)
                external view returns (bool)
            {
                bytes24 ah = reg.getApkHashAtBlockNumberAndIndex(q, bn, ai);
                require(bytes24(0) == ah, "x");
                BN254.G1Point memory a = apk.negate().plus(apk);
                return BN254.pairing(a, g2, a, g2);
            }
        }
    "#;

    // SAFE (EigenLayer CORE BN254SignatureVerifier): does `.plus`/`.scalar_mul` and
    // reaches `BN254.safePairing`, but reads NO block-indexed history at all — the
    // pubkey is a parameter. No dual-history accessors -> silent. This is the exact
    // core-vs-middleware boundary.
    const SAFE_CORE_SIGVERIFIER: &str = r#"
        library BN254 {
            struct G1Point { uint256 X; uint256 Y; }
            struct G2Point { uint256[2] X; uint256[2] Y; }
            function plus(G1Point memory a, G1Point memory b) internal view returns (G1Point memory) {}
            function negate(G1Point memory a) internal pure returns (G1Point memory) {}
            function scalar_mul(G1Point memory a, uint256 s) internal view returns (G1Point memory) {}
            function safePairing(G1Point memory a, G2Point memory b, G1Point memory c, G2Point memory d, uint256 g)
                internal view returns (bool, bool) {}
            function pairing(G1Point memory a, G2Point memory b, G1Point memory c, G2Point memory d)
                internal view returns (bool) {}
            function negGeneratorG2() internal pure returns (G2Point memory) {}
            function generatorG1() internal pure returns (G1Point memory) {}
        }
        library BN254SignatureVerifier {
            using BN254 for BN254.G1Point;
            function verifySignature(
                bytes32 msgHash, BN254.G1Point memory signature, BN254.G1Point memory pubkeyG1,
                BN254.G2Point memory pubkeyG2, BN254.G1Point memory messagePoint, uint256 gamma, uint256 pairingGas
            ) internal view returns (bool) {
                BN254.G1Point memory leftG1 = signature.plus(pubkeyG1.scalar_mul(gamma));
                BN254.G1Point memory rightG1 = messagePoint.plus(BN254.generatorG1().scalar_mul(gamma));
                (bool ok, bool valid) = BN254.safePairing(leftG1, BN254.negGeneratorG2(), rightG1, pubkeyG2, pairingGas);
                return ok && valid;
            }
        }
    "#;

    // SAFE (dual history, NO pairing): a function reads both an apk-history and a
    // bitmap-history accessor and even does point arithmetic, but never reaches a
    // pairing sink (it just returns a computed value). Out of class — the forged-sig
    // hazard requires the pairing acceptance.
    const SAFE_NO_PAIRING: &str = r#"
        library BN254 {
            struct G1Point { uint256 X; uint256 Y; }
            function plus(G1Point memory a, G1Point memory b) internal view returns (G1Point memory) {}
            function negate(G1Point memory a) internal pure returns (G1Point memory) {}
        }
        interface IRC {
            function getQuorumBitmapAtBlockNumberByIndex(bytes32 id, uint32 bn, uint256 idx) external view returns (uint192);
            function getApkHashAtBlockNumberAndIndex(uint8 q, uint32 bn, uint256 idx) external view returns (bytes24);
        }
        contract Reporter {
            using BN254 for BN254.G1Point;
            IRC public rc;
            function summarize(uint8 q, uint32 bn, uint256 ai, uint256 bi, BN254.G1Point memory p)
                external view returns (BN254.G1Point memory)
            {
                uint192 bm = rc.getQuorumBitmapAtBlockNumberByIndex(bytes32(0), bn, bi);
                bytes24 ah = rc.getApkHashAtBlockNumberAndIndex(q, bn, ai);
                require(uint256(bm) >= 0 && ah != bytes24(0), "x");
                return p.negate().plus(p);
            }
        }
    "#;

    // SAFE (two histories but both the SAME shape): two apk-history accessors and a
    // pairing — but no membership/bitmap history, so the apk-vs-membership desync
    // class does not apply. Silent.
    const SAFE_SAME_SHAPE_HISTORIES: &str = r#"
        library BN254 {
            struct G1Point { uint256 X; uint256 Y; }
            struct G2Point { uint256[2] X; uint256[2] Y; }
            function plus(G1Point memory a, G1Point memory b) internal view returns (G1Point memory) {}
            function pairing(G1Point memory a, G2Point memory b, G1Point memory c, G2Point memory d)
                internal view returns (bool) {}
        }
        interface IApk {
            function getApkHashAtBlockNumberAndIndex(uint8 q, uint32 bn, uint256 idx) external view returns (bytes24);
            function getApkHashAtBlockNumberByIndex(uint8 q, uint32 bn, uint256 idx) external view returns (bytes24);
        }
        contract TwoApk {
            using BN254 for BN254.G1Point;
            IApk public reg;
            function verify(uint8 q, uint32 bn, uint256 a1, uint256 a2, BN254.G1Point memory apk, BN254.G2Point memory g2)
                external view returns (bool)
            {
                bytes24 h1 = reg.getApkHashAtBlockNumberAndIndex(q, bn, a1);
                bytes24 h2 = reg.getApkHashAtBlockNumberByIndex(q, bn, a2);
                require(h1 == h2, "x");
                BN254.G1Point memory a = apk.plus(apk);
                return BN254.pairing(a, g2, a, g2);
            }
        }
    "#;

    // SAFE (ordinary checkpoint getter, not a verifier): a plain by-position
    // block-indexed history getter that returns a stake value — no apk, no bitmap,
    // no point arithmetic, no pairing. Silent.
    const SAFE_PLAIN_GETTER: &str = r#"
        contract StakeRegistry {
            mapping(uint8 => mapping(uint256 => uint96)) internal stakeHistory;
            function getTotalStakeAtBlockNumberFromIndex(uint8 q, uint32 bn, uint256 idx)
                external view returns (uint96)
            {
                return stakeHistory[q][idx];
            }
        }
    "#;

    #[test]
    fn silent_on_single_history() {
        assert!(!fires(SAFE_SINGLE_HISTORY), "{:#?}", run(SAFE_SINGLE_HISTORY));
    }

    #[test]
    fn silent_on_core_signature_verifier() {
        assert!(!fires(SAFE_CORE_SIGVERIFIER), "{:#?}", run(SAFE_CORE_SIGVERIFIER));
    }

    #[test]
    fn silent_on_dual_history_without_pairing() {
        assert!(!fires(SAFE_NO_PAIRING), "{:#?}", run(SAFE_NO_PAIRING));
    }

    #[test]
    fn silent_on_same_shape_histories() {
        assert!(!fires(SAFE_SAME_SHAPE_HISTORIES), "{:#?}", run(SAFE_SAME_SHAPE_HISTORIES));
    }

    #[test]
    fn silent_on_plain_checkpoint_getter() {
        assert!(!fires(SAFE_PLAIN_GETTER), "{:#?}", run(SAFE_PLAIN_GETTER));
    }
}
