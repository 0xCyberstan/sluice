//! Proof checked only at admission, trusted (stale) on the value-update path.
//!
//! A credential / membership proof — a beacon-chain **withdrawal-credential**
//! prefix check, a merkle/SNARK inclusion verify, or a signature recovery — gates
//! an **admission / registration** function: it proves the entity belongs, then
//! records it under an id (`status = ACTIVE`) in a per-id details mapping and
//! credits an initial balance/stake. A separate **value-update** function, keyed
//! by *the same id*, later moves that entity's balance/stake/reward — but it does
//! **not** re-verify the admission proof. It trusts the stored `ACTIVE` status as a
//! proxy for "the credential still holds". If the proven fact can *change* after
//! admission, the value update runs on a **stale proof**.
//!
//! ## The real target — Karak `NativeVault`
//!
//! Admission, `NativeVault.validateWithdrawalCredentials` →
//! `NativeVaultLib.validateWithdrawalCredentials`, checks the withdrawal-credential
//! prefix against a **single hardcoded `0x01` byte**:
//!
//! ```solidity
//! if (
//!     BeaconProofs.getWithdrawalCredentials(validatorFieldsProof.validatorFields)
//!         != bytes32(abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(node.nodeAddress)))
//! ) revert WithdrawalCredentialsMismatchWithNode();
//! ...
//! validatorDetails.status = ValidatorStatus.ACTIVE;
//! self.ownerToNode[nodeOwner].validatorPubkeyHashToDetails[validatorPubkeyHash] = validatorDetails;
//! ```
//!
//! Value update, `NativeVault.validateSnapshotProofs` →
//! `NativeVaultLib.validateSnapshotProof`, is keyed by the **same**
//! `validatorPubkeyHashToDetails[pubkeyHash]`, gates on the stored `status`, and
//! verifies only a *balance* proof — it never re-checks the withdrawal credential:
//!
//! ```solidity
//! ValidatorDetails memory d = node.validatorPubkeyHashToDetails[balanceProofs[i].pubkeyHash];
//! if (d.status != ValidatorStatus.ACTIVE) continue;          // trusts the stale admission
//! int256 balanceDeltaWei = self.validateSnapshotProof(...);  // only validateBalance(...)
//! ```
//!
//! Because the credential prefix is admitted as `0x01`-only, a post-admission
//! EIP-7251 `0x01 → 0x02` switch to a *compounding* validator (same execution
//! address) is never noticed: snapshot proofs keep crediting the now-larger
//! effective balance past the 32-ETH-per-validator regime the admission proved
//! against — the protocol invariant silently breaks (Karak K-N-02).
//!
//! ## Why this stays ~0-FP on the prior restaking codebases (esp. EigenLayer)
//!
//! EigenLayer's `EigenPod` has the *same* admission/checkpoint split, and is
//! **correct** — so it must NOT fire. The discriminator is the SUPPRESS clause
//! "the proof binds an immutable": EigenPod admits a validator on a **disjunction
//! of both credential forms** —
//!
//! ```solidity
//! require(
//!     validatorFields.getWithdrawalCredentials() == bytes32(_podWithdrawalCredentials())        // 0x01
//!         || validatorFields.getWithdrawalCredentials() == bytes32(_podCompoundingWithdrawalCredentials()), // 0x02
//!     WithdrawalCredentialsNotForEigenPod()
//! );
//! ```
//!
//! so the admitted fact ("credentials point at this pod, either prefix") is
//! **immutable** under a later `0x01 → 0x02` switch and cannot go stale. This
//! detector therefore fires only when the admission's credential check is gated on
//! a **single narrow prefix literal** (`uint8(1)` / `0x01`) with **no** compounding
//! (`uint8(2)` / `0x02`) alternative anywhere in the credential-checking
//! implementation — the case where the stored admission *can* drift out of date.
//! (EtherFi only *builds* credentials for `deposit` and forwards checkpoints to the
//! pod — it performs no `getWithdrawalCredentials() ==` admission comparison, so it
//! is excluded by the credential-comparison requirement.)
//!
//! ## Precision anchors (all required)
//!
//! Admission `A` and update `U` are **distinct** functions of the **same contract**,
//! both externally reachable, state-mutating, with bodies, and:
//!   * `A` performs a **credential/membership proof check** (its own body or a
//!     1-hop internal/library callee mentions `withdrawalCredential` /
//!     `getWithdrawalCredentials`), gated on a **single** prefix literal with no
//!     compounding alternative, and admits an entity (sets a per-id `status`
//!     ACTIVE / reaches a value-update);
//!   * `U` reaches a **value-update sink** (balance/stake/reward: `_updateBalance`,
//!     `_increaseBalance`/`_decreaseBalance`, mint/burn-shares, `balanceDelta…`);
//!   * `A` and `U` both index the **same per-id details/status mapping** (the shared
//!     key — `validatorPubkeyHashToDetails`, `*ToInfo`, `*Details`, `*Status`);
//!   * `U` performs **no** credential check (no `withdrawalCredential` token in `U`
//!     or its 1-hop callees) — it trusts the stored admission.
//!
//! SUPPRESS when `U` re-verifies the credential, or when the admission accepts the
//! full (compounding-inclusive) credential set (the proof binds an immutable).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::Function;

use super::prelude::*;

pub struct ProofAdmissionOnlyDetector;

impl Detector for ProofAdmissionOnlyDetector {
    fn id(&self) -> &'static str {
        "proof-admission-only"
    }
    fn category(&self) -> Category {
        Category::ProofAdmissionOnly
    }
    fn description(&self) -> &'static str {
        "Credential/membership proof verified only at admission; the value-update path keyed by the same id trusts the stale proof (Karak NativeVault validateWithdrawalCredentials vs validateSnapshotProofs)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for c in cx.scir.iter_contracts() {
            if c.is_interface() {
                continue;
            }
            // Functions defined in THIS contract (we pair within one contract — the
            // shared per-id mapping lives in one contract's storage).
            let funcs: Vec<&Function> = cx.scir.functions_of(c.id).collect();
            if funcs.len() < 2 {
                continue;
            }

            // Per-function expanded text (own body + 1-hop internal/library callee
            // bodies), computed once. The credential check and the shared mapping
            // often live in a library function the entry dispatches to, so a
            // body-only scan would miss them.
            let expanded: Vec<String> = funcs.iter().map(|f| expanded_text(cx, f)).collect();

            // Find an admission function A: credential check + single-prefix lock +
            // admits (reaches a value-update or marks a per-id status active).
            for (ai, a) in funcs.iter().enumerate() {
                if !is_entry(a) {
                    continue;
                }
                let a_text = &expanded[ai];
                if !mentions_credential_check(a_text) {
                    continue;
                }
                // SUPPRESS: the admission binds an immutable — it accepts the full
                // (compounding-inclusive) credential set, so a later prefix switch
                // cannot make the stored admission stale (EigenPod shape).
                if accepts_compounding_credentials(a_text) {
                    continue;
                }
                // The admission must actually *admit*: credit value or mark a per-id
                // status active (so it is a registration, not a read-only verifier).
                if !(reaches_value_update(a, &funcs) || marks_status_active(a_text)) {
                    continue;
                }
                // The shared per-id details/status mapping the admission keys on.
                let Some(shared_map) = id_keyed_mapping(a_text) else { continue };

                // Find the value-update function U keyed by the SAME mapping that
                // does NOT re-check the credential.
                for (ui, u) in funcs.iter().enumerate() {
                    if ui == ai || !is_entry(u) {
                        continue;
                    }
                    let u_text = &expanded[ui];
                    // U trusts the stale admission: it must NOT re-verify credentials.
                    if mentions_credential_check(u_text) {
                        continue;
                    }
                    // U must move value (balance/stake/reward update).
                    if !reaches_value_update(u, &funcs) {
                        continue;
                    }
                    // U must be keyed by the SAME per-id mapping as the admission
                    // (the stale-trust linkage), and read the stored admission state
                    // (status / the details record) rather than re-prove it.
                    if !text_has_word(u_text, &shared_map) {
                        continue;
                    }
                    if !trusts_stored_status(u_text) {
                        continue;
                    }

                    out.push(finish_at(
                        cx,
                        report!(self, Category::ProofAdmissionOnly,
                            title = "Credential proof checked only at admission; value-update path trusts the stale proof",
                            severity = Severity::High,
                            confidence = 0.8,
                            dimensions = [Dimension::Frontier, Dimension::Invariant],
                            message = format!(
                                "`{contract}.{update}` updates an entity's balance/stake keyed by \
                                 `{map}[...]`, gating only on the stored `status` admitted by \
                                 `{contract}.{admit}`. The admission proves a credential / membership \
                                 fact (a withdrawal-credential prefix / merkle / signature check) and \
                                 records the entity as ACTIVE, but `{update}` never re-verifies that \
                                 proof — it trusts the stored admission. Because the admission's \
                                 credential check is gated on a single narrow prefix literal (`uint8(1)` \
                                 / `0x01`) with no compounding (`0x02`) alternative, the proven fact is \
                                 NOT immutable: a post-admission credential switch (e.g. EIP-7251 \
                                 `0x01 → 0x02` to a compounding validator on the same execution address) \
                                 is never noticed, and `{update}` keeps crediting balance past the regime \
                                 the admission proved against — the per-id invariant silently breaks. \
                                 This is the Karak `NativeVault.validateWithdrawalCredentials` (admission) \
                                 vs `validateSnapshotProofs` (value update) split (K-N-02). Contrast \
                                 EigenLayer's `EigenPod`, which admits on a `0x01 || 0x02` disjunction so \
                                 the binding is immutable and the checkpoint path needs no re-check.",
                                contract = c.name,
                                update = u.name,
                                admit = a.name,
                                map = shared_map,
                            ),
                            recommendation =
                                "Re-validate the admission invariant on the value-update path, or bind it to \
                                 an immutable. Either (a) re-derive/verify the credential (and its prefix \
                                 regime) inside the balance-update proof so a post-admission switch is \
                                 caught, (b) cap the per-id balance delta at the maximum the admitted \
                                 credential regime allows (e.g. clamp to the 32-ETH / non-compounding \
                                 ceiling proven at admission), or (c) admit on the full credential set so \
                                 the stored admission cannot drift (accept both `0x01` and `0x02` \
                                 withdrawal-credential prefixes, as EigenLayer's EigenPod does).",
                        ),
                        u.id,
                        u.span,
                    ));
                    // One finding per admission is enough — the fix is shared.
                    break;
                }
            }
        }

        out
    }
}

// ----------------------------------------------------------------- structure

/// Externally reachable, state-mutating, with a body — the surface a proof would
/// gate.
fn is_entry(f: &Function) -> bool {
    f.has_body && f.is_externally_reachable() && f.is_state_mutating()
}

/// `f`'s own (comment-stripped, lowercased) source text plus the source text of
/// every program function whose name appears in `f`'s resolved `internal_calls`
/// (a 1-hop expansion). The credential check and the shared per-id mapping commonly
/// live in a `using`-bound library function the entry dispatches to (Karak:
/// `NativeVault.validateWithdrawalCredentials` calls the library
/// `validateWithdrawalCredentials`, whose body holds the prefix check and the
/// `validatorPubkeyHashToDetails` write), so the entry's own body alone is blind to
/// them.
fn expanded_text(cx: &AnalysisContext, f: &Function) -> String {
    let mut text = cx.source_text(f.span);
    if f.effects.internal_calls.is_empty() {
        return text;
    }
    // Avoid pulling in `f` itself (a self-recursive name) twice.
    for callee in cx.scir.all_functions() {
        if callee.id == f.id || !callee.has_body {
            continue;
        }
        if f.effects.internal_calls.iter().any(|n| n == &callee.name) {
            text.push(' ');
            text.push_str(&cx.source_text(callee.span));
        }
    }
    text
}

// ----------------------------------------------------------------- credential

/// Does the (expanded) text perform a **credential / withdrawal-credential**
/// check? The defining token is `withdrawalcredential` (covers
/// `getWithdrawalCredentials`, `WithdrawalCredentialsMismatch…`,
/// `_podWithdrawalCredentials`, …) — a beacon-chain credential read/compare. We
/// require the credential token specifically (not a bare merkle/signature verify)
/// so this stays on the credential-admission class, the one with a stale-proof
/// invariant, and excludes ordinary balance-only proof paths.
fn mentions_credential_check(text: &str) -> bool {
    text.contains("withdrawalcredential")
}

/// Does the admission accept a **compounding** credential as well — i.e. the
/// admitted credential set is the full `0x01 || 0x02` set (EigenPod)? If so the
/// proven fact ("credentials point at this entity, either prefix") is immutable
/// under a later prefix switch, so the stored admission cannot go stale — SUPPRESS.
///
/// Signals (any): an explicit compounding-credential token, or the `0x02` /
/// `uint8(2)` prefix literal, present in the credential-check text.
fn accepts_compounding_credentials(text: &str) -> bool {
    text.contains("compounding")
        || text.contains("uint8(2)")
        || text.contains("bytes1(0x02)")
        // `0x02000000...` packed-credential literal form.
        || text.contains("0x0200000000")
        // A second distinct prefix in a `==` disjunction also means "not single-prefix".
        || (text.contains("uint8(1)") && text.contains("uint8(2)"))
}

// ----------------------------------------------------------------- value sink

/// Does `f` reach a **balance / stake / reward value-update sink** — its own name,
/// or any function reachable from it through same-contract internal calls (bounded
/// transitive name-search)? The sink is the state change the stale proof is trusted
/// for. Karak's update entry reaches it via `validateSnapshotProof` /
/// `_updateSnapshot` → `_updateBalance` → `_increaseBalance`, so a 1-hop scan is not
/// enough.
fn reaches_value_update(f: &Function, funcs: &[&Function]) -> bool {
    if name_is_value_update(&f.name) {
        return true;
    }
    let mut seen: Vec<&str> = vec![f.name.as_str()];
    let mut frontier: Vec<&Function> = vec![f];
    while let Some(cur) = frontier.pop() {
        for n in &cur.effects.internal_calls {
            if name_is_value_update(n) {
                return true;
            }
            if seen.contains(&n.as_str()) {
                continue;
            }
            seen.push(n.as_str());
            if let Some(next) = funcs.iter().find(|g| &g.name == n && g.has_body) {
                frontier.push(next);
            }
        }
    }
    false
}

/// A function name that updates an accounting balance/stake/reward. Deliberately
/// the *update* verbs (`update`/`increase`/`decrease`/`mint`/`burn`/`credit`/
/// `award`/`slash`/`settle`) combined with an accounting noun, plus the canonical
/// `_updateBalance` / `increaseBalance` / `mintShares` shapes.
fn name_is_value_update(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    const SINKS: &[&str] = &[
        "updatebalance",
        "increasebalance",
        "decreasebalance",
        "updatesnapshot",
        "creditbalance",
        "awardshares",
        "mintshares",
        "burnshares",
        "updatestake",
        "updaterestaked",
        "recordbeaconchaineth",
        "balancedelta",
    ];
    if SINKS.iter().any(|s| l.contains(s)) {
        return true;
    }
    // `_mint` / `_burn` exact (share mint/burn), but not `previewMint` etc.
    matches!(l.as_str(), "_mint" | "_burn" | "mint" | "burn")
}

// ----------------------------------------------------------------- shared key

/// The per-id **details / status mapping** name the credential admission keys on
/// (the shared id the update path will also key on). We match a mapping/identifier
/// whose name reads as a per-entity record keyed by an id: `*pubkeyhashto*`,
/// `*todetails`, `*details`, `*toinfo`, `*info`, `*status`, `*record`. Returns the
/// first matching token (lowercased) found in `text`.
fn id_keyed_mapping(text: &str) -> Option<String> {
    identifier_tokens(text).into_iter().find(|tok| name_is_id_keyed_mapping(tok))
}

/// A name that reads as a per-id details/status record mapping.
fn name_is_id_keyed_mapping(tok: &str) -> bool {
    // Must look like a *mapping/record* of per-entity details, not a bare flag.
    // The strongest, least-ambiguous signals are the `...todetails` / `...toinfo`
    // map-naming idioms and explicit `details`/`validatordetails` records.
    (tok.contains("pubkeyhashto"))
        || tok.ends_with("todetails")
        || tok.ends_with("toinfo")
        || tok.ends_with("validatordetails")
        || tok == "validatorpubkeyhashtodetails"
        || tok == "validatorpubkeyhashtoinfo"
        || (tok.contains("validator") && (tok.ends_with("details") || tok.ends_with("info")))
}

/// Does the update text **trust the stored admission** — read a per-entity
/// `status` and gate on an `active` state (rather than re-proving it)? This is the
/// "trusts the stale proof" tell: `if (... .status != ACTIVE) continue/revert`.
fn trusts_stored_status(text: &str) -> bool {
    text.contains("status") && text.contains("active")
}

/// Does the admission text **mark a per-entity status active** (a registration
/// write `status = ... ACTIVE`)? One of the two ways an admission qualifies as
/// admitting (the other is reaching a value-update).
fn marks_status_active(text: &str) -> bool {
    // `.status = ...active` — a status write to an active state. We look for the
    // co-occurrence of a status assignment and an active enum value.
    text.contains("status") && text.contains("active") && text.contains('=')
}

// ----------------------------------------------------------------- text utils

/// Lowercased identifier tokens (`[A-Za-z0-9_$]+`) of `text`, de-duplicated in
/// first-seen order. `text` is already comment-stripped + lowercased by
/// `source_text`.
fn identifier_tokens(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let flush = |cur: &mut String, out: &mut Vec<String>| {
        if cur.len() >= 4 {
            let w = cur.clone();
            if !out.iter().any(|x| x == &w) {
                out.push(w);
            }
        }
        cur.clear();
    };
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' {
            cur.push(ch);
        } else {
            flush(&mut cur, &mut out);
        }
    }
    flush(&mut cur, &mut out);
    out
}

/// Whole-identifier containment of `needle` in `hay` (both already lowercased).
/// `needle` must appear bounded by non-identifier chars (or string ends) so a
/// mapping name like `validatorpubkeyhashtodetails` is matched as a token, not as a
/// substring of a longer identifier.
fn text_has_word(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let hb = hay.as_bytes();
    let nb = needle.as_bytes();
    let is_id = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'$';
    let mut from = 0usize;
    while let Some(rel) = hay[from..].find(needle) {
        let i = from + rel;
        let before_ok = i == 0 || !is_id(hb[i - 1]);
        let after = i + nb.len();
        let after_ok = after >= hb.len() || !is_id(hb[after]);
        if before_ok && after_ok {
            return true;
        }
        from = i + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "proof-admission-only")
    }

    // VULN — the Karak NativeVault shape (condensed): admission
    // `validateWithdrawalCredentials` checks the withdrawal credential against a
    // SINGLE `uint8(1)` prefix, marks the validator ACTIVE in
    // `validatorPubkeyHashToDetails`, and credits balance; the update
    // `validateSnapshotProofs` is keyed by the same mapping, gates on the stored
    // `status == ACTIVE`, and only verifies a balance proof — never re-checking the
    // credential.
    const VULN: &str = r#"
        library BeaconProofs {
            function getWithdrawalCredentials(bytes32[] calldata vf) external pure returns (bytes32) { return vf[1]; }
            function validateBalance(bytes32 r, uint40 i, bytes calldata p) external pure returns (uint256) { return 1; }
        }
        contract NativeVault {
            enum ValidatorStatus { INACTIVE, ACTIVE, WITHDRAWN }
            struct ValidatorDetails { uint40 validatorIndex; ValidatorStatus status; uint256 restakedBalanceWei; }
            struct Node { address nodeAddress; uint256 activeValidatorCount; mapping(bytes32 => ValidatorDetails) validatorPubkeyHashToDetails; }
            mapping(address => Node) ownerToNode;
            uint256 totalAssets;

            function validateWithdrawalCredentials(address nodeOwner, bytes32 beaconStateRoot, bytes32[] calldata validatorFields)
                external
            {
                bytes32 pubkeyHash = validatorFields[0];
                ValidatorDetails memory d = ownerToNode[nodeOwner].validatorPubkeyHashToDetails[pubkeyHash];
                if (d.status != ValidatorStatus.INACTIVE) revert();
                if (
                    BeaconProofs.getWithdrawalCredentials(validatorFields)
                        != bytes32(abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(ownerToNode[nodeOwner].nodeAddress)))
                ) revert();
                d.status = ValidatorStatus.ACTIVE;
                ownerToNode[nodeOwner].validatorPubkeyHashToDetails[pubkeyHash] = d;
                ownerToNode[nodeOwner].activeValidatorCount++;
                _increaseBalance(nodeOwner, 32 ether);
            }

            function validateSnapshotProofs(address nodeOwner, bytes32 balanceRoot, bytes32[] calldata pubkeyHashes)
                external
            {
                for (uint256 i = 0; i < pubkeyHashes.length; i++) {
                    ValidatorDetails memory d = ownerToNode[nodeOwner].validatorPubkeyHashToDetails[pubkeyHashes[i]];
                    if (d.status != ValidatorStatus.ACTIVE) continue;
                    uint256 newBal = BeaconProofs.validateBalance(balanceRoot, d.validatorIndex, msg.data);
                    d.restakedBalanceWei = newBal;
                    ownerToNode[nodeOwner].validatorPubkeyHashToDetails[pubkeyHashes[i]] = d;
                    _updateBalance(nodeOwner, int256(newBal));
                }
            }

            function _increaseBalance(address of_, uint256 a) internal { totalAssets += a; }
            function _decreaseBalance(address of_, uint256 a) internal { totalAssets -= a; }
            function _updateBalance(address of_, int256 a) internal {
                if (a > 0) _increaseBalance(of_, uint256(a)); else _decreaseBalance(of_, uint256(-a));
            }
        }
    "#;

    #[test]
    fn fires_on_karak_shape() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    // SAFE (EigenPod shape) — admission accepts BOTH `0x01` and a `compounding`
    // (`uint8(2)`) credential in a disjunction, so the admitted binding is immutable
    // under a prefix switch. Even though the checkpoint path trusts the stored
    // status, the proof binds an immutable -> SUPPRESS.
    const SAFE_COMPOUNDING: &str = r#"
        library BeaconProofs {
            function getWithdrawalCredentials(bytes32[] calldata vf) external pure returns (bytes32) { return vf[1]; }
            function validateBalance(bytes32 r, uint40 i, bytes calldata p) external pure returns (uint256) { return 1; }
        }
        contract EigenPod {
            enum VALIDATOR_STATUS { INACTIVE, ACTIVE, WITHDRAWN }
            struct ValidatorInfo { uint40 validatorIndex; VALIDATOR_STATUS status; uint256 restakedBalanceGwei; }
            mapping(bytes32 => ValidatorInfo) validatorPubkeyHashToInfo;
            uint256 activeValidatorCount;
            uint256 totalAssets;

            function _podWithdrawalCredentials() internal view returns (bytes memory) { return abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(this)); }
            function _podCompoundingWithdrawalCredentials() internal view returns (bytes memory) { return abi.encodePacked(bytes1(uint8(2)), bytes11(0), address(this)); }

            function verifyWithdrawalCredentials(bytes32 beaconStateRoot, bytes32[] calldata validatorFields) external {
                bytes32 pubkeyHash = validatorFields[0];
                ValidatorInfo memory info = validatorPubkeyHashToInfo[pubkeyHash];
                if (info.status != VALIDATOR_STATUS.INACTIVE) revert();
                require(
                    BeaconProofs.getWithdrawalCredentials(validatorFields) == bytes32(_podWithdrawalCredentials())
                        || BeaconProofs.getWithdrawalCredentials(validatorFields) == bytes32(_podCompoundingWithdrawalCredentials())
                );
                info.status = VALIDATOR_STATUS.ACTIVE;
                validatorPubkeyHashToInfo[pubkeyHash] = info;
                activeValidatorCount++;
                _updateBalance(32 ether);
            }

            function verifyCheckpointProofs(bytes32 balanceRoot, bytes32[] calldata pubkeyHashes) external {
                for (uint256 i = 0; i < pubkeyHashes.length; i++) {
                    ValidatorInfo memory info = validatorPubkeyHashToInfo[pubkeyHashes[i]];
                    if (info.status != VALIDATOR_STATUS.ACTIVE) continue;
                    uint256 newBal = BeaconProofs.validateBalance(balanceRoot, info.validatorIndex, msg.data);
                    info.restakedBalanceGwei = newBal;
                    validatorPubkeyHashToInfo[pubkeyHashes[i]] = info;
                    _updateBalance(int256(newBal));
                }
            }

            function _updateBalance(int256 a) internal { if (a > 0) totalAssets += uint256(a); }
            function _updateBalance(uint256 a) internal { totalAssets += a; }
        }
    "#;

    #[test]
    fn silent_when_admission_accepts_compounding() {
        assert!(!fires(SAFE_COMPOUNDING), "{:#?}", run(SAFE_COMPOUNDING));
    }

    // SAFE — the update path RE-VERIFIES the withdrawal credential on every balance
    // update (it carries the credential check too), so it is not running on a stale
    // proof. SUPPRESS.
    const SAFE_UPDATE_REVERIFIES: &str = r#"
        library BeaconProofs {
            function getWithdrawalCredentials(bytes32[] calldata vf) external pure returns (bytes32) { return vf[1]; }
            function validateBalance(bytes32 r, uint40 i, bytes calldata p) external pure returns (uint256) { return 1; }
        }
        contract NativeVault {
            enum ValidatorStatus { INACTIVE, ACTIVE, WITHDRAWN }
            struct ValidatorDetails { uint40 validatorIndex; ValidatorStatus status; uint256 restakedBalanceWei; }
            struct Node { address nodeAddress; mapping(bytes32 => ValidatorDetails) validatorPubkeyHashToDetails; }
            mapping(address => Node) ownerToNode;
            uint256 totalAssets;

            function validateWithdrawalCredentials(address nodeOwner, bytes32[] calldata validatorFields) external {
                bytes32 pubkeyHash = validatorFields[0];
                ValidatorDetails memory d = ownerToNode[nodeOwner].validatorPubkeyHashToDetails[pubkeyHash];
                if (
                    BeaconProofs.getWithdrawalCredentials(validatorFields)
                        != bytes32(abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(ownerToNode[nodeOwner].nodeAddress)))
                ) revert();
                d.status = ValidatorStatus.ACTIVE;
                ownerToNode[nodeOwner].validatorPubkeyHashToDetails[pubkeyHash] = d;
                _increaseBalance(nodeOwner, 32 ether);
            }

            function validateSnapshotProofs(address nodeOwner, bytes32 balanceRoot, bytes32[] calldata validatorFields) external {
                bytes32 pubkeyHash = validatorFields[0];
                ValidatorDetails memory d = ownerToNode[nodeOwner].validatorPubkeyHashToDetails[pubkeyHash];
                if (d.status != ValidatorStatus.ACTIVE) revert();
                // Re-verify the withdrawal credential on the update path too.
                if (
                    BeaconProofs.getWithdrawalCredentials(validatorFields)
                        != bytes32(abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(ownerToNode[nodeOwner].nodeAddress)))
                ) revert();
                uint256 newBal = BeaconProofs.validateBalance(balanceRoot, d.validatorIndex, msg.data);
                _updateBalance(nodeOwner, int256(newBal));
            }

            function _increaseBalance(address of_, uint256 a) internal { totalAssets += a; }
            function _updateBalance(address of_, int256 a) internal { if (a > 0) _increaseBalance(of_, uint256(a)); }
        }
    "#;

    #[test]
    fn silent_when_update_reverifies_credential() {
        assert!(!fires(SAFE_UPDATE_REVERIFIES), "{:#?}", run(SAFE_UPDATE_REVERIFIES));
    }

    // SAFE — no credential admission at all: an ordinary deposit/withdraw vault. The
    // two functions touch a balance mapping but there is no withdrawal-credential
    // proof gating admission, so the class does not apply.
    const SAFE_PLAIN_VAULT: &str = r#"
        contract Vault {
            mapping(address => uint256) public balanceOf;
            uint256 public totalAssets;
            function deposit(uint256 a) external { balanceOf[msg.sender] += a; totalAssets += a; }
            function withdraw(uint256 a) external { balanceOf[msg.sender] -= a; totalAssets -= a; }
        }
    "#;

    #[test]
    fn silent_on_plain_vault() {
        assert!(!fires(SAFE_PLAIN_VAULT), "{:#?}", run(SAFE_PLAIN_VAULT));
    }

    // SAFE — single credential-gated admission, but there is NO separate
    // value-update function keyed by the same mapping (only the admission exists).
    // Nothing trusts a stale proof, so SUPPRESS.
    const SAFE_NO_UPDATE_PATH: &str = r#"
        library BeaconProofs {
            function getWithdrawalCredentials(bytes32[] calldata vf) external pure returns (bytes32) { return vf[1]; }
        }
        contract NativeVault {
            enum ValidatorStatus { INACTIVE, ACTIVE }
            struct ValidatorDetails { ValidatorStatus status; }
            struct Node { address nodeAddress; mapping(bytes32 => ValidatorDetails) validatorPubkeyHashToDetails; }
            mapping(address => Node) ownerToNode;
            uint256 totalAssets;
            function validateWithdrawalCredentials(address nodeOwner, bytes32[] calldata validatorFields) external {
                bytes32 pubkeyHash = validatorFields[0];
                ValidatorDetails memory d = ownerToNode[nodeOwner].validatorPubkeyHashToDetails[pubkeyHash];
                if (
                    BeaconProofs.getWithdrawalCredentials(validatorFields)
                        != bytes32(abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(ownerToNode[nodeOwner].nodeAddress)))
                ) revert();
                d.status = ValidatorStatus.ACTIVE;
                ownerToNode[nodeOwner].validatorPubkeyHashToDetails[pubkeyHash] = d;
                _increaseBalance(nodeOwner, 32 ether);
            }
            function _increaseBalance(address of_, uint256 a) internal { totalAssets += a; }
        }
    "#;

    #[test]
    fn silent_without_update_path() {
        assert!(!fires(SAFE_NO_UPDATE_PATH), "{:#?}", run(SAFE_NO_UPDATE_PATH));
    }
}
