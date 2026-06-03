// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
//
// Incident:  Wormhole token bridge hack (February 2022)
// Loss:      ~$326,000,000 (120k wETH minted on Solana against nothing)
// Detector:  signature (guardian-set / ecrecover verification bypass)
//
// Root cause: the bridge accepts a VAA (Verifiable Action Approval) only if it
// carries enough valid guardian signatures. The verifier ecrecovers a signer
// from each attacker-supplied (v, r, s) over a digest of the attacker-supplied
// VAA body, but the recovery result is never properly checked:
//   * the recovered address is NOT verified to be a member of the trusted
//     guardian set (no `guardianSet[index] == recovered` cross-check), and
//   * the result is NOT rejected when `ecrecover` returns the zero address.
// A malformed signature makes `ecrecover` yield address(0); since the code only
// counts "non-reverting" recoveries toward the quorum instead of matching them
// to known guardians, an attacker forges a VAA that mints wrapped assets with
// no real backing. (On-chain this surfaced via a spoofable signature-set input
// to the Solana verify program; the EVM-shaped analogue is modeled here.)
//
// The dominant vulnerable pattern: ecrecover(digest, v, r, s) whose result is
// trusted without an address(0) guard and without a guardian-set membership
// check — verification keys off the attacker-supplied signatures themselves.
//
interface ITokenBridge {
    // Privileged sink: mints/releases wrapped tokens once a VAA "verifies".
    function completeTransfer(address recipient, uint256 amount) external;
}

contract WormholeCore {
    // The trusted guardian set whose quorum of signatures should gate every VAA.
    address[] public guardianSet;
    uint256 public quorum;
    // Replay guard over consumed VAA hashes — makes the entry point state-mutating.
    mapping(bytes32 => bool) public consumed;

    ITokenBridge public bridge;

    function initialize(address[] calldata guardians, ITokenBridge _bridge) external {
        guardianSet = guardians;
        quorum = (guardians.length * 2) / 3 + 1;
        bridge = _bridge;
    }

    // Verify a VAA and, if it "passes", release funds. The signatures, the body,
    // and the per-signature guardian indices are all attacker-supplied.
    function verifyVAA(
        bytes calldata body,
        uint8[] calldata v,
        bytes32[] calldata r,
        bytes32[] calldata s,
        address recipient,
        uint256 amount
    ) external {
        bytes32 hash = keccak256(body);
        require(!consumed[hash], "replayed");
        consumed[hash] = true;

        uint256 valid = 0;
        for (uint256 i = 0; i < v.length; i++) {
            // BUG: the recovered signer is trusted as "a guardian signed this"
            // without ever checking it against `guardianSet`, and without
            // rejecting the zero address that a malformed signature produces.
            address signer = ecrecover(hash, v[i], r[i], s[i]);
            valid++; // counts the recovery itself, not a match to a real guardian
            signer; // recovered address is discarded, never cross-checked
        }

        require(valid >= quorum, "no quorum");
        // Forged VAA reaches the mint/release sink with attacker-chosen recipient.
        bridge.completeTransfer(recipient, amount);
    }
}
