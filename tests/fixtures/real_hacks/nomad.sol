// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
//
// Incident:  Nomad Token Bridge hack (August 2022)
// Loss:      ~$190,000,000 (chaotic free-for-all drain of the Replica)
// Detector:  bridge-verification (Nomad zero-root class)
//
// Root cause: a routine Replica re-initialization seeded the trusted-root store
// with the ZERO root as if it were "proven". process() validated each inbound
// message against acceptableRoot[root] / confirmAt[root], whose DEFAULT value
// (0 / false) was therefore treated as a proven root. Because there is NO
// `require(root != bytes32(0))` guard, ANY message with an unset (zero) root
// passed verification and was executed — anyone could mint/release funds by
// copy-pasting a working transaction and swapping the recipient.
//
interface IBridgeRouter {
    function handle(address recipient, uint256 amount) external;
}

contract Replica {
    // proven-message store: maps a Merkle root to its confirmation timestamp.
    mapping(bytes32 => uint256) public confirmAt;
    // legacy boolean view kept for compatibility; defaults to false for unknown roots.
    mapping(bytes32 => bool) public acceptableRoot;
    mapping(bytes32 => bool) public processed;

    IBridgeRouter public router;

    // The fateful init: instead of leaving the root store empty, the upgrade
    // marked the zero root as confirmed/acceptable. Combined with the default-0
    // semantics below, this made every unproven message verify.
    function initialize(IBridgeRouter _router) external {
        router = _router;
        confirmAt[bytes32(0)] = block.timestamp; // zero root marked "proven"
        acceptableRoot[bytes32(0)] = true;
    }

    // Inbound cross-chain message handler. Validates against the proven-root
    // store but NEVER rejects the zero root, so a message whose root was never
    // actually proven (root == 0, defaulting to "acceptable") is executed.
    function process(bytes32 root, bytes32 messageHash, address recipient, uint256 amount) external {
        // BUG: the zero root is never rejected before it is trusted as proven.
        require(acceptableRoot[root], "!proven");
        require(processed[messageHash] == false, "replayed");
        processed[messageHash] = true;
        // Execute the (forgeable) message: release funds to attacker-chosen recipient.
        router.handle(recipient, amount);
    }
}
