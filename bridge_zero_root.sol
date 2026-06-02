// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice Cross-chain message bridge that processes inbound messages once
/// their Merkle root has been accepted. (Nomad-style root handling.)
contract MessageBridge {
    address public updater;

    // root => acceptance status. Uninitialized roots default to false.
    mapping(bytes32 => bool) public acceptedRoots;
    mapping(bytes32 => bool) public processed;

    event Processed(bytes32 indexed messageHash, address recipient);

    constructor(address _updater) {
        updater = _updater;
    }

    function acceptRoot(bytes32 root) external {
        require(msg.sender == updater, "not updater");
        acceptedRoots[root] = true;
    }

    /// @notice Verify a message against a committed root and execute it.
    function process(
        bytes32 root,
        bytes32 messageHash,
        address recipient,
        bytes calldata payload
    ) external {
        require(!processed[messageHash], "replayed");

        // The acceptance check trusts the mapping value but never asserts that
        // `root != bytes32(0)`. The default storage slot for any never-proven
        // message hashes to a zero root, which can be made to read as accepted.
        require(acceptedRoots[root], "root not accepted");

        processed[messageHash] = true;
        (bool ok, ) = recipient.call(payload);
        require(ok, "exec failed");
        emit Processed(messageHash, recipient);
    }
}
