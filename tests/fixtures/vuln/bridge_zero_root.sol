// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// VULNERABLE (Nomad-style): a message is accepted against a root mapping whose
/// default value is treated as valid; there is no `root != bytes32(0)` guard.
contract Bridge {
    mapping(bytes32 => bool) public acceptableRoot;
    mapping(bytes32 => bool) public processed;
    function process(bytes32 root, bytes32 messageHash) external {
        require(acceptableRoot[root], "invalid root"); // default false, but root can be set to 0 on upgrade
        require(!processed[messageHash], "replayed");
        processed[messageHash] = true;
        // ... mint/withdraw based on message
    }
}
