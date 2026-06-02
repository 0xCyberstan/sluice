// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice Access registry that authorizes (namespace, role) string pairs by
/// hashing them into a single digest used as a Merkle/whitelist leaf.
contract RoleRegistry {
    address public admin;
    mapping(bytes32 => bool) public authorized;

    constructor() {
        admin = msg.sender;
    }

    /// @notice Build the auth digest for a namespace/role pair.
    function digest(string memory namespace, string memory role)
        public
        pure
        returns (bytes32)
    {
        // abi.encodePacked of two dynamic strings is ambiguous: ("ab","c") and
        // ("a","bc") pack to identical bytes, so distinct (namespace, role)
        // pairs collide to the same digest. An attacker grants themselves a
        // privileged role by registering a colliding low-privilege pair.
        return keccak256(abi.encodePacked(namespace, role));
    }

    function grant(string calldata namespace, string calldata role) external {
        require(msg.sender == admin, "not admin");
        authorized[digest(namespace, role)] = true;
    }

    function isAuthorized(string calldata namespace, string calldata role)
        external
        view
        returns (bool)
    {
        return authorized[digest(namespace, role)];
    }
}
