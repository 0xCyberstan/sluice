// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// VULNERABLE: abi.encodePacked with two dynamic (string) arguments produces an
/// ambiguous preimage, enabling hash collisions in the authorization digest.
contract Authz {
    mapping(bytes32 => bool) public approved;
    function approve(string memory role, string memory resource) external {
        bytes32 id = keccak256(abi.encodePacked(role, resource));
        approved[id] = true;
    }
}
