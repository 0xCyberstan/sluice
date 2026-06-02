// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// VULNERABLE: narrowing downcast of an attacker-controlled amount silently
/// truncates the high bits (checked arithmetic does NOT catch casts).
contract Casting {
    mapping(address => uint128) public balances;
    function deposit(uint256 amount) external {
        balances[msg.sender] = uint128(amount); // truncates if amount > type(uint128).max
    }
}
