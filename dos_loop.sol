// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice Simple lottery where everyone who entered is paid out in one call.
contract BatchPayout {
    address public owner;
    address[] public participants;
    mapping(address => uint256) public owed;

    constructor() {
        owner = msg.sender;
    }

    /// @notice Anyone can enter by depositing; the array grows without bound.
    function enter() external payable {
        require(msg.value > 0, "no value");
        participants.push(msg.sender);
        owed[msg.sender] += msg.value;
    }

    /// @notice Pay every participant in a single loop (push payments).
    function distribute() external {
        require(msg.sender == owner, "not owner");

        // Iterating an attacker-growable array and pushing ETH to each entry.
        // A single participant that reverts on receive (or a large enough
        // array) makes this loop run out of gas, permanently bricking payouts.
        for (uint256 i = 0; i < participants.length; i++) {
            address payable who = payable(participants[i]);
            uint256 amount = owed[who];
            if (amount > 0) {
                owed[who] = 0;
                who.transfer(amount);
            }
        }
    }
}
