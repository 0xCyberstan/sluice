// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice A funding game that only releases once the exact target is hit.
contract ExactFunding {
    address public owner;
    uint256 public expected;
    bool public unlocked;

    constructor(uint256 _expected) {
        owner = msg.sender;
        expected = _expected;
    }

    function contribute() external payable {
        require(!unlocked, "already unlocked");
    }

    /// @notice Finalize once the contract holds exactly the expected balance.
    function finalize() external {
        // Strict equality on the contract balance. An attacker can preemptively
        // force ETH in via selfdestruct or a coinbase payment so this balance
        // never equals `expected`, permanently locking finalize() (or, if they
        // top it up later, unlocking at an unintended time).
        require(address(this).balance == expected, "wrong balance");
        unlocked = true;
    }

    function withdraw() external {
        require(msg.sender == owner, "not owner");
        require(unlocked, "locked");
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "send failed");
    }
}
