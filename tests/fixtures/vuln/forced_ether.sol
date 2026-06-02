// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// VULNERABLE: strict equality on the contract's ETH balance. ETH can be
/// force-injected via selfdestruct, permanently breaking this invariant.
contract Game {
    uint256 public target;
    function finalize() external {
        require(address(this).balance == target, "not exact");
        // ... payout logic assuming exact balance
    }
}
