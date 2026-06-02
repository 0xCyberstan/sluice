// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title TxOriginWallet
/// @notice A simple wallet that authenticates the owner using `tx.origin`.
///         This is unsafe: if the owner is tricked into calling a malicious
///         contract, that contract can call `transfer`/`setOwner` and the
///         `tx.origin == owner` check still passes, allowing the attacker to
///         drain or take over the wallet (phishing / authorization bypass).
contract TxOriginWallet {
    address public owner;

    event Transfer(address indexed to, uint256 amount);
    event OwnerChanged(address indexed newOwner);

    constructor() {
        owner = msg.sender;
    }

    /// @notice VULNERABLE: auth via tx.origin instead of msg.sender.
    modifier onlyOwner() {
        require(tx.origin == owner, "not owner");
        _;
    }

    function deposit() external payable {}

    /// @notice VULNERABLE: protected only by the tx.origin check.
    function transfer(address payable to, uint256 amount) external onlyOwner {
        require(address(this).balance >= amount, "insufficient");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "send failed");
        emit Transfer(to, amount);
    }

    /// @notice VULNERABLE: ownership change gated only by tx.origin.
    function setOwner(address newOwner) external {
        require(tx.origin == owner, "not owner");
        owner = newOwner;
        emit OwnerChanged(newOwner);
    }

    receive() external payable {}
}
