// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title LendingPool
/// @notice A money-market style pool. Three of the four risk-changing actions
///         (borrow, withdrawCollateral, redeem) re-validate account health via
///         `_checkHealth`. The fourth -- `emergencyWithdraw` -- removes
///         collateral WITHOUT a solvency check, letting a borrower pull
///         collateral while still holding debt and leaving the position
///         insolvent.
contract LendingPool {
    IERC20 public immutable token;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public constant COLLATERAL_FACTOR = 75; // percent

    constructor(IERC20 _token) {
        token = _token;
    }

    function _checkHealth(address user) internal view {
        // Debt must stay within COLLATERAL_FACTOR% of collateral.
        require(debt[user] * 100 <= collateral[user] * COLLATERAL_FACTOR, "insolvent");
    }

    function depositCollateral(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        collateral[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        debt[msg.sender] += amount;
        _checkHealth(msg.sender);
        token.transfer(msg.sender, amount);
    }

    function withdrawCollateral(uint256 amount) external {
        collateral[msg.sender] -= amount;
        _checkHealth(msg.sender);
        token.transfer(msg.sender, amount);
    }

    function redeem(uint256 amount) external {
        collateral[msg.sender] -= amount;
        _checkHealth(msg.sender);
        token.transfer(msg.sender, amount);
    }

    /// @notice VULNERABLE: pulls collateral with NO `_checkHealth` call, so a
    ///         user with outstanding debt can withdraw and become insolvent.
    function emergencyWithdraw(uint256 amount) external {
        collateral[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
