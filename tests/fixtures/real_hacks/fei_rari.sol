// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident: Fei Protocol / Rari Capital "Fuse" pools (April 2022)
// Loss: ~$80,000,000
// Expected detector: reentrancy
//
// Root cause: a Compound-fork cToken `borrow()` performed the external
// underlying-token transfer to the borrower BEFORE updating the borrower's
// borrow balance and the market's total borrows, and had no reentrancy guard.
// During the token transfer the attacker re-entered (via exitMarket / a second
// borrow) while accountBorrows / totalBorrows still reflected the pre-borrow
// state, letting them borrow far beyond their collateral and drain the pool.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract CErc20 {
    IERC20 public immutable underlying;

    mapping(address => uint256) public accountBorrows; // borrowed principal per account
    uint256 public totalBorrows;                        // market-wide outstanding debt
    mapping(address => uint256) public accountCollateral;

    constructor(IERC20 _underlying) {
        underlying = _underlying;
    }

    function supplyCollateral(uint256 amount) external {
        underlying.transferFrom(msg.sender, address(this), amount);
        accountCollateral[msg.sender] += amount;
    }

    // VULNERABLE: interactions-before-effects. The underlying tokens are sent to
    // the borrower first; only afterwards are accountBorrows / totalBorrows
    // updated. A malicious token receiver (or exitMarket callback) re-enters
    // borrow() while the debt is still unrecorded, so the collateral check keeps
    // passing and the pool is drained. No nonReentrant guard.
    function borrow(uint256 amount) external {
        require(accountCollateral[msg.sender] * 2 >= accountBorrows[msg.sender] + amount, "undercollateralized");

        // External transfer of control happens before state settles.
        underlying.transfer(msg.sender, amount);

        // State updated too late.
        accountBorrows[msg.sender] += amount;
        totalBorrows += amount;
    }

    function repayBorrow(uint256 amount) external {
        underlying.transferFrom(msg.sender, address(this), amount);
        accountBorrows[msg.sender] -= amount;
        totalBorrows -= amount;
    }
}
