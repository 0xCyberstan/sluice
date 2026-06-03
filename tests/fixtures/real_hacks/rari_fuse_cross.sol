// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident: Rari Capital / Fei Protocol "Fuse" pools (April 30, 2022)
// Approximate loss: ~$80,000,000
// Expected detector: reentrancy
//
// Root cause (CROSS-CONTRACT / read-before-write-after reentrancy):
//   Fuse markets are a Compound v2 fork. A cToken's borrow() sends the
//   underlying ERC-20 to the borrower BEFORE it records the new debt
//   (accountBorrows / totalBorrows), and the function carries NO nonReentrant
//   guard. The ERC-20 transfer hands control to the borrower mid-call. While
//   control is out, a *different* market contract (the comptroller / a sibling
//   cToken) reads this market's still-stale borrow accounting through a public
//   view getter to compute account liquidity. Because the debt of the in-flight
//   borrow has not yet been written, the cross-contract liquidity check keeps
//   passing, so the attacker re-borrows far beyond their collateral and drains
//   every Fuse pool that shares the manipulated asset.
//
// The exploitable shape is the classic checks-EFFECTS-INTERACTIONS inversion:
//   `accountBorrows[borrower]` is READ before the external transfer (the
//   collateral check) and WRITTEN after it, with the attacker's code running in
//   between — plus a value-like view getter that a separate market consumes.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract CToken {
    IERC20 public immutable underlying;

    mapping(address => uint256) public accountBorrows;     // per-account debt principal
    mapping(address => uint256) public accountCollateral;  // posted collateral
    uint256 public totalBorrows;                           // market-wide outstanding debt

    constructor(IERC20 _underlying) {
        underlying = _underlying;
    }

    function supplyCollateral(uint256 amount) external {
        underlying.transferFrom(msg.sender, address(this), amount);
        accountCollateral[msg.sender] += amount;
    }

    // Value-like view getter consumed CROSS-CONTRACT by the comptroller / a
    // sibling market to value this account's debt. During borrow()'s external
    // transfer it returns the pre-borrow (stale) debt -> read-only reentrancy.
    function borrowBalanceUnderlying(address account) external view returns (uint256) {
        return accountBorrows[account];
    }

    // VULNERABLE: interactions-before-effects, no nonReentrant.
    // accountBorrows[msg.sender] is read in the require (BEFORE the call), the
    // underlying is transferred (control leaves the contract), and only THEN are
    // accountBorrows / totalBorrows written. The borrower re-enters here while
    // the debt is unrecorded and the cross-market liquidity read is stale.
    function borrow(uint256 amount) external {
        require(accountCollateral[msg.sender] * 2 >= accountBorrows[msg.sender] + amount, "shortfall");

        underlying.transfer(msg.sender, amount); // external call BEFORE state settles

        accountBorrows[msg.sender] += amount;    // effect applied too late
        totalBorrows += amount;
    }

    function repayBorrow(uint256 amount) external {
        underlying.transferFrom(msg.sender, address(this), amount);
        accountBorrows[msg.sender] -= amount;
        totalBorrows -= amount;
    }
}

// A SEPARATE market contract that trusts CToken's view getter to gate borrowing.
// Mid-reentrancy it reads stale debt, so its own shortfall check also passes.
contract Comptroller {
    CToken public immutable market;

    constructor(CToken _market) {
        market = _market;
    }

    function liquidityShortfall(address account) external view returns (uint256) {
        return market.borrowBalanceUnderlying(account); // cross-contract stale read
    }
}
