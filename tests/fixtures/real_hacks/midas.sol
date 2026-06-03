// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:         Midas Capital (Compound/Fuse-style money market) — January 15, 2023
// Approximate loss:  ~$660,000 (BSC; jBRL / BOMB market)
// Expected detector: oracle-manipulation
//
// Root cause: Midas listed a brand-new lending market whose collateral asset was
// priced from a LIVE on-chain source — the underlying vault/LP `pricePerShare()`
// (equivalently a Curve `get_virtual_price()` or a raw `balanceOf` reserve read).
// That value reflects the pool's instantaneous state and is movable inside a
// single transaction. There is NO TWAP and NO Chainlink-style robust feed.
//
// The attacker flash-loaned, skewed the underlying pool so `pricePerShare()`
// spiked, then deposited the now-overvalued share token as collateral. Because
// borrow power is computed straight from this spot valuation, the inflated
// collateral let the attacker borrow far more of the other market assets than
// the collateral could ever back, draining the lending reserve. The defect is
// feeding borrow power from a single-transaction-movable spot price.

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IShareVault {
    // Instantaneous share price of the collateral token. Reflects live pool
    // state -> attacker-movable within one transaction (no TWAP).
    function pricePerShare() external view returns (uint256);
    // Spot reserve backing the share -> also movable in a single tx.
    function balanceOf(address account) external view returns (uint256);
}

contract MidasMarket {
    IShareVault public immutable collateralShare; // freshly-listed share collateral
    IERC20 public immutable borrowable;           // asset users borrow

    mapping(address => uint256) public collateral; // share units deposited
    mapping(address => uint256) public debt;        // borrowed amount

    constructor(IShareVault _collateralShare, IERC20 _borrowable) {
        collateralShare = _collateralShare;
        borrowable = _borrowable;
    }

    // VULNERABLE: collateral value = spot pricePerShare() scaled by the spot
    // pool reserve. Both reads are live, single-transaction-movable; no TWAP,
    // no robust oracle. Borrow power is derived directly from this.
    function collateralValue(uint256 shareAmount) public view returns (uint256) {
        uint256 pps = collateralShare.pricePerShare();               // spot, movable
        uint256 reserve = collateralShare.balanceOf(address(this));  // spot reserve
        return (shareAmount * pps * reserve) / 1e36;                 // value from spot state
    }

    function depositCollateral(uint256 shareAmount) external {
        collateral[msg.sender] += shareAmount;
    }

    // Borrow against the manipulable valuation: while pricePerShare() is inflated,
    // collateralValue over-reports and the attacker borrows more than the
    // collateral can back.
    function borrow(uint256 amount) external {
        uint256 maxDebt = collateralValue(collateral[msg.sender]);
        require(debt[msg.sender] + amount <= maxDebt, "undercollateralized");
        debt[msg.sender] += amount;
        require(borrowable.transfer(msg.sender, amount), "transfer failed");
    }
}
