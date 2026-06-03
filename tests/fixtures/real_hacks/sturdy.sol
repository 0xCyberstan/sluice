// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:         Sturdy Finance — June 12, 2023
// Approximate loss:  ~$800,000 (~442 ETH)
// Expected detector: oracle-manipulation
//
// Root cause: Sturdy let users borrow against Balancer/Curve LP tokens
// (the B-stETH-STABLE / cLP collateral), and priced that LP collateral from
// the pool's instantaneous virtual price — a `get_virtual_price()` /
// `getReserves()`-style spot read with NO manipulation resistance (no TWAP,
// no Chainlink feed, no reentrancy-state guard).
//
// The attacker flash-loaned, and during a Balancer Vault operation re-entered
// the protocol while the Vault was mid-callback (the classic Balancer
// READ-ONLY REENTRANCY): in that window the pool's reported reserves/rate were
// transiently inflated. Sturdy's oracle read that inflated `get_virtual_price()`
// and the pool reserves directly, over-valuing the LP collateral, so the
// attacker could borrow far more than the collateral was actually worth and
// drain the lending reserve. The defect is valuing collateral from a live,
// single-transaction-movable LP price.

interface IBalancerLP {
    // Both reflect the pool's instantaneous state -> attacker-movable, and
    // transiently corrupt during a read-only-reentrancy window.
    function get_virtual_price() external view returns (uint256);
    function getReserves() external view returns (uint256 reserve0, uint256 reserve1);
    function totalSupply() external view returns (uint256);
}

contract SturdyLPOracle {
    IBalancerLP public immutable lp; // Balancer/Curve LP used as collateral

    mapping(address => uint256) public collateralLP; // LP units deposited
    mapping(address => uint256) public debt;         // borrowed (in ETH terms)

    constructor(IBalancerLP _lp) {
        lp = _lp;
    }

    // VULNERABLE: LP collateral price = pool virtual price scaled by the spot
    // reserve-per-share. `get_virtual_price()` and `getReserves()` are both live,
    // single-transaction-movable reads (and corruptible via Balancer read-only
    // reentrancy). No TWAP, no Chainlink feed, no reentrancy guard.
    function getCollateralValue(uint256 lpAmount) public view returns (uint256) {
        uint256 vp = lp.get_virtual_price();              // spot, attacker-movable
        (uint256 r0, uint256 r1) = lp.getReserves();      // spot reserves, movable
        uint256 perShare = ((r0 + r1) * 1e18) / lp.totalSupply();
        return (lpAmount * vp * perShare) / 1e36;         // value derived from spot state
    }

    function depositCollateral(uint256 lpAmount) external {
        collateralLP[msg.sender] += lpAmount;
    }

    // Borrow against the manipulable LP valuation: while the spot price is
    // inflated, `getCollateralValue` over-reports and the attacker borrows
    // more ETH than the collateral can ever back.
    function borrow(uint256 amount) external {
        uint256 maxDebt = getCollateralValue(collateralLP[msg.sender]);
        require(debt[msg.sender] + amount <= maxDebt, "undercollateralized");
        debt[msg.sender] += amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}
