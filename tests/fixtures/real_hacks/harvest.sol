// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:        Harvest Finance — October 26, 2020
// Approximate loss: ~$34M (fUSDC + fUSDT vaults)
// Expected detector: oracle-manipulation
//
// Root cause: Harvest's stablecoin vaults priced their fToken shares off the
// LIVE state of a Curve pool — `get_virtual_price()` together with the pool's
// instantaneous token `balanceOf` reserves. Both are spot reads movable inside
// one transaction. The attacker flash-loaned, swapped a large USDC->USDT amount
// to lopside the Curve pool (depressing the share price), deposited at the
// cheap price to mint extra fTokens, swapped back to restore the pool, then
// redeemed those fTokens at the recovered (higher) price — pocketing the
// difference. There is NO TWAP and NO Chainlink feed guarding the valuation.

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface ICurvePool {
    // Both reads reflect the pool's instantaneous state -> attacker-movable.
    function get_virtual_price() external view returns (uint256);
    function balances(uint256 i) external view returns (uint256);
}

contract HarvestVault {
    ICurvePool public immutable pool;     // Curve stablecoin pool (e.g. 3pool)
    IERC20 public immutable underlying;   // the stablecoin deposited (USDC/USDT)

    mapping(address => uint256) public shares; // fToken balance per depositor
    uint256 public totalShares;

    constructor(ICurvePool _pool, IERC20 _underlying) {
        pool = _pool;
        underlying = _underlying;
    }

    // VULNERABLE: share price = Curve virtual price scaled by the pool's spot
    // reserve balance. Both `get_virtual_price()` and `balances(0)` are live,
    // single-transaction-movable reads — no TWAP, no robust oracle.
    function pricePerShare() public view returns (uint256) {
        uint256 vp = pool.get_virtual_price();      // spot, attacker-movable
        uint256 reserve = pool.balances(0);         // spot reserve, attacker-movable
        return (vp * reserve) / 1e18;               // fToken value derived from spot state
    }

    // Mint fTokens valued at the manipulable spot price (skewed low by a swap).
    function deposit(uint256 amount) external {
        require(underlying.transferFrom(msg.sender, address(this), amount), "transfer failed");
        uint256 minted = (amount * 1e18) / pricePerShare();
        shares[msg.sender] += minted;
        totalShares += minted;
    }

    // Redeem fTokens at the manipulable spot price (restored higher by a swap back).
    function withdraw(uint256 shareAmount) external {
        require(shares[msg.sender] >= shareAmount, "insufficient shares");
        uint256 owed = (shareAmount * pricePerShare()) / 1e18;
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        require(underlying.transfer(msg.sender, owed), "transfer failed");
    }
}
