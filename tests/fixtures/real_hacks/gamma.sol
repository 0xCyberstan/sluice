// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:        Gamma Strategies (Hypervisor vaults) — January 4, 2024
// Approximate loss: ~$6.2M (stablecoin + LST vaults on Arbitrum)
// Expected detector: oracle-manipulation
//
// Root cause: the Hypervisor deposit path valued an incoming deposit using the
// SPOT state of the underlying Uniswap-style pool — `getReserves()` plus the
// token `balanceOf` held by the position — to derive the price/ratio that scales
// the LP shares minted. There is NO TWAP and no independent oracle: the price is
// read live from the same pool an attacker can move within one transaction.
//
// The only protection was a price-deviation guard comparing the deposit-time
// spot price against a reference, but the threshold was misconfigured far too
// wide (-50% / +100% instead of ~2%). An attacker flash-loaned, swapped to push
// the pool's spot price up to the loose threshold, deposited at that inflated
// valuation to mint a disproportionate number of shares, then swapped back and
// withdrew — pocketing the difference. The dominant, reproducible flaw is the
// spot-reserve valuation feeding share minting, not the guard itself.

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IUniswapV2Pair {
    // Instantaneous reserves — single-transaction-movable via a swap.
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

contract GammaHypervisor {
    IUniswapV2Pair public immutable pool;  // underlying spot pool (token0/token1)
    IERC20 public immutable token0;        // deposit asset, accounted in token1 terms
    IERC20 public immutable token1;        // quote / pair asset

    mapping(address => uint256) public shares; // LP shares per depositor
    uint256 public totalShares;

    constructor(IUniswapV2Pair _pool, IERC20 _token0, IERC20 _token1) {
        pool = _pool;
        token0 = _token0;
        token1 = _token1;
    }

    // VULNERABLE: price = spot reserve ratio of the underlying pool. Both
    // `getReserves()` and the position `balanceOf` are live, attacker-movable
    // reads — no TWAP, no robust oracle. This price scales the shares minted.
    function getSpotPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = pool.getReserves();
        // token0 priced in token1, plus idle token1 the position already holds.
        uint256 priced = (uint256(reserve1) * 1e18) / uint256(reserve0);
        uint256 idle = token1.balanceOf(address(this)); // spot, attacker-movable
        return priced + idle;
    }

    // Mint shares valued at the manipulable spot price (skewed high by a swap).
    function deposit(uint256 amount0) external returns (uint256 minted) {
        require(token0.transferFrom(msg.sender, address(this), amount0), "transfer failed");
        uint256 price = getSpotPrice();              // spot valuation, no TWAP
        uint256 value = (amount0 * price) / 1e18;     // deposit value in shares units
        minted = totalShares == 0 ? value : (value * totalShares) / _spotTVL();
        shares[msg.sender] += minted;
        totalShares += minted;
    }

    // Redeem shares at the manipulable spot price (restored lower by a swap back).
    function withdraw(uint256 shareAmount) external returns (uint256 owed) {
        require(shares[msg.sender] >= shareAmount, "insufficient shares");
        owed = (shareAmount * _spotTVL()) / totalShares;
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        require(token0.transfer(msg.sender, owed), "transfer failed");
    }

    // Vault TVL is itself derived from the spot price -> compounds the manipulation.
    function _spotTVL() internal view returns (uint256) {
        uint256 bal0 = token0.balanceOf(address(this));
        return (bal0 * getSpotPrice()) / 1e18;
    }
}
