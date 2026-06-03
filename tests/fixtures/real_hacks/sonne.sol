// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident: Sonne Finance (Compound V2 fork) empty-market exploit — May 14, 2024.
// Approximate loss: ~$20M (Optimism; another ~$6.5M front-run / rescued).
// Expected detector: vault
//
// Root cause (cToken first-mint / exchange-rate inflation, a.k.a. the Compound v2
// "donation" attack also seen in Hundred Finance / Onyx):
//   A brand-new market (soVELO) was created with ZERO supply. A cToken prices
//   itself as
//       exchangeRate = (getCash() + totalBorrows - totalReserves) / totalSupply
//   where getCash() == underlying.balanceOf(address(this)) — a DONATABLE balance,
//   NOT internally tracked accounting. When totalSupply == 0 the contract falls
//   back to a fixed initialExchangeRate (the empty-market first-mint branch), with
//   NO virtual shares / decimal offset / dead shares to anchor the price.
//   The attacker minted a tiny amount of cToken (2 wei of soVELO), then transferred
//   a large amount of the underlying directly into the market to inflate getCash()
//   (so 2 wei of soVELO was valued at ~35.4M VELO). Because mint divides
//   mintAmount/exchangeRate (round-down) and redeemUnderlying divides
//   redeemAmount/exchangeRate ROUNDING UP, the attacker redeemed almost all the
//   donated + borrowed underlying while burning ~1 wei of cToken, draining the pool.

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract SonneCToken {
    IERC20 public immutable underlying;

    uint256 public totalSupply;      // cToken shares
    uint256 public totalBorrows;
    uint256 public totalReserves;
    mapping(address => uint256) public balanceOf; // cToken shares per holder

    // Fixed price used ONLY while the market is empty (totalSupply == 0).
    uint256 public constant initialExchangeRate = 2e26; // 0.02 scaled by 1e18 (Compound default)

    constructor(IERC20 _underlying) {
        underlying = _underlying;
    }

    // Donatable: the market's raw underlying balance, not internal accounting.
    function getCash() public view returns (uint256) {
        return underlying.balanceOf(address(this));
    }

    // exchangeRate = (cash + borrows - reserves) / totalSupply, scaled by 1e18.
    // First mint (empty market) returns the fixed initialExchangeRate.
    function exchangeRateStored() public view returns (uint256) {
        uint256 supply = totalSupply;
        if (supply == 0) {
            return initialExchangeRate;
        }
        return ((getCash() + totalBorrows - totalReserves) * 1e18) / supply;
    }

    // Deposit underlying, receive cToken. Round-DOWN truncation of shares.
    function mint(uint256 mintAmount) external returns (uint256 shares) {
        uint256 rate = exchangeRateStored();
        underlying.transferFrom(msg.sender, address(this), mintAmount);
        shares = (mintAmount * 1e18) / rate; // truncates toward zero
        totalSupply += shares;
        balanceOf[msg.sender] += shares;
    }

    // Redeem an exact underlying amount; cToken to burn is rounded UP, but the
    // inflated exchangeRate makes that ~1 wei — the attacker walks with the cash.
    function redeemUnderlying(uint256 redeemAmount) external returns (uint256 burned) {
        uint256 rate = exchangeRateStored();
        burned = (redeemAmount * 1e18 + rate - 1) / rate; // round up
        balanceOf[msg.sender] -= burned;
        totalSupply -= burned;
        underlying.transfer(msg.sender, redeemAmount);
    }
}
