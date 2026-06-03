// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident: Radiant Capital empty-market rounding exploit (Arbitrum) — Jan 3, 2024.
// Approximate loss: ~$4.5M (paused; ~1,190 ETH repaid, ~720 ETH bad debt).
// Expected detector: rounding-direction
//
// Root cause (first-interaction precision/rounding on a freshly-listed market):
//   A brand-new lending market was activated with ZERO liquidity (totalSupply == 0).
//   On the very first interaction the share/exchange-rate math rounded in the
//   user's favor instead of the protocol's. Radiant (an Aave-V2 fork) updated its
//   liquidity index with a ray-scaled formula of the shape (a * RAY + b/2) / b
//   and converted between underlying and aToken shares with bare integer
//   division and NO virtual shares / decimal offset / dead shares to anchor the
//   first mint. The attacker minted a tiny amount of shares, then drove the
//   index/totalAssets so the proportional conversion truncated, repeatedly
//   harvesting the rounding error until the market's funds were drained.
//
// Reconstructed below as a lending/vault mint where
//     shares = assets * totalSupply / totalAssets   (round-DOWN, truncating)
// with a totalSupply == 0 first-mint branch and no virtual shares — so the
// conversion rounds toward the depositor on every call.

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract RadiantMarket {
    IERC20 public immutable underlying;

    uint256 public totalSupply;  // aToken shares
    mapping(address => uint256) public balanceOf;

    constructor(IERC20 _underlying) {
        underlying = _underlying;
    }

    // Donatable: the market's raw underlying balance, not internal accounting.
    function totalAssets() public view returns (uint256) {
        return underlying.balanceOf(address(this));
    }

    // Deposit underlying, receive aToken shares. First mint (empty market) is
    // 1:1 with NO virtual-share anchor; afterwards shares = assets * supply /
    // totalAssets with a bare truncating division that rounds toward the user.
    function mint(uint256 assets) external returns (uint256 shares) {
        uint256 supply = totalSupply;
        shares = supply == 0 ? assets : assets * supply / totalAssets();
        underlying.transferFrom(msg.sender, address(this), assets);
        totalSupply = supply + shares;
        balanceOf[msg.sender] += shares;
    }

    // Burn shares, receive a proportional slice of underlying — also a bare
    // truncating mul-then-div with no rounding mode pinned in the protocol's
    // favor, paying out the harvested rounding surplus.
    function redeem(uint256 shares) external returns (uint256 assets) {
        uint256 supply = totalSupply;
        assets = shares * totalAssets() / supply;
        balanceOf[msg.sender] -= shares;
        totalSupply = supply - shares;
        underlying.transfer(msg.sender, assets);
    }
}
