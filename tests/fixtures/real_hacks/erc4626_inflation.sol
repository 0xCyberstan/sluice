// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident: ERC-4626 first-depositor "inflation" / share-price donation attack
// (vulnerability class; many incidents, e.g. early Rari/Fei, Hundred Finance,
// and numerous audited vaults; individual losses ranged from a few $k to >$1M).
// Root cause: an empty vault prices shares from a DONATABLE balance --
// totalAssets() == asset.balanceOf(address(this)) -- and mints
// shares = assets * totalSupply / totalAssets() with round-down division and
// NO virtual shares / decimal offset / dead shares. The first depositor mints
// 1 wei of shares, transfers a large amount of the underlying directly to the
// vault to inflate totalAssets(), and every subsequent deposit then rounds to
// zero shares, letting the attacker redeem the victims' principal.
// Expected detector: vault

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract InflatableVault {
    IERC20 public immutable asset;
    uint256 public totalSupply; // total shares
    mapping(address => uint256) public balanceOf; // shares per holder

    constructor(IERC20 _asset) {
        asset = _asset;
    }

    // Donatable: a raw token balance, NOT internally tracked accounting.
    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        uint256 supply = totalSupply;
        // First depositor: 1:1. Afterwards rounds down; once totalAssets() is
        // inflated by a direct donation, this truncates to zero shares.
        shares = supply == 0 ? assets : (assets * supply) / totalAssets();
        asset.transferFrom(msg.sender, address(this), assets);
        totalSupply = supply + shares;
        balanceOf[receiver] += shares;
    }

    function redeem(uint256 shares, address receiver) external returns (uint256 assets) {
        uint256 supply = totalSupply;
        assets = (shares * totalAssets()) / supply;
        balanceOf[msg.sender] -= shares;
        totalSupply = supply - shares;
        asset.transfer(receiver, assets);
    }
}
