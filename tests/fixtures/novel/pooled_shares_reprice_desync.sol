// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Bug class:  Pooled-shares reprice desync (assets slashed without burning the
//             matching shares)
// Based on:   Symbiotic Core — src/contracts/vault/Vault.sol onSlash, which
//             decrements `withdrawals[epoch]` (pooled assets) on a slash, while
//             withdrawalsOf()/_claim() price a claim as
//             previewRedeem(shares, withdrawals[epoch], withdrawalShares[epoch]).
//
// Root cause: a withdrawal epoch is an ERC4626-style pool: `withdrawals[epoch]` is
// the pooled assets and `withdrawalShares[epoch]` the pooled shares; a claim is
// `assets = withdrawals[epoch] * shares / withdrawalShares[epoch]`. The slash path
// reduces the ASSET side but leaves the SHARE side untouched, so the per-share
// price drops yet the share supply is unchanged. Early claimers redeem at the old
// ratio and drain a disproportionate slice, leaving late claimers short — a
// reprice desynchronization between pooled assets and pooled shares.

contract PooledSharesRepriceDesync {
    mapping(uint256 => uint256) public withdrawals;      // pooled assets per epoch
    mapping(uint256 => uint256) public withdrawalShares; // pooled shares per epoch
    mapping(uint256 => mapping(address => uint256)) public withdrawalSharesOf;

    function seed(uint256 epoch, uint256 assets, uint256 shares) external {
        withdrawals[epoch] = assets;
        withdrawalShares[epoch] = shares;
        withdrawalSharesOf[epoch][msg.sender] = shares;
    }

    // VULNERABLE: slash decrements the pooled ASSETS but NOT the pooled SHARES, so
    // the asset/share ratio used by previewRedeem silently shifts.
    function onSlash(uint256 epoch, uint256 amount) external {
        uint256 pooled = withdrawals[epoch];
        uint256 slashed = amount < pooled ? amount : pooled;
        withdrawals[epoch] = pooled - slashed; // withdrawalShares[epoch] left stale
    }

    function previewRedeem(uint256 epoch, uint256 shares) public view returns (uint256) {
        uint256 supply = withdrawalShares[epoch];
        if (supply == 0) return 0;
        return (withdrawals[epoch] * shares) / supply;
    }

    function claim(uint256 epoch) external returns (uint256 assets) {
        uint256 shares = withdrawalSharesOf[epoch][msg.sender];
        assets = previewRedeem(epoch, shares);
        withdrawalSharesOf[epoch][msg.sender] = 0;
        withdrawals[epoch] -= assets;
        withdrawalShares[epoch] -= shares;
    }
}
