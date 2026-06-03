// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture for the `pooled-shares-reprice-desync` detector.
//
// Symbiotic withdrawal-queue-under-slashing class: per-key pooled assets and
// per-key share supply are priced proportionally (previewRedeem /
// convertToAssets), so the two mappings are a single priced pool that must move
// in lockstep. A privileged/external path that mutates the pooled assets for a
// key WITHOUT updating the paired share supply for that same key silently
// reprices every outstanding share.

// ---------------------------------------------------------------------------
// VULNERABLE: `onSlash` reduces the per-epoch pooled assets but never touches
// the per-epoch share supply, while `previewRedeem` prices a claim as
// withdrawals[epoch] * shares / withdrawalShares[epoch].  EXPECT a finding on
// `onSlash`.
// ---------------------------------------------------------------------------
contract VulnerableWithdrawalQueue {
    mapping(uint256 => uint256) public withdrawals;       // pooled assets / epoch
    mapping(uint256 => uint256) public withdrawalShares;  // share supply  / epoch
    address public slasher;

    // The repricing site (the invariant): assets[k] * s / shares[k].
    function previewRedeem(uint256 epoch, uint256 s) public view returns (uint256) {
        return withdrawals[epoch] * s / withdrawalShares[epoch];
    }

    // Safe co-update: deposits scale BOTH sides for the same epoch.
    function requestWithdraw(uint256 epoch, uint256 assets, uint256 s) external {
        withdrawals[epoch] += assets;
        withdrawalShares[epoch] += s;
    }

    // BUG: slashing moves the numerator only; the denominator is frozen, so the
    // per-share price jumps for every holder of `epoch`.
    function onSlash(uint256 epoch, uint256 slashed) external {
        require(msg.sender == slasher, "auth");
        withdrawals[epoch] -= slashed;
    }
}

// ---------------------------------------------------------------------------
// SAFE (co-update): the slashing path scales BOTH the pooled assets and the
// share supply for the same epoch, preserving the per-share price.  EXPECT no
// finding.
// ---------------------------------------------------------------------------
contract SafeCoupdateWithdrawalQueue {
    mapping(uint256 => uint256) public withdrawals;
    mapping(uint256 => uint256) public withdrawalShares;
    address public slasher;

    function previewRedeem(uint256 epoch, uint256 s) public view returns (uint256) {
        return withdrawals[epoch] * s / withdrawalShares[epoch];
    }

    function requestWithdraw(uint256 epoch, uint256 assets, uint256 s) external {
        withdrawals[epoch] += assets;
        withdrawalShares[epoch] += s;
    }

    function onSlash(uint256 epoch, uint256 slashed, uint256 burnShares) external {
        require(msg.sender == slasher, "auth");
        withdrawals[epoch] -= slashed;
        withdrawalShares[epoch] -= burnShares; // co-update keeps the ratio
    }
}

// ---------------------------------------------------------------------------
// SAFE (no repricing): two per-epoch mappings are bookkept independently and are
// never divided against each other, so there is no proportional price to
// desync.  EXPECT no finding.
// ---------------------------------------------------------------------------
contract SafeNoReprice {
    mapping(uint256 => uint256) public withdrawals;
    mapping(uint256 => uint256) public withdrawalShares;

    function bumpAssets(uint256 epoch, uint256 a) external {
        withdrawals[epoch] += a;
    }

    function bumpShares(uint256 epoch, uint256 s) external {
        withdrawalShares[epoch] += s;
    }
}
