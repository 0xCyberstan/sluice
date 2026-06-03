// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Bug class:  Epoch-boundary staleness (decision reads live state, not the
//             capture-epoch snapshot)
// Based on:   Symbiotic Core — src/contracts/vault/VaultStorage.sol
//             (activeStakeAt(timestamp,hint) vs activeStake()) and
//             src/contracts/vault/Vault.sol onSlash, which slashes at a
//             historical `captureTimestamp`.
//
// Root cause: the contract exposes a point-in-time accessor `activeStakeAt(epoch)`
// that returns the stake snapshotted for a given epoch, yet the security-critical
// slashing function ignores it and reads the LIVE `activeStake()` instead. Slashing
// must be computed against the stake at the capture epoch; reading the current
// (post-withdrawal / post-deposit) value lets a staker withdraw between capture and
// slash so the live figure understates what was actually at risk, shrinking the
// slash — an epoch-boundary read-staleness flaw.

contract EpochBoundaryStaleness {
    mapping(uint256 => uint256) private _activeStakeAtEpoch; // snapshot per epoch
    uint256 private _activeStakeLive;                        // current live stake
    uint256 public cumulativeSlashed;

    function setEpochStake(uint256 epoch, uint256 amount) external {
        _activeStakeAtEpoch[epoch] = amount;
    }

    function setLiveStake(uint256 amount) external {
        _activeStakeLive = amount;
    }

    // Point-in-time accessor: the correct source of truth for a capture epoch.
    function activeStakeAt(uint256 epoch) public view returns (uint256) {
        return _activeStakeAtEpoch[epoch];
    }

    // Live accessor.
    function activeStake() public view returns (uint256) {
        return _activeStakeLive;
    }

    // VULNERABLE: slashing decision is bounded by the LIVE stake, not by
    // activeStakeAt(captureEpoch). The captureEpoch argument is accepted but never
    // used to read the snapshot, so the slash is computed against stale live state.
    function slash(uint256 captureEpoch, uint256 amount) external returns (uint256 slashed) {
        uint256 slashable = activeStake(); // BUG: should be activeStakeAt(captureEpoch)
        slashed = amount < slashable ? amount : slashable;
        _activeStakeLive -= slashed;
        cumulativeSlashed += slashed;
    }
}
