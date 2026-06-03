// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Bug class:  Checkpoint hint trust (unvalidated caller-supplied checkpoint index)
// Based on:   Symbiotic Core — src/contracts/libraries/Checkpoints.sol
//             (Trace256.upperLookupRecent(self, key, hint_)), consumed by
//             VaultStorage.activeStakeAt / NetworkRestakeDelegator stake lookups.
//
// Root cause: a historical-value lookup accepts an off-chain `hint` (an index into
// the checkpoint array) and returns `_checkpoints[hint]._value` WITHOUT re-checking
// that the checkpoint at that index actually corresponds to the requested `key`
// (timestamp). The real library guards with `if (checkpoint._key == key) return ...`
// plus an adjacency check (`at(hint+1)._key > key`); here both guards are removed,
// so a caller picks ANY index and is served that checkpoint's value as if it were
// the value active at `key`. Slashing / balance math then prices against an
// attacker-chosen historical stake.

contract CheckpointHintTrust {
    struct Checkpoint {
        uint48 key;   // timestamp at which `value` became active
        uint208 value; // stake / shares recorded at `key`
    }

    Checkpoint[] private _checkpoints;

    function push(uint48 key, uint208 value) external {
        _checkpoints.push(Checkpoint({key: key, value: value}));
    }

    // VULNERABLE: trusts the caller-supplied `hint` index and returns that
    // checkpoint's value with NO `require(_checkpoints[hint].key == key)` re-check
    // and no adjacency check. Any index can be passed to forge the value at `key`.
    function stakeAt(uint48 key, uint32 hint) external view returns (uint208) {
        return _checkpoints[hint].value;
    }
}
