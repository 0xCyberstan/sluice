// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Bug class:  Silenced privileged callback (return value of a settable-target
//             low-level call ignored, accounting advanced anyway)
// Based on:   Symbiotic Core — src/contracts/slasher/BaseSlasher.sol _burnerOnSlash,
//             which does `pop(call(BURNER_GAS_LIMIT, burner, ...))` (return value
//             discarded) and then _updateCumulativeSlash pushes
//             cumulativeSlash + amount.
//
// Root cause: the slash hook invokes the burner via a raw low-level `call` whose
// boolean success result is discarded, then unconditionally credits the slash to
// `cumulativeSlashed`. `burner` is a settable state variable, so a burner that
// reverts (or silently no-ops) does not stop the accounting from recording the
// stake as burned. The protocol's books say collateral was slashed/destroyed while
// it was never actually transferred or burned — a silenced privileged callback.

interface IBurner {
    function onSlash(uint256 amount) external;
}

contract SilencedPrivilegedCallback {
    address public burner;             // settable callback target
    uint256 public cumulativeSlashed;  // accounting advanced regardless of callback

    function setBurner(address burner_) external {
        burner = burner_;
    }

    // VULNERABLE: the burner call's success is ignored, then cumulativeSlashed is
    // incremented unconditionally. A reverting/no-op burner still gets the stake
    // marked as slashed in the books.
    function onSlash(uint256 amount) external {
        bytes memory data = abi.encodeCall(IBurner.onSlash, (amount));
        burner.call(data); // return value not checked

        cumulativeSlashed += amount;
    }
}

// ---------------------------------------------------------------------------
// Negative controls — each defuses exactly one gate clause, so the detector must
// stay silent on all three (precision anchors for the bug above).
// ---------------------------------------------------------------------------

// SAFE (return checked): the burner result is captured and required before the
// slash is booked, so a reverting burner reverts the whole action.
contract CheckedSlasher {
    address public burner;
    uint256 public cumulativeSlashed;

    function setBurner(address burner_) external {
        burner = burner_;
    }

    function onSlash(uint256 amount) external {
        bytes memory data = abi.encodeCall(IBurner.onSlash, (amount));
        (bool ok, ) = burner.call(data);
        require(ok, "burn failed");
        cumulativeSlashed += amount;
    }
}

// SAFE (immutable callee): the burner is fixed at construction, so governance
// cannot repoint it at a misbehaving contract — not a settable-hook problem.
contract ImmutableSlasher {
    address public immutable burner;
    uint256 public cumulativeSlashed;

    constructor(address burner_) {
        burner = burner_;
    }

    function onSlash(uint256 amount) external {
        bytes memory data = abi.encodeCall(IBurner.onSlash, (amount));
        burner.call(data); // ignored, but callee is immutable
        cumulativeSlashed += amount;
    }
}

// SAFE (no finalization): a pure best-effort notification to a settable hook,
// with no accounting finalized afterwards (no later storage write, no emit).
contract Notifier {
    address public hook;

    function setHook(address hook_) external {
        hook = hook_;
    }

    function ping(bytes calldata data) external {
        hook.call(data);
    }
}
