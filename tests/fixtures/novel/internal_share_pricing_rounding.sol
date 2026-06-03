// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Bug class:  Internal share-pricing rounding (floored conversion on a hidden
//             internal pricing helper)
// Based on:   Symbiotic Core — src/contracts/delegator/NetworkRestakeDelegator.sol
//             _stakeAt (operatorShares.mulDiv(min(activeStake, networkLimit),
//             totalOperatorNetworkShares)) and ERC4626Math.convertToAssets
//             (Math.Rounding.Floor).
//
// Root cause: an INTERNAL helper converts shares to an underlying stake amount with
// a floored integer `mulDiv`: `totalStake * frac / DENOM`. Because the function is
// internal and is NOT named like a public conversion entry point (no
// convertToAssets / previewRedeem / stakeAt signature for an analyzer to special-
// case), its rounding direction goes unreviewed. Flooring here truncates value on
// every call; an attacker structures many small slices so the per-call dust
// accumulates into a meaningful, repeatable loss against the pool.

contract InternalSharePricingRounding {
    uint256 public constant DENOM = 1e18;
    uint256 public totalStake;

    function setTotalStake(uint256 amount) external {
        totalStake = amount;
    }

    // VULNERABLE: internal floored conversion. `frac` is a share fraction scaled by
    // DENOM; the floored `mulDiv` silently rounds value down on each call, and the
    // helper's name hides it from conversion-aware review.
    function _stakeAt(uint256 frac) internal view returns (uint256) {
        return (totalStake * frac) / DENOM; // floor
    }

    function quoteSlice(uint256 frac) external view returns (uint256) {
        return _stakeAt(frac);
    }
}
