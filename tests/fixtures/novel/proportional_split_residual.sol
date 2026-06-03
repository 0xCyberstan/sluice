// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Bug class:  Proportional-split residual misassignment (rounding dust dumped on
//             one bucket)
// Based on:   Symbiotic Core — src/contracts/vault/Vault.sol onSlash, where the
//             slash is split across active stake / current-epoch withdrawals /
//             next-epoch withdrawals via mulDiv and the LAST share is computed as
//             `slashedAmount - activeSlashed - nextWithdrawalsSlashed`.
//
// Root cause: a total `amt` is split across buckets proportionally with floored
// integer `mulDiv`, then the remainder `c = amt - a - b` is assigned wholesale to
// ONE bucket to make the parts sum to `amt`. Because `a` and `b` round DOWN, the
// residual `c` absorbs ALL the truncation from every other bucket, so that single
// bucket is slashed more than its fair proportional share. Repeated/structured
// slashes let an actor steer the dust onto a victim bucket.

contract ProportionalSplitResidual {
    uint256 public bucketA; // active stake
    uint256 public bucketB; // next-epoch withdrawals
    uint256 public bucketC; // current-epoch withdrawals (receives the residual)

    function fund(uint256 a, uint256 b, uint256 c) external {
        bucketA = a;
        bucketB = b;
        bucketC = c;
    }

    // VULNERABLE: a and b are floored proportional shares; c takes the entire
    // leftover `amt - a - b`, so bucketC eats every other bucket's rounding loss
    // instead of being slashed by its own proportional (and floored) share.
    function onSlash(uint256 amt) external {
        uint256 total = bucketA + bucketB + bucketC;
        require(total > 0, "empty");
        uint256 wA = bucketA;
        uint256 wB = bucketB;

        uint256 a = (amt * wA) / total;
        uint256 b = (amt * wB) / total;
        uint256 c = amt - a - b; // residual dumped on bucketC

        bucketA -= a;
        bucketB -= b;
        bucketC -= c;
    }
}
