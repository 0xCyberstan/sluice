// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:         Saddle Finance — sUSDv2 metapool exploit (Apr 30, 2022)
// Approximate loss:  ~$10M (reported ~$11.9M gross drained from the sUSD metapool)
// Expected detector: rounding-direction
//
// Root cause: Saddle metapools price the base-pool LP token (saddleUSD) against the
// meta asset (sUSD) using the Curve-style StableSwap y-math. The LP token's true
// value is its VIRTUAL PRICE — `D * 1e18 / totalSupply`, a >1e18 quantity that
// drifts up as fees accrue. The buggy `MetaSwapUtils` deployment normalized the LP
// leg with a flat `tokenPrecisionMultiplier` (a plain 10**k scalar) instead of the
// virtual price, so the swap math never scaled the LP amount UP on the way in nor
// DOWN on the way out. The payout leg reduced to:
//
//     dy = xp[to].sub(y).sub(1);
//     dy = dy.sub(dyFee).div(tokenPrecisionMultipliers[to]);   // MetaSwapUtils:424
//
// i.e. a multiply-then-divide (`amount * supply / D`, then `/ precision`) with no
// pinned rounding mode. Solidity integer division truncates toward zero, so every
// leg that pays out the LP token floors the result in the *trader's* favor instead
// of the pool's. The attacker flash-borrowed sUSD and swapped sUSD<->LP back and
// forth through the mispriced curve; because the LP token was valued at its raw
// (precision-scaled) balance rather than `balance * virtualPrice / 1e18`, each
// round-trip returned slightly more value than it should, and ~14.8M sUSD round-
// tripped into ~16.8M.
//
// Reconstructed below: a metapool whose LP<->meta conversion divides
// (`amount * totalSupply / D`, then by precision) with no ceil/floor control. The
// virtual price that belongs in the numerator/denominator is omitted, so the
// conversion rounds toward the user on the LP payout path.

contract SaddleMetaPool {
    uint256 public D;                 // StableSwap invariant of the base pool
    uint256 public lpTotalSupply;     // saddleUSD LP total supply
    uint256 public metaBalance;       // sUSD held by the metapool (meta asset)
    uint256 public lpBalance;         // saddleUSD LP held by the metapool

    // Flat precision scalars (10**(18-decimals)) — the ONLY normalization the buggy
    // deployment applied to the LP leg, standing in for the missing virtual price.
    uint256 public constant LP_PRECISION = 1;
    uint256 public constant FEE_DENOMINATOR = 1e10;
    uint256 public swapFee = 4_000_000; // 4 bps in 1e10 terms

    // Deposit the meta asset (sUSD) and receive base LP tokens (saddleUSD).
    // The LP amount minted is `dx * lpTotalSupply / D` then de-scaled only by the
    // flat precision factor — an `a * b / c` truncating division with no rounding
    // mode. The LP virtual price (`D * 1e18 / lpTotalSupply`) that should size this
    // conversion is absent, so the floor rounds the LP payout toward the caller.
    function deposit(uint256 dx) external returns (uint256 lpOut) {
        uint256 dxFee = (dx * swapFee) / FEE_DENOMINATOR;
        uint256 dxAfter = dx - dxFee;
        // multiply-then-divide proportional conversion; truncates in caller's favor
        lpOut = (dxAfter * lpTotalSupply) / D / LP_PRECISION;
        metaBalance += dx;
        lpBalance -= lpOut;
    }

    // Burn base LP tokens and receive the meta asset back. Same flawed normalization
    // on the reverse leg: `lpIn * D / lpTotalSupply` floored, no ceil on the asset
    // payout. Round-tripping deposit()/withdraw() banks the rounding difference.
    function withdraw(uint256 lpIn) external returns (uint256 metaOut) {
        uint256 lpFee = (lpIn * swapFee) / FEE_DENOMINATOR;
        uint256 lpAfter = lpIn - lpFee;
        metaOut = (lpAfter * D) / lpTotalSupply / LP_PRECISION;
        lpBalance += lpIn;
        metaBalance -= metaOut;
    }
}
