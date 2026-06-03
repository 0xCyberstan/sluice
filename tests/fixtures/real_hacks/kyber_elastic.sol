// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:         KyberSwap Elastic (multi-chain) — November 22-23, 2023
// Approximate loss:  ~$48,000,000 (drained across Ethereum, Arbitrum, Optimism,
//                     Polygon and Base concentrated-liquidity pools)
// Expected detector: integer-issues
//
// Root cause: a precision / rounding defect in the concentrated-liquidity swap
// step math that let the attacker DOUBLE-COUNT liquidity at a tick boundary.
//
// In `computeSwapStep`, the amount needed to move price exactly to the next
// tick's `targetSqrtP` is derived from an *incremental reinvestment liquidity*
// term (`deltaL`). That term was meant to be rounded UP so the resulting price
// would be rounded DOWN and stay at-or-below the boundary. Instead it was
// rounded DOWN (a floor division — `mulDivFloor`), so the computed `nextSqrtP`
// was nudged slightly ABOVE `targetSqrtP`. The "did we cross the tick?" decision
// is an INEQUALITY on the consumed amount (`usedAmount > specifiedAmount`), and
// by sizing the swap so that `specifiedAmount = usedAmount - 1` the attacker made
// that check conclude the tick was NOT crossed — even though `nextSqrtP` had
// actually passed the boundary. The pool therefore advanced `currentSqrtP` past
// the tick WITHOUT running the cross routine. On the very next step the tick was
// crossed "again", so `_updateLiquidityAndCrossTick` applied the boundary's
// `liquidityNet` to `baseL` a second time: the same liquidity was counted twice,
// inflating `baseL` far above the real reserves and letting the attacker swap out
// almost the entire pool.
//
// The defect is an INTEGER hazard: a truncating (floor) division whose rounding
// direction is wrong on attacker-sized input, a narrowing `uint128(...)` downcast
// of an attacker-influenced amount in the liquidity-delta math, and the
// `liquidityNet`->`baseL` apply done in an `unchecked { }` block that silently
// wraps/truncates the doubled liquidity instead of reverting.

contract KyberElasticPool {
    uint128 public baseL;        // active in-range liquidity (the double-counted value)
    uint160 public currentSqrtP; // current sqrt price (Q64.96)
    int24 public currentTick;

    // Per-tick net liquidity to apply when the tick is crossed upward.
    mapping(int24 => int128) public liquidityNet;
    mapping(int24 => uint160) public tickSqrtP;

    constructor(uint128 _baseL, uint160 _sqrtP, int24 _tick) {
        baseL = _baseL;
        currentSqrtP = _sqrtP;
        currentTick = _tick;
    }

    // Incremental reinvestment-liquidity term. The comment in the original said
    // this must be rounded UP (so price rounds down and stays <= targetSqrtP);
    // the bug is the FLOOR division `(a * b) / d`, which rounds it DOWN and lets
    // the derived next price overshoot the boundary. `absDelta` and `liquidity`
    // are attacker-sized via the swap amount; the divisor is attacker-influenced.
    function estimateIncrementalLiquidity(
        uint256 absDelta,
        uint256 liquidity,
        uint160 nextSqrtP
    ) public pure returns (uint256 deltaL) {
        // truncating (round-toward-zero) division on attacker input: the wrong
        // rounding direction is exactly what shifts nextSqrtP past targetSqrtP.
        deltaL = (absDelta * liquidity) / uint256(nextSqrtP);
    }

    // One swap step. Returns how much input was consumed (`usedAmount`) and the
    // resulting price. Because `deltaL` was floored above, `nextSqrtP` can land
    // ABOVE `targetSqrtP`, while `usedAmount` is reported as <= specifiedAmount.
    function computeSwapStep(
        uint256 specifiedAmount,
        uint160 targetSqrtP,
        uint256 liquidity
    ) public view returns (uint256 usedAmount, uint160 nextSqrtP, bool crossed) {
        uint256 deltaL = estimateIncrementalLiquidity(specifiedAmount, liquidity, targetSqrtP);

        // narrowing downcast of an attacker-influenced amount: the high bits of a
        // crafted `specifiedAmount + deltaL` are silently dropped, so `usedAmount`
        // can be made to differ from the real consumed amount and dodge the check.
        usedAmount = uint128(specifiedAmount + deltaL);

        // attacker sets specifiedAmount = usedAmount - 1, so this inequality says
        // "tick not crossed" even though nextSqrtP overshoots the boundary below.
        crossed = usedAmount > specifiedAmount;

        // floored math overshoots: nextSqrtP ends up just past targetSqrtP.
        nextSqrtP = uint160(uint256(targetSqrtP) + (deltaL == 0 ? 0 : 1));
    }

    // Crossing a tick applies its net liquidity to the active liquidity. Done in
    // an `unchecked` block so the doubled `liquidityNet` add wraps/truncates into
    // `uint128` instead of reverting — this is where the second count lands.
    function _updateLiquidityAndCrossTick(int24 tick) internal {
        int128 net = liquidityNet[tick];
        unchecked {
            // baseL (uint128) +/- net (int128): on the doubled cross this silently
            // inflates baseL past the real reserves.
            baseL = net >= 0
                ? baseL + uint128(uint256(int256(net)))
                : baseL - uint128(uint256(int256(-net)));
        }
        currentTick = tick;
    }

    // VULNERABLE swap entry. The step says the boundary tick was not crossed, so
    // the pool advances price past it WITHOUT crossing — then the next step
    // crosses it, double-applying liquidityNet and inflating baseL.
    function swap(uint256 specifiedAmount, int24 targetTick) external {
        uint160 targetSqrtP = tickSqrtP[targetTick];
        (uint256 used, uint160 nextSqrtP, bool crossed) =
            computeSwapStep(specifiedAmount, targetSqrtP, uint256(baseL));

        // Advance price using the overshot value. Because `crossed` is false, the
        // cross routine is skipped here even though nextSqrtP passed targetSqrtP.
        currentSqrtP = nextSqrtP;
        require(used <= specifiedAmount, "exceeds input");

        if (!crossed) {
            // The boundary was effectively passed but not crossed; the subsequent
            // cross double-counts the tick's liquidity.
            _updateLiquidityAndCrossTick(targetTick);
        }
    }

    function setTick(int24 tick, int128 net, uint160 sqrtP) external {
        liquidityNet[tick] = net;
        tickSqrtP[tick] = sqrtP;
    }
}
