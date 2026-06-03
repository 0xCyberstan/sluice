// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:        Spartan Protocol (SPARTA) — May 2, 2021
// Approximate loss: ~$30M
// Expected detector: oracle-manipulation
//
// Root cause: Spartan's liquidity-removal payout was computed from the pool's
// CURRENT token balances (`token.balanceOf(pool)` spot share math) rather than
// from cached/checkpointed reserves. The attacker flash-loaned funds, swapped
// to skew the pool's live BNB/SPARTA balances, then called the removal path so
// the balanceOf-based share calculation valued their LP tokens at the inflated
// spot ratio — paying out far more than was deposited. The pool then synced its
// reserves to the manipulated balances, and the attacker unwound the swap and
// repaid the flash loan. There is NO TWAP and NO robust oracle: the valuation
// is an instantaneous, single-transaction-movable `balanceOf` read.

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract SpartanPool {
    address public immutable pool;   // address holding the pooled BASE/TOKEN
    IERC20 public immutable base;    // e.g. SPARTA
    IERC20 public immutable token;   // e.g. BNB-pegged token
    IERC20 public immutable lpToken; // pool share token (LP)

    uint256 public baseReserve;      // accounting: cached base reserve
    uint256 public tokenReserve;     // accounting: cached token reserve

    constructor(address _pool, IERC20 _base, IERC20 _token, IERC20 _lp) {
        pool = _pool;
        base = _base;
        token = _token;
        lpToken = _lp;
    }

    // VULNERABLE: the payout owed for `units` LP is derived from the pool's
    // LIVE balances via `balanceOf(pool)` spot share math. Both balances are
    // single-transaction-movable (flash-loan-assisted swap) — no TWAP, no
    // cached/checkpointed reserve is used for the valuation.
    function calcShare(uint256 units, uint256 spotBalance) internal view returns (uint256) {
        uint256 totalLp = lpToken.totalSupply();
        return (spotBalance * units) / totalLp; // proportional to manipulable spot balance
    }

    // External entry point: attacker skews the pool's live balances first, then
    // calls this so the balanceOf-based share math overpays.
    function removeLiquidity(uint256 units) external returns (uint256 outBase, uint256 outToken) {
        uint256 spotBase = base.balanceOf(pool);   // spot, attacker-movable
        uint256 spotToken = token.balanceOf(pool); // spot, attacker-movable

        outBase = calcShare(units, spotBase);
        outToken = calcShare(units, spotToken);

        // Reserves are re-synced to the manipulated balances (accounting writes).
        baseReserve = spotBase - outBase;
        tokenReserve = spotToken - outToken;

        require(base.transfer(msg.sender, outBase), "base out failed");
        require(token.transfer(msg.sender, outToken), "token out failed");
    }
}
