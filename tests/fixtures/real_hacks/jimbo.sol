// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:        Jimbos Protocol (JIMBO) — May 28, 2023 (Arbitrum)
// Approximate loss: ~$7.5M (≈4,090 ETH)
// Expected detector: oracle-manipulation
//
// Root cause: Jimbos kept its protocol-owned liquidity in a Uniswap V3 ETH-JIMBO
// pool and periodically "shifted" that liquidity into a new range. The shift /
// rebalance path read the pool's LIVE spot price straight from `slot0()` (the
// current sqrtPriceX96 / tick) and re-deployed the protocol's reserves around
// that price, with NO price-impact / slippage check and NO manipulation
// resistance. The attacker flash-loaned 10,000 ETH, swapped it into the pool to
// skew the spot price far from fair value, then called the permissionless shift
// so the protocol concentrated its liquidity at the manipulated price. The
// attacker swapped JIMBO back to ETH against that mis-placed liquidity and
// repaid the flash loan, extracting the difference. There is NO TWAP and NO
// external oracle: the price driving the fund movement is an instantaneous,
// single-transaction-movable `slot0()` read.

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IUniswapV3Pool {
    // Instantaneous pool price -> attacker-movable inside one transaction.
    function slot0() external view returns (
        uint160 sqrtPriceX96,
        int24 tick,
        uint16 observationIndex,
        uint16 observationCardinality,
        uint16 observationCardinalityNext,
        uint8 feeProtocol,
        bool unlocked
    );
}

contract JimboController {
    IUniswapV3Pool public immutable pool; // Uniswap V3 ETH-JIMBO pool
    IERC20 public immutable weth;
    IERC20 public immutable jimbo;

    uint256 public deployedWeth;  // accounting: protocol-owned WETH in range
    uint256 public deployedJimbo; // accounting: protocol-owned JIMBO in range

    constructor(IUniswapV3Pool _pool, IERC20 _weth, IERC20 _jimbo) {
        pool = _pool;
        weth = _weth;
        jimbo = _jimbo;
    }

    // VULNERABLE: derive the JIMBO/WETH price from the pool's SPOT `slot0()`
    // sqrtPriceX96. price = (sqrtP^2) >> 192. This is a live, single-
    // transaction-movable read — no TWAP, no external oracle.
    function spotPrice() public view returns (uint256) {
        (uint160 sqrtPriceX96, , , , , , ) = pool.slot0(); // spot, attacker-movable
        uint256 sp = uint256(sqrtPriceX96);
        return (sp * sp) >> 192; // JIMBO priced in WETH at the instantaneous tick
    }

    // Permissionless rebalance: move the protocol's reserves into a new range
    // valued at the manipulable spot price. The attacker pumps the pool first,
    // then calls this so liquidity is concentrated at the skewed price and can
    // be drained by swapping back.
    function shift() external {
        uint256 price = spotPrice();
        uint256 wethBal = weth.balanceOf(address(this));
        uint256 jimboBal = jimbo.balanceOf(address(this));

        // Re-deploy using the spot price to size the JIMBO leg against WETH.
        // No slippage / price-impact guard: a manipulated `price` mis-places
        // the whole position.
        uint256 jimboForRange = (wethBal * price) >> 0;
        deployedWeth = wethBal;
        deployedJimbo = jimboForRange <= jimboBal ? jimboForRange : jimboBal;

        // Push the reserves to the pool at the manipulated valuation.
        require(weth.transfer(address(pool), deployedWeth), "weth deploy failed");
        require(jimbo.transfer(address(pool), deployedJimbo), "jimbo deploy failed");
    }
}
