// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:        Warp Finance — December 17, 2020
// Approximate loss: ~$8M (later partially recovered)
// Expected detector: oracle-manipulation
//
// Root cause: Warp accepted Uniswap V2 LP tokens as collateral and valued them
// from the pair's LIVE state — the spot reserves from `getReserves()` (plus the
// tokens the pair holds) divided by the LP `totalSupply()`. That per-LP price is
// an instantaneous on-chain read with NO TWAP and NO Chainlink feed. The attacker
// flash-loaned, swapped a large amount into the pair to skew its reserves, which
// inflated the reported per-LP value, deposited LP collateral valued at the
// distorted price, and borrowed far more stablecoin than the collateral was worth
// before the pool re-balanced. The over-valued borrow power is the bug.

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IUniswapV2Pair {
    // Spot reserves of the pair — movable within a single transaction.
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function totalSupply() external view returns (uint256);
    function token0() external view returns (address);
    function token1() external view returns (address);
}

contract WarpLPLending {
    IUniswapV2Pair public immutable pair;   // Uniswap V2 LP token used as collateral
    IERC20 public immutable debtToken;      // borrowable stablecoin

    mapping(address => uint256) public collateralLP; // LP tokens posted per user
    mapping(address => uint256) public debtOf;

    constructor(IUniswapV2Pair _pair, IERC20 _debtToken) {
        pair = _pair;
        debtToken = _debtToken;
    }

    // VULNERABLE: per-LP price derived from the pair's instantaneous reserves.
    // `getReserves()` is a spot read an attacker can move with a flash-loaned
    // swap; combined with `balanceOf` of the held tokens and divided by the LP
    // supply, it yields an over-valued price. No TWAP, no robust oracle.
    function lpPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves(); // spot, attacker-movable
        uint256 bal0 = IERC20(pair.token0()).balanceOf(address(pair)); // spot reserve held by pair
        uint256 bal1 = IERC20(pair.token1()).balanceOf(address(pair)); // spot reserve held by pair
        uint256 poolValue = uint256(r0) + uint256(r1) + bal0 + bal1;   // naive spot sum
        return (poolValue * 1e18) / pair.totalSupply();                // value of one LP, spot only
    }

    function collateralValue(address user) public view returns (uint256) {
        return (collateralLP[user] * lpPrice()) / 1e18;
    }

    function depositCollateral(uint256 lpAmount) external {
        IERC20(address(pair)).transferFrom(msg.sender, address(this), lpAmount);
        collateralLP[msg.sender] += lpAmount;
    }

    function borrow(uint256 amount) external {
        // Borrow power granted by the manipulable spot valuation of the LP collateral.
        require(debtOf[msg.sender] + amount <= collateralValue(msg.sender), "undercollateralized");
        debtOf[msg.sender] += amount;
        debtToken.transfer(msg.sender, amount);
    }
}
