// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:        Inverse Finance (Anchor / Frontier money market) — April 2, 2022
// Approximate loss: ~$15.6M (DOLA, ETH, WBTC, YFI drained from the protocol)
// Expected detector: oracle-manipulation
//
// Root cause: Inverse's Anchor oracle priced collateral from the LIVE state of an
// on-chain pool. The INV market read the Sushiswap INV/WETH pair's instantaneous
// `getReserves()` (a Keep3r/SLP spot price) to value INV collateral, and a Curve
// LP collateral was valued from `get_virtual_price()` * the pool's spot `balanceOf`
// reserve. Both are single-transaction-movable reads with NO TWAP and NO robust
// Chainlink feed. The attacker flash-loaned WETH, swapped to pump the INV/WETH spot
// price, posted INV (and the LP) as collateral now valued absurdly high, and
// borrowed out the treasury's DOLA/ETH/WBTC/YFI against that false valuation.

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface ISushiPair {
    // Instantaneous pool reserves — attacker-movable within one transaction.
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

interface ICurvePool {
    // Live virtual price + spot reserve — both single-tx-movable, no TWAP.
    function get_virtual_price() external view returns (uint256);
}

contract InverseAnchorMarket {
    ISushiPair public immutable invWethPair;  // Sushiswap INV/WETH SLP
    ICurvePool public immutable curvePool;    // Curve LP used as a second collateral
    IERC20 public immutable curveLp;          // the LP token posted as collateral
    IERC20 public immutable debtToken;        // borrowable asset (DOLA/ETH/WBTC/YFI)

    mapping(address => uint256) public invCollateral; // INV units posted
    mapping(address => uint256) public lpCollateral;   // Curve LP units posted
    mapping(address => uint256) public debtOf;

    constructor(ISushiPair _pair, ICurvePool _pool, IERC20 _lp, IERC20 _debtToken) {
        invWethPair = _pair;
        curvePool = _pool;
        curveLp = _lp;
        debtToken = _debtToken;
    }

    // VULNERABLE: INV price = WETH reserve / INV reserve from the live SLP pair.
    // `getReserves()` is a spot read; a flash-loan swap moves it within one tx.
    function invPrice() public view returns (uint256) {
        (uint112 invReserve, uint112 wethReserve, ) = invWethPair.getReserves();
        return (uint256(wethReserve) * 1e18) / uint256(invReserve); // spot, no TWAP
    }

    // VULNERABLE: LP price = Curve virtual price scaled by the pool's spot reserve.
    function lpPrice() public view returns (uint256) {
        uint256 vp = curvePool.get_virtual_price();          // spot, attacker-movable
        uint256 reserve = debtToken.balanceOf(address(curvePool)); // spot reserve read
        return (vp * reserve) / 1e18;                        // no robust feed
    }

    function collateralValue(address user) public view returns (uint256) {
        return (invCollateral[user] * invPrice()) / 1e18
             + (lpCollateral[user] * lpPrice()) / 1e18;
    }

    function depositInv(uint256 amount) external { invCollateral[msg.sender] += amount; }
    function depositLp(uint256 amount) external {
        require(curveLp.transferFrom(msg.sender, address(this), amount), "xfer");
        lpCollateral[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        // Borrow power is set entirely by the manipulable spot valuation.
        require(debtOf[msg.sender] + amount <= collateralValue(msg.sender), "undercollateralized");
        debtOf[msg.sender] += amount;
        require(debtToken.transfer(msg.sender, amount), "xfer");
    }
}
