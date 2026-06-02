// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

/// @title SpotPriceLending
/// @notice Lending market that prices collateral using the live spot balance
///         of a token in a pool / AMM reserves. No Chainlink feed, no TWAP --
///         the price is trivially manipulable via a flash-loan that skews the
///         pool reserves within a single transaction.
contract SpotPriceLending {
    IERC20 public immutable collateral;   // e.g. some ERC20
    IERC20 public immutable debtToken;    // e.g. a stablecoin
    IUniswapV2Pair public immutable pair; // collateral/stable pool
    address public immutable pool;        // pool holding `debtToken` liquidity

    mapping(address => uint256) public collateralOf;
    mapping(address => uint256) public debtOf;

    constructor(IERC20 _collateral, IERC20 _debtToken, IUniswapV2Pair _pair, address _pool) {
        collateral = _collateral;
        debtToken = _debtToken;
        pair = _pair;
        pool = _pool;
    }

    /// @notice VULNERABLE: collateral value derived from raw pool balance and
    ///         AMM reserves -- a spot price an attacker controls.
    function collateralValue(address user) public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        // price = stable reserves / collateral balance held by the pool
        uint256 poolStable = debtToken.balanceOf(pool);
        uint256 spotPrice = (uint256(r1) * 1e18) / uint256(r0);
        uint256 amt = collateralOf[user];
        return (amt * spotPrice * poolStable) / (1e18 * (uint256(r0) + 1));
    }

    function depositCollateral(uint256 amount) external {
        collateral.transferFrom(msg.sender, address(this), amount);
        collateralOf[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        // Borrow up to the manipulable spot value of the collateral.
        require(debtOf[msg.sender] + amount <= collateralValue(msg.sender), "undercollateralized");
        debtOf[msg.sender] += amount;
        debtToken.transfer(msg.sender, amount);
    }
}
