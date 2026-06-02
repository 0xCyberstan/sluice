// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:        bZx (Fulcrum/iearn) flash-loan price manipulation, Feb 2020
// Approximate loss: ~$1,000,000 (two incidents, ~$350k + ~$650k)
// Expected detector: oracle-manipulation
//
// Root cause: bZx valued collateral using an on-chain DEX spot price
// (Kyber / Uniswap reserves) instead of a manipulation-resistant feed. An
// attacker used a flash loan to skew the pool reserves within a single
// transaction, inflating the collateral's reported value and borrowing far
// more than the position was actually worth. The reconstruction below reads
// the price from `getReserves()` / `getAmountsOut()` of an AMM pair and uses
// it directly as collateral value -- no TWAP, no Chainlink, no sanity check.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IUniswapV2Pair {
    function getReserves()
        external
        view
        returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

interface IDexRouter {
    // Kyber/Uniswap-style on-the-fly quote -- a spot price, attacker-movable.
    function getAmountsOut(uint256 amountIn, address[] calldata path)
        external
        view
        returns (uint256[] memory amounts);
}

contract BzxMargin {
    IERC20 public immutable loanToken;     // borrowed asset (e.g. stablecoin)
    IUniswapV2Pair public immutable pair;  // collateral/loan AMM pool
    IDexRouter public immutable router;    // DEX router for spot quotes
    address public immutable collateral;   // collateral token address (path[0])

    mapping(address => uint256) public collateralOf;
    mapping(address => uint256) public debtOf;

    constructor(IERC20 _loanToken, IUniswapV2Pair _pair, IDexRouter _router, address _collateral) {
        loanToken = _loanToken;
        pair = _pair;
        router = _router;
        collateral = _collateral;
    }

    function deposit(uint256 amount) external {
        // Effects before interaction; checked transfer. Plumbing only -- the
        // bug under test is the spot-price valuation below, not this function.
        collateralOf[msg.sender] += amount;
        require(IERC20(collateral).transferFrom(msg.sender, address(this), amount), "transfer failed");
    }

    // VULNERABLE: collateral priced off live AMM reserves + a router spot quote.
    // A flash loan that lopsides `pair` inflates this value within one tx.
    function collateralValue(address user) public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        uint256 spotPrice = (uint256(r1) * 1e18) / uint256(r0);

        address[] memory path = new address[](2);
        path[0] = collateral;
        path[1] = address(loanToken);
        uint256[] memory amounts = router.getAmountsOut(collateralOf[user], path);

        // Blend the two manipulable spot reads -- still no robust source.
        return (amounts[1] + (collateralOf[user] * spotPrice) / 1e18) / 2;
    }

    // Leverage/borrow against the manipulable spot valuation.
    function borrow(uint256 amount) external {
        require(debtOf[msg.sender] + amount <= collateralValue(msg.sender), "undercollateralized");
        debtOf[msg.sender] += amount;
        require(loanToken.transfer(msg.sender, amount), "transfer failed");
    }
}
