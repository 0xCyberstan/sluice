// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:        DEUS Finance (DEI stablecoin) — March / April 2022, ~$6M+ (April leg ~$13.4M)
// Approximate loss: ~$6M (the DEI lending/mint contract drained across the 2022 incidents)
// Expected detector: oracle-manipulation
//
// Root cause: DEUS priced and minted DEI against the LIVE state of a thin Solidly/Solidex
// StableV1 USDC/DEI AMM pair. The price feed computed DEI's USD value from the pair's
// instantaneous reserves (a getReserves()/balanceOf spot read) with NO TWAP and NO robust
// external feed. An attacker flash-loaned ~$143M USDC and swapped into the pool, spiking the
// reported DEI price far above its $1 peg; the inflated spot price was then used to value DEI
// collateral and mint/borrow many times more DEI than the collateral was actually worth.
// Because the valuation comes straight from single-transaction-movable pool balances, the
// whole mint amount is dictated by an attacker-controlled spot price.

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IStableV1Pair {
    // Instantaneous pool reserves — attacker-movable within a single transaction.
    function getReserves() external view returns (uint112 reserveUsdc, uint112 reserveDei, uint32 blockTimestampLast);
}

contract DeusDeiMinter {
    IStableV1Pair public immutable pair;   // Solidly/Solidex StableV1 USDC/DEI pool used as the oracle
    IERC20 public immutable usdc;          // collateral posted by users
    IERC20 public immutable dei;           // DEI minted out against the collateral

    mapping(address => uint256) public collateralUsdc;

    constructor(IStableV1Pair _pair, IERC20 _usdc, IERC20 _dei) {
        pair = _pair;
        usdc = _usdc;
        dei = _dei;
    }

    // VULNERABLE: DEI price = USDC reserve / DEI reserve read live from the thin pool.
    // getReserves() is a spot value; a flash-loan swap moves it within one transaction.
    function deiPrice() public view returns (uint256) {
        (uint112 reserveUsdc, uint112 reserveDei, ) = pair.getReserves();
        return (uint256(reserveUsdc) * 1e18) / uint256(reserveDei); // spot, no TWAP, no fallback feed
    }

    function depositCollateral(uint256 amount) external {
        require(usdc.transferFrom(msg.sender, address(this), amount), "xfer");
        collateralUsdc[msg.sender] += amount;
    }

    // Mints DEI proportional to the manipulable spot valuation of the caller's collateral.
    function mint(uint256 deiAmount) external {
        uint256 collateralValue = (collateralUsdc[msg.sender] * deiPrice()) / 1e18;
        require(deiAmount <= collateralValue, "undercollateralized");
        require(dei.transfer(msg.sender, deiAmount), "xfer");
    }
}
