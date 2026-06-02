// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident: Euler Finance (Mar 13 2023) — ~$197M flash-loan / self-liquidation exploit.
// Root cause: donateToReserves() burned the caller's eToken collateral WITHOUT the
//   post-op solvency/liquidity check (`checkLiquidity`) that every other
//   balance-reducing operation (mint/borrow/withdraw/liquidate) enforced. The
//   attacker minted leveraged eTokens, called donateToReserves to tank their own
//   health factor into bad debt, then liquidated their own under-water position
//   for profit. The defect is a CONSENSUS outlier: each function is well-formed,
//   but one value-moving function omits the settlement routine its siblings call.
// Expected detector: missing-solvency-check (SettlementBeforeMutation, Euler class).
//
// NOTE: Euler's real internal routine was named `checkLiquidity`; it is named
//   `_checkLiquidityHealth` here so the routine name reads as a settlement check.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract EulerEToken {
    IERC20 public immutable underlying;
    mapping(address => uint256) public eTokenBalance; // collateral (eTokens)
    mapping(address => uint256) public borrows;       // debt (dTokens)
    uint256 public constant COLLATERAL_FACTOR = 75;   // percent

    constructor(IERC20 _underlying) {
        underlying = _underlying;
    }

    // Solvency invariant: debt must stay within COLLATERAL_FACTOR% of collateral.
    function _checkLiquidityHealth(address account) internal view {
        require(borrows[account] * 100 <= eTokenBalance[account] * COLLATERAL_FACTOR, "insolvent");
    }

    function deposit(uint256 amount) external {
        underlying.transferFrom(msg.sender, address(this), amount);
        eTokenBalance[msg.sender] += amount;
        _checkLiquidityHealth(msg.sender);
    }

    function mint(uint256 amount) external {
        // Self-collateralized leverage: mint eTokens against new debt.
        eTokenBalance[msg.sender] += amount;
        borrows[msg.sender] += amount;
        _checkLiquidityHealth(msg.sender);
    }

    function borrow(uint256 amount) external {
        borrows[msg.sender] += amount;
        _checkLiquidityHealth(msg.sender);
        underlying.transfer(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        eTokenBalance[msg.sender] -= amount;
        _checkLiquidityHealth(msg.sender);
        underlying.transfer(msg.sender, amount);
    }

    function liquidate(address violator, uint256 repay) external {
        borrows[violator] -= repay;
        eTokenBalance[violator] -= repay;
        eTokenBalance[msg.sender] += repay;
        _checkLiquidityHealth(violator);
    }

    // VULNERABLE: burns the caller's eToken collateral but SKIPS
    // _checkLiquidityHealth — so a borrower can self-induce bad debt at will.
    function donateToReserves(uint256 amount) external {
        eTokenBalance[msg.sender] -= amount;
    }
}
