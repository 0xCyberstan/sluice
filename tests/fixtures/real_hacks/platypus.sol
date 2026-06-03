// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident: Platypus Finance (Feb 16 2023) — ~$8.5M stablecoin-AMM / LP exploit.
// Root cause: emergencyWithdraw() was meant to let an LP pull its deposited
//   collateral, but it gated on a FAULTY coverage-ratio call (`_checkCoverage`)
//   that only compared cash-to-liability and IGNORED the caller's open borrow
//   position. Every other balance-reducing action (borrow / withdraw / repay /
//   liquidate) instead enforced the real solvency invariant `_ensureSolvent`,
//   which requires debt to stay within collateral. By flash-borrowing against a
//   minted position and then calling emergencyWithdraw, the attacker reclaimed
//   the underlying collateral while the loan stayed open — the coverage check
//   passed, the solvency check was never run, and the position was left
//   insolvent (bad debt the protocol ate). The defect is a CONSENSUS outlier:
//   one value-moving function skips the settlement routine its siblings call.
// Expected detector: missing-solvency-check (SettlementBeforeMutation, Euler class).
//
// NOTE: the real protocol's guard was a coverage-ratio (cash/liability) check;
//   it is modeled here as `_checkCoverage` (passes for the attacker) alongside
//   the true invariant `_ensureSolvent` that the sibling functions enforce.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract PlatypusPool {
    IERC20 public immutable token;
    mapping(address => uint256) public collateral; // LP deposit backing the loan
    mapping(address => uint256) public debt;        // outstanding borrow
    uint256 public cash;                            // pool cash on hand
    uint256 public liability;                       // pool liability to LPs
    uint256 public constant COLLATERAL_FACTOR = 80; // percent

    constructor(IERC20 _token) {
        token = _token;
    }

    // TRUE solvency invariant: debt must stay within COLLATERAL_FACTOR% of collateral.
    function _ensureSolvent(address account) internal view {
        require(debt[account] * 100 <= collateral[account] * COLLATERAL_FACTOR, "insolvent");
    }

    // FAULTY guard: only checks pool coverage (cash vs liability); it never looks
    // at the caller's open debt, so it passes for an under-collateralized account.
    function _checkCoverage() internal view {
        require(cash >= liability, "under-covered");
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        collateral[msg.sender] += amount;
        cash += amount;
        liability += amount;
        _ensureSolvent(msg.sender);
    }

    function borrow(uint256 amount) external {
        debt[msg.sender] += amount;
        cash -= amount;
        _ensureSolvent(msg.sender);
        token.transfer(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        collateral[msg.sender] -= amount;
        cash -= amount;
        liability -= amount;
        _ensureSolvent(msg.sender);
        token.transfer(msg.sender, amount);
    }

    function repay(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        debt[msg.sender] -= amount;
        cash += amount;
        _ensureSolvent(msg.sender);
    }

    function liquidate(address user, uint256 repayAmt) external {
        debt[user] -= repayAmt;
        collateral[user] -= repayAmt;
        collateral[msg.sender] += repayAmt;
        _ensureSolvent(user);
    }

    // VULNERABLE: pulls the caller's collateral but gates only on the faulty
    // coverage check, SKIPPING _ensureSolvent — so an LP with an open borrow can
    // reclaim its collateral and leave the position insolvent (bad debt).
    function emergencyWithdraw(uint256 amount) external {
        collateral[msg.sender] -= amount;
        cash -= amount;
        liability -= amount;
        _checkCoverage();
        token.transfer(msg.sender, amount);
    }
}
