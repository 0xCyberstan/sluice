// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
//
// Incident:  TempleDAO STAX staking exploit (October 2022)
// Loss:      ~$2,300,000 (drained staked LP tokens)
// Detector:  access-control
//
// Root cause: StaxLPStaking.migrateStake(address oldStaking, uint256 amount)
// was meant to let a user move their stake from a previous staking contract
// into the new one. It had NO access control and, crucially, NO validation
// that `oldStaking` was a trusted/known staking contract. It blindly called
// oldStaking.migrateWithdraw(msg.sender, amount) and then credited the caller
// with `amount` of staked balance in THIS contract.
//
// An attacker supplied a fake `oldStaking` address (a contract they control,
// whose migrateWithdraw does nothing) and any `amount`. The external call to
// the attacker-controlled contract succeeded as a no-op, yet this contract
// still credited the attacker that `amount` of real staked balance. The
// attacker then called withdraw() to pull out genuine LP tokens deposited by
// other users. The fix is to gate migrateStake to an owner-whitelisted set of
// trusted staking contracts (validate `oldStaking`).
//
// This reconstructs the dominant flaw: a balance-crediting migration driven by
// a fully caller-supplied source contract with no validation and no access
// control.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IOldStaking {
    // Trusted contracts would actually move tokens here; a forged one need not.
    function migrateWithdraw(address staker, uint256 amount) external;
}

contract StaxLPStaking {
    IERC20 public stakingToken;
    mapping(address => uint256) public balanceOf;

    constructor(IERC20 _stakingToken) {
        stakingToken = _stakingToken;
    }

    // Honest deposit path: real LP tokens are pulled in and the staker is credited.
    function stake(uint256 amount) external {
        require(stakingToken.transferFrom(msg.sender, address(this), amount), "pull failed");
        balanceOf[msg.sender] += amount;
    }

    // The fateful migration: pulls a stake from a caller-supplied `oldStaking`
    // and credits the caller here. There is NO access control and NO check that
    // `oldStaking` is a trusted/known staking contract, so a forged source whose
    // migrateWithdraw is a no-op still results in a real balance credit.
    function migrateStake(address oldStaking, uint256 amount) external {
        // BUG: `oldStaking` is unvalidated, attacker-controlled.
        IOldStaking(oldStaking).migrateWithdraw(msg.sender, amount);
        balanceOf[msg.sender] += amount; // unbacked credit
    }

    // Withdraw genuine staked LP tokens against the (possibly forged) balance.
    function withdraw(uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        require(stakingToken.transfer(msg.sender, amount), "send failed");
    }
}
