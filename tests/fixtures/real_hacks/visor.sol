// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
//
// Incident:  Visor Finance (Hypervisor / VISOR staking) hack (December 2021)
// Loss:      ~$8,200,000
// Detector:  arbitrary-transfer (arbitrary-send-erc20 / allowance-theft class)
//
// Root cause: the staking vault's deposit path pulled tokens into the contract
// with `transferFrom(from, address(this), amount)` where `from` was a function
// PARAMETER supplied by the caller rather than `msg.sender`. The function had no
// access control and never pinned the source to the caller, so anyone could pass
// a victim's address as `from` and move tokens out of every wallet that had ever
// approved the vault. In the real exploit the attacker further abused the fact
// that the deposit trusted a caller-supplied "vault"/token contract, but the
// dominant, reproducible flaw is the unauthenticated, attacker-chosen `from`
// flowing straight into `transferFrom`.
//
// The dominant vulnerable pattern: a public deposit whose `from` is a
// user-supplied address parameter, not `msg.sender` / `address(this)`.
//
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VisorVault {
    // The deposit token the vault holds and accounts shares against.
    IERC20 public token;
    // Per-account staked balance, credited on deposit.
    mapping(address => uint256) public shares;

    constructor(IERC20 _token) {
        token = _token;
    }

    // Stake `amount` of `token` and credit shares to the caller.
    //
    // BUG: `from` is a caller-supplied address parameter, not `msg.sender`.
    // The function has no access control, so an attacker calls
    // deposit(amount, victim) and pulls `amount` tokens out of any `victim`
    // that has approved this vault — classic arbitrary-send-erc20.
    function deposit(uint256 amount, address from) external returns (uint256) {
        // Attacker chooses `from`; the vault never verifies it is the caller.
        token.transferFrom(from, address(this), amount);
        shares[msg.sender] += amount;
        return amount;
    }
}
