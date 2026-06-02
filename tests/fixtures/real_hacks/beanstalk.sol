// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident: Beanstalk Farms governance exploit (April 2022, ~$181M drained).
// Root cause: the BIP voting weight was the caller's CURRENT governance-token /
// LP balance read live at execution time, with no historical voting record, and
// an emergencyCommit path that executed a passing proposal immediately with no
// execution delay. An attacker flash-borrowed enough stalk/LP to pass a malicious
// BIP and drain the protocol, all in a single transaction, then repaid the loan.
// Expected detector: flashloan-governance

// Live-balance governance token (NO historical / past-block voting accessor).
interface IGovToken {
    function balanceOf(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

contract BeanstalkGovernance {
    IGovToken public token;

    struct Bip {
        uint256 forVotes;
        bool executed;
        address target;
        bytes data;
    }

    mapping(uint256 => Bip) public bips;
    mapping(uint256 => mapping(address => bool)) public voted;

    function propose(address target, bytes calldata data) external returns (uint256 id) {
        id = uint256(keccak256(abi.encode(target, data, block.number)));
        bips[id].target = target;
        bips[id].data = data;
    }

    // Vote weight = caller's LIVE balance at cast time (flash-loanable).
    function vote(uint256 id) external {
        require(!voted[id][msg.sender], "already voted");
        voted[id][msg.sender] = true;
        uint256 weight = token.balanceOf(msg.sender); // live read, no past-block lookup
        bips[id].forVotes += weight;
    }

    // Emergency path: execute immediately once live super-majority is met,
    // bypassing any execution delay (the Beanstalk emergencyCommit bug).
    function emergencyCommit(uint256 id) external {
        Bip storage b = bips[id];
        require(!b.executed, "executed");
        require(b.forVotes * 3 > token.totalSupply() * 2, "no super majority");
        b.executed = true;
        (bool ok, ) = b.target.call(b.data);
        require(ok, "exec failed");
    }
}
