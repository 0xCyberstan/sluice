// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IToken { function balanceOf(address a) external view returns (uint256); }
/// VULNERABLE: vote weight from LIVE balance, no snapshot, no timelock.
contract NaiveGovernor {
    IToken public token;
    mapping(uint256 => uint256) public forVotes;
    mapping(uint256 => bool) public executed;
    function castVote(uint256 id) external {
        uint256 weight = token.balanceOf(msg.sender); // flash-loanable in-block
        forVotes[id] += weight;
    }
    function execute(uint256 id) external {
        require(!executed[id], "done");
        require(forVotes[id] > 1_000_000e18, "quorum");
        executed[id] = true;
    }
}
