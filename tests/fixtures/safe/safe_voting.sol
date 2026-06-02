// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal ERC20Votes-style interface exposing historical (checkpointed) voting power.
interface IVotes {
    function getPastVotes(address account, uint256 timepoint) external view returns (uint256);
    function getPastTotalSupply(uint256 timepoint) external view returns (uint256);
}

/// @notice Governor that reads voting power from a PAST snapshot block via
///         getPastVotes, and enforces a timelock before execution. Because power
///         is measured at the proposal snapshot (not current balance), a flash-loaned
///         balance in the same block carries no weight. flashloan-governance stays silent.
contract SafeGovernor {
    IVotes public immutable token;
    uint256 public constant VOTING_DELAY = 1;        // snapshot taken 1 block after proposal
    uint256 public constant TIMELOCK_DELAY = 2 days; // execution delay after voting

    struct Proposal {
        uint256 snapshotBlock;
        uint256 eta;
        uint256 forVotes;
        bool executed;
    }

    uint256 public proposalCount;
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    function propose() external returns (uint256 id) {
        id = ++proposalCount;
        proposals[id].snapshotBlock = block.number + VOTING_DELAY;
        proposals[id].eta = block.timestamp + TIMELOCK_DELAY;
    }

    function castVote(uint256 id) external {
        Proposal storage p = proposals[id];
        require(block.number >= p.snapshotBlock, "voting not started");
        require(!hasVoted[id][msg.sender], "already voted");
        hasVoted[id][msg.sender] = true;

        // Voting weight is read from the historical snapshot, not the live balance.
        uint256 weight = token.getPastVotes(msg.sender, p.snapshotBlock - 1);
        p.forVotes += weight;
    }

    function execute(uint256 id) external {
        Proposal storage p = proposals[id];
        require(!p.executed, "executed");
        require(block.timestamp >= p.eta, "timelock not elapsed");
        uint256 supply = token.getPastTotalSupply(p.snapshotBlock - 1);
        require(p.forVotes * 2 > supply, "quorum not reached");
        p.executed = true;
    }
}
