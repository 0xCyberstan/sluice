// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IVotes {
    function getVotes(address account) external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
}

/// @notice On-chain governance where proposals execute once they reach quorum.
contract FlashGovernor {
    IVotes public token;
    uint256 public quorum;
    uint256 public proposalCount;

    struct Proposal {
        address target;
        bytes data;
        uint256 forVotes;
        bool executed;
        mapping(address => bool) voted;
    }

    mapping(uint256 => Proposal) internal proposals;

    constructor(address _token, uint256 _quorum) {
        token = IVotes(_token);
        quorum = _quorum;
    }

    function propose(address target, bytes calldata data) external returns (uint256 id) {
        id = ++proposalCount;
        Proposal storage p = proposals[id];
        p.target = target;
        p.data = data;
    }

    /// @notice Cast a vote weighted by the caller's CURRENT token balance.
    function vote(uint256 id) external {
        Proposal storage p = proposals[id];
        require(!p.voted[msg.sender], "voted");
        p.voted[msg.sender] = true;

        // Weight is read from the live balance with no snapshot block and no
        // timelock. A voter can flash-borrow tokens, vote, and repay atomically.
        uint256 weight = token.getVotes(msg.sender) + token.balanceOf(msg.sender);
        p.forVotes += weight;
    }

    function execute(uint256 id) external {
        Proposal storage p = proposals[id];
        require(!p.executed, "done");
        require(p.forVotes >= quorum, "no quorum");
        p.executed = true;
        (bool ok, ) = p.target.call(p.data);
        require(ok, "call failed");
    }
}
