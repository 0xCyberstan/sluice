// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice A raffle that picks a winner from on-chain entrants.
contract Raffle {
    address public owner;
    address[] public players;
    address public lastWinner;

    constructor() {
        owner = msg.sender;
    }

    function enter() external payable {
        require(msg.value == 0.01 ether, "wrong fee");
        players.push(msg.sender);
    }

    /// @notice Draw the winning player and pay out the pot.
    function draw() external {
        require(msg.sender == owner, "not owner");
        require(players.length > 0, "no players");

        // Randomness derived purely from on-chain block values. Both
        // block.timestamp and block.prevrandao are observable/influenceable, so
        // a contract entering in the same block can compute the winning index
        // and only enter when it wins.
        uint256 index = uint256(
            keccak256(abi.encodePacked(block.timestamp, block.prevrandao))
        ) % players.length;

        address winner = players[index];
        lastWinner = winner;
        delete players;

        (bool ok, ) = winner.call{value: address(this).balance}("");
        require(ok, "payout failed");
    }
}
