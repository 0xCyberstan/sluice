// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// VULNERABLE: winner selected from predictable block environment.
contract Lottery {
    address[] public players;
    address public winner;
    function enter() external { players.push(msg.sender); }
    function pickWinner() external {
        uint256 idx = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao, msg.sender))) % players.length;
        winner = players[idx];
    }
}
