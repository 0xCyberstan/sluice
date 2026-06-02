// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// VULNERABLE: push-payment loop over an attacker-growable array; one reverting
/// recipient bricks the whole distribution (and the loop is unbounded).
contract Airdrop {
    address[] public recipients;
    function add(address r) external { recipients.push(r); }
    function distribute() external {
        for (uint256 i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(1 ether);
        }
    }
}
