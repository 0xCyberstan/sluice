// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function transferFrom(address f, address t, uint256 a) external returns (bool); }
/// VULNERABLE: credits the REQUESTED amount, not the measured balance delta, so
/// a fee-on-transfer / deflationary token lets the depositor over-credit.
contract DepositVault {
    IERC20 public token;
    mapping(address => uint256) public deposits;
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount; // no balanceOf(this) before/after measurement
    }
}
