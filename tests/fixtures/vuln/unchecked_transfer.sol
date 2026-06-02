// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function transfer(address to, uint256 amt) external returns (bool); }
/// VULNERABLE: raw ERC20 transfer return value ignored (no SafeERC20).
contract Payer {
    IERC20 public token;
    function pay(address to, uint256 amt) external {
        token.transfer(to, amt); // return not checked; USDT-like tokens fail silently
    }
}
