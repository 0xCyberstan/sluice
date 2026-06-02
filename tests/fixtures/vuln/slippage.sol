// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IRouter {
    function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) external returns (uint256[] memory);
}
/// VULNERABLE: amountOutMin = 0 (no slippage bound) and deadline = block.timestamp (no-op).
contract Trader {
    IRouter public router;
    function trade(uint256 amountIn, address[] calldata path) external {
        router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, block.timestamp);
    }
}
