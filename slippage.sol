// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IRouter {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

/// @notice Auto-compounder that swaps reward tokens into the vault asset.
contract Compounder {
    IRouter public router;
    IERC20 public rewardToken;
    address public asset;

    constructor(address _router, address _rewardToken, address _asset) {
        router = IRouter(_router);
        rewardToken = IERC20(_rewardToken);
        asset = _asset;
    }

    /// @notice Swap the contract's reward tokens into the underlying asset.
    function compound(uint256 amountIn) external {
        rewardToken.transferFrom(msg.sender, address(this), amountIn);
        rewardToken.approve(address(router), amountIn);

        address[] memory path = new address[](2);
        path[0] = address(rewardToken);
        path[1] = asset;

        // amountOutMin is hardcoded to 0 (accept any output) and the deadline is
        // block.timestamp (always satisfied). The swap has no MEV/sandwich
        // protection: a searcher can sandwich it for near-total value loss.
        router.swapExactTokensForTokens(
            amountIn,
            0,
            path,
            address(this),
            block.timestamp
        );
    }
}
