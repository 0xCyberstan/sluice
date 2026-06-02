// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Rewards vault that pays out staked tokens to users.
contract RewardVault {
    IERC20 public token;
    address public owner;
    mapping(address => uint256) public rewards;

    constructor(address _token) {
        token = IERC20(_token);
        owner = msg.sender;
    }

    function accrue(address user, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        rewards[user] += amount;
    }

    /// @notice User withdraws their accrued rewards.
    function claim() external {
        uint256 amount = rewards[msg.sender];
        require(amount > 0, "nothing to claim");
        rewards[msg.sender] = 0;

        // Raw ERC20 transfer: return value is ignored. A token that returns
        // false on failure (instead of reverting) leaves the vault thinking
        // the payout succeeded while no tokens moved.
        token.transfer(msg.sender, amount);
    }

    /// @notice Owner sweeps tokens to the treasury.
    function sweep(address to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        token.transfer(to, amount);
    }
}
