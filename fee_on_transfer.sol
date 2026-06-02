// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Share-based vault: depositors receive shares 1:1 with tokens in.
contract ShareVault {
    IERC20 public token;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /// @notice Deposit `amount` tokens and mint matching shares.
    function deposit(uint256 amount) external {
        require(amount > 0, "zero");

        // Shares are credited from the requested `amount`, not from the actual
        // balance delta. For a fee-on-transfer token the vault receives less
        // than `amount`, yet mints shares for the full `amount`, so the
        // depositor (and later redeemers) drain value from honest LPs.
        token.transferFrom(msg.sender, address(this), amount);

        shares[msg.sender] += amount;
        totalShares += amount;
    }

    /// @notice Burn shares and reclaim the proportional token balance.
    function withdraw(uint256 amount) external {
        require(shares[msg.sender] >= amount, "insufficient");
        shares[msg.sender] -= amount;
        totalShares -= amount;

        uint256 bal = token.balanceOf(address(this));
        uint256 payout = (bal * amount) / (totalShares + amount);
        token.transferFrom(address(this), msg.sender, payout);
    }
}
