// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title ReadOnlyReentrantPool
/// @notice A liquidity pool whose `getPrice()` view is consumed by external
///         integrators as an oracle. `removeLiquidity` makes an external
///         transfer (ETH callback) BEFORE updating reserves/supply, so during
///         that callback `getPrice()` returns a stale, manipulated value:
///         a classic read-only reentrancy.
contract ReadOnlyReentrantPool {
    IERC20 public immutable token;
    uint256 public reserveETH;
    uint256 public reserveToken;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    constructor(IERC20 _token) {
        token = _token;
    }

    /// @notice Price of one share in wei. Read by other protocols as an oracle.
    function getPrice() external view returns (uint256) {
        if (totalShares == 0) return 0;
        return (reserveETH * 1e18) / totalShares;
    }

    function addLiquidity(uint256 tokenAmount) external payable {
        token.transferFrom(msg.sender, address(this), tokenAmount);
        uint256 minted = msg.value;
        shares[msg.sender] += minted;
        totalShares += minted;
        reserveETH += msg.value;
        reserveToken += tokenAmount;
    }

    /// @notice VULNERABLE: pays out ETH (re-entrant callback) before the
    ///         reserves and share supply are decremented. `getPrice()` reads
    ///         the not-yet-updated state mid-callback.
    function removeLiquidity(uint256 shareAmount) external {
        require(shares[msg.sender] >= shareAmount, "insufficient shares");
        uint256 ethOut = (reserveETH * shareAmount) / totalShares;

        // External call before state mutation.
        (bool ok, ) = msg.sender.call{value: ethOut}("");
        require(ok, "eth transfer failed");

        // Reserves and supply updated only after the callback returns.
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        reserveETH -= ethOut;
    }
}
