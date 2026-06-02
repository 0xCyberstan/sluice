// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Vault that records per-user deposits in packed 128-bit accounting.
contract PackedVault {
    IERC20 public token;

    struct Account {
        uint128 principal;
        uint128 shares;
    }

    mapping(address => Account) public accounts;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /// @notice Deposit tokens; the credited amount is stored in a uint128 slot.
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);

        // The full uint256 `amount` is pulled in, but only a narrowed uint128 is
        // credited. An attacker deposits amount = 2**128 + k: the contract takes
        // the whole sum yet records only `k`, and the same truncation lets a
        // crafted amount wrap the stored principal far below what was paid.
        uint128 credited = uint128(amount);
        accounts[msg.sender].principal += credited;

        unchecked {
            // Share math runs unchecked on the attacker-controlled value, so a
            // large `credited` overflows the running share total silently.
            accounts[msg.sender].shares += credited * 2;
        }
    }

    function principalOf(address user) external view returns (uint128) {
        return accounts[user].principal;
    }
}
