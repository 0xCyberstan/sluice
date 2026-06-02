// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title VulnerableBank
/// @notice Classic reentrancy: external call is made before the internal
///         balance is updated, and there is no reentrancy guard.
contract VulnerableBank {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Withdraw funds. VULNERABLE: sends ETH via a low-level call to
    ///         the caller BEFORE zeroing their balance, so a malicious
    ///         contract can re-enter `withdraw` during its fallback and drain
    ///         the contract.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");

        // External call happens first -- attacker re-enters here.
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        // State update is too late.
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        emit Withdrawn(msg.sender, amount);
    }

    function balanceOf(address user) external view returns (uint256) {
        return balances[user];
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
}
