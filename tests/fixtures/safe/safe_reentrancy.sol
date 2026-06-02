// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal ReentrancyGuard (OpenZeppelin-style).
abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status = _NOT_ENTERED;

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

/// @notice Pull-payment vault. Withdrawals use nonReentrant AND
///         checks-effects-interactions: state is zeroed before the external call.
contract SafeReentrancyVault is ReentrancyGuard {
    mapping(address => uint256) public balances;

    event Deposited(address indexed who, uint256 amount);
    event Withdrawn(address indexed who, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant {
        // CHECKS
        uint256 bal = balances[msg.sender];
        require(bal >= amount, "insufficient balance");

        // EFFECTS: update state before any external interaction.
        balances[msg.sender] = bal - amount;

        // INTERACTIONS: external call happens last, guarded by nonReentrant.
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        emit Withdrawn(msg.sender, amount);
    }
}
