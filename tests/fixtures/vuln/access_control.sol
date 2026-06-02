// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FeeManager
/// @notice Holds privileged configuration (owner, fee recipient, fee rate) but
///         the setters that mutate this state have NO access control modifier
///         -- anyone can call `setOwner`, `setFee`, and `setFeeRecipient` and
///         take over the contract / redirect fees.
contract FeeManager {
    address public owner;
    address public feeRecipient;
    uint256 public feeBps; // basis points

    event OwnerChanged(address indexed previousOwner, address indexed newOwner);
    event FeeChanged(uint256 oldFee, uint256 newFee);
    event FeeRecipientChanged(address indexed oldRecipient, address indexed newRecipient);

    constructor(address _feeRecipient, uint256 _feeBps) {
        owner = msg.sender;
        feeRecipient = _feeRecipient;
        feeBps = _feeBps;
    }

    /// @notice VULNERABLE: no `onlyOwner` -- any caller can seize ownership.
    function setOwner(address newOwner) external {
        emit OwnerChanged(owner, newOwner);
        owner = newOwner;
    }

    /// @notice VULNERABLE: no access control -- anyone can change the fee.
    function setFee(uint256 newFeeBps) external {
        require(newFeeBps <= 10_000, "fee too high");
        emit FeeChanged(feeBps, newFeeBps);
        feeBps = newFeeBps;
    }

    /// @notice VULNERABLE: no access control -- anyone can redirect fees.
    function setFeeRecipient(address newRecipient) external {
        emit FeeRecipientChanged(feeRecipient, newRecipient);
        feeRecipient = newRecipient;
    }

    function quoteFee(uint256 amount) external view returns (uint256) {
        return (amount * feeBps) / 10_000;
    }
}
