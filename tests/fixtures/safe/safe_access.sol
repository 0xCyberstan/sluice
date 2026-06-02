// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal Ownable (OpenZeppelin-style).
abstract contract Ownable {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    modifier onlyOwner() {
        require(msg.sender == _owner, "Ownable: caller is not the owner");
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Ownable: zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

/// @notice Protocol config whose every state-changing setter is guarded by onlyOwner.
///         No unguarded privileged setters, so access-control must stay silent.
contract SafeAccessConfig is Ownable {
    uint256 public feeBps;
    address public treasury;
    bool public paused;

    event FeeUpdated(uint256 newFeeBps);
    event TreasuryUpdated(address newTreasury);
    event PausedSet(bool paused);

    function setFee(uint256 newFeeBps) external onlyOwner {
        require(newFeeBps <= 1000, "fee too high");
        feeBps = newFeeBps;
        emit FeeUpdated(newFeeBps);
    }

    function setTreasury(address newTreasury) external onlyOwner {
        require(newTreasury != address(0), "zero address");
        treasury = newTreasury;
        emit TreasuryUpdated(newTreasury);
    }

    function setPaused(bool p) external onlyOwner {
        paused = p;
        emit PausedSet(p);
    }
}
