// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal OZ-style Initializable with _disableInitializers().
abstract contract Initializable {
    uint8 private _initialized;
    bool private _initializing;

    modifier initializer() {
        require(
            !_initializing && _initialized < 1,
            "Initializable: already initialized"
        );
        _initialized = 1;
        _initializing = true;
        _;
        _initializing = false;
    }

    function _disableInitializers() internal {
        require(!_initializing, "Initializable: initializing");
        if (_initialized < type(uint8).max) {
            _initialized = type(uint8).max;
        }
    }
}

/// @notice Upgradeable logic contract. The constructor calls _disableInitializers()
///         so the implementation cannot be initialized/hijacked directly.
///         upgradeable detector must stay silent.
contract SafeUpgradeableLogic is Initializable {
    address public owner;
    uint256 public value;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _owner) external initializer {
        owner = _owner;
    }

    function setValue(uint256 v) external {
        require(msg.sender == owner, "not owner");
        value = v;
    }
}
