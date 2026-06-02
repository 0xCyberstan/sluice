// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title UpgradeableVault (UUPS-style)
/// @notice An upgradeable implementation that uses an `initialize()` function
///         instead of a constructor for setup. VULNERABLE: the constructor
///         does NOT call `_disableInitializers()`, so the implementation
///         contract itself is left uninitialized. An attacker can call
///         `initialize()` directly on the implementation, become its owner,
///         and (via the UUPS `upgradeTo` path) point it at malicious logic and
///         `selfdestruct` the implementation -- bricking every proxy.
contract UpgradeableVault {
    address public owner;
    bool private _initialized;
    uint256 public totalDeposits;

    event Initialized(address indexed owner);
    event Upgraded(address indexed newImplementation);

    /// @dev VULNERABLE: no `_disableInitializers()` here, leaving the
    ///      implementation open to initialization by anyone.
    constructor() {
        // intentionally empty -- initializers NOT disabled
    }

    modifier initializer() {
        require(!_initialized, "already initialized");
        _initialized = true;
        _;
    }

    /// @notice Anyone can call this on an uninitialized (implementation)
    ///         contract and seize ownership.
    function initialize(address _owner) external initializer {
        owner = _owner;
        emit Initialized(_owner);
    }

    /// @notice UUPS-style upgrade hook gated only by `owner`, which the
    ///         attacker can set via the unguarded `initialize`.
    function upgradeTo(address newImplementation) external {
        require(msg.sender == owner, "not owner");
        emit Upgraded(newImplementation);
        // delegatecalled storage slot write would go here in a full UUPS proxy
    }

    function deposit() external payable {
        totalDeposits += msg.value;
    }
}
