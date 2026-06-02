// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MutableProxy
/// @notice A minimal proxy that delegatecalls into an implementation address.
///         VULNERABLE: the implementation target is a plain (non-constant,
///         non-immutable) storage variable that anyone can set via
///         `setImplementation`. An attacker points it at a malicious contract
///         and, because `delegatecall` executes in THIS contract's storage and
///         msg.sender context, they can rewrite storage (e.g. `admin`) or
///         `selfdestruct` the proxy.
contract MutableProxy {
    address public implementation; // attacker-settable delegatecall target
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    /// @notice VULNERABLE: no access control on the delegatecall target.
    function setImplementation(address impl) external {
        implementation = impl;
    }

    /// @notice VULNERABLE: delegatecall to an attacker-controlled address.
    function execute(bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = implementation.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            // Untrusted delegatecall target -- executes with this proxy's state.
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}
