// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident: Parity multisig wallet hacks (2017).
// Loss:     ~$30M (July 2017 drain) + ~$150M+ frozen (November 2017 self-destruct).
// Detector: access-control
//
// Root cause: the wallet's setup routine `initWallet(address _owner)` assigned
// the privileged `owner` but had NO access-control modifier and NO initializer
// guard (no `require(owner == address(0))`, no `initializer`/`onlyUninitialized`).
// On the live wallet (and the shared library that backed every wallet via
// delegatecall) this "constructor-like" function remained publicly callable by
// ANYONE after deployment. An attacker simply called initWallet to make
// themselves the owner, then used the now-owned wallet to move funds / suicide
// the library. The fix is an init guard + owner-restricted setup.
//
// This reconstructs the dominant flaw: a privileged `owner` write reachable by
// any caller, with no guard of any kind.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract ParityWallet {
    // The single privileged scalar that gates every sensitive action.
    address public owner;

    receive() external payable {}

    // The fateful "initializer": sets the privileged owner with NO access
    // control and NO one-time / uninitialized guard, so it can be (re)called
    // by anyone to seize ownership of an already-deployed wallet.
    function initWallet(address _owner) external {
        owner = _owner; // privileged write, callable by anyone
    }

    // Privileged owner-only action: drain ERC20 balances to an arbitrary target.
    function execute(IERC20 token, address to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        require(token.transfer(to, amount), "transfer failed");
    }

    // Privileged owner-only action: pay out native ETH.
    function withdraw(address payable to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "send failed");
    }

    // The November 2017 escalation: an owner could self-destruct the contract
    // (on the shared library this bricked every dependent wallet).
    function kill(address payable refund) external {
        require(msg.sender == owner, "not owner");
        selfdestruct(refund);
    }
}
