// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident: Furucombo "evil contract" proxy exploit (February 2021).
// Loss:     ~$15M (drained from users who had granted token approvals to the proxy).
// Detector: upgradeable  (controlled-delegatecall branch)
//
// Root cause: Furucombo is a "combo" router. A transaction is a list of "cubes",
// each naming a handler (`to`) plus calldata (`data`). The proxy executed each
// cube by DELEGATECALLing into `to` -- a target taken straight from user input.
// Handlers were meant to be registered/allowlisted, but the registry check was
// effectively bypassable (an attacker registered Aave V2's proxy as a handler and
// then made it delegatecall an attacker-controlled "evil implementation").
// Because delegatecall runs the callee's code against the PROXY's own storage and,
// crucially, the PROXY's outstanding ERC20 approvals, the attacker ran arbitrary
// code as the proxy and swept every token users had approved to it.
//
// This reconstructs the dominant flaw: the proxy delegatecalls into an address
// supplied by the caller, with NO allowlist / NO constant-or-immutable target.
// delegatecall to an attacker-controlled, non-constant address == takeover.

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract FurucomboProxy {
    // One step of a combo: which handler to run, and the calldata to run it with.
    struct Cube {
        address to;    // attacker-supplied handler / implementation address
        bytes data;    // attacker-supplied calldata
    }

    // The router entrypoint: execute a batch of user-defined cubes.
    function batchExec(Cube[] calldata cubes) external payable {
        for (uint256 i = 0; i < cubes.length; i++) {
            _exec(cubes[i].to, cubes[i].data);
        }
    }

    // Execute a single cube. The handler address `to` comes directly from caller
    // input -- there is NO allowlist and it is not a constant/immutable. The
    // delegatecall therefore runs foreign, attacker-chosen code against THIS
    // proxy's storage and its token approvals: an arbitrary-code / takeover
    // primitive (the Furucombo "evil contract" class).
    function _exec(address to, bytes memory data) internal returns (bytes memory result) {
        bool ok;
        (ok, result) = to.delegatecall(data); // controlled delegatecall
        require(ok, "exec failed");
    }

    // Users granted approvals to the proxy so it could pull their tokens during a
    // combo; the delegatecalled "evil" handler reused those approvals to steal.
    function pull(IERC20 token, address from, uint256 amount) external {
        require(token.transferFrom(from, address(this), amount), "pull failed");
    }
}
