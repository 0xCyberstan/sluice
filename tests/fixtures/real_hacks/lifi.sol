// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
//
// Incident:  LI.FI bridge/swap aggregator hack (March 2022)
// Loss:      ~$600,000
// Detector:  arbitrary-transfer (arbitrary-send-erc20 / allowance-theft class)
//
// Root cause: the aggregator's swap entrypoint took the source address, the token,
// the amount, AND the swap target/calldata all as caller-supplied parameters. To
// fund the swap it pulled tokens with `token.transferFrom(from, address(this), amount)`
// where `from` was a function PARAMETER rather than `msg.sender`, and `token` was
// likewise attacker-chosen. There was no access control and the source was never
// pinned to the caller, so an attacker passed a victim's address as `from` and any
// token the victim had approved, draining every wallet that had ever granted the
// aggregator an allowance. The real exploit then forwarded an arbitrary low-level
// call to a caller-supplied DEX target, but the dominant, reproducible flaw is the
// unauthenticated, attacker-chosen `from` flowing straight into `transferFrom`.
//
// The dominant vulnerable pattern: a public swap whose `from` (and `token`) are
// user-supplied parameters, not `msg.sender` / a vetted token.
//
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract LiFiDiamond {
    // Per-swap accounting of pulled funds, credited to the caller.
    mapping(address => uint256) public pulled;

    // Swap/bridge entrypoint: pull `amount` of `token` from `from`, then forward
    // the funds through a caller-supplied DEX `callTo` with arbitrary `callData`.
    //
    // BUG: `from` is a caller-supplied address parameter, not `msg.sender`, and the
    // function has no access control. An attacker calls
    // swap(victim, victimApprovedToken, amount, ...) and pulls tokens out of any
    // `victim` that has approved this contract — classic arbitrary-send-erc20.
    function swap(
        address from,
        address token,
        uint256 amount,
        address callTo,
        bytes calldata callData
    ) external returns (bool) {
        // Attacker chooses `from` and `token`; the contract never verifies the
        // source is the caller.
        IERC20(token).transferFrom(from, address(this), amount);
        pulled[msg.sender] += amount;

        // Funds are then handed to a caller-supplied target (the real exploit's
        // second leg); the dominant flaw remains the attacker-chosen `from` above.
        (bool ok, ) = callTo.call(callData);
        require(ok, "swap call failed");
        return ok;
    }
}
