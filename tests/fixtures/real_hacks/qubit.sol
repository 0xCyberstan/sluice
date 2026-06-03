// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
//
// Incident:  Qubit Finance / QBridge (BSC <-> Ethereum bridge) hack (January 2022)
// Loss:      ~$80,000,000
// Detector:  arbitrary-transfer (arbitrary-send-erc20 / allowance-theft class)
//
// Root cause: the bridge deposit path pulled the user's collateral with
// `transferFrom(from, address(this), amount)` where BOTH the token and the
// `from` source were caller-supplied parameters rather than `msg.sender`. The
// function had no access control and never pinned the source to the caller, so
// the deposit "trusted" attacker-controlled inputs:
//   - In the real exploit the attacker hit the native-asset/zero-address path,
//     so the `transferFrom` was effectively a no-op (no tokens left any wallet)
//     yet the bridge still emitted a deposit event and credited bridged xETH on
//     the destination chain — minting without ever depositing.
//   - The same unauthenticated, attacker-chosen `from` is also a textbook
//     allowance-theft sink: pass a victim's address as `from` and pull tokens
//     out of every wallet that has approved the bridge.
//
// The dominant, reproducible flaw the detector keys on: a public deposit whose
// `from` is a user-supplied address PARAMETER flowing straight into
// `transferFrom`, with the caller (not `from`) credited afterwards.
//
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract QBridge {
    // Bridged-asset balance the relayer mints against on the destination chain;
    // here, credited to whoever calls deposit() — never to `from`.
    mapping(address => uint256) public bridgedBalance;

    // Bridge `amount` of `token` from `from` and credit the caller's bridged
    // balance (which a relayer later mints on the other chain).
    //
    // BUG: `from` is a caller-supplied address parameter, not `msg.sender`, and
    // `token` is caller-supplied too. With no access control, an attacker calls
    // deposit(token, victim, amount) to pull `victim`'s approved tokens, or
    // points `token` at a no-op/native path so nothing is pulled at all — and
    // is still credited. Classic arbitrary-send-erc20 / mint-without-deposit.
    function deposit(address token, address from, uint256 amount) external returns (uint256) {
        // Attacker chooses `from`; the bridge never verifies it is the caller.
        IERC20(token).transferFrom(from, address(this), amount);
        bridgedBalance[msg.sender] += amount;
        return amount;
    }
}
