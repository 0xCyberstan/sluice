// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:         Lendf.Me / dForce — April 19, 2020
// Approximate loss:  ~$25M (drained, later returned by the attacker)
// Expected detector: erc777-reentrancy
//
// Root cause: Lendf.Me listed imBTC, an ERC777 token, as a supplyable asset.
// ERC777 invokes a `tokensToSend` / `tokensReceived` hook on the counterparty
// during transfer, handing control to the sender BEFORE the transfer's effects
// are observable to the protocol. supply()/withdraw() moved the tokens FIRST and
// only THEN updated the user's internal balance, with no reentrancy guard. The
// attacker's hook re-entered supply() during withdraw() (and vice versa) while
// the recorded balance was stale, inflating their credited supply far beyond the
// tokens actually deposited, then withdrew the inflated balance to drain the pool.

interface IERC777 {
    // ERC777 send: dispatches the recipient's `tokensReceived` hook (and the
    // sender's `tokensToSend` hook) mid-transfer — a control-transferring call.
    function send(address to, uint256 amount, bytes calldata data) external;
    // Looks like a vanilla ERC20 pull, but on an ERC777 it fires the hooks too.
    function safeTransferFrom(address from, address to, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
}

contract LendfMePool {
    IERC777 public immutable token; // the supplied asset, e.g. imBTC (ERC777)

    mapping(address => uint256) public supplyBalance; // internal accounting

    constructor(IERC777 _token) {
        token = _token;
    }

    // VULNERABLE: tokens are pulled (ERC777 hook fires) BEFORE the balance is
    // credited. The attacker's `tokensToSend` hook re-enters while supplyBalance
    // is still stale, with no nonReentrant guard.
    function supply(uint256 amount) external {
        token.safeTransferFrom(msg.sender, address(this), amount); // hook -> attacker
        supplyBalance[msg.sender] += amount;                       // effect, too late
    }

    // VULNERABLE: tokens are sent out (ERC777 `tokensReceived` hook fires) BEFORE
    // the balance is debited, so the hook re-enters with the old, larger balance.
    function withdraw(uint256 amount) external {
        require(supplyBalance[msg.sender] >= amount, "insufficient");
        token.send(msg.sender, amount, "");  // hook -> attacker re-enters here
        supplyBalance[msg.sender] -= amount; // effect, applied after reentry
    }
}
