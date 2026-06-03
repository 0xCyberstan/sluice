// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:         Orion Protocol (ExchangeWithOrionPool) — February 2, 2023
// Approximate loss:  ~$3M (across Ethereum and BSC)
// Expected detector: reentrancy
//
// Root cause: Orion's exchange let a user deposit ANY ERC20 by passing the token
// address as a parameter. depositAsset() snapshotted the user's current internal
// balance, then pulled the tokens with transferFrom, and only AFTER the transfer
// wrote the new balance built from that pre-call snapshot — classic
// read-before / write-after with no reentrancy guard. The attacker deposited a
// self-authored token whose transferFrom() ran a callback that re-entered
// depositAsset() before the first write landed. Every nested call read the same
// stale snapshot and credited on top of it, so the recorded balance compounded
// far beyond the tokens actually delivered. The attacker then withdrew the
// inflated balance, draining the exchange's real reserves (routed out as USDT).

interface IERC20 {
    // On a normal token this is a plain pull. But the token is supplied by the
    // caller, so transferFrom is attacker-controlled code: it can invoke a hook
    // that calls straight back into depositAsset before this returns.
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract OrionExchange {
    // assetBalances[user][token] — the exchange's internal credit ledger.
    mapping(address => mapping(address => uint256)) public assetBalances;

    // VULNERABLE: the balance is READ before the external call and the updated
    // balance is WRITTEN after it, with `token` being any address the caller
    // passes. An attacker token re-enters here while `prior` is still stale, so
    // each re-entry credits on top of the same uncredited base.
    function depositAsset(address token, uint256 amount) external {
        // READ: snapshot taken before control leaves the contract.
        uint256 prior = assetBalances[msg.sender][token];

        // INTERACTION: hands control to attacker-supplied token code.
        bool ok = IERC20(token).transferFrom(msg.sender, address(this), amount);
        require(ok, "transferFrom failed");

        // WRITE: applied after re-entry, from the stale snapshot — compounds.
        assetBalances[msg.sender][token] = prior + amount;
    }

    // Withdraw the (inflated) recorded balance, pulling out real reserves.
    function withdraw(address token, uint256 amount) external {
        uint256 bal = assetBalances[msg.sender][token];
        require(bal >= amount, "insufficient");
        assetBalances[msg.sender][token] = bal - amount;
        IERC20(token).transfer(msg.sender, amount);
    }
}
