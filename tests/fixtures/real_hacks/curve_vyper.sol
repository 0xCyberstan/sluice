// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:         Curve Finance / Vyper reentrancy-lock failure (July 30, 2023)
// Approximate loss:  ~$69,000,000 (across CRV/ETH, alETH/ETH, msETH/ETH, pETH/ETH
//                     and other native-ETH StableSwap pools)
// Expected detector: reentrancy
//
// Root cause: the affected pools were compiled with Vyper 0.2.15 / 0.2.16 / 0.3.0,
// whose `@nonreentrant('lock')` decorator was MISCOMPILED — the generated guard
// did not actually hold across the function, so the reentrancy lock was a no-op.
// `remove_liquidity` on a *native-ETH* pool sends raw ETH back to the caller (an
// external, control-transferring call) and only AFTER that updates the pool's
// per-coin `balances` and `total_supply`. With the lock broken, the attacker's
// `receive()` re-entered `remove_liquidity` (and add_liquidity / exchange) while
// `balances` and `total_supply` still held their stale, pre-burn values, letting
// them withdraw far more than their LP share was worth and drain the pool.
//
// The defect is the checks-effects-interactions inversion itself: a storage value
// is READ before the external ETH transfer and WRITTEN after it, with no working
// guard. Modeled here in Solidity with the (non-functional) lock omitted, exactly
// as the broken Vyper output behaved at runtime.

contract CurveETHPool {
    // Per-coin pool balances (coin 0 is native ETH here) and LP supply.
    uint256[2] public balances;
    uint256 public total_supply;                 // LP token total supply
    mapping(address => uint256) public balanceOf; // LP balances

    // VULNERABLE: interactions-before-effects with no working reentrancy lock.
    // `total_supply` and `balances[0]` are read to size the ETH payout, the ETH
    // is sent (handing control to the caller's receive()), and only THEN are
    // `total_supply`/`balanceOf`/`balances` debited. The re-entrant call sees the
    // un-debited supply and balances and computes another full-value payout.
    function remove_liquidity(uint256 lp_amount, uint256 min_eth) external {
        // ---- reads BEFORE the external call (stale values used for the payout) ----
        uint256 supply = total_supply;
        uint256 eth_bal = balances[0];
        uint256 eth_out = (eth_bal * lp_amount) / supply;
        require(eth_out >= min_eth, "slippage");

        // ---- INTERACTION: raw ETH transfer hands control to the caller ----
        // Equivalent to Vyper `raw_call(msg.sender, b"", value=eth_out)`.
        (bool ok, ) = msg.sender.call{value: eth_out}("");
        require(ok, "eth transfer failed");

        // ---- EFFECTS: state settled AFTER the call (too late) ----
        total_supply = supply - lp_amount;
        balanceOf[msg.sender] -= lp_amount;
        balances[0] = eth_bal - eth_out;
    }

    // Allows seeding the pool with ETH liquidity for the reconstruction.
    function add_liquidity() external payable {
        balances[0] += msg.value;
        total_supply += msg.value;
        balanceOf[msg.sender] += msg.value;
    }

    receive() external payable {}
}
