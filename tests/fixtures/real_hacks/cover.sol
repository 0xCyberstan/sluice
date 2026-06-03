// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:         Cover Protocol infinite-mint exploit (December 28, 2020)
// Approximate loss:  ~$3,000,000 effective (the attacker minted ~40 quintillion
//                     COVER governance tokens; ~$3M was dumped before a
//                     whitehat returned the bulk of the funds)
// Expected detector: access-control
//
// Root cause: Cover's `Blacksmith` rewards (yield-farming) contract minted COVER
// governance tokens to stakers from a STORED, per-user accounting value. Its
// deposit/withdraw path recomputed a pool's `accRewardsPerToken`, then minted
//     newRewards = miner.amount * accRewardsPerToken / 1e12 - miner.rewardWriteoff
// to the caller — but it read `miner` from a STALE in-memory copy whose
// `rewardWriteoff` was never resynced after the pool's accumulator was bumped.
// The mint expanded the privileged GOVERNANCE-token supply directly, was guarded
// by NO access control, and had no accounting/sync invariant, so a caller could
// re-enter the flow and inflate the governance supply without bound.
//
// The dominant, reproducible flaw reduced here: a PUBLICLY callable reward
// function that WRITES the privileged governance-token supply (a privileged
// scalar) with no `onlyOwner`/`onlyMinter` guard and no settled-accounting check.

contract Blacksmith {
    // Privileged scalar: the mintable COVER GOVERNANCE-token supply. Expanding
    // it is equivalent to minting governance tokens, so it must be guarded.
    uint256 public governanceSupply;

    // Per-pool reward accumulator (scaled by 1e12), bumped each interaction.
    uint256 public accRewardsPerToken;

    struct Miner {
        uint256 amount;         // staked LP balance (attacker-controllable)
        uint256 rewardWriteoff; // accounting baseline; MUST be resynced on each mint
    }
    mapping(address => Miner) public miners;
    mapping(address => uint256) public coverBalance; // COVER credited to each staker

    // Stake LP and (re)settle rewards.
    //
    // VULNERABLE: no access control and no guard that `rewardWriteoff` was synced
    // to the *current* accumulator before paying out. `pending` is computed from
    // the STORED `amount`/`rewardWriteoff`, then minted by expanding the privileged
    // `governanceSupply` — any caller can drive this and inflate the governance
    // supply at will.
    function deposit(uint256 lpAmount) external {
        Miner storage m = miners[msg.sender];

        // Reward owed since last writeoff, taken straight off stored accounting.
        uint256 pending = (m.amount * accRewardsPerToken) / 1e12 - m.rewardWriteoff;
        if (pending > 0) {
            governanceSupply += pending;        // privileged supply write, no auth
            coverBalance[msg.sender] += pending; // hand the freshly minted COVER over
        }

        m.amount += lpAmount;
        // BUG: writeoff is NOT updated to (m.amount * accRewardsPerToken / 1e12)
        // here, so the next call re-mints `pending` again off the stale baseline.
    }
}
