# Ethereum Credit Guild — Sluice dogfood / novel-bug hunt (2026-06-05)

Read-only review of `~/Data/bench/2023-12-ethereumcreditguild/src` (C4 contest, commit 2facb8f). Gauge-voted credit protocol: `LendingTerm`, `AuctionHouse`, `SimplePSM`, `ProfitManager`, rebasing `CreditToken`/`ERC20RebaseDistributor`, `GuildToken`.

## Bottom line
Confirmed **2 real Highs** (both correspond to C4 H-02 / H-04, verified with precise mechanisms — not novel, but stake-your-name solid). No new High beyond the known set this pass; best novel lead noted at the end.

## CONFIRMED #1 (High) — self-transfer mints arbitrary CREDIT via stale `rebasingState[to]` snapshot → drains PSM
- **Location:** `src/tokens/ERC20RebaseDistributor.sol:553-642` (`transfer`), identical at `:646-736` (`transferFrom`); reachable via `CreditToken.transfer/transferFrom` (`CreditToken.sol:113-136`) — no `from != to` guard.
- **Invariant:** `Σ balanceOf == totalSupply` and share conservation across a transfer.
- **Root cause:** both `rebasingStateFrom` (L559) and `rebasingStateTo` (L560) are snapshotted from the SAME storage slot at entry. The `from` branch writes new `nShares` (L596). The `to` branch then recomputes from the **stale in-memory `rebasingStateTo.nShares`** (L607) + a freshly re-read raw balance (L605), and mints `toBalanceAfter - rawToBalanceAfter` (L626-628).
- **Exploit (self-transfer whole balance R, rebasing account):** `from` branch sets shares→0; `to` branch uses stale `S` → `toBalanceAfter = 2R`, overwrites slot `nShares = 2S`, and `_mint(self, R)`. Account doubles its balance per call; repeat → unbounded CREDIT inflation.
- **Impact:** minted CREDIT redeems 1:1-via-multiplier at `SimplePSM.redeem` (`SimplePSM.sol:134`) → drains the entire PSM peg-token reserve; CREDIT worthless. Catastrophic.
- **Fix:** short-circuit `from == to`, or reload `rebasingState[to]` from storage after the `from`-branch write (don't use the L560 memory snapshot).

## CONFIRMED #2 (High) — `SurplusGuildMinter.getRewards` reads `userStake.lastGaugeLoss` before loading the stake → spurious slashing
- **Location:** `src/loan/SurplusGuildMinter.sol`, ordering of L229 vs L234.
- **Root cause:** `slashed = lastGaugeLoss > uint256(userStake.lastGaugeLoss)` (L229) is evaluated while `userStake` is the zero-initialized return var (`lastGaugeLoss == 0`); the real stake loads only at L234.
- **Impact:** any term that has EVER had a loss (`lastGaugeLoss > 0`) slashes a brand-new staker on first interaction (L274-284 wipes credit+guild stake + forfeits rewards), even though they staked after the loss. Loss of staked principal/rewards → High.
- **Fix:** move the `userStake = _stakes[user][term];` load above the L229 comparison.

## Triaged & rejected (with reasons)
- **`notifyPnL` creditMultiplier cascade** (`ProfitManager.sol:331-334`): proportional mark-down, no amplification; `getLoanDebt`/`onBid` correctly mark debts up when CREDIT devalues. Documented socialization, not a bug.
- **PSM bypasses `RateLimitedMinter`** (`SimplePSM.mint`): intentional; PSM mint is fully 1:1 collateralized same-call and excluded from `totalBorrowedCredit`, so it doesn't create the uncollateralized issuance the limiter throttles.
- **gauge-weight unstake at 1.2e18 tolerance**: lets issuance exceed ideal weight by 20%; unstaking can leave `issuance > debtCeiling` but that only blocks NEW borrows — documented tradeoff, no clean broken invariant.

## Best novel lead (unconfirmed)
The same stale-snapshot family in `_mint`/`_burn` during the 30-day reward interpolation: whether `decreaseUnmintedRebaseRewards` (`ERC20RebaseDistributor.sol:228-239`) can underflow or be double-decremented across the `from`/`to` branches when BOTH are rebasing in a single transfer. Not fully closed out.
