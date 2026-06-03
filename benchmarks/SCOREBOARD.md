# Sluice contest scoreboard

Recall + precision of Sluice vs published audit findings, over the contest corpus in `benchmarks/contests/*.json`. Regenerate with `cargo run -p sluice-bench --release`.

- **in-class recall** — known findings whose bug class Sluice models, caught at the right location with a compatible class.
- **out-of-class recall** — protocol-specific invariant/accounting/logic findings (no modeled detector class) caught.
- **Crit/High** — Sluice's Critical+High findings; **unmatched** = not aligned to any known finding (candidate false positives to triage).

| Contest | In-class recall | Out-of-class recall | Crit/High | Unmatched C/H | Total findings |
|---|---|---|---|---|---|
| `2023-01-reserve` | 80% (4/5) | 0% (0/2) | 13 | 11 | 84 |
| `2024-05-loop` | 100% (2/2) | 0% (0/3) | 0 | 0 | 3 |
| **AGGREGATE** | **86% (6/7)** | **0% (0/5)** | **13** | **11** | **87** |

## Per-finding detail

### `2023-01-reserve`

Repo `code-423n4/2023-01-reserve` @ `5e89ca44a917c9bd0277d58849c3edbc6181ff9d`.

| Known | Sev | Class | In-class | Result | Matched by | Summary |
|---|---|---|---|---|---|---|
| M-10 | Medium | `signed-cast` | yes | ✅ caught | SignedCast @ rtoken.sol:167 | issue() performs an unsafe downcast of an issuance amount to uint192 without bounds-checking, which can silently truncate and corrupt the issuance accounting. |
| M-07 | Medium | `erc777-reentrancy` | yes | ✅ caught | Erc777Reentrancy @ rtoken.sol:359 | redeem() transfers basket collateral that may be an ERC777 token; the receive hook re-enters before state settles, letting a redeemer extract more than their p… |
| M-02 | Medium | `share-inflation` | yes | 🟡 near (class mismatch) | — | The RSR:stRSR exchange rate can be inflated by a first/early staker (donation / rounding) so later stakers receive fewer shares than fair value — an ERC4626-st… |
| M-14 | Medium | `signed-cast` | yes | ✅ caught | SignedCast @ ctokenfiatcollateral.sol:46 | int8(referenceERC20Decimals) (and the analogous -int8(erc20Decimals) in Asset.bal) casts a uint8 decimals value to int8; a token with >127 decimals wraps negat… |
| M-18 | Medium | `cached-domain-separator` | yes | ✅ caught | CachedDomainSeparator @ strsr.sol:803 | StRSR caches the EIP-2612 domain separator at init but setName/setSymbol change the token name without recomputing it, so the cached DOMAIN_SEPARATOR no longer… |
| M-economic-rewards | Medium | `economic-reward-accounting` | no | 🟡 near (class mismatch) | — | Protocol-specific RSR-seizure / reward-distribution accounting edge (rounding of the seized amount across the era can leave dust or mis-split rewards) — an eco… |
| M-economic-melt | Medium | `economic-invariant` | no | 🟡 near (class mismatch) | — | Furnace melt-rate / period accounting (protocol-specific): the RToken melt schedule can be gamed across period boundaries to alter the realized melt, an econom… |

### `2024-05-loop`

Repo `code-423n4/2024-05-loop` @ `20d9013a93a1ba98154198d6cf3c63f73ab95658`.

| Known | Sev | Class | In-class | Result | Matched by | Summary |
|---|---|---|---|---|---|---|
| H-01 | High | `accounting-invariant` | no | ❌ missed | — | _claim sets claimedAmount = address(this).balance after the swap, so any pre-existing ETH balance (or a second claimer's funds) is credited to one user, over-m… |
| QA-setOwner | Low | `missing-zero-check` | yes | ✅ caught | MissingZeroCheck @ prelaunchpoints.sol:337 | setOwner assigns owner = _owner with no address(0) check; a zero owner permanently bricks the privileged role. |
| QA-setEmergencyMode | Low | `missing-event-emit` | yes | ✅ caught | MissingEventEmit @ prelaunchpoints.sol:372 | setEmergencyMode flips the emergencyMode flag without emitting an event, so the privileged state change is unobservable off-chain. |
| M-lockToken-allowlist | Medium | `logic-allowlist` | no | ❌ missed | — | Token allowlist / lock-token validation logic gap (protocol-specific): locked tokens are not constrained the way the design intends, allowing unsupported token… |
| M-swap-router-data | Medium | `logic-calldata-validation` | no | ❌ missed | — | User-supplied 0x swap calldata is only loosely validated; a crafted _data lets the swap deviate from the intended token/route (protocol-specific exchange-data … |

