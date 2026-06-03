# Sluice contest scoreboard

Recall + precision of Sluice vs published audit findings, over the contest corpus in `benchmarks/contests/*.json`. Regenerate with `cargo run -p sluice-bench --release`.

- **in-class recall** — known findings whose bug class Sluice models, caught at the right location with a compatible class.
- **out-of-class recall** — protocol-specific invariant/accounting/logic findings (no modeled detector class) caught.
- **Crit/High** — Sluice's Critical+High findings; **unmatched** = not aligned to any known finding (candidate false positives to triage).

| Contest | In-class recall | Out-of-class recall | Crit/High | Unmatched C/H | Total findings |
|---|---|---|---|---|---|
| `2022-12-tigris` | 100% (5/5) | 0% (0/3) | 3 | 3 | 155 |
| `2023-01-reserve` | 80% (4/5) | 0% (0/2) | 13 | 11 | 86 |
| `2023-04-caviar` | 67% (2/3) | 0% (0/3) | 0 | 0 | 41 |
| `2023-04-frankencoin` | 88% (7/8) | 0% (0/13) | 2 | 1 | 66 |
| `2023-06-stader` | 50% (2/4) | 0% (0/11) | 3 | 2 | 29 |
| `2023-07-basin` | 100% (3/3) | 0% (0/2) | 0 | 0 | 42 |
| `2024-05-loop` | 100% (2/2) | 33% (1/3) | 1 | 0 | 4 |
| **AGGREGATE** | **83% (25/30)** | **3% (1/37)** | **22** | **17** | **423** |

## Per-finding detail

### `2022-12-tigris`

Repo `code-423n4/2022-12-tigris` @ `a2896b60eec8815409d946580ce0ce0392851f00`.

| Known | Sev | Class | In-class | Result | Matched by | Summary |
|---|---|---|---|---|---|---|
| H-verifyprice-chainlink-staleness | High | `oracle-staleness` | yes | ✅ caught | OracleStaleness @ tradinglibrary.sol:91 | verifyPrice uses Chainlink latestAnswer() only as a ±2% sanity band and never checks updatedAt/round freshness, so a stale Chainlink price (or a node price wit… |
| H-bridgemint-public | High | `access-control` | yes | ✅ caught | Centralization @ govnft.sol:64 | _bridgeMint is declared public with no access control, so anyone can mint GovNFTs directly instead of only the LayerZero receive path, inflating governance/rew… |
| H-verifyprice-sig-replay | High | `signature-replay` | yes | ✅ caught | SignatureReplay @ tradinglibrary.sol:91 | The node-signed PriceData (recovered via ECDSA) has no nonce or single-use binding; within the _validSignatureTimer window the same signature can be replayed a… |
| H-addtoposition-price-manip | High | `accounting-invariant` | no | 🟡 near (class mismatch) | — | addToPosition recomputes the entry price as a margin-weighted average of the old position price and the new verified price; this protocol-specific averaging ca… |
| H-handleopenfees-referral | High | `economic-fee-accounting` | no | ❌ missed | — | Open-fee / referral-fee accounting in _handleOpenFees can be manipulated (self-referral, fee-multiplier interactions) to reduce or redirect fees — a protocol-s… |
| M-stablevault-decimals | Medium | `decimals-assumption` | yes | ✅ caught | DecimalsAssumption @ stablevault.sol:49 | deposit/withdraw scale by 10**(18 - token.decimals()); a margin token with more than 18 decimals underflows the exponent (and the assumption breaks for non-18-… |
| M-checkdelay-blocknumber | Medium | `block-number-as-time` | yes | ✅ caught | BlockNumberTime @ trading.sol:861 | _checkDelay enforces the anti-front-run open/close delay using block.number + blockDelay; block production rate is chain-dependent and irregular (L2 sequencer)… |
| M-removemargin-liqprice | Medium | `accounting-invariant` | no | 🟡 near (class mismatch) | — | removeMargin lets a trader withdraw margin and shift the liquidation price adversely relative to the protocol's solvency intent — a protocol-specific margin/li… |

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

### `2023-04-caviar`

Repo `code-423n4/2023-04-caviar` @ `5c87f7d69c6fac29eb253b5c7b2fb4a9f23f8750`.

| Known | Sev | Class | In-class | Result | Matched by | Summary |
|---|---|---|---|---|---|---|
| H-royalty-per-item | High | `accounting-logic` | no | 🟡 near (class mismatch) | — | buy()/sell() compute the royalty using a single per-item sale price (salePrice = netAmount / tokenIds.length) even when NFTs have different weights, so royalti… |
| H-flashloan-fee | High | `accounting-logic` | no | 🟡 near (class mismatch) | — | flashLoan pulls the ERC20 fee from msg.sender after the callback and only checks msg.value for the ETH case; the flashloaned NFT is removed from the pool's eff… |
| M-execute-arbitrary-call | Medium | `access-control` | yes | ✅ caught | Centralization @ privatepool.sol:459 | execute() lets the owner make an arbitrary target.call{value:msg.value}(data); the owner can approve/transfer NFTs or tokens held by the pool (including users'… |
| M-setvirtualreserves-reprice | Medium | `centralization` | yes | ❌ missed | — | setVirtualReserves lets the pool owner reprice the AMM at will with no bound or timelock, so the owner can front-run a pending buy/sell to extract value — an o… |
| M-missing-deadline | Medium | `missing-deadline` | yes | ✅ caught | MissingDeadline @ privatepool.sol:385 | PrivatePool.buy/sell/change accept no deadline parameter (only the EthRouter wrappers do); a transaction can sit in the mempool and execute later at a stale pr… |
| M-ethrouter-royalty-recipient | Medium | `accounting-logic` | no | 🟡 near (class mismatch) | — | EthRouter royalty payment trusts the royalty recipient/amount returned for each NFT; a malicious NFT/registry can direct or inflate the royalty leg of a sell, … |

### `2023-04-frankencoin`

Repo `code-423n4/2023-04-frankencoin` @ `0761a287999fa3efac5c9fa9b70fcef5eeecc213`.

| Known | Sev | Class | In-class | Result | Matched by | Summary |
|---|---|---|---|---|---|---|
| H-01 | High | `frontrunning-deleverage` | no | 🟡 near (class mismatch) | — | Position owner frontruns a challenge by repaying debt and lowering the liquidation price, making the challenger lose collateral in the auction. |
| H-02 | High | `double-entry-token` | yes | ✅ caught | UnsafeErc20 @ position.sol:253 | A double-entrypoint collateral token lets the owner withdraw the underlying via the legacy address (token != address(collateral)) without repaying ZCHF, steali… |
| H-03 | High | `accounting-logic` | no | 🟡 near (class mismatch) | — | Owner sends collateral directly to the position before a challenge finishes so balance>=minimum, avoiding the cooldown extension and re-minting profitably. |
| H-04 | High | `dos-on-revert` | no | 🟡 near (class mismatch) | — | Transferring position ownership to address(0) makes the owner payout transfer in end() revert, permanently locking challenger collateral and bidder funds. |
| H-05 | High | `integer-overflow` | yes | ✅ caught | IntegerOverflow @ position.sol:307 | Setting price to type(uint256).max overflows price*_collateralAmount in the bid/avert check (and the analogous adjustPrice path), reverting challenge resolutio… |
| H-06 | High | `accounting-logic` | no | 🟡 near (class mismatch) | — | Self-challenging a position created at an inflated price lets an attacker extract the 2% CHALLENGER_REWARD from reserves repeatedly, draining the protocol / mi… |
| M-01 | Medium | `loop-index-logic` | no | ❌ missed | — | Loop burns addressesToWipe[0] every iteration instead of addressesToWipe[i], so only the first address is wiped. |
| M-02 | Medium | `accounting-logic` | no | 🟡 near (class mismatch) | — | Cloning with _minimum equal to the remaining limit reduces the original position's limit to zero, denying the owner further minting. |
| M-03 | Medium | `share-inflation` | yes | ✅ caught | FirstDepositor @ equity.sol:268 | Redeeming below the 1000e18 totalShares floor lets an attacker manipulate the share/asset ratio so later depositors get fewer shares (first-depositor / inflati… |
| M-04 | Medium | `block-number-as-time` | yes | ✅ caught | BlockNumberTime @ equity.sol:173 | Holding-duration vote-weight timing uses block.number, which ticks irregularly on L2s like Optimism, breaking the 90-day minimum holding gate. |
| M-05 | Medium | `accounting-logic` | no | ❌ missed | — | deny() sets cooldown = expiration, so the owner of a denied (never-started) position cannot withdraw collateral until the position expires. |
| M-06 | Medium | `griefing-collusion` | no | 🟡 near (class mismatch) | — | Colluding challenger+bidder repeatedly launch and avert minimal challenges to keep the position under the 1-day minting restriction, griefing the owner. |
| M-07 | Medium | `dos-on-revert` | no | 🟡 near (class mismatch) | — | The serial ZCHF/collateral transfers in end() can revert (zero-amount transfer or blacklisted recipient), locking all challenge funds; needs a pull / postpone … |
| M-08 | Medium | `rounding-direction` | yes | ✅ caught | RoundingDirection @ position.sol:80 | Clone price = _mint*1e18/_coll rounds down; the rounded-down price can fail the collateral invariant and revert valid clone mints (should round up). |
| M-09 | Medium | `rounding-direction` | yes | ❌ missed | — | Rounding/precision loss in the collateral-vs-price check can make legitimate position adjustments revert. |
| M-10 | Medium | `slippage` | yes | ✅ caught | Slippage @ equity.sol:241 | FPS mint (onTokenTransfer) and redeem provide no minimum-out / slippage bound, so users can be sandwiched on the bonding-curve price. |
| M-11 | Medium | `frontrunning-ordering` | no | 🟡 near (class mismatch) | — | A later challenger can bid on an earlier challenge to bump its end time, ordering their own challenge to settle first and claim the reward. |
| M-12 | Medium | `design-economic` | no | 🟡 near (class mismatch) | — | Fixed challenge period ignores network congestion / volatility, so auctions can settle at unfair prices. |
| M-13 | Medium | `lifecycle-role-revoke-gap` | yes | ✅ caught | LifecycleRoleRevokeGap @ frankencoin.sol:88 | Once a minter passes its application period (isMinter true) there is no path to pause or remove it; denyMinter only works during the window. |
| M-14 | Medium | `reorg-create` | no | ❌ missed | — | Factory creates positions without nonce/salt binding, so a chain reorg can let a position address be reused / re-pointed. |
| M-15 | Medium | `frontrunning-ordering` | no | ❌ missed | — | notifyLoss can be frontrun by redeem, letting FPS holders exit before the loss is booked and dumping the loss on remaining holders. |

### `2023-06-stader`

Repo `code-423n4/2023-06-stader` @ `86c27eb6b1fb6e0928aaa906614a2d1c6e7543e3`.

| Known | Sev | Class | In-class | Result | Matched by | Summary |
|---|---|---|---|---|---|---|
| H-01 | High | `unprotected-initializer` | yes | ✅ caught | UnprotectedInitializer @ vaultproxy.sol:20 | initialise() has no access control (only an isInitialized flag); an attacker can initialise a fresh proxy and, because the proxy delegatecalls the vault implem… |
| M-01 | Medium | `logic-role-revoke` | no | ❌ missed | — | updateAdmin revokes DEFAULT_ADMIN_ROLE then grants it; setting the same address loses admin access (protocol-specific role lifecycle). |
| M-02 | Medium | `missing-implementation` | no | ❌ missed | — | Several Pausable contracts (SocializingPool, StaderOracle, OperatorRewardsCollector, Auction) never expose pause()/unpause(), so pausing is impossible. |
| M-03 | Medium | `centralization` | yes | ❌ missed | — | A single Stader OPERATOR unilaterally validates validators (markValidatorReadyToDeposit) with no appeal path — a centralization / single-point-of-failure on a … |
| M-04 | Medium | `logic-conflicting-require` | no | ❌ missed | — | updatePoolAddress always reverts for an existing poolId due to mutually exclusive validation conditions. |
| M-05 | Medium | `consensus-quorum-logic` | no | ❌ missed | — | Consensus uses strict-equal submission counting vs a threshold that can never be met after trusted nodes are removed. |
| M-06 | Medium | `accounting-error` | no | ❌ missed | — | slashValidatorSD slashes only poolThreshold.minThreshold rather than the actual penalty, under-slashing larger penalties. |
| M-07 | Medium | `design-pause-asymmetry` | no | ❌ missed | — | When Auction is paused, addBid is blocked but the lot still closes, letting a last-minute MEV bidder win all lots. |
| M-08 | Medium | `oracle-data-corruption` | no | ❌ missed | — | SD price median is built from submissions across different reporting blocks, corrupting the aggregated value (protocol-specific oracle aggregation logic). |
| M-09 | Medium | `accounting-state-advance` | no | 🟡 near (class mismatch) | — | poolIdArrayIndexForExcessDeposit / lastExcessETHDepositBlock advance even when balance is insufficient, letting deposits be mis-routed. |
| M-10 | Medium | `logic-zero-owner` | no | 🟡 near (class mismatch) | — | initialise sets owner = staderConfig.getAdmin(); if the admin mapping is unset, owner becomes address(0) (protocol-specific init dependency, distinct from the … |
| M-11 | Medium | `access-control` | yes | ❌ missed | — | distributeRewards is permissionless and can be front-run to push a validator's balance below threshold, making it slashable. |
| M-12 | Medium | `accounting-error` | no | ❌ missed | — | settleFunds ignores the NodeELRewardVault balance when computing penalty coverage, over-charging the operator. |
| M-13 | Medium | `design-fixed-endblock` | no | ❌ missed | — | Fixed endBlock with no extension gives no incentive to bid early; only last-block MEV bids. |
| M-14 | Medium | `oracle-staleness` | yes | ✅ caught | OracleStaleness @ staderoracle.sol:637 | getPORFeedData uses latestRoundData() and discards updatedAt/answeredInRound, accepting stale/incorrect Proof-of-Reserve data. |

### `2023-07-basin`

Repo `code-423n4/2023-07-basin` @ `73f7133b380ea027048f0b9aaa284b14f3ce43b4`.

| Known | Sev | Class | In-class | Result | Matched by | Summary |
|---|---|---|---|---|---|---|
| H-storeuint128-odd-slot | High | `accounting-logic` | no | ❌ missed | — | storeUint128's odd-reserve branch re-reads the target slot's high 128 bits (shr(128, sload(...))) and re-packs them; with certain reserve counts/layouts this c… |
| M-pump-twap-manip | Medium | `oracle-manipulation` | yes | ✅ caught | TwapManipulation @ multiflowpump.sol:171 | The MultiFlow geometric-mean pump derives reserves consumers use as an oracle; a single large swap right before reading (and the first/seeded update) can move … |
| M-pump-update-timestamp | Medium | `timestamp-dependence` | yes | ✅ caught | TimestampDependence @ multiflowpump.sol:121 | update() drives the EMA/cumulative reserves off block.timestamp deltas cast to uint40; the weighting depends on the exact timing of updates, so a party control… |
| M-calcreserve-rounding | Medium | `rounding-direction` | yes | ✅ caught | RoundingDirection @ constantproduct2.sol:53 | calcReserve recovers a reserve via an integer square root; the rounding direction of the sqrt/division can round in favor of the swapper rather than the pool, … |
| M-pump-init-seeding | Medium | `accounting-logic` | no | ❌ missed | — | The pump's first update (_init) seeds lastReserves from whatever the well reserves are at that block; an attacker can set the initial cumulative/last reserves … |

### `2024-05-loop`

Repo `code-423n4/2024-05-loop` @ `20d9013a93a1ba98154198d6cf3c63f73ab95658`.

| Known | Sev | Class | In-class | Result | Matched by | Summary |
|---|---|---|---|---|---|---|
| H-01 | High | `value-source-discipline` | no | ✅ caught | ValueSourceDiscipline @ prelaunchpoints.sol:262 | _claim sets claimedAmount = address(this).balance after the swap, so any pre-existing ETH balance (or a second claimer's funds) is credited to one user, over-m… |
| QA-setOwner | Low | `missing-zero-check` | yes | ✅ caught | MissingZeroCheck @ prelaunchpoints.sol:337 | setOwner assigns owner = _owner with no address(0) check; a zero owner permanently bricks the privileged role. |
| QA-setEmergencyMode | Low | `missing-event-emit` | yes | ✅ caught | MissingEventEmit @ prelaunchpoints.sol:372 | setEmergencyMode flips the emergencyMode flag without emitting an event, so the privileged state change is unobservable off-chain. |
| M-lockToken-allowlist | Medium | `logic-allowlist` | no | ❌ missed | — | Token allowlist / lock-token validation logic gap (protocol-specific): locked tokens are not constrained the way the design intends, allowing unsupported token… |
| M-swap-router-data | Medium | `logic-calldata-validation` | no | 🟡 near (class mismatch) | — | User-supplied 0x swap calldata is only loosely validated; a crafted _data lets the swap deviate from the intended token/route (protocol-specific exchange-data … |

