# Sluice contest scoreboard

Recall + precision of Sluice vs published audit findings, over the contest corpus in `benchmarks/contests/*.json`. Regenerate with `cargo run -p sluice-bench --release`.

- **in-class recall** — known findings whose bug class Sluice models, caught at the right location with a compatible class.
- **out-of-class recall** — protocol-specific invariant/accounting/logic findings (no modeled detector class) caught.
- **Crit/High** — Sluice's Critical+High findings; **unmatched** = not aligned to any known finding (candidate false positives to triage).

| Contest | In-class recall | Out-of-class recall | Crit/High | Unmatched C/H | Total findings |
|---|---|---|---|---|---|
| `2022-12-tigris` | 100% (4/4) | 0% (0/2) | 3 | 3 | 155 |
| `2023-01-reserve` | 80% (4/5) | 0% (0/2) | 13 | 11 | 87 |
| `2023-03-asymmetry` | 100% (5/5) | 50% (2/4) | 3 | 1 | 25 |
| `2023-04-caviar` | 100% (1/1) | 0% (0/4) | 0 | 0 | 41 |
| `2023-04-frankencoin` | 100% (8/8) | 0% (0/13) | 2 | 1 | 67 |
| `2023-06-stader` | 100% (3/3) | 8% (1/12) | 3 | 2 | 33 |
| `2023-07-basin` | 100% (3/3) | 0% (0/2) | 2 | 1 | 44 |
| `2024-05-loop` | 100% (2/2) | 50% (1/2) | 1 | 0 | 4 |
| **AGGREGATE** | **97% (30/31)** | **10% (4/41)** | **27** | **19** | **456** |

## Per-finding detail

### `2022-12-tigris`

Repo `code-423n4/2022-12-tigris` @ `a2896b60eec8815409d946580ce0ce0392851f00`.

| Known | Sev | Class | In-class | Result | Matched by | Summary |
|---|---|---|---|---|---|---|
| H-03-pnl-overflow | High | `integer-overflow` | yes | ✅ caught | UncheckedMath @ tradinglibrary.sol:36 | pnl() runs entirely inside an unchecked block; with a user-controlled take-profit/current price the expression (1e18 * _currentPrice / _price - 1e18) and _init… |
| H-06-addtoposition-price | High | `accounting-invariant` | no | 🟡 near (class mismatch) | — | addToPosition computes the blended entry price as _trade.price*_trade.margin/_newMargin + _price*_addMargin/_newMargin (a margin-weighted arithmetic average) i… |
| M-11-handleopenfees-referral | Medium | `economic-fee-accounting` | no | ❌ missed | — | _handleOpenFees returns an incorrect _feePaid when a referral is set (the referral discount/credit is mis-accounted), so the margin actually deposited diverges… |
| M-19-stablevault-decimals | Medium | `decimals-assumption` | yes | ✅ caught | DecimalsAssumption @ stablevault.sol:49 | deposit/withdraw scale the amount by 10**(18 - token.decimals()); a margin token with more than 18 decimals underflows the exponent (and the 18-decimal assumpt… |
| M-15-checkdelay-blocknumber | Medium | `block-number-as-time` | yes | ✅ caught | BlockNumberTime @ trading.sol:861 | _checkDelay enforces the anti-front-run open/close delay using block.number + blockDelay; on Arbitrum/Optimism block.number reflects the L1 block, not the L2 b… |
| M-24-verifyprice-staleness | Medium | `oracle-staleness` | yes | ✅ caught | OracleStaleness @ tradinglibrary.sol:91 | verifyPrice reads the Chainlink feed via latestAnswer() and uses it only as a +/-2% sanity band, never checking updatedAt/answeredInRound freshness, so a stale… |

### `2023-01-reserve`

Repo `code-423n4/2023-01-reserve` @ `5e89ca44a917c9bd0277d58849c3edbc6181ff9d`.

| Known | Sev | Class | In-class | Result | Matched by | Summary |
|---|---|---|---|---|---|---|
| M-10 | Medium | `signed-cast` | yes | ✅ caught | SignedCast @ rtoken.sol:167 | issue() performs an unsafe downcast of an issuance amount to uint192 without bounds-checking, which can silently truncate and corrupt the issuance accounting. |
| M-07 | Medium | `erc777-reentrancy` | yes | ✅ caught | Erc777Reentrancy @ rtoken.sol:359 | redeem() transfers basket collateral that may be an ERC777 token; the receive hook re-enters before state settles, letting a redeemer extract more than their p… |
| M-02 | Medium | `share-inflation` | yes | 🟡 near (class mismatch) | — | The RSR:stRSR exchange rate can be inflated by a first/early staker (donation / rounding) so later stakers receive fewer shares than fair value — an ERC4626-st… |
| M-14 | Medium | `signed-cast` | yes | ✅ caught | SignedCast @ ctokenfiatcollateral.sol:46 | int8(referenceERC20Decimals) (and the analogous -int8(erc20Decimals) in Asset.bal) casts a uint8 decimals value to int8; a token with >127 decimals wraps negat… |
| M-18 | Medium | `cached-domain-separator` | yes | ✅ caught | CachedDomainSeparator @ strsr.sol:803 | StRSR caches the EIP-2612 domain separator at init but setName/setSymbol change the token name without recomputing it, so the cached DOMAIN_SEPARATOR no longer… |
| M-23 | Medium | `economic-reward-accounting` | no | 🟡 near (class mismatch) | — | seizeRSR fails to update rsrRewardsAtLastPayout after seizing RSR, so the next payout computes rewards off a stale base and mis-distributes RSR rewards across … |
| M-15 | Medium | `frontrunning-ordering` | no | 🟡 near (class mismatch) | — | Furnace.melt() pays out RToken.balanceOf(this) on a public refresher with no protection, so it can be sandwiched: an attacker mints/issues right before melt() … |

### `2023-03-asymmetry`

Repo `code-423n4/2023-03-asymmetry` @ `1fa78d2116405a9e186bafabd24080c52bc32875`.

| Known | Sev | Class | In-class | Result | Matched by | Summary |
|---|---|---|---|---|---|---|
| H-01 | High | `first-depositor` | yes | ✅ caught | FirstDepositor @ safeth.sol:79 | stake() derives preDepositPrice = 10**18 * underlyingValue / totalSupply from live derivative balances; an early/sole staker can unstake down to a tiny supply … |
| H-03 | High | `dos-on-revert` | no | 🟡 near (class mismatch) | — | unstake() loops every derivative and calls derivatives[i].withdraw(); there is no way to remove a broken/untrusted derivative, so if one withdraw reverts (e.g.… |
| H-04 | High | `spot-priced-share-value` | no | ✅ caught | SpotPricedShareValue @ sfrxeth.sol:116 | SfrxEth.ethPerDerivative returns (10**18 * frxAmount) / price_oracle() — the price_oracle multiplication is inverted (should be frxAmount * price_oracle / 10**… |
| H-05 | High | `integer-overflow` | yes | ✅ caught | IntegerOverflow @ reth.sol:241 | Reth.poolPrice computes (sqrtPriceX96 * sqrtPriceX96 * 1e18) >> 192 with no overflow guard (unlike Uniswap's OracleLibrary); for large sqrtPriceX96 the multipl… |
| H-06 | High | `accounting-logic` | no | 🟡 near (class mismatch) | — | WstEth.withdraw computes minOut = stEthBal * (1e18 - maxSlippage) / 1e18, implicitly assuming 1 stETH = 1 ETH; during a stETH de-peg the Curve exchange returns… |
| M-04 | Medium | `missing-deadline` | yes | ✅ caught | MissingDeadline @ reth.sol:156 | Reth.deposit performs a Uniswap V3 swapExactInputSingleHop with no deadline parameter, so a pending stake transaction can be held by validators and executed la… |
| M-06 | Medium | `push-payment-dos` | no | ✅ caught | DenialOfService @ safeth.sol:124 | unstake() sends the withdrawn ETH with a single address(msg.sender).call{value:...} and requires success; a contract caller whose receive reverts (or a push-pa… |
| M-08 | Medium | `unbounded-loop` | yes | ✅ caught | UnboundedLoop @ safeth.sol:113 | unstake() loops over all derivatives (for i < derivativeCount), each doing external balance/withdraw calls; as derivativeCount grows the loop can exceed the bl… |
| M-12 | Medium | `slippage` | yes | ✅ caught | Slippage @ safeth.sol:63 | stake() accepts no user-supplied minimum-output (min safETH) parameter; the per-derivative deposits swap on AMMs and the final mintAmount has no slippage bound… |

### `2023-04-caviar`

Repo `code-423n4/2023-04-caviar` @ `5c87f7d69c6fac29eb253b5c7b2fb4a9f23f8750`.

| Known | Sev | Class | In-class | Result | Matched by | Summary |
|---|---|---|---|---|---|---|
| H-01-royalty-drain | High | `accounting-logic` | no | 🟡 near (class mismatch) | — | buy() computes royalties in a first loop, then refunds excess ETH to msg.sender via safeTransferETH, then re-reads _getRoyalty in a second loop to pay them. Th… |
| H-02-execute-arbitrary | High | `access-control` | yes | ✅ caught | Centralization @ privatepool.sol:459 | execute() lets the owner make an arbitrary target.call{value:msg.value}(data); the owner can approve/transfer NFTs or tokens held by the pool (including users'… |
| M-08-royalty-per-item | Medium | `accounting-logic` | no | 🟡 near (class mismatch) | — | buy()/sell() compute royalties using a single per-item sale price (salePrice = netAmount / tokenIds.length) even when NFTs carry different weights, so royaltie… |
| M-16-flashloan-fee | Medium | `accounting-logic` | no | 🟡 near (class mismatch) | — | flashLoan's fee handling is inconsistent: flashFee() returns an unscaled value (unlike changeFeeQuote) and the fee is pulled from the wrong address / not route… |
| M-14-ethrouter-royalty-recipient | Medium | `accounting-logic` | no | 🟡 near (class mismatch) | — | EthRouter.sell pays each NFT's royalty via royaltyRecipient.safeTransferETH using the recipient/amount returned per NFT; a non-payable or reverting royalty rec… |

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
| M-09 | Medium | `rounding-direction` | yes | ✅ caught | RoundingDirection @ position.sol:163 | Rounding/precision loss in the collateral-vs-price check can make legitimate position adjustments revert. |
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
| M-03 | Medium | `centralization` | yes | ✅ caught | Centralization @ permissionlessnoderegistry.sol:183 | A single Stader OPERATOR unilaterally validates validators (markValidatorReadyToDeposit) with no appeal path — a centralization / single-point-of-failure on a … |
| M-04 | Medium | `logic-conflicting-require` | no | ❌ missed | — | updatePoolAddress always reverts for an existing poolId due to mutually exclusive validation conditions. |
| M-05 | Medium | `consensus-quorum-logic` | no | ❌ missed | — | Consensus uses strict-equal submission counting vs a threshold that can never be met after trusted nodes are removed. |
| M-06 | Medium | `accounting-error` | no | ❌ missed | — | slashValidatorSD slashes only poolThreshold.minThreshold rather than the actual penalty, under-slashing larger penalties. |
| M-07 | Medium | `design-pause-asymmetry` | no | ❌ missed | — | When Auction is paused, addBid is blocked but the lot still closes, letting a last-minute MEV bidder win all lots. |
| M-08 | Medium | `oracle-data-corruption` | no | ❌ missed | — | SD price median is built from submissions across different reporting blocks, corrupting the aggregated value (protocol-specific oracle aggregation logic). |
| M-09 | Medium | `accounting-state-advance` | no | 🟡 near (class mismatch) | — | poolIdArrayIndexForExcessDeposit / lastExcessETHDepositBlock advance even when balance is insufficient, letting deposits be mis-routed. |
| M-10 | Medium | `logic-zero-owner` | no | 🟡 near (class mismatch) | — | initialise sets owner = staderConfig.getAdmin(); if the admin mapping is unset, owner becomes address(0) (protocol-specific init dependency, distinct from the … |
| M-11 | Medium | `frontrunning-deleverage` | no | ❌ missed | — | distributeRewards has only a partial guard (a non-operator may call it whenever totalRewards <= rewardsThreshold); calling it before settleFunds manipulates th… |
| M-12 | Medium | `accounting-error` | no | ✅ caught | Conservation @ validatorwithdrawalvault.sol:68 | settleFunds ignores the NodeELRewardVault balance when computing penalty coverage, over-charging the operator. |
| M-13 | Medium | `design-fixed-endblock` | no | ❌ missed | — | Fixed endBlock with no extension gives no incentive to bid early; only last-block MEV bids. |
| M-14 | Medium | `oracle-staleness` | yes | ✅ caught | OracleStaleness @ staderoracle.sol:637 | getPORFeedData uses latestRoundData() and discards updatedAt/answeredInRound, accepting stale/incorrect Proof-of-Reserve data. |

### `2023-07-basin`

Repo `code-423n4/2023-07-basin` @ `73f7133b380ea027048f0b9aaa284b14f3ce43b4`.

| Known | Sev | Class | In-class | Result | Matched by | Summary |
|---|---|---|---|---|---|---|
| H-01 | High | `oracle-manipulation` | yes | ✅ caught | OracleManipulation @ well.sol:596 | Well.sync() (and shift()) call _setReserves directly without first pushing the previous-block reserves into the attached pump (unlike swapFrom), so the pump's … |
| M-02 | Medium | `accounting-logic` | no | ❌ missed | — | storeUint128's odd-reserve branch re-reads the target slot's high 128 bits via shl(128, shr(128, sload(...))) and re-packs them; the slot/bit arithmetic mis-pr… |
| M-01 | Medium | `accounting-logic` | no | ❌ missed | — | getBytes32FromBytes bounds-checks with `index > data.length` instead of `>=`, allowing an out-of-bounds memory read of the last word, which can return corrupte… |
| M-06 | Medium | `rounding-direction` | yes | ✅ caught | RoundingDirection @ constantproduct2.sol:53 | calcLpTokenSupply computes the LP supply as sqrt(reserves[0]*reserves[1]*EXP_PRECISION); the integer sqrt loses precision asymmetrically versus the division us… |
| M-08 | Medium | `block-number-as-time` | yes | ✅ caught | TimestampDependence @ multiflowpump.sol:121 | The pump treats the immutable BLOCK_TIME as a permanent constant (blocksPassed = deltaTimestamp / BLOCK_TIME in _capReserve), so if average block time changes … |

### `2024-05-loop`

Repo `code-423n4/2024-05-loop` @ `20d9013a93a1ba98154198d6cf3c63f73ab95658`.

| Known | Sev | Class | In-class | Result | Matched by | Summary |
|---|---|---|---|---|---|---|
| H-01 | High | `value-source-discipline` | no | ✅ caught | ValueSourceDiscipline @ prelaunchpoints.sol:262 | _claim sets claimedAmount = address(this).balance after the swap, so any pre-existing/donated ETH (or a second claimer's funds) is credited to one user, over-m… |
| QA-03-setOwner | Low | `missing-zero-check` | yes | ✅ caught | MissingZeroCheck @ prelaunchpoints.sol:337 | setOwner assigns owner = _owner in one step with no address(0) check (QA: critical privileges transferred in one step); a zero owner permanently bricks the pri… |
| QA-04-setEmergencyMode | Low | `missing-event-emit` | yes | ✅ caught | MissingEventEmit @ prelaunchpoints.sol:372 | setEmergencyMode flips the emergencyMode flag without emitting an event (QA Finding 04: no event emissions for setEmergencyMode and allowToken), so the privile… |
| QA-06-validatedata-zero-recipient | Low | `logic-calldata-validation` | no | ❌ missed | — | _validateData validates the user-supplied 0x swap calldata but its recipient check `recipient != address(this) && recipient != address(0)` accepts address(0) a… |

