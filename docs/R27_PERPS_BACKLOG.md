# R27 candidate backlog — perpetuals / derivatives

> Source: R26 WF3 research agent, anchored to the live **Code4rena 2025-08 GTE Perps** corpus (a CLOB perps
> DEX: FundingRateEngine/Position/ClearingHouse/LiquidatorPanel/InsuranceFund/PriceHistory/Market.sol),
> cross-checked vs the SlowMist decentralized-perps audit guide + perpdex liquidation-attacks catalogue.
> Novelty verified: NO existing detector keys on funding/cumulativeFunding, mark/index price, ADL, OI-cap, or
> subaccount. Closest existing (interest-index-desync, liquidation-abuse, bad-debt-socialization, oracle-staleness,
> price-bounds, twap-manipulation) are all distinct (single-feed / lending / AMM shapes). Best first builds: #1 + #3.

## Ranked specs

**1. `FundingIndexSettleOrdering` (High, needs corpus) — BEST FIRST.** A path realizes a position's funding
(`payment = posAmount * (globalCumulativeFunding − position.lastCumulativeFunding)`) or makes a solvency/liquidation
decision against the global cumulative-funding index WITHOUT first advancing it via the interval-gated settle routine
→ charged against a stale index, re-accrued next call. The funding analog of interest-index-desync but on a
time/interval-gated index (`settleFunding` reverts `FundingIntervalNotElapsed`). Predicate: fire on externally-reachable
state-mutating `f` in a contract declaring a funding-index construct (state var/field `cumulativefunding`/`fundingindex`
or call `realizefundingpayment`/`getfundingpayment`), that (a) realizes funding or reads `*cumulativeFunding*`/`*fundingIndex*`
AND (b) on the same path writes a position field (openNotional/amount/margin/lastCumulativeFunding) or makes a liquidation
decision (`isliquidatable`/`assertliquidatable`/`hasbaddebt`/`minmargin`). Suppress: same fn or internal callee advances+persists
the global index (`settlefunding`/`_settlefunding`/`updatefunding` or a global `lastFundingTime`/`cumulativeFundingIndex` write
before the decision); `view`/`pure`. Anchor: gte-perps `ClearingHouse.isLiquidatable` (reads current `cumulativeFunding`, not
settled) + `LiquidatorPanel._setupAccountAndValidateLiquidation`; settle gated in `FundingRateEngine.settleFunding`. SlowMist
"Funding Fee Accumulation Check".

**2. `MarkVsIndexPriceInconsistency` (High, needs corpus — highest value/highest FP-risk).** Protocol maintains both a
platform `markPrice`/`markTwap` and an oracle `indexPrice`/`indexTwap`, and uses different ones for the liquidation/solvency
CHECK vs the PnL/close/settlement EXECUTION (or the non-conservative direction) → solvent at check price, different value at
execution (perpdex "Criteria Price Arbitrage"). Predicate: restrict to contracts declaring BOTH constructs; fire when the
solvency surface (`liquidat*`/`isliquidatable`/`*upnl*`/`*minmargin*`) reads construct A while the close/PnL helper reads B
(decision fn mentions A not B; settlement helper mentions B not A), or a single liquidation comparison uses a price symbol
with no direction-conditioned selection (`isLong ? low : high` / min/max). Suppress: same symbol both sides; conservative
selector present; single-construct contracts (defer to single-feed detectors). Anchor: gte-perps `Market.getUpnl*`/
`getNotionalValue` use `markPrice` while `FundingRateEngine._calcFundingIndex` uses `markTwap − indexTwap`. SlowMist "Extreme
Price Selection".

**3. `OICapCheckedBeforeFillCallout` (Med-High, ordering predicate robust now) — BEST FIRST.** An open-interest/capacity cap
is asserted BEFORE a position-modifying external/cross-module callout (CLOB fill / settlement hook), but the OI counters
(longOI/shortOI) are mutated only AFTER the callout returns and the cap is NOT re-checked post-update → fill pushes OI past
cap / callout re-enters. Predicate: fire on entry-point state-mutating `f` with (a) a guard/`require` on an OI/capacity symbol
(`openinterest`/`longoi`/`shortoi`/`oicap`/`maxopeninterest`/`maxmarketsize`/`skew`), (b) `first_external_call().is_some()`,
(c) an OI write/`updateOI` with `order > call.order`, AND (d) NO OI cap comparison after the callout. Suppress: post-callout
recheck present; OI updated before callout; reduce-only paths; reentrancy-guarded atomic pre-call check. Uses existing
`storage_writes.order` vs `first_external_call().order` (first-class). Anchor: gte-perps `ClearingHouse.processMakerFill`/
`_processTakerFill` → `MarketLib.updateOI` trails the fill. SlowMist "Global Open Interest Cap Check". (Synthetix-V3
`maxMarketSize` — VERIFY.)

**4. `PnlSettledBeforeFundingApplied` (Med-High, needs corpus).** On decrease/close/liquidation, realized PnL is settled onto
margin BEFORE the position's funding/borrow-fee is realized (or from inconsistent snapshots) → trader escapes owed funding /
double-charged; or margin returned before fees deducted. Predicate: in a perps-shaped contract, fire on a close/decrease/liq fn
where a margin write adding rpnl (or a returnMargin/credit call) has lower `order` than the funding realization
(`realizeFundingPayment` / `lastCumulativeFunding` write / `margin -= fundingPayment`), OR the realize call is absent on a path
settling rpnl. Suppress: funding netted in the SAME assignment (`margin += rpnl − fundingPayment − fee` — the safe GTE form);
`view`/`pure`; realize ordered before the credit. Anchor: gte-perps `_processTakerFill`/`processMakerFill` do it correctly
(realize first, then `margin += rpnl − fundingPayment − fee`) → must stay silent on that; fire on inverted/omitted. SlowMist
"Margin Deduction"/"PnL Calculation Consistency".

**5. `ADLBypassesSolvencyOrCounterparty` (Med, needs corpus).** Auto-deleverage reuses the regular liquidatable check instead
of an independent bad-debt reduction, or fails counterparty-pairing (maker underwater, taker still margined, opposite sides).
Predicate: fire on a deleverage/ADL/backstop fn omitting any of: a maker bad-debt check (`hasbaddebt`/`underwater`/`isbankrupt`),
a taker open-margin check (`isopenmarginrequirementmet`/`minopenmargin`), an opposite-side assertion (two `isLong` compared);
secondary: ADL gates on the same `isLiquidatable` as the standard liquidator with no `bankruptcyprice`/`baddebt` path. Suppress:
all three pairing predicates present (safe `_validateDeleveragePair`). Anchor: gte-perps `LiquidatorPanel._validateDeleveragePair`
(correct reference) + `_deleverage` (`_getBankruptcyPrice` + `InsuranceFund.claim`). SlowMist "ADL Logic Independence".

**6. `InsuranceFundBadDebtNettingDesync` (Med, needs corpus).** A dedicated insurance bucket exists but its pay/claim netting
is asymmetric/sign-dependent → fund balance diverges from realized loss (bad debt claimed without offsetting fee, or residual
dropped). Distinct from bad-debt-socialization (shared share-price index, no bucket). Predicate: in a contract with an insurance
construct (`insurancefund`, `pay`/`claim`), fire on a liq/ADL fn computing both a bad-debt and a fee but routing them to the fund
on antisymmetric branches (`if (fee>0) pay else claim`) with a separately-computed badDebt NOT in the same netting; secondary:
`claim(badDebt)` not bounded by `min`/clamp against the shortfall. Suppress: reconciled in one netting helper
(`_balanceBadDebt(fee, badDebt)`) before a single pay/claim; clamped claim. Anchor: gte-perps `LiquidatorPanel` (`_balanceBadDebt`
is the correct reconciliation; `InsuranceFund.claim` only reverts on underflow). perpdex "Cross-Order Attack".

**7. `SameBlockMarkPriceSnapshotOverwrite` (Med, secondary/corpus-dependent).** A mark-price TWAP buffer overwrites the current
block's snapshot in place (`if last.timestamp==block.timestamp last.price=price`) rather than appending → within one block the
latest/TWAP is the last value written; a fn that pushes the mark price then reads `latest()`/`twap()` same-block for a
liquidation/funding decision consumes an attacker-chosen value (mark-price manipulation, in-scope per GTE README; distinct from
twap-manipulation's AMM slot0 shape). Predicate: contract with a snapshot construct whose writer overwrites on equal timestamp +
a twap/latest reader; fire on a state-mutating liq/funding/valuation fn that both updates the snapshot and reads twap/latest
(write order < read order). Suppress: append-only buffer; multi-block min-window enforcement; pure view readers. Anchor: gte-perps
`PriceHistory.snapshot` (same-timestamp overwrite) read by `twap`/`latest`. Keep secondary — risks being a one-protocol detector.

## Dropped / merged (honest)
- Position-key/subaccount collision — DROPPED (GTE uses clean nested mapping; generic hashing already covered by
  selector-collision/encodepacked-collision; speculative without anchor).
- Oracle-confidence/spread on a perps mark — MERGED into #2 (the distinct mark-vs-index angle is #2; the index-feed confidence
  overlaps oracle-staleness/price-bounds).
- Funding-rate clamp / interest-skew miscalc — DROPPED as a detector (protocol-arithmetic-specific numeric-bounds property; better left to review).

## Corpus fetch (read-only, for tuning — clone to e.g. ~/Data/perps-corpus/)
```
git clone --depth 1 https://github.com/code-423n4/2025-08-gte-perps        # PRIMARY — every spec anchored here: contracts/perps/{types,modules}/*.sol
git clone --depth 1 https://github.com/gmx-io/gmx-synthetics               # GMX v2: Position/Order/Pricing/Fee/Funding handlers
git clone --depth 1 https://github.com/Synthetixio/synthetix-v3           # perps-market: maxMarketSize, funding, settlement (#3 VERIFY)
git clone --depth 1 https://github.com/Synthetixio/synthetix              # PerpsV2MarketBase: nextFunding/skew/premium
git clone --depth 1 https://github.com/perpetual-protocol/perp-curie-contract  # ClearingHouse/AccountBalance: settlePnl, bad debt
git clone --depth 1 https://github.com/dydxprotocol/perpetual            # dYdX v3 Perpetual: funding index, liquidation
```
Tuning priority: #2 + #4 are highest-value/highest-FP-risk (most cross-protocol calibration); #1 + #3 have the most robust
SCIR predicates today (ordering + state-var gating) → build first. Apply the R7 dogfood discipline: fire on a vulnerable
shape, ~0 FP on the correct GTE reference forms (which are mostly safe).
