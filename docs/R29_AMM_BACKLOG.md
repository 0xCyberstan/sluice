# R29 candidate backlog — concentrated-liquidity AMM core

> Source: R28 WF3 research agent, anchored to live Uniswap/v3-core (Tick/Position/SwapMath/TickMath/TickBitmap/
> UniswapV3Pool) on 2026-06-03. Distinct from Sluice's v4 round (which covered HOOKS + flash-accounting, NOT core
> tick math). **Duplication guard:** existing `feegrowth-accounting` fires only on the *unchecked over-claim* shape
> and SUPPRESSES the checked case; `rounding-direction` fires only on mint/redeem/burn-named `a*b/c`. Every spec
> below is chosen distinct from both. No IR extension required (spec #3 would benefit from adding feeGrowthInside/
> secondsPerLiquidity to the dataflow PriceLike set).

## Ranked specs

**1. `CheckedFeeGrowthRecompute` (High) — STRONGEST, build first.** An *integrator* recomputes v3
`feeGrowthInside = feeGrowthGlobal − feeGrowthOutsideLower − feeGrowthOutsideUpper` (or `… − …Last`) in a CHECKED
context on `^0.8` — but these are `uint256` ring counters that wrap by design, so the checked subtraction REVERTS
when the subtrahend exceeds the minuend (common on low-fee pools) → hard DoS of the integrator's liquidation/valuation
path. The **inverse** of `feegrowth-accounting` (which treats the checked case as safe). Predicate: gate
`solidity_ge_0_8()` ∧ fn is view/pure or named getfeegrowthinside/feegrowth/position/computefees/liquidat*; fire on a
`Binary{Sub}` (incl. nested `a−b−c`) with a `feegrowth`-matching operand NOT inside a `Block{unchecked:true}` (the
complement of the existing detector's isolation); corroborate when operands are ExternalReturn/feeGrowthGlobal/Outside
params. Suppress: the pool itself (declares feeGrowthGlobal0X128 + feeGrowthOutside* updated in `swap`); a
`require(global >= outside)` ordering; pre-0.8 pragmas. Anchor: Code4rena 2023-12-particle #10 `Base.getFeeGrowthInside`
(checked subtraction on 0.8.23, reverted liquidations on 0.05% pools); contrast v3-core `Tick.getFeeGrowthInside`
(same math, 0.7.6 wrap). Needs corpus only for FP dogfood.

**2. `TickCrossLiquidityNetSign` (High).** On a swap crossing an initialized tick, `liquidityNet` must be applied
direction-dependently (`if (zeroForOne) liquidityNet = -liquidityNet;` before `addDelta`). A fork dropping/inverting/
unconditional-negating corrupts active L across the boundary → mis-prices every subsequent step / bricks the pool.
Predicate: swap loop (`has_loop` + a `cross`-named call or `liquiditynet` read); find the `addDelta`/`state.liquidity ±=
liquidityNet`; FIRE when between `cross` and `addDelta` there's NO `If` on a direction flag (zeroforone) containing a
`Unary{Negate}` of liquidityNet (conditional sign-flip structurally absent); lower-confidence fire on unconditional
`liquidityNet = -liquidityNet`. Suppress: require the cross+addDelta co-occurrence (kills non-CL); negation guarded by a
direction `if` (correct); inline ternary `zeroForOne ? -ln : ln`; interface decls. Anchor: v3-core `UniswapV3Pool.swap` +
`Tick.cross`. Needs corpus (Algebra uses different names).

**3. `FeeGrowthInsideAsSpotValue` (High).** An integrator reads `feeGrowthInside`/`feeGrowthGlobal`/
`secondsPerLiquidityInside` at a SINGLE block and uses the raw value (or single-block delta) as price/TVL/reward/share
value — these accumulators are instantaneous and FLASH-MANIPULABLE (swap to inflate within the tx). Correct use needs
two time-separated snapshots (TWAL). Predicate: external value (ExternalReturn/StaticCall/storage read) whose source
matches feegrowthinside|feegrowthglobal|secondsperliquidity flowing (via provenance) into an accounting write / a
valuation-named return (price/value/quote/reward/weight/share) / a transfer-gating compare. Suppress: two reads
differenced across stored snapshots (`…Last`/`…Snapshot`/`…Prev` — legit TWAL); the pool itself; read used only to
credit tokensOwed (→ feegrowth-accounting's domain). Distinct from `oracle-manipulation` (keys on balanceOf/getReserves/
slot0, NOT fee accumulators). Anchor: Uniswap TWAL docs + oracle-manipulation family generalized — **VERIFY** a single
named integrator finding at build. Needs corpus (single-block-vs-differenced discrimination is the whole game).

**4. `TickBitmapNextWordBoundary` (Medium, ship Sub-check A only).** `nextInitializedTickWithinOneWord` scans within
one 256-bit word; caller must loop to the next word, and compressed-tick math floors negative ticks
(`if (tick<0 && tick%tickSpacing!=0) compressed--;`). Sub-check A (negative-tick floor missing): fn computes
`compressed = tick/tickSpacing` but has NO `if (tick<0 ... %tickSpacing!=0)` decrement → fire. Sub-check B (boundary
treated as initialized — caller ignores the returned `initialized` bool): lower-confidence, needs corpus. Suppress:
require the bitmap shape (`>>8`/`/256`/msb/lsb). Anchor: v3-core `TickBitmap.nextInitializedTickWithinOneWord`/`position`.
Lowest build-confidence (bit math the IR sees as generic arithmetic) — ship A first.

**5. `ProtocolFeeRoundsToZero` (Medium, Info/Low severity).** `delta = step.feeAmount / feeProtocol` truncates to 0
when feeAmount < feeProtocol → zero protocol fees on small swaps; attacker fragments a swap into sub-feeProtocol steps
to dodge the fee. Predicate: in a swap/fee fn, a `Binary{Div}` with a `fee`-named numerator and `feeprotocol`-named
denominator, quotient `+=`'d to a protocolfee accumulator, no non-zero guard, no ceil idiom (`!has_ceil_idiom`).
Suppress: require both fee-numerator + protocol-fee divisor; a min-fee floor `require`; const divisor proving no
truncation. Distinct from `rounding-direction` (mint/redeem only). Anchor: v3-core `UniswapV3Pool.swap` protocol-fee
split. **Ship at Info/Low** — by-design in canonical v3; escalate only on forks with a larger/per-step divisor.

**6. `SwapStepRoundingDirectionInverted` (Medium).** `SwapMath.computeSwapStep` rounds amountIn UP, amountOut DOWN
(pool's favor), fee via `mulDivRoundingUp`. A fork flipping a `roundUp` bool (in→down or out→up), or using `mulDiv` for
the fee, leaks value per step. Predicate: in computeswapstep/swap-math, inspect the `roundUp` bool arg of
`getamount0delta`/`getamount1delta`; FIRE when an amount-in computation passes `roundUp=false` or an amount-out passes
`roundUp=true` (inverted vs canonical), or fee uses bare `mulDiv`. Suppress: require the getAmount*Delta callee; the
correct in→up/out→down mapping; only literal-bool args (computed roundUp out of scope). Anchor: v3-core `SwapMath.
computeSwapStep` (+ `SqrtPriceMath`). Needs corpus (roundUp arg position differs per callee).

**7. `SqrtPriceTickBoundCheckMissing` (Low/Medium, ship last, tightly gated).** `TickMath` enforces
`require(absTick <= MAX_TICK,'T')` and `require(sqrtPriceX96 >= MIN_SQRT_RATIO && < MAX_SQRT_RATIO,'R')` (asymmetric `<`
on the upper sqrt bound). A fork omitting these or using `<=` where `<` is required overflows/returns out-of-domain.
Also: a swap `sqrtPriceLimitX96` param never bounded against MIN/MAX_SQRT_RATIO. Predicate: in getsqrtratioattick/
gettickatsqrtratio (or sqrtprice/tickmath math), fire if no ordering `require` on tick/absTick/sqrtprice vs a
max_tick/min_sqrt/max_sqrt bound (or the known constants ~887272 / the sqrt consts); secondary: an unbounded
`sqrtpricelimit*` param. Suppress: bound require present; interface decls; **tightly name-gate to tick↔sqrtPrice
conversion fns** (else overlaps price-bounds/integer-issues and goes noisy). Anchor: v3-core `TickMath` constants.

## Dropped
- "Position.update accrues tokensOwed on old vs new liquidity" — v3's `Position.update` is load-bearing-correct (fees on
  old `_self.liquidity` BEFORE writing `liquidityNext`); a detector here has a large FP surface and no anchored exploit. Speculative — revisit only on a fork-specific finding.
- Generic "unchecked feeGrowth × liquidity → owed" — already `feegrowth-accounting`; not duplicated.

## Build order / confidence
#1 (High conf, real C4 anchor, complements feegrowth-accounting) → #2 + #6 (Med-High, tight callee gates) → #3 (Med,
oracle-source, needs the single-block-vs-differenced discrimination) → #5 (Info/Low) → #4 Sub-check-A + #7 (lowest conf,
ship narrow/gated). All predicates expressible with current IR (`Block{unchecked}`, `Binary{Sub/Div}`, `Unary{Negate}`,
`If` walks, `Call.func_name`, `ValueSource`, prelude helpers).

## Corpus fetch (read-only)
```
git clone --depth 1 https://github.com/Uniswap/v3-core ~/Data/corpus/uniswap-v3-core
#   contracts/UniswapV3Pool.sol + contracts/libraries/{Tick,Position,SwapMath,SqrtPriceMath,TickMath,TickBitmap,FullMath}.sol
#   + add the Code4rena 2023-12-particle Base.sol checked-recompute snippet as the spec-#1 positive fixture
```
v3-core is the negative baseline (it's the correct pool, pre-0.8 → spec #1 silent; canonical rounding → #5/#6 silent);
the forks/integrators (Particle, Algebra) supply the positives. Apply R7 dogfood discipline.
