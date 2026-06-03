# R23 Candidate Backlog — Uniswap v4 Detectors

> Source: R23 research workflow (`wj15vg4zm`, 4 agents, web-verified against real
> Uniswap/v4-core + v4-periphery `main`). Grounded against Sluice's ACTUAL engine
> (120 registered detectors; the `DETECTOR_CATALOG.md` "18" count is STALE — fix it).
> Build-ready plan for R23/R24. Honors R7: tune on the real v4 corpus, not fixtures.

## Executive read

v4-core is hardened, but it pushes a large, mechanically-checkable safety burden onto
**integrator + hook code** — exactly Sluice's static SCIR wheelhouse. The single
highest-value/highest-precision class is **callback authentication**
(`msg.sender == poolManager` on `unlockCallback`/`beforeSwap`/…) and Sluice already owns
~90% of the machine: `flashloan_callback.rs` flags external callbacks lacking
`require(msg.sender == <trusted>)` via a fixed `CALLBACK_NAMES` allowlist. That allowlist
just lacks the IHooks set + `unlockCallback`, and the suppressor doesn't yet recognize the
`onlyPoolManager`/poolManager-immutable guard. **The Cork-Protocol ~$12M (2025-05-28) bug
is one allowlist + one guard-recognizer away — not a net-new detector.** Other v4 classes
have structural twins already in-tree: `arbitrary_transfer.rs` (caller-chosen `from`) =
the v4 payer-spoof drain; `policy_permission_declaration_gap.rs` (declared-vs-effective
table diff) = the hook permission-bitmap-vs-body mismatch; `feegrowth_accounting.rs`,
`tstore_guard_misscope.rs`, `reentrancy.rs` (read-only sub-class), `slippage`/`lp_slippage`
all partially cover v4 shapes. **Genuinely new** = v4's *deferred-settlement conservation*
invariant (take-without-settle, sync→transfer→settle ordering, mint==take/burn==settle) —
call-pairing/ordering properties invisible to per-call/ABI analysis. **Trap (R7):** the
"delta-mid-flight TOCTOU" and "fee-growth-as-oracle" classes need transient-storage
*value-evolution* modeling SCIR lacks → flood FPs on correct periphery → DO NOT BUILD.

## Ranked backlog (rank = value × mechanical × novelty; 19 specs → 12 entries, 7 merges)

| # | category_name | sev | surface | nov | mech | corpus? | anchor / shape |
|---|---|---|---|---|---|---|---|
| 1 | **V4CallbackMissingPoolManagerAuth** (M1: +UnguardedUnlockCallback) | Critical | hook+flash | 5 | 5 | light/extend | Cork CorkHook.beforeSwap ~$12M; v4-peri SafeCallback/ImmutableState.onlyPoolManager — callback name ∈ IHooks∪{unlockCallback}, has side-effect, no `msg.sender==poolManager` guard |
| 2 | **TakeWithoutMatchingSettle** | High | flash | 5 | 4 | YES | PoolManager.unlock(NonzeroDeltaCount)/take/settle — credit op (take/mint) on a branch with no paired debt (settle/burn) |
| 3 | **SyncSettleOrderingViolation** | High | flash | 5 | 4 | YES | CurrencySettler.sol — require sync(c) < transfer→PM < settle(c); flag transfer-before-sync / currency mismatch |
| 4 | **HookReturnsDeltaWithoutReturnDeltaPermissionBit** | High | hook | 5 | 4 | light | Hooks.callHookWithReturnDelta (`if(!parseReturn) return 0`) — non-zero delta return while matching `*ReturnDelta` bool literally false |
| 5 | **V4PayerSpoofSettleDrain** (M2: into arbitrary_transfer) | High | flash | 4 | 3 | light/extend | DeltaResolver._pay / BaseActionsRouter._mapPayer — payer from a param not bound to locker/`this` |
| 6 | **HookPermissionBodyBitmapMismatch** (M3) | Medium | hook | 4 | 4 | light | Hooks.validateHookPermissions (14 clauses) — 14-bit IMPL[] (non-stub body) vs DECL[] (Permissions struct) diff |
| 7 | Erc6909OperatorBlanketApprovalOnSingleton | High | 6909 | 4 | 4 | YES | ERC6909.transferFrom isOperator bypass — setOperator(x,true) where x non-immutable/param persists |
| 8 | DynamicLpFeeUnconstrainedMidSwapRepricing | Medium | fees | 4 | 4 | YES | updateDynamicLPFee / LPFeeLibrary.validate — swap on DYNAMIC_FEE_FLAG pool, no hook-independent amountOutMinimum |
| 9 | HookReentersPoolManagerUnderOpenLock | High | hook | 4 | 3 | YES | unlock/swap (no nonReentrant); Bunni v2 $8.4M — write-after-external-call where target = poolManager.{swap,modifyLiquidity,donate} |
| 10 | ClaimTokenDeltaNonConservation | High | flash/6909 | 5 | 2 | YES | PoolManager.mint/burn (mint==take/burn==settle) — wrapper self-_mint(shares) not matched by settle/burn |
| 11 | DonateFeeGrowthInflationToOraclePoison | High | fees | 4 | 3 | YES | Pool.donate (unchecked feeGrowthGlobal +=) — single-read feeGrowthInside/Global scaled into transfer/mint, no 2-obs delta |
| 12 | IntegratorTrustsCallerPoolKeyHooksAndFee | Medium | periphery | 3 | 3 | YES | PathKey / V4Router._swapExactInput — key.hooks calldata-tainted into swap, no allowlist + standing approvals |

**Realistic post-corroboration tiers:** ranks 1, 4, 7 are multi-signal → clear High/Critical
(≥0.77). Ranks 2,3,5,9,11 are single/dual-dimension on integrator code → realistically land
**Medium (≥0.47)** unless a 2nd dimension (value-flow / sibling consensus) corroborates. 6,8,12
Medium by design.

## Top-6 SCIR recipes (build first)

1. **V4CallbackMissingPoolManagerAuth** — extend `flashloan_callback.rs`. FIRE on a fn whose
   lowercased name ∈ {before/after × swap/addliquidity/removeliquidity/donate/initialize,
   unlockcallback} with a real side-effect (non-empty `storage_writes` OR a CallSite with
   `sends_value` or a PM-mutator `func_name`) AND no `GuardKind::MsgSenderCheck` / `onlyPoolManager`
   modifier comparing `msg.sender` to a state_var/immutable. SUPPRESS: extend `has_msg_sender_lender_check`
   to recognize `if (msg.sender != address(poolManager)) revert` + `onlyPoolManager`; treat base set ∋
   `SafeCallback`/`BaseActionsRouter` as guarded; suppress pure/view + `return selector`-only bodies.
   Anchor +: Cork CorkHook.beforeSwap. Anchor − (must stay silent): SafeCallback.unlockCallback,
   ImmutableState.onlyPoolManager.
2. **TakeWithoutMatchingSettle** — within fns reachable from `unlockCallback`, partition PM CallSites
   into credit {take,mint} / debt {settle,settleFor,burn,clear}; via `CallSite.order` + frontier branch
   membership, FIRE when a conditional branch has a credit not dominated/post-dominated by a debt on the
   same path. SUPPRESS unless BOTH credit+debt appear in-contract (real integrator, not a quoter); suppress
   router legs that dispatch a sibling SETTLE/SETTLE_ALL action in the same `_handleAction` switch; suppress
   staticcall/no-write quoter paths. Anchor −: DeltaResolver._take/_settle, V4Router._handleAction.
3. **SyncSettleOrderingViolation** — on PM CallSites, for each non-native `settle()` (`sends_value==false`)
   require by `order`: nearest preceding PM interaction is `sync(c)` and an ERC-20 transfer to poolManager
   sits strictly between (`sync.order < transfer.order < settle.order`). FIRE on transfer-before-sync, no
   sync, or currency(sync)≠transferred token. SUPPRESS native (`settle{value:}`), ERC-6909 burn-settles, and
   paths delegating to CurrencySettler/DeltaResolver — fire only when all three primitives inlined. Anchor:
   CurrencySettler.settle ("sync() before any erc-20 transfer"); − DeltaResolver._settle.
4. **HookReturnsDeltaWithoutReturnDeltaPermissionBit** — for after/beforeSwap/after{add,remove}Liquidity,
   flag when the return ValueSource is provably NOT compile-time zero (computed int128/BalanceDelta or
   param/storage-derived, not ZERO_DELTA/toBalanceDelta(0,0)/BeforeSwapDelta.wrap(0)) AND the matching
   `*ReturnDelta` bool in `getHookPermissions()` Permissions literal is literally `false`. SUPPRESS zero
   sentinels; suppress when parent action flag false; require a Permissions struct literal (else Info). Clean
   two-constant compare. Anchor: Hooks.callHookWithReturnDelta.
5. **V4PayerSpoofSettleDrain** — extend `arbitrary_transfer.rs`: also cover `poolManager.burn(from,id,amt)`,
   and taint THROUGH `_mapPayer(bool payerIsUser)` — a payer chosen by a `payerIsUser` bool resolves to
   attacker-controlled unless provably `msgSender()==ReentrancyLock._getLocker()` (set under `isNotLocked`) or
   `address(this)`. SUPPRESS those two safe shapes; fire only when payer can be arbitrary third party AND a
   `transferFrom` (not self-transfer) is used. Anchor: DeltaResolver._pay NatSpec, BaseActionsRouter._mapPayer.
6. **HookPermissionBodyBitmapMismatch** — clone `policy_permission_declaration_gap.rs` topology. Two 14-bit
   vectors: IMPL[i] = `functions_of(hook)` has a non-stub override of callback i (body has writes / a CallSite /
   non-constant return; bare `return selector` = NOT implemented); DECL[i] = i-th bool in getHookPermissions()
   Permissions literal. FIRE on IMPL[i]≠DECL[i] (declared-but-empty → dead logic; implemented-but-undeclared →
   permanently-skipped callback / DoS). Bonus: override whose only path is `revert` while DECL[i]==true.
   SUPPRESS opaque/inherited getHookPermissions (→ Info); don't double-report #4's ReturnDelta sub-bits.
   Anchor: Hooks.validateHookPermissions (14 clauses).

## DO NOT BUILD YET (honest static ceiling)

- **HookReadsMidUpdatePoolState + DeltaReadBeforeSettlement (merged TOCTOU)** — needs transient-storage
  value-evolution modeling SCIR lacks; can't distinguish read-then-settle (safe, the V4Router idiom) from
  read-then-hook-reenters-then-act → FP flood on correct periphery. Revisit only with a transient-value model.
- **NativeVsErc20SettleBranchDivergence** — chain-specific native/ERC-20 alias sets (CELO/MATIC); needs an
  alias oracle; "two branches write different storage" too broad (fires on every `isAddressZero()` split).
  Gas sub-signal partly in gas_griefing/hardcoded_gas_stipend.
- **PoolIdRawMemoryHashDirtyBitsMismatch** — weakest/speculative (only assembly/cross-lang dirty-high-bits;
  Solidity zero-extends). encodepacked_collision covers the different adjacent-dynamic case. Skip.
- **ProtocolFeeControllerSinglePointLiveReadNoTimelock** — governance-latency, covered by governance_timelock +
  centralization + delegated_signer_single_step; original OZ PULL finding stale under current PUSH model.
- **UnguardedPoolInitializeFrontrunByHook** — `initialize` permissionless by design; harm is an MEV/ordering
  race, not a static code defect; too much FP surface. Closest coverage: slippage/lp_slippage.

## Corpus fetch (read-only, R23 tuning — `~/Data` is a working dir)

```
git clone --depth 1 https://github.com/Uniswap/v4-core   ~/Data/corpus/v4-core
git clone --depth 1 https://github.com/Uniswap/v4-periphery ~/Data/corpus/v4-periphery
```
- v4-core tune: src/PoolManager.sol; src/libraries/{Hooks,Pool,LPFeeLibrary,ProtocolFeeLibrary,
  NonzeroDeltaCount,CurrencyDelta,TransientStateLibrary}.sol; src/{ERC6909,ERC6909Claims,ProtocolFees}.sol;
  src/types/{Currency,PoolId,PoolKey}.sol; test/utils/CurrencySettler.sol
- v4-periphery tune: src/base/{ImmutableState,SafeCallback,BaseActionsRouter,DeltaResolver,ReentrancyLock}.sol;
  src/V4Router.sol; src/libraries/PathKey.sol; src/base/hooks/BaseHook.sol
- **Build-first NOW (corpus-light):** ranks 1, 4, 5, 6 (structural + small constant reads; tune mostly on the
  negative-suppression anchors). **Corpus-required first:** ranks 2,3,7,8,9,10,11,12 (call-pairing/ordering/taint
  — WILL overfit on minimal fixtures; validate against real PoolManager/V4Router/DeltaResolver, per R7).
- Pin both to latest `main`/release tag; verify spec line numbers against the clone (anchors are WebFetch'd, may drift).
```
