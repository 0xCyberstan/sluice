# R23 build-ready specs (Uniswap v4 wave-1) — CORPUS-VERIFIED

> Source: R23 spec-refinement agent, verified against the read-only clone at
> `~/Data/corpus/{v4-core,v4-periphery}` and Sluice's actual SCIR. Supersedes the
> ranking guidance in `R23_V4_BACKLOG.md` with corpus-checked anchors + fixtures.

## CORPUS REALITY CHECK (read first — it re-ranks the build order)

`grep -rn "getHookPermissions\|BaseHook"` over both `src/` trees returns **nothing**:
- **`getHookPermissions()` and `BaseHook` are ABSENT from this corpus.** The per-hook
  *declaration* that specs 2 & 4 diff against lives only in integrator/hook code (not cloned).
  → **Specs 2 & 4 have NO fireable positive in the corpus; fixtures are their sole positive
  anchor.** This is the R7 overfit risk — build them Info-gated / defer until a real hook corpus
  is fetched. Corpus still gives strong *negatives* (the `Hooks` library + test hooks).
- **Spec 1 DOES have real fireable positives** (`MockHooks`, `SkipCallsTestHook`, `ActionsRouter`) +
  real negatives → fully corpus-tunable. **Build first.**
- **Spec 3** — periphery's own `_pay`/`_mapPayer` are all SAFE (precise negatives); no positive in
  corpus; fixture is sole positive.

**Recommended R23 build order:** Spec 1 (Critical, corpus-tunable) → Spec 3 (real negatives, fixture
positive) → Specs 2 & 4 only with Info-gating + a flagged need for an integrator/hook corpus.

The only new parsing both 2 & 4 need is a shared `Permissions`-literal parser
(`Option<[bool;14]>` from a `getHookPermissions` body) + the shared "provably-non-zero delta return"
+ "stub body (`return selector`/`revert`-only)" predicates.

---

## Spec 1 — `V4CallbackMissingPoolManagerAuth` (extend `flashloan_callback.rs`) — Critical

Extend the existing flashloan-callback detector: (a) add IHooks set + `unlockcallback` to
`CALLBACK_NAMES`; (b) teach `has_msg_sender_lender_check` the `onlyPoolManager` modifier + the
`msg.sender != address(poolManager)` revert.

**Positive anchors (SHOULD fire, all real in corpus):**
- `v4-core/src/test/SkipCallsTestHook.sol:95` `beforeSwap` — `counter++` (storage write) + `_swap(...)`
  re-enters PoolManager, no guard. Strongest.
- `v4-core/src/test/MockHooks.sol:89` `beforeSwap` (`beforeSwapData = hookData;`) + siblings
  `afterSwap:103`, `beforeAddLiquidity:43`, `afterAddLiquidity:53`, `beforeInitialize:31` — storage write, no auth.
- `v4-core/src/test/ActionsRouter.sol:52` `unlockCallback` — no `require(msg.sender==address(manager))`,
  dispatches `_settle/_take/_mint`.
- Real-world: Cork `CorkHook.beforeSwap` (~$12M, 2025-05-28) — captured by the positive fixture.

**Negative anchors (MUST stay silent):**
- `v4-periphery/src/base/SafeCallback.sol:15` `unlockCallback ... onlyPoolManager`.
- `v4-periphery/src/base/ImmutableState.sol:17-20` `modifier onlyPoolManager { if (msg.sender != address(poolManager)) revert NotPoolManager(); _; }` (`poolManager` immutable, line 11) — the suppression source.
- `v4-core/src/test/{PoolSwapTest.sol:48,PoolTakeTest.sol:28,SwapRouterNoChecks.sol:32}` — leading
  `require(msg.sender == address(manager));`.
- `v4-core/src/test/{FeeTakingHook:34,CustomCurveHook:33,DeltaReturningHook:47}` — `onlyPoolManager` modifier (`require(msg.sender==address(manager))`).
- `v4-core/src/test/BaseTestHooks.sol:14-108` — every body is `revert HookNotImplemented();` (no side-effect ⇒ stub gate).
- `v4-core/src/interfaces/IHooks.sol:21-151` — `!has_body` (already excluded).

**SCIR predicate** (reuse `FlashloanCallbackDetector::run`):
1. Extend `CALLBACK_NAMES` (lowercase) with: `unlockcallback`, `before/afterinitialize`,
   `before/afteraddliquidity`, `before/afterremoveliquidity`, `before/afterswap`, `before/afterdonate`.
2. **Real-side-effect gate** (IHooks set must NOT fire on pure stubs): fire only if
   `!storage_writes.is_empty()` OR any `call_site.sends_value` OR any `call_site.func_name`(lc) ∈
   {swap,modifyliquidity,donate,take,settle,settlefor,mint,burn,sync,clear,unlock}. Exclude bodies whose
   only stmts are `Revert`/`Placeholder` with empty writes+calls (BaseTestHooks).
3. **Extend `has_msg_sender_lender_check`** to also return true when
   `f.modifiers.any(|m| m.name.eq_ignore_ascii_case("onlyPoolManager"))`, OR the existing body scan
   matches `msg.sender ==/!= X` (X a state var/immutable, not attacker, not `address(this)`) — already
   covers the inline `require` form.
4. For the IHooks/unlock names set `initiator_param = None` (arg0 `address sender` is PM-supplied, not a
   loan initiator) so the finding hinges solely on PM-auth.
5. Fire: name ∈ extended set ∧ `has_body` ∧ externally reachable ∧ side-effect-gate ∧ ¬lender-check.
   **Severity Critical** (override base High); message: "lender/pool" → "Uniswap v4 PoolManager".

**Fixtures:**
```solidity
// POSITIVE — fires_on_v4_hook_missing_pm_auth
pragma solidity ^0.8.24;
interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
contract VulnHook {
    IERC20 public token; address public manager;     // PoolManager, never checked
    mapping(bytes4 => bytes) public lastData;
    function beforeSwap(address, bytes calldata key, bytes calldata params, bytes calldata hookData)
        external returns (bytes4, int256, uint24) {
        lastData[bytes4(hookData)] = hookData;        // storage_write
        token.transfer(msg.sender, 1);                // attacker-driven side effect
        return (this.beforeSwap.selector, int256(0), uint24(0));
    }
}
// NEGATIVE — silent_on_safe_pm_authed_callback
pragma solidity ^0.8.24;
interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
contract SafeHook {
    IERC20 public token; address public immutable poolManager;
    mapping(bytes4 => bytes) public lastData; error NotPoolManager();
    constructor(address pm) { poolManager = pm; }
    modifier onlyPoolManager() { if (msg.sender != address(poolManager)) revert NotPoolManager(); _; }
    function beforeSwap(address, bytes calldata key, bytes calldata params, bytes calldata hookData)
        external onlyPoolManager returns (bytes4, int256, uint24) {
        lastData[bytes4(hookData)] = hookData; token.transfer(address(this), 1);
        return (this.beforeSwap.selector, int256(0), uint24(0));
    }
}
// + 2nd negative: unlockCallback with leading `require(msg.sender == address(manager));` (state-var manager).
```

---

## Spec 3 — `V4PayerSpoofSettleDrain` (extend `arbitrary_transfer.rs`) — High (fixture positive)

Taint THROUGH `_mapPayer(bool payerIsUser)`; flag `permit2.transferFrom(payer,...)` / `poolManager.burn(payer,...)`
where `payer` isn't provably bound to the locked caller / `address(this)`.

**Negative anchors (the exact FPs to avoid):**
- `v4-periphery/src/base/BaseActionsRouter.sol:72-74` `_mapPayer(bool) => payerIsUser ? msgSender() : address(this)`.
- `v4-periphery/src/PositionManager.sol:528-535` `_pay` — `payer==address(this) ? currency.transfer(...) : permit2.transferFrom(payer,...)`, payer bound via `_settle(_mapPayer(...))` @ :257.
- `v4-periphery/src/V4Router.sol:59,65,69` `_settle(currency, msgSender()/_mapPayer(...), …)`.
- `msgSender()` = `_getLocker()` (`PositionManager.sol:191-193`, `ReentrancyLock.sol:10-17`, set under `isNotLocked`).
- NatSpec the detector enforces: `v4-periphery/src/base/DeltaResolver.sol:32-38` ("must ensure `payer` is a secure address").

**SCIR predicate** (extend `ArbitraryTransferDetector`):
- Add sinks: 4-arg `transferFrom(payer,to,amt,token)` where receiver root-ident is `permit2` (spoofable=arg0);
  `burn(from,id,amount)` where receiver resolves to `poolManager`/`manager` (spoofable=arg0).
- Scan **all** functions (not just entry_points) for the sink with an `address` param `P` as spoofable arg.
  `P` is SAFE iff *every* inbound internal-call argument binding `P` is one of: `address(this)`,
  `msgSender()`/`_getLocker()`, `_mapPayer(...)` (body = the safe ternary), or a const/immutable.
  UNSAFE iff any inbound binding is attacker-controlled and not the above (e.g. an address/bool decoded from
  calldata passed as payer without `_mapPayer`).
- Self-transfer suppression: 2-arg `currency.transfer(address(poolManager),amt)` ⇒ never fire.
- Abstract decl (`!has_body`, e.g. `DeltaResolver.sol:55`) ⇒ skip.
- Severity High, confidence ≈0.6 (single ValueFlow dimension → realistically Medium without corroboration).

**Fixtures:** POSITIVE `settle(address payer,...) { _pay(token, payer, amount); }` → `_pay` does
`permit2.transferFrom(payer, poolManager, amount, token)` (payer straight from calldata).
NEGATIVE same shape but `settle(bool payerIsUser,...) { _pay(token, _mapPayer(payerIsUser), amount); }` with
`_mapPayer => payerIsUser ? msgSender() : address(this)`. (Full text in the task output / agent transcript.)

---

## Spec 2 — `HookReturnsDeltaWithoutReturnDeltaPermissionBit` (new) — High — FIXTURE-ONLY POSITIVE

A `before/afterSwap`/`after{Add,Remove}Liquidity` returns a **non-zero delta** while the matching
`*ReturnDelta` bool in `getHookPermissions()` is `false`. At the PM, `Hooks.callHookWithReturnDelta`
does `if (!parseReturn) return 0;` (**`v4-core/src/libraries/Hooks.sol:163`**) → the delta is silently
dropped → the hook's own settle/take is unbalanced.

**No corpus positive (no `getHookPermissions` literal anywhere).** Negatives: `DeltaReturningHook.sol:47,63`,
`FeeTakingHook.sol:34,54,73`, `CustomCurveHook.sol:33` (return non-zero deltas but have NO `Permissions`
literal ⇒ MUST stay silent — the precision gate); `Hooks.sol:217,253,293` zero sentinels; the `Hooks` library.

**Predicate:** (1) parse the `Permissions` literal from `getHookPermissions()` (positional 14-bool OR named
fields per `Hooks.sol:49-64`); absent/opaque ⇒ **skip (no fire)**. (2) For each delta-returning callback,
on each `Return`, take the delta tuple element; "provably non-zero" = NOT (`*.ZERO_DELTA` / `to*Delta(0,0)` /
`*.wrap(0)` / literal 0) AND (computed `to*Delta`/`*.wrap` with non-zero/non-literal arg OR `cx.provenance_of`
∈ {AttackerInput,StorageState} OR root is param/state var). (3) Fire when a provably-non-zero return meets a
literally-`false` matching `*ReturnDelta` bit. Suppress: no literal, zero sentinel, parent action bit false
(dead code → Info), library/interface. Confidence ≈0.78. Add `Category::HookReturnDeltaPermissionGap`.

Positive fixture: `getHookPermissions` sets `afterSwap=true, afterSwapReturnDelta=false`; `afterSwap` returns
`int128(delta)/100*feeBips` (computed non-zero). Negative: same decl, `afterSwap` returns `int128(0)`.

---

## Spec 4 — `HookPermissionBodyBitmapMismatch` (new, clone `policy_permission_declaration_gap.rs`) — Medium — FIXTURE-ONLY POSITIVE

Two 14-bit vectors: IMPL[i] = callback i has a non-stub override (storage write / call site / non-constant
return; bare `return selector;`/`revert` = NOT impl); DECL[i] = i-th bool in the `Permissions` literal.
Fire on IMPL[i]≠DECL[i]: implemented-but-undeclared (PM never calls it → dead logic, High≈0.75) or
declared-but-empty (Medium≈0.65); revert-only body while DECL true → escalate (bricks the pool).

**No corpus positive (no `getHookPermissions` literal).** Field order: **`Hooks.sol:49-64`** (0 beforeInitialize
… 6 beforeSwap, 7 afterSwap … 10-13 the ReturnDelta bits). `validateHookPermissions` (`Hooks.sol:85-99`)
enforces DECL==addressBits; this detector adds the new IMPL==DECL axis. Negatives: `BaseTestHooks.sol:14-108`
(revert-only → IMPL=false, no DECL → silent), `FeeTakingHook`/`CustomCurveHook` (real bodies, no DECL → silent),
the `Hooks` library + `IHooks` interface.

**Predicate:** gate on "is a hook" (inherits IHooks-like OR defines `getHookPermissions`). Parse DECL (shared
parser); absent ⇒ Info only, no fire. IMPL[i] via non-stub test (shared). **Report only indices 0-9** (the 4
ReturnDelta bits 10-13 are owned by Spec 2 — no double-report). Two finding variants (undeclared-impl High /
declared-stub Medium), mirroring `policy_permission_declaration_gap.rs:232,270`. Add
`Category::HookPermissionBodyBitmapMismatch`.

Positive fixture: DECL `beforeSwap=true` only; bodies implement BOTH `beforeSwap` (swaps++) and `afterSwap`
(swaps++) → IMPL[afterSwap]=true, DECL=false → fire. Negative: no `getHookPermissions` literal + revert/stub bodies.

---

## Cross-cutting (shared helpers to implement once)
- `Permissions`-literal parser → `Option<[bool;14]>` (positional + named; field→index per `Hooks.sol:49-64`). Specs 2,4.
- "Provably-non-zero delta return" predicate (zero-sentinel suppression list + `cx.provenance_of`). Specs 2,4.
- "Stub body" predicate (`return selector`/`revert`-only, empty writes+calls). Specs 1,4.
- `msgSender`/`_getLocker`/`_mapPayer` recognition is name-exact in this ecosystem (defs: `BaseActionsRouter.sol:58,72`,
  `PositionManager.sol:191`, `ReentrancyLock.sol:17`, `V4Quoter.sol:155`). Spec 3.
- All 4 add a `Category` variant (R23 block in `finding.rs`); 2 & 4 are new modules to register in `mod.rs`;
  1 & 3 are edits to existing modules.

> Full verbatim fixtures + line-by-line negatives are in the agent transcript
> (`tasks/ac6945cdff498049e.output`) if more detail is needed at build time.
