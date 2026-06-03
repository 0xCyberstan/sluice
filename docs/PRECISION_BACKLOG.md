# Precision backlog

## R24 — addressed (committed `ff357d3`)
floating-pragma sub-classing; array-length full-body guard scan; upgradeable inheritance-chain `_disableInitializers`
+ staticDelegate mandatory-revert downgrade; centralization Info-tier suppression; parser `contract … layout at N is …`
recovery; `is_file()` IO guard. (From the first dogfood.)

## R28 dogfood — RESOLVED in precision wave 1 (2026-06-03), except as noted
> Wave 1 fixed all 5 detector FP classes below (reentrancy, encodepacked/selector, unchecked-return, twap,
> centralization) + the Aave oracle-manipulation FP — each with a real-shape regression test + recall preserved
> (real-hacks + corpus green). **STILL OPEN:** the `transient`-keyword parser gap (below); the upgradeable-proxy
> over-severity (Aave's remaining Critical — `InitializableUpgradeabilityProxy.initialize` rated Critical on a
> standard OZ proxy). Both queued for wave 2. Detail retained below for reference.
>
> **WAVE 2 DONE (2026-06-03)** — Compound Comet + Aave triage: oracle-manipulation Chainlink-feed FP (Comet 15→6),
> access-control empty-fallback + guarded-init + permissionless-deploy FPs (Comet 10→2), upgradeable guarded-OZ-proxy
> over-severity (Aave Crit 1→0), unprotected-initializer guarded one-shot (Comet 2→0), `transient`-keyword parser
> recovery (EntryPoint 0→35 fns). Re-bench: Aave 0 Crit/1 High, Comet 26→9 High (rest defensible), Morpho 0/0.
> **WAVE 3 DONE:** (a) `effects.rs::mk_guard` now recognizes OZ `_msgSender()` (Comet access-control 2→0, only-reduces);
> (b) engine output determinism fixed (total `location_key` sort before dedup/cap; byte-identical across threads —
> 200-permutation proof). **WAVE 4 (full backlog in `docs/IMPROVEMENT_LOG.md` "Real-code triage findings"):** #1
> **reentrancy must require a real external call + CEI-downgrade** (dominant FP — Lido all-5-Highs-FP on no-external-call
> StETH share fns, LoopFi over-rated on CEI-correct code); de-lexicalize twap (oracle CALL, not "observe" substring);
> integer-issues msg.value/BP/guarded-cast suppression; unchecked-return trusted-immutable-token; access-control
> ECDSA-signature-gated auth; forced-ether invariant-assert; parser Solidity-0.4.24; selector/encodepacked de-dup; +
> the STRATEGIC recall frontier (invariant-prover, not pattern-matcher — misses LoopFi-H-01-class accounting bugs);
> (c) Comet donatable-balance/absorb + (d) AA getDeposit re-triage still queued.

## R28 dogfood — original findings (broad scan of 7 corpora with the 132-detector binary, 2026-06-03)

**Headline (good):** the 9 R23/R26/R27 detectors (Uniswap-v4, ERC-4337 AA, perps) have **0 cross-domain false
positives** across v4-core/v4-periphery/account-abstraction/gte-perps/eigenlayer/symbiotic/pendle. Well-contained;
`funding-index-settle-ordering` fires only in gte-perps (6 plausible High in LiquidatorPanel/PerpManager).

**Open precision targets (the OLDER core detectors — a precision round when the loop resumes):**

1. **`reentrancy` (~55–65% TP — highest priority; some messages are factually wrong).**
   - Fires on pure `view` getters as "read-only reentrancy" when the fn has NO `call`/`staticcall` in body or direct
     chain — e.g. `GTELaunchpadV2Pair.getReserves` (reads 3 slots, returns), `NetworkRestakeDelegator.
     totalOperatorNetworkSharesAt` (single `upperLookupRecent`). The emitted message claims "performs an external
     call" — FALSE. FIX: require a visible `call`/`send`/`transfer`/`delegatecall`/`staticcall` in the body (not just
     an inherited superclass chain) before flagging read-only reentrancy.
   - Classic reentrancy mis-attributes a CEI-compliant *pre-call guard read* as a post-call state write
     (`v4-core ProtocolFees.collectProtocolFees` decrements `protocolFeesAccrued` BEFORE `currency.transfer` — it's
     CEI-correct). FIX: require the storage WRITE to be after the call in the same fn scope, not a guard read.
   - Also flags ERC20 `_update`/`setOperatorNetworkShares` (storage + emit only, no external call) — inherited-chain
     mis-walk. FIX: don't attribute a parent-chain external call to a child with none of its own.

2. **`encodepacked-collision` / `selector-collision` (~1/7 TP).** Misclassifies FIXED ABI types (`address`, `uintN`,
   `intN`, `bytesN`) as dynamic → fires on `abi.encodePacked(token0, token1)` (two addresses; `Launchpad.pairFor`) and
   on SVG/Descriptor display-string concatenation (`v4-periphery SVG.generateSVGBorderText`, 8 string args, no hash).
   FIX: (a) count only `string`/`bytes` as dynamic; (b) only flag when the packed result feeds `keccak256` / a
   signature / a mapping key.

3. **`unchecked-return`.** Flags `permit2.transferFrom(...)` (Permit2's `IAllowanceTransfer.transferFrom` is `void` +
   reverts on failure) as an unchecked ERC-20 transfer — e.g. `GTERouter.sol:139`. FIX: check the callee's return
   type is `bool` before flagging; suppress known reverts-not-returns interfaces (Permit2). (Real TPs remain:
   `BoringPtSeller` PT.transfer, `PendleMsgSendEndpointUpg` lzEndpoint.send.)

4. **`twap-manipulation`.** Fires on view getters / NFT `tokenURI` (`StateView.getSlot0`, `PositionDescriptor.
   tokenURI`) that aren't on-chain price consumers. FIX: require the read to flow into a swap/liquidation/borrow
   calculation, not a pure view/metadata return.

5. **`centralization-risk` (further refinement).** R24 removed the Info tier, but the Medium tier still conflates an
   admin SETTER (no fund movement, e.g. `setFeeToSetter` — only reassigns the next admin) with a direct fund-reroute
   (`BackingEigen.mint` to an arbitrary address — genuine). FIX: reserve Medium for fns with a `transfer`/`mint`/
   `approve` to an externally-supplied address in the body; downgrade pure setters to Low.

**Engine bug:**
- **Parser: Solidity `transient` keyword (0.8.28+ transient storage) not handled** → `account-abstraction/
  contracts/core/EntryPoint.sol` silently skipped (the AA reference EntryPoint/paymaster internals went unscanned, so
  AA recall is currently understated). FIX: recover/skip `transient` storage declarations in sluice-parse (mirror the
  R5 `layout at` / R24 comment-skip recovery — offset-preserving).

_No crashes on any of the 7 corpora; scan times 0.02–0.30s per repo. Total 132 detectors, all corpora traversed._

## R28 real-project benchmark — Aave v3 (`aave-dao/aave-v3-origin`, never tuned against)
172 source files scanned in **1.56s / 29 MB RSS**, 0 crashes → 192 findings (1 Crit / 4 High / 19 Med / 22 Low /
146 Info[floating-pragma]). Aave v3 is battle-tested, so the Crit/High are a pure precision test. Triage:
- **3× `oracle-manipulation` (High) = CONFIRMED FALSE POSITIVES** — `ERC4626StataTokenUpgradeable.{depositATokens,
  depositWithPermit,maxRedeem}` read the **user's own balance** (`balanceOf(_msgSender())` to cap a deposit,
  `balanceOf(owner)` to cap a redeem), NOT a price/reserve. **FIX (high-value, concrete):** `oracle-manipulation`
  must NOT treat `balanceOf(<msg.sender | a user/owner param>)` as price-like — only `balanceOf(address(this))` or a
  read off a pool/pair/oracle handle is a manipulable spot value. This is the single clearest precision win surfaced.
- **1× `upgradeable` (Critical)** — `InitializableUpgradeabilityProxy.initialize` delegatecalls a non-immutable
  `_logic`. Defensible (Parity-class shape) but **over-severity** on the canonical OZ proxy (safe given atomic
  one-shot init). Downgrade standard-proxy delegatecall-to-init-param below Critical.
- **1× `reentrancy` (High)** — `RewardsController._claimRewards`: claim-then-transfer via a configured
  `ITransferStrategyBase`. Likely safe (audited, trusted strategy) but a defensible review flag.
**Verdict:** 0 real bugs (expected on Aave v3), 3 clear FPs + 2 over-rated-but-defensible flags. Confirms the tool is
fast/clean at scale and flags the right CATEGORIES (oracle/proxy/reentrancy/oracle-staleness in a lending protocol),
but top-severity precision on untuned real code needs the core-detector pass above — esp. the `balanceOf(self/user)`
oracle-manipulation fix.
