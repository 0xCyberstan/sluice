# Precision backlog

## R24 — addressed (committed `ff357d3`)
floating-pragma sub-classing; array-length full-body guard scan; upgradeable inheritance-chain `_disableInitializers`
+ staticDelegate mandatory-revert downgrade; centralization Info-tier suppression; parser `contract … layout at N is …`
recovery; `is_file()` IO guard. (From the first dogfood.)

## R28 dogfood — OPEN (broad scan of 7 corpora with the 132-detector binary, 2026-06-03)

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
