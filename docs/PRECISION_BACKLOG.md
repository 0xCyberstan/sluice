# Precision-round backlog (dogfood audit, post-R21)

> Source: R22-round dogfood/precision agent. Scanned 3 real codebases READ-ONLY with the
> 124-detector binary: EigenLayer (106 .sol → 166 contracts/1199 fns, 1.31s, 128 findings),
> Symbiotic Core (128 → 70/428, 0.60s, 64), Pendle V2 (205 → 230/1464, 0.70s, 308). 500 total
> (Crit 2 / High 13 / Med 83 / Low 39 / Info 363). No crashes. Address in a dedicated precision round.

## Detector precision targets (ranked)

1. **`floating-pragma` — 344 hits (69% of ALL output).** R21 lint; technically 0% FP but extreme
   volume. **Fix:** split into sub-classes — keep full Info for genuinely-wide ranges (`>=`, `>`, `<`, `*`,
   unbounded like `>=0.5.0`); demote near-pinned `^0.x.y` with `y>=20` to a quieter "near-pinned-pragma"
   sub-class or suppress (near-zero real risk). Eliminates ~220 of 344 while keeping the wide ranges.
   (Note: firing broadly at Info IS the lint's design — this is optional noise-reduction polish, not a bug.)

2. **`array-length-mismatch` — 6 hits, ~50% FP.** Only checks the loop header; misses a length guard
   elsewhere in the body or a sibling fn. Real FPs: `LimitRouterBase.sol:476` (`require(len==lnFeeRateRoots.length)`
   3 lines above), `PendleMultiTokenMerkleDistributor.sol:85`, `ActionMiscV3.sol:79` (three *independent* loops,
   no cross-index). Real TPs: `ActionMiscV3.sol:184`, `DelegationManager.sol:220`. **Fix:** after collecting a
   fn's array params, scan the WHOLE body for `require(a.length==b.length)` / `if(a.length!=b.length) revert`
   on every cross-indexed pair; suppress if guarded.

3. **`centralization-risk` Info tier — ~16 Info hits, pure noise.** The detector's own message says "preset
   destination, not an admin-can-rug risk — informational" (e.g. `RewardsCoordinator.sol:126`,
   `PendleMsgSendEndpointUpg.sol:54`). **Fix:** suppress the Info sub-class entirely; reserve output for the
   Medium/High external-address-reroute-without-timelock tier. (Medium TPs are correct: BackingEigen.mint,
   StakedPendle.setFeeReceiver.)

4. **`upgradeable` `_disableInitializers` sub-class — 11 Med, ~36% FP.** Doesn't trace the inheritance chain.
   FPs: Symbiotic `BaseDelegator`/`Vault` constructors (parents `Entity`/`MigratableEntity` DO call
   `_disableInitializers()`). TPs: Pendle `AddressProvider` (no ctor at all), `PendlePrincipalToken`. **Fix:**
   walk the full inheritance chain for an ancestor-constructor `_disableInitializers()` before emitting.
   Also: Symbiotic `StaticDelegateCallable.staticDelegateCall` flagged **Critical** but it unconditionally
   reverts after the call (a pure `eth_call` simulation hook) → downgrade to Medium/Info when the delegatecall
   is followed by a mandatory `revert`.

## Engine bugs surfaced (worth fixing in the precision round)

- **Parser: `contract Foo layout at N is Bar` not handled.** EigenLayer `AllocationManagerView.sol` uses the
  Solidity 0.8.29 inherited-layout form (`contract … layout at 151 is …`). The R5 `layout at` recovery handled
  the standalone directive but NOT this `contract … layout at N is …` header form → file silently skipped, 1
  contract missed. Extend `blank_layout_directive` (sluice-parse) to also recover this header position.
- **IO: no `is_file()` pre-check.** Symbiotic `docs/autogen/` has 64 `.sol`-suffixed *directories* (Forge
  autogen artifacts); Sluice fed them to the file reader → 64 "Is a directory (os error 21)" lines. Add a
  `metadata().is_file()` guard before reading in the path-walk (sluice-parse / cli).

## Quick wins vs deeper
- Quick (low-risk): centralization Info suppression; `is_file()` guard; staticDelegateCall mandatory-revert downgrade.
- Medium: array-length full-body guard scan; upgradeable inheritance-chain `_disableInitializers` trace; floating-pragma sub-classing.
- Parser: `contract … layout at N is …` recovery (needs offset-preserving care like the R5 fix).
