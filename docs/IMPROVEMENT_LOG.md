# Sluice continuous-improvement log

Sluice runs a **perpetual improvement loop**: each round launches 3 concurrent
workflows plus a core-capability focus, then integrates, re-runs the full gate,
and pushes — then the next round starts automatically. The loop never stops.

## Invariants enforced every round (the gate)
- Corpus benchmark: recall ≥ 0.90, clean_rate = 1.00 (`tests/corpus.rs`).
- Real-hack validation: all reconstructed historical hacks still flagged (`tests/real_hacks*.rs`).
- `cargo build --workspace`: **0 warnings, 0 errors**.
- A net improvement (new capability, new detector, new validation, or a measured FP reduction on real code).

## Standing 3-workflow structure
1. **Detectors** — author N fresh detectors (rotating the backlog).
2. **Validation/corpus** — add real-hack fixtures + vuln/safe corpus variants.
3. **Dogfood/precision** — scan fresh real codebases, report FP/crash/perf; fixes land as regression fixtures.

## Rotating core focus
cross-contract linking → path-sensitivity → performance/caching → PoC compilation
→ reporting/diff/watch → deeper dataflow → (repeat, deeper each pass).

## Backlog (drawn from each round; effectively unbounded)
- Detector classes: TWAP-window, flashloan-callback-trust, unprotected-selfdestruct,
  delegatecall-in-loop, reward-debt-ordering, price-bounds, liquidation-abuse,
  double-entry-point token, ERC721 safeMint reentrancy, sandwich/commit-reveal,
  block-number-as-time, divide-before-multiply, uninitialized-storage-pointer,
  cross-contract read-only reentrancy, oracle-deviation-bounds, … (dozens more).
- Historical hacks to reconstruct: Harvest, Mango, Wormhole, Curve/Vyper reentrancy,
  Pickle, Visor, Sonne, Platypus, Rari-Fuse cross, Hundred, Inverse, Radiant, … .
- Codebases to dogfood: pendle, symbiotic, etherfi, karak, firedancer-sol, deeper olympus/eigenlayer.

---

## Rounds

### Round 1 — core: cross-contract resolver
- Detectors (6): twap-manipulation, flashloan-callback, unprotected-selfdestruct,
  delegatecall-loop, reward-debt, price-bounds.
- Validation: +8 historical hacks (Harvest, Mango, Wormhole, Curve-Vyper, Pickle, Visor, Sonne, Platypus).
- Dogfood: pendle, symbiotic, etherfi, karak.
- Core: interface→implementation resolver + cross-contract read-only-reentrancy groundwork in sluice-frontier.
- **Result:** 33 detectors; 18 real hacks all caught (10/10 + 8/8); cross-contract `ContractResolver` shipped.
  **Critical robustness fix** (from dogfooding): nested-expression input caused a stack-overflow abort / O(n²) hang —
  fixed with a 1 GiB analysis thread + a lowering depth cap (256) + an O(bytes) nesting pre-scan (skip >1024 deep).
  Precision fixes: upgradeable accepts `constructor() initializer`; storage-gap only flags inherited bases;
  governance-timelock skips `_authorizeUpgrade`; removed over-broad `/deploy/` exclude. Pendle FPs 95→65.
  72 tests, 0 warnings. _done._

### Round 2 — core: cross-contract usage (wire the resolver into detection)
- Detectors (6): signature-malleability, unprotected-initializer, array-length-mismatch, double-entry-token, liquidation-abuse, block-number-as-time.
- Validation: +8 historical hacks (Rari-Fuse cross, Hundred, Inverse, Radiant, Qubit, PancakeBunny, Conic, Sturdy).
- Dogfood: olympus-contracts, eigenlayer-middleware, layerzero (deeper), re-scan Pendle to confirm.
- Core: a cross-contract detector that uses the R1 resolver (oracle-from-resolved-pool / cross-contract reentrancy).
- **Result:** 39 detectors; +8 hacks (26 fixtures, all 29 harness entries caught). Oracle detector now follows the
  resolver to flag CROSS-CONTRACT spot-oracle dependencies. **Major precision win from dogfooding:**
  access-control awareness — params of onlyOwner/onlyRole functions are no longer seeded as attacker input
  (fixed reentrancy/oracle/integer FPs on admin setters everywhere); `balanceOf(address(this))` excluded from
  spot-price; reentrancy/oracle downgraded on access-controlled fns; cross-function reentrancy dropped there.
  olympus-contracts 134→96, EigenLayer 30. 86 tests, 0 warnings. _done._

### Round 3 — core: reentrancy CEI/ordering precision
- Detectors (6): decimals-assumption, centralization-risk, erc721-safety, unchecked-abi-decode, hardcoded-gas-stipend, cached-domain-separator.
- Validation: +8 hacks (Warp, Grim, Cover, bEarn, Nerve, Spartan, Value DeFi, ApeRocket).
- Dogfood: nitro-audit, firedancer-audit, grafana/cacti (sol?), re-scan olympus-contracts to confirm.
- Core: tighten reentrancy to require an SSTORE strictly after the call (exclude post-call reads / trailing calls).
- _status: launched._
