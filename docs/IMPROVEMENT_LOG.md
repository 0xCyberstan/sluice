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

## Long-horizon roadmap (user direction, 2026-06-03)

Beyond the near-term precision rounds, drive Sluice toward a **complete, revolutionary tool** along three
standing thrusts. Rotate the round THEME so each recurs (keep the green gate + dogfood-measured FP movement every round):

1. **Optimize structure (extensibility).** Make adding/modifying a detector near-trivial: shared SCIR query
   primitives (call-target trust map, ordered effect stream, taint queries), a detector-authoring macro/DSL to
   kill per-detector boilerplate, consistent FP-suppression helpers. Dedicated **architecture rounds** refactor
   toward this; measure by "lines + concepts to add a detector."
2. **Optimize speed (scale).** Profile hot paths; parallelize file parse + detector execution; intern/cache
   strings & spans; explore incremental / whole-program caching. Dedicated **performance rounds** benchmark on
   very large repos (10k+ files) and gate wall-clock + peak-RSS as tracked metrics (today: ~150ms / <36MB on
   ~200-file repos — must stay sub-linear-feeling at 50×).
3. **Creative novel-bug R&D (recurring workflow).** Don't stop at published hacks — spin up research agents to
   *hypothesize* under-publicised / emerging bug classes, then build detector + reconstructed fixture for each.
   Seed backlog: transient-storage (EIP-1153 tstore/tload) reentrancy-guard bypass; EIP-7702 delegated-EOA trust;
   ERC-4337 paymaster/validation-phase griefing; 3+-hop cross-protocol read-only reentrancy; rounding/dust
   accumulation over many txns; liquidation-ordering MEV; partial-upgrade invariant drift; cross-chain & EIP-712
   domain/message replay; checkpoint/snapshot vote manipulation; withdrawal-queue & slashing accounting desync.

The goal is to beat Slither/Aderyn/Mythril precisely on the complex / economic / novel logic bugs they miss.

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
- **Result:** 45 detectors; 34 hack fixtures, all 37 harness entries caught (4 harnesses). Fixes: a real
  **parser bug** (scientific literals `1e18` lost their exponent → now preserved); a **comment-stripping**
  `source_text` helper (a `// no timelock` comment was falsely suppressing centralization — general fragility);
  3 R3-detector self-test bugs (cached-domain mistook the constructor's separator-build for chainId handling).
  Core: cross-function reentrancy now requires the precise stale-read shape, AND external calls to project-defined
  `view`/`pure` methods (`gOHM.balanceFrom()`) are recognized as non-reentrant. olympus-contracts reentrancy
  58→36→**14** across the loop; 99 tests, 0 warnings. _done._

### Round 4 — core: migrate keyword detectors to comment-stripped source
- Detectors (6): l2-sequencer-uptime, lp-slippage, weird-erc20-no-revert, unchecked-erc1155-receiver, stale-while-paused, vote-no-snapshot-delegation.
- Validation: +8 hacks (Deus, Saddle, Sturdy2, UwU, Prisma, JimboLong, Gamma, KyberSwap).
- Dogfood: re-scan olympus-contracts/eigenlayer/pendle to confirm, + a fresh target.
- Core: route all keyword-suppression detectors (signature/randomness/price_bounds/twap/oracle/governance/...) through cx.source_text so comments never trip suppression.
- **Result:** 49 detectors; corpus 20/20 recall + 8/8 clean; 42 hack fixtures across 5 harnesses, R4 caught 7/8
  (Orion/DEUS/Saddle/KyberSwap/Gamma/Jimbo/Midas; **TempleDAO MISS** — see R5). 108 tests, 0 warnings.
  Core delivered: **27 keyword-suppression sites** migrated from raw `span_text(...).to_ascii_lowercase()` to
  comment-stripped `cx.source_text(...)` across 25 detectors (signature/randomness/price_bounds/twap/oracle_staleness/
  governance_timelock/bridge/fee_on_transfer/decimals/integer_issues/liquidation/double_entry/dos/reward_debt/
  cached_domain/unchecked_abi_decode/rounding/missing_zero/block_number/sig_malleability/flashloan + helper-based
  storage_gap/vault + case-sensitive upgradeable `_disableInitializers` + sub-span gas_griefing/slippage/erc721/
  array_length). Sub-expression numeric spans (forced_ether normalize, decimals normalize_num) correctly left raw.
  4 new detectors authored: l2-sequencer-uptime, lp-slippage, unchecked-erc1155-receiver, signed-cast. _done._

### Round 5 — core: per-call-target trust resolution + parser robustness (`layout at`)
Driven by the R4 four-codebase dogfood (olympus / eigenlayer / pendle / etherfi — all exit 0, sub-150ms, <36MB,
zero crashes; the bug surface is **precision/labeling**, plus one parser gap). Three workflows:
- **WF1 — cast/integer precision** (the noisiest detector: integer-issues fired 48× on etherfi, 8× on eigenlayer, ~7/8 FP):
  suppress width-safe casts — `uintN(address)` for N≥160, `uintN(bytesM)` for N≥8·M, operand a same-or-narrower
  fixed-width type (`int128(uint128(uint64))`), `uintN(_min(x, type(uintN).max))`/`Math.min` clamps, `uintN(x / CONST)`
  division-down, and a dominating `require/if(v > type(uintN).max) revert`. Fix the location bug (finding lands on the
  function-declaration line, not the cast). Tighten signed-cast the same way. Regression fixtures from the cited cases.
- **WF2 — reentrancy precision** (olympus 9/14 FP; etherfi F-006/F-013): read-only-reentrancy must require a real
  external call on the path to the storage read (F-013 fired on a getter with **zero** calls — a true bug); classic CEI
  must require a storage *write* strictly *after* the external call (F-006 write-precedes-call, F-046 `executed=true`
  set first); down-rank trusted/immutable/owner-set callees (distributor/treasury/veFXS); suppress when no post-call
  write. Regression fixtures: olympus harvest pattern, etherfi getter, governor execute.
- **WF3 — labeling/trust precision + new detector + parser:** (a) centralization-risk: require an actual fund-flow
  (transfer/`call{value}`/mint/approval/withdrawal-address reassignment) for the "move user funds" title, else a softer
  "privileged parameter setter (no timelock)"; down-rank rescue/`recover*`/`sweep*` to a fixed recipient. (b) erc721-safety:
  exclude explicit `IERC20(...)` casts / `ERC20`-typed handles (etherfi F-110/F-115 were ERC-20 3-arg transfers); route
  5-arg form to the erc1155 detector. (c) gas-griefing & arbitrary-call: exclude compile-time `constant`/`immutable`
  address callees (eigenlayer EIP-7002/7251 predeploys). (d) selector-collision: count an arg dynamic only if its static
  type is string/bytes/dyn-array AND not length-pinned by a preceding `require(x.length==K)`; allowlist the `"\x19\x01"`
  EIP-712 digest prefix. (e) access-control: recognize inline `require(msg.sender == authority.X())` / `permissions[..][msg.sender]`
  guards (olympus Treasury.disable FP) and exempt `receive()`/empty fallback. (f) **NEW detector `untrusted-call-target`**:
  caller-supplied address parameter used as an external **call target** whose return/side-effect drives a balance/state
  credit with no validation/whitelist — catches the **TempleDAO** $2.3M migrateStake hack (the R4 MISS) → its regression.
- Core: a per-call-site trust classifier (constant/immutable/param/storage/return-derived) shared by gas-griefing,
  arbitrary-transfer, reentrancy, and the new untrusted-call-target detector; + a parse-layer pre-pass that strips the
  Solidity 0.8.29 `contract X layout at <slot> is ...` directive solang 0.3.5 rejects (eigenlayer AllocationManagerView.sol
  silently dropped). _status: launching._
- **Result:** 51 detectors; corpus 20/20 + 8/8; real-hacks 8/8; 195 tests, 0 warnings. New core detector
  **erc721-mint-reentrancy** (a confirmed gap: `_safeMint`'s onERC721Received hook is an internal-call control
  transfer the reentrancy detector misses; precise CEI-around-callback shape; 0 FPs on the 4 non-NFT codebases).
  Measured FP wins (all four totals down, no regressions): **pendle signed-cast 9→0** (return-tuple location bug),
  **pendle DoS 8→2** (fault-tolerant/`try*` multicalls), pendle upgradeable self-delegatecall FPs reclassified
  Critical→Info (3 dropped to Info, 7 genuine `target.delegatecall` stay Medium), **etherfi integer 31→23**
  (48→23 across R5+R6), **eigenlayer signed-cast 5→2**, **olympus centralization 30→27 + properly tiered**
  (Medium/Low/Info; fixed the scorer bug where conf-0.4 made the Medium tier unreachable — Medium tier now
  carries 0.5 so 45×0.75=33.75 lands as Medium). Totals: olympus 97→92, eigenlayer 26→23, pendle 96→81,
  etherfi 134→126. _done._

### Round 7 — FIRST novel-bug R&D round (per the long-horizon roadmap, thrust #3)
Build detectors for the under-publicised classes WF3's R6 research surfaced on Symbiotic Core (restaking), each
with a reconstructed fixture + harness entry. Three workflows:
- **WF1 — checkpoint/epoch trust:** `checkpoint-hint-trust` (caller-supplied checkpoint index/`hint` drives a
  value-deciding view read — Symbiotic Checkpoints.upperLookupRecent) + `epoch-boundary-staleness` (a value read
  at "latest" while a sibling decision uses an epoch/capture-timestamp window). NEW categories.
- **WF2 — slashing/share accounting:** `proportional-split-residual` (multi-bucket pro-rata split force-assigns the
  rounding remainder to one bucket — Vault.onSlash) + `pooled-shares-reprice-desync` (an external path mutates a
  pooled-asset balance but per-key share supply is left stale, so `previewRedeem` reprices wrong) +
  `internal-share-pricing-rounding` (mulDiv share pricing in helpers the rounding detector skips because they aren't
  named deposit/withdraw/redeem). NEW categories.
- **WF3 — silenced callback + validation harness:** `silenced-privileged-callback` (fire-and-forget low-level call
  to a MUTABLE hook address whose revert/return is discarded — `pop(call(...))` in BaseDelegator/BaseSlasher onSlash —
  while a dependent accounting write is NOT contingent on success) + reconstruct each new class as a fixture in a new
  real-world/near-miss harness (`tests/real_hacks_r7.rs` or a `novel_classes.rs`), and dogfood-measure on
  symbiotic + the four prior targets (the new detectors must not add FPs there).
- Core: shared SCIR primitives the novel detectors need (ordered effect stream already exists; add a caller-supplied-
  index/`hint` taint query + a "pooled balance vs per-key share supply" co-update query) — a down payment on the
  roadmap's architecture/extensibility thrust. _status: pending._
- **Result:** 6 novel detectors authored + self-tested (fire on fixture, silent on SAFE) + 6 reconstructed fixtures.
  Dogfood vs REAL Symbiotic Core + the 4 prior codebases was the deciding gate and it was honest: **4 shipped, 2
  quarantined.** Shipped (55 active detectors): `epoch-boundary-staleness` (fires on real Vault deposit/withdraw/redeem
  + a few low-cost hits; net +~3 FPs on prior codebases), `proportional-split-residual`, `pooled-shares-reprice-desync`,
  `silenced-privileged-callback` (0 FPs everywhere). Quarantined (kept compiled, `fires` self-tests `#[ignore]`):
  `internal-share-pricing-rounding` (flooded — 52 FPs on every internal `a*b/c`: reward-index/points/penalty math) and
  `checkpoint-hint-trust` (over-fires on cert verifiers AND misses the real `Checkpoints.sol`). **Key lesson: novel
  detectors must be tuned against REAL target code, not minimal fixtures** — the 3 "tight" shipped ones fire 0 on the
  real Vault.onSlash/withdrawal-queue/pop(call) shapes (overfit to fixtures). 212 tests + 2 ignored, 0 warnings,
  corpus 20/20 + 8/8. _done._

### Round 8 — novel-detector REAL-CODE tuning (via parallel worktree-isolated agents)
Per [[feedback-agent-iteration]]: each agent runs in its OWN git worktree (isolation: "worktree") and does the FULL
loop itself — edit → `cargo build` → `./target/release/sluice scan` the real Symbiotic source + the 4 prior codebases →
iterate until its detector fires on the TRUE target with ~0 FPs → run the gate → copy ONLY its detector file back to the
main repo (the parent wires mod.rs registration once). Targets (real Symbiotic Core source under
symbiotic-audit/symbiotic-core/src/contracts):
- **WF1 (re-activate the 2 quarantined):** tighten `internal-share-pricing-rounding` to fire ONLY on genuine share/stake
  pricing that yields a user-withdrawable amount (exclude reward-index/points/penalty/ratio — kill the 52 FPs), and
  `checkpoint-hint-trust` to match the real `Checkpoints.upperLookupRecent(self,key,hint)` (fire there, drop the cert-
  verifier FPs). Re-activate each only if it fires on its real target with ~0 FPs on the 4 codebases.
- **WF2 (make the 3 fixture-only detectors fire on real code):** `proportional-split-residual` on real `Vault.onSlash`,
  `pooled-shares-reprice-desync` on the real withdrawal-queue (`withdrawals[epoch]` mutated, `withdrawalShares[epoch]`
  stale), `silenced-privileged-callback` on real `BaseDelegator.onSlash`/`BaseSlasher._burnerOnSlash` `pop(call(...))`;
  and cut `epoch-boundary-staleness`'s prior-codebase FPs (olympus rebase/unstake, eigenlayer sweep).
- **WF3 (research + full dogfood):** fresh novel-bug research on a NEW target (karak/renzo) for the R9 backlog, + a full
  dogfood re-measure of the tuned detector set.
- Core: shared SCIR primitives (caller-supplied-`hint` taint query; pooled-assets-vs-per-key-shares co-update query) so
  these detectors stop being one-off string matching — the architecture/extensibility thrust. _status: pending._
- **Result:** 50 detectors; corpus 20/20 recall + 8/8 clean; **R4 hacks now 8/8** (TempleDAO caught by the
  new `untrusted-call-target` detector — the R4 MISS, closed). 153 tests, 0 warnings. Delivered:
  - **WF1 cast precision:** integer-issues width-bit suppression (`uintN(address)`/`uintN(bytesM)`/narrower-int
    operand), `min()`-clamp, division-down, `type(uintN).max`-dominating-guard, unchecked-nonce — **etherfi
    integer-issues 48→31, eigenlayer 8→0** (measured). signed-cast width-safety added.
  - **WF2 reentrancy precision:** read-only-reentrancy now requires a real external call on the path (the etherfi
    zero-call getter FP); classic CEI requires a write STRICTLY after the call (write-before-call no longer fires);
    trusted (immutable/constant) callee downgrade — **olympus reentrancy 14→11** (measured).
  - **WF3 labeling/trust:** centralization fund-flow split (soft "parameter setter" title), erc721-vs-erc20 type
    exclusion (**etherfi erc721 3→0**), gas-griefing constant/immutable-callee exclusion (**eigenlayer 3→0**),
    selector EIP-712 `\x19\x01` allowlist + length-pinned-arg rule (**eigenlayer selector 3→0**).
  - **Core (direct):** new **untrusted-call-target** detector; **`layout at` parser recovery** (offset-preserving
    blank — Solidity 0.8.29 files no longer silently dropped); **guard-ordering root fix** — a `require(...)`/`assert(...)`
    now claims its order before its condition is walked, so an inline `require(msg.sender == authority.governor())`
    (call in the condition) is recognized as access control instead of being dropped past the leading-guard cutoff.
    This lifts `has_access_control` accuracy for EVERY detector (olympus access-control 8→6).
  - Dogfood re-measure (olympus/eigenlayer/pendle/etherfi): all exit 0, zero crashes. eigenlayer 32→26, etherfi
    143→134. **olympus 83→97 is correct, not a regression** — the guard-fix exposed ~21 genuinely privileged
    authority-guarded fund-movers that the ordering bug had hidden from centralization. _done._

### Round 6 — core: per-call-site trust map + return-value provenance
Driven by the R5 dogfood re-measure (the two real FP sources it surfaced). Three workflows:
- **WF1 — signed-cast & integer residual:** signed-cast fires on function **return-tuple signature lines**
  (`(int256 _netSyIn, int256 _netSyFee, …)` — pendle calcSyIn/calcSyOut, 6 FPs) and on width-safe / constant
  casts (`uint256(ONE_18)`, `uint16(year-1)`) — fix the location/false-match (only real `TypeCast` expression
  spans, never a return-param list) and port integer-issues' width-bit + clamp + guard suppression into signed-cast;
  also drive etherfi integer-issues 31→lower. Regression fixtures from the pendle/eigenlayer cases.
- **WF2 — upgradeable & DoS context (untouched in R5):** upgradeable self-delegatecall (`address(this).delegatecall`
  / `_delegateToSelf` — pendle, 3+ FPs) must not carry the foreign-takeover "Parity" message; cap `simulate()`-then-
  `revert` entrypoints below Critical; DoS must not fire on fault-tolerant `try*`/read-only multicalls (pendle
  Multicall2). + new detector: **uninitialized-storage-pointer** or **divide-before-multiply** (precision-loss).
- **WF3 — centralization severity & dogfood:** suppress initializers/`setVault`-style from centralization; reserve
  Low+ for genuine fund-sinks, Info for the rest (olympus 30 → tighter); re-scan all four targets + a fresh codebase
  (symbiotic / karak / renzo) to measure and to find new FP classes.
- Core: a per-call-site trust classifier (constant/immutable/param/storage/return-derived) + first-class external-
  return provenance, shared by signed-cast, gas-griefing, reentrancy, untrusted-call-target, upgradeable. _status: pending._
