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

### Round 6 — core: per-call-site trust map + return-value provenance + R5-FP precision
Driven by the R5 dogfood FP sources. WF1: signed-cast no longer matches return-tuple signature lines / width-safe
casts and inherits integer-issues' width-bit + clamp + guard suppression. WF2: upgradeable self-delegatecall
de-"Parity"'d, DoS excludes fault-tolerant `try*`/read-only multicalls, + new `uninitialized-storage-pointer`
detector. WF3: centralization reserves Low+ for genuine fund-sinks (Info otherwise). Core: a per-call-site trust
classifier (constant/immutable/param/storage/return-derived) + external-return provenance, shared by
signed-cast/gas-griefing/reentrancy/untrusted-call-target/upgradeable. _done._

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
- **Result (via 6 parallel worktree-isolated agents — first use of [[feedback-agent-iteration]]):** ALL 6 R7 novel
  detectors now ACTIVE + real-code-validated → **57 active detectors**. Independent dogfood (the authoritative gate,
  not the per-agent isolated numbers): novel-detector FPs on the 4 prior codebases = **0/0/0/0** (olympus/eigenlayer/
  pendle/etherfi back to their exact R6 baselines 92/23/81/126 — the 52-FP internal-rounding flood, the cert-verifier
  FPs, and the epoch FPs all eliminated), while **all 6 fire on the real Symbiotic source** (12 hits: epoch 4,
  checkpoint 2, silenced-callback 2, internal-rounding 2, proportional 1, pooled 1). Re-tuning that worked:
  internal-share-pricing-rounding → bare-`mulDiv`-with-pooled-aggregate-divisor only; checkpoint-hint-trust → requires
  an OZ/Symbiotic `Trace*` container (structurally excludes cert-verifier mapping-indexes / observation buffers);
  proportional/pooled/silenced rebuilt to match the real `Vault.onSlash` / withdrawal-queue / asm `pop(call)` shapes;
  epoch now requires the live read to have a captured/epoch sibling. 231 tests, 0 warnings, corpus 20/20 + 8/8.
  The 12 Symbiotic hits are candidate findings to triage (unverified; may be design tradeoffs). _done._

#### R9 candidate backlog (from R8 WF3 research on Renzo — ranked; several point at concrete LIVE sites to verify)
1. **unguarded-emergency-accounting-mutator** — an external accounting-state writer that LOST its access modifier while sibling `emergency*`/`track*` functions keep theirs (sibling-consensus on fund-accounting writes, distinct from name-based access-control). _Live site to verify: Renzo `OperatorDelegator.sol:572 emergencyTrackSlashedQueuedWithdrawalDelta` (no modifier; writes slash-delta that feeds ezETH TVL/price)._
2. **crosschain-rate-feed-staleness-trust** — L2/destination mints against a bridged price whose freshness is checked vs the *message's own* timestamp, not local receipt time (Renzo `xRenzoDepositNativeBridge`/`HyperlaneReceiver`).
3. **snapshot-redeem-reprice-asymmetry** — request→claim redeem amount clamped DOWN-only at claim while the reserve is decremented by the pre-clamp value (Renzo `WithdrawQueue.sol:469-534`).
4. **netted-aggregate-slash-desync** — `exposure = principalAgg − lossAgg` where the two aggregates are written by independent functions with no joint invariant (Renzo `OperatorDelegator:725`). Distinct from accounting CoUpdate (single-function paired write) — this is cross-writer netting.
5. **oracle-driven-first-mint-seeding** — LST exchange-rate mint (`supply*new/tvl`) whose empty-protocol guard only covers the literal first mint; re-emptyable (Renzo `RenzoOracle.calculateMintAmount`). Complements balance-driven `vault.rs` first-depositor.
6. **proportional-payout-tx-value-trust** — push splitter sizing each cut from a re-read `address(this).balance`, swallowing failed legs (order-dependent skew) (Renzo `PaymentSplitter.sol:191`). Inverse of `dos.rs` (failures swallowed, not reverting).
7. **whitelist-cooldown-bypass-coupled-to-pause** — withdrawal cooldown skipped for whitelisted users UNLESS an unrelated risk/pause flag is set (Renzo `WithdrawQueue.sol:434`). Distinct from governance-timelock (no-timelock); this is timelock-present-but-conditionally-bypassed.
_(Full agent report with SCIR signatures + FP-suppression per class is in the R8 WF3 task transcript.)_

#### R9 candidate verification (WF3, adversarial/skeptical) — HONEST result
Triaged the 12 live Symbiotic novel-detector hits + the 2 flagged Renzo sites. **0 of 14 are exploitable bugs** on
these mature audited protocols: the Symbiotic hits are documented loss-socialization (slash shrinks the asset side;
claims gated to past epochs), conservative floor-rounding (protocol-favorable, dust), self-correcting hinted lookups
(binary-search fallback), and deliberately fire-and-forget hooks (DoS resistance). **Renzo B1 (OperatorDelegator
`emergencyTrackSlashedQueuedWithdrawalDelta` L572): a REAL, confirmed missing-`onlyEmergency*` inconsistency vs its 3
siblings — but the body is an idempotent recompute over trusted state (can only push TVL to its true value; no profit
path) → a legitimate hygiene/consistency finding, not fund-loss.** Renzo B2 (WithdrawQueue cooldown bypass): intended
trusted-partner design, min-clamped pricing, no loss. **Takeaway:** the detectors correctly surface the risky shapes
(true to thesis) and the verification layer correctly triages them — the surface→triage pipeline works like a good
auditor; "first confirmed EXPLOITABLE bug" is not yet reached (expected on audited targets). This is why every novel
detector ships at modest severity/confidence as an auditor-attention signal, not an autonomous verdict.

### Round 9 — 7 Renzo-mined novel detectors (via parallel worktree agents) + adversarial verification
- **Result:** +7 detectors → **64 active** (13 now genuinely-novel restaking/LST/cross-chain/queue classes). Authored by
  7 parallel worktree-isolated agents (each built + scanned real Renzo + the 5 prior codebases in its own checkout):
  unguarded-accounting-mutator, snapshot-redeem-asymmetry, cooldown-bypass-flag, crosschain-rate-staleness,
  netted-aggregate-desync, oracle-first-mint-seeding, proportional-payout-tx-value. Independent dogfood (authoritative):
  **all 5 prior codebases unchanged (0 R9 FPs: olympus 92 / eigenlayer 23 / pendle 81 / etherfi 126 / symbiotic 41)**,
  while **all 7 fire on real Renzo (8 hits)**. 276 tests, 0 warnings, corpus 20/20 + 8/8. The 8 Renzo hits are candidate
  findings: WF3 verified the two highest-value ones (B1 unguarded-mutator = real-but-benign hygiene; B2 cooldown =
  design tradeoff); the other 6 are unverified (likely design tradeoffs on this audited protocol, worth human triage).
  Milestone: the surface→verify pipeline now spans two live protocols with 0 confirmed-exploitable but 1 real hygiene find.

### Round 10 — ROTATE THEME per roadmap: performance/scale + architecture/extensibility
R7–R9 were all novel-detector rounds; the roadmap says interleave the optimization thrusts. R10 (parallel worktree agents):
- **WF1 performance/scale:** generate/locate a very large Solidity corpus (10k+ files — concat/replicate or a big monorepo)
  and benchmark `sluice scan`; profile hot paths; parallelize per-file parse + per-detector execution (rayon); intern
  strings/spans; add wall-clock + peak-RSS as GATED metrics. Target: stay sub-linear-feeling at 50× today's repos.
- **WF2 architecture/extensibility:** extract shared SCIR query primitives (the call-target trust map, ordered effect
  stream, taint/hint queries, name-classifiers) into a `detectors/prelude` + a `detector!{}` authoring macro to kill the
  per-detector boilerplate (measure "lines/concepts to add a detector" before/after); migrate 3-4 detectors onto it as proof.
- **WF3:** R11 novel-bug research on a fresh target (karak/morpho) + a full dogfood re-measure of all 64 detectors.
- _status: **DONE** — all three integrated._ WF1 (performance): rayon-parallelized file read + parse + IR-build
  (sluice-parse) + per-function dataflow fixpoint + the detector phase; removed an O(contracts²) hot path in
  netted-aggregate-desync's inheritance-chain rebuild; added a parallel one-time `source_text` cache in
  AnalysisContext::new. **2.55× faster on 4,418 files, 3.27× on 13,254** (parse 880→335ms, dataflow 342→180ms,
  detectors 623→146ms). Also **fixed a pre-existing run-to-run nondeterminism** (a HashSet-iteration var pick → pinned
  to the lexicographically-smallest), so output is now byte-stable. Verified in main: findings byte-identical to the R9
  baseline (olympus 92 / etherfi 126 / pendle 81), md5-stable across runs, 285 tests, 0 warnings. (Integration caught a
  cross-round conflict: WF1's new private `source_cache` field broke a struct-literal `AnalysisContext{..}` in the arch
  round's prelude test — fixed by routing it through `AnalysisContext::new`.)

### Round 11 — 7 Karak-mined novel detectors (worktree agents) — validated against REAL audit findings
- **Result:** +7 detectors → **71 active**. Authored by 7 parallel worktree agents (each built + scanned real Karak +
  the 6 prior codebases, and USED the new R10 `prelude` — dogfooding the architecture work): shares-escrowed-repriced,
  percent-slash-live-base, hash-gated-replay, clamp-residual-burn, proof-admission-only, external-root-caller-timestamp,
  zero-margin-timing-window. Independent dogfood (authoritative): **all 7 fire on the real Karak source** (10 hits, at
  the exact sites of real Karak/C4 findings — finalizeSlashing/computeSlashAmount, NativeVault.validateSnapshotProofs,
  the Vault withdrawal queue); **0 FP on olympus/pendle/etherfi/symbiotic**; **1 defensible TP on eigenlayer**
  (hash-gated-replay correctly generalizes to EigenLayer `_completeQueuedWithdrawal` — same shape, agent-verified).
  333 tests, 0 warnings, corpus 20/20 + 8/8. **Strongest validation yet: the detectors fire where real published audit
  findings live (ground truth), not just on clean shapes.** 20 → 27 novel classes; 71 detectors total.

#### R12 candidate backlog (R11 WF3 research on ETHENA — non-restaking, maps to the user's own Ethena audit findings)
1. **escrow-exit-restriction-gap** — blacklist/restriction enforced at escrow ENTRY (burn leg) but NOT at the matured-asset EXIT (often a separate silo contract) → a frozen user still exits staged value. *This was the single High the whole Ethena audit produced.* StakedUSDeV2.sol:80-92 → USDeSilo.sol:27-29.
2. **vesting-buffered-tvl-donation** — `getRate` reads `totalAssets = balanceOf − unvested`, but a raw `transfer` donation lands in `balanceOf` un-buffered → atomic price jump that defeats the vesting anti-spike (only one inflow path is buffered). StakedUSDe.sol:161-180 + EthenaBalancerRateProvider.getRate.
3. **one-sided-peg-band-check** — mint/redeem price-band check constrains only the protocol-favorable direction.
4. **eip712-typehash-struct-mismatch** — typehash string field order/width diverges from the encoded struct.
5. **delegated-signer-single-step** — a signer/authorization delegate installed in one step (no two-step accept handshake).
6. **pre-auth-callout-to-caller-supplied-target** — EIP-1271/external auth call dispatched to an attacker-named address BEFORE authorization.
These broaden Sluice beyond restaking (synthetic-dollar / RFQ-mint / ERC4626-staking) and have ground truth (the user's confirmed Ethena High + Mediums). Full SCIR signatures in the R11 WF3 transcript.

### Round 12 — 6 Ethena synthetic-dollar detectors (worktree agents) — detects a REAL confirmed High
- **Result:** +6 → **77 active** (33 novel classes across 5 DeFi domains). Authored by 6 worktree agents via the prelude.
  Independent dogfood: **0 R12 FPs on all 7 prior codebases** (olympus 92 / eigenlayer 24 / pendle 81 / etherfi 126 /
  symbiotic 41 / karak 15, unchanged); on real Ethena, **`escrow-exit-restriction-gap` fires on the exact shape of the
  confirmed High** the user's own audit found, `vesting-buffered-donation` detects the rate-donation Medium, and
  `one-sided-peg-band` fires 3×. The 3 signature/auth detectors (eip712-typehash-mismatch / delegated-signer-single-step
  / preauth-callout-target) stay silent on Ethena (it lacks those specific defects) — tight, 0-FP, self-test-validated,
  correctly dormant (a possible later real-target-tuning candidate, but no regression). 379 tests, 0 warnings, corpus
  20/20 + 8/8. **Milestone: a Sluice detector fires on a real, independently-confirmed High in a live protocol.**

#### R13 candidate backlog (R12 WF3 research on PENDLE yield-tokenization/AMM — a 5th domain, none overlap the 77)
1. **sy-exchange-rate-jump-trust** — external `exchangeRate()`/`pricePerShare` feeds pricing with monotonic `max()` clamp but NO per-update jump bound; PendleYieldToken.sol:406 (≠ price-bounds=Chainlink, ≠ crosschain-rate-staleness=timestamp).
2. **monotone-clamp-masks-negative-yield** — `index = max(externalRate, stored)` self-ratchet hides a real loss (negative yield) → phantom YT interest/redemption; PendleYieldToken.sol:406 + InterestManagerYT.sol:76.
3. **post-expiry-dual-index-settlement** — principal vs accrued-yield settled with two different indices (frozen `firstPYIndex` vs live) at a lazily-set, attacker-timeable freeze; PendleYieldToken.sol:353-392.
4. **curve-logit-domain-edge** — `ln/exp` + `logit(proportion)` AMM math floor-divides near the 1.0/MAX_PROPORTION singularity; MarketMathCore (escapes name-gated rounding.rs).
5. **stale-anchor-reset-first-trade** — implied-rate anchor reset on first trade after dormancy (spot-implied-rate manipulation window).
6. **solver-convergence-trust** — off-chain `approx` guess fed to an iterative solver whose unbounded/clamped output is trusted without a convergence/residual check; MarketApproxLibV2.
7. **ratio-denominator-sign-edge** — YT/PT-ratio math with `r − 1` style denominators that hit 0/sign-flip at the rate boundary.
These open a 5th domain (yield-tokenization/AMM); the AMM-curve math is invisible to the name-gated rounding detector. Full SCIR signatures in the R12 WF3 transcript.

### Round 13 — 7 Pendle yield-tokenization/AMM detectors (worktree agents) — a 6th domain
- **Result:** +7 → **84 active** (40 novel classes across 6 DeFi domains). Authored by 7 worktree agents via the prelude.
  Independent dogfood: **all 7 fire on the real Pendle target** (24 hits on the SY-rate/index/curve/solver math),
  **0 R13 FPs on all 7 other codebases** (olympus 92 / eigenlayer 24 / etherfi 126 / symbiotic 41 / karak 15 / renzo 50 /
  ethena 31 — unchanged). Classes: sy-rate-jump-trust, monotone-clamp-negative-yield, post-expiry-dual-index,
  curve-logit-domain-edge, stale-anchor-reset, solver-convergence-trust, ratio-denominator-sign-edge. The AMM-curve
  math (ln/exp/logit, rate-scalar/anchor) was previously invisible to the name-gated rounding detector — now covered.
  (solver-convergence-trust fires 12× on Pendle's router — eager on the target, 0-FP elsewhere; a Pendle-specific tighten
  candidate, not a regression.) 419 tests, 0 warnings, corpus 20/20 + 8/8.

### Round 14 — 6 lending / intent-RFQ / governance / AMM-fee detectors — opens the LENDING domain
- **Result:** +6 → **90 active** (46 novel classes across 7 DeFi domains; lending is the new, largest-TVL domain).
  Authored by 6 worktree agents via the prelude. Independent dogfood: the **3 lending detectors fire on the real Olympus
  `MonoCooler`** (interest-index-desync, bad-debt-socialization, param-update-retroactive — 1 each, at the borrow/
  liquidate/setLtv sites), **rfq-fill-accounting fires on Pendle's limit router** (2×); **0 R14 FPs on all 6 other
  codebases** (eigenlayer 24 / etherfi 126 / symbiotic 41 / karak 15 / ethena 31 / olympus-contracts 92 — unchanged).
  vote-weight-checkpoint + feegrowth-accounting are fixture-only here (no governance/Uni-V3-AMM corpus on-disk) — tight,
  0-FP, self-test-validated, correctly dormant. 457 tests, 0 warnings, corpus 20/20 + 8/8.

#### R14+ STRATEGIC backlog (R13 WF3 completeness-critic — the structural blind spots; steers the next several rounds)
Whole DeFi domains with ZERO detectors today. Ranked by payout × matchability × non-overlap; each tied to a real on-disk target:
1. **interest-index-desync** (lending) — debt/LTV checked against a STALE interest accumulator (RO index gates a write). Target: Olympus `MonoCooler.sol` (interestAccumulatorRay, _globalStateRO vs RW). ≠ LiquidationAbuse (that's seize/bonus only).
2. **rfq-fill-accounting** (intent/RFQ) — signed-order fill where fee/making/taking split isn't reconciled to the signed amounts, or partial-fill residual replay. Target: Pendle `PendleLimitRouter`/`LimitMathCore` (limitRouterCallback), Ethena `EthenaMinting`. ≠ SolverConvergence (that's approx-swap).
3. **bad-debt-socialization** — insolvent loss written off against a shared pool index/totalAssets (all depositors eat it) or never deducted (last-redeemer holds the loss).
4. **vote-weight-checkpoint** (governance) — quorum/vote weight from a manipulable checkpoint/snapshot or flash-acquired balance.
5. **feegrowth-accounting** (concentrated-liquidity AMM) — tick/sqrtPrice rounding + fee-growth/liquidity-delta accounting.
6. **perp-funding-mark** (perps) — funding-rate / mark-vs-index manipulation, ADL/insurance-fund accounting.
7. **param-update-retroactive** — collateral-factor/LTV update applies retroactively to existing positions (no migration/grace).
8. **tstore-guard-bypass** — EIP-1153 transient-storage reentrancy guard incorrectly scoped/cleared.
9. **aa-paymaster-validation** — ERC-4337 paymaster/validation-phase storage-rule violation / griefing.
10. **nft-claim-stale-rate** — NFT-fi redemption/withdrawal-queue claim at a stale rate.
Lending (#1/#3) + RFQ (#2) are the highest-leverage next targets (huge TVL class, real on-disk targets, clean non-overlap). Full signatures in the R13 WF3 transcript.

#### R15 backlog (R14 WF3 — protocol-agnostic primitives, overlap-checked vs the 90; + NEW corpora + perps deferral)
**NEW on-disk corpora discovered** (expand validation/target pool): **Optimism** (2,418 .sol — incl. real EIP-1153
`TransientContext.sol` + `L2ToL2CrossDomainMessenger`), **LayerZero** (2,549), a sui EVM bridge (29). These give the
tstore-guard detector a REAL target and add L2-infra/cross-chain dogfood surface.
R15 picks (broadly matchable on ANY codebase — raise baseline coverage; checked non-overlapping):
1. **tstore-guard-mis-scope** — EIP-1153 transient-storage reentrancy guard set without clear-on-all-paths / cleared at
   wrong call-depth / dirty transient value read cross-call. Validated target: Optimism TransientContext + L2ToL2CDM;
   exempt the canonical OZ-v5 `ReentrancyGuardTransient` (library-name exemption, like signature_malleability does).
2. **gap-not-shrunk** — a `__gap` that EXISTS but wasn't shrunk when state was appended, or mid-layout insertion (distinct
   from StorageGap, which only catches an ABSENT gap). Surface: eigenlayer/symbiotic/pendle `*Storage`/`*Upg` (75 files).
3. **batch-verify-skip** — batch/aggregate signature verify that SKIPS an invalid sig instead of reverting.
4. **uninitialized-storage-pointer** — a local `storage` struct/array ref defaulting to slot 0, overwriting state.
5. (lower) cross-protocol read-only-reentrancy — needs the consumer in-corpus (high FP otherwise).
**PERPS DEFERRED as NEEDS-CORPUS:** no on-disk perps engine (no fundingRate/openInterest/markPrice). Per the R7 lesson,
do NOT build perp-funding-mark / ADL fixture-only — defer until a GMX-v2 / Synthetix-perps / dYdX-v4 repo is added.

### Round 15 — 4 protocol-agnostic primitive detectors (worktree agents) + validated on the Optimism L2 corpus
- **Result:** +4 → **94 active**. Authored by 4 worktree agents via the prelude. Independent dogfood:
  **tstore-guard-misscope fires 4× on the real Optimism EIP-1153 code** (TransientContext / L2ToL2CrossDomainMessenger —
  its intended target); **0 R15 FPs on all 6 other codebases** (olympus 92 / pendle 107 / etherfi 126 / ethena 31 /
  symbiotic 41 / eigenlayer 24 — unchanged). gap-not-shrunk / batch-verify-skip / uninitialized-storage-pointer found no
  real instance in the audited codebases (modern 0.8 code rarely has them) — tight, 0-FP, self-test-validated, correctly
  dormant. **Bonus: Sluice scanned the ~2,400-file Optimism L2 corpus cleanly (152 findings, no timeout) — the R10 rayon
  perf work holds at real scale.** 480 tests, 0 warnings, corpus 20/20 + 8/8. (Optimism + LayerZero now usable as
  standing dogfood + R16 targets.)

#### R16 backlog (R15 WF3 — L2 / cross-chain INFRASTRUCTURE: an 8th domain, the #1 DeFi loss category; real OP Stack + LayerZero v2 targets)
Bridge-verification is the highest-payout exploit class in DeFi (Wormhole $325M, Nomad $190M, Ronin $625M). All checked non-overlapping vs bridge.rs (Nomad/Poly) + crosschain-rate-staleness:
1. **dvn-quorum-confirmations-conflation** — LayerZero ULN M-of-N verify compares block-CONFIRMATIONS (liveness) not SIGNER quorum → Wormhole-class forge-a-message mint. `layerzero/.../uln/ReceiveUlnBase.sol:48-57,90-124`. (generalizes to Axelar/CCIP/Hyperlane M-of-N.)
2. **prove-finalize-game-substitution** — OptimismPortal2 withdrawal proven against one dispute-game, finalized while that game's validity is re-evaluated from a mutable registry + a caller-supplied proofSubmitter key → fake-withdrawal bridge-ETH theft. `optimism/.../L1/OptimismPortal2.sol:461,572,651`.
3. **interop-message-no-source-binding** — Superchain relay authorizes by cross-domain sender but never pins source chainId → cross-cluster replay / unbacked-ETH mint. `optimism/.../L2/SuperchainETHBridge.sol:64-78`.
4. **bond-credit-accrued-before-finalization-verdict** — fault-proof bond credited at subgame-resolve before the final verdict.
5. **oft-decimal-truncation-supply-leak** — OFT cross-chain debit/credit loses dust asymmetrically → burn≠mint supply break.
6. **lz-receive-failure-silent-vs-stored** — endpoint clears payload before execution → a reverting/under-gassed lzReceive is lost (no replay).
7. **l1-to-l2-alias-trust-on-eoa-shortcut** — privileged L2 handler trusts an aliased L1 sender with the alias applied conditionally.
8. **unset-peer-eid-default-trust** — OApp/OFT receive treats an unconfigured peer (bytes32(0)) / unconfigured-EID as trusted.
R16 = the highest-payout round yet (bridges); items 1–3 have concrete production targets. Full signatures in the R15 WF3 transcript.

### Round 16 — 6 L2/cross-chain bridge detectors — opens the 8th domain + the 100-DETECTOR milestone
- **Result:** +6 → **100 active detectors** (56 novel classes across 8 DeFi domains; L2/bridge infra = the #1 DeFi loss
  category). Authored by 6 worktree agents via the prelude. Independent dogfood: **all 6 fire on real production targets** —
  OP Stack 2 (interop-no-source-binding on SuperchainETHBridge, prove-finalize-game-substitution on OptimismPortal2),
  LayerZero 6 (dvn-quorum-conflation = the Wormhole-class $325M ULN M-of-N verification shape; unset-peer-default-trust ×3;
  lzreceive-failure-silent; oft-decimal-supply-leak); **0 R16 FPs on all 5 non-bridge codebases** (olympus 92 / pendle 107 /
  etherfi 126 / ethena 31 / symbiotic 41 — unchanged). 511 tests, 0 warnings, corpus 20/20 + 8/8. (Cleaned a stray
  `scratch_dump` debug module an R16 worktree agent had copied into main.) Sluice now spans restaking, LST, cross-chain,
  synthetic-dollar, yield-tokenization, lending, governance, and L2/bridge infra — the top DeFi exploit-impact categories.

#### R17 backlog (R16 WF3 — OP-Stack fault-proof classes + next-domain corpus assessment)
PART A — OP fault-proof (real targets in optimism/.../src/dispute + L1; non-overlapping with R16's LayerZero/messaging shapes):
1. **RefundCreditPreVerdict** — a bond/stake credited to a participant on the action that POSTS it, paid out by a later
   resolve branch gated only on a status/mode flag (REFUND/finalized) WITHOUT a per-claim did-win/counteredBy predicate.
   `FaultDisputeGame.sol:552,311` + claimCredit `984,1003-1007,1069-1073`. (Suppress: two credit-maps or a mode enum + missing win-predicate.)
2. **ConditionalSenderAliasing** — L1→L2 sender alias (`±0x1111…`) applied CONDITIONALLY on a code-shape/EOA heuristic
   (incl. the EIP-7702 delegated-EOA branch) so two senders collide / a contract presents un-aliased. `OptimismPortal2.sol:709-711` + `EOA.sol:9-26`.
3. **ClockExtensionDepthBranch** — a chess-clock/deadline extended by a depth-branched amount including an externally-mutable
   `challengePeriod()`, with the resolve-time "expired" gate comparing vs MAX. `FaultDisputeGame.sol:503-522,745`. (loosest — tighten to depth-branch + external-call term.)
4. **RespectedGameTypeSnapshotSwap** — authorization decides on a FROZEN `wasRespectedGameTypeWhenCreated` snapshot while a
   Guardian can later swap the live respected type with no re-validation of in-flight games. `FaultDisputeGame.sol:318-319` + `AnchorStateRegistry.sol:153-160,231-236`.
PART B — corpus availability: **AA/ERC-4337 = NEEDS-CORPUS** (only a Safe `Test4337ModuleAndHandler` mock on disk, no canonical EntryPoint);
**concentrated-liquidity AMM = NEEDS-CORPUS** (no TickMath/SwapMath/SqrtPriceMath/FullMath on disk). Per the R7 lesson, do NOT build either
fixture-only — add a public EntryPoint/UniswapV3-core (or v4) repo first. R17 should build PART A (real OP targets) + tune any R16 dormant detectors.

_NOTE: an R16 worktree agent left a stray debug `detectors/scratch_dump.rs` + `pub mod scratch_dump;` in main mod.rs — DELETE both at R16 integration._ (done in R16.)

### Round 17 — 4 OP-Stack fault-proof detectors — completes the L2/bridge domain
- **Result:** +4 → **104 active** (60 novel classes across 8 domains). Authored by 4 worktree agents via the prelude.
  Independent dogfood: **all 4 fire on real OP Stack** — dispute dir 6 (refund-credit-pre-verdict ×3, clock-extension-depth-branch
  ×2, respected-gametype-snapshot-swap ×1 on FaultDisputeGame/AnchorStateRegistry), L1 dir 1 (conditional-sender-aliasing on
  OptimismPortal2 — the EIP-7702 aliasing angle); **0 R17 FPs on all 6 DeFi codebases** (olympus 92 / pendle 107 / etherfi 126 /
  ethena 31 / symbiotic 41 / eigenlayer 24 — unchanged). 539 tests, 0 warnings, corpus 20/20 + 8/8. The OP fault-proof
  surface (bonds / clocks / aliasing / respected-game-type) is now covered alongside the R16 LayerZero/messaging classes.

#### R18 work-plan (R17 WF3 meta-quality audit at the 100-detector milestone — a PRECISION round, not new classes)
Audit method: scanned 12 source roots (all exit 0, 0.06–4.9s, ≤290MB; olympus-v3 kitchen-sink vendored code excluded as a measurement artifact). 50/100 detectors fire on real code; of the 50 dormant: 37 fire 1–2× (healthy novel classes), 13 fire 0.
- **A. Fix the 1 real bug:** `vesting-buffered-donation` REGRESSED — fired on the Ethena rate-donation Medium in R12, now 0 despite `StakedUSDe.totalAssets()` being on disk. Re-tune to the real `balanceOf(this) − vesting` shape + add the ethena site as a regression fixture. (highest priority)
- **B. Tighten 4 over-eager detectors (the systematic noise):**
  1. `centralization-risk` (double-digits on EVERY codebase — the #1 noise): apply the R5 inline-guard recognizer to its "privileged" test — if the only caller is a FIXED protocol contract (immutable/constant/`staking`-style storage) down-rank to Info; reclassify `mint(<protocol-contract>,…)` as not user-fund-flow. Clears the Low/0.4 bulk.
  2. `reentrancy` (49× on Optimism, Critical over-ranks): use the R5/R6 per-call-site trust classifier to EXCLUDE trusted immutable/system callees (`weth()`/DelayedWETH/project view-pure) from the arming external call; do NOT count internal `_assertOnly*()` guard calls as the external call; CAP severity at High unless the callee is caller-supplied AND a value write strictly follows.
  3. `integer-issues` (23 etherfi): add provenance — `uintN(x)` where x reads a `uintN`-or-narrower storage field, or `a-b` of two uintN, is width-safe; dedupe multi-cast-per-fn to one finding.
  4. `solver-convergence-trust` (12 pendle, 0 elsewhere — target-overfit): require the guess to FLOW to a fund-moving sink in the same call.
- **C. Leave the 9 correctly-rare dormant** (untrusted-call-target, unprotected-initializer, erc721-mint-reentrancy, unchecked-erc1155-receiver, lp-slippage, msg-value-in-loop, gap-not-shrunk, uninitialized-storage-pointer, delegated-signer-single-step) — audited code is genuinely clean of them; forcing them would repeat the R7 overfit mistake.
- **D. Corpus to acquire (ranked):** #1 **Uniswap v3-core + v4-core/periphery** (unlocks the already-built-but-starved `feegrowth-accounting` on `Tick.getFeeGrowthInside` + concentrated-liquidity classes — largest AMM TVL/bounty surface); #2 a canonical ERC-4337 **EntryPoint** (AA paymaster/validation); #3 **MasterChef**-class staking (gives `reward-debt` a live target); #4 a **GMX-v2/Synthetix-perps** engine (unblocks the deferred perps classes). Per the R7 lesson, build the needs-corpus classes only AFTER the corpus is on disk.

### Round 18 — PRECISION round (executed the R17 meta-audit work-plan): measured noise reduction, recall preserved
- **Result:** still 104 detectors (no new classes — pure precision). Measured FP reduction (R17→R18, all via worktree
  agents + an independent re-dogfood): **centralization** olympus 27→22 / etherfi 29→21 / ethena 21→11 / optimism 20→12 /
  pendle 13→10 (the #1 noise source cut 25–50% everywhere — inline-guard-on-fixed-protocol-contract + mint-to-protocol now
  down-ranked); **reentrancy** optimism 49→**28** / symbiotic 15→**4** / olympus 11→9 / pendle 6→3 (trusted-immutable/system
  callees + internal `_assertOnly*` guard-calls no longer arm reentrancy; Critical capped); **integer-issues** etherfi 23→15
  (provenance width-safety); **solver-convergence-trust** pendle 12→**4** (now requires flow to a fund-moving sink); and the
  **`vesting-buffered-donation` REGRESSION FIXED** — ethena 0→1 (fires on real StakedUSDe again, + a regression fixture so it
  can't silently regress). Totals down: olympus 92→85, etherfi 126→109, ethena 31→28, optimism 154→130, pendle 107→93,
  symbiotic 41→30. **Recall fully preserved: corpus 20/20 + 8/8, all 5 real-hack harnesses pass, 565 tests, 0 warnings.**
  The 9 correctly-rare detectors left dormant (per the audit). A genuine signal-to-noise improvement on real code.

#### R19 backlog (R18 WF3 — EigenLayer AVS-middleware: the AVS verification trust root; real eigenlayer-middleware targets; non-overlap verified vs the 104)
1. **apk-membership-desync** — aggregate BLS pubkey built from one block-indexed history while membership/threshold reads a SEPARATE bitmap-history, with no co-update invariant → a forged `apk` passes the pairing for a non-quorum set. BLSSignatureChecker.sol:135-144 vs 101-117; root BLSApkRegistry.sol:168-201. (≠ dvn-quorum/batch-verify/netted-aggregate — this is aggregate-key-vs-membership over block histories + a pairing sink.)
2. **verify-snapshot-block-caller-trust** — M-of-N stake threshold measured at a CALLER-SUPPLIED `referenceBlockNumber` bounded only `< block.number` → pick a stale block where a since-slashed/exited operator still had stake. BLSSignatureChecker.sol:60; ECDSAStakeRegistry twin :494-538. (≠ epoch-boundary-staleness/oracle-staleness — this is a verification reference block, older = attacker-favorable.)
3. **churn-replace-stale-stake-double-count** — churn validates `newOperatorStake`/`totalQuorumStake` measured AFTER the newcomer self-registered (total already includes both newcomer + kicked) → total/per-operator stake desync. RegistryCoordinator._registerOperatorWithChurn.
4. **index-registry-pop-swap-stale-id** — swap-and-pop operator-index bookkeeping leaves a stale id/index.
5. **ejection-ratelimit-live-base-bypass** — auto-ejection rate-limit budget = percentage of a LIVE base (manipulable).
6. **reregister-cooldown-vs-bitmap-residue** — deregistration clears the quorum bitmap but leaves residue enabling re-register-cooldown bypass.
AVS verification is EigenLayer's trust root (high payout). Full signatures in the R18 WF3 transcript.

### Round 19 — 6 EigenLayer AVS-middleware detectors — covers the AVS verification trust root
- **Result:** +6 → **110 active** (66 novel classes across 8 domains). Authored by 6 worktree agents via the prelude.
  Independent dogfood: **5 of 6 fire on real eigenlayer-middleware** (apk-membership-desync = forged-aggregate-sig,
  verify-snapshot-block-caller-trust = stale-stake threshold bypass, churn-stale-stake-double-count, ejection-ratelimit-live-base,
  reregister-cooldown-bitmap-residue); index-registry-pop-swap-stale is fixture-only here (IndexRegistry correctly updates its
  index). **0 R19 FPs on all 6 codebases** — incl. 0 on eigenlayer CORE (confirming the classes are middleware-specific, not
  generic). 603 tests, 0 warnings, corpus 20/20 + 8/8; the R18 precision gains held (olympus 85 / etherfi 109 / pendle 93 / etc.).
  The AVS verification surface (BLS aggregate-key/membership, stake-snapshot trust, churn/ejection/reregister) is now covered.

#### R20 backlog (R19 WF3 — olympus-v3: a distinct ARCHITECTURE = Default-Framework module-permission + algorithmic-stability; exact file:line on disk; non-overlap vs the 110)
1. **PolicyPermissionDeclarationGap** — a Policy calls a module `permissioned` selector ABSENT from its own `requestPermissions()` array (called-but-undeclared = live DoS; declared-but-uncalled = latent over-grant). A cross-policy/module static check unique to the Kernel two-table permission contract. Operator.sol:200-213 vs its RANGE/TRSRY/MINTR calls; Kernel.sol:110-116,314-315,376-392. (≠ AccessControl/Centralization = caller-side modifiers.)
2. **ModuleActiveFlagPrivilegeScope** — a global module kill-switch (`activate`/`deactivate`, a scalar bool flipper behind the flat `permissioned` channel) gating `onlyWhileActive` on mint/withdraw → any grantee can halt the protocol. OlympusMinter.sol:84-91, OlympusTreasury.sol:163-170.
3. **WallCapacityRegenDesync** — RBS wall capacity debited by swap with no matching regen/threshold/approval co-update (spread across Operator+OlympusRange). Operator.sol:578-581,644-690; OlympusRange.sol:86-157.
4. **ModuleUpgradeStateMigrationDrop** — `UpgradeModule`/`MigrateKernel` swaps a module without copying state; default `INIT` is a no-op → new version starts zeroed. Kernel.sol _upgradeModule.
5. **LifecycleRoleRevokeGap** — a ROLES-system role granted to a policy is never revoked on Kernel deactivation → stale privilege.
6. **KeeperRewardTimestampAuction** — keeper incentive scaled by `block.timestamp`-elapsed, caller-mintable (Heart).
7. **BackingSpotInflationFromUnbufferedPrice** — emission/bond payout sized from an instantaneous `getLastPrice`/pool spot. EmissionManager.sol.
Adds a 9th surface: framework-ARCHITECTURE-specific classes (the Default-Framework Kernel/module/policy permission model), not just a value domain. Full signatures in the R19 WF3 transcript.

### Round 20 — 7 olympus-v3 Default-Framework detectors — opens the 9th surface (framework ARCHITECTURE)
- **Result:** +7 → **117 active** (73 novel classes; 9th surface = framework-architecture-specific). 6 of 7 fire on real
  olympus-v3 (15 hits) — flagship **policy-permission-declaration-gap ×4** (cross-policy/module Kernel requestPermissions-
  vs-called check), module-active-flag-scope ×4, backing-spot-inflation ×4, + module-upgrade/keeper-reward/wall-regen ×1;
  **0 R20 FPs on all 6 non-framework codebases** (correctly 0 where there is no Kernel). lifecycle-role-revoke-gap fixture-only.
  643 tests, 0 warnings, corpus 20/20 + 8/8. A bug class NO generalist tool (Slither/Mythril/Aderyn) models.

### R21 work-plan (R20 WF3 taxonomy audit) — COMPLETE THE CANONICAL BASELINE
Verdict: Sluice covers 10/10 OWASP SC Top-10 + every high-loss Rekt/Immunefi logic class, strongest where funds are lost
(bridge/share-accounting/oracle + protocol-specific logic generalist tools miss); weakness = mundane lints (18/37 SWC).
R21 builds the ~7 table-stakes baseline classes the novel rounds skipped: missing-event-emit (highest), floating-pragma
(SWC-103), strict-balance-equality (SWC-132), deprecated-eth-send (.transfer/.send 2300-gas), shadowed-state-var (SWC-119),
encodepacked-collision (SWC-133), locked-ether. NOT building: SWC-118/129/130/131/135/136 legacy-lints + supply-chain.

- **Result:** +7 → **124 active** — the canonical SWC/OWASP baseline, completing the taxonomy. Clean build (0
  warnings); **671 unit tests + corpus 20/20 + 8/8 + all 5 real-hack harnesses (r1–r4) green**. Dogfood on
  freshly-cloned Uniswap v4-core/v4-periphery (never-scanned real code): floating-pragma fires broadly (45+58 Info,
  correct on `^0.8.x` libraries); strict-balance-equality on the genuine `assert(balanceOf(POOL_MANAGER)==totalSupply())`
  (Low); locked-ether on the genuine payable-no-egress mixins Permit2Forwarder/UnorderedNonce (Low, precise message);
  the other four correctly silent on v4's safe forms. No FP-flood, right severities; each lint's `fires_on_*` unit test
  proves it fires on the genuine shape. Sluice now spans the full SWC baseline AND every high-loss logic class. _done._

_(Doc-hygiene: stale R10/R11 duplication + the out-of-order pending-R6 draft removed below; authoritative record is Rounds 1-20 + R21 above.)_
