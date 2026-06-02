# Sluice — Architecture

Sluice is a Rust workspace that statically analyzes Solidity source for the
*economic and logic* bug classes that audits and bug bounties reward most —
manipulable price feeds, missing solvency checks, vault inflation, read-only
reentrancy, signature replay, bridge verification gaps, and the like. It parses
Solidity natively with [`solang-parser`](https://crates.io/crates/solang-parser)
— no compiler, no Node, no external tools.

The design is deliberately patterned after the `vortex` binary-analysis engine,
re-expressed for Solidity *source* instead of lifted machine code. The recurring
analogy in the codebase is:

| `vortex` (binaries) | Sluice (Solidity) | Crate |
|---|---|---|
| `vortex-ir` (typed IR, classified opcodes) | **SCIR** — typed IR, pre-classified calls | `sluice-ir` |
| `vortex-lift` (native lifter) | native `solang-parser` front-end | `sluice-parse` |
| entropy domain (where a value came from) | **value-flow provenance** | `sluice-dataflow` |
| ghost-state detection | **consensus-invariant mining** | `sluice-invariant` |
| `vortex-cross` (trust-boundary analysis) | **trust frontiers / reentrancy** | `sluice-frontier` |
| `vortex-engine` (orchestration + dimensional multiplier) | detectors + corroboration scoring | `sluice-engine` |
| `vortex-verify` (interval triage + PoC) | feasibility triage + Foundry PoC | `sluice-verify` |
| `vortex-findings` | finding model + renderers | `sluice-findings` |
| `vortex-config` (profiles + feedback DB) | TOML config + profiles + feedback | `sluice-config` |
| — | the `sluice` binary | `sluice-cli` |

---

## 1. The pipeline

A scan is one linear flow: parse once into SCIR, run three independent analysis
*dimensions* over that SCIR, run every enabled detector in parallel against a
read-only view of all four, then `finalize` (corroborate → score → suppress →
dedup → cap → sort → assign ids).

```
                      sources: Vec<(path, content)>
                                   │
                                   ▼
        ┌──────────────────────────────────────────────────────┐
        │  sluice-parse   parse_sources / parse_paths            │
        │  solang-parser AST  ──lower──►  SCIR (sluice_ir::Scir) │
        │  • phase 0 parse every file (errors captured per-file) │
        │  • phase 1 register contracts/libs, inherited statevars│
        │  • phase 2 build functions + FunctionEffects + guards  │
        │  • phase 3 resolve internal call edges (callees/callers)│
        └──────────────────────────────────────────────────────┘
                                   │ Scir
                                   ▼
        ┌─────────────────── analyze_scir(scir, cfg) ───────────────────┐
        │                                                               │
        │   THREE ORTHOGONAL DIMENSIONS  (independent, read SCIR only)  │
        │                                                               │
        │   DataflowFacts::analyze   InvariantFacts::mine   FrontierFacts::analyze
        │   value-flow provenance    consensus invariants   trust frontiers
        │   (sluice-dataflow)        (sluice-invariant)      (sluice-frontier)
        │           │                       │                       │   │
        │           └───────────┬───────────┴───────────┬───────────┘   │
        │                       ▼                                       │
        │              AnalysisContext { scir, dataflow,                │
        │                                invariants, frontier, config } │
        │                       │                                       │
        │            builtin_detectors()  filtered by cfg.detector_enabled
        │                       │  rayon par_iter().flat_map(|d| d.run(&cx))
        │                       ▼                                       │
        │              raw: Vec<Finding>   (each tags 1+ Dimension)     │
        │                       │                                       │
        │                       ▼   finalize(raw, &cx, cfg)             │
        │   1. cross-dimension corroboration: add Invariant/Frontier    │
        │      dimension if an independent pass implicates the function │
        │   2. score(f) = base × dimension_multiplier × confidence_factor│
        │      → recomputes the severity LABEL from the score           │
        │   3. feedback multiplier (TP×1.25 / FP×0.0) from FeedbackDb    │
        │   4. suppression: cfg.is_suppressed, score≤0, confidence floor │
        │      (floor relaxed ×0.8 for profile-emphasized detectors)    │
        │   5. dedup_keep_strongest (by dedup_key)                      │
        │   6. cap_per_function (cfg.max_findings_per_function)         │
        │   7. sort by severity_score desc, assign ids "F-001"…         │
        └───────────────────────────────────────────────────────────────┘
                                   │ EngineResult { scir, findings, stats, parse_errors }
                                   ▼
        ┌──────────────────────────────────────────────────────┐
        │  sluice-verify (optional, --poc):                      │
        │    attach_pocs(scir, &mut findings, top_n=10)          │
        │  sluice-findings renderers:                            │
        │    console │ markdown │ json │ sarif │ html            │
        │  sluice-cli: write to --out or stdout; --fail-on gate  │
        └──────────────────────────────────────────────────────┘
```

The orchestration entry points live in `sluice-engine`:
`analyze_sources` / `analyze_paths` parse and delegate to `analyze_scir`, which
prepares the three dimensions, builds the `AnalysisContext`, runs detectors with
`rayon`, and calls `finalize`.

---

## 2. Crate responsibilities

Ten single-responsibility crates (`crates/*`), wired through
`workspace.dependencies`. Rust edition 2021, `rust-version = "1.85"`,
`lto = "thin"` in release.

- **`sluice-ir`** — SCIR, the frozen IR contract of the workspace. Defines
  `Scir`, `Contract`, `Function`, `FunctionEffects`, the expression/statement
  trees, `CallKind`, `ValueSource`, `GuardKind`, and the stable id newtypes
  (`ContractId`, `FunctionId`, `Span`). Every other crate depends on it; it
  depends on nothing but `serde` + `rustc-hash`.

- **`sluice-parse`** — the native front-end. `parse_sources` / `parse_paths`
  drive `solang-parser`, lower the AST into SCIR (`lower.rs`), compute the
  per-function effect summary (`effects.rs`), classify modifiers into guard
  kinds (`classify_modifier`), and resolve internal call edges. Parsing is
  best-effort per file: a malformed file is recorded in `file_errors` and never
  aborts the rest (see the `resilient_to_bad_file` test).

- **`sluice-dataflow`** — value-flow provenance (dimension 1). `DataflowFacts`.

- **`sluice-invariant`** — consensus-invariant mining (dimension 2).
  `InvariantFacts`.

- **`sluice-frontier`** — trust-frontier / reentrancy analysis (dimension 3).
  `FrontierFacts`.

- **`sluice-engine`** — orchestration. The `Detector` trait, the
  `AnalysisContext` (IR + three dimensions + FP-suppression helpers), the
  built-in detector registry (`builtin_detectors`), corroboration scoring
  (`score.rs`), and `finalize`.

- **`sluice-verify`** — `feasible` (conservative reachability refutation) and
  `generate_poc` / `attach_pocs` (category-tailored Foundry test skeletons).

- **`sluice-findings`** — the `Finding` model, `FindingBuilder`, `Category`,
  `Severity`, `Dimension`, and the five renderers.

- **`sluice-config`** — `Config`, `Profile`, and the `FeedbackDb` (TP/FP
  verdict store).

- **`sluice-cli`** — the `sluice` binary (clap): `scan`, `detectors`,
  `profiles`, `init`, `feedback`.

---

## 3. SCIR — the Smart-Contract Intermediate Representation

SCIR (`sluice-ir`) is the single, frozen vocabulary every pass shares. Its
design goal, stated at the top of `expr.rs`, is that **the security-relevant
structure is computed once, at parse time, and baked into the IR** — so a
detector can ask "is this an external low-level call?" or "is this a price-like
read?" directly, without re-deriving it from syntax.

### 3.1 Container and ids

`Scir` (`module.rs`) is the root, mirroring `vortex_ir::Module`: entities live
in `FxHashMap`s keyed by id for O(1) lookup, plus a `contract_order` for stable
declaration-order iteration.

```rust
pub struct Scir {
    pub files: Vec<SourceFile>,
    pub contracts: FxHashMap<ContractId, Contract>,
    pub functions: FxHashMap<FunctionId, Function>,
    pub contract_by_name: FxHashMap<String, ContractId>,
    pub pragma_solidity: Option<String>,
    pub contract_order: Vec<ContractId>,
}
```

`SourceFile` precomputes a `line_starts` index so `line_col`, `slice`, and
`line_text` resolve byte-offset spans to `(line, col)` and snippets cheaply
(and char-boundary-safely, via `floor_char_boundary`, so multi-byte UTF-8 never
panics). `ContractId` / `FunctionId` are distinct `u32` newtypes (`ids.rs`,
`id_newtype!` macro) so a function id can never be silently used where a
contract id is expected. `Span` is a `{file, start, end}` byte range mirroring
`solang_parser::pt::Loc::File`.

`Scir::solidity_ge_0_8()` parses the captured pragma (`pragma_allows_only_ge_0_8`)
to decide whether the compiler guarantees built-in overflow checks — an unknown
pragma is assumed modern (`>=0.8`) to avoid overflow false positives. This is
consumed by the integer-issues detector.

### 3.2 Contracts and state

`Contract` (`contract.rs`) carries `kind` (`Contract` / `Interface` / `Library`
/ `Abstract`), `bases`, `state_vars`, the directly-defined `functions`, and
`using_for` directives. Two case-insensitive substring helpers drive a lot of
FP suppression and mixin recognition:

- `inherits_like(needle)` — does any base name contain `needle`? (Used to spot
  `ReentrancyGuard`, `Ownable`, `ERC4626`, `SafeERC20`-mixins.)
- `uses_library_like(needle)` — does a `using X for ...` bind a library named
  like `needle`? (Used to detect `using SafeERC20 for IERC20`.)

`StateVar` records `constant` / `immutable` / `initialized` and offers
`is_scalar_numeric` / `is_mapping` heuristics for the invariant miner.

### 3.3 Functions and the effect summary

`Function` (`func.rs`) holds the normalized `body: Vec<Stmt>`, plus the resolved
`callees` / `callers` edges and — the centerpiece — `effects: FunctionEffects`.
Convenience predicates encode the attack-surface vocabulary:
`is_externally_reachable` (public/external, or fallback/receive),
`is_state_mutating` (nonpayable/payable, i.e. not view/pure), `is_view_or_pure`,
`is_constructor`, `has_modifier_like`.

`FunctionEffects` is the precomputed security summary — the analog of `vortex`'s
function summaries — letting the consensus and frontier passes reason about a
function without re-walking its body:

```rust
pub struct FunctionEffects {
    pub storage_reads:  Vec<StorageAccess>,   // var + path + order
    pub storage_writes: Vec<StorageAccess>,   // var + path + order
    pub call_sites:     Vec<CallSite>,        // classified, ordered
    pub internal_calls: Vec<String>,          // names of internal calls
    pub guards:         Vec<Guard>,           // modifiers + leading requires
    pub emits:          Vec<String>,
    pub reads_msg_sender, reads_msg_value, reads_tx_origin, reads_block_env: bool,
    pub has_loop, has_unbounded_loop, has_assembly, has_unchecked_math: bool,
}
```

Helpers: `written_vars()` (distinct, sorted), `first_external_call()` (by
order), and crucially `has_write_after_external_call()` — the raw
checks-effects-interactions signal: any storage write whose `order` exceeds the
first external call's `order`.

**The `order` field is the key design choice.** Rather than reconstructing an
SSA/CFG from already-structured source (as `vortex` must for machine code),
SCIR keeps a normalized statement tree (`stmt.rs`) and imposes a single
**happens-before total order** on call sites and storage accesses. The effect
collector (`effects.rs`, `EffectCollector`) assigns a monotonically increasing
`order` in one source-ordered walk. `stmt.rs` documents the rationale: for
source-level heuristic + data-flow analysis, a normalized tree plus the effect
summary plus this ordering is sufficient and far less error-prone than rebuilding
SSA.

`CallSite` records the classification (`CallKind`), textual `target`, resolved
`func_name`, `order`, `return_checked`, `sends_value`, and `forwards_gas`.

### 3.4 Pre-classified calls

`CallKind` (`expr.rs`) is determined *at parse time*: `Internal`, `External`,
`LowLevelCall`, `DelegateCall`, `StaticCall`, `Send`, `Transfer`, `New`,
`TypeCast`, `Builtin(Builtin)`, `Unknown`. Two predicates encode the trust-
frontier semantics directly on the enum:

- `is_external_transfer_of_control()` — true for External / LowLevel /
  Delegate / Static / Send / Transfer: the surface where reentrancy and
  trust-frontier bugs live.
- `can_send_value()` — true for LowLevel / Send / Transfer.

`Builtin` recognizes the security-relevant globals: `Require`, `Assert`,
`Revert`, `Keccak256`, `Ecrecover`, the `abi.*` family, `Selfdestruct`,
`Blockhash`, `Gasleft`, `ModMath`, `ArrayPushPop`, etc. So the dataflow pass can
treat `ecrecover` as attacker-tainted and the DoS detector can see `push`/`pop`
as storage growth, straight from the IR.

### 3.5 Value-source labels

`ValueSource` is the smart-contract analog of `vortex`'s entropy *sources*:
`AttackerInput`, `MsgSender`, `MsgValue`, `TxOrigin`, `ExternalReturn`,
`PriceLike`, `BlockEnv`, `StorageState`, `Constant`, `Unknown`. These are the
labels the dataflow dimension propagates (§5).

### 3.6 Guards

`GuardKind` (`func.rs`) classifies entry-level authorization/state guards:
`Modifier(name)`, `Require`, `MsgSenderCheck`, `Initializer`, `ReentrancyLock`,
`PauseCheck`. Guards come from two sources, merged by `sluice-parse`:

1. **Modifiers**, classified by `classify_modifier` (`lib.rs`): a name
   containing `nonreentrant`/`reentrancy`/`mutex` (or `== "lock"`) →
   `ReentrancyLock`; `initializer` → `Initializer`; `paused`/`whennotpaused` →
   `PauseCheck`; `only`/`auth`/`owner`/`admin`/`role`/`governance`/`guardian`/
   `restricted` → `MsgSenderCheck`; otherwise `Modifier(name)`.
2. **Leading `require`/`if-revert`** statements. The effect collector keeps a
   guard only if its `order` precedes the first external call or storage write
   (`collect` in `effects.rs`) — i.e. it is genuinely an *entry* guard. A
   `require`/`if` whose condition references `msg.sender` or `tx.origin` is
   promoted to `MsgSenderCheck` (`mk_guard`).

This guard vocabulary is what lets the engine recognize a `nonReentrant` lock or
an `onlyOwner` check and suppress the corresponding finding (§8), and lets the
invariant miner reason about guard *consensus* (§6).

---

## 4. `sluice-parse` — native front-end

`parse_sources` (`lib.rs`) is a four-phase lowering:

- **Phase 0** parses every file with `solang_parser::parse`. Diagnostics become
  `FileError` entries; the raw text is stored as a `SourceFile`. The first
  `pragma solidity` seen is captured into `Scir::pragma_solidity`.
- **Phase 1** registers all contracts/interfaces/libraries first, so call
  classification can distinguish a cast `IERC20(x)` from an internal call, and
  builds each contract's transitive (own + inherited) state-variable name set
  via `collect_state_vars`. This inherited set is essential: a write to a base
  contract's `balances` must still be recognized as a storage write.
- **Phase 2** builds each `Function` (`build_function`): lowers the body
  (`Lowerer`), computes `FunctionEffects` (`EffectCollector`), and prepends
  modifier-derived guards ahead of leading-`require` guards.
- **Phase 3** resolves internal call edges by walking each function's
  `internal_calls` and matching names up the inheritance hierarchy
  (`resolve_in_hierarchy`), populating `callees` / `callers` for
  interprocedural analysis.

The effect collector deserves note for ordering correctness: in an assignment it
walks the RHS *before* recording the write, so a call in the RHS gets a lower
`order` than the resulting storage write; compound assignments (`+=`) and
`++`/`--`/`delete` record both a read and a write; `unchecked { }` blocks set
`has_unchecked_math` for arithmetic inside them; loops bounded by a state
array's `.length` set `has_unbounded_loop`; and `assembly { sstore ... }` is
recorded as a synthetic write (`asm:<slot>`) so CEI ordering still applies.

---

## 5. Dimension 1 — value-flow provenance (`sluice-dataflow`)

This is the entropy analog: instead of a boolean "tainted" bit, every value
carries a **set of provenance labels** (`ProvenanceSet`, a `u16` bitset over
`ValueSource`). A detector can therefore ask the precise question — *does a
price-like value reach this collateral calculation?* — rather than merely *is it
tainted?*

### 5.1 The lattice and its queries

`ProvenanceSet` exposes monotone set operations (`union`, `union_in`, `with`,
`contains`) and three composite predicates that detectors actually call:

- `is_attacker_controlled()` — any of ATTACKER / MSG_SENDER / MSG_VALUE /
  TX_ORIGIN.
- `is_price_like()` — the PRICE_LIKE bit (manipulable spot price).
- `is_externally_influenced()` — attacker bits ∪ EXTERNAL_RETURN ∪ PRICE_LIKE ∪
  BLOCK_ENV (anything from outside the contract's own trusted state).
- `is_block_env()` — the BLOCK_ENV bit.

### 5.2 Analysis structure

`DataflowFacts::analyze` is flow-insensitive *within* a function and runs an
**interprocedural return-provenance fixpoint** across the module: seed every
function's local flow, then iterate up to `MAX_ROUNDS = 6` re-evaluations so a
callee's refined `return_prov` flows back into its callers; stop early on a fixed
point. Per function, `build_flow` itself iterates a local fixpoint up to
`MAX_LOCAL_ITERS = 8` (a variable may be assigned from a later/looped variable).
The analysis is documented as a sound over-approximation for reachability.

`FnFlow` per function records `var_prov` (variable → provenance, unioned),
`return_prov`, and `guarded_vars` (range/bounds-checked variables).

### 5.3 Seeding and evaluation (concrete rules)

- **Parameters** of externally-reachable functions are seeded
  `AttackerInput`; otherwise `Unknown` (`build_flow`).
- `eval` resolves expressions: a known state var reads `StorageState`;
  `msg.sender`/`msg.value`/`msg.data` → MsgSender/MsgValue/AttackerInput;
  `tx.origin` → TxOrigin; `block.timestamp|number|prevrandao|difficulty|
  coinbase|basefee` → BlockEnv; binary/ternary/tuple expressions union their
  operands; a member/index whose root is a state var adds `StorageState`.
- **Calls** (`eval_call`): a spot-price call returns `PriceLike ∪
  ExternalReturn`; External / LowLevel / Static / Delegate calls return
  `ExternalReturn`; `ecrecover` returns `AttackerInput`; the `abi.*`/`keccak`
  family unions its arguments; `blockhash`/`gasleft` return `BlockEnv`; an
  internal call inherits the resolved callee's `return_prov` (the interprocedural
  link); a `TypeCast` passes through its first argument's provenance.

### 5.4 What counts as a manipulable price

The manipulable-spot-price set is explicit (`SPOT_PRICE_FUNCS`) and is the
heart of the oracle/price dimension: `getReserves`, `getAmountOut`/`In`
(+ plural), `slot0`, `pricePerShare`, `getPricePerFullShare`,
`get_virtual_price`/`getVirtualPrice`, `convertToAssets`/`convertToShares`,
`totalAssets`, `quote`, `getRate`, `exchangeRate`. `is_spot_price_call` also
treats `balanceOf(<pool>)` as the canonical manipulable read. Robust oracles
(`latestRoundData`) are deliberately **excluded** here — Chainlink staleness is
a separate concern handled by the oracle detector.

**Worked example.** For
`return IERC20(t).balanceOf(address(this));`, `eval_call` tags the result
`PriceLike ∪ ExternalReturn`, so the function's `return_prov.contains(PriceLike)`
is true (`balance_of_is_price_like` test). The oracle detector then checks
whether such a value influences accounting and, if so and no robust oracle is
present, raises a `Manipulable spot price used for valuation` finding tagged
with both `ValueFlow` and `Frontier` dimensions.

---

## 6. Dimension 2 — consensus-invariant mining (`sluice-invariant`)

Sluice's signature differentiator and the one with no syntactic signature at
all. Most analyzers look for *known anti-patterns*; this pass instead **learns
each contract's implicit invariants from the agreement among sibling functions**,
then flags the outlier. It is "the developer assumed this path was always
guarded" turned into a detector — the ghost-state analog.

`InvariantFacts::mine` walks each concrete contract, gathers the **peer group**
(functions that are `has_body && is_externally_reachable && is_state_mutating &&
!is_constructor`), and runs three miners only if the group has at least
`MIN_PEERS = 3` members (below which "consensus" is meaningless). Each miner
emits a `MinedInvariant` (the property + its `support` fraction) and an
`InvariantViolation` per non-conforming peer (carrying the `consensus` strength).
A mined invariant is only interesting when support is **strictly between the
threshold and 1.0** — if every peer satisfies it, there is no outlier to flag.

### 6.1 Guard consensus (`mine_guard_consensus`)

For each guard feature in `{access-control, reentrancy-lock, pause}` (derived
from each function's `GuardKind`s via `guard_features`), compute the fraction of
peers that enforce it. Threshold: `0.66` for small groups (`< 6` peers), `0.75`
for larger. If support is in `[threshold, 1.0)`, the peers that *lack* the guard
are flagged.

> *Example.* Three of four value-moving functions carry `onlyOwner`; the fourth
> doesn't. Support `0.75` ≥ threshold and `< 1.0` → the fourth is flagged: the
> missing-`onlyOwner` / Euler-style access bug.

### 6.2 Co-update consensus (`mine_co_update`)

Builds, per state variable, the set of peer functions that write it. For every
ordered pair `(a, b)` of variables each written by ≥ 2 functions, if `b`
accompanies `a` in ≥ 66% (but `< 100%`) of the functions that write `a`, then
each function that writes `a` *without* writing `b` is flagged as accounting
drift.

> *Example.* `totalSupply` is almost always written alongside `balances` (or
> `totalAssets` alongside `totalShares`); the one function that updates one
> without the other desynchronizes accounting.

### 6.3 Settlement-before-mutation (`mine_settlement`)

The Euler-class miner. Among peers, the **risky** ones (`is_risky`: transfer
value, or write a var whose name contains balance/debt/collateral/share/deposit/
borrow) are collected; if there are at least `MIN_PEERS` of them, candidate
**settlement routines** are the internal calls whose names look like settlement
(`is_settlement_routine`: contains health/solven/ishealthy/checkaccount/accrue/
updatepool/updatereward/settle/checkpoint/requirecollateral/validatehealth).
Threshold: `0.6` (`< 6` risky peers) or `0.7`. A risky function that does *not*
call a routine which `[threshold, 1.0)` of its risky siblings call is flagged as
the missing-solvency-check bug.

> *Example* (from the crate test): four risky functions, three of which call
> `_checkHealth()`; `withdraw()` reduces collateral but skips it → flagged
> `SettlementBeforeMutation`.

These violations are surfaced as `MissingSolvencyCheck` / accounting findings by
the `accounting` detector, **and** they corroborate any other finding on the same
function (§7).

---

## 7. Dimension 3 — trust frontiers (`sluice-frontier`)

Every external call is a boundary where control or value leaves the contract.
`FrontierFacts::analyze` enumerates those **crossings** and classifies the
reentrancy risk at each, with careful handling of the read-only case.

### 7.1 Crossings

For every function body, each call site whose `kind.is_external_transfer_of_control()`
becomes a `Crossing` recording `return_checked`, `sends_value`, and
`state_write_after` (any storage write with `order` greater than the call's).
`FrontierFacts::unchecked_returns()` exposes the subset of low-level/send/
external crossings whose return value is ignored.

### 7.2 The reentrancy-capability filter (the key FP suppressor)

`is_reentrancy_capable` decides whether a call can actually hand control to code
that may re-enter:

- LowLevel / Delegate / Send / Transfer → always capable.
- `External` → capable **only if** it sends value *or* is **not** a view method.
- `StaticCall` → never (read-only by construction).

`is_view_method` lists the view/pure external methods that run in a staticcall
context and **cannot** re-enter — `balanceOf`, `getReserves`, `totalSupply`,
`slot0`, `latestRoundData`, `decimals`, `previewRedeem`, `convertToAssets`, etc.
This is the single most important reentrancy false-positive suppressor: a
`token.balanceOf(...)` read followed by a state write is **not** reentrancy, and
Sluice will not report it.

### 7.3 The three reentrancy kinds (`ReentrancyKind`)

- **Classic** — a storage write occurs after the first reentrancy-capable call
  in the same function (`first_reentrant_call` → writes with higher `order`).
- **Read-only** — a *view* getter (from `view_readers_of`) reads a variable that
  some mutating path writes *after* an external call; that getter exposes
  mid-update state and is consumable as a corrupt oracle (the Sentiment class).
  Reported on the getter, with `guarded = false` (view functions are typically
  unguarded).
- **Cross-function** (`detect_cross_function`) — function A makes an external
  call (with no lock) while touching shared state before it, and a sibling B
  mutates one of those same variables, so re-entering B is harmful.

Each `ReentrancyRisk` records whether it is `guarded` — `function_has_lock`
(a `ReentrancyLock` guard) **or** the contract `inherits_like("reentrancyguard"
| "reentrant")`. Guarded classic risks are still recorded but the reentrancy
detector skips them (§8); the `guarded` flag also gates whether the finding
contributes frontier corroboration in `finalize`.

---

## 8. Detectors and the `AnalysisContext`

A `Detector` (`detector.rs`) is a tiny, stateless, `Sync + Send` trait —
`id()`, `category()`, `description()`, `run(&AnalysisContext) -> Vec<Finding>` —
so the engine can run all detectors in parallel with `rayon`. The 18 built-ins
are registered in `builtin_detectors()`:

`reentrancy`, `access-control`, `oracle-manipulation`, `unchecked-return`,
`accounting`, `signature`, `upgradeable`, `vault`, `flashloan-governance`,
`bridge`, `slippage`, `dos`, `fee-on-transfer`, `randomness`, `forced-ether`,
`selector` (collision), `integer-issues`, `erc777`. (`sluice detectors` prints
the live list with descriptions.)

The `AnalysisContext` (`context.rs`) is the read-only view handed to every
detector — the IR plus the three prepared dimensions plus the config — with two
classes of helper:

**Iteration / value-flow queries.** `functions()`, `entry_points()`
(externally-reachable, state-mutating, with a body — the usual attack surface),
`names(fid)`, `provenance_of(fid, e)`, `is_attacker_controlled(fid, e)`,
`is_price_like(fid, e)`, plus `report`/`finish` for building a `Finding` with
location resolved from a span.

**False-positive-suppression helpers** — detectors consult these before
emitting, so a *neutralized* pattern never becomes a finding:

- `has_reentrancy_guard(f)` — a `ReentrancyLock` guard or a `ReentrancyGuard`/
  `reentrant` base. (The reentrancy detector skips any function for which this
  holds.)
- `has_access_control(f)` — a `MsgSenderCheck` guard.
- `is_initializer(f)` — an `Initializer` guard.
- `uses_safe_erc20(cid)` — `using SafeERC20` or a SafeERC20 base (suppresses
  unchecked-transfer findings).
- `contract_inherits(cid, needle)` — generic mixin check.
- `uses_robust_oracle(f)` — a `latestRoundData`/`latestAnswer`/`getRoundData`
  call, or an internal call whose name mentions `chainlink`/`oracle`
  (suppresses spot-price oracle findings).

Detectors also draw on shared helpers in `detectors/mod.rs`: `find_spot_price`
(first manipulable-price call span), `is_accounting_name`, `is_privileged_name`,
and `visit_calls`.

### 8.1 Detectors in practice (representative)

- **`reentrancy`** consumes `frontier.reentrancy_of(f)`, skips guarded risks and
  any function with a reentrancy guard, maps each `ReentrancyKind` to a category
  + base severity + confidence (Classic High/0.8, ReadOnly High/0.6,
  CrossFunction Medium/0.55), always tags `Dimension::Frontier`, and additionally
  tags `Dimension::ValueFlow` when the function sends ETH (re-entry is trivial) —
  pre-corroborating itself.

- **`oracle-manipulation`** suppresses when `uses_robust_oracle(f)`; otherwise
  requires both a manipulable spot-price call (`find_spot_price`) *and* evidence
  it influences accounting (a write to an accounting-named var, or a function
  whose name implies valuation: price/value/collateral/mint/borrow/deposit/
  redeem/liquidat). It tags both `ValueFlow` and `Frontier` and cites the
  Cream/Harvest/bZx class.

- **`vault`** fires only on vault-like contracts (`is_vault_like`), suppresses
  when an inflation mitigation is present (`decimalsOffset`/virtual shares/dead
  shares, or an `ERC4626` base), and reports first-depositor/donation inflation
  only when the share price derives from a donatable balance
  (`balanceOf(address(this))` / `totalAssets`). It separately flags
  divide-before-multiply precision loss (`find_div_before_mul`).

---

## 9. Corroboration scoring (`score.rs`) — the false-positive suppressor

This is the heart of Sluice's precision, adapted from `vortex`'s dimensional
multiplier. The formula (`score.rs`):

```
score = base(severity) × dimension_multiplier(#dimensions) × confidence_factor
confidence_factor = 0.75 + 0.25 × confidence          // ∈ [0.75, 1.0]
```

with the exact constants from the code:

**Base scores** (`Severity::base_score`): Critical 90, High 70, Medium 45, Low 20,
Info 5.

**Dimension multiplier** (`dimension_multiplier`):

| corroborating dimensions | multiplier |
|---|---|
| 0 or 1 | **1.0** |
| 2 | **1.5** |
| 3 | **2.0** |

**Label from score** (`label_from_score`) — the final severity label is *derived
back* from the numeric score:

| score | label |
|---|---|
| ≥ 100 | Critical |
| ≥ 60 | High |
| ≥ 33 | Medium |
| ≥ 12 | Low |
| else | Info |

### Why this suppresses false positives

The label is recomputed from the score, so **corroboration can promote a finding's
severity** and lack of corroboration demotes it:

- A **single-dimension High** (the common case for a lone heuristic):
  `70 × 1.0 × (0.75 + 0.25·0.8) = 70 × 0.95 = 66.5` → stays **High** (≥ 60), but
  does not reach Critical. Drop the confidence to 0.5 and it is `61.25` — barely
  High; a Medium single-signal finding at modest confidence lands in Low/Info and
  sinks to the bottom of the sorted list.
- A **three-dimension High** — the same bug seen simultaneously by value-flow,
  invariant, *and* frontier: `70 × 2.0 × 0.95 = 133` → promoted to **Critical**
  (≥ 100). This is exactly the `corroboration_promotes_severity` test, and the
  composition effect the README describes: "a finding that is simultaneously a
  value-flow problem, an invariant violation, *and* a frontier crossing rises to
  Critical automatically."

So lone-signal noise stays Low/Info and ranks last, while independently
corroborated findings float to the top. Because findings are sorted by
`severity_score` (not just label), even two findings sharing a label are ordered
by how many dimensions corroborate them.

### Automatic corroboration in `finalize`

Detectors only tag the dimensions they *directly* establish. `finalize`
(`sluice-engine/src/lib.rs`) then performs **cross-dimension corroboration
automatically**: it builds the set of (contract, function) pairs implicated by
the invariant pass (any `violation`) and by the frontier pass (any *unguarded*
reentrancy risk, or any crossing with `state_write_after`), and for each finding
adds `Dimension::Invariant` / `Dimension::Frontier` if an independent pass also
implicates that function. Only then is `score(f)` computed. This is what lets,
e.g., a reentrancy finding on a function that *also* skips a solvency check
inherit a second dimension and be promoted — without the reentrancy detector
knowing anything about invariants (the `corroboration_lifts_euler_class` test).

---

## 10. FP-suppression: the full set

False-positive suppression is layered, not a single gate:

1. **Capability filtering at the IR level** — view-only external reads are not
   treated as reentrancy-capable (`is_reentrancy_capable` / `is_view_method`),
   and robust oracles are excluded from `SPOT_PRICE_FUNCS`. Noise is never even
   generated.
2. **Defensive-pattern recognition in detectors** — `has_reentrancy_guard`,
   `has_access_control`, `is_initializer`, `uses_safe_erc20`, `uses_robust_oracle`,
   and detector-local checks (e.g. the vault detector's virtual-shares/decimals-
   offset/`ERC4626` mitigation check). A neutralized pattern is dropped before it
   becomes a finding.
3. **Corroboration scoring** (§9) — lone-signal findings score low and sink;
   multi-dimension findings rise. The single biggest precision lever.
4. **Feedback multiplier** — recorded verdicts re-weight the score (§11): a
   confirmed FP multiplies the score by `0.0` (which then fails the `score ≤ 0.0`
   retain check and is removed); a confirmed TP multiplies by `1.25`.
5. **Config + confidence floor** — `cfg.is_suppressed(contract, function)` and a
   per-finding `confidence` floor (`cfg.min_confidence`), relaxed to `× 0.8` for
   detectors the active profile emphasizes (§11).
6. **Dedup + per-function cap** — `dedup_keep_strongest` keeps the
   highest-scoring finding per `dedup_key` (`category|contract|function|line`);
   `cap_per_function` limits findings per (contract, function) to
   `max_findings_per_function`.
7. **Feasibility triage** (`sluice-verify::feasible`) — a conservative
   refutation that drops attacker-input findings on functions that are neither
   externally reachable nor have any internal caller. It over-approximates and so
   never refutes a real finding.

`finalize`'s `retain` applies steps 4–5 (`is_suppressed`, `score ≤ 0.0`,
confidence floor), then dedup and cap, then sorts by score descending and assigns
`F-001`-style ids.

---

## 11. Config, profiles, and feedback (`sluice-config`)

### `Config`

`Config` (TOML, serde-defaulted) holds `profile`, `min_confidence` (default
`0.35`), `disabled` / `enabled_only` detector id lists, `suppress`
(`Contract.function` or bare-`function` substrings), `exclude_paths`,
`max_findings_per_function` (default `25`), and an optional `feedback_path`.
`default_excludes()` ships a sensible exclusion list (`node_modules/`, `/lib/`,
`forge-std`, `openzeppelin`, `/test/`, `.t.sol`, `/mocks/`, `/script/`,
`.s.sol`). `detector_enabled` honors `enabled_only` if non-empty, else
`disabled`; `is_suppressed` matches the qualified name; `is_excluded` filters
discovered paths.

### `Profile`

`Profile` (`Generic`, `Vault`, `Lending`, `Amm`, `Bridge`, `Staking`,
`Governance`; loosely parsed by `from_str_loose`, e.g. `erc4626`→Vault,
`dex`→Amm) does **not** hard-disable detectors — it returns an `emphasis()` list
of detector ids/categories it cares about:

| Profile | emphasis |
|---|---|
| Generic | (none — all detectors equal) |
| Vault | erc4626-inflation, first-depositor, rounding-direction, reentrancy |
| Lending | oracle-manipulation, missing-solvency-check, rounding-direction, price-manipulation |
| Amm | oracle-manipulation, slippage, read-only-reentrancy, reentrancy |
| Bridge | bridge-verification, signature-replay, access-control, selector-collision |
| Staking | reward-accounting, rounding-direction, reentrancy |
| Governance | flashloan-governance, access-control |

The emphasis feeds exactly one mechanism in `finalize`: an emphasized detector's
confidence floor is relaxed to `min_confidence × 0.8`, so the profile *sharpens*
sensitivity for the bug classes that matter to that protocol class without
silencing anything else.

### Feedback DB

`FeedbackDb` (`feedback.rs`) is a JSON map from a finding's `dedup_key` to a
`Verdict` (`TruePositive` / `FalsePositive`). `score_multiplier` returns
`0.0` for a confirmed FP, `1.25` for a confirmed TP, `1.0` otherwise — applied to
`severity_score` in `finalize` when `feedback_path` is set. The CLI's
`sluice feedback <key> --tp|--fp [--db ...]` records verdicts so scoring improves
run-over-run (the `vortex-config` feedback analog).

---

## 12. `sluice-verify` — feasibility triage and PoC generation

Two conservative jobs:

- **`feasible(scir, finding)`** — refutes a finding *only* when it can prove the
  flagged function is unreachable: for the attacker-reachability categories
  (`needs_attacker_reachability`: Reentrancy, Oracle/Price manipulation,
  AccessControl, SignatureReplay, FlashLoanGovernance), if the function is
  neither externally reachable nor has any caller, it is refuted. Otherwise it
  returns `true` (never refutes a real finding — the interval-triage philosophy).

- **`generate_poc(scir, finding)` / `attach_pocs`** — emits a `forge-std`
  `Test.sol` skeleton tailored to the finding's `Category`. `attack_steps`
  supplies category-specific commentary (a reentrancy PoC outlines deposit →
  re-enter in `receive()` → drain; an oracle PoC outlines flash-loan → skew spot
  source → mis-value → unwind; an ERC-4626 PoC outlines the 1-wei-share donation
  attack; etc.). The pragma is taken from `scir.pragma_solidity` (default
  `^0.8.20`). The CLI attaches PoCs to the top 10 findings when `--poc` is set.

---

## 13. Findings model and output (`sluice-findings`)

### `Finding`

The atomic output unit (`finding.rs`): `id`, `detector`, `title`, `category`,
`severity` + `severity_score`, `confidence`, location (`contract`, `function`,
`file`, `line`, `span`, `snippet`), `message`, `recommendation`, the corroborating
`dimensions`, an optional value-flow `trace` (`TraceStep`s), CWE/SWC `references`,
an optional Foundry `poc`, and free-form `tags`. `dedup_key()` is
`category|contract|function|line`.

`Category` (35 variants) is ordered roughly by historical payout/loss and carries
`slug()` (the stable detector/config id) and `references()` (CWE/SWC, e.g.
reentrancy → SWC-107/CWE-841, oracle → CWE-20/CWE-1339, signature → SWC-117/
SWC-121/CWE-347). `Dimension` (`ValueFlow` / `Invariant` / `Frontier`) is the
corroboration axis. `Severity` maps to `sarif_level` (error/warning/note) and to
`base_score` (§9).

`FindingBuilder` (`builder.rs`) is the fluent constructor detectors use — it
defaults severity Medium / confidence 0.5, auto-populates `references` from the
category, and `at(scir, contract, function, span)` resolves file/line/snippet
from the IR. Detectors express *intent*; the engine assigns the final `id` and
`severity_score`.

### Renderers (`render.rs`)

Five output formats, selected by `--format`:

- **`console`** — one compact block per finding (id, colored severity, category,
  title, `file:line`, `contract.function`, `score · conf · dimensions`) plus a
  severity tally. The CLI (`render_console`) adds ANSI color.
- **`markdown`** — a full report: severity table, then per-finding sections with
  the snippet, message, corroborating dimensions, value-flow trace,
  recommendation, embedded Foundry PoC, and references.
- **`json`** — `serde_json` array of the full `Finding` structs (this is where
  you read `dedup_key`-shaped data to feed `sluice feedback`).
- **`sarif`** — SARIF 2.1.0 with per-category rules and per-finding results
  (level from `sarif_level`; severity/score/confidence/dimensions in
  `properties`) for CI/IDE ingestion.
- **`html`** — a self-contained styled report.

---

## 14. `sluice-cli`

The `sluice` binary (clap) exposes:

- **`scan <path>`** — the main command. Flags: `--profile`, `--config`,
  `--format {console|markdown|json|sarif|html}`, `--out`, `--min-confidence`,
  `--only`/`--disable` (comma-separated detector ids), `--poc`, `--top N`, and
  `--fail-on <severity>` (CI gate: exit `1` if any finding ≥ threshold). It
  discovers `.sol` files via `walkdir` (honoring `exclude_paths`), runs
  `analyze_paths`, optionally truncates/attaches PoCs, renders, and writes to
  `--out` or stdout. A scan/parse/summary line is always printed to stderr.
- **`detectors`** — lists built-in detectors and descriptions.
- **`profiles`** — lists profiles and their emphasis.
- **`init [path]`** — writes a starter `sluice.toml`.
- **`feedback <key> --tp|--fp [--db ...]`** — records a TP/FP verdict.

`build_config` layers sources: an explicit `--config` file, else a `--profile`,
else `Config::default()`, with `--min-confidence`/`--only`/`--disable` overrides
applied on top.

---

## 15. End-to-end example

Given the classic vulnerable bank:

```solidity
contract Bank {
    mapping(address => uint256) balances;
    function withdraw() external {
        uint256 a = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: a}("");
        require(ok);
        balances[msg.sender] = 0;     // state write AFTER external call
    }
}
```

1. **Parse** → SCIR. `withdraw`'s `FunctionEffects` has a `LowLevelCall`
   (`sends_value = true`) at some `order`, and a `balances` write at a higher
   `order`; `has_write_after_external_call()` is true.
2. **Frontier** → `is_reentrancy_capable` is true (low-level call sending value);
   the write after it yields a `ReentrancyKind::Classic` risk with
   `guarded = false`.
3. **Reentrancy detector** → not guarded, so it emits a High `Reentrancy`
   finding tagged `Frontier`, and — because the call sends ETH — also `ValueFlow`.
4. **`finalize`** → the function is in `frontier_funcs` (unguarded reentrancy), so
   the `Frontier` dimension is confirmed; `score = 70 × 1.5 × ~0.95 ≈ 99.75`
   (two dimensions) → reported High, near the Critical line, top of the list.

Add the `ReentrancyGuard` base + `nonReentrant` modifier and the
`guard_suppresses` path applies: the risk is `guarded`, `has_reentrancy_guard`
is true, and the detector emits nothing.

The `corroboration_lifts_euler_class` test shows the multi-dimension case: a
`withdraw` that skips `_checkHealth` (invariant violation) *and* has
reentrancy-flavored structure (frontier) is independently implicated by two
passes, so `finalize` stacks both dimensions and the finding is promoted.

---

## 16. Design properties worth remembering

- **One frozen IR.** SCIR is the workspace contract; passes and detectors are
  pure consumers. The security-relevant facts (call classification, value
  sources, effect summary, happens-before order, guards) are computed once at
  parse time.
- **Three orthogonal dimensions, composed.** Value-flow, invariant, and frontier
  analyses are independent and run over the same SCIR; their composition — via
  the dimension multiplier — is the precision mechanism, not any single pass.
- **Corroboration over heuristics.** A lone heuristic produces a low-ranked
  finding; agreement across independent passes is what makes a finding rise to
  Critical. False positives are suppressed by *not corroborating*, plus explicit
  defensive-pattern recognition and a feedback loop.
- **Resilient, tool-free, parallel.** Native `solang-parser` (no compiler/node),
  per-file error isolation, and stateless detectors fanned out with `rayon`.

For writing new detectors, see [DETECTOR_AUTHORING.md](DETECTOR_AUTHORING.md).
