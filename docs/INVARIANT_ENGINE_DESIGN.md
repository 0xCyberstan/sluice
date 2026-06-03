# Invariant-inference engine — PHASE B design (build blueprint)

> North-star PHASE B (`docs/NORTH_STAR.md`): the leap from pattern-matcher → invariant-reasoner, to catch the
> protocol-specific accounting/logic bugs Sluice misses (out-of-class recall ~0% today). Design grounded in the
> real SCIR; **everything routes through the existing corroboration scorer (`score.rs`)** so it inherits the 5
> precision waves' FP discipline — no new severity path that could bypass them.

## Why today's engine misses it
`sluice-invariant` mines only 3 shallow relations (guard consensus / name-based co-update / settlement-before-mutation);
none reason about **where a credited value comes from**. So LoopFi H-01 (`claimedAmount = address(this).balance`) and
Reserve M-02 (stake-rate recompute over a mutated base) sail through. The leap = reason over **value semantics of writes**.

## Minimal IR/dataflow additions (smallest set; recover the rest in detectors via body-walk taint)
- **2A. `ValueSource::SelfBalance`** (additive, in `sluice-ir/src/expr.rs` + a `SELF_BALANCE` bit in `sluice-dataflow`):
  label `address(this).balance`/`this.balance` and the `balanceOf(self)` case dataflow currently *drops* (the
  `balance_of_self_or_sender` recognizer at `dataflow/src/lib.rs:237`). Add `ProvenanceSet::is_self_balance()`. **Purely
  additive — no existing query changes → cannot regress the waves.** This is the central gap for H-01.
- **2B. `TrackedVars(contract)`** (computed in `InvariantFacts::mine`): the contract's own bookkeeping vars — a state var
  written by ≥1 peer with a delta tied to a param/`msg.value`, accounting-named (`balances`/`totalSupply`/`stakeRSR`/`shares`).
  The denominator of conservation/value-source invariants. Exposed via `cx.invariants.is_tracked_var(cid, name)`.
- **2C. `credited_value_provenance(cx, f, sink_expr)`** (prelude helper, generalizes `backing_spot_inflation::spot_tainted_locals`):
  local taint over the body (VarDecl/Assign 3-pass fixpoint, leaves seeded from `cx.provenance_of`) → the provenance of a
  written/credited value. Answers "does this credited amount derive from `SelfBalance` and not a `Tracked` var?" **No
  `StorageAccess` RHS field added** (keeps parse fast); RHS recovered on demand inside the few invariant detectors.
- **2D.** Extend `InvariantKind` with `ValueSourceDiscipline`/`Conservation`/`Monotonicity`; existing finalize-time
  corroboration (`engine/src/lib.rs:151`, keyed on FunctionId) works unchanged.

## Invariant classes (MINE the relation from cross-function agreement → FLAG the outlier)
1. **Value-source discipline (LoopFi H-01) — HIGHEST PRIORITY, build first.** A value credited to a caller (mint/transfer-to-caller/
   per-user-slot write) must derive from a **tracked** var, not a live raw-balance read. Structural law (no 3-peer consensus
   needed) but corroborated when a sibling credit path uses tracked vars (H-01's ETH branch does — the cleanest signal).
2. **Conservation (Σ balances == tracked total).** Pair a balance-mapping `M` with an aggregate scalar `S`; mine when peers that
   write `M` ≈ peers that write `S` (support 0.66–<1.0). Flag: missing co-update (desync) OR **delta mismatch** (M bumped by a
   param, S set from a raw balance — the conservation analog of H-01).
3. **Monotonicity (index/share-price/cumulative only grows).** Classify each write's direction (`+=`/`max` = up; `-=`/fresh
   recompute = down). If supermajority up (≥0.75), flag a peer that moves it down without a sanctioned-reset guard. = Reserve
   M-02 shape (stakeRate recomputed over a just-reduced stakeRSR). Surfaces the *risky shape* at conservative severity (R9 altitude).
4. **Co-update (generalized, tightened).** Keep name-based co-update only as the weakest tier, gated to accounting pairs +
   a value-moving present-but-not-co-written function (kills the current noise). A precision win shipped alongside.

## The LoopFi-H-01 detector — `value-source-discipline` (Phase B1), fully specified
New `Category::ValueSourceDiscipline`, dims `[Invariant, ValueFlow]`, severity High, conf 0.6 (→0.72 with a tracked-var sibling).
**Fires iff:** (1) a credit sink — a transfer/mint/`deposit{value:}`/`call{value:}`/`M[caller]=`/`+=` whose amount `A` reaches a
caller-influenced recipient; (2) `credited_value_provenance(A).is_self_balance() && !derives_from_tracked(A)`; (3) recipient peels
to a param/`msg.sender`-derived (not constant/immutable/owner).
**FP-suppression (make-or-break):**
- **S1 (critical) — balance-delta idiom.** Tag a binding `BalanceDelta` (NOT raw `SelfBalance`) when its RHS is `Binary{Sub}` with
  both sides reaching a self-balance read (`bal2 = balance; … amt = balance − bal2`). `BalanceDelta` fails predicate (2). This
  keeps `_fillQuote`'s `boughtETHAmount = address(this).balance - boughtETHAmount` (LoopFi:503) SILENT.
- **S2** amount bounded by a `require`/`if`-revert tied to a tracked var → silent. **S3** access-controlled + recipient is the
  protocol itself (`convertAllETH` self-deposit) → silent. **S4** recipient `address(this)` with no per-user attribution → silent.
  **S5** confidence boost when a sibling credit site uses tracked vars.
**Emission:** anchors the `address(this).balance` read; message contrasts with the tracked-var sibling branch (LoopFi H-01 shape).

## FP-control (MUST NOT regress the 5 waves)
- Route all violations through `score.rs` (lone invariant heuristic → Low/Info; corroborated by value-flow/frontier → High/Critical).
- **Worktree-isolated, real-code-tuned authoring**: build + run each detector against the full standing dogfood set (olympus/
  etherfi/ethena/optimism/pendle/symbiotic/eigenlayer/karak — the R18 baselines) **before merge**; gate = **0 new Crit/High FPs** +
  corpus 20/20 + 8/8 + real-hacks green.
- **Both-way regression fixtures** from real shapes: H-01 token-branch (*fires*) + `_fillQuote` balance-delta + `convertAllETH`
  self-credit + the ETH branch tracked-var (*silent*) — encodes S1/S3/S4 so they can't silently regress.

## Phased build plan
- **B1 — `value-source-discipline` (LoopFi H-01). FIRST.** Smallest footprint (SelfBalance source + credited_value_provenance);
  maps 1:1 to a real missed High with on-disk ground truth (`~/Data/bench/2024-05-loop/src/PrelaunchPoints.sol` `_claim`:240 fires,
  `_fillQuote`:491 silent, `convertAllETH`:315 silent, ETH branch:249 silent). **This single detector moves out-of-class recall
  above 0 — the headline metric.**
- **B2 — TrackedVars + Conservation.** Reuses B1's taint; tighten co-update same round.
- **B3 — Monotonicity + Reserve M-02** (`~/Data/bench/2023-01-reserve/.../StRSR.sol` `seizeRSR`:374). Most subtle → most conservative confidence.
- **B4 — consolidate** the 4 new + 3 legacy `InvariantKind`s into one `invariant-engine` surface; full dogfood re-measure.

## Honest hard parts
No SSA/path-sensitivity (IR is a normalized tree) → handle branch-specific provenance via per-binding taint anchored at the
assignment site, not a function-level union. `Tracked` is a heuristic (a genuine ETH-forwarder needs S3/S4 to stay quiet — real-code
tuning mandatory). Conservation compares taint *shape*, not numeric magnitude (catches source-mismatch, not subtle magnitude divergence
→ triage). Monotonicity surfaces the shape; economic exploitability is a triage judgment.

## Files (build targets)
`sluice-ir/src/expr.rs` (SelfBalance) · `sluice-dataflow/src/lib.rs` (bit + eval wiring, reuse `balance_of_self_or_sender`:237) ·
`sluice-invariant/src/lib.rs` (new kinds + TrackedVars/conservation/monotonicity miners alongside :78) ·
`detectors/prelude.rs` (`credited_value_provenance` + `BalanceDelta`) · `detectors/value_source_discipline.rs` (new) + `mod.rs` +
`finding.rs` (new Category) · scorer unchanged (`score.rs`, finalize `lib.rs:149`).
