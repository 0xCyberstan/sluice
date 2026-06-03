# Sluice — North Star (the target every agent is pointed at)

> Set 2026-06-03 after 5 real-code precision waves + fair-recall benchmarking. This is the definition of "perfect"
> and the objective the perpetual agent loop optimizes. **Primary aim (chosen): a contest-benchmark SCOREBOARD +
> an INVARIANT-INFERENCE ENGINE.** Make the target objective, then close the real capability gap (recall on
> protocol-specific invariant/logic bugs).

## One sentence
Point Sluice at any Solidity codebase and in seconds it returns the **exploitable** bugs an elite auditor would find
— correctly ranked, each with a runnable PoC, almost no noise — **including the protocol-specific logic/invariant
bugs that pattern tools (and Sluice today) miss.**

## The six dimensions — where we are → perfect
1. **Recall (the frontier).** Today ~20–30% in-class on a fair contest; misses ~all custom invariant/accounting bugs.
   → **≥80% of a contest's High/Med findings, including protocol-specific invariant bugs** (the LoopFi `balance`-over-mint class).
2. **Precision.** ~0 false Crit/High on 6 audited protocols (Aave/Lido/Morpho/UR/LoopFi 0/0; Comet 0/9 defensible). →
   **Stay ~0 false Crit/High AND fix severity calibration** (true positives must rank above false ones — the Reserve inversion).
3. **Proof.** Tiered PoCs (T1/T2/T3). → **A compiling, asserting Foundry PoC (red→green) for every High/Critical.**
4. **Novelty.** Detects classes Slither/Mythril miss (v4/AA/perps/restaking). → **Land ≥1 confirmed NOVEL bug in a live protocol.**
5. **Speed / scale / extensibility.** Seconds on whole protocols, deterministic, trivial detector authoring. → **Hold at 10k+ files, CI/incremental.**
6. **Measurement (the missing piece).** Hand-triage one repo at a time. → **A standing scoreboard over a corpus of real
   audit contests with known findings, scoring recall + precision every commit.**

## The plan (primary aim → concrete phases)

### PHASE A — the SCOREBOARD (build first; it's the prerequisite for everything else)
You cannot improve recall you cannot measure. Build:
- **A contest corpus:** N real Code4rena/Sherlock/audit codebases (start ~10–20, grow), each with its published
  High/Medium findings mapped to ground truth: `(contract, function, bug-class, in-class?)`. Store as a versioned
  manifest (`benchmarks/contests/*.json`) — repo, commit, scope dir, and the labeled findings.
- **A scoring harness:** scan each contest, then compute **RECALL** (caught known findings — a finding on/near the
  right contract+function+class) split into *in-class* (a class Sluice models) vs *out-of-class* (logic/invariant), and
  **PRECISION** (Crit/High FP rate via the same triage discipline). Output a scoreboard (per-contest + aggregate) and a
  trend vs the previous commit. Gate: the aggregate recall/precision must never regress.
- This is what lets agents be pointed at a number and watch it move — the objective target.

### PHASE B — the INVARIANT ENGINE (the capability leap → revolutionary)
The fair benchmark proved the ceiling is custom-invariant bugs that no pattern detector models. Build the leap from
*pattern matcher* → *invariant reasoner* (the original "consensus-invariant" design DNA, realized):
- **Infer per-protocol invariants** from cross-function agreement + state structure: conservation (Σ balances ==
  totalSupply; reserves == Σ deposits − Σ withdrawals), monotonicity (a share price / index only grows), CEI consensus,
  co-update pairs (totalAssets↔shares), one-way flags. Mine them where most functions respect a relation and flag the
  **outlier** that breaks it.
- **Flag violations** — e.g. a function that credits from `address(this).balance` rather than a tracked accounting var
  (LoopFi H-01), a redeem that reads stale collateralization across an external call, a mint that doesn't co-update the
  supply invariant. Score every candidate against the scoreboard.
- Also fix the *tractable* recall gaps (existing detectors that under-fire) as they surface — but the invariant engine
  is the differentiator that catches what no other tool does.

### Supporting (continue opportunistically, never regress the scoreboard)
- Precision: keep the FP-fix waves on fresh contests (the proven real-code-triage loop) + fix severity calibration.
- Proof: push PoC-gen toward T1-for-every-High.
- Novelty/breadth: new surfaces only when they move the scoreboard.

## How agents are pointed at this
Every loop round states which dimension + which scoreboard metric it moves, and re-runs the scoreboard at integration.
The scoreboard number (in-class recall, out-of-class recall, Crit/High precision) is the objective Sluice optimizes.
Current honest baseline to beat: **in-class recall ~20–30%, out-of-class recall ~0%, Crit/High precision ~near-100%
on audited code** (per the LoopFi + Reserve benchmarks). Perfect = in-class ≥80%, out-of-class materially >0 (via the
invariant engine), precision held, every High with a compiling PoC.
