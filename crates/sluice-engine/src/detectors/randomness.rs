//! Weak on-chain randomness and exploitable timestamp dependence.
//!
//! (1) **Weak randomness** — a function derives a *selection* or *reward* outcome
//! from block-environment values (`block.prevrandao`/`block.difficulty`,
//! `blockhash(...)`, `block.timestamp`, `block.number`). These are all either
//! known or miner/validator-influenceable at execution time, so any winner /
//! lottery / mint / reward decision built on them is predictable or grindable.
//! The canonical shape is `keccak256(abi.encodePacked(block.prevrandao, ...)) %
//! n` used as an index, but we also catch block-env feeding a function whose
//! name/role is a selection/reward.
//!
//! (2) **Timestamp dependence** — two distinct, *narrow* shapes:
//!
//!   (2a) `block.timestamp` used as a *direct equality gate* (`== ` / `!=`) on a
//!   value-bearing path. A ~12s validator nudge defeats an exact-timestamp gate,
//!   unlike a coarse `block.timestamp <= deadline` bound (which we deliberately do
//!   *not* flag).
//!
//!   (2b) **Timestamp-delta used as an accumulator weight** — a `block.timestamp`
//!   *delta* (current minus a stored last-timestamp) is multiplied / exponentiated
//!   into a value that is then *accumulated* into a time-weighted oracle/reward
//!   accumulator (an EMA, a cumulative reserve, a TWAP, or a reward-/index-per-X),
//!   in a state-mutating function that an actor can call at chosen times. The
//!   geometric/EMA/cumulative weighting depends on the *exact spacing* of the
//!   advancing calls (not merely on total elapsed time), so a party controlling
//!   *when* the accumulator is advanced can bias the time-weighted value that
//!   downstream consumers read as a price/reward. This is the Basin
//!   `MultiFlowPump.update` class: `cumulative += lastReserve * deltaTimestamp` and
//!   `ema = reserve*(1-α^Δ) + ema*α^Δ`, advanced by a permissionless `update`.
//!
//!   Precision is paramount here because `block.timestamp` is read legitimately
//!   almost everywhere (deadlines, cooldowns, vesting). (2b) therefore fires ONLY
//!   on the delta-as-weight-into-accumulator shape: it requires (i) a value that is
//!   a timestamp *delta*, (ii) that delta *multiplied / raised* into another value,
//!   and (iii) that product *added into* an lvalue whose name denotes a
//!   time-weighted accumulator (cumulative/ema/twap/reward-per-/index). A plain
//!   `require(block.timestamp <= deadline)` bound (no multiply, no accumulation), a
//!   `lastUpdate = block.timestamp` cooldown stamp, and a linear `vested = total *
//!   (now - start) / duration` release (a multiply, but no self-accumulation into a
//!   time-weighted-named accumulator) all stay silent.
//!
//! False positives are suppressed when the function plainly uses a proper
//! randomness source (Chainlink VRF / `requestRandomness` / `fulfillRandomWords`)
//! or a commit-reveal scheme.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Builtin, CallKind, Expr, ExprKind, Function};

pub struct RandomnessDetector;

impl Detector for RandomnessDetector {
    fn id(&self) -> &'static str {
        "weak-randomness"
    }
    fn category(&self) -> Category {
        Category::WeakRandomness
    }
    fn description(&self) -> &'static str {
        "Predictable block-env randomness (selection/reward) and exact-timestamp value gates"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            let src = cx.source_text(f.span);

            // FP suppression: a proper randomness source is in use. Applies to
            // both branches — VRF/commit-reveal designs legitimately read block
            // values (e.g. the reveal-deadline) without the outcome depending on
            // them.
            if uses_proper_randomness(&src) {
                continue;
            }

            self.check_weak_randomness(cx, f, &src, &mut out);
            self.check_timestamp_dependence(cx, f, &mut out);
            self.check_timestamp_accumulator_weight(cx, f, &mut out);
        }
        out
    }
}

impl RandomnessDetector {
    /// (1) Block-env value drives a selection/reward outcome.
    fn check_weak_randomness(
        &self,
        cx: &AnalysisContext,
        f: &Function,
        src: &str,
        out: &mut Vec<Finding>,
    ) {
        // Proper randomness (VRF / commit-reveal) is never flagged.
        if uses_proper_randomness(src) {
            return;
        }

        // The weak-randomness signature is a *selection* over a block-environment
        // value: a modulo (`... % n`) or an array index whose value derives from
        // the block environment (directly, via `blockhash`, or via `keccak256`).
        // Merely reading `block.number` to record a start block, or hashing block
        // data into an id, is NOT randomness and must not be flagged — that
        // distinction is what keeps this quiet on real protocols.
        let mut hit: Option<sluice_ir::Span> = None;
        for s in &f.body {
            s.visit_exprs(&mut |e| {
                if hit.is_some() {
                    return;
                }
                // A genuine random draw seeds the modulo/index with a HASHED block
                // value or with prevrandao/difficulty. A raw `block.timestamp %
                // EPOCH` is deterministic time-bucketing, and `mapping[block.number]`
                // is per-block accounting — neither is randomness.
                match &e.kind {
                    ExprKind::Binary { op: sluice_ir::BinOp::Mod, lhs, .. } => {
                        if self.expr_reaches_block_env(cx, f, lhs) && is_strong_random_seed(lhs) {
                            hit = Some(e.span);
                        }
                    }
                    ExprKind::Index { index: Some(idx), .. } => {
                        if self.expr_reaches_block_env(cx, f, idx) && is_strong_random_seed(idx) {
                            hit = Some(e.span);
                        }
                    }
                    _ => {}
                }
            });
            if hit.is_some() {
                break;
            }
        }
        let span = match hit {
            Some(s) => s,
            None => return,
        };
        // A selection/reward-flavored name raises confidence but is not required.
        let selection_like = name_is_selection(&f.name) || src_mentions_selection(src);

        let mut b = FindingBuilder::new(self.id(), Category::WeakRandomness)
            .title("Predictable randomness derived from block environment")
            .severity(Severity::High)
            .confidence(if selection_like { 0.7 } else { 0.55 })
            // Value-flow: a block-env source reaches a selection/reward sink.
            .dimension(Dimension::ValueFlow)
            .message(format!(
                "`{}` derives a selection/reward outcome from block-environment values \
                 (block.prevrandao/difficulty, blockhash, block.timestamp/number). These are \
                 known or validator-influenceable at execution time, so the winner/payout is \
                 predictable or grindable — a builder can re-roll the transaction until it wins, \
                 or simply read the value and only enter when favorable. (SWC-120 weak randomness.)",
                f.name
            ))
            .recommendation(
                "Use a verifiable randomness source (Chainlink VRF `requestRandomness` / \
                 `fulfillRandomWords`) or a commit-reveal scheme; never derive a winner, mint, or \
                 reward from block.prevrandao/blockhash/timestamp.",
            );
        // Invariant corroboration: the function also mutates state on this
        // outcome (a payout/mint/winner write), so the predictable value is not
        // merely read but settles protocol state.
        if f.is_state_mutating() && !f.effects.storage_writes.is_empty() {
            b = b.dimension(Dimension::Invariant);
        }
        out.push(cx.finish(b, f.id, span));
    }

    /// (2) `block.timestamp` used as a direct equality/inequality gate.
    ///
    /// We require an `==`/`!=` comparison (an *exact* timestamp gate, which a
    /// ~12s validator nudge defeats) and never flag ordering comparisons
    /// (`<`,`<=`,`>`,`>=`), which are the coarse-deadline / TWAP-window shape the
    /// spec tells us to leave alone.
    fn check_timestamp_dependence(&self, cx: &AnalysisContext, f: &Function, out: &mut Vec<Finding>) {
        if !f.effects.reads_block_env {
            return;
        }
        // If the only timestamp use is a coarse deadline bound, stay silent. We
        // positively require an equality gate below, so this is a fast reject for
        // the common `require(block.timestamp <= deadline)` case.
        let mut hit: Option<sluice_ir::Span> = None;
        for s in &f.body {
            s.visit_exprs(&mut |e| {
                if hit.is_some() {
                    return;
                }
                if let ExprKind::Binary { op: BinOp::Eq | BinOp::Ne, lhs, rhs } = &e.kind {
                    if is_block_timestamp(lhs) || is_block_timestamp(rhs) {
                        // Suppress if the *other* operand is plainly a deadline /
                        // expiry sentinel — an exact `== 0` "unset" check etc. is
                        // not value-critical timestamp manipulation.
                        let other = if is_block_timestamp(lhs) { rhs } else { lhs };
                        if !operand_is_deadline_like(other) {
                            hit = Some(e.span);
                        }
                    }
                }
            });
        }
        let Some(span) = hit else { return };

        // Lift to Medium only when the function moves value (payable, sends ETH,
        // or writes accounting-like state); otherwise it is a Low-severity smell.
        let value_bearing = f.is_payable()
            || f.effects.call_sites.iter().any(|c| c.sends_value)
            || f
                .effects
                .written_vars()
                .iter()
                .any(|v| crate::detectors::is_accounting_name(v));

        let mut b = FindingBuilder::new(self.id(), Category::TimestampDependence)
            .title("Value decision gated on an exact block.timestamp")
            .severity(if value_bearing { Severity::Medium } else { Severity::Low })
            .confidence(0.5)
            // Value-flow: a validator-influenceable value (block.timestamp)
            // controls a value-bearing branch.
            .dimension(Dimension::ValueFlow)
            .message(format!(
                "`{}` compares `block.timestamp` for exact (in)equality to gate behavior. A \
                 validator can nudge the block timestamp by several seconds, so an exact-match gate \
                 is manipulable — unlike a coarse `block.timestamp <= deadline` bound. (SWC-116 \
                 timestamp dependence.)",
                f.name
            ))
            .recommendation(
                "Do not gate value on an exact `block.timestamp`; use a tolerant range/deadline \
                 bound, a block-number window, or an oracle, and assume the timestamp is \
                 attacker-nudgeable within ~12s.",
            );
        if value_bearing {
            b = b.dimension(Dimension::Invariant);
        }
        out.push(cx.finish(b, f.id, span));
    }

    /// (2b) A `block.timestamp` *delta* used as a multiplicative/exponential weight
    /// that is then *accumulated* into a time-weighted oracle/reward accumulator.
    ///
    /// The narrow, principled invariant (so deadlines/cooldowns/vesting stay
    /// silent): we require ALL THREE of —
    ///   (i)   a value that is a **timestamp delta** (current `block.timestamp`
    ///         minus a stored last-timestamp), recognized syntactically (a `Sub`
    ///         reaching `block.timestamp`) or by a delta-timestamp *name* whose
    ///         definition is block-env-derived (covers `deltaTimestamp =
    ///         _getDeltaTimestamp(last)`, where the subtraction is inside a helper);
    ///   (ii)  that delta **multiplied or raised** into another value (`*` / `**`
    ///         or an ABDK-style `.mul(...)` / `.powu(...)` / `.pow(...)` /
    ///         `.mulDiv(...)` member call) — i.e. it *scales* a value, it is not
    ///         merely compared;
    ///   (iii) that product **added into an accumulator** whose lvalue name denotes
    ///         a time-weighted accumulator (cumulative / ema / twap /
    ///         reward-per-* / index), via `+=`, a self-`add(...)`, or a plain `+`.
    ///
    /// Only when the delta-weight and the accumulation land on the SAME named
    /// accumulator do we fire. The function must also be state-mutating and
    /// externally reachable (or callable from one) — the accumulator is advanced at
    /// caller-chosen times, which is what makes the spacing (and thus the weighting)
    /// biasable.
    fn check_timestamp_accumulator_weight(
        &self,
        cx: &AnalysisContext,
        f: &Function,
        out: &mut Vec<Finding>,
    ) {
        // Must be able to advance state. A pure/view read (e.g. the matching
        // `readInstantaneousReserves`/`_readCumulativeReserves` getters) recomputes
        // the same delta math but does not *persist* a biased accumulator, so it is
        // not the advancing site — only the writer is.
        if !f.is_state_mutating() {
            return;
        }
        // Locate a delta-weighted accumulation: a (compound) assignment whose target
        // is a time-weighted-accumulator-named lvalue, and whose RHS both reads the
        // accumulator back AND multiplies/raises a timestamp delta into it.
        let delta_locals = collect_timestamp_delta_locals(cx, f);
        let mut hit: Option<sluice_ir::Span> = None;
        for s in &f.body {
            s.visit_exprs(&mut |e| {
                if hit.is_some() {
                    return;
                }
                let (target, rhs, is_compound_add) = match &e.kind {
                    ExprKind::Assign { op, target, value } => {
                        (target.as_ref(), value.as_ref(), matches!(op, sluice_ir::AssignOp::Add))
                    }
                    _ => return,
                };
                // (iii) the target must be a time-weighted accumulator by name. The
                // lvalue may be indexed/qualified (`pumpState.cumulativeReserves[i]`),
                // so take the deepest member/ident name on the access path.
                let Some(acc_name) = accumulator_lvalue_name(target) else { return };
                if !name_is_time_weighted_accumulator(acc_name) {
                    return;
                }
                // (iii) the RHS must accumulate: either `+=`, or the accumulator is
                // read back inside the RHS (`acc = acc.add(...)` / `acc = acc + ...`).
                let accumulates = is_compound_add || rhs_reads_back(rhs, acc_name);
                if !accumulates {
                    return;
                }
                // (i)+(ii) the RHS must multiply/raise a timestamp delta into a value.
                if rhs_multiplies_delta(rhs, &delta_locals) {
                    hit = Some(e.span);
                }
            });
            if hit.is_some() {
                break;
            }
        }
        let Some(span) = hit else { return };

        let mut b = FindingBuilder::new(self.id(), Category::TimestampDependence)
            .title("Time-weighted accumulator advanced by a block.timestamp-delta weight at attacker-chosen times")
            .severity(Severity::Medium)
            .confidence(0.55)
            // Value-flow: a validator/caller-influenceable timestamp delta scales a
            // value that settles into an oracle/reward accumulator.
            .dimension(Dimension::ValueFlow)
            // Invariant: the accumulator is protocol state read downstream as a
            // price/reward, so the biased weight corrupts a value-bearing invariant.
            .dimension(Dimension::Invariant)
            .message(format!(
                "`{}` advances a time-weighted accumulator (EMA / cumulative reserve / TWAP / \
                 reward-per-token) by multiplying a `block.timestamp` *delta* (current minus a \
                 stored last-timestamp) into a value and accumulating it. The geometric/EMA/\
                 cumulative weighting depends on the *exact spacing* of the advancing calls, not \
                 just on total elapsed time, so a party that controls *when* this function is \
                 called (it is permissionlessly advanceable and the timestamp is validator-\
                 nudgeable by ~12s) can bias the time-weighted reserves/rewards that downstream \
                 consumers read as an oracle. (SWC-116 timestamp dependence.)",
                f.name
            ))
            .recommendation(
                "Do not let the EMA/cumulative weighting depend on caller-chosen call spacing: \
                 require a minimum elapsed time (or a fixed cadence) between accumulator advances, \
                 cap the per-call timestamp delta, snap deltas to a coarse interval, and treat \
                 `block.timestamp` as attacker-nudgeable within ~12s when sizing the weight.",
            );
        // Slight confidence nudge: a function with neither a tracked storage write
        // nor inline assembly is more likely a compute-only path that does not
        // actually persist the biased accumulator (the persisting writer is the real
        // advancing site). Basin's `update` persists via assembly `sstore`, so it
        // keeps the higher confidence. We keep both dimensions either way.
        if f.effects.storage_writes.is_empty() && !f.effects.has_assembly {
            b = b.confidence(0.5);
        }
        out.push(cx.finish(b, f.id, span));
    }

    /// True if `e` (transitively) reads a block-environment value, per the
    /// dataflow provenance (covers `block.*` members and `blockhash(...)`).
    fn expr_reaches_block_env(&self, cx: &AnalysisContext, f: &Function, e: &Expr) -> bool {
        // Cheap syntactic check first (handles `block.prevrandao` literally
        // inside the encode args), then fall back to provenance for values that
        // were routed through a local.
        let mut syntactic = false;
        e.visit(&mut |sub| {
            if is_block_env_expr(sub) {
                syntactic = true;
            }
        });
        syntactic || cx.provenance_of(f.id, e).is_block_env()
    }
}

// ------------------------------------------------------------------- helpers

/// True if `e` is a *strong* random-draw seed: it hashes its inputs
/// (keccak256/sha256) or uses blockhash, or references prevrandao/difficulty
/// directly. This distinguishes `keccak256(block.*) % n` (a real draw) from
/// `block.timestamp % EPOCH` (time-bucketing) and `mapping[block.number]`
/// (per-block accounting), both of which are not randomness.
fn is_strong_random_seed(e: &Expr) -> bool {
    use sluice_ir::{Builtin, CallKind};
    let mut strong = false;
    e.visit(&mut |sub| match &sub.kind {
        ExprKind::Call(c) => {
            if matches!(
                c.kind,
                CallKind::Builtin(Builtin::Keccak256)
                    | CallKind::Builtin(Builtin::Sha256)
                    | CallKind::Builtin(Builtin::Blockhash)
            ) {
                strong = true;
            }
        }
        ExprKind::Member { base, member } => {
            if let ExprKind::Ident(b) = &base.kind {
                if b == "block" && (member == "prevrandao" || member == "difficulty") {
                    strong = true;
                }
            }
        }
        _ => {}
    });
    strong
}

/// A proper randomness construction the detector must not flag.
fn uses_proper_randomness(src: &str) -> bool {
    src.contains("vrf")
        || src.contains("chainlink")
        || src.contains("requestrandomness")
        || src.contains("fulfillrandomwords")
        || src.contains("requestrandomwords")
        // commit-reveal schemes derive the outcome from a pre-committed secret,
        // not from raw block entropy.
        || (src.contains("commit") && src.contains("reveal"))
        || src.contains("commitment")
}

/// Function names that denote a selection / reward outcome.
fn name_is_selection(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "random", "winner", "lottery", "draw", "raffle", "pickwinner", "reward", "mint", "gacha",
        "roll", "spin", "shuffle", "jackpot", "prize",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// Function *source* mentions a selection / reward concept (catches a helper
/// whose name is generic but body assigns `winner = ...`).
fn src_mentions_selection(src: &str) -> bool {
    ["winner", "lottery", "raffle", "jackpot", "prize", " reward", "gacha"]
        .iter()
        .any(|k| src.contains(k))
}

/// `block.timestamp`.
fn is_block_timestamp(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Member { base, member }
        if member == "timestamp"
            && matches!(&base.kind, ExprKind::Ident(b) if b == "block"))
}

/// Any single block-environment expression node (`block.<env>` member or a
/// `blockhash(...)` call).
fn is_block_env_expr(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Member { base, member } => {
            matches!(&base.kind, ExprKind::Ident(b) if b == "block")
                && matches!(
                    member.as_str(),
                    "timestamp" | "number" | "prevrandao" | "difficulty" | "coinbase" | "basefee"
                )
        }
        ExprKind::Call(c) => matches!(c.kind, CallKind::Builtin(Builtin::Blockhash)),
        _ => false,
    }
}

/// Span of the first `block.*` env read in the body (best-effort, for locating
/// the finding when no keccak is involved).

/// The non-timestamp operand looks like a deadline/expiry/"unset" sentinel — an
/// exact `block.timestamp == 0` / `== deadline` is not the value-critical
/// equality gate we target.
fn operand_is_deadline_like(e: &Expr) -> bool {
    // `== 0` (unset/initialization sentinel) is not value manipulation.
    if let ExprKind::Lit(sluice_ir::Lit::Number(n)) = &e.kind {
        if n == "0" {
            return true;
        }
    }
    match e.simple_name() {
        Some(name) => {
            let l = name.to_ascii_lowercase();
            ["deadline", "expiry", "expiration", "validuntil", "endtime", "starttime"]
                .iter()
                .any(|k| l.contains(k))
        }
        None => false,
    }
}

// ------------------------------- (2b) timestamp-delta accumulator-weight helpers

/// The descriptive name of an lvalue accumulator, looking *through* any index
/// subscripts to the deepest member/ident on the access path:
/// `pumpState.cumulativeReserves[i]` → `cumulativeReserves`; `rewardPerToken[u]`
/// → `rewardPerToken`; a bare `index` → `index`. Returns `None` for non-lvalue
/// shapes.
fn accumulator_lvalue_name(e: &Expr) -> Option<&str> {
    match &e.kind {
        ExprKind::Member { member, .. } => Some(member.as_str()),
        ExprKind::Ident(n) => Some(n.as_str()),
        // Look through subscripts: `acc[i]` / `acc[i][j]` describe `acc`.
        ExprKind::Index { base, .. } => accumulator_lvalue_name(base),
        _ => None,
    }
}

/// A name that denotes a *time-weighted* accumulator whose value is read
/// downstream as a price/reward: a cumulative reserve, an EMA, a TWAP, or a
/// reward-/fee-per-X growth accumulator. Deliberately a tight set — the
/// surrounding delta-multiply + self-accumulation gate is what makes this precise,
/// but the name still anchors the finding to the oracle/reward-accumulator class
/// (so an ordinary counter / running total never qualifies). Bare `index` is
/// intentionally excluded (loop counters, array indices) — interest-rate indices
/// are named `borrowIndex`/`liquidityIndex` and would be caught by `index` only
/// with high FP risk; we keep this conservative.
fn name_is_time_weighted_accumulator(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("cumulative")
        || l.contains("ema")
        || l.contains("twap")
        || l.contains("rewardpertoken")
        || l.contains("rewardpershare")
        || l.contains("accpershare")
        || l.contains("rewardpersecond")
        || l.contains("feegrowth")
        || l.contains("growthglobal")
        || l.contains("timeweighted")
}

/// True if the accumulator (by name) is *read back* anywhere inside `rhs` — the
/// hallmark of accumulation (`acc = acc.add(...)` / `acc = acc + delta*x`). The
/// `+=` compound form is handled separately by the caller.
fn rhs_reads_back(rhs: &Expr, acc_name: &str) -> bool {
    let mut found = false;
    rhs.visit(&mut |sub| {
        if found {
            return;
        }
        if accumulator_lvalue_name(sub) == Some(acc_name) {
            found = true;
        }
    });
    found
}

/// True if `rhs` contains a *multiplicative / exponential* operation one of whose
/// operands is a timestamp delta: a `*` / `**` binary, or an ABDK/FixedPoint-style
/// `.mul(...)` / `.powu(...)` / `.pow(...)` / `.mulDiv(...)` / `.mulWad*(...)`
/// member call. This is condition (ii)+(i): the delta *scales* a value (it is not
/// merely compared or added).
fn rhs_multiplies_delta(rhs: &Expr, delta_locals: &rustc_hash::FxHashSet<String>) -> bool {
    let mut found = false;
    rhs.visit(&mut |sub| {
        if found {
            return;
        }
        match &sub.kind {
            // `a * delta` / `delta ** n` (delta as base or exponent).
            ExprKind::Binary { op: BinOp::Mul | BinOp::Pow, lhs, rhs } => {
                if expr_is_delta(lhs, delta_locals) || expr_is_delta(rhs, delta_locals) {
                    found = true;
                }
            }
            // `base.mul(delta)` / `ALPHA.powu(delta)` / `x.mulDiv(delta, d)` — the
            // delta is the receiver or any argument.
            ExprKind::Call(c) => {
                if call_is_multiplicative(c) {
                    let recv_delta = c.receiver.as_deref().is_some_and(|r| expr_is_delta(r, delta_locals));
                    let arg_delta = c.args.iter().any(|a| expr_is_delta(a, delta_locals));
                    if recv_delta || arg_delta {
                        found = true;
                    }
                }
            }
            _ => {}
        }
    });
    found
}

/// A multiplicative/exponential fixed-point method name (`mul`, `powu`, `pow`,
/// `mulDiv`, `mulWad`, `mulDown`, …). These are how ABDKMathQuad / PRBMath /
/// FixedPointMathLib express `a * b` and `a ** b` on wrapped numeric types, where
/// the operation is a member call rather than a `BinOp`.
fn call_is_multiplicative(c: &sluice_ir::Call) -> bool {
    match c.func_name.as_deref() {
        Some(n) => {
            let l = n.to_ascii_lowercase();
            l == "mul"
                || l == "pow"
                || l == "powu"
                || l == "muldiv"
                || l == "muldivdown"
                || l == "muldivup"
                || l == "mulwad"
                || l == "mulwaddown"
                || l == "mulwadup"
                || l == "muldown"
                || l == "mulup"
        }
        None => false,
    }
}

/// True if `e` is (or wraps) a timestamp-delta value: a named delta local, an
/// inline `block.timestamp - X` subtraction, or a cast/unary/member-call wrapper
/// around one of those.
fn expr_is_delta(e: &Expr, delta_locals: &rustc_hash::FxHashSet<String>) -> bool {
    // A known delta local (by deepest member/ident name).
    if let Some(name) = e.simple_name() {
        if delta_locals.contains(name) {
            return true;
        }
    }
    // An inline subtraction reaching `block.timestamp` (`block.timestamp - last`,
    // or `uint40(block.timestamp) - last`).
    if expr_is_inline_timestamp_delta(e) {
        return true;
    }
    // A cast / fixed-point conversion / unary wrapper around a known delta:
    // `deltaTimestamp.fromUInt()`, `uint256(delta)`, `uint40(delta)`.
    match &e.kind {
        // `uint256(delta)` / `uint40(delta)` — a TypeCast over a delta.
        ExprKind::Call(c) if c.kind == CallKind::TypeCast => {
            c.args.iter().any(|a| expr_is_delta(a, delta_locals))
        }
        // A numeric conversion member call (`delta.fromUInt()`, `delta.toUint256()`)
        // — the receiver is the delta; the method is a non-mutating conversion.
        ExprKind::Call(c) if c.receiver.is_some() && is_numeric_conversion(c) => {
            c.receiver.as_deref().is_some_and(|r| expr_is_delta(r, delta_locals))
        }
        ExprKind::Unary { operand, .. } => expr_is_delta(operand, delta_locals),
        _ => false,
    }
}

/// True if `e` syntactically contains a subtraction where one side reaches
/// `block.timestamp` — an inline timestamp delta (`block.timestamp - lastTs`).
fn expr_is_inline_timestamp_delta(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Binary { op: BinOp::Sub, lhs, rhs } = &sub.kind {
            if expr_reaches_block_timestamp(lhs) || expr_reaches_block_timestamp(rhs) {
                found = true;
            }
        }
    });
    found
}

/// True if `e` (transitively, syntactically) reads `block.timestamp`.
fn expr_reaches_block_timestamp(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if is_block_timestamp(sub) {
            found = true;
        }
    });
    found
}

/// A non-mutating numeric conversion method (ABDK `fromUInt`/`fromUIntToLog2`,
/// SafeCast `toUint*`, generic `to*`/`from*`) — a delta passed through one of
/// these is still a delta.
fn is_numeric_conversion(c: &sluice_ir::Call) -> bool {
    match c.func_name.as_deref() {
        Some(n) => {
            let l = n.to_ascii_lowercase();
            l.starts_with("fromuint")
                || l.starts_with("touint")
                || l.starts_with("toint")
                || l == "fromint"
                || l == "tobytes16"
        }
        None => false,
    }
}

/// Collect the set of local-variable names in `f` that hold a *timestamp delta*
/// (or a multiplicative/exponential function of one — e.g. an EMA decay weight
/// `α^Δ`). Iterated to a small fixpoint so a delta defined through one or two
/// conversion/derivation hops is captured (Basin: `deltaTimestamp =
/// _getDeltaTimestamp(last)` → `deltaTimestampBytes = deltaTimestamp.fromUInt()`).
fn collect_timestamp_delta_locals(
    cx: &AnalysisContext,
    f: &Function,
) -> rustc_hash::FxHashSet<String> {
    use sluice_ir::StmtKind;
    // Gather `(name, rhs)` definitions (declarations + assignments).
    let mut defs: Vec<(String, &Expr)> = Vec::new();
    for s in &f.body {
        s.visit(&mut |st| match &st.kind {
            StmtKind::VarDecl { name: Some(n), init: Some(e), .. } => defs.push((n.clone(), e)),
            StmtKind::Expr(e) => {
                if let ExprKind::Assign { target, value, .. } = &e.kind {
                    if let ExprKind::Ident(n) = &target.kind {
                        defs.push((n.clone(), value));
                    }
                }
            }
            _ => {}
        });
    }

    let mut deltas: rustc_hash::FxHashSet<String> = rustc_hash::FxHashSet::default();
    // A few passes resolve chained derivations; defs are few per function.
    for _ in 0..4 {
        let mut changed = false;
        for (name, rhs) in &defs {
            if deltas.contains(name) {
                continue;
            }
            if rhs_defines_delta(cx, f, rhs, &deltas) {
                deltas.insert(name.clone());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    deltas
}

/// Decide whether a definition RHS makes its target a timestamp delta (or a
/// multiplicative/exponential function of an existing delta).
fn rhs_defines_delta(
    cx: &AnalysisContext,
    f: &Function,
    rhs: &Expr,
    known: &rustc_hash::FxHashSet<String>,
) -> bool {
    // (a) inline `block.timestamp - X` (possibly wrapped in casts).
    if expr_is_inline_timestamp_delta(rhs) {
        return true;
    }
    // (b) a call to a delta-timestamp helper (`_getDeltaTimestamp(...)`,
    //     `elapsed()`, `timeSince(...)`) — the subtraction lives inside the helper.
    if let ExprKind::Call(c) = &rhs.kind {
        if matches!(c.kind, CallKind::Internal) && c.func_name.as_deref().is_some_and(name_is_delta_timestamp) {
            return true;
        }
    }
    // (c) a cast / numeric-conversion / unary wrapper around a known delta, OR a
    //     multiplicative/exponential combination involving a known delta (the EMA
    //     decay weight `ALPHA.powu(deltaTimestamp)` — a function of the delta whose
    //     own value is therefore time-spacing-biasable). We reuse `expr_is_delta`
    //     for the wrapper cases and `rhs_multiplies_delta` for the derived-weight
    //     case.
    if expr_is_delta(rhs, known) {
        return true;
    }
    if rhs_multiplies_delta(rhs, known) {
        return true;
    }
    // (d) provenance fallback: the RHS is block-env-derived AND the *defining*
    //     expression involves a subtraction somewhere (a delta, not a raw
    //     timestamp). This catches helper shapes the name heuristic misses while
    //     staying off a bare `now = block.timestamp` stamp (no subtraction).
    if cx.provenance_of(f.id, rhs).is_block_env() && contains_subtraction(rhs) {
        return true;
    }
    false
}

/// A name that denotes a timestamp *delta* / elapsed-time quantity.
fn name_is_delta_timestamp(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // Require an elapsed/delta sense coupled to time, so a generic `delta`
    // (price/share delta) does not qualify.
    (l.contains("delta") && (l.contains("time") || l.contains("timestamp") || l.contains("stamp")))
        || l.contains("timeelapsed")
        || l.contains("elapsedtime")
        || l.contains("secondselapsed")
        || l.contains("secondssince")
        || l.contains("timesince")
        || l.contains("timepassed")
        || l == "elapsed"
}

/// True if `e` contains any subtraction node (used by the provenance fallback to
/// distinguish a delta from a bare timestamp read).
fn contains_subtraction(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if matches!(&sub.kind, ExprKind::Binary { op: BinOp::Sub, .. }) {
            found = true;
        }
    });
    found
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Lottery winner chosen by hashing block.prevrandao — the textbook weak-PRNG.
    const VULN: &str = r#"
pragma solidity ^0.8.20;
contract Lottery {
    address[] public players;
    address public winner;
    function pickWinner() external {
        uint256 idx = uint256(
            keccak256(abi.encodePacked(block.prevrandao, block.timestamp, players.length))
        ) % players.length;
        winner = players[idx];
        payable(winner).transfer(address(this).balance);
    }
}
"#;

    // Proper randomness via Chainlink VRF: outcome comes from fulfillRandomWords,
    // and the only block value (the request deadline) is a coarse bound.
    const SAFE: &str = r#"
pragma solidity ^0.8.20;
contract FairLottery {
    address[] public players;
    address public winner;
    uint256 public requestId;
    uint256 public deadline;
    function requestRandomness() external {
        require(block.timestamp <= deadline, "closed");
        requestId = _vrfCoordinator_requestRandomWords();
    }
    function fulfillRandomWords(uint256, uint256[] memory randomWords) internal {
        uint256 idx = randomWords[0] % players.length;
        winner = players[idx];
    }
    function _vrfCoordinator_requestRandomWords() internal returns (uint256) { return 1; }
}
"#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "weak-randomness"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "weak-randomness"));
    }

    // ---- (2b) timestamp-delta-as-accumulator-weight ----

    fn td(fs: &[sluice_findings::Finding]) -> Vec<&sluice_findings::Finding> {
        fs.iter()
            .filter(|f| f.detector == "weak-randomness" && f.category == sluice_findings::Category::TimestampDependence)
            .collect()
    }

    // FIRES — the Basin `MultiFlowPump.update` shape (reduced): a permissionless
    // `update` reads a stored `lastTimestamp`, computes a `block.timestamp` delta in
    // a helper, casts it to a fixed-point value, and accumulates `lastReserve * Δ`
    // into a `cumulativeReserves` accumulator (and an EMA via `α^Δ`). The geometric
    // weighting depends on the *spacing* of `update` calls, biasable by whoever
    // chooses when to call it.
    const EMA_CUMULATIVE_DELTA: &str = r#"
pragma solidity ^0.8.17;

library FP {
    function fromUInt(uint256 x) internal pure returns (bytes16) {}
    function mul(bytes16 a, bytes16 b) internal pure returns (bytes16) {}
    function add(bytes16 a, bytes16 b) internal pure returns (bytes16) {}
    function sub(bytes16 a, bytes16 b) internal pure returns (bytes16) {}
    function powu(bytes16 a, uint256 n) internal pure returns (bytes16) {}
}

contract MultiFlowPump {
    using FP for uint256;
    using FP for bytes16;

    bytes16 immutable ALPHA;
    uint40 lastTimestamp;
    bytes16[] lastReserves;
    bytes16[] emaReserves;
    bytes16[] cumulativeReserves;

    constructor(bytes16 _alpha) { ALPHA = _alpha; }

    function update(uint256[] calldata reserves, bytes calldata) external {
        uint256 n = reserves.length;
        uint256 deltaTimestamp = _getDeltaTimestamp(lastTimestamp);
        bytes16 alphaN = ALPHA.powu(deltaTimestamp);
        bytes16 deltaTimestampBytes = deltaTimestamp.fromUInt();
        bytes16 ONE;
        for (uint256 i; i < n; ++i) {
            emaReserves[i] = lastReserves[i].mul(ONE.sub(alphaN)).add(emaReserves[i].mul(alphaN));
            cumulativeReserves[i] = cumulativeReserves[i].add(lastReserves[i].mul(deltaTimestampBytes));
        }
        lastTimestamp = uint40(block.timestamp);
    }

    function _getDeltaTimestamp(uint40 _last) internal view returns (uint256) {
        return uint256(uint40(block.timestamp) - _last);
    }
}
"#;

    #[test]
    fn fires_on_ema_cumulative_delta_weight() {
        let fs = run(EMA_CUMULATIVE_DELTA);
        let hits = td(&fs);
        assert!(
            !hits.is_empty(),
            "the EMA/cumulative delta-weight accumulator (Basin update class) must fire \
             timestamp-dependence: {:?}",
            fs
        );
        // It is the accumulator-weight title, not the equality-gate title.
        assert!(
            hits.iter().any(|f| f.title.contains("Time-weighted accumulator")),
            "expected the accumulator-weight finding: {:?}",
            hits
        );
    }

    // FIRES — Synthetix-style reward-per-token accumulator advanced by a permission-
    // less `updateReward`: `rewardPerTokenStored += (block.timestamp - lastUpdate) *
    // rewardRate * 1e18 / totalSupply`. Same delta-weight-into-accumulator class.
    const REWARD_PER_TOKEN: &str = r#"
pragma solidity ^0.8.20;
contract Staking {
    uint256 public rewardPerTokenStored;
    uint256 public lastUpdateTime;
    uint256 public rewardRate;
    uint256 public totalSupply;

    function updateReward() public {
        if (totalSupply > 0) {
            rewardPerTokenStored += (block.timestamp - lastUpdateTime) * rewardRate * 1e18 / totalSupply;
        }
        lastUpdateTime = block.timestamp;
    }
}
"#;

    #[test]
    fn fires_on_reward_per_token_delta_weight() {
        let fs = run(REWARD_PER_TOKEN);
        assert!(
            !td(&fs).is_empty(),
            "a reward-per-token accumulator advanced by a timestamp delta must fire: {:?}",
            fs
        );
    }

    // SILENT — a plain deadline bound. `require(block.timestamp <= deadline)` is a
    // coarse ordering comparison: no multiply, no accumulation. Must NOT fire (2b)
    // (and not (2a), since it is `<=`, not `==`).
    const DEADLINE_BOUND: &str = r#"
pragma solidity ^0.8.20;
contract Swap {
    function swap(uint256 amountIn, uint256 deadline) external returns (uint256 out) {
        require(block.timestamp <= deadline, "expired");
        out = amountIn * 997 / 1000;
    }
}
"#;

    #[test]
    fn silent_on_deadline_bound() {
        let fs = run(DEADLINE_BOUND);
        assert!(
            td(&fs).is_empty(),
            "a coarse `block.timestamp <= deadline` bound must not fire timestamp-dependence: {:?}",
            td(&fs)
        );
    }

    // SILENT — a cooldown stamp. `lastAction = block.timestamp` plus a
    // `block.timestamp - lastAction >= COOLDOWN` ordering gate. The delta exists but
    // is only *compared*, never multiplied into an accumulator. Must NOT fire.
    const COOLDOWN_STAMP: &str = r#"
pragma solidity ^0.8.20;
contract Faucet {
    mapping(address => uint256) public lastClaim;
    uint256 public constant COOLDOWN = 1 days;
    uint256 public totalClaimed;

    function claim() external {
        require(block.timestamp - lastClaim[msg.sender] >= COOLDOWN, "cooldown");
        lastClaim[msg.sender] = block.timestamp;
        totalClaimed += 1 ether;
    }
}
"#;

    #[test]
    fn silent_on_cooldown_stamp() {
        let fs = run(COOLDOWN_STAMP);
        assert!(
            td(&fs).is_empty(),
            "a `lastClaim = block.timestamp` cooldown stamp must not fire timestamp-dependence: {:?}",
            td(&fs)
        );
    }

    // SILENT — linear vesting. `vested = total * (block.timestamp - start) / duration`
    // multiplies a timestamp delta, but assigns it to a plain local return value — it
    // does NOT self-accumulate into a time-weighted-named accumulator. Must NOT fire
    // (this is the over-broadening trap the (2b) accumulator-name gate prevents).
    const LINEAR_VESTING: &str = r#"
pragma solidity ^0.8.20;
contract Vesting {
    uint256 public start;
    uint256 public total;
    uint256 public constant DURATION = 365 days;

    function vestedAmount() public view returns (uint256 vested) {
        uint256 elapsed = block.timestamp - start;
        if (elapsed >= DURATION) return total;
        vested = total * elapsed / DURATION;
    }

    function release() external returns (uint256 amount) {
        amount = vestedAmount();
    }
}
"#;

    #[test]
    fn silent_on_linear_vesting() {
        let fs = run(LINEAR_VESTING);
        assert!(
            td(&fs).is_empty(),
            "linear vesting (delta multiplied but not self-accumulated into a \
             time-weighted accumulator) must not fire timestamp-dependence: {:?}",
            td(&fs)
        );
    }
}
