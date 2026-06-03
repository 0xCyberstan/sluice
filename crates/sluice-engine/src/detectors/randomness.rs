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
//! (2) **Timestamp dependence** — `block.timestamp` used as a *direct equality
//! gate* (`== ` / `!=`) on a value-bearing path. A ~12s validator nudge defeats
//! an exact-timestamp gate, unlike a coarse `block.timestamp <= deadline` bound
//! (which we deliberately do *not* flag).
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
}
