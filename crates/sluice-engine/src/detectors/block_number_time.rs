//! Block-number-as-time arithmetic (SWC-116 class, time-drift flavor).
//!
//! Flags arithmetic that converts `block.number` into an elapsed *wall-clock
//! time* by multiplying/dividing it against a **hardcoded seconds-per-block**
//! constant — the canonical shapes being `block.number * 12`,
//! `blocksPerDay = 7200`, or `elapsed = (block.number - start) * 13`.
//!
//! Block production time is not a protocol constant: Ethereum's average block
//! interval dropped from ~13s to ~12s at the Merge, and L2s/sidechains differ
//! by orders of magnitude (sub-second to many seconds) and can change again.
//! Any duration *derived* from a block count therefore drifts away from real
//! time, silently breaking vesting cliffs, reward-rate accrual, and deadline
//! logic that assumed a fixed cadence.
//!
//! ## What fires
//! A `Mul`/`Div` (statement or compound-assignment form) where one operand
//! reaches `block.number` and the other is either
//!   (a) a small integer literal in the plausible seconds-per-block band
//!       (~10..=15), or
//!   (b) a per-block / per-day / per-hour cadence constant (by name, e.g.
//!       `BLOCKS_PER_DAY`, `secondsPerBlock`, `blockTime`, or by a literal that
//!       equals a common blocks-per-period count such as 7200), or
//!   (c) *any* constant, when the surrounding function reads `block.number`
//!       in a duration / deadline / reward-rate context (`vesting`, `elapsed`,
//!       `rewardRate`, `deadline`, ...).
//!
//! ## What is deliberately suppressed (precision first)
//!   * `block.number` used purely for **checkpointing / snapshots / ordering**
//!     (`snapshotBlock`, `lastUpdateBlock`, `block.number > startBlock`) — i.e.
//!     never multiplied into a time/duration. Such uses produce no `Mul`/`Div`
//!     match and so never fire.
//!   * Contracts that compute time from **`block.timestamp`** instead — the
//!     correct primitive — are not penalized for also reading `block.number`
//!     for ordering, *unless* a `block.number`→time multiplication is present.
//!
//! Confidence is held low (informational): the pattern is a real correctness
//! hazard but not directly exploitable, and the constant-classification is a
//! heuristic.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{AssignOp, BinOp, Expr, ExprKind};

pub struct BlockNumberTimeDetector;

impl Detector for BlockNumberTimeDetector {
    fn id(&self) -> &'static str {
        "block-number-time"
    }
    fn category(&self) -> Category {
        Category::BlockNumberTime
    }
    fn description(&self) -> &'static str {
        "block.number converted to elapsed time via a hardcoded seconds-per-block constant (time drift)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Cheap reject: the function must read a block-environment value at
            // all. (`block.number` is one; this also avoids walking unrelated
            // bodies.)
            if !f.effects.reads_block_env {
                continue;
            }

            let src = cx.scir.span_text(f.span).to_ascii_lowercase();
            // Does the surrounding code frame this as a *time/duration* concern?
            // Used both to widen case (c) and to lift confidence slightly.
            let time_context = src_has_time_context(&src);

            // Find the first `Mul`/`Div` that turns `block.number` into a
            // duration via a cadence-like constant.
            let mut hit: Option<sluice_ir::Span> = None;
            for s in &f.body {
                s.visit_exprs(&mut |e| {
                    if hit.is_some() {
                        return;
                    }
                    let (lhs, rhs) = match &e.kind {
                        ExprKind::Binary { op: BinOp::Mul | BinOp::Div, lhs, rhs } => {
                            (lhs.as_ref(), rhs.as_ref())
                        }
                        // `x *= 12` / `x /= 7200` where `x` carries block.number.
                        ExprKind::Assign { op: AssignOp::Mul | AssignOp::Div, target, value } => {
                            (target.as_ref(), value.as_ref())
                        }
                        _ => return,
                    };
                    // One side must reach block.number; the *other* side must be
                    // a seconds-per-block-style constant.
                    let l_blk = expr_reaches_block_number(lhs);
                    let r_blk = expr_reaches_block_number(rhs);
                    if l_blk == r_blk {
                        // Neither side (or, implausibly, both) is block.number:
                        // not a block-number→time conversion.
                        return;
                    }
                    let other = if l_blk { rhs } else { lhs };
                    if is_seconds_per_block_operand(other, &src)
                        || (time_context && is_constant_operand(other))
                    {
                        hit = Some(e.span);
                    }
                });
                if hit.is_some() {
                    break;
                }
            }

            let Some(span) = hit else { continue };

            // The pattern is the same whether or not it is framed as time; the
            // explicit time/duration context raises confidence marginally but we
            // keep it informational throughout.
            let confidence = if time_context { 0.45 } else { 0.4 };

            let b = FindingBuilder::new(self.id(), Category::BlockNumberTime)
                .title("Elapsed time computed from block.number with a hardcoded seconds-per-block constant")
                .severity(Severity::Low)
                // Value-flow: block.number (a block-environment source) flows
                // into a duration/time computation via a fixed multiplier.
                .confidence(confidence)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` derives a wall-clock duration from `block.number` using a hardcoded \
                     seconds-per-block constant (e.g. `block.number * 12` or a `blocksPerDay`-style \
                     factor). Block time is not constant — Ethereum moved from ~13s to ~12s at the \
                     Merge and L2s/sidechains differ widely — so any time computed this way drifts \
                     from real time, skewing vesting cliffs, reward accrual, and deadlines. (SWC-116.)",
                    f.name
                ))
                .recommendation(
                    "Measure elapsed time with `block.timestamp` rather than multiplying \
                     `block.number` by an assumed block interval. Reserve `block.number` for \
                     ordering/checkpointing, and make any per-block cadence a governable parameter \
                     rather than a hardcoded constant.",
                );
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

// ------------------------------------------------------------------- helpers

/// `block.number` member access.
fn is_block_number(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Member { base, member }
        if member == "number"
            && matches!(&base.kind, ExprKind::Ident(b) if b == "block"))
}

/// True if `e` (transitively) contains a `block.number` read. This catches the
/// common `(block.number - startBlock) * 12` shape where block.number is nested
/// inside a subtraction on one side of the multiplication.
fn expr_reaches_block_number(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if is_block_number(sub) {
            found = true;
        }
    });
    found
}

/// Parse a numeric literal expression into its integer value, tolerating
/// Solidity digit separators (`7_200`). Returns `None` for non-integer or
/// out-of-range literals.
fn literal_u64(e: &Expr) -> Option<u64> {
    if let ExprKind::Lit(sluice_ir::Lit::Number(n)) = &e.kind {
        // Reject rationals like "1.5" (lowered as "m.f") — a fractional
        // seconds-per-block factor is not the pattern we model.
        if n.contains('.') {
            return None;
        }
        let cleaned: String = n.chars().filter(|c| *c != '_').collect();
        return cleaned.parse::<u64>().ok();
    }
    None
}

/// Is `e` a compile-time constant operand (a numeric literal, or an
/// UPPER_SNAKE-style identifier that conventionally names a `constant`)? Used
/// for the time-context-widened case where the multiplier need not sit in the
/// 10..=15 band.
fn is_constant_operand(e: &Expr) -> bool {
    if literal_u64(e).is_some() {
        return true;
    }
    // A bare CONSTANT_CASE identifier is, by overwhelming convention, a
    // `constant`/`immutable` cadence factor.
    matches!(&e.kind, ExprKind::Ident(name) if is_const_case(name))
}

/// `BLOCKS_PER_DAY`, `SECONDS_PER_BLOCK` — all-caps letters with only digits
/// and underscores allowed alongside (at least one letter required).
fn is_const_case(name: &str) -> bool {
    let has_alpha = name.chars().any(|c| c.is_ascii_alphabetic());
    has_alpha
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// True if `other` is the seconds-per-block constant in a block.number→time
/// conversion: a small integer literal in the plausible block-interval band, a
/// common blocks-per-period literal, a cadence-named identifier, or a literal
/// written with an explicit time unit (`13 seconds`).
fn is_seconds_per_block_operand(e: &Expr, src: &str) -> bool {
    // (a) A small integer literal in the realistic seconds-per-block band.
    //     Ethereum has been 12-15s historically; we accept 10..=15.
    if let Some(v) = literal_u64(e) {
        if (10..=15).contains(&v) {
            return true;
        }
        // (b-lit) A literal equal to a common blocks-per-period count (assuming a
        //         ~12s block: 7200/day, 300/hour, 5/minute, 50400/week). These
        //         are the values a `blocksPerDay`-style constant takes.
        if is_blocks_per_period_count(v) {
            return true;
        }
        // (c-unit) The literal carries an explicit time-unit suffix that the IR
        //          drops during lowering (`* 13 seconds`). Recover it from the
        //          function source by checking what immediately follows the
        //          literal's digits.
        if literal_has_time_unit_suffix(src, n_text(e)) {
            return true;
        }
    }
    // (b-name) A cadence-named identifier or member (`blocksPerDay`,
    //          `secondsPerBlock`, `BLOCK_TIME`, `self.blocksPerHour`).
    if let Some(name) = e.simple_name() {
        if name_is_cadence(name) {
            return true;
        }
    }
    false
}

/// Common blocks-per-period counts under a ~12s block assumption, the values a
/// hardcoded `blocksPerX` constant typically takes.
fn is_blocks_per_period_count(v: u64) -> bool {
    matches!(
        v,
        // per minute (12s -> 5), per hour (300), per day (7200), per week
        // (50400), ~per year (2628000). The round 12s-based figures dominate.
        5 | 300 | 7200 | 50400 | 2628000
    )
}

/// Identifier/member name that denotes a per-block / per-period cadence factor.
fn name_is_cadence(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // Require a "block" + period coupling so we don't fire on a generic `rate`.
    let blocks_per = l.contains("blockper") || l.contains("blocksper");
    let per_block = l.contains("perblock");
    let block_time = l.contains("blocktime") || l.contains("blockinterval") || l.contains("blockduration");
    let secs_per_block = l.contains("secondsperblock") || l.contains("secperblock");
    blocks_per || per_block || block_time || secs_per_block
}

/// Function source mentions a time / duration / deadline / reward-rate concept,
/// the contexts in which converting block.number to time is the bug.
fn src_has_time_context(src: &str) -> bool {
    [
        "vest", "vesting", "duration", "elapsed", "deadline", "expir", "rewardrate", "reward rate",
        "rewardspersecond", "rewardpersecond", "secondselapsed", "timeelapsed", "cliff",
        "perday", "per day", "perhour", "per hour", "accru", "secondssince", "timestamp",
    ]
    .iter()
    .any(|k| src.contains(k))
}

/// The raw (lowercased) digit text of a numeric literal, or `""`.
fn n_text(e: &Expr) -> &str {
    match &e.kind {
        ExprKind::Lit(sluice_ir::Lit::Number(n)) => n.as_str(),
        _ => "",
    }
}

/// Best-effort: does the numeric literal `num` appear in the (lowercased)
/// function source `src` immediately followed by a Solidity time-unit keyword
/// (`seconds`/`minutes`/`hours`/`days`/`weeks`)? The unit suffix is dropped by
/// IR lowering, so we recover it textually. We require the unit to follow the
/// digits with only optional whitespace between (a tight adjacency check) to
/// avoid matching an unrelated keyword elsewhere on the line. A miss here only
/// drops the rare non-band unit-suffix case; other paths still apply.
fn literal_has_time_unit_suffix(src: &str, num: &str) -> bool {
    if num.is_empty() {
        return false;
    }
    let num = num.to_ascii_lowercase();
    let bytes = src.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(&num) {
        let start = from + rel;
        let after = start + num.len();
        // Standalone number: not preceded by an alnum/underscore (else it's the
        // tail of a larger identifier or numeral).
        let prev_ok = start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        if prev_ok {
            // Skip whitespace, then test for a unit keyword at the cursor.
            let mut j = after;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\n' || bytes[j] == b'\r') {
                j += 1;
            }
            let rest = &src[j..];
            if rest.starts_with("seconds")
                || rest.starts_with("minutes")
                || rest.starts_with("hours")
                || rest.starts_with("days")
                || rest.starts_with("weeks")
            {
                return true;
            }
        }
        from = after;
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vesting math that turns block.number into seconds via a hardcoded 12s
    // block interval — the textbook block-number-as-time drift bug.
    const VULN: &str = r#"
pragma solidity ^0.8.20;
contract Vesting {
    uint256 public startBlock;
    uint256 public totalAllocation;
    uint256 public constant SECONDS_PER_BLOCK = 12;
    uint256 public constant VESTING_DURATION = 365 days;

    function vestedAmount() public view returns (uint256) {
        // BUG: elapsed seconds derived from block count * assumed 12s/block.
        uint256 elapsed = (block.number - startBlock) * 12;
        if (elapsed >= VESTING_DURATION) return totalAllocation;
        return totalAllocation * elapsed / VESTING_DURATION;
    }
}
"#;

    // Correct version: elapsed time comes from block.timestamp; block.number is
    // read only to record an ordering checkpoint, never multiplied into a time.
    const SAFE: &str = r#"
pragma solidity ^0.8.20;
contract Vesting {
    uint256 public startTime;
    uint256 public startBlock;
    uint256 public totalAllocation;
    uint256 public constant VESTING_DURATION = 365 days;

    function checkpoint() external {
        // block.number used purely for ordering/snapshot — not converted to time.
        startBlock = block.number;
        startTime = block.timestamp;
    }

    function vestedAmount() public view returns (uint256) {
        uint256 elapsed = block.timestamp - startTime;
        if (elapsed >= VESTING_DURATION) return totalAllocation;
        return totalAllocation * elapsed / VESTING_DURATION;
    }
}
"#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "block-number-time"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "block-number-time"));
    }
}
