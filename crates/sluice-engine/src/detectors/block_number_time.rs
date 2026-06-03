//! Block-number-as-time arithmetic (SWC-116 class, time-drift flavor).
//!
//! Flags code that uses `block.number` as a *wall-clock time / duration* measure
//! — i.e. that assumes a fixed block interval. Block production time is not a
//! protocol constant: Ethereum's average interval dropped from ~13s to ~12s at
//! the Merge, and L2s differ by orders of magnitude *and* change semantics —
//! notably **Arbitrum/Optimism `block.number` returns the L1 block height**, not
//! a local per-block tick, so any duration, delay, or deadline counted in
//! `block.number` breaks when the contract is deployed there. Any time derived
//! from a block count therefore drifts from real time, silently breaking vesting
//! cliffs, reward accrual, holding-period gates, and same-block delay guards.
//!
//! ## What fires
//! Three shapes, each requiring a *direct* `block.number` read in the function:
//!
//!   1. **seconds-per-block conversion** — a `Mul`/`Div` (statement or
//!      compound-assignment form) where one operand reaches `block.number` and
//!      the other is (a) a small integer literal in the plausible
//!      seconds-per-block band (~10..=15), (b) a per-block / per-day cadence
//!      constant (by name, e.g. `BLOCKS_PER_DAY`, `secondsPerBlock`, or by a
//!      literal equal to a common blocks-per-period count such as 7200), or
//!      (c) *any* constant when the function is framed as a duration/deadline.
//!
//!   2. **block.number-as-time-anchor** — `block.number << K` / `>> K` whose
//!      shifted operand is `block.number` and where the function/constant frames
//!      it as a *time* value (the Frankencoin `anchorTime()` idiom: a sub-block
//!      "time" anchor packed from the block number, later differenced to gate a
//!      90-day holding period — which silently mis-measures on L2s).
//!
//!   3. **block.number duration / delay / deadline gate** — `block.number ± X`
//!      stored into, or compared against, an lvalue whose name denotes a
//!      *deadline / delay / cooldown / expiry / elapsed* concept (the Tigris
//!      `_checkDelay` idiom: `delay = block.number + blockDelay; if (block.number
//!      < delay) revert;` — an anti-same-block guard counted in blocks that
//!      returns the L1 height on Arbitrum/Optimism).
//!
//! ## What is deliberately suppressed (precision first)
//!   * `block.number` used purely for **checkpointing / snapshots / ordering /
//!     block counting** (`snapshotBlock`, `fromBlock`, `lastBlock`, `blocks =
//!     block.number - lastBlock`, `block.number >= snapshotBlock`). Shapes 2–3
//!     fire only when the *target / compared* name is a duration/deadline word
//!     and is **not** a snapshot/ordering/block-count word, so these stay silent.
//!   * `block.number` mixed into a **hash / nonce / id** (`keccak256(abi.encode(
//!     ..., block.number))`) — never an arithmetic time measure, never matched.
//!   * Contracts that compute time from **`block.timestamp`** instead are not
//!     penalized for also reading `block.number` for ordering.
//!
//! Confidence is held low (informational): the pattern is a real correctness
//! hazard but not directly exploitable, and the classification is heuristic.

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

            let src = cx.source_text(f.span);
            // Does the surrounding code frame this as a *time/duration* concern?
            // Used both to widen the seconds-per-block case (c) and to lift the
            // confidence of a shift-as-time anchor slightly.
            let time_context = src_has_time_context(&src);

            // Try the shapes in order of specificity; the first match wins (we
            // report one finding per function). Shape 1 (seconds-per-block)
            // first, then the L2-unsafe duration shapes 2 (shift anchor) and 3
            // (delay/deadline gate).
            let hit = scan_seconds_per_block(f, &src, time_context)
                .or_else(|| scan_shift_anchor(f, &f.name, time_context))
                .or_else(|| scan_deadline_gate(f));

            let Some(Hit { span, kind }) = hit else { continue };

            // All three shapes are the same correctness hazard; we keep the
            // finding informational throughout. The seconds-per-block and
            // shift-anchor shapes gain a marginal lift when the surrounding code
            // explicitly frames itself as time; the deadline-gate shape is
            // already name-gated, so it carries its own (slightly higher)
            // confidence without needing the textual frame.
            let confidence = match kind {
                HitKind::SecondsPerBlock | HitKind::ShiftAnchor if time_context => 0.45,
                HitKind::DeadlineGate => 0.45,
                _ => 0.4,
            };

            let (title, message) = match kind {
                HitKind::SecondsPerBlock => (
                    "Elapsed time computed from block.number with a hardcoded seconds-per-block constant",
                    format!(
                        "`{}` derives a wall-clock duration from `block.number` using a hardcoded \
                         seconds-per-block constant (e.g. `block.number * 12` or a `blocksPerDay`-style \
                         factor). Block time is not constant — Ethereum moved from ~13s to ~12s at the \
                         Merge and L2s/sidechains differ widely — so any time computed this way drifts \
                         from real time, skewing vesting cliffs, reward accrual, and deadlines. (SWC-116.)",
                        f.name
                    ),
                ),
                HitKind::ShiftAnchor => (
                    "block.number used as a time anchor (mis-measures elapsed time on L2s)",
                    format!(
                        "`{}` packs `block.number` into a time-anchor value (`block.number << K`) and \
                         treats the difference between two such anchors as elapsed time — e.g. to gate \
                         a fixed holding/vesting period. This assumes a constant block interval: on \
                         Arbitrum/Optimism `block.number` reflects the L1 height rather than a local \
                         per-block tick, and even on L1 the interval is not fixed, so the measured \
                         duration drifts from real time and the period gate (e.g. a 90-day minimum) \
                         is wrong. (SWC-116.)",
                        f.name
                    ),
                ),
                HitKind::DeadlineGate => (
                    "block.number used as a delay/deadline (breaks on Arbitrum/Optimism)",
                    format!(
                        "`{}` derives a delay/deadline by counting in `block.number` \
                         (`deadline = block.number + N; if (block.number < deadline) revert;`). This \
                         assumes a fixed block interval: on Arbitrum/Optimism `block.number` returns \
                         the L1 block height, not a local per-block tick, so a block-counted delay can \
                         elapse far faster or slower than intended — defeating same-block / cooldown \
                         guards — and even on L1 the interval is not constant. (SWC-116.)",
                        f.name
                    ),
                ),
            };

            let b = FindingBuilder::new(self.id(), Category::BlockNumberTime)
                .title(title)
                .severity(Severity::Low)
                // Value-flow: block.number (a block-environment source) flows
                // into a duration / time / deadline computation.
                .confidence(confidence)
                .dimension(Dimension::ValueFlow)
                .message(message)
                .recommendation(
                    "Measure elapsed time, holding periods, and delays with `block.timestamp` rather \
                     than `block.number`. Reserve `block.number` for ordering/checkpointing, and note \
                     that on Arbitrum/Optimism `block.number` is the L1 height — use `block.timestamp` \
                     (or the chain's documented block-number source) for any duration that must hold \
                     across chains.",
                );
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

/// Which of the three block.number-as-time shapes matched, so the finding can
/// describe the specific hazard.
#[derive(Clone, Copy)]
enum HitKind {
    /// `block.number * 12` / `blocksPerDay`-style cadence conversion.
    SecondsPerBlock,
    /// `block.number << K` framed as a time anchor (Frankencoin `anchorTime`).
    ShiftAnchor,
    /// `block.number ± N` as a delay/deadline gate (Tigris `_checkDelay`).
    DeadlineGate,
}

struct Hit {
    span: sluice_ir::Span,
    kind: HitKind,
}

/// Shape 1: the first `Mul`/`Div` that turns `block.number` into a duration via
/// a cadence-like constant. (Original behavior — unchanged.)
fn scan_seconds_per_block(
    f: &sluice_ir::Function,
    src: &str,
    time_context: bool,
) -> Option<Hit> {
    let mut hit = None;
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
            // One side must reach block.number; the *other* side must be a
            // seconds-per-block-style constant.
            let l_blk = expr_reaches_block_number(lhs);
            let r_blk = expr_reaches_block_number(rhs);
            if l_blk == r_blk {
                // Neither side (or, implausibly, both) is block.number: not a
                // block-number→time conversion.
                return;
            }
            let other = if l_blk { rhs } else { lhs };
            if is_seconds_per_block_operand(other, src)
                || (time_context && is_constant_operand(other))
            {
                hit = Some(Hit { span: e.span, kind: HitKind::SecondsPerBlock });
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Shape 2: `block.number << K` / `>> K` (statement or compound-assignment form)
/// where the shifted operand reaches `block.number` and the surrounding code
/// frames the result as a *time* value.
///
/// The shift of `block.number` is the Frankencoin `anchorTime()` idiom — a
/// "block time with extra resolution bits" — and is the source of the
/// holding-period / vote-weight measure that breaks on L2s. Bit-packing
/// `block.number` for non-time reasons is rare; we still require an explicit
/// time/anchor frame (the function name, the shift-amount constant name, or the
/// surrounding source) so a packing shift without time semantics stays silent.
fn scan_shift_anchor(
    f: &sluice_ir::Function,
    fn_name: &str,
    time_context: bool,
) -> Option<Hit> {
    let framed_as_time = time_context || name_is_time_anchor(fn_name);
    let mut hit = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let (shifted, amount) = match &e.kind {
                ExprKind::Binary { op: BinOp::Shl | BinOp::Shr, lhs, rhs } => {
                    (lhs.as_ref(), rhs.as_ref())
                }
                ExprKind::Assign { op: AssignOp::Shl | AssignOp::Shr, target, value } => {
                    (target.as_ref(), value.as_ref())
                }
                _ => return,
            };
            // The block.number must be the *shifted* operand (the value), not the
            // shift amount.
            if !expr_reaches_block_number(shifted) {
                return;
            }
            // Time frame from the function/source, or from the shift-amount name
            // itself (`BLOCK_TIME_RESOLUTION_BITS`).
            let amount_named_time = amount.simple_name().is_some_and(name_is_time_anchor);
            if framed_as_time || amount_named_time {
                hit = Some(Hit { span: e.span, kind: HitKind::ShiftAnchor });
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Shape 3: `block.number` used as a *delay / deadline* counted in blocks — the
/// Tigris `_checkDelay` idiom. Fires when either
///   * `block.number ± X` is **assigned** to an lvalue whose name is a
///     deadline/delay/cooldown/expiry word, or
///   * `block.number` is **compared** (`<`, `<=`, `>`, `>=`) against an lvalue
///     whose name is such a word.
///
/// The name must be a duration/deadline word **and not** a snapshot / ordering /
/// block-count word (`snapshotBlock`, `fromBlock`, `lastBlock`, `blocks`). That
/// keeps a snapshot checkpoint (`snapshotBlock = block.number + VOTING_DELAY;
/// require(block.number >= snapshotBlock)`) and a block-rate window
/// (`blocks = block.number - lastBlock`) silent while catching a true
/// block-counted deadline.
fn scan_deadline_gate(f: &sluice_ir::Function) -> Option<Hit> {
    let mut hit = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            match &e.kind {
                // deadline = block.number ± N;
                ExprKind::Assign { op: AssignOp::Assign, target, value } => {
                    let is_offset = matches!(
                        &value.kind,
                        ExprKind::Binary { op: BinOp::Add | BinOp::Sub, .. }
                    );
                    if is_offset
                        && expr_reaches_block_number(value)
                        && target.simple_name().is_some_and(name_is_deadline)
                    {
                        hit = Some(Hit { span: e.span, kind: HitKind::DeadlineGate });
                    }
                }
                // if (block.number < deadline) ...  /  block.number >= deadline
                ExprKind::Binary { op, lhs, rhs } if op.is_ordering() => {
                    let l_blk = expr_reaches_block_number(lhs);
                    let r_blk = expr_reaches_block_number(rhs);
                    if l_blk == r_blk {
                        return;
                    }
                    let other = if l_blk { rhs } else { lhs };
                    if other.simple_name().is_some_and(name_is_deadline) {
                        hit = Some(Hit { span: e.span, kind: HitKind::DeadlineGate });
                    }
                }
                _ => {}
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
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

/// A name that frames `block.number` as a *time* value — `anchorTime`,
/// `blockTime`, `BLOCK_TIME_RESOLUTION_BITS`, `timeAnchor`. Used only to confirm
/// the (already rare) `block.number << K` shift-anchor shape, so a substring
/// match on `time`/`anchor` is precise enough: a bare bit-packing shift of
/// `block.number` without any time framing stays silent.
fn name_is_time_anchor(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("time") || l.contains("anchor")
}

/// A name that denotes a *delay / deadline / cooldown / expiry* — the target an
/// `block.number ± N` offset is stored into, or the bound `block.number` is
/// compared against, in a block-counted deadline gate.
///
/// Crucially this **excludes** any snapshot / checkpoint / ordering / block-count
/// name (anything containing `block`, `snapshot`, `checkpoint`, or `ckpt`): a
/// `snapshotBlock`, `fromBlock`, `lastBlock`, or `blocks` is a checkpoint or a
/// block-count window, not a wall-clock deadline, and must not fire. Tigris's
/// `delay` field passes (no excluded token); its `blockDelay` *addend* is never
/// tested here (we key on the assignment target / compared operand, not the
/// offset).
fn name_is_deadline(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // Ordering / snapshot / block-count names are explicitly not deadlines.
    if l.contains("block") || l.contains("snapshot") || l.contains("checkpoint") || l.contains("ckpt")
    {
        return false;
    }
    l.contains("delay")
        || l.contains("deadline")
        || l.contains("cooldown")
        || l.contains("expir")
        || l.contains("waituntil")
        || l.contains("notbefore")
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

    // Shape 2 — block.number packed into a "time anchor" via a shift, then the
    // difference between two anchors gates a fixed holding period. This is the
    // Frankencoin `Equity.anchorTime()` idiom (C4 M-04): the holding-duration
    // gate mis-measures on L2s where block.number is the L1 height.
    const SHIFT_ANCHOR: &str = r#"
pragma solidity ^0.8.20;
contract Equity {
    uint8 private constant BLOCK_TIME_RESOLUTION_BITS = 24;
    uint256 public constant MIN_HOLDING_DURATION = 90 * 7200 << BLOCK_TIME_RESOLUTION_BITS;
    mapping(address => uint64) private voteAnchor;

    function anchorTime() internal view returns (uint64) {
        return uint64(block.number << BLOCK_TIME_RESOLUTION_BITS);
    }

    function canRedeem(address owner) public view returns (bool) {
        return anchorTime() - voteAnchor[owner] >= MIN_HOLDING_DURATION;
    }
}
"#;

    // Shape 3 — block.number used as a same-block delay gate: a deadline counted
    // in blocks (`delay = block.number + blockDelay; if (block.number < delay)
    // revert;`). This is the Tigris `Trading._checkDelay` idiom (C4 M-15): the
    // guard returns the L1 height on Arbitrum/Optimism.
    const DEADLINE_GATE: &str = r#"
pragma solidity ^0.8.0;
contract Trading {
    struct Delay { uint delay; bool actionType; }
    mapping(uint => Delay) public blockDelayPassed;
    uint public blockDelay;

    function _checkDelay(uint _id, bool _type) internal {
        Delay memory _delay = blockDelayPassed[_id];
        if (_delay.actionType == _type) {
            blockDelayPassed[_id].delay = block.number + blockDelay;
        } else {
            if (block.number < _delay.delay) revert("0"); // Wait
            blockDelayPassed[_id].delay = block.number + blockDelay;
            blockDelayPassed[_id].actionType = _type;
        }
    }
}
"#;

    // Silent — block.number is an ingredient of a hash/nonce/id, never an
    // arithmetic time/duration measure.
    const NONCE_ID: &str = r#"
pragma solidity ^0.8.20;
contract Governance {
    struct Bip { address target; bytes data; }
    mapping(uint256 => Bip) public bips;

    function propose(address target, bytes calldata data) external returns (uint256 id) {
        id = uint256(keccak256(abi.encode(target, data, block.number)));
        bips[id].target = target;
        bips[id].data = data;
    }
}
"#;

    // Silent — block.number is stored as an ordering snapshot (`snapshotBlock`)
    // and only ever compared for ordering / passed to a historical lookup; this
    // must not be confused with a block-counted deadline.
    const SNAPSHOT_ORDERING: &str = r#"
pragma solidity ^0.8.20;
contract Governor {
    uint256 public constant VOTING_DELAY = 1;
    struct Proposal { uint256 snapshotBlock; }
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    function propose() external returns (uint256 id) {
        id = ++proposalCount;
        proposals[id].snapshotBlock = block.number + VOTING_DELAY;
    }

    function castVote(uint256 id) external view returns (bool) {
        return block.number >= proposals[id].snapshotBlock;
    }
}
"#;

    fn bnt(fs: &[sluice_findings::Finding]) -> Option<&sluice_findings::Finding> {
        fs.iter().find(|f| f.detector == "block-number-time")
    }

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(bnt(&fs).is_some(), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(bnt(&fs).is_none());
    }

    // block.number-as-duration (shift anchor) fires — Frankencoin M-04 class.
    #[test]
    fn fires_on_shift_anchor() {
        let fs = run(SHIFT_ANCHOR);
        let f = bnt(&fs).unwrap_or_else(|| panic!("expected a hit, got {:?}", fs));
        assert!(f.message.contains("time anchor") || f.title.contains("time anchor"), "{:?}", f);
    }

    // block.number-as-duration (delay/deadline gate) fires — Tigris M-15 class.
    #[test]
    fn fires_on_deadline_gate() {
        let fs = run(DEADLINE_GATE);
        let f = bnt(&fs).unwrap_or_else(|| panic!("expected a hit, got {:?}", fs));
        assert!(
            f.message.contains("delay/deadline") || f.title.contains("delay/deadline"),
            "{:?}",
            f
        );
    }

    // block.number-as-nonce stays silent (precision guard).
    #[test]
    fn silent_on_nonce_id() {
        let fs = run(NONCE_ID);
        assert!(bnt(&fs).is_none(), "nonce/id use must not fire: {:?}", fs);
    }

    // block.number ordering snapshot stays silent (precision guard): a
    // `snapshotBlock = block.number + DELAY` checkpoint and `block.number >=
    // snapshotBlock` ordering check are not a block-counted deadline.
    #[test]
    fn silent_on_snapshot_ordering() {
        let fs = run(SNAPSHOT_ORDERING);
        assert!(bnt(&fs).is_none(), "snapshot/ordering use must not fire: {:?}", fs);
    }
}
