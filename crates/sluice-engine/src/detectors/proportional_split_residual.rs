//! Proportional-split residual hazard: a function splits one amount across two
//! or more buckets with floor division and then force-assigns the leftover (the
//! rounding dust) to a single bucket via a `amount - a - b` residual.
//!
//! The canonical shape — the **Symbiotic `Vault.onSlash`** slashing split. In
//! the real contract the proportional shares are taken with OpenZeppelin's
//! `Math.mulDiv` (a *floor* `a * b / denom`, written as a `using Math for uint256`
//! bound call `slashedAmount.mulDiv(stake, total)`), and the residual is forced
//! onto the last bucket:
//! ```solidity
//! function onSlash(uint256 amount, uint48 captureTimestamp) external {
//!     uint256 slashableStake        = activeStake_ + withdrawals_ + nextWithdrawals;
//!     uint256 slashedAmount         = Math.min(amount, slashableStake);
//!     uint256 activeSlashed         = slashedAmount.mulDiv(activeStake_, slashableStake);     // floor
//!     uint256 nextWithdrawalsSlashed = slashedAmount.mulDiv(nextWithdrawals, slashableStake); // floor
//!     // the two floors lose dust; force the remainder onto ONE bucket:
//!     uint256 withdrawalsSlashed    = slashedAmount - activeSlashed - nextWithdrawalsSlashed;
//!     withdrawals[currentEpoch_]    = withdrawals_ - withdrawalsSlashed;   // <- residual sink
//! }
//! ```
//! The equivalent written with the bare `/` operator is the same bug:
//! ```solidity
//!     uint256 activeSlashed   = amount * activeStake   / totalStake;   // floor
//!     uint256 withdrawSlashed = amount * withdrawals   / totalStake;   // floor
//!     uint256 nextSlashed     = amount - activeSlashed - withdrawSlashed;
//!     nextEpochWithdrawals -= nextSlashed;        // <- residual sink
//! ```
//! Each `a * w / total` truncates toward zero, so `a + b < amount` by up to two
//! wei. The code then *forces* `r = amount - a - b` (strictly larger than the
//! bucket's true proportional share) onto one chosen bucket. That bucket
//! systematically absorbs all the rounding dust, and because `a`/`b` move with
//! attacker-chosen `amount`/stake splits, the size of the residual is
//! attacker-influenceable — one party is over-slashed (or under-credited) while
//! another is favored. The same pattern recurs in fee splitters, reward
//! distributors, and tranche waterfalls that "assign the remainder to the last
//! bucket".
//!
//! The fix is not a post-hoc `require(a + b + r == amount)` — that invariant
//! holds *by construction* of the residual and so is meaningless here. The fix
//! is to round the proportional buckets in a consistent, fair direction (a
//! `mulDivUp`/`ceilDiv` helper, or a pro-rata remainder distribution) so no
//! single bucket silently eats the dust. We therefore suppress only when such a
//! rounding-mode helper is used for the buckets.
//!
//! Precision anchors (all required, so this stays quiet on ordinary arithmetic):
//!   * the function is externally reachable and state-mutating;
//!   * its body contains **>= 2 floor proportional splits** — either the bare
//!     integer-division operator (`a * w / total`) or a *floor* `mulDiv`-family
//!     bound/library call (`x.mulDiv(w, total)` / `Math.mulDiv(x, w, total)` /
//!     `mulDivDown`), which is how the real Symbiotic vault writes the split;
//!   * a later assignment or `return` computes a value that is a chain of **>= 2
//!     subtractions** from a common quantity (`x - a - b`, the forced residual)
//!     and that value flows into a bucket state variable / mapping (an `Assign`
//!     to storage, a `-=`/`+=` on a bucket, or a `return`);
//!   * no `mulDivUp`/`mulDivCeil`/`ceilDiv`/`Rounding.Up`/`+ denom - 1` helper
//!     pins the bucket rounding direction (a 4-arg `mulDiv(.., Rounding.Up)` or a
//!     `mulDivUp` is *not* counted as a floor split and also suppresses).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{AssignOp, BinOp, Expr, ExprKind, Function, Span, StmtKind};

use super::prelude::*;

pub struct ProportionalSplitResidualDetector;

impl Detector for ProportionalSplitResidualDetector {
    fn id(&self) -> &'static str {
        "proportional-split-residual"
    }
    fn category(&self) -> Category {
        Category::ProportionalSplitResidual
    }
    fn description(&self) -> &'static str {
        "Amount split across >=2 floor-divided buckets, then the rounding remainder force-assigned to one bucket (Symbiotic onSlash-class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
                continue;
            }

            // (1) The multi-bucket split: at least two *floor* proportional
            // shares in the body — either the bare `/` operator or a floor
            // `mulDiv`-family call (the real Symbiotic vault uses `Math.mulDiv`,
            // a bound `x.mulDiv(w, total)`). A single share is an ordinary ratio,
            // not a split. Ceil-rounded shares are deliberately not counted here.
            if count_floor_splits(f) < 2 {
                continue;
            }

            // (2) A forced residual: an assignment/return whose value subtracts
            // two or more previously-computed parts from a common quantity
            // (`amount - a - b`), and whose destination is a bucket (a storage
            // write, or a `return`). Returns the residual expression's span.
            let Some(span) = find_residual_sink(f) else {
                continue;
            };

            // (3) Suppress only when the buckets pin a fair rounding direction —
            // a `mulDivUp` / `ceilDiv` / `Rounding.Up` helper. A post-hoc
            // `require(a + b + r == amount)` does NOT suppress: that equality is
            // true by construction of the residual and does not fix the bias.
            if uses_rounding_helper(cx, f) {
                continue;
            }

            let b = report!(self, Category::ProportionalSplitResidual,
                title = "Proportional split forces rounding remainder onto one bucket",
                severity = Severity::Medium,
                confidence = 0.45,
                dimensions = [Dimension::Invariant],
                message = format!(
                    "`{}` splits an amount across two or more buckets with integer (floor) division \
                     and then force-assigns the leftover via a `total - a - b` residual to a single \
                     bucket. Because each `amount * weight / total` truncates toward zero, the summed \
                     buckets fall short of the original amount, and the residual sink silently absorbs \
                     all of that rounding dust — systematically over-allocating one bucket. As the \
                     bucket weights and `amount` are caller/stake-influenced, the size of the residual \
                     is attacker-steerable, so one party is consistently over-slashed/under-credited \
                     while another is favored (the Symbiotic `Vault.onSlash` split class). A trailing \
                     `require(a + b + r == amount)` does not fix this — that equality holds by \
                     construction of the residual.",
                    f.name
                ),
                recommendation =
                    "Round the proportional buckets in a single, fair direction with an explicit \
                     rounding-mode helper (`mulDivUp` / `ceilDiv` / OpenZeppelin \
                     `Math.mulDiv(.., Rounding.Up)`), or distribute the remainder pro-rata across all \
                     buckets, instead of dumping the entire floor-division dust onto one chosen bucket.",
            );
            out.push(finish_at(cx, b, f.id, span));
        }
        out
    }
}

/// Count *floor* proportional-share computations in the body — the multi-bucket
/// split signal: two or more truncating shares of one quantity. Two forms count:
///   * the bare integer-division operator `BinOp::Div` (`a * w / total`); and
///   * a *floor* `mulDiv`-family call — OpenZeppelin's `Math.mulDiv(x, w, total)`
///     or the `using Math for uint256` bound form `x.mulDiv(w, total)`, plus the
///     `mulDivDown` spelling. This is exactly how the real Symbiotic
///     `Vault.onSlash` writes its split, so it must count or the detector never
///     fires on the true target.
///
/// Ceil/round-up shares are deliberately **not** counted: a 4-argument
/// `mulDiv(.., Rounding.Up)`, or `mulDivUp`/`mulDivCeil`/`ceilDiv`/`divUp`, pin a
/// fair rounding direction and are handled (as a suppressor) by
/// `uses_rounding_helper`.
fn count_floor_splits(f: &Function) -> usize {
    let mut n = 0usize;
    for s in &f.body {
        s.visit_exprs(&mut |e| match &e.kind {
            ExprKind::Binary { op: BinOp::Div, .. } => n += 1,
            ExprKind::Call(c) if is_floor_muldiv_call(c) => n += 1,
            _ => {}
        });
    }
    n
}

/// True if `c` is a *floor* `mulDiv`-family call. We key on the resolved
/// `func_name` (so both `Math.mulDiv(x, w, t)` and the bound `x.mulDiv(w, t)`
/// match — the parser records `func_name = Some("mulDiv")` for the member call,
/// and `Some("mulDiv")` for the library call too). A trailing rounding-mode
/// argument (a 4th positional arg to `mulDiv`, e.g. `mulDiv(x, w, t, Rounding.Up)`)
/// or an explicitly-up spelling (`mulDivUp`/`mulDivCeil`/`mulDivRoundingUp`)
/// means the rounding is pinned, so it is **not** a floor split.
fn is_floor_muldiv_call(c: &sluice_ir::Call) -> bool {
    let Some(name) = c.func_name.as_deref() else {
        return false;
    };
    let lname = name.to_ascii_lowercase();
    // An up/ceil-rounded variant is not a floor split.
    if lname.contains("up") || lname.contains("ceil") {
        return false;
    }
    // Recognize `mulDiv` and its explicit floor spelling `mulDivDown`.
    if lname != "muldiv" && lname != "muldivdown" {
        return false;
    }
    // Plain `mulDiv` floors with 2 (bound: receiver + 2 args) or 3 positional
    // args. A 4th positional arg is a `Rounding` mode -> not a floor split.
    let positional = c.args.len();
    let with_receiver = positional + usize::from(c.receiver.is_some());
    // Bound call `x.mulDiv(w, t)` => receiver + 2 args = 3 operands (floor).
    // Library call `Math.mulDiv(x, w, t)` => 3 args, no extra receiver (floor).
    // `mulDiv(x, w, t, Rounding.Up)` => 4 args (rounded) — already excluded by
    // the "up"/"ceil" name check only if spelled in the name, so also bail when
    // the operand count signals a rounding mode.
    with_receiver <= 3 && positional <= 3
}

/// Find a forced-residual sink: an assignment (incl. `+=`/`-=`) or a `return`
/// whose value is a `quantity - a - b` chain (>= 2 subtractions from a common
/// root) flowing into a bucket. Returns the span of the residual expression.
///
/// The shape `amount - a - b` parses left-associatively as
/// `Sub(Sub(amount, a), b)`: a `Sub` node whose left spine contains another
/// `Sub`. We require **two** subtractions so a benign single `x - fee` does not
/// trip the gate — the residual must mirror a >= 2-way split.
fn find_residual_sink(f: &Function) -> Option<Span> {
    let mut hit: Option<Span> = None;
    for s in &f.body {
        s.visit(&mut |st| {
            if hit.is_some() {
                return;
            }
            match &st.kind {
                // `bucket = a - x - y;` / `bucket -= a - x - y;` (assignment in
                // expression position) and the same inside an `Assign` expr.
                StmtKind::Expr(e) => {
                    scan_expr_for_residual(e, &mut hit);
                }
                // `uint256 r = amount - a - b;` — a residual bound to a local
                // that is (by the >=2-div + write gate) destined for a bucket.
                StmtKind::VarDecl { init: Some(e), .. } => {
                    if let Some(sp) = residual_span(e) {
                        hit = Some(sp);
                    }
                }
                // `return amount - a - b;`
                StmtKind::Return(Some(e)) => {
                    if let Some(sp) = residual_span(e) {
                        hit = Some(sp);
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

/// Walk an expression statement looking for an `Assign` whose RHS is a residual
/// chain (the value being written to a bucket).
fn scan_expr_for_residual(e: &Expr, hit: &mut Option<Span>) {
    e.visit(&mut |sub| {
        if hit.is_some() {
            return;
        }
        if let ExprKind::Assign { op, value, .. } = &sub.kind {
            // Plain `=`, or `-=`/`+=` onto a bucket: all are the residual being
            // committed to a single bucket.
            if matches!(op, AssignOp::Assign | AssignOp::Sub | AssignOp::Add) {
                if let Some(sp) = residual_span(value) {
                    *hit = Some(sp);
                }
            }
        }
    });
}

/// If `e` (after peeling enclosing casts/parens-as-calls) is a `quantity - a - b`
/// chain with **two or more** subtractions sharing a common left root, return the
/// span of the outermost `Sub`. Otherwise `None`.
fn residual_span(e: &Expr) -> Option<Span> {
    let e = peel_casts(e);
    if let ExprKind::Binary { op: BinOp::Sub, .. } = &e.kind {
        if count_sub_spine(e) >= 2 {
            return Some(e.span);
        }
    }
    None
}

/// Count the chained subtractions along the left spine of a `Sub` node:
/// `((x - a) - b) - c` => 3. A non-`Sub` node contributes 0. This is what
/// distinguishes a >= 2-bucket residual (`amount - a - b`) from an innocuous
/// single difference (`amount - fee`).
fn count_sub_spine(e: &Expr) -> usize {
    match &e.kind {
        ExprKind::Binary { op: BinOp::Sub, lhs, .. } => 1 + count_sub_spine(lhs),
        _ => 0,
    }
}

/// Suppress when the function pins a fair, consistent rounding direction for the
/// proportional buckets — a `mulDivUp` / `mulDivCeil` / `ceilDiv` helper, the
/// OpenZeppelin `Rounding.Up`/`Rounding.Ceil` enum, or the `+ denom - 1` ceil
/// idiom. Any of these means the dust does not silently land on one bucket.
/// Keyed on comment-stripped, lowercased source (per `cx.source_text`).
fn uses_rounding_helper(cx: &AnalysisContext, f: &Function) -> bool {
    let src = cx.source_text(f.span);
    if src.contains("muldivup")
        || src.contains("muldivceil")
        || src.contains("mulup")
        || src.contains("ceildiv")
        || src.contains("divup")
        || src.contains("rounding.up")
        || src.contains("rounding.ceil")
        || src.contains("roundup")
    {
        return true;
    }
    // Hand-rolled ceil-division `(a * b + c - 1) / c`: a `Div` whose numerator
    // subtracts `1`. Its presence means rounding was deliberately handled.
    has_ceil_idiom(f)
}

/// Detect the `(.. + denom - 1) / denom` ceil-division idiom structurally: a
/// `Div` whose numerator contains a `- 1` subtraction.
fn has_ceil_idiom(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Binary { op: BinOp::Div, lhs, .. } = &e.kind {
                lhs.visit(&mut |n| {
                    if let ExprKind::Binary { op: BinOp::Sub, rhs, .. } = &n.kind {
                        if is_one(rhs) {
                            found = true;
                        }
                    }
                });
            }
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: the Symbiotic `onSlash` shape. The amount is split across two
    // floor-divided buckets (`activeSlashed`, `withdrawSlashed`), then the
    // remainder `amount - activeSlashed - withdrawSlashed` is forced onto a third
    // bucket — that bucket eats all the rounding dust.
    const VULN: &str = r#"
        contract Vault {
            uint256 public activeStake;
            uint256 public withdrawals;
            uint256 public totalStake;
            uint256 public nextEpochWithdrawals;
            mapping(uint256 => uint256) public slashedOf;

            function onSlash(uint256 amount, uint256 epoch) external {
                uint256 activeSlashed   = amount * activeStake / totalStake;
                uint256 withdrawSlashed = amount * withdrawals / totalStake;
                uint256 nextSlashed     = amount - activeSlashed - withdrawSlashed;
                slashedOf[epoch] = nextSlashed;
                nextEpochWithdrawals -= nextSlashed;
            }
        }
    "#;

    // Safe: same two-bucket split with two in-line divisions (so the
    // division-count gate still passes) AND still computes a `amount - a - b`
    // residual — but the buckets are rounded UP with the `(.. + d - 1) / d`
    // ceil-division idiom. Because the rounding direction is pinned fairly, the
    // residual no longer silently absorbs floor dust, so the detector suppresses.
    // The VULN/SAFE pair differs only in this rounding fix.
    const SAFE: &str = r#"
        contract Vault {
            uint256 public activeStake;
            uint256 public withdrawals;
            uint256 public totalStake;
            uint256 public nextEpochWithdrawals;
            mapping(uint256 => uint256) public slashedOf;

            function onSlash(uint256 amount, uint256 epoch) external {
                uint256 activeSlashed   = (amount * activeStake + totalStake - 1) / totalStake;
                uint256 withdrawSlashed = (amount * withdrawals + totalStake - 1) / totalStake;
                uint256 nextSlashed     = amount - activeSlashed - withdrawSlashed;
                slashedOf[epoch] = nextSlashed;
                nextEpochWithdrawals -= nextSlashed;
            }
        }
    "#;

    // Safe (negative control): a single division and only a single subtraction
    // (`amount - fee`) — an ordinary net-amount computation, not a >=2-bucket
    // forced residual. Must stay silent (the spine/division gates doing their
    // job).
    const SAFE_SINGLE: &str = r#"
        contract Splitter {
            uint256 public feeBps;
            uint256 public treasury;
            mapping(address => uint256) public credit;

            function pay(uint256 amount) external {
                uint256 fee = amount * feeBps / 10000;
                uint256 net = amount - fee;
                treasury += fee;
                credit[msg.sender] += net;
            }
        }
    "#;

    // Vulnerable, faithful to the REAL Symbiotic `Vault.onSlash`: the shares are
    // taken with the floor `Math.mulDiv` (here the `using Math for uint256` bound
    // form `slashedAmount.mulDiv(stake, total)`, with NO bare `/` operator at
    // all), the split lives inside an `if/else` branch, and the residual
    // `slashedAmount - activeSlashed - nextWithdrawalsSlashed` is forced onto the
    // last bucket. This is the shape that previously fired 0 because the gate only
    // counted the `/` operator.
    const VULN_REAL_MULDIV: &str = r#"
        library Math {
            function mulDiv(uint256 x, uint256 y, uint256 d) internal pure returns (uint256) { return x * y / d; }
            function min(uint256 a, uint256 b) internal pure returns (uint256) { return a < b ? a : b; }
        }
        contract Vault {
            using Math for uint256;
            mapping(uint256 => uint256) public withdrawals;
            uint256 public activeStake_;
            address public burner;

            function onSlash(uint256 amount, uint256 currentEpoch_) external returns (uint256 slashedAmount) {
                uint256 withdrawals_ = withdrawals[currentEpoch_];
                uint256 nextWithdrawals = withdrawals[currentEpoch_ + 1];
                uint256 slashableStake = activeStake_ + withdrawals_ + nextWithdrawals;
                slashedAmount = Math.min(amount, slashableStake);
                if (slashedAmount > 0) {
                    uint256 activeSlashed = slashedAmount.mulDiv(activeStake_, slashableStake);
                    uint256 nextWithdrawalsSlashed = slashedAmount.mulDiv(nextWithdrawals, slashableStake);
                    uint256 withdrawalsSlashed = slashedAmount - activeSlashed - nextWithdrawalsSlashed;
                    withdrawals[currentEpoch_ + 1] = nextWithdrawals - nextWithdrawalsSlashed;
                    withdrawals[currentEpoch_] = withdrawals_ - withdrawalsSlashed;
                }
            }
        }
    "#;

    // Safe counterpart to the real shape: identical multi-bucket split, but the
    // shares are taken with `mulDivUp` (a pinned, fair round-up). The floor dust
    // no longer silently lands on one bucket, so the detector suppresses — and the
    // `mulDivUp` calls are not counted as floor splits.
    const SAFE_REAL_MULDIVUP: &str = r#"
        library Math {
            function mulDivUp(uint256 x, uint256 y, uint256 d) internal pure returns (uint256) { return (x * y + d - 1) / d; }
            function min(uint256 a, uint256 b) internal pure returns (uint256) { return a < b ? a : b; }
        }
        contract Vault {
            using Math for uint256;
            mapping(uint256 => uint256) public withdrawals;
            uint256 public activeStake_;

            function onSlash(uint256 amount, uint256 currentEpoch_) external returns (uint256 slashedAmount) {
                uint256 withdrawals_ = withdrawals[currentEpoch_];
                uint256 nextWithdrawals = withdrawals[currentEpoch_ + 1];
                uint256 slashableStake = activeStake_ + withdrawals_ + nextWithdrawals;
                slashedAmount = Math.min(amount, slashableStake);
                if (slashedAmount > 0) {
                    uint256 activeSlashed = slashedAmount.mulDivUp(activeStake_, slashableStake);
                    uint256 nextWithdrawalsSlashed = slashedAmount.mulDivUp(nextWithdrawals, slashableStake);
                    uint256 withdrawalsSlashed = slashedAmount - activeSlashed - nextWithdrawalsSlashed;
                    withdrawals[currentEpoch_ + 1] = nextWithdrawals - nextWithdrawalsSlashed;
                    withdrawals[currentEpoch_] = withdrawals_ - withdrawalsSlashed;
                }
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(
            fs.iter().any(|f| f.detector == "proportional-split-residual"),
            "{:#?}",
            fs
        );
    }

    #[test]
    fn fires_on_real_muldiv_shape() {
        let fs = run(VULN_REAL_MULDIV);
        assert!(
            fs.iter().any(|f| f.detector == "proportional-split-residual"),
            "real Symbiotic mulDiv onSlash shape must fire: {:#?}",
            fs
        );
    }

    #[test]
    fn silent_on_real_muldivup_shape() {
        let fs = run(SAFE_REAL_MULDIVUP);
        assert!(
            !fs.iter().any(|f| f.detector == "proportional-split-residual"),
            "mulDivUp (pinned rounding) must suppress: {:#?}",
            fs
        );
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "proportional-split-residual"));
    }

    #[test]
    fn silent_on_single_difference() {
        let fs = run(SAFE_SINGLE);
        assert!(!fs.iter().any(|f| f.detector == "proportional-split-residual"));
    }
}
