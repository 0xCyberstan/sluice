//! Proportional-split residual hazard: a function splits one amount across two
//! or more buckets with floor division and then force-assigns the leftover (the
//! rounding dust) to a single bucket via a `amount - a - b` residual.
//!
//! The canonical shape — the **Symbiotic `Vault.onSlash`** slashing split:
//! ```solidity
//! function onSlash(uint256 amount, ...) external {
//!     uint256 activeSlashed   = amount * activeStake   / totalStake;   // floor
//!     uint256 withdrawSlashed = amount * withdrawals   / totalStake;   // floor
//!     // the two floors lose dust; force the remainder onto ONE bucket:
//!     uint256 nextSlashed     = amount - activeSlashed - withdrawSlashed;
//!     nextEpochWithdrawals -= nextSlashed;        // <- residual sink
//! }
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
//!   * its body contains **>= 2 integer divisions** (the multi-bucket split);
//!   * a later assignment or `return` computes a value that is a chain of **>= 2
//!     subtractions** from a common quantity (`x - a - b`, the forced residual)
//!     and that value flows into a bucket state variable / mapping (an `Assign`
//!     to storage, a `-=`/`+=` on a bucket, or a `return`);
//!   * no `mulDivUp`/`mulDivCeil`/`ceilDiv`/`Rounding.Up` helper pins the bucket
//!     rounding direction.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{AssignOp, BinOp, Expr, ExprKind, Function, Span, StmtKind};

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

            // (1) The multi-bucket split: at least two integer divisions in the
            // body. A single division is an ordinary ratio, not a split.
            if count_divisions(f) < 2 {
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

            let b = FindingBuilder::new(self.id(), Category::ProportionalSplitResidual)
                .title("Proportional split forces rounding remainder onto one bucket")
                .severity(Severity::Medium)
                .confidence(0.45)
                .dimension(Dimension::Invariant)
                .message(format!(
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
                ))
                .recommendation(
                    "Round the proportional buckets in a single, fair direction with an explicit \
                     rounding-mode helper (`mulDivUp` / `ceilDiv` / OpenZeppelin \
                     `Math.mulDiv(.., Rounding.Up)`), or distribute the remainder pro-rata across all \
                     buckets, instead of dumping the entire floor-division dust onto one chosen bucket.",
                );
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

/// Count distinct integer-division (`BinOp::Div`) sub-expressions in the body.
/// This is the multi-bucket-split signal: two or more proportional shares of one
/// quantity. (`mulDiv`-family calls are deliberately *not* counted here — those
/// have an explicit rounding mode and are handled by `uses_rounding_helper`.)
fn count_divisions(f: &Function) -> usize {
    let mut n = 0usize;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if let ExprKind::Binary { op: BinOp::Div, .. } = &e.kind {
                n += 1;
            }
        });
    }
    n
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
    let e = unwrap_casts(e);
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

/// Peel single-argument type casts / parenthesizing calls (`uint256(x)`,
/// `(x)` modeled as a cast), so a wrapped residual is still recognized.
fn unwrap_casts(e: &Expr) -> &Expr {
    let mut cur = e;
    loop {
        match &cur.kind {
            ExprKind::Call(c)
                if c.kind == sluice_ir::CallKind::TypeCast && c.args.len() == 1 =>
            {
                cur = &c.args[0];
            }
            _ => return cur,
        }
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

fn is_one(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Lit(sluice_ir::Lit::Number(n)) if n.trim() == "1")
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
