//! ERC-20 `approve` front-running (SWC-114 allowance double-spend).
//!
//! `IERC20.approve(spender, amount)` sets the allowance to an absolute value. If
//! a contract changes an existing non-zero allowance to a new non-zero value in a
//! single `approve` call, the spender can front-run the change: they spend the
//! *old* allowance, then, once the new `approve` lands, spend the *new* one too —
//! receiving `old + new` instead of `new`. The canonical mitigations are to reset
//! to `0` first (`approve(spender, 0)` then `approve(spender, amount)`), or to use
//! SafeERC20's `safeIncreaseAllowance` / `safeDecreaseAllowance` / `forceApprove`
//! (or the legacy `increaseAllowance` / `decreaseAllowance`), which adjust the
//! allowance by a delta rather than overwriting it.
//!
//! This is an informational-class finding: it is genuinely front-runnable, but the
//! impact is bounded and many tokens / call-sites are benign, so confidence is kept
//! low and known-safe shapes are suppressed aggressively (precision over recall).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Call, CallKind, Expr, ExprKind, Function, Lit};

pub struct ApproveRaceDetector;

impl Detector for ApproveRaceDetector {
    fn id(&self) -> &'static str {
        "approve-race"
    }
    fn category(&self) -> Category {
        Category::ApproveRace
    }
    fn description(&self) -> &'static str {
        "ERC-20 approve() to a non-zero amount with no prior reset (front-runnable allowance double-spend)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        // Attack surface: externally-reachable, state-mutating bodies — the place a
        // contract would set an allowance on behalf of itself.
        for f in cx.entry_points() {
            // Contract-level mitigation: SafeERC20 in scope (its `safeApprove`/
            // `forceApprove`/`safeIncreaseAllowance` wrappers handle the race).
            if cx.uses_safe_erc20(f.contract) {
                continue;
            }
            // Function-level mitigation: the body uses a delta-based / forced
            // allowance update (`safeIncreaseAllowance`, `safeDecreaseAllowance`,
            // `safeApprove`, `forceApprove`, `increaseAllowance`, `decreaseAllowance`).
            if uses_safe_allowance_update(f) {
                continue;
            }

            // Collect the raw `approve(spender, amount)` calls in source order.
            let approves = collect_approves(f);
            if approves.is_empty() {
                continue;
            }

            for ap in &approves {
                // amount == 0 is a *reset*, never the dangerous direction.
                if is_zero_literal(&ap.amount) {
                    continue;
                }
                // Suppress when a reset to 0 for the same spender precedes this
                // non-zero approve (the documented `approve(0); approve(amount)`
                // safe pattern). A reset to 0 with no resolvable spender is treated
                // as covering this approve too (conservative: avoids a false flag
                // on the common two-call idiom).
                let reset_before = approves.iter().any(|other| {
                    other.order < ap.order
                        && is_zero_literal(&other.amount)
                        && same_or_unknown_spender(&other.spender, &ap.spender)
                });
                if reset_before {
                    continue;
                }

                let b = FindingBuilder::new(self.id(), Category::ApproveRace)
                    .title("ERC-20 approve() to a non-zero amount without a prior reset")
                    .severity(Severity::Low)
                    .confidence(0.4)
                    .dimension(Dimension::ValueFlow)
                    .message(format!(
                        "`{}` calls `approve(spender, amount)` with a non-zero `amount` and does not first \
                         reset the allowance to `0`. If `spender` already holds an allowance, it can \
                         front-run this transaction: spend the old allowance, then spend the new one once \
                         this `approve` lands, receiving the sum (SWC-114 allowance double-spend).",
                        f.name
                    ))
                    .recommendation(
                        "Set the allowance to `0` before assigning a new non-zero value \
                         (`approve(spender, 0); approve(spender, amount)`), or use OpenZeppelin SafeERC20 \
                         `forceApprove` / `safeIncreaseAllowance` / `safeDecreaseAllowance` which adjust the \
                         allowance safely.",
                    );
                out.push(cx.finish(b, f.id, ap.span));
            }
        }
        out
    }
}

/// A raw ERC-20 `approve(spender, amount)` call site recovered from the body.
struct ApproveCall<'a> {
    spender: Option<&'a Expr>,
    amount: &'a Expr,
    span: sluice_ir::Span,
    /// Source-order index (pre-order visitation position), used to decide whether
    /// a reset-to-zero precedes a non-zero approve.
    order: usize,
}

/// Collect every raw external `approve(spender, amount)` call in `f`, in
/// best-effort source order. Restricting to `func_name == "approve"` with exactly
/// two args and an external/unknown call kind keeps this from matching internal
/// helpers or unrelated two-arg functions.
fn collect_approves(f: &Function) -> Vec<ApproveCall<'_>> {
    let mut found = Vec::new();
    let mut order = 0usize;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            let ExprKind::Call(c) = &e.kind else { return };
            order += 1;
            if !is_raw_approve(c) {
                return;
            }
            // `approve(spender, amount)` — spender is arg 0, amount is arg 1.
            let amount = &c.args[1];
            let spender = c.args.first();
            found.push(ApproveCall {
                spender,
                amount,
                span: e.span,
                order,
            });
        });
    }
    found
}

/// True for a raw `approve(spender, amount)` token call (not a `safe*` wrapper).
/// We accept `External`/`Unknown` kinds because `token.approve(...)` on an
/// interface classifies as `External`, while an `approve` reached through a cast
/// or unresolved receiver can land as `Unknown`. Internal calls (a contract's own
/// `approve`-named helper) are excluded.
fn is_raw_approve(c: &Call) -> bool {
    c.func_name.as_deref() == Some("approve")
        && c.args.len() == 2
        && matches!(c.kind, CallKind::External | CallKind::Unknown)
}

/// Does the function body use a delta-based or forced allowance update that is
/// immune to the approve race? Checked by call name so it survives whether the
/// project routes through SafeERC20 (`safeIncreaseAllowance`, `forceApprove`) or
/// the token's own `increaseAllowance` / `decreaseAllowance`.
fn uses_safe_allowance_update(f: &Function) -> bool {
    f.effects.call_sites.iter().any(|c| {
        matches!(
            c.func_name.as_deref(),
            Some("safeIncreaseAllowance")
                | Some("safeDecreaseAllowance")
                | Some("safeApprove")
                | Some("forceApprove")
                | Some("increaseAllowance")
                | Some("decreaseAllowance")
        )
    })
}

/// True if a literal numeric/hex zero (`0`, `0x0`, `0x00`, ...). A computed or
/// parameterized amount is not a literal and is therefore (correctly) not treated
/// as a reset.
fn is_zero_literal(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(Lit::Number(n)) => {
            let s = n.trim();
            !s.is_empty() && s.chars().all(|ch| ch == '0' || ch == '_') && s.contains('0')
        }
        ExprKind::Lit(Lit::HexNumber(n)) => {
            let hex = n.trim_start_matches("0x").trim_start_matches("0X");
            !hex.is_empty() && hex.chars().all(|ch| ch == '0')
        }
        _ => false,
    }
}

/// Whether a preceding reset-to-zero plausibly covers `target`. True when the
/// spender expressions resolve to the same simple name, or when either spender
/// could not be resolved (best-effort textual match — we prefer to *suppress* the
/// common `approve(x, 0); approve(x, amount)` idiom rather than risk a false flag).
fn same_or_unknown_spender(reset: &Option<&Expr>, target: &Option<&Expr>) -> bool {
    match (reset, target) {
        (Some(a), Some(b)) => match (a.simple_name(), b.simple_name()) {
            (Some(x), Some(y)) => x == y,
            _ => true,
        },
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: sets a non-zero allowance directly, with no prior reset and no
    // SafeERC20 / increaseAllowance.
    const VULN: &str = r#"
        interface IERC20 {
            function approve(address spender, uint256 amount) external returns (bool);
        }
        contract Spender {
            IERC20 token;
            function grant(address spender, uint256 amount) external {
                token.approve(spender, amount);
            }
        }
    "#;

    // Safe: resets the allowance to 0 before assigning a new non-zero value.
    const SAFE: &str = r#"
        interface IERC20 {
            function approve(address spender, uint256 amount) external returns (bool);
        }
        contract Spender {
            IERC20 token;
            function grant(address spender, uint256 amount) external {
                token.approve(spender, 0);
                token.approve(spender, amount);
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "approve-race"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "approve-race"));
    }
}
