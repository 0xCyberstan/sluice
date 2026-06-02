//! Forced-ether / donatable-balance brittleness: accounting and invariants that
//! rely on a *strict* equality against a live on-chain balance.
//!
//! ETH can be injected into any contract without invoking a payable function:
//! `selfdestruct(payable(victim))` (and pre-`receive` coinbase payouts / the
//! genesis preallocation) credit the balance directly. Likewise an ERC-20
//! balance is freely *donatable* — anyone can `transfer` tokens to a contract.
//! A guard like `require(address(this).balance == expected)` or
//! `if (token.balanceOf(address(this)) != bookkeeping) revert();` is therefore a
//! brittle invariant: an attacker forces a tiny donation, the strict equality no
//! longer holds, and the path is permanently bricked (DoS) or the contract is
//! pushed into an unintended branch. The historical lesson is to track an
//! *internal* counter and to use inequalities (`>=`) rather than `==` when a live
//! balance is unavoidable.
//!
//! Strategy (best-effort, textual on the IR span — see `DETECTOR_AUTHORING.md`):
//! walk each function body for `ExprKind::Binary { op: Eq | Ne, .. }` and check
//! whether either operand's source text mentions a live-balance read
//! (`address(this).balance`, `this.balance`, or `balanceOf(address(this))` /
//! `balanceOf(this)`). Ordering comparisons (`>=`, `<=`, `>`, `<`) tolerate extra
//! balance and are never flagged. A bare presence check (`... == 0`) is also
//! suppressed: a forced donation can't make a balance *zero*, so the brittleness
//! does not apply.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Expr, ExprKind};

pub struct ForcedEtherDetector;

impl Detector for ForcedEtherDetector {
    fn id(&self) -> &'static str {
        "forced-ether"
    }
    fn category(&self) -> Category {
        Category::ForcedEther
    }
    fn description(&self) -> &'static str {
        "Strict equality against a live (force-injectable / donatable) ETH or token balance"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.functions() {
            if !f.has_body {
                continue;
            }

            // De-dup per function: report each offending comparison span once.
            let mut seen_spans: Vec<sluice_ir::Span> = Vec::new();

            for s in &f.body {
                s.visit_exprs(&mut |e: &Expr| {
                    let ExprKind::Binary { op, lhs, rhs } = &e.kind else {
                        return;
                    };
                    // Only strict equality / disequality. Ordering comparisons
                    // (`>=`, `<=`, `>`, `<`) tolerate extra balance — never flag.
                    if !matches!(op, BinOp::Eq | BinOp::Ne) {
                        return;
                    }

                    let lhs_txt = normalize(cx.scir.span_text(lhs.span));
                    let rhs_txt = normalize(cx.scir.span_text(rhs.span));

                    let lhs_eth = mentions_live_eth_balance(&lhs_txt);
                    let rhs_eth = mentions_live_eth_balance(&rhs_txt);
                    let lhs_tok = mentions_self_token_balance(&lhs_txt);
                    let rhs_tok = mentions_self_token_balance(&rhs_txt);

                    let eth_side = lhs_eth || rhs_eth;
                    let token_side = lhs_tok || rhs_tok;
                    if !eth_side && !token_side {
                        return;
                    }

                    // Suppress a bare presence check (`balance == 0` / `!= 0`):
                    // a forced donation can only *raise* a balance, so it cannot
                    // defeat a zero-check, and these are common benign gates.
                    if is_zero_literal(&lhs_txt) || is_zero_literal(&rhs_txt) {
                        return;
                    }

                    if seen_spans.contains(&e.span) {
                        return;
                    }
                    seen_spans.push(e.span);

                    let asset = if eth_side { "native ETH balance" } else { "token balance" };
                    let injection = if eth_side {
                        "`selfdestruct(payable(this))` (or a coinbase/genesis credit) can force ETH in \
                         even with no payable function"
                    } else {
                        "anyone can `transfer` tokens straight to this contract (a donation)"
                    };

                    // Value-flow: a live balance is an externally-influenced
                    // quantity feeding a sensitive comparison. Invariant: this is
                    // the broken accounting assumption (live balance used as the
                    // source of truth instead of an internal counter).
                    let b = FindingBuilder::new(self.id(), Category::ForcedEther)
                        .title("Strict equality against a force-injectable / donatable balance")
                        .severity(Severity::Medium)
                        .confidence(0.5)
                        .dimension(Dimension::ValueFlow)
                        .dimension(Dimension::Invariant)
                        .message(format!(
                            "`{}` compares a live {} for strict {} (`{}`). Because {}, an attacker can \
                             perturb the balance by 1 wei so the equality never holds — bricking this path \
                             (DoS) or forcing an unintended branch. Live balances must not be the source of \
                             truth for accounting invariants.",
                            f.name,
                            asset,
                            if matches!(op, BinOp::Eq) { "equality" } else { "disequality" },
                            cx.scir.span_text(e.span).trim(),
                            injection
                        ))
                        .recommendation(
                            "Track deposits/withdrawals in an internal counter and compare against that, or \
                             use an inequality (`>=`) that tolerates donated/forced balance instead of `==`/`!=`.",
                        );
                    out.push(cx.finish(b, f.id, e.span));
                });
            }
        }

        out
    }
}

/// Normalize a span's source text for substring matching: lowercase and strip
/// all ASCII whitespace, so `address ( this ) . balance` and the line-broken
/// form collapse to a single canonical token.
fn normalize(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_lowercase()
}

/// True if the (already-normalized) text reads the contract's own live ETH
/// balance: `address(this).balance` or `this.balance`.
fn mentions_live_eth_balance(norm: &str) -> bool {
    norm.contains("address(this).balance") || norm.contains("this.balance")
}

/// True if the (already-normalized) text reads the contract's own token balance:
/// `…balanceOf(address(this))` or `…balanceOf(this)`.
fn mentions_self_token_balance(norm: &str) -> bool {
    norm.contains("balanceof(address(this))") || norm.contains("balanceof(this)")
}

/// True if the normalized operand is exactly the integer literal `0` (a benign
/// presence check, not a brittle accounting equality).
fn is_zero_literal(norm: &str) -> bool {
    norm == "0" || norm == "0x0" || norm == "uint256(0)" || norm == "uint(0)"
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: a strict equality of an internal counter against the live ETH
    // balance. A forced 1-wei `selfdestruct` donation breaks the invariant.
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        contract Bank {
            uint256 public totalDeposited;
            mapping(address => uint256) public deposits;
            function deposit() external payable {
                deposits[msg.sender] += msg.value;
                totalDeposited += msg.value;
            }
            function checkpoint() external {
                // Brittle: forced ether makes this revert forever.
                require(address(this).balance == totalDeposited, "balance mismatch");
            }
        }
    "#;

    // Safe: same accounting, but the reconciliation uses `>=`, which tolerates
    // donated/forced balance. No strict equality against a live balance.
    const SAFE: &str = r#"
        pragma solidity ^0.8.20;
        contract Bank {
            uint256 public totalDeposited;
            mapping(address => uint256) public deposits;
            function deposit() external payable {
                deposits[msg.sender] += msg.value;
                totalDeposited += msg.value;
            }
            function checkpoint() external view returns (bool) {
                // Inequality tolerates forced/donated ether.
                return address(this).balance >= totalDeposited;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "forced-ether"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "forced-ether"));
    }
}
