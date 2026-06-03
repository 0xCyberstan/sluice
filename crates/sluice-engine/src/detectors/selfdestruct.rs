//! Unprotected `selfdestruct` / `suicide`: an externally-reachable function
//! destroys the contract with no access-control guard.
//!
//! `selfdestruct(recipient)` removes the contract's code and forwards its entire
//! balance to `recipient`. If any external caller can reach that opcode without
//! passing an `onlyOwner`/role check, anyone can brick the contract (and, when
//! the recipient is caller-supplied, sweep its balance to themselves). This is
//! the Parity multisig-library class: a public `kill()` left an upgradeable
//! library destructible, freezing every dependent wallet.
//!
//! The signal is structural — a reachable `Builtin(Selfdestruct)` call — so the
//! precision lever is suppression of the legitimately-guarded cases:
//!   * the function carries an access-control guard (`onlyOwner`, a role check,
//!     or a bare `require(msg.sender == ...)`), or
//!   * it is an initializer (`initializer`/`reinitializer`), which can only run
//!     once and under controlled conditions.
//! Both are read straight from the precomputed entry guards, so a shared
//! `_onlyOwner()` modifier or an inline sender check is honoured identically.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::detectors::visit_calls;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Builtin, CallKind, Span};

pub struct SelfdestructDetector;

impl Detector for SelfdestructDetector {
    fn id(&self) -> &'static str {
        "unprotected-selfdestruct"
    }
    fn category(&self) -> Category {
        Category::AccessControl
    }
    fn description(&self) -> &'static str {
        "Externally-reachable selfdestruct/suicide with no access-control guard"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // Must be a concrete, externally-reachable function: a `selfdestruct`
            // in an internal/private helper is only a hazard if some reachable
            // caller exposes it, which the access-control class proper covers.
            if !f.has_body || !f.is_externally_reachable() {
                continue;
            }
            // --- false-positive suppression (precision first) ---
            // A `msg.sender`/role/owner guard, or an `initializer` guard, means
            // the destruct is gated. These are exactly the legitimate patterns
            // (an admin `kill()` behind `onlyOwner`, a one-shot init).
            if cx.has_access_control(f) || cx.is_initializer(f) {
                continue;
            }

            // Find the `selfdestruct(...)` / `suicide(...)` builtin call in the
            // body, and whether its recipient argument is attacker-controlled.
            let mut hit: Option<Span> = None;
            let mut recipient_attacker = false;
            visit_calls(f, |c, span| {
                if !matches!(c.kind, CallKind::Builtin(Builtin::Selfdestruct)) {
                    return;
                }
                if hit.is_none() {
                    hit = Some(span);
                }
                // `selfdestruct(recipient)` forwards the whole balance to its
                // single argument; if that is caller-supplied, the destruct is
                // also a balance-theft primitive, not merely a brick.
                if let Some(recipient) = c.args.first() {
                    if cx.is_attacker_controlled(f.id, recipient) {
                        recipient_attacker = true;
                    }
                }
            });
            let Some(span) = hit else {
                continue;
            };

            let mut b = FindingBuilder::new(self.id(), Category::AccessControl)
                .title("Unprotected selfdestruct")
                .severity(if recipient_attacker { Severity::Critical } else { Severity::High })
                .confidence(0.7)
                .dimension(Dimension::Invariant)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` is externally callable and reaches `selfdestruct` with no access-control \
                     guard (no `onlyOwner`/role check, no `require(msg.sender == ...)`). Any account \
                     can destroy the contract — removing its code and freezing every dependent \
                     integration — the Parity multisig-library class.{}",
                    f.name,
                    if recipient_attacker {
                        " The destruct recipient is caller-controlled, so the same call also sweeps \
                         the contract's entire balance to the attacker."
                    } else {
                        ""
                    }
                ))
                .recommendation(
                    "Gate the destruct behind an authorization check (`onlyOwner`/role modifier or \
                     `require(msg.sender == owner)`), or remove `selfdestruct` entirely — it is \
                     deprecated and rarely necessary.",
                );
            if recipient_attacker {
                b = b.dimension(Dimension::Frontier);
            }
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: a public `kill()` reaches `selfdestruct(msg.sender)` with no
    // access control — anyone can destroy the contract and sweep its balance.
    const VULN: &str = r#"
        contract Bank {
            mapping(address => uint256) public balances;
            function deposit() external payable { balances[msg.sender] += msg.value; }
            function kill() external {
                selfdestruct(payable(msg.sender));
            }
        }
    "#;

    // Safe: identical destruct, but gated by an inline owner check.
    const SAFE: &str = r#"
        contract Bank {
            address public owner;
            mapping(address => uint256) public balances;
            constructor() { owner = msg.sender; }
            function deposit() external payable { balances[msg.sender] += msg.value; }
            function kill() external {
                require(msg.sender == owner, "not owner");
                selfdestruct(payable(owner));
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "unprotected-selfdestruct"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "unprotected-selfdestruct"));
    }
}
