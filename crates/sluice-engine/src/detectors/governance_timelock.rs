//! Missing governance timelock on privileged upgrades / critical parameter
//! changes.
//!
//! A privileged upgrade (`upgradeTo`, `_authorizeUpgrade`, `setImplementation`)
//! or critical setter (`set*Fee`, `setOracle`, `setOwner`) that executes
//! **immediately** — with no timelock/delay/queue+execute mechanism — gives
//! users no window to exit before a malicious or compromised admin action takes
//! effect. The class behind countless "admin rug" / governance-attack post-
//! mortems where the mitigation is "the action should sit behind a timelock".
//!
//! This is a structural/process finding rather than a value-flow one, so it is
//! reported on the [`Dimension::Invariant`] dimension at a deliberately modest
//! confidence: the absence of a timelock is heuristic (we cannot see an external
//! `TimelockController` wired up off-chain), and precision is prioritized via
//! aggressive suppression of any contract that evidences a timelock.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::detectors::is_privileged_name;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::Function;

pub struct GovernanceTimelockDetector;

/// Criticality rank of a privileged function (higher = report this one first).
/// We fire only once per contract, on the single most critical candidate.
fn criticality(f: &Function) -> u8 {
    let l = f.name.to_ascii_lowercase();
    // Upgrades replace *all* code, so they dominate.
    if l == "upgradeto" || l == "upgradetoandcall" {
        return 5;
    }
    if l == "_authorizeupgrade" || l == "setimplementation" {
        return 4;
    }
    // Ownership / governance handover.
    if l == "setowner" || l == "transferownership" || l == "setgovernance" || l == "setadmin" {
        return 3;
    }
    // Oracle swap (controls every valuation).
    if l.contains("setoracle") || l.contains("setpricefeed") {
        return 2;
    }
    // Fee / generic privileged parameter setters.
    1
}

/// Is this function an upgrade hook or critical privileged setter we care about?
fn is_critical_change(f: &Function) -> bool {
    let l = f.name.to_ascii_lowercase();

    // (1) Upgrade surface. `_authorizeUpgrade` is excluded: it is the UUPS auth
    // hook present in essentially every upgradeable contract, and the timelock
    // for upgrades conventionally lives in the owner/governance contract, not in
    // this hook — flagging it indiscriminately is pure noise (14/15 FPs observed
    // on real code). We flag the externally-callable upgrade entry points instead.
    let is_upgrade = matches!(l.as_str(), "upgradeto" | "upgradetoandcall" | "setimplementation")
        && f.is_externally_reachable();
    if is_upgrade {
        return true;
    }

    // (2) Critical setter that mutates privileged state. To keep precision we
    // require the setter to be externally reachable, state-mutating, and to
    // actually write a privileged-looking state variable (so per-user/bookkeeping
    // setters that merely happen to start with `set` are excluded).
    if !f.is_externally_reachable() || !f.is_state_mutating() {
        return false;
    }
    let setter_shape = l.starts_with("set")
        && (l.contains("fee") || l.contains("oracle") || l.contains("owner")
            || l.contains("pricefeed") || l.contains("governance") || l.contains("admin")
            || l.contains("implementation"));
    if !setter_shape {
        return false;
    }
    f.effects.written_vars().iter().any(|v| is_privileged_name(v))
}

/// Does the contract source evidence a timelock mechanism? Conservative on the
/// side of *suppression* — any plausible timelock signal silences the finding.
fn has_timelock_evidence(src_lc: &str) -> bool {
    // Direct vocabulary used by timelock implementations / bases.
    if src_lc.contains("timelock") || src_lc.contains("mindelay") {
        return true;
    }
    // A delay/eta/pending value combined with a queue/execute two-step flow is
    // the structural shape of a timelock (queue now, execute after the delay).
    let has_delay_word = src_lc.contains("delay") || src_lc.contains("eta") || src_lc.contains("pending");
    let has_two_step = (src_lc.contains("queue") || src_lc.contains("queued"))
        && (src_lc.contains("execute") || src_lc.contains("pending"));
    has_delay_word && has_two_step
}

impl Detector for GovernanceTimelockDetector {
    fn id(&self) -> &'static str {
        "governance-timelock"
    }
    fn category(&self) -> Category {
        Category::GovernanceTimelock
    }
    fn description(&self) -> &'static str {
        "Privileged upgrade / critical setter executes immediately with no timelock or exit window"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for contract in cx.scir.iter_contracts() {
            // Only concrete contracts have a deployable upgrade/admin surface.
            // Interfaces, libraries, and abstract bases are not the thing users
            // are exposed to.
            if !contract.is_concrete() {
                continue;
            }

            // --- false-positive suppression (whole-contract evidence) ---------

            // The contract *is* (or inherits) a timelock / governor — the delay
            // is its whole purpose.
            if contract.inherits_like("timelock")
                || contract.inherits_like("governor")
                || contract.inherits_like("timelockcontroller")
            {
                continue;
            }
            // Scan the contract source once for an in-contract timelock pattern.
            let src_lc = cx.scir.span_text(contract.span).to_ascii_lowercase();
            if has_timelock_evidence(&src_lc) {
                continue;
            }

            // --- pick the single most-critical privileged function ------------

            let mut best: Option<&Function> = None;
            for f in cx.scir.functions_of(contract.id) {
                if !f.has_body {
                    continue;
                }
                if !is_critical_change(f) {
                    continue;
                }
                best = match best {
                    Some(prev) if criticality(prev) >= criticality(f) => Some(prev),
                    _ => Some(f),
                };
            }
            let Some(f) = best else {
                continue;
            };

            let b = FindingBuilder::new(self.id(), Category::GovernanceTimelock)
                .title("Privileged change has no timelock (no user exit window)")
                .severity(Severity::Medium)
                .confidence(0.45)
                .dimension(Dimension::Invariant)
                .message(format!(
                    "`{}.{}` performs a privileged upgrade / critical parameter change that takes \
                     effect immediately — the contract has no timelock, delay, or queue→execute \
                     mechanism. A malicious or compromised admin can change the implementation, \
                     oracle, owner, or fees in a single transaction, giving users no window to \
                     withdraw before the change applies (the admin-rug / governance-attack class).",
                    contract.name, f.name
                ))
                .recommendation(
                    "Route privileged upgrades and critical setters through a timelock (e.g. \
                     OpenZeppelin `TimelockController`): queue the action, enforce a `minDelay`, \
                     and only `execute` after it elapses, so users can exit beforehand.",
                );
            out.push(cx.finish(b, f.id, f.span));
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

    // Vulnerable: a UUPS-style upgrade with no timelock anywhere in the contract.
    const VULN: &str = r#"
        contract Vault {
            address public owner;
            address public implementation;
            uint256 public fee;

            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }

            function upgradeTo(address newImpl) external onlyOwner {
                implementation = newImpl;
            }

            function setFee(uint256 newFee) external onlyOwner {
                fee = newFee;
            }
        }
    "#;

    // Safe: the privileged change is gated behind a queue→execute timelock with
    // a minDelay / eta, so users have an exit window.
    const SAFE: &str = r#"
        contract Vault {
            address public owner;
            address public implementation;
            uint256 public minDelay = 2 days;
            mapping(bytes32 => uint256) public queuedEta;

            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }

            function queueUpgrade(address newImpl) external onlyOwner {
                bytes32 id = keccak256(abi.encode(newImpl));
                queuedEta[id] = block.timestamp + minDelay;
            }

            function executeUpgrade(address newImpl) external onlyOwner {
                bytes32 id = keccak256(abi.encode(newImpl));
                require(queuedEta[id] != 0 && block.timestamp >= queuedEta[id], "timelock");
                implementation = newImpl;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "governance-timelock"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "governance-timelock"));
    }
}
