//! Flash-loan governance / vote-buying: voting power is weighted by a *live*
//! balance read at execution time (`balanceOf` / `getVotes` / a stake-share
//! read) instead of a historical snapshot. An attacker flash-borrows the
//! governance token, votes/executes with the inflated balance, then repays in
//! the same transaction. The Beanstalk ($181M) class.
//!
//! Two signals, both gated by snapshot/timelock suppression:
//!   1. A governance-flavored function (`vote`, `castVote`, `propose`,
//!      `execute`, `quorum`, `delegate`, `_countVotes`, `getVotes`, ...) reads a
//!      live balance to weight a decision, with no snapshot mechanism in sight.
//!   2. A single function that does deposit/stake -> a privileged/vote action
//!      -> withdraw within one call (the flash-loan shape laid bare in-contract).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Contract, ExprKind, Function};

pub struct FlashLoanGovernanceDetector;

impl Detector for FlashLoanGovernanceDetector {
    fn id(&self) -> &'static str {
        "flashloan-governance"
    }
    fn category(&self) -> Category {
        Category::FlashLoanGovernance
    }
    fn description(&self) -> &'static str {
        "Governance weight from a live balance (balanceOf/getVotes) with no snapshot — flash-loan vote-buying"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || !f.is_externally_reachable() {
                continue;
            }

            let (contract_name, _) = cx.names(f.id);
            let contract = cx.contract_of(f.id);

            // --- false-positive suppression (snapshot / timelock safe patterns) ---
            if uses_snapshot_or_timelock(cx, f, contract) {
                continue;
            }

            let governance = is_governance_context(f, &contract_name, contract);

            // Signal 2: deposit/stake -> privileged action -> withdraw in one call.
            // This is suspicious even outside an obvious governance name.
            let flash_shape = has_flash_shape(f);

            if !governance && !flash_shape {
                continue;
            }

            // Locate a live balance/voting-power read used to weight the decision.
            let Some((balance_span, balance_kind)) = find_live_balance_read(f) else {
                // No live power read: only fire on the unambiguous in-call flash shape
                // when the privileged action is itself governance-flavored.
                if flash_shape && governance {
                    out.push(self.flash_shape_finding(cx, f));
                }
                continue;
            };

            // Build the finding. Base evidence is value-flow (a live, attacker-movable
            // quantity reaches a governance decision).
            let mut b = FindingBuilder::new(self.id(), Category::FlashLoanGovernance)
                .title("Voting power read from a live balance (no snapshot)")
                .severity(Severity::High)
                .confidence(0.5)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` weights a governance decision using a live `{}` read taken at execution time \
                     rather than a historical snapshot (e.g. `getPastVotes` / `getPastTotalSupply`). An \
                     attacker can flash-borrow the governance token, inflate this balance, vote or execute, \
                     and repay in the same transaction — the Beanstalk vote-buying class.",
                    f.name, balance_kind
                ))
                .recommendation(
                    "Weight voting power by a snapshot taken at proposal creation (ERC20Votes \
                     `getPastVotes` + `getPastTotalSupply`, or ERC20Snapshot), and/or route execution \
                     through a timelock so borrowed power cannot vote and exit atomically.",
                );

            // Invariant corroboration: the in-call deposit->act->withdraw shape is a
            // guard/consensus violation (power that never settles into state).
            if flash_shape {
                b = b
                    .dimension(Dimension::Invariant)
                    .tag("flash-shape")
                    .confidence(0.6);
            }

            out.push(cx.finish(b, f.id, balance_span));
        }
        out
    }
}

impl FlashLoanGovernanceDetector {
    /// Finding for the in-call deposit/stake -> privileged action -> withdraw shape
    /// when no explicit live-power read was localized.
    fn flash_shape_finding(&self, cx: &AnalysisContext, f: &Function) -> Finding {
        let b = FindingBuilder::new(self.id(), Category::FlashLoanGovernance)
            .title("Stake -> privileged action -> withdraw within one call")
            .severity(Severity::High)
            .confidence(0.5)
            .dimension(Dimension::ValueFlow)
            .dimension(Dimension::Invariant)
            .tag("flash-shape")
            .message(format!(
                "`{}` deposits/stakes, performs a governance/privileged action, then withdraws — all in \
                 a single call. Borrowed (e.g. flash-loaned) capital can acquire voting power, use it, and \
                 exit atomically without ever holding a settled, snapshot-able stake. The Beanstalk class.",
                f.name
            ))
            .recommendation(
                "Require a settled snapshot of stake taken before the action (a prior block / proposal \
                 snapshot), and/or gate execution behind a timelock so transient stake cannot act.",
            );
        cx.finish(b, f.id, f.span)
    }
}

/// The snapshot / timelock safe markers. If any appear in the function or its
/// contract source, the live-balance reasoning is moot — suppress.
fn uses_snapshot_or_timelock(cx: &AnalysisContext, f: &Function, contract: Option<&Contract>) -> bool {
    // Cheap structural check on names first.
    let fname = f.name.to_ascii_lowercase();
    if fname.contains("timelock") || fname.contains("delay") {
        return true;
    }
    if let Some(c) = contract {
        let cn = c.name.to_ascii_lowercase();
        if cn.contains("timelock") || cn.contains("delay") {
            return true;
        }
        if c.inherits_like("erc20votes")
            || c.inherits_like("erc20snapshot")
            || c.inherits_like("votes")
            || c.inherits_like("timelock")
            || c.inherits_like("governortimelock")
        {
            return true;
        }
    }

    // Source-text markers (function body, then whole contract).
    const MARKERS: &[&str] = &[
        "getpastvotes",
        "getpriorvotes",
        "getpasttotalsupply",
        "snapshot",
        "checkpoint",
        "erc20votes",
        "erc20snapshot",
        "timelock",
    ];
    let fsrc = cx.scir.span_text(f.span).to_ascii_lowercase();
    if MARKERS.iter().any(|m| fsrc.contains(m)) {
        return true;
    }
    if let Some(c) = contract {
        let csrc = cx.scir.span_text(c.span).to_ascii_lowercase();
        if MARKERS.iter().any(|m| csrc.contains(m)) {
            return true;
        }
    }
    false
}

/// Does the function (by name) or its contract (by name/inheritance) look like
/// governance / voting?
fn is_governance_context(f: &Function, contract_name: &str, contract: Option<&Contract>) -> bool {
    if is_governance_name(&f.name) {
        return true;
    }
    let cn = contract_name.to_ascii_lowercase();
    if cn.contains("govern") || cn.contains("voting") || cn.contains("dao") || cn.contains("ballot") {
        return true;
    }
    if let Some(c) = contract {
        if c.inherits_like("governor") || c.inherits_like("governance") || c.inherits_like("dao") {
            return true;
        }
    }
    false
}

/// Governance/voting function-name heuristics (case-insensitive substring).
fn is_governance_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "vote", "castvote", "propose", "proposal", "execute", "quorum", "delegate", "countvotes",
        "getvotes", "votingpower", "tally", "ballot",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// Find a live balance / voting-power read (`balanceOf(...)`, `getVotes(...)`,
/// or a stake/share balance) used inside the function. Returns the call span and
/// a human label. Skips the *snapshot* variants (handled by suppression anyway).
fn find_live_balance_read(f: &Function) -> Option<(sluice_ir::Span, &'static str)> {
    let mut hit: Option<(sluice_ir::Span, &'static str)> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            let Some(name) = c.func_name.as_deref() else { return };
            let ln = name.to_ascii_lowercase();

            // Historical/snapshot reads are *safe* — never flag them.
            if ln.starts_with("getpast") || ln.starts_with("getprior") {
                return;
            }

            let label = if ln == "balanceof" {
                Some("balanceOf")
            } else if ln == "getvotes" {
                Some("getVotes")
            } else if ln == "votingpower" || ln == "getvotingpower" {
                Some("votingPower")
            } else if ln == "balanceofat" {
                // *At a block* is a snapshot read — safe.
                return;
            } else {
                None
            };
            let Some(label) = label else { return };

            // A live `balanceOf` / `getVotes` read is the hazard regardless of the
            // specific argument (the snapshot variants were already excluded above),
            // so we accept the read on name alone; the in-call flash shape raises
            // confidence separately at the call site.
            hit = Some((e.span, label));
        });
    }

    // Also accept a direct read of a stake/share *state variable* used to weight a
    // decision, expressed as an index/member on a balances-like mapping.
    if hit.is_none() {
        for s in &f.body {
            s.visit_exprs(&mut |e| {
                if hit.is_some() {
                    return;
                }
                if let ExprKind::Index { base, .. } = &e.kind {
                    if let Some(n) = base.simple_name() {
                        let nl = n.to_ascii_lowercase();
                        if nl.contains("balance")
                            || nl.contains("stake")
                            || nl.contains("share")
                            || nl.contains("deposit")
                            || nl.contains("votes")
                        {
                            hit = Some((e.span, "stake/share balance"));
                        }
                    }
                }
            });
        }
    }
    hit
}

/// Detect the in-call flash shape: a deposit/stake-like call, then a
/// privileged/vote-like call, then a withdraw/unstake-like call, in source order.
fn has_flash_shape(f: &Function) -> bool {
    // Collect call func-names in source order from the effect summary (ordered).
    let mut calls: Vec<(u32, String)> = f
        .effects
        .call_sites
        .iter()
        .filter_map(|c| c.func_name.as_ref().map(|n| (c.order, n.to_ascii_lowercase())))
        .collect();
    // Fold in internal calls (no precise order from the summary, but the body walk
    // below provides ordered names); prefer a body walk for ordering fidelity.
    calls.sort_by_key(|(o, _)| *o);

    // Body walk to get a reliable ordered sequence of call names.
    let mut seq: Vec<String> = Vec::new();
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if let ExprKind::Call(c) = &e.kind {
                if let Some(n) = &c.func_name {
                    seq.push(n.to_ascii_lowercase());
                }
            }
        });
    }
    if seq.is_empty() {
        seq = calls.into_iter().map(|(_, n)| n).collect();
    }

    let is_in = |n: &str| n.contains("deposit") || n.contains("stake") || n.contains("mint") || n.contains("borrow");
    let is_act = |n: &str| {
        n.contains("vote")
            || n.contains("propose")
            || n.contains("execute")
            || n.contains("delegate")
            || n.contains("quorum")
            || n.contains("tally")
    };
    let is_out =
        |n: &str| n.contains("withdraw") || n.contains("unstake") || n.contains("redeem") || n.contains("repay");

    // Find an in-index, then an act after it, then an out after that.
    let Some(i0) = seq.iter().position(|n| is_in(n)) else {
        return false;
    };
    let Some(rel) = seq[i0 + 1..].iter().position(|n| is_act(n)) else {
        return false;
    };
    let i1 = i0 + 1 + rel;
    seq[i1 + 1..].iter().any(|n| is_out(n))
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: a Governor-style contract that weights a vote by the LIVE
    // `getVotes(msg.sender)` at cast time, with no snapshot / timelock.
    const VULN: &str = r#"
        pragma solidity ^0.8.20;

        interface IToken { function getVotes(address) external view returns (uint256); }

        contract NaiveGovernor {
            IToken public token;
            mapping(uint256 => uint256) public forVotes;
            mapping(uint256 => bool) public passed;

            function castVote(uint256 proposalId, bool support) external {
                uint256 weight = token.getVotes(msg.sender);
                if (support) {
                    forVotes[proposalId] += weight;
                }
                if (forVotes[proposalId] > 1000e18) {
                    passed[proposalId] = true;
                }
            }
        }
    "#;

    // Safe: same logic but voting weight comes from a historical snapshot
    // (`getPastVotes`/`getPastTotalSupply`) — the ERC20Votes pattern.
    const SAFE: &str = r#"
        pragma solidity ^0.8.20;

        interface IToken {
            function getPastVotes(address, uint256) external view returns (uint256);
            function getPastTotalSupply(uint256) external view returns (uint256);
        }

        contract SnapshotGovernor {
            IToken public token;
            mapping(uint256 => uint256) public snapshotBlock;
            mapping(uint256 => uint256) public forVotes;
            mapping(uint256 => bool) public passed;

            function castVote(uint256 proposalId, bool support) external {
                uint256 bn = snapshotBlock[proposalId];
                uint256 weight = token.getPastVotes(msg.sender, bn);
                if (support) {
                    forVotes[proposalId] += weight;
                }
                if (forVotes[proposalId] > token.getPastTotalSupply(bn) / 2) {
                    passed[proposalId] = true;
                }
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "flashloan-governance"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "flashloan-governance"));
    }
}
