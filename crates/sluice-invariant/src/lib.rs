//! # sluice-invariant
//!
//! **Consensus-invariant mining** — the smart-contract analog of `vortex`'s
//! ghost-state detection, and Sluice's signature differentiator. Most static
//! analyzers look for *known anti-patterns*. This pass instead learns each
//! contract's *implicit invariants* from the agreement among its sibling
//! functions, then flags the function that breaks consensus:
//!
//! * **Guard consensus** — if most state-mutating entry points enforce an
//!   access-control / reentrancy-lock / pause guard, the one that doesn't is
//!   suspicious (the missing-`onlyOwner` class).
//! * **Co-update consensus** — if writing `totalSupply` is almost always
//!   accompanied by writing `balances` (or `totalAssets` with `totalShares`),
//!   a function that updates one without the other is an accounting-drift bug.
//! * **Settlement-before-mutation** — if most balance-reducing / transferring
//!   functions first call a `_healthCheck` / `accrue` / `updateReward` routine,
//!   the one that skips it is the Euler-class missing-solvency-check bug.
//!
//! This is "the developer assumed this path was dead / always guarded" turned
//! into a detector, exactly as ghost-state analysis is for binaries.

use rustc_hash::{FxHashMap, FxHashSet};
use sluice_ir::{CallKind, ContractId, Function, FunctionId, GuardKind, Scir, Span};

/// Minimum peer-group size before consensus is meaningful.
const MIN_PEERS: usize = 3;

#[derive(Debug, Clone, PartialEq)]
pub enum InvariantKind {
    /// Most peers enforce a guard (`access-control`, `reentrancy-lock`, `pause`).
    GuardConsensus { guard: String },
    /// Writing `primary` is almost always paired with writing `expected`.
    CoUpdate { primary: String, expected: String },
    /// Most risky peers call a settlement/solvency routine before mutating.
    SettlementBeforeMutation { routine: String },
}

impl InvariantKind {
    pub fn slug(&self) -> &'static str {
        match self {
            InvariantKind::GuardConsensus { .. } => "guard-consensus",
            InvariantKind::CoUpdate { .. } => "co-update",
            InvariantKind::SettlementBeforeMutation { .. } => "settlement",
        }
    }
}

/// A mined invariant: a property that holds across most peers in a contract.
#[derive(Debug, Clone)]
pub struct MinedInvariant {
    pub contract: ContractId,
    pub kind: InvariantKind,
    /// Fraction of peers that satisfy the invariant (the consensus strength).
    pub support: f32,
    pub peers: usize,
    pub description: String,
}

/// A function that breaks a mined invariant.
#[derive(Debug, Clone)]
pub struct InvariantViolation {
    pub function: FunctionId,
    pub contract: ContractId,
    pub kind: InvariantKind,
    /// Consensus strength of the violated invariant (how many peers satisfy it).
    pub consensus: f32,
    pub description: String,
    pub span: Span,
}

#[derive(Debug, Default)]
pub struct InvariantFacts {
    pub invariants: Vec<MinedInvariant>,
    pub violations: Vec<InvariantViolation>,
}

impl InvariantFacts {
    pub fn mine(scir: &Scir) -> Self {
        let mut facts = InvariantFacts::default();
        for c in scir.iter_contracts() {
            if !c.is_concrete() {
                continue;
            }
            let peers: Vec<&Function> = scir
                .functions_of(c.id)
                .filter(|f| {
                    f.has_body && f.is_externally_reachable() && f.is_state_mutating() && !f.is_constructor()
                })
                .collect();
            if peers.len() < MIN_PEERS {
                continue;
            }
            mine_guard_consensus(c.id, &peers, &mut facts);
            mine_co_update(c.id, &peers, &mut facts);
            mine_settlement(scir, c.id, &peers, &mut facts);
        }
        facts
    }

    pub fn violations_for(&self, fid: FunctionId) -> impl Iterator<Item = &InvariantViolation> {
        self.violations.iter().filter(move |v| v.function == fid)
    }

    pub fn has_violation(&self, fid: FunctionId) -> bool {
        self.violations.iter().any(|v| v.function == fid)
    }
}

// ----------------------------------------------------------- guard consensus

fn guard_features(f: &Function) -> FxHashSet<&'static str> {
    let mut set = FxHashSet::default();
    for g in &f.effects.guards {
        match &g.kind {
            GuardKind::MsgSenderCheck => {
                set.insert("access-control");
            }
            GuardKind::ReentrancyLock => {
                set.insert("reentrancy-lock");
            }
            GuardKind::PauseCheck => {
                set.insert("pause");
            }
            _ => {}
        }
    }
    set
}

fn mine_guard_consensus(cid: ContractId, peers: &[&Function], facts: &mut InvariantFacts) {
    let n = peers.len();
    let threshold = if n < 6 { 0.66 } else { 0.75 };
    for feature in ["access-control", "reentrancy-lock", "pause"] {
        let holders: Vec<&&Function> = peers.iter().filter(|f| guard_features(f).contains(feature)).collect();
        let support = holders.len() as f32 / n as f32;
        if support < threshold || support >= 1.0 {
            continue;
        }
        facts.invariants.push(MinedInvariant {
            contract: cid,
            kind: InvariantKind::GuardConsensus { guard: feature.to_string() },
            support,
            peers: n,
            description: format!("{:.0}% of state-mutating entry points enforce `{feature}`", support * 100.0),
        });
        for f in peers {
            if !guard_features(f).contains(feature) {
                facts.violations.push(InvariantViolation {
                    function: f.id,
                    contract: cid,
                    kind: InvariantKind::GuardConsensus { guard: feature.to_string() },
                    consensus: support,
                    description: format!(
                        "`{}` does not enforce `{feature}`, which {:.0}% of its sibling \
                         state-mutating functions do",
                        f.name,
                        support * 100.0
                    ),
                    span: f.span,
                });
            }
        }
    }
}

// --------------------------------------------------------------- co-update

fn mine_co_update(cid: ContractId, peers: &[&Function], facts: &mut InvariantFacts) {
    // writer set per variable
    let mut writers: FxHashMap<String, FxHashSet<FunctionId>> = FxHashMap::default();
    for f in peers {
        for v in f.effects.written_vars() {
            writers.entry(v.to_string()).or_default().insert(f.id);
        }
    }
    let vars: Vec<&String> = writers.keys().filter(|v| writers[*v].len() >= 2).collect();
    for i in 0..vars.len() {
        for j in 0..vars.len() {
            if i == j {
                continue;
            }
            let a = vars[i];
            let b = vars[j];
            let wa = &writers[a];
            let wb = &writers[b];
            let co = wa.intersection(wb).count();
            if co < 2 {
                continue;
            }
            let support = co as f32 / wa.len() as f32;
            // `b` accompanies `a` in most functions that write `a`, but not all.
            if support >= 0.66 && support < 1.0 {
                facts.invariants.push(MinedInvariant {
                    contract: cid,
                    kind: InvariantKind::CoUpdate { primary: a.clone(), expected: b.clone() },
                    support,
                    peers: wa.len(),
                    description: format!(
                        "writing `{a}` is paired with writing `{b}` in {:.0}% of cases",
                        support * 100.0
                    ),
                });
                for f in peers {
                    if wa.contains(&f.id) && !wb.contains(&f.id) {
                        facts.violations.push(InvariantViolation {
                            function: f.id,
                            contract: cid,
                            kind: InvariantKind::CoUpdate { primary: a.clone(), expected: b.clone() },
                            consensus: support,
                            description: format!(
                                "`{}` updates `{a}` without updating `{b}`; sibling functions update \
                                 them together {:.0}% of the time (accounting drift)",
                                f.name,
                                support * 100.0
                            ),
                            span: f.span,
                        });
                    }
                }
            }
        }
    }
}

// --------------------------------------------------------------- settlement

fn is_settlement_routine(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("health")
        || l.contains("solven")
        || l.contains("ishealthy")
        || l.contains("checkaccount")
        || l.contains("accrue")
        || l.contains("updatepool")
        || l.contains("updatereward")
        || l.contains("settle")
        || l.contains("checkpoint")
        || l.contains("requirecollateral")
        || l.contains("validatehealth")
}

/// A function is "risky" if it transfers value or reduces a balance-like var.
fn is_risky(f: &Function) -> bool {
    let does_transfer = f
        .effects
        .call_sites
        .iter()
        .any(|c| c.sends_value || matches!(c.kind, CallKind::External | CallKind::Transfer | CallKind::Send));
    let touches_balance = f.effects.written_vars().iter().any(|v| {
        let l = v.to_ascii_lowercase();
        l.contains("balance") || l.contains("debt") || l.contains("collateral") || l.contains("share")
            || l.contains("deposit") || l.contains("borrow")
    });
    does_transfer || touches_balance
}

fn mine_settlement(_scir: &Scir, cid: ContractId, peers: &[&Function], facts: &mut InvariantFacts) {
    let risky: Vec<&&Function> = peers.iter().filter(|f| is_risky(f)).collect();
    if risky.len() < MIN_PEERS {
        return;
    }
    // Candidate settlement routines = internal calls that look like settlement.
    let mut routine_callers: FxHashMap<String, FxHashSet<FunctionId>> = FxHashMap::default();
    for f in &risky {
        for call in &f.effects.internal_calls {
            if is_settlement_routine(call) {
                routine_callers.entry(call.clone()).or_default().insert(f.id);
            }
        }
    }
    let n = risky.len();
    let threshold = if n < 6 { 0.6 } else { 0.7 };
    for (routine, callers) in &routine_callers {
        let support = callers.len() as f32 / n as f32;
        if support < threshold || support >= 1.0 {
            continue;
        }
        facts.invariants.push(MinedInvariant {
            contract: cid,
            kind: InvariantKind::SettlementBeforeMutation { routine: routine.clone() },
            support,
            peers: n,
            description: format!(
                "{:.0}% of value-moving functions call `{routine}()` before mutating state",
                support * 100.0
            ),
        });
        for f in &risky {
            if !callers.contains(&f.id) {
                facts.violations.push(InvariantViolation {
                    function: f.id,
                    contract: cid,
                    kind: InvariantKind::SettlementBeforeMutation { routine: routine.clone() },
                    consensus: support,
                    description: format!(
                        "`{}` moves value / changes balances but does not call `{routine}()`, which \
                         {:.0}% of its sibling risky functions call (Euler-class missing check)",
                        f.name,
                        support * 100.0
                    ),
                    span: f.span,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mine(src: &str) -> (Scir, InvariantFacts) {
        let scir = sluice_parse::parse_sources(vec![("t.sol".into(), src.into())]).scir;
        let facts = InvariantFacts::mine(&scir);
        (scir, facts)
    }

    #[test]
    fn finds_missing_solvency_check() {
        // Three of four risky functions call _checkHealth(); withdraw() does not.
        let (scir, facts) = mine(
            r#"
            contract Lending {
                mapping(address => uint256) collateral;
                mapping(address => uint256) debt;
                function _checkHealth(address u) internal {}
                function borrow(uint256 a) external { debt[msg.sender] += a; _checkHealth(msg.sender); }
                function liquidate(address u) external { collateral[u] -= 1; _checkHealth(u); }
                function donate(address u) external { collateral[u] += 1; _checkHealth(u); }
                function withdraw(uint256 a) external { collateral[msg.sender] -= a; }
            }
            "#,
        );
        let withdraw = scir.all_functions().find(|f| f.name == "withdraw").unwrap();
        assert!(
            facts.violations_for(withdraw.id).any(|v| matches!(v.kind, InvariantKind::SettlementBeforeMutation { .. })),
            "expected withdraw to violate settlement consensus; violations: {:?}",
            facts.violations.iter().map(|v| &v.description).collect::<Vec<_>>()
        );
    }
}
