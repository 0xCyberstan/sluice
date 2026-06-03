//! MasterChef-style reward-accounting hazard: a staking function mutates a
//! user's staked balance (`amount` / `balance` / `staked`) WITHOUT first
//! settling pending rewards or updating the pool accumulator.
//!
//! The canonical MasterChef bookkeeping is:
//! ```solidity
//! function deposit(uint256 amount) external {
//!     updatePool();                                  // (1) bring accRewardPerShare current
//!     UserInfo storage u = userInfo[msg.sender];
//!     if (u.amount > 0) {
//!         uint256 pending = u.amount * accRewardPerShare / 1e12 - u.rewardDebt;
//!         safeRewardTransfer(msg.sender, pending);   // (2) settle pending
//!     }
//!     u.amount += amount;                            // (3) mutate balance
//!     u.rewardDebt = u.amount * accRewardPerShare / 1e12;  // (4) re-baseline debt
//! }
//! ```
//! Reward = `balance * accRewardPerShare - rewardDebt`. The accumulator
//! (`accRewardPerShare` / `rewardPerToken`) only moves forward in time, and
//! `rewardDebt` is the user's snapshot of it at their last interaction. If a
//! function changes `balance` but skips step (1)/(2) or forgets to re-baseline
//! `rewardDebt` (step 4), the snapshot no longer matches the new balance:
//!   * increasing `balance` without re-baselining lets the user claim rewards
//!     on tokens they only just deposited (theft);
//!   * decreasing `balance` without settling first strands the rewards the
//!     position had already accrued, or — if the accumulator wasn't refreshed —
//!     pays the wrong amount to everyone.
//! This is the SushiSwap-MasterChef / Pickle-Jar class of accounting bug.
//!
//! Precision: we only consider contracts that *are* reward stakers — they must
//! declare a per-share reward accumulator (`accRewardPerShare` / `rewardPerToken`
//! / `accumulatedRewardPerShare` ...). We suppress any function that calls an
//! update/settle routine or adjusts `rewardDebt` itself, since those are exactly
//! the safe shapes above.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Contract, Function};

pub struct RewardDebtDetector;

/// Substrings that identify a per-share reward accumulator — the state variable
/// that makes a contract a MasterChef/Synthetix-style reward staker. Without one
/// there is no reward-debt invariant to violate, so the detector stays silent.
const ACCUMULATOR_MARKERS: &[&str] = &[
    "accrewardpershare",
    "accrewardspershare",
    "accumulatedrewardpershare",
    "acctokenpershare",
    "rewardpertoken",
    "rewardspertoken",
    "accpershare",
    "rewardpershare",
];

/// Names of update/settle routines whose presence (as an internal call, or
/// mentioned in the function source) means rewards are being brought current
/// before the balance is touched.
const SETTLE_MARKERS: &[&str] = &[
    "updatepool",
    "_updatepool",
    "harvest",
    "_harvest",
    "updatereward",
    "_updatereward",
    "settle",
];

/// State-variable name fragments that represent a user's staked principal — the
/// quantity that must not move ahead of a reward settlement.
fn is_stake_balance_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // Deliberately scoped to staking principal. `rewarddebt` and accumulator
    // vars are excluded so that re-baselining writes don't themselves trip the
    // "balance changed" signal.
    if l.contains("rewarddebt") || l.contains("pershare") || l.contains("pertoken") {
        return false;
    }
    l.contains("amount") || l.contains("balance") || l.contains("staked") || l.contains("stake") || l.contains("deposit")
}

impl Detector for RewardDebtDetector {
    fn id(&self) -> &'static str {
        "reward-debt"
    }
    fn category(&self) -> Category {
        Category::RewardAccounting
    }
    fn description(&self) -> &'static str {
        "MasterChef stake balance changed without settling pending rewards / updating the accumulator"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for c in cx.scir.iter_contracts() {
            // Only reward stakers carry a reward-debt invariant. An interface
            // declaration has nothing to settle.
            if !c.is_concrete() || !has_reward_accumulator(c) {
                continue;
            }

            for f in cx.scir.functions_of(c.id) {
                if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
                    continue;
                }

                // It must change a staked-balance state variable.
                if !f.effects.written_vars().iter().any(|v| is_stake_balance_name(v)) {
                    continue;
                }

                // ---- false-positive suppression (precision first) ----
                let calls_settle_routine = f
                    .effects
                    .internal_calls
                    .iter()
                    .any(|n| settle_like(n));
                if calls_settle_routine {
                    continue;
                }

                // Source-level checks: a settle routine called through a path the
                // effect summary didn't resolve as an internal call, OR the
                // function re-baselines `rewardDebt` (the step-4 write) itself.
                let src = cx.scir.span_text(f.span).to_ascii_lowercase();
                if SETTLE_MARKERS.iter().any(|m| src.contains(m)) {
                    continue;
                }
                // `rewardDebt = ...` (any assignment, incl. `+=`/`-=`) in this
                // function means the snapshot is being adjusted alongside the
                // balance — the safe pattern.
                if mentions_reward_debt_assignment(&src) {
                    continue;
                }

                let span = stake_write_span(f).unwrap_or(f.span);
                let b = FindingBuilder::new(self.id(), Category::RewardAccounting)
                    .title("Stake balance changed without settling pending rewards")
                    .severity(Severity::Medium)
                    .confidence(0.5)
                    .dimension(Dimension::Invariant)
                    .message(format!(
                        "`{}` changes a staked-balance state variable but neither updates the pool \
                         accumulator / settles pending rewards first (no `updatePool` / `harvest` / \
                         `updateReward` / `settle` call) nor re-baselines `rewardDebt` in the same \
                         function. In MasterChef-style accounting, reward owed = `balance * \
                         accRewardPerShare - rewardDebt`; moving `balance` while that snapshot is \
                         stale lets a user claim rewards on freshly deposited tokens (theft) or \
                         strands rewards already accrued — the SushiSwap-MasterChef / Pickle class.",
                        f.name
                    ))
                    .recommendation(
                        "Before mutating the staked balance, call the pool-update routine \
                         (`updatePool()` / `updateReward()`) and pay out pending rewards, then set \
                         `rewardDebt = newBalance * accRewardPerShare / PRECISION` after the change.",
                    );
                out.push(cx.finish(b, f.id, span));
            }
        }
        out
    }
}

/// The contract declares a per-share reward accumulator state variable.
fn has_reward_accumulator(c: &Contract) -> bool {
    c.state_vars.iter().any(|v| {
        let l = v.name.to_ascii_lowercase();
        ACCUMULATOR_MARKERS.iter().any(|m| l.contains(m))
    })
}

/// An internal-call name that looks like an update/settle routine.
fn settle_like(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    SETTLE_MARKERS.iter().any(|m| l.contains(m))
}

/// Best-effort detection of a `rewardDebt = ...` (or `+=` / `-=`) assignment in
/// lowercased function source. We look for the identifier immediately followed
/// (allowing a mapping/member access and whitespace) by an `=` that is not a
/// comparison.
fn mentions_reward_debt_assignment(src: &str) -> bool {
    let needle = "rewarddebt";
    let bytes = src.as_bytes();
    let mut from = 0;
    while let Some(rel) = src[from..].find(needle) {
        let start = from + rel;
        let mut i = start + needle.len();
        // Skip an optional index/member tail: `rewardDebt[...]` or `.rewardDebt`
        // already handled (needle is the member); allow trailing index bracket.
        if i < bytes.len() && bytes[i] == b'[' {
            // skip to matching ']'
            while i < bytes.len() && bytes[i] != b']' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1; // consume ']'
            }
        }
        // Skip whitespace.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'=' {
            // Exclude `==` (comparison); `+=`/`-=`/`*=` handled because the op
            // char precedes `=` and we don't require the preceding char to be a
            // space — but a bare `=` here is an assignment.
            let is_eq_eq = i + 1 < bytes.len() && bytes[i + 1] == b'=';
            if !is_eq_eq {
                return true;
            }
        }
        from = start + needle.len();
    }
    false
}

/// Span of the first storage write to a stake-balance variable (for a precise
/// report location), falling back to the function span.
fn stake_write_span(f: &Function) -> Option<sluice_ir::Span> {
    f.effects
        .storage_writes
        .iter()
        .filter(|w| is_stake_balance_name(&w.var))
        .min_by_key(|w| w.order)
        .map(|w| w.span)
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: a reward staker (declares `accRewardPerShare`) whose `deposit`
    // increases the user's staked `amount` but never calls `updatePool` / settles
    // and never re-baselines `rewardDebt`. The next harvest pays rewards on the
    // just-deposited tokens.
    const VULN: &str = r#"
        contract MasterChef {
            struct UserInfo { uint256 amount; uint256 rewardDebt; }
            mapping(address => UserInfo) public userInfo;
            uint256 public accRewardPerShare;
            uint256 public totalStaked;

            function updatePool() public {
                accRewardPerShare += 1;
            }

            function deposit(uint256 _amount) external {
                UserInfo storage u = userInfo[msg.sender];
                u.amount += _amount;
                totalStaked += _amount;
            }
        }
    "#;

    // Safe: same staker, but `deposit` calls `updatePool()` to bring the
    // accumulator current and re-baselines `rewardDebt` after changing `amount`.
    const SAFE: &str = r#"
        contract MasterChef {
            struct UserInfo { uint256 amount; uint256 rewardDebt; }
            mapping(address => UserInfo) public userInfo;
            uint256 public accRewardPerShare;
            uint256 public totalStaked;
            uint256 internal constant PRECISION = 1e12;

            function updatePool() public {
                accRewardPerShare += 1;
            }

            function deposit(uint256 _amount) external {
                updatePool();
                UserInfo storage u = userInfo[msg.sender];
                if (u.amount > 0) {
                    uint256 pending = u.amount * accRewardPerShare / PRECISION - u.rewardDebt;
                    // pay pending ...
                }
                u.amount += _amount;
                totalStaked += _amount;
                u.rewardDebt = u.amount * accRewardPerShare / PRECISION;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "reward-debt"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "reward-debt"));
    }
}
