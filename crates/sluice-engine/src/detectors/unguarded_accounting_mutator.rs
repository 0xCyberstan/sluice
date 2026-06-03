//! Unguarded accounting mutator — a sibling-consensus outlier on fund accounting.
//!
//! A protocol's **accounting state** — the figures that decide share price, TVL,
//! slashed amounts, queued-withdrawal deltas, exit balances, checkpoint totals —
//! is normally written only by *permissioned* operators. When several functions in
//! the same contract write the **same** accounting variable and all but one carry
//! an access-control guard, the unguarded one is a consensus outlier: any caller
//! can move a figure the rest of the contract treats as privileged. If that figure
//! feeds the contract's pricing / redeem surface, the outlier lets an attacker skew
//! the protocol's reported value (mint cheap / redeem rich) at will.
//!
//! This is distinct from the generic *name-based* access-control detector (which
//! flags a function that writes an obviously-`owner`/`admin`-named scalar). Here the
//! signal is **sibling consensus on fund accounting**: the contract itself
//! demonstrates, through its guarded siblings, that this exact accounting variable
//! is meant to be permissioned, and one sibling forgot the guard.
//!
//! REAL instance — Renzo `OperatorDelegator`:
//!   * `emergencyTrackQueuedWithdrawals(...)`  — `onlyEmergencyWithdrawTrackingAdmin`
//!   * `emergencyTrackMissedCheckpoint(...)`   — `onlyEmergencyCheckpointTrackingAdmin`
//!   * `emergencyTrackAVSEthSlashedAmount(...)` — `onlyEmergencyTrackAVSEthSlashingAdmin`
//!   * `emergencyTrackSlashedQueuedWithdrawalDelta(bytes32[])` — **NO MODIFIER**, yet
//!     it drives `OperatorDelegatorLib.trackSlashedQueuedWithdrawalDelta(...)` over the
//!     same `queuedWithdrawal` / `queuedWithdrawalTokenInfo` storage *and*
//!     `totalTokenQueuedSharesSlashedDelta`, which `_getQueuedSharesWithSlashing`
//!     subtracts from `queuedShares` to compute the OperatorDelegator's token balance
//!     for TVL — i.e. the ezETH redeem price. Anyone can call it.
//!
//! Why accounting state is recognised through **reads as well as writes**: Renzo
//! mutates the figures by passing the storage mappings *by reference* into a
//! library (`OperatorDelegatorLib.track*`); the calling function's effect summary
//! records those mappings as `storage_reads` (the storage-pointer pass), not direct
//! writes. A non-view, externally-reachable function that hands an accounting
//! mapping to a callee is mutating it. We therefore treat a non-view function's
//! `writes ∪ reads` of accounting-named state as its accounting-mutation surface,
//! and require the same surface on a guarded sibling — the consensus anchor that
//! keeps this from firing on an ordinary getter that merely reads a balance.
//!
//! Precision anchors (all required):
//!   * the candidate is externally reachable, **state-mutating** (non-view), not an
//!     initializer/constructor, and **not** intentionally permissionless
//!     (deposit/withdraw/claim/… or a framework hook);
//!   * the candidate has **no** access-control guard (no `only*`/role modifier, no
//!     `require(msg.sender == …)`);
//!   * the candidate touches an **accounting-named** state variable
//!     (shares/slashed/delta/queued/tvl/exitBalance/checkpoint/…);
//!   * a **guarded sibling** in the same contract either touches the *same*
//!     accounting variable, or is a same-family `emergency*`/`track*` accounting
//!     mutator — the sibling-consensus signal;
//!   * **pricing/redeem taint** — at least one touched accounting variable is read
//!     by a `view`/`pure` accessor in scope (own + bases), i.e. it surfaces into a
//!     balance / TVL / price report rather than being purely internal bookkeeping.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Contract, Function, StateVar};
use std::collections::HashSet;

pub struct UnguardedAccountingMutatorDetector;

/// Name markers of protocol fund-accounting state. Deliberately the closed set the
/// CLASS calls out (shares / slashed / delta / queued / tvl / exit-balance /
/// checkpoint) plus the immediate value-bearing synonyms, so this never fires on
/// generic per-entity bookkeeping (`owner`, `nonce`, `paused`).
const ACCOUNTING_MARKERS: &[&str] = &[
    "shares",
    "slashed",
    "delta",
    "queued",
    "tvl",
    "exitbalance",
    "checkpoint",
];

/// View/pure accessor name/marker that, when it reads an accounting var, witnesses
/// the var tainting a pricing / balance / TVL / redeem surface.
const PRICING_GETTER_MARKERS: &[&str] = &[
    "price", "balance", "tvl", "value", "totalassets", "shares", "exchangerate", "rate",
    "underlying", "redeem", "withdrawable", "queued",
];

impl Detector for UnguardedAccountingMutatorDetector {
    fn id(&self) -> &'static str {
        "unguarded-accounting-mutator"
    }
    fn category(&self) -> Category {
        Category::UnguardedAccountingMutator
    }
    fn description(&self) -> &'static str {
        "Externally-reachable function mutates protocol accounting state with no guard while a sibling that touches the same state is guarded"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for contract in cx.scir.iter_contracts() {
            if contract.is_interface() || contract.is_library() {
                continue;
            }

            // State vars in scope (own + bases) that are accounting-named and not
            // constant/immutable (a `constant` can't be an outlier write target).
            let acct_vars = accounting_state_vars(cx, contract);
            if acct_vars.is_empty() {
                continue;
            }

            // Pre-compute: which accounting vars are read by a view/pure accessor in
            // scope (the pricing/redeem-taint witness set).
            let priced_vars = vars_read_by_pricing_getter(cx, contract, &acct_vars);

            // Collect every in-scope function's guarded-ness + accounting touch set.
            let fns: Vec<&Function> = scope_functions(cx, contract);

            for f in cx.scir.functions_of(contract.id) {
                if !f.has_body
                    || !f.is_externally_reachable()
                    || !f.is_state_mutating()
                    || f.is_view_or_pure()
                    || f.is_constructor()
                {
                    continue;
                }
                // A guarded / initializer / intentionally-permissionless function is
                // not the outlier.
                if cx.has_access_control(f)
                    || cx.is_initializer(f)
                    || is_user_facing(&f.name)
                    || is_framework_hook(&f.name)
                {
                    continue;
                }

                // CANDIDATE-FAMILY GATE — the precision anchor that separates an
                // administrative accounting *adjustment* (the bug) from a
                // permissionless *settlement/processing* op (intentional). The
                // candidate's name must mark it as a bookkeeping mutator
                // (`emergency*` / `track*`): these denote an admin adjustment to a
                // recorded accounting figure, which the rest of the contract guards.
                // A `clear`/`aggregate`/`claim`/`finalize`/`process` that happens to
                // touch the same figure is a different category (settlement) and is
                // commonly permissionless by design — those produced the only FPs on
                // the prior codebases (EigenLayer `clearBurnOrRedistributableShares`,
                // EtherFi `aggregateSumEEthShareAmount`).
                if accounting_family(&f.name).is_none() {
                    continue;
                }

                // Accounting vars this candidate mutates (writes, or hands by
                // reference into a callee — see module docs).
                let touched = accounting_touch(f, &acct_vars);
                if touched.is_empty() {
                    continue;
                }

                // Pricing/redeem taint: at least one touched var must surface into a
                // view pricing/balance/TVL accessor.
                if !touched.iter().any(|v| priced_vars.contains(v)) {
                    continue;
                }

                // Sibling consensus: a *guarded* sibling that touches the SAME var,
                // or a same-family (`emergency*`/`track*`) guarded accounting mutator.
                let Some((sib_name, shared_var)) = guarded_sibling(cx, &fns, f, &touched, &acct_vars)
                else {
                    continue;
                };

                let conf = 0.62;
                let b = FindingBuilder::new(self.id(), Category::UnguardedAccountingMutator)
                    .title("Accounting state mutable by anyone while a sibling guards the same state")
                    .severity(Severity::High)
                    .confidence(conf)
                    // Invariant: the sibling-consensus guard is broken on this figure.
                    // ValueFlow: the same figure taints the pricing/redeem surface, so a
                    // permissionless write reaches reported value — two corroborating
                    // dimensions, which is exactly what this class is.
                    .dimension(Dimension::Invariant)
                    .dimension(Dimension::ValueFlow)
                    .message(format!(
                        "`{}` is externally reachable and mutates protocol accounting state `{}` \
                         (a shares/slashed/delta/queued/exit-balance/checkpoint figure) but carries \
                         NO access-control guard, while its sibling `{}` in the same contract writes \
                         the same accounting state behind an authorization guard. The contract's own \
                         siblings establish that this figure is meant to be permissioned, so the \
                         unguarded function is a sibling-consensus outlier: any caller can move it. \
                         The figure feeds a view pricing/balance/TVL accessor, so manipulating it \
                         skews the protocol's reported value (e.g. the Renzo OperatorDelegator \
                         `emergencyTrackSlashedQueuedWithdrawalDelta` lacking `onlyEmergency*` while \
                         its `emergencyTrack*` siblings carry it, moving \
                         `totalTokenQueuedSharesSlashedDelta` / `queuedShares` that decide the \
                         ezETH redeem price).",
                        f.name, shared_var, sib_name
                    ))
                    .recommendation(
                        "Apply the same authorization modifier the guarded sibling uses \
                         (`onlyEmergency*`/`onlyRole`/`onlyOwner`) to the unguarded function, so \
                         the accounting figure can only be moved by the intended permissioned role.",
                    );
                out.push(cx.finish(b, f.id, f.span));
            }
        }

        out
    }
}

/// Accounting-named, non-constant/immutable state vars visible to `contract`
/// (its own declarations plus transitively-inherited bases). Returned lowercased.
fn accounting_state_vars(cx: &AnalysisContext, contract: &Contract) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut seen = HashSet::new();
    collect_acct_vars(cx, contract, &mut out, &mut seen);
    out
}

fn collect_acct_vars(
    cx: &AnalysisContext,
    contract: &Contract,
    out: &mut HashSet<String>,
    seen: &mut HashSet<String>,
) {
    if !seen.insert(contract.name.clone()) {
        return;
    }
    for v in &contract.state_vars {
        if !v.constant && !v.immutable && is_accounting_var(v) {
            out.insert(v.name.to_ascii_lowercase());
        }
    }
    for base in &contract.bases {
        if let Some(bc) = cx.scir.contract_named(base) {
            collect_acct_vars(cx, bc, out, seen);
        }
    }
}

/// A state variable whose name marks it as protocol fund accounting.
fn is_accounting_var(v: &StateVar) -> bool {
    let l = v.name.to_ascii_lowercase();
    ACCOUNTING_MARKERS.iter().any(|m| l.contains(m))
}

/// All functions visible to `contract` (own + transitive bases), so sibling-guard
/// consensus is computed over the whole inherited surface, not just the leaf file.
fn scope_functions<'a>(cx: &'a AnalysisContext, contract: &Contract) -> Vec<&'a Function> {
    let mut out: Vec<&Function> = Vec::new();
    let mut seen = HashSet::new();
    collect_scope_functions(cx, contract, &mut out, &mut seen);
    out
}

fn collect_scope_functions<'a>(
    cx: &'a AnalysisContext,
    contract: &Contract,
    out: &mut Vec<&'a Function>,
    seen: &mut HashSet<String>,
) {
    if !seen.insert(contract.name.clone()) {
        return;
    }
    for f in cx.scir.functions_of(contract.id) {
        out.push(f);
    }
    for base in &contract.bases {
        if let Some(bc) = cx.scir.contract_named(base) {
            collect_scope_functions(cx, bc, out, seen);
        }
    }
}

/// The accounting-named state vars a (non-view) function mutates. A direct write is
/// the obvious channel; a storage-pointer pass into a callee (Renzo's
/// `OperatorDelegatorLib.track*(queuedShares, …)`) is recorded as a `storage_read`
/// of the mapping but is equally a mutation, so for a non-view function we count
/// `writes ∪ reads` of accounting vars. Returned lowercased.
fn accounting_touch(f: &Function, acct_vars: &HashSet<String>) -> HashSet<String> {
    let mut out = HashSet::new();
    for w in &f.effects.storage_writes {
        let l = w.var.to_ascii_lowercase();
        if acct_vars.contains(&l) {
            out.insert(l);
        }
    }
    for r in &f.effects.storage_reads {
        let l = r.var.to_ascii_lowercase();
        if acct_vars.contains(&l) {
            out.insert(l);
        }
    }
    out
}

/// Of the candidate accounting vars, those read by some `view`/`pure` accessor in
/// scope whose name or own name marks a pricing / balance / TVL / redeem surface.
/// This is the pricing-taint witness: the figure surfaces into reported value.
fn vars_read_by_pricing_getter(
    cx: &AnalysisContext,
    contract: &Contract,
    acct_vars: &HashSet<String>,
) -> HashSet<String> {
    let mut out = HashSet::new();
    for f in scope_functions(cx, contract) {
        if !f.is_view_or_pure() {
            continue;
        }
        let fname = f.name.to_ascii_lowercase();
        let pricing_named = PRICING_GETTER_MARKERS.iter().any(|m| fname.contains(m));
        for r in &f.effects.storage_reads {
            let l = r.var.to_ascii_lowercase();
            if !acct_vars.contains(&l) {
                continue;
            }
            // Either the getter is pricing-named, or the var itself is a
            // shares/tvl/exit-balance figure (a value-bearing aggregate that, once
            // read by *any* view accessor, is part of the reported surface).
            if pricing_named || is_value_bearing(&l) {
                out.insert(l);
            }
        }
    }
    out
}

/// A var name that is intrinsically a value-bearing aggregate (so a view read of it
/// is a pricing/TVL surface regardless of the getter's name).
fn is_value_bearing(lname: &str) -> bool {
    ["shares", "tvl", "exitbalance", "balance", "assets"]
        .iter()
        .any(|m| lname.contains(m))
}

/// Find a *guarded* sibling of `f` (same contract scope, distinct, access
/// controlled, state-mutating, non-view) that either touches one of the same
/// accounting vars, or — failing an exact-var overlap — is a same-family
/// `emergency*`/`track*` accounting mutator. Returns (sibling name, shared var).
fn guarded_sibling(
    cx: &AnalysisContext,
    fns: &[&Function],
    f: &Function,
    touched: &HashSet<String>,
    acct_vars: &HashSet<String>,
) -> Option<(String, String)> {
    let f_family = accounting_family(&f.name);
    let mut family_fallback: Option<(String, String)> = None;

    for &g in fns {
        if g.id == f.id || g.is_view_or_pure() || !g.is_state_mutating() {
            continue;
        }
        if !cx.has_access_control(g) {
            continue;
        }
        let g_touch = accounting_touch(g, acct_vars);
        if g_touch.is_empty() {
            continue;
        }
        // Strongest: the guarded sibling touches the SAME accounting var. Pick the
        // lexicographically smallest shared var so the reported figure is stable
        // regardless of `HashSet` iteration order (determinism).
        if let Some(shared) = touched.iter().filter(|v| g_touch.contains(*v)).min() {
            return Some((g.name.clone(), shared.clone()));
        }
        // Fallback: same `emergency*`/`track*` accounting family. Record but keep
        // scanning for an exact-var match (preferred).
        if family_fallback.is_none()
            && f_family.is_some()
            && accounting_family(&g.name) == f_family
        {
            // Report the candidate's own touched var as the at-risk figure (the
            // lexicographically smallest, for a stable, order-independent choice).
            if let Some(v) = touched.iter().min() {
                family_fallback = Some((g.name.clone(), v.clone()));
            }
        }
    }
    family_fallback
}

/// The accounting-mutator *family* of a function name, if any: `emergency*` or
/// `track*` (the prefix the CLASS calls out). Returns a canonical family tag.
fn accounting_family(name: &str) -> Option<&'static str> {
    let l = name.to_ascii_lowercase();
    if l.starts_with("emergency") {
        Some("emergency")
    } else if l.starts_with("track") || l.contains("track") {
        Some("track")
    } else {
        None
    }
}

/// Intentionally-permissionless, user-facing function names — never the outlier.
///
/// An accounting-tracking function (`emergency*` / `track*`) is NEVER user-facing
/// even if a withdrawal/deposit *noun* appears in its name: Renzo's
/// `emergencyTrackSlashedQueuedWithdrawalDelta` is an admin bookkeeping call, not a
/// user `withdraw`. We exempt the accounting family first, then match an action verb
/// only as a leading token (so `withdraw`/`deposit` as the operation, not as an
/// embedded object noun).
fn is_user_facing(name: &str) -> bool {
    if accounting_family(name).is_some() {
        return false;
    }
    let l = name.to_ascii_lowercase();
    [
        "deposit", "withdraw", "claim", "mint", "redeem", "stake", "unstake", "swap", "borrow",
        "repay", "transfer", "approve", "permit", "wrap", "unwrap", "harvest", "compound",
        "flashloan", "liquidate", "enter", "exit", "vote", "delegate", "sweep", "rebase",
    ]
    .iter()
    .any(|k| l.starts_with(k) || l.contains(&format!("_{k}")))
}

/// Framework / standard lifecycle hooks gated by an implicit single trusted caller
/// or pure metadata — flagging them as missing access control is a false positive.
fn is_framework_hook(name: &str) -> bool {
    matches!(
        name,
        "configureDependencies"
            | "requestPermissions"
            | "supportsInterface"
            | "KEYCODE"
            | "VERSION"
            | "changeKernel"
            | "onERC721Received"
            | "onERC1155Received"
            | "onERC1155BatchReceived"
            | "tokensReceived"
            | "receive"
            | "fallback"
    )
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "unguarded-accounting-mutator")
    }

    // VULN — Renzo OperatorDelegator shape: three guarded `emergencyTrack*`
    // siblings move accounting state, one (`emergencyTrackSlashedQueuedWithdrawalDelta`)
    // forgot the guard. The figures are passed by reference into a library
    // (recorded as storage reads) and a view getter prices them.
    const VULN: &str = r#"
        interface IRoleManager { function isAdmin(address a) external view returns (bool); }
        library Lib {
            function track(bytes32[] calldata roots, mapping(address=>uint256) storage qs,
                           mapping(address=>uint256) storage d) internal {}
        }
        contract OperatorDelegator {
            IRoleManager roleManager;
            mapping(address => uint256) queuedShares;
            mapping(address => uint256) totalTokenQueuedSharesSlashedDelta;
            mapping(bytes32 => bool) queuedWithdrawal;

            modifier onlyEmergencyAdmin() {
                if (!roleManager.isAdmin(msg.sender)) revert();
                _;
            }

            // guarded sibling moving the same accounting state
            function emergencyTrackQueuedWithdrawals(bytes32[] calldata roots) external onlyEmergencyAdmin {
                Lib.track(roots, queuedShares, totalTokenQueuedSharesSlashedDelta);
            }

            // OUTLIER: no modifier, moves the same accounting state
            function emergencyTrackSlashedQueuedWithdrawalDelta(bytes32[] calldata roots) external {
                Lib.track(roots, queuedShares, totalTokenQueuedSharesSlashedDelta);
            }

            // pricing surface: TVL/redeem reads the figure
            function getTokenBalance(address u) external view returns (uint256) {
                return queuedShares[u] - totalTokenQueuedSharesSlashedDelta[u];
            }
        }
    "#;

    // VULN (direct write form): the outlier directly writes the slashed-delta var.
    const VULN_DIRECT: &str = r#"
        contract Vault {
            address owner;
            mapping(address => uint256) public queuedShares;
            uint256 public slashedDelta;
            modifier onlyOwner() { require(msg.sender == owner); _; }
            function adminSetSlashed(uint256 v) external onlyOwner { slashedDelta = v; }
            function trackSlashedDelta(uint256 v) external { slashedDelta = v; }
            function sharePrice() external view returns (uint256) { return slashedDelta + 1; }
        }
    "#;

    // SAFE (no guarded sibling): the slashed-delta mutator is unguarded, but NO
    // sibling guards the same var — there is no consensus to violate. (A genuinely
    // permissionless design, not an outlier.)
    const SAFE_NO_GUARDED_SIBLING: &str = r#"
        contract Vault {
            mapping(address => uint256) public queuedShares;
            uint256 public slashedDelta;
            function trackSlashedDelta(uint256 v) external { slashedDelta = v; }
            function bumpShares(address u, uint256 v) external { queuedShares[u] = v; }
            function sharePrice() external view returns (uint256) { return slashedDelta + 1; }
        }
    "#;

    // SAFE (the candidate is itself guarded): both functions writing the accounting
    // var carry a guard.
    const SAFE_BOTH_GUARDED: &str = r#"
        contract Vault {
            address owner;
            uint256 public slashedDelta;
            modifier onlyOwner() { require(msg.sender == owner); _; }
            function adminSetSlashed(uint256 v) external onlyOwner { slashedDelta = v; }
            function trackSlashedDelta(uint256 v) external onlyOwner { slashedDelta = v; }
            function sharePrice() external view returns (uint256) { return slashedDelta + 1; }
        }
    "#;

    // SAFE (no pricing taint): an unguarded mutator with a guarded sibling on the
    // same `checkpoint` var, but the var is never read by any view/pricing accessor
    // — pure internal bookkeeping, nothing to skew.
    const SAFE_NO_PRICING_TAINT: &str = r#"
        contract Tracker {
            address owner;
            mapping(uint64 => bool) public checkpointSeen;
            modifier onlyOwner() { require(msg.sender == owner); _; }
            function adminMarkCheckpoint(uint64 c) external onlyOwner { checkpointSeen[c] = true; }
            function markCheckpoint(uint64 c) external { checkpointSeen[c] = true; }
        }
    "#;

    // SAFE (non-accounting var): an unguarded setter for a non-accounting scalar
    // (`paused`) with a guarded sibling — not fund accounting, so out of scope here
    // (the name-based access-control detector owns that).
    const SAFE_NON_ACCOUNTING: &str = r#"
        contract Vault {
            address owner;
            bool public paused;
            uint256 public shares;
            modifier onlyOwner() { require(msg.sender == owner); _; }
            function adminPause(bool v) external onlyOwner { paused = v; }
            function setPaused(bool v) external { paused = v; }
            function sharePrice() external view returns (uint256) { return shares + 1; }
        }
    "#;

    #[test]
    fn fires_on_renzo_emergency_track_shape() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_direct_write_outlier() {
        assert!(fires(VULN_DIRECT), "{:#?}", run(VULN_DIRECT));
    }

    #[test]
    fn silent_without_guarded_sibling() {
        assert!(!fires(SAFE_NO_GUARDED_SIBLING), "{:#?}", run(SAFE_NO_GUARDED_SIBLING));
    }

    #[test]
    fn silent_when_both_guarded() {
        assert!(!fires(SAFE_BOTH_GUARDED), "{:#?}", run(SAFE_BOTH_GUARDED));
    }

    #[test]
    fn silent_without_pricing_taint() {
        assert!(!fires(SAFE_NO_PRICING_TAINT), "{:#?}", run(SAFE_NO_PRICING_TAINT));
    }

    #[test]
    fn silent_on_non_accounting_var() {
        assert!(!fires(SAFE_NON_ACCOUNTING), "{:#?}", run(SAFE_NON_ACCOUNTING));
    }
}
