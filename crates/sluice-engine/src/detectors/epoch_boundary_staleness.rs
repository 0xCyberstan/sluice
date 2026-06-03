//! Epoch-boundary staleness — a live quantity used where the *same* quantity has
//! an epoch/snapshot-captured accessor that the protocol's invariant requires.
//!
//! Restaking / staking / governance protocols organized around **epochs** (or
//! capture timestamps / snapshots) establish a rule: the figure that decides
//! slashing power, voting weight, or a reward share must be the value **captured
//! at the epoch boundary** (the moment the epoch was sealed), not the value as it
//! stands *right now*. The captured value cannot be moved once the epoch is
//! fixed; the live value can be pumped or drained inside the epoch with a
//! flash-deposit / flash-withdraw and reverted in the same block.
//!
//! The canonical instance is Symbiotic's `Vault.onSlash(amount, captureTimestamp)`:
//! it validates the epoch with `epochAt(captureTimestamp)`, yet computes the
//! slashable amount from the **live** `activeStake()` rather than
//! `activeStakeAt(captureTimestamp, hint)` — the captured accessor the vault
//! itself exposes. An operator who is being slashed for an old epoch can change
//! the *current* active stake between capture and the slash call.
//!
//! Precision anchor (the thing that distinguishes a real epoch-staleness bug from
//! an ordinary live read): the live quantity must be the **same quantity for which
//! the contract provides an epoch/snapshot-captured accessor**. We require, for
//! the live name `X` consumed in a decision, that the contract (its own functions
//! *plus inherited ones*) defines a **captured sibling** of `X` — a function named
//! like `X` + `At` (Symbiotic `activeStakeAt`, OZ-Snapshot `totalSupplyAt`) or the
//! `getPast<X>` form (OZ `getVotes` → `getPastVotes`) — that takes a
//! timestamp/epoch/snapshot/block parameter. This is strictly stronger than "the
//! contract mentions `epoch` somewhere": a vault that snapshots `activeStake` but
//! reads it live is flagged, whereas a staking contract whose `rebase` reads
//! `token.balanceOf(this)` — for which there is *no* `balanceOfAt` snapshot — is
//! not, even though it has an `epoch` struct.
//!
//! Additional gates (all required):
//!   * the consuming function is **state-mutating and externally reachable** and
//!     **uses** the live read in a `require`/branch/assignment (a decision), not
//!     merely forwards it from a getter;
//!   * the consuming function is **not** itself the captured accessor;
//!   * the specific decision read is the **live** variant, not the captured one
//!     (`activeStakeAt(...)` / `getPastVotes(...)` reads are the safe form and are
//!     never flagged).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Contract, Expr, ExprKind, Function};
use std::collections::HashSet;

pub struct EpochBoundaryStalenessDetector;

/// Capture-shaped parameter names / types: a captured accessor takes one of these
/// so the caller pins the read to a boundary.
const CAPTURE_PARAM_NAMES: &[&str] =
    &["timestamp", "epoch", "snapshot", "blocknumber", "blockno", "captureat", "pointat", "ts"];
const CAPTURE_PARAM_TYPES: &[&str] = &["uint48", "uint32"]; // common epoch/timestamp widths

/// Live / current / latest accessors for a stake-like, supply-like, or
/// voting-power-like quantity. Reading one of these *is* the manipulable read when
/// the protocol's invariant wants the epoch-captured value. Deliberately a closed,
/// stake/governance-shaped set so this never fires on unrelated `current*` helpers.
const LIVE_ACCESSORS: &[&str] = &[
    "activestake",
    "activeshares",
    "activesharesof",
    "activebalanceof",
    "totalstake",
    "currentstake",
    "totalsupply",
    "totalassets",
    "getvotes",
    "votingpower",
    "totalvotes",
];

impl Detector for EpochBoundaryStalenessDetector {
    fn id(&self) -> &'static str {
        "epoch-boundary-staleness"
    }
    fn category(&self) -> Category {
        Category::EpochBoundaryStaleness
    }
    fn description(&self) -> &'static str {
        "Live/current quantity used for a decision where the same quantity has an epoch/snapshot-captured accessor"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for contract in cx.scir.iter_contracts() {
            // Interfaces and libraries declare no consuming logic.
            if contract.is_interface() || contract.is_library() {
                continue;
            }

            // Collect, across this contract *and its inherited bases*, the set of
            // live accessor names for which a captured sibling exists. This is the
            // core precision gate: only a live read of one of THESE names can be a
            // staleness bug, because only these are quantities the protocol seals
            // at an epoch/snapshot boundary. (In Symbiotic, `onSlash` lives in
            // `Vault` while `activeStakeAt` lives in the inherited `VaultStorage`,
            // so the base walk is essential.)
            let captured_live_names = captured_live_quantities(cx, contract);
            if captured_live_names.is_empty() {
                continue;
            }

            for f in cx.scir.functions_of(contract.id) {
                if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
                    continue;
                }
                // A view/pure getter that surfaces the live value is not the bug;
                // `is_state_mutating` already excludes those, but be explicit.
                if f.is_view_or_pure() {
                    continue;
                }
                // SUPPRESS: a function that is itself a captured accessor (its own
                // name is the captured form) is the capture path, not a victim.
                if is_captured_accessor_name(&f.name) {
                    continue;
                }

                // Find a live-accessor read that (a) is *used* in a decision and
                // (b) names a quantity for which a captured sibling exists.
                let Some((span, accessor)) = first_live_decision_read(f, &captured_live_names) else {
                    continue;
                };

                let b = FindingBuilder::new(self.id(), Category::EpochBoundaryStaleness)
                    .title("Live quantity used where an epoch/snapshot-captured value is required")
                    .severity(Severity::Medium)
                    .confidence(0.5)
                    .dimension(Dimension::Invariant)
                    .message(format!(
                        "`{}` reads `{}` at the current/latest block and uses it in a decision \
                         (require / branch / assignment), while the contract exposes an \
                         epoch/snapshot-captured accessor for the *same* quantity \
                         (`{}At(...)` / `getPast{}` taking a timestamp/epoch/block argument). When \
                         the protocol's invariant is the epoch-captured figure, consuming the live \
                         one is manipulable *within* the epoch: an attacker can flash-deposit to \
                         inflate (or flash-withdraw to deflate) the stake/supply/voting weight in \
                         the same transaction, skew the slashing power / vote / reward share, and \
                         unwind — the epoch-boundary staleness class. (Symbiotic `onSlash` validates \
                         `epochAt(captureTimestamp)` but slashes against the live `activeStake()` \
                         instead of `activeStakeAt(captureTimestamp)`.)",
                        f.name, accessor, accessor, accessor
                    ))
                    .recommendation(
                        "Read the quantity at the epoch's capture point, not live: use the \
                         epoch-keyed accessor the contract already provides \
                         (`activeStakeAt(captureTimestamp, hint)`, `getPastVotes(epochBlock)`, a \
                         snapshot id) so the value is fixed for the epoch and cannot be \
                         flash-manipulated between capture and use.",
                    );
                out.push(cx.finish(b, f.id, span));
            }
        }

        out
    }
}

/// The set of live-accessor names (lowercased) for which the contract — its own
/// functions *and inherited ones* — provides a captured sibling. A captured
/// sibling of live name `X` is an in-scope function `g` such that:
///   * `g` takes a capture-shaped parameter (timestamp / epoch / snapshot / block,
///     or a `uint48`/`uint32` width), AND
///   * `g.name` is the captured form of `X`: `X + "At"` (Symbiotic `activeStakeAt`,
///     OZ-Snapshot `totalSupplyAt`) or the `getPast`-substituted form
///     (`getVotes` → `getPastVotes`).
/// Returning the *live* names (not the captured ones) lets the decision-read scan
/// match directly on what a buggy function actually calls.
fn captured_live_quantities(cx: &AnalysisContext, contract: &Contract) -> HashSet<String> {
    // 1. Gather every in-scope function name (own + transitive bases).
    let mut scope_fn_names: Vec<String> = Vec::new();
    collect_scope_function_names(cx, contract, &mut scope_fn_names, &mut HashSet::new());

    // 2. Also remember, for each in-scope function, whether it takes a capture
    //    param — a captured sibling must.
    let mut capture_param_fns: HashSet<String> = HashSet::new();
    collect_capture_param_fn_names(cx, contract, &mut capture_param_fns, &mut HashSet::new());

    // 3. For every live accessor that is a *plausible* captured form present in
    //    scope, record the corresponding live name.
    let mut out: HashSet<String> = HashSet::new();
    for live in LIVE_ACCESSORS {
        let live = *live;
        // Candidate captured-sibling names for this live accessor.
        let at_form = format!("{live}at");
        let getpast_form = live
            .strip_prefix("get")
            .map(|rest| format!("getpast{rest}"));

        let has_at = scope_fn_names
            .iter()
            .any(|n| n.to_ascii_lowercase() == at_form && capture_param_fns.contains(&n.to_ascii_lowercase()));
        let has_getpast = getpast_form.as_ref().is_some_and(|gp| {
            scope_fn_names
                .iter()
                .any(|n| n.to_ascii_lowercase() == *gp && capture_param_fns.contains(&n.to_ascii_lowercase()))
        });

        if has_at || has_getpast {
            out.insert(live.to_string());
        }
    }
    out
}

/// Collect the names of all functions visible to `contract` (own + transitively
/// inherited), by walking `bases` through `contract_named`.
fn collect_scope_function_names(
    cx: &AnalysisContext,
    contract: &Contract,
    out: &mut Vec<String>,
    seen: &mut HashSet<String>,
) {
    if !seen.insert(contract.name.clone()) {
        return;
    }
    for f in cx.scir.functions_of(contract.id) {
        out.push(f.name.clone());
    }
    for base in &contract.bases {
        if let Some(bc) = cx.scir.contract_named(base) {
            collect_scope_function_names(cx, bc, out, seen);
        }
    }
}

/// Collect (lowercased) names of in-scope functions that take a capture-shaped
/// parameter — the necessary condition for a function to be a captured accessor.
fn collect_capture_param_fn_names(
    cx: &AnalysisContext,
    contract: &Contract,
    out: &mut HashSet<String>,
    seen: &mut HashSet<String>,
) {
    if !seen.insert(contract.name.clone()) {
        return;
    }
    for f in cx.scir.functions_of(contract.id) {
        if function_takes_capture_param(f) {
            out.insert(f.name.to_ascii_lowercase());
        }
    }
    for base in &contract.bases {
        if let Some(bc) = cx.scir.contract_named(base) {
            collect_capture_param_fn_names(cx, bc, out, seen);
        }
    }
}

/// Does `f` accept a capture-shaped parameter (a timestamp/epoch/snapshot/block by
/// name, or a `uint48`/`uint32` by type)? Required of any captured accessor.
fn function_takes_capture_param(f: &Function) -> bool {
    f.params.iter().any(|p| {
        let lname = p.name.as_deref().unwrap_or("").to_ascii_lowercase();
        let lty = p.ty.to_ascii_lowercase();
        let name_hit = !lname.is_empty() && CAPTURE_PARAM_NAMES.iter().any(|m| lname.contains(m));
        let type_hit = CAPTURE_PARAM_TYPES.iter().any(|t| lty == *t);
        name_hit || type_hit
    })
}

/// `name` is itself a captured-accessor name (the safe form): it carries a capture
/// marker (`getPast*`, `*snapshot*`) or ends in the `At` suffix while starting with
/// a known live-accessor root (`activeStakeAt`, `totalSupplyAt`).
fn is_captured_accessor_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    if l.contains("getpast") || l.contains("snapshot") || l.contains("pointat") {
        return true;
    }
    // `...At` suffix over a live-accessor root.
    if l.ends_with("at") && LIVE_ACCESSORS.iter().any(|a| l.starts_with(a)) {
        return true;
    }
    false
}

/// STRUCTURAL GATE: the first read of a live accessor — *restricted to the live
/// names that have a captured sibling* — that is *used* in a decision (a
/// `require`/`assert`, an `if`/`while`/`for`/`do-while` condition, or an
/// assignment / var-decl initializer). Returns the span of the using statement and
/// the matched accessor name. Requiring genuine *use* is the second precision
/// anchor: a getter that merely surfaces the live value is not the bug.
fn first_live_decision_read(
    f: &Function,
    captured_live_names: &HashSet<String>,
) -> Option<(sluice_ir::Span, String)> {
    let mut hit: Option<(sluice_ir::Span, String)> = None;

    for s in &f.body {
        s.visit(&mut |st| {
            if hit.is_some() {
                return;
            }
            use sluice_ir::StmtKind;
            match &st.kind {
                // Used in a control-flow decision.
                StmtKind::If { cond, .. }
                | StmtKind::While { cond, .. }
                | StmtKind::DoWhile { cond, .. } => {
                    if let Some(a) = expr_reads_live_accessor(cond, captured_live_names) {
                        hit = Some((st.span, a));
                    }
                }
                StmtKind::For { cond: Some(cond), .. } => {
                    if let Some(a) = expr_reads_live_accessor(cond, captured_live_names) {
                        hit = Some((st.span, a));
                    }
                }
                // Used in a `require(...)` / `assert(...)` or assigned into state /
                // a local that then drives the decision.
                StmtKind::Expr(e) => {
                    if let Some(a) = require_or_assign_uses_live(e, captured_live_names) {
                        hit = Some((st.span, a));
                    }
                }
                // `uint256 power = activeStake();` — captured into a local that the
                // function will branch/compute on. The decisive use of the live
                // value starts here, so this is a fair anchor.
                StmtKind::VarDecl { init: Some(e), .. } => {
                    if let Some(a) = expr_reads_live_accessor(e, captured_live_names) {
                        hit = Some((st.span, a));
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

/// A `require`/`assert` whose args read a live accessor, or an assignment whose
/// value reads a live accessor.
fn require_or_assign_uses_live(e: &Expr, names: &HashSet<String>) -> Option<String> {
    if let ExprKind::Call(c) = &e.kind {
        use sluice_ir::{Builtin, CallKind};
        if matches!(
            c.kind,
            CallKind::Builtin(Builtin::Require) | CallKind::Builtin(Builtin::Assert)
        ) {
            for a in &c.args {
                if let Some(name) = expr_reads_live_accessor(a, names) {
                    return Some(name);
                }
            }
        }
    }
    if let ExprKind::Assign { value, .. } = &e.kind {
        if let Some(name) = expr_reads_live_accessor(value, names) {
            return Some(name);
        }
    }
    None
}

/// Does `e` contain a read of a live accessor *whose quantity has a captured
/// sibling* — either a call (`activeStake()`, `getVotes(...)`) or a bare
/// member/identifier — that is NOT itself the captured variant? Returns the matched
/// accessor name (as written).
fn expr_reads_live_accessor(e: &Expr, names: &HashSet<String>) -> Option<String> {
    let mut found: Option<String> = None;
    e.visit(&mut |sub| {
        if found.is_some() {
            return;
        }
        // Method / function call: match on the resolved/textual callee name.
        if let ExprKind::Call(c) = &sub.kind {
            let nm = c
                .func_name
                .clone()
                .or_else(|| c.callee.simple_name().map(|s| s.to_string()));
            if let Some(name) = nm {
                if is_live_match(&name, names) {
                    found = Some(name);
                    return;
                }
            }
        }
        // Bare member access (`pool.activeStake`) or identifier (`totalSupply`).
        match &sub.kind {
            ExprKind::Member { member, .. } => {
                if is_live_match(member, names) {
                    found = Some(member.clone());
                }
            }
            ExprKind::Ident(n) => {
                if is_live_match(n, names) {
                    found = Some(n.clone());
                }
            }
            _ => {}
        }
    });
    found
}

/// `name` resolves to a live accessor (lowercased, exact) that is present in the
/// captured-sibling set `names`, and is NOT itself the captured `*At`/`getPast*`
/// variant. The exact-name match (not substring) keeps `activeStakeAt` from being
/// read as `activestake` + noise.
fn is_live_match(name: &str, names: &HashSet<String>) -> bool {
    let l = name.to_ascii_lowercase();
    if is_captured_accessor_name(&l) {
        return false;
    }
    names.contains(&l)
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "epoch-boundary-staleness")
    }

    // VULN (Symbiotic onSlash shape, split across inheritance): the captured
    // accessor `activeStakeAt(uint48,bytes)` lives in the base `VaultStorage`,
    // while `onSlash` lives in the derived `Vault` and slashes against the LIVE
    // `activeStake()` after validating `epochAt(captureTimestamp)`. The capture
    // param flows into `epochAt`, NOT into the stake read — exactly the bug.
    const VULN: &str = r#"
        abstract contract VaultStorage {
            function epochAt(uint48 timestamp) public view returns (uint256) { return timestamp; }
            function activeStakeAt(uint48 timestamp, bytes memory hint) public view returns (uint256) { return timestamp; }
            function activeStake() public view returns (uint256) { return 1; }
        }
        contract Vault is VaultStorage {
            address slasher;
            mapping(uint256 => uint256) withdrawals;
            function onSlash(uint256 amount, uint48 captureTimestamp) external returns (uint256 slashedAmount) {
                uint256 captureEpoch = epochAt(captureTimestamp);
                uint256 activeStake_ = activeStake();
                uint256 slashableStake = activeStake_ + withdrawals[captureEpoch + 1];
                slashedAmount = amount < slashableStake ? amount : slashableStake;
                withdrawals[captureEpoch + 1] = slashableStake - slashedAmount;
            }
        }
    "#;

    // VULN (single contract): captured accessor and live read in the same body.
    const VULN_SINGLE: &str = r#"
        interface IStakeSource {
            function activeStake() external view returns (uint256);
        }
        contract SlashingVault {
            IStakeSource public source;
            mapping(uint256 => uint256) public slashedAt;
            function activeStakeAt(uint48 ts) external view returns (uint256) { return ts; }
            function requestSlash(uint256 amount) external {
                uint256 power = activeStake();
                require(amount <= power, "too much");
                slashedAt[block.timestamp] = amount;
            }
            function activeStake() public view returns (uint256) { return 1; }
        }
    "#;

    // SAFE (epoch-aware): `requestSlash` reads the CAPTURED `activeStakeAt(ts)` —
    // the safe form — so there is nothing to flash-manipulate.
    const SAFE_EPOCH_AWARE: &str = r#"
        contract SlashingVault {
            mapping(uint256 => uint256) public slashedAt;
            function activeStakeAt(uint48 ts) external view returns (uint256) { return ts; }
            function activeStake() public view returns (uint256) { return 1; }
            function requestSlash(uint256 amount, uint48 epochCaptureTimestamp) external {
                uint256 power = activeStakeAt(epochCaptureTimestamp);
                require(amount <= power, "too much");
                slashedAt[epochCaptureTimestamp] = amount;
            }
        }
    "#;

    // SAFE (no captured sibling for the live quantity): an epoch-based contract
    // whose mutating function reads `token.balanceOf(this)` — for which there is
    // NO `balanceOfAt` snapshot accessor. This is the olympus `rebase`/`unstake`
    // and eigenlayer `sweep` FP shape: epoch machinery present, but the live read
    // is of a quantity the contract never snapshots.
    const SAFE_NO_CAPTURED_SIBLING: &str = r#"
        interface IERC20 { function balanceOf(address a) external view returns (uint256); }
        contract Staking {
            struct Epoch { uint256 length; uint256 number; uint256 end; }
            Epoch public epoch;
            IERC20 OHM;
            // captured accessor exists, but for a DIFFERENT quantity (activeStake),
            // not for the balanceOf the function below reads.
            function activeStakeAt(uint48 ts) public view returns (uint256) { return ts; }
            function activeStake() public view returns (uint256) { return 1; }
            function rebase() public returns (uint256) {
                uint256 balance = OHM.balanceOf(address(this));
                if (balance > 0) { epoch.number++; }
                return balance;
            }
        }
    "#;

    // SAFE (no epoch machinery at all): ordinary staking, no captured accessor
    // anywhere. The live `activeStake()` read is the design.
    const SAFE_NO_EPOCH: &str = r#"
        interface IStakeSource { function activeStake() external view returns (uint256); }
        contract SimpleStaker {
            IStakeSource public source;
            uint256 public lastSeen;
            function poke(uint256 amount) external {
                uint256 power = source.activeStake();
                require(amount <= power, "too much");
                lastSeen = power;
            }
        }
    "#;

    #[test]
    fn fires_on_live_read_with_captured_sibling_across_inheritance() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_live_read_single_contract() {
        assert!(fires(VULN_SINGLE), "{:#?}", run(VULN_SINGLE));
    }

    #[test]
    fn silent_when_decision_reads_captured_value() {
        assert!(!fires(SAFE_EPOCH_AWARE), "{:#?}", run(SAFE_EPOCH_AWARE));
    }

    #[test]
    fn silent_when_live_quantity_has_no_captured_sibling() {
        assert!(!fires(SAFE_NO_CAPTURED_SIBLING), "{:#?}", run(SAFE_NO_CAPTURED_SIBLING));
    }

    #[test]
    fn silent_without_epoch_machinery() {
        assert!(!fires(SAFE_NO_EPOCH), "{:#?}", run(SAFE_NO_EPOCH));
    }
}
