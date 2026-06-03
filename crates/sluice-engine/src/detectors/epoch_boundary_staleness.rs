//! Epoch-boundary staleness — a live quantity used where an epoch/snapshot
//! capture is the protocol's invariant.
//!
//! Restaking / staking / governance protocols that are organized around
//! **epochs** (or capture timestamps / snapshots) establish a rule: the figure
//! that decides slashing power, voting weight, or a reward share must be the
//! value **captured at the epoch boundary** (the moment the epoch was sealed),
//! not the value as it stands *right now*. The captured value cannot be moved
//! once the epoch is fixed; the live value can be pumped or drained inside the
//! epoch with a flash-deposit / flash-withdraw and reverted in the same block.
//!
//! The staleness bug is the inverse of "stale oracle": here the contract *has*
//! the epoch-captured accessor (so the protocol clearly intends capture
//! semantics), yet a state-mutating entry point reaches for the **live / latest /
//! current** accessor of the *same quantity* and feeds it into a `require`, a
//! branch, or an assignment. Symbiotic/Mellow-style `activeStake()` used where
//! `activeStakeAt(captureTimestamp)` was required, or OZ `getVotes()` used where
//! `getPastVotes(blockNumber)` was required, are the canonical shapes.
//!
//! Precision anchors (all required, so this stays silent on protocols that have
//! no epoch machinery, and on functions that are already epoch-aware):
//!   * the **contract** exposes at least one epoch/capture/snapshot-keyed
//!     accessor (a function, state var, or call whose name contains `epoch`,
//!     `capturetimestamp`, `snapshot`, `getpast`, or `pointat`) — this proves the
//!     protocol's invariant is capture-based, not live;
//!   * a **state-mutating, externally-reachable** function in the *same* contract
//!     reads the same quantity through a **live/current/latest** accessor
//!     (`activestake`, `totalstake`, `totalsupply`, current `balanceof`, ...) and
//!     **uses** that read in a `require`/`if`/assignment (a decision), not merely
//!     forwards it;
//!   * the function is **not** itself epoch-aware: it takes no epoch/timestamp/
//!     snapshot parameter that it threads into the read (such a function is
//!     reading at a caller-supplied capture point on purpose).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Contract, Expr, ExprKind, Function};

pub struct EpochBoundaryStalenessDetector;

/// Tokens whose presence (in a function name, state-var name, or called method
/// name) evidences that the contract captures quantities at an epoch boundary /
/// snapshot. Their existence is what distinguishes an epoch-based protocol — for
/// which a live read is a real bug — from an ordinary one where a live read is
/// simply the design.
const EPOCH_MARKERS: &[&str] = &[
    "epoch",
    "capturetimestamp",
    "snapshot",
    "getpast",   // OZ ERC20Votes / ERC5805: getPastVotes / getPastTotalSupply
    "pointat",   // checkpoint "point at" style accessors
];

/// Live / current / latest accessors for a stake-like or supply-like quantity.
/// Reading one of these *is* the manipulable read when the protocol's invariant
/// wants the epoch-captured value. Deliberately a closed, stake/governance-shaped
/// set so this never fires on unrelated `current*` helpers.
const LIVE_ACCESSORS: &[&str] = &[
    "activestake",
    "totalstake",
    "currentstake",
    "totalsupply",
    "totalassets",
    "balanceof",
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
        "Live/current quantity used for a decision where an epoch/snapshot-captured value is the invariant"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for contract in cx.scir.iter_contracts() {
            // Interfaces and libraries declare no consuming logic.
            if contract.is_interface() || contract.is_library() {
                continue;
            }
            // STRUCTURAL GATE 1: the contract must demonstrably be epoch-based —
            // it captures some quantity at an epoch / snapshot / capture point.
            if !contract_has_epoch_machinery(cx, contract) {
                continue;
            }

            for f in cx.scir.functions_of(contract.id) {
                if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
                    continue;
                }
                // Reading the live value to expose it (a `view`) is fine; the bug
                // is using it to *drive a state mutation*. `is_state_mutating`
                // above already excludes view/pure, but be explicit for clarity.
                if f.is_view_or_pure() {
                    continue;
                }
                // SUPPRESS: a function that is itself an epoch/snapshot accessor
                // (its own name carries the marker) is the capture path, not a
                // victim of it.
                if name_has_marker(&f.name, EPOCH_MARKERS) {
                    continue;
                }
                // SUPPRESS: the function is already epoch-aware — it takes an
                // epoch / timestamp / snapshot parameter and threads it into the
                // body. Then its reads are deliberately at a chosen capture point.
                if is_epoch_aware(f) {
                    continue;
                }

                // STRUCTURAL GATE 2: find a live/current accessor read that is
                // actually *used* in a decision (require / branch / assignment).
                let Some((span, accessor)) = first_live_decision_read(f) else {
                    continue;
                };

                let b = FindingBuilder::new(self.id(), Category::EpochBoundaryStaleness)
                    .title("Live quantity used where an epoch/snapshot-captured value is required")
                    .severity(Severity::Medium)
                    .confidence(0.45)
                    .dimension(Dimension::Invariant)
                    .message(format!(
                        "`{}` reads `{}` at the current/latest block and uses it in a decision \
                         (require / branch / assignment), while `{}` captures the same kind of \
                         quantity at an epoch boundary / snapshot elsewhere (an `epoch` / \
                         `captureTimestamp` / `snapshot` / `getPast*` accessor exists). When the \
                         protocol's invariant is the epoch-captured figure, consuming the live one \
                         is manipulable *within* the epoch: an attacker can flash-deposit to inflate \
                         (or flash-withdraw to deflate) stake/supply/voting weight in the same \
                         transaction, skew the slashing power / vote / reward share, and unwind — \
                         the epoch-boundary staleness class.",
                        f.name, accessor, contract.name
                    ))
                    .recommendation(
                        "Read the quantity at the epoch's capture point, not live: use the \
                         epoch-keyed accessor the contract already provides \
                         (`activeStakeAt(captureTimestamp)`, `getPastVotes(epochBlock)`, a snapshot \
                         id) so the value is fixed for the epoch and cannot be flash-manipulated \
                         between capture and use.",
                    );
                out.push(cx.finish(b, f.id, span));
            }
        }

        out
    }
}

/// STRUCTURAL GATE 1: does the contract have any epoch/capture/snapshot-keyed
/// accessor? We look at (a) the names of its functions, (b) the names of its
/// state variables, and (c) the method names it calls — any one carrying an
/// epoch marker proves the protocol seals quantities at a boundary.
fn contract_has_epoch_machinery(cx: &AnalysisContext, contract: &Contract) -> bool {
    if contract.state_vars.iter().any(|v| name_has_marker(&v.name, EPOCH_MARKERS)) {
        return true;
    }
    for f in cx.scir.functions_of(contract.id) {
        if name_has_marker(&f.name, EPOCH_MARKERS) {
            return true;
        }
        if f.effects
            .call_sites
            .iter()
            .any(|c| c.func_name.as_deref().map(|n| name_has_marker(n, EPOCH_MARKERS)).unwrap_or(false))
        {
            return true;
        }
        if f.effects.internal_calls.iter().any(|n| name_has_marker(n, EPOCH_MARKERS)) {
            return true;
        }
    }
    false
}

/// SUPPRESS: a function is "epoch-aware" if it accepts an epoch / timestamp /
/// snapshot / block-number parameter and **passes that parameter into a call**
/// (the accessor read) — i.e. it reads at a caller-chosen capture point on
/// purpose. We require the parameter to flow into a call argument (not merely
/// appear somewhere) so a function that *accepts* an epoch arg but ignores it —
/// the very bug shape — is not mistaken for epoch-aware. Errs toward suppression
/// on genuinely epoch-threaded reads to keep precision high.
fn is_epoch_aware(f: &Function) -> bool {
    const PARAM_NAME_MARKERS: &[&str] =
        &["epoch", "timestamp", "snapshot", "blocknumber", "captureat", "pointat"];
    const PARAM_TYPE_HINTS: &[&str] = &["uint48", "uint32"]; // common epoch/timestamp widths

    for p in &f.params {
        let pname = p.name.as_deref().unwrap_or("");
        if pname.is_empty() {
            continue;
        }
        let lname = pname.to_ascii_lowercase();
        let lty = p.ty.to_ascii_lowercase();

        let name_hit = PARAM_NAME_MARKERS.iter().any(|m| lname.contains(m));
        let type_hit = PARAM_TYPE_HINTS.iter().any(|t| lty == *t);

        // The parameter is epoch/timestamp-shaped AND is handed to a call — it is
        // being threaded into the (capture-keyed) read deliberately.
        if (name_hit || type_hit) && param_flows_into_call_arg(f, pname) {
            return true;
        }
    }
    false
}

/// Does the parameter `name` appear as (part of) an argument to some call in the
/// body — `foo(name)`, `src.activeStakeAt(name)`, `getPastVotes(name)`? This is
/// the structural proxy for "passes the epoch param to the read".
fn param_flows_into_call_arg(f: &Function, name: &str) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            e.visit(&mut |sub| {
                if let ExprKind::Call(c) = &sub.kind {
                    if c.args.iter().any(|a| expr_mentions_ident(a, name)) {
                        found = true;
                    }
                }
            });
        });
        if found {
            break;
        }
    }
    found
}

/// Does `name` appear as an identifier anywhere in `e`?
fn expr_mentions_ident(e: &Expr, name: &str) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if let ExprKind::Ident(n) = &sub.kind {
            if n == name {
                found = true;
            }
        }
    });
    found
}

/// STRUCTURAL GATE 2: the first read of a live/current accessor that is *used* in
/// a decision (a `require`/`assert`, an `if`/`while`/`for`/`do-while` condition,
/// or an assignment / var-decl initializer). Returns the span of the using
/// statement and the matched accessor name. Requiring genuine *use* (not a bare
/// read, and not a value merely returned/forwarded) is the key precision anchor:
/// a getter that surfaces the live value is not the bug.
fn first_live_decision_read(f: &Function) -> Option<(sluice_ir::Span, String)> {
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
                    if let Some(a) = expr_reads_live_accessor(cond) {
                        hit = Some((st.span, a));
                    }
                }
                StmtKind::For { cond: Some(cond), .. } => {
                    if let Some(a) = expr_reads_live_accessor(cond) {
                        hit = Some((st.span, a));
                    }
                }
                // Used in a `require(...)` / `assert(...)` or assigned into state /
                // a local that then drives the decision.
                StmtKind::Expr(e) => {
                    if let Some(a) = require_or_assign_uses_live(e) {
                        hit = Some((st.span, a));
                    }
                }
                // `uint256 power = activeStake();` — captured into a local that the
                // function will branch/compute on. The decisive use of the live
                // value starts here, so this is a fair anchor.
                StmtKind::VarDecl { init: Some(e), .. } => {
                    if let Some(a) = expr_reads_live_accessor(e) {
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
fn require_or_assign_uses_live(e: &Expr) -> Option<String> {
    // require(... activeStake() ...) / assert(...)
    if let ExprKind::Call(c) = &e.kind {
        use sluice_ir::{Builtin, CallKind};
        if matches!(
            c.kind,
            CallKind::Builtin(Builtin::Require) | CallKind::Builtin(Builtin::Assert)
        ) {
            for a in &c.args {
                if let Some(name) = expr_reads_live_accessor(a) {
                    return Some(name);
                }
            }
        }
    }
    // x = activeStake();  /  x += totalStake();
    if let ExprKind::Assign { value, .. } = &e.kind {
        if let Some(name) = expr_reads_live_accessor(value) {
            return Some(name);
        }
    }
    None
}

/// Does `e` contain a read of a live/current accessor — either a call
/// (`activeStake()`, `token.balanceOf(...)`, `getVotes(...)`) or a bare
/// member/identifier (`activeStake`, `totalSupply`) — that is NOT an
/// epoch/snapshot-keyed variant? Returns the matched accessor name.
fn expr_reads_live_accessor(e: &Expr) -> Option<String> {
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
                if is_live_accessor_name(&name) {
                    found = Some(name);
                    return;
                }
            }
        }
        // Bare member access (`pool.activeStake`) or identifier (`totalSupply`),
        // e.g. a public auto-getter or state variable read.
        match &sub.kind {
            ExprKind::Member { member, .. } => {
                if is_live_accessor_name(member) {
                    found = Some(member.clone());
                }
            }
            ExprKind::Ident(n) => {
                if is_live_accessor_name(n) {
                    found = Some(n.clone());
                }
            }
            _ => {}
        }
    });
    found
}

/// `name` is a live/current accessor of a stake/supply/voting quantity, and is
/// NOT an epoch/snapshot-keyed variant (those carry an `EPOCH_MARKERS` token and
/// are exactly the safe form). The epoch-marker exclusion is essential: it lets
/// `activeStakeAt` / `getPastVotes` / `totalSupplyAt` pass through untouched.
fn is_live_accessor_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    if name_has_marker(&l, EPOCH_MARKERS) {
        return false;
    }
    // A trailing `at`/`At` (e.g. `activeStakeAt`) marks the captured variant even
    // though it is not in EPOCH_MARKERS; treat it as the safe form.
    if l.ends_with("at") && LIVE_ACCESSORS.iter().any(|a| l.starts_with(a)) {
        return false;
    }
    LIVE_ACCESSORS.iter().any(|a| l == *a || l.contains(a))
}

/// Case-insensitive: does `name` contain any of `markers`?
fn name_has_marker(name: &str, markers: &[&str]) -> bool {
    let l = name.to_ascii_lowercase();
    markers.iter().any(|m| l.contains(m))
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

    // VULN: an epoch-based vault. `slashableStake()` is the epoch-captured
    // accessor (proves capture semantics), but `requestSlash` decides the slash
    // amount from the LIVE `activeStake()` — manipulable within the epoch with a
    // flash deposit/withdraw. The function is not epoch-aware (no epoch param).
    const VULN: &str = r#"
        interface IStakeSource {
            function activeStake() external view returns (uint256);
            function activeStakeAt(uint48 captureTimestamp) external view returns (uint256);
        }
        contract SlashingVault {
            IStakeSource public source;
            uint48 public captureTimestamp;
            mapping(uint256 => uint256) public slashedAt;

            // Epoch-captured accessor — establishes the capture invariant.
            function slashableStakeAt(uint48 ts) external view returns (uint256) {
                return source.activeStakeAt(ts);
            }

            // BUG: decides slash power from the live value, not the captured one.
            function requestSlash(uint256 amount) external {
                uint256 power = source.activeStake();
                require(amount <= power, "too much");
                slashedAt[block.timestamp] = amount;
            }
        }
    "#;

    // SAFE (epoch-aware): the same vault, but `requestSlash` takes the epoch's
    // captureTimestamp and reads `activeStakeAt(captureTimestamp)` — it consumes
    // the captured value, so there is nothing to manipulate within the epoch.
    const SAFE_EPOCH_AWARE: &str = r#"
        interface IStakeSource {
            function activeStake() external view returns (uint256);
            function activeStakeAt(uint48 captureTimestamp) external view returns (uint256);
        }
        contract SlashingVault {
            IStakeSource public source;
            uint48 public captureTimestamp;
            mapping(uint256 => uint256) public slashedAt;

            function slashableStakeAt(uint48 ts) external view returns (uint256) {
                return source.activeStakeAt(ts);
            }

            function requestSlash(uint256 amount, uint48 epochCaptureTimestamp) external {
                uint256 power = source.activeStakeAt(epochCaptureTimestamp);
                require(amount <= power, "too much");
                slashedAt[epochCaptureTimestamp] = amount;
            }
        }
    "#;

    // SAFE (no epoch machinery): an ordinary staking contract with no epoch /
    // snapshot / capture accessor anywhere. Reading the live `activeStake()` is
    // the design, not a bug — the structural gate must keep us silent.
    const SAFE_NO_EPOCH: &str = r#"
        interface IStakeSource {
            function activeStake() external view returns (uint256);
        }
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
    fn fires_on_live_read_in_epoch_protocol() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn silent_when_function_is_epoch_aware() {
        assert!(!fires(SAFE_EPOCH_AWARE), "{:#?}", run(SAFE_EPOCH_AWARE));
    }

    #[test]
    fn silent_without_epoch_machinery() {
        assert!(!fires(SAFE_NO_EPOCH), "{:#?}", run(SAFE_NO_EPOCH));
    }
}
