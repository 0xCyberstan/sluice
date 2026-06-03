//! Vote-weight checkpoint — governance voting power read from a *current* /
//! manipulable balance instead of a snapshot taken at proposal **creation**.
//!
//! In a sound Compound-/OpenZeppelin-style `Governor`, the weight a voter
//! contributes to a proposal's tally is read from a **historical snapshot keyed
//! to the proposal's start**:
//! ```solidity
//! uint votes = token.getPriorVotes(voter, proposal.startBlock);     // Compound/Alpha
//! uint votes = token.getPastVotes(account, proposalSnapshot(id));   // OZ Governor
//! ```
//! Keying the lookup to the proposal-creation block/timestamp is what makes the
//! ballot resistant to **flash-acquired** or **just-transferred** voting power:
//! tokens bought (or borrowed via flash loan, or transferred in) *after* the
//! proposal was created carry no weight, because the checkpoint they would have
//! moved did not yet exist at `startBlock`.
//!
//! The bug is reading the weight from a **live, post-creation-mutable** source
//! at the vote-cast (or execute) moment instead:
//! ```solidity
//! uint votes = token.getCurrentVotes(voter);          // current checkpoint
//! uint votes = token.getVotes(voter);                 // OZ "now" accessor
//! uint votes = token.balanceOf(voter);                // raw balance
//! uint votes = token.getPriorVotes(voter, block.number - 1);   // ~now
//! proposal.forVotes += votes;
//! ```
//! Now an attacker flash-borrows or buys the governance token *after* the
//! proposal opens, calls `castVote`, and their transient balance is counted —
//! the flash-loan-governance / vote-buying class (Beanstalk-$182M shape, and the
//! perennial Compound-fork mis-port where `getPriorVotes(voter, startBlock)` is
//! "simplified" to a current read).
//!
//! Precision anchors (all required, so this stays silent on the *correct*
//! snapshot-keyed governors — e.g. Olympus `GovernorAlpha` /
//! `GovernorOHMegaDelegate`, which both read `gOHM.getPriorVotes(voter,
//! proposal.startBlock)`):
//!   * the function is a governance **vote-cast or execute** path — its name is
//!     vote-cast/execute-shaped (`castVote*`, `_castVote`, `castVoteInternal`,
//!     `execute`, `countVote*`) **or** it writes a proposal vote-tally
//!     (`forVotes`/`againstVotes`/`abstainVotes`/`*Votes`);
//!   * it reads a **voting-weight** value through a balance/votes accessor
//!     (`getVotes`/`getCurrentVotes`/`balanceOf`/`getPriorVotes`/`getPastVotes`/
//!     `votingPower`/`getVotingWeight` or a `.votes`/`.weight` checkpoint field);
//!   * and **no** weight accessor in the body is **keyed to a proposal-creation
//!     snapshot** — there is no `getPastVotes(account, proposal.startBlock)` /
//!     `getPriorVotes(_, startBlock)` / `getPastVotes(_, proposalSnapshot(id))`.
//!     Presence of *any* snapshot-keyed weight read suppresses the function: the
//!     ballot is anchored to creation, so flash/just-transferred power can't be
//!     counted.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{Expr, ExprKind, Function};

use super::prelude::*;

pub struct VoteWeightCheckpointDetector;

impl Detector for VoteWeightCheckpointDetector {
    fn id(&self) -> &'static str {
        "vote-weight-checkpoint"
    }
    fn category(&self) -> Category {
        Category::VoteWeightCheckpoint
    }
    fn description(&self) -> &'static str {
        "Governance voting weight read from a current/manipulable balance instead of a proposal-creation snapshot (flash-loan / just-transferred vote power)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Vote-cast helpers are commonly `internal` (`_castVote`,
            // `castVoteInternal`), so we must not restrict to entry points.
            //
            // MANDATORY anchor: the function must *count* votes — it writes a
            // proposal vote-tally (`forVotes`/`againstVotes`/`abstainVotes`/a
            // `*Votes` accumulator). This is the defining act of the bug class and
            // is what separates a real vote-counting path from look-alikes. A
            // `Governor.execute` that merely re-checks the *proposer's* threshold
            // via `getPriorVotes(proposer, block.number-1)` writes NO vote tally
            // (it sets `proposal.executed`), so it is excluded here — that is the
            // precise reason the real Olympus-V3 `GovernorBravoDelegate.execute`
            // does not fire.
            if !writes_vote_tally(f) {
                continue;
            }

            // The function must read a voting-weight value through a balance/votes
            // accessor, AND that value must flow into the vote tally (be the
            // counted weight) — not merely be read for an unrelated guard. Locate
            // the weight read that feeds the tally so the finding points at it.
            let Some((span, accessor)) = weight_read_into_tally(f) else { continue };

            // --- false-positive suppression (the whole point of the detector) ---
            // If ANY weight accessor in the body is keyed to a proposal-creation
            // snapshot (`getPriorVotes(voter, proposal.startBlock)` /
            // `getPastVotes(account, proposalSnapshot(id))`), the ballot is anchored
            // to creation and flash/just-transferred power cannot be counted —
            // suppress. This is exactly the correct Compound/OZ shape, and is what
            // the real Olympus governors use (incl. the Bravo `min(originalVotes,
            // currentVotes)` form, whose `originalVotes` is snapshot-keyed).
            if reads_snapshot_keyed_weight(f) {
                continue;
            }

            let b = report!(self, Category::VoteWeightCheckpoint,
                title = "Voting weight read from a current balance, not a proposal-creation snapshot",
                severity = Severity::Medium,
                confidence = 0.55,
                dimensions = [Dimension::ValueFlow],
                message = format!(
                    "`{}` derives a voter's weight from `{accessor}`, a current / post-creation-mutable \
                     source, at the vote-cast/execute moment rather than from a snapshot keyed to the \
                     proposal's creation block (no `getPastVotes(account, proposal.startBlock)` / \
                     `getPriorVotes(_, startBlock)` anywhere in the function). Because the weight is read \
                     `now`, an attacker can flash-borrow, buy, or have tokens transferred in *after* the \
                     proposal opens, cast a vote with that transient balance, and then return the tokens — \
                     the flash-loan-governance / vote-buying class (Beanstalk-$182M shape; also the common \
                     Compound-fork mis-port where `getPriorVotes(voter, startBlock)` is reduced to a \
                     current read).",
                    f.name
                ),
                recommendation =
                    "Read voting weight from a historical checkpoint keyed to the proposal's creation \
                     block/timestamp, captured when the proposal was created — \
                     `token.getPriorVotes(voter, proposal.startBlock)` (Compound/Alpha) or \
                     `token.getPastVotes(account, proposalSnapshot(proposalId))` (OpenZeppelin Governor). \
                     Never tally weight from `getCurrentVotes`/`getVotes(account)`/`balanceOf` or from \
                     `getPriorVotes(_, block.number)` at the vote-cast/execute moment.",
            );
            out.push(finish_at(cx, b, f.id, span));
        }
        out
    }
}

/// Does `f` write a proposal **vote tally** — assign to a
/// `.forVotes`/`.againstVotes`/`.abstainVotes`/`*Votes` member (the
/// `proposal.forVotes = add256(proposal.forVotes, votes)` shape) or to a
/// `*Votes` storage var? This is the mandatory anchor: only a vote-*counting*
/// path can mis-count flash power. A `Governor.execute` that sets
/// `proposal.executed` writes no tally and is therefore excluded.
///
/// We require the **member/var name** to be a tally, *not* `receipt.votes`
/// (which records a single voter's recorded weight, not the running tally) — so
/// the target's member must be a `*Votes` aggregate (`forVotes`/`againstVotes`/
/// `abstainVotes`), reached either directly or via the effect summary.
fn writes_vote_tally(f: &Function) -> bool {
    // Direct AST scan of assignment targets (the precise signal).
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Assign { target, .. } = &e.kind {
                if let ExprKind::Member { member, .. } = &target.kind {
                    if is_aggregate_tally_member(member) {
                        found = true;
                    }
                }
            }
        });
        if found {
            break;
        }
    }
    if found {
        return true;
    }
    // Fallback: the effect summary recorded a `*Votes` aggregate write path.
    f.effects.storage_writes.iter().any(|w| {
        is_aggregate_tally_member(&w.var) || path_has_aggregate_tally(&w.path)
    })
}

/// An *aggregate* tally member — `forVotes` / `againstVotes` / `abstainVotes`
/// (and `*Votes` accumulators), excluding the per-voter `receipt.votes`.
fn is_aggregate_tally_member(member: &str) -> bool {
    let l = member.to_ascii_lowercase();
    l == "forvotes"
        || l == "againstvotes"
        || l == "abstainvotes"
        || (l.ends_with("votes") && l != "votes")
}

/// Does an effect-summary access *path* end in an aggregate tally member, e.g.
/// `proposals[id].forVotes`? (The base var alone may be `proposals`.)
fn path_has_aggregate_tally(path: &str) -> bool {
    path.rsplit('.').next().map(is_aggregate_tally_member).unwrap_or(false)
}

/// Names of weight accessors that *could* be current or historical. We capture
/// every shape and let the snapshot-key test decide whether it is safe.
fn is_weight_accessor(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "getvotes"
        || l == "getcurrentvotes"
        || l == "getpriorvotes"
        || l == "getpastvotes"
        || l == "getpastvotingpower"
        || l == "getpriorvotingpower"
        || l == "votingpower"
        || l == "getvotingpower"
        || l == "getvotingweight"
        || l == "getvoteweight"
        || l == "balanceof"
        || l == "balanceofat"
}

/// The voting-weight read whose value **flows into the vote tally**, with its
/// span and a display label. We require linkage so that a weight accessor read
/// for an *unrelated* guard (e.g. a `Governor` re-checking the proposer's
/// threshold via `getPriorVotes(proposer, block.number-1)` while the tally write
/// adds a *different* value) does not trip the detector.
///
/// Linkage is established when either:
///   * the weight-accessor call result is bound to a local
///     (`uint votes = token.getCurrentVotes(voter);`) and that local is
///     referenced on the RHS of an aggregate-tally assignment
///     (`proposal.forVotes = proposal.forVotes + votes;`), or
///   * the aggregate-tally assignment's RHS *directly* contains the
///     weight-accessor call (`proposal.forVotes += token.getVotes(voter);`).
///
/// Returns `None` when no weight read feeds a tally (so it is not a real
/// mis-counting path).
fn weight_read_into_tally(f: &Function) -> Option<(sluice_ir::Span, String)> {
    // Locals bound to a weight accessor: name -> (span, label).
    let mut weight_locals: Vec<(String, sluice_ir::Span, String)> = Vec::new();
    // Every weight-accessor call in the body: (span, label, the call expr).
    let mut weight_calls: Vec<(sluice_ir::Span, String)> = Vec::new();

    for s in &f.body {
        // `T name = <weight-accessor call>;` at any nesting depth.
        s.visit(&mut |st| {
            if let sluice_ir::StmtKind::VarDecl { name: Some(name), init: Some(init), .. } = &st.kind {
                if let Some((span, label)) = as_weight_call(init) {
                    weight_locals.push((name.clone(), span, label));
                }
            }
        });
        s.visit_exprs(&mut |e| {
            if let Some((span, label)) = as_weight_call(e) {
                weight_calls.push((span, label));
            }
            // `local = <weight-accessor call>;` assignment binding.
            if let ExprKind::Assign { target, value, .. } = &e.kind {
                if let (ExprKind::Ident(name), Some((span, label))) =
                    (&target.kind, as_weight_call(value))
                {
                    weight_locals.push((name.clone(), span, label));
                }
            }
        });
    }
    if weight_calls.is_empty() {
        return None;
    }

    // Now find an aggregate-tally assignment whose RHS references a weight local
    // or directly contains a weight call.
    let mut result: Option<(sluice_ir::Span, String)> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if result.is_some() {
                return;
            }
            let ExprKind::Assign { target, value, .. } = &e.kind else { return };
            let ExprKind::Member { member, .. } = &target.kind else { return };
            if !is_aggregate_tally_member(member) {
                return;
            }
            // RHS directly contains a weight call?
            if let Some((span, label)) = first_weight_call_within(value) {
                result = Some((span, label));
                return;
            }
            // RHS references a local bound to a weight call?
            for (name, span, label) in &weight_locals {
                if expr_mentions_ident(value, name) {
                    result = Some((*span, label.clone()));
                    return;
                }
            }
        });
        if result.is_some() {
            break;
        }
    }
    result
}

/// If `e` *is* a weight-accessor call, return its span and display label.
fn as_weight_call(e: &Expr) -> Option<(sluice_ir::Span, String)> {
    if let ExprKind::Call(c) = &e.kind {
        if let Some(n) = &c.func_name {
            if is_weight_accessor(n) {
                let label = match c.receiver.as_deref().and_then(root_ident_str) {
                    Some(recv) => format!("{recv}.{n}"),
                    None => n.clone(),
                };
                return Some((e.span, label));
            }
        }
    }
    None
}

/// The first weight-accessor call found anywhere within `e` (RHS of an
/// assignment), with its span and label.
fn first_weight_call_within(e: &Expr) -> Option<(sluice_ir::Span, String)> {
    let mut hit: Option<(sluice_ir::Span, String)> = None;
    e.visit(&mut |sub| {
        if hit.is_some() {
            return;
        }
        if let Some(found) = as_weight_call(sub) {
            hit = Some(found);
        }
    });
    hit
}

/// Does `f` read voting weight from a **proposal-creation snapshot**? True when
/// any weight accessor call carries a *snapshot key* argument — an argument that
/// references a proposal-start block/timestamp (`proposal.startBlock`,
/// `startBlock`, `voteStart`, `snapshot`) or is a snapshot-accessor call
/// (`proposalSnapshot(id)` / `proposalVoteStart(id)`). Presence of any such read
/// means the ballot is anchored to creation -> safe -> suppress.
///
/// We err strongly toward suppression: a single snapshot-keyed weight read
/// anywhere in the body is enough.
fn reads_snapshot_keyed_weight(f: &Function) -> bool {
    let mut safe = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if safe {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            let is_weight = c.func_name.as_deref().map(is_weight_accessor).unwrap_or(false);
            if !is_weight {
                return;
            }
            if c.args.iter().any(arg_is_snapshot_key) {
                safe = true;
            }
        });
        if safe {
            break;
        }
    }
    safe
}

/// Is `e` a "snapshot key" — an argument that pins a weight read to the
/// proposal's creation point? Recognized shapes:
///   * a member access whose member name is snapshot-like
///     (`proposal.startBlock`, `p.voteStart`, `proposal.snapshot`);
///   * a bare identifier that is snapshot-like (`startBlock`, `snapshot`,
///     `voteStart`) — the locally-cached `uint startBlock = proposal.startBlock;`
///     case;
///   * a call to a snapshot accessor (`proposalSnapshot(id)`,
///     `proposalVoteStart(id)`) — the OZ Governor shape.
///
/// A `block.number`/`block.timestamp`-derived argument is deliberately **not**
/// snapshot-like: `getPriorVotes(voter, block.number - 1)` is a *current* read.
fn arg_is_snapshot_key(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        match &sub.kind {
            // `proposal.startBlock` — and not `block.number`/`block.timestamp`.
            ExprKind::Member { member, base } if is_snapshot_word(member) && !base_is_block(base) => {
                found = true;
            }
            ExprKind::Ident(n) if is_snapshot_word(n) => {
                found = true;
            }
            ExprKind::Call(c) if c.func_name.as_deref().map(is_snapshot_accessor).unwrap_or(false) => {
                found = true;
            }
            _ => {}
        }
    });
    found
}

/// Is `base` the `block` global (so a `.number`/`.timestamp`/member off it is a
/// *current* clock read, not a stored snapshot)?
fn base_is_block(base: &Expr) -> bool {
    matches!(&base.kind, ExprKind::Ident(n) if n.eq_ignore_ascii_case("block"))
}

/// A word that names a proposal-creation snapshot point. Kept tight so ordinary
/// identifiers (`amount`, `account`, `value`) never read as a snapshot key.
fn is_snapshot_word(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l == "startblock"
        || l == "startblocknumber"
        || l == "startblock_"
        || l == "votestart"
        || l == "votestartblock"
        || l == "snapshot"
        || l == "snapshotblock"
        || l == "snapshotid"
        || l == "proposalsnapshot"
        || l == "creationblock"
        || l == "startts"
        || l == "starttime"
        || l == "starttimestamp"
}

/// A snapshot-accessor function name (`proposalSnapshot`, `proposalVoteStart`) —
/// the OZ Governor accessor that returns a proposal's creation snapshot.
fn is_snapshot_accessor(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "proposalsnapshot" || l == "proposalvotestart" || l == "votestart" || l == "snapshot"
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "vote-weight-checkpoint")
    }

    // VULN: weight read from a CURRENT accessor (`getCurrentVotes`) at the
    // vote-cast moment and accumulated into the tally. No snapshot key anywhere.
    // A voter who flash-acquires the token after the proposal opens is counted.
    const VULN_CURRENT_VOTES: &str = r#"
        interface IToken { function getCurrentVotes(address a) external view returns (uint256); }
        contract Gov {
            IToken public token;
            struct Proposal { uint startBlock; uint forVotes; uint againstVotes; }
            mapping(uint => Proposal) public proposals;
            function _castVote(address voter, uint proposalId, bool support) internal {
                Proposal storage proposal = proposals[proposalId];
                uint votes = token.getCurrentVotes(voter);
                if (support) { proposal.forVotes = proposal.forVotes + votes; }
                else { proposal.againstVotes = proposal.againstVotes + votes; }
            }
        }
    "#;

    // VULN: weight read from raw `balanceOf` at cast time.
    const VULN_BALANCEOF: &str = r#"
        interface IToken { function balanceOf(address a) external view returns (uint256); }
        contract Gov {
            IToken public token;
            struct Proposal { uint startBlock; uint forVotes; uint againstVotes; }
            mapping(uint => Proposal) public proposals;
            function castVote(uint proposalId, bool support) external {
                Proposal storage proposal = proposals[proposalId];
                uint votes = token.balanceOf(msg.sender);
                if (support) { proposal.forVotes = proposal.forVotes + votes; }
                else { proposal.againstVotes = proposal.againstVotes + votes; }
            }
        }
    "#;

    // VULN: OZ `getVotes(account)` (the "now" accessor, no block arg) used for
    // the cast weight. The keyed form would be `getPastVotes(account, snapshot)`.
    const VULN_GETVOTES_NOW: &str = r#"
        interface IToken { function getVotes(address a) external view returns (uint256); }
        contract Gov {
            IToken public token;
            struct Proposal { uint voteStart; uint forVotes; }
            mapping(uint => Proposal) internal _proposals;
            function _countVote(uint proposalId, address account, uint8 support) internal {
                Proposal storage p = _proposals[proposalId];
                uint weight = token.getVotes(account);
                p.forVotes = p.forVotes + weight;
                support;
            }
        }
    "#;

    // VULN: `getPriorVotes(voter, block.number - 1)` — keyed to ~NOW, not to the
    // proposal's creation block. `block.number` is explicitly not a snapshot key.
    const VULN_PRIOR_AT_BLOCK_NUMBER: &str = r#"
        interface IToken { function getPriorVotes(address a, uint256 b) external view returns (uint256); }
        contract Gov {
            IToken public token;
            struct Proposal { uint startBlock; uint forVotes; uint againstVotes; }
            mapping(uint => Proposal) public proposals;
            function _castVote(address voter, uint proposalId, bool support) internal {
                Proposal storage proposal = proposals[proposalId];
                uint votes = token.getPriorVotes(voter, block.number - 1);
                if (support) { proposal.forVotes = proposal.forVotes + votes; }
                else { proposal.againstVotes = proposal.againstVotes + votes; }
            }
        }
    "#;

    // SAFE: the real Olympus / Compound shape — weight keyed to
    // `proposal.startBlock`. The snapshot anchor suppresses it.
    const SAFE_PRIOR_AT_STARTBLOCK: &str = r#"
        interface IToken { function getPriorVotes(address a, uint256 b) external view returns (uint256); }
        contract Gov {
            IToken public token;
            struct Proposal { uint startBlock; uint forVotes; uint againstVotes; }
            mapping(uint => Proposal) public proposals;
            function _castVote(address voter, uint proposalId, bool support) internal {
                Proposal storage proposal = proposals[proposalId];
                uint votes = token.getPriorVotes(voter, proposal.startBlock);
                if (support) { proposal.forVotes = proposal.forVotes + votes; }
                else { proposal.againstVotes = proposal.againstVotes + votes; }
            }
        }
    "#;

    // SAFE: OZ Governor shape — `getPastVotes(account, proposalSnapshot(id))`.
    const SAFE_PASTVOTES_SNAPSHOT: &str = r#"
        interface IToken { function getPastVotes(address a, uint256 b) external view returns (uint256); }
        contract Gov {
            IToken public token;
            mapping(uint => uint) internal _forVotes;
            function proposalSnapshot(uint proposalId) public view returns (uint256) { return proposalId; }
            function _countVote(uint proposalId, address account, uint8 support, uint256 weight) internal {
                uint w = token.getPastVotes(account, proposalSnapshot(proposalId));
                _forVotes[proposalId] = _forVotes[proposalId] + w;
                support; weight;
            }
        }
    "#;

    // SAFE: weight keyed to a locally-cached `startBlock` snapshot.
    const SAFE_CACHED_STARTBLOCK: &str = r#"
        interface IToken { function getPriorVotes(address a, uint256 b) external view returns (uint256); }
        contract Gov {
            IToken public token;
            struct Proposal { uint startBlock; uint forVotes; }
            mapping(uint => Proposal) public proposals;
            function _castVote(address voter, uint proposalId) internal {
                Proposal storage proposal = proposals[proposalId];
                uint startBlock = proposal.startBlock;
                uint votes = token.getPriorVotes(voter, startBlock);
                proposal.forVotes = proposal.forVotes + votes;
            }
        }
    "#;

    // SAFE (not governance): an ordinary ERC20 `balanceOf` getter must never fire
    // — it has no vote name and writes no `*Votes` tally.
    const SAFE_PLAIN_BALANCE: &str = r#"
        contract Token {
            mapping(address => uint256) private _balances;
            function balanceOf(address a) external view returns (uint256) {
                return _balances[a];
            }
            function totalShares() external view returns (uint256) {
                return _balances[msg.sender];
            }
        }
    "#;

    // SAFE (real Olympus-V3 GovernorBravoDelegate.execute shape): `execute` reads
    // a CURRENT `getPriorVotes(proposer, block.number - 1)` to re-check the
    // PROPOSER's anti-spam threshold — but it writes NO vote tally (it sets
    // `proposal.executed`). The mandatory vote-tally anchor excludes it. This is
    // the exact FP found on the live olympus-v3 codebase, pinned here.
    const SAFE_EXECUTE_PROPOSER_THRESHOLD: &str = r#"
        interface IToken { function getPriorVotes(address a, uint256 b) external view returns (uint256); }
        contract Gov {
            IToken public gohm;
            struct Proposal { address proposer; uint proposalThreshold; bool executed; }
            mapping(uint => Proposal) public proposals;
            function execute(uint proposalId) external payable {
                Proposal storage proposal = proposals[proposalId];
                require(gohm.getPriorVotes(proposal.proposer, block.number - 1) >= proposal.proposalThreshold, "below");
                proposal.executed = true;
            }
        }
    "#;

    // SAFE (real Olympus-V3 GovernorBravoDelegate.castVoteInternal shape): takes
    // `min(originalVotes@startBlock, currentVotes@now)`. Because the function
    // contains a snapshot-keyed read (`getPriorVotes(voter, proposal.startBlock)`),
    // the ballot is anchored to creation -> suppressed, even though it also reads
    // the current votes. Pinned to the live olympus-v3 shape.
    const SAFE_BRAVO_MIN_OF_PRIOR_AND_CURRENT: &str = r#"
        interface IToken { function getPriorVotes(address a, uint256 b) external view returns (uint256); }
        contract Gov {
            IToken public gohm;
            struct Proposal { uint startBlock; uint forVotes; uint againstVotes; uint abstainVotes; }
            mapping(uint => Proposal) public proposals;
            function castVoteInternal(address voter, uint proposalId, uint8 support) internal returns (uint) {
                Proposal storage proposal = proposals[proposalId];
                uint originalVotes = gohm.getPriorVotes(voter, proposal.startBlock);
                uint currentVotes = gohm.getPriorVotes(voter, block.number - 1);
                uint votes = currentVotes > originalVotes ? originalVotes : currentVotes;
                if (support == 0) { proposal.againstVotes = proposal.againstVotes + votes; }
                else if (support == 1) { proposal.forVotes = proposal.forVotes + votes; }
                else { proposal.abstainVotes = proposal.abstainVotes + votes; }
                return votes;
            }
        }
    "#;

    // SAFE (linkage gate): a vote-counting fn whose tally is fed by a value that
    // is NOT the current-balance read — the current read here is an unrelated
    // sanity guard, and the tally adds a snapshot-derived `weight` parameter.
    // Even without the snapshot suppression, the current read does not flow into
    // the tally, so the linkage requirement keeps this quiet. (Belt-and-braces:
    // it would also be suppressed by `getPastVotes(_, snapshot)`.)
    const SAFE_CURRENT_READ_NOT_TALLIED: &str = r#"
        interface IToken {
            function getVotes(address a) external view returns (uint256);
            function getPastVotes(address a, uint256 b) external view returns (uint256);
        }
        contract Gov {
            IToken public token;
            struct Proposal { uint snapshot; uint forVotes; }
            mapping(uint => Proposal) public proposals;
            function _countVote(uint proposalId, address account, uint8 support) internal {
                Proposal storage proposal = proposals[proposalId];
                uint live = token.getVotes(account);
                require(live >= 0, "sane");
                uint weight = token.getPastVotes(account, proposal.snapshot);
                proposal.forVotes = proposal.forVotes + weight;
                support;
            }
        }
    "#;

    #[test]
    fn fires_on_current_votes() {
        assert!(fires(VULN_CURRENT_VOTES), "{:#?}", run(VULN_CURRENT_VOTES));
    }
    #[test]
    fn fires_on_balanceof_weight() {
        assert!(fires(VULN_BALANCEOF), "{:#?}", run(VULN_BALANCEOF));
    }
    #[test]
    fn fires_on_getvotes_now() {
        assert!(fires(VULN_GETVOTES_NOW), "{:#?}", run(VULN_GETVOTES_NOW));
    }
    #[test]
    fn fires_on_prior_votes_at_block_number() {
        assert!(fires(VULN_PRIOR_AT_BLOCK_NUMBER), "{:#?}", run(VULN_PRIOR_AT_BLOCK_NUMBER));
    }

    #[test]
    fn silent_on_startblock_snapshot() {
        assert!(!fires(SAFE_PRIOR_AT_STARTBLOCK), "{:#?}", run(SAFE_PRIOR_AT_STARTBLOCK));
    }
    #[test]
    fn silent_on_pastvotes_snapshot_accessor() {
        assert!(!fires(SAFE_PASTVOTES_SNAPSHOT), "{:#?}", run(SAFE_PASTVOTES_SNAPSHOT));
    }
    #[test]
    fn silent_on_cached_startblock() {
        assert!(!fires(SAFE_CACHED_STARTBLOCK), "{:#?}", run(SAFE_CACHED_STARTBLOCK));
    }
    #[test]
    fn silent_on_plain_balanceof() {
        assert!(!fires(SAFE_PLAIN_BALANCE), "{:#?}", run(SAFE_PLAIN_BALANCE));
    }
    #[test]
    fn silent_on_execute_proposer_threshold() {
        // The real olympus-v3 GovernorBravoDelegate.execute FP must stay quiet.
        assert!(!fires(SAFE_EXECUTE_PROPOSER_THRESHOLD), "{:#?}", run(SAFE_EXECUTE_PROPOSER_THRESHOLD));
    }
    #[test]
    fn silent_on_bravo_min_of_prior_and_current() {
        assert!(
            !fires(SAFE_BRAVO_MIN_OF_PRIOR_AND_CURRENT),
            "{:#?}",
            run(SAFE_BRAVO_MIN_OF_PRIOR_AND_CURRENT)
        );
    }
    #[test]
    fn silent_when_current_read_not_tallied() {
        assert!(!fires(SAFE_CURRENT_READ_NOT_TALLIED), "{:#?}", run(SAFE_CURRENT_READ_NOT_TALLIED));
    }
}
