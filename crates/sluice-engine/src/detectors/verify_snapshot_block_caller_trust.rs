//! Verify-snapshot block caller-trust — an aggregate-signature / stake-quorum
//! verification function trusts a **caller-supplied reference block** whose only
//! guard is that it lies in the *past* (`referenceBlock < block.number`), then
//! reads historical per-operator stake/weight at that block, sums it, and the
//! aggregate decides whether a stake/weight threshold is met. Because the only
//! bound is "older than now", the caller can pick a *stale* block at which a
//! since-slashed / since-exited operator still held stake — older is always
//! attacker-favorable for clearing a threshold.
//!
//! ## The shape (EigenLayer middleware `BLSSignatureChecker.checkSignatures`)
//!
//! ```solidity
//! function checkSignatures(
//!     bytes32 msgHash,
//!     bytes calldata quorumNumbers,
//!     uint32 referenceBlockNumber,                 // <-- caller-supplied
//!     NonSignerStakesAndSignature memory params
//! ) public view returns (QuorumStakeTotals memory, bytes32) {
//!     ...
//!     require(referenceBlockNumber < uint32(block.number), InvalidReferenceBlocknumber()); // SOLE bound: just "in the past"
//!     ...
//!     for (uint256 i = 0; i < quorumNumbers.length; i++) {
//!         // total stake for the quorum AT referenceBlockNumber
//!         stakeTotals.totalStakeForQuorum[i] = stakeRegistry
//!             .getTotalStakeAtBlockNumberFromIndex({ ..., blockNumber: referenceBlockNumber, ... });
//!         stakeTotals.signedStakeForQuorum[i] = stakeTotals.totalStakeForQuorum[i];
//!         for (... each nonsigner ...) {
//!             // subtract each nonsigner's stake AT referenceBlockNumber
//!             stakeTotals.signedStakeForQuorum[i] -= stakeRegistry
//!                 .getStakeAtBlockNumberAndIndex({ ..., blockNumber: referenceBlockNumber, ... });
//!         }
//!     }
//!     ...
//!     return (stakeTotals, signatoryRecordHash);   // signed-stake totals -> caller's threshold check
//! }
//! ```
//!
//! Every historical read (`getQuorumBitmapAtBlockNumberByIndex`,
//! `getApkHashAtBlockNumberAndIndex`, `getTotalStakeAtBlockNumberFromIndex`,
//! `getStakeAtBlockNumberAndIndex`) is keyed by the **same** caller-supplied
//! `referenceBlockNumber`, and the results are *netted* into a per-quorum
//! `signedStakeForQuorum` total (`= totalStake`, then `-= nonSignerStake`). That
//! signed-stake total is exactly the quantity an operator-set / task contract
//! compares against its stake threshold. The only validation of the block is
//! `referenceBlockNumber < block.number` — i.e. it must merely be in the past.
//!
//! There is **no lower (freshness) bound**: no `referenceBlockNumber > block.number
//! - MAX_STALENESS` and no pin to a stored `quorumUpdateBlockNumber`. So a caller is
//! free to choose *any* historical block. Since an operator who has since been
//! slashed or has exited a quorum still shows nonzero stake at an older block, and
//! the verification trusts those historical stakes additively, picking an older
//! reference block is monotonically attacker-favorable for clearing a stake/weight
//! threshold — the signed-stake aggregate is computed against stale, more-favorable
//! state than "now".
//!
//! ## Why it stays at ~0 false positives
//!
//! Every anchor is structural and the genuine read family + the netting
//! aggregation + the sole `< block.number` bound co-occur only in this verification
//! shape:
//!   * a `uint*` parameter named like a reference block (`referenceBlock*` /
//!     `blockNumber` / `referenceBlockNumber`);
//!   * that parameter is passed as the block argument to **>= 2** historical
//!     snapshot reads of the AVS stake/weight/quorum-bitmap family
//!     (`getStake*AtBlockNumber*`, `getTotalStake*AtBlockNumber*`,
//!     `get*WeightAtBlock*`, `getQuorumBitmapAtBlockNumber*`,
//!     `getApkHash*AtBlock*`);
//!   * the function performs a **stake/weight aggregation** — a `+=` / `-=` netting
//!     (the signed-stake summation), so the reads feed a threshold-bound total
//!     rather than being returned verbatim;
//!   * the parameter's guard against `block.number` is a single `<` / `<=` *upper*
//!     bound ("must be in the past").
//!
//! ## Suppression (the SAFE shapes)
//!
//!   * **Freshness floor present** — the block is *also* bounded from below against
//!     recency: a `referenceBlock > block.number - MAX` comparison (a `block.number
//!     - X` subtraction), or an equality / `>=` pin to a stored
//!     `quorumUpdateBlock*`-named state variable. Either makes the block fresh, so
//!     a since-slashed operator cannot be cherry-picked, and the detector is silent.
//!   * **Reads only return data** — if there is no `+=`/`-=` stake aggregation, the
//!     function is a *getter* that hands the per-operator snapshot values straight
//!     back (`OperatorStateRetriever.getOperatorState` /
//!     `getCheckSignaturesIndices`, which assemble structs/arrays and never net a
//!     signed-stake total). Those are out of class and stay silent.
//!
//! Real target:
//! `eigenlayer-middleware/src/BLSSignatureChecker.sol::checkSignatures` (the sole
//! bound at line 60 feeding the `getTotalStakeAtBlockNumberFromIndex` /
//! `getStakeAtBlockNumberAndIndex` reads at lines 147-152 and 163-169).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{AssignOp, BinOp, Expr, ExprKind, Function, Span};

use super::prelude::*;

pub struct VerifySnapshotBlockCallerTrustDetector;

impl Detector for VerifySnapshotBlockCallerTrustDetector {
    fn id(&self) -> &'static str {
        "verify-snapshot-block-caller-trust"
    }
    fn category(&self) -> Category {
        Category::VerifySnapshotBlockCallerTrust
    }
    fn description(&self) -> &'static str {
        "Aggregate-signature / stake-quorum verification trusts a caller-supplied reference block whose only \
         bound is `< block.number`, then sums historical per-operator stake/weight at that block toward a \
         threshold — a since-slashed/exited operator still has stake at an older block (EigenLayer \
         BLSSignatureChecker.checkSignatures class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // A signature/stake verification predicate is a read-only check
            // (`view`/`pure`); a state-mutating function is out of this class. The
            // cited target `checkSignatures` is `public view`.
            if !f.is_view_or_pure() {
                continue;
            }

            // (1) A caller-supplied reference-block parameter (`uint*`, block-named).
            let Some(blk) = reference_block_param(f) else { continue };

            // (2) It is fed as the block argument to >= 2 historical AVS snapshot
            //     reads (stake / total-stake / weight / quorum-bitmap / apk-hash at
            //     a block number). This is the heart: multiple historical reads keyed
            //     by the same caller block.
            let reads = snapshot_reads_fed_param(f, &blk);
            if reads.len() < 2 {
                continue;
            }

            // (3) The reads feed a stake/weight AGGREGATION — a `+=`/`-=` netting (the
            //     signed-stake summation). Without it, the function is a getter that
            //     returns per-operator snapshots verbatim (the `OperatorStateRetriever`
            //     family) — out of class. This is the "reads only return data"
            //     suppression, expressed positively.
            if !has_stake_aggregation(f) {
                continue;
            }

            // (4) The parameter's bound against `block.number` is a single `<`/`<=`
            //     UPPER bound ("must be in the past") — the sole guard. If there is no
            //     such upper-bound compare at all, this is not the trusted-past shape.
            let Some(bound_span) = upper_bound_vs_block_number(f, &blk) else { continue };

            // (5) SUPPRESS when a freshness FLOOR exists: a `block.number - MAX`
            //     subtraction comparison on the block, OR an equality/`>=` pin to a
            //     stored `quorumUpdateBlock*` state variable. Either bounds the block
            //     from below (recency), defeating the stale-block cherry-pick.
            if has_freshness_floor(cx, f, &blk) {
                continue;
            }

            let span = reads.first().map(|r| r.span).unwrap_or(bound_span);
            let read_list = reads
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>()
                .join("`, `");

            let b = report!(self, Category::VerifySnapshotBlockCallerTrust,
                title = "Verification trusts a caller-supplied reference block bounded only by `< block.number`, summing stale historical stake toward a threshold",
                severity = Severity::High,
                confidence = 0.8,
                dimensions = [Dimension::Invariant, Dimension::Frontier],
                message = format!(
                    "`{fname}` takes the caller-supplied reference-block parameter `{blk}` and feeds it as the \
                     block argument to {n} historical AVS snapshot reads (`{reads}`), then nets the results \
                     into a signed stake/weight total that decides whether a stake threshold is met. The ONLY \
                     guard on `{blk}` is a single upper bound `{blk} < block.number` — it must merely lie in \
                     the *past*. There is no freshness floor: no `{blk} > block.number - MAX` and no pin to a \
                     stored `quorumUpdateBlockNumber`. Because an operator that has since been slashed or has \
                     exited a quorum still shows nonzero stake at an *older* block, and the verification trusts \
                     those historical stakes additively, a caller can pick any stale-but-past reference block \
                     at which the signing set's stake was more favorable and clear the threshold against state \
                     that no longer holds. Older is monotonically attacker-favorable. This is the EigenLayer \
                     middleware `BLSSignatureChecker.checkSignatures` class.",
                    fname = f.name,
                    blk = blk,
                    n = reads.len(),
                    reads = read_list,
                ),
                recommendation = format!(
                    "Bound `{blk}` from below as well as above: in addition to `{blk} < block.number`, require \
                     a recency floor — `require({blk} + MAX_REFERENCE_BLOCK_AGE >= block.number)` \
                     (equivalently `require(block.number - {blk} <= MAX)`), or pin it to a recent stored \
                     `quorumUpdateBlockNumber` (`require({blk} >= quorumUpdateBlockNumber[q])`), so the \
                     historical stake snapshot cannot be cherry-picked from an arbitrarily old block at which \
                     a since-slashed/exited operator still counted toward the quorum.",
                    blk = blk,
                ),
            );
            out.push(finish_at(cx, b, f.id, span));
            // One finding per verification function is enough — the fix is the same.
        }
        out
    }
}

// --------------------------------------------------------------------------- gates

/// A located historical snapshot read fed the reference-block parameter.
struct SnapshotRead {
    /// The resolved read method name (`getTotalStakeAtBlockNumberFromIndex`).
    name: String,
    /// Source span of the call (where to anchor the finding).
    span: Span,
}

/// A caller-supplied reference-block parameter: an unsigned-int parameter whose
/// name reads as a block number (`referenceBlock*` / `blockNumber` /
/// `referenceBlockNumber` / `*BlockNumber`). Returns the parameter name.
fn reference_block_param(f: &Function) -> Option<String> {
    f.params.iter().find_map(|p| {
        let name = p.name.as_deref()?;
        if !is_unsigned_int(&p.ty) {
            return None;
        }
        if is_reference_block_name(name) {
            Some(name.to_string())
        } else {
            None
        }
    })
}

/// `name` reads as a reference-block parameter. We match the AVS spelling
/// (`referenceBlock`, `referenceBlockNumber`), a bare `blockNumber`, or any
/// camelCase identifier ending in `BlockNumber` / `Block` (`refBlock`,
/// `snapshotBlockNumber`). We deliberately do NOT match `*timestamp`/`*slot` — this
/// class is block-number keyed (the historical-stake snapshot reads are by block).
fn is_reference_block_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "referenceblock"
        || l == "referenceblocknumber"
        || l == "blocknumber"
        || l == "refblock"
        || l == "refblocknumber"
        || l.ends_with("referenceblock")
        || l.ends_with("referenceblocknumber")
        || l.ends_with("blocknumber")
}

/// Textual type test for an unsigned integer (`uint`, `uint32`, `uint256`, possibly
/// with a `memory`/`calldata` location suffix). The reference block is a `uint32` in
/// the real target.
fn is_unsigned_int(ty: &str) -> bool {
    let t = ty.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
    t == "uint" || (t.starts_with("uint") && t[4..].chars().all(|c| c.is_ascii_digit()))
}

/// Every historical AVS snapshot read in `f` that is fed `blk` as an argument. A
/// snapshot read is a call whose resolved method name is in the historical
/// stake/weight/quorum-bitmap/apk-hash-at-block family AND one of whose arguments
/// mentions the reference-block parameter `blk`. De-duplicated by name+span is not
/// needed — each call site is a distinct read.
fn snapshot_reads_fed_param(f: &Function, blk: &str) -> Vec<SnapshotRead> {
    let mut out: Vec<SnapshotRead> = Vec::new();
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            let ExprKind::Call(c) = &e.kind else { return };
            let Some(name) = &c.func_name else { return };
            if !is_snapshot_read_name(name) {
                return;
            }
            // The reference block must actually be an argument of this read (the
            // call is keyed by the caller block). Named args are preserved in
            // `c.args`, so an identifier mention inside any arg counts.
            if c.args.iter().any(|a| expr_mentions_ident(a, blk)) {
                out.push(SnapshotRead { name: name.clone(), span: e.span });
            }
        });
    }
    out
}

/// A method name that reads a historical AVS stake / total-stake / weight /
/// quorum-bitmap / apk-hash **value at a block number**. These are the
/// `getStake*AtBlockNumber*` / `getTotalStake*AtBlockNumber*` / `get*WeightAtBlock*`
/// / `getQuorumBitmapAtBlockNumber*` / `getApkHash*AtBlock*` reads. The
/// `*AtBlock(Number)*` token is the discriminator: it is a *historical snapshot*
/// keyed by a block, exactly the kind of read whose result depends on the chosen
/// reference block.
///
/// We split on the `atblock` token and require the value semantics
/// (stake/weight/quorumbitmap/apk) to appear in the name, while EXCLUDING the
/// *position/list* lookups whose prefix (before `atblock`) names an `index` /
/// `indices` / `list` — `getStakeUpdate**Index**AtBlockNumber`,
/// `getQuorumBitmap**Indices**AtBlockNumber`, `getTotalStake**Indices**AtBlockNumber`,
/// `getOperator**List**AtBlockNumber`, `getApk**Indices**AtBlockNumber`. Those
/// return positions/membership (an index into a checkpoint array, or an operator
/// list), NOT the stake/weight quantity summed toward the threshold. A trailing
/// `AndIndex` / `ByIndex` / `FromIndex` *after* `AtBlockNumber` is fine — there the
/// index is an input argument and the call still returns the value
/// (`getStakeAtBlockNumber**AndIndex**`, `getTotalStakeAtBlockNumber**FromIndex**`).
fn is_snapshot_read_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // Locate the `atblock` boundary; the prefix carries the read's semantics.
    let Some(idx) = l.find("atblock") else { return false };
    let prefix = &l[..idx];
    // Position/list lookups (index/indices/list in the *prefix*) are not value reads.
    if prefix.contains("index") || prefix.contains("indices") || prefix.contains("list") {
        return false;
    }
    // The value family: a stake / weight / quorum-bitmap / apk-hash quantity.
    prefix.contains("stake")
        || prefix.contains("weight")
        || prefix.contains("quorumbitmap")
        || prefix.contains("apkhash")
}

/// Does `f` perform a stake/weight **aggregation** — a `+=` or `-=` compound
/// assignment (the signed-stake summation / netting)? This is the positive form of
/// the "reads only return data" suppression: a verification that *sums* the
/// historical reads into a threshold-bound total has such an aggregation; a getter
/// that returns the snapshots verbatim (the `OperatorStateRetriever` family) only
/// uses plain `=` assignments into structs/arrays and has none.
fn has_stake_aggregation(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Assign { op, .. } = &e.kind {
                if matches!(op, AssignOp::Add | AssignOp::Sub) {
                    found = true;
                }
            }
        });
        if found {
            break;
        }
    }
    found
}

/// The span of an *upper-bound* comparison of `blk` against `block.number`: a
/// `blk < block.number` / `blk <= block.number` (or the mirror `block.number > blk`
/// / `block.number >= blk`). This is the "must be in the past" sole bound, and the
/// positive anchor that ties the finding to the trusted-past shape. Returns the span
/// of that comparison (for finding placement if there are no reads, though there
/// always are by gate (2)).
fn upper_bound_vs_block_number(f: &Function, blk: &str) -> Option<Span> {
    let mut hit: Option<Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Binary { op, lhs, rhs } = &e.kind else { return };
            if !matches!(op, BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge) {
                return;
            }
            // Identify which side is `blk` and which reads `block.number`.
            let lhs_blk = expr_is_ident(lhs, blk);
            let rhs_blk = expr_is_ident(rhs, blk);
            let lhs_bn = expr_reads_block_number(lhs);
            let rhs_bn = expr_reads_block_number(rhs);
            // `blk < block.number` / `blk <= block.number`
            let blk_lt_bn = lhs_blk && rhs_bn && matches!(op, BinOp::Lt | BinOp::Le);
            // `block.number > blk` / `block.number >= blk`
            let bn_gt_blk = rhs_blk && lhs_bn && matches!(op, BinOp::Gt | BinOp::Ge);
            if blk_lt_bn || bn_gt_blk {
                hit = Some(e.span);
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Is there a **freshness floor** on `blk` — a *lower* bound enforcing recency?
/// Recognized as either:
///   * a comparison binding `blk` against a `block.number - MAX` subtraction (the
///     canonical `blk > block.number - MAX` / `block.number - blk <= MAX` window),
///     or its addition mirror `blk + MAX >= block.number`; OR
///   * an equality / `>=` comparison pinning `blk` to a stored
///     `quorumUpdateBlock*`-named state variable (a per-quorum recency anchor).
///
/// A bare upper bound `blk < block.number` is deliberately NOT a floor — it is the
/// very (insufficient) guard the bug relies on.
fn has_freshness_floor(cx: &AnalysisContext, f: &Function, blk: &str) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            let ExprKind::Binary { op, lhs, rhs } = &e.kind else { return };
            if !op.is_comparison() {
                return;
            }
            // The comparison must reference the reference block somewhere.
            if !(expr_mentions_ident(lhs, blk) || expr_mentions_ident(rhs, blk)) {
                return;
            }
            // (a) `block.number - X` subtraction anywhere in the comparison.
            if expr_has_blocknum_subtraction(lhs) || expr_has_blocknum_subtraction(rhs) {
                found = true;
                return;
            }
            // (b) `blk + MAX >= block.number` — addition to blk vs block.number.
            let blk_plus_vs_bn = (expr_has_addition_of(lhs, blk) && expr_reads_block_number(rhs))
                || (expr_has_addition_of(rhs, blk) && expr_reads_block_number(lhs));
            if blk_plus_vs_bn {
                found = true;
                return;
            }
            // (c) equality / lower-bound pin to a stored `quorumUpdateBlock*` var.
            if matches!(op, BinOp::Eq | BinOp::Ge | BinOp::Le | BinOp::Gt | BinOp::Lt)
                && (expr_mentions_quorum_update_block(cx, f, lhs)
                    || expr_mentions_quorum_update_block(cx, f, rhs))
            {
                found = true;
            }
        });
        if found {
            break;
        }
    }
    if found {
        return true;
    }
    // Textual fallback (covers idioms the structural pass may lower unusually): the
    // function source binds `blk` against a `block.number -` window, or pins it to a
    // stored quorum-update block. Keyed on comment-stripped, lowercased source.
    let src = cx.source_text(f.span);
    let compact: String = src.chars().filter(|c| !c.is_whitespace()).collect();
    let bl = blk.to_ascii_lowercase();
    compact.contains(&format!("block.number-{bl}"))
        || (compact.contains(&format!("{bl}+")) && compact.contains(">=block.number"))
        || compact.contains("quorumupdateblock")
}

// --------------------------------------------------------------------------- expr utils

/// Is `e` exactly the bare identifier `name`?
fn expr_is_ident(e: &Expr, name: &str) -> bool {
    matches!(&e.kind, ExprKind::Ident(n) if n == name)
}

/// Does `e` (anywhere) read `block.number`?
fn expr_reads_block_number(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Member { base, member } = &sub.kind {
            if member.eq_ignore_ascii_case("number")
                && matches!(&base.kind, ExprKind::Ident(b) if b == "block")
            {
                found = true;
            }
        }
    });
    found
}

/// `block.number - X` subtraction anywhere in `e`.
fn expr_has_blocknum_subtraction(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Binary { op: BinOp::Sub, lhs, rhs } = &sub.kind {
            if expr_reads_block_number(lhs) || expr_reads_block_number(rhs) {
                found = true;
            }
        }
    });
    found
}

/// `<name> + X` addition anywhere in `e` (the `blk + MAX` recency form).
fn expr_has_addition_of(e: &Expr, name: &str) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Binary { op: BinOp::Add, lhs, rhs } = &sub.kind {
            if expr_mentions_ident(lhs, name) || expr_mentions_ident(rhs, name) {
                found = true;
            }
        }
    });
    found
}

/// Does `e` mention a `quorumUpdateBlock*`-named operand that is a state variable of
/// `f`'s contract (the per-quorum recency anchor)? We accept either a bare
/// identifier or an index/member access whose root is such a state var
/// (`quorumUpdateBlockNumber[quorumNumber]`).
fn expr_mentions_quorum_update_block(cx: &AnalysisContext, f: &Function, e: &Expr) -> bool {
    let contract = cx.contract_of(f.id);
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        // Root of any ident / member / index chain.
        if let Some(root) = root_ident_str(sub) {
            if is_quorum_update_block_name(root)
                && contract.map(|c| is_state_var(c, root)).unwrap_or(true)
            {
                found = true;
            }
        }
    });
    found
}

/// A name denoting a stored per-quorum recency anchor block.
fn is_quorum_update_block_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("quorumupdateblock") || l.contains("quorumupdateblocknumber")
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "verify-snapshot-block-caller-trust")
    }

    // VULN — the EigenLayer `BLSSignatureChecker.checkSignatures` shape, reduced: a
    // caller-supplied `referenceBlockNumber` whose ONLY bound is `< block.number`,
    // fed to >= 2 historical stake/quorum-bitmap snapshot reads, with the results
    // netted into a `signedStakeForQuorum` total (`= total`, then `-= nonSigner`).
    const VULN: &str = r#"
        pragma solidity ^0.8.27;
        interface IStakeRegistry {
            function getTotalStakeAtBlockNumberFromIndex(uint8 q, uint32 blockNumber, uint256 index) external view returns (uint96);
            function getStakeAtBlockNumberAndIndex(uint8 q, uint32 blockNumber, bytes32 op, uint256 index) external view returns (uint96);
        }
        interface ICoord {
            function getQuorumBitmapAtBlockNumberByIndex(bytes32 op, uint32 blockNumber, uint256 index) external view returns (uint192);
        }
        contract BLSSignatureChecker {
            IStakeRegistry public stakeRegistry;
            ICoord public registryCoordinator;
            struct Totals { uint96[] totalStakeForQuorum; uint96[] signedStakeForQuorum; }
            function checkSignatures(
                bytes32 msgHash,
                bytes calldata quorumNumbers,
                uint32 referenceBlockNumber,
                bytes32[] calldata nonSigners
            ) public view returns (Totals memory) {
                require(referenceBlockNumber < uint32(block.number), "future");
                Totals memory stakeTotals;
                stakeTotals.totalStakeForQuorum = new uint96[](quorumNumbers.length);
                stakeTotals.signedStakeForQuorum = new uint96[](quorumNumbers.length);
                for (uint256 i = 0; i < quorumNumbers.length; i++) {
                    uint192 bm = registryCoordinator.getQuorumBitmapAtBlockNumberByIndex(nonSigners[i], referenceBlockNumber, i);
                    stakeTotals.totalStakeForQuorum[i] = stakeRegistry.getTotalStakeAtBlockNumberFromIndex(uint8(quorumNumbers[i]), referenceBlockNumber, i);
                    stakeTotals.signedStakeForQuorum[i] = stakeTotals.totalStakeForQuorum[i];
                    for (uint256 j = 0; j < nonSigners.length; j++) {
                        stakeTotals.signedStakeForQuorum[i] -= stakeRegistry.getStakeAtBlockNumberAndIndex(uint8(quorumNumbers[i]), referenceBlockNumber, nonSigners[j], j);
                    }
                }
                return stakeTotals;
            }
        }
    "#;

    #[test]
    fn fires_on_blssignaturechecker_shape() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    // SAFE (freshness floor) — same verification, but the reference block is ALSO
    // bounded from below against recency: `referenceBlockNumber + MAX >= block.number`.
    // A since-slashed operator cannot be cherry-picked, so suppress.
    const SAFE_FRESHNESS_FLOOR: &str = r#"
        pragma solidity ^0.8.27;
        interface IStakeRegistry {
            function getTotalStakeAtBlockNumberFromIndex(uint8 q, uint32 blockNumber, uint256 index) external view returns (uint96);
            function getStakeAtBlockNumberAndIndex(uint8 q, uint32 blockNumber, bytes32 op, uint256 index) external view returns (uint96);
        }
        contract BLSSignatureChecker {
            IStakeRegistry public stakeRegistry;
            uint32 public constant MAX_REFERENCE_BLOCK_AGE = 7200;
            struct Totals { uint96[] totalStakeForQuorum; uint96[] signedStakeForQuorum; }
            function checkSignatures(
                bytes calldata quorumNumbers,
                uint32 referenceBlockNumber,
                bytes32[] calldata nonSigners
            ) public view returns (Totals memory) {
                require(referenceBlockNumber < uint32(block.number), "future");
                require(referenceBlockNumber + MAX_REFERENCE_BLOCK_AGE >= uint32(block.number), "stale");
                Totals memory stakeTotals;
                stakeTotals.totalStakeForQuorum = new uint96[](quorumNumbers.length);
                stakeTotals.signedStakeForQuorum = new uint96[](quorumNumbers.length);
                for (uint256 i = 0; i < quorumNumbers.length; i++) {
                    stakeTotals.totalStakeForQuorum[i] = stakeRegistry.getTotalStakeAtBlockNumberFromIndex(uint8(quorumNumbers[i]), referenceBlockNumber, i);
                    stakeTotals.signedStakeForQuorum[i] = stakeTotals.totalStakeForQuorum[i];
                    for (uint256 j = 0; j < nonSigners.length; j++) {
                        stakeTotals.signedStakeForQuorum[i] -= stakeRegistry.getStakeAtBlockNumberAndIndex(uint8(quorumNumbers[i]), referenceBlockNumber, nonSigners[j], j);
                    }
                }
                return stakeTotals;
            }
        }
    "#;

    #[test]
    fn silent_with_freshness_floor() {
        assert!(!fires(SAFE_FRESHNESS_FLOOR), "{:#?}", run(SAFE_FRESHNESS_FLOOR));
    }

    // SAFE (window via block.number - MAX subtraction) — the `block.number - MAX`
    // lower-bound form: `require(referenceBlockNumber > block.number - MAX)`.
    const SAFE_WINDOW_SUBTRACTION: &str = r#"
        pragma solidity ^0.8.27;
        interface IStakeRegistry {
            function getTotalStakeAtBlockNumberFromIndex(uint8 q, uint32 blockNumber, uint256 index) external view returns (uint96);
            function getStakeAtBlockNumberAndIndex(uint8 q, uint32 blockNumber, bytes32 op, uint256 index) external view returns (uint96);
        }
        contract BLSSignatureChecker {
            IStakeRegistry public stakeRegistry;
            uint32 public constant MAX = 7200;
            struct Totals { uint96[] totalStakeForQuorum; uint96[] signedStakeForQuorum; }
            function checkSignatures(bytes calldata quorumNumbers, uint32 referenceBlockNumber, bytes32[] calldata nonSigners)
                public view returns (Totals memory)
            {
                require(referenceBlockNumber < uint32(block.number), "future");
                require(referenceBlockNumber > uint32(block.number) - MAX, "stale");
                Totals memory stakeTotals;
                stakeTotals.totalStakeForQuorum = new uint96[](quorumNumbers.length);
                stakeTotals.signedStakeForQuorum = new uint96[](quorumNumbers.length);
                for (uint256 i = 0; i < quorumNumbers.length; i++) {
                    stakeTotals.totalStakeForQuorum[i] = stakeRegistry.getTotalStakeAtBlockNumberFromIndex(uint8(quorumNumbers[i]), referenceBlockNumber, i);
                    stakeTotals.signedStakeForQuorum[i] = stakeTotals.totalStakeForQuorum[i];
                    for (uint256 j = 0; j < nonSigners.length; j++) {
                        stakeTotals.signedStakeForQuorum[i] -= stakeRegistry.getStakeAtBlockNumberAndIndex(uint8(quorumNumbers[i]), referenceBlockNumber, nonSigners[j], j);
                    }
                }
                return stakeTotals;
            }
        }
    "#;

    #[test]
    fn silent_with_window_subtraction() {
        assert!(!fires(SAFE_WINDOW_SUBTRACTION), "{:#?}", run(SAFE_WINDOW_SUBTRACTION));
    }

    // SAFE (pinned to stored quorumUpdateBlockNumber) — the block is pinned (`>=`) to
    // a stored per-quorum recency anchor, a stronger floor than a sliding window.
    const SAFE_QUORUM_UPDATE_PIN: &str = r#"
        pragma solidity ^0.8.27;
        interface IStakeRegistry {
            function getTotalStakeAtBlockNumberFromIndex(uint8 q, uint32 blockNumber, uint256 index) external view returns (uint96);
            function getStakeAtBlockNumberAndIndex(uint8 q, uint32 blockNumber, bytes32 op, uint256 index) external view returns (uint96);
        }
        contract BLSSignatureChecker {
            IStakeRegistry public stakeRegistry;
            mapping(uint8 => uint256) public quorumUpdateBlockNumber;
            struct Totals { uint96[] totalStakeForQuorum; uint96[] signedStakeForQuorum; }
            function checkSignatures(bytes calldata quorumNumbers, uint32 referenceBlockNumber, bytes32[] calldata nonSigners)
                public view returns (Totals memory)
            {
                require(referenceBlockNumber < uint32(block.number), "future");
                Totals memory stakeTotals;
                stakeTotals.totalStakeForQuorum = new uint96[](quorumNumbers.length);
                stakeTotals.signedStakeForQuorum = new uint96[](quorumNumbers.length);
                for (uint256 i = 0; i < quorumNumbers.length; i++) {
                    require(referenceBlockNumber >= quorumUpdateBlockNumber[uint8(quorumNumbers[i])], "stale quorum");
                    stakeTotals.totalStakeForQuorum[i] = stakeRegistry.getTotalStakeAtBlockNumberFromIndex(uint8(quorumNumbers[i]), referenceBlockNumber, i);
                    stakeTotals.signedStakeForQuorum[i] = stakeTotals.totalStakeForQuorum[i];
                    for (uint256 j = 0; j < nonSigners.length; j++) {
                        stakeTotals.signedStakeForQuorum[i] -= stakeRegistry.getStakeAtBlockNumberAndIndex(uint8(quorumNumbers[i]), referenceBlockNumber, nonSigners[j], j);
                    }
                }
                return stakeTotals;
            }
        }
    "#;

    #[test]
    fn silent_when_pinned_to_quorum_update_block() {
        assert!(!fires(SAFE_QUORUM_UPDATE_PIN), "{:#?}", run(SAFE_QUORUM_UPDATE_PIN));
    }

    // SAFE (reads only return data) — the `OperatorStateRetriever` family: a
    // caller-supplied `blockNumber` is fed to historical stake reads, but the values
    // are assembled into a returned struct/array (plain `=` assignments), never netted
    // into a signed-stake total. No `+=`/`-=` aggregation -> out of class. (Also no
    // `< block.number` guard, a second reason it stays silent.)
    const SAFE_GETTER_RETURNS_DATA: &str = r#"
        pragma solidity ^0.8.27;
        interface IStakeRegistry {
            function getStakeAtBlockNumber(bytes32 op, uint8 q, uint32 blockNumber) external view returns (uint96);
        }
        interface IIndexRegistry {
            function getOperatorListAtBlockNumber(uint8 q, uint32 blockNumber) external view returns (bytes32[] memory);
        }
        contract OperatorStateRetriever {
            struct Operator { address operator; bytes32 operatorId; uint96 stake; }
            function getOperatorState(IStakeRegistry stakeRegistry, IIndexRegistry indexRegistry, bytes memory quorumNumbers, uint32 blockNumber)
                public view returns (Operator[][] memory)
            {
                Operator[][] memory operators = new Operator[][](quorumNumbers.length);
                for (uint256 i = 0; i < quorumNumbers.length; i++) {
                    uint8 quorumNumber = uint8(quorumNumbers[i]);
                    bytes32[] memory operatorIds = indexRegistry.getOperatorListAtBlockNumber(quorumNumber, blockNumber);
                    operators[i] = new Operator[](operatorIds.length);
                    for (uint256 j = 0; j < operatorIds.length; j++) {
                        operators[i][j] = Operator({
                            operator: address(0),
                            operatorId: bytes32(operatorIds[j]),
                            stake: stakeRegistry.getStakeAtBlockNumber(bytes32(operatorIds[j]), quorumNumber, blockNumber)
                        });
                    }
                }
                return operators;
            }
        }
    "#;

    #[test]
    fn silent_on_getter_returning_data() {
        assert!(!fires(SAFE_GETTER_RETURNS_DATA), "{:#?}", run(SAFE_GETTER_RETURNS_DATA));
    }

    // SAFE (single read) — a verification that reads stake at a caller block but only
    // ONCE (one quorum, one total) and nets it: the `>= 2` historical-read anchor
    // keeps a single-read lookup out of class (it is not the multi-read quorum scan).
    const SAFE_SINGLE_READ: &str = r#"
        pragma solidity ^0.8.27;
        interface IStakeRegistry {
            function getTotalStakeAtBlockNumberFromIndex(uint8 q, uint32 blockNumber, uint256 index) external view returns (uint96);
        }
        contract MiniChecker {
            IStakeRegistry public stakeRegistry;
            function checkOne(uint8 q, uint32 referenceBlockNumber, uint96 deduct) public view returns (uint96) {
                require(referenceBlockNumber < uint32(block.number), "future");
                uint96 signed = stakeRegistry.getTotalStakeAtBlockNumberFromIndex(q, referenceBlockNumber, 0);
                signed -= deduct;
                return signed;
            }
        }
    "#;

    #[test]
    fn silent_on_single_read() {
        assert!(!fires(SAFE_SINGLE_READ), "{:#?}", run(SAFE_SINGLE_READ));
    }

    // SAFE (current-block read) — the block fed to the reads is the *current*
    // `block.number`, not a caller parameter: there is no caller-supplied reference
    // block at all, so nothing to cherry-pick. (No block-named param -> gate (1)
    // fails.)
    const SAFE_CURRENT_BLOCK: &str = r#"
        pragma solidity ^0.8.27;
        interface IStakeRegistry {
            function getTotalStakeAtBlockNumberFromIndex(uint8 q, uint32 blockNumber, uint256 index) external view returns (uint96);
            function getStakeAtBlockNumberAndIndex(uint8 q, uint32 blockNumber, bytes32 op, uint256 index) external view returns (uint96);
        }
        contract LiveChecker {
            IStakeRegistry public stakeRegistry;
            function checkLive(bytes calldata quorumNumbers, bytes32[] calldata nonSigners) public view returns (uint96) {
                uint32 bn = uint32(block.number) - 1;
                uint96 signed;
                for (uint256 i = 0; i < quorumNumbers.length; i++) {
                    signed += stakeRegistry.getTotalStakeAtBlockNumberFromIndex(uint8(quorumNumbers[i]), bn, i);
                    for (uint256 j = 0; j < nonSigners.length; j++) {
                        signed -= stakeRegistry.getStakeAtBlockNumberAndIndex(uint8(quorumNumbers[i]), bn, nonSigners[j], j);
                    }
                }
                return signed;
            }
        }
    "#;

    #[test]
    fn silent_on_current_block_read() {
        assert!(!fires(SAFE_CURRENT_BLOCK), "{:#?}", run(SAFE_CURRENT_BLOCK));
    }
}
