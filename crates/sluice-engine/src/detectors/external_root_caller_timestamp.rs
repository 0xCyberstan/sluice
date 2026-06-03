//! External / beacon root resolved from a CALLER-CONTROLLED timestamp with no
//! recency floor on the consuming path — the EIP-4788 stale-root acceptance class.
//!
//! ## The shape
//!
//! Post-Dencun, a contract that proves beacon-chain state to credit native
//! restaking stake resolves the *beacon block root* for a given slot via the
//! EIP-4788 ring buffer at `BEACON_ROOTS_ADDRESS`, keyed by a **timestamp**:
//!
//! ```solidity
//! function _getParentBlockRoot(uint64 timestamp) internal view returns (bytes32) {
//!     (bool ok, bytes memory r) = BEACON_ROOTS_ADDRESS.staticcall(abi.encode(timestamp));
//!     if (ok && r.length > 0) return abi.decode(r, (bytes32));
//!     revert BeaconRootFetchError();
//! }
//! ```
//!
//! The danger is when the `timestamp` fed to that lookup is **caller-controlled**
//! — a function parameter (or, in the real target, a field of a calldata struct
//! parameter) — and the resolved root then drives **proof acceptance that credits
//! stake**, with **no recency floor** on the consuming path:
//!
//! ```solidity
//! function validateWithdrawalCredentials(
//!     address nodeOwner,
//!     BeaconProofs.BeaconStateRootProof calldata beaconStateRootProof,   // <-- .timestamp is caller-chosen
//!     BeaconProofs.ValidatorFieldsProof[] calldata validatorFieldsProofs
//! ) external {
//!     if (beaconStateRootProof.timestamp == block.timestamp) revert BeaconTimestampIsCurrent();
//!     if (beaconStateRootProof.timestamp < node.lastSnapshotTimestamp           // <-- lower bound vs a STORED time,
//!         || beaconStateRootProof.timestamp < node.currentSnapshotTimestamp) //     NOT a recency floor vs block.timestamp
//!         revert BeaconTimestampTooOld();
//!     BeaconProofs.validateBeaconStateRootProof(
//!         _getParentBlockRoot(beaconStateRootProof.timestamp), beaconStateRootProof);   // root from caller ts
//!     ...
//!     _increaseBalance(nodeOwner, totalRestakedWei);                          // <-- credits stake
//! }
//! ```
//!
//! Read the guards. `!= block.timestamp` only rejects the *current* block. The two
//! `< node.*SnapshotTimestamp` checks are *lower* bounds against the node's own
//! stored snapshot times — they keep the proof from going *backwards* relative to
//! the last snapshot, but place **no ceiling on staleness relative to now**. There
//! is no `require(timestamp >= block.timestamp - MAX_AGE)`. So an attacker is free
//! to pick *any* still-resolvable historical timestamp whose beacon root is in the
//! 4788 ring buffer and whose corresponding validator state is favorable, and have
//! it accepted as a valid proof that mints restaking credit. (EIP-4788 keeps a
//! rolling ~8191-slot, ~27h window — ample room to cherry-pick a stale-but-valid
//! root.) This is the Karak `NativeVault.validateWithdrawalCredentials` class.
//!
//! ## Why it stays at ~0 false positives
//!
//! Every anchor is structural and specific, and the detector is **suppressed the
//! moment a recency floor on the timestamp argument exists**:
//!   * the resolved value is a *beacon/parent-block-root lookup keyed by a
//!     timestamp* — either a call to a `*ParentBlockRoot*` / `*BeaconRoot*` helper,
//!     or a direct `.staticcall` to a `BEACON_ROOTS`-named address;
//!   * the timestamp fed into that lookup **root-resolves to a caller-controlled
//!     parameter** (a bare `uint*` timestamp param, or `param.timestamp` where the
//!     struct param is a proof/beacon struct) — not `block.timestamp`, not a stored
//!     state var;
//!   * the function **credits stake / accepts a proof** — it reaches a
//!     balance-increase / mint sink, or a `validate*`/`verify*` proof call, after
//!     resolving the root;
//!   * **SUPPRESS** when the consuming function bounds that timestamp against
//!     `block.timestamp` with a *recency floor*: any comparison whose operands pair
//!     the caller timestamp with a `block.timestamp - MAX_AGE` (or `block.timestamp
//!     - ts <= MAX_AGE`) expression. A *lower* bound against a **stored** snapshot
//!     timestamp (`ts < node.lastSnapshotTimestamp`) is **not** a recency floor and
//!       does **not** suppress — it is exactly the insufficient guard in the bug.
//!
//! Real target:
//! `karak-audit/v2-contracts/src/NativeVault.sol::validateWithdrawalCredentials`
//! (the consumer, `_getParentBlockRoot(beaconStateRootProof.timestamp)` feeding
//! `validateBeaconStateRootProof` + `_increaseBalance`) and `_getParentBlockRoot`
//! (the `BEACON_ROOTS_ADDRESS.staticcall(abi.encode(timestamp))` lookup).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Call, CallKind, Expr, ExprKind, Function, Span};

use super::prelude::*;

pub struct ExternalRootCallerTimestampDetector;

impl Detector for ExternalRootCallerTimestampDetector {
    fn id(&self) -> &'static str {
        "external-root-caller-timestamp"
    }
    fn category(&self) -> Category {
        Category::ExternalRootCallerTimestamp
    }
    fn description(&self) -> &'static str {
        "Beacon/EIP-4788 root resolved from a caller-controlled timestamp with no recency floor, then driving proof acceptance / stake credit (Karak NativeVault.validateWithdrawalCredentials class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        // Set of internal helper names in the whole program that are themselves a
        // "root keyed by a timestamp" lookup — i.e. their body does a
        // `BEACON_ROOTS`-style `.staticcall(abi.encode(<their ts param>))`. The Karak
        // consumer reaches the 4788 staticcall *through* `_getParentBlockRoot`, so we
        // must recognize a call to such a helper, not only an inline staticcall.
        let root_lookup_helpers = root_lookup_helper_names(cx);

        for f in cx.entry_points() {
            // (1) Locate the root lookup fed a caller-controlled timestamp: either a
            //     call to a root-lookup helper, or a direct beacon-roots staticcall —
            //     whose timestamp argument root-resolves to a parameter of `f`.
            let Some(hit) = root_lookup_from_caller_ts(f, &root_lookup_helpers) else {
                continue;
            };

            // (2) The resolved root must drive proof acceptance / a stake credit. We
            //     anchor on the function reaching a proof-validation call (`validate*`
            //     / `verify*`) OR a stake-increase / mint sink. This ties the finding
            //     to "drives stake/proof acceptance" and excludes an idle read.
            if !accepts_proof_or_credits_stake(f) {
                continue;
            }

            // (3) SUPPRESS when a recency floor on the caller timestamp exists — a
            //     comparison binding that timestamp against `block.timestamp - MAX_AGE`.
            //     A lower bound vs a *stored* snapshot timestamp is NOT a recency floor.
            //     The floor may live in the CONSUMER (against `hit.ts_root`) OR inside
            //     the root-lookup HELPER (EigenLayer's `getParentBlockRoot` does
            //     `require(block.timestamp - timestamp < BUFFER * 12)` against its own
            //     `timestamp` parameter). Either location suppresses.
            if has_recency_floor(cx, f, &hit.ts_root) {
                continue;
            }
            if let Some(helper) = &hit.helper_name {
                if helper_has_recency_floor(cx, helper) {
                    continue;
                }
            }

            let b = report!(self, Category::ExternalRootCallerTimestamp,
                title = "Beacon/4788 root resolved from a caller-controlled timestamp with no recency floor",
                severity = Severity::High,
                confidence = 0.8,
                dimensions = [Dimension::ValueFlow, Dimension::Frontier],
                message = format!(
                    "`{fname}` resolves a beacon / parent-block root via {how} keyed by the \
                     caller-controlled timestamp `{ts}`, then uses the resolved root to accept a \
                     proof and credit stake. The consuming path (and the root-lookup helper) has NO \
                     recency floor on `{ts}`: there is no `require({ts} + MAX_AGE >= block.timestamp)` \
                     / `require(block.timestamp - {ts} < MAX_AGE)` (a `!= block.timestamp` check only \
                     rejects the current block, and a lower bound against a *stored* snapshot \
                     timestamp such as `{ts} < lastSnapshotTimestamp` bounds it from below, not from \
                     staleness). Because the EIP-4788 ring buffer keeps a rolling window of historical \
                     beacon roots (~8191 slots, ~27h), an attacker picks any stale-but-still-resolvable \
                     timestamp whose beacon root and validator state are favorable and submits it as a \
                     valid proof — minting restaking credit against stale state. This is the Karak \
                     `NativeVault.validateWithdrawalCredentials` / EIP-4788 stale-root acceptance class. \
                     (Contrast EigenLayer's `getParentBlockRoot`, which guards \
                     `require(block.timestamp - timestamp < BUFFER * 12)`.)",
                    fname = f.name,
                    how = hit.how,
                    ts = hit.ts_display,
                ),
                recommendation = format!(
                    "Bound the caller-supplied timestamp against the *current* time on the consuming \
                     path (or inside the root-lookup helper): \
                     `require({ts} + MAX_AGE >= block.timestamp)` (equivalently \
                     `require(block.timestamp - {ts} < MAX_AGE)`) before resolving the root, so only a \
                     recent beacon root can be used. Bounding the proof timestamp only from below \
                     (against a stored snapshot time) is insufficient — it still admits any \
                     historical root inside the 4788 window.",
                    ts = hit.ts_display,
                ),
            );
            out.push(finish_at(cx, b, f.id, hit.span));
            // One finding per consumer is enough — the fix is the same.
        }

        out
    }
}

/// A located "root keyed by a caller timestamp" lookup inside a consuming function.
struct RootLookupHit {
    /// Source span of the lookup call (where to anchor the finding).
    span: Span,
    /// Root identifier of the timestamp argument (the parameter name, e.g.
    /// `beaconStateRootProof` for `beaconStateRootProof.timestamp`, or `timestamp`
    /// for a bare param). Used by the recency-floor suppression and the message.
    ts_root: String,
    /// Display form of the timestamp argument (`beaconStateRootProof.timestamp`).
    ts_display: String,
    /// How the root is resolved, for the message (`_getParentBlockRoot(...)` /
    /// `BEACON_ROOTS_ADDRESS.staticcall(...)`).
    how: String,
    /// If the root is resolved via an internal helper call, the helper's name — so
    /// the recency-floor suppression can also inspect the helper's body (EigenLayer
    /// puts the `block.timestamp - timestamp < MAX_AGE` floor *inside*
    /// `getParentBlockRoot`, not in the consumer).
    helper_name: Option<String>,
}

/// Find, in `f`, a root-lookup call whose timestamp argument root-resolves to a
/// parameter of `f`. Two recognized lookup shapes:
///   * a call to an internal helper in `helpers` (a `*ParentBlockRoot*`/`*BeaconRoot*`
///     resolver) — `_getParentBlockRoot(beaconStateRootProof.timestamp)`;
///   * a direct `.staticcall` to a `BEACON_ROOTS`-named address whose encoded
///     argument is the caller timestamp.
fn root_lookup_from_caller_ts(f: &Function, helpers: &[String]) -> Option<RootLookupHit> {
    let mut hit: Option<RootLookupHit> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };

            // (a) Call to a root-lookup helper: `_getParentBlockRoot(<ts>)`.
            if let Some(name) = resolved_call_name(c) {
                if helpers.iter().any(|h| h == &name) {
                    if let Some((root, disp)) = caller_ts_arg(f, &c.args) {
                        hit = Some(RootLookupHit {
                            span: e.span,
                            ts_root: root,
                            ts_display: disp,
                            how: format!("`{name}(...)`"),
                            helper_name: Some(name.clone()),
                        });
                        return;
                    }
                }
            }

            // (b) Direct beacon-roots staticcall: `<BEACON_ROOTS>.staticcall(abi.encode(<ts>))`.
            if c.kind == CallKind::StaticCall && receiver_is_beacon_roots(c) {
                // The encoded timestamp is (transitively) an argument of the call; we
                // search the call's arguments for a caller-controlled timestamp ident.
                if let Some((root, disp)) = caller_ts_in_args(f, &c.args) {
                    hit = Some(RootLookupHit {
                        span: e.span,
                        ts_root: root,
                        ts_display: disp,
                        how: "a `BEACON_ROOTS` `.staticcall(abi.encode(timestamp))`".to_string(),
                        helper_name: None,
                    });
                }
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Names of internal functions whose body is itself a beacon-root-by-timestamp
/// lookup: a `BEACON_ROOTS`-named `.staticcall` *and* a timestamp-typed/named
/// parameter. This recognizes the `_getParentBlockRoot(uint64 timestamp)` helper so
/// a consumer that calls it (rather than inlining the staticcall) still matches.
fn root_lookup_helper_names(cx: &AnalysisContext) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for f in cx.functions() {
        if !f.has_body {
            continue;
        }
        // Name heuristic OR a beacon-roots staticcall in the body — either is enough,
        // but we additionally require a timestamp-ish parameter so the helper truly
        // resolves a root *from a timestamp*.
        let name_is_rootish = is_block_root_lookup_name(&f.name);
        let has_beacon_staticcall = any_call_where(f, |c| {
            c.kind == CallKind::StaticCall && receiver_is_beacon_roots(c)
        });
        if !(name_is_rootish || has_beacon_staticcall) {
            continue;
        }
        if !f.params.iter().any(param_is_timestamp) {
            continue;
        }
        if !out.iter().any(|n| n == &f.name) {
            out.push(f.name.clone());
        }
    }
    out
}

/// The first argument (root, display) that root-resolves to a parameter of `f` and
/// reads as a timestamp — used for the *helper-call* form, where the lookup takes
/// the timestamp directly as its argument. We accept either a bare timestamp param
/// or a `param.timestamp` field of a struct param.
fn caller_ts_arg(f: &Function, args: &[Expr]) -> Option<(String, String)> {
    args.iter().find_map(|a| caller_ts_expr(f, a))
}

/// As [`caller_ts_arg`] but searches *inside* each argument expression (for the
/// direct-staticcall form `abi.encode(timestamp)`, where the timestamp is nested
/// under an `abi.encode(...)` call argument).
fn caller_ts_in_args(f: &Function, args: &[Expr]) -> Option<(String, String)> {
    let mut found: Option<(String, String)> = None;
    for a in args {
        a.visit(&mut |sub| {
            if found.is_some() {
                return;
            }
            if let Some(r) = caller_ts_expr(f, sub) {
                found = Some(r);
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// Is `e` a caller-controlled timestamp value? Returns `(root_ident, display_text)`.
/// Accepted forms:
///   * a bare parameter whose name reads as a timestamp (`timestamp`, `ts`, ...):
///     root = the param name;
///   * `param.timestamp` (a timestamp-named field whose base root is a struct
///     parameter of `f`): root = the base parameter name (so the recency-floor
///     search, which keys on the same root, lines up).
fn caller_ts_expr(f: &Function, e: &Expr) -> Option<(String, String)> {
    match &e.kind {
        // `param.timestamp` — member access onto a (struct) parameter.
        ExprKind::Member { base, member } if is_timestamp_name(member) => {
            let root = root_ident_peeled(base)?;
            if is_param(f, &root) {
                return Some((root.clone(), format!("{root}.{member}")));
            }
            None
        }
        // bare `timestamp` parameter.
        ExprKind::Ident(n) if is_timestamp_name(n) && is_param(f, n) => {
            Some((n.clone(), n.clone()))
        }
        _ => None,
    }
}

/// Does `f` reach a proof-acceptance call (`validate*` / `verify*`) OR a
/// stake-increase / mint sink? This is the "drives stake/proof acceptance" anchor.
fn accepts_proof_or_credits_stake(f: &Function) -> bool {
    // Resolved call names (internal + external) reading as a proof validation.
    let proof_call = |n: &str| {
        let l = n.to_ascii_lowercase();
        (l.starts_with("validate") || l.starts_with("verify"))
            && (l.contains("proof") || l.contains("credential") || l.contains("withdrawal")
                || l.contains("beacon") || l.contains("balance") || l.contains("root"))
    };
    let credit_call = |n: &str| {
        let l = n.to_ascii_lowercase();
        l == "mint" || l == "_mint" || l == "safemint" || l.ends_with("mint")
            || l.contains("increasebalance") || l.contains("increasestake")
            || l.contains("credit") || l.contains("award") || l == "_deposit"
    };
    let any_name = |pred: &dyn Fn(&str) -> bool| {
        f.effects.internal_calls.iter().any(|n| pred(n))
            || f.effects
                .call_sites
                .iter()
                .any(|cs| cs.func_name.as_deref().map(pred).unwrap_or(false))
    };
    any_name(&proof_call) || any_name(&credit_call)
}

/// Is there a **recency floor** on the timestamp rooted at `ts_root` — a comparison
/// binding it against a `block.timestamp - MAX_AGE` expression? Recognized as a
/// comparison (`>=`/`<=`/`>`/`<`) one of whose operands mentions `ts_root` and the
/// *other side* (or the same side) involves a `block.timestamp - X` subtraction.
/// This is the canonical freshness bound:
///   * `ts >= block.timestamp - MAX_AGE`        (subtraction on the opposite operand)
///   * `block.timestamp - ts <= MAX_AGE`        (ts inside the subtraction itself)
///
/// A bare lower bound against a *stored* snapshot timestamp (`ts < lastSnapshotTs`,
/// no `block.timestamp -` subtraction) is deliberately NOT matched — it is exactly
/// the insufficient guard the bug relies on.
fn has_recency_floor(cx: &AnalysisContext, f: &Function, ts_root: &str) -> bool {
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
            // The comparison must reference the caller timestamp root somewhere.
            if !(expr_mentions_ident(lhs, ts_root) || expr_mentions_ident(rhs, ts_root)) {
                return;
            }
            // And somewhere in the comparison there must be a `block.timestamp - X`
            // (or `block.number - X`) subtraction — the recency-window arithmetic.
            // We additionally accept the symmetric `ts + MAX_AGE >= block.timestamp`
            // form (an *addition* to ts compared against block.timestamp).
            let has_blocktime_sub = expr_has_blocktime_subtraction(lhs)
                || expr_has_blocktime_subtraction(rhs);
            let has_ts_plus_vs_blocktime = (expr_has_addition_of(lhs, ts_root)
                && expr_reads_block_time(rhs))
                || (expr_has_addition_of(rhs, ts_root) && expr_reads_block_time(lhs));
            // Also cover the raw textual form (assembly / unusual lowering) as a
            // belt-and-braces fallback: the function source binds `ts` against a
            // `block.timestamp -` window. Keyed on `cx.source_text` (comment-stripped).
            if has_blocktime_sub || has_ts_plus_vs_blocktime {
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
    // Textual fallback: a `block.timestamp - <ts>` or `<ts> + ... >= block.timestamp`
    // somewhere in the function (covers idioms the structural pass may not shape).
    let src = cx.source_text(f.span);
    let compact: String = src.chars().filter(|c| !c.is_whitespace()).collect();
    let tl = ts_root.to_ascii_lowercase();
    compact.contains(&format!("block.timestamp-{tl}"))
        || compact.contains(&format!("{tl}+")) && compact.contains(">=block.timestamp")
        || compact.contains(&format!("{tl}<=block.timestamp"))
}

/// Does the root-lookup HELPER named `helper_name` itself enforce a recency floor
/// on its timestamp parameter? EigenLayer's `getParentBlockRoot(uint64 timestamp)`
/// guards `require(block.timestamp - timestamp < BUFFER_LEN * 12)` — a freshness
/// bound living in the *callee*, not the consumer. We resolve every function of that
/// name and check each timestamp-named parameter against the same recency-floor
/// shape used for the consumer. Karak's `_getParentBlockRoot` has no such bound, so
/// it is NOT suppressed.
fn helper_has_recency_floor(cx: &AnalysisContext, helper_name: &str) -> bool {
    for f in cx.functions() {
        if f.name != helper_name || !f.has_body {
            continue;
        }
        for p in &f.params {
            if let Some(pname) = p.name.as_deref() {
                if is_timestamp_name(pname) && has_recency_floor(cx, f, pname) {
                    return true;
                }
            }
        }
    }
    false
}

/// `block.timestamp - X` / `block.number - X` subtraction anywhere in `e`.
fn expr_has_blocktime_subtraction(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Binary { op: BinOp::Sub, lhs, rhs } = &sub.kind {
            if expr_reads_block_time(lhs) || expr_reads_block_time(rhs) {
                found = true;
            }
        }
    });
    found
}

/// `<name> + X` addition anywhere in `e` (the `ts + MAX_AGE` recency form).
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

/// Does `e` (anywhere) read `block.timestamp` / `block.number`?
fn expr_reads_block_time(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Member { base, member } = &sub.kind {
            let m = member.to_ascii_lowercase();
            if (m == "timestamp" || m == "number")
                && matches!(&base.kind, ExprKind::Ident(b) if b == "block")
            {
                found = true;
            }
        }
    });
    found
}

// ----------------------------------------------------------------- name/shape utils

/// Resolved callee name of a call (`func_name`, falling back to the callee's simple
/// name `a.b -> "b"`).
fn resolved_call_name(c: &Call) -> Option<String> {
    c.func_name
        .clone()
        .or_else(|| c.callee.simple_name().map(|s| s.to_string()))
}

/// Does the call's receiver name read as a beacon-roots system address? Matches a
/// receiver whose root identifier / member contains `beacon_roots` / `beaconroots`
/// (the EIP-4788 `BEACON_ROOTS_ADDRESS` constant, possibly via `Constants.`).
fn receiver_is_beacon_roots(c: &Call) -> bool {
    let Some(recv) = &c.receiver else { return false };
    let mut hit = false;
    recv.visit(&mut |sub| {
        if hit {
            return;
        }
        match &sub.kind {
            ExprKind::Ident(n) | ExprKind::Member { member: n, .. } if name_is_beacon_roots(n) => {
                hit = true;
            }
            _ => {}
        }
    });
    hit
}

/// A name reads as the EIP-4788 beacon-roots address.
fn name_is_beacon_roots(name: &str) -> bool {
    let l = name.to_ascii_lowercase().replace('_', "");
    l.contains("beaconroots") || l.contains("beaconblockroots")
}

/// A function name reads as a parent/beacon block-root resolver.
fn is_block_root_lookup_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase().replace('_', "");
    (l.contains("parentblockroot") || l.contains("parentbeaconblockroot")
        || l.contains("beaconblockroot") || l.contains("blockroot") || l.contains("beaconroot"))
        && (l.contains("get") || l.contains("fetch") || l.contains("read") || l.contains("root"))
}

/// A name reads as a timestamp (the lookup key / proof field).
fn is_timestamp_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "timestamp" || l == "ts" || l.ends_with("timestamp") || l.contains("timestamp")
}

/// A parameter that reads as a timestamp — by name OR by a `uint*`/`uint64` type
/// with a timestamp-ish name. Used to confirm a helper resolves a root *from a time*.
fn param_is_timestamp(p: &sluice_ir::Param) -> bool {
    p.name.as_deref().map(is_timestamp_name).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "external-root-caller-timestamp")
    }

    // VULN — the Karak NativeVault shape.
    const KARAK: &str = r#"
        pragma solidity 0.8.21;
        library Constants { address constant BEACON_ROOTS_ADDRESS = address(0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02); }
        library BeaconProofs {
            struct BeaconStateRootProof { uint64 timestamp; bytes32 beaconStateRoot; bytes proof; }
            struct ValidatorFieldsProof { bytes32[] validatorFields; bytes proof; }
            function validateBeaconStateRootProof(bytes32 r, BeaconStateRootProof calldata p) internal view {}
        }
        contract NativeVault {
            uint64 lastSnapshotTimestamp;
            uint64 currentSnapshotTimestamp;
            function _getParentBlockRoot(uint64 timestamp) internal view returns (bytes32) {
                (bool success, bytes memory result) = Constants.BEACON_ROOTS_ADDRESS.staticcall(abi.encode(timestamp));
                if (success && result.length > 0) { return abi.decode(result, (bytes32)); } else { revert(); }
            }
            function validateWithdrawalCredentials(
                address nodeOwner,
                BeaconProofs.BeaconStateRootProof calldata beaconStateRootProof,
                BeaconProofs.ValidatorFieldsProof[] calldata validatorFieldsProofs
            ) external {
                if (beaconStateRootProof.timestamp == block.timestamp) { revert(); }
                if (beaconStateRootProof.timestamp < lastSnapshotTimestamp
                    || beaconStateRootProof.timestamp < currentSnapshotTimestamp) revert();
                uint256 totalRestakedWei;
                BeaconProofs.validateBeaconStateRootProof(_getParentBlockRoot(beaconStateRootProof.timestamp), beaconStateRootProof);
                _increaseBalance(nodeOwner, totalRestakedWei);
            }
            function _increaseBalance(address a, uint256 b) internal {}
        }
    "#;

    #[test]
    fn fires_on_karak_shape() {
        assert!(fires(KARAK), "{:#?}", run(KARAK));
    }

    // SAFE — same lookup, but a recency floor on the caller timestamp:
    // `require(timestamp + MAX_AGE >= block.timestamp)` bounds staleness vs now.
    const SAFE_RECENCY_FLOOR: &str = r#"
        pragma solidity 0.8.21;
        library Constants { address constant BEACON_ROOTS_ADDRESS = address(0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02); }
        library BeaconProofs {
            struct BeaconStateRootProof { uint64 timestamp; bytes32 beaconStateRoot; bytes proof; }
            function validateBeaconStateRootProof(bytes32 r, BeaconStateRootProof calldata p) internal view {}
        }
        contract NativeVault {
            uint256 public constant MAX_AGE = 1 days;
            function _getParentBlockRoot(uint64 timestamp) internal view returns (bytes32) {
                (bool ok, bytes memory result) = Constants.BEACON_ROOTS_ADDRESS.staticcall(abi.encode(timestamp));
                if (ok && result.length > 0) { return abi.decode(result, (bytes32)); } else { revert(); }
            }
            function validateWithdrawalCredentials(
                address nodeOwner,
                BeaconProofs.BeaconStateRootProof calldata beaconStateRootProof
            ) external {
                require(beaconStateRootProof.timestamp + MAX_AGE >= block.timestamp, "stale");
                BeaconProofs.validateBeaconStateRootProof(_getParentBlockRoot(beaconStateRootProof.timestamp), beaconStateRootProof);
                _increaseBalance(nodeOwner, 1);
            }
            function _increaseBalance(address a, uint256 b) internal {}
        }
    "#;

    #[test]
    fn silent_with_recency_floor() {
        assert!(!fires(SAFE_RECENCY_FLOOR), "{:#?}", run(SAFE_RECENCY_FLOOR));
    }

    // SAFE — the root is taken from the *current* block time, not a caller param:
    // `_getParentBlockRoot(uint64(block.timestamp))`. No caller-controlled timestamp.
    const SAFE_BLOCKTIME: &str = r#"
        pragma solidity 0.8.21;
        library Constants { address constant BEACON_ROOTS_ADDRESS = address(0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02); }
        contract NativeVault {
            uint64 currentSnapshotTimestamp;
            function _getParentBlockRoot(uint64 timestamp) internal view returns (bytes32) {
                (bool ok, bytes memory r) = Constants.BEACON_ROOTS_ADDRESS.staticcall(abi.encode(timestamp));
                if (ok && r.length > 0) { return abi.decode(r, (bytes32)); } else { revert(); }
            }
            function startSnapshot() external {
                bytes32 root = _getParentBlockRoot(uint64(block.timestamp));
                currentSnapshotTimestamp = uint64(block.timestamp);
                _increaseBalance(msg.sender, 1);
            }
            function _increaseBalance(address a, uint256 b) internal {}
        }
    "#;

    #[test]
    fn silent_on_blocktime_root() {
        assert!(!fires(SAFE_BLOCKTIME), "{:#?}", run(SAFE_BLOCKTIME));
    }

    // SAFE — the REAL EigenLayer `EigenPod` shape: the consumer
    // (`verifyWithdrawalCredentials`) has only lower-bound checks against *stored*
    // checkpoint timestamps (`require(beaconTimestamp > currentCheckpointTimestamp)`),
    // BUT the root-lookup HELPER `getParentBlockRoot` enforces the recency floor
    // `require(block.timestamp - timestamp < BUFFER * 12)`. The floor in the callee
    // must suppress — this is the precise TP/FP boundary vs Karak (whose
    // `_getParentBlockRoot` has no such bound).
    const SAFE_EIGENLAYER_HELPER_FLOOR: &str = r#"
        pragma solidity 0.8.21;
        library BeaconChainProofs {
            struct StateRootProof { bytes32 beaconStateRoot; bytes proof; }
            function verifyStateRoot(bytes32 beaconBlockRoot, StateRootProof calldata p) internal view {}
        }
        contract EigenPod {
            uint256 internal constant BEACON_ROOTS_HISTORY_BUFFER_LENGTH = 8191;
            address internal constant BEACON_ROOTS_ADDRESS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;
            uint64 currentCheckpointTimestamp;
            uint64 lastCheckpointTimestamp;
            function getParentBlockRoot(uint64 timestamp) public view returns (bytes32) {
                require(block.timestamp - timestamp < BEACON_ROOTS_HISTORY_BUFFER_LENGTH * 12, "out of range");
                (bool success, bytes memory result) = BEACON_ROOTS_ADDRESS.staticcall(abi.encode(timestamp));
                require(success && result.length > 0, "bad 4788");
                return abi.decode(result, (bytes32));
            }
            function verifyWithdrawalCredentials(
                uint64 beaconTimestamp,
                BeaconChainProofs.StateRootProof calldata stateRootProof
            ) external {
                require(beaconTimestamp > currentCheckpointTimestamp, "too far past");
                require(beaconTimestamp > lastCheckpointTimestamp, "before latest");
                BeaconChainProofs.verifyStateRoot(getParentBlockRoot(beaconTimestamp), stateRootProof);
                _increaseBalance(msg.sender, 1);
            }
            function _increaseBalance(address a, uint256 b) internal {}
        }
    "#;

    #[test]
    fn silent_when_helper_enforces_recency_floor() {
        assert!(!fires(SAFE_EIGENLAYER_HELPER_FLOOR), "{:#?}", run(SAFE_EIGENLAYER_HELPER_FLOOR));
    }

    // VULN (direct-staticcall form, no helper): the consumer inlines the EIP-4788
    // `BEACON_ROOTS_ADDRESS.staticcall(abi.encode(proofTs))` itself, with no recency
    // floor, then validates a proof + credits stake. Must still fire.
    const VULN_INLINE_STATICCALL: &str = r#"
        pragma solidity 0.8.21;
        contract NativeVault {
            address internal constant BEACON_ROOTS_ADDRESS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;
            uint64 lastSnapshotTimestamp;
            function validateWithdrawalCredentials(uint64 proofTimestamp, bytes calldata proof) external {
                if (proofTimestamp < lastSnapshotTimestamp) revert();
                (bool ok, bytes memory result) = BEACON_ROOTS_ADDRESS.staticcall(abi.encode(proofTimestamp));
                require(ok && result.length > 0, "bad");
                bytes32 root = abi.decode(result, (bytes32));
                verifyValidatorProof(root, proof);
                _increaseBalance(msg.sender, 1);
            }
            function verifyValidatorProof(bytes32 root, bytes calldata proof) internal {}
            function _increaseBalance(address a, uint256 b) internal {}
        }
    "#;

    #[test]
    fn fires_on_inline_staticcall() {
        assert!(fires(VULN_INLINE_STATICCALL), "{:#?}", run(VULN_INLINE_STATICCALL));
    }

    // SAFE — direct-staticcall consumer that DOES enforce the recency floor inline:
    // `require(block.timestamp - proofTimestamp < MAX_AGE)`. Suppress.
    const SAFE_INLINE_FLOOR: &str = r#"
        pragma solidity 0.8.21;
        contract NativeVault {
            address internal constant BEACON_ROOTS_ADDRESS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;
            uint256 constant MAX_AGE = 98292;
            function validateWithdrawalCredentials(uint64 proofTimestamp, bytes calldata proof) external {
                require(block.timestamp - proofTimestamp < MAX_AGE, "stale");
                (bool ok, bytes memory result) = BEACON_ROOTS_ADDRESS.staticcall(abi.encode(proofTimestamp));
                require(ok && result.length > 0, "bad");
                bytes32 root = abi.decode(result, (bytes32));
                verifyValidatorProof(root, proof);
                _increaseBalance(msg.sender, 1);
            }
            function verifyValidatorProof(bytes32 root, bytes calldata proof) internal {}
            function _increaseBalance(address a, uint256 b) internal {}
        }
    "#;

    #[test]
    fn silent_on_inline_recency_floor() {
        assert!(!fires(SAFE_INLINE_FLOOR), "{:#?}", run(SAFE_INLINE_FLOOR));
    }
}
