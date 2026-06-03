//! Shares-escrowed-then-repriced withdrawal — a two-step request/claim flow that
//! escrows **share units** at request and **re-prices them from the live rate** at
//! claim, so any slash / negative rebase between the two steps is borne by the
//! exiting user (and the queued exit stays slashable until it is finished).
//!
//! ## The class
//!
//! A vault with a queued withdrawal has two entry points:
//!
//!   * a **request** (`startRedeem` / `requestWithdraw`) that takes a `shares`
//!     amount, computes the *current* asset value with an ERC-4626 conversion
//!     (`convertToAssets(shares)` / `previewRedeem(shares)`) — but **discards** that
//!     asset figure (it is only emitted in an event) and persists the **shares**
//!     into the queued-withdrawal record (`record.shares = shares`); and
//!   * a **finish** (`finishRedeem` / `claim`) that, after the cooldown, reads the
//!     stored `record.shares` and **re-computes** `convertToAssets(record.shares)`
//!     against the **live** rate, paying out that freshly-derived amount.
//!
//! Because the asset amount is re-derived at claim from the live share price, the
//! exiting user is *not* insulated from rate movements between request and finish.
//! If the vault is slashed (or suffers a negative rebase) in that window, the
//! per-share rate falls and the user receives strictly less than the value their
//! shares were worth when they queued — the queued position remains fully
//! slashable. (Karak even documents the converse risk: "DSS shouldn't consider
//! stakes queued in withdrawals", yet the *vault* keeps repricing them.)
//!
//! ```solidity
//! // request — asset value computed but DISCARDED, SHARES escrowed:
//! uint256 assets = convertToAssets(shares);                 // <- not stored
//! state.withdrawalMap[key].shares = shares;                 // <- SHARES persisted
//! emit StartedRedeem(staker, op, shares, key, assets);      // assets only logged
//!
//! // finish — re-price the stored shares at the LIVE rate:
//! uint256 shares = startedWithdrawal.shares;
//! uint256 redeemableAssets = convertToAssets(shares);       // <- live reprice
//! _withdraw({ assets: redeemableAssets, shares: shares });  // pays live value
//! ```
//!
//! ## Distinct from `snapshot-redeem-asymmetry`
//!
//! That detector targets a two-step claim that *does* lock an asset amount and then
//! clamps it **down-only** against a live value while a reserve is debited by the
//! pre-clamp figure. Here there is **no clamp and no reserve**: the request never
//! stores an asset amount at all — it stores raw shares — and the finish recomputes
//! unconditionally. The two are mutually exclusive by construction (this fires only
//! when *no* asset field is persisted at request).
//!
//! ## Precision anchors (all required)
//!
//! Fires on a contract only when it has BOTH a request leg (anchors 1–3) and a
//! finish leg (anchors 4–5):
//!
//! 1. the **request** calls a share→asset conversion (`convertToAssets` /
//!    `previewRedeem` / `previewMint`) — the spot pricing of the shares;
//! 2. the **request** **persists a `*.shares`-like record field** (a member-write
//!    whose final field name is share-like), escrowing share units; and
//! 3. the **request** **persists no `*.assets`/`*.amount`/`*.value`-like record
//!    field** — the asset figure is discarded. This is the discriminator against
//!    the safe *lock-the-rate* shape, where the request stores
//!    `record.assets = assets` and the finish pays that stored value (then this
//!    detector stays silent);
//! 4. a **finish** function (a *different* function of the same contract) reads a
//!    `*.shares`-like record field (the stored shares); and
//! 5. that **finish** calls a share→asset conversion again (the live reprice).
//!
//! The finding is reported on the **request** function — the site where the asset
//! value is thrown away and shares are escrowed (the root cause). Real target:
//! Karak `Vault.startRedeem` (asset discarded) + `Vault.finishRedeem`
//! (`convertToAssets` recomputed from the live rate).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{AssignOp, Expr, ExprKind, Function, Span};

use super::prelude::*;

pub struct SharesEscrowedRepricedDetector;

impl Detector for SharesEscrowedRepricedDetector {
    fn id(&self) -> &'static str {
        "shares-escrowed-repriced"
    }
    fn category(&self) -> Category {
        Category::SharesEscrowedRepriced
    }
    fn description(&self) -> &'static str {
        "Two-step withdrawal escrows share units at request and re-prices them from the live rate at \
         finish, so a slash/negative-rebase between the steps hits the exiting user (Karak Vault \
         startRedeem/finishRedeem class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        // Analyse contract-by-contract: the request and the finish must belong to
        // the same contract (share the same queued-withdrawal storage) for the
        // two-step repricing to be one mechanism.
        for c in cx.scir.iter_contracts() {
            // A pure interface declares no request/finish bodies.
            if c.is_interface() {
                continue;
            }
            let funcs: Vec<&Function> = cx.scir.functions_of(c.id).collect();
            if funcs.len() < 2 {
                continue;
            }

            // (A) Is there a FINISH function — reads a stored `*.shares` field AND
            // re-computes a share→asset conversion (the live reprice)? We only need
            // to know one exists in this contract to corroborate a request.
            let has_finish = funcs.iter().any(|f| f.has_body && is_finish_repricer(f));
            if !has_finish {
                continue;
            }

            // (B) Find a REQUEST function: escrows `*.shares`, prices via a
            // share→asset conversion, and persists NO asset amount.
            for f in &funcs {
                if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
                    continue;
                }
                // The request shape requires a `*.shares` field WRITE plus the
                // asset-discard; the finish leg only READS `*.shares` (and stores
                // nothing), so a pure claim function never matches `request_shape`
                // and is not reported here — the two legs are separated by
                // construction (write-at-request vs. read-at-finish).
                let Some(req) = request_shape(f) else { continue };

                let b = report!(self, Category::SharesEscrowedRepriced,
                    title = "Withdrawal escrows shares at request and re-prices them at the live rate on finish",
                    severity = Severity::High,
                    confidence = 0.8,
                    dimensions = [Dimension::Invariant],
                    message = format!(
                        "`{fname}` is the request leg of a two-step withdrawal: it prices the user's \
                         position with a share→asset conversion (`{conv}(...)`) but **discards** that \
                         asset amount (it is never stored) and escrows raw **share units** into the \
                         queued-withdrawal record (`{shares_field}`). The contract's finish leg then \
                         re-derives the payout with `convertToAssets`/`previewRedeem` against the \
                         **live** per-share rate. Because the asset value is recomputed at claim rather \
                         than locked at request, any slash or negative rebase in the request→finish \
                         window is borne by the exiting user — they receive strictly less than their \
                         shares were worth when queued, and the queued exit stays fully slashable until \
                         it is finished. This is the shares-escrowed-then-repriced class (Karak \
                         `Vault.startRedeem` discards the converted assets / `Vault.finishRedeem` \
                         recomputes `convertToAssets`). It differs from the snapshot-redeem-asymmetry \
                         clamp/reserve bug: here no asset amount is ever stored and there is no clamp.",
                        fname = f.name,
                        conv = req.conversion,
                        shares_field = req.shares_field,
                    ),
                    recommendation =
                        "Lock the redemption rate at request time: compute `assets = convertToAssets(shares)` \
                         once and **store the asset amount** in the withdrawal record \
                         (`record.assets = assets`), then have the finish pay out that stored value rather \
                         than recomputing `convertToAssets(record.shares)` from the live rate. If the design \
                         intends queued exits to keep absorbing slashing, make that explicit and bound it \
                         (e.g. socialise the loss symmetrically across queued and active stake), and ensure \
                         the slashing accounting and the DSS view of queued stake agree.",
                );
                out.push(finish_at(cx, b, f.id, req.span));
                // One report per request function is enough.
            }
        }
        out
    }
}

// --------------------------------------------------------------------- analysis

/// What a matched request leg looks like (for the diagnostic).
struct RequestShape {
    /// Name of the share→asset conversion call used to price the position.
    conversion: String,
    /// Best-effort path of the escrowed `*.shares` record field.
    shares_field: String,
    /// Span to report (the conversion site / the function).
    span: Span,
}

/// Share→asset conversion helpers (ERC-4626): each takes a *shares* amount and
/// returns the *assets* it is worth at the current rate. These are exactly the
/// calls a request leg uses to *price* the position and a finish leg uses to
/// *re-price* it. We deliberately exclude the asset→share direction
/// (`convertToShares` / `previewDeposit` / `previewWithdraw`), which is the
/// deposit/mint side and not this bug.
fn is_shares_to_assets_conv(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    matches!(l.as_str(), "converttoassets" | "previewredeem" | "previewmint")
}

/// Does `f` look like the REQUEST leg: prices via a share→asset conversion,
/// escrows a `*.shares`-like record field, and stores NO asset amount?
fn request_shape(f: &Function) -> Option<RequestShape> {
    // (1) a share→asset conversion call somewhere in the body (the spot pricing).
    let conv = first_conversion_call(f)?;

    // (2) a `*.shares`-like record field WRITE (member-assign, final field
    //     share-like) — the share escrow. Capture its path for the message.
    let shares_field = first_shares_field_write(f)?;

    // (3) SUPPRESS the safe lock-the-rate shape: if the request *also* persists an
    //     asset/amount-like record field, the asset value is being stored (and the
    //     finish presumably pays it), so there is no live-reprice exposure.
    if writes_asset_field(f) {
        return None;
    }

    Some(RequestShape { conversion: conv.0, shares_field, span: conv.1 })
}

/// Does `f` look like the FINISH leg: it READS a stored `*.shares`-like record
/// field and RE-computes a share→asset conversion (the live reprice)? This
/// corroborates that the escrowed shares are repriced at claim.
fn is_finish_repricer(f: &Function) -> bool {
    reads_shares_field(f) && first_conversion_call(f).is_some()
}

/// The first share→asset conversion call in `f`'s body, returning `(name, span)`.
fn first_conversion_call(f: &Function) -> Option<(String, Span)> {
    let mut hit: Option<(String, Span)> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if let Some(name) = &c.func_name {
                    if is_shares_to_assets_conv(name) {
                        hit = Some((name.clone(), e.span));
                    }
                }
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Path of the first `record.shares = ...` style member-write in `f` (a plain `=`
/// whose target is a member access ending in a share-like field name). Returns the
/// best-effort textual path for the diagnostic, or `None` if there is no such
/// write. Compound (`+=`) writes are excluded — escrowing is a fresh assignment of
/// the requested share amount, and accepting compound writes would match unrelated
/// per-key share-supply accumulation.
fn first_shares_field_write(f: &Function) -> Option<String> {
    let mut hit: Option<String> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Assign { op: AssignOp::Assign, target, .. } = &e.kind else { return };
            if let ExprKind::Member { member, .. } = &target.kind {
                if is_shares_field(member) {
                    hit = Some(member_path_text(target));
                }
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Does `f` persist an **asset/amount-like** record field — a member-write whose
/// final field name is asset-like (`assets`, `amount`, `value`, `redeemable`)?
/// This is the safe lock-the-rate marker (the request stored the converted asset
/// value), and its presence suppresses the finding.
fn writes_asset_field(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Assign { op, target, .. } = &e.kind {
                if matches!(op, AssignOp::Assign | AssignOp::Add) {
                    if let ExprKind::Member { member, .. } = &target.kind {
                        if is_asset_field(member) {
                            found = true;
                        }
                    }
                }
            }
        });
        if found {
            break;
        }
    }
    found
}

/// Does `f` READ a `*.shares`-like record field — a member access ending in a
/// share-like field name **in a read position** (NOT the lvalue of an assignment)?
/// The finish leg loads `startedWithdrawal.shares` to reprice it (a `VarDecl` init
/// or a call argument).
///
/// `visit_exprs` includes the assignment *target*, so a request leg's
/// `record.shares = shares` write would otherwise be mistaken for a read. We
/// therefore walk read positions explicitly: at an `Assign` only the RHS `value`
/// (and any index sub-expressions of the target — `record[k].shares = …` reads
/// `k`) are read positions, never the target member itself.
fn reads_shares_field(f: &Function) -> bool {
    f.body.iter().any(stmt_reads_shares)
}

/// Apply the write-aware [`expr_reads_shares`] to the **root** expression of every
/// statement in `s`'s subtree. We must NOT use `Stmt::visit_exprs` here: it
/// flattens every *descendant* expression node, so the assignment-target member
/// `record.shares` would be re-presented as a standalone expression and miscounted
/// as a read. `Stmt::visit` is pre-order over statements, so feeding each
/// statement's root expression into [`expr_reads_shares`] (which itself stops at
/// assignment LHS members) covers all nesting while preserving the write exclusion.
fn stmt_reads_shares(s: &sluice_ir::Stmt) -> bool {
    use sluice_ir::StmtKind;
    let mut found = false;
    s.visit(&mut |sub| {
        if found {
            return;
        }
        let hit = match &sub.kind {
            StmtKind::Expr(e) | StmtKind::Emit(e) => expr_reads_shares(e),
            StmtKind::VarDecl { init: Some(e), .. } => expr_reads_shares(e),
            StmtKind::Return(Some(e)) => expr_reads_shares(e),
            StmtKind::If { cond, .. } | StmtKind::While { cond, .. } | StmtKind::DoWhile { cond, .. } => {
                expr_reads_shares(cond)
            }
            StmtKind::For { cond, step, .. } => {
                cond.as_ref().is_some_and(expr_reads_shares)
                    || step.as_ref().is_some_and(expr_reads_shares)
            }
            StmtKind::Revert { args, .. } => args.iter().any(expr_reads_shares),
            StmtKind::Try { expr, .. } => expr_reads_shares(expr),
            _ => false,
        };
        if hit {
            found = true;
        }
    });
    found
}

/// True if `e` contains a share-like member access in a **read** position.
fn expr_reads_shares(e: &Expr) -> bool {
    match &e.kind {
        // The lvalue of an assignment is a write: only the RHS (and the target's
        // index keys) are reads. A compound op (`+=`) also reads the target, but a
        // share-field compound write is not the finish-leg load we want, so we keep
        // to RHS + index keys uniformly.
        ExprKind::Assign { target, value, .. } => {
            expr_reads_shares(value) || target_index_reads_shares(target)
        }
        ExprKind::Member { base, member } => {
            (is_shares_field(member) && !is_self_member(base)) || expr_reads_shares(base)
        }
        ExprKind::Index { base, index } => {
            expr_reads_shares(base) || index.as_deref().is_some_and(expr_reads_shares)
        }
        ExprKind::Call(c) => {
            c.receiver.as_deref().is_some_and(expr_reads_shares)
                || c.args.iter().any(expr_reads_shares)
        }
        ExprKind::Unary { operand, .. } => expr_reads_shares(operand),
        ExprKind::Binary { lhs, rhs, .. } => expr_reads_shares(lhs) || expr_reads_shares(rhs),
        ExprKind::Ternary { cond, then_e, else_e } => {
            expr_reads_shares(cond) || expr_reads_shares(then_e) || expr_reads_shares(else_e)
        }
        ExprKind::Tuple(items) | ExprKind::ArrayLit(items) => {
            items.iter().flatten().any(expr_reads_shares)
        }
        ExprKind::New(inner) => expr_reads_shares(inner),
        _ => false,
    }
}

/// Reads contributed by the index keys of an assignment *target* (`a[k].shares`
/// writes the field but reads `k`). We descend the target chain and treat only
/// index expressions as reads, never the member field being written.
fn target_index_reads_shares(target: &Expr) -> bool {
    match &target.kind {
        ExprKind::Member { base, .. } => target_index_reads_shares(base),
        ExprKind::Index { base, index } => {
            target_index_reads_shares(base) || index.as_deref().is_some_and(expr_reads_shares)
        }
        _ => false,
    }
}

// --------------------------------------------------------------------- helpers

/// A field name that denotes **share units** in a withdrawal record. Kept narrow
/// so it matches `shares` / `shareAmount` / `numShares` but not asset fields.
fn is_shares_field(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("share")
}

/// A field name that denotes a stored **asset amount** (the lock-the-rate marker).
/// `share`-named fields are excluded by checking shares first at the call sites.
fn is_asset_field(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    if l.contains("share") {
        return false;
    }
    ["asset", "amount", "value", "redeemable", "owed", "payout"]
        .iter()
        .any(|m| l.contains(m))
}

/// Is `base` the `msg`/`this`/`block`/`tx` pseudo-object? A `*.shares` member off
/// such a base is not a record field (it never is `msg.shares`, but guard cheaply
/// against environment members so the read heuristic stays tight).
fn is_self_member(base: &Expr) -> bool {
    matches!(&base.kind, ExprKind::Ident(n) if matches!(n.as_str(), "msg" | "block" | "tx"))
}

/// Best-effort textual path of a member-access lvalue (`a.b[c].shares`).
fn member_path_text(e: &Expr) -> String {
    fn go(e: &Expr) -> Option<String> {
        match &e.kind {
            ExprKind::Ident(n) => Some(n.clone()),
            ExprKind::Member { base, member } => Some(format!("{}.{}", go(base)?, member)),
            ExprKind::Index { base, index } => {
                let b = go(base)?;
                let idx = index.as_ref().and_then(|i| go(i)).unwrap_or_default();
                Some(format!("{b}[{idx}]"))
            }
            _ => None,
        }
    }
    go(e).unwrap_or_else(|| "<record>.shares".to_string())
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "shares-escrowed-repriced")
    }

    // VULN — the exact Karak `Vault` shape (de-sugared from the assembly-slot
    // storage so the parser sees ordinary members):
    //   * `startRedeem` computes `assets = convertToAssets(shares)` but DISCARDS it
    //     (only emits it) and persists `record.shares = shares`;
    //   * `finishRedeem` reads `startedWithdrawal.shares` and RE-derives
    //     `convertToAssets(shares)` from the live rate, paying that amount.
    const VULN_KARAK: &str = r#"
        pragma solidity ^0.8.25;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract Vault {
            struct QueuedWithdrawal { address staker; uint96 start; uint256 shares; address beneficiary; }
            mapping(bytes32 => QueuedWithdrawal) withdrawalMap;
            mapping(address => uint256) nonces;
            event StartedRedeem(address staker, uint256 shares, bytes32 key, uint256 assets);
            event FinishedRedeem(address staker, uint256 shares, uint256 assets);
            function convertToAssets(uint256 shares) public view returns (uint256) { return shares; }
            function maxRedeem(address a) public view returns (uint256) { return type(uint256).max; }
            function key(address s, uint256 n) internal pure returns (bytes32) { return keccak256(abi.encode(s, n)); }
            function _withdraw(address to, uint256 assets, uint256 shares) internal {}

            function startRedeem(uint256 shares, address beneficiary) external returns (bytes32 withdrawalKey) {
                address staker = msg.sender;
                uint256 assets = convertToAssets(shares);
                withdrawalKey = key(staker, nonces[staker]++);
                withdrawalMap[withdrawalKey].staker = staker;
                withdrawalMap[withdrawalKey].start = uint96(block.timestamp);
                withdrawalMap[withdrawalKey].shares = shares;
                withdrawalMap[withdrawalKey].beneficiary = beneficiary;
                emit StartedRedeem(staker, shares, withdrawalKey, assets);
            }

            function finishRedeem(bytes32 withdrawalKey) external {
                QueuedWithdrawal memory startedWithdrawal = withdrawalMap[withdrawalKey];
                uint256 shares = startedWithdrawal.shares;
                if (shares > maxRedeem(address(this))) revert();
                uint256 redeemableAssets = convertToAssets(shares);
                delete withdrawalMap[withdrawalKey];
                _withdraw(startedWithdrawal.beneficiary, redeemableAssets, shares);
                emit FinishedRedeem(startedWithdrawal.staker, shares, redeemableAssets);
            }
        }
    "#;

    // VULN (previewRedeem variant): same structure, conversion named previewRedeem.
    const VULN_PREVIEW: &str = r#"
        pragma solidity ^0.8.0;
        contract Queue {
            struct Req { address user; uint256 shares; }
            mapping(uint256 => Req) reqs;
            uint256 nextId;
            function previewRedeem(uint256 s) public view returns (uint256) { return s; }
            function startWithdraw(uint256 shares) external returns (uint256 id) {
                uint256 assets = previewRedeem(shares);
                id = nextId++;
                reqs[id].user = msg.sender;
                reqs[id].shares = shares;
            }
            function finishWithdraw(uint256 id) external {
                Req memory r = reqs[id];
                uint256 redeem = previewRedeem(r.shares);
                payable(r.user).transfer(redeem);
            }
        }
    "#;

    // SAFE — lock-the-rate: the request STORES the converted asset amount
    // (`reqs[id].assets = assets`) and the finish pays the STORED value (no live
    // reprice). The asset-field write suppresses the finding even though a
    // `convertToAssets` call and a `.shares` field exist.
    const SAFE_LOCK_RATE: &str = r#"
        pragma solidity ^0.8.0;
        contract Queue {
            struct Req { address user; uint256 shares; uint256 assets; }
            mapping(uint256 => Req) reqs;
            uint256 nextId;
            function convertToAssets(uint256 s) public view returns (uint256) { return s; }
            function startWithdraw(uint256 shares) external returns (uint256 id) {
                uint256 assets = convertToAssets(shares);
                id = nextId++;
                reqs[id].user = msg.sender;
                reqs[id].shares = shares;
                reqs[id].assets = assets;
            }
            function finishWithdraw(uint256 id) external {
                Req memory r = reqs[id];
                payable(r.user).transfer(r.assets);
            }
        }
    "#;

    // SAFE — no finish repricer: the request escrows shares and prices them, but
    // NO function in the contract reads a stored `.shares` and reconverts. Without
    // the live-reprice claim leg there is no two-step exposure.
    const SAFE_NO_FINISH: &str = r#"
        pragma solidity ^0.8.0;
        contract Queue {
            struct Req { address user; uint256 shares; }
            mapping(uint256 => Req) reqs;
            uint256 nextId;
            function convertToAssets(uint256 s) public view returns (uint256) { return s; }
            function startWithdraw(uint256 shares) external returns (uint256 id) {
                uint256 assets = convertToAssets(shares);
                id = nextId++;
                reqs[id].user = msg.sender;
                reqs[id].shares = shares;
            }
            // settle reads the stored shares but does NOT reconvert — pays 1:1.
            function settle(uint256 id) external {
                Req memory r = reqs[id];
                payable(r.user).transfer(r.shares);
            }
        }
    "#;

    // SAFE — single-step redeem: an ordinary ERC4626 redeem that converts and pays
    // in one call, escrowing nothing. No `.shares` record field is written, so the
    // request shape never matches.
    const SAFE_SINGLE_STEP: &str = r#"
        pragma solidity ^0.8.0;
        contract Vault {
            function convertToAssets(uint256 s) public view returns (uint256) { return s; }
            function redeem(uint256 shares, address to) external returns (uint256 assets) {
                assets = convertToAssets(shares);
                payable(to).transfer(assets);
            }
            function finishRedeem(bytes32 k) external { k = k; }
        }
    "#;

    #[test]
    fn fires_on_karak_shape() {
        assert!(fires(VULN_KARAK), "{:#?}", run(VULN_KARAK));
        // Reported on the request leg (startRedeem), not the finish.
        let fs = run(VULN_KARAK);
        assert!(
            fs.iter()
                .any(|f| f.detector == "shares-escrowed-repriced" && f.function == "startRedeem"),
            "expected report on startRedeem; got {:#?}",
            fs
        );
    }

    #[test]
    fn fires_on_preview_variant() {
        assert!(fires(VULN_PREVIEW), "{:#?}", run(VULN_PREVIEW));
    }

    #[test]
    fn silent_on_lock_the_rate() {
        assert!(!fires(SAFE_LOCK_RATE), "{:#?}", run(SAFE_LOCK_RATE));
    }

    #[test]
    fn silent_without_finish_repricer() {
        assert!(!fires(SAFE_NO_FINISH), "{:#?}", run(SAFE_NO_FINISH));
    }

    #[test]
    fn silent_on_single_step_redeem() {
        assert!(!fires(SAFE_SINGLE_STEP), "{:#?}", run(SAFE_SINGLE_STEP));
    }
}

