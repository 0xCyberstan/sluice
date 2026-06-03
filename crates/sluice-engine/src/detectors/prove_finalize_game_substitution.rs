//! Prove→finalize game/proof-pointer substitution — an optimistic-bridge
//! withdrawal-theft class where the *validity oracle* a withdrawal is checked
//! against is whatever the prover stored, under a key the finalizer lets the
//! caller choose, with no binding back to a canonical/immutable contract.
//!
//! ## The shape
//!
//! A two-step **prove → finalize** withdrawal flow:
//!
//!   * **fn-A (prove)** writes a record into a *nested* mapping
//!     `mapping(bytes32 => mapping(address => Struct))`, where `Struct` carries a
//!     **contract/address field** (the validity oracle the withdrawal will be
//!     judged against) plus a **timestamp** (when it was proven):
//!
//!     ```solidity
//!     provenWithdrawals[withdrawalHash][msg.sender] =
//!         ProvenWithdrawal({ disputeGameProxy: disputeGameProxy, timestamp: uint64(block.timestamp) });
//!     ```
//!
//!   * **fn-B (finalize / check)** reads that *same* nested mapping by a
//!     **caller-supplied address key** (a function parameter, not `msg.sender`),
//!     gates on an **elapsed-time delay** (`block.timestamp - storedTs > DELAY`),
//!     and then makes an **external validity call on the stored contract field** to
//!     decide whether the withdrawal may proceed — *without ever checking that the
//!     stored contract equals a canonical / immutable one*:
//!
//!     ```solidity
//!     function checkWithdrawal(bytes32 _withdrawalHash, address _proofSubmitter) public view {
//!         ProvenWithdrawal memory provenWithdrawal = provenWithdrawals[_withdrawalHash][_proofSubmitter];
//!         IDisputeGame disputeGameProxy = provenWithdrawal.disputeGameProxy;     // stored pointer
//!         ...
//!         if (block.timestamp - provenWithdrawal.timestamp <= PROOF_MATURITY_DELAY_SECONDS) revert ...; // delay
//!         if (!anchorStateRegistry.isGameClaimValid(disputeGameProxy)) revert ...; // validity call on STORED ptr
//!     }
//!     ```
//!
//! Because the finalizer keys the lookup by a caller-chosen address and trusts the
//! *stored* contract as the validity oracle, the safety of a finalize reduces to
//! "was the pointer that some proof-submitter stored honest?". If a prover can get
//! the contract to store a record whose contract field is a proxy they control (or
//! a game that later resolves favorably), and the finalizer re-reads it by that
//! submitter's address, the external "is this valid?" call is answered by the
//! attacker's own oracle — the withdrawal finalizes against a substituted game.
//! This is the Optimism `OptimismPortal2` prove/finalize shape (the validity check
//! lives in `checkWithdrawal`, fed by `proveWithdrawalTransaction`'s write).
//!
//! ## Precision anchors (all required)
//!
//!   * the **state var** read is a *nested* mapping `mapping(_ => mapping(address
//!     => Struct))` whose value is a user **struct** (the proven-record store);
//!   * **fn-B** reads it with the **inner (address) key root-resolving to a
//!     parameter** of fn-B — the caller chooses whose record is finalized;
//!   * **fn-B** uses a **field of that struct record as the receiver of an external
//!     call** (the validity oracle the stored pointer designates);
//!   * **fn-B** gates on an **elapsed delay** — a `block.timestamp - <structField>`
//!     subtraction inside a comparison (the proof-maturity window);
//!   * a **sibling fn-A** in the same contract **writes** that nested mapping (the
//!     prove step that populated the record);
//!   * the contract reads as a **portal / withdrawal / finalize / prove** component
//!     (by name, a sibling function, or a proven-record state var).
//!
//! ## Suppression
//!
//!   * fn-B **equality-checks the stored pointer against an immutable/constant**
//!     state var (`require(storedGame == CANONICAL_GAME)` / `!= ` guard), or
//!   * fn-B **re-derives the pointer from a registry/factory** by index inside the
//!     same function (a `gameAtIndex` / `*AtIndex` / `gameByIndex` re-fetch),
//!   so the stored contract is no longer free — it is rebound to a canonical source.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, CallKind, Contract, Expr, ExprKind, Function, Span, StmtKind};

use super::prelude::*;

pub struct ProveFinalizeGameSubstitutionDetector;

impl Detector for ProveFinalizeGameSubstitutionDetector {
    fn id(&self) -> &'static str {
        "prove-finalize-game-substitution"
    }
    fn category(&self) -> Category {
        Category::ProveFinalizeGameSubstitution
    }
    fn description(&self) -> &'static str {
        "Prove→finalize where the finalizer reads a proven-record struct by a caller-supplied address key, \
         gates on an elapsed delay, and makes the validity call on the STORED contract pointer with no binding \
         to a canonical/immutable one (optimistic-bridge withdrawal theft; OptimismPortal2 class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // fn-B (the finalizer/checker) has a body. It may be `view`
            // (OptimismPortal2's `checkWithdrawal` is `view`), so we do NOT gate on
            // state-mutation; we iterate every concrete function with a body.
            if !f.has_body {
                continue;
            }
            let Some(contract) = cx.contract_of(f.id) else { continue };
            if contract.is_interface() {
                continue;
            }
            // The component must read as a portal / withdrawal / finalize / prove
            // surface (precision gate — keeps this off ordinary nested-map code).
            if !contract_is_portal_like(cx, contract) {
                continue;
            }

            if let Some(hit) = analyze(cx, f, contract) {
                out.push(self.finding(cx, f, &hit));
            }
        }
        out
    }
}

impl ProveFinalizeGameSubstitutionDetector {
    fn finding(&self, cx: &AnalysisContext, f: &Function, hit: &Hit) -> Finding {
        let b = report!(self, Category::ProveFinalizeGameSubstitution,
            title = "Finalizer trusts a caller-keyed stored contract pointer as the validity oracle (prove→finalize substitution)",
            severity = Severity::High,
            confidence = 0.8,
            dimensions = [Dimension::Invariant, Dimension::Frontier],
            message = format!(
                "`{fname}` reads the proven-record struct from the nested mapping `{store}` using a \
                 caller-supplied address key `{key}` (a function parameter, not `msg.sender`), gates only on \
                 an elapsed-time delay (`block.timestamp - {ts_field}` compared against a maturity window), \
                 and then makes the validity call `{validity}` on the contract pointer stored in that record \
                 (`{ptr_field}`) — with no check that the stored contract equals a canonical / immutable one. \
                 The safety of a finalize therefore reduces to whether the pointer some proof-submitter stored \
                 is honest: the prove step (`{store}[...][...] = Struct(...)`, written elsewhere in this \
                 contract) lets a submitter associate the withdrawal with a contract of their choosing, and \
                 because the finalizer re-reads the record by that submitter's address and answers \"is this \
                 valid?\" by calling the *stored* contract, an attacker-controlled (or self-resolving) game \
                 proxy is consulted as the oracle — the withdrawal finalizes against a substituted game. This \
                 is the optimistic-bridge prove→finalize game-substitution / withdrawal-theft class \
                 (Optimism `OptimismPortal2.checkWithdrawal` fed by `proveWithdrawalTransaction`).",
                fname = f.name,
                store = hit.store_var,
                key = hit.caller_key,
                ts_field = hit.ts_field,
                ptr_field = hit.ptr_field,
                validity = hit.validity_desc,
            ),
            recommendation =
                "Do not treat the stored contract as the validity oracle on the strength of a caller-keyed \
                 lookup. Bind the proven record to a canonical source: re-derive the dispute game / proof \
                 target from an immutable registry by its index at finalize time and `require` the stored \
                 pointer equals it, or validate the stored game against a registry-curated \
                 `isGameProper`/blacklist/respected-type set *and* a creation-time/root-claim check before \
                 acting. Equivalently, finalize against a canonical record keyed by the withdrawal hash alone \
                 rather than re-reading a per-submitter record whose pointer the submitter chose.",
        );
        finish_at(cx, b, f.id, hit.span)
    }
}

// --------------------------------------------------------------------- analysis

/// A matched prove→finalize substitution in one finalizer function.
struct Hit {
    /// The proven-record nested-mapping state var (`provenWithdrawals`).
    store_var: String,
    /// The caller-supplied inner-key parameter name (`_proofSubmitter`).
    caller_key: String,
    /// The struct field used as the validity-call receiver (`disputeGameProxy`).
    ptr_field: String,
    /// The struct field subtracted from `block.timestamp` in the delay gate (`timestamp`).
    ts_field: String,
    /// Human description of the validity call (`anchorStateRegistry.isGameClaimValid(...)`).
    validity_desc: String,
    /// Report location (the validity call).
    span: Span,
}

fn analyze(cx: &AnalysisContext, f: &Function, contract: &Contract) -> Option<Hit> {
    // (1) Find a read of a *nested* mapping(_ => mapping(address => Struct)) whose
    //     inner key root-resolves to a parameter of `f`, bound to a struct local.
    let read = find_nested_record_read(f, contract)?;

    // (2) A field of that record local must be used as the receiver of an external
    //     call (the validity oracle the stored pointer designates).
    let validity = find_validity_call_on_field(f, &read.record_local)?;

    // (3) SUPPRESS: the stored pointer is rebound to a canonical source — either an
    //     equality/inequality check of a record field against an immutable/constant
    //     state var, or a re-derivation from a registry/factory by index in `f`.
    if rebinds_pointer_to_canonical(cx, f, &read.record_local) {
        return None;
    }

    // (4) fn-B must gate on an elapsed delay: `block.timestamp - <record.field>`
    //     inside a comparison (the proof-maturity window).
    let ts_field = find_elapsed_delay_field(f, &read.record_local)?;

    // (5) A sibling fn-A in the same contract must WRITE that nested mapping (the
    //     prove step). A finalizer alone (no prover populating the store) is out of
    //     class.
    if !sibling_writes_store(cx, contract, f.id, &read.store_var) {
        return None;
    }

    Some(Hit {
        store_var: read.store_var,
        caller_key: read.caller_key,
        ptr_field: validity.ptr_field,
        ts_field,
        validity_desc: validity.desc,
        span: validity.span,
    })
}

// ----------------------------------------- (1) nested-record read, caller-keyed

/// The proven-record read located in fn-B.
struct RecordRead {
    /// Nested-mapping state var name.
    store_var: String,
    /// Caller-supplied inner-key parameter name.
    caller_key: String,
    /// Local the struct record is bound to.
    record_local: String,
}

/// Find a `Struct memory rec = store[k1][k2];` where `store` is a contract state var
/// of type `mapping(_ => mapping(address => Struct))`, `Struct` is a user struct, and
/// `k2` (the inner key) root-resolves to a **parameter** of `f`.
fn find_nested_record_read(f: &Function, contract: &Contract) -> Option<RecordRead> {
    let mut found: Option<RecordRead> = None;
    for top in &f.body {
        top.visit(&mut |st| {
            if found.is_some() {
                return;
            }
            let StmtKind::VarDecl { name: Some(local), init: Some(init), .. } = &st.kind else {
                return;
            };
            // The initializer must be a doubly-indexed `store[k1][k2]`.
            let ExprKind::Index { base: outer_base, index: Some(inner_key) } = &init.kind else {
                return;
            };
            // Inner index level: outer_base must itself be `store[k1]`.
            let ExprKind::Index { base: store_expr, .. } = &outer_base.kind else {
                return;
            };
            let Some(store_var) = root_ident_str(store_expr) else { return };
            // The store must be a contract state var that is a NESTED mapping to a
            // user struct value.
            if !is_nested_struct_mapping(contract, store_var) {
                return;
            }
            // The inner (caller-chosen) key must root-resolve to a parameter of `f`.
            let Some(key_root) = root_ident_peeled(inner_key) else { return };
            if !is_param(f, &key_root) {
                return;
            }
            found = Some(RecordRead {
                store_var: store_var.to_string(),
                caller_key: key_root,
                record_local: local.clone(),
            });
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// Is `name` a contract state variable declared as a *nested* mapping
/// `mapping(_ => mapping(_ => Struct))` whose value type is a user struct? The
/// doubly-`mapping(` text plus a capitalized, non-primitive value type is the
/// proven-record-store signature.
fn is_nested_struct_mapping(contract: &Contract, name: &str) -> bool {
    contract.state_vars.iter().any(|v| {
        if v.name != name {
            return false;
        }
        let ty = v.ty.trim();
        // Two nested `mapping(` levels.
        if ty.matches("mapping").count() < 2 {
            return false;
        }
        // The final value type (after the last `=>`) must be a user struct.
        value_type_is_struct(ty)
    })
}

/// Best-effort value type of a (nested) mapping declaration: the text after the
/// last `=>`, trimmed of trailing `)` and any storage qualifier. Returns true when
/// that type reads as a user **struct** (capitalized, not a primitive / interface
/// handle / array / mapping).
fn value_type_is_struct(mapping_ty: &str) -> bool {
    let Some(after) = mapping_ty.rsplit("=>").next() else { return false };
    let val = after.trim().trim_end_matches(')').trim();
    type_is_user_struct(val)
}

/// Heuristic: is `ty` a user-defined struct type? (capitalized first segment, not a
/// primitive / `bytes*` / `string` / array / mapping, and not an `I<Upper>`
/// interface handle). Mirrors the struct heuristic used by `hash_gated_replay`.
fn type_is_user_struct(ty: &str) -> bool {
    let t = ty.trim();
    if t.is_empty() || t.contains('[') || t.contains("mapping") {
        return false;
    }
    let last = t.rsplit('.').next().unwrap_or(t).trim();
    let Some(first) = last.chars().next() else { return false };
    if !first.is_ascii_uppercase() {
        return false;
    }
    const NON_STRUCT: &[&str] = &[
        "bytes", "string", "uint", "int", "address", "bool", "bytes32", "bytes4", "claim", "gametype",
    ];
    let ll = last.to_ascii_lowercase();
    if NON_STRUCT.iter().any(|n| ll == *n) {
        return false;
    }
    // Guard out the `I<Upper>` interface-naming convention.
    if last.len() >= 2 {
        let mut ch = last.chars();
        if ch.next() == Some('I') && ch.next().is_some_and(|c| c.is_ascii_uppercase()) {
            return false;
        }
    }
    true
}

// ------------------------------------------- (2) validity call on a record field

/// The validity-oracle call located in fn-B.
struct ValidityCall {
    /// The struct field used as the call receiver (`disputeGameProxy`).
    ptr_field: String,
    /// Human description (`anchorStateRegistry.isGameClaimValid(...)` or
    /// `disputeGameProxy.status(...)`).
    desc: String,
    span: Span,
}

/// Find an external call in `f` whose **receiver root-resolves to a field of the
/// record local** — i.e. the stored contract pointer is consulted as a validity
/// oracle. Two recognized forms:
///   * the receiver is `rec.field` directly (or a cast thereof), or a local that was
///     bound from `rec.field`; OR
///   * the stored field is passed as an **argument** to an external/internal
///     validity-style call (`isGameClaimValid(disputeGameProxy)` where
///     `disputeGameProxy = rec.disputeGameProxy`).
fn find_validity_call_on_field(f: &Function, record_local: &str) -> Option<ValidityCall> {
    // Locals aliased to a field of the record: `IDisputeGame g = rec.disputeGameProxy;`.
    // Map alias-local -> field name.
    let aliases = field_aliases(f, record_local);

    let mut hit: Option<ValidityCall> = None;
    for top in &f.body {
        top.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            // Only calls that consult an external/cross-contract oracle.
            if !matches!(c.kind, CallKind::External | CallKind::StaticCall | CallKind::Internal) {
                return;
            }

            // (a) receiver is a record field (directly or via an alias local).
            if let Some(recv) = &c.receiver {
                if let Some(field) = field_of_record_or_alias(recv, record_local, &aliases) {
                    hit = Some(ValidityCall {
                        ptr_field: field.clone(),
                        desc: describe_call(c, &format!("<{field}>")),
                        span: e.span,
                    });
                    return;
                }
            }

            // (b) the stored pointer is an ARGUMENT to a validity-style call.
            if c.func_name.as_deref().map(is_validity_name).unwrap_or(false) {
                for a in &c.args {
                    if let Some(field) = field_of_record_or_alias(a, record_local, &aliases) {
                        hit = Some(ValidityCall {
                            ptr_field: field.clone(),
                            desc: describe_call(c, &format!("<{field}>")),
                            span: e.span,
                        });
                        return;
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

/// Locals declared as `T x = record.field;` — return a map local -> field.
fn field_aliases(f: &Function, record_local: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for top in &f.body {
        top.visit(&mut |st| {
            if let StmtKind::VarDecl { name: Some(local), init: Some(init), .. } = &st.kind {
                if let Some(field) = direct_record_field(init, record_local) {
                    out.push((local.clone(), field));
                }
            }
        });
    }
    out
}

/// If `e` is exactly `record.field` (possibly cast-wrapped), return `field`.
fn direct_record_field(e: &Expr, record_local: &str) -> Option<String> {
    if let ExprKind::Member { base, member } = &peel_casts(e).kind {
        if root_ident_str(base) == Some(record_local) {
            return Some(member.clone());
        }
    }
    None
}

/// Does `e` (after peeling casts) reference a field of the record — either directly
/// `record.field`, or via an alias local bound to `record.field`? Returns the field.
fn field_of_record_or_alias(e: &Expr, record_local: &str, aliases: &[(String, String)]) -> Option<String> {
    let pe = peel_casts(e);
    // direct record.field
    if let Some(field) = direct_record_field(pe, record_local) {
        return Some(field);
    }
    // an alias local
    if let Some(root) = root_ident_peeled(pe) {
        if let Some((_, field)) = aliases.iter().find(|(local, _)| *local == root) {
            return Some(field.clone());
        }
    }
    None
}

/// A function name reads as a validity / proof-acceptance check.
fn is_validity_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    (l.contains("valid") || l.contains("verify") || l.contains("isgame") || l.contains("proper")
        || l.contains("respected") || l.contains("rootclaim") || l.contains("status")
        || l.contains("resolved") || l.contains("claim"))
        // Avoid matching the store-write helper / struct ctor names.
        && !l.contains("hash")
}

/// Human-readable `recv.method(...)` for the message.
fn describe_call(c: &sluice_ir::Call, recv_disp: &str) -> String {
    let method = c.func_name.clone().unwrap_or_else(|| "call".into());
    // If the receiver is a plain ident (a state var like anchorStateRegistry), show it.
    if let Some(recv) = &c.receiver {
        if let ExprKind::Ident(n) = &peel_casts(recv).kind {
            return format!("{n}.{method}(... {recv_disp} ...)");
        }
    }
    format!("{method}(... {recv_disp} ...)")
}

// --------------------------------------------- (3) canonical-rebind suppression

/// SUPPRESS: the stored pointer is rebound to a canonical source inside `f` —
///   (a) a record field is equality/inequality-compared against an immutable/
///       constant state var (`require(rec.game == CANONICAL)`); OR
///   (b) the pointer is re-derived from a registry/factory by index in this same
///       function (`*AtIndex` / `*ByIndex` / `gameAt*`), so the value the validity
///       call uses is no longer the free stored one.
fn rebinds_pointer_to_canonical(cx: &AnalysisContext, f: &Function, record_local: &str) -> bool {
    let aliases = field_aliases(f, record_local);

    // (a) equality/inequality comparison of a record field (or its alias) vs an
    //     immutable/constant state var.
    let mut equality_bound = false;
    for top in &f.body {
        top.visit_exprs(&mut |e| {
            if equality_bound {
                return;
            }
            let ExprKind::Binary { op, lhs, rhs } = &e.kind else { return };
            if !matches!(op, BinOp::Eq | BinOp::Ne) {
                return;
            }
            let lhs_field = field_of_record_or_alias(lhs, record_local, &aliases);
            let rhs_field = field_of_record_or_alias(rhs, record_local, &aliases);
            // One side is the stored pointer; the other side is an immutable/constant.
            let other = if lhs_field.is_some() { rhs } else if rhs_field.is_some() { lhs } else { return };
            if (lhs_field.is_some() || rhs_field.is_some())
                && root_is_const_or_immutable(cx, f, other)
            {
                equality_bound = true;
            }
        });
        if equality_bound {
            break;
        }
    }
    if equality_bound {
        return true;
    }

    // (b) re-derivation from a registry/factory by index in this function.
    any_call_where(f, |c| {
        c.func_name.as_deref().map(is_index_rederive_name).unwrap_or(false)
    })
}

/// A function name that re-derives a target from a registry/factory by its index
/// (`gameAtIndex`, `gameByIndex`, `*AtIndex`) — the canonical re-fetch.
fn is_index_rederive_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.ends_with("atindex") || l.ends_with("byindex") || l.contains("ataindex")
}

// ----------------------------------------------- (4) elapsed-delay gate

/// Find a comparison whose subtraction is `block.timestamp - <record.field>` (the
/// proof-maturity / elapsed-delay window). Returns the record field subtracted.
fn find_elapsed_delay_field(f: &Function, record_local: &str) -> Option<String> {
    let aliases = field_aliases(f, record_local);
    let mut field: Option<String> = None;
    for top in &f.body {
        top.visit_exprs(&mut |e| {
            if field.is_some() {
                return;
            }
            let ExprKind::Binary { op, lhs, rhs } = &e.kind else { return };
            if !op.is_comparison() {
                return;
            }
            // Some operand must be a `block.timestamp - X` subtraction where X is a
            // field of the record (or an alias of one).
            for side in [lhs.as_ref(), rhs.as_ref()] {
                if let Some(fld) = blocktime_minus_record_field(side, record_local, &aliases) {
                    field = Some(fld);
                    return;
                }
            }
        });
        if field.is_some() {
            break;
        }
    }
    field
}

/// `block.timestamp - <record.field>` anywhere in `e` → the field name. Also accepts
/// the field via an alias local.
fn blocktime_minus_record_field(
    e: &Expr,
    record_local: &str,
    aliases: &[(String, String)],
) -> Option<String> {
    let mut found: Option<String> = None;
    e.visit(&mut |sub| {
        if found.is_some() {
            return;
        }
        if let ExprKind::Binary { op: BinOp::Sub, lhs, rhs } = &sub.kind {
            // lhs reads block.timestamp; rhs is the stored ts field.
            if expr_reads_block_time(lhs) {
                if let Some(fld) = field_of_record_or_alias(rhs, record_local, aliases) {
                    found = Some(fld);
                }
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

// ------------------------------------------------ (5) sibling prove-write

/// Does some *other* function in the same contract WRITE the nested-mapping store
/// `store_var` (the prove step that populates the record)? We accept any storage
/// write whose base var is `store_var` (the effect summary already records the base
/// var for `store[a][b] = ...`).
fn sibling_writes_store(cx: &AnalysisContext, contract: &Contract, finalizer: sluice_ir::FunctionId, store_var: &str) -> bool {
    cx.scir.functions_of(contract.id).any(|g| {
        g.id != finalizer && g.has_body && g.effects.storage_writes.iter().any(|w| w.var == store_var)
    })
}

// --------------------------------------------------------------- portal gate

/// Does the contract read as a portal / withdrawal / finalize / prove component?
/// By contract name, a proven-record-shaped state var, or a sibling function name.
fn contract_is_portal_like(cx: &AnalysisContext, contract: &Contract) -> bool {
    const NAMEY: &[&str] = &[
        "portal", "withdraw", "finaliz", "prove", "proven", "bridge", "messenger", "optimism",
        "rollup", "outbox", "exit", "claim",
    ];
    let name_hit = |s: &str| {
        let l = s.to_ascii_lowercase();
        NAMEY.iter().any(|k| l.contains(k))
    };
    if name_hit(&contract.name) {
        return true;
    }
    // Proven-record-shaped state var name.
    if contract.state_vars.iter().any(|v| {
        let l = v.name.to_ascii_lowercase();
        l.contains("proven") || l.contains("withdraw") || l.contains("finaliz") || l.contains("provensubmit")
    }) {
        return true;
    }
    // A sibling function reveals the prove/finalize role.
    cx.scir.functions_of(contract.id).any(|g| {
        let l = g.name.to_ascii_lowercase();
        l.contains("prove") || l.contains("finaliz") || l.contains("checkwithdrawal") || l.contains("withdraw")
    })
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "prove-finalize-game-substitution")
    }

    // VULN — the OptimismPortal2 prove/finalize shape, reduced. `prove` writes the
    // nested `provenWithdrawals[hash][msg.sender]` record (contract pointer +
    // timestamp); `checkWithdrawal` reads it by a caller-supplied `_proofSubmitter`,
    // gates on `block.timestamp - rec.timestamp <= DELAY`, and answers validity by
    // calling the STORED `disputeGameProxy` — with no canonical binding.
    const VULN: &str = r#"
        pragma solidity 0.8.15;
        interface IDisputeGame { function status() external view returns (uint8); }
        interface IRegistry { function isGameClaimValid(IDisputeGame g) external view returns (bool); }
        contract OptimismPortal2 {
            struct ProvenWithdrawal { IDisputeGame disputeGameProxy; uint64 timestamp; }
            mapping(bytes32 => bool) public finalizedWithdrawals;
            mapping(bytes32 => mapping(address => ProvenWithdrawal)) public provenWithdrawals;
            IRegistry public anchorStateRegistry;
            uint256 internal immutable PROOF_MATURITY_DELAY_SECONDS;
            constructor(uint256 d) { PROOF_MATURITY_DELAY_SECONDS = d; }
            function proveWithdrawalTransaction(bytes32 withdrawalHash, IDisputeGame disputeGameProxy) external {
                provenWithdrawals[withdrawalHash][msg.sender] =
                    ProvenWithdrawal({ disputeGameProxy: disputeGameProxy, timestamp: uint64(block.timestamp) });
            }
            function checkWithdrawal(bytes32 _withdrawalHash, address _proofSubmitter) public view {
                ProvenWithdrawal memory provenWithdrawal = provenWithdrawals[_withdrawalHash][_proofSubmitter];
                IDisputeGame disputeGameProxy = provenWithdrawal.disputeGameProxy;
                if (finalizedWithdrawals[_withdrawalHash]) revert();
                if (provenWithdrawal.timestamp == 0) revert();
                if (block.timestamp - provenWithdrawal.timestamp <= PROOF_MATURITY_DELAY_SECONDS) revert();
                if (!anchorStateRegistry.isGameClaimValid(disputeGameProxy)) revert();
            }
        }
    "#;

    // SAFE (canonical rebind by equality vs immutable): identical shape, but the
    // finalizer requires the stored game equals an immutable canonical game before
    // trusting it — the pointer is no longer free.
    const SAFE_EQ_IMMUTABLE: &str = r#"
        pragma solidity 0.8.15;
        interface IDisputeGame { function status() external view returns (uint8); }
        interface IRegistry { function isGameClaimValid(IDisputeGame g) external view returns (bool); }
        contract OptimismPortal2 {
            struct ProvenWithdrawal { IDisputeGame disputeGameProxy; uint64 timestamp; }
            mapping(bytes32 => bool) public finalizedWithdrawals;
            mapping(bytes32 => mapping(address => ProvenWithdrawal)) public provenWithdrawals;
            IRegistry public anchorStateRegistry;
            IDisputeGame public immutable CANONICAL_GAME;
            uint256 internal immutable PROOF_MATURITY_DELAY_SECONDS;
            constructor(uint256 d, IDisputeGame g) { PROOF_MATURITY_DELAY_SECONDS = d; CANONICAL_GAME = g; }
            function proveWithdrawalTransaction(bytes32 withdrawalHash, IDisputeGame disputeGameProxy) external {
                provenWithdrawals[withdrawalHash][msg.sender] =
                    ProvenWithdrawal({ disputeGameProxy: disputeGameProxy, timestamp: uint64(block.timestamp) });
            }
            function checkWithdrawal(bytes32 _withdrawalHash, address _proofSubmitter) public view {
                ProvenWithdrawal memory provenWithdrawal = provenWithdrawals[_withdrawalHash][_proofSubmitter];
                IDisputeGame disputeGameProxy = provenWithdrawal.disputeGameProxy;
                require(disputeGameProxy == CANONICAL_GAME, "not canonical");
                if (block.timestamp - provenWithdrawal.timestamp <= PROOF_MATURITY_DELAY_SECONDS) revert();
                if (!anchorStateRegistry.isGameClaimValid(disputeGameProxy)) revert();
            }
        }
    "#;

    // SAFE (re-derive from registry by index): the finalizer re-fetches the dispute
    // game from the factory by its index inside the same function, so the validity
    // call no longer trusts a free stored pointer.
    const SAFE_REDERIVE_INDEX: &str = r#"
        pragma solidity 0.8.15;
        interface IDisputeGame { function status() external view returns (uint8); }
        interface IFactory { function gameAtIndex(uint256 i) external view returns (IDisputeGame); }
        interface IRegistry { function isGameClaimValid(IDisputeGame g) external view returns (bool); }
        contract OptimismPortal2 {
            struct ProvenWithdrawal { uint256 gameIndex; uint64 timestamp; }
            mapping(bytes32 => mapping(address => ProvenWithdrawal)) public provenWithdrawals;
            IRegistry public anchorStateRegistry;
            IFactory public factory;
            uint256 internal immutable PROOF_MATURITY_DELAY_SECONDS;
            constructor(uint256 d) { PROOF_MATURITY_DELAY_SECONDS = d; }
            function proveWithdrawalTransaction(bytes32 withdrawalHash, uint256 idx) external {
                provenWithdrawals[withdrawalHash][msg.sender] =
                    ProvenWithdrawal({ gameIndex: idx, timestamp: uint64(block.timestamp) });
            }
            function checkWithdrawal(bytes32 _withdrawalHash, address _proofSubmitter) public view {
                ProvenWithdrawal memory provenWithdrawal = provenWithdrawals[_withdrawalHash][_proofSubmitter];
                IDisputeGame g = factory.gameAtIndex(provenWithdrawal.gameIndex);
                if (block.timestamp - provenWithdrawal.timestamp <= PROOF_MATURITY_DELAY_SECONDS) revert();
                if (!anchorStateRegistry.isGameClaimValid(g)) revert();
            }
        }
    "#;

    // SAFE (single-level mapping, not nested): a per-hash proven record (not keyed
    // by a caller-supplied address) — outside the class (the caller does not choose
    // whose record is finalized).
    const SAFE_SINGLE_MAP: &str = r#"
        pragma solidity 0.8.15;
        interface IDisputeGame { function status() external view returns (uint8); }
        interface IRegistry { function isGameClaimValid(IDisputeGame g) external view returns (bool); }
        contract OptimismPortal {
            struct ProvenWithdrawal { IDisputeGame disputeGameProxy; uint64 timestamp; }
            mapping(bytes32 => ProvenWithdrawal) public provenWithdrawals;
            IRegistry public anchorStateRegistry;
            uint256 internal immutable PROOF_MATURITY_DELAY_SECONDS;
            constructor(uint256 d) { PROOF_MATURITY_DELAY_SECONDS = d; }
            function proveWithdrawalTransaction(bytes32 withdrawalHash, IDisputeGame disputeGameProxy) external {
                provenWithdrawals[withdrawalHash] =
                    ProvenWithdrawal({ disputeGameProxy: disputeGameProxy, timestamp: uint64(block.timestamp) });
            }
            function checkWithdrawal(bytes32 _withdrawalHash) public view {
                ProvenWithdrawal memory provenWithdrawal = provenWithdrawals[_withdrawalHash];
                IDisputeGame disputeGameProxy = provenWithdrawal.disputeGameProxy;
                if (block.timestamp - provenWithdrawal.timestamp <= PROOF_MATURITY_DELAY_SECONDS) revert();
                if (!anchorStateRegistry.isGameClaimValid(disputeGameProxy)) revert();
            }
        }
    "#;

    // SAFE (no elapsed-delay gate): the record is read by a caller key and the
    // stored pointer drives a validity call, but there is no `block.timestamp - ts`
    // maturity window — not the prove/finalize-delay class this targets.
    const SAFE_NO_DELAY: &str = r#"
        pragma solidity 0.8.15;
        interface IDisputeGame { function status() external view returns (uint8); }
        interface IRegistry { function isGameClaimValid(IDisputeGame g) external view returns (bool); }
        contract WithdrawalPortal {
            struct ProvenWithdrawal { IDisputeGame disputeGameProxy; uint64 timestamp; }
            mapping(bytes32 => mapping(address => ProvenWithdrawal)) public provenWithdrawals;
            IRegistry public anchorStateRegistry;
            function proveWithdrawalTransaction(bytes32 withdrawalHash, IDisputeGame disputeGameProxy) external {
                provenWithdrawals[withdrawalHash][msg.sender] =
                    ProvenWithdrawal({ disputeGameProxy: disputeGameProxy, timestamp: uint64(block.timestamp) });
            }
            function checkWithdrawal(bytes32 _withdrawalHash, address _proofSubmitter) public view {
                ProvenWithdrawal memory provenWithdrawal = provenWithdrawals[_withdrawalHash][_proofSubmitter];
                IDisputeGame disputeGameProxy = provenWithdrawal.disputeGameProxy;
                if (!anchorStateRegistry.isGameClaimValid(disputeGameProxy)) revert();
            }
        }
    "#;

    // SAFE (no sibling prove-write): a finalizer with the full read+delay+validity
    // shape, but NO other function in the contract writes the store — so the record
    // is never populated by a prove step (out of class).
    const SAFE_NO_PROVER: &str = r#"
        pragma solidity 0.8.15;
        interface IDisputeGame { function status() external view returns (uint8); }
        interface IRegistry { function isGameClaimValid(IDisputeGame g) external view returns (bool); }
        contract WithdrawalPortal {
            struct ProvenWithdrawal { IDisputeGame disputeGameProxy; uint64 timestamp; }
            mapping(bytes32 => mapping(address => ProvenWithdrawal)) public provenWithdrawals;
            IRegistry public anchorStateRegistry;
            uint256 internal immutable PROOF_MATURITY_DELAY_SECONDS;
            constructor(uint256 d) { PROOF_MATURITY_DELAY_SECONDS = d; }
            function checkWithdrawal(bytes32 _withdrawalHash, address _proofSubmitter) public view {
                ProvenWithdrawal memory provenWithdrawal = provenWithdrawals[_withdrawalHash][_proofSubmitter];
                IDisputeGame disputeGameProxy = provenWithdrawal.disputeGameProxy;
                if (block.timestamp - provenWithdrawal.timestamp <= PROOF_MATURITY_DELAY_SECONDS) revert();
                if (!anchorStateRegistry.isGameClaimValid(disputeGameProxy)) revert();
            }
        }
    "#;

    #[test]
    fn fires_on_optimism_portal_shape() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn silent_when_pointer_eq_immutable() {
        assert!(!fires(SAFE_EQ_IMMUTABLE), "{:#?}", run(SAFE_EQ_IMMUTABLE));
    }

    #[test]
    fn silent_when_rederived_by_index() {
        assert!(!fires(SAFE_REDERIVE_INDEX), "{:#?}", run(SAFE_REDERIVE_INDEX));
    }

    #[test]
    fn silent_on_single_level_mapping() {
        assert!(!fires(SAFE_SINGLE_MAP), "{:#?}", run(SAFE_SINGLE_MAP));
    }

    #[test]
    fn silent_without_elapsed_delay() {
        assert!(!fires(SAFE_NO_DELAY), "{:#?}", run(SAFE_NO_DELAY));
    }

    #[test]
    fn silent_without_sibling_prover() {
        assert!(!fires(SAFE_NO_PROVER), "{:#?}", run(SAFE_NO_PROVER));
    }
}
