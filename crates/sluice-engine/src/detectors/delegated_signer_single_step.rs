//! One-step delegate-signer / authorization grant with no two-step accept.
//!
//! A signer/authorization **delegate** — a delegate-signer mapping entry, an
//! admin/owner transfer, a benefactor→beneficiary signing link — is installed in
//! a **single step** by the grantor, with **no paired accept handshake** from the
//! delegatee. Because the grantee never has to confirm, a typo'd or malicious
//! address gains signing / admin rights the instant the grantor calls the setter:
//! there is no window in which the wrong address can be caught before it becomes
//! active, and (for a hostile grantee) no proof the address is even controllable.
//!
//! The canonical example is the **original Ethena `EthenaMinting`** (C4 audit
//! version): `setDelegatedSigner(address _delegateTo)` wrote
//! `delegatedSigner[_delegateTo][msg.sender] = true;` directly — one call by the
//! benefactor and `_delegateTo` could sign mint/redeem orders on its behalf. The
//! fix Ethena shipped was exactly a two-step flow: `setDelegatedSigner` now writes
//! `DelegatedSignerStatus.PENDING`, and the delegatee must call
//! `confirmDelegatedSigner` (which checks the entry is `PENDING` then promotes it
//! to `ACCEPTED`). That paired pending→confirm flow is the mitigation, and this
//! detector stays silent on it.
//!
//! Shape we fire on (all required):
//!   * an externally-reachable, state-mutating function (the grantor's setter);
//!   * it writes a state var whose name denotes a **signer/authorization grant**
//!     (`delegatedSigner`, `signer`, `approvedSigner`, …) — or a generic
//!     `delegate`-named **nested** mapping whose installed value is a status, not
//!     an address (this excludes ERC20Votes-style `mapping(address=>address)
//!     delegates` and restaking `delegatedTo`, which are vote/stake delegation,
//!     not a forgeable signing grant);
//!   * the installed value is **active/granting** (`true`, `ACCEPTED`/`ACTIVE`/
//!     `APPROVED`/`ENABLED`, a non-zero status) — never a removal (`false`, `0`,
//!     `REJECTED`, `delete`) and never a `PENDING` request;
//!   * a caller-supplied **address parameter** is the delegatee being authorized
//!     (it appears as a mapping index key or as the assigned address), i.e. the
//!     grantor names *who* gets the rights.
//!
//! Suppression (a two-step accept exists, so the wrong address can be caught):
//!   * the setter itself installs a **PENDING** value (it is only the request half
//!     of a request→confirm flow), or
//!   * a sibling function (same contract, or an inherited/inheriting one by name)
//!     looks like the **accept half** — named `accept*`/`confirm*`/`claim*` — and
//!     writes the same target variable family, or guards on a `pending`-named var.
//!
//! Scope discipline (why this is not "every one-step `setOwner`"): a bare scalar
//! `owner`/`admin`/`authority` setter is the missing-zero-check / centralization
//! class and is a heavy false-positive source across real protocols, so it is
//! **not** matched here. This detector is deliberately narrowed to the
//! *signer/authorization-delegate* shape that genuinely warrants a confirm step.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{AssignOp, Expr, ExprKind, Function, Lit, Span};

use super::prelude::*;

pub struct DelegatedSignerSingleStepDetector;

impl Detector for DelegatedSignerSingleStepDetector {
    fn id(&self) -> &'static str {
        "delegated-signer-single-step"
    }
    fn category(&self) -> Category {
        Category::DelegatedSignerSingleStep
    }
    fn description(&self) -> &'static str {
        "Signer/authorization delegate granted in one step with no two-step accept handshake from the delegatee"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.entry_points() {
            // The accept/confirm half of a two-step flow is the delegatee's own
            // confirmation — by construction it installs the active grant, but
            // that IS the mitigation, so it is never the finding.
            if is_accept_named(&f.name) {
                continue;
            }
            // The grantor's setter must not itself be the request half of a
            // request→confirm flow (writing PENDING means the install happens in
            // the accept half elsewhere).
            if writes_pending_value(f) {
                continue;
            }

            // Find a one-step "active grant" write whose delegatee is a caller
            // parameter. The first such write anchors the report.
            let Some(hit) = find_one_step_grant(f) else { continue };

            // Two-step accept handshake present anywhere reachable for this var
            // family → the wrong address can be caught before it is active.
            if has_two_step_accept(cx, f, &hit.var) {
                continue;
            }

            let b = report!(self, Category::DelegatedSignerSingleStep,
                title = "Signer/authorization delegate installed in one step (no accept handshake)",
                severity = Severity::Medium,
                confidence = 0.6,
                dimensions = [Dimension::Invariant],
                message = format!(
                    "`{}` writes the signer/authorization mapping `{}` to a caller-supplied delegate \
                     (`{}`) and marks it active in a single step, with no paired accept/confirm flow \
                     from the delegatee. A mistyped or malicious address therefore gains signing/admin \
                     rights immediately — there is no pending window in which the grantor can catch a \
                     wrong address, and no proof a hostile delegate address is controllable. This is the \
                     one-step delegated-signer class fixed in Ethena `EthenaMinting` by adding \
                     `confirmDelegatedSigner` (a PENDING→ACCEPTED handshake).",
                    f.name, hit.var, hit.delegatee
                ),
                recommendation =
                    "Make delegation two-step: have the grantor record the entry as PENDING, and require \
                     the delegatee itself to call an `accept`/`confirm` function (checking the entry is \
                     PENDING) before it becomes ACCEPTED/active. This mirrors OpenZeppelin \
                     `Ownable2Step` / `AccessControlDefaultAdminRules` and Ethena's \
                     `setDelegatedSigner`→`confirmDelegatedSigner` fix.",
            );
            out.push(finish_at(cx, b, f.id, hit.span));
        }
        out
    }
}

// ----------------------------------------------------------------- detection

/// A one-step active-grant write, with where to report and what it installed.
struct Grant {
    /// The target state-var (mapping) name (`delegatedSigner`, `signer`).
    var: String,
    /// The caller-supplied delegatee param being authorized.
    delegatee: String,
    /// Span of the offending assignment.
    span: Span,
}

/// First assignment in `f` that installs an *active* signer/authorization grant
/// keyed by a caller-supplied delegate parameter.
fn find_one_step_grant(f: &Function) -> Option<Grant> {
    let mut found: Option<Grant> = None;
    for s in &f.body {
        if found.is_some() {
            break;
        }
        s.visit_exprs(&mut |e: &Expr| {
            if found.is_some() {
                return;
            }
            let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind else {
                return;
            };
            // Target root must be a signer/authorization-grant state var actually
            // written by this function (not a local shadow).
            let Some(var) = root_ident_str(target) else { return };
            if !f.effects.writes_var(var) {
                return;
            }

            // The installed value must be an *active grant*. A nested-mapping
            // `delegate`-named var additionally needs a status (bool/enum) value,
            // not an address, so vote/stake delegation does not match.
            if !is_active_grant_value(value) {
                return;
            }
            let value_is_status = value_is_status_literal(value);
            if !target_is_signer_authority(var, target, value_is_status) {
                return;
            }

            // A caller-supplied address parameter must be the delegatee — either a
            // mapping index key, or (for a scalar/single-key grant) the assigned
            // value itself.
            let Some(delegatee) = delegatee_param(f, target, value) else { return };

            found = Some(Grant { var: var.to_string(), delegatee, span: e.span });
        });
    }
    found
}

/// Does the target name (optionally with the nested-mapping + status-value
/// refinement) denote a signer/authorization grant we should police?
///
/// * Names that explicitly mean a signing grant (`signer`, `delegatedsigner`,
///   `approvedsigner`, …) qualify directly.
/// * A generic `delegate`/`authoriz`-named var qualifies **only** when it is a
///   nested (two-key) mapping *and* the installed value is a status literal —
///   this is the `delegatedSigner[delegate][grantor] = true` authorization shape
///   and structurally excludes `mapping(address=>address) delegates`/`delegatedTo`
///   (single-key, address value) used for vote/stake delegation.
fn target_is_signer_authority(var: &str, target: &Expr, value_is_status: bool) -> bool {
    let l = var.to_ascii_lowercase();
    // Explicit signing-grant names.
    let explicit = l.contains("signer")
        || l.contains("signing")
        || l == "delegatedsigner"
        || (l.contains("approved") && l.contains("sign"))
        || (l.contains("authorized") && l.contains("sign"));
    if explicit {
        return true;
    }
    // Generic delegation/authorization: require the nested-mapping + status shape.
    let generic = l.contains("delegate") || l.contains("authoriz");
    generic && value_is_status && is_nested_index(target)
}

/// Is `target` a nested (≥2 level) mapping index `base[i][j]`?
fn is_nested_index(target: &Expr) -> bool {
    if let ExprKind::Index { base, .. } = &target.kind {
        return matches!(&base.kind, ExprKind::Index { .. });
    }
    false
}

/// The installed value is an *active grant* — `true`, a positive numeric status,
/// or an enum member denoting an accepted/active/approved/enabled state. It is
/// **not** a removal (`false`, `0`, `REJECTED`, `delete`) and not a `PENDING`
/// request.
fn is_active_grant_value(value: &Expr) -> bool {
    match &value.kind {
        ExprKind::Lit(Lit::Bool(b)) => *b,
        ExprKind::Lit(Lit::Number(n)) => n.trim() != "0",
        ExprKind::Lit(Lit::HexNumber(n)) => {
            let t = n.trim().trim_start_matches("0x").trim_start_matches("0X");
            !t.chars().all(|c| c == '0')
        }
        // Enum member (`DelegatedSignerStatus.ACCEPTED`) — accept only states that
        // denote an active grant, never `PENDING`/`REJECTED`/disabled.
        ExprKind::Member { member, .. } | ExprKind::Ident(member) => {
            let m = member.to_ascii_lowercase();
            (m.contains("accept")
                || m.contains("active")
                || m.contains("approve")
                || m.contains("enabled")
                || m == "true"
                || m == "yes"
                || m == "granted")
                && !m.contains("pending")
                && !m.contains("reject")
        }
        _ => false,
    }
}

/// Is the assigned value a *status* literal (bool / numeric / accept-state enum)
/// rather than an address-valued expression? Used to gate the generic
/// `delegate`-named shape so address-pointer delegation does not match.
fn value_is_status_literal(value: &Expr) -> bool {
    match &value.kind {
        ExprKind::Lit(Lit::Bool(_)) | ExprKind::Lit(Lit::Number(_)) | ExprKind::Lit(Lit::HexNumber(_)) => true,
        ExprKind::Member { .. } | ExprKind::Ident(_) => {
            // An enum member access reduces to a leaf name; an address-typed local
            // also reduces to a name, but those are filtered out earlier because
            // an address value never satisfies `is_active_grant_value`'s state set.
            is_active_grant_value(value)
        }
        _ => false,
    }
}

/// The caller-supplied address parameter that is being authorized as the
/// delegatee: a parameter used as a mapping index key in `target`, or (for a
/// scalar/single-key grant) the assigned value when it is a bare parameter.
/// Returns the parameter name. A delegatee keyed purely by `msg.sender` (the
/// grantor authorizing itself) does not count — there must be a *named other*.
fn delegatee_param(f: &Function, target: &Expr, value: &Expr) -> Option<String> {
    // Collect index-key identifiers from the target's index chain.
    let mut keys: Vec<String> = Vec::new();
    collect_index_keys(target, &mut keys);
    for k in &keys {
        if is_param(f, k) {
            return Some(k.clone());
        }
    }
    // Scalar / single-key grant: the assigned value is a bare address parameter.
    if let Some(rhs) = value.simple_name() {
        if is_param(f, rhs) {
            return Some(rhs.to_string());
        }
    }
    None
}

/// Push the *bare identifier* index keys of an index chain (`m[a][b].x`) onto
/// `keys` (here `a`, `b`).
fn collect_index_keys(e: &Expr, keys: &mut Vec<String>) {
    if let ExprKind::Index { base, index } = &e.kind {
        if let Some(idx) = index {
            if let ExprKind::Ident(n) = &idx.kind {
                keys.push(n.clone());
            }
        }
        collect_index_keys(base, keys);
    } else if let ExprKind::Member { base, .. } = &e.kind {
        collect_index_keys(base, keys);
    }
}

// ----------------------------------------------------------------- suppression

/// A function name denoting the *accept/confirm half* of a two-step handshake
/// (`acceptAdmin`, `confirmDelegatedSigner`, `claimOwnership`).
fn is_accept_named(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.starts_with("accept") || l.starts_with("confirm") || l.starts_with("claim")
}

/// Does `f` write a **PENDING** value into a signer/authorization-like target?
/// Such a setter is the *request* half of a two-step flow, so it is safe.
fn writes_pending_value(f: &Function) -> bool {
    let mut pending = false;
    for s in &f.body {
        if pending {
            break;
        }
        s.visit_exprs(&mut |e: &Expr| {
            if pending {
                return;
            }
            if let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind {
                let is_pending_val = matches!(
                    value.simple_name(),
                    Some(name) if name.to_ascii_lowercase().contains("pending")
                );
                if is_pending_val {
                    if let Some(var) = root_ident_str(target) {
                        let l = var.to_ascii_lowercase();
                        if l.contains("signer")
                            || l.contains("delegate")
                            || l.contains("authoriz")
                            || l.contains("admin")
                            || l.contains("owner")
                        {
                            pending = true;
                        }
                    }
                }
            }
        });
    }
    pending
}

/// Is there a two-step accept handshake for the grant variable `var` reachable
/// from `f`'s contract? An `accept*`/`confirm*`/`claim*` sibling that writes the
/// same var family, or that guards on a `pending`-named variable, is the
/// delegatee-side confirmation that makes the install two-step.
fn has_two_step_accept(cx: &AnalysisContext, f: &Function, var: &str) -> bool {
    let Some(contract) = cx.contract_of(f.id) else { return false };
    let var_l = var.to_ascii_lowercase();

    // Functions to consider: this contract's, plus any contract related by name
    // (a base this contract inherits, or one that inherits this contract) so an
    // accept defined in a parent/child still suppresses.
    let related = |c: &sluice_ir::Contract| -> bool {
        c.id == contract.id
            || contract.bases.iter().any(|b| b.eq_ignore_ascii_case(&c.name))
            || c.bases.iter().any(|b| b.eq_ignore_ascii_case(&contract.name))
    };

    for c in cx.scir.iter_contracts() {
        if !related(c) {
            continue;
        }
        for g in cx.scir.functions_of(c.id) {
            if !g.has_body || g.id == f.id {
                continue;
            }
            if !is_accept_named(&g.name) {
                continue;
            }
            // The accept half must be tied to the SAME grant — it must touch the
            // exact target variable `var` (the confirm function always reads or
            // writes the same mapping/var). This prevents an unrelated accept
            // (e.g. `acceptAdmin` for an admin var) from suppressing a finding on
            // a different family (e.g. `delegatedSigner`).
            //
            //   * directly writes the same var (`delegatedSigner[...][...] =
            //     ACCEPTED` in `confirmDelegatedSigner`), or
            //   * its source references `var` AND guards on a `pending`-named value
            //     (the `require(status == PENDING)` confirm check), or
            //   * writes a same-family pending/current var (`acceptAdmin` writing
            //     `_currentDefaultAdmin`/`_pendingDefaultAdmin` for an `admin` var).
            if g.effects.writes_var(var) {
                return true;
            }
            let src = cx.source_text(g.span);
            let references_var = src.contains(&var_l);
            if references_var && src.contains("pending") {
                return true;
            }
            // Same-family fallback only when `var` names a generic admin/owner role
            // (a scalar transfer family), keyed by a shared family token. This is
            // intentionally NOT applied to `signer`/`delegate` families, where the
            // var name is specific and must match exactly (above).
            let admin_family = var_l.contains("admin") || var_l.contains("owner");
            if admin_family {
                let writes_same_family = g.effects.storage_writes.iter().any(|w| {
                    let wl = w.var.to_ascii_lowercase();
                    wl == var_l
                        || (wl.contains("admin") && var_l.contains("admin"))
                        || (wl.contains("owner") && var_l.contains("owner"))
                        || wl.contains("pending")
                });
                if writes_same_family {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "delegated-signer-single-step")
    }

    // VULN — the original Ethena one-step delegated signer: a benefactor authorizes
    // an arbitrary `_delegateTo` to sign on its behalf in a single call, with no
    // confirmation from the delegatee.
    const VULN_DELEGATED_SIGNER: &str = r#"
        contract Minting {
            mapping(address => mapping(address => bool)) public delegatedSigner;
            event DelegatedSignerAdded(address signer, address delegator);
            function setDelegatedSigner(address _delegateTo) external {
                delegatedSigner[_delegateTo][msg.sender] = true;
                emit DelegatedSignerAdded(_delegateTo, msg.sender);
            }
            function removeDelegatedSigner(address _removedSigner) external {
                delegatedSigner[_removedSigner][msg.sender] = false;
            }
        }
    "#;

    // VULN — enum-status variant without the PENDING/confirm half (hypothetical
    // one-step version that jumps straight to ACCEPTED).
    const VULN_ENUM_STATUS: &str = r#"
        contract Minting {
            enum Status { REJECTED, PENDING, ACCEPTED }
            mapping(address => mapping(address => Status)) public delegatedSigner;
            function setDelegatedSigner(address _delegateTo) external {
                delegatedSigner[_delegateTo][msg.sender] = Status.ACCEPTED;
            }
        }
    "#;

    // SAFE — the shipped Ethena fix: setDelegatedSigner records PENDING, and the
    // delegatee must call confirmDelegatedSigner (a PENDING→ACCEPTED handshake).
    const SAFE_TWO_STEP: &str = r#"
        contract Minting {
            enum DelegatedSignerStatus { REJECTED, PENDING, ACCEPTED }
            mapping(address => mapping(address => DelegatedSignerStatus)) public delegatedSigner;
            event DelegatedSignerInitiated(address signer, address delegator);
            event DelegatedSignerAdded(address signer, address delegator);
            error DelegationNotInitiated();
            function setDelegatedSigner(address _delegateTo) external {
                delegatedSigner[_delegateTo][msg.sender] = DelegatedSignerStatus.PENDING;
                emit DelegatedSignerInitiated(_delegateTo, msg.sender);
            }
            function confirmDelegatedSigner(address _delegatedBy) external {
                if (delegatedSigner[msg.sender][_delegatedBy] != DelegatedSignerStatus.PENDING) {
                    revert DelegationNotInitiated();
                }
                delegatedSigner[msg.sender][_delegatedBy] = DelegatedSignerStatus.ACCEPTED;
                emit DelegatedSignerAdded(msg.sender, _delegatedBy);
            }
            function removeDelegatedSigner(address _removedSigner) external {
                delegatedSigner[_removedSigner][msg.sender] = DelegatedSignerStatus.REJECTED;
            }
        }
    "#;

    // SAFE — vote/stake delegation: `mapping(address => address)` pointing the
    // delegator at a delegatee address. Not a signing-authority grant; must stay
    // silent (the structural address-value / single-key exclusion).
    const SAFE_VOTE_DELEGATION: &str = r#"
        contract Votes {
            mapping(address => address) public delegates;
            function delegate(address delegatee) external {
                delegates[msg.sender] = delegatee;
            }
        }
    "#;

    // SAFE — a two-step admin transfer (transferAdmin → acceptAdmin), the
    // SingleAdminAccessControl shape. The setter writes a `pending` var, so it is
    // the request half and must be silent.
    const SAFE_TWO_STEP_ADMIN: &str = r#"
        contract Acl {
            address private _pendingDefaultAdmin;
            address private _currentDefaultAdmin;
            error NotPendingAdmin();
            function transferAdmin(address newAdmin) external {
                _pendingDefaultAdmin = newAdmin;
            }
            function acceptAdmin() external {
                if (msg.sender != _pendingDefaultAdmin) revert NotPendingAdmin();
                _currentDefaultAdmin = msg.sender;
            }
        }
    "#;

    #[test]
    fn fires_on_one_step_delegated_signer() {
        assert!(fires(VULN_DELEGATED_SIGNER), "{:#?}", run(VULN_DELEGATED_SIGNER));
    }

    #[test]
    fn fires_on_one_step_enum_status() {
        assert!(fires(VULN_ENUM_STATUS), "{:#?}", run(VULN_ENUM_STATUS));
    }

    #[test]
    fn silent_on_two_step_confirm() {
        assert!(!fires(SAFE_TWO_STEP));
    }

    #[test]
    fn silent_on_vote_delegation() {
        assert!(!fires(SAFE_VOTE_DELEGATION));
    }

    #[test]
    fn silent_on_two_step_admin_transfer() {
        assert!(!fires(SAFE_TWO_STEP_ADMIN));
    }
}
