//! Lifecycle role/permission grant with no paired revoke (stale-privilege gap).
//!
//! A role or permission that is **granted** to an address/policy in a *lifecycle
//! activation* path (`activate` / `install` / `enable` / `configure` / `register`
//! / `setup` / `start` / `add*`) but is **never revoked** in any matching
//! *deactivation / teardown* path leaves the grantee holding a standing privilege
//! after the component is deactivated. The privilege is stale: the address can
//! still call the role-gated functions even though the policy/module that needed
//! it is no longer active. This is the access-control lifecycle asymmetry behind
//! "deactivated but still privileged" findings (CWE-266 / CWE-284).
//!
//! ## What fires
//! A concrete contract that, in one of its functions, makes a real **grant** call
//! — `saveRole(...)` / `grantRole(...)` / `_grantRole(...)` / `_setupRole(...)`
//! (Olympus Default-Framework `ROLES.saveRole`, OpenZeppelin `AccessControl`) —
//! where:
//!
//!   * the granting function is a **repeatable lifecycle-activation** operation
//!     (its name denotes activate / install / enable / configure / register /
//!     setup / start / add), **not** a one-shot constructor or initializer; AND
//!   * the **same contract** has **no** revoke call anywhere
//!     (`removeRole` / `revokeRole` / `_revokeRole` / `renounceRole`), i.e. there
//!     is no teardown that undoes the grant.
//!
//! ## What is deliberately suppressed (precision first)
//!   * **A revoke exists.** If the contract makes any revoke call, the lifecycle
//!     is paired — grant and teardown both present — so it is silenced even if the
//!     two live in different functions (e.g. Olympus `RolesAdmin.grantRole`/
//!     `revokeRole`). This is the cardinal suppression for the class.
//!   * **One-shot setup grants.** A grant inside a `constructor`, an `initializer`
//!     / `reinitializer` modifier, or an `initialize` / `__init` / `_initialize` /
//!     `__initialize`-named function is a deployment-time seed of the admin role,
//!     not a repeatable lifecycle action — these are the standard, correct OZ
//!     `_grantRole(DEFAULT_ADMIN_ROLE, admin)` pattern and never fire (this is what
//!     every grant in the EigenLayer / Symbiotic / Pendle / Ethena corpora is).
//!   * **Role-management surfaces.** A contract whose granting function *is* the
//!     generic role-admin API (`grantRole`/`revokeRole` re-exported as the public
//!     surface) is covered by the revoke-exists rule above; a bare `grantRole`
//!     entry point with a sibling `revokeRole` does not fire.
//!
//! The grant/revoke calls are matched on the resolved method name of a real call
//! expression, so an `abi.encodeWithSelector(RolesAdmin.grantRole.selector, ...)`
//! in a governance/deploy script (a `.selector` member access, never an invoked
//! `grantRole`) is **not** a grant and does not trigger the class.
//!
//! Reported on the [`Dimension::Invariant`] dimension at Medium with modest
//! confidence: the asymmetry is a real standing-privilege hazard, but whether the
//! stale role is exploitable depends on what the role gates, which is out of scope
//! here.

use super::prelude::*;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{
    AssignOp, Builtin, CallKind, Contract, Expr, ExprKind, Function, Lit, Stmt, StmtKind, UnOp,
};

pub struct LifecycleRoleRevokeGapDetector;

impl Detector for LifecycleRoleRevokeGapDetector {
    fn id(&self) -> &'static str {
        "lifecycle-role-revoke-gap"
    }
    fn category(&self) -> Category {
        Category::LifecycleRoleRevokeGap
    }
    fn description(&self) -> &'static str {
        "Role/permission granted in an activation path is never revoked in the matching deactivation path (stale privilege)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for contract in cx.scir.iter_contracts() {
            // Only a concrete, deployable contract has a real activate/deactivate
            // lifecycle. Interfaces / libraries / abstract bases declare the
            // grant/revoke surface but do not own the lifecycle state.
            if !contract.is_concrete() {
                continue;
            }

            // (1) Role-CALL lifecycle: a `grantRole`/`saveRole`-style call in an
            //     activation path with no paired revoke call anywhere. (Original.)
            if let Some(f) = self.role_call_gap(cx, contract) {
                out.push(f);
            }

            // (2) Mapping-PRIVILEGE lifecycle: a bespoke address→activation mapping
            //     (the Frankencoin `minters` shape) whose grant has no
            //     post-activation removal path. (Broadening.)
            if let Some(f) = self.mapping_privilege_gap(cx, contract) {
                out.push(f);
            }
        }

        out
    }
}

impl LifecycleRoleRevokeGapDetector {
    /// Original class: a role/permission **grant call** in a repeatable
    /// activation path with **no** revoke call anywhere in the contract.
    fn role_call_gap(&self, cx: &AnalysisContext, contract: &Contract) -> Option<Finding> {
        // ---- Cardinal suppression: a revoke exists anywhere in the contract.
        // If teardown can undo the grant (even from a different function), the
        // lifecycle is paired — not this class. This silences the standard
        // role-admin shape (Olympus `RolesAdmin.grantRole` + `.revokeRole`).
        if contract_has_revoke(cx, contract) {
            return None;
        }

        // ---- Find the lifecycle-activation grant, if any. ------------------
        // Walk the contract's own functions for a real grant call living in a
        // repeatable activation path (not a one-shot constructor/initializer).
        let (grant_fn, grant_span, grant_callee) =
            cx.scir.functions_of(contract.id).find_map(|f| {
                if !f.has_body || is_one_shot_setup(f) || !is_lifecycle_activation(&f.name) {
                    return None;
                }
                first_grant_call(f).map(|(span, name)| (f, span, name))
            })?;

        Some(finish_at(
            cx,
            report!(self, Category::LifecycleRoleRevokeGap,
                title = "Role granted in an activation path is never revoked on deactivation",
                severity = Severity::Medium,
                confidence = 0.5,
                dimensions = [Dimension::Invariant],
                message = format!(
                    "`{}.{}` grants a role/permission (`{}`) in a lifecycle-activation path, but \
                     `{}` defines no matching revoke (`removeRole`/`revokeRole`/`_revokeRole`/\
                     `renounceRole`) in any deactivation/teardown path. After the policy/module \
                     is deactivated the grantee keeps the role, so it can still call the \
                     role-gated functions — a stale standing privilege (access-control lifecycle \
                     asymmetry).",
                    contract.name, grant_fn.name, grant_callee, contract.name
                ),
                recommendation =
                    "Pair the activation grant with a revoke in the deactivation/teardown path: \
                     call the matching `removeRole`/`revokeRole`/`_revokeRole` (or have the \
                     grantee `renounceRole`) when the policy/module is deactivated, so a \
                     deactivated component holds no standing privilege.",
            ),
            grant_fn.id,
            grant_span,
        ))
    }

    /// Broadening for the Frankencoin M-13 shape: a bespoke address-keyed
    /// **privilege mapping** (`minters`) granted as a *time-activated* entry
    /// (`minters[m] = block.timestamp + period`), gating a powerful action
    /// (`mint`/`burn`), whose **only** removal path is reachable **only before
    /// activation** (`denyMinter`: `if (block.timestamp > minters[m]) revert;
    /// delete minters[m]`) — so once the minter activates it can never be
    /// removed. See [`mapping_privilege_gap`] for the full predicate.
    fn mapping_privilege_gap(&self, cx: &AnalysisContext, contract: &Contract) -> Option<Finding> {
        let (gate, grant_fn, grant_span) = find_activation_mapping_gap(cx, contract)?;
        Some(finish_at(
            cx,
            report!(self, Category::LifecycleRoleRevokeGap,
                title = "Time-activated privilege mapping has no post-activation revoke path",
                severity = Severity::Medium,
                confidence = 0.5,
                dimensions = [Dimension::Invariant],
                message = format!(
                    "`{}.{}` grants a standing privilege by writing the activation-mapping \
                     `{}[...]` (a `block.timestamp`-based approval that gates a powerful action \
                     such as mint/burn). The only path that clears `{}[...]` is reachable **only \
                     before** the entry activates (its removal is guarded by a comparison against \
                     `block.timestamp`/`{}` itself, i.e. an application-window veto), and there is \
                     no unconditional removal. Once the entry activates, the privilege can never be \
                     paused or revoked — a malicious/compromised grantee is permanent (access-control \
                     lifecycle asymmetry, CWE-284).",
                    contract.name, grant_fn.name, gate.mapping, gate.mapping, gate.mapping
                ),
                recommendation =
                    "Add an unconditional, access-controlled removal path for an already-activated \
                     entry (a deny/remove/pause that works after the application window — e.g. clears \
                     the mapping entry or sets a paused flag the action gate also checks), so a \
                     compromised or misbehaving grantee can be stopped after activation, not only \
                     vetoed beforehand.",
            ),
            grant_fn.id,
            grant_span,
        ))
    }
}

/// A recognised address-keyed privilege mapping plus the facts that make its
/// lifecycle asymmetric. Built by [`find_activation_mapping_gap`].
struct ActivationGate {
    /// Name of the privilege mapping state var (`minters`).
    mapping: String,
}

/// Detect the Frankencoin minter-lifecycle shape on `contract` and, if present,
/// return `(gate, grant_fn, grant_span)`.
///
/// Fires iff a **settable** state mapping `M` keyed by `address`/`bytes32`
/// exists for which ALL of the following hold:
///
///   1. **Grant.** Some externally-reachable, state-mutating, non-one-shot
///      function writes `M[k] = <rhs>` where the granted value is a
///      *time-activation* (`rhs` mentions `block.timestamp`). This is the
///      "turn it on at/after time T" approval write.
///   2. **Privilege.** `M` gates a powerful action — `M` (directly, or through a
///      same-contract reader function it is read in, e.g. `isMinter`) is read by
///      the access guard of a state-mutating action that mints/burns/moves value.
///   3. **No post-activation removal.** Every function that *clears* an `M[k]`
///      entry (a `delete M[k]` or an `M[k] = 0`) is reachable **only before
///      activation** — its body is guarded by a comparison against
///      `block.timestamp` / `M[..]` (the application-window veto) — OR there is
///      **no** clearing function at all. (An *unconditional* clear — a plain
///      `removeMinter`/`revoke` with no such time gate — is a real teardown and
///      suppresses the finding.)
///
/// The time-gated/absent removal in (3) is the discriminator: an OpenZeppelin
/// `AccessControl` role mapping is cleared by an unconditional `revokeRole`, so
/// it is suppressed; only a privilege whose removal is *itself* gated to the
/// pre-activation window (or missing) is a genuine "can grant, can never revoke"
/// asymmetry.
fn find_activation_mapping_gap<'a>(
    cx: &'a AnalysisContext,
    contract: &'a Contract,
) -> Option<(ActivationGate, &'a Function, sluice_ir::Span)> {
    for var in &contract.state_vars {
        if !is_privilege_mapping(var) {
            continue;
        }

        // (1) Grant: an external, state-mutating, non-one-shot function that
        //     writes a *time-activation* entry into this mapping.
        let Some((grant_fn, grant_span)) = cx
            .scir
            .functions_of(contract.id)
            .find_map(|f| time_activation_grant(f, &var.name).map(|s| (f, s)))
        else {
            continue;
        };

        // (2) Privilege: the mapping must gate a powerful action.
        if !mapping_gates_action(cx, contract, &var.name) {
            continue;
        }

        // (3) No post-activation removal: every clear of this mapping is
        //     activation-window-gated (or there is none). An unconditional clear
        //     is a real teardown and disqualifies the finding.
        if has_unconditional_clear(cx, contract, &var.name) {
            continue;
        }

        return Some((ActivationGate { mapping: var.name.clone() }, grant_fn, grant_span));
    }
    None
}

/// Is `var` a **settable** (non-constant/immutable) state **mapping** keyed by an
/// identity type (`address` / `bytes32`) — the shape of a bespoke
/// role/minter/whitelist map? The key type is read from the declared mapping
/// text `mapping(K => V)`.
fn is_privilege_mapping(var: &sluice_ir::StateVar) -> bool {
    if var.constant || var.immutable || !var.is_mapping() {
        return false;
    }
    let key = mapping_key_type(&var.ty);
    key == "address" || key == "bytes32"
}

/// Extract the key type `K` from a `mapping(K => V)` declared type (best-effort).
fn mapping_key_type(ty: &str) -> &str {
    let t = ty.trim();
    let Some(rest) = t.strip_prefix("mapping") else { return "" };
    let rest = rest.trim_start().strip_prefix('(').unwrap_or(rest);
    let key = rest.split("=>").next().unwrap_or("").trim();
    // Strip a trailing storage keyword / name the parser may keep.
    key.split_whitespace().next().unwrap_or(key)
}

/// If `f` is an externally-reachable, state-mutating, non-one-shot function that
/// writes a **time-activation** entry into mapping `var` — i.e. an assignment
/// `var[k] = <rhs>` whose right-hand side mentions `block.timestamp` — return the
/// span of that assignment. This is the "approval that turns on at/after a
/// timestamp" grant (`minters[_minter] = block.timestamp + _applicationPeriod`).
fn time_activation_grant(f: &Function, var: &str) -> Option<sluice_ir::Span> {
    if !f.has_body
        || is_one_shot_setup(f)
        || !f.is_externally_reachable()
        || !f.is_state_mutating()
    {
        return None;
    }
    // Must actually write the mapping (cheap effect-summary pre-filter).
    if !f.effects.writes_var(var) {
        return None;
    }
    let mut hit: Option<sluice_ir::Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            if let ExprKind::Assign { target, value, .. } = &e.kind {
                if assign_target_indexes_var(target, var) && expr_mentions_block_time(value) {
                    hit = Some(e.span);
                }
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Is `target` an index expression `var[...]` (an assignment to a mapping entry),
/// after peeling casts on the base? Matches the lvalue of `minters[_minter] = …`.
fn assign_target_indexes_var(target: &Expr, var: &str) -> bool {
    matches!(&target.kind, ExprKind::Index { base, .. }
        if root_ident_str(peel_casts(base)) == Some(var))
}

/// Does `e` reference `block.timestamp` / `block.number` / `now` anywhere — the
/// marker that a written mapping value is a *time activation*?
fn expr_mentions_block_time(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| match &sub.kind {
        ExprKind::Member { base, member } => {
            if matches!(&base.kind, ExprKind::Ident(b) if b == "block")
                && (member == "timestamp" || member == "number")
            {
                found = true;
            }
        }
        ExprKind::Ident(n) if n == "now" => found = true,
        _ => {}
    });
    found
}

/// Does mapping `var` gate a **powerful action** in `contract`? True when some
/// externally-reachable, state-mutating function that performs a value action
/// (mint/burn/transfer — by `_mint`/`_burn`/`_transfer` internal call or a
/// mint/burn-named entry) is access-guarded by a check that reads `var` —
/// directly, or through a same-contract *reader* function (e.g. `isMinter`) whose
/// body reads `var`. This is the "the mapping is what authorises minting" link.
fn mapping_gates_action(cx: &AnalysisContext, contract: &Contract, var: &str) -> bool {
    // Same-contract reader functions whose body reads `var` (e.g. `isMinter`,
    // `minterOnly`). The action's guard usually goes through one of these.
    let readers: Vec<&str> = cx
        .scir
        .functions_of(contract.id)
        .filter(|f| f.effects.reads_var(var))
        .map(|f| f.name.as_str())
        .collect();

    cx.scir.functions_of(contract.id).any(|f| {
        if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
            return false;
        }
        if !performs_value_action(f) {
            return false;
        }
        // The function must be access-gated, and that gate must reference `var`
        // or one of its reader functions (the modifier/`require` text, or a
        // direct read of `var` inside the body of a function gated on it).
        f.effects.guards.iter().any(|g| {
            guard_references(g, var, &readers)
        }) || f.effects.reads_var(var)
    })
}

/// Does the function perform a value action — mint / burn / token transfer — by
/// either calling a `_mint`/`_burn`/`mint`/`burn`/`_transfer`-style internal
/// helper or being itself named like one?
fn performs_value_action(f: &Function) -> bool {
    let acts = |n: &str| {
        let l = n.to_ascii_lowercase();
        l.contains("mint") || l.contains("burn") || l.contains("transfer")
    };
    f.effects.internal_calls.iter().any(|c| acts(c)) || acts(&f.name)
}

/// Does guard `g` reference the privilege mapping `var` or one of its reader
/// function names (so the guard is the one that consults the mapping)? The guard
/// text is the modifier name (`minterOnly`) or the `require`/`if` source.
fn guard_references(g: &sluice_ir::Guard, var: &str, readers: &[&str]) -> bool {
    let t = g.text.to_ascii_lowercase();
    if t.contains(&var.to_ascii_lowercase()) {
        return true;
    }
    readers.iter().any(|r| {
        let r = r.to_ascii_lowercase();
        // A bare modifier name like `minterOnly` is the whole guard text; a
        // reader like `isMinter` shows up as `isminter(...)` in a require.
        !r.is_empty() && t.contains(&r)
    })
}

/// Does `contract` have an **unconditional** clear of mapping `var` — a function
/// that clears an `var[k]` entry (`delete var[k]` or `var[k] = 0`) WITHOUT being
/// gated to the pre-activation window? "Pre-activation-gated" means the function
/// has an entry guard that compares against `block.timestamp` / `var[..]` (the
/// `denyMinter` "`if (block.timestamp > minters[m]) revert TooLate()`" veto).
///
/// If such an unconditional clear exists, the privilege *can* be revoked after
/// activation, so the lifecycle is paired and the finding is suppressed. A clear
/// that exists only behind the application-window guard does NOT count (it cannot
/// run post-activation), and so does not suppress.
fn has_unconditional_clear(cx: &AnalysisContext, contract: &Contract, var: &str) -> bool {
    cx.scir.functions_of(contract.id).any(|f| {
        f.has_body && function_clears_mapping(f, var) && !is_activation_window_gated(f, var)
    })
}

/// Does `f` clear an entry of mapping `var` — `delete var[k]` or an assignment
/// `var[k] = 0`?
fn function_clears_mapping(f: &Function, var: &str) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            match &e.kind {
                // `delete var[k]`
                ExprKind::Unary { op: UnOp::Delete, operand } => {
                    if assign_target_indexes_var(operand, var) {
                        found = true;
                    }
                }
                // `var[k] = 0`
                ExprKind::Assign { op: AssignOp::Assign, target, value } => {
                    if assign_target_indexes_var(target, var) && is_zero_lit(value) {
                        found = true;
                    }
                }
                _ => {}
            }
        });
        if found {
            break;
        }
    }
    found
}

/// Is `e` the integer literal `0` (decimal or `0x0`)?
fn is_zero_lit(e: &Expr) -> bool {
    match &peel_casts(e).kind {
        ExprKind::Lit(Lit::Number(n)) => n.trim() == "0",
        ExprKind::Lit(Lit::HexNumber(h)) => {
            let s = h.trim().trim_start_matches("0x").trim_start_matches("0X");
            !s.is_empty() && s.bytes().all(|b| b == b'0')
        }
        _ => false,
    }
}

/// Is `f` gated to the **pre-activation window** for mapping `var`? True when an
/// entry guard (a leading `require` / `if (...) revert`) compares against
/// `block.timestamp` *and* references `var` — the `denyMinter` shape
/// `if (block.timestamp > minters[m]) revert TooLate();`, which makes the body
/// reachable only while the entry has not yet activated.
fn is_activation_window_gated(f: &Function, var: &str) -> bool {
    // Scan the guards' text first (cheap, already extracted).
    for g in &f.effects.guards {
        let t = g.text.to_ascii_lowercase();
        if t.contains("block.timestamp") && t.contains(&var.to_ascii_lowercase()) {
            return true;
        }
    }
    // Fall back to the body: any `if (<cmp involving block.timestamp and var>)`
    // whose then-branch reverts.
    let mut gated = false;
    for s in &f.body {
        s.visit(&mut |st| {
            if gated {
                return;
            }
            if let StmtKind::If { cond, then_branch, .. } = &st.kind {
                if cond_compares_blocktime_and_var(cond, var) && branch_reverts(then_branch) {
                    gated = true;
                }
            }
        });
        if gated {
            break;
        }
    }
    gated
}

/// Does `cond` contain an ordering/equality comparison whose operands together
/// reference both `block.timestamp` and the mapping `var`? (`block.timestamp >
/// minters[_minter]`.)
fn cond_compares_blocktime_and_var(cond: &Expr, var: &str) -> bool {
    let mut hit = false;
    cond.visit(&mut |sub| {
        if hit {
            return;
        }
        if let ExprKind::Binary { op, lhs, rhs } = &sub.kind {
            if op.is_comparison()
                && ((expr_mentions_block_time(lhs) && expr_mentions_ident(rhs, var))
                    || (expr_mentions_block_time(rhs) && expr_mentions_ident(lhs, var)))
            {
                hit = true;
            }
        }
    });
    hit
}

/// Does a statement list (a branch) contain a `revert` / `require(false)`-style
/// terminator at its top level?
fn branch_reverts(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|s| match &s.kind {
        StmtKind::Revert { .. } => true,
        StmtKind::Expr(e) => matches!(&e.kind,
            ExprKind::Call(c) if matches!(c.kind, CallKind::Builtin(Builtin::Revert))),
        _ => false,
    })
}

/// Resolved-name set of a role/permission **grant** call.
fn is_grant_name(name: &str) -> bool {
    matches!(
        name,
        "saveRole" | "grantRole" | "_grantRole" | "_grantRoles" | "grantRoles" | "_setupRole"
    )
}

/// Resolved-name set of a role/permission **revoke** call (the teardown side).
fn is_revoke_name(name: &str) -> bool {
    matches!(
        name,
        "removeRole"
            | "revokeRole"
            | "_revokeRole"
            | "_revokeRoles"
            | "revokeRoles"
            | "renounceRole"
            | "_renounceRole"
    )
}

/// Span + resolved name of the first real grant **call** in `f`'s body, if any.
/// Matches only an invoked call (an `ExprKind::Call` whose `func_name` is a grant
/// name) — never a `RolesAdmin.grantRole.selector` member access, which is a
/// `.selector` field read in deploy/governance scripts and not a grant.
fn first_grant_call(f: &Function) -> Option<(sluice_ir::Span, String)> {
    for (call, span) in f.calls() {
        if let Some(name) = call.func_name.as_deref() {
            if is_grant_name(name) {
                return Some((span, name.to_string()));
            }
        }
    }
    None
}

/// Does **any** function of `contract` make a real revoke call? Scans the
/// contract's own functions (the lifecycle owner); an inherited generic
/// `revokeRole` from an out-of-scope base is not the teardown this class is about.
fn contract_has_revoke(cx: &AnalysisContext, contract: &Contract) -> bool {
    cx.scir.functions_of(contract.id).any(|f| {
        f.has_body
            && f.calls()
                .iter()
                .any(|(c, _)| c.func_name.as_deref().is_some_and(is_revoke_name))
    })
}

/// A **one-shot setup** function — a constructor, an `initializer`/`reinitializer`
/// modifier-guarded function, or an `initialize`/`__init`/`_initialize`-named
/// function. A grant here seeds the admin role exactly once at deployment (the
/// standard OZ `_grantRole(DEFAULT_ADMIN_ROLE, admin)` idiom); it is not a
/// repeatable lifecycle action, so it must never fire this class.
fn is_one_shot_setup(f: &Function) -> bool {
    if f.is_constructor()
        || f.has_modifier_like("initializer")
        || f.has_modifier_like("reinitializer")
    {
        return true;
    }
    let l = f.name.to_ascii_lowercase();
    l.starts_with("initialize")
        || l.starts_with("reinitialize")
        || l.starts_with("__init")
        || l.starts_with("_init")
        || l == "init"
}

/// Does the function name denote a **repeatable lifecycle-activation** operation —
/// the surface whose grant should be undone on deactivation? Activate / install /
/// enable / configure / register / setup / start / add. This deliberately
/// *excludes* one-shot init (handled by [`is_one_shot_setup`]) and the bare
/// `grantRole` role-admin API (handled by the revoke-exists suppression), so the
/// class fires only on a genuine "turn this on, but never able to turn it off"
/// asymmetry.
fn is_lifecycle_activation(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // `setUp` (test) / `setup*` config, and `configure*` dependency wiring.
    if l == "setup" || l.starts_with("setup") || l.starts_with("configure") {
        return true;
    }
    // Activation / install / enable / register / start verbs.
    const ACTIVATE: &[&str] = &[
        "activate", "install", "enable", "register", "start", "launch", "onboard", "commission",
    ];
    if ACTIVATE.iter().any(|k| l.contains(k)) {
        return true;
    }
    // `add<Thing>` (addPolicy / addOperator / addModule) — an additive lifecycle
    // step whose inverse is a `remove<Thing>` teardown. A bare `add` is too generic
    // to qualify; require the `add` prefix with a following word.
    l.starts_with("add") && l.len() > 3
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    fn fired(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.detector == "lifecycle-role-revoke-gap")
    }

    // VULN: an activation path grants a role, but the contract has a `deactivate`
    // teardown that does NOT revoke it — stale privilege after deactivation.
    const VULN: &str = r#"
        interface IROLES { function saveRole(bytes32 role, address addr) external;
                           function removeRole(bytes32 role, address addr) external; }
        contract PolicyManager {
            IROLES public ROLES;
            address public operator;
            bool public active;

            function activatePolicy(address operator_) external {
                operator = operator_;
                active = true;
                ROLES.saveRole("operator_role", operator_);
            }

            function deactivatePolicy() external {
                active = false;
                // BUG: forgot to ROLES.removeRole("operator_role", operator) —
                // the operator keeps the role after deactivation.
            }
        }
    "#;

    // SAFE: same activation grant, but the deactivation path revokes it.
    const SAFE: &str = r#"
        interface IROLES { function saveRole(bytes32 role, address addr) external;
                           function removeRole(bytes32 role, address addr) external; }
        contract PolicyManager {
            IROLES public ROLES;
            address public operator;
            bool public active;

            function activatePolicy(address operator_) external {
                operator = operator_;
                active = true;
                ROLES.saveRole("operator_role", operator_);
            }

            function deactivatePolicy() external {
                active = false;
                ROLES.removeRole("operator_role", operator);
            }
        }
    "#;

    // SAFE: the grant is a one-shot constructor/initializer seed (standard OZ
    // pattern). No lifecycle activation, must not fire even with no revoke.
    const SAFE_INIT: &str = r#"
        abstract contract AccessControl {
            function _grantRole(bytes32 role, address account) internal virtual {}
        }
        contract Token is AccessControl {
            bytes32 public constant ADMIN = keccak256("ADMIN");
            function initialize(address admin) external {
                _grantRole(ADMIN, admin);
            }
        }
    "#;

    // SAFE: the OZ-style role-admin surface — a `grantRole` entry point with a
    // sibling `revokeRole`. Revoke exists, so suppressed (mirrors Olympus
    // RolesAdmin).
    const SAFE_ADMIN_API: &str = r#"
        abstract contract AccessControl {
            function _grantRole(bytes32 role, address account) internal virtual {}
            function _revokeRole(bytes32 role, address account) internal virtual {}
        }
        contract RolesAdmin is AccessControl {
            function grantRole(bytes32 role, address wallet) external {
                _grantRole(role, wallet);
            }
            function revokeRole(bytes32 role, address wallet) external {
                _revokeRole(role, wallet);
            }
        }
    "#;

    #[test]
    fn fires_on_activation_grant_without_revoke() {
        let fs = run(VULN);
        assert!(fired(&fs), "expected lifecycle-role-revoke-gap on VULN, got {:?}", fs);
    }

    #[test]
    fn silent_when_deactivation_revokes() {
        assert!(!fired(&run(SAFE)), "should not fire when teardown revokes the role");
    }

    #[test]
    fn silent_on_one_shot_init_grant() {
        assert!(!fired(&run(SAFE_INIT)), "should not fire on a constructor/initializer seed grant");
    }

    #[test]
    fn silent_on_role_admin_api_with_revoke_sibling() {
        assert!(!fired(&run(SAFE_ADMIN_API)), "should not fire when a sibling revoke exists");
    }

    // ---- Mapping-privilege lifecycle path (Frankencoin M-13) ---------------

    /// Fired specifically by the *mapping-privilege* path (not the role-call one).
    fn fired_mapping(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| {
            f.detector == "lifecycle-role-revoke-gap"
                && f.title.contains("Time-activated privilege mapping")
        })
    }

    // VULN: the Frankencoin minter shape. `minters[m] = block.timestamp + period`
    // grants a time-activated privilege that gates `mint` (via the `minterOnly`
    // guard → `isMinter` reading `minters`); the only path that clears the entry
    // (`denyMinter`) is gated to the pre-activation window
    // (`if (block.timestamp > minters[m]) revert`), so an activated minter is
    // permanent. Must fire on the mapping-privilege path.
    const VULN_MINTER: &str = r#"
        contract Stable {
            mapping(address => uint256) public minters;
            uint256 immutable APPLY;
            constructor(uint256 a){ APPLY = a; }

            function suggestMinter(address _minter, uint256 _period) external {
                if (minters[_minter] != 0) revert();
                minters[_minter] = block.timestamp + _period;
            }

            function denyMinter(address _minter) external {
                if (block.timestamp > minters[_minter]) revert();
                delete minters[_minter];
            }

            function isMinter(address _m) public view returns (bool) {
                return minters[_m] != 0 && block.timestamp >= minters[_m];
            }

            modifier minterOnly() {
                if (!isMinter(msg.sender)) revert();
                _;
            }

            function mint(address to, uint256 amt) external minterOnly {
                _mint(to, amt);
            }
            function _mint(address to, uint256 amt) internal {}
        }
    "#;

    // SAFE: same time-activated minter grant + a pre-activation `denyMinter`, BUT
    // also an UNCONDITIONAL `removeMinter` that clears an activated entry. The
    // privilege can be revoked after activation, so the lifecycle is paired and
    // the mapping-privilege path must stay silent.
    const SAFE_MINTER_REMOVABLE: &str = r#"
        contract Stable {
            mapping(address => uint256) public minters;
            address public admin;

            function suggestMinter(address _minter, uint256 _period) external {
                minters[_minter] = block.timestamp + _period;
            }

            function denyMinter(address _minter) external {
                if (block.timestamp > minters[_minter]) revert();
                delete minters[_minter];
            }

            // Unconditional teardown of an already-activated minter.
            function removeMinter(address _minter) external {
                require(msg.sender == admin);
                delete minters[_minter];
            }

            function isMinter(address _m) public view returns (bool) {
                return minters[_m] != 0 && block.timestamp >= minters[_m];
            }

            modifier minterOnly() {
                if (!isMinter(msg.sender)) revert();
                _;
            }

            function mint(address to, uint256 amt) external minterOnly {
                _mint(to, amt);
            }
            function _mint(address to, uint256 amt) internal {}
        }
    "#;

    // SAFE: an address mapping that is NOT a time-activated approval — it is a
    // plain balance/bookkeeping map written with a value, not `block.timestamp`.
    // Not a privilege-activation lifecycle, so it must not fire.
    const SAFE_NOT_TIME_GATED: &str = r#"
        contract Vault {
            mapping(address => uint256) public balances;
            function deposit(address who, uint256 amt) external {
                balances[who] = amt;
            }
            function mint(address to, uint256 amt) external {
                _mint(to, amt);
            }
            function _mint(address to, uint256 amt) internal {}
        }
    "#;

    #[test]
    fn fires_on_time_activated_minter_without_post_activation_revoke() {
        let fs = run(VULN_MINTER);
        assert!(
            fired_mapping(&fs),
            "expected mapping-privilege lifecycle finding on the minter shape, got {:?}",
            fs
        );
    }

    #[test]
    fn silent_when_minter_has_unconditional_removal() {
        assert!(
            !fired_mapping(&run(SAFE_MINTER_REMOVABLE)),
            "should not fire when an unconditional removeMinter can revoke an activated minter"
        );
    }

    #[test]
    fn silent_on_non_time_activated_mapping() {
        assert!(
            !fired_mapping(&run(SAFE_NOT_TIME_GATED)),
            "should not fire on a plain bookkeeping mapping (no time-activation grant)"
        );
    }
}
