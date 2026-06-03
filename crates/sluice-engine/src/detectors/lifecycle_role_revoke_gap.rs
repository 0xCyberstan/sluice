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
use sluice_ir::{Contract, Function};

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

            // ---- Cardinal suppression: a revoke exists anywhere in the contract.
            // If teardown can undo the grant (even from a different function), the
            // lifecycle is paired — not this class. This silences the standard
            // role-admin shape (Olympus `RolesAdmin.grantRole` + `.revokeRole`).
            if contract_has_revoke(cx, contract) {
                continue;
            }

            // ---- Find the lifecycle-activation grant, if any. ------------------
            // Walk the contract's own functions for a real grant call living in a
            // repeatable activation path (not a one-shot constructor/initializer).
            let Some((grant_fn, grant_span, grant_callee)) =
                cx.scir.functions_of(contract.id).find_map(|f| {
                    if !f.has_body || is_one_shot_setup(f) || !is_lifecycle_activation(&f.name) {
                        return None;
                    }
                    first_grant_call(f).map(|(span, name)| (f, span, name))
                })
            else {
                continue;
            };

            out.push(finish_at(
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
            ));
        }

        out
    }
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
}
