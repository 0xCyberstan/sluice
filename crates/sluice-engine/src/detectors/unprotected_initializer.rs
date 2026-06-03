//! Unprotected initializer: an `initialize()`-style function that seizes
//! privileged state (owner/admin/governance/role) while protected by **neither**
//! an initializer guard **nor** access control — so any caller can invoke it and
//! become owner.
//!
//! This is the *standalone-initializer* class, distinct from the
//! uninitialized-**implementation** case that `upgradeable.rs` covers. That
//! detector reasons at the **contract** level (an upgradeable proxy whose
//! constructor omits `_disableInitializers()`); here we reason at the
//! **function** level: regardless of any proxy, an externally-reachable
//! `initialize`/`init`/`setup` function that writes admin state with no
//! `initializer` modifier (so it can be called more than once) and no
//! `msg.sender` gate (so *anyone* can call it) lets an attacker (re)initialize
//! and take ownership. The two detectors use different `Category`s and report at
//! different locations, so they do not collide.
//!
//! Precision first. We fire only when **all** of these hold and **none** of the
//! suppressors do:
//!   * the function name denotes initialization (`initialize`/`init`/`__init`/`setup`);
//!   * it is externally reachable and state-mutating, with a body;
//!   * it writes a privileged *scalar* state variable (owner/admin/governance/role);
//!   * `cx.is_initializer(f) == false`  — no `initializer`/`reinitializer` guard;
//!   * `cx.has_access_control(f) == false` — no `onlyOwner`-style modifier and no
//!     leading `require(msg.sender == ...)`;
//!   * it is not a constructor, and not declared in a library/interface.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::detectors::is_privileged_name;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::Function;

pub struct UnprotectedInitializerDetector;

impl Detector for UnprotectedInitializerDetector {
    fn id(&self) -> &'static str {
        "unprotected-initializer"
    }
    fn category(&self) -> Category {
        Category::UnprotectedInitializer
    }
    fn description(&self) -> &'static str {
        "initialize()-style function that sets owner/admin without an initializer guard or access control"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        // `entry_points()` already restricts to externally-reachable,
        // state-mutating functions that have a body.
        for f in cx.entry_points() {
            // A constructor runs exactly once at deploy time and is never
            // externally re-callable, so it can never be a re-init takeover.
            if f.is_constructor() {
                continue;
            }
            // The name must denote initialization. Without this gate an ordinary
            // setter that happens to write `owner` (and is intentionally
            // permissionless on some designs) would be flagged — that is the
            // access-control detector's job, not this one's.
            if !name_is_init(&f.name) {
                continue;
            }
            // Library/interface "functions" are not deployable attack surface.
            if cx
                .contract_of(f.id)
                .map(|c| c.is_library() || c.is_interface())
                .unwrap_or(false)
            {
                continue;
            }
            // The init function must actually seize *privileged* state. Use the
            // shared conservative privileged-name set (owner/admin/governance/
            // treasury/...), plus an explicit `role`-style write, which the spec
            // calls out and the shared set deliberately omits.
            let Some(var) = privileged_write(f) else {
                continue;
            };

            // ---- false-positive suppression (precision first) ----
            // (1) Guarded by `initializer`/`reinitializer`: it cannot be called
            //     again, so ownership can't be re-seized. `is_initializer`
            //     inspects the parsed `Initializer` guard; the `has_modifier_like`
            //     check is a belt-and-suspenders fallback on the raw modifier name.
            if cx.is_initializer(f) || f.has_modifier_like("initializer") {
                continue;
            }
            // (2) Guarded by access control (an `onlyOwner`-style modifier or a
            //     leading `require(msg.sender == ...)`): not anyone-callable.
            if cx.has_access_control(f) {
                continue;
            }

            let b = FindingBuilder::new(self.id(), Category::UnprotectedInitializer)
                .title("Unprotected initializer can be called by anyone to seize ownership")
                .severity(Severity::High)
                .confidence(0.6)
                // Invariant: the "initialized exactly once, by a trusted party"
                // invariant is unenforced. Value-flow: an attacker-chosen owner
                // value flows into privileged state.
                .dimension(Dimension::Invariant)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` is an initializer-style function that writes privileged state (`{}`) but carries \
                     neither an `initializer`/`reinitializer` guard nor an access-control check. Any account \
                     can call it — and, with no `initializer` guard, call it again after deployment — to set \
                     itself as owner/admin and take over the contract (the unprotected-`initialize` takeover \
                     class).",
                    f.name, var
                ))
                .recommendation(
                    "Add OpenZeppelin's `initializer` (or `reinitializer`) modifier so it runs exactly once, \
                     and/or gate it with access control. If this is meant to run only at deploy time, fold \
                     the logic into the constructor.",
                );
            out.push(cx.finish(b, f.id, f.span));
        }
        out
    }
}

// ------------------------------------------------------------------- helpers

/// True if the function name denotes initialization (`initialize`, `init`,
/// `__init`, `setup`, `reinitialize`, ...). Matched case-insensitively as a
/// substring so `initializeV2` / `__SomeBase_init` / `setUp` are covered.
fn name_is_init(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("initialize") || l.contains("init") || l.contains("__init") || l.contains("setup")
}

/// If the function writes a privileged scalar state variable, return its name.
/// Uses the shared conservative privileged-name set (which intentionally excludes
/// generic per-entity words like `operator`/`minter`), extended with an explicit
/// `role`-style match because seizing a role mapping/var is exactly the takeover
/// the spec targets.
fn privileged_write(f: &Function) -> Option<String> {
    f.effects
        .written_vars()
        .into_iter()
        .find(|v| is_privileged_name(v) || is_role_name(v))
        .map(|v| v.to_string())
}

/// `role`/`roles` (e.g. `roles[msg.sender] = ADMIN`). Kept separate from
/// `is_privileged_name`, which deliberately omits `role` to stay quiet on
/// ordinary RBAC bookkeeping; here it is in scope because the write happens
/// inside an unguarded initializer.
fn is_role_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "role" || l == "roles" || l.ends_with("role") || l.ends_with("roles")
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Externally-callable `initialize` that sets `owner` with no `initializer`
    // modifier and no access control — anyone can call it and become owner.
    const VULN: &str = r#"
pragma solidity ^0.8.20;
contract Vault {
    address public owner;
    uint256 public fee;
    function initialize(address _owner, uint256 _fee) external {
        owner = _owner;
        fee = _fee;
    }
}
"#;

    // Same shape, but guarded by the OpenZeppelin `initializer` modifier, so it
    // can run only once — not a takeover.
    const SAFE: &str = r#"
pragma solidity ^0.8.20;
contract Vault {
    address public owner;
    uint256 public fee;
    bool private _initialized;
    modifier initializer() { require(!_initialized, "init"); _initialized = true; _; }
    function initialize(address _owner, uint256 _fee) external initializer {
        owner = _owner;
        fee = _fee;
    }
}
"#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "unprotected-initializer"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "unprotected-initializer"));
    }
}
