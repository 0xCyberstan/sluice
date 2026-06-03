//! Missing event emission on a privileged config / role setter.
//!
//! A privileged, access-controlled setter that changes ownership, configuration,
//! a role, or a protocol parameter but emits **no event** is invisible to
//! off-chain monitoring: indexers, dashboards, and incident-response tooling have
//! no log to subscribe to, so a privileged change (a new owner, a re-pointed
//! treasury/oracle, a bumped fee/limit) happens silently. Emitting an event on
//! every privileged state change is the canonical hygiene convention (it is what
//! every standard linter — Slither's `events-access` / `events-maths`, SWC — ships
//! a rule for). Its absence is the single most visible incompleteness signal, so
//! this fires broadly wherever the shape exists, at **Low** severity (hygiene).
//!
//! ## What fires
//!
//! The subject is a *privileged config/role SETTER* — a function that is the
//! standing admin surface for changing contract configuration:
//!
//!   * **Arm A — an access-controlled setter by name.** The function carries an
//!     access-control guard (`cx.has_access_control` — an `onlyOwner` / `onlyRole`
//!     / `onlyGovernor` modifier or an inline `require(msg.sender == …)`), its name
//!     begins `set` / `update` / `change`, and it writes a **scalar** state
//!     variable. This is the overwhelming majority of real setters
//!     (`setTreasury`, `updateAdmin`, `setFeeRecipient`, `setHook`, …).
//!   * **Arm B — a privileged-state writer.** The function (access-controlled, or
//!     setter-named) writes a **scalar** state variable whose *name* denotes a
//!     privileged / config / role / parameter role (owner, governance, treasury,
//!     oracle, implementation, fee, limit, threshold, duration, …). This catches
//!     role-mutating functions that do not start with `set` (an ownership-accept
//!     `acceptOwnership` reassigning `owner`, a `_setImplementation`).
//!
//! In every arm the function must actually perform a **scalar** state write: a
//! per-key `mapping[...] = ...` write is ordinary bookkeeping, not a single
//! config/role change, and is not the subject here. Requiring a concrete scalar
//! write also keeps the lint off privileged functions that merely *call* something
//! (a `pause()` that flips no scalar, a delegating wrapper).
//!
//! ## What stays silent (the safe form)
//!
//! * **Any function that emits.** The presence of a single `emit …;` statement
//!   anywhere in the body (including inside an `if` / loop) suppresses the finding
//!   entirely — that is the correct, logged form (`setHook(...) { …; emit
//!   SetHook(hook_); }`). This is checked structurally on the body's `Emit` nodes,
//!   so it never misses a real emission.
//! * **Constructors and initializers.** One-shot setup, not the standing setter
//!   surface (an initializer commonly seeds config without per-field events).
//! * **`view` / `pure` functions.** They change nothing — already excluded by
//!   `entry_points`, and guarded explicitly.
//! * **Non-privileged user operations.** `deposit` / `stake` / `claim` / … are not
//!   config setters; they are excluded unless they genuinely match the privileged
//!   setter shape above.
//!
//! This is intentionally a *hygiene* class: it flags a missing log, not a code
//! defect, so the confidence is modest (0.35) and the severity Low — it never
//! outranks a real value finding.

use super::prelude::*;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{Contract, Function, StmtKind};

pub struct MissingEventEmitDetector;

impl Detector for MissingEventEmitDetector {
    fn id(&self) -> &'static str {
        "missing-event-emit"
    }
    fn category(&self) -> Category {
        Category::MissingEventEmit
    }
    fn description(&self) -> &'static str {
        "Privileged config/role setter changes state but emits no event"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.entry_points() {
            // Non-setter shapes are dropped up front. `entry_points` already
            // restricts to externally-reachable, state-mutating, bodied functions
            // (so `view`/`pure` and interface decls are gone), but constructors and
            // initializers are one-shot setup — not the standing admin setter
            // surface — and a per-field event there is not the convention.
            if f.is_constructor()
                || f.is_view_or_pure()
                || cx.is_initializer(f)
                || f.has_modifier_like("initializer")
                || is_initializer_name(&f.name)
            {
                continue;
            }

            // The safe form: a body that emits *any* event is correctly logged —
            // stay silent. Checked structurally on the body's `Emit` nodes (robust
            // to emits nested in `if`/loops, and to events whose call carries no
            // resolved `func_name`), so a real emission is never missed.
            if body_emits_event(f) {
                continue;
            }

            let Some(contract) = cx.contract_of(f.id) else { continue };

            // The function must perform a concrete **scalar** state write — the
            // config/role/param change itself. A purely-`mapping[...]=` writer is
            // per-key bookkeeping (handled elsewhere), and a function that writes no
            // scalar state is not a config setter (a `pause()` flipping nothing, a
            // delegating wrapper). `target_var` is the scalar we will name.
            let Some(target_var) = first_scalar_state_write(f, contract) else { continue };

            let guarded = cx.has_access_control(f);
            let setter = is_setter_name(&f.name);
            let priv_state = is_privileged_config_name(&target_var);

            // Fire on the genuine *privileged setter* shape:
            //   * Arm A — guarded + setter-named (the dominant real case); or
            //   * Arm B — a privileged/config/role scalar write that is itself
            //     administrative, i.e. either access-controlled or setter-named.
            //     (Requiring guard-or-name keeps the lint off an ordinary user op
            //     that merely touches a config-shaped scalar.)
            let arm_a = guarded && setter;
            let arm_b = priv_state && (guarded || setter);
            if !(arm_a || arm_b) {
                continue;
            }

            out.push(finish_at(
                cx,
                report!(self, Category::MissingEventEmit,
                    title = "Privileged setter changes state without emitting an event",
                    severity = Severity::Low,
                    confidence = 0.35,
                    dimensions = [Dimension::Invariant],
                    message = format!(
                        "`{}.{}` is an access-controlled / privileged setter that writes state \
                         (`{}`) but emits no event. Off-chain monitoring, indexers, and \
                         incident-response tooling have no log to observe this privileged change, \
                         so a re-pointed owner / treasury / oracle or a changed fee / limit / \
                         parameter happens silently. Emitting an event on every privileged state \
                         change is the standard hygiene convention.",
                        contract.name, f.name, target_var
                    ),
                    recommendation = format!(
                        "Emit an event recording the change (ideally the old and new value), e.g. \
                         `emit {}Updated(old{}, {});`, so the privileged update is observable \
                         off-chain.",
                        cap_first(&target_var),
                        cap_first(&target_var),
                        target_var
                    ),
                ),
                f.id,
                f.span,
            ));
        }

        out
    }
}

/// True if the body contains **any** `emit …;` statement (transitively — the
/// recursive `Stmt::visit` descends into `if`/`while`/`for`/`try`/block bodies).
/// This is the precise "the function logs the change" check: its presence is the
/// safe form and suppresses the finding. We test the structural `Emit` node rather
/// than `effects.emits`, because the latter only records emits whose call resolves
/// a `func_name` and would miss an unusual emission — which here would be a false
/// positive (we would claim a logged setter is unlogged).
fn body_emits_event(f: &Function) -> bool {
    let mut emits = false;
    for s in &f.body {
        s.visit(&mut |st| {
            if matches!(st.kind, StmtKind::Emit(_)) {
                emits = true;
            }
        });
        if emits {
            break;
        }
    }
    emits
}

/// The name of the first **scalar** (non-mapping) state variable written by `f`,
/// resolved against the function's contract. Returns `None` if the function writes
/// no scalar state variable (only mapping entries, or no state at all). The
/// returned name is the concrete config/role field this setter changes — used both
/// to gate Arm B and to name the field in the finding.
fn first_scalar_state_write(f: &Function, contract: &Contract) -> Option<String> {
    for w in &f.effects.storage_writes {
        // Resolve the written var to its declaration; a write to a name that is not
        // a declared state var, or to a `mapping(...)`, is not a scalar config set.
        if let Some(sv) = contract.state_vars.iter().find(|v| v.name == w.var) {
            if !sv.is_mapping() {
                return Some(sv.name.clone());
            }
        }
    }
    None
}

/// A configuration/role *setter* by name: begins `set` / `update` / `change`
/// (case-insensitive). The dominant naming convention for an admin setter
/// (`setTreasury`, `updateAdmin`, `changeRouter`).
fn is_setter_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.starts_with("set") || l.starts_with("update") || l.starts_with("change")
}

/// An initializer-by-name: a one-shot setup function (`initialize`, `reinitialize`,
/// `__init`, `init`). Mirrors the centralization detector's filter — these seed
/// state once and are not the standing setter surface, and per-field events are not
/// the convention there. Complements `cx.is_initializer`, which only sees the
/// `initializer` *modifier* guard.
fn is_initializer_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.starts_with("initialize") || l.starts_with("reinitialize") || l.starts_with("__init") || l == "init"
}

/// Does `name` denote a privileged / configuration / role / parameter state field
/// — the kind of value whose change should be logged? Extends the shared
/// `is_privileged_name` (owner / admin / governance / treasury / oracle /
/// implementation / authority / …) with the common configuration-parameter
/// vocabulary (fee, rate, limit, cap, threshold, duration, recipient, router,
/// feed, …). Used for Arm B and as a corroborating signal.
fn is_privileged_config_name(name: &str) -> bool {
    if is_privileged_name(name) {
        return true;
    }
    let l = name.to_ascii_lowercase();
    const CONFIG: &[&str] = &[
        "fee",
        "rate",
        "limit",
        "cap",
        "threshold",
        "duration",
        "period",
        "delay",
        "recipient",
        "receiver",
        "beneficiary",
        "router",
        "feed",
        "registry",
        "factory",
        "manager",
        "controller",
        "vault",
        "delegator",
        "slasher",
        "hook",
        "minter",
        "operator",
        "validator",
        "signer",
        "verifier",
        "config",
        "param",
        "weight",
        "merkleroot",
        "root",
        "uri",
        "metadata",
        "pendingowner",
        "pending",
    ];
    CONFIG.iter().any(|k| l.contains(k))
}

/// Capitalize the first character of `s` (for a readable suggested event name:
/// `treasury` → `Treasury`). ASCII-only; leaves non-alphabetic leads unchanged.
fn cap_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + c.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    fn fired(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.detector == "missing-event-emit")
    }

    // FIRES: an `onlyOwner` setter that re-points a privileged address scalar and
    // emits NO event — the canonical missing-log shape.
    const UNSAFE: &str = r#"
        contract Vault {
            address public owner;
            address public treasury;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
            constructor() { owner = msg.sender; }
            function setTreasury(address t) external onlyOwner {
                treasury = t;
            }
        }
    "#;

    // SILENT (safe form): the same setter, but it emits an event recording the
    // change. The presence of `emit` is exactly the convention this lint checks.
    const SAFE_EMITS: &str = r#"
        contract Vault {
            address public owner;
            address public treasury;
            event TreasurySet(address t);
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
            constructor() { owner = msg.sender; }
            function setTreasury(address t) external onlyOwner {
                treasury = t;
                emit TreasurySet(t);
            }
        }
    "#;

    #[test]
    fn fires_on_unlogged_setter() {
        let fs = run(UNSAFE);
        assert!(fired(&fs), "{:?}", fs);
    }

    #[test]
    fn silent_when_setter_emits() {
        let fs = run(SAFE_EMITS);
        assert!(!fired(&fs), "{:?}", fs);
    }

    // SILENT: a non-privileged user operation that writes a mapping entry (ordinary
    // per-key bookkeeping), not a config/role setter — must not fire.
    #[test]
    fn silent_on_user_mapping_write() {
        let src = r#"
            contract Pool {
                mapping(address => uint256) public balanceOf;
                function deposit(uint256 amt) external {
                    balanceOf[msg.sender] += amt;
                }
            }
        "#;
        let fs = run(src);
        assert!(!fired(&fs), "{:?}", fs);
    }

    // SILENT: a constructor that seeds privileged state (one-shot setup), even
    // without an event.
    #[test]
    fn silent_on_constructor() {
        let src = r#"
            contract C {
                address public owner;
                address public treasury;
                constructor(address t) { owner = msg.sender; treasury = t; }
            }
        "#;
        let fs = run(src);
        assert!(!fired(&fs), "{:?}", fs);
    }

    // SILENT: an emit nested inside an `if` still counts as logging the change.
    #[test]
    fn silent_when_emit_nested_in_if() {
        let src = r#"
            contract Vault {
                address public owner;
                uint256 public fee;
                event FeeSet(uint256 f);
                modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
                function setFee(uint256 f) external onlyOwner {
                    if (f != fee) {
                        fee = f;
                        emit FeeSet(f);
                    }
                }
            }
        "#;
        let fs = run(src);
        assert!(!fired(&fs), "{:?}", fs);
    }

    // FIRES (Arm B): a role-mutating function that does NOT start with `set`
    // (`acceptOwnership` reassigning `owner`), access-controlled, no event.
    #[test]
    fn fires_on_unnamed_role_writer() {
        let src = r#"
            contract C {
                address public owner;
                address public pendingOwner;
                modifier onlyPending() { require(msg.sender == pendingOwner, "no"); _; }
                function acceptOwnership() external onlyPending {
                    owner = pendingOwner;
                }
            }
        "#;
        let fs = run(src);
        assert!(fired(&fs), "{:?}", fs);
    }
}
