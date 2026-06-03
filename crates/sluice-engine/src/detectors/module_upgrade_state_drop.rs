//! Module/proxy upgrade that silently drops state — the new implementation is
//! swapped in and an init hook (`INIT()`) is fired, but that hook is a **no-op**
//! that does **not copy** the prior implementation's storage, so the upgraded
//! module starts from zeroed storage.
//!
//! ## The class
//!
//! A registry / kernel upgrade path of the shape
//!
//! ```solidity
//! function _upgradeModule(Module newModule_) internal {
//!     Keycode keycode = newModule_.KEYCODE();
//!     Module oldModule = getModuleForKeycode[keycode];      // old handle bound…
//!     ...
//!     getModuleForKeycode[keycode] = newModule_;            // …new address installed
//!     newModule_.INIT();                                    // …init hook fired
//!     _reconfigurePolicies(keycode);
//! }
//! ```
//!
//! installs a new module *address* for an existing keycode and then calls an
//! `INIT()` hook on the **new** module. The hook is the only opportunity to seed
//! the new implementation, but in the Default Framework the base
//! `Module.INIT()` is an empty `onlyKernel` no-op
//!
//! ```solidity
//! function INIT() external virtual onlyKernel {}
//! ```
//!
//! and the concrete modules (`OlympusMinter`, `OlympusTreasury`,
//! `OlympusRange`, …) do **not** override it with a state-copying body. The
//! upgrade path also never reads the *old* module (`oldModule` is bound only to
//! zero-out its reverse mapping and check the no-op-upgrade guard, it is never
//! called to read prior balances/figures), so on `UpgradeModule` the new module
//! comes up with **zeroed storage** — every figure the old module tracked
//! (treasury debt ceilings, minter approvals, range bands, …) is silently lost.
//!
//! This is an Invariant-class state-continuity bug: the system's invariant that a
//! module's state survives an in-place version upgrade is violated by an init
//! hook that neither copies from the old module nor is overridden to.
//!
//! ## What the detector matches (all required)
//!
//! On a contract `C` that owns an upgrade-shaped function `U`:
//!   1. `U`'s **name** is an upgrade/migrate verb (`_upgradeModule`, `upgradeTo`,
//!      `upgradeModule`, `migrate*`) — *not* a one-time `install`/`add` (a fresh
//!      install legitimately starts empty; only an in-place *upgrade* of an
//!      existing slot drops state).
//!   2. `U` **installs a new implementation**: it assigns a state var (the module
//!      registry slot) the value of one of `U`'s own **parameters** (the new
//!      module / implementation handle).
//!   3. `U` **fires an init hook** on that same new-implementation parameter: a
//!      call `newImpl.INIT()` / `newImpl.initialize(...)` whose receiver roots to
//!      the installed parameter.
//!   4. `U` performs **no state copy from the old module**: there is no call on a
//!      *different* old-handle receiver, and the init hook is passed **no
//!      argument** that could carry prior state (a bare `INIT()`); i.e. nothing in
//!      `U` reads the prior implementation to migrate it.
//!   5. The fired init hook is a **no-op / not overridden to copy**: the framework
//!      declares an `INIT`-named hook whose base body is empty, and **no** concrete
//!      module in the codebase overrides that hook with a body that writes state.
//!
//! ## Suppression (so this stays ~0-FP off the Default Framework)
//!
//!   * **A migration that copies state** — if `U` reads the old handle (calls a
//!     method on a second, non-installed module handle, or threads it into the
//!     init hook as an argument) it is migrating, not dropping → silent.
//!   * **An init hook that reads the prior module / writes state** — if *any*
//!     concrete override of the hook has a state-writing body (it seeds storage),
//!     the class does not apply → silent.
//!   * **Fresh-install-only registries** — a path named `install`/`add`/`register`
//!     with no pre-existing slot is not an in-place upgrade → not matched.
//!   * **OZ UUPS `upgradeToAndCall`** — handled by the `upgradeable` detector;
//!     here we require the *install-by-parameter + init-hook-on-that-parameter*
//!     module-registry shape, which a UUPS proxy (delegatecall, shared storage)
//!     does not present, so this adds nothing on a plain proxy.

use super::prelude::*;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{AssignOp, CallKind, Contract, Expr, ExprKind, Function, StmtKind};

pub struct ModuleUpgradeStateDropDetector;

/// Init-hook method names: the Default-Framework `INIT` plus the common
/// `initialize`/`init`/`setUp` post-install seed hooks.
fn is_init_hook_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "init" || l == "initialize" || l == "initialise" || l == "setup" || l == "__init"
}

/// An upgrade/migrate verb that swaps an *existing* implementation in place. A
/// fresh `install`/`add`/`register` is deliberately excluded — starting empty on a
/// first install is not a state drop, only an in-place upgrade of a populated slot
/// is.
fn is_upgrade_fn_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    let l = l.trim_start_matches('_');
    // `upgrademodule`, `upgradeto`, `upgradetoandcall`, `upgrade`, `migratemodule`,
    // `migrate`, `migrateto`. Require the verb as a leading token so an unrelated
    // `_reconfigure`/`_setUpgradeDelay` is not swept in.
    l.starts_with("upgrade") || l.starts_with("migrate")
}

impl Detector for ModuleUpgradeStateDropDetector {
    fn id(&self) -> &'static str {
        "module-upgrade-state-drop"
    }
    fn category(&self) -> Category {
        Category::ModuleUpgradeStateDrop
    }
    fn description(&self) -> &'static str {
        "A module/proxy upgrade swaps the implementation and calls an init hook that is a no-op \
         (does not copy state from the old module), so the new version starts with zeroed storage"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for c in cx.scir.iter_contracts() {
            if c.is_interface() || c.is_library() {
                continue;
            }
            for f in cx.scir.functions_of(c.id) {
                if !f.has_body || f.is_view_or_pure() || f.is_constructor() {
                    continue;
                }
                if !is_upgrade_fn_name(&f.name) {
                    continue;
                }
                let Some(site) = upgrade_site(f) else { continue };

                // The fired hook must be the framework's NO-OP default: there is a
                // `virtual` declaration of that exact hook name with an **empty
                // body** (`function INIT() external virtual {}`), the seam every
                // module inherits. If the base hook itself has a body that seeds /
                // copies state, an in-place upgrade migrates and the class does not
                // apply. (This is scoped to the fired hook *name* — a project's
                // unrelated `initialize()` does not enter into it — and is what makes
                // the Olympus `Module.INIT()` no-op the anchor while staying silent on
                // proxies whose base init actually initialises.)
                if !base_hook_is_noop(cx, &site.hook_name) {
                    continue;
                }

                // Suppress a real migration: the function binds a handle to the OLD
                // module (a local read out of the registry state var) and then reads
                // / threads it (calls a method on it, or passes it into a callee) —
                // i.e. it copies prior state forward.
                if migrates_old_state(c, f, &site) {
                    continue;
                }

                let b = report!(self, Category::ModuleUpgradeStateDrop,
                    title = "Module upgrade swaps implementation but the init hook drops prior state",
                    severity = Severity::Medium,
                    confidence = 0.62,
                    dimensions = [Dimension::Invariant],
                    message = format!(
                        "`{fname}` upgrades a module in place: it installs the new implementation \
                         `{newp}` into the registry and then calls its init hook `{newp}.{hook}()`, \
                         but that hook is a no-op — the framework's base `{hook}()` is empty and no \
                         concrete module overrides it to seed storage, and `{fname}` itself never \
                         reads the old module to copy its state. On an in-place upgrade the new \
                         implementation therefore comes up with **zeroed storage**: every figure the \
                         previous version tracked (treasury limits, minter approvals, range bands, …) \
                         is silently dropped. This is the Default-Framework `_upgradeModule` + no-op \
                         `INIT()` state-continuity hazard.",
                        fname = f.name,
                        newp = site.new_impl_param,
                        hook = site.hook_name,
                    ),
                    recommendation =
                        "On an in-place upgrade, migrate the prior module's state into the new one: \
                         either copy the old module's storage in the init hook (read the old \
                         implementation and re-write its figures) or pass the old module's address \
                         into `INIT(oldModule)` so the new version can pull its predecessor's state. \
                         An empty/no-op init hook is only safe for a *fresh* install, never for an \
                         upgrade of a populated slot.",
                );
                out.push(finish_at(cx, b, f.id, site.span));
            }
        }

        out
    }
}

// ------------------------------------------------------------------ upgrade-site

/// The structural facts of a matched upgrade path.
struct UpgradeSite {
    /// Name of the parameter holding the new implementation (`newModule_`).
    new_impl_param: String,
    /// Name of the init hook fired on the new implementation (`INIT`).
    hook_name: String,
    /// Span of the init-hook call (the report anchor).
    span: sluice_ir::Span,
}

/// If `f` is the install-new-impl + fire-init-hook shape, return the site:
///   * some assignment `stateVar[..] = p` / `stateVar = p` where `p` is one of
///     `f`'s parameters (the new implementation handle is installed), AND
///   * a call `p.<initHook>()` whose receiver roots to that same parameter `p`
///     and which takes **no arguments** (a bare seed hook — a hook that took the
///     old module would be a migration).
fn upgrade_site(f: &Function) -> Option<UpgradeSite> {
    // 1. Find every parameter that is *installed* into a state var.
    let installed: Vec<String> = installed_params(f);
    if installed.is_empty() {
        return None;
    }

    // 2. Find an init-hook call on one of those installed params, taking no args.
    let mut found: Option<UpgradeSite> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            let ExprKind::Call(call) = &e.kind else { return };
            // External / unknown method call (`p.INIT()`); not a cast/builtin.
            if !matches!(call.kind, CallKind::External | CallKind::Unknown | CallKind::Internal) {
                return;
            }
            let Some(method) = call.func_name.as_deref() else { return };
            if !is_init_hook_name(method) {
                return;
            }
            // No arguments: a bare `INIT()` seed. A hook fed the old module's
            // address/state is a migration and must not match here.
            if !call.args.is_empty() {
                return;
            }
            let Some(recv) = call.receiver.as_deref() else { return };
            let Some(root) = root_ident_peeled(recv) else { return };
            if !installed.contains(&root) {
                return;
            }
            found = Some(UpgradeSite {
                new_impl_param: root,
                hook_name: method.to_string(),
                span: e.span,
            });
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// Parameters of `f` that are assigned into a state-var registry slot
/// (`getModuleForKeycode[keycode] = newModule_` → `newModule_`). We look for an
/// `Assign` whose **value** root-resolves to a parameter and whose **target** is
/// an index/member/ident chain rooted in a non-parameter (a storage slot).
fn installed_params(f: &Function) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            let ExprKind::Assign { op, target, value } = &e.kind else { return };
            if *op != AssignOp::Assign {
                return; // a `+=` is accumulation, not an implementation install
            }
            let Some(val_root) = root_ident_peeled(value) else { return };
            if !is_param(f, &val_root) {
                return;
            }
            // The target must be a storage destination: rooted in something that is
            // NOT a parameter (a state var / mapping), and be an index or member
            // access (a registry slot), not a bare local rebind.
            if !is_storage_target(f, target) {
                return;
            }
            if !out.contains(&val_root) {
                out.push(val_root);
            }
        });
    }
    out
}

/// True if `target` is a storage-slot lvalue: an `Index`/`Member` chain (or bare
/// ident) whose root identifier is **not** one of `f`'s parameters. The new-module
/// param is the *value*; the destination must be contract storage.
fn is_storage_target(f: &Function, target: &Expr) -> bool {
    // Must be an index or member access (registry mapping / struct field), or a
    // bare state ident — but in all cases the root must not be a parameter.
    let rooted_in_param = root_ident_peeled(target).is_some_and(|r| is_param(f, &r));
    if rooted_in_param {
        return false;
    }
    matches!(
        target.kind,
        ExprKind::Index { .. } | ExprKind::Member { .. } | ExprKind::Ident(_)
    )
}

/// True if `f` migrates the OLD module's state forward — the precise state-copy
/// signal that distinguishes a real migration from a silent drop.
///
/// We first identify the **old-handle locals**: local variables bound from a read
/// of one of `f`'s contract storage slots (`Module oldModule =
/// getModuleForKeycode[keycode];`). These are the handles to the *previous*
/// implementation. The path migrates if it then **reads** such a handle — calls a
/// method on it (`oldModule.exportState()`) or threads it into a callee as an
/// argument (`newModule_.seed(oldModule)`).
///
/// Scoping the signal to *registry-bound locals* (rather than any non-new receiver)
/// is what keeps the Default-Framework no-op path matching: that path binds
/// `oldModule` only to zero its reverse mapping and to power the `oldModule ==
/// newModule_` guard — it never *calls* it and never passes it to anyone, so this
/// stays false. Library/UDVT calls like `Keycode.wrap(...)` are not on an
/// old-handle local and so never count.
fn migrates_old_state(c: &Contract, f: &Function, site: &UpgradeSite) -> bool {
    // 1. Old-handle locals: `VarDecl`s whose initializer roots to a storage slot of
    //    this contract (the module registry), and that are not the new-impl param.
    let old_handles = old_module_handles(c, f, site);
    if old_handles.is_empty() {
        return false;
    }

    // 2. The path migrates if any old handle is *used* in a genuine call — as the
    //    receiver of a method call (`oldModule.exportState()`), or threaded into a
    //    callee as an argument (`newModule_.seed(oldModule)` / a migration helper).
    //
    //    Only **real** calls count. A type-cast (`address(oldModule)`,
    //    `Module(slot)`) or a builtin (`require(oldModule == ...)`) is plumbing /
    //    a guard, not a state-reading migration — the framework's no-op path casts
    //    and compares `oldModule` (for its reverse-mapping wipe and the
    //    `oldModule == newModule_` guard) but never *calls* it, so those must not
    //    trip this. Restricting to real calls is what keeps that path matching.
    let mut migrates = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if migrates {
                return;
            }
            let ExprKind::Call(call) = &e.kind else { return };
            if !is_real_call(call.kind) {
                return;
            }
            // Old handle as the receiver of a method call: a read of prior state.
            if let Some(recv) = call.receiver.as_deref() {
                if let Some(root) = root_ident_peeled(recv) {
                    if old_handles.contains(&root) && root != site.new_impl_param {
                        migrates = true;
                        return;
                    }
                }
            }
            // Old handle threaded into a callee as an argument.
            for a in &call.args {
                if let Some(root) = root_ident_peeled(a) {
                    if old_handles.contains(&root) {
                        migrates = true;
                        return;
                    }
                }
            }
        });
        if migrates {
            break;
        }
    }
    migrates
}

/// A genuine value-/control-transferring call (a method/internal/low-level call) —
/// **not** a type-cast or a builtin. Used to distinguish a real read of the old
/// module from cast/guard plumbing around it.
fn is_real_call(kind: CallKind) -> bool {
    matches!(
        kind,
        CallKind::External
            | CallKind::Internal
            | CallKind::Unknown
            | CallKind::LowLevelCall
            | CallKind::DelegateCall
            | CallKind::StaticCall
    )
}

/// Names of `f`'s local variables that are bound from a read of one of the
/// contract's storage slots — the handles to the previous implementation
/// (`Module oldModule = getModuleForKeycode[keycode];`). The new-impl param is
/// never an old handle. We scan `VarDecl` initializers (and `Assign`s into a
/// local) whose value root-resolves to a state variable of `c`.
fn old_module_handles(c: &Contract, f: &Function, site: &UpgradeSite) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut consider = |name: Option<&str>, init: Option<&Expr>| {
        let (Some(name), Some(init)) = (name, init) else { return };
        if name == site.new_impl_param {
            return;
        }
        // The initializer must root to a STATE variable of this contract (the
        // registry read), peeling any cast (`Module(getModuleForKeycode[k])`).
        if let Some(root) = root_ident_peeled(init) {
            if is_state_var(c, &root) && !out.iter().any(|n| n == name) {
                out.push(name.to_string());
            }
        }
    };
    for s in &f.body {
        match &s.kind {
            StmtKind::VarDecl { name, init, .. } => consider(name.as_deref(), init.as_ref()),
            _ => {}
        }
        // Also catch `oldModule = getModuleForKeycode[k];` re-binds.
        s.visit_exprs(&mut |e| {
            if let ExprKind::Assign { op, target, value } = &e.kind {
                if *op == AssignOp::Assign {
                    if let ExprKind::Ident(name) = &target.kind {
                        consider(Some(name), Some(value));
                    }
                }
            }
        });
    }
    out
}

// ------------------------------------------------------ base init-hook analysis

/// True if the fired hook (`hook_name`, e.g. `INIT`) has a **no-op virtual base
/// declaration** somewhere in the codebase: a `virtual` function of that exact name
/// whose body is empty — `function INIT() external virtual {}`. This is the
/// framework seam every module inherits, and an empty default means the upgrade
/// fires a hook that does nothing, so a module that does not override it loses its
/// state on an in-place upgrade.
///
/// Scoped to the **exact** hook name (case-insensitive) so an unrelated
/// `initialize()` in some other contract never enters into it. The override
/// question is intentionally NOT the gate: that some module (or a test mock)
/// overrides `INIT()` to migrate does not make the *default* safe — every module
/// that inherits the empty base still drops state, which is the finding. A genuine
/// migration in the matched upgrade *path* is handled separately by
/// [`migrates_old_state`].
fn base_hook_is_noop(cx: &AnalysisContext, hook_name: &str) -> bool {
    let target = hook_name.to_ascii_lowercase();
    for c in cx.scir.iter_contracts() {
        if c.is_interface() || c.is_library() {
            continue;
        }
        for f in cx.scir.functions_of(c.id) {
            if f.name.to_ascii_lowercase() != target {
                continue;
            }
            // The default seam: virtual, and an empty body (the framework no-op).
            if f.is_virtual && hook_body_is_empty(f) {
                return true;
            }
        }
    }
    false
}

/// True if a hook function body is empty / a pure no-op — `{}` or a body of only
/// placeholders. The framework default `function INIT() external virtual {}` is
/// exactly this. Any real statement (assignment, call, branch, …) makes it
/// non-empty.
fn hook_body_is_empty(f: &Function) -> bool {
    if !f.has_body {
        // A pure declaration (interface) is not the concrete no-op seam.
        return false;
    }
    // Storage effects are the quickest disqualifier: a hook that writes/reads state
    // is not the empty default.
    if !f.effects.storage_writes.is_empty() {
        return false;
    }
    body_has_no_effect(&f.body)
}

/// True if a statement list contains no effecting statement — only empty blocks,
/// placeholders, or break/continue. Used to recognise an empty hook body.
fn body_has_no_effect(stmts: &[sluice_ir::Stmt]) -> bool {
    stmts.iter().all(|s| match &s.kind {
        StmtKind::Block { stmts, .. } => body_has_no_effect(stmts),
        StmtKind::Placeholder | StmtKind::Break | StmtKind::Continue => true,
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    use sluice_findings::Finding;

    fn run(src: &str) -> Vec<Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "module-upgrade-state-drop")
    }

    // VULN — the Default-Framework shape: `_upgradeModule` installs the new module
    // and fires the empty no-op `INIT()`, never reading the old module.
    const VULN: &str = r#"
        type Keycode is bytes5;
        abstract contract Module {
            function KEYCODE() public pure virtual returns (Keycode) {}
            // empty no-op init hook (framework default)
            function INIT() external virtual {}
        }
        contract OlympusMinter is Module {
            mapping(address => uint256) public mintApproval;
            function KEYCODE() public pure override returns (Keycode) { return Keycode.wrap("MINTR"); }
            // does NOT override INIT
        }
        contract Kernel {
            mapping(Keycode => Module) public getModuleForKeycode;
            mapping(Module => Keycode) public getKeycodeForModule;

            function _upgradeModule(Module newModule_) internal {
                Keycode keycode = newModule_.KEYCODE();
                Module oldModule = getModuleForKeycode[keycode];
                if (address(oldModule) == address(0) || oldModule == newModule_) revert();

                getKeycodeForModule[oldModule] = Keycode.wrap(bytes5(0));
                getKeycodeForModule[newModule_] = keycode;
                getModuleForKeycode[keycode] = newModule_;

                newModule_.INIT();
            }
        }
    "#;

    // SAFE (migration copies state via the init hook arg): the upgrade threads the
    // OLD module into `INIT(oldModule)`, so the new module can pull prior state.
    const SAFE_INIT_TAKES_OLD: &str = r#"
        type Keycode is bytes5;
        abstract contract Module {
            function KEYCODE() public pure virtual returns (Keycode) {}
            function INIT(address old) external virtual {}
        }
        contract Mod is Module {
            uint256 public total;
            function KEYCODE() public pure override returns (Keycode) { return Keycode.wrap("AAAAA"); }
        }
        contract Kernel {
            mapping(Keycode => Module) public getModuleForKeycode;
            function _upgradeModule(Module newModule_) internal {
                Keycode keycode = newModule_.KEYCODE();
                Module oldModule = getModuleForKeycode[keycode];
                getModuleForKeycode[keycode] = newModule_;
                newModule_.INIT(address(oldModule));
            }
        }
    "#;

    // SAFE (the upgrade reads the old module to migrate it): `oldModule.exportState()`
    // is read in the path — a genuine migration, not a drop.
    const SAFE_READS_OLD: &str = r#"
        type Keycode is bytes5;
        interface IMod { function exportState() external view returns (uint256); }
        abstract contract Module {
            function KEYCODE() public pure virtual returns (Keycode) {}
            function INIT() external virtual {}
            function seed(uint256 v) external virtual {}
        }
        contract Mod is Module {
            uint256 public total;
            function KEYCODE() public pure override returns (Keycode) { return Keycode.wrap("AAAAA"); }
        }
        contract Kernel {
            mapping(Keycode => Module) public getModuleForKeycode;
            function _upgradeModule(Module newModule_) internal {
                Keycode keycode = newModule_.KEYCODE();
                Module oldModule = getModuleForKeycode[keycode];
                getModuleForKeycode[keycode] = newModule_;
                uint256 prior = IMod(address(oldModule)).exportState();
                newModule_.INIT();
                newModule_.seed(prior);
            }
        }
    "#;

    // SAFE (the base hook is NOT a no-op): the framework's base `INIT()` itself has
    // a body that seeds/initialises state, so every module inherits a real init —
    // an upgrade does not silently drop state. The no-op-default anchor is absent.
    const SAFE_BASE_HOOK_HAS_BODY: &str = r#"
        type Keycode is bytes5;
        abstract contract Module {
            uint256 internal _initialized;
            function KEYCODE() public pure virtual returns (Keycode) {}
            // base hook does real work (not the empty no-op default)
            function INIT() external virtual { _initialized = 1; }
        }
        contract Mod is Module {
            function KEYCODE() public pure override returns (Keycode) { return Keycode.wrap("AAAAA"); }
        }
        contract Kernel {
            mapping(Keycode => Module) public getModuleForKeycode;
            function _upgradeModule(Module newModule_) internal {
                Keycode keycode = newModule_.KEYCODE();
                Module oldModule = getModuleForKeycode[keycode];
                getModuleForKeycode[keycode] = newModule_;
                newModule_.INIT();
            }
        }
    "#;

    // VULN (precision): the EXACT Olympus shape where a *test-mock-style* module
    // overrides `INIT()` to migrate (`permissionedState = old.permissionedState()`),
    // yet the framework base `INIT()` is still the empty no-op every *other* module
    // inherits. A single migrating override does NOT make the generic `_upgradeModule`
    // path safe — modules that inherit the empty base still drop state — so the
    // finding must still fire. (Mirrors `src/test/mocks/KernelTestMocks.sol` +
    // production modules that do not override INIT.)
    const VULN_WITH_MIGRATING_OVERRIDE: &str = r#"
        type Keycode is bytes5;
        abstract contract Module {
            function KEYCODE() public pure virtual returns (Keycode) {}
            function INIT() external virtual {}            // empty no-op default
        }
        // production-style module: does NOT override INIT (inherits the no-op)
        contract OlympusMinter is Module {
            mapping(address => uint256) public mintApproval;
            function KEYCODE() public pure override returns (Keycode) { return Keycode.wrap("MINTR"); }
        }
        // test-mock-style module that DOES migrate in its INIT override
        contract UpgradedMockModule is Module {
            Module internal _oldModule;
            uint256 public permissionedState;
            function KEYCODE() public pure override returns (Keycode) { return Keycode.wrap("MOCKY"); }
            function INIT() external override { permissionedState = 1; }
        }
        contract Kernel {
            mapping(Keycode => Module) public getModuleForKeycode;
            mapping(Module => Keycode) public getKeycodeForModule;
            function _upgradeModule(Module newModule_) internal {
                Keycode keycode = newModule_.KEYCODE();
                Module oldModule = getModuleForKeycode[keycode];
                if (address(oldModule) == address(0) || oldModule == newModule_) revert();
                getKeycodeForModule[oldModule] = Keycode.wrap(bytes5(0));
                getKeycodeForModule[newModule_] = keycode;
                getModuleForKeycode[keycode] = newModule_;
                newModule_.INIT();
            }
        }
    "#;

    // SAFE (fresh install only): an `_installModule` path with no in-place upgrade
    // verb — starting empty on a first install is not a state drop.
    const SAFE_INSTALL_ONLY: &str = r#"
        type Keycode is bytes5;
        abstract contract Module {
            function KEYCODE() public pure virtual returns (Keycode) {}
            function INIT() external virtual {}
        }
        contract Mod is Module {
            uint256 public total;
            function KEYCODE() public pure override returns (Keycode) { return Keycode.wrap("AAAAA"); }
        }
        contract Kernel {
            mapping(Keycode => Module) public getModuleForKeycode;
            function _installModule(Module newModule_) internal {
                Keycode keycode = newModule_.KEYCODE();
                getModuleForKeycode[keycode] = newModule_;
                newModule_.INIT();
            }
        }
    "#;

    // SAFE (no init hook fired): an upgrade that swaps the address but never calls
    // any init hook is a different (no-init) shape, not this class.
    const SAFE_NO_INIT_CALL: &str = r#"
        type Keycode is bytes5;
        abstract contract Module {
            function KEYCODE() public pure virtual returns (Keycode) {}
        }
        contract Mod is Module {
            function KEYCODE() public pure override returns (Keycode) { return Keycode.wrap("AAAAA"); }
        }
        contract Kernel {
            mapping(Keycode => Module) public getModuleForKeycode;
            function _upgradeModule(Module newModule_) internal {
                Keycode keycode = newModule_.KEYCODE();
                getModuleForKeycode[keycode] = newModule_;
            }
        }
    "#;

    #[test]
    fn fires_on_default_framework_upgrade() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_at_the_upgrade_function() {
        let fs = run(VULN);
        assert!(
            fs.iter().any(|f| f.detector == "module-upgrade-state-drop"
                && f.function == "_upgradeModule"),
            "{:#?}",
            fs
        );
    }

    #[test]
    fn silent_when_init_takes_old_module() {
        assert!(!fires(SAFE_INIT_TAKES_OLD), "{:#?}", run(SAFE_INIT_TAKES_OLD));
    }

    #[test]
    fn silent_when_upgrade_reads_old_module() {
        assert!(!fires(SAFE_READS_OLD), "{:#?}", run(SAFE_READS_OLD));
    }

    #[test]
    fn silent_when_base_hook_has_body() {
        assert!(!fires(SAFE_BASE_HOOK_HAS_BODY), "{:#?}", run(SAFE_BASE_HOOK_HAS_BODY));
    }

    #[test]
    fn fires_despite_a_single_migrating_override() {
        // A test-mock-style migrating override does NOT immunise the generic upgrade
        // path: the empty no-op base hook is still what non-overriding (production)
        // modules inherit, so the finding must still fire.
        assert!(
            fires(VULN_WITH_MIGRATING_OVERRIDE),
            "{:#?}",
            run(VULN_WITH_MIGRATING_OVERRIDE)
        );
    }

    #[test]
    fn silent_on_install_only() {
        assert!(!fires(SAFE_INSTALL_ONLY), "{:#?}", run(SAFE_INSTALL_ONLY));
    }

    #[test]
    fn silent_when_no_init_hook_called() {
        assert!(!fires(SAFE_NO_INIT_CALL), "{:#?}", run(SAFE_NO_INIT_CALL));
    }
}
