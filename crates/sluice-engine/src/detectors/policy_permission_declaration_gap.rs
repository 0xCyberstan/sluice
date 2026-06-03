//! Policy / module two-table permission-contract gap (Default Framework).
//!
//! The Default Framework (Olympus V3 "Bophades", and any fork of it) splits a
//! module function's authorization across **two tables that must agree**:
//!
//!   1. On the **module** side, a state-mutating function is gated by the
//!      `permissioned` modifier. That modifier consults the Kernel:
//!      `kernel.modulePermissions(KEYCODE(), Policy(msg.sender), msg.sig)` — i.e.
//!      the call only succeeds if the Kernel has *granted* this exact
//!      `(keycode, policy, selector)` triple.
//!
//!   2. On the **policy** side, the grant table is populated from the policy's
//!      own `requestPermissions()` return array. When governance activates the
//!      policy, the Kernel walks that array and sets
//!      `modulePermissions[keycode][policy][selector] = true` for each entry.
//!
//! So `requestPermissions()` is the *single source of truth* for which module
//! selectors the policy is allowed to invoke at run time. If the two tables
//! disagree, one of two bugs results:
//!
//!   * **Called-but-undeclared (`C \ D`)** — the policy's code calls a module
//!     `permissioned` selector that it never lists in `requestPermissions()`.
//!     The Kernel never grants that triple, so the `permissioned` modifier
//!     reverts (`Module_PolicyNotPermitted`) **every time** that code path runs.
//!     This is a guaranteed, unconditional **denial of service** of that policy
//!     function in production — the call can never succeed. Reported **High**.
//!
//!   * **Declared-but-uncalled (`D \ C`)** — the policy lists a `permissioned`
//!     selector in `requestPermissions()` that its code never calls. The Kernel
//!     grants the policy standing authority over a module mutator it does not
//!     use: an unnecessary, latent **over-grant** that widens the blast radius
//!     of a policy compromise (a bug elsewhere in the policy, or a future code
//!     path, can now reach a privileged module function the audit did not expect
//!     it to). Reported **Low** (least-privilege hygiene).
//!
//! ## Algorithm
//!
//! For each concrete contract that *is a Policy* (transitively inherits `Policy`)
//! and has a `requestPermissions()` body:
//!
//!   (a) **D — declared set.** Walk `requestPermissions()` and collect every
//!       `X.fn.selector` member chain (the second field of each
//!       `Permissions(KEYCODE, X.fn.selector)` / `Permissions({funcSelector:
//!       X.fn.selector})` construction). `X` is canonicalized to the underlying
//!       **module type** (a module-typed state var resolves to its declared
//!       type; a bare module-type name — the `TRSRYv1.withdrawReserves.selector`
//!       idiom — resolves to itself). Keep only entries whose `fn` actually
//!       carries `permissioned` on that module.
//!
//!   (b) **C — called set.** Across the policy's functions, collect every
//!       external call `recv.fn(args)` where `recv` is a **module-typed** state
//!       var (its type transitively inherits `Module`, or it is assigned in
//!       `configureDependencies()` from `getModuleAddress(...)`) **and** `fn`
//!       carries the `permissioned` modifier on that module. Both sides are keyed
//!       on `(module type, selector)`.
//!
//!   (c) Flag `C \ D` **High** (the undeclared call DoS) and `D \ C` **Low** (the
//!       over-grant).
//!
//! ## Precision (single Invariant dimension)
//!
//!   * **The `permissioned` gate is the FP killer.** A call/declaration only
//!     enters `C`/`D` if the callee carries the module `permissioned` modifier.
//!     This automatically excludes plain view getters (`VERSION`, `KEYCODE`,
//!     `getReserveBalance`, `decimals`, …), the `INIT` / `changeKernel` /
//!     `configureDependencies` lifecycle hooks (none are `permissioned`), and
//!     any call whose receiver is a non-module type (an ERC20/ERC4626 token, a
//!     local, `this`) — even when an unrelated module happens to own a
//!     `permissioned` function of the same name (e.g. `VOTES.transfer` vs an
//!     ERC4626 `transfer`).
//!   * **Module-type resolution through the abstract/concrete split.** The
//!     `permissioned` modifier lives on the *concrete* module (`OlympusTreasury`)
//!     while the policy's state var is typed as the *abstract* module
//!     (`TRSRYv1 internal TRSRY`). We resolve a module type to its concrete
//!     implementation(s) and check the modifier on either.
//!   * **Non-Default-Framework code is silent by construction.** A codebase with
//!     no `requestPermissions()` *and* no `permissioned` modifier produces no
//!     `D` and no `C`, so the detector never fires there.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use super::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{Contract, ContractKind, Expr, ExprKind, Function, Scir, Span};

pub struct PolicyPermissionDeclarationGapDetector;

/// The base contract name a Default-Framework module inherits.
const MODULE_BASE: &str = "Module";
/// The base contract name a Default-Framework policy inherits.
const POLICY_BASE: &str = "Policy";
/// The module-side authorization modifier whose presence makes a selector a
/// permissioned (grant-gated) function.
const PERMISSIONED_MODIFIER: &str = "permissioned";
/// Lifecycle / framework selectors that are never the subject of a grant even if
/// they were somehow `permissioned`; belt-and-suspenders alongside the modifier
/// gate (which already excludes them, since none carry `permissioned`).
const LIFECYCLE_SELECTORS: &[&str] = &["INIT", "changeKernel", "configureDependencies"];

/// A `(module type, selector)` permission key — canonical across both tables.
type PermKey = (String, String);

impl Detector for PolicyPermissionDeclarationGapDetector {
    fn id(&self) -> &'static str {
        "policy-permission-declaration-gap"
    }
    fn category(&self) -> Category {
        Category::PolicyPermissionDeclarationGap
    }
    fn description(&self) -> &'static str {
        "A Default-Framework Policy calls a module `permissioned` selector it never lists in \
         `requestPermissions()` (called-but-undeclared = guaranteed revert / DoS), or declares a \
         permissioned selector it never calls (over-grant)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let scir = cx.scir;
        let mut out = Vec::new();

        // Name -> contract index (last-declared-wins, matching the module's own
        // `contract_named`). Used to walk inheritance chains by name.
        let by_name: FxHashMap<&str, &Contract> =
            scir.iter_contracts().map(|c| (c.name.as_str(), c)).collect();

        // Module concrete-implementation index: for every concrete contract that
        // transitively inherits `Module`, register it under every ancestor name in
        // its chain. So `impls_of["TRSRYv1"]` includes `OlympusTreasury`, letting
        // us find the `permissioned` modifier that lives on the concrete override
        // even when the policy's state var is typed as the abstract module.
        let mut impls_of: FxHashMap<&str, Vec<&Contract>> = FxHashMap::default();
        for c in scir.iter_contracts() {
            if matches!(c.kind, ContractKind::Contract) && inherits_base(&by_name, &c.name, MODULE_BASE) {
                for anc in chain_names(&by_name, &c.name) {
                    impls_of.entry(anc).or_default().push(c);
                }
            }
        }

        let resolver = ModuleResolver { scir, by_name: &by_name, impls_of: &impls_of };

        for policy in scir.iter_contracts() {
            // Only concrete Policy contracts host a real grant contract; abstract
            // bases / interfaces / libraries are skipped.
            if !matches!(policy.kind, ContractKind::Contract) {
                continue;
            }
            if !inherits_base(&by_name, &policy.name, POLICY_BASE) {
                continue;
            }
            // The policy must declare its own `requestPermissions()` body (the
            // grant source of truth). The empty `virtual` base declaration has no
            // body and is skipped.
            let Some(req) = scir
                .functions_of(policy.id)
                .into_iter()
                .find(|f| f.name == "requestPermissions" && f.has_body)
            else {
                continue;
            };

            // Map every state var name visible to the policy (own + inherited) to
            // its declared type, so a call/declaration receiver can be resolved to
            // a module type.
            let var_ty = visible_state_var_types(&by_name, policy);

            // The set of state-var names assigned from `getModuleAddress(...)` in
            // `configureDependencies()` — the framework's "this var IS a kernel
            // module" signal, used as a robustness fallback when the declared type
            // is not itself resolvable as a `Module` subclass.
            let module_vars = module_vars_from_configure(scir, policy);

            // Canonicalize a receiver/decl root token to its module type name.
            let canon = |root: &str| -> Option<String> {
                if let Some(ty) = var_ty.get(root) {
                    if inherits_base(&by_name, ty, MODULE_BASE) {
                        return Some(ty.clone());
                    }
                    // Fallback: the var is a confirmed kernel module (assigned from
                    // getModuleAddress) even though we could not statically tie its
                    // type to `Module` (e.g. the type is an out-of-scope interface).
                    if module_vars.contains(root) {
                        return Some(ty.clone());
                    }
                }
                // The `TypeName.fn.selector` declaration idiom: the root is itself a
                // module type.
                if inherits_base(&by_name, root, MODULE_BASE) {
                    return Some(root.to_string());
                }
                None
            };

            // ---- D: declared permission set, keyed on (module type, selector). ----
            let mut declared: FxHashMap<PermKey, Span> = FxHashMap::default();
            for s in &req.body {
                s.visit_exprs(&mut |e| {
                    if let Some((root, sel)) = selector_chain(e) {
                        if LIFECYCLE_SELECTORS.contains(&sel.as_str()) {
                            return;
                        }
                        if let Some(mty) = canon(&root) {
                            if resolver.is_permissioned(&mty, &sel) {
                                declared.entry((mty, sel)).or_insert(e.span);
                            }
                        }
                    }
                });
            }
            // Not a real two-table policy (no permissioned declarations) — nothing
            // to contrast. This also keeps non-Default-Framework code silent.
            if declared.is_empty() {
                continue;
            }

            // ---- C: called permissioned set, keyed on (module type, selector). ----
            // Map each called key to a representative call-site span (for High DoS
            // reporting at the offending call).
            let mut called: FxHashMap<PermKey, Span> = FxHashMap::default();
            for f in scir.functions_of(policy.id) {
                if !f.has_body {
                    continue;
                }
                collect_permissioned_calls(f, &canon, &resolver, &mut called);
            }

            // ---- C \ D: called but undeclared — guaranteed revert / DoS (High). ----
            let mut undeclared: Vec<(&PermKey, Span)> =
                called.iter().filter(|(k, _)| !declared.contains_key(*k)).map(|(k, s)| (k, *s)).collect();
            undeclared.sort_by(|a, b| a.0.cmp(b.0));
            for ((mty, sel), span) in undeclared {
                out.push(finish_at(
                    cx,
                    report!(self, Category::PolicyPermissionDeclarationGap,
                        title = "Policy calls a module permissioned function it never requests permission for (guaranteed revert / DoS)",
                        severity = Severity::High,
                        confidence = 0.85,
                        dimensions = [Dimension::Invariant],
                        message = format!(
                            "Policy `{policy}` calls the module function `{mty}.{sel}` — which carries the \
                             Default-Framework `permissioned` modifier — but `{sel}` is NOT listed in this \
                             policy's `requestPermissions()`. The `permissioned` modifier only succeeds when \
                             the Kernel has granted `modulePermissions[KEYCODE][policy][{sel}.selector]`, and \
                             that grant is populated *exclusively* from `requestPermissions()`. Because the \
                             selector is absent from the declaration array, the grant is never set, so this \
                             call reverts with `Module_PolicyNotPermitted` on **every** invocation in \
                             production — an unconditional denial of service of the code path that reaches it. \
                             This is the Default-Framework two-table permission-contract gap (the policy's \
                             call table and its `requestPermissions()` table disagree).",
                            policy = policy.name, mty = mty, sel = sel,
                        ),
                        recommendation = format!(
                            "Add `Permissions({mty_kc}, {mty}.{sel}.selector)` to `{policy}.requestPermissions()` \
                             so the Kernel grants the policy authority to call `{mty}.{sel}` — or, if the call is \
                             not actually needed, remove the `{sel}` call. The set of module `permissioned` \
                             selectors a policy invokes and the set it requests must be kept identical.",
                            policy = policy.name, mty = mty, sel = sel, mty_kc = "KEYCODE",
                        ),
                    ),
                    req.id,
                    span,
                ));
            }

            // ---- D \ C: declared but never called — least-privilege over-grant (Low). ----
            let mut overgrant: Vec<(&PermKey, Span)> =
                declared.iter().filter(|(k, _)| !called.contains_key(*k)).map(|(k, s)| (k, *s)).collect();
            overgrant.sort_by(|a, b| a.0.cmp(b.0));
            for ((mty, sel), span) in overgrant {
                out.push(finish_at(
                    cx,
                    report!(self, Category::PolicyPermissionDeclarationGap,
                        title = "Policy requests a module permission it never uses (least-privilege over-grant)",
                        severity = Severity::Low,
                        confidence = 0.7,
                        dimensions = [Dimension::Invariant],
                        message = format!(
                            "Policy `{policy}` lists `{mty}.{sel}` in `requestPermissions()`, so the Kernel grants \
                             it standing authority to call this module `permissioned` function — yet the policy's \
                             code never calls `{mty}.{sel}`. This is an unnecessary over-grant: the policy holds a \
                             privileged module capability it does not exercise, widening the blast radius of any \
                             policy compromise or future code path beyond what the audited call surface requires. \
                             (Contrast: the dangerous direction is calling an *undeclared* selector, which DoSes; \
                             this direction is an unused grant.)",
                            policy = policy.name, mty = mty, sel = sel,
                        ),
                        recommendation = format!(
                            "Remove `{mty}.{sel}.selector` from `{policy}.requestPermissions()` unless a code path \
                             that calls it is intended (and then add the call). Keep the requested-permission set \
                             minimal and exactly equal to the set of module `permissioned` selectors the policy \
                             actually invokes.",
                            policy = policy.name, mty = mty, sel = sel,
                        ),
                    ),
                    req.id,
                    span,
                ));
            }
        }

        out
    }
}

// --------------------------------------------------------------------- resolver

/// Resolves whether a `(module type, selector)` is a `permissioned` module
/// function, looking through the abstract→concrete module split.
struct ModuleResolver<'a> {
    scir: &'a Scir,
    by_name: &'a FxHashMap<&'a str, &'a Contract>,
    impls_of: &'a FxHashMap<&'a str, Vec<&'a Contract>>,
}

impl ModuleResolver<'_> {
    /// True if a function named `sel` carrying the `permissioned` modifier exists
    /// on module type `mty` — checked on `mty`'s own inheritance chain *and* on any
    /// concrete implementation of `mty` (where the modifier usually lives, since the
    /// abstract module declares the function `virtual` without it).
    fn is_permissioned(&self, mty: &str, sel: &str) -> bool {
        // The receiver type must actually be a Default-Framework module; a same-named
        // function on a non-module type (an ERC20 `transfer`) is not in scope.
        if !inherits_base(self.by_name, mty, MODULE_BASE) {
            return false;
        }
        if self.chain_has_permissioned(mty, sel) {
            return true;
        }
        if let Some(impls) = self.impls_of.get(mty) {
            for c in impls {
                if self.chain_has_permissioned(&c.name, sel) {
                    return true;
                }
            }
        }
        false
    }

    /// Does any contract in the inheritance chain rooted at `name` declare a
    /// function `sel` with the `permissioned` modifier?
    fn chain_has_permissioned(&self, name: &str, sel: &str) -> bool {
        for anc in chain_names(self.by_name, name) {
            if let Some(c) = self.by_name.get(anc) {
                for f in self.scir.functions_of(c.id) {
                    if f.name == sel
                        && f.modifiers.iter().any(|m| m.name == PERMISSIONED_MODIFIER)
                    {
                        return true;
                    }
                }
            }
        }
        false
    }
}

// ----------------------------------------------------------------- AST helpers

/// If `e` is an `X.fn.selector` member chain (the second field of a
/// `Permissions(...)` construction), return `(X_root_ident, fn)`. Matches both the
/// instance idiom (`RANGE.updateCapacity.selector`) and the type idiom
/// (`TRSRYv1.withdrawReserves.selector`).
fn selector_chain(e: &Expr) -> Option<(String, String)> {
    let ExprKind::Member { base, member } = &e.kind else { return None };
    if member != "selector" {
        return None;
    }
    let ExprKind::Member { base: inner, member: fname } = &base.kind else { return None };
    let root = root_ident_str(inner)?;
    Some((root.to_string(), fname.clone()))
}

/// Collect every permissioned module call `recv.fn(args)` in `f` into `out`, keyed
/// on `(module type, selector)` with the call-site span (first-seen kept).
fn collect_permissioned_calls(
    f: &Function,
    canon: &impl Fn(&str) -> Option<String>,
    resolver: &ModuleResolver,
    out: &mut FxHashMap<PermKey, Span>,
) {
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            let ExprKind::Call(call) = &e.kind else { return };
            if call.kind != sluice_ir::CallKind::External {
                return;
            }
            let (Some(recv), Some(fname)) = (&call.receiver, &call.func_name) else { return };
            // Receiver must be a bare identifier naming a module-typed state var.
            let ExprKind::Ident(rname) = &recv.kind else { return };
            if LIFECYCLE_SELECTORS.contains(&fname.as_str()) {
                return;
            }
            let Some(mty) = canon(rname) else { return };
            if resolver.is_permissioned(&mty, fname) {
                out.entry((mty, fname.clone())).or_insert(e.span);
            }
        });
    }
}

/// Every state-var name visible to `c` (its own declarations plus those of every
/// transitive base) mapped to its declared type. First (most-derived) wins.
fn visible_state_var_types(
    by_name: &FxHashMap<&str, &Contract>,
    c: &Contract,
) -> FxHashMap<String, String> {
    let mut m: FxHashMap<String, String> = FxHashMap::default();
    for anc in chain_names(by_name, &c.name) {
        if let Some(cc) = by_name.get(anc) {
            for v in &cc.state_vars {
                m.entry(v.name.clone()).or_insert_with(|| v.ty.trim().to_string());
            }
        }
    }
    m
}

/// State-var names that `c.configureDependencies()` assigns from a
/// `getModuleAddress(...)` call — the framework's authoritative "this var is a
/// kernel module" marker. Used as a fallback when a module var's declared type is
/// not statically resolvable to a `Module` subclass.
fn module_vars_from_configure(scir: &Scir, c: &Contract) -> FxHashSet<String> {
    let mut out = FxHashSet::default();
    let Some(cfg) = scir.functions_of(c.id).into_iter().find(|f| f.name == "configureDependencies" && f.has_body)
    else {
        return out;
    };
    for s in &cfg.body {
        s.visit_exprs(&mut |e| {
            let ExprKind::Assign { target, value, .. } = &e.kind else { return };
            let Some(tname) = root_ident_str(target) else { return };
            if value_calls_get_module_address(value) {
                out.insert(tname.to_string());
            }
        });
    }
    out
}

/// True if `e` contains a call to `getModuleAddress(...)` anywhere (the RHS is
/// typically `MODULEv1(getModuleAddress(deps[i]))`, a cast wrapping the call).
fn value_calls_get_module_address(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if let ExprKind::Call(c) = &sub.kind {
            if c.func_name.as_deref() == Some("getModuleAddress") {
                found = true;
            }
        }
    });
    found
}

// -------------------------------------------------------------- inheritance walk

/// True if the contract named `name` transitively inherits a base named `base`
/// (by exact name match through `by_name`). `name == base` counts.
fn inherits_base(by_name: &FxHashMap<&str, &Contract>, name: &str, base: &str) -> bool {
    let mut stack = vec![name.to_string()];
    let mut seen: FxHashSet<String> = FxHashSet::default();
    while let Some(n) = stack.pop() {
        if !seen.insert(n.clone()) {
            continue;
        }
        if n == base {
            return true;
        }
        if let Some(c) = by_name.get(n.as_str()) {
            for b in &c.bases {
                stack.push(b.clone());
            }
        }
    }
    false
}

/// All contract names in the inheritance chain rooted at `name` (itself + every
/// transitive base resolvable through `by_name`), de-duplicated, as borrowed
/// `&str`s into the name index.
fn chain_names<'a>(by_name: &FxHashMap<&'a str, &'a Contract>, name: &str) -> Vec<&'a str> {
    let mut out: Vec<&'a str> = Vec::new();
    let mut seen: FxHashSet<&'a str> = FxHashSet::default();
    // Seed from the index so the returned lifetime is the index's, not `name`'s.
    let mut stack: Vec<&'a str> = Vec::new();
    if let Some((k, _)) = by_name.get_key_value(name) {
        stack.push(k);
    }
    while let Some(n) = stack.pop() {
        if !seen.insert(n) {
            continue;
        }
        out.push(n);
        if let Some(c) = by_name.get(n) {
            for b in &c.bases {
                if let Some((k, _)) = by_name.get_key_value(b.as_str()) {
                    stack.push(k);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::context::AnalysisContext;
    use crate::detector::Detector;
    use sluice_findings::{Finding, Severity};

    /// Run *only this detector* against `src`, bypassing the global registry (which
    /// is contended in the shared worktree). Mirrors the engine wiring in
    /// `analyze_sources` but with a one-element detector list.
    fn run(src: &str) -> Vec<Finding> {
        let cfg = crate::Config::default();
        let parsed = sluice_parse::parse_sources(vec![("t.sol".into(), src.into())]);
        let scir = parsed.scir;
        let dataflow = sluice_dataflow::DataflowFacts::analyze(&scir);
        let invariants = sluice_invariant::InvariantFacts::mine(&scir);
        let frontier = sluice_frontier::FrontierFacts::analyze(&scir);
        let cx = AnalysisContext::new(&scir, &dataflow, &invariants, &frontier, &cfg);
        super::PolicyPermissionDeclarationGapDetector.run(&cx)
    }

    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "policy-permission-declaration-gap")
    }

    /// Minimal Default-Framework scaffold: a `Module` base with the `permissioned`
    /// modifier, a `Policy` base with `requestPermissions`/`configureDependencies`,
    /// a `Permissions` struct shape, and a concrete RANGE module split across an
    /// abstract (`RANGEv1`) + concrete (`OlympusRange`) pair — exactly the Olympus
    /// abstract/concrete layout.
    const SCAFFOLD: &str = r#"
        type Keycode is bytes5;
        struct Permissions { Keycode keycode; bytes4 funcSelector; }
        contract Kernel {}
        abstract contract Module {
            modifier permissioned() { _; }
            function KEYCODE() public pure virtual returns (Keycode) {}
        }
        abstract contract Policy {
            function getModuleAddress(Keycode k) internal view returns (address) {}
            function configureDependencies() external virtual returns (Keycode[] memory) {}
            function requestPermissions() external view virtual returns (Permissions[] memory) {}
        }
        abstract contract RANGEv1 is Module {
            function updateCapacity(bool h, uint256 c) external virtual;
            function updateMarket(bool h, uint256 m) external virtual;
            function regenerate(bool h, uint256 c) external virtual;
            function capacity(bool h) external view virtual returns (uint256);
        }
        contract OlympusRange is RANGEv1 {
            function updateCapacity(bool h, uint256 c) external override permissioned {}
            function updateMarket(bool h, uint256 m) external override permissioned {}
            function regenerate(bool h, uint256 c) external override permissioned {}
            function capacity(bool h) external view override returns (uint256) { return 0; }
            function KEYCODE() public pure override returns (Keycode) { return Keycode.wrap("RANGE"); }
        }
    "#;

    fn with_scaffold(policy: &str) -> String {
        format!("{SCAFFOLD}\n{policy}")
    }

    // VULN (C \ D): the policy CALLS `RANGE.regenerate` (a `permissioned` module
    // function) but its `requestPermissions()` only declares updateCapacity +
    // updateMarket. The `regenerate` grant is never set, so the call reverts on
    // every invocation — a guaranteed DoS.
    const VULN_UNDECLARED: &str = r#"
        contract OperatorVuln is Policy {
            RANGEv1 internal RANGE;
            function configureDependencies() external override returns (Keycode[] memory deps) {
                deps = new Keycode[](1);
                RANGE = RANGEv1(getModuleAddress(deps[0]));
            }
            function requestPermissions() external view override returns (Permissions[] memory reqs) {
                reqs = new Permissions[](2);
                reqs[0] = Permissions(Keycode.wrap("RANGE"), RANGE.updateCapacity.selector);
                reqs[1] = Permissions(Keycode.wrap("RANGE"), RANGE.updateMarket.selector);
            }
            function operate() external {
                RANGE.updateCapacity(true, 1);
                RANGE.regenerate(true, 2);   // <-- called but NOT declared => reverts in prod
            }
        }
    "#;

    // SAFE: the declared set and the called set match exactly. Also calls a view
    // getter (`capacity`, not permissioned) which must be ignored.
    const SAFE_MATCHED: &str = r#"
        contract OperatorSafe is Policy {
            RANGEv1 internal RANGE;
            function configureDependencies() external override returns (Keycode[] memory deps) {
                deps = new Keycode[](1);
                RANGE = RANGEv1(getModuleAddress(deps[0]));
            }
            function requestPermissions() external view override returns (Permissions[] memory reqs) {
                reqs = new Permissions[](2);
                reqs[0] = Permissions(Keycode.wrap("RANGE"), RANGE.updateCapacity.selector);
                reqs[1] = Permissions(Keycode.wrap("RANGE"), RANGE.updateMarket.selector);
            }
            function operate() external {
                uint256 c = RANGE.capacity(true);          // view getter — ignored
                RANGE.updateCapacity(true, c);
                RANGE.updateMarket(true, 1);
            }
        }
    "#;

    // VULN (D \ C, over-grant): declares `regenerate` but never calls it.
    const VULN_OVERGRANT: &str = r#"
        contract OperatorOver is Policy {
            RANGEv1 internal RANGE;
            function configureDependencies() external override returns (Keycode[] memory deps) {
                deps = new Keycode[](1);
                RANGE = RANGEv1(getModuleAddress(deps[0]));
            }
            function requestPermissions() external view override returns (Permissions[] memory reqs) {
                reqs = new Permissions[](2);
                reqs[0] = Permissions(Keycode.wrap("RANGE"), RANGE.updateCapacity.selector);
                reqs[1] = Permissions(Keycode.wrap("RANGE"), RANGE.regenerate.selector); // declared, never called
            }
            function operate() external {
                RANGE.updateCapacity(true, 1);
            }
        }
    "#;

    // SAFE (not a Policy): the same call/declaration mismatch shape, but the
    // contract is NOT a Default-Framework policy (does not inherit Policy and has no
    // requestPermissions). Out of scope — must stay silent.
    const SAFE_NOT_POLICY: &str = r#"
        contract NotAPolicy {
            RANGEv1 internal RANGE;
            function operate() external {
                RANGE.regenerate(true, 2);
            }
        }
    "#;

    // SAFE (non-module receiver, same-named permissioned fn elsewhere): the policy
    // calls `token.transfer` where `token` is an ERC20 (NOT a module), even though a
    // module type in scope has a `permissioned transfer`. Must not be treated as a
    // module permissioned call.
    const SAFE_NONMODULE_RECEIVER: &str = r#"
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        abstract contract VOTESv1 is Module {
            function transfer(address to, uint256 a) external virtual returns (bool);
        }
        contract OlympusVotes is VOTESv1 {
            function transfer(address to, uint256 a) external override permissioned returns (bool) { return true; }
            function KEYCODE() public pure override returns (Keycode) { return Keycode.wrap("VOTES"); }
        }
        contract TokenMover is Policy {
            RANGEv1 internal RANGE;
            IERC20 internal token;
            function configureDependencies() external override returns (Keycode[] memory deps) {
                deps = new Keycode[](1);
                RANGE = RANGEv1(getModuleAddress(deps[0]));
            }
            function requestPermissions() external view override returns (Permissions[] memory reqs) {
                reqs = new Permissions[](1);
                reqs[0] = Permissions(Keycode.wrap("RANGE"), RANGE.updateCapacity.selector);
            }
            function move() external {
                RANGE.updateCapacity(true, 1);
                token.transfer(msg.sender, 1);   // ERC20.transfer, NOT VOTES.transfer — ignored
            }
        }
    "#;

    #[test]
    fn fires_on_undeclared_call_dos() {
        let src = with_scaffold(VULN_UNDECLARED);
        let fs = run(&src);
        assert!(
            fs.iter().any(|f| f.detector == "policy-permission-declaration-gap"
                && f.severity == Severity::High
                && f.message.contains("regenerate")),
            "expected High undeclared-call finding for regenerate, got: {:#?}",
            fs
        );
    }

    #[test]
    fn silent_on_matched_tables() {
        let src = with_scaffold(SAFE_MATCHED);
        assert!(!fires(&src), "{:#?}", run(&src));
    }

    #[test]
    fn fires_on_overgrant_low() {
        let src = with_scaffold(VULN_OVERGRANT);
        let fs = run(&src);
        assert!(
            fs.iter().any(|f| f.detector == "policy-permission-declaration-gap"
                && f.severity == Severity::Low
                && f.message.contains("regenerate")),
            "expected Low over-grant finding for regenerate, got: {:#?}",
            fs
        );
        // And it must NOT raise a High for this policy (no undeclared call).
        assert!(
            !fs.iter().any(|f| f.detector == "policy-permission-declaration-gap"
                && f.severity == Severity::High),
            "over-grant must not produce a High finding: {:#?}",
            fs
        );
    }

    #[test]
    fn silent_on_non_policy() {
        let src = with_scaffold(SAFE_NOT_POLICY);
        assert!(!fires(&src), "{:#?}", run(&src));
    }

    #[test]
    fn silent_on_non_module_receiver() {
        let src = with_scaffold(SAFE_NONMODULE_RECEIVER);
        assert!(!fires(&src), "{:#?}", run(&src));
    }
}
