//! Module active-flag privilege scope — a **global kill-switch on the flat
//! permission channel** of a Default-Framework `Module`.
//!
//! ## The class
//!
//! In the Default Framework (Olympus V3 / "Bophades"), a `Module` grants policies
//! access to its functions through a single flat channel: the `permissioned`
//! modifier, which checks only that the *kernel* registered the caller's selector
//! (`kernel.modulePermissions(KEYCODE(), Policy(msg.sender), msg.sig)`). Every
//! policy that holds *any* permission on the module passes `permissioned` for the
//! function it was granted — there is no per-function privilege tier inside the
//! module beyond that one selector grant.
//!
//! On top of that flat channel some modules layer a **single scalar `bool active`
//! kill-switch**, read by an `onlyWhileActive`-style modifier that reverts when the
//! flag is `false`. The flag is flipped by a pair of `permissioned` functions whose
//! **entire body is one SSTORE of the bool** (`active = false;` / `active = true;`).
//!
//! ```solidity
//! abstract contract MINTRv1 is Module {
//!     bool public active;                                  // the scalar flag
//!     modifier onlyWhileActive() { if (!active) revert MINTR_NotActive(); _; }
//!     function mintOhm(...) external permissioned onlyWhileActive { ... }   // guarded
//!     function burnOhm(...) external permissioned onlyWhileActive { ... }   // guarded
//!     function deactivate() external permissioned;          // the flipper
//!     function activate()   external permissioned;
//! }
//! contract OlympusMinter is MINTRv1 {
//!     function deactivate() external override permissioned { active = false; }  // <-- here
//!     function activate()   external override permissioned { active = true;  }
//! }
//! ```
//!
//! ### Why it is a bug
//!
//! Because `deactivate()` is gated by the **same** flat `permissioned` channel as
//! `mintOhm` / `burnOhm` / `withdrawReserves`, *any* grantee — a policy holding only
//! a narrow permission for one routine — can call `deactivate()` and set `active =
//! false`, which trips `onlyWhileActive` on **every** other `permissioned` function
//! the modifier guards. One narrowly-scoped grantee thereby halts the whole
//! module's mint / burn / withdraw surface: a privilege-scope mismatch (a global
//! kill-switch sitting on a per-selector permission channel). The fix is to gate the
//! flipper behind a *distinct, more privileged* role (an emergency/admin role) than
//! the routines it can freeze.
//!
//! ## What the detector matches (all required)
//!
//! Walking each concrete `Module`-derived contract's full inheritance scope
//! (own + bases — the flag, the modifier and the guarded functions routinely live
//! in the abstract base, the flipper override in the leaf):
//!
//!   1. a **flipper**: an externally-reachable, state-mutating function carrying a
//!      `permissioned`-style modifier whose **entire body is a single assignment of
//!      a boolean literal to a scalar `bool` state variable** (`flag = false;` /
//!      `flag = true;`);
//!   2. an **`onlyWhileActive`-style reader**: a modifier in scope whose body
//!      *reads* that same flag in a revert-guard (`if (!flag) revert` /
//!      `require(flag)`) and is **not** a `msg.sender` access check; and
//!   3. **flat-channel breadth**: at least **two OTHER** functions in scope carry
//!      *both* that reader modifier *and* a `permissioned`-style modifier — i.e. the
//!      flag is a kill-switch over >= 2 sibling permissioned functions.
//!
//! Fires **at the flipper**. Severity is High; confidence is raised (still High)
//! when the guarded set includes a `mint` / `burn` / `withdraw` function — freezing
//! the protocol's value surface.
//!
//! ## Suppression (precision over volume)
//!
//!   * **Per-entity pause mappings.** The flag must be a **scalar `bool`**, never a
//!     `mapping(address => bool) paused` (`paused[addr] = true`) — a per-account
//!     freeze is ordinary bookkeeping, not a global kill-switch, and never fires.
//!   * **No `onlyWhileActive` reader.** A `permissioned` bool setter whose flag is
//!     not read by any revert-guard modifier is just a config toggle (nothing is
//!     globally frozen by it) — silent.
//!   * **No flat `permissioned` channel.** If the flipper is not on the
//!     Default-Framework flat permission modifier (e.g. it is `onlyOwner` /
//!     `onlyRole`-gated — a *distinct* admin role from the routines), there is no
//!     privilege-scope collapse, so the class does not apply.
//!   * **Breadth < 2.** A flag guarding only one (or zero) other permissioned
//!     function is too narrow to be the "halt the protocol" shape.

use super::prelude::*;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{AssignOp, BinOp, Contract, Expr, ExprKind, Function, Lit, Stmt, StmtKind, UnOp};
use std::collections::HashSet;

pub struct ModuleActiveFlagScopeDetector;

impl Detector for ModuleActiveFlagScopeDetector {
    fn id(&self) -> &'static str {
        "module-active-flag-scope"
    }
    fn category(&self) -> Category {
        Category::ModuleActiveFlagPrivilegeScope
    }
    fn description(&self) -> &'static str {
        "A permissioned scalar-bool kill-switch flipper on a Module's flat permission \
         channel lets any grantee freeze >=2 other permissioned functions guarded by an \
         onlyWhileActive-style modifier"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for contract in cx.scir.iter_contracts() {
            // Only a concrete Module-derived contract hosts the flipper override.
            // Interfaces/libraries never do; an abstract base declares the surface
            // but the deployable flipper body lives in the leaf, so we anchor on
            // concrete contracts and resolve the flag/modifier/siblings through the
            // inheritance scope.
            if !contract.is_concrete() {
                continue;
            }
            if !inherits_module(cx, contract) {
                continue;
            }

            // Full inherited surface: the flag, the `onlyWhileActive` modifier and the
            // guarded functions overwhelmingly sit in the abstract base while the
            // flipper override sits in the leaf — so every query is over scope, not
            // just this contract's own declarations.
            let scope_fns = scope_functions(cx, contract);
            let scope_bool_flags = scalar_bool_flags(cx, contract);
            if scope_bool_flags.is_empty() {
                continue;
            }

            // For each scalar-bool flag, find the `onlyWhileActive`-style reader
            // modifier(s) that gate on it.
            for flag in &scope_bool_flags {
                let reader_mods = reader_modifiers_for_flag(&scope_fns, flag);
                // SUPPRESS: a bool with no onlyWhileActive-style reader is just a
                // config toggle — nothing is globally frozen by flipping it.
                if reader_mods.is_empty() {
                    continue;
                }

                // Flat-channel breadth: OTHER permissioned functions guarded by one of
                // the reader modifiers. Collect names + whether any is mint/burn/withdraw.
                let guarded = guarded_permissioned_fns(&scope_fns, &reader_mods);
                if guarded.len() < 2 {
                    // SUPPRESS: a kill-switch over fewer than two sibling permissioned
                    // functions is too narrow to be the "halt the protocol" shape.
                    continue;
                }
                let hits_value_surface = guarded.iter().any(|n| is_value_surface_name(n));

                // Find the flipper(s): a permissioned function in THIS contract whose
                // entire body is `flag = <bool literal>;`. We report only flippers
                // declared in the concrete contract (the deployable override), so the
                // finding lands on the live `active = false;` site, not the abstract
                // base's bodyless declaration.
                for f in cx.scir.functions_of(contract.id) {
                    if !is_single_bool_store_flipper(f, flag) {
                        continue;
                    }
                    // CORE GATE: the flipper must be on the FLAT permission channel
                    // (`permissioned`-style), not a distinct admin/role guard. If it is
                    // `onlyOwner`/`onlyRole`-gated, the flip role is already separated
                    // from the routines and there is no privilege-scope collapse.
                    if !has_flat_permission_modifier(f) {
                        continue;
                    }

                    let guarded_list = sample_names(&guarded);
                    let (sev, conf) = if hits_value_surface {
                        // Freezing mint/burn/withdraw is the protocol-halting case —
                        // keep it solidly High (single Invariant dimension).
                        (Severity::High, 0.86)
                    } else {
                        (Severity::High, 0.78)
                    };

                    let b = report!(self, Category::ModuleActiveFlagPrivilegeScope,
                        title = "Module kill-switch shares the flat permission channel it can freeze",
                        severity = sev,
                        confidence = conf,
                        dimensions = [Dimension::Invariant],
                        message = format!(
                            "`{contract}.{flipper}` is gated only by the Module's flat `permissioned` \
                             channel and its entire body flips the scalar kill-switch `{flag} = {val};`, \
                             which the `{reader}` modifier reads to guard {n} OTHER permissioned \
                             function(s) ({guarded}). Because the flipper sits on the SAME per-selector \
                             permission channel as those functions, any policy holding a permission for \
                             a single routine can call `{flipper}` and set `{flag} = false`, tripping \
                             `{reader}` on every guarded function and halting the module's whole \
                             surface{value_note}. The kill-switch is a global privilege but rides a \
                             flat, per-function permission grant — a privilege-scope mismatch.",
                            contract = contract.name,
                            flipper = f.name,
                            flag = flag,
                            val = flip_value_text(f, flag),
                            reader = reader_mods.iter().next().cloned().unwrap_or_default(),
                            n = guarded.len(),
                            guarded = guarded_list,
                            value_note = if hits_value_surface {
                                " (including the protocol's mint/burn/withdraw value surface)"
                            } else {
                                ""
                            },
                        ),
                        recommendation =
                            "Gate the kill-switch flipper behind a DISTINCT, more-privileged role \
                             (a dedicated emergency/admin role or the kernel executor) than the \
                             per-selector `permissioned` grant used by the functions it can freeze, so \
                             a narrowly-scoped grantee cannot deactivate the whole module.",
                    );
                    out.push(finish_at(cx, b, f.id, f.span));
                }
            }
        }

        out
    }
}

// ============================================================ scope collection

/// True if `contract` is a Default-Framework `Module` (inherits `Module`, or a base
/// whose name ends in the module-version convention `*v1`/`*v2`… that itself derives
/// from `Module`). Resolved transitively over the inheritance scope.
fn inherits_module(cx: &AnalysisContext, contract: &Contract) -> bool {
    let mut seen = HashSet::new();
    inherits_module_rec(cx, contract, &mut seen)
}

fn inherits_module_rec(cx: &AnalysisContext, contract: &Contract, seen: &mut HashSet<String>) -> bool {
    if !seen.insert(contract.name.clone()) {
        return false;
    }
    for base in &contract.bases {
        // The base type literally named `Module` (the Default-Framework base).
        if base == "Module" {
            return true;
        }
        if let Some(bc) = cx.scir.contract_named(base) {
            if inherits_module_rec(cx, bc, seen) {
                return true;
            }
        }
    }
    false
}

/// All functions (including modifiers) visible to `contract` — own declarations plus
/// every transitively-inherited base — so flag/modifier/sibling resolution spans the
/// whole inherited surface, not just the leaf file.
fn scope_functions<'a>(cx: &'a AnalysisContext, contract: &Contract) -> Vec<&'a Function> {
    let mut out: Vec<&Function> = Vec::new();
    let mut seen = HashSet::new();
    collect_scope_functions(cx, contract, &mut out, &mut seen);
    out
}

fn collect_scope_functions<'a>(
    cx: &'a AnalysisContext,
    contract: &Contract,
    out: &mut Vec<&'a Function>,
    seen: &mut HashSet<String>,
) {
    if !seen.insert(contract.name.clone()) {
        return;
    }
    for f in cx.scir.functions_of(contract.id) {
        out.push(f);
    }
    for base in &contract.bases {
        if let Some(bc) = cx.scir.contract_named(base) {
            collect_scope_functions(cx, bc, out, seen);
        }
    }
}

/// Names of **scalar `bool`** state variables visible to `contract` (own + bases)
/// that are settable (not `constant`). A `mapping(... => bool)` is *excluded* — a
/// per-entity pause map is not a global kill-switch (the cardinal suppression).
fn scalar_bool_flags(cx: &AnalysisContext, contract: &Contract) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    collect_bool_flags(cx, contract, &mut out, &mut seen);
    out
}

fn collect_bool_flags(
    cx: &AnalysisContext,
    contract: &Contract,
    out: &mut Vec<String>,
    seen: &mut HashSet<String>,
) {
    if !seen.insert(contract.name.clone()) {
        return;
    }
    for v in &contract.state_vars {
        // Scalar bool only. `bool public active;` qualifies; `mapping(address =>
        // bool) paused;` does NOT (per-entity pause map — suppressed by class).
        if v.constant {
            continue;
        }
        if v.is_mapping() {
            continue;
        }
        if v.ty.trim() == "bool" && !out.contains(&v.name) {
            out.push(v.name.clone());
        }
    }
    for base in &contract.bases {
        if let Some(bc) = cx.scir.contract_named(base) {
            collect_bool_flags(cx, bc, out, seen);
        }
    }
}

// ============================================================ modifier classifiers

/// The names of modifiers in scope that READ `flag` as an `onlyWhileActive`-style
/// revert-guard — i.e. their body checks the flag and reverts/returns when it is
/// `false` — and that are **not** a `msg.sender` access check. These are the kill
/// guards the flipper trips.
fn reader_modifiers_for_flag(scope_fns: &[&Function], flag: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for m in scope_fns {
        if !m.is_modifier() {
            continue;
        }
        // An `onlyWhileActive` modifier gates on a STATE FLAG, not the caller. The
        // parser classifies any "only*" modifier's *invocation* as a MsgSenderCheck,
        // so we cannot rely on that — instead we inspect the modifier BODY: it must
        // read `flag` and must not compare `msg.sender`.
        if modifier_body_reads_flag_guard(m, flag) && !modifier_body_checks_sender(m) {
            out.insert(m.name.clone());
        }
    }
    out
}

/// The modifier body contains a guard that READS `flag` and reverts/returns on it:
/// `if (!flag) revert ...;` / `if (flag == false) ...` / `require(flag)` /
/// `require(active, ...)`. We accept any read of the bare `flag` identifier inside
/// an `if`-condition guarding a revert/return, or inside a `require`/`assert`.
fn modifier_body_reads_flag_guard(m: &Function, flag: &str) -> bool {
    let mut found = false;
    for s in &m.body {
        s.visit(&mut |st| {
            if found {
                return;
            }
            match &st.kind {
                // `if (<cond mentioning flag>) revert/return ...;`
                StmtKind::If { cond, then_branch, else_branch } => {
                    if cond_reads_flag(cond, flag)
                        && (branch_reverts_or_returns(then_branch)
                            || branch_reverts_or_returns(else_branch))
                    {
                        found = true;
                    }
                }
                // `require(flag, ...)` / `assert(flag)` mentioning the flag.
                StmtKind::Expr(e) => {
                    if let ExprKind::Call(c) = &e.kind {
                        if is_require_or_assert(c) {
                            if let Some(arg) = c.args.first() {
                                if expr_mentions_ident(arg, flag) {
                                    found = true;
                                }
                            }
                        }
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

/// The condition reads the flag — either the bare `flag` identifier, `!flag`, or a
/// comparison `flag == false` / `flag != true`. We require the flag to appear as a
/// bare identifier (not as an index base `m[flag]`), which a scalar bool always is.
fn cond_reads_flag(cond: &Expr, flag: &str) -> bool {
    // The common shape is `!flag` or bare `flag`. Accept any mention of the bare
    // identifier; the surrounding `if (... ) revert` shape is enforced by the caller.
    expr_mentions_bare_ident(cond, flag)
}

/// Does `e` mention `name` as a bare identifier (`flag`, `!flag`, `flag == false`),
/// as opposed to only as a member/index base? A scalar bool flag is always read as a
/// bare ident, so this avoids matching an unrelated `something.flag` member.
fn expr_mentions_bare_ident(e: &Expr, name: &str) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        match &sub.kind {
            ExprKind::Ident(n) if n == name => found = true,
            // Unary `!flag` / `flag` inside a not.
            ExprKind::Unary { op: UnOp::Not, operand } => {
                if let ExprKind::Ident(n) = &operand.kind {
                    if n == name {
                        found = true;
                    }
                }
            }
            // `flag == false`, `flag != true`.
            ExprKind::Binary { op: BinOp::Eq | BinOp::Ne, lhs, rhs } => {
                for side in [lhs, rhs] {
                    if let ExprKind::Ident(n) = &side.kind {
                        if n == name {
                            found = true;
                        }
                    }
                }
            }
            _ => {}
        }
    });
    found
}

/// True if a branch is a single (or leading) revert/return — the kill action of an
/// `onlyWhileActive` guard.
fn branch_reverts_or_returns(branch: &[Stmt]) -> bool {
    branch.iter().any(|s| {
        matches!(
            &s.kind,
            StmtKind::Revert { .. } | StmtKind::Return(_)
        ) || matches!(&s.kind, StmtKind::Expr(e) if is_revert_call(e))
    })
}

/// `revert Foo();` lowered as a call expression (some parsers surface `revert
/// CustomError()` as a call rather than a `Revert` statement).
fn is_revert_call(e: &Expr) -> bool {
    if let ExprKind::Call(c) = &e.kind {
        if matches!(c.kind, sluice_ir::CallKind::Builtin(sluice_ir::Builtin::Revert)) {
            return true;
        }
        if let Some(n) = c.func_name.as_deref() {
            return n == "revert";
        }
    }
    false
}

/// The modifier body compares `msg.sender` (an access-control guard, not a state-flag
/// guard) — used to EXCLUDE `permissioned`/`onlyRole`-style modifiers from the
/// `onlyWhileActive` reader set even though they share the `only*` prefix.
fn modifier_body_checks_sender(m: &Function) -> bool {
    if m.effects.reads_msg_sender {
        return true;
    }
    let mut found = false;
    for s in &m.body {
        s.visit_exprs(&mut |e| {
            if e.mentions_member("msg", "sender") || e.mentions_member("tx", "origin") {
                found = true;
            }
        });
        if found {
            break;
        }
    }
    found
}

/// True if `f` carries a **flat-permission-channel** modifier — the Default-Framework
/// `permissioned` modifier (or an equivalently-named flat permission gate). This is
/// the per-selector channel shared by every grantee; it is deliberately NOT a
/// discretionary `onlyOwner`/`onlyRole` admin guard.
fn has_flat_permission_modifier(f: &Function) -> bool {
    f.modifiers.iter().any(|m| is_flat_permission_name(&m.name))
}

/// A modifier name denoting the Module's flat permission channel. `permissioned` is
/// the Default-Framework name; we also accept the close synonyms a fork might use
/// (`onlyPermitted`, `permissionedOnly`) while staying narrow enough to avoid
/// matching discretionary role guards.
fn is_flat_permission_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "permissioned" || l == "onlypermissioned" || l.starts_with("permissioned")
}

// ============================================================ flipper recognizer

/// True if `f` is a **flipper** for `flag`: its entire (effective) body is a single
/// statement assigning a boolean literal to the scalar state var `flag`
/// (`flag = false;` / `flag = true;`). Comments / pragmas are already stripped at the
/// IR level. `unchecked { }` wrappers and trivial blocks are unwrapped.
fn is_single_bool_store_flipper(f: &Function, flag: &str) -> bool {
    if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
        return false;
    }
    if f.is_constructor() || f.is_modifier() {
        return false;
    }
    let effective = effective_body_stmts(&f.body);
    let [only] = effective.as_slice() else {
        return false;
    };
    let StmtKind::Expr(e) = &only.kind else {
        return false;
    };
    is_bool_store_to(e, flag)
}

/// The boolean literal the flipper stores ("false"/"true"), for the message. Falls
/// back to "false" (the halting direction) if not resolvable.
fn flip_value_text(f: &Function, flag: &str) -> &'static str {
    for only in effective_body_stmts(&f.body) {
        if let StmtKind::Expr(e) = &only.kind {
            if let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind {
                if matches!(&target.kind, ExprKind::Ident(n) if n == flag) {
                    if let ExprKind::Lit(Lit::Bool(b)) = &value.kind {
                        return if *b { "true" } else { "false" };
                    }
                }
            }
        }
    }
    "false"
}

/// Unwrap a body down to its meaningful statements, descending through a single
/// wrapping `{ }` / `unchecked { }` block. (A flipper override is usually just
/// `{ active = false; }`, but a defensive `unchecked { }` wrap should not hide it.)
fn effective_body_stmts(body: &[Stmt]) -> Vec<&Stmt> {
    // Drop no-op placeholder statements, then unwrap a lone block.
    let meaningful: Vec<&Stmt> = body
        .iter()
        .filter(|s| !matches!(s.kind, StmtKind::Placeholder))
        .collect();
    if let [only] = meaningful.as_slice() {
        if let StmtKind::Block { stmts, .. } = &only.kind {
            return effective_body_stmts(stmts);
        }
    }
    meaningful
}

/// `e` is `flag = <bool literal>` where `flag` is a bare identifier (the scalar state
/// var). The assignment operator must be plain `=` (a compound op is not a flag flip).
fn is_bool_store_to(e: &Expr, flag: &str) -> bool {
    let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind else {
        return false;
    };
    // Target is the bare scalar flag identifier (NOT `paused[addr]` — an index/member
    // target is a per-entity write, never a global flip).
    if !matches!(&target.kind, ExprKind::Ident(n) if n == flag) {
        return false;
    }
    matches!(&value.kind, ExprKind::Lit(Lit::Bool(_)))
}

// ============================================================ breadth + naming

/// Distinct names of functions in scope that carry BOTH a reader modifier (the
/// `onlyWhileActive`-style guard) AND a flat-permission modifier — the sibling
/// permissioned functions the kill-switch can freeze.
fn guarded_permissioned_fns(scope_fns: &[&Function], reader_mods: &HashSet<String>) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for f in scope_fns {
        if f.is_modifier() || f.is_constructor() {
            continue;
        }
        let has_reader = f.modifiers.iter().any(|m| reader_mods.contains(&m.name));
        if !has_reader {
            continue;
        }
        if !has_flat_permission_modifier(f) {
            continue;
        }
        if !names.contains(&f.name) {
            names.push(f.name.clone());
        }
    }
    names
}

/// Is `name` a protocol value-surface function — mint / burn / withdraw / redeem —
/// freezing which is the protocol-halting case that raises severity.
fn is_value_surface_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    ["mint", "burn", "withdraw", "redeem", "incurdebt", "borrow"]
        .iter()
        .any(|k| l.contains(k))
}

/// A short, deterministic sample of guarded-function names for the message.
fn sample_names(names: &[String]) -> String {
    let mut sorted: Vec<&String> = names.iter().collect();
    sorted.sort();
    let shown: Vec<&str> = sorted.iter().take(4).map(|s| s.as_str()).collect();
    let mut s = shown.join(", ");
    if sorted.len() > 4 {
        s.push_str(", …");
    }
    s
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "module-active-flag-scope")
    }

    // The Default-Framework base providing `Module` + the flat `permissioned` channel.
    const FRAMEWORK: &str = r#"
        abstract contract Module {
            modifier permissioned() {
                require(msg.sender == address(0xBEEF), "perm");
                _;
            }
            function KEYCODE() public pure virtual returns (bytes5) {}
        }
    "#;

    // VULN — Olympus MINTR shape: `active` flag + `onlyWhileActive` reader in the
    // abstract base, the `deactivate`/`activate` flippers in the concrete leaf,
    // mint/burn guarded by both `permissioned` and `onlyWhileActive`.
    fn vuln_src() -> String {
        format!(
            r#"{FRAMEWORK}
            abstract contract MINTRv1 is Module {{
                bool public active;
                mapping(address => uint256) public mintApproval;
                modifier onlyWhileActive() {{ if (!active) revert(); _; }}
                function mintOhm(address to_, uint256 amount_) external virtual;
                function burnOhm(address from_, uint256 amount_) external virtual;
                function deactivate() external virtual;
                function activate() external virtual;
            }}
            contract OlympusMinter is MINTRv1 {{
                function mintOhm(address to_, uint256 amount_) external override permissioned onlyWhileActive {{
                    mintApproval[to_] = amount_;
                }}
                function burnOhm(address from_, uint256 amount_) external override permissioned onlyWhileActive {{
                    mintApproval[from_] = amount_;
                }}
                function deactivate() external override permissioned {{ active = false; }}
                function activate() external override permissioned {{ active = true; }}
            }}"#
        )
    }

    #[test]
    fn fires_on_olympus_minter_shape() {
        let src = vuln_src();
        assert!(fires(&src), "{:#?}", run(&src));
    }

    #[test]
    fn fires_at_both_flippers() {
        let src = vuln_src();
        let hits: Vec<_> = run(&src)
            .into_iter()
            .filter(|f| f.detector == "module-active-flag-scope")
            .collect();
        // deactivate + activate are both single-bool-store flippers on the flat channel.
        assert_eq!(hits.len(), 2, "{hits:#?}");
        assert!(hits.iter().all(|f| matches!(f.severity, sluice_findings::Severity::High)));
    }

    // VULN single-file variant (flag + modifier + flippers + guarded fns all in one
    // concrete Module contract) — proves scope walking is not load-bearing for firing.
    const VULN_SINGLE: &str = r#"
        abstract contract Module {
            modifier permissioned() { require(msg.sender == address(0xBEEF)); _; }
        }
        contract Treasury is Module {
            bool public active;
            mapping(address => uint256) public approval;
            modifier onlyWhileActive() { if (!active) revert(); _; }
            function withdrawReserves(address to_, uint256 a_) external permissioned onlyWhileActive {
                approval[to_] = a_;
            }
            function incurDebt(uint256 a_) external permissioned onlyWhileActive {
                approval[msg.sender] = a_;
            }
            function deactivate() external permissioned { active = false; }
            function activate() external permissioned { active = true; }
        }
    "#;

    #[test]
    fn fires_on_single_file_treasury() {
        assert!(fires(VULN_SINGLE), "{:#?}", run(VULN_SINGLE));
    }

    // SAFE — per-entity pause MAPPING, not a scalar bool. `paused[addr] = true` is
    // ordinary bookkeeping; there is no global kill-switch.
    const SAFE_PAUSE_MAPPING: &str = r#"
        abstract contract Module {
            modifier permissioned() { require(msg.sender == address(0xBEEF)); _; }
        }
        contract Vault is Module {
            mapping(address => bool) public paused;
            mapping(address => uint256) public bal;
            modifier whileLive(address u) { if (paused[u]) revert(); _; }
            function withdraw(address u, uint256 a) external permissioned { bal[u] = a; }
            function borrow(address u, uint256 a) external permissioned { bal[u] = a; }
            function pause(address u) external permissioned { paused[u] = true; }
        }
    "#;

    #[test]
    fn silent_on_per_entity_pause_mapping() {
        assert!(!fires(SAFE_PAUSE_MAPPING), "{:#?}", run(SAFE_PAUSE_MAPPING));
    }

    // SAFE — the bool flag has NO onlyWhileActive-style reader. `frozen` is set but no
    // modifier gates on it, so flipping it freezes nothing.
    const SAFE_NO_READER: &str = r#"
        abstract contract Module {
            modifier permissioned() { require(msg.sender == address(0xBEEF)); _; }
        }
        contract Cfg is Module {
            bool public frozen;
            uint256 public x;
            function setX(uint256 v) external permissioned { x = v; }
            function setY(uint256 v) external permissioned { x = v + 1; }
            function freeze() external permissioned { frozen = true; }
        }
    "#;

    #[test]
    fn silent_without_only_while_active_reader() {
        assert!(!fires(SAFE_NO_READER), "{:#?}", run(SAFE_NO_READER));
    }

    // SAFE — the flipper is gated by a DISTINCT admin role (`onlyOwner`), not the flat
    // `permissioned` channel. The flip privilege is already separated from the
    // routines, so there is no privilege-scope collapse.
    const SAFE_DISTINCT_ROLE: &str = r#"
        abstract contract Module {
            modifier permissioned() { require(msg.sender == address(0xBEEF)); _; }
        }
        contract Mod is Module {
            address public owner;
            bool public active;
            mapping(address => uint256) public bal;
            modifier onlyOwner() { require(msg.sender == owner); _; }
            modifier onlyWhileActive() { if (!active) revert(); _; }
            function mint(address to, uint256 a) external permissioned onlyWhileActive { bal[to] = a; }
            function burn(address to, uint256 a) external permissioned onlyWhileActive { bal[to] = a; }
            function deactivate() external onlyOwner { active = false; }
            function activate() external onlyOwner { active = true; }
        }
    "#;

    #[test]
    fn silent_when_flipper_has_distinct_role() {
        assert!(!fires(SAFE_DISTINCT_ROLE), "{:#?}", run(SAFE_DISTINCT_ROLE));
    }

    // SAFE — breadth < 2: the kill-switch guards only ONE other permissioned function.
    const SAFE_NARROW: &str = r#"
        abstract contract Module {
            modifier permissioned() { require(msg.sender == address(0xBEEF)); _; }
        }
        contract Mod is Module {
            bool public active;
            mapping(address => uint256) public bal;
            modifier onlyWhileActive() { if (!active) revert(); _; }
            function mint(address to, uint256 a) external permissioned onlyWhileActive { bal[to] = a; }
            function deactivate() external permissioned { active = false; }
            function activate() external permissioned { active = true; }
        }
    "#;

    #[test]
    fn silent_when_breadth_under_two() {
        assert!(!fires(SAFE_NARROW), "{:#?}", run(SAFE_NARROW));
    }

    // SAFE — the flipper body is NOT a single bool store: it does extra work
    // (emits/loops/other writes), so it is not the minimal kill-switch shape this
    // class targets (a richer admin function is a different surface).
    const SAFE_RICH_BODY: &str = r#"
        abstract contract Module {
            modifier permissioned() { require(msg.sender == address(0xBEEF)); _; }
        }
        contract Mod is Module {
            bool public active;
            uint256 public lastToggle;
            mapping(address => uint256) public bal;
            modifier onlyWhileActive() { if (!active) revert(); _; }
            function mint(address to, uint256 a) external permissioned onlyWhileActive { bal[to] = a; }
            function burn(address to, uint256 a) external permissioned onlyWhileActive { bal[to] = a; }
            function deactivate() external permissioned { active = false; lastToggle = block.timestamp; }
            function activate() external permissioned { active = true; lastToggle = block.timestamp; }
        }
    "#;

    #[test]
    fn silent_when_flipper_body_is_not_single_store() {
        assert!(!fires(SAFE_RICH_BODY), "{:#?}", run(SAFE_RICH_BODY));
    }

    // SAFE — not a Module at all. A plain Ownable contract with a global `paused`
    // bool + `whenNotPaused` reader is the ordinary pausable pattern, not the
    // Default-Framework flat-channel privilege-scope bug.
    const SAFE_NOT_MODULE: &str = r#"
        contract Pausable {
            address public owner;
            bool public paused;
            mapping(address => uint256) public bal;
            modifier onlyOwner() { require(msg.sender == owner); _; }
            modifier whenNotPaused() { if (paused) revert(); _; }
            function deposit(address u, uint256 a) external whenNotPaused { bal[u] = a; }
            function withdraw(address u, uint256 a) external whenNotPaused { bal[u] = a; }
            function pause() external onlyOwner { paused = true; }
            function unpause() external onlyOwner { paused = false; }
        }
    "#;

    #[test]
    fn silent_on_plain_pausable_non_module() {
        assert!(!fires(SAFE_NOT_MODULE), "{:#?}", run(SAFE_NOT_MODULE));
    }
}
