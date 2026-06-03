//! State-variable shadowing — SWC-119 / CWE-710.
//!
//! Solidity resolves a bare name to the **innermost** declaration in scope, so a
//! function parameter or local variable whose name equals an in-scope state
//! variable silently *shadows* that storage slot: every read/write of the name
//! inside the function hits the local, not storage. The state variable is left
//! untouched even though the code reads as if it were being updated. The mirror
//! case is a **child contract** that re-declares a state variable already
//! declared by one of its bases: the child's declaration occupies a *new* slot
//! (pre-0.6 it silently shadowed; ≥0.6 it is a hard error only with `override`
//! semantics for functions, never for plain state), and base methods keep using
//! the base's slot while child methods use the child's — two variables of the
//! same name holding different values. Both are a classic source of "the setter
//! ran but the value never changed" bugs, and are especially dangerous in
//! inherited / upgradeable code where the layout is shared.
//!
//! What this flags (two shapes):
//!
//!   * **Shape A — param/local shadows an in-scope state var.** A function
//!     parameter or a local `VarDecl` whose name equals a state variable of the
//!     function's own contract *or* of any (transitive) base. Resolved via
//!     `cx.contract_of(f.id)` plus the base chain's `state_vars`.
//!   * **Shape B — child state var shadows a base state var.** A contract
//!     declares a state variable whose name also appears in the `state_vars` of
//!     one of its (transitive) bases.
//!
//! Safe form suppressed (kept Low, precise): the disambiguated initializer /
//! setter idiom, where the shadowing parameter is written *through* an explicit
//! `this.<name> = <name>` (member) assignment. Qualifying the left-hand side
//! with `this.` reaches the state variable unambiguously, so the same-name
//! parameter is intentional and correct — not a silent shadow. Every
//! *unqualified* collision still fires.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{
    AssignOp, Contract, Expr, ExprKind, Function, Span, StateVar, Stmt, StmtKind, Visibility,
};
use std::collections::HashSet;

use super::prelude::*;

pub struct ShadowedStateVarDetector;

impl Detector for ShadowedStateVarDetector {
    fn id(&self) -> &'static str {
        "shadowed-state-var"
    }
    fn category(&self) -> Category {
        Category::ShadowedStateVar
    }
    fn description(&self) -> &'static str {
        "A parameter/local or a child state variable shadows an in-scope state variable (SWC-119)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        // ---- Shape A: a parameter or local shadows an in-scope state var. ----
        for f in cx.functions() {
            if !f.has_body {
                continue; // interface / abstract decl: nothing to shadow inside.
            }
            let Some(c) = cx.contract_of(f.id) else { continue };

            // In-scope state-var names = this contract's own + every (transitive)
            // base's. A bare name inside `f` shadows ANY of these, not just the
            // contract's own, so an inherited collision is caught too.
            let in_scope = in_scope_state_vars(cx, c);
            if in_scope.is_empty() {
                continue;
            }

            // Collect every (name, span, what) that shadows an in-scope state var:
            // function parameters, then local `VarDecl`s in the body.
            let mut hits: Vec<(String, Span, &'static str)> = Vec::new();
            for p in &f.params {
                if let Some(n) = &p.name {
                    if in_scope.contains(n.as_str()) {
                        hits.push((n.clone(), f.span, "parameter"));
                    }
                }
            }
            for s in &f.body {
                s.visit(&mut |st: &Stmt| {
                    if let StmtKind::VarDecl { name: Some(n), .. } = &st.kind {
                        if in_scope.contains(n.as_str()) {
                            hits.push((n.clone(), st.span, "local variable"));
                        }
                    }
                });
            }
            if hits.is_empty() {
                continue;
            }

            // Safe-form suppression: the disambiguated `this.<name> = <name>`
            // initializer/setter idiom. Collect the names so written; a hit on
            // such a name is intentional (the `this.` reaches storage) and is
            // dropped. Computed once per function, only when there is a hit.
            let qualified = this_qualified_writes(f);

            // De-dup per (function, name): one finding per shadowed name.
            let mut reported: HashSet<String> = HashSet::new();
            for (name, span, what) in hits {
                if qualified.contains(&name) {
                    continue; // intended, disambiguated setter/initializer.
                }
                if !reported.insert(name.clone()) {
                    continue;
                }
                let b = report!(self, Category::ShadowedStateVar,
                    title = "Local/parameter shadows a state variable",
                    severity = Severity::Low,
                    confidence = 0.55,
                    dimensions = [Dimension::Invariant],
                    message = format!(
                        "In `{}.{}`, the {} `{}` has the same name as an in-scope state variable. \
                         Solidity resolves the bare name `{}` to the innermost (local) declaration, so \
                         every read/write of `{}` inside this function hits the local and leaves the \
                         state variable untouched — a setter can appear to run while storage never \
                         changes (SWC-119).",
                        c.name, f.name, what, name, name, name
                    ),
                    recommendation =
                        "Rename the parameter/local (e.g. a trailing `_`, the OpenZeppelin convention) so \
                         it no longer shadows the state variable, or qualify the storage access explicitly.",
                );
                out.push(finish_at(cx, b, f.id, span));
            }
        }

        // ---- Shape B: a child state var shadows a base state var. ----
        for c in cx.scir.iter_contracts() {
            if c.state_vars.is_empty() || c.bases.is_empty() {
                continue;
            }
            // Names declared by any (transitive) base — NOT including `c`'s own.
            let base_names = base_state_vars(cx, c);
            if base_names.is_empty() {
                continue;
            }
            let mut reported: HashSet<&str> = HashSet::new();
            for v in &c.state_vars {
                if !base_names.contains(v.name.as_str()) {
                    continue;
                }
                // Safe form: a per-level storage-gap reservation (`uint256[N]
                // private __gap;`). The OpenZeppelin upgradeable convention has
                // EVERY contract in the chain reserve its OWN private `__gap`
                // padding slot, so the same name recurring across levels is
                // intentional layout, not a shadowed variable. (Absence of a gap
                // is the `storage-gap` detector's job, not this one.)
                if is_storage_gap_reservation(v) {
                    continue;
                }
                if !reported.insert(v.name.as_str()) {
                    continue;
                }
                let b = report!(self, Category::ShadowedStateVar,
                    title = "Child contract state variable shadows a base state variable",
                    severity = Severity::Low,
                    confidence = 0.55,
                    dimensions = [Dimension::Invariant],
                    message = format!(
                        "`{}` declares state variable `{}`, which is already declared by one of its base \
                         contracts. The child's declaration is a separate variable that shadows the base's: \
                         base methods read/write the base slot while child methods use the child slot, so the \
                         two same-named variables can hold different values. In inherited / upgradeable \
                         layouts this silently desynchronizes state (SWC-119).",
                        c.name, v.name
                    ),
                    recommendation =
                        "Remove the duplicate declaration and use the inherited variable, or rename one of \
                         them so the base and child slots are distinct and unambiguous.",
                );
                // Contract-level finding: no single function is responsible, so
                // build the location directly from `Scir` (mirrors `storage_gap`).
                out.push(b.at(cx.scir, c.name.clone(), String::new(), v.span).build());
            }
        }

        out
    }
}

// --------------------------------------------------------------------- helpers

/// All state-variable names visible *inside* `c` by bare name: `c`'s own plus
/// every (transitive) base contract's. A parameter/local named like any of these
/// shadows it.
fn in_scope_state_vars(cx: &AnalysisContext, c: &Contract) -> HashSet<String> {
    let mut names: HashSet<String> = c.state_vars.iter().map(|v| v.name.clone()).collect();
    names.extend(base_state_vars(cx, c));
    names
}

/// State-variable names declared by `c`'s (transitive) base contracts, excluding
/// `c`'s own declarations. Walks the inheritance graph by base *name* (the only
/// link the IR records), guarding against cycles / missing bases.
fn base_state_vars(cx: &AnalysisContext, c: &Contract) -> HashSet<String> {
    let mut names = HashSet::new();
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(c.name.clone());
    let mut stack: Vec<String> = c.bases.clone();
    while let Some(base) = stack.pop() {
        if !visited.insert(base.clone()) {
            continue; // already expanded (cycle / diamond) — skip.
        }
        let Some(bc) = cx.scir.contract_named(&base) else { continue };
        for v in &bc.state_vars {
            names.insert(v.name.clone());
        }
        for b in &bc.bases {
            if !visited.contains(b) {
                stack.push(b.clone());
            }
        }
    }
    names
}

/// Is `v` an OpenZeppelin-style storage-gap reservation — a `private`,
/// fixed-size array named `__gap` / `_gap`? Upgradeable contracts reserve one
/// such padding slot *per inheritance level*, so the same `__gap` name recurring
/// in a base and a child is the intended layout, not a shadowed variable.
fn is_storage_gap_reservation(v: &StateVar) -> bool {
    let n = v.name.to_ascii_lowercase();
    (n == "__gap" || n == "_gap")
        && v.visibility == Visibility::Private
        && v.ty.contains('[') // a fixed-size array reservation (`uint256[N]`).
}

/// Names `x` written through an explicit `this.x = ...` (member-qualified)
/// assignment anywhere in `f`'s body. These reach the state variable
/// unambiguously, so a same-name parameter/local is the intended,
/// already-disambiguated setter/initializer idiom and is not a silent shadow.
fn this_qualified_writes(f: &Function) -> HashSet<String> {
    let mut names = HashSet::new();
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            if let ExprKind::Assign { op: AssignOp::Assign, target, .. } = &e.kind {
                if let ExprKind::Member { base, member } = &target.kind {
                    if matches!(&base.kind, ExprKind::Ident(n) if n == "this") {
                        names.insert(member.clone());
                    }
                }
            }
        });
    }
    names
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fired(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "shadowed-state-var")
    }
    fn count(src: &str) -> usize {
        run(src).iter().filter(|f| f.detector == "shadowed-state-var").count()
    }

    // Shape A (param shadows own-contract state var) AND Shape B (child shadows
    // base) both present — the canonical SWC-119 shapes.
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        contract Base {
            address public owner;
            uint256 public total;
        }
        contract Vault is Base {
            // Shape B: re-declares the inherited `owner` slot.
            address public owner;
            uint256 public fee;
            // Shape A: parameter `fee` shadows the state variable `fee`.
            function setFee(uint256 fee) external {
                fee = fee; // hits the local; storage `fee` never changes.
            }
            // Shape A via inherited state var: local `total` shadows Base.total.
            function tally() external view returns (uint256) {
                uint256 total = 7;
                return total;
            }
        }
    "#;

    // Safe: no parameter/local collides with any state variable (trailing-`_`
    // convention) and no child re-declares a base variable.
    const SAFE: &str = r#"
        pragma solidity ^0.8.20;
        contract Base {
            address public owner;
        }
        contract Vault is Base {
            uint256 public fee;
            function setFee(uint256 fee_) external {
                fee = fee_;
            }
            function whoami() external view returns (address) {
                return owner;
            }
        }
    "#;

    // Safe form (suppressed, kept Low): the disambiguated `this.x = x`
    // initializer idiom. The `this.`-qualified write reaches the state variable,
    // so the same-name parameter is intentional and must NOT fire.
    const SAFE_THIS_QUALIFIED: &str = r#"
        pragma solidity ^0.8.20;
        contract Conf {
            address public owner;
            uint256 public fee;
            function configure(address owner, uint256 fee) external {
                this.owner = owner;
                this.fee = fee;
            }
        }
    "#;

    // Safe form (suppressed, kept Low): the OpenZeppelin per-level storage-gap
    // convention. Both base and child reserve their OWN `uint256[N] private
    // __gap;` padding slot — the recurring name is intended layout, not a
    // shadowed variable. Must NOT fire (that absence-of-gap concern belongs to
    // the `storage-gap` detector).
    const SAFE_PER_LEVEL_GAP: &str = r#"
        pragma solidity ^0.8.20;
        contract BaseUpg {
            uint256 public x;
            uint256[50] private __gap;
        }
        contract ChildUpg is BaseUpg {
            uint256 public y;
            uint256[49] private __gap;
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        assert!(fired(VULN), "{:?}", run(VULN));
    }

    #[test]
    fn fires_on_each_shape() {
        // setFee param shadow (A) + tally local shadow of inherited (A) +
        // child `owner` re-decl (B) = 3 distinct findings.
        assert_eq!(count(VULN), 3, "{:?}", run(VULN));
    }

    #[test]
    fn silent_on_safe() {
        assert!(!fired(SAFE), "{:?}", run(SAFE));
    }

    #[test]
    fn silent_on_this_qualified_setter() {
        assert!(!fired(SAFE_THIS_QUALIFIED), "{:?}", run(SAFE_THIS_QUALIFIED));
    }

    #[test]
    fn silent_on_per_level_storage_gap() {
        assert!(!fired(SAFE_PER_LEVEL_GAP), "{:?}", run(SAFE_PER_LEVEL_GAP));
    }
}
