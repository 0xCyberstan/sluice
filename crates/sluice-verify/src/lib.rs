//! # sluice-verify
//!
//! Lightweight finding triage and **real, compiling Foundry proof-of-concept
//! generation** — the analog of `vortex-verify`. Two jobs:
//!
//! * **Feasibility filter** (`feasible`): a cheap, conservative reachability
//!   check that refutes findings whose sink is plainly guarded on every path.
//!   It over-approximates, so it never refutes a real finding (matching
//!   `vortex`'s interval-arithmetic triage philosophy).
//! * **PoC generation** (`generate_poc`): emit a `forge` test tailored to the
//!   finding's category. For the first-class families (reentrancy, access
//!   control, ERC-4626 inflation, oracle, bridge) this is a *real, compiling*
//!   harness — imports the target by relative path, deploys it, builds an
//!   attacker contract where needed, and ends in a real assertion
//!   (`assertGt`/`assertLt`/`assertEq`/`expectRevert`). The long tail falls back
//!   to a trace-annotated stub. Sluice **never invokes `forge`** — it is
//!   static-only; it *emits* artifacts a human runs (`forge test`).
//!
//! ## Honesty tiers (recorded in `Finding.tags` + a header banner)
//! * **T1** — compiling exploit harness (valid given the target resolves its imports).
//! * **T2** — compiling skeleton + asserted hypothesis (fill the `/* FILL */` constants).
//! * **T3** — trace-annotated stub (not claimed to compile).

mod context;
mod project;
mod templates;

pub use context::{PocContext, Tier};

use sluice_findings::{Category, Finding};
use sluice_ir::{Function, Scir};

/// Conservative feasibility check. Returns `false` only when we can show the
/// flagged function is unreachable / fully guarded; otherwise `true`.
pub fn feasible(scir: &Scir, finding: &Finding) -> bool {
    // Find the function by (contract, name).
    let func = scir.all_functions().find(|f| {
        f.name == finding.function
            && scir.contract(f.contract).map(|c| c.name == finding.contract).unwrap_or(false)
    });
    let Some(f) = func else {
        return true; // can't locate → don't refute
    };
    // The only refutation we make: an unreachable (non-external, never-called)
    // private function can't be triggered by an attacker for attacker-input
    // categories.
    if needs_attacker_reachability(finding.category)
        && !f.is_externally_reachable()
        && f.callers.is_empty()
    {
        return false;
    }
    true
}

fn needs_attacker_reachability(cat: Category) -> bool {
    matches!(
        cat,
        Category::Reentrancy
            | Category::OracleManipulation
            | Category::PriceManipulation
            | Category::AccessControl
            | Category::SignatureReplay
            | Category::FlashLoanGovernance
    )
}

/// Resolve the honesty tier a finding's PoC would carry (without rendering it).
/// `T3` when no first-class template applies or the target isn't concrete.
pub fn poc_tier(scir: &Scir, finding: &Finding) -> Tier {
    match context::poc_context(scir, finding) {
        Some(cx) => templates::first_class()
            .iter()
            .find(|t| t.applies(finding.category))
            .map(|t| t.tier(&cx))
            .unwrap_or(Tier::T3),
        None => Tier::T3,
    }
}

/// Generate a Foundry PoC for a finding. Dispatches by category to the first
/// matching first-class template (reentrancy / access-control / ERC-4626 /
/// oracle / bridge); falls back to the trace-annotated T3 stub when no template
/// applies or the target isn't a concrete contract.
pub fn generate_poc(scir: &Scir, finding: &Finding) -> String {
    match context::poc_context(scir, finding) {
        Some(cx) => {
            for t in templates::first_class() {
                if t.applies(finding.category) {
                    return t.render(&cx);
                }
            }
            // Concrete contract but a non-first-class category → T3 stub *with*
            // the real import + typed call.
            templates::stub::render(scir, finding, Some(&cx))
        }
        // Interface/library/unresolved target → name-only T3 stub.
        None => templates::stub::render(scir, finding, None),
    }
}

/// Attach PoCs to the top-N highest-severity findings in place, tagging each with
/// its honesty tier (`poc:tier1|tier2|tier3`). Findings are assumed already
/// sorted by severity_score (the engine sorts before id assignment), so PoC
/// budget is spent on the strongest findings first.
pub fn attach_pocs(scir: &Scir, findings: &mut [Finding], top_n: usize) {
    for f in findings.iter_mut().take(top_n) {
        let tier = poc_tier(scir, f);
        let tag = tier.tag();
        if !f.tags.iter().any(|t| t == tag) {
            f.tags.push(tag.to_string());
        }
        f.poc = Some(generate_poc(scir, f));
    }
}

/// Emit a self-contained Foundry skeleton project to `out_dir/sluice-poc/`:
/// `foundry.toml`, `remappings.txt`, `README.md`, and one
/// `test/F-XXX_<slug>.t.sol` per PoC'd finding. The README states each PoC's
/// tier and the honesty banner. Returns the list of files written.
///
/// This is the *project* form of [`generate_poc`]; it does not run `forge`.
pub fn emit_poc_project(
    scir: &Scir,
    findings: &[Finding],
    out_dir: &std::path::Path,
    top_n: usize,
) -> std::io::Result<Vec<std::path::PathBuf>> {
    project::emit(scir, findings, out_dir, top_n)
}

#[allow(dead_code)]
fn touch(_f: &Function) {}
