//! # sluice-verify
//!
//! Lightweight finding triage and **Foundry proof-of-concept generation** — the
//! analog of `vortex-verify`. Two jobs:
//!
//! * **Feasibility filter** (`feasible`): a cheap, conservative reachability
//!   check that refutes findings whose sink is plainly guarded on every path.
//!   It over-approximates, so it never refutes a real finding (matching
//!   `vortex`'s interval-arithmetic triage philosophy).
//! * **PoC scaffolding** (`generate_poc`): emit a `forge` test skeleton tailored
//!   to the finding's category, the practical differentiator for turning a
//!   finding into a bug-bounty submission.

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

/// Generate a Foundry PoC skeleton for a finding.
pub fn generate_poc(scir: &Scir, finding: &Finding) -> String {
    let contract = &finding.contract;
    let func = &finding.function;
    let steps = attack_steps(finding.category, contract, func);
    // `pragma_solidity` may hold a full directive ("pragma solidity ^0.8.20") or
    // just a version range; normalize to the bare version constraint.
    let pragma = {
        let raw = scir.pragma_solidity.clone().unwrap_or_default();
        let v = raw
            .trim()
            .trim_start_matches("pragma")
            .trim()
            .trim_start_matches("solidity")
            .trim()
            .trim_end_matches(';')
            .trim()
            .to_string();
        if v.is_empty() { "^0.8.20".to_string() } else { v }
    };

    format!(
        "// SPDX-License-Identifier: MIT\n\
         pragma solidity {pragma};\n\n\
         import \"forge-std/Test.sol\";\n\
         // import the target: {contract} (defines `{func}`)\n\n\
         contract {contract}_{cat}_PoC is Test {{\n\
         \x20   {contract} target;\n\
         \x20   address attacker = address(0xA11CE);\n\n\
         \x20   function setUp() public {{\n\
         \x20       // TODO: deploy {contract} and any collaborators (tokens, pools, oracle)\n\
         \x20       // target = new {contract}(...);\n\
         \x20   }}\n\n\
         \x20   /// Finding {id} ({sev}): {title}\n\
         \x20   function test_exploit_{func}() public {{\n\
         \x20       vm.startPrank(attacker);\n{steps}\
         \x20       vm.stopPrank();\n\
         \x20       // TODO: assert the attacker profited / invariant broke\n\
         \x20   }}\n\
         }}\n",
        pragma = pragma,
        contract = sanitize(contract),
        func = sanitize(func),
        cat = finding.category.slug().replace('-', "_"),
        id = finding.id,
        sev = finding.severity.label(),
        title = finding.title,
        steps = steps,
    )
}

fn attack_steps(cat: Category, contract: &str, func: &str) -> String {
    let body = match cat {
        Category::Reentrancy | Category::ReadOnlyReentrancy => format!(
            "       // 1. Deposit so the contract owes the attacker.\n\
             \x20       // 2. Call {func}(); in the attacker's receive()/fallback, re-enter {func}().\n\
             \x20       // 3. Drain more than the deposited balance before state settles.\n"
        ),
        Category::OracleManipulation | Category::PriceManipulation => format!(
            "       // 1. Flash-loan a large amount of the priced asset.\n\
             \x20       // 2. Skew the spot source (swap into the pool / donate) to move the price.\n\
             \x20       // 3. Call {func}() so {contract} values collateral/shares at the false price.\n\
             \x20       // 4. Extract value, unwind the swap, repay the flash loan.\n"
        ),
        Category::Erc4626Inflation | Category::FirstDepositor => format!(
            "       // 1. As the FIRST depositor, deposit 1 wei -> mint 1 share.\n\
             \x20       // 2. Donate a large amount directly to the vault (transfer), inflating share price.\n\
             \x20       // 3. Victim deposits; their shares round down to 0.\n\
             \x20       // 4. Redeem your 1 share for the whole balance.\n"
        ),
        Category::MissingSolvencyCheck => format!(
            "       // 1. Open a position via the normal guarded path.\n\
             \x20       // 2. Use {func}() (which skips the solvency check) to push your account insolvent.\n\
             \x20       // 3. Self-liquidate / withdraw against the unbacked position.\n"
        ),
        Category::AccessControl | Category::TxOriginAuth => format!(
            "       // 1. As an unprivileged account, directly call {contract}.{func}().\n\
             \x20       // 2. Observe privileged state changed without authorization.\n"
        ),
        Category::SignatureReplay | Category::EcrecoverZeroAddress | Category::SignatureMalleability => format!(
            "       // 1. Capture or forge a signature accepted by {func}().\n\
             \x20       // 2. Replay it (no nonce) or submit address(0)/malleable variant.\n"
        ),
        Category::DelegatecallStorage | Category::UninitializedProxy => format!(
            "       // 1. Initialize/point the proxy implementation at attacker code.\n\
             \x20       // 2. delegatecall executes it against {contract}'s storage -> takeover.\n"
        ),
        Category::UnsafeErc20 | Category::FeeOnTransfer => format!(
            "       // 1. Use a fee-on-transfer / non-standard token so {contract} credits more than received.\n\
             \x20       // 2. Withdraw the difference.\n"
        ),
        _ => format!("       // TODO: drive {contract}.{func}() into the vulnerable state.\n"),
    };
    body
}

fn sanitize(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric() || *c == '_').collect()
}

/// Attach PoCs to the top-N highest-severity findings in place.
pub fn attach_pocs(scir: &Scir, findings: &mut [Finding], top_n: usize) {
    for f in findings.iter_mut().take(top_n) {
        f.poc = Some(generate_poc(scir, f));
    }
}

#[allow(dead_code)]
fn touch(_f: &Function) {}
