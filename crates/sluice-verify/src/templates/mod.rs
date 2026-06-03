//! Per-family PoC templates behind a [`PocTemplate`] trait. `generate_poc`
//! dispatches by category to the first template that `applies`, falling back to
//! the T3 [`stub`] when nothing first-class matches or the target isn't concrete.

use crate::context::{PocContext, Tier};
use sluice_findings::Category;

pub mod access_control;
pub mod bridge;
pub mod erc4626;
pub mod oracle;
pub mod reentrancy;
pub mod stub;

/// A family template: decides whether it applies to a category, what tier the
/// concrete `PocContext` qualifies for, and renders the `.t.sol` body.
pub trait PocTemplate {
    /// Does this template handle the finding's category?
    fn applies(&self, cat: Category) -> bool;
    /// The honesty tier for this specific context (T1 if all inputs are concrete,
    /// T2 if a `/* FILL */` is required).
    fn tier(&self, cx: &PocContext) -> Tier;
    /// Render the full emitted Solidity test source.
    fn render(&self, cx: &PocContext) -> String;
}

/// The ordered list of first-class templates (excludes the always-last stub).
pub fn first_class() -> Vec<Box<dyn PocTemplate>> {
    vec![
        Box::new(reentrancy::ReentrancyTemplate),
        Box::new(access_control::AccessControlTemplate),
        Box::new(erc4626::Erc4626Template),
        Box::new(oracle::OracleTemplate),
        Box::new(bridge::BridgeTemplate),
    ]
}

/// The shared honesty-banner header every template stamps at the top of its
/// output (after the SPDX line). `tier` is the resolved tier for the finding.
pub fn header(cx: &PocContext, tier: Tier) -> String {
    let f = cx.finding;
    format!(
        "// SPDX-License-Identifier: MIT\n\
         // Sluice PoC — {banner}\n\
         // Generated statically by Sluice — Sluice never runs `forge`; you run `forge test`.\n\
         // Finding {id} ({sev}): {title}\n\
         // Target: {contract}.{function}  ({file}:{line})\n\
         pragma solidity {pragma};\n\n\
         import \"forge-std/Test.sol\";\n\
         import {{{ident}}} from \"{import_path}\";\n\n",
        banner = tier.banner(),
        id = f.id,
        sev = f.severity.label(),
        title = escape_comment(&f.title),
        contract = cx.contract.name,
        function = cx.function.name,
        file = cx.finding.file,
        line = cx.finding.line,
        pragma = cx.pragma,
        ident = cx.contract_ident,
        import_path = cx.import_path,
    )
}

/// Strip newlines / `*/` from a string so it is safe inside a `//` or `/* */`
/// comment.
pub fn escape_comment(s: &str) -> String {
    s.replace(['\n', '\r'], " ").replace("*/", "* /")
}
