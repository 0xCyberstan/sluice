//! Tier-3 trace-annotated stub — the long-tail / non-concrete fallback.
//!
//! Upgrades the historical comment-only skeleton: injects the real
//! `Function.signature`, a correctly-typed call, and the finding's `trace` steps
//! as `// step N:` comments. Not claimed to compile (no real assertions / mocks
//! for arbitrary categories), and the banner says so.

use crate::context::{normalize_pragma, sanitize_ident, PocContext, Tier};
use sluice_findings::Finding;
use sluice_ir::Scir;

/// Render the T3 stub. When `cx` is `Some` (a concrete contract we resolved but
/// for which no first-class template applies) we still import the real source
/// and emit a typed call; when `None` (interface/library/unresolved target) we
/// fall back to a name-only skeleton with no import.
pub fn render(scir: &Scir, finding: &Finding, cx: Option<&PocContext>) -> String {
    let pragma = normalize_pragma(scir.pragma_solidity.as_deref());
    let contract = sanitize_ident(&finding.contract);
    let func = sanitize_ident(&finding.function);
    let cat = finding.category.slug().replace('-', "_");

    // The real signature + typed call args when we have a resolved function.
    let (signature, call_args, import_line, deploy_line) = match cx {
        Some(c) => (
            if c.function.signature.is_empty() {
                format!("{}(...)", finding.function)
            } else {
                c.function.signature.clone()
            },
            c.call_args_str(),
            format!("import {{{contract}}} from \"{}\";\n", c.import_path),
            format!(
                "        // {ctor_comment}\n        // target = new {contract}({ctor_args});",
                ctor_comment = c.ctor_comment(),
                ctor_args = c.ctor_args_str(),
            ),
        ),
        None => (
            format!("{}(...)", finding.function),
            String::new(),
            format!("// import the target: {contract} (defines `{func}`) — resolve its path manually\n"),
            format!("        // TODO: deploy {contract} and any collaborators (tokens, pools, oracle)\n        // target = new {contract}(...);"),
        ),
    };

    // Trace steps as `// step N:` comments (the finding's real value-flow trace).
    let mut trace_block = String::new();
    if finding.trace.is_empty() {
        trace_block.push_str(&format!(
            "        // step 1: drive {contract}.{func}({call_args}) into the vulnerable state.\n"
        ));
    } else {
        for (i, t) in finding.trace.iter().enumerate() {
            trace_block.push_str(&format!(
                "        // step {}: {} — {}:{}  `{}`\n",
                i + 1,
                super::escape_comment(&t.label),
                t.file,
                t.line,
                super::escape_comment(&t.snippet),
            ));
        }
    }

    format!(
        "// SPDX-License-Identifier: MIT\n\
         // Sluice PoC — {banner}\n\
         // Generated statically by Sluice — Sluice never runs `forge`; you run `forge test`.\n\
         // Finding {id} ({sev}): {title}\n\
         // Target: {contract}.{func}  ({file}:{line})\n\
         // Vulnerable function signature: {signature}\n\
         pragma solidity {pragma};\n\n\
         import \"forge-std/Test.sol\";\n\
         {import_line}\n\
         contract {contract}_{cat}_PoC is Test {{\n\
         \x20   // {contract} target;\n\
         \x20   address attacker = makeAddr(\"attacker\");\n\n\
         \x20   function setUp() public {{\n\
         {deploy_line}\n\
         \x20   }}\n\n\
         \x20   /// Finding {id}: {title}\n\
         \x20   function test_exploit_{func}() public {{\n\
         \x20       vm.startPrank(attacker);\n\
         {trace_block}\
         \x20       // target.{func}({call_args});\n\
         \x20       vm.stopPrank();\n\
         \x20       // TODO: assert the attacker profited / the invariant broke.\n\
         \x20   }}\n\
         }}\n",
        banner = Tier::T3.banner(),
        id = finding.id,
        sev = finding.severity.label(),
        title = super::escape_comment(&finding.title),
        file = finding.file,
        line = finding.line,
    )
}
