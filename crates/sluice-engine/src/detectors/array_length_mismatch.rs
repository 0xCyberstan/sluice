//! Array-length-mismatch in batch / airdrop / multicall functions.
//!
//! A function that accepts **two or more dynamic-array parameters** and then
//! indexes more than one of them inside a loop (`a[i]`, `b[i]`) is unsafe unless
//! it first requires the arrays to be the same length. If a caller passes arrays
//! of different lengths the loop either:
//!   * silently truncates to the shorter array (the longer array's tail is
//!     dropped — e.g. recipients credited with no amount, or amounts paid to no
//!     one), or
//!   * indexes past the end of the shorter array and reverts out-of-bounds
//!     (griefing / wasted gas), or
//!   * mis-pairs data when one array is built from another with a stale length.
//!
//! This is the classic `airdrop(recipients, amounts)` / `batchTransfer(to, ids,
//! amounts)` footgun. The canonical fix is a single
//! `require(a.length == b.length)` at the top of the function.
//!
//! ## Detection
//! Flag a function with `>= 2` array-typed parameters (parameter `ty` contains
//! `"[]"`) whose body contains a loop that indexes **two or more distinct array
//! parameters** by a subscript (`param[expr]`), when the function source does
//! **not** contain a length-equality comparison (`.length ==` / `.length !=`) or
//! a `LengthMismatch` revert.
//!
//! ## False-positive suppression (precision first)
//!   * Suppress when the source contains a `.length ==` / `.length !=` comparison
//!     or a `LengthMismatch`-style custom error/revert — the guard is present.
//!   * Suppress when only one array parameter is actually indexed in a loop
//!     (single-array iteration cannot mismatch).
//!
//! Confidence is kept modest (0.5): this is a syntactic heuristic and the
//! equality guard could in principle be expressed in a form we don't recognize,
//! or the arrays could be independent (not co-indexed by the same index).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{ExprKind, Function, Span, Stmt, StmtKind};
use std::collections::HashSet;

pub struct ArrayLengthMismatchDetector;

impl Detector for ArrayLengthMismatchDetector {
    fn id(&self) -> &'static str {
        "array-length-mismatch"
    }
    fn category(&self) -> Category {
        Category::ArrayLengthMismatch
    }
    fn description(&self) -> &'static str {
        "Batch/airdrop function co-indexes 2+ array params in a loop without requiring equal lengths"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Batch entry points are externally reachable and state-mutating;
            // a pure view that reads mismatched arrays is not a value bug.
            if !f.is_externally_reachable() || !f.is_state_mutating() {
                continue;
            }

            // (1) Collect the names of the dynamic-array parameters. We need two
            //     or more to even have a mismatch.
            let array_params: HashSet<&str> = f
                .params
                .iter()
                .filter(|p| p.ty.contains("[]"))
                .filter_map(|p| p.name.as_deref())
                .collect();
            if array_params.len() < 2 {
                continue;
            }

            // (2) The function must loop and co-index two or more of those array
            //     parameters within the loop body.
            let indexed = indexed_array_params_in_loops(f, &array_params);
            if indexed.len() < 2 {
                continue;
            }

            // (3) FP suppression: a length-equality guard (or a LengthMismatch
            //     revert) is present in the source.
            if source_requires_equal_lengths(cx.scir.span_text(f.span)) {
                continue;
            }

            // Locate the finding at the first co-indexing site inside a loop.
            let span = first_coindex_span(f, &array_params).unwrap_or(f.span);

            // Two or more *named* array parameters listed for the message.
            let mut names: Vec<&str> = indexed.iter().copied().collect();
            names.sort_unstable();
            let arrays = names.join("`, `");

            let b = FindingBuilder::new(self.id(), Category::ArrayLengthMismatch)
                .title("Parallel arrays indexed in a loop without an equal-length check")
                .severity(Severity::Medium)
                .confidence(0.5)
                // Invariant: the implicit "the parallel arrays are the same
                // length" precondition is never asserted before the loop.
                .dimension(Dimension::Invariant)
                .message(format!(
                    "`{}` takes multiple array parameters (`{}`) and indexes more than one of them \
                     together in a loop without first requiring their lengths to be equal. If a \
                     caller passes arrays of different lengths the loop silently truncates to the \
                     shorter one (dropping or mis-pairing the tail) or reverts out-of-bounds — the \
                     classic airdrop/batch-transfer length-mismatch footgun (CWE-129).",
                    f.name, arrays
                ))
                .recommendation(
                    "Add `require(a.length == b.length, \"length mismatch\")` (one check per extra \
                     array) at the top of the function so mismatched inputs revert deterministically.",
                );
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

// ------------------------------------------------------------------- helpers

/// The set of array-parameter names that are subscripted (`param[expr]`) inside
/// at least one loop body. Only names present in `array_params` are counted, and
/// indexing must occur *within a loop* (a one-off `a[0]` outside a loop is not
/// the co-iteration pattern we target).
fn indexed_array_params_in_loops<'a>(f: &'a Function, array_params: &HashSet<&'a str>) -> HashSet<&'a str> {
    let mut found: HashSet<&'a str> = HashSet::new();
    for s in &f.body {
        visit_loops(s, &mut |loop_body| {
            for ls in loop_body {
                ls.visit_exprs(&mut |e| {
                    if let ExprKind::Index { base, index: Some(_) } = &e.kind {
                        if let Some(name) = base.simple_name() {
                            if let Some(p) = array_params.get(name) {
                                found.insert(*p);
                            }
                        }
                    }
                });
            }
        });
    }
    found
}

/// Span of the first subscript on an array parameter inside a loop (best-effort
/// location for the finding).
fn first_coindex_span(f: &Function, array_params: &HashSet<&str>) -> Option<Span> {
    let mut span: Option<Span> = None;
    for s in &f.body {
        visit_loops(s, &mut |loop_body| {
            for ls in loop_body {
                ls.visit_exprs(&mut |e| {
                    if span.is_some() {
                        return;
                    }
                    if let ExprKind::Index { base, index: Some(_) } = &e.kind {
                        if let Some(name) = base.simple_name() {
                            if array_params.contains(name) {
                                span = Some(e.span);
                            }
                        }
                    }
                });
            }
        });
    }
    span
}

/// Invoke `f` with the body of every loop (`for`/`while`/`do-while`) reachable
/// from `s`, including loops nested inside other statements.
fn visit_loops<'a>(s: &'a Stmt, f: &mut impl FnMut(&'a [Stmt])) {
    s.visit(&mut |inner| match &inner.kind {
        StmtKind::For { body, .. }
        | StmtKind::While { body, .. }
        | StmtKind::DoWhile { body, .. } => f(body),
        _ => {}
    });
}

/// True if the source text carries a length-equality guard (or a
/// `LengthMismatch`-style revert) that would make the mismatch revert. We strip
/// ASCII whitespace so both `a.length == b.length` and `a.length==b.length`
/// match, and lowercase so `LengthMismatch` / `lengthMismatch` are caught.
fn source_requires_equal_lengths(src: &str) -> bool {
    let lower = src.to_ascii_lowercase();
    if lower.contains("lengthmismatch") {
        return true;
    }
    let compact: String = lower.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    // `.length ==` / `length ==` / `.length !=` / `length !=`, with or without
    // spaces — the canonical parallel-array precondition.
    compact.contains("length==") || compact.contains("length!=")
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Airdrop co-indexes `recipients` and `amounts` in a loop with NO equal-length
    // check — mismatched arrays silently truncate or revert out-of-bounds.
    const VULN: &str = r#"
pragma solidity ^0.8.20;
contract Airdrop {
    mapping(address => uint256) public credited;
    function airdrop(address[] calldata recipients, uint256[] calldata amounts) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            credited[recipients[i]] += amounts[i];
        }
    }
}
"#;

    // Same shape, but a leading `require(... .length == ... .length)` enforces the
    // precondition, so a mismatch reverts deterministically.
    const SAFE: &str = r#"
pragma solidity ^0.8.20;
contract Airdrop {
    mapping(address => uint256) public credited;
    function airdrop(address[] calldata recipients, uint256[] calldata amounts) external {
        require(recipients.length == amounts.length, "len");
        for (uint256 i = 0; i < recipients.length; i++) {
            credited[recipients[i]] += amounts[i];
        }
    }
}
"#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "array-length-mismatch"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "array-length-mismatch"));
    }
}
