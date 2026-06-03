//! Floating (unpinned) `pragma solidity` directive — SWC-103.
//!
//! A source unit whose version pragma is **unpinned** compiles under a *range*
//! of compiler versions rather than one fixed release:
//!
//!   * a **caret** range — `pragma solidity ^0.8.20;` (any `0.8.x >= 0.8.20`);
//!   * an **open / comparator** range — `pragma solidity >=0.7.0 <0.9.0;` or a
//!     bare `pragma solidity >0.8.0;`.
//!
//! The hazard is reproducibility and review-integrity, not a runtime exploit: the
//! contract a team audits, tests, and deploys can each be built by a *different*
//! `solc` within the allowed window, so a compiler bug, a changed codegen
//! default, or a behavioural difference between two admitted versions silently
//! ships code that was never the code under review. The canonical guidance
//! (Consensys SWC-103, and `solhint`'s `compiler-version` / `not-rely-on-time`
//! family) is to **pin** the pragma to one exact version for any contract
//! intended for deployment: `pragma solidity 0.8.20;` (an implicit `=`), or the
//! explicit `pragma solidity =0.8.20;`.
//!
//! A range that admits a pre-`0.8.0` compiler (`<0.8.0`, `^0.7.x`, `>=0.6 <0.8`)
//! is flagged at *slightly higher* confidence: those releases lack the built-in
//! checked arithmetic of `0.8.0`, so an unpinned-below-0.8 pragma additionally
//! carries an implicit overflow/underflow risk if it ever resolves to such a
//! compiler.
//!
//! ## Why this is correct to fire broadly
//!
//! This is a *canonical-baseline* (table-stakes) lint, not a novel-bug detector:
//! it should fire on **every** source unit that genuinely carries an unpinned
//! pragma — that breadth is the expected, correct behaviour, not noise. It ships
//! at **Info** severity with modest confidence so it never outranks a real
//! value finding.
//!
//! ## Precision — the safe form is suppressed
//!
//!   * A **pinned** pragma is silent. Pinned means a single exact version, with
//!     or without a leading `=`: `pragma solidity 0.8.20;` and
//!     `pragma solidity =0.8.20;` both suppress. (A bare `0.8.20` is Solidity's
//!     implicit-`=` exact pin.)
//!   * A source unit with **no** `pragma solidity` directive at all (an
//!     interface-only `.sol`, an `abicoder`/`experimental`-only file) is silent —
//!     there is no unpinned version constraint to flag.
//!   * `pragma abicoder v2;` / `pragma experimental ...;` are not version
//!     pragmas and never match.
//!
//! ## Reporting granularity
//!
//! At most **one** finding per source unit (per file), located on the pragma
//! line. The per-file path is recorded as the finding's `contract` slot so each
//! file is its own de-dup / cap bucket (file-level findings carry no function),
//! which is what lets the lint surface the genuine per-file breadth instead of
//! collapsing many same-line pragmas into one. The task also asks for the
//! pinned-vs-floating split per codebase; that is a reporting concern computed
//! from the set of findings (one per floating file) against the file total.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report; // the prelude's declarative reporting macro
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::Span;

pub struct FloatingPragmaDetector;

impl Detector for FloatingPragmaDetector {
    fn id(&self) -> &'static str {
        "floating-pragma"
    }
    fn category(&self) -> Category {
        Category::FloatingPragma
    }
    fn description(&self) -> &'static str {
        "Unpinned (floating) `pragma solidity` version — pin to one exact compiler version (SWC-103)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        // One source unit = one file. The single corpus-wide `cx.scir.pragma_solidity`
        // only captures the *first* pragma seen across all files, so to fire per
        // source unit (and to compute the pinned-vs-floating split) we read each
        // file's own `pragma solidity` directive from its source text. The captured
        // `cx.scir.pragma_solidity` is consulted as the fallback for the (rare) file
        // whose own directive the scan does not locate but which the parser did read.
        for (file_idx, sf) in cx.scir.files.iter().enumerate() {
            let Some(p) = find_solidity_pragma(&sf.content) else {
                // No version pragma in this file's own text. As a last resort use the
                // corpus-captured pragma *only* when there is exactly one file (so we
                // do not mis-attribute another file's pragma to this one).
                if cx.scir.files.len() == 1 {
                    if let Some(raw) = cx.scir.pragma_solidity.as_deref() {
                        if let Some(c) = classify_constraint(&strip_pragma_prefix(raw)) {
                            out.push(self.finding(cx, &sf.path, Span::dummy(), &c));
                        }
                    }
                }
                continue;
            };

            // `p.constraint` is the version-constraint text (everything between
            // `solidity` and `;`). Pinned ⇒ suppress; floating ⇒ one finding.
            let Some(c) = classify_constraint(&p.constraint) else {
                continue;
            };

            let span = Span::new(file_idx as u32, p.start as u32, p.end as u32);
            out.push(self.finding(cx, &sf.path, span, &c));
        }

        out
    }
}

impl FloatingPragmaDetector {
    fn finding(&self, cx: &AnalysisContext, path: &str, span: Span, c: &Floating) -> Finding {
        // Confidence stays modest (Info-tier hygiene) so this never outranks a real
        // value finding. A range that can resolve below 0.8.0 gets a small bump
        // because it additionally carries the implicit-overflow risk.
        let confidence = if c.below_0_8 { 0.5 } else { 0.4 };

        let kind = if c.below_0_8 {
            "an unpinned version range that can resolve to a pre-0.8.0 compiler (which lacks \
             built-in overflow/underflow checks)"
        } else if c.is_caret {
            "a caret (`^`) version range"
        } else {
            "an open comparator (`>=` / `>` / `<`) version range"
        };

        let b = report!(self, Category::FloatingPragma,
            title = "Floating (unpinned) Solidity pragma",
            severity = Severity::Info,
            confidence = confidence,
            dimensions = [Dimension::Invariant],
            message = format!(
                "`{path}` declares `pragma solidity {constraint};` — {kind}. The contract that is \
                 audited, tested, and deployed can each be built by a *different* `solc` within the \
                 allowed window, so a compiler bug or changed codegen default can silently ship code \
                 that was never the code under review (SWC-103). Pin the pragma to one exact \
                 compiler version for any contract intended for deployment.",
                path = path,
                constraint = c.text.trim(),
                kind = kind,
            ),
            recommendation =
                "Pin the version pragma to a single exact release, e.g. `pragma solidity 0.8.20;` \
                 (an implicit `=`) or `pragma solidity =0.8.20;`, matching the compiler the code is \
                 audited and deployed with. Libraries meant for downstream reuse may keep a range, \
                 but deployable contracts should pin.",
        );

        // File-level finding: there is no function. Record the file path in the
        // `contract` slot so each source unit is its own de-dup key
        // (`floating-pragma | <path> | "" | <line>`) and its own cap bucket — this
        // is what preserves the per-file breadth instead of collapsing every
        // same-line pragma into one. `at(..)` resolves file/line/snippet from the
        // span; a dummy span (the single-file fallback) leaves them at the file head.
        b.at(cx.scir, path.to_string(), String::new(), span).build()
    }
}

/// A classified floating constraint.
struct Floating {
    /// The original constraint text (for the message), e.g. `^0.8.20`.
    text: String,
    /// True if it is a caret (`^`) range.
    is_caret: bool,
    /// True if the range can resolve to a pre-0.8.0 compiler (implicit-overflow risk).
    below_0_8: bool,
}

/// Classify a version-constraint string (the text after `pragma solidity`).
/// Returns `Some(Floating)` for an unpinned constraint (caret or open range),
/// `None` for a pinned exact version (`0.8.20` / `=0.8.20`) — the safe form.
fn classify_constraint(constraint: &str) -> Option<Floating> {
    let t = constraint.trim();
    if t.is_empty() {
        return None;
    }

    let is_caret = t.contains('^');
    // An open / comparator range: `>=`, `<=`, `>`, `<`. (`=` alone is a pin.)
    let has_range = t.contains('>') || t.contains('<');
    // A multi-clause `||` union (`0.7.6 || 0.8.20`) is also not a single pin.
    let is_union = t.contains("||");

    if !is_caret && !has_range && !is_union {
        // A single clause with no caret / comparator / union. This is a pinned
        // exact version, with or without a leading `=`: `0.8.20`, `=0.8.20`,
        // `v0.8.20`. The safe form — suppress.
        return None;
    }

    Some(Floating {
        text: t.to_string(),
        is_caret,
        below_0_8: range_admits_below_0_8(t),
    })
}

/// Best-effort: does the (floating) constraint admit a compiler **below 0.8.0**?
/// Scans every `<minor>` that follows a `0.` in the constraint and reports true
/// if any admitted minor is `< 8`. Conservative for the message bump only:
///   * `^0.8.20` -> the lowest admitted is 0.8.20, not below 0.8 -> false.
///   * `^0.7.6`  -> 0.7.x -> true.
///   * `>=0.6.0 <0.8.0` -> mentions 0.6 -> true.
///   * `>=0.8.0 <0.9.0` -> only 0.8 / 0.9 -> false.
fn range_admits_below_0_8(t: &str) -> bool {
    let bytes = t.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'0' && bytes[i + 1] == b'.' {
            // Parse the minor digits after `0.`.
            let mut j = i + 2;
            let mut minor: u32 = 0;
            let mut any = false;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                minor = minor.saturating_mul(10).saturating_add((bytes[j] - b'0') as u32);
                j += 1;
                any = true;
            }
            if any && minor < 8 {
                return true;
            }
            i = j;
            continue;
        }
        i += 1;
    }
    false
}

/// A located `pragma solidity` directive within a file's source text.
struct PragmaHit {
    /// The version-constraint text (between `solidity` and `;`).
    constraint: String,
    /// Byte offset of the start of the directive (`pragma`) within the file.
    start: usize,
    /// Byte offset just past the terminating `;`.
    end: usize,
}

/// Locate the first `pragma solidity <constraint>;` directive in `src`, skipping
/// `//` line comments and `/* */` block comments so a commented-out pragma is not
/// matched. Returns `None` if there is no version pragma (an interface-only file,
/// or a file with only `pragma abicoder v2;` / `pragma experimental ...;`).
fn find_solidity_pragma(src: &str) -> Option<PragmaHit> {
    let b = src.as_bytes();
    let n = b.len();
    let mut i = 0;
    while i < n {
        // Skip comments so a `// pragma solidity ^0.8.0;` is never matched.
        if b[i] == b'/' && i + 1 < n && b[i + 1] == b'/' {
            i += 2;
            while i < n && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b[i] == b'/' && i + 1 < n && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < n && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(n);
            continue;
        }

        // Match the keyword `pragma` on a word boundary.
        if matches_kw(b, i, b"pragma") {
            let dir_start = i;
            let mut k = i + 6;
            k = skip_ws(b, k, n);
            // The next word must be `solidity` (skip `abicoder` / `experimental`).
            if matches_kw(b, k, b"solidity") {
                let mut c = k + 8;
                // Capture everything up to the terminating `;`.
                let cs = c;
                while c < n && b[c] != b';' {
                    c += 1;
                }
                if c < n {
                    let constraint = src.get(cs..c).unwrap_or("").trim().to_string();
                    return Some(PragmaHit { constraint, start: dir_start, end: c + 1 });
                }
                return None; // malformed (no `;`) — nothing to flag
            }
            // A non-`solidity` pragma; keep scanning past it.
            i = k;
            continue;
        }
        i += 1;
    }
    None
}

/// Does `kw` occur at `b[i..]` as a whole word (not a prefix of a longer ident)?
fn matches_kw(b: &[u8], i: usize, kw: &[u8]) -> bool {
    if i + kw.len() > b.len() {
        return false;
    }
    if &b[i..i + kw.len()] != kw {
        return false;
    }
    // Preceding char must not be an identifier char.
    if i > 0 && is_ident_byte(b[i - 1]) {
        return false;
    }
    // Following char must not be an identifier char.
    let after = i + kw.len();
    if after < b.len() && is_ident_byte(b[after]) {
        return false;
    }
    true
}

fn is_ident_byte(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric()
}

fn skip_ws(b: &[u8], mut i: usize, n: usize) -> usize {
    while i < n && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Strip a leading `pragma solidity` (and surrounding whitespace / trailing `;`)
/// from a raw captured pragma string, leaving just the version constraint. Used
/// only for the single-file `cx.scir.pragma_solidity` fallback path.
fn strip_pragma_prefix(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("pragma")
        .trim()
        .trim_start_matches("solidity")
        .trim()
        .trim_end_matches(';')
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fired(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "floating-pragma")
    }

    // FIRES — a caret (unpinned) pragma.
    const UNSAFE_CARET: &str = r#"
        pragma solidity ^0.8.20;
        contract A { uint256 x; function f() external { x = 1; } }
    "#;

    // SILENT — a pinned exact version (the safe form).
    const SAFE_PINNED: &str = r#"
        pragma solidity 0.8.20;
        contract A { uint256 x; function f() external { x = 1; } }
    "#;

    // SILENT — an explicitly-`=`-pinned version (also safe).
    const SAFE_PINNED_EQ: &str = r#"
        pragma solidity =0.8.20;
        contract A { uint256 x; function f() external { x = 1; } }
    "#;

    #[test]
    fn fires_on_caret() {
        assert!(fired(UNSAFE_CARET), "{:?}", run(UNSAFE_CARET));
    }

    #[test]
    fn silent_on_pinned() {
        assert!(!fired(SAFE_PINNED));
    }

    #[test]
    fn silent_on_explicit_eq_pin() {
        assert!(!fired(SAFE_PINNED_EQ));
    }

    #[test]
    fn fires_on_open_range() {
        assert!(fired(
            "pragma solidity >=0.7.0 <0.9.0;\ncontract A { function f() external {} }"
        ));
    }

    #[test]
    fn fires_on_caret_below_0_8_with_overflow_note_and_higher_conf() {
        let fs = run("pragma solidity ^0.7.6;\ncontract A { function f() external {} }");
        let f = fs.iter().find(|f| f.detector == "floating-pragma").expect("fires");
        // The below-0.8 bump: confidence 0.5 and an overflow note in the message.
        assert!((f.confidence - 0.5).abs() < 1e-6, "confidence={}", f.confidence);
        assert!(f.message.contains("overflow"), "{}", f.message);
    }

    #[test]
    fn caret_at_0_8_is_not_flagged_as_below_0_8() {
        let fs = run(UNSAFE_CARET);
        let f = fs.iter().find(|f| f.detector == "floating-pragma").expect("fires");
        assert!((f.confidence - 0.4).abs() < 1e-6, "confidence={}", f.confidence);
        assert!(!f.message.contains("overflow"), "{}", f.message);
    }

    #[test]
    fn at_most_one_per_file() {
        // Two contracts, one file, one pragma -> exactly one floating-pragma finding.
        let src = r#"
            pragma solidity ^0.8.20;
            contract A { function f() external {} }
            contract B { function g() external {} }
        "#;
        let count = run(src).iter().filter(|f| f.detector == "floating-pragma").count();
        assert_eq!(count, 1, "{:?}", run(src));
    }

    #[test]
    fn silent_when_no_version_pragma() {
        // No `pragma solidity` directive at all.
        assert!(!fired("contract A { function f() external {} }"));
        // Only a non-version pragma.
        assert!(!fired(
            "pragma abicoder v2;\ncontract A { function f() external {} }"
        ));
    }

    #[test]
    fn commented_out_pragma_is_ignored() {
        // A commented pragma is the only `pragma solidity` text -> must stay silent.
        assert!(!fired(
            "// pragma solidity ^0.8.0;\npragma solidity 0.8.20;\ncontract A { function f() external {} }"
        ));
    }

    #[test]
    fn fires_per_file_across_a_multi_file_codebase() {
        // Distinct files each with a floating pragma -> one finding per file (the
        // per-file `contract`=path discriminator keeps them from de-duping by line).
        let res = analyze_sources(
            vec![
                ("a.sol".into(), "pragma solidity ^0.8.20;\ncontract A { function f() external {} }".into()),
                ("b.sol".into(), "pragma solidity ^0.8.19;\ncontract B { function g() external {} }".into()),
                ("c.sol".into(), "pragma solidity 0.8.20;\ncontract C { function h() external {} }".into()),
            ],
            &Config::default(),
        );
        let hits: Vec<_> = res.findings.iter().filter(|f| f.detector == "floating-pragma").collect();
        // a.sol + b.sol float; c.sol is pinned (silent).
        assert_eq!(hits.len(), 2, "{:?}", hits);
        assert!(hits.iter().any(|f| f.file == "a.sol"));
        assert!(hits.iter().any(|f| f.file == "b.sol"));
        assert!(!hits.iter().any(|f| f.file == "c.sol"));
    }

    #[test]
    fn classify_constraint_unit() {
        assert!(classify_constraint("0.8.20").is_none());
        assert!(classify_constraint("=0.8.20").is_none());
        assert!(classify_constraint("^0.8.20").is_some());
        assert!(classify_constraint(">=0.7.0 <0.9.0").is_some());
        assert!(classify_constraint("0.7.6 || 0.8.20").is_some());
        assert!(range_admits_below_0_8("^0.7.6"));
        assert!(range_admits_below_0_8(">=0.6.0 <0.8.0"));
        assert!(!range_admits_below_0_8("^0.8.20"));
        assert!(!range_admits_below_0_8(">=0.8.0 <0.9.0"));
    }
}
