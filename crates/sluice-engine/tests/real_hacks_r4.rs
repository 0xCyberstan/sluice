//! Real historical DeFi hack regression test — round 5 (`_r4`).
//!
//! A FIFTH, independent real-hack harness alongside `real_hacks.rs`,
//! `real_hacks_r1.rs`, `real_hacks_r2.rs`, and `real_hacks_r3.rs`. It covers a
//! distinct set of incidents and detector attributions. Each fixture under
//! `tests/fixtures/real_hacks/` is a small, parseable reconstruction of the
//! vulnerable shape from one real incident; the detector named for that
//! incident MUST fire (some `Finding.detector` equals the expected id) for the
//! fixture to count as CAUGHT. If it stays silent that is a MISS.
//!
//! Missing or unreadable fixtures are tolerated: they are skipped with a printed
//! `WARN` and excluded from the denominator `N`, so a not-yet-authored
//! reconstruction never panics the run and never silently fails the floor.

use sluice_engine::{analyze_sources, Config};

/// `(filename, expected detector id, incident name)`.
///
/// `expected` is the `Finding.detector` id (see `sluice-engine/src/detectors/`)
/// that must be attributed to at least one finding for the fixture to count as
/// CAUGHT.
const HACKS: &[(&str, &str, &str)] = &[
    ("orion.sol", "reentrancy", "Orion Protocol ($3M ERC777 swap reentrancy, Feb 2023)"),
    ("deus.sol", "oracle-manipulation", "DEUS Finance ($3M oracle/price manipulation, Mar 2022)"),
    ("saddle.sol", "rounding-direction", "Saddle Finance ($10M metapool rounding/swap, Apr 2022)"),
    ("kyber_elastic.sol", "integer-issues", "KyberSwap Elastic ($48M tick math integer flaw, Nov 2023)"),
    ("gamma.sol", "oracle-manipulation", "Gamma Strategies ($6M LP price manipulation, Jan 2024)"),
    ("jimbo.sol", "oracle-manipulation", "Jimbo's Protocol ($7.5M floor-price manipulation, May 2023)"),
    ("midas.sol", "oracle-manipulation", "Midas Capital ($660K read-only oracle, Jan 2023)"),
    ("templedao.sol", "untrusted-call-target", "TempleDAO ($2.3M unprotected migrateStake, Oct 2022)"),
];

/// Read a fixture, returning `None` (with a printed `WARN`) if it is missing or
/// unreadable so the harness never panics on a not-yet-authored reconstruction.
fn read_fixture(path: &std::path::Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("  WARN  skipping missing/unreadable fixture {}: {e}", path.display());
            None
        }
    }
}

/// `true` iff some finding was attributed to `detector_id`.
fn fired(findings: &[sluice_engine::Finding], detector_id: &str) -> bool {
    findings.iter().any(|f| f.detector == detector_id)
}

#[test]
fn flags_real_historical_hacks_r4() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/real_hacks");
    let cfg = Config::default();

    let mut caught = 0usize; // detector fired as expected
    let mut analyzed = 0usize; // fixtures actually present and analyzed (the N denominator)

    eprintln!("\n=== Real historical DeFi hacks — round 5 (named detector MUST fire) ===");
    eprintln!("{:<8} {:<22} {:<62} {}", "result", "detector", "incident", "fixture");
    eprintln!("{}", "-".repeat(114));

    for (file, expected, incident) in HACKS {
        let path = dir.join(file);
        let Some(content) = read_fixture(&path) else { continue };
        analyzed += 1;

        let res = analyze_sources(vec![(path.display().to_string(), content)], &cfg);
        if !res.parse_errors.is_empty() {
            eprintln!("  WARN  parse errors in {file}: {:?}", res.parse_errors);
        }

        let hit = fired(&res.findings, expected);
        if hit {
            caught += 1;
        }
        eprintln!(
            "{:<8} {:<22} {:<62} {}",
            if hit { "PASS" } else { "MISS" },
            expected,
            incident,
            file,
        );
    }

    let skipped = HACKS.len() - analyzed;
    eprintln!("\n=== SCORECARD ===");
    eprintln!("caught       = {caught}/{analyzed}  (detectors that fired / fixtures analyzed)");
    eprintln!("skipped      = {skipped}  (missing/unreadable fixtures, excluded from N)");
    eprintln!("total hacks  = {}", HACKS.len());

    // Guard against a vacuous pass: if every fixture were missing, `caught` and
    // `analyzed` would both be 0 and the floor below would be trivially unmet.
    assert!(
        analyzed > 0,
        "no real_hacks fixtures found under {} — nothing was analyzed",
        dir.display()
    );

    // Tolerant floor: at least 6 of the historical hacks must be flagged.
    eprintln!("floor        = 6  (actual caught = {caught})");
    assert!(
        caught >= 6,
        "too few historical hacks flagged: caught {caught} of {analyzed} analyzed (floor 6)"
    );
}
