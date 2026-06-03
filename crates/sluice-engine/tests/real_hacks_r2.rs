//! Real historical DeFi hack regression test — round 3 (`_r2`).
//!
//! A THIRD, independent real-hack harness alongside `real_hacks.rs` and
//! `real_hacks_r1.rs`. It covers a distinct set of incidents and detector
//! attributions. Each fixture under `tests/fixtures/real_hacks/` is a small,
//! parseable reconstruction of the vulnerable shape from one real incident; the
//! detector named for that incident MUST fire (some `Finding.detector` equals
//! the expected id) for the fixture to count as CAUGHT. If it stays silent that
//! is a MISS.
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
    ("rari_fuse_cross.sol", "reentrancy", "Rari/Fuse cross-contract reentrancy ($80M, Apr/May 2022)"),
    ("hundred.sol", "reentrancy", "Hundred Finance ($7.4M, Mar 2022)"),
    ("inverse.sol", "oracle-manipulation", "Inverse Finance ($15.6M, Apr 2022)"),
    ("radiant.sol", "rounding-direction", "Radiant Capital ($4.5M precision, Jan 2024)"),
    ("qubit.sol", "arbitrary-transfer", "Qubit Finance / QBridge ($80M, Jan 2022)"),
    ("pancakebunny.sol", "oracle-manipulation", "PancakeBunny ($45M, May 2021)"),
    ("conic.sol", "reentrancy", "Conic Finance ($3.2M read-only reentrancy, Jul 2023)"),
    ("sturdy.sol", "oracle-manipulation", "Sturdy Finance ($800K read-only reentrancy/oracle, Jun 2023)"),
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
fn flags_real_historical_hacks_r2() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/real_hacks");
    let cfg = Config::default();

    let mut caught = 0usize; // detector fired as expected
    let mut analyzed = 0usize; // fixtures actually present and analyzed (the N denominator)

    eprintln!("\n=== Real historical DeFi hacks — round 3 (named detector MUST fire) ===");
    eprintln!("{:<8} {:<22} {:<58} {}", "result", "detector", "incident", "fixture");
    eprintln!("{}", "-".repeat(110));

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
            "{:<8} {:<22} {:<58} {}",
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
