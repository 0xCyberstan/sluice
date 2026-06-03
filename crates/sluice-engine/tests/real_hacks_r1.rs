//! Real historical DeFi hack regression test — round 2 (`_r1`).
//!
//! A SECOND, independent real-hack harness alongside `real_hacks.rs`. It covers
//! a partly overlapping but distinct set of incidents and detector
//! attributions. Each fixture under `tests/fixtures/real_hacks/` is a small,
//! parseable reconstruction of the vulnerable shape from one real incident; the
//! detector named for that incident MUST fire for the fixture to count as a
//! CAUGHT. If it stays silent that is a MISS.
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
    ("harvest.sol", "oracle-manipulation", "Harvest Finance ($34M, Oct 2020)"),
    ("mango.sol", "oracle-manipulation", "Mango Markets ($117M, Oct 2022)"),
    ("wormhole.sol", "signature", "Wormhole Bridge ($326M, Feb 2022)"),
    ("curve_vyper.sol", "reentrancy", "Curve/Vyper nonreentrant-lock failure ($69M, Jul 2023)"),
    ("pickle.sol", "missing-solvency-check", "Pickle Finance ($20M, Nov 2020)"),
    ("visor.sol", "arbitrary-transfer", "Visor Finance ($8.2M, Dec 2021)"),
    ("sonne.sol", "vault", "Sonne Finance ($20M, May 2024)"),
    ("platypus.sol", "missing-solvency-check", "Platypus Finance ($8.5M, Feb 2023)"),
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
    findings.iter().any(|f| f.detector.as_str() == detector_id)
}

#[test]
fn flags_real_historical_hacks_r1() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/real_hacks");
    let cfg = Config::default();

    let mut caught = 0usize; // detector fired as expected
    let mut analyzed = 0usize; // fixtures actually present and analyzed (the N denominator)

    eprintln!("\n=== Real historical DeFi hacks — round 2 (named detector MUST fire) ===");
    eprintln!("{:<8} {:<22} {:<42} {}", "result", "detector", "incident", "fixture");
    eprintln!("{}", "-".repeat(98));

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
            "{:<8} {:<22} {:<42} {}",
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
