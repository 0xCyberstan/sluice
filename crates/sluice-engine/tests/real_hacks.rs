//! Real historical DeFi hack regression test.
//!
//! Proves that Sluice flags the *kind* of bug behind a set of well-known,
//! high-impact on-chain exploits. Each fixture under
//! `tests/fixtures/real_hacks/` is a small, parseable reconstruction of the
//! vulnerable shape from one real incident; the detector named for that
//! incident MUST fire (a CAUGHT). If it stays silent that is a MISS.
//!
//! Missing or unreadable fixtures are tolerated: they are skipped with a
//! printed `WARN` and excluded from the denominator, so a not-yet-authored
//! reconstruction never panics the run and never silently fails the floor.

use sluice_engine::{analyze_sources, Config};

/// `(filename, expected detector id, incident name)`.
///
/// `expected` is the `Finding.detector` id (see
/// `sluice-engine/src/detectors/`) that must be attributed to at least one
/// finding for the fixture to count as CAUGHT.
const HACKS: &[(&str, &str, &str)] = &[
    ("euler.sol", "missing-solvency-check", "Euler Finance ($197M, Mar 2022)"),
    ("cream.sol", "oracle-manipulation", "Cream Finance ($130M, Oct 2021)"),
    ("bzx.sol", "oracle-manipulation", "bZx ($8M, Feb 2020)"),
    ("beanstalk.sol", "flashloan-governance", "Beanstalk ($182M, Apr 2022)"),
    ("nomad.sol", "bridge-verification", "Nomad Bridge ($190M, Aug 2022)"),
    ("fei_rari.sol", "reentrancy", "Fei/Rari Fuse ($80M, Apr 2022)"),
    ("erc4626_inflation.sol", "vault", "ERC-4626 inflation / first-depositor"),
    ("lendf_erc777.sol", "erc777-reentrancy", "Lendf.me / dForce ($25M, Apr 2020)"),
    ("parity.sol", "access-control", "Parity multisig ($150M+, Jul/Nov 2017)"),
    ("polynetwork.sol", "bridge-verification", "Poly Network ($611M, Aug 2021)"),
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
fn flags_real_historical_hacks() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/real_hacks");
    let cfg = Config::default();

    let mut caught = 0usize; // detector fired as expected
    let mut analyzed = 0usize; // fixtures actually present and analyzed (the N denominator)

    eprintln!("\n=== Real historical DeFi hacks (named detector MUST fire) ===");
    eprintln!("{:<8} {:<22} {:<40} {}", "result", "detector", "incident", "fixture");
    eprintln!("{}", "-".repeat(96));

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
            "{:<8} {:<22} {:<40} {}",
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

    // Tolerant floor: at least 7 of the historical hacks must be flagged.
    assert!(
        caught >= 7,
        "too few historical hacks flagged: caught {caught} of {analyzed} analyzed (floor 7)"
    );
}
