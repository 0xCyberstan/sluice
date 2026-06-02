//! Corpus precision/recall benchmark.
//!
//! Runs the full engine (`analyze_sources`) over the hand-built fixture corpus
//! and scores it the way an external reviewer would:
//!
//!   * Every file under `tests/fixtures/vuln/` is a realistic, parseable
//!     contract that genuinely exhibits one bug. The named detector for that
//!     file MUST fire (a TRUE POSITIVE). If it stays silent that is a MISS
//!     (false negative) and costs recall.
//!   * Every file under `tests/fixtures/safe/` is the *mitigated* version of a
//!     bug class. The named detector MUST stay silent (a CLEAN). If it fires
//!     anyway that is a FALSE POSITIVE and costs the clean-rate.
//!
//! We then assert modest floors: recall >= 0.90 and clean_rate >= 1.00.
//!
//! Missing fixture files are tolerated: they are skipped with a printed warning
//! and excluded from the denominators, so a not-yet-authored fixture never
//! silently drags a score down (and a read error never panics the run).

use sluice_engine::{analyze_sources, Config};

/// `(filename, expected detector id)` — the vuln file's named detector MUST fire.
const VULN: &[(&str, &str)] = &[
    ("reentrancy.sol", "reentrancy"),
    ("read_only_reentrancy.sol", "reentrancy"),
    ("oracle_manipulation.sol", "oracle-manipulation"),
    ("vault_inflation.sol", "vault"),
    ("missing_solvency.sol", "missing-solvency-check"),
    ("access_control.sol", "access-control"),
    ("tx_origin.sol", "access-control"),
    ("signature_replay.sol", "signature"),
    ("delegatecall.sol", "upgradeable"),
    ("uninitialized_proxy.sol", "upgradeable"),
    ("unchecked_transfer.sol", "unchecked-return"),
    ("flashloan_governance.sol", "flashloan-governance"),
    ("bridge_zero_root.sol", "bridge-verification"),
    ("slippage.sol", "slippage"),
    ("dos_loop.sol", "denial-of-service"),
    ("weak_randomness.sol", "weak-randomness"),
    ("forced_ether.sol", "forced-ether"),
    ("selector_collision.sol", "selector-collision"),
    ("integer_truncation.sol", "integer-issues"),
    ("fee_on_transfer.sol", "fee-on-transfer"),
];

/// `(filename, detector id that must stay silent)` — the mitigated version.
const SAFE: &[(&str, &str)] = &[
    ("safe_reentrancy.sol", "reentrancy"),
    ("safe_oracle.sol", "oracle-manipulation"),
    ("safe_vault.sol", "vault"),
    ("safe_access.sol", "access-control"),
    ("safe_signature.sol", "signature"),
    ("safe_proxy.sol", "upgradeable"),
    ("safe_erc20.sol", "unchecked-return"),
    ("safe_voting.sol", "flashloan-governance"),
];

/// Read a fixture, returning `None` (with a printed warning) if it is missing
/// or unreadable so the harness never panics on a not-yet-authored file.
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
fn corpus_precision_recall() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let cfg = Config::default();

    // ---- vuln corpus: each named detector must fire ----
    let mut tp = 0usize; // true positives (detector fired as expected)
    let mut vuln_total = 0usize; // files actually present and analyzed
    eprintln!("\n=== VULN corpus (named detector MUST fire) ===");
    eprintln!("{:<26} {:<22} {}", "fixture", "expected detector", "result");
    eprintln!("{}", "-".repeat(62));
    for (file, expected) in VULN {
        let path = root.join("vuln").join(file);
        let Some(content) = read_fixture(&path) else { continue };
        vuln_total += 1;

        let res = analyze_sources(vec![(path.display().to_string(), content)], &cfg);
        if !res.parse_errors.is_empty() {
            eprintln!("  WARN  parse errors in {file}: {:?}", res.parse_errors);
        }
        let hit = fired(&res.findings, expected);
        if hit {
            tp += 1;
        }
        eprintln!(
            "{:<26} {:<22} {}",
            file,
            expected,
            if hit { "PASS (fired)" } else { "MISS (silent)" }
        );
    }

    // ---- safe corpus: each named detector must stay silent ----
    let mut clean = 0usize; // true negatives (detector correctly silent)
    let mut safe_total = 0usize;
    eprintln!("\n=== SAFE corpus (named detector must STAY SILENT) ===");
    eprintln!("{:<26} {:<22} {}", "fixture", "must-not-fire", "result");
    eprintln!("{}", "-".repeat(62));
    for (file, detector) in SAFE {
        let path = root.join("safe").join(file);
        let Some(content) = read_fixture(&path) else { continue };
        safe_total += 1;

        let res = analyze_sources(vec![(path.display().to_string(), content)], &cfg);
        if !res.parse_errors.is_empty() {
            eprintln!("  WARN  parse errors in {file}: {:?}", res.parse_errors);
        }
        let false_positive = fired(&res.findings, detector);
        if !false_positive {
            clean += 1;
        }
        eprintln!(
            "{:<26} {:<22} {}",
            file,
            detector,
            if false_positive { "MISS (false +)" } else { "PASS (clean)" }
        );
    }

    // ---- scorecard ----
    // Guard against an empty corpus producing a divide-by-zero or a vacuous pass.
    assert!(vuln_total > 0, "no vuln fixtures found under {}", root.join("vuln").display());
    assert!(safe_total > 0, "no safe fixtures found under {}", root.join("safe").display());

    let recall = tp as f64 / vuln_total as f64;
    let clean_rate = clean as f64 / safe_total as f64;

    eprintln!("\n=== SCORECARD ===");
    eprintln!("recall      = {tp}/{vuln_total} = {recall:.3}  (true positives / vuln files)");
    eprintln!("clean_rate  = {clean}/{safe_total} = {clean_rate:.3}  (clean / safe files)");
    eprintln!("skipped vuln = {}, skipped safe = {}", VULN.len() - vuln_total, SAFE.len() - safe_total);

    assert!(
        recall >= 0.90,
        "recall too low: {tp}/{vuln_total} = {recall:.3} (floor 0.90)"
    );
    assert!(
        clean_rate >= 1.00,
        "clean_rate too low: {clean}/{safe_total} = {clean_rate:.3} (floor 1.00 — precision is paramount)"
    );
}
