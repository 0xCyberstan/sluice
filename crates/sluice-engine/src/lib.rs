//! # sluice-engine
//!
//! Orchestration: prepare the three analysis dimensions (value-flow, invariant,
//! frontier), run every enabled [`Detector`] in parallel, then finalize with
//! **cross-dimension corroboration**, severity scoring, de-duplication,
//! config/feedback suppression, and stable id assignment. The analog of
//! `vortex-engine`.

pub mod context;
pub mod detector;
pub mod detectors;
mod score;

pub use context::AnalysisContext;
pub use detector::Detector;
pub use detectors::builtin_detectors;
pub use score::{dimension_multiplier, label_from_score, score};

// Re-export the analysis facts so the CLI/tests have one import surface.
pub use sluice_config::{Config, FeedbackDb, Profile, Verdict};
pub use sluice_dataflow::DataflowFacts;
pub use sluice_findings::{Category, Dimension, Finding, Severity};
pub use sluice_frontier::FrontierFacts;
pub use sluice_invariant::InvariantFacts;
pub use sluice_ir::Scir;

use rayon::prelude::*;
use rustc_hash::FxHashSet;

#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub contracts: usize,
    pub functions: usize,
    pub detectors_run: usize,
    pub raw_findings: usize,
}

pub struct EngineResult {
    pub scir: Scir,
    pub findings: Vec<Finding>,
    pub stats: Stats,
    pub parse_errors: Vec<String>,
}

/// Analyze a set of in-memory `(path, content)` sources.
pub fn analyze_sources(sources: Vec<(String, String)>, cfg: &Config) -> EngineResult {
    let parsed = sluice_parse::parse_sources(sources);
    let parse_errors = parsed
        .file_errors
        .iter()
        .map(|e| format!("{}: {}", e.path, e.message))
        .collect();
    let mut res = analyze_scir(parsed.scir, cfg);
    res.parse_errors = parse_errors;
    res
}

/// Analyze files from disk.
pub fn analyze_paths<P: AsRef<std::path::Path> + Sync>(paths: &[P], cfg: &Config) -> EngineResult {
    let parsed = sluice_parse::parse_paths(paths);
    let parse_errors = parsed
        .file_errors
        .iter()
        .map(|e| format!("{}: {}", e.path, e.message))
        .collect();
    let mut res = analyze_scir(parsed.scir, cfg);
    res.parse_errors = parse_errors;
    res
}

/// Core: analyze an already-parsed module.
pub fn analyze_scir(scir: Scir, cfg: &Config) -> EngineResult {
    let dataflow = DataflowFacts::analyze(&scir);
    let invariants = InvariantFacts::mine(&scir);
    let frontier = FrontierFacts::analyze(&scir);

    let stats = Stats {
        contracts: scir.contracts.len(),
        functions: scir.functions.len(),
        ..Default::default()
    };

    let (findings, raw_n, det_n) = {
        let cx = AnalysisContext::new(&scir, &dataflow, &invariants, &frontier, cfg);

        let dets = builtin_detectors();
        let enabled: Vec<&Box<dyn Detector>> =
            dets.iter().filter(|d| cfg.detector_enabled(d.id())).collect();
        let raw: Vec<Finding> = enabled.par_iter().flat_map(|d| d.run(&cx)).collect();
        let raw_n = raw.len();
        let det_n = enabled.len();
        (finalize(raw, &cx, cfg), raw_n, det_n)
    };

    EngineResult {
        scir,
        findings,
        stats: Stats { detectors_run: det_n, raw_findings: raw_n, ..stats },
        parse_errors: Vec::new(),
    }
}

/// Score, corroborate, suppress, dedup, cap, and assign ids.
fn finalize(mut raw: Vec<Finding>, cx: &AnalysisContext, cfg: &Config) -> Vec<Finding> {
    // Build corroboration sets keyed by (contract, function).
    let mut inv_funcs: FxHashSet<(String, String)> = FxHashSet::default();
    for v in &cx.invariants.violations {
        inv_funcs.insert(cx.names(v.function));
    }
    let mut frontier_funcs: FxHashSet<(String, String)> = FxHashSet::default();
    for r in &cx.frontier.reentrancy {
        if !r.guarded {
            frontier_funcs.insert(cx.names(r.function));
        }
    }
    for c in &cx.frontier.crossings {
        if c.state_write_after {
            frontier_funcs.insert(cx.names(c.function));
        }
    }

    let feedback = cfg.feedback_path.as_ref().map(FeedbackDb::load);
    let emphasis = cfg.profile.emphasis();

    for f in &mut raw {
        // Automatic cross-dimension corroboration: if an independent pass also
        // implicates this function, add its dimension so the score reflects it.
        let key = (f.contract.clone(), f.function.clone());
        if inv_funcs.contains(&key) && !f.dimensions.contains(&Dimension::Invariant) {
            f.dimensions.push(Dimension::Invariant);
        }
        if frontier_funcs.contains(&key) && !f.dimensions.contains(&Dimension::Frontier) {
            f.dimensions.push(Dimension::Frontier);
        }

        let (s, label) = score(f);
        f.severity_score = s;
        f.severity = label;

        if let Some(db) = &feedback {
            f.severity_score *= db.score_multiplier(&f.dedup_key());
        }
    }

    // Suppression: config rules, feedback-zeroed, and confidence floor (relaxed
    // for detectors the active profile emphasizes).
    raw.retain(|f| {
        if cfg.is_suppressed(&f.contract, &f.function) || f.severity_score <= 0.0 {
            return false;
        }
        let floor = if emphasis.iter().any(|e| *e == f.detector || *e == f.category.slug()) {
            cfg.min_confidence * 0.8
        } else {
            cfg.min_confidence
        };
        f.confidence >= floor
    });

    dedup_keep_strongest(&mut raw);
    cap_per_function(&mut raw, cfg.max_findings_per_function);

    raw.sort_by(|a, b| {
        b.severity_score
            .partial_cmp(&a.severity_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for (i, f) in raw.iter_mut().enumerate() {
        f.id = format!("F-{:03}", i + 1);
    }
    raw
}

fn dedup_keep_strongest(findings: &mut Vec<Finding>) {
    use rustc_hash::FxHashMap;
    let mut best: FxHashMap<String, usize> = FxHashMap::default();
    let mut keep = vec![true; findings.len()];
    for (i, f) in findings.iter().enumerate() {
        let k = f.dedup_key();
        match best.get(&k) {
            Some(&j) => {
                if findings[j].severity_score >= f.severity_score {
                    keep[i] = false;
                } else {
                    keep[j] = false;
                    best.insert(k, i);
                }
            }
            None => {
                best.insert(k, i);
            }
        }
    }
    let mut idx = 0;
    findings.retain(|_| {
        let k = keep[idx];
        idx += 1;
        k
    });
}

fn cap_per_function(findings: &mut Vec<Finding>, cap: usize) {
    if cap == 0 {
        return;
    }
    use rustc_hash::FxHashMap;
    // Keep the strongest `cap` per (contract, function).
    findings.sort_by(|a, b| {
        b.severity_score
            .partial_cmp(&a.severity_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut counts: FxHashMap<(String, String), usize> = FxHashMap::default();
    findings.retain(|f| {
        let c = counts.entry((f.contract.clone(), f.function.clone())).or_insert(0);
        *c += 1;
        *c <= cap
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(src: &str) -> Vec<Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    #[test]
    fn end_to_end_reentrancy() {
        let fs = run(r#"
            contract Bank {
                mapping(address => uint256) balances;
                function withdraw() external {
                    uint256 a = balances[msg.sender];
                    (bool ok,) = msg.sender.call{value: a}("");
                    require(ok);
                    balances[msg.sender] = 0;
                }
            }
        "#);
        assert!(fs.iter().any(|f| f.category == Category::Reentrancy), "findings: {:?}", fs.iter().map(|f| f.title.clone()).collect::<Vec<_>>());
    }

    #[test]
    fn corroboration_lifts_euler_class() {
        // withdraw skips _checkHealth AND has reentrancy-flavored structure.
        let fs = run(r#"
            contract Lending {
                mapping(address => uint256) collateral;
                mapping(address => uint256) debt;
                function _checkHealth(address u) internal {}
                function borrow(uint256 a) external { debt[msg.sender] += a; _checkHealth(msg.sender); }
                function repay(uint256 a) external { debt[msg.sender] -= a; _checkHealth(msg.sender); }
                function addCollateral(uint256 a) external { collateral[msg.sender] += a; _checkHealth(msg.sender); }
                function withdraw(uint256 a) external { collateral[msg.sender] -= a; }
            }
        "#);
        assert!(
            fs.iter().any(|f| f.category == Category::MissingSolvencyCheck),
            "expected a missing-solvency finding; got {:?}",
            fs.iter().map(|f| (f.category, f.severity)).collect::<Vec<_>>()
        );
    }
}
