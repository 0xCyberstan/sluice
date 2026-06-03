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

/// Lightweight per-phase profiling, gated on `SLUICE_PROFILE=1`. Prints
/// `[profile] <label> <millis>ms` to stderr. Off by default and never touches
/// the finding set, so it cannot affect determinism.
fn profiling_enabled() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var("SLUICE_PROFILE").map(|v| v != "0" && !v.is_empty()).unwrap_or(false)
    })
}

/// Run `f`, and if profiling is on, print how long `label` took to stderr.
#[inline]
fn phase<T>(label: &str, f: impl FnOnce() -> T) -> T {
    if !profiling_enabled() {
        return f();
    }
    let t = std::time::Instant::now();
    let out = f();
    eprintln!("[profile] {label:<22} {:>8.1}ms", t.elapsed().as_secs_f64() * 1000.0);
    out
}

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
    let dataflow = phase("dataflow", || DataflowFacts::analyze(&scir));
    let invariants = phase("invariant", || InvariantFacts::mine(&scir));
    let frontier = phase("frontier", || FrontierFacts::analyze(&scir));

    let stats = Stats {
        contracts: scir.contracts.len(),
        functions: scir.functions.len(),
        ..Default::default()
    };

    let (findings, raw_n, det_n) = {
        let cx = phase("context-build", || {
            AnalysisContext::new(&scir, &dataflow, &invariants, &frontier, cfg)
        });

        let dets = builtin_detectors();
        let enabled: Vec<&Box<dyn Detector>> =
            dets.iter().filter(|d| cfg.detector_enabled(d.id())).collect();
        let raw: Vec<Finding> = phase("detectors", || {
            if profiling_enabled() {
                // Per-detector timing so a dominant detector is attributable.
                // Same flat_map result, just timed individually.
                let mut timed: Vec<(f64, &str, Vec<Finding>)> = enabled
                    .par_iter()
                    .map(|d| {
                        let t = std::time::Instant::now();
                        let fs = d.run(&cx);
                        (t.elapsed().as_secs_f64() * 1000.0, d.id(), fs)
                    })
                    .collect();
                timed.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
                for (ms, id, _) in timed.iter().take(15) {
                    eprintln!("[profile]   detector {id:<28} {ms:>8.1}ms");
                }
                timed.into_iter().flat_map(|(_, _, fs)| fs).collect()
            } else {
                enabled.par_iter().flat_map(|d| d.run(&cx)).collect()
            }
        });
        let raw_n = raw.len();
        let det_n = enabled.len();
        (phase("finalize", || finalize(raw, &cx, cfg)), raw_n, det_n)
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

    order_dedup_cap(&mut raw, cfg.max_findings_per_function);
    for (i, f) in raw.iter_mut().enumerate() {
        f.id = format!("F-{:03}", i + 1);
    }
    raw
}

/// Impose a deterministic order on the scored findings, then dedup and cap —
/// the run-to-run-stability core of the pipeline.
///
/// The detector phase collects findings via a rayon `par_iter().flat_map(...)`,
/// whose interleaving depends on thread scheduling, so the input here arrives in
/// a run-to-run-unstable order. Each step below — the dedup tie-break, the
/// per-function cap, and the final severity sort — would otherwise inherit that
/// order for any group of equal-scoring findings, making *which* finding
/// survives dedup/cap and the emitted ordering nondeterministic.
///
/// Sorting by a total, content-derived [`location_key`] first pins one canonical
/// order before dedup/cap, so identical input yields byte-identical output no
/// matter how rayon interleaved the detectors. Parallelism (in the detector
/// phase) is untouched; only this post-collection ordering is made
/// deterministic. Factored out of `finalize` so the determinism property can be
/// unit-tested directly with shuffled inputs.
fn order_dedup_cap(raw: &mut Vec<Finding>, cap: usize) {
    raw.sort_by(|a, b| location_key(a).cmp(&location_key(b)));

    dedup_keep_strongest(raw);
    cap_per_function(raw, cap);

    // Final presentation order: strongest first, ties broken by the same
    // canonical location key. A plain stable sort would also preserve the
    // anchored order, but the explicit tie-break makes the total order
    // self-contained and obviously deterministic.
    raw.sort_by(|a, b| {
        b.severity_score
            .partial_cmp(&a.severity_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| location_key(a).cmp(&location_key(b)))
    });
}

/// A total, content-derived ordering key for a finding, used to pin a canonical
/// order before dedup/cap and as the tie-break for the final severity sort.
///
/// Keying on location first (file, line, span) yields a human-reasonable
/// top-to-bottom-of-file order among equal-scoring findings; the trailing
/// fields (detector, category, severity, title, message) make the key total so
/// two distinct findings can never compare equal, which is what removes the
/// dependence on rayon's collection order. Borrows everything — no allocation.
fn location_key(f: &Finding) -> (&str, usize, u32, u32, &str, &'static str, Severity, &str, &str) {
    (
        f.file.as_str(),
        f.line,
        f.span.start,
        f.span.end,
        f.detector.as_str(),
        f.category.slug(),
        f.severity,
        f.title.as_str(),
        f.message.as_str(),
    )
}

fn dedup_keep_strongest(findings: &mut Vec<Finding>) {
    use rustc_hash::FxHashMap;
    let mut best: FxHashMap<String, usize> = FxHashMap::default();
    let mut keep = vec![true; findings.len()];
    for (i, f) in findings.iter().enumerate() {
        let k = f.dedup_key();
        match best.get(&k) {
            Some(&j) => {
                // On equal scores keep the incumbent `j`. Because `findings` is
                // pre-sorted by the canonical `location_key`, the incumbent is
                // the canonically-first finding for this dedup key, so the
                // survivor is deterministic regardless of detector timing.
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
    // Keep the strongest `cap` per (contract, function). Ties are broken by the
    // canonical `location_key` so the kept subset is deterministic even when
    // several findings in a function share a score.
    findings.sort_by(|a, b| {
        b.severity_score
            .partial_cmp(&a.severity_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| location_key(a).cmp(&location_key(b)))
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

    // ---- determinism of the aggregation/dedup/cap/sort core ----
    //
    // These exercise `order_dedup_cap` (the post-detector pipeline that used to
    // inherit rayon's nondeterministic `flat_map` collection order) directly,
    // feeding it the SAME finding set in many different input permutations and
    // asserting the result is byte-identical every time. This models exactly the
    // run-to-run order variance that thread scheduling produces, without needing
    // to win a timing race against rayon.

    use sluice_findings::FindingBuilder;
    use sluice_ir::Span;

    /// A finding with a chosen score and location, for the determinism fixtures.
    fn mk(
        detector: &str,
        cat: Category,
        file: &str,
        line: usize,
        span_start: u32,
        score: f32,
    ) -> Finding {
        let mut f = FindingBuilder::new(detector, cat)
            .title(format!("{detector}@{file}:{line}"))
            .message(format!("m {detector} {line}"))
            .location("C", "fn", file, line, "src")
            .build();
        f.severity_score = score;
        f.span = Span::new(0, span_start, span_start + 4);
        f
    }

    /// Apply permutation `p` (indices into `base`) to produce a reordered clone.
    fn permute(base: &[Finding], p: &[usize]) -> Vec<Finding> {
        p.iter().map(|&i| base[i].clone()).collect()
    }

    /// Deterministic Fisher–Yates shuffle (fixed-seed LCG) — gives many
    /// reproducible orderings without a `rand` dependency.
    fn shuffled_indices(n: usize, seed: u64) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..n).collect();
        let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        for i in (1..n).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (state >> 33) as usize % (i + 1);
            idx.swap(i, j);
        }
        idx
    }

    /// Reduce a finding list to the order-defining tuple (post-sort the ids are
    /// reassigned by `finalize`, so we compare on the stable identity instead).
    fn shape(fs: &[Finding]) -> Vec<(String, usize, f32)> {
        fs.iter().map(|f| (f.detector.clone(), f.line, f.severity_score)).collect()
    }

    /// A fixture full of deliberate score-ties across files/lines/detectors —
    /// the case the old code resolved by (nondeterministic) insertion order.
    fn tie_heavy_fixture() -> Vec<Finding> {
        vec![
            // three-way tie at 33.75, different files/lines
            mk("reentrancy", Category::Reentrancy, "b.sol", 10, 100, 33.75),
            mk("access-control", Category::AccessControl, "a.sol", 5, 40, 33.75),
            mk("oracle", Category::OracleManipulation, "a.sol", 5, 80, 33.75),
            // tie at 3.5, including a same-(file,line) pair distinguished by span
            mk("slippage", Category::Slippage, "c.sol", 2, 10, 3.5),
            mk("unchecked-return", Category::UncheckedReturn, "c.sol", 2, 20, 3.5),
            mk("weak-randomness", Category::WeakRandomness, "a.sol", 99, 200, 3.5),
            // distinct higher scores (should lead, strongest-first)
            mk("bridge", Category::BridgeVerification, "a.sol", 1, 4, 81.0),
            mk("forced-ether", Category::ForcedEther, "z.sol", 7, 30, 56.0),
        ]
    }

    #[test]
    fn order_dedup_cap_is_permutation_invariant() {
        let base = tie_heavy_fixture();
        // Reference output from the natural order.
        let mut reference = base.clone();
        order_dedup_cap(&mut reference, 0);
        let want = shape(&reference);

        // Identity, reversal, every rotation, and 64 fixed-seed shuffles.
        let n = base.len();
        let mut perms: Vec<Vec<usize>> = Vec::new();
        perms.push((0..n).collect());
        perms.push((0..n).rev().collect());
        for r in 0..n {
            perms.push((0..n).map(|i| (i + r) % n).collect());
        }
        for seed in 0..64u64 {
            perms.push(shuffled_indices(n, seed));
        }

        for (k, p) in perms.iter().enumerate() {
            let mut got = permute(&base, p);
            order_dedup_cap(&mut got, 0);
            assert_eq!(
                shape(&got),
                want,
                "permutation #{k} {:?} produced a different ordering than the reference",
                p
            );
        }
    }

    #[test]
    fn final_order_is_human_reasonable() {
        // Strongest first; within an equal-score group, ascending by file then
        // line (a sensible top-to-bottom-of-file reading order).
        let mut fs = tie_heavy_fixture();
        order_dedup_cap(&mut fs, 0);

        // Scores must be non-increasing.
        for w in fs.windows(2) {
            assert!(
                w[0].severity_score >= w[1].severity_score,
                "not sorted strongest-first: {} then {}",
                w[0].severity_score,
                w[1].severity_score
            );
        }
        // Leaders are the two distinct high scores, strongest first.
        assert_eq!(fs[0].detector, "bridge"); // 81.0
        assert_eq!(fs[1].detector, "forced-ether"); // 56.0

        // The 33.75 tie-group is ordered by (file, line, span): a.sol:5 before
        // b.sol:10, and within a.sol:5 the smaller span first.
        let g: Vec<_> = fs.iter().filter(|f| f.severity_score == 33.75).collect();
        assert_eq!(g.len(), 3);
        assert_eq!((g[0].file.as_str(), g[0].line), ("a.sol", 5));
        assert_eq!((g[1].file.as_str(), g[1].line), ("a.sol", 5));
        assert!(g[0].span.start < g[1].span.start, "tie not ordered by span");
        assert_eq!((g[2].file.as_str(), g[2].line), ("b.sol", 10));
    }

    #[test]
    fn dedup_survivor_is_order_independent() {
        // Two findings collide on dedup_key (same category/contract/function/line)
        // but carry different scores: the strongest must always survive, and when
        // scores tie, the canonically-first one must — never the rayon-first one.
        let strong = {
            let mut f = mk("d", Category::Reentrancy, "a.sol", 3, 10, 50.0);
            f.contract = "C".into();
            f.function = "fn".into();
            f
        };
        let weak = {
            let mut f = mk("d", Category::Reentrancy, "a.sol", 3, 20, 10.0);
            f.contract = "C".into();
            f.function = "fn".into();
            f
        };
        for order in [vec![strong.clone(), weak.clone()], vec![weak.clone(), strong.clone()]] {
            let mut v = order;
            order_dedup_cap(&mut v, 0);
            assert_eq!(v.len(), 1, "dedup should collapse the pair");
            assert_eq!(v[0].severity_score, 50.0, "the stronger finding must win");
        }
    }

    #[test]
    fn cap_subset_is_order_independent() {
        // Five tied findings in one function, capped to 2: the kept subset must be
        // the canonically-first two regardless of input order.
        let base: Vec<Finding> = (0..5)
            .map(|i| {
                let mut f = mk("d", Category::Reentrancy, "a.sol", 10 + i, (i as u32) * 4, 20.0);
                f.title = format!("t{i}");
                f.message = format!("m{i}");
                f
            })
            .collect();

        let mut reference = base.clone();
        order_dedup_cap(&mut reference, 2);
        let want = shape(&reference);
        assert_eq!(want.len(), 2);

        for seed in 0..32u64 {
            let mut got = permute(&base, &shuffled_indices(base.len(), seed));
            order_dedup_cap(&mut got, 2);
            assert_eq!(shape(&got), want, "cap kept a different subset for seed {seed}");
        }
    }
}
