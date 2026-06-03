//! Coarse phase profiler for `sluice scan` on a large corpus.
//!
//! Walks a directory for `.sol` files and times the major engine phases
//! (read+parse, dataflow, invariant, frontier, detector-run, finalize) so we can
//! see where wall-clock goes on a big project. Read-only; does not change results.
//!
//! Usage: `cargo run --release --example profile_phases -- <dir>`

use std::path::PathBuf;
use std::time::Instant;

use sluice_engine::{
    builtin_detectors, AnalysisContext, Config, DataflowFacts, Finding, FrontierFacts,
    InvariantFacts,
};
use walkdir::WalkDir;

fn main() {
    let dir = std::env::args().nth(1).expect("usage: profile_phases <dir>");

    let cfg = Config::default();
    let t = Instant::now();
    let files: Vec<PathBuf> = WalkDir::new(&dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "sol").unwrap_or(false))
        .filter(|e| !cfg.is_excluded(&e.path().to_string_lossy()))
        .map(|e| e.path().to_path_buf())
        .collect();
    let t_walk = t.elapsed();
    eprintln!("discover : {:>8.1} ms  ({} files)", t_walk.as_secs_f64() * 1e3, files.len());

    // Read + parse (this is `sluice_parse::parse_paths`).
    let t = Instant::now();
    let parsed = sluice_parse::parse_paths(&files);
    let scir = parsed.scir;
    let t_parse = t.elapsed();
    eprintln!(
        "parse    : {:>8.1} ms  ({} contracts, {} functions)",
        t_parse.as_secs_f64() * 1e3,
        scir.contracts.len(),
        scir.functions.len()
    );

    let t = Instant::now();
    let dataflow = DataflowFacts::analyze(&scir);
    let t_df = t.elapsed();
    eprintln!("dataflow : {:>8.1} ms", t_df.as_secs_f64() * 1e3);

    let t = Instant::now();
    let invariants = InvariantFacts::mine(&scir);
    let t_inv = t.elapsed();
    eprintln!("invariant: {:>8.1} ms", t_inv.as_secs_f64() * 1e3);

    let t = Instant::now();
    let frontier = FrontierFacts::analyze(&scir);
    let t_fr = t.elapsed();
    eprintln!("frontier : {:>8.1} ms", t_fr.as_secs_f64() * 1e3);

    let t = Instant::now();
    let cx = AnalysisContext::new(&scir, &dataflow, &invariants, &frontier, &cfg);
    let t_cache = t.elapsed();
    eprintln!("srccache : {:>8.1} ms  (source_text precompute)", t_cache.as_secs_f64() * 1e3);

    let dets = builtin_detectors();

    // Detector run (parallel, as in the engine).
    let t = Instant::now();
    use rayon::prelude::*;
    let raw: Vec<Finding> = dets.par_iter().flat_map(|d| d.run(&cx)).collect();
    let t_det = t.elapsed();
    eprintln!("detectors: {:>8.1} ms  ({} detectors, {} raw findings)", t_det.as_secs_f64() * 1e3, dets.len(), raw.len());

    // Per-detector serial timing to find the worst offenders.
    if std::env::var("PER_DETECTOR").is_ok() {
        let mut timings: Vec<(&str, f64, usize)> = dets
            .iter()
            .map(|d| {
                let t = Instant::now();
                let fs = d.run(&cx);
                (d.id(), t.elapsed().as_secs_f64() * 1e3, fs.len())
            })
            .collect();
        timings.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        eprintln!("\n-- per-detector (serial) top 20 --");
        for (id, ms, n) in timings.iter().take(20) {
            eprintln!("  {:>8.1} ms  {:<34} {} findings", ms, id, n);
        }
    }

    let total = t_walk + t_parse + t_df + t_inv + t_fr + t_cache + t_det;
    eprintln!("\nsum of phases: {:.1} ms", total.as_secs_f64() * 1e3);
}
