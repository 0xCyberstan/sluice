//! `sluice-bench` — the contest-benchmark scoreboard.
//!
//! Given the committed manifests in `benchmarks/contests/*.json` and the local
//! contest clones, it drives the release `sluice` binary over each contest's
//! `scope_dirs`, then scores **recall** (in-class vs out-of-class) and a
//! **precision proxy** (Crit/High count + unmatched count) against the published
//! audit findings. Prints a per-contest + aggregate table and writes
//! `benchmarks/SCOREBOARD.md`.
//!
//! Usage (from the workspace root):
//!   cargo run -p sluice-bench --release
//!   cargo run -p sluice-bench --release -- --verbose
//!   cargo run -p sluice-bench --release -- --contest 2024-05-loop
//!   cargo run -p sluice-bench --release -- --sluice-bin target/release/sluice

mod manifest;
mod score;

use anyhow::{Context, Result};
use clap::Parser;
use manifest::Manifest;
use score::{score_contest, Aggregate, ContestScore, EmittedFinding};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser)]
#[command(name = "sluice-bench", about = "Recall + precision scoreboard vs known audit findings")]
struct Cli {
    /// Directory of contest manifests (default: <crate>/contests).
    #[arg(long)]
    contests_dir: Option<PathBuf>,
    /// Only run this contest (manifest `name`); repeatable.
    #[arg(long)]
    contest: Vec<String>,
    /// Path to the `sluice` binary. If omitted, the harness builds the release
    /// binary with `cargo build -p sluice-cli --release` and uses it.
    #[arg(long)]
    sluice_bin: Option<PathBuf>,
    /// Skip the `cargo build` step (use an already-built binary at the default
    /// release path or `--sluice-bin`).
    #[arg(long)]
    no_build: bool,
    /// Print per-known-finding detail under each contest.
    #[arg(long)]
    verbose: bool,
    /// Where to write the scoreboard markdown (default: <crate>/SCOREBOARD.md).
    #[arg(long)]
    out: Option<PathBuf>,
    /// Also report the *location ceiling*: recall if any-class location match
    /// counted as a catch (shows how much recall is lost to class mismatch vs
    /// the detector simply not firing at the location at all).
    #[arg(long)]
    location_ceiling: bool,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| crate_dir.clone());

    let contests_dir = cli.contests_dir.clone().unwrap_or_else(|| crate_dir.join("contests"));
    let manifests = load_manifests(&contests_dir, &cli.contest)?;
    if manifests.is_empty() {
        anyhow::bail!("no manifests found in {}", contests_dir.display());
    }

    let sluice_bin = resolve_sluice_bin(&cli, &workspace_root)?;
    eprintln!("using sluice binary: {}", sluice_bin.display());

    let mut rows: Vec<ContestScore> = Vec::new();
    let mut ceiling_rows: Vec<ContestScore> = Vec::new();
    for m in &manifests {
        let scope = m.scope_paths();
        let missing: Vec<_> = scope.iter().filter(|p| !p.exists()).collect();
        if !missing.is_empty() {
            eprintln!(
                "warning: contest {} scope path(s) missing, skipping: {}",
                m.name,
                missing.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
            );
            continue;
        }
        eprintln!("scanning contest {} ({} scope dir(s)) ...", m.name, scope.len());
        let emitted = scan(&sluice_bin, &scope)
            .with_context(|| format!("scanning contest {}", m.name))?;
        eprintln!("  → {} findings emitted", emitted.len());
        rows.push(score_contest(m, &emitted, false));
        if cli.location_ceiling {
            ceiling_rows.push(score_contest(m, &emitted, true));
        }
    }
    if rows.is_empty() {
        anyhow::bail!("no contests could be scored (all scope paths missing?)");
    }

    let mut agg = Aggregate::default();
    for r in &rows {
        agg.add(r);
    }

    let report = render(&rows, &agg, cli.verbose, &ceiling_rows);
    print!("{report}");

    let out = cli.out.clone().unwrap_or_else(|| crate_dir.join("SCOREBOARD.md"));
    std::fs::write(&out, render_md(&rows, &agg, &ceiling_rows))
        .with_context(|| format!("writing {}", out.display()))?;
    eprintln!("wrote {}", out.display());
    Ok(())
}

/// Load every `*.json` manifest in `dir`, optionally filtered to `only` names.
fn load_manifests(dir: &Path, only: &[String]) -> Result<Vec<Manifest>> {
    let mut out = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading contests dir {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    entries.sort();
    for p in entries {
        let m = Manifest::load(&p)?;
        if only.is_empty() || only.contains(&m.name) {
            out.push(m);
        }
    }
    Ok(out)
}

/// Decide which `sluice` binary to use, building it if needed.
fn resolve_sluice_bin(cli: &Cli, workspace_root: &Path) -> Result<PathBuf> {
    if let Some(p) = &cli.sluice_bin {
        if !p.exists() {
            anyhow::bail!("--sluice-bin {} does not exist", p.display());
        }
        return Ok(p.clone());
    }
    let default = workspace_root.join("target/release/sluice");
    if cli.no_build {
        if !default.exists() {
            anyhow::bail!(
                "--no-build set but {} does not exist; build it or pass --sluice-bin",
                default.display()
            );
        }
        return Ok(default);
    }
    eprintln!("building release sluice (cargo build -p sluice-cli --release) ...");
    let status = Command::new(env!("CARGO"))
        .current_dir(workspace_root)
        .args(["build", "-p", "sluice-cli", "--release"])
        .status()
        .context("running cargo build for sluice-cli")?;
    if !status.success() {
        anyhow::bail!("cargo build -p sluice-cli --release failed");
    }
    if !default.exists() {
        anyhow::bail!("release build did not produce {}", default.display());
    }
    Ok(default)
}

/// Run `sluice scan <scope...> --format json` and parse the findings.
fn scan(sluice_bin: &Path, scope: &[PathBuf]) -> Result<Vec<EmittedFinding>> {
    // The CLI takes a single path arg; scan each scope dir and merge. (Both
    // seeded contests have one scope dir, but this generalizes cleanly.)
    let mut all = Vec::new();
    for dir in scope {
        let output = Command::new(sluice_bin)
            .arg("scan")
            .arg(dir)
            .args(["--format", "json"])
            .output()
            .with_context(|| format!("running sluice scan {}", dir.display()))?;
        if !output.status.success() && output.stdout.is_empty() {
            anyhow::bail!(
                "sluice scan {} failed: {}",
                dir.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let parsed: Vec<EmittedFinding> = serde_json::from_slice(&output.stdout).with_context(|| {
            format!("parsing sluice JSON for {} (stderr: {})", dir.display(), String::from_utf8_lossy(&output.stderr))
        })?;
        all.extend(parsed);
    }
    Ok(all)
}

/// Render the human (stdout) scoreboard.
fn render(rows: &[ContestScore], agg: &Aggregate, verbose: bool, ceiling: &[ContestScore]) -> String {
    let mut s = String::new();
    s.push_str("\n=== Sluice contest scoreboard ===\n\n");
    s.push_str(&format!(
        "{:<18} {:>14} {:>16} {:>12} {:>16}\n",
        "contest", "in-class rec.", "out-class rec.", "Crit/High", "unmatched C/H"
    ));
    s.push_str(&"-".repeat(80));
    s.push('\n');
    for r in rows {
        s.push_str(&format!(
            "{:<18} {:>13} {:>15} {:>12} {:>16}\n",
            trunc(&r.name, 18),
            frac(r.in_class_caught, r.in_class_total, r.in_class_recall()),
            frac(r.out_class_caught, r.out_class_total, r.out_class_recall()),
            r.crit_high_total,
            r.crit_high_unmatched,
        ));
    }
    s.push_str(&"-".repeat(80));
    s.push('\n');
    s.push_str(&format!(
        "{:<18} {:>13} {:>15} {:>12} {:>16}\n",
        "AGGREGATE",
        frac(agg.in_class_caught, agg.in_class_total, agg.in_class_recall()),
        frac(agg.out_class_caught, agg.out_class_total, agg.out_class_recall()),
        agg.crit_high_total,
        agg.crit_high_unmatched,
    ));
    s.push('\n');
    s.push_str(&format!(
        "Headline: in-class recall {:.0}% ({}/{}), out-of-class recall {:.0}% ({}/{}), \
         Crit/High {} ({} unmatched / candidate FP), total findings {}.\n",
        agg.in_class_recall(), agg.in_class_caught, agg.in_class_total,
        agg.out_class_recall(), agg.out_class_caught, agg.out_class_total,
        agg.crit_high_total, agg.crit_high_unmatched, agg.emitted_total,
    ));

    if !ceiling.is_empty() {
        let mut cagg = Aggregate::default();
        for r in ceiling {
            cagg.add(r);
        }
        s.push_str(&format!(
            "Location ceiling (any-class match counts): in-class {:.0}% ({}/{}), out-of-class {:.0}% ({}/{}).\n",
            cagg.in_class_recall(), cagg.in_class_caught, cagg.in_class_total,
            cagg.out_class_recall(), cagg.out_class_caught, cagg.out_class_total,
        ));
    }

    if verbose {
        for r in rows {
            s.push_str(&format!("\n--- {} ---\n", r.name));
            for d in &r.details {
                let mark = if d.caught { "CAUGHT " } else if d.location_only { "near   " } else { "MISSED " };
                let cls = if d.in_class { "in " } else { "out" };
                s.push_str(&format!(
                    "  [{}] {} {:<6} {:<5} {:<22} {}",
                    mark, d.id, d.severity, cls, d.bug_class, d.location
                ));
                if let Some(by) = &d.by {
                    s.push_str(&format!("  ⟵ {by}"));
                } else if d.location_only {
                    s.push_str("  (location matched, class mismatch)");
                }
                s.push('\n');
            }
        }
    }
    s
}

/// Render the committed SCOREBOARD.md.
fn render_md(rows: &[ContestScore], agg: &Aggregate, ceiling: &[ContestScore]) -> String {
    let mut s = String::new();
    s.push_str("# Sluice contest scoreboard\n\n");
    s.push_str(
        "Recall + precision of Sluice vs published audit findings, over the contest corpus in \
         `benchmarks/contests/*.json`. Regenerate with `cargo run -p sluice-bench --release`.\n\n",
    );
    s.push_str("- **in-class recall** — known findings whose bug class Sluice models, caught at the right location with a compatible class.\n");
    s.push_str("- **out-of-class recall** — protocol-specific invariant/accounting/logic findings (no modeled detector class) caught.\n");
    s.push_str("- **Crit/High** — Sluice's Critical+High findings; **unmatched** = not aligned to any known finding (candidate false positives to triage).\n\n");

    s.push_str("| Contest | In-class recall | Out-of-class recall | Crit/High | Unmatched C/H | Total findings |\n");
    s.push_str("|---|---|---|---|---|---|\n");
    for r in rows {
        s.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} |\n",
            r.name,
            frac(r.in_class_caught, r.in_class_total, r.in_class_recall()),
            frac(r.out_class_caught, r.out_class_total, r.out_class_recall()),
            r.crit_high_total,
            r.crit_high_unmatched,
            r.emitted_total,
        ));
    }
    s.push_str(&format!(
        "| **AGGREGATE** | **{}** | **{}** | **{}** | **{}** | **{}** |\n\n",
        frac(agg.in_class_caught, agg.in_class_total, agg.in_class_recall()),
        frac(agg.out_class_caught, agg.out_class_total, agg.out_class_recall()),
        agg.crit_high_total,
        agg.crit_high_unmatched,
        agg.emitted_total,
    ));

    if !ceiling.is_empty() {
        let mut cagg = Aggregate::default();
        for r in ceiling {
            cagg.add(r);
        }
        s.push_str(&format!(
            "_Location ceiling (any-class match would count): in-class {} ({}/{}), out-of-class {} ({}/{})._\n\n",
            pct_str(cagg.in_class_recall()), cagg.in_class_caught, cagg.in_class_total,
            pct_str(cagg.out_class_recall()), cagg.out_class_caught, cagg.out_class_total,
        ));
    }

    s.push_str("## Per-finding detail\n\n");
    for r in rows {
        let commit = r.commit.as_deref().unwrap_or("(unpinned)");
        s.push_str(&format!("### `{}`\n\n", r.name));
        s.push_str(&format!("Repo `{}` @ `{}`.\n\n", r.repo, commit));
        s.push_str("| Known | Sev | Class | In-class | Result | Matched by | Summary |\n");
        s.push_str("|---|---|---|---|---|---|---|\n");
        for d in &r.details {
            let res = if d.caught {
                "✅ caught"
            } else if d.location_only {
                "🟡 near (class mismatch)"
            } else {
                "❌ missed"
            };
            s.push_str(&format!(
                "| {} | {} | `{}` | {} | {} | {} | {} |\n",
                d.id,
                d.severity,
                d.bug_class,
                if d.in_class { "yes" } else { "no" },
                res,
                d.by.clone().unwrap_or_else(|| "—".into()),
                md_cell(&d.summary),
            ));
        }
        s.push('\n');
    }
    s
}

/// Sanitize a free-text summary for a single markdown table cell (escape pipes,
/// collapse newlines, clamp length).
fn md_cell(s: &str) -> String {
    let one_line: String = s.split_whitespace().collect::<Vec<_>>().join(" ").replace('|', "\\|");
    if one_line.chars().count() > 160 {
        let clamped: String = one_line.chars().take(159).collect();
        format!("{clamped}…")
    } else {
        one_line
    }
}

fn frac(caught: usize, total: usize, p: f64) -> String {
    format!("{:.0}% ({}/{})", p, caught, total)
}

fn pct_str(p: f64) -> String {
    format!("{p:.0}%")
}

fn trunc(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}

#[cfg(test)]
mod tests {
    use super::score::*;
    use crate::manifest::{compatible_categories, KnownFinding};

    fn known(contract: &str, function: &str, file: &str, line: usize, class: &str, in_class: bool) -> KnownFinding {
        KnownFinding {
            id: "T-1".into(),
            severity: "Medium".into(),
            contract: contract.into(),
            function: function.into(),
            file: file.into(),
            line,
            bug_class: class.into(),
            in_class,
            summary: String::new(),
        }
    }

    fn emit(category: &str, severity: &str, contract: &str, function: &str, file: &str, line: usize) -> EmittedFinding {
        EmittedFinding {
            category: category.into(),
            severity: severity.into(),
            contract: contract.into(),
            function: function.into(),
            file: file.into(),
            line,
        }
    }

    #[test]
    fn normalizes_p0_p1_suffix() {
        assert_eq!(norm_contract("RTokenP1"), "rtoken");
        assert_eq!(norm_contract("RTokenP0"), "rtoken");
        assert_eq!(norm_contract("StRSRP1"), "strsr");
        // Don't strip when it would empty the name or isn't a known suffix.
        assert_eq!(norm_contract("Vault"), "vault");
        assert_eq!(norm_contract("P1"), "p1");
    }

    #[test]
    fn underscore_function_matches() {
        assert_eq!(norm_fn("_claim"), "claim");
        assert_eq!(norm_fn("claim"), "claim");
    }

    #[test]
    fn contract_function_match_with_p1_suffix() {
        // Manifest says RToken.issue at p1/RToken.sol; Sluice emits RTokenP1.issue.
        let k = known("RToken", "issue", "protocol/contracts/p1/RToken.sol", 177, "signed-cast", true);
        let e = emit("IntegerOverflow", "Medium", "RTokenP1", "issue", "/abs/protocol/contracts/p1/RToken.sol", 233);
        // location: same normalized contract + function.
        assert_eq!(location_match(&k, &e), LocMatch::ContractFunction);
        // class: IntegerOverflow is compatible with signed-cast.
        assert!(class_match(&k, &e));
        let out = score_known(&k, std::slice::from_ref(&e), false);
        assert!(out.caught);
    }

    #[test]
    fn line_window_matches_within_five() {
        let k = known("Foo", "bar", "src/Foo.sol", 100, "missing-zero-check", true);
        let near = emit("MissingZeroCheck", "Low", "Foo", "different", "/abs/src/Foo.sol", 104);
        // Function differs, but file basename + line within ±5 → FileLine.
        assert_eq!(location_match(&k, &near), LocMatch::FileLine);
        let far = emit("MissingZeroCheck", "Low", "Foo", "different", "/abs/src/Foo.sol", 120);
        assert_eq!(location_match(&k, &far), LocMatch::None);
    }

    #[test]
    fn class_mismatch_is_near_not_caught() {
        // A reentrancy-class emission at a signed-cast bug's location: location
        // matches, class does not → not caught (default), flagged location_only.
        let k = known("RToken", "redeem", "protocol/contracts/p1/RToken.sol", 439, "erc777-reentrancy", true);
        let e = emit("OracleManipulation", "High", "RTokenP1", "redeem", "/abs/protocol/contracts/p1/RToken.sol", 480);
        let out = score_known(&k, std::slice::from_ref(&e), false);
        assert!(!out.caught);
        assert!(out.location_only);
        // Lenient (location ceiling): any-class location match counts.
        let out2 = score_known(&k, std::slice::from_ref(&e), true);
        assert!(out2.caught);
    }

    #[test]
    fn out_of_class_has_no_compatible_categories() {
        // Economic/logic invariants the pattern set does not model still map to
        // nothing (catchable only by the location-only ceiling).
        assert!(compatible_categories("economic-invariant").is_empty());
        // An unknown class also yields none (cannot silently match on class).
        assert!(compatible_categories("totally-made-up").is_empty());
    }

    #[test]
    fn value_source_discipline_maps_precisely_no_spurious_channel() {
        // PHASE B1: the LoopFi-H-01 class is now modeled by the invariant engine's
        // value-source-discipline detector. The catch must score via the PRECISE
        // `value-source-discipline` bug_class — it stays out-of-class for the tally
        // (governed by the manifest `in_class` flag), so catching it moves
        // *out-of-class* recall.
        assert_eq!(compatible_categories("value-source-discipline"), &["ValueSourceDiscipline"]);
        // Anti-spurious-channel: the coarse `accounting-invariant` label also tags
        // two UNRELATED Tigris price/margin findings. It must NOT map to any modeled
        // category, so a `ValueSourceDiscipline` emission landing near those Tigris
        // lines cannot falsely score them as caught.
        assert!(compatible_categories("accounting-invariant").is_empty());
    }

    #[test]
    fn unmatched_crit_high_counts_as_candidate_fp() {
        let knowns = vec![known("RToken", "issue", "p1/RToken.sol", 177, "signed-cast", true)];
        // A High oracle finding nowhere near a known finding → unmatched.
        let e = emit("OracleManipulation", "High", "Furnace", "melt", "/abs/p1/Furnace.sol", 37);
        assert!(!emitted_matches_any_known(&e, &knowns));
        assert!(e.is_crit_or_high());
    }
}
