//! `sluice` — point it at a Solidity codebase and it hunts the complex,
//! high-payout bug classes that audits and bounties reward.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use sluice_config::{Config, FeedbackDb, Profile, Verdict};
use sluice_engine::{analyze_paths, builtin_detectors, Severity};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name = "sluice", version, about = "Smart-contract vulnerability analysis that hunts high-payout bug classes")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Analyze a Solidity file or directory.
    Scan(ScanArgs),
    /// List the built-in detectors.
    Detectors,
    /// List the protocol profiles.
    Profiles,
    /// Write a starter `sluice.toml` config.
    Init {
        #[arg(default_value = "sluice.toml")]
        path: PathBuf,
    },
    /// Record a true/false-positive verdict to tune future scoring.
    Feedback {
        /// Finding dedup key (printed by `scan --format json`).
        key: String,
        #[arg(long, conflicts_with = "fp")]
        tp: bool,
        #[arg(long)]
        fp: bool,
        #[arg(long, default_value = "sluice-feedback.json")]
        db: PathBuf,
    },
}

#[derive(Parser)]
struct ScanArgs {
    /// File or directory to analyze.
    path: PathBuf,
    /// Protocol profile (generic, vault, lending, amm, bridge, staking, governance).
    #[arg(long, short)]
    profile: Option<String>,
    /// Config file (TOML).
    #[arg(long, short)]
    config: Option<PathBuf>,
    /// Output format.
    #[arg(long, short, default_value = "console")]
    format: Format,
    /// Write the report to a file instead of stdout.
    #[arg(long, short)]
    out: Option<PathBuf>,
    /// Minimum confidence to report (0.0–1.0).
    #[arg(long)]
    min_confidence: Option<f32>,
    /// Only run these detector ids (comma-separated).
    #[arg(long, value_delimiter = ',')]
    only: Vec<String>,
    /// Disable these detector ids (comma-separated).
    #[arg(long, value_delimiter = ',')]
    disable: Vec<String>,
    /// Attach a Foundry PoC skeleton to the top findings.
    #[arg(long)]
    poc: bool,
    /// Limit to the top N findings.
    #[arg(long)]
    top: Option<usize>,
    /// Exit non-zero if any finding is at or above this severity (for CI).
    #[arg(long)]
    fail_on: Option<SeverityArg>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Format {
    Console,
    Markdown,
    Json,
    Sarif,
    Html,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl SeverityArg {
    fn to_sev(self) -> Severity {
        match self {
            SeverityArg::Critical => Severity::Critical,
            SeverityArg::High => Severity::High,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Info => Severity::Info,
        }
    }
}

fn main() {
    // Parse args on the main thread (so clap's --help/--version exit cleanly),
    // then run analysis on a worker thread with a large (1 GiB) stack. Solidity
    // can nest expressions arbitrarily deep, and a recursive-descent parse +
    // analysis of a pathological/adversarial file would otherwise overflow the
    // default 8 MiB stack and abort the process — a hostile-input DoS that would
    // crash CI. The big stack absorbs realistic worst cases gracefully.
    let cli = Cli::parse();
    let code = std::thread::Builder::new()
        .stack_size(1024 * 1024 * 1024)
        .spawn(move || dispatch(cli))
        .ok()
        .and_then(|h| h.join().ok())
        .unwrap_or(2);
    std::process::exit(code);
}

fn dispatch(cli: Cli) -> i32 {
    match cli.cmd {
        Cmd::Scan(args) => run_scan(args).unwrap_or_else(|e| {
            eprintln!("{} {e:#}", "error:".red().bold());
            2
        }),
        Cmd::Detectors => {
            list_detectors();
            0
        }
        Cmd::Profiles => {
            list_profiles();
            0
        }
        Cmd::Init { path } => init_config(&path).map(|_| 0).unwrap_or_else(|e| {
            eprintln!("{} {e:#}", "error:".red().bold());
            2
        }),
        Cmd::Feedback { key, tp, fp, db } => {
            record_feedback(&key, tp, fp, &db).map(|_| 0).unwrap_or_else(|e| {
                eprintln!("{} {e:#}", "error:".red().bold());
                2
            })
        }
    }
}

fn build_config(args: &ScanArgs) -> Result<Config> {
    let mut cfg = if let Some(path) = &args.config {
        Config::load(path).with_context(|| format!("loading config {}", path.display()))?
    } else if let Some(p) = &args.profile {
        let profile = Profile::from_str_loose(p).context("unknown profile")?;
        Config::for_profile(profile)
    } else {
        Config::default()
    };
    if let Some(p) = &args.profile {
        if let Some(profile) = Profile::from_str_loose(p) {
            cfg.profile = profile;
        }
    }
    if let Some(mc) = args.min_confidence {
        cfg.min_confidence = mc;
    }
    if !args.only.is_empty() {
        cfg.enabled_only = args.only.clone();
    }
    if !args.disable.is_empty() {
        cfg.disabled.extend(args.disable.clone());
    }
    Ok(cfg)
}

fn discover_sol_files(root: &Path, cfg: &Config) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    let mut files = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().map(|e| e == "sol").unwrap_or(false) {
            let s = path.to_string_lossy();
            if !cfg.is_excluded(&s) {
                files.push(path.to_path_buf());
            }
        }
    }
    files
}

fn run_scan(args: ScanArgs) -> Result<i32> {
    let cfg = build_config(&args)?;
    let files = discover_sol_files(&args.path, &cfg);
    if files.is_empty() {
        anyhow::bail!("no .sol files found under {}", args.path.display());
    }
    eprintln!(
        "{} {} Solidity file(s) · profile {}",
        "scanning".cyan().bold(),
        files.len(),
        cfg.profile.slug().yellow()
    );

    let mut result = analyze_paths(&files, &cfg);
    for e in &result.parse_errors {
        eprintln!("{} {e}", "parse:".yellow());
    }

    if let Some(top) = args.top {
        result.findings.truncate(top);
    }
    if args.poc {
        sluice_verify::attach_pocs(&result.scir, &mut result.findings, 10);
    }

    let project = args
        .path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".into());

    let rendered = match args.format {
        Format::Console => render_console(&result.findings),
        Format::Markdown => sluice_findings::markdown(&result.findings, &project),
        Format::Json => sluice_findings::json(&result.findings),
        Format::Sarif => sluice_findings::sarif(&result.findings),
        Format::Html => sluice_findings::html(&result.findings, &project),
    };

    match &args.out {
        Some(path) => {
            std::fs::write(path, &rendered).with_context(|| format!("writing {}", path.display()))?;
            eprintln!("{} {}", "wrote".green().bold(), path.display());
        }
        None => println!("{rendered}"),
    }

    // Always print a short summary to stderr.
    eprintln!(
        "\n{} analyzed {} contracts / {} functions with {} detectors → {} findings",
        "done:".green().bold(),
        result.stats.contracts,
        result.stats.functions,
        result.stats.detectors_run,
        result.findings.len()
    );

    if let Some(threshold) = args.fail_on {
        let t = threshold.to_sev();
        if result.findings.iter().any(|f| f.severity >= t) {
            return Ok(1);
        }
    }
    Ok(0)
}

fn render_console(findings: &[sluice_findings::Finding]) -> String {
    let mut out = String::new();
    for f in findings {
        let sev = match f.severity {
            Severity::Critical => f.severity.label().red().bold(),
            Severity::High => f.severity.label().red(),
            Severity::Medium => f.severity.label().yellow(),
            Severity::Low => f.severity.label().normal(),
            Severity::Info => f.severity.label().dimmed(),
        };
        let dims: Vec<&str> = f.dimensions.iter().map(|d| d.label()).collect();
        out.push_str(&format!(
            "{}  {:<10} {}  {}\n      {}  {}  {}\n",
            format!("[{}]", f.id).dimmed(),
            sev,
            f.category.slug().cyan(),
            f.title.bold(),
            format!("{}:{}", f.file, f.line).dimmed(),
            format!("{}.{}", f.contract, f.function).blue(),
            format!("score {:.0} · conf {:.0}% · {}", f.severity_score, f.confidence * 100.0, dims.join("+")).dimmed(),
        ));
    }
    let c = sluice_findings::severity_counts(findings);
    out.push_str(&format!(
        "\n  {}  {}  {}  {}  {}\n",
        format!("Critical {}", c[0].1).red().bold(),
        format!("High {}", c[1].1).red(),
        format!("Medium {}", c[2].1).yellow(),
        format!("Low {}", c[3].1).normal(),
        format!("Info {}", c[4].1).dimmed(),
    ));
    out
}

fn list_detectors() {
    println!("{}", "Built-in detectors:".bold());
    for d in builtin_detectors() {
        println!("  {:<22} {}", d.id().cyan(), d.description());
    }
}

fn list_profiles() {
    println!("{}", "Protocol profiles:".bold());
    for p in [
        Profile::Generic,
        Profile::Vault,
        Profile::Lending,
        Profile::Amm,
        Profile::Bridge,
        Profile::Staking,
        Profile::Governance,
    ] {
        let emph = p.emphasis().join(", ");
        println!("  {:<12} {}", p.slug().yellow(), if emph.is_empty() { "all detectors".into() } else { emph });
    }
}

fn init_config(path: &Path) -> Result<()> {
    let sample = r#"# Sluice configuration
profile = "generic"        # generic | vault | lending | amm | bridge | staking | governance
min_confidence = 0.35

# disabled = ["timestamp-dependence"]
# enabled_only = ["reentrancy", "oracle-manipulation"]
# suppress = ["MockToken.transfer"]
# feedback_path = "sluice-feedback.json"
"#;
    std::fs::write(path, sample).with_context(|| format!("writing {}", path.display()))?;
    println!("{} {}", "wrote".green().bold(), path.display());
    Ok(())
}

fn record_feedback(key: &str, tp: bool, fp: bool, db_path: &Path) -> Result<()> {
    if tp == fp {
        anyhow::bail!("specify exactly one of --tp or --fp");
    }
    let mut db = FeedbackDb::load(db_path);
    db.record(key, if tp { Verdict::TruePositive } else { Verdict::FalsePositive });
    db.save(db_path)?;
    println!("{} recorded {} for {key}", "feedback:".green().bold(), if tp { "TP" } else { "FP" });
    Ok(())
}
