//! Matching a known finding against Sluice's emitted findings, and the
//! per-contest / aggregate scoreboard tallies.

use crate::manifest::{compatible_categories, KnownFinding, Manifest};
use serde::Deserialize;
use std::path::Path;

/// The subset of a `sluice scan --format json` finding the harness reads. Parsed
/// from the raw JSON so the harness never links the engine crate; `severity` and
/// `category` are the serde enum-variant names (`"High"`, `"SignedCast"`).
#[derive(Debug, Clone, Deserialize)]
pub struct EmittedFinding {
    pub category: String,
    pub severity: String,
    #[serde(default)]
    pub contract: String,
    #[serde(default)]
    pub function: String,
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub line: usize,
}

impl EmittedFinding {
    pub fn is_crit_or_high(&self) -> bool {
        matches!(self.severity.as_str(), "Critical" | "High")
    }
}

/// Window (in source lines) within which a finding counts as "same location".
pub const LINE_WINDOW: i64 = 5;

/// Normalize a contract name for matching: lowercase and strip a trailing
/// `p0`/`p1`/`v1`/`v2`/`v3` implementation suffix (the Reserve repo ships
/// `RTokenP0` and `RTokenP1` for the one logical `RToken`).
pub fn norm_contract(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    for suf in ["p0", "p1", "v1", "v2", "v3"] {
        if let Some(stripped) = lower.strip_suffix(suf) {
            if !stripped.is_empty() {
                return stripped.to_string();
            }
        }
    }
    lower
}

/// Normalize a function name (lowercase, drop a leading underscore so `_claim`
/// and `claim` compare equal).
pub fn norm_fn(name: &str) -> String {
    name.trim_start_matches('_').to_ascii_lowercase()
}

/// File basename, lowercased (manifests store repo-relative paths; Sluice emits
/// absolute paths — compare on the file name).
pub fn basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// Why (if at all) an emitted finding matches a known finding's *location*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocMatch {
    /// Same contract (normalized) AND same function (normalized).
    ContractFunction,
    /// Same file basename AND within ±LINE_WINDOW lines.
    FileLine,
    /// Same file basename AND same normalized function (handles P0/P1 where the
    /// emitted contract differs but the function name is unique in the file).
    FileFunction,
    None,
}

/// Does `emitted` sit at the same location as the known finding `k`?
pub fn location_match(k: &KnownFinding, e: &EmittedFinding) -> LocMatch {
    let same_file = basename(&k.file) == basename(&e.file);
    let same_fn = !k.function.is_empty() && norm_fn(&k.function) == norm_fn(&e.function);
    let same_contract = norm_contract(&k.contract) == norm_contract(&e.contract);
    let near_line = e.line != 0 && (e.line as i64 - k.line as i64).abs() <= LINE_WINDOW;

    if same_contract && same_fn {
        LocMatch::ContractFunction
    } else if same_file && same_fn {
        LocMatch::FileFunction
    } else if same_file && near_line {
        LocMatch::FileLine
    } else {
        LocMatch::None
    }
}

/// Is the emitted finding's class compatible with the known finding's class?
pub fn class_match(k: &KnownFinding, e: &EmittedFinding) -> bool {
    compatible_categories(&k.bug_class).contains(&e.category.as_str())
}

/// The outcome of scoring one known finding against all emitted findings.
#[derive(Debug, Clone)]
pub struct KnownOutcome {
    pub caught: bool,
    /// The emitted finding that caught it (category + location), for the report.
    pub by: Option<String>,
    /// Whether a finding sits at the right *location* but with an incompatible
    /// class (a "near miss" — useful signal for the loop).
    pub location_only: bool,
}

/// Score one known finding. A catch requires a compatible-class finding at a
/// matching location. With `lenient_class`, a location match alone (any class)
/// counts as caught — used to measure the *location ceiling* separately.
pub fn score_known(k: &KnownFinding, emitted: &[EmittedFinding], lenient_class: bool) -> KnownOutcome {
    let mut location_only = false;
    for e in emitted {
        let loc = location_match(k, e);
        if loc == LocMatch::None {
            continue;
        }
        let cls = class_match(k, e);
        if cls || lenient_class {
            return KnownOutcome {
                caught: true,
                by: Some(format!("{} @ {}:{}", e.category, basename(&e.file), e.line)),
                location_only: !cls,
            };
        }
        // Location matched but class didn't — remember as a near miss.
        location_only = true;
    }
    KnownOutcome { caught: false, by: None, location_only }
}

/// Does this emitted Crit/High finding match *any* known finding (compatible
/// class at a matching location)? Used for the precision proxy: unmatched
/// Crit/High findings are candidate false positives to triage.
pub fn emitted_matches_any_known(e: &EmittedFinding, knowns: &[KnownFinding]) -> bool {
    knowns.iter().any(|k| {
        location_match(k, e) != LocMatch::None && class_match(k, e)
    })
}

/// Per-contest scoreboard row.
#[derive(Debug, Clone, Default)]
pub struct ContestScore {
    pub name: String,
    /// Source repo (`org/name`) and pinned commit, echoed into the report so the
    /// scoreboard is self-describing / reproducible.
    pub repo: String,
    pub commit: Option<String>,
    pub in_class_total: usize,
    pub in_class_caught: usize,
    pub out_class_total: usize,
    pub out_class_caught: usize,
    /// Total Sluice findings emitted across the scope.
    pub emitted_total: usize,
    /// Crit/High count + how many are unmatched (candidate FPs).
    pub crit_high_total: usize,
    pub crit_high_unmatched: usize,
    /// Per-known detail lines (id, caught, how) for the verbose report.
    pub details: Vec<KnownDetail>,
}

#[derive(Debug, Clone)]
pub struct KnownDetail {
    pub id: String,
    pub severity: String,
    pub in_class: bool,
    pub caught: bool,
    pub by: Option<String>,
    pub location_only: bool,
    pub bug_class: String,
    pub location: String,
    pub summary: String,
}

impl ContestScore {
    pub fn in_class_recall(&self) -> f64 {
        pct(self.in_class_caught, self.in_class_total)
    }
    pub fn out_class_recall(&self) -> f64 {
        pct(self.out_class_caught, self.out_class_total)
    }
}

/// Score one contest given its manifest and the findings Sluice emitted on it.
pub fn score_contest(m: &Manifest, emitted: &[EmittedFinding], lenient_class: bool) -> ContestScore {
    let mut s = ContestScore {
        name: m.name.clone(),
        repo: m.repo.clone(),
        commit: m.commit.clone(),
        emitted_total: emitted.len(),
        ..Default::default()
    };
    for k in &m.known_findings {
        let out = score_known(k, emitted, lenient_class);
        if k.in_class {
            s.in_class_total += 1;
            if out.caught {
                s.in_class_caught += 1;
            }
        } else {
            s.out_class_total += 1;
            if out.caught {
                s.out_class_caught += 1;
            }
        }
        s.details.push(KnownDetail {
            id: k.id.clone(),
            severity: k.severity.clone(),
            in_class: k.in_class,
            caught: out.caught,
            by: out.by,
            location_only: out.location_only && !out.caught,
            bug_class: k.bug_class.clone(),
            location: format!("{}:{} {}.{}", basename(&k.file), k.line, k.contract, k.function),
            summary: k.summary.clone(),
        });
    }
    for e in emitted {
        if e.is_crit_or_high() {
            s.crit_high_total += 1;
            if !emitted_matches_any_known(e, &m.known_findings) {
                s.crit_high_unmatched += 1;
            }
        }
    }
    s
}

/// Aggregate across contests.
#[derive(Debug, Clone, Default)]
pub struct Aggregate {
    pub in_class_total: usize,
    pub in_class_caught: usize,
    pub out_class_total: usize,
    pub out_class_caught: usize,
    pub emitted_total: usize,
    pub crit_high_total: usize,
    pub crit_high_unmatched: usize,
}

impl Aggregate {
    pub fn add(&mut self, c: &ContestScore) {
        self.in_class_total += c.in_class_total;
        self.in_class_caught += c.in_class_caught;
        self.out_class_total += c.out_class_total;
        self.out_class_caught += c.out_class_caught;
        self.emitted_total += c.emitted_total;
        self.crit_high_total += c.crit_high_total;
        self.crit_high_unmatched += c.crit_high_unmatched;
    }
    pub fn in_class_recall(&self) -> f64 {
        pct(self.in_class_caught, self.in_class_total)
    }
    pub fn out_class_recall(&self) -> f64 {
        pct(self.out_class_caught, self.out_class_total)
    }
}

fn pct(num: usize, den: usize) -> f64 {
    if den == 0 {
        0.0
    } else {
        100.0 * num as f64 / den as f64
    }
}
