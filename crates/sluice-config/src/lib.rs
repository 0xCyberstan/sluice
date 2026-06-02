//! # sluice-config
//!
//! TOML configuration with protocol **profiles** and a TP/FP **feedback**
//! database — mirroring `vortex-config`. A profile (`vault`, `lending`, `amm`,
//! `bridge`, `staking`, `governance`) preloads the emphasis and thresholds that
//! suit a protocol class, so the same engine sharpens itself per target.

mod feedback;

pub use feedback::{FeedbackDb, Verdict};

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Protocol class, used to bias detector selection and thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    #[default]
    Generic,
    Vault,
    Lending,
    Amm,
    Bridge,
    Staking,
    Governance,
}

impl Profile {
    pub fn from_str_loose(s: &str) -> Option<Profile> {
        Some(match s.to_ascii_lowercase().as_str() {
            "generic" | "default" => Profile::Generic,
            "vault" | "erc4626" | "4626" => Profile::Vault,
            "lending" | "lend" | "money-market" => Profile::Lending,
            "amm" | "dex" | "swap" => Profile::Amm,
            "bridge" | "crosschain" | "cross-chain" => Profile::Bridge,
            "staking" | "stake" | "rewards" => Profile::Staking,
            "governance" | "gov" | "dao" => Profile::Governance,
            _ => return None,
        })
    }

    pub fn slug(self) -> &'static str {
        match self {
            Profile::Generic => "generic",
            Profile::Vault => "vault",
            Profile::Lending => "lending",
            Profile::Amm => "amm",
            Profile::Bridge => "bridge",
            Profile::Staking => "staking",
            Profile::Governance => "governance",
        }
    }

    /// Detector ids this profile especially cares about (used to raise their
    /// confidence floor / surface them). Empty means "all detectors equally".
    pub fn emphasis(self) -> &'static [&'static str] {
        match self {
            Profile::Generic => &[],
            Profile::Vault => &["erc4626-inflation", "first-depositor", "rounding-direction", "reentrancy"],
            Profile::Lending => &["oracle-manipulation", "missing-solvency-check", "rounding-direction", "price-manipulation"],
            Profile::Amm => &["oracle-manipulation", "slippage", "read-only-reentrancy", "reentrancy"],
            Profile::Bridge => &["bridge-verification", "signature-replay", "access-control", "selector-collision"],
            Profile::Staking => &["reward-accounting", "rounding-direction", "reentrancy"],
            Profile::Governance => &["flashloan-governance", "access-control"],
        }
    }
}

/// Top-level configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub profile: Profile,
    /// Findings below this confidence are dropped.
    pub min_confidence: f32,
    /// Detector ids to disable.
    pub disabled: Vec<String>,
    /// If non-empty, ONLY these detector ids run.
    pub enabled_only: Vec<String>,
    /// `Contract.function` or `function` substrings to suppress.
    pub suppress: Vec<String>,
    /// Path substrings to exclude during file discovery.
    pub exclude_paths: Vec<String>,
    /// Cap on findings per (contract, function) to avoid floods.
    pub max_findings_per_function: usize,
    /// Path to the feedback database (TP/FP verdicts).
    pub feedback_path: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            profile: Profile::Generic,
            min_confidence: 0.35,
            disabled: Vec::new(),
            enabled_only: Vec::new(),
            suppress: Vec::new(),
            exclude_paths: default_excludes(),
            max_findings_per_function: 25,
            feedback_path: None,
        }
    }
}

fn default_excludes() -> Vec<String> {
    [
        "node_modules/",
        "/lib/",
        "lib/forge-std",
        "lib/openzeppelin",
        "/test/",
        "/tests/",
        ".t.sol",
        "/mock",
        "/mocks/",
        "/script/",
        ".s.sol",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Config {
    /// A config tuned for a protocol profile.
    pub fn for_profile(profile: Profile) -> Self {
        Config { profile, ..Default::default() }
    }

    /// Load from a TOML file, falling back to defaults for missing keys.
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&text)?;
        Ok(cfg)
    }

    pub fn detector_enabled(&self, id: &str) -> bool {
        if !self.enabled_only.is_empty() {
            return self.enabled_only.iter().any(|d| d == id);
        }
        !self.disabled.iter().any(|d| d == id)
    }

    /// True if a finding at `contract.function` should be suppressed.
    pub fn is_suppressed(&self, contract: &str, function: &str) -> bool {
        let qualified = format!("{contract}.{function}");
        self.suppress.iter().any(|s| qualified.contains(s.as_str()) || function == s)
    }

    /// True if a discovered path should be excluded from analysis.
    pub fn is_excluded(&self, path: &str) -> bool {
        self.exclude_paths.iter().any(|e| path.contains(e.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_parsing_and_toml() {
        assert_eq!(Profile::from_str_loose("ERC4626"), Some(Profile::Vault));
        let cfg: Config = toml::from_str("profile = \"lending\"\nmin_confidence = 0.5\n").unwrap();
        assert_eq!(cfg.profile, Profile::Lending);
        assert!((cfg.min_confidence - 0.5).abs() < 1e-6);
        assert!(!cfg.exclude_paths.is_empty(), "defaults fill in");
    }

    #[test]
    fn suppress_and_enable() {
        let mut cfg = Config::default();
        cfg.suppress.push("Vault.skim".into());
        assert!(cfg.is_suppressed("Vault", "skim"));
        assert!(!cfg.is_suppressed("Vault", "deposit"));
        cfg.enabled_only.push("reentrancy".into());
        assert!(cfg.detector_enabled("reentrancy"));
        assert!(!cfg.detector_enabled("oracle-manipulation"));
    }
}
