//! Feedback database: persisted true-positive / false-positive verdicts that
//! tune scoring across runs (the analog of `vortex-config`'s feedback DB).

use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    TruePositive,
    FalsePositive,
}

/// Maps a finding's stable dedup key to a recorded verdict.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeedbackDb {
    #[serde(default)]
    verdicts: FxHashMap<String, Verdict>,
}

impl FeedbackDb {
    pub fn load(path: impl AsRef<Path>) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let text = serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into());
        std::fs::write(path, text)
    }

    pub fn record(&mut self, key: impl Into<String>, verdict: Verdict) {
        self.verdicts.insert(key.into(), verdict);
    }

    pub fn verdict(&self, key: &str) -> Option<Verdict> {
        self.verdicts.get(key).copied()
    }

    /// Multiplier applied to a finding's score given its history:
    /// confirmed FPs are heavily penalized, confirmed TPs are boosted.
    pub fn score_multiplier(&self, key: &str) -> f32 {
        match self.verdict(key) {
            Some(Verdict::FalsePositive) => 0.0,
            Some(Verdict::TruePositive) => 1.25,
            None => 1.0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.verdicts.is_empty()
    }
}
