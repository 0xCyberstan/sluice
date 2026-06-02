//! Corroboration scoring — the heart of Sluice's false-positive suppression,
//! adapted from `vortex`'s dimensional multiplier.
//!
//! `score = base(severity) × dimension_multiplier × confidence_factor`
//!
//! A finding implicated by two or three independent analysis dimensions
//! (value-flow, invariant, frontier) is multiplied up, so corroborated findings
//! rise to the top and lone-dimension noise sinks. The final severity *label*
//! is derived from the score, so corroboration can promote a Medium to a
//! Critical — exactly the composition effect that made `vortex` precise.

use sluice_findings::{Finding, Severity};

/// Multiplier for the number of corroborating dimensions.
pub fn dimension_multiplier(dims: usize) -> f32 {
    match dims {
        0 | 1 => 1.0,
        2 => 1.5,
        _ => 2.0,
    }
}

/// Compute `(score, label)` for a finding.
///
/// Confidence is weighted heavily (`0.5 + 0.5·conf`) so that a lone, low-confidence
/// heuristic settles into Low/Info while a corroborated, high-confidence finding
/// rises to High/Critical. This is what gives the output a usable triage
/// distribution instead of everything piling into High/Medium.
pub fn score(f: &Finding) -> (f32, Severity) {
    let base = f.severity.base_score();
    let mult = dimension_multiplier(f.dimensions.len());
    let conf = 0.5 + 0.5 * f.confidence;
    let s = base * mult * conf;
    (s, label_from_score(s))
}

pub fn label_from_score(s: f32) -> Severity {
    if s >= 100.0 {
        Severity::Critical
    } else if s >= 62.0 {
        Severity::High
    } else if s >= 33.0 {
        Severity::Medium
    } else if s >= 13.0 {
        Severity::Low
    } else {
        Severity::Info
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sluice_findings::{Category, Dimension, FindingBuilder};

    fn f(sev: Severity, dims: &[Dimension], conf: f32) -> Finding {
        let mut b = FindingBuilder::new("t", Category::Reentrancy).severity(sev).confidence(conf);
        for d in dims {
            b = b.dimension(*d);
        }
        b.build()
    }

    #[test]
    fn corroboration_promotes_severity() {
        // A single-dimension High stays High; three dimensions promote to Critical.
        let one = score(&f(Severity::High, &[Dimension::Frontier], 0.8));
        let three = score(&f(
            Severity::High,
            &[Dimension::Frontier, Dimension::Invariant, Dimension::ValueFlow],
            0.8,
        ));
        assert_eq!(one.1, Severity::High);
        assert_eq!(three.1, Severity::Critical);
        assert!(three.0 > one.0);
    }
}
