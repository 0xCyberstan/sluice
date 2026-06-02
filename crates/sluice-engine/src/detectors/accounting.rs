//! Invariant-driven accounting bugs: missing solvency/settlement checks
//! (Euler class) and co-update / reward-accounting drift.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_invariant::InvariantKind;

pub struct AccountingDetector;

impl Detector for AccountingDetector {
    fn id(&self) -> &'static str {
        "missing-solvency-check"
    }
    fn category(&self) -> Category {
        Category::MissingSolvencyCheck
    }
    fn description(&self) -> &'static str {
        "Settlement/solvency-check consensus outliers and co-update drift (Euler class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for v in &cx.invariants.violations {
            match &v.kind {
                InvariantKind::SettlementBeforeMutation { routine } => {
                    let conf = (v.consensus * 0.9).clamp(0.45, 0.9);
                    let f = cx.scir.function(v.function);
                    let moves_value = f
                        .map(|f| f.effects.call_sites.iter().any(|c| c.sends_value))
                        .unwrap_or(false);
                    let mut b = FindingBuilder::new(self.id(), Category::MissingSolvencyCheck)
                        .title("Value-moving function skips the solvency/settlement check its siblings enforce")
                        .severity(Severity::High)
                        .confidence(conf)
                        .dimension(Dimension::Invariant)
                        .message(format!(
                            "{} Skipping `{routine}()` can leave the position/pool insolvent or let an \
                             attacker self-induce bad debt — the Euler ($197M) pattern.",
                            v.description
                        ))
                        .recommendation(format!(
                            "Call `{routine}()` (or assert the solvency invariant) on this path, as the \
                             sibling functions do."
                        ));
                    if moves_value {
                        b = b.dimension(Dimension::ValueFlow);
                    }
                    out.push(cx.finish(b, v.function, v.span));
                }
                InvariantKind::CoUpdate { primary, expected } => {
                    let conf = (v.consensus * 0.85).clamp(0.4, 0.85);
                    let cat = if expected.to_ascii_lowercase().contains("reward")
                        || primary.to_ascii_lowercase().contains("reward")
                    {
                        Category::RewardAccounting
                    } else {
                        Category::RewardAccounting
                    };
                    let b = FindingBuilder::new(self.id(), cat)
                        .title("Paired accounting variables updated inconsistently")
                        .severity(Severity::Medium)
                        .confidence(conf)
                        .dimension(Dimension::Invariant)
                        .message(format!(
                            "{} This accounting drift lets supply/share/reward bookkeeping desynchronize.",
                            v.description
                        ))
                        .recommendation(format!(
                            "Update `{expected}` whenever `{primary}` changes (settle rewards / adjust \
                             totals before mutating balances)."
                        ));
                    out.push(cx.finish(b, v.function, v.span));
                }
                InvariantKind::GuardConsensus { .. } => { /* handled by access-control */ }
            }
        }
        out
    }
}
