//! Reentrancy: classic (state-after-call), cross-function, and read-only.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder};
use sluice_frontier::ReentrancyKind;

pub struct ReentrancyDetector;

impl Detector for ReentrancyDetector {
    fn id(&self) -> &'static str {
        "reentrancy"
    }
    fn category(&self) -> Category {
        Category::Reentrancy
    }
    fn description(&self) -> &'static str {
        "External call before state update (classic, cross-function, read-only)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            for r in cx.frontier.reentrancy_of(f.id) {
                if r.guarded || cx.has_reentrancy_guard(f) {
                    continue;
                }
                let (cat, sev, conf, title) = match r.kind {
                    ReentrancyKind::Classic => (
                        Category::Reentrancy,
                        sluice_findings::Severity::High,
                        0.8,
                        "State updated after external call (classic reentrancy)",
                    ),
                    ReentrancyKind::ReadOnly => (
                        Category::ReadOnlyReentrancy,
                        sluice_findings::Severity::High,
                        0.6,
                        "View getter exposes mid-update state (read-only reentrancy)",
                    ),
                    ReentrancyKind::CrossFunction => (
                        Category::Reentrancy,
                        sluice_findings::Severity::Medium,
                        0.55,
                        "Shared state reachable during external call (cross-function reentrancy)",
                    ),
                };
                let mut b = FindingBuilder::new(self.id(), cat)
                    .title(title)
                    .severity(sev)
                    .confidence(conf)
                    .dimension(Dimension::Frontier)
                    .message(format!(
                        "`{}` performs an external call and then touches storage [{}]. An attacker \
                         contract can re-enter before state settles. {}",
                        f.name,
                        r.vars_written_after.join(", "),
                        match r.kind {
                            ReentrancyKind::ReadOnly =>
                                "A consumer reading this getter mid-transaction sees corrupted values.",
                            ReentrancyKind::CrossFunction =>
                                "Re-entering a sibling function that shares this state is profitable.",
                            ReentrancyKind::Classic => "This is the DAO/Curve-class pattern.",
                        }
                    ))
                    .recommendation(
                        "Apply checks-effects-interactions (update storage before the external call) \
                         and/or a `nonReentrant` guard covering all entry points sharing this state.",
                    );
                // Value-flow corroboration: sending ETH makes re-entry trivial.
                if f.effects.call_sites.iter().any(|c| c.sends_value) {
                    b = b.dimension(Dimension::ValueFlow);
                }
                out.push(cx.finish(b, f.id, r.span));
            }
        }
        out
    }
}
