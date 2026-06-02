//! Missing access control, consensus-guard outliers, and `tx.origin` auth.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::detectors::is_privileged_name;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_invariant::InvariantKind;

pub struct AccessControlDetector;

impl Detector for AccessControlDetector {
    fn id(&self) -> &'static str {
        "access-control"
    }
    fn category(&self) -> Category {
        Category::AccessControl
    }
    fn description(&self) -> &'static str {
        "Unprotected privileged functions, guard-consensus outliers, tx.origin auth"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        // (1) Consensus guard violations (most siblings enforce access control).
        for v in &cx.invariants.violations {
            if let InvariantKind::GuardConsensus { guard } = &v.kind {
                if guard == "access-control" {
                    let conf = (v.consensus * 0.9).clamp(0.4, 0.9);
                    let b = FindingBuilder::new(self.id(), Category::AccessControl)
                        .title("Function skips the access-control guard its siblings enforce")
                        .severity(Severity::High)
                        .confidence(conf)
                        .dimension(Dimension::Invariant)
                        .message(v.description.clone())
                        .recommendation("Add the same authorization modifier/require used by sibling functions.");
                    out.push(cx.finish(b, v.function, v.span));
                }
            }
        }

        // (2) Direct: external state-mutating function writes privileged state
        //     with no access control or initializer guard.
        for f in cx.entry_points() {
            if cx.has_access_control(f) || cx.is_initializer(f) || f.is_constructor() {
                continue;
            }
            let priv_write = f.effects.storage_writes.iter().find(|w| is_privileged_name(&w.var));
            if let Some(w) = priv_write {
                // skip if a sibling-consensus finding already covers it (dedup by line later)
                let b = FindingBuilder::new(self.id(), Category::AccessControl)
                    .title("Privileged state mutable by anyone")
                    .severity(Severity::High)
                    .confidence(0.5)
                    .dimension(Dimension::Invariant)
                    .message(format!(
                        "`{}` writes privileged state `{}` but has no `onlyOwner`/role guard, so any \
                         caller can change it.",
                        f.name, w.var
                    ))
                    .recommendation("Restrict with an access-control modifier (e.g. `onlyOwner`/`onlyRole`).");
                out.push(cx.finish(b, f.id, w.span));
            }

            // (3) tx.origin used for authorization.
            if f.effects.reads_tx_origin
                && f.effects.guards.iter().any(|g| g.text.contains("tx.origin"))
            {
                let b = FindingBuilder::new(self.id(), Category::TxOriginAuth)
                    .title("Authorization via tx.origin")
                    .severity(Severity::High)
                    .confidence(0.7)
                    .dimension(Dimension::ValueFlow)
                    .message(format!(
                        "`{}` authorizes using `tx.origin`, which is phishable: a malicious \
                         intermediary contract passes the check on the victim's behalf.",
                        f.name
                    ))
                    .recommendation("Use `msg.sender` for authorization, never `tx.origin`.");
                out.push(cx.finish(b, f.id, f.span));
            }
        }
        out
    }
}
