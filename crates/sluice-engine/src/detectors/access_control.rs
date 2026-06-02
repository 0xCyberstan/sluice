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
                    // Initializers are guarded by `initializer` (not a per-call auth
                    // modifier), and user-facing functions (deposit/withdraw/claim/…)
                    // are intentionally permissionless — neither is a missing-guard
                    // bug, so don't report them as consensus violations.
                    if let Some(f) = cx.scir.function(v.function) {
                        if cx.is_initializer(f) || is_user_facing(&f.name) || is_framework_hook(&f.name) {
                            continue;
                        }
                    }
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
            // (3) tx.origin authorization — checked FIRST, because a tx.origin
            // guard is itself the vulnerability and would otherwise be mistaken
            // for valid access control and suppressed.
            if uses_tx_origin_auth(cx, f) {
                let b = FindingBuilder::new(self.id(), Category::TxOriginAuth)
                    .title("Authorization via tx.origin")
                    .severity(Severity::High)
                    .confidence(0.7)
                    .dimension(Dimension::ValueFlow)
                    .message(format!(
                        "`{}` authorizes using `tx.origin`, which is phishable: a malicious \
                         intermediary contract the owner is tricked into calling passes the check \
                         on the victim's behalf.",
                        f.name
                    ))
                    .recommendation("Use `msg.sender` for authorization, never `tx.origin`.");
                out.push(cx.finish(b, f.id, f.span));
            }

            if cx.has_access_control(f) || cx.is_initializer(f) || f.is_constructor() || is_framework_hook(&f.name) {
                continue;
            }
            // Admin state is a scalar (`owner = x`), not a per-key mapping write
            // (which is ordinary per-entity bookkeeping). Skip mapping writes.
            let is_mapping_var = |name: &str| {
                cx.contract_of(f.id)
                    .and_then(|c| c.state_vars.iter().find(|v| v.name == name))
                    .map(|v| v.is_mapping())
                    .unwrap_or(false)
            };
            let priv_write = f
                .effects
                .storage_writes
                .iter()
                .find(|w| is_privileged_name(&w.var) && !is_mapping_var(&w.var));
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

        }
        out
    }
}

/// Framework / standard lifecycle hooks that look unguarded but are gated by an
/// implicit single trusted caller (e.g. a Kernel) or are pure metadata — flagging
/// them for "missing access control" is a false positive (Default Framework's
/// `configureDependencies`/`requestPermissions`, ERC-165 `supportsInterface`, …).
fn is_framework_hook(name: &str) -> bool {
    matches!(
        name,
        "configureDependencies"
            | "requestPermissions"
            | "supportsInterface"
            | "KEYCODE"
            | "VERSION"
            | "changeKernel"
            | "onERC721Received"
            | "onERC1155Received"
            | "onERC1155BatchReceived"
            | "tokensReceived"
    )
}

/// Intentionally-permissionless, user-facing function names that should not be
/// flagged for "missing the access-control guard their siblings enforce".
fn is_user_facing(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "deposit", "withdraw", "claim", "mint", "redeem", "stake", "unstake", "swap", "borrow",
        "repay", "transfer", "approve", "permit", "wrap", "unwrap", "harvest", "compound",
        "flashloan", "liquidate", "enter", "exit", "vote", "delegate",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// True if a function authorizes via `tx.origin` — either directly in its body
/// or through an applied modifier whose body reads `tx.origin`.
fn uses_tx_origin_auth(cx: &AnalysisContext, f: &sluice_ir::Function) -> bool {
    if f.effects.reads_tx_origin && f.effects.guards.iter().any(|g| g.text.contains("tx.origin")) {
        return true;
    }
    // Look through applied modifiers (the `onlyOwner { require(tx.origin == owner) }` case).
    for m in &f.modifiers {
        if let Some(modf) = cx
            .scir
            .functions_of(f.contract)
            .find(|x| x.is_modifier() && x.name == m.name)
        {
            if modf.effects.reads_tx_origin {
                return true;
            }
        }
    }
    false
}
