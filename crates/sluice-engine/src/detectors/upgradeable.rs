//! Proxy / upgradeable hazards: controlled delegatecall and uninitialized
//! (UUPS) implementations.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::detectors::visit_calls;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::CallKind;
use std::collections::HashSet;

pub struct UpgradeableDetector;

impl Detector for UpgradeableDetector {
    fn id(&self) -> &'static str {
        "upgradeable"
    }
    fn category(&self) -> Category {
        Category::DelegatecallStorage
    }
    fn description(&self) -> &'static str {
        "Controlled delegatecall and uninitialized upgradeable implementations"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        // (1) Controlled delegatecall: target is not a constant/immutable.
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            let immutables: HashSet<String> = cx
                .scir
                .contract(f.contract)
                .map(|c| {
                    c.state_vars
                        .iter()
                        .filter(|v| v.constant || v.immutable)
                        .map(|v| v.name.clone())
                        .collect()
                })
                .unwrap_or_default();

            visit_calls(f, |c, span| {
                if c.kind == CallKind::DelegateCall {
                    let target_root = c
                        .receiver
                        .as_ref()
                        .and_then(|r| r.simple_name())
                        .unwrap_or("")
                        .to_string();
                    let constant_target = immutables.contains(&target_root)
                        || c.receiver.as_ref().map(|r| matches!(r.kind, sluice_ir::ExprKind::Lit(_))).unwrap_or(false);
                    if !constant_target {
                        let attacker = c
                            .receiver
                            .as_ref()
                            .map(|r| cx.is_attacker_controlled(f.id, r))
                            .unwrap_or(false);
                        let mut b = FindingBuilder::new(self.id(), Category::DelegatecallStorage)
                            .title("delegatecall to a non-constant target")
                            .severity(if attacker { Severity::Critical } else { Severity::High })
                            .confidence(if attacker { 0.75 } else { 0.5 })
                            .dimension(Dimension::Frontier)
                            .message(format!(
                                "`{}` delegatecalls into `{}`, which is not a constant/immutable address. \
                                 delegatecall runs foreign code against THIS contract's storage; a \
                                 controllable target is an arbitrary-write / takeover primitive (Parity class).",
                                f.name, target_root
                            ))
                            .recommendation(
                                "delegatecall only to a hardcoded/immutable, audited implementation; never to \
                                 an address derived from input or mutable storage.",
                            );
                        if attacker {
                            b = b.dimension(Dimension::ValueFlow);
                        }
                        out.push(cx.finish(b, f.id, span));
                    }
                }
            });
        }

        // (2) Uninitialized upgradeable implementation (UUPS): inherits an
        //     Initializable/UUPS mixin, has an initializer, but the constructor
        //     doesn't call `_disableInitializers()`.
        for c in cx.scir.iter_contracts() {
            let has_initializer = cx
                .scir
                .functions_of(c.id)
                .any(|f| cx.is_initializer(f) || f.name.to_ascii_lowercase().contains("initialize"));
            // A UUPS-style upgrade hook is strong evidence of an upgradeable
            // implementation even without an `Initializable` base (many projects
            // inline the pattern).
            let has_upgrade_hook = cx.scir.functions_of(c.id).any(|f| {
                let n = f.name.to_ascii_lowercase();
                n.contains("upgradeto") || n.contains("_authorizeupgrade") || n == "proxiableuuid"
            });
            let upgradeable = c.inherits_like("initializable")
                || c.inherits_like("uupsupgradeable")
                || c.inherits_like("upgradeable")
                || (has_initializer && has_upgrade_hook);
            if !upgradeable || !has_initializer {
                continue;
            }
            let ctor = cx.scir.functions_of(c.id).find(|f| f.is_constructor());
            let disables = ctor
                .map(|f| cx.scir.span_text(f.span).contains("_disableInitializers"))
                .unwrap_or(false);
            if !disables {
                let span = c.span;
                let b = FindingBuilder::new(self.id(), Category::UninitializedProxy)
                    .title("Upgradeable implementation may be left uninitialized")
                    .severity(Severity::High)
                    .confidence(0.55)
                    .dimension(Dimension::Invariant)
                    .message(format!(
                        "`{}` is upgradeable with an `initialize` function but its constructor does not call \
                         `_disableInitializers()`. The implementation contract can be initialized by anyone \
                         and (for UUPS) self-destructed/bricked — the Parity/Wormhole-impl class.",
                        c.name
                    ))
                    .recommendation("Call `_disableInitializers()` in the implementation's constructor.");
                out.push(b.at(cx.scir, c.name.clone(), "constructor", span).build());
            }
        }
        out
    }
}
