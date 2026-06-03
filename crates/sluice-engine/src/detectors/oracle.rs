//! Spot-price oracle manipulation: a manipulable price (`balanceOf`,
//! `getReserves`, `pricePerShare`, ...) feeds protocol accounting with no robust
//! oracle / TWAP. The Cream / Harvest / bZx class.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::detectors::{find_spot_price, is_accounting_name};
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{CallKind, Expr, ExprKind, Function, Span};

pub struct OracleDetector;

impl Detector for OracleDetector {
    fn id(&self) -> &'static str {
        "oracle-manipulation"
    }
    fn category(&self) -> Category {
        Category::OracleManipulation
    }
    fn description(&self) -> &'static str {
        "Manipulable spot price (balanceOf/getReserves/pricePerShare) used for value"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || !f.is_externally_reachable() {
                continue;
            }
            // Robust oracle present → suppress (Chainlink staleness is a separate class).
            if cx.uses_robust_oracle(f) {
                continue;
            }
            // A spot price may be read locally, OR reached cross-contract: the
            // function calls an external oracle whose in-repo implementation
            // itself reads a manipulable spot source (resolved via the frontier's
            // ContractResolver). The latter is invisible to single-contract tools.
            let (price_span, cross) = match find_spot_price(f) {
                Some(s) => (s, false),
                None => match find_cross_contract_spot_oracle(cx, f) {
                    Some(s) => (s, true),
                    None => continue,
                },
            };
            // The price must influence accounting: a write to an accounting var,
            // or the function mints/borrows/values something.
            let writes_accounting = f.effects.written_vars().iter().any(|v| is_accounting_name(v));
            let valuation_name = {
                let l = f.name.to_ascii_lowercase();
                l.contains("price")
                    || l.contains("value")
                    || l.contains("collateral")
                    || l.contains("mint")
                    || l.contains("borrow")
                    || l.contains("deposit")
                    || l.contains("redeem")
                    || l.contains("liquidat")
            };
            if !writes_accounting && !valuation_name {
                continue;
            }

            let message = if cross {
                format!(
                    "`{}` values assets via an external oracle whose in-repo implementation derives \
                     its price from an instantaneous spot source (`getReserves`/`balanceOf`/`slot0`). \
                     The dependency is cross-contract, so the manipulation surface is not visible in \
                     this function alone, but an attacker can still move the underlying pool within one \
                     transaction to mint/borrow/liquidate at a false valuation (Cream/Harvest class).",
                    f.name
                )
            } else {
                format!(
                    "`{}` derives a value from an instantaneous on-chain price (a `balanceOf` / \
                     `getReserves` / `pricePerShare`-style read). An attacker can move that source \
                     within one transaction (flash-loan-assisted) to mint, borrow, or liquidate at a \
                     false valuation — the Cream/Harvest/bZx class.",
                    f.name
                )
            };
            let b = FindingBuilder::new(self.id(), Category::OracleManipulation)
                .title(if cross {
                    "Cross-contract manipulable spot price used for valuation"
                } else {
                    "Manipulable spot price used for valuation"
                })
                .severity(Severity::High)
                .confidence({
                    let base = if cross { 0.5 } else { 0.55 };
                    // An access-controlled valuation can only be driven by a
                    // trusted actor — much lower manipulation risk.
                    if cx.has_access_control(f) { base * 0.5 } else { base }
                })
                .dimension(Dimension::ValueFlow)
                .dimension(Dimension::Frontier)
                .message(message)
                .recommendation(
                    "Price via a manipulation-resistant source: a Chainlink feed with staleness + \
                     deviation checks, or a sufficiently long TWAP; never a single spot reserve / \
                     `balanceOf` (directly or through a thin oracle wrapper).",
                );
            out.push(cx.finish(b, f.id, price_span));
        }
        out
    }
}

/// Find an external call in `f` whose target type resolves (via the cross-contract
/// resolver) to an in-repo implementation that itself reads a manipulable spot
/// price. Returns the call's span.
fn find_cross_contract_spot_oracle(cx: &AnalysisContext, f: &Function) -> Option<Span> {
    let mut hit: Option<Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if !c.kind.is_external_transfer_of_control() {
                    return;
                }
                let (Some(method), Some(recv)) = (c.func_name.as_deref(), c.receiver.as_deref())
                else {
                    return;
                };
                if let Some(ty) = receiver_type(cx, f, recv) {
                    if cx.frontier.resolver.resolves_to_spot_oracle(cx.scir, &ty, method).is_some() {
                        hit = Some(e.span);
                    }
                }
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Best-effort type name of a call receiver: an interface cast `IOracle(x)`, or
/// the declared type of a parameter / state variable named like the receiver.
fn receiver_type(cx: &AnalysisContext, f: &Function, recv: &Expr) -> Option<String> {
    match &recv.kind {
        // `IOracle(addr).method()` — the cast's name is the type.
        ExprKind::Call(c) if c.kind == CallKind::TypeCast => c.func_name.clone(),
        ExprKind::Ident(name) => {
            if let Some(p) = f.params.iter().find(|p| p.name.as_deref() == Some(name.as_str())) {
                return Some(first_token(&p.ty));
            }
            if let Some(c) = cx.contract_of(f.id) {
                if let Some(v) = c.state_vars.iter().find(|v| &v.name == name) {
                    return Some(first_token(&v.ty));
                }
            }
            None
        }
        _ => None,
    }
}

fn first_token(ty: &str) -> String {
    ty.split_whitespace().next().unwrap_or(ty).to_string()
}
