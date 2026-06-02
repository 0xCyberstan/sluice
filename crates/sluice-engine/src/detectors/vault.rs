//! ERC-4626 / vault hazards: first-depositor share-inflation (donation) and
//! divide-before-multiply precision loss.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Contract, ExprKind, Function};

pub struct VaultDetector;

impl Detector for VaultDetector {
    fn id(&self) -> &'static str {
        "vault"
    }
    fn category(&self) -> Category {
        Category::Erc4626Inflation
    }
    fn description(&self) -> &'static str {
        "ERC-4626 first-depositor inflation/donation and precision-loss rounding"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for c in cx.scir.iter_contracts() {
            if !c.is_concrete() || !is_vault_like(cx, c) {
                continue;
            }
            // Inflation mitigation present? OZ ERC4626 offset / virtual shares /
            // dead shares close the donation channel.
            let contract_src = contract_source(cx, c).to_ascii_lowercase();
            let mitigated = contract_src.contains("decimalsoffset")
                || contract_src.contains("_decimaloffset")
                || contract_src.contains("virtual_shares")
                || contract_src.contains("virtualshares")
                || contract_src.contains("dead_shares")
                || contract_src.contains("deadshares")
                || c.inherits_like("erc4626"); // OZ ERC4626 ships virtual offset
            let donatable = contract_src.contains("balanceof(address(this))")
                || contract_src.contains(".balanceof(address(this))")
                || contract_src.contains("totalassets");

            if !mitigated && donatable {
                // locate a deposit/mint function for the report span
                let f = cx
                    .scir
                    .functions_of(c.id)
                    .find(|f| {
                        let n = f.name.to_ascii_lowercase();
                        n.contains("deposit") || n.contains("mint")
                    })
                    .or_else(|| cx.scir.functions_of(c.id).next());
                if let Some(f) = f {
                    let b = FindingBuilder::new(self.id(), Category::Erc4626Inflation)
                        .title("First-depositor / donation share-inflation")
                        .severity(Severity::High)
                        .confidence(0.55)
                        .dimension(Dimension::ValueFlow)
                        .message(format!(
                            "`{}` derives share price from a donatable balance (`balanceOf(address(this))` / \
                             `totalAssets`) with no virtual-shares / decimal-offset / dead-shares defense. \
                             A first depositor can mint 1 wei of shares, donate to inflate the price, and make \
                             every later deposit round to zero shares.",
                            c.name
                        ))
                        .recommendation(
                            "Use OpenZeppelin ERC4626 with a decimals offset (virtual shares), burn dead \
                             shares on first deposit, or track assets internally instead of `balanceOf`.",
                        );
                    out.push(cx.finish(b, f.id, f.span));
                }
            }

            // Divide-before-multiply precision loss in share/asset math.
            for f in cx.scir.functions_of(c.id) {
                if !f.has_body {
                    continue;
                }
                if let Some(span) = find_div_before_mul(f) {
                    let b = FindingBuilder::new(self.id(), Category::PrecisionLoss)
                        .title("Divide-before-multiply precision loss")
                        .severity(Severity::Low)
                        .confidence(0.45)
                        .dimension(Dimension::ValueFlow)
                        .message(format!(
                            "`{}` divides before multiplying, truncating low-order bits and biasing share/asset \
                             conversion (often against the user or the protocol).",
                            f.name
                        ))
                        .recommendation("Reorder to multiply before dividing, or use a mulDiv that rounds explicitly.");
                    out.push(cx.finish(b, f.id, span));
                }
            }
        }
        out
    }
}

fn is_vault_like(cx: &AnalysisContext, c: &Contract) -> bool {
    if c.inherits_like("erc4626") || c.inherits_like("vault") {
        return true;
    }
    let mut has_deposit = false;
    let mut has_redeem = false;
    let mut has_shares = c.state_vars.iter().any(|v| {
        let l = v.name.to_ascii_lowercase();
        l.contains("share") || l.contains("totalsupply")
    });
    for f in cx.scir.functions_of(c.id) {
        let n = f.name.to_ascii_lowercase();
        if n.contains("deposit") || n.contains("mint") {
            has_deposit = true;
        }
        if n.contains("withdraw") || n.contains("redeem") {
            has_redeem = true;
        }
        if n == "totalassets" {
            has_shares = true;
        }
    }
    has_deposit && has_redeem && has_shares
}

fn contract_source<'a>(cx: &'a AnalysisContext, c: &Contract) -> &'a str {
    cx.scir.span_text(c.span)
}

/// Detect `(a / b) * c` — division feeding a multiplication.
fn find_div_before_mul(f: &Function) -> Option<sluice_ir::Span> {
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            if let ExprKind::Binary { op: sluice_ir::BinOp::Mul, lhs, rhs } = &e.kind {
                for side in [lhs, rhs] {
                    if let ExprKind::Binary { op: sluice_ir::BinOp::Div, .. } = &side.kind {
                        found = Some(e.span);
                    }
                }
            }
        });
    }
    found
}
