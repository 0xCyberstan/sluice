//! Rounding-direction hazard: a share/asset conversion in a mint/deposit or
//! withdraw/redeem path computes an amount with integer division but pins no
//! explicit rounding mode. Solidity integer division truncates toward zero, so a
//! conversion that should round *against* the user (down on mint, up on
//! withdraw) instead rounds in the user's favor — bleeding the protocol a few
//! wei per call until the buffer is gone. The ERC-4626 "rounding must favor the
//! vault" rule; this is the class behind a long tail of vault-accounting reports.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function};

pub struct RoundingDetector;

impl Detector for RoundingDetector {
    fn id(&self) -> &'static str {
        "rounding-direction"
    }
    fn category(&self) -> Category {
        Category::RoundingDirection
    }
    fn description(&self) -> &'static str {
        "Share/asset conversion (mint/deposit/withdraw) divides with no explicit rounding mode"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
                continue;
            }
            // Only the conversion entry points: mint/deposit/issue (assets→shares)
            // and withdraw/redeem/burn (shares→assets). Other arithmetic is out of
            // scope and a major false-positive source.
            if !is_conversion_name(&f.name) {
                continue;
            }
            // The function must actually perform an `a * b / c` mul-then-div
            // (or a mulDiv helper) — the shape of a proportional conversion.
            let Some(span) = find_mul_div(f) else {
                continue;
            };
            // Suppress when the code pins a rounding direction or otherwise shows
            // it handles rounding deliberately (OZ Math.mulDiv with Rounding, an
            // explicit ceil/floor helper, or the `+ denominator - 1` ceil idiom).
            if uses_explicit_rounding(cx, f) {
                continue;
            }

            let b = FindingBuilder::new(self.id(), Category::RoundingDirection)
                .title("Share/asset conversion with unspecified rounding direction")
                .severity(Severity::Low)
                .confidence(0.4)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` converts between assets and shares with an integer `a * b / c` division but \
                     pins no explicit rounding mode. Solidity division truncates toward zero, so the \
                     conversion may round in the user's favor (e.g. minting too many shares or paying \
                     out too many assets) instead of the protocol's — draining the vault a few wei per \
                     call. ERC-4626 requires rounding to favor the vault.",
                    f.name
                ))
                .recommendation(
                    "Pin the rounding direction explicitly: round down on deposit/mint share issuance and \
                     round up on withdraw/redeem asset payout — e.g. OpenZeppelin `Math.mulDiv(a, b, c, \
                     Rounding.Floor/Ceil)` or a `mulDivUp`/`mulDivDown` helper.",
                );
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

/// A conversion entry point: assets→shares (`mint`/`deposit`/`issue`) or
/// shares→assets (`withdraw`/`redeem`/`burn`).
fn is_conversion_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    ["mint", "deposit", "issue", "withdraw", "redeem", "burn"]
        .iter()
        .any(|k| l.contains(k))
}

/// Detect a proportional conversion: an `a * b / c` (a `Mul` whose operand is a
/// `Div`, in either order) or a `mulDiv`-family call. Returns the span of the
/// offending expression. This is the inverse of the vault detector's
/// divide-before-multiply check (which looks for `(a / b) * c`); here we want
/// multiply-then-divide, the canonical share/asset formula.
fn find_mul_div(f: &Function) -> Option<sluice_ir::Span> {
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            match &e.kind {
                // `a * b / c` parses as `Div(Mul(a, b), c)`, and `c * (a / b)`
                // (or `(a / b) * c`) parses as a `Mul` with a `Div` operand. Both
                // are integer-division conversions; flag either shape.
                ExprKind::Binary { op: BinOp::Div, lhs, .. } => {
                    if contains_mul(lhs) {
                        found = Some(e.span);
                    }
                }
                ExprKind::Binary { op: BinOp::Mul, lhs, rhs } => {
                    if is_div(lhs) || is_div(rhs) {
                        found = Some(e.span);
                    }
                }
                // `mulDiv(a, b, c)` / `Math.mulDiv(...)` helper call.
                ExprKind::Call(c) => {
                    if c
                        .func_name
                        .as_deref()
                        .map(|n| n.eq_ignore_ascii_case("muldiv"))
                        .unwrap_or(false)
                    {
                        found = Some(e.span);
                    }
                }
                _ => {}
            }
        });
    }
    found
}

fn is_div(e: &Expr) -> bool {
    matches!(e.kind, ExprKind::Binary { op: BinOp::Div, .. })
}

/// True if `e` is a `Mul`, or transitively contains one (e.g. `(a * b) + d`).
fn contains_mul(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |n| {
        if let ExprKind::Binary { op: BinOp::Mul, .. } = &n.kind {
            found = true;
        }
    });
    found
}

/// Suppress when the function clearly controls its rounding direction. Conducted
/// textually over the function source because the rounding mode is usually an
/// enum argument or a named helper rather than a distinct IR shape:
///   - `Rounding.Up` / `Rounding.Ceil` / `Rounding.Down` / `Rounding.Floor`,
///   - `mulDivUp` / `mulDivDown` / `ceilDiv` / `floorDiv` helpers,
///   - the `+ denominator - 1` (or `+ ... - 1`) ceil-division idiom.
fn uses_explicit_rounding(cx: &AnalysisContext, f: &Function) -> bool {
    let src = cx.source_text(f.span);
    if src.contains("rounding.up")
        || src.contains("rounding.ceil")
        || src.contains("rounding.down")
        || src.contains("rounding.floor")
        || src.contains("muldivup")
        || src.contains("muldivdown")
        || src.contains("muldivceil")
        || src.contains("ceildiv")
        || src.contains("floordiv")
        || src.contains("rounddown")
        || src.contains("roundup")
    {
        return true;
    }
    // `+ <denominator> - 1` ceil idiom: a `- 1` sub-expression added into the
    // numerator. Approximate textually (no whitespace normalization needed for
    // the common `- 1` / `-1` spellings) so we catch hand-rolled ceilDiv.
    has_ceil_idiom(f)
}

/// Detect the `(a * b + c - 1) / c` ceil-division idiom structurally: a `Div`
/// whose numerator subtracts `1`. This is the canonical hand-rolled
/// round-up, so its presence means rounding was considered.
fn has_ceil_idiom(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Binary { op: BinOp::Div, lhs, .. } = &e.kind {
                lhs.visit(&mut |n| {
                    if let ExprKind::Binary { op: BinOp::Sub, rhs, .. } = &n.kind {
                        if is_one(rhs) {
                            found = true;
                        }
                    }
                });
            }
        });
    }
    found
}

fn is_one(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Lit(sluice_ir::Lit::Number(n)) if n.trim() == "1")
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // A mint that issues shares with a bare `a * b / c` and no rounding mode:
    // truncation silently favors the depositor.
    const VULN: &str = r#"
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            mapping(address => uint256) public shares;
            function deposit(uint256 assets) external returns (uint256 shrs) {
                shrs = assets * totalSupply / totalAssets;
                shares[msg.sender] += shrs;
                totalSupply += shrs;
                totalAssets += assets;
            }
        }
    "#;

    // The same conversion but rounding is pinned with the `+ denominator - 1`
    // ceil idiom, so the protocol is protected — no finding.
    const SAFE: &str = r#"
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            mapping(address => uint256) public shares;
            function deposit(uint256 assets) external returns (uint256 shrs) {
                shrs = (assets * totalSupply + totalAssets - 1) / totalAssets;
                shares[msg.sender] += shrs;
                totalSupply += shrs;
                totalAssets += assets;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "rounding-direction"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "rounding-direction"));
    }
}
