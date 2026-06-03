//! Missing zero-address check on a critical-address setter.
//!
//! A setter for privileged/critical address state (`owner`, `oracle`,
//! `implementation`, `treasury`, ...) that assigns a user-supplied `address`
//! parameter without first rejecting `address(0)` risks permanently bricking the
//! contract: a fat-fingered or malicious zero address can lock administration,
//! redirect funds to the zero account, or point a proxy at nothing. This is the
//! classic low-severity "missing zero-address validation" finding.
//!
//! Precision is the priority here (this class is common and easily over-reported):
//! we only fire when (a) the function is externally reachable and state-mutating,
//! (b) it writes a state variable whose name is a recognized critical/privileged
//! address role, (c) the assigned value is a *direct address parameter* of that
//! same function (never a computed or contract-derived address), and (d) the
//! function source contains no zero-address guard for that parameter.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{AssignOp, Expr, ExprKind, Function};

pub struct MissingZeroCheckDetector;

impl Detector for MissingZeroCheckDetector {
    fn id(&self) -> &'static str {
        "missing-zero-check"
    }
    fn category(&self) -> Category {
        Category::MissingZeroCheck
    }
    fn description(&self) -> &'static str {
        "Critical-address setter assigns a parameter with no zero-address check"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.entry_points() {
            // Address-typed parameters that carry a name (the only values that
            // can be a "user-supplied address" assigned straight into state).
            let addr_params: Vec<&str> = f
                .params
                .iter()
                .filter(|p| ty_is_address(&p.ty))
                .filter_map(|p| p.name.as_deref())
                .collect();
            if addr_params.is_empty() {
                continue;
            }

            // The function's source text, lowercased once, for zero-check suppression.
            let src = cx.source_text(f.span);

            // Walk the body for `<critical_state_var> = <address_param>` assignments.
            // We require the target to be a critical/privileged *state* variable
            // (cross-checked against the function's storage writes so we never trip
            // on a local-variable assignment) and the RHS to be a bare parameter.
            let mut reported_here = false;
            for s in &f.body {
                if reported_here {
                    break;
                }
                s.visit_exprs(&mut |e: &Expr| {
                    if reported_here {
                        return;
                    }
                    let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind else {
                        return;
                    };
                    // Target: leaf name of the lvalue (`owner`, or `cfg.owner`).
                    let Some(var) = target.simple_name() else {
                        return;
                    };
                    if !is_critical_address_name(var) {
                        return;
                    }
                    // Must be a genuine state write (not a local shadow), and not a
                    // per-key mapping write (ordinary bookkeeping, addressed elsewhere).
                    if !f.effects.writes_var(var) || is_mapping_var(cx, f, var) {
                        return;
                    }
                    // RHS must be a *direct* address parameter. Anything computed
                    // (`address(new X())`, `factory.get()`, `address(uint160(...))`)
                    // is intentionally not a finding — that is the FP-suppression the
                    // task calls out.
                    let Some(rhs) = value.simple_name() else {
                        return;
                    };
                    if !addr_params.contains(&rhs) {
                        return;
                    }
                    // Suppress if the source guards this very parameter against zero.
                    if has_zero_check_for(&src, rhs) {
                        return;
                    }

                    let b = FindingBuilder::new(self.id(), Category::MissingZeroCheck)
                        .title("Critical-address setter lacks a zero-address check")
                        .severity(Severity::Low)
                        .confidence(0.5)
                        .dimension(Dimension::Invariant)
                        .message(format!(
                            "`{}` assigns the user-supplied address `{}` to critical state `{}` \
                             without checking it against `address(0)`. Passing the zero address \
                             permanently loses control of (or bricks) this role — e.g. an \
                             unrecoverable owner, a misrouted treasury, or a proxy pointed at nothing.",
                            f.name, rhs, var
                        ))
                        .recommendation(format!(
                            "Validate the input first, e.g. `require({rhs} != address(0), \"zero address\");`."
                        ));
                    out.push(cx.finish(b, f.id, e.span));
                    reported_here = true;
                });
            }
        }
        out
    }
}

/// True if a declared parameter type is (or wraps) `address` / `address payable`.
/// We match on the leading token so `IERC20`/`contract`-typed params are excluded
/// (those are not the "raw user address into admin state" shape we target).
fn ty_is_address(ty: &str) -> bool {
    let t = ty.trim().to_ascii_lowercase();
    t == "address" || t.starts_with("address ") || t.starts_with("address payable") || t == "address payable"
}

/// Critical/privileged address roles whose accidental zeroing bricks the system.
/// Deliberately the curated set the task specifies — narrow, to keep this common
/// low-severity class precise.
fn is_critical_address_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "owner",
        "admin",
        "oracle",
        "implementation",
        "treasury",
        "router",
        "feerecipient",
        "token",
        "vault",
        "beneficiary",
        "governance",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// Is `var` a `mapping(...)` state variable on the function's contract? Mapping
/// writes are per-entity bookkeeping, not a single critical-role setter.
fn is_mapping_var(cx: &AnalysisContext, f: &Function, var: &str) -> bool {
    cx.contract_of(f.id)
        .and_then(|c| c.state_vars.iter().find(|v| v.name == var))
        .map(|v| v.is_mapping())
        .unwrap_or(false)
}

/// Does the (lowercased) function source contain a zero-address / zero guard that
/// references `param`? We scan line-by-line so the comparison must co-occur with
/// the parameter name, i.e. an actual `require(param != address(0))` /
/// `if (param == address(0)) revert` rather than an unrelated zero check.
fn has_zero_check_for(src_lower: &str, param: &str) -> bool {
    let p = param.to_ascii_lowercase();
    for line in src_lower.lines() {
        if !line.contains(&p) {
            continue;
        }
        let zero_cmp = line.contains("address(0)")
            || line.contains("!= 0")
            || line.contains("== 0")
            || line.contains("> 0");
        // A bare assignment line also mentions the param; only treat lines that
        // additionally express a comparison (require/if/revert context) as guards.
        let comparison_ctx = line.contains("require")
            || line.contains("revert")
            || line.contains("if ")
            || line.contains("if(")
            || line.contains("assert")
            || line.contains("!=")
            || line.contains("==");
        if zero_cmp && comparison_ctx {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    const VULN: &str = r#"
        contract Vault {
            address public owner;
            constructor() { owner = msg.sender; }
            function setOwner(address newOwner) external {
                owner = newOwner;
            }
        }
    "#;

    const SAFE: &str = r#"
        contract Vault {
            address public owner;
            constructor() { owner = msg.sender; }
            function setOwner(address newOwner) external {
                require(newOwner != address(0), "zero");
                owner = newOwner;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "missing-zero-check"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "missing-zero-check"));
    }
}
