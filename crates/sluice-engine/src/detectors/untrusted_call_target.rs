//! Untrusted external call target — caller-supplied callee drives a state credit.
//!
//! A function lets the caller pass an address (or interface handle) and then
//! makes an **external call on that caller-supplied target**, trusting its
//! return / side-effect, and on the strength of that call **credits the caller**
//! a balance in this contract. If the target is neither validated (no
//! whitelist / equality check) nor fixed (immutable / constant), an attacker
//! supplies a contract they control whose method is a no-op, yet still walks
//! away with a real, unbacked balance credit they can later withdraw.
//!
//! This is the shape behind the **TempleDAO STAX exploit** (Oct 2022, ~$2.3M):
//! `migrateStake(address oldStaking, uint256 amount)` called
//! `IOldStaking(oldStaking).migrateWithdraw(msg.sender, amount)` against a
//! fully caller-supplied `oldStaking` and then did `balanceOf[msg.sender] +=
//! amount` — a forged `oldStaking` whose `migrateWithdraw` did nothing still
//! produced a genuine staked-balance credit, which the attacker drained.
//!
//! Precision anchors (all required, so this stays quiet on ordinary
//! pass-an-interface code such as `swap(IRouter r, ...)`):
//!   * the function is externally reachable, state-mutating, and **not** access
//!     controlled (an `onlyOwner` operator choosing the target is intentional);
//!   * the external/low-level call's **receiver** root-resolves to an
//!     unvalidated function **parameter** (no `require`/`if`/whitelist-index
//!     touches it before the call);
//!   * the function then **credits an accounting balance keyed by
//!     `msg.sender`** (`balanceOf[msg.sender] += …`) *after* an external call.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{CallKind, Expr, ExprKind, Function};

use super::is_accounting_name;

pub struct UntrustedCallTargetDetector;

impl Detector for UntrustedCallTargetDetector {
    fn id(&self) -> &'static str {
        "untrusted-call-target"
    }
    fn category(&self) -> Category {
        Category::UntrustedCallTarget
    }
    fn description(&self) -> &'static str {
        "Caller-supplied, unvalidated external call target whose result drives a balance credit (TempleDAO-class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.entry_points() {
            // An access-controlled operator choosing the target is intentional
            // (a privileged migration / sweep), not attacker-driven.
            if cx.has_access_control(f) {
                continue;
            }

            // There must be an external transfer of control, and — the precision
            // anchor — a balance keyed by the caller must be credited after it.
            if !f.effects.has_write_after_external_call() {
                continue;
            }
            let credits_sender = f.effects.storage_writes.iter().any(|w| {
                w.path.contains("msg.sender") && is_accounting_name(&w.var)
            });
            if !credits_sender {
                continue;
            }

            // Find an external/low-level/delegate call whose receiver root is an
            // unvalidated parameter of this function.
            let Some(span) = first_untrusted_param_call(f) else { continue };

            let b = FindingBuilder::new(self.id(), Category::UntrustedCallTarget)
                .title("Untrusted caller-supplied call target drives a balance credit")
                .severity(Severity::High)
                .confidence(0.6)
                .dimension(Dimension::Frontier)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` makes an external call on a caller-supplied address parameter that is never \
                     validated (no whitelist / equality check) and is not an immutable/constant address, \
                     then credits an accounting balance keyed by `msg.sender`. An attacker can pass a \
                     contract they control whose method is a no-op, yet still receive a real, unbacked \
                     balance credit and later withdraw genuine funds — the untrusted-call-target / \
                     unvalidated-external-contract class (e.g. the TempleDAO STAX migrateStake drain).",
                    f.name
                ))
                .recommendation(
                    "Validate the caller-supplied target against an owner-curated allowlist of trusted \
                     contracts (`require(isTrusted[target])`), or derive the source contract from \
                     immutable/governance-set state rather than a call parameter. Never credit a balance \
                     on the strength of a call to an address the caller chose.",
                );
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

/// The span of the first external/low-level/delegate call whose receiver
/// root-resolves to an unvalidated parameter of `f`, if any.
fn first_untrusted_param_call(f: &Function) -> Option<sluice_ir::Span> {
    let mut hit: Option<sluice_ir::Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Call(call) = &e.kind else { return };
            // Only calls that hand control to an external party.
            if !matches!(
                call.kind,
                CallKind::External | CallKind::LowLevelCall | CallKind::DelegateCall
            ) {
                return;
            }
            let Some(recv) = &call.receiver else { return };
            let Some(root) = root_ident(unwrap_casts(recv)) else { return };
            // The receiver root must be a parameter of this function, and that
            // parameter must not be validated anywhere in the body.
            if !is_param(f, &root) {
                return;
            }
            if param_is_validated(f, &root) {
                return;
            }
            hit = Some(e.span);
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Peel single-argument type casts (`IOldStaking(x)`, `address(x)`, `payable(x)`).
fn unwrap_casts(e: &Expr) -> &Expr {
    let mut cur = e;
    loop {
        match &cur.kind {
            ExprKind::Call(c) if c.kind == CallKind::TypeCast && c.args.len() == 1 => {
                cur = &c.args[0];
            }
            _ => return cur,
        }
    }
}

/// Root identifier of an lvalue/member/index chain (`a.b[c]` -> `a`).
fn root_ident(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root_ident(base),
        _ => None,
    }
}

/// Is `name` a parameter of `f`?
fn is_param(f: &Function, name: &str) -> bool {
    f.params.iter().any(|p| p.name.as_deref() == Some(name))
}

/// Best-effort: does the parameter `name` get validated somewhere in the body —
/// referenced inside a `require`/`assert`/`revert`, an `if`/`while` condition, or
/// used as a mapping index (a whitelist lookup `trusted[name]`)? Any of these
/// means the caller-supplied target is checked, so it is not a free target. We
/// err toward suppression (treat ambiguous references as validation).
fn param_is_validated(f: &Function, name: &str) -> bool {
    let mut validated = false;
    for s in &f.body {
        s.visit(&mut |st| {
            if validated {
                return;
            }
            match &st.kind {
                sluice_ir::StmtKind::If { cond, .. }
                | sluice_ir::StmtKind::While { cond, .. }
                | sluice_ir::StmtKind::DoWhile { cond, .. } => {
                    if expr_mentions_ident(cond, name) {
                        validated = true;
                    }
                }
                sluice_ir::StmtKind::Revert { args, .. } => {
                    if args.iter().any(|a| expr_mentions_ident(a, name)) {
                        validated = true;
                    }
                }
                sluice_ir::StmtKind::Expr(e) | sluice_ir::StmtKind::Emit(e) => {
                    if expr_validates_ident(e, name) {
                        validated = true;
                    }
                }
                sluice_ir::StmtKind::VarDecl { init: Some(e), .. } => {
                    // `bool ok = trusted[name];` style whitelist read.
                    if expr_indexes_ident(e, name) {
                        validated = true;
                    }
                }
                _ => {}
            }
        });
        if validated {
            break;
        }
    }
    validated
}

/// `require(...)` / `assert(...)` whose args mention `name`, or any `base[name]`
/// mapping index anywhere in the expression (whitelist lookup).
fn expr_validates_ident(e: &Expr, name: &str) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Call(c) = &sub.kind {
            if matches!(
                c.kind,
                CallKind::Builtin(sluice_ir::Builtin::Require) | CallKind::Builtin(sluice_ir::Builtin::Assert)
            ) && c.args.iter().any(|a| expr_mentions_ident(a, name))
            {
                found = true;
            }
        }
        if let ExprKind::Index { index: Some(idx), .. } = &sub.kind {
            if matches!(&idx.kind, ExprKind::Ident(n) if n == name) {
                found = true;
            }
        }
    });
    found
}

/// Any `base[name]` index where `name` is the bare index (a whitelist lookup).
fn expr_indexes_ident(e: &Expr, name: &str) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if let ExprKind::Index { index: Some(idx), .. } = &sub.kind {
            if matches!(&idx.kind, ExprKind::Ident(n) if n == name) {
                found = true;
            }
        }
    });
    found
}

/// Does `name` appear as an identifier anywhere in `e`?
fn expr_mentions_ident(e: &Expr, name: &str) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if let ExprKind::Ident(n) = &sub.kind {
            if n == name {
                found = true;
            }
        }
    });
    found
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // TempleDAO shape: caller-supplied `oldStaking` is called and the caller is
    // then credited a real balance. No validation, no access control.
    const VULN: &str = r#"
        interface IOldStaking { function migrateWithdraw(address staker, uint256 amount) external; }
        contract Stax {
            mapping(address => uint256) public balanceOf;
            function migrateStake(address oldStaking, uint256 amount) external {
                IOldStaking(oldStaking).migrateWithdraw(msg.sender, amount);
                balanceOf[msg.sender] += amount;
            }
        }
    "#;

    // Validated: the caller-supplied source is checked against an owner allowlist.
    const SAFE_WHITELIST: &str = r#"
        interface IOldStaking { function migrateWithdraw(address staker, uint256 amount) external; }
        contract Stax {
            mapping(address => uint256) public balanceOf;
            mapping(address => bool) public trusted;
            function migrateStake(address oldStaking, uint256 amount) external {
                require(trusted[oldStaking], "untrusted");
                IOldStaking(oldStaking).migrateWithdraw(msg.sender, amount);
                balanceOf[msg.sender] += amount;
            }
        }
    "#;

    // Ordinary "pass an interface" code: there is no msg.sender balance credit,
    // so this must stay silent (the precision anchor doing its job).
    const SAFE_NO_CREDIT: &str = r#"
        interface IRouter { function swap(uint256 a) external returns (uint256); }
        contract Trade {
            uint256 public last;
            function doSwap(IRouter r, uint256 a) external {
                last = r.swap(a);
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "untrusted-call-target"), "{:#?}", fs);
    }

    #[test]
    fn silent_when_target_whitelisted() {
        let fs = run(SAFE_WHITELIST);
        assert!(!fs.iter().any(|f| f.detector == "untrusted-call-target"));
    }

    #[test]
    fn silent_without_sender_credit() {
        let fs = run(SAFE_NO_CREDIT);
        assert!(!fs.iter().any(|f| f.detector == "untrusted-call-target"));
    }
}
