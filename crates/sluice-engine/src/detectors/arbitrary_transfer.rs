//! Arbitrary `transferFrom` source — allowance theft / arbitrary-send-erc20.
//!
//! `IERC20.transferFrom(from, to, amount)` moves `amount` tokens out of `from`,
//! and succeeds for any `from` that has granted the contract an allowance. If a
//! function lets the *caller choose `from`* — i.e. `from` is an attacker-supplied
//! address parameter rather than `msg.sender` / `address(this)` / a stored
//! trusted address — then anyone can drain any address that ever approved the
//! contract. This is the "arbitrary-send-erc20" / allowance-theft class behind
//! multiple real incidents (e.g. the Multichain/AnySwap and Dexible drains): a
//! router that forwards `transferFrom(userSuppliedFrom, ...)` is a honeypot for
//! every wallet with a lingering approval.
//!
//! The safe forms pin `from` to the caller (`transferFrom(msg.sender, ...)`) or
//! to the contract's own balance (`transferFrom(address(this), ...)`), or gate
//! the function behind access control. Those are suppressed; only a free,
//! user-controlled `from` is reported. Precision is the priority.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{CallKind, Expr, ExprKind, Function};

pub struct ArbitraryTransferDetector;

impl Detector for ArbitraryTransferDetector {
    fn id(&self) -> &'static str {
        "arbitrary-transfer"
    }
    fn category(&self) -> Category {
        Category::ArbitraryTransfer
    }
    fn description(&self) -> &'static str {
        "Attacker-controlled `from` in transferFrom (allowance theft / arbitrary-send-erc20)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.entry_points() {
            // Access control means a privileged operator chooses `from`; a
            // sweeper/rescue guarded by `onlyOwner` is intentional, not theft.
            if cx.has_access_control(f) {
                continue;
            }

            // Quick gate via the precomputed effect summary: the function must
            // contain a transferFrom-style call site at all.
            let has_transfer_from = f.effects.call_sites.iter().any(|c| {
                matches!(c.func_name.as_deref(), Some("transferFrom") | Some("safeTransferFrom"))
            });
            if !has_transfer_from {
                continue;
            }

            // Walk the body for the offending call. Report at most one finding per
            // function (the first arbitrary-`from` transferFrom); dedup handles the
            // rest and avoids spamming a multi-pull function.
            let mut hit: Option<sluice_ir::Span> = None;
            for s in &f.body {
                s.visit_exprs(&mut |e| {
                    if hit.is_some() {
                        return;
                    }
                    let ExprKind::Call(call) = &e.kind else { return };
                    if !matches!(
                        call.func_name.as_deref(),
                        Some("transferFrom") | Some("safeTransferFrom")
                    ) {
                        return;
                    }
                    // Only the genuine token-transfer shapes. A bound
                    // `token.safeTransferFrom(from, to, amt)` lowers to
                    // `Internal`; a raw `token.transferFrom(...)` to `External`.
                    // The `SafeERC20.safeTransferFrom(token, from, ...)` library
                    // shape has the *token* as arg0 (a state var / cast, never
                    // attacker-controlled) so it self-suppresses below.
                    if !matches!(call.kind, CallKind::External | CallKind::Internal) {
                        return;
                    }
                    let Some(arg0) = call.args.first() else { return };

                    // Strip casts: `payable(msg.sender)`, `address(x)` →inspect `x`.
                    let from = unwrap_casts(arg0);

                    // Safe pins: the caller, the contract itself, or a constant.
                    if is_msg_sender_or_origin(from) || is_address_this(from) {
                        return;
                    }
                    // A stored trusted address (`owner`, a configured `vault`,
                    // ...) is contract-controlled, not attacker-controlled.
                    if root_is_state_var(cx, f, from) {
                        return;
                    }
                    // Core gate: the `from` value must be attacker-controlled, and
                    // specifically a user-supplied address *parameter* (not just
                    // any tainted expression). We require the stripped `from` to
                    // resolve to a parameter name to keep this precise.
                    if !cx.is_attacker_controlled(f.id, arg0) {
                        return;
                    }
                    if !is_address_param(f, from) {
                        return;
                    }
                    hit = Some(e.span);
                });
                if hit.is_some() {
                    break;
                }
            }

            let Some(span) = hit else { continue };
            let b = FindingBuilder::new(self.id(), Category::ArbitraryTransfer)
                .title("Arbitrary `from` in transferFrom (allowance theft)")
                .severity(Severity::High)
                .confidence(0.6)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` calls `transferFrom` with a caller-supplied `from` address that is neither \
                     `msg.sender` nor `address(this)`, and the function has no access control. Anyone \
                     can pass a victim's address as `from` and pull tokens from every wallet that has \
                     approved this contract — the arbitrary-send-erc20 / allowance-theft class.",
                    f.name
                ))
                .recommendation(
                    "Pin the source to the caller (`transferFrom(msg.sender, ...)`) or to \
                     `address(this)`; never let an external caller choose an arbitrary `from`. If a \
                     privileged sweep is intended, gate it behind an access-control modifier.",
                );
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

/// Peel `address(...)` / `payable(...)` / `IERC20(...)` and other single-argument
/// type casts off an expression so the underlying value can be inspected.
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

/// `msg.sender` or `tx.origin` — the caller. A `from` pinned to either is, by
/// construction, the actor whose allowance is being spent, so it is not theft.
fn is_msg_sender_or_origin(e: &Expr) -> bool {
    e.mentions_member("msg", "sender") || e.mentions_member("tx", "origin")
}

/// Bare `this` or `address(this)` (after cast-stripping it is the `this` ident).
fn is_address_this(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Ident(n) if n == "this")
}

/// True if the expression's root identifier is a state variable of the function's
/// contract (a stored, contract-controlled address — not attacker input).
fn root_is_state_var(cx: &AnalysisContext, f: &Function, e: &Expr) -> bool {
    let Some(root) = root_ident(e) else { return false };
    cx.contract_of(f.id)
        .map(|c| c.state_vars.iter().any(|v| v.name == root))
        .unwrap_or(false)
}

/// True if the expression is a bare identifier naming an `address`-typed
/// parameter of the function — the precise "user-supplied address parameter"
/// shape the detector targets. `transferFrom`'s `from` is always an `address`
/// (`address` / `address payable`), so requiring an address-typed param keeps
/// this tight and rejects unrelated tainted values.
fn is_address_param(f: &Function, e: &Expr) -> bool {
    let ExprKind::Ident(name) = &e.kind else { return false };
    f.params.iter().any(|p| {
        p.name.as_deref() == Some(name.as_str()) && p.ty.to_ascii_lowercase().contains("address")
    })
}

/// Root identifier of an lvalue/member/index chain (`a.b[c]` -> `a`).
fn root_ident(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root_ident(base),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // `from` is a free, caller-supplied address parameter: anyone can drain any
    // wallet that approved this contract. The arbitrary-send-erc20 bug.
    const VULN: &str = r#"
        interface IERC20 { function transferFrom(address f, address t, uint256 a) external returns (bool); }
        contract Router {
            IERC20 public token;
            function pull(address from, address to, uint256 amount) external {
                token.transferFrom(from, to, amount);
            }
        }
    "#;

    // `from` is pinned to `msg.sender`: callers can only move their own tokens.
    const SAFE: &str = r#"
        interface IERC20 { function transferFrom(address f, address t, uint256 a) external returns (bool); }
        contract Router {
            IERC20 public token;
            function pull(address to, uint256 amount) external {
                token.transferFrom(msg.sender, to, amount);
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "arbitrary-transfer"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "arbitrary-transfer"));
    }
}
