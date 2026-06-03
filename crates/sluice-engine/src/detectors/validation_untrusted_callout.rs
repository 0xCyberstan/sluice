//! ERC-4337 validation-phase untrusted callout (R26-3, ERC-7562 OP-041/OP-061).
//!
//! ERC-7562 confines what a UserOperation's *validation* may touch: an account or
//! paymaster may call the `EntryPoint` (the OP-051..055 carve-outs) and use the
//! signature precompiles, but it must **not** transfer control to an arbitrary
//! external address during validation (OP-041 forbids calling an address with no
//! code yet; OP-061 forbids `CALL` with value). A generic
//! `target.call(...)` / `someContract.method(...)` / `delegatecall` during
//! validation is therefore disallowed:
//!
//!   * it is **un-simulatable** — the bundler cannot predict the callee's behavior,
//!     so the op is mempool-rejected or, if it slips through, invalidates the bundle;
//!   * worse, when the call target is **caller-supplied** (an EIP-1271
//!     `isValidSignature` to a signer named in the `userOp`, an oracle address from
//!     calldata), validation hands control to attacker code — which can grief other
//!     ops in the bundle or probe banned state.
//!
//! The detector fires when [`is_aa_validation_fn`] (or a function transitively
//! reachable from one) makes the first external/low-level/delegate/static/send/
//! transfer call whose target does **not** root-resolve to the EntryPoint handle and
//! is not a precompile. It **escalates** confidence when the target root-resolves to
//! a function parameter (attacker-chosen callee).
//!
//! ## Precision (false-positive suppression)
//!   * **EntryPoint calls** — a call whose receiver root mentions `entryPoint` /
//!     `_entryPoint` (the OP-051..055 carve-out) is suppressed.
//!   * **Precompiles / builtins** — `ecrecover` and the hash builtins are
//!     `CallKind::Builtin` (not transfers of control) and never match; a
//!     `staticcall` to a small precompile address literal (`0x1`..`0x9`) is skipped.
//!   * **Self / internal calls** — `address(this).…` and internal helpers are not
//!     external transfers of control.
//!   * **Staked entities** — a staked account/paymaster has relaxed call rules;
//!     suppressed.
//!
//! Distinct from `preauth-callout-target` (which needs an `isValidSignature` +
//! inverted-order guard) and `untrusted-call-target` (no validation-phase awareness):
//! here the signal is *any* control transfer during ERC-4337 validation.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use super::prelude::*;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Call, CallKind, Expr, ExprKind, Function, Lit, Span};

pub struct ValidationUntrustedCalloutDetector;

impl Detector for ValidationUntrustedCalloutDetector {
    fn id(&self) -> &'static str {
        "validation-untrusted-callout"
    }
    fn category(&self) -> Category {
        Category::ValidationUntrustedCallout
    }
    fn description(&self) -> &'static str {
        "ERC-4337 validateUserOp/validatePaymasterUserOp makes an external call to a non-EntryPoint target during validation (ERC-7562 OP-041/OP-061)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            if !reachable_from_aa_validation(cx, f) {
                continue;
            }
            // Staked entities have relaxed callout rules.
            if is_staked_entity(cx, f) {
                continue;
            }

            // The first external transfer-of-control to a non-EntryPoint,
            // non-precompile target.
            let mut hit: Option<(Span, bool)> = None;
            for s in &f.body {
                s.visit_exprs(&mut |e| {
                    if hit.is_some() {
                        return;
                    }
                    let ExprKind::Call(c) = &e.kind else { return };
                    if !c.kind.is_external_transfer_of_control() {
                        return;
                    }
                    if call_target_is_entrypoint(cx, f, c)
                        || call_target_is_precompile(c)
                        || call_target_is_self(c)
                        || call_target_is_msg_sender(c)
                    {
                        return;
                    }
                    // Attacker-chosen callee (target root-resolves to a parameter)?
                    let attacker_target = call_target_root_is_param(f, c);
                    hit = Some((e.span, attacker_target));
                });
                if hit.is_some() {
                    break;
                }
            }
            let Some((span, attacker_target)) = hit else { continue };

            out.push(build(self, cx, f, span, attacker_target));
        }
        out
    }
}

// ------------------------------------------------------------- target analysis

/// The call's receiver/target (best-effort): the explicit receiver, else the root
/// of the callee chain (`target.call` -> `target`).
fn call_target_expr(c: &Call) -> Option<&Expr> {
    c.receiver.as_deref().or(Some(&c.callee))
}

/// Does the call target root-resolve to the EntryPoint handle? The OP-051..055
/// carve-out. Recognized by either:
///   * the receiver root *name* mentioning `entryPoint` / `_entryPoint` (incl.
///     `address(entryPoint())` and `entryPoint().foo()`), or
///   * the receiver root resolving to a **state variable typed `IEntryPoint` /
///     `EntryPoint`** — the reference holds it as `IEntryPoint _entryPoint`, but a
///     contract may name the handle anything (e.g. `ep`), so the declared type is
///     the robust signal.
fn call_target_is_entrypoint(cx: &AnalysisContext, f: &Function, c: &Call) -> bool {
    let Some(t) = call_target_expr(c) else { return false };

    // (a) the receiver name mentions entryPoint anywhere.
    let mut mentions = false;
    t.visit(&mut |sub| {
        if let ExprKind::Ident(n) = &sub.kind {
            if n.to_ascii_lowercase().contains("entrypoint") {
                mentions = true;
            }
        }
        if let ExprKind::Member { member, .. } = &sub.kind {
            if member.to_ascii_lowercase().contains("entrypoint") {
                mentions = true;
            }
        }
    });
    if mentions {
        return true;
    }

    // (b) the receiver root is a state variable whose declared type is the EntryPoint.
    if let Some(root) = root_ident_peeled(t) {
        if let Some(contract) = cx.contract_of(f.id) {
            if contract.state_vars.iter().any(|v| {
                v.name == root && {
                    let ty = v.ty.to_ascii_lowercase();
                    ty.contains("ientrypoint") || ty.contains("entrypoint")
                }
            }) {
                return true;
            }
        }
    }
    false
}

/// Is the call target `msg.sender` / `payable(msg.sender)`? A value send back to the
/// caller (the prefund to the EntryPoint, `_payPrefund`'s
/// `payable(msg.sender).call{value:}("")`) is the sanctioned shape, not an OP-041
/// control transfer to an attacker-chosen contract.
fn call_target_is_msg_sender(c: &Call) -> bool {
    call_target_expr(c).is_some_and(|t| peel_casts(t).mentions_member("msg", "sender"))
}

/// Is the call a `staticcall` to a small precompile address literal (`0x1`..`0x9`)?
/// (The signature/hash precompiles are reached this way when not via a builtin.)
fn call_target_is_precompile(c: &Call) -> bool {
    if c.kind != CallKind::StaticCall {
        return false;
    }
    let Some(t) = call_target_expr(c) else { return false };
    let inner = peel_casts(t);
    matches!(&inner.kind, ExprKind::Lit(Lit::Number(n)) if small_precompile(n))
        || matches!(&inner.kind, ExprKind::Lit(Lit::HexNumber(h)) if small_precompile_hex(h))
}

fn small_precompile(n: &str) -> bool {
    matches!(n.trim().parse::<u32>(), Ok(1..=9))
}
fn small_precompile_hex(h: &str) -> bool {
    let s = h.trim().trim_start_matches("0x").trim_start_matches("0X");
    matches!(u32::from_str_radix(s, 16), Ok(1..=9))
}

/// Is the call to `this` / `address(this)` (a self-call, not an external frontier)?
fn call_target_is_self(c: &Call) -> bool {
    let Some(t) = call_target_expr(c) else { return false };
    matches!(&peel_casts(t).kind, ExprKind::Ident(n) if n == "this")
}

/// Does the call target root-resolve to a function parameter (attacker-chosen)?
fn call_target_root_is_param(f: &Function, c: &Call) -> bool {
    call_target_expr(c).is_some_and(|t| root_is_param(f, t))
}

/// Staked-entity marker (shared with the env-opcode detector's rationale): a staked
/// account/paymaster has relaxed validation-scope rules.
fn is_staked_entity(cx: &AnalysisContext, f: &Function) -> bool {
    if f.effects
        .internal_calls
        .iter()
        .chain(f.effects.call_sites.iter().filter_map(|c| c.func_name.as_ref()))
        .any(|n| n.to_ascii_lowercase().contains("stake"))
    {
        return true;
    }
    cx.contract_of(f.id).is_some_and(|c| {
        c.inherits_like("stakeable")
            || c.inherits_like("stakemanager")
            || c.state_vars.iter().any(|v| v.name.to_ascii_lowercase().contains("stake"))
    })
}

// ------------------------------------------------------------------- reporting

fn build(
    det: &ValidationUntrustedCalloutDetector,
    cx: &AnalysisContext,
    f: &Function,
    span: Span,
    attacker_target: bool,
) -> Finding {
    let confidence = if attacker_target { 0.7 } else { 0.6 };
    let target_clause = if attacker_target {
        " The call target root-resolves to a function parameter, so the callee is attacker-chosen — \
          validation hands control to attacker code (the EIP-1271 `isValidSignature`-to-a-supplied-signer \
          shape), which can grief other ops in the bundle."
    } else {
        " A non-EntryPoint callee makes validation un-simulatable, so the bundler rejects the op or \
          the bundle reverts on inclusion."
    };
    let b = FindingBuilder::new(det.id(), Category::ValidationUntrustedCallout)
        .title("ERC-4337 validation makes an external call to a non-EntryPoint target (ERC-7562 OP-041/OP-061)")
        .severity(Severity::High)
        .confidence(confidence)
        .dimension(Dimension::Frontier)
        .dimension(Dimension::ValueFlow)
        .message(format!(
            "`{}` runs inside the ERC-4337 validation phase yet makes an external/low-level/delegate call \
             to a target that is not the EntryPoint and not a precompile. ERC-7562 (OP-041/OP-061, with \
             the OP-051..055 EntryPoint carve-out) bars control transfer to arbitrary addresses during \
             validation.{} Restrict validation-phase calls to the EntryPoint and the signature precompiles.",
            f.name, target_clause
        ))
        .recommendation(
            "Do not call arbitrary external contracts during validation. Verify signatures with \
             `ecrecover` / the EIP-1271 precompile path against a *trusted, stored* signer (never a \
             caller-supplied address), confine any other interaction to the EntryPoint, and defer \
             external interactions to the execution phase.",
        );
    cx.finish(b, f.id, span)
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.detector == "validation-untrusted-callout")
    }

    // VULN — validateUserOp calls a caller-supplied signer's isValidSignature
    // during validation (attacker-chosen callee, control transfer).
    const VULN_PARAM_CALLOUT: &str = r#"
        pragma solidity ^0.8.20;
        struct PackedUserOperation { uint256 nonce; bytes signature; address signer; }
        interface IERC1271 { function isValidSignature(bytes32 h, bytes calldata s) external view returns (bytes4); }
        contract VulnAccount {
            function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
                external returns (uint256 validationData) {
                IERC1271 signer = IERC1271(userOp.signer);            // attacker-chosen
                bytes4 ok = signer.isValidSignature(userOpHash, userOp.signature);
                return ok == 0x1626ba7e ? 0 : 1;
            }
        }
    "#;

    // VULN — a generic external oracle call during validation (not the EntryPoint).
    const VULN_ORACLE: &str = r#"
        pragma solidity ^0.8.20;
        struct PackedUserOperation { uint256 nonce; bytes signature; }
        interface IOracle { function price() external view returns (uint256); }
        contract Pm {
            IOracle public oracle;
            function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
                external returns (bytes memory context, uint256 validationData) {
                uint256 p = oracle.price();                            // external, non-EntryPoint
                return ("", p > 0 ? 0 : 1);
            }
        }
    "#;

    // SAFE — validateUserOp only calls the EntryPoint (the OP-051..055 carve-out)
    // and uses ecrecover (a builtin, not a control transfer).
    const SAFE: &str = r#"
        pragma solidity ^0.8.20;
        struct PackedUserOperation { uint256 nonce; bytes signature; }
        interface IEntryPoint { function getNonce(address a, uint192 k) external view returns (uint256); }
        contract Account {
            IEntryPoint public entryPoint;
            address public owner;
            function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
                external returns (uint256 validationData) {
                require(msg.sender == address(entryPoint));
                uint256 n = entryPoint.getNonce(address(this), 0);     // EntryPoint call — allowed
                address rec = ecrecover(userOpHash, 27, bytes32(0), bytes32(0));  // builtin, not a callout
                return (rec == owner && n >= 0) ? 0 : 1;
            }
        }
    "#;

    #[test]
    fn fires_on_caller_supplied_callout() {
        let fs = run(VULN_PARAM_CALLOUT);
        assert!(fires(&fs), "{:?}", fs);
    }

    #[test]
    fn fires_on_oracle_callout() {
        let fs = run(VULN_ORACLE);
        assert!(fires(&fs), "{:?}", fs);
    }

    #[test]
    fn silent_on_entrypoint_only() {
        let fs = run(SAFE);
        assert!(!fires(&fs), "{:?}", fs);
    }
}
