//! ERC-4337 missing `EntryPoint` guard (R26-4).
//!
//! Every ERC-4337 validation / post-execution entry point — an account's
//! `validateUserOp`, a paymaster's `validatePaymasterUserOp` and `postOp` — is
//! invoked **only** by the singleton `EntryPoint`. The reference implementation
//! makes the first statement of each `_requireFromEntryPoint()` (the
//! `require(msg.sender == address(entryPoint()))` check). If that guard is absent,
//! the function is `external`/`public`, so **anyone can call it directly**:
//!
//!   * a missing guard on `validateUserOp` lets an attacker invoke it with a forged
//!     `userOp`; the account's `_payPrefund(missingAccountFunds)` then `call{value:
//!     missingAccountFunds}`s the *direct caller* (`payable(msg.sender)`), draining
//!     the account's ETH to the attacker;
//!   * a missing guard on `postOp` lets an attacker forge a post-execution call and
//!     mis-account the paymaster's `EntryPoint` deposit (it is pre-paid from that
//!     deposit and re-runnable on revert).
//!
//! This is the `BaseAccount._requireFromEntryPoint()` invariant. The detector fires
//! on an externally-reachable function that is *EntryPoint-shaped* — recognized as
//! a validation/`postOp` entry by [`is_aa_validation_fn`], or one that reads
//! `missingAccountFunds`/`maxCost`, or one that `payable(msg.sender).call{value:}`s
//! — yet binds `msg.sender` to the EntryPoint nowhere (no inline
//! `msg.sender == address(entryPoint())`, no `_requireFromEntryPoint` internal call,
//! and no `onlyEntryPoint`-style modifier).
//!
//! Severity is **Critical** when the unguarded function can drain — it (or a helper
//! it calls) runs `_payPrefund` / sends ETH to `msg.sender`, or it is a paymaster
//! `postOp` (deposit mis-accounting) — and **High** otherwise.
//!
//! ## Precision (false-positive suppression)
//!   * The internal `_validateSignature` / `_validateNonce` /
//!     `_validatePaymasterUserOp` / `_postOp` overrides are `internal`, so they are
//!     not externally reachable and never fire — the public guard lives in the
//!     `BaseAccount` / `BasePaymaster` parent's entry, exactly as the spec requires.
//!   * The real `BaseAccount` / `BasePaymaster` entries DO call
//!     `_requireFromEntryPoint`, so they are suppressed (no FP on the safe corpus).
//!   * The guard comparand must resolve to the EntryPoint (an `entryPoint`/
//!     `_entryPoint`-named state read or accessor), not to attacker input.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use super::prelude::*;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, CallKind, Expr, ExprKind, Function};

pub struct MissingEntryPointGuardDetector;

impl Detector for MissingEntryPointGuardDetector {
    fn id(&self) -> &'static str {
        "missing-entrypoint-guard"
    }
    fn category(&self) -> Category {
        Category::MissingEntryPointGuard
    }
    fn description(&self) -> &'static str {
        "ERC-4337 validateUserOp/validatePaymasterUserOp/postOp missing the EntryPoint-only guard (_requireFromEntryPoint)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // Only a real, externally-callable body can be invoked directly by an
            // attacker. The internal `_validate*`/`_postOp` overrides are filtered
            // here (their public entry in the base carries the guard).
            if !f.has_body || !f.is_externally_reachable() {
                continue;
            }

            // Is this an EntryPoint-only function? Per §R26-4 the entry is one of:
            //   * a recognized validateUserOp/validatePaymasterUserOp/postOp, or
            //   * a function reading the EntryPoint-supplied `missingAccountFunds` /
            //     `maxCost` prefund word.
            // A bare `payable(msg.sender).call{value:}` is NOT a standalone trigger
            // (an ordinary WETH-style `withdraw` matches it); it only *escalates*
            // severity (the prefund drain) once the function is already AA-anchored.
            let is_named_entry = is_aa_validation_fn(cx, f);
            let reads_funds = reads_missing_funds_param(f);
            let pays_sender = pays_value_to_msg_sender(f);
            if !(is_named_entry || reads_funds) {
                continue;
            }

            // Already guarded? Suppress.
            if has_entrypoint_guard(cx, f) {
                continue;
            }

            // Does it drain / mis-account? -> Critical, else High.
            let drains = pays_sender
                || calls_pay_prefund(f)
                || is_paymaster_postop(cx, f);

            out.push(build(self, cx, f, drains, is_named_entry, reads_funds));
        }
        out
    }
}

// --------------------------------------------------------------------- triggers

/// Does `f` read a `missingAccountFunds` / `maxCost` parameter — the prefund word
/// only the EntryPoint supplies? (A bare name match on the parameter list.)
fn reads_missing_funds_param(f: &Function) -> bool {
    f.params.iter().any(|p| {
        p.name
            .as_deref()
            .map(|n| n.to_ascii_lowercase())
            .is_some_and(|n| n.contains("missingaccountfunds") || n.contains("maxcost"))
    })
}

/// Does `f` (or a helper it calls) run `_payPrefund`? Recorded in `internal_calls`.
fn calls_pay_prefund(f: &Function) -> bool {
    f.effects
        .internal_calls
        .iter()
        .any(|n| n.trim_start_matches('_').eq_ignore_ascii_case("payprefund"))
}

/// Is `f` a paymaster `postOp` (a forged call mis-accounts the EntryPoint deposit)?
fn is_paymaster_postop(cx: &AnalysisContext, f: &Function) -> bool {
    f.name.eq_ignore_ascii_case("postop")
        && (aa_postop_shape_external(f) || contract_inherits_aa(cx, f))
}

/// `postOp` first-arg-is-PostOpMode shape, recomputed here (the prelude keeps the
/// composite `has_aa_validation_shape`; this is the postOp slice).
fn aa_postop_shape_external(f: &Function) -> bool {
    f.params
        .first()
        .and_then(|p| p.ty.split_whitespace().next())
        .is_some_and(|t| t.eq_ignore_ascii_case("postopmode"))
}

/// Does `f` send ETH to `payable(msg.sender)` — the `_payPrefund` drain shape
/// (`(bool ok,) = payable(msg.sender).call{value: x}("")`)? A value-bearing
/// low-level/transfer/send call whose target mentions `msg.sender`.
fn pays_value_to_msg_sender(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            let sends_value = c.value.is_some()
                || matches!(c.kind, CallKind::Transfer | CallKind::Send);
            if !sends_value {
                return;
            }
            // Receiver / target mentions msg.sender (peel `payable(...)`).
            if let Some(recv) = c.receiver.as_deref() {
                if expr_mentions_msg_sender(peel_casts(recv)) {
                    found = true;
                }
            }
        });
        if found {
            break;
        }
    }
    found
}

// ----------------------------------------------------------------- guard check

/// Is the EntryPoint-only guard present? Any of:
///   1. an internal call to `_requireFromEntryPoint` (the reference helper);
///   2. an `onlyEntryPoint` / `requireFromEntryPoint`-style modifier;
///   3. an inline `msg.sender ==/!= <entryPoint>` (in)equality where the comparand
///      resolves to the EntryPoint (an `entryPoint`/`_entryPoint`-named state read
///      or accessor), not to attacker input.
fn has_entrypoint_guard(cx: &AnalysisContext, f: &Function) -> bool {
    // (1) the canonical internal guard call.
    if f.effects.internal_calls.iter().any(|n| {
        let l = n.trim_start_matches('_').to_ascii_lowercase();
        l == "requirefromentrypoint" || l == "requireforexecute"
    }) {
        return true;
    }
    // (2) a guard modifier naming the EntryPoint.
    if f.modifiers.iter().any(|m| {
        let l = m.name.to_ascii_lowercase();
        l.contains("entrypoint")
    }) {
        return true;
    }
    // (3) an inline `msg.sender (==|!=) <entryPoint-resolving>` check.
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            let ExprKind::Binary { op, lhs, rhs } = &e.kind else { return };
            if !matches!(op, BinOp::Eq | BinOp::Ne) {
                return;
            }
            let other = if is_msg_sender(lhs) {
                Some(rhs.as_ref())
            } else if is_msg_sender(rhs) {
                Some(lhs.as_ref())
            } else {
                None
            };
            let Some(other) = other else { return };
            // Reject a comparison against attacker input (a forged param).
            if cx.is_attacker_controlled(f.id, other) {
                return;
            }
            if comparand_is_entrypoint(other) {
                found = true;
            }
        });
        if found {
            break;
        }
    }
    found
}

/// Does the comparand resolve to the EntryPoint? Accepts `entryPoint()` / a
/// stored `entryPoint`/`_entryPoint` (the reference holds it as an immutable), peeling
/// `address(...)` casts and `()` calls.
fn comparand_is_entrypoint(e: &Expr) -> bool {
    let inner = peel_casts(e);
    // `address(entryPoint())` -> the call's callee names entryPoint.
    if let ExprKind::Call(c) = &inner.kind {
        if let Some(n) = c.func_name.as_deref().or_else(|| inner.simple_name()) {
            if n.to_ascii_lowercase().contains("entrypoint") {
                return true;
            }
        }
        // also peel the callee chain root
        if let Some(r) = root_ident_peeled(&c.callee) {
            if r.to_ascii_lowercase().contains("entrypoint") {
                return true;
            }
        }
    }
    // a bare / member identifier mentioning entryPoint (`_entryPoint`, `entryPoint`).
    root_ident_peeled(inner)
        .map(|r| r.to_ascii_lowercase().contains("entrypoint"))
        .unwrap_or(false)
        || inner
            .simple_name()
            .map(|n| n.to_ascii_lowercase().contains("entrypoint"))
            .unwrap_or(false)
}

/// `msg.sender` (shallow member access).
fn is_msg_sender(e: &Expr) -> bool {
    e.mentions_member("msg", "sender")
}

/// Does `e` mention `msg.sender` anywhere (e.g. inside `payable(msg.sender)`)?
fn expr_mentions_msg_sender(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if is_msg_sender(sub) {
            found = true;
        }
    });
    found
}

// ------------------------------------------------------------------- reporting

fn build(
    det: &MissingEntryPointGuardDetector,
    cx: &AnalysisContext,
    f: &Function,
    drains: bool,
    is_named_entry: bool,
    reads_funds: bool,
) -> Finding {
    let severity = if drains { Severity::Critical } else { Severity::High };
    let what = if is_named_entry {
        "an ERC-4337 validation/post-execution entry point"
    } else if reads_funds {
        "an ERC-4337-shaped function (it reads the `missingAccountFunds`/`maxCost` prefund word only the EntryPoint supplies)"
    } else {
        "an ERC-4337-shaped function (it sends ETH to `payable(msg.sender)`, the `_payPrefund` shape)"
    };
    let drain_clause = if drains {
        " Because it then sends ETH to the direct caller (`_payPrefund`/`payable(msg.sender).call{value:}`) \
          or mis-accounts the paymaster's EntryPoint deposit (`postOp`), an attacker who calls it directly \
          drains the account's ETH or corrupts the deposit accounting."
    } else {
        " Because the function is externally callable, an attacker can invoke it directly with a forged \
          UserOperation, bypassing the EntryPoint's simulation and nonce/signature accounting."
    };
    let b = FindingBuilder::new(det.id(), Category::MissingEntryPointGuard)
        .title("ERC-4337 validation/postOp entry point missing the EntryPoint-only guard")
        .severity(severity)
        .confidence(0.7)
        .dimension(Dimension::Frontier)
        .dimension(Dimension::ValueFlow)
        .message(format!(
            "`{}` is {} but binds `msg.sender` to the EntryPoint nowhere — there is no \
             `_requireFromEntryPoint()` call, no `onlyEntryPoint` modifier, and no inline \
             `require(msg.sender == address(entryPoint()))`.{} This is the \
             `BaseAccount._requireFromEntryPoint()` invariant.",
            f.name, what, drain_clause
        ))
        .recommendation(
            "Make the first statement of the entry point `_requireFromEntryPoint()` (or an \
             equivalent `require(msg.sender == address(entryPoint()))` / `onlyEntryPoint` modifier), \
             so only the singleton EntryPoint can drive validation, prefunding, and postOp.",
        );
    cx.finish(b, f.id, f.span)
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.detector == "missing-entrypoint-guard")
    }

    // VULN — a `validateUserOp` that prefunds the *direct caller* with NO
    // _requireFromEntryPoint guard. Anyone calls it and drains the account's ETH.
    const VULN_ACCOUNT: &str = r#"
        pragma solidity ^0.8.20;
        struct PackedUserOperation { uint256 nonce; bytes signature; }
        contract VulnAccount {
            function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
                external returns (uint256 validationData) {
                if (missingAccountFunds != 0) {
                    (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
                    (ok);
                }
                return 0;
            }
        }
    "#;

    // VULN — a paymaster `postOp` with no guard (deposit mis-accounting).
    const VULN_POSTOP: &str = r#"
        pragma solidity ^0.8.20;
        contract VulnPaymaster {
            enum PostOpMode { opSucceeded, opReverted, postOpReverted }
            mapping(address => uint256) public spent;
            function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 feePerGas)
                external {
                address user = abi.decode(context, (address));
                spent[user] += actualGasCost;     // finalized accounting, forgeable
            }
        }
    "#;

    // SAFE — the reference shape: validateUserOp calls _requireFromEntryPoint first.
    const SAFE_ACCOUNT: &str = r#"
        pragma solidity ^0.8.20;
        struct PackedUserOperation { uint256 nonce; bytes signature; }
        interface IEntryPoint { function getNonce(address a, uint192 k) external view returns (uint256); }
        abstract contract BaseAccount {
            function entryPoint() public view virtual returns (IEntryPoint);
            function _requireFromEntryPoint() internal view virtual {
                require(msg.sender == address(entryPoint()), "not from EntryPoint");
            }
            function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
                external virtual returns (uint256 validationData) {
                _requireFromEntryPoint();
                if (missingAccountFunds != 0) {
                    (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
                    (ok);
                }
                return 0;
            }
        }
    "#;

    // SAFE — an inline `require(msg.sender == address(entryPoint()))` (no helper).
    const SAFE_INLINE: &str = r#"
        pragma solidity ^0.8.20;
        struct PackedUserOperation { uint256 nonce; bytes signature; }
        interface IEntryPoint { function getNonce(address a, uint192 k) external view returns (uint256); }
        contract InlineAccount {
            IEntryPoint public entryPoint;
            function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
                external returns (uint256 validationData) {
                require(msg.sender == address(entryPoint), "not entrypoint");
                return 0;
            }
        }
    "#;

    // SAFE — the internal `_validateSignature` override is internal (not externally
    // reachable); its public entry carries the guard in the base. Must not fire.
    const SAFE_INTERNAL_OVERRIDE: &str = r#"
        pragma solidity ^0.8.20;
        struct PackedUserOperation { uint256 nonce; bytes signature; }
        abstract contract BaseAccount {}
        contract MyAccount is BaseAccount {
            function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
                internal virtual returns (uint256) { return 0; }
        }
    "#;

    #[test]
    fn fires_on_unguarded_validate_userop() {
        let fs = run(VULN_ACCOUNT);
        assert!(fires(&fs), "{:?}", fs);
        assert!(
            fs.iter().any(|f| f.detector == "missing-entrypoint-guard"
                && f.severity == sluice_findings::Severity::Critical),
            "draining validateUserOp must be Critical: {:?}",
            fs
        );
    }

    #[test]
    fn fires_on_unguarded_postop() {
        let fs = run(VULN_POSTOP);
        assert!(fires(&fs), "{:?}", fs);
    }

    #[test]
    fn silent_on_guarded_account() {
        let fs = run(SAFE_ACCOUNT);
        assert!(!fires(&fs), "{:?}", fs);
    }

    #[test]
    fn silent_on_inline_guard() {
        let fs = run(SAFE_INLINE);
        assert!(!fires(&fs), "{:?}", fs);
    }

    #[test]
    fn silent_on_internal_override() {
        let fs = run(SAFE_INTERNAL_OVERRIDE);
        assert!(!fires(&fs), "{:?}", fs);
    }

    // The eth-infinitism reference contracts are CORRECT code: all three R26
    // detectors must be SILENT on the safe baseline (no FP-flood). Skipped when the
    // corpus checkout is absent.
    #[test]
    fn silent_on_safe_aa_reference_corpus() {
        let root = "/home/stan/Data/corpus/account-abstraction/contracts";
        let safe = [
            "core/BaseAccount.sol",
            "core/BasePaymaster.sol",
            "core/EntryPoint.sol",
            "core/NonceManager.sol",
            "core/StakeManager.sol",
            "interfaces/IAccount.sol",
            "interfaces/IPaymaster.sol",
            "interfaces/IEntryPoint.sol",
            "accounts/SimpleAccount.sol",
            "accounts/SimpleAccountFactory.sol",
            "accounts/Simple7702Account.sol",
        ];
        let mut sources = Vec::new();
        for s in &safe {
            let p = format!("{root}/{s}");
            match std::fs::read_to_string(&p) {
                Ok(c) => sources.push((p, c)),
                Err(_) => {
                    eprintln!("AA corpus absent — skipping safe-baseline silence test");
                    return;
                }
            }
        }
        let res = analyze_sources(sources, &Config::default());
        let ours = ["missing-entrypoint-guard", "validation-phase-env-opcode", "validation-untrusted-callout"];
        let fps: Vec<_> = res
            .findings
            .iter()
            .filter(|f| ours.contains(&f.detector.as_str()))
            .map(|f| format!("{} on {}::{}", f.detector, f.contract, f.function))
            .collect();
        assert!(fps.is_empty(), "R26 detectors must be silent on the safe AA reference, got: {:?}", fps);
    }
}
