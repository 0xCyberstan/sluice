//! ERC-4337 validation-phase environment opcode (R26-1, ERC-7562 OP-011/OP-080).
//!
//! During the *validation* phase of a UserOperation (`validateUserOp` /
//! `validatePaymasterUserOp`), ERC-7562 forbids reading block-environment and
//! other non-deterministic state:
//!
//!   * **OP-011** — `TIMESTAMP`, `NUMBER`, `BLOCKHASH`, `PREVRANDAO`/`DIFFICULTY`,
//!     `COINBASE`, `GASLIMIT`, `BASEFEE`, `GASPRICE`, `GAS`, `ORIGIN`.
//!   * **OP-080** — `BALANCE`/`SELFBALANCE` (allowed only for a staked entity).
//!
//! The bundler simulates validation off-chain at block *N* and must be able to
//! trust that result until the op is included. If validation branches on a block
//! value, an op that passes simulation at block *N* can flip at *N+1*: the bundler's
//! whole bundle reverts on-chain and the offending entity is reputation-banned —
//! a mempool denial-of-service paid for out of pooled bundler/entity funds. (The
//! reference even warns in `BaseAccount`: "the validation code cannot use
//! `block.timestamp` (or `block.number`) directly".)
//!
//! The detector fires when [`is_aa_validation_fn`] (or a function transitively
//! reachable from one — the rule applies to the whole validation call tree) reads
//! any banned environment value: `block.{timestamp,number,coinbase,prevrandao,
//! difficulty,basefee,gaslimit}`, `tx.{origin,gasprice}`, `blockhash(...)`,
//! `gasleft()`, or a `.balance` / `address(this).balance` read.
//!
//! ## Precision (false-positive suppression)
//!   * **Time-range packing** — when the only env use is folding a value into the
//!     returned `validationData` (a `<<`/`|` packing, or a `_packValidationData`
//!     call) the contract is encoding `validUntil`/`validAfter`, which the EntryPoint
//!     interprets off-chain — *not* an OP-011 violation. Such a body is reported at
//!     **Info** (correctness note), not High.
//!   * **Staked entities** — a staked account/paymaster (the body / contract names a
//!     stake, or it `addStake`s) is permitted OP-080 BALANCE reads; suppressed.
//!   * Interfaces and pure view helpers carry no executable validation and are
//!     skipped.
//!
//! Distinct from `weak-randomness` / `block-number-time` (which frame env reads as
//! manipulation / time-drift); here the harm is validation-phase mempool DoS.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use super::prelude::*;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Builtin, CallKind, Expr, ExprKind, Function, StmtKind};

pub struct ValidationPhaseEnvOpcodeDetector;

impl Detector for ValidationPhaseEnvOpcodeDetector {
    fn id(&self) -> &'static str {
        "validation-phase-env-opcode"
    }
    fn category(&self) -> Category {
        Category::ValidationPhaseEnvOpcode
    }
    fn description(&self) -> &'static str {
        "ERC-4337 validateUserOp/validatePaymasterUserOp reads banned block-env / balance / tx.origin (ERC-7562 OP-011/OP-080)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // The validation entry itself, or a function reached from one (the rule
            // governs the whole validation call tree).
            if !reachable_from_aa_validation(cx, f) {
                continue;
            }

            // Locate the first banned env read (and classify it).
            let Some((span, what, is_balance)) = first_banned_env_read(f) else {
                continue;
            };

            // OP-080 BALANCE is allowed for a staked entity.
            if is_balance && is_staked_entity(cx, f) {
                continue;
            }

            // The harmful shape is an env value that *gates* validation (a branch /
            // require / comparison) — that is the value that flips between blocks N
            // and N+1. An env value that only folds into the returned
            // `validationData` (validUntil/validAfter time-range packing, which the
            // EntryPoint interprets off-chain) is a correctness note, reported at
            // Info. `gates` selects High vs Info in `build`.
            let gates = env_gates_control_flow(cx, f);

            out.push(build(self, cx, f, span, what, gates));
        }
        out
    }
}

// ----------------------------------------------------------- env-read detection

/// The first banned environment read in `f`, with a human label and whether it is a
/// BALANCE (OP-080) read. Walks the body once in document order.
fn first_banned_env_read(f: &Function) -> Option<(sluice_ir::Span, &'static str, bool)> {
    // Fast path label from the precomputed flags is not enough (no span / no
    // tx.gasprice / no balance), so always walk for the span + the extra opcodes.
    let mut hit: Option<(sluice_ir::Span, &'static str, bool)> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            if let Some((label, is_bal)) = classify_env_expr(e) {
                hit = Some((e.span, label, is_bal));
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Classify a single expression as a banned env read, if it is one. Returns a label
/// and whether it is a BALANCE read (OP-080).
fn classify_env_expr(e: &Expr) -> Option<(&'static str, bool)> {
    match &e.kind {
        // Member reads: block.* / tx.* / *.balance.
        ExprKind::Member { base, member } => {
            if let ExprKind::Ident(b) = &base.kind {
                match (b.as_str(), member.as_str()) {
                    ("block", "timestamp") => return Some(("block.timestamp", false)),
                    ("block", "number") => return Some(("block.number", false)),
                    ("block", "coinbase") => return Some(("block.coinbase", false)),
                    ("block", "prevrandao") => return Some(("block.prevrandao", false)),
                    ("block", "difficulty") => return Some(("block.difficulty", false)),
                    ("block", "basefee") => return Some(("block.basefee", false)),
                    ("block", "gaslimit") => return Some(("block.gaslimit", false)),
                    ("tx", "origin") => return Some(("tx.origin", false)),
                    ("tx", "gasprice") => return Some(("tx.gasprice", false)),
                    _ => {}
                }
            }
            // `<expr>.balance` (incl. `address(this).balance`, `addr.balance`).
            if member == "balance" {
                return Some((".balance", true));
            }
            None
        }
        // Builtins: blockhash(...) and gasleft().
        ExprKind::Call(c) => match c.kind {
            CallKind::Builtin(Builtin::Blockhash) => Some(("blockhash()", false)),
            CallKind::Builtin(Builtin::Gasleft) => Some(("gasleft()", false)),
            _ => None,
        },
        _ => None,
    }
}

// ------------------------------------------------------------------ suppression

/// Is the function's entity staked (so OP-080 BALANCE is permitted)? Heuristic: the
/// contract or body mentions staking (`stake`/`addStake`/`stakeManager`) — staked
/// accounts/paymasters opt into balance-sensitive validation.
fn is_staked_entity(cx: &AnalysisContext, f: &Function) -> bool {
    if f.effects
        .internal_calls
        .iter()
        .any(|n| n.to_ascii_lowercase().contains("stake"))
    {
        return true;
    }
    if f.effects
        .call_sites
        .iter()
        .filter_map(|c| c.func_name.as_deref())
        .any(|n| n.to_ascii_lowercase().contains("stake"))
    {
        return true;
    }
    // Contract-level marker (a Stakeable base / a *stake* state var name).
    cx.contract_of(f.id).is_some_and(|c| {
        c.inherits_like("stakeable")
            || c.inherits_like("stakemanager")
            || c.state_vars.iter().any(|v| v.name.to_ascii_lowercase().contains("stake"))
    })
}

/// Does a banned env value **gate control flow** — does it reach an `if`/`while`/
/// `for` condition, a `require`/`assert`/`revert`, or a comparison? That is the
/// harmful shape (the op passes simulation at block N and flips at N+1). An env read
/// that only folds into the returned `validationData` (validUntil/validAfter
/// packing) gates nothing and is downgraded to Info.
///
/// "Reaches" combines a structural check (the env member appears in the condition
/// expression) with provenance (the condition operand carries `BlockEnv`, catching
/// the `uint256 t = block.timestamp; if (x > t)` local-variable hop).
fn env_gates_control_flow(cx: &AnalysisContext, f: &Function) -> bool {
    let mut gates = false;
    for s in &f.body {
        s.visit(&mut |st| {
            if gates {
                return;
            }
            // A branch / loop condition (`if`/`while`/`do-while`/`for`) or a
            // `revert`-path argument that reaches an env value is a control-flow gate.
            let gated = match &st.kind {
                StmtKind::If { cond, .. }
                | StmtKind::While { cond, .. }
                | StmtKind::DoWhile { cond, .. } => cond_reaches_env(cx, f, cond),
                StmtKind::For { cond: Some(c), .. } => cond_reaches_env(cx, f, c),
                StmtKind::Revert { args, .. } => args.iter().any(|a| cond_reaches_env(cx, f, a)),
                _ => false,
            };
            if gated {
                gates = true;
            }
        });
        if gates {
            break;
        }
        // `require(env-gated)` / a bare comparison / a ternary whose condition is
        // env-derived — each gates the validation outcome.
        s.visit_exprs(&mut |e| {
            if gates {
                return;
            }
            let gated = match &e.kind {
                ExprKind::Binary { op, lhs, rhs } if op.is_comparison() => {
                    cond_reaches_env(cx, f, lhs) || cond_reaches_env(cx, f, rhs)
                }
                ExprKind::Ternary { cond, .. } => cond_reaches_env(cx, f, cond),
                ExprKind::Call(c) if is_require_or_assert(c) => {
                    c.args.iter().any(|a| cond_reaches_env(cx, f, a))
                }
                _ => false,
            };
            if gated {
                gates = true;
            }
        });
        if gates {
            break;
        }
    }
    gates
}

/// Does expression `e` reach a banned env value — structurally (an env member is
/// nested in it) or by provenance (`ValueSource::BlockEnv`, catching a local hop)?
fn cond_reaches_env(cx: &AnalysisContext, f: &Function, e: &Expr) -> bool {
    if expr_reaches_env(e) {
        return true;
    }
    cx.provenance_of(f.id, e).contains(sluice_ir::ValueSource::BlockEnv)
}

/// Does `e` transitively contain any banned env read (structural)?
fn expr_reaches_env(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if classify_env_expr(sub).is_some() {
            found = true;
        }
    });
    found
}

// ------------------------------------------------------------------- reporting

fn build(
    det: &ValidationPhaseEnvOpcodeDetector,
    cx: &AnalysisContext,
    f: &Function,
    span: sluice_ir::Span,
    what: &str,
    gates: bool,
) -> Finding {
    let (severity, confidence) = if gates {
        (Severity::High, 0.65)
    } else {
        (Severity::Info, 0.4)
    };
    let pack_note = if gates {
        ""
    } else {
        " Here the value only folds into the returned `validationData` (validUntil/validAfter \
          time-range packing), which the EntryPoint interprets off-chain rather than the validation \
          gating on it directly — informational; confirm it never reaches a branch/require."
    };
    let mut b = FindingBuilder::new(det.id(), Category::ValidationPhaseEnvOpcode)
        .title("ERC-4337 validation reads banned block-env / balance / tx.origin (ERC-7562 OP-011/OP-080)")
        .severity(severity)
        .confidence(confidence)
        // Frontier: a validation-scope / mempool trust concern.
        .dimension(Dimension::Frontier);
    // When the env value gates the validation outcome it also flows into the
    // accept/reject decision — a second (value-flow) dimension that corroborates the
    // finding; the Info packing case keeps the lone dimension.
    if gates {
        b = b.dimension(Dimension::ValueFlow);
    }
    let b = b
        .message(format!(
            "`{}` runs inside the ERC-4337 validation phase yet reads `{}`, which ERC-7562 OP-011/OP-080 \
             forbid during validation. The bundler simulates validation off-chain at block N and trusts \
             that result; an op that branches on a block value can pass at N and flip at N+1, so the \
             bundler's bundle reverts on-chain and the entity is reputation-banned — a mempool DoS paid \
             out of pooled funds.{} (The reference `BaseAccount` warns the validation code must not use \
             `block.timestamp`/`block.number` directly.)",
            f.name, what, pack_note
        ))
        .recommendation(
            "Remove block-environment / balance / tx.origin reads from the validation path. Encode any \
             time bounds as `validUntil`/`validAfter` in the returned `validationData` (the EntryPoint \
             enforces them), and gate balance-sensitive logic to a staked entity or move it to the \
             execution phase.",
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
        fs.iter().any(|f| f.detector == "validation-phase-env-opcode")
    }

    // VULN — validateUserOp branches on block.timestamp to decide validity (a
    // direct OP-011 violation, gating control flow).
    const VULN_TIMESTAMP: &str = r#"
        pragma solidity ^0.8.20;
        struct PackedUserOperation { uint256 nonce; bytes signature; }
        interface IEntryPoint { function x() external; }
        abstract contract BaseAccount {
            function entryPoint() public view virtual returns (IEntryPoint);
            function _requireFromEntryPoint() internal view virtual {
                require(msg.sender == address(entryPoint()));
            }
            function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
                external virtual returns (uint256 validationData) {
                _requireFromEntryPoint();
                if (block.timestamp > 1000000) {     // OP-011: env-gated validation
                    return 1;
                }
                return 0;
            }
        }
    "#;

    // VULN — validatePaymasterUserOp reads tx.origin during validation.
    const VULN_TXORIGIN: &str = r#"
        pragma solidity ^0.8.20;
        struct PackedUserOperation { uint256 nonce; bytes signature; }
        contract Pm {
            function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
                external returns (bytes memory context, uint256 validationData) {
                require(tx.origin == userOp.nonce ? address(0) : msg.sender);   // tx.origin in validation
                return ("", 0);
            }
        }
    "#;

    // SAFE — no env read in validation; signature only.
    const SAFE: &str = r#"
        pragma solidity ^0.8.20;
        struct PackedUserOperation { uint256 nonce; bytes signature; }
        interface IEntryPoint { function x() external; }
        abstract contract BaseAccount {
            address public owner;
            function entryPoint() public view virtual returns (IEntryPoint);
            function _requireFromEntryPoint() internal view virtual { require(msg.sender == address(entryPoint())); }
            function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
                external virtual returns (uint256 validationData) {
                _requireFromEntryPoint();
                return userOp.nonce == 0 ? 0 : 1;
            }
        }
    "#;

    // INFO — env value packed into validationData (validUntil/validAfter), via a
    // shift/or that mixes a timestamp — legitimate time-range encoding -> Info.
    const PACKING: &str = r#"
        pragma solidity ^0.8.20;
        struct PackedUserOperation { uint256 nonce; bytes signature; }
        contract Account {
            function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
                external returns (uint256 validationData) {
                uint256 validUntil = block.timestamp + 3600;
                validationData = (validUntil << 160) | uint256(uint160(msg.sender));
                return validationData;
            }
        }
    "#;

    #[test]
    fn fires_on_timestamp_gate() {
        let fs = run(VULN_TIMESTAMP);
        assert!(fires(&fs), "{:?}", fs);
        // The env value gates control flow (two dimensions) -> scored up to High.
        assert!(
            fs.iter().any(|f| f.detector == "validation-phase-env-opcode"
                && f.severity == sluice_findings::Severity::High),
            "control-flow env gate must score to High: {:?}",
            fs
        );
    }

    #[test]
    fn fires_on_tx_origin() {
        let fs = run(VULN_TXORIGIN);
        assert!(fires(&fs), "{:?}", fs);
    }

    #[test]
    fn silent_on_clean_validation() {
        let fs = run(SAFE);
        assert!(!fires(&fs), "{:?}", fs);
    }

    #[test]
    fn packing_is_info_not_high() {
        let fs = run(PACKING);
        // It DOES fire (env read present) but is downgraded to Info.
        let hit: Vec<_> = fs.iter().filter(|f| f.detector == "validation-phase-env-opcode").collect();
        assert!(!hit.is_empty(), "expected an Info finding for packing: {:?}", fs);
        assert!(
            hit.iter().all(|f| f.severity == sluice_findings::Severity::Info),
            "time-range packing must be Info, got {:?}",
            hit
        );
    }
}
