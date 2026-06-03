//! Proxy / upgradeable hazards: controlled delegatecall and uninitialized
//! (UUPS) implementations.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::detectors::visit_calls;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{CallKind, Expr, ExprKind, Function, StmtKind};
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
            // Does this function look like eth_call-only simulation dev-tooling:
            // the only non-call top-level statement is an unconditional revert?
            let simulation_shape = is_simulation_revert_shape(f);

            visit_calls(f, |c, span| {
                if c.kind != CallKind::DelegateCall {
                    return;
                }
                let recv = match c.receiver.as_ref() {
                    Some(r) => r,
                    None => return,
                };
                let target_root = recv.simple_name().unwrap_or("").to_string();

                // (1a) SELF-DELEGATECALL / multicall: the target syntactically
                // resolves to `address(this)` / `this`. This is the standard
                // self-multicall (batch-call-self) pattern — control never
                // leaves THIS code, so it is NOT a foreign-target / Parity
                // takeover. Demote to Info with multicall wording.
                // (An *immutable* handle set to `address(this)` in the constructor
                // — e.g. `original = address(this)` — is likewise a self-call; it
                // is already silently suppressed by the constant/immutable check
                // in (1) below, so it never reaches the foreign-target branch.)
                if is_self_target(recv) {
                    let b = FindingBuilder::new(self.id(), Category::DelegatecallStorage)
                        .title("self-delegatecall (multicall pattern)")
                        .severity(Severity::Info)
                        .confidence(0.4)
                        .dimension(Dimension::Frontier)
                        .message(format!(
                            "`{}` delegatecalls into `address(this)` (self-delegatecall / multicall): the \
                             call dispatches back into THIS contract's own code, so no foreign \
                             implementation runs. This is the standard batch-self-call pattern and is \
                             not a controllable-target takeover.",
                            f.name
                        ))
                        .recommendation(
                            "No action required for a self-delegatecall. Ensure the decoded selector cannot \
                             reach privileged functions in an unintended context.",
                        );
                    out.push(cx.finish(b, f.id, span));
                    return;
                }

                let constant_target = immutables.contains(&target_root)
                    || matches!(recv.kind, ExprKind::Lit(_));
                if constant_target {
                    return;
                }

                let attacker = cx.is_attacker_controlled(f.id, recv);
                // (1b) SIMULATION ENTRYPOINT: a `simulate()`-style function that
                // delegatecalls a caller-supplied `target` and then does nothing
                // but `revert(...)`. This is eth_call-only dev tooling (the state
                // change is always rolled back), so flagging it is correct but
                // Critical is too hot — the revert means it cannot persist a
                // takeover on-chain. Cap it in the Medium/High band.
                if simulation_shape {
                    // Base Medium (not Critical): even with full cross-dimension
                    // corroboration the score formula keeps this in the Medium/High
                    // band, never Critical — the unconditional revert means it
                    // cannot persist on-chain.
                    let b = FindingBuilder::new(self.id(), Category::DelegatecallStorage)
                        .title("delegatecall to a caller-supplied target in a simulate/revert helper")
                        .severity(Severity::Medium)
                        .confidence(0.6)
                        .dimension(Dimension::Frontier)
                        .dimension(Dimension::ValueFlow)
                        .message(format!(
                            "`{}` delegatecalls into caller-supplied `{}` and then unconditionally \
                             `revert`s. This is an eth_call-only simulation helper: because the call \
                             always reverts, on-chain state cannot be mutated, so it is not a persistent \
                             takeover primitive. Still ensure it is never reachable in a state-committing \
                             context (e.g. inside another delegatecall that does not revert).",
                            f.name, target_root
                        ))
                        .recommendation(
                            "Keep simulation entrypoints `eth_call`-only: guarantee the unconditional revert \
                             cannot be bypassed and that the function is not delegatecalled by a committing caller.",
                        );
                    out.push(cx.finish(b, f.id, span));
                    return;
                }

                // (1c) Genuine controllable delegatecall target (mutable storage
                // slot or caller-supplied address) — the arbitrary-write / Parity
                // takeover primitive.
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
            // The implementation is locked if the constructor calls
            // `_disableInitializers()` OR carries the `initializer` modifier
            // (`constructor() initializer {}` — an equally valid, common idiom).
            let disables = ctor
                .map(|f| {
                    cx.source_text(f.span).contains("_disableinitializers")
                        || cx.is_initializer(f)
                        || f.has_modifier_like("initializer")
                })
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

// --------------------------------------------------------------- self-call helpers

/// True if `e` is the literal `this` expression, or a type-cast wrapping it
/// (`address(this)`, `payable(address(this))`). Such a delegatecall receiver
/// dispatches back into THIS contract — the self-multicall pattern.
fn is_this_expr(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Ident(n) => n == "this",
        // `address(this)`, `payable(this)`, `payable(address(this))`, ...
        ExprKind::Call(c) if c.kind == CallKind::TypeCast => {
            c.args.len() == 1 && is_this_expr(&c.args[0])
        }
        _ => false,
    }
}

/// True if a delegatecall receiver `recv` resolves to self: a literal
/// `this` / `address(this)` (`payable(address(this))`, ...). An *immutable* bound
/// to `address(this)` is also a self-call, but it is already suppressed by the
/// constant/immutable target check, so it never needs to be matched here.
fn is_self_target(recv: &Expr) -> bool {
    is_this_expr(recv)
}

/// True if the function body is the eth_call-only "simulate then revert" shape:
/// there is at least one top-level **unconditional** `revert(...)` and no
/// top-level `return`, branch, loop, emit, or assignment — i.e. the only
/// non-call statement is an unconditional revert. This distinguishes a
/// `simulate(target, data){ target.delegatecall(data); revert(...); }` dev helper
/// from a genuine committing `exec(target, data){ target.delegatecall(data); }`.
fn is_simulation_revert_shape(f: &Function) -> bool {
    let mut has_uncond_revert = false;
    for s in &f.body {
        match &s.kind {
            // An unconditional revert: either a `revert Error(...)` statement or a
            // bare `revert(...)` builtin call expression at the top level.
            StmtKind::Revert { .. } => has_uncond_revert = true,
            StmtKind::Expr(e) if is_revert_call(e) => has_uncond_revert = true,
            // Pure plumbing around the delegatecall is fine.
            StmtKind::Expr(_) | StmtKind::VarDecl { .. } | StmtKind::Block { .. } => {}
            StmtKind::Assembly { .. } => {}
            // Anything that can commit state or branch around the revert
            // disqualifies the "always reverts" reading.
            StmtKind::Return(_)
            | StmtKind::If { .. }
            | StmtKind::While { .. }
            | StmtKind::DoWhile { .. }
            | StmtKind::For { .. }
            | StmtKind::Emit(_)
            | StmtKind::Try { .. } => return false,
            StmtKind::Break | StmtKind::Continue | StmtKind::Placeholder | StmtKind::Unsupported => {}
        }
    }
    has_uncond_revert
}

/// True if `e` is a `revert(...)` builtin call.
fn is_revert_call(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Call(c) if c.kind == CallKind::Builtin(sluice_ir::Builtin::Revert))
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    use sluice_findings::{Finding, Severity};

    fn run(src: &str) -> Vec<Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn upg(fs: &[Finding]) -> Vec<&Finding> {
        fs.iter().filter(|f| f.detector == "upgradeable").collect()
    }

    // --- (C) positive anchors: genuine controllable-target delegatecall MUST stay
    //     a strong (Critical/High) "non-constant target" finding. ---

    // Caller-supplied `target` delegatecalled directly, no revert — a genuine
    // arbitrary-code / Parity takeover primitive.
    const VULN_EXEC: &str = r#"
        contract Exec {
            function exec(address target, bytes calldata data) external {
                target.delegatecall(data);
            }
        }
    "#;

    // Mutable storage slot as the delegatecall target (the corpus MutableProxy
    // shape), attacker-settable via a setter.
    const VULN_MUTABLE: &str = r#"
        contract Proxy {
            address public implementation;
            function setImpl(address i) external { implementation = i; }
            function run(bytes calldata data) external returns (bytes memory) {
                (bool ok, bytes memory r) = implementation.delegatecall(data);
                require(ok);
                return r;
            }
        }
    "#;

    #[test]
    fn fires_strong_on_caller_supplied_target() {
        let fs = run(VULN_EXEC);
        let us = upg(&fs);
        assert!(
            us.iter().any(|f| f.title == "delegatecall to a non-constant target"
                && f.severity >= Severity::High),
            "expected a strong non-constant-target finding, got {us:#?}"
        );
        // It must NOT be demoted to the self-delegatecall Info wording.
        assert!(
            !us.iter().any(|f| f.severity == Severity::Info),
            "caller-supplied target must not be treated as self-delegatecall: {us:#?}"
        );
        // No "Parity takeover" wording suppression regressions here: the message
        // is the foreign-target one.
        assert!(us.iter().any(|f| f.message.contains("foreign code")));
    }

    #[test]
    fn fires_on_mutable_storage_target() {
        // The corpus MutableProxy shape: a mutable storage slot as the
        // delegatecall target. It must still fire as the foreign-target
        // "non-constant target" finding (the engine scores it Medium because the
        // slot is not provably attacker-tainted) — and must NOT be demoted to the
        // self-delegatecall Info note.
        let fs = run(VULN_MUTABLE);
        let us = upg(&fs);
        assert!(
            us.iter().any(|f| f.title == "delegatecall to a non-constant target"),
            "expected the foreign-target finding for a mutable-slot target, got {us:#?}"
        );
        assert!(
            !us.iter().any(|f| f.severity == Severity::Info),
            "mutable-slot target must not be treated as self-delegatecall: {us:#?}"
        );
    }

    // --- (A) self-delegatecall / multicall: must be silent-or-Info, never the
    //     Critical foreign-target "Parity takeover" finding. ---

    // The canonical batch-self-call (multicall) helper.
    const SELF_MULTICALL: &str = r#"
        contract MC {
            function multicall(bytes[] calldata data) external {
                for (uint256 i = 0; i < data.length; i++) {
                    address(this).delegatecall(data[i]);
                }
            }
        }
    "#;

    // Pendle `_delegateToSelf` shape (ActionBase / StakedPendle): `address(this)`
    // delegatecall with a Yul bubble-up revert nested inside an `if`.
    const SELF_DELEGATE_HELPER: &str = r#"
        contract Action {
            function _delegateToSelf(bytes memory data, bool allowFailure)
                internal returns (bool success, bytes memory result)
            {
                (success, result) = address(this).delegatecall(data);
                if (!success && !allowFailure) {
                    assembly { revert(add(32, result), mload(result)) }
                }
            }
        }
    "#;

    // PendleMulticallV2.tryAggregateRevert shape: `address(this).delegatecall{gas:}`.
    const SELF_DELEGATE_GAS: &str = r#"
        contract MV2 {
            struct Call { address target; bytes callData; }
            function tryAggregateRevert(uint256 gasLimit, Call[] calldata calls)
                public payable returns (bytes[] memory returnData)
            {
                returnData = new bytes[](calls.length);
                for (uint256 i = 0; i < calls.length;) {
                    (, returnData[i]) = address(this).delegatecall{gas: gasLimit}(
                        abi.encodeWithSignature("callThenRevert(address,bytes)", calls[i].target, calls[i].callData)
                    );
                    unchecked { ++i; }
                }
            }
        }
    "#;

    // Immutable bound to `address(this)` in the constructor, then delegatecalled
    // (SimulateHelper.multicallRevert shape).
    const SELF_VIA_IMMUTABLE: &str = r#"
        contract SH {
            address private immutable original;
            constructor() { original = address(this); }
            function multicallRevert(uint256 gasLimit, bytes[] calldata cd) external {
                for (uint256 i = 0; i < cd.length;) {
                    original.delegatecall{gas: gasLimit}(cd[i]);
                    unchecked { ++i; }
                }
            }
        }
    "#;

    fn assert_self_call_softened(src: &str, label: &str) {
        let fs = run(src);
        let us = upg(&fs);
        // No Critical/High foreign-target finding, and no "Parity"/"foreign code" wording.
        assert!(
            !us.iter().any(|f| f.severity >= Severity::High),
            "{label}: self-delegatecall must not produce a High/Critical finding: {us:#?}"
        );
        assert!(
            !us.iter().any(|f| f.message.contains("Parity") || f.message.contains("foreign code")),
            "{label}: self-delegatecall must not carry foreign-target/Parity wording: {us:#?}"
        );
        // Whatever upgradeable findings remain are Info self-delegatecall notes.
        for f in &us {
            assert!(
                f.severity == Severity::Info && f.message.contains("self-delegatecall"),
                "{label}: unexpected non-Info upgradeable finding: {f:#?}"
            );
        }
    }

    #[test]
    fn self_multicall_is_info_or_silent() {
        assert_self_call_softened(SELF_MULTICALL, "multicall");
    }
    #[test]
    fn self_delegate_helper_is_info_or_silent() {
        assert_self_call_softened(SELF_DELEGATE_HELPER, "_delegateToSelf");
    }
    #[test]
    fn self_delegate_with_gas_is_info_or_silent() {
        assert_self_call_softened(SELF_DELEGATE_GAS, "tryAggregateRevert");
    }
    #[test]
    fn self_delegate_via_immutable_is_info_or_silent() {
        assert_self_call_softened(SELF_VIA_IMMUTABLE, "immutable-bound-to-this");
    }

    // --- (B) simulation entrypoint: a caller-supplied delegatecall target whose
    //     only non-call statement is an unconditional revert is correct to flag
    //     but must be capped below Critical. ---

    const SIMULATE: &str = r#"
        contract Sim {
            error SimulationResults(bool success, bytes result);
            function simulate(address target, bytes calldata data) external payable {
                (bool success, bytes memory result) = target.delegatecall(data);
                revert SimulationResults(success, result);
            }
        }
    "#;

    #[test]
    fn simulation_entrypoint_is_capped_below_critical() {
        let fs = run(SIMULATE);
        let us = upg(&fs);
        // It still fires (correct to flag)...
        assert!(!us.is_empty(), "simulate() should still be flagged");
        // ...but never Critical.
        assert!(
            us.iter().all(|f| f.severity < Severity::Critical),
            "simulate() must be capped below Critical: {us:#?}"
        );
        // And it is the dedicated simulate/revert finding, not the foreign-target one.
        assert!(
            us.iter().any(|f| f.title.contains("simulate/revert")),
            "expected the simulate/revert-helper finding: {us:#?}"
        );
    }

    // --- guard: a near-twin that does NOT unconditionally revert (it returns the
    //     result) is a genuine committing delegatecall and must stay Critical. ---
    const SIMULATE_BUT_RETURNS: &str = r#"
        contract NotSim {
            function run(address target, bytes calldata data) external returns (bytes memory) {
                (bool ok, bytes memory r) = target.delegatecall(data);
                require(ok);
                return r;
            }
        }
    "#;

    #[test]
    fn committing_delegatecall_with_return_stays_critical() {
        let fs = run(SIMULATE_BUT_RETURNS);
        let us = upg(&fs);
        assert!(
            us.iter().any(|f| f.title == "delegatecall to a non-constant target"
                && f.severity == Severity::Critical),
            "a returning (committing) caller-target delegatecall must stay Critical: {us:#?}"
        );
    }
}
