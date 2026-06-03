//! Proxy / upgradeable hazards: controlled delegatecall and uninitialized
//! (UUPS) implementations.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::detectors::visit_calls;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{CallKind, Contract, ContractId, Expr, ExprKind, Function, StmtKind};
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
            // the only non-call top-level statement is an unconditional revert
            // (including an `assembly { revert(...) }` bubble-up — the
            // `StaticDelegateCallable.staticDelegateCall` shape)?
            let simulation_shape = is_simulation_revert_shape(cx, f);

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

                // (1b2) STANDARD GUARDED PROXY INIT: the delegatecall-to-a-param
                // (or mutable slot) lives in a proxy `initialize`/constructor that
                // is GUARDED against re-initialization — a one-time
                // `require(_implementation() == address(0))` / `require(!initialized)`
                // / an `initializer`/`reinitializer` modifier, or it is a plain
                // constructor (which the language already runs exactly once). This
                // is the canonical OpenZeppelin upgradeable-proxy pattern: the
                // proxy delegatecalls the *initial implementation* once at deploy.
                // delegatecall-to-a-param is what EVERY proxy does; an init-guarded
                // one is NOT a takeover primitive (the Parity bug was an UNGUARDED,
                // re-callable initializer — see (1c)). Downgrade to Low/Info.
                if is_guarded_oneshot_init(cx, f) {
                    let where_ = if f.is_constructor() {
                        "a constructor (runs once at deploy)"
                    } else {
                        "a re-init-guarded `initialize` (one-time)"
                    };
                    let b = FindingBuilder::new(self.id(), Category::DelegatecallStorage)
                        .title("delegatecall to the initial implementation in a guarded proxy initializer")
                        .severity(Severity::Low)
                        .confidence(0.4)
                        .dimension(Dimension::Frontier)
                        .message(format!(
                            "`{}` delegatecalls into `{}` from {}. This is the standard OpenZeppelin \
                             upgradeable-proxy pattern: the proxy delegatecalls its *initial implementation* \
                             exactly once, guarded against re-initialization. delegatecall-to-a-parameter is \
                             what every proxy does; because the call is one-shot and init-guarded it is NOT a \
                             re-callable takeover primitive (contrast the UNGUARDED, re-callable Parity-class \
                             initializer, which is rated Critical/High).",
                            f.name, target_root, where_
                        ))
                        .recommendation(
                            "No action required for a standard, init-guarded proxy. Ensure the re-init guard \
                             (`require(_implementation() == address(0))` / `initializer` modifier) cannot be \
                             bypassed so the implementation slot can only be set once.",
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
            // The implementation is locked if a constructor *anywhere in the
            // inheritance chain* calls `_disableInitializers()` OR carries the
            // `initializer` modifier (`constructor() initializer {}` — an equally
            // valid, common idiom). Symbiotic's `BaseDelegator`/`Vault` declare no
            // `_disableInitializers()` of their own but extend `Entity` /
            // `MigratableEntity`, whose constructors DO call it — so a
            // direct-constructor-only check false-positives on the whole family.
            let disables = chain_disables_initializers(cx, c);
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

// --------------------------------------------------- inheritance-chain helpers

/// True if a constructor *anywhere in `c`'s inheritance chain* (`c` itself plus
/// the transitive closure of its declared base contracts, resolved by name)
/// locks the implementation — by calling `_disableInitializers()` or by carrying
/// an `initializer`/`reinitializer` modifier on the constructor.
///
/// Walking the chain (not just `c`'s own constructor) is what clears the
/// Symbiotic `BaseDelegator`/`Vault`/`BaseSlasher`/`VaultTokenized` family: each
/// derived constructor delegates to a base (`Entity` / `MigratableEntity`) whose
/// constructor calls `_disableInitializers()`. A base init call always runs
/// before the derived body, so the implementation IS locked.
fn chain_disables_initializers(cx: &AnalysisContext, c: &Contract) -> bool {
    let mut seen: HashSet<ContractId> = HashSet::new();
    let mut frontier: Vec<ContractId> = vec![c.id];
    while let Some(cid) = frontier.pop() {
        if !seen.insert(cid) {
            continue;
        }
        let Some(cur) = cx.scir.contract(cid) else { continue };
        if let Some(ctor) = cx.scir.functions_of(cid).find(|f| f.is_constructor()) {
            if cx.source_text(ctor.span).contains("_disableinitializers")
                || cx.is_initializer(ctor)
                || ctor.has_modifier_like("initializer")
            {
                return true;
            }
        }
        // Resolve each declared base name to its (last-declared) contract.
        for base in &cur.bases {
            if let Some(bid) = cx.scir.contract_by_name.get(base) {
                if !seen.contains(bid) {
                    frontier.push(*bid);
                }
            }
        }
    }
    false
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

// ------------------------------------------------ guarded one-shot proxy init

/// True if `f` is a *guarded one-shot* proxy initializer or constructor — the
/// context in which a delegatecall-to-a-parameter (or mutable slot) is the
/// canonical OpenZeppelin upgradeable-proxy pattern rather than a Parity-class
/// takeover primitive.
///
/// A delegatecall target that is a constructor argument / `initialize` parameter
/// is what *every* proxy does (`new UpgradeabilityProxy(logic, data)` →
/// `logic.delegatecall(data)`); the security question is solely whether that
/// implementation slot can be set **more than once**. It is one-shot when:
///
///   * the call is in a plain **constructor** — the language guarantees it runs
///     exactly once, so the implementation can never be re-pointed via this path; or
///   * the call is in an `initialize`-style function that is **re-init-guarded**,
///     either by an `initializer`/`reinitializer` modifier
///     ([`AnalysisContext::is_initializer`]) or by a one-time sentinel
///     `require`/`if` of the OZ form — `_implementation() == address(0)` (the
///     EIP-1967 proxy idiom) or a boolean `!initialized` / `_initialized` flag.
///
/// An `initialize` with **no** such guard is the genuine Parity-class
/// re-initializable-proxy bug and is deliberately NOT matched here, so it stays
/// Critical/High in branch (1c). Likewise a generic `exec(target,data)` /
/// mutable-slot `execute` (no init name, no guard) never matches.
fn is_guarded_oneshot_init(cx: &AnalysisContext, f: &Function) -> bool {
    // A constructor delegatecalling its `_logic` argument is the immutable-proxy
    // variant (`UpgradeabilityProxy`): it can only run at deploy time.
    if f.is_constructor() {
        return true;
    }

    // Otherwise it must look like an initializer entry-point …
    let name = f.name.to_ascii_lowercase();
    let init_like = name == "initialize"
        || name.starts_with("initialize")
        || name.starts_with("__init")
        || name.starts_with("init_")
        || name == "init";
    if !init_like {
        return false;
    }

    // … AND be guarded against re-initialization.
    // (a) an `initializer` / `reinitializer` modifier.
    if cx.is_initializer(f) || f.has_modifier_like("initializer") {
        return true;
    }
    // (b) a one-time sentinel guard in the body. We match the canonical OZ
    //     proxy idioms on the comment-stripped, lowercased, whitespace-normalized
    //     source so an explicit `require(_implementation() == address(0))` or a
    //     `require(!initialized)` boolean flag both count, while a "must already
    //     be initialized" check (`!= address(0)`) does NOT (that is not a
    //     one-shot guard).
    let src: String = cx.source_text(f.span).split_whitespace().collect::<Vec<_>>().join(" ");
    let implementation_is_zero = src.contains("_implementation()")
        && (src.contains("== address(0)") || src.contains("==address(0)"));
    let initialized_flag = src.contains("!initialized")
        || src.contains("!_initialized")
        || src.contains("require(!initializing")
        || src.contains("require(!_initializing")
        || src.contains("initialized == false")
        || src.contains("initialized==false");
    implementation_is_zero || initialized_flag
}

/// True if the function body is the eth_call-only "simulate then revert" shape:
/// there is at least one top-level **unconditional** `revert(...)` and no
/// top-level `return`, branch, loop, emit, or assignment — i.e. the only
/// non-call statement is an unconditional revert. This distinguishes a
/// `simulate(target, data){ target.delegatecall(data); revert(...); }` dev helper
/// from a genuine committing `exec(target, data){ target.delegatecall(data); }`.
///
/// The mandatory revert may be expressed three ways, all recognized here:
///   * a `revert Error(...)` statement,
///   * a bare `revert(...)` builtin call expression, or
///   * an `assembly { revert(add(32, p), mload(p)) }` bubble-up block — the
///     `StaticDelegateCallable.staticDelegateCall` pattern. A Yul block whose
///     only terminator is `return(...)` is NOT a revert (it commits and returns),
///     so we check the assembly source for `revert(` specifically rather than
///     trusting the generic `has_terminator` flag.
fn is_simulation_revert_shape(cx: &AnalysisContext, f: &Function) -> bool {
    let mut has_uncond_revert = false;
    for s in &f.body {
        match &s.kind {
            // An unconditional revert: either a `revert Error(...)` statement or a
            // bare `revert(...)` builtin call expression at the top level.
            StmtKind::Revert { .. } => has_uncond_revert = true,
            StmtKind::Expr(e) if is_revert_call(e) => has_uncond_revert = true,
            // A Yul `assembly { revert(...) }` bubble-up is a mandatory revert iff
            // its terminator is a `revert` (not a committing `return`).
            StmtKind::Assembly { has_terminator: true, .. } => {
                let asm = cx.source_text(s.span);
                if asm.contains("revert(") || asm.contains("selfdestruct(") {
                    has_uncond_revert = true;
                } else {
                    // A top-level `return(...)`/other Yul terminator commits — this
                    // is not the always-reverts simulation shape.
                    return false;
                }
            }
            // Pure plumbing around the delegatecall is fine (incl. an assembly
            // block that merely reads/writes scratch without a terminator).
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

    // --- (D) Fix 2a: ancestor `_disableInitializers()`. A derived upgradeable
    //     contract whose OWN constructor omits `_disableInitializers()` but whose
    //     base constructor calls it is locked — must NOT raise the
    //     "uninitialized implementation" finding. (Symbiotic
    //     `BaseDelegator`→`Entity`, `Vault`→`MigratableEntity`.) ---
    const ANCESTOR_DISABLES: &str = r#"
        abstract contract Initializable {
            function _disableInitializers() internal {}
        }
        abstract contract Entity is Initializable {
            address public immutable FACTORY;
            constructor(address factory) {
                _disableInitializers();
                FACTORY = factory;
            }
            function initialize(bytes calldata data) external {}
        }
        contract BaseDelegator is Entity {
            address public immutable NETWORK_REGISTRY;
            constructor(address networkRegistry, address delegatorFactory) Entity(delegatorFactory) {
                NETWORK_REGISTRY = networkRegistry;
            }
        }
    "#;

    // Two levels deep: derived -> Vault -> MigratableEntity (which disables).
    const ANCESTOR_DISABLES_TWO_LEVELS: &str = r#"
        abstract contract Initializable {
            function _disableInitializers() internal {}
        }
        abstract contract MigratableEntity is Initializable {
            constructor(address factory) { _disableInitializers(); }
            function initialize(bytes calldata data) external {}
        }
        contract Vault is MigratableEntity {
            constructor(address f) MigratableEntity(f) {}
        }
        contract VaultTokenized is Vault {
            constructor(address f) Vault(f) {}
        }
    "#;

    #[test]
    fn silent_on_ancestor_disableinit() {
        for (src, label) in [(ANCESTOR_DISABLES, "BaseDelegator/Entity"), (ANCESTOR_DISABLES_TWO_LEVELS, "VaultTokenized/MigratableEntity")] {
            let fs = run(src);
            let us = upg(&fs);
            assert!(
                !us.iter().any(|f| f.title.contains("uninitialized")),
                "{label}: an ancestor-constructor `_disableInitializers()` must suppress the uninitialized-impl finding: {us:#?}"
            );
        }
    }

    // Retained TP: NO constructor anywhere in the chain disables initializers, so
    // the implementation can be initialized by anyone. (Pendle `AddressProvider`
    // has no ctor at all; `PendlePrincipalToken`'s ctor + bases never disable.) ---
    const NO_DISABLE_IN_CHAIN: &str = r#"
        abstract contract Initializable {
            function _disableInitializers() internal {}
        }
        abstract contract BoringOwnableUpgradeableV2 is Initializable {
            address public owner;
            function __BoringOwnableV2_init(address o) internal { owner = o; }
        }
        contract AddressProvider is BoringOwnableUpgradeableV2 {
            mapping(uint256 => address) public get;
            function initialize(address _owner) external { __BoringOwnableV2_init(_owner); }
        }
    "#;

    #[test]
    fn fires_on_no_disableinit_in_chain() {
        let fs = run(NO_DISABLE_IN_CHAIN);
        let us = upg(&fs);
        assert!(
            us.iter().any(|f| f.title.contains("uninitialized")),
            "an upgradeable impl whose whole chain omits `_disableInitializers()` must still fire: {us:#?}"
        );
    }

    // --- (E) Fix 2b: an `assembly { revert(...) }` bubble-up after a
    //     caller-supplied delegatecall is the eth_call simulation shape
    //     (`StaticDelegateCallable.staticDelegateCall`). It must be capped below
    //     Critical, NOT raised as the Critical foreign-target takeover. ---
    const STATIC_DELEGATE_CALL: &str = r#"
        abstract contract StaticDelegateCallable {
            function staticDelegateCall(address target, bytes calldata data) external {
                (bool success, bytes memory returndata) = target.delegatecall(data);
                bytes memory revertData = abi.encode(success, returndata);
                assembly {
                    revert(add(32, revertData), mload(revertData))
                }
            }
        }
    "#;

    #[test]
    fn silent_on_simulation_staticdelegate() {
        let fs = run(STATIC_DELEGATE_CALL);
        let us = upg(&fs);
        // It still fires (correct to flag a controllable-target delegatecall)...
        assert!(!us.is_empty(), "staticDelegateCall should still be flagged");
        // ...but the mandatory assembly-revert caps it below Critical.
        assert!(
            us.iter().all(|f| f.severity < Severity::Critical),
            "an assembly-revert simulation hook must be capped below Critical: {us:#?}"
        );
        // And it carries the simulate/revert wording, not the foreign-target one.
        assert!(
            us.iter().any(|f| f.title.contains("simulate/revert")),
            "expected the simulate/revert-helper finding for the assembly-revert hook: {us:#?}"
        );
    }

    // Guard: a near-twin whose assembly block `return(...)`s (commits) instead of
    // reverting must NOT be downgraded — it stays the Critical foreign-target.
    const ASM_RETURN_COMMITS: &str = r#"
        contract Exec {
            function run(address target, bytes calldata data) external {
                (bool ok, bytes memory r) = target.delegatecall(data);
                assembly {
                    return(add(32, r), mload(r))
                }
            }
        }
    "#;

    #[test]
    fn asm_return_commit_stays_critical() {
        let fs = run(ASM_RETURN_COMMITS);
        let us = upg(&fs);
        assert!(
            us.iter().any(|f| f.title == "delegatecall to a non-constant target"
                && f.severity == Severity::Critical),
            "an assembly `return` (committing) caller-target delegatecall must stay Critical: {us:#?}"
        );
    }

    // --- (F) STANDARD GUARDED PROXY INIT: the canonical OpenZeppelin
    //     upgradeable-proxy pattern — `initialize(address _logic, bytes _data)`
    //     guarded by `require(_implementation() == address(0))`, delegatecalling
    //     the initial implementation once at deploy. delegatecall-to-a-param is
    //     what every proxy does; an init-guarded one is NOT a takeover primitive,
    //     so it must be DOWNGRADED to Low/Info (not Critical). This is the exact
    //     Aave-v3 `InitializableUpgradeabilityProxy` false positive being fixed. ---
    const OZ_INIT_PROXY: &str = r#"
        contract InitializableUpgradeabilityProxy {
            function _implementation() internal view returns (address impl) {}
            function _setImplementation(address) internal {}
            function initialize(address _logic, bytes memory _data) public payable {
                require(_implementation() == address(0));
                _setImplementation(_logic);
                if (_data.length > 0) {
                    (bool success, ) = _logic.delegatecall(_data);
                    require(success);
                }
            }
        }
    "#;

    // The immutable-proxy variant: same delegatecall, but in a CONSTRUCTOR (runs
    // exactly once at deploy by language semantics — Aave `UpgradeabilityProxy`).
    const OZ_CTOR_PROXY: &str = r#"
        contract UpgradeabilityProxy {
            function _setImplementation(address) internal {}
            constructor(address _logic, bytes memory _data) payable {
                _setImplementation(_logic);
                if (_data.length > 0) {
                    (bool success, ) = _logic.delegatecall(_data);
                    require(success);
                }
            }
        }
    "#;

    // Guarded by an `initializer` modifier instead of the `_implementation()==0`
    // sentinel (OZ `ERC1967Upgrade._upgradeToAndCallUUPS` style init).
    const MODIFIER_GUARDED_INIT: &str = r#"
        contract P {
            bool private _initialized;
            modifier initializer() { require(!_initialized); _initialized = true; _; }
            function initialize(address _logic, bytes calldata _data) external initializer {
                (bool ok, ) = _logic.delegatecall(_data);
                require(ok);
            }
        }
    "#;

    // Guarded by an explicit boolean one-shot flag in the body.
    const FLAG_GUARDED_INIT: &str = r#"
        contract P {
            bool public initialized;
            function initialize(address _logic, bytes calldata _data) external {
                require(!initialized, "init");
                initialized = true;
                (bool ok, ) = _logic.delegatecall(_data);
                require(ok);
            }
        }
    "#;

    fn assert_guarded_proxy_init_downgraded(src: &str, label: &str) {
        let fs = run(src);
        let us = upg(&fs);
        // It still surfaces (so a reviewer sees the proxy delegatecall)…
        assert!(!us.is_empty(), "{label}: guarded proxy init should still surface a (low) note");
        // …but never as Critical/High, and never with the Parity foreign-target
        // takeover wording.
        assert!(
            us.iter().all(|f| f.severity <= Severity::Low),
            "{label}: a guarded one-shot proxy initializer must be downgraded to Low/Info: {us:#?}"
        );
        assert!(
            !us.iter().any(|f| f.message.contains("takeover primitive (Parity class)")),
            "{label}: a guarded proxy init must not carry the Parity-takeover wording: {us:#?}"
        );
        assert!(
            us.iter().any(|f| f.title.contains("guarded proxy initializer")),
            "{label}: expected the guarded-proxy-initializer finding: {us:#?}"
        );
    }

    #[test]
    fn oz_initializable_proxy_is_downgraded() {
        assert_guarded_proxy_init_downgraded(OZ_INIT_PROXY, "InitializableUpgradeabilityProxy");
    }
    #[test]
    fn oz_constructor_proxy_is_downgraded() {
        assert_guarded_proxy_init_downgraded(OZ_CTOR_PROXY, "UpgradeabilityProxy(ctor)");
    }
    #[test]
    fn modifier_guarded_init_is_downgraded() {
        assert_guarded_proxy_init_downgraded(MODIFIER_GUARDED_INIT, "initializer-modifier");
    }
    #[test]
    fn flag_guarded_init_is_downgraded() {
        assert_guarded_proxy_init_downgraded(FLAG_GUARDED_INIT, "boolean-flag-guard");
    }

    // --- (G) HARD RECALL GUARD: an UNGUARDED, re-callable `initialize` that
    //     delegatecalls a parameter is the GENUINE Parity-class
    //     re-initializable-proxy takeover (anyone can re-point the implementation
    //     and run arbitrary code in this contract's storage). It must STAY
    //     Critical — the downgrade above must not leak onto it. ---
    const UNGUARDED_REINIT_PROXY: &str = r#"
        contract P {
            function initialize(address _logic, bytes calldata _data) external {
                (bool ok, ) = _logic.delegatecall(_data);
                require(ok);
            }
        }
    "#;

    #[test]
    fn unguarded_reinit_proxy_stays_critical() {
        let fs = run(UNGUARDED_REINIT_PROXY);
        let us = upg(&fs);
        assert!(
            us.iter().any(|f| f.title == "delegatecall to a non-constant target"
                && f.severity == Severity::Critical),
            "an UNGUARDED re-callable initialize() that delegatecalls a param is the Parity-class \
             takeover and must stay Critical: {us:#?}"
        );
        // It must NOT be softened to the guarded-proxy note.
        assert!(
            !us.iter().any(|f| f.title.contains("guarded proxy initializer")),
            "an unguarded re-init proxy must not be treated as a guarded one-shot init: {us:#?}"
        );
    }

    // A guard that requires the implementation to be ALREADY set (`!= address(0)`)
    // is NOT a one-shot init guard — it must not trigger the downgrade.
    const NOT_A_ONESHOT_GUARD: &str = r#"
        contract P {
            function _implementation() internal view returns (address) {}
            function initialize(address _logic, bytes calldata _data) external {
                require(_implementation() != address(0));
                (bool ok, ) = _logic.delegatecall(_data);
                require(ok);
            }
        }
    "#;

    #[test]
    fn not_a_oneshot_guard_stays_critical() {
        let fs = run(NOT_A_ONESHOT_GUARD);
        let us = upg(&fs);
        assert!(
            us.iter().any(|f| f.title == "delegatecall to a non-constant target"
                && f.severity == Severity::Critical),
            "a `!= address(0)` (must-already-be-initialized) guard is not a one-shot guard; \
             the delegatecall must stay Critical: {us:#?}"
        );
    }
}
