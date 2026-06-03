//! Gas griefing via an uncapped low-level call in a relayer / keeper / batch
//! context (SWC-126).
//!
//! A `addr.call(...)` that forwards **all** remaining gas (no `{gas:}` stipend)
//! to an untrusted callee lets that callee grief the caller in two ways:
//!
//!   1. **Gas burn** — the callee consumes (almost) all forwarded gas, so even if
//!      its own work reverts, the relayer/keeper has already paid for it. In a
//!      meta-transaction relayer this lets a target burn the relayer's gas; in a
//!      `for`/`while` batch a single uncapped entry can drain the gas budget meant
//!      for the rest of the batch.
//!   2. **Return-bombing** — the callee returns enormous `returndata`; copying it
//!      back into the caller's memory costs the *caller* quadratic memory-expansion
//!      gas, again on the caller's dime.
//!
//! Either way the *caller* pays for the callee's behaviour. The danger is only
//! real when the gas the call burns is not the caller's own concern — i.e. the
//! caller is relaying/keeping on behalf of others (a relayer/keeper/multicall/
//! batch/process entry) or is iterating over many callees in a loop, where one
//! greedy callee harms the others.
//!
//! Precision over recall (this is a niche, low-confidence class):
//!   * A call that sets a `{gas:}` cap is **not** a finding — the cap is exactly
//!     the mitigation, so any capped call suppresses.
//!   * A call that explicitly bounds / ignores the returndata (an assembly block
//!     that uses `returndatasize`/`returndatacopy`, i.e. handles the return-bomb
//!     by hand) suppresses.
//!   * A plain single low-level call in a non-relayer function is *not* flagged:
//!     forwarding all gas to one trusted callee whose gas you are already paying
//!     for is normal and expected. The relayer/keeper/loop gate is what keeps this
//!     quiet on ordinary code.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Call, CallKind, Expr, ExprKind, Function, Lit, Span, Stmt, StmtKind};

pub struct GasGriefingDetector;

impl Detector for GasGriefingDetector {
    fn id(&self) -> &'static str {
        "gas-griefing"
    }
    fn category(&self) -> Category {
        Category::GasGriefing
    }
    fn description(&self) -> &'static str {
        "Uncapped low-level call (forwards all gas) to an untrusted callee in a relayer/keeper/batch context (gas burn / return-bomb)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // The grief costs the *caller* gas on a state-changing path; a
            // view/pure helper can be re-tried for free off-chain, and a body-less
            // declaration has nothing to analyse.
            if !f.has_body || f.is_view_or_pure() {
                continue;
            }

            // Does this function look like it relays/keeps/batches on behalf of
            // others? (relay / execute / forward / multicall / batch / process)
            let relayer_name = is_relayer_name(&f.name);
            // Spans of all low-level calls that sit lexically inside a loop body —
            // there one greedy callee can starve the rest of the batch.
            let in_loop = uncapped_calls_in_loops(f);

            // Only an uncapped low-level call in one of those two contexts is a
            // finding. A single uncapped call in an ordinary function is normal.
            if !relayer_name && in_loop.is_empty() {
                continue;
            }

            // Find every uncapped low-level call in the body (with its span), then
            // suppress capped / return-bounded ones.
            for (span, sends_value) in uncapped_low_level_calls(f) {
                // Suppress when the surrounding call expression already bounds the
                // return data by hand (assembly returndatasize/returndatacopy).
                if call_handles_returndata(cx, span) {
                    continue;
                }

                // The grief only exists if the *callee* is externally controlled.
                // A call whose target is a compile-time `constant`/`immutable`
                // state var, a bare address literal, or `address(CONST)` — e.g. an
                // EIP-7002/7251 system predeploy declared
                // `address internal constant SYS = 0x...0007002;` — is a fixed,
                // contract-controlled address. Whatever gas it consumes is the
                // protocol's own concern, not an attacker's lever, so it is not a
                // gas-griefing finding. Require a storage- or parameter-sourced
                // (mutable, non-immutable) address before flagging.
                if let Some(call) = find_call_at(f, span) {
                    if !callee_is_untrusted(cx, f, call) {
                        continue;
                    }
                }

                let looped = in_loop.contains(&span);
                // A call must be in *some* griefable context to count: either the
                // enclosing function is a relayer/keeper/batch entry, or this very
                // call is inside a loop.
                if !relayer_name && !looped {
                    continue;
                }

                // In a loop the impact is amplified (a single greedy callee bricks
                // the remaining iterations / the whole batch) → Medium; a single
                // relayer call is Low.
                let severity = if looped { Severity::Medium } else { Severity::Low };

                let mut b = FindingBuilder::new(self.id(), Category::GasGriefing)
                    .title("Uncapped low-level call forwards all gas to an untrusted callee")
                    .severity(severity)
                    .confidence(0.45)
                    .dimension(Dimension::Frontier)
                    .message(format!(
                        "`{}` makes a low-level `call` that forwards all remaining gas (no `{{gas:}}` cap) \
                         to an externally-controlled address {context}. A malicious callee can burn the \
                         forwarded gas or return an enormous `returndata` blob (a \"return bomb\"), and the \
                         {victim} pays for it — the gas-griefing class (SWC-126).",
                        f.name,
                        context = if looped {
                            "inside a loop, once per iteration"
                        } else {
                            "while relaying/executing on behalf of others"
                        },
                        victim = if looped { "rest of the batch" } else { "relayer/keeper" },
                    ))
                    .recommendation(
                        "Cap the gas forwarded to the callee with `addr.call{gas: STIPEND}(...)`, and avoid \
                         copying unbounded returndata back into memory (use assembly to read only the bytes \
                         you need, or ignore the return). In a batch, budget gas per entry so one greedy \
                         callee cannot starve the others.",
                    );
                if sends_value {
                    b = b.dimension(Dimension::ValueFlow);
                }
                out.push(cx.finish(b, f.id, span));
                // One finding per function is enough signal for this low-confidence
                // class; avoid spamming a multicall with N near-identical hits.
                break;
            }
        }
        out
    }
}

// ----------------------------------------------------------------- helpers

/// The function name suggests it relays / keeps / batches on behalf of others.
fn is_relayer_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    ["relay", "execute", "forward", "multicall", "batch", "process"]
        .iter()
        .any(|k| l.contains(k))
}

/// Every low-level call in the body that forwards all gas (no `{gas:}` cap),
/// paired with whether it also sends native value. Deduplicated by span.
fn uncapped_low_level_calls(f: &Function) -> Vec<(Span, bool)> {
    let mut out: Vec<(Span, bool)> = Vec::new();
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if let ExprKind::Call(c) = &e.kind {
                // `addr.call{...}(...)` with NO `{gas:}` clause forwards all gas.
                if c.kind == CallKind::LowLevelCall && c.gas.is_none() {
                    if !out.iter().any(|(sp, _)| *sp == e.span) {
                        out.push((e.span, c.value.is_some()));
                    }
                }
            }
        });
    }
    out
}

/// Spans of uncapped low-level calls that lie lexically inside a loop body.
fn uncapped_calls_in_loops(f: &Function) -> std::collections::HashSet<Span> {
    let mut set = std::collections::HashSet::new();
    for s in &f.body {
        s.visit(&mut |st| {
            let body: &[Stmt] = match &st.kind {
                StmtKind::While { body, .. }
                | StmtKind::For { body, .. }
                | StmtKind::DoWhile { body, .. } => body,
                _ => return,
            };
            for inner in body {
                inner.visit_exprs(&mut |e| {
                    if let ExprKind::Call(c) = &e.kind {
                        if c.kind == CallKind::LowLevelCall && c.gas.is_none() {
                            set.insert(e.span);
                        }
                    }
                });
            }
        });
    }
    set
}

/// True if the source text of the call site shows the returndata is bounded /
/// handled by hand (an assembly block reading `returndatasize` /
/// `returndatacopy`), which neutralizes the return-bomb vector. Conservative
/// substring check on the call's own span.
fn call_handles_returndata(cx: &AnalysisContext, span: Span) -> bool {
    let src = cx.source_text(span);
    src.contains("returndatasize") || src.contains("returndatacopy")
}

/// Locate the low-level [`Call`] node whose expression span equals `span` (the
/// span recorded by [`uncapped_low_level_calls`]). Lets the callee-trust gate
/// inspect the receiver without changing the existing `(Span, bool)` plumbing.
fn find_call_at(f: &Function, span: Span) -> Option<&Call> {
    let mut found: Option<&Call> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            if e.span == span {
                if let ExprKind::Call(c) = &e.kind {
                    found = Some(c);
                }
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// True when the callee of a low-level call is an *externally controlled* (and
/// therefore griefable) address: a storage- or parameter-sourced, mutable,
/// non-immutable address.
///
/// It is **not** untrusted — and so not a finding — when the target is a fixed,
/// compile-time address that the protocol itself pinned:
///   * the receiver (after stripping `address(...)`/cast wrappers) is a bare
///     address/hex literal (`0x...`), or
///   * its root identifier resolves to a `constant` or `immutable` state var of
///     the function's contract (e.g. the EIP-7002/7251 system predeploys
///     `address internal constant WITHDRAWAL_REQUEST_ADDRESS = 0x...0007002;`).
///
/// Anything else — a function parameter, a mutable storage address, or an
/// unresolved local — is treated as untrusted, so genuine relayer/loop griefing
/// (`target.call(...)` with a caller-supplied `target`) keeps firing.
fn callee_is_untrusted(cx: &AnalysisContext, f: &Function, call: &Call) -> bool {
    // No resolvable receiver (an odd shape): be conservative and keep the
    // existing behaviour (treat as a candidate).
    let Some(recv) = call.receiver.as_deref() else {
        return true;
    };
    let recv = unwrap_casts(recv);

    // A *self-call* — `address(this).call(...)` or `this.foo(...)` — is the
    // contract calling itself, not an externally-controlled party. The callee is
    // this very contract, whose gas the protocol already owns, so it cannot be an
    // attacker's griefing lever. This is the Balancer `Swaps.queryBatchSwap` shape
    // (the Gnosis query-revert trick: `address(this).call(msg.data)` in a
    // view-only `eth_call` helper), which must not be flagged.
    if receiver_is_self(recv) {
        return false;
    }

    // A bare address / hex-number literal target is a fixed predeploy-style
    // address, never attacker-controlled.
    if is_address_literal(recv) {
        return false;
    }

    // A target whose root is a compile-time `constant`/`immutable` state var is
    // contract-pinned and cannot be redirected by an attacker.
    if root_is_const_or_immutable_state_var(cx, f, recv) {
        return false;
    }

    true
}

/// Peel single-argument type casts (`address(x)`, `payable(x)`, `IERC20(x)`) so
/// the underlying callee can be inspected. Mirrors the cast-stripping used by
/// the arbitrary-transfer detector.
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

/// True if the receiver expression is `this` (the current contract), so the call
/// is a self-call. Casts have already been peeled by `unwrap_casts`, so
/// `address(this)` arrives here as the bare identifier `this`; `this.foo()`
/// arrives the same way. `solang_parser` lowers the `this` keyword to a plain
/// `Variable`/`Ident` named `"this"` (it is not modeled as a distinct node), so a
/// case-sensitive identifier match is exact.
fn receiver_is_self(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Ident(n) if n == "this")
}

/// True if the expression is a literal address (`0x...`). Solidity lexes a
/// 20-byte hex value as an `Address` literal when it checksums, otherwise as a
/// `HexNumber`; either way a literal target is a fixed, contract-chosen address.
fn is_address_literal(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Lit(Lit::Address(_)) | ExprKind::Lit(Lit::HexNumber(_)))
}

/// True if the expression's root identifier names a `constant` or `immutable`
/// state variable of the function's contract — a compile-time-fixed address that
/// an attacker cannot redirect.
fn root_is_const_or_immutable_state_var(cx: &AnalysisContext, f: &Function, e: &Expr) -> bool {
    let Some(root) = root_ident_of(e) else { return false };
    cx.contract_of(f.id)
        .map(|c| {
            c.state_vars
                .iter()
                .any(|v| v.name == root && (v.constant || v.immutable))
        })
        .unwrap_or(false)
}

/// Root identifier of an identifier/member/index chain (`a.b[c]` -> `a`).
fn root_ident_of(e: &Expr) -> Option<&str> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root_ident_of(base),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Relayer that forwards ALL gas to a caller-supplied target inside a loop. A
    // malicious target can burn the forwarded gas or return-bomb the relayer,
    // griefing the rest of the batch (SWC-126).
    const VULN: &str = r#"
        pragma solidity ^0.8.0;
        contract Relayer {
            struct Call { address to; bytes data; }
            function relayBatch(Call[] calldata calls) external {
                for (uint256 i = 0; i < calls.length; i++) {
                    (bool ok, bytes memory ret) = calls[i].to.call(calls[i].data);
                    require(ok, "call failed");
                }
            }
        }
    "#;

    // Safe: the same relayer caps the gas it forwards with `{gas:}`, so a greedy
    // callee cannot burn the relayer's whole budget.
    const SAFE: &str = r#"
        pragma solidity ^0.8.0;
        contract CappedRelayer {
            struct Call { address to; bytes data; uint256 gasLimit; }
            function relayBatch(Call[] calldata calls) external {
                for (uint256 i = 0; i < calls.length; i++) {
                    (bool ok, ) = calls[i].to.call{gas: calls[i].gasLimit}(calls[i].data);
                    require(ok, "call failed");
                }
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "gas-griefing"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "gas-griefing"));
    }

    // ------------------------------------------------------------------
    // Regression: a low-level call to a compile-time-fixed address is not an
    // *untrusted external* callee, so it must not be flagged — even in a
    // relayer/keeper context. This is the eigenlayer dogfood FP (F-009/F-010):
    // the EIP-7002/7251 system predeploys are declared
    // `address internal constant ... = 0x...` and called with
    // `SYS.call{value: fee}(data)`. The relayer-name gate (`execute`) is
    // satisfied here on purpose, so what keeps it silent is the callee-trust
    // check, not the context gate.

    // `constant` predeploy callee (the literal F-009/F-010 shape) → silent.
    const CONST_PREDEPLOY: &str = r#"
        pragma solidity ^0.8.0;
        contract Withdrawals {
            address internal constant WITHDRAWAL_REQUEST_ADDRESS =
                0x00000961Ef480Eb55e80D19ad83579A64c007002;
            function executeWithdrawal(bytes calldata data) external payable {
                uint256 fee = msg.value;
                (bool ok, ) = WITHDRAWAL_REQUEST_ADDRESS.call{value: fee}(data);
                require(ok, "predeploy call failed");
            }
        }
    "#;

    // `immutable` address callee → also contract-pinned → silent.
    const IMMUTABLE_TARGET: &str = r#"
        pragma solidity ^0.8.0;
        contract Forwarder {
            address private immutable SYSTEM;
            constructor(address s) { SYSTEM = s; }
            function forwardCall(bytes calldata data) external payable {
                (bool ok, ) = SYSTEM.call{value: msg.value}(data);
                require(ok, "forward failed");
            }
        }
    "#;

    // `address(CONST).call(...)` — the constant wrapped in a cast → silent.
    const CAST_CONST: &str = r#"
        pragma solidity ^0.8.0;
        contract Consolidations {
            address internal constant CONSOLIDATION_REQUEST_ADDRESS =
                0x0000BBdDc7CE488642fb579F8B00f3a590007251;
            function executeConsolidation(bytes calldata data) external payable {
                (bool ok, ) = address(CONSOLIDATION_REQUEST_ADDRESS).call{value: msg.value}(data);
                require(ok, "consolidation failed");
            }
        }
    "#;

    // A bare address literal callee `0x....call(...)` → fixed address → silent.
    const LITERAL_TARGET: &str = r#"
        pragma solidity ^0.8.0;
        contract LiteralRelayer {
            function executeFixed(bytes calldata data) external payable {
                (bool ok, ) = address(0x00000961Ef480Eb55e80D19ad83579A64c007002)
                    .call{value: msg.value}(data);
                require(ok, "fixed call failed");
            }
        }
    "#;

    // Positive control: an attacker-chosen `target` *parameter* (mutable, not a
    // constant/immutable) in the same relayer context still grieves the
    // relayer — this MUST stay a finding so the suppression above is precise,
    // not a blanket silencer.
    const PARAM_TARGET: &str = r#"
        pragma solidity ^0.8.0;
        contract ParamRelayer {
            function execute(address target, bytes calldata data) external payable {
                uint256 v = msg.value;
                (bool ok, ) = target.call{value: v}(data);
                require(ok, "call failed");
            }
        }
    "#;

    // Positive control: a *mutable* storage address (settable post-deploy) is
    // not compile-time-pinned, so a call to it stays a finding.
    const MUTABLE_STORAGE_TARGET: &str = r#"
        pragma solidity ^0.8.0;
        contract MutableRelayer {
            address public target;
            function setTarget(address t) external { target = t; }
            function execute(bytes calldata data) external payable {
                (bool ok, ) = target.call{value: msg.value}(data);
                require(ok, "call failed");
            }
        }
    "#;

    #[test]
    fn silent_on_constant_predeploy_callee() {
        let fs = run(CONST_PREDEPLOY);
        assert!(
            !fs.iter().any(|f| f.detector == "gas-griefing"),
            "constant predeploy callee should not be gas-griefing: {:?}",
            fs
        );
    }

    #[test]
    fn silent_on_immutable_callee() {
        let fs = run(IMMUTABLE_TARGET);
        assert!(
            !fs.iter().any(|f| f.detector == "gas-griefing"),
            "immutable address callee should not be gas-griefing: {:?}",
            fs
        );
    }

    #[test]
    fn silent_on_cast_constant_callee() {
        let fs = run(CAST_CONST);
        assert!(
            !fs.iter().any(|f| f.detector == "gas-griefing"),
            "address(CONST) callee should not be gas-griefing: {:?}",
            fs
        );
    }

    #[test]
    fn silent_on_literal_address_callee() {
        let fs = run(LITERAL_TARGET);
        assert!(
            !fs.iter().any(|f| f.detector == "gas-griefing"),
            "literal address callee should not be gas-griefing: {:?}",
            fs
        );
    }

    #[test]
    fn fires_on_param_target() {
        let fs = run(PARAM_TARGET);
        assert!(
            fs.iter().any(|f| f.detector == "gas-griefing"),
            "caller-supplied target param should still be gas-griefing: {:?}",
            fs
        );
    }

    #[test]
    fn fires_on_mutable_storage_target() {
        let fs = run(MUTABLE_STORAGE_TARGET);
        assert!(
            fs.iter().any(|f| f.detector == "gas-griefing"),
            "mutable storage target should still be gas-griefing: {:?}",
            fs
        );
    }

    // ------------------------------------------------------------------
    // Regression: a *self-call* (`address(this).call(...)` / `this.foo()`) is the
    // contract calling itself, not an untrusted external party, so it must not be
    // flagged — even though the function name (`query`...) is irrelevant and the
    // call forwards all gas. This is the Balancer `Swaps.queryBatchSwap` FP: the
    // Gnosis query-revert trick re-enters the Vault via `address(this).call(msg.data)`
    // inside an `eth_call`-only helper. The relayer-name gate is deliberately
    // satisfied (the variants below use `execute`/`batch`/`forward`) so what keeps
    // it silent is the self-call exclusion, not the context gate.

    // The literal Balancer shape: `address(this).call(msg.data)` re-dispatching the
    // same calldata in a non-view query helper. Name `queryBatchSwap` is not a
    // relayer name; this stays silent because the callee is self.
    const SELF_CALL_QUERY: &str = r#"
        pragma solidity ^0.8.0;
        contract Vault {
            function queryBatchSwap(bytes calldata) external returns (int256[] memory deltas) {
                if (msg.sender != address(this)) {
                    (bool success, ) = address(this).call(msg.data);
                    success;
                }
            }
        }
    "#;

    // Self-call under a *relayer name* (`execute`): the context gate fires, so the
    // self-call exclusion is what must keep it silent.
    const SELF_CALL_RELAYER: &str = r#"
        pragma solidity ^0.8.0;
        contract Reentrant {
            function execute(bytes calldata data) external payable {
                (bool ok, ) = address(this).call{value: msg.value}(data);
                require(ok, "self call failed");
            }
        }
    "#;

    // `this.foo()`-style self-call (no `address(...)` cast) in a relayer — also self.
    const SELF_CALL_BARE_THIS: &str = r#"
        pragma solidity ^0.8.0;
        contract Forwarder {
            function forwardSelf(bytes calldata data) external {
                (bool ok, ) = this.call(data);
                require(ok, "self forward failed");
            }
        }
    "#;

    #[test]
    fn silent_on_self_call_query_helper() {
        let fs = run(SELF_CALL_QUERY);
        assert!(
            !fs.iter().any(|f| f.detector == "gas-griefing"),
            "address(this).call self-call in a query helper must not be gas-griefing: {:?}",
            fs
        );
    }

    #[test]
    fn silent_on_self_call_in_relayer() {
        let fs = run(SELF_CALL_RELAYER);
        assert!(
            !fs.iter().any(|f| f.detector == "gas-griefing"),
            "address(this).call self-call must not be gas-griefing even under a relayer name: {:?}",
            fs
        );
    }

    #[test]
    fn silent_on_bare_this_self_call() {
        let fs = run(SELF_CALL_BARE_THIS);
        assert!(
            !fs.iter().any(|f| f.detector == "gas-griefing"),
            "`this.call(...)` self-call must not be gas-griefing: {:?}",
            fs
        );
    }
}
