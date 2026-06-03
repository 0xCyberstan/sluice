//! Uniswap v4 hook returns a non-zero delta while the matching `*ReturnDelta`
//! permission bit is `false` — the PoolManager silently drops the delta.
//!
//! ## The bug
//!
//! A Uniswap v4 hook advertises which callbacks the PoolManager should invoke
//! (and, separately, whether each delta-returning callback's returned delta is
//! to be *applied*) through the `Permissions` struct it returns from
//! `getHookPermissions()`. The four delta-application bits are
//! `beforeSwapReturnDelta`, `afterSwapReturnDelta`, `afterAddLiquidityReturnDelta`
//! and `afterRemoveLiquidityReturnDelta` (`Hooks.sol:60-63`).
//!
//! When the PoolManager calls a delta-returning hook callback it routes the
//! return through `Hooks.callHookWithReturnDelta`, which opens with
//!
//! ```solidity
//! if (!parseReturn) return 0;
//! ```
//!
//! (`v4-core/src/libraries/Hooks.sol`). `parseReturn` is exactly the matching
//! `*ReturnDelta` permission bit. So if the hook *computes and returns* a
//! non-zero delta from one of these callbacks but its `getHookPermissions()`
//! literal sets the matching `*ReturnDelta` bit to `false`, the PoolManager
//! **discards** the returned delta (`return 0`). The hook's own
//! `take`/`settle`/`mint`/`burn` against the PoolManager — performed in the
//! expectation that the returned delta would balance the books — is then left
//! unsettled, breaking the hook's flash accounting (a stuck/locked pool or a
//! free-funds drain depending on the sign of the orphaned delta).
//!
//! ## Detection (precision-gated on the `Permissions` literal)
//!
//! The detector is deliberately silent unless it can *read* the hook's
//! `getHookPermissions()` `Permissions` literal — that literal is the entire
//! signal. For each contract with a `getHookPermissions()` body:
//!
//!   1. Parse the `Permissions(...)` construction into a `[Option<bool>; 14]`
//!      indexed per the struct field order at `Hooks.sol:49-64`. Two forms are
//!      supported: the named-field form `Permissions({beforeSwap: true, ...})`
//!      (field names recovered from source text, since the IR drops them) and
//!      the bare positional 14-bool form `Permissions(false, ..., true)`. If the
//!      literal is absent or cannot be parsed, the contract is skipped — **this
//!      is the key false-positive gate**: the v4 test hooks (`DeltaReturningHook`,
//!      `FeeTakingHook`, `CustomCurveHook`) return non-zero deltas but carry NO
//!      `getHookPermissions()` literal, so they never fire.
//!
//!   2. For each delta-returning callback (`beforeSwap`, `afterSwap`,
//!      `afterAddLiquidity`, `afterRemoveLiquidity`) implemented on that contract,
//!      inspect every `return` and pull the delta tuple element. The delta is
//!      "provably non-zero" when it is NOT a zero sentinel (`*.ZERO_DELTA`,
//!      `to*Delta(0,0)`, `*.wrap(0)`, a literal `0`) AND it is either a
//!      `to*Delta`/`*.wrap` of a non-literal/non-zero argument, or its provenance
//!      is `AttackerInput`/`StorageState`, or its (cast-peeled) root is a function
//!      parameter or a state variable.
//!
//!   3. Fire when a provably-non-zero return meets a literally-`false` matching
//!      `*ReturnDelta` bit. Suppressions: no literal (skip), zero-sentinel return
//!      (not a real delta), the *parent* action bit being `false` (the callback is
//!      never invoked at all → the returned delta is dead code, reported as Info
//!      rather than the High delta-drop), and library/interface contracts.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use super::prelude::*;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::Contract;

pub struct HookReturnDeltaPermissionGapDetector;

// --------------------------------------------------------------------- field order

/// The 14 `Hooks.Permissions` fields, in struct-declaration order
/// (`v4-core/src/libraries/Hooks.sol:49-64`). The index of a field here is the
/// index used for the parsed `[Option<bool>; 14]` permission vector and matches
/// the positional construction order.
const PERMISSION_FIELDS: [&str; 14] = [
    "beforeInitialize",
    "afterInitialize",
    "beforeAddLiquidity",
    "afterAddLiquidity",
    "beforeRemoveLiquidity",
    "afterRemoveLiquidity",
    "beforeSwap",
    "afterSwap",
    "beforeDonate",
    "afterDonate",
    "beforeSwapReturnDelta",
    "afterSwapReturnDelta",
    "afterAddLiquidityReturnDelta",
    "afterRemoveLiquidityReturnDelta",
];

/// A delta-returning hook callback: its name, the index into the return tuple at
/// which the delta element sits, the permission index of the *parent action* bit
/// (e.g. `afterSwap`), and the permission index of the matching `*ReturnDelta`
/// bit that must be `true` for the PoolManager to apply the returned delta.
struct DeltaCallback {
    name: &'static str,
    /// Index of the delta element within the `return (...)` tuple.
    delta_idx: usize,
    /// Permission-vector index of the parent action bit.
    action_bit: usize,
    /// Permission-vector index of the matching `*ReturnDelta` bit.
    return_delta_bit: usize,
}

/// The four delta-returning callbacks and their return-tuple / permission-bit
/// geometry:
///   * `beforeSwap`  -> `(bytes4, BeforeSwapDelta, uint24)` — delta at index 1.
///   * `afterSwap`   -> `(bytes4, int128)`                  — delta at index 1.
///   * `afterAddLiquidity`    -> `(bytes4, BalanceDelta)`   — delta at index 1.
///   * `afterRemoveLiquidity` -> `(bytes4, BalanceDelta)`   — delta at index 1.
const DELTA_CALLBACKS: [DeltaCallback; 4] = [
    DeltaCallback { name: "beforeSwap", delta_idx: 1, action_bit: 6, return_delta_bit: 10 },
    DeltaCallback { name: "afterSwap", delta_idx: 1, action_bit: 7, return_delta_bit: 11 },
    DeltaCallback { name: "afterAddLiquidity", delta_idx: 1, action_bit: 3, return_delta_bit: 12 },
    DeltaCallback {
        name: "afterRemoveLiquidity",
        delta_idx: 1,
        action_bit: 5,
        return_delta_bit: 13,
    },
];

impl Detector for HookReturnDeltaPermissionGapDetector {
    fn id(&self) -> &'static str {
        "hook-return-delta-permission-gap"
    }
    fn category(&self) -> Category {
        Category::HookReturnDeltaPermissionGap
    }
    fn description(&self) -> &'static str {
        "A Uniswap v4 hook returns a non-zero delta from a callback whose matching \
         `*ReturnDelta` permission bit is `false`, so the PoolManager silently drops the delta \
         and the hook's own settlement is left unbalanced"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let scir = cx.scir;
        let mut out = Vec::new();

        for c in scir.iter_contracts() {
            // Libraries and interfaces never host a real hook implementation with a
            // settlement to unbalance: `Hooks` (library) + `IHooks` (interface) are
            // out of scope by construction.
            if c.is_library() || c.is_interface() {
                continue;
            }

            // The `Permissions` literal in this contract's own `getHookPermissions()`
            // body is the ENTIRE signal. No literal => silent (the precision gate).
            let Some(perms) = parse_permissions_for_contract(cx, c) else {
                continue;
            };

            for cb in &DELTA_CALLBACKS {
                // The callback must be implemented on this contract (an override with
                // a body). An inherited stub / interface decl is not this contract's
                // settlement.
                let Some(f) = scir
                    .functions_of(c.id)
                    .into_iter()
                    .find(|f| f.name == cb.name && f.has_body)
                else {
                    continue;
                };

                // The matching `*ReturnDelta` bit must be *literally false*. Unknown
                // (un-parsed) or `true` is not a gap.
                if perms[cb.return_delta_bit] != Some(false) {
                    continue;
                }

                // Find a provably-non-zero returned delta in the callback body.
                let Some(delta_span) = first_nonzero_delta_return(cx, f, cb.delta_idx) else {
                    continue;
                };

                // If the PARENT action bit is also false, the PoolManager never calls
                // this callback at all — the returned delta is dead code, not a
                // live delta-drop. Report as Info (dead logic) rather than the High
                // settlement-imbalance.
                let action_false = perms[cb.action_bit] == Some(false);

                let (severity, confidence, title, body) = if action_false {
                    (
                        Severity::Info,
                        0.5,
                        "Uniswap v4 hook returns a delta from a callback its permissions disable entirely",
                        format!(
                            "`{contract}.{cb}` returns a non-zero delta, but `getHookPermissions()` sets both \
                             the `{action}` action bit AND the matching `{ret}` bit to `false`. The \
                             PoolManager never invokes `{cb}` on this hook, so the returned delta is \
                             unreachable dead code. This is most likely a stale/incorrect callback \
                             implementation; reconcile it with the declared permissions.",
                            contract = c.name,
                            cb = cb.name,
                            action = PERMISSION_FIELDS[cb.action_bit],
                            ret = PERMISSION_FIELDS[cb.return_delta_bit],
                        ),
                    )
                } else {
                    (
                        Severity::High,
                        0.78,
                        "Uniswap v4 hook returns a non-zero delta while its `*ReturnDelta` permission is false (delta silently dropped)",
                        format!(
                            "`{contract}.{cb}` computes and returns a non-zero delta, but this hook's \
                             `getHookPermissions()` declares `{ret}: false`. When the PoolManager routes \
                             the callback's return through `Hooks.callHookWithReturnDelta`, it executes \
                             `if (!parseReturn) return 0;` — and `parseReturn` is exactly the `{ret}` bit. \
                             So the returned delta is **silently discarded** while the hook's own \
                             `take`/`settle`/`mint`/`burn` against the PoolManager (issued on the \
                             assumption the delta would balance the swap/liquidity accounting) still \
                             executes. The hook's flash accounting is left unbalanced: depending on the \
                             sign of the orphaned delta the pool either locks (a stuck `settle` debt) or \
                             leaks funds (an unbacked `take`). The declared permission and the implemented \
                             return are out of sync.",
                            contract = c.name,
                            cb = cb.name,
                            ret = PERMISSION_FIELDS[cb.return_delta_bit],
                        ),
                    )
                };

                out.push(finish_at(
                    cx,
                    report!(self, Category::HookReturnDeltaPermissionGap,
                        title = title,
                        severity = severity,
                        confidence = confidence,
                        dimensions = [Dimension::Invariant, Dimension::ValueFlow],
                        message = body,
                        recommendation = format!(
                            "Set `{ret}: true` in `{contract}.getHookPermissions()` (and ensure the hook \
                             address encodes the matching `*_RETURNS_DELTA_FLAG`) so the PoolManager applies \
                             the delta `{cb}` returns — or, if the hook must not move funds here, return the \
                             zero sentinel (`{zero}`) instead of a computed delta. The set of callbacks that \
                             return a non-zero delta and the set of `*ReturnDelta` bits that are `true` must \
                             agree.",
                            contract = c.name,
                            cb = cb.name,
                            ret = PERMISSION_FIELDS[cb.return_delta_bit],
                            zero = if cb.name == "beforeSwap" {
                                "BeforeSwapDeltaLibrary.ZERO_DELTA"
                            } else if cb.name == "afterSwap" {
                                "0"
                            } else {
                                "BalanceDeltaLibrary.ZERO_DELTA"
                            },
                        ),
                    ),
                    f.id,
                    delta_span,
                ));
            }
        }

        out
    }
}

// ==================================================== Permissions-literal parsing

/// Parse the `Permissions(...)` literal in `c`'s own `getHookPermissions()` body
/// into the per-slot `[Option<bool>; 14]` (index per [`PERMISSION_FIELDS`], which
/// matches the prelude's `HOOK_PERMISSION_FIELDS`). `None` (no `getHookPermissions()`
/// body, or no parseable `Permissions(...)` literal in it) is the precision gate —
/// the caller skips the contract. The literal parsing itself is the shared
/// [`parse_hook_permissions`].
fn parse_permissions_for_contract(cx: &AnalysisContext, c: &Contract) -> Option<[Option<bool>; 14]> {
    let f = cx
        .scir
        .functions_of(c.id)
        .into_iter()
        .find(|f| f.name == "getHookPermissions" && f.has_body)?;
    parse_hook_permissions(cx, f)
}

#[cfg(test)]
mod tests {
    use crate::context::AnalysisContext;
    use crate::detector::Detector;
    use sluice_findings::{Finding, Severity};

    /// Run *only this detector* against `src`, bypassing the global registry
    /// (which is contended in the shared worktree). Mirrors the engine wiring in
    /// `analyze_sources` but with a one-element detector list.
    fn run(src: &str) -> Vec<Finding> {
        let cfg = crate::Config::default();
        let parsed = sluice_parse::parse_sources(vec![("t.sol".into(), src.into())]);
        let scir = parsed.scir;
        let dataflow = sluice_dataflow::DataflowFacts::analyze(&scir);
        let invariants = sluice_invariant::InvariantFacts::mine(&scir);
        let frontier = sluice_frontier::FrontierFacts::analyze(&scir);
        let cx = AnalysisContext::new(&scir, &dataflow, &invariants, &frontier, &cfg);
        super::HookReturnDeltaPermissionGapDetector.run(&cx)
    }

    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "hook-return-delta-permission-gap")
    }

    /// Minimal v4 hook scaffold: the `Permissions` struct shape + the delta
    /// types/constructors a hook references, so the fixtures parse standalone.
    const SCAFFOLD: &str = r#"
        type BalanceDelta is int256;
        type BeforeSwapDelta is int256;
        struct Permissions {
            bool beforeInitialize; bool afterInitialize;
            bool beforeAddLiquidity; bool afterAddLiquidity;
            bool beforeRemoveLiquidity; bool afterRemoveLiquidity;
            bool beforeSwap; bool afterSwap;
            bool beforeDonate; bool afterDonate;
            bool beforeSwapReturnDelta; bool afterSwapReturnDelta;
            bool afterAddLiquidityReturnDelta; bool afterRemoveLiquidityReturnDelta;
        }
        function toBeforeSwapDelta(int128 a, int128 b) pure returns (BeforeSwapDelta) {}
        function toBalanceDelta(int128 a, int128 b) pure returns (BalanceDelta) {}
        library BeforeSwapDeltaLibrary { BeforeSwapDelta public constant ZERO_DELTA = BeforeSwapDelta.wrap(0); }
        library BalanceDeltaLibrary { BalanceDelta public constant ZERO_DELTA = BalanceDelta.wrap(0); }
        interface IPoolManager { function take(address c, address to, uint256 a) external; }
    "#;

    fn with_scaffold(hook: &str) -> String {
        format!("{SCAFFOLD}\n{hook}")
    }

    // POSITIVE (fires_on_returndelta_without_bit): the BadHook of Spec 2.
    // `getHookPermissions` declares `afterSwap: true` but `afterSwapReturnDelta:
    // false`; `afterSwap` returns a COMPUTED non-zero delta (`int128(delta) / 100 *
    // feeBips`, derived from a storage feeBips). The PoolManager drops it.
    const BAD_HOOK: &str = r#"
        contract BadHook {
            IPoolManager public manager;
            int128 public feeBips;
            function getHookPermissions() public pure returns (Permissions memory) {
                return Permissions({
                    beforeInitialize: false, afterInitialize: false,
                    beforeAddLiquidity: false, afterAddLiquidity: false,
                    beforeRemoveLiquidity: false, afterRemoveLiquidity: false,
                    beforeSwap: false, afterSwap: true,
                    beforeDonate: false, afterDonate: false,
                    beforeSwapReturnDelta: false, afterSwapReturnDelta: false,
                    afterAddLiquidityReturnDelta: false, afterRemoveLiquidityReturnDelta: false
                });
            }
            function afterSwap(address, bytes calldata, bytes calldata, int128 delta, bytes calldata)
                external returns (bytes4, int128) {
                manager.take(address(0), address(this), 1);
                int128 hookDelta = int128(delta) / 100 * feeBips;   // computed, non-zero
                return (this.afterSwap.selector, hookDelta);
            }
        }
    "#;

    // NEGATIVE (silent_on_zero_sentinel_return): the GoodHook of Spec 2. Same
    // declaration, but `afterSwap` returns `int128(0)` — the zero sentinel — so
    // there is no delta to drop.
    const GOOD_HOOK: &str = r#"
        contract GoodHook {
            IPoolManager public manager;
            function getHookPermissions() public pure returns (Permissions memory) {
                return Permissions({
                    beforeInitialize: false, afterInitialize: false,
                    beforeAddLiquidity: false, afterAddLiquidity: false,
                    beforeRemoveLiquidity: false, afterRemoveLiquidity: false,
                    beforeSwap: false, afterSwap: true,
                    beforeDonate: false, afterDonate: false,
                    beforeSwapReturnDelta: false, afterSwapReturnDelta: false,
                    afterAddLiquidityReturnDelta: false, afterRemoveLiquidityReturnDelta: false
                });
            }
            function afterSwap(address, bytes calldata, bytes calldata, int128 delta, bytes calldata)
                external returns (bytes4, int128) {
                return (this.afterSwap.selector, int128(0));   // zero sentinel — no delta
            }
        }
    "#;

    // NEGATIVE (silent_on_no_permissions_literal): a delta-returning hook with NO
    // `getHookPermissions()` literal at all — the corpus DeltaReturningHook/
    // FeeTakingHook/CustomCurveHook shape. The precision gate: must stay silent.
    const NO_PERMISSIONS_HOOK: &str = r#"
        contract NoPermsHook {
            IPoolManager public manager;
            int128 public storedDelta;
            function afterSwap(address, bytes calldata, bytes calldata, int128 delta, bytes calldata)
                external returns (bytes4, int128) {
                manager.take(address(0), address(this), 1);
                return (this.afterSwap.selector, storedDelta);   // non-zero, but no perms literal
            }
            function beforeSwap(address, bytes calldata, bytes calldata, bytes calldata)
                external returns (bytes4, BeforeSwapDelta, uint24) {
                return (this.beforeSwap.selector, toBeforeSwapDelta(storedDelta, storedDelta), 0);
            }
        }
    "#;

    #[test]
    fn fires_on_returndelta_without_bit() {
        let src = with_scaffold(BAD_HOOK);
        let fs = run(&src);
        assert!(
            fs.iter().any(|f| f.detector == "hook-return-delta-permission-gap"
                && f.severity == Severity::High
                && f.message.contains("afterSwapReturnDelta")),
            "expected High delta-drop finding for afterSwap, got: {:#?}",
            fs
        );
    }

    #[test]
    fn silent_on_zero_sentinel_return() {
        let src = with_scaffold(GOOD_HOOK);
        assert!(!fires(&src), "zero-sentinel return must stay silent: {:#?}", run(&src));
    }

    #[test]
    fn silent_on_no_permissions_literal() {
        let src = with_scaffold(NO_PERMISSIONS_HOOK);
        assert!(
            !fires(&src),
            "a delta-returning hook with no getHookPermissions literal must stay silent (precision gate): {:#?}",
            run(&src)
        );
    }

    // Extra guard 1: same BadHook shape but the `afterSwapReturnDelta` bit is TRUE
    // (the correct declaration) — no gap, must stay silent.
    #[test]
    fn silent_when_returndelta_bit_true() {
        let hook = r#"
            contract OkHook {
                IPoolManager public manager;
                int128 public feeBips;
                function getHookPermissions() public pure returns (Permissions memory) {
                    return Permissions({
                        beforeInitialize: false, afterInitialize: false,
                        beforeAddLiquidity: false, afterAddLiquidity: false,
                        beforeRemoveLiquidity: false, afterRemoveLiquidity: false,
                        beforeSwap: false, afterSwap: true,
                        beforeDonate: false, afterDonate: false,
                        beforeSwapReturnDelta: false, afterSwapReturnDelta: true,
                        afterAddLiquidityReturnDelta: false, afterRemoveLiquidityReturnDelta: false
                    });
                }
                function afterSwap(address, bytes calldata, bytes calldata, int128 delta, bytes calldata)
                    external returns (bytes4, int128) {
                    return (this.afterSwap.selector, int128(delta) / 100 * feeBips);
                }
            }
        "#;
        assert!(!fires(&with_scaffold(hook)), "ReturnDelta=true is correct, must stay silent");
    }

    // Extra guard 2: parent action bit false AND returndelta bit false, but a
    // non-zero delta is returned => Info (dead code), NOT High.
    #[test]
    fn info_when_parent_action_bit_false() {
        let hook = r#"
            contract DeadHook {
                IPoolManager public manager;
                int128 public feeBips;
                function getHookPermissions() public pure returns (Permissions memory) {
                    return Permissions({
                        beforeInitialize: false, afterInitialize: false,
                        beforeAddLiquidity: false, afterAddLiquidity: false,
                        beforeRemoveLiquidity: false, afterRemoveLiquidity: false,
                        beforeSwap: false, afterSwap: false,
                        beforeDonate: false, afterDonate: false,
                        beforeSwapReturnDelta: false, afterSwapReturnDelta: false,
                        afterAddLiquidityReturnDelta: false, afterRemoveLiquidityReturnDelta: false
                    });
                }
                function afterSwap(address, bytes calldata, bytes calldata, int128 delta, bytes calldata)
                    external returns (bytes4, int128) {
                    return (this.afterSwap.selector, int128(delta) / 100 * feeBips);
                }
            }
        "#;
        let fs = run(&with_scaffold(hook));
        assert!(
            fs.iter().any(|f| f.detector == "hook-return-delta-permission-gap" && f.severity == Severity::Info),
            "parent-action-false must downgrade to Info dead-code, got: {:#?}",
            fs
        );
        assert!(
            !fs.iter().any(|f| f.detector == "hook-return-delta-permission-gap" && f.severity == Severity::High),
            "must NOT raise a High when the parent action bit is false: {:#?}",
            fs
        );
    }

    // Extra guard 3: the positional 14-bool form is parsed too.
    #[test]
    fn fires_on_positional_permissions_form() {
        let hook = r#"
            contract PosHook {
                IPoolManager public manager;
                int128 public feeBips;
                function getHookPermissions() public pure returns (Permissions memory) {
                    // beforeSwap (idx6)=true, afterSwap (idx7)=true, afterSwapReturnDelta (idx11)=false
                    return Permissions(false, false, false, false, false, false,
                                        true, true, false, false,
                                        false, false, false, false);
                }
                function afterSwap(address, bytes calldata, bytes calldata, int128 delta, bytes calldata)
                    external returns (bytes4, int128) {
                    return (this.afterSwap.selector, int128(delta) / 100 * feeBips);
                }
            }
        "#;
        assert!(
            fires(&with_scaffold(hook)),
            "positional Permissions(...) form must be parsed and fire: {:#?}",
            run(&with_scaffold(hook))
        );
    }
}
