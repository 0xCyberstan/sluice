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
use sluice_ir::{Contract, Expr, ExprKind, Function, Lit, ValueSource};

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
                let Some(delta_span) = first_provably_nonzero_delta(cx, f, cb.delta_idx) else {
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

/// Parse the `Permissions(...)` construction inside `c`'s own `getHookPermissions()`
/// body into a `[Option<bool>; 14]` (index per [`PERMISSION_FIELDS`]). `None` for a
/// slot means the bit could not be resolved (missing field / non-literal value);
/// callers treat `None` conservatively (never a gap). Returns `None` if the
/// contract has no `getHookPermissions()` body or no parseable `Permissions(...)`
/// literal in it — the precision gate.
fn parse_permissions_for_contract(
    cx: &AnalysisContext,
    c: &Contract,
) -> Option<[Option<bool>; 14]> {
    let f = cx
        .scir
        .functions_of(c.id)
        .into_iter()
        .find(|f| f.name == "getHookPermissions" && f.has_body)?;

    // Find the first `Permissions(...)` call in the body. `func_name` is
    // `Some("Permissions")` for both `Hooks.Permissions(...)` (member callee) and
    // a bare `Permissions(...)`.
    let mut found: Option<[Option<bool>; 14]> = None;
    for s in &f.body {
        if found.is_some() {
            break;
        }
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            let ExprKind::Call(call) = &e.kind else { return };
            if call.func_name.as_deref() != Some("Permissions") {
                return;
            }
            found = Some(parse_permissions_call(cx, e, &call.args));
        });
    }
    found
}

/// Parse one `Permissions(...)` call into the 14-slot vector. Prefers the
/// named-field form (recovering field names from the call's source text, since the
/// IR lowers `Permissions({a: x, b: y})` to positional `args` and drops the
/// names); falls back to the bare positional 14-bool form using the IR args by
/// index.
fn parse_permissions_call(cx: &AnalysisContext, call_expr: &Expr, args: &[Expr]) -> [Option<bool>; 14] {
    let text = cx.scir.span_text(call_expr.span);
    if text.contains(':') {
        parse_named_permissions(text)
    } else {
        parse_positional_permissions(args)
    }
}

/// Named-field form: scan the literal source text for `field: true|false` pairs.
/// Robust to arbitrary field ordering (Solidity allows reordering named struct
/// fields). A field whose value is not a literal `true`/`false` (or is absent)
/// stays `None`.
fn parse_named_permissions(text: &str) -> [Option<bool>; 14] {
    let mut out = [None; 14];
    for (idx, field) in PERMISSION_FIELDS.iter().enumerate() {
        if let Some(val) = field_bool(text, field) {
            out[idx] = Some(val);
        }
    }
    out
}

/// Find `field` used as a struct-literal key (`field` optionally surrounded by
/// whitespace, immediately followed by `:`) and return the literal bool that
/// follows, if any. Matches on a whole-token boundary so `afterSwap` does not
/// match inside `afterSwapReturnDelta`.
fn field_bool(text: &str, field: &str) -> Option<bool> {
    let bytes = text.as_bytes();
    let flen = field.len();
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find(field) {
        let start = search_from + rel;
        let end = start + flen;
        search_from = end;

        // Left boundary: previous non-space char must not be an identifier char,
        // so `afterSwap` does not match the tail of `XafterSwap`. (The struct-field
        // overlap `afterSwap` vs `afterSwapReturnDelta` is handled by the right
        // boundary below.)
        let left_ok = bytes[..start]
            .iter()
            .rev()
            .find(|b| !b.is_ascii_whitespace())
            .map(|b| !is_ident_byte(*b))
            .unwrap_or(true);
        if !left_ok {
            continue;
        }

        // Right boundary: skip whitespace; the field name must be followed by `:`
        // (the struct-key colon), with no further identifier characters in between
        // (so `afterSwap` followed by `ReturnDelta...` is rejected — the next char
        // is `R`, an identifier byte, not `:`).
        let mut j = end;
        // The very next char must terminate the identifier (a colon, whitespace,
        // or nothing). If it is an identifier byte, this was a prefix of a longer
        // field name — reject.
        if j < bytes.len() && is_ident_byte(bytes[j]) {
            continue;
        }
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b':' {
            continue;
        }
        j += 1; // past ':'
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        // Read the value token.
        let vstart = j;
        while j < bytes.len() && is_ident_byte(bytes[j]) {
            j += 1;
        }
        let val = &text[vstart..j];
        return match val {
            "true" => Some(true),
            "false" => Some(false),
            _ => None, // a non-literal (a variable / expression) — unknown
        };
    }
    None
}

/// Positional form `Permissions(b0, b1, ..., b13)`: read each IR arg as a literal
/// bool by index. A non-literal arg leaves that slot `None`.
fn parse_positional_permissions(args: &[Expr]) -> [Option<bool>; 14] {
    let mut out = [None; 14];
    for (i, slot) in out.iter_mut().enumerate() {
        if let Some(a) = args.get(i) {
            if let ExprKind::Lit(Lit::Bool(b)) = &a.kind {
                *slot = Some(*b);
            }
        }
    }
    out
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

// =================================================== provably-non-zero delta return

/// Span of the first `return` in `f` whose tuple element at `delta_idx` is a
/// provably-non-zero delta (per [`is_provably_nonzero_delta`]), if any.
fn first_provably_nonzero_delta(cx: &AnalysisContext, f: &Function, delta_idx: usize) -> Option<sluice_ir::Span> {
    let mut hit: Option<sluice_ir::Span> = None;
    for s in &f.body {
        s.visit(&mut |stmt| {
            if hit.is_some() {
                return;
            }
            if let sluice_ir::StmtKind::Return(Some(e)) = &stmt.kind {
                if let Some(delta) = return_delta_element(e, delta_idx) {
                    if is_provably_nonzero_delta(cx, f, delta) {
                        hit = Some(delta.span);
                    }
                }
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// The delta tuple element of a `return` expression: for a tuple `return (a, b, c)`
/// it is the element at `delta_idx`; for a single-value `return x` (a hook that
/// returns just the delta, atypical but tolerated) it is `x` when `delta_idx` is
/// the only element. Returns `None` if the element is absent.
fn return_delta_element(ret: &Expr, delta_idx: usize) -> Option<&Expr> {
    match &ret.kind {
        ExprKind::Tuple(items) => items.get(delta_idx).and_then(|o| o.as_ref()),
        // A non-tuple return only carries a delta if the delta is the sole element.
        _ if delta_idx == 0 => Some(ret),
        _ => None,
    }
}

/// Is `d` a provably non-zero hook delta?
///
///   * NOT a zero sentinel: not `*.ZERO_DELTA`, not `to*Delta(0[,0])`, not
///     `*.wrap(0)`, not a literal `0` (incl. `int128(0)` / `int256(0)`).
///   * AND positively non-zero by one of: a `to*Delta`/`*.wrap` construction whose
///     argument is non-literal or a non-zero literal; provenance ∈
///     {AttackerInput, StorageState}; or a cast-peeled root that is a function
///     parameter or a state variable of the contract.
fn is_provably_nonzero_delta(cx: &AnalysisContext, f: &Function, d: &Expr) -> bool {
    if is_zero_sentinel(d) {
        return false;
    }

    // (a) A delta constructor / `.wrap` with a non-zero / computed argument.
    if let Some(args) = delta_constructor_args(d) {
        // Non-zero iff at least one constructor argument is not a zero literal.
        if args.iter().any(|a| !is_zero_literal(peel_casts(a))) {
            return true;
        }
        // All-zero constructor args => zero delta (already handled by the sentinel
        // check for the common forms, but belt-and-suspenders here).
        return false;
    }

    // (b) Provenance-derived: attacker input or storage state flowing into the
    // returned delta is a real (non-constant) value.
    let prov = cx.provenance_of(f.id, d);
    if prov.contains(ValueSource::AttackerInput) || prov.contains(ValueSource::StorageState) {
        return true;
    }

    // (c) The delta's (cast-peeled) root is a parameter or a state variable — a
    // dynamic value, not a compile-time zero.
    if root_is_param(f, d) || root_is_state_var(cx, f, d) {
        return true;
    }

    false
}

/// True if `d` is a recognised ZERO delta sentinel:
///   * `*.ZERO_DELTA`  (the `BalanceDeltaLibrary.ZERO_DELTA` / `BeforeSwapDeltaLibrary.ZERO_DELTA` constants),
///   * `to*Delta(0)` / `to*Delta(0, 0)`,
///   * `*.wrap(0)`  (`BalanceDelta.wrap(0)` / `BeforeSwapDelta.wrap(0)`),
///   * a literal `0` (including `int128(0)` / `int256(0)` casts of `0`).
fn is_zero_sentinel(d: &Expr) -> bool {
    // `*.ZERO_DELTA`
    if let ExprKind::Member { member, .. } = &d.kind {
        if member == "ZERO_DELTA" {
            return true;
        }
    }
    // literal 0 (peeling any `int128(...)`/`int256(...)` cast)
    if is_zero_literal(peel_casts(d)) {
        return true;
    }
    // `to*Delta(...)` / `*.wrap(...)` whose every argument is a zero literal.
    if let Some(args) = delta_constructor_args(d) {
        if !args.is_empty() && args.iter().all(|a| is_zero_literal(peel_casts(a))) {
            return true;
        }
    }
    false
}

/// If `d` is a delta-constructing call — a free function `to*Delta(...)` (e.g.
/// `toBalanceDelta`, `toBeforeSwapDelta`) or a `Type.wrap(...)` — return its
/// argument list. `None` if `d` is not such a construction.
fn delta_constructor_args(d: &Expr) -> Option<&[Expr]> {
    let ExprKind::Call(call) = &d.kind else { return None };
    match call.func_name.as_deref() {
        // `toBalanceDelta(...)`, `toBeforeSwapDelta(...)`, and any `to<...>Delta`.
        Some(n) if n.starts_with("to") && n.ends_with("Delta") => Some(&call.args),
        // `BalanceDelta.wrap(x)` / `BeforeSwapDelta.wrap(x)`.
        Some("wrap") => Some(&call.args),
        _ => None,
    }
}

/// True if `e` is a literal integer `0` (decimal `0`, hex `0x0`/`0x00...`).
fn is_zero_literal(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(Lit::Number(n)) => n.trim().trim_start_matches('-').parse::<u128>() == Ok(0),
        ExprKind::Lit(Lit::HexNumber(h)) => {
            let s = h.trim().trim_start_matches("0x").trim_start_matches("0X");
            !s.is_empty() && s.bytes().all(|b| b == b'0')
        }
        _ => false,
    }
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
