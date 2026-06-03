//! Silenced privileged callback — a privileged state-changing function makes a
//! **fire-and-forget** low-level call to a *settable hook* and then finalizes
//! accounting state regardless of whether that call succeeded.
//!
//! Restaking / slashing cores delegate a side-effect (burn the slashed stake,
//! notify a delegator hook, forward to a receiver) to an address the protocol
//! lets governance *change* — a `burner`, `hook`, or `receiver` reached through a
//! mutable state variable. The danger is the combination of two choices:
//!
//!   1. the call is **fire-and-forget**: its return value is never inspected.
//!      Two concrete forms exist and both are matched here:
//!        * a source-level `hook.call(data);` with no `(bool ok, )` capture (the
//!          IR records `CallSite{ kind: LowLevelCall, return_checked: false }`);
//!        * the **assembly** analog `pop(call(GAS, hook_, 0, ...))`, where the
//!          return word is *explicitly discarded* by `pop`. Inline assembly is
//!          summarized in the IR as `StmtKind::Assembly { has_call, .. }` and
//!          never produces a `CallSite`, so this form is recovered by scanning
//!          the assembly block's source text; and
//!   2. the surrounding slash/burn flow then **finalizes accounting** — a
//!      storage write or an `emit` — that is **not contingent** on the call
//!      having succeeded.
//!
//! So a hook that silently reverts, runs out of gas, or simply no-ops still lets
//! the protocol record the action as done: the slash is booked
//! (`cumulativeSlash += amount`), the event is emitted, the round advances — but
//! the value was never actually burned/forwarded. This is exactly the shape of
//! Symbiotic Core `BaseDelegator.onSlash` (`pop(call(HOOK_GAS_LIMIT, hook_, ...))`
//! to the governance-set `hook`, then `emit OnSlash`) and
//! `BaseSlasher._burnerOnSlash` (`pop(call(BURNER_GAS_LIMIT, burner, ...))` to the
//! vault's burner, whose enclosing `slash` / `executeSlash` has already booked the
//! `cumulativeSlash` and emits the completion event).
//!
//! Why a *settable* hook is the precision anchor: if the callee is `constant` or
//! `immutable`, governance cannot point it at a misbehaving contract, and a fixed
//! system address that reverts is the protocol's own (auditable) problem, not a
//! silently-absorbed failure of an attacker- or governance-controlled endpoint.
//! The interesting bug is the *mutable* hook whose failure is swallowed.
//!
//! Precision anchors:
//!   * **fire-and-forget** — for the source form, a `LowLevelCall` whose
//!     `return_checked == false`; for the assembly form, the discard is made
//!     syntactically explicit by `pop(call(...))`. A captured
//!     `(bool ok, ) = hook.call(...)` is *not* flagged even if `ok` is ignored,
//!     because the value is at least observable;
//!   * the call **target** root-resolves to a state variable of the contract that
//!     is **neither `constant` nor `immutable`** (a settable hook/burner/receiver).
//!     For the assembly form the call operand is usually a *local* copied from the
//!     hook (`address hook_ = hook;`) or fetched through a settable handle
//!     (`address burner = IVault(vault).burner();`), so the operand is resolved
//!     back through the function's locals to a settable state var. A literal
//!     address, a `constant`/`immutable` callee, or an operand that touches no
//!     settable state var all suppress;
//!   * for the **source** form the function must additionally **finalize state
//!     after** the call (a later storage write, or a lexically-later `emit`),
//!     because a bare best-effort `hook.call(...)` with no dependent post-call
//!     invariant is ordinary code. The explicit `pop(call(...))` discard of a
//!     *privileged, mutable-target* hook return is itself the deliberate-silencing
//!     signal and does not need a same-function finalization (in Symbiotic the
//!     `_burnerOnSlash` helper's accounting is finalized by its callers).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{CallKind, Contract, Function, Span, StmtKind};

use super::prelude::*;

pub struct SilencedPrivilegedCallbackDetector;

impl Detector for SilencedPrivilegedCallbackDetector {
    fn id(&self) -> &'static str {
        "silenced-privileged-callback"
    }
    fn category(&self) -> Category {
        Category::SilencedPrivilegedCallback
    }
    fn description(&self) -> &'static str {
        "Privileged function makes a fire-and-forget low-level call (source `hook.call(...)` or assembly `pop(call(...))`) to a settable hook, then finalizes accounting regardless of the call's success (Symbiotic onSlash/_burnerOnSlash class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // The bug is about *finalizing state* after a swallowed call, so the
            // function must be able to write state. A `view`/`pure` helper books
            // nothing, and a body-less declaration has nothing to analyse.
            if !f.has_body || f.is_view_or_pure() {
                continue;
            }
            // Resolve the contract once so we can classify the call target as a
            // settable hook (a mutable, non-constant/immutable state var).
            let Some(contract) = cx.contract_of(f.id) else { continue };
            // Interfaces / pure declarations have no concrete callback to silence.
            if contract.is_interface() {
                continue;
            }

            // --- Path B: assembly `pop(call(...))` to a settable hook --------
            // Recovered by scanning assembly text because inline asm produces no
            // CallSite. This is the true Symbiotic shape and is reported first.
            if let Some(hit) = first_silenced_asm_call(cx, f, contract) {
                out.push(self.finding(cx, f, &hit, true));
                continue;
            }

            // --- Path A: source-level fire-and-forget `hook.call(...)` -------
            let Some(hit) = first_silenced_hook_call(f, contract) else { continue };

            // For the source form the precision anchor is: state is finalized
            // AFTER that call (a later storage write, or a lexically-later emit).
            // A best-effort notification with no dependent post-call accounting is
            // NOT a finding. (The assembly `pop(call)` form needs no such anchor —
            // the explicit `pop` discard is itself the deliberate silencing.)
            let writes_after = f.effects.storage_writes.iter().any(|w| w.order > hit.order);
            let emits_after = emit_after_span(f, hit.span);
            if !writes_after && !emits_after {
                continue;
            }

            out.push(self.finding(cx, f, &hit, writes_after || emits_after));
        }
        out
    }
}

impl SilencedPrivilegedCallbackDetector {
    fn finding(&self, cx: &AnalysisContext, f: &Function, hit: &SilencedCall, finalized: bool) -> Finding {
        let how = if hit.is_assembly {
            "via the assembly analog `pop(call(...))`, which explicitly discards the call's return word"
        } else {
            "with no `(bool ok, )` capture of the call's return value"
        };
        let tail = if finalized {
            " It then finalizes accounting (a storage write or a completion event) that does not depend on the call \
             succeeding."
        } else if hit.is_assembly {
            " The slash/burn flow that drives this helper books the action and emits the completion event regardless \
             of whether the call succeeded."
        } else {
            ""
        };
        let b = report!(self, Category::SilencedPrivilegedCallback,
            title = "Fire-and-forget privileged callback to a settable hook, then state is finalized regardless",
            severity = Severity::Medium,
            confidence = 0.5,
            dimensions = [Dimension::Frontier],
            message = format!(
                "`{}` makes a fire-and-forget low-level call to `{}` — a settable hook reached through the \
                 mutable state variable `{}` (not `constant`/`immutable`) — {how}.{tail} A hook that silently \
                 reverts, runs out of gas, or no-ops still lets the protocol record the action as completed: the \
                 side-effect (burn / forward / notify) never happened, yet the accounting says it did. This is the \
                 Symbiotic Core `BaseDelegator.onSlash` / `BaseSlasher._burnerOnSlash` swallowed-callback shape.",
                f.name, hit.target, hit.root,
            ),
            recommendation =
                "Capture and check the callback result before finalizing — `(bool ok, ) = hook.call(data); \
                 require(ok);` (or check the returned status word of the assembly `call` instead of `pop`-ing it) — \
                 so a failed hook reverts the whole privileged action instead of being booked as done. If the call \
                 is intentionally best-effort, do not write accounting state or emit a completion event on the \
                 strength of it; record the outcome so off-chain consumers can reconcile, and prefer a fixed \
                 (`immutable`) or vetted callback target.",
        );
        finish_at(cx, b, f.id, hit.span)
    }
}

// ----------------------------------------------------------------- helpers

/// A matched fire-and-forget low-level call to a settable hook.
struct SilencedCall {
    /// Textual call target (`burner`, `delegator.hook`, or the Yul operand `hook_`).
    target: String,
    /// Root state-var name the target ultimately resolves to (`hook`, `vault`).
    root: String,
    /// Sequential effect order of the call (shared with storage writes). For the
    /// assembly form this is unused (set to `u32::MAX`).
    order: u32,
    /// Source span of the call site (the assembly block, for the asm form).
    span: Span,
    /// True when recovered from an assembly `pop(call(...))` block.
    is_assembly: bool,
}

/// The first `LowLevelCall` whose return is **not** checked and whose target
/// root-resolves to a *settable* (non-constant/immutable) state-var hook.
fn first_silenced_hook_call(f: &Function, contract: &Contract) -> Option<SilencedCall> {
    f.effects
        .call_sites
        .iter()
        .filter(|cs| cs.kind == CallKind::LowLevelCall && !cs.return_checked)
        .find_map(|cs| {
            let root = root_of_target(&cs.target);
            if !is_settable_state_var(contract, root) {
                return None;
            }
            Some(SilencedCall {
                target: cs.target.clone(),
                root: root.to_string(),
                order: cs.order,
                span: cs.span,
                is_assembly: false,
            })
        })
}

/// The first inline-assembly block in `f` that does `pop(call(...))` (the return
/// word is explicitly discarded) where the `call`'s address operand resolves to a
/// *settable* hook. This is the real Symbiotic `BaseDelegator.onSlash` /
/// `BaseSlasher._burnerOnSlash` shape, which lives in `assembly ("memory-safe")`
/// and therefore never surfaces as a `CallSite`.
fn first_silenced_asm_call(cx: &AnalysisContext, f: &Function, contract: &Contract) -> Option<SilencedCall> {
    let mut found: Option<SilencedCall> = None;
    for top in &f.body {
        top.visit(&mut |st| {
            if found.is_some() {
                return;
            }
            // Only inline-assembly statements that actually contain a call.
            if !matches!(&st.kind, StmtKind::Assembly { has_call: true, .. }) {
                return;
            }
            // Comment-stripped, lowercased text of the whole `assembly { ... }` block.
            let text = cx.source_text(st.span);
            // The return word must be discarded by `pop` wrapping the call: the
            // deliberate-silencing signal. Match `pop(...call(...))` with optional
            // intervening whitespace. We accept `call`/`delegatecall`/`staticcall`.
            let Some(target_op) = pop_call_target_operand(&text) else { return };
            // Resolve the Yul operand (usually a local copied from / fetched
            // through a settable hook) back to a settable state var.
            let Some(root) = resolve_settable_root(contract, f, cx, &target_op) else { return };
            found = Some(SilencedCall {
                target: target_op,
                root,
                order: u32::MAX,
                span: st.span,
                is_assembly: true,
            });
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// If `text` (lowercased) contains a `pop(...call(...))` where the discarded
/// expression *is* the call (the return word is thrown away), return the call's
/// **address operand** — the 2nd Yul argument of `call`/`callcode`
/// (`call(gas, addr, value, inP, inSz, outP, outSz)`) or the 2nd of
/// `delegatecall`/`staticcall` (`(gas, addr, inP, inSz, outP, outSz)`). The
/// operand position (index 1) is the same for all four.
fn pop_call_target_operand(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find("pop(") {
        let open = search_from + rel + 3; // index of '(' after "pop"
        // Find the matching ')' for this pop(, scanning balanced parens.
        let Some(close) = matching_paren(bytes, open) else {
            search_from = open + 1;
            continue;
        };
        let inner = text[open + 1..close].trim();
        // The discarded expression must itself be a call: `call(...)`,
        // `delegatecall(...)`, `staticcall(...)`, or `callcode(...)`.
        if let Some(op) = call_second_operand(inner) {
            return Some(op);
        }
        search_from = open + 1;
    }
    None
}

/// If `expr` (trimmed) is exactly one of the Yul external-call ops applied to an
/// argument list, return its 2nd argument (the address operand), trimmed. The
/// keyword order matters: `delegatecall`/`staticcall`/`callcode` must be tried
/// before the `call` prefix so the longer ops are not mis-split.
fn call_second_operand(expr: &str) -> Option<String> {
    let e = expr.trim();
    for kw in ["delegatecall", "staticcall", "callcode", "call"] {
        let Some(after_kw) = e.strip_prefix(kw) else { continue };
        let after_kw = after_kw.trim_start();
        if !after_kw.starts_with('(') {
            continue;
        }
        // Balanced span of the call's argument list, then split at top level.
        let close = matching_paren(after_kw.as_bytes(), 0)?;
        let inner = &after_kw[1..close];
        let parts = split_top_level_commas(inner);
        return parts.get(1).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    }
    None
}

/// Index of the `)` matching the `(` at `open` (which must be `b'('`). Returns
/// `None` if unbalanced. Operates on raw bytes (assembly bodies are ASCII Yul).
fn matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let mut depth = 0i32;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Split `s` on commas that are at paren-depth 0.
fn split_top_level_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                out.push(s[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(s[start..].to_string());
    out
}

/// Resolve a Yul call operand (`operand`, lowercased) to the name of a *settable*
/// hook state variable, if it ultimately reaches one.
///
/// Three resolution steps, each conservative:
///   1. the operand directly names a settable state var (e.g. `pop(call(.., hook, ..))`);
///   2. the operand names a function-local whose **initializer** mentions a
///      settable state var (`address hook_ = hook;` →`hook`; or
///      `address burner = IVault(vault).burner();` → `vault`). The hook value is
///      copied into a local before the asm block in both Symbiotic functions;
///   3. nothing matches → not a settable hook (suppress).
fn resolve_settable_root(contract: &Contract, f: &Function, cx: &AnalysisContext, operand: &str) -> Option<String> {
    let op = operand.trim();
    // Operand may be a path (rare in Yul) — take the leading identifier.
    let op_root = root_of_target(op);
    if op_root.is_empty() {
        return None;
    }
    // (1) direct settable state var.
    if is_settable_state_var(contract, op_root) {
        return Some(op_root.to_string());
    }
    // (2) a local var of this name whose initializer touches a settable state var.
    if let Some(root) = settable_var_via_local(contract, f, cx, op_root) {
        return Some(root);
    }
    None
}

/// If `f` declares a local variable named `local_name` whose initializer's source
/// text references a settable state var of `contract`, return that state var name.
/// This connects the Yul operand (`hook_`, `burner`) to the settable hook it was
/// copied from / fetched through.
fn settable_var_via_local(
    contract: &Contract,
    f: &Function,
    cx: &AnalysisContext,
    local_name: &str,
) -> Option<String> {
    let mut hit: Option<String> = None;
    for top in &f.body {
        top.visit(&mut |st| {
            if hit.is_some() {
                return;
            }
            if let StmtKind::VarDecl { name: Some(n), init: Some(init), .. } = &st.kind {
                if n == local_name {
                    // Initializer source text, comment-stripped + lowercased.
                    let init_text = cx.source_text(init.span);
                    if let Some(root) = settable_var_mentioned(contract, &init_text) {
                        hit = Some(root);
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

/// Return the name of any *settable* state var of `contract` that appears as a
/// whole-word identifier in `text` (lowercased). Used to decide whether a local's
/// initializer derives from a mutable hook. Constant/immutable vars never qualify.
fn settable_var_mentioned(contract: &Contract, text: &str) -> Option<String> {
    contract
        .state_vars
        .iter()
        .filter(|v| !(v.constant || v.immutable))
        .map(|v| v.name.as_str())
        .filter(|name| !name.is_empty())
        .find(|name| word_present(text, &name.to_ascii_lowercase()))
        .map(|s| s.to_string())
}

/// Whole-word (identifier-boundary) containment test: `needle` appears in `hay`
/// not flanked by identifier characters (so `vault` does not match `vaults` or
/// `myvault`). `hay` is already lowercased; `needle` must be too.
fn word_present(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let hb = hay.as_bytes();
    let nb = needle.as_bytes();
    let is_id = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'$';
    let mut from = 0usize;
    while let Some(rel) = hay[from..].find(needle) {
        let i = from + rel;
        let before_ok = i == 0 || !is_id(hb[i - 1]);
        let after = i + nb.len();
        let after_ok = after >= hb.len() || !is_id(hb[after]);
        if before_ok && after_ok {
            return true;
        }
        from = i + 1;
    }
    false
}

/// Root identifier of a textual call target. `CallSite.target` is the rendered
/// receiver text (`ir_text`), so `burner` -> `burner`, `delegator.hook` ->
/// `delegator`, `hooks[i]` -> `hooks`. We split on the first member/index/call
/// boundary and trim.
fn root_of_target(target: &str) -> &str {
    let t = target.trim();
    let end = t
        .find(|c: char| c == '.' || c == '[' || c == '(' || c.is_whitespace())
        .unwrap_or(t.len());
    t[..end].trim()
}

/// True if an `emit` statement begins lexically after the call at `call_span`
/// (i.e. `emit.span.start >= call_span.end`, same file). Used as the secondary
/// "state finalized after the call" signal when there is no storage write.
fn emit_after_span(f: &Function, call_span: Span) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit(&mut |st| {
            if found {
                return;
            }
            if matches!(st.kind, StmtKind::Emit(_))
                && st.span.file == call_span.file
                && st.span.start >= call_span.end
            {
                found = true;
            }
        });
        if found {
            break;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "silenced-privileged-callback")
    }

    // Symbiotic onSlash / _burnerOnSlash shape: a privileged slash handler makes
    // a FIRE-AND-FORGET low-level call to a *settable* burner (a mutable state var
    // governance can repoint), ignores the result, and then BOOKS the slash
    // (`cumulativeSlash += amount`) regardless. A burner that silently reverts
    // still leaves the slash recorded as done while nothing was burned.
    const VULN: &str = r#"
        pragma solidity ^0.8.0;
        contract BaseSlasher {
            address public burner;             // settable hook (not immutable)
            uint256 public cumulativeSlash;
            event Slashed(uint256 amount);
            function setBurner(address b) external { burner = b; }
            function onSlash(uint256 amount, bytes calldata data) external {
                // fire-and-forget: return value is discarded (pop(call(...)) analog)
                burner.call(abi.encodeWithSignature("onSlash(uint256,bytes)", amount, data));
                // accounting is finalized regardless of whether the burn happened
                cumulativeSlash += amount;
                emit Slashed(amount);
            }
        }
    "#;

    // The REAL Symbiotic `BaseDelegator.onSlash` shape: the hook is copied into a
    // local and the low-level call lives inside `assembly` with its return word
    // discarded by `pop`. Accounting (`emit OnSlash`) is finalized afterwards.
    const VULN_ASM_HOOK: &str = r#"
        pragma solidity ^0.8.0;
        interface IDelegatorHook { function onSlash(uint256 a) external; }
        contract BaseDelegator {
            address public hook;               // settable, not immutable
            uint256 public constant HOOK_GAS_LIMIT = 250000;
            event OnSlash(uint256 amount);
            function setHook(address h) external { hook = h; }
            function onSlash(uint256 amount, bytes memory data) external {
                address hook_ = hook;
                if (hook_ != address(0)) {
                    bytes memory calldata_ = abi.encodeCall(IDelegatorHook.onSlash, (amount));
                    assembly ("memory-safe") {
                        pop(call(HOOK_GAS_LIMIT, hook_, 0, add(calldata_, 0x20), mload(calldata_), 0, 0))
                    }
                }
                emit OnSlash(amount);
            }
        }
    "#;

    // The REAL Symbiotic `BaseSlasher._burnerOnSlash` shape: the burner is fetched
    // through a SETTABLE handle (`IVault(vault).burner()`) into a local, and the
    // assembly `call` to it is `pop`-discarded. The helper itself finalizes nothing
    // (its callers book the slash), so this must fire WITHOUT a same-function
    // finalization purely on the `pop(call(settable))` shape.
    const VULN_ASM_BURNER: &str = r#"
        pragma solidity ^0.8.0;
        interface IVault { function burner() external view returns (address); }
        interface IBurner { function onSlash(uint256 a) external; }
        contract BaseSlasher {
            address public vault;              // settable handle
            bool public isBurnerHook;
            uint256 public constant BURNER_GAS_LIMIT = 150000;
            function _burnerOnSlash(uint256 amount) internal {
                if (isBurnerHook) {
                    address burner = IVault(vault).burner();
                    bytes memory calldata_ = abi.encodeCall(IBurner.onSlash, (amount));
                    assembly ("memory-safe") {
                        pop(call(BURNER_GAS_LIMIT, burner, 0, add(calldata_, 0x20), mload(calldata_), 0, 0))
                    }
                }
            }
        }
    "#;

    // Safe: the callback result is captured and required before the slash is
    // booked, so a reverting burner reverts the whole action. return_checked == true.
    const SAFE_RETURN_CHECKED: &str = r#"
        pragma solidity ^0.8.0;
        contract CheckedSlasher {
            address public burner;
            uint256 public cumulativeSlash;
            function setBurner(address b) external { burner = b; }
            function onSlash(uint256 amount, bytes calldata data) external {
                (bool ok, ) = burner.call(abi.encodeWithSignature("onSlash(uint256,bytes)", amount, data));
                require(ok, "burn failed");
                cumulativeSlash += amount;
            }
        }
    "#;

    // Safe: the burner is `immutable`, so governance cannot point it at a
    // misbehaving contract — a fixed callee that reverts is the protocol's own
    // (auditable) problem, not a silently-settable hook. Not a finding.
    const SAFE_IMMUTABLE_BURNER: &str = r#"
        pragma solidity ^0.8.0;
        contract ImmutableSlasher {
            address public immutable burner;
            uint256 public cumulativeSlash;
            constructor(address b) { burner = b; }
            function onSlash(uint256 amount, bytes calldata data) external {
                burner.call(abi.encodeWithSignature("onSlash(uint256,bytes)", amount, data));
                cumulativeSlash += amount;
            }
        }
    "#;

    // Safe (assembly): the call operand is an `immutable` callee copied into a
    // local. Even though the return is `pop`-discarded, governance cannot repoint
    // it, so it is not a silenced *settable* hook.
    const SAFE_ASM_IMMUTABLE: &str = r#"
        pragma solidity ^0.8.0;
        contract Fixed {
            address public immutable SINK;
            uint256 public constant GAS = 150000;
            event Done(uint256 a);
            constructor(address s) { SINK = s; }
            function onSlash(uint256 amount, bytes memory data) external {
                address sink_ = SINK;
                assembly ("memory-safe") {
                    pop(call(GAS, sink_, 0, add(data, 0x20), mload(data), 0, 0))
                }
                emit Done(amount);
            }
        }
    "#;

    // Safe (assembly): the `call`'s return IS captured (`let ok := call(...)`) and
    // checked, not `pop`-discarded — so this is not the fire-and-forget shape.
    const SAFE_ASM_RETURN_CHECKED: &str = r#"
        pragma solidity ^0.8.0;
        contract Checked {
            address public hook;
            uint256 public constant GAS = 150000;
            event Done();
            function setHook(address h) external { hook = h; }
            function onSlash(bytes memory data) external {
                address hook_ = hook;
                assembly ("memory-safe") {
                    let ok := call(GAS, hook_, 0, add(data, 0x20), mload(data), 0, 0)
                    if iszero(ok) { revert(0, 0) }
                }
                emit Done();
            }
        }
    "#;

    // Safe (assembly): the `pop(call(...))` operand is a function PARAMETER copied
    // into a local — not a settable contract state var. A caller-supplied target
    // is a different concern; this detector targets *governance-settable* hooks.
    const SAFE_ASM_PARAM_TARGET: &str = r#"
        pragma solidity ^0.8.0;
        contract Forwarder {
            event Done();
            function forward(address to, bytes memory data) external {
                address to_ = to;
                assembly ("memory-safe") {
                    pop(call(gas(), to_, 0, add(data, 0x20), mload(data), 0, 0))
                }
                emit Done();
            }
        }
    "#;

    // Safe: a pure best-effort notification — fire-and-forget *source* call to a
    // settable hook, but NO accounting is finalized afterwards (no later storage
    // write, no emit). There is no dependent post-call invariant to violate.
    const SAFE_NO_FINALIZE: &str = r#"
        pragma solidity ^0.8.0;
        contract Notifier {
            address public hook;
            function setHook(address h) external { hook = h; }
            function ping(bytes calldata data) external {
                hook.call(data);
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_real_asm_hook() {
        assert!(fires(VULN_ASM_HOOK), "{:#?}", run(VULN_ASM_HOOK));
    }

    #[test]
    fn fires_on_real_asm_burner_no_local_finalize() {
        assert!(fires(VULN_ASM_BURNER), "{:#?}", run(VULN_ASM_BURNER));
    }

    #[test]
    fn silent_when_return_checked() {
        assert!(!fires(SAFE_RETURN_CHECKED), "{:#?}", run(SAFE_RETURN_CHECKED));
    }

    #[test]
    fn silent_when_callee_immutable() {
        assert!(!fires(SAFE_IMMUTABLE_BURNER), "{:#?}", run(SAFE_IMMUTABLE_BURNER));
    }

    #[test]
    fn silent_asm_when_callee_immutable() {
        assert!(!fires(SAFE_ASM_IMMUTABLE), "{:#?}", run(SAFE_ASM_IMMUTABLE));
    }

    #[test]
    fn silent_asm_when_return_checked() {
        assert!(!fires(SAFE_ASM_RETURN_CHECKED), "{:#?}", run(SAFE_ASM_RETURN_CHECKED));
    }

    #[test]
    fn silent_asm_when_target_is_param() {
        assert!(!fires(SAFE_ASM_PARAM_TARGET), "{:#?}", run(SAFE_ASM_PARAM_TARGET));
    }

    #[test]
    fn silent_without_post_call_finalization() {
        assert!(!fires(SAFE_NO_FINALIZE), "{:#?}", run(SAFE_NO_FINALIZE));
    }
}
