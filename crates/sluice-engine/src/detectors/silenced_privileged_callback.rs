//! Silenced privileged callback — a privileged state-changing function makes a
//! **fire-and-forget** low-level call to a *settable hook* and then finalizes
//! accounting state regardless of whether that call succeeded.
//!
//! Restaking / slashing cores delegate a side-effect (burn the slashed stake,
//! notify a delegator hook, forward to a receiver) to an address the protocol
//! lets governance *change* — a `burner`, `hook`, or `receiver` stored in a
//! mutable state variable. The danger is the combination of two choices:
//!
//!   1. the call is **fire-and-forget**: its return value is never inspected.
//!      In source this is a bare `hook.call(data);` with no `(bool ok, )`
//!      capture (the IR records `CallSite{ kind: LowLevelCall, return_checked:
//!      false }`); the assembly analog is `pop(call(...))`; and
//!   2. the function then **finalizes accounting** — a storage write (or an
//!      `emit`) at a *later* position — that is **not contingent** on the call
//!      having succeeded.
//!
//! So a hook that silently reverts, runs out of gas, or simply no-ops still lets
//! the protocol record the action as done: the slash is booked
//! (`cumulativeSlash += amount`), the event is emitted, the round advances — but
//! the value was never actually burned/forwarded. This is the shape behind
//! Symbiotic Core `BaseDelegator.onSlash` / `BaseSlasher._burnerOnSlash`, which
//! do `pop(call(...))` to a governance-set burner and then commit the slash.
//!
//! Why a *settable* hook is the precision anchor: if the callee is `constant` or
//! `immutable`, governance cannot point it at a misbehaving contract, and a
//! fixed system address that reverts is the protocol's own (auditable) problem,
//! not a silently-absorbed failure of an attacker- or governance-controlled
//! endpoint. The interesting bug is the *mutable* hook whose failure is swallowed.
//!
//! Precision anchors (all required, so this stays quiet on ordinary
//! best-effort-notification code):
//!   * a `LowLevelCall` whose `return_checked == false` (the return is ignored —
//!     fire-and-forget). A captured `(bool ok, ) = hook.call(...)` is *not*
//!     flagged, even if `ok` is later ignored, because the value is at least
//!     observable and this detector targets the un-captured form precisely;
//!   * the call **target** root-resolves to a state variable of the contract
//!     that is **neither `constant` nor `immutable`** (a settable hook/burner/
//!     receiver). A literal address, a `constant`/`immutable` callee, a local,
//!     or a bare parameter all suppress;
//!   * the function **finalizes state after** that call — a storage write at a
//!     later `order`, or an `emit` lexically after the call. A pure best-effort
//!     notification with no dependent post-call invariant is *not* a finding.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{CallKind, Contract, Function, Span, StmtKind};

pub struct SilencedPrivilegedCallbackDetector;

impl Detector for SilencedPrivilegedCallbackDetector {
    fn id(&self) -> &'static str {
        "silenced-privileged-callback"
    }
    fn category(&self) -> Category {
        Category::SilencedPrivilegedCallback
    }
    fn description(&self) -> &'static str {
        "Privileged function makes a fire-and-forget low-level call to a settable hook, then finalizes accounting regardless of the call's success (Symbiotic onSlash/_burnerOnSlash class)"
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

            // --- find a fire-and-forget low-level call to a settable hook ---
            let Some(hit) = first_silenced_hook_call(f, contract) else { continue };

            // --- the precision anchor: state is finalized AFTER that call ---
            // Either a storage write strictly later in source order, or an `emit`
            // lexically after the call. A best-effort notification with no
            // dependent post-call accounting is NOT a finding.
            let writes_after = f
                .effects
                .storage_writes
                .iter()
                .any(|w| w.order > hit.order);
            let emits_after = emit_after_span(f, hit.span);
            if !writes_after && !emits_after {
                continue;
            }

            let finalization = if writes_after {
                "records accounting state (a storage write)"
            } else {
                "emits a completion event"
            };

            let b = FindingBuilder::new(self.id(), Category::SilencedPrivilegedCallback)
                .title("Fire-and-forget privileged callback to a settable hook, then state is finalized regardless")
                .severity(Severity::Medium)
                .confidence(0.5)
                .dimension(Dimension::Frontier)
                .message(format!(
                    "`{}` makes a fire-and-forget low-level call to `{}` — a settable hook stored in the \
                     mutable state variable `{}` (not `constant`/`immutable`) — and never inspects the \
                     call's return value (no `(bool ok, )` capture; the assembly analog is `pop(call(...))`). \
                     It then {finalization} that does not depend on the call succeeding. A hook that silently \
                     reverts, runs out of gas, or no-ops still lets the protocol record the action as \
                     completed: the side-effect (burn / forward / notify) never happened, yet the accounting \
                     says it did. This is the Symbiotic Core `BaseDelegator.onSlash` / \
                     `BaseSlasher._burnerOnSlash` swallowed-callback shape.",
                    f.name, hit.target, hit.root,
                ))
                .recommendation(
                    "Capture and check the callback result before finalizing — `(bool ok, ) = \
                     hook.call(data); require(ok);` (or `if (!ok) revert)` — so a failed hook reverts the \
                     whole privileged action instead of being booked as done. If the call is intentionally \
                     best-effort, do not write accounting state or emit a completion event on the strength \
                     of it; record the outcome (success/failure) so off-chain consumers can reconcile, and \
                     prefer a fixed (`immutable`) or vetted callback target.",
                );
            out.push(cx.finish(b, f.id, hit.span));
        }
        out
    }
}

// ----------------------------------------------------------------- helpers

/// A matched fire-and-forget low-level call to a settable hook.
struct SilencedCall {
    /// Textual call target (`burner`, `delegator.hook`).
    target: String,
    /// Root state-var name that the target resolves to (`burner`).
    root: String,
    /// Sequential effect order of the call (shared with storage writes).
    order: u32,
    /// Source span of the call site.
    span: Span,
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
            if !is_settable_hook(contract, root) {
                return None;
            }
            Some(SilencedCall {
                target: cs.target.clone(),
                root: root.to_string(),
                order: cs.order,
                span: cs.span,
            })
        })
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

/// True when `root` names a state variable of `contract` that is a **settable**
/// hook — declared without `constant` or `immutable`, so governance / an admin
/// can repoint it at an arbitrary contract. A `constant`/`immutable` callee, or
/// a name that is not a state var at all (a local, a bare parameter, a literal
/// address), is *not* a settable hook and suppresses.
fn is_settable_hook(contract: &Contract, root: &str) -> bool {
    if root.is_empty() {
        return false;
    }
    contract
        .state_vars
        .iter()
        .any(|v| v.name == root && !(v.constant || v.immutable))
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

    // Safe: a pure best-effort notification — fire-and-forget call to a settable
    // hook, but NO accounting is finalized afterwards (no later storage write, no
    // emit). There is no dependent post-call invariant to silently violate.
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
    fn silent_when_return_checked() {
        assert!(!fires(SAFE_RETURN_CHECKED), "{:#?}", run(SAFE_RETURN_CHECKED));
    }

    #[test]
    fn silent_when_callee_immutable() {
        assert!(!fires(SAFE_IMMUTABLE_BURNER), "{:#?}", run(SAFE_IMMUTABLE_BURNER));
    }

    #[test]
    fn silent_without_post_call_finalization() {
        assert!(!fires(SAFE_NO_FINALIZE), "{:#?}", run(SAFE_NO_FINALIZE));
    }
}
