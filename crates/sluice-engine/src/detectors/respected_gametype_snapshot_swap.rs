//! Respected-game-type snapshot swap — an authorization / validity decision is
//! made against a **frozen creation-time snapshot** of a config flag, while a
//! privileged setter can later change the **live** config it was snapshotted from,
//! with no re-validation of in-flight items.
//!
//! ## The shape
//!
//! A dispute-game system records, at game *creation*, whether the game's type was
//! the protocol's "respected" type at that instant, and freezes the answer into a
//! per-game boolean:
//!
//! ```solidity
//! // FaultDisputeGame.initialize()  (the snapshot capture)
//! wasRespectedGameTypeWhenCreated =
//!     GameType.unwrap(anchorStateRegistry().respectedGameType()) == GameType.unwrap(gameType());
//! ```
//!
//! The registry's *authorization / validity gate* then trusts that frozen
//! snapshot, not the live config:
//!
//! ```solidity
//! // AnchorStateRegistry.isGameRespected()  (the auth gate)
//! function isGameRespected(IDisputeGame _game) public view returns (bool) {
//!     return _game.wasRespectedGameTypeWhenCreated();      // <-- FROZEN snapshot
//! }
//! // ...used by isGameClaimValid(): `if (!isGameRespected(_game)) return false;`
//! ```
//!
//! But a privileged setter mutates the **live** source the snapshot was taken
//! from, and does **not** re-validate games already in flight:
//!
//! ```solidity
//! // AnchorStateRegistry.setRespectedGameType()  (the privileged live setter)
//! function setRespectedGameType(GameType _gameType) external {
//!     _assertOnlyGuardian();
//!     respectedGameType = _gameType;                       // <-- LIVE config changes
//!     emit RespectedGameTypeSet(_gameType);
//! }
//! ```
//!
//! Because the gate reads `wasRespectedGameTypeWhenCreated` (the value captured at
//! *each game's* creation) and never re-reads the *current* `respectedGameType`,
//! flipping the respected type does not retroactively invalidate games created
//! under the old type, and does not validate games created under the new type
//! before the flip. A game whose type was respected-at-creation stays
//! "respected" forever in the eyes of `isGameRespected`, even after the guardian
//! moves the respected type away from it — and vice versa. The authorization
//! decision is desynchronized from the live config it is meant to track.
//!
//! ## Precision anchors (all required — keeps this silent on ordinary snapshots)
//!   * an **auth / validity gate** function (name reads as `is*Respected` /
//!     `isGame*` / `*valid*` / `*authorized*` / `*allowed*` / `*eligible*`, or it
//!     returns a `bool` consumed by a `require`/branch) that **reads a frozen
//!     creation-time snapshot bool** — a `*WhenCreated` / `*AtCreation` /
//!     `*OnCreation` member call or member/state read;
//!   * a **sibling privileged setter** in the *same contract* — an externally
//!     reachable `set*` (or `update*`) function, guarded by an access-control
//!     modifier or an `_assertOnly*` / `onlyGuardian`-style internal guard, that
//!     **writes a live config state var** whose name is the snapshot's live
//!     counterpart (the live var name appears inside the snapshot name, e.g. live
//!     `respectedGameType` ⊂ `wasRespectedGameTypeWhenCreated`);
//!   * **SUPPRESS** when the auth gate **re-reads the live value at use** — if the
//!     gate body itself reads the live config var (`respectedGameType`) it is doing
//!     a live re-check, not trusting the frozen snapshot, so it is safe.
//!
//! Real target:
//! `optimism/packages/contracts-bedrock/src/dispute/FaultDisputeGame.sol:318-319`
//! (the `wasRespectedGameTypeWhenCreated` snapshot capture) +
//! `AnchorStateRegistry.sol:153-160` (`setRespectedGameType`, the privileged live
//! setter) and `:231-236` (`isGameRespected`, the auth gate trusting the frozen
//! snapshot).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{Contract, Expr, ExprKind, Function, GuardKind, Span, StmtKind};

use super::prelude::*;

pub struct RespectedGameTypeSnapshotSwapDetector;

impl Detector for RespectedGameTypeSnapshotSwapDetector {
    fn id(&self) -> &'static str {
        "respected-gametype-snapshot-swap"
    }
    fn category(&self) -> Category {
        Category::RespectedGameTypeSnapshotSwap
    }
    fn description(&self) -> &'static str {
        "Authorization/validity gate trusts a frozen creation-time snapshot bool (`*WhenCreated`) while a privileged setter mutates the live config it was snapshotted from, with no re-validation of in-flight items (Optimism AnchorStateRegistry.isGameRespected / setRespectedGameType class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for contract in cx.scir.iter_contracts() {
            // The gate + the live setter both live in a concrete registry-style
            // contract. Interfaces declare no logic; libraries have no admin setter.
            if contract.is_interface() || contract.is_library() {
                continue;
            }

            // (1) Collect the privileged live setters of this contract: an
            //     externally-reachable, access-controlled `set*`/`update*` that
            //     writes a (settable) config state var. We record each (function,
            //     live-var-name) so the auth-gate scan can match a snapshot to its
            //     live counterpart.
            let setters = privileged_live_setters(cx, contract);
            if setters.is_empty() {
                continue;
            }

            // (2) Find an auth/validity gate that reads a frozen creation-time
            //     snapshot whose live counterpart is one of those settable config
            //     vars, and that does NOT re-read the live value (suppression).
            for f in cx.scir.functions_of(contract.id) {
                if !f.has_body {
                    continue;
                }
                // The gate is a *read-only* authorization decision (`view`), or at
                // least a boolean-returning predicate. The privileged setter itself
                // is excluded by requiring the function to read a snapshot, not write
                // the live var.
                if !reads_auth_decision_shape(f) {
                    continue;
                }

                let Some(snap) = snapshot_auth_read(f) else { continue };

                // The snapshot must correspond to a LIVE config var that a privileged
                // setter in this contract mutates: the live var name appears inside
                // the snapshot name (live `respectedGameType` ⊂ snapshot
                // `wasRespectedGameTypeWhenCreated`).
                let Some(setter) = setters.iter().find(|s| {
                    snapshot_mentions_live_var(&snap.snap_name, &s.live_var)
                }) else {
                    continue;
                };

                // SUPPRESS: the gate re-reads the live config var at use — it is doing
                // a live re-check, not trusting the frozen snapshot. (A gate that reads
                // both the snapshot AND the live `respectedGameType` is safe.)
                if reads_live_var(f, &setter.live_var) {
                    continue;
                }

                let b = report!(self, Category::RespectedGameTypeSnapshotSwap,
                    title = "Authorization gate trusts a frozen creation-time snapshot while a privileged setter changes the live config",
                    severity = Severity::High,
                    // Multi-anchor structural fingerprint: a `*WhenCreated` snapshot read
                    // driving a bool auth decision, paired with a same-contract privileged
                    // `set*` that mutates the snapshot's live source, and the
                    // live-re-read suppression. Confidence set so a single Invariant
                    // dimension lands a High label (70 × (0.5 + 0.5·0.79) = 62.65 ≥ 62).
                    confidence = 0.79,
                    dimensions = [Dimension::Invariant],
                    message = format!(
                        "`{gate}` makes an authorization / validity decision from the frozen \
                         creation-time snapshot `{snap}` (captured once when the item was created), \
                         but the sibling privileged setter `{setter}` can later change the **live** \
                         config `{live}` that the snapshot was taken from — and re-validates no \
                         in-flight items. Because the gate trusts the frozen `{snap}` and never \
                         re-reads the current `{live}`, changing `{live}` does not retroactively \
                         invalidate items created under the old value, nor validate items created \
                         under the new value before the change: the authorization decision is \
                         desynchronized from the live config it is meant to track. (Optimism \
                         `AnchorStateRegistry.isGameRespected` returns \
                         `_game.wasRespectedGameTypeWhenCreated()` while \
                         `setRespectedGameType(GameType)` rewrites the live `respectedGameType` with \
                         no re-check of existing games.)",
                        gate = f.name,
                        snap = snap.snap_name,
                        setter = setter.name,
                        live = setter.live_var,
                    ),
                    recommendation = format!(
                        "Make the authorization decision against the **live** value at use, not the \
                         frozen snapshot: have `{gate}` compare the item's game type against the \
                         *current* `{live}` (re-read it on each check), or have `{setter}` re-validate \
                         / invalidate every in-flight item when it mutates `{live}` (a retirement \
                         timestamp or a sweep). A creation-time snapshot used for a standing \
                         authorization gate silently diverges from the config the privileged setter \
                         controls.",
                        gate = f.name,
                        setter = setter.name,
                        live = setter.live_var,
                    ),
                );
                out.push(finish_at(cx, b, f.id, snap.span));
                break; // one finding per gate function is enough.
            }
        }

        out
    }
}

/// A privileged live-config setter: `(function name, live state-var it writes)`.
struct LiveSetter {
    name: String,
    live_var: String,
}

/// A located frozen-snapshot read inside an auth gate.
struct SnapshotRead {
    /// Span of the snapshot read (where to anchor the finding).
    span: Span,
    /// The snapshot identifier read (`wasRespectedGameTypeWhenCreated`).
    snap_name: String,
}

/// The privileged live-config setters of `contract`: externally-reachable,
/// access-controlled `set*` / `update*` functions that write a *settable* config
/// state var of the contract. Returns `(setter name, live var name)` per
/// written-config-var, so a snapshot can be matched to its live counterpart.
fn privileged_live_setters(cx: &AnalysisContext, contract: &Contract) -> Vec<LiveSetter> {
    let mut out: Vec<LiveSetter> = Vec::new();
    for f in cx.scir.functions_of(contract.id) {
        if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
            continue;
        }
        if !name_is_setter(&f.name) {
            continue;
        }
        if !is_access_controlled(cx, f) {
            continue;
        }
        // The setter must WRITE a settable (non-const/immutable) config state var.
        // We take each written var that is settable and config-shaped; this is the
        // "live config" the snapshot was captured from.
        for w in f.effects.written_vars() {
            if is_settable_state_var(contract, w)
                && is_config_var_name(w)
                && !out.iter().any(|s| s.name == f.name && s.live_var == w)
            {
                out.push(LiveSetter { name: f.name.clone(), live_var: w.to_string() });
            }
        }
    }
    out
}

/// Does `f` have the *shape* of an authorization / validity gate: a boolean
/// predicate whose result feeds an auth decision? Accepted when EITHER
///   * the function name reads as an auth/validity gate (`is*Respected`, `isGame*`,
///     `*valid*`, `*authorized*`, `*allowed*`, `*eligible*`, `*respected*`), OR
///   * it returns a single `bool` (a predicate the caller branches on).
///
/// This keeps the gate scan tight without requiring the consumer to be in-body.
fn reads_auth_decision_shape(f: &Function) -> bool {
    if name_is_auth_gate(&f.name) {
        return true;
    }
    // A bool-returning predicate (one return that is `bool`).
    f.returns.len() == 1 && f.returns[0].ty.trim().eq_ignore_ascii_case("bool")
}

/// Find a frozen creation-time snapshot read in `f` that flows to the auth
/// decision — a `return`, a `require`/`assert` argument, or an `if`/`while`
/// condition. The snapshot is recognized by name: a `*WhenCreated` /
/// `*AtCreation` / `*OnCreation` identifier, read as a **member call**
/// (`_game.wasRespectedGameTypeWhenCreated()`), a **member access**
/// (`_game.wasRespectedGameTypeWhenCreated`), or a bare identifier / state read.
fn snapshot_auth_read(f: &Function) -> Option<SnapshotRead> {
    let mut hit: Option<SnapshotRead> = None;
    for s in &f.body {
        s.visit(&mut |st| {
            if hit.is_some() {
                return;
            }
            match &st.kind {
                // `return <expr>;` — the canonical `isGameRespected` shape.
                StmtKind::Return(Some(e)) => {
                    if let Some(found) = snapshot_in_expr(e) {
                        hit = Some(found);
                    }
                }
                // `if (<snap>) ...` / `while (<snap>)`.
                StmtKind::If { cond, .. }
                | StmtKind::While { cond, .. }
                | StmtKind::DoWhile { cond, .. } => {
                    if let Some(found) = snapshot_in_expr(cond) {
                        hit = Some(found);
                    }
                }
                // `require(<snap>, ...)` / `bool ok = <snap>;`.
                StmtKind::Expr(e) => {
                    if let Some(found) = snapshot_in_require_or_assign(e) {
                        hit = Some(found);
                    }
                }
                StmtKind::VarDecl { init: Some(e), .. } => {
                    if let Some(found) = snapshot_in_expr(e) {
                        hit = Some(found);
                    }
                }
                _ => {}
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// A `require`/`assert` whose args read a snapshot, or an assignment whose value
/// reads a snapshot.
fn snapshot_in_require_or_assign(e: &Expr) -> Option<SnapshotRead> {
    if let ExprKind::Call(c) = &e.kind {
        if is_require_or_assert(c) {
            for a in &c.args {
                if let Some(found) = snapshot_in_expr(a) {
                    return Some(found);
                }
            }
        }
    }
    if let ExprKind::Assign { value, .. } = &e.kind {
        return snapshot_in_expr(value);
    }
    None
}

/// Find a frozen-snapshot read anywhere inside `e`. Recognizes the snapshot by a
/// `*WhenCreated`/`*AtCreation`/`*OnCreation` name in:
///   * a **call** func-name (`_game.wasRespectedGameTypeWhenCreated()`),
///   * a **member** access (`x.wasRespectedGameTypeWhenCreated`),
///   * a bare **identifier** (`wasRespectedGameTypeWhenCreated` as a state read).
fn snapshot_in_expr(e: &Expr) -> Option<SnapshotRead> {
    let mut found: Option<SnapshotRead> = None;
    e.visit(&mut |sub| {
        if found.is_some() {
            return;
        }
        match &sub.kind {
            ExprKind::Call(c) => {
                if let Some(n) = &c.func_name {
                    if is_creation_snapshot_name(n) {
                        found = Some(SnapshotRead { span: sub.span, snap_name: n.clone() });
                    }
                }
            }
            ExprKind::Member { member, .. } if is_creation_snapshot_name(member) => {
                found = Some(SnapshotRead { span: sub.span, snap_name: member.clone() });
            }
            ExprKind::Ident(n) if is_creation_snapshot_name(n) => {
                found = Some(SnapshotRead { span: sub.span, snap_name: n.clone() });
            }
            _ => {}
        }
    });
    found
}

/// Does the auth gate re-read the **live** config var `live_var` anywhere in its
/// body (call, member, or identifier)? If so it is doing a live re-check and is
/// safe — the SUPPRESS condition.
fn reads_live_var(f: &Function, live_var: &str) -> bool {
    let lv = live_var.to_ascii_lowercase();
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            match &e.kind {
                ExprKind::Call(c)
                    if c.func_name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(live_var)) =>
                {
                    found = true;
                }
                ExprKind::Member { member, .. } if member.to_ascii_lowercase() == lv => {
                    found = true;
                }
                ExprKind::Ident(n) if n.to_ascii_lowercase() == lv => {
                    found = true;
                }
                _ => {}
            }
        });
        if found {
            break;
        }
    }
    found
}

/// Is `f` access-controlled — an auth modifier (`onlyOwner`/`onlyGuardian`/…), a
/// `msg.sender` guard, OR an internal `_assertOnly*` / `only*` guard call in the
/// body? Optimism's `setRespectedGameType` uses `_assertOnlyGuardian()` (an
/// internal call), not a modifier, so the internal-call form is essential.
fn is_access_controlled(cx: &AnalysisContext, f: &Function) -> bool {
    // Modifier or msg.sender-comparison guard.
    if cx.has_access_control(f) {
        return true;
    }
    if f.modifiers.iter().any(|m| is_auth_modifier_name(&m.name)) {
        return true;
    }
    // Internal guard call: `_assertOnlyGuardian()`, `_checkOwner()`, `onlyRole(...)`.
    if f.effects.internal_calls.iter().any(|n| is_auth_guard_call(n)) {
        return true;
    }
    // Some `_assertOnly*` lower as external-shaped member calls or sit in call_sites.
    if f.effects.call_sites.iter().any(|cs| {
        cs.func_name.as_deref().map(is_auth_guard_call).unwrap_or(false)
    }) {
        return true;
    }
    // A leading `if (msg.sender != ...) revert` guard surfaces as a Require/MsgSenderCheck
    // guard; also accept a textual `_assertonly` / `onlyguardian` token in the body.
    let src = cx.source_text(f.span);
    src.contains("_assertonly")
        || src.contains("onlyguardian")
        || src.contains("onlyowner")
        || src.contains("onlyrole")
        || f.effects.guards.iter().any(|g| matches!(g.kind, GuardKind::MsgSenderCheck))
}

// ----------------------------------------------------------------- name classifiers

/// A `*WhenCreated` / `*AtCreation` / `*OnCreation` snapshot identifier — a value
/// frozen at the item's creation. Case-insensitive.
fn is_creation_snapshot_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.ends_with("whencreated")
        || l.ends_with("atcreation")
        || l.ends_with("oncreation")
        || l.ends_with("ascreated")
        || l.ends_with("atcreate")
}

/// Does the snapshot name embed the live config var name (the live→snapshot link)?
/// e.g. live `respectedGameType` is a substring of `wasRespectedGameTypeWhenCreated`.
/// We require the live var to be a reasonably specific token (length ≥ 4) so a tiny
/// var name (`id`) does not spuriously "match" inside an unrelated snapshot.
fn snapshot_mentions_live_var(snap_name: &str, live_var: &str) -> bool {
    if live_var.len() < 4 {
        return false;
    }
    snap_name.to_ascii_lowercase().contains(&live_var.to_ascii_lowercase())
}

/// A setter-shaped function name (`set*` / `update*` / `change*`).
fn name_is_setter(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.starts_with("set") || l.starts_with("update") || l.starts_with("change")
}

/// A function name that reads as an authorization / validity gate.
fn name_is_auth_gate(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("respected")
        || l.contains("authorized")
        || l.contains("allowed")
        || l.contains("eligible")
        || l.contains("isvalid")
        || l.contains("valid")
        || (l.starts_with("is") && l.contains("game"))
        || l.starts_with("isgame")
        || l.starts_with("can")
        || l.contains("permitted")
}

/// A config-shaped state var name — a protocol-level setting an authorization
/// decision keys on (`respectedGameType`, `*config`, `*type`, a `respected*`,
/// `*mode`, `*policy`). Deliberately closed-ish so an unrelated mutable var
/// (`balance`, `nonce`) does not qualify as the "live config".
fn is_config_var_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("respected")
        || l.contains("gametype")
        || l.ends_with("type")
        || l.contains("config")
        || l.contains("policy")
        || l.ends_with("mode")
        || l.contains("authorized")
        || l.contains("allowed")
        || l.contains("eligible")
}

/// An auth modifier name (`onlyOwner`, `onlyGuardian`, `onlyRole`, `onlyAdmin`,
/// `restricted`, `auth`).
fn is_auth_modifier_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.starts_with("only")
        || l == "auth"
        || l == "restricted"
        || l.contains("requiresauth")
        || l.contains("onlyrole")
}

/// An internal auth-guard call name (`_assertOnlyGuardian`, `_checkOwner`,
/// `_authorizeUpgrade`, `onlyRole`, `_onlyGovernance`).
fn is_auth_guard_call(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    (l.contains("assert") && l.contains("only"))
        || (l.starts_with("_") && l.contains("only"))
        || l == "_checkowner"
        || l == "checkowner"
        || l.contains("authorize")
        || l == "onlyrole"
        || (l.contains("only") && (l.contains("guardian") || l.contains("owner") || l.contains("admin") || l.contains("governance")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::AnalysisContext;
    use crate::detector::Detector;
    use crate::Config;

    // Run ONLY this detector against `src`, building the analysis context directly.
    // This deliberately bypasses `builtin_detectors()` / the shared `mod.rs` registry
    // so these unit tests are independent of sibling detectors authored concurrently.
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        let parsed = sluice_parse::parse_sources(vec![("t.sol".into(), src.into())]);
        let scir = parsed.scir;
        let dataflow = sluice_dataflow::DataflowFacts::analyze(&scir);
        let invariants = sluice_invariant::InvariantFacts::mine(&scir);
        let frontier = sluice_frontier::FrontierFacts::analyze(&scir);
        let cfg = Config::default();
        let cx = AnalysisContext::new(&scir, &dataflow, &invariants, &frontier, &cfg);
        RespectedGameTypeSnapshotSwapDetector.run(&cx)
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "respected-gametype-snapshot-swap")
    }

    // VULN — the exact Optimism AnchorStateRegistry shape: `isGameRespected` returns
    // the frozen `_game.wasRespectedGameTypeWhenCreated()` while `setRespectedGameType`
    // (guarded by `_assertOnlyGuardian()`) rewrites the live `respectedGameType` with
    // no re-validation of in-flight games.
    const VULN: &str = r#"
        interface IDisputeGame {
            function wasRespectedGameTypeWhenCreated() external view returns (bool);
        }
        contract AnchorStateRegistry {
            uint32 public respectedGameType;
            function setRespectedGameType(uint32 _gameType) external {
                _assertOnlyGuardian();
                respectedGameType = _gameType;
            }
            function isGameRespected(IDisputeGame _game) public view returns (bool) {
                return _game.wasRespectedGameTypeWhenCreated();
            }
            function _assertOnlyGuardian() internal view {
                require(msg.sender == guardian, "not guardian");
            }
            address guardian;
        }
    "#;

    // VULN (require form + modifier-guarded setter): the gate reads the snapshot into
    // a require, and the privileged setter uses an `onlyGuardian` modifier.
    const VULN_REQUIRE_MODIFIER: &str = r#"
        interface IGame { function wasRespectedTypeWhenCreated() external view returns (bool); }
        contract Registry {
            uint8 public respectedType;
            modifier onlyGuardian() { _; }
            function setRespectedType(uint8 t) external onlyGuardian {
                respectedType = t;
            }
            function checkRespected(IGame g) public view returns (bool ok) {
                ok = g.wasRespectedTypeWhenCreated();
                require(ok, "not respected");
            }
        }
    "#;

    // SAFE — the gate re-reads the LIVE config at use: it compares the game's type
    // against the *current* `respectedGameType`, not a frozen snapshot. There is no
    // desync because the decision tracks the live value.
    const SAFE_LIVE_RECHECK: &str = r#"
        interface IDisputeGame { function gameType() external view returns (uint32); }
        contract AnchorStateRegistry {
            uint32 public respectedGameType;
            function setRespectedGameType(uint32 _gameType) external {
                _assertOnlyGuardian();
                respectedGameType = _gameType;
            }
            function isGameRespected(IDisputeGame _game) public view returns (bool) {
                return _game.gameType() == respectedGameType;
            }
            function _assertOnlyGuardian() internal view {}
        }
    "#;

    // SAFE — there is NO privileged setter mutating the live config: the snapshot is
    // captured once and read, but the protocol provides no way to change the live
    // `respectedGameType` afterward, so the frozen value can never diverge.
    const SAFE_NO_SETTER: &str = r#"
        interface IDisputeGame { function wasRespectedGameTypeWhenCreated() external view returns (bool); }
        contract AnchorStateRegistry {
            uint32 public immutable respectedGameType;
            constructor(uint32 t) { respectedGameType = t; }
            function isGameRespected(IDisputeGame _game) public view returns (bool) {
                return _game.wasRespectedGameTypeWhenCreated();
            }
        }
    "#;

    // SAFE — the setter is NOT privileged (anyone can call it). This is not the class
    // (the bug is about an *admin* repointing the live config under standing
    // authorizations); an unguarded setter is a different, separately-detected issue.
    const SAFE_UNGUARDED_SETTER: &str = r#"
        interface IDisputeGame { function wasRespectedGameTypeWhenCreated() external view returns (bool); }
        contract AnchorStateRegistry {
            uint32 public respectedGameType;
            function setRespectedGameType(uint32 _gameType) external {
                respectedGameType = _gameType;
            }
            function isGameRespected(IDisputeGame _game) public view returns (bool) {
                return _game.wasRespectedGameTypeWhenCreated();
            }
        }
    "#;

    // SAFE — the snapshot the gate reads has no live counterpart that any setter
    // mutates: the privileged setter changes an unrelated config (`pauseMode`), and
    // the snapshot name (`wasFooWhenCreated`) does not embed it. No snapshot→live link.
    const SAFE_UNRELATED_SETTER: &str = r#"
        interface IGame { function wasFooWhenCreated() external view returns (bool); }
        contract Registry {
            uint8 public pauseMode;
            function setPauseMode(uint8 m) external { _assertOnlyOwner(); pauseMode = m; }
            function isGameRespected(IGame g) public view returns (bool) {
                return g.wasFooWhenCreated();
            }
            function _assertOnlyOwner() internal view {}
        }
    "#;

    // SAFE — an ordinary getter that surfaces a creation-time snapshot but is NOT an
    // auth gate (returns a uint, not a bool predicate) and there is no config setter.
    // The auth-decision-shape gate keeps this quiet.
    const SAFE_PLAIN_GETTER: &str = r#"
        contract Game {
            uint256 public createdAtBlock;
            function blockCreatedAt() public view returns (uint256) {
                return createdAtBlock;
            }
        }
    "#;

    #[test]
    fn fires_on_optimism_shape() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_require_modifier_shape() {
        assert!(fires(VULN_REQUIRE_MODIFIER), "{:#?}", run(VULN_REQUIRE_MODIFIER));
    }

    #[test]
    fn silent_when_gate_rereads_live_value() {
        assert!(!fires(SAFE_LIVE_RECHECK), "{:#?}", run(SAFE_LIVE_RECHECK));
    }

    #[test]
    fn silent_without_privileged_setter() {
        assert!(!fires(SAFE_NO_SETTER), "{:#?}", run(SAFE_NO_SETTER));
    }

    #[test]
    fn silent_on_unguarded_setter() {
        assert!(!fires(SAFE_UNGUARDED_SETTER), "{:#?}", run(SAFE_UNGUARDED_SETTER));
    }

    #[test]
    fn silent_on_unrelated_setter() {
        assert!(!fires(SAFE_UNRELATED_SETTER), "{:#?}", run(SAFE_UNRELATED_SETTER));
    }

    #[test]
    fn silent_on_plain_getter() {
        assert!(!fires(SAFE_PLAIN_GETTER), "{:#?}", run(SAFE_PLAIN_GETTER));
    }
}
