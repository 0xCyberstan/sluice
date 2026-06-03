//! Mis-scoped EIP-1153 transient-storage reentrancy guard.
//!
//! EIP-1153 (`tstore`/`tload`, Solidity `>=0.8.24`) gives contracts *transient*
//! storage: a slot that is writable like normal storage but is automatically
//! cleared at the **end of the transaction**, not the end of the call. It is the
//! intended substrate for a cheap reentrancy guard (OpenZeppelin v5's
//! `ReentrancyGuardTransient`): set an `entered` flag on entry, clear it on exit,
//! and because the value survives across nested calls within the *same* tx the
//! guard composes correctly.
//!
//! That same persistence is the footgun. Two distinct mistakes turn a transient
//! guard from a safety device into a vulnerability:
//!
//! 1. **Unbalanced entered-flag.** A guard that does `tstore(SLOT, 1)` on entry
//!    but does not `tstore(SLOT, 0)` on *every* exit path leaves the flag set for
//!    the rest of the transaction. Every later top-level call in the same tx then
//!    sees `entered == 1` and either reverts (a self-DoS) or — worse, if the read
//!    side is the inverse — is silently treated as already-inside. A `return` /
//!    `revert` / early-exit branch that skips the reset, or a guard expressed only
//!    as `increment()` with no paired `decrement()`, exhibits this.
//!
//! 2. **Cross-call dirty transient read.** A function reads `tload(SLOT)` for a
//!    slot it does **not** itself write, trusting a value some *other* function
//!    wrote earlier in the transaction (e.g. a `crossDomainMessageSender()` getter
//!    that returns a sender slot populated by a different `relayMessage` entry).
//!    Because transient storage is not cleared between top-level calls, a value
//!    left over from an earlier (or a re-entered) call is observed as if it
//!    belonged to the current context — a stale / attacker-seeded read that the
//!    function has no way to distinguish from a freshly-set one.
//!
//! Detection is necessarily source-text driven: the IR summarizes inline assembly
//! as a `StmtKind::Assembly` (capturing only `sstore` slots, calls, and
//! terminators), so `tstore`/`tload` are recovered from `cx.source_text(span)` —
//! exactly how the sibling `signature_malleability` detector reads source for its
//! guard scan. A finding therefore requires the transient-guard *idiom* to be
//! present (a `tstore(`/`tload(` in the contract plus an `entered`/reentrancy-aware
//! shape), and the canonical OpenZeppelin `ReentrancyGuardTransient` library — the
//! reference implementation that gets this right — is exempt by name (mirroring
//! how `signature_malleability` exempts OZ `ECDSA`).
//!
//! Heuristic by nature; confidence is held moderate (0.55–0.6).

use super::prelude::*;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::Function;

pub struct TstoreGuardMisscopeDetector;

impl Detector for TstoreGuardMisscopeDetector {
    fn id(&self) -> &'static str {
        "tstore-guard-misscope"
    }
    fn category(&self) -> Category {
        Category::TstoreGuardMisscope
    }
    fn description(&self) -> &'static str {
        "EIP-1153 transient reentrancy guard with an unbalanced entered-flag or a cross-call dirty tload"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.functions() {
            if !f.has_body || f.body.is_empty() {
                continue;
            }

            // The canonical OpenZeppelin v5 `ReentrancyGuardTransient` is the
            // reference implementation that balances set/clear correctly — never
            // flag the library that defines the pattern (mirrors the OZ-`ECDSA`
            // exemption in `signature_malleability`).
            if is_exempt_oz_transient(cx, f) {
                continue;
            }

            // Read the function source once. The IR does not retain `tstore`/`tload`
            // (only `sstore` is summarized), so the transient ops are recovered
            // textually — the same source-scan approach the sibling malleability
            // detector uses.
            let body_src = cx.source_text(f.span);
            let lower = body_src.to_ascii_lowercase();
            let has_tstore = lower.contains("tstore(");
            let has_tload = lower.contains("tload(");

            // Gate: must actually use transient storage. This single condition is
            // what keeps the detector silent on every codebase that predates / does
            // not use EIP-1153 (no `tstore`/`tload` anywhere).
            if !has_tstore && !has_tload {
                continue;
            }

            // Gate: must be the reentrancy-guard / transient-context idiom, not an
            // arbitrary transient-storage use. We require the surrounding contract
            // to carry the entered-flag / reentrancy-aware shape so a one-off
            // `tload` for, say, a packed-struct read is not misread as a guard.
            if !is_transient_guard_idiom(cx, f, &lower) {
                continue;
            }

            // ---- Shape 1: unbalanced entered-flag (set without a matching reset) ----
            if let Some(slot) = unbalanced_entered_flag(f, &body_src) {
                let b = report!(self, Category::TstoreGuardMisscope,
                    title = "Transient reentrancy guard sets the entered-flag without clearing it on every exit",
                    severity = Severity::High,
                    confidence = 0.6,
                    dimensions = [Dimension::Invariant, Dimension::Frontier],
                    message = format!(
                        "`{}` sets a transient entered-flag (`tstore({}, <nonzero>)` / `increment()`) but does not \
                         clear it (`tstore({}, 0)` / `decrement()`) on every exit path. EIP-1153 transient storage \
                         is cleared at END OF TRANSACTION, not end of call, so the flag stays set for the rest of \
                         the tx: every later top-level call in the same transaction observes `entered != 0` and \
                         either reverts (self-DoS) or — if the read side is inverted — is treated as already-inside, \
                         defeating the guard. (SWC-107, CWE-459.)",
                        f.name, slot, slot
                    ),
                    recommendation =
                        "Clear the transient flag on EVERY exit, including early `return`/`revert` branches — pair \
                         `tstore(SLOT, 1)` with `tstore(SLOT, 0)` (or `increment()` with `decrement()`) in a \
                         modifier so the reset is unconditional, e.g. OpenZeppelin v5 `ReentrancyGuardTransient`.",
                );
                out.push(finish_at(cx, b, f.id, f.span));
                continue;
            }

            // ---- Shape 2: cross-call dirty transient read ----
            // A `tload(SLOT)` where SLOT is NOT written by this same function — the
            // value was populated by a different function within the external entry,
            // and (being transient) can be a stale leftover from an earlier or
            // re-entered top-level call in the same transaction.
            if let Some(slot) = dirty_cross_call_tload(f, &body_src) {
                let b = report!(self, Category::TstoreGuardMisscope,
                    title = "Transient slot read (tload) is populated by a different function (cross-call dirty read)",
                    severity = Severity::High,
                    confidence = 0.55,
                    dimensions = [Dimension::Invariant, Dimension::Frontier],
                    message = format!(
                        "`{}` reads transient slot `{}` via `tload` but never writes it — the value is set by a \
                         DIFFERENT function within the external entry (e.g. a metadata-store step) and then read \
                         here. EIP-1153 transient storage persists for the WHOLE transaction, so a value left over \
                         from an earlier top-level call (or a re-entrant call) is observed as if it belonged to the \
                         current context: a stale / cross-call dirty read the function cannot distinguish from a \
                         freshly-set one. (SWC-107, CWE-459.)",
                        f.name, slot
                    ),
                    recommendation =
                        "Bind the transient read to the same scope that wrote it: gate the getter on the live \
                         entered/call-depth flag set in THIS call (revert when not entered), and clear sender/source \
                         slots on every exit so a stale value from a prior top-level call can never be read.",
                );
                out.push(finish_at(cx, b, f.id, f.span));
            }
        }

        out
    }
}

/// The OpenZeppelin v5 `ReentrancyGuardTransient` library — the reference
/// implementation of the transient guard, which balances set/clear correctly.
/// Exempt by name (case-insensitive), like `signature_malleability` exempts the
/// canonical OZ `ECDSA` library.
fn is_exempt_oz_transient(cx: &AnalysisContext, f: &Function) -> bool {
    cx.contract_of(f.id)
        .map(|c| {
            let n = c.name.to_ascii_lowercase();
            n == "reentrancyguardtransient" || n.contains("reentrancyguardtransient")
        })
        .unwrap_or(false)
}

/// Is `f` (or its contract) part of the transient reentrancy-guard / transient-
/// context idiom — i.e. there is an `entered`-flag slot, a reentrancy-aware
/// modifier shape, or a `TransientContext`/`TransientReentrancyAware` mixin —
/// rather than an unrelated one-off transient-storage use? Keeps the detector
/// scoped to the guard class (precision first).
fn is_transient_guard_idiom(cx: &AnalysisContext, f: &Function, lower_body: &str) -> bool {
    // Strong in-function signals: the guard vocabulary appears right here.
    const FN_SIGNALS: [&str; 6] =
        ["entered", "reentr", "calldepth", "call_depth", "increment(", "decrement("];
    if FN_SIGNALS.iter().any(|s| lower_body.contains(s)) {
        return true;
    }
    // A modifier on this function names the transient guard.
    if f.has_modifier_like("reentr") || f.has_modifier_like("entered") {
        return true;
    }
    // Contract-level signals: it inherits / is the transient-aware mixin, or the
    // contract source carries the entered-flag slot constant.
    if let Some(c) = cx.contract_of(f.id) {
        if c.inherits_like("transient")
            || c.inherits_like("reentrancyguard")
            || c.name.to_ascii_lowercase().contains("transient")
        {
            return true;
        }
        let csrc = cx.source_text(c.span).to_ascii_lowercase();
        if csrc.contains("entered_slot")
            || csrc.contains("reentrantaware")
            || csrc.contains("transientcontext")
            || csrc.contains("transientreentrancyaware")
            || (csrc.contains("entered") && (csrc.contains("tstore(") || csrc.contains("tload(")))
        {
            return true;
        }
    }
    false
}

/// Does `f` set a transient entered-flag (`tstore(SLOT, <nonzero>)` or call
/// `increment()`) without a matching clear (`tstore(SLOT, 0)` / `decrement()`) on
/// every path? Returns the slot name (or `"call-depth"`) of the unbalanced flag.
///
/// Two forms:
///   * Direct: `tstore(SLOT, 1)` (or any nonzero literal) present, `tstore(SLOT, 0)`
///     for the *same* slot absent.
///   * Helper: a guard *scope* (a modifier, or a body containing the `_;`
///     placeholder) that *calls* `increment()` with no paired `decrement()`.
///
/// Precision: the helper form must be a genuine **call** (`X.increment()` /
/// `increment();`), not the `function increment(` declaration of the primitive
/// itself, and `f` must not BE the `increment`/`decrement` primitive — those
/// building blocks legitimately do one half each. The canonical
/// `increment(); _; decrement();` modifier is balanced and never matches; if the
/// `_;` body reverts, the whole tx (and its transient writes) is rolled back, so
/// the skipped `decrement()` is safe by EVM semantics — exactly why we require the
/// asymmetry to be *textual* (no `decrement` anywhere in the scope).
fn unbalanced_entered_flag(f: &Function, src: &str) -> Option<String> {
    // Helper form: a guard scope that calls `increment()` but never `decrement()`.
    // Restricted to modifiers / `_;`-bearing scopes so a primitive or an ordinary
    // helper is not implicated, and to genuine call sites (not the declaration).
    let fname = f.name.to_ascii_lowercase();
    let is_primitive = fname == "increment" || fname == "decrement";
    let is_guard_scope = f.is_modifier() || src.contains("_;");
    if !is_primitive && is_guard_scope {
        let calls_inc = calls_helper(src, "increment");
        let calls_dec = calls_helper(src, "decrement");
        if calls_inc && !calls_dec {
            return Some("call-depth".to_string());
        }
    }

    // Direct form: parse every `tstore(SLOT, VALUE)` and classify the VALUE as
    // zero or nonzero per slot.
    let stores = parse_tstores(src);
    if stores.is_empty() {
        return None;
    }
    // A function with no `tstore` at all (only `tload`) is not a flag-setter.
    use std::collections::HashMap;
    let mut sets_nonzero: HashMap<String, bool> = HashMap::new();
    let mut clears_zero: HashMap<String, bool> = HashMap::new();
    for (slot, value) in &stores {
        if value_is_zeroish(value) {
            clears_zero.insert(slot.clone(), true);
        } else {
            sets_nonzero.insert(slot.clone(), true);
        }
    }
    // Only treat this as a *guard* shape (avoid flagging a metadata writer that
    // legitimately stores arbitrary values): require the slot name or the function
    // to look like an entered/guard flag, OR the stored nonzero value to be the
    // literal `1` (the canonical entered marker).
    for (slot, _) in sets_nonzero.iter() {
        if clears_zero.get(slot).copied().unwrap_or(false) {
            continue; // balanced: this slot is both set and cleared.
        }
        let slot_l = slot.to_ascii_lowercase();
        let looks_like_flag = slot_l.contains("enter")
            || slot_l.contains("lock")
            || slot_l.contains("guard")
            || slot_l.contains("reentr")
            || f.name.to_ascii_lowercase().contains("enter")
            || f.has_modifier_like("reentr");
        // The canonical entered marker `tstore(SLOT, 1)`.
        let sets_one = stores
            .iter()
            .any(|(s, v)| s == slot && v.trim() == "1");
        if looks_like_flag && sets_one {
            return Some(slot.clone());
        }
    }
    None
}

/// Find a `tload(SLOT)` whose `SLOT` is a named identifier that this same source
/// never `tstore`s — the cross-call dirty-read shape. Returns the slot name.
///
/// We only consider *named-constant* slots (an identifier, typically an
/// ALL_CAPS slot constant) so a `tload(keccak256(...))` computed-slot read or a
/// `tload(localVar)` is not misclassified. The read is "dirty" precisely because
/// the writer is some other function — within this function the slot is read but
/// never set.
///
/// Precision gate (avoid flagging a library's own depth plumbing): the read is
/// only reported when it is *consequential* —
///   * the function is externally reachable (a getter that EXPOSES the leftover
///     transient value to a cross-call caller — the highest-value case), **or**
///   * the slot denotes identity / context / guard state (`sender`, `source`,
///     `owner`, `enter`, `lock`, `guard`, `reentr`), i.e. a value whose staleness
///     is a security fact — as opposed to a bare call-depth counter read inside an
///     internal accessor primitive (the mechanism, not the bug).
fn dirty_cross_call_tload(f: &Function, src: &str) -> Option<String> {
    let loads = parse_slot_calls(src, "tload(");
    if loads.is_empty() {
        return None;
    }
    let stores: std::collections::HashSet<String> =
        parse_tstores(src).into_iter().map(|(s, _)| s).collect();
    let externally_reachable = f.is_externally_reachable();
    for slot in loads {
        // Must be a plausible named slot constant (an identifier), not a computed
        // expression or a bare local. Require it to look like a SLOT constant.
        if !is_named_slot(&slot) {
            continue;
        }
        // The current function must NOT write this slot — that is what makes the
        // read cross-call (some other function populated it).
        if stores.contains(&slot) {
            continue;
        }
        // Consequential-read gate.
        if externally_reachable || slot_is_context(&slot) {
            return Some(slot);
        }
    }
    None
}

/// Does the slot name denote identity / context / guard state whose staleness is a
/// security fact (sender/source/owner/entered/lock/guard), as opposed to a pure
/// mechanism counter (call depth)?
fn slot_is_context(slot: &str) -> bool {
    let l = slot.to_ascii_lowercase();
    ["sender", "source", "owner", "origin", "enter", "lock", "guard", "reentr", "caller", "context"]
        .iter()
        .any(|k| l.contains(k))
}

/// Parse `tstore(SLOT, VALUE)` occurrences from source, returning `(slot, value)`
/// pairs with both operands as trimmed source substrings. Best-effort: handles
/// nested parentheses in the VALUE (e.g. `tstore(S, add(tload(S), 1))`).
fn parse_tstores(src: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let needle = b"tstore(";
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle && !preceded_by_ident(bytes, i) {
            let open = i + needle.len() - 1; // index of '('
            if let Some((args, _end)) = balanced_args(src, open) {
                if let Some((slot, value)) = split_top_comma(&args) {
                    out.push((slot.trim().to_string(), value.trim().to_string()));
                }
            }
            i = open + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Parse the first argument (the slot) of every `<needle>SLOT...)` call, e.g.
/// `tload(`, returning the slot operand source for each. Best-effort, paren-aware.
fn parse_slot_calls(src: &str, needle_str: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let needle = needle_str.as_bytes();
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle && !preceded_by_ident(bytes, i) {
            let open = i + needle.len() - 1;
            if let Some((args, _end)) = balanced_args(src, open) {
                let slot = match split_top_comma(&args) {
                    Some((slot, _)) => slot,
                    None => args.clone(),
                };
                out.push(slot.trim().to_string());
            }
            i = open + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Given the byte index of an opening `(`, return the inner argument text (between
/// the matching parens) and the index just past the closing `)`. Paren-balanced.
fn balanced_args(src: &str, open_paren: usize) -> Option<(String, usize)> {
    let bytes = src.as_bytes();
    if bytes.get(open_paren) != Some(&b'(') {
        return None;
    }
    let mut depth = 0i32;
    let mut j = open_paren;
    while j < bytes.len() {
        match bytes[j] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((src[open_paren + 1..j].to_string(), j + 1));
                }
            }
            _ => {}
        }
        j += 1;
    }
    None
}

/// Split an argument list on the FIRST top-level comma (depth-0), returning
/// `(first, rest)`. Returns `None` if there is no top-level comma (single arg).
fn split_top_comma(args: &str) -> Option<(String, String)> {
    let bytes = args.as_bytes();
    let mut depth = 0i32;
    for (k, &c) in bytes.iter().enumerate() {
        match c {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                return Some((args[..k].to_string(), args[k + 1..].to_string()));
            }
            _ => {}
        }
    }
    None
}

/// Is byte index `i` (start of a needle like `tstore`) immediately preceded by an
/// identifier character? If so it is part of a longer word (`mytstore(`) and must
/// not match.
fn preceded_by_ident(bytes: &[u8], i: usize) -> bool {
    i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_')
}

/// Does `src` contain a genuine *call* to a helper named `name` (e.g.
/// `increment`) — `Lib.increment()` or a bare `increment();` — as opposed to the
/// `function increment(...)` declaration of the helper itself? We find each
/// `name(` occurrence whose preceding non-space token is not the `function`
/// keyword and which is not glued to a longer identifier.
fn calls_helper(src: &str, name: &str) -> bool {
    let bytes = src.as_bytes();
    let needle: Vec<u8> = format!("{name}(").into_bytes();
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle.as_slice() && !preceded_by_ident(bytes, i) {
            // Skip if the token just before this is the `function` keyword (a
            // declaration `function increment(`), even across a `.` it would be a
            // call. Look back over whitespace for the prior word.
            let mut j = i;
            while j > 0 && bytes[j - 1].is_ascii_whitespace() {
                j -= 1;
            }
            let end = j;
            while j > 0 && (bytes[j - 1].is_ascii_alphanumeric() || bytes[j - 1] == b'_') {
                j -= 1;
            }
            let prev_word = &src[j..end];
            if prev_word != "function" {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Does the value operand of a `tstore` denote zero / the cleared state? Matches a
/// literal `0`, `0x0`, `0x00…`, `false`, `address(0)`, `bytes32(0)`-style casts.
fn value_is_zeroish(value: &str) -> bool {
    let v = value.trim();
    if v == "0" || v == "false" {
        return true;
    }
    // 0x000... (any number of zeros).
    if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        if !hex.is_empty() && hex.bytes().all(|b| b == b'0') {
            return true;
        }
    }
    // `address(0)` / `bytes32(0)` / `uint256(0)` style zero casts.
    let lower = v.to_ascii_lowercase();
    if (lower.starts_with("address(")
        || lower.starts_with("bytes32(")
        || lower.starts_with("uint256(")
        || lower.starts_with("uint(")
        || lower.starts_with("payable("))
        && (lower.contains("(0)") || lower.contains("(0x0"))
    {
        return true;
    }
    false
}

/// Is `slot` a plausible *named* transient-slot constant — a bare identifier
/// (often ALL_CAPS, frequently ending in `_SLOT`)? Excludes computed slots
/// (`keccak256(...)`), numeric literals, and member/index expressions, where the
/// "cross-call" reasoning does not apply cleanly.
fn is_named_slot(slot: &str) -> bool {
    let s = slot.trim();
    if s.is_empty() {
        return false;
    }
    // Must be a single bare identifier (letters/digits/underscore), starting with
    // a letter or underscore. This excludes `keccak256(0,64)`, `add(...)`, numeric
    // literals, and dotted/indexed expressions.
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    // A real local read variable like `value` is unlikely to be a SLOT; require
    // either an ALL-CAPS-ish constant or an explicit `slot` token to keep this to
    // genuine slot constants. (`CROSS_DOMAIN_MESSAGE_SENDER_SLOT`, `ENTERED_SLOT`.)
    let lower = s.to_ascii_lowercase();
    let looks_const = s.chars().any(|c| c.is_ascii_uppercase())
        && !s.chars().any(|c| c.is_ascii_lowercase());
    looks_const || lower.contains("slot")
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn findings(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        findings(src).iter().any(|f| f.detector == "tstore-guard-misscope")
    }

    // ---- VULN A: unbalanced entered-flag — set on entry, NOT cleared on the
    // early-return path. The flag stays set for the rest of the tx. ----
    const VULN_UNBALANCED: &str = r#"
pragma solidity ^0.8.24;
contract Guarded {
    bytes32 internal constant ENTERED_SLOT = 0xf135698148;
    bool public didWork;
    function _entered() internal view returns (bool e) {
        assembly { e := gt(tload(ENTERED_SLOT), 0) }
    }
    // Sets the entered flag but only clears it on the success path; the early
    // revert/return branch leaves it set.
    function work(uint256 x) external {
        if (_entered()) revert();
        assembly { tstore(ENTERED_SLOT, 1) }
        if (x == 0) {
            return; // EARLY EXIT — flag never cleared
        }
        didWork = true;
        assembly { tstore(ENTERED_SLOT, 0) }
    }
}
"#;

    // ---- VULN B: cross-call dirty transient read. `senderOf()` reads a transient
    // slot that is written by a DIFFERENT function (`_store`). ----
    const VULN_CROSSCALL: &str = r#"
pragma solidity ^0.8.24;
contract Messenger {
    bytes32 internal constant SENDER_SLOT = 0xb83444d070;
    bytes32 internal constant ENTERED_SLOT = 0xf135698148;
    // Reads a transient slot it does not write — value set by _store() in a
    // different external entry, persists across the whole tx (dirty cross-call).
    function crossDomainMessageSender() external view returns (address s) {
        assembly { s := tload(SENDER_SLOT) }
    }
    function _store(address _sender) internal {
        assembly { tstore(SENDER_SLOT, _sender) }
    }
    function relay(address sender) external {
        assembly { tstore(ENTERED_SLOT, 1) }
        _store(sender);
        assembly { tstore(ENTERED_SLOT, 0) }
    }
}
"#;

    // ---- SAFE: a properly balanced transient guard. Set on entry, cleared
    // unconditionally on exit; the read of ENTERED_SLOT happens in the SAME
    // modifier scope that sets it. Mirrors OZ ReentrancyGuardTransient. ----
    const SAFE_BALANCED: &str = r#"
pragma solidity ^0.8.24;
contract WellGuarded {
    bytes32 internal constant ENTERED_SLOT = 0xf135698148;
    bool public didWork;
    function work() external {
        assembly { tstore(ENTERED_SLOT, 1) }
        didWork = true;
        assembly { tstore(ENTERED_SLOT, 0) }
    }
}
"#;

    // ---- SAFE: the canonical OZ ReentrancyGuardTransient library is exempt by
    // name even though its body sets and reads a transient flag. ----
    const SAFE_OZ_EXEMPT: &str = r#"
pragma solidity ^0.8.24;
library ReentrancyGuardTransient {
    bytes32 private constant REENTRANCY_GUARD_STORAGE = 0x9b779b17;
    function _reentrancyGuardEntered() internal view returns (bool e) {
        assembly { e := tload(REENTRANCY_GUARD_STORAGE) }
    }
}
"#;

    #[test]
    fn fires_on_unbalanced_flag() {
        assert!(fires(VULN_UNBALANCED), "{:?}", findings(VULN_UNBALANCED));
    }

    #[test]
    fn fires_on_cross_call_dirty_read() {
        assert!(fires(VULN_CROSSCALL), "{:?}", findings(VULN_CROSSCALL));
    }

    #[test]
    fn silent_on_balanced_guard() {
        assert!(!fires(SAFE_BALANCED), "{:?}", findings(SAFE_BALANCED));
    }

    #[test]
    fn silent_on_oz_reentrancy_guard_transient() {
        assert!(!fires(SAFE_OZ_EXEMPT), "{:?}", findings(SAFE_OZ_EXEMPT));
    }
}
