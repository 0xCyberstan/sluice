//! Reentrancy: classic (state-after-call), cross-function, and read-only.
//!
//! Precision rules enforced here (on top of the trust-frontier facts):
//!   * A reentrancy finding MUST be backed by a genuine reentrancy-capable
//!     external / low-level call (`.call`/`.delegatecall`/a non-view interface
//!     call/`.transfer`/`.send`). A function whose effects contain no such call
//!     site cannot be re-entered and never trips any reentrancy rule.
//!   * `Classic` requires a storage WRITE positioned STRICTLY AFTER the external
//!     call (a write that precedes the call is the safe checks-effects shape).
//!   * Calls whose target root-resolves to an immutable/constant or
//!     owner/governance-set trusted infrastructure address (`distributor`,
//!     `treasury`, `veFXS`, a timelock/gauge/minter module, …) are not
//!     attacker-controlled re-entry vectors and are suppressed.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder};
use sluice_frontier::ReentrancyKind;
use sluice_ir::{CallKind, CallSite, Contract, Function};

pub struct ReentrancyDetector;

/// A view/pure external method name that runs in a staticcall context and cannot
/// re-enter (mirrors the frontier's built-in view list). A call to one of these
/// is a read, not a re-entry vector.
fn is_view_call_name(name: Option<&str>) -> bool {
    matches!(
        name,
        Some(
            "balanceOf" | "getReserves" | "totalSupply" | "slot0" | "pricePerShare"
                | "getPricePerFullShare" | "get_virtual_price" | "getVirtualPrice" | "latestRoundData"
                | "latestAnswer" | "decimals" | "allowance" | "getAmountsOut" | "getAmountOut"
                | "getAmountsIn" | "getAmountIn" | "symbol" | "name" | "totalAssets" | "convertToAssets"
                | "convertToShares" | "previewRedeem" | "previewDeposit" | "previewMint"
                | "previewWithdraw" | "getRate" | "exchangeRate" | "quote" | "observe"
                | "getPastVotes" | "getPriorVotes" | "getVotes" | "getPastTotalSupply"
                | "delegates" | "nonces" | "checkpoints" | "numCheckpoints" | "getCurrentVotes"
        )
    )
}

/// Token-transfer-style methods: even an immutable/trusted token address can be an
/// ERC-777/ERC-721 contract whose transfer hook re-enters, so these are NEVER
/// trusted away (mirrors the frontier's `is_token_transfer_method`).
fn is_token_transfer_name(name: Option<&str>) -> bool {
    matches!(
        name,
        Some(
            "transfer" | "transferFrom" | "safeTransfer" | "safeTransferFrom" | "send"
                | "operatorSend" | "safeMint" | "mint" | "safeBatchTransferFrom"
        )
    )
}

/// True if this call site can hand control to code that may re-enter the
/// contract (the frontier's `is_reentrancy_capable`, replicated locally so the
/// detector can corroborate the facts without exporting internals).
fn is_reentry_vector(cs: &CallSite) -> bool {
    match cs.kind {
        CallKind::LowLevelCall | CallKind::DelegateCall | CallKind::Send | CallKind::Transfer => true,
        CallKind::External => cs.sends_value || !is_view_call_name(cs.func_name.as_deref()),
        // staticcall is read-only; everything else is not a control transfer.
        _ => false,
    }
}

/// True if this reentry-capable call is to a TRUSTED target (immutable/constant or
/// owner/governance-set infrastructure) and is a plain (non-value, non-transfer)
/// method call — i.e. not an attacker-controlled re-entry surface. Token-transfer
/// methods and value-bearing/low-level calls are never trusted on this basis.
fn is_trusted_call(cs: &CallSite, trusted: &rustc_hash::FxHashSet<String>) -> bool {
    cs.kind == CallKind::External
        && !cs.sends_value
        && !is_token_transfer_name(cs.func_name.as_deref())
        && trusted.contains(sluice_frontier::target_root(&cs.target))
}

/// True iff this `External` call is really a STATELESS-LIBRARY / static-namespace
/// dispatch (`Time.timestamp()`, `Math.max(...)`, `UQ112x112.encode(...)`,
/// `SafeCast.toUint128(...)`) rather than a call into another contract. Such a
/// call runs in-process (an internal `JUMP`), never hands control to attacker
/// code, and therefore can never arm reentrancy.
///
/// The parser already classifies these as `Internal` when the library is in the
/// analyzed source set; the problem is the common case where the library lives in
/// an EXCLUDED dependency tree (`lib/`, `@openzeppelin/…`) and so is invisible to
/// the parser, which then falls back to `External`. We recover the library shape
/// structurally: the call receiver is a BARE PascalCase identifier (`Time`,
/// `UQ112x112`) — a type/library namespace — and NOT a state variable of the
/// contract (a `Pool`-named handle would be a real callee). A receiver that is a
/// member/cast/index/`msg.*` expression (`IFoo(addr)`, `a.b`, `q[i]`, `msg`) is
/// never a bare namespace, so genuine external calls are unaffected. Value-bearing
/// and token-transfer-named calls are excluded for safety: even a namespaced
/// `SafeERC20.safeTransfer(token, …)` ultimately moves tokens and is left armed.
fn is_library_static_call(cs: &CallSite, contract_state_vars: &rustc_hash::FxHashSet<String>) -> bool {
    if cs.kind != CallKind::External || cs.sends_value || is_token_transfer_name(cs.func_name.as_deref()) {
        return false;
    }
    let root = sluice_frontier::target_root(&cs.target);
    // The receiver must be EXACTLY a bare identifier (`target` is the whole
    // receiver text; if it had a `.`/`(`/`[`/space the root would be a prefix of
    // it). Reject anything where the root is not the full target.
    if root != cs.target.trim() {
        return false;
    }
    // PascalCase (type/library convention) and not a declared state variable.
    let mut chars = root.chars();
    let pascal = chars.next().map(|c| c.is_ascii_uppercase()).unwrap_or(false)
        && root.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    pascal && !contract_state_vars.contains(root)
}

/// True iff `ty` (a textual Solidity type) is a VALUE type — a fixed-width
/// numeric/bytes/bool/enum scalar. You cannot make a cross-contract call on a
/// value, so a method invoked on a value-typed receiver is ALWAYS a `using`-bound
/// library dispatch (an internal `JUMP`), never an external re-entry vector.
/// (`address`/`address payable` and capitalized interface/contract types are NOT
/// value types — calls on those can be real external calls and stay armed.)
fn is_value_type_str(ty: &str) -> bool {
    let t = ty.trim();
    t.starts_with("uint")
        || t.starts_with("int")
        || t == "bool"
        || t.starts_with("enum ")
        || (t.starts_with("bytes")
            // `bytes1..bytes32` are value types; dynamic `bytes`/`bytes calldata`
            // are reference types (but still never a call receiver, so harmless).
            && t[5..].chars().next().map(|c| c.is_ascii_digit()).unwrap_or(true))
}

/// The element/value type of a `mapping(K => V)` or `T[]` declaration, if the
/// outer type is a mapping or array. Used to decide whether `m[k].foo()` /
/// `a[i].foo()` invokes a library on a VALUE element (a helper) or on a stored
/// interface/address (a real external call). For nested `mapping(=>mapping(=>V))`
/// we peel to the innermost `V`.
fn mapping_or_array_value_type(ty: &str) -> Option<String> {
    let t = ty.trim();
    if t.starts_with("mapping") {
        // Innermost value type is the segment after the LAST `=>`.
        let after = t.rsplit("=>").next()?.trim();
        // Strip a trailing `)` chain from the nested-mapping close-parens.
        let v = after.trim_end_matches(')').trim();
        return Some(v.to_string());
    }
    if let Some(stripped) = t.strip_suffix("]") {
        // `T[]` / `T[N]` -> element type `T` (drop the `[...]`).
        if let Some(open) = stripped.rfind('[') {
            return Some(stripped[..open].trim().to_string());
        }
    }
    None
}

/// Per-contract facts the detector needs to recognize `using`-bound library /
/// value-helper pseudo-external calls and to reason about config/guard storage.
struct ContractCallFacts {
    /// State-var names whose receiver resolves to a VALUE type: a value-typed
    /// scalar (`bytes32 TOTAL_SHARES_POSITION`, `uint256 x`) or a mapping/array
    /// whose ELEMENT is a value type (`mapping(address=>uint256) shares` ->
    /// `shares[k]`). A method call whose target root is one of these is a bound
    /// library/value helper, never a cross-contract call.
    value_recv_vars: rustc_hash::FxHashSet<String>,
    /// `true` iff the contract has at least one `using L for <valueType>` directive
    /// (the SafeMath/Math/SafeCast/UnstructuredStorage pattern) — the precondition
    /// for treating a value-helper-NAMED call on a non-state receiver
    /// (`localUint.sub(x)`, `userStake.mulDiv(...)`) as a library dispatch.
    binds_value_library: bool,
    /// State-var names that are `constant`/`immutable` — a read of one of these is
    /// a fixed value an attacker cannot corrupt by re-entering, so it can never
    /// seed a cross-function "stale value carried across the call" surface.
    fixed_vars: rustc_hash::FxHashSet<String>,
}

impl ContractCallFacts {
    fn build(contract: Option<&Contract>) -> Self {
        let mut value_recv_vars = rustc_hash::FxHashSet::default();
        let mut fixed_vars = rustc_hash::FxHashSet::default();
        let mut binds_value_library = false;
        if let Some(c) = contract {
            for v in &c.state_vars {
                if v.constant || v.immutable {
                    fixed_vars.insert(v.name.clone());
                }
                let elem = mapping_or_array_value_type(&v.ty);
                let recv_is_value = match &elem {
                    // `m[k]`/`a[i]` receiver is the element type.
                    Some(e) => is_value_type_str(e),
                    // Bare scalar receiver.
                    None => is_value_type_str(&v.ty),
                };
                if recv_is_value {
                    value_recv_vars.insert(v.name.clone());
                }
            }
            // A `using L for <valueType>` (or `using L for *`) binds library methods
            // to value receivers — the marker that helper-named calls on value
            // locals are internal dispatches.
            for u in &c.using_for {
                let binds = match &u.ty {
                    None => true, // `using L for *` binds everything, incl. value types
                    Some(t) => is_value_type_str(t),
                };
                if binds {
                    binds_value_library = true;
                    break;
                }
            }
        }
        ContractCallFacts { value_recv_vars, binds_value_library, fixed_vars }
    }
}

/// A curated set of `using`-bound, side-effect-free VALUE / math / cast / unstructured
/// storage helper method names (SafeMath, Math, SignedMath, FixedPointMath,
/// SafeCast, UnstructuredStorage and the Lido `UnstructuredStorageExt`). These are
/// pure in-process computations on a value/storage-slot receiver and never a
/// cross-contract control transfer, so a call to one cannot arm reentrancy. Only
/// consulted when the contract actually binds a value-type library, so a same-named
/// genuine external method (rare) on a contract that does NOT use such a library is
/// unaffected.
fn is_value_helper_name(name: Option<&str>) -> bool {
    let Some(n) = name else { return false };
    // Prefix families: SafeCast `toUintNN`/`toIntNN`, UnstructuredStorage
    // `setStorageX`/`getStorageX`, FixedPoint `mulDiv*`/`mulWad*`/`divWad*`,
    // Lido `setLowUint*`/`getLowUint*`/`setHighUint*`/`getHighUint*`.
    if n.starts_with("toUint")
        || n.starts_with("toInt")
        || n.starts_with("setStorage")
        || n.starts_with("getStorage")
        || n.starts_with("mulDiv")
        || n.starts_with("mulWad")
        || n.starts_with("divWad")
        || n.starts_with("rayMul")
        || n.starts_with("rayDiv")
        || n.starts_with("wadMul")
        || n.starts_with("wadDiv")
        || n.starts_with("setLowUint")
        || n.starts_with("getLowUint")
        || n.starts_with("setHighUint")
        || n.starts_with("getHighUint")
    {
        return true;
    }
    matches!(
        n,
        "add" | "sub" | "mul" | "div" | "mod" | "pow" | "exp"
            | "min" | "max" | "average" | "ceilDiv" | "sqrt"
            | "log2" | "log10" | "log256" | "abs" | "diff"
            | "tryAdd" | "trySub" | "tryMul" | "tryDiv" | "tryMod"
            | "addMod" | "mulMod"
    )
}

/// True iff this `External`, non-value, non-token-transfer call is really a
/// `using`-bound library / VALUE-helper dispatch rather than a cross-contract call.
/// Two sound sources (mirroring `is_library_static_call`, which handles the bare
/// PascalCase-namespace shape `Time.timestamp()`):
///   * (i) the receiver provably resolves to a VALUE type — a value-typed state
///     var (`TOTAL_SHARES_POSITION_LOW128.setLowUint128`) or a value-element
///     mapping/array element (`shares[k].add`). You cannot call a contract on a
///     `uint256`/`bytes32`, so this is always a `using` library call.
///   * (ii) the contract binds a value-type library (`using SafeMath for uint256`,
///     `using Math for uint256`) AND the method name is a known math/cast/storage
///     helper — covering the receiver-is-a-value-LOCAL case (`currentSenderShares.sub`,
///     `userStake.mulDiv`, `_getTotalShares().add`) where the receiver's value type
///     isn't visible from a state-var declaration.
/// Token-transfer-named and value-bearing calls are excluded for safety: even a
/// `using SafeERC20 for IERC20` `token.safeTransfer(...)` moves tokens and stays
/// armed (the ERC-777/721 hook re-entry surface).
fn is_value_helper_call(cs: &CallSite, facts: &ContractCallFacts) -> bool {
    if cs.kind != CallKind::External || cs.sends_value || is_token_transfer_name(cs.func_name.as_deref()) {
        return false;
    }
    let root = sluice_frontier::target_root(&cs.target);
    // (i) provable value-typed receiver (scalar var, or value-mapping/array element).
    if facts.value_recv_vars.contains(root) {
        return true;
    }
    // (ii) value-library `using` + recognized pure helper method name.
    facts.binds_value_library && is_value_helper_name(cs.func_name.as_deref())
}

/// True iff `name` reads like a CONFIG / time-window / guard scalar — a date,
/// activation/deadline window, limit/cap/threshold, pause/mode/status flag — that
/// an entry guard compares against (`if (block.timestamp >= startClaimDate) ...`,
/// `if (emergencyMode) ...`). A pre-call READ of such a scalar is a permission/state
/// check, not a value an attacker corrupts by re-entering, so it must not seed a
/// cross-function surface (LoopFi `withdraw` reads `startClaimDate`/`loopActivation`/
/// `emergencyMode` before its `msg.sender.call{value:}` while settling balances
/// first — CEI-correct). Kept narrow (config/time/flag words only) so a genuine
/// value/accounting var carried across the call (Pendle `positionData`) is never
/// excluded.
fn is_config_guard_name(name: &str) -> bool {
    let l = name.trim_start_matches('_').to_ascii_lowercase();
    const CONFIG_KEYS: &[&str] = &[
        "date", "time", "activation", "deadline", "start", "end", "delay",
        "period", "window", "duration", "cooldown", "epoch", "cap", "limit",
        "threshold", "maxim", "minim", "enabled", "disabled", "paused", "pause",
        "mode", "status", "phase", "state", "flag", "active", "frozen", "locked",
    ];
    CONFIG_KEYS.iter().any(|k| l.contains(k))
}

/// True iff `f` contains at least one GENUINE (untrusted) reentrancy-capable
/// external/low-level call that actually ARMS reentrancy (untrusted, and not an
/// internal guard/assert helper). A function with none of these cannot be
/// re-entered, so it must never trip a classic/cross-function reentrancy rule.
fn has_genuine_reentry_vector(
    f: &Function,
    trusted: &rustc_hash::FxHashSet<String>,
    state_vars: &rustc_hash::FxHashSet<String>,
    facts: &ContractCallFacts,
) -> bool {
    f.effects.call_sites.iter().any(|cs| is_arming_call(cs, trusted, state_vars, facts))
}

/// True iff the arming external call is a low-level/value call to a
/// CALLER-SUPPLIED target (`msg.sender`, a `target`/`to`/`recipient` parameter,
/// an attacker-passed `token`) — the strongest re-entry surface, where the
/// attacker fully controls the re-entered code. Used to gate the Critical
/// severity escalation: a classic finding only deserves Critical when the callee
/// is caller-controlled, not when it is merely an unrecognized in-protocol call.
fn has_caller_supplied_value_vector(
    f: &Function,
    trusted: &rustc_hash::FxHashSet<String>,
    state_vars: &rustc_hash::FxHashSet<String>,
    facts: &ContractCallFacts,
) -> bool {
    f.effects.call_sites.iter().any(|cs| {
        is_arming_call(cs, trusted, state_vars, facts)
            && cs.sends_value
            && {
                let root = sluice_frontier::target_root(&cs.target).to_ascii_lowercase();
                root == "msg"
                    || root.contains("recipient")
                    || root.contains("sender")
                    || root == "to"
                    || root == "target"
                    || root == "receiver"
                    || root == "caller"
                    || root == "token"
            }
    })
}

/// True iff `name` reads like a VALUE / balance / accounting state variable — the
/// only storage whose post-call corruption is the classic reentrancy payday
/// (drain a balance, double-count a share, inflate a deposit). Every real-hack
/// reentrancy fixture writes such a var after its call (`balances`,
/// `accountBorrows`, `totalSupply`, `assetBalances`, `supplyShares`, `reserveETH`,
/// `refundModeCredit`, …). A write to an unrelated bool/flag/registry/status var
/// (`isFeatureEnabled`, `initialized`, `status`, `claimData`, `_disputeGames`,
/// `l2Sender`, `drips`) is bookkeeping, not value at risk, and is the dominant
/// classic false-positive shape (Optimism `SystemConfig.setFeature`).
fn is_value_state_var(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    const VALUE_KEYS: &[&str] = &[
        "balance", "borrow", "supply", "deposit", "share", "underlying", "reserve",
        "credit", "collateral", "amount", "stake", "debt", "principal", "asset",
        "liquidity", "funds", "owed", "escrow", "withdraw", "redeem", "payout",
        "vault", "token", "reward", "ledger", "accru",
    ];
    VALUE_KEYS.iter().any(|k| l.contains(k))
}

/// True iff `name` is an INTERNAL guard / assertion helper — a function whose sole
/// job is to authorize or revert (`_assertOnlyOwner`, `_checkRole`, `_onlyAdmin`,
/// `_requireNotPaused`). A call to one of these is a CHECK, never the external
/// re-entry vector that arms a reentrancy finding, even if (mis)modeled as a call
/// site. (Optimism `SystemConfig.setFeature` opens with
/// `_assertOnlyProxyAdminOrProxyAdminOwner()`.)
fn is_guard_helper_name(name: Option<&str>) -> bool {
    let Some(n) = name else { return false };
    let l = n.trim_start_matches('_').to_ascii_lowercase();
    l.starts_with("assert")
        || l.starts_with("check")
        || l.starts_with("require")
        || l.starts_with("only")
        || l.starts_with("verify")
        || l.starts_with("validate")
        || l.starts_with("ensure")
}

/// A reentry-capable call site that genuinely ARMS reentrancy: an untrusted
/// re-entry vector that is NOT an internal guard/assert helper, NOT a
/// stateless-library / static-namespace dispatch, and NOT a `using`-bound
/// value/math/storage-helper call. The guard-helper exclusion is the
/// `setFeature`-shape protection (an `_assertOnly*()` check must never be read as
/// the arming external call); the library-static exclusion is the
/// `Time.timestamp()` / `UQ112x112.encode()` shape (a pure in-process library call
/// mis-classified `External` because the library lives in an excluded dependency
/// tree); the value-helper exclusion is the SafeMath/UnstructuredStorage shape
/// (`x.sub(y)`, `shares[k].add(a)`, `SLOT.setLowUint128(v)`, `userStake.mulDiv(...)`)
/// — a method on a value/storage receiver that is `using`-bound to an excluded
/// library and so mis-classified `External`. None of these hands control to an
/// external party, so none can be re-entered. (Lido StETH `_mintShares`/
/// `_burnShares`/`_transferShares` and LoopFi `_claim` are armed by exactly such
/// mis-classified value-helper calls.)
fn is_arming_call(
    cs: &CallSite,
    trusted: &rustc_hash::FxHashSet<String>,
    state_vars: &rustc_hash::FxHashSet<String>,
    facts: &ContractCallFacts,
) -> bool {
    is_reentry_vector(cs)
        && !is_trusted_call(cs, trusted)
        && !is_guard_helper_name(cs.func_name.as_deref())
        && !is_library_static_call(cs, state_vars)
        && !is_value_helper_call(cs, facts)
}

/// True iff `f` performs a storage WRITE to one of `vars` STRICTLY AFTER a
/// genuine (untrusted) reentrancy-capable external call, AND that written var is
/// VALUE/balance state (the thing re-entry actually corrupts), AND that var was
/// NOT already SETTLED (written) before the first arming call. This is the
/// concrete classic checks-effects-interactions violation: a value write whose
/// position index is greater than the arming call's index.
///
/// The settle-before-the-call exclusion is the CEI-downgrade rule. In a genuine
/// classic drain the vulnerable slot is read before and written ONLY after the
/// call (`balances[msg.sender] -= amt` with no pre-call balances write). When the
/// SAME var is also written before the call, the function settles it before
/// interacting (LoopFi `_claim` zeroes `balances` before `lpETH.safeTransfer`, and
/// the other-branch `balances` write only trails a sibling branch's call;
/// `_processLock` credits balances/totalSupply before the WETH branch and only the
/// non-ETH branch trails `safeTransferFrom`). A var settled before the arming call
/// is CEI-correct on every path it is interacted on, so its later (cross-branch)
/// write is not the vulnerable post-call update — suppress it.
fn has_qualifying_post_call_write(
    f: &Function,
    vars: &[String],
    trusted: &rustc_hash::FxHashSet<String>,
    state_vars: &rustc_hash::FxHashSet<String>,
    facts: &ContractCallFacts,
) -> bool {
    let first_vector = f
        .effects
        .call_sites
        .iter()
        .filter(|cs| is_arming_call(cs, trusted, state_vars, facts))
        .map(|cs| cs.order)
        .min();
    let Some(first) = first_vector else { return false };
    // Vars SETTLED (written) before the first arming call — CEI-correct; their
    // later writes are not the vulnerable post-call update.
    let settled_before: rustc_hash::FxHashSet<&str> = f
        .effects
        .storage_writes
        .iter()
        .filter(|w| w.order < first)
        .map(|w| w.var.as_str())
        .collect();
    f.effects.storage_writes.iter().any(|w| {
        w.order > first
            && is_value_state_var(&w.var)
            && !settled_before.contains(w.var.as_str())
            && vars.iter().any(|v| v == &w.var)
    })
}

/// True iff the arming call is a PLAIN, NON-value, NON-token-transfer `External`
/// method call (`market.setReserveRatioBips(x)`) — NOT a value-bearing or low-level
/// (`.call{value:}`) call and NOT a token-transfer-named method (`transfer`,
/// `safeTransferFrom`, …). Such a call hands control to another contract but moves
/// no native value through this call site and does not invoke an ERC-20/777/721
/// transfer hook from here, so re-entering it cannot directly extract funds via the
/// call itself. It is the weakest re-entry surface — the precondition for the
/// benign cleanup-delete suppression below.
fn is_plain_nonvalue_call(cs: &CallSite) -> bool {
    cs.kind == CallKind::External
        && !cs.sends_value
        && !is_token_transfer_name(cs.func_name.as_deref())
}

/// True iff a post-call storage write is a `delete` / in-place RESET of the SAME
/// slot — a cleanup, not a value-bearing mutation an attacker could profit from by
/// re-entering. The robust structural signature (the IR does not tag `delete`
/// explicitly) is: the written PATH is also READ at the IDENTICAL path immediately
/// before the write (a `delete X[k]` lowers to a read of `X[k]` followed by a write
/// of `X[k]`; an in-place `X[k] = X[k] - n` / `X[k] -= n` shares the same shape, but
/// those are gated out by `is_plain_nonvalue_call` — a real `-=` drain always pairs
/// with a value/transfer call, never a plain method call). A genuine drain writes
/// either a *fresh-computed* value (`balances[u] = bal - amt`, where the write path
/// is NOT read just before) or zeroes a slot via a plain `= 0` assign (xsurge), and
/// xsurge's call is low-level+value — so neither matches this read-then-write-same-
/// path-after-plain-call shape.
fn is_same_slot_reset(reads: &[sluice_ir::StorageAccess], write: &sluice_ir::StorageAccess) -> bool {
    // The delete/in-place-reset signature: a read of the EXACT same access path,
    // positioned immediately before the write (one slot earlier in source order).
    reads
        .iter()
        .any(|r| r.order + 1 == write.order && r.path == write.path)
}

/// True iff the classic post-call write surface of `f` is the BENIGN
/// cleanup-delete-after-a-trusted-plain-call shape and must be suppressed:
///   (b) the FIRST arming call is a plain, non-value, non-token-transfer `External`
///       method call (`WildcatMarket(market).setReserveRatioBips(...)`), AND
///   (a) EVERY value-state write strictly after that call is a `delete` / in-place
///       reset of the same slot (a cleanup of a per-key temporary record), with at
///       least one such post-call write present.
/// This is the WildcatMarketController `resetReserveRatio` shape: a plain guarded
/// call into a protocol market followed by `delete temporaryExcessReserveRatio[market]`.
/// Re-entry cannot profit — the call moves no value and the only after-effect zeroes
/// an idempotent temporary slot. Kept tight: ANY value-bearing / low-level / token-
/// transfer arming call, or ANY post-call value write that is NOT a same-slot reset
/// (a fresh-computed balance update — the real drain), defeats the suppression.
fn is_benign_cleanup_delete(
    f: &Function,
    trusted: &rustc_hash::FxHashSet<String>,
    state_vars: &rustc_hash::FxHashSet<String>,
    facts: &ContractCallFacts,
) -> bool {
    // The arming calls and the first (earliest) one.
    let arming: Vec<&CallSite> = f
        .effects
        .call_sites
        .iter()
        .filter(|cs| is_arming_call(cs, trusted, state_vars, facts))
        .collect();
    let Some(first) = arming.iter().map(|cs| cs.order).min() else { return false };
    // (b) EVERY arming call must be a plain non-value method call. If any arming
    // call is value-bearing / low-level / a token transfer, this is not the benign
    // shape (a value send could itself extract funds on re-entry).
    if !arming.iter().all(|cs| is_plain_nonvalue_call(cs)) {
        return false;
    }
    // (a) consider the value-state writes strictly after the first arming call.
    let post_call_value_writes: Vec<&sluice_ir::StorageAccess> = f
        .effects
        .storage_writes
        .iter()
        .filter(|w| w.order > first && is_value_state_var(&w.var))
        .collect();
    // There must be at least one (otherwise nothing to suppress), and EVERY one of
    // them must be a same-slot reset/`delete`. A single fresh-computed value write
    // (the genuine drain) defeats the suppression.
    !post_call_value_writes.is_empty()
        && post_call_value_writes
            .iter()
            .all(|w| is_same_slot_reset(&f.effects.storage_reads, w))
}

/// True iff the read-only-flagged getter `f` (or one of its DIRECTLY resolved
/// internal callees) performs a genuine reentrancy-capable external/low-level call
/// in its OWN body. Read-only reentrancy is only reportable when the getter itself
/// hands control out mid-read; a getter that merely returns a storage read
/// (`getReserves`, `totalOperatorNetworkSharesAt` — a pure `upperLookupRecent`
/// library lookup) makes no external call and therefore cannot expose mid-update
/// state through its own execution. We look at the getter's own call sites and its
/// directly resolved callees (`f.callees`) — NOT an inherited superclass chain and
/// NOT a transitive closure — matching the precision contract exactly.
fn readonly_getter_has_own_call(
    cx: &AnalysisContext,
    f: &Function,
    trusted: &rustc_hash::FxHashSet<String>,
    state_vars: &rustc_hash::FxHashSet<String>,
    facts: &ContractCallFacts,
) -> bool {
    if has_genuine_reentry_vector(f, trusted, state_vars, facts) {
        return true;
    }
    f.callees.iter().any(|cid| {
        cx.scir.function(*cid).is_some_and(|callee| {
            // A callee in another contract resolves its own trusted set; reuse the
            // getter's (a superset of immutable/infra names) as a safe approximation
            // — the only goal is to detect a REAL external/low-level call there.
            has_genuine_reentry_vector(callee, trusted, state_vars, facts)
        })
    })
}

/// True iff `f` exposes a GENUINE cross-function re-entry surface across its
/// external call: it either (a) writes some storage STRICTLY AFTER the call
/// (leaving shared state mid-update — the revest double-mint shape, and the
/// deferred-write case where the post-call write lives in a callee is still
/// covered by (b) via the read-before var), or (b) reads BEFORE the call a storage
/// var it does NOT settle (write) before the call and that is not a trusted
/// governance/config address — a value it carries across the re-entry window
/// (Pendle `increaseLockPosition`'s `positionData`).
///
/// A function that SETTLES every var it reads before the call (writes the new
/// value before interacting — CEI) and whose only other pre-call reads are
/// trusted config/guard addresses, constants, or config/time/flag scalars, with
/// NO post-call write, has nothing for a re-entrant sibling to corrupt. That is
/// the v4 `collectProtocolFees` shape (`protocolFeesAccrued` decremented before
/// `currency.transfer`, guard read `protocolFeeController`) and the LoopFi
/// `withdraw` shape (`balances`/`totalSupply` settled before `msg.sender.call`, the
/// only other pre-call reads being the `startClaimDate`/`loopActivation` window
/// dates and `emergencyMode` flag) — both CEI-correct.
fn has_cross_function_surface(
    f: &Function,
    trusted: &rustc_hash::FxHashSet<String>,
    state_vars: &rustc_hash::FxHashSet<String>,
    facts: &ContractCallFacts,
) -> bool {
    let Some(first) = f
        .effects
        .call_sites
        .iter()
        .filter(|cs| is_arming_call(cs, trusted, state_vars, facts))
        .map(|cs| cs.order)
        .min()
    else {
        return false;
    };
    // (a) any storage write strictly after the external call — state left
    // mid-update for a re-entrant sibling.
    if f.effects.storage_writes.iter().any(|w| w.order > first) {
        return true;
    }
    // (b) a pre-call read of a var that is a genuine value carried across the
    // re-entry window: NOT settled before the call, NOT a trusted governance/config
    // ADDRESS, NOT a `constant`/`immutable` (a fixed value re-entry cannot corrupt),
    // and NOT a config/time/flag/limit scalar read in an entry guard. A genuine
    // accounting var carried across the call (Pendle `positionData`) matches none
    // of these exclusions and is still surfaced.
    let written_before: rustc_hash::FxHashSet<&str> = f
        .effects
        .storage_writes
        .iter()
        .filter(|w| w.order < first)
        .map(|w| w.var.as_str())
        .collect();
    f.effects.storage_reads.iter().any(|r| {
        r.order < first
            && !written_before.contains(r.var.as_str())
            && !is_trusted_state_name(&r.var)
            && !facts.fixed_vars.contains(r.var.as_str())
            && !is_config_guard_name(&r.var)
    })
}

/// True iff `name` reads like a trusted governance/config/guard ADDRESS variable —
/// a `*controller`/`*owner`/`*admin`/`*authority`/`*governor`/`*registry`/… handle
/// that an entry guard compares against (`if (msg.sender != protocolFeeController)`).
/// A pre-call read of such a var is a permission check, not value carried across
/// the re-entry window, so it must not seed a cross-function finding.
fn is_trusted_state_name(name: &str) -> bool {
    let l = name.trim_start_matches('_').to_ascii_lowercase();
    const TRUSTED: &[&str] = &[
        "controller", "owner", "admin", "authority", "governor", "governance",
        "registry", "factory", "manager", "guardian", "role", "timelock",
        "comptroller", "oracle", "feed",
    ];
    TRUSTED.iter().any(|k| l.contains(k))
}

impl Detector for ReentrancyDetector {
    fn id(&self) -> &'static str {
        "reentrancy"
    }
    fn category(&self) -> Category {
        Category::Reentrancy
    }
    fn description(&self) -> &'static str {
        "External call before state update (classic, cross-function, read-only)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // Trusted call targets for f's contract: immutable/constant + the
            // owner/governance-set infrastructure names, PLUS the contract's own
            // no-arg view/pure getters (`weth()`, `optimismPortal()`). Used to
            // discount calls into in-protocol modules
            // (`distributor`/`treasury`/`veFXS`/a getter-dispatched module). This
            // mirrors the frontier exactly so detector and producer agree.
            let trusted = sluice_frontier::reentrancy_trusted_targets(cx.scir, f.contract);
            // Declared state-variable names of f's contract — used to tell a
            // stateless-library namespace (`Time`, `UQ112x112`) apart from a real
            // contract handle stored in a (rare PascalCase) state var.
            let state_vars: rustc_hash::FxHashSet<String> = cx
                .scir
                .contract(f.contract)
                .map(|c| c.state_vars.iter().map(|v| v.name.clone()).collect())
                .unwrap_or_default();
            // Per-contract call facts: which receivers resolve to a VALUE type (so a
            // method on them is a `using`-bound library/value helper, not a
            // cross-contract call), whether the contract binds a value-type library,
            // and the constant/immutable var set. Lets the gates below see through
            // SafeMath/UnstructuredStorage `x.sub(y)` / `SLOT.setLowUint128(v)`
            // pseudo-external calls that the parser fell back to `External` because
            // the library lives in an excluded dependency tree.
            let call_facts = ContractCallFacts::build(cx.scir.contract(f.contract));

            for r in cx.frontier.reentrancy_of(f.id) {
                if r.guarded || cx.has_reentrancy_guard(f) {
                    continue;
                }

                // PRECISION GATE 1 — a reentrancy finding must be backed by a
                // genuine external/low-level call on the path that produced it.
                // For read-only the call lives on the mutating writer path; for
                // classic/cross-function it is the flagged function's own call.
                // A risk with no backing call is never reportable.
                if !r.backed_by_call {
                    continue;
                }

                match r.kind {
                    // Classic and cross-function both flag the function that MAKES
                    // the external call, so that function must itself contain a
                    // genuine (untrusted) re-entry vector.
                    ReentrancyKind::Classic | ReentrancyKind::CrossFunction => {
                        if !has_genuine_reentry_vector(f, &trusted, &state_vars, &call_facts) {
                            // No external/low-level call at all, every such call
                            // targets trusted infrastructure (the
                            // harvest-calls-`distributor`/`treasury` class), or the
                            // only "call" is a stateless-library dispatch
                            // (`Time.timestamp()`/`UQ112x112.encode()` — the
                            // VaultTokenized `_update`/`setOperatorNetworkShares`
                            // shape). Not an open re-entry surface — suppress.
                            continue;
                        }
                    }
                    // Read-only flags a view getter. Per the precision contract it
                    // is reportable ONLY when the getter ITSELF (or a directly
                    // resolved internal callee) makes a genuine external/low-level
                    // call mid-read — a pure storage-read getter (`getReserves`,
                    // `totalOperatorNetworkSharesAt`) cannot expose mid-update state
                    // through its own execution and must stay silent, regardless of
                    // what a sibling mutating writer does.
                    ReentrancyKind::ReadOnly => {
                        if !readonly_getter_has_own_call(cx, f, &trusted, &state_vars, &call_facts) {
                            continue;
                        }
                    }
                }

                // PRECISION GATE 2 (classic only) — require a storage write
                // STRICTLY AFTER the external call. A state update that precedes
                // the call (`executed = true;` before a timelock call) is the safe
                // checks-effects shape, not the vulnerable post-call update; and if
                // there is no post-call write at all (a one-line transfer), there
                // is nothing for re-entry to corrupt.
                if r.kind == ReentrancyKind::Classic
                    && !has_qualifying_post_call_write(f, &r.vars_written_after, &trusted, &state_vars, &call_facts)
                {
                    continue;
                }

                // PRECISION GATE 2c (classic only) — benign cleanup-delete shape.
                // Suppress when the arming call is a plain, non-value, non-token-
                // transfer `External` method call (no `{value:}`, no `.call`) AND
                // the only post-call value-state effect is a `delete` / in-place
                // reset of the same slot (a cleanup of a per-key temporary record).
                // Re-entering such a call moves no value and the after-effect only
                // zeroes an idempotent slot, so there is nothing to profit from —
                // the WildcatMarketController `resetReserveRatio` shape
                // (`market.setReserveRatioBips(...)` then `delete temp[market]`). A
                // value-bearing / low-level / token-transfer call, or a fresh-
                // computed balance update after the call, is never suppressed here.
                if r.kind == ReentrancyKind::Classic
                    && is_benign_cleanup_delete(f, &trusted, &state_vars, &call_facts)
                {
                    continue;
                }

                // PRECISION GATE 2b (cross-function only) — require a genuine
                // cross-function surface on f: state left written AFTER the call, or
                // an unsettled, non-config pre-call read carried across the call. A
                // CEI-correct function that settles every value it reads before the
                // call and only otherwise reads a trusted config/guard address, with
                // no post-call write, is not re-enterable into harm (v4
                // `collectProtocolFees`: decrement before `currency.transfer`).
                if r.kind == ReentrancyKind::CrossFunction
                    && !has_cross_function_surface(f, &trusted, &state_vars, &call_facts)
                {
                    continue;
                }

                // Access-controlled functions can only be entered by a trusted
                // actor, so reentrancy risk is much lower. Cross-function (the
                // weakest signal) is dropped entirely there; classic/read-only are
                // downgraded to a low confidence so they sink to Low/Info.
                let access_controlled = cx.has_access_control(f);
                if access_controlled && r.kind == ReentrancyKind::CrossFunction {
                    continue;
                }
                let (cat, sev, conf, title) = match r.kind {
                    ReentrancyKind::Classic => (
                        Category::Reentrancy,
                        sluice_findings::Severity::High,
                        0.8,
                        "State updated after external call (classic reentrancy)",
                    ),
                    ReentrancyKind::ReadOnly => (
                        Category::ReadOnlyReentrancy,
                        sluice_findings::Severity::High,
                        0.6,
                        "View getter exposes mid-update state (read-only reentrancy)",
                    ),
                    ReentrancyKind::CrossFunction => (
                        Category::Reentrancy,
                        sluice_findings::Severity::Medium,
                        0.55,
                        "Shared state reachable during external call (cross-function reentrancy)",
                    ),
                };
                let conf = if access_controlled { conf * 0.5 } else { conf };
                let mut b = FindingBuilder::new(self.id(), cat)
                    .title(title)
                    .severity(sev)
                    .confidence(conf)
                    .dimension(Dimension::Frontier)
                    .message(format!(
                        "`{}` performs an external call and then touches storage [{}]. An attacker \
                         contract can re-enter before state settles. {}",
                        f.name,
                        r.vars_written_after.join(", "),
                        match r.kind {
                            ReentrancyKind::ReadOnly =>
                                "A consumer reading this getter mid-transaction sees corrupted values.",
                            ReentrancyKind::CrossFunction =>
                                "Re-entering a sibling function that shares this state is profitable.",
                            ReentrancyKind::Classic => "This is the DAO/Curve-class pattern.",
                        }
                    ))
                    .recommendation(
                        "Apply checks-effects-interactions (update storage before the external call) \
                         and/or a `nonReentrant` guard covering all entry points sharing this state.",
                    );
                // Value-flow corroboration — and the Critical-severity cap (d).
                // The final label is promoted to Critical only at THREE
                // corroborating dimensions; Frontier+Invariant alone settle at
                // High. We therefore add the ValueFlow dimension (the third) ONLY
                // when re-entry is genuinely attacker-controlled: a value-bearing
                // call to a CALLER-SUPPLIED target with a value-state write strictly
                // after it (the `reentrancy.sol`/`curve_vyper` drain shape). A
                // value send to an in-protocol/getter-dispatched callee, or a
                // classic with no caller-supplied value vector, stays capped at
                // High — so an unrecognized in-protocol call can no longer over-rank
                // to Critical (the `claimCredit` shape). Read-only / cross-function
                // keep their existing value-flow corroboration.
                let caller_supplied_value = has_caller_supplied_value_vector(f, &trusted, &state_vars, &call_facts);
                let add_value_flow = match r.kind {
                    ReentrancyKind::Classic => caller_supplied_value,
                    _ => f.effects.call_sites.iter().any(|c| c.sends_value),
                };
                if add_value_flow {
                    b = b.dimension(Dimension::ValueFlow);
                }
                out.push(cx.finish(b, f.id, r.span));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyze_sources, Config};

    /// All reentrancy-detector findings for a source blob.
    fn reentrancy_findings(src: &str) -> Vec<Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default())
            .findings
            .into_iter()
            .filter(|f| f.detector == "reentrancy")
            .collect()
    }

    fn fires(src: &str) -> bool {
        !reentrancy_findings(src).is_empty()
    }

    // ---- FP1: a view getter with ZERO external calls must stay silent. ----
    // etherfi WithdrawRequestNFT.isScan…: a pure getter that returns a comparison
    // of two storage reads. With no vulnerable mutating writer and no external
    // call anywhere, nothing can seed a read-only risk.
    #[test]
    fn silent_on_view_getter_with_zero_calls() {
        let src = r#"
            contract WithdrawRequestNFT {
                uint256 public lastFinalizedRequestId;
                uint256 public nextRequestId;
                // pure comparison of two storage reads, no external call at all.
                function isScanRequested(uint256 id) external view returns (bool) {
                    return id <= lastFinalizedRequestId && id < nextRequestId;
                }
                function shareValue() external view returns (uint256) {
                    return lastFinalizedRequestId * nextRequestId; // oracle-ish name, still no call
                }
            }
        "#;
        assert!(!fires(src), "read-only reentrancy must not fire on a call-free view getter");
    }

    // ---- FP2: a storage write BEFORE the external call must not fire classic. ----
    // olympus GovernorOHMegaDelegate.execute: `proposal.executed = true;` is set
    // BEFORE the call; checks-effects order is correct. The external call here is a
    // genuine, untrusted low-level call (to an arbitrary `target` param), so the
    // ONLY reason this stays silent is the write-precedes-call rule.
    #[test]
    fn silent_on_write_before_call() {
        let src = r#"
            contract Governor {
                mapping(uint256 => bool) public executed;
                function execute(uint256 id, address target, bytes calldata d) external {
                    require(!executed[id], "already");
                    executed[id] = true;            // WRITE before the call (CEI-correct)
                    (bool ok,) = target.call(d);    // genuine untrusted external call AFTER the write
                    require(ok, "exec failed");
                }
            }
        "#;
        assert!(
            !fires(src),
            "classic reentrancy must not fire when the only state write precedes the external call"
        );
    }

    // ---- FP3: a harvest that calls an immutable/trusted module then writes
    // unrelated state must stay silent (trusted call target). ----
    #[test]
    fn silent_on_harvest_calling_immutable_distributor() {
        let src = r#"
            interface IDistributor { function distribute() external; }
            contract Staking {
                IDistributor public immutable distributor; // trusted: immutable module
                uint256 public lastHarvest;
                uint256 public epoch;
                constructor(IDistributor d) { distributor = d; }
                function harvest() external {
                    uint256 prev = lastHarvest;       // read before
                    distributor.distribute();         // plain call to a trusted immutable module
                    lastHarvest = block.timestamp;    // write after — but target is trusted
                    epoch = prev + 1;
                }
            }
        "#;
        assert!(
            !fires(src),
            "reentrancy must not fire when the only external call targets a trusted immutable module"
        );
    }

    // FP3 variant: an owner/governance-set (non-immutable) trusted-named module is
    // also discounted via the extended trusted-target name set.
    #[test]
    fn silent_on_harvest_calling_named_treasury() {
        let src = r#"
            interface ITreasury { function deposit(uint256 a) external; }
            contract Vault {
                ITreasury public treasury;   // owner-set, but trusted-named infrastructure
                uint256 public totalHarvested;
                function setTreasury(ITreasury t) external { treasury = t; }
                function harvest(uint256 amount) external {
                    uint256 prev = totalHarvested;  // read before
                    treasury.deposit(amount);       // plain call to trusted-named module
                    totalHarvested = prev + amount; // write after, but trusted target
                }
            }
        "#;
        assert!(
            !fires(src),
            "reentrancy must not fire when the only external call targets a trusted-named module"
        );
    }

    // ---- FP4: a one-line transfer with NO post-call state write must stay
    // silent. olympus OhmFaucet.dispense. ----
    #[test]
    fn silent_on_dispense_with_no_post_call_write() {
        let src = r#"
            interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
            contract OhmFaucet {
                IERC20 public ohm;
                uint256 public dripAmount;
                function dispense() external {
                    ohm.transfer(msg.sender, dripAmount); // single transfer, no state write after
                }
            }
        "#;
        assert!(
            !fires(src),
            "reentrancy must not fire when there is no state write after the external call"
        );
    }

    // ---- TRUE POSITIVE: classic write-after-call must still fire. ----
    // `msg.sender.call{value:amt}(""); balances[msg.sender] -= amt;` — the write
    // lands STRICTLY AFTER the external call. The leading `require(amt > 0)` does
    // not reference msg.sender, so this is not treated as access-controlled and
    // the finding surfaces at full confidence.
    #[test]
    fn fires_on_classic_write_after_call() {
        let src = r#"
            contract Bank {
                mapping(address => uint256) public balances;
                function deposit() external payable { balances[msg.sender] += msg.value; }
                function withdraw(uint256 amt) external {
                    require(amt > 0, "zero");
                    uint256 bal = balances[msg.sender];       // storage READ before the call
                    require(bal >= amt, "insufficient");
                    (bool ok,) = msg.sender.call{value: amt}(""); // external call first
                    require(ok, "fail");
                    balances[msg.sender] -= amt;              // WRITE strictly after the call
                }
            }
        "#;
        let fs = reentrancy_findings(src);
        assert!(
            fs.iter().any(|f| f.category == Category::Reentrancy),
            "classic reentrancy (write strictly after the external call) must fire"
        );
    }

    // ---- FP5 (claimCredit shape): write-before-call, then a call dispatched off
    // a no-arg view/pure getter that returns an in-protocol immutable module, must
    // stay silent. Optimism `FaultDisputeGame.claimCredit`: `hasUnlockedCredit[r]`
    // is set BEFORE `weth().unlock(...)` (CEI-correct), and the later value writes
    // (`refundModeCredit`/`normalModeCredit`) follow ONLY trusted `weth()` calls;
    // the one genuine caller-supplied value call has no write after it. ----
    #[test]
    fn silent_on_write_before_getter_dispatched_trusted_call() {
        let src = r#"
            interface IWETH {
                function unlock(address a, uint256 v) external;
                function withdraw(address a, uint256 v) external;
            }
            contract FaultDisputeGame {
                mapping(address => bool) public hasUnlockedCredit;
                mapping(address => uint256) public refundModeCredit;
                mapping(address => uint256) public normalModeCredit;
                // no-arg pure getter returning a clones-with-immutable-args module
                function weth() public pure returns (IWETH) { return IWETH(address(1)); }
                function claimCredit(address _recipient) external {
                    uint256 c = refundModeCredit[_recipient];      // read before
                    if (!hasUnlockedCredit[_recipient]) {
                        hasUnlockedCredit[_recipient] = true;      // flag write BEFORE the call
                        weth().unlock(_recipient, c);              // trusted getter-dispatched call
                        return;
                    }
                    refundModeCredit[_recipient] = 0;              // value writes follow trusted calls only
                    normalModeCredit[_recipient] = 0;
                    weth().withdraw(_recipient, c);
                    (bool ok,) = _recipient.call{value: c}("");    // caller-supplied call has NO write after
                    require(ok, "fail");
                }
            }
        "#;
        assert!(
            !fires(src),
            "claimCredit shape (write-before-call then trusted getter-dispatched call) must stay silent"
        );
    }

    // ---- FP6 (setFeature shape): an internal `_assertOnly*()` guard followed by a
    // write to a NON-value bool feature flag must stay silent. Optimism
    // `SystemConfig.setFeature`: opens with `_assertOnlyProxyAdminOrProxyAdminOwner()`
    // (an internal guard, not an external re-entry vector) and the only state write
    // is `isFeatureEnabled` — a bool flag, not value/balance state. ----
    #[test]
    fn silent_on_assert_guard_then_flag_write() {
        let src = r#"
            interface IPortal { function ethLockbox() external returns (address); }
            contract SystemConfig {
                mapping(bytes32 => bool) public isFeatureEnabled;
                function _assertOnlyProxyAdminOrProxyAdminOwner() internal view { require(true); }
                function optimismPortal() public view returns (address) { return address(2); }
                function setFeature(bytes32 _feature, bool _enabled) external {
                    _assertOnlyProxyAdminOrProxyAdminOwner();        // internal guard, not a re-entry vector
                    if (_enabled == isFeatureEnabled[_feature]) revert();   // read before
                    address lb = IPortal(optimismPortal()).ethLockbox();    // external getter call
                    require(lb != address(0) || _enabled, "x");
                    isFeatureEnabled[_feature] = _enabled;           // write AFTER — but a bool flag, not value state
                }
            }
        "#;
        assert!(
            !fires(src),
            "setFeature shape (internal assert guard, then a non-value flag write) must stay silent"
        );
    }

    // The Critical cap (d): a classic finding whose value-bearing call targets a
    // caller-supplied address (the genuine drain shape) is still allowed to carry
    // the ValueFlow dimension, so it can corroborate up. This guards that the cap
    // is a precision fix, not a blanket downgrade that would weaken true positives.
    #[test]
    fn caller_supplied_value_keeps_value_flow_dimension() {
        let src = r#"
            contract Bank {
                mapping(address => uint256) public balances;
                function withdraw(uint256 amt) external {
                    uint256 bal = balances[msg.sender];
                    require(bal >= amt);
                    (bool ok,) = msg.sender.call{value: amt}("");  // caller-supplied value call
                    require(ok);
                    balances[msg.sender] = bal - amt;              // value write strictly after
                }
            }
        "#;
        let fs = reentrancy_findings(src);
        let classic = fs.iter().find(|f| f.title.contains("classic")).expect("classic must fire");
        assert!(
            classic.dimensions.contains(&Dimension::ValueFlow),
            "a caller-supplied value re-entry must retain the ValueFlow corroboration dimension"
        );
    }

    /// R28 FP1 — read-only reentrancy on a pure storage-read view getter.
    /// Real sites: gte `GTELaunchpadV2Pair.getReserves` (returns three reserve
    /// slots) and symbiotic `NetworkRestakeDelegator.totalOperatorNetworkSharesAt`
    /// (a single `upperLookupRecent` library lookup). The getter makes NO external
    /// call of its own, so it cannot expose mid-update state through its own
    /// execution — read-only reentrancy must stay silent even though a mutating
    /// writer (`_update`) updates the same reserves after an (in this fixture,
    /// genuine) external call. The classic finding on the writer may still fire;
    /// only the read-only finding on the getter is suppressed.
    #[test]
    fn silent_on_readonly_view_getter_without_own_call() {
        // `getReserves` shape: oracle-named value getter, pure storage reads, no call.
        let src = r#"
            interface IERC20 { function balanceOf(address) external view returns (uint256); }
            contract Pair {
                uint112 private reserve0;
                uint112 private reserve1;
                uint32  private blockTimestampLast;
                address public token0;
                // Read by integrators as a price/reserve oracle, but makes NO call.
                function getReserves() public view returns (uint112 r0, uint112 r1, uint32 t) {
                    r0 = reserve0; r1 = reserve1; t = blockTimestampLast;
                }
                // Mutating writer with a genuine external token call before the writes.
                function sync() external {
                    uint256 bal = IERC20(token0).balanceOf(address(this)); // staticcall-ish read
                    (bool ok,) = token0.call(""); require(ok);             // genuine external call
                    reserve0 = uint112(bal);                               // write after the call
                    blockTimestampLast = uint32(block.timestamp);
                }
            }
        "#;
        let fs = reentrancy_findings(src);
        assert!(
            !fs.iter().any(|f| f.category == Category::ReadOnlyReentrancy),
            "read-only reentrancy must not fire on a pure storage-read getter with no call of its own"
        );
    }

    /// R28 FP1 — the `totalOperatorNetworkSharesAt` shape: the getter's only "call"
    /// is an internal stateless-library lookup (`upperLookupRecent`), which is not
    /// an external re-entry vector. Read-only must stay silent.
    #[test]
    fn silent_on_readonly_getter_with_only_library_lookup() {
        let src = r#"
            library Checkpoints {
                struct Trace { uint256 v; }
                function upperLookupRecent(Trace storage t, uint48 ts) internal view returns (uint256) { return t.v; }
                function push(Trace storage t, uint48 ts, uint256 x) internal { t.v = x; }
            }
            contract Delegator {
                using Checkpoints for Checkpoints.Trace;
                mapping(bytes32 => Checkpoints.Trace) internal _shares;
                // value-oracle-named getter whose only call is a library lookup
                function totalOperatorNetworkSharesAt(bytes32 sn, uint48 ts) public view returns (uint256) {
                    return _shares[sn].upperLookupRecent(ts);
                }
            }
        "#;
        assert!(
            !reentrancy_findings(src).iter().any(|f| f.category == Category::ReadOnlyReentrancy),
            "read-only must not fire when the getter only performs an internal library lookup"
        );
    }

    /// R28 FP2 — CEI-correct function flagged as cross-function reentrancy.
    /// Real site: v4-core `ProtocolFees.collectProtocolFees` reads the
    /// `protocolFeeController` guard and DECREMENTS `protocolFeesAccrued` BEFORE
    /// `currency.transfer` — checks-effects-interactions correct, no post-call
    /// write. A sibling (`_updateProtocolFees`/`setProtocolFeeController`) touches
    /// the same vars, but since this function settles its value before the call
    /// and its only other pre-call read is the controller guard, there is nothing a
    /// re-entrant sibling can corrupt. Must stay silent.
    #[test]
    fn silent_on_cei_correct_pre_call_guard_and_settle() {
        let src = r#"
            interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
            contract ProtocolFees {
                mapping(address => uint256) public protocolFeesAccrued;
                address public protocolFeeController;
                IERC20 public token;
                function setProtocolFeeController(address c) external { protocolFeeController = c; }      // sibling writes controller
                function _updateProtocolFees(address cur, uint256 a) internal { protocolFeesAccrued[cur] += a; } // sibling writes accrued
                function collectProtocolFees(address recipient, address cur, uint256 amount) external returns (uint256 c) {
                    if (msg.sender != protocolFeeController) revert();          // guard READ before call
                    c = (amount == 0) ? protocolFeesAccrued[cur] : amount;
                    protocolFeesAccrued[cur] -= c;                              // SETTLE before the call (CEI)
                    token.transfer(recipient, c);                              // external transfer LAST, no write after
                }
            }
        "#;
        assert!(
            !fires(src),
            "a CEI-correct function (settle-then-transfer, guard read before the call, no post-call write) must stay silent"
        );
    }

    /// R28 FP3 — classic/cross fired on a function whose only "external" call is a
    /// stateless-library dispatch off a bare PascalCase namespace
    /// (`Time.timestamp()`), mis-classified `External` because the library lives in
    /// an excluded dependency tree. Real sites: symbiotic `VaultTokenized._update`
    /// and `NetworkRestakeDelegator.setOperatorNetworkShares` — storage + emit only,
    /// no external call of their own. Must stay silent.
    #[test]
    fn silent_on_library_static_dispatch_only() {
        let src = r#"
            library Time { function timestamp() internal view returns (uint48) { return uint48(block.timestamp); } }
            library Checkpoints {
                struct Trace { uint256 v; }
                function push(Trace storage t, uint48 ts, uint256 x) internal { t.v = x; }
                function latest(Trace storage t) internal view returns (uint256) { return t.v; }
            }
            contract Delegator {
                using Checkpoints for Checkpoints.Trace;
                mapping(bytes32 => Checkpoints.Trace) internal _total;
                mapping(bytes32 => mapping(address => Checkpoints.Trace)) internal _ops;
                function setOperatorNetworkShares(bytes32 sn, address op, uint256 shares) external {
                    uint256 prev = _ops[sn][op].latest();                 // pre-call read
                    if (prev == shares) revert();
                    _total[sn].push(Time.timestamp(), shares);            // "call" is Time.timestamp (library)
                    _ops[sn][op].push(Time.timestamp(), shares);
                }
            }
        "#;
        // The library namespace `Time` (a bare PascalCase receiver, not a state var)
        // is NOT a re-entry vector, so there is no genuine external call to arm any
        // reentrancy finding.
        assert!(
            !fires(src),
            "a function whose only external-looking call is a stateless-library dispatch must stay silent"
        );
    }

    /// Recall guard — a GENUINE external-call-then-state-write must STILL fire even
    /// when the post-call write is performed by a directly-called internal helper.
    /// Real site: pendle `VotingEscrowPendleMainchain.increaseLockPosition` does
    /// `pendle.safeTransferFrom(...)` (reads `positionData` before it) and defers
    /// the `positionData` write to `_increasePosition`. A sibling (`withdraw`) also
    /// writes `positionData`, so this is a real cross-function re-entry surface.
    #[test]
    fn fires_on_transfer_then_deferred_state_write() {
        let src = r#"
            interface IERC20 { function safeTransferFrom(address f, address t, uint256 a) external; }
            contract VE {
                struct Pos { uint128 amount; uint128 expiry; }
                mapping(address => Pos) public positionData;
                IERC20 public pendle;
                function _increasePosition(address u, uint128 amt) internal {
                    positionData[u] = Pos(positionData[u].amount + amt, positionData[u].expiry); // write (post-call, in callee)
                }
                function withdraw() external {                       // sibling that mutates positionData
                    delete positionData[msg.sender];
                }
                function increaseLockPosition(uint128 amt, uint128 newExpiry) external returns (uint128) {
                    address u = msg.sender;
                    if (newExpiry < positionData[u].expiry) revert();  // pre-call READ of positionData (unsettled)
                    uint128 total = amt + positionData[u].amount;
                    pendle.safeTransferFrom(u, address(this), amt);    // genuine external token call
                    _increasePosition(u, amt);                         // state settled AFTER the call, in a callee
                    return total;
                }
            }
        "#;
        assert!(
            fires(src),
            "a genuine transfer-then-(deferred)-state-write must still fire as cross-function reentrancy"
        );
    }

    // ---- R-next FP (Lido StETH shares): a function whose ONLY "external" calls are
    // `using`-bound SafeMath / UnstructuredStorage value helpers (`x.sub(y)`,
    // `shares[k].add(a)`, `SLOT.setLowUint128(v)`) — mis-classified `External`
    // because those libraries live in an excluded dependency tree — must stay
    // silent. There is NO genuine external call, so there is no re-entry vector.
    // Real sites: StETH `_mintShares` / `_burnShares` / `_transferShares`. ----
    #[test]
    fn silent_on_safemath_unstructured_value_helper_calls_only() {
        let src = r#"
            // Bound libraries deliberately omitted from the source set (as in the real
            // tree), so `.sub`/`.add`/`.setLowUint128` fall back to `External`.
            contract StETH {
                using SafeMath for uint256;
                using UnstructuredStorage for bytes32;
                mapping(address => uint256) private shares;
                bytes32 internal constant TOTAL_SHARES_POSITION_LOW128 = keccak256("lido.StETH.totalShares");
                function _transferShares(address _sender, address _recipient, uint256 _sharesAmount) internal {
                    uint256 currentSenderShares = shares[_sender];
                    require(_sharesAmount <= currentSenderShares, "BALANCE_EXCEEDED");
                    shares[_sender] = currentSenderShares.sub(_sharesAmount);   // value-helper, not a call
                    shares[_recipient] = shares[_recipient].add(_sharesAmount); // value-helper, not a call
                }
                function _mintShares(address _recipient, uint256 _sharesAmount) internal returns (uint256 newTotalShares) {
                    newTotalShares = _getTotalShares().add(_sharesAmount);      // value-helper on a value local
                    TOTAL_SHARES_POSITION_LOW128.setLowUint128(newTotalShares); // value-helper on a bytes32 constant
                    shares[_recipient] = shares[_recipient].add(_sharesAmount);
                }
                function _getTotalShares() internal view returns (uint256) {
                    return TOTAL_SHARES_POSITION_LOW128.getLowUint128();
                }
            }
        "#;
        assert!(
            !fires(src),
            "a function whose only external-looking calls are using-bound value/storage helpers must stay silent"
        );
    }

    // ---- R-next FP (LoopFi `_claim`): a value-helper math call (`userStake.mulDiv`,
    // `using Math for uint256`) must not be read as the arming call, and a `balances`
    // slot SETTLED before the real `safeTransfer`/value call is CEI-correct even when
    // a sibling branch writes the same var after a different branch's call (the
    // cross-branch ordering artifact). Must stay silent. Real site: LoopFi
    // `PrelaunchPoints._claim`. ----
    #[test]
    fn silent_on_cei_claim_with_math_helper_and_cross_branch_write() {
        let src = r#"
            interface ILpETH {
                function safeTransfer(address to, uint256 a) external;
                function deposit(address r) external payable;
            }
            contract PrelaunchPoints {
                using Math for uint256;
                mapping(address => mapping(address => uint256)) public balances;
                uint256 public totalSupply;
                uint256 public totalLpETH;
                address public constant ETH = address(0xee);
                ILpETH public lpETH;
                function _fillQuote(address t, uint256 a) internal { (bool ok,) = t.call(""); require(ok); }
                function _claim(address _token, address _receiver) internal returns (uint256 claimedAmount) {
                    uint256 userStake = balances[msg.sender][_token];
                    require(userStake != 0);
                    if (_token == ETH) {
                        claimedAmount = userStake.mulDiv(totalLpETH, totalSupply); // math helper, NOT a call
                        balances[msg.sender][_token] = 0;                          // settle BEFORE the transfer
                        lpETH.safeTransfer(_receiver, claimedAmount);              // real external call, last
                    } else {
                        balances[msg.sender][_token] = userStake - 1;              // settle BEFORE the calls
                        _fillQuote(_token, 1);
                        claimedAmount = address(this).balance;
                        lpETH.deposit{value: claimedAmount}(_receiver);
                    }
                }
            }
        "#;
        assert!(
            !fires(src),
            "CEI-correct claim (balances settled before the real call; math helper is not the arming call) must stay silent"
        );
    }

    // ---- R-next FP (LoopFi `withdraw` cross-function): `balances`/`totalSupply` are
    // settled BEFORE `msg.sender.call{value:}`, and the only other pre-call reads are
    // the `startClaimDate`/`loopActivation` window dates and the `emergencyMode`
    // flag — config/guard scalars, not value carried across the call. Cross-function
    // must stay silent. Real site: LoopFi `PrelaunchPoints.withdraw`. ----
    #[test]
    fn silent_on_cei_withdraw_with_only_config_guard_reads() {
        let src = r#"
            interface IERC20 { function safeTransfer(address to, uint256 a) external; }
            contract PrelaunchPoints {
                mapping(address => mapping(address => uint256)) public balances;
                uint256 public totalSupply;
                uint32 public loopActivation;
                uint32 public startClaimDate;
                bool public emergencyMode;
                address public constant ETH = address(0xee);
                function setStartClaimDate(uint32 d) external { startClaimDate = d; } // sibling writes the date
                function withdraw(address _token) external {
                    if (!emergencyMode) {
                        if (block.timestamp <= loopActivation) revert();
                        if (block.timestamp >= startClaimDate) revert();
                    }
                    uint256 lockedAmount = balances[msg.sender][_token];
                    balances[msg.sender][_token] = 0;             // settle BEFORE the call
                    require(lockedAmount != 0);
                    if (_token == ETH) {
                        if (block.timestamp >= startClaimDate) revert();
                        totalSupply = totalSupply - lockedAmount; // settle BEFORE the call
                        (bool sent,) = msg.sender.call{value: lockedAmount}(""); // real call, nothing written after
                        require(sent);
                    } else {
                        IERC20(_token).safeTransfer(msg.sender, lockedAmount);
                    }
                }
            }
        "#;
        assert!(
            !fires(src),
            "CEI-correct withdraw (value settled before the call; only config/date/flag pre-call reads) must stay silent"
        );
    }

    // ---- Recall guard: a genuine `using SafeMath` contract that STILL has a real
    // external value call followed by a balance write must FIRE. This proves the
    // value-helper exclusion only removes the SafeMath pseudo-calls, never the real
    // re-entry vector. ----
    #[test]
    fn fires_on_real_call_then_write_even_with_safemath() {
        let src = r#"
            contract Bank {
                using SafeMath for uint256;            // binds a value library, but...
                mapping(address => uint256) public balances;
                function withdraw(uint256 amt) external {
                    uint256 bal = balances[msg.sender];
                    require(bal >= amt);
                    (bool ok,) = msg.sender.call{value: amt}("");  // GENUINE low-level value call
                    require(ok);
                    balances[msg.sender] = bal.sub(amt);           // value write strictly after (via helper)
                }
            }
        "#;
        let fs = reentrancy_findings(src);
        assert!(
            fs.iter().any(|f| f.category == Category::Reentrancy),
            "a real call-then-write must still fire even when the write uses a SafeMath helper"
        );
    }

    // ---- R-next FP (Wildcat `resetReserveRatio`): a plain, non-value `External`
    // method call into a protocol market followed by a `delete temp[market]` cleanup
    // must stay silent. The call moves no value and the only post-call effect is an
    // idempotent reset of a per-key temporary record — re-entry cannot profit. Real
    // site: WildcatMarketController.resetReserveRatio. ----
    #[test]
    fn silent_on_cleanup_delete_after_plain_nonvalue_call() {
        let src = r#"
            interface IMarket { function setReserveRatioBips(uint16 b) external; }
            contract WildcatMarketController {
                struct Temp { uint16 reserveRatioBips; uint256 expiry; }
                mapping(address => Temp) public temporaryExcessReserveRatio;
                function resetReserveRatio(address market) external {
                    Temp memory tmp = temporaryExcessReserveRatio[market];      // pre-call read (copy)
                    if (tmp.expiry == 0) revert();
                    if (block.timestamp < tmp.expiry) revert();
                    IMarket(market).setReserveRatioBips(tmp.reserveRatioBips);   // plain, no-value External call
                    delete temporaryExcessReserveRatio[market];                 // cleanup delete AFTER the call
                }
            }
        "#;
        assert!(
            !fires(src),
            "cleanup-delete after a plain non-value external call must stay silent"
        );
    }

    // ---- Recall guard A: a GENUINE balance drain (`balances[msg.sender] -= amt`
    // after a `.call{value:}`) must STILL fire — the value/low-level call defeats
    // the cleanup-delete suppression (it is not a plain non-value method call). ----
    #[test]
    fn fires_on_value_call_then_balance_decrement_not_suppressed() {
        let src = r#"
            contract Bank {
                mapping(address => uint256) public balances;
                function withdraw(uint256 amt) external {
                    uint256 bal = balances[msg.sender];
                    require(bal >= amt);
                    (bool ok,) = msg.sender.call{value: amt}(""); // value/low-level call (NOT plain)
                    require(ok);
                    balances[msg.sender] -= amt;                  // genuine post-call balance drain
                }
            }
        "#;
        let fs = reentrancy_findings(src);
        assert!(
            fs.iter().any(|f| f.category == Category::Reentrancy),
            "a real value-call-then-balance-decrement must still fire (not a benign cleanup delete)"
        );
    }

    // ---- Recall guard B: a `delete` post-call write does NOT over-suppress when the
    // arming call IS value-bearing. A `delete balances[msg.sender]` after a
    // `.call{value:}` is still a re-entry surface (the value send can be re-entered
    // before the slot is zeroed) — the value call defeats the suppression. ----
    #[test]
    fn fires_on_delete_after_value_bearing_call() {
        let src = r#"
            contract Bank {
                mapping(address => uint256) public balances;
                function withdrawAll() external {
                    uint256 bal = balances[msg.sender];
                    require(bal > 0);
                    (bool ok,) = msg.sender.call{value: bal}(""); // value call — not a plain method call
                    require(ok);
                    delete balances[msg.sender];                  // delete AFTER a value call still fires
                }
            }
        "#;
        let fs = reentrancy_findings(src);
        assert!(
            fs.iter().any(|f| f.category == Category::Reentrancy),
            "a delete after a VALUE-bearing call must still fire (don't over-suppress on delete alone)"
        );
    }
}
