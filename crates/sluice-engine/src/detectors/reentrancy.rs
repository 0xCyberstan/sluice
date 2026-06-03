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
use sluice_ir::{CallKind, CallSite, Function};

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

/// True iff `f` contains at least one GENUINE (untrusted) reentrancy-capable
/// external/low-level call that actually ARMS reentrancy (untrusted, and not an
/// internal guard/assert helper). A function with none of these cannot be
/// re-entered, so it must never trip a classic/cross-function reentrancy rule.
fn has_genuine_reentry_vector(
    f: &Function,
    trusted: &rustc_hash::FxHashSet<String>,
    state_vars: &rustc_hash::FxHashSet<String>,
) -> bool {
    f.effects.call_sites.iter().any(|cs| is_arming_call(cs, trusted, state_vars))
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
) -> bool {
    f.effects.call_sites.iter().any(|cs| {
        is_arming_call(cs, trusted, state_vars)
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
/// re-entry vector that is NOT an internal guard/assert helper and NOT a
/// stateless-library / static-namespace dispatch. The guard-helper exclusion is
/// the `setFeature`-shape protection (an `_assertOnly*()` check must never be read
/// as the arming external call); the library-static exclusion is the
/// `Time.timestamp()` / `UQ112x112.encode()` shape (a pure in-process library call
/// mis-classified `External` because the library lives in an excluded dependency
/// tree — it hands control to no one and cannot be re-entered).
fn is_arming_call(
    cs: &CallSite,
    trusted: &rustc_hash::FxHashSet<String>,
    state_vars: &rustc_hash::FxHashSet<String>,
) -> bool {
    is_reentry_vector(cs)
        && !is_trusted_call(cs, trusted)
        && !is_guard_helper_name(cs.func_name.as_deref())
        && !is_library_static_call(cs, state_vars)
}

/// True iff `f` performs a storage WRITE to one of `vars` STRICTLY AFTER a
/// genuine (untrusted) reentrancy-capable external call, AND that written var is
/// VALUE/balance state (the thing re-entry actually corrupts). This is the
/// concrete classic checks-effects-interactions violation: a value write whose
/// position index is greater than the arming call's index. A write that precedes
/// the call is the safe shape; a write to a non-value flag/registry var is
/// bookkeeping; neither counts.
fn has_qualifying_post_call_write(
    f: &Function,
    vars: &[String],
    trusted: &rustc_hash::FxHashSet<String>,
    state_vars: &rustc_hash::FxHashSet<String>,
) -> bool {
    let first_vector = f
        .effects
        .call_sites
        .iter()
        .filter(|cs| is_arming_call(cs, trusted, state_vars))
        .map(|cs| cs.order)
        .min();
    let Some(first) = first_vector else { return false };
    f.effects.storage_writes.iter().any(|w| {
        w.order > first && is_value_state_var(&w.var) && vars.iter().any(|v| v == &w.var)
    })
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
) -> bool {
    if has_genuine_reentry_vector(f, trusted, state_vars) {
        return true;
    }
    f.callees.iter().any(|cid| {
        cx.scir.function(*cid).is_some_and(|callee| {
            // A callee in another contract resolves its own trusted set; reuse the
            // getter's (a superset of immutable/infra names) as a safe approximation
            // — the only goal is to detect a REAL external/low-level call there.
            has_genuine_reentry_vector(callee, trusted, state_vars)
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
/// trusted config/guard addresses, with NO post-call write, has nothing for a
/// re-entrant sibling to corrupt. That is the v4 `collectProtocolFees` shape:
/// `protocolFeesAccrued` is decremented before `currency.transfer` and the guard
/// read is `protocolFeeController` (a trusted controller address) — CEI-correct.
fn has_cross_function_surface(
    f: &Function,
    trusted: &rustc_hash::FxHashSet<String>,
    state_vars: &rustc_hash::FxHashSet<String>,
) -> bool {
    let Some(first) = f
        .effects
        .call_sites
        .iter()
        .filter(|cs| is_arming_call(cs, trusted, state_vars))
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
    // (b) a pre-call read of a var that is NOT settled before the call and is not a
    // trusted config/guard address — a stale value relied on across the call.
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
                        if !has_genuine_reentry_vector(f, &trusted, &state_vars) {
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
                        if !readonly_getter_has_own_call(cx, f, &trusted, &state_vars) {
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
                    && !has_qualifying_post_call_write(f, &r.vars_written_after, &trusted, &state_vars)
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
                    && !has_cross_function_surface(f, &trusted, &state_vars)
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
                let caller_supplied_value = has_caller_supplied_value_vector(f, &trusted, &state_vars);
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
}
