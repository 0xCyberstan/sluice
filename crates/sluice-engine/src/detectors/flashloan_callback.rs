//! Unauthenticated flash-loan / swap callback receiver.
//!
//! A flash-loan or swap *callback* is invoked by the lending pool / pair after it
//! has optimistically sent the borrowed funds (or completed the swap). The pool
//! calls a fixed, well-known entry point on the borrower:
//!
//! | callback                  | protocol            | initiator/sender param |
//! |---------------------------|---------------------|------------------------|
//! | `onFlashLoan`             | EIP-3156            | `initiator` (arg 0)    |
//! | `executeOperation`        | Aave V2/V3          | `initiator`            |
//! | `receiveFlashLoan`        | Balancer V2         | — (none)               |
//! | `uniswapV2Call`           | Uniswap V2 / forks  | `sender` (arg 0)       |
//! | `pancakeCall`             | PancakeSwap         | `sender` (arg 0)       |
//! | `uniswapV3SwapCallback`   | Uniswap V3          | — (none)               |
//!
//! Because the function is `external`/`public`, **anyone** can call it directly —
//! not just the real pool. Two authentications are mandatory:
//!
//!   (a) `require(msg.sender == <trusted lender/pool/pair/vault>)` — otherwise an
//!       attacker calls the callback themselves with a forged `data` payload (no
//!       loan ever taken) and drives whatever logic the borrower performs on the
//!       supposedly-borrowed funds (often a `transferFrom`/`approve` of the
//!       contract's own allowances).
//!   (b) for EIP-3156 / Aave / Uniswap-V2-style callbacks that carry the loan
//!       *initiator*, `require(initiator == address(this))` — otherwise even a
//!       legitimate pool call can be triggered by a third party who initiated a
//!       loan and named this contract as the receiver, replaying its callback
//!       logic on their behalf.
//!
//! This is the EIP-3156 flash-borrower reference-implementation security note and
//! the root cause behind several callback-confusion drains. The detector fires on
//! a known callback function that is missing (a), or missing (b) when an
//! initiator/sender parameter is present.
//!
//! Precision (false-positive suppression): a callback that requires
//! `msg.sender == <stored, non-attacker address>` **and** (when it has an
//! initiator/sender parameter) `initiator/sender == address(this)` is the correct
//! pattern and is suppressed. The comparison against the lender must be to a value
//! that is *not* attacker-controlled (a state variable, an immutable, or a
//! hardcoded address) — a bogus `require(msg.sender == initiator)` does not count.
//!
//! # Uniswap v4 hook / `unlockCallback` extension (`V4CallbackMissingPoolManagerAuth`)
//!
//! The same callback-confusion class has a Uniswap-v4 incarnation. The PoolManager
//! is the *only* legitimate caller of a hook's `beforeSwap` / `afterSwap` /
//! `before|afterInitialize` / `before|after{Add,Remove}Liquidity` /
//! `before|afterDonate` callbacks and of `unlockCallback`. Because each is
//! `external`, anyone can call it directly with a forged `key`/`params`/`hookData`
//! and drive whatever the hook does on the supposedly-locked funds — exactly the
//! Cork-Protocol drain (`CorkHook.beforeSwap`, ~$12M, 2025-05-28).
//!
//! The mandatory guard is `msg.sender == address(poolManager)`, conventionally a
//! `modifier onlyPoolManager` (e.g. v4-periphery `SafeCallback`/`ImmutableState`),
//! or the inline `require(msg.sender == address(manager))` form. For the v4 set the
//! finding hinges *solely* on this PoolManager-authentication: arg0 (`address
//! sender`) is supplied by the PoolManager and is **not** a loan initiator, so the
//! initiator check does not apply. To avoid flagging the abstract `IHooks`
//! interface and the ubiquitous `revert HookNotImplemented()` stub hooks
//! (`BaseTestHooks`), a v4 callback is only flagged when it has a *real
//! side-effect* (a storage write, a value-bearing call, or a call — direct or via
//! an internal helper — to a PoolManager mutator such as
//! `swap`/`modifyLiquidity`/`take`/`settle`/`mint`/`unlock`). Such a finding is
//! **Critical**.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, CallKind, Expr, ExprKind, Function};

pub struct FlashloanCallbackDetector;

/// The classic flash-loan / swap callback entry points (lower-cased for a
/// case-insensitive match on the function name). These follow the EIP-3156 /
/// lender-pin + initiator-pin pattern and fire as [`Category::FlashloanCallback`]
/// at High severity.
const CALLBACK_NAMES: &[&str] = &[
    "onflashloan",           // EIP-3156
    "executeoperation",      // Aave V2/V3
    "receiveflashloan",      // Balancer V2
    "uniswapv2call",         // Uniswap V2 / forks
    "uniswapv3swapcallback", // Uniswap V3
    "pancakecall",           // PancakeSwap
];

/// The Uniswap v4 hook / lock callbacks (lower-cased). The PoolManager is their
/// sole legitimate caller, so the only required guard is `msg.sender ==
/// address(poolManager)` (typically an `onlyPoolManager` modifier). These fire as
/// [`Category::V4CallbackMissingPoolManagerAuth`] at Critical severity and skip the
/// initiator check (arg0 `address sender` is PoolManager-supplied, not a loan
/// initiator). Gated behind the real-side-effect test so the abstract `IHooks`
/// interface and revert-only stub hooks (`BaseTestHooks`) never fire.
const V4_CALLBACK_NAMES: &[&str] = &[
    "unlockcallback", // IUnlockCallback (the v4 flash-accounting lock callback)
    "beforeinitialize",
    "afterinitialize",
    "beforeaddliquidity",
    "afteraddliquidity",
    "beforeremoveliquidity",
    "afterremoveliquidity",
    "beforeswap",
    "afterswap",
    "beforedonate",
    "afterdonate",
];

/// PoolManager state-mutating methods. A v4 callback that calls one of these —
/// directly (an external `call_site`) or through an internal helper (an
/// `internal_calls` entry, after stripping a leading `_`) — has a real, attacker-
/// drivable side-effect on the locked accounting and is therefore a fireable
/// target even when it performs no storage write of its own (e.g. `ActionsRouter`,
/// whose `unlockCallback` dispatches to internal `_settle`/`_take`/`_mint`).
const PM_MUTATORS: &[&str] = &[
    "swap",
    "modifyliquidity",
    "donate",
    "take",
    "settle",
    "settlefor",
    "settlenative",
    "mint",
    "burn",
    "sync",
    "clear",
    "unlock",
    "initialize",
];

impl Detector for FlashloanCallbackDetector {
    fn id(&self) -> &'static str {
        "flashloan-callback"
    }
    fn category(&self) -> Category {
        Category::FlashloanCallback
    }
    fn description(&self) -> &'static str {
        "Flash-loan/swap callback (onFlashLoan/executeOperation/uniswapV2Call/...) without lender & initiator checks"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // Must be a real, externally-reachable implementation: an interface
            // declaration carries no body to authenticate and no risk.
            if !f.has_body || !f.is_externally_reachable() {
                continue;
            }

            // ---- Uniswap v4 hook / unlockCallback path (Critical) ----
            // The PoolManager is the only legitimate caller, so the finding hinges
            // solely on PoolManager-authentication. Gated behind a real-side-effect
            // test so the `IHooks` interface and revert-only stub hooks stay silent.
            if is_v4_callback_name(&f.name) {
                if !has_real_side_effect(f) {
                    continue;
                }
                // The only required guard: `msg.sender == address(poolManager)`,
                // either an `onlyPoolManager` modifier or the inline `require` form.
                if has_msg_sender_lender_check(cx, f) {
                    continue;
                }
                out.push(build_v4_finding(self, cx, f));
                continue;
            }

            if !is_callback_name(&f.name) {
                continue;
            }

            // Does the callback carry the loan initiator / swap originator? Aave
            // names it `initiator`; EIP-3156 / Uniswap-V2 / Pancake pass it as the
            // first argument named `initiator` / `sender`. Balancer's
            // `receiveFlashLoan` and Uniswap V3's `uniswapV3SwapCallback` have no
            // such parameter, so the initiator check is not applicable to them.
            let initiator_param = find_initiator_param(f);

            // --- evidence: which authentications are present? ---
            let has_lender_check = has_msg_sender_lender_check(cx, f);
            let has_initiator_check = match &initiator_param {
                // Vacuously satisfied when the callback has no initiator param.
                None => true,
                Some(name) => has_initiator_is_this_check(f, name),
            };

            // Correct pattern (lender pinned AND, where applicable, initiator
            // pinned to self) → suppress. Precision is the priority.
            if has_lender_check && has_initiator_check {
                continue;
            }

            // Compose a precise message describing exactly what is missing.
            let (what_missing, recommendation) = match (has_lender_check, has_initiator_check) {
                (false, false) => (
                    "neither authenticates the caller (`require(msg.sender == <trusted lender/pool>)`) \
                     nor confirms it initiated the loan (`require(initiator == address(this))`)",
                    "Authenticate the callback: `require(msg.sender == <the lender/pool/pair you called>)` \
                     and `require(initiator == address(this))` (reject any loan this contract did not start).",
                ),
                (false, true) => (
                    "does not authenticate the caller — there is no \
                     `require(msg.sender == <trusted lender/pool>)`, so anyone can invoke it directly",
                    "Add `require(msg.sender == <the lender/pool/pair you called>)` so only the real \
                     lender can drive this callback.",
                ),
                (true, false) => (
                    "authenticates the lender but never checks that this contract initiated the loan — \
                     there is no `require(initiator == address(this))`",
                    "Add `require(initiator == address(this))` so a third party cannot name this contract \
                     as the receiver of a loan it did not start and replay this callback's logic.",
                ),
                (true, true) => unreachable!("suppressed above"),
            };

            let b = FindingBuilder::new(self.id(), Category::FlashloanCallback)
                .title("Flash-loan/swap callback does not authenticate caller or initiator")
                .severity(Severity::High)
                .confidence(0.6)
                .dimension(Dimension::Frontier)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` is a flash-loan/swap callback that the lending pool/pair calls after sending \
                     funds, but it {}. Because the function is externally callable, an attacker can call \
                     it directly with a forged `data` payload (no loan ever taken) and drive whatever the \
                     borrower does with the supposedly-borrowed funds — e.g. spending this contract's own \
                     token allowances. The EIP-3156 callback-confusion class.",
                    f.name, what_missing
                ))
                .recommendation(recommendation);
            out.push(cx.finish(b, f.id, f.span));
        }
        out
    }
}

/// Is the function name one of the recognized (classic) flash-loan / swap callbacks?
fn is_callback_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    CALLBACK_NAMES.contains(&l.as_str())
}

/// Is the function name one of the Uniswap v4 hook / `unlockCallback` callbacks?
fn is_v4_callback_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    V4_CALLBACK_NAMES.contains(&l.as_str())
}

/// Does this v4 callback have a real, attacker-drivable side-effect (as opposed to
/// being a pure `revert HookNotImplemented()` / `return selector` stub)?
///
/// True when it writes storage, makes a value-bearing call, or calls a PoolManager
/// mutator — directly (an external `call_site`) or via an internal helper (an
/// `internal_calls` entry, after stripping a leading `_`, e.g. `ActionsRouter`'s
/// `_settle`/`_take`/`_mint`). Revert-only / selector-only stubs have empty
/// `storage_writes`, `call_sites` and `internal_calls`, so they fail every arm.
fn has_real_side_effect(f: &Function) -> bool {
    let eff = &f.effects;
    if !eff.storage_writes.is_empty() {
        return true;
    }
    if eff.call_sites.iter().any(|c| c.sends_value) {
        return true;
    }
    if eff
        .call_sites
        .iter()
        .filter_map(|c| c.func_name.as_deref())
        .any(is_pm_mutator)
    {
        return true;
    }
    // PoolManager mutations reached through an internal dispatcher count too: the
    // helper name is recorded in `internal_calls` (e.g. `_settle`, `_take`).
    eff.internal_calls.iter().any(|n| is_pm_mutator(n))
}

/// Does `name` (case-insensitive, leading `_` stripped) denote a PoolManager
/// state-mutating method?
fn is_pm_mutator(name: &str) -> bool {
    let l = name.trim_start_matches('_').to_ascii_lowercase();
    PM_MUTATORS.contains(&l.as_str())
}

/// Build the Critical `V4CallbackMissingPoolManagerAuth` finding for an unguarded
/// Uniswap v4 hook / `unlockCallback`.
fn build_v4_finding(det: &FlashloanCallbackDetector, cx: &AnalysisContext, f: &Function) -> Finding {
    let b = FindingBuilder::new(det.id(), Category::V4CallbackMissingPoolManagerAuth)
        .title("Uniswap v4 hook/unlockCallback does not authenticate the PoolManager")
        .severity(Severity::Critical)
        .confidence(0.7)
        .dimension(Dimension::Frontier)
        .dimension(Dimension::ValueFlow)
        .message(format!(
            "`{}` is a Uniswap v4 hook/lock callback that only the PoolManager should ever call, but it \
             has no `require(msg.sender == address(poolManager))` (nor an `onlyPoolManager` modifier) and \
             performs a real side-effect. Because the function is externally callable, an attacker can \
             invoke it directly with a forged `key`/`params`/`hookData` (no swap or lock ever taken) and \
             drive the hook's settle/take/mint/storage logic on the supposedly-locked accounting — the \
             Cork-Protocol callback-confusion drain (~$12M). This is the Uniswap v4 PoolManager \
             authentication gap.",
            f.name
        ))
        .recommendation(
            "Restrict the callback to the PoolManager: apply an `onlyPoolManager` modifier (e.g. \
             v4-periphery's `SafeCallback`/`ImmutableState`) or add \
             `require(msg.sender == address(poolManager))` as the first statement, so only the real \
             PoolManager can drive this hook.",
        );
    cx.finish(b, f.id, f.span)
}

/// Locate the loan-initiator / swap-originator parameter, if the callback has one.
/// Aave passes it as a parameter explicitly named `initiator`; EIP-3156,
/// Uniswap V2 and PancakeSwap pass it as the first parameter, conventionally named
/// `initiator` / `sender`. Returns the parameter name to compare against
/// `address(this)`.
fn find_initiator_param(f: &Function) -> Option<String> {
    f.params.iter().find_map(|p| {
        let n = p.name.as_deref()?;
        let nl = n.to_ascii_lowercase();
        if nl == "initiator" || nl == "sender" || nl == "originator" {
            Some(n.to_string())
        } else {
            None
        }
    })
}

/// True if the caller is pinned to a trusted, non-attacker-controlled address.
///
/// Two accepted forms:
///   1. an `onlyPoolManager` modifier (the v4-periphery `SafeCallback` /
///      `ImmutableState` pattern, whose body is `if (msg.sender !=
///      address(poolManager)) revert`); the modifier *name* is the signal — the
///      check itself lives in the modifier definition, not this function's body, so
///      a body scan alone would miss it.
///   2. an inline body (in)equality of `msg.sender` against a value that is *not*
///      attacker-controlled — a stored/trusted lender, pool, pair, vault, an
///      immutable, or a hardcoded address. Both `==` (a positive `require`) and
///      `!=` (an `if (msg.sender != lender) revert` guard) count.
fn has_msg_sender_lender_check(cx: &AnalysisContext, f: &Function) -> bool {
    // Form (1): the conventional `onlyPoolManager` access-control modifier.
    if f
        .modifiers
        .iter()
        .any(|m| m.name.eq_ignore_ascii_case("onlyPoolManager"))
    {
        return true;
    }

    // Form (2): an inline `msg.sender ==/!= <trusted>` comparison in the body.
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            let ExprKind::Binary { op, lhs, rhs } = &e.kind else { return };
            if !matches!(op, BinOp::Eq | BinOp::Ne) {
                return;
            }
            // One side must be `msg.sender`; the other the trusted comparand.
            let other = if is_msg_sender(lhs) {
                Some(rhs.as_ref())
            } else if is_msg_sender(rhs) {
                Some(lhs.as_ref())
            } else {
                None
            };
            let Some(other) = other else { return };
            // A real lender pin compares against something the attacker does not
            // control: a state var / immutable, a constant address, or a member
            // read off one (e.g. `provider.getPool()`). Reject comparisons against
            // attacker input (a forged param) — those are not authentication.
            if cx.is_attacker_controlled(f.id, other) {
                return;
            }
            // `msg.sender == address(this)` is not a lender pin (the pool is a
            // distinct contract); don't accept it as the lender check.
            if is_address_this(unwrap_casts(other)) {
                return;
            }
            // Accept: stored address, immutable, hardcoded address literal, or a
            // call/member that resolves to a non-attacker value.
            found = true;
        });
        if found {
            break;
        }
    }
    found
}

/// True if the body requires the initiator/sender parameter to equal
/// `address(this)` (the loan was started by this contract). Accepts `==` and the
/// negated `!=`-revert guard form.
fn has_initiator_is_this_check(f: &Function, param: &str) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            let ExprKind::Binary { op, lhs, rhs } = &e.kind else { return };
            if !matches!(op, BinOp::Eq | BinOp::Ne) {
                return;
            }
            let l = unwrap_casts(lhs);
            let r = unwrap_casts(rhs);
            let matches_pair = (is_named_ident(l, param) && is_address_this(r))
                || (is_named_ident(r, param) && is_address_this(l));
            if matches_pair {
                found = true;
            }
        });
        if found {
            break;
        }
    }
    found
}

/// `msg.sender` (shallow member access).
fn is_msg_sender(e: &Expr) -> bool {
    e.mentions_member("msg", "sender")
}

/// `this` or (after cast-stripping) `address(this)`.
fn is_address_this(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Ident(n) if n == "this")
}

/// Bare identifier with the given name.
fn is_named_ident(e: &Expr, name: &str) -> bool {
    matches!(&e.kind, ExprKind::Ident(n) if n == name)
}

/// Peel single-argument type casts (`address(...)`, `payable(...)`, `IERC20(...)`)
/// so the underlying value can be inspected.
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

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: an EIP-3156 `onFlashLoan` receiver that authenticates nothing.
    // Anyone can call it directly with a crafted payload; the contract acts on
    // funds it never borrowed (here: approving an attacker-chosen spender).
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC20 { function approve(address s, uint256 a) external returns (bool); }
        contract Borrower {
            IERC20 public token;
            address public lender;
            function onFlashLoan(
                address initiator,
                address tokenAddr,
                uint256 amount,
                uint256 fee,
                bytes calldata data
            ) external returns (bytes32) {
                address spender = abi.decode(data, (address));
                token.approve(spender, amount);
                return keccak256("ERC3156FlashBorrower.onFlashLoan");
            }
        }
    "#;

    // Safe: the same receiver, but it pins the caller to the stored lender AND
    // confirms it initiated the loan — the EIP-3156 reference pattern.
    const SAFE: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC20 { function approve(address s, uint256 a) external returns (bool); }
        contract Borrower {
            IERC20 public token;
            address public lender;
            function onFlashLoan(
                address initiator,
                address tokenAddr,
                uint256 amount,
                uint256 fee,
                bytes calldata data
            ) external returns (bytes32) {
                require(msg.sender == lender, "untrusted lender");
                require(initiator == address(this), "untrusted initiator");
                address spender = abi.decode(data, (address));
                token.approve(spender, amount);
                return keccak256("ERC3156FlashBorrower.onFlashLoan");
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "flashloan-callback"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "flashloan-callback"));
    }

    // ---- Uniswap v4 hook / unlockCallback path ----

    use sluice_findings::{Category, Severity};

    fn fires_v4(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.category == Category::V4CallbackMissingPoolManagerAuth)
    }

    // POSITIVE — a `beforeSwap` hook with a storage write + an attacker-driven
    // token transfer and NO PoolManager authentication. Anyone can call it.
    const V4_VULN: &str = r#"
        pragma solidity ^0.8.24;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract VulnHook {
            IERC20 public token; address public manager;     // PoolManager, never checked
            mapping(bytes4 => bytes) public lastData;
            function beforeSwap(address, bytes calldata key, bytes calldata params, bytes calldata hookData)
                external returns (bytes4, int256, uint24) {
                lastData[bytes4(hookData)] = hookData;        // storage_write
                token.transfer(msg.sender, 1);                // attacker-driven side effect
                return (this.beforeSwap.selector, int256(0), uint24(0));
            }
        }
    "#;

    // NEGATIVE — the same hook, but guarded by an `onlyPoolManager` modifier
    // (the v4-periphery SafeCallback / ImmutableState pattern).
    const V4_SAFE_MODIFIER: &str = r#"
        pragma solidity ^0.8.24;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract SafeHook {
            IERC20 public token; address public immutable poolManager;
            mapping(bytes4 => bytes) public lastData; error NotPoolManager();
            constructor(address pm) { poolManager = pm; }
            modifier onlyPoolManager() { if (msg.sender != address(poolManager)) revert NotPoolManager(); _; }
            function beforeSwap(address, bytes calldata key, bytes calldata params, bytes calldata hookData)
                external onlyPoolManager returns (bytes4, int256, uint24) {
                lastData[bytes4(hookData)] = hookData; token.transfer(address(this), 1);
                return (this.beforeSwap.selector, int256(0), uint24(0));
            }
        }
    "#;

    // NEGATIVE — an `unlockCallback` guarded by the inline `require(msg.sender ==
    // address(manager))` form (manager is a state variable).
    const V4_SAFE_INLINE: &str = r#"
        pragma solidity ^0.8.24;
        interface IPoolManager { function take(address c, address to, uint256 a) external; }
        contract SafeRouter {
            IPoolManager public manager;
            uint256 public n;
            function unlockCallback(bytes calldata data) external returns (bytes memory) {
                require(msg.sender == address(manager));
                n++;
                manager.take(address(0), msg.sender, 1);
                return "";
            }
        }
    "#;

    // NEGATIVE — a revert-only stub hook (the `BaseTestHooks` shape): no
    // side-effect, so the side-effect gate keeps it silent even without a guard.
    const V4_STUB: &str = r#"
        pragma solidity ^0.8.24;
        contract StubHook {
            error HookNotImplemented();
            function beforeSwap(address, bytes calldata, bytes calldata, bytes calldata)
                external returns (bytes4, int256, uint24) {
                revert HookNotImplemented();
            }
        }
    "#;

    #[test]
    fn fires_on_v4_hook_missing_pm_auth() {
        let fs = run(V4_VULN);
        assert!(fires_v4(&fs), "expected a V4 PM-auth finding, got {:?}", fs);
        // Must be Critical.
        assert!(
            fs.iter()
                .any(|f| f.category == Category::V4CallbackMissingPoolManagerAuth
                    && f.severity == Severity::Critical),
            "expected Critical severity, got {:?}",
            fs
        );
    }

    #[test]
    fn silent_on_safe_pm_authed_callback() {
        let fs = run(V4_SAFE_MODIFIER);
        assert!(!fires_v4(&fs), "onlyPoolManager modifier must suppress, got {:?}", fs);
    }

    #[test]
    fn silent_on_inline_pm_guarded_callback() {
        let fs = run(V4_SAFE_INLINE);
        assert!(!fires_v4(&fs), "inline require(msg.sender == manager) must suppress, got {:?}", fs);
    }

    #[test]
    fn silent_on_revert_only_stub_hook() {
        let fs = run(V4_STUB);
        assert!(!fires_v4(&fs), "revert-only stub must not fire (no side-effect), got {:?}", fs);
    }
}
