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

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, CallKind, Expr, ExprKind, Function};

pub struct FlashloanCallbackDetector;

/// The known flash-loan / swap callback entry points (lower-cased for a
/// case-insensitive match on the function name). Only these are ever flagged.
const CALLBACK_NAMES: &[&str] = &[
    "onflashloan",           // EIP-3156
    "executeoperation",      // Aave V2/V3
    "receiveflashloan",      // Balancer V2
    "uniswapv2call",         // Uniswap V2 / forks
    "uniswapv3swapcallback", // Uniswap V3
    "pancakecall",           // PancakeSwap
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

/// Is the function name one of the recognized flash-loan / swap callbacks?
fn is_callback_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    CALLBACK_NAMES.contains(&l.as_str())
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

/// True if the body contains an (in)equality comparison of `msg.sender` against a
/// value that is *not* attacker-controlled — i.e. a stored/trusted lender, pool,
/// pair, vault, an immutable, or a hardcoded address. Both `==` (a positive
/// `require`) and `!=` (an `if (msg.sender != lender) revert` guard) count.
fn has_msg_sender_lender_check(cx: &AnalysisContext, f: &Function) -> bool {
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
}
