//! Deprecated native-ETH push via `.transfer(...)` / `.send(...)` (SWC-134).
//!
//! `payable(x).transfer(v)` and `x.send(v)` are the classic ways to push native
//! ETH out of a contract — and both forward only the fixed **2300-gas stipend**
//! to the recipient. That stipend was sized for a trivial `receive()`/`fallback()`
//! under pre-Istanbul gas costs; EIP-1884 (Istanbul) and EIP-2929 (Berlin)
//! repriced `SLOAD`/`BALANCE`/cold-access opcodes upward, so a recipient that does
//! anything non-trivial in `receive()` (write a slot, read its balance, forward
//! through a proxy) now blows past 2300 gas and the push *reverts*. When the payee
//! can be a contract — a smart-contract wallet, a multisig, a Safe, another
//! protocol — a withdrawal built on `.transfer`/`.send` can be permanently
//! bricked, and any *future* opcode repricing can break it again.
//!
//! The modern, robust replacement is the checked low-level call that forwards all
//! remaining gas:
//!
//! ```solidity
//! (bool ok, ) = recipient.call{value: amount}("");
//! require(ok, "ETH transfer failed");
//! ```
//!
//! This is a hygiene / hardening lint (Severity::Low, modest confidence): the
//! brittleness is a liveness risk, not a guaranteed loss, and only bites when the
//! recipient is (or becomes) a contract with a non-trivial hook. It fires *broadly*
//! wherever the genuine shape exists — that is correct for a baseline lint.
//!
//! ## Precision — fire only on the genuine NATIVE-ETH push, stay silent otherwise
//!
//!   * Fires on [`CallKind::Transfer`] (`payable(x).transfer(v)` / `x.transfer(v)`
//!     where `x` is an address) and [`CallKind::Send`] (`x.send(v)`). The parser
//!     already resolves these to the native-ETH shapes: a `.transfer` is only
//!     `CallKind::Transfer` when it has `<= 1` argument and the receiver name is
//!     *not* token-like, so a two-argument ERC-20 `token.transfer(to, amt)` lowers
//!     to `CallKind::External` and is **never** seen here. We additionally require a
//!     single positional argument (the wei amount) as a belt-and-braces guard
//!     against a token-shaped `Transfer`.
//!   * **Silent on `.call{value:}("")`** — that is a [`CallKind::LowLevelCall`], the
//!     recommended form, never flagged by this detector.
//!   * **Silent on ERC-20 `token.transfer(to, amt)` / `transferFrom`** — those are
//!     `CallKind::External` (two args / token-like receiver), not native-ETH.
//!
//! ## Relationship to `hardcoded-gas-stipend`
//!
//! Distinct trigger. `hardcoded-gas-stipend` keys on an *explicit* `{gas:}` clause
//! (a `call{gas: 2300}` literal cap); this detector keys on the *implicit* 2300
//! stipend baked into the `.transfer(`/`.send(` push form itself — the deprecated
//! API, independent of any `{gas:}` annotation.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{Call, CallKind, Function, Span};

use super::prelude::*;

pub struct DeprecatedEthSendDetector;

impl Detector for DeprecatedEthSendDetector {
    fn id(&self) -> &'static str {
        "deprecated-eth-send"
    }
    fn category(&self) -> Category {
        Category::DeprecatedEthSend
    }
    fn description(&self) -> &'static str {
        "Native-ETH push via the deprecated `.transfer(...)`/`.send(...)` form (fixed 2300-gas stipend); \
         bricks on contract recipients with a non-trivial receive() and is fragile to gas repricing — \
         prefer a checked `recipient.call{value: amount}(\"\")`"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // The stipend only matters on a path that actually moves ETH, i.e. a
            // body that runs. A body-less interface declaration has no push to make.
            if !f.has_body {
                continue;
            }

            // First native-ETH `.transfer`/`.send` push in this function. One
            // finding per function is enough signal for a hygiene class — a
            // withdrawal that calls `.transfer` in a loop should not emit N hits.
            let Some((call, span)) = first_eth_push(f) else {
                continue;
            };

            let (api, rec) = match call.kind {
                CallKind::Send => (
                    ".send(...)",
                    "Replace `.send` with a checked low-level call that forwards all gas — \
                     `(bool ok, ) = recipient.call{value: amount}(\"\"); require(ok, \"ETH transfer failed\");` \
                     — or adopt a pull-payment pattern. `.send` also silently returns `false` on failure, \
                     so an unchecked `.send` can additionally drop funds.",
                ),
                _ => (
                    ".transfer(...)",
                    "Replace `.transfer` with a checked low-level call that forwards all gas — \
                     `(bool ok, ) = recipient.call{value: amount}(\"\"); require(ok, \"ETH transfer failed\");` \
                     — or adopt a pull-payment pattern, so a contract recipient's `receive()` cannot run out \
                     of the fixed 2300-gas stipend.",
                ),
            };

            let b = report!(self, Category::DeprecatedEthSend,
                title = "Native-ETH push uses the deprecated `.transfer`/`.send` (fixed 2300-gas stipend)",
                severity = Severity::Low,
                confidence = 0.45,
                dimensions = [Dimension::Frontier],
                message = format!(
                    "`{}` pushes native ETH with `{api}`, which forwards only the fixed 2300-gas stipend. \
                     After EIP-1884/EIP-2929 opcode repricing, a contract recipient with a non-trivial \
                     `receive()`/`fallback()` (a smart-contract wallet, multisig or Safe) can exceed 2300 \
                     gas, reverting the push and bricking the payout — and any future repricing can break it \
                     again (SWC-134). The recommended `recipient.call{{value: amount}}(\"\")` form (which \
                     forwards all gas) is intentionally not flagged.",
                    f.name
                ),
                recommendation = rec,
            );
            out.push(finish_at(cx, b, f.id, span));
        }
        out
    }
}

// ----------------------------------------------------------------- helpers

/// Span of the first native-ETH push (`CallKind::Transfer` / `CallKind::Send`) in
/// `f`'s body, with the call, in document order. Returns `None` if the body makes
/// no such push.
///
/// The parser already guarantees a `CallKind::Transfer` is the native-ETH shape
/// (`.transfer` with `<= 1` arg on a non-token-like receiver) rather than an ERC-20
/// `token.transfer(to, amt)` (which lowers to `CallKind::External`). We add an
/// explicit "exactly one positional argument" guard as defence in depth: a genuine
/// ETH push is `x.transfer(amount)` / `x.send(amount)`, never zero- or two-arg.
fn first_eth_push(f: &Function) -> Option<(&Call, Span)> {
    f.calls()
        .into_iter()
        .find(|(c, _)| matches!(c.kind, CallKind::Transfer | CallKind::Send) && c.args.len() == 1)
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    fn fired(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.detector == "deprecated-eth-send")
    }

    // Vulnerable: withdrawal pays the caller with `payable(x).transfer(...)`, the
    // deprecated native-ETH push pinning the 2300-gas stipend. A contract-wallet
    // payee with a non-trivial `receive()` bricks the withdrawal.
    const VULN_TRANSFER: &str = r#"
        pragma solidity ^0.8.0;
        contract Bank {
            mapping(address => uint256) public balance;
            function deposit() external payable { balance[msg.sender] += msg.value; }
            function withdraw() external {
                uint256 amt = balance[msg.sender];
                balance[msg.sender] = 0;
                payable(msg.sender).transfer(amt);
            }
        }
    "#;

    // Vulnerable: same brittleness via `.send(...)` (which also drops the bool).
    const VULN_SEND: &str = r#"
        pragma solidity ^0.8.0;
        contract Payout {
            function pay(address payable to, uint256 amt) external {
                to.send(amt);
            }
        }
    "#;

    // Safe: the recommended checked `.call{value:}("")` forwarding all gas. This is
    // a LowLevelCall, not a Transfer/Send — the detector must stay silent.
    const SAFE_CALL: &str = r#"
        pragma solidity ^0.8.0;
        contract Bank {
            mapping(address => uint256) public balance;
            function deposit() external payable { balance[msg.sender] += msg.value; }
            function withdraw() external {
                uint256 amt = balance[msg.sender];
                balance[msg.sender] = 0;
                (bool ok, ) = payable(msg.sender).call{value: amt}("");
                require(ok, "transfer failed");
            }
        }
    "#;

    // Safe: an ERC-20 `token.transfer(to, amt)` is a TWO-argument token call on a
    // token-like receiver — it lowers to CallKind::External, not Transfer. The
    // detector keys on NATIVE ETH only, so it must stay silent here.
    const SAFE_ERC20: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function transfer(address to, uint256 amt) external returns (bool); }
        contract Pay {
            IERC20 public token;
            function payout(address to, uint256 amt) external {
                token.transfer(to, amt);
            }
        }
    "#;

    #[test]
    fn fires_on_transfer() {
        assert!(fired(&run(VULN_TRANSFER)), "expected deprecated-eth-send on .transfer");
    }

    #[test]
    fn fires_on_send() {
        assert!(fired(&run(VULN_SEND)), "expected deprecated-eth-send on .send");
    }

    #[test]
    fn silent_on_call_value() {
        assert!(!fired(&run(SAFE_CALL)), "must not fire on the recommended .call{{value:}} form");
    }

    #[test]
    fn silent_on_erc20_transfer() {
        assert!(!fired(&run(SAFE_ERC20)), "must not fire on a two-arg ERC-20 token.transfer");
    }
}
