//! Reliance on the fixed 2300-gas stipend for native-ETH transfers (SWC-134).
//!
//! `address.transfer(x)` and `address.send(x)` forward a hard-coded **2300 gas**
//! to the recipient. Before EIP-1884 (Istanbul) and EIP-2929 (Berlin) that was
//! enough for a trivial `receive()`/`fallback()`; those EIPs repriced `SLOAD`,
//! `BALANCE`, `EXTCODEHASH` and the cold-access opcodes upward, so a recipient
//! whose `receive()` does anything non-trivial (write a slot, read its own
//! balance, emit through a proxy) now exceeds 2300 gas and the transfer reverts.
//! The same applies to a low-level `addr.call{gas: 2300}("")` that hard-codes a
//! tiny stipend. When the recipient can be a contract (a smart-contract wallet,
//! a multisig, another protocol), a withdrawal built on the 2300 stipend can be
//! permanently bricked — and any future opcode repricing can break it again.
//!
//! This is a hardening finding (Severity::Low, confidence 0.5): the stipend is a
//! heuristic liveness risk, not a guaranteed loss, and is only realised when the
//! recipient is (or becomes) a contract with a non-trivial receive hook.
//!
//! Precision over recall:
//!   * Only the fixed-stipend shapes are flagged: a `CallKind::Transfer` /
//!     `CallKind::Send` site, or a `CallKind::LowLevelCall` whose `{gas:}` clause
//!     is a literal `<= 2300`. A `.call{value:}("")` with **no** `{gas:}` clause
//!     forwards all remaining gas — that is the recommended pull-payment pattern,
//!     so it is *not* a finding.
//!   * Suppressed when the recipient is provably an externally-owned account
//!     (`.transfer(tx.origin)` — `tx.origin` is always an EOA), since an EOA's
//!     fallback costs nothing and the stipend is always sufficient.
//!   * Suppressed when the *same function* already performs an uncapped
//!     `.call{value:}` native send (the protocol has adopted the pull-payment /
//!     unbounded-gas pattern alongside a legacy `.transfer`); flagging the
//!     redundant legacy line would be noise.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Call, CallKind, Expr, ExprKind, Function, Span};

pub struct HardcodedGasStipendDetector;

impl Detector for HardcodedGasStipendDetector {
    fn id(&self) -> &'static str {
        "hardcoded-gas-stipend"
    }
    fn category(&self) -> Category {
        Category::HardcodedGasStipend
    }
    fn description(&self) -> &'static str {
        "Native-ETH transfer relies on the fixed 2300-gas stipend (.transfer/.send or call{gas:<=2300}); can brick withdrawals to contract recipients post-EIP-1884/2929"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // The stipend only matters on a path that actually moves ETH, i.e. a
            // state-mutating body. A view/pure helper or a body-less declaration
            // has nothing to send.
            if !f.has_body || f.is_view_or_pure() {
                continue;
            }

            // The recommended mitigation is a pull-payment `.call{value:}("")`
            // with no `{gas:}` cap. If this very function already does that, a
            // sibling legacy `.transfer`/`.send` line is redundant and flagging it
            // would be noise.
            let uses_uncapped_value_call = has_uncapped_value_call(f);

            for (call, span) in stipend_calls(f) {
                // EOA-only recipient (`tx.origin` is always an externally-owned
                // account): its fallback costs nothing, so 2300 gas is always
                // enough. Provable suppression.
                if recipient_is_eoa(&call) {
                    continue;
                }
                if uses_uncapped_value_call {
                    continue;
                }

                let (shape, rec) = match call.kind {
                    CallKind::Transfer => (
                        "uses `.transfer(...)`, which forwards a fixed 2300 gas",
                        "Use a pull-payment pattern or `(*ok*,) = recipient.call{value: amount}(\"\")` \
                         (forwarding all gas) and `require(ok)`, so a contract recipient's `receive()` \
                         cannot run out of the 2300-gas stipend.",
                    ),
                    CallKind::Send => (
                        "uses `.send(...)`, which forwards a fixed 2300 gas (and only returns a bool)",
                        "Replace `.send` with a checked `recipient.call{value: amount}(\"\")` (forwarding \
                         all gas) and `require(ok)`, or use a pull-payment pattern.",
                    ),
                    _ => (
                        "makes a low-level `call` with a hard-coded tiny `{gas:}` stipend (<= 2300)",
                        "Do not hard-code the gas forwarded on a value-bearing `call`; forward all gas \
                         (`call{value: amount}(\"\")`) and check the returned success flag, or use a \
                         pull-payment pattern.",
                    ),
                };

                let b = FindingBuilder::new(self.id(), Category::HardcodedGasStipend)
                    .title("Native-ETH transfer relies on the fixed 2300-gas stipend")
                    .severity(Severity::Low)
                    .confidence(0.5)
                    .dimension(Dimension::Frontier)
                    .message(format!(
                        "`{}` {shape}. Post-EIP-1884/2929 opcode repricing, a contract recipient with a \
                         non-trivial `receive()`/`fallback()` (e.g. a smart-contract wallet or multisig) \
                         can exceed 2300 gas, reverting the transfer and bricking the withdrawal — and any \
                         future repricing can break it again (SWC-134).",
                        f.name
                    ))
                    .recommendation(rec);
                out.push(cx.finish(b, f.id, span));
                // One finding per function is enough signal for this hardening
                // class; avoid spamming a withdrawal loop with N identical hits.
                break;
            }
        }
        out
    }
}

// ----------------------------------------------------------------- helpers

/// Every call in the body that pins the 2300-gas stipend: a `.transfer`/`.send`
/// site (implicit 2300), or a low-level `call` whose `{gas:}` clause is a literal
/// `<= 2300`. Returns the call and its span, deduplicated by span.
fn stipend_calls(f: &Function) -> Vec<(Call, Span)> {
    let mut out: Vec<(Call, Span)> = Vec::new();
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if let ExprKind::Call(c) = &e.kind {
                let is_stipend = match c.kind {
                    CallKind::Transfer | CallKind::Send => true,
                    CallKind::LowLevelCall => gas_literal_is_tiny(c.gas.as_deref()),
                    _ => false,
                };
                if is_stipend && !out.iter().any(|(_, sp)| *sp == e.span) {
                    out.push((c.clone(), e.span));
                }
            }
        });
    }
    out
}

/// True if a `{gas:}` clause is present and is a numeric literal `<= 2300`
/// (tolerating Solidity digit separators like `2_300` and hex like `0x8FC`).
/// Absent or non-literal gas (a variable / expression) is *not* a fixed tiny
/// stipend and returns false.
fn gas_literal_is_tiny(gas: Option<&Expr>) -> bool {
    match gas.map(|g| &g.kind) {
        Some(ExprKind::Lit(sluice_ir::Lit::Number(n))) => {
            if n.contains('.') {
                return false; // not an integer
            }
            let cleaned: String = n.chars().filter(|c| *c != '_').collect();
            cleaned.parse::<u64>().map(|v| v <= 2300).unwrap_or(false)
        }
        Some(ExprKind::Lit(sluice_ir::Lit::HexNumber(n))) => {
            let hex = n.trim().trim_start_matches("0x").trim_start_matches("0X");
            let cleaned: String = hex.chars().filter(|c| *c != '_').collect();
            u64::from_str_radix(&cleaned, 16).map(|v| v <= 2300).unwrap_or(false)
        }
        _ => false,
    }
}

/// True if the value/receiver of this transfer is provably an externally-owned
/// account — i.e. `tx.origin`, which is always an EOA at call time. (msg.sender
/// is deliberately *not* treated as an EOA: it can be a contract, and a
/// `.transfer(msg.sender)` is exactly the common flagged shape.)
fn recipient_is_eoa(c: &Call) -> bool {
    // The recipient of `x.transfer(amt)` / `x.send(amt)` is the call receiver `x`;
    // for a low-level `x.call{...}(...)` it is likewise `x`.
    let recv = match &c.receiver {
        Some(r) => r.as_ref(),
        None => return false,
    };
    expr_is_tx_origin(recv)
}

/// `tx.origin`, possibly wrapped in a `payable(...)` / `address(...)` cast.
fn expr_is_tx_origin(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Member { base, member } => {
            member == "origin" && matches!(&base.kind, ExprKind::Ident(n) if n == "tx")
        }
        // `payable(tx.origin)` / `address(tx.origin)` — a single-arg cast.
        ExprKind::Call(c) if matches!(c.kind, CallKind::TypeCast) => {
            c.args.len() == 1 && expr_is_tx_origin(&c.args[0])
        }
        _ => false,
    }
}

/// True if the body performs a native-value low-level call (`{value:}`) that
/// forwards *all* gas (no `{gas:}` cap) — the recommended pull-payment / robust
/// withdrawal pattern. Used to suppress a redundant legacy `.transfer`/`.send`
/// in the same function.
fn has_uncapped_value_call(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if c.kind == CallKind::LowLevelCall && c.value.is_some() && c.gas.is_none() {
                    found = true;
                }
            }
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: withdrawal pays the caller with `.transfer(...)`, pinning the
    // 2300-gas stipend. If `msg.sender` is a smart-contract wallet with a
    // non-trivial `receive()`, the withdrawal reverts and the funds are stuck.
    const VULN: &str = r#"
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

    // Safe: the same withdrawal uses a checked `.call{value:}("")` forwarding all
    // gas (the recommended pull pattern), so no fixed 2300 stipend is relied on.
    const SAFE: &str = r#"
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

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "hardcoded-gas-stipend"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "hardcoded-gas-stipend"));
    }
}
