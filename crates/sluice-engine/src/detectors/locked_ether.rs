//! Locked ether: a contract that can **receive** ETH but has **no path that
//! sends ETH out** — funds sent to it are permanently stuck.
//!
//! A contract accepts native ETH when it exposes a *payable ingress*: a
//! `payable` function (including a `payable` constructor or `payable fallback`),
//! or a `receive()` function (which is implicitly payable). For that ETH to ever
//! leave again the contract must contain an *egress* somewhere — a value-bearing
//! call (`addr.call{value: v}(...)`, `IFoo(x).bar{value: v}()`, or the legacy
//! `target.call.value(v)(data)` spelling), a `.transfer(`/`.send(`, or a
//! `selfdestruct(...)` (which forwards the whole balance). A
//! contract that has the ingress but **none** of the egress forms can be funded
//! by anyone yet can never pay out: the balance is locked forever. This is the
//! classic "locked ether" / "ether trap" finding (a `payable` deposit with a
//! forgotten or never-implemented withdrawal).
//!
//! ## What fires
//!
//! Per **concrete** contract: a payable ingress exists in the contract or any of
//! its bases, AND no ETH egress appears anywhere in the contract or its bases.
//!
//! ## What is suppressed (precision first)
//!
//!   * **Any egress path** — if the contract (or an inherited base) can send ETH
//!     via `{value:}` / `.transfer` / `.send` / `selfdestruct`, the ether is not
//!     trapped and we stay silent. This is the safe form the lint must not flag.
//!   * **Proxies / `delegatecall` forwarders** — a proxy delegates every call (and
//!     its ETH) to an implementation, so the *delegated* code provides the egress;
//!     a contract that inherits a `Proxy`/`Delegator` base or contains a
//!     `delegatecall` is therefore not locked.
//!   * **Libraries and interfaces** — they have no instance balance to lock.
//!   * **Abstract contracts** — an `abstract` base may legitimately omit the
//!     withdrawal; the concrete child that completes it carries the egress, so
//!     flagging the abstract parent would be a false positive.
//!
//! Egress is detected both structurally (over the classified IR call graph of the
//! contract's own functions) and, as a conservative backstop, textually over the
//! contract source (so an egress the classifier missed still suppresses). Erring
//! toward "found an egress" keeps this Low-severity lint precise on the safe form.

use super::prelude::*;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{Builtin, CallKind, Contract, FunctionKind};
use std::collections::HashSet;

pub struct LockedEtherDetector;

impl Detector for LockedEtherDetector {
    fn id(&self) -> &'static str {
        "locked-ether"
    }
    fn category(&self) -> Category {
        Category::LockedEther
    }
    fn description(&self) -> &'static str {
        "Contract accepts ETH (payable ingress) but has no path to send it out — funds are permanently locked"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for c in cx.scir.iter_contracts() {
            // Libraries and interfaces have no instance balance, and an `abstract`
            // base may legitimately leave the withdrawal to its concrete child —
            // so only concrete contracts can "lock" ether.
            if !c.is_concrete() {
                continue;
            }

            // A proxy forwards every call (and the ETH it carries) to an
            // implementation via `delegatecall`; the delegated logic — not this
            // contract's own body — provides the egress, so a proxy is never
            // "locked". Suppress anything inheriting a `Proxy`-like base
            // (OZ `Proxy`/`ERC1967Proxy`/`TransparentUpgradeableProxy`, Compound
            // `*Delegator`). The `delegatecall` *itself* is also treated as an
            // egress in `contract_has_egress`, covering inline-proxy bodies.
            if c.inherits_like("proxy") || c.inherits_like("delegator") {
                continue;
            }

            // Flatten the contract together with its (transitive, in-tree) bases:
            // an inherited `payable` ingress and an inherited withdrawal both run
            // in a deployed instance's own context, so ingress *and* egress must be
            // evaluated over the whole inheritance closure.
            let chain = inheritance_chain(cx, c);

            // (1) Ingress: does any function in the chain accept native ETH?
            let ingress = chain.iter().find_map(|cc| ingress_function_name(cx, cc));
            let Some(ingress_name) = ingress else { continue };

            // (2) Egress: does any function in the chain send native ETH out?
            //     Structural (classified calls) first, then a textual backstop over
            //     each contract's source so a missed classification still suppresses.
            let has_egress = chain.iter().any(|cc| contract_has_egress(cx, cc));
            if has_egress {
                continue;
            }

            let b = report!(self, Category::LockedEther,
                title = "Contract can receive ETH but has no path to send it out (locked ether)",
                severity = Severity::Low,
                confidence = 0.5,
                dimensions = [Dimension::Invariant],
                message = format!(
                    "`{}` exposes a payable ingress (e.g. `{}`) so anyone can send it native ETH, but no \
                     function in the contract or its bases can send ETH out — there is no `{{value:}}` call, \
                     no `.transfer`/`.send`, and no `selfdestruct`. Any ETH deposited is permanently locked \
                     (the classic forgotten-withdrawal / ether-trap bug).",
                    c.name, ingress_name
                ),
                recommendation = "Add a withdrawal path (an access-controlled function that sends the balance via \
                     `to.call{value: amount}(\"\")`), or remove the payable ingress (drop `payable`, or revert in \
                     `receive`/`fallback`) if the contract is not meant to hold ETH.",
            );
            // Contract-level finding: no single function is responsible, so report
            // at the contract span (mirrors `storage_gap.rs`).
            out.push(b.at(cx.scir, c.name.clone(), String::new(), c.span).build());
        }

        out
    }
}

// --------------------------------------------------------------------- helpers

/// The contract together with its transitive bases that are present in the SCIR,
/// in a stable order (self first). A base named by a contract but not defined in
/// the analyzed sources is simply skipped (we cannot inspect what we cannot see).
fn inheritance_chain<'a>(cx: &'a AnalysisContext, c: &'a Contract) -> Vec<&'a Contract> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut chain: Vec<&Contract> = Vec::new();
    let mut stack: Vec<&Contract> = vec![c];
    while let Some(cur) = stack.pop() {
        if !seen.insert(cur.name.as_str()) {
            continue;
        }
        chain.push(cur);
        for base in &cur.bases {
            if let Some(bc) = cx.scir.contract_named(base) {
                if !seen.contains(bc.name.as_str()) {
                    stack.push(bc);
                }
            }
        }
    }
    chain
}

/// If `c` has a function that accepts native ETH (a payable ingress), return a
/// human-readable name for it. Ingress forms:
///   * a `receive()` function — implicitly payable, always accepts value;
///   * any `payable` function (covers `payable fallback`, `payable` external/
///     public methods, and a `payable` constructor).
fn ingress_function_name(cx: &AnalysisContext, c: &Contract) -> Option<String> {
    cx.scir.functions_of(c.id).find_map(|f| {
        if matches!(f.kind, FunctionKind::Receive) {
            return Some("receive()".to_string());
        }
        if f.is_payable() {
            return Some(match f.kind {
                FunctionKind::Fallback => "fallback() payable".to_string(),
                FunctionKind::Constructor => "constructor() payable".to_string(),
                _ => format!("{}() payable", f.name),
            });
        }
        None
    })
}

/// Does any function defined directly in `c` contain an ETH-egress? Structural
/// pass over the classified call graph, plus a textual backstop over the source.
fn contract_has_egress(cx: &AnalysisContext, c: &Contract) -> bool {
    // (1) Structural: a value-bearing call, a `.transfer`/`.send`, or a
    //     `selfdestruct` anywhere in any of the contract's own function bodies.
    let structural = cx
        .scir
        .functions_of(c.id)
        .any(|f| f.has_body && any_call_where(f, call_is_eth_egress));
    if structural {
        return true;
    }

    // (2) Textual backstop over the contract source. Catches value sends the
    //     classifier may not have tagged: the legacy `.value(...)` ETH-send
    //     modifier (`target.call.value(v)(data)`, `f.value(v)(...)`), the modern
    //     `{value:}` spelling, `.transfer`/`.send`, `selfdestruct`/`suicide`, and
    //     a `delegatecall`/`callcode` (the delegated code can move the ETH).
    //     Comments are stripped by `source_text`, so a `// no withdraw` comment
    //     cannot fake an egress.
    let src = cx.source_text(c.span);
    let norm: String = src.chars().filter(|ch| !ch.is_whitespace()).collect();
    norm.contains("{value:")
        || norm.contains(".value(")
        || norm.contains(".transfer(")
        || norm.contains(".send(")
        || norm.contains("selfdestruct(")
        || norm.contains("suicide(")
        || norm.contains("delegatecall")
        || norm.contains("callcode")
        // LayerZero OApp sender idiom: `_lzSend(...)` forwards the native messaging
        // fee (`msg.value`) to the endpoint via a `{value:}` call inside the
        // (out-of-tree) `OAppSender` base, so a contract that calls it is an ETH
        // egress even though the `{value:}` itself is not in the analyzed source.
        || norm.contains("_lzsend(")
        || norm.contains("lzsend(")
}

/// Is this classified call an ETH-egress?
///   * a `{value:}`-bearing call (low-level or external) — `c.value` is set;
///   * a `.transfer(`/`.send(` (classified as [`CallKind::Transfer`]/[`Send`]);
///   * a `delegatecall` ([`CallKind::DelegateCall`]) — the delegated code runs in
///     this contract's context and can send out the balance, so a contract that
///     can delegatecall is not "locked" (the proxy / inline-proxy case);
///   * a `selfdestruct(...)` builtin (forwards the whole balance);
///   * the **legacy** `.value(...)` ETH-send modifier — pre-0.6 Solidity writes
///     `target.call.value(v)(data)` / `f.value(v)(...)`, which the parser surfaces
///     as a call whose method name is `value` (the `{value:}` field is *not* set
///     in this spelling), so match that name explicitly.
fn call_is_eth_egress(c: &sluice_ir::Call) -> bool {
    c.value.is_some()
        || matches!(c.kind, CallKind::Transfer | CallKind::Send | CallKind::DelegateCall)
        || matches!(c.kind, CallKind::Builtin(Builtin::Selfdestruct))
        || c.func_name.as_deref() == Some("value")
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn count(src: &str) -> usize {
        run(src).iter().filter(|f| f.detector == "locked-ether").count()
    }

    // Vulnerable: a `payable` deposit credits an internal ledger but there is NO
    // withdrawal — no `{value:}` call, no transfer/send, no selfdestruct. Every
    // wei sent to `deposit()` is permanently locked.
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        contract Trap {
            mapping(address => uint256) public balances;
            uint256 public total;
            function deposit() external payable {
                balances[msg.sender] += msg.value;
                total += msg.value;
            }
            function balanceOf(address a) external view returns (uint256) {
                return balances[a];
            }
        }
    "#;

    // Safe: identical ingress, but `withdraw` sends ETH out via a `{value:}`
    // low-level call — the ether is not trapped, so the detector must stay silent.
    const SAFE: &str = r#"
        pragma solidity ^0.8.20;
        contract Vault {
            mapping(address => uint256) public balances;
            function deposit() external payable {
                balances[msg.sender] += msg.value;
            }
            function withdraw(uint256 amount) external {
                require(balances[msg.sender] >= amount, "insufficient");
                balances[msg.sender] -= amount;
                (bool ok, ) = msg.sender.call{value: amount}("");
                require(ok, "send failed");
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "locked-ether"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        assert_eq!(count(SAFE), 0);
    }

    // A `receive()` with no withdrawal is the bare ether-trap — must fire.
    #[test]
    fn fires_on_receive_only() {
        let src = r#"
            pragma solidity ^0.8.20;
            contract Tip { receive() external payable {} }
        "#;
        assert_eq!(count(src), 1);
    }

    // `.transfer` is an egress: a payable contract that pays out via `.transfer`
    // is safe.
    #[test]
    fn silent_when_transfer_egress() {
        let src = r#"
            pragma solidity ^0.8.20;
            contract Payout {
                address payable public owner;
                constructor() { owner = payable(msg.sender); }
                receive() external payable {}
                function sweep() external { owner.transfer(address(this).balance); }
            }
        "#;
        assert_eq!(count(src), 0);
    }

    // `selfdestruct` forwards the whole balance — counts as an egress.
    #[test]
    fn silent_when_selfdestruct_egress() {
        let src = r#"
            pragma solidity ^0.8.20;
            contract Bomb {
                function fund() external payable {}
                function blow(address payable to) external { selfdestruct(to); }
            }
        "#;
        assert_eq!(count(src), 0);
    }

    // Inherited egress: the payable ingress is on the base, the withdrawal is on
    // the (concrete) child. The deployed child can pay out, so it is NOT locked.
    #[test]
    fn silent_when_egress_inherited_from_chain() {
        let src = r#"
            pragma solidity ^0.8.20;
            contract Depositable {
                function deposit() external payable {}
            }
            contract Withdrawable is Depositable {
                function withdraw(address to, uint256 amt) external {
                    (bool ok, ) = to.call{value: amt}("");
                    require(ok);
                }
            }
        "#;
        // `Withdrawable` inherits the ingress and adds the egress -> silent.
        // `Depositable` is itself a concrete, deployable payable-with-no-egress
        // contract, so it is (correctly) flagged once.
        let fs = run(src);
        let locked: Vec<&str> = fs
            .iter()
            .filter(|f| f.detector == "locked-ether")
            .map(|f| f.contract.as_str())
            .collect();
        assert!(locked.contains(&"Depositable"), "{:?}", locked);
        assert!(!locked.contains(&"Withdrawable"), "{:?}", locked);
    }

    // Abstract base with a payable ingress and no egress: suppressed, because the
    // concrete child that completes it carries the withdrawal.
    #[test]
    fn silent_on_abstract_base() {
        let src = r#"
            pragma solidity ^0.8.20;
            abstract contract Base {
                function deposit() external payable {}
            }
            contract Impl is Base {
                function withdraw(address to) external {
                    (bool ok, ) = to.call{value: address(this).balance}("");
                    require(ok);
                }
            }
        "#;
        let fs = run(src);
        let locked: Vec<&str> = fs
            .iter()
            .filter(|f| f.detector == "locked-ether")
            .map(|f| f.contract.as_str())
            .collect();
        // Neither the abstract `Base` (suppressed) nor `Impl` (has egress) fires.
        assert!(locked.is_empty(), "{:?}", locked);
    }

    // Non-payable contract: not an ingress, so nothing to lock — silent.
    #[test]
    fn silent_when_not_payable() {
        let src = r#"
            pragma solidity ^0.8.20;
            contract Plain {
                uint256 public x;
                function set(uint256 v) external { x = v; }
            }
        "#;
        assert_eq!(count(src), 0);
    }

    // Library/interface are never flagged even with payable-looking members.
    #[test]
    fn silent_on_library_and_interface() {
        let src = r#"
            pragma solidity ^0.8.20;
            interface IPay { function pay() external payable; }
            library L { function noop() internal pure {} }
        "#;
        assert_eq!(count(src), 0);
    }

    // Regression (Olympus `Timelock`/`GovernorAlpha` Compound-fork shape): a legacy
    // `payable` fallback ingress whose withdrawal forwards ETH with the pre-0.6
    // `.value(...)` modifier (`target.call.value(v)(data)`) is NOT locked — the
    // value-modifier spelling must be recognized as an egress and suppressed.
    #[test]
    fn silent_on_legacy_value_send() {
        let src = r#"
            pragma solidity 0.5.16;
            contract Timelock {
                function() external payable {}
                function exec(address target, uint256 value, bytes memory data) public payable {
                    (bool ok, ) = target.call.value(value)(data);
                    require(ok, "reverted");
                }
            }
        "#;
        assert_eq!(count(src), 0);
    }

    // Regression (Pendle `PendleRouterV4` / Compound `*Delegator` shape): a proxy
    // with a `payable receive()` whose fallback `delegatecall`s an implementation
    // is NOT locked — the delegated facet provides the egress. Both the inline
    // `delegatecall` and the inherited `Proxy` base independently suppress it.
    #[test]
    fn silent_on_proxy_delegatecall() {
        let src = r#"
            pragma solidity ^0.8.20;
            contract Router {
                address impl;
                receive() external payable {}
                fallback() external payable {
                    (bool ok, ) = impl.delegatecall(msg.data);
                    require(ok);
                }
            }
        "#;
        assert_eq!(count(src), 0);
    }

    // Positive (Pendle `PendleMulticallV1` / `PendleMsgReceiveEndpointUpg` shape):
    // a `payable` entry point that makes a plain `target.call(data)` WITHOUT
    // forwarding `{value:}` and never withdraws — `msg.value` is trapped. The
    // value-modifier / delegatecall softenings must NOT silence this real bug.
    #[test]
    fn fires_on_payable_call_without_value() {
        let src = r#"
            pragma solidity ^0.8.20;
            contract Multicall {
                function aggregate(address target, bytes calldata data) external payable {
                    (bool ok, ) = target.call(data);
                    require(ok);
                }
            }
        "#;
        assert_eq!(count(src), 1);
    }

    // Regression (Pendle `PendleExchangeRateOracleApp` / LayerZero OApp sender):
    // a `payable` function that forwards the native messaging fee with `_lzSend`
    // is NOT locked — `_lzSend` performs the `{value:}` endpoint call in the
    // (out-of-tree) `OAppSender` base, so the call site must read as an egress.
    #[test]
    fn silent_on_layerzero_lzsend() {
        let src = r#"
            pragma solidity ^0.8.20;
            contract OracleApp {
                function sendRate(uint32 dstEid, bytes calldata message, bytes calldata options)
                    external
                    payable
                {
                    _lzSend(dstEid, message, options, msg.sender);
                }
                function _lzSend(uint32, bytes calldata, bytes calldata, address) internal {}
            }
        "#;
        assert_eq!(count(src), 0);
    }
}

