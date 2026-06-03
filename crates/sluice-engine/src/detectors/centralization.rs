//! Centralization risk: a privileged admin can move user funds or re-route fund
//! flows in a single transaction, with no timelock / exit window (the "admin can
//! rug" class that audits and bug-bounty programs routinely flag).
//!
//! The pattern: a function gated by an access-control guard (`onlyOwner` /
//! `onlyAdmin` / `onlyRole` / `onlyGovernance` — all of which the IR classifies
//! as [`GuardKind::MsgSenderCheck`], so `cx.has_access_control(f)` is true) that
//! either
//!
//!   (a) **moves funds** — performs a native-ETH send (`sends_value`) or a raw
//!       ERC-20 `transfer`/`transferFrom` of tokens that are not obviously the
//!       caller's own, or
//!   (b) **re-routes funds** — sets a fund-affecting parameter
//!       (`set*Fee` / `setRecipient` / `setTreasury` / `setRouter` /
//!       `withdrawAll` / `rescue` / `migrate` / `setImplementation`),
//!
//! while the contract evidences **no timelock / governance delay**. A single
//! compromised or malicious admin key can then drain or redirect user funds with
//! no window for users to exit first.
//!
//! This is deliberately a *low-confidence, informational* class — it flags a
//! trust assumption, not a code defect — so the confidence is modest (0.4) and
//! the severity is Low/Medium. Precision is prioritized via aggressive
//! suppression:
//!
//!   * Any contract that evidences a timelock / governance delay
//!     (`timelock` / `delay` / `eta` / `minDelay`, a `Timelock`/`Governor` base,
//!     or a `queue`→`execute` two-step) is silenced — the exit window exists.
//!   * A fund move that is **provably the caller's own** (every value-moving call
//!     pins its destination/source to `msg.sender`) is not a rug and is silenced.
//!   * Ordinary user operations (`deposit`/`stake`/`claim`/…) are not flagged.
//!
//! Distinct from `governance-timelock`: that detector fires once per *contract*
//! on the single most-critical upgrade/setter regardless of guard; this one
//! requires an *access-control guard* and a concrete *fund-movement or
//! fund-routing* effect, and reports under a distinct category
//! ([`Category::Centralization`]) so the two never dedup against each other.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{CallKind, Contract, Expr, ExprKind, Function};

pub struct CentralizationDetector;

impl Detector for CentralizationDetector {
    fn id(&self) -> &'static str {
        "centralization-risk"
    }
    fn category(&self) -> Category {
        Category::Centralization
    }
    fn description(&self) -> &'static str {
        "Privileged admin can move user funds or re-route fund flows with no timelock (admin-can-rug centralization risk)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.entry_points() {
            // Core gate: the function must be access-controlled. A privileged
            // admin operation is the whole subject of this class; a
            // permissionless function is covered by other detectors
            // (arbitrary-transfer, access-control).
            if !cx.has_access_control(f) {
                continue;
            }
            // Constructors / initializers set up the contract once and are not the
            // standing admin surface.
            if f.is_constructor() || cx.is_initializer(f) {
                continue;
            }
            // Ordinary user operations are not a centralization risk even when an
            // operator-style guard happens to apply.
            if is_user_op(&f.name) {
                continue;
            }

            let Some(contract) = cx.contract_of(f.id) else { continue };
            // Whole-contract suppression: if a timelock / governance delay exists,
            // users have an exit window, so the admin cannot rug without warning.
            if contract_has_timelock(cx, contract) {
                continue;
            }

            // ---- Arm (b): fund-routing parameter setter ----------------------
            // A pure name match is enough here — these names denote fund-affecting
            // configuration whose change re-routes or releases user funds.
            if is_fund_routing_setter(&f.name) {
                out.push(self.finding(
                    cx,
                    f,
                    Severity::Medium,
                    format!(
                        "`{}.{}` is an access-controlled function that changes a fund-affecting \
                         parameter (fee / recipient / treasury / router / implementation, or sweeps \
                         funds), and the contract has no timelock or delay. A single compromised or \
                         malicious admin key can re-route or release user funds in one transaction, \
                         with no window for users to exit first — the admin-can-rug centralization risk.",
                        contract.name, f.name
                    ),
                ));
                continue;
            }

            // ---- Arm (a): moves user funds -----------------------------------
            // The function performs a native-ETH send or a raw ERC-20 transfer.
            if !moves_funds(f) {
                continue;
            }
            // Suppress when every value-moving call is provably the caller's own
            // funds (destination / source pinned to `msg.sender`): an admin that
            // can only move funds *to itself* is not rugging users.
            if all_value_moves_are_caller_own(f) {
                continue;
            }

            out.push(self.finding(
                cx,
                f,
                Severity::Low,
                format!(
                    "`{}.{}` is an access-controlled function that transfers ETH or tokens that are \
                     not obviously the caller's own, and the contract has no timelock or delay. A \
                     single compromised or malicious admin key can move user funds out in one \
                     transaction, with no window for users to exit first — the admin-can-rug \
                     centralization risk.",
                    contract.name, f.name
                ),
            ));
        }
        out
    }
}

impl CentralizationDetector {
    fn finding(&self, cx: &AnalysisContext, f: &Function, sev: Severity, msg: String) -> Finding {
        let b = FindingBuilder::new(self.id(), Category::Centralization)
            .title("Privileged admin can move/re-route user funds with no timelock")
            .severity(sev)
            // Honest: the absence of an off-chain timelock owner cannot be proven
            // from source, and "trusted admin" is often an accepted assumption, so
            // this is a low-confidence informational signal.
            .confidence(0.4)
            .dimension(Dimension::Invariant)
            .message(msg)
            .recommendation(
                "Route fund-moving / fund-routing admin actions through a timelock (e.g. \
                 OpenZeppelin `TimelockController`) with a meaningful `minDelay`, or behind \
                 multisig / on-chain governance, so users have a window to exit before a \
                 privileged change to funds takes effect.",
            );
        cx.finish(b, f.id, f.span)
    }
}

// ----------------------------------------------------------------- helpers

/// Fund-routing / fund-releasing privileged setters and sweepers. An exact-ish
/// name match: these denote configuration whose change moves or redirects user
/// funds (fee skim, payout recipient, treasury, swap router, proxy code), or a
/// bulk sweep / rescue / migration of held funds.
fn is_fund_routing_setter(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // `set*Fee` (setFee, setSwapFee, setProtocolFee, …) routes a skim of value.
    if l.starts_with("set") && l.contains("fee") {
        return true;
    }
    // Payout / treasury / router / proxy-code re-routing setters.
    if matches!(
        l.as_str(),
        "setrecipient"
            | "setfeerecipient"
            | "settreasury"
            | "setrouter"
            | "setimplementation"
    ) {
        return true;
    }
    // Bulk sweep / rescue / migrate of held funds.
    l.contains("withdrawall") || l.contains("rescue") || l.contains("migrate")
}

/// Intentionally-permissionless user operations that are not a centralization
/// risk even if an operator/role guard happens to apply. Mirrors the user-facing
/// list used by the access-control detector, minus the admin-sweep verbs
/// (`withdrawAll`/`rescue`/`migrate`) which are handled as fund-routing above.
fn is_user_op(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // `withdraw` is a user op, but `withdrawAll` (admin sweep) is not — keep the
    // sweep distinguishable.
    if l.contains("withdrawall") {
        return false;
    }
    [
        "deposit", "withdraw", "claim", "redeem", "stake", "unstake", "swap", "borrow", "repay",
        "wrap", "unwrap", "harvest", "compound", "vote",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// True if the function moves funds: a native-ETH send (`sends_value`) or a raw
/// ERC-20 `transfer`/`transferFrom` (incl. `safe*` wrappers) external/internal
/// call site.
fn moves_funds(f: &Function) -> bool {
    f.effects.call_sites.iter().any(|c| {
        if c.sends_value {
            return true;
        }
        let is_token_move = matches!(
            c.func_name.as_deref(),
            Some("transfer") | Some("transferFrom") | Some("safeTransfer") | Some("safeTransferFrom")
        );
        is_token_move && matches!(c.kind, CallKind::External | CallKind::Internal)
    })
}

/// True if **every** value-moving call in the body provably routes to / from the
/// caller (`msg.sender`). Such a function lets the admin move funds only to
/// itself, which is not a rug of *user* funds, so it is suppressed.
///
/// Conservative: returns false (i.e. does NOT suppress) unless we positively see
/// at least one value-moving call and all of them are caller-pinned.
fn all_value_moves_are_caller_own(f: &Function) -> bool {
    let mut saw_move = false;
    let mut all_caller = true;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            let ExprKind::Call(call) = &e.kind else { return };

            // Native-ETH sends: `recipient.transfer(x)` / `.send(x)` /
            // `recipient.call{value:x}(...)`. The recipient is the call receiver.
            if matches!(call.kind, CallKind::Transfer | CallKind::Send)
                || (call.kind == CallKind::LowLevelCall && call.value.is_some())
            {
                saw_move = true;
                let to_caller = call
                    .receiver
                    .as_deref()
                    .map(|r| mentions_msg_sender(r))
                    .unwrap_or(false);
                if !to_caller {
                    all_caller = false;
                }
                return;
            }

            // ERC-20 moves: inspect the recipient / source argument.
            //   transfer(to, amt)            -> arg0 is `to`
            //   transferFrom(from, to, amt)  -> arg0 is `from`, arg1 is `to`
            //   safeTransfer(token, to, amt) -> arg1 is `to`
            //   safeTransferFrom(token, from, to, amt) -> arg1 `from`, arg2 `to`
            match call.func_name.as_deref() {
                Some("transfer") if matches!(call.kind, CallKind::External | CallKind::Internal) => {
                    saw_move = true;
                    if !arg_is_msg_sender(&call.args, 0) {
                        all_caller = false;
                    }
                }
                Some("transferFrom")
                    if matches!(call.kind, CallKind::External | CallKind::Internal) =>
                {
                    saw_move = true;
                    // Caller's own funds iff both endpoints are the caller (rare);
                    // any other endpoint means it can touch non-caller funds.
                    if !(arg_is_msg_sender(&call.args, 0) && arg_is_msg_sender(&call.args, 1)) {
                        all_caller = false;
                    }
                }
                Some("safeTransfer") => {
                    saw_move = true;
                    if !arg_is_msg_sender(&call.args, 1) {
                        all_caller = false;
                    }
                }
                Some("safeTransferFrom") => {
                    saw_move = true;
                    if !(arg_is_msg_sender(&call.args, 1) && arg_is_msg_sender(&call.args, 2)) {
                        all_caller = false;
                    }
                }
                _ => {}
            }
        });
    }
    saw_move && all_caller
}

/// The argument at `idx` (after stripping `address(...)`/`payable(...)` casts) is
/// `msg.sender`.
fn arg_is_msg_sender(args: &[Expr], idx: usize) -> bool {
    args.get(idx).map(|a| mentions_msg_sender(unwrap_casts(a))).unwrap_or(false)
}

/// `msg.sender` (best-effort, after cast-stripping).
fn mentions_msg_sender(e: &Expr) -> bool {
    let e = unwrap_casts(e);
    e.mentions_member("msg", "sender")
}

/// Peel single-argument type casts (`address(x)`, `payable(x)`, `IERC20(x)`).
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

/// Does the contract evidence a timelock / governance delay? Conservative on the
/// side of *suppression*: any plausible timelock signal silences the finding.
/// Mirrors the suppression used by the governance-timelock detector.
fn contract_has_timelock(cx: &AnalysisContext, contract: &Contract) -> bool {
    // The contract *is* (or inherits) a timelock / governor — the delay is its
    // purpose.
    if contract.inherits_like("timelock")
        || contract.inherits_like("timelockcontroller")
        || contract.inherits_like("governor")
    {
        return true;
    }
    let src = cx.source_text(contract.span); // comment-stripped (a `// no timelock` comment must not suppress)
    // Direct vocabulary used by timelock implementations / bases.
    if src.contains("timelock") || src.contains("mindelay") {
        return true;
    }
    // A delay/eta value combined with a queue→execute two-step is the structural
    // shape of a timelock (queue now, execute after the delay elapses).
    let has_delay_word = src.contains("delay") || src.contains("eta");
    let has_two_step = (src.contains("queue") || src.contains("queued"))
        && (src.contains("execute") || src.contains("pending"));
    has_delay_word && has_two_step
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: an `onlyOwner` rescue that sends arbitrary tokens to an
    // admin-chosen address, with no timelock anywhere — the admin can drain user
    // funds in a single tx (admin-can-rug centralization risk).
    const VULN: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract Vault {
            address public owner;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }

            // users deposit funds here (held by the contract)
            function deposit() external payable {}

            // admin can sweep any token to any address — no timelock
            function rescueTokens(address token, address to, uint256 amt) external onlyOwner {
                IERC20(token).transfer(to, amt);
            }
        }
    "#;

    // Safe: the same kind of admin sweep, but the contract routes privileged
    // changes through a timelock (minDelay / queue→execute), so users have an
    // exit window — not a silent rug.
    const SAFE: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract TimelockedVault {
            address public owner;
            uint256 public minDelay = 2 days;
            mapping(bytes32 => uint256) public queuedEta;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }

            function deposit() external payable {}

            function queueRescue(address token, address to, uint256 amt) external onlyOwner {
                bytes32 id = keccak256(abi.encode(token, to, amt));
                queuedEta[id] = block.timestamp + minDelay;
            }

            function executeRescue(address token, address to, uint256 amt) external onlyOwner {
                bytes32 id = keccak256(abi.encode(token, to, amt));
                require(queuedEta[id] != 0 && block.timestamp >= queuedEta[id], "timelock");
                IERC20(token).transfer(to, amt);
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "centralization-risk"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "centralization-risk"));
    }
}
