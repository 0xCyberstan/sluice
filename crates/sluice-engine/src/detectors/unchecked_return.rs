//! Unchecked external-call return values and unsafe ERC-20 transfers.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{CallKind, FunctionId, Span};

pub struct UncheckedReturnDetector;

impl Detector for UncheckedReturnDetector {
    fn id(&self) -> &'static str {
        "unchecked-return"
    }
    fn category(&self) -> Category {
        Category::UncheckedReturn
    }
    fn description(&self) -> &'static str {
        "Ignored return of low-level call / send / ERC-20 transfer"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for c in cx.frontier.unchecked_returns() {
            // Only value-moving transfers matter here. `approve` (and especially
            // `approve(spender, 0)` resets) returns a bool that is conventionally
            // ignored and is not a fund-loss vector — flagging it was noise.
            let is_token_call = matches!(
                c.func_name.as_deref(),
                Some("transfer") | Some("transferFrom")
            ) && c.kind == CallKind::External;

            // Only two cases are genuinely "unchecked return" bugs:
            //   (a) a raw low-level call / send (the boolean really is dropped), or
            //   (b) a RAW ERC-20 transfer/transferFrom/approve (returns a bool).
            // Any other external call (notify hooks, `safe*` wrappers that revert,
            // arbitrary contract methods) is NOT a finding — flagging those was a
            // major false-positive source.
            let is_low_level = matches!(c.kind, CallKind::LowLevelCall | CallKind::Send);
            if !is_low_level && !is_token_call {
                continue;
            }
            // `safe*` wrappers (SafeERC20 / Address.sendValue) revert on failure;
            // ignoring their return is correct.
            if c.func_name.as_deref().map(|n| n.starts_with("safe")).unwrap_or(false) {
                continue;
            }

            // SafeERC20 in scope → token transfers are safe.
            if is_token_call && cx.uses_safe_erc20(c.contract) {
                continue;
            }

            // Permit2 (`IAllowanceTransfer` / `ISignatureTransfer`) is a
            // reverts-not-returns interface: its `transferFrom` returns **`void`**
            // and reverts on failure, so there is no boolean to check and ignoring
            // it is correct, not a bug. This is the realization of the general
            // rule "only flag a call that has a `bool` return to check": the IR
            // does not carry callee return types, but the one ERC-20-shaped
            // `transfer*` method that returns nothing is the Permit2 overload, so
            // we suppress it specifically. Two independent signals, either of which
            // identifies the Permit2 shape (one suffices — receiver type is often
            // inherited from a base and thus unresolved on the calling contract):
            //
            //   1. the receiver resolves to a Permit2 interface type, or is
            //      named like a Permit2 handle (`permit2`); OR
            //   2. the call is the 4-argument Permit2
            //      `transferFrom(address from, address to, uint160 amount,
            //      address token)` shape — distinct from the 3-argument ERC-20
            //      `transferFrom(address, address, uint256)`.
            //
            // The genuine bool-returning ERC-20 sites (`token.transfer(to, amt)`,
            // `PT.transfer(to, amt)`, 3-arg `token.transferFrom(a, b, amt)`) match
            // neither signal and keep firing.
            if c.func_name.as_deref() == Some("transferFrom") {
                let recv_is_permit2 = is_permit2_receiver(cx, c.function, &c.target);
                let four_arg_permit2 = transfer_from_arg_count(cx, c.span) == Some(4);
                if recv_is_permit2 || four_arg_permit2 {
                    continue;
                }
            }

            let (cat, title, sev, msg, rec) = if is_token_call {
                (
                    Category::UnsafeErc20,
                    "Unchecked ERC-20 transfer",
                    Severity::Medium,
                    "calls a raw ERC-20 transfer/approve and ignores the boolean return. Non-standard \
                     tokens (USDT, etc.) return false or revert, silently losing funds.",
                    "Use OpenZeppelin `SafeERC20` (`safeTransfer`/`safeTransferFrom`).",
                )
            } else {
                (
                    Category::UncheckedReturn,
                    "Unchecked low-level call",
                    Severity::Medium,
                    "ignores the success boolean of a low-level call/send. A failed call is swallowed, \
                     leaving the contract in an inconsistent state.",
                    "Check the returned success flag (`require(ok)`), or use a checked wrapper.",
                )
            };

            let (cname, fname) = cx.names(c.function);
            let b = FindingBuilder::new(self.id(), cat)
                .title(title)
                .severity(sev)
                .confidence(0.6)
                .dimension(Dimension::Frontier)
                .message(format!("`{cname}.{fname}` {msg}"))
                .recommendation(rec);
            out.push(cx.finish(b, c.function, c.span));
        }
        out
    }
}

/// True if the call receiver (the textual target string recorded for the
/// crossing, e.g. `permit2`) is the reverts-not-returns Permit2 interface — by
/// resolved declared type (`IAllowanceTransfer` / `ISignatureTransfer` /
/// `*Permit2*`) or, as a fallback when the handle is inherited and so not
/// declared on the calling contract, by a `permit2`-like name.
fn is_permit2_receiver(cx: &AnalysisContext, fid: FunctionId, target: &str) -> bool {
    // The textual target is the receiver expression text (`permit2`,
    // `PERMIT2`, `_permit2`, ...). An inline cast `IAllowanceTransfer(x)` would
    // render as such; check the raw text first.
    let t = target.trim();
    let lt = t.to_ascii_lowercase();
    if is_permit2_type(t) {
        return true;
    }

    // Resolve a bare-identifier receiver to its declared type via the calling
    // function's params and the owning contract's state vars (mirrors
    // `oracle::receiver_type`). Permit2 handles are conventionally typed
    // `IAllowanceTransfer`/`ISignatureTransfer`.
    if let Some(f) = cx.scir.function(fid) {
        if let Some(p) = f.params.iter().find(|p| p.name.as_deref() == Some(t)) {
            if is_permit2_type(&p.ty) {
                return true;
            }
        }
        if let Some(contract) = cx.scir.contract(f.contract) {
            if let Some(v) = contract.state_vars.iter().find(|v| v.name == t) {
                if is_permit2_type(&v.ty) {
                    return true;
                }
            }
        }
    }

    // Name fallback: a receiver named `permit2` (or `_permit2`) whose type we
    // could not resolve (inherited handle). Narrow enough to never match an
    // ERC-20 token handle (`token`, `currency`, `PT`, ...).
    lt == "permit2" || lt == "_permit2" || lt.ends_with(".permit2")
}

/// True if a declared type string names a Permit2 interface.
fn is_permit2_type(ty: &str) -> bool {
    let first = ty.split_whitespace().next().unwrap_or(ty);
    // Strip a leading cast/parenthesis (`IAllowanceTransfer(x)` -> name token).
    let name = first.split(['(', '<']).next().unwrap_or(first);
    let lower = name.to_ascii_lowercase();
    lower.contains("iallowancetransfer")
        || lower.contains("isignaturetransfer")
        || lower.contains("permit2")
}

/// Count the top-level (paren-depth-1) positional arguments of the call whose
/// span is given, when its callee method is `transferFrom`. Returns `None` if
/// the argument list cannot be located. Used to tell the 4-argument Permit2
/// `transferFrom(addr, addr, uint160, addr)` apart from the 3-argument ERC-20
/// `transferFrom(addr, addr, uint256)`.
///
/// `cx.source_text(span)` is comment-stripped and lowercased, and the crossing
/// span covers the whole call expression (callee + argument list), so scanning
/// from the `transferfrom(` opener and balancing parentheses yields the call's
/// own argument list (nested calls like `address(this)`/`uint160(x)` are
/// skipped by depth tracking).
fn transfer_from_arg_count(cx: &AnalysisContext, span: Span) -> Option<usize> {
    let text = cx.source_text(span);
    let bytes = text.as_bytes();
    // Find the method-name opener `transferfrom(` (already lowercased).
    let needle = "transferfrom";
    let mut search = 0usize;
    loop {
        let rel = text[search..].find(needle)?;
        let after = search + rel + needle.len();
        // Skip any whitespace between the name and `(`.
        let mut j = after;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'(' {
            return Some(count_top_level_args(&text[j..]));
        }
        search = after;
    }
}

/// Given a string starting at `(`, count the comma-separated arguments at the
/// matching top level, returning 0 for an empty `()`.
fn count_top_level_args(s: &str) -> usize {
    let bytes = s.as_bytes();
    debug_assert_eq!(bytes.first(), Some(&b'('));
    let mut depth = 0i32;
    let mut commas = 0usize;
    let mut saw_content = false;
    for &b in bytes {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            b',' if depth == 1 => commas += 1,
            b if depth == 1 && !b.is_ascii_whitespace() => saw_content = true,
            _ => {}
        }
    }
    if !saw_content && commas == 0 {
        0
    } else {
        commas + 1
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    fn fired(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.detector == "unchecked-return")
    }

    // TRUE POSITIVE: a raw 2-arg ERC-20 `token.transfer(to, amt)` returns a bool
    // that is dropped — must fire (the Lendf.me / unchecked-transfer class).
    const VULN_ERC20_TRANSFER: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC20 { function transfer(address to, uint256 amt) external returns (bool); }
        contract Payer {
            IERC20 public token;
            function pay(address to, uint256 amt) external { token.transfer(to, amt); }
        }
    "#;

    // TRUE POSITIVE: a bool-returning `PT.transfer(...)` whose return is ignored
    // (mirrors pendle BoringPtSeller) — must still fire.
    const VULN_PT_TRANSFER: &str = r#"
        pragma solidity ^0.8.20;
        interface IPPrincipalToken { function transfer(address to, uint256 amt) external returns (bool); }
        contract Seller {
            IPPrincipalToken public PT;
            function dump(address to, uint256 amt) external { PT.transfer(to, amt); }
        }
    "#;

    // TRUE POSITIVE: a raw 3-arg ERC-20 `transferFrom(from, to, amount)` (bool
    // return) — must still fire; the 4-arg Permit2 suppression must not catch it.
    const VULN_ERC20_TRANSFER_FROM: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC20 { function transferFrom(address f, address t, uint256 a) external returns (bool); }
        contract Puller {
            IERC20 public token;
            function pull(address f, uint256 a) external { token.transferFrom(f, address(this), a); }
        }
    "#;

    // FALSE POSITIVE (must be silent): the Permit2 `IAllowanceTransfer.transferFrom`
    // returns void and reverts — there is no bool to check. Both signals apply:
    // receiver typed `IAllowanceTransfer` AND the 4-argument shape.
    const SAFE_PERMIT2_TRANSFER_FROM: &str = r#"
        pragma solidity ^0.8.20;
        interface IAllowanceTransfer {
            function transferFrom(address from, address to, uint160 amount, address token) external;
        }
        contract Router {
            IAllowanceTransfer public immutable permit2;
            constructor(address p) { permit2 = IAllowanceTransfer(p); }
            function spotDeposit(uint160 amount, address token) external {
                permit2.transferFrom(msg.sender, address(this), amount, token);
            }
        }
    "#;

    // FALSE POSITIVE (must be silent): the Permit2 4-arg shape where the handle is
    // *inherited* (no local `permit2` state var / param to resolve a type from),
    // with a `uint160(...)` cast argument — the arity signal alone must suppress.
    const SAFE_PERMIT2_INHERITED: &str = r#"
        pragma solidity ^0.8.20;
        interface IAllowanceTransfer {
            function transferFrom(address from, address to, uint160 amount, address token) external;
        }
        abstract contract Forwarder {
            IAllowanceTransfer public immutable permit2;
            constructor(IAllowanceTransfer _p) { permit2 = _p; }
        }
        contract Manager is Forwarder {
            constructor(IAllowanceTransfer _p) Forwarder(_p) {}
            function settle(address payer, uint256 amount, address token) external {
                permit2.transferFrom(payer, address(this), uint160(amount), token);
            }
        }
    "#;

    #[test]
    fn fires_on_erc20_transfer() {
        assert!(fired(&run(VULN_ERC20_TRANSFER)), "raw 2-arg ERC-20 transfer must fire");
    }

    #[test]
    fn fires_on_pt_transfer() {
        assert!(fired(&run(VULN_PT_TRANSFER)), "bool-returning PT.transfer must fire");
    }

    #[test]
    fn fires_on_erc20_transfer_from() {
        assert!(fired(&run(VULN_ERC20_TRANSFER_FROM)), "raw 3-arg ERC-20 transferFrom must fire");
    }

    #[test]
    fn silent_on_permit2_transfer_from() {
        assert!(
            !fired(&run(SAFE_PERMIT2_TRANSFER_FROM)),
            "Permit2 (void, reverts) transferFrom must not fire"
        );
    }

    #[test]
    fn silent_on_permit2_inherited_handle() {
        assert!(
            !fired(&run(SAFE_PERMIT2_INHERITED)),
            "4-arg Permit2 transferFrom with inherited handle must not fire (arity signal)"
        );
    }
}
