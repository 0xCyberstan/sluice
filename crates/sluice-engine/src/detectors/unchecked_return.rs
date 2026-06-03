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
                // A raw ERC-20 transfer/transferFrom whose receiver resolves to a
                // FIXED, trusted, in-protocol token — an `immutable`/`constant`
                // state var, or a receiver whose name/type is a canonical
                // revert-on-failure token (`WETH9`/`IWETH`, `stETH`/`wstETH`) —
                // does not lose funds silently: such tokens return `true` or revert,
                // so the dropped boolean is never `false`. The "non-standard token
                // like USDT returns false" narrative does not apply to a hardcoded
                // protocol-owned token. Downgrade to Low (a hygiene note: a
                // `require`/`SafeERC20` is still best practice) and drop the
                // USDT-style wording. The Medium case — an arbitrary /
                // caller-supplied / parameter token address, where the
                // returns-false risk is genuine — is preserved unchanged.
                if is_fixed_in_protocol_token(cx, c.function, &c.target) {
                    (
                        Category::UnsafeErc20,
                        "Unchecked transfer of trusted in-protocol token",
                        Severity::Low,
                        "ignores the boolean return of a transfer on a fixed, in-protocol token \
                         (a hardcoded/immutable WETH/stETH-class token that returns true or reverts). \
                         No funds are lost silently here, but checking the result is still best practice.",
                        "For hygiene, route the transfer through `SafeERC20` (`safeTransfer`/`safeTransferFrom`) \
                         or wrap it in a `require`.",
                    )
                } else {
                    (
                        Category::UnsafeErc20,
                        "Unchecked ERC-20 transfer",
                        Severity::Medium,
                        "calls a raw ERC-20 transfer/approve and ignores the boolean return. Non-standard \
                         tokens (USDT, etc.) return false or revert, silently losing funds.",
                        "Use OpenZeppelin `SafeERC20` (`safeTransfer`/`safeTransferFrom`).",
                    )
                }
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

/// True if the receiver of an ERC-20 `transfer`/`transferFrom` resolves to a
/// FIXED, trusted, in-protocol token — one whose `transfer` is known to return
/// `true` or revert (never the USDT-style silent `false`). Two independent
/// signals, either of which is sufficient:
///
///   1. the receiver's ROOT identifier is an `immutable`/`constant` state var on
///      the calling contract (a token wired once at construction: WETH9, the
///      protocol's own stETH/wstETH module), OR
///   2. the receiver's name or declared type is a canonical revert-on-failure
///      token (`WETH9`/`IWETH`/`*WETH*`, `stETH`/`STETH`, `wstETH`/`WSTETH`).
///
/// The name/type signal is what catches a non-immutable but still-canonical
/// handle — e.g. Lido's `WstETH.sol` holds `IStETH public stETH` (a plain state
/// var) and calls `stETH.transfer(...)`.
///
/// An arbitrary / caller-supplied / parameter token (`IERC20(userToken)`, a
/// `token` param, a mutable `token` var) matches NEITHER and stays Medium, so the
/// genuine USDT-returns-false risk is preserved.
fn is_fixed_in_protocol_token(cx: &AnalysisContext, fid: FunctionId, target: &str) -> bool {
    let root = sluice_frontier::target_root(target.trim());
    // Signal 2 (text): the receiver expression text itself names a canonical
    // token — covers inline casts like `IWETH9(x).transfer(...)` and the bare
    // identifier alike.
    if is_canonical_token_name(root) || is_canonical_token_type(target.trim()) {
        return true;
    }

    if let Some(f) = cx.scir.function(fid) {
        // Signal 2 (param type): a receiver that is a function parameter whose
        // declared type is a canonical token (a token handed in but still of the
        // fixed WETH/stETH class — its transfer reverts, never returns false).
        if let Some(p) = f.params.iter().find(|p| p.name.as_deref() == Some(root)) {
            if is_canonical_token_type(&p.ty) {
                return true;
            }
        }
        if let Some(contract) = cx.scir.contract(f.contract) {
            if let Some(v) = contract.state_vars.iter().find(|v| v.name == root) {
                // Signal 1: a fixed (immutable/constant) state var — wired once at
                // construction and never reassignable.
                if v.immutable || v.constant {
                    return true;
                }
                // Signal 2 (state-var type): a state var typed as a canonical token.
                if is_canonical_token_type(&v.ty) {
                    return true;
                }
            }
        }
    }
    false
}

/// True if an identifier names a canonical revert-on-failure token (case-
/// insensitive): the WETH family (`WETH`/`WETH9`/`weth9`) or the Lido staked-ETH
/// family (`stETH`/`STETH`/`wstETH`/`WSTETH`). Substring match so handles like
/// `_weth9` / `wstEth` are caught. Deliberately narrow — a generic `token` /
/// `currency` / `asset` receiver is NOT canonical and stays Medium.
fn is_canonical_token_name(name: &str) -> bool {
    let n = name.trim_start_matches('_').to_ascii_lowercase();
    n.contains("weth") || n.contains("steth")
}

/// True if a declared type string names a canonical revert-on-failure token
/// interface (`IWETH`/`IWETH9`/`WETH9`, `IStETH`/`IWstETH`/`WstETH`, ...). The
/// leading type token is taken (an inline cast `IWETH9(x)` renders the name
/// first), then matched against the WETH / stETH families. The `steth` substring
/// also subsumes `wsteth`.
fn is_canonical_token_type(ty: &str) -> bool {
    let first = ty.split_whitespace().next().unwrap_or(ty);
    let name = first.split(['(', '<']).next().unwrap_or(first);
    is_canonical_token_name(name)
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

    /// The severity of the (single) `unchecked-return` finding, or `None` if it
    /// did not fire.
    fn ur_severity(fs: &[sluice_findings::Finding]) -> Option<sluice_findings::Severity> {
        fs.iter().find(|f| f.detector == "unchecked-return").map(|f| f.severity)
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

    // ---- trusted in-protocol token downgrade (Medium -> Low) ----
    use sluice_findings::Severity;

    // An `immutable` WETH9 handle whose `transfer` return is dropped is a hygiene
    // note, not a fund-loss bug (WETH9 returns true / reverts). Mirrors
    // universal-router `Payments.wrapETH` (`IWETH9 internal immutable WETH9`).
    // Must still FIRE, but at LOW.
    const FIXED_IMMUTABLE_WETH9: &str = r#"
        pragma solidity ^0.8.20;
        interface IWETH9 { function transfer(address to, uint256 amt) external returns (bool); function deposit() external payable; }
        contract Payments {
            IWETH9 internal immutable WETH9;
            constructor(address w) { WETH9 = IWETH9(w); }
            function wrapETH(address recipient, uint256 amount) external {
                WETH9.transfer(recipient, amount);
            }
        }
    "#;

    // A non-immutable but canonically-named stETH handle (Lido `WstETH.sol` holds
    // `IStETH public stETH`). The name/type signal must downgrade it to LOW even
    // though it is a plain (reassignable-typed) state var.
    const FIXED_STETH_BY_NAME: &str = r#"
        pragma solidity ^0.8.20;
        interface IStETH { function transfer(address to, uint256 amt) external returns (bool); function transferFrom(address f, address t, uint256 a) external returns (bool); }
        contract WstETH {
            IStETH public stETH;
            constructor(IStETH _s) { stETH = _s; }
            function unwrap(uint256 amt) external { stETH.transfer(msg.sender, amt); }
        }
    "#;

    // An immutable STETH/WSTETH `transferFrom` (3-arg ERC-20 shape) — Lido
    // `WithdrawalQueue`. Must fire at LOW (immutable signal), and the 4-arg
    // Permit2 suppression must not swallow the 3-arg call.
    const FIXED_IMMUTABLE_STETH_TRANSFER_FROM: &str = r#"
        pragma solidity ^0.8.20;
        interface IStETH { function transferFrom(address f, address t, uint256 a) external returns (bool); }
        contract WithdrawalQueue {
            IStETH public immutable STETH;
            constructor(IStETH _s) { STETH = _s; }
            function requestWithdrawal(uint256 amt) external {
                STETH.transferFrom(msg.sender, address(this), amt);
            }
        }
    "#;

    // ARBITRARY / caller-supplied token via inline cast `IERC20(userToken)` — the
    // genuine USDT-returns-false risk. Must stay MEDIUM.
    const ARBITRARY_TOKEN_TRANSFER: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC20 { function transfer(address to, uint256 amt) external returns (bool); }
        contract Router {
            function rescue(address userToken, address to, uint256 amt) external {
                IERC20(userToken).transfer(to, amt);
            }
        }
    "#;

    #[test]
    fn fires_low_on_immutable_weth9() {
        assert_eq!(
            ur_severity(&run(FIXED_IMMUTABLE_WETH9)),
            Some(Severity::Low),
            "immutable WETH9.transfer must fire at Low (trusted in-protocol token)"
        );
    }

    #[test]
    fn fires_low_on_steth_by_name() {
        assert_eq!(
            ur_severity(&run(FIXED_STETH_BY_NAME)),
            Some(Severity::Low),
            "canonically-named stETH.transfer must fire at Low even when not immutable"
        );
    }

    #[test]
    fn fires_low_on_immutable_steth_transfer_from() {
        assert_eq!(
            ur_severity(&run(FIXED_IMMUTABLE_STETH_TRANSFER_FROM)),
            Some(Severity::Low),
            "immutable STETH.transferFrom (3-arg) must fire at Low"
        );
    }

    #[test]
    fn fires_medium_on_arbitrary_token_cast() {
        assert_eq!(
            ur_severity(&run(ARBITRARY_TOKEN_TRANSFER)),
            Some(Severity::Medium),
            "IERC20(userToken).transfer must stay Medium (USDT-returns-false risk is real)"
        );
    }

    // Recall guard: the arbitrary-token corpus shapes must stay MEDIUM, not get
    // swept into Low. A generic `token`/`PT` receiver is not a canonical token.
    #[test]
    fn arbitrary_receivers_stay_medium() {
        assert_eq!(
            ur_severity(&run(VULN_ERC20_TRANSFER)),
            Some(Severity::Medium),
            "generic `token.transfer` must stay Medium"
        );
        assert_eq!(
            ur_severity(&run(VULN_PT_TRANSFER)),
            Some(Severity::Medium),
            "generic `PT.transfer` must stay Medium"
        );
        assert_eq!(
            ur_severity(&run(VULN_ERC20_TRANSFER_FROM)),
            Some(Severity::Medium),
            "generic 3-arg `token.transferFrom` must stay Medium"
        );
    }
}
