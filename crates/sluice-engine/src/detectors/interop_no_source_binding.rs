//! Interop cross-domain handler that authenticates the SENDER but not the SOURCE
//! chain — a cross-chain replay / unbacked-mint frontier.
//!
//! ## The shape
//!
//! A predeploy (or any contract that lives at the *same address on every chain in
//! an interop cluster*) exposes a state-mutating handler that is invoked by the
//! cross-domain messenger. The handler:
//!
//!   1. gates `msg.sender == <messenger>` — confirms the call arrived through the
//!      messenger predeploy;
//!   2. reads the **cross-domain context tuple** — a `(sender, source)` pair via
//!      `crossDomainMessageContext()` (or a `crossDomainMessageSender()` +
//!      `crossDomainMessageSource()` pair);
//!   3. authorizes by checking the **sender identity** —
//!      `crossDomainMessageSender == address(this)` (the peer is "me on the other
//!      chain") or `== <peer>` — but **does NOT also gate the `source` chain id**
//!      it just read (it only emits / ignores it);
//!   4. moves value: `mint(...)`, a token `transfer`, or a native ETH send.
//!
//! Because authorization binds only "the message came from *this same contract
//! address*", and that address is identical on every chain in the cluster, a
//! message legitimately produced by the same predeploy on **chain B** is
//! replay-acceptable on **chain A**: the `address(this)` check still passes, and
//! the un-checked `source` was the only field that distinguished the originating
//! chain. The handler will `mint` / release value for a deposit that was burned
//! on a *different* chain than the one the funds are credited against — a
//! cross-cluster replay / unbacked mint.
//!
//! This is the **Optimism `SuperchainETHBridge.relayETH`** shape:
//!
//! ```solidity
//! function relayETH(address _from, address _to, uint256 _amount) external {
//!     if (msg.sender != Predeploys.L2_TO_L2_CROSS_DOMAIN_MESSENGER) revert Unauthorized();
//!     (address crossDomainMessageSender, uint256 source) =
//!         IL2ToL2CrossDomainMessenger(Predeploys.L2_TO_L2_CROSS_DOMAIN_MESSENGER).crossDomainMessageContext();
//!     if (crossDomainMessageSender != address(this)) revert InvalidCrossDomainSender();   // SENDER only
//!     IETHLiquidity(Predeploys.ETH_LIQUIDITY).mint(_amount);                               // value move
//!     new SafeSend{ value: _amount }(payable(_to));
//!     emit RelayETH(_from, _to, _amount, source);                                         // `source` only emitted
//! }
//! ```
//!
//! `source` is read into the tuple and then only emitted — never compared against
//! a configured/expected chain id — while `crossDomainMessageSender` *is* gated.
//!
//! ## Precision anchors (all required)
//!
//!   * an externally-reachable, state-mutating handler whose body gates
//!     `msg.sender [==|!=] <messenger>` (a cross-domain *messenger*-named operand);
//!   * the body reads a cross-domain **context** primitive
//!     (`crossDomainMessageContext` / `crossDomainMessageSender` /
//!     `xDomainMessageSender`);
//!   * a **sender-identity** check is present — a comparison against
//!     `address(this)` or a peer-named operand;
//!   * a **source / chainId** element is read (a `source` / `sourceChainId` /
//!     `origin*` destructured local or a `crossDomainMessageSource()` read) but is
//!     **never** itself placed in a comparison / `require` / `if` condition;
//!   * a **value move** runs (a `mint` / `burn` / `transfer`-shaped call, or any
//!     native-ETH send).
//!
//! ## Suppression
//!
//!   * the `source` element **is** gated — it appears in a comparison / require / if
//!     (the chain is bound, so no cross-cluster replay);
//!   * no cross-domain context primitive is read, or no sender-identity check is
//!     present (the legacy L1<->L2 `xDomainMessageSender() == otherBridge` bridges
//!     have a fixed point-to-point messenger and expose **no** source field — they
//!     are outside this class and stay silent);
//!   * the routing layer itself (`relayMessage`) — it reads `source` but performs
//!     no `== address(this)` sender-identity check and calls no context primitive,
//!     so it is excluded.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, CallKind, Expr, ExprKind, Function, Span, StmtKind};

use super::prelude::*;

pub struct InteropNoSourceBindingDetector;

impl Detector for InteropNoSourceBindingDetector {
    fn id(&self) -> &'static str {
        "interop-no-source-binding"
    }
    fn category(&self) -> Category {
        Category::InteropNoSourceBinding
    }
    fn description(&self) -> &'static str {
        "Interop cross-domain handler authenticates the message sender (== address(this)/peer) but never gates \
         the source chain id it reads, then moves value — a same-predeploy cross-cluster replay / unbacked mint \
         (Optimism SuperchainETHBridge.relayETH class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.entry_points() {
            // Interfaces / libraries declare no inbound handler logic.
            if let Some(c) = cx.contract_of(f.id) {
                if c.is_interface() || c.is_library() {
                    continue;
                }
            }
            if let Some(hit) = analyze(cx, f) {
                out.push(self.finding(cx, f, &hit));
            }
        }
        out
    }
}

impl InteropNoSourceBindingDetector {
    fn finding(&self, cx: &AnalysisContext, f: &Function, hit: &Hit) -> Finding {
        let b = report!(self, Category::InteropNoSourceBinding,
            title = "Interop handler checks the cross-domain sender but not the source chain, then moves value",
            severity = Severity::High,
            confidence = 0.8,
            dimensions = [Dimension::Invariant, Dimension::Frontier],
            message = format!(
                "`{fname}` is an inbound cross-domain handler (gated on `msg.sender == <messenger>`) that reads \
                 the cross-domain context (`{ctx}`) and authorizes on the **sender identity** \
                 (`{sender_check}`) — i.e. it trusts that the message came from *this same contract address* — \
                 but reads the **source chain id `{src}` without ever comparing it**: `{src}` is only emitted / \
                 ignored, never placed in a `require` / `if` / comparison. It then moves value (`{mover}`). \
                 Because a predeploy lives at the *same address on every chain in the interop cluster*, the \
                 `== address(this)` (peer) check also passes for a message produced by the same predeploy on a \
                 **different** cluster chain — so a message can be replayed cross-chain and the handler will \
                 mint / release funds against the wrong source. This is the interop cross-chain-replay / \
                 unbacked-mint class (Optimism `SuperchainETHBridge.relayETH`: gates \
                 `crossDomainMessageSender == address(this)` but only `emit`s the `source` it read).",
                fname = f.name,
                ctx = hit.context_call,
                sender_check = hit.sender_check_desc,
                src = hit.source_field,
                mover = hit.mover_desc,
            ),
            recommendation =
                "Authorize on the (source chain id, sender) pair, not the sender alone. After reading the \
                 cross-domain context, gate the source against the set of chains this handler accepts \
                 (`require(isAllowedSource[source])` / `require(source == expectedChainId)`), or include the \
                 source chain id in the replay-protection key so a message from the same predeploy on another \
                 cluster chain cannot be replayed here. Do not move value on the strength of a \
                 `sender == address(this)` check while leaving the source chain unconstrained.",
        );
        finish_at(cx, b, f.id, hit.span)
    }
}

// --------------------------------------------------------------------- analysis

/// A matched interop-no-source-binding handler.
struct Hit {
    /// The cross-domain context primitive read (`crossDomainMessageContext`).
    context_call: String,
    /// Human description of the sender-identity check (`== address(this)`).
    sender_check_desc: String,
    /// The source/chainId element name that is read but never gated (`source`).
    source_field: String,
    /// Description of the value-moving call.
    mover_desc: String,
    /// Report location (the function).
    span: Span,
}

fn analyze(cx: &AnalysisContext, f: &Function) -> Option<Hit> {
    // (1) Inbound cross-domain frontier: a `msg.sender [==|!=] <messenger>` guard.
    if !has_messenger_sender_guard(f) {
        return None;
    }

    // (2) Reads a cross-domain *context* primitive (the sender+source tuple, or a
    //     sender getter). This anchors us to the interop messenger pattern and
    //     excludes the routing layer (`relayMessage`), which provides — but never
    //     reads — the context.
    let context_call = context_primitive_call(f)?;

    // (3) A sender-IDENTITY check: a comparison against `address(this)` or a peer.
    let sender_check_desc = sender_identity_check(f)?;

    // (4) A source / chainId element is read. Prefer the 2nd destructured local of
    //     `(.., src) = crossDomainMessageContext()`; else any source-named local /
    //     a `crossDomainMessageSource()` read.
    let source_field = source_element_name(cx, f)?;

    // (5) SUPPRESS: the source element is gated (compared / required) somewhere.
    if source_is_gated(f, &source_field) {
        return None;
    }

    // (6) A value move runs (mint / burn / transfer / native ETH send).
    let mover_desc = value_mover(f)?;

    Some(Hit {
        context_call,
        sender_check_desc,
        source_field,
        mover_desc,
        span: f.span,
    })
}

// ---------------------------------------------------- (1) messenger sender guard

/// Does the body contain a comparison `msg.sender [==|!=] X` where `X` is a
/// cross-domain *messenger*-like operand (its name mentions `messenger` /
/// `crossdomain` / `l2tol2` / a `*MESSENGER*` predeploy member)? This is the
/// inbound-handler frontier that says "the call arrived via the messenger".
fn has_messenger_sender_guard(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
                if matches!(op, BinOp::Eq | BinOp::Ne) {
                    let (a, b) = (lhs.as_ref(), rhs.as_ref());
                    let sides_are_sender_vs_messenger = (is_msg_sender(a) && is_messenger_operand(b))
                        || (is_msg_sender(b) && is_messenger_operand(a));
                    if sides_are_sender_vs_messenger {
                        found = true;
                    }
                }
            }
        });
        if found {
            break;
        }
    }
    found
}

/// `msg.sender`.
fn is_msg_sender(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Member { base, member }
        if member == "sender" && matches!(&base.kind, ExprKind::Ident(n) if n == "msg"))
}

/// An operand naming a cross-domain messenger (the predeploy / handle). Matches on
/// the *last* name segment of an ident/member chain.
fn is_messenger_operand(e: &Expr) -> bool {
    let name = match &e.kind {
        ExprKind::Ident(n) => n.clone(),
        ExprKind::Member { member, .. } => member.clone(),
        // `IFoo(x)` cast — look through to the inner operand's name.
        ExprKind::Call(c) if c.kind == CallKind::TypeCast => {
            return c.args.first().is_some_and(is_messenger_operand);
        }
        _ => return false,
    };
    let l = name.to_ascii_lowercase();
    l.contains("messenger") || l.contains("crossdomain") || l.contains("l2_to_l2") || l.contains("l2tol2")
}

// ---------------------------------------------- (2) cross-domain context primitive

/// Names of the cross-domain *context* primitives — a call that yields the
/// `(sender, source)` pair (or the sender) for the in-flight message.
const CONTEXT_PRIMITIVES: &[&str] =
    &["crossdomainmessagecontext", "crossdomainmessagesender", "xdomainmessagesender"];

/// Find a call to a cross-domain context primitive; return its (display-cased)
/// name. Structural — keyed on the resolved `func_name`.
fn context_primitive_call(f: &Function) -> Option<String> {
    let mut found: Option<String> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if let Some(name) = c.func_name.as_deref() {
                    if CONTEXT_PRIMITIVES.contains(&name.to_ascii_lowercase().as_str()) {
                        found = Some(format!("{name}()"));
                    }
                }
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

// ------------------------------------------------- (3) sender-identity check

/// A sender-identity comparison: `<x> [==|!=] address(this)` or `<x> [==|!=]
/// <peer>` (a peer-named operand). This is the "the peer is me on the other
/// chain" authorization — present in the vulnerable handler, ABSENT in the
/// router (`relayMessage`), which checks `_id.origin` against the messenger
/// predeploy instead. Returns a human description.
fn sender_identity_check(f: &Function) -> Option<String> {
    let mut desc: Option<String> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if desc.is_some() {
                return;
            }
            if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
                if !matches!(op, BinOp::Eq | BinOp::Ne) {
                    return;
                }
                let (a, b) = (lhs.as_ref(), rhs.as_ref());
                if is_address_this(a) || is_address_this(b) {
                    desc = Some("== address(this)".to_string());
                } else if let Some(p) = peer_operand_name(a).or_else(|| peer_operand_name(b)) {
                    desc = Some(format!("== {p}"));
                }
            }
        });
        if desc.is_some() {
            break;
        }
    }
    desc
}

/// `address(this)` — a cast `address(...)` whose sole argument is `this`.
fn is_address_this(e: &Expr) -> bool {
    if let ExprKind::Call(c) = &e.kind {
        if c.kind == CallKind::TypeCast {
            // `address(this)`
            if matches!(&c.callee.kind, ExprKind::TypeName(t) if t.eq_ignore_ascii_case("address"))
                || c.func_name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case("address"))
            {
                return c.args.iter().any(|a| matches!(&a.kind, ExprKind::Ident(n) if n == "this"));
            }
        }
    }
    // bare `this`
    matches!(&e.kind, ExprKind::Ident(n) if n == "this")
}

/// Name of a peer-like operand (`peer`, `trustedRemote`, `otherBridge`, `remote`,
/// `counterpart`) — the configured cross-chain twin. Matched on the last name
/// segment of an ident/member/index chain.
fn peer_operand_name(e: &Expr) -> Option<String> {
    let name = match &e.kind {
        ExprKind::Ident(n) => n.clone(),
        ExprKind::Member { member, .. } => member.clone(),
        ExprKind::Index { base, .. } => return peer_operand_name(base),
        _ => return None,
    };
    let l = name.to_ascii_lowercase();
    const PEERS: &[&str] = &["peer", "trustedremote", "otherbridge", "counterpart", "remotebridge"];
    if PEERS.iter().any(|p| l.contains(p)) {
        Some(name)
    } else {
        None
    }
}

// ----------------------------------------- (4) source / chainId element read

/// The name of the source/chainId element read from the cross-domain context.
/// Two recognized origins:
///   1. the **2nd destructured local** of `(.., <ty> <name>) =
///      <...>crossDomainMessageContext();` (the canonical interop tuple — the
///      sender is the 1st return, the source chain id is the 2nd);
///   2. otherwise any **source-named local** declared in the body
///      (`uint256 source = ...crossDomainMessageSource();`).
fn source_element_name(cx: &AnalysisContext, f: &Function) -> Option<String> {
    // (1) Parse the destructure out of the (normalized, lowercased) source text.
    //     The tuple types are erased in the IR, so the binding names — which the
    //     source text preserves — are the reliable handle.
    let src = cx.source_text(f.span);
    if let Some(name) = destructured_source_name(&src) {
        return Some(name);
    }

    // (2) A source-named local declared anywhere in the body.
    let mut found: Option<String> = None;
    for s in &f.body {
        s.visit(&mut |st| {
            if found.is_some() {
                return;
            }
            if let StmtKind::VarDecl { name: Some(n), .. } = &st.kind {
                if is_source_field_name(n) {
                    found = Some(n.clone());
                }
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// From normalized text `( ... , <type> <name> ) = <expr>crossdomainmessagecontext()`,
/// return the second binding's `<name>`. Robust to whitespace/newlines. We only
/// trust this when the right-hand side is a `crossDomainMessageContext()` call, so
/// the second element really is the *source chain id* of the interop tuple.
fn destructured_source_name(src: &str) -> Option<String> {
    let l = src; // already lowercased by source_text
    // Locate a destructuring assignment that binds from crossdomainmessagecontext.
    // Find the assignment's '=' that precedes a crossdomainmessagecontext call.
    let ctx_pos = l.find("crossdomainmessagecontext")?;
    // The tuple is the parenthesized group ending at the '=' before ctx_pos.
    let eq_pos = l[..ctx_pos].rfind('=')?;
    let before_eq = &l[..eq_pos];
    let open = before_eq.rfind('(')?;
    let close = before_eq[open..].find(')').map(|i| open + i)?;
    if close <= open {
        return None;
    }
    let tuple = &before_eq[open + 1..close];
    // Expect at least two comma-separated members; take the LAST member's name.
    let members: Vec<&str> = tuple.split(',').collect();
    if members.len() < 2 {
        return None;
    }
    let last = members.last()?.trim();
    // `<type> <name>` or just `<name>` (skipped slot `,)` would be empty).
    let name = last.split_whitespace().last()?.trim();
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

/// Does a binding name look like a source / source-chain element?
fn is_source_field_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "source"
        || l == "src"
        || l.starts_with("source")
        || l.starts_with("srcchain")
        || l == "origin"
        || l.starts_with("originchain")
        || l.ends_with("sourcechainid")
        || l.ends_with("sourcechain")
}

// ----------------------------------------------- (5) is the source gated?

/// SUPPRESS gate: does the source element `src` ever appear in a *comparison* —
/// a binary `==`/`!=`/ordering, or as the indexed key of an allow-set lookup
/// (`isAllowed[source]`), or inside a `require`/`assert`/`if`/`revert` condition?
/// Any of these means the chain id is bound and there is no cross-cluster replay.
fn source_is_gated(f: &Function, src: &str) -> bool {
    let mut gated = false;

    // (a) a comparison operand, or an allow-set index, anywhere.
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if gated {
                return;
            }
            match &e.kind {
                ExprKind::Binary { op, lhs, rhs } if op.is_comparison() => {
                    if expr_mentions_ident(lhs, src) || expr_mentions_ident(rhs, src) {
                        gated = true;
                    }
                }
                // `allowed[source]` / `expectedChain[source]` — a membership lookup
                // keyed by the source is a binding.
                ExprKind::Index { index: Some(idx), .. } => {
                    if matches!(&idx.kind, ExprKind::Ident(n) if n == src) {
                        gated = true;
                    }
                }
                _ => {}
            }
        });
        if gated {
            break;
        }
    }
    if gated {
        return true;
    }

    // (b) referenced inside an `if`/`while` condition or a `require`/`revert`.
    for s in &f.body {
        s.visit(&mut |st| {
            if gated {
                return;
            }
            match &st.kind {
                StmtKind::If { cond, .. } | StmtKind::While { cond, .. } | StmtKind::DoWhile { cond, .. } => {
                    if expr_mentions_ident(cond, src) {
                        gated = true;
                    }
                }
                StmtKind::Revert { args, .. } => {
                    if args.iter().any(|a| expr_mentions_ident(a, src)) {
                        gated = true;
                    }
                }
                StmtKind::Expr(e) => {
                    if let ExprKind::Call(c) = &e.kind {
                        if is_require_or_assert(c) && c.args.iter().any(|a| expr_mentions_ident(a, src)) {
                            gated = true;
                        }
                    }
                }
                _ => {}
            }
        });
        if gated {
            break;
        }
    }
    gated
}

// ------------------------------------------------------------ (6) value mover

/// A value-moving call: a `mint`/`burn`/`transfer`-shaped method, OR any native
/// ETH send (a call carrying `{value:}`, a `.transfer`/`.send`, or a `new C{value:}`
/// construction). Returns a description of the first one found.
fn value_mover(f: &Function) -> Option<String> {
    let mut desc: Option<String> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if desc.is_some() {
                return;
            }
            // `new SafeSend{ value: x }(...)` — the New wraps a Call carrying value.
            if let ExprKind::New(inner) = &e.kind {
                if let ExprKind::Call(c) = &inner.kind {
                    if c.value.is_some() {
                        desc = Some(format!(
                            "new {}{{ value: … }}(...)",
                            c.func_name.clone().unwrap_or_else(|| "C".into())
                        ));
                        return;
                    }
                }
            }
            let ExprKind::Call(c) = &e.kind else { return };
            // A native-value send is always a value move.
            if c.value.is_some() || matches!(c.kind, CallKind::Transfer | CallKind::Send) {
                desc = Some(c.func_name.clone().unwrap_or_else(|| "value send".into()));
                return;
            }
            // A name-matched mover must be a real invocation (not a revert-error ctor).
            if !matches!(
                c.kind,
                CallKind::External | CallKind::LowLevelCall | CallKind::DelegateCall | CallKind::Internal
            ) {
                return;
            }
            if let Some(name) = c.func_name.as_deref() {
                if is_value_mover_name(name) {
                    desc = Some(name.to_string());
                }
            }
        });
        if desc.is_some() {
            break;
        }
    }
    desc
}

/// Method names that move value (mint / burn / transfer family), camelCase-boundary
/// aware so revert-error identifiers that merely begin with a verb are not matched.
fn is_value_mover_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    const ERROR_TOKENS: &[&str] =
        &["invalid", "mismatch", "exceed", "zero", "empty", "notqueued", "already", "unauthorized"];
    if ERROR_TOKENS.iter().any(|t| l.contains(t)) {
        return false;
    }
    const MOVERS: &[&str] =
        &["mint", "burn", "transfer", "withdraw", "redeem", "release", "send", "deposit", "pay", "credit"];
    for m in MOVERS {
        if l == *m {
            return true;
        }
        // camelCase prefix (`safeTransferFrom` via `transfer`, `mintTo`): the verb
        // is a prefix and the next ORIGINAL char is upper-case (a word boundary).
        if let Some(rest) = l.strip_prefix(m) {
            if rest.is_empty() {
                return true;
            }
            if name.as_bytes().get(m.len()).copied().is_some_and(|b| b.is_ascii_uppercase()) {
                return true;
            }
        }
        // suffix at a boundary (`safeTransfer`, `_mint`, `_burn`).
        if let Some(pos) = l.rfind(m) {
            if pos > 0 && pos + m.len() == l.len() {
                let before = name.as_bytes()[pos - 1];
                if before.is_ascii_uppercase() || before == b'_' {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "interop-no-source-binding")
    }

    // VULN — the Optimism `SuperchainETHBridge.relayETH` shape, reduced: gates
    // `msg.sender == messenger`, reads `(sender, source) = crossDomainMessageContext()`,
    // checks `sender == address(this)` but only EMITS `source`, then mints + sends ETH.
    const VULN: &str = r#"
        pragma solidity 0.8.15;
        interface IL2ToL2CrossDomainMessenger { function crossDomainMessageContext() external view returns (address, uint256); }
        interface IETHLiquidity { function mint(uint256 a) external; }
        library Predeploys { address constant L2_TO_L2_CROSS_DOMAIN_MESSENGER = address(0x4200000000000000000000000000000000000023); address constant ETH_LIQUIDITY = address(0x4200000000000000000000000000000000000025); }
        contract SuperchainETHBridge {
            error Unauthorized();
            error InvalidCrossDomainSender();
            event RelayETH(address indexed from, address indexed to, uint256 amount, uint256 source);
            function relayETH(address _from, address _to, uint256 _amount) external {
                if (msg.sender != Predeploys.L2_TO_L2_CROSS_DOMAIN_MESSENGER) revert Unauthorized();
                (address crossDomainMessageSender, uint256 source) =
                    IL2ToL2CrossDomainMessenger(Predeploys.L2_TO_L2_CROSS_DOMAIN_MESSENGER).crossDomainMessageContext();
                if (crossDomainMessageSender != address(this)) revert InvalidCrossDomainSender();
                IETHLiquidity(Predeploys.ETH_LIQUIDITY).mint(_amount);
                payable(_to).transfer(_amount);
                emit RelayETH(_from, _to, _amount, source);
            }
        }
    "#;

    // VULN (token-mint variant): same context read + sender-only check, but the
    // value move is a token `mint(to, amount)` and source is just ignored.
    const VULN_MINT: &str = r#"
        pragma solidity 0.8.20;
        interface IMessenger { function crossDomainMessageContext() external view returns (address, uint256); }
        interface IToken { function mint(address to, uint256 a) external; }
        contract SuperToken {
            address public constant MESSENGER = address(0x4200000000000000000000000000000000000023);
            IToken public token;
            error BadSender();
            function relayMint(address _to, uint256 _amount) external {
                require(msg.sender == MESSENGER, "not messenger");
                (address sender, uint256 source) = IMessenger(MESSENGER).crossDomainMessageContext();
                require(sender == address(this), "bad peer");
                token.mint(_to, _amount);
            }
        }
    "#;

    // SAFE (source gated) — identical shape but the handler ALSO requires the
    // source chain id is in an allow-set, so cross-cluster replay is blocked.
    const SAFE_SOURCE_GATED: &str = r#"
        pragma solidity 0.8.15;
        interface IMessenger { function crossDomainMessageContext() external view returns (address, uint256); }
        interface IETHLiquidity { function mint(uint256 a) external; }
        contract SuperchainETHBridge {
            address public constant MESSENGER = address(0x4200000000000000000000000000000000000023);
            address public constant LIQ = address(0x4200000000000000000000000000000000000025);
            mapping(uint256 => bool) public allowedSource;
            error Unauthorized();
            error InvalidCrossDomainSender();
            function relayETH(address _to, uint256 _amount) external {
                if (msg.sender != MESSENGER) revert Unauthorized();
                (address crossDomainMessageSender, uint256 source) =
                    IMessenger(MESSENGER).crossDomainMessageContext();
                if (crossDomainMessageSender != address(this)) revert InvalidCrossDomainSender();
                require(allowedSource[source], "bad source");
                IETHLiquidity(LIQ).mint(_amount);
                payable(_to).transfer(_amount);
            }
        }
    "#;

    // SAFE (source equality-gated) — source compared against an expected chain id.
    const SAFE_SOURCE_EQ: &str = r#"
        pragma solidity 0.8.15;
        interface IMessenger { function crossDomainMessageContext() external view returns (address, uint256); }
        interface IToken { function mint(address to, uint256 a) external; }
        contract SuperToken {
            address public constant MESSENGER = address(0x4200000000000000000000000000000000000023);
            uint256 public expectedChain;
            IToken public token;
            function relayMint(address _to, uint256 _amount) external {
                require(msg.sender == MESSENGER, "not messenger");
                (address sender, uint256 source) = IMessenger(MESSENGER).crossDomainMessageContext();
                require(sender == address(this), "bad peer");
                require(source == expectedChain, "bad source");
                token.mint(_to, _amount);
            }
        }
    "#;

    // SAFE (legacy L1<->L2 bridge) — the StandardBridge.finalizeBridgeETH shape:
    // gated by `xDomainMessageSender() == otherBridge` (a peer check, NOT a tuple
    // context with a source field). There is NO source element read at all, so it
    // is outside the class and must stay silent.
    const SAFE_LEGACY_BRIDGE: &str = r#"
        pragma solidity 0.8.15;
        interface IMessenger { function xDomainMessageSender() external view returns (address); }
        contract StandardBridge {
            IMessenger public messenger;
            address public otherBridge;
            modifier onlyOtherBridge() {
                require(msg.sender == address(messenger) && messenger.xDomainMessageSender() == otherBridge, "no");
                _;
            }
            function finalizeBridgeETH(address _from, address _to, uint256 _amount) external payable onlyOtherBridge {
                require(_to != address(this), "self");
                payable(_to).transfer(_amount);
            }
        }
    "#;

    // SAFE (routing layer = relayMessage) — reads `source` and never compares it,
    // moves value (target.call), BUT performs no `== address(this)` sender-identity
    // check and calls NO context primitive (it provides the context). Excluded.
    const SAFE_ROUTER: &str = r#"
        pragma solidity 0.8.15;
        library Predeploys { address constant L2_TO_L2_CROSS_DOMAIN_MESSENGER = address(0x4200000000000000000000000000000000000023); }
        struct Identifier { address origin; uint256 chainId; }
        contract L2ToL2CrossDomainMessenger {
            mapping(bytes32 => bool) public successfulMessages;
            error IdOriginNotMessenger();
            error MessageAlreadyRelayed();
            function relayMessage(Identifier calldata _id, bytes calldata _sentMessage) external payable returns (bytes memory returnData_) {
                if (_id.origin != Predeploys.L2_TO_L2_CROSS_DOMAIN_MESSENGER) revert IdOriginNotMessenger();
                uint256 source = _id.chainId;
                bytes32 messageHash = keccak256(abi.encode(source, _sentMessage));
                if (successfulMessages[messageHash]) revert MessageAlreadyRelayed();
                successfulMessages[messageHash] = true;
                (bool success, bytes memory r) = address(this).call{ value: msg.value }(_sentMessage);
                returnData_ = r;
                require(success, "fail");
            }
        }
    "#;

    // SAFE (no context primitive) — gates msg.sender against a messenger and checks
    // address(this), moves value, but never reads a cross-domain context primitive
    // or a source field. Outside the class.
    const SAFE_NO_CONTEXT: &str = r#"
        pragma solidity 0.8.15;
        contract Thing {
            address public constant MESSENGER = address(0x4200000000000000000000000000000000000023);
            function f(address _to, uint256 _amount) external {
                require(msg.sender == MESSENGER, "no");
                require(_to != address(this), "self");
                payable(_to).transfer(_amount);
            }
        }
    "#;

    #[test]
    fn fires_on_superchain_eth_bridge_relay_eth() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_token_mint_variant() {
        assert!(fires(VULN_MINT), "{:#?}", run(VULN_MINT));
    }

    #[test]
    fn silent_when_source_in_allow_set() {
        assert!(!fires(SAFE_SOURCE_GATED), "{:#?}", run(SAFE_SOURCE_GATED));
    }

    #[test]
    fn silent_when_source_equality_checked() {
        assert!(!fires(SAFE_SOURCE_EQ), "{:#?}", run(SAFE_SOURCE_EQ));
    }

    #[test]
    fn silent_on_legacy_l1l2_bridge() {
        assert!(!fires(SAFE_LEGACY_BRIDGE), "{:#?}", run(SAFE_LEGACY_BRIDGE));
    }

    #[test]
    fn silent_on_routing_layer() {
        assert!(!fires(SAFE_ROUTER), "{:#?}", run(SAFE_ROUTER));
    }

    #[test]
    fn silent_without_context_primitive() {
        assert!(!fires(SAFE_NO_CONTEXT), "{:#?}", run(SAFE_NO_CONTEXT));
    }
}
