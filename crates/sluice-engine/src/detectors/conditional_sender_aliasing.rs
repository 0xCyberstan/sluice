//! L1→L2 sender alias applied **conditionally** behind a code-shape / EOA
//! heuristic, with the aliased result flowing to a stored / emitted sender used
//! for authorization — so two L1 senders that must map to *distinct* L2
//! principals can collide, or a contract presents its un-aliased address.
//!
//! ## The shape
//!
//! An L1→L2 deposit / cross-domain entry transforms the from-address to its L2
//! alias — `applyL1ToL2Alias(x)` / `undoL1ToL2Alias(x)` (the canonical
//! Arbitrum/Optimism `address(uint160(x) ± 0x11110000…00001111)` offset) — but
//! does so **only inside a branch** whose predicate is an *EOA / code-shape
//! heuristic* rather than the address itself:
//!
//! ```solidity
//! // OptimismPortal2.depositTransaction
//! address from = msg.sender;
//! if (!EOA.isSenderEOA()) {                          // (P) code-shape predicate
//!     from = AddressAliasHelper.applyL1ToL2Alias(msg.sender);   // (A) alias op
//! }
//! ...
//! emit TransactionDeposited(from, _to, DEPOSIT_VERSION, opaqueData);   // (F) emitted sender
//! ```
//!
//! `EOA.isSenderEOA()` returns true for `msg.sender == tx.origin` **and** for an
//! EIP-7702 delegated EOA — an account that carries a `0xEF0100…`-prefixed,
//! 23-byte delegation designator (`EOA.sol`). The L1→L2 alias exists precisely so
//! that a *contract* at address `A` on L1 does not impersonate the *EOA* at the
//! same address `A` on L2 (their `msg.sender` would otherwise be identical). The
//! safety of that separation reduces to "is the from-address aliased iff it is a
//! contract?". Gating the alias on a code-shape heuristic re-opens the gap at the
//! boundary: an account the heuristic classifies as an EOA (e.g. a 7702-delegated
//! account, or any account whose code shape the predicate mis-judges) is **left
//! un-aliased**, so on L2 it presents the *same* principal the un-aliased path
//! produces — colliding with, or impersonating, the address the alias was meant
//! to keep distinct. The emitted / stored `from` is then consumed as the
//! authorized sender of the deposit.
//!
//! ## Precision anchors (all required)
//!
//!   * **(A) an alias operation** — a call named `applyL1ToL2Alias` /
//!     `undoL1ToL2Alias`, or the magic-offset arithmetic
//!     `<uint160-cast> ± 0x1111000000000000000000000000000000001111` (the offset
//!     given inline as the hex literal, or as a constant named `offset`);
//!   * **(P) a conditional wrapper** — that alias op sits inside the `then`/`else`
//!     branch of an `if`, or an arm of a ternary, whose **predicate is a
//!     code-shape / EOA heuristic**: `msg.sender == tx.origin`, a `.code.length`
//!     read, or a call to an `isSenderEOA` / `isEOA` / `isContract`-style helper;
//!   * **(F) a sender flow** — the aliased value is assigned to / initializes a
//!     **sender-like local** (`from`, `sender`, `aliased`, `caller`, …), the lever
//!     the deposit's authorization / event uses.
//!
//! ## Suppression
//!
//!   * **Unconditional aliasing is correct and stays silent.** An alias op that is
//!     *not* guarded by an EOA / code-shape predicate — `undoL1ToL2Alias(msg.sender)
//!     == otherMessenger` (`L2CrossDomainMessenger`), `owner() ==
//!     undoL1ToL2Alias(msg.sender)` (`CrossDomainOwnable`), or the
//!     `AddressAliasHelper` library bodies themselves — never fires.
//!   * Libraries / interfaces are skipped (the helper that *defines* the alias
//!     arithmetic is not a consumer).
//!   * A conditional whose predicate is an ordinary value check (not a code-shape /
//!     EOA heuristic) does not fire, even if it guards an alias op.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, CallKind, Expr, ExprKind, Function, Span, Stmt, StmtKind};

use super::prelude::*;

pub struct ConditionalSenderAliasingDetector;

impl Detector for ConditionalSenderAliasingDetector {
    fn id(&self) -> &'static str {
        "conditional-sender-aliasing"
    }
    fn category(&self) -> Category {
        Category::ConditionalSenderAliasing
    }
    fn description(&self) -> &'static str {
        "L1->L2 sender alias (applyL1ToL2Alias / undoL1ToL2Alias / the 0x1111..1111 offset) applied \
         CONDITIONALLY behind a code-shape / EOA heuristic (msg.sender == tx.origin, .code.length, an \
         isSenderEOA-style check that also accepts EIP-7702 delegated EOAs), with the aliased result flowing \
         to a stored/emitted sender used for authorization (OptimismPortal2.depositTransaction class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // The library that *defines* the alias arithmetic (AddressAliasHelper)
            // and interface stubs are not consumers — the unconditional alias body
            // is correct. Skip them.
            if let Some(c) = cx.contract_of(f.id) {
                if c.is_interface() || c.is_library() {
                    continue;
                }
            }
            if let Some(hit) = analyze(f) {
                out.push(self.finding(cx, f, &hit));
            }
        }
        out
    }
}

impl ConditionalSenderAliasingDetector {
    fn finding(&self, cx: &AnalysisContext, f: &Function, hit: &Hit) -> Finding {
        let b = report!(self, Category::ConditionalSenderAliasing,
            title = "L1->L2 sender alias applied conditionally behind a code-shape/EOA heuristic",
            severity = Severity::Medium,
            confidence = 0.62,
            dimensions = [Dimension::Frontier],
            message = format!(
                "`{fname}` applies an L1->L2 sender alias ({alias}) **only inside a branch** guarded by a \
                 code-shape / EOA heuristic ({pred}), then routes the result into the sender-like value \
                 `{sink}`. The L1->L2 alias (`address(uint160(x) + 0x1111…1111)`) exists so that a *contract* \
                 at address A on L1 cannot present the same `msg.sender` as the *EOA* at address A on L2 — \
                 they must map to distinct L2 principals. Gating the alias on a code-shape predicate re-opens \
                 that gap: a `msg.sender == tx.origin` / `.code.length` / `isSenderEOA`-style test classifies \
                 an EIP-7702 delegated EOA (a 23-byte `0xEF0100…`-prefixed account) — or any account whose \
                 code shape the heuristic mis-judges — as an EOA and leaves it **un-aliased**, so on L2 it \
                 collides with / impersonates the address the alias was meant to keep separate. Because the \
                 un-aliased `{sink}` is the sender consumed for the deposit's authorization / event, two \
                 senders that should map to different L2 identities can act as one.",
                fname = f.name,
                alias = hit.alias_desc,
                pred = hit.predicate_desc,
                sink = hit.sink_desc,
            ),
            recommendation =
                "Apply the L1->L2 alias UNCONDITIONALLY based on whether the caller is a contract as observed \
                 by the L2 system, not on a code-shape / EOA heuristic that an EIP-7702 delegated EOA (or a \
                 mis-classified account) can satisfy. If a contract must be aliased exactly when an EOA is \
                 not, ensure the branch predicate cannot return the EOA verdict for any account that the L2 \
                 will see as a contract (or alias every non-`tx.origin` sender), so that no two distinct L1 \
                 senders collide onto one L2 principal. Do not derive the stored/emitted authorization sender \
                 from a conditionally-aliased value.",
        );
        finish_at(cx, b, f.id, hit.span)
    }
}

// --------------------------------------------------------------------- analysis

/// A matched conditional-sender-aliasing site.
struct Hit {
    /// Description of the alias operation (`applyL1ToL2Alias(...)` / `+ 0x1111…1111`).
    alias_desc: String,
    /// Description of the guarding code-shape predicate.
    predicate_desc: String,
    /// Description of the sender-like sink the aliased value flows to.
    sink_desc: String,
    /// Report location (the alias operation).
    span: Span,
}

fn analyze(f: &Function) -> Option<Hit> {
    // (1) `if` form: scan every `if` whose predicate is a code-shape/EOA heuristic
    //     and whose then/else branch contains an alias op assigned to a sender-like
    //     local.
    let mut hit: Option<Hit> = None;
    for top in &f.body {
        top.visit(&mut |st| {
            if hit.is_some() {
                return;
            }
            if let StmtKind::If { cond, then_branch, else_branch } = &st.kind {
                let Some(predicate_desc) = code_shape_predicate(cond) else { return };
                // The guarded region is the then ∪ else branches.
                for branch in [then_branch.as_slice(), else_branch.as_slice()] {
                    if let Some((alias_desc, sink_desc, span)) = alias_assign_in_branch(branch) {
                        hit = Some(Hit { alias_desc, predicate_desc: predicate_desc.clone(), sink_desc, span });
                        return;
                    }
                }
            }
        });
        if hit.is_some() {
            break;
        }
    }
    if hit.is_some() {
        return hit;
    }

    // (2) Ternary form: `address from = <code-shape-pred> ? a : alias(b);`. The
    //     ternary's arm holds the alias op; the enclosing VarDecl / Assign names the
    //     sender-like sink.
    for top in &f.body {
        top.visit(&mut |st| {
            if hit.is_some() {
                return;
            }
            // The sender-like sink for a ternary init/assign.
            let sink = ternary_sink_name(st);
            st.visit_exprs(&mut |e| {
                if hit.is_some() {
                    return;
                }
                if let ExprKind::Ternary { cond, then_e, else_e } = &e.kind {
                    let Some(predicate_desc) = code_shape_predicate(cond) else { return };
                    for arm in [then_e.as_ref(), else_e.as_ref()] {
                        if let Some((alias_desc, span)) = alias_op_in_expr(arm) {
                            // Require a sender-like sink for the ternary (precision).
                            let Some(sink_desc) = sink.clone() else { continue };
                            hit = Some(Hit { alias_desc, predicate_desc: predicate_desc.clone(), sink_desc, span });
                            return;
                        }
                    }
                }
            });
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

// ----------------------------------------------- (P) code-shape / EOA predicate

/// Does `cond` (anywhere within) read as a **code-shape / EOA heuristic**? Three
/// recognized forms:
///   * `msg.sender == tx.origin` (or `!=`, either operand order) — the classic
///     "is the caller an EOA" test;
///   * a `.code.length` read — `x.code.length` (an `extcodesize`-style shape used
///     to distinguish contracts from EOAs);
///   * a call to an EOA / contract predicate (`isSenderEOA`, `isEOA`, `isContract`,
///     `isAccountEOA`, …).
/// Returns a short human description of the matched predicate.
fn code_shape_predicate(cond: &Expr) -> Option<String> {
    let mut desc: Option<String> = None;
    cond.visit(&mut |e| {
        if desc.is_some() {
            return;
        }
        // (a) msg.sender == tx.origin
        if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
            if matches!(op, BinOp::Eq | BinOp::Ne) {
                let (a, b) = (lhs.as_ref(), rhs.as_ref());
                if (is_msg_sender(a) && is_tx_origin(b)) || (is_tx_origin(a) && is_msg_sender(b)) {
                    desc = Some("msg.sender == tx.origin".to_string());
                    return;
                }
            }
        }
        // (b) `.code.length`
        if is_code_length(e) {
            desc = Some(".code.length".to_string());
            return;
        }
        // (c) an EOA / contract predicate call.
        if let ExprKind::Call(c) = &e.kind {
            if let Some(name) = c.func_name.as_deref() {
                if is_eoa_predicate_name(name) {
                    desc = Some(format!("{name}()"));
                }
            }
        }
    });
    desc
}

/// `msg.sender`.
fn is_msg_sender(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Member { base, member }
        if member == "sender" && matches!(&base.kind, ExprKind::Ident(n) if n == "msg"))
}

/// `tx.origin`.
fn is_tx_origin(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Member { base, member }
        if member == "origin" && matches!(&base.kind, ExprKind::Ident(n) if n == "tx"))
}

/// `<x>.code.length` — a `.length` member whose base is a `.code` member.
fn is_code_length(e: &Expr) -> bool {
    if let ExprKind::Member { base, member } = &e.kind {
        if member == "length" {
            if let ExprKind::Member { member: inner, .. } = &base.kind {
                return inner == "code";
            }
        }
    }
    false
}

/// A function name that reads as an EOA / contract-shape predicate. Matched on the
/// resolved method name (`EOA.isSenderEOA()` resolves to `isSenderEOA`).
fn is_eoa_predicate_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // `isSenderEOA`, `isEOA`, `isEoa`, `isAccountEOA`, `isContract`, `isNotContract`.
    (l.starts_with("is") || l.contains("iseoa"))
        && (l.ends_with("eoa") || l.contains("eoa") || l.contains("contract"))
}

// ------------------------------------------------- (A)+(F) alias op in a branch

/// In an `if`-branch statement list, find an alias op whose result is assigned to
/// (or declares) a **sender-like** local. Returns (alias description, sink
/// description, alias-op span).
fn alias_assign_in_branch(branch: &[Stmt]) -> Option<(String, String, Span)> {
    let mut found: Option<(String, String, Span)> = None;
    for st in branch {
        st.visit(&mut |s| {
            if found.is_some() {
                return;
            }
            match &s.kind {
                // `from = applyL1ToL2Alias(msg.sender);`
                StmtKind::Expr(e) => {
                    if let ExprKind::Assign { target, value, .. } = &e.kind {
                        if let Some(sink) = sender_like_lvalue(target) {
                            if let Some((alias_desc, span)) = alias_op_in_expr(value) {
                                found = Some((alias_desc, sink, span));
                            }
                        }
                    }
                }
                // `address from = applyL1ToL2Alias(msg.sender);` (declared in-branch)
                StmtKind::VarDecl { name: Some(n), init: Some(init), .. } => {
                    if is_sender_like_name(n) {
                        if let Some((alias_desc, span)) = alias_op_in_expr(init) {
                            found = Some((alias_desc, format!("`{n}`"), span));
                        }
                    }
                }
                _ => {}
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// If `st` is a VarDecl / Assign that targets a sender-like local, return its
/// display name — the sink a ternary's aliased arm flows into.
fn ternary_sink_name(st: &Stmt) -> Option<String> {
    match &st.kind {
        StmtKind::VarDecl { name: Some(n), .. } if is_sender_like_name(n) => Some(format!("`{n}`")),
        StmtKind::Expr(e) => {
            if let ExprKind::Assign { target, .. } = &e.kind {
                return sender_like_lvalue(target);
            }
            None
        }
        _ => None,
    }
}

/// If `lv` is a sender-like lvalue (a bare ident, or `x.field`/`x[k]` whose leaf or
/// root is sender-like), return its display name.
fn sender_like_lvalue(lv: &Expr) -> Option<String> {
    match &lv.kind {
        ExprKind::Ident(n) if is_sender_like_name(n) => Some(format!("`{n}`")),
        ExprKind::Member { member, .. } if is_sender_like_name(member) => Some(format!("`{member}`")),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => sender_like_lvalue(base),
        _ => None,
    }
}

/// A variable / field name that names a transaction sender / from-address — the
/// value an L1->L2 alias produces and the deposit authorizes against.
fn is_sender_like_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    const SENDERY: &[&str] = &[
        "from", "sender", "aliased", "alias", "caller", "account", "origin", "l2sender", "l1sender",
        "msgsender", "fromaddress", "depositor", "submitter",
    ];
    SENDERY.iter().any(|k| l == *k || l.ends_with(k) || l.starts_with(k))
}

/// If `e` contains an **alias operation**, return (description, span). Two forms:
///   * a call named `applyL1ToL2Alias` / `undoL1ToL2Alias`;
///   * the magic-offset arithmetic `<uint160 cast> ± 0x1111…1111` (offset inline or
///     a named `offset` constant), wrapped/cast to an address-width value.
fn alias_op_in_expr(e: &Expr) -> Option<(String, Span)> {
    let mut found: Option<(String, Span)> = None;
    e.visit(&mut |x| {
        if found.is_some() {
            return;
        }
        // (a) named alias helper call.
        if let ExprKind::Call(c) = &x.kind {
            if let Some(name) = c.func_name.as_deref() {
                if is_alias_call_name(name) {
                    found = Some((format!("{name}(...)"), x.span));
                    return;
                }
            }
        }
        // (b) magic-offset arithmetic: an Add/Sub where one operand is the L1->L2
        //     offset and the other is a uint160-width address operand.
        if let ExprKind::Binary { op: BinOp::Add | BinOp::Sub, lhs, rhs } = &x.kind {
            let one_is_offset = is_alias_offset(lhs) || is_alias_offset(rhs);
            let one_is_addr_width = is_uint160_castish(lhs) || is_uint160_castish(rhs);
            if one_is_offset && one_is_addr_width {
                found = Some(("the 0x1111…1111 L1->L2 alias offset".to_string(), x.span));
            }
        }
    });
    found
}

/// `applyL1ToL2Alias` / `undoL1ToL2Alias` (any casing).
fn is_alias_call_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "applyl1tol2alias" || l == "undol1tol2alias"
}

/// Is `e` the canonical L1->L2 alias offset — the hex literal
/// `0x1111000000000000000000000000000000001111`, or a constant named `offset` /
/// `*aliasoffset*` (the `AddressAliasHelper.offset` idiom)?
fn is_alias_offset(e: &Expr) -> bool {
    match &peel_casts(e).kind {
        // The exact magic constant, given inline (hex or decimal spelling).
        ExprKind::Lit(sluice_ir::Lit::HexNumber(h)) => is_magic_offset_hex(h),
        ExprKind::Lit(sluice_ir::Lit::Number(n)) => is_magic_offset_dec(n),
        // A constant named `offset` / `l1l2offset` / `aliasOffset`.
        ExprKind::Ident(n) => {
            let l = n.to_ascii_lowercase();
            l == "offset" || l.ends_with("offset") && (l.contains("alias") || l.contains("l1") || l.contains("l2"))
        }
        ExprKind::Member { member, .. } => {
            let l = member.to_ascii_lowercase();
            l == "offset" || (l.ends_with("offset") && (l.contains("alias") || l.contains("l1") || l.contains("l2")))
        }
        _ => false,
    }
}

/// Exact `0x1111000000000000000000000000000000001111`, tolerant of `_` separators,
/// leading zeros, and casing.
fn is_magic_offset_hex(h: &str) -> bool {
    let s = h.trim().trim_start_matches("0x").trim_start_matches("0X").replace('_', "");
    let s = s.trim_start_matches('0');
    let canon = "1111000000000000000000000000000000001111";
    s.eq_ignore_ascii_case(canon)
}

/// The same offset expressed in decimal: 0x1111…1111 = 97174558018597328401582302087230435515428141585.
fn is_magic_offset_dec(n: &str) -> bool {
    let s = n.trim().replace('_', "");
    s == "97174558018597328401582302087230435515428141585"
}

/// Does `e` (after peeling casts) read as a `uint160(...)`-width cast of an address,
/// or an address-typed operand — the left/right side of the alias offset add? We
/// accept a `uint160(...)` / `uint(...)` cast call, or a bare sender-ish operand.
fn is_uint160_castish(e: &Expr) -> bool {
    // A `uint160(x)` (or other uint cast) call.
    if let ExprKind::Call(c) = &e.kind {
        if c.kind == CallKind::TypeCast {
            if let ExprKind::TypeName(t) = &c.callee.kind {
                let l = t.to_ascii_lowercase();
                if l.starts_with("uint") || l == "address" {
                    return true;
                }
            }
        }
    }
    // A bare address-ish operand (msg.sender / a *address* local) — defensive: the
    // offset arithmetic is `addrWidth ± offset`, so the non-offset side is the addr.
    is_msg_sender(e) || matches!(&e.kind, ExprKind::Ident(_) | ExprKind::Member { .. })
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "conditional-sender-aliasing")
    }

    // VULN — the real OptimismPortal2.depositTransaction shape: `from = msg.sender`,
    // then `if (!EOA.isSenderEOA()) from = applyL1ToL2Alias(msg.sender);`, and the
    // un-/aliased `from` is emitted as the deposit sender.
    const VULN_PORTAL: &str = r#"
        pragma solidity 0.8.15;
        library EOA { function isSenderEOA() internal view returns (bool) { return true; } }
        library AddressAliasHelper {
            function applyL1ToL2Alias(address a) internal pure returns (address) { return a; }
        }
        contract OptimismPortal2 {
            event TransactionDeposited(address indexed from, address indexed to, uint256 version, bytes opaqueData);
            function depositTransaction(address _to, uint256 _value, bytes memory _data) public payable {
                address from = msg.sender;
                if (!EOA.isSenderEOA()) {
                    from = AddressAliasHelper.applyL1ToL2Alias(msg.sender);
                }
                bytes memory opaqueData = abi.encodePacked(_value, _data);
                emit TransactionDeposited(from, _to, 0, opaqueData);
            }
        }
    "#;

    // VULN — `msg.sender == tx.origin` gating the magic-offset arithmetic, ternary
    // form. EOA-classified (== tx.origin) is left un-aliased.
    const VULN_TXORIGIN_TERNARY: &str = r#"
        pragma solidity 0.8.15;
        contract Inbox {
            event Dep(address from);
            function deposit() external {
                address from = (msg.sender == tx.origin)
                    ? msg.sender
                    : address(uint160(msg.sender) + 0x1111000000000000000000000000000000001111);
                emit Dep(from);
            }
        }
    "#;

    // VULN — `.code.length` gating an `applyL1ToL2Alias` reassignment, if/else form.
    const VULN_CODELEN_IF: &str = r#"
        pragma solidity 0.8.15;
        library AddressAliasHelper {
            function applyL1ToL2Alias(address a) internal pure returns (address) { return a; }
        }
        contract Bridge {
            mapping(address => uint256) public credited;
            function depositETH() external payable {
                address sender;
                if (msg.sender.code.length == 0) {
                    sender = msg.sender;
                } else {
                    sender = AddressAliasHelper.applyL1ToL2Alias(msg.sender);
                }
                credited[sender] += msg.value;
            }
        }
    "#;

    // VULN — magic-offset arithmetic with the named `offset` constant, gated by an
    // `isSenderEOA()`-style call inside an `if`.
    const VULN_OFFSET_CONST: &str = r#"
        pragma solidity 0.8.15;
        contract Portal {
            uint160 constant offset = uint160(0x1111000000000000000000000000000000001111);
            event Dep(address from);
            function isSenderEOA() internal view returns (bool) { return msg.sender == tx.origin; }
            function deposit() external {
                address from = msg.sender;
                if (!isSenderEOA()) {
                    from = address(uint160(msg.sender) + offset);
                }
                emit Dep(from);
            }
        }
    "#;

    // SAFE (unconditional alias) — `undoL1ToL2Alias(msg.sender) == otherMessenger`
    // is the L2CrossDomainMessenger shape: the alias is applied UNCONDITIONALLY
    // (inside a `return` comparison), with no EOA/code-shape predicate guarding it.
    // Correct — must stay silent.
    const SAFE_UNCOND_MESSENGER: &str = r#"
        pragma solidity 0.8.15;
        library AddressAliasHelper {
            function undoL1ToL2Alias(address a) internal pure returns (address) { return a; }
        }
        contract L2CrossDomainMessenger {
            address public otherMessenger;
            function _isOtherMessenger() internal view returns (bool) {
                return AddressAliasHelper.undoL1ToL2Alias(msg.sender) == address(otherMessenger);
            }
        }
    "#;

    // SAFE (unconditional alias) — CrossDomainOwnable._checkOwner: `owner() ==
    // undoL1ToL2Alias(msg.sender)` inside a require. Unconditional → silent.
    const SAFE_UNCOND_OWNABLE: &str = r#"
        pragma solidity 0.8.15;
        library AddressAliasHelper {
            function undoL1ToL2Alias(address a) internal pure returns (address) { return a; }
        }
        contract CrossDomainOwnable {
            address private _owner;
            function owner() public view returns (address) { return _owner; }
            function _checkOwner() internal view {
                require(owner() == AddressAliasHelper.undoL1ToL2Alias(msg.sender), "not owner");
            }
        }
    "#;

    // SAFE (the AddressAliasHelper library itself) — the alias arithmetic lives in a
    // LIBRARY, unconditionally. The detector skips libraries, and there is no
    // code-shape predicate anyway. Silent.
    const SAFE_HELPER_LIB: &str = r#"
        pragma solidity 0.8.15;
        library AddressAliasHelper {
            uint160 constant offset = uint160(0x1111000000000000000000000000000000001111);
            function applyL1ToL2Alias(address l1Address) internal pure returns (address l2Address) {
                unchecked { l2Address = address(uint160(l1Address) + offset); }
            }
            function undoL1ToL2Alias(address l2Address) internal pure returns (address l1Address) {
                unchecked { l1Address = address(uint160(l2Address) - offset); }
            }
        }
    "#;

    // SAFE (conditional, but NOT an EOA/code-shape predicate) — the alias is gated
    // on an ordinary value check (`_to != address(0)`), not on a code-shape
    // heuristic. Outside the class → silent.
    const SAFE_NON_CODESHAPE_PRED: &str = r#"
        pragma solidity 0.8.15;
        library AddressAliasHelper {
            function applyL1ToL2Alias(address a) internal pure returns (address) { return a; }
        }
        contract Portal {
            event Dep(address from);
            function deposit(address _to) external {
                address from = msg.sender;
                if (_to != address(0)) {
                    from = AddressAliasHelper.applyL1ToL2Alias(msg.sender);
                }
                emit Dep(from);
            }
        }
    "#;

    // SAFE (EOA predicate but no alias op in the branch) — the branch guarded by the
    // code-shape predicate does something else (a require), no alias is applied.
    // Silent — this is the ERC721Bridge/StandardBridge `require(EOA.isSenderEOA())`
    // shape (EOA-gate without aliasing).
    const SAFE_EOA_GATE_NO_ALIAS: &str = r#"
        pragma solidity 0.8.15;
        library EOA { function isSenderEOA() internal view returns (bool) { return true; } }
        contract StandardBridge {
            function bridgeETH() external payable {
                require(EOA.isSenderEOA(), "not EOA");
            }
        }
    "#;

    #[test]
    fn fires_on_optimism_portal_deposit() {
        let fs = run(VULN_PORTAL);
        assert!(
            fs.iter().any(|f| f.detector == "conditional-sender-aliasing"
                && f.function == "depositTransaction"),
            "expected conditional-sender-aliasing on depositTransaction; got {:#?}",
            fs
        );
    }

    #[test]
    fn fires_on_txorigin_ternary() {
        assert!(fires(VULN_TXORIGIN_TERNARY), "{:#?}", run(VULN_TXORIGIN_TERNARY));
    }

    #[test]
    fn fires_on_codelen_if() {
        assert!(fires(VULN_CODELEN_IF), "{:#?}", run(VULN_CODELEN_IF));
    }

    #[test]
    fn fires_on_named_offset_const() {
        assert!(fires(VULN_OFFSET_CONST), "{:#?}", run(VULN_OFFSET_CONST));
    }

    #[test]
    fn silent_on_unconditional_messenger() {
        assert!(!fires(SAFE_UNCOND_MESSENGER), "{:#?}", run(SAFE_UNCOND_MESSENGER));
    }

    #[test]
    fn silent_on_unconditional_ownable() {
        assert!(!fires(SAFE_UNCOND_OWNABLE), "{:#?}", run(SAFE_UNCOND_OWNABLE));
    }

    #[test]
    fn silent_on_helper_library() {
        assert!(!fires(SAFE_HELPER_LIB), "{:#?}", run(SAFE_HELPER_LIB));
    }

    #[test]
    fn silent_on_non_codeshape_predicate() {
        assert!(!fires(SAFE_NON_CODESHAPE_PRED), "{:#?}", run(SAFE_NON_CODESHAPE_PRED));
    }

    #[test]
    fn silent_on_eoa_gate_without_alias() {
        assert!(!fires(SAFE_EOA_GATE_NO_ALIAS), "{:#?}", run(SAFE_EOA_GATE_NO_ALIAS));
    }
}
