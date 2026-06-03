//! Custodial contract that receives ERC-1155 tokens but cannot safely hold them
//! (missing `onERC1155Received` / `onERC1155BatchReceived`) — the locked-token
//! class, the multi-token analog of `erc721_safety.rs`.
//!
//! Unlike ERC-721, the ERC-1155 standard has **no** unsafe transfer primitive:
//! the only ways to move a token are
//!
//!   * `safeTransferFrom(from, to, id, amount, data)`, and
//!   * `safeBatchTransferFrom(from, to, ids, amounts, data)`,
//!
//! and *both* require that, when `to` is a contract, `to` implements the
//! `IERC1155Receiver` hook — `onERC1155Received` for the single transfer and
//! `onERC1155BatchReceived` for the batch — and returns the matching magic
//! selector; otherwise the transfer **reverts**.
//!
//! A contract that is *meant to custody* ERC-1155 tokens — a staking pool,
//! escrow, vault, or marketplace that pulls a token into **itself**
//! (`token.safeTransferFrom(from, address(this), id, amount, data)` /
//! `token.safeBatchTransferFrom(from, address(this), ids, amounts, data)`) — but
//! that does not implement the receiver hook is simply broken: every deposit
//! reverts, so no token can ever be pulled in, and any token that arrives by a
//! third-party `safeTransferFrom` likewise reverts. There is no "unsafe" escape
//! hatch as there is for ERC-721, so the impact is unconditional.
//!
//! The OpenZeppelin remedy is to inherit `ERC1155Holder` (which implements both
//! hooks to accept everything) or to implement `IERC1155Receiver` explicitly.
//!
//! Heuristic (precision first — this is a modest-confidence structural smell):
//!   * The contract has a function that pulls an ERC-1155 **into itself**: a
//!     `safeTransferFrom`/`safeBatchTransferFrom` whose recipient argument is
//!     `address(this)`, on a handle that is 1155-typed (type mentions `1155`) or
//!     in a contract that plainly deals in ERC-1155. The recipient is keyed on
//!     the ERC-1155 position (`from, to, ...` → `to == args[1]`).
//!   * The ERC-1155 `safeTransferFrom(from, to, id, amount, data)` shares the
//!     `to == args[1]` position with ERC-721's three-arg form, while the four-arg
//!     SafeERC20 library form `safeTransferFrom(token, from, to, amount)` puts
//!     `to` at args[2] and so never matches here. The 1155-ness gate further
//!     separates ERC-1155 custody from ERC-721 custody (handled by its own
//!     detector). `safeBatchTransferFrom` is unique to ERC-1155 and is matched
//!     unconditionally on the recipient position.
//!   * Suppressed when the contract can safely receive: it defines
//!     `onERC1155Received` / `onERC1155BatchReceived`, or inherits
//!     `ERC1155Holder` / `IERC1155Receiver` / `ERC1155TokenReceiver`, or never
//!     custodies a 1155 (only sends them out).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Contract, Expr, ExprKind, Function, Span};

pub struct Erc1155ReceiverDetector;

impl Detector for Erc1155ReceiverDetector {
    fn id(&self) -> &'static str {
        "unchecked-erc1155-receiver"
    }
    fn category(&self) -> Category {
        Category::Erc1155Safety
    }
    fn description(&self) -> &'static str {
        "Contract custodies ERC-1155 tokens (pulls them into itself) but does not implement onERC1155Received/onERC1155BatchReceived (locked-token risk)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for c in cx.scir.iter_contracts() {
            // Only a concrete/abstract contract can custody a token. Interfaces
            // have no bodies; libraries have no `address(this)` instance to hold
            // tokens.
            if c.is_interface() || c.is_library() {
                continue;
            }

            // FP suppression: the contract can already safely receive ERC-1155s.
            if defines_receiver_hook(cx, c) || inherits_receiver(c) {
                continue;
            }

            // Find the first pull-in of a 1155 *into this contract*. If none, the
            // contract does not custody 1155 tokens (it only sends them out, or
            // never touches them) and is out of scope.
            let Some(hit) = find_token_pull_in(cx, c) else {
                continue;
            };

            // Both `safeTransferFrom` and `safeBatchTransferFrom` into a
            // non-receiver contract are a guaranteed revert: ERC-1155 has no
            // unsafe transfer, so the deposit path simply cannot succeed. The
            // batch form additionally implies the contract intends to custody
            // multiple ids at once. We treat the unconditional-revert case as
            // Medium, matching the broken-deposit severity in the ERC-721 dual.
            let how = if hit.is_batch {
                "`safeBatchTransferFrom(..., address(this), ...)` — which reverts unless `to` implements \
                 `onERC1155BatchReceived`, so this transfer cannot succeed and the deposit path is broken"
            } else {
                "`safeTransferFrom(..., address(this), ...)` — which reverts unless `to` implements \
                 `onERC1155Received`, so this transfer cannot succeed and the deposit path is broken"
            };

            let (cname, fname) = cx.names(hit.function);
            let b = FindingBuilder::new(self.id(), Category::Erc1155Safety)
                .title("Contract custodies ERC-1155 tokens without implementing onERC1155Received")
                .severity(Severity::Medium)
                // Honest: a structural smell. We cannot prove the contract is a
                // genuine custodian (vs. a router that immediately forwards), and
                // a deployed token could in principle skip the receiver check —
                // hence a modest, single-dimension confidence.
                .confidence(0.45)
                // Invariant: a custodial contract that cannot receive its own
                // custodied asset violates the implicit "I can hold what I pull
                // in" invariant of an ERC-1155 holder.
                .dimension(Dimension::Invariant)
                .message(format!(
                    "`{cname}.{fname}` pulls an ERC-1155 token into the contract via {how}. `{cname}` does \
                     not implement `onERC1155Received` / `onERC1155BatchReceived` and does not inherit \
                     `ERC1155Holder` / `IERC1155Receiver`, so it cannot safely act as the token's custodian. \
                     ERC-1155 has no unsafe transfer primitive, so every deposit into this contract reverts \
                     and the tokens it is meant to hold can never arrive.",
                ))
                .recommendation(
                    "Implement `IERC1155Receiver.onERC1155Received` and `onERC1155BatchReceived` (returning \
                     their magic selectors) or inherit OpenZeppelin `ERC1155Holder` so the contract can \
                     accept and account for ERC-1155 tokens; expose a path to transfer custodied tokens back \
                     out.",
                );
            out.push(cx.finish(b, hit.function, hit.span));
        }

        out
    }
}

// ------------------------------------------------------------------- helpers

/// A located ERC-1155 pull-in: the function it occurs in, the call span, and
/// whether it used the batch variant.
struct PullIn {
    function: sluice_ir::FunctionId,
    span: Span,
    is_batch: bool,
}

/// The contract defines `onERC1155Received` or `onERC1155BatchReceived` (it
/// implements the receiver hook directly, so it can safely hold ERC-1155 tokens).
fn defines_receiver_hook(cx: &AnalysisContext, c: &Contract) -> bool {
    cx.scir.functions_of(c.id).any(|f| {
        f.name.eq_ignore_ascii_case("onERC1155Received")
            || f.name.eq_ignore_ascii_case("onERC1155BatchReceived")
    })
}

/// The contract inherits a standard ERC-1155-receiver mixin (`ERC1155Holder`,
/// `IERC1155Receiver`, `ERC1155TokenReceiver`, `ERC1155Receiver`). Any of these
/// makes the contract a valid ERC-1155 recipient.
fn inherits_receiver(c: &Contract) -> bool {
    ["erc1155holder", "ierc1155receiver", "erc1155tokenreceiver", "erc1155receiver"]
        .iter()
        .any(|needle| c.inherits_like(needle))
}

/// Find the first call in any of the contract's functions that pulls an
/// ERC-1155 **into the contract itself** (recipient `address(this)`).
fn find_token_pull_in(cx: &AnalysisContext, c: &Contract) -> Option<PullIn> {
    // Whether the *contract* plainly deals in ERC-1155 (used as corroboration
    // when the token handle's type isn't locally resolvable to a 1155 type).
    // Matched on the comment-stripped contract source so an `IERC1155`/`ERC1155`
    // mention counts, while a plainly-ERC20/ERC721 contract (no such mention) is
    // not pulled in via this path.
    let contract_is_1155 = source_is_1155(&cx.source_text(c.span));

    let mut found: Option<PullIn> = None;
    for f in cx.scir.functions_of(c.id) {
        if !f.has_body {
            continue;
        }
        for s in &f.body {
            s.visit_exprs(&mut |e| {
                if found.is_some() {
                    return;
                }
                let ExprKind::Call(call) = &e.kind else { return };
                let is_batch = match call.func_name.as_deref() {
                    Some("safeTransferFrom") => false,
                    Some("safeBatchTransferFrom") => true,
                    _ => return,
                };
                // ERC-1155 recipient position: both `safeTransferFrom(from, to,
                // id, amount, data)` and `safeBatchTransferFrom(from, to, ids,
                // amounts, data)` put `to` at args[1]. The SafeERC20 library form
                // `safeTransferFrom(token, from, to, amount)` puts `to` at
                // args[2], so it will not match here — which keeps this detector
                // off ERC-20 code.
                let Some(to_arg) = call.args.get(1) else { return };
                if !arg_is_address_this(to_arg) {
                    return;
                }
                // 1155-ness gate (precision): the moved asset must look like an
                // ERC-1155, not an ERC-20 or ERC-721. Strongest signal is a
                // 1155-typed handle (the receiver root resolves to a state var /
                // param whose type mentions `1155`). Otherwise accept the call in
                // a contract that plainly deals in ERC-1155. `safeBatchTransferFrom`
                // is unique to ERC-1155, but we still require a 1155 signal so an
                // unrelated identically-named method cannot trip the detector.
                let handle_is_1155 = call
                    .receiver
                    .as_deref()
                    .and_then(|r| handle_type(c, f, r))
                    .map(|ty| type_is_1155(&ty))
                    .unwrap_or(false);
                if !handle_is_1155 && !contract_is_1155 {
                    return;
                }
                found = Some(PullIn { function: f.id, span: e.span, is_batch });
            });
            if found.is_some() {
                break;
            }
        }
        if found.is_some() {
            break;
        }
    }
    found
}

/// Peel single-argument type casts (`address(x)`, `payable(x)`, `IERC1155(x)`).
fn unwrap_casts(e: &Expr) -> &Expr {
    let mut cur = e;
    loop {
        match &cur.kind {
            ExprKind::Call(c) if c.kind == sluice_ir::CallKind::TypeCast && c.args.len() == 1 => {
                cur = &c.args[0];
            }
            _ => return cur,
        }
    }
}

/// `address(this)` — after stripping the cast it is the bare `this` identifier.
fn arg_is_address_this(e: &Expr) -> bool {
    matches!(&unwrap_casts(e).kind, ExprKind::Ident(n) if n == "this")
}

/// Root identifier of a member/index/cast chain (`IERC1155(t).x` -> `t`, `a.b` -> `a`).
fn root_ident(e: &Expr) -> Option<String> {
    match &unwrap_casts(e).kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root_ident(base),
        _ => None,
    }
}

/// Best-effort textual type of the call receiver (the token handle): if the
/// receiver is a cast `IERC1155(x)` use the cast type; otherwise resolve its root
/// identifier to a function parameter or a contract state variable and use that
/// declared type.
fn handle_type(c: &Contract, f: &Function, recv: &Expr) -> Option<String> {
    // `IERC1155(x).safeTransferFrom(...)` — the cast names the type directly.
    if let ExprKind::Call(call) = &recv.kind {
        if call.kind == sluice_ir::CallKind::TypeCast {
            if let ExprKind::TypeName(t) = &call.callee.kind {
                return Some(t.clone());
            }
        }
    }
    let root = root_ident(recv)?;
    // A function parameter typed as the token handle.
    if let Some(p) = f.params.iter().find(|p| p.name.as_deref() == Some(root.as_str())) {
        return Some(p.ty.clone());
    }
    // A contract state variable holding the token handle.
    if let Some(v) = c.state_vars.iter().find(|v| v.name == root) {
        return Some(v.ty.clone());
    }
    None
}

/// A declared type that denotes an ERC-1155 handle (`IERC1155`, `ERC1155`,
/// `ERC1155Supply`, ...). Matched as a case-insensitive substring on `1155`.
fn type_is_1155(ty: &str) -> bool {
    ty.to_ascii_lowercase().contains("1155")
}

/// The (comment-stripped, lowercased) contract source plainly references
/// ERC-1155 (an `IERC1155`/`ERC1155` mention). Used as corroboration that a
/// `safeTransferFrom`/`safeBatchTransferFrom` into `address(this)` moves a 1155
/// rather than an ERC-20/ERC-721.
fn source_is_1155(src: &str) -> bool {
    src.contains("1155")
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Staking contract that pulls an ERC-1155 into itself via
    // safeTransferFrom(msg.sender, address(this), id, amount, "") but never
    // implements the receiver hook and does not inherit a receiver mixin. The
    // safe deposit reverts unconditionally — the locked-token class.
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC1155 {
            function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external;
            function safeBatchTransferFrom(address from, address to, uint256[] calldata ids, uint256[] calldata amounts, bytes calldata data) external;
        }
        contract TokenStaking {
            IERC1155 public token;
            mapping(uint256 => address) public depositorOf;
            function stake(uint256 id, uint256 amount) external {
                depositorOf[id] = msg.sender;
                token.safeTransferFrom(msg.sender, address(this), id, amount, "");
            }
        }
    "#;

    // Same custodial staking contract, but it implements both receiver hooks (the
    // OpenZeppelin pattern), so it can safely hold ERC-1155 tokens -> must stay
    // silent.
    const SAFE: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC1155 {
            function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external;
            function safeBatchTransferFrom(address from, address to, uint256[] calldata ids, uint256[] calldata amounts, bytes calldata data) external;
        }
        contract TokenStaking {
            IERC1155 public token;
            mapping(uint256 => address) public depositorOf;
            function stake(uint256 id, uint256 amount) external {
                depositorOf[id] = msg.sender;
                token.safeTransferFrom(msg.sender, address(this), id, amount, "");
            }
            function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
                return this.onERC1155Received.selector;
            }
            function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata) external pure returns (bytes4) {
                return this.onERC1155BatchReceived.selector;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "unchecked-erc1155-receiver"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "unchecked-erc1155-receiver"));
    }
}
