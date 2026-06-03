//! Custodial contract that receives ERC-721 tokens but cannot safely hold them
//! (missing `onERC721Received`) — the locked-NFT class.
//!
//! ERC-721 defines two ways to move a token to another address:
//!
//!   * `transferFrom(from, to, tokenId)` — moves the token with **no** check that
//!     `to` is able to handle it. If `to` is a contract that does not track the
//!     incoming token, the NFT is silently stranded at an address that has no code
//!     path to ever move it out again.
//!   * `safeTransferFrom(from, to, tokenId[, data])` — additionally requires that,
//!     when `to` is a contract, `to` implements `IERC721Receiver.onERC721Received`
//!     and returns its magic selector; otherwise the transfer **reverts**.
//!
//! A contract that is *meant to custody* NFTs — a staking pool, escrow, vault, or
//! marketplace that pulls a token into **itself** (`nft.transferFrom(from,
//! address(this), id)` / `nft.safeTransferFrom(..., address(this), ...)`) — but
//! that does not implement `onERC721Received` is broken either way:
//!
//!   * A `safeTransferFrom` *into* it reverts (the user cannot deposit at all, or a
//!     third party can never `safeTransferFrom` an NFT to the contract), and
//!   * if the contract relies on the unsafe `transferFrom`, an NFT that arrives by
//!     any safe path lands in a contract with no receiver hook and is locked.
//!
//! The OpenZeppelin remedy is to inherit `ERC721Holder` (which implements
//! `onERC721Received` to accept everything) or to implement `IERC721Receiver`
//! explicitly.
//!
//! Heuristic (precision first — this is a modest-confidence structural smell):
//!   * The contract has a function that pulls an ERC-721 **into itself**: a
//!     `transferFrom`/`safeTransferFrom` whose recipient argument is
//!     `address(this)`, on a handle that is NFT-typed (type mentions `721`/`nft`)
//!     or in a contract that plainly deals in ERC-721. The recipient is keyed on
//!     the 3-argument ERC-721 position (`from, to, tokenId` → `to == args[1]`), so
//!     the 4-argument SafeERC20 library form `safeTransferFrom(token, from, to,
//!     amount)` (whose `to` is `args[2]`) does **not** match — this keeps the
//!     detector off ordinary ERC-20 code.
//!   * Suppressed when the contract can safely receive: it defines
//!     `onERC721Received`, or inherits `ERC721Holder` / `IERC721Receiver` /
//!     `ERC721TokenReceiver`, or never custodies an NFT (only sends them out).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Contract, Expr, ExprKind, Function, Span};

pub struct Erc721SafetyDetector;

impl Detector for Erc721SafetyDetector {
    fn id(&self) -> &'static str {
        "erc721-safety"
    }
    fn category(&self) -> Category {
        Category::Erc721Safety
    }
    fn description(&self) -> &'static str {
        "Contract custodies ERC-721 tokens (pulls them into itself) but does not implement onERC721Received (locked-NFT risk)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for c in cx.scir.iter_contracts() {
            // Only a concrete/abstract contract can custody an NFT. Interfaces have
            // no bodies; libraries have no `address(this)` instance to hold tokens.
            if c.is_interface() || c.is_library() {
                continue;
            }

            // FP suppression: the contract can already safely receive ERC-721s.
            if defines_on_erc721_received(cx, c) || inherits_receiver(c) {
                continue;
            }

            // Find the first pull-in of an NFT *into this contract*. If none, the
            // contract does not custody NFTs (it only sends them out, or never
            // touches them) and is out of scope.
            let Some(hit) = find_nft_pull_in(cx, c) else {
                continue;
            };

            // `safeTransferFrom` into a non-receiver contract is a guaranteed
            // revert (the deposit path is simply broken / the NFT cannot arrive
            // safely) → Medium. A plain `transferFrom` only *risks* stranding an
            // NFT that arrives without the hook → Low.
            let severity = if hit.is_safe { Severity::Medium } else { Severity::Low };
            let how = if hit.is_safe {
                "`safeTransferFrom(..., address(this), ...)` — which reverts unless `to` implements \
                 `onERC721Received`, so this transfer cannot succeed and the deposit path is broken"
            } else {
                "`transferFrom(from, address(this), tokenId)` — the unsafe variant performs no receiver \
                 check, so any NFT that reaches this contract has no `onERC721Received` hook and can be \
                 permanently stranded"
            };

            let (cname, fname) = cx.names(hit.function);
            let b = FindingBuilder::new(self.id(), Category::Erc721Safety)
                .title("Contract custodies ERC-721 tokens without implementing onERC721Received")
                .severity(severity)
                // Honest: a structural smell. We cannot prove the contract is a
                // genuine custodian (vs. a router that immediately forwards), and
                // the deployed token's `safeTransferFrom` behaviour decides the
                // concrete impact — hence a modest, single-dimension confidence.
                .confidence(0.45)
                // Invariant: a custodial contract that cannot receive its own
                // custodied asset violates the implicit "I can hold what I pull in"
                // invariant of an ERC-721 holder.
                .dimension(Dimension::Invariant)
                .message(format!(
                    "`{cname}.{fname}` pulls an ERC-721 token into the contract via {how}. `{cname}` does \
                     not implement `onERC721Received` and does not inherit `ERC721Holder` / \
                     `IERC721Receiver`, so it cannot safely act as the NFT's custodian. This is the \
                     locked-NFT class: a token transferred to this contract becomes unrecoverable (or the \
                     safe-deposit path reverts outright).",
                ))
                .recommendation(
                    "Implement `IERC721Receiver.onERC721Received` (return its magic selector) or inherit \
                     OpenZeppelin `ERC721Holder` so the contract can accept and account for NFTs; expose a \
                     path to transfer custodied tokens back out.",
                );
            out.push(cx.finish(b, hit.function, hit.span));
        }

        out
    }
}

// ------------------------------------------------------------------- helpers

/// A located NFT pull-in: the function it occurs in, the call span, and whether
/// it used the `safe` (reverting) variant.
struct PullIn {
    function: sluice_ir::FunctionId,
    span: Span,
    is_safe: bool,
}

/// The contract defines a function named `onERC721Received` (it implements the
/// receiver hook directly, so it can safely hold NFTs).
fn defines_on_erc721_received(cx: &AnalysisContext, c: &Contract) -> bool {
    cx.scir
        .functions_of(c.id)
        .any(|f| f.name.eq_ignore_ascii_case("onERC721Received"))
}

/// The contract inherits a standard ERC-721-receiver mixin (`ERC721Holder`,
/// `IERC721Receiver`, `ERC721TokenReceiver`, `ERC721Receiver`). Any of these makes
/// the contract a valid NFT recipient.
fn inherits_receiver(c: &Contract) -> bool {
    ["erc721holder", "ierc721receiver", "erc721tokenreceiver", "erc721receiver"]
        .iter()
        .any(|needle| c.inherits_like(needle))
}

/// Find the first call in any of the contract's functions that pulls an ERC-721
/// **into the contract itself** (recipient `address(this)`).
fn find_nft_pull_in(cx: &AnalysisContext, c: &Contract) -> Option<PullIn> {
    // Whether the *contract* plainly deals in ERC-721 (used as corroboration when
    // the token handle's type isn't locally resolvable to an NFT type). Matched on
    // the contract source so an `IERC721`/`ERC721`/`nft` mention counts, while a
    // plainly-ERC20 contract (no such mention) is not pulled in via this path.
    let contract_is_nfty = source_is_nfty(&cx.source_text(c.span));

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
                let name = match call.func_name.as_deref() {
                    Some("transferFrom") => "transferFrom",
                    Some("safeTransferFrom") => "safeTransferFrom",
                    _ => return,
                };
                // ERC-721 recipient position: `transferFrom(from, to, tokenId)` and
                // `safeTransferFrom(from, to, tokenId[, data])` both put `to` at
                // args[1]. The SafeERC20 library form `safeTransferFrom(token, from,
                // to, amount)` puts `to` at args[2], so it will not match here —
                // which is exactly what keeps this detector off ERC-20 code.
                let Some(to_arg) = call.args.get(1) else { return };
                if !arg_is_address_this(to_arg) {
                    return;
                }
                // NFT-ness gate (precision): the moved asset must look like an NFT,
                // not an ERC-20. Strongest signal is an NFT-typed handle (the
                // receiver root resolves to a state var / param whose type mentions
                // `721`/`nft`). Otherwise accept `safeTransferFrom` in a contract
                // that plainly deals in ERC-721, or a `transferFrom` likewise.
                let handle_is_nft = call
                    .receiver
                    .as_deref()
                    .and_then(|r| handle_type(c, f, r))
                    .map(|ty| type_is_nfty(&ty))
                    .unwrap_or(false);
                if !handle_is_nft && !contract_is_nfty {
                    return;
                }
                found = Some(PullIn {
                    function: f.id,
                    span: e.span,
                    is_safe: name == "safeTransferFrom",
                });
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

/// Peel single-argument type casts (`address(x)`, `payable(x)`, `IERC721(x)`).
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

/// Root identifier of a member/index/cast chain (`IERC721(t).x` -> `t`, `a.b` -> `a`).
fn root_ident(e: &Expr) -> Option<String> {
    match &unwrap_casts(e).kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root_ident(base),
        _ => None,
    }
}

/// Best-effort textual type of the call receiver (the token handle): if the
/// receiver is a cast `IERC721(x)` use the cast type; otherwise resolve its root
/// identifier to a function parameter or a contract state variable and use that
/// declared type.
fn handle_type(c: &Contract, f: &Function, recv: &Expr) -> Option<String> {
    // `IERC721(x).safeTransferFrom(...)` — the cast names the type directly.
    if let ExprKind::Call(call) = &recv.kind {
        if call.kind == sluice_ir::CallKind::TypeCast {
            if let ExprKind::TypeName(t) = &call.callee.kind {
                return Some(t.clone());
            }
        }
    }
    let root = root_ident(recv)?;
    // A function parameter typed as the NFT handle.
    if let Some(p) = f.params.iter().find(|p| p.name.as_deref() == Some(root.as_str())) {
        return Some(p.ty.clone());
    }
    // A contract state variable holding the NFT handle.
    if let Some(v) = c.state_vars.iter().find(|v| v.name == root) {
        return Some(v.ty.clone());
    }
    None
}

/// A declared type that denotes an ERC-721 handle (`IERC721`, `ERC721`,
/// `ERC721Enumerable`, `INft`, `MyNFT`, ...). Matched as a case-insensitive
/// substring on `721`/`nft`.
fn type_is_nfty(ty: &str) -> bool {
    let l = ty.to_ascii_lowercase();
    l.contains("721") || l.contains("nft")
}

/// The contract source plainly references ERC-721 (an `IERC721`/`ERC721`/`nft`
/// mention). Used as corroboration that a `transferFrom`/`safeTransferFrom` into
/// `address(this)` moves an NFT rather than an ERC-20.
fn source_is_nfty(src: &str) -> bool {
    let l = src.to_ascii_lowercase();
    l.contains("721") || l.contains("nft")
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Staking contract that pulls an ERC-721 into itself via
    // `safeTransferFrom(msg.sender, address(this), tokenId)` but never implements
    // `onERC721Received` and does not inherit a receiver mixin. The safe deposit
    // reverts, and an unsafe deposit would strand the NFT — the locked-NFT class.
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC721 {
            function safeTransferFrom(address from, address to, uint256 tokenId) external;
            function transferFrom(address from, address to, uint256 tokenId) external;
        }
        contract NftStaking {
            IERC721 public nft;
            mapping(uint256 => address) public depositorOf;
            function stake(uint256 tokenId) external {
                depositorOf[tokenId] = msg.sender;
                nft.safeTransferFrom(msg.sender, address(this), tokenId);
            }
        }
    "#;

    // Same custodial staking contract, but it implements `onERC721Received` (the
    // OpenZeppelin receiver hook), so it can safely hold NFTs → must stay silent.
    const SAFE: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC721 {
            function safeTransferFrom(address from, address to, uint256 tokenId) external;
            function transferFrom(address from, address to, uint256 tokenId) external;
        }
        contract NftStaking {
            IERC721 public nft;
            mapping(uint256 => address) public depositorOf;
            function stake(uint256 tokenId) external {
                depositorOf[tokenId] = msg.sender;
                nft.safeTransferFrom(msg.sender, address(this), tokenId);
            }
            function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
                return this.onERC721Received.selector;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "erc721-safety"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "erc721-safety"));
    }
}
