//! Hook-callback reentrancy: an external token operation that *looks* inert (a
//! "plain ERC20" `transfer`/`transferFrom`/`mint`/`send`) but actually hands
//! control to the caller via a token-standard receive hook
//! (ERC777 `tokensReceived`/`tokensToSend`, ERC721 `onERC721Received`). If such
//! a call precedes a state update and the function has no reentrancy guard, the
//! callee can re-enter before storage settles.
//!
//! This is the dForce / Lendf.me ($25M) class: the protocol believed it was
//! interacting with a vanilla ERC20, but the token implemented ERC777, so the
//! "interaction" was really an attacker-controlled callback executed *before*
//! the "effects" — a checks-effects-interactions violation hidden behind a
//! transfer that the developer assumed could not re-enter.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::CallKind;

pub struct Erc777Detector;

/// Token-operation method names that carry a standard receive/send hook. A call
/// to any of these on an external token can dispatch control to a counterparty
/// contract (ERC777 `tokensReceived`/`tokensToSend`, ERC721 `onERC721Received`),
/// even though the call site reads like an ordinary ERC20 movement.
// Only genuinely hook-dispatching ops. Plain ERC-20 `transfer`/`transferFrom`
// are intentionally excluded: those are already covered by the generic
// reentrancy detector, and including them double-reported every standard
// `transferFrom`-then-update deposit. This detector is specifically for the
// ERC777/ERC721 *callback* surface (the dForce/Lendf.me class).
const HOOK_BEARING_TOKEN_OPS: &[&str] = &[
    "safeTransferFrom",  // ERC721/1155: invokes onERC721Received/onERC1155Received
    "safeTransfer",      // ERC721 safe transfer hook
    "safeMint",          // ERC721: invokes onERC721Received
    "_safeMint",
    "safeBatchTransferFrom",
    "send",              // ERC777 `token.send(to, amount, data)` -> tokensReceived
    "operatorSend",      // ERC777 operator send
];

impl Detector for Erc777Detector {
    fn id(&self) -> &'static str {
        "erc777-reentrancy"
    }
    fn category(&self) -> Category {
        Category::Erc777Reentrancy
    }
    fn description(&self) -> &'static str {
        "Reentrancy via a token receive hook (ERC777 tokensReceived / ERC721 onERC721Received) on a \
         supposedly-inert ERC20 transfer before a state update"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Suppression: an explicit reentrancy guard (lock modifier or a
            // ReentrancyGuard base) makes the callback harmless.
            if cx.has_reentrancy_guard(f) {
                continue;
            }

            // Find the earliest hook-bearing token op that is classified as a
            // genuine external call (a token handle's `transfer`, not an ETH
            // `addr.transfer`). We anchor on the earliest such op so any later
            // storage write counts as "state updated after the hook".
            let token_op = f
                .effects
                .call_sites
                .iter()
                .filter(|c| c.kind == CallKind::External)
                .filter(|c| {
                    c.func_name
                        .as_deref()
                        .map(|n| HOOK_BEARING_TOKEN_OPS.contains(&n))
                        .unwrap_or(false)
                })
                .min_by_key(|c| c.order);

            let token_op = match token_op {
                Some(c) => c,
                None => continue,
            };

            // Suppression: if no storage write follows the token op, the
            // function already honors checks-effects-interactions — the hook
            // can re-enter but finds fully-settled state, so there is nothing to
            // exploit.
            let write_after = f
                .effects
                .storage_writes
                .iter()
                .find(|w| w.order > token_op.order);
            let write_after = match write_after {
                Some(w) => w,
                None => continue,
            };

            let op_name = token_op.func_name.as_deref().unwrap_or("transfer");
            let mut b = FindingBuilder::new(self.id(), Category::Erc777Reentrancy)
                .title("Token-hook reentrancy: external token op before state update")
                .severity(Severity::High)
                // Heuristic, and it overlaps the generic reentrancy detector
                // (the engine de-duplicates by location), so keep confidence
                // modest rather than asserting structural certainty.
                .confidence(0.5)
                // Frontier: the hazard is a trust frontier crossed unsafely —
                // an external token call hands control to a counterparty before
                // `{}` is written.
                .dimension(Dimension::Frontier)
                .message(format!(
                    "`{}` calls `{}` on an external token and only afterwards writes `{}`. If that token \
                     implements a receive hook (ERC777 `tokensReceived`/`tokensToSend`, or ERC721 \
                     `onERC721Received`), the recipient regains control *before* the state update and can \
                     re-enter. A path the developer assumed was a vanilla, non-reentrant ERC20 transfer is \
                     actually reentrant — the dForce/Lendf.me ($25M) class.",
                    f.name, op_name, write_after.var
                ))
                .recommendation(
                    "Apply checks-effects-interactions (update storage before the token call) and add a \
                     `nonReentrant` guard. Do not assume an external token is hook-free; treat ERC777/ERC721 \
                     transfers as control-transferring external calls.",
                );

            // Value-flow corroboration: a hook-bearing transfer is itself a
            // value movement, and the post-call write is what the re-entrant
            // path manipulates.
            b = b.dimension(Dimension::ValueFlow);

            out.push(cx.finish(b, f.id, token_op.span));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Hook-bearing token op (ERC721 safeTransferFrom -> onERC721Received) executed
    // BEFORE the balance update, with no reentrancy guard: the recipient hook can
    // re-enter while state is stale (dForce/Lendf.me class).
    const VULN: &str = r#"
        interface INFT { function safeTransferFrom(address from, address to, uint256 id) external; }
        contract Bank {
            mapping(address => uint256) public balances;
            INFT public nft;
            function deposit() external { balances[msg.sender] += 1; }
            function withdraw(uint256 id) external {
                require(balances[msg.sender] >= 1);
                nft.safeTransferFrom(address(this), msg.sender, id);
                balances[msg.sender] -= 1;
            }
        }
    "#;

    // Checks-effects-interactions honored: the balance is decremented BEFORE
    // the hook-bearing call, so no state write follows it.
    const SAFE: &str = r#"
        interface INFT { function safeTransferFrom(address from, address to, uint256 id) external; }
        contract Bank {
            mapping(address => uint256) public balances;
            INFT public nft;
            function deposit() external { balances[msg.sender] += 1; }
            function withdraw(uint256 id) external {
                require(balances[msg.sender] >= 1);
                balances[msg.sender] -= 1;
                nft.safeTransferFrom(address(this), msg.sender, id);
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "erc777-reentrancy"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "erc777-reentrancy"));
    }
}
