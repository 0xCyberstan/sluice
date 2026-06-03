//! ERC-721 `_safeMint` / `safeMint` callback reentrancy.
//!
//! `_safeMint(to, id)` (OpenZeppelin) calls `to.onERC721Received(...)` when `to`
//! is a contract — handing control to a potentially attacker-controlled recipient
//! *in the middle of the mint*. Crucially, `_safeMint`/`safeMint` are **inherited
//! internal** functions, so the classic reentrancy detector — which keys on
//! external/low-level calls (`CallKind::is_external_transfer_of_control`) — does
//! not model this control transfer at all. The gap is real and historically
//! exploited: an attacker's `onERC721Received` re-enters the mint function before
//! a post-mint state update (a supply counter, a per-wallet mint cap, the next
//! token id) settles, minting past the cap or paying once for many NFTs.
//!
//! Precise shape (checks-effects-interactions around the implicit callback): a
//! state-mutating, externally reachable, **non-`nonReentrant`** function performs
//! a `_safeMint`/`safeMint` and then writes a contract state variable *after* it.
//! A function that updates its supply/cap/id **before** the safe-mint (correct
//! CEI) does not fire — the ordering is what distinguishes the bug from a safe
//! mint. A `nonReentrant` guard, or no post-mint state write, suppresses.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Expr, ExprKind, Span, Stmt, StmtKind, UnOp};

pub struct Erc721MintReentrancyDetector;

impl Detector for Erc721MintReentrancyDetector {
    fn id(&self) -> &'static str {
        "erc721-mint-reentrancy"
    }
    fn category(&self) -> Category {
        Category::MintCallbackReentrancy
    }
    fn description(&self) -> &'static str {
        "ERC-721 _safeMint/safeMint hands control to the recipient's onERC721Received before a post-mint state update settles (mint-callback reentrancy)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.entry_points() {
            // A reentrancy lock makes the callback re-entry harmless.
            if cx.has_reentrancy_guard(f) {
                continue;
            }
            let Some(contract) = cx.contract_of(f.id) else { continue };
            let state: Vec<&str> = contract.state_vars.iter().map(|v| v.name.as_str()).collect();

            // In-order event stream over the body: a safe-mint event, then any
            // contract-state write that follows it, is the vulnerable shape.
            let mut events = Vec::new();
            collect_events(&f.body, &state, &mut events);

            let Some(mint_span) = first_mint_followed_by_write(&events) else { continue };

            let b = FindingBuilder::new(self.id(), Category::MintCallbackReentrancy)
                .title("ERC-721 safe-mint callback reentrancy (state updated after _safeMint)")
                .severity(Severity::High)
                .confidence(0.5)
                .dimension(Dimension::Frontier)
                .message(format!(
                    "`{}` calls `_safeMint`/`safeMint`, which invokes the recipient's `onERC721Received` \
                     hook (a control transfer to a potentially attacker-controlled contract), and then \
                     writes contract state AFTER the mint. Because `_safeMint` is an inherited internal \
                     call, the ordinary reentrancy check does not see this callback. The recipient can \
                     re-enter before the post-mint state (supply counter / mint cap / token id) settles — \
                     the NFT-mint reentrancy class.",
                    f.name
                ))
                .recommendation(
                    "Apply checks-effects-interactions: perform all state updates (increment the supply / \
                     id / per-wallet counter) BEFORE the `_safeMint`, and/or add a `nonReentrant` guard so \
                     the `onERC721Received` callback cannot re-enter.",
                );
            out.push(cx.finish(b, f.id, mint_span));
        }
        out
    }
}

/// One ordered effect inside a function body.
enum Ev {
    /// A `_safeMint`/`safeMint` call (control transfer to the recipient), at span.
    Mint(Span),
    /// A write to a contract state variable.
    Write,
}

/// The span of the first `_safeMint`/`safeMint` that is followed (in execution
/// order) by a contract-state write.
fn first_mint_followed_by_write(events: &[Ev]) -> Option<Span> {
    let mut pending_mint: Option<Span> = None;
    for e in events {
        match e {
            Ev::Mint(s) => pending_mint = Some(*s),
            Ev::Write => {
                if let Some(s) = pending_mint {
                    return Some(s);
                }
            }
        }
    }
    None
}

/// Walk statements in execution order, appending `Mint`/`Write` events. Recurses
/// into nested blocks/branches/loops so a mint-then-write inside a loop or an
/// `if` body is captured (a batch mint that bumps a running counter per iteration
/// is exactly the dangerous case).
fn collect_events(stmts: &[Stmt], state: &[&str], out: &mut Vec<Ev>) {
    for s in stmts {
        match &s.kind {
            StmtKind::Expr(e) | StmtKind::Emit(e) => scan_expr(e, state, out),
            StmtKind::VarDecl { init: Some(e), .. } => scan_expr(e, state, out),
            StmtKind::Return(Some(e)) => scan_expr(e, state, out),
            StmtKind::If { cond, then_branch, else_branch } => {
                scan_expr(cond, state, out);
                collect_events(then_branch, state, out);
                collect_events(else_branch, state, out);
            }
            StmtKind::While { cond, body } => {
                scan_expr(cond, state, out);
                collect_events(body, state, out);
            }
            StmtKind::DoWhile { body, cond } => {
                collect_events(body, state, out);
                scan_expr(cond, state, out);
            }
            StmtKind::For { init, cond, step, body } => {
                if let Some(i) = init {
                    collect_events(std::slice::from_ref(i), state, out);
                }
                if let Some(c) = cond {
                    scan_expr(c, state, out);
                }
                collect_events(body, state, out);
                if let Some(st) = step {
                    scan_expr(st, state, out);
                }
            }
            StmtKind::Block { stmts, .. } => collect_events(stmts, state, out),
            StmtKind::Try { expr, body, catches, .. } => {
                scan_expr(expr, state, out);
                collect_events(body, state, out);
                for c in catches {
                    collect_events(&c.body, state, out);
                }
            }
            _ => {}
        }
    }
}

/// Scan a single expression (pre-order) for a safe-mint call and for writes to a
/// contract state variable, appending events in the order encountered.
fn scan_expr(e: &Expr, state: &[&str], out: &mut Vec<Ev>) {
    e.visit(&mut |sub| match &sub.kind {
        ExprKind::Call(c) => {
            if matches!(c.func_name.as_deref(), Some("_safeMint") | Some("safeMint")) {
                out.push(Ev::Mint(sub.span));
            }
        }
        ExprKind::Assign { target, .. } => {
            if root_is_state(target, state) {
                out.push(Ev::Write);
            }
        }
        ExprKind::Unary { op, operand } => {
            if matches!(op, UnOp::PreInc | UnOp::PostInc | UnOp::PreDec | UnOp::PostDec | UnOp::Delete)
                && root_is_state(operand, state)
            {
                out.push(Ev::Write);
            }
        }
        _ => {}
    });
}

/// True if the lvalue's root identifier names a contract state variable.
fn root_is_state(e: &Expr, state: &[&str]) -> bool {
    match root_ident(e) {
        Some(r) => state.iter().any(|s| *s == r),
        None => false,
    }
}

fn root_ident(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root_ident(base),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn fires(src: &str) -> bool {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default())
            .findings
            .iter()
            .any(|f| f.detector == "erc721-mint-reentrancy")
    }

    // State (`totalMinted`) is bumped AFTER `_safeMint`, whose onERC721Received
    // hook can re-enter before the counter settles → vulnerable.
    const VULN: &str = r#"
        contract NFT {
            uint256 public totalMinted;
            uint256 public constant CAP = 5;
            function mint() external {
                require(totalMinted < CAP, "cap");
                _safeMint(msg.sender, totalMinted);
                totalMinted += 1;
            }
            function _safeMint(address to, uint256 id) internal {}
        }
    "#;

    // Correct CEI: the counter is incremented BEFORE the safe-mint → safe.
    const SAFE_CEI: &str = r#"
        contract NFT {
            uint256 public totalMinted;
            uint256 public constant CAP = 5;
            function mint() external {
                require(totalMinted < CAP, "cap");
                totalMinted += 1;
                _safeMint(msg.sender, totalMinted);
            }
            function _safeMint(address to, uint256 id) internal {}
        }
    "#;

    // A reentrancy guard neutralizes the callback re-entry.
    const SAFE_GUARD: &str = r#"
        contract NFT is ReentrancyGuard {
            uint256 public totalMinted;
            function mint() external nonReentrant {
                _safeMint(msg.sender, totalMinted);
                totalMinted += 1;
            }
            function _safeMint(address to, uint256 id) internal {}
        }
        contract ReentrancyGuard { modifier nonReentrant() { _; } }
    "#;

    #[test]
    fn fires_when_state_written_after_safemint() {
        assert!(fires(VULN));
    }

    #[test]
    fn silent_on_cei_ordered_mint() {
        assert!(!fires(SAFE_CEI));
    }

    #[test]
    fn silent_with_reentrancy_guard() {
        assert!(!fires(SAFE_GUARD));
    }
}
