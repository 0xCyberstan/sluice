//! Strict equality / disequality against a live, externally-perturbable balance
//! or supply read used inside a guard (SWC-132).
//!
//! A `require`/`assert`/`if` condition that pins a *live* on-chain quantity with
//! `==` or `!=` is brittle, because an attacker can move that quantity by an
//! arbitrary amount the contract never accounts for:
//!
//!   * `address(_).balance` — ETH can be force-credited with
//!     `selfdestruct(payable(victim))` (and coinbase / genesis preallocation),
//!     bypassing every payable hook; the balance can always be nudged up by 1 wei.
//!   * an ERC-20 `balanceOf(_)` — anyone may `transfer` tokens straight to the
//!     account (a *donation*), inflating the balance with no cooperation.
//!   * `totalSupply()` — a permissionless `mint`/`deposit` (or, for a rebasing /
//!     fee-on-transfer token, ordinary activity) shifts supply.
//!
//! When such a read is one operand of a strict `==`/`!=` inside a guard, an
//! attacker forces a 1-unit perturbation so the equality never holds — bricking
//! the path (DoS) or pushing the contract into the unintended branch (logic
//! bypass). The historical lesson (SWC-132) is to never use *strict* equality on
//! a value an outsider can move; track an internal counter, or use an inequality
//! (`>=` / `<=`) that tolerates the donated/forced surplus.
//!
//! ## What fires
//!
//! A [`BinOp::Eq`] / [`BinOp::Ne`] comparison, *inside a guard condition*
//! (a `require`/`assert` argument, or an `if`/`while`/`do-while`/`for`/ternary
//! condition), at least one of whose operand subtrees contains a balance/supply
//! read — recognised structurally on the IR call/member node, not by text:
//!   * a call whose resolved method name is `balanceOf` (>= 1 arg) or
//!     `totalSupply` (0 args), or
//!   * a `.balance` member access (`address(x).balance` / `x.balance`).
//!
//! ## What stays silent (the safe form)
//!
//!   * **Non-strict comparisons** — `>=`, `<=`, `>`, `<` never match `Eq`/`Ne`,
//!     so an inequality reconciliation (`balance >= booked`) is silent *by
//!     construction*. This is the recommended fix and the primary suppressed shape.
//!   * **A bare presence check** (`balance == 0` / `!= 0`): a forced donation can
//!     only *raise* a balance, so it cannot defeat a zero-check — a common benign
//!     gate, suppressed.
//!   * Equalities **outside** any guard (a plain assignment RHS, an event arg, a
//!     `return a == b` that is not a guard) are not this class.
//!
//! Canonical-baseline lint (SWC-132): it *should* fire wherever the genuine shape
//! exists. Shipped at **Low** severity with modest confidence so it never
//! outranks a real value finding. Pairs with `forced-ether` (which is textual and
//! self-balance-only, fires on both guard and non-guard `==`/`!=` at Medium, and
//! reports under a *different* category so the two never dedup).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Builtin, CallKind, Expr, ExprKind, Function, Span, StmtKind};

use super::prelude::finish_at;

pub struct StrictBalanceEqualityDetector;

impl Detector for StrictBalanceEqualityDetector {
    fn id(&self) -> &'static str {
        "strict-balance-equality"
    }
    fn category(&self) -> Category {
        Category::StrictBalanceEquality
    }
    fn description(&self) -> &'static str {
        "Strict ==/!= against a live balance/supply read (balanceOf / totalSupply / address.balance) inside a guard (SWC-132)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.functions() {
            if !f.has_body {
                continue;
            }

            // De-dup per function: report each offending comparison span once.
            let mut seen: Vec<Span> = Vec::new();

            // Every guard *condition* subtree in the body (a `require`/`assert`
            // argument, or an `if`/`while`/`do-while`/`for`/ternary condition).
            // We only inspect comparisons that live inside one of these — an
            // equality elsewhere (an assignment RHS, an event arg) is not a guard.
            for cond in guard_conditions(f) {
                cond.visit(&mut |e: &Expr| {
                    let ExprKind::Binary { op, lhs, rhs } = &e.kind else {
                        return;
                    };
                    // Only strict equality / disequality. Ordering comparisons
                    // (`>=`, `<=`, `>`, `<`) tolerate a donated/forced surplus and
                    // are the recommended fix — never flagged (silent by match).
                    if !matches!(op, BinOp::Eq | BinOp::Ne) {
                        return;
                    }

                    // At least one operand subtree must read a live balance/supply.
                    let lhs_read = expr_reads_live_balance(lhs);
                    let rhs_read = expr_reads_live_balance(rhs);
                    let Some(read) = lhs_read.or(rhs_read) else {
                        return;
                    };

                    // Suppress a bare presence check (`balance == 0` / `!= 0`): a
                    // forced donation can only raise a balance, so it cannot defeat
                    // a zero-check — a common benign gate, not a brittle equality.
                    if operand_is_zero(lhs) || operand_is_zero(rhs) {
                        return;
                    }

                    if seen.contains(&e.span) {
                        return;
                    }
                    seen.push(e.span);

                    let (asset, injection) = read.describe();
                    let b = report!(self, Category::StrictBalanceEquality,
                        title = "Strict equality against a live, donatable/forceable balance in a guard",
                        severity = Severity::Low,
                        confidence = 0.45,
                        dimensions = [Dimension::Invariant],
                        message = format!(
                            "`{}` guards on a strict {} (`{}`) where one operand is a live {}. Because {}, \
                             an attacker can perturb it by one unit so the comparison never holds — \
                             bricking this path (DoS) or forcing the unintended branch (SWC-132). A live \
                             balance/supply must not be the source of truth for a strict equality.",
                            f.name,
                            if matches!(op, BinOp::Eq) { "equality" } else { "disequality" },
                            cx.scir.span_text(e.span).trim(),
                            asset,
                            injection,
                        ),
                        recommendation =
                            "Compare against an internal counter you control, or use a non-strict \
                             inequality (`>=` / `<=`) that tolerates donated or force-sent surplus \
                             instead of `==` / `!=`.",
                    );
                    out.push(finish_at(cx, b, f.id, e.span));
                });
            }
        }

        out
    }
}

/// What kind of live, externally-perturbable quantity an operand reads.
#[derive(Clone, Copy)]
enum BalanceRead {
    /// `address(_).balance` / `x.balance` — force-injectable ETH.
    NativeBalance,
    /// An ERC-20 `balanceOf(_)` — freely donatable token balance.
    TokenBalance,
    /// `totalSupply()` — shiftable by a permissionless mint / deposit / rebase.
    TotalSupply,
}

impl BalanceRead {
    /// `(asset phrase, why-it's-perturbable phrase)` for the finding message.
    fn describe(self) -> (&'static str, &'static str) {
        match self {
            BalanceRead::NativeBalance => (
                "native ETH balance (`address(_).balance`)",
                "`selfdestruct(payable(_))` (or a coinbase / genesis credit) can force ETH in with no \
                 payable hook",
            ),
            BalanceRead::TokenBalance => (
                "ERC-20 balance (`balanceOf(_)`)",
                "anyone can `transfer` tokens straight to that account (a donation)",
            ),
            BalanceRead::TotalSupply => (
                "token `totalSupply()`",
                "a permissionless mint / deposit (or a rebasing / fee-on-transfer token) shifts the supply",
            ),
        }
    }
}

/// If the expression subtree contains a live balance/supply read, return the
/// first one found. Recognised structurally on the IR node:
///   * a call whose resolved method name is `balanceOf` (>= 1 arg) — the ERC-20
///     balance getter; the 1-arg requirement excludes a 0-arg `balanceOf()`
///     accessor that is not the standard reading;
///   * a call whose resolved method name is `totalSupply` (0 args) — excludes an
///     unrelated `totalSupply(x)` helper that takes an argument;
///   * a `.balance` member access (`address(this).balance`, `a.balance`). We
///     exclude a `.balance` that is itself a *call* receiver/method (there is no
///     `.balance()` method on `address`, so a bare member read is the balance).
fn expr_reads_live_balance(e: &Expr) -> Option<BalanceRead> {
    let mut found: Option<BalanceRead> = None;
    e.visit(&mut |sub: &Expr| {
        if found.is_some() {
            return;
        }
        match &sub.kind {
            ExprKind::Call(c) => {
                // Only genuine method calls (external / internal / lib-bound),
                // never a type cast, count as a balance/supply getter.
                if matches!(c.kind, CallKind::TypeCast | CallKind::Builtin(_)) {
                    return;
                }
                match c.func_name.as_deref() {
                    Some("balanceOf") if !c.args.is_empty() => {
                        found = Some(BalanceRead::TokenBalance);
                    }
                    Some("totalSupply") if c.args.is_empty() => {
                        found = Some(BalanceRead::TotalSupply);
                    }
                    _ => {}
                }
            }
            ExprKind::Member { member, .. } if member == "balance" => {
                found = Some(BalanceRead::NativeBalance);
            }
            _ => {}
        }
    });
    found
}

/// Collect every guard *condition* expression in `f`'s body: the first argument
/// of a `require`/`assert` call, and the condition of an `if`/`while`/`do-while`/
/// `for` statement and of a ternary. Returned by clone so the caller can re-`visit`
/// them freely. (A `revert`-guarded `if (cond) revert;` is reached via the `If`
/// condition; the `require`/`assert` argument is reached via the call walk.)
fn guard_conditions(f: &Function) -> Vec<Expr> {
    let mut conds: Vec<Expr> = Vec::new();

    // Statement-level conditions: `if`/`while`/`do-while`/`for` headers.
    for s in &f.body {
        s.visit(&mut |st| match &st.kind {
            StmtKind::If { cond, .. }
            | StmtKind::While { cond, .. }
            | StmtKind::DoWhile { cond, .. } => conds.push(cond.clone()),
            StmtKind::For { cond: Some(c), .. } => conds.push(c.clone()),
            _ => {}
        });
    }

    // Expression-level guard conditions: a `require`/`assert` argument, and any
    // ternary `cond ? a : b` condition. `visit_exprs` reaches nested expressions,
    // so a `require(... ? ... : ...)` and a ternary in any position are covered.
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| match &e.kind {
            ExprKind::Call(c)
                if matches!(
                    c.kind,
                    CallKind::Builtin(Builtin::Require) | CallKind::Builtin(Builtin::Assert)
                ) =>
            {
                if let Some(arg) = c.args.first() {
                    conds.push(arg.clone());
                }
            }
            ExprKind::Ternary { cond, .. } => conds.push((**cond).clone()),
            _ => {}
        });
    }

    conds
}

/// True if `e` is exactly the integer literal `0` (a benign presence check, not a
/// brittle accounting equality). Tolerates the common spellings.
fn operand_is_zero(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(sluice_ir::Lit::Number(n)) | ExprKind::Lit(sluice_ir::Lit::HexNumber(n)) => {
            let t = n.trim().trim_start_matches("0x").trim_start_matches("0X");
            t.is_empty() || t.chars().all(|c| c == '0')
        }
        // `uint256(0)` / `uint(0)` — a single-arg cast of a zero literal.
        ExprKind::Call(c) if c.kind == CallKind::TypeCast && c.args.len() == 1 => {
            operand_is_zero(&c.args[0])
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    fn fired(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "strict-balance-equality")
    }

    // Vulnerable: a `require` pins the contract's own ETH balance with strict `==`.
    // A 1-wei `selfdestruct` donation bricks the path forever.
    const VULN_ETH: &str = r#"
        pragma solidity ^0.8.20;
        contract Bank {
            uint256 public booked;
            function check() external view returns (bool) {
                require(address(this).balance == booked, "mismatch");
                return true;
            }
        }
    "#;

    // Vulnerable: an `if`-guard on an ERC-20 `balanceOf(this)` disequality. A
    // donated token defeats the `!=` and forces the revert branch.
    const VULN_TOKEN: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC20 { function balanceOf(address) external view returns (uint256); }
        contract Vault {
            IERC20 token;
            uint256 expected;
            function sync() external {
                if (token.balanceOf(address(this)) != expected) revert();
            }
        }
    "#;

    // Vulnerable: a `require` on `totalSupply()` strict equality. A permissionless
    // mint shifts supply and bricks the check.
    const VULN_SUPPLY: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC20 { function totalSupply() external view returns (uint256); }
        contract Cap {
            IERC20 token;
            uint256 cap;
            function atCap() external view returns (bool) {
                require(token.totalSupply() == cap, "supply");
                return true;
            }
        }
    "#;

    // Safe form 1: the SAME reconciliation, but with a non-strict `>=`. An
    // inequality tolerates donated / forced surplus — the recommended fix.
    const SAFE_GE: &str = r#"
        pragma solidity ^0.8.20;
        contract Bank {
            uint256 public booked;
            function check() external view returns (bool) {
                require(address(this).balance >= booked, "short");
                return true;
            }
        }
    "#;

    // Safe form 2: a bare presence check (`balance == 0`). A forced donation can
    // only raise a balance, so it cannot defeat a zero-check — suppressed.
    const SAFE_ZERO: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC20 { function balanceOf(address) external view returns (uint256); }
        contract Vault {
            IERC20 token;
            function empty() external view returns (bool) {
                return token.balanceOf(address(this)) == 0;
            }
        }
    "#;

    // Safe form 3: the strict equality is NOT in a guard — it is a plain `return`
    // boolean and a `==` used as a value. Not a guard context.
    const SAFE_NOT_GUARD: &str = r#"
        pragma solidity ^0.8.20;
        interface IERC20 { function balanceOf(address) external view returns (uint256); }
        contract Reader {
            IERC20 token;
            uint256 expected;
            function eq() external view returns (bool) {
                bool b = token.balanceOf(address(this)) == expected;
                return b;
            }
        }
    "#;

    #[test]
    fn fires_on_eth_balance_equality() {
        assert!(fired(VULN_ETH), "{:?}", run(VULN_ETH));
    }

    #[test]
    fn fires_on_token_balance_disequality() {
        assert!(fired(VULN_TOKEN), "{:?}", run(VULN_TOKEN));
    }

    #[test]
    fn fires_on_total_supply_equality() {
        assert!(fired(VULN_SUPPLY), "{:?}", run(VULN_SUPPLY));
    }

    #[test]
    fn silent_on_non_strict_inequality() {
        assert!(!fired(SAFE_GE), "{:?}", run(SAFE_GE));
    }

    #[test]
    fn silent_on_zero_presence_check() {
        assert!(!fired(SAFE_ZERO), "{:?}", run(SAFE_ZERO));
    }

    #[test]
    fn silent_outside_guard() {
        // The `return b;` boolean is not a guard; the `==` builds a value, not a
        // require/if condition. (If this proves noisy to suppress, the assertion
        // documents intent — but the guard-only gate should keep it silent.)
        assert!(!fired(SAFE_NOT_GUARD), "{:?}", run(SAFE_NOT_GUARD));
    }
}
