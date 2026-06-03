//! Fee-on-transfer / deflationary / rebasing deposit-accounting mismatch.
//!
//! A deposit that pulls tokens with `transferFrom` and then credits internal
//! accounting (balances / shares / deposits) using the *requested* `amount`
//! rather than the *measured* balance delta over-credits the depositor on any
//! token that takes a transfer fee, rebases, or otherwise delivers less than
//! `amount`. The fix is the balance-before/after pattern:
//! `bal = token.balanceOf(address(this)); transferFrom(...); received = token.balanceOf(address(this)) - bal;`
//! and crediting `received`. The Compound-cToken / many-vault deposit class.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{CallKind, Contract, Expr, ExprKind, Function};

pub struct FeeOnTransferDetector;

impl Detector for FeeOnTransferDetector {
    fn id(&self) -> &'static str {
        "fee-on-transfer"
    }
    fn category(&self) -> Category {
        Category::FeeOnTransfer
    }
    fn description(&self) -> &'static str {
        "Deposit credits requested amount, not measured balance delta (fee-on-transfer/rebasing tokens)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.entry_points() {
            // 1. Must pull tokens in via an external transferFrom / safeTransferFrom.
            let Some((amount_name, call_span)) = pull_in_amount(f) else {
                continue;
            };

            // 2. The same amount value must be credited to internal accounting
            //    (a storage write whose value mentions that amount identifier).
            if !credits_amount_to_accounting(f, &amount_name) {
                continue;
            }

            // 3. Suppress when the function measures the real balance delta.
            let src = cx.source_text(f.span);
            if measures_balance_delta(&src) {
                continue;
            }

            // 4. Suppress when the contract demonstrably handles only a fixed,
            //    standard non-fee token (e.g. WETH/DAI) — no untrusted token can
            //    reach this path.
            if let Some(c) = cx.contract_of(f.id) {
                if only_fixed_standard_token(c) {
                    continue;
                }
            }

            let b = FindingBuilder::new(self.id(), Category::FeeOnTransfer)
                .title("Deposit credits requested amount instead of measured balance delta")
                .severity(Severity::Medium)
                .confidence(0.5)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` pulls tokens with `transferFrom` and credits internal accounting using the \
                     requested `{}`, without measuring `token.balanceOf(address(this))` before and after \
                     the transfer. A fee-on-transfer, deflationary, or rebasing token delivers fewer tokens \
                     than `{}`, so the contract over-credits the depositor and becomes insolvent — later \
                     withdrawers cannot all be paid.",
                    f.name, amount_name, amount_name
                ))
                .recommendation(
                    "Measure the actual received amount: read `token.balanceOf(address(this))` before and \
                     after the `transferFrom`/`safeTransferFrom` and credit the delta, not the requested \
                     amount. Alternatively, disallow non-standard tokens explicitly.",
                );
            out.push(cx.finish(b, f.id, call_span));
        }
        out
    }
}

/// If the function performs an external `transferFrom` / `safeTransferFrom`
/// pulling tokens *in* (recipient is `address(this)` or no explicit recipient
/// that diverts elsewhere), return the simple name of the amount argument and
/// the call's span.
fn pull_in_amount(f: &Function) -> Option<(String, sluice_ir::Span)> {
    // Quick gate using the precomputed effect summary: there must be an external
    // transferFrom-style call site.
    let has_pull = f.effects.call_sites.iter().any(|c| {
        c.kind == CallKind::External
            && matches!(c.func_name.as_deref(), Some("transferFrom") | Some("safeTransferFrom"))
    });
    if !has_pull {
        return None;
    }

    let mut found: Option<(String, sluice_ir::Span)> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            let ExprKind::Call(call) = &e.kind else { return };
            if call.kind != CallKind::External {
                return;
            }
            if !matches!(call.func_name.as_deref(), Some("transferFrom") | Some("safeTransferFrom")) {
                return;
            }
            // transferFrom(from, to, amount) / safeTransferFrom(token, from, to, amount):
            // the amount is the last argument. Take its simple identifier name.
            if let Some(amt) = call.args.last().and_then(amount_ident) {
                found = Some((amt, e.span));
            }
        });
    }
    found
}

/// Best-effort: extract a single identifier name an amount expression resolves
/// to (`amount`, or `amount` inside `uint256(amount)` casts, etc.).
fn amount_ident(e: &Expr) -> Option<String> {
    if let ExprKind::Ident(n) = &e.kind {
        return Some(n.clone());
    }
    // A cast like `uint256(amount)` — descend into the single argument.
    if let ExprKind::Call(c) = &e.kind {
        if c.kind == CallKind::TypeCast {
            if let Some(a) = c.args.first() {
                return amount_ident(a);
            }
        }
    }
    None
}

/// True if a storage write credits internal balance/shares/deposit accounting
/// using the given amount identifier (e.g. `balances[msg.sender] += amount`).
fn credits_amount_to_accounting(f: &Function, amount: &str) -> bool {
    // The written storage var must look like accounting state.
    let writes_accounting = f
        .effects
        .storage_writes
        .iter()
        .any(|w| is_credit_name(&w.var));
    if !writes_accounting {
        return false;
    }

    // And an assignment's *value* (right-hand side) must mention the amount.
    let mut credited = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if credited {
                return;
            }
            if let ExprKind::Assign { target, value, .. } = &e.kind {
                if assign_target_is_credit(target) && expr_mentions_ident(value, amount) {
                    credited = true;
                }
            }
        });
    }
    credited
}

/// Does an assignment lvalue write a balance/shares/deposit-style accounting slot?
fn assign_target_is_credit(target: &Expr) -> bool {
    let mut hit = false;
    target.visit(&mut |e| {
        if let ExprKind::Ident(n) = &e.kind {
            if is_credit_name(n) {
                hit = true;
            }
        }
    });
    hit
}

/// Does an expression reference the given identifier anywhere?
fn expr_mentions_ident(e: &Expr, ident: &str) -> bool {
    let mut hit = false;
    e.visit(&mut |x| {
        if let ExprKind::Ident(n) = &x.kind {
            if n == ident {
                hit = true;
            }
        }
    });
    hit
}

/// Internal-accounting variable names that a deposit would credit.
fn is_credit_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    ["balance", "share", "deposit", "staked", "stake", "principal", "collateral"]
        .iter()
        .any(|k| l.contains(k))
}

/// True if the function source measures the real balance delta around the pull.
fn measures_balance_delta(src_lower: &str) -> bool {
    src_lower.contains("balanceof(address(this))")
        || src_lower.contains("balancebefore")
        || src_lower.contains("balanceafter")
        || src_lower.contains("balbefore")
        || src_lower.contains("balafter")
        || src_lower.contains("received")
        || src_lower.contains("amountreceived")
}

/// Best-effort: the contract handles a single, fixed, standard non-fee token
/// (WETH/DAI) held in an `immutable`/`constant` token state var, so no untrusted
/// fee-on-transfer token can reach the deposit path.
fn only_fixed_standard_token(c: &Contract) -> bool {
    let token_vars: Vec<&sluice_ir::StateVar> = c
        .state_vars
        .iter()
        .filter(|v| {
            let t = v.ty.to_ascii_lowercase();
            t.contains("ierc20") || t.contains("erc20") || t.trim() == "address"
        })
        .collect();
    if token_vars.is_empty() {
        return false;
    }
    // Every token-typed var must be fixed (immutable/constant) AND named after a
    // known standard non-fee token.
    token_vars.iter().all(|v| {
        let fixed = v.immutable || v.constant;
        let n = v.name.to_ascii_lowercase();
        let standard = n.contains("weth") || n.contains("dai") || n.contains("wsteth");
        fixed && standard
    })
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Pulls `amount` via transferFrom, then credits `balances[msg.sender] += amount`
    // without ever measuring balanceOf(address(this)). Insolvent on FoT tokens.
    const VULN: &str = r#"
        interface IERC20 { function transferFrom(address f, address t, uint256 a) external returns (bool); }
        contract Vault {
            IERC20 public token;
            mapping(address => uint256) public balances;
            function deposit(uint256 amount) external {
                token.transferFrom(msg.sender, address(this), amount);
                balances[msg.sender] += amount;
            }
        }
    "#;

    // Measures the real balance delta and credits the received amount.
    const SAFE: &str = r#"
        interface IERC20 {
            function transferFrom(address f, address t, uint256 a) external returns (bool);
            function balanceOf(address who) external view returns (uint256);
        }
        contract Vault {
            IERC20 public token;
            mapping(address => uint256) public balances;
            function deposit(uint256 amount) external {
                uint256 balanceBefore = token.balanceOf(address(this));
                token.transferFrom(msg.sender, address(this), amount);
                uint256 received = token.balanceOf(address(this)) - balanceBefore;
                balances[msg.sender] += received;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "fee-on-transfer"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "fee-on-transfer"));
    }
}
