//! Double-entry-point token sweep — the Compound/Balancer TUSD class.
//!
//! Some ERC-20s are reachable through **two contract addresses** that share the
//! same underlying balance ledger (the canonical example is old TUSD, which had
//! a proxy *and* a legacy `TrueUSD` entry point; a number of Compound/Balancer-
//! listed tokens had the same property). For such a token,
//! `token.balanceOf(address(this))` returns the *same* number no matter which
//! entry point `token` points at — so a sweeper that (a) lets the caller pass an
//! arbitrary token address and (b) sweeps `balanceOf(address(this))` of *that*
//! token can be pointed at the second entry point of the protocol's own core
//! asset. The contract then "sweeps" what it believes is a foreign / surplus
//! token but is in fact its real reserves, via the alternate address. This is
//! the bug behind Compound's TUSD freeze and Balancer's double-entry advisories.
//!
//! Shape we flag: a function named `sweep`/`skim`/`recover`/`rescue`/
//! `withdrawToken`/`collect` (etc.) that reads `token.balanceOf(address(this))`
//! where `token` is a **function parameter** (an arbitrary, caller-chosen token)
//! and then transfers that balance out of the contract. A sweeper over a *fixed*
//! token (state variable / cast) is not in scope — only an arbitrary-token sweep
//! is exposed to the second-entry-point trick.
//!
//! False positives are suppressed when the function explicitly excludes the
//! protocol's main/underlying token — a `require(token != underlying)` /
//! "cannot sweep the main token" guard — which is exactly the documented
//! mitigation for this class. Confidence is deliberately modest: this is a
//! heuristic over a real but narrow token-integration hazard.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{CallKind, Expr, ExprKind, Function};

pub struct DoubleEntryTokenDetector;

impl Detector for DoubleEntryTokenDetector {
    fn id(&self) -> &'static str {
        "double-entry-token"
    }
    fn category(&self) -> Category {
        Category::DoubleEntryToken
    }
    fn description(&self) -> &'static str {
        "Arbitrary-token sweep via balanceOf(address(this)) exposed to double-entry-point tokens (TUSD class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.entry_points() {
            // The function's role must be a sweep/skim/recover of "other" tokens.
            if !name_is_sweep(&f.name) {
                continue;
            }
            // Quick gate via the effect summary: it must read `balanceOf` and
            // also move tokens out (otherwise there is nothing to sweep).
            let reads_balance_of = f
                .effects
                .call_sites
                .iter()
                .any(|c| c.func_name.as_deref() == Some("balanceOf"));
            if !reads_balance_of || !moves_tokens_out(f) {
                continue;
            }

            // Find a `token.balanceOf(address(this))` whose `token` receiver root
            // is an arbitrary (caller-chosen) token *parameter*. Report at most
            // one finding per function.
            let mut hit: Option<(sluice_ir::Span, String)> = None;
            for s in &f.body {
                s.visit_exprs(&mut |e| {
                    if hit.is_some() {
                        return;
                    }
                    let ExprKind::Call(call) = &e.kind else { return };
                    if call.func_name.as_deref() != Some("balanceOf") {
                        return;
                    }
                    // Must be `balanceOf(address(this))` — the contract's *own*
                    // balance is what a double-entry token lets an attacker
                    // redirect onto the real reserves. A `balanceOf(user)` read is
                    // a different shape and out of scope.
                    if !call.args.first().map(arg_is_address_this).unwrap_or(false) {
                        return;
                    }
                    // The token (call receiver) must be an arbitrary token chosen
                    // by the caller: an `address`/`IERC20`-typed *parameter*. A
                    // fixed token (state var / literal / cast of one) is not
                    // exposed to the second-entry-point trick, so it is skipped.
                    let Some(recv) = call.receiver.as_deref() else { return };
                    let Some(tok) = token_param_root(f, recv) else { return };
                    hit = Some((e.span, tok));
                });
                if hit.is_some() {
                    break;
                }
            }
            let Some((span, token)) = hit else { continue };

            // FP suppression: the function explicitly forbids sweeping the
            // protocol's main/underlying token (the documented mitigation).
            if excludes_main_token(cx, f, &token) {
                continue;
            }

            let b = FindingBuilder::new(self.id(), Category::DoubleEntryToken)
                .title("Arbitrary-token sweep trusts balanceOf — exposed to double-entry-point tokens")
                .severity(Severity::Medium)
                // Honest: a heuristic over a narrow token-integration hazard that
                // depends on the *deployed* token actually having two entry points.
                .confidence(0.45)
                // Value-flow: a caller-chosen token's `balanceOf(address(this))`
                // decides how many tokens leave the contract.
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` sweeps `{token}.balanceOf(address(this))` for a caller-supplied token and transfers \
                     that amount out, without excluding the protocol's main/underlying token. A \
                     double-entry-point token (e.g. legacy TUSD, which is reachable through two addresses \
                     sharing one balance ledger) lets an attacker point `{token}` at the *second* entry point \
                     of the protocol's own reserve asset: `balanceOf` then reports the real reserves and the \
                     sweep drains them through the alternate address. This is the Compound/Balancer TUSD \
                     double-entry class.",
                    f.name
                ))
                .recommendation(
                    "Do not sweep balances of an arbitrary caller-chosen token. Maintain an allowlist of \
                     sweepable tokens, or explicitly reject the protocol's core/underlying token \
                     (`require(token != underlying)`) AND every known alternate entry point of it. Prefer \
                     tracking surplus as `balanceOf(this) - accountedReserves` rather than the raw balance.",
                );
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

// ------------------------------------------------------------------- helpers

/// Function names that denote sweeping/recovering *other* tokens out of a
/// contract — the surface for the double-entry-point trick.
fn name_is_sweep(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "sweep",
        "skim",
        "recover",
        "rescue",
        "withdrawtoken",
        "withdrawerc20",
        "collect",
        "salvage",
        "reclaim",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// The function transfers tokens out (an ERC-20 transfer / safeTransfer /
/// transferFrom, or a low-level call that can send value). Required so we only
/// flag a real *sweep*, not a view that merely reads `balanceOf`.
fn moves_tokens_out(f: &Function) -> bool {
    f.effects.call_sites.iter().any(|c| {
        matches!(
            c.func_name.as_deref(),
            Some("transfer") | Some("safeTransfer") | Some("transferFrom") | Some("safeTransferFrom")
        ) || c.sends_value
    })
}

/// Peel single-argument type casts (`address(x)`, `payable(x)`, `IERC20(x)`).
fn unwrap_casts(e: &Expr) -> &Expr {
    let mut cur = e;
    loop {
        match &cur.kind {
            ExprKind::Call(c) if c.kind == CallKind::TypeCast && c.args.len() == 1 => {
                cur = &c.args[0];
            }
            _ => return cur,
        }
    }
}

/// `address(this)` (after stripping the cast it is the bare `this` identifier).
fn arg_is_address_this(e: &Expr) -> bool {
    matches!(&unwrap_casts(e).kind, ExprKind::Ident(n) if n == "this")
}

/// Root identifier of a member/index/cast chain (`IERC20(t).x` -> `t`, `a.b` -> `a`).
fn root_ident(e: &Expr) -> Option<String> {
    match &unwrap_casts(e).kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root_ident(base),
        _ => None,
    }
}

/// If the `balanceOf` receiver resolves to an `address`/`IERC20`-typed function
/// parameter, return that parameter name. This is what makes the token
/// "arbitrary" (caller-chosen) rather than a fixed protocol asset.
fn token_param_root(f: &Function, recv: &Expr) -> Option<String> {
    let root = root_ident(recv)?;
    f.params.iter().find_map(|p| {
        if p.name.as_deref() != Some(root.as_str()) {
            return None;
        }
        let ty = p.ty.to_ascii_lowercase();
        // Exclude the value types (`int*`/`uint*`/`bool`/`bytes*`/`string`) so the
        // leading "i" of `int256` doesn't masquerade as an `IXxx` interface.
        let is_value_type = ty.starts_with("uint")
            || ty.starts_with("int")
            || ty.starts_with("bool")
            || ty.starts_with("bytes")
            || ty.starts_with("string");
        // A token handle is typed `address` or an ERC-20-ish interface/contract.
        let looks_token = !is_value_type
            && (ty.contains("address")
                || ty.contains("erc20")
                || ty.contains("erc721")
                || ty.contains("token")
                || ty.starts_with("i")); // `IERC20`, `IToken`, ... interface convention.
        if looks_token {
            Some(root.clone())
        } else {
            None
        }
    })
}

/// True if the function explicitly forbids sweeping the protocol's main /
/// underlying token — the documented mitigation for this class. We look for a
/// disequality guard (`token != <core>` / `<core> != token`) against a
/// core-asset-named state variable or local, or a textual "cannot/not sweep"
/// rejection mentioning the core token. Conservative on purpose: a present guard
/// strongly indicates the author already considered this hazard.
fn excludes_main_token(cx: &AnalysisContext, f: &Function, token: &str) -> bool {
    // (1) Structural: a `!=` comparison with one side rooted at the token param
    //     and the other rooted at a core-asset name.
    let mut guarded = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if guarded {
                return;
            }
            if let ExprKind::Binary { op: sluice_ir::BinOp::Ne, lhs, rhs } = &e.kind {
                let l = root_ident(lhs);
                let r = root_ident(rhs);
                let touches_token = l.as_deref() == Some(token) || r.as_deref() == Some(token);
                let touches_core = l.as_deref().map(name_is_core_asset).unwrap_or(false)
                    || r.as_deref().map(name_is_core_asset).unwrap_or(false);
                if touches_token && touches_core {
                    guarded = true;
                }
            }
        });
        if guarded {
            break;
        }
    }
    if guarded {
        return true;
    }

    // (2) Textual fallback: the source plainly rejects sweeping the core token
    //     (covers custom-error reverts and phrasings the structural pass misses).
    let src = cx.source_text(f.span);
    let mentions_core = name_is_core_asset(&src) || src.contains("underlying") || src.contains("reserve");
    let rejects = src.contains("cannot sweep")
        || src.contains("can not sweep")
        || src.contains("not sweep")
        || src.contains("notmaintoken")
        || src.contains("nottoken")
        || src.contains("protected");
    mentions_core && rejects
}

/// A name that denotes the protocol's *core* asset (the token a sweeper must not
/// touch). Matched as a substring so `underlyingToken`, `_asset`, `wantToken`,
/// `coreAsset`, `mainToken`, `stakingToken` etc. all qualify.
fn name_is_core_asset(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "underlying",
        "asset",
        "want",
        "core",
        "main",
        "reserve",
        "principal",
        "stake",
        "deposittoken",
    ]
    .iter()
    .any(|k| l.contains(k))
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Arbitrary-token sweep: `token` is caller-chosen, the contract sweeps its
    // own `balanceOf(address(this))`, and there is NO exclusion of the underlying
    // asset. A double-entry-point token (old TUSD) can be pointed at the second
    // entry point of `underlying` to drain real reserves.
    const VULN: &str = r#"
pragma solidity ^0.8.20;
interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}
contract Vault {
    IERC20 public underlying;
    address public owner;
    function sweep(IERC20 token, address to) external {
        require(msg.sender == owner, "auth");
        uint256 bal = token.balanceOf(address(this));
        token.transfer(to, bal);
    }
}
"#;

    // Same sweeper, but it explicitly excludes the underlying token before
    // reading the balance — the documented mitigation. Must stay silent.
    const SAFE: &str = r#"
pragma solidity ^0.8.20;
interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}
contract Vault {
    IERC20 public underlying;
    address public owner;
    function sweep(IERC20 token, address to) external {
        require(msg.sender == owner, "auth");
        require(address(token) != address(underlying), "cannot sweep underlying");
        uint256 bal = token.balanceOf(address(this));
        token.transfer(to, bal);
    }
}
"#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "double-entry-token"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "double-entry-token"));
    }
}
