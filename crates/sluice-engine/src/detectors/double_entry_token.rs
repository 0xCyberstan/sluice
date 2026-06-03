//! Double-entry-point token hazards — the Compound/Balancer TUSD class.
//!
//! Some ERC-20s are reachable through **two contract addresses** that share the
//! same underlying balance ledger (the canonical example is old TUSD, which had
//! a proxy *and* a legacy `TrueUSD` entry point; a number of Compound/Balancer-
//! listed tokens had the same property). For such a token, both
//! `token.balanceOf(x)` *and* `token.transfer(...)` resolve to the **same**
//! ledger no matter which of the two addresses `token` points at. A contract
//! that treats "the core asset" as a single address — either by sweeping
//! `balanceOf(address(this))` of an arbitrary token, or by *dispatching on*
//! `token == address(coreAsset)` — can be defeated by passing the asset's
//! **second** entry point: the equality / surplus check is fooled while the
//! real reserves move through the alternate address.
//!
//! Two shapes are flagged, both keyed on a caller-chosen `token` parameter (a
//! fixed token — state variable / literal / cast of one — is never in scope):
//!
//! 1. **Arbitrary-token sweep** (TUSD freeze / Balancer advisories): a function
//!    named `sweep`/`skim`/`recover`/`rescue`/`withdrawToken`/`collect` (etc.)
//!    that reads `token.balanceOf(address(this))` for a caller-supplied `token`
//!    and transfers that balance out. Pointing `token` at the second entry point
//!    of the protocol's reserve asset makes `balanceOf` report the real reserves
//!    and the sweep drains them through the alternate address.
//!
//! 2. **Core-asset equality-dispatch withdraw** (Frankencoin `Position.withdraw`
//!    / C4 H-02): a privileged withdraw that takes an arbitrary `token` address,
//!    branches on `token == address(coreAsset)` (collateral / underlying), routes
//!    the *equality* case through the collateralization-checked path, but on the
//!    *mismatch* branch does a raw `IERC20(token).transfer(target, amount)` of a
//!    caller-chosen amount. The `==` treats the asset as exactly one address; a
//!    double-entry collateral lets the owner pass the asset's **other** address,
//!    fall to the raw-transfer branch, and withdraw the underlying collateral
//!    **without** the solvency check — stealing collateral while the debt stays.
//!
//! False positives are suppressed when the function explicitly excludes the
//! protocol's main/underlying token — a `require(token != underlying)` /
//! "cannot sweep the main token" guard — which is exactly the documented
//! mitigation for this class. Confidence is deliberately modest: this is a
//! heuristic over a real but narrow token-integration hazard.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Call, CallKind, Expr, ExprKind, Function};

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
            // Shape 1 — the arbitrary-token `balanceOf` sweep (TUSD/Balancer).
            if let Some(finding) = self.detect_sweep(cx, f) {
                out.push(finding);
                continue;
            }
            // Shape 2 — the core-asset equality-dispatch withdraw (Frankencoin
            // C4 H-02). Only attempted if the sweep shape did not already match,
            // so a function is reported at most once.
            if let Some(finding) = self.detect_dispatch_withdraw(cx, f) {
                out.push(finding);
            }
        }
        out
    }
}

impl DoubleEntryTokenDetector {
    /// Shape 1 — arbitrary-token sweep over `token.balanceOf(address(this))`.
    /// Unchanged in behavior from the original detector; factored into its own
    /// method so the two double-entry shapes are independently readable.
    fn detect_sweep(&self, cx: &AnalysisContext, f: &Function) -> Option<Finding> {
        // The function's role must be a sweep/skim/recover of "other" tokens.
        if !name_is_sweep(&f.name) {
            return None;
        }
        // Quick gate via the effect summary: it must read `balanceOf` and also
        // move tokens out (otherwise there is nothing to sweep).
        let reads_balance_of = f
            .effects
            .call_sites
            .iter()
            .any(|c| c.func_name.as_deref() == Some("balanceOf"));
        if !reads_balance_of || !moves_tokens_out(f) {
            return None;
        }

        // Find a `token.balanceOf(address(this))` whose `token` receiver root is
        // an arbitrary (caller-chosen) token *parameter*. Report at most one
        // finding per function.
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
                // balance is what a double-entry token lets an attacker redirect
                // onto the real reserves. A `balanceOf(user)` read is a different
                // shape and out of scope.
                if !call.args.first().map(arg_is_address_this).unwrap_or(false) {
                    return;
                }
                // The token (call receiver) must be an arbitrary token chosen by
                // the caller: an `address`/`IERC20`-typed *parameter*. A fixed
                // token (state var / literal / cast of one) is not exposed to the
                // second-entry-point trick, so it is skipped.
                let Some(recv) = call.receiver.as_deref() else { return };
                let Some(tok) = token_param_root(f, recv) else { return };
                hit = Some((e.span, tok));
            });
            if hit.is_some() {
                break;
            }
        }
        let (span, token) = hit?;

        // FP suppression: the function explicitly forbids sweeping the protocol's
        // main/underlying token (the documented mitigation).
        if excludes_main_token(cx, f, &token) {
            return None;
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
        Some(cx.finish(b, f.id, span))
    }

    /// Shape 2 — the core-asset **equality-dispatch withdraw** (Frankencoin
    /// `Position.withdraw` / C4 H-02).
    ///
    /// Structural signature (all must hold for the *same* caller-chosen token
    /// parameter `tok`):
    ///   * `tok` is an arbitrary `address`/`IERC20`-typed parameter;
    ///   * the body branches on an **equality** `tok == X` / `X == tok` where `X`
    ///     (cast-peeled root) is a `collateral`/`underlying`-named **state
    ///     variable** of the contract — the dispatch that assumes the asset is
    ///     exactly one address;
    ///   * the body performs a raw `IERC20(tok).transfer/safeTransfer/
    ///     transferFrom(...)` whose receiver root is that same `tok` (the
    ///     attacker-chosen second entry point flows straight into the transfer).
    ///
    /// This is name-agnostic on purpose: the real bug is a plain `withdraw`, so
    /// the *structure* (arbitrary token + core-asset `==` dispatch + raw transfer
    /// of that token) is the gate, not a sweep-style name. A rescue/withdraw that
    /// has no core-asset equality dispatch (a generic "pull any ERC20 out") is not
    /// flagged here — without the single-address `==` assumption there is nothing
    /// for the second entry point to defeat.
    fn detect_dispatch_withdraw(&self, cx: &AnalysisContext, f: &Function) -> Option<Finding> {
        // The function must actually move tokens out — otherwise there is no
        // withdrawal to subvert.
        if !moves_tokens_out(f) {
            return None;
        }

        // (1) A `tok == coreAsset` / `coreAsset == tok` equality where `tok` is an
        //     arbitrary token parameter and `coreAsset` is a core-asset-named
        //     *state variable* of the owning contract. Capture that token name.
        let token = find_core_asset_equality_token(cx, f)?;

        // (2) A raw outbound transfer whose receiver root is that same `tok`:
        //     `IERC20(tok).transfer(...)` / `tok.safeTransfer(...)` / a
        //     `transferFrom` pulling via `tok`. The caller-chosen address (the
        //     second entry point) is what the tokens move through.
        let span = first_transfer_via_token(f, &token)?;

        // FP suppression: an explicit `token != underlying`-style exclusion (the
        // documented mitigation). The vulnerable `==` dispatch is NOT an
        // exclusion — `excludes_main_token` only honors `!=` / textual rejections —
        // so Frankencoin's `token == address(collateral)` does not suppress here.
        if excludes_main_token(cx, f, &token) {
            return None;
        }

        let b = FindingBuilder::new(self.id(), Category::DoubleEntryToken)
            .title(
                "Core-asset equality-dispatch withdraw bypassed by a double-entry-point token",
            )
            .severity(Severity::Medium)
            // Honest: privileged, and contingent on the *deployed* core asset
            // actually having a second entry point — same calibration as the sweep.
            .confidence(0.45)
            // Value-flow: a caller-chosen token address selects the withdraw path
            // and is the receiver the funds move through.
            .dimension(Dimension::ValueFlow)
            .message(format!(
                "`{}` dispatches on `{token} == address(<coreAsset>)`: the equality case is routed through \
                 the collateralization/solvency-checked path, but the mismatch branch performs a raw \
                 `IERC20({token}).transfer(...)` of a caller-chosen amount. A double-entry-point token \
                 (one ERC-20 ledger reachable through two addresses, e.g. legacy TUSD) lets a caller pass \
                 the core asset's *second* address as `{token}`: the `==` check sees a different address and \
                 falls to the raw-transfer branch, so the underlying collateral is withdrawn through the \
                 alternate entry point WITHOUT the collateralization check — the position keeps its debt \
                 while its backing is drained. This is the Frankencoin Position.withdraw (C4 H-02) shape.",
                f.name
            ))
            .recommendation(
                "Do not decide \"is this the core asset?\" by a single-address equality. A double-entry \
                 token defeats `token == address(collateral)`. Either maintain an allowlist of withdrawable \
                 tokens that excludes every known entry point of the collateral, route ALL collateral-asset \
                 withdrawals (by ledger identity, not address) through the collateralization check, or re-run \
                 the solvency check after any token transfer out of the position.",
            );
        Some(cx.finish(b, f.id, span))
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

/// Find a `tok == coreAsset` / `coreAsset == tok` **equality** in `f` where one
/// side's (cast-peeled) root is a caller-chosen token *parameter* and the other
/// side's root is a **core-asset-named state variable** of the owning contract
/// (`collateral`, `underlying`, `asset`, ...). Returns the token parameter name.
///
/// This is the structural tell of shape 2: the function decides "is this the
/// core asset?" by a single-address equality — exactly the assumption a
/// double-entry-point token defeats. Requiring the compared name to be an actual
/// *state variable* (not just any local) keeps an arbitrary `if (a == b)` from
/// tripping the detector.
fn find_core_asset_equality_token(cx: &AnalysisContext, f: &Function) -> Option<String> {
    let contract = cx.contract_of(f.id);
    let mut found: Option<String> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            let ExprKind::Binary { op: sluice_ir::BinOp::Eq, lhs, rhs } = &e.kind else { return };
            // One side a token param, the other a core-asset state variable.
            let l = root_ident(lhs);
            let r = root_ident(rhs);
            let l_tok = l.as_deref().and_then(|n| token_param_root(f, lhs).map(|_| n.to_string()));
            let r_tok = r.as_deref().and_then(|n| token_param_root(f, rhs).map(|_| n.to_string()));
            let l_core = l.as_deref().is_some_and(|n| is_core_asset_state_var(contract, n));
            let r_core = r.as_deref().is_some_and(|n| is_core_asset_state_var(contract, n));
            if let (Some(tok), true) = (l_tok.clone(), r_core) {
                found = Some(tok);
            } else if let (Some(tok), true) = (r_tok, l_core) {
                found = Some(tok);
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// Is `name` a core-asset-named **state variable** of `contract`? Combines the
/// core-asset name heuristic with a real state-var lookup, so only a genuine
/// tracked-asset field (any mutability — `collateral` is typically `immutable`)
/// qualifies. `None` contract ⇒ false.
fn is_core_asset_state_var(contract: Option<&sluice_ir::Contract>, name: &str) -> bool {
    name_is_core_asset(name) && contract.is_some_and(|c| c.state_vars.iter().any(|v| v.name == name))
}

/// Span of the first raw outbound token transfer in `f` whose receiver root is
/// the caller-chosen token parameter `token` — `IERC20(token).transfer(...)`,
/// `token.safeTransfer(...)`, or a `token.transferFrom(...)`. This is the sink
/// the attacker-chosen second entry point flows through.
fn first_transfer_via_token(f: &Function, token: &str) -> Option<sluice_ir::Span> {
    let mut hit: Option<sluice_ir::Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Call(call) = &e.kind else { return };
            let is_transfer = matches!(
                call.func_name.as_deref(),
                Some("transfer") | Some("safeTransfer") | Some("transferFrom") | Some("safeTransferFrom")
            );
            if !is_transfer {
                return;
            }
            let Some(recv) = call.receiver.as_deref() else { return };
            if receiver_root_through_wrappers(recv).as_deref() == Some(token) {
                hit = Some(e.span);
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Resolve the root identifier of a *call receiver*, peeling not only
/// [`CallKind::TypeCast`] casts (`address(x)`) but also the **interface-wrapper
/// idiom** `IERC20(x)` / `IToken(x)` even when the parser classified it as a
/// plain call (`CallKind::Internal`) rather than a cast.
///
/// This matters because `IERC20(token)` resolves to a `TypeCast` when `IERC20` is
/// declared in the same file, but to an `Internal` call when `IERC20` is an
/// *imported* interface (which is the Frankencoin layout). In both cases it is the
/// same wrapper and the receiver's identity is its single argument. We only peel a
/// single-argument call whose callee is a bare **type-name-like identifier** (an
/// uppercase-led `IERC20`/`ERC20`/`IToken` …), so an ordinary lowercase internal
/// helper (`foo(x).bar()`) is never mistaken for a wrapper.
fn receiver_root_through_wrappers(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => {
            receiver_root_through_wrappers(base)
        }
        ExprKind::Call(c) if c.args.len() == 1 && is_type_wrapper_callee(c) => {
            receiver_root_through_wrappers(&c.args[0])
        }
        _ => None,
    }
}

/// Is call `c` a type/interface wrapper such as `address(_)`, `payable(_)`,
/// `IERC20(_)`, `ERC20(_)` — i.e. a [`CallKind::TypeCast`], or a single-arg call
/// whose callee is a bare identifier that reads like a type name (uppercase-led)?
fn is_type_wrapper_callee(c: &Call) -> bool {
    if c.kind == CallKind::TypeCast {
        return true;
    }
    // A bare-identifier callee that looks like a type/interface name. The IR keeps
    // the resolved method name in `func_name` for member calls; for a wrapper the
    // callee is the type identifier itself.
    let name = match &c.callee.kind {
        ExprKind::Ident(n) => Some(n.as_str()),
        _ => c.func_name.as_deref(),
    };
    name.is_some_and(|n| n.chars().next().is_some_and(|ch| ch.is_ascii_uppercase()))
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
/// touch, and the asset an equality-dispatch withdraw assumes is one address).
/// Matched as a substring so `underlyingToken`, `_asset`, `wantToken`,
/// `coreAsset`, `mainToken`, `stakingToken`, `collateralToken` etc. all qualify.
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
        "collateral",
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

    // ---------------- shape 2: core-asset equality-dispatch withdraw ----------------

    // The Frankencoin `Position.withdraw` (C4 H-02) shape, minimized: a privileged
    // withdraw takes an arbitrary `token`, routes `token == address(collateral)`
    // through the collateralization-checked path, but sends ANY other token via a
    // raw `IERC20(token).transfer(...)` of a caller-chosen amount. A double-entry
    // collateral lets the owner pass its second address, dodge the `==`, and drain
    // the collateral through the raw-transfer branch without the solvency check.
    const DISPATCH_VULN: &str = r#"
pragma solidity ^0.8.20;
interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}
contract Position {
    IERC20 public immutable collateral;
    uint256 public minted;
    uint256 public price;
    address public owner;
    constructor(address c) { collateral = IERC20(c); owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function checkCollateral(uint256 bal) internal view {
        require(bal * price >= minted, "InsufficientCollateral");
    }
    function withdrawCollateral(address target, uint256 amount) public onlyOwner {
        collateral.transfer(target, amount);
        checkCollateral(collateral.balanceOf(address(this)));
    }
    function withdraw(address token, address target, uint256 amount) external onlyOwner {
        if (token == address(collateral)) {
            withdrawCollateral(target, amount);
        } else {
            IERC20(token).transfer(target, amount);
        }
    }
}
"#;

    // Mitigated dispatch withdraw: the same withdraw, but it explicitly rejects the
    // core asset with a `!=` exclusion before transferring. The documented
    // mitigation — must stay silent. (Still imperfect against a *second* entry
    // point in reality, but a present exclusion means the author considered the
    // hazard, which is exactly the suppression contract this detector honors.)
    const DISPATCH_SAFE_EXCLUSION: &str = r#"
pragma solidity ^0.8.20;
interface IERC20 {
    function transfer(address, uint256) external returns (bool);
}
contract Position {
    IERC20 public immutable collateral;
    address public owner;
    constructor(address c) { collateral = IERC20(c); owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function withdrawToken(address token, address target, uint256 amount) external onlyOwner {
        require(token != address(collateral), "cannot withdraw collateral");
        IERC20(token).transfer(target, amount);
    }
}
"#;

    // Single-collateral withdraw: NO arbitrary-token parameter and NO core-asset
    // equality dispatch — it withdraws the one fixed `collateral` state var,
    // guarded by the solvency check. There is no second-address assumption for a
    // double-entry token to defeat, so the detector must stay silent.
    const SINGLE_COLLATERAL_SAFE: &str = r#"
pragma solidity ^0.8.20;
interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}
contract Position {
    IERC20 public immutable collateral;
    uint256 public minted;
    uint256 public price;
    address public owner;
    constructor(address c) { collateral = IERC20(c); owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function withdrawCollateral(address target, uint256 amount) public onlyOwner {
        collateral.transfer(target, amount);
        require(collateral.balanceOf(address(this)) * price >= minted, "InsufficientCollateral");
    }
}
"#;

    // Generic arbitrary-token rescue with NO core-asset equality dispatch: pulls
    // any caller-named ERC20 out, but never compares `token` against a tracked
    // core asset. Without the single-address `==` assumption there is nothing for
    // a second entry point to defeat, so shape 2 must NOT fire. (Its name is not a
    // sweep keyword either, so shape 1 stays silent too — this guards against the
    // dispatch path degenerating into "any arbitrary-token transfer".)
    const GENERIC_RESCUE_SILENT: &str = r#"
pragma solidity ^0.8.20;
interface IERC20 {
    function transfer(address, uint256) external returns (bool);
}
contract Treasury {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function withdrawToTreasury(address token, address target, uint256 amount) external onlyOwner {
        IERC20(token).transfer(target, amount);
    }
}
"#;

    #[test]
    fn fires_on_dispatch_withdraw() {
        let fs = run(DISPATCH_VULN);
        let hit = fs.iter().find(|f| f.detector == "double-entry-token");
        assert!(hit.is_some(), "expected double-entry-token on dispatch withdraw: {fs:?}");
        // It must be reported at the function `withdraw` (the dispatch site), not
        // the inner `withdrawCollateral`.
        assert_eq!(hit.unwrap().function, "withdraw", "{:?}", hit);
    }

    #[test]
    fn silent_on_dispatch_exclusion() {
        let fs = run(DISPATCH_SAFE_EXCLUSION);
        assert!(!fs.iter().any(|f| f.detector == "double-entry-token"), "{fs:?}");
    }

    #[test]
    fn silent_on_single_collateral_withdraw() {
        let fs = run(SINGLE_COLLATERAL_SAFE);
        assert!(!fs.iter().any(|f| f.detector == "double-entry-token"), "{fs:?}");
    }

    #[test]
    fn silent_on_generic_rescue_without_core_dispatch() {
        let fs = run(GENERIC_RESCUE_SILENT);
        assert!(!fs.iter().any(|f| f.detector == "double-entry-token"), "{fs:?}");
    }

    // Recall lock on the real Frankencoin source, when the benchmark checkout is
    // present. `Position.withdraw` MUST fire shape 2. Skipped (not failed) if the
    // file is absent, mirroring the AA-corpus recognizer tests.
    #[test]
    fn fires_on_real_frankencoin_position() {
        let path = "/home/stan/Data/bench/2023-04-frankencoin/contracts/Position.sol";
        let Ok(src) = std::fs::read_to_string(path) else {
            eprintln!("Frankencoin checkout absent — skipping real-source recall lock");
            return;
        };
        let fs = analyze_sources(vec![(path.into(), src)], &Config::default()).findings;
        let hit = fs
            .iter()
            .find(|f| f.detector == "double-entry-token" && f.function == "withdraw");
        assert!(
            hit.is_some(),
            "Position.withdraw must fire double-entry-token (C4 H-02); findings: {:?}",
            fs.iter().map(|f| (&f.detector, &f.function)).collect::<Vec<_>>()
        );
    }
}
