//! Vesting-buffered share price that a raw token donation can jump, read by an
//! external rate consumer — the Ethena `StakedUSDe.totalAssets` /
//! `EthenaBalancerRateProvider.getRate` class.
//!
//! ## The shape
//!
//! An ERC4626-style vault prices itself with
//!
//! ```solidity
//! function totalAssets() public view returns (uint256) {
//!     return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();
//! }
//! function getUnvestedAmount() public view returns (uint256) {
//!     uint256 dt = block.timestamp - lastDistributionTimestamp;
//!     if (dt >= VESTING_PERIOD) return 0;
//!     return ((VESTING_PERIOD - dt) * vestingAmount) / VESTING_PERIOD;   // time-decaying
//! }
//! ```
//!
//! and a *second* contract republishes that as a price feed:
//!
//! ```solidity
//! function getRate() external view returns (uint256) {     // EthenaBalancerRateProvider
//!     return stakedUSDe.totalAssets() * 1 ether / stakedUSDe.totalSupply();
//! }
//! ```
//!
//! Two facts collide. (1) The minuend of `totalAssets` is the contract's **raw
//! token balance** `balanceOf(address(this))`, which **anyone can bump** by sending
//! the asset straight to the vault with a plain `transfer` — there is no `sync()`
//! that re-derives an internal reserve, so a donation lands in the priced balance
//! immediately. (2) The subtrahend `getUnvestedAmount()` is a **time-decaying
//! vesting buffer**: it is `(VESTING_PERIOD - elapsed) * vestingAmount /
//! VESTING_PERIOD`, and `vestingAmount` is mutated **only** inside the role-gated
//! reward drip (`transferInRewards` → `_updateVestingAmount`). A donation increases
//! `balanceOf(this)` *without* increasing `vestingAmount`, so it is **not buffered**
//! — the whole donation is recognized into `totalAssets` **atomically**, and the
//! published `getRate` jumps in a single block. The drip path was designed so new
//! rewards vest in over `VESTING_PERIOD` (no instantaneous price move a flash-loan
//! could exploit), but the raw-balance read leaves an unbuffered side door: anyone
//! can hand the contract assets and force the exact atomic re-price the vesting
//! buffer exists to prevent — moving every downstream consumer of `getRate`.
//!
//! ## Why it is a finding (the two REQUIRED structural anchors + one booster)
//!
//! The bug is the donation-jumpable share price itself, so the fingerprint is the
//! `balanceOf(this) - decaying-buffer` subtraction over a drip-gated var. An
//! external rate publisher makes the blast radius bigger but is **not** required —
//! the vault's own ERC4626 redemption math (`convertToAssets`/`previewRedeem`)
//! already reads the jumpable price.
//!
//!   * **(required) The price view** is a `view`/`pure` function whose body contains
//!     a `balanceOf(address(this)) - G()` **subtraction** where:
//!       - the **minuend** is an external `balanceOf` call whose argument resolves to
//!         `this` / `address(this)` (the donation-bumpable raw balance), and
//!       - the **subtrahend** `G` is a **time-decaying vesting term**: an internal
//!         view that reads `block.timestamp` *and* scales a **settable** state
//!         variable (`vestingAmount`) by a Mul/Div (the linear-decay arithmetic);
//!   * **(required) the vesting var is drip-gated** — every function that writes it is
//!     either access-controlled or an internal helper whose callers are all
//!     access-controlled (mutated only in the privileged reward drip, never by a
//!     public path). This is the asymmetry that makes a donation bypass the buffer;
//!   * **(booster → High) an external rate consumer** — some function (typically in a
//!     *separate* contract) publishes `… * UNIT / totalSupply()` as a rate,
//!     referencing `totalAssets`/the priced contract and `totalSupply` in a
//!     `Mul`-over-`Div`. When such a publisher is in scope the finding is raised from
//!     Medium to High and the consumer is named; when it is not (e.g. a single-file
//!     scan of the vault, where the rate provider lives in another file) the core
//!     donation-jumpable price still fires at Medium.
//!
//! ## Suppression
//!
//!   * **Donations are `sync()`-gated** — the contract exposes a `sync`/`skim`-style
//!     resync, or the price view reads a *stored reserve* rather than the raw
//!     `balanceOf(this)`. If the minuend is not a raw `balanceOf(this)` the
//!     structural anchor simply does not match (a synced reserve cannot be bumped by
//!     a bare transfer), and an explicit `sync`/`skim` resync also suppresses.
//!   * **The vesting var is publicly bumpable** — if any non-access-controlled public
//!     path writes the vesting var, the donation asymmetry is gone (anyone can move
//!     the buffer too), so this is a different design and stays silent.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Call, Contract, Expr, ExprKind, Function, Span, StmtKind};

use super::prelude::*;

pub struct VestingBufferedDonationDetector;

impl Detector for VestingBufferedDonationDetector {
    fn id(&self) -> &'static str {
        "vesting-buffered-donation"
    }
    fn category(&self) -> Category {
        Category::VestingBufferedDonation
    }
    fn description(&self) -> &'static str {
        "A share-price view returns balanceOf(this) minus a time-decaying vesting term whose state var is mutated only by a role-gated drip, so a raw token donation atomically jumps a price republished by an external rate consumer (Ethena StakedUSDe.totalAssets / EthenaBalancerRateProvider.getRate class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.functions() {
            // The price view is a read-only accessor with a body.
            if !f.has_body || !f.is_view_or_pure() {
                continue;
            }
            let Some(contract) = cx.contract_of(f.id) else { continue };
            // Interfaces declare no body to price from.
            if contract.is_interface() {
                continue;
            }

            // (1) Find a `balanceOf(this) - G()` subtraction in the body, where the
            //     minuend is the raw self-balance and G is a time-decaying vesting
            //     term over a settable state var.
            let Some(hit) = find_vesting_subtraction(cx, f, contract) else { continue };

            // (2) The vesting var must be drip-gated: mutated only by a role-gated
            //     path (otherwise a donation is not asymmetric — anyone could bump
            //     the buffer too, which is a different design).
            if !vesting_var_is_drip_gated(cx, contract, &hit.vesting_var) {
                continue;
            }

            // SUPPRESS: the contract resyncs donations via a `sync()`/`skim()` — then
            // a bare transfer does not land in the priced balance unbuffered.
            if contract_has_sync_resync(cx, contract) {
                continue;
            }

            // (3) An external rate consumer that republishes a `… * UNIT / totalSupply()`
            //     price tied to this priced contract is a CONFIDENCE BOOSTER, not a hard
            //     gate. The donation-jumpable `balanceOf(this) - decaying-buffer` share
            //     price (anchors 1 + 2) is itself the bug: the gradual-vesting defense is
            //     bypassed and every reader of the share price — the vault's own ERC4626
            //     `convertToAssets` / `previewRedeem` redemption math, or an external rate
            //     provider — sees an atomic re-price. Requiring the publisher to live in
            //     the SAME scan was an overfit: the rate provider is a separate contract
            //     in a separate file (Ethena's `EthenaBalancerRateProvider`), so a
            //     single-file or partial scan of the vault saw no consumer and went
            //     silent (the regression). When a consumer IS in scope we raise to High
            //     and name it; otherwise we still fire at Medium on the structural shape.
            let consumer = find_rate_consumer(cx, contract, f);

            // High when a downstream rate publisher is visible (the full Ethena
            // StakedUSDe + EthenaBalancerRateProvider chain); Medium for the core
            // donation-jumpable vesting-buffered share price on its own (the Ethena
            // finding itself shipped as a Medium).
            let (severity, confidence) = if consumer.is_some() {
                (Severity::High, 0.8)
            } else {
                (Severity::Medium, 0.6)
            };

            // A trailing clause that names the external consumer when one is visible, or
            // points at the in-contract / separate-file price readers when it is not.
            let consumer_clause = match &consumer {
                Some((cn, fnm)) => format!(
                    " The price `{cn}.{fnm}` republishes as `... * UNIT / totalSupply()` jumps in a single \
                     block, so every consumer of that rate (here a Balancer rate provider) can be moved by an \
                     unprivileged transfer.",
                ),
                None => String::from(
                    " Any reader of this share price — the vault's own ERC4626 `convertToAssets`/`previewRedeem` \
                     redemption math, or an external rate provider that republishes `... * UNIT / totalSupply()` \
                     (Ethena ships this as a separate `EthenaBalancerRateProvider`) — is moved by an unprivileged \
                     transfer in a single block.",
                ),
            };

            let b = report!(self, Category::VestingBufferedDonation,
                title = "Vesting-buffered share price can be jumped atomically by a raw token donation",
                severity = severity,
                // Structural fingerprint: a `view` returns `balanceOf(address(this)) -
                // <time-decaying vesting term>` whose subtrahend scales a SETTABLE state
                // var mutated ONLY by a role-gated drip — with the sync()-gated and
                // public-drip suppressions. An external `*UNIT/totalSupply()` rate
                // publisher, when visible, lifts this to a High.
                confidence = confidence,
                dimensions = [Dimension::ValueFlow, Dimension::Invariant],
                message = format!(
                    "`{cn}.{fname}` prices the vault as `{bal} - {sub}`: the minuend is the contract's RAW \
                     token balance (`balanceOf(address(this))`), which anyone can increase by sending the asset \
                     with a plain `transfer`, while the subtrahend `{sub}` is a TIME-DECAYING vesting buffer \
                     (`block.timestamp`-elapsed × the settable `{vv}`) that is mutated ONLY inside the role-gated \
                     reward drip. A donation raises `balanceOf(this)` without raising `{vv}`, so it is NOT \
                     buffered — the entire donation is recognized into `{fname}` ATOMICALLY, bypassing the \
                     vesting drip's gradual-recognition defense.{consumer_clause} This is the Ethena \
                     `StakedUSDe.totalAssets` / `EthenaBalancerRateProvider.getRate` class.",
                    cn = contract.name,
                    fname = f.name,
                    bal = hit.minuend_text,
                    sub = hit.subtrahend_text,
                    vv = hit.vesting_var,
                    consumer_clause = consumer_clause,
                ),
                recommendation =
                    "Do not price from the raw `balanceOf(address(this))`. Track an internal `totalReserves` \
                     accounting variable that only the deposit / role-gated reward paths update, so an \
                     unsolicited transfer cannot enter the priced balance, and add a `sync()`/`skim()` that \
                     re-derives it deliberately. Equivalently, also buffer donated balance through the same \
                     vesting accumulator (credit any `balanceOf(this) - lastReserves` surplus into \
                     `vestingAmount` so it vests in over `VESTING_PERIOD` like the drip), and have downstream \
                     rate providers consume a smoothed / TWAP price rather than the instantaneous \
                     `totalAssets * UNIT / totalSupply`.",
            );
            out.push(finish_at(cx, b, f.id, hit.span));
        }

        out
    }
}

// ------------------------------------------------------------------- match data

/// A matched `balanceOf(this) - vestingTerm()` subtraction in a price view.
struct VestingSub {
    /// Span of the subtraction (the report location).
    span: Span,
    /// Source text of the minuend (`IERC20(asset()).balanceOf(address(this))`).
    minuend_text: String,
    /// Source text of the subtrahend (`getUnvestedAmount()`).
    subtrahend_text: String,
    /// The settable state var the vesting term decays (`vestingAmount`).
    vesting_var: String,
}

// ----------------------------------------------------------- (1) the subtraction

/// Scan `f`'s body for a `Binary(Sub)` whose minuend is a raw `balanceOf(this)`
/// read and whose subtrahend resolves to a time-decaying vesting term over a
/// settable state var of `contract`. Returns the first such match.
fn find_vesting_subtraction(cx: &AnalysisContext, f: &Function, contract: &Contract) -> Option<VestingSub> {
    let mut hit: Option<VestingSub> = None;
    for st in &f.body {
        st.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Binary { op: BinOp::Sub, lhs, rhs } = &e.kind else { return };
            // Minuend: raw self-balance `balanceOf(address(this))`.
            if !is_self_balance_of(lhs) {
                return;
            }
            // Subtrahend: a time-decaying vesting term over a settable state var.
            let Some(vesting_var) = vesting_term_var(cx, f, contract, rhs) else { return };
            hit = Some(VestingSub {
                span: e.span,
                minuend_text: trimmed_text(cx, lhs.span, 80),
                subtrahend_text: trimmed_text(cx, rhs.span, 60),
                vesting_var,
            });
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Is `e` a `balanceOf(...)` external call whose (single) argument resolves to
/// `this` / `address(this)` — the contract's own raw token balance? This is the
/// donation-bumpable read. We accept the call appearing as the receiver-method
/// `IERC20(asset()).balanceOf(address(this))` or a bare `token.balanceOf(this)`.
fn is_self_balance_of(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        let ExprKind::Call(c) = &sub.kind else { return };
        if !is_balance_of_call(c) {
            return;
        }
        // The first positional arg must be `this` / `address(this)`.
        if c.args.first().is_some_and(arg_is_this) {
            found = true;
        }
    });
    found
}

/// `c` is a `balanceOf(...)` call (the ERC20 self-balance read). We key on the
/// resolved method name; the receiver is the asset token (`IERC20(asset())`), an
/// external handle, but a `balanceOf` with a `this` argument is unambiguous.
fn is_balance_of_call(c: &Call) -> bool {
    c.func_name.as_deref() == Some("balanceOf")
}

/// After peeling casts, is `e` the `this` keyword (so `address(this)` / `this`)?
fn arg_is_this(e: &Expr) -> bool {
    matches!(&peel_casts(e).kind, ExprKind::Ident(n) if n == "this")
}

/// If `sub` is the **subtrahend** of the price subtraction, return the settable
/// state var of `contract` that its time-decaying vesting term scales — or `None`.
///
/// Two forms are accepted:
///   * an **internal call** `getUnvestedAmount()` to a same-contract view that is
///     itself a time-decaying vesting term (the Ethena shape — resolve the callee
///     and test its body); or
///   * an **inline** time-decaying expression in this very `sub` (some vaults
///     inline the buffer): the expression mentions `block.timestamp` and scales a
///     settable state var by a Mul/Div.
fn vesting_term_var(cx: &AnalysisContext, f: &Function, contract: &Contract, sub: &Expr) -> Option<String> {
    // Form A: internal call to a vesting view.
    if let ExprKind::Call(c) = &peel_casts(sub).kind {
        if c.kind == sluice_ir::CallKind::Internal {
            if let Some(name) = c.func_name.as_deref().or_else(|| c.callee.simple_name()) {
                if let Some(callee) = same_contract_fn(cx, contract, name) {
                    if let Some(v) = decaying_vesting_var_of(cx, callee, contract) {
                        return Some(v);
                    }
                }
            }
        }
    }
    // Form B: the subtrahend is itself an inline decaying term.
    inline_decaying_var(f, contract, sub)
}

/// A same-contract (or inherited) function with the given name, if resolvable.
fn same_contract_fn<'a>(cx: &'a AnalysisContext, contract: &Contract, name: &str) -> Option<&'a Function> {
    // Prefer a function declared directly in this contract.
    for fid in &contract.functions {
        if let Some(g) = cx.scir.function(*fid) {
            if g.name == name {
                return Some(g);
            }
        }
    }
    // Fall back to any function of that name in an inherited base.
    cx.scir
        .all_functions()
        .find(|g| g.name == name && contract.bases.iter().any(|b| base_matches(cx, b, g.contract)))
}

/// Does base name `b` resolve to the contract that declares `g`'s function?
fn base_matches(cx: &AnalysisContext, b: &str, cid: sluice_ir::ContractId) -> bool {
    cx.scir.contract(cid).is_some_and(|c| c.name == b)
}

/// Is `g` a **time-decaying vesting view** — it reads `block.timestamp` *and*
/// scales a settable state var of `contract` by a Mul/Div? Returns the var.
fn decaying_vesting_var_of(cx: &AnalysisContext, g: &Function, contract: &Contract) -> Option<String> {
    if !g.has_body || !g.is_view_or_pure() {
        return None;
    }
    // Must read block.timestamp / block.number (the elapsed-time decay).
    if !reads_block_time(cx, g) {
        return None;
    }
    // Find a settable state var that is multiplied/divided somewhere in g's body.
    settable_var_in_muldiv(g, contract)
}

/// Is the subtrahend `sub` itself an inline decaying term: it mentions
/// `block.timestamp` and a settable state var of `contract` (not a parameter of
/// the price view `f`) participates in a Mul/Div inside it?
fn inline_decaying_var(f: &Function, contract: &Contract, sub: &Expr) -> Option<String> {
    if !expr_reads_block_time(sub) {
        return None;
    }
    settable_var_in_muldiv_subtree(f, contract, sub)
}

/// Scan every statement of `g`'s body for a `Mul`/`Div` one of whose operands
/// roots to a **settable** state var of `contract` (and is not a parameter of
/// `g`). Returns that var's name — the time-decay-scaled vesting amount.
fn settable_var_in_muldiv(g: &Function, contract: &Contract) -> Option<String> {
    let mut found: Option<String> = None;
    for st in &g.body {
        st.visit_exprs(&mut |e| {
            if found.is_none() {
                found = settable_var_in_muldiv_subtree(g, contract, e);
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// Within the expression subtree `e`, find a `Mul`/`Div` whose left or right
/// operand roots to a settable state var of `contract` that is not a parameter of
/// `f`. Used by both the resolved-callee (Form A) and inline (Form B) matches.
fn settable_var_in_muldiv_subtree(f: &Function, contract: &Contract, e: &Expr) -> Option<String> {
    let mut found: Option<String> = None;
    e.visit(&mut |sub| {
        if found.is_some() {
            return;
        }
        if let ExprKind::Binary { op: BinOp::Mul | BinOp::Div, lhs, rhs } = &sub.kind {
            for side in [lhs, rhs] {
                if let Some(root) = root_ident_peeled(side) {
                    if !is_param(f, &root) && is_settable_state_var(contract, &root) {
                        found = Some(root);
                        break;
                    }
                }
            }
        }
    });
    found
}

// --------------------------------------------------- (2) drip-gated vesting var

/// Is `var` mutated **only** by a role-gated path? Every function of `contract`
/// that writes `var` must be either access-controlled, or an internal/private
/// helper whose externally-reachable callers are all access-controlled. A single
/// public, non-access-controlled writer means the buffer is bumpable by anyone (a
/// different design) and disqualifies the asymmetry — so we return false.
fn vesting_var_is_drip_gated(cx: &AnalysisContext, contract: &Contract, var: &str) -> bool {
    let mut saw_writer = false;
    for fid in &contract.functions {
        let Some(w) = cx.scir.function(*fid) else { continue };
        if !w.effects.writes_var(var) {
            continue;
        }
        saw_writer = true;
        if !writer_is_gated(cx, w) {
            return false;
        }
    }
    saw_writer
}

/// A single writer is "gated" if it is itself access-controlled, or it is an
/// internal/private helper all of whose externally-reachable callers are
/// access-controlled. (A constructor write is fine — one-time init.)
fn writer_is_gated(cx: &AnalysisContext, w: &Function) -> bool {
    if w.is_constructor() {
        return true;
    }
    if cx.has_access_control(w) {
        return true;
    }
    // Externally reachable AND not access-controlled → public bump path → not gated.
    if w.is_externally_reachable() {
        return false;
    }
    // Internal/private helper: require it to actually have callers, and every
    // externally-reachable caller to be access-controlled. (Internal callers are
    // checked one level — sufficient for the helper-behind-drip shape; an internal
    // caller with no access control that is itself only reached from gated entries
    // is conservatively treated as gated via its own external reachability check.)
    if w.callers.is_empty() {
        // An internal helper nobody calls cannot bump the buffer from outside.
        return true;
    }
    w.callers.iter().all(|cid| match cx.scir.function(*cid) {
        Some(caller) => !caller.is_externally_reachable() || cx.has_access_control(caller),
        None => true,
    })
}

// ------------------------------------------------------ sync()-gating suppression

/// Does `contract` deliberately resync donations — exposing a `sync`/`skim`-style
/// function (the Uniswap-style reserve resync)? If so, a bare transfer is reconciled
/// rather than silently entering the priced balance, so this is not the bug.
fn contract_has_sync_resync(cx: &AnalysisContext, contract: &Contract) -> bool {
    contract.functions.iter().any(|fid| {
        cx.scir.function(*fid).is_some_and(|g| {
            let l = g.name.to_ascii_lowercase();
            // `sync` / `skim` (reserve resync) — but not unrelated names that merely
            // contain the substring (`asyncFoo`): require the name to *be* or *start
            // with* the resync verb.
            (l == "sync" || l == "skim" || l.starts_with("sync") || l.starts_with("skim"))
                && g.is_externally_reachable()
        })
    })
}

// ----------------------------------------------------- (3) external rate consumer

/// Find an external rate consumer that republishes a `… * UNIT / totalSupply()`
/// price tied to the priced contract `priced` (whose view is `price_fn`). Returns
/// `(contract_name, function_name)` of the consumer.
///
/// The consumer is any function — typically in a *separate* contract (a Balancer /
/// Curve rate provider) — that:
///   * returns a `Div` whose numerator contains a `Mul` (the `value * UNIT / supply`
///     shape), and
///   * textually references `totalSupply` AND (`totalAssets` or the priced
///     contract's name), so it is bound to *this* priced contract's price.
fn find_rate_consumer(cx: &AnalysisContext, priced: &Contract, price_fn: &Function) -> Option<(String, String)> {
    let priced_name = priced.name.to_ascii_lowercase();
    let price_fn_name = price_fn.name.to_ascii_lowercase();
    for g in cx.functions() {
        if !g.has_body || !g.is_view_or_pure() {
            continue;
        }
        // Structural: a `Mul`-over-`Div` in a return (the rate computation).
        if !returns_muldiv_rate(g) {
            continue;
        }
        // Textual binding to this priced contract's price surface.
        let text = cx.source_text(g.span);
        let mentions_supply = text.contains("totalsupply");
        // Tie to the priced contract: it calls the priced view (`totalAssets`-style
        // `price_fn`) or names the priced contract. This keeps the consumer bound to
        // the contract we flagged rather than any unrelated `x*UNIT/supply` math.
        let mentions_priced = text.contains(&price_fn_name) || references_contract(cx, g, priced) || text.contains(&priced_name);
        if mentions_supply && mentions_priced {
            let (cn, fnm) = cx.names(g.id);
            // The rate provider is usually a *different* contract; allow same-contract
            // too (a vault may publish its own pricePerShare).
            return Some((cn, fnm));
        }
    }
    let _ = price_fn_name;
    None
}

/// Does any call site / cast in `g` reference the priced contract by name (an
/// `IPriced(x).` handle, a `StakedUSDeV2 public stakedUSDe` typed state var)?
fn references_contract(cx: &AnalysisContext, g: &Function, priced: &Contract) -> bool {
    // A typed state var of the consumer contract whose type names the priced
    // contract (`StakedUSDeV2 public immutable stakedUSDe`).
    if let Some(consumer) = cx.contract_of(g.id) {
        if consumer.state_vars.iter().any(|v| v.ty.trim() == priced.name || v.ty.contains(&priced.name)) {
            return true;
        }
    }
    false
}

/// Does `g` return a `Div` whose numerator subtree contains a `Mul` — the
/// `value * UNIT / divisor` rate shape?
fn returns_muldiv_rate(g: &Function) -> bool {
    let mut found = false;
    for st in &g.body {
        st.visit(&mut |s| {
            if found {
                return;
            }
            if let StmtKind::Return(Some(e)) = &s.kind {
                if expr_is_muldiv_rate(e) {
                    found = true;
                }
            }
        });
        if found {
            break;
        }
    }
    found
}

/// `e` (or a sub-expression of a return) is a `Div` whose numerator (lhs) contains
/// a `Mul` somewhere. Matches `a * UNIT / b` and `(a * b) / c`.
fn expr_is_muldiv_rate(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Binary { op: BinOp::Div, lhs, .. } = &sub.kind {
            if subtree_has_mul(lhs) {
                found = true;
            }
        }
    });
    found
}

/// Does the expression subtree contain a `Mul`?
fn subtree_has_mul(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if matches!(&sub.kind, ExprKind::Binary { op: BinOp::Mul, .. }) {
            found = true;
        }
    });
    found
}

// ------------------------------------------------------------------- shared util

/// `block.timestamp` / `block.number` read anywhere in `g`'s body (via the
/// precomputed effect flag, with a textual fallback).
fn reads_block_time(cx: &AnalysisContext, g: &Function) -> bool {
    if g.effects.reads_block_env {
        return true;
    }
    let t = cx.source_text(g.span);
    t.contains("block.timestamp") || t.contains("block.number")
}

/// Shallow `block.timestamp` / `block.number` member read inside an expression.
fn expr_reads_block_time(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Member { base, member } = &sub.kind {
            let m = member.to_ascii_lowercase();
            if (m == "timestamp" || m == "number")
                && matches!(&base.kind, ExprKind::Ident(b) if b == "block")
            {
                found = true;
            }
        }
    });
    found
}

/// Comment-stripped, lowercased, trimmed source for a span, truncated to `max`.
fn trimmed_text(cx: &AnalysisContext, span: Span, max: usize) -> String {
    let t = cx.source_text(span);
    let t = t.trim();
    if t.len() > max {
        format!("{}…", &t[..max.min(t.len())])
    } else {
        t.to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "vesting-buffered-donation")
    }
    /// Severity of the (first) `vesting-buffered-donation` finding, if any.
    fn severity(src: &str) -> Option<sluice_findings::Severity> {
        run(src)
            .into_iter()
            .find(|f| f.detector == "vesting-buffered-donation")
            .map(|f| f.severity)
    }

    // VULN — the Ethena StakedUSDe / EthenaBalancerRateProvider shape, condensed:
    // `totalAssets = balanceOf(this) - getUnvestedAmount()`, getUnvestedAmount is a
    // time-decaying buffer over the settable `vestingAmount` mutated only by the
    // role-gated `transferInRewards` → `_updateVestingAmount`, and a SEPARATE
    // `getRate` publishes `totalAssets * 1 ether / totalSupply`.
    const VULN: &str = r#"
        interface IERC20 { function balanceOf(address) external view returns (uint256); }
        contract StakedUSDe {
            uint256 public vestingAmount;
            uint256 public lastDistributionTimestamp;
            uint256 private constant VESTING_PERIOD = 8 hours;
            address public assetToken;
            function asset() public view returns (address) { return assetToken; }
            modifier onlyRewarder() { _; }
            function transferInRewards(uint256 amount) external onlyRewarder {
                _updateVestingAmount(amount);
            }
            function _updateVestingAmount(uint256 newVestingAmount) internal {
                vestingAmount = newVestingAmount;
                lastDistributionTimestamp = block.timestamp;
            }
            function totalSupply() public view returns (uint256) { return 1; }
            function totalAssets() public view returns (uint256) {
                return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();
            }
            function getUnvestedAmount() public view returns (uint256) {
                uint256 dt = block.timestamp - lastDistributionTimestamp;
                if (dt >= VESTING_PERIOD) return 0;
                return ((VESTING_PERIOD - dt) * vestingAmount) / VESTING_PERIOD;
            }
        }
        contract RateProvider {
            StakedUSDe public stakedUSDe;
            function getRate() external view returns (uint256) {
                uint256 _ts = stakedUSDe.totalSupply();
                if (_ts == 0) return 0;
                return stakedUSDe.totalAssets() * 1 ether / _ts;
            }
        }
    "#;

    // VULN — inline decaying buffer (no separate getUnvestedAmount): the subtraction
    // itself is `balanceOf(this) - (elapsed * vestingAmount / PERIOD)`, var still
    // drip-gated, rate consumer present.
    const VULN_INLINE: &str = r#"
        interface IERC20 { function balanceOf(address) external view returns (uint256); }
        contract Vault {
            uint256 public vestingAmount;
            uint256 public lastUpdate;
            uint256 private constant PERIOD = 8 hours;
            address public token;
            modifier onlyAdmin() { _; }
            function drip(uint256 a) external onlyAdmin {
                vestingAmount = a; lastUpdate = block.timestamp;
            }
            function totalSupply() public view returns (uint256) { return 1; }
            function totalAssets() public view returns (uint256) {
                return IERC20(token).balanceOf(address(this))
                     - ((PERIOD - (block.timestamp - lastUpdate)) * vestingAmount) / PERIOD;
            }
            function pricePerShare() external view returns (uint256) {
                return totalAssets() * 1e18 / totalSupply();
            }
        }
    "#;

    // VULN (Medium) — NO external rate publisher in scope. The donation-jumpable
    // `balanceOf(this) - getUnvestedAmount()` price is STILL the bug (the vault's own
    // ERC4626 redemption math reads it, and a separate-file rate provider may consume
    // it), so the core shape fires at Medium even though no `*UNIT/totalSupply()`
    // publisher is co-scanned. Demoting this to "silent" was the overfit that caused
    // the regression — re-tied here to assert the Medium tier.
    const NO_PUBLISHER: &str = r#"
        interface IERC20 { function balanceOf(address) external view returns (uint256); }
        contract StakedUSDe {
            uint256 public vestingAmount;
            uint256 public lastDistributionTimestamp;
            uint256 private constant VESTING_PERIOD = 8 hours;
            address public assetToken;
            function asset() public view returns (address) { return assetToken; }
            modifier onlyRewarder() { _; }
            function transferInRewards(uint256 amount) external onlyRewarder {
                _updateVestingAmount(amount);
            }
            function _updateVestingAmount(uint256 n) internal {
                vestingAmount = n; lastDistributionTimestamp = block.timestamp;
            }
            function totalSupply() public view returns (uint256) { return 1; }
            function totalAssets() public view returns (uint256) {
                return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();
            }
            function getUnvestedAmount() public view returns (uint256) {
                uint256 dt = block.timestamp - lastDistributionTimestamp;
                if (dt >= VESTING_PERIOD) return 0;
                return ((VESTING_PERIOD - dt) * vestingAmount) / VESTING_PERIOD;
            }
        }
    "#;

    // SAFE — donations are sync()-gated: the contract exposes a `sync()` reserve
    // resync, so a bare transfer is reconciled rather than landing unbuffered.
    const SAFE_SYNC_GATED: &str = r#"
        interface IERC20 { function balanceOf(address) external view returns (uint256); }
        contract StakedUSDe {
            uint256 public vestingAmount;
            uint256 public lastDistributionTimestamp;
            uint256 private constant VESTING_PERIOD = 8 hours;
            address public assetToken;
            function asset() public view returns (address) { return assetToken; }
            modifier onlyRewarder() { _; }
            function transferInRewards(uint256 amount) external onlyRewarder {
                vestingAmount = amount; lastDistributionTimestamp = block.timestamp;
            }
            function sync() external { /* re-derive internal reserve */ }
            function totalSupply() public view returns (uint256) { return 1; }
            function totalAssets() public view returns (uint256) {
                return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();
            }
            function getUnvestedAmount() public view returns (uint256) {
                uint256 dt = block.timestamp - lastDistributionTimestamp;
                if (dt >= VESTING_PERIOD) return 0;
                return ((VESTING_PERIOD - dt) * vestingAmount) / VESTING_PERIOD;
            }
        }
        contract RateProvider {
            StakedUSDe public stakedUSDe;
            function getRate() external view returns (uint256) {
                return stakedUSDe.totalAssets() * 1 ether / stakedUSDe.totalSupply();
            }
        }
    "#;

    // SAFE — the vesting buffer var is PUBLICLY bumpable (no access control on the
    // drip): the donation asymmetry is gone (anyone can move the buffer too), so this
    // is a different design and must stay silent.
    const SAFE_PUBLIC_DRIP: &str = r#"
        interface IERC20 { function balanceOf(address) external view returns (uint256); }
        contract StakedUSDe {
            uint256 public vestingAmount;
            uint256 public lastDistributionTimestamp;
            uint256 private constant VESTING_PERIOD = 8 hours;
            address public assetToken;
            function asset() public view returns (address) { return assetToken; }
            function transferInRewards(uint256 amount) external {
                vestingAmount = amount; lastDistributionTimestamp = block.timestamp;
            }
            function totalSupply() public view returns (uint256) { return 1; }
            function totalAssets() public view returns (uint256) {
                return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();
            }
            function getUnvestedAmount() public view returns (uint256) {
                uint256 dt = block.timestamp - lastDistributionTimestamp;
                if (dt >= VESTING_PERIOD) return 0;
                return ((VESTING_PERIOD - dt) * vestingAmount) / VESTING_PERIOD;
            }
        }
        contract RateProvider {
            StakedUSDe public stakedUSDe;
            function getRate() external view returns (uint256) {
                return stakedUSDe.totalAssets() * 1 ether / stakedUSDe.totalSupply();
            }
        }
    "#;

    // SAFE — an ordinary ERC4626 `totalAssets` that just returns `balanceOf(this)`
    // with NO vesting subtraction. No time-decaying buffer ⇒ not this class.
    const SAFE_PLAIN_4626: &str = r#"
        interface IERC20 { function balanceOf(address) external view returns (uint256); }
        contract Vault {
            address public token;
            function totalSupply() public view returns (uint256) { return 1; }
            function totalAssets() public view returns (uint256) {
                return IERC20(token).balanceOf(address(this));
            }
            function pricePerShare() external view returns (uint256) {
                return totalAssets() * 1e18 / totalSupply();
            }
        }
    "#;

    // VULN (Medium) — a HIGH-FIDELITY reproduction of the REAL on-disk
    // `StakedUSDe.sol` (ethena-vuln-analysis/.../contracts/StakedUSDe.sol): the exact
    // `totalAssets() = balanceOf(address(this)) - getUnvestedAmount()` body, the real
    // `getUnvestedAmount` with its early `>= VESTING_PERIOD` return and the `unchecked`
    // `deltaT` block, `vestingAmount` written only by the internal `_updateVestingAmount`
    // (guarded by `if (getUnvestedAmount() > 0) revert`), itself reached only from the
    // role-gated `transferInRewards` (`onlyRole(REWARDER_ROLE)`) and
    // `redistributeLockedAmount` (`onlyRole(DEFAULT_ADMIN_ROLE)`). Crucially the rate
    // consumer (`EthenaBalancerRateProvider`) is a SEPARATE contract in a SEPARATE file
    // and is NOT present here — exactly the single-file-scan condition under which the
    // R12 detector silently regressed to 0. This must fire (at Medium) on the structural
    // shape alone, so the regression can never silently return.
    const REAL_STAKED_USDE: &str = r#"
        interface IERC20 { function balanceOf(address) external view returns (uint256); }
        contract StakedUSDe {
            uint256 public vestingAmount;
            uint256 public lastDistributionTimestamp;
            uint256 private constant VESTING_PERIOD = 8 hours;
            bytes32 private constant REWARDER_ROLE = keccak256("REWARDER_ROLE");
            bytes32 private constant DEFAULT_ADMIN_ROLE = 0x00;
            modifier onlyRole(bytes32 role) { _; }
            modifier nonReentrant() { _; }
            modifier notZero(uint256 amount) { _; }
            function asset() public view returns (address) { return address(0); }
            function totalSupply() public view returns (uint256) { return 1; }

            function transferInRewards(uint256 amount)
                external nonReentrant onlyRole(REWARDER_ROLE) notZero(amount)
            {
                _updateVestingAmount(amount);
            }

            function redistributeLockedAmount(address from, address to)
                external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE)
            {
                if (to == address(0)) {
                    _updateVestingAmount(123);
                }
            }

            function totalAssets() public view returns (uint256) {
                return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();
            }

            function getUnvestedAmount() public view returns (uint256) {
                uint256 timeSinceLastDistribution = block.timestamp - lastDistributionTimestamp;
                if (timeSinceLastDistribution >= VESTING_PERIOD) {
                    return 0;
                }
                uint256 deltaT;
                unchecked {
                    deltaT = (VESTING_PERIOD - timeSinceLastDistribution);
                }
                return (deltaT * vestingAmount) / VESTING_PERIOD;
            }

            function _updateVestingAmount(uint256 newVestingAmount) internal {
                if (getUnvestedAmount() > 0) revert();
                vestingAmount = newVestingAmount;
                lastDistributionTimestamp = block.timestamp;
            }
        }
    "#;

    #[test]
    fn fires_on_ethena_shape() {
        assert!(fires(VULN), "{:#?}", run(VULN));
        // With the external rate publisher in scope the blast radius is largest → High.
        assert_eq!(severity(VULN), Some(sluice_findings::Severity::High), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_inline_buffer() {
        assert!(fires(VULN_INLINE), "{:#?}", run(VULN_INLINE));
        assert_eq!(severity(VULN_INLINE), Some(sluice_findings::Severity::High), "{:#?}", run(VULN_INLINE));
    }

    // REGRESSION GUARD (R12 overfit): the detector must fire on the bare
    // donation-jumpable vesting-buffered share price even when NO `*UNIT/totalSupply()`
    // rate publisher is co-scanned (the real `EthenaBalancerRateProvider` lives in a
    // separate file, so a single-file scan of `StakedUSDe` saw no consumer and went
    // silent — that was the regression). It now fires at Medium on the core shape.
    #[test]
    fn fires_without_rate_publisher_at_medium() {
        assert!(fires(NO_PUBLISHER), "{:#?}", run(NO_PUBLISHER));
        assert_eq!(severity(NO_PUBLISHER), Some(sluice_findings::Severity::Medium), "{:#?}", run(NO_PUBLISHER));
    }

    #[test]
    fn silent_when_sync_gated() {
        assert!(!fires(SAFE_SYNC_GATED), "{:#?}", run(SAFE_SYNC_GATED));
    }

    #[test]
    fn silent_when_drip_is_public() {
        assert!(!fires(SAFE_PUBLIC_DRIP), "{:#?}", run(SAFE_PUBLIC_DRIP));
    }

    #[test]
    fn silent_on_plain_erc4626() {
        assert!(!fires(SAFE_PLAIN_4626), "{:#?}", run(SAFE_PLAIN_4626));
    }

    // REGRESSION GUARD: the real on-disk Ethena `StakedUSDe` shape (rate consumer in a
    // separate file, hence absent here) MUST fire. This is the exact condition the R12
    // detector regressed on. See `REAL_STAKED_USDE`.
    #[test]
    fn fires_on_real_staked_usde_without_consumer() {
        assert!(fires(REAL_STAKED_USDE), "{:#?}", run(REAL_STAKED_USDE));
        assert_eq!(
            severity(REAL_STAKED_USDE),
            Some(sluice_findings::Severity::Medium),
            "{:#?}",
            run(REAL_STAKED_USDE)
        );
    }
}
