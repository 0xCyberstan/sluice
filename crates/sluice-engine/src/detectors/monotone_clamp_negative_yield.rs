//! Monotone "max-with-self" clamp that masks negative yield / a real loss.
//!
//! ## The class
//!
//! A storage index/rate variable `S` (a yield index, exchange rate, price-per-share)
//! is updated as a **self-ratchet**:
//!
//! ```solidity
//! S = max(<fresh / externally-sourced value>, S);   // or via a temp:
//! uint256 fresh = max(externalRate(), S);  S = fresh;
//! ```
//!
//! so `S` can only ever stay flat or rise — it is non-decreasing by construction.
//! That same `S` is **later read as a divisor / multiplier in an interest or
//! redemption payout** (`interest = principal * (curIndex - prevIndex) / (prevIndex
//! * curIndex)`, `assets = shares * index / 1e18`, …). When the underlying yield
//! source actually loses value (a slashing event, a negative-rebase, a depeg, an
//! exploit on the wrapped vault), the *fresh* value drops **below** the stored one,
//! the `max(...)` discards it, and the index sticks at its old high. The protocol
//! then keeps paying out yield computed against an index that no longer reflects
//! reality — a genuine loss is **masked as phantom yield**, paid to whoever exits
//! first and socialised onto everyone who exits later (or onto the protocol's own
//! reserve / treasury). It is the dual of the high-water-mark fee trick, applied to
//! the *payout* index instead of a performance fee.
//!
//! This is the shape behind Pendle's `PendleYieldToken._pyIndexCurrent`
//! (`_pyIndexStored = max(SY.exchangeRate(), _pyIndexStored)` — explicitly
//! "guaranteeing non-decreasing PY index") whose `_pyIndexStored` then drives the
//! interest accrual in `InterestManagerYT._distributeInterestPrivate`
//! (`(principal * (currentIndex - prevIndex)).divDown(prevIndex * currentIndex)`):
//! a real drop in `SY.exchangeRate()` is silently floored, so YT holders are still
//! credited interest the underlying never earned.
//!
//! ## Why "max-with-self" is the anchor
//!
//! Writing a state variable as `max(somethingElse, sameVar)` is a deliberate,
//! **rare** idiom — across seven unrelated audited codebases (Olympus, EigenLayer,
//! EtherFi, Symbiotic, Renzo, Karak, Ethena) it does not appear once outside
//! comments. Ordinary code does not clamp a stored value up against itself by
//! accident; when it does, it is precisely the monotone-ratchet pattern. So the
//! anchor here is structural and high-signal: a `max(...)` call one of whose
//! operands root-resolves to a *settable* state variable `S`, where `S` is also
//! written in the same function (directly, `S = max(..)`, or through the temp the
//! `max` initialises, `t = max(..); S = t;`).
//!
//! ## Precision gates (so this stays quiet on benign high-water-marks)
//!
//!   * the clamped var must read like a yield **index / rate / price-per-share**
//!     (`index`, `rate`, `exchangeRate`, `pricePerShare`, `…PerShare`) — a plain
//!     `highestBid` / `maxSeen` counter is not a payout divisor;
//!   * there must be a corroborating **payout** elsewhere in the codebase: a
//!     division or multiplication, in an interest / redemption / accrual context,
//!     whose operands reference an index/rate — i.e. the ratcheted index is
//!     actually consumed to compute a paid-out amount. A pure high-water-mark that
//!     is never used as a payout divisor is **suppressed**;
//!   * **suppressed** if a sibling write moves the same var *down* — a `-=`, a
//!     `S = … - …`, `S = min(…)`, or `delete S`. If the protocol can also write the
//!     index down, a real loss is not permanently masked, so the ratchet is not the
//!     bug.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{AssignOp, BinOp, Call, Expr, ExprKind, Function, Span};

use super::prelude::*;

pub struct MonotoneClampNegativeYieldDetector;

impl Detector for MonotoneClampNegativeYieldDetector {
    fn id(&self) -> &'static str {
        "monotone-clamp-negative-yield"
    }
    fn category(&self) -> Category {
        Category::MonotoneClampNegativeYield
    }
    fn description(&self) -> &'static str {
        "Index/rate var written as max(fresh, self) (non-decreasing ratchet) then used as an interest/redemption payout divisor — masks real negative yield"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        // The payout corroboration is a whole-codebase property (the ratcheted
        // index is frequently consumed in a *sibling* contract — Pendle accrues in
        // `InterestManagerYT` while the ratchet lives in `PendleYieldToken`), so
        // compute it once up front.
        let has_payout = codebase_has_index_payout(cx);

        for f in cx.functions() {
            if !f.has_body || f.is_modifier() {
                continue;
            }
            // The ratchet write is a *mutation*, never a pure view/interface decl.
            if f.is_view_or_pure() {
                continue;
            }

            // --- anchor: a max(fresh, S) self-ratchet on a settable state var S ---
            let Some((span, var)) = find_self_ratchet(cx, f) else {
                continue;
            };

            // The clamped var must read like a yield index / rate / price-per-share
            // — the kind of value that ends up a payout divisor. A bare counter
            // ("highestBid", "maxObserved") is out of scope.
            if !is_index_rate_name(&var) {
                continue;
            }

            // A pure high-water-mark that never feeds a payout is benign — require
            // the codebase to actually consume an index/rate in an interest /
            // redemption payout division.
            if !has_payout {
                continue;
            }

            // --- suppression: a sibling write moves the SAME var down ---
            // If anything anywhere can decrement / write the index down, a real loss
            // is not permanently masked, so the monotone ratchet is not the defect.
            if contract_writes_var_down(cx, f, &var) {
                continue;
            }

            let b = report!(self, Category::MonotoneClampNegativeYield,
                title = "Monotone max-with-self clamp on a payout index masks negative yield",
                severity = Severity::High,
                confidence = 0.8,
                dimensions = [Dimension::Invariant, Dimension::ValueFlow],
                message = format!(
                    "`{f}` writes the index/rate state variable `{var}` as `max(<fresh value>, {var})`, \
                     a self-ratchet that makes `{var}` strictly non-decreasing, and `{var}` is then read \
                     as a divisor/multiplier in an interest/redemption payout. If the underlying yield \
                     source actually loses value (slashing, negative rebase, depeg, a hack on the wrapped \
                     vault) the fresh value drops below the stored one, the `max(...)` discards it, and \
                     `{var}` sticks at its old high. The protocol then keeps paying yield computed against \
                     an index that no longer reflects reality — a real negative yield / loss is masked as \
                     phantom yield, paid to whoever exits first and socialised onto later exiters or the \
                     protocol's reserve. No sibling function writes `{var}` down, so the loss cannot be \
                     reconciled.",
                    f = f.name,
                    var = var
                ),
                recommendation =
                    "Do not clamp a payout index up against itself. Let the index track the true \
                     (possibly decreasing) value of the underlying so a real loss is reflected the moment \
                     it happens, or — if monotonicity is a hard requirement — book the shortfall \
                     explicitly (a loss/deficit accumulator that future yield must repay, or a write-down \
                     path that an authorised role can trigger) so the discarded drop is socialised \
                     correctly rather than silently paid out as yield that was never earned.",
            );
            out.push(finish_at(cx, b, f.id, span));
        }
        out
    }
}

// ============================================================ anchor: the ratchet

/// Find a `max(fresh, S)` self-ratchet in `f`: a `max(...)` call one of whose
/// operands root-resolves to a *settable* state variable `S`, where `S` is also
/// written in this function — either directly (`S = max(..)…`) or through the temp
/// the `max` initialises (`t = max(..); … S = t;`). Returns the span of the `max`
/// call expression and the variable name `S`.
fn find_self_ratchet(cx: &AnalysisContext, f: &Function) -> Option<(Span, String)> {
    // (1) Collect the names of state variables this function writes (assignment
    //     targets + `delete`/`++`-style mutations are covered by assignment-target
    //     roots; for the ratchet we only need plain write targets).
    let written = written_state_vars(cx, f);
    if written.is_empty() {
        return None;
    }

    // (2) Find a `max(...)` call whose operand set contains one of those written
    //     state vars. That operand is the "self" side of the ratchet.
    let mut hit: Option<(Span, String)> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            if !is_max_call(c) {
                return;
            }
            // `max` operands: free form `max(a, b)` => args; method/library form
            // `X.max(b)` => receiver + args (a value receiver is an operand, the
            // bare `Math`/`PMath` namespace is not).
            for operand in max_operands(c) {
                if let Some(root) = root_ident_peeled(operand) {
                    if written.iter().any(|w| w == &root) {
                        hit = Some((e.span, root));
                        return;
                    }
                }
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Is `c` a `max(...)` call — the free function `max(a,b)`, a library/method form
/// `PMath.max(a,b)` / `a.max(b)`? Matched purely on the callee name being `max`.
fn is_max_call(c: &Call) -> bool {
    c.func_name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case("max"))
}

/// The value operands of a `max(...)` call, accounting for both spellings:
///   * free / library form `max(a, b)` or `PMath.max(a, b)` — operands are the
///     args (a math-namespace receiver such as `PMath` is *not* an operand);
///   * bound method form `value.max(b)` — the receiver is itself an operand.
fn max_operands(c: &Call) -> Vec<&Expr> {
    let mut ops: Vec<&Expr> = c.args.iter().collect();
    if let Some(recv) = c.receiver.as_deref() {
        if !is_math_namespace(recv) {
            ops.push(recv);
        }
    }
    ops
}

/// A math-library *namespace* receiver (`PMath.max`, `Math.max`) — the receiver is
/// the library, not a value operand. Mirrors the namespace check used by the
/// share-pricing detector.
fn is_math_namespace(recv: &Expr) -> bool {
    let ExprKind::Ident(n) = &peel_casts(recv).kind else { return false };
    let l = n.to_ascii_lowercase();
    l == "math" || l.ends_with("math") || l == "signedmath" || l == "fixedpoint"
}

/// State variables of `f`'s contract that `f` *writes* (assignment target whose
/// root resolves to a settable state var). Covers the direct ratchet `S = max(..)`
/// and the temp-then-store `t = max(..); S = t;` (both write `S`).
fn written_state_vars(cx: &AnalysisContext, f: &Function) -> Vec<String> {
    let mut vars: Vec<String> = Vec::new();
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if let ExprKind::Assign { target, .. } = &e.kind {
                if root_is_settable_state_var(cx, f, target) {
                    if let Some(root) = root_ident_peeled(target) {
                        if !vars.contains(&root) {
                            vars.push(root);
                        }
                    }
                }
            }
        });
    }
    vars
}

// ===================================================== suppression: write-down

/// Does any function in the same contract write `var` *down* — `var -= …`,
/// `var = … - …`, `var = min(…)`, or `delete var`? If so, the index is not a
/// permanent one-way ratchet and a real loss can be reconciled, so we suppress.
fn contract_writes_var_down(cx: &AnalysisContext, f: &Function, var: &str) -> bool {
    let Some(contract) = cx.contract_of(f.id) else { return false };
    for fid in &contract.functions {
        let Some(g) = cx.scir.function(*fid) else { continue };
        if function_writes_var_down(g, var) {
            return true;
        }
    }
    false
}

/// True if `g` contains a downward write of `var`: a `-=` to `var`, an assignment
/// `var = <expr with a Sub or a min(..)>`, or a `delete var` / `var--`.
fn function_writes_var_down(g: &Function, var: &str) -> bool {
    let mut found = false;
    for s in &g.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            match &e.kind {
                ExprKind::Assign { op, target, value } => {
                    if !target_root_is(target, var) {
                        return;
                    }
                    // `var -= …` is an explicit decrement.
                    if matches!(op, AssignOp::Sub) {
                        found = true;
                        return;
                    }
                    // `var = … - …` or `var = min(…)` writes a value that can be
                    // lower than the current one — a reconciling write-down.
                    if *op == AssignOp::Assign && value_can_decrease(value) {
                        found = true;
                    }
                }
                // `var--` / `--var`.
                ExprKind::Unary { op, operand }
                    if matches!(op, sluice_ir::UnOp::PreDec | sluice_ir::UnOp::PostDec | sluice_ir::UnOp::Delete) =>
                {
                    if target_root_is(operand, var) {
                        found = true;
                    }
                }
                _ => {}
            }
        });
        if found {
            break;
        }
    }
    found
}

/// Does the root identifier of an lvalue equal `var` (casts peeled)?
fn target_root_is(target: &Expr, var: &str) -> bool {
    root_ident_peeled(target).as_deref() == Some(var)
}

/// A value that can move the index *down*: it contains a subtraction, or a
/// `min(...)` clamp. (`max(...)` is the ratchet itself and does not count.)
fn value_can_decrease(value: &Expr) -> bool {
    let mut found = false;
    value.visit(&mut |n| {
        match &n.kind {
            ExprKind::Binary { op: BinOp::Sub, .. } => found = true,
            ExprKind::Call(c) if c.func_name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case("min")) => {
                found = true
            }
            _ => {}
        }
    });
    found
}

// ============================================== corroboration: an index payout

/// Does the codebase contain an interest / redemption / accrual payout that
/// divides or multiplies by an index/rate? This is the "the ratcheted index is
/// actually consumed in yield math" corroboration. We look codebase-wide because
/// the payout commonly lives in a sibling/base contract from the ratchet (Pendle
/// accrues in `InterestManagerYT`, ratchets in `PendleYieldToken`).
fn codebase_has_index_payout(cx: &AnalysisContext) -> bool {
    cx.functions().any(|f| f.has_body && function_has_index_payout(cx, f))
}

/// True if `f` reads like an interest / redemption / accrual routine *and* performs
/// a division or multiplication whose operands reference an index/rate. The Pendle
/// accrual `(principal * (currentIndex - prevIndex)).divDown(prevIndex *
/// currentIndex)` matches: it is in `_distributeInterest…` and divides by a product
/// of `…Index` operands.
fn function_has_index_payout(cx: &AnalysisContext, f: &Function) -> bool {
    if !payout_context_name(&f.name) {
        // The context may instead be evidenced by the surrounding source (a
        // `redeem`/`interest` helper called from a differently-named function), so
        // fall back to a source-keyword check on the function body.
        let src = cx.source_text(f.span);
        if !PAYOUT_KEYWORDS.iter().any(|k| src.contains(k)) {
            return false;
        }
    }
    index_div_or_mul(f)
}

/// A `Div` / `divDown` / `divUp` / `mulDiv` / `Mul` whose operands reference an
/// index/rate identifier — the index being used as a payout divisor/multiplier.
fn index_div_or_mul(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            match &e.kind {
                // Native `a / b` or `a * b`.
                ExprKind::Binary { op: BinOp::Div | BinOp::Mul, lhs, rhs } => {
                    if expr_mentions_index_rate(lhs) || expr_mentions_index_rate(rhs) {
                        found = true;
                    }
                }
                // Helper divisions/products: `x.divDown(y)`, `Math.mulDiv(a,b,c)`, …
                ExprKind::Call(c) if is_div_mul_helper(c) => {
                    let mut ops: Vec<&Expr> = c.args.iter().collect();
                    if let Some(r) = c.receiver.as_deref() {
                        ops.push(r);
                    }
                    if ops.iter().any(|o| expr_mentions_index_rate(o)) {
                        found = true;
                    }
                }
                _ => {}
            }
        });
        if found {
            break;
        }
    }
    found
}

/// A division/multiplication *helper* call: `divDown`/`divUp`/`div`/`mulDiv`/
/// `mulDown`/`mulUp`/`mul`. (Plain `min`/`max` are not payouts.)
fn is_div_mul_helper(c: &Call) -> bool {
    let Some(n) = c.func_name.as_deref() else { return false };
    let l = n.to_ascii_lowercase();
    matches!(
        l.as_str(),
        "divdown" | "divup" | "div" | "muldiv" | "muldivdown" | "muldivup" | "muldown" | "mulup"
    )
}

/// Does an expression mention an index/rate identifier anywhere (an `…Index`,
/// `…Rate`, `exchangeRate`, `pricePerShare`)?
fn expr_mentions_index_rate(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |n| match &n.kind {
        ExprKind::Ident(s) => {
            if token_is_index_rate(s) {
                found = true;
            }
        }
        ExprKind::Member { member, .. } => {
            if token_is_index_rate(member) {
                found = true;
            }
        }
        _ => {}
    });
    found
}

// ===================================================================== name sets

/// Keywords (lowercased, comment-stripped) that mark a function body as an
/// interest / redemption / accrual payout context.
const PAYOUT_KEYWORDS: &[&str] =
    &["interest", "redeem", "accru", "yield", "duere", "claimable", "withdrawable"];

/// Does a function *name* read like an interest / redemption / accrual payout?
fn payout_context_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "interest", "redeem", "accru", "yield", "distribute", "claim", "harvest", "duere",
        "withdrawable", "claimable",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// Is `name` a yield-index / rate / price-per-share variable — the kind of value
/// that becomes a payout divisor? Kept tight so a generic `highestBid` / `maxSeen`
/// high-water-mark does not qualify.
fn is_index_rate_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("index")
        || l.contains("rate")
        || l.contains("pershare")
        || l.contains("per_share")
        || l.contains("exchange")
        || (l.contains("price") && (l.contains("share") || l.contains("per")))
}

/// A single identifier token that names an index/rate used in a payout.
fn token_is_index_rate(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    l.contains("index") || l.contains("rate") || l.contains("pershare") || l.contains("exchange")
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fired(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.detector == "monotone-clamp-negative-yield")
    }

    // VULN — the Pendle shape: `_pyIndexStored` is ratcheted up with
    // `max(SY.exchangeRate(), _pyIndexStored)` (non-decreasing index), and the
    // index drives the interest accrual division in a sibling abstract contract.
    const VULN: &str = r#"
        library PMath {
            function max(uint256 a, uint256 b) internal pure returns (uint256) { return a > b ? a : b; }
            function divDown(uint256 a, uint256 b) internal pure returns (uint256) { return a / b; }
        }
        abstract contract InterestManagerYT {
            using PMath for uint256;
            mapping(address => uint256) public userIndex;
            mapping(address => uint256) public accrued;
            function _getInterestIndex() internal virtual returns (uint256);
            function _balanceOf(address u) internal view virtual returns (uint256);
            function _distributeInterest(address user, uint256 currentIndex) internal {
                uint256 prevIndex = userIndex[user];
                if (prevIndex == 0 || prevIndex == currentIndex) { userIndex[user] = currentIndex; return; }
                uint256 principal = _balanceOf(user);
                uint256 interestFromYT = (principal * (currentIndex - prevIndex)).divDown(prevIndex * currentIndex);
                accrued[user] += interestFromYT;
                userIndex[user] = currentIndex;
            }
        }
        interface ISY { function exchangeRate() external view returns (uint256); }
        contract PendleYieldToken is InterestManagerYT {
            using PMath for uint256;
            address public immutable SY;
            uint128 internal _pyIndexStored;
            uint128 public pyIndexLastUpdatedBlock;
            constructor(address sy) { SY = sy; }
            function _balanceOf(address) internal view override returns (uint256) { return 0; }
            function _getInterestIndex() internal override returns (uint256) { return _pyIndexCurrent(); }
            function _pyIndexCurrent() internal returns (uint256 currentIndex) {
                uint256 index = PMath.max(ISY(SY).exchangeRate(), _pyIndexStored);
                _pyIndexStored = uint128(index);
                pyIndexLastUpdatedBlock = uint128(block.number);
                currentIndex = index;
            }
        }
    "#;

    // VULN_DIRECT — the same ratchet written *directly* into the state var
    // (`exchangeRateStored = max(fresh, exchangeRateStored)`), with the index
    // consumed in a redeem payout. Exercises the direct-assignment write shape.
    const VULN_DIRECT: &str = r#"
        library Math { function max(uint256 a, uint256 b) internal pure returns (uint256) { return a > b ? a : b; } }
        interface IVault { function rate() external view returns (uint256); }
        contract Wrapper {
            using Math for uint256;
            address public vault;
            uint256 public exchangeRateStored;
            mapping(address => uint256) public shares;
            function poke() external {
                exchangeRateStored = Math.max(IVault(vault).rate(), exchangeRateStored);
            }
            function redeem(uint256 amt) external returns (uint256 assetsOut) {
                assetsOut = amt * exchangeRateStored / 1e18;
                shares[msg.sender] -= amt;
            }
        }
    "#;

    // SAFE_WRITEDOWN — same ratchet AND payout, but a sibling function writes the
    // index *down* (`syncDown` sets it to a fresh, possibly-lower value via a Sub),
    // so a real loss is reconciled — must stay silent.
    const SAFE_WRITEDOWN: &str = r#"
        library Math { function max(uint256 a, uint256 b) internal pure returns (uint256) { return a > b ? a : b; } }
        interface IVault { function rate() external view returns (uint256); }
        contract Wrapper {
            using Math for uint256;
            address public vault;
            uint256 public exchangeRateStored;
            function poke() external {
                exchangeRateStored = Math.max(IVault(vault).rate(), exchangeRateStored);
            }
            function syncDown(uint256 loss) external {
                exchangeRateStored = exchangeRateStored - loss;
            }
            function redeem(uint256 amt) external returns (uint256 assetsOut) {
                assetsOut = amt * exchangeRateStored / 1e18;
            }
        }
    "#;

    // SAFE_HWM — a genuine high-water-mark (`highestSharePrice = max(cur, highest)`)
    // that is NOT used as a payout divisor (only emitted / compared), and is not an
    // index/rate payout var in any division. Must stay silent.
    const SAFE_HWM: &str = r#"
        library Math { function max(uint256 a, uint256 b) internal pure returns (uint256) { return a > b ? a : b; } }
        contract Fund {
            using Math for uint256;
            uint256 public highWaterMark;
            event NewHigh(uint256 v);
            function update(uint256 cur) external {
                highWaterMark = Math.max(cur, highWaterMark);
                emit NewHigh(highWaterMark);
            }
        }
    "#;

    // SAFE_NOMAX — an index updated by a plain assignment (no max-with-self), used
    // in a redeem payout. Without the ratchet anchor there is no finding.
    const SAFE_NOMAX: &str = r#"
        interface IVault { function rate() external view returns (uint256); }
        contract Wrapper {
            address public vault;
            uint256 public exchangeRateStored;
            function poke() external {
                exchangeRateStored = IVault(vault).rate();
            }
            function redeem(uint256 amt) external returns (uint256 assetsOut) {
                assetsOut = amt * exchangeRateStored / 1e18;
            }
        }
    "#;

    #[test]
    fn fires_on_pendle_shape() {
        let fs = run(VULN);
        assert!(fired(&fs), "{:#?}", fs);
    }

    #[test]
    fn fires_on_direct_ratchet() {
        let fs = run(VULN_DIRECT);
        assert!(fired(&fs), "{:#?}", fs);
    }

    #[test]
    fn silent_when_sibling_writes_down() {
        let fs = run(SAFE_WRITEDOWN);
        assert!(!fired(&fs), "{:#?}", fs);
    }

    #[test]
    fn silent_on_pure_high_water_mark() {
        let fs = run(SAFE_HWM);
        assert!(!fired(&fs), "{:#?}", fs);
    }

    #[test]
    fn silent_without_max_anchor() {
        let fs = run(SAFE_NOMAX);
        assert!(!fired(&fs), "{:#?}", fs);
    }
}
