//! An off-chain-supplied guess is fed to an iterative on-chain solver whose
//! result is then used to move funds, but the solver **trusts that the guess
//! converged** — there is no post-solve residual / exact re-check on the value it
//! returns.
//!
//! ## The shape
//!
//! Pendle's AMM has no closed form for "how much PT do I swap to spend exactly
//! `exactSyIn`", so the router solves it numerically. The caller hands in an
//! [`ApproxParams`] struct
//!
//! ```solidity
//! struct ApproxParams { uint256 guessMin; uint256 guessMax; uint256 guessOffchain; uint256 maxIteration; uint256 eps; }
//! ```
//!
//! and the library (`MarketApproxLibV2.sol`) runs a bisection loop seeded from it:
//!
//! ```solidity
//! function approxSwapExactSyForYtV2(..., ApproxParams memory approx) internal pure returns (uint256, uint256) {
//!     if (approx.guessOffchain == 0) { ...; validateApprox(approx); }   // only the *on-chain* path is validated
//!     uint256 guess = getFirstGuess(approx);                            // == approx.guessOffchain when supplied
//!     for (uint256 iter = 0; iter < approx.maxIteration; ++iter) {
//!         (uint256 netSyOut,,) = calcSyOut(market, comp, index, guess);
//!         uint256 netSyToPull = index.assetToSyUp(guess) - netSyOut;
//!         if (netSyToPull <= exactSyIn) {
//!             if (PMath.isASmallerApproxB(netSyToPull, exactSyIn, approx.eps)) return (guess, netSyFee); // <-- only gate
//!             ...
//!         } else { approx.guessMax = guess - 1; }
//!         guess = (iter <= CUT_OFF_SCALE_CLAMP) ? scaleClamp(...) : calcMidpoint(approx);
//!     }
//!     revert("Slippage: APPROX_EXHAUSTED");
//! }
//! ```
//!
//! The only thing standing between a caller-chosen `guessOffchain` and the
//! returned swap amount is `isASmallerApproxB(.., .., approx.eps)` — an
//! **approximate** band whose width `eps` is *also* taken from the same caller
//! struct. There is no exact re-check (`require(f(result) == target)`) and no
//! residual bound that the contract controls. A guess that does not truly converge
//! — but happens to fall inside a wide `eps` band, or is on the on-chain-validated
//! path only when `guessOffchain == 0` — is trusted, and the returned `guess`
//! flows straight into the swap/mint that moves user funds.
//!
//! Contrast the on-chain variants in `MarketApproxLibOnchain.sol`
//! (`approxSwap...Onchain`): they take **no** `ApproxParams`, seed the search from
//! an on-chain `estimate...()` and a fixed `DEFAULT_EPS`, and so there is no
//! attacker-supplied guess to trust. This detector deliberately does not fire on
//! them — the discriminator is precisely *the caller-supplied guess struct
//! reaching a returned solver result with no exact re-check*.
//!
//! ## What we match
//!
//! A function that
//!   1. takes a parameter shaped like the off-chain guess struct — either typed
//!      `ApproxParams` (the real Pendle type), or a struct the body treats as one
//!      (it reads `guessMin` **and** `guessMax` **and** `guessOffchain` off it);
//!   2. contains an **iterative solver loop** (`for`/`while`/`do`) that advances a
//!      guess and whose convergence test is **approximate** — an `isAApproxB`-style
//!      comparator or a comparison against the struct's `eps` tolerance;
//!   3. **returns the solved guess** (a `return` inside the loop yielding the value
//!      the loop is converging) — that returned amount is what upstream router
//!      actions feed into the swap/mint.
//!
//! ## What suppresses it (the post-solve check that makes it safe)
//!
//! If the function re-checks the solved value **exactly** after / outside the
//! approximate loop — a `require`/`assert` with an exact equality (`==`/`!=`) on
//! the result, or an explicit residual assertion that is *not* the same
//! caller-supplied `eps` band (e.g. `require(f(result) <= tolerance)` against a
//! contract-owned bound) — then a non-converged guess cannot be trusted and we
//! stay silent.

use super::prelude::*;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function, Span, Stmt, StmtKind};

pub struct SolverConvergenceTrustDetector;

/// The off-chain guess struct's field names. A parameter whose body reads all
/// three is a guess-shaped struct even if the type alias differs from
/// `ApproxParams`.
const GUESS_FIELDS: &[&str] = &["guessmin", "guessmax", "guessoffchain"];

/// Names of approximate-equality comparators that judge convergence by a
/// tolerance band rather than exactly. The presence of one of these (or a bare
/// comparison against an `eps`/tolerance field) is the "loose convergence test"
/// signal.
const APPROX_COMPARATORS: &[&str] =
    &["isaapproxb", "isasmallerapproxb", "isaapproxbunchecked", "approxeq", "isapprox", "withintol"];

impl Detector for SolverConvergenceTrustDetector {
    fn id(&self) -> &'static str {
        "solver-convergence-trust"
    }
    fn category(&self) -> Category {
        Category::SolverConvergenceTrust
    }
    fn description(&self) -> &'static str {
        "Off-chain-supplied guess fed to an iterative solver whose result moves funds, with no post-solve residual/exact convergence re-check"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || f.is_modifier() || f.is_constructor() {
                continue;
            }

            // --- (1) Does it take an off-chain-supplied guess-shaped struct? ---
            let Some(guess_param) = guess_struct_param(f) else {
                continue;
            };

            // --- (2) Is there an iterative solver loop? ---
            // The loop that both advances a guess and returns a value — the
            // root-finding loop whose result is handed back to the caller.
            let Some(loop_body) = find_solver_loop(&f.body) else {
                continue;
            };

            // --- (3) The loop's convergence test is *approximate* (eps band). ---
            // Either a named approximate comparator, or a comparison that mentions
            // the struct's `eps`/tolerance field. A purely exact loop is not this
            // class (it already trusts nothing loose).
            if !loop_uses_approx_convergence(cx, loop_body, &guess_param) {
                continue;
            }

            // --- (4) The solved value is *returned* from inside the loop. ---
            // The returned amount is what upstream actions feed into the swap/mint.
            // We also capture the *identifiers* in that return expression — the
            // names of the solved value(s) — so the post-solve-check suppression
            // can require a re-check that actually references the result.
            let Some((ret_span, result_idents)) = return_inside_loop(loop_body) else {
                continue;
            };

            // --- (5) Suppression: an EXACT / residual re-check on the result. ---
            // If the function re-validates the *solved value* with an exact equality
            // or a non-eps residual bound (a `require`/`assert` that references one
            // of the returned result identifiers), a non-converged guess cannot slip
            // through — stay silent. The approximate `if (isAApproxB(...))` gate is
            // not a `require`, so it never counts as this re-check.
            if has_exact_postsolve_check(f, &result_idents) {
                continue;
            }

            // Confidence: the `ApproxParams`-typed signal is the precise Pendle
            // shape; a duck-typed guess struct is slightly looser. A fund-moving
            // function name (swap/mint/add-liquidity/approx) nudges it up.
            let typed = param_is_approx_params(f, &guess_param);
            let fund_name = moves_funds_name(&f.name);
            let mut confidence: f32 = if typed { 0.6 } else { 0.5 };
            if fund_name {
                confidence += 0.05;
            }

            let why_struct = if typed {
                "an `ApproxParams` struct (`guessMin`/`guessMax`/`guessOffchain`/`maxIteration`/`eps`)"
            } else {
                "a caller-supplied guess struct (`guessMin`/`guessMax`/`guessOffchain`)"
            };

            let b = report!(self, Category::SolverConvergenceTrust,
                title = "Iterative solver trusts an off-chain guess with no post-solve convergence/residual re-check",
                severity = Severity::Medium,
                confidence = confidence,
                dimensions = [Dimension::ValueFlow, Dimension::Invariant],
                message = format!(
                    "`{}` seeds an iterative solver from {}, and the only convergence gate is an \
                     *approximate* `eps`-band test (e.g. `isAApproxB(.., .., approx.eps)`) whose tolerance \
                     is taken from the same caller-supplied struct. The solved `guess` is returned directly \
                     and flows into the swap/mint amount that moves funds, with no post-loop exact re-check \
                     (`require(f(result) == target)`) or contract-owned residual bound. A crafted \
                     `guessOffchain` that does not truly converge — but falls inside a wide `eps` band, or \
                     takes the off-chain path that skips the on-chain `validateApprox` (run only when \
                     `guessOffchain == 0`) — is therefore trusted, letting a caller steer the executed \
                     amount away from the true solution of the AMM equation.",
                    f.name, why_struct
                ),
                recommendation =
                    "After the solver returns, re-evaluate the AMM equation at the chosen `guess` on-chain \
                     and assert the residual against a contract-owned tolerance — e.g. \
                     `require(PMath.isAApproxB(f(result), target, MAX_EPS))` with a hard-coded `MAX_EPS`, or \
                     an exact `require(netSyToPull <= exactSyIn)` invariant — so a non-converged or \
                     adversarial off-chain guess cannot be accepted. Validate `guessMin/guessMax/guessOffchain/eps` \
                     on the off-chain path too (not only when `guessOffchain == 0`), and bound `eps` by a \
                     protocol constant rather than trusting the caller's value.",
            );
            out.push(finish_at(cx, b, f.id, ret_span));
        }
        out
    }
}

// ----------------------------------------------------------------- (1) the param

/// True if `p`'s textual type is (or wraps) `ApproxParams` — the precise Pendle
/// off-chain guess struct.
fn param_is_approx_params(f: &Function, pname: &str) -> bool {
    f.params
        .iter()
        .find(|p| p.name.as_deref() == Some(pname))
        .map(|p| p.ty.to_ascii_lowercase().contains("approxparams"))
        .unwrap_or(false)
}

/// Find a parameter that is the off-chain-supplied *guess struct*: either typed
/// `ApproxParams`, or a struct parameter the body reads all three guess fields off
/// (`<p>.guessMin`, `<p>.guessMax`, `<p>.guessOffchain`). Returns the parameter
/// name so later checks can scope to "fields of *this* struct".
fn guess_struct_param(f: &Function) -> Option<String> {
    // (a) typed `ApproxParams` — the real shape.
    if let Some(p) = f
        .params
        .iter()
        .find(|p| p.ty.to_ascii_lowercase().contains("approxparams"))
    {
        if let Some(n) = &p.name {
            return Some(n.clone());
        }
    }
    // (b) duck-typed: a parameter whose members include all three guess fields.
    for p in &f.params {
        let Some(name) = p.name.as_deref() else { continue };
        if GUESS_FIELDS.iter().all(|fld| body_reads_member(f, name, fld)) {
            return Some(name.to_string());
        }
    }
    None
}

/// Does the body contain a `<base>.<member>` access whose root identifier is
/// `base` and whose member matches `member` (case-insensitive)? Casts on the base
/// are peeled (`a.b.guessMin` roots at `a`, so we match `member` against the
/// *immediate* member and the chain root against `base`).
fn body_reads_member(f: &Function, base: &str, member: &str) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Member { base: b, member: m } = &e.kind {
                if m.eq_ignore_ascii_case(member)
                    && root_ident_peeled(b).as_deref() == Some(base)
                {
                    found = true;
                }
            }
        });
    }
    found
}

// --------------------------------------------------------------- (2) solver loop

/// Find the body of an iterative solver loop: a `for`/`while`/`do-while` whose
/// body both (a) advances a guess (assigns/updates a local, or calls a
/// midpoint/clamp/step helper) and (b) returns a value. Returns the loop's body
/// statements (the innermost such loop) so later checks can scope to it.
fn find_solver_loop(stmts: &[Stmt]) -> Option<&[Stmt]> {
    let mut best: Option<&[Stmt]> = None;
    walk_loops(stmts, &mut |body| {
        if loop_advances_guess(body) && stmts_contain_return(body) && best.is_none() {
            best = Some(body);
        }
    });
    best
}

/// Visit the body of every loop in `stmts` (recursing through all statement
/// nesting). `f` is called once per loop body.
fn walk_loops<'a>(stmts: &'a [Stmt], f: &mut impl FnMut(&'a [Stmt])) {
    for s in stmts {
        match &s.kind {
            StmtKind::For { body, .. } | StmtKind::While { body, .. } | StmtKind::DoWhile { body, .. } => {
                f(body);
                walk_loops(body, f);
            }
            StmtKind::If { then_branch, else_branch, .. } => {
                walk_loops(then_branch, f);
                walk_loops(else_branch, f);
            }
            StmtKind::Block { stmts, .. } => walk_loops(stmts, f),
            StmtKind::Try { body, catches, .. } => {
                walk_loops(body, f);
                for c in catches {
                    walk_loops(&c.body, f);
                }
            }
            _ => {}
        }
    }
}

/// True if a loop body advances a numeric guess: it assigns to a local (a
/// `guess = ...` update) or calls a stepping helper (`calcMidpoint`,
/// `scaleClamp`, `moveGuessToMiddle`, `quickCalc`, `transition...`). This
/// distinguishes a root-finding loop from an incidental `for` (e.g. an event
/// emit loop).
fn loop_advances_guess(body: &[Stmt]) -> bool {
    let mut advances = false;
    for s in body {
        s.visit_exprs(&mut |e| {
            if advances {
                return;
            }
            match &e.kind {
                // `guess = ...` / `state.curGuess = ...` reassignment.
                ExprKind::Assign { target, .. } => {
                    if let Some(r) = root_ident_str(target) {
                        let l = r.to_ascii_lowercase();
                        if l.contains("guess") || l.contains("mid") || l.contains("state") {
                            advances = true;
                        }
                    } else if let ExprKind::Member { member, .. } = &target.kind {
                        let m = member.to_ascii_lowercase();
                        if m.contains("guess") || m.contains("range") || m.contains("mid") {
                            advances = true;
                        }
                    }
                }
                // A stepping helper call.
                ExprKind::Call(c) => {
                    if let Some(n) = &c.func_name {
                        let l = n.to_ascii_lowercase();
                        if l.contains("midpoint")
                            || l.contains("clamp")
                            || l.contains("transition")
                            || l.contains("moveguess")
                            || l.contains("quickcalc")
                            || l.contains("nextguess")
                            || l.contains("bisect")
                        {
                            advances = true;
                        }
                    }
                }
                _ => {}
            }
        });
        if advances {
            break;
        }
    }
    advances
}

/// True if `stmts` (a loop body) contains a `return <expr>;`.
fn stmts_contain_return(stmts: &[Stmt]) -> bool {
    find_return_expr(stmts).is_some()
}

// --------------------------------------------------- (3) approximate convergence

/// True if the loop body judges convergence *approximately*: it calls a named
/// approximate comparator (`isAApproxB`, …), or it has a comparison whose operand
/// subtree references the guess struct's `eps`/tolerance field. A loop that only
/// ever compares exactly (`==`) is not this loose-convergence class.
fn loop_uses_approx_convergence(cx: &AnalysisContext, body: &[Stmt], guess_param: &str) -> bool {
    let mut approx = false;
    for s in body {
        s.visit_exprs(&mut |e| {
            if approx {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if let Some(n) = &c.func_name {
                    let l = n.to_ascii_lowercase();
                    if APPROX_COMPARATORS.iter().any(|m| l == *m || l.contains(m)) {
                        approx = true;
                        return;
                    }
                    // A comparator that takes the struct's `eps` as an argument
                    // (any name) is an approximate test.
                    if c.args.iter().any(|a| mentions_eps(a, guess_param)) {
                        approx = true;
                    }
                }
            }
        });
        if approx {
            break;
        }
    }
    if approx {
        return true;
    }
    // Textual fallback over the loop's source: an `eps` reference inside the loop
    // body is the tolerance-band signal (covers comparators we did not enumerate).
    // Scoped to the loop span so we do not pick up an unrelated `eps` elsewhere.
    if let Some(sp) = loop_span(body) {
        let src = cx.source_text(sp).to_ascii_lowercase();
        if src.contains(".eps") || src.contains("approx") {
            return true;
        }
    }
    false
}

/// Does `e` reference the guess struct's `eps`/tolerance field
/// (`<guess_param>.eps`, or any `.eps`/`.tolerance` member)?
fn mentions_eps(e: &Expr, guess_param: &str) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if let ExprKind::Member { base, member } = &sub.kind {
            let m = member.to_ascii_lowercase();
            if m == "eps" || m == "tolerance" || m == "tol" {
                // Prefer a match rooted at the guess struct, but accept any `.eps`
                // (the solver's tolerance lives on the approx struct in practice).
                if root_ident_peeled(base).as_deref() == Some(guess_param)
                    || root_ident_peeled(base).is_some()
                {
                    found = true;
                }
            }
        }
    });
    found
}

// -------------------------------------------------------- (4) return inside loop

/// Span of the first value-returning `return <expr>;` inside `stmts` (recursing
/// through nested blocks/ifs/loops), together with the set of bare identifiers
/// that appear in that return expression — the names of the solved value(s). A
/// nested loop's return still counts as "the solver returns its result".
fn return_inside_loop(stmts: &[Stmt]) -> Option<(Span, Vec<String>)> {
    let e = find_return_expr(stmts)?;
    let mut idents: Vec<String> = Vec::new();
    e.0.visit(&mut |sub| {
        if let ExprKind::Ident(n) = &sub.kind {
            let l = n.to_ascii_lowercase();
            if !idents.contains(&l) {
                idents.push(l);
            }
        }
    });
    Some((e.1, idents))
}

/// Find the first value-returning `return e;` in `stmts`, returning a reference to
/// its expression and the statement span (recursing through control-flow nesting).
fn find_return_expr(stmts: &[Stmt]) -> Option<(&Expr, Span)> {
    for s in stmts {
        match &s.kind {
            StmtKind::Return(Some(e)) => return Some((e, s.span)),
            StmtKind::If { then_branch, else_branch, .. } => {
                if let Some(r) = find_return_expr(then_branch).or_else(|| find_return_expr(else_branch)) {
                    return Some(r);
                }
            }
            StmtKind::For { body, .. } | StmtKind::While { body, .. } | StmtKind::DoWhile { body, .. } => {
                if let Some(r) = find_return_expr(body) {
                    return Some(r);
                }
            }
            StmtKind::Block { stmts, .. } => {
                if let Some(r) = find_return_expr(stmts) {
                    return Some(r);
                }
            }
            StmtKind::Try { body, catches, .. } => {
                if let Some(r) = find_return_expr(body) {
                    return Some(r);
                }
                for c in catches {
                    if let Some(r) = find_return_expr(&c.body) {
                        return Some(r);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

// ----------------------------------------------------- (5) post-solve exact check

/// True if the function performs an EXACT / contract-owned residual re-check **on
/// the solved value** that makes a non-converged guess unusable. The credited
/// check is a `require`/`assert` (anywhere in the body — the safe pattern may
/// re-check just before returning the candidate or after the loop) that
///   * references one of the returned result identifiers (`result_idents` — the
///     solved value the loop produced), **and**
///   * either compares it with an exact equality (`==`/`!=`), or asserts a
///     residual/`abs(...)` bound on it.
///
/// Crucially we do **not** suppress on an equality that merely involves an
/// unrelated input (e.g. `require(market.totalLp != 0)`, a pre-condition on the
/// pool, not a re-check of the solved amount) — hence the re-check must touch a
/// result identifier — nor on an input-validation guard on the guess struct's own
/// fields (`require(guessMin <= guessMax)`). The approximate convergence gate
/// itself is an `if (isAApproxB(...))`, not a `require`, so it is never miscounted
/// as a safe re-check.
fn has_exact_postsolve_check(f: &Function, result_idents: &[String]) -> bool {
    let mut suppress = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if suppress {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            if !is_require_or_assert(c) {
                return;
            }
            let Some(arg) = c.args.first() else { return };
            // The re-check must reference the *solved value* (a returned result
            // identifier). A guard on an unrelated input (e.g. `totalLp != 0`,
            // `guessMin > guessMax`) does not validate convergence.
            if !expr_mentions_any_ident(arg, result_idents) {
                return;
            }
            // Input-validation guard on the guess struct's own fields? Not a check
            // of the solved output.
            if is_input_validation(arg) {
                return;
            }
            // Exact equality re-check (`==`/`!=`) on the result, or a residual/abs
            // bound on it.
            if expr_has_exact_equality(arg) || mentions_residual(arg) {
                suppress = true;
            }
        });
        if suppress {
            break;
        }
    }
    suppress
}

/// Does `e` contain a bare identifier whose lower-cased name is in `idents`?
fn expr_mentions_any_ident(e: &Expr, idents: &[String]) -> bool {
    if idents.is_empty() {
        return false;
    }
    let mut found = false;
    e.visit(&mut |sub| {
        if let ExprKind::Ident(n) = &sub.kind {
            if idents.contains(&n.to_ascii_lowercase()) {
                found = true;
            }
        }
    });
    found
}

/// Is this `require`/`assert` argument an **input-validation** comparison on the
/// guess struct's own fields (`guessMin > guessMax`, `eps > ONE`,
/// `guessMin > guessOffchain`, `hardBounds[0] <= hardBounds[1]`)? Such guards
/// validate the supplied range, not the solved output.
fn is_input_validation(arg: &Expr) -> bool {
    let mut hits_guess_field = false;
    arg.visit(&mut |sub| {
        if let ExprKind::Member { member, .. } = &sub.kind {
            let m = member.to_ascii_lowercase();
            if GUESS_FIELDS.contains(&m.as_str()) || m == "hardbounds" || m == "ranges" {
                hits_guess_field = true;
            }
        }
        if let ExprKind::Ident(n) = &sub.kind {
            let l = n.to_ascii_lowercase();
            if l.contains("hardbounds") || l == "eps" {
                hits_guess_field = true;
            }
        }
    });
    hits_guess_field
}

/// Does `e` contain an exact equality/inequality comparison (`==` / `!=`)?
fn expr_has_exact_equality(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if let ExprKind::Binary { op: BinOp::Eq | BinOp::Ne, .. } = &sub.kind {
            found = true;
        }
    });
    found
}

/// Does `e` reference a residual/error quantity or an `abs`-style call (a
/// post-solve residual bound that is not the caller's `eps` band)?
fn mentions_residual(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| match &sub.kind {
        ExprKind::Ident(n) => {
            let l = n.to_ascii_lowercase();
            if l.contains("residual") || l.contains("invariant") {
                found = true;
            }
        }
        ExprKind::Call(c) => {
            if let Some(n) = &c.func_name {
                let l = n.to_ascii_lowercase();
                if l == "abs" || l.contains("residual") {
                    found = true;
                }
            }
        }
        _ => {}
    });
    found
}

// ------------------------------------------------------------------- span utils

/// Span covering a loop body — from the first statement to the last. Used to
/// scope the textual `eps`/`approx` convergence-signal fallback to the loop.
fn loop_span(body: &[Stmt]) -> Option<Span> {
    let first = body.first()?.span;
    let last = body.last()?.span;
    Some(Span { start: first.start, end: last.end, file: first.file })
}

// --------------------------------------------------------------------- name hint

/// A function name that moves funds (swap / mint / add-liquidity / the Pendle
/// `approxSwap...` solver entry points). Used only to nudge confidence.
fn moves_funds_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    ["swap", "mint", "addliquidity", "approxswap", "redeem", "deposit", "borrow"]
        .iter()
        .any(|k| l.contains(k))
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable (Pendle `approxSwapExactSyForYtV2` shape): a caller-supplied
    // `ApproxParams` seeds a bisection loop; the only convergence gate is the
    // approximate `isASmallerApproxB(.., .., approx.eps)` band, and the solved
    // `guess` is returned straight out of the loop with no exact re-check.
    const VULN: &str = r#"
        struct ApproxParams { uint256 guessMin; uint256 guessMax; uint256 guessOffchain; uint256 maxIteration; uint256 eps; }
        library PMath {
            function isASmallerApproxB(uint256 a, uint256 b, uint256 eps) internal pure returns (bool) { return a <= b + eps; }
        }
        library MarketApprox {
            function getFirstGuess(ApproxParams memory approx) internal pure returns (uint256) {
                return approx.guessOffchain != 0 ? approx.guessOffchain : (approx.guessMin + approx.guessMax + 1) / 2;
            }
            function calcMidpoint(ApproxParams memory approx) internal pure returns (uint256) {
                return (approx.guessMin + approx.guessMax + 1) / 2;
            }
            function approxSwapExactSyForYtV2(uint256 exactSyIn, ApproxParams memory approx)
                internal pure returns (uint256, uint256)
            {
                uint256 guess = getFirstGuess(approx);
                for (uint256 iter = 0; iter < approx.maxIteration; ++iter) {
                    uint256 netSyToPull = guess * 2;
                    uint256 netSyFee = guess / 100;
                    if (netSyToPull <= exactSyIn) {
                        if (PMath.isASmallerApproxB(netSyToPull, exactSyIn, approx.eps)) {
                            return (guess, netSyFee);
                        }
                        if (approx.guessMin == guess) break;
                        approx.guessMin = guess;
                    } else {
                        approx.guessMax = guess - 1;
                    }
                    guess = calcMidpoint(approx);
                }
                revert("Slippage: APPROX_EXHAUSTED");
            }
        }
    "#;

    // Safe: same off-chain-guess solver, but once the approximate gate accepts a
    // candidate it re-checks the AMM equation EXACTLY on the solved value against a
    // contract-owned invariant (`require(netSyToPull == exactSyIn)`) before
    // returning it. A non-converged guess can no longer be trusted, so we stay
    // silent. (`netSyToPull` is one of the returned result's value-bearing names.)
    const SAFE_EXACT: &str = r#"
        struct ApproxParams { uint256 guessMin; uint256 guessMax; uint256 guessOffchain; uint256 maxIteration; uint256 eps; }
        library PMath {
            function isASmallerApproxB(uint256 a, uint256 b, uint256 eps) internal pure returns (bool) { return a <= b + eps; }
        }
        library MarketApprox {
            function calcMidpoint(ApproxParams memory approx) internal pure returns (uint256) {
                return (approx.guessMin + approx.guessMax + 1) / 2;
            }
            function approxSwapExactSyForYtV2(uint256 exactSyIn, ApproxParams memory approx)
                internal pure returns (uint256 guess)
            {
                guess = (approx.guessMin + approx.guessMax + 1) / 2;
                for (uint256 iter = 0; iter < approx.maxIteration; ++iter) {
                    uint256 netSyToPull = guess * 2;
                    if (PMath.isASmallerApproxB(netSyToPull, exactSyIn, approx.eps)) {
                        // post-solve EXACT re-check on the solved value before returning it.
                        require(guess * 2 == exactSyIn, "not converged");
                        return guess;
                    }
                    approx.guessMin = guess;
                    guess = calcMidpoint(approx);
                }
                revert("APPROX_EXHAUSTED");
            }
        }
    "#;

    // Negative control: the ON-CHAIN variant. It takes NO `ApproxParams` — the
    // search is seeded from an on-chain estimate and a fixed eps — so there is no
    // off-chain guess to trust. Must stay silent (the discriminator of the class).
    const SAFE_ONCHAIN: &str = r#"
        library PMath {
            function isASmallerApproxB(uint256 a, uint256 b, uint256 eps) internal pure returns (bool) { return a <= b + eps; }
        }
        library MarketApproxOnchain {
            uint256 constant DEFAULT_EPS = 5e13;
            function estimate(uint256 exactSyIn) internal pure returns (uint256) { return exactSyIn / 2; }
            function approxSwapExactSyForYtOnchain(uint256 exactSyIn)
                internal pure returns (uint256)
            {
                uint256 guess = estimate(exactSyIn);
                for (uint256 iter = 0; iter < 30; ++iter) {
                    uint256 netSyToPull = guess * 2;
                    if (PMath.isASmallerApproxB(netSyToPull, exactSyIn, DEFAULT_EPS)) {
                        return guess;
                    }
                    guess = guess + 1;
                }
                revert("Slippage: APPROX_EXHAUSTED");
            }
        }
    "#;

    // Negative control: an `ApproxParams`-typed input-validation helper. It reads
    // the guess fields but has NO solver loop returning a result — it only
    // validates the supplied range. Must stay silent.
    const SAFE_VALIDATE: &str = r#"
        struct ApproxParams { uint256 guessMin; uint256 guessMax; uint256 guessOffchain; uint256 maxIteration; uint256 eps; }
        library MarketApprox {
            function validateApprox(ApproxParams memory approx) internal pure {
                if (approx.guessMin > approx.guessMax || approx.eps > 1e18) revert("INVALID_APPROX_PARAMS");
            }
        }
    "#;

    #[test]
    fn fires_on_offchain_guess_solver() {
        let fs = run(VULN);
        assert!(
            fs.iter().any(|f| f.detector == "solver-convergence-trust"),
            "{:#?}",
            fs
        );
    }

    #[test]
    fn silent_when_exact_postsolve_check() {
        let fs = run(SAFE_EXACT);
        assert!(!fs.iter().any(|f| f.detector == "solver-convergence-trust"), "{:#?}", fs);
    }

    #[test]
    fn silent_on_onchain_variant() {
        let fs = run(SAFE_ONCHAIN);
        assert!(!fs.iter().any(|f| f.detector == "solver-convergence-trust"), "{:#?}", fs);
    }

    #[test]
    fn silent_on_input_validation_helper() {
        let fs = run(SAFE_VALIDATE);
        assert!(!fs.iter().any(|f| f.detector == "solver-convergence-trust"), "{:#?}", fs);
    }
}
