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
//! The bug only bites when the trusted-but-unverified solved value **actually
//! moves funds**. A pure quoting / `view` solver that merely *returns* the guess to
//! an off-chain caller (Pendle's `router-static` `*Static` helpers, and the
//! `internal pure` `MarketApproxLib*` libraries themselves) cannot move a single
//! wei, so it is **not** this finding — it is at worst an off-chain mis-quote. We
//! therefore require the solved value to reach a value-moving sink **in the same
//! state-mutating function**, and recognise two shapes:
//!
//!   **(A) router call-site** — a state-mutating function that
//!     1. takes an off-chain guess struct (`ApproxParams` / `guessMin`+`guessMax`+
//!        `guessOffchain`) parameter, and
//!     2. hands that struct to a **solver call** (a callee named like
//!        `approxSwap…` / `solve…` / `bisect…`), and
//!     3. after that call performs a **fund-moving sink** — an ERC-20
//!        `transfer`/`transferFrom`/`safeTransfer`, a market `mint`/`burn`/`swap…`,
//!        a `_transferOut`/`_transferIn` router helper, or a `balances[..] += …`
//!        balance write. This is the real Pendle path
//!        (`ActionBase._swapExactSyForPt`, `ActionAddRemoveLiqV3.addLiquiditySinglePt`,
//!        …): `approxSwap…V2(…, guessPtOut)` → `IPMarket.swapSyForExactPt(…)` /
//!        `IPMarket.mint(…)`.
//!
//!   **(B) self-contained solver** — a state-mutating function that *inlines* the
//!     search: it takes the guess struct, contains an **iterative solver loop**
//!     whose only convergence test is **approximate** (an `isAApproxB`-style
//!     comparator or a comparison against the struct's `eps`), **returns the solved
//!     guess** from inside the loop, **and** moves funds with that solved value in
//!     its own body (a transfer / mint / `balances[..] += guess`).
//!
//! Either way the *discriminator* is the off-chain guess flowing into an executed,
//! fund-moving amount with no exact re-check — not the mere presence of an
//! `ApproxParams` parameter.
//!
//! ## What suppresses it (the safe shapes)
//!
//! * **No fund-moving sink reached by the solved value** — a `view`/`pure` solver
//!   or a function that solves but only returns/quotes the result. (Kills the 12
//!   `MarketApproxLib*` libraries and every `router-static` `*Static` helper.)
//! * **A post-solve exact / contract-owned residual re-check** on the solved value
//!   — a `require`/`assert` with an exact equality (`==`/`!=`) on the result, or a
//!   residual assertion that is *not* the same caller-supplied `eps` band (e.g.
//!   `require(f(result) == target)` / `require(residual <= MAX_EPS)`). A
//!   non-converged guess then cannot be trusted, so we stay silent. The approximate
//!   `if (isAApproxB(...))` gate is not a `require`, so it never counts.

use super::prelude::*;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{AssignOp, BinOp, CallKind, Expr, ExprKind, Function, Span, Stmt, StmtKind};

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

            // --- (2) A view/pure function cannot move funds, so the trusted guess
            // cannot steer an executed amount — it can only mis-quote off-chain.
            // This single gate drops every `internal pure` `MarketApproxLib*`
            // solver and every `view` `router-static` `*Static` quoting helper. ---
            if f.is_view_or_pure() {
                continue;
            }

            // --- (3) The solved value must reach a fund-moving sink *in this
            // function*. Two shapes (see module docs):
            //   (A) router call-site: the guess struct is handed to a solver call
            //       and a fund-moving sink follows it (the real Pendle router path);
            //   (B) self-contained: an inlined approximate solver loop returns the
            //       guess and the same body moves funds with it.
            // `result_idents` are the solved value's names (empty for shape A,
            // because Solidity tuple-destructuring of the solver call's return
            // erases the bound names in the IR) — used only to scope the post-solve
            // re-check suppression to the actual result. `report_span` anchors the
            // finding at the converging `return` (B) or the solver call (A). ---
            let Some(Matched { report_span, result_idents, shape }) =
                match_fund_moving_solver(cx, f, &guess_param)
            else {
                continue;
            };

            // --- (4) Suppression: an EXACT / residual re-check on the result. ---
            // If the function re-validates the *solved value* with an exact equality
            // or a non-eps residual bound (a `require`/`assert` that references one
            // of the returned result identifiers), a non-converged guess cannot slip
            // through — stay silent. The approximate `if (isAApproxB(...))` gate is
            // not a `require`, so it never counts as this re-check. (Shape A has no
            // recoverable result identifiers, so this never spuriously suppresses a
            // genuine router; routers gate output with a *slippage* `<`/`>` band, not
            // an exact equality on the solved amount.)
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
            let how_flow = match shape {
                Shape::CallSite =>
                    "hands that struct to an iterative solver call (`approxSwap…`) and then feeds the \
                     solved amount into a fund-moving sink (a market `swap`/`mint`/`burn` or a token \
                     `transfer`) in the same call",
                Shape::SelfContained =>
                    "seeds an inlined iterative solver loop from it whose only convergence gate is an \
                     *approximate* `eps`-band test (e.g. `isAApproxB(.., .., approx.eps)`), returns the \
                     converged `guess`, and moves funds with that amount in the same body",
            };

            let b = report!(self, Category::SolverConvergenceTrust,
                title = "Iterative solver trusts an off-chain guess with no post-solve convergence/residual re-check",
                severity = Severity::Medium,
                confidence = confidence,
                dimensions = [Dimension::ValueFlow, Dimension::Invariant],
                message = format!(
                    "`{}` takes {} and {}. The only convergence gate is an *approximate* `eps`-band test \
                     whose tolerance is taken from the same caller-supplied struct; the solved amount is \
                     used directly with no post-solve exact re-check (`require(f(result) == target)`) or \
                     contract-owned residual bound. A crafted `guessOffchain` that does not truly \
                     converge — but falls inside a wide `eps` band, or takes the off-chain path that skips \
                     the on-chain `validateApprox` (run only when `guessOffchain == 0`) — is therefore \
                     trusted, letting a caller steer the executed swap/mint amount away from the true \
                     solution of the AMM equation.",
                    f.name, why_struct, how_flow
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
            out.push(finish_at(cx, b, f.id, report_span));
        }
        out
    }
}

/// Which of the two fund-moving solver shapes matched (drives the message wording).
#[derive(Clone, Copy)]
enum Shape {
    /// Router call-site: guess struct → solver call → fund-moving sink.
    CallSite,
    /// Self-contained: inlined approximate solver loop returning a guess that moves
    /// funds in the same body.
    SelfContained,
}

/// A successful match: where to anchor the finding, the solved value's identifiers
/// (for scoping the post-solve re-check suppression), and which shape fired.
struct Matched {
    report_span: Span,
    result_idents: Vec<String>,
    shape: Shape,
}

/// Decide whether `f` (already known to take the guess struct `guess_param` and to
/// be state-mutating) is a fund-moving solver of either shape.
///
/// Shape **B** (self-contained) is tried first because it is the more specific
/// signal (an inlined approximate solver loop): if the body contains such a loop,
/// its convergence test is approximate, and the converged value reaches a
/// fund-moving sink in the same body, that is the finding — anchored at the
/// converging `return` if there is one, else at the loop. Otherwise shape **A**
/// (router call-site): the guess struct is passed whole to a solver call and a
/// fund-moving sink follows it.
fn match_fund_moving_solver(
    cx: &AnalysisContext,
    f: &Function,
    guess_param: &str,
) -> Option<Matched> {
    // (B) Self-contained inlined solver.
    if let Some(loop_body) = find_solver_loop(&f.body) {
        if loop_uses_approx_convergence(cx, loop_body, guess_param) {
            // The solved value(s): identifiers the loop converges — names returned
            // from inside the loop, plus locals the loop assigns (the advancing
            // guess and anything it is copied into, e.g. `netYtOut = guess`). The
            // converged value may be `return`ed from the loop (the library shape) or
            // `break` out and then move funds (the inlined-router shape), so we do
            // not require a return — only that one of these solved values reaches a
            // fund-moving sink in this body.
            let result_idents = solved_value_idents(loop_body, guess_param);
            if !result_idents.is_empty() && body_moves_funds_with(f, &result_idents) {
                let report_span = return_inside_loop(loop_body)
                    .map(|(sp, _)| sp)
                    .or_else(|| loop_span(loop_body))
                    .unwrap_or(f.span);
                return Some(Matched { report_span, result_idents, shape: Shape::SelfContained });
            }
        }
    }

    // (A) Router call-site: guess struct -> solver call -> fund-moving sink.
    if let Some(solver_span) = solver_call_taking(f, guess_param) {
        if fund_moving_sink_after(f, solver_span.start) {
            // Tuple-destructuring erases the bound result name in the IR, so there
            // are no result identifiers to scope the re-check suppression to.
            return Some(Matched { report_span: solver_span, result_idents: Vec::new(), shape: Shape::CallSite });
        }
    }

    None
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

/// Find the body of an iterative solver loop: a `for`/`while`/`do-while` whose body
/// **advances a guess** (assigns/updates a local, or calls a midpoint/clamp/step
/// helper). Returns the first such loop body (outermost-first) so later checks can
/// scope to it. We do *not* require the loop to itself `return` — a fund-moving
/// inlined solver typically `break`s out on convergence and moves funds with the
/// result *after* the loop. The approximate-convergence and fund-moving-sink gates
/// (applied by the caller) are what confirm this is the trusted-guess solver.
fn find_solver_loop(stmts: &[Stmt]) -> Option<&[Stmt]> {
    let mut best: Option<&[Stmt]> = None;
    walk_loops(stmts, &mut |body| {
        if loop_advances_guess(body) && best.is_none() {
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

/// The solved-value identifiers of a self-contained solver loop — the names the
/// loop converges on, so a downstream fund-moving sink / post-solve re-check can be
/// matched against them. Collected as:
///   * every bare identifier in a `return …;` inside the loop (the library shape
///     hands the result straight back), **and**
///   * the *local* lvalues the loop assigns (the advancing `guess`, and anything it
///     is copied into such as `netYtOut = guess` before a `break`) — i.e. the root
///     identifier of each `Assign` target / named `VarDecl` in the loop body, when
///     that root is a bare local and **not** the guess struct parameter itself
///     (so `approx.guessMin = guess` does not make `approx` a "solved value").
///
/// Lower-cased and de-duplicated.
fn solved_value_idents(loop_body: &[Stmt], guess_param: &str) -> Vec<String> {
    let mut idents: Vec<String> = Vec::new();
    let mut push = |n: &str| {
        let l = n.to_ascii_lowercase();
        if !l.is_empty() && l != guess_param.to_ascii_lowercase() && !idents.contains(&l) {
            idents.push(l);
        }
    };

    // (a) returns inside the loop.
    if let Some((_, ret)) = return_inside_loop(loop_body) {
        for n in ret {
            push(&n);
        }
    }

    // (b) locals the loop assigns. We walk the loop's statements directly so we see
    // `VarDecl` names (which `visit_exprs` does not surface) as well as `Assign`
    // targets, recursing through nested control flow.
    fn walk(stmts: &[Stmt], push: &mut impl FnMut(&str)) {
        for s in stmts {
            match &s.kind {
                StmtKind::VarDecl { name: Some(n), .. } => push(n),
                StmtKind::If { then_branch, else_branch, .. } => {
                    walk(then_branch, push);
                    walk(else_branch, push);
                }
                StmtKind::For { body, .. } | StmtKind::While { body, .. } | StmtKind::DoWhile { body, .. } => {
                    walk(body, push)
                }
                StmtKind::Block { stmts, .. } => walk(stmts, push),
                StmtKind::Try { body, catches, .. } => {
                    walk(body, push);
                    for c in catches {
                        walk(&c.body, push);
                    }
                }
                _ => {}
            }
            // Assignment targets (`guess = …`, `netYtOut = guess`) at any depth.
            s.visit_exprs(&mut |e| {
                if let ExprKind::Assign { target, .. } = &e.kind {
                    if let Some(r) = root_ident_str(target) {
                        push(r);
                    }
                }
            });
        }
    }
    walk(loop_body, &mut push);

    idents
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

// ---------------------------------------------------- fund-moving sink / flow (3)

/// Method names that *move funds*: ERC-20 transfers, market mint/burn/swap, and
/// the Pendle router's `_transferOut`/`_transferIn`/`_transferFrom` helpers. A call
/// to one of these is the value-moving sink the solved amount must reach — the
/// thing that distinguishes a genuine swap/mint path from a pure quote/`view`
/// solver that only returns the guess. Matched as a substring of the (lower-cased)
/// resolved callee name so wrapped/suffixed variants (`safeTransferFrom`,
/// `swapSyForExactPt`, `swapExactPtForSy`) are covered.
const FUND_SINK_CALLS: &[&str] = &[
    "transfer", "transferfrom", "safetransfer", "swap", "mint", "burn", "deposit", "withdraw", "redeem",
];

/// True if `c` is a call to a fund-moving sink (by resolved method name). Type
/// casts (`uint256(x)`) and `require`/`assert` builtins are never sinks. A
/// *solver* call (`approxSwap…`/`solve…`/`bisect…`) is also never counted as a
/// sink even though `approxSwap…` contains "swap": it produces the guess, it does
/// not move funds, so the genuine fund-moving sink the solved value reaches is a
/// *later, distinct* call (the actual `swapSyForExactPt`/`mint`).
fn is_fund_sink_call(c: &sluice_ir::Call) -> bool {
    if matches!(c.kind, CallKind::TypeCast) || is_require_or_assert(c) {
        return false;
    }
    let Some(n) = &c.func_name else { return false };
    let l = n.to_ascii_lowercase();
    if ["approx", "solve", "bisect", "search", "newton"].iter().any(|k| l.contains(k)) {
        return false;
    }
    FUND_SINK_CALLS.iter().any(|k| l.contains(k))
}

/// Is `target` an lvalue rooted at a balance-like state slot (`balances[..]`,
/// `balanceOf[..]`, `<x>.balance = …`)? A `+=`/`-=`/`=` write to such a slot is a
/// fund-moving sink that does not go through a call.
fn is_balance_lvalue(target: &Expr) -> bool {
    let mut hit = false;
    target.visit(&mut |sub| match &sub.kind {
        ExprKind::Ident(n) => {
            let l = n.to_ascii_lowercase();
            if l.contains("balance") || l == "shares" || l.contains("reserve") {
                hit = true;
            }
        }
        ExprKind::Member { member, .. } => {
            let m = member.to_ascii_lowercase();
            if m.contains("balance") || m == "shares" {
                hit = true;
            }
        }
        _ => {}
    });
    hit
}

/// Walk every fund-moving sink in `f`'s body, calling `visit(args, span)` with the
/// sink's argument expressions and its span. Covers both call sinks (the args are
/// the call arguments) and balance-write sinks (the args are the assigned value).
fn visit_fund_sinks<'a>(f: &'a Function, mut visit: impl FnMut(&'a [Expr], Span)) {
    for s in &f.body {
        s.visit_exprs(&mut |e| match &e.kind {
            ExprKind::Call(c) if is_fund_sink_call(c) => visit(&c.args, e.span),
            ExprKind::Assign { op, target, value }
                if matches!(op, AssignOp::Add | AssignOp::Sub | AssignOp::Assign)
                    && is_balance_lvalue(target) =>
            {
                visit(std::slice::from_ref(value.as_ref()), e.span);
            }
            _ => {}
        });
    }
}

/// (Shape A) Is there a fund-moving sink that occurs *after* byte offset `after`?
/// Ordering (the sink follows the solver call) is the cheap, faithful proxy for
/// "the solved value flows forward into the sink" — Solidity tuple-destructuring
/// erases the bound result name in the IR, so we cannot link them by identifier.
fn fund_moving_sink_after(f: &Function, after: u32) -> bool {
    let mut found = false;
    visit_fund_sinks(f, |_args, span| {
        if span.start > after {
            found = true;
        }
    });
    found
}

/// (Shape B) Does the body move funds *with the solved value*? A fund-moving sink
/// whose argument expressions mention one of the solved-value identifiers
/// (`result_idents`), or — because the converged `guess` is frequently re-derived
/// into the transferred amount — a `balances[..] +=`/transfer whose value mentions
/// a `guess`-named local. Requires a non-empty `result_idents` (a self-contained
/// solver always has them; if it somehow does not, there is nothing to trace).
fn body_moves_funds_with(f: &Function, result_idents: &[String]) -> bool {
    if result_idents.is_empty() {
        return false;
    }
    let mut found = false;
    visit_fund_sinks(f, |args, _span| {
        if found {
            return;
        }
        if args.iter().any(|a| expr_mentions_any_ident(a, result_idents)) {
            found = true;
        }
    });
    found
}

/// (Shape A) Span of the first call in `f` that *is* an iterative solver — a call
/// that **returns** a solved guess — to which the off-chain guess struct
/// `guess_param` is passed *whole* as an argument. This is the router's
/// `_readMarket(market).approxSwap…V2(…, guessPtOut)` call site.
///
/// "Solver" is recognised by a name reading like `approxSwap…`/`solve…`/`bisect…`/
/// `search…`/`newton…`, **excluding** the approximate-*comparator* helpers
/// (`isAApproxB`, `approxEq`, …) — those judge convergence and return a `bool`, they
/// do not produce a guess, and the struct is only ever handed to them as the `.eps`
/// field, not whole.
fn solver_call_taking(f: &Function, guess_param: &str) -> Option<Span> {
    first_call_where_span(f, |c| {
        let Some(n) = &c.func_name else { return false };
        let l = n.to_ascii_lowercase();
        if APPROX_COMPARATORS.iter().any(|m| l == *m || l.contains(m)) {
            return false;
        }
        let looks_like_solver = ["approxswap", "solve", "bisect", "search", "newton"]
            .iter()
            .any(|k| l.contains(k));
        looks_like_solver && c.args.iter().any(|a| expr_passes_struct(a, guess_param))
    })
}

/// Does `e` pass the guess struct `guess_param` **itself** (the whole struct, e.g.
/// `approxSwap…(.., guessPtOut)`) — the bare parameter or a cast of it? A *field*
/// access (`approx.eps`) is deliberately **not** a match: handing a tolerance field
/// to a comparator is not handing the guess struct to a solver.
fn expr_passes_struct(e: &Expr, guess_param: &str) -> bool {
    matches!(&peel_casts(e).kind, ExprKind::Ident(n) if n == guess_param)
}

/// [`first_call_where`](super::prelude::first_call_where)-style scan that returns
/// the matching call's span. (The prelude helper takes `FnMut(&Call)`; we need the
/// span of the matched call, so this is the local variant.)
fn first_call_where_span(f: &Function, mut pred: impl FnMut(&sluice_ir::Call) -> bool) -> Option<Span> {
    for s in &f.body {
        let mut hit: Option<Span> = None;
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if pred(c) {
                    hit = Some(e.span);
                }
            }
        });
        if hit.is_some() {
            return hit;
        }
    }
    None
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

    // Vulnerable (Pendle `approxSwapExactSyForYtV2` shape, inlined into a
    // state-mutating action — "shape B"): a caller-supplied `ApproxParams` seeds a
    // bisection loop; the only convergence gate is the approximate
    // `isASmallerApproxB(.., .., approx.eps)` band; the converged `guess` is
    // returned from inside the loop AND the same body moves funds with it
    // (`balanceOf[...] += guess` / `transfer(.., guess)`) with no exact re-check.
    const VULN: &str = r#"
        struct ApproxParams { uint256 guessMin; uint256 guessMax; uint256 guessOffchain; uint256 maxIteration; uint256 eps; }
        library PMath {
            function isASmallerApproxB(uint256 a, uint256 b, uint256 eps) internal pure returns (bool) { return a <= b + eps; }
        }
        interface IToken { function transfer(address to, uint256 amount) external returns (bool); }
        contract Action {
            mapping(address => uint256) public balanceOf;
            IToken public sy;
            function getFirstGuess(ApproxParams memory approx) internal pure returns (uint256) {
                return approx.guessOffchain != 0 ? approx.guessOffchain : (approx.guessMin + approx.guessMax + 1) / 2;
            }
            function calcMidpoint(ApproxParams memory approx) internal pure returns (uint256) {
                return (approx.guessMin + approx.guessMax + 1) / 2;
            }
            function swapExactSyForYt(uint256 exactSyIn, ApproxParams memory approx)
                external returns (uint256 netYtOut)
            {
                uint256 guess = getFirstGuess(approx);
                for (uint256 iter = 0; iter < approx.maxIteration; ++iter) {
                    uint256 netSyToPull = guess * 2;
                    if (netSyToPull <= exactSyIn) {
                        if (PMath.isASmallerApproxB(netSyToPull, exactSyIn, approx.eps)) {
                            netYtOut = guess;
                            break;
                        }
                        if (approx.guessMin == guess) break;
                        approx.guessMin = guess;
                    } else {
                        approx.guessMax = guess - 1;
                    }
                    guess = calcMidpoint(approx);
                }
                // the solved `netYtOut` moves funds with no post-solve exact re-check.
                balanceOf[msg.sender] += netYtOut;
                sy.transfer(msg.sender, netYtOut);
            }
        }
    "#;

    // Safe: same off-chain-guess solver that *does* move funds with the solved
    // value, but once the approximate gate accepts a candidate it re-checks the AMM
    // equation EXACTLY on the solved value against a contract-owned invariant
    // (`require(netYtOut * 2 == exactSyIn)`) before using it. A non-converged guess
    // can no longer be trusted, so we stay silent — proving it is the *exact
    // re-check* (not the absence of a sink) that suppresses.
    const SAFE_EXACT: &str = r#"
        struct ApproxParams { uint256 guessMin; uint256 guessMax; uint256 guessOffchain; uint256 maxIteration; uint256 eps; }
        library PMath {
            function isASmallerApproxB(uint256 a, uint256 b, uint256 eps) internal pure returns (bool) { return a <= b + eps; }
        }
        interface IToken { function transfer(address to, uint256 amount) external returns (bool); }
        contract Action {
            mapping(address => uint256) public balanceOf;
            IToken public sy;
            function calcMidpoint(ApproxParams memory approx) internal pure returns (uint256) {
                return (approx.guessMin + approx.guessMax + 1) / 2;
            }
            function swapExactSyForYt(uint256 exactSyIn, ApproxParams memory approx)
                external returns (uint256 netYtOut)
            {
                uint256 guess = (approx.guessMin + approx.guessMax + 1) / 2;
                for (uint256 iter = 0; iter < approx.maxIteration; ++iter) {
                    uint256 netSyToPull = guess * 2;
                    if (PMath.isASmallerApproxB(netSyToPull, exactSyIn, approx.eps)) {
                        netYtOut = guess;
                        break;
                    }
                    approx.guessMin = guess;
                    guess = calcMidpoint(approx);
                }
                // post-solve EXACT re-check on the solved value before using it.
                require(netYtOut * 2 == exactSyIn, "not converged");
                balanceOf[msg.sender] += netYtOut;
                sy.transfer(msg.sender, netYtOut);
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

    // Router "shape A" (the genuine on-chain fund-moving path, à la
    // `ActionBase._swapExactSyForPt`): a *state-mutating* action hands the caller's
    // `ApproxParams` to an `approxSwap…` solver call, then feeds the solved amount
    // straight into a market `swapSyForExactPt` and `mint` that move funds. Must
    // FIRE — even though the iterative loop itself lives in the (separate) library,
    // because the off-chain guess steers an executed swap/mint amount here.
    const SWAP_WITH_APPROX: &str = r#"
        struct ApproxParams { uint256 guessMin; uint256 guessMax; uint256 guessOffchain; uint256 maxIteration; uint256 eps; }
        interface IPMarket {
            function swapSyForExactPt(address r, uint256 a, bytes calldata b) external returns (uint256, uint256);
            function mint(address r, uint256 sy, uint256 pt) external returns (uint256, uint256, uint256);
        }
        library MarketApprox {
            function approxSwapExactSyForPtV2(uint256 exactSyIn, ApproxParams memory approx)
                internal pure returns (uint256, uint256) { return (approx.guessOffchain, 0); }
        }
        contract Action {
            using MarketApprox for uint256;
            function swapExactSyForPt(address market, uint256 exactSyIn, ApproxParams calldata guessPtOut)
                external returns (uint256 netPtOut, uint256 netSyFee)
            {
                (uint256 netPtOutMarket,) = exactSyIn.approxSwapExactSyForPtV2(guessPtOut);
                (, uint256 fee) = IPMarket(market).swapSyForExactPt(msg.sender, netPtOutMarket, "");
                IPMarket(market).mint(msg.sender, netPtOutMarket, 0);
                netPtOut = netPtOutMarket;
                netSyFee = fee;
            }
        }
    "#;

    // Negative control (the pure quote/`view` path, à la `router-static`
    // `swapExactSyForPtStatic`): a *view* helper hands the (default) `ApproxParams`
    // to the same `approxSwap…` solver and even calls a `swap…`-named *library*
    // method on an in-memory `MarketState` to compute a quote. It cannot move a
    // single wei, so it must stay SILENT — this is the false positive the
    // fund-moving-sink requirement removes.
    const VIEW_ONLY_APPROX: &str = r#"
        struct ApproxParams { uint256 guessMin; uint256 guessMax; uint256 guessOffchain; uint256 maxIteration; uint256 eps; }
        struct MarketState { uint256 totalPt; }
        library MarketMathCore {
            function approxSwapExactSyForPt(MarketState memory s, uint256 exactSyIn, ApproxParams memory approx)
                internal pure returns (uint256, uint256, uint256) { return (approx.guessOffchain, 0, 0); }
            function swapSyForExactPt(MarketState memory s, uint256 netPtOut) internal pure returns (uint256) { return netPtOut; }
        }
        contract LensStatic {
            using MarketMathCore for MarketState;
            ApproxParams public defaultApproxParams;
            function swapExactSyForPtStatic(MarketState memory state, uint256 exactSyIn)
                public view returns (uint256 netPtOut, uint256 netSyFee, uint256 exchangeRateAfter)
            {
                (netPtOut, netSyFee,) = state.approxSwapExactSyForPt(exactSyIn, defaultApproxParams);
                // a `swap`-named *library* call on a memory struct — a quote, not a transfer.
                exchangeRateAfter = state.swapSyForExactPt(netPtOut);
            }
        }
    "#;

    // Negative control (the `MarketApproxLib*` library itself): a *pure* solver with
    // the exact vulnerable loop shape — approximate `isASmallerApproxB` gate, returns
    // the converged `guess` — but it only *returns* the result; it moves no funds in
    // its own body. Must stay SILENT (it is at worst an off-chain mis-quote). This is
    // the bulk of the suppressed Pendle firings.
    const PURE_SOLVER_NO_SINK: &str = r#"
        struct ApproxParams { uint256 guessMin; uint256 guessMax; uint256 guessOffchain; uint256 maxIteration; uint256 eps; }
        library PMath {
            function isASmallerApproxB(uint256 a, uint256 b, uint256 eps) internal pure returns (bool) { return a <= b + eps; }
        }
        library MarketApprox {
            function calcMidpoint(ApproxParams memory approx) internal pure returns (uint256) {
                return (approx.guessMin + approx.guessMax + 1) / 2;
            }
            function approxSwapExactSyForYtV2(uint256 exactSyIn, ApproxParams memory approx)
                internal pure returns (uint256, uint256)
            {
                uint256 guess = approx.guessOffchain != 0 ? approx.guessOffchain : calcMidpoint(approx);
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

    #[test]
    fn fires_on_offchain_guess_solver() {
        let fs = run(VULN);
        assert!(
            fs.iter().any(|f| f.detector == "solver-convergence-trust"),
            "{:#?}",
            fs
        );
    }

    // The new discriminator pair: a view-only approx solver is silent while the
    // state-mutating swap-with-approx path fires.
    #[test]
    fn fires_on_router_swap_with_approx() {
        let fs = run(SWAP_WITH_APPROX);
        assert!(
            fs.iter().any(|f| f.detector == "solver-convergence-trust"),
            "{:#?}",
            fs
        );
    }

    #[test]
    fn silent_on_view_only_approx_quote() {
        let fs = run(VIEW_ONLY_APPROX);
        assert!(!fs.iter().any(|f| f.detector == "solver-convergence-trust"), "{:#?}", fs);
    }

    #[test]
    fn silent_on_pure_solver_without_fund_sink() {
        let fs = run(PURE_SOLVER_NO_SINK);
        assert!(!fs.iter().any(|f| f.detector == "solver-convergence-trust"), "{:#?}", fs);
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
