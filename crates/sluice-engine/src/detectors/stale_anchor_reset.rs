//! Stale implied-rate ANCHOR reset from a spot proportion after a dormancy gap.
//!
//! An AMM that prices off an *implied rate* keeps a running anchor
//! (`rateAnchor` / `lastImpliedRate` / `lastLnImpliedRate`) so that, between
//! trades, the quoted exchange rate evolves only by the carried rate and the
//! elapsed time — not by whoever last touched the pool. The hazard this detector
//! targets is the **re-anchoring step**: on the first interaction after a period
//! of dormancy the contract recomputes the anchor from the *current spot
//! proportion of the reserves*
//!
//! ```solidity
//! int256 newExchangeRate = _getExchangeRateFromImpliedRate(lastLnImpliedRate, timeToExpiry);
//! int256 proportion      = totalPt.divDown(totalPt + totalAsset);   // <- FRESH SPOT
//! int256 lnProportion    = _logProportion(proportion);
//! rateAnchor = newExchangeRate - lnProportion.divDown(rateScalar);  // <- anchor := f(spot)
//! ```
//!
//! `proportion` is read straight from the live reserves (`totalPt`,
//! `totalAsset`), with no time-weighted-average / observation-buffer / median
//! smoothing on that input. The carried `lastLnImpliedRate` is decayed over
//! `timeToExpiry` (the time-since-last-trade term), so after a dormancy gap the
//! carried component contributes little and the anchor effectively *snaps to the
//! instantaneous spot proportion*. A single attacker-sized trade (or flash-loan
//! imbalance) right before the re-anchoring therefore sets the anchor — and hence
//! every subsequent quote — to a manipulable spot value. This is the
//! `MarketMathCore._getRateAnchor` / Notional-style "rate anchor reset" class.
//!
//! ## What fires
//!
//! A function that **writes an implied-rate anchor** (`*Anchor` /
//! `*ImpliedRate` / a `*Rate` that names an anchor) from a **freshly-computed
//! reserve proportion** (a `Div`/`divDown` of one pooled reserve over a sum of
//! pooled reserves) while the same function carries a **time / last-update**
//! signal (`last*`, `timeToExpiry`, `blockTime`/`timestamp`, `secondsAgo`,
//! elapsed) — i.e. the reset is conditioned on time since the last update.
//!
//! ## What is suppressed (precision)
//!
//!   * the proportion that feeds the anchor is itself drawn from a **TWAP /
//!     observation buffer / median / moving average** (`observe`, `observation`,
//!     `cumulative`, `twap`, `median`, `movingAverage`, an OZ `Trace`/checkpoint
//!     container) — then it is not a spot value and the class does not apply;
//!   * the reset is **bounded / clamped** — a `min`/`max`/`clamp`/`bound` is
//!     applied to the proportion or the anchor, so a single trade cannot move it
//!     arbitrarily.
//!
//! The detector deliberately keys on the *anchor write fed by a spot
//! proportion*, not on any `Div` of reserves: ordinary pro-rata maths
//! (`amount * total / supply`) does not write a rate **anchor**, and the genuine
//! TWAP/observation path is excluded by the smoothing suppression above. Note
//! that Pendle keeps a real `OracleLib` observation buffer for a *separate*
//! lnImpliedRate oracle read; the trade-pricing anchor in `_getRateAnchor` does
//! **not** consult it, so the suppression is evaluated per-function on the
//! proportion's own source.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_ir::{AssignOp, BinOp, Expr, ExprKind, Function, Span};

use super::prelude::*;

pub struct StaleAnchorResetDetector;

impl Detector for StaleAnchorResetDetector {
    fn id(&self) -> &'static str {
        "stale-anchor-reset"
    }
    fn category(&self) -> sluice_findings::Category {
        sluice_findings::Category::StaleAnchorReset
    }
    fn description(&self) -> &'static str {
        "Implied-rate anchor (rateAnchor/lastImpliedRate) reset from the current spot reserve proportion on the first trade after dormancy, with no TWAP/median smoothing"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<sluice_findings::Finding> {
        use sluice_findings::{Category, Dimension, Severity};
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || f.is_modifier() || f.is_constructor() {
                continue;
            }
            // Pure interface/abstract declarations carry no logic.
            if cx.contract_of(f.id).map(|c| c.is_interface()).unwrap_or(false) {
                continue;
            }

            // (1) The function must WRITE an implied-rate anchor: an assignment
            //     target (or returned var) whose name reads like a rate anchor.
            let Some((anchor_span, anchor_value)) = find_anchor_write(f) else {
                continue;
            };

            // (2) The written anchor value must be derived from a freshly-computed
            //     SPOT PROPORTION of the reserves — a division of one pooled
            //     reserve over a sum/total of pooled reserves, computed inline in
            //     this function (not read back from a stored field).
            if !value_uses_spot_proportion(f, &anchor_value) {
                continue;
            }

            let src_l = cx.source_text(f.span).to_ascii_lowercase();

            // (3) The reset must be gated on TIME SINCE LAST UPDATE: a carried
            //     `last*` rate, an elapsed/`timeToExpiry` term, or a block-time /
            //     `secondsAgo` reference. This is what makes the reset trigger on
            //     the first trade after a dormancy gap.
            if !has_time_since_last_update(f, &src_l) {
                continue;
            }

            // --- precision suppression ---------------------------------------

            // 4a. The proportion is itself a TWAP / observation-buffer / median /
            //     moving-average read — not a spot value.
            if uses_smoothed_source(&src_l) {
                continue;
            }
            // Also exclude if the contract is fundamentally an observation/oracle
            // buffer whose own writes are the time-weighted accumulator (so a
            // `cumulative`/`observation` write is the average, not a spot anchor).
            if anchor_is_cumulative_accumulator(&anchor_value) {
                continue;
            }

            // 4b. The reset is bounded / clamped (min/max/clamp/bound on the
            //     proportion or anchor) — a single trade cannot move it freely.
            if reset_is_bounded(f, &src_l) {
                continue;
            }

            // Confidence: base on the strong shape (anchor-write ← spot proportion
            // ← time-gated). Lift when the carried value is explicitly a
            // `last*ImpliedRate`/`last*Rate` (the canonical re-anchor input) and
            // when a logit/log-proportion transform is present (the
            // implied-rate-curve fingerprint), which together make this
            // unmistakably an implied-rate anchor reset rather than incidental
            // reserve arithmetic.
            let mut confidence = 0.5_f32;
            if src_l.contains("lastlnimpliedrate")
                || src_l.contains("lastimpliedrate")
                || (src_l.contains("last") && src_l.contains("impliedrate"))
            {
                confidence += 0.06;
            }
            if src_l.contains("logproportion")
                || src_l.contains("ln(")
                || src_l.contains(".ln()")
                || src_l.contains("logit")
            {
                confidence += 0.04;
            }
            confidence = confidence.min(0.62);

            let b = report!(self, Category::StaleAnchorReset,
                title = "Implied-rate anchor reset from the spot reserve proportion after dormancy (no TWAP smoothing)",
                severity = Severity::Medium,
                confidence = confidence,
                dimensions = [Dimension::ValueFlow, Dimension::Frontier],
                message = format!(
                    "`{}` recomputes an implied-rate anchor (a `rateAnchor` / `lastImpliedRate`-style \
                     value) from the *current spot proportion of the reserves* (a `totalPt / (totalPt + \
                     totalAsset)`-shaped division of live balances) while gating on time since the last \
                     update (a carried `last*` rate decayed over the elapsed/`timeToExpiry` term). After \
                     a period of dormancy the carried component contributes little, so the anchor snaps \
                     to the instantaneous reserve proportion. There is no time-weighted-average / \
                     observation-buffer / median smoothing on that proportion, so a single trade (or a \
                     flash-loan-sized imbalance) executed immediately before the re-anchoring sets the \
                     anchor — and therefore every subsequent quote — to a manipulable spot value. This \
                     is the `MarketMathCore._getRateAnchor` / Notional-style implied-rate anchor-reset \
                     class.",
                    f.name
                ),
                recommendation =
                    "Do not seed the rate anchor from the instantaneous reserve proportion. Re-anchor \
                     from a time-weighted average / observation buffer (the same oracle accumulator the \
                     market already maintains for its lnImpliedRate), or bound the per-update anchor \
                     move (clamp the proportion / the resulting anchor to a band around the previous \
                     value) so that a single dormancy-gap trade cannot reset pricing to a manipulated \
                     spot. If a spot read is unavoidable, require a minimum number of observations / a \
                     minimum elapsed-but-bounded window before re-anchoring.",
            );
            out.push(finish_at(cx, b, f.id, anchor_span));
        }
        out
    }
}

// --------------------------------------------------------------------- helpers

/// A name that reads like an implied-rate *anchor* — the running pricing base an
/// AMM carries between trades. We require an `anchor` token, or an `impliedrate`
/// token, or a `rate` token *qualified* as a carried/last anchor value (so a bare
/// `feeRate` / `exchangeRate` local does not match). Kept on the lower-cased
/// identifier.
fn is_anchor_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    if l.contains("anchor") {
        return true;
    }
    if l.contains("impliedrate") {
        return true;
    }
    false
}

/// Find the first write of an anchor-named lvalue (an `Assign` whose target roots
/// at an anchor name, or a `VarDecl` of an anchor-named local with an
/// initializer), returning the write's span and the assigned value expression.
/// Also matches the `returns (int256 rateAnchor)` named-return idiom where the
/// anchor is produced by an `Assign`/`VarDecl` to that return name.
fn find_anchor_write(f: &Function) -> Option<(Span, Expr)> {
    // A named return that is anchor-like makes any assignment to it the "write".
    let returns_anchor = f
        .returns
        .iter()
        .any(|p| p.name.as_deref().map(is_anchor_name).unwrap_or(false));

    let mut found: Option<(Span, Expr)> = None;
    for s in &f.body {
        s.visit(&mut |st| {
            if found.is_some() {
                return;
            }
            match &st.kind {
                sluice_ir::StmtKind::VarDecl { name: Some(n), init: Some(init), .. }
                    if is_anchor_name(n) =>
                {
                    found = Some((st.span, init.clone()));
                }
                _ => {}
            }
            // Assignments live in expression position; scan them too.
            st.visit_exprs(&mut |e| {
                if found.is_some() {
                    return;
                }
                if let ExprKind::Assign { op: AssignOp::Assign, target, value } = &e.kind {
                    let tgt_is_anchor = root_ident_str(target)
                        .map(is_anchor_name)
                        .unwrap_or(false)
                        // assigning to the anchor-like named return
                        || (returns_anchor
                            && root_ident_str(target)
                                .map(|r| {
                                    f.returns.iter().any(|p| {
                                        p.name.as_deref() == Some(r) && is_anchor_name(r)
                                    })
                                })
                                .unwrap_or(false));
                    if tgt_is_anchor {
                        found = Some((e.span, (**value).clone()));
                    }
                }
            });
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// Reserve-pool tokens — the live balances whose ratio is the spot proportion.
fn is_reserve_token(t: &str) -> bool {
    // Pendle: totalPt / totalAsset / totalSy. General AMMs: reserve0/reserve1,
    // balance, total*, pooled.
    t.contains("totalpt")
        || t.contains("totalasset")
        || t.contains("totalsy")
        || t.contains("reserve")
        || t.contains("pooled")
        || (t.contains("total") && (t.contains("pt") || t.contains("sy") || t.contains("asset") || t.contains("supply") || t.contains("liquidity")))
        || t.contains("balance")
}

/// Lower-cased identifier / member / callee-name tokens reachable inside `e`.
fn name_tokens(e: &Expr) -> Vec<String> {
    let mut v = Vec::new();
    e.visit(&mut |n| match &n.kind {
        ExprKind::Ident(s) => v.push(s.to_ascii_lowercase()),
        ExprKind::Member { member, .. } => v.push(member.to_ascii_lowercase()),
        ExprKind::Call(c) => {
            if let Some(fname) = &c.func_name {
                v.push(fname.to_ascii_lowercase());
            }
        }
        _ => {}
    });
    v
}

/// Is `e` a *spot proportion of reserves* — a division `num / den` (a `Div`
/// BinOp, or a `divDown`/`divUp`/`mulDiv` proportion call) where the numerator is
/// a pooled reserve and the denominator is a sum/total of pooled reserves
/// (`totalPt + totalAsset`, `reserve0 + reserve1`, a `total*`)? This is the
/// `totalPt.divDown(totalPt + totalAsset)` fingerprint.
fn is_reserve_proportion(e: &Expr) -> bool {
    match &e.kind {
        // `num / den`
        ExprKind::Binary { op: BinOp::Div, lhs, rhs } => {
            proportion_operands_are_reserves(lhs, rhs)
        }
        // `num.divDown(den)` / `num.divUp(den)` — method form: receiver is num,
        // first arg is den.
        ExprKind::Call(c) => {
            let fname = c.func_name.as_deref().unwrap_or("").to_ascii_lowercase();
            let is_div_call = fname == "divdown" || fname == "divup" || fname == "rawdiv" || fname == "rawdivup";
            if is_div_call {
                if let (Some(recv), Some(den)) = (c.receiver.as_deref(), c.args.first()) {
                    return proportion_operands_are_reserves(recv, den);
                }
            }
            // `mulDiv(num, x, den)` free form where num and den are reserves.
            if fname == "muldiv" && c.args.len() >= 2 {
                let num = &c.args[0];
                let den = c.args.last().unwrap();
                return proportion_operands_are_reserves(num, den);
            }
            false
        }
        _ => false,
    }
}

/// The numerator must reference a reserve, and the denominator must read like a
/// *sum/total of reserves* (the proportion denominator). We require the
/// denominator to be either an additive combination touching reserves, or a
/// single `total*`/`pooled` aggregate — so `x / rateScalar` (divide by a scalar)
/// is NOT mistaken for a reserve proportion.
fn proportion_operands_are_reserves(num: &Expr, den: &Expr) -> bool {
    let num_tokens = name_tokens(num);
    let num_is_reserve = num_tokens.iter().any(|t| is_reserve_token(t));
    if !num_is_reserve {
        return false;
    }
    // Denominator: a sum (`a + b`) of reserves, OR a single pooled aggregate.
    let den_tokens = name_tokens(den);
    let den_touches_reserve = den_tokens.iter().any(|t| is_reserve_token(t));
    if !den_touches_reserve {
        return false;
    }
    // Reject "divide by a scalar/rate/scale" denominators even if they happen to
    // also mention a reserve token (rare): require the denominator to be additive
    // (a `+`/sum of pooled sides) OR a recognizable pool *total* aggregate.
    let den_is_sum = expr_contains_add(den);
    let den_is_total_aggregate = den_tokens
        .iter()
        .any(|t| t.contains("total") || t.contains("pooled") || t.contains("supply"));
    if !(den_is_sum || den_is_total_aggregate) {
        return false;
    }
    // Exclude obvious scalar/scaling denominators.
    let den_is_scalar = den_tokens.iter().any(|t| {
        t.contains("scalar") || t.contains("scale") || t.contains("wad") || t.contains("ray") || t.contains("precision")
    });
    !den_is_scalar
}

/// True if `e` contains an additive (`+`) combination anywhere (the
/// `totalPt + totalAsset` proportion denominator).
fn expr_contains_add(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |n| {
        if let ExprKind::Binary { op: BinOp::Add, .. } = &n.kind {
            found = true;
        }
    });
    found
}

/// Does the assigned anchor value (or a local it is computed from in `f`) embed a
/// spot reserve proportion? We check the value expression directly, and — because
/// re-anchoring usually computes `proportion` into a local first — also any
/// `VarDecl` initializer in `f` whose name is mentioned by the value.
fn value_uses_spot_proportion(f: &Function, value: &Expr) -> bool {
    // Direct: the anchor value itself contains the reserve proportion.
    let mut direct = false;
    value.visit(&mut |sub| {
        if !direct && is_reserve_proportion(sub) {
            direct = true;
        }
    });
    if direct {
        return true;
    }
    // Indirect: the value mentions a local (`proportion`, `lnProportion`) that is
    // assigned a reserve proportion (possibly through a `_logProportion(...)`
    // transform) elsewhere in the body.
    let value_idents: Vec<String> = {
        let mut v = Vec::new();
        value.visit(&mut |n| {
            if let ExprKind::Ident(s) = &n.kind {
                v.push(s.clone());
            }
            // also pull call-argument identifiers, e.g. _logProportion(proportion)
            if let ExprKind::Call(c) = &n.kind {
                for a in &c.args {
                    if let ExprKind::Ident(s) = &a.kind {
                        v.push(s.clone());
                    }
                }
            }
        });
        v
    };
    if value_idents.is_empty() {
        return false;
    }
    let mut indirect = false;
    // Build the transitive set of locals that carry a reserve proportion.
    let mut tainted: Vec<String> = Vec::new();
    // First pass: locals directly assigned a reserve proportion.
    collect_proportion_locals(f, &mut tainted);
    // Second pass: locals assigned from a tainted local (one hop is enough for
    // the `proportion -> lnProportion -> anchor` chain).
    let mut hop: Vec<String> = Vec::new();
    visit_local_writes(f, &mut |name, init| {
        let init_idents = ident_set(init);
        if init_idents.iter().any(|i| tainted.iter().any(|t| t == i)) {
            hop.push(name.to_string());
        }
    });
    tainted.extend(hop);
    for id in &value_idents {
        if tainted.iter().any(|t| t == id) {
            indirect = true;
        }
    }
    indirect
}

/// Collect names of locals (VarDecl or Assign) whose initializer/value embeds a
/// reserve proportion.
fn collect_proportion_locals(f: &Function, out: &mut Vec<String>) {
    visit_local_writes(f, &mut |name, init| {
        let mut has = false;
        init.visit(&mut |sub| {
            if !has && is_reserve_proportion(sub) {
                has = true;
            }
        });
        if has {
            out.push(name.to_string());
        }
    });
}

/// Visit `(name, init_expr)` for every `VarDecl { name, init }` and
/// `Assign { target = ident, value }` in `f`'s body.
fn visit_local_writes<'a>(f: &'a Function, cb: &mut impl FnMut(&'a str, &'a Expr)) {
    for s in &f.body {
        s.visit(&mut |st| {
            if let sluice_ir::StmtKind::VarDecl { name: Some(n), init: Some(init), .. } = &st.kind {
                cb(n, init);
            }
            st.visit_exprs(&mut |e| {
                if let ExprKind::Assign { target, value, .. } = &e.kind {
                    if let ExprKind::Ident(n) = &target.kind {
                        cb(n, value);
                    }
                }
            });
        });
    }
}

fn ident_set(e: &Expr) -> Vec<String> {
    let mut v = Vec::new();
    e.visit(&mut |n| {
        if let ExprKind::Ident(s) = &n.kind {
            v.push(s.clone());
        }
        if let ExprKind::Call(c) = &n.kind {
            for a in &c.args {
                if let ExprKind::Ident(s) = &a.kind {
                    v.push(s.clone());
                }
            }
        }
    });
    v
}

/// Is the reset conditioned on TIME SINCE THE LAST UPDATE? The fingerprint is one
/// of: a carried `last*` value (`lastLnImpliedRate`, `lastImpliedRate`,
/// `lastUpdate`), an elapsed / time-to-expiry term, or a block-time /
/// `secondsAgo` reference used in the rate computation. Combine a parameter/local
/// scan with a textual fallback (members like `market.lastLnImpliedRate`).
fn has_time_since_last_update(f: &Function, src_l: &str) -> bool {
    // Parameter names carrying the last-rate / elapsed signal.
    let param_signal = f.params.iter().any(|p| {
        p.name
            .as_deref()
            .map(|n| {
                let l = n.to_ascii_lowercase();
                l.starts_with("last")
                    || l.contains("lastimplied")
                    || l.contains("lastln")
                    || l.contains("timetoexpiry")
                    || l.contains("elapsed")
                    || l.contains("secondsago")
                    || l.contains("blocktime")
                    || l.contains("timestamp")
            })
            .unwrap_or(false)
    });
    if param_signal {
        return true;
    }
    // Textual fallback over the function body for member/local forms.
    src_l.contains("lastlnimpliedrate")
        || src_l.contains("lastimpliedrate")
        || src_l.contains("timetoexpiry")
        || src_l.contains("secondsago")
        || src_l.contains("lastupdate")
        || src_l.contains("lasttrade")
        || src_l.contains("elapsed")
        || (src_l.contains("last") && (src_l.contains("impliedrate") || src_l.contains("blocktimestamp") || src_l.contains("timestamp")))
        // `expiry - blockTime` / `block.timestamp - last*` elapsed subtraction.
        || (src_l.contains("blocktime") && src_l.contains("expiry"))
}

/// The proportion (or the anchor) is sourced from a time-weighted average /
/// observation buffer / median / moving average — not a spot value. Suppresses
/// the genuine TWAP path.
fn uses_smoothed_source(src_l: &str) -> bool {
    src_l.contains("observe")
        || src_l.contains("observation")
        || src_l.contains("cumulative")
        || src_l.contains("twap")
        || src_l.contains("median")
        || src_l.contains("movingaverage")
        || src_l.contains("moving_average")
        || src_l.contains("timeweighted")
        || src_l.contains("time_weighted")
        // OZ Trace/checkpoint accumulators used as the averaged source.
        || src_l.contains("trace.")
        || src_l.contains("trace2")
        || src_l.contains(".upperlookup")
}

/// True if the anchor write target is itself a *cumulative accumulator* (the
/// observation-buffer `transform` shape `cumulative + rate * dt`), which is the
/// average itself, not a spot anchor.
fn anchor_is_cumulative_accumulator(value: &Expr) -> bool {
    let toks = name_tokens(value);
    toks.iter().any(|t| t.contains("cumulative") || t.contains("observation"))
}

/// The reset is bounded / clamped, so a single trade cannot move it arbitrarily.
/// We look for a clamp helper or `min`/`max`/`bound`/`clamp` applied near the
/// anchor / proportion (textual, since the clamp is usually a helper call). A bare
/// `MAX_*PROPORTION` *revert guard* on the post-trade proportion is NOT a bound on
/// the re-anchor input, so we require an actual min/max/clamp *combinator*, not
/// just a comparison.
fn reset_is_bounded(f: &Function, src_l: &str) -> bool {
    // Textual clamp helpers / combinators.
    if src_l.contains(".clamp(")
        || src_l.contains("clamp(")
        || src_l.contains("boundedanchor")
        || src_l.contains("clampanchor")
        || src_l.contains("anchorbound")
    {
        return true;
    }
    // A `min(...)`/`max(...)` (or `Math.min`/`PMath.min`) call whose arguments
    // touch the anchor or a proportion — a true clamp of the re-anchor value.
    let mut bounded = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if bounded {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                let fname = c.func_name.as_deref().unwrap_or("").to_ascii_lowercase();
                if fname == "min" || fname == "max" || fname == "clamp" || fname == "bound" {
                    // arguments reference an anchor or proportion?
                    let touches = c.args.iter().any(|a| {
                        name_tokens(a).iter().any(|t| {
                            t.contains("anchor") || t.contains("proportion") || t.contains("impliedrate")
                        })
                    });
                    if touches {
                        bounded = true;
                    }
                }
            }
        });
        if bounded {
            break;
        }
    }
    bounded
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable — the Pendle `_getRateAnchor` shape: the return `rateAnchor` is
    // set from `newExchangeRate` (the carried `lastLnImpliedRate` decayed over
    // `timeToExpiry`) minus a fresh spot proportion `totalPt / (totalPt +
    // totalAsset)`. No TWAP/observation smoothing on that proportion, and the
    // reset is gated on the elapsed `timeToExpiry` / carried last rate.
    const VULN: &str = r#"
        library MarketMathCore {
            function _getRateAnchor(
                int256 totalPt,
                uint256 lastLnImpliedRate,
                int256 totalAsset,
                int256 rateScalar,
                uint256 timeToExpiry
            ) internal pure returns (int256 rateAnchor) {
                int256 newExchangeRate = _getExchangeRateFromImpliedRate(lastLnImpliedRate, timeToExpiry);
                int256 proportion = totalPt.divDown(totalPt + totalAsset);
                int256 lnProportion = _logProportion(proportion);
                rateAnchor = newExchangeRate - lnProportion.divDown(rateScalar);
            }
        }
    "#;

    // Safe — same anchor reset, but the proportion is read from a time-weighted
    // observation buffer (`observe(...)`), i.e. a real TWAP, so the smoothing
    // suppression must keep it silent.
    const SAFE_TWAP: &str = r#"
        library MarketMathCore {
            function _getRateAnchor(
                uint256 lastLnImpliedRate,
                int256 rateScalar,
                uint256 timeToExpiry,
                uint32 secondsAgo
            ) internal view returns (int256 rateAnchor) {
                int256 newExchangeRate = _getExchangeRateFromImpliedRate(lastLnImpliedRate, timeToExpiry);
                int256 twapProportion = observe(secondsAgo);
                int256 lnProportion = _logProportion(twapProportion);
                rateAnchor = newExchangeRate - lnProportion.divDown(rateScalar);
            }
        }
    "#;

    // Safe — the anchor is clamped: the freshly-computed proportion-derived anchor
    // is bounded against the previous anchor via `PMath.min`, so a single trade
    // cannot reset pricing arbitrarily.
    const SAFE_BOUNDED: &str = r#"
        library MarketMathCore {
            function _getRateAnchor(
                int256 totalPt,
                uint256 lastLnImpliedRate,
                int256 totalAsset,
                int256 rateScalar,
                uint256 timeToExpiry,
                int256 prevAnchor
            ) internal pure returns (int256 rateAnchor) {
                int256 newExchangeRate = _getExchangeRateFromImpliedRate(lastLnImpliedRate, timeToExpiry);
                int256 proportion = totalPt.divDown(totalPt + totalAsset);
                int256 lnProportion = _logProportion(proportion);
                int256 rawAnchor = newExchangeRate - lnProportion.divDown(rateScalar);
                rateAnchor = PMath.min(rawAnchor, prevAnchor);
            }
        }
    "#;

    // Negative control — ordinary pro-rata share maths. It divides reserves but it
    // does NOT write a rate ANCHOR, so the anchor-write gate excludes it.
    const SAFE_PRORATA: &str = r#"
        library Pool {
            function removeLiquidity(int256 lpToRemove, int256 totalSy, int256 totalLp)
                internal pure returns (int256 netSyToAccount)
            {
                netSyToAccount = (lpToRemove * totalSy) / totalLp;
            }
        }
    "#;

    // Negative control — writes a `rateAnchor`, but the value is a constant carry
    // (no fresh reserve proportion), so the spot-proportion gate excludes it.
    const SAFE_NO_PROPORTION: &str = r#"
        library MarketMathCore {
            function _getRateAnchor(uint256 lastLnImpliedRate, uint256 timeToExpiry)
                internal pure returns (int256 rateAnchor)
            {
                rateAnchor = _getExchangeRateFromImpliedRate(lastLnImpliedRate, timeToExpiry);
            }
        }
    "#;

    // Negative control — writes a rateAnchor from a fresh reserve proportion, but
    // there is NO time-since-last-update gating (no last*/elapsed/timeToExpiry),
    // so it is an instantaneous quote, not a dormancy-gap re-anchor. Suppressed.
    const SAFE_NO_TIME_GATE: &str = r#"
        library Quote {
            function spotAnchor(int256 totalPt, int256 totalAsset, int256 rateScalar)
                internal pure returns (int256 rateAnchor)
            {
                int256 proportion = totalPt.divDown(totalPt + totalAsset);
                rateAnchor = proportion.divDown(rateScalar);
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "stale-anchor-reset"), "{:#?}", fs);
    }

    #[test]
    fn silent_on_twap() {
        let fs = run(SAFE_TWAP);
        assert!(!fs.iter().any(|f| f.detector == "stale-anchor-reset"));
    }

    #[test]
    fn silent_on_bounded() {
        let fs = run(SAFE_BOUNDED);
        assert!(!fs.iter().any(|f| f.detector == "stale-anchor-reset"));
    }

    #[test]
    fn silent_on_prorata() {
        let fs = run(SAFE_PRORATA);
        assert!(!fs.iter().any(|f| f.detector == "stale-anchor-reset"));
    }

    #[test]
    fn silent_without_proportion() {
        let fs = run(SAFE_NO_PROPORTION);
        assert!(!fs.iter().any(|f| f.detector == "stale-anchor-reset"));
    }

    #[test]
    fn silent_without_time_gate() {
        let fs = run(SAFE_NO_TIME_GATE);
        assert!(!fs.iter().any(|f| f.detector == "stale-anchor-reset"));
    }
}
