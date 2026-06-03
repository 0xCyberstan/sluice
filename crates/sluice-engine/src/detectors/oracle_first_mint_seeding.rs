//! Oracle/TVL first-mint seeding — an LST / vault share-mint amount is priced by
//! an *exchange rate over a TVL* (`supply * newValue / currentTVL`) but the only
//! thing standing between an attacker and an arbitrary mint ratio is a **literal
//! first-mint short-circuit** (`if (tvl == 0 || supply == 0) return newValue;`).
//!
//! This is the oracle/TVL-driven sibling of the balance-driven first-depositor
//! inflation in `vault.rs`. There the share price comes from a *donatable
//! balance* (`balanceOf(address(this))` / `totalAssets`); here it comes from a
//! *protocol value / supply pair* threaded in as arguments (the Renzo
//! `RenzoOracle.calculateMintAmount(currentValueInProtocol, newValueAdded,
//! existingEzETHSupply)` shape, or any `convertToShares`-style helper that prices
//! a deposit by `totalSupply * amount / totalValue`).
//!
//! The bug has two halves, both of which must be present:
//!
//!   1. a **proportional exchange-rate mint** — a division `num / den` where the
//!      divisor `den` is the current TVL / total value and the numerator multiplies
//!      the share supply by the incoming value (`supply * newValue / tvl`), so the
//!      minted amount scales as `amount * supply / tvl`; and
//!   2. the only protection is a **literal first-mint short-circuit** — an early
//!      `if (tvl == 0 || supply == 0) return newValue;` (or `... return amount;`)
//!      that compares the very TVL/supply variables used in the ratio against the
//!      integer literal `0`.
//!
//! Why that guard is not enough:
//!   * **re-emptyable.** The check is "is the pool currently empty?", not "has the
//!     pool *ever* been seeded?". A full withdraw, a redeem-to-zero, or a slashing
//!     event can drive TVL (or supply) back to ~0, re-arming the
//!     `return newValue` branch for a fresh attacker who again sets the rate;
//!   * **extreme-ratio gameable.** Even on the genuine first mint, seeding a tiny
//!     supply against a large value (or vice-versa) fixes an extreme exchange rate.
//!     A later depositor's `amount * supply / tvl` then truncates toward zero —
//!     classic share-inflation — letting the seeder capture rounding dust across
//!     every subsequent deposit.
//!
//! The robust fix is a value that *cannot be re-emptied*: a permanent
//! virtual-shares / dead-shares offset added to supply and TVL in the ratio, or a
//! one-time minimum-liquidity lock burned on the first mint (Uniswap-V2
//! `MINIMUM_LIQUIDITY`). When such an offset/lock is present in the same function
//! we **suppress** — the literal `== 0` branch is then either dead or harmless.
//!
//! Precision strategy (single ValueFlow finding, Medium @ 0.5):
//!   * we fire **only** when both halves are tied to the *same* TVL/supply
//!     variables: the divisor of the ratio is a variable that the first-mint guard
//!     compares `== 0`, and the guard also `== 0`-checks the supply factor of the
//!     numerator. Requiring the guard and the ratio to talk about the same two
//!     operands is what separates this from an ordinary "divide by a parameter"
//!     and an ordinary "early return on a zero argument";
//!   * a virtual-offset (`+ 1` / `+ VIRTUAL_*` on the ratio operands), a
//!     dead-shares / minimum-liquidity marker, or an `mulDiv`-with-offset in the
//!     same function suppresses;
//!   * pure interfaces and bodies without the ratio are never reported.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function, Lit, Span, Stmt, StmtKind};

pub struct OracleFirstMintSeedingDetector;

impl Detector for OracleFirstMintSeedingDetector {
    fn id(&self) -> &'static str {
        "oracle-first-mint-seeding"
    }
    fn category(&self) -> Category {
        Category::OracleFirstMintSeeding
    }
    fn description(&self) -> &'static str {
        "LST/share mint priced by an oracle/TVL exchange rate (supply * value / TVL) guarded only by a \
         literal first-mint check (if tvl==0 || supply==0 return value) — re-emptyable and extreme-ratio \
         gameable (Renzo RenzoOracle.calculateMintAmount class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // A pure interface declaration has no body to price anything.
            if cx.contract_of(f.id).map(|c| c.is_interface()).unwrap_or(false) {
                continue;
            }

            // ---- (1) the proportional exchange-rate mint ratio --------------
            // `num / den` where `den` is the TVL/total-value divisor and `num`
            // multiplies a supply-like factor by the incoming value. We capture the
            // divisor var and the set of variables multiplied in the numerator.
            let Some(ratio) = find_exchange_rate_ratio(f) else { continue };

            // ---- (2) the literal first-mint short-circuit -------------------
            // An early `if (... == 0 ...) return X;` whose `== 0` operands include
            // the ratio divisor AND a numerator factor (the supply). Requiring both
            // the TVL var and the supply var to be the guarded operands is what ties
            // this to the exchange-rate ratio rather than an incidental zero-return.
            let Some(guard) = find_first_mint_guard(f, &ratio) else { continue };

            // ---- suppression: a permanent offset / min-liquidity lock -------
            // A virtual-shares / dead-shares offset or a minimum-liquidity lock makes
            // the pool un-re-emptyable, so the literal `== 0` branch is dead/harmless.
            if has_offset_or_lock(cx, f, &ratio) {
                continue;
            }

            let span = guard.return_span.unwrap_or(f.span);
            let b = FindingBuilder::new(self.id(), Category::OracleFirstMintSeeding)
                .title("Mint amount priced by a TVL exchange rate, guarded only by a literal first-mint check")
                .severity(Severity::Medium)
                .confidence(0.55)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{fname}` computes a mint/share amount from an exchange rate over the protocol's total \
                     value — `{supply} * {value} / {tvl}` — and the only thing guarding that ratio is the \
                     literal first-mint short-circuit `if ({tvl} == 0 || {supply} == 0) return {value};`. That \
                     check asks \"is the pool empty *right now*\", not \"has the pool ever been seeded\", so it \
                     is **re-emptyable**: a full withdraw, a redeem-to-zero, or a slashing event can drive \
                     `{tvl}` (or `{supply}`) back to ~0 and re-arm the `return {value}` branch for a fresh \
                     attacker, who again fixes the exchange rate by seeding one unit against an arbitrary \
                     value. Even on the genuine first mint the rate is **extreme-ratio gameable**: seeding a \
                     tiny `{supply}` against a large `{value}` (or vice-versa) makes every later depositor's \
                     `amount * {supply} / {tvl}` truncate toward zero, so the seeder harvests rounding dust \
                     from all subsequent mints. This is the oracle/TVL-driven first-mint seeding class (Renzo \
                     `RenzoOracle.calculateMintAmount`).",
                    fname = f.name,
                    supply = ratio.supply_factor.as_deref().unwrap_or("supply"),
                    value = guard.return_var.as_deref().unwrap_or("newValue"),
                    tvl = ratio.divisor,
                ))
                .recommendation(
                    "Replace the re-emptyable `== 0` short-circuit with a value that cannot be driven back to \
                     zero: add a permanent virtual-shares / dead-shares offset to both the supply and the TVL \
                     in the ratio (price as `(supply + OFFSET) * amount / (tvl + OFFSET)`), or burn a one-time \
                     minimum-liquidity amount on the first mint (Uniswap-V2 `MINIMUM_LIQUIDITY`) so an \
                     attacker can never re-seed the exchange rate or inflate it to a share-truncating extreme.",
                );
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

// ----------------------------------------------------------------- helpers

/// A discovered proportional exchange-rate ratio `num / den`: the divisor variable
/// (the current TVL / total value), and the set of variable names multiplied
/// together in the numerator (which must include a share-supply factor and the
/// incoming value). Plus the variable we believe is the supply factor, for the
/// guard cross-check and the message.
struct ExchangeRatio {
    /// The divisor variable name (the TVL / total value), e.g. `_currentValueInProtocol`.
    divisor: String,
    /// All variable names that appear as factors in the numerator product.
    numerator_factors: Vec<String>,
    /// The numerator factor we classify as the share supply (used to cross-check
    /// the first-mint guard). `None` if no factor is recognizably supply-like.
    supply_factor: Option<String>,
}

/// Find a proportional exchange-rate division in `f`: `(a * b [* ...]) / den`
/// where the numerator is a **product of at least two variable factors** and `den`
/// is a single variable. This matches `supply * newValue / tvl` (and the redeem
/// dual `tvl * burned / supply`), while *not* matching a bare `x / y` scale or a
/// `value * SCALE / price` unit conversion (those have a constant factor, not two
/// distinct pool variables — see [`numerator_var_factors`]).
fn find_exchange_rate_ratio(f: &Function) -> Option<ExchangeRatio> {
    let mut hit: Option<ExchangeRatio> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Binary { op: BinOp::Div, lhs, rhs } = &e.kind else { return };
            // Divisor must root-resolve to a single variable (the TVL / supply
            // denominator). A literal or compound divisor is not this shape.
            let Some(divisor) = sole_var(rhs) else { return };
            // Numerator must be a product of >= 2 *variable* factors (supply * value),
            // i.e. an exchange-rate, not a `const * x` unit scale.
            let factors = numerator_var_factors(lhs);
            if factors.len() < 2 {
                return;
            }
            // Don't let the divisor also be (only) the numerator — the ratio must
            // relate distinct quantities.
            if factors.iter().all(|v| v == &divisor) {
                return;
            }
            let supply_factor = factors
                .iter()
                .find(|v| is_supply_like(v))
                .cloned()
                .or_else(|| {
                    // Fall back: if the divisor itself is supply-like (the redeem
                    // dual `tvl * burned / supply`), the supply is the divisor.
                    is_supply_like(&divisor).then(|| divisor.clone())
                });
            hit = Some(ExchangeRatio {
                divisor,
                numerator_factors: factors,
                supply_factor,
            });
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// The set of distinct *variable* root names multiplied together at the top of a
/// numerator expression. We descend only through `*` (and parenthesization) so that
/// `supply * newValue` yields `{supply, newValue}` but `supply * (value + 1)` still
/// yields `{supply, value}` (we collect the leaf vars on each side of the `*`).
/// Literals and pure constants contribute no variable, so `value * SCALE` (a unit
/// conversion) yields only `{value}` and is rejected by the >= 2 caller check.
fn numerator_var_factors(e: &Expr) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    collect_mul_factors(e, &mut out);
    out.sort();
    out.dedup();
    out
}

/// Walk a `*`-rooted product tree, pushing the root variable of each non-`*`
/// factor. A factor that is a literal, or a **constant-like identifier** (an
/// ALL_CAPS scale such as `SCALE` / `SCALE_FACTOR` / `WAD`, or a `1e18`-style
/// literal), pushes nothing — those mark a *unit conversion* (`value * SCALE`),
/// not the two-runtime-variable product of an exchange rate. This is what keeps
/// `value * SCALE / price` (Renzo `lookupTokenAmountFromValue`) from looking like
/// `supply * value / tvl`.
fn collect_mul_factors(e: &Expr, out: &mut Vec<String>) {
    match &e.kind {
        ExprKind::Binary { op: BinOp::Mul, lhs, rhs } => {
            collect_mul_factors(lhs, out);
            collect_mul_factors(rhs, out);
        }
        // A parenthesized additive factor like `(value + 1)` or `(supply)` — take
        // the variable(s) inside but treat the whole thing as one factor position.
        // We grab the first/root variable of the factor.
        _ => {
            if let Some(v) = sole_var(e) {
                if !looks_constant(&v) {
                    out.push(v);
                }
            } else if let Some(v) = first_var_in(e) {
                // additive/compound factor (`value + 1`): contribute its leading var
                if !looks_constant(&v) {
                    out.push(v);
                }
            }
        }
    }
}

/// True if an identifier name looks like a compile-time **constant scale**, not a
/// runtime quantity: ALL_CAPS (`SCALE`, `SCALE_FACTOR`, `WAD`, `RAY`,
/// `PRECISION`), or a name containing `scale` / `precision` / `factor`. Such a
/// factor in a product is a unit conversion, not a pool variable.
fn looks_constant(name: &str) -> bool {
    let has_alpha = name.chars().any(|c| c.is_ascii_alphabetic());
    let all_upper = has_alpha
        && name
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .all(|c| c.is_ascii_uppercase());
    if all_upper {
        return true;
    }
    let l = name.to_ascii_lowercase();
    l.contains("scale") || l.contains("precision") || l.contains("factor") || l == "wad" || l == "ray"
}

/// If `e` root-resolves to exactly one variable (an ident, or an
/// index/member chain rooted at a variable), return that variable's name.
/// Casts (`uint256(x)`) are unwrapped to their single argument.
fn sole_var(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => sole_var(base),
        ExprKind::Call(c) => {
            // Unwrap a type cast `uint256(x)` / `IERC20(x)` to its single argument.
            if matches!(c.kind, sluice_ir::CallKind::TypeCast) && c.args.len() == 1 {
                sole_var(&c.args[0])
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The first (leading) variable mentioned anywhere in `e`. Used to pull a variable
/// out of an additive factor such as `value + 1`.
fn first_var_in(e: &Expr) -> Option<String> {
    let mut found: Option<String> = None;
    e.visit(&mut |sub| {
        if found.is_some() {
            return;
        }
        if let ExprKind::Ident(n) = &sub.kind {
            found = Some(n.clone());
        }
    });
    found
}

/// A discovered literal first-mint short-circuit.
struct FirstMintGuard {
    /// The variable returned by the short-circuit branch (`newValue`/`amount`) — a
    /// numerator factor of the ratio, i.e. the *incoming value* whose 1:1 return
    /// seeds the exchange rate.
    return_var: Option<String>,
    /// Span of the `return` inside the short-circuit branch.
    return_span: Option<Span>,
}

/// Find the **defining** first-mint *seeding* guard: an early
/// `if (tvl == 0 || supply == 0) { return value; }` where
///   * the condition `== 0`-checks **both** the ratio's divisor (the TVL) **and**
///     the ratio's share-supply factor — the double-clause form whose explicit
///     purpose (per Renzo's own comment, "guard against gaming the initial mint")
///     is to special-case the empty pool's first mint; and
///   * the short-circuit branch returns the **incoming value** — a numerator factor
///     that is *not* the supply — establishing the 1:1 seed rate.
///
/// Requiring the double `== 0` clause AND the value-return is the precision anchor
/// that separates a first-mint *seeding* special-case (re-emptyable, rate-fixing —
/// the Renzo bug) from an ordinary defensive divide-by-zero guard that merely
/// returns `0` or guards a single denominator (the etherFi `sharesForAmount` /
/// Pendle pro-rata-balance shapes, which are not rate-seeding and stay silent).
fn find_first_mint_guard(f: &Function, ratio: &ExchangeRatio) -> Option<FirstMintGuard> {
    // The supply factor must be a concrete, zero-checkable variable for the
    // double-clause discriminator to apply. A ratio whose supply side is an
    // external call (`eETH.totalShares()`) has no such variable and is not this
    // seeding shape.
    let supply = ratio.supply_factor.as_ref()?;
    let mut hit: Option<FirstMintGuard> = None;
    for s in &f.body {
        s.visit(&mut |st| {
            if hit.is_some() {
                return;
            }
            let StmtKind::If { cond, then_branch, else_branch } = &st.kind else { return };
            // Variables this condition compares `== 0` (or `<= 0` for signed).
            let zero_vars = zero_checked_vars(cond);
            // The guard must zero-check BOTH the divisor (TVL) and the supply
            // factor — the canonical `tvl == 0 || supply == 0` double clause.
            if !zero_vars.iter().any(|v| v == &ratio.divisor) {
                return;
            }
            if !zero_vars.iter().any(|v| v == supply) {
                return;
            }
            // The short-circuit branch must `return` the *incoming value*: a
            // numerator factor that is neither the divisor nor the supply.
            let (rv, rspan) = match find_return_var(then_branch).or_else(|| find_return_var(else_branch)) {
                Some(x) => x,
                None => return,
            };
            let returns_value = rv
                .as_ref()
                .map(|v| {
                    v != &ratio.divisor
                        && v != supply
                        && ratio.numerator_factors.iter().any(|nf| nf == v)
                })
                .unwrap_or(false);
            if !returns_value {
                return;
            }
            hit = Some(FirstMintGuard {
                return_var: rv,
                return_span: Some(rspan),
            });
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// The set of variable names compared against the integer literal `0` inside a
/// boolean condition. Handles `x == 0`, `0 == x`, `x <= 0` (signed-amount form),
/// and the `a || b` / `a && b` composition of such comparisons.
fn zero_checked_vars(cond: &Expr) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    collect_zero_checks(cond, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_zero_checks(e: &Expr, out: &mut Vec<String>) {
    match &e.kind {
        ExprKind::Binary { op: BinOp::Or | BinOp::And, lhs, rhs } => {
            collect_zero_checks(lhs, out);
            collect_zero_checks(rhs, out);
        }
        ExprKind::Binary { op, lhs, rhs } if is_zero_relation(*op) => {
            // One side must be the literal 0, the other a variable.
            if is_zero_lit(lhs) {
                if let Some(v) = sole_var(rhs) {
                    out.push(v);
                }
            } else if is_zero_lit(rhs) {
                if let Some(v) = sole_var(lhs) {
                    out.push(v);
                }
            }
        }
        _ => {}
    }
}

/// Comparisons that express "is this zero / not-positive": `==`, `<=` (for a
/// signed value, `<= 0` is the empty check), and `<` (with the 0 on the right).
fn is_zero_relation(op: BinOp) -> bool {
    matches!(op, BinOp::Eq | BinOp::Le | BinOp::Lt)
}

/// True if `e` is the integer literal `0` (decimal or `0x0`).
fn is_zero_lit(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(Lit::Number(n)) => n.trim() == "0",
        ExprKind::Lit(Lit::HexNumber(n)) => {
            let t = n.trim().trim_start_matches("0x").trim_start_matches('0');
            t.is_empty()
        }
        _ => false,
    }
}

/// If a statement subtree contains an early `return [X];`, return `(X-var, span)`
/// for the first such return. Used to confirm the guard branch short-circuits.
fn find_return_var(stmts: &[Stmt]) -> Option<(Option<String>, Span)> {
    let mut hit: Option<(Option<String>, Span)> = None;
    for s in stmts {
        s.visit(&mut |st| {
            if hit.is_some() {
                return;
            }
            if let StmtKind::Return(ret) = &st.kind {
                let var = ret.as_ref().and_then(sole_var);
                hit = Some((var, st.span));
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Names that mark a variable as a **share supply** — the factor whose pairing
/// with the value makes the ratio an exchange rate (rather than two unrelated
/// numbers). Matched as a lowercased substring of the variable name.
const SUPPLY_MARKERS: &[&str] = &["supply", "share", "totalshares", "totalsupply"];

fn is_supply_like(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    SUPPLY_MARKERS.iter().any(|m| l.contains(m))
}

/// Suppress when the function already neutralizes the re-emptyable guard with a
/// permanent offset or a minimum-liquidity lock:
///
///   * a **virtual-shares / dead-shares offset** — the ratio operands are bumped by
///     a constant (`+ 1`, `+ VIRTUAL_SHARES`, `+ _decimalsOffset`), the OZ ERC4626 /
///     virtual-shares defense, so the divisor can never actually be zero; or
///   * a **minimum-liquidity lock** / dead-shares burn (`MINIMUM_LIQUIDITY`,
///     `deadShares`, `_mint(address(0), ...)` / burn on first mint).
///
/// We look in the function's source text (comment-stripped + lowercased by
/// `source_text`) for these markers, and additionally detect a structural `+ const`
/// applied to the ratio's divisor or a numerator factor.
fn has_offset_or_lock(cx: &AnalysisContext, f: &Function, ratio: &ExchangeRatio) -> bool {
    let src = cx.source_text(f.span);
    const MARKERS: &[&str] = &[
        "virtual_shares",
        "virtualshares",
        "virtual_assets",
        "virtualassets",
        "dead_shares",
        "deadshares",
        "decimalsoffset",
        "_decimaloffset",
        "_decimalsoffset",
        "minimum_liquidity",
        "minimumliquidity",
        "min_liquidity",
        "minliquidity",
    ];
    if MARKERS.iter().any(|m| src.contains(m)) {
        return true;
    }
    // Structural: a `(operand + constant)` offset on the divisor or a numerator
    // factor in some division of the function (the `+ 1` virtual-share trick).
    offset_added_to_ratio_operand(f, ratio)
}

/// True if any division in `f` adds a constant to its divisor or to a factor of its
/// numerator (`(supply + 1) * amount / (tvl + 1)`) — the inline virtual-offset
/// defense. We only treat it as a defense when the bumped operand is one of *this*
/// ratio's operands, so an unrelated `+ 1` elsewhere does not over-suppress.
fn offset_added_to_ratio_operand(f: &Function, ratio: &ExchangeRatio) -> bool {
    let operands: Vec<&str> = std::iter::once(ratio.divisor.as_str())
        .chain(ratio.numerator_factors.iter().map(|s| s.as_str()))
        .collect();
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            let ExprKind::Binary { op: BinOp::Div, lhs, rhs } = &e.kind else { return };
            for side in [lhs.as_ref(), rhs.as_ref()] {
                if expr_bumps_operand(side, &operands) {
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

/// True if `e` contains an `operand + <constant>` (or `const + operand`) where
/// `operand` root-resolves to one of `operands` and the other addend is a
/// literal/constant. This is the virtual-shares `(x + 1)` offset.
fn expr_bumps_operand(e: &Expr, operands: &[&str]) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        let ExprKind::Binary { op: BinOp::Add, lhs, rhs } = &sub.kind else { return };
        let lhs_op = sole_var(lhs).map(|v| operands.iter().any(|o| *o == v)).unwrap_or(false);
        let rhs_op = sole_var(rhs).map(|v| operands.iter().any(|o| *o == v)).unwrap_or(false);
        // operand + constant   OR   constant + operand
        if (lhs_op && is_const_addend(rhs)) || (rhs_op && is_const_addend(lhs)) {
            found = true;
        }
    });
    found
}

/// True if `e` is a constant-ish addend: a numeric literal, or an identifier in
/// ALL_CAPS / containing an offset marker (`VIRTUAL_SHARES`, `OFFSET`, `_ONE`).
fn is_const_addend(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(Lit::Number(_)) | ExprKind::Lit(Lit::HexNumber(_)) => true,
        ExprKind::Ident(n) => {
            let upper = n.chars().filter(|c| c.is_ascii_alphabetic()).all(|c| c.is_ascii_uppercase())
                && n.chars().any(|c| c.is_ascii_alphabetic());
            let l = n.to_ascii_lowercase();
            upper || l.contains("offset") || l.contains("virtual")
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
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "oracle-first-mint-seeding")
    }

    // VULN — the real Renzo `RenzoOracle.calculateMintAmount` shape: the mint
    // amount is `existingEzETHSupply * newValueAdded / currentValueInProtocol`,
    // guarded ONLY by the literal first-mint short-circuit
    // `if (currentValueInProtocol == 0 || existingEzETHSupply == 0) return newValueAdded;`.
    // No virtual-shares / dead-shares offset, so the guard is re-emptyable.
    const VULN: &str = r#"
        contract RenzoOracle {
            function calculateMintAmount(
                uint256 _currentValueInProtocol,
                uint256 _newValueAdded,
                uint256 _existingEzETHSupply
            ) external pure returns (uint256) {
                if (_currentValueInProtocol == 0 || _existingEzETHSupply == 0) {
                    return _newValueAdded;
                }
                uint256 mintAmount = (_existingEzETHSupply * _newValueAdded) / _currentValueInProtocol;
                if (mintAmount == 0) revert();
                return mintAmount;
            }
        }
    "#;

    // VULN (named-var supply, double clause): a generic `convertToShares`-style
    // deposit pricer with the canonical `tvl == 0 || supply == 0` double-clause
    // guard returning the incoming `amount`. Same class as Renzo. Must fire.
    const VULN_GENERIC: &str = r#"
        contract Pricer {
            function deposit(uint256 amount, uint256 totalShares, uint256 totalValue)
                external pure returns (uint256)
            {
                if (totalValue == 0 || totalShares == 0) {
                    return amount;
                }
                return totalShares * amount / totalValue;
            }
        }
    "#;

    // SAFE (single-clause defensive guard): only the TVL divisor is `== 0`-checked
    // and the branch returns `0` (a plain divide-by-zero guard, NOT a rate-seeding
    // special case). This is the etherFi `sharesForAmount` / `amountForShare`
    // shape — the supply is an external `eETH.totalShares()` call, never a
    // zero-checked variable, and nothing seeds a 1:1 rate. Must stay silent.
    const SAFE_DIVZERO_GUARD: &str = r#"
        interface IShare { function totalShares() external view returns (uint256); }
        contract Pool {
            IShare public eETH;
            function getTotalPooledEther() public view returns (uint256) { return 1; }
            function sharesForAmount(uint256 _amount) public view returns (uint256) {
                uint256 totalPooledEther = getTotalPooledEther();
                if (totalPooledEther == 0) {
                    return 0;
                }
                return (_amount * eETH.totalShares()) / totalPooledEther;
            }
        }
    "#;

    // SAFE (pro-rata balance read, single clause, struct return): a read-only
    // helper computing a user's share of a pool (`userLp * totalPt / totalLp`)
    // behind `if (totalLp == 0) return res;`. Single-clause guard, returns a
    // struct (not the incoming value), no rate seeding. The Pendle
    // `getUserMarketInfo` shape. Must stay silent.
    const SAFE_PRORATA_BALANCE: &str = r#"
        contract Static {
            struct Info { uint256 a; }
            function getUserMarketInfo(uint256 userLp, uint256 totalPt, uint256 totalLp)
                external pure returns (Info memory res)
            {
                if (totalLp == 0) return res;
                uint256 userPt = (userLp * totalPt) / totalLp;
                res = Info(userPt);
            }
        }
    "#;

    // SAFE — same exchange-rate ratio, but a permanent virtual-shares offset
    // (`+ 1` on both the supply and the TVL) is added, so the pool can never be
    // re-emptied to game the rate. Must stay silent even though a `== 0` early
    // return is still present.
    const SAFE_VIRTUAL_OFFSET: &str = r#"
        contract OffsetPricer {
            function calculateMintAmount(
                uint256 _currentValueInProtocol,
                uint256 _newValueAdded,
                uint256 _existingEzETHSupply
            ) external pure returns (uint256) {
                if (_currentValueInProtocol == 0 || _existingEzETHSupply == 0) {
                    return _newValueAdded;
                }
                return ((_existingEzETHSupply + 1) * _newValueAdded) / (_currentValueInProtocol + 1);
            }
        }
    "#;

    // SAFE — a minimum-liquidity lock (Uniswap-V2 MINIMUM_LIQUIDITY) is burned on
    // the first mint, so TVL/supply cannot be driven back to zero. Marker present.
    const SAFE_MIN_LIQUIDITY: &str = r#"
        contract Pair {
            uint256 public constant MINIMUM_LIQUIDITY = 1000;
            function mint(uint256 amount, uint256 totalSupply, uint256 reserve)
                external pure returns (uint256 liquidity)
            {
                if (totalSupply == 0) {
                    return amount - MINIMUM_LIQUIDITY;
                }
                liquidity = totalSupply * amount / reserve;
            }
        }
    "#;

    // SAFE — there IS a literal zero-return on an argument, but the computation is
    // a unit conversion `value * SCALE / price`, NOT a supply*value/tvl exchange
    // rate (only one *variable* numerator factor). No exchange-rate ratio forms,
    // so no finding. (Mirrors Renzo `lookupTokenAmountFromValue`.)
    const SAFE_UNIT_CONVERSION: &str = r#"
        contract Oracle {
            uint256 constant SCALE = 1e18;
            function lookupTokenAmountFromValue(uint256 price, uint256 value)
                external pure returns (uint256)
            {
                if (price == 0) {
                    return 0;
                }
                return (value * SCALE) / price;
            }
        }
    "#;

    // SAFE — a proportional `supply * value / tvl` ratio exists, but there is NO
    // first-mint short-circuit at all (the empty-pool case is handled some other
    // way / reverts). Without the literal `== 0 return` guard there is nothing for
    // this detector to flag — the "guarded ONLY by a literal check" premise fails.
    const SAFE_NO_GUARD: &str = r#"
        contract Pricer {
            function deposit(uint256 amount, uint256 totalShares, uint256 totalValue)
                external pure returns (uint256)
            {
                require(totalValue > 0, "empty");
                return totalShares * amount / totalValue;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_generic_double_clause() {
        assert!(fires(VULN_GENERIC), "{:#?}", run(VULN_GENERIC));
    }

    #[test]
    fn silent_on_divzero_guard() {
        assert!(!fires(SAFE_DIVZERO_GUARD), "{:#?}", run(SAFE_DIVZERO_GUARD));
    }

    #[test]
    fn silent_on_prorata_balance() {
        assert!(!fires(SAFE_PRORATA_BALANCE), "{:#?}", run(SAFE_PRORATA_BALANCE));
    }

    #[test]
    fn silent_on_virtual_offset() {
        assert!(!fires(SAFE_VIRTUAL_OFFSET), "{:#?}", run(SAFE_VIRTUAL_OFFSET));
    }

    #[test]
    fn silent_on_min_liquidity() {
        assert!(!fires(SAFE_MIN_LIQUIDITY), "{:#?}", run(SAFE_MIN_LIQUIDITY));
    }

    #[test]
    fn silent_on_unit_conversion() {
        assert!(!fires(SAFE_UNIT_CONVERSION), "{:#?}", run(SAFE_UNIT_CONVERSION));
    }

    #[test]
    fn silent_without_first_mint_guard() {
        assert!(!fires(SAFE_NO_GUARD), "{:#?}", run(SAFE_NO_GUARD));
    }
}
