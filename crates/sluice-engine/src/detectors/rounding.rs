//! Rounding-direction hazard: a share/asset conversion in a mint/deposit or
//! withdraw/redeem path computes an amount with integer division but pins no
//! explicit rounding mode. Solidity integer division truncates toward zero, so a
//! conversion that should round *against* the user (down on mint, up on
//! withdraw) instead rounds in the user's favor — bleeding the protocol a few
//! wei per call until the buffer is gone. The ERC-4626 "rounding must favor the
//! vault" rule; this is the class behind a long tail of vault-accounting reports.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function};

pub struct RoundingDetector;

impl Detector for RoundingDetector {
    fn id(&self) -> &'static str {
        "rounding-direction"
    }
    fn category(&self) -> Category {
        Category::RoundingDirection
    }
    fn description(&self) -> &'static str {
        "Share/asset conversion (mint/deposit/withdraw) divides with no explicit rounding mode"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }

            // ---- Arm 1: conversion entry points (the original detector) ----
            // mint/deposit/issue (assets→shares) and withdraw/redeem/burn
            // (shares→assets). Requires the function be externally reachable and
            // state-mutating, contain an `a * b / c` mul-then-div, and pin no
            // rounding mode. Other arithmetic is out of scope here (major FP source).
            if f.is_externally_reachable()
                && f.is_state_mutating()
                && is_conversion_name(&f.name)
            {
                if let Some(span) = find_mul_div(f) {
                    if !uses_explicit_rounding(cx, f) {
                        out.push(self.conversion_finding(cx, f, span));
                        continue;
                    }
                }
            }

            // ---- Arm 2: solvency/collateral-gated price division ----
            // A value computed by integer division (`a * b / c` or `a / c`) that
            // is then used to gate a collateral/solvency comparison. Truncating it
            // the wrong way makes the invariant fail and reverts *legitimate*
            // actions (Frankencoin clone price `_mint * 1e18 / _coll` feeding
            // `collateralReserve * price < minted * 1e18`). Gated on the function
            // mentioning collateral/solvency vocabulary so we never flag generic
            // arithmetic.
            if let Some(span) = find_solvency_gated_division(cx, f) {
                if !uses_explicit_rounding(cx, f) {
                    out.push(self.solvency_finding(cx, f, span));
                    continue;
                }
            }

            // ---- Arm 3: sqrt-based reserve recovery ----
            // A reserve/invariant value recovered through an integer square root
            // (`LibMath.sqrt(..)`, `x.sqrt()`) or its inverse `s ** 2 / b`. Integer
            // `sqrt` floors, so a reserve recovered this way can round in favor of
            // the swapper rather than the pool (Basin `calcReserve` /
            // `calcReserveAtRatioSwap`). The div-rounding helpers that Arm-2 honors
            // do NOT control the *sqrt* direction, so this arm checks for
            // sqrt-specific rounding control only.
            if is_reserve_calc_name(&f.name) {
                if let Some(span) = find_unrounded_sqrt_reserve(f) {
                    if !pins_sqrt_rounding(cx, f) {
                        out.push(self.sqrt_finding(cx, f, span));
                        continue;
                    }
                }
            }
        }
        out
    }
}

impl RoundingDetector {
    fn conversion_finding(
        &self,
        cx: &AnalysisContext,
        f: &Function,
        span: sluice_ir::Span,
    ) -> Finding {
        let b = FindingBuilder::new(self.id(), Category::RoundingDirection)
            .title("Share/asset conversion with unspecified rounding direction")
            .severity(Severity::Low)
            .confidence(0.4)
            .dimension(Dimension::ValueFlow)
            .message(format!(
                "`{}` converts between assets and shares with an integer `a * b / c` division but \
                 pins no explicit rounding mode. Solidity division truncates toward zero, so the \
                 conversion may round in the user's favor (e.g. minting too many shares or paying \
                 out too many assets) instead of the protocol's — draining the vault a few wei per \
                 call. ERC-4626 requires rounding to favor the vault.",
                f.name
            ))
            .recommendation(
                "Pin the rounding direction explicitly: round down on deposit/mint share issuance and \
                 round up on withdraw/redeem asset payout — e.g. OpenZeppelin `Math.mulDiv(a, b, c, \
                 Rounding.Floor/Ceil)` or a `mulDivUp`/`mulDivDown` helper.",
            );
        cx.finish(b, f.id, span)
    }

    fn solvency_finding(&self, cx: &AnalysisContext, f: &Function, span: sluice_ir::Span) -> Finding {
        let b = FindingBuilder::new(self.id(), Category::RoundingDirection)
            .title("Solvency-gating value computed by truncating division (rounds against caller)")
            .severity(Severity::Medium)
            .confidence(0.5)
            .dimension(Dimension::ValueFlow)
            .message(format!(
                "`{}` derives a price/collateral quantity with an integer division that pins no \
                 rounding mode, and that quantity then gates a collateral/solvency comparison. \
                 Solidity division truncates toward zero, so the rounded-down value can fail an \
                 invariant such as `collateral * price >= debt` and revert an action that is \
                 actually well-collateralized — e.g. a clone price `mint * 1e18 / collateral` that \
                 should round *up* to keep the collateral check satisfiable.",
                f.name
            ))
            .recommendation(
                "Round the solvency-gating quotient in the direction that keeps the invariant \
                 satisfiable for legitimate callers — typically round the price/required-collateral \
                 *up* (e.g. `Math.mulDiv(a, b, c, Rounding.Ceil)` or a `ceilDiv`/`roundUpDiv` helper) \
                 rather than relying on truncation.",
            );
        cx.finish(b, f.id, span)
    }

    fn sqrt_finding(&self, cx: &AnalysisContext, f: &Function, span: sluice_ir::Span) -> Finding {
        let b = FindingBuilder::new(self.id(), Category::RoundingDirection)
            .title("Reserve recovered via integer sqrt with unspecified rounding direction")
            .severity(Severity::Medium)
            .confidence(0.5)
            .dimension(Dimension::ValueFlow)
            .message(format!(
                "`{}` recovers a reserve/invariant quantity through an integer square root (or its \
                 `x ** 2` inverse) with no explicit rounding-direction control. Integer `sqrt` floors, \
                 so the recovered reserve can round in favor of the swapper rather than the pool: the \
                 LP-supply side floors `sqrt(b0*b1)` while the reserve side computes `s^2 / b`, and the \
                 two rounding directions must be reconciled so the pool never gives out more than the \
                 invariant allows.",
                f.name
            ))
            .recommendation(
                "Make the sqrt-based reserve recovery round in the pool's favor: round the recovered \
                 reserve *up* (and the forward LP-supply *down*) so the constant-product invariant can \
                 never be satisfied by a value that over-credits the swapper — e.g. add 1 to the floored \
                 sqrt when it is not exact, or use a ceil variant on the reserve side.",
            );
        cx.finish(b, f.id, span)
    }
}

/// A conversion entry point: assets→shares (`mint`/`deposit`/`issue`) or
/// shares→assets (`withdraw`/`redeem`/`burn`).
fn is_conversion_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    ["mint", "deposit", "issue", "withdraw", "redeem", "burn"]
        .iter()
        .any(|k| l.contains(k))
}

/// Detect a proportional conversion: an `a * b / c` (a `Mul` whose operand is a
/// `Div`, in either order) or a `mulDiv`-family call. Returns the span of the
/// offending expression. This is the inverse of the vault detector's
/// divide-before-multiply check (which looks for `(a / b) * c`); here we want
/// multiply-then-divide, the canonical share/asset formula.
fn find_mul_div(f: &Function) -> Option<sluice_ir::Span> {
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            match &e.kind {
                // `a * b / c` parses as `Div(Mul(a, b), c)`, and `c * (a / b)`
                // (or `(a / b) * c`) parses as a `Mul` with a `Div` operand. Both
                // are integer-division conversions; flag either shape.
                ExprKind::Binary { op: BinOp::Div, lhs, .. } => {
                    if contains_mul(lhs) {
                        found = Some(e.span);
                    }
                }
                ExprKind::Binary { op: BinOp::Mul, lhs, rhs } => {
                    if is_div(lhs) || is_div(rhs) {
                        found = Some(e.span);
                    }
                }
                // `mulDiv(a, b, c)` / `Math.mulDiv(...)` helper call.
                ExprKind::Call(c) => {
                    if c
                        .func_name
                        .as_deref()
                        .map(|n| n.eq_ignore_ascii_case("muldiv"))
                        .unwrap_or(false)
                    {
                        found = Some(e.span);
                    }
                }
                _ => {}
            }
        });
    }
    found
}

fn is_div(e: &Expr) -> bool {
    matches!(e.kind, ExprKind::Binary { op: BinOp::Div, .. })
}

/// True if `e` is a `Mul`, or transitively contains one (e.g. `(a * b) + d`).
fn contains_mul(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |n| {
        if let ExprKind::Binary { op: BinOp::Mul, .. } = &n.kind {
            found = true;
        }
    });
    found
}

// ---------------------------------------------------------------------------
// Arm 2: solvency/collateral-gated price division
// ---------------------------------------------------------------------------

/// Find an integer division whose result gates a collateral/solvency check.
///
/// Conservative gating, in order:
///   1. the function (or its source) must mention collateral/solvency vocabulary
///      *and* contain a relational comparison that mentions that vocabulary — the
///      `collateral * price >= debt` invariant shape;
///   2. there must be a plain integer division (`a * b / c` or `a / c`) outside a
///      `mulDiv` helper;
///   3. the division must plausibly feed the gated quantity (a `price`-like name
///      or an assignment to a state variable that the comparison reads).
///
/// Returns the span of the offending division. Restricted to functions that read
/// or write a `price`-like state variable so we never flag generic ratio math.
fn find_solvency_gated_division(cx: &AnalysisContext, f: &Function) -> Option<sluice_ir::Span> {
    // Whole-function source (comment-stripped, lowercased) for the cheap vocab gate.
    let src = cx.source_text(f.span);
    if !mentions_solvency_vocab(&src) {
        return None;
    }
    // Require an actual relational comparison touching the vocabulary — the
    // invariant check. Without it this is just arithmetic, not a gate.
    if !has_solvency_comparison(f) {
        return None;
    }
    // Find a bare integer division that assigns into / produces a price-like value.
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            // Assignment whose value is (or contains) a bare division: the canonical
            // `price = mint * 1e18 / coll;` shape. Prefer this so the reported span
            // is the offending statement and so we know the quotient is *kept*.
            if let ExprKind::Assign { target, value, .. } = &e.kind {
                if target_is_price_like(target) {
                    if let Some(sp) = first_bare_div_span(value) {
                        found = Some(sp);
                    }
                }
            }
        });
    }
    found
}

/// Vocabulary that marks a function as part of a collateral/solvency/liquidation
/// path (as opposed to generic arithmetic). Textual, over the comment-stripped,
/// lowercased function source.
fn mentions_solvency_vocab(src: &str) -> bool {
    // `price` alone is too broad; require it to co-occur with a collateralization
    // concept, or require an explicit collateral/solvency term.
    let has_collateral = src.contains("collateral");
    let has_solvency = src.contains("solven") || src.contains("undercollat") || src.contains("liqui");
    let has_debt = src.contains("minted") || src.contains("debt") || src.contains("borrow");
    let has_price = src.contains("price");
    has_collateral || has_solvency || (has_price && has_debt)
}

/// True if the function body contains a relational comparison (`<`, `>`, `<=`,
/// `>=`) whose source text mentions collateral/solvency vocabulary — the
/// `collateral * price >= debt` invariant shape that the division feeds.
fn has_solvency_comparison(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
                if op.is_ordering() {
                    // Cheap structural vocab check on the two operands.
                    let mut hit = false;
                    let mut probe = |n: &Expr| {
                        if let Some(name) = n.simple_name() {
                            let l = name.to_ascii_lowercase();
                            if l.contains("collateral")
                                || l.contains("minted")
                                || l.contains("debt")
                                || l.contains("price")
                                || l.contains("reserve")
                            {
                                hit = true;
                            }
                        }
                    };
                    lhs.visit(&mut |n| probe(n));
                    rhs.visit(&mut |n| probe(n));
                    if hit {
                        found = true;
                    }
                }
            }
        });
    }
    found
}

/// True if an assignment target names the liquidation/collateral *price* that a
/// solvency check gates on. Deliberately narrow: only `price`-like names, not
/// generic `rate`/`ratio` (which match unrelated interest-rate config scaling and
/// are pure FP noise). The collateral invariant this arm targets is
/// `collateral * price >= debt`, so the gated quantity is a price.
fn target_is_price_like(target: &Expr) -> bool {
    target
        .simple_name()
        .map(|n| n.to_ascii_lowercase().contains("price"))
        .unwrap_or(false)
}

/// Span of the first *bare* integer division (`a / b`, not a `mulDiv` helper)
/// found in `e`, if any. Used to point at the truncating quotient.
fn first_bare_div_span(e: &Expr) -> Option<sluice_ir::Span> {
    let mut found = None;
    e.visit(&mut |n| {
        if found.is_some() {
            return;
        }
        if let ExprKind::Binary { op: BinOp::Div, .. } = &n.kind {
            found = Some(n.span);
        }
    });
    found
}

// ---------------------------------------------------------------------------
// Arm 3: sqrt-based reserve recovery
// ---------------------------------------------------------------------------

/// A reserve/invariant recovery entry point: `calcReserve`, `calcReserveAtRatio*`,
/// `calcLpTokenSupply`, or a name mentioning `reserve`/`invariant` paired with a
/// `calc`/`get`/`compute` verb. Kept tight so we only consider AMM-style math.
fn is_reserve_calc_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    if l.contains("reserve") || l.contains("lptoken") || l.contains("invariant") {
        return l.starts_with("calc")
            || l.starts_with("get")
            || l.starts_with("compute")
            || l.contains("reserve")
            || l.contains("lptoken")
            || l.contains("invariant");
    }
    false
}

/// Find an integer-`sqrt` (or its `x ** 2` inverse) used to recover a reserve.
/// Returns the span of the sqrt call / pow expression. We accept either:
///   - a call whose resolved name is `sqrt` / `nthRoot` (`x.sqrt()`,
///     `LibMath.sqrt(x)`), or
///   - a `BinOp::Pow` with exponent `2` (the `s ** 2` inverse used by
///     `calcReserve`, which is the reading that must reconcile with a floored
///     forward `sqrt`).
fn find_unrounded_sqrt_reserve(f: &Function) -> Option<sluice_ir::Span> {
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            match &e.kind {
                ExprKind::Call(c) => {
                    if let Some(n) = c.func_name.as_deref() {
                        let l = n.to_ascii_lowercase();
                        if l == "sqrt" || l == "nthroot" {
                            found = Some(e.span);
                        }
                    }
                }
                ExprKind::Binary { op: BinOp::Pow, rhs, .. } => {
                    if is_two(rhs) {
                        found = Some(e.span);
                    }
                }
                _ => {}
            }
        });
    }
    found
}

fn is_two(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Lit(sluice_ir::Lit::Number(n)) if n.trim() == "2")
}

/// True if the function pins the rounding direction *of the sqrt itself* — e.g.
/// it uses a `sqrtUp`/`sqrtCeil`/`ceilSqrt` helper. A div-rounding helper such as
/// `roundUpDiv` (which lowercases to a string containing `roundup`) must NOT
/// count: it controls the division, not the floor of the integer square root,
/// which is the hazard this arm targets. Comments are stripped by `source_text`,
/// so a `/// rounds up` annotation does not suppress either.
fn pins_sqrt_rounding(cx: &AnalysisContext, f: &Function) -> bool {
    let src = cx.source_text(f.span);
    src.contains("sqrtup")
        || src.contains("upsqrt")
        || src.contains("sqrtceil")
        || src.contains("ceilsqrt")
        || src.contains("sqrtroundup")
        || src.contains("sqrtrounding")
}

/// Suppress when the function clearly controls its rounding direction. Conducted
/// textually over the function source because the rounding mode is usually an
/// enum argument or a named helper rather than a distinct IR shape:
///   - `Rounding.Up` / `Rounding.Ceil` / `Rounding.Down` / `Rounding.Floor`,
///   - `mulDivUp` / `mulDivDown` / `ceilDiv` / `floorDiv` helpers,
///   - the `+ denominator - 1` (or `+ ... - 1`) ceil-division idiom.
fn uses_explicit_rounding(cx: &AnalysisContext, f: &Function) -> bool {
    let src = cx.source_text(f.span);
    if src.contains("rounding.up")
        || src.contains("rounding.ceil")
        || src.contains("rounding.down")
        || src.contains("rounding.floor")
        || src.contains("muldivup")
        || src.contains("muldivdown")
        || src.contains("muldivceil")
        || src.contains("ceildiv")
        || src.contains("floordiv")
        || src.contains("rounddown")
        || src.contains("roundup")
    {
        return true;
    }
    // `+ <denominator> - 1` ceil idiom: a `- 1` sub-expression added into the
    // numerator. Approximate textually (no whitespace normalization needed for
    // the common `- 1` / `-1` spellings) so we catch hand-rolled ceilDiv.
    has_ceil_idiom(f)
}

/// Detect the `(a * b + c - 1) / c` ceil-division idiom structurally: a `Div`
/// whose numerator subtracts `1`. This is the canonical hand-rolled
/// round-up, so its presence means rounding was considered.
fn has_ceil_idiom(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Binary { op: BinOp::Div, lhs, .. } = &e.kind {
                lhs.visit(&mut |n| {
                    if let ExprKind::Binary { op: BinOp::Sub, rhs, .. } = &n.kind {
                        if is_one(rhs) {
                            found = true;
                        }
                    }
                });
            }
        });
    }
    found
}

fn is_one(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Lit(sluice_ir::Lit::Number(n)) if n.trim() == "1")
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // A mint that issues shares with a bare `a * b / c` and no rounding mode:
    // truncation silently favors the depositor.
    const VULN: &str = r#"
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            mapping(address => uint256) public shares;
            function deposit(uint256 assets) external returns (uint256 shrs) {
                shrs = assets * totalSupply / totalAssets;
                shares[msg.sender] += shrs;
                totalSupply += shrs;
                totalAssets += assets;
            }
        }
    "#;

    // The same conversion but rounding is pinned with the `+ denominator - 1`
    // ceil idiom, so the protocol is protected — no finding.
    const SAFE: &str = r#"
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            mapping(address => uint256) public shares;
            function deposit(uint256 assets) external returns (uint256 shrs) {
                shrs = (assets * totalSupply + totalAssets - 1) / totalAssets;
                shares[msg.sender] += shrs;
                totalSupply += shrs;
                totalAssets += assets;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "rounding-direction"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "rounding-direction"));
    }

    // ---- Arm 2: solvency/collateral-gated price division (Frankencoin M-08/09)
    // A clone-init computes `price = mint * 1e18 / collateral` with truncating
    // division, then gates a collateral invariant on it. Rounding down can make a
    // legitimately-collateralized clone revert; the quotient should round up.
    const SOLVENCY_VULN: &str = r#"
        contract Position {
            uint256 public price;
            uint256 public minted;
            uint256 constant ONE_DEC18 = 1e18;
            function initializeClone(uint256 _price, uint256 _coll, uint256 _mint) external {
                price = _mint * ONE_DEC18 / _coll;
                if (price > _price) revert();
                checkCollateral(_coll, price);
            }
            function checkCollateral(uint256 collateralReserve, uint256 atPrice) internal view {
                if (collateralReserve * atPrice < minted * ONE_DEC18) revert();
            }
        }
    "#;

    // Same shape but the gating price is rounded *up* via a ceil helper, so the
    // collateral invariant stays satisfiable for honest callers — no finding.
    const SOLVENCY_SAFE: &str = r#"
        contract Position {
            uint256 public price;
            uint256 public minted;
            uint256 constant ONE_DEC18 = 1e18;
            function initializeClone(uint256 _price, uint256 _coll, uint256 _mint) external {
                price = ceilDiv(_mint * ONE_DEC18, _coll);
                if (price > _price) revert();
                checkCollateral(_coll, price);
            }
            function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
                return (a + b - 1) / b;
            }
            function checkCollateral(uint256 collateralReserve, uint256 atPrice) internal view {
                if (collateralReserve * atPrice < minted * ONE_DEC18) revert();
            }
        }
    "#;

    #[test]
    fn fires_on_solvency_gated_division() {
        let fs = run(SOLVENCY_VULN);
        assert!(
            fs.iter().any(|f| f.detector == "rounding-direction"
                && f.function == "initializeClone"),
            "{:?}",
            fs
        );
    }

    #[test]
    fn silent_on_rounded_solvency_division() {
        let fs = run(SOLVENCY_SAFE);
        assert!(
            !fs.iter().any(|f| f.detector == "rounding-direction"),
            "{:?}",
            fs
        );
    }

    // A bare config-scaling division (`perYearRate / SECONDS_PER_YEAR`) inside a
    // collateral-aware contract must NOT trip Arm 2: the target is a `rate`, not a
    // gating `price`. Guards against the comet interest-rate-slope false positives.
    const RATE_CONFIG_SAFE: &str = r#"
        contract Market {
            uint256 public supplyRate;
            uint256 public collateralFactor;
            uint256 constant SECONDS_PER_YEAR = 31536000;
            function setRate(uint256 perYearRate, uint256 minted) external {
                supplyRate = perYearRate / SECONDS_PER_YEAR;
                if (collateralFactor < minted) revert();
            }
        }
    "#;

    #[test]
    fn silent_on_rate_config_scaling() {
        let fs = run(RATE_CONFIG_SAFE);
        assert!(
            !fs.iter().any(|f| f.detector == "rounding-direction"),
            "{:?}",
            fs
        );
    }

    // ---- Arm 3: sqrt-based reserve recovery (Basin calcReserve) ----
    // A constant-product reserve recovered via integer sqrt / `s ** 2` with no
    // sqrt-rounding control: the floored sqrt can round in favor of the swapper.
    const SQRT_VULN: &str = r#"
        library LibMath {
            function sqrt(uint256 a) internal pure returns (uint256) { return a; }
            function roundUpDiv(uint256 a, uint256 b) internal pure returns (uint256) {
                if (a == 0) return 0;
                return (a - 1) / b + 1;
            }
        }
        contract CP2 {
            using LibMath for uint256;
            uint256 constant EXP_PRECISION = 1e12;
            function calcLpTokenSupply(uint256[] calldata reserves) external pure returns (uint256 s) {
                s = (reserves[0] * reserves[1] * EXP_PRECISION).sqrt();
            }
            function calcReserve(uint256[] calldata reserves, uint256 j, uint256 lpTokenSupply)
                external pure returns (uint256 reserve)
            {
                reserve = lpTokenSupply ** 2;
                reserve = LibMath.roundUpDiv(reserve, reserves[j == 1 ? 0 : 1] * EXP_PRECISION);
            }
        }
    "#;

    // The reserve recovery pins the sqrt direction with a `sqrtUp` helper, so the
    // pool's favor is preserved — no finding.
    const SQRT_SAFE: &str = r#"
        library LibMath {
            function sqrtUp(uint256 a) internal pure returns (uint256) { return a + 1; }
        }
        contract CP2 {
            using LibMath for uint256;
            uint256 constant EXP_PRECISION = 1e12;
            function calcLpTokenSupply(uint256[] calldata reserves) external pure returns (uint256 s) {
                s = (reserves[0] * reserves[1] * EXP_PRECISION).sqrtUp();
            }
        }
    "#;

    #[test]
    fn fires_on_sqrt_reserve_recovery() {
        let fs = run(SQRT_VULN);
        // Both the forward floored sqrt and the `** 2` inverse are flagged.
        assert!(
            fs.iter().any(|f| f.detector == "rounding-direction"
                && f.function == "calcReserve"),
            "calcReserve not flagged: {:?}",
            fs
        );
        assert!(
            fs.iter().any(|f| f.detector == "rounding-direction"
                && f.function == "calcLpTokenSupply"),
            "calcLpTokenSupply not flagged: {:?}",
            fs
        );
    }

    #[test]
    fn silent_on_rounded_sqrt_reserve() {
        let fs = run(SQRT_SAFE);
        assert!(
            !fs.iter().any(|f| f.detector == "rounding-direction"),
            "{:?}",
            fs
        );
    }
}
