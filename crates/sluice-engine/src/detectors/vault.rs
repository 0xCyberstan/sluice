//! ERC-4626 / vault hazards: first-depositor share-inflation (donation),
//! divide-before-multiply precision loss, and the bespoke-curve analog where the
//! empty/small-pool case is "protected" by a *constant floor* that an attacker can
//! redeem the supply back down to (Frankencoin-Equity-style cubic bonding curve).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Contract, Expr, ExprKind, Function, Lit};

pub struct VaultDetector;

impl Detector for VaultDetector {
    fn id(&self) -> &'static str {
        "vault"
    }
    fn category(&self) -> Category {
        Category::Erc4626Inflation
    }
    fn description(&self) -> &'static str {
        "ERC-4626 first-depositor inflation/donation and precision-loss rounding"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for c in cx.scir.iter_contracts() {
            if !c.is_concrete() || !is_vault_like(cx, c) {
                continue;
            }
            // Inflation mitigation present? OZ ERC4626 offset / virtual shares /
            // dead shares close the donation channel.
            let contract_src = contract_source(cx, c).to_ascii_lowercase();
            let mitigated = contract_src.contains("decimalsoffset")
                || contract_src.contains("_decimaloffset")
                || contract_src.contains("virtual_shares")
                || contract_src.contains("virtualshares")
                || contract_src.contains("dead_shares")
                || contract_src.contains("deadshares")
                || c.inherits_like("erc4626"); // OZ ERC4626 ships virtual offset
            let donatable = contract_src.contains("balanceof(address(this))")
                || contract_src.contains(".balanceof(address(this))")
                || contract_src.contains("totalassets");

            if !mitigated && donatable {
                // locate a deposit/mint function for the report span
                let f = cx
                    .scir
                    .functions_of(c.id)
                    .find(|f| {
                        let n = f.name.to_ascii_lowercase();
                        n.contains("deposit") || n.contains("mint")
                    })
                    .or_else(|| cx.scir.functions_of(c.id).next());
                if let Some(f) = f {
                    let b = FindingBuilder::new(self.id(), Category::Erc4626Inflation)
                        .title("First-depositor / donation share-inflation")
                        .severity(Severity::High)
                        .confidence(0.55)
                        .dimension(Dimension::ValueFlow)
                        .message(format!(
                            "`{}` derives share price from a donatable balance (`balanceOf(address(this))` / \
                             `totalAssets`) with no virtual-shares / decimal-offset / dead-shares defense. \
                             A first depositor can mint 1 wei of shares, donate to inflate the price, and make \
                             every later deposit round to zero shares.",
                            c.name
                        ))
                        .recommendation(
                            "Use OpenZeppelin ERC4626 with a decimals offset (virtual shares), burn dead \
                             shares on first deposit, or track assets internally instead of `balanceOf`.",
                        );
                    out.push(cx.finish(b, f.id, f.span));
                }
            }

            // Divide-before-multiply precision loss in share/asset math.
            for f in cx.scir.functions_of(c.id) {
                if !f.has_body {
                    continue;
                }
                if let Some(span) = find_div_before_mul(f) {
                    let b = FindingBuilder::new(self.id(), Category::PrecisionLoss)
                        .title("Divide-before-multiply precision loss")
                        .severity(Severity::Low)
                        .confidence(0.45)
                        .dimension(Dimension::ValueFlow)
                        .message(format!(
                            "`{}` divides before multiplying, truncating low-order bits and biasing share/asset \
                             conversion (often against the user or the protocol).",
                            f.name
                        ))
                        .recommendation("Reorder to multiply before dividing, or use a mulDiv that rounds explicitly.");
                    out.push(cx.finish(b, f.id, span));
                }
            }
        }

        // Bespoke-curve first-depositor / share-inflation analog.
        //
        // A vault need not be an ERC-4626 with a donatable `totalAssets` to be
        // exposed to first-depositor / inflation manipulation. A custom bonding
        // curve that prices new shares as `shares ∝ f(totalShares, capital)`
        // typically special-cases the empty/small pool with a *constant floor*:
        //
        //   newTotalShares = totalShares < FLOOR ? FLOOR
        //                                        : mul(totalShares, curve(...));
        //
        // That floor only protects the genesis mint. If the contract also lets
        // holders `redeem`/`burn` shares (reducing `totalShares`), an attacker can
        // push the supply back down toward/below the floor boundary and re-enter the
        // constant branch, manipulating the share/asset ratio so later depositors
        // receive fewer shares than fair value. This is the first-depositor /
        // inflation class on a non-ERC4626 curve (Frankencoin
        // `Equity.calculateSharesInternal`, the FPS cubic curve).
        //
        // This is a *separate* pass from the donation check above and deliberately
        // does NOT require `is_vault_like`: a curve contract like Frankencoin's
        // `Equity` tracks shares in an inherited ERC20 base, so it has no
        // `totalShares`/`totalAssets` member of its own and the donation gate never
        // sees it. The structural shape — a `supply < CONST ? CONST : scale(supply)`
        // ternary plus a supply-reducing redeem/burn path — is itself the gate and
        // is far more specific (and FP-resistant) than the `is_vault_like` heuristic.
        //
        // Suppressed when the contract is already protected by OZ virtual-shares /
        // decimals-offset (those vaults close this channel and use no constant-floor
        // ternary anyway).
        for c in cx.scir.iter_contracts() {
            if !c.is_concrete() {
                continue;
            }
            if contract_uses_inflation_mitigation(cx, c) {
                continue;
            }
            let Some((floor_fn, floor_span)) = find_bypassable_floor_curve(cx, c) else {
                continue;
            };
            if !contract_has_supply_reducer(cx, c) {
                continue; // floor is a one-way genesis guard, not bypassable
            }
            let Some(fid) = floor_fn_id(cx, c, floor_span) else {
                continue;
            };
            let b = FindingBuilder::new(self.id(), Category::FirstDepositor)
                .title("Bypassable share-price floor (custom-curve first-depositor inflation)")
                .severity(Severity::High)
                .confidence(0.5)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` prices minted shares from a curve that scales by the current total supply \
                     (`shares ∝ f(totalSupply, capital)`) and handles the empty/small-pool case with a \
                     *constant floor* (`totalSupply < FLOOR ? FLOOR : …`). The floor only protects the \
                     genesis mint: because `{}` also lets holders redeem/burn shares, an attacker can drive \
                     the supply back down to the floor boundary, re-enter the constant branch, and skew the \
                     share/asset ratio so that later depositors mint fewer shares than they pay for — the \
                     first-depositor / share-inflation class on a bespoke (non-ERC4626) bonding curve.",
                    floor_fn, c.name
                ))
                .recommendation(
                    "Do not rely on a constant supply/equity floor that redemptions can return to. \
                     Permanently lock a bootstrap amount of shares (mint dead shares to a burn address on \
                     first deposit) or add a virtual-shares / decimals-offset term to the curve so the ratio \
                     cannot be manipulated near the floor; forbid redeeming the supply below the bootstrap \
                     level.",
                );
            out.push(cx.finish(b, fid, floor_span));
        }

        // Share-price-from-live-supply with only a genesis zero-guard (no
        // first-deposit floor) — the Asymmetry-SafEth H-01 class.
        //
        // The bespoke-curve pass above keys on `supply <ord> FLOOR ? FLOOR :
        // mul(supply, …)` — an *ordering* guard against a constant floor whose
        // non-genesis branch *multiplies* by the supply (the Frankencoin cubic
        // curve). A second, distinct first-depositor shape prices a share/redeem
        // ratio by *dividing* a live/underlying value by the running supply and
        // special-cases only the *empty* pool with a constant:
        //
        //   price = totalSupply == 0 ? 1e18 : (1e18 * underlyingValue) / totalSupply;
        //   ...
        //   mintAmount = totalDepositValue * 1e18 / price;   // _mint(...)
        //
        // `underlyingValue` is the *live* sum of external derivative balances, not a
        // tracked accounting variable, so it is donatable. The only protection is
        // the `== 0` branch, which guards the very first mint and nothing after it:
        // because the contract also lets holders unstake/burn (driving the supply
        // back toward 1 wei), an early/sole staker can shrink the supply and inflate
        // `underlyingValue/totalSupply`, making every later staker's `mintAmount`
        // round toward zero — the first-depositor / share-inflation class on a
        // non-ERC4626 staking-share token.
        //
        // This is gated on a *very specific* structural conjunction, kept disjoint
        // from (and far narrower than) the donation gate so share-pricing FPs stay
        // out:
        //   1. a `supply == 0` / `supply != 0` *equality* genesis guard, whose
        //   2. non-genesis branch *divides by the running supply* (`x / supply`, or
        //      a `*div*` helper with the supply as divisor) — the share-price-from-
        //      live-balance shape, the dual of the curve pass's multiply-by-supply;
        //   3. inside a function that mints (`_mint`/`mint`);
        //   4. the contract has a supply reducer (so the guard is bypassable); and
        //   5. the genesis branch does NOT mint a minimum/dead-share amount to a
        //      burn address (Balancer-style `_mint(address(0), MINIMUM)` is exactly
        //      the lock that closes this channel — never flag it).
        // Suppressed, as elsewhere, when the contract already uses OZ virtual-shares
        // / decimals-offset / dead-shares.
        for c in cx.scir.iter_contracts() {
            if !c.is_concrete() {
                continue;
            }
            if contract_uses_inflation_mitigation(cx, c) {
                continue;
            }
            if !contract_has_supply_reducer(cx, c) {
                continue; // zero-guard is a one-way genesis guard, not bypassable
            }
            let Some((price_fn, price_span)) = find_unfloored_supply_divisor_mint(cx, c) else {
                continue;
            };
            let Some(fid) = floor_fn_id(cx, c, price_span) else {
                continue;
            };
            let b = FindingBuilder::new(self.id(), Category::FirstDepositor)
                .title("Share price divided by live supply with no first-deposit floor")
                .severity(Severity::High)
                .confidence(0.5)
                .dimension(Dimension::ValueFlow)
                .message(format!(
                    "`{}` prices minted shares from a ratio that divides a live/underlying value by the \
                     current total supply (`price ∝ value / totalSupply`) and special-cases only the empty \
                     pool with a constant (`totalSupply == 0 ? CONST : value / totalSupply`). That `== 0` \
                     branch protects only the genesis mint and adds no virtual-shares / dead-shares / \
                     minimum-liquidity floor. Because `{}` also lets holders unstake/burn (reducing the \
                     supply), an early or sole staker can shrink the supply back toward 1 wei and inflate the \
                     value/supply ratio, so every later staker's minted amount rounds toward zero — the \
                     first-depositor / share-inflation class on a bespoke (non-ERC4626) staking-share token.",
                    price_fn, c.name
                ))
                .recommendation(
                    "Do not gate share pricing on `totalSupply == 0` alone. Permanently lock a bootstrap \
                     amount of shares on first deposit (mint dead shares to a burn address), add a \
                     virtual-shares / decimals-offset term so the ratio cannot be manipulated near an empty \
                     pool, or track underlying value internally instead of summing live external balances.",
                );
            out.push(cx.finish(b, fid, price_span));
        }

        out
    }
}

/// OZ virtual-shares / decimals-offset / dead-shares inflation defense (or an OZ
/// `ERC4626` base, which ships the virtual offset). Mirrors the donation path's
/// `mitigated` check but as a reusable helper for the bespoke-curve pass.
fn contract_uses_inflation_mitigation(cx: &AnalysisContext, c: &Contract) -> bool {
    if c.inherits_like("erc4626") {
        return true;
    }
    let src = cx.source_text(c.span);
    src.contains("decimalsoffset")
        || src.contains("_decimaloffset")
        || src.contains("virtual_shares")
        || src.contains("virtualshares")
        || src.contains("dead_shares")
        || src.contains("deadshares")
}

fn is_vault_like(cx: &AnalysisContext, c: &Contract) -> bool {
    if c.inherits_like("erc4626") || c.inherits_like("vault") {
        return true;
    }
    let mut has_deposit = false;
    let mut has_redeem = false;
    let mut has_shares = c.state_vars.iter().any(|v| {
        let l = v.name.to_ascii_lowercase();
        l.contains("share") || l.contains("totalsupply")
    });
    for f in cx.scir.functions_of(c.id) {
        let n = f.name.to_ascii_lowercase();
        if n.contains("deposit") || n.contains("mint") {
            has_deposit = true;
        }
        if n.contains("withdraw") || n.contains("redeem") {
            has_redeem = true;
        }
        if n == "totalassets" {
            has_shares = true;
        }
    }
    has_deposit && has_redeem && has_shares
}

fn contract_source(cx: &AnalysisContext, c: &Contract) -> String {
    cx.source_text(c.span)
}

/// Detect `(a / b) * c` — division feeding a multiplication.
fn find_div_before_mul(f: &Function) -> Option<sluice_ir::Span> {
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            if let ExprKind::Binary { op: sluice_ir::BinOp::Mul, lhs, rhs } = &e.kind {
                for side in [lhs, rhs] {
                    if let ExprKind::Binary { op: sluice_ir::BinOp::Div, .. } = &side.kind {
                        found = Some(e.span);
                    }
                }
            }
        });
    }
    found
}

// ----- bespoke-curve bypassable-floor detection -----

/// True if a name looks like the running share supply: `totalShares`,
/// `totalSupply`, `_totalSupply`, or a `*shares*` total. (Not `totalAssets`,
/// `totalVotes`, etc.)
fn is_supply_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "totalsupply"
        || l == "_totalsupply"
        || l == "totalshares"
        || l == "_totalshares"
        || (l.contains("share") && (l.starts_with("total") || l.contains("supply")))
}

/// True if `e` reads the running supply: an identifier like `totalShares`, a
/// `totalSupply()` call, or a member `.totalSupply()` — i.e. the quantity the
/// curve scales by.
fn reads_supply(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Ident(n) => is_supply_name(n),
        ExprKind::Call(c) => c.func_name.as_deref().map(is_supply_name).unwrap_or(false),
        ExprKind::Member { member, .. } => is_supply_name(member),
        _ => false,
    }
}

/// True if `e` (transitively) reads the running supply anywhere.
fn mentions_supply(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |n| {
        if !found && reads_supply(n) {
            found = true;
        }
    });
    found
}

/// True if `e` looks like a constant share/equity floor: a numeric literal, a
/// `N * 1e18`/`N * ONE_DEC18` scaled constant, or a constant-style identifier
/// (`MINIMUM_…`, `INITIAL_…`). We reject anything that reads the supply (so the
/// curve branch is never mistaken for the floor branch).
fn is_const_floor(e: &Expr) -> bool {
    if mentions_supply(e) {
        return false;
    }
    match &e.kind {
        ExprKind::Lit(Lit::Number(_)) | ExprKind::Lit(Lit::HexNumber(_)) => true,
        // `N * 1e18` / `1000 * ONE_DEC18` — every leaf a number or a decimals constant.
        ExprKind::Binary { op: BinOp::Mul, .. } | ExprKind::Binary { op: BinOp::Pow, .. } => {
            all_const_leaves(e)
        }
        ExprKind::Ident(n) => looks_like_const_name(n),
        // `MathUtil.ONE_DEC18`-style member constant.
        ExprKind::Member { member, .. } => looks_like_const_name(member),
        _ => false,
    }
}

/// Every leaf of an arithmetic expression is a numeric literal or a constant-ish
/// identifier (`ONE_DEC18`, `MINIMUM_EQUITY`) — used to accept `N * ONE_DEC18`.
fn all_const_leaves(e: &Expr) -> bool {
    let mut ok = true;
    e.visit(&mut |n| {
        if !ok {
            return;
        }
        match &n.kind {
            ExprKind::Lit(Lit::Number(_)) | ExprKind::Lit(Lit::HexNumber(_)) => {}
            ExprKind::Binary { op, .. } if matches!(op, BinOp::Mul | BinOp::Pow | BinOp::Add) => {}
            ExprKind::Ident(name) => {
                if !looks_like_const_name(name) {
                    ok = false;
                }
            }
            ExprKind::Member { member, .. } => {
                if !looks_like_const_name(member) {
                    ok = false;
                }
            }
            // anything else (a call, division, …) disqualifies
            _ => ok = false,
        }
    });
    ok
}

/// UPPER_SNAKE_CASE or a well-known 1e18 unit name — i.e. a compile-time
/// constant rather than a state value.
fn looks_like_const_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let shape_ok = name
        .chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_');
    shape_ok && name.chars().any(|ch| ch.is_ascii_alphabetic())
}

/// True if `cond` is `supply <ord> const` or `const <ord> supply` for an ordering
/// comparison (`<`, `<=`, `>`, `>=`) — the "is the pool below the floor?" guard.
fn is_supply_vs_floor_guard(cond: &Expr) -> bool {
    if let ExprKind::Binary { op, lhs, rhs } = &cond.kind {
        if op.is_ordering() {
            return (reads_supply(lhs) && is_const_floor(rhs))
                || (reads_supply(rhs) && is_const_floor(lhs));
        }
    }
    false
}

/// True if `e` scales the supply by something: a `mul(totalShares, …)` /
/// `_mulD18(totalShares, …)` call, or a `Mul` with the supply on one side. This is
/// the `shares ∝ f(totalSupply, …)` curve branch.
fn scales_by_supply(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Binary { op: BinOp::Mul, lhs, rhs } => mentions_supply(lhs) || mentions_supply(rhs),
        ExprKind::Call(c) => {
            let is_mul_helper = c
                .func_name
                .as_deref()
                .map(|n| {
                    let l = n.to_ascii_lowercase();
                    l.contains("mul")
                })
                .unwrap_or(false);
            is_mul_helper && c.args.iter().any(mentions_supply)
        }
        _ => false,
    }
}

/// The core shape: a ternary `supply <cmp> FLOOR ? A : B` where one branch is the
/// constant floor and the *other* branch scales by the supply (the curve). Returns
/// the ternary's span on a match.
fn floor_ternary_span(e: &Expr) -> Option<sluice_ir::Span> {
    if let ExprKind::Ternary { cond, then_e, else_e } = &e.kind {
        if is_supply_vs_floor_guard(cond) {
            let then_floor = is_const_floor(then_e);
            let else_floor = is_const_floor(else_e);
            let then_curve = scales_by_supply(then_e);
            let else_curve = scales_by_supply(else_e);
            // Exactly one branch is the constant floor and the other is the curve.
            if (then_floor && else_curve) || (else_floor && then_curve) {
                return Some(e.span);
            }
        }
    }
    None
}

/// Scan a concrete contract for the bypassable-floor curve shape. Returns the
/// `(function_name, ternary_span)` of the first match.
fn find_bypassable_floor_curve(cx: &AnalysisContext, c: &Contract) -> Option<(String, sluice_ir::Span)> {
    for f in cx.scir.functions_of(c.id) {
        if !f.has_body {
            continue;
        }
        let mut hit = None;
        for s in &f.body {
            s.visit_exprs(&mut |e| {
                if hit.is_none() {
                    hit = floor_ternary_span(e);
                }
            });
            if hit.is_some() {
                break;
            }
        }
        if let Some(span) = hit {
            return Some((f.name.clone(), span));
        }
    }
    None
}

/// Resolve which function (by id) owns a span, so the finding points at the real
/// share-mint function rather than an arbitrary one.
fn floor_fn_id(cx: &AnalysisContext, c: &Contract, span: sluice_ir::Span) -> Option<sluice_ir::FunctionId> {
    cx.scir
        .functions_of(c.id)
        .find(|f| f.span.file == span.file && f.span.start <= span.start && span.end <= f.span.end)
        .map(|f| f.id)
}

/// True if the contract exposes a path that *reduces* the share supply: a
/// `redeem`/`withdraw`/`burn` function, or any function that calls `_burn`. This is
/// what makes the constant floor bypassable — supply can be pushed back down to it.
/// Without a redeem path the floor is a one-way genesis guard and not a hazard.
fn contract_has_supply_reducer(cx: &AnalysisContext, c: &Contract) -> bool {
    for f in cx.scir.functions_of(c.id) {
        let n = f.name.to_ascii_lowercase();
        if n.contains("redeem") || n.contains("withdraw") || n.contains("burn") {
            return true;
        }
        if f.effects
            .internal_calls
            .iter()
            .any(|ic| ic.to_ascii_lowercase().contains("burn"))
        {
            return true;
        }
    }
    false
}

// ----- unfloored share-price-from-live-supply detection (Asymmetry H-01) -----

/// Local variable names that are assigned *directly* from a supply read inside a
/// function (`uint256 ts = totalSupply();`, `supply = totalSupply()`). Real share-
/// pricing code reads the supply once into a local and divides by the local, so to
/// recognize `value / ts` we must treat such aliases as the supply. Scoped to this
/// pass (the floor-curve pass keeps the stricter name-only `reads_supply`), so no
/// existing behavior changes.
fn supply_aliases(f: &Function) -> Vec<String> {
    let mut names = Vec::new();
    for s in &f.body {
        s.visit(&mut |st| match &st.kind {
            sluice_ir::StmtKind::VarDecl { name: Some(n), init: Some(init), .. }
                if reads_supply(init) && !is_supply_name(n) =>
            {
                names.push(n.clone());
            }
            sluice_ir::StmtKind::Expr(e) => {
                if let ExprKind::Assign { target, value, .. } = &e.kind {
                    if let ExprKind::Ident(n) = &target.kind {
                        if reads_supply(value) && !is_supply_name(n) {
                            names.push(n.clone());
                        }
                    }
                }
            }
            _ => {}
        });
    }
    names
}

/// `reads_supply`, plus: an identifier that is a known local alias of the supply
/// (assigned `= totalSupply()` earlier in the same function).
fn reads_supply_or_alias(e: &Expr, aliases: &[String]) -> bool {
    if reads_supply(e) {
        return true;
    }
    matches!(&e.kind, ExprKind::Ident(n) if aliases.iter().any(|a| a == n))
}

/// True if `cond` is an *equality* genesis guard on the running supply (or a supply
/// alias) against a numeric zero: `supply == 0`, `0 == supply`, `supply != 0`, or
/// `0 != supply`. Returns `Some(eq)` with `eq == true` for `==` (genesis branch is
/// `then`) and `eq == false` for `!=` (genesis branch is `else`). This is
/// deliberately *only* the `== 0` empty-pool case — not the `< FLOOR` ordering
/// guard the bespoke-curve pass already owns.
fn supply_zero_guard(cond: &Expr, aliases: &[String]) -> Option<bool> {
    if let ExprKind::Binary { op, lhs, rhs } = &cond.kind {
        let eq = match op {
            BinOp::Eq => true,
            BinOp::Ne => false,
            _ => return None,
        };
        let supply_vs_zero = (reads_supply_or_alias(lhs, aliases) && is_literal_zero(rhs))
            || (reads_supply_or_alias(rhs, aliases) && is_literal_zero(lhs));
        if supply_vs_zero {
            return Some(eq);
        }
    }
    None
}

/// True if `e` is the numeric literal `0` (decimal or `0x0`).
fn is_literal_zero(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(Lit::Number(n)) | ExprKind::Lit(Lit::HexNumber(n)) => {
            let t = n.trim().trim_start_matches("0x").trim_start_matches("0X");
            !t.is_empty() && t.chars().all(|ch| ch == '0')
        }
        _ => false,
    }
}

/// True if `e` (transitively) divides by the running supply: a `Div` whose
/// right-hand side reads the supply (`x / totalSupply`), or a `*div*` helper call
/// whose *second* argument reads the supply (`_divD18(value, totalSupply)`). This
/// is the share-price-from-live-value shape and the dual of `scales_by_supply`
/// (which multiplies by the supply). `aliases` lets a local bound to `totalSupply()`
/// count as the supply.
fn divides_by_supply(e: &Expr, aliases: &[String]) -> bool {
    let mut found = false;
    e.visit(&mut |n| {
        if found {
            return;
        }
        match &n.kind {
            ExprKind::Binary { op: BinOp::Div, rhs, .. } if reads_supply_or_alias(rhs, aliases) => {
                found = true;
            }
            ExprKind::Call(call) => {
                let is_div_helper = call
                    .func_name
                    .as_deref()
                    .map(|nm| nm.to_ascii_lowercase().contains("div"))
                    .unwrap_or(false);
                // Divisor is the 2nd arg of a `div(a, b)` helper.
                if is_div_helper {
                    if let Some(divisor) = call.args.get(1) {
                        if reads_supply_or_alias(divisor, aliases) {
                            found = true;
                        }
                    }
                }
            }
            _ => {}
        }
    });
    found
}

/// True if a statement list mints a fixed minimum/bootstrap amount to a burn
/// address (`_mint(address(0), …)`, `_mintPoolTokens(address(0), …)`, or to a
/// `0xdead`-style sink). This is the dead-shares / minimum-liquidity lock that
/// *closes* the first-depositor channel (Balancer locks `_getMinimumBpt()` to
/// `address(0)` in its genesis branch), so its presence must suppress the finding.
fn stmts_mint_to_burn_address(stmts: &[sluice_ir::Stmt]) -> bool {
    let mut found = false;
    for s in stmts {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Call(call) = &e.kind {
                let is_mint = call
                    .func_name
                    .as_deref()
                    .map(|nm| nm.to_ascii_lowercase().contains("mint"))
                    .unwrap_or(false);
                if is_mint {
                    if let Some(first) = call.args.first() {
                        if is_burn_address(first) {
                            found = true;
                        }
                    }
                }
            }
        });
    }
    found
}

/// True if `e` is a burn/zero address recipient: `address(0)`, `address(0x0)`,
/// a bare `0`, or a `0x..dead`-style constant.
fn is_burn_address(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(Lit::Number(_)) | ExprKind::Lit(Lit::HexNumber(_)) => {
            is_literal_zero(e) || is_dead_hex(e)
        }
        ExprKind::Lit(Lit::Address(a)) => {
            let l = a.to_ascii_lowercase();
            l.trim_start_matches("0x").chars().all(|ch| ch == '0') || l.contains("dead")
        }
        // `address(0)` / `address(0xdead)` cast.
        ExprKind::Call(call) if matches!(call.kind, sluice_ir::CallKind::TypeCast) => {
            call.args.first().map(is_burn_address).unwrap_or(false)
        }
        _ => false,
    }
}

fn is_dead_hex(e: &Expr) -> bool {
    if let ExprKind::Lit(Lit::HexNumber(n)) = &e.kind {
        return n.to_ascii_lowercase().contains("dead");
    }
    false
}

/// True if the function mints share tokens: an internal/own `_mint`/`mint*` call
/// (recorded in `internal_calls`) or a `*mint*` call site. Pure helpers named
/// `mint…` are not state-mutating, but this runs only on the share-pricing
/// function that also carries the zero-guard divisor, so the conjunction is tight.
fn function_mints(f: &Function) -> bool {
    if f
        .effects
        .internal_calls
        .iter()
        .any(|ic| ic.to_ascii_lowercase().contains("mint"))
    {
        return true;
    }
    f.effects
        .call_sites
        .iter()
        .any(|cs| cs.func_name.as_deref().map(|n| n.to_ascii_lowercase().contains("mint")).unwrap_or(false))
}

/// Scan a function body for the unfloored `supply == 0 ? CONST : value/supply`
/// share-price shape, in either the `if/else`-statement form or the ternary form.
/// Returns the span of the guard/ternary on a match — but only if the genesis
/// (empty-pool) branch does NOT lock dead shares to a burn address.
fn find_unfloored_divisor_in_fn(f: &Function) -> Option<sluice_ir::Span> {
    let aliases = supply_aliases(f);
    let mut hit = None;
    for s in &f.body {
        // `if (supply == 0) { genesis } else { value/supply }` statement form.
        s.visit(&mut |st| {
            if hit.is_some() {
                return;
            }
            if let sluice_ir::StmtKind::If { cond, then_branch, else_branch } = &st.kind {
                if let Some(eq) = supply_zero_guard(cond, &aliases) {
                    // genesis branch = the one taken when supply IS zero.
                    let (genesis, nongenesis) =
                        if eq { (then_branch, else_branch) } else { (else_branch, then_branch) };
                    if stmts_mint_to_burn_address(genesis) {
                        return; // minimum-liquidity lock present — channel closed.
                    }
                    if branch_divides_by_supply(nongenesis, &aliases) {
                        hit = Some(st.span);
                    }
                }
            }
        });
        if hit.is_some() {
            break;
        }
        // `supply == 0 ? CONST : value/supply` ternary form.
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            if let ExprKind::Ternary { cond, then_e, else_e } = &e.kind {
                if let Some(eq) = supply_zero_guard(cond, &aliases) {
                    let (_genesis, nongenesis) =
                        if eq { (then_e, else_e) } else { (else_e, then_e) };
                    if divides_by_supply(nongenesis, &aliases) {
                        hit = Some(e.span);
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

/// True if any statement in `stmts` evaluates an expression that divides by the
/// running supply (or a supply alias).
fn branch_divides_by_supply(stmts: &[sluice_ir::Stmt], aliases: &[String]) -> bool {
    let mut found = false;
    for s in stmts {
        s.visit_exprs(&mut |e| {
            if !found && divides_by_supply(e, aliases) {
                found = true;
            }
        });
        if found {
            break;
        }
    }
    found
}

/// Find a minting function in `c` that carries the unfloored supply-divisor
/// share-price shape. Returns `(function_name, guard_span)`.
fn find_unfloored_supply_divisor_mint(
    cx: &AnalysisContext,
    c: &Contract,
) -> Option<(String, sluice_ir::Span)> {
    for f in cx.scir.functions_of(c.id) {
        if !f.has_body || !function_mints(f) {
            continue;
        }
        if let Some(span) = find_unfloored_divisor_in_fn(f) {
            return Some((f.name.clone(), span));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires_floor(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| {
            f.detector == "vault"
                && matches!(f.category, sluice_findings::Category::FirstDepositor)
        })
    }

    // Frankencoin-Equity shape (M-03): minted shares come from a cubic bonding
    // curve `newTotalShares = totalShares < 1000*ONE_DEC18 ? 1000*ONE_DEC18
    // : _mulD18(totalShares, _cubicRoot(...))`. The 1000-share floor only guards
    // the genesis mint; because holders can `redeem` (burning supply), the supply
    // can be pushed back down to the floor and the share/asset ratio manipulated.
    const CUBIC_CURVE: &str = r#"
        contract Equity {
            uint256 private constant ONE_DEC18 = 10**18;
            function totalSupply() public view returns (uint256) { return 0; }
            function _mulD18(uint256 a, uint256 b) internal pure returns (uint256) { return a * b / ONE_DEC18; }
            function _divD18(uint256 a, uint256 b) internal pure returns (uint256) { return a * ONE_DEC18 / b; }
            function _cubicRoot(uint256 v) internal pure returns (uint256) { return v; }
            function _mint(address to, uint256 amount) internal {}
            function _burn(address from, uint256 amount) internal {}
            function calculateSharesInternal(uint256 capitalBefore, uint256 investment) internal view returns (uint256) {
                uint256 totalShares = totalSupply();
                uint256 newTotalShares = totalShares < 1000 * ONE_DEC18 ? 1000 * ONE_DEC18 : _mulD18(totalShares, _cubicRoot(_divD18(capitalBefore + investment, capitalBefore)));
                return newTotalShares - totalShares;
            }
            function onTokenTransfer(uint256 amount) external returns (uint256) {
                uint256 shares = calculateSharesInternal(1, amount);
                _mint(msg.sender, shares);
                return shares;
            }
            function redeem(uint256 shares) external returns (uint256) {
                _burn(msg.sender, shares);
                return shares;
            }
        }
    "#;

    // The same bonding curve with a bypassable floor, but the contract has *no*
    // redeem/withdraw/burn path: the floor is a one-way genesis guard the supply
    // can never return to, so there is no manipulation channel — must stay silent.
    const CURVE_NO_REDEEM: &str = r#"
        contract MintOnly {
            uint256 private constant ONE_DEC18 = 10**18;
            function totalSupply() public view returns (uint256) { return 0; }
            function _mulD18(uint256 a, uint256 b) internal pure returns (uint256) { return a * b / ONE_DEC18; }
            function _mint(address to, uint256 amount) internal {}
            function calculateSharesInternal(uint256 capitalBefore, uint256 investment) internal view returns (uint256) {
                uint256 totalShares = totalSupply();
                uint256 newTotalShares = totalShares < 1000 * ONE_DEC18 ? 1000 * ONE_DEC18 : _mulD18(totalShares, capitalBefore + investment);
                return newTotalShares - totalShares;
            }
            function mint(uint256 amount) external returns (uint256) {
                uint256 shares = calculateSharesInternal(1, amount);
                _mint(msg.sender, shares);
                return shares;
            }
        }
    "#;

    // A real ERC-4626-style vault protected by OZ virtual shares / decimals
    // offset: `convertToShares` adds `10 ** _decimalsOffset()` virtual shares and
    // `+ 1` virtual assets, which closes the inflation channel. No constant-floor
    // ternary, and the mitigation keyword is present — must stay silent.
    const OZ_VIRTUAL_SHARES: &str = r#"
        contract Vault4626 {
            uint256 public totalSupply;
            uint256 public totalAssets;
            mapping(address => uint256) public shares;
            function _decimalsOffset() internal pure returns (uint8) { return 3; }
            function convertToShares(uint256 assets) public view returns (uint256) {
                return assets * (totalSupply + 10 ** _decimalsOffset()) / (totalAssets + 1);
            }
            function deposit(uint256 assets) external returns (uint256 s) {
                s = convertToShares(assets);
                shares[msg.sender] += s;
                totalSupply += s;
                totalAssets += assets;
            }
            function redeem(uint256 s) external returns (uint256 a) {
                a = s * (totalAssets + 1) / (totalSupply + 10 ** _decimalsOffset());
                shares[msg.sender] -= s;
                totalSupply -= s;
                totalAssets -= a;
            }
        }
    "#;

    // A vault that simply caps total supply with a constant (an `if (totalSupply
    // > CAP) revert` style guard, not a share-pricing ternary) and mints shares
    // 1:1 — no curve scaling by supply, so the floor-curve shape does not match.
    const SUPPLY_CAP_NO_CURVE: &str = r#"
        contract Capped {
            uint256 public constant CAP = 1000 * 10**18;
            uint256 public totalSupply;
            mapping(address => uint256) public shares;
            function deposit(uint256 assets) external returns (uint256 s) {
                s = assets;
                require(totalSupply + s < CAP, "cap");
                shares[msg.sender] += s;
                totalSupply += s;
            }
            function redeem(uint256 s) external { shares[msg.sender] -= s; totalSupply -= s; }
        }
    "#;

    #[test]
    fn fires_on_bypassable_floor_curve() {
        let fs = run(CUBIC_CURVE);
        assert!(fires_floor(&fs), "expected FirstDepositor on cubic curve, got {:?}", fs);
    }

    #[test]
    fn silent_without_redeem_path() {
        let fs = run(CURVE_NO_REDEEM);
        assert!(!fires_floor(&fs), "no redeem path => floor not bypassable; got {:?}", fs);
    }

    #[test]
    fn silent_on_oz_virtual_shares() {
        let fs = run(OZ_VIRTUAL_SHARES);
        assert!(!fires_floor(&fs), "OZ virtual-shares vault must stay silent; got {:?}", fs);
    }

    #[test]
    fn silent_on_supply_cap_without_curve() {
        let fs = run(SUPPLY_CAP_NO_CURVE);
        assert!(!fires_floor(&fs), "supply cap with no curve scaling must stay silent; got {:?}", fs);
    }

    // Asymmetry-SafEth H-01 shape: a non-ERC4626 staking-share token prices new
    // shares from `preDepositPrice = totalSupply == 0 ? 1e18 : (1e18 *
    // underlyingValue) / totalSupply`, where `underlyingValue` is the live sum of
    // external derivative balances. The `== 0` branch guards only the genesis mint
    // (no virtual/dead shares); because `unstake` burns supply, a sole staker can
    // shrink the supply and inflate the value/supply ratio so later stakers' mint
    // rounds toward zero — the first-depositor / share-inflation class.
    const ASYMMETRY_PRICE: &str = r#"
        interface IDerivative { function balance() external view returns (uint256); function ethPerDerivative(uint256) external view returns (uint256); function withdraw(uint256) external; }
        contract SafEth {
            mapping(uint256 => IDerivative) public derivatives;
            uint256 public derivativeCount;
            function totalSupply() public view returns (uint256) { return 0; }
            function _mint(address to, uint256 amount) internal {}
            function _burn(address from, uint256 amount) internal {}
            function stake() external payable {
                uint256 underlyingValue = 0;
                for (uint i = 0; i < derivativeCount; i++)
                    underlyingValue += (derivatives[i].ethPerDerivative(derivatives[i].balance()) * derivatives[i].balance()) / 10 ** 18;
                uint256 totalSupply = totalSupply();
                uint256 preDepositPrice;
                if (totalSupply == 0) preDepositPrice = 10 ** 18;
                else preDepositPrice = (10 ** 18 * underlyingValue) / totalSupply;
                uint256 mintAmount = (underlyingValue * 10 ** 18) / preDepositPrice;
                _mint(msg.sender, mintAmount);
            }
            function unstake(uint256 amount) external {
                _burn(msg.sender, amount);
            }
        }
    "#;

    // The ternary form of the same shape: `price = supply == 0 ? 1e18 :
    // value / supply` written as a `? :` expression rather than an `if/else`,
    // AND with the supply read into a short local `ts` (not named like the
    // supply) — exercises both the ternary arm and the `ts = totalSupply()`
    // alias-tracking. Must fire.
    const ASYMMETRY_PRICE_TERNARY: &str = r#"
        contract StakeT {
            uint256 liveValue;
            function totalSupply() public view returns (uint256) { return 0; }
            function _mint(address to, uint256 amount) internal {}
            function _burn(address from, uint256 amount) internal {}
            function stake(uint256 deposited) external {
                uint256 ts = totalSupply();
                uint256 price = ts == 0 ? 10 ** 18 : (10 ** 18 * liveValue) / ts;
                uint256 minted = deposited * 10 ** 18 / price;
                _mint(msg.sender, minted);
            }
            function withdraw(uint256 amount) external { _burn(msg.sender, amount); }
        }
    "#;

    // Balancer-style genesis lock: `if (totalSupply() == 0) { _mintPoolTokens(
    // address(0), MINIMUM); _mintPoolTokens(recipient, out - MINIMUM); } else {
    // _mintPoolTokens(recipient, out); }`. The empty-pool branch mints a minimum
    // amount to the zero address (dead shares), which closes the first-depositor
    // channel, and the non-genesis branch does NOT divide by the supply — must
    // stay silent even though there is a burn path.
    const BALANCER_MIN_LOCK: &str = r#"
        contract Pool {
            uint256 internal constant MINIMUM_BPT = 1e6;
            function totalSupply() public view returns (uint256) { return 0; }
            function _mintPoolTokens(address to, uint256 amount) internal {}
            function _burnPoolTokens(address from, uint256 amount) internal {}
            function _onJoin(bytes memory d) internal returns (uint256) { return 1; }
            function _onInit(bytes memory d) internal returns (uint256) { return 1; }
            function onJoinPool(address recipient, bytes memory userData) external returns (uint256 out) {
                if (totalSupply() == 0) {
                    out = _onInit(userData);
                    _mintPoolTokens(address(0), MINIMUM_BPT);
                    _mintPoolTokens(recipient, out - MINIMUM_BPT);
                } else {
                    out = _onJoin(userData);
                    _mintPoolTokens(recipient, out);
                }
            }
            function exitPool(uint256 amount) external { _burnPoolTokens(msg.sender, amount); }
        }
    "#;

    // The asymmetry divisor shape but with NO supply reducer (no unstake/burn):
    // the `== 0` genesis guard can never be re-entered, so the price cannot be
    // manipulated back down — must stay silent (mirrors silent_without_redeem_path).
    const DIVISOR_NO_REDEEM: &str = r#"
        contract MintOnlyPrice {
            uint256 liveValue;
            function totalSupply() public view returns (uint256) { return 0; }
            function _mint(address to, uint256 amount) internal {}
            function stake(uint256 deposited) external {
                uint256 ts = totalSupply();
                uint256 price = ts == 0 ? 10 ** 18 : (10 ** 18 * liveValue) / ts;
                _mint(msg.sender, deposited * 10 ** 18 / price);
            }
        }
    "#;

    #[test]
    fn fires_on_asymmetry_unfloored_divisor() {
        let fs = run(ASYMMETRY_PRICE);
        assert!(
            fires_floor(&fs),
            "expected FirstDepositor on supply-divisor share price (Asymmetry H-01), got {:?}",
            fs
        );
    }

    #[test]
    fn fires_on_asymmetry_divisor_ternary() {
        let fs = run(ASYMMETRY_PRICE_TERNARY);
        assert!(fires_floor(&fs), "expected FirstDepositor on ternary supply-divisor price, got {:?}", fs);
    }

    #[test]
    fn silent_on_balancer_minimum_liquidity_lock() {
        let fs = run(BALANCER_MIN_LOCK);
        assert!(
            !fires_floor(&fs),
            "genesis mint of dead shares to address(0) closes the channel; must stay silent; got {:?}",
            fs
        );
    }

    #[test]
    fn silent_on_divisor_without_redeem() {
        let fs = run(DIVISOR_NO_REDEEM);
        assert!(
            !fires_floor(&fs),
            "no supply reducer => zero-guard not bypassable; must stay silent; got {:?}",
            fs
        );
    }
}
