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
}
