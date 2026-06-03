//! Spot-price oracle manipulation: a manipulable price (`balanceOf`,
//! `getReserves`, `pricePerShare`, ...) feeds protocol accounting with no robust
//! oracle / TWAP. The Cream / Harvest / bZx class.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::detectors::is_accounting_name;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{Call, CallKind, Expr, ExprKind, Function, Span};

pub struct OracleDetector;

impl Detector for OracleDetector {
    fn id(&self) -> &'static str {
        "oracle-manipulation"
    }
    fn category(&self) -> Category {
        Category::OracleManipulation
    }
    fn description(&self) -> &'static str {
        "Manipulable spot price (balanceOf/getReserves/pricePerShare) used for value"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || !f.is_externally_reachable() {
                continue;
            }
            // Robust oracle present → suppress (Chainlink staleness is a separate class).
            if cx.uses_robust_oracle(f) {
                continue;
            }
            // A spot price may be read locally, OR reached cross-contract: the
            // function calls an external oracle whose in-repo implementation
            // itself reads a manipulable spot source (resolved via the frontier's
            // ContractResolver). The latter is invisible to single-contract tools.
            let (price_span, cross) = match find_spot_price_for_valuation(cx, f) {
                Some(s) => (s, false),
                None => match find_cross_contract_spot_oracle(cx, f) {
                    Some(s) => (s, true),
                    None => continue,
                },
            };
            // The price must influence accounting: a write to an accounting var,
            // or the function mints/borrows/values something.
            let writes_accounting = f.effects.written_vars().iter().any(|v| is_accounting_name(v));
            let valuation_name = {
                let l = f.name.to_ascii_lowercase();
                l.contains("price")
                    || l.contains("value")
                    || l.contains("collateral")
                    || l.contains("mint")
                    || l.contains("borrow")
                    || l.contains("deposit")
                    || l.contains("redeem")
                    || l.contains("liquidat")
            };
            if !writes_accounting && !valuation_name {
                continue;
            }

            let message = if cross {
                format!(
                    "`{}` values assets via an external oracle whose in-repo implementation derives \
                     its price from an instantaneous spot source (`getReserves`/`balanceOf`/`slot0`). \
                     The dependency is cross-contract, so the manipulation surface is not visible in \
                     this function alone, but an attacker can still move the underlying pool within one \
                     transaction to mint/borrow/liquidate at a false valuation (Cream/Harvest class).",
                    f.name
                )
            } else {
                format!(
                    "`{}` derives a value from an instantaneous on-chain price (a `balanceOf` / \
                     `getReserves` / `pricePerShare`-style read). An attacker can move that source \
                     within one transaction (flash-loan-assisted) to mint, borrow, or liquidate at a \
                     false valuation — the Cream/Harvest/bZx class.",
                    f.name
                )
            };
            let b = FindingBuilder::new(self.id(), Category::OracleManipulation)
                .title(if cross {
                    "Cross-contract manipulable spot price used for valuation"
                } else {
                    "Manipulable spot price used for valuation"
                })
                .severity(Severity::High)
                .confidence({
                    let base = if cross { 0.5 } else { 0.55 };
                    // An access-controlled valuation can only be driven by a
                    // trusted actor — much lower manipulation risk.
                    if cx.has_access_control(f) { base * 0.5 } else { base }
                })
                .dimension(Dimension::ValueFlow)
                .dimension(Dimension::Frontier)
                .message(message)
                .recommendation(
                    "Price via a manipulation-resistant source: a Chainlink feed with staleness + \
                     deviation checks, or a sufficiently long TWAP; never a single spot reserve / \
                     `balanceOf` (directly or through a thin oracle wrapper).",
                );
            out.push(cx.finish(b, f.id, price_span));
        }
        out
    }
}

/// Find the first spot-price read in `f` that is genuinely manipulable *as a
/// valuation source*, returning its span.
///
/// This is a local refinement of the shared `find_spot_price`: for `balanceOf`
/// reads we discriminate on the argument. A `balanceOf` is only a manipulable
/// price when it reads the *protocol's own* (or a pool/pair/vault/reserve)
/// holdings — `balanceOf(address(this))` or `balanceOf(<pool>)` — which an
/// attacker can flash-loan-move within a single transaction (Cream/Harvest).
/// When the argument is instead a *user-supplied account* (`msg.sender`,
/// `_msgSender()`, `tx.origin`, `owner()`, or a parameter/identifier named like
/// a user/owner/recipient/account), the call is just reading that account's own
/// balance — typically to cap a deposit/redeem at what the caller actually holds
/// — which is NOT a price and cannot be manipulated against the protocol. Those
/// are suppressed here (confirmed FPs on Aave v3's `ERC4626StataToken`:
/// `depositATokens`/`depositWithPermit` use `balanceOf(_msgSender())` and
/// `maxRedeem` uses `balanceOf(owner)` purely as deposit/redeem caps).
///
/// Non-`balanceOf` spot reads (`getReserves`/`slot0`/`pricePerShare`/...) are
/// delegated unchanged to the shared `sluice_dataflow::is_spot_price_call`
/// classifier; the discrimination is intentionally local to this detector so the
/// shared classifier (used by other detectors) is not perturbed.
///
/// A second local refinement (also confined here) SUPPRESSES the `getPrice`-style
/// match when the "price" source is actually a Chainlink / oracle-*feed* read
/// (`latestRoundData`/`latestAnswer`/`getRoundData`/`getPrice`/`getPriceUnsafe`/
/// `consult` on an `IPriceFeed`/`AggregatorV3`/`*Oracle`/`*PriceFeed` handle, or
/// an in-repo wrapper that resolves to such a feed read). A push-feed answer is
/// NOT attacker-movable within a transaction, so it is an oracle-staleness
/// dependency, not a flash-manipulable spot price (confirmed FPs on Compound
/// Comet: `isLiquidatable`/`isBorrowCollateralized`/`buyCollateral`/
/// `quoteCollateral` all price via `getPrice(priceFeed)` →
/// `IPriceFeed(priceFeed).latestRoundData()`). Genuine spot reads
/// (`balanceOf(address(this))`/`getReserves`/`slot0`/`pricePerShare` on a
/// pool/pair/vault) are untouched and keep firing (Cream/Harvest/bZx class).
fn find_spot_price_for_valuation(cx: &AnalysisContext, f: &Function) -> Option<Span> {
    let mut found: Option<Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if is_manipulable_spot_price(cx, f, c) {
                    found = Some(e.span);
                }
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// Local spot-price classifier with `balanceOf`-argument discrimination and
/// Chainlink/oracle-feed suppression.
fn is_manipulable_spot_price(cx: &AnalysisContext, f: &Function, c: &Call) -> bool {
    match c.func_name.as_deref() {
        Some("balanceOf") => match c.args.first() {
            // `balanceOf(<arg>)` is a manipulable price only when `<arg>` is the
            // protocol's own / a pool handle, not a user/owner/recipient account.
            Some(arg) => !is_user_account_arg(f, arg),
            // `balanceOf()` with no argument: not a meaningful spot read.
            None => false,
        },
        // All other spot reads keep the shared classifier's behaviour exactly,
        // EXCEPT a read that is really a Chainlink/oracle-feed dependency: that is
        // not attacker-movable within a tx (oracle-staleness's domain), so it is
        // suppressed here even though the shared classifier counts `getPrice` as a
        // generic spot read.
        _ => sluice_dataflow::is_spot_price_call(c) && !is_oracle_feed_read(cx, f, c),
    }
}

/// Names of read methods that, *on an oracle/feed handle*, denote a robust
/// push-feed answer (Chainlink) or a TWAP — NOT a flash-manipulable spot price.
/// `latestRoundData`/`latestAnswer`/`getRoundData` are unambiguously Chainlink;
/// `getPrice`/`getPriceUnsafe`/`consult`/`peek`/`read`/`price` are ambiguous and
/// only treated as a feed read when the receiver (or the resolved in-repo wrapper)
/// is itself an oracle feed.
const FEED_METHODS: &[&str] = &[
    "latestRoundData",
    "latestAnswer",
    "getRoundData",
    "getPrice",
    "getPriceUnsafe",
    "consult",
    "peek",
    "read",
    "price",
    "getAnswer",
];

/// Methods that are *always* a Chainlink read regardless of how the receiver is
/// spelled — seeing one of these is conclusive evidence of an oracle-feed (push)
/// dependency, never a spot read.
const CHAINLINK_METHODS: &[&str] = &["latestRoundData", "latestAnswer", "getRoundData", "getAnswer"];

/// Is `c` a Chainlink / oracle-*feed* read (an oracle-staleness dependency)
/// rather than an attacker-movable spot price?
///
/// Three shapes, all confined to this detector:
///   1. A direct Chainlink method (`latestRoundData`/`latestAnswer`/...) — always
///      a feed read.
///   2. An ambiguous feed method (`getPrice`/`consult`/...) on a receiver whose
///      type or name is an oracle/feed handle (`IPriceFeed`/`AggregatorV3`/
///      `*Oracle`/`*PriceFeed`).
///   3. An ambiguous feed method called as a *bare in-repo function*
///      (`getPrice(priceFeed)`, no receiver) that resolves to a same-name in-repo
///      function whose body is itself a feed read — the Comet `getPrice` wrapper.
fn is_oracle_feed_read(cx: &AnalysisContext, f: &Function, c: &Call) -> bool {
    // (1)+(2): a feed read visible directly at this call site.
    if is_direct_feed_read(cx, f, c) {
        return true;
    }
    let Some(method) = c.func_name.as_deref() else { return false };
    // Only the ambiguous feed-method names follow an in-repo wrapper. A call with
    // a present-but-not-feed-shaped receiver was already rejected by
    // `is_direct_feed_read`; here we only follow *bare* in-repo calls.
    if !FEED_METHODS.contains(&method) || c.receiver.is_some() {
        return false;
    }
    // (3) Bare in-repo wrapper: `getPrice(priceFeed)` with no receiver. Resolve to
    // a same-named in-repo function and check whether its body is a feed read (and
    // is NOT itself a manipulable spot read — a spot-backed wrapper must keep
    // firing, Cream/Harvest routed through an internal helper).
    if c.kind == CallKind::Internal || c.kind == CallKind::Unknown {
        return wrapper_is_feed_read(cx, f, method);
    }
    false
}

/// Cases (1)+(2): is `c` *itself* a feed read — a Chainlink method, or an
/// ambiguous feed method on an oracle/feed-typed-or-named receiver? Does NOT
/// follow in-repo wrappers (so it never recurses), making it the safe spot-vs-feed
/// discriminator to reuse inside a wrapper body scan.
fn is_direct_feed_read(cx: &AnalysisContext, f: &Function, c: &Call) -> bool {
    let Some(method) = c.func_name.as_deref() else { return false };
    if CHAINLINK_METHODS.contains(&method) {
        return true;
    }
    if !FEED_METHODS.contains(&method) {
        return false;
    }
    // `IPriceFeed(x).getPrice()` / `someOracle.consult(...)`: receiver is an
    // oracle/feed handle (by declared type or by identifier name).
    if let Some(recv) = c.receiver.as_deref() {
        let ty_feed =
            receiver_type(cx, f, recv).map(|t| is_oracle_feed_typename(&t)).unwrap_or(false);
        let name_feed = receiver_name(recv).map(|n| is_oracle_feed_name(&n)).unwrap_or(false);
        return ty_feed || name_feed;
    }
    false
}

/// Non-recursing local spot classifier: `is_manipulable_spot_price` minus the
/// in-repo-wrapper following. Used inside a wrapper body so wrapper resolution
/// happens only once (at the top-level call), never nested.
fn is_local_manipulable_spot(cx: &AnalysisContext, f: &Function, c: &Call) -> bool {
    match c.func_name.as_deref() {
        Some("balanceOf") => match c.args.first() {
            Some(arg) => !is_user_account_arg(f, arg),
            None => false,
        },
        _ => sluice_dataflow::is_spot_price_call(c) && !is_direct_feed_read(cx, f, c),
    }
}

/// True if a same-named in-repo function (preferring the caller's own contract /
/// its bases, then any contract) has a body that reads a Chainlink/oracle feed
/// and does NOT read a manipulable spot source.
fn wrapper_is_feed_read(cx: &AnalysisContext, f: &Function, name: &str) -> bool {
    // Candidate functions defined in-repo with this exact name. Prefer the
    // caller's own contract first so an unrelated same-named function elsewhere
    // cannot flip the classification.
    let own_contract = cx.contract_of(f.id).map(|c| c.id);
    let mut candidates: Vec<&Function> = cx
        .functions()
        .filter(|g| g.name == name && g.has_body && g.id != f.id)
        .collect();
    candidates.sort_by_key(|g| (Some(g.contract) != own_contract) as u8);

    for g in candidates {
        let (mut feed, mut spot) = (false, false);
        for s in &g.body {
            s.visit_exprs(&mut |e| {
                if let ExprKind::Call(call) = &e.kind {
                    // A feed read visible directly in the wrapper body.
                    if is_direct_feed_read(cx, g, call) {
                        feed = true;
                    }
                    // A genuine manipulable spot read inside the wrapper.
                    if is_local_manipulable_spot(cx, g, call) {
                        spot = true;
                    }
                }
            });
        }
        if feed && !spot {
            return true;
        }
        if spot {
            // A spot-backed wrapper of this name exists: do not suppress.
            return false;
        }
    }
    false
}

/// Does a receiver *type* name denote an oracle / price-feed handle?
/// Matches `IPriceFeed`, `AggregatorV3Interface`, `AggregatorV2V3Interface`,
/// `*Oracle`, `*PriceFeed`, `*PriceOracle`, `*Aggregator`, ... (case-insensitive).
fn is_oracle_feed_typename(ty: &str) -> bool {
    let l = first_token(ty).to_ascii_lowercase();
    let l = l.trim_start_matches('_');
    l.contains("pricefeed")
        || l.contains("aggregator")
        || l.contains("chainlink")
        || l.contains("oracle")
        || l.contains("datafeed")
        || l.contains("feedregistry")
}

/// Does a receiver *name* (state var / param identifier) read like an oracle /
/// price-feed handle? e.g. `priceFeed`, `baseTokenPriceFeed`, `oracle`,
/// `chainlinkFeed`, `feed`. Deliberately requires a feed/oracle-shaped token so a
/// generic identifier never suppresses a real spot read.
fn is_oracle_feed_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    let l = l.trim_start_matches('_');
    l.contains("pricefeed")
        || l.contains("price_feed")
        || l.contains("aggregator")
        || l.contains("chainlink")
        || l.contains("oracle")
        || l == "feed"
        || l.ends_with("feed")
}

/// Best-effort identifier name of a call receiver (`priceFeed`,
/// `baseTokenPriceFeed`, or the inner identifier of a cast `IPriceFeed(x)` →
/// `x`). Returns `None` for shapes we do not model as a plain handle.
fn receiver_name(recv: &Expr) -> Option<String> {
    match &recv.kind {
        ExprKind::Ident(n) => Some(n.clone()),
        // `IPriceFeed(priceFeed)` — the cast's argument identifier.
        ExprKind::Call(c) if c.kind == CallKind::TypeCast => {
            c.args.first().and_then(|a| receiver_name(a))
        }
        // `cfg.baseTokenPriceFeed` — the accessed member.
        ExprKind::Member { member, .. } => Some(member.clone()),
        _ => None,
    }
}

/// Is this `balanceOf` argument a *user-supplied account* (so the read is the
/// caller's own balance, not a manipulable pool/protocol balance)?
///
/// True for `msg.sender`, `_msgSender()`, `tx.origin`, `owner()`, and any
/// identifier that is a function parameter OR is simply named like a user /
/// owner / recipient / account. Deliberately conservative: anything that does
/// NOT clearly look like an arbitrary account (e.g. `address(this)`, a pool /
/// pair / vault / reserve state handle, a cast over such a handle) returns
/// `false` so the genuine flash-loanable reads (Cream's `balanceOf(yVault)`,
/// `balanceOf(address(this))`) keep firing.
fn is_user_account_arg(f: &Function, arg: &Expr) -> bool {
    match &arg.kind {
        // `address(x)` / `payable(x)` — unwrap the cast and re-judge the inner.
        // (A cast over `this` / a pool handle is NOT a user account; a cast over
        // `msg.sender` / a user param IS.)
        ExprKind::Call(inner) if inner.kind == CallKind::TypeCast => {
            inner.args.first().map(|a| is_user_account_arg(f, a)).unwrap_or(false)
        }
        // `msg.sender`, `tx.origin`.
        ExprKind::Member { base, member } => {
            matches!(&base.kind, ExprKind::Ident(b) if b == "msg") && member == "sender"
                || matches!(&base.kind, ExprKind::Ident(b) if b == "tx") && member == "origin"
        }
        // `_msgSender()` / `msgSender()` / `_owner()` / `owner()` — getters that
        // resolve to the calling user / contract owner. A bare account getter
        // with no receiver and a user/owner-like name.
        ExprKind::Call(call) if call.receiver.is_none() => call
            .func_name
            .as_deref()
            .map(is_user_account_name)
            .unwrap_or(false),
        // `owner`, `user`, `account`, `receiver`, ... — a parameter or a plainly
        // user/owner-named identifier. `this` is the protocol itself (NOT a user
        // account), so it is excluded by `is_user_account_name`.
        ExprKind::Ident(name) => {
            // Any function parameter that is an account-typed user input, or any
            // identifier whose name reads like a user/owner/recipient account.
            is_user_account_name(name) || is_account_param(f, name)
        }
        _ => false,
    }
}

/// Is `name` a function parameter that is an *address-typed* user input (so a
/// `balanceOf(name)` is the caller's-own / an externally-supplied account's
/// balance)? Restricted to address-typed params so a numeric/amount parameter
/// reused as a name never accidentally suppresses a real pool read.
fn is_account_param(f: &Function, name: &str) -> bool {
    f.params.iter().any(|p| {
        p.name.as_deref() == Some(name) && {
            let ty = p.ty.split_whitespace().next().unwrap_or(&p.ty);
            ty == "address" || ty.starts_with("address")
        }
    })
}

/// Does this identifier / getter name read like a user / owner / recipient /
/// arbitrary account (as opposed to the protocol's own pool/pair/vault handle)?
fn is_user_account_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    let l = l.trim_start_matches('_');
    // `this` is the protocol's own address — emphatically NOT a user account,
    // and a pool/pair/vault/reserve handle is the protocol's own balance.
    if l == "this"
        || l.contains("pool")
        || l.contains("pair")
        || l.contains("vault")
        || l.contains("reserve")
    {
        return false;
    }
    // Exact matches for short/ambiguous account names. Substring matching these
    // would misfire (e.g. `token` contains `to`, `freshAmount` contains `from`),
    // wrongly suppressing genuine pool reads, so they must match the whole name.
    const EXACT: &[&str] = &["from", "to", "payer", "payee", "minter", "burner"];
    if EXACT.contains(&l) {
        return true;
    }
    // Unambiguous account substrings.
    [
        "msgsender", "sender", "owner", "user", "account", "recipient", "receiver", "holder",
        "beneficiary", "caller", "depositor", "redeemer", "spender", "borrower", "lender",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// Find an external call in `f` whose target type resolves (via the cross-contract
/// resolver) to an in-repo implementation that itself reads a manipulable spot
/// price. Returns the call's span.
fn find_cross_contract_spot_oracle(cx: &AnalysisContext, f: &Function) -> Option<Span> {
    let mut hit: Option<Span> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if !c.kind.is_external_transfer_of_control() {
                    return;
                }
                let (Some(method), Some(recv)) = (c.func_name.as_deref(), c.receiver.as_deref())
                else {
                    return;
                };
                if let Some(ty) = receiver_type(cx, f, recv) {
                    if cx.frontier.resolver.resolves_to_spot_oracle(cx.scir, &ty, method).is_some() {
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

/// Best-effort type name of a call receiver: an interface cast `IOracle(x)`, or
/// the declared type of a parameter / state variable named like the receiver.
fn receiver_type(cx: &AnalysisContext, f: &Function, recv: &Expr) -> Option<String> {
    match &recv.kind {
        // `IOracle(addr).method()` — the cast's name is the type.
        ExprKind::Call(c) if c.kind == CallKind::TypeCast => c.func_name.clone(),
        ExprKind::Ident(name) => {
            if let Some(p) = f.params.iter().find(|p| p.name.as_deref() == Some(name.as_str())) {
                return Some(first_token(&p.ty));
            }
            if let Some(c) = cx.contract_of(f.id) {
                if let Some(v) = c.state_vars.iter().find(|v| &v.name == name) {
                    return Some(first_token(&v.ty));
                }
            }
            None
        }
        _ => None,
    }
}

fn first_token(ty: &str) -> String {
    ty.split_whitespace().next().unwrap_or(ty).to_string()
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn fired(src: &str) -> bool {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default())
            .findings
            .iter()
            .any(|f| f.detector == "oracle-manipulation")
    }

    // FALSE-POSITIVE CASE (confirmed on Aave v3 `ERC4626StataTokenUpgradeable`):
    // `balanceOf(_msgSender())` / `balanceOf(owner)` cap a deposit/redeem at the
    // *caller's own* balance. That is not a price and cannot be manipulated
    // against the protocol — the detector MUST stay silent. Distilled from
    // `depositATokens` (L79), `depositWithPermit` (L114), `maxRedeem` (L174).
    const AAVE_USER_BALANCE_CAP: &str = r#"
        interface IERC20 {
            function balanceOf(address account) external view returns (uint256);
        }
        contract StataToken {
            function aToken() public view returns (address) { return address(this); }
            function _msgSender() internal view returns (address) { return msg.sender; }
            function previewDeposit(uint256 a) public view returns (uint256) { return a; }

            // balanceOf(_msgSender()) — caller's own balance as a deposit cap.
            function depositATokens(uint256 assets) external view returns (uint256) {
                uint256 actualUserBalance = IERC20(aToken()).balanceOf(_msgSender());
                if (assets > actualUserBalance) { assets = actualUserBalance; }
                return previewDeposit(assets);
            }

            // balanceOf(owner) — owner is a user-supplied account parameter.
            function maxRedeem(address owner) public view returns (uint256) {
                uint256 cachedUserBalance = IERC20(aToken()).balanceOf(owner);
                return cachedUserBalance;
            }
        }
    "#;

    // TRUE-POSITIVE CASE (Cream/Harvest class): `balanceOf(address(<vault>))`
    // reads the *protocol/pool's* holdings and derives a share price from it —
    // an attacker flash-loan-donates to the vault to inflate the price within one
    // tx, then borrows against the inflated valuation. MUST still fire.
    const POOL_BALANCE_AS_PRICE: &str = r#"
        interface IERC20 { function balanceOf(address account) external view returns (uint256); }
        interface IYVault { function totalSupply() external view returns (uint256); }
        contract Lending {
            IYVault public yVault;
            IERC20 public underlying;
            mapping(address => uint256) public collateralShares;
            mapping(address => uint256) public debtOf;

            // balanceOf(address(yVault)) — pool's own holdings = manipulable price.
            function pricePerShare() public view returns (uint256) {
                uint256 vaultAssets = underlying.balanceOf(address(yVault));
                uint256 shares = yVault.totalSupply();
                return (vaultAssets * 1e18) / shares;
            }
            function collateralValue(address user) public view returns (uint256) {
                return (collateralShares[user] * pricePerShare()) / 1e18;
            }
            function borrow(uint256 amount) external {
                require(debtOf[msg.sender] + amount <= collateralValue(msg.sender), "undercoll");
                debtOf[msg.sender] += amount;
            }
        }
    "#;

    // TRUE-POSITIVE CASE: `balanceOf(address(this))` used as a price. The shared
    // dataflow classifier treats this as an own-balance audit read, but as a
    // *valuation* source it is exactly the donatable balance an attacker inflates
    // (Sonne/Compound `getCash` class). The local classifier re-includes it.
    const SELF_BALANCE_AS_PRICE: &str = r#"
        interface IERC20 { function balanceOf(address account) external view returns (uint256); }
        contract Market {
            IERC20 public underlying;
            uint256 public totalSupply;
            mapping(address => uint256) public debtOf;

            function pricePerShare() public view returns (uint256) {
                uint256 assets = underlying.balanceOf(address(this));
                return (assets * 1e18) / totalSupply;
            }
            function borrow(uint256 amount) external {
                require(amount <= pricePerShare(), "undercoll");
                debtOf[msg.sender] += amount;
            }
        }
    "#;

    #[test]
    fn silent_on_user_balance_cap() {
        assert!(
            !fired(AAVE_USER_BALANCE_CAP),
            "balanceOf(_msgSender())/balanceOf(owner) deposit caps are not a manipulable price"
        );
    }

    #[test]
    fn fires_on_pool_balance_as_price() {
        assert!(
            fired(POOL_BALANCE_AS_PRICE),
            "balanceOf(address(yVault)) used as a share price IS manipulable (Cream/Harvest)"
        );
    }

    #[test]
    fn fires_on_self_balance_as_price() {
        assert!(
            fired(SELF_BALANCE_AS_PRICE),
            "balanceOf(address(this)) used as a valuation IS manipulable (donatable balance)"
        );
    }

    // FALSE-POSITIVE CASE (confirmed on Compound Comet): the protocol prices via
    // `getPrice(priceFeed)`, a thin in-repo wrapper over Chainlink
    // (`IPriceFeed(priceFeed).latestRoundData()`). A push-feed answer is NOT
    // attacker-movable within a transaction — it is an oracle-*staleness*
    // dependency, not a flash-manipulable spot price — so `oracle-manipulation`
    // MUST stay silent. Distilled from `isLiquidatable` (L576) / `getPrice` (L493).
    const COMET_CHAINLINK_WRAPPER: &str = r#"
        interface IPriceFeed {
            function latestRoundData() external view
                returns (uint80, int256, uint256, uint256, uint80);
        }
        contract Comet {
            address public baseTokenPriceFeed;
            mapping(address => int256) principal;

            // Thin Chainlink wrapper — the exact Comet shape.
            function getPrice(address priceFeed) public view returns (uint256) {
                (, int256 price, , , ) = IPriceFeed(priceFeed).latestRoundData();
                require(price > 0, "bad price");
                return uint256(price);
            }
            function isLiquidatable(address account) public view returns (bool) {
                int256 liquidity = principal[account] * int256(getPrice(baseTokenPriceFeed));
                return liquidity < 0;
            }
        }
    "#;

    // FALSE-POSITIVE CASE: a function that reads a Chainlink feed *directly*
    // (`IPriceFeed(feed).latestRoundData()`) to value a liquidation. Same class —
    // a robust push feed, not a movable spot price. MUST stay silent.
    const DIRECT_CHAINLINK_LIQUIDATION: &str = r#"
        interface AggregatorV3Interface {
            function latestRoundData() external view
                returns (uint80, int256, uint256, uint256, uint80);
        }
        contract Lender {
            AggregatorV3Interface public oracle;
            mapping(address => uint256) debtOf;
            function liquidate(address account) external view returns (bool) {
                (, int256 answer, , , ) = oracle.latestRoundData();
                return debtOf[account] > uint256(answer);
            }
        }
    "#;

    // TRUE-POSITIVE CASE (keep firing): a `getReserves` AMM spot read used as a
    // price. This is the canonical flash-manipulable source (Uniswap-pair reserves)
    // and is the Cream/bZx class — the Chainlink suppression MUST NOT touch it.
    const GETRESERVES_SPOT_PRICE: &str = r#"
        interface IPair {
            function getReserves() external view returns (uint112, uint112, uint32);
        }
        contract Lending {
            IPair public pair;
            mapping(address => uint256) public debtOf;
            function getPrice() public view returns (uint256) {
                (uint112 r0, uint112 r1, ) = pair.getReserves();
                return (uint256(r1) * 1e18) / uint256(r0);
            }
            function borrow(uint256 amount) external {
                require(amount <= getPrice(), "undercoll");
                debtOf[msg.sender] += amount;
            }
        }
    "#;

    #[test]
    fn silent_on_comet_chainlink_wrapper() {
        assert!(
            !fired(COMET_CHAINLINK_WRAPPER),
            "getPrice(priceFeed) over Chainlink latestRoundData is a push feed, not a movable spot price"
        );
    }

    #[test]
    fn silent_on_direct_chainlink_liquidation() {
        assert!(
            !fired(DIRECT_CHAINLINK_LIQUIDATION),
            "IPriceFeed(feed).latestRoundData() liquidation prices via a robust feed, not a spot read"
        );
    }

    #[test]
    fn fires_on_getreserves_spot_price() {
        assert!(
            fired(GETRESERVES_SPOT_PRICE),
            "getReserves() used as a price IS a flash-manipulable spot read (Cream/bZx class)"
        );
    }
}
