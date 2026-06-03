//! Pooled-shares reprice desync — a one-sided mutation of a per-key pooled-asset
//! balance while the paired per-key share supply stays fixed, silently
//! repricing everyone's claim.
//!
//! This is the **Symbiotic withdrawal-queue-under-slashing** shape. A vault
//! accounts pooled withdrawals per epoch/id with two parallel mappings: the
//! pooled *assets* held for that key, and the *share supply* minted against that
//! key. A claim is priced proportionally — `assets[k] * userShares / shares[k]`
//! (the `previewRedeem` / `convertToAssets` / `claim` math). The invariant is
//! that the two mappings move **together**: whenever the pooled assets for a key
//! change, the share supply for that same key must change in lockstep (or the
//! per-share price must be intended to move, e.g. a deposit at the current rate).
//!
//! A privileged / external path (a slashing hook, a sweep, an admin
//! rebalance) that mutates `withdrawals[epoch]` / `pooledAssets[id]` **without**
//! touching the paired `withdrawalShares[epoch]` / `shares[id]` breaks that
//! lockstep: the numerator of the pricing formula moves while the denominator is
//! frozen, so every outstanding share is silently repriced. Under slashing this
//! lets the loss be socialised incorrectly — early claimants redeem at the
//! pre-slash price and drain the queue, leaving the rest short — or, in the
//! inflate direction, a one-sided top-up over-pays whoever claims first.
//!
//! ```solidity
//! mapping(uint256 => uint256) public withdrawals;        // pooled assets / epoch
//! mapping(uint256 => uint256) public withdrawalShares;   // share supply / epoch
//!
//! // repricing site (the invariant): price = assets[k] * s / shares[k]
//! function withdrawalsOf(uint256 epoch, uint256 s) public view returns (uint256) {
//!     return withdrawals[epoch] * s / withdrawalShares[epoch];
//! }
//!
//! // one-sided writer (the bug): assets move, shares frozen
//! function onSlash(uint256 epoch, uint256 slashed) external onlySlasher {
//!     withdrawals[epoch] -= slashed;                     // <-- no withdrawalShares write
//! }
//! ```
//!
//! In the real Symbiotic `Vault`, the proportional price is not an inline `/`: it
//! is an **ERC-4626 ratio helper** — `ERC4626Math.previewRedeem(userShares,
//! withdrawals[epoch], withdrawalShares[epoch])`, i.e.
//! `convertToAssets(shares, totalAssets, totalShares)` — so the assets var and the
//! share-supply var appear as the two *pool-total* arguments of the helper call,
//! not as the numerator/denominator of a `Div`. The detector treats both forms as
//! the same repricing invariant.
//!
//! Precision strategy (single Invariant dimension, Medium @ 0.5):
//!   * we only fire when a **repricing site pairs** an assets-like var with a
//!     shares-like var, indexed by the *same key* — either as an inline
//!     `assets[k] * s / shares[k]` division, or as the two pool-total arguments of
//!     an ERC-4626 ratio helper (`previewRedeem` / `convertToAssets` /
//!     `previewDeposit` / ...) — in *some* function. This is the structural proof
//!     that the two mappings are a priced pool, not two unrelated numbers;
//!   * we then report a **different** function that writes the assets var but
//!     **not** the shares var. A function that writes both (the co-update) is the
//!     safe shape and is suppressed;
//!   * the repricing site itself, and pure interfaces, are never reported.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function};

use super::prelude::*;

pub struct PooledSharesRepriceDesyncDetector;

/// A repricing pair discovered at a division site: the pooled-asset state var,
/// the paired share-supply state var, and the source location of the division
/// (kept only for diagnostics / dedup, not reported).
#[derive(Clone)]
struct RepricePair {
    assets_var: String,
    shares_var: String,
}

impl Detector for PooledSharesRepriceDesyncDetector {
    fn id(&self) -> &'static str {
        "pooled-shares-reprice-desync"
    }
    fn category(&self) -> Category {
        Category::PooledSharesRepriceDesync
    }
    fn description(&self) -> &'static str {
        "Per-key pooled assets mutated one-sidedly while the paired per-key share supply stays fixed, \
         repricing a proportional claim (Symbiotic withdrawal-queue-under-slashing class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        // Analyse contract-by-contract: the repricing site and the one-sided
        // writer must share the same storage namespace (same contract's state
        // vars) for the pairing to be a real invariant.
        for c in cx.scir.iter_contracts() {
            // A pure interface has no bodies to reprice or to mutate.
            if c.is_interface() {
                continue;
            }
            let funcs: Vec<&Function> = cx.scir.functions_of(c.id).collect();
            if funcs.is_empty() {
                continue;
            }

            // ---- (1) collect repricing pairs across all functions of `c` ----
            // A pair `(assetsVar, sharesVar)` is established by a division
            // `assetsVar[k] ... / sharesVar[k]` somewhere (typically a view
            // previewRedeem/convertToAssets, but any function counts).
            let mut pairs: Vec<RepricePair> = Vec::new();
            for f in &funcs {
                if !f.has_body {
                    continue;
                }
                collect_reprice_pairs(f, &mut pairs);
            }
            if pairs.is_empty() {
                continue;
            }
            dedup_pairs(&mut pairs);

            // ---- (2) find one-sided writers of a paired assets var ----
            for f in &funcs {
                if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
                    continue;
                }

                for pair in &pairs {
                    // The function must write the pooled-assets var of this pair.
                    if !f.effects.writes_var(&pair.assets_var) {
                        continue;
                    }
                    // SUPPRESS the safe co-update: a function that also writes the
                    // paired share-supply var is keeping the two in lockstep.
                    if f.effects.writes_var(&pair.shares_var) {
                        continue;
                    }
                    // Don't report a function that *is* a repricing site for this
                    // same pair (it reads/prices, the write is incidental and the
                    // ratio is computed in-line — out of scope here).
                    if function_prices_pair(f, pair) {
                        continue;
                    }

                    let span = assets_write_span(f, &pair.assets_var).unwrap_or(f.span);
                    let b = report!(self, Category::PooledSharesRepriceDesync,
                        title = "Pooled assets mutated without updating paired per-key share supply",
                        severity = Severity::Medium,
                        confidence = 0.5,
                        dimensions = [Dimension::Invariant],
                        message = format!(
                            "`{fname}` writes the pooled-asset balance `{assets}` for a key but never \
                             writes the paired per-key share supply `{shares}`. Elsewhere this contract \
                             prices a claim proportionally as `{assets}[k] * shares / {shares}[k]` \
                             (a previewRedeem / convertToAssets-style repricing), so the two mappings are \
                             a single priced pool that must move together. Mutating `{assets}` while \
                             `{shares}` stays fixed silently reprices every outstanding share for that \
                             key: under slashing the loss is mis-socialised (early claimants redeem at the \
                             stale, higher per-share price and drain the queue), and a one-sided top-up \
                             over-pays whoever claims first. This is the Symbiotic withdrawal-queue / \
                             pooled-shares reprice-desync class.",
                            fname = f.name,
                            assets = pair.assets_var,
                            shares = pair.shares_var,
                        ),
                        recommendation = format!(
                            "Keep the pooled-asset and share-supply mappings in lockstep for the same \
                             key: whenever `{assets}[k]` changes, update `{shares}[k]` correspondingly \
                             (burn/mint shares for the same key, or route a slashing loss through a \
                             mechanism that scales both sides), so the proportional price \
                             `{assets}[k] * s / {shares}[k]` stays invariant for existing holders.",
                            assets = pair.assets_var,
                            shares = pair.shares_var,
                        ),
                    );
                    out.push(finish_at(cx, b, f.id, span));
                    // One finding per writer is enough — a writer that desyncs one
                    // pair is the report; avoid stacking near-duplicate messages.
                    break;
                }
            }
        }
        out
    }
}

/// Scan `f`'s body for repricing sites and push any discovered
/// `(assetsVar, sharesVar)` pairs into `out`.
///
/// Two repricing forms are recognized, both of which prove the two mappings are a
/// single priced pool:
///
///   1. an **inline division** `Div` whose numerator indexes an assets-like state
///      var and whose denominator indexes a shares-like state var with the *same
///      index key* (`assets[k] * x / shares[k]`);
///   2. an **ERC-4626 ratio-helper call** (`previewRedeem` / `convertToAssets` /
///      `previewDeposit` / ...) where the two *pool-total* arguments are an
///      assets-like indexed var and a shares-like indexed var with the same key —
///      the real Symbiotic shape `ERC4626Math.previewRedeem(userShares,
///      withdrawals[epoch], withdrawalShares[epoch])`.
///
/// Requiring the matching index key on both sides is what ties the two mappings to
/// one pool and keeps this from firing on two unrelated ratios.
fn collect_reprice_pairs(f: &Function, out: &mut Vec<RepricePair>) {
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            match &e.kind {
                // Form 1: inline `assets[k] * x / shares[k]`.
                ExprKind::Binary { op: BinOp::Div, lhs, rhs } => {
                    // Denominator must be (or contain) a shares-like indexed access.
                    let Some((shares_var, shares_key)) = find_indexed(rhs, NameKind::Shares) else {
                        return;
                    };
                    // Numerator must be (or contain) an assets-like indexed access
                    // whose key matches the denominator's key.
                    let Some((assets_var, assets_key)) = find_indexed(lhs, NameKind::Assets) else {
                        return;
                    };
                    if !keys_match(&assets_key, &shares_key) {
                        return;
                    }
                    out.push(RepricePair { assets_var, shares_var });
                }
                // Form 2: ERC-4626 ratio helper `previewRedeem(s, totalAssets, totalShares)`.
                ExprKind::Call(call) => {
                    if let Some(pair) = pair_from_reprice_call(call) {
                        out.push(pair);
                    }
                }
                _ => {}
            }
        });
    }
}

/// Method/function names of the canonical ERC-4626 ratio helpers. Each prices a
/// proportional conversion between assets and shares against the two *pool totals*
/// passed as its trailing two arguments (`fn(amount, totalA, totalB)`), so the
/// assets-side and shares-side state vars surface as `args[1]` and `args[2]`
/// (order varies per helper — we classify by name, not position).
const REPRICE_HELPERS: &[&str] = &[
    "previewredeem",   // convertToAssets(shares, totalAssets, totalShares)
    "previewmint",     // convertToAssets(shares, totalAssets, totalShares)
    "previewdeposit",  // convertToShares(assets, totalShares, totalAssets)
    "previewwithdraw", // convertToShares(assets, totalShares, totalAssets)
    "converttoassets", // (shares, totalAssets, totalShares)
    "converttoshares", // (assets, totalShares, totalAssets)
];

/// If `call` is an ERC-4626 ratio helper whose two pool-total arguments are an
/// assets-like indexed var and a shares-like indexed var keyed identically, return
/// that pair. The per-user `amount` is always `args[0]` and is excluded — we look
/// only at the trailing two (the pool totals), so the per-user share balance
/// (itself a "shares"-named access) cannot be mistaken for the pool's share supply.
fn pair_from_reprice_call(call: &sluice_ir::Call) -> Option<RepricePair> {
    let name = call.func_name.as_deref()?.to_ascii_lowercase();
    if !REPRICE_HELPERS.iter().any(|h| name == *h) {
        return None;
    }
    // Need at least the two pool-total args (`amount, totalA, totalB`).
    if call.args.len() < 3 {
        return None;
    }
    let totals = &call.args[1..3];

    // Among the two pool-total args, find one assets-like and one shares-like
    // indexed access whose keys match. Order-independent, so this handles both
    // `(…, totalAssets, totalShares)` and `(…, totalShares, totalAssets)`.
    let mut assets: Option<(String, String)> = None;
    let mut shares: Option<(String, String)> = None;
    for a in totals {
        if shares.is_none() {
            if let Some(s) = find_indexed(a, NameKind::Shares) {
                shares = Some(s);
                continue;
            }
        }
        if assets.is_none() {
            if let Some(s) = find_indexed(a, NameKind::Assets) {
                assets = Some(s);
            }
        }
    }
    let (assets_var, assets_key) = assets?;
    let (shares_var, shares_key) = shares?;
    if !keys_match(&assets_key, &shares_key) {
        return None;
    }
    Some(RepricePair { assets_var, shares_var })
}

/// Does `f` contain a repricing division for *this specific pair*? Used to avoid
/// reporting the pricing function itself when its write to the assets var is
/// incidental.
fn function_prices_pair(f: &Function, pair: &RepricePair) -> bool {
    let mut local = Vec::new();
    collect_reprice_pairs(f, &mut local);
    local
        .iter()
        .any(|p| p.assets_var == pair.assets_var && p.shares_var == pair.shares_var)
}

/// Name classification for the two sides of the pool. Order matters: a var is
/// tested for "shares-like" first, so `withdrawalShares` is a SHARE var (not an
/// asset var, even though it contains `withdrawal`).
#[derive(Clone, Copy, PartialEq)]
enum NameKind {
    Assets,
    Shares,
}

/// Substrings that name a per-key **share supply** (the denominator of the price).
const SHARE_MARKERS: &[&str] = &[
    "share",        // shares, withdrawalShares, totalShares, sharesOf
    "supply",       // shareSupply, totalSupply-per-key
];

/// Substrings that name a per-key **pooled asset balance** (the numerator).
/// `share`/`supply` vars are excluded by the share-first test in [`name_kind`].
const ASSET_MARKERS: &[&str] = &[
    "withdrawal",   // withdrawals[epoch] (pooled assets queued for an epoch)
    "pooled",       // pooledAssets[id]
    "pool",         // poolBalance[id]
    "asset",        // assets[k]
    "balance",      // balances[id] / balanceOf-per-key pool
    "amount",       // amounts[k]
    "reserve",      // reserves[k]
    "collateral",   // collateral[k]
    "deposit",      // deposits[k]
];

/// Classify a state-var name. Returns `None` for names that match neither side,
/// or that are ambiguous (match an asset marker but are actually a share var —
/// resolved by testing share markers first).
fn name_kind(name: &str) -> Option<NameKind> {
    let l = name.to_ascii_lowercase();
    if SHARE_MARKERS.iter().any(|m| l.contains(m)) {
        return Some(NameKind::Shares);
    }
    if ASSET_MARKERS.iter().any(|m| l.contains(m)) {
        return Some(NameKind::Assets);
    }
    None
}

/// Find an indexed access `var[key]` of the requested `kind` anywhere inside `e`,
/// returning `(var_name, key_text)`. The key text is the lowercased source-ish
/// rendering of the index expression, used for the same-key check.
fn find_indexed(e: &Expr, want: NameKind) -> Option<(String, String)> {
    let mut hit: Option<(String, String)> = None;
    e.visit(&mut |sub| {
        if hit.is_some() {
            return;
        }
        let ExprKind::Index { base, index: Some(idx) } = &sub.kind else {
            return;
        };
        let Some(var) = root_ident(base) else { return };
        if name_kind(&var) != Some(want) {
            return;
        }
        hit = Some((var, render_key(idx)));
    });
    hit
}

/// True if two index keys refer to the same key. We compare a normalized textual
/// rendering of the index expression (`epoch`, `id`, `msg.sender`, ...). This is
/// deliberately conservative: only when both sides index by a recognizably equal
/// key do we treat the division as a single-pool repricing.
fn keys_match(a: &str, b: &str) -> bool {
    !a.is_empty() && a == b
}

/// Render an index expression to a stable, lowercased key string for comparison.
/// Handles the common forms: a bare identifier, a member chain (`info.epoch`),
/// and a literal. Anything else renders empty (so it won't match).
fn render_key(e: &Expr) -> String {
    fn go(e: &Expr, buf: &mut String) -> bool {
        match &e.kind {
            ExprKind::Ident(n) => {
                buf.push_str(&n.to_ascii_lowercase());
                true
            }
            ExprKind::Member { base, member } => {
                if !go(base, buf) {
                    return false;
                }
                buf.push('.');
                buf.push_str(&member.to_ascii_lowercase());
                true
            }
            ExprKind::Lit(sluice_ir::Lit::Number(n)) => {
                buf.push_str(n.trim());
                true
            }
            _ => false,
        }
    }
    let mut buf = String::new();
    if go(e, &mut buf) {
        buf
    } else {
        String::new()
    }
}

/// Span of the first write to `var` (for a precise report location).
fn assets_write_span(f: &Function, var: &str) -> Option<sluice_ir::Span> {
    f.effects
        .storage_writes
        .iter()
        .filter(|w| w.var == var)
        .min_by_key(|w| w.order)
        .map(|w| w.span)
}

/// Drop duplicate `(assets, shares)` pairs.
fn dedup_pairs(pairs: &mut Vec<RepricePair>) {
    pairs.sort_by(|a, b| (&a.assets_var, &a.shares_var).cmp(&(&b.assets_var, &b.shares_var)));
    pairs.dedup_by(|a, b| a.assets_var == b.assets_var && a.shares_var == b.shares_var);
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // VULN (Symbiotic withdrawal-queue-under-slashing): per-epoch pooled assets
    // (`withdrawals`) and per-epoch share supply (`withdrawalShares`) are priced
    // proportionally in `previewRedeem`. The privileged `onSlash` reduces
    // `withdrawals[epoch]` but never touches `withdrawalShares[epoch]`, silently
    // repricing every outstanding share for that epoch.
    const VULN: &str = r#"
        contract WithdrawalQueue {
            mapping(uint256 => uint256) public withdrawals;       // pooled assets / epoch
            mapping(uint256 => uint256) public withdrawalShares;  // share supply / epoch
            address public slasher;

            function previewRedeem(uint256 epoch, uint256 s) public view returns (uint256) {
                return withdrawals[epoch] * s / withdrawalShares[epoch];
            }

            function requestWithdraw(uint256 epoch, uint256 assets, uint256 s) external {
                withdrawals[epoch] += assets;
                withdrawalShares[epoch] += s;
            }

            function onSlash(uint256 epoch, uint256 slashed) external {
                require(msg.sender == slasher, "auth");
                withdrawals[epoch] -= slashed;
            }
        }
    "#;

    // SAFE: identical pricing, but the slashing path scales BOTH sides for the
    // same epoch (the co-update), so the per-share price is preserved.
    const SAFE_COUPDATE: &str = r#"
        contract WithdrawalQueue {
            mapping(uint256 => uint256) public withdrawals;
            mapping(uint256 => uint256) public withdrawalShares;
            address public slasher;

            function previewRedeem(uint256 epoch, uint256 s) public view returns (uint256) {
                return withdrawals[epoch] * s / withdrawalShares[epoch];
            }

            function requestWithdraw(uint256 epoch, uint256 assets, uint256 s) external {
                withdrawals[epoch] += assets;
                withdrawalShares[epoch] += s;
            }

            function onSlash(uint256 epoch, uint256 slashed, uint256 burnShares) external {
                require(msg.sender == slasher, "auth");
                withdrawals[epoch] -= slashed;
                withdrawalShares[epoch] -= burnShares;
            }
        }
    "#;

    // SAFE: a one-sided writer exists, but NOTHING prices the two mappings against
    // each other (no `assets[k]/shares[k]` division), so there is no repricing
    // invariant to break — the detector must stay silent.
    const SAFE_NO_REPRICE: &str = r#"
        contract Bookkeeping {
            mapping(uint256 => uint256) public withdrawals;
            mapping(uint256 => uint256) public withdrawalShares;

            function bumpAssets(uint256 epoch, uint256 a) external {
                withdrawals[epoch] += a;
            }
            function bumpShares(uint256 epoch, uint256 s) external {
                withdrawalShares[epoch] += s;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(
            fs.iter().any(|f| f.detector == "pooled-shares-reprice-desync"
                && f.function == "onSlash"),
            "{:#?}",
            fs
        );
    }

    #[test]
    fn silent_on_coupdate() {
        let fs = run(SAFE_COUPDATE);
        assert!(!fs.iter().any(|f| f.detector == "pooled-shares-reprice-desync"));
    }

    #[test]
    fn silent_without_repricing_division() {
        let fs = run(SAFE_NO_REPRICE);
        assert!(!fs.iter().any(|f| f.detector == "pooled-shares-reprice-desync"));
    }

    // ---- the REAL Symbiotic Vault shape ------------------------------------
    //
    // Mirrors symbiotic-core/src/contracts/vault/Vault.sol precisely:
    //   * the pooled-asset / share-supply mappings are declared in an ABSTRACT
    //     BASE (`VaultStorage`), and the pricing + slashing live in the derived
    //     `Vault` — exercising inherited-state-var resolution;
    //   * the repricing site is an ERC-4626 ratio HELPER CALL
    //     `ERC4626Math.previewRedeem(userShares, withdrawals[epoch],
    //     withdrawalShares[epoch])` (i.e. `convertToAssets(s, totalAssets,
    //     totalShares)`) — NOT an inline `/`;
    //   * `onSlash` writes `withdrawals[...]` at DIFFERENT key expressions
    //     (`currentEpoch_`, `currentEpoch_ + 1`) than the repricer's `epoch`, and
    //     never touches `withdrawalShares` — the one-sided desync;
    //   * `_withdraw` is the SAFE co-update: it writes both `withdrawals[epoch]`
    //     and `withdrawalShares[epoch]` and must stay suppressed.
    const SYMBIOTIC: &str = r#"
        library ERC4626Math {
            function previewRedeem(uint256 shares, uint256 totalAssets, uint256 totalShares)
                internal pure returns (uint256)
            {
                return (shares * (totalAssets + 1)) / (totalShares + 1);
            }
            function previewDeposit(uint256 assets, uint256 totalShares, uint256 totalAssets)
                internal pure returns (uint256)
            {
                return (assets * (totalShares + 1)) / (totalAssets + 1);
            }
        }

        abstract contract VaultStorage {
            mapping(uint256 => uint256) public withdrawals;       // pooled assets / epoch
            mapping(uint256 => uint256) public withdrawalShares;  // share supply / epoch
            mapping(uint256 => mapping(address => uint256)) public withdrawalSharesOf;
            address public slasher;
            address public burner;
            uint256 internal _epoch;
            function currentEpoch() public view returns (uint256) { return _epoch; }
        }

        contract Vault is VaultStorage {
            function withdrawalsOf(uint256 epoch, address account) public view returns (uint256) {
                return ERC4626Math.previewRedeem(
                    withdrawalSharesOf[epoch][account], withdrawals[epoch], withdrawalShares[epoch]
                );
            }

            function _withdraw(address claimer, uint256 assets) internal returns (uint256 mintedShares) {
                uint256 epoch = currentEpoch() + 1;
                uint256 w = withdrawals[epoch];
                uint256 ws = withdrawalShares[epoch];
                mintedShares = ERC4626Math.previewDeposit(assets, ws, w);
                withdrawals[epoch] = w + assets;
                withdrawalShares[epoch] = ws + mintedShares;
                withdrawalSharesOf[epoch][claimer] += mintedShares;
            }

            function onSlash(uint256 amount, uint48) external returns (uint256 slashedAmount) {
                if (msg.sender != slasher) revert();
                uint256 currentEpoch_ = currentEpoch();
                uint256 nextWithdrawals = withdrawals[currentEpoch_ + 1];
                uint256 withdrawals_ = withdrawals[currentEpoch_];
                slashedAmount = amount;
                withdrawals[currentEpoch_ + 1] = nextWithdrawals - 1;
                withdrawals[currentEpoch_] = withdrawals_ - slashedAmount;
            }
        }
    "#;

    #[test]
    fn fires_on_symbiotic_helper_call_shape() {
        let fs = run(SYMBIOTIC);
        assert!(
            fs.iter().any(|f| f.detector == "pooled-shares-reprice-desync"
                && f.contract == "Vault"
                && f.function == "onSlash"),
            "expected onSlash desync via ERC4626 helper pairing; got {:#?}",
            fs
        );
        // The safe co-update `_withdraw` (writes both mappings) must NOT be flagged.
        assert!(
            !fs.iter().any(|f| f.detector == "pooled-shares-reprice-desync"
                && f.function == "_withdraw"),
            "co-update _withdraw must be suppressed; got {:#?}",
            fs
        );
    }

    // SAFE (Pendle shape): `previewRedeem` exists, but as a 2-arg EXTERNAL call on
    // an interface (`IStandardizedYield(SY).previewRedeem(tokenOut, netSyIn)`) whose
    // args are not same-keyed assets/shares pool totals. No repricing pair forms, so
    // a one-sided writer of an unrelated mapping must not be flagged.
    const SAFE_TWO_ARG_PREVIEW: &str = r#"
        interface ISY { function previewRedeem(address t, uint256 n) external view returns (uint256); }
        contract Router {
            mapping(uint256 => uint256) public withdrawals;
            address public sy;
            function quote(address tokenOut, uint256 netSyIn) external view returns (uint256) {
                return ISY(sy).previewRedeem(tokenOut, netSyIn);
            }
            function bump(uint256 epoch, uint256 a) external {
                withdrawals[epoch] += a;
            }
        }
    "#;

    #[test]
    fn silent_on_two_arg_external_preview() {
        let fs = run(SAFE_TWO_ARG_PREVIEW);
        assert!(
            !fs.iter().any(|f| f.detector == "pooled-shares-reprice-desync"),
            "2-arg external previewRedeem must not form a repricing pair; got {:#?}",
            fs
        );
    }
}
