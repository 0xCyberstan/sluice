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
//! function previewRedeem(uint256 epoch, uint256 s) public view returns (uint256) {
//!     return withdrawals[epoch] * s / withdrawalShares[epoch];
//! }
//!
//! // one-sided writer (the bug): assets move, shares frozen
//! function onSlash(uint256 epoch, uint256 slashed) external onlySlasher {
//!     withdrawals[epoch] -= slashed;                     // <-- no withdrawalShares write
//! }
//! ```
//!
//! Precision strategy (single Invariant dimension, Medium @ 0.5):
//!   * we only fire when a **repricing division pairs** an assets-like var with a
//!     shares-like var, indexed by the *same key*, in *some* function — this is
//!     the structural proof that the two mappings are a priced pool, not two
//!     unrelated numbers;
//!   * we then report a **different** function that writes the assets var but
//!     **not** the shares var. A function that writes both (the co-update) is the
//!     safe shape and is suppressed;
//!   * the repricing site itself, and pure interfaces, are never reported.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function};

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
                    if !writes_var(f, &pair.assets_var) {
                        continue;
                    }
                    // SUPPRESS the safe co-update: a function that also writes the
                    // paired share-supply var is keeping the two in lockstep.
                    if writes_var(f, &pair.shares_var) {
                        continue;
                    }
                    // Don't report a function that *is* a repricing site for this
                    // same pair (it reads/prices, the write is incidental and the
                    // ratio is computed in-line — out of scope here).
                    if function_prices_pair(f, pair) {
                        continue;
                    }

                    let span = assets_write_span(f, &pair.assets_var).unwrap_or(f.span);
                    let b = FindingBuilder::new(self.id(), Category::PooledSharesRepriceDesync)
                        .title("Pooled assets mutated without updating paired per-key share supply")
                        .severity(Severity::Medium)
                        .confidence(0.5)
                        .dimension(Dimension::Invariant)
                        .message(format!(
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
                        ))
                        .recommendation(format!(
                            "Keep the pooled-asset and share-supply mappings in lockstep for the same \
                             key: whenever `{assets}[k]` changes, update `{shares}[k]` correspondingly \
                             (burn/mint shares for the same key, or route a slashing loss through a \
                             mechanism that scales both sides), so the proportional price \
                             `{assets}[k] * s / {shares}[k]` stays invariant for existing holders.",
                            assets = pair.assets_var,
                            shares = pair.shares_var,
                        ));
                    out.push(cx.finish(b, f.id, span));
                    // One finding per writer is enough — a writer that desyncs one
                    // pair is the report; avoid stacking near-duplicate messages.
                    break;
                }
            }
        }
        out
    }
}

/// Scan `f`'s body for repricing divisions and push any discovered
/// `(assetsVar, sharesVar)` pairs into `out`.
///
/// A repricing division is a `Div` whose **numerator** indexes an assets-like
/// state var and whose **denominator** indexes a shares-like state var, with the
/// *same index key* on both sides (`assets[k] * x / shares[k]`). Requiring the
/// matching key is what ties the two mappings to one pool and keeps this from
/// firing on two unrelated ratios.
fn collect_reprice_pairs(f: &Function, out: &mut Vec<RepricePair>) {
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            let ExprKind::Binary { op: BinOp::Div, lhs, rhs } = &e.kind else {
                return;
            };
            // Denominator must be (or contain) a shares-like indexed access.
            let Some((shares_var, shares_key)) = find_indexed(rhs, NameKind::Shares) else {
                return;
            };
            // Numerator must be (or contain) an assets-like indexed access whose
            // key matches the denominator's key.
            let Some((assets_var, assets_key)) = find_indexed(lhs, NameKind::Assets) else {
                return;
            };
            if !keys_match(&assets_key, &shares_key) {
                return;
            }
            out.push(RepricePair { assets_var, shares_var });
        });
    }
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

/// Root identifier of an lvalue/member/index chain (`a.b[c]` -> `a`).
fn root_ident(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root_ident(base),
        _ => None,
    }
}

/// Does `f` write the state variable `var` (per its effect summary)?
fn writes_var(f: &Function, var: &str) -> bool {
    f.effects.storage_writes.iter().any(|w| w.var == var)
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
}
