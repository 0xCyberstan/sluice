//! Contest manifest model + the bug-class → Sluice-category compatibility map.
//!
//! A manifest (`benchmarks/contests/<name>.json`) names one audit contest, the
//! local clone, the in-scope directories, and the published High/Medium findings
//! mapped to ground truth `(contract, function, file, line, bug_class, in_class)`.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// One published audit finding, mapped to ground truth.
#[derive(Debug, Clone, Deserialize)]
pub struct KnownFinding {
    pub id: String,
    pub severity: String,
    pub contract: String,
    pub function: String,
    /// Path of the bug, relative to the contest root (e.g. `src/Foo.sol`).
    pub file: String,
    pub line: usize,
    /// Free-form ground-truth class label (see [`compatible_categories`]).
    pub bug_class: String,
    /// `true` if `bug_class` is one Sluice's detector set models; `false` for
    /// protocol-specific invariant/accounting/logic bugs.
    pub in_class: bool,
    #[serde(default)]
    pub summary: String,
}

/// A parsed contest manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub name: String,
    pub repo: String,
    #[serde(default)]
    pub commit: Option<String>,
    pub local_path: String,
    pub scope_dirs: Vec<String>,
    // Documentation-only fields: parsed and validated as part of the committed
    // manifest schema (so a typo'd key is rejected and they round-trip), but the
    // scoreboard does not render them. Kept here so the schema is the struct.
    #[serde(default)]
    #[allow(dead_code)]
    pub audit_url: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub note: Option<String>,
    pub known_findings: Vec<KnownFinding>,
}

impl Manifest {
    /// Load and parse a manifest file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("reading manifest {}: {e}", path.display()))?;
        let m: Manifest = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("parsing manifest {}: {e}", path.display()))?;
        Ok(m)
    }

    /// Expand `~` in `local_path` and return the absolute contest root.
    pub fn root(&self) -> PathBuf {
        expand_tilde(&self.local_path)
    }

    /// The absolute scope directories to hand to `sluice scan`.
    pub fn scope_paths(&self) -> Vec<PathBuf> {
        let root = self.root();
        self.scope_dirs.iter().map(|d| root.join(d)).collect()
    }
}

/// Expand a leading `~` / `~/` to the user's home directory.
pub fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    } else if p == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home);
        }
    }
    PathBuf::from(p)
}

/// Map a manifest `bug_class` to the set of Sluice `Category` *variant names*
/// (as they appear in `sluice scan --format json`, e.g. `"SignedCast"`) that
/// count as a compatible catch for that class.
///
/// A known finding is "caught with a compatible class" when Sluice emits a
/// finding at the right location whose `category` is in this set. The mapping is
/// deliberately generous within a class family (a `signed-cast` ground-truth bug
/// is satisfied by `SignedCast`, `IntegerOverflow`, `UncheckedMath`, or
/// `DecimalsAssumption`) so that a correct catch under a sibling detector still
/// scores as recall, while staying narrow enough that an unrelated class (e.g.
/// `Reentrancy` for a `signed-cast` bug) does not falsely count.
///
/// Returning an empty slice means "no Sluice class models this" — used for the
/// out-of-class protocol-specific bugs, which therefore can only ever be matched
/// by the location-only fallback (see the `--lenient-class` flag), never by class.
pub fn compatible_categories(bug_class: &str) -> &'static [&'static str] {
    match bug_class {
        // ---- in-class families (classes Sluice models) ----
        "signed-cast" | "unsafe-downcast" | "integer" | "integer-overflow" => {
            &["SignedCast", "IntegerOverflow", "UncheckedMath", "DecimalsAssumption"]
        }
        "decimals" | "decimals-assumption" => &["DecimalsAssumption", "SignedCast"],
        "reentrancy" => &["Reentrancy", "ReadOnlyReentrancy", "Erc777Reentrancy", "MintCallbackReentrancy"],
        "erc777-reentrancy" => &["Erc777Reentrancy", "Reentrancy", "ReadOnlyReentrancy"],
        "read-only-reentrancy" => &["ReadOnlyReentrancy", "Reentrancy", "Erc777Reentrancy"],
        "oracle" | "oracle-manipulation" | "price-manipulation" => {
            &["OracleManipulation", "PriceManipulation", "TwapManipulation", "OracleStaleness", "PriceBounds"]
        }
        "oracle-staleness" => &["OracleStaleness", "OracleManipulation", "SequencerUptime"],
        "share-inflation" | "erc4626-inflation" | "first-depositor" => {
            &["Erc4626Inflation", "FirstDepositor", "RoundingDirection", "PrecisionLoss", "InternalSharePricingRounding"]
        }
        "rounding" | "rounding-direction" | "precision-loss" => {
            &["RoundingDirection", "PrecisionLoss", "Erc4626Inflation", "InternalSharePricingRounding"]
        }
        "cached-domain-separator" => &["CachedDomainSeparator"],
        "access-control" | "missing-access-control" => {
            &["AccessControl", "UnprotectedInitializer", "TxOriginAuth", "Centralization", "ArbitraryTransfer"]
        }
        // Single over-powerful operator / governance SPOF: the modeled
        // `Centralization` detector, with `AccessControl` as the sibling an
        // over-broad privileged role is also commonly emitted under.
        "centralization" => &["Centralization", "AccessControl"],
        "unprotected-initializer" => &["UnprotectedInitializer", "AccessControl", "UninitializedProxy"],
        // A privileged role/minter that, once granted, has no pause/revoke path:
        // the modeled `LifecycleRoleRevokeGap` detector (with `AccessControl` as
        // the sibling access-control-shaped catch).
        "lifecycle-role-revoke-gap" => &["LifecycleRoleRevokeGap", "AccessControl"],
        // A token with a second legitimate entrypoint (proxy / legacy address)
        // bypassing a `token == address(collateral)` style check.
        "double-entry-token" => &["DoubleEntryToken", "ArbitraryTransfer", "UnsafeErc20"],
        "unchecked-return" => &["UncheckedReturn", "UnsafeErc20"],
        "unsafe-erc20" => &["UnsafeErc20", "UncheckedReturn", "FeeOnTransfer"],
        "fee-on-transfer" => &["FeeOnTransfer", "UnsafeErc20"],
        "signature-replay" => &["SignatureReplay", "SignatureMalleability", "Eip712TypehashMismatch", "CachedDomainSeparator"],
        "signature-malleability" => &["SignatureMalleability", "SignatureReplay", "EcrecoverZeroAddress"],
        "missing-deadline" => &["MissingDeadline"],
        "slippage" => &["Slippage", "LpSlippage"],
        "missing-zero-check" => &["MissingZeroCheck"],
        "missing-event-emit" => &["MissingEventEmit"],
        "denial-of-service" | "dos" => &["DenialOfService", "UnboundedLoop", "GasGriefing"],
        "unbounded-loop" => &["UnboundedLoop", "DenialOfService"],
        "weak-randomness" => &["WeakRandomness"],
        "timestamp" | "timestamp-dependence" => &["TimestampDependence", "BlockNumberTime"],
        // Using block.number as a proxy for elapsed wall-clock time (irregular
        // across chains / L2 sequencers): the modeled `BlockNumberTime` detector.
        "block-number-as-time" => &["BlockNumberTime", "TimestampDependence"],
        "flashloan-governance" => &["FlashLoanGovernance", "GovernanceTimelock"],
        "delegatecall" => &["DelegatecallStorage", "UninitializedProxy", "SelectorCollision"],
        "bridge-verification" => &["BridgeVerification", "UntrustedCallTarget"],
        "missing-solvency-check" => &["MissingSolvencyCheck"],
        // Crediting a caller from a live raw-balance read (`address(this).balance`)
        // instead of a tracked accounting var — the invariant-engine class (PHASE
        // B1, LoopFi H-01). Mapped to the modeled `ValueSourceDiscipline` detector
        // so the catch scores as recall. NOTE: orthogonal to the per-finding
        // `in_class` flag — H-01 stays `in_class: false` (a protocol-specific
        // accounting invariant in the taxonomy), so catching it moves *out-of-class*
        // recall. Kept distinct from the coarse `accounting-invariant` label (which
        // also tags two unrelated Tigris price/margin findings) so this detector
        // cannot spuriously "catch" those.
        "value-source-discipline" => &["ValueSourceDiscipline"],
        // An obligation (penalty / debt) capped to a *partial* fund source while a
        // recovery action is expected to make it whole — the recovered value never
        // folds back, so the shortfall is silently dropped (PHASE B2, the invariant-
        // engine conservation/accounting class). Mapped to the modeled `Conservation`
        // detector so the catch scores as recall. Like `value-source-discipline`,
        // this is orthogonal to the per-finding `in_class` flag — the corpus's two
        // `accounting-error` findings (Stader M-06 / M-12) stay `in_class: false`, so
        // catching one moves *out-of-class* recall. `accounting-error` is the precise
        // label for these two genuine accounting bugs (no other corpus finding uses
        // it), so this mapping cannot spuriously credit an unrelated class.
        "accounting-error" => &["Conservation"],
        // A price-per-share / exchange-rate getter that derives the share value from
        // a manipulable on-chain SPOT source (a Curve `price_oracle()` pool read, an
        // AMM `get_dy`/`getReserves` quote, a Uni-v3 `slot0`) with no TWAP window, no
        // Chainlink-with-staleness cross-check, and no min/max bound — the value then
        // drives mint/redeem share pricing (asymmetry H-04, `SfrxEth.ethPerDerivative`
        // over Curve `price_oracle`). Mapped to the modeled `SpotPricedShareValue`
        // detector so the catch scores as recall. NOTE: orthogonal to the per-finding
        // `in_class` flag — H-04 stays `in_class: false` (the corpus tags it as a
        // protocol-specific accounting/price-formula bug), so catching it moves
        // *out-of-class* recall, exactly like `value-source-discipline` /
        // `accounting-error`. Kept distinct from the coarse `accounting-logic` /
        // `oracle-data-corruption` labels (which tag unrelated findings) so this
        // detector cannot spuriously "catch" those.
        "spot-priced-share-value" => &["SpotPricedShareValue"],
        // A withdrawal/claim/unstake/redeem that pushes the principal ETH to a
        // caller- or recipient-controlled address via a low-level
        // `call{value:..}("")`/`transfer`/`send` and then hard-`require`s the push
        // succeeded — a contract caller whose `receive` reverts permanently blocks
        // the withdrawal even though every upstream step succeeded (asymmetry M-06,
        // `SafEth.unstake`). Mapped to the modeled `DenialOfService` detector (the
        // new Pattern-4 push-payment arm in `dos.rs`) so the catch scores as recall.
        // NOTE: orthogonal to the per-finding `in_class` flag — M-06 stays
        // `in_class: false` (the corpus tags it as a protocol-specific
        // DoS-on-revert), so catching it moves *out-of-class* recall, exactly like
        // `value-source-discipline` / `spot-priced-share-value`. This is a PRECISE
        // sub-label of the coarse `dos-on-revert` class: only M-06 carries it, so
        // the mapping cannot spuriously credit the sibling `dos-on-revert` findings
        // (H-03, the no-way-to-remove-a-broken-derivative loop revert), which keep
        // their coarse `dos-on-revert` label and remain match-able only by location.
        // Mapped to `DenialOfService` ALONE (not `UnboundedLoop`) so the catch is
        // genuinely driven by the new Pattern-4 push-payment arm at the exact push
        // line, and is not spuriously credited by the unrelated M-08 unbounded-loop
        // finding that also sits in `unstake`.
        "push-payment-dos" => &["DenialOfService"],
        // ---- out-of-class (protocol-specific): no modeled category ----
        // accounting / economic / logic invariants the pattern set does not model.
        // Listed explicitly (rather than only via the `_` arm) so the corpus's
        // out-of-class labels are documented and a typo'd in-class key can't slip
        // through silently.
        "accounting-invariant"
        | "accounting-logic"
        | "accounting-state-advance"
        | "economic-invariant"
        | "economic-reward-accounting"
        | "economic-fee-accounting"
        | "design-economic"
        | "design-pause-asymmetry"
        | "design-fixed-endblock"
        | "dos-on-revert"
        | "frontrunning-deleverage"
        | "frontrunning-ordering"
        | "griefing-collusion"
        | "loop-index-logic"
        | "reorg-create"
        | "consensus-quorum-logic"
        | "oracle-data-corruption"
        | "missing-implementation"
        | "logic"
        | "logic-allowlist"
        | "logic-calldata-validation"
        | "logic-role-revoke"
        | "logic-conflicting-require"
        | "logic-zero-owner"
        | "invariant" => &[],
        // Unknown class: treat as out-of-class (empty), so it cannot silently
        // match on class — only the location-only fallback can catch it.
        _ => &[],
    }
}
