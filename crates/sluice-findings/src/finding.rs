//! The `Finding` data model — the atomic unit of Sluice output. Every detector
//! normalizes its result into this struct, exactly as `vortex-findings` does.

use serde::{Deserialize, Serialize};
use sluice_ir::Span;

/// The three orthogonal analysis dimensions. A finding corroborated by more than
/// one dimension is scored higher — the central false-positive-suppression idea
/// inherited from `vortex` (entropy × ghost-state × trust-boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Dimension {
    /// Attacker-controlled / price-like value reaches a sensitive sink.
    ValueFlow,
    /// A consensus invariant (guard, co-update, solvency check) is violated.
    Invariant,
    /// A trust frontier (external call / cross-contract / bridge) is crossed unsafely.
    Frontier,
}

impl Dimension {
    pub fn label(self) -> &'static str {
        match self {
            Dimension::ValueFlow => "value-flow",
            Dimension::Invariant => "invariant",
            Dimension::Frontier => "frontier",
        }
    }
}

/// The vulnerability class. Ordered roughly by the historical payout/loss the
/// class commands (see the project research report).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Category {
    Reentrancy,
    ReadOnlyReentrancy,
    OracleManipulation,
    PriceManipulation,
    Erc4626Inflation,
    FirstDepositor,
    RoundingDirection,
    PrecisionLoss,
    FlashLoanGovernance,
    MissingSolvencyCheck,
    AccessControl,
    UnprotectedInitializer,
    TxOriginAuth,
    SignatureReplay,
    SignatureMalleability,
    EcrecoverZeroAddress,
    MissingDeadline,
    DelegatecallStorage,
    UninitializedProxy,
    SelectorCollision,
    BridgeVerification,
    UncheckedReturn,
    UnsafeErc20,
    FeeOnTransfer,
    Erc777Reentrancy,
    Slippage,
    DenialOfService,
    UnboundedLoop,
    WeakRandomness,
    TimestampDependence,
    RewardAccounting,
    ForcedEther,
    IntegerOverflow,
    UncheckedMath,
    // ---- expansion classes ----
    OracleStaleness,
    ArbitraryTransfer,
    MsgValueInLoop,
    MissingZeroCheck,
    GasGriefing,
    GovernanceTimelock,
    ApproveRace,
    StorageGap,
    TwapManipulation,
    FlashloanCallback,
    PriceBounds,
    ArrayLengthMismatch,
    DoubleEntryToken,
    LiquidationAbuse,
    BlockNumberTime,
    DecimalsAssumption,
    Centralization,
    Erc721Safety,
    UncheckedAbiDecode,
    HardcodedGasStipend,
    CachedDomainSeparator,
    SequencerUptime,
    LpSlippage,
    Erc1155Safety,
    SignedCast,
    UntrustedCallTarget,
    MintCallbackReentrancy,
    // ---- Round 7: novel / under-publicised classes (restaking, checkpoints, slashing) ----
    CheckpointHintTrust,
    EpochBoundaryStaleness,
    ProportionalSplitResidual,
    PooledSharesRepriceDesync,
    InternalSharePricingRounding,
    SilencedPrivilegedCallback,
    // ---- Round 9: novel classes mined from Renzo (LST/LRT, cross-chain, queues) ----
    UnguardedAccountingMutator,
    CrossChainRateStaleness,
    SnapshotRedeemAsymmetry,
    NettedAggregateDesync,
    OracleFirstMintSeeding,
    ProportionalPayoutTxValue,
    CooldownBypassFlag,
    // ---- Round 11: novel classes mined from Karak V2 (map to real Karak/C4 findings) ----
    SharesEscrowedRepriced,
    PercentSlashOnLiveBase,
    HashGatedStructReplay,
    ClampResidualBurnSink,
    ProofAdmissionOnly,
    ExternalRootCallerTimestamp,
    ZeroMarginTimingWindow,
    // ---- Round 12: synthetic-dollar / RFQ-mint / ERC4626-staking classes (Ethena; map to real findings) ----
    EscrowExitRestrictionGap,
    VestingBufferedDonation,
    OneSidedPegBand,
    Eip712TypehashMismatch,
    DelegatedSignerSingleStep,
    PreAuthCalloutTarget,
    // ---- Round 13: yield-tokenization / AMM-curve classes (Pendle; a 6th domain) ----
    SyRateJumpTrust,
    MonotoneClampNegativeYield,
    PostExpiryDualIndex,
    CurveLogitDomainEdge,
    StaleAnchorReset,
    SolverConvergenceTrust,
    RatioDenominatorSignEdge,
    // ---- Round 14: lending / intent-RFQ / governance / AMM-fee classes (the big blind spots) ----
    InterestIndexDesync,
    BadDebtSocialization,
    RfqFillAccounting,
    VoteWeightCheckpoint,
    FeegrowthAccounting,
    ParamUpdateRetroactive,
    // ---- Round 15: protocol-agnostic primitive classes (matchable broadly) ----
    TstoreGuardMisscope,
    GapNotShrunk,
    BatchVerifySkip,
    UninitializedStoragePointer,
    // ---- Round 16: L2 / cross-chain INFRASTRUCTURE (bridges — the #1 DeFi loss category) ----
    DvnQuorumConflation,
    ProveFinalizeGameSubstitution,
    InteropNoSourceBinding,
    OftDecimalSupplyLeak,
    LzReceiveFailureSilent,
    UnsetPeerDefaultTrust,
    // ---- Round 17: OP-Stack fault-proof bond / clock / aliasing classes ----
    RefundCreditPreVerdict,
    ConditionalSenderAliasing,
    ClockExtensionDepthBranch,
    RespectedGameTypeSnapshotSwap,
    // ---- Round 19: EigenLayer AVS-middleware (quorum / BLS-registry / churn) ----
    ApkMembershipDesync,
    VerifySnapshotBlockCallerTrust,
    ChurnStaleStakeDoubleCount,
    IndexRegistryPopSwapStale,
    EjectionRatelimitLiveBase,
    ReregisterCooldownBitmapResidue,
    // ---- Round 20: Default-Framework module-permission / algorithmic-stability (olympus-v3) ----
    PolicyPermissionDeclarationGap,
    ModuleActiveFlagPrivilegeScope,
    WallCapacityRegenDesync,
    ModuleUpgradeStateDrop,
    LifecycleRoleRevokeGap,
    KeeperRewardTimestampAuction,
    BackingSpotInflation,
    Other,
}

impl Category {
    pub fn slug(self) -> &'static str {
        use Category::*;
        match self {
            Reentrancy => "reentrancy",
            ReadOnlyReentrancy => "read-only-reentrancy",
            OracleManipulation => "oracle-manipulation",
            PriceManipulation => "price-manipulation",
            Erc4626Inflation => "erc4626-inflation",
            FirstDepositor => "first-depositor",
            RoundingDirection => "rounding-direction",
            PrecisionLoss => "precision-loss",
            FlashLoanGovernance => "flashloan-governance",
            MissingSolvencyCheck => "missing-solvency-check",
            AccessControl => "access-control",
            UnprotectedInitializer => "unprotected-initializer",
            TxOriginAuth => "tx-origin-auth",
            SignatureReplay => "signature-replay",
            SignatureMalleability => "signature-malleability",
            EcrecoverZeroAddress => "ecrecover-zero-address",
            MissingDeadline => "missing-deadline",
            DelegatecallStorage => "delegatecall-storage",
            UninitializedProxy => "uninitialized-proxy",
            SelectorCollision => "selector-collision",
            BridgeVerification => "bridge-verification",
            UncheckedReturn => "unchecked-return",
            UnsafeErc20 => "unsafe-erc20",
            FeeOnTransfer => "fee-on-transfer",
            Erc777Reentrancy => "erc777-reentrancy",
            Slippage => "slippage",
            DenialOfService => "denial-of-service",
            UnboundedLoop => "unbounded-loop",
            WeakRandomness => "weak-randomness",
            TimestampDependence => "timestamp-dependence",
            RewardAccounting => "reward-accounting",
            ForcedEther => "forced-ether",
            IntegerOverflow => "integer-overflow",
            UncheckedMath => "unchecked-math",
            OracleStaleness => "oracle-staleness",
            ArbitraryTransfer => "arbitrary-transfer",
            MsgValueInLoop => "msg-value-in-loop",
            MissingZeroCheck => "missing-zero-check",
            GasGriefing => "gas-griefing",
            GovernanceTimelock => "governance-timelock",
            ApproveRace => "approve-race",
            StorageGap => "storage-gap",
            TwapManipulation => "twap-manipulation",
            FlashloanCallback => "flashloan-callback",
            PriceBounds => "price-bounds",
            ArrayLengthMismatch => "array-length-mismatch",
            DoubleEntryToken => "double-entry-token",
            LiquidationAbuse => "liquidation-abuse",
            BlockNumberTime => "block-number-time",
            DecimalsAssumption => "decimals-assumption",
            Centralization => "centralization-risk",
            Erc721Safety => "erc721-safety",
            UncheckedAbiDecode => "unchecked-abi-decode",
            HardcodedGasStipend => "hardcoded-gas-stipend",
            CachedDomainSeparator => "cached-domain-separator",
            SequencerUptime => "l2-sequencer-uptime",
            LpSlippage => "lp-slippage",
            Erc1155Safety => "unchecked-erc1155-receiver",
            SignedCast => "signed-cast",
            UntrustedCallTarget => "untrusted-call-target",
            MintCallbackReentrancy => "erc721-mint-reentrancy",
            CheckpointHintTrust => "checkpoint-hint-trust",
            EpochBoundaryStaleness => "epoch-boundary-staleness",
            ProportionalSplitResidual => "proportional-split-residual",
            PooledSharesRepriceDesync => "pooled-shares-reprice-desync",
            InternalSharePricingRounding => "internal-share-pricing-rounding",
            SilencedPrivilegedCallback => "silenced-privileged-callback",
            UnguardedAccountingMutator => "unguarded-accounting-mutator",
            CrossChainRateStaleness => "crosschain-rate-staleness",
            SnapshotRedeemAsymmetry => "snapshot-redeem-asymmetry",
            NettedAggregateDesync => "netted-aggregate-desync",
            OracleFirstMintSeeding => "oracle-first-mint-seeding",
            ProportionalPayoutTxValue => "proportional-payout-tx-value",
            CooldownBypassFlag => "cooldown-bypass-flag",
            SharesEscrowedRepriced => "shares-escrowed-repriced",
            PercentSlashOnLiveBase => "percent-slash-live-base",
            HashGatedStructReplay => "hash-gated-replay",
            ClampResidualBurnSink => "clamp-residual-burn",
            ProofAdmissionOnly => "proof-admission-only",
            ExternalRootCallerTimestamp => "external-root-caller-timestamp",
            ZeroMarginTimingWindow => "zero-margin-timing-window",
            EscrowExitRestrictionGap => "escrow-exit-restriction-gap",
            VestingBufferedDonation => "vesting-buffered-donation",
            OneSidedPegBand => "one-sided-peg-band",
            Eip712TypehashMismatch => "eip712-typehash-mismatch",
            DelegatedSignerSingleStep => "delegated-signer-single-step",
            PreAuthCalloutTarget => "preauth-callout-target",
            SyRateJumpTrust => "sy-rate-jump-trust",
            MonotoneClampNegativeYield => "monotone-clamp-negative-yield",
            PostExpiryDualIndex => "post-expiry-dual-index",
            CurveLogitDomainEdge => "curve-logit-domain-edge",
            StaleAnchorReset => "stale-anchor-reset",
            SolverConvergenceTrust => "solver-convergence-trust",
            RatioDenominatorSignEdge => "ratio-denominator-sign-edge",
            InterestIndexDesync => "interest-index-desync",
            BadDebtSocialization => "bad-debt-socialization",
            RfqFillAccounting => "rfq-fill-accounting",
            VoteWeightCheckpoint => "vote-weight-checkpoint",
            FeegrowthAccounting => "feegrowth-accounting",
            ParamUpdateRetroactive => "param-update-retroactive",
            TstoreGuardMisscope => "tstore-guard-misscope",
            GapNotShrunk => "gap-not-shrunk",
            BatchVerifySkip => "batch-verify-skip",
            UninitializedStoragePointer => "uninitialized-storage-pointer",
            DvnQuorumConflation => "dvn-quorum-conflation",
            ProveFinalizeGameSubstitution => "prove-finalize-game-substitution",
            InteropNoSourceBinding => "interop-no-source-binding",
            OftDecimalSupplyLeak => "oft-decimal-supply-leak",
            LzReceiveFailureSilent => "lzreceive-failure-silent",
            UnsetPeerDefaultTrust => "unset-peer-default-trust",
            RefundCreditPreVerdict => "refund-credit-pre-verdict",
            ConditionalSenderAliasing => "conditional-sender-aliasing",
            ClockExtensionDepthBranch => "clock-extension-depth-branch",
            RespectedGameTypeSnapshotSwap => "respected-gametype-snapshot-swap",
            ApkMembershipDesync => "apk-membership-desync",
            VerifySnapshotBlockCallerTrust => "verify-snapshot-block-caller-trust",
            ChurnStaleStakeDoubleCount => "churn-stale-stake-double-count",
            IndexRegistryPopSwapStale => "index-registry-pop-swap-stale",
            EjectionRatelimitLiveBase => "ejection-ratelimit-live-base",
            ReregisterCooldownBitmapResidue => "reregister-cooldown-bitmap-residue",
            PolicyPermissionDeclarationGap => "policy-permission-declaration-gap",
            ModuleActiveFlagPrivilegeScope => "module-active-flag-scope",
            WallCapacityRegenDesync => "wall-capacity-regen-desync",
            ModuleUpgradeStateDrop => "module-upgrade-state-drop",
            LifecycleRoleRevokeGap => "lifecycle-role-revoke-gap",
            KeeperRewardTimestampAuction => "keeper-reward-timestamp-auction",
            BackingSpotInflation => "backing-spot-inflation",
            Other => "other",
        }
    }

    /// CWE / SWC references for the class (for SARIF and reports).
    pub fn references(self) -> &'static [&'static str] {
        use Category::*;
        match self {
            Reentrancy | ReadOnlyReentrancy | Erc777Reentrancy => &["SWC-107", "CWE-841"],
            OracleManipulation | PriceManipulation => &["CWE-20", "CWE-1339"],
            Erc4626Inflation | FirstDepositor | RoundingDirection | PrecisionLoss => &["CWE-682"],
            AccessControl | UnprotectedInitializer | TxOriginAuth => &["SWC-105", "SWC-115", "CWE-284"],
            SignatureReplay | SignatureMalleability | EcrecoverZeroAddress | MissingDeadline => {
                &["SWC-117", "SWC-121", "CWE-347"]
            }
            DelegatecallStorage | UninitializedProxy | SelectorCollision => &["SWC-112", "CWE-1108"],
            BridgeVerification => &["CWE-345"],
            UncheckedReturn | UnsafeErc20 | FeeOnTransfer => &["SWC-104", "CWE-252"],
            Slippage => &["CWE-682"],
            DenialOfService | UnboundedLoop => &["SWC-128", "CWE-400"],
            WeakRandomness => &["SWC-120", "CWE-330"],
            TimestampDependence => &["SWC-116"],
            IntegerOverflow | UncheckedMath => &["SWC-101", "CWE-190"],
            OracleStaleness => &["CWE-672", "CWE-20"],
            ArbitraryTransfer => &["CWE-284", "CWE-863"],
            MsgValueInLoop => &["CWE-682"],
            MissingZeroCheck => &["CWE-20", "SWC-123"],
            GasGriefing => &["SWC-126", "CWE-400"],
            GovernanceTimelock => &["CWE-284"],
            ApproveRace => &["SWC-114"],
            StorageGap => &["CWE-1108"],
            TwapManipulation => &["CWE-1339", "CWE-20"],
            FlashloanCallback => &["CWE-345", "CWE-863"],
            PriceBounds => &["CWE-20", "CWE-1339"],
            ArrayLengthMismatch => &["CWE-129"],
            DoubleEntryToken => &["CWE-20"],
            LiquidationAbuse => &["CWE-682", "CWE-840"],
            BlockNumberTime => &["SWC-116"],
            DecimalsAssumption => &["CWE-682"],
            Centralization => &["CWE-269"],
            Erc721Safety => &["CWE-20"],
            UncheckedAbiDecode => &["CWE-20", "SWC-128"],
            HardcodedGasStipend => &["SWC-134"],
            CachedDomainSeparator => &["SWC-117", "CWE-347"],
            SequencerUptime => &["CWE-672"],
            LpSlippage => &["CWE-682"],
            Erc1155Safety => &["CWE-20"],
            SignedCast => &["CWE-196", "CWE-681"],
            UntrustedCallTarget => &["CWE-345", "CWE-20", "CWE-863"],
            MintCallbackReentrancy => &["SWC-107", "CWE-841"],
            CheckpointHintTrust => &["CWE-20", "CWE-345"],
            EpochBoundaryStaleness => &["CWE-672", "CWE-367"],
            ProportionalSplitResidual => &["CWE-682", "CWE-191"],
            PooledSharesRepriceDesync => &["CWE-682", "CWE-841"],
            InternalSharePricingRounding => &["CWE-682"],
            SilencedPrivilegedCallback => &["CWE-252", "CWE-754"],
            UnguardedAccountingMutator => &["CWE-862", "CWE-284"],
            CrossChainRateStaleness => &["CWE-672", "CWE-345"],
            SnapshotRedeemAsymmetry => &["CWE-682", "CWE-840"],
            NettedAggregateDesync => &["CWE-682", "CWE-191"],
            OracleFirstMintSeeding => &["CWE-1339", "CWE-682"],
            ProportionalPayoutTxValue => &["CWE-682", "CWE-362"],
            CooldownBypassFlag => &["CWE-284", "CWE-841"],
            SharesEscrowedRepriced => &["CWE-682", "CWE-841"],
            PercentSlashOnLiveBase => &["CWE-682", "CWE-672"],
            HashGatedStructReplay => &["CWE-294", "CWE-345"],
            ClampResidualBurnSink => &["CWE-682"],
            ProofAdmissionOnly => &["CWE-345", "CWE-863"],
            ExternalRootCallerTimestamp => &["CWE-345", "CWE-672"],
            ZeroMarginTimingWindow => &["CWE-362", "CWE-367"],
            EscrowExitRestrictionGap => &["CWE-284", "CWE-863"],
            VestingBufferedDonation => &["CWE-682", "CWE-1339"],
            OneSidedPegBand => &["CWE-682", "CWE-840"],
            Eip712TypehashMismatch => &["CWE-347"],
            DelegatedSignerSingleStep => &["CWE-284"],
            PreAuthCalloutTarget => &["CWE-863", "CWE-345"],
            SyRateJumpTrust => &["CWE-345", "CWE-1339"],
            MonotoneClampNegativeYield => &["CWE-682", "CWE-840"],
            PostExpiryDualIndex => &["CWE-682", "CWE-362"],
            CurveLogitDomainEdge => &["CWE-682", "CWE-1339"],
            StaleAnchorReset => &["CWE-672", "CWE-1339"],
            SolverConvergenceTrust => &["CWE-682", "CWE-345"],
            RatioDenominatorSignEdge => &["CWE-682", "CWE-369"],
            InterestIndexDesync => &["CWE-682", "CWE-672"],
            BadDebtSocialization => &["CWE-682", "CWE-840"],
            RfqFillAccounting => &["CWE-682", "CWE-294"],
            VoteWeightCheckpoint => &["CWE-682", "CWE-345"],
            FeegrowthAccounting => &["CWE-682"],
            ParamUpdateRetroactive => &["CWE-362", "CWE-840"],
            TstoreGuardMisscope => &["SWC-107", "CWE-459"],
            GapNotShrunk => &["SWC-112", "CWE-1108"],
            BatchVerifySkip => &["CWE-347"],
            UninitializedStoragePointer => &["SWC-109", "CWE-824"],
            DvnQuorumConflation => &["CWE-347", "CWE-345"],
            ProveFinalizeGameSubstitution => &["CWE-362", "CWE-345"],
            InteropNoSourceBinding => &["CWE-345", "CWE-294"],
            OftDecimalSupplyLeak => &["CWE-682"],
            LzReceiveFailureSilent => &["CWE-755"],
            UnsetPeerDefaultTrust => &["CWE-909", "CWE-345"],
            RefundCreditPreVerdict => &["CWE-682", "CWE-840"],
            ConditionalSenderAliasing => &["CWE-345", "CWE-290"],
            ClockExtensionDepthBranch => &["CWE-682", "CWE-362"],
            RespectedGameTypeSnapshotSwap => &["CWE-345", "CWE-672"],
            ApkMembershipDesync => &["CWE-347", "CWE-345"],
            VerifySnapshotBlockCallerTrust => &["CWE-345", "CWE-672"],
            ChurnStaleStakeDoubleCount => &["CWE-682"],
            IndexRegistryPopSwapStale => &["CWE-672", "CWE-824"],
            EjectionRatelimitLiveBase => &["CWE-682", "CWE-840"],
            ReregisterCooldownBitmapResidue => &["CWE-459", "CWE-841"],
            PolicyPermissionDeclarationGap => &["CWE-862", "CWE-863"],
            ModuleActiveFlagPrivilegeScope => &["CWE-284", "CWE-269"],
            WallCapacityRegenDesync => &["CWE-682", "CWE-841"],
            ModuleUpgradeStateDrop => &["CWE-665", "CWE-1108"],
            LifecycleRoleRevokeGap => &["CWE-266", "CWE-284"],
            KeeperRewardTimestampAuction => &["SWC-116", "CWE-829"],
            BackingSpotInflation => &["CWE-1339", "CWE-682"],
            _ => &[],
        }
    }
}

/// Severity label. Final scores are produced by the engine's corroboration scorer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Info",
        }
    }

    /// SARIF level mapping.
    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        }
    }

    /// A nominal base score for the label, used when a detector hasn't been
    /// scored yet.
    pub fn base_score(self) -> f32 {
        match self {
            Severity::Critical => 90.0,
            Severity::High => 70.0,
            Severity::Medium => 45.0,
            Severity::Low => 20.0,
            Severity::Info => 5.0,
        }
    }
}

/// A single step in a source→sink value-flow trace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceStep {
    pub label: String,
    pub file: String,
    pub line: usize,
    pub snippet: String,
}

/// A normalized finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable per-run id (`F-001`), assigned by the engine.
    pub id: String,
    /// The detector that produced it (`reentrancy`, `oracle-manipulation`).
    pub detector: String,
    pub title: String,
    pub category: Category,
    pub severity: Severity,
    pub severity_score: f32,
    pub confidence: f32,

    pub contract: String,
    pub function: String,
    pub file: String,
    pub line: usize,
    #[serde(skip)]
    pub span: Span,
    pub snippet: String,

    pub message: String,
    pub recommendation: String,
    /// Analysis dimensions that corroborate this finding.
    pub dimensions: Vec<Dimension>,
    pub trace: Vec<TraceStep>,
    pub references: Vec<String>,
    /// Generated Foundry proof-of-concept stub (filled by `sluice-verify`).
    pub poc: Option<String>,
    pub tags: Vec<String>,
}

impl Finding {
    /// A stable de-duplication key (category + location).
    pub fn dedup_key(&self) -> String {
        format!("{}|{}|{}|{}", self.category.slug(), self.contract, self.function, self.line)
    }
}
