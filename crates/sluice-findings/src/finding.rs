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
