//! Built-in detectors. Each module is one detector implementing
//! [`crate::detector::Detector`]. New detectors only need to (a) implement the
//! trait and (b) be added to [`builtin_detectors`].

pub mod accounting;
pub mod access_control;
pub mod oracle;
pub mod reentrancy;
pub mod signature;
pub mod unchecked_return;
pub mod upgradeable;
pub mod vault;
// Expansion detectors (authored in parallel; registered ahead of time).
pub mod bridge;
pub mod dos;
pub mod erc777;
pub mod fee_on_transfer;
pub mod flashloan;
pub mod forced_ether;
pub mod integer_issues;
pub mod randomness;
pub mod selector;
pub mod slippage;
// v2 expansion detectors.
pub mod approve_race;
pub mod arbitrary_transfer;
pub mod gas_griefing;
pub mod governance_timelock;
pub mod missing_zero_check;
pub mod msg_value_loop;
pub mod oracle_staleness;
pub mod rounding;
pub mod storage_gap;
// Round 1 (perpetual loop) detectors.
pub mod delegatecall_loop;
pub mod flashloan_callback;
pub mod price_bounds;
pub mod reward_debt;
pub mod selfdestruct;
pub mod twap_manipulation;
// Round 2 (perpetual loop) detectors.
pub mod array_length_mismatch;
pub mod block_number_time;
pub mod double_entry_token;
pub mod liquidation_abuse;
pub mod signature_malleability;
pub mod unprotected_initializer;
// Round 3 (perpetual loop) detectors.
pub mod cached_domain_separator;
pub mod centralization;
pub mod decimals_assumption;
pub mod erc721_safety;
pub mod hardcoded_gas_stipend;
pub mod unchecked_abi_decode;
// Round 4 (perpetual loop) detectors.
pub mod erc1155_receiver;
pub mod l2_sequencer;
pub mod lp_slippage;
pub mod signed_cast;
// Round 5 (perpetual loop) detectors.
pub mod untrusted_call_target;
// Round 6 (perpetual loop) detectors.
pub mod erc721_mint_reentrancy;
// Round 7 (perpetual loop) — novel / under-publicised classes (restaking, checkpoints, slashing).
pub mod checkpoint_hint_trust;
pub mod epoch_boundary_staleness;
pub mod internal_share_pricing_rounding;
pub mod pooled_shares_reprice_desync;
pub mod proportional_split_residual;
pub mod silenced_privileged_callback;

use crate::detector::Detector;

/// The registry of built-in detectors.
pub fn builtin_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(reentrancy::ReentrancyDetector),
        Box::new(access_control::AccessControlDetector),
        Box::new(oracle::OracleDetector),
        Box::new(unchecked_return::UncheckedReturnDetector),
        Box::new(accounting::AccountingDetector),
        Box::new(signature::SignatureDetector),
        Box::new(upgradeable::UpgradeableDetector),
        Box::new(vault::VaultDetector),
        // Expansion set.
        Box::new(flashloan::FlashLoanGovernanceDetector),
        Box::new(bridge::BridgeDetector),
        Box::new(slippage::SlippageDetector),
        Box::new(dos::DosDetector),
        Box::new(fee_on_transfer::FeeOnTransferDetector),
        Box::new(randomness::RandomnessDetector),
        Box::new(forced_ether::ForcedEtherDetector),
        Box::new(selector::SelectorCollisionDetector),
        Box::new(integer_issues::IntegerIssuesDetector),
        Box::new(erc777::Erc777Detector),
        // v2 expansion set.
        Box::new(oracle_staleness::OracleStalenessDetector),
        Box::new(arbitrary_transfer::ArbitraryTransferDetector),
        Box::new(msg_value_loop::MsgValueInLoopDetector),
        Box::new(missing_zero_check::MissingZeroCheckDetector),
        Box::new(gas_griefing::GasGriefingDetector),
        Box::new(governance_timelock::GovernanceTimelockDetector),
        Box::new(approve_race::ApproveRaceDetector),
        Box::new(storage_gap::StorageGapDetector),
        Box::new(rounding::RoundingDetector),
        // Round 1 (perpetual loop).
        Box::new(twap_manipulation::TwapManipulationDetector),
        Box::new(flashloan_callback::FlashloanCallbackDetector),
        Box::new(selfdestruct::SelfdestructDetector),
        Box::new(delegatecall_loop::DelegatecallLoopDetector),
        Box::new(reward_debt::RewardDebtDetector),
        Box::new(price_bounds::PriceBoundsDetector),
        // Round 2 (perpetual loop).
        Box::new(signature_malleability::SignatureMalleabilityDetector),
        Box::new(unprotected_initializer::UnprotectedInitializerDetector),
        Box::new(array_length_mismatch::ArrayLengthMismatchDetector),
        Box::new(double_entry_token::DoubleEntryTokenDetector),
        Box::new(liquidation_abuse::LiquidationAbuseDetector),
        Box::new(block_number_time::BlockNumberTimeDetector),
        // Round 3 (perpetual loop).
        Box::new(decimals_assumption::DecimalsAssumptionDetector),
        Box::new(centralization::CentralizationDetector),
        Box::new(erc721_safety::Erc721SafetyDetector),
        Box::new(unchecked_abi_decode::UncheckedAbiDecodeDetector),
        Box::new(hardcoded_gas_stipend::HardcodedGasStipendDetector),
        Box::new(cached_domain_separator::CachedDomainSeparatorDetector),
        // Round 4 (perpetual loop).
        Box::new(l2_sequencer::L2SequencerDetector),
        Box::new(lp_slippage::LpSlippageDetector),
        Box::new(erc1155_receiver::Erc1155ReceiverDetector),
        Box::new(signed_cast::SignedCastDetector),
        // Round 5 (perpetual loop).
        Box::new(untrusted_call_target::UntrustedCallTargetDetector),
        // Round 6 (perpetual loop).
        Box::new(erc721_mint_reentrancy::Erc721MintReentrancyDetector),
        // Round 7 (perpetual loop) — novel classes. Shipped after the R7 dogfood vs
        // REAL Symbiotic Core + the 4 prior codebases. `epoch-boundary-staleness` fires
        // on the real Vault epoch ops (+ a few low-cost hits elsewhere); the other three
        // are tight (0 FPs on all 5 codebases). R8 will tune them to also fire on the
        // real Vault.onSlash / withdrawal-queue / pop(call) shapes (currently fixture-only).
        Box::new(epoch_boundary_staleness::EpochBoundaryStalenessDetector),
        Box::new(proportional_split_residual::ProportionalSplitResidualDetector),
        Box::new(pooled_shares_reprice_desync::PooledSharesRepriceDesyncDetector),
        Box::new(silenced_privileged_callback::SilencedPrivilegedCallbackDetector),
        // QUARANTINED pending R8 real-code tuning (the R7 dogfood showed these regress
        // precision): internal-share-pricing-rounding floods on every internal `a*b/c`
        // (52 FPs across the 4 codebases — reward-index / points / penalty-ratio math),
        // and checkpoint-hint-trust over-fires on cert verifiers AND misses the real
        // Checkpoints.sol it targets. R8 tightens both, then re-activates.
        // Box::new(internal_share_pricing_rounding::InternalSharePricingRoundingDetector),
        // Box::new(checkpoint_hint_trust::CheckpointHintTrustDetector),
    ]
}

// ----------------------------------------------------------------- shared utils

use sluice_ir::{Expr, ExprKind, Function, Span};

/// Find the first spot-price call (`balanceOf`, `getReserves`, ...) in a
/// function body, returning its span.
pub(crate) fn find_spot_price(f: &Function) -> Option<Span> {
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if sluice_dataflow::is_spot_price_call(c) {
                    found = Some(e.span);
                }
            }
        });
    }
    found
}

/// Does a name look like protocol accounting state (balance, collateral, debt,
/// shares, price, reserves, amount)?
pub(crate) fn is_accounting_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "balance", "collateral", "debt", "share", "deposit", "borrow", "reserve", "price", "amount",
        "liquidity", "total", "supply", "assets", "rate",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// Names that indicate privileged/admin state. Deliberately conservative:
/// generic words like `operator`/`manager`/`minter`/`role` appear in ordinary
/// per-entity bookkeeping and produced false positives on real protocols, so
/// they are excluded. Combined with the mapping-write skip in the access-control
/// detector (admin state is a scalar, not a per-key mapping).
pub(crate) fn is_privileged_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "owner", "admin", "governance", "governor", "treasury", "implementation", "paused",
        "oracle", "pricefeed", "whitelist", "blacklist", "pendingowner", "proxy", "beacon",
        "guardian", "authority",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// Visit every call expression in a function body.
pub(crate) fn visit_calls<'a>(f: &'a Function, mut visit: impl FnMut(&'a sluice_ir::Call, Span)) {
    for s in &f.body {
        s.visit_exprs(&mut |e: &'a Expr| {
            if let ExprKind::Call(c) = &e.kind {
                visit(c, e.span);
            }
        });
    }
}
