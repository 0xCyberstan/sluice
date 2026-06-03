//! Built-in detectors. Each module is one detector implementing
//! [`crate::detector::Detector`]. New detectors only need to (a) implement the
//! trait and (b) be added to [`builtin_detectors`].

/// Shared SCIR-query + FP-suppression helpers for detector authors. A new
/// detector should `use super::prelude::*;` rather than re-deriving the common
/// `root_ident` / `peel_casts` / call-walk / FindingBuilder boilerplate.
pub mod prelude;

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
pub mod gap_not_shrunk;
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
pub mod netted_aggregate_desync;
// Round 8 (perpetual loop) — cross-chain / bridge value-flow classes.
pub mod crosschain_rate_staleness;
// Round 9 (perpetual loop) — remaining Renzo-mined novel classes.
pub mod cooldown_bypass_flag;
pub mod hash_gated_replay;
pub mod oracle_first_mint_seeding;
pub mod proportional_payout_tx_value;
pub mod snapshot_redeem_asymmetry;
pub mod unguarded_accounting_mutator;
pub mod zero_margin_timing_window;
// Round 11 (perpetual loop) — novel classes mined from Karak V2.
pub mod percent_slash_live_base;
pub mod clamp_residual_burn;
pub mod external_root_caller_timestamp;
pub mod proof_admission_only;
pub mod shares_escrowed_repriced;
// Round 12 (perpetual loop) — Ethena-mined classes.
pub mod eip712_typehash_mismatch;
pub mod escrow_exit_restriction_gap;
pub mod vesting_buffered_donation;
pub mod one_sided_peg_band;
pub mod delegated_signer_single_step;
pub mod preauth_callout_target;
// Round 13 (perpetual loop) — Pendle yield-tokenization / AMM-curve classes.
pub mod curve_logit_domain_edge;
pub mod sy_rate_jump_trust;
pub mod monotone_clamp_negative_yield;
pub mod post_expiry_dual_index;
pub mod stale_anchor_reset;
pub mod solver_convergence_trust;
pub mod ratio_denominator_sign_edge;
// Round 14 (perpetual loop) — lending / intent-RFQ / governance / AMM-fee classes.
pub mod interest_index_desync;
pub mod bad_debt_socialization;
pub mod param_update_retroactive;
pub mod rfq_fill_accounting;
pub mod vote_weight_checkpoint;
pub mod feegrowth_accounting;
// Round 15 (perpetual loop) — protocol-agnostic primitive classes.
pub mod tstore_guard_misscope;
pub mod batch_verify_skip;
pub mod uninitialized_storage_pointer;
// Round 16 — L2 / cross-chain infrastructure (LayerZero OApp).
pub mod unset_peer_default_trust;
// Round 16 — bridge M-of-N verification (Wormhole / LayerZero ReceiveUlnBase).
pub mod dvn_quorum_conflation;
// Round 16 — interop cross-domain source-binding (Optimism SuperchainETHBridge).
pub mod interop_no_source_binding;
// Round 16 — remaining bridge classes (OptimismPortal2 + LayerZero OFT/Endpoint).
pub mod prove_finalize_game_substitution;
pub mod lzreceive_failure_silent;
pub mod oft_decimal_supply_leak;
// Round 17 — OP FaultDisputeGame depth-branched clock-extension class.
pub mod clock_extension_depth_branch;
// Round 17 — OP AnchorStateRegistry respected-game-type snapshot swap.
pub mod respected_gametype_snapshot_swap;
// Round 17 — OP fault-proof bond + L1->L2 aliasing.
pub mod refund_credit_pre_verdict;
pub mod conditional_sender_aliasing;
// Round 19 — EigenLayer AVS-middleware (quorum / BLS-registry / churn).
pub mod apk_membership_desync;
pub mod verify_snapshot_block_caller_trust;
pub mod churn_stale_stake_double_count;
pub mod index_registry_pop_swap_stale;
pub mod ejection_ratelimit_live_base;
pub mod reregister_cooldown_bitmap_residue;
pub mod keeper_reward_timestamp_auction;
pub mod policy_permission_declaration_gap;
pub mod module_active_flag_scope;
pub mod wall_capacity_regen_desync;
pub mod module_upgrade_state_drop;
pub mod lifecycle_role_revoke_gap;
pub mod backing_spot_inflation;
// Round 21 — canonical-baseline lints (SWC table-stakes; fire broadly at Low/Info,
// precise on the safe form). WF1: missing-event-emit, floating-pragma, strict-balance-
// equality (SWC-132), deprecated-eth-send (.transfer/.send 2300 stipend). WF2: shadowed-
// state-var (SWC-119), encodepacked-collision (SWC-133), locked-ether (payable, no egress).
pub mod missing_event_emit;
pub mod floating_pragma;
pub mod strict_balance_equality;
pub mod deprecated_eth_send;
pub mod shadowed_state_var;
pub mod encodepacked_collision;
pub mod locked_ether;
// Round 23 — Uniswap v4 hook permission / delta-accounting classes.
pub mod hook_return_delta_permission_gap;
pub mod hook_permission_body_bitmap_mismatch;
// Round 26 — ERC-4337 / EIP-7702 account-abstraction classes.
pub mod missing_entrypoint_guard;
pub mod validation_phase_env_opcode;
pub mod validation_untrusted_callout;

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
        Box::new(gap_not_shrunk::GapNotShrunkDetector),
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
        Box::new(netted_aggregate_desync::NettedAggregateDesyncDetector),
        // R8-tuned + re-activated (were R7-quarantined). internal-share-pricing-rounding
        // now matches ONLY a bare `mulDiv` (no Rounding arg) with a pooled-aggregate
        // divisor spanning share+asset operands (kills the 52 FPs); checkpoint-hint-trust
        // now requires an OZ/Symbiotic `Trace*` container (structurally excludes the
        // cert-verifier / observation-buffer FPs) and fires on the real Checkpoints.sol.
        Box::new(internal_share_pricing_rounding::InternalSharePricingRoundingDetector),
        Box::new(checkpoint_hint_trust::CheckpointHintTrustDetector),
        // Round 8 — cross-chain rate staleness (Renzo xRenzoDeposit class).
        Box::new(crosschain_rate_staleness::CrossChainRateStalenessDetector),
        // Round 9 — remaining Renzo-mined novel classes (each self-validated in its
        // worktree: fires on the cited real Renzo site, ~0 FP on the 5 prior codebases).
        Box::new(unguarded_accounting_mutator::UnguardedAccountingMutatorDetector),
        Box::new(snapshot_redeem_asymmetry::SnapshotRedeemAsymmetryDetector),
        Box::new(cooldown_bypass_flag::CooldownBypassFlagDetector),
        Box::new(hash_gated_replay::HashGatedStructReplayDetector),
        Box::new(oracle_first_mint_seeding::OracleFirstMintSeedingDetector),
        Box::new(proportional_payout_tx_value::ProportionalPayoutTxValueDetector),
        // Zero-margin finalize/veto/unbonding window boundary (Karak Slasher/Vault class).
        Box::new(zero_margin_timing_window::ZeroMarginTimingWindowDetector),
        // Percent-of-live-base slashing finalize (Karak SlasherLib computeSlashAmount class).
        Box::new(percent_slash_live_base::PercentSlashOnLiveBaseDetector),
        // Remaining R11 Karak-mined classes.
        Box::new(shares_escrowed_repriced::SharesEscrowedRepricedDetector),
        Box::new(clamp_residual_burn::ClampResidualBurnDetector),
        Box::new(proof_admission_only::ProofAdmissionOnlyDetector),
        Box::new(external_root_caller_timestamp::ExternalRootCallerTimestampDetector),
        // Round 12 — Ethena-mined classes.
        Box::new(eip712_typehash_mismatch::Eip712TypehashMismatchDetector),
        Box::new(escrow_exit_restriction_gap::EscrowExitRestrictionGapDetector),
        Box::new(vesting_buffered_donation::VestingBufferedDonationDetector),
        Box::new(one_sided_peg_band::OneSidedPegBandDetector),
        Box::new(delegated_signer_single_step::DelegatedSignerSingleStepDetector),
        Box::new(preauth_callout_target::PreAuthCalloutTargetDetector),
        // Round 13 — Pendle yield-tokenization / AMM-curve classes.
        Box::new(curve_logit_domain_edge::CurveLogitDomainEdgeDetector),
        Box::new(sy_rate_jump_trust::SyRateJumpTrustDetector),
        Box::new(monotone_clamp_negative_yield::MonotoneClampNegativeYieldDetector),
        Box::new(post_expiry_dual_index::PostExpiryDualIndexDetector),
        Box::new(stale_anchor_reset::StaleAnchorResetDetector),
        Box::new(solver_convergence_trust::SolverConvergenceTrustDetector),
        Box::new(ratio_denominator_sign_edge::RatioDenominatorSignEdgeDetector),
        // Round 14 — lending / intent-RFQ / governance / AMM-fee classes.
        Box::new(interest_index_desync::InterestIndexDesyncDetector),
        Box::new(bad_debt_socialization::BadDebtSocializationDetector),
        Box::new(param_update_retroactive::ParamUpdateRetroactiveDetector),
        Box::new(rfq_fill_accounting::RfqFillAccountingDetector),
        Box::new(vote_weight_checkpoint::VoteWeightCheckpointDetector),
        Box::new(feegrowth_accounting::FeegrowthAccountingDetector),
        // Round 15 — protocol-agnostic primitive classes.
        Box::new(tstore_guard_misscope::TstoreGuardMisscopeDetector),
        Box::new(batch_verify_skip::BatchVerifySkipDetector),
        Box::new(uninitialized_storage_pointer::UninitializedStoragePointerDetector),
        // Round 16 — LayerZero OApp unset-peer default-trust.
        Box::new(unset_peer_default_trust::UnsetPeerDefaultTrustDetector),
        // Round 16 — bridge M-of-N verification (DVN quorum conflation).
        Box::new(dvn_quorum_conflation::DvnQuorumConflationDetector),
        // Round 16 — interop cross-domain source-binding (SuperchainETHBridge.relayETH).
        Box::new(interop_no_source_binding::InteropNoSourceBindingDetector),
        // Round 16 — remaining bridge classes.
        Box::new(prove_finalize_game_substitution::ProveFinalizeGameSubstitutionDetector),
        Box::new(lzreceive_failure_silent::LzReceiveFailureSilentDetector),
        Box::new(oft_decimal_supply_leak::OftDecimalSupplyLeakDetector),
        // Round 17 — OP FaultDisputeGame depth-branched clock-extension class.
        Box::new(clock_extension_depth_branch::ClockExtensionDepthBranchDetector),
        // Round 17 — OP AnchorStateRegistry respected-game-type snapshot swap.
        Box::new(respected_gametype_snapshot_swap::RespectedGameTypeSnapshotSwapDetector),
        // Round 17 — OP fault-proof bond + L1->L2 aliasing.
        Box::new(refund_credit_pre_verdict::RefundCreditPreVerdictDetector),
        Box::new(conditional_sender_aliasing::ConditionalSenderAliasingDetector),
        // Round 19 — EigenLayer AVS-middleware classes.
        Box::new(apk_membership_desync::ApkMembershipDesyncDetector),
        Box::new(verify_snapshot_block_caller_trust::VerifySnapshotBlockCallerTrustDetector),
        Box::new(churn_stale_stake_double_count::ChurnStaleStakeDoubleCountDetector),
        Box::new(index_registry_pop_swap_stale::IndexRegistryPopSwapStaleDetector),
        Box::new(ejection_ratelimit_live_base::EjectionRatelimitLiveBaseDetector),
        Box::new(reregister_cooldown_bitmap_residue::ReregisterCooldownBitmapResidueDetector),
        Box::new(keeper_reward_timestamp_auction::KeeperRewardTimestampAuctionDetector),
        // Round 20 — Olympus Default-Framework two-table permission-contract gap.
        Box::new(policy_permission_declaration_gap::PolicyPermissionDeclarationGapDetector),
        // Round 20 — remaining Default-Framework / algorithmic-stability classes.
        Box::new(module_active_flag_scope::ModuleActiveFlagScopeDetector),
        Box::new(wall_capacity_regen_desync::WallCapacityRegenDesyncDetector),
        Box::new(module_upgrade_state_drop::ModuleUpgradeStateDropDetector),
        Box::new(lifecycle_role_revoke_gap::LifecycleRoleRevokeGapDetector),
        Box::new(backing_spot_inflation::BackingSpotInflationDetector),
        // Round 21 — canonical-baseline lints (SWC table-stakes).
        Box::new(missing_event_emit::MissingEventEmitDetector),
        Box::new(floating_pragma::FloatingPragmaDetector),
        Box::new(strict_balance_equality::StrictBalanceEqualityDetector),
        Box::new(deprecated_eth_send::DeprecatedEthSendDetector),
        Box::new(shadowed_state_var::ShadowedStateVarDetector),
        Box::new(encodepacked_collision::EncodePackedCollisionDetector),
        Box::new(locked_ether::LockedEtherDetector),
        // Round 23 — Uniswap v4 hook permission / delta-accounting classes.
        Box::new(hook_return_delta_permission_gap::HookReturnDeltaPermissionGapDetector),
        Box::new(hook_permission_body_bitmap_mismatch::HookPermissionBodyBitmapMismatchDetector),
        // Round 26 — ERC-4337 / EIP-7702 account-abstraction classes.
        Box::new(missing_entrypoint_guard::MissingEntryPointGuardDetector),
        Box::new(validation_phase_env_opcode::ValidationPhaseEnvOpcodeDetector),
        Box::new(validation_untrusted_callout::ValidationUntrustedCalloutDetector),
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
