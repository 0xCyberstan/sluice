//! Reentrancy: classic (state-after-call), cross-function, and read-only.
//!
//! Precision rules enforced here (on top of the trust-frontier facts):
//!   * A reentrancy finding MUST be backed by a genuine reentrancy-capable
//!     external / low-level call (`.call`/`.delegatecall`/a non-view interface
//!     call/`.transfer`/`.send`). A function whose effects contain no such call
//!     site cannot be re-entered and never trips any reentrancy rule.
//!   * `Classic` requires a storage WRITE positioned STRICTLY AFTER the external
//!     call (a write that precedes the call is the safe checks-effects shape).
//!   * Calls whose target root-resolves to an immutable/constant or
//!     owner/governance-set trusted infrastructure address (`distributor`,
//!     `treasury`, `veFXS`, a timelock/gauge/minter module, …) are not
//!     attacker-controlled re-entry vectors and are suppressed.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder};
use sluice_frontier::ReentrancyKind;
use sluice_ir::{CallKind, CallSite, Function};

pub struct ReentrancyDetector;

/// A view/pure external method name that runs in a staticcall context and cannot
/// re-enter (mirrors the frontier's built-in view list). A call to one of these
/// is a read, not a re-entry vector.
fn is_view_call_name(name: Option<&str>) -> bool {
    matches!(
        name,
        Some(
            "balanceOf" | "getReserves" | "totalSupply" | "slot0" | "pricePerShare"
                | "getPricePerFullShare" | "get_virtual_price" | "getVirtualPrice" | "latestRoundData"
                | "latestAnswer" | "decimals" | "allowance" | "getAmountsOut" | "getAmountOut"
                | "getAmountsIn" | "getAmountIn" | "symbol" | "name" | "totalAssets" | "convertToAssets"
                | "convertToShares" | "previewRedeem" | "previewDeposit" | "previewMint"
                | "previewWithdraw" | "getRate" | "exchangeRate" | "quote" | "observe"
                | "getPastVotes" | "getPriorVotes" | "getVotes" | "getPastTotalSupply"
                | "delegates" | "nonces" | "checkpoints" | "numCheckpoints" | "getCurrentVotes"
        )
    )
}

/// Token-transfer-style methods: even an immutable/trusted token address can be an
/// ERC-777/ERC-721 contract whose transfer hook re-enters, so these are NEVER
/// trusted away (mirrors the frontier's `is_token_transfer_method`).
fn is_token_transfer_name(name: Option<&str>) -> bool {
    matches!(
        name,
        Some(
            "transfer" | "transferFrom" | "safeTransfer" | "safeTransferFrom" | "send"
                | "operatorSend" | "safeMint" | "mint" | "safeBatchTransferFrom"
        )
    )
}

/// True if this call site can hand control to code that may re-enter the
/// contract (the frontier's `is_reentrancy_capable`, replicated locally so the
/// detector can corroborate the facts without exporting internals).
fn is_reentry_vector(cs: &CallSite) -> bool {
    match cs.kind {
        CallKind::LowLevelCall | CallKind::DelegateCall | CallKind::Send | CallKind::Transfer => true,
        CallKind::External => cs.sends_value || !is_view_call_name(cs.func_name.as_deref()),
        // staticcall is read-only; everything else is not a control transfer.
        _ => false,
    }
}

/// True if this reentry-capable call is to a TRUSTED target (immutable/constant or
/// owner/governance-set infrastructure) and is a plain (non-value, non-transfer)
/// method call — i.e. not an attacker-controlled re-entry surface. Token-transfer
/// methods and value-bearing/low-level calls are never trusted on this basis.
fn is_trusted_call(cs: &CallSite, trusted: &rustc_hash::FxHashSet<String>) -> bool {
    cs.kind == CallKind::External
        && !cs.sends_value
        && !is_token_transfer_name(cs.func_name.as_deref())
        && trusted.contains(sluice_frontier::target_root(&cs.target))
}

/// True iff `f` contains at least one GENUINE (untrusted) reentrancy-capable
/// external/low-level call. A function with none of these cannot be re-entered,
/// so it must never trip a classic/cross-function reentrancy rule.
fn has_genuine_reentry_vector(f: &Function, trusted: &rustc_hash::FxHashSet<String>) -> bool {
    f.effects
        .call_sites
        .iter()
        .any(|cs| is_reentry_vector(cs) && !is_trusted_call(cs, trusted))
}

/// True iff `f` performs a storage WRITE to one of `vars` STRICTLY AFTER a
/// genuine (untrusted) reentrancy-capable external call. This is the concrete
/// classic checks-effects-interactions violation: a write whose position index
/// is greater than the external call's index. A write that precedes the call is
/// the safe shape and does not count.
fn has_qualifying_post_call_write(
    f: &Function,
    vars: &[String],
    trusted: &rustc_hash::FxHashSet<String>,
) -> bool {
    let first_vector = f
        .effects
        .call_sites
        .iter()
        .filter(|cs| is_reentry_vector(cs) && !is_trusted_call(cs, trusted))
        .map(|cs| cs.order)
        .min();
    let Some(first) = first_vector else { return false };
    f.effects
        .storage_writes
        .iter()
        .any(|w| w.order > first && vars.iter().any(|v| v == &w.var))
}

impl Detector for ReentrancyDetector {
    fn id(&self) -> &'static str {
        "reentrancy"
    }
    fn category(&self) -> Category {
        Category::Reentrancy
    }
    fn description(&self) -> &'static str {
        "External call before state update (classic, cross-function, read-only)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // Trusted call targets for f's contract (immutable/constant + the
            // owner/governance-set infrastructure names). Used to discount calls
            // into in-protocol modules (`distributor`/`treasury`/`veFXS`/…).
            let trusted = sluice_frontier::trusted_targets(cx.scir, f.contract);

            for r in cx.frontier.reentrancy_of(f.id) {
                if r.guarded || cx.has_reentrancy_guard(f) {
                    continue;
                }

                // PRECISION GATE 1 — a reentrancy finding must be backed by a
                // genuine external/low-level call on the path that produced it.
                // For read-only the call lives on the mutating writer path; for
                // classic/cross-function it is the flagged function's own call.
                // A risk with no backing call is never reportable.
                if !r.backed_by_call {
                    continue;
                }

                match r.kind {
                    // Classic and cross-function both flag the function that MAKES
                    // the external call, so that function must itself contain a
                    // genuine (untrusted) re-entry vector.
                    ReentrancyKind::Classic | ReentrancyKind::CrossFunction => {
                        if !has_genuine_reentry_vector(f, &trusted) {
                            // Either no external/low-level call at all, or every
                            // such call targets trusted infrastructure (the
                            // harvest-calls-`distributor`/`treasury` class). Not an
                            // open re-entry surface — suppress.
                            continue;
                        }
                    }
                    // Read-only flags a view getter (which makes no external call);
                    // its backing call was already validated on the writer path and
                    // recorded in `backed_by_call`.
                    ReentrancyKind::ReadOnly => {}
                }

                // PRECISION GATE 2 (classic only) — require a storage write
                // STRICTLY AFTER the external call. A state update that precedes
                // the call (`executed = true;` before a timelock call) is the safe
                // checks-effects shape, not the vulnerable post-call update; and if
                // there is no post-call write at all (a one-line transfer), there
                // is nothing for re-entry to corrupt.
                if r.kind == ReentrancyKind::Classic
                    && !has_qualifying_post_call_write(f, &r.vars_written_after, &trusted)
                {
                    continue;
                }

                // Access-controlled functions can only be entered by a trusted
                // actor, so reentrancy risk is much lower. Cross-function (the
                // weakest signal) is dropped entirely there; classic/read-only are
                // downgraded to a low confidence so they sink to Low/Info.
                let access_controlled = cx.has_access_control(f);
                if access_controlled && r.kind == ReentrancyKind::CrossFunction {
                    continue;
                }
                let (cat, sev, conf, title) = match r.kind {
                    ReentrancyKind::Classic => (
                        Category::Reentrancy,
                        sluice_findings::Severity::High,
                        0.8,
                        "State updated after external call (classic reentrancy)",
                    ),
                    ReentrancyKind::ReadOnly => (
                        Category::ReadOnlyReentrancy,
                        sluice_findings::Severity::High,
                        0.6,
                        "View getter exposes mid-update state (read-only reentrancy)",
                    ),
                    ReentrancyKind::CrossFunction => (
                        Category::Reentrancy,
                        sluice_findings::Severity::Medium,
                        0.55,
                        "Shared state reachable during external call (cross-function reentrancy)",
                    ),
                };
                let conf = if access_controlled { conf * 0.5 } else { conf };
                let mut b = FindingBuilder::new(self.id(), cat)
                    .title(title)
                    .severity(sev)
                    .confidence(conf)
                    .dimension(Dimension::Frontier)
                    .message(format!(
                        "`{}` performs an external call and then touches storage [{}]. An attacker \
                         contract can re-enter before state settles. {}",
                        f.name,
                        r.vars_written_after.join(", "),
                        match r.kind {
                            ReentrancyKind::ReadOnly =>
                                "A consumer reading this getter mid-transaction sees corrupted values.",
                            ReentrancyKind::CrossFunction =>
                                "Re-entering a sibling function that shares this state is profitable.",
                            ReentrancyKind::Classic => "This is the DAO/Curve-class pattern.",
                        }
                    ))
                    .recommendation(
                        "Apply checks-effects-interactions (update storage before the external call) \
                         and/or a `nonReentrant` guard covering all entry points sharing this state.",
                    );
                // Value-flow corroboration: sending ETH makes re-entry trivial.
                if f.effects.call_sites.iter().any(|c| c.sends_value) {
                    b = b.dimension(Dimension::ValueFlow);
                }
                out.push(cx.finish(b, f.id, r.span));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyze_sources, Config};

    /// All reentrancy-detector findings for a source blob.
    fn reentrancy_findings(src: &str) -> Vec<Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default())
            .findings
            .into_iter()
            .filter(|f| f.detector == "reentrancy")
            .collect()
    }

    fn fires(src: &str) -> bool {
        !reentrancy_findings(src).is_empty()
    }

    // ---- FP1: a view getter with ZERO external calls must stay silent. ----
    // etherfi WithdrawRequestNFT.isScan…: a pure getter that returns a comparison
    // of two storage reads. With no vulnerable mutating writer and no external
    // call anywhere, nothing can seed a read-only risk.
    #[test]
    fn silent_on_view_getter_with_zero_calls() {
        let src = r#"
            contract WithdrawRequestNFT {
                uint256 public lastFinalizedRequestId;
                uint256 public nextRequestId;
                // pure comparison of two storage reads, no external call at all.
                function isScanRequested(uint256 id) external view returns (bool) {
                    return id <= lastFinalizedRequestId && id < nextRequestId;
                }
                function shareValue() external view returns (uint256) {
                    return lastFinalizedRequestId * nextRequestId; // oracle-ish name, still no call
                }
            }
        "#;
        assert!(!fires(src), "read-only reentrancy must not fire on a call-free view getter");
    }

    // ---- FP2: a storage write BEFORE the external call must not fire classic. ----
    // olympus GovernorOHMegaDelegate.execute: `proposal.executed = true;` is set
    // BEFORE the call; checks-effects order is correct. The external call here is a
    // genuine, untrusted low-level call (to an arbitrary `target` param), so the
    // ONLY reason this stays silent is the write-precedes-call rule.
    #[test]
    fn silent_on_write_before_call() {
        let src = r#"
            contract Governor {
                mapping(uint256 => bool) public executed;
                function execute(uint256 id, address target, bytes calldata d) external {
                    require(!executed[id], "already");
                    executed[id] = true;            // WRITE before the call (CEI-correct)
                    (bool ok,) = target.call(d);    // genuine untrusted external call AFTER the write
                    require(ok, "exec failed");
                }
            }
        "#;
        assert!(
            !fires(src),
            "classic reentrancy must not fire when the only state write precedes the external call"
        );
    }

    // ---- FP3: a harvest that calls an immutable/trusted module then writes
    // unrelated state must stay silent (trusted call target). ----
    #[test]
    fn silent_on_harvest_calling_immutable_distributor() {
        let src = r#"
            interface IDistributor { function distribute() external; }
            contract Staking {
                IDistributor public immutable distributor; // trusted: immutable module
                uint256 public lastHarvest;
                uint256 public epoch;
                constructor(IDistributor d) { distributor = d; }
                function harvest() external {
                    uint256 prev = lastHarvest;       // read before
                    distributor.distribute();         // plain call to a trusted immutable module
                    lastHarvest = block.timestamp;    // write after — but target is trusted
                    epoch = prev + 1;
                }
            }
        "#;
        assert!(
            !fires(src),
            "reentrancy must not fire when the only external call targets a trusted immutable module"
        );
    }

    // FP3 variant: an owner/governance-set (non-immutable) trusted-named module is
    // also discounted via the extended trusted-target name set.
    #[test]
    fn silent_on_harvest_calling_named_treasury() {
        let src = r#"
            interface ITreasury { function deposit(uint256 a) external; }
            contract Vault {
                ITreasury public treasury;   // owner-set, but trusted-named infrastructure
                uint256 public totalHarvested;
                function setTreasury(ITreasury t) external { treasury = t; }
                function harvest(uint256 amount) external {
                    uint256 prev = totalHarvested;  // read before
                    treasury.deposit(amount);       // plain call to trusted-named module
                    totalHarvested = prev + amount; // write after, but trusted target
                }
            }
        "#;
        assert!(
            !fires(src),
            "reentrancy must not fire when the only external call targets a trusted-named module"
        );
    }

    // ---- FP4: a one-line transfer with NO post-call state write must stay
    // silent. olympus OhmFaucet.dispense. ----
    #[test]
    fn silent_on_dispense_with_no_post_call_write() {
        let src = r#"
            interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
            contract OhmFaucet {
                IERC20 public ohm;
                uint256 public dripAmount;
                function dispense() external {
                    ohm.transfer(msg.sender, dripAmount); // single transfer, no state write after
                }
            }
        "#;
        assert!(
            !fires(src),
            "reentrancy must not fire when there is no state write after the external call"
        );
    }

    // ---- TRUE POSITIVE: classic write-after-call must still fire. ----
    // `msg.sender.call{value:amt}(""); balances[msg.sender] -= amt;` — the write
    // lands STRICTLY AFTER the external call. The leading `require(amt > 0)` does
    // not reference msg.sender, so this is not treated as access-controlled and
    // the finding surfaces at full confidence.
    #[test]
    fn fires_on_classic_write_after_call() {
        let src = r#"
            contract Bank {
                mapping(address => uint256) public balances;
                function deposit() external payable { balances[msg.sender] += msg.value; }
                function withdraw(uint256 amt) external {
                    require(amt > 0, "zero");
                    uint256 bal = balances[msg.sender];       // storage READ before the call
                    require(bal >= amt, "insufficient");
                    (bool ok,) = msg.sender.call{value: amt}(""); // external call first
                    require(ok, "fail");
                    balances[msg.sender] -= amt;              // WRITE strictly after the call
                }
            }
        "#;
        let fs = reentrancy_findings(src);
        assert!(
            fs.iter().any(|f| f.category == Category::Reentrancy),
            "classic reentrancy (write strictly after the external call) must fire"
        );
    }
}
