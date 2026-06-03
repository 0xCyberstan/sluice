//! # sluice-frontier
//!
//! **Trust-frontier analysis** — the analog of `vortex-cross`. Every external
//! call (`other.foo()`, `addr.call{value:}()`, `delegatecall`, ERC-20
//! `transfer`) is a boundary where control or value leaves the contract and an
//! untrusted party may act. This pass enumerates those crossings and classifies
//! the reentrancy / unchecked-return / value-flow risk at each, including the
//! subtle **read-only reentrancy** case where a `view` getter exposes
//! mid-update state to an external consumer.

use rustc_hash::{FxHashMap, FxHashSet};
use sluice_ir::{CallKind, ContractId, Function, FunctionId, GuardKind, Scir, Span};

pub mod xcontract;
pub use xcontract::ContractResolver;

/// One external-call crossing.
#[derive(Debug, Clone)]
pub struct Crossing {
    pub function: FunctionId,
    pub contract: ContractId,
    pub kind: CallKind,
    pub target: String,
    /// Resolved method name (`transfer`, `call`, ...), if any.
    pub func_name: Option<String>,
    pub order: u32,
    pub return_checked: bool,
    pub sends_value: bool,
    /// A state write occurs after this call in the same function (CEI violation).
    pub state_write_after: bool,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReentrancyKind {
    /// State written after an external call in the same function.
    Classic,
    /// A sibling state-mutating function shares storage written after the call.
    CrossFunction,
    /// A `view` getter reads state that a mutating path updates after an
    /// external call — consumable as a corrupt oracle.
    ReadOnly,
}

#[derive(Debug, Clone)]
pub struct ReentrancyRisk {
    pub function: FunctionId,
    pub contract: ContractId,
    pub kind: ReentrancyKind,
    /// True if protected by a reentrancy lock (modifier or inherited guard).
    pub guarded: bool,
    /// Storage variables written after the external call.
    pub vars_written_after: Vec<String>,
    pub span: Span,
}

#[derive(Debug, Default)]
pub struct FrontierFacts {
    pub crossings: Vec<Crossing>,
    pub reentrancy: Vec<ReentrancyRisk>,
    /// Interface/type -> implementation resolver, for cross-contract analysis.
    pub resolver: ContractResolver,
}

impl FrontierFacts {
    pub fn analyze(scir: &Scir) -> Self {
        let mut facts = FrontierFacts::default();
        facts.resolver = ContractResolver::build(scir);
        for c in scir.iter_contracts() {
            let contract_has_lock = c.inherits_like("reentrancyguard") || c.inherits_like("reentrant");

            // Map storage var -> view getters that read it (for read-only reentrancy).
            let view_readers = view_readers_of(scir, c.id);
            let trusted = trusted_targets(scir, c.id);

            for f in scir.functions_of(c.id) {
                // Constructors run once at deploy and modifiers are analyzed via
                // their host functions — neither is a reentrancy entry point.
                if !f.has_body || f.is_constructor() || f.is_modifier() {
                    continue;
                }
                let guarded = function_has_lock(f) || contract_has_lock;

                let first_ext = first_reentrant_call(f, &trusted);
                for cs in &f.effects.call_sites {
                    if !cs.kind.is_external_transfer_of_control() {
                        continue;
                    }
                    let writes_after: Vec<String> = f
                        .effects
                        .storage_writes
                        .iter()
                        .filter(|w| w.order > cs.order)
                        .map(|w| w.var.clone())
                        .collect();
                    facts.crossings.push(Crossing {
                        function: f.id,
                        contract: c.id,
                        kind: cs.kind,
                        target: cs.target.clone(),
                        func_name: cs.func_name.clone(),
                        order: cs.order,
                        return_checked: cs.return_checked,
                        sends_value: cs.sends_value,
                        state_write_after: !writes_after.is_empty(),
                        span: cs.span,
                    });
                }

                // Classic reentrancy requires the actual CEI-violation shape: a
                // storage variable that is READ BEFORE the external call (its
                // stale value is used) and WRITTEN AFTER it. A write-after-call to
                // a var that was not read before (e.g. an event-bookkeeping flag,
                // or a registry entry) is not exploitable via re-entry — requiring
                // the read-before-and-write-after overlap removes the bulk of the
                // real-world false positives (Timelock flag-clears, factory
                // registry writes, etc.).
                if let Some(first) = first_ext {
                    let reads_before: std::collections::HashSet<&str> = f
                        .effects
                        .storage_reads
                        .iter()
                        .filter(|r| r.order < first)
                        .map(|r| r.var.as_str())
                        .collect();
                    let vars_after: Vec<String> = f
                        .effects
                        .storage_writes
                        .iter()
                        .filter(|w| w.order > first && reads_before.contains(w.var.as_str()))
                        .map(|w| w.var.clone())
                        .collect();
                    if !vars_after.is_empty() {
                        facts.reentrancy.push(ReentrancyRisk {
                            function: f.id,
                            contract: c.id,
                            kind: ReentrancyKind::Classic,
                            guarded,
                            vars_written_after: dedup(vars_after.clone()),
                            span: f.span,
                        });

                        // Read-only reentrancy: a view getter reads one of the
                        // vars updated after the call.
                        for v in &vars_after {
                            if let Some(getters) = view_readers.get(v) {
                                if let Some(getter) = getters.first() {
                                    facts.reentrancy.push(ReentrancyRisk {
                                        function: *getter,
                                        contract: c.id,
                                        kind: ReentrancyKind::ReadOnly,
                                        guarded: false, // view fns are typically unguarded
                                        vars_written_after: vec![v.clone()],
                                        span: scir.function(*getter).map(|g| g.span).unwrap_or(f.span),
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // Cross-function reentrancy: an external call in function A leaves a
            // shared var that sibling B writes/reads, while A has no lock.
            detect_cross_function(scir, c.id, &mut facts);
        }
        facts
    }

    pub fn crossings_of(&self, fid: FunctionId) -> impl Iterator<Item = &Crossing> {
        self.crossings.iter().filter(move |c| c.function == fid)
    }

    pub fn reentrancy_of(&self, fid: FunctionId) -> impl Iterator<Item = &ReentrancyRisk> {
        self.reentrancy.iter().filter(move |r| r.function == fid)
    }

    /// Unchecked external/low-level calls (return value ignored).
    pub fn unchecked_returns(&self) -> impl Iterator<Item = &Crossing> {
        self.crossings.iter().filter(|c| {
            !c.return_checked
                && matches!(c.kind, CallKind::LowLevelCall | CallKind::Send | CallKind::External)
        })
    }
}

/// Common view/pure external method names that cannot re-enter (they run in a
/// staticcall context). Excluding these is the key reentrancy FP suppressor:
/// a `token.balanceOf(...)` read followed by a state write is not reentrancy.
fn is_view_method(name: Option<&str>) -> bool {
    matches!(
        name,
        Some(
            "balanceOf" | "getReserves" | "totalSupply" | "slot0" | "pricePerShare"
                | "getPricePerFullShare" | "get_virtual_price" | "getVirtualPrice" | "latestRoundData"
                | "latestAnswer" | "decimals" | "allowance" | "getAmountsOut" | "getAmountOut"
                | "getAmountsIn" | "getAmountIn" | "symbol" | "name" | "totalAssets" | "convertToAssets"
                | "convertToShares" | "previewRedeem" | "previewDeposit" | "previewMint"
                | "previewWithdraw" | "getRate" | "exchangeRate" | "quote" | "observe"
                // governance / token view reads (ERC20Votes etc.)
                | "getPastVotes" | "getPriorVotes" | "getVotes" | "getPastTotalSupply"
                | "delegates" | "nonces" | "checkpoints" | "numCheckpoints" | "getCurrentVotes"
                // factory deploy / clone helpers: deploy fresh code, no attacker callback
                | "clone" | "cloneDeterministic" | "create" | "create2" | "create3"
                | "predictDeterministicAddress" | "computeAddress" | "deploy"
        )
    )
}

/// True if a call site can hand control to code that may re-enter this contract.
fn is_reentrancy_capable(cs: &sluice_ir::CallSite) -> bool {
    match cs.kind {
        CallKind::LowLevelCall | CallKind::DelegateCall | CallKind::Send | CallKind::Transfer => true,
        // A non-view external method call can run attacker code; a view read cannot.
        CallKind::External => cs.sends_value || !is_view_method(cs.func_name.as_deref()),
        // staticcall is read-only by construction.
        CallKind::StaticCall => false,
        _ => false,
    }
}

/// Order of the first reentrancy-capable external call in a function, ignoring
/// calls to `trusted` (immutable/constant) target addresses. An immutable target
/// is set once at construction (WETH, a router, an in-protocol module) and is not
/// an attacker-controlled re-entry vector — though value-sending and low-level
/// calls are still counted regardless of target.
fn first_reentrant_call(f: &Function, trusted: &FxHashSet<String>) -> Option<u32> {
    f.effects
        .call_sites
        .iter()
        .filter(|cs| is_reentrancy_capable(cs) && !is_trusted_external(cs, trusted))
        .map(|cs| cs.order)
        .min()
}

/// True if this is a plain (non-value, non-low-level) external method call to a
/// trusted immutable/constant target. Token-transfer methods are NEVER trusted on
/// this basis: even an immutable token address can be an ERC-777/ERC-721 contract
/// whose transfer hook re-enters (the dForce/Lendf.me class), so those stay
/// reentrancy-capable regardless of how the address was set.
fn is_trusted_external(cs: &sluice_ir::CallSite, trusted: &FxHashSet<String>) -> bool {
    cs.kind == CallKind::External
        && !cs.sends_value
        && !is_token_transfer_method(cs.func_name.as_deref())
        && trusted.contains(target_root(&cs.target))
}

fn is_token_transfer_method(name: Option<&str>) -> bool {
    matches!(
        name,
        Some(
            "transfer" | "transferFrom" | "safeTransfer" | "safeTransferFrom" | "send"
                | "operatorSend" | "safeMint" | "mint" | "safeBatchTransferFrom"
        )
    )
}

/// Leading identifier of a textual call target (`MINTR.x[y]` -> `MINTR`).
fn target_root(target: &str) -> &str {
    target
        .split(|c: char| c == '.' || c == '(' || c == '[' || c == ' ')
        .next()
        .unwrap_or(target)
}

/// State variables that are immutable or constant addresses — trusted targets.
fn trusted_targets(scir: &Scir, cid: ContractId) -> FxHashSet<String> {
    scir.contract(cid)
        .map(|c| {
            c.state_vars
                .iter()
                .filter(|v| v.immutable || v.constant)
                .map(|v| v.name.clone())
                .collect()
        })
        .unwrap_or_default()
}

fn function_has_lock(f: &Function) -> bool {
    f.effects
        .guards
        .iter()
        .any(|g| matches!(g.kind, GuardKind::ReentrancyLock))
}

/// For each storage var, the *price/value-like* view getters in the contract
/// that read it. Read-only reentrancy is only meaningful when an external
/// consumer trusts a getter that returns a value derived from mid-update state
/// (a price / share rate / virtual price) — the Curve/Sentinel class. Flagging
/// every `version()`/`isLocked()`-style getter was pure noise on real code.
fn view_readers_of(scir: &Scir, cid: ContractId) -> FxHashMap<String, Vec<FunctionId>> {
    let mut map: FxHashMap<String, Vec<FunctionId>> = FxHashMap::default();
    for f in scir.functions_of(cid) {
        if f.is_view_or_pure() && f.is_externally_reachable() && is_value_oracle_getter(&f.name) {
            for r in &f.effects.storage_reads {
                map.entry(r.var.clone()).or_default().push(f.id);
            }
        }
    }
    map
}

/// A getter whose return value reads like a price / share value an external
/// protocol might consume as an oracle.
fn is_value_oracle_getter(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "price", "value", "share", "rate", "reserve", "virtual", "totalassets", "convertto",
        "exchange", "quote", "worth", "collateral", "underlying", "pershare", "amountout",
    ]
    .iter()
    .any(|k| l.contains(k))
}

fn detect_cross_function(scir: &Scir, cid: ContractId, facts: &mut FrontierFacts) {
    // Collect (function, vars-written-after-call, guarded) for functions with
    // an external call that is NOT followed by their own write (so classic
    // doesn't fire) but leaves shared state for siblings.
    let funcs: Vec<&Function> = scir.functions_of(cid).filter(|f| f.has_body).collect();
    let trusted = trusted_targets(scir, cid);
    for f in &funcs {
        // Cross-function reentrancy is about an EXTERNAL entry point leaving
        // shared state mid-call; internal helpers and constructors are not entry
        // points an attacker calls directly.
        if !f.is_externally_reachable() || f.is_constructor() {
            continue;
        }
        let Some(first) = first_reentrant_call(f, &trusted) else {
            continue;
        };
        if function_has_lock(f) {
            continue;
        }
        // Vars read or written by f around the call.
        let touched: Vec<&str> = f
            .effects
            .storage_reads
            .iter()
            .chain(f.effects.storage_writes.iter())
            .filter(|a| a.order < first)
            .map(|a| a.var.as_str())
            .collect();
        // Does a sibling mutate one of those vars (so re-entering it is harmful)?
        for sib in &funcs {
            if sib.id == f.id || !sib.is_state_mutating() || !sib.is_externally_reachable() {
                continue;
            }
            let shared: Vec<String> = sib
                .effects
                .written_vars()
                .iter()
                .filter(|v| touched.contains(v))
                .map(|v| v.to_string())
                .collect();
            if !shared.is_empty() {
                facts.reentrancy.push(ReentrancyRisk {
                    function: f.id,
                    contract: cid,
                    kind: ReentrancyKind::CrossFunction,
                    guarded: false,
                    vars_written_after: dedup(shared),
                    span: f.span,
                });
                break;
            }
        }
    }
}

fn dedup(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(src: &str) -> (Scir, FrontierFacts) {
        let scir = sluice_parse::parse_sources(vec![("t.sol".into(), src.into())]).scir;
        (scir.clone(), FrontierFacts::analyze(&scir))
    }

    #[test]
    fn classic_reentrancy_detected() {
        let (scir, facts) = analyze(
            r#"
            contract Bank {
                mapping(address => uint256) balances;
                function withdraw() external {
                    uint256 a = balances[msg.sender];
                    (bool ok,) = msg.sender.call{value: a}("");
                    require(ok);
                    balances[msg.sender] = 0;
                }
            }
            "#,
        );
        let w = scir.all_functions().find(|f| f.name == "withdraw").unwrap();
        assert!(facts.reentrancy_of(w.id).any(|r| r.kind == ReentrancyKind::Classic && !r.guarded));
    }

    #[test]
    fn guard_suppresses() {
        let (scir, facts) = analyze(
            r#"
            contract Bank is ReentrancyGuard {
                mapping(address => uint256) balances;
                function withdraw() external nonReentrant {
                    (bool ok,) = msg.sender.call{value: balances[msg.sender]}("");
                    balances[msg.sender] = 0;
                }
            }
            "#,
        );
        let w = scir.all_functions().find(|f| f.name == "withdraw").unwrap();
        assert!(facts.reentrancy_of(w.id).all(|r| r.guarded));
    }
}
