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
    /// True iff the path that produced this risk contains at least one genuine
    /// reentrancy-capable external / low-level call (`.call`/`.delegatecall`/a
    /// non-view interface call/`.transfer`/`.send`). For `Classic`/`CrossFunction`
    /// this is the flagged function's own call; for `ReadOnly` it reflects the
    /// *mutating writer* path that seeded the getter. A risk with this set to
    /// `false` must never be reported — a function whose effects contain no
    /// external/low-level call site cannot be reentered.
    pub backed_by_call: bool,
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
        // Project-wide view/pure method names — external calls to these are reads,
        // not re-entry vectors (computed once for the whole module).
        let view_methods = module_view_methods(scir);
        for c in scir.iter_contracts() {
            let contract_has_lock = c.inherits_like("reentrancyguard") || c.inherits_like("reentrant");

            // Map storage var -> view getters that read it (for read-only reentrancy).
            let view_readers = view_readers_of(scir, c.id);
            // Trusted call targets: immutable/constant + governance infra
            // (`trusted_targets`) AND the contract's own no-arg view/pure getters
            // (`weth()`, `optimismPortal()`), which dispatch off in-protocol
            // immutable addresses rather than attacker-controlled ones.
            let trusted = reentrancy_trusted_targets(scir, c.id);

            for f in scir.functions_of(c.id) {
                // Constructors run once at deploy and modifiers are analyzed via
                // their host functions — neither is a reentrancy entry point.
                if !f.has_body || f.is_constructor() || f.is_modifier() {
                    continue;
                }
                let guarded = function_has_lock(f) || contract_has_lock;

                let first_ext = first_reentrant_call(f, &trusted, &view_methods);
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
                    // A qualifying post-call state update: a write whose position
                    // index is STRICTLY GREATER than the external call's index
                    // (`w.order > first`) AND whose variable was read before the
                    // call (its stale value is what re-entry corrupts). A write
                    // that PRECEDES the call (`w.order <= first`, e.g.
                    // `proposal.executed = true;` before a timelock call) is the
                    // safe checks-effects-interactions shape and must NEVER be
                    // treated as the vulnerable post-call update. If no such write
                    // exists, there is nothing an attacker can corrupt by
                    // re-entering, so no classic risk is recorded at all.
                    let vars_after: Vec<String> = f
                        .effects
                        .storage_writes
                        .iter()
                        .filter(|w| w.order > first && reads_before.contains(w.var.as_str()))
                        .map(|w| w.var.clone())
                        .collect();
                    if !vars_after.is_empty() {
                        // `first` is, by construction, the order of a genuine
                        // reentrancy-capable, non-trusted external/low-level call
                        // (see `first_reentrant_call`), so this risk is backed by a
                        // real re-entry vector.
                        facts.reentrancy.push(ReentrancyRisk {
                            function: f.id,
                            contract: c.id,
                            kind: ReentrancyKind::Classic,
                            guarded,
                            vars_written_after: dedup(vars_after.clone()),
                            backed_by_call: true,
                            span: f.span,
                        });

                        // Read-only reentrancy: a value/price-like view getter reads
                        // one of the vars this mutating path updates AFTER its real
                        // external call. The re-entry vector lives on THIS writer
                        // path (which has a genuine call), not in the getter, so the
                        // read-only risk is `backed_by_call: true` even though the
                        // getter itself makes no external call.
                        for v in &vars_after {
                            if let Some(getters) = view_readers.get(v) {
                                if let Some(getter) = getters.first() {
                                    facts.reentrancy.push(ReentrancyRisk {
                                        function: *getter,
                                        contract: c.id,
                                        kind: ReentrancyKind::ReadOnly,
                                        guarded: false, // view fns are typically unguarded
                                        vars_written_after: vec![v.clone()],
                                        backed_by_call: true,
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
            detect_cross_function(scir, c.id, &mut facts, &view_methods);
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
fn is_reentrancy_capable(cs: &sluice_ir::CallSite, view_methods: &FxHashSet<String>) -> bool {
    match cs.kind {
        CallKind::LowLevelCall | CallKind::DelegateCall | CallKind::Send | CallKind::Transfer => true,
        // A non-view external method call can run attacker code; a view read cannot.
        // `view_methods` adds the project's own view/pure-declared method names
        // (resolved from interfaces/contracts) to the built-in view list, so a call
        // like `gOHM.balanceFrom(x)` or `treasury.baseSupply()` is recognized as a
        // staticcall-equivalent read and does not count as a re-entry vector.
        CallKind::External => {
            cs.sends_value
                || !(is_view_method(cs.func_name.as_deref())
                    || cs.func_name.as_deref().map(|n| view_methods.contains(n)).unwrap_or(false))
        }
        // staticcall is read-only by construction.
        CallKind::StaticCall => false,
        _ => false,
    }
}

/// Method names declared `view`/`pure` anywhere in the module, MINUS any name
/// also declared state-mutating somewhere (kept conservative to avoid silencing a
/// genuinely mutating call that happens to share a name). Used to recognize
/// external calls to project-defined view functions as non-reentrant.
fn module_view_methods(scir: &Scir) -> FxHashSet<String> {
    let mut view: FxHashSet<String> = FxHashSet::default();
    let mut mutating: FxHashSet<String> = FxHashSet::default();
    for f in scir.all_functions() {
        if f.is_modifier() || f.is_constructor() {
            continue;
        }
        if f.is_view_or_pure() {
            view.insert(f.name.clone());
        } else if f.is_state_mutating() {
            mutating.insert(f.name.clone());
        }
    }
    view.difference(&mutating).cloned().collect()
}

/// Order of the first reentrancy-capable external call in a function, ignoring
/// calls to `trusted` (immutable/constant) target addresses. An immutable target
/// is set once at construction (WETH, a router, an in-protocol module) and is not
/// an attacker-controlled re-entry vector — though value-sending and low-level
/// calls are still counted regardless of target.
fn first_reentrant_call(
    f: &Function,
    trusted: &FxHashSet<String>,
    view_methods: &FxHashSet<String>,
) -> Option<u32> {
    f.effects
        .call_sites
        .iter()
        .filter(|cs| is_reentrancy_capable(cs, view_methods) && !is_trusted_external(cs, trusted))
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
pub fn target_root(target: &str) -> &str {
    target
        .split(|c: char| c == '.' || c == '(' || c == '[' || c == ' ')
        .next()
        .unwrap_or(target)
}

/// State variables that are trusted call targets — calls to them (when the call
/// is a plain, non-value, non-token-transfer external method invocation, see
/// `is_trusted_external`) are not attacker-controlled re-entry vectors. Two
/// sources of trust:
///   1. `immutable`/`constant` address vars: wired once at construction (WETH, a
///      router, an in-protocol module) and never reassignable.
///   2. Owner/governance-set protocol infrastructure: an address-typed var whose
///      NAME matches a well-known trusted-component pattern (`distributor`,
///      `treasury`, `timelock`, `veFXS`, a `gauge`/`minter`/`staking` module,
///      etc.). These are set by privileged setters to in-protocol contracts, so a
///      method call into them is not an open re-entry surface. This is the
///      `harvest`-calls-`distributor`/`treasury` false-positive class.
/// Mapping/array/numeric vars are never trusted targets (they are not addresses).
pub fn trusted_targets(scir: &Scir, cid: ContractId) -> FxHashSet<String> {
    scir.contract(cid)
        .map(|c| {
            c.state_vars
                .iter()
                .filter(|v| v.immutable || v.constant || is_trusted_infra_var(v))
                .map(|v| v.name.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// True for an address/interface-typed state var whose name reads like a piece of
/// owner/governance-configured protocol infrastructure (a module the protocol
/// itself deploys/sets, not an end-user-supplied address). Used to extend the
/// trusted-target set beyond `immutable`/`constant`.
fn is_trusted_infra_var(v: &sluice_ir::StateVar) -> bool {
    // Must be address-like: an explicit `address`, or a custom/interface type
    // (capitalized type name, e.g. `ITreasury`, `IDistributor`). Exclude
    // mappings, arrays, and value types — those are never call targets.
    let ty = v.ty.trim();
    let address_like = ty == "address"
        || ty == "address payable"
        || (!v.is_mapping()
            && !ty.contains('[')
            && !v.is_scalar_numeric()
            && !ty.starts_with("string")
            && !ty.starts_with("bytes")
            && ty.chars().next().map(|c| c.is_ascii_uppercase()).unwrap_or(false));
    if !address_like {
        return false;
    }
    let n = v.name.trim_start_matches('_').to_ascii_lowercase();
    const TRUSTED_INFRA: &[&str] = &[
        "distributor",
        "treasury",
        "vefxs",
        "vefx",
        "timelock",
        "staking",
        "gauge",
        "minter",
        "rewarder",
        "rewards",
        "controller",
        "comptroller",
        "registry",
        "router",
        "factory",
        "vault",
        "module",
        "kernel",
        "authority",
        "governor",
        "governance",
    ];
    TRUSTED_INFRA.iter().any(|k| n.contains(k))
}

/// Same-contract NO-ARG `view`/`pure` getter names. A call whose target *root*
/// is one of these (e.g. `weth().unlock(...)`, `optimismPortal().ethLockbox()`)
/// dispatches off a value computed by an in-contract getter that returns an
/// immutable / `clones-with-immutable-args` / fixed-storage address — it is the
/// protocol's own wired module, not an attacker-controlled address. Treating the
/// getter root as a trusted call target (alongside `trusted_targets`) removes the
/// `claimCredit`-shape false positive where a write follows a `weth().withdraw()`
/// call. Restricted to ZERO-parameter getters so that an attacker-parameterized
/// lookup (`getPool(userToken)`) is never trusted on this basis. As with
/// `is_trusted_external`, this only ever discounts a plain, non-value,
/// non-token-transfer call — value-bearing and ERC-20/777 transfer calls stay
/// reentrancy-capable regardless of how the receiver was obtained.
pub fn view_getter_targets(scir: &Scir, cid: ContractId) -> FxHashSet<String> {
    scir.functions_of(cid)
        .filter(|f| f.is_view_or_pure() && f.params.is_empty() && !f.is_modifier())
        .map(|f| f.name.clone())
        .collect()
}

/// The full set of trusted call-target roots for reentrancy reasoning: the
/// owner/governance/immutable `trusted_targets` plus the same-contract no-arg
/// view/pure getter names (`view_getter_targets`). Shared by the frontier and the
/// reentrancy detector so both agree on which callees are in-protocol.
pub fn reentrancy_trusted_targets(scir: &Scir, cid: ContractId) -> FxHashSet<String> {
    let mut t = trusted_targets(scir, cid);
    t.extend(view_getter_targets(scir, cid));
    t
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

fn detect_cross_function(
    scir: &Scir,
    cid: ContractId,
    facts: &mut FrontierFacts,
    view_methods: &FxHashSet<String>,
) {
    // Collect (function, vars-written-after-call, guarded) for functions with
    // an external call that is NOT followed by their own write (so classic
    // doesn't fire) but leaves shared state for siblings.
    let funcs: Vec<&Function> = scir.functions_of(cid).filter(|f| f.has_body).collect();
    let trusted = reentrancy_trusted_targets(scir, cid);
    for f in &funcs {
        // Cross-function reentrancy is about an EXTERNAL entry point leaving
        // shared state mid-call; internal helpers and constructors are not entry
        // points an attacker calls directly. A `view`/`pure` function is also
        // never the leaving-state vector: it WRITES nothing, so re-entering a
        // sibling cannot find it mid-write. (A value getter that merely *exposes*
        // mid-update state is read-only reentrancy, handled separately and gated
        // on `is_value_oracle_getter`.) Flagging every `view` getter that happens
        // to read a shared var and make an interface call was the dominant
        // cross-function false-positive source on real code.
        if !f.is_externally_reachable() || f.is_constructor() || f.is_view_or_pure() {
            continue;
        }
        let Some(first) = first_reentrant_call(f, &trusted, view_methods) else {
            continue;
        };
        if function_has_lock(f) {
            continue;
        }
        // The real cross-function pattern: f READS a shared var before its
        // external call (and relies on that value afterwards), and a sibling can
        // WRITE that var during the re-entry, invalidating f's stale read. We key
        // on reads-before-call (not arbitrary touches) — a var f merely writes
        // before the call, or only reads after, is not this bug, and counting
        // those was the dominant cross-function false-positive source.
        let touched: Vec<&str> = f
            .effects
            .storage_reads
            .iter()
            .filter(|a| a.order < first)
            .map(|a| a.var.as_str())
            .collect();
        if touched.is_empty() {
            continue;
        }
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
                    // `first` came from `first_reentrant_call`, so `f` makes a
                    // genuine reentrancy-capable external/low-level call.
                    backed_by_call: true,
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

    // A no-arg view/pure getter (`weth()`) is an in-protocol immutable module: a
    // plain call dispatched off it must NOT arm classic reentrancy even when a
    // value-state write follows it. (Optimism `FaultDisputeGame.claimCredit`
    // shape: writes `refundModeCredit`/`normalModeCredit` after `weth().unlock`.)
    #[test]
    fn getter_dispatched_call_is_trusted() {
        let (scir, facts) = analyze(
            r#"
            interface IWETH { function unlock(address a, uint256 v) external; }
            contract Game {
                mapping(address => uint256) public refundModeCredit;
                function weth() public pure returns (IWETH) { return IWETH(address(1)); }
                function claimCredit(address r) external {
                    uint256 c = refundModeCredit[r];   // read before
                    weth().unlock(r, c);               // call dispatched off a no-arg getter
                    refundModeCredit[r] = 0;           // value write after — but trusted callee
                }
            }
            "#,
        );
        let f = scir.all_functions().find(|f| f.name == "claimCredit").unwrap();
        assert!(
            !facts.reentrancy_of(f.id).any(|r| r.kind == ReentrancyKind::Classic),
            "a write after a no-arg-getter-dispatched call must not record classic reentrancy"
        );
    }

    // A `view`/`pure` function that reads a shared var and makes an interface call
    // writes nothing, so it can never be the cross-function "leaves state mid-call"
    // vector. (Optimism `GasPriceOracle.scalar`, `ProxyAdmin.getProxyImplementation`
    // shape.) The mutating sibling shares the var, but only the read-only lens (a
    // value-oracle getter) applies — never cross-function.
    #[test]
    fn view_getter_not_cross_function() {
        let (scir, facts) = analyze(
            r#"
            interface IL1 { function feeData() external returns (uint256); }
            contract Oracle {
                bool public isEcotone;
                function configure(bool e) external { isEcotone = e; }   // mutating sibling
                function scalar() public view returns (uint256) {
                    if (isEcotone) { return IL1(address(2)).feeData(); }  // reads shared var + call
                    return 0;
                }
            }
            "#,
        );
        let f = scir.all_functions().find(|f| f.name == "scalar").unwrap();
        assert!(
            !facts.reentrancy_of(f.id).any(|r| r.kind == ReentrancyKind::CrossFunction),
            "a view/pure getter must not be flagged as the cross-function reentrancy vector"
        );
    }
}
