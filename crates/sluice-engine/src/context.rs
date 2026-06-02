//! The analysis context handed to every detector: the IR plus the three
//! prepared analysis dimensions, with convenience and false-positive-suppression
//! helpers.

use sluice_config::Config;
use sluice_dataflow::{DataflowFacts, ProvenanceSet};
use sluice_findings::{Category, Finding, FindingBuilder};
use sluice_frontier::FrontierFacts;
use sluice_invariant::InvariantFacts;
use sluice_ir::{Contract, ContractId, Expr, Function, FunctionId, GuardKind, Scir, Span};

pub struct AnalysisContext<'a> {
    pub scir: &'a Scir,
    pub dataflow: &'a DataflowFacts,
    pub invariants: &'a InvariantFacts,
    pub frontier: &'a FrontierFacts,
    pub config: &'a Config,
}

impl<'a> AnalysisContext<'a> {
    // -------- iteration helpers --------

    pub fn functions(&self) -> impl Iterator<Item = &Function> {
        self.scir.all_functions()
    }

    /// Externally-reachable, state-mutating functions with a body (the usual
    /// attack surface).
    pub fn entry_points(&self) -> impl Iterator<Item = &Function> {
        self.scir
            .all_functions()
            .filter(|f| f.has_body && f.is_externally_reachable() && f.is_state_mutating())
    }

    pub fn contract_of(&self, fid: FunctionId) -> Option<&Contract> {
        self.scir.function(fid).and_then(|f| self.scir.contract(f.contract))
    }

    /// `(contract_name, function_name)` for a function id.
    pub fn names(&self, fid: FunctionId) -> (String, String) {
        match self.scir.function(fid) {
            Some(f) => (
                self.scir.contract(f.contract).map(|c| c.name.clone()).unwrap_or_default(),
                f.name.clone(),
            ),
            None => (String::new(), String::new()),
        }
    }

    // -------- finding construction --------

    pub fn report(&self, detector: &dyn crate::detector::Detector, category: Category) -> FindingBuilder {
        FindingBuilder::new(detector.id(), category)
    }

    /// Finalize a builder, resolving location from a function id + span.
    pub fn finish(&self, b: FindingBuilder, fid: FunctionId, span: Span) -> Finding {
        let (c, f) = self.names(fid);
        b.at(self.scir, c, f, span).build()
    }

    // -------- value-flow queries --------

    pub fn provenance_of(&self, fid: FunctionId, e: &Expr) -> ProvenanceSet {
        self.dataflow.provenance_of(self.scir, fid, e)
    }
    pub fn is_attacker_controlled(&self, fid: FunctionId, e: &Expr) -> bool {
        self.dataflow.is_attacker_controlled(self.scir, fid, e)
    }
    pub fn is_price_like(&self, fid: FunctionId, e: &Expr) -> bool {
        self.dataflow.is_price_like(self.scir, fid, e)
    }

    // -------- false-positive-suppression helpers --------

    /// True if a function is protected against reentrancy (lock modifier or the
    /// contract inherits a reentrancy-guard mixin).
    pub fn has_reentrancy_guard(&self, f: &Function) -> bool {
        if f.effects.guards.iter().any(|g| matches!(g.kind, GuardKind::ReentrancyLock)) {
            return true;
        }
        self.contract_inherits(f.contract, "reentrancyguard") || self.contract_inherits(f.contract, "reentrant")
    }

    /// True if a function enforces access control (auth modifier or msg.sender check).
    pub fn has_access_control(&self, f: &Function) -> bool {
        f.effects
            .guards
            .iter()
            .any(|g| matches!(g.kind, GuardKind::MsgSenderCheck))
    }

    pub fn is_initializer(&self, f: &Function) -> bool {
        f.effects.guards.iter().any(|g| matches!(g.kind, GuardKind::Initializer))
    }

    /// Contract (or any base, by name match) uses SafeERC20.
    pub fn uses_safe_erc20(&self, cid: ContractId) -> bool {
        match self.scir.contract(cid) {
            Some(c) => c.uses_library_like("safeerc20") || c.inherits_like("safeerc20"),
            None => false,
        }
    }

    /// Contract inherits a base whose name contains `needle` (case-insensitive).
    pub fn contract_inherits(&self, cid: ContractId, needle: &str) -> bool {
        self.scir.contract(cid).map(|c| c.inherits_like(needle)).unwrap_or(false)
    }

    /// True if the function (or contract) appears to use a robust oracle
    /// (Chainlink-style) — used to suppress spot-price oracle findings.
    pub fn uses_robust_oracle(&self, f: &Function) -> bool {
        f.effects.call_sites.iter().any(|c| {
            matches!(
                c.func_name.as_deref(),
                Some("latestRoundData") | Some("latestAnswer") | Some("getRoundData")
            )
        }) || f
            .effects
            .internal_calls
            .iter()
            .any(|n| n.to_ascii_lowercase().contains("chainlink") || n.to_ascii_lowercase().contains("oracle"))
    }
}
