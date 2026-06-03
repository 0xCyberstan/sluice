//! # sluice-dataflow
//!
//! Value-flow **provenance** analysis — the smart-contract analog of `vortex`'s
//! entropy domain. Instead of a boolean "tainted" bit, every value carries a set
//! of [`sluice_ir::ValueSource`] labels describing *where it came from*:
//! attacker input, an external-call return, a manipulable spot price, the block
//! environment, contract storage, or a constant. This lets a detector ask "does
//! a *price-like* value reach this collateral calculation?" rather than merely
//! "is it tainted?".
//!
//! The baseline is flow-insensitive per function with an interprocedural
//! return-provenance fixpoint over the whole module (callee returns refine
//! caller flows). Sound as an over-approximation for reachability.

use rustc_hash::{FxHashMap, FxHashSet};
use sluice_ir::{
    Builtin, Call, CallKind, Expr, ExprKind, Function, FunctionId, GuardKind, Lit, Scir, ValueSource,
};

const MAX_ROUNDS: usize = 6;
const MAX_LOCAL_ITERS: usize = 8;

/// A set of provenance labels (bitset over [`ValueSource`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProvenanceSet(u16);

mod bits {
    pub const ATTACKER: u16 = 1 << 0;
    pub const MSG_SENDER: u16 = 1 << 1;
    pub const MSG_VALUE: u16 = 1 << 2;
    pub const TX_ORIGIN: u16 = 1 << 3;
    pub const EXTERNAL_RETURN: u16 = 1 << 4;
    pub const PRICE_LIKE: u16 = 1 << 5;
    pub const BLOCK_ENV: u16 = 1 << 6;
    pub const STORAGE: u16 = 1 << 7;
    pub const CONSTANT: u16 = 1 << 8;
    pub const UNKNOWN: u16 = 1 << 9;
}

fn bit_of(s: ValueSource) -> u16 {
    match s {
        ValueSource::AttackerInput => bits::ATTACKER,
        ValueSource::MsgSender => bits::MSG_SENDER,
        ValueSource::MsgValue => bits::MSG_VALUE,
        ValueSource::TxOrigin => bits::TX_ORIGIN,
        ValueSource::ExternalReturn => bits::EXTERNAL_RETURN,
        ValueSource::PriceLike => bits::PRICE_LIKE,
        ValueSource::BlockEnv => bits::BLOCK_ENV,
        ValueSource::StorageState => bits::STORAGE,
        ValueSource::Constant => bits::CONSTANT,
        ValueSource::Unknown => bits::UNKNOWN,
    }
}

impl ProvenanceSet {
    pub fn empty() -> Self {
        ProvenanceSet(0)
    }
    pub fn of(s: ValueSource) -> Self {
        ProvenanceSet(bit_of(s))
    }
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub fn contains(self, s: ValueSource) -> bool {
        self.0 & bit_of(s) != 0
    }
    pub fn with(mut self, s: ValueSource) -> Self {
        self.0 |= bit_of(s);
        self
    }
    pub fn union(self, other: Self) -> Self {
        ProvenanceSet(self.0 | other.0)
    }
    pub fn union_in(&mut self, other: Self) -> bool {
        let before = self.0;
        self.0 |= other.0;
        self.0 != before
    }

    /// Controlled directly or indirectly by an external actor.
    pub fn is_attacker_controlled(self) -> bool {
        self.0 & (bits::ATTACKER | bits::MSG_SENDER | bits::MSG_VALUE | bits::TX_ORIGIN) != 0
    }
    /// Derives from a manipulable spot-price source.
    pub fn is_price_like(self) -> bool {
        self.0 & bits::PRICE_LIKE != 0
    }
    /// Flows from outside the contract's own trusted state.
    pub fn is_externally_influenced(self) -> bool {
        self.0
            & (bits::ATTACKER
                | bits::MSG_SENDER
                | bits::MSG_VALUE
                | bits::EXTERNAL_RETURN
                | bits::PRICE_LIKE
                | bits::BLOCK_ENV)
            != 0
    }
    pub fn is_block_env(self) -> bool {
        self.0 & bits::BLOCK_ENV != 0
    }
}

/// Per-function flow facts.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FnFlow {
    /// Variable name → provenance (flow-insensitive union).
    pub var_prov: FxHashMap<String, ProvenanceSet>,
    /// Provenance of the function's return value(s).
    pub return_prov: ProvenanceSet,
    /// Variables that were range/bounds-checked by a guard (`require(x < n)`).
    pub guarded_vars: FxHashSet<String>,
}

/// Module-wide dataflow facts.
#[derive(Debug, Clone, Default)]
pub struct DataflowFacts {
    per_fn: FxHashMap<FunctionId, FnFlow>,
    /// Provenance flowing INTO each function's parameters from its callers
    /// (interprocedural argument propagation). Index i is parameter i.
    param_in: FxHashMap<FunctionId, Vec<ProvenanceSet>>,
}

impl DataflowFacts {
    /// Run the analysis over a whole module.
    pub fn analyze(scir: &Scir) -> Self {
        let mut facts = DataflowFacts::default();

        // Precompute internal call edges once: (caller, callee, arg expressions).
        // This is what lets attacker-controlled arguments flow INTO internal
        // helper parameters, so bugs in helpers reachable from an external entry
        // point are no longer invisible.
        let edges = internal_call_edges(scir);

        // Seed local flows (internal-call returns + param_in unknown initially).
        for f in scir.all_functions() {
            facts.per_fn.insert(f.id, build_flow(scir, f, &facts));
        }

        // Joint fixpoint over return-provenance AND parameter-provenance.
        for _ in 0..MAX_ROUNDS {
            let snapshot = facts.clone();

            // (a) Recompute incoming parameter provenance from caller arguments.
            facts.param_in = compute_param_in(scir, &snapshot, &edges);

            // (b) Recompute flows: callee returns from the snapshot, parameter
            //     seeds from the freshly-computed param_in.
            let mut new_per_fn: FxHashMap<FunctionId, FnFlow> = FxHashMap::default();
            for f in scir.all_functions() {
                new_per_fn.insert(f.id, build_flow(scir, f, &facts));
            }

            let changed = new_per_fn != snapshot.per_fn || facts.param_in != snapshot.param_in;
            facts.per_fn = new_per_fn;
            if !changed {
                break;
            }
        }
        facts
    }

    pub fn flow(&self, fid: FunctionId) -> Option<&FnFlow> {
        self.per_fn.get(&fid)
    }

    /// Evaluate the provenance of an expression within a function.
    pub fn provenance_of(&self, scir: &Scir, fid: FunctionId, e: &Expr) -> ProvenanceSet {
        let empty = FnFlow::default();
        let flow = self.per_fn.get(&fid).unwrap_or(&empty);
        eval(self, scir, fid, flow, e)
    }

    pub fn is_attacker_controlled(&self, scir: &Scir, fid: FunctionId, e: &Expr) -> bool {
        self.provenance_of(scir, fid, e).is_attacker_controlled()
    }
    pub fn is_price_like(&self, scir: &Scir, fid: FunctionId, e: &Expr) -> bool {
        self.provenance_of(scir, fid, e).is_price_like()
    }
}

/// Manipulable spot-price source method names (excludes robust oracles like
/// Chainlink's `latestRoundData`, which the oracle detector treats separately).
pub const SPOT_PRICE_FUNCS: &[&str] = &[
    "getReserves",
    "getReserve",
    "getAmountOut",
    "getAmountsOut",
    "getAmountIn",
    "getAmountsIn",
    "slot0",
    "pricePerShare",
    "getPricePerFullShare",
    "get_virtual_price",
    "getVirtualPrice",
    // generic instantaneous price reads (a Chainlink-style robust feed is
    // suppressed separately by the oracle detector's `uses_robust_oracle` check)
    "getPrice",
    "getCurrentPrice",
    "currentPrice",
    "latestPrice",
    "getSpotPrice",
    "spotPrice",
];

/// Is this call a price read we treat as *manipulable within a transaction*?
///
/// Deliberately excludes ERC-4626 standard accounting (`totalAssets`,
/// `convertToAssets`/`Shares`) and generic `quote`/`getRate`/`exchangeRate`,
/// which are not necessarily manipulable external spot prices — including them
/// produced oracle false positives on legitimate vaults.
pub fn is_spot_price_call(c: &Call) -> bool {
    match &c.func_name {
        Some(n) if n == "balanceOf" => {
            // `balanceOf(<pool>)` used as a value is the canonical manipulable
            // read — but `balanceOf(address(this))` / `balanceOf(msg.sender)` is a
            // contract reading its OWN holdings (an audit/accounting read), not an
            // external price, and cannot be flash-loan-moved against itself.
            !balance_of_self_or_sender(c)
        }
        Some(n) => SPOT_PRICE_FUNCS.contains(&n.as_str()),
        None => false,
    }
}

/// True if a `balanceOf(...)` call's argument is `address(this)` / `this` /
/// `msg.sender` (an own-balance read, not a pool spot price).
fn balance_of_self_or_sender(c: &Call) -> bool {
    let Some(arg) = c.args.first() else { return false };
    match &arg.kind {
        // `address(this)` / `address(msg.sender)` — a TypeCast over this/sender.
        ExprKind::Call(inner) if inner.kind == CallKind::TypeCast => inner
            .args
            .first()
            .map(|a| is_this_or_sender(a))
            .unwrap_or(false),
        _ => is_this_or_sender(arg),
    }
}

fn is_this_or_sender(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Ident(n) => n == "this",
        ExprKind::Member { base, member } => {
            member == "sender" && matches!(&base.kind, ExprKind::Ident(b) if b == "msg")
        }
        _ => false,
    }
}

// ------------------------------------------------------------------ internals

fn build_flow(scir: &Scir, f: &Function, facts: &DataflowFacts) -> FnFlow {
    let mut flow = FnFlow::default();

    // Seed parameters. Externally-reachable functions are entry points, so their
    // parameters are attacker-controlled. Internal/private functions inherit the
    // provenance their callers pass in (interprocedural), defaulting to Unknown
    // when no caller is known yet.
    // A function gated by an access-control guard (onlyOwner / onlyRole /
    // require(msg.sender == ...)) can only be called by a trusted privileged
    // actor, so its parameters are NOT arbitrary attacker input. Treating them as
    // attacker-controlled produced large false-positive volume on admin/governor
    // setters across real protocols. Such functions are taint-seeded like internal
    // ones (from caller args, else Unknown).
    let attacker = f.is_externally_reachable() && !is_access_controlled(f);
    let incoming = facts.param_in.get(&f.id);
    for (i, p) in f.params.iter().enumerate() {
        if let Some(name) = &p.name {
            let prov = if attacker {
                ProvenanceSet::of(ValueSource::AttackerInput)
            } else {
                incoming
                    .and_then(|v| v.get(i))
                    .copied()
                    .filter(|p| !p.is_empty())
                    .unwrap_or_else(|| ProvenanceSet::of(ValueSource::Unknown))
            };
            flow.var_prov.insert(name.clone(), prov);
        }
    }

    // Collect assignments and guard checks via a body walk, iterating to a local
    // fixpoint (a var may be assigned from a later/looped var).
    let assigns = collect_assignments(&f.body);
    collect_guards(&f.body, &mut flow.guarded_vars);

    for _ in 0..MAX_LOCAL_ITERS {
        let mut changed = false;
        for (var, rhs) in &assigns {
            let p = eval(facts, scir, f.id, &flow, rhs);
            let entry = flow.var_prov.entry(var.clone()).or_insert_with(ProvenanceSet::empty);
            if entry.union_in(p) {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // Return provenance.
    let mut ret = ProvenanceSet::empty();
    visit_returns(&f.body, &mut |e| {
        ret = ret.union(eval(facts, scir, f.id, &flow, e));
    });
    // Named return parameters contribute their provenance too.
    for p in &f.returns {
        if let Some(name) = &p.name {
            if let Some(pr) = flow.var_prov.get(name) {
                ret = ret.union(*pr);
            }
        }
    }
    flow.return_prov = ret;

    flow
}

/// Evaluate the provenance of an expression given a (partial) flow.
fn eval(facts: &DataflowFacts, scir: &Scir, fid: FunctionId, flow: &FnFlow, e: &Expr) -> ProvenanceSet {
    match &e.kind {
        ExprKind::Lit(l) => match l {
            Lit::Address(_) => ProvenanceSet::of(ValueSource::Constant),
            _ => ProvenanceSet::of(ValueSource::Constant),
        },
        ExprKind::Ident(n) => {
            if let Some(p) = flow.var_prov.get(n) {
                *p
            } else if is_state_var(scir, fid, n) {
                ProvenanceSet::of(ValueSource::StorageState)
            } else {
                ProvenanceSet::of(ValueSource::Unknown)
            }
        }
        ExprKind::Member { base, member } => {
            if let ExprKind::Ident(b) = &base.kind {
                match (b.as_str(), member.as_str()) {
                    ("msg", "sender") => return ProvenanceSet::of(ValueSource::MsgSender),
                    ("msg", "value") => return ProvenanceSet::of(ValueSource::MsgValue),
                    ("msg", "data") => return ProvenanceSet::of(ValueSource::AttackerInput),
                    ("tx", "origin") => return ProvenanceSet::of(ValueSource::TxOrigin),
                    (
                        "block",
                        "timestamp" | "number" | "prevrandao" | "difficulty" | "coinbase" | "basefee",
                    ) => return ProvenanceSet::of(ValueSource::BlockEnv),
                    _ => {}
                }
            }
            let base_p = eval(facts, scir, fid, flow, base);
            if root_is_state(scir, fid, base) {
                base_p.with(ValueSource::StorageState)
            } else {
                base_p
            }
        }
        ExprKind::Index { base, index } => {
            let mut p = eval(facts, scir, fid, flow, base);
            if let Some(i) = index {
                let _ = eval(facts, scir, fid, flow, i);
            }
            if root_is_state(scir, fid, base) {
                p = p.with(ValueSource::StorageState);
            }
            p
        }
        ExprKind::Call(c) => eval_call(facts, scir, fid, flow, c),
        ExprKind::Unary { operand, .. } => eval(facts, scir, fid, flow, operand),
        ExprKind::Binary { lhs, rhs, .. } => {
            eval(facts, scir, fid, flow, lhs).union(eval(facts, scir, fid, flow, rhs))
        }
        ExprKind::Ternary { then_e, else_e, .. } => {
            eval(facts, scir, fid, flow, then_e).union(eval(facts, scir, fid, flow, else_e))
        }
        ExprKind::Assign { value, .. } => eval(facts, scir, fid, flow, value),
        ExprKind::Tuple(items) | ExprKind::ArrayLit(items) => {
            let mut p = ProvenanceSet::empty();
            for it in items.iter().flatten() {
                p = p.union(eval(facts, scir, fid, flow, it));
            }
            p
        }
        ExprKind::New(_) => ProvenanceSet::of(ValueSource::Constant),
        ExprKind::TypeName(_) | ExprKind::Unsupported => ProvenanceSet::empty(),
    }
}

fn eval_call(facts: &DataflowFacts, scir: &Scir, fid: FunctionId, flow: &FnFlow, c: &Call) -> ProvenanceSet {
    // Spot-price reads.
    if is_spot_price_call(c) {
        return ProvenanceSet::of(ValueSource::PriceLike).with(ValueSource::ExternalReturn);
    }
    match c.kind {
        CallKind::External | CallKind::LowLevelCall | CallKind::StaticCall => {
            ProvenanceSet::of(ValueSource::ExternalReturn)
        }
        CallKind::DelegateCall => ProvenanceSet::of(ValueSource::ExternalReturn),
        CallKind::TypeCast => c
            .args
            .first()
            .map(|a| eval(facts, scir, fid, flow, a))
            .unwrap_or_else(ProvenanceSet::empty),
        CallKind::Builtin(b) => match b {
            Builtin::Ecrecover => ProvenanceSet::of(ValueSource::AttackerInput),
            Builtin::Keccak256
            | Builtin::Sha256
            | Builtin::AbiEncode
            | Builtin::AbiEncodePacked
            | Builtin::AbiEncodeWithSelector
            | Builtin::AbiEncodeWithSignature
            | Builtin::AbiDecode => {
                let mut p = ProvenanceSet::empty();
                for a in &c.args {
                    p = p.union(eval(facts, scir, fid, flow, a));
                }
                p
            }
            Builtin::Blockhash | Builtin::Gasleft => ProvenanceSet::of(ValueSource::BlockEnv),
            _ => ProvenanceSet::of(ValueSource::Constant),
        },
        CallKind::Internal => {
            // Resolve callee by name and inherit its return provenance.
            if let Some(name) = &c.func_name {
                if let Some(f) = scir.function(fid) {
                    for callee in &f.callees {
                        if scir.function(*callee).map(|c| c.name.as_str()) == Some(name.as_str()) {
                            if let Some(cf) = facts.per_fn.get(callee) {
                                return cf.return_prov;
                            }
                        }
                    }
                }
            }
            ProvenanceSet::of(ValueSource::Unknown)
        }
        CallKind::New | CallKind::Send | CallKind::Transfer | CallKind::Unknown => {
            ProvenanceSet::of(ValueSource::Unknown)
        }
    }
}

/// True if the function is gated by an access-control guard (a `msg.sender`/role
/// check or an auth modifier), so its caller is a trusted privileged actor.
fn is_access_controlled(f: &Function) -> bool {
    f.effects.guards.iter().any(|g| matches!(g.kind, GuardKind::MsgSenderCheck))
}

fn is_state_var(scir: &Scir, fid: FunctionId, name: &str) -> bool {
    let Some(f) = scir.function(fid) else { return false };
    let Some(c) = scir.contract(f.contract) else { return false };
    c.state_vars.iter().any(|v| v.name == name)
}

fn root_is_state(scir: &Scir, fid: FunctionId, e: &Expr) -> bool {
    fn root<'a>(e: &'a Expr) -> Option<&'a str> {
        match &e.kind {
            ExprKind::Ident(n) => Some(n),
            ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root(base),
            _ => None,
        }
    }
    root(e).map(|n| is_state_var(scir, fid, n)).unwrap_or(false)
}

/// Collect `(var, rhs)` for assignments and initialized declarations.
fn collect_assignments(body: &[sluice_ir::Stmt]) -> Vec<(String, Expr)> {
    use sluice_ir::StmtKind;
    let mut out = Vec::new();
    for s in body {
        s.visit(&mut |st| match &st.kind {
            StmtKind::VarDecl { name: Some(n), init: Some(e), .. } => out.push((n.clone(), e.clone())),
            StmtKind::Expr(e) => collect_assign_expr(e, &mut out),
            _ => {}
        });
    }
    out
}

fn collect_assign_expr(e: &Expr, out: &mut Vec<(String, Expr)>) {
    if let ExprKind::Assign { target, value, .. } = &e.kind {
        if let ExprKind::Ident(n) = &target.kind {
            out.push((n.clone(), (**value).clone()));
        }
    }
}

/// Record variables that are range-checked in a `require`/`if` comparison.
fn collect_guards(body: &[sluice_ir::Stmt], guarded: &mut FxHashSet<String>) {
    use sluice_ir::StmtKind;
    for s in body {
        s.visit_exprs(&mut |e| {
            if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
                if op.is_ordering() || matches!(op, sluice_ir::BinOp::Eq | sluice_ir::BinOp::Ne) {
                    if let ExprKind::Ident(n) = &lhs.kind {
                        guarded.insert(n.clone());
                    }
                    if let ExprKind::Ident(n) = &rhs.kind {
                        guarded.insert(n.clone());
                    }
                }
            }
        });
        // Touch StmtKind to keep the import meaningful even if structure changes.
        let _ = std::mem::discriminant(&StmtKind::Break);
    }
}

fn visit_returns(body: &[sluice_ir::Stmt], f: &mut impl FnMut(&Expr)) {
    use sluice_ir::StmtKind;
    for s in body {
        s.visit(&mut |st| {
            if let StmtKind::Return(Some(e)) = &st.kind {
                f(e);
            }
        });
    }
}

/// Internal call edges `(caller, callee, arg-expressions)` for interprocedural
/// argument propagation. Resolves a callee by matching the call's function name
/// against the caller's resolved internal callees (best-effort, first match).
fn internal_call_edges(scir: &Scir) -> Vec<(FunctionId, FunctionId, Vec<Expr>)> {
    let mut edges = Vec::new();
    for f in scir.all_functions() {
        for s in &f.body {
            s.visit_exprs(&mut |e| {
                if let ExprKind::Call(c) = &e.kind {
                    if c.kind == CallKind::Internal {
                        if let Some(name) = &c.func_name {
                            if let Some(callee) = f.callees.iter().copied().find(|cid| {
                                scir.function(*cid).map(|g| g.name.as_str()) == Some(name.as_str())
                            }) {
                                edges.push((f.id, callee, c.args.clone()));
                            }
                        }
                    }
                }
            });
        }
    }
    edges
}

/// Join the provenance of each call argument into the callee's parameter slots.
fn compute_param_in(
    scir: &Scir,
    snapshot: &DataflowFacts,
    edges: &[(FunctionId, FunctionId, Vec<Expr>)],
) -> FxHashMap<FunctionId, Vec<ProvenanceSet>> {
    let mut out: FxHashMap<FunctionId, Vec<ProvenanceSet>> = FxHashMap::default();
    for f in scir.all_functions() {
        out.insert(f.id, vec![ProvenanceSet::empty(); f.params.len()]);
    }
    for (caller, callee, args) in edges {
        let Some(caller_flow) = snapshot.per_fn.get(caller) else { continue };
        let Some(slot) = out.get_mut(callee) else { continue };
        for (i, arg) in args.iter().enumerate() {
            if i < slot.len() {
                let p = eval(snapshot, scir, *caller, caller_flow, arg);
                slot[i] = slot[i].union(p);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sluice_ir::ValueSource;

    fn analyze(src: &str) -> (Scir, DataflowFacts) {
        let scir = sluice_parse::parse_sources(vec![("t.sol".into(), src.into())]).scir;
        let facts = DataflowFacts::analyze(&scir);
        (scir, facts)
    }

    #[test]
    fn interprocedural_arg_provenance() {
        // Attacker input passed into an internal helper must reach the helper's
        // parameter (previously seeded Unknown, hiding bugs in helpers).
        let (scir, facts) = analyze(
            "contract C {
                function entry(uint256 amt) external { _helper(amt); }
                function _helper(uint256 x) internal { uint256 y = x; }
            }",
        );
        let helper = scir.all_functions().find(|f| f.name == "_helper").unwrap();
        let flow = facts.flow(helper.id).unwrap();
        assert!(
            flow.var_prov.get("x").map(|p| p.is_attacker_controlled()).unwrap_or(false),
            "internal helper param should inherit attacker provenance from caller"
        );
    }

    #[test]
    fn param_is_attacker_controlled() {
        let (scir, facts) = analyze(
            "contract C { function f(uint256 amt) external { uint256 x = amt; } }",
        );
        let f = scir.all_functions().find(|f| f.name == "f").unwrap();
        let flow = facts.flow(f.id).unwrap();
        assert!(flow.var_prov.get("x").unwrap().is_attacker_controlled());
    }

    #[test]
    fn balance_of_pool_is_price_like_but_self_is_not() {
        // `balanceOf(pool)` of an external address is a manipulable spot read...
        let (scir, facts) = analyze(
            "contract C { function p(address t, address pool) external returns (uint256) { return IERC20(t).balanceOf(pool); } }",
        );
        let f = scir.all_functions().find(|f| f.name == "p").unwrap();
        assert!(facts.flow(f.id).unwrap().return_prov.contains(ValueSource::PriceLike));

        // ...but `balanceOf(address(this))` is an own-balance read, NOT a price.
        let (scir2, facts2) = analyze(
            "contract C { function q(address t) external returns (uint256) { return IERC20(t).balanceOf(address(this)); } }",
        );
        let g = scir2.all_functions().find(|f| f.name == "q").unwrap();
        assert!(!facts2.flow(g.id).unwrap().return_prov.contains(ValueSource::PriceLike));
    }
}
