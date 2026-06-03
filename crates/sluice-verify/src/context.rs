//! The `PocContext` assembler.
//!
//! One function — [`poc_context`] — resolves everything a template needs from
//! `(Scir, &Finding)` into a single flat struct: the target `Contract`/`Function`,
//! the relative import path computed from `Contract.file`, typed constructor and
//! call argument lists, the balance/asset/owner state vars (lifted name
//! heuristics), the arming call site + post-call written var (reentrancy), and
//! the flagged privileged var (access control). Templates read this; they never
//! touch the IR directly, so the IR-traversal heuristics live in exactly one
//! place.

use sluice_findings::Finding;
use sluice_ir::{CallKind, CallSite, Contract, Function, Mutability, Param, Scir};

/// The honesty tier of an emitted PoC (also recorded in `Finding.tags`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Compiling exploit harness (given the target resolves its own imports).
    T1,
    /// Compiling skeleton with `/* FILL */` constants + a real asserted hypothesis.
    T2,
    /// Trace-annotated stub — not claimed to compile.
    T3,
}

impl Tier {
    pub fn tag(self) -> &'static str {
        match self {
            Tier::T1 => "poc:tier1",
            Tier::T2 => "poc:tier2",
            Tier::T3 => "poc:tier3",
        }
    }

    /// The one-line banner stamped at the top of every emitted PoC so a bounty
    /// submitter never over-claims a skeleton as a green test.
    pub fn banner(self) -> &'static str {
        match self {
            Tier::T1 => "Tier 1 (compiling exploit harness — valid given the target resolves its imports)",
            Tier::T2 => "Tier 2 (compiling skeleton + asserted hypothesis — fill the /* FILL */ constants)",
            Tier::T3 => "Tier 3 (trace-annotated stub — NOT claimed to compile; complete the TODOs)",
        }
    }
}

/// A typed argument: the rendered literal plus whether it is a `/* FILL */`
/// placeholder (interface / complex type we cannot synthesize a real value for).
#[derive(Debug, Clone, PartialEq)]
pub struct TypedArg {
    /// The Solidity literal to emit (`1`, `makeAddr("arg0")`, `address(0)`, `""`).
    pub literal: String,
    /// `true` when the literal is a `/* FILL */` (interface handle / struct / etc.).
    pub needs_fill: bool,
}

/// Everything a template needs, assembled once per finding.
pub struct PocContext<'a> {
    pub finding: &'a Finding,
    pub contract: &'a Contract,
    pub function: &'a Function,
    /// Normalized bare pragma constraint (`^0.8.20`).
    pub pragma: String,
    /// Relative import path from the emitted `test/` dir to the target source.
    pub import_path: String,
    /// Solidity identifier-safe contract name.
    pub contract_ident: String,
    /// Solidity identifier-safe function name.
    pub function_ident: String,
    /// Typed placeholder args for the vulnerable function's params.
    pub call_args: Vec<TypedArg>,
    /// Typed placeholder args for the constructor's params (empty if none/default).
    pub ctor_args: Vec<TypedArg>,
    /// The constructor's params (for the `// constructor: ...` comment).
    pub ctor_params: Vec<Param>,
    /// `true` if the target has a `payable` externally-reachable deposit-like fn.
    pub deposit_fn: Option<String>,
    /// Balance mapping state var (`balances`), if one is identifiable.
    pub balance_var: Option<String>,
    /// The vault asset / token handle state var (`asset`, `token`), if any.
    pub asset_var: Option<String>,
    /// The owner / admin / privileged-address state var, if any.
    pub owner_var: Option<String>,
    /// The arming external call site that re-entrancy would re-enter, if any.
    pub arming_call: Option<CallSite>,
    /// The state var written *after* the external call (the drained var), if any.
    pub drained_var: Option<String>,
    /// The privileged state var the access-control detector flagged.
    pub privileged_var: Option<String>,
    /// `true` if `privileged_var` is publicly readable (auto-getter exists).
    pub privileged_var_public: bool,
    /// The spot-price read method (for oracle templates), if identifiable.
    pub spot_method: Option<String>,
}

impl PocContext<'_> {
    /// Render the call-args list as a comma-joined Solidity argument string.
    pub fn call_args_str(&self) -> String {
        join_args(&self.call_args)
    }
    /// Render the ctor-args list as a comma-joined Solidity argument string.
    pub fn ctor_args_str(&self) -> String {
        join_args(&self.ctor_args)
    }
    /// A human comment describing the constructor params.
    pub fn ctor_comment(&self) -> String {
        if self.ctor_params.is_empty() {
            "constructor: (none / default)".to_string()
        } else {
            let parts: Vec<String> = self
                .ctor_params
                .iter()
                .map(|p| format!("{} {}", p.ty.trim(), p.name.clone().unwrap_or_default()))
                .collect();
            format!("constructor({})", parts.join(", "))
        }
    }
    /// Does the typed call/ctor arg list contain any `/* FILL */` placeholder?
    /// (One of the signals pushing a finding from T1 to T2.)
    pub fn has_fill(&self) -> bool {
        self.ctor_args.iter().any(|a| a.needs_fill) || self.call_args.iter().any(|a| a.needs_fill)
    }
}

fn join_args(args: &[TypedArg]) -> String {
    args.iter().map(|a| a.literal.clone()).collect::<Vec<_>>().join(", ")
}

/// Assemble a [`PocContext`] for a finding. Returns `None` when the finding
/// cannot be anchored to a concrete contract+function in the IR (interface /
/// library targets, or an unresolvable name) — the caller then falls back to the
/// T3 stub.
pub fn poc_context<'a>(scir: &'a Scir, finding: &'a Finding) -> Option<PocContext<'a>> {
    let (contract, function) = resolve(scir, finding)?;

    let pragma = normalize_pragma(scir.pragma_solidity.as_deref());
    let import_path = relative_import_path(scir, contract);

    // Constructor params (typed placeholders).
    let ctor = scir
        .functions_of(contract.id)
        .find(|f| f.is_constructor())
        .cloned();
    let ctor_params = ctor.as_ref().map(|c| c.params.clone()).unwrap_or_default();
    let ctor_args = ctor_params.iter().map(|p| typed_arg(p, scir, contract)).collect();

    let call_args = function.params.iter().map(|p| typed_arg(p, scir, contract)).collect();

    let deposit_fn = find_deposit_fn(scir, contract);
    let balance_var = find_balance_var(contract);
    let asset_var = find_asset_var(contract);
    let owner_var = find_owner_var(contract);

    // Prefer the most plausible re-entry vector (value-bearing / sender-targeted
    // low-level call) over merely the first external call, so the reentrancy
    // template points its hook at the right site.
    let arming_call = function
        .effects
        .call_sites
        .iter()
        .filter(|c| is_reentry_vector(c))
        .min_by_key(|c| c.order)
        .or_else(|| function.effects.first_external_call())
        .cloned();
    let drained_var = drained_after_call(function);

    let privileged_var = privileged_write_var(function, contract);
    let privileged_var_public = privileged_var
        .as_ref()
        .map(|v| state_var_public(contract, v))
        .unwrap_or(false);

    let spot_method = spot_read_method(function);

    Some(PocContext {
        finding,
        contract,
        function,
        pragma,
        import_path,
        contract_ident: sanitize_ident(&contract.name),
        function_ident: sanitize_ident(&function.name),
        call_args,
        ctor_args,
        ctor_params,
        deposit_fn,
        balance_var,
        asset_var,
        owner_var,
        arming_call,
        drained_var,
        privileged_var,
        privileged_var_public,
        spot_method,
    })
}

/// Resolve the `(Contract, Function)` a finding anchors to. Prefers the threaded
/// IR ids; falls back to a `(contract-name, function-name)` scan for findings
/// built without `cx.finish`. Concrete contracts only (interfaces/libraries → `None`).
fn resolve<'a>(scir: &'a Scir, finding: &Finding) -> Option<(&'a Contract, &'a Function)> {
    // Fast path: precise ids threaded by the builder.
    if let (Some(cid), Some(fid)) = (finding.contract_id, finding.function_id) {
        if let (Some(c), Some(f)) = (scir.contract(cid), scir.function(fid)) {
            if c.is_concrete() {
                return Some((c, f));
            }
            return None;
        }
    }
    // Fallback: locate by name (matches the historical `generate_poc` lookup).
    let func = scir.all_functions().find(|f| {
        f.name == finding.function
            && scir.contract(f.contract).map(|c| c.name == finding.contract).unwrap_or(false)
    })?;
    let contract = scir.contract(func.contract)?;
    if !contract.is_concrete() {
        return None;
    }
    Some((contract, func))
}

/// Normalize a pragma directive/range to the bare version constraint.
pub fn normalize_pragma(raw: Option<&str>) -> String {
    let raw = raw.unwrap_or_default();
    let v = raw
        .trim()
        .trim_start_matches("pragma")
        .trim()
        .trim_start_matches("solidity")
        .trim()
        .trim_end_matches(';')
        .trim()
        .to_string();
    if v.is_empty() { "^0.8.20".to_string() } else { v }
}

/// Relative path from the emitted `sluice-poc/test/` dir back to the target
/// source file. The skeleton lives at `<repo>/sluice-poc/test/F-XXX.t.sol`, so a
/// target whose recorded path is absolute/repo-relative is reached via `../../`
/// then the path. We keep it simple and robust: strip a leading `./`, and if the
/// path is absolute, prefix the climb; relative paths are assumed repo-rooted.
pub fn relative_import_path(scir: &Scir, contract: &Contract) -> String {
    let path = scir
        .files
        .get(contract.file as usize)
        .map(|f| f.path.clone())
        .unwrap_or_else(|| format!("{}.sol", contract.name));
    let p = path.trim_start_matches("./").to_string();
    // From `sluice-poc/test/` two levels up reaches the repo root the user runs in.
    if p.starts_with('/') {
        // Absolute on-disk path — still resolvable when the user keeps the file
        // there; emit as-is (forge accepts absolute import paths via remappings,
        // and the README explains pointing remappings at the repo).
        p
    } else {
        format!("../../{p}")
    }
}

// ----------------------------------------------------------------- typed args

/// Map a parameter type to a valid Solidity literal placeholder. Interface and
/// otherwise-unsynthesizable types become a `/* FILL */` (flagged `needs_fill`).
pub fn typed_arg(p: &Param, scir: &Scir, contract: &Contract) -> TypedArg {
    literal_for_type(&p.ty, p.name.as_deref(), scir, contract)
}

fn literal_for_type(ty: &str, name: Option<&str>, scir: &Scir, contract: &Contract) -> TypedArg {
    let t = ty.trim();
    let base = t.split_whitespace().next().unwrap_or(t); // drop `memory`/`calldata`
    let nm = name.unwrap_or("arg");
    // Arrays / mappings → empty/fill.
    if base.ends_with("[]") {
        let elem = base.trim_end_matches("[]");
        return TypedArg {
            literal: format!("new {elem}[](0)"),
            needs_fill: false,
        };
    }
    if base.starts_with("uint") || base.starts_with("int") {
        return TypedArg { literal: "1".to_string(), needs_fill: false };
    }
    if base == "bool" {
        return TypedArg { literal: "false".to_string(), needs_fill: false };
    }
    if base == "address" || base == "addresspayable" || base == "address payable" {
        return TypedArg {
            literal: format!("makeAddr(\"{}\")", sanitize_ident(nm)),
            needs_fill: false,
        };
    }
    if base == "string" {
        return TypedArg { literal: "\"\"".to_string(), needs_fill: false };
    }
    if base == "bytes" {
        return TypedArg { literal: "\"\"".to_string(), needs_fill: false };
    }
    // Fixed-size bytesN → zero literal of that size.
    if let Some(rest) = base.strip_prefix("bytes") {
        if rest.parse::<u32>().is_ok() {
            return TypedArg {
                literal: format!("bytes{rest}(0)"),
                needs_fill: false,
            };
        }
    }
    // Enum declared in the target contract → cast 0 to it (valid first variant).
    if base.starts_with("enum ") {
        let en = base.trim_start_matches("enum ").trim();
        return TypedArg { literal: format!("{en}(0)"), needs_fill: false };
    }
    // A type the *target* contract or this file declares as a contract/interface
    // we cannot instantiate generically → FILL. Interfaces conventionally `I*`.
    let is_known_contract = scir.contract_by_name.contains_key(base);
    let looks_interface = base.starts_with('I') && base.len() > 1 && base.as_bytes()[1].is_ascii_uppercase();
    let _ = contract; // reserved for future contract-local type resolution
    if is_known_contract || looks_interface {
        return TypedArg {
            literal: format!("/* FILL: {base} {nm} */ address(0)"),
            needs_fill: true,
        };
    }
    // Unknown / struct / user type → conservative FILL that still compiles as a
    // comment + a zero address won't (type mismatch), so use a typed zero cast.
    TypedArg {
        literal: format!("/* FILL: {base} {nm} */ {base}(0)"),
        needs_fill: true,
    }
}

// --------------------------------------------------- lifted name heuristics

/// A balance/accounting mapping: `mapping(address => uint*)` whose name reads
/// like a per-account balance/share ledger. (Lifted from the accounting-name
/// heuristics the reentrancy/vault detectors use.)
fn find_balance_var(contract: &Contract) -> Option<String> {
    contract
        .state_vars
        .iter()
        .find(|v| v.is_mapping() && is_accounting_name(&v.name) && maps_to_numeric(&v.ty))
        .map(|v| v.name.clone())
        // Fall back to the first address→uint mapping if no name matched.
        .or_else(|| {
            contract
                .state_vars
                .iter()
                .find(|v| v.is_mapping() && maps_to_numeric(&v.ty) && v.ty.contains("address"))
                .map(|v| v.name.clone())
        })
}

/// The vault asset / token handle: a state var typed as an `I*ERC20`-ish
/// interface or named `asset`/`token`/`underlying`.
fn find_asset_var(contract: &Contract) -> Option<String> {
    contract
        .state_vars
        .iter()
        .find(|v| {
            let n = v.name.to_ascii_lowercase();
            let t = v.ty.to_ascii_lowercase();
            n == "asset"
                || n == "token"
                || n == "underlying"
                || n.ends_with("token")
                || t.contains("erc20")
        })
        .map(|v| v.name.clone())
}

/// The owner / admin privileged-address var.
fn find_owner_var(contract: &Contract) -> Option<String> {
    contract
        .state_vars
        .iter()
        .find(|v| {
            let n = v.name.to_ascii_lowercase();
            v.ty.trim() == "address"
                && (n == "owner" || n == "admin" || n.contains("owner") || n.contains("admin") || n == "governance")
        })
        .map(|v| v.name.clone())
}

/// An externally-reachable, payable, deposit-shaped function (so the reentrancy
/// harness can credit the attacker before re-entering).
fn find_deposit_fn(scir: &Scir, contract: &Contract) -> Option<String> {
    scir.functions_of(contract.id)
        .find(|f| {
            f.is_externally_reachable()
                && matches!(f.mutability, Mutability::Payable)
                && {
                    let n = f.name.to_ascii_lowercase();
                    n.contains("deposit") || n.contains("stake") || n.contains("mint") || f.name.is_empty()
                }
        })
        .map(|f| f.name.clone())
}

/// The first state var written *after* the function's first external call — the
/// drained/clobbered var that a checks-effects-interactions violation exposes.
fn drained_after_call(function: &Function) -> Option<String> {
    let first = function.effects.first_external_call()?;
    function
        .effects
        .storage_writes
        .iter()
        .filter(|w| w.order > first.order)
        .min_by_key(|w| w.order)
        .map(|w| w.var.clone())
}

/// The privileged state var an access-control finding flags: the first state var
/// the function writes (the detector localizes this; we recover it from effects).
fn privileged_write_var(function: &Function, contract: &Contract) -> Option<String> {
    // Prefer a written var that looks privileged (owner/admin/role/paused/...).
    function
        .effects
        .written_vars()
        .into_iter()
        .find(|v| is_privileged_name(v))
        .map(|s| s.to_string())
        .or_else(|| {
            // else the owner var if the function writes it, else the first write.
            function
                .effects
                .storage_writes
                .iter()
                .min_by_key(|w| w.order)
                .map(|w| w.var.clone())
        })
        .filter(|v| contract.state_vars.iter().any(|sv| &sv.name == v))
}

/// The spot-price read method for oracle templates (`getReserves`,
/// `balanceOf`, `price`, ...) — best-effort from call-site method names.
fn spot_read_method(function: &Function) -> Option<String> {
    function.effects.call_sites.iter().find_map(|c| {
        let m = c.func_name.as_deref()?;
        let ml = m.to_ascii_lowercase();
        if ml.contains("price")
            || ml.contains("reserve")
            || ml == "balanceof"
            || ml.contains("rate")
            || ml.contains("answer")
        {
            Some(m.to_string())
        } else {
            None
        }
    })
}

/// Is a state var externally readable (public auto-getter / public visibility)?
fn state_var_public(contract: &Contract, name: &str) -> bool {
    contract
        .state_vars
        .iter()
        .find(|v| v.name == name)
        .map(|v| matches!(v.visibility, sluice_ir::Visibility::Public))
        .unwrap_or(false)
}

/// Name looks like a balance/share/accounting ledger.
fn is_accounting_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("balance")
        || n.contains("share")
        || n.contains("deposit")
        || n.contains("credit")
        || n.contains("staked")
        || n.contains("amount")
        || n == "balanceof"
}

/// Name looks like a privileged / authority-bearing state var.
fn is_privileged_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("owner")
        || n.contains("admin")
        || n.contains("role")
        || n.contains("paused")
        || n.contains("governance")
        || n.contains("authority")
        || n.contains("operator")
        || n.contains("minter")
        || n.contains("guardian")
        || n.contains("initialized")
        || n.contains("implementation")
}

/// A mapping type whose value side is numeric (`=> uint*` / `=> int*`).
fn maps_to_numeric(ty: &str) -> bool {
    // crude: the last `=> T)` value type is an integer
    if let Some(idx) = ty.rfind("=>") {
        let val = ty[idx + 2..].trim_end_matches(')').trim();
        let base = val.split_whitespace().next().unwrap_or(val);
        return base.starts_with("uint") || base.starts_with("int");
    }
    false
}

/// Identifier-safe slug (alphanumeric + `_`).
pub fn sanitize_ident(s: &str) -> String {
    let out: String = s.chars().filter(|c| c.is_alphanumeric() || *c == '_').collect();
    if out.is_empty() {
        "X".to_string()
    } else {
        out
    }
}

/// Is a call site one that transfers control to an attacker-supplied party that
/// could re-enter (a value-bearing low-level `.call`, or an external call to a
/// `msg.sender`-rooted target)?
fn is_reentry_vector(c: &CallSite) -> bool {
    let target_is_sender = {
        let t = c.target.to_ascii_lowercase();
        t.contains("msg.sender") || t.contains("recipient") || t.contains("receiver") || t.contains("to")
    };
    match c.kind {
        CallKind::LowLevelCall => c.sends_value || target_is_sender,
        CallKind::External => target_is_sender || c.sends_value,
        CallKind::Send | CallKind::Transfer => true,
        _ => c.sends_value,
    }
}
