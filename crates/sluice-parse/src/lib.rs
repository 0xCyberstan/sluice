//! # sluice-parse
//!
//! The native Solidity front-end: parses `.sol` sources with `solang-parser`
//! and lowers them into [`sluice_ir::Scir`]. Zero external tools required — the
//! same "native lifter" philosophy as `vortex-lift`.
//!
//! Pipeline:
//! 1. Parse every file (errors are captured per-file, never fatal).
//! 2. **Register** all contracts/interfaces/libraries so call classification
//!    can tell a cast (`IERC20(x)`) from an internal call, and resolve the full
//!    (inherited) set of state variables per contract.
//! 3. **Build** each function: lower its body, compute [`sluice_ir::FunctionEffects`],
//!    and attach modifier/require guards.
//! 4. Resolve internal call edges for SCC-ordered interprocedural analysis.

mod effects;
mod lower;

use effects::EffectCollector;
use lower::{ident_path_text, sol_type_text, Lowerer};
use rustc_hash::{FxHashMap, FxHashSet};
use sluice_ir::{
    Contract, ContractId, ContractKind, Function, FunctionId, FunctionKind, Guard, GuardKind,
    ModifierInvocation, Mutability, Param, Scir, SourceFile, Span, StateVar, UsingDirective, Visibility,
};
use solang_parser::pt;
use std::path::Path;

/// Result of parsing a set of sources.
pub struct ParseOutput {
    pub scir: Scir,
    /// Files that failed to parse (with a short diagnostic). Parsing is
    /// best-effort: a malformed file never prevents analysis of the rest.
    pub file_errors: Vec<FileError>,
}

pub struct FileError {
    pub path: String,
    pub message: String,
}

/// Parse a list of files from disk.
pub fn parse_paths<P: AsRef<Path>>(paths: &[P]) -> ParseOutput {
    let mut sources = Vec::new();
    let mut file_errors = Vec::new();
    for p in paths {
        let path = p.as_ref();
        match std::fs::read_to_string(path) {
            Ok(content) => sources.push((path.display().to_string(), content)),
            Err(e) => file_errors.push(FileError {
                path: path.display().to_string(),
                message: format!("read error: {e}"),
            }),
        }
    }
    let mut out = parse_sources(sources);
    out.file_errors.extend(file_errors);
    out
}

/// Parse in-memory `(path, content)` sources into an [`Scir`].
pub fn parse_sources(sources: Vec<(String, String)>) -> ParseOutput {
    let mut scir = Scir::new();
    let mut file_errors = Vec::new();

    // ---- Phase 0: parse every file. ----
    let mut units: Vec<(u32, pt::SourceUnit)> = Vec::new();
    let mut srcs: Vec<String> = Vec::new();
    for (path, content) in sources {
        let file_no = srcs.len() as u32;
        match solang_parser::parse(&content, file_no as usize) {
            Ok((unit, _comments)) => {
                units.push((file_no, unit));
            }
            Err(diags) => {
                let msg = diags
                    .first()
                    .map(|d| d.message.clone())
                    .unwrap_or_else(|| "parse error".into());
                file_errors.push(FileError { path: path.clone(), message: msg });
            }
        }
        if scir.pragma_solidity.is_none() {
            // best-effort pragma capture handled below per-unit
        }
        scir.files.push(SourceFile::new(path, content.clone()));
        srcs.push(content);
    }

    // ---- Phase 1: register contracts and collect global name sets. ----
    let mut known_types: FxHashSet<String> = FxHashSet::default();
    let mut known_libs: FxHashSet<String> = FxHashSet::default();
    let mut own_state_vars: FxHashMap<String, Vec<String>> = FxHashMap::default();
    let mut base_names: FxHashMap<String, Vec<String>> = FxHashMap::default();

    struct Reg<'u> {
        id: ContractId,
        file_no: u32,
        def: &'u pt::ContractDefinition,
    }
    let mut regs: Vec<Reg> = Vec::new();
    let mut next_cid: u32 = 0;

    for (file_no, unit) in &units {
        for part in &unit.0 {
            match part {
                pt::SourceUnitPart::ContractDefinition(def) => {
                    let id = ContractId(next_cid);
                    next_cid += 1;
                    let name = def.name.as_ref().map(|i| i.name.clone()).unwrap_or_default();
                    if !name.is_empty() {
                        known_types.insert(name.clone());
                        if matches!(def.ty, pt::ContractTy::Library(_)) {
                            known_libs.insert(name.clone());
                        }
                    }
                    // own state vars + base names
                    let mut svs = Vec::new();
                    for cp in &def.parts {
                        if let pt::ContractPart::VariableDefinition(v) = cp {
                            if let Some(n) = &v.name {
                                svs.push(n.name.clone());
                            }
                        }
                    }
                    own_state_vars.insert(name.clone(), svs);
                    base_names.insert(
                        name.clone(),
                        def.base.iter().map(|b| ident_path_text(&b.name)).collect(),
                    );
                    regs.push(Reg { id, file_no: *file_no, def });
                }
                pt::SourceUnitPart::PragmaDirective(p) => {
                    if scir.pragma_solidity.is_none() {
                        if let Some(text) = pragma_text(p, &srcs) {
                            scir.pragma_solidity = Some(text);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // ---- Phase 2: build contracts + functions. ----
    let mut next_fid: u32 = 0;
    // Track per-contract (name -> own function ids) for callee resolution.
    let mut contract_fn_names: FxHashMap<ContractId, FxHashMap<String, FunctionId>> = FxHashMap::default();

    for reg in &regs {
        let def = reg.def;
        let src = &srcs[reg.file_no as usize];
        let cname = def.name.as_ref().map(|i| i.name.clone()).unwrap_or_default();

        // Full (inherited) state-var name set for this contract.
        let mut state_set: FxHashSet<String> = FxHashSet::default();
        collect_state_vars(&cname, &own_state_vars, &base_names, &mut state_set, &mut FxHashSet::default());

        let lowerer = Lowerer {
            file_no: reg.file_no,
            src,
            known_types: &known_types,
            known_libraries: &known_libs,
        };

        // State variables (own).
        let mut state_vars = Vec::new();
        let mut using_for = Vec::new();
        for cp in &def.parts {
            match cp {
                pt::ContractPart::VariableDefinition(v) => {
                    state_vars.push(lower_state_var(v, reg.file_no));
                }
                pt::ContractPart::Using(u) => {
                    if let Some(d) = lower_using(u) {
                        using_for.push(d);
                    }
                }
                _ => {}
            }
        }

        let mut fn_ids = Vec::new();
        let mut name_map = FxHashMap::default();
        for cp in &def.parts {
            if let pt::ContractPart::FunctionDefinition(fd) = cp {
                let fid = FunctionId(next_fid);
                next_fid += 1;
                let func = build_function(fid, reg.id, fd, &lowerer, &state_set);
                if !func.name.is_empty() {
                    name_map.insert(func.name.clone(), fid);
                }
                fn_ids.push(fid);
                scir.functions.insert(fid, func);
            }
        }
        contract_fn_names.insert(reg.id, name_map);

        let contract = Contract {
            id: reg.id,
            name: cname.clone(),
            kind: contract_kind(&def.ty),
            bases: def.base.iter().map(|b| ident_path_text(&b.name)).collect(),
            state_vars,
            functions: fn_ids,
            using_for,
            file: reg.file_no,
            span: span_of(def.loc, reg.file_no),
        };
        if !cname.is_empty() {
            scir.contract_by_name.insert(cname, reg.id);
        }
        scir.contract_order.push(reg.id);
        scir.contracts.insert(reg.id, contract);
    }

    // ---- Phase 3: resolve internal call edges (best-effort). ----
    resolve_callees(&mut scir, &contract_fn_names, &base_names);

    ParseOutput { scir, file_errors }
}

// ---------------------------------------------------------------- builders

fn build_function(
    id: FunctionId,
    contract: ContractId,
    fd: &pt::FunctionDefinition,
    lowerer: &Lowerer,
    state_set: &FxHashSet<String>,
) -> Function {
    let kind = match fd.ty {
        pt::FunctionTy::Constructor => FunctionKind::Constructor,
        pt::FunctionTy::Function => FunctionKind::Function,
        pt::FunctionTy::Fallback => FunctionKind::Fallback,
        pt::FunctionTy::Receive => FunctionKind::Receive,
        pt::FunctionTy::Modifier => FunctionKind::Modifier,
    };
    let name = fd
        .name
        .as_ref()
        .map(|i| i.name.clone())
        .unwrap_or_else(|| default_name(kind));

    let mut visibility = Visibility::Default;
    let mut mutability = Mutability::NonPayable;
    let mut is_virtual = false;
    let mut is_override = false;
    let mut modifiers: Vec<ModifierInvocation> = Vec::new();

    for attr in &fd.attributes {
        match attr {
            pt::FunctionAttribute::Visibility(v) => visibility = lower_visibility(v),
            pt::FunctionAttribute::Mutability(m) => mutability = lower_mutability(m),
            pt::FunctionAttribute::Virtual(_) => is_virtual = true,
            pt::FunctionAttribute::Override(..) => is_override = true,
            pt::FunctionAttribute::BaseOrModifier(loc, base) => {
                modifiers.push(ModifierInvocation {
                    name: ident_path_text(&base.name),
                    args: base
                        .args
                        .as_ref()
                        .map(|a| a.iter().map(|e| lowerer.lower_expr(e)).collect())
                        .unwrap_or_default(),
                    span: span_of(*loc, lowerer.file_no),
                });
            }
            _ => {}
        }
    }

    let params = lower_params(&fd.params);
    let returns = lower_params(&fd.returns);
    let signature = format!(
        "{}({})",
        name,
        params.iter().map(|p| p.ty.clone()).collect::<Vec<_>>().join(",")
    );

    let (body, has_body) = match &fd.body {
        Some(b) => (lowerer.lower_body(b), true),
        None => (Vec::new(), false),
    };

    // Effects from the body, then prepend guards contributed by modifiers.
    let mut effects = EffectCollector::new(state_set).collect(&body);
    let mut modifier_guards: Vec<Guard> = modifiers
        .iter()
        .map(|m| Guard {
            kind: classify_modifier(&m.name),
            text: m.name.clone(),
            span: m.span,
        })
        .collect();
    modifier_guards.append(&mut effects.guards);
    effects.guards = modifier_guards;

    Function {
        id,
        name,
        contract,
        kind,
        visibility,
        mutability,
        params,
        returns,
        modifiers,
        is_virtual,
        is_override,
        has_body,
        body,
        signature,
        span: span_of(fd.loc, lowerer.file_no),
        effects,
        callees: Vec::new(),
        callers: Vec::new(),
    }
}

fn lower_state_var(v: &pt::VariableDefinition, file_no: u32) -> StateVar {
    let mut visibility = Visibility::Internal; // state vars default to internal
    let mut constant = false;
    let mut immutable = false;
    for a in &v.attrs {
        match a {
            pt::VariableAttribute::Visibility(vis) => visibility = lower_visibility(vis),
            pt::VariableAttribute::Constant(_) => constant = true,
            pt::VariableAttribute::Immutable(_) => immutable = true,
            _ => {}
        }
    }
    StateVar {
        name: v.name.as_ref().map(|i| i.name.clone()).unwrap_or_default(),
        ty: sol_type_text(&v.ty),
        visibility,
        constant,
        immutable,
        initialized: v.initializer.is_some(),
        span: span_of(v.loc, file_no),
    }
}

fn lower_using(u: &pt::Using) -> Option<UsingDirective> {
    let library = match &u.list {
        pt::UsingList::Library(path) => ident_path_text(path),
        pt::UsingList::Functions(fns) => {
            fns.first().map(|f| ident_path_text(&f.path)).unwrap_or_default()
        }
        pt::UsingList::Error => return None,
    };
    Some(UsingDirective {
        library,
        ty: u.ty.as_ref().map(sol_type_text),
    })
}

fn lower_params(params: &pt::ParameterList) -> Vec<Param> {
    params
        .iter()
        .filter_map(|(_, p)| p.as_ref())
        .map(|p| Param {
            name: p.name.as_ref().map(|i| i.name.clone()),
            ty: sol_type_text(&p.ty),
            location: p.storage.as_ref().map(storage_text),
        })
        .collect()
}

fn resolve_callees(
    scir: &mut Scir,
    contract_fn_names: &FxHashMap<ContractId, FxHashMap<String, FunctionId>>,
    base_names: &FxHashMap<String, Vec<String>>,
) {
    // Build name -> contractId for resolving inherited functions.
    let name_to_cid: FxHashMap<String, ContractId> = scir
        .contracts
        .values()
        .map(|c| (c.name.clone(), c.id))
        .collect();

    let fids: Vec<FunctionId> = scir.functions.keys().copied().collect();
    let mut edges: Vec<(FunctionId, FunctionId)> = Vec::new();
    for fid in fids {
        let (cid, calls) = {
            let f = &scir.functions[&fid];
            (f.contract, f.effects.internal_calls.clone())
        };
        let cname = scir.contracts.get(&cid).map(|c| c.name.clone()).unwrap_or_default();
        for call in calls {
            if let Some(target) = resolve_in_hierarchy(
                &cname, &call, contract_fn_names, base_names, &name_to_cid,
            ) {
                if target != fid {
                    edges.push((fid, target));
                }
            }
        }
    }
    for (caller, callee) in edges {
        if let Some(f) = scir.functions.get_mut(&caller) {
            if !f.callees.contains(&callee) {
                f.callees.push(callee);
            }
        }
        if let Some(f) = scir.functions.get_mut(&callee) {
            if !f.callers.contains(&caller) {
                f.callers.push(caller);
            }
        }
    }
}

fn resolve_in_hierarchy(
    contract_name: &str,
    fn_name: &str,
    contract_fn_names: &FxHashMap<ContractId, FxHashMap<String, FunctionId>>,
    base_names: &FxHashMap<String, Vec<String>>,
    name_to_cid: &FxHashMap<String, ContractId>,
) -> Option<FunctionId> {
    let mut stack = vec![contract_name.to_string()];
    let mut seen = FxHashSet::default();
    while let Some(name) = stack.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        if let Some(cid) = name_to_cid.get(&name) {
            if let Some(map) = contract_fn_names.get(cid) {
                if let Some(fid) = map.get(fn_name) {
                    return Some(*fid);
                }
            }
        }
        if let Some(bases) = base_names.get(&name) {
            stack.extend(bases.iter().cloned());
        }
    }
    None
}

/// Transitively collect a contract's own + inherited state-variable names.
fn collect_state_vars(
    name: &str,
    own: &FxHashMap<String, Vec<String>>,
    bases: &FxHashMap<String, Vec<String>>,
    out: &mut FxHashSet<String>,
    seen: &mut FxHashSet<String>,
) {
    if !seen.insert(name.to_string()) {
        return;
    }
    if let Some(vs) = own.get(name) {
        for v in vs {
            out.insert(v.clone());
        }
    }
    if let Some(bs) = bases.get(name) {
        for b in bs {
            collect_state_vars(b, own, bases, out, seen);
        }
    }
}

// ---------------------------------------------------------------- small mappers

fn contract_kind(ty: &pt::ContractTy) -> ContractKind {
    match ty {
        pt::ContractTy::Abstract(_) => ContractKind::Abstract,
        pt::ContractTy::Contract(_) => ContractKind::Contract,
        pt::ContractTy::Interface(_) => ContractKind::Interface,
        pt::ContractTy::Library(_) => ContractKind::Library,
    }
}

fn lower_visibility(v: &pt::Visibility) -> Visibility {
    match v {
        pt::Visibility::External(_) => Visibility::External,
        pt::Visibility::Public(_) => Visibility::Public,
        pt::Visibility::Internal(_) => Visibility::Internal,
        pt::Visibility::Private(_) => Visibility::Private,
    }
}

fn lower_mutability(m: &pt::Mutability) -> Mutability {
    match m {
        pt::Mutability::Pure(_) => Mutability::Pure,
        pt::Mutability::View(_) | pt::Mutability::Constant(_) => Mutability::View,
        pt::Mutability::Payable(_) => Mutability::Payable,
    }
}

fn storage_text(s: &pt::StorageLocation) -> String {
    match s {
        pt::StorageLocation::Memory(_) => "memory".into(),
        pt::StorageLocation::Storage(_) => "storage".into(),
        pt::StorageLocation::Calldata(_) => "calldata".into(),
    }
}

fn default_name(kind: FunctionKind) -> String {
    match kind {
        FunctionKind::Constructor => "constructor",
        FunctionKind::Fallback => "fallback",
        FunctionKind::Receive => "receive",
        _ => "",
    }
    .to_string()
}

/// Classify a modifier name into a guard kind (drives access-control / reentrancy
/// false-positive suppression and consensus mining).
pub fn classify_modifier(name: &str) -> GuardKind {
    let l = name.to_ascii_lowercase();
    if l.contains("nonreentrant") || l.contains("reentrancy") || l == "lock" || l.contains("mutex") {
        GuardKind::ReentrancyLock
    } else if l.contains("initializer") {
        GuardKind::Initializer
    } else if l.contains("paused") || l == "pause" || l.contains("whennotpaused") {
        GuardKind::PauseCheck
    } else if l.contains("only")
        || l.contains("auth")
        || l.contains("owner")
        || l.contains("admin")
        || l.contains("role")
        || l.contains("governance")
        || l.contains("guardian")
        || l.contains("restricted")
    {
        GuardKind::MsgSenderCheck
    } else {
        GuardKind::Modifier(name.to_string())
    }
}

fn span_of(loc: pt::Loc, file_no: u32) -> Span {
    match loc {
        pt::Loc::File(_, s, e) => Span::new(file_no, s as u32, e as u32),
        _ => Span::dummy(),
    }
}

fn pragma_text(p: &pt::PragmaDirective, srcs: &[String]) -> Option<String> {
    let (loc, is_solidity) = match p {
        pt::PragmaDirective::Version(loc, id, _) => (*loc, id.name == "solidity"),
        pt::PragmaDirective::Identifier(loc, id, _) => {
            (*loc, id.as_ref().map(|i| i.name == "solidity").unwrap_or(false))
        }
        pt::PragmaDirective::StringLiteral(loc, id, _) => (*loc, id.name == "solidity"),
    };
    if !is_solidity {
        return None;
    }
    if let pt::Loc::File(f, s, e) = loc {
        return srcs.get(f).and_then(|src| src.get(s..e)).map(|t| t.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use sluice_ir::CallKind;

    fn parse_one(src: &str) -> Scir {
        parse_sources(vec![("t.sol".into(), src.into())]).scir
    }

    #[test]
    fn parses_basic_contract() {
        let scir = parse_one(
            r#"
            pragma solidity ^0.8.20;
            contract Bank {
                mapping(address => uint256) public balances;
                address owner;
                function withdraw(uint256 amt) external {
                    require(balances[msg.sender] >= amt, "no");
                    (bool ok, ) = msg.sender.call{value: amt}("");
                    require(ok);
                    balances[msg.sender] -= amt;
                }
                function setOwner(address o) external onlyOwner { owner = o; }
            }
            "#,
        );
        let c = scir.contract_named("Bank").expect("Bank");
        assert_eq!(c.state_vars.len(), 2);
        assert!(scir.solidity_ge_0_8());

        let withdraw = scir.functions_of(c.id).find(|f| f.name == "withdraw").unwrap();
        assert!(withdraw.is_externally_reachable());
        // low-level call with value
        let cs = &withdraw.effects.call_sites;
        assert!(cs.iter().any(|c| c.kind == CallKind::LowLevelCall && c.sends_value));
        // classic reentrancy signal: state write after external call
        assert!(withdraw.effects.has_write_after_external_call());

        let set_owner = scir.functions_of(c.id).find(|f| f.name == "setOwner").unwrap();
        assert!(set_owner.has_modifier_like("onlyOwner"));
        assert!(set_owner.effects.writes_var("owner"));
    }

    #[test]
    fn resilient_to_bad_file() {
        let out = parse_sources(vec![
            ("bad.sol".into(), "contract { this is not valid ".into()),
            ("good.sol".into(), "contract A { function f() public {} }".into()),
        ]);
        assert!(!out.file_errors.is_empty());
        assert!(out.scir.contract_named("A").is_some());
    }
}
