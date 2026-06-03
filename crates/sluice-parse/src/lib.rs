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
use rayon::prelude::*;
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
pub fn parse_paths<P: AsRef<Path> + Sync>(paths: &[P]) -> ParseOutput {
    // Read files in parallel (many small files → I/O + UTF-8 validation overlap),
    // collecting `Result`s in input order so the downstream `file_no` assignment
    // and reporting order stay identical to a serial read.
    let read: Vec<Result<(String, String), FileError>> = paths
        .par_iter()
        .map(|p| {
            let path = p.as_ref();
            match std::fs::read_to_string(path) {
                Ok(content) => Ok((path.display().to_string(), content)),
                Err(e) => Err(FileError {
                    path: path.display().to_string(),
                    message: format!("read error: {e}"),
                }),
            }
        })
        .collect();

    let mut sources = Vec::with_capacity(read.len());
    let mut file_errors = Vec::new();
    for r in read {
        match r {
            Ok(s) => sources.push(s),
            Err(e) => file_errors.push(e),
        }
    }
    let mut out = parse_sources(sources);
    out.file_errors.extend(file_errors);
    out
}

/// Maximum bracket-nesting depth a file may contain before we skip it as a
/// likely DoS input. The parser is super-linear in nesting depth, so this guards
/// against a hostile file; real Solidity is rarely more than a few dozen deep.
const MAX_NESTING_DEPTH: usize = 1024;

/// O(bytes) scan for the maximum `()[]{}` nesting depth; returns `Some(depth)` if
/// it exceeds `limit`, else `None`. (Brackets inside strings/comments are counted
/// too, but a legitimate file with 1024+ nested brackets does not exist, so the
/// crude approximation never causes a meaningful false skip.)
fn excessive_nesting(src: &str, limit: usize) -> Option<usize> {
    let mut depth: usize = 0;
    let mut max: usize = 0;
    for b in src.bytes() {
        match b {
            b'(' | b'[' | b'{' => {
                depth += 1;
                if depth > max {
                    max = depth;
                }
            }
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    (max > limit).then_some(max)
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// True if position `i` begins a word (the byte before it is not an identifier
/// byte) — used to match keywords (`layout`, `at`, `is`) without matching a
/// substring inside a larger identifier.
fn word_boundary_before(bytes: &[u8], i: usize) -> bool {
    i == 0 || !is_ident_byte(bytes[i - 1])
}

/// End (exclusive) of a `layout at <expr>` directive: the offset of the `is`
/// keyword or the `{` that begins the contract body, scanning at bracket depth 0.
/// Returns `None` if neither is found before a `;`/EOF (malformed → don't touch).
fn find_layout_expr_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth: i32 = 0;
    let mut k = start;
    while k < bytes.len() {
        match bytes[k] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b'{' if depth == 0 => return Some(k),
            b';' if depth == 0 => return None,
            b'i' if depth == 0
                && bytes[k..].starts_with(b"is")
                && word_boundary_before(bytes, k)
                && (k + 2 >= bytes.len() || !is_ident_byte(bytes[k + 2])) =>
            {
                return Some(k)
            }
            _ => {}
        }
        k += 1;
    }
    None
}

/// Solidity 0.8.29 introduced the `contract X layout at <slot> is ...` custom
/// storage-layout directive (EIP-7201 era). `solang-parser` 0.3.5 predates it and
/// rejects the **entire file**, silently dropping every contract in it from
/// analysis. We blank the `layout at <expr>` span with spaces — preserving every
/// byte offset, so all `Span`s still line up with the original source we keep for
/// reporting — before handing the text to the parser. Returns `None` when the
/// directive is absent (the overwhelmingly common case → no allocation).
fn blank_layout_directive(src: &str) -> Option<String> {
    const KW: &[u8] = b"layout";
    if !src.contains("layout") {
        return None;
    }
    let bytes = src.as_bytes();
    let mut out: Option<Vec<u8>> = None;
    let mut i = 0;
    while i + KW.len() <= bytes.len() {
        if &bytes[i..i + KW.len()] == KW && word_boundary_before(bytes, i) {
            // After `layout`: whitespace, then the `at` keyword, then whitespace.
            let mut j = i + KW.len();
            let ws_start = j;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let saw_ws = j > ws_start;
            if saw_ws
                && j + 2 <= bytes.len()
                && &bytes[j..j + 2] == b"at"
                && (j + 2 == bytes.len() || !is_ident_byte(bytes[j + 2]))
            {
                j += 2;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if let Some(end) = find_layout_expr_end(bytes, j) {
                    let buf = out.get_or_insert_with(|| bytes.to_vec());
                    for b in buf.iter_mut().take(end).skip(i) {
                        // Preserve newlines (line numbers) and any non-ASCII byte;
                        // blank everything else of the directive to a space.
                        if *b != b'\n' && *b != b'\r' && *b < 0x80 {
                            *b = b' ';
                        }
                    }
                    i = end;
                    continue;
                }
            }
        }
        i += 1;
    }
    // We only ever overwrote ASCII bytes with ASCII spaces, so the buffer is still
    // valid UTF-8; `from_utf8` cannot fail, but stay lossless to be safe.
    out.map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// Parse in-memory `(path, content)` sources into an [`Scir`].
pub fn parse_sources(sources: Vec<(String, String)>) -> ParseOutput {
    let mut scir = Scir::new();
    let mut file_errors = Vec::new();

    // ---- Phase 0: parse every file (in parallel). ----
    //
    // Each file's CPU work — the O(bytes) nesting pre-scan, the `layout at`
    // recovery, the recursive-descent `solang_parser::parse`, and the
    // `SourceFile` line-index build — is independent, so we fan it out with
    // rayon. Results are collected **indexed by input position** and folded back
    // in order, so `file_no` and the order of `scir.files` / `srcs` / `units` /
    // `file_errors` are byte-for-byte identical to the previous serial pass
    // (determinism preserved regardless of thread scheduling).
    enum Parsed {
        Ok(pt::SourceUnit),
        Err(String),
    }
    struct FileWork {
        path: String,
        file: SourceFile,
        content: String,
        parsed: Parsed,
    }

    let work: Vec<FileWork> = sources
        .into_par_iter()
        .enumerate()
        .map(|(idx, (path, content))| {
            let file_no = idx as u32;
            // Pre-scan: reject pathologically nested input in O(bytes) BEFORE handing
            // it to the parser. The parser is super-linear in bracket-nesting depth,
            // so a ~60 KB file of nested parens would otherwise burn seconds of CPU
            // (a hostile-input DoS). Real Solidity is never this deep.
            let parsed = if let Some(depth) = excessive_nesting(&content, MAX_NESTING_DEPTH) {
                Parsed::Err(format!(
                    "skipped: bracket-nesting depth {depth} exceeds limit {MAX_NESTING_DEPTH} (possible DoS input)"
                ))
            } else {
                // Recover Solidity 0.8.29 `contract X layout at <slot> is ...` headers
                // that solang-parser 0.3.5 rejects, by blanking the directive
                // (offset-preserving, so spans still index the original `content` we
                // store below for reporting).
                let blanked = blank_layout_directive(&content);
                let parse_input: &str = blanked.as_deref().unwrap_or(&content);
                match solang_parser::parse(parse_input, file_no as usize) {
                    Ok((unit, _comments)) => Parsed::Ok(unit),
                    Err(diags) => Parsed::Err(
                        diags
                            .first()
                            .map(|d| d.message.clone())
                            .unwrap_or_else(|| "parse error".into()),
                    ),
                }
            };
            let file = SourceFile::new(path.clone(), content.clone());
            FileWork { path, file, content, parsed }
        })
        .collect();

    // Fold the per-file results back in input order: identical to the serial loop.
    let mut units: Vec<(u32, pt::SourceUnit)> = Vec::new();
    let mut srcs: Vec<String> = Vec::with_capacity(work.len());
    for (idx, fw) in work.into_iter().enumerate() {
        let file_no = idx as u32;
        match fw.parsed {
            Parsed::Ok(unit) => units.push((file_no, unit)),
            Parsed::Err(message) => file_errors.push(FileError { path: fw.path, message }),
        }
        scir.files.push(fw.file);
        srcs.push(fw.content);
    }

    // ---- Phase 1: register contracts and collect global name sets. ----
    let mut known_types: FxHashSet<String> = FxHashSet::default();
    let mut known_libs: FxHashSet<String> = FxHashSet::default();
    let mut known_lib_funcs: FxHashSet<String> = FxHashSet::default();
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
                    let is_library = matches!(def.ty, pt::ContractTy::Library(_));
                    if !name.is_empty() {
                        known_types.insert(name.clone());
                        if is_library {
                            known_libs.insert(name.clone());
                        }
                    }
                    if is_library {
                        for cp in &def.parts {
                            if let pt::ContractPart::FunctionDefinition(fd) = cp {
                                if let Some(n) = &fd.name {
                                    known_lib_funcs.insert(n.name.clone());
                                }
                            }
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

    // ---- Phase 2: build contracts + functions (in parallel). ----
    //
    // Each contract's build — lowering its state vars, every function body, and the
    // per-function `FunctionEffects` — is independent work, but `FunctionId`s must
    // stay identical to the old serial counter (findings reference them, and output
    // must be byte-for-byte stable). So we PRE-ASSIGN each contract a contiguous
    // `FunctionId` range by prefix-summing function counts over `regs` (the same
    // order the serial `next_fid` walked), then build the contracts in parallel,
    // each numbering its own functions from its reserved base. The results are
    // folded back in `regs` order, so every map/order is deterministic.
    let fn_counts: Vec<u32> = regs
        .iter()
        .map(|reg| {
            reg.def
                .parts
                .iter()
                .filter(|cp| matches!(cp, pt::ContractPart::FunctionDefinition(_)))
                .count() as u32
        })
        .collect();
    let mut fid_base: Vec<u32> = Vec::with_capacity(regs.len());
    let mut acc = 0u32;
    for &n in &fn_counts {
        fid_base.push(acc);
        acc += n;
    }

    struct BuiltContract {
        contract: Contract,
        funcs: Vec<(FunctionId, Function)>,
        name_map: FxHashMap<String, FunctionId>,
    }

    let built: Vec<BuiltContract> = regs
        .par_iter()
        .zip(fid_base.par_iter())
        .map(|(reg, &base_fid)| {
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
                known_lib_funcs: &known_lib_funcs,
                depth: std::cell::Cell::new(0),
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
            let mut funcs = Vec::new();
            let mut name_map = FxHashMap::default();
            let mut local_fid = base_fid;
            for cp in &def.parts {
                if let pt::ContractPart::FunctionDefinition(fd) = cp {
                    let fid = FunctionId(local_fid);
                    local_fid += 1;
                    let func = build_function(fid, reg.id, fd, &lowerer, &state_set);
                    if !func.name.is_empty() {
                        name_map.insert(func.name.clone(), fid);
                    }
                    fn_ids.push(fid);
                    funcs.push((fid, func));
                }
            }

            let contract = Contract {
                id: reg.id,
                name: cname,
                kind: contract_kind(&def.ty),
                bases: def.base.iter().map(|b| ident_path_text(&b.name)).collect(),
                state_vars,
                functions: fn_ids,
                using_for,
                file: reg.file_no,
                span: span_of(def.loc, reg.file_no),
            };
            BuiltContract { contract, funcs, name_map }
        })
        .collect();

    // Fold the per-contract results back in `regs` order — identical to serial.
    let mut contract_fn_names: FxHashMap<ContractId, FxHashMap<String, FunctionId>> = FxHashMap::default();
    for b in built {
        for (fid, func) in b.funcs {
            scir.functions.insert(fid, func);
        }
        contract_fn_names.insert(b.contract.id, b.name_map);
        if !b.contract.name.is_empty() {
            scir.contract_by_name.insert(b.contract.name.clone(), b.contract.id);
        }
        scir.contract_order.push(b.contract.id);
        scir.contracts.insert(b.contract.id, b.contract);
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
    fn rejects_pathological_nesting_without_hanging() {
        // A deeply nested expression must be skipped fast (not crash or hang).
        let src = format!("contract C {{ function f() public pure returns (uint) {{ return {}1{}; }} }}",
            "(".repeat(5000), ")".repeat(5000));
        let out = parse_sources(vec![("bomb.sol".into(), src)]);
        assert!(out.file_errors.iter().any(|e| e.message.contains("nesting")));
        assert!(out.scir.contract_named("C").is_none(), "pathological file is skipped");
    }

    #[test]
    fn inline_require_with_call_in_condition_is_access_control() {
        // `require(msg.sender == authority.governor())` — the condition contains an
        // external call. The guard must still be recognized as a MsgSenderCheck
        // (regression: the inner call used to be ordered ahead of the guard, pushing
        // it past the leading-guard cutoff and silently dropping it).
        let scir = parse_one(
            r#"
            pragma solidity ^0.8.20;
            interface IAuthority { function governor() external view returns (address); }
            contract Treasury {
                IAuthority public authority;
                mapping(uint256 => bool) public flags;
                function disable(uint256 s) external {
                    require(msg.sender == authority.governor(), "unauth");
                    flags[s] = true;
                }
            }
            "#,
        );
        let c = scir.contract_named("Treasury").unwrap();
        let f = scir.functions_of(c.id).find(|f| f.name == "disable").unwrap();
        assert!(
            f.effects.guards.iter().any(|g| matches!(g.kind, GuardKind::MsgSenderCheck)),
            "inline msg.sender==authority.governor() guard must be captured; guards={:?}",
            f.effects.guards
        );
    }

    #[test]
    fn recovers_solidity_0_8_29_layout_at_directive() {
        // The `layout at <slot>` header (Solidity 0.8.29) must not drop the file.
        let scir = parse_one(
            r#"
            pragma solidity ^0.8.29;
            interface IFoo { function x() external view returns (uint256); }
            contract Foo layout at 151 is IFoo {
                uint256 public x;
                function set(uint256 v) external { x = v; }
            }
            "#,
        );
        let c = scir.contract_named("Foo").expect("Foo recovered despite `layout at`");
        assert!(c.bases.iter().any(|b| b == "IFoo"), "inheritance after the directive preserved");
        let set = scir.functions_of(c.id).find(|f| f.name == "set").expect("set");
        assert!(set.effects.writes_var("x"));
        // Offset preservation: the span of the function still reads real source.
        assert!(scir.span_text(set.span).contains("x = v"));
    }

    #[test]
    fn layout_at_no_inheritance_blanks_to_brace() {
        let scir = parse_one(
            r#"
            pragma solidity ^0.8.29;
            contract Bar layout at 42 {
                uint256 public y;
                function g() external { y = 1; }
            }
            "#,
        );
        assert!(scir.contract_named("Bar").is_some(), "Bar recovered (blank up to `{{`)");
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
