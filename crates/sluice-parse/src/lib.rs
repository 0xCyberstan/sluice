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

/// Lightweight phase profiling, gated on `SLUICE_PROFILE=1` (stderr only, never
/// affects output). Mirrors the engine's helper so parse sub-phases are visible.
fn profiling_enabled() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var("SLUICE_PROFILE").map(|v| v != "0" && !v.is_empty()).unwrap_or(false)
    })
}

#[inline]
fn phase<T>(label: &str, f: impl FnOnce() -> T) -> T {
    if !profiling_enabled() {
        return f();
    }
    let t = std::time::Instant::now();
    let out = f();
    eprintln!("[profile] {label:<22} {:>8.1}ms", t.elapsed().as_secs_f64() * 1000.0);
    out
}

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
    //
    // A `.sol`-*suffixed directory* (e.g. Forge's `docs/autogen/` artifact dirs
    // named `Foo.sol/`) reaches here when a caller's path-walk matched on the
    // extension alone; `read_to_string` on it returns "Is a directory (os error
    // 21)". The metadata probe skips any non-file silently (`None`) — neither a
    // source nor a `FileError` — so directory entries never pollute the report.
    let read: Vec<Result<(String, String), FileError>> = phase("read-files", || {
        paths
            .par_iter()
            .filter_map(|p| {
                let path = p.as_ref();
                if !std::fs::metadata(path).map(|m| m.is_file()).unwrap_or(false) {
                    return None;
                }
                Some(match std::fs::read_to_string(path) {
                    Ok(content) => Ok((path.display().to_string(), content)),
                    Err(e) => Err(FileError {
                        path: path.display().to_string(),
                        message: format!("read error: {e}"),
                    }),
                })
            })
            .collect()
    });

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

/// If a comment or string/char literal *begins* at `k`, return the offset just
/// past its end; otherwise `None`. Lets the `layout at` scanners step over
/// regions where Solidity tokens (`is`, `{`, `;`, the `layout` keyword itself)
/// may appear as plain text rather than syntax — e.g. the `/// … layout at 151 …`
/// doc-comments above an EIP-7201 contract header. Conservative: an unterminated
/// block comment / string runs to EOF (returns `bytes.len()`), matching how the
/// parser would treat it.
fn skip_comment_or_string(bytes: &[u8], k: usize) -> Option<usize> {
    match bytes[k] {
        // `//` line comment → to end of line (newline kept for line numbers).
        b'/' if bytes.get(k + 1) == Some(&b'/') => {
            let mut j = k + 2;
            while j < bytes.len() && bytes[j] != b'\n' {
                j += 1;
            }
            Some(j)
        }
        // `/* … */` block comment.
        b'/' if bytes.get(k + 1) == Some(&b'*') => {
            let mut j = k + 2;
            while j + 1 < bytes.len() && !(bytes[j] == b'*' && bytes[j + 1] == b'/') {
                j += 1;
            }
            // Past the closing `*/`, or EOF if unterminated.
            Some((j + 2).min(bytes.len()))
        }
        // `"…"` / `'…'` string or char literal (Solidity has no multi-line raw
        // strings; a `\` escapes the next byte, including the quote).
        q @ (b'"' | b'\'') => {
            let mut j = k + 1;
            while j < bytes.len() {
                match bytes[j] {
                    b'\\' => j += 2,
                    b if b == q => return Some(j + 1),
                    _ => j += 1,
                }
            }
            Some(bytes.len())
        }
        _ => None,
    }
}

/// End (exclusive) of a `layout at <expr>` directive: the offset of the `is`
/// keyword or the `{` that begins the contract body, scanning at bracket depth 0.
/// Comments and string literals are skipped so a stray `is`/`{`/`;` inside them
/// can't truncate the directive early. Returns `None` if neither is found before
/// a `;`/EOF (malformed → don't touch).
fn find_layout_expr_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth: i32 = 0;
    let mut k = start;
    while k < bytes.len() {
        if let Some(next) = skip_comment_or_string(bytes, k) {
            k = next;
            continue;
        }
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

/// Solidity 0.8.29 introduced the custom storage-layout directive, in two forms:
/// a standalone `contract X layout at <slot> { … }` and the inherited-layout
/// header `contract X layout at <slot> is Base, … { … }` (EIP-7201 era).
/// `solang-parser` 0.3.5 predates both and rejects the **entire file**, silently
/// dropping every contract in it from analysis. We blank the `layout at <expr>`
/// span with spaces — preserving every byte offset, so all `Span`s still line up
/// with the original source we keep for reporting — before handing the text to
/// the parser. The `is Base, …` clause (when present) is left intact, so the
/// recovered contract still parses with its full inheritance list.
///
/// The scan steps over comments and string literals (via
/// [`skip_comment_or_string`]): real contracts carry doc-comments that mention
/// the directive (e.g. EigenLayer's `AllocationManagerView` has three
/// `/// … layout at 151 …` lines above the header). A comment-blind match there
/// would start blanking inside the comment and run forward through the genuine
/// `contract …` keyword to the first real `is`/`{`, corrupting the header — which
/// is exactly the "header form not handled" failure this guards against.
///
/// Returns `None` when the directive is absent (the overwhelmingly common case
/// → no allocation).
fn blank_layout_directive(src: &str) -> Option<String> {
    const KW: &[u8] = b"layout";
    if !src.contains("layout") {
        return None;
    }
    let bytes = src.as_bytes();
    let mut out: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < bytes.len() {
        // Never match the keyword inside a comment or string literal.
        if let Some(next) = skip_comment_or_string(bytes, i) {
            i = next;
            continue;
        }
        if i + KW.len() <= bytes.len()
            && &bytes[i..i + KW.len()] == KW
            && word_boundary_before(bytes, i)
        {
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

/// First significant byte at or after `k` — skipping ASCII whitespace and any
/// `//`/`/* */` comment (string/char literals can't begin a state-var's
/// data-location/visibility/name run, so they're treated like any other byte and
/// stop the scan). Returns the offset of that byte, or `None` at EOF.
fn next_significant(bytes: &[u8], k: usize) -> Option<usize> {
    let mut j = k;
    while j < bytes.len() {
        if bytes[j].is_ascii_whitespace() {
            j += 1;
            continue;
        }
        // Only *comments* are skipped here, not strings: a `"…"` after `transient`
        // would itself be a syntax error, so we let it stop the scan (no match).
        if bytes[j] == b'/' && matches!(bytes.get(j + 1), Some(&b'/') | Some(&b'*')) {
            match skip_comment_or_string(bytes, j) {
                Some(next) => {
                    j = next;
                    continue;
                }
                None => return Some(j),
            }
        }
        return Some(j);
    }
    None
}

/// Solidity 0.8.28 introduced the `transient` data-location keyword for state
/// variables: `<type> transient [visibility] <name>;` (e.g. ERC-4337's
/// EntryPoint: `bytes32 transient private currentUserOpHash;`). `solang-parser`
/// 0.3.5 predates it and parses `transient` as the *variable name*, then chokes on
/// the following `private`/identifier and rejects the **entire file** — silently
/// dropping every contract in it from analysis.
///
/// We recover it the same offset-preserving way as [`blank_layout_directive`]:
/// blank just the `transient` keyword to equal-length spaces so solang parses the
/// declaration as an ordinary state var (`bytes32 private currentUserOpHash;`).
/// Every byte offset is preserved, so all `Span`s still index the original source
/// we keep for reporting, and a transient var is analyzed exactly like a normal
/// state var (its slot semantics don't affect Sluice's logic/state-bug detectors).
///
/// Discrimination (so a variable/function genuinely *named* `transient` is left
/// untouched): the keyword form is always followed by another word — the
/// visibility (`private`/`public`/`internal`) or the variable name itself — i.e.
/// the next significant token begins with an identifier byte. A `transient` that
/// is itself a name is instead immediately followed by `;`, `=`, `,`, `)` or `(`
/// (`uint256 transient;`, `transient = 1`, `function transient()`), which solang
/// already parses, so we only blank when the next significant token starts an
/// identifier. The scan also skips comments/strings (via
/// [`skip_comment_or_string`]) so a `transient` mentioned in a doc-comment is
/// never blanked.
///
/// Returns `None` when no such keyword is present (the common case → no
/// allocation).
fn blank_transient_keyword(src: &str) -> Option<String> {
    const KW: &[u8] = b"transient";
    if !src.contains("transient") {
        return None;
    }
    let bytes = src.as_bytes();
    let mut out: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < bytes.len() {
        // Never match the keyword inside a comment or string literal.
        if let Some(next) = skip_comment_or_string(bytes, i) {
            i = next;
            continue;
        }
        if i + KW.len() <= bytes.len()
            && &bytes[i..i + KW.len()] == KW
            && word_boundary_before(bytes, i)
            && (i + KW.len() == bytes.len() || !is_ident_byte(bytes[i + KW.len()]))
        {
            // Keyword usage iff the next significant token starts an identifier
            // (the visibility keyword or the variable name). Otherwise `transient`
            // is itself a name (`transient;`, `transient =`, `transient(`) — leave it.
            let after = i + KW.len();
            if let Some(n) = next_significant(bytes, after) {
                if is_ident_byte(bytes[n]) {
                    let buf = out.get_or_insert_with(|| bytes.to_vec());
                    for b in buf.iter_mut().take(after).skip(i) {
                        *b = b' '; // KW is pure ASCII; equal-length blanking.
                    }
                    i = after;
                    continue;
                }
            }
        }
        i += 1;
    }
    // Only ASCII bytes were overwritten with ASCII spaces → still valid UTF-8.
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
        parsed: Parsed,
    }

    let work: Vec<FileWork> = phase("parse-files", || sources
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
                // Recover Solidity-syntax that solang-parser 0.3.5 predates and would
                // otherwise reject *for the whole file* (dropping every contract in it):
                //   - 0.8.29 `contract X layout at <slot> is ...` storage-layout headers
                //   - 0.8.28 `<type> transient <vis> <name>;` transient storage vars
                // Each recovery blanks only the offending keyword/directive to spaces,
                // so byte offsets are preserved and every `Span` still indexes the
                // original `content` we store below for reporting. They compose: a file
                // may use both, so we feed the output of one into the next (each is a
                // no-op allocation-free `None` when its keyword is absent).
                let blanked_layout = blank_layout_directive(&content);
                let after_layout: &str = blanked_layout.as_deref().unwrap_or(&content);
                let blanked_transient = blank_transient_keyword(after_layout);
                let parse_input: &str = blanked_transient.as_deref().unwrap_or(after_layout);
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
            // `SourceFile` owns the content (needed for reporting). We used to also
            // keep a *second* owned copy of the same bytes (`content`) to feed the
            // lowerer / pragma scan; on a large corpus that doubled the resident
            // source (tens of MB) and cost a full extra copy per file. Instead the
            // downstream phases borrow the content straight out of `scir.files`
            // (see `srcs` below) — one copy, same bytes.
            let file = SourceFile::new(path.clone(), content);
            FileWork { path, file, parsed }
        })
        .collect());

    // Fold the per-file results back in input order: identical to the serial loop.
    let mut units: Vec<(u32, pt::SourceUnit)> = Vec::new();
    for (idx, fw) in work.into_iter().enumerate() {
        let file_no = idx as u32;
        match fw.parsed {
            Parsed::Ok(unit) => units.push((file_no, unit)),
            Parsed::Err(message) => file_errors.push(FileError { path: fw.path, message }),
        }
        scir.files.push(fw.file);
    }

    // Borrowed view of each file's source text, indexed by `file_no`. This is the
    // single source-of-truth copy (the `SourceFile.content` we just stored); the
    // register/build phases read through it instead of a duplicated `Vec<String>`.
    let srcs: Vec<&str> = scir.files.iter().map(|f| f.content.as_str()).collect();

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
    // First `pragma solidity` seen (assigned to `scir` after the borrow of `srcs`
    // ends, to keep `scir.files` borrowed immutably through phases 1–2).
    let mut pragma_solidity: Option<String> = None;

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
                    // Collect into a local (not `scir.pragma_solidity` directly) so
                    // we don't need `&mut scir` while `srcs` borrows `scir.files`.
                    // Same "first solidity pragma wins" semantics as before.
                    if pragma_solidity.is_none() {
                        if let Some(text) = pragma_text(p, &srcs) {
                            pragma_solidity = Some(text);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    scir.pragma_solidity = pragma_solidity;

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

    let built: Vec<BuiltContract> = phase("build-funcs", || regs
        .par_iter()
        .zip(fid_base.par_iter())
        .map(|(reg, &base_fid)| {
            let def = reg.def;
            let src: &str = srcs[reg.file_no as usize];
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
        .collect());

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
    phase("resolve-callees", || resolve_callees(&mut scir, &contract_fn_names, &base_names));

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

fn pragma_text(p: &pt::PragmaDirective, srcs: &[&str]) -> Option<String> {
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

    #[test]
    fn recovers_layout_at_header_with_directive_in_doc_comments() {
        // Shape of EigenLayer's `AllocationManagerView.sol`: the `layout at 151`
        // directive is mentioned in `///` and `/* */` comments *above* the genuine
        // `contract … layout at 151 is …` header. A comment-blind recovery starts
        // blanking inside a comment and runs forward through the `contract` keyword
        // to the first real `is`/`{`, corrupting the header so solang rejects the
        // whole file (the "header form not handled" bug). The recovery must ignore
        // the comment mentions and blank only the real directive.
        let out = parse_sources(vec![(
            "AllocationManagerView.sol".into(),
            r#"
            pragma solidity ^0.8.29; // Minimum for `layout at` directive.
            interface IView { function v() external view returns (uint256); }
            interface IStore {}
            /// @dev The `layout at 151` directive specifies that storage should be
            ///      placed starting at storage slot 151; this is calculated from
            ///      the main contract layout. It uses `layout at 151` to align.
            /* block comment also naming layout at 151 is/{ ; tokens inside */
            contract AllocationManagerView layout at 151 is IView, IStore {
                uint256 public x;
                function set(uint256 v) external { x = v; }
            }
            "#
            .into(),
        )]);
        assert!(
            out.file_errors.is_empty(),
            "no parse/skip error expected; got {:?}",
            out.file_errors.iter().map(|e| &e.message).collect::<Vec<_>>()
        );
        let scir = out.scir;
        let c = scir
            .contract_named("AllocationManagerView")
            .expect("contract recovered despite `layout at` in doc-comments");
        // Full inheritance list after the directive is preserved.
        assert!(c.bases.iter().any(|b| b == "IView"));
        assert!(c.bases.iter().any(|b| b == "IStore"));
        let set = scir.functions_of(c.id).find(|f| f.name == "set").expect("set");
        assert!(set.effects.writes_var("x"));
        // Offset preservation: spans still index the original (unblanked) source.
        assert!(scir.span_text(set.span).contains("x = v"));
    }

    #[test]
    fn layout_keyword_inside_string_is_not_a_directive() {
        // A `layout at N` appearing inside a string literal must not be blanked
        // (it isn't a directive); the contract parses normally.
        let scir = parse_one(
            r#"
            pragma solidity ^0.8.20;
            contract S {
                string public note = "use layout at 151 is best practice";
                function f() external pure returns (uint256) { return 1; }
            }
            "#,
        );
        let c = scir.contract_named("S").expect("S parses");
        assert!(scir.functions_of(c.id).any(|f| f.name == "f"));
    }

    #[test]
    fn dot_sol_directory_is_skipped_without_error() {
        // Forge's `docs/autogen/` emits `.sol`-*suffixed directories*. If a caller
        // collected one as a path, `parse_paths` must skip it silently (no
        // "Is a directory" FileError) while still reading the real sibling file.
        let base = std::env::temp_dir().join(format!("sluice_parse_dirtest_{}", std::process::id()));
        let dir_named_sol = base.join("Artifact.sol"); // a DIRECTORY ending in .sol
        std::fs::create_dir_all(&dir_named_sol).unwrap();
        let real = base.join("Real.sol");
        std::fs::write(&real, "contract Real { function f() public {} }").unwrap();

        let out = parse_paths(&[dir_named_sol.clone(), real.clone()]);

        // No error of any kind from the directory entry.
        assert!(
            !out.file_errors.iter().any(|e| e.message.contains("Is a directory")
                || e.message.to_ascii_lowercase().contains("directory")),
            "directory entry must be skipped silently; errors={:?}",
            out.file_errors.iter().map(|e| (&e.path, &e.message)).collect::<Vec<_>>()
        );
        // The real sibling file still parsed.
        assert!(out.scir.contract_named("Real").is_some(), "real file still parsed");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn recovers_solidity_0_8_28_transient_storage_var() {
        // The `transient` data-location keyword (Solidity 0.8.28) must not drop the
        // file. Shape mirrors ERC-4337's EntryPoint: `bytes32 transient private x;`.
        let scir = parse_one(
            r#"
            pragma solidity ^0.8.28;
            contract EntryLike {
                bytes32 transient private currentUserOpHash;
                uint256 public regular;
                function setHash(bytes32 h) external {
                    currentUserOpHash = h;
                }
            }
            "#,
        );
        let c = scir
            .contract_named("EntryLike")
            .expect("EntryLike recovered despite `transient`");
        // The transient var is treated as a normal state var.
        assert!(
            c.state_vars.iter().any(|v| v.name == "currentUserOpHash"),
            "transient var present as a normal state var; state_vars={:?}",
            c.state_vars.iter().map(|v| &v.name).collect::<Vec<_>>()
        );
        let set = scir.functions_of(c.id).find(|f| f.name == "setHash").expect("setHash");
        assert!(set.effects.writes_var("currentUserOpHash"));
        // Offset preservation: the function span still reads the real source.
        assert!(scir.span_text(set.span).contains("currentUserOpHash = h"));
    }

    #[test]
    fn recovers_transient_without_visibility_and_other_forms() {
        // `<type> transient <name>;` (no visibility) and `mapping(...) transient
        // public m;` are both keyword usages solang rejects; both must recover.
        let scir = parse_one(
            r#"
            pragma solidity ^0.8.28;
            contract T {
                uint256 transient lockCount;
                mapping(address => uint256) transient public deltas;
                function bump() external { lockCount = lockCount + 1; }
            }
            "#,
        );
        let c = scir.contract_named("T").expect("T recovered");
        assert!(c.state_vars.iter().any(|v| v.name == "lockCount"));
        assert!(c.state_vars.iter().any(|v| v.name == "deltas"));
        let bump = scir.functions_of(c.id).find(|f| f.name == "bump").expect("bump");
        assert!(bump.effects.writes_var("lockCount"));
    }

    #[test]
    fn transient_as_variable_name_is_not_blanked() {
        // A variable/function genuinely *named* `transient` already parses in solang
        // (it is followed by `;`/`=`/`(`, not another word). The recovery must leave
        // it intact so the name is preserved.
        let scir = parse_one(
            r#"
            pragma solidity ^0.8.20;
            contract Named {
                uint256 transient;
                uint256 transientInit = 7;
                function transient_fn() external pure returns (uint256) { return 1; }
            }
            "#,
        );
        let c = scir.contract_named("Named").expect("Named parses");
        // The state var literally named `transient` is preserved (NOT blanked away).
        assert!(
            c.state_vars.iter().any(|v| v.name == "transient"),
            "var named `transient` preserved; state_vars={:?}",
            c.state_vars.iter().map(|v| &v.name).collect::<Vec<_>>()
        );
        assert!(c.state_vars.iter().any(|v| v.name == "transientInit"));
        assert!(scir.functions_of(c.id).any(|f| f.name == "transient_fn"));
    }

    #[test]
    fn transient_in_comment_is_not_blanked() {
        // `transient` mentioned only in comments (the common case across v4-core /
        // v4-periphery libraries) must not be touched; the contract parses normally
        // and the comment text is irrelevant to spans.
        let scir = parse_one(
            r#"
            pragma solidity ^0.8.20;
            /// @notice This is a temporary library using transient storage (tstore/tload).
            /* TODO: delete when the transient keyword lands. transient private x; */
            contract LibLike {
                uint256 public count;
                function f() external { count = count + 1; }
            }
            "#,
        );
        let c = scir.contract_named("LibLike").expect("LibLike parses");
        assert!(c.state_vars.iter().any(|v| v.name == "count"));
        let f = scir.functions_of(c.id).find(|f| f.name == "f").expect("f");
        // Offset preservation: span still indexes the original source past the comments.
        assert!(scir.span_text(f.span).contains("count = count + 1"));
    }

    #[test]
    fn transient_recovery_preserves_byte_offsets_and_line_numbers() {
        // The recovery must be exactly offset-preserving: blanking `transient` to
        // equal-length spaces must not move any byte after it, so a finding's line
        // number is identical to what it would be with the keyword absent.
        //
        // We parse two sources that are byte-for-byte identical *except* one uses
        // the `transient` keyword and the other replaces it with the same number of
        // spaces (i.e. the recovery's own output). The recovered function's span —
        // and thus its line number — must match the control exactly.
        let with_kw = concat!(
            "pragma solidity ^0.8.28;\n",
            "contract C {\n",
            "    bytes32 transient private h;\n",
            "    function f(bytes32 x) external { h = x; }\n",
            "}\n",
        );
        // `transient ` (9 chars + 1 space) → 10 spaces, preserving every later offset.
        let control = with_kw.replace("transient ", "          ");
        assert_eq!(with_kw.len(), control.len(), "control must be the same length");

        let scir_kw = parse_one(with_kw);
        let scir_ctl = parse_one(&control);

        let line_kw = {
            let c = scir_kw.contract_named("C").expect("C (transient) parses");
            let f = scir_kw.functions_of(c.id).find(|f| f.name == "f").unwrap();
            scir_kw.line_of(f.span)
        };
        let line_ctl = {
            let c = scir_ctl.contract_named("C").expect("C (control) parses");
            let f = scir_ctl.functions_of(c.id).find(|f| f.name == "f").unwrap();
            scir_ctl.line_of(f.span)
        };
        assert_eq!(line_kw, line_ctl, "transient recovery must not shift line numbers");
        assert_eq!(line_kw, 4, "function f is on source line 4 in both");
    }

    #[test]
    fn transient_recovery_is_noop_when_keyword_absent() {
        // A source with no `transient` keyword must not be transformed at all
        // (returns `None`, no allocation) — guaranteeing zero offset drift for the
        // overwhelmingly common case (and for every existing corpus/real_hacks file).
        let src = "pragma solidity ^0.8.20;\ncontract A { uint256 x; function f() external { x = 1; } }\n";
        assert!(blank_transient_keyword(src).is_none(), "no keyword → no transform");
        // And a `transient` that is purely a substring of an identifier is ignored.
        let ident = "contract B { uint256 transientBalance; }";
        assert!(
            blank_transient_keyword(ident).is_none(),
            "`transientBalance` is one identifier, not the keyword"
        );
    }

    #[test]
    fn recovers_combined_layout_at_and_transient() {
        // A file using *both* the 0.8.29 `layout at` header and a 0.8.28 `transient`
        // var must recover: the two offset-preserving blanks compose.
        let scir = parse_one(
            r#"
            pragma solidity ^0.8.29;
            interface IFoo { function x() external view returns (uint256); }
            contract Combined layout at 151 is IFoo {
                uint256 transient private slotGuard;
                uint256 public x;
                function set(uint256 v) external { x = v; slotGuard = v; }
            }
            "#,
        );
        let c = scir
            .contract_named("Combined")
            .expect("Combined recovered despite `layout at` + `transient`");
        assert!(c.bases.iter().any(|b| b == "IFoo"), "inheritance preserved");
        assert!(c.state_vars.iter().any(|v| v.name == "slotGuard"));
        let set = scir.functions_of(c.id).find(|f| f.name == "set").expect("set");
        assert!(set.effects.writes_var("x"));
        assert!(set.effects.writes_var("slotGuard"));
        assert!(scir.span_text(set.span).contains("x = v"));
    }
}
