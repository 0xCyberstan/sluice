//! The `Scir` module container — the root produced by `sluice-parse` and
//! consumed by every analysis pass.

use crate::contract::Contract;
use crate::func::Function;
use crate::ids::{ContractId, FunctionId, Span};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

/// A parsed source file with a precomputed line index for fast offset→(line,col).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFile {
    pub path: String,
    pub content: String,
    /// Byte offset at which each line starts (`line_starts[0] == 0`).
    line_starts: Vec<usize>,
}

impl SourceFile {
    pub fn new(path: impl Into<String>, content: impl Into<String>) -> Self {
        let content = content.into();
        let mut line_starts = vec![0usize];
        for (i, b) in content.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push(i + 1);
            }
        }
        Self { path: path.into(), content, line_starts }
    }

    /// 1-based (line, column) for a byte offset.
    pub fn line_col(&self, offset: usize) -> (usize, usize) {
        let offset = offset.min(self.content.len());
        let line = match self.line_starts.binary_search(&offset) {
            Ok(l) => l,
            Err(l) => l - 1,
        };
        let col = offset - self.line_starts[line] + 1;
        (line + 1, col)
    }

    /// The substring covered by a byte range.
    pub fn slice(&self, start: usize, end: usize) -> &str {
        let start = start.min(self.content.len());
        let end = end.min(self.content.len()).max(start);
        // Clamp to char boundaries to avoid panics on multi-byte UTF-8.
        let start = floor_char_boundary(&self.content, start);
        let end = floor_char_boundary(&self.content, end);
        &self.content[start..end]
    }

    /// The full source line(s) containing a byte range, trimmed.
    pub fn line_text(&self, offset: usize) -> &str {
        let offset = offset.min(self.content.len());
        let line = match self.line_starts.binary_search(&offset) {
            Ok(l) => l,
            Err(l) => l.saturating_sub(1),
        };
        let start = self.line_starts[line];
        let end = self.line_starts.get(line + 1).copied().unwrap_or(self.content.len());
        self.content[start..end].trim_end_matches(['\n', '\r'])
    }
}

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// The root container. Mirrors `vortex_ir::Module`: all entities are stored in
/// hash maps keyed by their IDs for O(1) lookup.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Scir {
    pub files: Vec<SourceFile>,
    pub contracts: FxHashMap<ContractId, Contract>,
    pub functions: FxHashMap<FunctionId, Function>,
    /// Lookup by (last-declared) contract name.
    pub contract_by_name: FxHashMap<String, ContractId>,
    /// The most permissive pragma version string seen (`^0.8.20`, `>=0.7.0`).
    pub pragma_solidity: Option<String>,
    /// Ordered list of contract ids (declaration order across all files).
    pub contract_order: Vec<ContractId>,
}

impl Scir {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contract(&self, id: ContractId) -> Option<&Contract> {
        self.contracts.get(&id)
    }

    pub fn function(&self, id: FunctionId) -> Option<&Function> {
        self.functions.get(&id)
    }

    pub fn contract_named(&self, name: &str) -> Option<&Contract> {
        self.contract_by_name.get(name).and_then(|id| self.contracts.get(id))
    }

    /// All contracts in declaration order.
    pub fn iter_contracts(&self) -> impl Iterator<Item = &Contract> {
        self.contract_order.iter().filter_map(move |id| self.contracts.get(id))
    }

    /// All functions defined in a contract.
    ///
    /// Borrows the contract's function-id list rather than cloning it: this is on
    /// a hot path (detectors call it per-contract, sometimes nested), so the old
    /// per-call `Vec<FunctionId>` clone showed up under load. Yields the exact
    /// same functions in the exact same order, so output is unchanged.
    pub fn functions_of(&self, cid: ContractId) -> impl Iterator<Item = &Function> {
        // Empty static fallback when the contract id is unknown — no allocation.
        const NONE: &[FunctionId] = &[];
        let ids: &[FunctionId] = self.contracts.get(&cid).map(|c| c.functions.as_slice()).unwrap_or(NONE);
        ids.iter().filter_map(move |fid| self.functions.get(fid))
    }

    /// Every function across all contracts.
    pub fn all_functions(&self) -> impl Iterator<Item = &Function> {
        self.functions.values()
    }

    /// Text covered by a span (empty string if out of range).
    pub fn span_text(&self, span: Span) -> &str {
        match self.files.get(span.file as usize) {
            Some(f) => f.slice(span.start as usize, span.end as usize),
            None => "",
        }
    }

    /// 1-based starting line of a span.
    pub fn line_of(&self, span: Span) -> usize {
        match self.files.get(span.file as usize) {
            Some(f) => f.line_col(span.start as usize).0,
            None => 0,
        }
    }

    /// (path, line) for a span — convenient for findings.
    pub fn location(&self, span: Span) -> (String, usize) {
        match self.files.get(span.file as usize) {
            Some(f) => (f.path.clone(), f.line_col(span.start as usize).0),
            None => (String::new(), 0),
        }
    }

    /// The trimmed source line for a span (for finding snippets).
    pub fn line_text(&self, span: Span) -> String {
        match self.files.get(span.file as usize) {
            Some(f) => f.line_text(span.start as usize).trim().to_string(),
            None => String::new(),
        }
    }

    /// Whether the detected pragma guarantees built-in overflow checks (>= 0.8.0).
    pub fn solidity_ge_0_8(&self) -> bool {
        match &self.pragma_solidity {
            Some(p) => pragma_allows_only_ge_0_8(p),
            // Unknown pragma: assume modern (>=0.8) to avoid overflow FPs.
            None => true,
        }
    }
}

/// Best-effort: does this pragma string constrain the compiler to >= 0.8.0?
fn pragma_allows_only_ge_0_8(p: &str) -> bool {
    // Find the first `0.<minor>` and check minor >= 8. Handles `^0.8.x`,
    // `>=0.8.0 <0.9.0`, `0.8.20`, `pragma solidity 0.8.0;` fragments.
    let bytes = p.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'0' && bytes[i + 1] == b'.' {
            // parse minor number
            let mut j = i + 2;
            let mut minor: u32 = 0;
            let mut any = false;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                minor = minor.saturating_mul(10).saturating_add((bytes[j] - b'0') as u32);
                j += 1;
                any = true;
            }
            if any {
                return minor >= 8;
            }
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_col_basic() {
        let f = SourceFile::new("a.sol", "abc\ndef\nghi");
        assert_eq!(f.line_col(0), (1, 1));
        assert_eq!(f.line_col(4), (2, 1));
        assert_eq!(f.line_col(5), (2, 2));
        assert_eq!(f.line_text(5), "def");
    }

    #[test]
    fn pragma_detection() {
        assert!(pragma_allows_only_ge_0_8("^0.8.20"));
        assert!(pragma_allows_only_ge_0_8(">=0.8.0 <0.9.0"));
        assert!(!pragma_allows_only_ge_0_8("^0.7.6"));
        assert!(!pragma_allows_only_ge_0_8("0.6.12"));
    }
}
