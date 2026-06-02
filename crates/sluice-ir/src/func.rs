//! Function model and the per-function effect summary.

use crate::expr::{CallKind, Expr};
use crate::ids::{ContractId, FunctionId, Span};
use crate::stmt::Stmt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Function {
    pub id: FunctionId,
    pub name: String,
    pub contract: ContractId,
    pub kind: FunctionKind,
    pub visibility: Visibility,
    pub mutability: Mutability,
    pub params: Vec<Param>,
    pub returns: Vec<Param>,
    /// Modifiers applied to this function, in source order (`onlyOwner`,
    /// `nonReentrant`, `whenNotPaused`, `initializer`, ...).
    pub modifiers: Vec<ModifierInvocation>,
    pub is_virtual: bool,
    pub is_override: bool,
    /// `true` if a body `{ ... }` was present (interfaces / abstract decls are `false`).
    pub has_body: bool,
    /// Normalized statement tree of the body.
    pub body: Vec<Stmt>,
    /// Canonical signature `name(t1,t2,...)` used for selectors / cross-refs.
    pub signature: String,
    pub span: Span,
    /// Precomputed effect summary (filled by `sluice-parse`).
    pub effects: FunctionEffects,
    /// Resolved internal callees (best-effort) for SCC ordering.
    pub callees: Vec<FunctionId>,
    /// Resolved internal callers (best-effort).
    pub callers: Vec<FunctionId>,
}

impl Function {
    /// Reachable by an external actor (the precondition for most attacks).
    pub fn is_externally_reachable(&self) -> bool {
        matches!(self.visibility, Visibility::Public | Visibility::External)
            || matches!(self.kind, FunctionKind::Fallback | FunctionKind::Receive)
    }

    pub fn is_modifier(&self) -> bool {
        matches!(self.kind, FunctionKind::Modifier)
    }

    pub fn is_constructor(&self) -> bool {
        matches!(self.kind, FunctionKind::Constructor)
    }

    /// Can read/write state (not `view`/`pure`).
    pub fn is_state_mutating(&self) -> bool {
        matches!(self.mutability, Mutability::NonPayable | Mutability::Payable)
    }

    pub fn is_view_or_pure(&self) -> bool {
        matches!(self.mutability, Mutability::View | Mutability::Pure)
    }

    pub fn is_payable(&self) -> bool {
        matches!(self.mutability, Mutability::Payable)
    }

    /// True if a modifier with the given (case-insensitive substring) name is applied.
    pub fn has_modifier_like(&self, needle: &str) -> bool {
        let needle = needle.to_ascii_lowercase();
        self.modifiers
            .iter()
            .any(|m| m.name.to_ascii_lowercase().contains(&needle))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FunctionKind {
    Function,
    Constructor,
    Fallback,
    Receive,
    Modifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Visibility {
    Public,
    External,
    Internal,
    Private,
    /// No explicit visibility (legacy default `public` for functions).
    Default,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Mutability {
    NonPayable,
    Payable,
    View,
    Pure,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Param {
    pub name: Option<String>,
    /// Textual type (`uint256`, `address`, `IERC20`, `bytes calldata`).
    pub ty: String,
    /// Storage location (`memory`/`storage`/`calldata`), if present.
    pub location: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModifierInvocation {
    pub name: String,
    pub args: Vec<Expr>,
    pub span: Span,
}

/// A precomputed summary of a function's security-relevant effects. This is the
/// analog of `vortex`'s function summaries: it lets the consensus and frontier
/// passes reason about a function without re-walking its body.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FunctionEffects {
    /// State variables read (with best-effort access path).
    pub storage_reads: Vec<StorageAccess>,
    /// State variables written (with best-effort access path).
    pub storage_writes: Vec<StorageAccess>,
    /// Classified external/low-level call sites, in source order.
    pub call_sites: Vec<CallSite>,
    /// Names of internal functions invoked.
    pub internal_calls: Vec<String>,
    /// Entry-level guards (modifiers + leading `require`s).
    pub guards: Vec<Guard>,
    /// Events emitted.
    pub emits: Vec<String>,
    pub reads_msg_sender: bool,
    pub reads_msg_value: bool,
    pub reads_tx_origin: bool,
    pub reads_block_env: bool,
    /// Contains at least one loop.
    pub has_loop: bool,
    /// Loops whose bound references a (potentially attacker-growable) array length.
    pub has_unbounded_loop: bool,
    pub has_assembly: bool,
    /// Performs raw arithmetic inside an `unchecked { }` block.
    pub has_unchecked_math: bool,
}

impl FunctionEffects {
    pub fn writes_var(&self, name: &str) -> bool {
        self.storage_writes.iter().any(|a| a.var == name)
    }
    pub fn reads_var(&self, name: &str) -> bool {
        self.storage_reads.iter().any(|a| a.var == name)
    }
    /// The set of distinct state variables written.
    pub fn written_vars(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.storage_writes.iter().map(|a| a.var.as_str()).collect();
        v.sort_unstable();
        v.dedup();
        v
    }
    /// First call site (by order) that transfers control to an external party.
    pub fn first_external_call(&self) -> Option<&CallSite> {
        self.call_sites
            .iter()
            .filter(|c| c.kind.is_external_transfer_of_control())
            .min_by_key(|c| c.order)
    }
    /// True if any state write happens *after* an external call in source order
    /// (the raw signal for a checks-effects-interactions violation).
    pub fn has_write_after_external_call(&self) -> bool {
        if let Some(first) = self.first_external_call() {
            self.storage_writes.iter().any(|w| w.order > first.order)
        } else {
            false
        }
    }
}

/// A read or write of contract storage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageAccess {
    /// The base state variable name (`balances`, `totalSupply`).
    pub var: String,
    /// Best-effort full access path (`balances[msg.sender]`).
    pub path: String,
    /// Sequential position within the function (shared ordering with call sites).
    pub order: u32,
    pub span: Span,
}

/// A classified call site.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallSite {
    pub kind: CallKind,
    /// Textual target (`token`, `msg.sender`, `pool`, `address(this)`).
    pub target: String,
    /// Resolved method name, if any.
    pub func_name: Option<String>,
    /// Sequential position within the function.
    pub order: u32,
    pub span: Span,
    /// Best-effort: is the return value checked (used in a `require`/`if`/assignment)?
    pub return_checked: bool,
    /// Sends native ETH (via `{value:}`, `.transfer`, or `.send`).
    pub sends_value: bool,
    /// Forwards all gas (no `{gas:}` stipend) — relevant to reentrancy feasibility.
    pub forwards_gas: bool,
}

/// An entry-level authorization / state guard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Guard {
    pub kind: GuardKind,
    /// The textual guard (`onlyOwner`, `require(msg.sender == owner)`).
    pub text: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GuardKind {
    /// A modifier was applied (carries the modifier name).
    Modifier(String),
    /// A leading `require(...)` / `if (...) revert`.
    Require,
    /// A `require`/`if` that compares against `msg.sender` (access control).
    MsgSenderCheck,
    /// An `initializer` / `reinitializer` modifier (upgradeable init guard).
    Initializer,
    /// A reentrancy lock modifier (`nonReentrant`, `lock`, mutex).
    ReentrancyLock,
    /// A pause guard (`whenNotPaused`).
    PauseCheck,
}
