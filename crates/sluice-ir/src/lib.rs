//! # sluice-ir
//!
//! **SCIR** — the Smart-Contract Intermediate Representation shared by every
//! Sluice analysis pass. It is the frozen contract of the workspace: the parser
//! produces it, the dataflow/invariant/frontier passes consume it, and detectors
//! read it.
//!
//! Design (adapted from `vortex-ir`, but for Solidity *source* rather than
//! lifted machine code):
//!
//! * **Pre-classified calls.** Every call is tagged with a [`CallKind`]
//!   (internal / external / low-level / delegatecall / transfer / cast /
//!   builtin) so detectors get the trust-frontier signal for free.
//! * **Value-source provenance.** [`ValueSource`] labels where a value comes
//!   from (attacker input, external return, price-like read, block env, ...),
//!   the smart-contract analog of `vortex`'s entropy sources.
//! * **Per-function effect summaries.** [`FunctionEffects`] precomputes storage
//!   reads/writes, ordered call sites, and entry guards — the substrate for
//!   consensus-invariant mining and checks-effects-interactions analysis.

pub mod contract;
pub mod expr;
pub mod func;
pub mod ids;
pub mod module;
pub mod stmt;

// ---- Re-exports: the public vocabulary of the IR. ----
pub use contract::{Contract, ContractKind, StateVar, UsingDirective};
pub use expr::{AssignOp, BinOp, Builtin, Call, CallKind, Expr, ExprKind, Lit, UnOp, ValueSource};
pub use func::{
    CallSite, Function, FunctionEffects, FunctionKind, Guard, GuardKind, ModifierInvocation, Mutability,
    Param, StorageAccess, Visibility,
};
pub use ids::{ContractId, FunctionId, Span};
pub use module::{Scir, SourceFile};
pub use stmt::{CatchClause, Stmt, StmtKind};
