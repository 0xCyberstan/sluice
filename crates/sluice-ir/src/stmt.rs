//! Normalized statement model.
//!
//! Solidity's structured control flow is preserved as a statement tree (rather
//! than lowered to a basic-block CFG with phi nodes as `vortex` does for machine
//! code). For source-level heuristic and data-flow analysis a normalized tree,
//! plus the per-function [`crate::func::FunctionEffects`] summary and a
//! happens-before ordering on call sites, is both sufficient and far less
//! error-prone than reconstructing SSA from already-structured source.

use crate::expr::Expr;
use crate::ids::Span;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stmt {
    pub span: Span,
    pub kind: StmtKind,
}

impl Stmt {
    pub fn new(span: Span, kind: StmtKind) -> Self {
        Self { span, kind }
    }

    /// Visit this statement and all nested statements (pre-order).
    pub fn visit<'a>(&'a self, f: &mut impl FnMut(&'a Stmt)) {
        f(self);
        match &self.kind {
            StmtKind::If { then_branch, else_branch, .. } => {
                for s in then_branch {
                    s.visit(f);
                }
                for s in else_branch {
                    s.visit(f);
                }
            }
            StmtKind::While { body, .. }
            | StmtKind::DoWhile { body, .. }
            | StmtKind::For { body, .. }
            | StmtKind::Block { stmts: body, .. } => {
                for s in body {
                    s.visit(f);
                }
            }
            StmtKind::Try { body, catches, .. } => {
                for s in body {
                    s.visit(f);
                }
                for c in catches {
                    for s in &c.body {
                        s.visit(f);
                    }
                }
            }
            _ => {}
        }
    }

    /// Visit every expression contained (transitively) in this statement.
    pub fn visit_exprs<'a>(&'a self, f: &mut impl FnMut(&'a Expr)) {
        self.visit(&mut |s| match &s.kind {
            StmtKind::Expr(e) | StmtKind::Emit(e) => e.visit(f),
            StmtKind::VarDecl { init: Some(e), .. } => e.visit(f),
            StmtKind::Return(Some(e)) => e.visit(f),
            StmtKind::If { cond, .. } | StmtKind::While { cond, .. } | StmtKind::DoWhile { cond, .. } => {
                cond.visit(f)
            }
            StmtKind::For { cond, step, .. } => {
                if let Some(c) = cond {
                    c.visit(f);
                }
                if let Some(st) = step {
                    st.visit(f);
                }
            }
            StmtKind::Revert { args, .. } => {
                for a in args {
                    a.visit(f);
                }
            }
            StmtKind::Try { expr, .. } => expr.visit(f),
            _ => {}
        });
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StmtKind {
    /// A bare expression statement (most calls live here).
    Expr(Expr),
    /// `T x [= init];`
    VarDecl { name: Option<String>, ty: String, init: Option<Expr> },
    /// `if (cond) { then } else { else }`
    If { cond: Expr, then_branch: Vec<Stmt>, else_branch: Vec<Stmt> },
    /// `while (cond) { body }`
    While { cond: Expr, body: Vec<Stmt> },
    /// `do { body } while (cond);`
    DoWhile { body: Vec<Stmt>, cond: Expr },
    /// `for (init; cond; step) { body }`
    For {
        init: Option<Box<Stmt>>,
        cond: Option<Expr>,
        step: Option<Expr>,
        body: Vec<Stmt>,
    },
    /// `return [e];`
    Return(Option<Expr>),
    /// `revert [Error](args);`
    Revert { error: Option<String>, args: Vec<Expr> },
    /// `emit Event(args);`
    Emit(Expr),
    /// `{ ... }`, with `unchecked` flag for `unchecked { ... }`.
    Block { unchecked: bool, stmts: Vec<Stmt> },
    /// `try expr returns (...) { body } catch ... { ... }`
    Try {
        expr: Expr,
        returns: Vec<String>,
        body: Vec<Stmt>,
        catches: Vec<CatchClause>,
    },
    /// Inline assembly. We capture a best-effort summary rather than full Yul.
    Assembly {
        /// Slots written via `sstore` (textual, best-effort).
        sstore_slots: Vec<String>,
        /// Whether the block contains a `call`/`delegatecall`/`staticcall`.
        has_call: bool,
        /// Whether the block contains `return`/`revert`/`selfdestruct`.
        has_terminator: bool,
    },
    /// `break;`
    Break,
    /// `continue;`
    Continue,
    /// `_;` placeholder inside a modifier body.
    Placeholder,
    /// Unmodeled statement.
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatchClause {
    /// e.g. `Error`, `Panic`, or `None` for the catch-all.
    pub selector: Option<String>,
    pub param: Option<String>,
    pub body: Vec<Stmt>,
}
