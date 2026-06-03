//! Computes [`sluice_ir::FunctionEffects`] from a normalized function body.
//!
//! A single ordered walk assigns a monotonically increasing `order` to each
//! call site and storage access, giving the happens-before relation that
//! checks-effects-interactions / reentrancy analysis needs.

use rustc_hash::FxHashSet;
use sluice_ir::{
    Builtin, Call, CallKind, CallSite, Expr, ExprKind, FunctionEffects, Guard, GuardKind, Lit, Span,
    StorageAccess, Stmt, StmtKind, UnOp,
};

pub struct EffectCollector<'a> {
    state_vars: &'a FxHashSet<String>,
    order: u32,
    unchecked_depth: u32,
    eff: FunctionEffects,
    /// All require/if-revert guards seen, with their order, for leading-guard filtering.
    require_candidates: Vec<(u32, Guard)>,
}

impl<'a> EffectCollector<'a> {
    pub fn new(state_vars: &'a FxHashSet<String>) -> Self {
        Self {
            state_vars,
            order: 0,
            unchecked_depth: 0,
            eff: FunctionEffects::default(),
            require_candidates: Vec::new(),
        }
    }

    pub fn collect(mut self, body: &[Stmt]) -> FunctionEffects {
        self.walk_stmts(body);
        // Keep only require-guards that lead the function (before the first
        // external interaction or state write) — these are entry guards.
        let first_effect = self
            .eff
            .call_sites
            .iter()
            .filter(|c| c.kind.is_external_transfer_of_control())
            .map(|c| c.order)
            .chain(self.eff.storage_writes.iter().map(|w| w.order))
            .min()
            .unwrap_or(u32::MAX);
        for (ord, g) in std::mem::take(&mut self.require_candidates) {
            if ord <= first_effect {
                self.eff.guards.push(g);
            }
        }
        self.eff
    }

    fn next(&mut self) -> u32 {
        let o = self.order;
        self.order += 1;
        o
    }

    fn walk_stmts(&mut self, stmts: &[Stmt]) {
        for s in stmts {
            self.walk_stmt(s);
        }
    }

    fn walk_stmt(&mut self, s: &Stmt) {
        match &s.kind {
            StmtKind::Block { unchecked, stmts } => {
                if *unchecked {
                    self.unchecked_depth += 1;
                }
                self.walk_stmts(stmts);
                if *unchecked {
                    self.unchecked_depth -= 1;
                }
            }
            StmtKind::Expr(e) => {
                // A bare call statement: its return value is not consumed.
                if let ExprKind::Call(c) = &e.kind {
                    self.walk_call(c, e.span, false);
                } else {
                    self.walk_expr(e);
                }
            }
            StmtKind::VarDecl { init, .. } => {
                if let Some(e) = init {
                    self.walk_expr(e);
                }
            }
            StmtKind::If { cond, then_branch, else_branch } => {
                // `if (cond) revert/return;` with no else is a guard.
                if else_branch.is_empty() && is_guard_branch(then_branch) {
                    let ord = self.next();
                    self.require_candidates.push((ord, mk_guard(cond)));
                }
                self.walk_expr(cond);
                self.walk_stmts(then_branch);
                self.walk_stmts(else_branch);
            }
            StmtKind::While { cond, body } => {
                self.eff.has_loop = true;
                self.note_unbounded(cond);
                self.walk_expr(cond);
                self.walk_stmts(body);
            }
            StmtKind::DoWhile { body, cond } => {
                self.eff.has_loop = true;
                self.note_unbounded(cond);
                self.walk_stmts(body);
                self.walk_expr(cond);
            }
            StmtKind::For { init, cond, step, body } => {
                self.eff.has_loop = true;
                if let Some(c) = cond {
                    self.note_unbounded(c);
                }
                if let Some(i) = init {
                    self.walk_stmt(i);
                }
                if let Some(c) = cond {
                    self.walk_expr(c);
                }
                self.walk_stmts(body);
                if let Some(st) = step {
                    self.walk_expr(st);
                }
            }
            StmtKind::Return(Some(e)) => self.walk_expr(e),
            StmtKind::Revert { args, .. } => {
                for a in args {
                    self.walk_expr(a);
                }
            }
            StmtKind::Emit(e) => {
                if let ExprKind::Call(c) = &e.kind {
                    if let Some(n) = &c.func_name {
                        self.eff.emits.push(n.clone());
                    }
                }
                self.walk_expr(e);
            }
            StmtKind::Try { expr, body, catches, .. } => {
                self.walk_expr(expr);
                self.walk_stmts(body);
                for c in catches {
                    self.walk_stmts(&c.body);
                }
            }
            StmtKind::Assembly { sstore_slots, .. } => {
                self.eff.has_assembly = true;
                for slot in sstore_slots {
                    let ord = self.next();
                    self.eff.storage_writes.push(StorageAccess {
                        var: format!("asm:{slot}"),
                        path: "assembly sstore".into(),
                        order: ord,
                        span: s.span,
                    });
                }
            }
            _ => {}
        }
    }

    fn walk_expr(&mut self, e: &Expr) {
        match &e.kind {
            ExprKind::Assign { op, target, value } => {
                use sluice_ir::AssignOp;
                // Evaluate RHS first (so a call in the RHS precedes the write).
                self.walk_expr(value);
                // Compound assignment also reads the target.
                if !matches!(op, AssignOp::Assign) {
                    self.record_read(target);
                }
                self.record_write(target, e.span);
                self.walk_target_indices(target);
            }
            ExprKind::Call(c) => self.walk_call(c, e.span, true),
            ExprKind::Member { base, member } => {
                self.detect_env(base, member);
                self.walk_expr(base);
                self.record_read(e);
            }
            ExprKind::Index { base, index } => {
                self.walk_expr(base);
                if let Some(i) = index {
                    self.walk_expr(i);
                }
                self.record_read(e);
            }
            ExprKind::Ident(_) => self.record_read(e),
            ExprKind::Unary { op, operand } => {
                if matches!(op, UnOp::PreInc | UnOp::PreDec | UnOp::PostInc | UnOp::PostDec | UnOp::Delete)
                {
                    self.record_read(operand);
                    self.record_write(operand, e.span);
                } else {
                    self.walk_expr(operand);
                }
            }
            ExprKind::Binary { op, lhs, rhs } => {
                if self.unchecked_depth > 0 && op.is_arithmetic() {
                    self.eff.has_unchecked_math = true;
                }
                self.walk_expr(lhs);
                self.walk_expr(rhs);
            }
            ExprKind::Ternary { cond, then_e, else_e } => {
                self.walk_expr(cond);
                self.walk_expr(then_e);
                self.walk_expr(else_e);
            }
            ExprKind::Tuple(items) | ExprKind::ArrayLit(items) => {
                for it in items.iter().flatten() {
                    self.walk_expr(it);
                }
            }
            ExprKind::New(inner) => self.walk_expr(inner),
            ExprKind::Lit(_) | ExprKind::TypeName(_) | ExprKind::Unsupported => {}
        }
    }

    fn walk_call(&mut self, c: &Call, span: Span, return_checked: bool) {
        // A `require`/`assert` guard must claim its order BEFORE its condition is
        // walked. An external/internal call *inside* the condition — e.g.
        // `require(msg.sender == authority.governor())` or
        // `require(hasRole(ADMIN, msg.sender))` — would otherwise be assigned an
        // earlier order than the guard, become the function's "first effect", and
        // push the guard past the leading-guard cutoff in `collect()`, silently
        // dropping a real access-control guard (and so under-suppressing every
        // detector that keys on `has_access_control`). Claim the order first, build
        // the guard, then walk the condition (whose nested calls get later orders).
        if matches!(c.kind, CallKind::Builtin(Builtin::Require) | CallKind::Builtin(Builtin::Assert)) {
            let ord = self.next();
            if let Some(cond) = c.args.first() {
                self.require_candidates.push((ord, mk_guard(cond)));
            }
            for a in &c.args {
                self.walk_expr(a);
            }
            return;
        }
        // Walk receiver/args/value first (they are evaluated before the call).
        if let Some(r) = &c.receiver {
            self.walk_expr(r);
        }
        for a in &c.args {
            self.walk_expr(a);
        }
        if let Some(v) = &c.value {
            self.walk_expr(v);
        }

        match c.kind {
            CallKind::Internal => {
                if let Some(n) = &c.func_name {
                    self.eff.internal_calls.push(n.clone());
                }
            }
            CallKind::Builtin(b) => {
                match b {
                    // `Require`/`Assert` are handled at the top of `walk_call` (they
                    // claim their order before their condition is walked).
                    Builtin::ArrayPushPop => {
                        // `arr.push(x)` grows storage — record as a write.
                        if let Some(r) = &c.receiver {
                            if let Some(root) = root_ident(r) {
                                if self.state_vars.contains(root) {
                                    let ord = self.next();
                                    self.eff.storage_writes.push(StorageAccess {
                                        var: root.to_string(),
                                        path: format!("{}.push/pop", ir_text(r)),
                                        order: ord,
                                        span,
                                    });
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            CallKind::TypeCast | CallKind::New | CallKind::Unknown => {}
            kind => {
                // External / low-level / delegatecall / staticcall / send / transfer.
                let ord = self.next();
                let target = c
                    .receiver
                    .as_ref()
                    .map(|r| ir_text(r))
                    .unwrap_or_else(|| ir_text(&c.callee));
                let sends_value = c.value.is_some() || matches!(kind, CallKind::Transfer | CallKind::Send);
                let forwards_gas = matches!(
                    kind,
                    CallKind::External | CallKind::LowLevelCall | CallKind::DelegateCall | CallKind::StaticCall
                ) && c.gas.is_none();
                self.eff.call_sites.push(CallSite {
                    kind,
                    target,
                    func_name: c.func_name.clone(),
                    order: ord,
                    span,
                    return_checked,
                    sends_value,
                    forwards_gas,
                });
            }
        }
    }

    /// Walk only the index sub-expressions of an lvalue (skipping the root read).
    fn walk_target_indices(&mut self, target: &Expr) {
        match &target.kind {
            ExprKind::Index { base, index } => {
                if let Some(i) = index {
                    self.walk_expr(i);
                }
                self.walk_target_indices(base);
            }
            ExprKind::Member { base, .. } => self.walk_target_indices(base),
            _ => {}
        }
    }

    fn record_write(&mut self, target: &Expr, span: Span) {
        if let Some(root) = root_ident(target) {
            if self.state_vars.contains(root) {
                let ord = self.next();
                self.eff.storage_writes.push(StorageAccess {
                    var: root.to_string(),
                    path: ir_text(target),
                    order: ord,
                    span,
                });
            }
        }
    }

    fn record_read(&mut self, e: &Expr) {
        if let Some(root) = root_ident(e) {
            if self.state_vars.contains(root) {
                let ord = self.next();
                self.eff.storage_reads.push(StorageAccess {
                    var: root.to_string(),
                    path: ir_text(e),
                    order: ord,
                    span: e.span,
                });
            }
        }
    }

    fn detect_env(&mut self, base: &Expr, member: &str) {
        if let ExprKind::Ident(b) = &base.kind {
            match (b.as_str(), member) {
                ("msg", "sender") => self.eff.reads_msg_sender = true,
                ("msg", "value") => self.eff.reads_msg_value = true,
                ("tx", "origin") => self.eff.reads_tx_origin = true,
                ("block", "timestamp" | "number" | "prevrandao" | "difficulty" | "coinbase" | "basefee") => {
                    self.eff.reads_block_env = true
                }
                _ => {}
            }
        }
    }

    fn note_unbounded(&mut self, cond: &Expr) {
        let mut unbounded = false;
        cond.visit(&mut |e| {
            if let ExprKind::Member { base, member } = &e.kind {
                if member == "length" {
                    if let Some(root) = root_ident(base) {
                        if self.state_vars.contains(root) {
                            unbounded = true;
                        }
                    }
                }
            }
        });
        if unbounded {
            self.eff.has_unbounded_loop = true;
        }
    }
}

// -------------------------------------------------------------------- helpers

pub fn root_ident(e: &Expr) -> Option<&str> {
    crate::lower::root_ident(e)
}

/// Compact textual rendering of an IR expression (for paths and call targets).
pub fn ir_text(e: &Expr) -> String {
    match &e.kind {
        ExprKind::Ident(n) => n.clone(),
        ExprKind::Member { base, member } => format!("{}.{}", ir_text(base), member),
        ExprKind::Index { base, index } => format!(
            "{}[{}]",
            ir_text(base),
            index.as_ref().map(|i| ir_text(i)).unwrap_or_default()
        ),
        ExprKind::Call(c) => format!("{}(...)", ir_text(&c.callee)),
        ExprKind::Lit(l) => lit_text(l),
        ExprKind::TypeName(t) => t.clone(),
        ExprKind::New(inner) => format!("new {}", ir_text(inner)),
        ExprKind::Unary { operand, .. } => ir_text(operand),
        ExprKind::Binary { lhs, rhs, .. } => format!("{} … {}", ir_text(lhs), ir_text(rhs)),
        ExprKind::Assign { target, value, .. } => format!("{} = {}", ir_text(target), ir_text(value)),
        ExprKind::Ternary { .. } => "<ternary>".into(),
        ExprKind::Tuple(_) => "(…)".into(),
        ExprKind::ArrayLit(_) => "[…]".into(),
        ExprKind::Unsupported => "<expr>".into(),
    }
}

fn lit_text(l: &Lit) -> String {
    match l {
        Lit::Number(n) | Lit::HexNumber(n) | Lit::Other(n) => n.clone(),
        Lit::Bool(b) => b.to_string(),
        Lit::String(s) => format!("\"{s}\""),
        Lit::Address(a) => a.clone(),
        Lit::HexBytes(h) => h.clone(),
    }
}

/// True if a branch body is a single `revert`/`return` (i.e. an inline guard).
fn is_guard_branch(branch: &[Stmt]) -> bool {
    if branch.len() != 1 {
        return false;
    }
    matches!(
        &branch[0].kind,
        StmtKind::Revert { .. } | StmtKind::Return(None) | StmtKind::Return(Some(_))
    )
}

/// Build a guard, classifying it as a msg.sender / tx.origin access-control check
/// when the condition references the caller.
fn mk_guard(cond: &Expr) -> Guard {
    let mut references_sender = false;
    cond.visit(&mut |e| {
        if let ExprKind::Member { base, member } = &e.kind {
            if let ExprKind::Ident(b) = &base.kind {
                if (b == "msg" && member == "sender") || (b == "tx" && member == "origin") {
                    references_sender = true;
                }
            }
        }
    });
    Guard {
        kind: if references_sender { GuardKind::MsgSenderCheck } else { GuardKind::Require },
        text: ir_text(cond),
        span: cond.span,
    }
}
