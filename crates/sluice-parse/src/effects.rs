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
                    // A standalone call-statement guard, e.g.
                    // `UtilLib.onlyOperatorRole(msg.sender, staderConfig);` or
                    // `_checkOwner();` / `onlyRole(ADMIN_ROLE, msg.sender);`. Such a
                    // call *is* the access-control check, but it is neither a
                    // `require`/`assert` nor an `if (...) revert` and carries no
                    // access-control modifier, so it was previously invisible to
                    // `has_access_control`. Recognize the common idioms and record a
                    // leading `MsgSenderCheck` guard with the same representation a
                    // `require(msg.sender == ...)` produces. Claim the order *before*
                    // walking the call so any nested effect inside its arguments gets
                    // a later order and cannot push the guard past the leading cutoff.
                    if let Some(g) = call_stmt_access_guard(c, e.span) {
                        let ord = self.next();
                        self.require_candidates.push((ord, g));
                    }
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

/// True if an expression *is* a reference to the caller — either the `msg.sender`
/// / `tx.origin` member access, or the OpenZeppelin / ERC-2771 `Context` accessor
/// `_msgSender()` / `msgSender()` (which returns `msg.sender`). Matched exactly and
/// only as the zero-argument accessor named `_msgSender`/`msgSender`, never an
/// arbitrary function, so a guard like `require(_msgSender() == owner())` or
/// `if (_msgSender() != admin) revert` is recognized as a caller check.
fn expr_is_caller(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Member { base, member } => {
            matches!(&base.kind, ExprKind::Ident(b)
                if (b == "msg" && member == "sender") || (b == "tx" && member == "origin"))
        }
        ExprKind::Call(c) => {
            c.args.is_empty()
                && c.receiver.is_none()
                && matches!(c.func_name.as_deref(), Some("_msgSender") | Some("msgSender"))
        }
        _ => false,
    }
}

/// Build a guard, classifying it as a msg.sender / tx.origin access-control check
/// when the condition references the caller.
fn mk_guard(cond: &Expr) -> Guard {
    let mut references_sender = false;
    cond.visit(&mut |e| {
        if expr_is_caller(e) {
            references_sender = true;
        }
    });
    Guard {
        kind: if references_sender { GuardKind::MsgSenderCheck } else { GuardKind::Require },
        text: ir_text(cond),
        span: cond.span,
    }
}

/// Unwrap surrounding identity-like casts so `address(msg.sender)` /
/// `payable(msg.sender)` (or nestings thereof) still expose the `msg.sender`
/// member access underneath. Only the single-argument `address`/`payable` casts
/// are unwrapped — an arbitrary call is left intact.
fn unwrap_caller_casts(e: &Expr) -> &Expr {
    if let ExprKind::Call(c) = &e.kind {
        let is_cast = matches!(c.kind, CallKind::TypeCast)
            || matches!(c.func_name.as_deref(), Some("address") | Some("payable"));
        if is_cast && c.receiver.is_none() && c.args.len() == 1 {
            return unwrap_caller_casts(&c.args[0]);
        }
    }
    e
}

/// True if any argument of the call references the caller (`msg.sender` /
/// `tx.origin` / the OZ `_msgSender()` accessor), seen through `address(...)` /
/// `payable(...)` casts and anywhere inside the argument subtree.
fn args_mention_caller(c: &Call) -> bool {
    c.args.iter().any(|a| {
        let mut found = false;
        unwrap_caller_casts(a).visit(&mut |e| {
            if expr_is_caller(unwrap_caller_casts(e)) {
                found = true;
            }
        });
        found
    })
}

/// Classify a callee name as an access-control guard shape.
///
/// Two tiers, deliberately asymmetric for precision:
/// * `only`-prefixed names (`onlyOwner`, `onlyOperatorRole`, `onlyRole`,
///   `onlyGovernor`, …) are a strong, near-unambiguous access-control idiom —
///   matched on the name alone, mirroring how an `only*` *modifier* is classified
///   as a `MsgSenderCheck` in `classify_modifier`.
/// * `check`/`validate`/`require`/`assert`-prefixed names are far more generic
///   (`checkBalance`, `validateAmount`, `requireGtZero`), so they only qualify
///   when the name *also* carries a strong authorization token
///   (`role`/`auth`/`owner`/`admin`/`access`/`caller`/`governor`/`guardian` — a
///   bare `sender` token is excluded as too weak). These still additionally
///   require a `msg.sender` argument at the call site (enforced by the caller),
///   so a name match alone never promotes them.
///
/// Returns `true` for tier-1 (`only`-prefixed) names, and for tier-2 names that
/// pair an auth verb with an auth token. The boolean in the tuple is
/// `requires_sender_arg`: tier-1 may be recognized without a `msg.sender` arg
/// (matching modifier behavior); tier-2 must have one.
fn access_name_shape(name: &str) -> Option<bool> {
    let l = name.trim_start_matches('_').to_ascii_lowercase();
    // Tier 1: `only*` — strong on its own, no argument requirement.
    if l.starts_with("only") {
        return Some(false);
    }
    // Tier 2: an auth *verb* prefix paired with an auth *token*.
    let has_verb = l.starts_with("check")
        || l.starts_with("validate")
        || l.starts_with("require")
        || l.starts_with("assert")
        || l.starts_with("enforce")
        || l.starts_with("verify");
    // NB: deliberately NOT keyed on a bare `sender` token. An auth verb combined
    // with `sender` (`_requireSender(addr)`, `assertSenderBalance(...)`) describes
    // a generic input-validation helper as often as a real authorization check,
    // so the `sender` token alone is too weak to promote a call to an
    // access-control guard. The strong access tokens below cover every real
    // auth-helper idiom (`requireAuth`, `validateCaller`, `checkRole`,
    // `_checkOwner`); a genuine caller check is still distinguished by its
    // `msg.sender` *argument*, which is what the call-site check enforces.
    let has_token = l.contains("role")
        || l.contains("auth")
        || l.contains("owner")
        || l.contains("admin")
        || l.contains("access")
        || l.contains("caller")
        || l.contains("governor")
        || l.contains("guardian");
    if has_verb && has_token {
        return Some(true);
    }
    None
}

/// If a bare call statement is a standalone access-control guard
/// (`UtilLib.onlyOperatorRole(msg.sender, cfg)`, `onlyRole(ADMIN, msg.sender)`,
/// `_checkOwner()`, `validateCaller(msg.sender)`), build the corresponding leading
/// `MsgSenderCheck` guard. Returns `None` for ordinary business calls.
///
/// Precision rules:
/// * The callee name must match an access-control shape (`access_name_shape`).
/// * `only`-prefixed names match on the name alone (mirroring `only*` modifiers).
/// * Every other shape additionally requires a `msg.sender`/`tx.origin` argument,
///   so `transfer(msg.sender, amt)` (no auth name) and `checkBalance(x)` (auth verb
///   but no auth token / no caller arg) are both left as plain calls.
/// * Only `Internal`/`External`/`Unknown` call kinds are considered — builtins,
///   casts, `new`, and value-/gas-bearing calls are never guards.
fn call_stmt_access_guard(c: &Call, span: Span) -> Option<Guard> {
    if !matches!(c.kind, CallKind::Internal | CallKind::External | CallKind::Unknown) {
        return None;
    }
    // A guard call neither sends value nor forwards an explicit gas stipend.
    if c.value.is_some() || c.gas.is_some() {
        return None;
    }
    let name = c.func_name.as_deref()?;
    let requires_sender_arg = access_name_shape(name)?;
    if requires_sender_arg && !args_mention_caller(c) {
        return None;
    }
    Some(Guard {
        kind: GuardKind::MsgSenderCheck,
        text: format!("{}(…)", ir_text(&c.callee)),
        span,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sluice_ir::BinOp;

    fn ident(n: &str) -> Expr {
        Expr::dummy(ExprKind::Ident(n.into()))
    }

    /// `msg.sender` (or `tx.origin`) member access.
    fn member(base: &str, m: &str) -> Expr {
        Expr::dummy(ExprKind::Member { base: Box::new(ident(base)), member: m.into() })
    }

    /// A zero-arg, no-receiver internal call `name()` (e.g. `_msgSender()`, `owner()`).
    fn zero_arg_call(name: &str) -> Expr {
        Expr::dummy(ExprKind::Call(Call {
            callee: Box::new(ident(name)),
            receiver: None,
            func_name: Some(name.into()),
            args: vec![],
            value: None,
            gas: None,
            kind: CallKind::Internal,
        }))
    }

    fn cmp(op: BinOp, lhs: Expr, rhs: Expr) -> Expr {
        Expr::dummy(ExprKind::Binary { op, lhs: Box::new(lhs), rhs: Box::new(rhs) })
    }

    #[test]
    fn msg_sender_member_is_caller_check() {
        // `msg.sender == owner` — the existing behavior must be preserved.
        let g = mk_guard(&cmp(BinOp::Eq, member("msg", "sender"), ident("owner")));
        assert_eq!(g.kind, GuardKind::MsgSenderCheck, "msg.sender comparison");

        // `tx.origin != owner` — still a caller check.
        let g = mk_guard(&cmp(BinOp::Ne, member("tx", "origin"), ident("owner")));
        assert_eq!(g.kind, GuardKind::MsgSenderCheck, "tx.origin comparison");
    }

    #[test]
    fn msg_sender_accessor_is_caller_check() {
        // `_msgSender() != owner()` — the OZ Context accessor must classify as a
        // MsgSenderCheck (regression: CometProxyAdmin.setMarketAdminPermissionChecker
        // `if (_msgSender() != owner()) revert Unauthorized();` was seen as unguarded).
        let g = mk_guard(&cmp(BinOp::Ne, zero_arg_call("_msgSender"), zero_arg_call("owner")));
        assert_eq!(
            g.kind,
            GuardKind::MsgSenderCheck,
            "_msgSender() != owner() must be a MsgSenderCheck; got {:?}",
            g.kind
        );

        // `require(_msgSender() == admin)` — the `== admin` shape too.
        let g = mk_guard(&cmp(BinOp::Eq, zero_arg_call("_msgSender"), ident("admin")));
        assert_eq!(g.kind, GuardKind::MsgSenderCheck, "_msgSender() == admin");

        // ERC-2771 spelling without the leading underscore.
        let g = mk_guard(&cmp(BinOp::Eq, zero_arg_call("msgSender"), ident("admin")));
        assert_eq!(g.kind, GuardKind::MsgSenderCheck, "msgSender() == admin");
    }

    #[test]
    fn non_caller_comparison_is_plain_require() {
        // `amount >= minAmount` — no caller reference, stays a plain Require.
        let g = mk_guard(&cmp(BinOp::Ge, ident("amount"), ident("minAmount")));
        assert_eq!(g.kind, GuardKind::Require, "non-caller guard stays Require");
    }

    #[test]
    fn arbitrary_zero_arg_call_is_not_a_caller() {
        // Precision: an unrelated zero-arg accessor (`owner()`, `paused()`) compared
        // against a constant must NOT be mistaken for a caller check.
        let g = mk_guard(&cmp(BinOp::Eq, zero_arg_call("paused"), Expr::dummy(ExprKind::Lit(Lit::Bool(false)))));
        assert_eq!(g.kind, GuardKind::Require, "paused() is not a caller reference");
        assert!(!expr_is_caller(&zero_arg_call("owner")), "owner() is not the caller");
    }

    #[test]
    fn msg_sender_named_member_call_is_not_accessor() {
        // Precision: `something.msgSender(...)` (a *member* call with a receiver, or
        // any call carrying arguments) is not the zero-arg OZ accessor.
        let with_receiver = Expr::dummy(ExprKind::Call(Call {
            callee: Box::new(member("ctx", "msgSender")),
            receiver: Some(Box::new(ident("ctx"))),
            func_name: Some("msgSender".into()),
            args: vec![],
            value: None,
            gas: None,
            kind: CallKind::External,
        }));
        assert!(!expr_is_caller(&with_receiver), "receiver-qualified msgSender() is not the accessor");

        let with_args = Expr::dummy(ExprKind::Call(Call {
            callee: Box::new(ident("_msgSender")),
            receiver: None,
            func_name: Some("_msgSender".into()),
            args: vec![ident("x")],
            value: None,
            gas: None,
            kind: CallKind::Internal,
        }));
        assert!(!expr_is_caller(&with_args), "_msgSender(x) with an arg is not the zero-arg accessor");
    }

    // ------------------------------------------------ bare call-statement guards

    /// `Lib.fn(args...)` — a member call (external/library) named `fn` on `lib`.
    fn member_call(lib: &str, fn_name: &str, args: Vec<Expr>) -> Call {
        Call {
            callee: Box::new(member(lib, fn_name)),
            receiver: Some(Box::new(ident(lib))),
            func_name: Some(fn_name.into()),
            args,
            value: None,
            gas: None,
            kind: CallKind::External,
        }
    }

    /// `fn(args...)` — a free / internal call named `fn`.
    fn free_call(fn_name: &str, args: Vec<Expr>) -> Call {
        Call {
            callee: Box::new(ident(fn_name)),
            receiver: None,
            func_name: Some(fn_name.into()),
            args,
            value: None,
            gas: None,
            kind: CallKind::Internal,
        }
    }

    fn cast(name: &str, inner: Expr) -> Expr {
        Expr::dummy(ExprKind::Call(Call {
            callee: Box::new(ident(name)),
            receiver: None,
            func_name: Some(name.into()),
            args: vec![inner],
            value: None,
            gas: None,
            kind: CallKind::TypeCast,
        }))
    }

    #[test]
    fn lib_only_role_call_is_access_guard() {
        // `UtilLib.onlyOperatorRole(msg.sender, staderConfig);` — the Stader idiom.
        let c = member_call("UtilLib", "onlyOperatorRole", vec![member("msg", "sender"), ident("staderConfig")]);
        let g = call_stmt_access_guard(&c, Span::dummy()).expect("recognized");
        assert_eq!(g.kind, GuardKind::MsgSenderCheck);
    }

    #[test]
    fn only_role_sender_second_arg_is_access_guard() {
        // `onlyRole(ADMIN_ROLE, msg.sender);` — caller in the *second* position.
        let c = free_call("onlyRole", vec![ident("ADMIN_ROLE"), member("msg", "sender")]);
        let g = call_stmt_access_guard(&c, Span::dummy()).expect("recognized");
        assert_eq!(g.kind, GuardKind::MsgSenderCheck);
    }

    #[test]
    fn only_prefixed_call_without_sender_arg_is_access_guard() {
        // `onlyGovernor();` — a tier-1 `only*` call invoked as a bare statement (some
        // codebases call a modifier-like internal guard as a plain function). Tier-1
        // names are recognized on the name alone, mirroring how an `only*` *modifier*
        // classifies as MsgSenderCheck even with no visible argument.
        let c = free_call("onlyGovernor", vec![]);
        let g = call_stmt_access_guard(&c, Span::dummy()).expect("recognized");
        assert_eq!(g.kind, GuardKind::MsgSenderCheck);
    }

    #[test]
    fn check_owner_no_arg_is_access_guard_via_token() {
        // `_checkOwner();` — tier-2 verb (`check`) + token (`owner`). DESIGN CHOICE:
        // tier-2 normally requires a `msg.sender` arg, but `_checkOwner()` is the
        // canonical OZ `Ownable._checkOwner()` accessor that reads `_msgSender()`
        // internally and takes no argument. We do NOT special-case it: with no
        // caller argument it is NOT recognized here, to keep tier-2 tight. (The OZ
        // `onlyOwner` *modifier* path already covers the real usage.)
        let c = free_call("_checkOwner", vec![]);
        assert!(
            call_stmt_access_guard(&c, Span::dummy()).is_none(),
            "tier-2 _checkOwner() with no caller arg is intentionally not promoted"
        );
        // With an explicit caller arg it IS recognized.
        let c = free_call("_checkOwner", vec![member("msg", "sender")]);
        assert!(call_stmt_access_guard(&c, Span::dummy()).is_some(), "_checkOwner(msg.sender) recognized");
    }

    #[test]
    fn validate_caller_with_sender_is_access_guard() {
        // `validateCaller(msg.sender);` — verb (`validate`) + token (`caller`) + arg.
        let c = free_call("validateCaller", vec![member("msg", "sender")]);
        assert!(call_stmt_access_guard(&c, Span::dummy()).is_some());
    }

    #[test]
    fn caller_arg_through_address_cast_is_recognized() {
        // `requireAuth(address(msg.sender));` — caller wrapped in an `address(...)`
        // cast must still be seen.
        let c = free_call("requireAuth", vec![cast("address", member("msg", "sender"))]);
        assert!(call_stmt_access_guard(&c, Span::dummy()).is_some());
    }

    #[test]
    fn require_sender_helper_is_not_guard() {
        // `_requireSender(msg.sender);` — verb (`require`) + caller arg, but the only
        // token is `sender`, which is intentionally NOT a strong auth token. Generic
        // helpers (`_requireSender(addr)`, `assertSenderBalance(...)`) share this
        // shape, so it is left as a plain call rather than promoted to a guard.
        let c = free_call("_requireSender", vec![member("msg", "sender")]);
        assert!(
            call_stmt_access_guard(&c, Span::dummy()).is_none(),
            "_requireSender(msg.sender): bare `sender` token is too weak to promote"
        );
    }

    #[test]
    fn business_call_with_sender_is_not_guard() {
        // `transfer(msg.sender, amt);` — a caller arg but NO access-control name.
        let c = free_call("transfer", vec![member("msg", "sender"), ident("amt")]);
        assert!(
            call_stmt_access_guard(&c, Span::dummy()).is_none(),
            "transfer(msg.sender, amt) is a business call, not a guard"
        );
    }

    #[test]
    fn check_balance_without_token_is_not_guard() {
        // `checkBalance(msg.sender);` — verb but no auth token → not a guard.
        let c = free_call("checkBalance", vec![member("msg", "sender")]);
        assert!(call_stmt_access_guard(&c, Span::dummy()).is_none());
    }

    #[test]
    fn tier2_role_name_without_sender_arg_is_not_guard() {
        // `checkRole(SOME_ROLE);` — auth name but no caller arg → not promoted.
        let c = free_call("checkRole", vec![ident("SOME_ROLE")]);
        assert!(
            call_stmt_access_guard(&c, Span::dummy()).is_none(),
            "tier-2 checkRole without a caller arg is not promoted"
        );
        // `checkRole(SOME_ROLE, msg.sender);` — with the caller arg it IS.
        let c = free_call("checkRole", vec![ident("SOME_ROLE"), member("msg", "sender")]);
        assert!(call_stmt_access_guard(&c, Span::dummy()).is_some());
    }

    #[test]
    fn value_or_gas_bearing_call_is_not_guard() {
        // A call that sends value / forwards gas is an interaction, never a guard,
        // even if its name happens to start with `only`.
        let mut c = free_call("onlyOwner", vec![]);
        c.value = Some(Box::new(Expr::dummy(ExprKind::Lit(Lit::Number("1".into())))));
        assert!(call_stmt_access_guard(&c, Span::dummy()).is_none());
    }

    /// End-to-end: a function whose only access check is a bare library call must
    /// expose a leading `MsgSenderCheck` guard in its computed effects (this is
    /// exactly what `has_access_control` consumes — the Stader M-03 root cause).
    #[test]
    fn bare_lib_guard_yields_leading_msg_sender_check() {
        let state: FxHashSet<String> = FxHashSet::default();
        // Statement: `UtilLib.onlyOperatorRole(msg.sender, staderConfig);`
        let call = member_call("UtilLib", "onlyOperatorRole", vec![member("msg", "sender"), ident("staderConfig")]);
        let stmt = Stmt {
            kind: StmtKind::Expr(Expr::dummy(ExprKind::Call(call))),
            span: Span::dummy(),
        };
        let eff = EffectCollector::new(&state).collect(&[stmt]);
        assert!(
            eff.guards.iter().any(|g| matches!(g.kind, GuardKind::MsgSenderCheck)),
            "bare library access-control call must record a leading MsgSenderCheck guard; got {:?}",
            eff.guards
        );
    }
}
