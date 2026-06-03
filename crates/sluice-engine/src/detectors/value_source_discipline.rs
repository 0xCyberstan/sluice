//! **Value-source discipline** — a value credited to a caller must derive from a
//! *tracked accounting var*, not a live raw-balance read (the LoopFi H-01 class).
//!
//! ## The class
//!
//! A protocol that mints/transfers a token to a caller, or credits a per-user
//! ledger slot, must size that credit from its own *bookkeeping* — the staked
//! principal, the share supply, the recorded balance — i.e. a **tracked** state
//! variable. Sizing the credit instead from a **live read of the contract's own
//! balance** (`address(this).balance`, `balanceOf(address(this))`) folds *any*
//! unrelated inflow into one caller's credit: a prior balance, a second caller's
//! in-flight funds, dust, a forced send. The crediting caller walks away with
//! more than their accounting entitlement, at every other user's expense.
//!
//! The motivating real instance is **LoopFi `PrelaunchPoints._claim`**
//! (`2024-05-loop`, H-01). Its token branch does:
//!
//! ```solidity
//! _fillQuote(IERC20(_token), userClaim, _data);          // swap token -> ETH
//! claimedAmount = address(this).balance;                 // (!) live self-balance
//! lpETH.deposit{value: claimedAmount}(_receiver);        // credited to the caller
//! ```
//!
//! so `claimedAmount` is the *entire* contract balance, not the swap's actual
//! output — any ETH already in the contract (or another claimer's funds) is
//! minted 1:1 to this `_receiver`. The **ETH branch of the same function** sizes
//! the credit correctly from tracked vars:
//!
//! ```solidity
//! claimedAmount = userStake.mulDiv(totalLpETH, totalSupply);  // tracked
//! lpETH.safeTransfer(_receiver, claimedAmount);
//! ```
//!
//! That sibling branch is the cleanest possible corroborator: the contract itself
//! demonstrates the disciplined idiom one branch over.
//!
//! ## What fires (predicate, design §3)
//!
//!   1. A **credit sink** — a `mint`/`deposit{value:}`/`call{value:}`/`safe
//!      Transfer`/`transfer`/per-user-slot write (`M[caller] = …` / `+=`) whose
//!      **recipient** is caller-influenced (a parameter or a `msg.sender`-derived
//!      value), and
//!   2. the credited **amount** `A` satisfies `credited_value_provenance(A)
//!      .is_undisciplined_self_balance()` — it derives from a live self-balance
//!      read and **not** from a tracked accounting var.
//!
//! ## Suppressions (precision first — these are make-or-break)
//!
//!   * **S1 — balance-delta idiom.** A binding `amt = address(this).balance -
//!     before` (both sides a self-balance read) is a *balance delta*, the safe
//!     `_fillQuote` shape; it is classified `balance_delta` (not raw self-balance)
//!     inside [`credited_value_provenance`] and therefore fails the predicate.
//!   * **S2 — bounded by a tracked-var guard.** The amount is constrained by a
//!     `require`/`if`-revert comparing it against a tracked accounting var
//!     (`require(amt <= balances[user])`) → silent.
//!   * **S3 — access-controlled self-credit.** The function is access-controlled
//!     and the recipient is the protocol itself (`address(this)`) — the
//!     `convertAllETH` self-deposit → silent.
//!   * **S4 — recipient is `address(this)` only.** No per-user attribution → silent.
//!   * **S5 — confidence boost.** A *sibling* credit site (another branch / peer
//!     function) sizes its credit from tracked vars → 0.6 → 0.72.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Call, CallKind, Expr, ExprKind, Function, Span, StmtKind, ValueSource};

use super::prelude::*;

pub struct ValueSourceDisciplineDetector;

/// Credit-sink method names: a token mint / vault deposit-for / push transfer.
/// The recipient is conventionally the FIRST positional argument; the amount is
/// the `{value:}` operand (for `deposit{value:}`) or the trailing amount argument.
const CREDIT_FUNCS: &[&str] = &[
    "mint", "deposit", "depositfor", "transfer", "safetransfer", "deposite",
];

impl Detector for ValueSourceDisciplineDetector {
    fn id(&self) -> &'static str {
        "value-source-discipline"
    }
    fn category(&self) -> Category {
        Category::ValueSourceDiscipline
    }
    fn description(&self) -> &'static str {
        "A value credited to a caller (mint / transfer-to-caller / per-user-slot write) is sized \
         from a live self-balance read (address(this).balance) rather than a tracked accounting \
         variable — the LoopFi H-01 over-mint class"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body || f.is_view_or_pure() {
                continue;
            }
            // Interface/abstract declarations carry no implementation.
            if cx.contract_of(f.id).map(|c| c.is_interface()).unwrap_or(false) {
                continue;
            }

            // ---- Gate: the value-source invariant only EXISTS if the contract
            // maintains a tracked accounting ledger that a credit should have been
            // sized from. A stateless router / bulker / payment module / recovery
            // helper (Universal-Router `Payments`, Comet `BaseBulker.sweepNative
            // Token`, a bridge sweep) holds no per-user accounting, so sweeping its
            // whole balance to a caller-designated recipient is its PURPOSE, not an
            // over-credit — there is no disciplined sibling to be the outlier of.
            // LoopFi `PrelaunchPoints` declares `balances`/`totalSupply`/`totalLp
            // ETH`, so the gate passes and the token branch is the outlier. ----
            if !contract_has_tracked_var(cx, f) {
                continue;
            }

            // ---- S3 (broadened): access-controlled credit is not the permission
            // less multi-user over-credit class. The H-01 exploit fundamentally
            // requires an ARBITRARY caller to have the contract's whole balance
            // credited to them, absorbing other users' in-flight funds. When the
            // function is access-controlled (`onlyOwner`/`onlyGuardian`/`require
            // (msg.sender == …)`) the caller is a trusted privileged actor — an
            // admin sweep/recovery, a per-owner-vault refund, a guardian
            // allocation — none of which is a permissionless multi-user
            // over-credit. (This mirrors the dataflow's own choice to treat
            // access-controlled params as trusted, not attacker input.) LoopFi's
            // `claim`/`claimAndStake` are permissionless (only a TIME guard), so
            // `_claim` is NOT access-controlled and still fires. ----
            if function_or_entrypoints_access_controlled(cx, f) {
                continue;
            }

            // Find a credit sink whose amount is an undisciplined self-balance.
            let Some(hit) = find_undisciplined_credit(cx, f) else { continue };

            // ---- S2: amount bounded by a require/if tied to a tracked var ----
            if amount_bounded_by_tracked_guard(cx, f, &hit) {
                continue;
            }

            // ---- S5: a sibling credit site sizes its credit from tracked vars ----
            let sibling_tracked = has_tracked_credit_sibling(cx, f, hit.amount_span);
            let confidence = if sibling_tracked { 0.72 } else { 0.6 };

            let b = report!(self, Category::ValueSourceDiscipline,
                title = "Caller credit sized from a live self-balance read, not a tracked accounting var",
                severity = Severity::High,
                confidence = confidence,
                dimensions = [Dimension::Invariant, Dimension::ValueFlow],
                message = format!(
                    "`{}` credits the caller (`{}`) an amount derived from a *live* read of the \
                     contract's own balance (`address(this).balance` / `balanceOf(address(this))`) \
                     rather than from a tracked accounting variable (a recorded balance / share / \
                     stake / supply). Because the credited amount is the contract's *whole* current \
                     balance — not this caller's accounting entitlement — any unrelated ETH already \
                     held (a prior balance, a second caller's in-flight funds, dust, a forced send) \
                     is folded into THIS caller's credit, over-crediting them at every other user's \
                     expense.{} The disciplined idiom sizes the credit from the tracked ledger (e.g. \
                     `userStake.mulDiv(total, totalSupply)`) or from a balance *delta* \
                     (`balanceAfter - balanceBefore`), never from the raw live balance.",
                    f.name,
                    hit.sink_name,
                    if sibling_tracked {
                        " A sibling credit path in the same contract DOES size its credit from \
                         tracked vars — making this branch the outlier that breaks the contract's \
                         own value-source discipline (the LoopFi H-01 shape)."
                    } else {
                        ""
                    },
                ),
                recommendation = "Size the caller's credit from a tracked accounting quantity — the \
                     recorded per-user balance / share / stake, or the supply ratio — never from a \
                     live `address(this).balance` / `balanceOf(address(this))` read. If the credit \
                     must reflect funds just received (e.g. a swap output), measure the *delta* \
                     (`balanceAfter - balanceBefore`) so pre-existing balance and concurrent inflows \
                     are excluded.",
            );
            out.push(finish_at(cx, b, f.id, hit.anchor));
        }
        out
    }
}

// ------------------------------------------------------------------- internals

/// Privileged-actor words that mark a guard/modifier as genuine ACCESS control
/// (a trusted caller), as opposed to a time/state gate. Matched as a
/// case-insensitive substring of the guard text (the modifier name or the
/// `require` expression).
const ACCESS_CONTROL_WORDS: &[&str] = &[
    "owner", "admin", "auth", "role", "guardian", "governor", "governance",
    "onlyby", "keeper", "operator", "manager", "minter", "controller", "hasrole",
];

/// Is `f` gated by a GENUINE access-control guard? `cx.has_access_control` keys on
/// the parser's `MsgSenderCheck` guard kind, which the parser also stamps on
/// non-auth `only*` modifiers (e.g. LoopFi's time gate `onlyAfterDate`). To avoid
/// suppressing a permissionless credit reached through a time-gated entry, we
/// additionally require the guard TEXT to name a privileged actor (owner / admin /
/// role / auth / guardian …) or to be an explicit `msg.sender ==` comparison.
fn is_real_access_control(f: &Function) -> bool {
    f.effects.guards.iter().any(|g| {
        if !matches!(g.kind, sluice_ir::GuardKind::MsgSenderCheck) {
            return false;
        }
        let t = g.text.to_ascii_lowercase();
        // An explicit msg.sender comparison is access control regardless of name.
        if t.contains("msg.sender") {
            return true;
        }
        // Otherwise the modifier name must name a privileged actor.
        ACCESS_CONTROL_WORDS.iter().any(|w| t.contains(w))
    })
}

/// Is `f` effectively access-controlled — itself gated by a genuine access-control
/// guard, or (if internal) reachable ONLY through public entry points that are all
/// access-controlled? A permissionless public path to the credit means it is NOT
/// access-controlled (the LoopFi `_claim` case: reached from `claim`/`claimAndStake`,
/// which carry only a TIME gate `onlyAfterDate` — not access control — so it fires).
fn function_or_entrypoints_access_controlled(cx: &AnalysisContext, f: &Function) -> bool {
    if is_real_access_control(f) {
        return true;
    }
    // A public/external function with no access guard is permissionless.
    if f.is_externally_reachable() {
        return false;
    }
    // Internal/private: walk callers up to public entry points. If there are no
    // resolved callers, treat as permissionless (conservatively fire — a library
    // helper with an undisciplined credit is still suspicious).
    use std::collections::HashSet;
    let mut seen: HashSet<_> = HashSet::new();
    let mut stack = vec![f.id];
    seen.insert(f.id);
    let mut saw_entry = false;
    while let Some(id) = stack.pop() {
        let Some(g) = cx.scir.function(id) else { continue };
        if g.is_externally_reachable() {
            saw_entry = true;
            // A single permissionless public entry point exposes the credit.
            if !is_real_access_control(g) {
                return false;
            }
            continue;
        }
        for &caller in &g.callers {
            if seen.insert(caller) {
                stack.push(caller);
            }
        }
    }
    // Reached only access-controlled entry points (or none). If we saw at least one
    // entry and all were gated → access-controlled.
    saw_entry
}

/// Does `f`'s contract declare at least one **tracked accounting state variable**
/// — a settable state var whose name reads like a per-user/aggregate ledger
/// (`balances`/`totalSupply`/`shares`/`stake`/`deposits`…)? This is the gate that
/// keeps the detector on contracts that actually have a value-source invariant to
/// violate, and silent on stateless routers / bulkers / sweep helpers.
fn contract_has_tracked_var(cx: &AnalysisContext, f: &Function) -> bool {
    let Some(c) = cx.contract_of(f.id) else { return false };
    c.state_vars
        .iter()
        .any(|v| !(v.constant || v.immutable) && is_tracked_accounting_name(&v.name))
}

/// A located undisciplined-credit hit within a function.
struct CreditHit {
    /// Span to anchor the finding (the self-balance read driving the amount).
    anchor: Span,
    /// Span of the amount expression (to exclude it when scanning for a sibling).
    amount_span: Span,
    /// Backtick-able recipient text for the message (`_receiver`, `to`, …).
    sink_name: String,
}

/// Scan `f` for a credit sink whose recipient is caller-influenced and whose
/// amount is an undisciplined self-balance (self-balance-derived, not tracked,
/// not a balance-delta). Returns the first such hit. Suppression S4 (recipient is
/// the protocol itself, `address(this)`) is applied here at the recipient check;
/// S3 (access control) is applied by the caller before this runs.
fn find_undisciplined_credit(cx: &AnalysisContext, f: &Function) -> Option<CreditHit> {
    let mut hit: Option<CreditHit> = None;

    // (a) Call-shaped credit sinks: mint/deposit{value:}/transfer/call{value:}.
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            let Some((recipient, amount)) = credit_recipient_and_amount(c) else { return };

            // ---- S4: recipient is the protocol itself (address(this)) ----
            if expr_is_self_address(recipient) {
                return;
            }

            // Recipient must be caller-influenced: a parameter, or a value whose
            // provenance carries msg.sender / attacker input. A constant /
            // immutable / owner recipient is NOT a per-user credit.
            if !recipient_is_caller_influenced(cx, f, recipient) {
                return;
            }

            // The credited amount must be an undisciplined self-balance
            // (self-balance-derived, not tracked-var-derived, not a balance-delta).
            let prov = credited_value_provenance(cx, f, amount);
            if !prov.is_undisciplined_self_balance() {
                return;
            }

            hit = Some(CreditHit {
                anchor: self_balance_anchor(cx, f, amount).unwrap_or(e.span),
                amount_span: amount.span,
                sink_name: recipient_text(cx, recipient),
            });
        });
        if hit.is_some() {
            break;
        }
    }
    if hit.is_some() {
        return hit;
    }

    // (b) Per-user-slot writes: `M[caller] = amt` / `M[caller] += amt` where `M`
    // is a tracked-name mapping keyed by a caller-influenced index and `amt` is an
    // undisciplined self-balance.
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Assign { target, value, .. } = &e.kind else { return };
            // Target must be an index write into a tracked mapping keyed by a
            // caller-influenced index.
            let ExprKind::Index { base, index: Some(idx) } = &target.kind else { return };
            let Some(root) = root_ident_str(base) else { return };
            if !is_tracked_accounting_var(cx, f, root) {
                return;
            }
            if !recipient_is_caller_influenced(cx, f, idx) {
                return;
            }
            let prov = credited_value_provenance(cx, f, value);
            if !prov.is_undisciplined_self_balance() {
                return;
            }
            hit = Some(CreditHit {
                anchor: self_balance_anchor(cx, f, value).unwrap_or(e.span),
                amount_span: value.span,
                sink_name: format!("{}[…]", root),
            });
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// For a credit-sink call, return `(recipient, amount)` expressions if `c` is a
/// recognized credit. Handles:
///   * `lpETH.deposit{value: amt}(recipient)` — value operand is the amount, the
///     first positional arg is the recipient.
///   * `token.mint(recipient, amt)` / `token.transfer(recipient, amt)` /
///     `safeTransfer(recipient, amt)` — arg0 recipient, arg1 amount.
///   * `recipient.call{value: amt}("")` — a raw native send; the receiver is the
///     recipient, the value operand is the amount.
fn credit_recipient_and_amount(c: &Call) -> Option<(&Expr, &Expr)> {
    // Raw native send: `addr.call{value: amt}(...)` — recipient is the receiver.
    if matches!(c.kind, CallKind::LowLevelCall | CallKind::Transfer | CallKind::Send) {
        if let (Some(recv), Some(val)) = (c.receiver.as_deref(), c.value.as_deref()) {
            return Some((recv, val));
        }
        // `addr.transfer(amt)` / `addr.send(amt)`.
        if matches!(c.kind, CallKind::Transfer | CallKind::Send) {
            if let (Some(recv), Some(amt)) = (c.receiver.as_deref(), c.args.first()) {
                return Some((recv, amt));
            }
        }
    }

    let name = c.func_name.as_deref()?.to_ascii_lowercase();
    if !CREDIT_FUNCS.contains(&name.as_str()) {
        return None;
    }
    // `deposit{value: amt}(recipient)` — the amount is the `{value:}` operand and
    // the recipient is the (sole) positional argument.
    if let Some(val) = c.value.as_deref() {
        if let Some(recipient) = c.args.first() {
            return Some((recipient, val));
        }
    }
    // `mint(recipient, amt)` / `transfer(recipient, amt)` — arg0/arg1.
    if c.args.len() >= 2 {
        return Some((&c.args[0], &c.args[1]));
    }
    None
}

/// Is `recipient` a caller-influenced value — a function parameter, or a value
/// whose provenance carries `msg.sender` / attacker input — and NOT a fixed
/// constant/immutable/owner-like recipient?
fn recipient_is_caller_influenced(cx: &AnalysisContext, f: &Function, recipient: &Expr) -> bool {
    // A constant / immutable recipient (a fixed treasury / module address) is not
    // a per-user credit.
    if root_is_const_or_immutable(cx, f, recipient) {
        return false;
    }
    // An `owner`/admin-like recipient is a privileged sink, not a per-user credit.
    if let Some(root) = root_ident_peeled(recipient) {
        if super::is_privileged_name(&root) {
            return false;
        }
    }
    // A parameter recipient is caller-influenced (callers pass `msg.sender` or an
    // arbitrary `_for`/`to`); this is the LoopFi `_receiver` shape.
    if root_is_param(f, recipient) {
        return true;
    }
    // Or a value whose provenance reaches msg.sender / attacker input.
    let prov = cx.provenance_of(f.id, recipient);
    prov.contains(ValueSource::MsgSender) || prov.contains(ValueSource::AttackerInput)
}

/// Span of the self-balance read inside `amount` (the `address(this).balance` /
/// `balanceOf(address(this))`), to anchor the finding precisely; or, if the
/// amount only *references* a balance-seeded local, the span of the local's
/// seeding read elsewhere in the body. Falls back to `None`.
fn self_balance_anchor(cx: &AnalysisContext, f: &Function, amount: &Expr) -> Option<Span> {
    // Direct read inside the amount expression.
    if let Some(sp) = direct_self_balance_span(amount) {
        return Some(sp);
    }
    // The amount references a local; find that local's seeding self-balance read.
    let mut names: Vec<String> = Vec::new();
    amount.visit(&mut |x| {
        if let ExprKind::Ident(n) = &x.kind {
            names.push(n.clone());
        }
    });
    let mut found: Option<Span> = None;
    for s in &f.body {
        s.visit(&mut |st| {
            if found.is_some() {
                return;
            }
            if let StmtKind::VarDecl { name: Some(n), init: Some(init), .. } = &st.kind {
                if names.iter().any(|m| m == n) {
                    if let Some(sp) = direct_self_balance_span(init) {
                        found = Some(sp);
                    }
                }
            }
            if let StmtKind::Expr(Expr { kind: ExprKind::Assign { target, value, .. }, .. }) = &st.kind {
                if let ExprKind::Ident(n) = &target.kind {
                    // Skip a balance-delta reassignment (`x = balance - x`) — its
                    // span is the safe idiom, not the undisciplined read.
                    if names.iter().any(|m| m == n)
                        && direct_self_balance_span(value).is_some()
                        && !rhs_is_sub(value)
                    {
                        found = direct_self_balance_span(value);
                    }
                }
            }
        });
        if found.is_some() {
            break;
        }
    }
    let _ = cx;
    found
}

/// Is `e` (top-level) a subtraction? Used to avoid anchoring on the safe
/// balance-delta reassignment.
fn rhs_is_sub(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Binary { op: BinOp::Sub, .. })
}

/// Span of the first direct self-balance read (`address(this).balance` /
/// `balanceOf(address(this))`) inside `e`.
fn direct_self_balance_span(e: &Expr) -> Option<Span> {
    let mut sp: Option<Span> = None;
    e.visit(&mut |x| {
        if sp.is_some() {
            return;
        }
        match &x.kind {
            ExprKind::Member { base, member } if member == "balance" && expr_is_self_address(base) => {
                sp = Some(x.span);
            }
            ExprKind::Call(c)
                if c.func_name.as_deref() == Some("balanceOf")
                    && c.args.first().map(expr_is_self_address).unwrap_or(false) =>
            {
                sp = Some(x.span);
            }
            _ => {}
        }
    });
    sp
}

/// Backtick-able text of the recipient expression for the message.
fn recipient_text(cx: &AnalysisContext, recipient: &Expr) -> String {
    let raw = cx.scir.span_text(recipient.span);
    let t = raw.trim();
    if t.is_empty() || t.len() > 40 {
        root_ident_peeled(recipient).unwrap_or_else(|| "the caller".to_string())
    } else {
        t.to_string()
    }
}

/// S2 — is the credited amount bounded by a `require`/`if`-revert comparison that
/// ties it to a tracked accounting var? `require(amt <= balances[user])` makes the
/// self-balance read merely an upper bound that cannot exceed the user's tracked
/// entitlement, so the over-credit cannot occur.
fn amount_bounded_by_tracked_guard(cx: &AnalysisContext, f: &Function, hit: &CreditHit) -> bool {
    // The local name(s) the amount is carried in.
    let amount_names = amount_local_names(f, hit.amount_span);
    if amount_names.is_empty() {
        return false;
    }
    let mut bounded = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if bounded {
                return;
            }
            if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
                if !op.is_comparison() {
                    return;
                }
                let mentions_amount =
                    expr_mentions_any_name(lhs, &amount_names) || expr_mentions_any_name(rhs, &amount_names);
                let mentions_tracked = expr_mentions_tracked(cx, f, lhs) || expr_mentions_tracked(cx, f, rhs);
                if mentions_amount && mentions_tracked {
                    bounded = true;
                }
            }
        });
        if bounded {
            break;
        }
    }
    bounded
}

/// Local-variable names that carry the amount at `amount_span` (the amount expr
/// itself if it is an identifier, plus any identifier inside it).
fn amount_local_names(f: &Function, amount_span: Span) -> Vec<String> {
    let mut names = Vec::new();
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if e.span == amount_span {
                e.visit(&mut |x| {
                    if let ExprKind::Ident(n) = &x.kind {
                        if !names.contains(n) {
                            names.push(n.clone());
                        }
                    }
                });
            }
        });
    }
    names
}

/// Does `e` mention any of `names` as a bare identifier?
fn expr_mentions_any_name(e: &Expr, names: &[String]) -> bool {
    let mut hit = false;
    e.visit(&mut |x| {
        if let ExprKind::Ident(n) = &x.kind {
            if names.iter().any(|m| m == n) {
                hit = true;
            }
        }
    });
    hit
}

/// Does `e` mention a tracked accounting state var (`balances`, `totalSupply`, …)?
fn expr_mentions_tracked(cx: &AnalysisContext, f: &Function, e: &Expr) -> bool {
    let mut hit = false;
    e.visit(&mut |x| {
        if hit {
            return;
        }
        if let Some(root) = root_ident_str(x) {
            if is_tracked_accounting_var(cx, f, root) {
                hit = true;
            }
        }
    });
    hit
}

/// S5 — does a *sibling* credit site size its credit from tracked vars? A sibling
/// is either another credit in the SAME function (a different branch — LoopFi's
/// ETH branch) or a credit in a peer function of the same contract. Excludes the
/// firing site itself (by `skip_span`).
fn has_tracked_credit_sibling(cx: &AnalysisContext, f: &Function, skip_span: Span) -> bool {
    // (a) Same function, a different branch.
    if function_has_tracked_credit(cx, f, Some(skip_span)) {
        return true;
    }
    // (b) A peer function of the same contract.
    let Some(c) = cx.contract_of(f.id) else { return false };
    for g in cx.functions() {
        if g.id == f.id || !g.has_body {
            continue;
        }
        if cx.contract_of(g.id).map(|gc| gc.id) != Some(c.id) {
            continue;
        }
        if function_has_tracked_credit(cx, g, None) {
            return true;
        }
    }
    false
}

/// Does `g` contain a credit sink (to a caller-influenced recipient) whose amount
/// is tracked-var-derived (and not self-balance)? `skip_span` excludes one amount.
fn function_has_tracked_credit(cx: &AnalysisContext, g: &Function, skip_span: Option<Span>) -> bool {
    let mut found = false;
    for s in &g.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            let Some((recipient, amount)) = credit_recipient_and_amount(c) else { return };
            if Some(amount.span) == skip_span {
                return;
            }
            if expr_is_self_address(recipient) {
                return;
            }
            if !recipient_is_caller_influenced(cx, g, recipient) {
                return;
            }
            let prov = credited_value_provenance(cx, g, amount);
            if prov.tracked && !prov.self_balance {
                found = true;
            }
        });
        if found {
            break;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    fn fired(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.detector == "value-source-discipline")
    }

    // VULN — the LoopFi H-01 token-branch shape: the credit is sized from
    // `address(this).balance` and minted to a caller-supplied `_receiver`, while
    // the ETH branch sizes it from tracked vars (`userStake.mulDiv(total, supply)`).
    const VULN: &str = r#"
        interface ILpETH {
            function deposit(address to) external payable;
            function safeTransfer(address to, uint256 a) external;
        }
        contract Prelaunch {
            ILpETH public lpETH;
            uint256 public totalSupply;
            uint256 public totalLpETH;
            mapping(address => mapping(address => uint256)) public balances;
            address public constant ETH = address(0xEee);

            function claim(address _token, address _receiver) external {
                uint256 userStake = balances[msg.sender][_token];
                if (_token == ETH) {
                    uint256 claimedAmount = userStake * totalLpETH / totalSupply;
                    balances[msg.sender][_token] = 0;
                    lpETH.safeTransfer(_receiver, claimedAmount);
                } else {
                    balances[msg.sender][_token] = 0;
                    swap(_token, userStake);
                    uint256 claimedAmount = address(this).balance;
                    lpETH.deposit{value: claimedAmount}(_receiver);
                }
            }
            function swap(address t, uint256 a) internal {}
        }
    "#;

    // SAFE-DELTA — the `_fillQuote` balance-delta idiom (S1): the value credited is
    // `balanceAfter - balanceBefore`, not the raw balance. Must stay silent.
    const SAFE_DELTA: &str = r#"
        interface ILpETH { function deposit(address to) external payable; }
        contract Prelaunch {
            ILpETH public lpETH;
            function claimDelta(address _receiver) external {
                uint256 before = address(this).balance;
                swap();
                uint256 bought = address(this).balance - before;
                lpETH.deposit{value: bought}(_receiver);
            }
            function swap() internal {}
        }
    "#;

    // SAFE-SELF — access-controlled self-deposit to `address(this)` (S3/S4): the
    // `convertAllETH` shape. The recipient is the protocol, not a caller.
    const SAFE_SELF: &str = r#"
        interface ILpETH { function deposit(address to) external payable; }
        contract Prelaunch {
            ILpETH public lpETH;
            address public owner;
            modifier onlyOwner() { require(msg.sender == owner); _; }
            function convertAllETH() external onlyOwner {
                uint256 totalBalance = address(this).balance;
                lpETH.deposit{value: totalBalance}(address(this));
            }
        }
    "#;

    // SAFE-TRACKED — the credit is sized purely from tracked vars (the ETH branch
    // in isolation). Must stay silent.
    const SAFE_TRACKED: &str = r#"
        interface ILpETH { function safeTransfer(address to, uint256 a) external; }
        contract Prelaunch {
            ILpETH public lpETH;
            uint256 public totalSupply;
            uint256 public totalLpETH;
            mapping(address => uint256) public balances;
            function claimEth(address _receiver) external {
                uint256 userStake = balances[msg.sender];
                uint256 claimedAmount = userStake * totalLpETH / totalSupply;
                balances[msg.sender] = 0;
                lpETH.safeTransfer(_receiver, claimedAmount);
            }
        }
    "#;

    // SAFE-EXCESS — the Reserve `RewardableLib.sweepRewardsSingle` shape (S1
    // broadened): the credited amount is `balanceOf(this) - liabilities[t]`, the
    // EXCESS over a tracked liability ledger. The minuend is a self-balance read
    // but it is a delta/excess, not the raw balance, so it must stay silent.
    const SAFE_EXCESS: &str = r#"
        interface IERC20x { function balanceOf(address) external view returns (uint256); function safeTransfer(address to, uint256 a) external; }
        contract Sweeper {
            mapping(address => uint256) public liabilities;   // tracked ledger
            uint256 public totalSupply;                       // a tracked var (gate)
            function sweep(address erc20, address to) external {
                uint256 amt = IERC20x(erc20).balanceOf(address(this)) - liabilities[erc20];
                if (amt > 0) {
                    IERC20x(erc20).safeTransfer(to, amt);
                }
            }
        }
    "#;

    // SAFE-NO-LEDGER — a stateless router/sweep helper (Universal-Router
    // `Payments` / Comet `BaseBulker` shape): no tracked accounting state var, so
    // sweeping the whole balance to a caller-designated recipient is its purpose,
    // not an over-credit. The contract-tracked-var gate keeps it silent.
    const SAFE_NO_LEDGER: &str = r#"
        interface IERC20y { function balanceOf(address) external view returns (uint256); function transfer(address to, uint256 a) external; }
        contract Router {
            address public immutable WETH;
            constructor(address w) { WETH = w; }
            function sweep(address token, address recipient) external {
                uint256 balance = IERC20y(token).balanceOf(address(this));
                if (balance > 0) IERC20y(token).transfer(recipient, balance);
            }
        }
    "#;

    // SAFE-ADMIN — an access-controlled admin recovery / per-owner-vault refund
    // (S3 broadened): the credit is the whole self-balance to a caller-supplied
    // recipient, but the function is `onlyOwner`. A permissionless attacker cannot
    // reach it, so it is not the multi-user over-credit class.
    const SAFE_ADMIN: &str = r#"
        interface IERC20z { function balanceOf(address) external view returns (uint256); function transfer(address to, uint256 a) external; }
        contract Vault {
            address public owner;
            mapping(address => uint256) public balances;   // tracked var (gate passes)
            modifier onlyOwner() { require(msg.sender == owner); _; }
            function withdrawLinks(address token, address to) external onlyOwner {
                uint256 balance = IERC20z(token).balanceOf(address(this));
                IERC20z(token).transfer(to, balance);
            }
        }
    "#;

    #[test]
    fn fires_on_balance_credit() {
        let fs = run(VULN);
        assert!(fired(&fs), "expected value-source-discipline; got {:?}",
            fs.iter().map(|f| &f.detector).collect::<Vec<_>>());
    }

    #[test]
    fn silent_on_balance_excess_over_tracked() {
        assert!(!fired(&run(SAFE_EXCESS)), "balance - liabilities is a safe excess (S1)");
    }

    #[test]
    fn silent_on_stateless_router() {
        assert!(!fired(&run(SAFE_NO_LEDGER)), "no tracked ledger => no invariant to violate");
    }

    #[test]
    fn silent_on_access_controlled_recovery() {
        assert!(!fired(&run(SAFE_ADMIN)), "access-controlled credit is not the permissionless class (S3)");
    }

    // VULN-TIMEGATE — a time-gated (NOT access-controlled) permissionless credit:
    // the LoopFi shape where the entry carries `onlyAfterDate` (a time gate the
    // parser stamps as a MsgSenderCheck). It must STILL fire — a time gate does
    // not make the credit access-controlled.
    const VULN_TIMEGATE: &str = r#"
        interface ILpETH { function deposit(address to) external payable; }
        contract Prelaunch {
            ILpETH public lpETH;
            uint256 public totalSupply;
            mapping(address => uint256) public balances;
            uint32 public startDate;
            modifier onlyAfterDate(uint256 d) { require(block.timestamp > d); _; }
            function claim(address _receiver) external onlyAfterDate(startDate) {
                uint256 userStake = balances[msg.sender];
                require(userStake > 0);
                balances[msg.sender] = 0;
                swap(userStake);
                uint256 claimedAmount = address(this).balance;
                lpETH.deposit{value: claimedAmount}(_receiver);
            }
            function swap(uint256 a) internal {}
        }
    "#;

    #[test]
    fn fires_through_time_gate() {
        assert!(fired(&run(VULN_TIMEGATE)), "a time gate (onlyAfterDate) is not access control; must still fire");
    }

    #[test]
    fn silent_on_balance_delta() {
        assert!(!fired(&run(SAFE_DELTA)));
    }

    #[test]
    fn silent_on_access_controlled_self_deposit() {
        assert!(!fired(&run(SAFE_SELF)));
    }

    #[test]
    fn silent_on_tracked_credit() {
        assert!(!fired(&run(SAFE_TRACKED)));
    }

    #[test]
    fn fires_high_with_sibling() {
        // The VULN has a tracked-var sibling branch (ETH branch) so confidence is
        // boosted to 0.72. With its two base dims [Invariant, ValueFlow] (and any
        // automatic frontier corroboration the scorer adds for the external credit
        // call), the finding lands in the Crit/High band — exactly the scorer
        // behavior the design routes this through (no bespoke severity path).
        let fs = run(VULN);
        let f = fs.iter().find(|f| f.detector == "value-source-discipline").expect("fired");
        assert!(
            matches!(f.severity, sluice_findings::Severity::High | sluice_findings::Severity::Critical),
            "expected High/Critical, got {:?} (score {})",
            f.severity, f.severity_score
        );
        assert_eq!(f.confidence, 0.72, "tracked-var sibling should boost confidence to 0.72");
    }
}
