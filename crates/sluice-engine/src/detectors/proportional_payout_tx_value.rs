//! Proportional payout sized from a re-read `address(this).balance`, paid in a
//! push loop that swallows per-recipient send failures.
//!
//! This is the **Renzo `PaymentSplitter.receive()`** shape. A `receive`/`fallback`
//! (or any payable entry) splits the contract's *entire current balance* across a
//! list of recipients in a loop, sizing each recipient's cut from a **re-read of
//! `address(this).balance`** divided by a **decreasing "recipients-left" divisor**:
//!
//! ```solidity
//! receive() external payable {
//!     uint256 amountLeftToPay = address(this).balance;          // (1) balance-reread
//!     for (uint256 i = 0; i < recipients.length; i++) {
//!         uint256 amountToPay = amountLeftToPay / (recipients.length - i);  // (2) left/(n-i)
//!         ...
//!         (bool success, ) = recipients[i].call{ value: amountToPay }("");  // (3) push send
//!         if (success) {                                         // (4) debit ONLY on success
//!             amountOwed[recipients[i]] -= amountToPay;
//!             amountLeftToPay          -= amountToPay;
//!         }
//!         // ... continues past failures (no revert) ...
//!     }
//! }
//! ```
//!
//! Three hazards combine, and each is the deliberate **inverse** of a different
//! safe idiom:
//!
//!   * **Order-dependent skew.** The per-cut divisor is `recipients.length - i`,
//!     which *shrinks* as `i` advances, so the same `amountLeftToPay` is divided
//!     by a smaller number for later recipients. The payout each address receives
//!     depends on its *position* in the list (and on whether earlier sends
//!     succeeded), not solely on what it is owed — an owner-controlled list order
//!     becomes a value lever.
//!   * **Balance-reread mixes unrelated inflows.** Seeding the split from
//!     `address(this).balance` (rather than from the `msg.value` that triggered
//!     this call, or from per-recipient `owed` ledgers) folds *any* ETH already in
//!     the contract — forced sends, leftover dust, a griefer's pre-funding — into
//!     the divided pot, so what each recipient gets is a function of the whole
//!     balance at call time, not of this payment.
//!   * **Swallowed failures.** The recipient send is a low-level `call` whose
//!     success bit gates the bookkeeping: on failure the loop *skips* the debit
//!     and **continues** to the next recipient instead of reverting. This is the
//!     exact inverse of the DoS / `dos.rs` push-loop (which `require(success)`s and
//!     bricks the batch): here a recipient that reverts is silently passed over,
//!     its `amountOwed` is never reduced, and the residual it would have received
//!     is re-divided among (or skewed toward) the remaining addresses.
//!
//! ## Why this is a distinct class from the other splitter detectors
//!
//! `dos.rs` fires on a push loop that **reverts** the whole batch on one failure;
//! this class is the opposite — it *tolerates* failures and re-skews the split.
//! `proportional-split-residual` fires on a `amount - a - b` rounding-dust residual
//! forced onto one bucket; here there is no residual sink, the bug is the
//! `balance / (n - i)` sizing + swallowed send. `msg-value-in-loop` fires on a
//! per-iteration `msg.value` read; here the loop reads `address(this).balance`
//! once into a local and re-divides *that*.
//!
//! ## Precision anchors (all required)
//!
//! Precision over recall. We fire only when every one of these holds, which is
//! what keeps the detector silent on fixed-amount and pull-payment splitters:
//!
//!   1. an externally-reachable, state-mutating function with a body;
//!   2. a loop whose body sends **native value** to a recipient (a low-level
//!      `call{value:}` / `.transfer` / `.send`);
//!   3. the value sent is sized by a **division** (`left / divisor`) whose
//!      numerator root-resolves to a **local seeded from `address(this).balance`**
//!      — the balance-reread — and whose **divisor is a decreasing "count-left"
//!      expression**: a subtraction involving the loop index or the recipient-array
//!      length (`recipients.length - i`, `n - i`), i.e. a shrinking denominator;
//!   4. the send's failure is **swallowed** — the call's success is captured but
//!      the loop does **not** `require`/`revert` on it (the debit is gated behind
//!      an `if (success)` and iteration continues). A loop that bubbles the failure
//!      (`require(success)`) is the `dos.rs` batch-bricking class, not this one,
//!      and is left to that detector.
//!
//! Suppressed shapes: a **fixed / per-recipient amount** (the value is `owed[r]`,
//! a parameter, or a constant — no `balance/(n-i)` sizing); a **pull-payment**
//! splitter (`withdraw`/`claim`/`release` that credits a ledger and lets each
//! recipient pull, no in-loop push); and any loop that reverts on a failed send.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, CallKind, Expr, ExprKind, Function, Span, Stmt, StmtKind};

pub struct ProportionalPayoutTxValueDetector;

impl Detector for ProportionalPayoutTxValueDetector {
    fn id(&self) -> &'static str {
        "proportional-payout-tx-value"
    }
    fn category(&self) -> Category {
        Category::ProportionalPayoutTxValue
    }
    fn description(&self) -> &'static str {
        "Push-payment splitter loop that sizes each cut from a re-read address(this).balance \
         divided by a decreasing recipients-left divisor and swallows per-recipient send failures \
         (Renzo PaymentSplitter.receive class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            // The bug finalizes payout/accounting state, so the function must be a
            // reachable, state-mutating body. A `view`/`pure` helper books nothing.
            if !f.has_body || f.is_view_or_pure() || !f.is_externally_reachable() {
                continue;
            }
            // A pull-payment splitter (`withdraw`/`claim`/`release`) credits a
            // ledger and lets each recipient pull independently — no in-loop push,
            // so none of the three hazards apply. Suppress by name up front.
            if is_pull_payment(f) {
                continue;
            }

            // Names of locals seeded from `address(this).balance` (the reread).
            let balance_locals = balance_seeded_locals(f);
            if balance_locals.is_empty() {
                continue;
            }

            // Walk each loop. We need, within ONE loop body: (a) a native-value
            // send whose amount is sized `balanceLocal / (countLeftDivisor)`, and
            // (b) that the send's failure is swallowed (no require/revert on it).
            let mut hit: Option<Span> = None;
            for loop_stmt in loops_in(f) {
                let body = loop_body(loop_stmt);
                let Some(span) = proportional_balance_send(body, &balance_locals) else {
                    continue;
                };
                // The defining inverse-of-DoS anchor: a failed send must be
                // TOLERATED. If the loop bubbles the failure (`require(success)` /
                // `if (!ok) revert`), it is the batch-bricking DoS class, not this
                // swallow-and-reskew class — leave it to `dos.rs`.
                if loop_reverts_on_send_failure(body) {
                    continue;
                }
                hit = Some(span);
                break;
            }
            let Some(span) = hit else { continue };

            let b = FindingBuilder::new(self.id(), Category::ProportionalPayoutTxValue)
                .title("Push-payment split sized from re-read balance with swallowed send failures")
                .severity(Severity::Medium)
                .confidence(0.55)
                .dimension(Dimension::Invariant)
                .message(format!(
                    "`{}` splits the contract's current `address(this).balance` across recipients in a \
                     loop, sizing each cut as `balance / (recipientsLeft - i)` — a divisor that shrinks \
                     as the loop advances — and pays each recipient with a low-level `call` whose failure \
                     is swallowed (the debit is gated behind `if (success)` and the loop continues instead \
                     of reverting). Three flaws compound: (1) the payout is ORDER-DEPENDENT — the same \
                     balance is divided by a smaller number for later recipients, so an address's cut \
                     depends on its position in the list and on whether earlier sends succeeded, not \
                     solely on what it is owed; (2) re-reading `address(this).balance` folds UNRELATED \
                     INFLOWS (forced sends, leftover dust, pre-funding) into the divided pot, so each \
                     recipient receives a function of the whole balance at call time rather than of this \
                     payment; (3) a recipient that reverts is SILENTLY SKIPPED — its `amountOwed` is never \
                     reduced and the funds it would have received are re-divided among / skewed toward the \
                     remaining addresses. This is the inverse of the DoS push-loop that reverts the batch.",
                    f.name
                ))
                .recommendation(
                    "Size each payout from a fixed per-recipient ledger (the `owed`/`amountOwed` amount), \
                     not from a re-read `address(this).balance` divided by a decreasing count; do not let \
                     the split depend on list order or on balance contributed by unrelated inflows. Prefer \
                     a pull-payment design (credit each recipient and let them `withdraw()` independently) \
                     so one reverting recipient cannot re-skew everyone else's share, and record skipped \
                     payouts so off-chain consumers can reconcile.",
                );
            out.push(cx.finish(b, f.id, span));
        }
        out
    }
}

// ----------------------------------------------------------------- helpers

/// All loop statements (`for`/`while`/`do-while`) anywhere in the function body,
/// in pre-order.
fn loops_in(f: &Function) -> Vec<&Stmt> {
    let mut loops = Vec::new();
    for s in &f.body {
        s.visit(&mut |st| {
            if matches!(
                st.kind,
                StmtKind::While { .. } | StmtKind::For { .. } | StmtKind::DoWhile { .. }
            ) {
                loops.push(st);
            }
        });
    }
    loops
}

/// The statement list forming a loop's body (empty for non-loops).
fn loop_body(loop_stmt: &Stmt) -> &[Stmt] {
    match &loop_stmt.kind {
        StmtKind::While { body, .. }
        | StmtKind::For { body, .. }
        | StmtKind::DoWhile { body, .. } => body,
        _ => &[],
    }
}

/// Names of function-local variables whose declared initializer reads
/// `address(this).balance` — the "balance-reread" pot the split is divided from.
/// In the Renzo shape this is `uint256 amountLeftToPay = address(this).balance;`.
fn balance_seeded_locals(f: &Function) -> std::collections::HashSet<String> {
    let mut locals = std::collections::HashSet::new();
    for s in &f.body {
        s.visit(&mut |st| {
            if let StmtKind::VarDecl { name: Some(n), init: Some(init), .. } = &st.kind {
                if expr_reads_this_balance(init) {
                    locals.insert(n.clone());
                }
            }
        });
    }
    locals
}

/// True if `e` contains a read of `address(this).balance` — a `Member{member:
/// "balance"}` whose base is `address(this)` (a `TypeCast` to `address` of
/// `this`), or, defensively, `this.balance` directly. We require the base to be
/// `this` so an ERC20 `token.balanceOf(...)` or some other `.balance` member on an
/// unrelated object does not qualify.
fn expr_reads_this_balance(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |x| {
        if found {
            return;
        }
        if let ExprKind::Member { base, member } = &x.kind {
            if member == "balance" && base_is_this(base) {
                found = true;
            }
        }
    });
    found
}

/// True if `e` is `address(this)` (a type cast of `this`) or the bare `this`.
fn base_is_this(e: &Expr) -> bool {
    match &e.kind {
        // `this`
        ExprKind::Ident(n) => n == "this",
        // `address(this)` — a TypeCast call whose single arg is `this`.
        ExprKind::Call(c) if c.kind == CallKind::TypeCast => {
            c.args.iter().any(base_is_this) || c.receiver.as_deref().map(base_is_this).unwrap_or(false)
        }
        _ => false,
    }
}

/// Scan a loop body for a native-value send whose amount is sized
/// `balanceLocal / (decreasingCountDivisor)`. Returns the span of that send.
///
/// The per-cut division and the send are usually two separate statements: the
/// Renzo shape computes `uint256 amountToPay = amountLeftToPay / (recipients.length
/// - i);` and *then* sends `recipients[i].call{ value: amountToPay }("")`. So the
/// call's `{value:}` operand is the local `amountToPay`, not the division itself.
/// We therefore:
///   1. collect the set of **proportional-cut locals** — locals declared or
///      assigned anywhere in the loop body as `balanceLocal / countLeftDivisor`
///      (`amountToPay`); and
///   2. report a native-value send whose amount is *either* an inline proportional
///      division, *or* references one of those proportional-cut locals.
///
/// The "amount" of a send is the `{value: amount}` operand of a low-level
/// `call`/`send`, or the first argument of `.transfer(amount)` / `.send(amount)`.
fn proportional_balance_send(
    body: &[Stmt],
    balance_locals: &std::collections::HashSet<String>,
) -> Option<Span> {
    // (1) Locals that hold a `balanceLocal / (countLeft)` cut.
    let cut_locals = proportional_cut_locals(body, balance_locals);
    if cut_locals.is_empty() {
        // No proportional cut anywhere — but the division could still be written
        // *inline* as the send value. Fall through; the inline check below covers
        // that, so we don't early-return here.
    }

    // (2) A native-value send sized by such a cut (inline division or a cut local).
    let mut found: Option<Span> = None;
    for s in body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            let Some(amount) = send_value_amount(c) else { return };
            // Inline `call{ value: balanceLocal / (n - i) }(...)`.
            if amount_is_proportional_to_balance(amount, balance_locals) {
                found = Some(e.span);
                return;
            }
            // `call{ value: amountToPay }(...)` where `amountToPay` is a cut local.
            if expr_mentions_any(amount, &cut_locals) {
                found = Some(e.span);
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// The set of loop-body locals bound to a proportional cut
/// `balanceLocal / (decreasingCountDivisor)`. Covers both the declaration
/// `uint256 amountToPay = amountLeftToPay / (recipients.length - i);` and a later
/// re-assignment to the same shape. A subsequent cap (`if (owed < amountToPay)
/// amountToPay = owed;`) does not remove the local from this set — it is still
/// seeded from the proportional division.
fn proportional_cut_locals(
    body: &[Stmt],
    balance_locals: &std::collections::HashSet<String>,
) -> std::collections::HashSet<String> {
    let mut cut = std::collections::HashSet::new();
    for s in body {
        s.visit(&mut |st| match &st.kind {
            // `uint256 amountToPay = balanceLocal / (n - i);`
            StmtKind::VarDecl { name: Some(n), init: Some(init), .. } => {
                if amount_is_proportional_to_balance(init, balance_locals) {
                    cut.insert(n.clone());
                }
            }
            // `amountToPay = balanceLocal / (n - i);` (assignment in expr position)
            StmtKind::Expr(e) => {
                e.visit(&mut |x| {
                    if let ExprKind::Assign { target, value, .. } = &x.kind {
                        if amount_is_proportional_to_balance(value, balance_locals) {
                            if let ExprKind::Ident(n) = &target.kind {
                                cut.insert(n.clone());
                            }
                        }
                    }
                });
            }
            _ => {}
        });
    }
    cut
}

/// True if `e` references (anywhere) one of the names in `set`.
fn expr_mentions_any(e: &Expr, set: &std::collections::HashSet<String>) -> bool {
    if set.is_empty() {
        return false;
    }
    let mut hit = false;
    e.visit(&mut |x| {
        if hit {
            return;
        }
        if let ExprKind::Ident(n) = &x.kind {
            if set.contains(n) {
                hit = true;
            }
        }
    });
    hit
}

/// If `c` is a call that sends native ETH, return the expression giving the
/// amount sent: the `{value:}` operand for a low-level `call`/`send`, or the first
/// positional argument for `.transfer(x)` / `.send(x)`.
fn send_value_amount(c: &sluice_ir::Call) -> Option<&Expr> {
    // `addr.call{value: amt}(...)` / any call carrying a `{value:}`.
    if let Some(v) = &c.value {
        return Some(v);
    }
    // `addr.transfer(amt)` / `addr.send(amt)` — amount is the first arg.
    if matches!(c.kind, CallKind::Transfer | CallKind::Send) {
        return c.args.first();
    }
    None
}

/// True if `amount` is (or contains) a division `num / divisor` where `num`
/// root-resolves to a balance-seeded local and `divisor` is a decreasing
/// "count-left" expression (`recipients.length - i`, `n - i`). This is the
/// `balance / (recipientsLeft - i)` sizing.
fn amount_is_proportional_to_balance(
    amount: &Expr,
    balance_locals: &std::collections::HashSet<String>,
) -> bool {
    let mut hit = false;
    amount.visit(&mut |x| {
        if hit {
            return;
        }
        if let ExprKind::Binary { op: BinOp::Div, lhs, rhs } = &x.kind {
            if numerator_is_balance_local(lhs, balance_locals) && divisor_is_count_left(rhs) {
                hit = true;
            }
        }
    });
    hit
}

/// True if `e` root-resolves to one of the balance-seeded locals (`amountLeftToPay`
/// or `amountLeftToPay - something`, etc.). We accept the var appearing anywhere in
/// the numerator subtree so `(left) / d` and `(left - x) / d` both match.
fn numerator_is_balance_local(
    e: &Expr,
    balance_locals: &std::collections::HashSet<String>,
) -> bool {
    let mut hit = false;
    e.visit(&mut |x| {
        if hit {
            return;
        }
        if let ExprKind::Ident(n) = &x.kind {
            if balance_locals.contains(n) {
                hit = true;
            }
        }
    });
    hit
}

/// True if `e` is a **decreasing "count-left" divisor**: a subtraction
/// (`a - b`) where one side is the recipient-array `.length` or a loop-index-like
/// identifier (`i`, `idx`, `index`, ...). The canonical Renzo form is
/// `recipients.length - i`. Requiring the subtraction (a shrinking denominator) is
/// what distinguishes this from an ordinary fixed-denominator pro-rata
/// (`amount * weight / total`), which is not order-dependent.
fn divisor_is_count_left(e: &Expr) -> bool {
    let mut hit = false;
    e.visit(&mut |x| {
        if hit {
            return;
        }
        if let ExprKind::Binary { op: BinOp::Sub, lhs, rhs } = &x.kind {
            // `length - i` (canonical) or `count - i`: a `.length` member /
            // count-like ident minus a loop-index-like ident.
            let lhs_count = is_length_or_count(lhs);
            let rhs_index = mentions_index_ident(rhs);
            // Also accept the mirrored / total-minus-progress form `total - paid`
            // only when the left side is a length/count: we keep this tight so a
            // generic `a - b` divisor does not match.
            if lhs_count && rhs_index {
                hit = true;
            }
        }
    });
    hit
}

/// True if `e` is (or contains) a `.length` member access or a count-like
/// identifier (`count`, `len`, `total`, `numRecipients`, ...). Used for the left
/// side of the shrinking divisor.
fn is_length_or_count(e: &Expr) -> bool {
    let mut hit = false;
    e.visit(&mut |x| {
        if hit {
            return;
        }
        match &x.kind {
            ExprKind::Member { member, .. } if member == "length" => hit = true,
            ExprKind::Ident(n) => {
                let l = n.to_ascii_lowercase();
                if l.contains("length") || l.contains("count") || l == "len" || l.contains("total") {
                    hit = true;
                }
            }
            _ => {}
        }
    });
    hit
}

/// True if `e` is (or contains) a loop-index-like identifier — `i`, `j`, `k`,
/// `idx`, `index`, or a name ending in `index`/`idx`. This is the "- i" of the
/// shrinking divisor `length - i`.
fn mentions_index_ident(e: &Expr) -> bool {
    let mut hit = false;
    e.visit(&mut |x| {
        if hit {
            return;
        }
        if let ExprKind::Ident(n) = &x.kind {
            if is_index_name(n) {
                hit = true;
            }
        }
    });
    hit
}

/// Whole-name classification of a loop-index variable. Deliberately tight: the
/// conventional single-letter counters and `idx`/`index` spellings only. A bare
/// `n` is intentionally excluded — it usually names a *count/total*, not an index,
/// and `total - n` is an ordinary difference, not a shrinking loop divisor.
fn is_index_name(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    matches!(l.as_str(), "i" | "j" | "k" | "idx" | "index")
        || l.ends_with("index")
        || l.ends_with("idx")
}

/// True if the loop body **bubbles** a send failure — a `require(success)` /
/// `assert(success)` / `if (!success) revert` over the captured success bit, which
/// would make this the batch-bricking DoS class rather than the swallow-and-reskew
/// class. We detect it textually-structurally: any `Revert` statement, or a
/// `require`/`assert` builtin call, that appears in the body and is NOT merely the
/// loop's own benign control flow.
///
/// Concretely the swallowing Renzo shape gates the *debit* behind `if (success)`
/// and never reverts on a failed send; a DoS shape instead does
/// `require(success)` / `if (!success) revert`. So the presence of a `revert`/
/// `require`/`assert` reachable from a failed send in the loop body suppresses.
fn loop_reverts_on_send_failure(body: &[Stmt]) -> bool {
    let mut reverts = false;
    for s in body {
        s.visit(&mut |st| {
            if reverts {
                return;
            }
            match &st.kind {
                // `revert ...;` / `revert Error(...)`.
                StmtKind::Revert { .. } => reverts = true,
                // `require(...)` / `assert(...)` — a builtin call in expression
                // position. Either bubbles a failure and bricks the batch.
                StmtKind::Expr(e) => {
                    e.visit(&mut |x| {
                        if let ExprKind::Call(c) = &x.kind {
                            if let Some(name) = c.func_name.as_deref() {
                                let l = name.to_ascii_lowercase();
                                if l == "require" || l == "assert" {
                                    reverts = true;
                                }
                            }
                        }
                    });
                }
                _ => {}
            }
        });
        if reverts {
            break;
        }
    }
    reverts
}

/// A pull-payment splitter — `withdraw`/`claim`/`release`/`collect` — credits a
/// per-recipient ledger and lets each party pull independently, so there is no
/// in-loop push to re-skew. Suppress by the function (or any) name idiom.
fn is_pull_payment(f: &Function) -> bool {
    let n = f.name.to_ascii_lowercase();
    n.contains("withdraw") || n.contains("claim") || n.contains("release") || n.contains("collect")
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "proportional-payout-tx-value")
    }

    // VULN — the real Renzo `PaymentSplitter.receive()` shape: the split is seeded
    // from a re-read `address(this).balance`, each cut is sized
    // `amountLeftToPay / (recipients.length - i)` (a shrinking divisor), and the
    // recipient `call` failure is swallowed (the debit is gated behind
    // `if (success)` and the loop continues instead of reverting).
    const VULN: &str = r#"
        pragma solidity ^0.8.0;
        contract PaymentSplitter {
            address[] public recipients;
            mapping(address => uint256) public amountOwed;
            mapping(address => uint256) public totalAmountPaid;
            uint256 private constant DUST_AMOUNT = 1_000_000 gwei;
            address public fallbackPaymentAddress;

            receive() external payable {
                uint256 amountLeftToPay = address(this).balance;
                if (amountLeftToPay == 0) {
                    return;
                }
                for (uint256 i = 0; i < recipients.length; i++) {
                    uint256 amountToPay = amountLeftToPay / (recipients.length - i);
                    if (amountOwed[recipients[i]] < amountToPay) {
                        amountToPay = amountOwed[recipients[i]];
                    }
                    if (amountToPay == 0) {
                        continue;
                    }
                    (bool success, ) = recipients[i].call{ value: amountToPay }("");
                    if (success) {
                        amountOwed[recipients[i]] -= amountToPay;
                        amountLeftToPay -= amountToPay;
                        totalAmountPaid[recipients[i]] += amountToPay;
                    }
                }
            }
        }
    "#;

    // SAFE (fixed / per-recipient amount): the same push loop, but each recipient
    // is paid exactly what it is OWED (a fixed per-recipient ledger amount), not a
    // re-read-balance cut divided by a shrinking count. No `balance / (n - i)`
    // sizing → no order-dependent skew → must stay silent.
    const SAFE_FIXED_AMOUNT: &str = r#"
        pragma solidity ^0.8.0;
        contract FixedSplitter {
            address[] public recipients;
            mapping(address => uint256) public amountOwed;

            receive() external payable {
                for (uint256 i = 0; i < recipients.length; i++) {
                    uint256 amountToPay = amountOwed[recipients[i]];
                    if (amountToPay == 0) {
                        continue;
                    }
                    (bool success, ) = recipients[i].call{ value: amountToPay }("");
                    if (success) {
                        amountOwed[recipients[i]] -= amountToPay;
                    }
                }
            }
        }
    "#;

    // SAFE (pull-payment): credits a per-recipient ledger from the incoming value;
    // each recipient pulls its own funds via `withdraw()`. No in-loop push of a
    // balance-divided cut → must stay silent.
    const SAFE_PULL: &str = r#"
        pragma solidity ^0.8.0;
        contract PullSplitter {
            address[] public recipients;
            uint256[] public weights;
            uint256 public totalWeight;
            mapping(address => uint256) public credited;

            receive() external payable {
                for (uint256 i = 0; i < recipients.length; i++) {
                    credited[recipients[i]] += msg.value * weights[i] / totalWeight;
                }
            }

            function withdraw() external {
                uint256 amt = credited[msg.sender];
                credited[msg.sender] = 0;
                (bool ok, ) = msg.sender.call{ value: amt }("");
                require(ok, "transfer failed");
            }
        }
    "#;

    // SAFE (DoS / batch-bricking inverse): identical balance-reread + `n - i`
    // sizing, BUT the send failure is BUBBLED via `require(success)` — this reverts
    // the whole batch on one failure, which is the `dos.rs` class, NOT the
    // swallow-and-reskew class. This detector must stay silent (left to dos.rs).
    const SAFE_REVERTS_ON_FAILURE: &str = r#"
        pragma solidity ^0.8.0;
        contract RevertingSplitter {
            address[] public recipients;
            mapping(address => uint256) public amountOwed;

            receive() external payable {
                uint256 amountLeftToPay = address(this).balance;
                for (uint256 i = 0; i < recipients.length; i++) {
                    uint256 amountToPay = amountLeftToPay / (recipients.length - i);
                    (bool success, ) = recipients[i].call{ value: amountToPay }("");
                    require(success, "transfer failed");
                    amountOwed[recipients[i]] -= amountToPay;
                    amountLeftToPay -= amountToPay;
                }
            }
        }
    "#;

    // SAFE (fixed-denominator pro-rata): a per-iteration pro-rata `balance * weight
    // / totalWeight` with a CONSTANT denominator — not a shrinking `n - i` divisor.
    // The split is not order-dependent, so this is not the class. Must stay silent.
    const SAFE_PRORATA_FIXED_DENOM: &str = r#"
        pragma solidity ^0.8.0;
        contract ProRata {
            address[] public recipients;
            uint256[] public weights;
            uint256 public totalWeight;

            receive() external payable {
                uint256 bal = address(this).balance;
                for (uint256 i = 0; i < recipients.length; i++) {
                    uint256 amountToPay = bal * weights[i] / totalWeight;
                    (bool success, ) = recipients[i].call{ value: amountToPay }("");
                    if (success) {
                        // booked elsewhere
                    }
                }
            }
        }
    "#;

    // SAFE (single balance forward, no loop): the common LST/recovery shape —
    // sweep the whole `address(this).balance` to ONE address. No loop, no shrinking
    // `n - i` divisor, no per-recipient skew. Must stay silent (this is the kind of
    // pattern that appears all over the prior codebases).
    const SAFE_SINGLE_FORWARD: &str = r#"
        pragma solidity ^0.8.0;
        contract Sweeper {
            address public treasury;
            function sweep() external {
                uint256 bal = address(this).balance;
                (bool ok, ) = treasury.call{ value: bal }("");
                require(ok, "sweep failed");
            }
        }
    "#;

    // VULN (`.transfer` send path): same balance-reread + shrinking `n - i` divisor,
    // but the per-recipient send is `recipients[i].transfer(amountToPay)` and the
    // accounting is booked unconditionally afterwards (no revert on a failed send —
    // `.transfer` of course reverts on failure, but the structural anchors here are
    // the balance-reread proportional sizing + a value send in the loop; the
    // `.transfer` arg is the amount). Exercises the `send_value_amount` transfer arm.
    const VULN_TRANSFER: &str = r#"
        pragma solidity ^0.8.0;
        contract TransferSplitter {
            address payable[] public recipients;
            mapping(address => uint256) public amountOwed;

            receive() external payable {
                uint256 amountLeftToPay = address(this).balance;
                for (uint256 i = 0; i < recipients.length; i++) {
                    uint256 amountToPay = amountLeftToPay / (recipients.length - i);
                    if (amountToPay == 0) {
                        continue;
                    }
                    recipients[i].transfer(amountToPay);
                    amountLeftToPay -= amountToPay;
                }
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(
            fs.iter().any(|f| f.detector == "proportional-payout-tx-value"
                && f.function == "receive"),
            "expected proportional-payout-tx-value on receive; got {:#?}",
            fs
        );
    }

    #[test]
    fn fires_on_transfer_send_path() {
        // Note: `.transfer` reverts on failure, so the `loop_reverts_on_send_failure`
        // gate must NOT treat the bare `.transfer(amt)` (no require/revert statement
        // in the body) as a bubbling-failure suppressor — the structural hazard is
        // the balance-reread proportional sizing of an in-loop value send.
        assert!(fires(VULN_TRANSFER), "{:#?}", run(VULN_TRANSFER));
    }

    #[test]
    fn silent_on_single_balance_forward() {
        assert!(!fires(SAFE_SINGLE_FORWARD), "{:#?}", run(SAFE_SINGLE_FORWARD));
    }

    #[test]
    fn silent_on_fixed_amount() {
        assert!(!fires(SAFE_FIXED_AMOUNT), "{:#?}", run(SAFE_FIXED_AMOUNT));
    }

    #[test]
    fn silent_on_pull_payment() {
        assert!(!fires(SAFE_PULL), "{:#?}", run(SAFE_PULL));
    }

    #[test]
    fn silent_when_reverts_on_failure() {
        assert!(!fires(SAFE_REVERTS_ON_FAILURE), "{:#?}", run(SAFE_REVERTS_ON_FAILURE));
    }

    #[test]
    fn silent_on_fixed_denominator_prorata() {
        assert!(!fires(SAFE_PRORATA_FIXED_DENOM), "{:#?}", run(SAFE_PRORATA_FIXED_DENOM));
    }
}

