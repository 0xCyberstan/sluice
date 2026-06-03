//! Bond/stake credited *pre-verdict* and refunded on a status/mode flag with no
//! per-claim win predicate — a dispute-game / escrow accounting-invariant class.
//!
//! ## The shape
//!
//! A two-phase bonded protocol:
//!
//!   * **fn-A (the poster / deposit / move)** credits a bond to the participant who
//!     *posts* it, on the very action that posts it — an additive write to a
//!     `mapping(address => uint)` ledger keyed by `msg.sender`, fed by the value the
//!     caller just sent:
//!
//!     ```solidity
//!     function move(...) public payable {
//!         ...
//!         refundModeCredit[msg.sender] += msg.value;   // credited when the bond is POSTED
//!         weth().deposit{ value: msg.value }();
//!     }
//!     ```
//!
//!     The credit is recorded *before* the dispute is decided: every depositor —
//!     attacker and defender, eventual winner and eventual loser — accrues a
//!     refund-mode credit equal to what they put in.
//!
//!   * **fn-B (the claim / withdraw)** pays out that *same* ledger, gated **only** on
//!     a status / distribution-**mode** flag, and **without** any per-claim
//!     did-this-participant-win predicate:
//!
//!     ```solidity
//!     function claimCredit(address _recipient) external {
//!         closeGame();
//!         uint256 recipientCredit;
//!         if (bondDistributionMode == BondDistributionMode.REFUND) {
//!             recipientCredit = refundModeCredit[_recipient];   // gated ONLY on the mode enum
//!         } else if (bondDistributionMode == BondDistributionMode.NORMAL) {
//!             recipientCredit = normalModeCredit[_recipient];
//!         }
//!         ...
//!         (bool success,) = _recipient.call{ value: recipientCredit }("");  // pays the pre-verdict credit
//!     }
//!     ```
//!
//! The hazard is the *missing* per-claim binding. The `NORMAL`-mode ledger
//! (`normalModeCredit`) is populated only by a winner-selecting routine
//! (`_distributeBond(counteredBy == address(0) ? claimant : challenger, ...)`), so
//! its payout is implicitly bound to who won. The `REFUND`-mode ledger, by
//! contrast, was credited at *post* time to **everyone**, and the claim path pays it
//! out on the strength of the mode flag alone — there is no
//! `counteredBy == address(0)` / `status == DEFENDER_WINS` / winner check anywhere on
//! that payout path. Whether such a refund is intended (a globally-invalidated game)
//! or a bug (a per-claim refund that should have honored the verdict), the invariant
//! worth surfacing is identical: **a credit posted before the verdict is paid out on
//! a status/mode flag with no did-win predicate**, so the safety of the payout rests
//! entirely on the mode flag being set correctly rather than on the recipient having
//! actually won their claim. This is the Optimism `FaultDisputeGame` refund-mode
//! shape (`refundModeCredit[msg.sender] += msg.value` in `move`/`initialize`, paid by
//! `claimCredit` gated on `bondDistributionMode == REFUND`).
//!
//! ## Precision anchors (all required)
//!
//!   * **fn-A** is an externally-reachable, state-mutating *poster* that does an
//!     **additive credit** `creditMap[msg.sender] += <value>` into a
//!     `mapping(address => uint)` state var (the value root-resolving to `msg.value`
//!     or a `bond`-shaped local) — the bond is recorded on the posting action;
//!   * **fn-B** is an externally-reachable *claim/withdraw* that **reads that same
//!     `creditMap[recipient]`** and pays it out (a native-ETH send, or a
//!     `weth`/escrow `unlock`/`withdraw` of that amount to the recipient);
//!   * **fn-B's read/payout of the credit is gated on a status/mode flag** — a
//!     comparison of a *mode/status/finalized/closed*-named state var against an enum
//!     variant or boolean (`mode == REFUND`, `isFinalized`, `closed`);
//!   * **fn-B has NO per-claim win/counter predicate** — nowhere on its body does it
//!     compare a `counteredBy`/`claimant`/`winner`-shaped value (e.g.
//!     `counteredBy == address(0)`, `status == DEFENDER_WINS`).
//!
//! ## Suppression (keeps this off ordinary pull-payment vaults)
//!
//! Per the class definition we fire **only** when at least one of the following
//! "this is verdict-shaped accounting, not a plain vault" signals holds:
//!
//!   * the contract declares **two distinct credit/bond ledgers** (the
//!     `refundModeCredit` + `normalModeCredit` split — a refund ledger and a
//!     winner-paid ledger), OR
//!   * **a mode *enum* gates the payout** — fn-B compares a mode/status state var
//!     against an `ALL_CAPS` enum variant (not merely a bare bool).
//!
//! A single-ledger pull-payment vault (`credit[msg.sender] += x` then
//! `withdraw()` paying `credit[msg.sender]`) has neither a second ledger nor an
//! enum-gated mode branch, so it stays silent. And any fn-B that *does* carry a
//! win/counter predicate (the credit is bound to who won) is out of class.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{AssignOp, BinOp, CallKind, Contract, Expr, ExprKind, Function, Lit, Span, StmtKind};

use super::prelude::*;

pub struct RefundCreditPreVerdictDetector;

impl Detector for RefundCreditPreVerdictDetector {
    fn id(&self) -> &'static str {
        "refund-credit-pre-verdict"
    }
    fn category(&self) -> Category {
        Category::RefundCreditPreVerdict
    }
    fn description(&self) -> &'static str {
        "A bond/stake credited to a participant on the action that posts it, refunded by a claim/withdraw \
         gated only on a status/distribution-mode flag with no per-claim did-win/counteredBy predicate \
         (Optimism FaultDisputeGame refund-mode class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for contract in cx.scir.contracts.values() {
            if !contract.is_concrete() {
                continue;
            }
            if let Some(hit) = analyze_contract(cx, contract) {
                out.push(self.finding(cx, &hit));
            }
        }
        out
    }
}

impl RefundCreditPreVerdictDetector {
    fn finding(&self, cx: &AnalysisContext, hit: &Hit) -> Finding {
        let b = report!(self, Category::RefundCreditPreVerdict,
            title = "Bond credited pre-verdict is refunded on a status/mode flag with no per-claim win predicate",
            severity = Severity::High,
            confidence = 0.78,
            dimensions = [Dimension::Invariant, Dimension::Frontier],
            message = format!(
                "`{poster}` credits a bond to the participant that posts it — `{credit}[msg.sender] += {value}` \
                 into the `mapping(address => uint)` ledger `{credit}`, on the very action that posts the bond, \
                 so the credit is recorded *before* the dispute is decided (every depositor accrues it, winner \
                 and loser alike). `{payout}` then pays that same ledger out: it reads `{credit}[{recipient}]` \
                 and sends it ({mover}), gated **only** on a status/distribution-mode flag ({mode_gate}) and with \
                 **no per-claim did-win / counteredBy predicate** anywhere on the payout path (no \
                 `counteredBy == address(0)`, no `status == DEFENDER_WINS`, no winner/claimant check). The safety \
                 of the refund therefore rests entirely on the mode flag being set correctly rather than on the \
                 recipient having actually won their claim — a credit posted pre-verdict is released on a mode \
                 flag alone. {why}. This is the Optimism `FaultDisputeGame` refund-mode invariant \
                 (`refundModeCredit[msg.sender] += msg.value` posted in `move`/`initialize`, paid by \
                 `claimCredit` gated on `bondDistributionMode == REFUND`).",
                poster = hit.poster_name,
                payout = hit.payout_name,
                credit = hit.credit_var,
                value = hit.credited_value,
                recipient = hit.payout_key,
                mover = hit.mover_desc,
                mode_gate = hit.mode_gate_desc,
                why = hit.why,
            ),
            recommendation =
                "Bind the refund to the verdict, not merely to a distribution-mode flag. On the claim/withdraw \
                 path, require the recipient actually won their claim before paying a bond credited at post time \
                 (check the per-claim `counteredBy == address(0)` / resolved-winner before crediting the \
                 refundable amount), or populate the refundable ledger only from a winner-selecting resolution \
                 routine (the way the normal-mode ledger is fed by `_distributeBond(counteredBy == address(0) ? \
                 claimant : challenger, ...)`) so that what is paid out is already a function of who won. If a \
                 blanket refund is genuinely intended (a globally-invalidated game), gate it on an explicit \
                 game-level invalidation predicate rather than on the bond-distribution mode alone, and ensure \
                 that mode can only be entered when no honest verdict is being overridden.",
        );
        finish_at(cx, b, hit.payout_fid, hit.span)
    }
}

// --------------------------------------------------------------------- analysis

/// A matched pre-verdict-refund pairing within one contract.
struct Hit {
    poster_name: String,
    payout_name: String,
    payout_fid: sluice_ir::FunctionId,
    /// The credit-ledger state var (`refundModeCredit`).
    credit_var: String,
    /// Textual credited value (`msg.value` / a bond local).
    credited_value: String,
    /// The recipient key root the payout reads the credit by (`_recipient`).
    payout_key: String,
    /// Human description of the value move (`_recipient.call{value: ...}` / `weth().unlock(...)`).
    mover_desc: String,
    /// Human description of the status/mode gate (`bondDistributionMode == REFUND`).
    mode_gate_desc: String,
    /// Which suppression-gate signal qualified the contract (two ledgers / enum mode).
    why: String,
    /// Report location (the value move in fn-B).
    span: Span,
}

fn analyze_contract(cx: &AnalysisContext, contract: &Contract) -> Option<Hit> {
    // (1) Find every additive `creditMap[msg.sender] += value` post across the
    //     contract's functions — the bonds recorded on the posting action.
    let posts = find_credit_posts(cx, contract);
    if posts.is_empty() {
        return None;
    }

    // (2) For each posted credit ledger, look for a claim/withdraw fn-B that reads
    //     that same ledger by a recipient key, pays it out, is gated on a status/mode
    //     flag, and has NO per-claim win/counter predicate.
    for post in &posts {
        for f in cx.scir.functions_of(contract.id) {
            if !f.has_body || !f.is_externally_reachable() || f.is_view_or_pure() {
                continue;
            }
            // fn-B should read the credit ledger and pay something out — a claim path.
            let Some(payout) = find_credit_payout(f, &post.credit_var) else { continue };

            // The credit read/payout must be gated on a status/mode flag.
            let Some(mode_gate) = find_mode_gate(f) else { continue };

            // DISQUALIFY: a per-claim win/counter predicate anywhere on fn-B binds the
            // payout to who won — out of class.
            if has_win_counter_predicate(f) {
                continue;
            }

            // SUPPRESS unless this is verdict-shaped accounting (not a plain vault):
            //   two distinct credit ledgers, OR an enum-gated mode branch.
            let why = match suppression_signal(contract, &mode_gate) {
                Some(w) => w,
                None => continue,
            };

            return Some(Hit {
                poster_name: post.poster_name.clone(),
                payout_name: f.name.clone(),
                payout_fid: f.id,
                credit_var: post.credit_var.clone(),
                credited_value: post.credited_value.clone(),
                payout_key: payout.key_root,
                mover_desc: payout.mover_desc,
                mode_gate_desc: mode_gate.desc,
                why,
                span: payout.span,
            });
        }
    }
    None
}

// ------------------------------------------------- (1) credit posts (fn-A)

/// A `creditMap[msg.sender] += value` post located in some poster function.
struct CreditPost {
    poster_name: String,
    /// The credit-ledger state var name.
    credit_var: String,
    /// Textual credited value.
    credited_value: String,
}

/// Find all additive credits `creditMap[msg.sender] += <value>` where `creditMap`
/// is a `mapping(address => uint)` state var, the index key is `msg.sender`, and the
/// credited value root-resolves to `msg.value` or a bond-shaped local. We require the
/// poster to be externally reachable and state-mutating (a real deposit/move path).
fn find_credit_posts(cx: &AnalysisContext, contract: &Contract) -> Vec<CreditPost> {
    let mut out: Vec<CreditPost> = Vec::new();
    for f in cx.scir.functions_of(contract.id) {
        if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
            continue;
        }
        for top in &f.body {
            top.visit_exprs(&mut |e| {
                let ExprKind::Assign { op, target, value } = &e.kind else { return };
                // Additive credit only (`+=`), or a `m[k] = m[k] + v` rewrite.
                let plain_add = matches!(op, AssignOp::Add);
                if !plain_add && !is_self_plus_assign(target, value) {
                    return;
                }
                // target must be `creditMap[key]`.
                let ExprKind::Index { base, index: Some(key) } = &target.kind else { return };
                let Some(credit_var) = root_ident_str(base) else { return };
                if !is_addr_uint_mapping(contract, credit_var) {
                    return;
                }
                // The credit must be keyed by `msg.sender` (the participant posting).
                if !is_msg_sender(key) {
                    return;
                }
                // The credited value is `msg.value` or a bond-shaped local/amount.
                if !value_is_bond_like(value) {
                    return;
                }
                if out.iter().any(|p| p.credit_var == credit_var && p.poster_name == f.name) {
                    return;
                }
                out.push(CreditPost {
                    poster_name: f.name.clone(),
                    credit_var: credit_var.to_string(),
                    credited_value: describe_value(value),
                });
            });
        }
    }
    out
}

/// `m[k] += v` may also surface as `m[k] = m[k] + v`. True when `target` (an lvalue)
/// reappears inside `value` under an `Add`.
fn is_self_plus_assign(target: &Expr, value: &Expr) -> bool {
    let ExprKind::Binary { op: BinOp::Add, lhs, rhs } = &value.kind else { return false };
    let same = |e: &Expr| exprs_textually_eq(e, target);
    same(lhs) || same(rhs)
}

/// Structural equality of two lvalue expressions, good enough for `m[k]` vs `m[k]`.
fn exprs_textually_eq(a: &Expr, b: &Expr) -> bool {
    match (&a.kind, &b.kind) {
        (ExprKind::Ident(x), ExprKind::Ident(y)) => x == y,
        (ExprKind::Member { base: ba, member: ma }, ExprKind::Member { base: bb, member: mb }) => {
            ma == mb && exprs_textually_eq(ba, bb)
        }
        (ExprKind::Index { base: ba, index: ia }, ExprKind::Index { base: bb, index: ib }) => {
            exprs_textually_eq(ba, bb)
                && match (ia, ib) {
                    (Some(x), Some(y)) => exprs_textually_eq(x, y),
                    (None, None) => true,
                    _ => false,
                }
        }
        _ => false,
    }
}

/// Is `name` a contract state var of type `mapping(address => uint*)` (the credit
/// ledger shape)? We accept the value type being any `uint`/`int` width.
fn is_addr_uint_mapping(contract: &Contract, name: &str) -> bool {
    contract.state_vars.iter().any(|v| {
        if v.name != name {
            return false;
        }
        let ty = v.ty.replace(char::is_whitespace, "");
        // A single-level mapping (not nested) from address to a numeric value.
        if ty.matches("mapping").count() != 1 {
            return false;
        }
        let inner = ty.strip_prefix("mapping(").and_then(|s| s.strip_suffix(')')).unwrap_or(&ty);
        let Some((k, val)) = inner.split_once("=>") else { return false };
        k.trim() == "address" && {
            let v = val.trim().trim_end_matches(')').trim();
            v.starts_with("uint") || v.starts_with("int")
        }
    })
}

/// Is `e` `msg.sender`?
fn is_msg_sender(e: &Expr) -> bool {
    matches!(&peel_casts(e).kind,
        ExprKind::Member { base, member } if member == "sender"
            && matches!(&base.kind, ExprKind::Ident(b) if b == "msg"))
}

/// Does the credited value read as a posted *bond* — `msg.value`, or a local/field
/// whose name reads `bond`/`stake`/`deposit`/`amount`/`value`? We accept `msg.value`
/// (the canonical post) and a bond-named operand (`uint128(msg.value)` localized to a
/// `bond` field), and reject obviously unrelated values.
fn value_is_bond_like(e: &Expr) -> bool {
    let pe = peel_casts(e);
    // Direct `msg.value`.
    let mut reads_msg_value = false;
    pe.visit(&mut |x| {
        if let ExprKind::Member { base, member } = &x.kind {
            if member == "value" && matches!(&base.kind, ExprKind::Ident(b) if b == "msg") {
                reads_msg_value = true;
            }
        }
    });
    if reads_msg_value {
        return true;
    }
    // A bond/stake/amount-named identifier or member.
    let mut bondish = false;
    pe.visit(&mut |x| {
        let nm = match &x.kind {
            ExprKind::Ident(n) => Some(n.as_str()),
            ExprKind::Member { member, .. } => Some(member.as_str()),
            _ => None,
        };
        if let Some(n) = nm {
            let l = n.to_ascii_lowercase();
            if l.contains("bond") || l.contains("stake") || l.contains("deposit") {
                bondish = true;
            }
        }
    });
    bondish
}

/// Textual description of a credited value (best-effort).
fn describe_value(e: &Expr) -> String {
    match &peel_casts(e).kind {
        ExprKind::Member { base, member } => {
            if let ExprKind::Ident(b) = &base.kind {
                format!("{b}.{member}")
            } else {
                member.clone()
            }
        }
        ExprKind::Ident(n) => n.clone(),
        _ => "msg.value".to_string(),
    }
}

// ------------------------------------------------- (2) credit payout (fn-B)

/// The credit-read + value-move located in fn-B.
struct CreditPayout {
    /// The recipient key root the credit is read by (`_recipient`).
    key_root: String,
    /// Human description of the value move.
    mover_desc: String,
    /// Report span (the value move).
    span: Span,
}

/// In fn-B, find a read of `creditMap[recipient]` (the same ledger) whose value is
/// paid out — either bound to a local that is later sent natively, or passed as the
/// amount to a `weth`/escrow `unlock`/`withdraw`-style call, or sent inline. Returns
/// the recipient key and the value-move location.
fn find_credit_payout(f: &Function, credit_var: &str) -> Option<CreditPayout> {
    // Locals bound from `creditMap[key]` -> (local, key_root).
    let mut credit_locals: Vec<(String, String)> = Vec::new();
    // The recipient key root (first credit read encountered).
    let mut key_root: Option<String> = None;

    for top in &f.body {
        top.visit(&mut |st| {
            // `uint256 c = creditMap[recipient];`
            if let StmtKind::VarDecl { name: Some(local), init: Some(init), .. } = &st.kind {
                if let Some(k) = credit_index_key(init, credit_var) {
                    key_root.get_or_insert_with(|| k.clone());
                    credit_locals.push((local.clone(), k));
                }
            }
            // `c = creditMap[recipient];` (assignment form, as in claimCredit's
            // `recipientCredit = refundModeCredit[_recipient];`).
            if let StmtKind::Expr(e) = &st.kind {
                e.visit(&mut |x| {
                    if let ExprKind::Assign { target, value, .. } = &x.kind {
                        if let Some(k) = credit_index_key(value, credit_var) {
                            key_root.get_or_insert_with(|| k.clone());
                            if let ExprKind::Ident(local) = &target.kind {
                                credit_locals.push((local.clone(), k));
                            }
                        }
                    }
                });
            }
        });
    }
    // No read of this ledger in fn-B.
    let key_root = key_root?;

    // Now find the value move: a native send, or a weth/escrow withdraw/unlock, whose
    // amount references a credit local (or reads the ledger inline).
    let mut mover: Option<(String, Span)> = None;
    for top in &f.body {
        top.visit_exprs(&mut |e| {
            if mover.is_some() {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            // (a) native ETH send whose `{value:}` (or transfer/send arg) is a credit local.
            if let Some(amount) = native_send_amount(c) {
                if amount_uses_credit(amount, &credit_locals, credit_var) {
                    mover = Some((describe_send(c), e.span));
                    return;
                }
            }
            // (b) a withdraw/unlock-style external call paying the credit out to the
            //     recipient (`weth().unlock(_recipient, recipientCredit)` /
            //     `weth().withdraw(_recipient, recipientCredit)`).
            if c.func_name.as_deref().map(is_payout_method).unwrap_or(false)
                && matches!(c.kind, CallKind::External | CallKind::Internal | CallKind::LowLevelCall)
                && c.args.iter().any(|a| amount_uses_credit(a, &credit_locals, credit_var))
            {
                mover = Some((describe_call_method(c), e.span));
            }
        });
        if mover.is_some() {
            break;
        }
    }
    let (mover_desc, span) = mover?;
    Some(CreditPayout { key_root, mover_desc, span })
}

/// If `e` is exactly `creditMap[key]` (possibly cast-wrapped), return the key's root
/// identifier.
fn credit_index_key(e: &Expr, credit_var: &str) -> Option<String> {
    if let ExprKind::Index { base, index: Some(key) } = &peel_casts(e).kind {
        if root_ident_str(base) == Some(credit_var) {
            return root_ident_peeled(key);
        }
    }
    None
}

/// The amount of a native send: `{value:}` operand, or first arg of `.transfer`/`.send`.
fn native_send_amount(c: &sluice_ir::Call) -> Option<&Expr> {
    if let Some(v) = &c.value {
        return Some(v);
    }
    if matches!(c.kind, CallKind::Transfer | CallKind::Send) {
        return c.args.first();
    }
    None
}

/// Does `amount` reference a credit local, or read the ledger inline?
fn amount_uses_credit(amount: &Expr, credit_locals: &[(String, String)], credit_var: &str) -> bool {
    let mut hit = false;
    amount.visit(&mut |x| {
        if hit {
            return;
        }
        match &x.kind {
            ExprKind::Ident(n) if credit_locals.iter().any(|(local, _)| local == n) => hit = true,
            ExprKind::Index { base, .. } if root_ident_str(base) == Some(credit_var) => hit = true,
            _ => {}
        }
    });
    hit
}

/// A method name that pays a credited amount out of an escrow/WETH wrapper
/// (`unlock`, `withdraw`, `release`, `transfer`/`send` are covered separately).
fn is_payout_method(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "unlock" || l == "withdraw" || l == "release" || l == "payout" || l == "redeem"
}

fn describe_send(c: &sluice_ir::Call) -> String {
    let recv = c
        .receiver
        .as_deref()
        .and_then(|r| match &peel_casts(r).kind {
            ExprKind::Ident(n) => Some(n.clone()),
            ExprKind::Member { member, .. } => Some(member.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "recipient".into());
    format!("{recv}.call{{ value: <credit> }}(...)")
}

fn describe_call_method(c: &sluice_ir::Call) -> String {
    let method = c.func_name.clone().unwrap_or_else(|| "withdraw".into());
    let recv = c
        .receiver
        .as_deref()
        .and_then(|r| match &peel_casts(r).kind {
            ExprKind::Ident(n) => Some(n.clone()),
            ExprKind::Member { member, .. } => Some(member.clone()),
            ExprKind::Call(_) => Some("weth()".into()),
            _ => None,
        })
        .unwrap_or_else(|| "escrow".into());
    format!("{recv}.{method}(..., <credit>)")
}

// ------------------------------------------------- (status/mode gate)

/// A status/distribution-mode gate located in fn-B.
struct ModeGate {
    desc: String,
    /// True if the gate compares against an `ALL_CAPS` enum variant (mode *enum*),
    /// as opposed to a bare boolean flag.
    is_enum: bool,
}

/// Find a guard in fn-B that gates on a *status / distribution-mode* flag: a
/// comparison whose operand is a `mode`/`status`/`finalized`/`closed`/`distribution`-
/// named state-var-ish identifier (the `if (bondDistributionMode == REFUND)` /
/// `if (isFinalized)` shape). Records whether the comparison is against an `ALL_CAPS`
/// enum variant.
fn find_mode_gate(f: &Function) -> Option<ModeGate> {
    let mut best: Option<ModeGate> = None;
    for top in &f.body {
        top.visit_exprs(&mut |e| {
            if best.as_ref().map(|g| g.is_enum).unwrap_or(false) {
                return; // already found the strongest (enum) gate
            }
            // `mode == VARIANT` / `status != X`.
            if let ExprKind::Binary { op: op @ (BinOp::Eq | BinOp::Ne), lhs, rhs } = &e.kind {
                let l_mode = is_mode_status_name_expr(lhs);
                let r_mode = is_mode_status_name_expr(rhs);
                if l_mode || r_mode {
                    let other = if l_mode { rhs } else { lhs };
                    let is_enum = expr_is_enum_variant(other);
                    let desc = format!(
                        "`{} {} {}`",
                        short_expr(if l_mode { lhs } else { rhs }),
                        if matches!(op, BinOp::Eq) { "==" } else { "!=" },
                        short_expr(other),
                    );
                    promote(&mut best, ModeGate { desc, is_enum });
                }
            }
        });
    }
    // Also accept a bare boolean status flag used as an `if`/`require` condition
    // (`if (isFinalized)`, `if (!closed) revert`), if no comparison-form gate found.
    if best.is_none() {
        for top in &f.body {
            top.visit(&mut |st| {
                if best.is_some() {
                    return;
                }
                if let StmtKind::If { cond, .. } = &st.kind {
                    if let Some(name) = bare_bool_status_name(cond) {
                        best = Some(ModeGate { desc: format!("`{name}`"), is_enum: false });
                    }
                }
            });
        }
    }
    best
}

fn promote(slot: &mut Option<ModeGate>, g: ModeGate) {
    match slot {
        Some(existing) if existing.is_enum => {}
        _ => *slot = Some(g),
    }
}

/// Does `e` root-resolve to a `mode`/`status`/`finalized`/`closed`/`distribution`-
/// named identifier or member? (the distribution-mode / game-status flag).
fn is_mode_status_name_expr(e: &Expr) -> bool {
    root_ident_peeled(e).map(|r| is_mode_status_name(&r)).unwrap_or(false)
        || matches!(&peel_casts(e).kind, ExprKind::Member { member, .. } if is_mode_status_name(member))
}

fn is_mode_status_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("mode")
        || l.contains("status")
        || l.contains("finaliz")
        || l == "closed"
        || l.contains("distribution")
        || l.contains("phase")
        || l == "state"
        || l.contains("resolved")
}

/// Is `e` an `ALL_CAPS`(-ish) enum variant — a bare or member-accessed identifier
/// whose terminal segment is all-uppercase with an underscore or ≥3 caps
/// (`REFUND`, `BondDistributionMode.REFUND`, `DEFENDER_WINS`)?
fn expr_is_enum_variant(e: &Expr) -> bool {
    let seg = match &peel_casts(e).kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { member, .. } => Some(member.clone()),
        _ => None,
    };
    seg.map(|s| is_screaming_case(&s)).unwrap_or(false)
}

/// SCREAMING_CASE heuristic: all the alphabetic chars are uppercase and the token is
/// not a single short word like `WAD`/`ETH` accidentally — we accept underscores or
/// length ≥ 3 of all-caps.
fn is_screaming_case(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let alpha: Vec<char> = s.chars().filter(|c| c.is_alphabetic()).collect();
    if alpha.is_empty() {
        return false;
    }
    let all_upper = alpha.iter().all(|c| c.is_ascii_uppercase());
    all_upper && (s.contains('_') || alpha.len() >= 3)
}

/// If `cond` is (or directly negates) a bare boolean status flag identifier, return
/// its name. `if (isFinalized)` / `if (!closed)`.
fn bare_bool_status_name(cond: &Expr) -> Option<String> {
    let inner = match &cond.kind {
        ExprKind::Unary { op: sluice_ir::UnOp::Not, operand } => operand.as_ref(),
        _ => cond,
    };
    match &inner.kind {
        ExprKind::Ident(n) if is_mode_status_name(n) => Some(n.clone()),
        ExprKind::Member { member, .. } if is_mode_status_name(member) => Some(member.clone()),
        _ => None,
    }
}

fn short_expr(e: &Expr) -> String {
    match &peel_casts(e).kind {
        ExprKind::Ident(n) => n.clone(),
        ExprKind::Member { base, member } => {
            if let ExprKind::Ident(b) = &base.kind {
                format!("{b}.{member}")
            } else {
                member.clone()
            }
        }
        ExprKind::Lit(Lit::Number(n)) => n.clone(),
        _ => "…".into(),
    }
}

// ------------------------------------------------- (win/counter predicate)

/// Does fn-B carry a **per-claim win/counter predicate** — a comparison involving a
/// `counteredBy`/`claimant`/`winner`/`challenger`-shaped value, or a status compared
/// against a `*_WINS`/`DEFENDER`/`CHALLENGER` enum variant? Such a predicate binds the
/// payout to who won, taking it out of class.
fn has_win_counter_predicate(f: &Function) -> bool {
    let mut found = false;
    for top in &f.body {
        top.visit_exprs(&mut |e| {
            if found {
                return;
            }
            let ExprKind::Binary { op, lhs, rhs } = &e.kind else { return };
            if !op.is_comparison() {
                return;
            }
            if expr_is_win_counter(lhs) || expr_is_win_counter(rhs) {
                found = true;
            }
        });
        if found {
            break;
        }
    }
    found
}

/// Is `e` (anywhere within) a win/counter-shaped operand — a `counteredBy`/`claimant`/
/// `winner`/`challenger`/`prevailing`-named identifier or member, or a `*_WINS`/
/// `DEFENDER`/`CHALLENGER` enum variant?
fn expr_is_win_counter(e: &Expr) -> bool {
    let mut hit = false;
    e.visit(&mut |x| {
        if hit {
            return;
        }
        let nm = match &x.kind {
            ExprKind::Ident(n) => Some(n.as_str()),
            ExprKind::Member { member, .. } => Some(member.as_str()),
            _ => None,
        };
        if let Some(n) = nm {
            let l = n.to_ascii_lowercase();
            if l.contains("counteredby")
                || l.contains("countered")
                || l.contains("claimant")
                || l.contains("winner")
                || l.contains("challenger")
                || l.contains("prevail")
                || l.contains("defender")
                || l.contains("wins")
            {
                hit = true;
            }
        }
    });
    hit
}

// ------------------------------------------------- (suppression signal)

/// SUPPRESS unless the contract is verdict-shaped accounting (not a plain vault):
///   (a) two distinct credit/bond ledgers (`mapping(address => uint)` whose names
///       read credit/bond/stake/refund/normal), OR
///   (b) an enum-gated payout mode (the gate compares against an ALL_CAPS variant).
/// Returns a short human reason when one holds.
fn suppression_signal(contract: &Contract, mode_gate: &ModeGate) -> Option<String> {
    // (b) enum-gated mode branch — strongest.
    if mode_gate.is_enum {
        return Some(
            "the payout is gated on a distribution-MODE enum (a refund-mode branch), the \
             FaultDisputeGame-class signal that this is verdict-shaped accounting and not a plain \
             pull-payment vault"
                .into(),
        );
    }
    // (a) two distinct credit/bond ledgers.
    let ledgers: Vec<&str> = contract
        .state_vars
        .iter()
        .filter(|v| is_addr_uint_mapping(contract, &v.name) && is_credit_ledger_name(&v.name))
        .map(|v| v.name.as_str())
        .collect();
    if ledgers.len() >= 2 {
        return Some(format!(
            "the contract declares two distinct credit/bond ledgers (`{}` and `{}`) — a refund ledger \
             and a winner-paid ledger — the FaultDisputeGame split that distinguishes this from a plain \
             single-ledger pull-payment vault",
            ledgers[0], ledgers[1]
        ));
    }
    None
}

/// A `mapping(address => uint)` name that reads as a credit / bond / stake / refund
/// ledger (used only for the two-ledger suppression signal).
fn is_credit_ledger_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("credit")
        || l.contains("bond")
        || l.contains("stake")
        || l.contains("refund")
        || l.contains("escrow")
        || (l.contains("mode") && l.contains("credit"))
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "refund-credit-pre-verdict")
    }

    // VULN — the Optimism `FaultDisputeGame` refund-mode shape, reduced. `move`
    // credits `refundModeCredit[msg.sender] += msg.value` when the bond is POSTED.
    // `claimCredit` reads that same ledger gated only on
    // `bondDistributionMode == BondDistributionMode.REFUND` (an enum mode), pays it
    // out, and carries NO per-claim win/counter predicate. Two distinct ledgers
    // (`refundModeCredit` + `normalModeCredit`) and an enum-gated mode both qualify.
    const VULN: &str = r#"
        pragma solidity 0.8.15;
        interface IWETH { function deposit() external payable; function unlock(address a, uint256 v) external; function withdraw(address a, uint256 v) external; }
        contract FaultDisputeGame {
            enum BondDistributionMode { UNDECIDED, REFUND, NORMAL }
            mapping(address => uint256) public refundModeCredit;
            mapping(address => uint256) public normalModeCredit;
            mapping(address => bool) public hasUnlockedCredit;
            BondDistributionMode public bondDistributionMode;
            IWETH internal _weth;
            function weth() internal view returns (IWETH) { return _weth; }
            function move(uint256 parentIndex) public payable {
                refundModeCredit[msg.sender] += msg.value;
                weth().deposit{ value: msg.value }();
            }
            function claimCredit(address _recipient) external {
                uint256 recipientCredit;
                if (bondDistributionMode == BondDistributionMode.REFUND) {
                    recipientCredit = refundModeCredit[_recipient];
                } else if (bondDistributionMode == BondDistributionMode.NORMAL) {
                    recipientCredit = normalModeCredit[_recipient];
                }
                if (!hasUnlockedCredit[_recipient]) {
                    hasUnlockedCredit[_recipient] = true;
                    weth().unlock(_recipient, recipientCredit);
                    return;
                }
                refundModeCredit[_recipient] = 0;
                normalModeCredit[_recipient] = 0;
                weth().withdraw(_recipient, recipientCredit);
                (bool success,) = _recipient.call{ value: recipientCredit }(hex"");
                if (!success) revert();
            }
        }
    "#;

    // SAFE (per-claim win predicate present): identical posting + a mode-gated claim,
    // but the claim binds the payout to who WON — it checks `counteredBy == address(0)`
    // before paying. The credit is bound to the verdict, so it is out of class.
    const SAFE_WIN_PREDICATE: &str = r#"
        pragma solidity 0.8.15;
        interface IWETH { function deposit() external payable; }
        contract FaultDisputeGame {
            enum BondDistributionMode { UNDECIDED, REFUND, NORMAL }
            struct ClaimData { address counteredBy; address claimant; }
            mapping(address => uint256) public refundModeCredit;
            mapping(address => uint256) public normalModeCredit;
            mapping(address => ClaimData) public claimOf;
            BondDistributionMode public bondDistributionMode;
            IWETH internal _weth;
            function weth() internal view returns (IWETH) { return _weth; }
            function move() public payable {
                refundModeCredit[msg.sender] += msg.value;
                weth().deposit{ value: msg.value }();
            }
            function claimCredit(address _recipient) external {
                uint256 recipientCredit;
                if (bondDistributionMode == BondDistributionMode.REFUND) {
                    recipientCredit = refundModeCredit[_recipient];
                }
                // per-claim win predicate: only the uncountered (winning) claim is paid
                if (claimOf[_recipient].counteredBy != address(0)) revert();
                (bool success,) = _recipient.call{ value: recipientCredit }(hex"");
                if (!success) revert();
            }
        }
    "#;

    // SAFE (plain single-ledger pull-payment vault): one `credit` ledger,
    // `deposit()` credits `credit[msg.sender] += msg.value`, `withdraw()` pays
    // `credit[msg.sender]`. No second ledger and no enum-gated mode branch, so the
    // suppression gate keeps it silent (this is the shape we must NOT light up on).
    const SAFE_PLAIN_VAULT: &str = r#"
        pragma solidity 0.8.15;
        contract EscrowVault {
            mapping(address => uint256) public credit;
            function deposit() external payable {
                credit[msg.sender] += msg.value;
            }
            function withdraw() external {
                uint256 amt = credit[msg.sender];
                credit[msg.sender] = 0;
                (bool ok,) = msg.sender.call{ value: amt }("");
                require(ok, "transfer failed");
            }
        }
    "#;

    // SAFE (single ledger, mode-gated but BARE BOOL, not an enum): one credit ledger,
    // a `bool public closed` flag gating the claim. Only ONE ledger and the gate is a
    // bare boolean (not an enum variant), so neither suppression signal holds → silent.
    const SAFE_SINGLE_LEDGER_BOOL_MODE: &str = r#"
        pragma solidity 0.8.15;
        contract BoolGatedEscrow {
            mapping(address => uint256) public bondCredit;
            bool public closed;
            function deposit() external payable {
                bondCredit[msg.sender] += msg.value;
            }
            function claim(address _recipient) external {
                uint256 amt;
                if (closed) {
                    amt = bondCredit[_recipient];
                }
                (bool ok,) = _recipient.call{ value: amt }("");
                require(ok, "transfer failed");
            }
        }
    "#;

    // SAFE (no mode/status gate at all): two ledgers, credited at post time, but the
    // claim pays unconditionally with no status/mode flag guarding the read. Missing a
    // required anchor (the mode gate) → silent.
    const SAFE_NO_MODE_GATE: &str = r#"
        pragma solidity 0.8.15;
        contract NoGate {
            mapping(address => uint256) public refundCredit;
            mapping(address => uint256) public normalCredit;
            function move() external payable {
                refundCredit[msg.sender] += msg.value;
            }
            function claim(address _recipient) external {
                uint256 amt = refundCredit[_recipient];
                refundCredit[_recipient] = 0;
                (bool ok,) = _recipient.call{ value: amt }("");
                require(ok, "transfer failed");
            }
        }
    "#;

    // SAFE (no posting credit): a contract whose claim reads a mode-gated ledger but
    // the ledger is never credited additively from a `msg.sender` post (it is set by
    // an admin assignment). No `creditMap[msg.sender] += value` poster → silent.
    const SAFE_NO_POST: &str = r#"
        pragma solidity 0.8.15;
        contract NoPost {
            enum Mode { OPEN, REFUND }
            mapping(address => uint256) public refundModeCredit;
            mapping(address => uint256) public normalModeCredit;
            Mode public mode;
            function setCredit(address a, uint256 v) external {
                refundModeCredit[a] = v;   // not a msg.sender += msg.value post
            }
            function claim(address _recipient) external {
                uint256 amt;
                if (mode == Mode.REFUND) {
                    amt = refundModeCredit[_recipient];
                }
                (bool ok,) = _recipient.call{ value: amt }("");
                require(ok, "transfer failed");
            }
        }
    "#;

    #[test]
    fn fires_on_fault_dispute_game_refund_mode() {
        let fs = run(VULN);
        assert!(
            fs.iter().any(|f| f.detector == "refund-credit-pre-verdict" && f.function == "claimCredit"),
            "expected refund-credit-pre-verdict on claimCredit; got {:#?}",
            fs
        );
    }

    #[test]
    fn silent_when_win_predicate_present() {
        assert!(!fires(SAFE_WIN_PREDICATE), "{:#?}", run(SAFE_WIN_PREDICATE));
    }

    #[test]
    fn silent_on_plain_pull_payment_vault() {
        assert!(!fires(SAFE_PLAIN_VAULT), "{:#?}", run(SAFE_PLAIN_VAULT));
    }

    #[test]
    fn silent_on_single_ledger_bool_mode() {
        assert!(!fires(SAFE_SINGLE_LEDGER_BOOL_MODE), "{:#?}", run(SAFE_SINGLE_LEDGER_BOOL_MODE));
    }

    #[test]
    fn silent_without_mode_gate() {
        assert!(!fires(SAFE_NO_MODE_GATE), "{:#?}", run(SAFE_NO_MODE_GATE));
    }

    #[test]
    fn silent_without_posting_credit() {
        assert!(!fires(SAFE_NO_POST), "{:#?}", run(SAFE_NO_POST));
    }
}
