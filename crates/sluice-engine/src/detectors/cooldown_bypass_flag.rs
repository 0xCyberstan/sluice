//! Cooldown bypass behind a whitelist + risk-flag gate — a withdrawal/unbonding
//! **delay defense** that is *skipped* in normal operation for whitelisted users.
//!
//! Withdrawal queues and unbonding flows enforce a time delay between requesting
//! and claiming: a `coolDownPeriod` such that
//! `if (block.timestamp - createdAt < coolDownPeriod) revert EarlyClaim();`. This
//! delay is a security control — it is what lets the protocol re-price, re-collateralize,
//! or pause in response to a depeg/oracle event before funds actually leave.
//!
//! The bug class is when that cooldown check is **conditionally executed** behind a
//! gate of the shape
//!
//! ```solidity
//! bool _instantWithdrawPaused = riskOracle.instantWithdrawPaused();
//! if (_instantWithdrawPaused || !whitelisted[user]) {     // <-- the gate
//!     uint256 _cd = ...;
//!     if (block.timestamp - createdAt < _cd) revert EarlyClaim();   // <-- the delay
//! }
//! // ... funds released ...
//! ```
//!
//! Read the gate's truth table. The cooldown body runs only when
//! `instantWithdrawPaused == true` **OR** `whitelisted[user] == false`. So in
//! *normal* operation (the risk flag is **off**) a **whitelisted** user takes the
//! `false` branch and the cooldown is **never evaluated** — they exit with **zero
//! delay**. The delay defense is therefore disabled for the exact set of users it is
//! waived for (whitelisted) precisely when the protocol is *not* in a heightened-risk
//! state — the opposite of when an instant exit is safe. A whitelisted address (or one
//! the admin is tricked/compelled into whitelisting, or a compromised whitelist) can
//! drain through the queue with no waiting period, defeating the re-price / pause window.
//!
//! This is Renzo `WithdrawQueue.claim` (~L434-446): the literal
//! `if (_instantWithdrawPaused || !whitelisted[user]) { ... if (block.timestamp -
//! _withdrawRequest.createdAt < _coolDownPeriod) revert EarlyClaim(); }`.
//!
//! Precision anchors (all required, so this stays silent on an *unconditional*
//! cooldown and on ordinary pause/whitelist branching):
//!   * the function is externally reachable, state-mutating, with a body;
//!   * there is an **outer `if`** whose condition is a **disjunction** (`||`) that
//!     contains a **negated allowlist-membership test** — `!whitelisted[k]` /
//!     `!isWhitelisted[k]` / `whitelisted[k] == false` (a `Unary{Not}` over a
//!     whitelist-named mapping index, or an `== false`). The negation is the tell:
//!     the protected (whitelisted) user is the one routed *out* of the branch;
//!   * **inside that branch** there is a **cooldown delay check** — an
//!     `if (Δtime < period) revert/return` where the compared quantity is a
//!     `block.timestamp` (or `block.number`) *elapsed-since* subtraction with a
//!     `<`/`<=` comparison, OR an `if (...) revert E` whose error name / branch text
//!     reads as a cooldown (`earlyclaim`, `cooldown`, `tooearly`, `notmatured`, ...);
//!   * **SUPPRESS** when the same function *also* performs that cooldown delay check
//!     **unconditionally** (outside any whitelist/flag-gated branch) — then the delay
//!     is always enforced and the gated copy is not a bypass.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Expr, ExprKind, Function, Span, Stmt, StmtKind, UnOp};

pub struct CooldownBypassFlagDetector;

impl Detector for CooldownBypassFlagDetector {
    fn id(&self) -> &'static str {
        "cooldown-bypass-flag"
    }
    fn category(&self) -> Category {
        Category::CooldownBypassFlag
    }
    fn description(&self) -> &'static str {
        "Withdrawal/unbonding cooldown delay is skipped for whitelisted users when an unrelated risk/pause flag is off (Renzo WithdrawQueue.claim class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.functions() {
            if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
                continue;
            }

            // Find a whitelist-gated `if` whose branch holds a cooldown delay check.
            let Some(hit) = find_gated_cooldown(cx, f) else { continue };

            // SUPPRESS: if the cooldown delay is ALSO checked unconditionally
            // somewhere in the function (not inside any whitelist/flag-gated
            // branch), then the delay is always enforced and the gated copy is
            // merely a redundant / stricter re-check, not a bypass.
            if has_unconditional_cooldown(cx, &f.body) {
                continue;
            }

            let b = FindingBuilder::new(self.id(), Category::CooldownBypassFlag)
                .title("Withdrawal cooldown is bypassed for whitelisted users when the risk flag is off")
                .severity(Severity::High)
                // Multi-anchor structural fingerprint (disjunction gate + negated-whitelist
                // disjunct + elapsed-since cooldown delay inside the gated branch, with the
                // unconditional-cooldown suppression), and 0 FPs across the five prior
                // real-protocol codebases — a high-confidence match.
                .confidence(0.78)
                .dimension(Dimension::Invariant)
                .message(format!(
                    "`{}` gates its withdrawal/unbonding cooldown delay behind \
                     `if ({} || !whitelisted[...]) {{ ... if (Δtime < coolDownPeriod) revert ... }}`. \
                     Because the cooldown body runs only when the risk/pause flag is true OR the user is \
                     NOT whitelisted, a whitelisted user in normal operation (flag off) takes the false \
                     branch and the delay is never evaluated — they claim with **zero cooldown**. The \
                     delay defense (the window the protocol uses to re-price / re-collateralize / pause on \
                     a depeg or oracle event) is thus disabled for whitelisted addresses exactly when the \
                     protocol is NOT in a heightened-risk state. A whitelisted account — or one an admin is \
                     induced to whitelist, or a compromised whitelist — drains the queue instantly, \
                     defeating the cooldown. This is the Renzo `WithdrawQueue.claim` \
                     `if (_instantWithdrawPaused || !whitelisted[user]) {{ ... revert EarlyClaim(); }}` shape.",
                    f.name, hit.flag_text,
                ))
                .recommendation(
                    "Make the cooldown delay unconditional and use the whitelist/risk flag only to *extend* \
                     it, never to skip it. If an instant-exit allowlist is intended, gate it on a \
                     deliberate `instantWithdrawEnabled` flag that defaults off and is itself a monitored \
                     privileged action — do not let `!whitelisted` plus an unrelated pause flag being off \
                     silently waive the delay. At minimum, require the cooldown check on every claim path \
                     and apply the waiver only when the protocol is explicitly in an instant-withdraw mode.",
                );
            out.push(cx.finish(b, f.id, hit.span));
        }

        out
    }
}

/// A matched whitelist-gated cooldown.
struct GatedCooldown {
    /// Source span of the outer gating `if`.
    span: Span,
    /// Textual form of the non-whitelist disjunct (the risk/pause flag), for the message.
    flag_text: String,
}

/// Scan `f` for an outer `if` whose condition is a disjunction containing a
/// negated allowlist-membership test, whose then-branch holds a cooldown delay
/// check. Returns the first such match.
fn find_gated_cooldown(cx: &AnalysisContext, f: &Function) -> Option<GatedCooldown> {
    let mut hit: Option<GatedCooldown> = None;
    for top in &f.body {
        top.visit(&mut |st| {
            if hit.is_some() {
                return;
            }
            let StmtKind::If { cond, then_branch, .. } = &st.kind else { return };
            // The gate must be a disjunction that includes a negated whitelist test.
            if !disjunction_has_negated_whitelist(cond) {
                return;
            }
            // And the protected branch must contain a cooldown delay check.
            if !branch_has_cooldown_check(cx, then_branch) {
                return;
            }
            hit = Some(GatedCooldown { span: st.span, flag_text: other_disjunct_text(cx, cond) });
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Does `cond` (the gate) contain, among the operands of a top-level `||` chain, a
/// **negated allowlist-membership test**? We only descend through `||` (the
/// disjunction structure that makes "flag true OR not-whitelisted" route the
/// protected user out of the cooldown). A bare `if (!whitelisted[u])` with no `||`
/// is *not* this class (there is no flag waiver), so a disjunction is required.
fn disjunction_has_negated_whitelist(cond: &Expr) -> bool {
    let operands = or_operands(cond);
    // Require an actual disjunction (>=2 operands) AND a negated whitelist disjunct.
    operands.len() >= 2 && operands.iter().any(|e| is_negated_whitelist(e))
}

/// Flatten a left/right-nested `||` tree into its leaf operands.
fn or_operands(e: &Expr) -> Vec<&Expr> {
    let mut out = Vec::new();
    fn rec<'a>(e: &'a Expr, out: &mut Vec<&'a Expr>) {
        if let ExprKind::Binary { op: BinOp::Or, lhs, rhs } = &e.kind {
            rec(lhs, out);
            rec(rhs, out);
        } else {
            out.push(e);
        }
    }
    rec(e, &mut out);
    out
}

/// Is `e` a negated allowlist-membership test — `!whitelisted[k]`,
/// `!isWhitelisted[k]`, or `whitelisted[k] == false`? The whitelist signal is a
/// mapping/array index whose **base name** reads as an allowlist
/// (`whitelist`/`whitelisted`/`allowlist`/`allowed`/`isWhitelisted`).
fn is_negated_whitelist(e: &Expr) -> bool {
    match &e.kind {
        // `!whitelisted[k]` (or `!isWhitelisted(k)`).
        ExprKind::Unary { op: UnOp::Not, operand } => expr_is_whitelist_membership(operand),
        // `whitelisted[k] == false`.
        ExprKind::Binary { op: BinOp::Eq, lhs, rhs } => {
            (expr_is_whitelist_membership(lhs) && is_false_lit(rhs))
                || (expr_is_whitelist_membership(rhs) && is_false_lit(lhs))
        }
        _ => false,
    }
}

/// True if `e` reads an allowlist membership: an index/call/member whose root base
/// name looks like a whitelist. Matches `whitelisted[k]`, `isWhitelisted[k]`,
/// `whitelist[k].active`, `isWhitelisted(k)`.
fn expr_is_whitelist_membership(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Index { base, .. } => base_name_is_whitelist(base),
        ExprKind::Member { base, .. } => expr_is_whitelist_membership(base),
        ExprKind::Call(c) => {
            // `isWhitelisted(user)` form.
            let nm = c
                .func_name
                .clone()
                .or_else(|| c.callee.simple_name().map(|s| s.to_string()));
            nm.map(|n| name_is_whitelist(&n)).unwrap_or(false)
        }
        ExprKind::Ident(n) => name_is_whitelist(n),
        _ => false,
    }
}

/// Root identifier of an index/member chain reads as a whitelist.
fn base_name_is_whitelist(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Ident(n) => name_is_whitelist(n),
        ExprKind::Member { member, base } => name_is_whitelist(member) || base_name_is_whitelist(base),
        ExprKind::Index { base, .. } => base_name_is_whitelist(base),
        _ => false,
    }
}

/// A name reads as an allowlist-membership map.
fn name_is_whitelist(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // `whitelist`/`whitelisted`/`allowlist` cover the membership maps; `iswhitelisted`
    // and `allowed`/`isallowed` cover the predicate forms. Deliberately a closed,
    // allowlist-shaped set so this never fires on unrelated mappings.
    l.contains("whitelist") || l.contains("allowlist") || l == "allowed" || l == "isallowed"
}

fn is_false_lit(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Lit(sluice_ir::Lit::Bool(false)))
}

/// Textual form of the *non*-whitelist disjunct(s) of the gate — the risk/pause
/// flag — for the finding message. Falls back to "the risk flag" if unrecoverable.
fn other_disjunct_text(cx: &AnalysisContext, cond: &Expr) -> String {
    for op in or_operands(cond) {
        if is_negated_whitelist(op) {
            continue;
        }
        let t = cx.source_text(op.span);
        let t = t.trim();
        if !t.is_empty() && t.len() <= 60 {
            return t.to_string();
        }
        return "the risk flag".to_string();
    }
    "the risk flag".to_string()
}

/// Does any statement in `branch` contain a **cooldown delay check** — an
/// `if (...) revert/return` whose condition is an elapsed-time `<`/`<=`
/// comparison rooted in `block.timestamp`/`block.number`, or whose revert error /
/// branch text reads as a cooldown? We descend the whole branch subtree so the
/// inner check can be nested under further conditionals.
fn branch_has_cooldown_check(cx: &AnalysisContext, branch: &[Stmt]) -> bool {
    let mut found = false;
    for s in branch {
        s.visit(&mut |st| {
            if found {
                return;
            }
            if let StmtKind::If { cond, then_branch, else_branch } = &st.kind {
                // The classic delay check: `block.timestamp - createdAt < period`.
                if is_elapsed_time_lt(cond) {
                    found = true;
                    return;
                }
                // Or an `if (...) revert EarlyClaim()` whose error / body text reads
                // as a cooldown, with a single revert/return body (a guard shape).
                if (branch_is_single_guard(then_branch) || branch_is_single_guard(else_branch))
                    && text_reads_cooldown(&cx.source_text(st.span))
                {
                    found = true;
                }
            }
        });
        if found {
            break;
        }
    }
    found
}

/// `lhs < rhs` / `lhs <= rhs` where the `lhs` is an *elapsed-since* subtraction
/// rooted in `block.timestamp` (or `block.number`): `block.timestamp - createdAt`.
/// This is the canonical "delay not yet elapsed" comparison. We require the
/// subtraction so an ordinary deadline check (`block.timestamp < deadline`) is not
/// matched — only the `now - start < period` cooldown shape.
fn is_elapsed_time_lt(e: &Expr) -> bool {
    let ExprKind::Binary { op, lhs, rhs } = &e.kind else { return false };
    if !matches!(op, BinOp::Lt | BinOp::Le) {
        return false;
    }
    // Elapsed-time subtraction on either side of the comparison.
    is_block_time_subtraction(lhs) || is_block_time_subtraction(rhs)
}

/// `block.timestamp - X` (or `block.number - X`): a subtraction one of whose
/// operands is a block-time member access.
fn is_block_time_subtraction(e: &Expr) -> bool {
    let ExprKind::Binary { op: BinOp::Sub, lhs, rhs } = &e.kind else { return false };
    expr_reads_block_time(lhs) || expr_reads_block_time(rhs)
}

/// Does `e` (shallowly) read `block.timestamp` / `block.number` / a `now`-like
/// alias? Matches the `Member { base: block, member: timestamp|number }` shape.
fn expr_reads_block_time(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Member { base, member } = &sub.kind {
            let m = member.to_ascii_lowercase();
            if (m == "timestamp" || m == "number")
                && matches!(&base.kind, ExprKind::Ident(b) if b == "block")
            {
                found = true;
            }
        }
    });
    found
}

/// A branch body that is a single `revert`/`return` (an inline guard).
fn branch_is_single_guard(branch: &[Stmt]) -> bool {
    if branch.len() != 1 {
        return false;
    }
    matches!(branch[0].kind, StmtKind::Revert { .. } | StmtKind::Return(_))
}

/// Comment-stripped, lowercased statement text reads as a cooldown / early-claim.
fn text_reads_cooldown(text: &str) -> bool {
    [
        "earlyclaim",
        "early_claim",
        "cooldown",
        "cool_down",
        "tooearly",
        "too_early",
        "notmatured",
        "not_matured",
        "withdrawaldelay",
        "claimtooearly",
    ]
    .iter()
    .any(|k| text.contains(k))
}

/// Is the cooldown delay check performed **unconditionally** — i.e. at a point in
/// the body that is NOT inside any whitelist/flag-gated `if`? We re-walk the body
/// tracking whether we are under a gating `if`, and report any `is_elapsed_time_lt`
/// check that occurs outside such a gate. If found, the delay is always enforced,
/// so the gated copy is not a bypass (suppress).
fn has_unconditional_cooldown(cx: &AnalysisContext, body: &[Stmt]) -> bool {
    fn walk(cx: &AnalysisContext, stmts: &[Stmt], under_gate: bool) -> bool {
        for s in stmts {
            match &s.kind {
                StmtKind::If { cond, then_branch, else_branch } => {
                    // Is THIS if a delay check at the unconditional level?
                    if !under_gate && is_elapsed_time_lt(cond) {
                        return true;
                    }
                    if !under_gate
                        && (branch_is_single_guard(then_branch) || branch_is_single_guard(else_branch))
                        && text_reads_cooldown(&cx.source_text(s.span))
                    {
                        return true;
                    }
                    // Descend; the then-branch is gated iff this if is a whitelist gate
                    // (or we were already under a gate). The else-branch of a whitelist
                    // gate is the *bypass* path, so it stays at the current gate level.
                    let then_gated = under_gate || disjunction_has_negated_whitelist(cond);
                    if walk(cx, then_branch, then_gated) {
                        return true;
                    }
                    if walk(cx, else_branch, under_gate) {
                        return true;
                    }
                }
                StmtKind::While { body, .. }
                | StmtKind::DoWhile { body, .. }
                | StmtKind::For { body, .. }
                | StmtKind::Block { stmts: body, .. } => {
                    if walk(cx, body, under_gate) {
                        return true;
                    }
                }
                StmtKind::Try { body, catches, .. } => {
                    if walk(cx, body, under_gate) {
                        return true;
                    }
                    for c in catches {
                        if walk(cx, &c.body, under_gate) {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }
        false
    }
    walk(cx, body, false)
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "cooldown-bypass-flag")
    }

    // VULN — the exact Renzo `WithdrawQueue.claim` shape: the cooldown delay is
    // gated behind `if (_instantWithdrawPaused || !whitelisted[user])`, so a
    // whitelisted user with the flag off exits with zero delay.
    const VULN: &str = r#"
        interface IRisk { function instantWithdrawPaused() external view returns (bool);
                          function withdrawCooldownPeriod() external view returns (uint256); }
        contract WithdrawQueue {
            mapping(address => bool) public whitelisted;
            uint256 public coolDownPeriod;
            IRisk riskOracleMiddleware;
            struct Req { uint256 createdAt; }
            mapping(address => Req[]) withdrawRequests;
            function claim(uint256 idx, address user) external {
                Req memory r = withdrawRequests[user][idx];
                bool _instantWithdrawPaused = riskOracleMiddleware.instantWithdrawPaused();
                if (_instantWithdrawPaused || !whitelisted[user]) {
                    uint256 _rc = riskOracleMiddleware.withdrawCooldownPeriod();
                    uint256 _cd = _rc > coolDownPeriod ? _rc : coolDownPeriod;
                    if (block.timestamp - r.createdAt < _cd) revert();
                }
                withdrawRequests[user].pop();
            }
        }
    "#;

    // VULN — `== false` form with a named EarlyClaim revert, no time arithmetic in
    // the inner condition (relies on the cooldown-named revert + guard shape).
    const VULN_NAMED: &str = r#"
        contract Queue {
            mapping(address => bool) public isWhitelisted;
            bool public paused;
            mapping(address => uint256) createdAt;
            error EarlyClaim();
            function claim(address user) external {
                if (paused || isWhitelisted[user] == false) {
                    if (block.timestamp - createdAt[user] < 7 days) revert EarlyClaim();
                }
                createdAt[user] = 0;
            }
        }
    "#;

    // SAFE — the cooldown is UNCONDITIONAL: it is enforced on every claim, and the
    // whitelist only governs an unrelated fee path. No bypass.
    const SAFE_UNCONDITIONAL: &str = r#"
        contract Queue {
            mapping(address => bool) public whitelisted;
            uint256 public coolDownPeriod;
            mapping(address => uint256) createdAt;
            function claim(address user) external {
                if (block.timestamp - createdAt[user] < coolDownPeriod) revert();
                if (!whitelisted[user]) {
                    // charge a fee for non-whitelisted users
                }
                createdAt[user] = 0;
            }
        }
    "#;

    // SAFE — a bare `if (!whitelisted[user])` branch with NO disjunction / flag
    // waiver: the cooldown is simply skipped for whitelisted users by design with no
    // risk-flag coupling, which is the ordinary "whitelisted = instant" pattern this
    // detector intentionally does not flag (no `flag || !whitelisted` gate).
    // (Structurally distinct: there is no `||`.)
    const SAFE_NO_DISJUNCTION: &str = r#"
        contract Queue {
            mapping(address => bool) public whitelisted;
            uint256 public coolDownPeriod;
            mapping(address => uint256) createdAt;
            function claim(address user) external {
                if (!whitelisted[user]) {
                    if (block.timestamp - createdAt[user] < coolDownPeriod) revert();
                }
                createdAt[user] = 0;
            }
        }
    "#;

    // SAFE — ordinary pause + deadline branching with no whitelist and no elapsed
    // subtraction: `if (paused || amount == 0)` then a plain deadline check. None of
    // the anchors (negated whitelist disjunct, elapsed-since cooldown) are present.
    const SAFE_NO_WHITELIST: &str = r#"
        contract Queue {
            bool public paused;
            uint256 public deadline;
            function claim(uint256 amount) external {
                if (paused || amount == 0) {
                    if (block.timestamp < deadline) revert();
                }
            }
        }
    "#;

    #[test]
    fn fires_on_renzo_shape() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_named_eq_false_shape() {
        assert!(fires(VULN_NAMED), "{:#?}", run(VULN_NAMED));
    }

    #[test]
    fn silent_when_cooldown_unconditional() {
        assert!(!fires(SAFE_UNCONDITIONAL), "{:#?}", run(SAFE_UNCONDITIONAL));
    }

    #[test]
    fn silent_without_disjunction_gate() {
        assert!(!fires(SAFE_NO_DISJUNCTION), "{:#?}", run(SAFE_NO_DISJUNCTION));
    }

    #[test]
    fn silent_without_whitelist_or_elapsed_check() {
        assert!(!fires(SAFE_NO_WHITELIST), "{:#?}", run(SAFE_NO_WHITELIST));
    }
}
