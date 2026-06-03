//! Depth-branched clock-extension whose external-param term can mismatch the
//! resolve gate — the OP `FaultDisputeGame` move/clock-extension class.
//!
//! ## The shape
//!
//! A chess-clock / response-deadline game (a fault-proof dispute tree) computes,
//! on each `move`, how much to extend the would-be grandchild's clock. The amount
//! is chosen by a **branch on the tree depth/level** against named depth constants,
//! and one branch's extension is an **additive term that folds in an
//! externally-mutable value** — an oracle / `challengePeriod()` read:
//!
//! ```solidity
//! // FaultDisputeGame.move  (~L503-522)
//! uint64 actualExtension;
//! if (nextPositionDepth == MAX_GAME_DEPTH - 1) {
//!     // about to step: account for the LPP challenge period on top of the clock extension
//!     actualExtension = CLOCK_EXTENSION.raw() + uint64(vm().oracle().challengePeriod()); // <- external term
//! } else if (nextPositionDepth == SPLIT_DEPTH - 1) {
//!     actualExtension = CLOCK_EXTENSION.raw() * 2;
//! } else {
//!     actualExtension = CLOCK_EXTENSION.raw();
//! }
//! if (nextDuration.raw() > MAX_CLOCK_DURATION.raw() - actualExtension) {
//!     nextDuration = Duration.wrap(MAX_CLOCK_DURATION.raw() - actualExtension);   // clock write
//! }
//! ```
//!
//! The sibling resolve/finalize step gates the state transition on a plain
//! `< MAX_*` clock comparison that has **no knowledge of the per-depth extension**:
//!
//! ```solidity
//! // FaultDisputeGame.resolveClaim  (~L745)
//! if (challengeClockDuration.raw() < MAX_CLOCK_DURATION.raw()) revert ClockNotExpired();
//! ```
//!
//! Because the extension term in the `MAX_GAME_DEPTH - 1` branch depends on a
//! value the oracle can move (`challengePeriod()`), the duration written by `move`
//! and the fixed `< MAX_CLOCK_DURATION` gate in `resolveClaim` can disagree about
//! when a clock is "expired": the extension that `move` subtracts off the cap is
//! not the same quantity the resolve gate measures against, so a depth/oracle
//! combination can make the move-time clamp and the resolve-time gate inconsistent
//! (a claim's clock is treated as still-running by one path and expired by the
//! other). This is an invariant mismatch between a *depth-branched, externally
//! parameterized* clock extension and a *constant* resolve gate.
//!
//! ## Why this is tight (≈0 FP)
//!
//! Two independent structural anchors must BOTH hold, and each is rare:
//!   * a **depth/level branch** — an `if`/`else-if` chain whose conditions compare a
//!     tree-`depth()`/`level` operand against **named depth constants**
//!     (`*_DEPTH` / `*_LEVEL`, optionally `± k`). Across the entire FP corpus
//!     (Olympus / Pendle / EtherFi / Ethena / Symbiotic / EigenLayer) there is *not
//!     one* `== *_DEPTH` branch or `.depth()` call — this pattern is specific to the
//!     bisection-game tree;
//!   * one selected branch assigns a **clock/extension/deadline** field an
//!     **additive term containing an externally-mutable getter** (`challengePeriod()`
//!     / an `oracle()`-rooted read / a period/window/delay getter on an
//!     external/unknown call) — not a pure constant arithmetic.
//!
//! Plain `deadline = block.timestamp + period` is NOT matched: there is no
//! depth/level branch, and `block.timestamp`/`period` is not an external getter
//! call. A purely constant per-depth extension (`CLOCK_EXTENSION * 2`) is not
//! matched either — the external-call term is required.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Call, Expr, ExprKind, Function, Span, Stmt, StmtKind};

use super::prelude::*;

pub struct ClockExtensionDepthBranchDetector;

impl Detector for ClockExtensionDepthBranchDetector {
    fn id(&self) -> &'static str {
        "clock-extension-depth-branch"
    }
    fn category(&self) -> Category {
        Category::ClockExtensionDepthBranch
    }
    fn description(&self) -> &'static str {
        "Depth/level-branched clock/deadline extension whose additive term folds in an externally-mutable getter (oracle/challengePeriod), able to mismatch a sibling constant `< MAX_*` resolve gate (OP FaultDisputeGame move/clock-extension class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.functions() {
            if !f.has_body {
                continue;
            }

            // Locate, anywhere in the body, a depth/level-branched if-chain in which
            // one arm assigns a clock/extension/deadline target an additive term that
            // contains an externally-mutable getter call.
            let Some(hit) = find_depth_branched_clock_extension(f) else { continue };

            // Corroborating context (not required): a sibling function in the same
            // contract whose state transition is gated by a constant `X < MAX_*`
            // comparison — the resolve gate that does not see the extension term.
            let resolve = cx
                .contract_of(f.id)
                .map(|c| sibling_has_max_resolve_gate(cx, c.id, f.id))
                .unwrap_or(false);

            // Confidence: the two-anchor structural match is already very specific;
            // the corroborating constant resolve gate nudges it up.
            let confidence = if resolve { 0.66 } else { 0.58 };

            let b = report!(self, Category::ClockExtensionDepthBranch,
                title = "Depth-branched clock extension with an external-param term can mismatch the resolve gate",
                severity = Severity::Medium,
                confidence = confidence,
                dimensions = [Dimension::Invariant],
                message = format!(
                    "`{fname}` selects a clock/deadline extension by branching on the tree \
                     **depth/level** (`{depthcond}`) against named depth constants, and the selected \
                     branch writes the clock field `{target}` an **additive** term that folds in an \
                     externally-mutable getter `{ext}()` (`{addexpr}`). The extension magnitude in this \
                     branch therefore moves with a value outside the game's control (an \
                     oracle / challenge-period read). {resolve_note}A move-time clock clamp computed \
                     from `MAX_* - extension` and a constant `< MAX_*` resolve/finalize gate can then \
                     disagree about when a clock is \"expired\": the per-depth, externally parameterized \
                     extension subtracted off the cap is not the quantity the resolve gate measures, so \
                     a depth/oracle combination makes the move-time clamp and the resolve-time gate \
                     inconsistent — an invariant mismatch in the OP `FaultDisputeGame` \
                     move/clock-extension class.",
                    fname = f.name,
                    depthcond = clip(&hit.cond_text),
                    target = hit.target_name,
                    ext = hit.ext_getter,
                    addexpr = clip(&hit.add_text),
                    resolve_note = if resolve {
                        "A sibling function in the same contract gates its state transition on a constant \
                         `< MAX_*` clock comparison that has no knowledge of this per-depth extension. "
                    } else {
                        ""
                    },
                ),
                recommendation =
                    "Make the move-time clock-extension arithmetic and the resolve/finalize gate measure \
                     the *same* quantity. Either fold the depth-branched, externally parameterized \
                     extension (the `+ challengePeriod()` term) into the resolve gate's threshold so \
                     `resolveClaim` compares against `MAX_* ` adjusted by the same extension, or bound / \
                     freeze the external getter at game creation (snapshot `challengePeriod()` into an \
                     immutable) so the move-time clamp and the constant `< MAX_*` resolve gate cannot \
                     drift. Add an invariant test asserting a clock the move path treats as still-running \
                     is never accepted as expired by the resolve path for every depth branch.",
            );
            out.push(finish_at(cx, b, f.id, hit.span));
        }

        out
    }
}

/// A matched depth-branched clock-extension assignment.
struct Hit {
    /// Span of the assignment (where the extension is written).
    span: Span,
    /// Source text of the branch condition that selects this arm.
    cond_text: String,
    /// Leaf name of the assignment target (the clock/extension/deadline field).
    target_name: String,
    /// Resolved name of the external-param getter folded into the term.
    ext_getter: String,
    /// Source text of the additive term containing the external getter.
    add_text: String,
}

/// Find an `if`/`else-if` chain that branches on tree depth/level against named
/// depth constants, in which one arm assigns a clock/extension/deadline target an
/// additive term that contains an externally-mutable getter call.
///
/// The chain is the Solidity `if/else if/else` lowered to a *nested* `If` whose
/// `else_branch` is the next `If`. We require at least two depth-keyed conditions in
/// the chain (a genuine depth branch, not a lone `if`).
fn find_depth_branched_clock_extension(f: &Function) -> Option<Hit> {
    let mut found: Option<Hit> = None;
    for top in &f.body {
        top.visit(&mut |st| {
            if found.is_some() {
                return;
            }
            let StmtKind::If { .. } = &st.kind else { return };
            // Collect the whole if/else-if chain rooted here.
            let arms = collect_if_chain(st);
            // Require a genuine depth branch: at least two arms whose condition is a
            // depth/level-vs-named-constant comparison.
            let depth_arms = arms.iter().filter(|a| a.is_depth_cond).count();
            if depth_arms < 2 {
                return;
            }
            // In some depth-keyed arm, find a clock-field assignment whose RHS holds
            // an additive external-getter term.
            for arm in &arms {
                if !arm.is_depth_cond {
                    continue;
                }
                if let Some(mut hit) = arm_clock_extension_hit(arm.body) {
                    hit.cond_text = arm.cond_text.clone();
                    found = Some(hit);
                    return;
                }
            }
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// One arm of an if/else-if chain: its (optional) condition text + whether the
/// condition is a depth/level branch + the arm body statements.
struct Arm<'a> {
    is_depth_cond: bool,
    cond_text: String,
    body: &'a [Stmt],
}

/// Flatten the nested `If` chain rooted at `st` (an `If`) into its arms. The final
/// bare `else { ... }` (no condition) is included as a non-depth arm so its body is
/// still scanned, but it never counts toward the depth-arm requirement.
fn collect_if_chain(st: &Stmt) -> Vec<Arm<'_>> {
    let mut arms = Vec::new();
    let mut cur = st;
    loop {
        let StmtKind::If { cond, then_branch, else_branch } = &cur.kind else {
            // A bare trailing else block: scan its statements as a condition-less arm.
            arms.push(Arm { is_depth_cond: false, cond_text: String::new(), body: std::slice::from_ref(cur) });
            break;
        };
        arms.push(Arm {
            is_depth_cond: is_depth_branch_cond(cond),
            cond_text: expr_src(cond),
            body: then_branch,
        });
        // Continue down an `else if`: else_branch is exactly one `If`.
        if else_branch.len() == 1 && matches!(else_branch[0].kind, StmtKind::If { .. }) {
            cur = &else_branch[0];
            continue;
        }
        // Trailing bare else (zero or more statements, not an if-chain): scan it.
        if !else_branch.is_empty() {
            arms.push(Arm { is_depth_cond: false, cond_text: String::new(), body: else_branch });
        }
        break;
    }
    arms
}

/// Within an arm body, find a clock/extension/deadline assignment whose value
/// contains an **additive** term that includes an externally-mutable getter call.
fn arm_clock_extension_hit(body: &[Stmt]) -> Option<Hit> {
    let mut hit: Option<Hit> = None;
    for s in body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Assign { target, value, .. } = &e.kind else { return };
            let Some(target_name) = leaf_name(target) else { return };
            if !is_clock_field_name(&target_name) {
                return;
            }
            // The value must contain `A + B` where one side has an external getter.
            let Some((ext_getter, add_text)) = additive_external_term(value) else { return };
            hit = Some(Hit {
                span: e.span,
                cond_text: String::new(),
                target_name,
                ext_getter,
                add_text,
            });
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Is `cond` a depth/level branch — a comparison one of whose sides is a tree
/// depth/level operand and the other a **named depth/level constant** (optionally
/// `CONST ± literal`)? Both `==`/`!=` (the target's form) and ordering comparisons
/// qualify; the named-constant gate is what keeps this specific.
fn is_depth_branch_cond(cond: &Expr) -> bool {
    let ExprKind::Binary { op, lhs, rhs } = &cond.kind else { return false };
    if !op.is_comparison() {
        return false;
    }
    let (l, r) = (lhs.as_ref(), rhs.as_ref());
    (is_depth_operand(l) && is_named_depth_const(r)) || (is_depth_operand(r) && is_named_depth_const(l))
}

/// A tree depth/level operand: a `.depth()` / `.level()` call, or a variable whose
/// name reads as a depth/level (`nextPositionDepth`, `currentDepth`, `treeLevel`).
fn is_depth_operand(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Call(c) => {
            let n = call_method_name(c).unwrap_or_default().to_ascii_lowercase();
            n == "depth" || n == "level"
        }
        _ => leaf_name(e).map(|n| name_reads_depth(&n)).unwrap_or(false),
    }
}

/// A **named depth/level constant** — an identifier (optionally `CONST ± literal`)
/// whose name reads as a depth/level constant: it contains `depth`/`level` AND is
/// constant-shaped (ALL-CAPS / contains `_`, e.g. `MAX_GAME_DEPTH`, `SPLIT_DEPTH`).
fn is_named_depth_const(e: &Expr) -> bool {
    match &e.kind {
        // `CONST - 1` / `CONST + 1` — the `MAX_GAME_DEPTH - 1` form.
        ExprKind::Binary { op: BinOp::Add | BinOp::Sub, lhs, rhs } => {
            (is_named_depth_const(lhs) && is_int_literal(rhs)) || (is_named_depth_const(rhs) && is_int_literal(lhs))
        }
        ExprKind::Ident(n) => name_is_depth_const(n),
        _ => false,
    }
}

/// `name` reads as a depth/level quantity (contains `depth` or `level`).
fn name_reads_depth(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("depth") || l.contains("level")
}

/// `name` reads as a depth/level **constant**: contains `depth`/`level` AND is
/// spelled like a constant (no lowercase letters, or contains an underscore) — so a
/// local `nextPositionDepth` does not count as the constant side, but `MAX_GAME_DEPTH`
/// / `SPLIT_DEPTH` / `MAXDEPTH` do.
fn name_is_depth_const(name: &str) -> bool {
    if !name_reads_depth(name) {
        return false;
    }
    let has_underscore = name.contains('_');
    let has_lower = name.chars().any(|c| c.is_ascii_lowercase());
    has_underscore || !has_lower
}

/// Is `e` an integer literal? (`MAX_GAME_DEPTH - 1`).
fn is_int_literal(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Lit(sluice_ir::Lit::Number(_)) | ExprKind::Lit(sluice_ir::Lit::HexNumber(_)))
}

/// Does `e` contain an **additive** subexpression `A + B` one of whose operands
/// contains an externally-mutable getter call? Returns `(getter_name, add_src)`.
///
/// The `Add` requirement is the "additive extension term" anchor: a `* 2` constant
/// scaling, or a bare external read with no addition, does not qualify.
fn additive_external_term(e: &Expr) -> Option<(String, String)> {
    let mut out: Option<(String, String)> = None;
    e.visit(&mut |sub| {
        if out.is_some() {
            return;
        }
        let ExprKind::Binary { op: BinOp::Add, lhs, rhs } = &sub.kind else { return };
        if let Some(name) = external_getter_call(lhs).or_else(|| external_getter_call(rhs)) {
            out = Some((name, expr_src(sub)));
        }
    });
    out
}

/// Find, anywhere in `e`, a call to an **externally-mutable parameter getter** —
/// a call whose resolved method name (or a method name in its receiver chain) reads
/// as an oracle / challenge-period / tunable-window getter, on an external/unknown
/// (non-internal) call. Returns the matched getter name.
///
/// We key on the *method name* rather than `CallKind::External` alone, because a
/// `CONST.raw()` wrapper read is also classified external; the name gate
/// (`challengePeriod`, `oracle`, `period`/`window`/`delay`/`duration` getter) is what
/// pins this to a genuinely tunable external parameter.
fn external_getter_call(e: &Expr) -> Option<String> {
    let mut found: Option<String> = None;
    e.visit(&mut |sub| {
        if found.is_some() {
            return;
        }
        let ExprKind::Call(c) = &sub.kind else { return };
        // Skip pure internal calls — an internal helper is in-protocol, not an
        // external tunable. (`vm().oracle().challengePeriod()`'s leaf call is
        // External; `vm()` itself is Internal and is correctly ignored.)
        if matches!(c.kind, sluice_ir::CallKind::Internal | sluice_ir::CallKind::TypeCast) {
            return;
        }
        let Some(name) = call_method_name(c) else { return };
        if is_external_param_getter(&name) {
            found = Some(name);
            return;
        }
        // The getter may be the leaf of a receiver chain whose receiver is an
        // `oracle()` read (`vm().oracle().challengePeriod()`): accept the leaf name
        // when an `oracle`-named call appears anywhere in the receiver chain.
        if let Some(recv) = &c.receiver {
            if receiver_chain_has_oracle(recv) {
                found = Some(name);
            }
        }
    });
    found
}

/// The method/function name of a call: `func_name`, else the callee's simple name.
fn call_method_name(c: &Call) -> Option<String> {
    c.func_name.clone().or_else(|| c.callee.simple_name().map(|s| s.to_string()))
}

/// `name` reads as an externally-mutable parameter getter — a challenge-period /
/// oracle / tunable window-or-delay-or-duration accessor.
fn is_external_param_getter(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("challengeperiod")
        || l == "oracle"
        || l.contains("oracle")
        || l.contains("disputeperiod")
        || l.contains("finalizationperiod")
        || l.contains("provingtime")
        || l.contains("challengedelay")
        || l == "period"
        || l == "delay"
        || l == "window"
        || l == "duration"
        || (l.ends_with("period") && l != "graceperiod")
}

/// Does a call appear in the receiver chain `e` whose method name reads like an
/// oracle accessor (`oracle`, `vm().oracle()`)?
fn receiver_chain_has_oracle(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Call(c) = &sub.kind {
            if let Some(n) = call_method_name(c) {
                if n.to_ascii_lowercase().contains("oracle") {
                    found = true;
                }
            }
        }
    });
    found
}

/// `name` reads as a chess-clock / response-deadline field: an extension / clock /
/// duration / deadline / timer / period field. This is the "clock storage field"
/// anchor on the assignment target.
fn is_clock_field_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("extension")
        || l.contains("clock")
        || l.contains("duration")
        || l.contains("deadline")
        || l.contains("timer")
        || l.contains("expiry")
        || l.contains("expiration")
}

/// Leaf identifier of a member/index/ident chain (`a.b[c]` -> `a`'s leaf member, or
/// the bare ident). For an `Assign` target this gives the written field's name.
fn leaf_name(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { member, .. } => Some(member.clone()),
        ExprKind::Index { base, .. } => leaf_name(base),
        _ => None,
    }
}

/// Does the same contract expose a sibling function (other than `self_fid`) whose
/// state transition is gated by a constant `X < MAX_*` (or `MAX_* > X`) comparison —
/// the resolve/finalize gate that does not account for the per-depth extension?
fn sibling_has_max_resolve_gate(
    cx: &AnalysisContext,
    contract: sluice_ir::ContractId,
    self_fid: sluice_ir::FunctionId,
) -> bool {
    for g in cx.scir.functions_of(contract) {
        if g.id == self_fid || !g.has_body {
            continue;
        }
        if function_has_max_lt_gate(g) {
            return true;
        }
    }
    false
}

/// Does `g` contain a comparison of some value against a `MAX_*`-named constant in
/// the strict-less direction (`X < MAX_*` or `MAX_* > X`) — the resolve gate shape?
fn function_has_max_lt_gate(g: &Function) -> bool {
    let mut found = false;
    for s in &g.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            let ExprKind::Binary { op, lhs, rhs } = &e.kind else { return };
            match op {
                BinOp::Lt if mentions_max_const(rhs) => found = true,
                BinOp::Gt if mentions_max_const(lhs) => found = true,
                _ => {}
            }
        });
        if found {
            break;
        }
    }
    found
}

/// Does `e` reference a `MAX_*`-named constant (e.g. `MAX_CLOCK_DURATION`)? We look
/// at the leaf name of a member/ident chain (`MAX_CLOCK_DURATION.raw()` -> via the
/// call's receiver leaf) — accept any name starting with `max` and reading like a
/// duration/clock/time cap.
fn mentions_max_const(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        match &sub.kind {
            ExprKind::Ident(n) | ExprKind::Member { member: n, .. } => {
                let l = n.to_ascii_lowercase();
                if l.starts_with("max")
                    && (l.contains("clock") || l.contains("duration") || l.contains("time") || l.contains("deadline"))
                {
                    found = true;
                }
            }
            _ => {}
        }
    });
    found
}

/// Best-effort source text of an expression node (whitespace-normalized via `clip`
/// at the call site). Uses the IR `simple_name`/debug-free reconstruction is not
/// available, so we fall back to a compact textual rendering by walking idents.
fn expr_src(e: &Expr) -> String {
    // We cannot reach `cx.source_text` here (no span resolver), so render a compact
    // approximation from the expression tree. This is only used for the message.
    render(e)
}

/// Compact textual rendering of an expression (for messages only).
fn render(e: &Expr) -> String {
    match &e.kind {
        ExprKind::Ident(n) => n.clone(),
        ExprKind::Member { base, member } => format!("{}.{}", render(base), member),
        ExprKind::Index { base, index } => match index {
            Some(i) => format!("{}[{}]", render(base), render(i)),
            None => format!("{}[]", render(base)),
        },
        ExprKind::Call(c) => {
            let args: Vec<String> = c.args.iter().map(render).collect();
            format!("{}({})", render(&c.callee), args.join(", "))
        }
        ExprKind::Lit(l) => match l {
            sluice_ir::Lit::Number(s) | sluice_ir::Lit::HexNumber(s) => s.clone(),
            sluice_ir::Lit::Bool(b) => b.to_string(),
            sluice_ir::Lit::String(s) => format!("\"{s}\""),
            sluice_ir::Lit::Address(s) | sluice_ir::Lit::HexBytes(s) | sluice_ir::Lit::Other(s) => s.clone(),
        },
        ExprKind::Binary { op, lhs, rhs } => format!("{} {} {}", render(lhs), bin_sym(*op), render(rhs)),
        ExprKind::Unary { operand, .. } => render(operand),
        ExprKind::TypeName(n) => n.clone(),
        _ => "…".to_string(),
    }
}

fn bin_sym(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::Div => "/",
        BinOp::Eq => "==",
        BinOp::Ne => "!=",
        BinOp::Lt => "<",
        BinOp::Gt => ">",
        BinOp::Le => "<=",
        BinOp::Ge => ">=",
        _ => "?",
    }
}

/// Trim a snippet for inclusion in a message (single line, length-bounded).
fn clip(s: &str) -> String {
    let one = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.len() > 100 {
        format!("{}…", &one[..100])
    } else {
        one
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::AnalysisContext;
    use crate::detector::Detector;
    use crate::Config;

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        let parsed = sluice_parse::parse_sources(vec![("t.sol".into(), src.into())]);
        let scir = parsed.scir;
        let dataflow = sluice_dataflow::DataflowFacts::analyze(&scir);
        let invariants = sluice_invariant::InvariantFacts::mine(&scir);
        let frontier = sluice_frontier::FrontierFacts::analyze(&scir);
        let cfg = Config::default();
        let cx = AnalysisContext::new(&scir, &dataflow, &invariants, &frontier, &cfg);
        ClockExtensionDepthBranchDetector.run(&cx)
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "clock-extension-depth-branch")
    }

    // VULN — the FaultDisputeGame `move` clock-extension + a sibling `resolveClaim`
    // constant `< MAX_CLOCK_DURATION` gate.
    const VULN: &str = r#"
        contract FaultDisputeGame {
            uint256 internal immutable MAX_GAME_DEPTH;
            uint256 internal immutable SPLIT_DEPTH;
            function vm() internal view returns (FaultDisputeGame) { return this; }
            function oracle() internal view returns (FaultDisputeGame) { return this; }
            function challengePeriod() external view returns (uint256) { return 1; }
            function move(uint256 nextPositionDepth, uint64 maxClock) external {
                uint64 actualExtension;
                if (nextPositionDepth == MAX_GAME_DEPTH - 1) {
                    actualExtension = clockExtensionRaw() + uint64(vm().oracle().challengePeriod());
                } else if (nextPositionDepth == SPLIT_DEPTH - 1) {
                    actualExtension = clockExtensionRaw() * 2;
                } else {
                    actualExtension = clockExtensionRaw();
                }
                uint64 nextDuration = maxClock;
                if (nextDuration > maxClock - actualExtension) {
                    nextDuration = maxClock - actualExtension;
                }
            }
            function clockExtensionRaw() internal view returns (uint64) { return 1; }
            function resolveClaim(uint256 idx, uint64 challengeClockDuration) external {
                if (challengeClockDuration < MAX_CLOCK_DURATION()) revert();
            }
            function MAX_CLOCK_DURATION() internal pure returns (uint64) { return 100; }
        }
    "#;

    // VULN — closer to the real source: external getter via `vm().oracle().challengePeriod()`
    // folded into the clock-extension field with the exact `MAX_GAME_DEPTH - 1` /
    // `SPLIT_DEPTH - 1` chain and a `MAX_CLOCK_DURATION` state-var resolve gate.
    const VULN_REAL: &str = r#"
        interface IBigStepper { function oracle() external view returns (IPreimage); }
        interface IPreimage { function challengePeriod() external view returns (uint256); }
        contract FaultDisputeGame {
            uint64 internal immutable MAX_GAME_DEPTH = 73;
            uint64 internal immutable SPLIT_DEPTH = 30;
            uint64 internal immutable CLOCK_EXTENSION = 10;
            uint64 internal immutable MAX_CLOCK_DURATION = 100;
            function vm() internal view returns (IBigStepper) { return IBigStepper(address(0)); }
            function move(uint256 nextPositionDepth, uint64 nextDuration) external {
                uint64 actualExtension;
                if (nextPositionDepth == MAX_GAME_DEPTH - 1) {
                    actualExtension = CLOCK_EXTENSION + uint64(vm().oracle().challengePeriod());
                } else if (nextPositionDepth == SPLIT_DEPTH - 1) {
                    actualExtension = CLOCK_EXTENSION * 2;
                } else {
                    actualExtension = CLOCK_EXTENSION;
                }
                if (nextDuration > MAX_CLOCK_DURATION - actualExtension) {
                    nextDuration = MAX_CLOCK_DURATION - actualExtension;
                }
            }
            function resolveClaim(uint64 challengeClockDuration) external {
                if (challengeClockDuration < MAX_CLOCK_DURATION) revert();
            }
        }
    "#;

    // SAFE — plain `deadline = block.timestamp + period`: no depth/level branch, and
    // the additive term is `block.timestamp + period`, not an external getter call.
    const SAFE_PLAIN_DEADLINE: &str = r#"
        contract Escrow {
            uint256 public period = 7 days;
            mapping(uint256 => uint256) public deadline;
            function open(uint256 id) external {
                deadline[id] = block.timestamp + period;
            }
        }
    "#;

    // SAFE — a depth branch exists, but the per-depth extension is purely constant
    // arithmetic (`* 2`, `+ 5`): no external getter folded in. (The external-call
    // anchor is required.)
    const SAFE_CONST_EXTENSION: &str = r#"
        contract Game {
            uint64 internal immutable MAX_GAME_DEPTH = 73;
            uint64 internal immutable SPLIT_DEPTH = 30;
            uint64 internal immutable CLOCK_EXTENSION = 10;
            function move(uint256 nextPositionDepth, uint64 nextDuration) external {
                uint64 clockExtension;
                if (nextPositionDepth == MAX_GAME_DEPTH - 1) {
                    clockExtension = CLOCK_EXTENSION + 5;
                } else if (nextPositionDepth == SPLIT_DEPTH - 1) {
                    clockExtension = CLOCK_EXTENSION * 2;
                } else {
                    clockExtension = CLOCK_EXTENSION;
                }
            }
        }
    "#;

    // SAFE — an external getter is folded into a clock extension, but there is NO
    // depth/level branch: the amount is chosen by an unrelated boolean. (The
    // depth-branch anchor is required; this is an ordinary parameterized deadline.)
    const SAFE_NO_DEPTH_BRANCH: &str = r#"
        interface IOracle { function challengePeriod() external view returns (uint256); }
        contract Game {
            IOracle oracle;
            function extend(bool isStep, uint64 clockDuration) external {
                uint64 clockExtension;
                if (isStep) {
                    clockExtension = 10 + uint64(oracle.challengePeriod());
                } else {
                    clockExtension = 10;
                }
            }
        }
    "#;

    // SAFE — depth branch + external getter, but the WRITE target is not a clock /
    // deadline field (it is a fee). The clock-field anchor on the target is required.
    const SAFE_NOT_CLOCK_TARGET: &str = r#"
        interface IOracle { function challengePeriod() external view returns (uint256); }
        contract Game {
            uint64 internal immutable MAX_GAME_DEPTH = 73;
            uint64 internal immutable SPLIT_DEPTH = 30;
            IOracle oracle;
            function move(uint256 nextPositionDepth) external {
                uint64 feeAmount;
                if (nextPositionDepth == MAX_GAME_DEPTH - 1) {
                    feeAmount = 10 + uint64(oracle.challengePeriod());
                } else if (nextPositionDepth == SPLIT_DEPTH - 1) {
                    feeAmount = 20;
                } else {
                    feeAmount = 10;
                }
            }
        }
    "#;

    #[test]
    fn fires_on_fault_dispute_game_move() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_real_shape() {
        assert!(fires(VULN_REAL), "{:#?}", run(VULN_REAL));
    }

    #[test]
    fn silent_on_plain_deadline() {
        assert!(!fires(SAFE_PLAIN_DEADLINE), "{:#?}", run(SAFE_PLAIN_DEADLINE));
    }

    #[test]
    fn silent_on_constant_extension() {
        assert!(!fires(SAFE_CONST_EXTENSION), "{:#?}", run(SAFE_CONST_EXTENSION));
    }

    #[test]
    fn silent_without_depth_branch() {
        assert!(!fires(SAFE_NO_DEPTH_BRANCH), "{:#?}", run(SAFE_NO_DEPTH_BRANCH));
    }

    #[test]
    fn silent_when_target_not_clock() {
        assert!(!fires(SAFE_NOT_CLOCK_TARGET), "{:#?}", run(SAFE_NOT_CLOCK_TARGET));
    }
}
