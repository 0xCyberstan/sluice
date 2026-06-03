//! Keeper / cranker incentive scaled by `block.timestamp`-elapsed-since-last and
//! paid to the caller — a self-serving timing auction (Olympus `Heart.beat()`
//! class).
//!
//! ## The shape
//!
//! A protocol that needs a periodic on-chain action (a "beat", "poke", "crank",
//! "update", "checkpoint") performed by an arbitrary keeper rewards whoever calls
//! the public entry point. The reward is computed as a function of the wall-clock
//! time elapsed since the last action:
//!
//! ```solidity
//! function beat() external {                       // public, anyone may call
//!     ...
//!     uint256 reward = currentReward();            // = f(block.timestamp - lastBeat)
//!     lastBeat = uint48(block.timestamp);
//!     MINTR.mintOhm(msg.sender, reward);           // paid to the caller
//! }
//! function currentReward() public view returns (uint256) {
//!     uint48 nextBeat = lastBeat + frequency();
//!     uint48 t = uint48(block.timestamp);
//!     return (uint256(t - nextBeat) * maxReward) / duration;   // linear ramp
//! }
//! ```
//!
//! Because the reward grows monotonically with `block.timestamp - lastStored`,
//! and is paid to `msg.sender`, a rational keeper does **not** call the action as
//! soon as it is due — it *waits* to let the elapsed-scaled reward grow before
//! claiming it. That is a self-serving timing auction: the keeper extracts the
//! maximum payout the ramp allows (and, when the ramp is uncapped, an unbounded
//! payout) while the protocol's periodic action is performed later than intended.
//! It also invites a gas-auction race between keepers near the top of the ramp.
//!
//! ## What fires
//!
//! A public / external **state-mutating** function `f` such that, jointly:
//!   1. **Caller-paid** — `f` pays `msg.sender`: a `mint`/`_mint`/`mintOhm`-style
//!      supply op whose recipient (first arg) is `msg.sender`, or a
//!      `transfer`/`safeTransfer` whose `to` is `msg.sender`. This is the keeper
//!      reward leaving the protocol to whoever called.
//!   2. **Elapsed-scaled** — `f`, *or an internal / same-contract view helper it
//!      calls* (`currentReward()`), contains a multiplication `A * B` where one
//!      operand reaches a subtraction whose minuend is `block.timestamp` and whose
//!      subtrahend is a **stored** value (`block.timestamp - lastBeat`,
//!      `now - lastUpdate`). The multiply turns "seconds since last action" into a
//!      reward magnitude.
//!   3. **Incentive context** — the entry or its reward helper is framed as a
//!      keeper reward (a `reward`/`incentive`/`bounty`/`keeper`-named function,
//!      operand, or emitted event), so we are looking at an incentive payout and
//!      not some unrelated time-delta.
//!
//! ## What is deliberately suppressed (precision first)
//!
//!   * **Not caller-paid** — the elapsed-scaled value is never sent to
//!     `msg.sender` (it is an *un-vesting* schedule subtracted from a balance, as
//!     in Ethena `StakedUSDe.getUnvestedAmount` = `(block.timestamp - last) *
//!     vestingAmount / PERIOD`, or it is pulled *in* from the caller). No payout to
//!     the caller ⇒ no auction the caller can win.
//!   * **Fixed / non-elapsed reward** — the payout to `msg.sender` is a constant,
//!     or scales with something other than `block.timestamp - lastStored` (a flat
//!     bounty). Without the elapsed ramp there is nothing to wait for.
//!   * **Proportional per-stake accrual** — the elapsed-scaled term is also
//!     multiplied by the caller's own staked balance / shares
//!     (`stakes[msg.sender] * (block.timestamp - last) * rate`). That is fair
//!     pro-rata yield (waiting longer accrues proportionally, it is not a
//!     winner-take-all crank), not a self-serving crank auction. We require the
//!     ramp's *other* multiplicand to be a **global scalar** (a `reward`/`rate`/
//!     `max`-named state var or constant), not a per-account balance.
//!
//! Confidence is held to a single value-flow dimension at the Medium band: this is
//! a real economic / incentive-design defect (keepers game the timing, and an
//! uncapped ramp is a direct fund leak) but it is a design-level finding rather
//! than a memory-safety bug, and the "waits to maximize" harm is an incentive
//! argument, so it is not promoted to High.

use super::prelude::*;
use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Call, CallKind, Contract, Expr, ExprKind, Function};

pub struct KeeperRewardTimestampAuctionDetector;

impl Detector for KeeperRewardTimestampAuctionDetector {
    fn id(&self) -> &'static str {
        "keeper-reward-timestamp-auction"
    }
    fn category(&self) -> Category {
        Category::KeeperRewardTimestampAuction
    }
    fn description(&self) -> &'static str {
        "Keeper reward scaled by `block.timestamp`-elapsed-since-last and paid to msg.sender (a self-serving timing auction)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.entry_points() {
            // (1) Caller-paid gate: the entry must pay `msg.sender` (the keeper).
            //     A reward that does not leave the protocol to the caller cannot be
            //     gamed by the caller, so this is the precision anchor.
            let Some(pay_span) = caller_payout_span(f) else { continue };

            let Some(contract) = cx.contract_of(f.id) else { continue };

            // (2) Elapsed-scaled gate: somewhere reachable from `f` (its own body,
            //     or a same-contract view/internal reward helper it calls) a
            //     multiplication turns `block.timestamp - <stored>` into a magnitude
            //     whose *other* operand is a global scalar (not a per-account
            //     balance). The reward-helper indirection is the `currentReward()`
            //     shape; resolve one level deep.
            let scaled = elapsed_scaled_global_in_fn(cx, f, contract)
                || reward_helper_is_elapsed_scaled(cx, f, contract);
            if !scaled {
                continue;
            }

            // (3) Incentive context: the entry or its reward helper must read as a
            //     keeper/cranker reward, not an unrelated time delta. Checking the
            //     entry's source *and* its callees' names keeps the `currentReward`
            //     indirection in scope.
            if !incentive_context(cx, f) {
                continue;
            }

            // (4) Suppress proportional per-stake accrual: if every elapsed-scaled
            //     multiplication in scope is also multiplied by the caller's own
            //     balance/shares, this is fair pro-rata yield, not a winner-take-all
            //     crank. (Handled inside the scaled checks by requiring a global
            //     scalar multiplicand; re-checked here against the payout amount.)
            //     Nothing further to do — the global-scalar requirement above is the
            //     discriminator.

            let capped = reward_has_cap(cx, f, contract);
            // The cap bounds the *magnitude* but not the *timing* incentive: a
            // bounded linear auction still pays the keeper the maximum the ramp
            // allows if it waits, so it still fires — the cap only tempers the
            // message and confidence.
            let confidence = if capped { 0.5 } else { 0.6 };

            let cap_clause = if capped {
                "The ramp is bounded by a maximum, so the magnitude is capped — but the keeper still \
                 has every incentive to wait until the ramp tops out before calling, performing the \
                 protocol's periodic action later than intended and always extracting the maximum \
                 reward rather than a fair, smaller one."
            } else {
                "The ramp has no cap, so the longer a keeper waits the larger the reward grows without \
                 bound — both a direct, unbounded drain of protocol funds and a guaranteed delay of the \
                 periodic action, since no rational keeper acts until the reward is large."
            };

            let b = report!(self, Category::KeeperRewardTimestampAuction,
                title = "Keeper reward scales with elapsed time and is paid to the caller (self-serving timing auction)",
                severity = Severity::Medium,
                confidence = confidence,
                dimensions = [Dimension::ValueFlow],
                message = format!(
                    "`{}.{}` is a permissionless keeper action that pays `msg.sender` a reward computed \
                     from `block.timestamp` minus a stored last-action timestamp (a `reward = f(now - \
                     lastBeat)` linear-auction ramp). Because the reward grows monotonically with the \
                     elapsed time and goes to whoever calls, a rational keeper does not act as soon as \
                     the action is due — it waits to maximize the elapsed-scaled reward, a self-serving \
                     timing auction. {}",
                    contract.name, f.name, cap_clause
                ),
                recommendation =
                    "Decouple the keeper incentive from caller-chosen timing: pay a fixed, bounded \
                     reward for performing the action on schedule, or compute the reward from the \
                     scheduled cadence rather than the realized `block.timestamp - lastAction` delta \
                     (so waiting does not increase the payout). If a ramp is intended, keep it strictly \
                     bounded and ensure the protocol's periodic action cannot be deferred for profit \
                     (e.g. settle the schedule to the due time, not to `now`).",
            );
            out.push(finish_at(cx, b, f.id, pay_span));
        }
        out
    }
}

// ------------------------------------------------------------------- caller-paid

/// Span of a call in `f`'s body that pays **`msg.sender`** — a supply op
/// (`mint`/`_mint`/`mintOhm`/`mintTo`) whose recipient (first argument) is
/// `msg.sender`, or an ERC-20 `transfer`/`safeTransfer` whose `to` is
/// `msg.sender`. This is the keeper reward leaving the protocol to the caller.
/// Returns the first such call's span (used as the finding anchor).
fn caller_payout_span(f: &Function) -> Option<sluice_ir::Span> {
    for s in &f.body {
        let mut hit: Option<sluice_ir::Span> = None;
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            if call_pays_msg_sender(c) {
                hit = Some(e.span);
            }
        });
        if hit.is_some() {
            return hit;
        }
    }
    None
}

/// Does this call pay `msg.sender`? Recognizes the two canonical reward egress
/// shapes, by recipient position:
///   * mint family (`mint`/`_mint`/`mintOhm`/`mintTo`/`safeMint`): recipient is
///     the **first** argument — `MINTR.mintOhm(msg.sender, reward)`;
///   * transfer family (`transfer`/`safeTransfer`): `to` is the **second-to-last**
///     argument (amount is last) in both the member form
///     (`token.transfer(to, amt)`, to=arg[-2]) and the library form
///     (`SafeERC20.safeTransfer(token, to, amt)`, to=arg[-2]).
fn call_pays_msg_sender(c: &Call) -> bool {
    match c.func_name.as_deref() {
        Some("mint") | Some("_mint") | Some("mintOhm") | Some("mintTo") | Some("safeMint") => {
            arg_is_msg_sender(c.args.first())
        }
        Some("transfer") | Some("safeTransfer") => {
            // transfer (non-safe) must be a token move, not a native-ETH
            // `payable(x).transfer(v)` (a `Transfer` kind).
            if c.func_name.as_deref() == Some("transfer")
                && !matches!(c.kind, CallKind::External | CallKind::Internal)
            {
                return false;
            }
            let n = c.args.len();
            n >= 2 && arg_is_msg_sender(c.args.get(n - 2))
        }
        _ => false,
    }
}

/// The (optional) argument is `msg.sender` after peeling `address(...)` /
/// `payable(...)` casts. Also accepts the OZ accessor `_msgSender()` /
/// `msgSender()`.
fn arg_is_msg_sender(arg: Option<&Expr>) -> bool {
    match arg {
        Some(a) => expr_is_msg_sender(peel_casts(a)),
        None => false,
    }
}

/// `msg.sender` (member access), or a `_msgSender()` / `msgSender()` accessor
/// call resolving to the caller.
fn expr_is_msg_sender(e: &Expr) -> bool {
    if e.mentions_member("msg", "sender") {
        return true;
    }
    if let ExprKind::Call(c) = &e.kind {
        if matches!(c.func_name.as_deref(), Some("_msgSender") | Some("msgSender")) {
            return true;
        }
    }
    false
}

// --------------------------------------------------------------- elapsed-scaled

/// True if `f`'s own body contains a multiplication `A * B` (or `x *= y`) where
/// one side reaches an elapsed-time subtraction `block.timestamp - <stored>` and
/// the **other** side is a *global scalar* (not a per-account balance). This is
/// the linear-auction ramp `(now - lastBeat) * maxReward`.
fn elapsed_scaled_global_in_fn(cx: &AnalysisContext, f: &Function, contract: &Contract) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            let (lhs, rhs) = match &e.kind {
                ExprKind::Binary { op: BinOp::Mul, lhs, rhs } => (lhs.as_ref(), rhs.as_ref()),
                ExprKind::Assign { op: sluice_ir::AssignOp::Mul, target, value } => {
                    (target.as_ref(), value.as_ref())
                }
                _ => return,
            };
            let l_elapsed = expr_reaches_elapsed(lhs, cx, f, contract);
            let r_elapsed = expr_reaches_elapsed(rhs, cx, f, contract);
            if l_elapsed == r_elapsed {
                // neither side (or implausibly both) is the elapsed term.
                return;
            }
            let other = if l_elapsed { rhs } else { lhs };
            // The other multiplicand must be a global scalar reward parameter, not
            // the caller's own balance/shares (which would make this pro-rata yield).
            if multiplicand_is_global_scalar(other, contract) && !mentions_per_account_balance(other)
            {
                found = true;
            }
        });
        if found {
            break;
        }
    }
    found
}

/// True if any **same-contract** internal / view reward-helper that `f` calls is
/// itself elapsed-scaled (the `beat()` → `currentReward()` indirection). We only
/// descend into helpers whose name reads as a reward getter, to keep the scan
/// cheap and precise.
fn reward_helper_is_elapsed_scaled(cx: &AnalysisContext, f: &Function, contract: &Contract) -> bool {
    for callee_name in &f.effects.internal_calls {
        if !name_is_reward_like(callee_name) {
            continue;
        }
        let Some(helper) = cx
            .scir
            .functions_of(f.contract)
            .find(|g| &g.name == callee_name && !g.is_modifier() && g.has_body)
        else {
            continue;
        };
        if elapsed_scaled_global_in_fn(cx, helper, contract) {
            return true;
        }
    }
    false
}

/// True if `e` (transitively) contains an elapsed-time subtraction
/// `block.timestamp - <stored>` (or `<stored cast> - <stored cast>` where the
/// minuend reaches `block.timestamp`). We look for a `Sub` whose **minuend** side
/// reaches `block.timestamp`/`now` and whose **subtrahend** reaches a stored
/// last-timestamp value (a state var or a local derived from one). The order
/// matters: `lastBeat - block.timestamp` is not "elapsed".
fn expr_reaches_elapsed(e: &Expr, cx: &AnalysisContext, f: &Function, contract: &Contract) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Binary { op: BinOp::Sub, lhs, rhs } = &sub.kind {
            // minuend reaches block.timestamp / now (directly, or via a local
            // current-time alias such as `currentTime = uint48(block.timestamp)`);
            // subtrahend reaches a stored last-time value (state var, or a local
            // timestamp identifier such as `nextBeat = lastBeat + frequency`).
            if minuend_is_current_time(lhs) && reaches_stored_time(rhs, cx, f, contract) {
                found = true;
            }
        }
    });
    found
}

/// `block.timestamp` member access, or a bare `now` identifier (legacy alias).
fn is_block_time(e: &Expr) -> bool {
    e.mentions_member("block", "timestamp")
        || matches!(&e.kind, ExprKind::Ident(n) if n == "now")
}

/// True if `e` transitively reads `block.timestamp` / `now`. Catches
/// `uint48(block.timestamp)` (cast wrapping the member read).
fn expr_reaches_block_time(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if is_block_time(sub) {
            found = true;
        }
    });
    found
}

/// True if `e` is the **minuend** of an elapsed-since subtraction — it reads the
/// current time, either directly (`block.timestamp` / `uint48(block.timestamp)`)
/// or via a local alias whose name reads as the current time (`currentTime`,
/// `nowTime`, `timestamp`, `blockTime`). The local-alias case is what makes the
/// `currentTime = uint48(block.timestamp); ... currentTime - nextBeat` shape
/// resolve without full local def-use tracking.
fn minuend_is_current_time(e: &Expr) -> bool {
    if expr_reaches_block_time(e) {
        return true;
    }
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let Some(name) = ident_or_member_name(sub) {
            if name_is_current_time(name) {
                found = true;
            }
        }
    });
    found
}

/// A name denoting a current-time alias (`currentTime`, `nowTime`, `timeNow`,
/// `blockTime`, or a bare `timestamp`). Distinct from a *stored* time anchor — a
/// current-time alias is the freshly-read `block.timestamp`, the minuend side.
fn name_is_current_time(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "currenttime"
        || l == "currenttimestamp"
        || l == "nowtime"
        || l == "timenow"
        || l == "blocktime"
        || l == "blocktimestamp"
        || l == "timestamp"
        || l == "_now"
        || l == "nowts"
}

/// True if `e` reaches a *stored* last-action timestamp: a state variable of the
/// contract (settable — a `constant`/`immutable` is not a moving "last action"),
/// or a local identifier whose name reads as a stored time anchor
/// (`lastBeat`, `nextBeat`, `lastUpdate`, `lastTime`, `start`, `checkpoint`).
/// This distinguishes `block.timestamp - lastBeat` (elapsed) from
/// `block.timestamp - someDuration` (a deadline arithmetic, not elapsed).
fn reaches_stored_time(e: &Expr, _cx: &AnalysisContext, _f: &Function, contract: &Contract) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let Some(name) = ident_or_member_name(sub) {
            // A settable state var that names a time anchor.
            if is_settable_state_var(contract, name) && name_is_time_anchor(name) {
                found = true;
                return;
            }
            // A local/derived identifier that clearly names a stored time anchor
            // (e.g. `nextBeat = lastBeat + frequency()`), even if not a direct
            // state var — the subtraction `now - nextBeat` is still elapsed-since.
            if name_is_time_anchor(name) {
                found = true;
            }
        }
    });
    found
}

/// Bare identifier or the trailing member of a member access (`lastBeat`,
/// `self.lastBeat` -> `"lastBeat"`).
fn ident_or_member_name(e: &Expr) -> Option<&str> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.as_str()),
        ExprKind::Member { member, .. } => Some(member.as_str()),
        _ => None,
    }
}

/// A name that denotes a *stored last-action time anchor* — the subtrahend of an
/// elapsed-since computation. Deliberately excludes pure-duration words
/// (`duration`, `period`, `frequency`, `delay`, `cooldown`) so that
/// `deadline = block.timestamp - duration` is not mistaken for elapsed-since.
fn name_is_time_anchor(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // A `last*` anchor (covers `lastBeat`/`lastUpdate`/`lastClaim`/… by prefix),
    // a `next*`-beat / checkpoint / start anchor, or a `*timestamp`-suffixed name.
    l.starts_with("last")
        || l.contains("nextbeat")
        || l.contains("checkpoint")
        || l.contains("starttime")
        || l == "start"
        || l.ends_with("timestamp")
}

// ----------------------------------------------------- global-scalar multiplicand

/// True if `e` is a *global scalar* reward magnitude — a state variable or
/// constant whose name reads as a reward/rate/max (`maxReward`, `rewardRate`,
/// `incentive`, `bounty`), or a bare numeric literal. This is the non-per-account
/// multiplicand of the auction ramp `(now - last) * maxReward`. We require a
/// reward-shaped name (or a literal) so an arbitrary `(now - last) * someFactor`
/// in unrelated math does not match.
fn multiplicand_is_global_scalar(e: &Expr, contract: &Contract) -> bool {
    // A numeric literal multiplier (`(now - last) * 5`).
    if matches!(&e.kind, ExprKind::Lit(sluice_ir::Lit::Number(_))) {
        return true;
    }
    // An identifier / member naming a reward magnitude.
    let mut hit = false;
    e.visit(&mut |sub| {
        if hit {
            return;
        }
        if let Some(name) = ident_or_member_name(sub) {
            if name_is_reward_magnitude(name) {
                // Prefer that it actually be a state var/constant, but a
                // reward-named local (`uint256 maxReward = ...`) is equally a global
                // scalar. The name carries the signal.
                let _ = contract; // (kept for future state-var disambiguation)
                hit = true;
            }
        }
    });
    hit
}

/// A name denoting a reward/rate/max magnitude paid out (the auction's scalar).
fn name_is_reward_magnitude(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    (l.contains("reward") && !l.contains("rewarddebt"))
        || l.contains("incentive")
        || l.contains("bounty")
        || l.contains("maxreward")
        || l.contains("rewardrate")
        || l.contains("ratepersecond")
        || l.contains("emission")
        || l == "rate"
        || l.ends_with("rate")
        || l.contains("maxpayout")
        || l.contains("maxbounty")
}

/// True if `e` mentions a **per-account** balance / share / stake lookup — the
/// signature of pro-rata yield (`stakes[msg.sender]`, `balanceOf[user]`,
/// `shares[account]`), which must NOT count as a global scalar. A keeper auction
/// multiplies elapsed time by a single global magnitude, not by the caller's own
/// balance.
fn mentions_per_account_balance(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        // An indexed lookup whose base names a balance/share/stake map.
        if let ExprKind::Index { base, .. } = &sub.kind {
            if let Some(name) = root_ident_str(base) {
                let l = name.to_ascii_lowercase();
                if l.contains("balance")
                    || l.contains("share")
                    || l.contains("stake")
                    || l.contains("deposit")
                    || l.contains("amount")
                {
                    found = true;
                    return;
                }
            }
        }
        // A bare/member identifier naming a per-account balance/share quantity.
        if let Some(name) = ident_or_member_name(sub) {
            let l = name.to_ascii_lowercase();
            if l.contains("balanceof") || l.contains("staked") || l.contains("userbalance") || l.contains("usershares") {
                found = true;
            }
        }
    });
    found
}

// ------------------------------------------------------------- incentive context

/// True if the entry (or one of its callees, by name) reads as a keeper / cranker
/// reward incentive: a reward-shaped function name, a reward-shaped callee
/// (`currentReward`), an emitted reward event, or reward wording in the source.
fn incentive_context(cx: &AnalysisContext, f: &Function) -> bool {
    if name_is_reward_like(&f.name) || name_is_keeper_action(&f.name) {
        return true;
    }
    if f.effects.internal_calls.iter().any(|c| name_is_reward_like(c)) {
        return true;
    }
    if f.effects.emits.iter().any(|ev| {
        let l = ev.to_ascii_lowercase();
        l.contains("reward") || l.contains("incentive") || l.contains("bounty") || l.contains("beat")
    }) {
        return true;
    }
    // Fall back to source wording (comment-stripped, lowercased).
    let src = cx.source_text(f.span);
    src.contains("reward") || src.contains("incentive") || src.contains("bounty") || src.contains("keeper")
}

/// A reward-getter / reward-issuer function name (`currentReward`, `getReward`,
/// `pendingReward`, `_reward`, `issueReward`, `keeperReward`).
fn name_is_reward_like(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    (l.contains("reward") && !l.contains("rewarddebt")) || l.contains("incentive") || l.contains("bounty")
}

/// A periodic-keeper action verb (`beat`, `poke`, `crank`, `tick`, `ping`,
/// `heartbeat`, `update`, `checkpoint`, `sync`) — the action a cranker performs.
/// Used only as one of several incentive-context signals (never on its own).
fn name_is_keeper_action(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    matches!(
        l.as_str(),
        "beat" | "heartbeat" | "poke" | "crank" | "tick" | "ping"
    ) || l.contains("keeper")
}

// ----------------------------------------------------------------------- the cap

/// True if the reward is bounded by a maximum in scope — a `min(...)`-style clamp,
/// a `>= duration ? maxReward : ramp` ternary, or an explicit comparison against a
/// `max`-named bound. Used only to temper the message/confidence (a bounded ramp
/// still constitutes a timing auction), never to suppress.
fn reward_has_cap(cx: &AnalysisContext, f: &Function, contract: &Contract) -> bool {
    if fn_has_cap(f) {
        return true;
    }
    // Also look in the reward helper (`currentReward`), where the clamp usually lives.
    for callee_name in &f.effects.internal_calls {
        if !name_is_reward_like(callee_name) {
            continue;
        }
        if let Some(helper) = cx
            .scir
            .functions_of(f.contract)
            .find(|g| &g.name == callee_name && !g.is_modifier() && g.has_body)
        {
            if fn_has_cap(helper) {
                return true;
            }
        }
    }
    let _ = contract;
    false
}

/// Heuristic cap detection within one function body: a `min(` call, or a ternary /
/// comparison that returns a `max*`-named bound when the ramp would exceed it.
fn fn_has_cap(f: &Function) -> bool {
    let mut capped = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if capped {
                return;
            }
            // `min(ramp, maxReward)` / `Math.min(...)`.
            if let ExprKind::Call(c) = &e.kind {
                if matches!(c.func_name.as_deref(), Some("min") | Some("Min")) {
                    capped = true;
                    return;
                }
            }
            // `(... >= duration) ? maxReward : ramp` — a `max*`-named operand in a
            // ternary is the cap arm.
            if let ExprKind::Ternary { then_e, else_e, .. } = &e.kind {
                if ternary_arm_is_max(then_e) || ternary_arm_is_max(else_e) {
                    capped = true;
                }
            }
        });
        if capped {
            break;
        }
    }
    capped
}

/// A ternary arm that is (or reaches) a `max*`-named magnitude — the saturating
/// branch of a bounded auction.
fn ternary_arm_is_max(e: &Expr) -> bool {
    let mut hit = false;
    e.visit(&mut |sub| {
        if let Some(name) = ident_or_member_name(sub) {
            let l = name.to_ascii_lowercase();
            if l.starts_with("max") || l.contains("maxreward") || l.contains("cap") {
                hit = true;
            }
        }
    });
    hit
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // VULN: the Olympus `Heart.beat()` shape — a permissionless keeper action that
    // pays msg.sender a reward computed from `block.timestamp - lastBeat` via a
    // `currentReward()` helper. Even though the ramp is bounded by `maxReward`, the
    // keeper waits to maximize the elapsed-scaled reward — the timing auction.
    const VULN: &str = r#"
pragma solidity ^0.8.20;
interface IMinter { function mintOhm(address to, uint256 amount) external; }
contract Heart {
    uint48 public lastBeat;
    uint48 public frequency;
    uint256 public maxReward;
    uint48 public auctionDuration;
    IMinter public MINTR;

    event RewardIssued(address to, uint256 reward);

    function beat() external {
        uint48 currentTime = uint48(block.timestamp);
        require(currentTime >= lastBeat + frequency, "out of cycle");
        // ... periodic protocol work ...
        uint256 reward = currentReward();
        lastBeat = currentTime;
        if (reward > 0) {
            MINTR.mintOhm(msg.sender, reward);
            emit RewardIssued(msg.sender, reward);
        }
    }

    function currentReward() public view returns (uint256) {
        uint48 nextBeat = lastBeat + frequency;
        uint48 currentTime = uint48(block.timestamp);
        uint48 duration = auctionDuration;
        if (currentTime <= nextBeat) {
            return 0;
        } else {
            return currentTime - nextBeat >= duration
                ? maxReward
                : (uint256(currentTime - nextBeat) * maxReward) / duration;
        }
    }
}
"#;

    // SAFE 1 (not caller-paid): the Ethena `StakedUSDe.getUnvestedAmount` shape.
    // `(block.timestamp - lastDistributionTimestamp) * vestingAmount / PERIOD` is an
    // *un-vesting* schedule subtracted from a balance — never paid to msg.sender,
    // and the only timestamp writer is access-controlled. No caller payout ⇒ silent.
    const SAFE_UNVEST: &str = r#"
pragma solidity ^0.8.20;
contract StakedVault {
    uint256 public vestingAmount;
    uint256 public lastDistributionTimestamp;
    uint256 public constant VESTING_PERIOD = 8 hours;

    function getUnvestedAmount() public view returns (uint256) {
        uint256 timeSinceLastDistribution = block.timestamp - lastDistributionTimestamp;
        if (timeSinceLastDistribution >= VESTING_PERIOD) {
            return 0;
        }
        uint256 deltaT = VESTING_PERIOD - timeSinceLastDistribution;
        return (deltaT * vestingAmount) / VESTING_PERIOD;
    }

    function transferInRewards(uint256 amount) external {
        // pulls FROM the caller; access control elsewhere
        vestingAmount = amount;
        lastDistributionTimestamp = block.timestamp;
    }
}
"#;

    // SAFE 2 (proportional per-stake accrual): a normal staking-reward claim where
    // the elapsed term is multiplied by the caller's OWN staked balance. Waiting
    // accrues pro-rata, it is not a winner-take-all crank — must not fire.
    const SAFE_PRORATA: &str = r#"
pragma solidity ^0.8.20;
interface IToken { function transfer(address to, uint256 amount) external; }
contract Staking {
    mapping(address => uint256) public stakes;
    mapping(address => uint256) public lastClaim;
    uint256 public rewardRate;
    IToken public token;

    function claimReward() external {
        uint256 elapsed = block.timestamp - lastClaim[msg.sender];
        uint256 reward = stakes[msg.sender] * elapsed * rewardRate;
        lastClaim[msg.sender] = block.timestamp;
        token.transfer(msg.sender, reward);
    }
}
"#;

    // SAFE 3 (fixed reward): a permissionless keeper action that pays msg.sender a
    // FIXED bounty, with no elapsed scaling. Nothing to wait for — must not fire.
    const SAFE_FIXED: &str = r#"
pragma solidity ^0.8.20;
interface IToken { function transfer(address to, uint256 amount) external; }
contract FixedKeeper {
    uint48 public lastBeat;
    uint48 public frequency;
    uint256 public constant KEEPER_REWARD = 1e18;
    IToken public token;

    function poke() external {
        require(uint48(block.timestamp) >= lastBeat + frequency, "early");
        lastBeat = uint48(block.timestamp);
        token.transfer(msg.sender, KEEPER_REWARD);
    }
}
"#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(
            fs.iter().any(|f| f.detector == "keeper-reward-timestamp-auction"),
            "expected keeper-reward-timestamp-auction on Heart.beat(); got {:?}",
            fs.iter().map(|f| &f.detector).collect::<Vec<_>>()
        );
    }

    #[test]
    fn silent_on_unvesting_schedule() {
        let fs = run(SAFE_UNVEST);
        assert!(
            !fs.iter().any(|f| f.detector == "keeper-reward-timestamp-auction"),
            "must not fire on a non-caller-paid un-vesting schedule"
        );
    }

    #[test]
    fn silent_on_prorata_accrual() {
        let fs = run(SAFE_PRORATA);
        assert!(
            !fs.iter().any(|f| f.detector == "keeper-reward-timestamp-auction"),
            "must not fire on proportional per-stake reward accrual"
        );
    }

    #[test]
    fn silent_on_fixed_reward() {
        let fs = run(SAFE_FIXED);
        assert!(
            !fs.iter().any(|f| f.detector == "keeper-reward-timestamp-auction"),
            "must not fire on a fixed (non-elapsed-scaled) keeper bounty"
        );
    }
}
