//! Centralization risk: a privileged admin can move user funds or re-route fund
//! flows in a single transaction, with no timelock / exit window (the "admin can
//! rug" class that audits and bug-bounty programs routinely flag).
//!
//! The pattern: a function gated by an access-control guard (`onlyOwner` /
//! `onlyAdmin` / `onlyRole` / `onlyGovernance` — all of which the IR classifies
//! as [`GuardKind::MsgSenderCheck`], so `cx.has_access_control(f)` is true) that
//! touches funds or fund-affecting configuration while the contract evidences
//! **no timelock / governance delay**.
//!
//! The class historically over-claimed: every match was reported with the strong
//! "can move/re-route user funds" title, even for bounded scalar setters
//! (`setFeeToDaoPercent` capped by `require(x <= MAX)`) and token-rescue helpers
//! that send only to a fixed/preset recipient. Those are not rugs. So the title
//! and severity are now **tiered by what the function body actually does**. The
//! cardinal rule (precision over volume): a Low (or higher) finding is reserved
//! for a body with a genuine **fund-sink whose destination is not a fixed/preset
//! recipient** — i.e. an attacker-steerable fund movement. Everything weaker is
//! Info or silent.
//!
//!   * **Strong** — "Privileged admin can move/re-route user funds with no
//!     timelock" — when the body contains a real fund-flow (token
//!     `transfer`/`safeTransfer`/`transferFrom`, `.call{value:}` / `.send` ETH
//!     move, `mint`/`burn`, `approve`, or a reassignment of a
//!     withdrawal/treasury/recipient **address** state variable) AND that flow is
//!     attacker-steerable: the destination is **caller-chosen** (`withdrawTo(to,
//!     …)` / `rescue(token,to,amt)`), or it is a supply move (`mint`/`burn`), or
//!     it re-points a recipient **address** state var. A fund-routing-shaped
//!     setter (`set*Fee` / `setRouter` / `migrate`) that also moves funds is the
//!     more serious configuration-reroute case → **Medium**; a plain steerable
//!     fund mover → **Low**.
//!   * **Info — preset-destination fund mover** — a body that *does* move funds
//!     but only to a **fixed / preset / internal** destination (a state var, a
//!     constant, a per-`id` mapping entry, or a bare `approve` to a fixed
//!     spender) and is not a routing setter. It moves protocol funds along a
//!     hard-wired path rather than re-routing *user* funds to an attacker-chosen
//!     address, so it is informational, not a rug.
//!   * **Info — token-rescue** — `recover*` / `sweep*` / `rescue*` that sends to a
//!     **fixed / immutable / preset** recipient: a token-rescue, not a rug.
//!   * **Soft — "Privileged parameter setter (no timelock)"** at Info — a
//!     fund-routing-shaped setter (`set*Fee` / `setRouter` / `setImplementation`,
//!     …) whose body moves **no** funds (no fund-sink ⇒ never Low+). Suppressed
//!     entirely when it is only a bounded `uintN`/`bool` set guarded by a cap
//!     (`require(x <= MAX)`), which cannot be pushed to an abusive value.
//!
//! Non-centralization shapes are dropped up front: constructors, initializers
//! (the `initializer` modifier-guard *or* an `initialize`/`reinitialize`-style
//! name — sets up the contract once, it is not the standing admin surface), and
//! `view`/`pure` functions (they cannot move anything).
//!
//! Precision is otherwise prioritized via aggressive suppression:
//!
//!   * Any contract that evidences a timelock / governance delay
//!     (`timelock` / `delay` / `eta` / `minDelay`, a `Timelock`/`Governor` base,
//!     or a `queue`→`execute` two-step) is silenced — the exit window exists.
//!   * A fund move that is **provably the caller's own** (every value-moving call
//!     pins its destination/source to `msg.sender`) is not a rug and is silenced.
//!   * Ordinary user operations (`deposit`/`stake`/`claim`/…) are not flagged —
//!     unless they are a *targeted* admin transfer to a caller-chosen address
//!     (`withdrawTo(address to, ...)`), which is the rug shape.
//!
//! This remains a *low-confidence, informational* class — it flags a trust
//! assumption, not a code defect — so the confidence is modest (0.4).
//!
//! Distinct from `governance-timelock`: that detector fires once per *contract*
//! on the single most-critical upgrade/setter regardless of guard; this one
//! requires an *access-control guard* and a concrete *fund-movement or
//! fund-routing* effect, and reports under a distinct category
//! ([`Category::Centralization`]) so the two never dedup against each other.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{CallKind, Contract, Expr, ExprKind, Function};

pub struct CentralizationDetector;

const STRONG_TITLE: &str = "Privileged admin can move/re-route user funds with no timelock";
const SOFT_TITLE: &str = "Privileged parameter setter (no timelock)";
const RESCUE_TITLE: &str = "Privileged token-rescue to a fixed recipient";
const FIXED_DEST_TITLE: &str = "Privileged admin moves protocol funds to a preset destination";

impl Detector for CentralizationDetector {
    fn id(&self) -> &'static str {
        "centralization-risk"
    }
    fn category(&self) -> Category {
        Category::Centralization
    }
    fn description(&self) -> &'static str {
        "Privileged admin can move user funds or re-route fund flows with no timelock (admin-can-rug centralization risk)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.entry_points() {
            // Core gate: the function must be access-controlled. A privileged
            // admin operation is the whole subject of this class; a
            // permissionless function is covered by other detectors
            // (arbitrary-transfer, access-control).
            if !cx.has_access_control(f) {
                continue;
            }
            // Non-centralization shapes are not the standing admin fund surface:
            //   * constructors / initializers set up the contract exactly once.
            //     `cx.is_initializer` only catches the `initializer` *modifier*
            //     guard, so also drop functions whose *name* is an initializer
            //     (`initialize` / `reinitialize` / `__init`, e.g. Olympus
            //     `sOlympus.initialize`, which guards with a manual
            //     `require(msg.sender == initializer)` and seeds `treasury` —
            //     setup, not a standing fund-move lever).
            //   * `view`/`pure` functions cannot move or re-route anything.
            if f.is_constructor()
                || cx.is_initializer(f)
                || f.has_modifier_like("initializer")
                || is_initializer_name(&f.name)
                || f.is_view_or_pure()
            {
                continue;
            }
            // Ordinary user operations are not a centralization risk even when an
            // operator-style guard happens to apply — UNLESS the function is a
            // *targeted* admin transfer to a caller-chosen address
            // (`withdrawTo(address to, ...)`), which is exactly the rug shape and
            // must not be hidden behind the "withdraw" substring.
            if is_user_op(&f.name) && !has_caller_chosen_value_move(f) {
                continue;
            }

            let Some(contract) = cx.contract_of(f.id) else { continue };
            // Whole-contract suppression: if a timelock / governance delay exists,
            // users have an exit window, so the admin cannot rug without warning.
            if contract_has_timelock(cx, contract) {
                continue;
            }

            // ---- Token-rescue helpers (`recover*` / `sweep*` / `rescue*`) ------
            // These are handled up front and always `continue`, because a rescue
            // to a *fixed* recipient is a benign token-recovery, while a rescue to
            // a *caller-chosen* address is a genuine rug. Deciding here keeps the
            // two classifications from colliding with the generic arms below.
            if is_recover_name(&f.name) {
                if has_fund_flow(f, contract) {
                    if all_value_moves_are_caller_own(f) {
                        // Admin can only pull funds to itself — not a rug of users.
                        continue;
                    }
                    if has_caller_chosen_value_move(f) {
                        // Destination is a caller/admin-supplied parameter: this is
                        // the classic `rescue(token, to, amt)` rug vector.
                        out.push(self.finding(
                            cx,
                            f,
                            STRONG_TITLE,
                            Severity::Low,
                            strong_msg(&contract.name, &f.name),
                        ));
                    } else {
                        // Every move goes to a fixed / immutable / preset recipient:
                        // a token-rescue, not a rug. Down-rank to an informational
                        // note rather than over-claiming a fund-rerouting risk.
                        out.push(self.finding(
                            cx,
                            f,
                            RESCUE_TITLE,
                            Severity::Info,
                            format!(
                                "`{}.{}` is an access-controlled token-rescue function that transfers \
                                 tokens/ETH only to a fixed, preset recipient (not a caller-supplied \
                                 address). This recovers stranded assets to a hard-coded destination \
                                 rather than re-routing user funds, so it is informational — but note \
                                 the contract has no timelock, so verify the preset recipient is the \
                                 intended one.",
                                contract.name, f.name
                            ),
                        ));
                    }
                } else {
                    // A rescue-shaped name with no detectable fund move. Don't claim
                    // a fund reroute, but keep a soft signal rather than going fully
                    // silent (never silence a possible real bug). No fund-sink ⇒
                    // Info, not Low (Low is reserved for steerable fund movers).
                    out.push(self.finding(
                        cx,
                        f,
                        SOFT_TITLE,
                        Severity::Info,
                        soft_msg(&contract.name, &f.name),
                    ));
                }
                continue;
            }

            // ---- Real fund-flow → tier by steerability ------------------------
            // A token transfer / ETH send / mint / burn / approve, or a
            // reassignment of a withdrawal/treasury/recipient address state var.
            if has_fund_flow(f, contract) {
                // Suppress when every value-moving call is provably the caller's
                // own funds (destination / source pinned to `msg.sender`): an admin
                // that can only move funds *to itself* is not rugging users.
                if all_value_moves_are_caller_own(f) {
                    continue;
                }
                // A fund-routing-shaped name (sets a fee/recipient/treasury/router,
                // or a sweep/migrate) that *also* moves funds is the most serious
                // configuration-reroute case → Medium, strong title.
                if is_fund_routing_setter(&f.name) {
                    out.push(self.finding(
                        cx,
                        f,
                        STRONG_TITLE,
                        Severity::Medium,
                        strong_msg(&contract.name, &f.name),
                    ));
                    continue;
                }
                // Steerable fund-flow → Low, strong title. "Steerable" means the
                // admin can direct value somewhere an attacker would care about:
                //   * the destination is **caller-chosen** (a parameter), the
                //     classic `withdrawTo(to, …)` / arbitrary-recipient rug; or
                //   * the body **mints / burns** supply (creates or destroys
                //     balances out of thin air); or
                //   * it re-points a withdrawal/treasury/recipient **address**
                //     state var (re-routes where future funds go).
                if has_caller_chosen_value_move(f)
                    || has_mint_or_burn(f)
                    || reassigns_recipient_address(f, contract)
                {
                    out.push(self.finding(
                        cx,
                        f,
                        STRONG_TITLE,
                        Severity::Low,
                        strong_msg(&contract.name, &f.name),
                    ));
                    continue;
                }
                // Otherwise the body moves funds only to a **fixed / preset /
                // internal** destination (a state var, a constant, a per-`id`
                // mapping entry, or a bare `approve` to a fixed spender). This
                // routes protocol funds along a hard-wired path rather than
                // re-routing user funds to an attacker-chosen address — a trust
                // note, not a rug → Info.
                out.push(self.finding(
                    cx,
                    f,
                    FIXED_DEST_TITLE,
                    Severity::Info,
                    fixed_dest_msg(&contract.name, &f.name),
                ));
                continue;
            }

            // ---- Fund-routing-shaped setter with NO fund move -----------------
            // The body did not actually move funds. Only the configuration-setter
            // *shape* matched (e.g. `setFee`, `setRouter`, `setImplementation`).
            // This is a softer trust concern, not a fund reroute.
            if is_fund_routing_setter(&f.name) {
                // A bounded `uintN`/`bool` setter guarded by an explicit cap
                // (`require(x <= MAX)`) cannot push the parameter to an abusive
                // value, so it is not a meaningful centralization lever → suppress.
                if is_bounded_scalar_setter(f, contract) {
                    continue;
                }
                // In-between: a routing-shaped setter that moves no funds. Keep the
                // soft "parameter setter" signal, but at Info — with no fund-sink
                // in the body this is never a Low+ (fund-mover) finding.
                out.push(self.finding(cx, f, SOFT_TITLE, Severity::Info, soft_msg(&contract.name, &f.name)));
                continue;
            }

            // Neither a fund mover nor a fund-routing-shaped setter: not this
            // detector's concern. Emitting a finding here would only add soft
            // noise on every access-controlled function (`pause`, `grantRole`, …).
        }
        out
    }
}

impl CentralizationDetector {
    fn finding(
        &self,
        cx: &AnalysisContext,
        f: &Function,
        title: &str,
        sev: Severity,
        msg: String,
    ) -> Finding {
        // Honest: the absence of an off-chain timelock owner cannot be proven from
        // source, and "trusted admin" is often an accepted assumption, so this is a
        // low-confidence signal. BUT the engine's corroboration scorer recomputes
        // the final severity from `base(sev) × (0.5 + 0.5·confidence)`, and at
        // confidence 0.4 a `Medium` label scores 45×0.7 = 31.5, which falls back
        // under the Medium threshold (33) — making the Medium tier unreachable. Give
        // the Medium tier (routing-shaped name that actually moves funds — the most
        // serious config-reroute case) just enough confidence to land as Medium
        // (45×0.75 = 33.75); Low/Info tiers keep 0.4 so their scores are unchanged.
        let conf = if matches!(sev, Severity::Medium) { 0.5 } else { 0.4 };
        let b = FindingBuilder::new(self.id(), Category::Centralization)
            .title(title)
            .severity(sev)
            .confidence(conf)
            .dimension(Dimension::Invariant)
            .message(msg)
            .recommendation(
                "Route fund-moving / fund-routing admin actions through a timelock (e.g. \
                 OpenZeppelin `TimelockController`) with a meaningful `minDelay`, or behind \
                 multisig / on-chain governance, so users have a window to exit before a \
                 privileged change to funds takes effect. For parameter setters, bound the \
                 value with an explicit cap.",
            );
        cx.finish(b, f.id, f.span)
    }
}

// ----------------------------------------------------------------- messages

fn strong_msg(contract: &str, func: &str) -> String {
    format!(
        "`{}.{}` is an access-controlled function that moves funds (a token transfer / ETH \
         send / mint / burn / approve, or a reassignment of a withdrawal/treasury/recipient \
         address) to a destination that is not provably the caller's own, and the contract \
         has no timelock or delay. A single compromised or malicious admin key can move or \
         re-route user funds in one transaction, with no window for users to exit first — the \
         admin-can-rug centralization risk.",
        contract, func
    )
}

fn soft_msg(contract: &str, func: &str) -> String {
    format!(
        "`{}.{}` is an access-controlled parameter setter that changes configuration \
         immediately, with no timelock or delay. Its body does not itself move user funds, so \
         this is a softer trust concern than a direct fund reroute — but a compromised or \
         malicious admin can still change the parameter in one transaction with no exit window.",
        contract, func
    )
}

fn fixed_dest_msg(contract: &str, func: &str) -> String {
    format!(
        "`{}.{}` is an access-controlled function that moves funds (a token transfer / ETH \
         send / approve) only to a fixed, preset, or internal destination — a state variable, a \
         constant, a per-id mapping entry, or an `approve` to a fixed spender — not to a \
         caller-chosen address, and it neither mints/burns supply nor re-points a \
         recipient/treasury address. It routes protocol funds along a hard-wired path rather \
         than re-routing user funds to an attacker-chosen destination, so it is informational \
         rather than an admin-can-rug risk — but note the contract has no timelock, so verify \
         the preset destination is the intended one.",
        contract, func
    )
}

// ----------------------------------------------------------------- helpers

/// Fund-routing / fund-releasing privileged setters and sweepers. An exact-ish
/// name match: these denote configuration whose change moves or redirects user
/// funds (fee skim, payout recipient, treasury, swap router, proxy code), or a
/// bulk sweep / migration of held funds. A name match alone no longer earns the
/// strong title — it only selects the *trigger surface* and the severity tier;
/// the strong title is reserved for bodies with a real fund-flow.
fn is_fund_routing_setter(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // `set*Fee` (setFee, setSwapFee, setProtocolFee, …) routes a skim of value.
    if l.starts_with("set") && l.contains("fee") {
        return true;
    }
    // Payout / treasury / router / proxy-code re-routing setters.
    if matches!(
        l.as_str(),
        "setrecipient"
            | "setfeerecipient"
            | "settreasury"
            | "setrouter"
            | "setimplementation"
    ) {
        return true;
    }
    // Bulk sweep / migration of held funds. (`rescue` is handled by the dedicated
    // recover-name path, which runs first.)
    l.contains("withdrawall") || l.contains("migrate")
}

/// Token-rescue / recovery / sweep helpers, by name. These conventionally move
/// stranded assets; whether that is benign (fixed recipient) or a rug
/// (caller-chosen recipient) is decided from the body, not the name.
fn is_recover_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("recover") || l.contains("rescue") || l.contains("sweep")
}

/// An initializer-by-name: a one-shot setup function (`initialize`,
/// `reinitialize`, `__init`, `init`). These seed contract state once and are not
/// the standing admin fund surface. A bare `init` prefix is used because the
/// convention (`initialize`, `initializeV2`, `__ERC20_init`, …) is unambiguous;
/// it complements `cx.is_initializer`, which only sees the `initializer`
/// *modifier* guard and misses manual `require(msg.sender == initializer)` forms.
fn is_initializer_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.starts_with("initialize")
        || l.starts_with("reinitialize")
        || l.starts_with("__init")
        || l == "init"
}

/// Intentionally-permissionless user operations that are not a centralization
/// risk even if an operator/role guard happens to apply. Mirrors the user-facing
/// list used by the access-control detector, minus the admin-sweep verbs
/// (`withdrawAll`) which are handled as fund-routing above.
fn is_user_op(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // `withdraw` is a user op, but `withdrawAll` (admin sweep) is not — keep the
    // sweep distinguishable.
    if l.contains("withdrawall") {
        return false;
    }
    [
        "deposit", "withdraw", "claim", "redeem", "stake", "unstake", "swap", "borrow", "repay",
        "wrap", "unwrap", "harvest", "compound", "vote",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// True if the function contains a real **fund-flow** in its body: a native-ETH
/// send, a token `transfer`/`transferFrom`/`safe*` move, a `mint`/`burn`, an
/// `approve`, or a reassignment of a withdrawal/treasury/recipient **address**
/// state variable. This is the gate for the strong "can move/re-route user
/// funds" title — a bare config-setter name does not qualify.
fn has_fund_flow(f: &Function, contract: &Contract) -> bool {
    if reassigns_recipient_address(f, contract) {
        return true;
    }
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            let ExprKind::Call(call) = &e.kind else { return };

            // Native-ETH send: `to.transfer(x)` / `.send(x)` / `to.call{value:}`.
            if matches!(call.kind, CallKind::Transfer | CallKind::Send)
                || (call.kind == CallKind::LowLevelCall && call.value.is_some())
            {
                found = true;
                return;
            }

            match call.func_name.as_deref() {
                // Token moves.
                Some("transfer") | Some("transferFrom")
                    if matches!(call.kind, CallKind::External | CallKind::Internal) =>
                {
                    found = true;
                }
                Some("safeTransfer") | Some("safeTransferFrom") => found = true,
                // Mint / burn create or destroy balances.
                Some("mint") | Some("_mint") | Some("burn") | Some("_burn") => found = true,
                // Approvals grant spending authority over held funds.
                Some("approve") | Some("safeApprove") | Some("forceApprove") => found = true,
                _ => {}
            }
        });
        if found {
            break;
        }
    }
    found
}

/// True if the body contains a `mint`/`burn` call — a supply move that creates or
/// destroys balances out of thin air (not a transfer of existing held funds).
/// This is one of the "steerable" effects that keeps a fund-flow at Low rather
/// than down-ranking it to the preset-destination Info tier.
fn has_mint_or_burn(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Call(call) = &e.kind {
                if matches!(
                    call.func_name.as_deref(),
                    Some("mint") | Some("_mint") | Some("burn") | Some("_burn") | Some("burnFrom")
                ) {
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

/// True if the function writes a state variable that is an **address** typed
/// withdrawal/treasury/recipient role — re-pointing where funds are sent.
fn reassigns_recipient_address(f: &Function, contract: &Contract) -> bool {
    f.effects
        .storage_writes
        .iter()
        .any(|w| is_recipient_role_address(contract, &w.var))
}

/// Is `var_name` a state variable on `contract` that is a scalar `address`
/// (not a mapping) whose name denotes a fund destination (treasury / recipient /
/// payout / beneficiary / collector / vault / …)?
fn is_recipient_role_address(contract: &Contract, var_name: &str) -> bool {
    let Some(sv) = contract
        .state_vars
        .iter()
        .find(|v| v.name == var_name || v.name.eq_ignore_ascii_case(var_name))
    else {
        return false;
    };
    let ty = sv.ty.trim();
    // Scalar address only — a `mapping(... => address)` write is per-key
    // bookkeeping, not a single fund-destination re-point.
    if sv.is_mapping() || !ty.starts_with("address") {
        return false;
    }
    let n = sv.name.to_ascii_lowercase();
    const ROLES: &[&str] = &[
        "treasury",
        "recipient",
        "beneficiary",
        "payee",
        "payout",
        "collector",
        "receiver",
        "withdraw",
        "feeto",
        "destination",
        "vault",
    ];
    ROLES.iter().any(|r| n.contains(r))
}

/// True if **every** value-moving call in the body provably routes to / from the
/// caller (`msg.sender`). Such a function lets the admin move funds only to
/// itself, which is not a rug of *user* funds, so it is suppressed.
///
/// Conservative: returns false (i.e. does NOT suppress) unless we positively see
/// at least one value-moving call and all of them are caller-pinned.
fn all_value_moves_are_caller_own(f: &Function) -> bool {
    let mut saw_move = false;
    let mut all_caller = true;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            let ExprKind::Call(call) = &e.kind else { return };

            // Native-ETH sends: `recipient.transfer(x)` / `.send(x)` /
            // `recipient.call{value:x}(...)`. The recipient is the call receiver.
            if matches!(call.kind, CallKind::Transfer | CallKind::Send)
                || (call.kind == CallKind::LowLevelCall && call.value.is_some())
            {
                saw_move = true;
                let to_caller = call
                    .receiver
                    .as_deref()
                    .map(|r| mentions_msg_sender(r))
                    .unwrap_or(false);
                if !to_caller {
                    all_caller = false;
                }
                return;
            }

            // ERC-20 moves. The amount is always the **last** argument, the
            // recipient `to` is the **second-to-last**, and for the `*From`
            // family the source `from` is the argument before `to`. Indexing
            // from the end is robust to *both* call shapes:
            //   member form        `token.transfer(to, amt)`         to=arg[-2]
            //   library form  `SafeERC20.safeTransfer(token, to, amt)` to=arg[-2]
            // which the old fixed-index logic got wrong for the member form
            // (it read arg1 as `to`, so `wsOHM.safeTransfer(msg.sender, bal)`
            // looked non-caller-own and leaked a self-pull as a "rug").
            let (is_plain, is_from) = match call.func_name.as_deref() {
                Some("transfer") => (true, false),
                Some("transferFrom") => (true, true),
                Some("safeTransfer") => (false, false),
                Some("safeTransferFrom") => (false, true),
                _ => return,
            };
            // `transfer`/`transferFrom` only count as token moves when
            // external/internal (a `payable(x).transfer(v)` ETH send is a
            // `Transfer` kind, handled above).
            if is_plain && !matches!(call.kind, CallKind::External | CallKind::Internal) {
                return;
            }
            let n = call.args.len();
            if n < 2 {
                return;
            }
            saw_move = true;
            // Destination `to` = second-to-last arg.
            let to_caller = arg_is_msg_sender(&call.args, n - 2);
            // For the `*From` family the funds originate at `from` = arg before
            // `to`; "caller's own" requires that source to be the caller too.
            let from_caller = !is_from || (n >= 3 && arg_is_msg_sender(&call.args, n - 3));
            if !(to_caller && from_caller) {
                all_caller = false;
            }
        });
    }
    saw_move && all_caller
}

/// True if the body contains at least one value-moving call whose **destination**
/// is a caller-chosen value — an identifier matching one of the function's
/// parameters (e.g. `transfer(to, amt)` where `to` is a parameter). This is the
/// signal that an admin can direct funds to an arbitrary address (the rug shape),
/// as opposed to a fixed/preset recipient.
fn has_caller_chosen_value_move(f: &Function) -> bool {
    let params = param_names(f);
    if params.is_empty() {
        return false;
    }
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            let ExprKind::Call(call) = &e.kind else { return };
            if let Some(dest) = value_move_dest(call) {
                if let Some(name) = ident_name(unwrap_casts(dest)) {
                    if params.iter().any(|&p| p == name) {
                        found = true;
                    }
                }
            }
        });
        if found {
            break;
        }
    }
    found
}

/// The destination ("to") expression of a value-moving call, if this call moves
/// value. ETH sends route to the receiver. For the ERC-20 transfer / mint family
/// the recipient `to` is, in **every** call shape, the *second-to-last* argument
/// (the amount is always last) — which makes this robust to both the member form
/// (`token.transfer(to, amt)` → `to` is arg0) and the explicit library form
/// (`SafeERC20.safeTransfer(token, to, amt)` → `to` is arg1) without guessing
/// fixed indices.
fn value_move_dest(call: &sluice_ir::Call) -> Option<&Expr> {
    if matches!(call.kind, CallKind::Transfer | CallKind::Send)
        || (call.kind == CallKind::LowLevelCall && call.value.is_some())
    {
        return call.receiver.as_deref();
    }
    let is_transfer_family = matches!(
        call.func_name.as_deref(),
        Some("transfer") | Some("transferFrom") | Some("safeTransfer") | Some("safeTransferFrom")
            | Some("mint") | Some("_mint")
    );
    if !is_transfer_family {
        return None;
    }
    // `transfer`/`transferFrom` only count as token moves when external/internal
    // (a `payable(x).transfer(v)` ETH send is a `Transfer` kind, handled above).
    if matches!(call.func_name.as_deref(), Some("transfer") | Some("transferFrom"))
        && !matches!(call.kind, CallKind::External | CallKind::Internal)
    {
        return None;
    }
    // Second-to-last argument = the recipient (amount is last). Needs >= 2 args.
    let n = call.args.len();
    if n >= 2 {
        call.args.get(n - 2)
    } else {
        None
    }
}

/// A bounded scalar setter: a state-mutating function that sets a numeric
/// (`uintN`/`intN`) parameter into scalar state and guards it with an explicit
/// ordering cap (`require(x <= MAX)` / `if (x > MAX) revert`). Such a setter
/// cannot push the parameter to an abusive value, so it is not a meaningful
/// centralization lever and is suppressed.
fn is_bounded_scalar_setter(f: &Function, contract: &Contract) -> bool {
    // Must take a numeric parameter to bound, and must not take/route an address
    // (an address setter is a routing concern, not a bounded scalar).
    if !has_numeric_param(f) || has_address_param(f) {
        return false;
    }
    // Must not write an address-typed state variable (that would be a re-point,
    // handled as a fund-flow elsewhere).
    if f.effects
        .storage_writes
        .iter()
        .any(|w| writes_address_var(contract, &w.var))
    {
        return false;
    }
    has_ordering_bound(f)
}

/// The function body contains an ordering comparison (`<`, `<=`, `>`, `>=`)
/// against a non-zero operand — the structural shape of a cap / bound check
/// (`require(x <= MAX)`, `if (x > MAX) revert`). A bare `x > 0` sign check does
/// not count.
fn has_ordering_bound(f: &Function) -> bool {
    let mut bounded = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if bounded {
                return;
            }
            if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
                if op.is_ordering() && !is_zero_literal(lhs) && !is_zero_literal(rhs) {
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

fn is_zero_literal(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(sluice_ir::Lit::Number(n)) | ExprKind::Lit(sluice_ir::Lit::HexNumber(n)) => {
            let t = n.trim();
            t == "0" || t == "0x0" || t == "0x00" || t.trim_start_matches('0').is_empty()
        }
        _ => false,
    }
}

/// Distinct, non-empty parameter names of the function.
fn param_names(f: &Function) -> Vec<&str> {
    f.params.iter().filter_map(|p| p.name.as_deref()).collect()
}

fn has_numeric_param(f: &Function) -> bool {
    f.params.iter().any(|p| {
        let t = p.ty.trim();
        t.starts_with("uint") || t.starts_with("int")
    })
}

fn has_address_param(f: &Function) -> bool {
    f.params.iter().any(|p| p.ty.trim().starts_with("address"))
}

fn writes_address_var(contract: &Contract, var_name: &str) -> bool {
    contract
        .state_vars
        .iter()
        .find(|v| v.name == var_name || v.name.eq_ignore_ascii_case(var_name))
        .map(|sv| !sv.is_mapping() && sv.ty.trim().starts_with("address"))
        .unwrap_or(false)
}

/// The bare identifier name of an expression, if it is one (`to` from `to`,
/// `payable(to)`, `address(to)` after cast-stripping).
fn ident_name(e: &Expr) -> Option<&str> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.as_str()),
        _ => None,
    }
}

/// The argument at `idx` (after stripping `address(...)`/`payable(...)` casts) is
/// `msg.sender`.
fn arg_is_msg_sender(args: &[Expr], idx: usize) -> bool {
    args.get(idx).map(|a| mentions_msg_sender(unwrap_casts(a))).unwrap_or(false)
}

/// `msg.sender` (best-effort, after cast-stripping).
fn mentions_msg_sender(e: &Expr) -> bool {
    let e = unwrap_casts(e);
    e.mentions_member("msg", "sender")
}

/// Peel single-argument type casts (`address(x)`, `payable(x)`, `IERC20(x)`).
fn unwrap_casts(e: &Expr) -> &Expr {
    let mut cur = e;
    loop {
        match &cur.kind {
            ExprKind::Call(c) if c.kind == CallKind::TypeCast && c.args.len() == 1 => {
                cur = &c.args[0];
            }
            _ => return cur,
        }
    }
}

/// Does the contract evidence a timelock / governance delay? Conservative on the
/// side of *suppression*: any plausible timelock signal silences the finding.
/// Mirrors the suppression used by the governance-timelock detector.
fn contract_has_timelock(cx: &AnalysisContext, contract: &Contract) -> bool {
    // The contract *is* (or inherits) a timelock / governor — the delay is its
    // purpose.
    if contract.inherits_like("timelock")
        || contract.inherits_like("timelockcontroller")
        || contract.inherits_like("governor")
    {
        return true;
    }
    let src = cx.source_text(contract.span); // comment-stripped (a `// no timelock` comment must not suppress)
    // Direct vocabulary used by timelock implementations / bases.
    if src.contains("timelock") || src.contains("mindelay") {
        return true;
    }
    // A delay/eta value combined with a queue→execute two-step is the structural
    // shape of a timelock (queue now, execute after the delay elapses).
    let has_delay_word = src.contains("delay") || src.contains("eta");
    let has_two_step = (src.contains("queue") || src.contains("queued"))
        && (src.contains("execute") || src.contains("pending"));
    has_delay_word && has_two_step
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    fn central(fs: &[sluice_findings::Finding]) -> Vec<&sluice_findings::Finding> {
        fs.iter().filter(|f| f.detector == "centralization-risk").collect()
    }

    // Vulnerable: an `onlyOwner` rescue that sends arbitrary tokens to an
    // admin-chosen address, with no timelock anywhere — the admin can drain user
    // funds in a single tx (admin-can-rug centralization risk).
    const VULN: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract Vault {
            address public owner;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }

            // users deposit funds here (held by the contract)
            function deposit() external payable {}

            // admin can sweep any token to any address — no timelock
            function rescueTokens(address token, address to, uint256 amt) external onlyOwner {
                IERC20(token).transfer(to, amt);
            }
        }
    "#;

    // Safe: the same kind of admin sweep, but the contract routes privileged
    // changes through a timelock (minDelay / queue→execute), so users have an
    // exit window — not a silent rug.
    const SAFE: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract TimelockedVault {
            address public owner;
            uint256 public minDelay = 2 days;
            mapping(bytes32 => uint256) public queuedEta;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }

            function deposit() external payable {}

            function queueRescue(address token, address to, uint256 amt) external onlyOwner {
                bytes32 id = keccak256(abi.encode(token, to, amt));
                queuedEta[id] = block.timestamp + minDelay;
            }

            function executeRescue(address token, address to, uint256 amt) external onlyOwner {
                bytes32 id = keccak256(abi.encode(token, to, amt));
                require(queuedEta[id] != 0 && block.timestamp >= queuedEta[id], "timelock");
                IERC20(token).transfer(to, amt);
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "centralization-risk"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "centralization-risk"));
    }

    // The VULN rescue, being a caller-chosen-destination sweep, must keep the
    // STRONG title (not be down-ranked to the rescue/Info tier).
    #[test]
    fn vuln_keeps_strong_title() {
        let fs = run(VULN);
        let c = central(&fs);
        assert!(
            c.iter().any(|f| f.title.contains("move/re-route user funds")),
            "{:?}",
            c
        );
    }

    // ---- Regression: false positives that must now be softened or silenced ----

    // Bounded scalar setter: `setFeeToDaoPercent(uint256) onlyOwner`, capped by a
    // `require(x <= MAX)`, moves no funds. Must NOT carry the strong fund-reroute
    // title; here it is suppressed entirely (softer-or-silent satisfied).
    const BOUNDED_SETTER: &str = r#"
        pragma solidity ^0.8.0;
        contract Fees {
            address public owner;
            uint256 public feeToDaoPercent;
            uint256 public constant MAX_BPS = 10_000;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }

            function setFeeToDaoPercent(uint256 p) external onlyOwner {
                require(p <= MAX_BPS, "too high");
                feeToDaoPercent = p;
            }
        }
    "#;

    #[test]
    fn bounded_fee_setter_softened_or_silent() {
        let fs = run(BOUNDED_SETTER);
        let c = central(&fs);
        // Never the strong fund-reroute claim on a bounded, fund-less scalar set.
        assert!(
            !c.iter().any(|f| f.title.contains("move/re-route user funds")),
            "{:?}",
            c
        );
        // This particular shape (bounded uintN cap) is suppressed entirely.
        assert!(c.is_empty(), "bounded scalar setter should be silent: {:?}", c);
    }

    // An *unbounded* fee setter (no cap) should still be softened — reported, but
    // only as the soft "parameter setter" tier, never the strong fund-reroute
    // title. Guards against over-suppression.
    const UNBOUNDED_SETTER: &str = r#"
        pragma solidity ^0.8.0;
        contract Fees {
            address public owner;
            uint256 public protocolFee;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }

            function setProtocolFee(uint256 p) external onlyOwner {
                protocolFee = p;
            }
        }
    "#;

    #[test]
    fn unbounded_fee_setter_is_soft_not_strong() {
        let fs = run(UNBOUNDED_SETTER);
        let c = central(&fs);
        assert!(!c.is_empty(), "unbounded setter should still be reported (soft)");
        assert!(
            c.iter().all(|f| !f.title.contains("move/re-route user funds")),
            "unbounded fee setter must not carry the strong title: {:?}",
            c
        );
        assert!(
            c.iter().any(|f| f.title == "Privileged parameter setter (no timelock)"),
            "expected the soft setter title: {:?}",
            c
        );
    }

    // Recovery to a PRESET recipient: `recoverERC20(addr, amt) onlyRole` that
    // forwards to a fixed treasury address (not a caller-supplied destination).
    // This is a token-rescue, not a rug → must be softened/Info, never strong.
    // (`onlyRole` classifies as a msg.sender access-control guard by name.)
    const RECOVER_PRESET: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract Recoverable {
            address public owner;
            address public treasury;
            modifier onlyRole(bytes32 r) { require(msg.sender == owner, "no"); _; }

            // recovers stranded tokens to a fixed, preset treasury (not a param)
            function recoverERC20(address token, uint256 amt) external onlyRole(0x0) {
                IERC20(token).transfer(treasury, amt);
            }
        }
    "#;

    #[test]
    fn recover_to_preset_recipient_softened() {
        let fs = run(RECOVER_PRESET);
        let c = central(&fs);
        // Must not over-claim a fund reroute on a fixed-recipient rescue.
        assert!(
            c.iter().all(|f| !f.title.contains("move/re-route user funds")),
            "preset-recipient rescue must not be strong: {:?}",
            c
        );
        // Either silent or the Info-tier rescue note — both acceptable.
        assert!(
            c.iter().all(|f| f.severity == sluice_findings::Severity::Info),
            "any finding here must be Info-tier (token-rescue): {:?}",
            c
        );
    }

    // Positive: a real `onlyOwner withdrawTo(address to, uint256 amt)` that does
    // `token.transfer(to, amt)` with a caller-chosen `to`. Even though the name
    // contains "withdraw", this is a targeted admin transfer to an arbitrary
    // address and MUST still fire with the strong title.
    const WITHDRAW_TO: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract Treasury {
            address public owner;
            IERC20 public token;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }

            function withdrawTo(address to, uint256 amt) external onlyOwner {
                token.transfer(to, amt);
            }
        }
    "#;

    #[test]
    fn fires_strong_on_withdraw_to() {
        let fs = run(WITHDRAW_TO);
        let c = central(&fs);
        assert!(
            c.iter().any(|f| f.title.contains("move/re-route user funds")),
            "withdrawTo(to, amt) must fire with the strong title: {:?}",
            c
        );
    }

    // Positive: a real `onlyOwner setTreasury(address)` that reassigns the
    // treasury *address* state var — a fund re-point, strong title.
    const SET_TREASURY: &str = r#"
        pragma solidity ^0.8.0;
        contract Protocol {
            address public owner;
            address public treasury;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }

            function setTreasury(address t) external onlyOwner {
                treasury = t;
            }
        }
    "#;

    #[test]
    fn fires_strong_on_set_treasury() {
        let fs = run(SET_TREASURY);
        let c = central(&fs);
        assert!(
            c.iter().any(|f| f.title.contains("move/re-route user funds")),
            "setTreasury(address) must fire with the strong title: {:?}",
            c
        );
    }

    // ===== R6 volume/severity tuning regressions =========================

    use sluice_findings::Severity;

    /// Convenience: highest severity among the centralization findings, or None
    /// when the detector stayed silent.
    fn max_central_sev(fs: &[sluice_findings::Finding]) -> Option<Severity> {
        central(fs).iter().map(|f| f.severity).max()
    }

    // (A) Non-centralization shapes are dropped up front.

    // Bounded `setFeePercent(uint256 p) onlyOwner { require(p<=MAX); fee=p; }` —
    // the exact shape called out in the task. A capped scalar fee setter that
    // moves no funds must be silent (or, at the very most, Info) — never Low+.
    const SET_FEE_PERCENT: &str = r#"
        pragma solidity ^0.8.0;
        contract Fees {
            address public owner;
            uint256 public fee;
            uint256 public constant MAX = 1000;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
            function setFeePercent(uint256 p) external onlyOwner {
                require(p <= MAX, "too high");
                fee = p;
            }
        }
    "#;

    #[test]
    fn set_fee_percent_silent_or_info() {
        let fs = run(SET_FEE_PERCENT);
        let c = central(&fs);
        // Bounded fee/percent setter: suppressed here, and in no case above Info.
        assert!(c.is_empty(), "bounded setFeePercent must be silent: {:?}", c);
        assert!(
            max_central_sev(&fs).map_or(true, |s| s <= Severity::Info),
            "bounded setFeePercent must never exceed Info: {:?}",
            c
        );
    }

    // An `initialize()` that even seeds a treasury address (the Olympus
    // `sOlympus.initialize` shape, which uses a manual
    // `require(msg.sender == initializer)` rather than the `initializer`
    // modifier) is one-shot setup, not a standing fund lever → must be silent,
    // and in particular must NOT be mislabeled a fund mover.
    const INITIALIZE_SEEDS_TREASURY: &str = r#"
        pragma solidity ^0.8.0;
        contract Staked {
            address public initializer;
            address public stakingContract;
            address public treasury;
            constructor() { initializer = msg.sender; }
            function initialize(address _stakingContract, address _treasury) external {
                require(msg.sender == initializer, "not initializer");
                require(_stakingContract != address(0), "Staking");
                stakingContract = _stakingContract;
                require(_treasury != address(0), "Zero address: Treasury");
                treasury = _treasury;
                initializer = address(0);
            }
        }
    "#;

    #[test]
    fn initialize_is_silent() {
        let fs = run(INITIALIZE_SEEDS_TREASURY);
        let c = central(&fs);
        assert!(
            c.is_empty(),
            "initialize() (even seeding treasury) must be silent, not a fund mover: {:?}",
            c
        );
    }

    // A `view`/`pure` privileged-looking getter cannot move anything → silent.
    const VIEW_GETTER: &str = r#"
        pragma solidity ^0.8.0;
        contract V {
            address public owner;
            address public treasury;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
            function previewTreasury() external view onlyOwner returns (address) {
                return treasury;
            }
        }
    "#;

    #[test]
    fn view_function_is_silent() {
        let fs = run(VIEW_GETTER);
        assert!(central(&fs).is_empty(), "view/pure must be silent: {:?}", central(&fs));
    }

    // (B) Severity by impact.

    // Positive (exact task shape): `withdrawTo(address to, uint256 a) onlyOwner
    // { token.transfer(to, a); }` is a steerable transfer to a caller-chosen
    // address → Low or higher, strong title.
    const WITHDRAW_TO_EXACT: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract T {
            address public owner;
            IERC20 public token;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
            function withdrawTo(address to, uint256 a) external onlyOwner {
                token.transfer(to, a);
            }
        }
    "#;

    #[test]
    fn withdraw_to_is_low_or_higher() {
        let fs = run(WITHDRAW_TO_EXACT);
        let c = central(&fs);
        assert!(
            c.iter().any(|f| f.title.contains("move/re-route user funds")
                && f.severity >= Severity::Low),
            "withdrawTo(to, a) must be Low+ with the strong title: {:?}",
            c
        );
    }

    // A genuine supply move (`mint`) stays Low+: minting balances out of thin
    // air is a steerable fund-affecting power, kept meaningful.
    const MINTER: &str = r#"
        pragma solidity ^0.8.0;
        contract Token {
            address public owner;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
            function _mint(address to, uint256 a) internal {}
            function mint(address to, uint256 a) external onlyOwner { _mint(to, a); }
        }
    "#;

    #[test]
    fn mint_stays_low_or_higher() {
        let fs = run(MINTER);
        let c = central(&fs);
        assert!(
            c.iter().any(|f| f.severity >= Severity::Low
                && f.title.contains("move/re-route user funds")),
            "mint() must remain Low+ (supply move): {:?}",
            c
        );
    }

    // A fund-routing-shaped name that also moves funds is the more serious
    // configuration-reroute case → Medium.
    const MIGRATE_MOVER: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function safeTransfer(address to, uint256 a) external; }
        contract Allocator {
            address public owner;
            address public newAllocator;
            IERC20 public token;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
            function migrate() external onlyOwner {
                token.safeTransfer(newAllocator, 100);
            }
        }
    "#;

    #[test]
    fn migrate_fund_mover_is_medium() {
        let fs = run(MIGRATE_MOVER);
        let c = central(&fs);
        assert!(
            c.iter().any(|f| f.severity == Severity::Medium
                && f.title.contains("move/re-route user funds")),
            "migrate() that moves funds must be Medium: {:?}",
            c
        );
    }

    // Preset-destination fund mover: an `onlyOwner` transfer whose destination is
    // a fixed *state variable* (not a caller-chosen param), with no mint/burn and
    // no recipient-address re-point. It moves protocol funds along a hard-wired
    // path → Info (the FIXED_DEST tier), never Low+.
    const PRESET_DEST_MOVER: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function safeTransfer(address to, uint256 a) external; }
        contract Escrow {
            address public owner;
            address public counterparty;
            IERC20 public externalToken;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
            // returns the held token to a FIXED, preset counterparty (state var)
            function settle(uint256 a) external onlyOwner {
                externalToken.safeTransfer(counterparty, a);
            }
        }
    "#;

    #[test]
    fn preset_destination_mover_is_info() {
        let fs = run(PRESET_DEST_MOVER);
        let c = central(&fs);
        assert!(!c.is_empty(), "a preset-destination fund mover should still be reported");
        assert!(
            c.iter().all(|f| f.severity == Severity::Info),
            "a fund move only to a fixed/preset destination must be Info, not Low+: {:?}",
            c
        );
        assert!(
            c.iter().all(|f| !f.title.contains("move/re-route user funds")),
            "preset-destination mover must not carry the strong rug title: {:?}",
            c
        );
    }

    // An admin sweep to `msg.sender` (the caller's own funds) via the *member*
    // form `token.safeTransfer(msg.sender, bal)` must be suppressed. This is the
    // Olympus `CrossChainMigrator.replenish/clear` shape — the old fixed-arg
    // logic read arg1 as the recipient and leaked it as a "rug"; recipient =
    // second-to-last arg fixes it.
    const SWEEP_TO_SELF_MEMBER_FORM: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 {
            function safeTransfer(address to, uint256 a) external;
            function balanceOf(address who) external view returns (uint256);
        }
        contract Migrator {
            address public owner;
            IERC20 public wsOHM;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
            function replenish() external onlyOwner {
                wsOHM.safeTransfer(msg.sender, wsOHM.balanceOf(address(this)));
            }
        }
    "#;

    #[test]
    fn sweep_to_self_member_form_is_silent() {
        let fs = run(SWEEP_TO_SELF_MEMBER_FORM);
        let c = central(&fs);
        assert!(
            c.is_empty(),
            "admin sweep to msg.sender (member-form safeTransfer) is caller-own, must be silent: {:?}",
            c
        );
    }

    // An *unbounded* routing-shaped setter that moves no funds is reported, but
    // (no fund-sink) only at Info, with the soft title — never Low+.
    const UNBOUNDED_ROUTING_SETTER: &str = r#"
        pragma solidity ^0.8.0;
        contract R {
            address public owner;
            address public router;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
            // setRouter is routing-shaped but writes no recipient-role address var
            // here (the var is named `router`, not a treasury/recipient role) and
            // moves no funds, so it is the soft, fund-less, Info tier.
            function setRouterFee(uint256 f) external onlyOwner { /* no-op */ }
        }
    "#;

    #[test]
    fn unbounded_routing_setter_is_info_soft() {
        let fs = run(UNBOUNDED_ROUTING_SETTER);
        let c = central(&fs);
        assert!(!c.is_empty(), "unbounded routing setter should still be reported");
        assert!(
            c.iter().all(|f| f.severity <= Severity::Info),
            "a no-fund-move setter must never exceed Info: {:?}",
            c
        );
        assert!(
            c.iter().any(|f| f.title == "Privileged parameter setter (no timelock)"),
            "expected the soft setter title for the in-between: {:?}",
            c
        );
    }
}
