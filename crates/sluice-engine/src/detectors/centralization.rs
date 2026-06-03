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
//! Info or silent. The Medium (fund-reroute) tier is in turn reserved for a body
//! that executes a genuine **fund-movement opcode** — a token
//! `transfer`/`safeTransfer`/`transferFrom`, an ETH send, a `mint`/`burn`, or an
//! `approve` — to an **externally-supplied / steerable** destination; a pure
//! privileged setter that only reassigns configuration (an **address re-point**
//! with no transfer/mint/approve opcode) is not a fund mover and is capped at Low.
//!
//!   * **Strong** — "Privileged admin can move/re-route user funds with no
//!     timelock" — when the body contains a real fund-flow (token
//!     `transfer`/`safeTransfer`/`transferFrom`, `.call{value:}` / `.send` ETH
//!     move, `mint`/`burn`, `approve`, or a reassignment of a
//!     withdrawal/treasury/recipient **address** state variable). The severity
//!     then turns on whether the body executes a fund-movement **opcode** and how
//!     steerable it is:
//!       - **Medium** — a fund-movement opcode (`transfer`/`safeTransfer`/
//!         `transferFrom`/`mint`/`burn`/`approve`/ETH-send) to an
//!         **externally-supplied / steerable** destination: a caller-chosen
//!         (parameter) recipient (`withdrawTo(to, …)`, `Collector.transfer(token,
//!         recipient, …)`), or a `mint`/`burn` to a non-fixed-protocol account
//!         (Aave `BackingEigen.mint(to, …)`). A fund-routing-shaped setter
//!         (`set*Fee` / `setRouter` / `migrate` / `setFeeReceiver`) that *also*
//!         executes a fund-movement opcode — even to a fixed/preset destination
//!         (`Allocator.migrate` → `safeTransfer(newAllocator, …)`) — is the
//!         configuration-reroute case and is likewise **Medium**.
//!       - **Low** — a privileged setter that **re-points** a withdrawal/treasury/
//!         recipient **address** state var but executes **no** fund-movement opcode
//!         (`setFeeToSetter` reassigning the next admin, `setTreasury(address)`,
//!         the `pullVault` ownership-accept two-step). It changes where *future*
//!         funds go but moves nothing itself in this transaction, so it is a pure
//!         privileged setter — capped at Low, never the Medium fund-reroute tier.
//!   * **Suppressed — preset-destination fund mover** — a body that *does* move
//!     funds but only to a **fixed / preset / internal** destination (a state
//!     var, a constant, a per-`id` mapping entry, or a bare `approve` to a fixed
//!     spender) and is not a routing setter. It moves protocol funds along a
//!     hard-wired path rather than re-routing *user* funds to an attacker-chosen
//!     address — not an admin-can-rug risk. This was previously an Info note but
//!     is **pure noise** (the destination is hard-wired, so there is nothing for
//!     an admin to steer), so the sub-class is now suppressed entirely; the class
//!     reserves its output for the steerable-reroute tiers (Low/Medium/High).
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
//!     pins its destination/source to `msg.sender` — including a self-supply op
//!     `_burn(msg.sender, x)` / `_mint(_msgSender(), x)`) is not a rug, silenced.
//!   * **Protocol-internal plumbing** — when the access guard proves the *only*
//!     caller is a **fixed protocol contract** (an inline / modifier
//!     `require(msg.sender == X)` where `X` is `immutable` / `constant` / a
//!     contract-interface-typed state var, or an `address` whose name denotes a
//!     wired callee — `*Manager` / `*Bridge` / `staking` / `minter` / a
//!     `Predeploys.<MESSENGER>`-style constant), and there is **no** discretionary
//!     `onlyOwner` / `onlyRole` / `owner`/`admin`/governance path — a mint / burn
//!     / transfer in the body is the protocol's own machinery, not a discretionary
//!     admin who can rug (e.g. `StakingDistributor.distribute` minting to the
//!     immutable `staking`, an `OptimismMintableERC20.mint` callable only by
//!     `BRIDGE`). It is suppressed. The guard is resolved through inherited
//!     modifiers and one level of internal-helper indirection
//!     (`modifier onlyVault { _onlyVault(); _; }`). **Exception:** a body that
//!     *re-points* a withdrawal/treasury/recipient **address** state var is a
//!     genuine fund-routing change regardless of caller (an ownership-accept
//!     two-step such as `pullVault` reassigning `vault`), so it still fires.
//!   * A mint / burn whose recipient is a **fixed protocol destination**
//!     (`msg.sender`, `address(this)`, or a `constant`/`immutable` var) is not an
//!     attacker-steerable supply move (mint-to-protocol/self is not a user-fund
//!     flow), so it does not by itself earn the Low tier.
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
                    // Protocol-internal rescue: callable only by a fixed protocol
                    // contract (not a discretionary admin), so even a caller-chosen
                    // destination is chosen by that wired contract, not an admin
                    // who can rug — suppress (mirrors the fund-flow arm below).
                    if guard_pins_to_fixed_protocol_contract(cx, f, contract) {
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
                // that can only move funds *to itself* is not rugging users. This
                // also covers a supply op on the caller's own balance
                // (`_burn(msg.sender, x)` in a `cooldown`/`unstake`), which is a
                // user operation, not an admin fund-move.
                if all_value_moves_are_caller_own(f) {
                    continue;
                }
                // Protocol-internal plumbing: the access guard pins `msg.sender` to
                // a **fixed protocol contract** (an inline / modifier
                // `require(msg.sender == <immutable | constant | contract-typed |
                // *Manager/*Bridge/staking-style> var)`), and there is no
                // discretionary-admin (`onlyOwner` / `onlyRole` / `owner` / `admin`
                // / governance) path. The *only* caller is that one wired contract,
                // so a mint/burn or transfer here is the protocol's own machinery
                // (e.g. `StakingDistributor.distribute` minting to `staking`, an
                // `OptimismMintableERC20.mint` callable only by `BRIDGE`, an Aave
                // `AToken.transferUnderlyingTo` callable only by the immutable
                // `POOL`), not a discretionary admin who can rug users — suppress.
                // (Checked before the tiering arms so protocol plumbing never lands
                // in the Medium fund-movement tier.)
                //
                // Exception: a body that **re-points** a withdrawal/treasury/
                // recipient *address* state var is a genuine fund-routing change
                // regardless of who triggers it (an ownership-accept two-step such
                // as `OlympusAuthority.pullVault` reassigns `vault`), so it still
                // falls through to the steerable tier below.
                if guard_pins_to_fixed_protocol_contract(cx, f, contract)
                    && !reassigns_recipient_address(f, contract)
                {
                    continue;
                }

                // Does the body actually execute a **fund-movement opcode** — a
                // token `transfer`/`safeTransfer`/`transferFrom`, an ETH send, a
                // `mint`/`burn`, or an `approve`? This is the genuine-fund-movement
                // gate that separates the Medium (fund-reroute) tier from a pure
                // privileged setter. A body whose *only* fund-flow signal is a
                // recipient-**address re-point** (a state-var write, no transfer /
                // mint / approve) is a privileged setter, not a fund mover.
                let has_opcode = has_fund_movement_opcode(f);
                // Is that movement **steerable** — directed somewhere an attacker
                // would care about: a caller-chosen (externally-supplied) destination
                // (`withdrawTo(to, …)` / `mint(to, …)`), or a `mint`/`burn` to a
                // non-fixed-protocol account (creates/destroys balances at an
                // attacker-relevant address)?
                let steerable = has_caller_chosen_value_move(f) || mint_or_burn_is_steerable(f, contract);

                // (1) Genuine fund movement to an externally-supplied / steerable
                //     destination → Medium. This is the real fund-reroute the class
                //     is for: a `transfer`/`safeTransfer`/`transferFrom`/`mint`/
                //     `approve` opcode whose destination an admin can steer to an
                //     attacker-relevant address (Aave `BackingEigen.mint(to, …)`,
                //     `Collector.transfer(token, recipient, …)`, an
                //     `emergencyTokenTransfer(token, to, …)`). Reserving Medium for
                //     an actual fund-movement opcode is what keeps a pure admin
                //     setter (no opcode) out of the Medium tier.
                if has_opcode && steerable {
                    out.push(self.finding(
                        cx,
                        f,
                        STRONG_TITLE,
                        Severity::Medium,
                        strong_msg(&contract.name, &f.name),
                    ));
                    continue;
                }
                // (2) A fund-routing-shaped name (`set*Fee` / `setRouter` / `migrate`
                //     / `setFeeReceiver`) that *also* executes a fund-movement opcode
                //     — even to a fixed/preset destination — is the configuration-
                //     reroute case → Medium, strong title (e.g. `Allocator.migrate`
                //     transferring held funds to `newAllocator`). The opcode
                //     requirement is what now excludes a pure address-re-pointing
                //     setter (`setFeeToSetter` / `setFeeTo`, body `feeTo = x;` with
                //     no transfer/mint) from this Medium arm; such a setter falls
                //     through to the Low tier below.
                if is_fund_routing_setter(&f.name) && has_opcode {
                    out.push(self.finding(
                        cx,
                        f,
                        STRONG_TITLE,
                        Severity::Medium,
                        strong_msg(&contract.name, &f.name),
                    ));
                    continue;
                }
                // (3) A privileged change that **re-points** a withdrawal / treasury
                //     / recipient **address** state var but executes no fund-movement
                //     opcode is a pure privileged setter — it redirects where *future*
                //     funds go, but moves nothing itself in this transaction. Per the
                //     tiering, a setter with no fund-movement opcode is at most Low
                //     (the `setFeeToSetter` / `setTreasury` / `pullVault` shape).
                if reassigns_recipient_address(f, contract) {
                    out.push(self.finding(
                        cx,
                        f,
                        STRONG_TITLE,
                        Severity::Low,
                        strong_msg(&contract.name, &f.name),
                    ));
                    continue;
                }
                // (4) A steerable fund movement that is not caught above (defensive:
                //     e.g. a caller-chosen move our opcode scan could not positively
                //     confirm) → Low, strong title.
                if steerable {
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
                // re-routing user funds to an attacker-chosen address — the
                // detector's own message classed it "a preset destination — not an
                // admin-can-rug risk — informational". That preset-destination Info
                // sub-class is pure noise (it flags a hard-wired internal flow, not
                // a discretionary admin who can rug), so it is **suppressed
                // entirely**: this class now reserves its output for the
                // steerable-reroute tiers (Low/Medium/High). The kept tiers above
                // (caller-chosen move, steerable mint/burn, recipient-address
                // re-point, routing-setter-that-moves-funds) are unaffected.
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

// (The former `fixed_dest_msg` / FIXED_DEST_TITLE preset-destination Info
// sub-class was removed: that tier is now suppressed entirely — see the
// fund-flow arm in `run`.)

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

/// True if the function body executes a real **fund-movement opcode**: a token
/// `transfer`/`transferFrom`/`safeTransfer`/`safeTransferFrom`, a native-ETH send
/// (`.transfer`/`.send`/`.call{value:}`), a `mint`/`burn`, or an `approve`. This
/// is the subset of [`has_fund_flow`] that *moves value in this transaction* — it
/// deliberately **excludes** a bare recipient-**address re-point** (a state-var
/// write). It is the gate for the Medium fund-reroute tier: a privileged setter
/// that merely reassigns an address (`setFeeToSetter` / `setFeeTo`, body `feeTo =
/// x;`) executes no opcode and so is not a fund mover.
fn has_fund_movement_opcode(f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            let ExprKind::Call(call) = &e.kind else { return };
            // Native-ETH send.
            if matches!(call.kind, CallKind::Transfer | CallKind::Send)
                || (call.kind == CallKind::LowLevelCall && call.value.is_some())
            {
                found = true;
                return;
            }
            match call.func_name.as_deref() {
                Some("transfer") | Some("transferFrom")
                    if matches!(call.kind, CallKind::External | CallKind::Internal) =>
                {
                    found = true;
                }
                Some("safeTransfer") | Some("safeTransferFrom") => found = true,
                Some("mint") | Some("_mint") | Some("burn") | Some("_burn") | Some("burnFrom") => {
                    found = true
                }
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

/// True if the body contains a `mint`/`burn` call whose account is **steerable** —
/// i.e. a supply move that creates or destroys balances at a destination an
/// attacker would care about, rather than along a hard-wired protocol path. A
/// supply op is *not* steerable when its account (the first argument) is a fixed
/// protocol destination: `msg.sender` (the caller's own balance), `address(this)`
/// / `this` (self), or a `constant`/`immutable` state variable (a hard-wired
/// protocol address that can never be repointed). This implements the
/// "mint-to-protocol/self is not a user-fund-flow" reclassification — e.g.
/// `treasury.mint(staking, …)` where `staking` is immutable is protocol issuance
/// along a fixed path, not an admin minting to an arbitrary recipient.
fn mint_or_burn_is_steerable(f: &Function, contract: &Contract) -> bool {
    let mut steerable = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if steerable {
                return;
            }
            let ExprKind::Call(call) = &e.kind else { return };
            if !matches!(
                call.func_name.as_deref(),
                Some("mint") | Some("_mint") | Some("burn") | Some("_burn") | Some("burnFrom")
            ) {
                return;
            }
            // Account = first argument (`(account, amount)`). Absent ⇒ can't prove
            // a fixed destination, so treat as steerable (conservative: keep firing).
            let Some(account) = call.args.first() else {
                steerable = true;
                return;
            };
            if !dest_is_fixed_protocol(account, contract) {
                steerable = true;
            }
        });
        if steerable {
            break;
        }
    }
    steerable
}

/// Is `dest` a **fixed protocol destination** for a fund move — one that an admin
/// cannot steer to an attacker-relevant address? True for `msg.sender` (caller's
/// own), `address(this)` / `this` (self), or a `constant`/`immutable` state
/// variable of `contract` (a hard-wired address). Casts are peeled first.
fn dest_is_fixed_protocol(dest: &Expr, contract: &Contract) -> bool {
    let d = unwrap_casts(dest);
    if mentions_msg_sender(d) || is_this(d) {
        return true;
    }
    if let Some(name) = ident_name(d) {
        return contract
            .state_vars
            .iter()
            .any(|v| v.name == name && (v.constant || v.immutable));
    }
    false
}

/// `this` / `address(this)` (after cast-stripping).
fn is_this(e: &Expr) -> bool {
    matches!(&unwrap_casts(e).kind, ExprKind::Ident(n) if n == "this")
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

// -------------------------------------------- fixed-protocol-contract guard

/// What a `msg.sender == X` access guard pins the caller to.
#[derive(Clone, Copy, PartialEq)]
enum GuardTarget {
    /// A **fixed protocol contract**: a `constant`/`immutable` address, a
    /// contract/interface-typed state var, or an `address`-typed state var whose
    /// name denotes a wired callee (`*Manager`, `*Bridge`, `staking`, `minter`,
    /// …). The *only* caller is that one wired contract.
    FixedContract,
    /// A **discretionary admin / role holder**: `owner` / `admin` / `governor` /
    /// `governance` / `guardian` / `authority`, or a role-based check
    /// (`onlyRole` / `hasRole`). A human key can call.
    DiscretionaryAdmin,
    /// Could not classify (an unrecognized var, a `mapping`/whitelist check, a
    /// complex condition). Neither suppresses nor blocks suppression.
    Other,
}

/// True if `f`'s access control proves the **only** caller is a fixed protocol
/// contract: there is at least one `msg.sender == <fixed-contract var>` guard
/// (inline or via a modifier) AND no discretionary-admin / role guard. Such a
/// function is protocol-internal plumbing (only that one wired contract can call
/// it), not a discretionary admin who can rug users.
///
/// Resolves both guard shapes:
///   * **inline** — a leading `require(msg.sender == X)` / `if (msg.sender != X)
///     revert` in the body; and
///   * **modifier** — a `MsgSenderCheck`-classified modifier (`onlyStakingManager`,
///     `onlyVault`, …) whose body, resolved within the same contract, contains the
///     `require(msg.sender == X)`.
fn guard_pins_to_fixed_protocol_contract(
    cx: &AnalysisContext,
    f: &Function,
    contract: &Contract,
) -> bool {
    let mut saw_fixed = false;
    let mut classify = |t: GuardTarget| -> bool {
        // Returns true to short-circuit (a blocker was seen).
        match t {
            GuardTarget::DiscretionaryAdmin => true,
            GuardTarget::FixedContract => {
                saw_fixed = true;
                false
            }
            GuardTarget::Other => false,
        }
    };

    // Inline guards in the function body: `require(msg.sender == X)` /
    // `if (msg.sender != X) revert`.
    for cond in inline_sender_guard_conds(f) {
        if classify(classify_sender_guard(&cond, contract)) {
            return false;
        }
    }

    // Modifier guards: resolve each access-control modifier's body (same contract)
    // and read its `require(msg.sender == X)`. A modifier we cannot resolve to a
    // body but whose *name* is unmistakably a discretionary admin/role guard
    // (`onlyOwner`, `onlyRole`, …) is a blocker; otherwise it is `Other`.
    for m in &f.modifiers {
        if !modifier_is_access_control(&m.name) {
            continue;
        }
        match resolve_modifier_guard_target(cx, f, contract, &m.name) {
            Some(t) => {
                if classify(t) {
                    return false;
                }
            }
            None => {
                if modifier_name_is_discretionary(&m.name) {
                    return false;
                }
            }
        }
    }

    saw_fixed
}

/// The conditions of inline `msg.sender`-comparing guards in a function body:
/// `require(msg.sender == X)` / `require(msg.sender != X)` and
/// `if (msg.sender (==|!=) X) revert/return`. Only leading guards matter for
/// access control, but scanning the whole body is harmless (a non-leading
/// `msg.sender ==` check is rare and still informative).
fn inline_sender_guard_conds(f: &Function) -> Vec<Expr> {
    let mut conds = Vec::new();
    for s in &f.body {
        s.visit(&mut |st| match &st.kind {
            sluice_ir::StmtKind::Expr(e) => {
                if let ExprKind::Call(c) = &e.kind {
                    if matches!(
                        c.kind,
                        CallKind::Builtin(sluice_ir::Builtin::Require)
                            | CallKind::Builtin(sluice_ir::Builtin::Assert)
                    ) {
                        if let Some(arg) = c.args.first() {
                            if expr_mentions_msg_sender(arg) {
                                conds.push(arg.clone());
                            }
                        }
                    }
                }
            }
            sluice_ir::StmtKind::If { cond, .. } if expr_mentions_msg_sender(cond) => {
                conds.push(cond.clone());
            }
            _ => {}
        });
    }
    conds
}

/// Classify a `msg.sender`-comparing guard condition by the variable it pins the
/// caller to. Finds an equality/inequality `msg.sender (==|!=) X` inside `cond`
/// and classifies `X`. A role check (`hasRole(...)` / `onlyRole`) anywhere in the
/// condition is a discretionary-admin guard.
fn classify_sender_guard(cond: &Expr, contract: &Contract) -> GuardTarget {
    // A role lookup anywhere in the condition ⇒ discretionary (role-gated).
    let mut role_based = false;
    cond.visit(&mut |e| {
        if let ExprKind::Call(c) = &e.kind {
            if let Some(n) = call_callee_name(c) {
                let l = n.to_ascii_lowercase();
                if l.contains("hasrole") || l == "checkrole" || l == "_checkrole" {
                    role_based = true;
                }
            }
        }
    });
    if role_based {
        return GuardTarget::DiscretionaryAdmin;
    }
    match sender_eq_target_name(cond) {
        Some(name) => classify_guard_target_name(&name, contract),
        None => GuardTarget::Other,
    }
}

/// Find the identifier compared for (in)equality against `msg.sender` in `cond`.
/// Handles either operand order and peels `address(...)` / `payable(...)` casts:
/// `msg.sender == staking` / `staking != msg.sender` / `msg.sender == owner()`.
fn sender_eq_target_name(cond: &Expr) -> Option<String> {
    let mut found: Option<String> = None;
    cond.visit(&mut |e| {
        if found.is_some() {
            return;
        }
        if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
            if !matches!(op, sluice_ir::BinOp::Eq | sluice_ir::BinOp::Ne) {
                return;
            }
            let l = unwrap_casts(lhs);
            let r = unwrap_casts(rhs);
            let (other, sender_side) = if mentions_msg_sender(l) {
                (r, true)
            } else if mentions_msg_sender(r) {
                (l, true)
            } else {
                (r, false)
            };
            if !sender_side {
                return;
            }
            // The other side is the pinned target. Resolve it to a name across the
            // shapes a guard target takes:
            //   * a bare identifier (`staking`);
            //   * a getter call (`owner()` / `authority.governor()`);
            //   * a member access (a predeploy / library constant
            //     `Predeploys.L2_TO_L2_CROSS_DOMAIN_MESSENGER`), classified by the
            //     trailing member name.
            if let Some(n) = ident_name(other) {
                found = Some(n.to_string());
            } else if let ExprKind::Call(c) = &other.kind {
                if let Some(n) = call_callee_name(c) {
                    found = Some(n.to_string());
                }
            } else if let ExprKind::Member { member, .. } = &other.kind {
                found = Some(member.to_string());
            }
        }
    });
    found
}

/// Classify a guard-target *name* (a state var, or a getter like `owner`) as a
/// fixed protocol contract vs a discretionary admin.
fn classify_guard_target_name(name: &str, contract: &Contract) -> GuardTarget {
    let l = name.to_ascii_lowercase();
    // Discretionary admin / human role holders — these are real admin levers, keep
    // firing. Checked first so an `owner`/`governor`-named var never counts fixed.
    if is_discretionary_admin_name(&l) {
        return GuardTarget::DiscretionaryAdmin;
    }
    // A `constant`/`immutable` or contract/interface-typed state var is, by its
    // declaration, a hard-wired protocol address — a fixed callee.
    if let Some(sv) = contract.state_vars.iter().find(|v| v.name == name) {
        if sv.constant || sv.immutable {
            return GuardTarget::FixedContract;
        }
        let ty = sv.ty.trim();
        if is_contract_typed(ty) {
            return GuardTarget::FixedContract;
        }
        // A settable `address` whose *name* denotes a wired callee contract.
        if ty.starts_with("address") && is_fixed_contract_name(&l) {
            return GuardTarget::FixedContract;
        }
        return GuardTarget::Other;
    }
    // Not a known state var (e.g. an inherited getter): fall back to the name.
    if is_fixed_contract_name(&l) {
        GuardTarget::FixedContract
    } else {
        GuardTarget::Other
    }
}

/// A textual type that is a contract/interface reference (not a Solidity value
/// type / mapping / array). Used to recognize `IStaking staking` as a fixed
/// protocol-contract reference.
fn is_contract_typed(ty: &str) -> bool {
    let t = ty.trim();
    // Strip a trailing storage location / array / payable marker for the prefix
    // test (we only need the leading type word).
    const VALUE_PREFIXES: &[&str] = &[
        "address", "uint", "int", "bool", "bytes", "string", "mapping", "enum", "fixed", "ufixed",
    ];
    if VALUE_PREFIXES.iter().any(|p| t.starts_with(p)) {
        return false;
    }
    // Arrays / tuples are not a single contract handle.
    if t.contains('[') || t.starts_with('(') {
        return false;
    }
    // A leading identifier char ⇒ a named (contract/interface/struct) type. We
    // accept struct-typed too (rare as a guard target); the surrounding guard
    // shape `msg.sender == X` makes a non-address X implausible unless it is a
    // contract handle.
    t.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
}

/// Discretionary-admin / human-role variable names — a guard pinning to one of
/// these is a genuine admin lever, never suppressed.
fn is_discretionary_admin_name(l: &str) -> bool {
    const ADMIN: &[&str] = &[
        "owner",
        "admin",
        "governor",
        "governance",
        "guardian",
        "authority",
        "dao",
        "multisig",
        "council",
        "committee",
        "timelock",
        "sudo",
        "deployer",
        "team",
    ];
    ADMIN.iter().any(|a| l.contains(a))
}

/// `address`-typed variable names that denote a **wired protocol callee contract**
/// (not a human admin). A guard pinning to one of these means "only this specific
/// protocol contract may call" — protocol plumbing.
fn is_fixed_contract_name(l: &str) -> bool {
    // The `*Address` / `*Contract` suffix convention (`stakingManagerAddress`,
    // `mintingContract`) is a strong contract signal on its own.
    if l.ends_with("address") || l.ends_with("contract") {
        return true;
    }
    const CONTRACT_ROLES: &[&str] = &[
        "staking",
        "minter",
        "bridge",
        "manager",
        "controller",
        "hub",
        "endpoint",
        "gateway",
        "router",
        "distributor",
        "module",
        "factory",
        "pool",
        "vault",
        "escrow",
        "relayer",
        "messenger",
        "portal",
        "inbox",
        "outbox",
        "silo",
        "migrator",
        "allocator",
        "approved", // the "approved" minter role (`onlyApproved` mint/burn gate)
    ];
    if CONTRACT_ROLES.iter().any(|r| l.contains(r)) {
        return true;
    }
    // Short, ambiguous tokens matched only as a whole word (an exact name, or a
    // `_`/case-delimited segment) to avoid spurious substring hits (`yt` must not
    // match `payToken`/`cryptoVault`). `yt` = a Pendle YieldToken handle (`onlyYT`).
    const EXACT: &[&str] = &["yt"];
    EXACT.iter().any(|t| l == *t || l == format!("_{t}"))
}

/// Does a modifier name classify as a `msg.sender` access-control guard? Mirrors
/// `sluice_parse::classify_modifier`'s `MsgSenderCheck` arm so we only inspect the
/// modifiers that actually gate the caller.
fn modifier_is_access_control(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("only")
        || l.contains("auth")
        || l.contains("owner")
        || l.contains("admin")
        || l.contains("role")
        || l.contains("governance")
        || l.contains("guardian")
        || l.contains("restricted")
}

/// A modifier name that is *unmistakably* a discretionary admin/role guard, used
/// only as a fallback when the modifier body cannot be resolved (e.g. inherited
/// from an out-of-scope base such as OpenZeppelin `Ownable`/`AccessControl`).
fn modifier_name_is_discretionary(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("owner")
        || l.contains("admin")
        || l.contains("role")
        || l.contains("governance")
        || l.contains("governor")
        || l.contains("guardian")
        || l.contains("authority")
}

/// Resolve a modifier (by name) to the guard target it pins `msg.sender` to.
/// Returns `None` if no definition of that modifier has a resolvable
/// `msg.sender ==` check.
///
/// Robust to the realities of a multi-file corpus:
///   * the modifier is commonly **inherited** from a base (Olympus
///     `OlympusAccessControlled.onlyVault` is `require(msg.sender ==
///     authority.vault())`, not in the token that applies it) — so all
///     definitions of the name are considered, not just the same-contract one;
///   * a definition may be **indirect** (`OlympusAccessControlledV2.onlyVault` is
///     `{ _onlyVault(); _; }`) — so an internal helper the modifier body calls is
///     resolved one level deep for its guard;
///   * several same-named definitions may coexist (V1 / V2 / `VaultOwned`) — the
///     results are combined conservatively: a discretionary-admin reading
///     anywhere wins (keep firing), else a fixed-contract reading suffices.
fn resolve_modifier_guard_target(
    cx: &AnalysisContext,
    f: &Function,
    contract: &Contract,
    mod_name: &str,
) -> Option<GuardTarget> {
    let mut saw_fixed = false;
    // All modifier definitions of this name, same contract first (irrelevant to
    // correctness since we combine, but keeps the common case cheap).
    let defs = cx
        .scir
        .functions_of(f.contract)
        .filter(|g| g.is_modifier() && g.name == mod_name)
        .chain(
            cx.scir
                .all_functions()
                .filter(|g| g.is_modifier() && g.name == mod_name && g.contract != f.contract),
        );
    for m in defs {
        match guard_target_in_body(cx, f, contract, m, 1) {
            Some(GuardTarget::DiscretionaryAdmin) => return Some(GuardTarget::DiscretionaryAdmin),
            Some(GuardTarget::FixedContract) => saw_fixed = true,
            _ => {}
        }
    }
    saw_fixed.then_some(GuardTarget::FixedContract)
}

/// The guard target pinned by a function/modifier body: its inline
/// `require(msg.sender == X)` / `if (msg.sender != X) revert`, descending up to
/// `depth` levels into internal helper functions it calls (to follow the
/// `modifier onlyVault { _onlyVault(); _; }` → `function _onlyVault()` indirection).
fn guard_target_in_body(
    cx: &AnalysisContext,
    f: &Function,
    contract: &Contract,
    body_fn: &Function,
    depth: u32,
) -> Option<GuardTarget> {
    for cond in inline_sender_guard_conds(body_fn) {
        let t = classify_sender_guard(&cond, contract);
        if t != GuardTarget::Other {
            return Some(t);
        }
    }
    if depth == 0 {
        return None;
    }
    // Descend into internal helper functions the body calls (e.g. `_onlyVault()`).
    let mut result: Option<GuardTarget> = None;
    for callee_name in &body_fn.effects.internal_calls {
        let Some(helper) = cx
            .scir
            .functions_of(f.contract)
            .find(|g| &g.name == callee_name && !g.is_modifier())
            .or_else(|| {
                cx.scir
                    .all_functions()
                    .find(|g| &g.name == callee_name && !g.is_modifier())
            })
        else {
            continue;
        };
        match guard_target_in_body(cx, f, contract, helper, depth - 1) {
            Some(GuardTarget::DiscretionaryAdmin) => return Some(GuardTarget::DiscretionaryAdmin),
            Some(GuardTarget::FixedContract) => result = Some(GuardTarget::FixedContract),
            _ => {}
        }
    }
    result
}

/// Best-effort callee name of a call (`owner` from `owner()`, `governor` from
/// `authority.governor()`, `hasRole` from `hasRole(...)`).
fn call_callee_name(c: &sluice_ir::Call) -> Option<&str> {
    if let Some(n) = c.func_name.as_deref() {
        return Some(n);
    }
    c.callee.simple_name()
}

/// True if the expression mentions the caller anywhere (deep) — either
/// `msg.sender` or the OZ / ERC-2771 accessor `_msgSender()` / `msgSender()`. Used
/// to pre-filter guard conditions, so a guard written as
/// `require(_msgSender() == address(POOL))` (the Aave `onlyPool` shape) is
/// recognized as a `msg.sender` access check just like `msg.sender == POOL`.
fn expr_mentions_msg_sender(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if mentions_msg_sender(sub) {
            found = true;
        }
    });
    found
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
                    .map(mentions_msg_sender)
                    .unwrap_or(false);
                if !to_caller {
                    all_caller = false;
                }
                return;
            }

            // Supply ops on the caller's **own** balance: `_burn(msg.sender, x)` /
            // `_mint(msg.sender, x)` / `burn(msg.sender, x)` / `burnFrom(msg.sender,
            // x)`. The account is the **first** argument (`(account, amount)`). This
            // is a user operation (e.g. a `cooldown`/`unstake` burning the caller's
            // own stake), not an admin minting/burning *someone else's* balance.
            if matches!(
                call.func_name.as_deref(),
                Some("mint") | Some("_mint") | Some("burn") | Some("_burn") | Some("burnFrom")
            ) {
                saw_move = true;
                // Account = first arg; be robust to a `token.burn(account, amt)`
                // member form too (account still leads the arg list).
                if !arg_is_msg_sender(&call.args, 0) {
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
                    if params.contains(&name) {
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
            // `approve(spender, amt)` grants spending authority; the spender is the
            // steerable destination (second-to-last arg, like a transfer recipient).
            | Some("approve") | Some("safeApprove") | Some("forceApprove")
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

/// `msg.sender` (best-effort, after cast-stripping). Also accepts the OZ /
/// ERC-2771 accessor `_msgSender()` / `msgSender()` (a zero-arg call resolving to
/// the caller), so a `_mint(_msgSender(), x)` self-mint is recognized as
/// caller-own just like `_mint(msg.sender, x)`.
fn mentions_msg_sender(e: &Expr) -> bool {
    let e = unwrap_casts(e);
    if e.mentions_member("msg", "sender") {
        return true;
    }
    if let ExprKind::Call(c) = &e.kind {
        if c.args.is_empty() {
            if let Some(n) = c.func_name.as_deref().or_else(|| c.callee.simple_name()) {
                return n == "_msgSender" || n == "msgSender";
            }
        }
    }
    false
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
    // path — the former FIXED_DEST Info sub-class, now SUPPRESSED ENTIRELY (Fix 2:
    // the "preset destination — not an admin-can-rug risk — informational" tier is
    // pure noise; the destination is hard-wired so there is nothing to steer).
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

    // Fix 2 — the preset-destination fund-mover sub-class is now silent.
    #[test]
    fn preset_destination_mover_is_silent() {
        let fs = run(PRESET_DEST_MOVER);
        let c = central(&fs);
        assert!(
            c.is_empty(),
            "preset-destination fund mover (FIXED_DEST sub-class) must be suppressed entirely: {:?}",
            c
        );
    }

    // A second preset-destination shape: an `approve` to a fixed (state-var)
    // spender under an admin guard. No caller-chosen dest, no mint/burn, no
    // recipient re-point → was the FIXED_DEST Info tier → now silent.
    const PRESET_APPROVE_FIXED_SPENDER: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function approve(address s, uint256 a) external returns (bool); }
        contract Pool {
            address public owner;
            address public router;
            IERC20 public token;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
            // approves a FIXED, preset router (state var) — hard-wired path
            function reapprove(uint256 a) external onlyOwner {
                token.approve(router, a);
            }
        }
    "#;

    #[test]
    fn preset_approve_fixed_spender_is_silent() {
        let fs = run(PRESET_APPROVE_FIXED_SPENDER);
        let c = central(&fs);
        assert!(
            c.is_empty(),
            "approve to a fixed/preset spender (FIXED_DEST sub-class) must be suppressed: {:?}",
            c
        );
    }

    // Over-suppression guard for Fix 2: suppressing the FIXED_DEST Info tier must
    // NOT silence the steerable tiers. The exact-task Medium shape — a
    // routing-shaped setter (`setFeeReceiver`) that *also* moves funds (a transfer
    // to a fixed dest) — must STILL fire Medium with the strong title (the
    // `StakedPendle.setFeeReceiver` / `BackingEigen.mint`-class output is reserved
    // here). Without the routing-setter name this body would have been FIXED_DEST.
    const ROUTING_SETTER_MOVES_TO_FIXED_DEST: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function safeTransfer(address to, uint256 a) external; }
        contract Fees {
            address public owner;
            address public feeReceiver;
            IERC20 public token;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
            // routing-shaped name + a real fund move (to a fixed dest) => Medium,
            // strong title — NOT the suppressed FIXED_DEST tier.
            function setFeeReceiver() external onlyOwner {
                token.safeTransfer(feeReceiver, 1);
            }
        }
    "#;

    #[test]
    fn routing_setter_that_moves_funds_still_fires_medium() {
        let fs = run(ROUTING_SETTER_MOVES_TO_FIXED_DEST);
        let c = central(&fs);
        assert!(
            c.iter().any(|f| f.severity == Severity::Medium
                && f.title.contains("move/re-route user funds")),
            "a routing-shaped setter that moves funds must still fire Medium (not be \
             swallowed by the FIXED_DEST suppression): {:?}",
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

    // ===== R18 fixed-protocol-contract-guard regressions ==================

    /// Helper: is the centralization detector entirely silent on `src`?
    fn silent(src: &str) -> bool {
        central(&run(src)).is_empty()
    }

    // (1) The exact task shape: `StakingDistributor.distribute` guarded by an
    // inline `if (msg.sender != staking) revert` where `staking` is an
    // `immutable` address, minting to that same fixed `staking` contract. The
    // only caller is a fixed protocol contract (not a discretionary admin), so
    // this is protocol-internal issuance — it must now be Info/suppressed (here:
    // suppressed), never the Low "admin-can-rug" claim.
    const DISTRIBUTE_STAKING_GUARD: &str = r#"
        pragma solidity ^0.8.0;
        interface ITreasury { function mint(address to, uint256 a) external; }
        contract StakingDistributor {
            ITreasury private immutable treasury;
            address private immutable staking;
            uint256 public rate;
            error Only_Staking();
            constructor(address _t, address _s) { treasury = ITreasury(_t); staking = _s; }
            function distribute() external {
                if (msg.sender != staking) revert Only_Staking();
                treasury.mint(staking, nextReward());
            }
            function nextReward() internal view returns (uint256) { return rate; }
        }
    "#;

    #[test]
    fn distribute_guarded_by_immutable_staking_is_suppressed() {
        let fs = run(DISTRIBUTE_STAKING_GUARD);
        let c = central(&fs);
        // Must NOT carry the strong rug title (the headline regression).
        assert!(
            c.iter().all(|f| !f.title.contains("move/re-route user funds")),
            "msg.sender==staking-guarded distribute must not be a strong rug: {:?}",
            c
        );
        // And in no case above Info — here it is suppressed entirely.
        assert!(
            c.iter().all(|f| f.severity <= Severity::Info),
            "distribute() (fixed-contract gated) must never exceed Info: {:?}",
            c
        );
        assert!(
            c.is_empty(),
            "distribute() gated by a fixed protocol contract should be silent: {:?}",
            c
        );
    }

    // (2) A token `mint(_to, amt)` whose ONLY caller is a fixed protocol contract
    // — the guard is a modifier resolving to `require(msg.sender == bridge)` where
    // `bridge` is `immutable`. Protocol plumbing (only the bridge can mint), not a
    // discretionary admin → suppressed. (`OptimismMintableERC20`-shape.)
    const MINT_GATED_BY_IMMUTABLE_BRIDGE: &str = r#"
        pragma solidity ^0.8.0;
        contract Token {
            address public immutable BRIDGE;
            constructor(address _b) { BRIDGE = _b; }
            modifier onlyBridge() { require(msg.sender == BRIDGE, "only bridge"); _; }
            function _mint(address to, uint256 a) internal {}
            function _burn(address from, uint256 a) internal {}
            function mint(address _to, uint256 _a) external onlyBridge { _mint(_to, _a); }
            function burn(address _from, uint256 _a) external onlyBridge { _burn(_from, _a); }
        }
    "#;

    #[test]
    fn mint_gated_by_immutable_contract_is_suppressed() {
        assert!(
            silent(MINT_GATED_BY_IMMUTABLE_BRIDGE),
            "mint/burn callable only by an immutable bridge must be suppressed: {:?}",
            central(&run(MINT_GATED_BY_IMMUTABLE_BRIDGE))
        );
    }

    // (3) A mint gated by a *contract-typed* state var (`IManager manager`), via a
    // modifier — the Olympus/etherfi `onlyXManager` shape. Suppressed.
    const MINT_GATED_BY_CONTRACT_TYPED: &str = r#"
        pragma solidity ^0.8.0;
        interface IManager {}
        contract NFT {
            IManager manager;
            modifier onlyManager() { require(msg.sender == address(manager), "only mgr"); _; }
            function _mint(address to, uint256 a) internal {}
            function mint(address _to, uint256 _a) external onlyManager { _mint(_to, _a); }
        }
    "#;

    #[test]
    fn mint_gated_by_contract_typed_var_is_suppressed() {
        assert!(
            silent(MINT_GATED_BY_CONTRACT_TYPED),
            "mint callable only by a contract-typed manager must be suppressed: {:?}",
            central(&run(MINT_GATED_BY_CONTRACT_TYPED))
        );
    }

    // (4) Over-suppression guard: an `onlyOwner mint(to, amt)` — a *discretionary*
    // admin who can mint supply to ANY address — MUST still fire Low with the
    // strong title. The fixed-contract suppression must not touch admin levers.
    const OWNER_MINT_TO_ANYONE: &str = r#"
        pragma solidity ^0.8.0;
        contract Token {
            address public owner;
            modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
            function _mint(address to, uint256 a) internal {}
            function mint(address to, uint256 a) external onlyOwner { _mint(to, a); }
        }
    "#;

    #[test]
    fn owner_mint_to_anyone_still_fires_strong() {
        let fs = run(OWNER_MINT_TO_ANYONE);
        let c = central(&fs);
        assert!(
            c.iter().any(|f| f.severity >= Severity::Low
                && f.title.contains("move/re-route user funds")),
            "onlyOwner mint(to, amt) must remain a Low+ strong finding: {:?}",
            c
        );
    }

    // (5) Over-suppression guard: a `role`-gated mint (`onlyRole(MINTER_ROLE)`) is
    // a discretionary role lever, not fixed-contract plumbing — it must still fire
    // (the Ethena `EthenaMinting`-shape). The modifier name carries `role`.
    const ROLE_GATED_MINT: &str = r#"
        pragma solidity ^0.8.0;
        contract Minting {
            mapping(bytes32 => mapping(address => bool)) roles;
            bytes32 constant MINTER_ROLE = keccak256("M");
            modifier onlyRole(bytes32 r) { require(roles[r][msg.sender], "role"); _; }
            function _mint(address to, uint256 a) internal {}
            function mint(address to, uint256 a) external onlyRole(MINTER_ROLE) { _mint(to, a); }
        }
    "#;

    #[test]
    fn role_gated_mint_still_fires() {
        let fs = run(ROLE_GATED_MINT);
        let c = central(&fs);
        assert!(
            !c.is_empty() && c.iter().any(|f| f.severity >= Severity::Low),
            "onlyRole-gated mint is a discretionary lever and must still fire Low+: {:?}",
            c
        );
    }

    // (6) A supply op on the caller's OWN balance via `_burn(msg.sender, x)` (a
    // `cooldown`/`unstake`), where the `msg.sender`-referencing `require` makes the
    // function look access-controlled — must be treated as caller-own and
    // suppressed (the Pendle `StakedPendle.cooldown`-shape).
    const COOLDOWN_BURNS_SELF: &str = r#"
        pragma solidity ^0.8.0;
        contract Staked {
            struct CD { uint256 amount; }
            mapping(address => CD) public userCooldown;
            function _burn(address from, uint256 a) internal {}
            function cooldown(uint256 amount) external {
                require(amount > 0, "amt");
                require(userCooldown[msg.sender].amount == 0, "in cooldown");
                userCooldown[msg.sender] = CD({amount: amount});
                _burn(msg.sender, amount);
            }
        }
    "#;

    #[test]
    fn cooldown_burning_own_balance_is_suppressed() {
        assert!(
            silent(COOLDOWN_BURNS_SELF),
            "a user cooldown burning its own balance must be suppressed: {:?}",
            central(&run(COOLDOWN_BURNS_SELF))
        );
    }

    // (7) Inherited-modifier indirection: the applying token has only
    // `function mint(...) onlyVault`; `onlyVault` is defined in a base as
    // `{ _onlyVault(); _; }` and `_onlyVault()` is `if (msg.sender !=
    // authority.vault()) revert`. The detector must resolve the base modifier and
    // its one-level internal helper to see the fixed-contract pin, and suppress.
    // (Olympus `OlympusAccessControlledV2` shape.)
    const INHERITED_INDIRECT_VAULT_GUARD: &str = r#"
        pragma solidity ^0.8.0;
        interface IAuth { function vault() external view returns (address); }
        abstract contract AC {
            IAuth public authority;
            error UNAUTHORIZED();
            modifier onlyVault() { _onlyVault(); _; }
            function _onlyVault() internal view {
                if (msg.sender != authority.vault()) revert UNAUTHORIZED();
            }
        }
        contract OToken is AC {
            function _mint(address a, uint256 v) internal {}
            function mint(address account_, uint256 amount_) external onlyVault {
                _mint(account_, amount_);
            }
        }
    "#;

    #[test]
    fn inherited_indirect_fixed_guard_is_suppressed() {
        assert!(
            silent(INHERITED_INDIRECT_VAULT_GUARD),
            "mint gated by an inherited, indirect fixed-contract (vault) guard must be suppressed: {:?}",
            central(&run(INHERITED_INDIRECT_VAULT_GUARD))
        );
    }

    // (8) A treasury/recipient *address re-point* is a genuine fund-routing change
    // regardless of who triggers it — even a fixed-contract guard must NOT suppress
    // it (the `OlympusAuthority.pullVault` exception: a `msg.sender == newVault`
    // two-step that reassigns `vault`).
    const FIXED_GUARD_BUT_REASSIGNS_VAULT: &str = r#"
        pragma solidity ^0.8.0;
        contract Authority {
            address public vault;
            address public newVault;
            function pullVault() external {
                require(msg.sender == newVault, "!newVault");
                vault = newVault;
            }
        }
    "#;

    #[test]
    fn fixed_guard_that_reassigns_recipient_still_fires() {
        let fs = run(FIXED_GUARD_BUT_REASSIGNS_VAULT);
        let c = central(&fs);
        assert!(
            c.iter().any(|f| f.title.contains("move/re-route user funds")),
            "a recipient/treasury re-point must still fire strong even under a fixed-contract guard: {:?}",
            c
        );
    }

    // ===== Fix B: Medium reserved for a genuine fund-movement opcode ==========

    // Real shape (gte-perps `GTELaunchpadV2PairFactory.setFeeToSetter`): a pure
    // admin setter that only **reassigns the next admin** address —
    // `feeToSetter = _feeToSetter;` — with NO transfer/mint/approve opcode. It moves
    // no funds, so it must NOT sit at the Medium fund-reroute tier; downgraded to
    // Low (a privileged setter), never Medium+.
    const PURE_ADMIN_SETTER_NO_OPCODE: &str = r#"
        pragma solidity ^0.8.0;
        contract Factory {
            address public feeTo;
            address public feeToSetter;
            function setFeeToSetter(address _feeToSetter) external {
                if (msg.sender != feeToSetter) revert("FORBIDDEN");
                feeToSetter = _feeToSetter;
            }
            function setFeeTo(address _feeTo) external {
                if (msg.sender != feeToSetter) revert("FORBIDDEN");
                feeTo = _feeTo;
            }
        }
    "#;

    #[test]
    fn pure_admin_setter_no_opcode_is_at_most_low() {
        let fs = run(PURE_ADMIN_SETTER_NO_OPCODE);
        let c = central(&fs);
        assert!(!c.is_empty(), "the address-re-pointing setters should still be reported");
        // A setter with no fund-movement opcode must never reach Medium+.
        assert!(
            c.iter().all(|f| f.severity <= Severity::Low),
            "a pure admin setter (no transfer/mint/approve opcode) must be at most Low, never Medium: {:?}",
            c
        );
        // Specifically the named `setFeeToSetter` shape is Low (not Medium).
        assert!(
            c.iter().any(|f| f.function == "setFeeToSetter" && f.severity == Severity::Low),
            "setFeeToSetter must be Low: {:?}",
            c
        );
    }

    // Real shape (Aave/EigenLayer `BackingEigen.mint`): a privileged `mint(to,
    // amount)` to a caller-supplied (externally-supplied) address — a genuine
    // fund-movement opcode that creates balances at an attacker-relevant address.
    // This is the fund-reroute tier and MUST be Medium or higher.
    const MINT_TO_ARBITRARY_ADDRESS: &str = r#"
        pragma solidity ^0.8.0;
        contract BackingEigen {
            mapping(address => bool) public isMinter;
            function _mint(address to, uint256 a) internal {}
            function mint(address to, uint256 amount) external {
                require(isMinter[msg.sender], "not a minter");
                _mint(to, amount);
            }
        }
    "#;

    #[test]
    fn mint_to_arbitrary_address_is_medium_or_higher() {
        let fs = run(MINT_TO_ARBITRARY_ADDRESS);
        let c = central(&fs);
        assert!(
            c.iter().any(|f| f.function == "mint"
                && f.severity >= Severity::Medium
                && f.title.contains("move/re-route user funds")),
            "mint(to, amount) to a caller-supplied address must be Medium+ (genuine fund-reroute): {:?}",
            c
        );
    }

    // Companion: a caller-chosen *transfer* to an externally-supplied address (the
    // Aave `Collector.transfer(token, recipient, amt)` / `emergencyTokenTransfer`
    // shape) is also a genuine fund movement → Medium+, strong title.
    const TRANSFER_TO_ARBITRARY_ADDRESS: &str = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { function safeTransfer(address to, uint256 a) external; }
        contract Collector {
            address public owner;
            modifier onlyFundsAdmin() { require(msg.sender == owner, "no"); _; }
            function transfer(IERC20 token, address recipient, uint256 amount) external onlyFundsAdmin {
                token.safeTransfer(recipient, amount);
            }
        }
    "#;

    #[test]
    fn admin_transfer_to_arbitrary_address_is_medium_or_higher() {
        let fs = run(TRANSFER_TO_ARBITRARY_ADDRESS);
        let c = central(&fs);
        assert!(
            c.iter().any(|f| f.severity >= Severity::Medium
                && f.title.contains("move/re-route user funds")),
            "an admin transfer to a caller-supplied recipient must be Medium+: {:?}",
            c
        );
    }
}

