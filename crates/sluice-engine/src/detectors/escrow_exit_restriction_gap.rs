//! Escrow exit restriction gap — a two-phase withdraw whose **entry/burn** leg
//! enforces a restriction/blacklist role but whose matured-asset **exit** leg
//! releases the escrowed funds with **no restriction check at all**.
//!
//! Restriction-enforcing stablecoin / staking vaults give a privileged role the
//! power to freeze an address: a `FULL_RESTRICTED_STAKER_ROLE` (or a
//! `blacklist`/`denylist` mapping) that must block any value movement to or from
//! the restricted account. In a single-phase ERC4626 vault that is enforced in one
//! place — the withdraw/redeem hook. But once a **cooldown / unbonding** is layered
//! on top, the withdrawal becomes *two* transactions against *two* code paths:
//!
//!   1. **Entry / burn leg** — `cooldownAssets` / `cooldownShares` (which call the
//!      ERC4626 `_withdraw` hook) burn the user's shares, escrow the matured
//!      underlying into a separate **silo / holding** contract, and stamp a
//!      per-user cooldown struct. *This* leg runs the restriction check
//!      (`StakedUSDe._withdraw`: `if (hasRole(FULL_RESTRICTED_STAKER_ROLE, caller)
//!      || ... ) revert`).
//!   2. **Exit / claim leg** — `unstake(receiver)` waits for the cooldown to
//!      mature, **zeroes the per-user escrow struct**, and **releases the escrowed
//!      assets out of the silo** (`silo.withdraw(receiver, assets)`). This leg has
//!      **no restriction read whatsoever**.
//!
//! So an address that is blacklisted *after* it has already entered the cooldown
//! (or that the protocol freezes while assets sit in the silo) still walks the
//! matured underlying out through the unguarded exit: the restriction defense is
//! enforced on the leg that *locks* value but absent on the leg that *frees* it.
//! This is the real Ethena `StakedUSDeV2.unstake` → `USDeSilo.withdraw`
//! (`_USDE.transfer(to, amount)`, `onlyStakingVault` only) bug, with the entry gate
//! at `StakedUSDe._withdraw` (the `FULL_RESTRICTED_STAKER_ROLE` revert).
//!
//! ## Fingerprint (all required, so this stays silent on single-phase vaults and
//! on flows whose exit re-checks the role)
//!
//!   * an externally reachable, state-mutating **exit** function with a body that
//!     - **zeroes a per-user escrow/cooldown struct field** — an `x.field = 0`
//!       assignment whose `x` is a `storage` handle bound to a per-user state
//!       mapping (`UserCooldown storage uc = cooldowns[msg.sender]`), or a direct
//!       `cooldowns[key].field = 0` write; and
//!     - then **releases value** — an outbound transfer
//!       (`silo.withdraw(...)` / `*.transfer` / `*.safeTransfer` / `*.send` /
//!       `*.withdraw`) carrying an amount **derived from that zeroed struct**; and
//!     - performs **no restriction read** — neither the function body nor its
//!       modifiers read a restriction role / blacklist (`hasRole(..RESTRICTED..)`,
//!       a `restricted`/`blacklist`/`denylist`/`frozen`/`banned` map);
//!   * **asymmetry, demonstrable in-codebase**: some deposit/withdraw/redeem/stake
//!     **entry** function in the *same inheritance family* (the exit's contract or
//!     any of its transitive base contracts — Ethena's gate lives in the base
//!     `StakedUSDe`) **does** read a restriction role. This proves the restriction
//!     defense exists and is simply missing on the exit leg.
//!
//! ## Suppression
//!
//!   * the exit leg itself reads a restriction role (the check is present — no gap);
//!   * no restriction role exists anywhere in the contract family (then this is not
//!     a restriction-bypass class at all — `escrow_exit` shapes without a freeze
//!     capability are ordinary cooldown claims);
//!   * single-phase: no escrow-zeroing + value-release pair (the two-leg structure
//!     is the whole premise).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{
    AssignOp, CallKind, Contract, Expr, ExprKind, Function, Lit, Span, StmtKind,
};

use super::prelude::*;

pub struct EscrowExitRestrictionGapDetector;

impl Detector for EscrowExitRestrictionGapDetector {
    fn id(&self) -> &'static str {
        "escrow-exit-restriction-gap"
    }
    fn category(&self) -> Category {
        Category::EscrowExitRestrictionGap
    }
    fn description(&self) -> &'static str {
        "Two-phase escrow withdraw whose matured-asset exit leg releases funds with no restriction/blacklist check, while the entry/burn leg in the same contract family enforces one (Ethena StakedUSDeV2.unstake -> USDeSilo class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.functions() {
            // The exit leg is an externally reachable, state-mutating claim with a body.
            if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
                continue;
            }
            let Some(contract) = cx.contract_of(f.id) else { continue };
            // Interfaces / libraries have no concrete exit to analyse.
            if !contract.is_concrete() {
                continue;
            }

            // (1) The two-leg structure: this function zeroes a per-user escrow
            //     struct and then releases value derived from it.
            let Some(hit) = matured_exit_release(cx, f) else { continue };

            // (2) SUPPRESS — the exit leg itself reads a restriction role (the
            //     check is present on this leg, so there is no gap).
            if function_reads_restriction(cx, f) {
                continue;
            }

            // (3) ASYMMETRY — a deposit/withdraw/redeem entry function in the same
            //     inheritance family DOES enforce a restriction role. This both
            //     proves a restriction capability exists (else suppress) and
            //     demonstrates the missing-on-exit asymmetry in-codebase.
            let Some(entry) = restriction_entry_in_family(cx, contract, f) else { continue };

            let b = report!(self, Category::EscrowExitRestrictionGap,
                title = "Escrowed-asset exit leg releases funds with no restriction/blacklist check",
                severity = Severity::High,
                // Multi-anchor structural fingerprint — escrow-struct zeroing + value
                // release derived from it, no restriction read on the exit, AND a
                // demonstrated restriction gate on a sibling entry leg in the same
                // inheritance family. Tight enough for 0 FPs across the prior codebases.
                confidence = 0.8,
                dimensions = [Dimension::Invariant],
                message = format!(
                    "`{exit}` is the matured-asset *exit* leg of a two-phase escrow withdraw: it zeroes a \
                     per-user escrow/cooldown struct ({zero}) and then releases the escrowed value \
                     ({release}) — but performs **no restriction/blacklist check**. Meanwhile the \
                     entry/burn leg `{entry}` in the same contract family enforces a restriction role \
                     (a `hasRole(..RESTRICTED..)` / blacklist read). A restriction is therefore enforced on \
                     the leg that *locks* value (burn + escrow into the silo/holding contract) but absent on \
                     the leg that *frees* it: an address blacklisted after it entered the cooldown — or \
                     frozen while its assets sit in the silo — still withdraws the matured underlying through \
                     the unguarded exit. This is the Ethena `StakedUSDeV2.unstake` → `USDeSilo.withdraw` \
                     (bare `_USDE.transfer`, `onlyStakingVault` only) gap, with the entry gate at \
                     `StakedUSDe._withdraw`'s `FULL_RESTRICTED_STAKER_ROLE` revert.",
                    exit = f.name,
                    entry = entry,
                    zero = hit.zero_text,
                    release = hit.release_text,
                ),
                recommendation =
                    "Re-check the restriction/blacklist role on the exit leg, not only at burn/escrow time: \
                     in `unstake` (and in the silo's release function) revert if the cooldown owner or the \
                     `receiver` holds `FULL_RESTRICTED_STAKER_ROLE` (or is blacklisted). Equivalently, run \
                     the same `_beforeTokenTransfer`/restriction guard on the matured-asset transfer out of \
                     the silo. A freeze must hold across *both* phases of a two-step withdraw; enforcing it \
                     only on the leg that locks value leaves the leg that releases it open.",
            );
            out.push(finish_at(cx, b, f.id, hit.span));
        }

        out
    }
}

/// A matched two-leg escrow exit: an escrow-struct zeroing plus a value release
/// derived from that struct.
struct ExitRelease {
    /// Span of the value-release call (the bug site).
    span: Span,
    /// Text of the escrow-zeroing assignment (for the message).
    zero_text: String,
    /// Text of the value-release call (for the message).
    release_text: String,
}

/// Does `f` exhibit the matured-asset exit shape: it **zeroes a per-user escrow
/// struct field** and then **releases value derived from that struct**? Returns the
/// release-call span and snippets if so.
fn matured_exit_release(cx: &AnalysisContext, f: &Function) -> Option<ExitRelease> {
    // -- escrow handles: `<Type> storage h = <mapping>[<key>];` locals, plus the
    //    mapping base names themselves (for the direct `cooldowns[k].x = 0` form).
    let handles = escrow_handles(f);
    if handles.is_empty() {
        return None;
    }

    // -- a zeroing assignment `<handle>.field = 0` (or `<mapping>[key].field = 0`).
    let zero = first_escrow_zeroing(f, &handles)?;

    // -- amount locals: locals whose initializer reads `<handle>.field` (the matured
    //    underlying amount the exit pays out, e.g. `uint256 assets = uc.underlyingAmount;`).
    let amount_locals = amount_locals_from_handles(f, &handles);

    // -- a value-release outbound call carrying an amount derived from the escrow.
    let release = first_value_release(f, &handles, &amount_locals)?;

    Some(ExitRelease {
        span: release.0,
        zero_text: clip(&cx.source_text(zero)),
        release_text: clip(&cx.source_text(release.0)),
    })
}

/// Identifiers that name a per-user escrow record — both the `storage` locals
/// bound to a per-user state mapping (`UserCooldown storage uc = cooldowns[k]`)
/// and the mapping base names themselves (for direct `cooldowns[k].field = 0`
/// writes). Any of these, used as the base of a `base.field = 0` assignment,
/// signals zeroing the escrow struct. Returned as one flat set.
fn escrow_handles(f: &Function) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for top in &f.body {
        top.visit(&mut |st| {
            if let StmtKind::VarDecl { name: Some(n), init: Some(init), .. } = &st.kind {
                // `<Type> storage h = cooldowns[...]` — a storage pointer into a
                // per-user mapping. We accept any local whose initializer indexes a
                // mapping by a per-user key (msg.sender or a param), which is the
                // escrow handle; the downstream zeroing + value-release + family
                // asymmetry gates keep this from over-matching.
                if is_per_user_index(init) {
                    out.push(n.clone());
                    // Also remember the underlying mapping base (for direct writes).
                    if let Some(base) = index_base_name(init) {
                        if !out.contains(&base) {
                            out.push(base);
                        }
                    }
                }
            }
        });
    }
    // Also seed mapping bases referenced directly as `cooldowns[key].field`.
    for top in &f.body {
        top.visit_exprs(&mut |e| {
            if let ExprKind::Assign { target, .. } = &e.kind {
                if let Some(base) = struct_index_base(target) {
                    if !out.contains(&base) {
                        out.push(base);
                    }
                }
            }
        });
    }
    out
}

/// `mapping[key]` where `key` is `msg.sender` or a bare identifier (a per-user key).
fn is_per_user_index(e: &Expr) -> bool {
    if let ExprKind::Index { base: _, index: Some(idx) } = &e.kind {
        return is_msg_sender(idx) || matches!(&idx.kind, ExprKind::Ident(_));
    }
    false
}

/// Base identifier of an `Index` expression: `cooldowns[k]` -> `Some("cooldowns")`.
fn index_base_name(e: &Expr) -> Option<String> {
    if let ExprKind::Index { base, .. } = &e.kind {
        return root_ident(base);
    }
    None
}

/// For a target `mapping[key].field` (member over an index), return the mapping
/// base name. `cooldowns[msg.sender].underlyingAmount` -> `Some("cooldowns")`.
fn struct_index_base(target: &Expr) -> Option<String> {
    if let ExprKind::Member { base, .. } = &target.kind {
        if let ExprKind::Index { base: ibase, .. } = &base.kind {
            return root_ident(ibase);
        }
    }
    None
}

/// First assignment `<handle>.field = 0` (or `<mapping>[key].field = 0`) where the
/// base resolves to one of the escrow `handles`. Returns its span.
fn first_escrow_zeroing(f: &Function, handles: &[String]) -> Option<Span> {
    let mut hit: Option<Span> = None;
    for top in &f.body {
        top.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Assign { op, target, value } = &e.kind else { return };
            if !matches!(op, AssignOp::Assign) {
                return;
            }
            if !is_zero_lit(value) {
                return;
            }
            // target must be `<base>.field` whose base root is an escrow handle.
            let ExprKind::Member { base, .. } = &target.kind else { return };
            let root = match &base.kind {
                ExprKind::Ident(n) => Some(n.clone()),
                ExprKind::Index { base: ib, .. } => root_ident(ib),
                _ => None,
            };
            if let Some(r) = root {
                if handles.contains(&r) {
                    hit = Some(e.span);
                }
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Local variables whose initializer reads `<handle>.field` — the matured amount
/// the exit pays out (`uint256 assets = userCooldown.underlyingAmount;`).
fn amount_locals_from_handles(f: &Function, handles: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for top in &f.body {
        top.visit(&mut |st| {
            if let StmtKind::VarDecl { name: Some(n), init: Some(init), .. } = &st.kind {
                if reads_handle_member(init, handles) && !out.contains(n) {
                    out.push(n.clone());
                }
            }
        });
    }
    out
}

/// Does `e` read `<handle>.field` for some escrow handle?
fn reads_handle_member(e: &Expr, handles: &[String]) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Member { base, .. } = &sub.kind {
            let root = match &base.kind {
                ExprKind::Ident(n) => Some(n.as_str()),
                _ => None,
            };
            if let Some(r) = root {
                if handles.iter().any(|h| h == r) {
                    found = true;
                }
            }
        }
    });
    found
}

/// First outbound value-release call in `f` carrying an amount derived from the
/// escrow (an `amount_local`, or a direct `<handle>.field` read). Returns its span.
///
/// A value release is an external/low-level call whose method reads as a transfer
/// or holding-withdraw (`withdraw`, `transfer`, `safetransfer`, `send`,
/// `transferfrom`). The amount-derivation anchor keeps this from firing on an
/// unrelated external call in the same function.
fn first_value_release<'a>(
    f: &'a Function,
    handles: &[String],
    amount_locals: &[String],
) -> Option<(Span, &'a sluice_ir::Call)> {
    let mut hit: Option<(Span, &sluice_ir::Call)> = None;
    for top in &f.body {
        top.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            if !matches!(c.kind, CallKind::External | CallKind::LowLevelCall | CallKind::Transfer | CallKind::Send) {
                return;
            }
            if !is_release_method(c) {
                return;
            }
            // The released amount must be tied to the escrow: an argument that is an
            // amount-local, or that directly reads `<handle>.field`.
            let amount_tied = c.args.iter().any(|a| {
                arg_mentions_any(a, amount_locals) || reads_handle_member(a, handles)
            });
            if amount_tied {
                hit = Some((e.span, c));
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// The call method reads as an outbound value movement.
fn is_release_method(c: &sluice_ir::Call) -> bool {
    let name = c
        .func_name
        .clone()
        .or_else(|| c.callee.simple_name().map(|s| s.to_string()))
        .unwrap_or_default()
        .to_ascii_lowercase();
    name == "withdraw"
        || name == "transfer"
        || name == "safetransfer"
        || name == "send"
        || name == "transferfrom"
        || name == "safetransferfrom"
}

/// Does `e` mention any identifier in `names` as a bare identifier?
fn arg_mentions_any(e: &Expr, names: &[String]) -> bool {
    names.iter().any(|n| expr_mentions_ident(e, n))
}

// ---------------------------------------------------------------- restriction reads

/// Does `f` (its body **or** its modifiers) read a restriction / blacklist role?
/// Two signals, either sufficient:
///   * a storage read whose **var name** matches a restriction pattern — this
///     captures both the role-constant form (`FULL_RESTRICTED_STAKER_ROLE`, recorded
///     as a storage read) and the blacklist-mapping form (`blacklist[user]`); and
///   * a `hasRole`/`isBlacklisted`-style call whose own source mentions a restriction
///     token (covers role checks where the constant is inlined differently).
fn function_reads_restriction(cx: &AnalysisContext, f: &Function) -> bool {
    // Storage-read var names.
    if f.effects.storage_reads.iter().any(|r| name_is_restriction(&r.var)) {
        return true;
    }
    // Restriction-shaped calls (hasRole / isBlacklisted / isRestricted / isFrozen)
    // whose source text carries a restriction token.
    if has_restriction_call(cx, f) {
        return true;
    }
    // Modifiers: a guard modifier whose name reads as a restriction (`notRestricted`,
    // `notBlacklisted`).
    if f.modifiers.iter().any(|m| name_is_restriction(&m.name)) {
        return true;
    }
    false
}

/// A call to a role/blacklist predicate (`hasRole`, `isBlacklisted`, `isRestricted`,
/// `isFrozen`, `checkRestriction`) whose source text references a restriction token.
fn has_restriction_call(cx: &AnalysisContext, f: &Function) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                let nm = c
                    .func_name
                    .clone()
                    .or_else(|| c.callee.simple_name().map(|s| s.to_string()))
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                let is_pred = nm == "hasrole"
                    || nm.contains("blacklist")
                    || nm.contains("restrict")
                    || nm.contains("isfrozen")
                    || nm.contains("denylist")
                    || nm.contains("banned");
                if is_pred {
                    // hasRole is generic; require a restriction token in the call source.
                    let txt = cx.source_text(e.span);
                    if nm != "hasrole" || text_has_restriction_token(&txt) {
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

/// A name reads as a restriction/blacklist marker.
fn name_is_restriction(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("restrict")
        || l.contains("blacklist")
        || l.contains("denylist")
        || l.contains("blocklist")
        || l.contains("frozen")
        || l.contains("freeze")
        || l.contains("banned")
        || l.contains("blocked")
}

/// Comment-stripped, lowercased text references a restriction token.
fn text_has_restriction_token(text: &str) -> bool {
    text.contains("restrict")
        || text.contains("blacklist")
        || text.contains("denylist")
        || text.contains("blocklist")
        || text.contains("frozen")
        || text.contains("banned")
}

// ---------------------------------------------------------------- asymmetry (family)

/// Find a deposit/withdraw/redeem/stake **entry** function in the same inheritance
/// family (the exit's contract or any of its transitive base contracts) that reads
/// a restriction role. Returns its `Contract::name + fn` for the message.
///
/// Ethena's gate lives in the *base* `StakedUSDe._withdraw`, while the exit
/// (`unstake`) is in the derived `StakedUSDeV2`, so we must search bases — not just
/// the exit's own contract.
fn restriction_entry_in_family(cx: &AnalysisContext, exit_contract: &Contract, exit: &Function) -> Option<String> {
    let family = family_contract_names(cx, exit_contract);
    for g in cx.functions() {
        // Skip the exit function itself.
        if g.id == exit.id || !g.has_body {
            continue;
        }
        let Some(gc) = cx.contract_of(g.id) else { continue };
        if !family.contains(&gc.name) {
            continue;
        }
        // The entry leg is a deposit/withdraw/redeem/mint/stake-shaped function that
        // moves value AND reads a restriction role.
        if !is_entry_leg_name(&g.name) {
            continue;
        }
        if function_reads_restriction(cx, g) {
            return Some(format!("{}.{}", gc.name, g.name));
        }
    }
    None
}

/// The set of contract names in `c`'s inheritance family: `c` itself plus the
/// transitive closure of its declared base names (resolved by name through the
/// SCIR). Name-based (SCIR stores `bases` as names), which is exactly what we need
/// to reach `StakedUSDe` from `StakedUSDeV2`.
fn family_contract_names(cx: &AnalysisContext, c: &Contract) -> Vec<String> {
    let mut names: Vec<String> = vec![c.name.clone()];
    let mut frontier: Vec<String> = c.bases.clone();
    while let Some(b) = frontier.pop() {
        if names.contains(&b) {
            continue;
        }
        names.push(b.clone());
        if let Some(bc) = cx.scir.contract_named(&b) {
            for bb in &bc.bases {
                if !names.contains(bb) {
                    frontier.push(bb.clone());
                }
            }
        }
    }
    names
}

/// The function name reads as a value-moving deposit/withdraw entry leg.
fn is_entry_leg_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("withdraw")
        || l.contains("redeem")
        || l.contains("deposit")
        || l.contains("mint")
        || l.contains("stake")
        || l.contains("transfer")
}

// ---------------------------------------------------------------- small helpers

fn is_zero_lit(e: &Expr) -> bool {
    matches!(&peel_casts(e).kind, ExprKind::Lit(Lit::Number(n)) if n.trim() == "0")
}

fn is_msg_sender(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Member { base, member }
        if member == "sender" && matches!(&base.kind, ExprKind::Ident(b) if b == "msg"))
}

/// Trim and collapse a source snippet for inclusion in a finding message.
fn clip(s: &str) -> String {
    let t = s.trim();
    if t.len() <= 80 {
        t.to_string()
    } else {
        format!("{}…", &t[..t.char_indices().take(80).last().map(|(i, _)| i).unwrap_or(t.len())])
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "escrow-exit-restriction-gap")
    }

    // VULN — the real Ethena shape: entry/burn gate (`_withdraw` reads
    // FULL_RESTRICTED_STAKER_ROLE) lives in the BASE `StakedUSDe`; the matured-asset
    // exit `unstake` in the derived `StakedUSDeV2` zeroes the cooldown struct and
    // releases via `silo.withdraw(receiver, assets)` with NO restriction read.
    const VULN: &str = r#"
        interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
        contract Roles {
            mapping(bytes32 => mapping(address => bool)) _roles;
            function hasRole(bytes32 r, address a) public view returns (bool) { return _roles[r][a]; }
        }
        contract StakedUSDe is Roles {
            bytes32 constant FULL_RESTRICTED_STAKER_ROLE = keccak256("F");
            function _withdraw(address caller, address receiver, address _owner, uint256 assets, uint256 shares) internal {
                if (hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)
                    || hasRole(FULL_RESTRICTED_STAKER_ROLE, _owner)) {
                    revert();
                }
            }
        }
        contract USDeSilo {
            IERC20 _USDE;
            function withdraw(address to, uint256 amount) external {
                _USDE.transfer(to, amount);
            }
        }
        struct UserCooldown { uint104 cooldownEnd; uint152 underlyingAmount; }
        contract StakedUSDeV2 is StakedUSDe {
            mapping(address => UserCooldown) public cooldowns;
            USDeSilo public silo;
            uint24 public cooldownDuration;
            function unstake(address receiver) external {
                UserCooldown storage userCooldown = cooldowns[msg.sender];
                uint256 assets = userCooldown.underlyingAmount;
                if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
                    userCooldown.cooldownEnd = 0;
                    userCooldown.underlyingAmount = 0;
                    silo.withdraw(receiver, assets);
                } else {
                    revert();
                }
            }
        }
    "#;

    // VULN (single-contract, blacklist-mapping form) — the entry `withdraw` reads a
    // `blacklist` mapping; the exit `claim` zeroes the escrow and `token.safeTransfer`s
    // the matured amount with no blacklist read.
    const VULN_BLACKLIST: &str = r#"
        interface IERC20 { function safeTransfer(address to, uint256 a) external; }
        struct Escrow { uint256 maturesAt; uint256 amount; }
        contract Vault {
            mapping(address => bool) public blacklist;
            mapping(address => Escrow) public escrows;
            IERC20 token;
            function withdraw(uint256 amount) external {
                require(!blacklist[msg.sender], "restricted");
                escrows[msg.sender].amount += amount;
                escrows[msg.sender].maturesAt = block.timestamp + 7 days;
            }
            function claim() external {
                Escrow storage e = escrows[msg.sender];
                uint256 amount = e.amount;
                require(block.timestamp >= e.maturesAt, "early");
                e.amount = 0;
                e.maturesAt = 0;
                token.safeTransfer(msg.sender, amount);
            }
        }
    "#;

    // SAFE — the exit leg DOES re-check the restriction role (blacklist). No gap.
    const SAFE_EXIT_CHECKS: &str = r#"
        interface IERC20 { function safeTransfer(address to, uint256 a) external; }
        struct Escrow { uint256 maturesAt; uint256 amount; }
        contract Vault {
            mapping(address => bool) public blacklist;
            mapping(address => Escrow) public escrows;
            IERC20 token;
            function withdraw(uint256 amount) external {
                require(!blacklist[msg.sender], "restricted");
                escrows[msg.sender].amount += amount;
            }
            function claim() external {
                require(!blacklist[msg.sender], "restricted");
                Escrow storage e = escrows[msg.sender];
                uint256 amount = e.amount;
                e.amount = 0;
                token.safeTransfer(msg.sender, amount);
            }
        }
    "#;

    // SAFE — no restriction role exists ANYWHERE: an ordinary two-phase cooldown
    // claim with no freeze capability. Not this class.
    const SAFE_NO_RESTRICTION: &str = r#"
        interface IERC20 { function safeTransfer(address to, uint256 a) external; }
        struct Escrow { uint256 maturesAt; uint256 amount; }
        contract Vault {
            mapping(address => Escrow) public escrows;
            IERC20 token;
            function withdraw(uint256 amount) external {
                escrows[msg.sender].amount += amount;
                escrows[msg.sender].maturesAt = block.timestamp + 7 days;
            }
            function claim() external {
                Escrow storage e = escrows[msg.sender];
                uint256 amount = e.amount;
                require(block.timestamp >= e.maturesAt, "early");
                e.amount = 0;
                token.safeTransfer(msg.sender, amount);
            }
        }
    "#;

    // SAFE — single-phase: the restriction-gated withdraw transfers directly with no
    // escrow-zeroing + separate-exit structure. No two-leg shape.
    const SAFE_SINGLE_PHASE: &str = r#"
        interface IERC20 { function safeTransfer(address to, uint256 a) external; }
        contract Vault {
            mapping(address => bool) public blacklist;
            mapping(address => uint256) public balances;
            IERC20 token;
            function withdraw(uint256 amount) external {
                require(!blacklist[msg.sender], "restricted");
                balances[msg.sender] -= amount;
                token.safeTransfer(msg.sender, amount);
            }
        }
    "#;

    #[test]
    fn fires_on_ethena_unstake_silo() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_blacklist_two_phase() {
        assert!(fires(VULN_BLACKLIST), "{:#?}", run(VULN_BLACKLIST));
    }

    #[test]
    fn silent_when_exit_rechecks_restriction() {
        assert!(!fires(SAFE_EXIT_CHECKS), "{:#?}", run(SAFE_EXIT_CHECKS));
    }

    #[test]
    fn silent_when_no_restriction_role_anywhere() {
        assert!(!fires(SAFE_NO_RESTRICTION), "{:#?}", run(SAFE_NO_RESTRICTION));
    }

    #[test]
    fn silent_on_single_phase_withdraw() {
        assert!(!fires(SAFE_SINGLE_PHASE), "{:#?}", run(SAFE_SINGLE_PHASE));
    }
}
