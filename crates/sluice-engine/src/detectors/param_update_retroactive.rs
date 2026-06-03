//! Retroactive risk-parameter update: a privileged setter rewrites a *global*
//! risk parameter (collateral-factor / LTV / liquidation-threshold / interest
//! rate / fee) that the health / liquidation / accrual path reads **live** for
//! every standing position, with no per-position snapshot and no
//! timelock / grace / migration.
//!
//! ## The class
//!
//! A lending market stores a single, contract-wide risk knob — e.g.
//! `liquidationLtv`, `collateralFactor`, `interestRateWad`, `liquidationThreshold`
//! — and reads it directly when it decides whether a position is liquidatable,
//! how much can be borrowed, or how much debt has accrued. If an
//! `onlyOwner` / role-gated setter assigns that knob a new value and **every
//! existing position is immediately measured against the new value**, the change
//! is *retroactive*: positions that were healthy a block ago are now underwater
//! and instantly liquidatable, and accrued debt reprices against a parameter the
//! borrower never agreed to. There is no grace period for users to top up
//! collateral or unwind, and no snapshot of the old value that standing positions
//! continue to be judged by.
//!
//! The safe shapes this must stay silent on:
//!   * **Snapshot-at-open** — each position records the parameter value in force
//!     when it was opened (`position.collateralFactor = collateralFactor`) and is
//!     forever judged by *that* snapshot, so a later setter only affects new
//!     positions.
//!   * **Accrue-then-change** — the setter first forces a global checkpoint /
//!     interest accrual at the *old* rate before writing the new one (the
//!     `_globalStateRW()` / `accrue()` / `updateIndex()` call), so already-accrued
//!     debt is crystallised under the parameter that produced it. (Olympus
//!     `MonoCooler.setInterestRateWad` does exactly this — it must NOT fire.)
//!   * **Timelock / grace** — the setter is delayed (a timelock modifier, a
//!     `pending*` two-step, or a grace window before the new value takes effect).
//!
//! ## What we fire on
//!
//! A function that (a) is externally reachable, state-mutating, and **access
//! controlled** (an admin/role/owner setter — a permissionless write is a
//! different bug, access-control, not this one); (b) writes a *settable*
//! (non-constant / non-immutable) state variable whose name is a recognised risk
//! parameter; (c) where that same variable is **read by a health / liquidation /
//! accrual routine** of the same contract (so the new value flows into every
//! position's solvency test); and (d) the setter does **not** accrue/checkpoint
//! first, snapshot the old value per position, or sit behind a timelock/grace.
//!
//! Real target: Olympus `MonoCooler.setLtvOracle` — repoints `ltvOracle`, whose
//! `currentLtvs()` feed `liquidationLtv` / `maxOriginationLtv` into
//! `_computeLiquidity` for *all* accounts, with no per-account LTV snapshot and no
//! grace; while the sibling `setInterestRateWad` (which calls `_globalStateRW()`
//! first) is correctly suppressed.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{Contract, Function};

use super::prelude::*;

pub struct ParamUpdateRetroactiveDetector;

/// State-variable name fragments naming a *risk* parameter — a knob that governs
/// whether a position is solvent / liquidatable or how its debt accrues. These
/// are the values that, applied retroactively, instantly reprice standing
/// positions. Deliberately scoped to risk knobs (not every admin-settable var):
/// a fee/treasury/pause toggle that does not feed a health test is out of class.
const RISK_PARAM_MARKERS: &[&str] = &[
    "ltv", // loan-to-value (origination & liquidation)
    "loantovalue",
    "collateralfactor",
    "collateral_factor",
    "collateralratio",
    "liquidationthreshold",
    "liquidation_threshold",
    "liquidationltv",
    "liquidationratio",
    "maintenancemargin",
    "marginratio",
    "interestrate",
    "interest_rate",
    "borrowrate",
    "ratemodel",
    "interestmodel",
    "ratlimit", // (rate limiters that gate borrow capacity)
    "ltvoracle", // a repointable oracle that *serves* the LTV is itself the knob
    "riskparam",
];

/// Fragments that, when they appear in the *function or var name* of a routine
/// that READS the risk param, evidence that the read is on the health /
/// liquidation / accrual path applied to positions — i.e. the new value will be
/// measured against existing positions.
const HEALTH_PATH_MARKERS: &[&str] = &[
    "liquidat",
    "health",
    "solvenc",
    "computeliquidity",
    "currentltv",
    "calculateltv",
    "isundercollateralized",
    "undercollateralized",
    "shortfall",
    "borrow",
    "accountdebt",
    "currentdebt",
    "accrue",
    "checkpoint",
    "globalstate",
    "initglobalstate",
    "updateindex",
    "_position",
    "maxdebt",
    "validateorigination",
];

/// Markers (in the setter source or its modifiers) that evidence a
/// timelock / grace / pending two-step — a delay before the new value bites.
const TIMELOCK_MARKERS: &[&str] = &[
    "timelock",
    "pending",
    "queue",
    "grace",
    "effectiveat",
    "effective_at",
    "activationtime",
    "scheduled",
    "delay",
    "cooldown",
    "targettime", // glide-path / rate-of-change setters (CoolerLtvOracle.setOriginationLtvAt)
    "rateofchange",
    "ratelimit",
];

/// Markers that evidence the setter accrues / checkpoints global state at the
/// OLD value before writing the new one (the safe `accrue-then-change` shape),
/// either as an internal-call name or a substring of the setter source.
const ACCRUE_FIRST_MARKERS: &[&str] = &[
    "accrue",
    "checkpoint",
    "updateindex",
    "_update",
    "updatepool",
    "globalstaterw",
    "_globalstaterw",
    "syncstate",
    "settle",
    "refresh",
    "harvest",
];

impl Detector for ParamUpdateRetroactiveDetector {
    fn id(&self) -> &'static str {
        "param-update-retroactive"
    }
    fn category(&self) -> Category {
        Category::ParamUpdateRetroactive
    }
    fn description(&self) -> &'static str {
        "Admin setter changes a global risk parameter (LTV/collateral-factor/rate/fee) that applies retroactively to existing positions (no snapshot/grace)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for c in cx.scir.iter_contracts() {
            // Only concrete contracts have a real liquidation/accrual path; an
            // interface declaration has nothing to apply retroactively.
            if !c.is_concrete() {
                continue;
            }

            // The contract must look like a lending / risk-bearing market: it has
            // a health / liquidation / accrual routine at all. Without one, a
            // risk-named var has no position-solvency path to retroactively
            // reprice (this keeps us off generic config setters elsewhere).
            if !contract_has_health_path(cx, c) {
                continue;
            }

            // If positions snapshot a risk parameter at open (a per-position field
            // whose name is a risk knob, written on a borrow/open/deposit path),
            // then a later setter only governs new positions — the entire class is
            // mitigated for this contract. Suppress.
            if positions_snapshot_param(cx, c) {
                continue;
            }

            for f in cx.scir.functions_of(c.id) {
                if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
                    continue;
                }

                // (a) Privileged setter. A *permissionless* write of a risk param
                //     is an access-control bug, not this class; require admin/role
                //     gating so we report the retroactive-application hazard of an
                //     *intended* governance action.
                if !cx.has_access_control(f) {
                    continue;
                }

                // (b) It writes a settable risk-parameter state variable.
                let Some(param_var) = written_risk_param(c, f) else { continue };

                // (c) That same variable is read by a health / liquidation /
                //     accrual routine of this contract (so the new value flows into
                //     every position's solvency test / debt accrual).
                if !param_read_on_health_path(cx, c, f.id, &param_var) {
                    continue;
                }

                // ---- false-positive suppression ----
                let src = cx.source_text(f.span);

                // (d0) Monotonic safe-direction guard on a SCALAR param. If the
                //      written param is a plain value type (uint/int/bool/…) and the
                //      setter constrains the new value relative to the *current*
                //      stored value or a max/min bound with a revert (e.g.
                //      `if (premiumBps < liquidationLtvPremiumBps) revert
                //      CannotDecreaseLtv()`), the param can only move in the
                //      position-safening direction — raising a liquidation LTV /
                //      collateral factor can never make a standing position
                //      liquidatable. That monotonic constraint is itself the
                //      mitigation, so suppress.
                //
                //      We deliberately do NOT apply this to an ADDRESS / interface
                //      typed param (an oracle/registry repoint). A one-time check of
                //      the values *served* by the new pointer at swap time does not
                //      bind the new contract's future trajectory — the values it
                //      serves are read live forever with no snapshot — so an
                //      oracle repoint stays in class even with such a check (the
                //      `MonoCooler.setLtvOracle` shape).
                if is_scalar_param_type(c, &param_var) && setter_has_direction_guard(f, &src, &param_var) {
                    continue;
                }

                // (d1) Timelock / grace / pending two-step before it bites.
                if TIMELOCK_MARKERS.iter().any(|m| src.contains(m))
                    || f.modifiers.iter().any(|m| {
                        let l = m.name.to_ascii_lowercase();
                        TIMELOCK_MARKERS.iter().any(|t| l.contains(t))
                    })
                {
                    continue;
                }

                // (d2) Accrue-then-change: the setter forces a global checkpoint /
                //      interest accrual at the OLD value before writing the new
                //      one, so already-accrued debt is crystallised under the
                //      parameter that produced it. This is the safe shape that
                //      `MonoCooler.setInterestRateWad` (calls `_globalStateRW()`
                //      first) uses — it must stay silent.
                if setter_accrues_first(f, &src) {
                    continue;
                }

                let span = param_write_span(f, &param_var).unwrap_or(f.span);

                let b = report!(self, Category::ParamUpdateRetroactive,
                    title = "Risk parameter change applies retroactively to existing positions",
                    severity = Severity::Medium,
                    confidence = 0.6,
                    dimensions = [Dimension::Invariant],
                    message = format!(
                        "`{}` is an access-controlled setter that overwrites the global risk parameter \
                         `{}`, which the contract's health / liquidation / accrual path reads live for \
                         *every* position — with no per-position snapshot of the prior value and no \
                         timelock / grace / accrual-first. Changing `{}` therefore reprices all standing \
                         positions instantly: a position that was healthy a block ago can become \
                         immediately liquidatable, and accrued debt is repriced against a parameter the \
                         borrower never opted into. (E.g. raising a liquidation LTV / collateral factor / \
                         interest rate with no migration window.)",
                        f.name, param_var, param_var
                    ),
                    recommendation =
                        "Apply the new risk parameter only to positions opened after the change \
                         (snapshot the value into each position at open and judge it by that snapshot), \
                         OR force a global accrual / checkpoint at the old value before writing the new \
                         one, AND gate the change behind a timelock / grace window so borrowers can top \
                         up collateral or unwind before it takes effect. Avoid letting a single setter \
                         instantly reprice the solvency of every standing position.",
                );
                out.push(finish_at(cx, b, f.id, span));
            }
        }
        out
    }
}

// ------------------------------------------------------------------- helpers

/// A name fragment is a recognised risk parameter.
fn name_is_risk_param(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    RISK_PARAM_MARKERS.iter().any(|m| l.contains(m))
}

/// A function name reads as a health / liquidation / accrual routine.
fn name_is_health_path(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    HEALTH_PATH_MARKERS.iter().any(|m| l.contains(m))
}

/// The contract declares at least one function that looks like a health /
/// liquidation / accrual routine — the precondition for there being a
/// position-solvency path that a risk-param change could reprice.
fn contract_has_health_path(cx: &AnalysisContext, c: &Contract) -> bool {
    cx.scir.functions_of(c.id).any(|f| f.has_body && name_is_health_path(&f.name))
}

/// The settable risk-parameter state variable this function writes, if any. We
/// only consider *settable* (non-constant / non-immutable) vars — a `constant` /
/// `immutable` knob cannot be re-pointed by governance, so there is nothing
/// retroactive to do.
fn written_risk_param(c: &Contract, f: &Function) -> Option<String> {
    f.effects
        .storage_writes
        .iter()
        .map(|w| w.var.clone())
        .find(|v| name_is_risk_param(v) && is_settable_state_var(c, v))
}

/// Is `param_var` read by some *other* routine of this contract that is on the
/// health / liquidation / accrual path? We treat a read as "on the health path"
/// when the reading function's own name is a health/accrual routine, OR the
/// reading function also reads/computes a liquidation-shaped quantity (its source
/// mentions a health marker). The setter itself is excluded.
fn param_read_on_health_path(
    cx: &AnalysisContext,
    c: &Contract,
    setter: sluice_ir::FunctionId,
    param_var: &str,
) -> bool {
    for g in cx.scir.functions_of(c.id) {
        if g.id == setter || !g.has_body {
            continue;
        }
        if !g.effects.reads_var(param_var) {
            continue;
        }
        // A *privileged config setter* that merely reads the param (or a bound)
        // to validate another write is NOT the liquidation/accrual path — e.g.
        // `setLiquidationLtvPremiumBps` reading `maxLiquidationLtvPremiumBps` as a
        // cap. Exclude any access-controlled function that itself writes a risk
        // param, so a bound read by a sibling setter is not mistaken for a health
        // read.
        if is_privileged_param_setter(cx, c, g) {
            continue;
        }
        // The reader is on the health path if its name says so, or its body
        // textually performs a liquidation/health/accrual computation.
        if name_is_health_path(&g.name) {
            return true;
        }
        let gsrc = cx.source_text(g.span);
        if HEALTH_PATH_MARKERS.iter().any(|m| gsrc.contains(m)) {
            return true;
        }
    }
    false
}

/// A function is a privileged config setter: access-controlled and writes a
/// risk-parameter state var. Such a function reading a (bound) value is config
/// validation, not the health/accrual path.
fn is_privileged_param_setter(cx: &AnalysisContext, c: &Contract, g: &Function) -> bool {
    if !g.is_state_mutating() || !cx.has_access_control(g) {
        return false;
    }
    g.effects
        .storage_writes
        .iter()
        .any(|w| name_is_risk_param(&w.var) && is_settable_state_var(c, &w.var))
}

/// Is `param_var` declared with a plain *value* type (uint/int/bool/bytes/
/// address-of-value) rather than an address / interface / contract pointer? A
/// scalar value can be bound forever by a monotonic guard; a repointable
/// oracle/registry handle cannot (its served values are unconstrained going
/// forward). `address` is treated as address-like (a repoint), not scalar.
fn is_scalar_param_type(c: &Contract, param_var: &str) -> bool {
    let Some(v) = c.state_vars.iter().find(|v| v.name == param_var) else { return false };
    let ty = v.ty.to_ascii_lowercase();
    // Address / interface / contract handles are NOT scalar.
    if ty.contains("address") || ty.contains("oracle") || ty.contains("registry") {
        return false;
    }
    // An uppercase-`I`-prefixed or otherwise capitalized custom type in the
    // ORIGINAL casing usually denotes an interface/contract (`ICoolerLtvOracle`).
    // Use the original-cased type for that test.
    let orig = &v.ty;
    let looks_like_interface = orig
        .chars()
        .next()
        .map(|ch| ch.is_ascii_uppercase())
        .unwrap_or(false)
        && !orig.starts_with("OriginationLtvData"); // a plain value-struct, still scalar-ish
    if looks_like_interface && !is_value_struct_type(&ty) {
        return false;
    }
    // Plain value types.
    ty.starts_with("uint")
        || ty.starts_with("int")
        || ty == "bool"
        || ty.starts_with("bytes")
        || ty.starts_with("string")
        || is_value_struct_type(&ty)
}

/// A struct type that bundles plain values (a per-config struct), still subject
/// to a monotonic / glide guard. Conservatively: any non-mapping type we did not
/// already classify as an address/interface.
fn is_value_struct_type(ty: &str) -> bool {
    !ty.contains("mapping") && !ty.contains("address") && !ty.contains("[]")
        && (ty.contains("data") || ty.contains("config") || ty.contains("params") || ty.contains("info"))
}

/// The setter constrains the new value relative to the *current* stored param or
/// a `max<Param>` / `min<Param>` bound, with a revert — the monotonic / bounded
/// "can only move in the safe direction" guard (`if (premiumBps <
/// liquidationLtvPremiumBps) revert CannotDecreaseLtv()`). Such a guard makes a
/// scalar risk knob unable to reprice a standing position into insolvency, so it
/// is the mitigation for this class.
///
/// Detected as: the function reads the same risk-param var it writes (reading the
/// prior value to bound the new one) **and** there is a guard/revert in the body
/// (a `require`/`assert`, an `if (...) revert`, or a `cannotDecrease` /
/// `cannotIncrease` / `onlyIncrease` / `CannotLower` token). A bare self-read
/// without any guard (e.g. `x = x + delta`) does not qualify.
fn setter_has_direction_guard(f: &Function, src: &str, param_var: &str) -> bool {
    if !f.effects.reads_var(param_var) {
        return false;
    }
    // Guard present: a require/assert/if-revert in the body, or an explicit
    // direction token in a custom error / function logic.
    let has_revert_guard = f.body.iter().any(|s| {
        let mut hit = false;
        s.visit(&mut |st| {
            if matches!(&st.kind, sluice_ir::StmtKind::Revert { .. }) {
                hit = true;
            }
        });
        hit
    }) || any_call_where(f, is_require_or_assert);
    let has_direction_token = ["cannotdecrease", "cannotincrease", "cannotlower", "cannotraise", "onlyincrease", "onlydecrease", "monoton"]
        .iter()
        .any(|t| src.contains(t));
    has_revert_guard || has_direction_token
}

/// Does any position record a risk parameter at open — a per-position field
/// (a mapping/struct member) whose name is a risk knob, written on an
/// open/borrow/deposit path? If so the parameter is snapshotted and a later
/// setter only governs new positions (class mitigated). Heuristic and
/// deliberately broad on the suppression side.
///
/// Two signals (either suffices), because a write through a `storage` pointer
/// alias (`Position storage p = positions[id]; p.collateralFactor = ...`) is NOT
/// recorded as a storage write (its root is a local), so we cannot rely on the
/// effect summary alone:
///   * a recorded storage WRITE whose access path is position-keyed (`[`) to a
///     risk-named member (`positions[id].collateralFactor = ...` written
///     directly); or
///   * the opener's source assigns a risk-named *member* (`....collateralFactor
///     = ...`) — the snapshot-copy idiom, which captures the storage-pointer
///     alias case.
fn positions_snapshot_param(cx: &AnalysisContext, c: &Contract) -> bool {
    for f in cx.scir.functions_of(c.id) {
        if !f.has_body || !f.is_state_mutating() {
            continue;
        }
        // Only consider position-opening style entrypoints (open / borrow /
        // deposit / mint / createPosition), where a snapshot would be taken.
        let l = f.name.to_ascii_lowercase();
        let opens_position = l.contains("open")
            || l.contains("borrow")
            || l.contains("deposit")
            || l.contains("mint")
            || l.contains("createposition")
            || l.contains("addcollateral");
        if !opens_position {
            continue;
        }
        // Signal 1: a directly-recorded keyed write to a risk-named member.
        for w in &f.effects.storage_writes {
            let path = w.path.to_ascii_lowercase();
            if path.contains('[') && (name_is_risk_param(&w.var) || path_member_is_risk_param(&path))
            {
                return true;
            }
        }
        // Signal 2: the opener assigns a risk-named member (the snapshot copy),
        // e.g. `p.collateralFactor = collateralFactor;` through a storage alias.
        if source_assigns_risk_member(&cx.source_text(f.span)) {
            return true;
        }
    }
    false
}

/// The trailing member of a keyed access path names a risk parameter
/// (`positions[id].collateralFactor`). `w.var` is the base mapping name, which is
/// usually generic (`positions`), so we also inspect the member tail.
fn path_member_is_risk_param(path: &str) -> bool {
    // Take the substring after the last '.' (the member), if any.
    let member = path.rsplit('.').next().unwrap_or(path);
    RISK_PARAM_MARKERS.iter().any(|m| member.contains(m))
}

/// Best-effort: the (lowercased, comment-stripped) source assigns a *member*
/// whose name is a risk parameter — `<base>.<riskparam> = ...` (not `==`). This
/// captures the snapshot-copy idiom written through a `storage` pointer alias,
/// which the effect summary does not record as a storage write. We require a
/// preceding `.` so this matches a struct/member field, not a bare global setter
/// (`collateralFactor =`), which is exactly the retroactive write we DO want to
/// fire on elsewhere.
fn source_assigns_risk_member(src: &str) -> bool {
    let bytes = src.as_bytes();
    for marker in RISK_PARAM_MARKERS {
        let mut from = 0;
        while let Some(rel) = src[from..].find(marker) {
            let start = from + rel;
            from = start + marker.len();
            // Must be a member access: a '.' immediately precedes the marker
            // (allowing the marker to be the field name). Scan back over any
            // trailing field chars first — we want `.<...marker...>`.
            // Find the start of the identifier the marker is part of.
            let mut id_start = start;
            while id_start > 0 {
                let ch = bytes[id_start - 1];
                if ch == b'_' || ch.is_ascii_alphanumeric() {
                    id_start -= 1;
                } else {
                    break;
                }
            }
            let is_member = id_start > 0 && bytes[id_start - 1] == b'.';
            if !is_member {
                continue;
            }
            // Find the end of the identifier and the next non-space char.
            let mut i = from;
            while i < bytes.len() && (bytes[i] == b'_' || bytes[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'=' {
                let is_eq_eq = i + 1 < bytes.len() && bytes[i + 1] == b'=';
                if !is_eq_eq {
                    return true;
                }
            }
        }
    }
    false
}

/// The setter forces a global accrual / checkpoint at the OLD parameter value
/// before writing the new one (the safe `accrue-then-change` shape). Detected by
/// an internal-call name or a source substring naming an accrual/checkpoint
/// routine. We additionally require the accrual to read like a *global* state
/// sync (not merely the setter's own name), which the markers encode.
fn setter_accrues_first(f: &Function, src: &str) -> bool {
    // An internal call to an accrual/checkpoint routine.
    if f.effects
        .internal_calls
        .iter()
        .any(|n| {
            let l = n.to_ascii_lowercase();
            ACCRUE_FIRST_MARKERS.iter().any(|m| l.contains(m))
        })
    {
        return true;
    }
    // A source-level call the effect summary didn't resolve as internal (e.g. a
    // module call `MODULE.accrue()` / `_globalStateRW()`), excluding the setter's
    // own name from matching itself.
    let fname = f.name.to_ascii_lowercase();
    ACCRUE_FIRST_MARKERS.iter().any(|m| src.contains(m) && !fname.contains(m))
}

/// Span of the first storage write to `param_var` (precise report location).
fn param_write_span(f: &Function, param_var: &str) -> Option<sluice_ir::Span> {
    f.effects
        .storage_writes
        .iter()
        .filter(|w| w.var == param_var)
        .min_by_key(|w| w.order)
        .map(|w| w.span)
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fired(fs: &[sluice_findings::Finding]) -> bool {
        fs.iter().any(|f| f.detector == "param-update-retroactive")
    }

    // VULN: an admin setter overwrites the global `liquidationThreshold`, which
    // `liquidate` reads live for every borrower. No snapshot, no grace, no
    // accrual-first. Raising the threshold instantly makes standing positions
    // liquidatable.
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        contract Lending {
            mapping(address => uint256) public collateral;
            mapping(address => uint256) public debt;
            uint256 public liquidationThreshold = 0.8e18; // global risk knob
            address public owner;
            uint256 public price = 1e18;

            modifier onlyOwner() { require(msg.sender == owner, "auth"); _; }

            function setLiquidationThreshold(uint256 newThreshold) external onlyOwner {
                liquidationThreshold = newThreshold;
            }

            function healthy(address user) public view returns (bool) {
                if (debt[user] == 0) return true;
                uint256 ltv = debt[user] * 1e18 / (collateral[user] * price / 1e18);
                return ltv <= liquidationThreshold;
            }

            function liquidate(address user) external {
                require(!healthy(user), "still healthy");
                uint256 seized = collateral[user];
                collateral[user] = 0;
                debt[user] = 0;
                // pay liquidator seized ...
            }
        }
    "#;

    // SAFE (snapshot-at-open): each position records the collateralFactor in force
    // when it was opened and is judged by that snapshot, so a later setter only
    // affects new positions.
    const SAFE_SNAPSHOT: &str = r#"
        pragma solidity ^0.8.20;
        contract Lending {
            struct Position { uint256 collateral; uint256 debt; uint256 collateralFactor; }
            mapping(address => Position) public positions;
            uint256 public collateralFactor = 0.8e18; // current global knob
            address public owner;
            uint256 public price = 1e18;

            modifier onlyOwner() { require(msg.sender == owner, "auth"); _; }

            function setCollateralFactor(uint256 newFactor) external onlyOwner {
                collateralFactor = newFactor;
            }

            function borrow(uint256 amount) external {
                Position storage p = positions[msg.sender];
                // snapshot the parameter in force at open
                p.collateralFactor = collateralFactor;
                p.debt += amount;
            }

            function liquidate(address user) external {
                Position storage p = positions[user];
                uint256 ltv = p.debt * 1e18 / p.collateral;
                require(ltv > p.collateralFactor, "healthy"); // judged by snapshot
                p.collateral = 0;
                p.debt = 0;
            }
        }
    "#;

    // SAFE (accrue-then-change): the interest-rate setter forces a global accrual
    // checkpoint at the OLD rate before writing the new one, so accrued debt is
    // crystallised under the rate that produced it (the MonoCooler.setInterestRateWad
    // shape).
    const SAFE_ACCRUE_FIRST: &str = r#"
        pragma solidity ^0.8.20;
        contract Lending {
            mapping(address => uint256) public debt;
            uint256 public interestRate = 0.05e18; // global risk knob
            uint256 public interestIndex = 1e18;
            uint256 public lastAccrual;
            address public owner;

            modifier onlyOwner() { require(msg.sender == owner, "auth"); _; }

            function accrue() public {
                interestIndex += interestIndex * interestRate / 1e18;
                lastAccrual = block.timestamp;
            }

            function setInterestRate(uint256 newRate) external onlyOwner {
                accrue(); // crystallise accrued debt at the OLD rate first
                interestRate = newRate;
            }

            function borrow(uint256 amount) external {
                accrue();
                debt[msg.sender] += amount;
            }
        }
    "#;

    // SAFE (timelock): the setter is delayed behind a pending two-step / timelock,
    // so borrowers have a grace window before the new value takes effect.
    const SAFE_TIMELOCK: &str = r#"
        pragma solidity ^0.8.20;
        contract Lending {
            mapping(address => uint256) public collateral;
            mapping(address => uint256) public debt;
            uint256 public liquidationThreshold = 0.8e18;
            uint256 public pendingLiquidationThreshold;
            uint256 public pendingEffectiveAt;
            address public owner;

            modifier onlyOwner() { require(msg.sender == owner, "auth"); _; }

            function queueLiquidationThreshold(uint256 newThreshold) external onlyOwner {
                pendingLiquidationThreshold = newThreshold;
                pendingEffectiveAt = block.timestamp + 2 days; // grace window
            }

            function liquidate(address user) external {
                uint256 ltv = debt[user] * 1e18 / collateral[user];
                require(ltv > liquidationThreshold, "healthy");
                collateral[user] = 0;
                debt[user] = 0;
            }
        }
    "#;

    // SAFE (permissionless / no access control): a setter with no auth is an
    // access-control bug, not this retroactive-application class — we stay silent
    // and let the access-control detector own it.
    const SAFE_NO_AUTH: &str = r#"
        pragma solidity ^0.8.20;
        contract Lending {
            mapping(address => uint256) public collateral;
            mapping(address => uint256) public debt;
            uint256 public liquidationThreshold = 0.8e18;

            function setLiquidationThreshold(uint256 newThreshold) external {
                liquidationThreshold = newThreshold;
            }

            function liquidate(address user) external {
                uint256 ltv = debt[user] * 1e18 / collateral[user];
                require(ltv > liquidationThreshold, "healthy");
                collateral[user] = 0;
                debt[user] = 0;
            }
        }
    "#;

    // SAFE (non-risk param): an admin setter for a non-risk config var (a fee
    // recipient address) is out of class even though it's admin-gated.
    const SAFE_NONRISK: &str = r#"
        pragma solidity ^0.8.20;
        contract Lending {
            mapping(address => uint256) public collateral;
            mapping(address => uint256) public debt;
            uint256 public liquidationThreshold = 0.8e18;
            address public feeRecipient;
            address public owner;

            modifier onlyOwner() { require(msg.sender == owner, "auth"); _; }

            function setFeeRecipient(address r) external onlyOwner {
                feeRecipient = r;
            }

            function liquidate(address user) external {
                uint256 ltv = debt[user] * 1e18 / collateral[user];
                require(ltv > liquidationThreshold, "healthy");
                collateral[user] = 0;
                debt[user] = 0;
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fired(&fs), "{:#?}", fs);
    }

    #[test]
    fn silent_on_snapshot() {
        assert!(!fired(&run(SAFE_SNAPSHOT)));
    }

    #[test]
    fn silent_on_accrue_first() {
        assert!(!fired(&run(SAFE_ACCRUE_FIRST)));
    }

    #[test]
    fn silent_on_timelock() {
        assert!(!fired(&run(SAFE_TIMELOCK)));
    }

    #[test]
    fn silent_without_access_control() {
        assert!(!fired(&run(SAFE_NO_AUTH)));
    }

    #[test]
    fn silent_on_nonrisk_param() {
        assert!(!fired(&run(SAFE_NONRISK)));
    }
}
