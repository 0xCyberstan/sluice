//! Percent-slash on a live base — a queued-slashing *finalize* whose realized
//! loss is a **stored percentage** multiplied by a **live aggregate read taken at
//! settle time**, so the actual amount burned depends on deposits/withdrawals that
//! happen during the request→finalize veto window.
//!
//! ## The shape
//!
//! A two-step slashing flow queues a slash request (`requestSlashing`) carrying a
//! *percentage* (a WAD/bps fraction) and a veto window, then later settles it
//! (`finalizeSlashing`). The settle path:
//!
//!   1. **validates the queued request via a root/hash membership check** — it
//!      recomputes a commitment (`keccak256`/`calculateRoot`) over the request and
//!      asserts that root is still registered (`if (!slashingRequests[root])
//!      revert`). This is what proves the request was genuinely queued and not yet
//!      finalized — the marker of a two-step queue rather than a one-shot slash;
//!   2. computes the hit as `storedPct.mulDiv(liveAggregate(), MAX)` — a **stored**
//!      percentage times a **live** pool aggregate (`totalAssets()` /
//!      `balanceOf(this)` / `totalSupply()`) read *at finalize time*, divided by a
//!      precision constant.
//!
//! Because the aggregate is read live at settle and only the *fraction* was fixed
//! at request, the realized loss is `pct * totalAssets_at_finalize / MAX`, not
//! `pct * totalAssets_at_request / MAX`. During the veto window the operator (or
//! anyone) can deposit to inflate `totalAssets()` and over-slash, or withdraw to
//! shrink it and under-slash — the slash magnitude is not what was committed. This
//! is exactly **Karak `SlasherLib`**: `finalizeSlashing` checks
//! `self.slashingRequests[slashRoot]` then calls `computeSlashAmount` →
//! `Math.mulDiv(slashPercentageWad, IKarakBaseVault(vault).totalAssets(),
//! Constants.MAX_SLASHING_PERCENT_WAD)`.
//!
//! ```solidity
//! function computeSlashAmount(address vault, uint256 slashPercentageWad) internal view returns (uint256) {
//!     return Math.mulDiv(slashPercentageWad, IKarakBaseVault(vault).totalAssets(), Constants.MAX_SLASHING_PERCENT_WAD);
//! }                                          // ^stored pct          ^LIVE read at settle      ^MAX
//! function finalizeSlashing(CoreLib.Storage storage self, QueuedSlashing memory q) internal {
//!     bytes32 slashRoot = calculateRoot(q);
//!     if (!self.slashingRequests[slashRoot]) revert InvalidSlashingParams();   // root membership gate
//!     ...
//!     uint256 slashAmount = computeSlashAmount(q.vaults[i], q.slashPercentagesWad[i]); // pct * live / MAX
//! }
//! ```
//!
//! ## Precision anchors (all required)
//!
//!   * **finalize-name gate**: the function name reads as a settle of a slash
//!     (`finaliz|complete|execute|settle|process|apply` + `slash`). This rules out
//!     `requestSlashing` (a request, captured at *that* moment) and `cancelSlashing`
//!     (no payout). Plain pricing views are excluded since the function must be
//!     state-mutating.
//!   * **root/hash membership gate** in the function's *own* body: a revert-guarded
//!     read of a request/queue/root-registry mapping by a hash/root key (or a
//!     `calculateRoot`/`keccak256`-derived commitment). This is the proof of a
//!     *queued* request and, crucially, selects the library `finalizeSlashing`
//!     (which performs the check) over a thin external wrapper that merely delegates.
//!   * **percent × live-base computation** reachable from the function (its own body
//!     **or a directly-called internal helper**, the `computeSlashAmount` indirection):
//!     a `mulDiv(pct, base, MAX)` (or inline `pct * base / MAX`) where `base`
//!     **contains a live aggregate *call*** — `totalAssets()` / `balanceOf(...)` /
//!     `totalSupply()` / `getReserves()` / `getTotalPooled*()` — and `pct` is a
//!     *stored / parameter* value (not itself a live read).
//!
//! ## Suppression
//!
//!   * **absolute amount captured at request**: if the numerator base is a plain
//!     stored value (a struct field / variable, *no* live call), the loss was fixed
//!     at request — there is no live-base anchor and nothing fires.
//!   * **captured `*At(ts)` snapshot accessor**: if the base read is a historical
//!     accessor (`totalAssetsAt`, `balanceOfAt`, `getPastTotalSupply`,
//!     `getPastVotes`, any `…At(…)` / `getPast…`), the aggregate is the value *at a
//!     captured timestamp*, not live — suppressed.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Call, Expr, ExprKind, Function, Span, StmtKind};

use super::prelude::*;

pub struct PercentSlashOnLiveBaseDetector;

impl Detector for PercentSlashOnLiveBaseDetector {
    fn id(&self) -> &'static str {
        "percent-slash-live-base"
    }
    fn category(&self) -> Category {
        Category::PercentSlashOnLiveBase
    }
    fn description(&self) -> &'static str {
        "Queued-slashing finalize computes the hit as a stored percentage times a live aggregate read at \
         settle time, so the realized loss depends on deposits/withdrawals during the veto window \
         (Karak SlasherLib computeSlashAmount class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.functions() {
            // Only a concrete, state-mutating settle path can both gate on a queued
            // request and trigger the live-base computation. View/pure helpers and
            // bare interface declarations cannot.
            if !f.has_body || f.is_view_or_pure() {
                continue;
            }
            // Interfaces declare no settle logic. (Libraries / concrete contracts
            // are both in scope — the real target is a `library`.)
            let Some(contract) = cx.contract_of(f.id) else { continue };
            if contract.is_interface() {
                continue;
            }

            // (1) finalize-of-a-slash name gate.
            if !is_finalize_slash_name(&f.name) {
                continue;
            }

            // (2) root/hash membership gate in this function's OWN body — proves a
            // queued two-step request and selects the function that performs the
            // check (not a wrapper that merely forwards to it).
            if !has_root_membership_gate(f) {
                continue;
            }

            // (3) the percent × live-base computation, reachable from this function
            // (own body or a directly-called internal helper such as
            // `computeSlashAmount`). Capture the live-read name for the message.
            let Some(hit) = find_percent_live_base(cx, f) else { continue };

            let b = report!(self, Category::PercentSlashOnLiveBase,
                title = "Slashing finalize applies a stored percentage to a live aggregate read at settle time",
                severity = Severity::High,
                // Three independent structural anchors (finalize-of-slash name, an
                // own-body root/hash membership gate, and a `pct × live-aggregate /
                // MAX` computation with both suppression arms) make this a tight,
                // high-confidence match — it surfaces as a High label (single
                // Invariant dimension): 70 × (0.5 + 0.5·0.78) = 62.3 ≥ 62.
                confidence = 0.78,
                dimensions = [Dimension::Invariant],
                message = format!(
                    "`{fname}` validates a queued slashing request via a root/hash membership check and \
                     then computes the slash as a **stored percentage** times a **live** pool aggregate \
                     read at finalize time (`{base}`), divided by a precision constant \
                     (`pct.mulDiv({base}, MAX)`). The fraction was fixed when the request was queued, but \
                     the base is read live at settlement, so the realized loss is \
                     `pct * {base}_at_finalize / MAX` — not the amount committed at request. During the \
                     request→finalize veto window deposits/withdrawals change `{base}`, so an operator (or \
                     anyone) can deposit to inflate the base and over-slash, or withdraw to shrink it and \
                     under-slash; the slashed magnitude is not what was agreed. This is the Karak \
                     `SlasherLib.computeSlashAmount` percent-on-live-base shape \
                     (`Math.mulDiv(slashPercentageWad, vault.totalAssets(), MAX_SLASHING_PERCENT_WAD)` \
                     reached from `finalizeSlashing`).",
                    fname = f.name,
                    base = hit.live_name,
                ),
                recommendation =
                    "Bind the slash to a value captured at request time rather than a live read at \
                     finalize: snapshot the absolute slashable amount (or the aggregate) into the queued \
                     request struct when `requestSlashing` runs, or read a historical/checkpointed \
                     accessor (`totalAssetsAt(requestTimestamp)` / `getPastTotalSupply(...)`) at finalize \
                     so the realized loss equals `pct * base_at_request / MAX` and cannot be steered by \
                     deposits/withdrawals during the veto window.",
            );
            out.push(finish_at(cx, b, f.id, hit.span));
        }

        out
    }
}

// --------------------------------------------------------------------- analysis

/// A matched percent-on-live-base computation.
struct LiveBaseHit {
    /// Best-effort name of the live aggregate accessor (`totalassets`, `balanceof`).
    live_name: String,
    /// Span of the `mulDiv` / division site (for a precise report location).
    span: Span,
}

/// Settle-of-a-slash name: contains a settle verb AND `slash`. `requestSlashing`
/// (request verb) and `cancelSlashing` (cancel verb) are excluded — neither
/// settles a payout against a live base.
fn is_finalize_slash_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    if !l.contains("slash") {
        return false;
    }
    ["finaliz", "complete", "execute", "settle", "process", "apply", "fulfill", "claim"]
        .iter()
        .any(|verb| l.contains(verb))
}

/// Does `f`'s own body validate a queued request via a root/hash membership
/// check? We look for a revert-guarded read (`if (!X) revert …` / `require(X)`)
/// whose condition reads a *registry-like* mapping indexed by a *hash/root-like*
/// key, or for a commitment recomputation (`calculateRoot` / `keccak256`) whose
/// result later indexes such a registry. Either is the two-step-queue signature.
fn has_root_membership_gate(f: &Function) -> bool {
    // A commitment is recomputed in this body (the classic `bytes32 root =
    // calculateRoot(q)` / `keccak256(abi.encode(q))` preamble).
    let mut builds_commitment = false;
    // A registry-like mapping is read by a root/hash-like key inside a guard.
    let mut gated_registry_read = false;

    for top in &f.body {
        top.visit(&mut |st| {
            match &st.kind {
                // `if (!self.slashingRequests[root]) revert …` — the canonical gate.
                StmtKind::If { cond, .. } if expr_reads_root_registry(cond) => {
                    gated_registry_read = true;
                }
                // `require(self.slashingRequests[root])` / `require(registry[root], …)`.
                StmtKind::Expr(e) | StmtKind::Emit(e) => {
                    e.visit(&mut |sub| {
                        if let ExprKind::Call(c) = &sub.kind {
                            if is_require_or_assert(c) && c.args.iter().any(expr_reads_root_registry) {
                                gated_registry_read = true;
                            }
                            if call_builds_commitment(c) {
                                builds_commitment = true;
                            }
                        }
                    });
                }
                // `bytes32 root = calculateRoot(q);` / `... = keccak256(abi.encode(q));`
                StmtKind::VarDecl { init: Some(e), .. } => {
                    e.visit(&mut |sub| {
                        if let ExprKind::Call(c) = &sub.kind {
                            if call_builds_commitment(c) {
                                builds_commitment = true;
                            }
                        }
                    });
                    if expr_reads_root_registry(e) {
                        gated_registry_read = true;
                    }
                }
                _ => {}
            }
        });
    }

    // A registry read inside a guard is the strongest signal; alternatively a
    // commitment recomputation *and* any registry read in the body together prove
    // the queued-request gate even when the guard shape isn't an `if`/`require`.
    gated_registry_read || (builds_commitment && body_reads_root_registry(f))
}

/// `keccak256(...)` builtin, or a call to a `*Root*` / `*Hash*` / `*Commit*`
/// helper (e.g. `calculateRoot`) — the recomputation of the request commitment.
fn call_builds_commitment(c: &Call) -> bool {
    if is_builtin(c, sluice_ir::Builtin::Keccak256) {
        return true;
    }
    match c.func_name.as_deref() {
        Some(name) => {
            let l = name.to_ascii_lowercase();
            l.contains("root") || l.contains("hash") || l.contains("commit") || l.contains("digest")
        }
        None => false,
    }
}

/// Does any statement in `f`'s body read a registry-like mapping by a root/hash
/// key? (used together with a commitment recomputation as a fallback gate signal).
fn body_reads_root_registry(f: &Function) -> bool {
    for top in &f.body {
        let mut hit = false;
        top.visit_exprs(&mut |e| {
            if expr_reads_root_registry(e) {
                hit = true;
            }
        });
        if hit {
            return true;
        }
    }
    false
}

/// Does `e` contain an indexed read `registry[key]` where `registry` is a
/// request/queue/root-registry-like mapping AND `key` is a root/hash-like value
/// (a `*root*`/`*hash*`/`*commit*`/`*id*` identifier/member, or a
/// `keccak256`/`*Root*` call)? Requiring *both* the registry-name and the
/// root-key shape keeps this from matching ordinary `balances[user]` reads.
fn expr_reads_root_registry(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        let ExprKind::Index { base, index: Some(idx) } = &sub.kind else { return };
        // The mapping (possibly `self.slashingRequests`) must name a request/root
        // registry.
        let Some(reg) = registry_name(base) else { return };
        if !is_request_registry_name(&reg) {
            return;
        }
        if index_is_root_like(idx) {
            found = true;
        }
    });
    found
}

/// Best-effort trailing name of a (possibly member) mapping base:
/// `self.slashingRequests` -> `slashingrequests`, `requests` -> `requests`.
fn registry_name(base: &Expr) -> Option<String> {
    match &base.kind {
        ExprKind::Ident(n) => Some(n.to_ascii_lowercase()),
        ExprKind::Member { member, .. } => Some(member.to_ascii_lowercase()),
        // `a.b[c]` base of an outer index — descend to the inner base's name.
        ExprKind::Index { base, .. } => registry_name(base),
        _ => None,
    }
}

/// Mapping names that hold queued requests / commitments / roots.
fn is_request_registry_name(name: &str) -> bool {
    ["request", "queued", "queue", "pending", "root", "commit", "slashing", "claimroot", "merkle"]
        .iter()
        .any(|m| name.contains(m))
}

/// Is the index key a root/hash-like value — a `*root*`/`*hash*`/`*commit*`/`*id*`
/// identifier or member, or a commitment-building call?
fn index_is_root_like(idx: &Expr) -> bool {
    match &idx.kind {
        ExprKind::Ident(n) => is_root_like_name(n),
        ExprKind::Member { member, .. } => is_root_like_name(member),
        ExprKind::Call(c) => call_builds_commitment(c),
        _ => false,
    }
}

fn is_root_like_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("root") || l.contains("hash") || l.contains("commit") || l.contains("digest") || l == "id"
}

// ---- the percent × live-base computation ----------------------------------

/// Find a `mulDiv(pct, base, max)` / inline `pct * base / max` reachable from `f`
/// (its own body, or the body of any directly-resolved internal callee — the
/// `computeSlashAmount` indirection), where `base` contains a *live* aggregate
/// read and `pct` is a stored / parameter value (not itself a live read).
fn find_percent_live_base(cx: &AnalysisContext, f: &Function) -> Option<LiveBaseHit> {
    if let Some(h) = scan_body_for_live_base(f) {
        return Some(h);
    }
    // One level of internal-callee indirection (the helper that does the math).
    for callee_id in &f.callees {
        let Some(callee) = cx.scir.function(*callee_id) else { continue };
        if !callee.has_body {
            continue;
        }
        if let Some(mut h) = scan_body_for_live_base(callee) {
            // Re-anchor to the call of this helper *inside* `f` so the report points
            // at the finalize body (`computeSlashAmount(...)` site), not the helper's
            // internal `mulDiv`. Fall back to the helper span if the site is opaque.
            if let Some(call_span) = call_site_span_in(f, &callee.name) {
                h.span = call_span;
            }
            return Some(h);
        }
    }
    None
}

/// Span of the first call to an internal helper named `name` within `f`'s body.
fn call_site_span_in(f: &Function, name: &str) -> Option<Span> {
    first_call_where(f, |c| c.func_name.as_deref() == Some(name))
}

/// Scan one function body for the percent-on-live-base computation.
fn scan_body_for_live_base(f: &Function) -> Option<LiveBaseHit> {
    let mut hit: Option<LiveBaseHit> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            match &e.kind {
                // `mulDiv(pct, base, max)` (Math.mulDiv / FullMath.mulDiv / .mulDiv).
                // The third arg is a divisor by the helper's contract, so the
                // percentage + live-base anchors carry the match here.
                ExprKind::Call(c) if is_muldiv(c) && c.args.len() >= 3 => {
                    let pct = &c.args[0];
                    let base = &c.args[1];
                    if is_percent_factor(pct) && !is_live_aggregate_read(pct) {
                        if let Some(live) = live_read_name(base) {
                            hit = Some(LiveBaseHit { live_name: live, span: e.span });
                        }
                    }
                }
                // inline `pct * base / max`: a `Div` whose lhs is a `Mul`. This form
                // is structurally weaker than `mulDiv`, so we additionally require the
                // divisor to look like a fixed precision constant (`MAX`/`WAD`/`1e18`)
                // — that is what makes `pct * base` a *fraction* of the base.
                ExprKind::Binary { op: BinOp::Div, lhs, rhs } => {
                    let max = rhs;
                    if !looks_like_max_denominator(max) {
                        return;
                    }
                    if let ExprKind::Binary { op: BinOp::Mul, lhs: a, rhs: b } = &lhs.kind {
                        // Either factor may be the percentage and the other the base.
                        for (pct, base) in [(a.as_ref(), b.as_ref()), (b.as_ref(), a.as_ref())] {
                            if is_percent_factor(pct) && !is_live_aggregate_read(pct) {
                                if let Some(live) = live_read_name(base) {
                                    hit = Some(LiveBaseHit { live_name: live, span: e.span });
                                    break;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// Is `c` a `mulDiv` / `mulDivDown` / `mulDivUp` call (Math/FullMath/library or
/// bound `.mulDiv`)? Classified purely on the resolved method name.
fn is_muldiv(c: &Call) -> bool {
    match c.func_name.as_deref() {
        Some(name) => {
            let l = name.to_ascii_lowercase();
            l == "muldiv" || l == "muldivdown" || l == "muldivup" || l == "mulwad" || l == "mulwaddown"
        }
        None => false,
    }
}

/// Names of **live** pool aggregates — read fresh from current state. A call to
/// one of these (with no historical/timestamp argument) is the live base.
const LIVE_AGGREGATE_NAMES: &[&str] = &[
    "totalassets",
    "totalsupply",
    "balanceof",
    "getreserves",
    "totalpooledether",
    "gettotalpooledether",
    "totaldeposits",
    "totalstaked",
    "totalshares",
    "totalliquidity",
    "getvirtualprice",
    "underlyingbalance",
    "totalunderlying",
];

/// Names that are **historical / snapshot** accessors — the captured-at-timestamp
/// forms whose presence SUPPRESSES the finding (the base is *not* live).
fn is_historical_accessor(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // `…At(…)` (balanceOfAt / totalSupplyAt / totalAssetsAt) or `getPast…`.
    l.ends_with("at") || l.starts_with("getpast") || l.contains("snapshot") || l.contains("checkpoint")
}

/// If `e` contains a *live* aggregate read (a call to a [`LIVE_AGGREGATE_NAMES`]
/// accessor that is NOT a historical/snapshot accessor), return that accessor's
/// (lowercased) name. Returns `None` for a plain stored value (struct field /
/// variable with no call) — the "absolute amount captured at request" case — or
/// for a historical accessor — the "captured snapshot" case.
fn live_read_name(e: &Expr) -> Option<String> {
    let mut found: Option<String> = None;
    e.visit(&mut |sub| {
        if found.is_some() {
            return;
        }
        let ExprKind::Call(c) = &sub.kind else { return };
        let Some(name) = c.func_name.as_deref() else { return };
        let l = name.to_ascii_lowercase();
        if is_historical_accessor(&l) {
            return; // snapshot accessor — not live
        }
        if LIVE_AGGREGATE_NAMES.iter().any(|n| l == *n) {
            found = Some(l);
        }
    });
    found
}

/// Does `e` (any sub-expr) contain a live aggregate *call* at all? Used to ensure
/// the *percentage* operand is not itself a live read (which would make the
/// product two live reads, not pct × base).
fn is_live_aggregate_read(e: &Expr) -> bool {
    live_read_name(e).is_some()
}

/// Is `e` shaped like a stored *percentage* factor — a parameter / variable /
/// struct-field / indexed value (not a literal, not a live call)? We accept any
/// identifier/member/index leaf and lean on the name hint when present, but do not
/// *require* a percentage-named identifier (the real helper takes the pct as a
/// plain `slashPercentageWad` parameter, while a caller indexes a struct array
/// `q.slashPercentagesWad[i]`).
fn is_percent_factor(e: &Expr) -> bool {
    matches!(
        &e.kind,
        ExprKind::Ident(_) | ExprKind::Member { .. } | ExprKind::Index { .. }
    )
}

/// Does `e` look like a fixed precision denominator — a `MAX*`/`WAD`/`BPS`/
/// `PRECISION`/`DENOMINATOR`/`*_PERCENT_*` constant or a numeric/scientific
/// literal (`1e18`, `10000`)? Required for the inline `pct * base / max` form to
/// confirm the division is *fractioning* the base by a precision constant.
fn looks_like_max_denominator(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(sluice_ir::Lit::Number(_)) | ExprKind::Lit(sluice_ir::Lit::HexNumber(_)) => true,
        ExprKind::Ident(n) => is_denominator_name(n),
        ExprKind::Member { member, .. } => is_denominator_name(member),
        _ => false,
    }
}

fn is_denominator_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("max")
        || l.contains("wad")
        || l.contains("bps")
        || l.contains("precision")
        || l.contains("denominator")
        || l.contains("percent")
        || l.contains("basis")
        || l.contains("ray")
        || l.contains("one")
        || l.contains("scale")
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "percent-slash-live-base")
    }

    // VULN — the Karak `SlasherLib` shape: `finalizeSlashing` recomputes the
    // request commitment and gates on `slashingRequests[slashRoot]`, then reaches
    // `computeSlashAmount`, which does `mulDiv(storedPct, vault.totalAssets(), MAX)`.
    // The live `totalAssets()` is read at settle, so the loss tracks the veto-window
    // pool size, not the committed fraction.
    const VULN: &str = r#"
        pragma solidity ^0.8.0;
        library Math { function mulDiv(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) { return a * b / c; } }
        interface IVault { function totalAssets() external view returns (uint256); }
        library Constants { uint256 internal constant MAX_SLASHING_PERCENT_WAD = 1e18; }
        contract Slasher {
            mapping(bytes32 => bool) public slashingRequests;
            function calculateRoot(bytes memory q) internal pure returns (bytes32) { return keccak256(q); }
            function computeSlashAmount(address vault, uint256 slashPercentageWad) internal view returns (uint256) {
                return Math.mulDiv(slashPercentageWad, IVault(vault).totalAssets(), Constants.MAX_SLASHING_PERCENT_WAD);
            }
            function finalizeSlashing(bytes memory qenc, address vault, uint256 pct) external {
                bytes32 slashRoot = calculateRoot(qenc);
                if (!slashingRequests[slashRoot]) revert();
                delete slashingRequests[slashRoot];
                uint256 slashAmount = computeSlashAmount(vault, pct);
                IVault(vault).totalAssets();
                slashAmount;
            }
        }
    "#;

    // VULN (inline) — same shape, but the `pct * live / MAX` is written inline in
    // the finalize body (no helper) and gated by a `require(requests[root])`.
    const VULN_INLINE: &str = r#"
        pragma solidity ^0.8.0;
        interface IVault { function totalAssets() external view returns (uint256); }
        contract Slasher {
            mapping(bytes32 => bool) public requests;
            uint256 constant MAX = 1e18;
            function executeSlash(bytes32 root, address vault, uint256 pctWad) external {
                require(requests[root], "not queued");
                uint256 amount = pctWad * IVault(vault).totalAssets() / MAX;
                IVault(vault).totalAssets();
                amount;
            }
        }
    "#;

    // SAFE — the struct carries an ABSOLUTE amount captured at request. Finalize
    // gates on the root registry but pays a stored amount; no live read feeds the
    // payout. Must stay silent (live-base anchor fails).
    const SAFE_ABSOLUTE_AMOUNT: &str = r#"
        pragma solidity ^0.8.0;
        contract Slasher {
            mapping(bytes32 => bool) public slashingRequests;
            struct Queued { address vault; uint256 slashAmount; }
            function calculateRoot(bytes memory q) internal pure returns (bytes32) { return keccak256(q); }
            function finalizeSlashing(bytes memory qenc, Queued memory q) external {
                bytes32 slashRoot = calculateRoot(qenc);
                if (!slashingRequests[slashRoot]) revert();
                delete slashingRequests[slashRoot];
                // pay the absolute amount fixed at request — no live aggregate
                uint256 slashAmount = q.slashAmount;
                slashAmount;
            }
        }
    "#;

    // SAFE — finalize reads a CAPTURED `*At(ts)` snapshot accessor instead of a
    // live aggregate. The base is the value at the request timestamp, so the loss
    // is what was committed. Must stay silent.
    const SAFE_SNAPSHOT_AT: &str = r#"
        pragma solidity ^0.8.0;
        interface IVault { function totalAssetsAt(uint256 ts) external view returns (uint256); }
        library Math { function mulDiv(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) { return a * b / c; } }
        library Constants { uint256 internal constant MAX_SLASHING_PERCENT_WAD = 1e18; }
        contract Slasher {
            mapping(bytes32 => bool) public slashingRequests;
            function calculateRoot(bytes memory q) internal pure returns (bytes32) { return keccak256(q); }
            function finalizeSlashing(bytes memory qenc, address vault, uint256 pctWad, uint256 reqTs) external {
                bytes32 slashRoot = calculateRoot(qenc);
                if (!slashingRequests[slashRoot]) revert();
                delete slashingRequests[slashRoot];
                uint256 amount = Math.mulDiv(pctWad, IVault(vault).totalAssetsAt(reqTs), Constants.MAX_SLASHING_PERCENT_WAD);
                amount;
            }
        }
    "#;

    // SAFE — `requestSlashing` does the SAME `pct * live / MAX`, but at REQUEST
    // time (the committed moment) and with no root-membership gate. Reading the
    // live base when you queue the request is correct; the name gate + missing
    // membership gate keep this silent.
    const SAFE_REQUEST_TIME: &str = r#"
        pragma solidity ^0.8.0;
        interface IVault { function totalAssets() external view returns (uint256); }
        contract Slasher {
            mapping(bytes32 => bool) public slashingRequests;
            uint256 constant MAX = 1e18;
            function requestSlashing(address vault, uint256 pctWad) external returns (bytes32 root) {
                uint256 amount = pctWad * IVault(vault).totalAssets() / MAX;
                root = keccak256(abi.encode(vault, amount));
                slashingRequests[root] = true;
            }
        }
    "#;

    // SAFE — a generic two-step finalize with a root gate, but it pays a fixed
    // bonus computed from a per-user balance mapping (no live pool-aggregate
    // *call*). Different mechanism; must stay silent.
    const SAFE_NO_LIVE_CALL: &str = r#"
        pragma solidity ^0.8.0;
        contract Rewarder {
            mapping(bytes32 => bool) public claimRoots;
            mapping(address => uint256) public stored;
            uint256 constant MAX = 1e18;
            function finalizeClaim(bytes32 root, address user, uint256 pct) external {
                require(claimRoots[root], "no");
                uint256 amount = pct * stored[user] / MAX;
                amount;
            }
        }
    "#;

    #[test]
    fn fires_on_karak_finalize_helper_shape() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_inline_percent_live_base() {
        assert!(fires(VULN_INLINE), "{:#?}", run(VULN_INLINE));
    }

    #[test]
    fn silent_when_absolute_amount_captured() {
        assert!(!fires(SAFE_ABSOLUTE_AMOUNT), "{:#?}", run(SAFE_ABSOLUTE_AMOUNT));
    }

    #[test]
    fn silent_when_snapshot_at_accessor() {
        assert!(!fires(SAFE_SNAPSHOT_AT), "{:#?}", run(SAFE_SNAPSHOT_AT));
    }

    #[test]
    fn silent_on_request_time_live_read() {
        assert!(!fires(SAFE_REQUEST_TIME), "{:#?}", run(SAFE_REQUEST_TIME));
    }

    #[test]
    fn silent_without_live_aggregate_call() {
        assert!(!fires(SAFE_NO_LIVE_CALL), "{:#?}", run(SAFE_NO_LIVE_CALL));
    }
}
