//! Cross-chain rate staleness — a destination / L2 contract mints (or prices a
//! mint) using a rate whose *freshness is checked against a stored timestamp that
//! was itself supplied by a bridge message*, not against a local receipt time.
//!
//! The canonical shape (Renzo `xRenzoDeposit` family). The L2 deposit contract
//! keeps a price and a price-timestamp in storage:
//!
//! ```solidity
//! uint256 public lastPrice;
//! uint256 public lastPriceTimestamp;
//!
//! // bridge sink: authed ONLY by the cross-chain endpoint, writes the timestamp
//! // straight from the inbound message — NOT from block.timestamp.
//! function updatePrice(uint256 _price, uint256 _timestamp) external {
//!     if (msg.sender != receiver) revert InvalidSender(...);
//!     lastPrice = _price;
//!     lastPriceTimestamp = _timestamp;          // <-- attacker/relayer-supplied time
//! }
//!
//! // consumer: freshness is checked against the STORED (bridge-supplied) time,
//! // then the price feeds a mint divisor.
//! function _deposit(...) internal returns (uint256) {
//!     (uint256 lastPrice, uint256 lastPriceTimestamp) = getMintRate();
//!     if (block.timestamp > lastPriceTimestamp + 1 days) revert OraclePriceExpired();
//!     uint256 xezETHAmount = (1e18 * _tokenEthValue) / lastPrice;   // <-- divisor
//!     IXERC20(address(xezETH)).mint(msg.sender, xezETHAmount);
//! }
//! ```
//!
//! Why this is a value-flow bug: `lastPriceTimestamp` is whatever the *source* side
//! put in the message. The `block.timestamp > lastPriceTimestamp + DELAY` guard
//! therefore proves nothing about when *this* chain received the price — it only
//! proves the source claimed a recent time. A relayer that delays delivery, or a
//! compromised / buggy source that stamps a future-ish time, keeps a stale price
//! "fresh" indefinitely, and that price is the divisor that mints the L2 token:
//! mint too much (price too low / stale-high collateral) and the peg breaks.
//!
//! Two suppressions keep this at ~0 false positives:
//!   * **Chainlink sources** — a staleness check whose timestamp operand is a
//!     *local* destructured from `latestRoundData()` / `getRoundData()` is the
//!     robust-feed pattern (handled by `oracle-staleness`), not a bridge-supplied
//!     stored time. Such a check never counts as the bridge-stale consumer.
//!   * **Local receipt time** — if the freshness state var is *only ever* written
//!     from `block.timestamp` / `block.number` (the contract stamps the time it
//!     received the message itself), the guard is genuine and we stay silent. We
//!     fire only when some endpoint-authed writer stamps it from a bridge-message
//!     **parameter**.
//!
//! Real target: `renzo-contracts/contracts/Bridge/L2/xRenzoDepositNativeBridge.sol`
//! `_deposit` (the consumer, staleness on `lastPriceTimestamp` + `/ lastPrice` mint)
//! and `updatePrice` / `_updatePrice` (the bridge sink that stamps `lastPriceTimestamp`
//! from the inbound `_timestamp`).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, Contract, Expr, ExprKind, Function, Span, StateVar};

pub struct CrossChainRateStalenessDetector;

impl Detector for CrossChainRateStalenessDetector {
    fn id(&self) -> &'static str {
        "crosschain-rate-staleness"
    }
    fn category(&self) -> Category {
        Category::CrossChainRateStaleness
    }
    fn description(&self) -> &'static str {
        "Mint/price freshness checked against a bridge-message-supplied stored timestamp (not a local receipt time), then that price feeds a mint divisor/multiplier (Renzo xRenzoDeposit class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        // Analyse per *implementation group*: a concrete/abstract contract together
        // with everything it inherits. The bridge sink (writer of the freshness
        // var), the consumer (the mint that checks it), and the freshness/price
        // state vars commonly live in *different* members of one inheritance chain
        // — in Renzo the vars are in the abstract `...StorageV1` base while the
        // logic is in the derived `xRenzoDepositNativeBridge`. We therefore merge
        // the chain's functions and state vars before matching.
        for c in cx.scir.iter_contracts() {
            if c.is_interface() {
                continue;
            }
            // Only analyse a contract that *itself* defines at least one body
            // (avoids reporting the same inheritance group once per base).
            if cx.scir.functions_of(c.id).next().is_none() {
                continue;
            }
            // Functions and state vars visible to `c` (own + transitive bases).
            let funcs = inherited_functions(cx, c);
            if funcs.is_empty() {
                continue;
            }
            let state_vars = inherited_state_vars(cx, c);
            if state_vars.is_empty() {
                continue;
            }

            // (1) Which timestamp-like state vars are stamped from a bridge-supplied
            //     message parameter under endpoint-only auth? (As opposed to only
            //     ever from `block.timestamp` — local receipt.)
            let bridge_stale_vars = bridge_supplied_timestamp_vars(cx, &state_vars, &funcs);
            if bridge_stale_vars.is_empty() {
                continue;
            }

            // (2) Find the consumer: a function (defined in THIS contract) that
            //     checks `block.timestamp` against one of those stored vars and then
            //     mints, with a price var used as a divisor / multiplier.
            for f in cx.scir.functions_of(c.id) {
                if !f.has_body {
                    continue;
                }
                // Must reach a mint sink (this is a *minting* class).
                if !calls_mint(f) {
                    continue;
                }

                // Staleness check on a bridge-supplied stored timestamp var. If the
                // only freshness check uses a Chainlink local, this returns None.
                let Some(stale_var) = staleness_on_bridge_var(cx, f, &state_vars, &bridge_stale_vars) else {
                    continue;
                };

                // A price/rate state var, read here and used as a mint divisor or
                // multiplier. This is the value the stale timestamp is "protecting".
                let Some((price_var, price_span)) = mint_rate_factor(f, &state_vars) else {
                    continue;
                };
                // The freshness var and the rate var must be different state vars.
                if price_var == stale_var {
                    continue;
                }

                // Confidence is high: every gate is structural and specific — an
                // endpoint-only-authed sink that stamps the freshness var from a
                // *bridge-message parameter* (not block.timestamp), a staleness
                // comparison of `block.timestamp` against *that stored var*, and the
                // paired rate used as the mint divisor/multiplier — with Chainlink
                // feeds, local-receipt-time stamps, and owner-only writers all
                // suppressed. A benign contract matching all of these at once is
                // very unlikely (0 FPs across the prior-codebase corpus).
                let b = FindingBuilder::new(self.id(), Category::CrossChainRateStaleness)
                    .title("Mint rate freshness checked against a bridge-supplied timestamp, not a local receipt time")
                    .severity(Severity::High)
                    .confidence(0.78)
                    .dimension(Dimension::ValueFlow)
                    .message(format!(
                        "`{fname}` mints using the rate `{price}` and guards its freshness with \
                         `block.timestamp` vs the stored timestamp `{stale}`. But `{stale}` is written by a \
                         cross-chain message sink in this contract that stamps it straight from the inbound \
                         message (authorized only by `msg.sender == <endpoint>`), not from a local receipt \
                         time. The staleness check therefore only proves the *source* claimed a recent time \
                         — a delaying relayer, or a compromised / buggy source that stamps a future-ish \
                         timestamp, keeps a stale `{price}` accepted as fresh. That stale rate is then the \
                         divisor / multiplier for the L2 mint (`... / {price}` feeding `mint(...)`), so the \
                         minted amount is mispriced and the peg / collateralization breaks. This is the \
                         Renzo xRenzoDeposit cross-chain rate-staleness class.",
                        fname = f.name,
                        price = price_var,
                        stale = stale_var,
                    ))
                    .recommendation(format!(
                        "Do not trust a bridge-supplied timestamp for freshness. Record the *local* receipt \
                         time when the price message is accepted (`{stale} = block.timestamp;` in the sink) \
                         and check `block.timestamp - {stale} <= maxDelay` against that local time; \
                         additionally bound how far the source-claimed time may lead/lag local time, and \
                         consider a heartbeat / sequencer-uptime check before using `{price}` to mint.",
                        stale = stale_var,
                        price = price_var,
                    ));
                out.push(cx.finish(b, f.id, price_span));
                // One finding per consumer is enough — the fix is the same.
                break;
            }
        }
        out
    }
}

// ------------------------------------------------- inheritance resolution

/// All functions visible to `c` — its own plus every transitively inherited base's
/// — deduplicated. The bridge sink and the consumer can live in different members
/// of one chain (Renzo: logic in the derived contract, none in the storage base),
/// so phase-1 must see the whole group's functions.
fn inherited_functions<'a>(cx: &'a AnalysisContext, c: &'a Contract) -> Vec<&'a Function> {
    let mut out: Vec<&Function> = Vec::new();
    let mut seen_fn: Vec<sluice_ir::FunctionId> = Vec::new();
    for cid in inheritance_chain(cx, c) {
        for f in cx.scir.functions_of(cid) {
            if !seen_fn.contains(&f.id) {
                seen_fn.push(f.id);
                out.push(f);
            }
        }
    }
    out
}

/// All state vars visible to `c` — its own plus every transitively inherited
/// base's. Renzo declares `lastPrice` / `lastPriceTimestamp` / `receiver` in the
/// abstract `...StorageV1` base, not in the concrete contract, so phase-1/2 var
/// matching must resolve through the chain.
fn inherited_state_vars<'a>(cx: &'a AnalysisContext, c: &'a Contract) -> Vec<&'a StateVar> {
    let mut out: Vec<&StateVar> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for cid in inheritance_chain(cx, c) {
        if let Some(bc) = cx.scir.contract(cid) {
            for v in &bc.state_vars {
                if !seen.contains(&v.name) {
                    seen.push(v.name.clone());
                    out.push(v);
                }
            }
        }
    }
    out
}

/// `c` followed by its transitive base contracts (resolved by name). Cycles and
/// unknown base names are handled gracefully. Order is `c` first, then bases.
fn inheritance_chain(cx: &AnalysisContext, c: &Contract) -> Vec<sluice_ir::ContractId> {
    let mut order: Vec<sluice_ir::ContractId> = Vec::new();
    let mut stack: Vec<sluice_ir::ContractId> = vec![c.id];
    while let Some(cid) = stack.pop() {
        if order.contains(&cid) {
            continue;
        }
        order.push(cid);
        if let Some(cur) = cx.scir.contract(cid) {
            for base in &cur.bases {
                // Resolve the (last-declared) contract with this base name.
                if let Some(bid) = cx.scir.contract_by_name.get(base) {
                    if !order.contains(bid) {
                        stack.push(*bid);
                    }
                }
            }
        }
    }
    order
}

// ----------------------------------------------------------------- phase 1

/// Timestamp-like state vars (in `sv`) that are written from a *bridge-supplied
/// message parameter* under endpoint-only authorization — i.e. NOT (only) from a
/// local `block.timestamp` receipt time.
///
/// Two writer shapes are recognized, both rooted at an endpoint-authed external
/// entry:
///   * **direct** — an endpoint-authed external function does `T = <param>;`;
///   * **forwarded** — an endpoint-authed external function calls an internal
///     writer `_w(..., p, ...)` and that internal writer does `T = <its param>`,
///     where the external entry passes *its own parameter* (a bridge-message
///     field) — not `block.timestamp` — into that position. This is the real Renzo
///     `updatePrice -> _updatePrice` split.
fn bridge_supplied_timestamp_vars(cx: &AnalysisContext, sv: &[&StateVar], funcs: &[&Function]) -> Vec<String> {
    let mut vars: Vec<String> = Vec::new();

    for entry in funcs {
        if !entry.has_body || !entry.is_externally_reachable() {
            continue;
        }
        // Endpoint-only auth: a `msg.sender == X` guard where X is a
        // bridge-endpoint-like state var (receiver / endpoint / mailbox / ...).
        // An owner/governance modifier (`onlyOwner`) is NOT an endpoint guard, so
        // an owner-only price push (which stamps block.timestamp) does not qualify.
        if !is_endpoint_authed(cx, entry, sv) {
            continue;
        }

        // (a) direct writes `T = <param>` in the entry itself.
        for tv in timestamp_var_param_writes(cx, entry, sv) {
            push_unique(&mut vars, tv);
        }

        // (b) forwarded: entry calls an internal writer, passing its own param as a
        //     bridge-message field; the internal writer stamps `T` from that param.
        for callee in funcs {
            if !callee.has_body || std::ptr::eq(*entry, *callee) {
                continue;
            }
            // entry must invoke callee internally.
            if !entry.effects.internal_calls.iter().any(|n| n == &callee.name) {
                continue;
            }
            // For each `T = <calleeParam>` write inside the callee, check the entry
            // forwards a *parameter* (not block.timestamp) into that param position.
            for (tvar, callee_param_idx) in timestamp_var_writes_from_param_idx(cx, callee, sv) {
                if entry_forwards_param_into(cx, entry, &callee.name, callee_param_idx) {
                    push_unique(&mut vars, tvar);
                }
            }
        }
    }

    vars
}

/// Direct `T = <param>` writes in `f`, where `T` is a timestamp-like state var
/// (in `sv`) and the RHS is a parameter of `f` (not `block.timestamp`/`block.number`).
fn timestamp_var_param_writes(cx: &AnalysisContext, f: &Function, sv: &[&StateVar]) -> Vec<String> {
    let mut out = Vec::new();
    visit_assigns(f, &mut |target, value| {
        let Some(var) = lvalue_root_statevar(target, sv) else { return };
        if !is_timestamp_name(&var) {
            return;
        }
        if rhs_is_param_not_blocktime(cx, f, value) {
            push_unique(&mut out, var);
        }
    });
    out
}

/// `(T, param_index)` for each write `T = p` inside `f` where `T` is a
/// timestamp-like state var (in `sv`) and `p` is the function's parameter at
/// `param_index` (so a caller can be checked for what it forwards there).
fn timestamp_var_writes_from_param_idx(cx: &AnalysisContext, f: &Function, sv: &[&StateVar]) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    visit_assigns(f, &mut |target, value| {
        let Some(var) = lvalue_root_statevar(target, sv) else { return };
        if !is_timestamp_name(&var) {
            return;
        }
        // RHS must be exactly a bare parameter identifier.
        let ExprKind::Ident(rhs) = &value.kind else { return };
        if mentions_block_time(&cx.source_text(value.span)) {
            return;
        }
        if let Some(idx) = f.params.iter().position(|p| p.name.as_deref() == Some(rhs.as_str())) {
            out.push((var, idx));
        }
    });
    out
}

/// Does `entry` call `callee_name(...)` passing one of its OWN parameters (and not
/// `block.timestamp`) as argument number `arg_idx`? This captures the Renzo
/// `updatePrice(_price, _timestamp) -> _updatePrice(_price, _timestamp)` forward,
/// while rejecting the owner path `_updatePrice(price, block.timestamp)`.
fn entry_forwards_param_into(cx: &AnalysisContext, entry: &Function, callee_name: &str, arg_idx: usize) -> bool {
    let mut hit = false;
    for s in &entry.body {
        s.visit_exprs(&mut |e| {
            if hit {
                return;
            }
            let ExprKind::Call(call) = &e.kind else { return };
            if call.func_name.as_deref() != Some(callee_name) {
                return;
            }
            let Some(arg) = call.args.get(arg_idx) else { return };
            // The forwarded argument must be a bare identifier that is a parameter
            // of `entry` (a bridge-message field), not block.timestamp.
            let ExprKind::Ident(name) = &arg.kind else { return };
            if mentions_block_time(&cx.source_text(arg.span)) {
                return;
            }
            if entry.params.iter().any(|p| p.name.as_deref() == Some(name.as_str())) {
                hit = true;
            }
        });
        if hit {
            break;
        }
    }
    hit
}

/// True if `f` is authorized *only* by a cross-chain endpoint check — a
/// `msg.sender == X` guard where `X` is a bridge-endpoint-like state var (in `sv`):
/// receiver / endpoint / mailbox / router / peer / ... . An owner/admin modifier
/// does not count; this is what separates the bridge sink from an owner price push.
fn is_endpoint_authed(cx: &AnalysisContext, f: &Function, sv: &[&StateVar]) -> bool {
    use sluice_ir::GuardKind;
    // A msg.sender comparison guard whose text names an endpoint-like state var.
    for g in &f.effects.guards {
        if matches!(g.kind, GuardKind::MsgSenderCheck) {
            let t = g.text.to_ascii_lowercase();
            // Modifier-style msg.sender guards carry the modifier name as text
            // (`onlyOwner`); a raw `require(msg.sender == receiver)` carries the
            // comparison. Accept only when an endpoint-like *state var* is named.
            if names_endpoint_statevar(&t, sv) {
                return true;
            }
        }
    }
    // Fallback: scan the function source for `msg.sender == <endpointVar>` /
    // `msg.sender != <endpointVar>` (covers `if (msg.sender != receiver) revert`).
    let src = cx.source_text(f.span);
    if src.contains("msg.sender") {
        for v in sv {
            if is_endpoint_name(&v.name) && compares_msg_sender_to(&src, &v.name.to_ascii_lowercase()) {
                return true;
            }
        }
    }
    false
}

/// Does the (lowercased) guard/text mention an endpoint-like state var (in `sv`)?
fn names_endpoint_statevar(text: &str, sv: &[&StateVar]) -> bool {
    sv.iter()
        .any(|v| is_endpoint_name(&v.name) && word_present(text, &v.name.to_ascii_lowercase()))
}

/// True if `src` contains `msg.sender == name` or `msg.sender != name` (whitespace
/// insensitive), tying the auth to that endpoint var.
fn compares_msg_sender_to(src: &str, name: &str) -> bool {
    let compact: String = src.chars().filter(|c| !c.is_whitespace()).collect();
    compact.contains(&format!("msg.sender=={name}")) || compact.contains(&format!("msg.sender!={name}"))
}

// ----------------------------------------------------------------- phase 2

/// If `f` performs a staleness comparison of `block.timestamp` (or `block.number`)
/// against a **stored bridge-supplied** timestamp var (a member of
/// `bridge_stale_vars`, read from this contract's storage), return that var's name.
///
/// Crucially this returns `None` when the comparison's time operand is a *local*
/// destructured from a Chainlink `latestRoundData()` / `getRoundData()` call — the
/// robust-feed pattern, which is `oracle-staleness`'s job, not ours.
fn staleness_on_bridge_var(
    cx: &AnalysisContext,
    f: &Function,
    sv: &[&StateVar],
    bridge_stale_vars: &[String],
) -> Option<String> {
    // Names that are *local* timestamps fed by a Chainlink feed in this function —
    // these must never satisfy the staleness link.
    let chainlink_locals = chainlink_timestamp_locals(cx, f);

    let mut found: Option<String> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            let ExprKind::Binary { op, lhs, rhs } = &e.kind else { return };
            if !op.is_comparison() {
                return;
            }
            // The comparison must involve block.timestamp / block.number somewhere.
            // We handle BOTH idioms:
            //   * `block.timestamp > T + DELAY`           (T on the other operand)
            //   * `block.timestamp - T > DELAY`           (T on the same operand as
            //                                              block.timestamp)
            // so we gather identifiers from *both* operands of the comparison.
            if !(mentions_block_time(&cx.source_text(lhs.span))
                || mentions_block_time(&cx.source_text(rhs.span)))
            {
                return;
            }
            let mut idents: Vec<String> = Vec::new();
            for side in [lhs.as_ref(), rhs.as_ref()] {
                side.visit(&mut |x| {
                    if let ExprKind::Ident(n) = &x.kind {
                        idents.push(n.clone());
                    }
                });
            }
            // Reject a Chainlink-local comparison outright (the freshness operand is
            // a local destructured from a robust feed, not a bridge-stored time).
            if idents.iter().any(|n| chainlink_locals.iter().any(|cl| cl == n)) {
                return;
            }
            // Accept iff the comparison references a bridge-supplied stored timestamp
            // var that this function actually reads from storage.
            for v in bridge_stale_vars {
                if idents.iter().any(|n| n == v) && reads_statevar(f, v) && is_statevar(sv, v) {
                    found = Some(v.clone());
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

/// Local variable names in `f` that are destructured from / assigned by a Chainlink
/// `latestRoundData()` / `getRoundData()` call. We treat any local on the LHS of an
/// assignment whose RHS source mentions such a call as a Chainlink-derived time.
fn chainlink_timestamp_locals(cx: &AnalysisContext, f: &Function) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    visit_assigns(f, &mut |target, value| {
        let vt = cx.source_text(value.span);
        if !(vt.contains("latestrounddata") || vt.contains("getrounddata") || vt.contains("latestanswer")) {
            return;
        }
        // LHS may be a tuple destructure `(, int256 price, , uint256 timestamp, )`
        // or a single ident. Pull every identifier named on the LHS.
        let tt = cx.source_text(target.span);
        for id in identifiers_in_text(&tt) {
            push_unique(&mut out, id);
        }
    });
    // Also handle `(...) = feed.latestRoundData()` declared via VarDecl tuple: the
    // assign visitor above already covers the lowered Assign form; nothing more.
    out
}

/// A price/rate state var (in `sv`) that is read by `f` and used as a **divisor or
/// multiplier** somewhere in `f`'s body. Returns `(var_name, span_of_use)`.
///
/// Renzo: `lastPrice` used as `(1e18 * _tokenEthValue) / lastPrice`.
fn mint_rate_factor(f: &Function, sv: &[&StateVar]) -> Option<(String, Span)> {
    let mut hit: Option<(String, Span)> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if hit.is_some() {
                return;
            }
            let ExprKind::Binary { op, lhs, rhs } = &e.kind else { return };
            if !matches!(op, BinOp::Div | BinOp::Mul) {
                return;
            }
            // The rate appears as the divisor (rhs of `/`) or either factor of `*`.
            let candidates: [&Expr; 2] = [lhs.as_ref(), rhs.as_ref()];
            for cand in candidates {
                if let Some(var) = price_statevar_in(cand, sv) {
                    // Must be read from storage by this function (a real state read,
                    // not a same-named local that never touches storage).
                    if reads_statevar(f, &var) {
                        hit = Some((var, e.span));
                        return;
                    }
                }
            }
        });
        if hit.is_some() {
            break;
        }
    }
    hit
}

/// First price/rate-like state var (in `sv`) named by a *bare-ident* operand `e`.
/// We require a bare identifier (the divisor/multiplier is the rate itself, e.g.
/// `lastPrice`), not an arbitrary sub-expression, to stay precise.
fn price_statevar_in(e: &Expr, sv: &[&StateVar]) -> Option<String> {
    if let ExprKind::Ident(n) = &e.kind {
        if is_price_name(n) && is_statevar(sv, n) {
            return Some(n.clone());
        }
    }
    None
}

// ----------------------------------------------------------------- name/utility

/// Substrings that mark a timestamp-like state var (the freshness operand).
fn is_timestamp_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    (l.contains("timestamp") || l.contains("updatedat") || l.contains("lastupdate") || l.contains("updatetime"))
        // a pure `time` suffix is too broad; require it to co-occur with update/price/last
        || ((l.contains("price") || l.contains("rate") || l.contains("last")) && l.contains("time"))
}

/// Endpoint-like state-var names that gate a cross-chain message sink.
fn is_endpoint_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        "receiver", "endpoint", "mailbox", "router", "messenger", "relayer", "bridge", "gateway",
        "portal", "peer", "lzendpoint", "ccip", "hyperlane", "connext", "inbox", "l2messenger",
        "crosschain", "remote",
    ];
    NEEDLES.iter().any(|n| l.contains(n))
}

/// Substrings that mark a price/rate state var used to mint.
fn is_price_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        "price", "rate", "exchangerate", "pershare", "ratio", "mintrate", "redeemrate",
    ];
    NEEDLES.iter().any(|n| l.contains(n))
}

/// Does `f` call a mint sink? `mint` / `_mint` / `safeMint` as a resolved callee
/// name, on any call kind (interface external, internal, low-level).
fn calls_mint(f: &Function) -> bool {
    let by_name = |n: &str| {
        let l = n.to_ascii_lowercase();
        l == "mint" || l == "_mint" || l == "safemint" || l.ends_with("mint")
    };
    if f.effects.call_sites.iter().any(|cs| cs.func_name.as_deref().map(by_name).unwrap_or(false)) {
        return true;
    }
    f.effects.internal_calls.iter().any(|n| by_name(n))
}

/// True if `f` reads the state var `var` (per its effect summary).
fn reads_statevar(f: &Function, var: &str) -> bool {
    f.effects.storage_reads.iter().any(|r| r.var == var)
}

/// True if `name` is one of the (inherited) state vars in `sv`.
fn is_statevar(sv: &[&StateVar], name: &str) -> bool {
    sv.iter().any(|v| v.name == name)
}

/// Root state-var name of an lvalue (`a.b[c]` -> `a`), if it is in `sv`.
fn lvalue_root_statevar(target: &Expr, sv: &[&StateVar]) -> Option<String> {
    let root = root_ident(target)?;
    if is_statevar(sv, &root) {
        Some(root)
    } else {
        None
    }
}

/// RHS of a `T = ...` write is a *parameter* of `f` (not `block.timestamp`).
fn rhs_is_param_not_blocktime(cx: &AnalysisContext, f: &Function, value: &Expr) -> bool {
    if mentions_block_time(&cx.source_text(value.span)) {
        return false;
    }
    match &value.kind {
        ExprKind::Ident(n) => f.params.iter().any(|p| p.name.as_deref() == Some(n.as_str())),
        _ => false,
    }
}

/// True if (lowercased-ish) `text` mentions `block.timestamp` / `block.number` /
/// `now`. Used to classify a write/operand as a *local receipt time*.
fn mentions_block_time(text: &str) -> bool {
    let l = text.to_ascii_lowercase();
    l.contains("block.timestamp") || l.contains("block.number") || word_present(&l, "now")
}

/// Walk every `Assign { target, value }` in `f`'s body, plus VarDecl initializers
/// rendered as assignments, invoking `cb(target, value)`.
fn visit_assigns(f: &Function, cb: &mut impl FnMut(&Expr, &Expr)) {
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if let ExprKind::Assign { target, value, .. } = &e.kind {
                cb(target, value);
            }
        });
    }
}

/// Root identifier of an lvalue/member/index chain (`a.b[c]` -> `a`).
fn root_ident(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root_ident(base),
        _ => None,
    }
}

/// Extract identifier-ish tokens from raw lowercased source text (used for tuple
/// destructure LHS like `(, int256 price, , uint256 timestamp, )`). Splits on any
/// non-identifier char and drops Solidity type keywords.
fn identifiers_in_text(text: &str) -> Vec<String> {
    const TYPE_KW: &[&str] = &[
        "uint", "uint8", "uint16", "uint32", "uint64", "uint80", "uint128", "uint256", "int",
        "int256", "address", "bool", "bytes", "bytes32", "string", "memory", "calldata", "storage",
        "uint48",
    ];
    let mut out = Vec::new();
    let mut cur = String::new();
    let flush = |cur: &mut String, out: &mut Vec<String>| {
        if !cur.is_empty() {
            let w = std::mem::take(cur);
            if !TYPE_KW.contains(&w.as_str()) && !w.chars().all(|ch| ch.is_ascii_digit()) {
                out.push(w);
            }
        }
    };
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' {
            cur.push(ch);
        } else {
            flush(&mut cur, &mut out);
        }
    }
    flush(&mut cur, &mut out);
    out
}

/// Whole-word (identifier-boundary) containment test on lowercased `hay`/`needle`.
fn word_present(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let hb = hay.as_bytes();
    let nb = needle.as_bytes();
    let is_id = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'$';
    let mut from = 0usize;
    while let Some(rel) = hay[from..].find(needle) {
        let i = from + rel;
        let before_ok = i == 0 || !is_id(hb[i - 1]);
        let after = i + nb.len();
        let after_ok = after >= hb.len() || !is_id(hb[after]);
        if before_ok && after_ok {
            return true;
        }
        from = i + 1;
    }
    false
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.iter().any(|x| x == &s) {
        v.push(s);
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "crosschain-rate-staleness")
    }

    // VULN (Renzo xRenzoDeposit shape): the L2 deposit contract stamps
    // `lastPriceTimestamp` from the inbound bridge message (`updatePrice` authed
    // only by `msg.sender == receiver`, forwarding `_timestamp` into the writer),
    // then `_deposit` checks freshness against that stored time and mints with
    // `lastPrice` as the divisor.
    const VULN: &str = r#"
        pragma solidity 0.8.27;
        interface IXERC20 { function mint(address to, uint256 amt) external; }
        contract xRenzoDeposit {
            uint256 public lastPrice;
            uint256 public lastPriceTimestamp;
            address public receiver;
            IXERC20 public xezETH;

            function getMintRate() public view returns (uint256, uint256) {
                return (lastPrice, lastPriceTimestamp);
            }

            function updatePrice(uint256 _price, uint256 _timestamp) external {
                if (msg.sender != receiver) revert();
                _updatePrice(_price, _timestamp);
            }
            function updatePriceByOwner(uint256 price) external {
                _updatePrice(price, block.timestamp);
            }
            function _updatePrice(uint256 _price, uint256 _timestamp) internal {
                lastPrice = _price;
                lastPriceTimestamp = _timestamp;
            }

            function _deposit(uint256 _tokenEthValue, uint256 _minOut) internal returns (uint256) {
                (uint256 lastPrice, uint256 lastPriceTimestamp) = getMintRate();
                if (block.timestamp > lastPriceTimestamp + 1 days) revert();
                uint256 xezETHAmount = (1e18 * _tokenEthValue) / lastPrice;
                if (xezETHAmount < _minOut) revert();
                xezETH.mint(msg.sender, xezETHAmount);
                return xezETHAmount;
            }
        }
    "#;

    #[test]
    fn fires_on_renzo_shape() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    // SAFE: identical mint + freshness check, but the bridge sink stamps the
    // *local* receipt time (`lastPriceTimestamp = block.timestamp`) instead of the
    // message's claimed time. The freshness guard is then genuine.
    const SAFE_LOCAL_RECEIPT: &str = r#"
        pragma solidity 0.8.27;
        interface IXERC20 { function mint(address to, uint256 amt) external; }
        contract xRenzoDeposit {
            uint256 public lastPrice;
            uint256 public lastPriceTimestamp;
            address public receiver;
            IXERC20 public xezETH;

            function updatePrice(uint256 _price, uint256 _timestamp) external {
                if (msg.sender != receiver) revert();
                lastPrice = _price;
                lastPriceTimestamp = block.timestamp;   // local receipt time
            }

            function _deposit(uint256 _tokenEthValue, uint256 _minOut) internal returns (uint256) {
                if (block.timestamp > lastPriceTimestamp + 1 days) revert();
                uint256 amt = (1e18 * _tokenEthValue) / lastPrice;
                if (amt < _minOut) revert();
                xezETH.mint(msg.sender, amt);
                return amt;
            }
        }
    "#;

    #[test]
    fn silent_on_local_receipt_time() {
        assert!(!fires(SAFE_LOCAL_RECEIPT), "{:#?}", run(SAFE_LOCAL_RECEIPT));
    }

    // SAFE (Chainlink): freshness is checked against a `updatedAt` local
    // destructured from a robust feed's `latestRoundData()`, not a bridge-supplied
    // stored timestamp. There IS an endpoint-authed bridge writer of a stored time,
    // but the mint's staleness check uses the Chainlink local — so this detector
    // (which targets the bridge-stored-time check) must stay silent; `oracle-staleness`
    // owns the robust-feed case.
    const SAFE_CHAINLINK: &str = r#"
        pragma solidity 0.8.27;
        interface IXERC20 { function mint(address to, uint256 amt) external; }
        interface AggregatorV3Interface {
            function latestRoundData() external view
                returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
        }
        contract L2Mint {
            uint256 public lastPrice;
            uint256 public lastPriceTimestamp;
            address public receiver;
            AggregatorV3Interface public feed;
            IXERC20 public token;

            function updatePrice(uint256 _price, uint256 _timestamp) external {
                if (msg.sender != receiver) revert();
                lastPrice = _price;
                lastPriceTimestamp = _timestamp;
            }

            function mintAt(uint256 amountIn, uint256 _minOut) external returns (uint256) {
                (, int256 price, , uint256 updatedAt, ) = feed.latestRoundData();
                if (block.timestamp > updatedAt + 1 days) revert();
                if (price <= 0) revert();
                uint256 out = (amountIn * uint256(price)) / 1e18;
                if (out < _minOut) revert();
                token.mint(msg.sender, out);
                return out;
            }
        }
    "#;

    #[test]
    fn silent_on_chainlink_staleness() {
        assert!(!fires(SAFE_CHAINLINK), "{:#?}", run(SAFE_CHAINLINK));
    }

    // SAFE: bridge writer stamps a parameter, but the consumer has NO freshness
    // check against it at all (it just mints). No staleness-on-bridge-var link, so
    // this detector (about a *deceptive* freshness check) stays silent — a missing
    // check is a different class.
    const SAFE_NO_STALENESS_CHECK: &str = r#"
        pragma solidity 0.8.27;
        interface IXERC20 { function mint(address to, uint256 amt) external; }
        contract L2Mint {
            uint256 public lastPrice;
            uint256 public lastPriceTimestamp;
            address public receiver;
            IXERC20 public token;
            function updatePrice(uint256 _price, uint256 _timestamp) external {
                if (msg.sender != receiver) revert();
                lastPrice = _price;
                lastPriceTimestamp = _timestamp;
            }
            function mintTokens(uint256 amountIn) external returns (uint256) {
                uint256 out = (1e18 * amountIn) / lastPrice;
                token.mint(msg.sender, out);
                return out;
            }
        }
    "#;

    #[test]
    fn silent_without_staleness_check() {
        assert!(!fires(SAFE_NO_STALENESS_CHECK), "{:#?}", run(SAFE_NO_STALENESS_CHECK));
    }

    // SAFE: the stored-time writer is `onlyOwner` (governance), NOT an endpoint sink.
    // The freshness var is therefore not "bridge-supplied", so even though a mint
    // checks it, this is an ordinary owner-fed price and we stay silent.
    const SAFE_OWNER_ONLY: &str = r#"
        pragma solidity 0.8.27;
        interface IXERC20 { function mint(address to, uint256 amt) external; }
        contract OwnerPriced {
            uint256 public lastPrice;
            uint256 public lastPriceTimestamp;
            address public owner;
            IXERC20 public token;
            modifier onlyOwner() { require(msg.sender == owner); _; }
            function setPrice(uint256 _price, uint256 _timestamp) external onlyOwner {
                lastPrice = _price;
                lastPriceTimestamp = _timestamp;
            }
            function mintTokens(uint256 amountIn, uint256 _minOut) external returns (uint256) {
                if (block.timestamp > lastPriceTimestamp + 1 days) revert();
                uint256 out = (1e18 * amountIn) / lastPrice;
                if (out < _minOut) revert();
                token.mint(msg.sender, out);
                return out;
            }
        }
    "#;

    #[test]
    fn silent_on_owner_only_writer() {
        assert!(!fires(SAFE_OWNER_ONLY), "{:#?}", run(SAFE_OWNER_ONLY));
    }

    // VULN (subtraction idiom): the staleness guard is written as
    // `block.timestamp - lastPriceTimestamp > DELAY` (the freshness var sits on the
    // *same* operand as block.timestamp). Must still fire.
    const VULN_SUB_FORM: &str = r#"
        pragma solidity 0.8.27;
        interface IXERC20 { function mint(address to, uint256 amt) external; }
        contract L2Mint {
            uint256 public lastPrice;
            uint256 public lastPriceTimestamp;
            address public mailbox;
            IXERC20 public token;
            function receivePrice(uint256 _price, uint256 _timestamp) external {
                require(msg.sender == mailbox, "auth");
                lastPrice = _price;
                lastPriceTimestamp = _timestamp;
            }
            function mintTokens(uint256 amountIn, uint256 _minOut) external returns (uint256) {
                if (block.timestamp - lastPriceTimestamp > 1 days) revert();
                uint256 out = (1e18 * amountIn) / lastPrice;
                if (out < _minOut) revert();
                token.mint(msg.sender, out);
                return out;
            }
        }
    "#;

    #[test]
    fn fires_on_subtraction_idiom() {
        assert!(fires(VULN_SUB_FORM), "{:#?}", run(VULN_SUB_FORM));
    }

    // VULN (inheritance split — the REAL Renzo layout): the price/timestamp/receiver
    // state vars live in an ABSTRACT base; the bridge sink and the consumer live in
    // the DERIVED contract. Exercises inherited-state-var + inherited-function
    // resolution (the contract-local version would miss this).
    const VULN_INHERITED: &str = r#"
        pragma solidity 0.8.27;
        interface IXERC20 { function mint(address to, uint256 amt) external; }
        abstract contract DepositStorageV1 {
            uint256 public lastPrice;
            uint256 public lastPriceTimestamp;
            address public receiver;
            IXERC20 public xezETH;
        }
        contract xRenzoDeposit is DepositStorageV1 {
            function getMintRate() public view returns (uint256, uint256) {
                return (lastPrice, lastPriceTimestamp);
            }
            function updatePrice(uint256 _price, uint256 _timestamp) external {
                if (msg.sender != receiver) revert();
                _updatePrice(_price, _timestamp);
            }
            function _updatePrice(uint256 _price, uint256 _timestamp) internal {
                lastPrice = _price;
                lastPriceTimestamp = _timestamp;
            }
            function _deposit(uint256 _tokenEthValue, uint256 _minOut) internal returns (uint256) {
                (uint256 lastPrice, uint256 lastPriceTimestamp) = getMintRate();
                if (block.timestamp > lastPriceTimestamp + 1 days) revert();
                uint256 xezETHAmount = (1e18 * _tokenEthValue) / lastPrice;
                if (xezETHAmount < _minOut) revert();
                xezETH.mint(msg.sender, xezETHAmount);
                return xezETHAmount;
            }
        }
    "#;

    #[test]
    fn fires_on_inherited_layout() {
        let fs = run(VULN_INHERITED);
        assert!(
            fs.iter().any(|f| f.detector == "crosschain-rate-staleness"
                && f.contract == "xRenzoDeposit"
                && f.function == "_deposit"),
            "{:#?}",
            fs
        );
    }

    // SAFE (forwarded block.timestamp): an endpoint-authed entry exists and forwards
    // into an internal writer, but it forwards `block.timestamp` (local receipt),
    // not its own message parameter — so the stored time is genuine.
    const SAFE_FORWARDS_BLOCKTIME: &str = r#"
        pragma solidity 0.8.27;
        interface IXERC20 { function mint(address to, uint256 amt) external; }
        contract L2Mint {
            uint256 public lastPrice;
            uint256 public lastPriceTimestamp;
            address public endpoint;
            IXERC20 public token;
            function receivePrice(uint256 _price, uint256 _timestamp) external {
                require(msg.sender == endpoint, "auth");
                _store(_price);
            }
            function _store(uint256 _price) internal {
                lastPrice = _price;
                lastPriceTimestamp = block.timestamp;   // local receipt time
            }
            function mintTokens(uint256 amountIn, uint256 _minOut) external returns (uint256) {
                if (block.timestamp > lastPriceTimestamp + 1 days) revert();
                uint256 out = (1e18 * amountIn) / lastPrice;
                if (out < _minOut) revert();
                token.mint(msg.sender, out);
                return out;
            }
        }
    "#;

    #[test]
    fn silent_when_forwarding_blocktime() {
        assert!(!fires(SAFE_FORWARDS_BLOCKTIME), "{:#?}", run(SAFE_FORWARDS_BLOCKTIME));
    }
}
