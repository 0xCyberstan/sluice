//! DVN / M-of-N quorum conflation — a receive-side message-verification predicate
//! that proves a signer "verified" by comparing its submitted block
//! **confirmations** against a config `confirmations` value, conflating *liveness*
//! (how deep the chain was when the DVN observed the message) with the *security
//! quorum* (how many distinct, trusted DVNs attested). This is the Wormhole-class
//! M-of-N verification shape.
//!
//! ## The shape
//!
//! An attestation/verification library stores per-DVN attestations in a **3-deep
//! mapping keyed last by the signer address**:
//!
//! ```solidity
//! struct Verification { bool submitted; uint64 confirmations; }
//! mapping(bytes32 headerHash =>
//!     mapping(bytes32 payloadHash =>
//!         mapping(address dvn => Verification))) public hashLookup;
//! ```
//!
//! and a **per-signer predicate** decides "this DVN verified" by reading that
//! store and comparing the stored `confirmations` against a *config* confirmation
//! count — `verification.confirmations >= _requiredConfirmation`:
//!
//! ```solidity
//! function _verified(address _dvn, bytes32 h, bytes32 p, uint64 _required)
//!     internal view returns (bool verified)
//! {
//!     Verification memory v = hashLookup[h][p][_dvn];
//!     verified = v.submitted && v.confirmations >= _required;   // liveness, not quorum
//! }
//! ```
//!
//! The number of block confirmations a DVN reports is a *liveness* signal — it
//! says nothing about how many **distinct** trusted signers attested. A threshold
//! loop built on this predicate (`for i in requiredDVNs: if !_verified(...) return
//! false`) is only as strong as the per-signer predicate: if the predicate can be
//! satisfied by a single signer reporting a large-enough `confirmations`, or if the
//! same submission counts toward the quorum without an exact distinct-signer
//! cardinality check, the M-of-N guarantee is not actually enforced. This is the
//! LayerZero `ReceiveUlnBase._verified` / `_checkVerifiable` shape and the broader
//! Wormhole-class verification surface.
//!
//! ## Why the `confirmations` compare is the tell
//!
//! A *correct* M-of-N predicate ANDs a membership/submitted bool with an **exact
//! cardinality** — `count == requiredDVNs.length`, `signers >= requiredThreshold`
//! over a set of *distinct* addresses. A predicate whose only numeric comparison is
//! a `confirmations`-named field (a block-depth liveness count) is conflating the
//! two: depth-of-chain is being treated as the security threshold.
//!
//! ## Precision anchors (all required)
//!
//!   * the contract is verification-shaped by name (`uln`, `dvn`, `verif`,
//!     `attest`, `quorum`, `receivelib`, `receiveuln`);
//!   * a state variable is a **3-deep `mapping(... => mapping(... => mapping(address
//!     => …)))`** whose innermost key is `address` (the per-signer attestation
//!     store);
//!   * a `view`/`pure` **per-signer predicate** returns `bool`, reads that 3-deep
//!     store indexed by an `address` signer key, and its **only numeric comparison
//!     is against a `confirmations`-named member** (an ordering/equality compare on
//!     `x.confirmations`), not an exact required-count.
//!
//! ## Suppression (the EXEMPT correct shape)
//!
//!   * the predicate's numeric compare is an **exact cardinality** — an `==`/`>=`
//!     against a `.length` / `count` / `threshold` / `required`-named operand (a
//!     real distinct-signer quorum) — and not a bare `confirmations` ordering. Such
//!     a predicate enforces the M-of-N set size and is out of class.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Contract, Expr, ExprKind, Function, Span};

use super::prelude::*;

pub struct DvnQuorumConflationDetector;

impl Detector for DvnQuorumConflationDetector {
    fn id(&self) -> &'static str {
        "dvn-quorum-conflation"
    }
    fn category(&self) -> Category {
        Category::DvnQuorumConflation
    }
    fn description(&self) -> &'static str {
        "Receive-side M-of-N verification predicate counts a DVN/signer as verified by comparing submitted \
         block confirmations against a config value, conflating liveness with the security quorum (Wormhole / \
         LayerZero ReceiveUlnBase class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for c in cx.scir.iter_contracts() {
            // Restrict to verification-shaped contracts; this class only lives in a
            // bridge / DVN / attestation receive-library, never in a vault/AMM.
            if !contract_is_verification_lib(c) {
                continue;
            }
            // There must be a 3-deep `mapping(=>mapping(=>mapping(address=>X)))`
            // attestation store keyed last by the signer address.
            let Some(store) = three_deep_signer_store(c) else { continue };

            // Find the per-signer predicate whose only numeric compare conflates the
            // confirmations liveness count with the security quorum.
            for f in cx.scir.functions_of(c.id) {
                if let Some(hit) = vulnerable_predicate(f, &store) {
                    out.push(self.finding(cx, c, f, &store, hit));
                }
            }
        }
        out
    }
}

impl DvnQuorumConflationDetector {
    fn finding(
        &self,
        cx: &AnalysisContext,
        c: &Contract,
        f: &Function,
        store: &str,
        hit: PredicateHit,
    ) -> Finding {
        let b = report!(self, Category::DvnQuorumConflation,
            title = "M-of-N verification predicate conflates block-confirmations (liveness) with the security quorum",
            severity = Severity::High,
            confidence = 0.8,
            dimensions = [Dimension::Frontier],
            message = format!(
                "`{contract}.{fname}` is a per-signer message-verification predicate that reads the 3-deep \
                 per-DVN attestation store `{store}[..][..][<address>]` and decides a signer \"verified\" by \
                 comparing its stored `{field}`-named field against a config confirmation count \
                 (`{field} {op} <required>`) — its only numeric quorum compare is on block CONFIRMATIONS, a \
                 LIVENESS signal, not on the number of DISTINCT trusted signers. The count of block \
                 confirmations a DVN reports says nothing about how many independent DVNs attested, so a \
                 threshold loop built on this predicate does not actually enforce its M-of-N security \
                 guarantee: it can be satisfied by liveness depth rather than by an exact distinct-signer \
                 cardinality (`count == requiredDVNs.length` / `optionalDVNThreshold`). This is the \
                 Wormhole-class / LayerZero `ReceiveUlnBase._verified` + `_checkVerifiable` conflation of \
                 liveness with quorum.",
                contract = c.name,
                fname = f.name,
                store = store,
                field = hit.field,
                op = hit.op_text,
            ),
            recommendation =
                "Separate liveness from quorum. Use the per-signer `confirmations` value only as a freshness \
                 / finality gate, and enforce the security threshold against the number of DISTINCT trusted \
                 signers that submitted — e.g. require an exact cardinality `verifiedCount == \
                 requiredDVNs.length` and `optionalCount >= optionalDVNThreshold` over the set of unique DVN \
                 addresses, never letting a single attestation's confirmation depth stand in for the M-of-N \
                 count.",
        );
        finish_at(cx, b, f.id, hit.span)
    }
}

// --------------------------------------------------------------------------- gates

/// The matched predicate: the `confirmations`-named field it compares, the
/// comparison operator (for the message), and the report span.
struct PredicateHit {
    field: String,
    op_text: &'static str,
    span: Span,
}

/// Contract name marks it as a verification / DVN / attestation receive-library.
/// This is the scope restriction — the class is bridge-message-verification only.
fn contract_is_verification_lib(c: &Contract) -> bool {
    let n = c.name.to_ascii_lowercase();
    const NAMES: &[&str] = &[
        "uln", "dvn", "verif", "attest", "quorum", "receivelib", "receiveuln", "msgverif",
    ];
    NAMES.iter().any(|k| n.contains(k))
}

/// Find a state variable that is a **3-deep** `mapping(K1 => mapping(K2 =>
/// mapping(address => V)))` whose innermost key is `address` — the per-signer
/// attestation store. Returns the variable name.
fn three_deep_signer_store(c: &Contract) -> Option<String> {
    c.state_vars.iter().find(|v| is_three_deep_address_keyed_mapping(&v.ty)).map(|v| v.name.clone())
}

/// Textual test: `ty` is exactly three nested `mapping(...)` levels and the
/// innermost key type is `address` (`mapping(.. => mapping(.. => mapping(address
/// => X)))`). The parser collapses field-named mapping keys, so we match on the
/// canonical `mapping(K => ...)` form rather than on the original key names.
fn is_three_deep_address_keyed_mapping(ty: &str) -> bool {
    let t = ty.trim();
    // Exactly three `mapping` keywords — two outer + one innermost address-keyed.
    if t.matches("mapping").count() != 3 {
        return false;
    }
    // The innermost mapping must be keyed by `address`: the last `mapping(` opener
    // is immediately followed by `address =>`.
    let Some(idx) = t.rfind("mapping(") else { return false };
    let inner = t[idx + "mapping(".len()..].trim_start();
    let key = inner.split("=>").next().unwrap_or("").trim();
    key == "address"
}

/// Is `f` the *vulnerable per-signer predicate*? It must be a `view`/`pure` `bool`
/// returner that (a) reads the 3-deep attestation `store` indexed by an `address`
/// signer key, and (b) whose only numeric quorum comparison is against a
/// `confirmations`-named member — and is NOT the exempt exact-cardinality shape.
fn vulnerable_predicate(f: &Function, store: &str) -> Option<PredicateHit> {
    if !f.has_body || !f.is_view_or_pure() {
        return None;
    }
    // Must return a bool (the per-signer verdict). Accept a named `verified` /
    // anonymous bool return.
    if !returns_bool(f) {
        return None;
    }
    // It must read the 3-deep attestation store indexed three levels deep ending in
    // an address-typed signer key (a parameter typed `address`).
    if !reads_store_by_signer(f, store) {
        return None;
    }

    // Collect the numeric comparisons in the body.
    let cmps = numeric_comparisons(f);
    if cmps.is_empty() {
        return None;
    }

    // EXEMPT: if any comparison is an exact-cardinality quorum check (a `.length` /
    // count / threshold / required operand), the predicate enforces a real
    // distinct-signer M-of-N and is out of class.
    if cmps.iter().any(|c| c.is_exact_cardinality) {
        return None;
    }

    // FIRE: the (only) numeric compare(s) are against a `confirmations`-named field.
    cmps.iter().find(|c| c.is_confirmations).map(|c| PredicateHit {
        field: c.field.clone(),
        op_text: c.op_text,
        span: c.span,
    })
}

// --------------------------------------------------------------------------- helpers

/// Does `f` declare a `bool` return (named or anonymous)?
fn returns_bool(f: &Function) -> bool {
    f.returns.iter().any(|r| r.ty.trim() == "bool")
}

/// Does the body read `store[..][..][<addr>]` — the 3-deep attestation mapping
/// indexed three levels deep, the last index resolving to an `address`-typed
/// parameter (the signer / DVN)? We require the triple-`Index` chain rooted at the
/// store var, and the innermost index to be an `address` parameter of `f`.
fn reads_store_by_signer(f: &Function, store: &str) -> bool {
    let mut found = false;
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            if found {
                return;
            }
            // Outermost `Index` of a 3-deep chain: base is `store[a][b]`, this adds
            // `[signer]`.
            let ExprKind::Index { base, index: Some(idx) } = &e.kind else { return };
            if index_depth(base) != 2 {
                return;
            }
            if root_ident_str(base).as_deref() != Some(store) {
                return;
            }
            // Innermost (signer) key must be an address-typed parameter.
            if let Some(name) = root_ident_str(idx) {
                if is_address_param(f, name) {
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

/// Count of nested `Index` levels rooted at this expression: `a` -> 0, `a[i]` -> 1,
/// `a[i][j]` -> 2. (Member chains in between, e.g. `self.a[i]`, are transparent.)
fn index_depth(e: &Expr) -> u32 {
    match &e.kind {
        ExprKind::Index { base, .. } => 1 + index_depth(base),
        ExprKind::Member { base, .. } => index_depth(base),
        _ => 0,
    }
}

/// Is `name` a parameter of `f` whose declared type is `address`?
fn is_address_param(f: &Function, name: &str) -> bool {
    f.params.iter().any(|p| p.name.as_deref() == Some(name) && p.ty.trim() == "address")
}

/// A numeric comparison found in the predicate body, classified.
struct Cmp {
    /// `confirmations`-named member on one side.
    is_confirmations: bool,
    /// Exact-cardinality quorum compare (`.length` / count / threshold / required).
    is_exact_cardinality: bool,
    /// The matched member field name (for the message).
    field: String,
    op_text: &'static str,
    span: Span,
}

/// All numeric (ordering or equality) comparisons in the body, each classified as a
/// `confirmations` liveness compare and/or an exact-cardinality quorum compare.
fn numeric_comparisons(f: &Function) -> Vec<Cmp> {
    let mut out = Vec::new();
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            let ExprKind::Binary { op, lhs, rhs } = &e.kind else { return };
            if !op.is_comparison() {
                return;
            }
            // We only care about ordering/equality compares that gate the verdict
            // (`==`/`>=`/`>`/`<=`/`<`). `!=` against zero is a presence check, not a
            // quorum compare — but classify it anyway; it is neither confirmations
            // nor cardinality, so it is inert.
            let conf = side_is_confirmations(lhs).or_else(|| side_is_confirmations(rhs));
            let card = side_is_cardinality(lhs, *op) || side_is_cardinality(rhs, *op);
            if conf.is_none() && !card {
                return;
            }
            out.push(Cmp {
                is_confirmations: conf.is_some(),
                is_exact_cardinality: card,
                field: conf.unwrap_or_default(),
                op_text: op_text(*op),
                span: e.span,
            });
        });
    }
    out
}

/// If `e` is (or contains as a direct operand) a member access ending in a
/// `confirmation(s)`-named field, return that field name. We match the *immediate*
/// comparison operand: a `x.confirmations` member, or a bare `confirmations`-named
/// identifier/parameter.
fn side_is_confirmations(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Member { member, .. } if is_confirmations_name(member) => Some(member.clone()),
        ExprKind::Ident(n) if is_confirmations_name(n) => Some(n.clone()),
        _ => None,
    }
}

/// A field/identifier name denoting a block-confirmation liveness count.
fn is_confirmations_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l == "confirmations"
        || l == "confirmation"
        || l.ends_with("confirmations")
        || l.ends_with("confirmation")
        || l == "blockconfirmations"
        || l == "_requiredconfirmation"
        || l == "requiredconfirmations"
}

/// Is one side of the comparison an **exact-cardinality** quorum operand — a
/// `.length`, or a count/threshold/required-named member/identifier — under an
/// equality or `>=`/`<=` operator (the real distinct-signer M-of-N check)? This is
/// the EXEMPT correct shape.
fn side_is_cardinality(e: &Expr, op: BinOp) -> bool {
    // The compare must be a cardinality-style operator (an exact set-size check or a
    // threshold-over-count), not an arbitrary ordering on an unrelated scalar.
    if !matches!(op, BinOp::Eq | BinOp::Ge | BinOp::Le | BinOp::Gt | BinOp::Lt) {
        return false;
    }
    match &e.kind {
        // `requiredDVNs.length`, `signers.length`
        ExprKind::Member { member, .. } if member == "length" => true,
        // `count`, `verifiedCount`, `requiredCount`, `threshold`, `requiredDVNs`...
        ExprKind::Member { member, .. } => is_cardinality_name(member),
        ExprKind::Ident(n) => is_cardinality_name(n),
        _ => false,
    }
}

/// A name denoting a distinct-signer **count / threshold / required-set size** — an
/// exact-cardinality quorum operand (not a confirmation-depth liveness count).
fn is_cardinality_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // A `confirmations` field is explicitly NOT a cardinality operand even though it
    // is a count — it is liveness, the very thing we flag.
    if is_confirmations_name(name) {
        return false;
    }
    l == "length"
        || l.ends_with("count")
        || l.ends_with("threshold")
        || l.contains("required")
        || l.ends_with("signers")
        || l.ends_with("quorum")
        || l == "numsigned"
        || l == "numverified"
}

fn op_text(op: BinOp) -> &'static str {
    match op {
        BinOp::Eq => "==",
        BinOp::Ne => "!=",
        BinOp::Lt => "<",
        BinOp::Gt => ">",
        BinOp::Le => "<=",
        BinOp::Ge => ">=",
        _ => "<cmp>",
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "dvn-quorum-conflation")
    }

    // VULN — the LayerZero `ReceiveUlnBase._verified` shape, reduced: a 3-deep
    // per-DVN attestation store, and a per-signer predicate whose only numeric
    // compare is `v.confirmations >= _requiredConfirmation` (liveness as quorum).
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        struct Verification { bool submitted; uint64 confirmations; }
        abstract contract ReceiveUlnBase {
            mapping(bytes32 => mapping(bytes32 => mapping(address => Verification))) public hashLookup;
            function _verified(address _dvn, bytes32 _h, bytes32 _p, uint64 _requiredConfirmation)
                internal view returns (bool verified)
            {
                Verification memory v = hashLookup[_h][_p][_dvn];
                verified = v.submitted && v.confirmations >= _requiredConfirmation;
            }
        }
    "#;

    // VULN (return-form): same conflation, but the predicate `return`s the bool
    // directly and uses `>` on a `blockConfirmations` field.
    const VULN_RETURN: &str = r#"
        pragma solidity ^0.8.20;
        contract DvnAttestation {
            struct Att { bool present; uint64 blockConfirmations; }
            mapping(bytes32 => mapping(bytes32 => mapping(address => Att))) public attestations;
            function isVerified(address signer, bytes32 a, bytes32 b, uint64 minConf)
                public view returns (bool)
            {
                Att storage att = attestations[a][b][signer];
                return att.present && att.blockConfirmations > minConf;
            }
        }
    "#;

    // SAFE (EXEMPT exact-cardinality): the verification predicate ANDs a submitted
    // bool with an EXACT distinct-signer count check (`signed == requiredDVNs.length`)
    // — a real M-of-N quorum, not a confirmations conflation. Must stay silent.
    const SAFE_CARDINALITY: &str = r#"
        pragma solidity ^0.8.20;
        contract UlnVerifier {
            struct Att { bool submitted; uint64 confirmations; }
            mapping(bytes32 => mapping(bytes32 => mapping(address => Att))) public hashLookup;
            address[] public requiredDVNs;
            function _quorumMet(bytes32 h, bytes32 p, uint256 signed)
                internal view returns (bool ok)
            {
                // exact cardinality over the distinct required-DVN set
                ok = signed == requiredDVNs.length;
            }
            function _submitted(address dvn, bytes32 h, bytes32 p) internal view returns (bool) {
                return hashLookup[h][p][dvn].submitted;
            }
        }
    "#;

    // SAFE (threshold over count): predicate checks `verifiedCount >= threshold`
    // over the distinct-signer count — exact cardinality, out of class.
    const SAFE_THRESHOLD: &str = r#"
        pragma solidity ^0.8.20;
        contract QuorumVerifier {
            struct Att { bool submitted; uint64 confirmations; }
            mapping(bytes32 => mapping(bytes32 => mapping(address => Att))) public store;
            function verified(address dvn, bytes32 h, bytes32 p, uint8 verifiedCount, uint8 threshold)
                public view returns (bool)
            {
                Att memory a = store[h][p][dvn];
                return a.submitted && verifiedCount >= threshold;
            }
        }
    "#;

    // SAFE (not a verification-named contract): identical confirmations-conflating
    // predicate, but the contract is a vault — out of scope by name restriction.
    const SAFE_WRONG_CONTRACT: &str = r#"
        pragma solidity ^0.8.20;
        contract Vault {
            struct V { bool submitted; uint64 confirmations; }
            mapping(bytes32 => mapping(bytes32 => mapping(address => V))) public lookup;
            function _verified(address d, bytes32 h, bytes32 p, uint64 req)
                internal view returns (bool ok)
            {
                V memory v = lookup[h][p][d];
                ok = v.submitted && v.confirmations >= req;
            }
        }
    "#;

    // SAFE (only 2-deep store): a verification-named contract whose attestation
    // store is only 2-deep — not the per-(header,payload,signer) shape, so the
    // 3-deep gate excludes it even though it compares confirmations.
    const SAFE_TWO_DEEP: &str = r#"
        pragma solidity ^0.8.20;
        contract UlnLite {
            struct V { bool submitted; uint64 confirmations; }
            mapping(bytes32 => mapping(address => V)) public lookup;
            function _verified(address d, bytes32 p, uint64 req)
                internal view returns (bool ok)
            {
                V memory v = lookup[p][d];
                ok = v.submitted && v.confirmations >= req;
            }
        }
    "#;

    #[test]
    fn fires_on_receiveulnbase_shape() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_return_form() {
        assert!(fires(VULN_RETURN), "{:#?}", run(VULN_RETURN));
    }

    #[test]
    fn silent_on_exact_cardinality() {
        assert!(!fires(SAFE_CARDINALITY), "{:#?}", run(SAFE_CARDINALITY));
    }

    #[test]
    fn silent_on_threshold_over_count() {
        assert!(!fires(SAFE_THRESHOLD), "{:#?}", run(SAFE_THRESHOLD));
    }

    #[test]
    fn silent_on_non_verification_contract() {
        assert!(!fires(SAFE_WRONG_CONTRACT), "{:#?}", run(SAFE_WRONG_CONTRACT));
    }

    #[test]
    fn silent_on_two_deep_store() {
        assert!(!fires(SAFE_TWO_DEEP), "{:#?}", run(SAFE_TWO_DEEP));
    }
}
