//! Pre-auth callout to an attacker-named target — an EIP-1271 / external
//! authorization callback dispatched to a *caller-supplied* address **before**
//! that address is authorized / whitelisted.
//!
//! A signature-verification path lets the caller name the address that is
//! supposed to have signed (the order's `benefactor` / `signer` / a `target`
//! field) and then, to support smart-contract signers, performs an **EIP-1271
//! `isValidSignature` callback on that very caller-named address** — i.e. it
//! hands control to attacker code — *ahead of* the access guard that decides
//! whether the address is allowed to participate (a whitelist `contains`, a
//! `hasRole`, an `isApproved`, or a `require`/`if-revert` on the same field).
//!
//! Because the callback fires first, the named contract runs with the full
//! pre-check state of the protocol: it can re-enter, observe/poison transient
//! state, or simply force the magic-value return to pass the signature gate —
//! all while the contract has not yet confirmed the address is even on the
//! allowlist. The guard that *would* have rejected an arbitrary `benefactor`
//! runs only *after* the attacker's code has already executed. This is the
//! Ethena `EthenaMinting.verifyOrder` shape:
//!
//! ```solidity
//! } else if (signature.signature_type == SignatureType.EIP1271) {
//!   if (IERC1271(order.benefactor).isValidSignature(taker_order_hash, signature.signature_bytes)
//!         != EIP1271_MAGICVALUE) {              // <-- callout to caller-named order.benefactor
//!     revert InvalidEIP1271Signature();
//!   }
//! }
//! if (!_whitelistedBenefactors.contains(order.benefactor)) {  // <-- guard runs AFTER the callout
//!   revert BenefactorNotWhitelisted();
//! }
//! ```
//!
//! Precision anchors (all required, so this stays quiet on ordinary
//! pass-an-interface / value-transfer code):
//!   * the call is an **authorization callback** — its resolved method name is
//!     `isValidSignature` / `isValidSignatureNow` / a `*callback*` / `*onSign*`
//!     hook — not a plain `transfer`/`call`/`swap` (a raw value send to a param
//!     is the `untrusted-call-target` / `arbitrary-transfer` class, not this);
//!   * the call's **receiver root-resolves to a caller-supplied parameter**
//!     (after peeling the `IFoo(x)` interface-cast wrapper), and the leaf field
//!     it reads names a *signer-like* principal (`benefactor` / `signer` /
//!     `owner` / `target` / `account` / `from`);
//!   * there is an **access / whitelist guard on that same principal that runs
//!     AFTER the callback** (a `contains` / `hasRole` / `isApproved` /
//!     `isWhitelisted` lookup, or a `require`/`if-revert` mentioning the field) —
//!     established by call/effect order and lexical span;
//!   * **SUPPRESS** when the principal is already checked/whitelisted *before*
//!     the callback (the guard is correctly ordered), or when the call receiver
//!     is an immutable/constant address (a fixed, non-attacker target).

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{CallKind, Expr, ExprKind, Function, Span};

use super::prelude::*;

pub struct PreAuthCalloutTargetDetector;

impl Detector for PreAuthCalloutTargetDetector {
    fn id(&self) -> &'static str {
        "preauth-callout-target"
    }
    fn category(&self) -> Category {
        Category::PreAuthCalloutTarget
    }
    fn description(&self) -> &'static str {
        "EIP-1271 / external authorization callback dispatched to a caller-supplied (attacker-named) address before the whitelist/role check authorizes it (Ethena verifyOrder class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        // Not restricted to `entry_points()`: the real target (`verifyOrder`) is a
        // `public view` verification helper, and the bug is the control-transfer
        // *ordering*, which a view function exhibits just as readily as a mutating
        // one. We require only a body and a contract context. Library `recover`
        // helpers etc. are excluded structurally below (no EIP-1271 callout there).
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            let Some(contract) = cx.contract_of(f.id) else { continue };
            // Interfaces / pure declarations carry no concrete call to analyse.
            if contract.is_interface() {
                continue;
            }

            // Find the first authorization callback whose receiver is a caller-named
            // principal.
            let Some(callout) = first_preauth_callout(f) else { continue };

            // Suppress if the principal is validated *before* the callback (the
            // guard is correctly ordered) — that is the safe pattern.
            if principal_guarded_before(f, &callout) {
                continue;
            }

            // Require a guard on the SAME principal that runs AFTER the callback —
            // the inverted order that makes this the bug rather than a benign
            // EIP-1271 verification with no allowlist at all.
            if !principal_guarded_after(f, &callout) {
                continue;
            }

            let b = report!(self, Category::PreAuthCalloutTarget,
                title = "EIP-1271 authorization callback dispatched to a caller-named address before it is whitelisted",
                severity = Severity::High,
                confidence = 0.62,
                dimensions = [Dimension::Frontier, Dimension::ValueFlow],
                message = format!(
                    "`{}` performs an EIP-1271 / authorization callback (`{}`) on `{}` — a caller-supplied address \
                     taken from the `{}` parameter — and only checks that the address is authorized/whitelisted \
                     AFTERWARD. Because the callback hands control to the caller-named contract before the guard \
                     runs, an attacker can name a contract they control as the signer: its `isValidSignature` (or \
                     callback) executes first — able to re-enter, observe pre-check state, or simply return the \
                     magic value to pass the signature gate — all before the contract confirms the address is even \
                     allowed. This is the pre-auth-callout-to-attacker-target class (e.g. Ethena \
                     `EthenaMinting.verifyOrder` calling `IERC1271(order.benefactor).isValidSignature(...)` ahead of \
                     the `_whitelistedBenefactors.contains(order.benefactor)` check).",
                    f.name, callout.method, callout.receiver_text, callout.root_param
                ),
                recommendation =
                    "Authorize the caller-supplied principal BEFORE dispatching any EIP-1271 / callback to it: check \
                     the whitelist / role / approval (`require(_whitelisted.contains(benefactor))`, `hasRole`, …) \
                     first, then call `isValidSignature`. Equivalently, route smart-contract-signature checks \
                     through a guarded helper that admits only already-authorized addresses, and add a reentrancy \
                     guard on the surrounding mint/redeem path so the callback cannot re-enter pre-authorization \
                     state.",
            );
            out.push(finish_at(cx, b, f.id, callout.span));
        }
        out
    }
}

// ----------------------------------------------------------------- helpers

/// A matched pre-auth authorization callback.
struct Callout {
    /// Resolved callback method name (`isValidSignature`, …).
    method: String,
    /// Source-rendered receiver text (`IERC1271(order.benefactor)`), best-effort.
    receiver_text: String,
    /// Root identifier the receiver resolves to — must be a function parameter
    /// (`order`, or a bare `signer` address param).
    root_param: String,
    /// Leaf field/principal name the receiver reads (`benefactor`, `signer`), or
    /// the param name itself when the receiver is a bare address parameter.
    principal: String,
    /// Lexical span of the callback call (where the finding points).
    span: Span,
    /// Start byte offset of the callback — the lexical ordering anchor.
    pos: u32,
}

/// The first external authorization-callback call in `f` whose receiver
/// root-resolves to a caller-supplied parameter and reads a signer-like
/// principal. Document order, short-circuiting on the first match.
fn first_preauth_callout(f: &Function) -> Option<Callout> {
    let mut found: Option<Callout> = None;
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            if found.is_some() {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            // Only calls that transfer control to an external party. (Interface
            // casts sometimes surface the call kind as External; staticcall/
            // lowlevel are also accepted — an EIP-1271 check is typically a
            // `staticcall` under the hood.)
            if !matches!(
                c.kind,
                CallKind::External | CallKind::StaticCall | CallKind::LowLevelCall
            ) {
                return;
            }
            // The resolved method must be an authorization callback.
            if !is_auth_callback(c.func_name.as_deref()) {
                return;
            }
            let Some(recv) = c.receiver.as_deref() else { return };
            // Resolve the receiver to its root identifier + leaf principal field,
            // peeling the interface-cast wrapper (even when the parser mislabels
            // `IFoo(x)` as an Internal call rather than a TypeCast).
            let Some((root, principal)) = resolve_receiver(recv) else { return };
            // The root must be a caller-supplied parameter.
            if !is_param(f, &root) {
                return;
            }
            // The principal it reads must look like a signer/benefactor/target —
            // an address the caller names as the supposed authorizer.
            if !is_principal_name(&principal) {
                return;
            }
            found = Some(Callout {
                method: c.func_name.clone().unwrap_or_default(),
                receiver_text: render_receiver(recv),
                root_param: root,
                principal,
                span: e.span,
                pos: e.span.start,
            });
        });
        if found.is_some() {
            break;
        }
    }
    found
}

/// Is `name` an EIP-1271 / authorization-callback method? (`isValidSignature`,
/// `isValidSignatureNow`, or a generic `*callback*` / `*onSign*` auth hook).
fn is_auth_callback(name: Option<&str>) -> bool {
    let Some(n) = name else { return false };
    let l = n.to_ascii_lowercase();
    l == "isvalidsignature"
        || l == "isvalidsignaturenow"
        || l.starts_with("isvalidsignature")
        || l.contains("verifysignature")
        || l == "onsignature"
        || l.contains("signaturecallback")
}

/// Does `name` denote a signer-like *principal* — the address a caller claims is
/// the authorizer/owner of an order? Deliberately the auth-relevant set
/// (`benefactor`/`signer`/`owner`/`target`/`account`/`from`/`maker`/`taker`),
/// not arbitrary address fields, so a value-transfer recipient (`beneficiary`,
/// `wallet`, `to`, `recipient`) does not trip this signature-callback detector.
fn is_principal_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "benefactor", "signer", "owner", "target", "account", "maker", "taker", "principal",
    ]
    .iter()
    .any(|k| l == *k || l.ends_with(k))
        // `from`/`sender` only as a whole word (avoid `fromBlock`, etc.).
        || l == "from"
        || l == "sender"
}

/// Resolve a callback receiver to `(root_ident, leaf_principal)`, peeling
/// interface-cast wrappers. Returns `None` if the receiver is not rooted in a
/// bare identifier.
///
/// Two leaf shapes:
///   * `IERC1271(order.benefactor)` -> root `order`, principal `benefactor`
///     (the cast is peeled; the inner `order.benefactor` member gives both);
///   * `IERC1271(signer)` -> root `signer`, principal `signer` (bare address
///     param used directly as the receiver).
fn resolve_receiver(recv: &Expr) -> Option<(String, String)> {
    let inner = peel_cast_like(recv);
    match &inner.kind {
        // `order.benefactor` -> root = base root, principal = the member.
        ExprKind::Member { base, member } => {
            let root = root_through_casts(base)?;
            Some((root, member.clone()))
        }
        // `signer` -> a bare address parameter; principal == root.
        ExprKind::Ident(n) => Some((n.clone(), n.clone())),
        // `targets[i]` -> root = base root, principal = base root (no member name).
        ExprKind::Index { base, .. } => {
            let root = root_through_casts(base)?;
            Some((root.clone(), root))
        }
        _ => None,
    }
}

/// Peel cast-like single-argument wrappers off `e`, returning the innermost
/// operand. Handles both the canonical [`peel_casts`] (`CallKind::TypeCast`) AND
/// the case where an interface cast `IFoo(x)` is parsed as a one-arg call with a
/// bare-identifier/type-name callee and **no receiver** — which the Ethena IR
/// produces for `IERC1271(order.benefactor)` (callee `Ident("IERC1271")`, kind
/// `Internal`). A one-arg, receiver-less call to a capitalized/type-like callee is
/// overwhelmingly a type cast, not a real function call.
fn peel_cast_like(e: &Expr) -> &Expr {
    let mut cur = e;
    loop {
        match &cur.kind {
            ExprKind::Call(c) if c.kind == CallKind::TypeCast && c.args.len() == 1 => {
                cur = &c.args[0];
            }
            ExprKind::Call(c)
                if c.args.len() == 1 && c.receiver.is_none() && callee_is_cast_like(&c.callee) =>
            {
                cur = &c.args[0];
            }
            _ => return cur,
        }
    }
}

/// Is this callee expression a type/interface name used for a cast — a bare
/// identifier that is either a known address-cast keyword or looks like a type
/// (`IERC1271`, `Foo`, starts uppercase or `I`-prefixed), or a `TypeName` node?
fn callee_is_cast_like(callee: &Expr) -> bool {
    match &callee.kind {
        ExprKind::TypeName(_) => true,
        ExprKind::Ident(n) => {
            let l = n.to_ascii_lowercase();
            // Address/value cast keywords.
            if l == "address" || l == "payable" || l.starts_with("uint") || l.starts_with("int") || l == "bytes32" {
                return true;
            }
            // Interface/contract type name: `IERC1271`, `IFoo`, or any
            // capitalized identifier (Solidity types are conventionally
            // PascalCase; locals/params are lowerCamelCase).
            n.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        }
        _ => false,
    }
}

/// Root identifier of a member/index chain, descending through cast-like
/// wrappers at every level. `IFoo(a).b[c]` -> `Some("a")`.
fn root_through_casts(e: &Expr) -> Option<String> {
    match &peel_cast_like(e).kind {
        ExprKind::Ident(n) => Some(n.clone()),
        ExprKind::Member { base, .. } | ExprKind::Index { base, .. } => root_through_casts(base),
        _ => None,
    }
}

/// Best-effort textual rendering of the receiver for the message — the leaf shape
/// (`IFoo(order.benefactor)` / `signer`). Falls back to the principal chain.
fn render_receiver(recv: &Expr) -> String {
    fn go(e: &Expr) -> String {
        match &e.kind {
            ExprKind::Ident(n) => n.clone(),
            ExprKind::Member { base, member } => format!("{}.{}", go(base), member),
            ExprKind::Index { base, .. } => format!("{}[..]", go(base)),
            ExprKind::Call(c) if c.args.len() == 1 && c.receiver.is_none() => {
                let name = c.func_name.clone().unwrap_or_else(|| "_".into());
                format!("{}({})", name, go(&c.args[0]))
            }
            _ => "<target>".to_string(),
        }
    }
    go(recv)
}

/// Is the principal **authorized** *before* the callback (lower lexical
/// position)? A whitelist/role/approval *lookup* on the principal that runs
/// before the callout is the safe ordering — suppress. Only the lookup family
/// counts as authorization; a signature-equality comparison
/// (`signer == order.benefactor`) in a sibling branch is **not** authorization
/// and must not suppress.
fn principal_guarded_before(f: &Function, callout: &Callout) -> bool {
    authz_lookup_on_side(f, callout, Side::Before)
}

/// Is there a whitelist/role/approval lookup on the principal that runs *after*
/// the callback (higher lexical position)? This inverted order — callout first,
/// authorization second — is the signal that makes the callout a pre-auth bug
/// rather than a benign EIP-1271 check with no allowlist at all.
fn principal_guarded_after(f: &Function, callout: &Callout) -> bool {
    authz_lookup_on_side(f, callout, Side::After)
}

#[derive(Clone, Copy, PartialEq)]
enum Side {
    Before,
    After,
}

/// Does a whitelist/role/approval *lookup* on the principal occur entirely on the
/// requested lexical side of the callout? `Before` requires the lookup to end at
/// or before the callout start (so the callout's own enclosing condition, which
/// *contains* the callout, never counts); `After` requires the lookup to begin
/// strictly after the callout start.
fn authz_lookup_on_side(f: &Function, callout: &Callout, side: Side) -> bool {
    let mut hit = false;
    for s in &f.body {
        s.visit_exprs(&mut |e: &Expr| {
            if hit {
                return;
            }
            let ExprKind::Call(c) = &e.kind else { return };
            if !is_whitelist_lookup(c.func_name.as_deref()) {
                return;
            }
            // The lookup must be *about* the principal: it appears in the lookup's
            // arguments, or indexes the lookup's receiver
            // (`_approvedBeneficiariesPerBenefactor[order.benefactor].contains(..)`).
            let about_principal = c.args.iter().any(|a| mentions_principal(a, callout))
                || c.receiver.as_deref().is_some_and(|r| mentions_principal(r, callout));
            if !about_principal {
                return;
            }
            let on_side = match side {
                // Strictly before: the whole lookup precedes the callout.
                Side::Before => e.span.end <= callout.pos,
                // Strictly after: the lookup starts past the callout.
                Side::After => e.span.start > callout.pos,
            };
            if on_side {
                hit = true;
            }
        });
        if hit {
            break;
        }
    }
    hit
}

/// Is `name` a membership / role / approval lookup method?
fn is_whitelist_lookup(name: Option<&str>) -> bool {
    let Some(n) = name else { return false };
    let l = n.to_ascii_lowercase();
    l == "contains"
        || l == "hasrole"
        || l.starts_with("iswhitelisted")
        || l.starts_with("isapproved")
        || l.starts_with("isallowed")
        || l.starts_with("isregistered")
        || l.contains("whitelist")
        || l == "checkrole"
}

/// Does `e` reference the *specific principal* the callout dispatched to —
/// either the bare-address parameter itself (`signer`), or a member access whose
/// leaf is the principal field (`order.benefactor`)? This is deliberately the
/// leaf field, not merely the struct root: a later guard on a *different* field
/// of the same struct (`order.beneficiary`) must NOT count as authorizing the
/// principal, so e.g. an `_approvedBeneficiaries.contains(order.beneficiary)`
/// lookup does not satisfy the "principal guarded after" requirement.
fn mentions_principal(e: &Expr, callout: &Callout) -> bool {
    // For a bare-address principal (root == principal) the field IS the ident.
    if callout.root_param == callout.principal {
        return expr_mentions_ident(e, &callout.principal);
    }
    let mut found = false;
    e.visit(&mut |sub| {
        if found {
            return;
        }
        if let ExprKind::Member { member, .. } = &sub.kind {
            if member == &callout.principal {
                found = true;
            }
        }
    });
    found
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "preauth-callout-target")
    }

    // The Ethena `EthenaMinting.verifyOrder` shape: the EIP-1271 callback fires on
    // the caller-named `order.benefactor` BEFORE the `_whitelistedBenefactors`
    // whitelist check authorizes it.
    const VULN: &str = r#"
        pragma solidity 0.8.20;
        interface IERC1271 { function isValidSignature(bytes32 h, bytes calldata s) external view returns (bytes4); }
        library EnumerableSet {
            struct AddressSet { uint256 _x; }
            function contains(AddressSet storage set, address v) internal view returns (bool) {}
        }
        contract Minting {
            using EnumerableSet for EnumerableSet.AddressSet;
            EnumerableSet.AddressSet internal _whitelistedBenefactors;
            bytes4 private constant EIP1271_MAGICVALUE = 0x1626ba7e;
            enum SignatureType { EIP712, EIP1271 }
            struct Signature { SignatureType signature_type; bytes signature_bytes; }
            struct Order { address benefactor; address beneficiary; }
            error InvalidEIP1271Signature();
            error BenefactorNotWhitelisted();
            function hashOrder(Order calldata o) public pure returns (bytes32) { return bytes32(0); }
            function verifyOrder(Order calldata order, Signature calldata signature) public view returns (bytes32 h) {
                h = hashOrder(order);
                if (signature.signature_type == SignatureType.EIP1271) {
                    if (IERC1271(order.benefactor).isValidSignature(h, signature.signature_bytes) != EIP1271_MAGICVALUE) {
                        revert InvalidEIP1271Signature();
                    }
                }
                if (!_whitelistedBenefactors.contains(order.benefactor)) {
                    revert BenefactorNotWhitelisted();
                }
            }
        }
    "#;

    // Safe: the whitelist check on `order.benefactor` runs BEFORE the EIP-1271
    // callback, so the callback only ever reaches an already-authorized address.
    const SAFE_CHECK_FIRST: &str = r#"
        pragma solidity 0.8.20;
        interface IERC1271 { function isValidSignature(bytes32 h, bytes calldata s) external view returns (bytes4); }
        library EnumerableSet {
            struct AddressSet { uint256 _x; }
            function contains(AddressSet storage set, address v) internal view returns (bool) {}
        }
        contract Minting {
            using EnumerableSet for EnumerableSet.AddressSet;
            EnumerableSet.AddressSet internal _whitelistedBenefactors;
            bytes4 private constant EIP1271_MAGICVALUE = 0x1626ba7e;
            struct Signature { bytes signature_bytes; }
            struct Order { address benefactor; }
            error InvalidEIP1271Signature();
            error BenefactorNotWhitelisted();
            function verifyOrder(Order calldata order, Signature calldata signature) public view {
                if (!_whitelistedBenefactors.contains(order.benefactor)) {
                    revert BenefactorNotWhitelisted();
                }
                if (IERC1271(order.benefactor).isValidSignature(bytes32(0), signature.signature_bytes) != EIP1271_MAGICVALUE) {
                    revert InvalidEIP1271Signature();
                }
            }
        }
    "#;

    // Safe: the EIP-1271 callback is on an IMMUTABLE/configured signer address, not
    // a caller-supplied parameter — governance cannot point it at attacker code,
    // and the caller does not name it.
    const SAFE_IMMUTABLE_SIGNER: &str = r#"
        pragma solidity 0.8.20;
        interface IERC1271 { function isValidSignature(bytes32 h, bytes calldata s) external view returns (bytes4); }
        contract Verifier {
            address public immutable signer;
            bytes4 private constant MAGIC = 0x1626ba7e;
            struct Signature { bytes signature_bytes; }
            struct Order { uint256 amount; }
            error BadSig();
            constructor(address s) { signer = s; }
            function verifyOrder(Order calldata order, Signature calldata signature) public view {
                if (IERC1271(signer).isValidSignature(bytes32(order.amount), signature.signature_bytes) != MAGIC) {
                    revert BadSig();
                }
            }
        }
    "#;

    // Safe: an ordinary value transfer to a caller-supplied recipient — NOT an
    // authorization callback. This is the untrusted-call-target / arbitrary-transfer
    // class, not the pre-auth-callout class, so this detector stays silent.
    const SAFE_VALUE_TRANSFER: &str = r#"
        pragma solidity 0.8.20;
        contract Payer {
            error TransferFailed();
            function pay(address to, uint256 amount) external {
                (bool ok, ) = to.call{value: amount}("");
                if (!ok) revert TransferFailed();
            }
        }
    "#;

    // Safe: an EIP-1271 callback to a caller-named benefactor, but there is no
    // later allowlist/role guard on that benefactor at all (the contract simply
    // does not whitelist). Without the inverted-order guard there is nothing to
    // mis-order, so this is out of scope for THIS detector (a different class).
    const SAFE_NO_LATER_GUARD: &str = r#"
        pragma solidity 0.8.20;
        interface IERC1271 { function isValidSignature(bytes32 h, bytes calldata s) external view returns (bytes4); }
        contract Open {
            bytes4 private constant MAGIC = 0x1626ba7e;
            struct Signature { bytes signature_bytes; }
            struct Order { address benefactor; }
            error BadSig();
            function verifyOrder(Order calldata order, Signature calldata signature) public view {
                if (IERC1271(order.benefactor).isValidSignature(bytes32(0), signature.signature_bytes) != MAGIC) {
                    revert BadSig();
                }
            }
        }
    "#;

    // Vulnerable variant: the principal is a BARE address parameter (`signer`),
    // the EIP-1271 callback fires on it, and a ROLE check (`hasRole`) on the same
    // address runs only afterward. Exercises the bare-param + role-lookup path.
    const VULN_BARE_SIGNER_ROLE: &str = r#"
        pragma solidity 0.8.20;
        interface IERC1271 { function isValidSignature(bytes32 h, bytes calldata s) external view returns (bytes4); }
        contract Roles {
            mapping(bytes32 => mapping(address => bool)) _roles;
            bytes4 private constant MAGIC = 0x1626ba7e;
            bytes32 private constant SIGNER_ROLE = keccak256("SIGNER_ROLE");
            error BadSig();
            error NotAuthorized();
            function hasRole(bytes32 role, address account) public view returns (bool) {
                return _roles[role][account];
            }
            function verify(address signer, bytes32 digest, bytes calldata sig) external view {
                if (IERC1271(signer).isValidSignature(digest, sig) != MAGIC) {
                    revert BadSig();
                }
                if (!hasRole(SIGNER_ROLE, signer)) {
                    revert NotAuthorized();
                }
            }
        }
    "#;

    // Safe: the OZ `SignatureChecker` library form. `SignatureChecker.isValidSignatureNow(maker, ...)`
    // dispatches through the *library* — the call's receiver is the library, not the
    // caller-named address — so it is not a direct `IFoo(maker).isValidSignature`
    // callout. This is the recommended pattern; the detector deliberately scopes to
    // the direct-cast form (the Ethena bug) and stays silent here.
    const SAFE_SIGCHECKER_LIB: &str = r#"
        pragma solidity 0.8.20;
        library SignatureChecker {
            function isValidSignatureNow(address signer, bytes32 hash, bytes memory sig) internal view returns (bool) {}
        }
        library EnumerableSet {
            struct AddressSet { uint256 _x; }
            function contains(AddressSet storage set, address v) internal view returns (bool) {}
        }
        contract Limit {
            using EnumerableSet for EnumerableSet.AddressSet;
            EnumerableSet.AddressSet internal _whitelistedMakers;
            struct Order { address maker; }
            error BadSig();
            error NotWhitelisted();
            function hashOrder(Order memory o) internal pure returns (bytes32) { return bytes32(0); }
            function checkSig(Order memory order, bytes memory signature) public view {
                bytes32 h = hashOrder(order);
                require(SignatureChecker.isValidSignatureNow(order.maker, h, signature), "BadSig");
                if (!_whitelistedMakers.contains(order.maker)) revert NotWhitelisted();
            }
        }
    "#;

    // Safe: an EIP-1271 callback to a caller-named benefactor with a later guard,
    // but the later guard is on a DIFFERENT field (`order.beneficiary`), not the
    // callout principal (`order.benefactor`). The principal itself is never
    // authorized after the callout, so the leaf-field discrimination keeps this
    // from matching the unrelated guard.
    const SAFE_GUARD_DIFFERENT_FIELD: &str = r#"
        pragma solidity 0.8.20;
        interface IERC1271 { function isValidSignature(bytes32 h, bytes calldata s) external view returns (bytes4); }
        library EnumerableSet {
            struct AddressSet { uint256 _x; }
            function contains(AddressSet storage set, address v) internal view returns (bool) {}
        }
        contract Minting {
            using EnumerableSet for EnumerableSet.AddressSet;
            EnumerableSet.AddressSet internal _approvedBeneficiaries;
            bytes4 private constant MAGIC = 0x1626ba7e;
            struct Signature { bytes signature_bytes; }
            struct Order { address benefactor; address beneficiary; }
            error BadSig();
            error BeneficiaryNotApproved();
            function verifyOrder(Order calldata order, Signature calldata signature) public view {
                if (IERC1271(order.benefactor).isValidSignature(bytes32(0), signature.signature_bytes) != MAGIC) {
                    revert BadSig();
                }
                if (!_approvedBeneficiaries.contains(order.beneficiary)) {
                    revert BeneficiaryNotApproved();
                }
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        assert!(fires(VULN), "{:#?}", run(VULN));
    }

    #[test]
    fn fires_on_bare_signer_role_after() {
        assert!(fires(VULN_BARE_SIGNER_ROLE), "{:#?}", run(VULN_BARE_SIGNER_ROLE));
    }

    #[test]
    fn silent_on_signaturechecker_library_form() {
        assert!(!fires(SAFE_SIGCHECKER_LIB), "{:#?}", run(SAFE_SIGCHECKER_LIB));
    }

    #[test]
    fn silent_when_later_guard_on_different_field() {
        assert!(!fires(SAFE_GUARD_DIFFERENT_FIELD), "{:#?}", run(SAFE_GUARD_DIFFERENT_FIELD));
    }

    #[test]
    fn silent_when_check_first() {
        assert!(!fires(SAFE_CHECK_FIRST), "{:#?}", run(SAFE_CHECK_FIRST));
    }

    #[test]
    fn silent_when_signer_immutable() {
        assert!(!fires(SAFE_IMMUTABLE_SIGNER), "{:#?}", run(SAFE_IMMUTABLE_SIGNER));
    }

    #[test]
    fn silent_on_value_transfer() {
        assert!(!fires(SAFE_VALUE_TRANSFER), "{:#?}", run(SAFE_VALUE_TRANSFER));
    }

    #[test]
    fn silent_without_later_guard() {
        assert!(!fires(SAFE_NO_LATER_GUARD), "{:#?}", run(SAFE_NO_LATER_GUARD));
    }
}
