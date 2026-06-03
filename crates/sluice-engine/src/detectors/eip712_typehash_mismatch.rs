//! EIP-712 TYPEHASH string vs. encoded-struct field divergence (wrong-field
//! binding / signature-domain confusion).
//!
//! EIP-712 defines the `hashStruct` of a value `s` of type `S` as
//! `keccak256(typeHash ‖ encodeData(s))`, where `typeHash =
//! keccak256(encodeType(S))` is the constant
//! `keccak256("S(field1 type1,field2 type2,…)")`, and `encodeData(s)` is the
//! `abi.encode` of the members **in the exact order they appear in the type
//! string**. The signer (a wallet / off-chain service) builds the digest from
//! the *declared* type string; the contract rebuilds it from whatever it
//! actually `abi.encode`s. Those two must describe the same tuple, in the same
//! order, or the recomputed digest differs from the one the user signed.
//!
//! When the field list baked into the `TYPEHASH` constant **diverges** from the
//! struct the contract feeds into `abi.encode(TYPEHASH, …)` — a field renamed, a
//! type changed, two fields swapped, or a field added/dropped on one side only —
//! the on-chain digest binds the signature to a *different* message than the one
//! presented to (and approved by) the signer. Depending on the direction this is
//! either a permanent DoS (no signature ever verifies) or, worse, a wrong-field
//! binding: a signature the user believed authorised message *A* validates as
//! authorisation for the reordered message *B* (e.g. amount and recipient
//! transposed). This is a CWE-347 (improper verification of a cryptographic
//! signature) integrity bug.
//!
//! ## What this detector does
//!
//! For each contract it pairs every EIP-712 `TYPEHASH` constant —
//! `keccak256("Name(f1 t1,f2 t2,…)")` — with the `abi.encode(TYPEHASH, a1, a2,
//! …)` call in the *same contract* that hashes a struct under it, and compares
//! the **ordered field list** of the type string against the **ordered value
//! arguments** of the encode (the trailing member of each `s.field` argument).
//! It fires only on a *provable* divergence:
//!   * **count mismatch** — the type string lists N fields but M ≠ N value args
//!     are encoded (a field was added/dropped); or
//!   * **provable reorder** — every encoded argument names a *declared field*,
//!     the field-name multiset matches, **but the order differs** (a field
//!     transposition — the wrong-field-binding bug).
//!
//! ## Suppression (precision first — this is the common, correct case)
//!
//! * **Exact match** — the type-string field list corresponds one-to-one, in
//!   order, to the encoded arguments. This is the overwhelmingly common shape
//!   (e.g. Ethena `EthenaMinting.ORDER_TYPE` vs `encodeOrder`'s `abi.encode`),
//!   and it is *not* a finding.
//! * **Rename / pre-hash / computed value** — an encoded argument whose name is
//!   not a declared field (a renamed local such as a permit nonce passed as
//!   `currentValidNonce`, or a domain `name` passed as `keccak256(bytes(name))`,
//!   the EigenLayer `DelegationApproval` `delegationApprover`→`approver` rename)
//!   is *ambiguous*, not a proven mismatch, and never on its own fires. Such a
//!   faithful-but-renamed encoding still has a matching field **count**, so the
//!   count signal also stays silent.
//! * No `abi.encode(TYPEHASH, …)` pairing is found in the contract (the typehash
//!   is unused here, declared in a separate inherited storage base, or encoded in
//!   a way we cannot line up) — we stay silent rather than guess.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};

use super::prelude::*;

pub struct Eip712TypehashMismatchDetector;

impl Detector for Eip712TypehashMismatchDetector {
    fn id(&self) -> &'static str {
        "eip712-typehash-mismatch"
    }
    fn category(&self) -> Category {
        Category::Eip712TypehashMismatch
    }
    fn description(&self) -> &'static str {
        "EIP-712 TYPEHASH field list diverges from the struct abi.encode-d under it (wrong-field binding / signature-domain confusion)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for c in cx.scir.iter_contracts() {
            // Only concrete contracts verify signatures with their own typehash;
            // an interface/abstract base declares no `abi.encode` body to compare.
            if !c.is_concrete() {
                continue;
            }

            // The full contract source (comment-stripped, lowercased) — both the
            // `constant TYPEHASH = keccak256("…")` declarations and the
            // `abi.encode(TYPEHASH, …)` call live here. Constant initializers are
            // not always surfaced as function-body exprs, so we read text (the
            // same approach the sibling `cached-domain-separator` detector uses).
            let contract_src = cx.source_text(c.span);

            // Each EIP-712 typehash constant in this contract: its variable name
            // plus the parsed field list from the baked-in type string.
            for th in find_typehashes(c, cx, &contract_src) {
                // The struct actually abi.encode-d under this typehash, if we can
                // find and line up the `abi.encode(NAME, …)` call here.
                let Some(encoded) = find_encoded_struct(&contract_src, &th.var) else {
                    continue;
                };

                let Some(divergence) = compare(&th.fields, &encoded) else {
                    // Exact correspondence — the signed digest matches the struct.
                    continue;
                };

                let b = report!(self, Category::Eip712TypehashMismatch,
                    title = "EIP-712 TYPEHASH field list diverges from the abi.encode-d struct",
                    severity = Severity::Medium,
                    confidence = 0.6,
                    dimensions = [Dimension::Invariant],
                    message = format!(
                        "In `{contract}`, the EIP-712 type string baked into `{var}` declares the fields \
                         [{decl}], but the struct hashed under it via `abi.encode({var}, …)` supplies \
                         [{enc}] — {why}. EIP-712 `hashStruct` is `keccak256(typeHash ‖ abi.encode(members \
                         in type-string order))`, so the on-chain digest no longer matches the message the \
                         signer approved: at best no signature verifies (DoS), at worst a signature for one \
                         message validates as authorisation for the reordered/relabelled message \
                         (wrong-field binding, CWE-347).",
                        contract = c.name,
                        var = th.var,
                        decl = th.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>().join(", "),
                        enc = encoded.join(", "),
                        why = divergence,
                    ),
                    recommendation =
                        "Make the `TYPEHASH` string and the `abi.encode` argument list describe the SAME \
                         tuple in the SAME order: list every struct member in declaration order in the type \
                         string and pass each member, in that order, to `abi.encode(TYPEHASH, …)`. Add a \
                         test that recovers a wallet-signed EIP-712 digest to lock the correspondence.",
                );
                out.push(finish_at(cx, b, th.fid, th.span));
            }
        }

        out
    }
}

// --------------------------------------------------------------------- model

/// One EIP-712 typehash constant: the state-var name, the parsed type-string
/// field list, and where to report.
struct Typehash {
    /// The constant's name, lowercased (`order_type`, `permit_typehash`).
    var: String,
    /// Fields in type-string order.
    fields: Vec<Field>,
    fid: sluice_ir::FunctionId,
    span: sluice_ir::Span,
}

/// A `type name` pair from an EIP-712 type string (both lowercased).
struct Field {
    ty: String,
    name: String,
}

// ------------------------------------------------------------------- discovery

/// Every EIP-712 typehash constant declared in `c`: a `bytes32` whose own
/// declaration text is `keccak256("Name(field type,…)")` with a parseable,
/// non-empty field list. (The `EIP712Domain(...)` separator is intentionally
/// included — if a contract mis-encoded its domain we'd want to know — but it
/// only fires when an `abi.encode(<that var>, …)` pairing also diverges.)
fn find_typehashes(
    c: &sluice_ir::Contract,
    cx: &AnalysisContext,
    contract_src: &str,
) -> Vec<Typehash> {
    // An anchor function id for location resolution (any function of the
    // contract; the report span is the state-var declaration regardless).
    let Some(fid) = cx.scir.functions_of(c.id).next().map(|f| f.id) else {
        // No functions ⇒ nothing encodes a struct here; skip the whole contract.
        return Vec::new();
    };

    let mut out = Vec::new();
    for v in &c.state_vars {
        // EIP-712 typehashes are `bytes32` constants. (`immutable` ones computed
        // from `abi.encodePacked` of another constant are domain separators, not
        // a struct type string we can field-match — they won't parse below.)
        if !v.constant || v.ty.trim() != "bytes32" {
            continue;
        }
        let decl = cx.source_text(v.span);
        // Must be a `keccak256("…")` over a *string literal* type string.
        let Some(type_string) = extract_keccak_string_literal(&decl) else {
            continue;
        };
        let Some(fields) = parse_type_string(&type_string) else {
            continue;
        };
        if fields.is_empty() {
            continue;
        }
        // Sanity: the constant must actually be referenced by an abi.encode in
        // the contract for the pairing to exist (cheap pre-filter; the precise
        // pairing happens in `find_encoded_struct`).
        if !contract_src.contains(&v.name.to_ascii_lowercase()) {
            continue;
        }
        out.push(Typehash { var: v.name.to_ascii_lowercase(), fields, fid, span: v.span });
    }
    out
}

/// Pull the single string-literal argument out of a `keccak256("…")` initializer.
/// Returns the literal's contents (without the surrounding quotes). Returns
/// `None` when the initializer is not a `keccak256` of a single string literal
/// (e.g. `keccak256(abi.encodePacked(EIP712_DOMAIN))` — a derived hash, not a
/// type string).
fn extract_keccak_string_literal(decl: &str) -> Option<String> {
    let k = decl.find("keccak256")?;
    let after = &decl[k + "keccak256".len()..];
    let open = after.find('(')?;
    let rest = after[open + 1..].trim_start();
    // The very next non-space token must be a string literal — otherwise this is
    // a hash over an expression, not a type string.
    let mut chars = rest.char_indices();
    let (q_idx, quote) = loop {
        match chars.next() {
            Some((i, ch)) if ch == '"' || ch == '\'' => break (i, ch),
            // Allow only whitespace before the quote; a non-space, non-quote
            // first token (`abi`, an ident) means no leading string literal.
            Some((_, ch)) if ch.is_whitespace() => continue,
            _ => return None,
        }
    };
    let body = &rest[q_idx + 1..];
    let end = body.find(quote)?;
    Some(body[..end].to_string())
}

/// Parse an EIP-712 type string `Name(field1 type1,field2 type2,…)` into its
/// ordered field list. Only the **primary** struct's member list (the first
/// parenthesised group) is parsed; trailing nested-struct definitions
/// `…)Sub(…)` are ignored — their hashing is by sub-`hashStruct`, which we don't
/// field-match. Returns `None` if the string is not in `Name(...)` shape.
fn parse_type_string(type_string: &str) -> Option<Vec<Field>> {
    let open = type_string.find('(')?;
    // Everything from the first `(` to its matching `)` (the primary member list).
    let after = &type_string[open + 1..];
    let close = after.find(')')?;
    let members = &after[..close];
    let members = members.trim();
    if members.is_empty() {
        return Some(Vec::new());
    }
    let mut fields = Vec::new();
    for part in members.split(',') {
        let part = part.trim();
        if part.is_empty() {
            // A stray trailing comma ⇒ malformed; bail rather than misalign.
            return None;
        }
        // `type name` — split on the LAST whitespace run so multi-word types
        // (there are none in canonical EIP-712, but be safe) keep the trailing
        // identifier as the name.
        let mut it = part.rsplitn(2, char::is_whitespace);
        let name = it.next()?.trim();
        let ty = it.next()?.trim();
        if name.is_empty() || ty.is_empty() {
            return None;
        }
        fields.push(Field { ty: ty.to_ascii_lowercase(), name: name.to_ascii_lowercase() });
    }
    Some(fields)
}

/// Find the `abi.encode(<var>, a1, a2, …)` call in the contract source and
/// return the ordered list of **value-field names** of `a1..` — the trailing
/// member of each argument (`order.collateral_asset` → `collateral_asset`, bare
/// `expiry` → `expiry`). Returns `None` when no such call is found.
///
/// We pick the encode whose **first** argument is the typehash variable, which
/// is the canonical `abi.encode(TYPEHASH, fields…)` hashStruct shape. The
/// returned vector excludes the typehash itself.
fn find_encoded_struct(contract_src: &str, var: &str) -> Option<Vec<String>> {
    // Scan every `abi.encode(` occurrence; take the first whose leading argument
    // is exactly `var`.
    let mut search_from = 0usize;
    while let Some(rel) = contract_src[search_from..].find("abi.encode") {
        let at = search_from + rel;
        // Advance past this match for the next iteration regardless of outcome.
        search_from = at + "abi.encode".len();

        // Reject `abi.encodepacked` / `abi.encodewithselector` / … — only the
        // plain `abi.encode(` builds a struct's `encodeData`.
        let tail = &contract_src[at + "abi.encode".len()..];
        let tail = tail.trim_start();
        if !tail.starts_with('(') {
            continue;
        }

        // Extract the balanced argument list inside the parentheses.
        let Some(args_src) = balanced_parens(tail) else { continue };
        let args = split_top_level_commas(&args_src);
        if args.is_empty() {
            continue;
        }
        // Leading arg must be the typehash variable (allowing a `this.`/`self`
        // qualifier is unnecessary for a constant; compare the trailing token).
        if trailing_member(args[0].trim()) != var {
            continue;
        }
        // The remaining args are the struct's encoded value fields.
        let fields: Vec<String> = args[1..].iter().map(|a| trailing_member(a.trim())).collect();
        return Some(fields);
    }
    None
}

/// Given a string that starts with `(`, return the contents up to the matching
/// `)` (handling nesting and skipping string literals so a `)` inside `"…"`
/// does not close early). Excludes the outer parentheses.
fn balanced_parens(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'(') {
        return None;
    }
    let mut depth = 0i32;
    let mut in_str: Option<u8> = None;
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        match in_str {
            Some(q) => {
                if b == q {
                    in_str = None;
                }
            }
            None => match b {
                b'"' | b'\'' => in_str = Some(b),
                b'(' => {
                    depth += 1;
                    if depth == 1 {
                        start = i + 1;
                    }
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(s[start..i].to_string());
                    }
                }
                _ => {}
            },
        }
    }
    None
}

/// Split a call's argument source on top-level commas (ignoring commas nested
/// inside `()`/`[]` and inside string literals).
fn split_top_level_commas(args: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_str: Option<u8> = None;
    let mut cur = String::new();
    for &b in args.as_bytes() {
        let ch = b as char;
        match in_str {
            Some(q) => {
                cur.push(ch);
                if b == q {
                    in_str = None;
                }
            }
            None => match b {
                b'"' | b'\'' => {
                    in_str = Some(b);
                    cur.push(ch);
                }
                b'(' | b'[' => {
                    depth += 1;
                    cur.push(ch);
                }
                b')' | b']' => {
                    depth -= 1;
                    cur.push(ch);
                }
                b',' if depth == 0 => {
                    out.push(std::mem::take(&mut cur));
                }
                _ => cur.push(ch),
            },
        }
    }
    let last = cur.trim();
    if !last.is_empty() || !out.is_empty() {
        out.push(cur);
    }
    out
}

/// The trailing member identifier of a (possibly dotted/indexed) expression:
/// `order.collateral_asset` → `collateral_asset`, `s.a.b` → `b`, bare `expiry`
/// → `expiry`. For anything that does not end in a plain identifier (a literal,
/// a call, an index) returns a sentinel that cannot equal a real field name, so
/// it never produces a spurious *match*.
fn trailing_member(expr: &str) -> String {
    let e = expr.trim();
    // Strip a trailing index `[...]` so `arr[i]` → the base's trailing member is
    // not mistaken for a name; such an arg simply won't match any field name.
    if e.ends_with(']') || e.ends_with(')') {
        return "\u{0}__nonident".to_string();
    }
    let last = e.rsplit('.').next().unwrap_or(e).trim();
    // Must be a clean identifier; otherwise it cannot correspond to a field name.
    if last.is_empty() || !last.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
        return "\u{0}__nonident".to_string();
    }
    last.to_ascii_lowercase()
}

// ------------------------------------------------------------------- compare

/// Compare the type-string fields against the encoded value-field names.
/// Returns `None` when they correspond (no finding), or `Some(reason)`
/// describing the first **provable** divergence.
///
/// Two divergence signals, both chosen to be unambiguous so the detector stays
/// near-zero-FP on faithful encodings (which routinely rename a field to a local
/// or pass a pre-hashed/computed value — e.g. a permit nonce passed as
/// `currentValidNonce`, or a domain `name` passed as `keccak256(bytes(name))`):
///
/// 1. **Count mismatch** — the type string lists N fields but M ≠ N value args
///    are `abi.encode`d. In EIP-712 every member (including dynamic `bytes` /
///    `string` / arrays, which are hashed to one word, and nested structs, which
///    become one sub-`hashStruct` word) contributes exactly one `abi.encode`
///    argument, so a faithful encoding always has N == M. A count mismatch is a
///    dropped/added field.
///
/// 2. **Provable reorder** — every encoded argument we can name is itself a
///    declared field name, the multiset of named args equals the field-name
///    multiset, **but the positional order differs.** This is a true field
///    transposition (the wrong-field-binding bug) and cannot be explained by a
///    rename: a renamed local would not appear in the field-name set at all.
///
/// A rename / pre-hash / computed value (an encoded arg whose name is not a
/// declared field, or that we cannot name at all) is treated as *ambiguous* and
/// never, on its own, produces a finding.
fn compare(fields: &[Field], encoded: &[String]) -> Option<String> {
    // (1) Count mismatch — unambiguous add/drop of a field.
    if fields.len() != encoded.len() {
        return Some(format!(
            "the type string lists {} field(s) but {} value(s) are abi.encode-d (a field was \
             added or dropped on one side)",
            fields.len(),
            encoded.len()
        ));
    }

    // (2) Provable reorder. Only consider it if EVERY encoded arg is nameable and
    //     names a declared field (so renames/pre-hashes don't masquerade as a
    //     swap), the multisets match, and the order differs at some position.
    let field_names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
    let all_named_are_fields = encoded
        .iter()
        .all(|e| !e.starts_with('\u{0}') && field_names.contains(&e.as_str()));
    if all_named_are_fields {
        let mut fs = field_names.clone();
        let mut es: Vec<&str> = encoded.iter().map(String::as_str).collect();
        fs.sort_unstable();
        es.sort_unstable();
        if fs == es {
            // Same set of names; report the first position whose name differs.
            for (i, (f, enc)) in fields.iter().zip(encoded.iter()).enumerate() {
                if &f.name != enc {
                    return Some(format!(
                        "field #{pos} is declared `{decl_ty} {decl_name}` but the value `{decl_name}` \
                         is encoded at a different position — fields `{decl_name}` and `{enc}` are \
                         transposed relative to the type string (wrong-field binding)",
                        pos = i + 1,
                        decl_ty = f.ty,
                        decl_name = f.name,
                        enc = enc,
                    ));
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fired(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "eip712-typehash-mismatch")
    }

    // ---- unit tests for the text parsers (the load-bearing logic) ----

    #[test]
    fn parses_keccak_string_literal() {
        let decl = r#"bytes32 private constant order_type = keccak256(
            "order(uint8 order_type,uint256 expiry,address benefactor)"
        );"#;
        let s = extract_keccak_string_literal(decl).unwrap();
        assert_eq!(s, "order(uint8 order_type,uint256 expiry,address benefactor)");
    }

    #[test]
    fn rejects_keccak_of_expression() {
        // A domain separator derived from another constant, not a type string.
        let decl = "bytes32 private constant eip712_domain_typehash = keccak256(abi.encodepacked(eip712_domain));";
        assert!(extract_keccak_string_literal(decl).is_none());
    }

    #[test]
    fn parses_type_string_fields() {
        let f = parse_type_string("order(uint8 order_type,uint256 expiry,address benefactor)").unwrap();
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].ty, "uint8");
        assert_eq!(f[0].name, "order_type");
        assert_eq!(f[2].name, "benefactor");
    }

    #[test]
    fn encoded_struct_args_trailing_member() {
        let src = "return abi.encode(order_type, order.order_type, order.expiry, order.benefactor);";
        let enc = find_encoded_struct(src, "order_type").unwrap();
        assert_eq!(enc, vec!["order_type", "expiry", "benefactor"]);
    }

    #[test]
    fn ignores_encode_packed_and_wrong_leading_arg() {
        // encodePacked is not a hashStruct encode.
        assert!(find_encoded_struct("abi.encodepacked(order_type, order.expiry)", "order_type").is_none());
        // Leading arg is not the typehash.
        assert!(find_encoded_struct("abi.encode(something_else, order.expiry)", "order_type").is_none());
    }

    // ---- end-to-end detector tests ----

    // VULN: the type string lists fields in order [to, value] but the struct is
    // encoded in order [value, to] — amount and recipient are TRANSPOSED, so a
    // signature for "pay `to` `value`" validates as "pay `value-as-address`
    // `to-as-amount`". Classic wrong-field binding.
    const VULN_SWAP: &str = r#"
        pragma solidity ^0.8.20;
        contract Pay {
            bytes32 private constant TRANSFER_TYPEHASH =
                keccak256("Transfer(address to,uint256 value,uint256 nonce)");
            function hashTransfer(address to, uint256 value, uint256 nonce)
                public pure returns (bytes memory)
            {
                // BUG: `value` and `to` are encoded in the wrong order vs the type string.
                return abi.encode(TRANSFER_TYPEHASH, value, to, nonce);
            }
        }
    "#;

    // VULN: the type string declares 3 fields but only 2 are encoded (a field
    // was dropped from the encode) — count mismatch.
    const VULN_DROP: &str = r#"
        pragma solidity ^0.8.20;
        contract Permit {
            bytes32 private constant PERMIT_TYPEHASH =
                keccak256("Permit(address owner,address spender,uint256 value)");
            function encodePermit(address owner, address spender)
                public pure returns (bytes memory)
            {
                return abi.encode(PERMIT_TYPEHASH, owner, spender);
            }
        }
    "#;

    // SAFE: faithful Ethena-shaped Order — 8 fields, encoded in the same order.
    const SAFE_ETHENA: &str = r#"
        pragma solidity ^0.8.20;
        contract Minting {
            bytes32 private constant ORDER_TYPE = keccak256(
                "Order(uint8 order_type,uint256 expiry,uint256 nonce,address benefactor,address beneficiary,address collateral_asset,uint256 collateral_amount,uint256 usde_amount)"
            );
            struct Order {
                uint8 order_type; uint256 expiry; uint256 nonce; address benefactor;
                address beneficiary; address collateral_asset; uint256 collateral_amount; uint256 usde_amount;
            }
            function encodeOrder(Order calldata order) public pure returns (bytes memory) {
                return abi.encode(
                    ORDER_TYPE,
                    order.order_type, order.expiry, order.nonce, order.benefactor,
                    order.beneficiary, order.collateral_asset, order.collateral_amount, order.usde_amount
                );
            }
        }
    "#;

    // SAFE: faithful Permit (the OZ ERC20Permit shape) — 5 fields, in order.
    const SAFE_PERMIT: &str = r#"
        pragma solidity ^0.8.20;
        contract Token {
            bytes32 private constant PERMIT_TYPEHASH =
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
            function encode(address owner, address spender, uint256 value, uint256 nonce, uint256 deadline)
                public pure returns (bytes memory)
            {
                return abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonce, deadline);
            }
        }
    "#;

    // SAFE: a typehash that is declared but never abi.encode-d in this contract
    // (no pairing) — we must not guess a mismatch.
    const SAFE_UNUSED: &str = r#"
        pragma solidity ^0.8.20;
        contract Decl {
            bytes32 private constant ROUTE_TYPE = keccak256("Route(address[] addresses,uint256[] ratios)");
            function noop() external {}
        }
    "#;

    // SAFE (the EigenLayer `DelegationApproval` shape): faithful, but two fields
    // are passed as RENAMED locals — type field `delegationApprover` is encoded as
    // `approver`, and `salt` as `approverSalt`. Counts match (5==5) and the
    // renamed args are not in the field-name set, so this is an ambiguous rename,
    // not a proven mismatch — must stay silent. (Naive name-matching would FP.)
    const SAFE_RENAMED_LOCALS: &str = r#"
        pragma solidity ^0.8.20;
        contract Delegation {
            bytes32 public constant DELEGATION_APPROVAL_TYPEHASH = keccak256(
                "DelegationApproval(address delegationApprover,address staker,address operator,bytes32 salt,uint256 expiry)"
            );
            function digest(address staker, address operator, address approver, bytes32 approverSalt, uint256 expiry)
                public pure returns (bytes memory)
            {
                return abi.encode(DELEGATION_APPROVAL_TYPEHASH, approver, staker, operator, approverSalt, expiry);
            }
        }
    "#;

    // SAFE (the EIP712Domain separator shape, the exact Ethena/TestnetERC20 FP):
    // the domain `name`/`version` are encoded as PRE-HASHED constants /
    // `keccak256(bytes(name))`, not as `name`/`version` members. Count matches
    // (4==4) and the args are unnameable / not field names — ambiguous, silent.
    const SAFE_DOMAIN_SEPARATOR: &str = r#"
        pragma solidity ^0.8.20;
        contract Dom {
            bytes32 private constant EIP712_DOMAIN =
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
            bytes32 private constant EIP_712_NAME = keccak256("MyApp");
            bytes32 private constant EIP712_REVISION = keccak256("1");
            function sep() internal view returns (bytes32) {
                return keccak256(abi.encode(EIP712_DOMAIN, EIP_712_NAME, EIP712_REVISION, block.chainid, address(this)));
            }
        }
    "#;

    // SAFE (nested struct): the primary type `Mail` has 3 members; the encode
    // passes a sub-hashStruct for each struct member and `keccak256(bytes(...))`
    // for the dynamic one — 3 args, 3 fields, none nameable to a swap. Silent.
    const SAFE_NESTED: &str = r#"
        pragma solidity ^0.8.20;
        contract Mailer {
            bytes32 private constant MAIL_TYPEHASH =
                keccak256("Mail(Person from,Person to,string contents)Person(string name,address wallet)");
            function hashMail(bytes32 fromHash, bytes32 toHash, bytes memory contents)
                public pure returns (bytes memory)
            {
                return abi.encode(MAIL_TYPEHASH, fromHash, toHash, keccak256(contents));
            }
        }
    "#;

    #[test]
    fn fires_on_field_swap() {
        assert!(fired(VULN_SWAP), "{:#?}", run(VULN_SWAP));
    }

    #[test]
    fn fires_on_dropped_field() {
        assert!(fired(VULN_DROP), "{:#?}", run(VULN_DROP));
    }

    #[test]
    fn silent_on_faithful_ethena_order() {
        assert!(!fired(SAFE_ETHENA), "{:#?}", run(SAFE_ETHENA));
    }

    #[test]
    fn silent_on_faithful_permit() {
        assert!(!fired(SAFE_PERMIT));
    }

    #[test]
    fn silent_when_typehash_unused() {
        assert!(!fired(SAFE_UNUSED));
    }

    #[test]
    fn silent_on_faithful_renamed_locals() {
        // The key precision guarantee: a faithful encoding that renames fields to
        // locals must NOT fire (EigenLayer DelegationApproval class).
        assert!(!fired(SAFE_RENAMED_LOCALS), "{:#?}", run(SAFE_RENAMED_LOCALS));
    }

    #[test]
    fn silent_on_domain_separator_prehash() {
        assert!(!fired(SAFE_DOMAIN_SEPARATOR), "{:#?}", run(SAFE_DOMAIN_SEPARATOR));
    }

    #[test]
    fn silent_on_nested_struct() {
        assert!(!fired(SAFE_NESTED), "{:#?}", run(SAFE_NESTED));
    }
}
