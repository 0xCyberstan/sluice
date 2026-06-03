//! Batch verification that *skips* an invalid element instead of reverting the
//! whole batch — so an unauthorized signature / merkle-proof / authorization is
//! silently dropped (or recorded as `success[i] = false`) while the loop keeps
//! processing, marking, counting, or paying out the remaining elements.
//!
//! ## The bug class
//!
//! A function that verifies a **batch** of signatures / merkle proofs /
//! authorizations should fail **atomically**: if any element is invalid the whole
//! call reverts. The vulnerable shape instead verifies each element inside a loop
//! and, on a verification failure, executes a `continue` (or sets a per-element
//! `success[i] = false` flag) rather than a `revert` / `require`. The loop then
//! goes on to apply a state effect — a `target.call(...)`, a balance/counter
//! update, a `usedHashes[h] = true` mark — for the *other* elements, while the
//! caller's batch is treated as "partially succeeded".
//!
//! Why that is dangerous:
//!   * **Silent authorization drop.** A batch the caller believes was atomic is
//!     applied partially; an element whose signature/proof failed is quietly
//!     ignored instead of aborting the transaction, masking a forged or stale
//!     element and breaking the "all-or-nothing" guarantee callers rely on.
//!   * **Counting / quorum corruption.** When the loop *counts* (e.g. tallies a
//!     signed-stake weight or a vote) and merely skips the bad element, an
//!     off-by-one or a duplicate can be smuggled past a threshold check.
//!
//! This is the canonical LayerZero `DVN.execute` shape (`verifySignatures(...)`
//! inside the loop, `if (!sigsValid) { emit ...; continue; }`, then
//! `target.call(callData)` for the surviving elements) — a deliberately
//! non-atomic batch executor.
//!
//! ## Detection
//!
//! Fire on a **state-mutating** function whose body contains a loop where the
//! loop body:
//!   1. performs a **verification** — `ecrecover`, or a call whose resolved name
//!      is a signature/proof verifier (`isValidSignature`, `recover`, `verify`,
//!      `verifyProof`, `verifyInclusion[Keccak]`, `merkleVerify`,
//!      `verifySignature(s)`, `checkSignature`, `processProof`, …); **and**
//!   2. on the verification's failure path executes a `continue` (or writes a
//!      per-element boolean result flag) rather than reverting the batch; **and**
//!   3. still performs a **state effect** in the loop body regardless — a storage
//!      write, an external/low-level call, or a transfer.
//!
//! ## False-positive suppression (precision first)
//!
//!   * **The verify failure reverts the batch.** If the loop body reverts on a
//!     failed element — `if (!verify(...)) revert ...;` / `require(verify(...))`
//!     — the batch *is* atomic and there is no bug. This is the Pendle
//!     `MerkleDistributor.claim` / EigenLayer cert-verifier shape and is
//!     explicitly suppressed: a loop that contains a `revert`/`require` and no
//!     `continue`/flag-write never fires.
//!   * **No state effect.** A loop that only reads (e.g. a view tally that the
//!     caller checks afterwards) cannot silently *process* an unauthorized
//!     element, so it is not reported.
//!   * **No verification at all.** A `continue` used to filter on a plain
//!     membership/range predicate (`if (!isPeer(...)) continue;`,
//!     `if (block.number <= until) continue;`) is ordinary iteration, not a
//!     skipped authorization, and is not matched — a genuine verify call must be
//!     present in the same loop.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};

use super::prelude::*;
use sluice_ir::{AssignOp, Builtin, CallKind, Expr, ExprKind, Span, Stmt, StmtKind};

pub struct BatchVerifySkipDetector;

impl Detector for BatchVerifySkipDetector {
    fn id(&self) -> &'static str {
        "batch-verify-skip"
    }
    fn category(&self) -> Category {
        Category::BatchVerifySkip
    }
    fn description(&self) -> &'static str {
        "Batch signature/proof verification skips an invalid element (continue / success[i]=false) instead of reverting"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // A batch *verifier* is an externally reachable, state-mutating entry
            // point. A pure/view tally cannot silently *process* an element, and a
            // never-called internal helper is reported via its caller.
            if !f.is_externally_reachable() || !f.is_state_mutating() {
                continue;
            }

            // Inspect each loop body independently — the bug is local to one loop.
            let mut hit: Option<Span> = None;
            for s in &f.body {
                visit_loop_bodies(s, &mut |body| {
                    if hit.is_some() {
                        return;
                    }
                    if let Some(span) = qualifying_loop(body) {
                        hit = Some(span);
                    }
                });
                if hit.is_some() {
                    break;
                }
            }
            let Some(span) = hit else { continue };

            // Confidence: this is a structural pattern (loop + verify + skip +
            // effect). The strongest corroboration is an explicit per-element
            // result flag write (`success[i] = false`) alongside the continue,
            // which makes the "partial success" intent unambiguous; otherwise the
            // plain continue-past-verify shape sits a notch lower.
            let conf = 0.62;

            let b = report!(self, Category::BatchVerifySkip,
                title = "Batch verification skips invalid elements instead of reverting",
                severity = Severity::High,
                confidence = conf,
                dimensions = [Dimension::Invariant, Dimension::Frontier],
                message = format!(
                    "`{}` verifies a batch of signatures/proofs inside a loop but, when an element \
                     fails verification, executes a `continue` (or records a per-element failure flag) \
                     instead of reverting the whole batch — and still applies a state effect \
                     (storage write / external call / transfer) for the surviving elements. The batch \
                     is therefore NOT atomic: an unauthorized element is silently dropped while the \
                     rest are processed, breaking the all-or-nothing guarantee callers rely on and \
                     letting a forged/stale element slip past (CWE-347).",
                    f.name
                ),
                recommendation =
                    "Make batch verification atomic: on a failed signature/proof `revert` (or \
                     `require(verify(...))`) so the entire batch aborts. If partial application is \
                     genuinely intended, return the per-element results to the caller and have a \
                     trusted caller re-check them — do not silently `continue` past a failed auth.",
            );
            out.push(finish_at(cx, b, f.id, span));
        }
        out
    }
}

// --------------------------------------------------------------------- helpers

/// Resolved-name set for signature / merkle-proof / authorization verifiers. A
/// call whose `func_name` is one of these (case-insensitively) is treated as the
/// per-element verification gate. `ecrecover` is matched separately via its
/// [`Builtin`] classification.
fn is_verify_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // Substring matches so `verifyInclusionKeccak`, `isValidSignatureNow`,
    // `_verifyMerkleData`, `checkSignatures` all hit a stem below.
    [
        "isvalidsignature",
        "verifysignature", // covers verifySignature / verifySignatures
        "checksignature",  // covers checkSignature / checkSignatures
        "verifyproof",
        "verifyinclusion",
        "merkleverify",
        "verifymerkle",
        "processproof",
        "verifycertificate",
        "verifyorder",
    ]
    .iter()
    .any(|k| l.contains(k))
        // Bare `recover` / `verify` are matched as *whole* names only — too generic
        // as substrings (`recoverERC20`, `verifyAndUpdate…`) and would over-fire.
        || l == "recover"
        || l == "verify"
}

/// Is `c` a per-element verification call (`ecrecover(...)`, `*.verifyProof(...)`,
/// `sig.recover(...)`, an internal `_verifyMerkleData(...)`, …)?
fn is_verify_call(c: &sluice_ir::Call) -> bool {
    if matches!(c.kind, CallKind::Builtin(Builtin::Ecrecover)) {
        return true;
    }
    c.func_name.as_deref().is_some_and(is_verify_name)
}

/// Does `e` (transitively) contain a verification call?
fn expr_has_verify(e: &Expr) -> bool {
    let mut found = false;
    e.visit(&mut |sub| {
        if let ExprKind::Call(c) = &sub.kind {
            if is_verify_call(c) {
                found = true;
            }
        }
    });
    found
}

/// Does the statement list (one loop body) contain a verification call anywhere?
fn body_has_verify(body: &[Stmt]) -> bool {
    body.iter().any(|s| {
        let mut found = false;
        s.visit_exprs(&mut |e| {
            if !found && expr_has_verify(e) {
                found = true;
            }
        });
        found
    })
}

/// Does the loop body contain a `continue;` at its own level (not inside a
/// further nested loop, whose `continue` belongs to that inner loop)?
fn body_has_continue(body: &[Stmt]) -> bool {
    body.iter().any(stmt_has_continue_same_level)
}

/// Walk `s` looking for a `Continue` that targets the *current* loop: descend
/// through `if`/`block`/`try` but STOP at a nested `for`/`while`/`do-while`
/// (its `continue`/`break` bind to that inner loop, not ours).
fn stmt_has_continue_same_level(s: &Stmt) -> bool {
    match &s.kind {
        StmtKind::Continue => true,
        StmtKind::If { then_branch, else_branch, .. } => {
            then_branch.iter().any(stmt_has_continue_same_level)
                || else_branch.iter().any(stmt_has_continue_same_level)
        }
        StmtKind::Block { stmts, .. } => stmts.iter().any(stmt_has_continue_same_level),
        StmtKind::Try { body, catches, .. } => {
            body.iter().any(stmt_has_continue_same_level)
                || catches
                    .iter()
                    .any(|c| c.body.iter().any(stmt_has_continue_same_level))
        }
        // Nested loops own their own continue/break — do not cross into them.
        _ => false,
    }
}

/// Does the loop body assign to an indexed lvalue with a boolean-looking result
/// (`success[i] = ...`, `valid[i] = false`, `results[idx] = ok`)? This is the
/// "record per-element failure instead of reverting" variant of the skip.
fn body_writes_result_flag(body: &[Stmt]) -> bool {
    body.iter().any(|s| {
        let mut found = false;
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            if let ExprKind::Assign { op: AssignOp::Assign, target, .. } = &e.kind {
                if let ExprKind::Index { base, index: Some(_) } = &target.kind {
                    if base.simple_name().is_some_and(is_result_flag_name) {
                        found = true;
                    }
                }
            }
        });
        found
    })
}

/// Names that read as a per-element success/validity result array.
fn is_result_flag_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    ["success", "valid", "verified", "results", "ok", "passed", "failed"]
        .iter()
        .any(|k| l == *k || l.contains(k))
}

/// Does the loop body perform a STATE EFFECT — a storage/lvalue write or an
/// external/low-level/transfer call — that runs for surviving elements? A loop
/// that only reads cannot silently *process* an unauthorized element.
fn body_has_state_effect(body: &[Stmt]) -> bool {
    body.iter().any(|s| {
        let mut found = false;
        s.visit_exprs(&mut |e| {
            if found {
                return;
            }
            match &e.kind {
                // An assignment / compound-assign to some lvalue.
                ExprKind::Assign { .. } => found = true,
                ExprKind::Call(c) => {
                    if matches!(
                        c.kind,
                        CallKind::External
                            | CallKind::LowLevelCall
                            | CallKind::DelegateCall
                            | CallKind::Send
                            | CallKind::Transfer
                    ) {
                        found = true;
                    }
                }
                _ => {}
            }
        });
        found
    })
}

/// True if the loop body contains a `revert`/`require` reachable as the failure
/// handling for a verification (the SAFE atomic-batch shape). We approximate this
/// structurally: any `revert` statement, or a `require(...)` whose argument
/// mentions a verify call, inside the loop body counts as "this loop aborts on a
/// bad element".
fn body_aborts_on_failure(body: &[Stmt]) -> bool {
    // (a) An explicit `revert ...;` statement anywhere in the loop body.
    let mut has_revert = false;
    // (b) A `require(<expr-with-verify>)` / `assert(<expr-with-verify>)`.
    let mut has_require_verify = false;
    for s in body {
        s.visit(&mut |inner| {
            if matches!(inner.kind, StmtKind::Revert { .. }) {
                has_revert = true;
            }
        });
        s.visit_exprs(&mut |e| {
            if let ExprKind::Call(c) = &e.kind {
                if is_require_or_assert(c) && c.args.iter().any(expr_has_verify) {
                    has_require_verify = true;
                }
            }
        });
    }
    has_revert || has_require_verify
}

/// If this loop body is a qualifying batch-verify-skip, return a span to anchor
/// the finding at (the verify call site, falling back to the first statement).
///
/// Requires, in the SAME loop body: a verify call, a skip (continue OR a
/// per-element result-flag write), a state effect — and crucially NO atomic
/// abort (`revert`/`require(verify)`) that would make the batch all-or-nothing.
fn qualifying_loop(body: &[Stmt]) -> Option<Span> {
    if !body_has_verify(body) {
        return None;
    }
    // The skip: a continue at this loop's level, or a per-element flag write.
    let skips = body_has_continue(body) || body_writes_result_flag(body);
    if !skips {
        return None;
    }
    // Atomic-abort batches (Pendle/EigenLayer `if (!verify) revert`) are SAFE.
    if body_aborts_on_failure(body) {
        return None;
    }
    // A state effect must run for the surviving elements.
    if !body_has_state_effect(body) {
        return None;
    }
    Some(first_verify_span(body).unwrap_or_else(|| first_stmt_span(body)))
}

/// Span of the first verification call in the loop body.
fn first_verify_span(body: &[Stmt]) -> Option<Span> {
    let mut span: Option<Span> = None;
    for s in body {
        s.visit_exprs(&mut |e| {
            if span.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if is_verify_call(c) {
                    span = Some(e.span);
                }
            }
        });
        if span.is_some() {
            break;
        }
    }
    span
}

fn first_stmt_span(body: &[Stmt]) -> Span {
    body.first().map(|s| s.span).unwrap_or_else(Span::dummy)
}

/// Invoke `f` with the body of every loop (`for`/`while`/`do-while`) reachable
/// from `s`, including loops nested inside other statements. (Mirrors the
/// `array_length_mismatch` helper; kept local so the detector is self-contained.)
fn visit_loop_bodies<'a>(s: &'a Stmt, f: &mut impl FnMut(&'a [Stmt])) {
    s.visit(&mut |inner| match &inner.kind {
        StmtKind::For { body, .. }
        | StmtKind::While { body, .. }
        | StmtKind::DoWhile { body, .. } => f(body),
        _ => {}
    });
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn findings(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn fires(src: &str) -> bool {
        findings(src).iter().any(|f| f.detector == "batch-verify-skip")
    }

    // ---- VULN: the LayerZero DVN.execute shape. A batch of authorizations is
    // verified inside the loop; on a failed signature the loop `continue`s
    // (emits + skips) instead of reverting, and still performs a state effect
    // (target.call + usedHashes[hash] = true) for the surviving elements. ----
    const VULN_DVN: &str = r#"
pragma solidity ^0.8.20;
contract DVN {
    mapping(bytes32 => bool) public usedHashes;
    uint64 vid;
    function verifySignatures(bytes32 h, bytes calldata sigs) public view returns (bool, uint8) {}
    function hashCallData(uint64 v, address t, bytes calldata cd, uint256 e) public pure returns (bytes32) {}
    struct ExecuteParam { uint64 vid; address target; bytes callData; uint256 expiration; bytes signatures; }
    function execute(ExecuteParam[] calldata _params) external {
        for (uint256 i = 0; i < _params.length; ++i) {
            ExecuteParam calldata param = _params[i];
            if (param.vid != vid) { continue; }
            bytes32 hash = hashCallData(param.vid, param.target, param.callData, param.expiration);
            (bool sigsValid, ) = verifySignatures(hash, param.signatures);
            if (!sigsValid) {
                continue;                       // <-- skip bad-sig element, do NOT revert the batch
            }
            usedHashes[hash] = true;            // state effect for surviving elements
            (bool ok, ) = param.target.call(param.callData);
        }
    }
}
"#;

    // ---- VULN variant: records `success[i] = false` instead of reverting, then
    // still pays out / marks the others. ----
    const VULN_FLAG: &str = r#"
pragma solidity ^0.8.20;
interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }
contract BatchPay {
    IERC20 token;
    mapping(address => uint256) public paid;
    function batchPay(address[] calldata to, uint256[] calldata amt, bytes[] calldata sigs)
        external returns (bool[] memory success)
    {
        success = new bool[](to.length);
        bytes32 root = keccak256("x");
        for (uint256 i = 0; i < to.length; i++) {
            bool ok = MerkleProof.verify(abi.decode(sigs[i], (bytes32[])), root, keccak256(abi.encode(to[i], amt[i])));
            if (!ok) {
                success[i] = false;             // <-- record failure, do NOT revert
            }
            paid[to[i]] += amt[i];              // state effect runs regardless of `ok`
            token.transfer(to[i], amt[i]);
        }
    }
}
library MerkleProof { function verify(bytes32[] memory, bytes32, bytes32) internal pure returns (bool) {} }
"#;

    // ---- SAFE 1: atomic batch — the Pendle MerkleDistributor.claim shape. The
    // loop verifies each proof and `revert`s the WHOLE batch on a bad element, so
    // there is no silent skip. (`if (!verify) revert`.) ----
    const SAFE_ATOMIC: &str = r#"
pragma solidity ^0.8.20;
contract Distributor {
    bytes32 public merkleRoot;
    mapping(address => uint256) public claimed;
    error InvalidMerkleProof();
    function claim(address[] memory tokens, uint256[] memory amts, bytes32[][] memory proofs) external {
        for (uint256 i = 0; i < tokens.length; ++i) {
            bytes32 leaf = keccak256(abi.encodePacked(tokens[i], msg.sender, amts[i]));
            if (!MerkleProof.verify(proofs[i], merkleRoot, leaf)) revert InvalidMerkleProof();
            claimed[tokens[i]] = amts[i];
        }
    }
}
library MerkleProof { function verify(bytes32[] memory, bytes32, bytes32) internal pure returns (bool) {} }
"#;

    // ---- SAFE 2: atomic batch via `require(verify(...))` — EigenLayer
    // cert-verifier shape. require aborts the batch on a bad proof. ----
    const SAFE_REQUIRE: &str = r#"
pragma solidity ^0.8.20;
contract CertVerifier {
    mapping(uint256 => bool) public seen;
    error VerificationFailed();
    function verifyBatch(bytes[] calldata proofs, bytes32 root, bytes32[] calldata leaves) external {
        for (uint256 i = 0; i < proofs.length; i++) {
            bool verified = Merkle.verifyInclusionKeccak(root, i, proofs[i], leaves[i]);
            require(verified, VerificationFailed());
            seen[i] = true;
        }
    }
}
library Merkle { function verifyInclusionKeccak(bytes32, uint256, bytes calldata, bytes32) internal pure returns (bool) {} }
"#;

    // ---- SAFE 3: a `continue` filtering on a PLAIN predicate (membership /
    // range) with NO verification call — ordinary iteration, not a skipped auth.
    // (EtherFi withdrawal-filter / LayerZero PreCrime isPeer shape.) ----
    const SAFE_PLAIN_CONTINUE: &str = r#"
pragma solidity ^0.8.20;
contract Filter {
    mapping(address => bool) public isPeer;
    mapping(address => uint256) public credited;
    function process(address[] calldata users, uint256[] calldata amts) external {
        for (uint256 i = 0; i < users.length; i++) {
            if (!isPeer[users[i]]) continue;        // membership filter, not a verify gate
            if (amts[i] == 0) continue;             // range filter
            credited[users[i]] += amts[i];
        }
    }
}
"#;

    // ---- SAFE 4: a batch verify with a continue but NO state effect — a pure
    // tally the caller checks afterwards cannot silently *process* an element. ----
    const SAFE_NO_EFFECT: &str = r#"
pragma solidity ^0.8.20;
contract Counter {
    function countValid(bytes32 h, bytes[] calldata sigs) external returns (uint256 n) {
        for (uint256 i = 0; i < sigs.length; i++) {
            address signer = ecrecover(h, 27, bytes32(0), bytes32(0));
            if (signer == address(0)) continue;     // skip, but only a local counter changes
            n++;
        }
    }
}
"#;

    #[test]
    fn fires_on_dvn_continue_skip() {
        assert!(fires(VULN_DVN), "DVN.execute-style continue-past-verify must fire");
    }

    #[test]
    fn fires_on_success_flag_skip() {
        assert!(fires(VULN_FLAG), "success[i]=false skip with state effect must fire");
    }

    #[test]
    fn silent_on_atomic_revert_batch() {
        assert!(!fires(SAFE_ATOMIC), "if(!verify) revert is an atomic batch — must not fire");
    }

    #[test]
    fn silent_on_require_verify_batch() {
        assert!(!fires(SAFE_REQUIRE), "require(verify(...)) is an atomic batch — must not fire");
    }

    #[test]
    fn silent_on_plain_predicate_continue() {
        assert!(!fires(SAFE_PLAIN_CONTINUE), "continue on a non-verify predicate must not fire");
    }

    #[test]
    fn silent_on_pure_tally_no_state_effect() {
        assert!(!fires(SAFE_NO_EFFECT), "a continue-tally with no state effect must not fire");
    }
}
