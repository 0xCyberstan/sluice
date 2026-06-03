//! Integer hazards that survive Solidity >=0.8 checked arithmetic:
//! attacker-influenced `unchecked { }` math, silent narrowing downcasts
//! (`uintN(x)` with `N < 256`), and division by a non-constant, un-guarded
//! divisor (div-by-zero).
//!
//! Solidity >=0.8 inserts overflow/underflow checks on plain `+`/`-`/`*`, so a
//! bare arithmetic expression is *not* a finding on a modern pragma. What the
//! compiler does **not** protect: arithmetic the author explicitly opted out of
//! with `unchecked { }`, truncating casts (which never revert), and division by
//! a value that can be zero. This detector targets exactly those residual
//! hazards and suppresses the compiler-checked cases.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::detectors::visit_calls;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::{BinOp, CallKind, Expr, ExprKind};

pub struct IntegerIssuesDetector;

impl Detector for IntegerIssuesDetector {
    fn id(&self) -> &'static str {
        "integer-issues"
    }
    fn category(&self) -> Category {
        Category::IntegerOverflow
    }
    fn description(&self) -> &'static str {
        "Unchecked-block math on attacker input, narrowing downcasts, and unguarded division"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.functions() {
            if !f.has_body {
                continue;
            }

            // SafeCast-style libraries make truncation revert; if the source
            // leans on them we suppress the downcast/division noise for this
            // function entirely (precision over recall).
            let src_lc = cx.source_text(f.span);
            let uses_safecast = src_lc.contains("safecast")
                || src_lc.contains("touint")
                || src_lc.contains("toint")
                || src_lc.contains("safecast");

            // Does this function ingest attacker input? Externally reachable with
            // at least one parameter is the cheap structural proxy.
            let takes_attacker_input = f.is_externally_reachable() && !f.params.is_empty();

            // ---- (1) unchecked { } arithmetic on attacker-controlled input ----
            // On >=0.8, `has_unchecked_math` is set *only* for arithmetic inside
            // an `unchecked { }` block — plain checked +/-/* never set it — so we
            // are not flagging compiler-protected math.
            if f.effects.has_unchecked_math && takes_attacker_input {
                let b = FindingBuilder::new(self.id(), Category::UncheckedMath)
                    .title("Unchecked arithmetic on attacker-controlled input")
                    .severity(Severity::Medium)
                    .confidence(0.5)
                    .dimension(Dimension::ValueFlow)
                    .message(format!(
                        "`{}` performs arithmetic inside an `unchecked {{ }}` block and is externally \
                         callable with caller-supplied parameters. The compiler's >=0.8 overflow/underflow \
                         checks are disabled there, so a crafted input can wrap a sum/difference/product \
                         and corrupt the downstream accounting.",
                        f.name
                    ))
                    .recommendation(
                        "Remove the `unchecked` block (let the compiler check), or prove the operands are \
                         bounded so wrap-around is impossible before opting out.",
                    );
                out.push(cx.finish(b, f.id, f.span));
            }

            // ---- (2) narrowing downcast of an attacker-controlled / large value ----
            if !uses_safecast {
                visit_calls(f, |c, span| {
                    if c.kind != CallKind::TypeCast {
                        return;
                    }
                    // The cast target type: either `uintN(x)` (callee is a
                    // `TypeName`) or a named cast whose `func_name` is `uintN`.
                    let ty = cast_target_type(c);
                    let Some(ty) = ty else { return };
                    let Some(bits) = narrowing_int_bits(&ty) else {
                        return;
                    };

                    // Single-argument cast only; the argument is the value cast.
                    let Some(arg) = c.args.first() else { return };

                    // Suppress provably-bounded values (constant literals can't
                    // overflow the target unless written that way on purpose).
                    if is_constant_expr(arg) {
                        return;
                    }
                    // Only flag when the value is attacker-controlled (and thus
                    // can be made to exceed the narrowed range to drop high bits).
                    if !cx.is_attacker_controlled(f.id, arg) {
                        return;
                    }

                    let b = FindingBuilder::new(self.id(), Category::IntegerOverflow)
                        .title(format!("Narrowing downcast to `{ty}` silently truncates high bits"))
                        .severity(Severity::Medium)
                        .confidence(0.5)
                        .dimension(Dimension::ValueFlow)
                        .message(format!(
                            "`{}` casts an attacker-controlled value to `{ty}` ({bits}-bit). Solidity casts \
                             never revert: a value larger than `type({ty}).max` is silently truncated to its \
                             low {bits} bits, so an attacker can choose an input whose wrapped value differs \
                             arbitrarily from the intended one (accounting / id / timestamp confusion).",
                            f.name
                        ))
                        .recommendation(
                            "Use OpenZeppelin `SafeCast.toUintN` (reverts on truncation) or `require` the value \
                             is `<= type(uintN).max` before narrowing.",
                        );
                    out.push(cx.finish(b, f.id, span));
                });
            }

            // ---- (3) division by a non-constant divisor with no zero-check ----
            // Only meaningful on >=0.8 (where this is the residual arithmetic
            // hazard the compiler does not catch).
            if cx.scir.solidity_ge_0_8() && !uses_safecast {
                // Collect divisor names guarded by a `require(x != 0)` / `> 0`
                // style check anywhere in the function, to suppress those.
                let guarded = zero_checked_names(cx, f);
                for s in &f.body {
                    s.visit_exprs(&mut |e| {
                        let ExprKind::Binary { op: BinOp::Div, rhs, .. } = &e.kind else {
                            return;
                        };
                        // Suppress division by a compile-time constant (cannot be
                        // zero unless literally `/ 0`, which the compiler rejects).
                        if is_constant_expr(rhs) {
                            return;
                        }
                        // Suppress if the divisor was zero-checked in this function.
                        if let Some(name) = rhs.simple_name() {
                            if guarded.iter().any(|g| g == name) {
                                return;
                            }
                        }
                        // Only flag when the divisor is actually controllable by an
                        // attacker (or externally influenced). Dividing by a trusted
                        // storage total (e.g. `x / totalSupply`) is not a finding —
                        // flagging every division was a large false-positive source.
                        let prov = cx.provenance_of(f.id, rhs);
                        if !prov.is_attacker_controlled() {
                            return;
                        }
                        let divisor = rhs.simple_name().unwrap_or("<expr>").to_string();
                        let b = FindingBuilder::new(self.id(), Category::IntegerOverflow)
                            .title("Division by a non-constant divisor with no zero-check")
                            .severity(Severity::Medium)
                            .confidence(0.5)
                            .dimension(Dimension::ValueFlow)
                            .message(format!(
                                "`{}` divides by `{}`, which is not a constant and is not guarded by a \
                                 `require(... != 0)`. A zero divisor reverts (a DoS griefing vector) and a \
                                 caller-influenced denominator can force it; division also truncates toward \
                                 zero, so a small/attacker-set divisor distorts the result.",
                                f.name, divisor
                            ))
                            .recommendation(
                                "`require(divisor != 0)` (or `> 0`) before dividing, and review the rounding \
                                 direction of the truncating division.",
                            );
                        out.push(cx.finish(b, f.id, e.span));
                    });
                }
            }
        }

        out
    }
}

// ----------------------------------------------------------------- helpers

/// The textual target type of a `TypeCast` call: `uint128(x)` lowers the callee
/// to `ExprKind::TypeName("uint128")`; named casts (`MyType(x)`) carry the name
/// in `func_name`.
fn cast_target_type(c: &sluice_ir::Call) -> Option<String> {
    if let ExprKind::TypeName(t) = &c.callee.kind {
        return Some(t.clone());
    }
    c.func_name.clone()
}

/// If `ty` is a narrowing integer type (`uintN`/`intN` with `N < 256`), return
/// its bit width. `uint`/`int` (alias for 256) and non-integer types return
/// `None`. `uint256`/`int256` are full-width and never narrow → `None`.
fn narrowing_int_bits(ty: &str) -> Option<u32> {
    let ty = ty.trim();
    let digits = ty.strip_prefix("uint").or_else(|| ty.strip_prefix("int"))?;
    // Bare `uint`/`int` (no digits) == 256-bit, not a narrowing cast.
    if digits.is_empty() {
        return None;
    }
    let bits: u32 = digits.parse().ok()?;
    // Must be a valid EVM integer width and strictly less than 256.
    if bits > 0 && bits < 256 && bits % 8 == 0 {
        Some(bits)
    } else {
        None
    }
}

/// True if the expression is a compile-time constant literal (so its value is
/// provably bounded and a cast/division of it is not attacker-driven).
fn is_constant_expr(e: &Expr) -> bool {
    matches!(e.kind, ExprKind::Lit(_))
}

/// Best-effort set of identifier names that the function guards against zero
/// (`require(x != 0)`, `require(x > 0)`, `if (x == 0) revert`). Used to suppress
/// division findings whose divisor is provably non-zero.
fn zero_checked_names(cx: &AnalysisContext, f: &sluice_ir::Function) -> Vec<String> {
    let mut names = Vec::new();
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            // Look for `x != 0`, `0 != x`, `x > 0`, `x >= 1`.
            if let ExprKind::Binary { op, lhs, rhs } = &e.kind {
                if matches!(op, BinOp::Ne | BinOp::Gt | BinOp::Ge | BinOp::Eq | BinOp::Lt | BinOp::Le) {
                    let lhs_zero = is_zero_lit(lhs);
                    let rhs_zero = is_zero_lit(rhs);
                    if rhs_zero {
                        if let Some(n) = lhs.simple_name() {
                            names.push(n.to_string());
                        }
                    }
                    if lhs_zero {
                        if let Some(n) = rhs.simple_name() {
                            names.push(n.to_string());
                        }
                    }
                }
            }
        });
    }
    let _ = cx;
    names
}

/// True if the expression is the numeric literal `0`.
fn is_zero_lit(e: &Expr) -> bool {
    matches!(&e.kind, ExprKind::Lit(sluice_ir::Lit::Number(n)) if n.trim() == "0")
        || matches!(&e.kind, ExprKind::Lit(sluice_ir::Lit::HexNumber(n)) if {
            let h = n.trim_start_matches("0x").trim_start_matches("0X");
            !h.is_empty() && h.bytes().all(|b| b == b'0')
        })
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Vulnerable: >=0.8 pragma, but a narrowing downcast of an attacker-supplied
    // value, an `unchecked { }` block on input, and an unguarded division.
    const VULN: &str = r#"
pragma solidity ^0.8.20;
contract Vuln {
    mapping(address => uint128) public packed;
    uint256 public total;
    function deposit(uint256 amount, uint256 parts) external {
        // narrowing downcast of attacker input -> silent truncation
        packed[msg.sender] = uint128(amount);
        // unchecked math on attacker input -> wrap-around
        unchecked { total = total + amount; }
        // division by a non-constant, un-checked divisor -> div-by-zero
        uint256 share = amount / parts;
        total = total + share;
    }
}
"#;

    // Safe: >=0.8 checked arithmetic only, SafeCast for narrowing, divisor is
    // require'd non-zero. Nothing here is a residual integer hazard.
    const SAFE: &str = r#"
pragma solidity ^0.8.20;
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
contract Safe {
    using SafeCast for uint256;
    mapping(address => uint128) public packed;
    uint256 public total;
    function deposit(uint256 amount, uint256 parts) external {
        require(parts != 0, "zero");
        packed[msg.sender] = amount.toUint128();
        total = total + amount;            // compiler-checked on >=0.8
        uint256 share = amount / parts;    // divisor proven non-zero
        total = total + share;
    }
}
"#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "integer-issues"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "integer-issues"));
    }
}
