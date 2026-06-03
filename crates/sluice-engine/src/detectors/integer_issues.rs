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
use sluice_ir::{BinOp, CallKind, Expr, ExprKind, UnOp};

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
            //
            // SUPPRESSION (F) — SAFE UNCHECKED: the canonical `unchecked { x =
            // nonce + 1; }` / `unchecked { ++counter; }` increment of a 256-bit
            // accumulator is not a reachable overflow (2^256 increments are
            // infeasible), and `unchecked` there is the standard gas
            // optimization. If *every* arithmetic op inside the function's
            // `unchecked` blocks is an increment-by-one, this is that pattern and
            // we stay silent. Any other unchecked arithmetic (`+ amount`, `- x`,
            // `* y`) still fires.
            //
            // SUPPRESSION (G) — GUARDED SUBTRACTION: the canonical ERC20 idiom
            // `require(a >= b); unchecked { ... a - b ... }` (e.g. OpenZeppelin
            // `decreaseAllowance`/`transferFrom`) is provably underflow-free — the
            // dominating `>=`/`>` check pins `a >= b` before the wrap-disabled
            // subtraction. We stay silent only when *every* unchecked subtraction
            // has such a matching guard and there is no other unchecked arithmetic.
            // Any unguarded `- x`, or any `+`/`*`, still fires.
            if f.effects.has_unchecked_math
                && takes_attacker_input
                && !unchecked_is_only_increment(f)
                && !unchecked_subtraction_is_guarded(f)
            {
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
                // SUPPRESSION (D) — DOMINATING GUARD: a function whose body has a
                // `type(uint...)`-bounds check feeding a `revert`/`require` (e.g.
                // `if (amount > type(uint96).max) revert E();`) has already proven
                // its values fit before narrowing. Suppress this function's
                // unsigned downcast findings entirely. Computed once per function.
                let fn_src = cx.source_text(f.span);
                let has_dominating_guard = fn_src.contains("type(uint")
                    && (fn_src.contains("revert") || fn_src.contains("require"));

                // Classify each local once: was it defined (last write) by a
                // `min(..., type(uintN).max)` clamp or by a monotonic
                // shrink (`a / b` / `a >> k`)? The cast operand is frequently a
                // bare local that holds such a value (`x = a / b; y = uintN(x);`),
                // which suppressions (B)/(C) miss when they look only at the cast's
                // own span. See `classify_locals`.
                let locals = classify_locals(cx, f);

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
                    if c.args.len() != 1 {
                        return;
                    }

                    // SUPPRESSION (A) — WIDTH-SAFE: the operand provably cannot
                    // exceed the target width, so truncation can never drop a set
                    // bit. Kills `uint160(address(x))`, `uint32(bytes4_var)`,
                    // `int128(uint128(uint64_var))`, and (via the nested-cast peel)
                    // the inner `uint160(msg.sender)` of
                    // `bytes32(uint256(uint160(msg.sender)))`.
                    if let Some(operand_bits) = operand_max_bits(cx, f, arg) {
                        if operand_bits <= bits {
                            return;
                        }
                    }

                    // SUPPRESSION (B) — CLAMPED: `uintN(_min(x, type(uintN).max))`
                    // is explicitly saturated to the target max before narrowing,
                    // so it cannot truncate. Detect the `min(` + `type(uint` shape
                    // in the cast's own source span.
                    let cast_src = cx.source_text(span);
                    if cast_src.contains("min(") && cast_src.contains("type(uint") {
                        return;
                    }
                    // SUPPRESSION (B') — CLAMPED-VIA-LOCAL: the same saturation, but
                    // the `min(..., type(uintN).max)` result was stored in a local
                    // first (`uint256 total = _min(x, type(uint40).max); ... uint40(total)`).
                    // The cast operand is then a bare identifier whose defining
                    // expression carries the clamp. Suppress only when the local was
                    // *last* written by such a clamp (computed in `classify_locals`).
                    if let ExprKind::Ident(name) = &arg.kind {
                        if matches!(locals.get(name.as_str()), Some(LocalDef::ClampedToTypeMax)) {
                            return;
                        }
                    }

                    // SUPPRESSION (C) — DIVISION-DOWN: `uintN(a / b)` (and the
                    // equally monotone `uintN(a >> k)`) shrinks the value toward
                    // zero, so casting the result does not introduce a fresh
                    // truncation hazard the author did not already reason about.
                    // Kills `uint32((t - g) / s)`.
                    if matches!(
                        &arg.kind,
                        ExprKind::Binary { op: BinOp::Div | BinOp::Shr, .. }
                    ) {
                        return;
                    }
                    // SUPPRESSION (C') — DIVISION-DOWN-VIA-LOCAL: identical monotone
                    // shrink, but the quotient was bound to a local first
                    // (`uint256 q = a / b; ... uintN(q)`). Same reasoning as (C);
                    // only the named-local indirection differs.
                    if let ExprKind::Ident(name) = &arg.kind {
                        if matches!(locals.get(name.as_str()), Some(LocalDef::ShrunkMonotone)) {
                            return;
                        }
                    }

                    // SUPPRESSION (D) — see `has_dominating_guard` above. Only
                    // applies to unsigned (`uintN`) narrowings, matching the
                    // `type(uintN).max` guard idiom.
                    if has_dominating_guard && ty.trim_start().starts_with("uint") {
                        return;
                    }

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

                    // (E) LOCATION: report at the cast expression `span` (the
                    // `uintN(...)` site), never `f.span`/the signature line.
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

/// Bit-width that an EVM value of textual type `ty` occupies, or `None` for
/// types whose width we can't bound:
///   * `address` / `payable` → 160
///   * `uintK` / `intK` → K (bare `uint`/`int` == 256)
///   * `bytesM` → 8*M (the fixed-size `bytes1`..`bytes32`; *not* dynamic `bytes`)
/// Used by the WIDTH-SAFE suppression (A): a cast `uintN(x)` cannot truncate when
/// the operand's width is `<= N`.
fn type_to_bits(ty: &str) -> Option<u32> {
    let ty = ty.trim();
    // Strip a storage-location / `payable` suffix if present (`address payable`).
    let head = ty.split_whitespace().next().unwrap_or(ty);
    if head == "address" || head == "payable" {
        return Some(160);
    }
    if let Some(digits) = head.strip_prefix("uint").or_else(|| head.strip_prefix("int")) {
        if digits.is_empty() {
            return Some(256); // bare `uint`/`int`
        }
        let bits: u32 = digits.parse().ok()?;
        return (bits > 0 && bits <= 256 && bits % 8 == 0).then_some(bits);
    }
    // Fixed-size `bytesM` (M in 1..=32). Dynamic `bytes` has no digits → unbounded.
    if let Some(digits) = head.strip_prefix("bytes") {
        if digits.is_empty() {
            return None; // dynamic `bytes`
        }
        let m: u32 = digits.parse().ok()?;
        return (m >= 1 && m <= 32).then_some(m * 8);
    }
    None
}

/// Resolve the declared textual type of a bare identifier `name` within function
/// `f`: first its parameters, then its contract's state variables. Returns `None`
/// for locals / unknowns (we then conservatively decline to suppress).
fn lookup_ident_type(cx: &AnalysisContext, f: &sluice_ir::Function, name: &str) -> Option<String> {
    for p in &f.params {
        if p.name.as_deref() == Some(name) {
            return Some(p.ty.clone());
        }
    }
    let contract = cx.scir.contract(f.contract)?;
    contract
        .state_vars
        .iter()
        .find(|v| v.name == name)
        .map(|v| v.ty.clone())
}

/// Upper bound (in bits) on the value an operand of a narrowing cast can hold, or
/// `None` when we cannot prove a bound (in which case the cast is *not*
/// width-suppressed). The nested-cast peel: the result of `uintK(...)` / `intK(...)`
/// / `address(...)` / `bytesM(...)` is exactly the target width regardless of what
/// is inside, so we read the inner cast's *target* type and never recurse further.
fn operand_max_bits(cx: &AnalysisContext, f: &sluice_ir::Function, arg: &Expr) -> Option<u32> {
    match &arg.kind {
        // A nested type cast: its width is its own target type's width.
        ExprKind::Call(c) if c.kind == CallKind::TypeCast => {
            let ty = cast_target_type(c)?;
            type_to_bits(&ty)
        }
        // `msg.sender` / `tx.origin` are `address` (160-bit). `.length` is a
        // `uint256` and therefore *not* width-safe (returns 256).
        ExprKind::Member { base, member } => {
            if member == "length" {
                return Some(256);
            }
            if let ExprKind::Ident(root) = &base.kind {
                if (root == "msg" && member == "sender") || (root == "tx" && member == "origin") {
                    return Some(160);
                }
            }
            None
        }
        // A bare identifier: resolve its declared (param/state-var) type.
        ExprKind::Ident(name) => {
            let ty = lookup_ident_type(cx, f, name)?;
            type_to_bits(&ty)
        }
        _ => None,
    }
}

/// SUPPRESSION (F) helper. True when *every* arithmetic operation inside the
/// function's `unchecked { }` blocks is an increment-by-one (`x + 1`, `1 + x`,
/// `x++`, `++x`) — the canonical bounded nonce/counter bump on a 256-bit
/// accumulator, which cannot realistically overflow. Returns `false` if any
/// other arithmetic (`+ amount`, `- x`, `* y`, division, ...) appears, so genuine
/// attacker-influenced wrap-around still fires. Returns `false` if there is no
/// unchecked arithmetic at all (nothing to suppress here).
fn unchecked_is_only_increment(f: &sluice_ir::Function) -> bool {
    let mut saw_arith = false;
    let mut all_increment = true;

    fn is_one_lit(e: &Expr) -> bool {
        matches!(&e.kind, ExprKind::Lit(sluice_ir::Lit::Number(n)) if n.trim() == "1")
    }

    // Walk a statement subtree, recording arithmetic seen within it.
    fn scan(stmt: &sluice_ir::Stmt, saw_arith: &mut bool, all_increment: &mut bool) {
        stmt.visit_exprs(&mut |e| match &e.kind {
            ExprKind::Binary { op, lhs, rhs } if op.is_arithmetic() => {
                *saw_arith = true;
                // Only a `+ 1` / `1 +` add counts as a safe increment.
                let is_inc = matches!(op, BinOp::Add) && (is_one_lit(rhs) || is_one_lit(lhs));
                if !is_inc {
                    *all_increment = false;
                }
            }
            ExprKind::Unary { op, .. } => {
                if matches!(op, UnOp::PreInc | UnOp::PostInc) {
                    // `++x` / `x++` — a safe increment; does not flip the flag.
                    *saw_arith = true;
                } else if matches!(op, UnOp::PreDec | UnOp::PostDec) {
                    // A decrement inside `unchecked` can underflow → not safe.
                    *saw_arith = true;
                    *all_increment = false;
                }
            }
            _ => {}
        });
    }

    // Find `unchecked { }` blocks and scan their contents.
    for s in &f.body {
        s.visit(&mut |st| {
            if let sluice_ir::StmtKind::Block { unchecked: true, stmts } = &st.kind {
                for inner in stmts {
                    scan(inner, &mut saw_arith, &mut all_increment);
                }
            }
        });
    }

    saw_arith && all_increment
}

/// How a local variable was *last* defined, when that definition makes a
/// subsequent narrowing cast of the local provably non-truncating. Used by the
/// CLAMPED-VIA-LOCAL (B') and DIVISION-DOWN-VIA-LOCAL (C') suppressions, which
/// generalize the existing single-expression (B)/(C) shapes to the common
/// `tmp = <safe expr>; ... uintN(tmp)` form.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LocalDef {
    /// Bound to a `min(..., type(uintN).max)` saturation — cannot exceed the
    /// clamped maximum, so a downcast to that max's width cannot truncate.
    ClampedToTypeMax,
    /// Bound to a monotone shrink (`a / b` or `a >> k`) — rounds toward zero, so
    /// casting the result is not a fresh truncation hazard (same as (C)).
    ShrunkMonotone,
}

/// Classify a function's locals by their *last* top-level definition (VarDecl
/// init or plain `=` assignment) into the `LocalDef` shapes above. Later writes
/// overwrite earlier ones (last-write-wins), matching the value the cast will
/// actually see. Definitions we cannot prove safe are simply absent from the map
/// (we then decline to suppress — precision over recall). Compound assignments
/// (`+=`, `-=`, ...) are intentionally ignored: they are not a pure clamp/shrink.
fn classify_locals(
    cx: &AnalysisContext,
    f: &sluice_ir::Function,
) -> std::collections::HashMap<String, LocalDef> {
    // First gather `(name, defining-expr)` pairs in source order, then fold them
    // last-write-wins. Collecting into a Vec first keeps the statement walk a
    // simple shared-borrow closure (no nested mutable capture of `map`).
    let mut defs: Vec<(&str, &Expr)> = Vec::new();
    for s in &f.body {
        s.visit(&mut |st| match &st.kind {
            // `T name = init;`
            sluice_ir::StmtKind::VarDecl { name: Some(n), init: Some(init), .. } => {
                defs.push((n.as_str(), init));
            }
            // `name = value;` (plain assignment only; compound ops are not a clamp/shrink).
            sluice_ir::StmtKind::Expr(Expr {
                kind: ExprKind::Assign { op: sluice_ir::AssignOp::Assign, target, value },
                ..
            }) => {
                if let ExprKind::Ident(n) = &target.kind {
                    defs.push((n.as_str(), value.as_ref()));
                }
            }
            _ => {}
        });
    }

    let mut map = std::collections::HashMap::new();
    for (name, def) in defs {
        // Monotone shrink: top-level `/` or `>>` (right-shift, like integer
        // division, only ever sheds magnitude — never grows the value).
        if matches!(&def.kind, ExprKind::Binary { op: BinOp::Div | BinOp::Shr, .. }) {
            map.insert(name.to_string(), LocalDef::ShrunkMonotone);
            continue;
        }
        // Clamp: `min(..., type(uintN).max)` saturation. Reuse the exact textual
        // signal suppression (B) keys on, but read it from the *definition's* span.
        let def_src = cx.source_text(def.span);
        if def_src.contains("min(") && def_src.contains("type(uint") {
            map.insert(name.to_string(), LocalDef::ClampedToTypeMax);
            continue;
        }
        // Anything else: this local is no longer provably safe — drop any prior
        // classification so a later unsafe rebind cannot be mistaken for safe.
        map.remove(name);
    }

    map
}

/// SUPPRESSION (G) helper. True when the function's `unchecked { }` arithmetic is
/// exclusively subtraction *and* every such subtraction `a - b` is dominated by a
/// matching `require(a >= b)` / `require(a > b)` (or `assert`) lower-bound guard,
/// i.e. the canonical OpenZeppelin allowance/balance idiom that is provably
/// underflow-free.
///
/// Conservative by construction: any `+`/`*`/`/` inside `unchecked`, any
/// decrement (`--`), or any subtraction whose operands are not pinned by such a
/// require'd lower bound makes this return `false`, so genuine attacker-influenced
/// wrap-around still fires.
fn unchecked_subtraction_is_guarded(f: &sluice_ir::Function) -> bool {
    // (1) Collect ordered `(larger, smaller)` name pairs proven by a
    //     `require(a >= b)` / `require(a > b)` (or `assert`). We deliberately only
    //     trust `>=`/`>` *inside a require/assert*: there the comparison is the
    //     surviving (truthy) condition, so `a >= b` genuinely holds afterwards. A
    //     bare `a <= b` or an `if (a >= b) revert` would prove the *opposite* on
    //     the surviving path, so we do NOT infer bounds from those (soundness over
    //     reach — a wrong inference here would silence a real underflow).
    let mut guarded_pairs: Vec<(String, String)> = Vec::new();
    // Pull `(a, b)` out of a `>=`/`>` comparison; recurse through `&&` so
    // `require(a >= b && p >= q)` records both pairs.
    fn collect_ge(cond: &Expr, out: &mut Vec<(String, String)>) {
        match &cond.kind {
            ExprKind::Binary { op: BinOp::Ge | BinOp::Gt, lhs, rhs } => {
                if let (Some(h), Some(l)) = (lhs.simple_name(), rhs.simple_name()) {
                    out.push((h.to_string(), l.to_string()));
                }
            }
            ExprKind::Binary { op: BinOp::And, lhs, rhs } => {
                collect_ge(lhs.as_ref(), out);
                collect_ge(rhs.as_ref(), out);
            }
            _ => {}
        }
    }
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if let ExprKind::Call(c) = &e.kind {
                if matches!(
                    c.kind,
                    CallKind::Builtin(sluice_ir::Builtin::Require)
                        | CallKind::Builtin(sluice_ir::Builtin::Assert)
                ) {
                    if let Some(cond) = c.args.first() {
                        collect_ge(cond, &mut guarded_pairs);
                    }
                }
            }
        });
    }

    // (2) Inspect every arithmetic op inside `unchecked { }`. Require all to be
    //     subtractions with a matching guard; reject anything else.
    let mut saw_sub = false;
    let mut all_guarded_sub = true;
    for s in &f.body {
        s.visit(&mut |st| {
            let sluice_ir::StmtKind::Block { unchecked: true, stmts } = &st.kind else {
                return;
            };
            for inner in stmts {
                inner.visit_exprs(&mut |e| match &e.kind {
                    ExprKind::Binary { op, lhs, rhs } if op.is_arithmetic() => {
                        if matches!(op, BinOp::Sub) {
                            saw_sub = true;
                            // `lhs - rhs` is safe iff a guard proved `lhs >= rhs`
                            // on the same two names.
                            let matched = match (lhs.simple_name(), rhs.simple_name()) {
                                (Some(a), Some(b)) => {
                                    guarded_pairs.iter().any(|(h, l)| h == a && l == b)
                                }
                                _ => false,
                            };
                            if !matched {
                                all_guarded_sub = false;
                            }
                        } else {
                            // `+` / `*` / `/` / `%` inside unchecked — not this pattern.
                            all_guarded_sub = false;
                        }
                    }
                    // `--x` / `x--` inside unchecked can underflow — reject.
                    ExprKind::Unary { op: UnOp::PreDec | UnOp::PostDec, .. } => {
                        all_guarded_sub = false;
                    }
                    _ => {}
                });
            }
        });
    }

    saw_sub && all_guarded_sub
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

    // ------------------------------------------------------------------
    // Tightening regressions (false positives that must now stay SILENT).
    // Each wraps the cast in an externally-callable function with a
    // parameter so the operand is attacker-controlled — i.e. these WOULD
    // have fired before the suppressions were added.
    // ------------------------------------------------------------------

    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "integer-issues")
    }

    // (A) WIDTH-SAFE: `uint160(msg.sender)` (the inner cast of
    // `bytes32(uint256(uint160(msg.sender)))`) cannot truncate — `msg.sender`
    // is 160-bit. The wrapping `uint256(...)`/`bytes32(...)` are non-narrowing.
    #[test]
    fn silent_on_address_packed_to_bytes32() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    mapping(bytes32 => bool) public seen;
    function mark(uint256 salt) external {
        seen[bytes32(uint256(uint160(msg.sender)))] = true;
        salt;
    }
}
"#;
        assert!(!fires(src), "width-safe address->bytes32 pack must be silent");
    }

    // (A) WIDTH-SAFE: `uint160(address(x))`, `uint32(b4)` (bytes4 == 32-bit),
    // and `int128(uint128(u64))` (nested-cast peel + uint64 <= 128).
    #[test]
    fn silent_on_width_safe_casts() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint64 public u64;
    uint160 public a160;
    int128 public i128;
    function f(address x) external {
        a160 = uint160(address(x));
    }
    function g(uint64 v) external {
        // nested-cast peel: inner cast result is uint128 (<= int128 target).
        i128 = int128(uint128(v));
    }
    function h(bytes4 b4) external {
        // bytes4 param narrowed to uint32 (8*4 == 32 bits) — width-safe.
        u64 = uint64(uint32(b4));
    }
}
"#;
        assert!(!fires(src), "width-safe casts must be silent");
    }

    // (B) CLAMPED: `uint40(_min(p, type(uint40).max))` is saturated first.
    #[test]
    fn silent_on_min_clamped_cast() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint40 public packed;
    function set(uint256 p) external {
        packed = uint40(_min(p, type(uint40).max));
    }
    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
"#;
        assert!(!fires(src), "min()-clamped downcast must be silent");
    }

    // (C) DIVISION-DOWN: `uint32((t - g) / s)` — division rounds down.
    #[test]
    fn silent_on_division_down_cast() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint32 public rate;
    function f(uint256 t, uint256 g, uint256 s) external {
        require(s != 0);
        rate = uint32((t - g) / s);
    }
}
"#;
        assert!(!fires(src), "downcast of a division quotient must be silent");
    }

    // (D) DOMINATING GUARD: `uint96(amount)` guarded by an explicit
    // `if (amount > type(uint96).max) revert E();` bounds check.
    #[test]
    fn silent_on_dominating_guard_cast() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    error E();
    uint96 public packed;
    function f(uint256 amount) external {
        if (amount > type(uint96).max) revert E();
        packed = uint96(amount);
    }
}
"#;
        assert!(!fires(src), "type(uintN).max-guarded downcast must be silent");
    }

    // (F) SAFE UNCHECKED: a bare `unchecked { x = nonce + 1; }` increment of a
    // 256-bit accumulator is not a reachable overflow.
    #[test]
    fn silent_on_unchecked_nonce_increment() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint256 public nonce;
    function bump(uint256 x) external {
        unchecked { nonce = nonce + 1; }
        x;
    }
}
"#;
        assert!(!fires(src), "unchecked +1 nonce increment must be silent");
    }

    // POSITIVE: a genuinely-unbounded downcast of a full-width attacker value
    // still FIRES — the tightening must not silence real truncation bugs.
    #[test]
    fn fires_on_unbounded_downcast() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint64 public y;
    function f(uint256 x) external { y = uint64(x); }
}
"#;
        assert!(fires(src), "unbounded uint256->uint64 downcast must still fire");
    }

    // ------------------------------------------------------------------
    // R6 tightening regressions: the residual etherfi FP shapes.
    // ------------------------------------------------------------------

    // (B') CLAMPED-VIA-LOCAL: `min(..., type(uintN).max)` is stored in a local
    // and the cast operates on that local (etherfi MembershipNFT.tierPointsOf /
    // loyaltyPointsOf). Suppression (B) only saw the cast's own span; (B') reads
    // the local's defining clamp.
    #[test]
    fn silent_on_min_clamped_via_local() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    function pointsOf(uint256 base, uint256 earned) external pure returns (uint40) {
        uint256 total = _min(base + earned, type(uint40).max);
        return uint40(total);
    }
    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
"#;
        assert!(!fires(src), "min()-clamped-via-local downcast must be silent");
    }

    // (B') CLAMPED-VIA-LOCAL with a later reassignment (etherfi
    // MembershipNFT.membershipPointsEarning): the local is first a quotient, then
    // re-bound to a `min(..., type(uint40).max)` clamp; the *last* write (clamp)
    // governs the subsequent cast.
    #[test]
    fn silent_on_min_clamped_via_reassigned_local() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    function earningOf(uint256 shares, uint256 elapsed, uint256 rate) external pure returns (uint40) {
        uint256 earning = shares * elapsed * rate / 10000;
        earning = _min((earning / 1 days) / 0.001 ether, type(uint40).max);
        return uint40(earning);
    }
    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
"#;
        assert!(!fires(src), "reassigned min()-clamped local downcast must be silent");
    }

    // (C') DIVISION-DOWN-VIA-LOCAL: a quotient bound to a local, then narrowed
    // (etherfi depositDataRootGenerator `uint64(deposit_amount)` where
    // `deposit_amount = _amountIn / GWEI`, and MembershipManager._topUpDeposit
    // `uint40(dilutedPoints)`). Divisors here are constant / zero-checked so the
    // separate div-by-zero detector stays silent and only the DOWNCAST is under
    // test.
    #[test]
    fn silent_on_division_down_via_local() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint64 public packed;
    function f(uint256 amountIn) external {
        uint256 q = amountIn / 1e9;
        packed = uint64(q);
    }
    function g(uint256 total, uint256 pts, uint256 divisor) external returns (uint40) {
        require(divisor != 0);
        uint256 diluted = (total * pts) / divisor;
        return uint40(diluted);
    }
}
"#;
        assert!(!fires(src), "downcast of a division quotient held in a local must be silent");
    }

    // (C) extended to right-shift: `uintN(a >> k)` is also a monotone shrink.
    #[test]
    fn silent_on_shift_right_cast() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint128 public half;
    function f(uint256 x) external {
        half = uint128(x >> 1);
    }
}
"#;
        assert!(!fires(src), "downcast of a right-shift result must be silent");
    }

    // (G) GUARDED SUBTRACTION: the canonical ERC20 `require(a >= b); unchecked {
    // a - b }` idiom (etherfi EETH.decreaseAllowance / transferFrom) is
    // provably underflow-free.
    #[test]
    fn silent_on_guarded_unchecked_subtraction() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    mapping(address => uint256) public allowanceOf;
    function decreaseAllowance(address spender, uint256 amount) external returns (bool) {
        uint256 currentAllowance = allowanceOf[spender];
        require(currentAllowance >= amount, "below zero");
        unchecked { allowanceOf[spender] = currentAllowance - amount; }
        return true;
    }
}
"#;
        assert!(!fires(src), "guarded unchecked subtraction (ERC20 idiom) must be silent");
    }

    // POSITIVE (G): an UNGUARDED unchecked subtraction on attacker input still
    // FIRES — the guard-matching must be precise, not a blanket pass for any
    // unchecked `-`.
    #[test]
    fn fires_on_unguarded_unchecked_subtraction() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint256 public bal;
    function withdraw(uint256 amount) external {
        unchecked { bal = bal - amount; }
    }
}
"#;
        assert!(fires(src), "unguarded unchecked subtraction must still fire");
    }

    // POSITIVE (G): a guard on the WRONG operands does not license the
    // subtraction — `require(x >= y)` must not suppress `a - b`.
    #[test]
    fn fires_on_unchecked_subtraction_with_mismatched_guard() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint256 public bal;
    function f(uint256 a, uint256 b, uint256 x, uint256 y) external {
        require(x >= y);
        unchecked { bal = a - b; }
    }
}
"#;
        assert!(fires(src), "unchecked subtraction with a mismatched guard must still fire");
    }

    // POSITIVE (B'/C'): a downcast of a local that is NEITHER a clamp NOR a
    // monotone shrink (it is an unbounded sum of attacker input) still FIRES —
    // the local-resolution must not blanket-suppress every local.
    #[test]
    fn fires_on_downcast_of_unbounded_local() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint64 public y;
    function f(uint256 a, uint256 b) external {
        uint256 s = a + b;
        y = uint64(s);
    }
}
"#;
        assert!(fires(src), "downcast of an unbounded (sum) local must still fire");
    }
}
