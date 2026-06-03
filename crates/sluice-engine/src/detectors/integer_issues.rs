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
        // Hoisted out of the per-function loop: `struct_field_widths` depends only on
        // `cx` (it scans every parsed struct in the corpus), so calling it once instead
        // of once-per-function turns an O(functions × total-source-bytes) full-corpus
        // rescan (~225s on a 2800-file repo — the dominant cost of the whole analysis)
        // into a single pass. Loop-invariant, so findings are byte-identical.
        let fields = struct_field_widths(cx);

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

                // PROVENANCE WIDTHS: an upper bound (in bits) on the value each
                // named variable in this function can hold. Built once and threaded
                // through `operand_max_bits` so the WIDTH-SAFE suppression (A) can
                // reason about identifiers, struct-field members, subtractions and
                // `min`/`max` results — not just the cast's own syntactic shape:
                //   * params / state vars → their *declared* type width;
                //   * locals → the *tighter* of their declared type width and the
                //     inferred width of their defining expression (so a `uint256`
                //     local that only ever holds a `uint96` struct field is bounded
                //     at 96). See `value_widths`.
                // Struct field name → widest declared field width across all parsed
                // structs (widest == sound upper bound when a field name is reused
                // with different widths in different structs). Lets a cast operand
                // `request.amountOfEEth` (a `uint96` struct field) be proven safe.
                let widths = value_widths(cx, f, &fields);

                // DEDUPE: collapse repeated same-width downcasts inside one function
                // (e.g. `x += uint128(a); y += uint128(b);`) to a single finding,
                // keyed by target bit width so two genuinely different-width
                // truncations in one function are still both reported.
                let mut reported_widths: std::collections::HashSet<u32> =
                    std::collections::HashSet::new();

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
                    //
                    // PROVENANCE-extended: also kills the dominant etherfi shapes —
                    //   * `uint128(request.amountOfEEth)` where `amountOfEEth` is a
                    //     `uint96` STORAGE/STRUCT FIELD (rule a);
                    //   * `uint96(request.shareOfEEth - x)` / a local bound to it,
                    //     since `a - b <= a` and `a` is a `uint96` field (rule b);
                    //   * `uint40(_max(p1, p2))` where both `p1`/`p2` are `uint40`
                    //     locals (the max of `uintN`-typed operands is `<= uintN`).
                    if let Some(operand_bits) = operand_max_bits(cx, f, arg, &widths, &fields) {
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

                    // DEDUPE: one finding per (function, target width). A function
                    // that narrows several values to the same `uintN` (the common
                    // paired `x += uintN(a); y += uintN(b);` accounting update) is a
                    // single review item, not N.
                    if !reported_widths.insert(bits) {
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

/// An upper bound (in bits) on the value each named variable in `f` can hold —
/// the PROVENANCE backbone of the WIDTH-SAFE suppression. A name is bounded by:
///   * params / state vars → their declared type width (Solidity guarantees the
///     stored value fits the declared width);
///   * locals → the *tighter* (minimum) of their declared type width and the
///     inferred width of their defining expression. The defining-expression bound
///     lets a `uint256 amountToWithdraw = request.amountWithFee;` local inherit the
///     `uint96` field's 96-bit bound, and a `uint256 remainder = a96 > b ? a96 - b
///     : 0;` local inherit 96 via the subtraction/ternary rules.
///
/// Computed as a forward pass in source order so a later local may reference an
/// earlier one. Names whose width we cannot bound are simply absent (we then
/// decline to suppress — precision over recall).
fn value_widths(
    cx: &AnalysisContext,
    f: &sluice_ir::Function,
    fields: &std::collections::HashMap<String, u32>,
) -> std::collections::HashMap<String, u32> {
    let mut widths: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

    // (1) Params and state vars: declared-type width.
    for p in &f.params {
        if let (Some(n), Some(b)) = (p.name.as_deref(), type_to_bits(&p.ty)) {
            widths.insert(n.to_string(), b);
        }
    }
    if let Some(c) = cx.scir.contract(f.contract) {
        for v in &c.state_vars {
            if let Some(b) = type_to_bits(&v.ty) {
                // Don't let a state var shadow a same-named param already bounded.
                widths.entry(v.name.clone()).or_insert(b);
            }
        }
    }

    // (2) Locals, in source order: tighten declared width by the defining
    //     expression's inferred width. Collect `(name, declared_ty, init)` first to
    //     keep the statement walk a shared-borrow closure, then fold in order.
    let mut defs: Vec<(String, String, Option<&Expr>)> = Vec::new();
    for s in &f.body {
        s.visit(&mut |st| match &st.kind {
            sluice_ir::StmtKind::VarDecl { name: Some(n), ty, init } => {
                defs.push((n.clone(), ty.clone(), init.as_ref()));
            }
            sluice_ir::StmtKind::Expr(Expr {
                kind: ExprKind::Assign { op: sluice_ir::AssignOp::Assign, target, value },
                ..
            }) => {
                if let ExprKind::Ident(n) = &target.kind {
                    // A plain reassignment: type is whatever was declared earlier
                    // (unknown here), so carry only the value's inferred width.
                    defs.push((n.clone(), String::new(), Some(value.as_ref())));
                }
            }
            _ => {}
        });
    }
    for (name, ty, init) in defs {
        let declared = type_to_bits(&ty);
        let inferred = init.and_then(|e| operand_max_bits(cx, f, e, &widths, fields));
        let bound = match (declared, inferred) {
            (Some(d), Some(i)) => Some(d.min(i)),
            (Some(d), None) => Some(d),
            (None, Some(i)) => Some(i),
            (None, None) => None,
        };
        match bound {
            // Last-write-wins: a later definition replaces the earlier bound.
            Some(b) => {
                widths.insert(name, b);
            }
            // Unbounded redefinition: drop any earlier (now-stale) bound so a later
            // cast cannot be wrongly suppressed by a superseded value.
            None => {
                widths.remove(&name);
            }
        }
    }

    widths
}

/// Map of struct-field name → an upper bound (in bits) on that field's declared
/// integer width, scanned textually from every parsed source file's `struct { ...
/// }` bodies. When the same field name appears with different widths in different
/// structs we keep the **widest** (the sound upper bound, since a bare `base.field`
/// member access does not tell us which struct `base` is). Non-integer fields and
/// fields whose type we can't width (`address`, `bytesM` included via `type_to_bits`)
/// are recorded too, so e.g. an `address` field bounds at 160.
///
/// This is the structural source-of-truth for rule (a): a downcast `uintN(x)` is
/// width-safe when `x` is read from a `uintN`-or-narrower struct/state field.
fn struct_field_widths(cx: &AnalysisContext) -> std::collections::HashMap<String, u32> {
    let mut map: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for file in &cx.scir.files {
        scan_struct_fields(&file.content, &mut map);
    }
    map
}

/// Textually extract `type field;` declarations from every `struct <Name> { ... }`
/// block in `src`, folding each field's width into `map` (keeping the widest on a
/// name collision). Deliberately lightweight: it scans for the `struct` keyword,
/// finds the matching `{`/`}` (brace-depth) and splits the body on `;`.
fn scan_struct_fields(src: &str, map: &mut std::collections::HashMap<String, u32>) {
    let bytes = src.as_bytes();
    let mut search_from = 0usize;
    while let Some(rel) = src[search_from..].find("struct") {
        let kw = search_from + rel;
        // Require `struct` to be a standalone keyword (word boundaries).
        let before_ok = kw == 0 || !is_ident_byte(bytes[kw - 1]);
        let after = kw + "struct".len();
        let after_ok = after < bytes.len() && !is_ident_byte(bytes[after]);
        if !(before_ok && after_ok) {
            search_from = after;
            continue;
        }
        // Find the opening brace of the struct body.
        let Some(open_rel) = src[after..].find('{') else { break };
        let open = after + open_rel;
        // Walk to the matching close brace by depth.
        let mut depth = 0i32;
        let mut i = open;
        let mut close = None;
        while i < bytes.len() {
            match bytes[i] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(i);
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        let Some(close) = close else { break };
        // Strip `//` line and `/* */` block comments from the body first, so a
        // trailing `// 12 bytes` on one field does not bleed into the *next*
        // `;`-entry and shadow its leading type token (the bug that left
        // `amountWithFee` / `totalVaultShares` unresolved).
        let body = strip_solidity_comments(&src[open + 1..close]);
        // Each `;`-separated entry is `type name`. Take the first token as the type
        // and the last identifier-ish token as the field name.
        for entry in body.split(';') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let Some(tyf) = entry.split_whitespace().next() else { continue };
            // The field name is the final whitespace-token (strip a trailing
            // bracket for fixed arrays, which we don't width anyway).
            let Some(field) = entry.split_whitespace().last() else { continue };
            // Skip mapping/array/nested types (not a plain `uintN`/`address` scalar).
            if field.ends_with(']') || tyf.starts_with("mapping") {
                continue;
            }
            let field = field.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_');
            if field.is_empty() {
                continue;
            }
            if let Some(b) = type_to_bits(tyf) {
                map.entry(field.to_string())
                    .and_modify(|w| *w = (*w).max(b))
                    .or_insert(b);
            }
        }
        search_from = close + 1;
    }
}

/// Identifier continuation byte (ASCII letter/digit/underscore/`$`).
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// Replace `//` line comments and `/* ... */` block comments with whitespace. We
/// only re-tokenize the result on whitespace, so collapsing comments to a single
/// space is enough. Self-contained so this detector does not depend on the
/// context's private stripper. Char-based to stay UTF-8 safe on comment text.
fn strip_solidity_comments(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            // Line comment: skip to end of line.
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if chars[i] == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            // Block comment: skip to closing `*/`.
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            out.push(' ');
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Upper bound (in bits) on the value an operand of a narrowing cast can hold, or
/// `None` when we cannot prove a bound (in which case the cast is *not*
/// width-suppressed). The nested-cast peel: the result of `uintK(...)` / `intK(...)`
/// / `address(...)` / `bytesM(...)` is exactly the target width regardless of what
/// is inside, so we read the inner cast's *target* type and never recurse further.
///
/// PROVENANCE-aware. Beyond the original nested-cast / `msg.sender` / declared-type
/// cases, this also bounds:
///   * a struct-field member `base.field` by `field`'s declared width (rule a),
///     resolved from `fields` (built by [`struct_field_widths`]);
///   * a subtraction `a - b` by the width of its minuend `a` (since `a - b <= a`,
///     rule b);
///   * a ternary `c ? x : y` by `max(width(x), width(y))`;
///   * a `min`/`max` call by the appropriate bound over its argument widths
///     (`min` <= the smaller arg, `max` <= the larger), so `uintN(_max(p, q))` with
///     `uintN`-typed `p`/`q` is width-safe;
///   * a bare identifier by its entry in `widths` (declared param/state-var/local
///     type, tightened by its defining expression — see [`value_widths`]).
fn operand_max_bits(
    cx: &AnalysisContext,
    f: &sluice_ir::Function,
    arg: &Expr,
    widths: &std::collections::HashMap<String, u32>,
    fields: &std::collections::HashMap<String, u32>,
) -> Option<u32> {
    match &arg.kind {
        // A nested type cast: its width is its own target type's width.
        ExprKind::Call(c) if c.kind == CallKind::TypeCast => {
            let ty = cast_target_type(c)?;
            type_to_bits(&ty)
        }
        // `min`/`max` over operands of known width: the result cannot exceed the
        // bound implied by the operands. `min(a, b) <= min(widths)`,
        // `max(a, b) <= max(widths)`. Requires *every* argument's width to be
        // known (an unknown arg leaves the result unbounded → `None`).
        ExprKind::Call(c)
            if c.kind == CallKind::Internal && is_min_max_name(c.func_name.as_deref()) =>
        {
            if c.args.is_empty() {
                return None;
            }
            let mut acc: Option<u32> = None;
            let is_min = is_min_name(c.func_name.as_deref());
            for a in &c.args {
                let w = operand_max_bits(cx, f, a, widths, fields)?;
                acc = Some(match acc {
                    None => w,
                    Some(prev) if is_min => prev.min(w),
                    Some(prev) => prev.max(w),
                });
            }
            acc
        }
        // `msg.sender` / `tx.origin` are `address` (160-bit). `.length` is a
        // `uint256` and therefore *not* width-safe (returns 256). Otherwise, if the
        // accessed `member` is a struct field of known width, use that.
        ExprKind::Member { base, member } => {
            if member == "length" {
                return Some(256);
            }
            if let ExprKind::Ident(root) = &base.kind {
                if (root == "msg" && member == "sender") || (root == "tx" && member == "origin") {
                    return Some(160);
                }
            }
            // `base.field` where `field` is a declared struct field (rule a).
            fields.get(member.as_str()).copied()
        }
        // A subtraction is bounded by its minuend: `a - b <= a` (rule b). We do not
        // bound `+`/`*` (those can grow), nor recurse into other binary ops here
        // (division/shift are handled by the dedicated DIVISION-DOWN suppressions).
        ExprKind::Binary { op: BinOp::Sub, lhs, .. } => {
            operand_max_bits(cx, f, lhs, widths, fields)
        }
        // A ternary is bounded by the wider of its two arms.
        ExprKind::Ternary { then_e, else_e, .. } => {
            let t = operand_max_bits(cx, f, then_e, widths, fields)?;
            let e = operand_max_bits(cx, f, else_e, widths, fields)?;
            Some(t.max(e))
        }
        // A numeric/hex literal: bounded by the bits its constant value occupies.
        ExprKind::Lit(_) => literal_bits(arg),
        // A bare identifier: its precomputed provenance width (declared type,
        // tightened by its defining expression).
        ExprKind::Ident(name) => widths.get(name.as_str()).copied(),
        _ => None,
    }
}

/// True if `name` is a recognized `min`/`max` helper (`min`, `max`, `_min`,
/// `_max`, or `Math.min`/`Math.max` lowered to the bare member name). Used to
/// bound the result of such a call by its arguments' widths.
fn is_min_max_name(name: Option<&str>) -> bool {
    is_min_name(name) || is_max_name(name)
}
fn is_min_name(name: Option<&str>) -> bool {
    matches!(name, Some("min") | Some("_min") | Some("Math.min"))
}
fn is_max_name(name: Option<&str>) -> bool {
    matches!(name, Some("max") | Some("_max") | Some("Math.max"))
}

/// Bits occupied by a non-negative integer literal, or `None` for anything we
/// cannot evaluate cheaply (so the cast is not suppressed). A decimal/hex `0`
/// occupies 0 bits; otherwise we round the value up to a byte-aligned EVM width.
fn literal_bits(e: &Expr) -> Option<u32> {
    let raw = match &e.kind {
        ExprKind::Lit(sluice_ir::Lit::Number(n)) => n.trim().replace('_', ""),
        ExprKind::Lit(sluice_ir::Lit::HexNumber(n)) => {
            let h = n.trim().trim_start_matches("0x").trim_start_matches("0X").replace('_', "");
            if h.is_empty() || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            // 4 bits per hex digit, byte-aligned, leading zeros trimmed.
            let trimmed = h.trim_start_matches('0');
            if trimmed.is_empty() {
                return Some(0);
            }
            let bits = (trimmed.len() as u32) * 4;
            return Some(bits.div_ceil(8) * 8);
        }
        _ => return None,
    };
    // Plain decimal only (no scientific/`ether`/`days` suffix — those are not bare
    // digits and we conservatively decline). Parse into u128; bail if too large.
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let v: u128 = raw.parse().ok()?;
    if v == 0 {
        return Some(0);
    }
    let bits = 128 - v.leading_zeros();
    Some(bits.div_ceil(8) * 8)
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

    // ------------------------------------------------------------------
    // R7 PROVENANCE-WIDTH regressions: the residual etherfi downcast FPs.
    // The dominant shape is `field/slot += uintN(x)` where the cast operand
    // `x` is itself proven `<= N` bits by its provenance (a narrow struct
    // field, a subtraction/ternary/min-max of narrow operands, or a local
    // that inherits such a bound). Each must now stay SILENT.
    // ------------------------------------------------------------------

    // (A/rule-a) MEMBER → NARROW STRUCT FIELD: `uint128(request.amountOfEEth)`
    // where `amountOfEEth` is a `uint96` struct field — the 128-bit target
    // trivially holds a 96-bit field, so it cannot truncate. (etherfi
    // PriorityWithdrawalQueue._claimWithdraw line 582.)
    #[test]
    fn silent_on_downcast_of_narrow_struct_field() {
        let src = r#"
pragma solidity ^0.8.20;
interface I {
    struct WithdrawRequest {
        address user;        // 20 bytes
        uint96 amountOfEEth; // 12 bytes
        uint96 shareOfEEth;  // 12 bytes
    }
}
contract C is I {
    uint128 public ethLocked;
    function claim(WithdrawRequest calldata request) external {
        ethLocked -= uint128(request.amountOfEEth);
    }
}
"#;
        assert!(!fires(src), "uint128 cast of a uint96 struct field must be silent");
    }

    // (rule-b) SUBTRACTION/TERNARY bounded by a narrow field: a local
    // `remainder = a96 > b ? a96 - b : 0` is `<= a96` (a `uint96` field), so
    // `uint96(remainder)` cannot truncate. (etherfi PriorityWithdrawalQueue
    // ._claimWithdraw line 580.)
    #[test]
    fn silent_on_downcast_of_subtraction_bounded_by_narrow_field() {
        let src = r#"
pragma solidity ^0.8.20;
interface I { struct R { uint96 shareOfEEth; uint96 amountWithFee; } }
contract C is I {
    uint96 public totalRemainderShares;
    function claim(R calldata request, uint256 sharesToBurn) external {
        uint256 remainder = request.shareOfEEth > sharesToBurn
            ? request.shareOfEEth - sharesToBurn
            : 0;
        totalRemainderShares += uint96(remainder);
    }
}
"#;
        assert!(!fires(src), "downcast of (narrow-field - x) ternary must be silent");
    }

    // (rule-a via-local) a `uint256` local that only ever holds a narrow struct
    // field inherits the field's bound: `uint256 amt = request.amountWithFee;`
    // (a `uint96` field) then `uint96(amt)` is width-safe. (etherfi
    // PriorityWithdrawalQueue._claimWithdraw line 587.)
    #[test]
    fn silent_on_downcast_of_local_bound_to_narrow_field() {
        let src = r#"
pragma solidity ^0.8.20;
interface I { struct R { address user; uint96 amountWithFee; } }
contract C is I {
    event Claimed(address user, uint96 amount);
    function claim(R calldata request) external {
        uint256 amountToWithdraw = request.amountWithFee;
        emit Claimed(request.user, uint96(amountToWithdraw));
    }
}
"#;
        assert!(!fires(src), "downcast of a uint256 local that holds a uint96 field must be silent");
    }

    // (rule-b) MIN/MAX of `uintN`-typed operands: `uint40(_max(p, q))` with
    // `p`/`q` declared `uint40` cannot exceed `type(uint40).max`. (etherfi
    // MembershipManager._applyUnwrapPenalty line 718.)
    #[test]
    fn silent_on_downcast_of_max_of_narrow_operands() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    mapping(uint256 => uint40) public pts;
    function f(uint256 id, uint40 a, uint40 b) external {
        uint40 penalty = uint40(_max(a, b));
        pts[id] = penalty;
    }
    function _max(uint256 x, uint256 y) internal pure returns (uint256) {
        return x > y ? x : y;
    }
}
"#;
        assert!(!fires(src), "downcast of max() of uint40 operands must be silent");
    }

    // DEDUPE: a function narrowing several values to the SAME `uintN` is a
    // single review item. Two `uint128(_p)` casts in one function => one finding.
    // (etherfi MembershipManager._incrementTierVaultV1 lines 548/549.)
    #[test]
    fn dedupes_same_width_downcasts_in_one_function() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    struct V { uint128 a; uint128 b; }
    V public v;
    function inc(uint256 p, uint256 q) external {
        v.a += uint128(p);
        v.b += uint128(q);
    }
}
"#;
        let n = run(src).iter().filter(|f| f.detector == "integer-issues").count();
        assert_eq!(n, 1, "two same-width downcasts in one function must dedupe to one finding");
    }

    // DEDUPE must NOT merge genuinely different target widths: a `uint128` and a
    // `uint64` truncation in the same function are two distinct review items.
    #[test]
    fn does_not_dedupe_different_width_downcasts() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint128 public big;
    uint64 public small;
    function f(uint256 p, uint256 q) external {
        big = uint128(p);
        small = uint64(q);
    }
}
"#;
        let n = run(src).iter().filter(|f| f.detector == "integer-issues").count();
        assert_eq!(n, 2, "distinct-width downcasts must each be reported");
    }

    // STRUCT PARSING: a field with a trailing `//` comment must still be picked
    // up — the comment must not bleed into the *next* field's type token (the
    // exact etherfi shape that initially leaked: `totalVaultShares`, the SECOND
    // commented field, was missed). Casting that field to its own width is safe.
    #[test]
    fn silent_with_comment_annotated_struct_fields() {
        let src = r#"
pragma solidity ^0.8.20;
interface I {
    struct TierVault {
        uint128 totalPooledEEthShares; // total share of eEth in the tier vault
        uint128 totalVaultShares;      // total share of the tier vault
    }
}
contract C is I {
    uint128 public mirror;
    function read(TierVault calldata tv) external {
        // The *second* commented field, narrowed to its own width — width-safe
        // only if the comment did not corrupt parsing of `totalVaultShares`.
        mirror = uint128(tv.totalVaultShares);
    }
}
"#;
        assert!(!fires(src), "second comment-annotated struct field must parse and suppress");
    }

    // POSITIVE: the field-width provenance must not over-suppress. A downcast of
    // a value read from a WIDE field (`uint256`) still FIRES.
    #[test]
    fn fires_on_downcast_of_wide_struct_field() {
        let src = r#"
pragma solidity ^0.8.20;
interface I { struct R { uint256 bigValue; } }
contract C is I {
    uint64 public y;
    function f(R calldata r) external {
        y = uint64(r.bigValue);
    }
}
"#;
        assert!(fires(src), "downcast of a uint256 struct field must still fire");
    }

    // POSITIVE: `max()` of operands where ONE is wide is not bounded by the
    // narrow one — `uint40(_max(wide, narrow))` can exceed uint40, so it FIRES.
    #[test]
    fn fires_on_downcast_of_max_with_wide_operand() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    mapping(uint256 => uint40) public pts;
    function f(uint256 id, uint256 wide, uint40 narrow) external {
        pts[id] = uint40(_max(wide, narrow));
    }
    function _max(uint256 x, uint256 y) internal pure returns (uint256) {
        return x > y ? x : y;
    }
}
"#;
        assert!(fires(src), "max() with a wide operand must still fire");
    }
}
