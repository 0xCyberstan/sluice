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
use sluice_ir::{BinOp, CallKind, Expr, ExprKind, UnOp, ValueSource};

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

        // Per-contract set of `price`-like state-variable names that an external
        // setter can drive to an *unbounded* value (no upper-bound check, no
        // `min` clamp). These are the factors that turn a plain `price * amount`
        // product into a guaranteed-overflow revert-DoS — see section (4). Built
        // lazily and memoized per contract (the scan is O(contract functions), so
        // computing it once per contract instead of once per function matters on
        // large files). Loop-invariant ⇒ findings are unaffected by the caching.
        let mut unbounded_price_vars: std::collections::HashMap<
            sluice_ir::ContractId,
            std::collections::HashSet<String>,
        > = std::collections::HashMap::new();

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

                // SUPPRESSION (H) — BASIS-POINTS BOUNDED: names that a preceding
                // guard pins to `<= TOTAL_BASIS_POINTS` / `<= 10000` / `<= MAX_*BP`
                // (or a `_requireSane*`-style helper) so a downcast to `uint16`+ of a
                // basis-points value cannot truncate (10000 < 2^14). Built once per
                // function. See `basis_points_bounds`.
                let bp = basis_points_bounds(cx, f);

                // SUPPRESSION (I) — ACCESS-GATED CONFIG: the function is gated by an
                // access-control sender check (an `only*` / role modifier, a body
                // `_requireSender(...)`, or a `require(msg.sender == ...)` classified
                // as a `MsgSenderCheck`). A cast operand that is a *plain parameter*
                // of such a function is a privileged configuration value chosen by a
                // trusted role — not unbounded attacker input — so it is not a
                // realistic silent-truncation vector. Computed once per function.
                let access_gated = is_access_gated(cx, f);

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

                    // SUPPRESSION (H) — MSG.VALUE INTO A WIDE TARGET: native ETH is
                    // capped by the total supply (~1.2e26 wei < 2^96), so casting a
                    // `msg.value`-derived amount to a target of width >= 96 bits
                    // (`uint96`/`uint128`/`int104`/...) physically cannot truncate —
                    // the high bits dropped are always zero. We require BOTH a wide
                    // target (>= 96) AND `msg.value` provenance on the operand, so a
                    // genuine narrowing of a `msg.value`-derived value to `uint64`
                    // (or below) still fires. The dataflow propagates `MsgValue`
                    // through the wrapping `int256(...)` cast / arithmetic, so
                    // `int104(int256(msg.value))` and `uint128(msg.value)` are both
                    // caught. (Lido PredepositGuarantee._topUpNodeOperatorBalance,
                    // VaultHub.fund.)
                    if bits >= 96 {
                        let prov = cx.provenance_of(f.id, arg);
                        if prov.contains(ValueSource::MsgValue) {
                            return;
                        }
                    }

                    // SUPPRESSION (I) — BASIS-POINTS BOUNDED: a basis-points value
                    // (identifier matching `*BP`/`*Bps`/`*BasisPoints`/`bp`) that a
                    // preceding `require(x <= TOTAL_BASIS_POINTS/10000/MAX_*BP)` or a
                    // `_requireSane*` helper pins below ~10000 (< 2^14) cannot
                    // truncate to `uint16`+. We also treat such a value as bounded
                    // when the function is access-control gated: a basis-points
                    // parameter of a privileged setter is a trusted config value, not
                    // unbounded attacker input. (Lido VaultHub.updateConnection
                    // `uint16(_reserveRatioBP)`.)
                    if let ExprKind::Ident(name) = &arg.kind {
                        if is_basis_points_name(name)
                            && (bp.bounds_name(name) || bp.has_sane_guard || access_gated)
                        {
                            return;
                        }
                    }

                    // SUPPRESSION (J) — ACCESS-GATED CONFIG PARAM: a plain parameter
                    // cast inside an access-control-gated setter is a privileged
                    // configuration value chosen by a trusted role. When that param
                    // is additionally proven bounded by a `_requireSane*`-style guard
                    // we fully suppress (e.g. VaultHub.updateConnection
                    // `uint96(_shareLimit)`, bounded by `_requireSaneShareLimit`).
                    // Otherwise we *downgrade* (lower confidence / Low) rather than
                    // drop it — a privileged role is trusted, but an unguarded
                    // misconfiguration that silently truncates is still worth a
                    // review note. Plain params only: a value derived from
                    // `msg.value`/`msg.data` is handled by the rules above and must
                    // not be laundered through this trust assumption.
                    let mut downgrade = false;
                    if access_gated {
                        if let ExprKind::Ident(name) = &arg.kind {
                            if is_plain_param(f, name) {
                                if bp.bounds_name(name) || bp.has_sane_guard {
                                    return;
                                }
                                downgrade = true;
                            }
                        }
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
                    // A `downgrade`d finding (access-gated config param with no
                    // explicit bound) is reported at Low / reduced confidence — the
                    // privileged-role trust assumption makes it a review note, not a
                    // Medium attacker-truncation finding. Kept just above the default
                    // confidence floor (0.35) so it stays *visible* as a de-emphasized
                    // Low rather than being silently filtered out — a privileged
                    // misconfiguration that wraps is still a real (if lower-priority)
                    // hazard, so this is a downgrade, not a suppression.
                    let (sev, conf) =
                        if downgrade { (Severity::Low, 0.4) } else { (Severity::Medium, 0.5) };
                    let b = FindingBuilder::new(self.id(), Category::IntegerOverflow)
                        .title(format!("Narrowing downcast to `{ty}` silently truncates high bits"))
                        .severity(sev)
                        .confidence(conf)
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

            // ---- (4) guaranteed-overflow product of an unbounded settable price ----
            // On >=0.8 a plain `a * b` is *checked*, so it cannot silently wrap — but
            // it still REVERTS on overflow. That revert is itself the weapon when one
            // factor is a `price`-like storage variable a privileged setter can drive
            // to an arbitrary value with no upper bound: the owner sets `price =
            // type(uint256).max`, and from then on every `price * amount` product
            // reverts, permanently freezing whatever path performs it (challenge
            // resolution, a bid, a collateralization check). This is the Frankencoin
            // H-05 shape (`price * _collateralAmount` in `tryAvertChallenge`, and
            // `collateralReserve * atPrice` in `checkCollateral`): a guaranteed-overflow
            // griefing/DoS rather than a value-corruption wrap.
            //
            // It is deliberately *not* keyed on `is_attacker_controlled` of the
            // operands. The dangerous factor is a STORAGE `price` (provenance
            // StorageState, never attacker-tainted) and the multiply lives in an
            // access-gated (`onlyHub`) function whose params are not taint-seeded, so
            // the existing attacker-flow tests would never see it. The precise signal
            // is structural: a multiplication by a price-like state var that an
            // external setter can make unbounded, with no upper-bound guard before the
            // product. The unbounded-settable gate (computed in
            // `unbounded_settable_price_vars`) is what keeps this off ordinary bounded
            // `a * b` math — an oracle-read local or a capped/immutable price never
            // qualifies.
            if cx.scir.solidity_ge_0_8() {
                let names = unbounded_price_vars
                    .entry(f.contract)
                    .or_insert_with(|| unbounded_settable_price_vars(cx, f.contract));
                if !names.is_empty() {
                    // Names of price-like factors already guarded by an upper bound
                    // earlier in *this* function (`require(price <= cap)` / `if (price
                    // > cap) revert`). Such a product cannot reach the overflow, so we
                    // do not flag it. Computed once per function.
                    let capped_here = upper_bounded_names(f);
                    // One finding per (function, price-var): a function that multiplies
                    // the same unbounded price in several places is a single review item.
                    let mut reported: std::collections::HashSet<String> =
                        std::collections::HashSet::new();
                    for s in &f.body {
                        s.visit_exprs(&mut |e| {
                            let ExprKind::Binary { op: BinOp::Mul, lhs, rhs } = &e.kind else {
                                return;
                            };
                            // Identify which side (if any) is an unbounded price var,
                            // and require the *other* side to be a non-constant
                            // (user/protocol) amount — `price * 1e18` scaling by a
                            // literal is not the unbounded-amount product we mean.
                            let (price_name, other) =
                                match (price_factor(lhs, names), price_factor(rhs, names)) {
                                    (Some(n), _) => (n, rhs.as_ref()),
                                    (None, Some(n)) => (n, lhs.as_ref()),
                                    (None, None) => return,
                                };
                            if capped_here.contains(price_name) {
                                return;
                            }
                            if !is_unbounded_amount_factor(other) {
                                return;
                            }
                            if !reported.insert(price_name.to_string()) {
                                return;
                            }
                            let b = FindingBuilder::new(self.id(), Category::IntegerOverflow)
                                .title(
                                    "Multiplication by an unbounded settable price reverts on overflow (DoS)",
                                )
                                .severity(Severity::High)
                                // High structural confidence: the trigger requires a
                                // price-like state var that an external setter can make
                                // *unbounded* AND a product of it with a non-constant
                                // amount AND no upper-bound guard before the multiply —
                                // a narrow conjunction, not a bare `*`. Set high enough
                                // that the corroboration score (`70·(0.5+0.5·conf)`)
                                // clears the High label threshold, since H-05 is a
                                // genuine High-severity griefing DoS.
                                .confidence(0.9)
                                .dimension(Dimension::ValueFlow)
                                .message(format!(
                                    "`{}` computes a product with `{price_name}`, a price-like state variable \
                                     that a setter can drive to an arbitrary value with no upper bound. Under \
                                     Solidity >=0.8 the multiplication is checked, so a price near \
                                     `type(uint256).max` makes the product overflow and REVERT. An owner (or \
                                     whoever controls the setter) can therefore set the price so high that this \
                                     path always reverts — permanently bricking challenge resolution / bidding / \
                                     the collateralization check (a griefing DoS), not merely corrupting a value.",
                                    f.name
                                ))
                                .recommendation(
                                    "Bound the settable price (`require(newPrice <= MAX_PRICE)`), or compute the \
                                     product with a mul-div that cannot overflow for in-range collateral (e.g. \
                                     `Math.mulDiv` / scale the price down first), so a maliciously huge price \
                                     cannot turn the multiply into a guaranteed revert.",
                                );
                            out.push(cx.finish(b, f.id, e.span));
                        });
                    }
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

/// True if `name` reads as a basis-points quantity: a suffix of `BP`/`Bps`/
/// `BasisPoints` (case-insensitive), or the standalone token `bp`. Basis points
/// range 0..=10000 (< 2^14), so such a value — once bounded — trivially fits any
/// `uint16`+ target. Matched on the trailing token so `_reserveRatioBP`,
/// `feeBps`, `maxBasisPoints` all hit, while an unrelated `bridge` does not.
fn is_basis_points_name(name: &str) -> bool {
    let lc = name.to_ascii_lowercase();
    lc == "bp"
        || lc.ends_with("bp")
        || lc.ends_with("bps")
        || lc.ends_with("basispoints")
}

/// Names a function's guards prove are basis-points-bounded, plus whether a
/// `_requireSane*`-style helper guard is present at all.
struct BpBounds {
    /// Identifier names pinned `<= TOTAL_BASIS_POINTS` / `<= 10000` / `<= MAX_*BP`
    /// by a `require(...)` or `if (...) revert` in the function body.
    names: std::collections::HashSet<String>,
    /// A `_requireSane*` (or `_requireValid*BP`) helper is invoked. Such helpers
    /// validate a config value's range internally; we cannot see inside cheaply,
    /// so its presence licenses suppressing a basis-points downcast in the same
    /// function (precision is preserved by the `is_basis_points_name` gate).
    has_sane_guard: bool,
}

impl BpBounds {
    fn bounds_name(&self, name: &str) -> bool {
        self.names.contains(name)
    }
}

/// True if `e` is a basis-points upper bound: the constant `10000` (with or
/// without a `_` digit separator) or an identifier whose name signals a
/// basis-points cap (`TOTAL_BASIS_POINTS`, `MAX_*BP`, `*BASIS_POINTS`, ...).
fn is_bp_limit_expr(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Lit(sluice_ir::Lit::Number(n)) => n.replace('_', "").trim() == "10000",
        ExprKind::Ident(n) => {
            let lc = n.to_ascii_lowercase();
            lc.contains("basis_points")
                || lc.contains("basispoints")
                || (lc.contains("bp") && (lc.starts_with("max") || lc.starts_with("total")))
        }
        ExprKind::Member { member, .. } => {
            let lc = member.to_ascii_lowercase();
            lc.contains("basis_points") || lc.contains("basispoints")
        }
        _ => false,
    }
}

/// Collect the basis-points bounds a function establishes. We look for two
/// shapes, both of which prove the surviving (post-guard) value is `<= ~10000`:
///   * a `require(x <= BP_LIMIT)` / `require(x < BP_LIMIT)` (the comparison is the
///     truthy surviving condition), and
///   * an `if (x > BP_LIMIT) revert ...` / `if (x >= BP_LIMIT) revert ...` (the
///     revert prunes the over-limit path, so `x <= BP_LIMIT` survives).
/// where `BP_LIMIT` is `10000` or a basis-points cap identifier ([`is_bp_limit_expr`]).
/// Also records whether any `_requireSane*` / `_requireValid*` helper is called.
fn basis_points_bounds(cx: &AnalysisContext, f: &sluice_ir::Function) -> BpBounds {
    let mut names: std::collections::HashSet<String> = std::collections::HashSet::new();

    // (a) `require(...)` / `assert(...)` conditions: `x <= LIMIT` / `x < LIMIT`
    //     proves `x <= LIMIT` on the surviving path.
    fn collect_le(cond: &Expr, names: &mut std::collections::HashSet<String>) {
        match &cond.kind {
            ExprKind::Binary { op: BinOp::Le | BinOp::Lt, lhs, rhs } if is_bp_limit_expr(rhs) => {
                if let Some(n) = lhs.simple_name() {
                    names.insert(n.to_string());
                }
            }
            // `LIMIT >= x` / `LIMIT > x` — same proof, operands swapped.
            ExprKind::Binary { op: BinOp::Ge | BinOp::Gt, lhs, rhs } if is_bp_limit_expr(lhs) => {
                if let Some(n) = rhs.simple_name() {
                    names.insert(n.to_string());
                }
            }
            ExprKind::Binary { op: BinOp::And, lhs, rhs } => {
                collect_le(lhs, names);
                collect_le(rhs, names);
            }
            _ => {}
        }
    }
    // (b) `if (x > LIMIT) revert` / `if (x >= LIMIT) revert` — the revert prunes the
    //     over-limit branch, so `x <= LIMIT` holds afterwards. Only credit this when
    //     the then-branch is exclusively a revert/return (no fall-through).
    fn collect_if_revert(cond: &Expr, names: &mut std::collections::HashSet<String>) {
        match &cond.kind {
            ExprKind::Binary { op: BinOp::Gt | BinOp::Ge, lhs, rhs } if is_bp_limit_expr(rhs) => {
                if let Some(n) = lhs.simple_name() {
                    names.insert(n.to_string());
                }
            }
            ExprKind::Binary { op: BinOp::Lt | BinOp::Le, lhs, rhs } if is_bp_limit_expr(lhs) => {
                if let Some(n) = rhs.simple_name() {
                    names.insert(n.to_string());
                }
            }
            _ => {}
        }
    }

    let mut has_sane_guard = false;
    for s in &f.body {
        s.visit(&mut |st| {
            if let sluice_ir::StmtKind::If { cond, then_branch, else_branch } = &st.kind {
                if else_branch.is_empty() && branch_only_aborts(then_branch) {
                    collect_if_revert(cond, &mut names);
                }
            }
        });
        s.visit_exprs(&mut |e| {
            if let ExprKind::Call(c) = &e.kind {
                match c.kind {
                    CallKind::Builtin(sluice_ir::Builtin::Require)
                    | CallKind::Builtin(sluice_ir::Builtin::Assert) => {
                        if let Some(cond) = c.args.first() {
                            collect_le(cond, &mut names);
                        }
                    }
                    // `_requireSane*` / `_requireValid*` range-validation helpers.
                    CallKind::Internal => {
                        if let Some(fname) = c.func_name.as_deref() {
                            let lc = fname.to_ascii_lowercase();
                            if lc.starts_with("_requiresane")
                                || lc.starts_with("requiresane")
                                || (lc.contains("requirevalid") && lc.contains("bp"))
                            {
                                has_sane_guard = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        });
    }
    let _ = cx;
    BpBounds { names, has_sane_guard }
}

/// True when a statement list's sole effect is to abort (a `revert`, a bare
/// `return`, or a `return e`) — i.e. an `if (cond) { <abort> }` guard prunes the
/// `cond` branch so its negation survives. Mirrors the parser's leading-guard
/// recognition; kept local so this detector owns its own bounds reasoning.
fn branch_only_aborts(branch: &[sluice_ir::Stmt]) -> bool {
    if branch.is_empty() {
        return false;
    }
    branch.iter().all(|s| {
        matches!(
            &s.kind,
            sluice_ir::StmtKind::Revert { .. } | sluice_ir::StmtKind::Return(_)
        )
    })
}

/// True if the function is gated by an access-control sender check — the signal
/// that its parameters are privileged configuration values rather than unbounded
/// attacker input. Three independent signals, any of which suffices:
///   * an `only*` / role-style modifier (`onlyOwner`, `onlyRole(...)`,
///     `onlyGuarantorOf(...)`) — recognized by the parser as a `MsgSenderCheck`
///     guard, surfaced via `cx.has_access_control`;
///   * a body call to a `_requireSender(...)` / `_checkRole(...)`-style helper
///     (the comparison lives inside the helper, so the parser does not classify
///     the bare call as a `MsgSenderCheck` — we detect it textually here);
///   * a leading `require(msg.sender == ...)` (also `MsgSenderCheck`).
fn is_access_gated(cx: &AnalysisContext, f: &sluice_ir::Function) -> bool {
    if cx.has_access_control(f) {
        return true;
    }
    // `only*` modifier whose name signals access control (the parser classifies
    // the *invocation* as a MsgSenderCheck only when it can see the comparison;
    // a name-based fallback catches modifiers defined elsewhere).
    if f.modifiers.iter().any(|m| {
        let lc = m.name.to_ascii_lowercase();
        lc.starts_with("only") || lc.contains("auth") || lc.contains("restricted")
    }) {
        return true;
    }
    // Body call to a sender-check helper: `_requireSender(...)`, `_checkRole(...)`,
    // `_requireRole(...)`, `_authorizeSender(...)`, ...
    let mut gated = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if let ExprKind::Call(c) = &e.kind {
                if let Some(fname) = c.func_name.as_deref() {
                    let lc = fname.to_ascii_lowercase();
                    if lc.contains("requiresender")
                        || lc.contains("checkrole")
                        || lc.contains("requirerole")
                        || lc.contains("authorizesender")
                        || lc.contains("onlysender")
                    {
                        gated = true;
                    }
                }
            }
        });
    }
    gated
}

/// True if `name` is a *plain parameter* of `f` — a direct argument the caller
/// supplies, not a local or state variable. The access-gated-config suppression
/// only trusts plain params (a privileged setter's inputs); a derived local could
/// have been computed from an unmodeled source and is left to fire.
fn is_plain_param(f: &sluice_ir::Function, name: &str) -> bool {
    f.params.iter().any(|p| p.name.as_deref() == Some(name))
}

// --------------- section (4): unbounded settable price products ------------

/// True if `name` reads as a `price`-like quantity (a `price`, `*Price`,
/// `*price`, or a `*PerShare`/`liqPrice`-style rate). These are the storage
/// values whose product with a user amount can be turned into a guaranteed
/// overflow. Matched on the lowercased name so `price`, `liqPrice`,
/// `pricePerUnit`, `_collateralPrice` all hit while an unrelated `principal`
/// (which merely starts with `pri`) does not.
fn is_price_like_name(name: &str) -> bool {
    let lc = name.to_ascii_lowercase();
    lc == "price" || lc.ends_with("price") || lc.starts_with("price") || lc.contains("pershare")
}

/// The `price`-var name if `e` is a bare read of one of the contract's
/// unbounded-settable price-like state variables, else `None`. Deliberately
/// only a *bare identifier* (`price`), not a derived expression — a value that
/// has already been scaled/divided down is no longer the unbounded factor.
fn price_factor<'a>(
    e: &'a Expr,
    names: &std::collections::HashSet<String>,
) -> Option<&'a str> {
    match &e.kind {
        ExprKind::Ident(n) if names.contains(n) => Some(n),
        _ => None,
    }
}

/// True if `e` is a plausible *unbounded amount* factor — anything that is not a
/// compile-time constant. A `price * 1e18` decimal-scaling by a literal is not
/// the user-amount product we target (the literal cannot push the price-side
/// magnitude), so we require the co-factor to be non-constant: an identifier
/// (a collateral / size / amount), a member, an index, a call result, or an
/// arithmetic combination thereof. This keeps the finding to genuine
/// `price * collateral` shapes.
fn is_unbounded_amount_factor(e: &Expr) -> bool {
    !is_constant_expr(e)
}

/// Names that an upper-bound guard pins in *this* function: a `require(x <= n)` /
/// `require(x < n)` (the surviving comparison) or an `if (x > n) revert` /
/// `if (x >= n) revert` (the revert prunes the over-limit branch). A product
/// using such a name cannot reach the overflow, so it is not flagged. We record
/// the constrained name regardless of the limit's value (any upper bound on the
/// price defeats the `type(uint256).max` attack).
fn upper_bounded_names(f: &sluice_ir::Function) -> std::collections::HashSet<String> {
    let mut names: std::collections::HashSet<String> = std::collections::HashSet::new();

    // `x <= n` / `x < n` (and the swapped `n >= x` / `n > x`) prove an upper
    // bound on `x` when they are the surviving condition of a require/assert.
    fn collect_le(cond: &Expr, names: &mut std::collections::HashSet<String>) {
        match &cond.kind {
            ExprKind::Binary { op: BinOp::Le | BinOp::Lt, lhs, .. } => {
                if let Some(n) = lhs.simple_name() {
                    names.insert(n.to_string());
                }
            }
            ExprKind::Binary { op: BinOp::Ge | BinOp::Gt, rhs, .. } => {
                if let Some(n) = rhs.simple_name() {
                    names.insert(n.to_string());
                }
            }
            ExprKind::Binary { op: BinOp::And, lhs, rhs } => {
                collect_le(lhs, names);
                collect_le(rhs, names);
            }
            _ => {}
        }
    }
    // `if (x > n) revert` / `if (x >= n) revert` — the revert prunes the
    // over-limit path, so `x <= n` survives. Only credit a then-branch that is
    // exclusively an abort.
    fn collect_if_revert(cond: &Expr, names: &mut std::collections::HashSet<String>) {
        match &cond.kind {
            ExprKind::Binary { op: BinOp::Gt | BinOp::Ge, lhs, .. } => {
                if let Some(n) = lhs.simple_name() {
                    names.insert(n.to_string());
                }
            }
            ExprKind::Binary { op: BinOp::Lt | BinOp::Le, rhs, .. } => {
                if let Some(n) = rhs.simple_name() {
                    names.insert(n.to_string());
                }
            }
            _ => {}
        }
    }

    for s in &f.body {
        s.visit(&mut |st| {
            if let sluice_ir::StmtKind::If { cond, then_branch, else_branch } = &st.kind {
                if else_branch.is_empty() && branch_only_aborts(then_branch) {
                    collect_if_revert(cond, &mut names);
                }
            }
        });
        s.visit_exprs(&mut |e| {
            if let ExprKind::Call(c) = &e.kind {
                if matches!(
                    c.kind,
                    CallKind::Builtin(sluice_ir::Builtin::Require)
                        | CallKind::Builtin(sluice_ir::Builtin::Assert)
                ) {
                    if let Some(cond) = c.args.first() {
                        collect_le(cond, &mut names);
                    }
                }
            }
        });
    }
    names
}

/// Compute the contract's set of `price`-like state-variable names that an
/// externally-reachable setter can drive to an *unbounded* value. A name
/// qualifies when ALL hold:
///   * it is a `price`-like, numeric (`uintN`/`intN`), NON-`constant`,
///     NON-`immutable`, non-mapping state variable (an immutable/constant price
///     is fixed at construction, so it cannot be weaponized post-deploy);
///   * some externally-reachable function in the contract assigns it (`price =
///     <expr>` / `price += ...`) from a value that is NOT a compile-time
///     constant — i.e. a caller-chosen input rather than a hard-coded reset; and
///   * that setter does NOT clamp the new value: no `min(` in the assignment's
///     RHS and no upper-bound guard (`require(_p <= cap)` / `if (_p > cap)
///     revert`) on the assigned name or the price variable.
///
/// Conservative by construction: a price with any clamp/bound on its write, an
/// immutable/constant price, or a price only ever set to a constant is excluded,
/// so an oracle-read local or a capped configuration value never qualifies.
fn unbounded_settable_price_vars(
    cx: &AnalysisContext,
    cid: sluice_ir::ContractId,
) -> std::collections::HashSet<String> {
    let mut out: std::collections::HashSet<String> = std::collections::HashSet::new();
    let Some(contract) = cx.scir.contract(cid) else { return out };

    // Candidate price-like state vars: numeric, mutable (settable) storage.
    let candidates: Vec<&str> = contract
        .state_vars
        .iter()
        .filter(|v| {
            !v.constant
                && !v.immutable
                && !v.is_mapping()
                && is_price_like_name(&v.name)
                && {
                    let t = v.ty.trim();
                    t.starts_with("uint") || t.starts_with("int")
                }
        })
        .map(|v| v.name.as_str())
        .collect();
    if candidates.is_empty() {
        return out;
    }

    for f in cx.scir.functions_of(cid) {
        if !f.has_body || !f.is_externally_reachable() {
            continue;
        }
        // Names this setter pins with an upper bound (so a write under such a
        // guard is bounded, not weaponizable).
        let bounded = upper_bounded_names(f);
        for s in &f.body {
            s.visit_exprs(&mut |e| {
                let ExprKind::Assign { op, target, value } = &e.kind else { return };
                // Plain `=` or arithmetic-compound writes both let the caller pick
                // the resulting magnitude; bitwise compounds do not grow it.
                if matches!(
                    op,
                    sluice_ir::AssignOp::BitAnd
                        | sluice_ir::AssignOp::BitOr
                        | sluice_ir::AssignOp::BitXor
                        | sluice_ir::AssignOp::Shl
                        | sluice_ir::AssignOp::Shr
                ) {
                    return;
                }
                let ExprKind::Ident(var) = &target.kind else { return };
                if !candidates.contains(&var.as_str()) {
                    return;
                }
                // A write that only ever stores a compile-time constant cannot be
                // pushed to `type(uint256).max` by a caller.
                if is_constant_expr(value) {
                    return;
                }
                // A clamp in the RHS (`min(_p, CAP)`) or an upper-bound guard on the
                // price var (or the source identifier) means the stored value is
                // bounded — not weaponizable.
                let rhs_src = cx.source_text(value.span);
                if rhs_src.contains("min(") {
                    return;
                }
                if bounded.contains(var.as_str()) {
                    return;
                }
                if let Some(src_name) = value.simple_name() {
                    if bounded.contains(src_name) {
                        return;
                    }
                }
                out.insert(var.clone());
            });
        }
    }
    out
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

    // ------------------------------------------------------------------
    // R8 BOUNDED-CAST regressions: the residual Lido FP shapes.
    //   (H) `msg.value` cast to a wide (>= 96-bit) target — capped by ETH supply.
    //   (I) basis-points value pinned by a `<= 10000`/`*BP` guard, a `_requireSane*`
    //       helper, or an access-control gate.
    //   (J) plain config parameter of an access-control-gated setter.
    // Each must now stay SILENT, while the matching unbounded shape still FIRES.
    // ------------------------------------------------------------------

    // (H) `uint128(msg.value)` — native ETH (< 2^96) cast to a 128-bit target
    // cannot truncate. (Lido PredepositGuarantee._topUpNodeOperatorBalance:805.)
    #[test]
    fn silent_on_msg_value_to_wide_uint() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    mapping(address => uint128) public bal;
    function topUp() external payable {
        bal[msg.sender] += uint128(msg.value);
    }
}
"#;
        assert!(!fires(src), "uint128(msg.value) must be silent (ETH < 2^96)");
    }

    // (H) `int104(int256(msg.value))` — the wrapping `int256(...)` cast propagates
    // `msg.value` provenance; the 104-bit target still holds ETH. (Lido
    // VaultHub.fund:733.)
    #[test]
    fn silent_on_msg_value_via_int256_to_int104() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    function fund() external payable {
        _delta(int104(int256(msg.value)));
    }
    function _delta(int104 d) internal { d; }
}
"#;
        assert!(!fires(src), "int104(int256(msg.value)) must be silent (ETH < 2^96)");
    }

    // POSITIVE (H): the msg.value bound only holds for WIDE targets. A narrowing
    // of `msg.value` to `uint64` (< 96 bits) can genuinely truncate (a 100-ETH
    // value exceeds type(uint64).max wei), so it MUST still fire.
    #[test]
    fn fires_on_msg_value_to_narrow_uint() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint64 public packed;
    function topUp() external payable {
        packed = uint64(msg.value);
    }
}
"#;
        assert!(fires(src), "uint64(msg.value) must still fire (< 96-bit target truncates)");
    }

    // (I) ACCESS-GATED + BASIS-POINTS PARAM: a `*BP` parameter of an
    // access-control-gated setter is a trusted config value. (Lido
    // VaultHub.updateConnection `uint16(_reserveRatioBP)`:489, gated by
    // `_requireSender`.)
    #[test]
    fn silent_on_access_gated_basis_points_param() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint16 public reserveRatioBP;
    function updateConnection(uint256 _reserveRatioBP) external {
        _requireSender(msg.sender);
        reserveRatioBP = uint16(_reserveRatioBP);
    }
    function _requireSender(address s) internal view { if (msg.sender != s) revert(); }
}
"#;
        assert!(!fires(src), "access-gated basis-points param downcast must be silent");
    }

    // (I) BASIS-POINTS PARAM BOUNDED BY `<= 10000` REQUIRE: pinned below 2^14, so a
    // `uint16` downcast cannot truncate — even without access control.
    #[test]
    fn silent_on_require_bounded_basis_points() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint16 public feeBP;
    function setFee(uint256 feeBp) external {
        require(feeBp <= 10000, "too high");
        feeBP = uint16(feeBp);
    }
}
"#;
        assert!(!fires(src), "require(bp <= 10000) bounded downcast must be silent");
    }

    // (I) BASIS-POINTS PARAM BOUNDED BY `if (x > TOTAL_BASIS_POINTS) revert`: the
    // revert prunes the over-limit path, so `x <= TOTAL_BASIS_POINTS` survives.
    // (Lido-style `TOTAL_BASIS_POINTS` cap.)
    #[test]
    fn silent_on_if_revert_bounded_basis_points() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint256 internal constant TOTAL_BASIS_POINTS = 100_00;
    uint16 public rateBP;
    function setRate(uint256 rateBp) external {
        if (rateBp > TOTAL_BASIS_POINTS) revert();
        rateBP = uint16(rateBp);
    }
}
"#;
        assert!(!fires(src), "if (bp > TOTAL_BASIS_POINTS) revert bounded downcast must be silent");
    }

    // POSITIVE (I): a basis-points-NAMED param with NO bound and NO access control
    // is still attacker-supplied and unbounded — it MUST fire. (The name alone
    // does not license suppression.)
    #[test]
    fn fires_on_unbounded_unguarded_basis_points() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint16 public feeBP;
    function setFee(uint256 feeBp) external {
        feeBP = uint16(feeBp);
    }
}
"#;
        assert!(fires(src), "unbounded, unguarded basis-points downcast must still fire");
    }

    // (J) ACCESS-GATED CONFIG PARAM + SANE GUARD: a plain param of an
    // access-control-gated setter that is also range-validated by a
    // `_requireSane*` helper is fully suppressed. (Lido VaultHub.updateConnection
    // `uint96(_shareLimit)`:488, bounded by `_requireSaneShareLimit`.)
    #[test]
    fn silent_on_access_gated_sane_guarded_param() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint96 public shareLimit;
    function updateConnection(uint256 _shareLimit) external {
        _requireSender(msg.sender);
        _requireSaneShareLimit(_shareLimit);
        shareLimit = uint96(_shareLimit);
    }
    function _requireSender(address s) internal view { if (msg.sender != s) revert(); }
    function _requireSaneShareLimit(uint256 v) internal pure { v; }
}
"#;
        assert!(!fires(src), "access-gated, sane-guarded param downcast must be silent");
    }

    // (J) ACCESS-GATED CONFIG PARAM, NO EXPLICIT BOUND: downgraded (Low), NOT
    // dropped — a privileged role is trusted, but an unguarded misconfiguration
    // that silently truncates is still a review note. It must (a) not be Medium
    // and (b) not vanish entirely (it sits just above the confidence floor).
    //
    // NB: the gate here is a body `_requireSender(...)` *helper* call, not an
    // `onlyOwner` modifier / `require(msg.sender == ...)`. The latter is
    // recognized by the dataflow, which then seeds the function's params as
    // non-attacker (so they never reach this detector at all). A helper call is
    // NOT dataflow-recognized, so its params arrive as attacker input and it is
    // this detector's `is_access_gated` that must neutralize them — exactly the
    // Lido VaultHub shape this rule targets.
    #[test]
    fn downgrades_access_gated_unbounded_param() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint64 public window;
    function setWindow(uint256 _window) external {
        _requireSender(msg.sender);
        window = uint64(_window);
    }
    function _requireSender(address s) internal view { if (msg.sender != s) revert(); }
}
"#;
        let fs: Vec<_> = run(src)
            .into_iter()
            .filter(|f| f.detector == "integer-issues")
            .collect();
        assert_eq!(fs.len(), 1, "access-gated unbounded param must still be reported (downgraded)");
        assert_eq!(
            fs[0].severity,
            sluice_findings::Severity::Low,
            "access-gated unbounded config-param downcast must be downgraded to Low"
        );
    }

    // POSITIVE: a downcast inside an access-control-gated function whose operand is
    // NOT a plain param (here a sum of a param + storage, an unmodeled local) is
    // NOT laundered by the access gate — it still FIRES at Medium. The trust
    // assumption is limited to direct parameters.
    #[test]
    fn fires_on_access_gated_nonparam_downcast() {
        let src = r#"
pragma solidity ^0.8.20;
contract C {
    uint128 public acc;
    uint256 public base;
    function bump(uint256 amount) external {
        _requireSender(msg.sender);
        uint256 total = base + amount;
        acc = uint128(total);
    }
    function _requireSender(address s) internal view { if (msg.sender != s) revert(); }
}
"#;
        assert!(fires(src), "access-gated downcast of a non-param local must still fire");
    }

    // ------------------------------------------------------------------
    // (4) UNBOUNDED-SETTABLE-PRICE PRODUCT regressions (Frankencoin H-05).
    // A `price * amount` product where `price` is a state var an external setter
    // can drive to `type(uint256).max` is a guaranteed-overflow revert-DoS on
    // >=0.8. The trigger must fire on that shape (as High) and stay silent when
    // the price is immutable, capped, only-constant-set, or oracle-derived — and
    // when the co-factor is a constant scale.
    // ------------------------------------------------------------------

    // True if the unbounded-settable-price finding is present.
    fn fires_unbounded_price(src: &str) -> bool {
        run(src)
            .iter()
            .any(|f| f.detector == "integer-issues" && f.title.contains("unbounded settable price"))
    }

    // POSITIVE: the exact Frankencoin H-05 shape. `price` is owner-settable with
    // no upper bound (`adjustPrice`), and `tryAvertChallenge` computes `price *
    // _collateralAmount`. On >=0.8 the checked multiply reverts for a huge price,
    // so the owner can brick challenge resolution — a High-severity griefing DoS.
    #[test]
    fn fires_on_unbounded_price_times_collateral() {
        let src = r#"
pragma solidity ^0.8.0;
contract Position {
    uint256 public price;
    uint256 public minted;
    uint256 constant ONE_DEC18 = 1e18;
    function adjustPrice(uint256 newPrice) public {
        // owner setter, no upper bound on newPrice
        price = newPrice;
    }
    function tryAvertChallenge(uint256 _collateralAmount, uint256 _bidAmountZCHF) external returns (bool) {
        if (_bidAmountZCHF * ONE_DEC18 >= price * _collateralAmount) {
            return true;
        }
        return false;
    }
}
"#;
        let fs: Vec<_> = run(src)
            .into_iter()
            .filter(|f| f.detector == "integer-issues" && f.title.contains("unbounded settable price"))
            .collect();
        assert_eq!(fs.len(), 1, "must flag the price*collateral product exactly once: {:?}", fs);
        assert_eq!(
            fs[0].severity,
            sluice_findings::Severity::High,
            "unbounded-price product DoS must surface as High"
        );
    }

    // SAFE (bounded factor): the same product, but the setter caps the price with
    // a `require(newPrice <= MAX_PRICE)`. A bounded price cannot overflow the
    // multiply, so the finding must stay SILENT.
    #[test]
    fn silent_on_capped_price_times_collateral() {
        let src = r#"
pragma solidity ^0.8.0;
contract Position {
    uint256 public price;
    uint256 constant MAX_PRICE = 1e30;
    uint256 constant ONE_DEC18 = 1e18;
    function adjustPrice(uint256 newPrice) public {
        require(newPrice <= MAX_PRICE, "too high");
        price = newPrice;
    }
    function check(uint256 _collateralAmount, uint256 _bid) external returns (bool) {
        return _bid * ONE_DEC18 >= price * _collateralAmount;
    }
}
"#;
        assert!(!fires_unbounded_price(src), "capped (require <= MAX) price product must be silent");
    }

    // SAFE (immutable price): an `immutable` price is fixed at construction and
    // cannot be weaponized post-deploy, so the product is not a settable-DoS.
    #[test]
    fn silent_on_immutable_price_times_collateral() {
        let src = r#"
pragma solidity ^0.8.0;
contract Position {
    uint256 public immutable price;
    uint256 constant ONE_DEC18 = 1e18;
    constructor(uint256 p) { price = p; }
    function check(uint256 _collateralAmount, uint256 _bid) external returns (bool) {
        return _bid * ONE_DEC18 >= price * _collateralAmount;
    }
}
"#;
        assert!(!fires_unbounded_price(src), "immutable price product must be silent");
    }

    // SAFE (no settable price var): an oracle-read price held in a LOCAL (not a
    // mutable storage var with a setter) is the dogfood shape (Comet/Morpho/Aave).
    // There is no settable price state variable, so it must stay SILENT.
    #[test]
    fn silent_on_oracle_local_price_times_amount() {
        let src = r#"
pragma solidity ^0.8.0;
interface IOracle { function getPrice() external view returns (uint256); }
contract Vault {
    IOracle oracle;
    function value(uint256 amount) external view returns (uint256) {
        uint256 price = oracle.getPrice();
        return price * amount;
    }
}
"#;
        assert!(!fires_unbounded_price(src), "oracle-read local price product must be silent");
    }

    // SAFE (constant-only setter): a price var that is only ever reset to a
    // compile-time constant cannot be driven to type(uint256).max by a caller.
    #[test]
    fn silent_on_constant_only_settable_price() {
        let src = r#"
pragma solidity ^0.8.0;
contract C {
    uint256 public price;
    function reset() external { price = 1e18; }
    function value(uint256 amount) external view returns (uint256) {
        return price * amount;
    }
}
"#;
        assert!(!fires_unbounded_price(src), "price only ever set to a constant must be silent");
    }

    // SAFE (constant co-factor): `price * 1e18` is a decimal-scaling by a literal,
    // not a product with an unbounded user amount — the literal cannot push the
    // magnitude, and on its own this is ordinary scaling, so it must stay SILENT.
    #[test]
    fn silent_on_unbounded_price_times_constant_scale() {
        let src = r#"
pragma solidity ^0.8.0;
contract C {
    uint256 public price;
    function setPrice(uint256 p) external { price = p; }
    function scaled() external view returns (uint256) {
        return price * 1e18;
    }
}
"#;
        assert!(!fires_unbounded_price(src), "price * <constant> scaling must be silent");
    }

    // PRECISION: a non-price unbounded settable storage var multiplied by an
    // amount must NOT fire — the trigger is scoped to PRICE-like factors (the
    // distinguishing FP-control signal), not every settable storage multiplicand.
    #[test]
    fn silent_on_unbounded_nonprice_var_times_amount() {
        let src = r#"
pragma solidity ^0.8.0;
contract C {
    uint256 public multiplier;
    function setMultiplier(uint256 m) external { multiplier = m; }
    function value(uint256 amount) external view returns (uint256) {
        return multiplier * amount;
    }
}
"#;
        assert!(!fires_unbounded_price(src), "non-price settable factor must be silent (scoped to price)");
    }
}
