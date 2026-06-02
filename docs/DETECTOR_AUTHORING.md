# Writing a Sluice detector

A detector is a stateless type implementing `sluice_engine::Detector`, living in
its own file under `crates/sluice-engine/src/detectors/`. It receives an
`AnalysisContext` (the IR + the three analysis dimensions) and returns
`Vec<Finding>`.

## The trait

```rust
pub trait Detector: Sync + Send {
    fn id(&self) -> &'static str;          // stable id, e.g. "slippage"
    fn category(&self) -> Category;         // primary Category
    fn description(&self) -> &'static str;  // one line, shown by `sluice detectors`
    fn run(&self, cx: &AnalysisContext) -> Vec<Finding>;
}
```

## `AnalysisContext` (what you get)

Fields: `cx.scir` (the `Scir` module), `cx.dataflow`, `cx.invariants`,
`cx.frontier`, `cx.config`.

Helpers:
- `cx.functions()` — iterator over every `&Function`.
- `cx.entry_points()` — externally-reachable, state-mutating functions with a body.
- `cx.contract_of(fid) -> Option<&Contract>`.
- `cx.names(fid) -> (String, String)` — (contract, function) names.
- `cx.finish(builder, fid, span) -> Finding` — resolve location and build.
- Value-flow: `cx.provenance_of(fid, &expr)`, `cx.is_attacker_controlled(fid, &expr)`, `cx.is_price_like(fid, &expr)`.
- FP suppression: `cx.has_reentrancy_guard(f)`, `cx.has_access_control(f)`,
  `cx.is_initializer(f)`, `cx.uses_safe_erc20(cid)`, `cx.contract_inherits(cid, "needle")`,
  `cx.uses_robust_oracle(f)`.

## `FindingBuilder` (how you report)

```rust
use sluice_findings::{Category, Dimension, FindingBuilder, Severity};

let b = FindingBuilder::new(self.id(), Category::Slippage)
    .title("Swap with no minimum-output bound")
    .severity(Severity::Medium)            // base severity; engine rescales by corroboration
    .confidence(0.6)                        // 0..1; below cx.config.min_confidence is dropped
    .dimension(Dimension::ValueFlow)        // add the dimension(s) your evidence covers
    .message(format!("`{}` ...", f.name))
    .recommendation("Pass and enforce a user-supplied minOut.");
out.push(cx.finish(b, f.id, span));         // span = the relevant sluice_ir::Span
```

**Dimensions** are `Dimension::ValueFlow | Invariant | Frontier`. Add the ones
your evidence genuinely covers — the engine adds more automatically when other
passes independently implicate the same function, and multiplies the score by
the number of corroborating dimensions. Do **not** pad dimensions you can't
justify.

## IR you'll use (`sluice_ir`)

`Function` fields: `name`, `contract`, `kind`, `visibility`, `mutability`,
`params: Vec<Param>`, `returns`, `modifiers`, `body: Vec<Stmt>`, `span`,
`effects: FunctionEffects`. Methods: `is_externally_reachable()`,
`is_state_mutating()`, `is_view_or_pure()`, `is_payable()`, `is_constructor()`,
`has_modifier_like("onlyOwner")`.

`FunctionEffects`: `storage_reads`/`storage_writes: Vec<StorageAccess{var,path,order,span}>`,
`call_sites: Vec<CallSite>`, `internal_calls: Vec<String>`, `guards: Vec<Guard>`,
`reads_msg_sender`, `reads_msg_value`, `reads_tx_origin`, `reads_block_env`,
`has_loop`, `has_unbounded_loop`, `has_assembly`, `has_unchecked_math`.
Methods: `writes_var("x")`, `reads_var`, `written_vars() -> Vec<&str>`,
`first_external_call()`, `has_write_after_external_call()`.

`CallSite`: `kind: CallKind`, `target: String`, `func_name: Option<String>`,
`order: u32`, `span`, `return_checked: bool`, `sends_value: bool`, `forwards_gas: bool`.

`CallKind`: `Internal, External, LowLevelCall, DelegateCall, StaticCall, Send,
Transfer, New, TypeCast, Builtin(Builtin), Unknown`. Helpers
`is_external_transfer_of_control()`, `can_send_value()`.

`Builtin`: `Require, Assert, Revert, Keccak256, Ecrecover, AbiEncode,
AbiEncodePacked, AbiEncodeWithSelector, AbiEncodeWithSignature, AbiDecode,
Selfdestruct, Blockhash, Gasleft, ModMath, ArrayPushPop, ...`.

`Expr { span, kind: ExprKind }`. `ExprKind`: `Ident(String)`,
`Member{base, member}`, `Index{base, index}`, `Call(Call)`, `Lit(Lit)`,
`Unary{op,operand}`, `Binary{op,lhs,rhs}`, `Assign{op,target,value}`,
`Ternary{cond,then_e,else_e}`, `Tuple(Vec<Option<Expr>>)`, `TypeName(String)`,
`New(Box<Expr>)`, `ArrayLit(...)`, `Unsupported`. Use `expr.visit(&mut |e| ...)`,
`expr.simple_name()`. `Call`: `callee, receiver: Option<Box<Expr>>,
func_name: Option<String>, args: Vec<Expr>, value: Option<Box<Expr>>,
gas: Option<Box<Expr>>, kind: CallKind`.

`Stmt { span, kind: StmtKind }` with `stmt.visit(&mut f)` and
`stmt.visit_exprs(&mut f)`. To scan a function body for a pattern, iterate
`for s in &f.body { s.visit_exprs(&mut |e| { ... }); }`.

Source text for a span: `cx.scir.span_text(span)` (returns `&str`). Useful for
substring checks (e.g. does the function source mention `"nonce"`).

`Contract`: `name`, `kind`, `bases`, `state_vars: Vec<StateVar>`, `functions`,
`using_for`, `span`. Methods `inherits_like("erc4626")`,
`uses_library_like("safeerc20")`, `is_concrete()`, `is_interface()`.
`StateVar`: `name, ty, visibility, constant, immutable, span`,
`is_scalar_numeric()`, `is_mapping()`.

Dataflow extras: `sluice_dataflow::is_spot_price_call(&call) -> bool`,
`ProvenanceSet` with `.is_attacker_controlled()`, `.is_price_like()`,
`.is_externally_influenced()`, `.is_block_env()`, `.contains(ValueSource::X)`.

## Rules

- **Mirror the seed detectors** (`reentrancy.rs`, `access_control.rs`,
  `oracle.rs`, `unchecked_return.rs`, `accounting.rs`, `vault.rs`) for structure.
- **Suppress known-safe patterns** (SafeERC20, ECDSA, ReentrancyGuard, virtual
  shares, robust oracle, `_disableInitializers`). Precision matters more than recall.
- Keep `confidence` honest: 0.8 for a structural certainty, 0.5 for a heuristic.
- Register the detector in `detectors/mod.rs` `builtin_detectors()` (already done
  for the planned set).
- Add a `#[cfg(test)]` module proving the detector fires on a vulnerable snippet
  and is silent on a safe one.
