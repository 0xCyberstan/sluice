# R22 Design — Real, Compiling Foundry PoC Generation for Sluice

> Source: Round 21 WF3 capability-research agent (`wugsvg6wl`). Authoritative design
> for R22 implementation. No detector logic changes; all work is in `sluice-verify/`
> plus one small CLI wiring change. Sluice NEVER invokes `forge` (static-only, per
> `feedback_static_analysis_not_fuzzing` + `feedback_agent_concurrent_builds`); it
> *emits* artifacts a human runs.

## 1. Current state (the stub being replaced)

`crates/sluice-verify/src/lib.rs` (~160 lines) emits a **comment-only skeleton**:
keyed only on `finding.category` (6 hardcoded arms, rest → `// TODO`); `setUp()` is
`// TODO: deploy {contract}`; **no `import` of real source** (never resolves the file →
cannot compile); body is `vm.startPrank/stopPrank` around prose + `// TODO: assert profit`.
No assertions, no attacker contract, no mocks. Wired at `sluice-cli/src/main.rs:220`
`attach_pocs(&result.scir, &mut result.findings, 10)` under `--poc`, rendered verbatim
by `render.rs:95`. It threads nothing but `contract`/`function`/`category`/`pragma`.

## 2. Thread-in data is ALREADY in the IR (no new analysis)

`attach_pocs` already passes `Scir`. Per finding, recover `Function`/`Contract` and read:
target name/kind/bases; `Scir.pragma_solidity`; **`Contract.file` → `Scir.files[file].path/.content`
(the missing import target — we know the on-disk path)**; `Function.signature`/`.params`
(typed call, not `withdraw()`); visibility/mutability/`is_payable()`; constructor params
(via `functions_of` + `is_constructor()`); `Contract.state_vars` (balance mapping / token /
owner / immutables); `Finding.span/.line/.snippet`; `effects.call_sites` (kind/target/func_name/
sends_value — the arming call + value-bearing); `effects.storage_writes` + `has_write_after_external_call()`
(the drained var); `effects.guards`/`cx.has_access_control`; `reads_msg_sender/value`; `I*` param
types → which interfaces to mock; `Finding.trace`. The harder "which mapping is the balance /
which interface is the oracle" facts come from name heuristics that ALREADY exist in detectors
(`is_accounting_name`, `is_value_state_var`, `find_spot_price`, reentrancy `is_token_transfer_name`)
— lift them into a shared `sluice-verify` helper.

## 3. Three honest "compiles" tiers

- **T1 — Compiling exploit harness.** Don't compile the real protocol. Emit one `.t.sol`:
  imports `forge-std/Test.sol` + the target by **relative path from `Contract.file`**; declares
  minimal `interface` stubs for external deps (names/arity from `call_sites.func_name`) backed by
  `vm.mockCall`/`vm.etch`; deploys via `new Target(<typed placeholders>)`; real attacker contract +
  real assertion. "Compiles **given the target source resolves its own imports**." Ship a `sluice-poc/`
  skeleton (foundry.toml + remappings + README) so the user drops it in and runs `forge test`.
- **T2 — Compiling skeleton + asserted hypothesis.** Same, but statically-unknown values
  (ctor args, pool address, oracle decimals) become `/* FILL: ... */` valid-literal constants.
  Compiles as-is and contains a real `assertLt/assertGt/expectRevert` encoding the exploit.
- **T3 — Trace-annotated stub.** Long tail / non-concrete targets: upgrade today's stub with the
  real signature + real `trace` steps as `// step N:` comments + honest TODOs. Not claimed to compile.

Record tier in `tags` (`poc:tier1|tier2|tier3`) + a header banner so a bounty submitter never
over-claims a skeleton as a green test.

## 4. First families (highest payout × most mechanical)

1. **Reentrancy** (`Reentrancy`/`ReadOnlyReentrancy`/`Erc777Reentrancy`/`MintCallbackReentrancy`) — FIRST.
   IR pins the external call site + post-call written var + `sends_value`. One fixed attacker-contract
   skeleton + 3 hook variants (`receive` / `onERC721Received`+`onERC1155Received` / `tokensReceived`)
   covers all 4 categories. Highest credibility.
2. **Access control** (`AccessControl`/`UnprotectedInitializer`/`TxOriginAuth`) — SECOND. Most mechanical:
   usually no attacker contract / no mocks. prank an unprivileged addr → call `f(typed args)` → assert the
   detector-flagged privileged var changed / `expectRevert` *didn't* fire. Near-zero unknowns.
3. **ERC4626 inflation / first-depositor** (`Erc4626Inflation`/`FirstDepositor`/`OracleFirstMintSeeding`) —
   THIRD. Famous fixed 4-step donation script + `shares == 0` assertion; needs a canned `MockERC20`
   (shipped), vault surface standardized.

Defer **oracle/price-manipulation** + **bridge-verification** to a second wave as **T2-only**
(pool address/decimals/flash-loan provider or message struct unknowable statically → `vm.mockCall`
on the exact `{spot_method}` from `find_spot_price` + asserted hypothesis the user completes).

## 5. Template skeletons

(Full emitted-Solidity skeletons for all 4 families are in the WF3 output —
`/tmp/claude-1000/.../tasks/wugsvg6wl.output`, sections 6.1–6.4. Reentrancy: attacker contract with
re-entry hook + `assertGt(attacker.balance)` / `assertLt(vault.balance)`. Access control: `vm.prank(attacker)`
+ call + assert privileged var. ERC4626: first-depositor 1-wei → donate → victim `assertEq(victimShares, 0)`.
Oracle: `vm.mockCall` spot skew + asserted over-valuation hypothesis.)

## 6. Implementation steps (all in `sluice-verify/` + 1 CLI change)

- **6.1 Thread real IDs.** Add `#[serde(skip)] contract_id`/`function_id` to `Finding` (populated by
  `cx.finish`/`FindingBuilder::at`, which already know `fid`/`Span`), or a side-map from `attach_pocs`.
  Replaces brittle name-string re-lookup.
- **6.2 `PocContext` assembler** (`sluice-verify/src/context.rs`): `poc_context(scir, finding) -> PocContext`
  resolving Contract+Function, relative import path, ctor params, balance/asset/owner vars (lifted heuristics),
  arming call site + post-call written var, flagged privileged var, and a typed `ty -> literal` placeholder map
  (`uint256`→`1`, `address`→`makeAddr("x")`/`address(0)`, `bool`→`false`, `bytes`→`""`, `I*`→mock handle).
- **6.3 Per-family template modules** (`templates/{reentrancy,access_control,erc4626,oracle,bridge,stub}.rs`)
  behind `trait PocTemplate { fn applies(cat)->bool; fn tier(&PocContext)->Tier; fn render(&PocContext)->String; }`.
  `generate_poc` dispatches by category, falls back to upgraded T3 stub when no first-class template applies or
  `!Contract.is_concrete()`.
- **6.4 Upgrade T3 stub** to inject `Function.signature`, typed call args, and `trace` steps as comments.
- **6.5 Emit a foundry skeleton** `emit_poc_project(scir, findings, out_dir)` → `sluice-poc/{foundry.toml,
  remappings.txt, README.md, test/F-XXX_*.t.sol}`. README states each PoC's tier + `forge install forge-std`
  + how to point remappings at the target repo. Keep `generate_poc` returning the inline string for `render.rs:95`.
- **6.6 CLI**: keep `--poc` (inline top-10); add `--poc-out <dir>` (skeleton project) + `--poc-top N` (default 5
  for T1/T2). Tag tier per finding for SARIF/JSON/HTML filtering.
- **6.7 Tier gating in `attach_pocs`**: top-N by severity_score; category ∈ first-class ∧ `is_concrete()` ∧
  buildable PocContext → T1/T2; else T3.
- **6.8 Tests** (`sluice-verify/tests/`): per template, fixture Solidity → engine → `generate_poc` → assert
  output contains real signature/var names + a real assertion + is byte-stable (snapshot). Optional `#[ignore]`
  gated integration test: when `forge` is on PATH, drop fixture + T1 PoC into a temp project, assert `forge test`
  goes red→green — opt-in so CI never depends on forge (respects no-build-orchestration).
- **6.9 Honesty banner** on every emitted PoC.

## 7. Honest limits (state in the emitted README)

We never run `forge` (static-only) — "compiles" = harness valid given the target resolves its imports.
Constructor/external-wiring unknowns are the dominant reason a family is T2 not T1. Non-concrete targets
(interface/library) + non-first-class categories stay T3 — no false promise. One template covers a family,
not a finding — the hypothesis is asserted, but protocol-specific profit magnitude (oracle over-borrow, bridge
message struct) needs the user's final `assert`. That is the realistic static ceiling, and still a massive
upgrade over comment-only stubs.

## 8. Files

- Rewrite/extend: `crates/sluice-verify/src/lib.rs`
- `Finding` (add `contract_id`/`function_id`): `crates/sluice-findings/src/finding.rs`
- Builder (`trace_step`, `at`): `crates/sluice-findings/src/builder.rs`
- IR thread-in: `crates/sluice-ir/src/{func.rs,contract.rs,module.rs}`
- Detector context API: `crates/sluice-engine/src/context.rs`
- Render (inline block): `crates/sluice-findings/src/render.rs:95`
- CLI wiring (`attach_pocs(..., 10)`): `crates/sluice-cli/src/main.rs:219`
