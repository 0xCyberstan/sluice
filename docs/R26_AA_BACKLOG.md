# R26 candidate backlog — ERC-4337 / EIP-7702 account abstraction

> Source: R25 WF3 research agent, verified against eth-infinitism/account-abstraction `develop`
> (EntryPoint/BaseAccount/BasePaymaster/IPaymaster), ERC-7562 (validation scope rules), EIP-7702.
> Build-ready seed for a future round. **No existing detector targets ERC-4337/EntryPoint/paymaster/
> validateUserOp — genuinely open surface.** Each new detector needs a `Category` variant + id + CWE
> in `crates/sluice-findings/src/finding.rs`.

## The load-bearing prerequisite
Every spec hinges on recognizing "is this an AA validation/postOp entry point?" Sluice has no AA IR, so build
ONE shared helper `is_aa_validation_fn` from: function name ∈ {validateUserOp, validatePaymasterUserOp, postOp},
param-shape (`(_, bytes32 userOpHash, uint256 missingAccountFunds)`; paymaster 2-tuple return; `PostOpMode` arg),
`Contract.inherits_like("baseaccount"|"basepaymaster"|"iaccount"|"ipaymaster")`, or transitive reachability from
such a fn. **Unit-test it on eth-infinitism `samples/` BEFORE wiring any detector.** Without the corpus, recall is
low (fires mostly where the fn is literally named `validateUserOp`). All predicates below are expressible from
existing `FunctionEffects` (reads_block_env/reads_tx_origin, storage_reads/writes+path, call_sites, guards,
has_write_after_external_call) + prelude helpers.

## Ranked specs

**R26-1 `ValidationPhaseEnvOpcode` (High, no corpus needed) — SHIP FIRST.** A `validate*` fn reads block-env /
non-deterministic state banned by ERC-7562 OP-011 (timestamp/number/blockhash/prevrandao/coinbase/gasprice/
tx.origin) or BALANCE/SELFBALANCE (OP-080, staked-only) → op passes off-chain sim at block N, flips at N+1 →
bundler invalidates the whole bundle / entity reputation-ban (mempool DoS over pooled funds). Trigger:
`is_aa_validation_fn` ∧ (`reads_block_env` ∨ `reads_tx_origin` ∨ block.coinbase/tx.gasprice member ∨
`Builtin::Blockhash` ∨ `.balance` read). Suppress: env value that is shifted/OR'd into the RETURNED
`validationData` (correct validUntil/validAfter → Info), staked-entity marker, interfaces/view helpers. Distinct
from `randomness`/`block-number-time` (those frame it as manipulation, not validation-phase mempool DoS). Anchor:
ERC-7562 OP-011/OP-080; `BaseAccount.validateUserOp`. VERIFY exact opcode list vs canonical ethereum/ERCs md.

**R26-2 `ValidationExternalStorageRead` (High, needs corpus).** `validate*` reads/writes storage that is NOT the
account's "associated storage" (ERC-7562 STO-01x/02x) — a bare scalar, a mapping not keyed by sender, or storage
via an external call → one other op mutating that shared slot invalidates all pending ops. Trigger:
`is_aa_validation_fn` ∧ a storage path not keyed by `msg.sender`/`userOp.sender`/`address(this)`, OR an external/
staticcall whose return flows into the validation decision (only EntryPoint calls allowed, OP-051..055). Suppress:
sender-keyed slots (associated), EntryPoint calls, staked marker. v1 = textual path-key heuristic; corpus-tune the
associated-vs-shared decision (needs dataflow for robustness). Anchor: STO-010/021/022, OP-041/051-055.

**R26-3 `ValidationUntrustedCallout` (High, no corpus needed).** `validate*` makes an external/low-level/delegate
call to a non-EntryPoint address during validation (EIP-1271 isValidSignature to a caller-supplied signer, oracle,
generic `target.call`) → un-simulatable + control transfer to attacker code inside validation. Trigger:
`is_aa_validation_fn` ∧ `first_call_where(is_external_transfer_of_control)` whose target doesn't root-resolve to the
EntryPoint handle and isn't a precompile; escalate if target root-resolves to a caller param (`root_is_param`).
Suppress: EntryPoint-handle calls, `Builtin::Ecrecover`/precompiles, internal/`address(this)` calls, staked marker.
Distinct from `preauth-callout-target` (needs isValidSignature + inverted-order guard) and `untrusted-call-target`
(no phase awareness). Anchor: ERC-7562 OP-041/061/051-055.

**R26-4 `MissingEntryPointGuard` (High, Critical if it drains; no corpus needed) — SHIP WITH R26-1.** A
validateUserOp/validatePaymasterUserOp/postOp (or a fn that `_payPrefund`s / reads `missingAccountFunds`) is missing
the `_requireFromEntryPoint`/`msg.sender==entryPoint` guard → anyone calls validation directly; `_payPrefund` sends
ETH to the direct caller, or a forged `postOp` mis-accounts against the paymaster's EntryPoint deposit. Trigger:
externally reachable ∧ (name ∈ {validateUserOp,validatePaymasterUserOp,postOp} ∨ reads `missingAccountFunds`/`maxCost`
∨ `payable(msg.sender).call{value:}`) ∧ no guard binding msg.sender to the EntryPoint and no `_requireFromEntryPoint`
internal-call/modifier. Suppress: `inherits_like(baseaccount|basepaymaster)` AND the fn is an `_validate*`/`_postOp`
internal override (public guard in base) — fire only when the public/external entry lacks the guard. Distinct from
`access-control` (its privileged-write heuristic + `is_privileged_name` don't model the EntryPoint-only invariant or
the `_payPrefund` drain). Anchor: `BaseAccount._requireFromEntryPoint()`, `_payPrefund` (verified, develop).

**R26-5 `PaymasterPostOpDepositAssumption` (Med-High, needs corpus).** A paymaster `postOp` writes finalized
accounting / makes an external call without branching on `PostOpMode` (opSucceeded/opReverted), or assumes its
EntryPoint deposit is unchanged — but postOp is pre-paid from deposit, called post-execution, can re-enter, and is
re-run on its own revert → unconditional credit/refund/allowance-decrement mis-accounts. Trigger: name==postOp w/
`PostOpMode` arg in a paymaster ∧ (accounting `storage_writes` ∨ external value call) ∧ body does NOT branch on
`mode`, OR `has_write_after_external_call` without a reentrancy guard. Suppress: mode-aware (If/ternary on mode),
`has_reentrancy_guard`, stub bodies. Distinct from generic reentrancy (doesn't model EntryPoint↔paymaster deposit /
PostOpMode obligation). Anchor: `IPaymaster.postOp(PostOpMode,...)`, `EntryPoint._postExecution`.

**R26-6 `CounterfactualInitFrontRun` (Med, needs corpus).** An account `initialize`/`init` sets owner/signer from a
param with no binding to the deploying authorization → for a counterfactual CREATE2 address anyone deploys it first
with their own owner; under EIP-7702 storage isn't cleared on (re)delegation so a stale init flag/owner persists.
Trigger: initializer (`GuardKind::Initializer` or name∈{initialize,init,__init}) in an account-shaped contract ∧
writes an owner/signer (`is_privileged_name`) from a param (`root_is_param`) ∧ no guard binds that param to
msg.sender/authorization. Suppress: owner from msg.sender; two-step/reinitializer guard + factory-only caller; 7702
sub-case Low until corpus-tuned. Distinct from `unprotected-initializer` (missing-guard) — here the guard exists but
the owner is caller-supplied + the 7702 persistence angle. Anchor: SimpleAccountFactory.createAccount →
SimpleAccount.initialize; EIP-7702 setup-calldata-must-be-signed + storage-not-cleared. VERIFY sample sig.

**R26-7 `Eip7702TxOriginAuth` (Med, no corpus; may be merged/dropped).** `tx.origin==msg.sender` (or
`.code.length==0`/extcodesize==0) used as an EOA check / sandwich-atomicity / reentrancy guard — EIP-7702 breaks it
(a delegated EOA has code, can make multiple calls/tx, can be tx.origin while running contract logic). Trigger:
`Binary{Eq|Ne}` of msg.sender vs tx.origin, or `.code.length`/extcodesize==0 in a gating guard. Suppress: alias op
present (defer to `conditional-sender-aliasing`); de-dup vs `access-control` TxOriginAuth (which is `tx.origin==owner`,
this is `tx.origin==msg.sender`). **If `access_control.rs` already catches `msg.sender==tx.origin`, DROP this and
extend that branch with a 7702 note.** Anchor: EIP-7702 Security Considerations.

## Honesty / dropped
- Biggest risk = the entry-point recognizer; build + unit-test it on `samples/` first.
- R26-2/R26-6 may be foldable into `untrusted-call-target`/`unprotected-initializer` with AA-aware gates — evaluate at build time. R26-7 may collapse into existing detectors.
- **Dropped:** standalone "missing nonce binding" (the `userOpHash` the account signs already encodes nonce+chainId+EntryPoint → collapses into the `signature`/`hash-gated-replay`/`cached-domain-separator` family); signature-aggregator trust + EntryPoint-internal deposit/stake desync (live in infra code, not user smart-account/paymaster code → ~0 recall on real targets).

## Corpus fetch (read-only, for tuning)
```
git clone --depth 1 https://github.com/eth-infinitism/account-abstraction   # core/{EntryPoint,BaseAccount,BasePaymaster,StakeManager,NonceManager}.sol; interfaces/{IAccount,IPaymaster,IEntryPoint}.sol; samples/{SimpleAccount,SimpleAccountFactory,*Paymaster}.sol  <-- recognizer + R26-5/6 tuning
git clone --depth 1 https://github.com/safe-global/safe-modules            # 4337 module + counterfactual init (R26-6)
git clone --depth 1 https://github.com/erc7579/erc7579-implementation      # modular accounts (broader entry shapes)
# Pin anchors: ERC-7562 (ethereum/ERCs ERCS/erc-7562.md) for OP-/STO- rule IDs; EIP-7702 Security Considerations.
```
Use to (1) calibrate `is_aa_validation_fn`, (2) set R26-2's associated-storage heuristic, (3) confirm each detector
fires on a real vulnerable shape with ~0 FP on the safe BaseAccount/BasePaymaster/SimpleAccount baselines (R7+ dogfood discipline).
