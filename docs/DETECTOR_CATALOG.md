# Sluice Detector Catalog

This catalog documents detectors registered in `builtin_detectors()`
(`crates/sluice-engine/src/detectors/mod.rs`). There are **124** registered
detectors as of R21; the table below documents the original core set, while the
full, always-current registry is enumerated by `sluice detectors`.
Each row is one detector. Categories, CWE/SWC references,
and the three analysis dimensions (`value-flow`, `invariant`, `frontier`) are
defined in `crates/sluice-findings/src/finding.rs`.

A detector's **id** is its `Detector::id()`. The **Category** column lists the
primary `Detector::category()` first, followed by any *additional* `Category`
values the detector can also emit (several detectors raise more than one class).
**CWE/SWC refs** are taken from `Category::references()` for the classes the
detector emits. Dimensions are the `Dimension`s the detector attaches; some are
attached conditionally (noted as "+X if …").

The corroboration scorer ranks a finding higher when more than one dimension
supports it (the `vortex`-inherited entropy × ghost-state × trust-boundary idea),
and the engine de-duplicates findings by `(category, contract, function, line)`.

## Detector table

| Detector id | Category | Bug class | Technique (1 sentence) | Dimensions | CWE/SWC refs | Key FP suppressions |
|---|---|---|---|---|---|---|
| `reentrancy` | Reentrancy (+ReadOnlyReentrancy) | Classic / cross-function / read-only reentrancy | Consumes `sluice-frontier`'s per-function reentrancy analysis (state written after an external call) and classifies each unguarded site as classic, cross-function, or read-only. | frontier; +value-flow if a call site sends ETH | SWC-107, CWE-841 | Skips sites the frontier marks `guarded`, or where `has_reentrancy_guard` finds a `nonReentrant`/lock modifier. |
| `access-control` | AccessControl (+TxOriginAuth) | Missing authorization, guard-consensus outliers, `tx.origin` auth | Flags `GuardConsensus{access-control}` invariant violations (siblings enforce a guard this function skips), entry points that write privileged state with no guard, and `tx.origin`-based authorization. | invariant (consensus + direct write); value-flow (tx.origin) | SWC-105, SWC-115, CWE-284 | Skips functions with access control, initializers, and constructors; privileged-write only fires on un-guarded entry points; tx.origin requires an actual guard referencing it. |
| `oracle-manipulation` | OracleManipulation | Spot-price oracle manipulation (Cream/Harvest/bZx) | Finds the first spot-price read (`balanceOf`/`getReserves`/`pricePerShare`) in an externally-reachable function and fires only when that price influences accounting or a valuation-named function. | value-flow + frontier | CWE-20, CWE-1339 | Suppressed when `uses_robust_oracle` (Chainlink/TWAP) holds; requires both a spot-price read *and* an accounting-write or valuation-flavored name. |
| `unchecked-return` | UncheckedReturn (+UnsafeErc20) | Ignored low-level call / send / ERC-20 transfer return | Iterates `sluice-frontier`'s unchecked-return call sites, splitting raw-ERC20 `transfer`/`transferFrom`/`approve` (UnsafeErc20) from generic low-level calls (UncheckedReturn). | frontier | SWC-104, CWE-252 | Token calls suppressed when `uses_safe_erc20` is true for the contract (SafeERC20 in scope). |
| `missing-solvency-check` | MissingSolvencyCheck (+RewardAccounting) | Skipped solvency/settlement check (Euler) and co-update / reward drift | Reads mined invariant violations: `SettlementBeforeMutation` (value-moving function skips the settlement routine its siblings call) and `CoUpdate` (paired accounting vars updated inconsistently). | invariant; +value-flow if the function moves value | (none mapped for these classes) | Confidence is scaled by the mined `consensus` strength; `GuardConsensus` violations are deferred to `access-control`. |
| `signature` | SignatureReplay (+EcrecoverZeroAddress, +MissingDeadline) | ecrecover→address(0), replay (nonce/chainId), missing deadline, malleability | On any function whose source mentions `ecrecover`, runs four textual presence checks (zero-address reject, `nonce`, `chainId`/domain separator, `deadline`/expiry) and emits one finding per missing protection. | value-flow | SWC-117, SWC-121, CWE-347 (replay/deadline); — | If OZ `ECDSA.recover` / an `ecdsa` library is in use, the zero-address branch is suppressed (ECDSA handles zero-addr + malleability); each sub-check only fires when its keyword is absent. |
| `upgradeable` | DelegatecallStorage (+UninitializedProxy) | Controlled delegatecall and uninitialized UUPS implementations | Flags `delegatecall` whose target is not a constant/immutable (Critical if the target is attacker-controlled), and upgradeable contracts whose constructor omits `_disableInitializers()`. | frontier (delegatecall); +value-flow if target tainted; invariant (uninitialized impl) | SWC-112, CWE-1108 | delegatecall to a constant/immutable/literal target is skipped; uninitialized-impl only fires on `Initializable`/UUPS-like contracts that have an initializer and no `_disableInitializers()`. |
| `vault` | Erc4626Inflation (+PrecisionLoss) | ERC-4626 first-depositor/donation share inflation and divide-before-multiply precision loss | On vault-like contracts, flags share-price derived from a donatable balance (`balanceOf(address(this))`/`totalAssets`) with no inflation defense, and `(a/b)*c` precision loss in share/asset math. | value-flow | CWE-682 | Suppressed by a virtual-shares / decimals-offset / dead-shares marker or OZ `ERC4626` inheritance; inflation finding requires both a donatable read *and* no mitigation. |
| `flashloan-governance` | FlashLoanGovernance | Flash-loan vote-buying (Beanstalk) | Flags governance-context functions that weight a decision on a *live* balance read (`balanceOf`/`getVotes`/stake-share) with no snapshot, and the in-call stake→act→withdraw "flash shape". | value-flow; +invariant if the flash shape is present | (none mapped) | Suppressed by snapshot/timelock markers (`getPastVotes`, `ERC20Votes`, `ERC20Snapshot`, `timelock`, checkpoints); historical `getPast*`/`balanceOfAt` reads are never flagged. |
| `bridge-verification` | BridgeVerification | Cross-chain message verification gaps (Nomad, Poly Network) | On bridge-like inbound handlers, flags (a) a root/proof store checked with no non-zero guard, (b) a low-level/delegate dispatch with attacker-derived target/selector, and (c) a cross-chain sender trusted without binding the source chain. | frontier; +value-flow if the dispatch target is tainted | CWE-345 | Runs only on bridge-named/-shaped contracts with message-handler names; suppressed by a non-zero root guard, a target allowlist, source-chain binding, or a guardian/validator signature set. |
| `slippage` | Slippage | MEV value-leak: unbounded `minOut` / no-op deadline | Inspects arguments of swap/LP-router calls in entry points and fires on a literal `0` minimum-output or a `block.timestamp`/`type(uint256).max` deadline. | value-flow; +value-flow if the call sends ETH | CWE-682 | Restricted to a fixed allowlist of swap/LP method names; only literal-`0` min-outs and literal no-op deadlines fire — computed bounds, params, and future deadlines are not literals and are ignored. |
| `denial-of-service` | DenialOfService (+UnboundedLoop) | Loop DoS: external call in a loop, attacker-growable loops | Walks loop bodies for an external transfer-of-control call (one reverting recipient bricks the batch) and for in-loop storage-array growth, plus the frontier's `has_unbounded_loop` flag. | frontier (call-in-loop); +value-flow if value sent; invariant (growth / unbounded) | SWC-128, CWE-400 | View/pure and non-reachable functions skipped; calls inside `try { }` are not descended into; pull-payment (`withdraw`/`claim` + credit) idioms suppress the in-loop-call finding. |
| `fee-on-transfer` | FeeOnTransfer | Deposit credits requested amount, not measured delta (FoT/rebasing) | Detects an entry point that pulls tokens via `transferFrom`/`safeTransferFrom` and then credits accounting using the *requested* amount identifier rather than a measured balance delta. | value-flow | SWC-104, CWE-252 | Suppressed when the body measures `balanceOf(address(this))` before/after (or names like `received`/`balanceBefore`), or when the contract handles only a fixed immutable standard token (WETH/DAI/wstETH). |
| `weak-randomness` | WeakRandomness (+TimestampDependence) | Predictable block-env randomness and exact-timestamp value gates | Flags selection/reward outcomes derived from `block.prevrandao`/`difficulty`/`blockhash`/`timestamp`/`number` (esp. `keccak256` over block env), and `block.timestamp` used in an `==`/`!=` value gate. | value-flow; +invariant if state-mutating / value-bearing | SWC-120, CWE-330; SWC-116 (timestamp) | Suppressed when a proper source is used (Chainlink VRF / `requestRandomness` / `fulfillRandomWords` / commit-reveal); ordering comparisons and `== 0`/deadline-sentinel operands are not flagged. |
| `forced-ether` | ForcedEther | Strict equality against a force-injectable / donatable balance | Walks the body for `==`/`!=` comparisons where an operand's text reads a live ETH (`address(this).balance`) or self token balance (`balanceOf(address(this))`). | value-flow + invariant | (none mapped) | Ordering comparisons (`>=`/`<=`/`>`/`<`) never flagged (they tolerate extra balance); a bare `== 0` / `!= 0` presence check is suppressed. |
| `selector-collision` | SelectorCollision | `abi.encodePacked` hash/selector collision | Resolves each `abi.encodePacked` argument's type and fires when two args are (or could be) dynamic-length, raising confidence when the packed bytes feed a `keccak256`/selector sink. | value-flow | SWC-112, CWE-1108 | Single-arg packs and all-fixed-width packs are ignored; pure-`Unknown` argument noise alone does not fire (needs a resolved dynamic arg). |
| `integer-issues` | IntegerOverflow (+UncheckedMath) | Residual >=0.8 integer hazards | On modern pragmas, flags `unchecked { }` math on attacker input, narrowing downcasts (`uintN(x)`, N<256) of attacker-controlled values, and division by a non-constant, un-guarded divisor. | value-flow | SWC-101, CWE-190 | SafeCast usage suppresses downcast/division findings for the function; constant operands are skipped; downcasts require attacker-controlled args; zero-checked divisors and constant divisors are suppressed; division only on `solidity_ge_0_8`. |
| `erc777-reentrancy` | Erc777Reentrancy | Hook-callback reentrancy on a "plain" transfer (dForce/Lendf.me) | Finds the earliest hook-bearing token op (`transfer`/`transferFrom`/`mint`/`send`/`safe*`) classified as an external call, and fires when a storage write follows it. | frontier + value-flow | SWC-107, CWE-841 | Suppressed by a reentrancy guard; suppressed when no storage write follows the token op (checks-effects-interactions already honored); overlaps `reentrancy` and is de-duplicated by location. |

## High-value detectors and the incidents they target

These detectors target specific multi-million-dollar exploit classes that
generic Solidity linters (Solhint, basic Slither rules) systematically miss,
because the bug is a *protocol-logic / state* defect rather than a syntactic
anti-pattern. Sluice scores them via cross-dimension corroboration and the mined
invariant/value-flow context rather than by pattern-matching a single token.

### `reentrancy` — The DAO, Curve/Vyper, and the read-only class

The classic case is **The DAO (2016, ~$60M)**: a withdrawal sent ETH via an
external call *before* zeroing the caller's balance, so the recipient's fallback
re-entered and drained the contract. Sluice does not grep for `.call` near a
storage write; it consumes `sluice-frontier`'s per-function reentrancy
analysis, which tracks *which* storage variables are written *after* the
external call and whether any entry point sharing that state is unguarded. That
lets it separate the three sub-classes a linter conflates: classic
(state-after-call in the same function), **cross-function** (a sibling that
shares the mutated state is the real re-entry target — the shape behind several
lending-pool drains), and **read-only reentrancy** (a `view` getter returns
mid-update state, the **Curve/Vyper-era** class that fooled integrators reading
`get_virtual_price()` during a callback). Generic linters either flag every
external-call-then-write as a false positive or miss the read-only and
cross-function variants entirely because no single function looks wrong.

### `oracle-manipulation` — Cream, Harvest, bZx

This targets the **flash-loan spot-price** class: **Harvest Finance (2020,
~$34M)**, **bZx**, and the **Cream Finance** oracle exploits, where collateral or
share value was read from an instantaneous on-chain source (`getReserves`,
`balanceOf`, `pricePerShare`) that an attacker moves within one transaction
using a flash loan, then mints/borrows/liquidates at a false valuation. Sluice
fires only when a *manipulable spot read* both exists and *flows into accounting*
(a write to a balance/collateral/price var, or a valuation-named function), and
it suppresses when a manipulation-resistant source (Chainlink with
staleness/deviation checks, or a TWAP) is detected. A generic linter has no
concept of "this price is manipulable within a block" versus "this is a robust
feed" — it sees a normal function call — so it cannot distinguish the
vulnerable spot read from a safe oracle integration.

### `missing-solvency-check` — Euler Finance

This is the **Euler Finance (2023, ~$197M)** class. Euler's `donateToReserves`
path skipped the health/solvency check (`checkLiquidity`) that its sibling
operations enforced, letting an attacker self-induce bad debt and then liquidate
their own under-water position for profit. The bug is invisible to a token-level
linter because *each individual function is well-formed* — the defect is that
**one value-moving function omits a settlement/solvency routine its siblings
consistently call**. Sluice mines that consensus across sibling functions
(`SettlementBeforeMutation`) and reports the outlier, scaling confidence by how
strongly the siblings agree. No syntactic rule can express "this function should
have called the same invariant check as its peers."

### `vault` — Yearn-style ERC-4626 first-depositor / donation inflation

This targets the **ERC-4626 first-depositor / share-inflation (donation)**
attack seen across early vault forks: the first depositor mints 1 wei of shares,
then *donates* assets directly to the vault to inflate the share price so every
subsequent depositor's deposit rounds down to **zero shares** and is effectively
stolen. Sluice flags vault-like contracts whose share price derives from a
*donatable* balance (`balanceOf(address(this))` / `totalAssets`) with no
virtual-shares / decimals-offset / dead-shares defense, and suppresses when OZ
ERC4626's virtual-offset mitigation is present. A generic linter sees a normal
`deposit`/`mint` and a normal division; it has no model of the rounding
direction or the donation channel, so it cannot see that an attacker controls
the share-price denominator.

### `flashloan-governance` — Beanstalk

This is the **Beanstalk (2022, ~$182M)** class: governance weight was measured
from a *live* token balance at execution time, so an attacker flash-borrowed the
governance token, used the inflated voting power to pass and execute a malicious
proposal, and repaid the loan — all atomically. Sluice flags governance-context
functions that read a live balance/`getVotes`/stake-share to weight a decision
**with no snapshot**, and additionally detects the in-call
stake→privileged-action→withdraw "flash shape." It suppresses when a snapshot
(ERC20Votes `getPastVotes`/`getPastTotalSupply`, ERC20Snapshot, checkpoints) or
a timelock is in use. Generic linters have no notion of "voting power must come
from a historical snapshot, not a live balance," so a live `getVotes(msg.sender)`
read looks entirely ordinary to them.

### `bridge-verification` — Nomad and Poly Network

Two of the largest hacks ever anchor this detector. **Nomad (2022, ~$190M)**: a
bad upgrade left the trusted-roots mapping treating the **zero root** as proven,
so *any* message whose computed root was zero verified — and the exploit was
trivially copyable by hundreds of addresses. **Poly Network (2021, ~$611M)**: a
relayed cross-chain message let the attacker choose the **call target and
selector** on the destination chain, so they called a privileged keeper-change
function. Sluice models exactly these shapes on bridge-like inbound handlers:
(a) a root/proof store checked with **no `!= bytes32(0)` guard** (Nomad), (b) a
low-level/delegate dispatch whose **target/selector is attacker-derived** (Poly,
Critical when the target itself is tainted), and (c) a cross-chain sender trusted
**without binding the source chain id**. It suppresses on a non-zero root guard,
a target allowlist, source-chain binding, or a guardian signature set. A generic
linter cannot reason about cross-chain trust at all — these read as ordinary
`mapping` lookups and `.call` dispatches.

### `signature` — Wintermute/Profanity-era ecrecover and replay bugs

This detector targets the EIP-712 / `ecrecover` failure family that underlies
many permit/meta-transaction and signature-gated exploits: `ecrecover` returning
**`address(0)`** on a malformed signature and that zero address matching an
uninitialized signer; **replay** because the signed digest omits a per-signer
**nonce**; **cross-chain/cross-contract replay** because the digest omits
**chainId / the EIP-712 domain separator**; and signatures that are **valid
forever** for lack of a **deadline**. Sluice emits one finding per missing
protection on any `ecrecover`-using function and suppresses the zero-address
branch when OZ `ECDSA.recover` (which reverts on bad sigs and handles
malleability) is in use. Generic linters at most warn "ecrecover used"; they do
not check whether the *signed payload* binds a nonce, a chainId, and a deadline,
which is where the actual replay/forgery money is lost.
