# Sluice

**Point it at a Solidity codebase; it hunts the complex, high-payout bug classes
that audits and bounties reward.**

Most smart-contract linters (Slither, Aderyn, Semgrep, Mythril) are very good at
*syntactic* anti-patterns — and they generate a lot of noise doing it. The bugs
that earn the biggest bounties and cause the biggest losses are not syntactic.
They are **economic and logic bugs**: a manipulable price feeding collateral
math (Cream, Harvest, bZx), one function missing the solvency check its siblings
enforce (Euler, $197M), a vault with no donation defense (ERC-4626 inflation),
read-only reentrancy through a `view` getter (Sentiment), a signed message with
no nonce, a bridge that trusts a zero root (Nomad, $190M).

Sluice goes after exactly those.

## How it's different

Sluice tracks **three orthogonal dimensions** and composes them, the way
[Vortex](https://github.com/) does for binaries:

1. **Value-flow provenance** — not boolean taint, but *where a value came from*:
   attacker input, an external-call return, a **manipulable spot price**
   (`balanceOf`, `getReserves`, `pricePerShare`), the block environment, or
   trusted storage. A detector can ask "does a *price-like* value reach this
   collateral calculation?" rather than merely "is it tainted?".

2. **Consensus invariants** — Sluice *learns* each contract's implicit invariants
   from the agreement among its sibling functions, then flags the outlier. If
   three of four value-moving functions call `_checkHealth()` and one doesn't,
   that one is the Euler bug. If writing `totalSupply` is almost always paired
   with writing `balances`, the function that desyncs them is accounting drift.
   This finds bugs that have no syntactic signature at all.

3. **Trust frontiers** — every external call is a boundary where control or value
   leaves the contract. Sluice classifies reentrancy (classic, cross-function,
   **read-only**), unchecked returns, and unsafe value flow at each crossing —
   and correctly *ignores* view reads (`balanceOf`) that cannot re-enter.

A finding corroborated by two or three dimensions is scored higher. This
**corroboration multiplier** is the core false-positive suppressor: lone-signal
noise sinks, and a finding that is simultaneously a value-flow problem, an
invariant violation, *and* a frontier crossing rises to Critical automatically.

Sluice also recognizes defensive patterns (OpenZeppelin `SafeERC20`, `ECDSA`,
`ReentrancyGuard`, ERC-4626 virtual shares, `_disableInitializers`) and suppresses
findings they neutralize, and it can emit a **Foundry proof-of-concept skeleton**
for each top finding to jump-start a bounty submission.

## Quick start

```bash
cargo build --release

# Scan a file or a whole repo:
target/release/sluice scan path/to/contracts

# Tune to a protocol class (sharpens detector selection + thresholds):
target/release/sluice scan path/to/contracts --profile lending

# Machine-readable output + Foundry PoCs for the top findings:
target/release/sluice scan src --format sarif --out sluice.sarif
target/release/sluice scan src --poc --format markdown --out report.md

# CI gate:
target/release/sluice scan src --fail-on high
```

Other commands: `sluice detectors`, `sluice profiles`, `sluice init`,
`sluice feedback <key> --tp|--fp`.

## Bug classes detected

Reentrancy (classic / cross-function / read-only), oracle & spot-price
manipulation, ERC-4626 first-depositor inflation, rounding/precision, missing
solvency/settlement checks (Euler class), access control & unprotected
initializers, `tx.origin` auth, signature replay / `ecrecover` zero-address /
missing deadline / malleability, controlled `delegatecall` & uninitialized
proxies, bridge verification gaps, unchecked returns & unsafe ERC-20,
fee-on-transfer accounting, slippage/deadline, denial-of-service (unbounded
loops, push-payment), weak randomness & timestamp dependence, reward-accounting
drift, forced-ether balance assumptions, integer/truncation issues, and more.
Run `sluice detectors` for the live list.

## Architecture

Sluice is a Rust workspace of ten single-responsibility crates. It parses
Solidity natively with `solang-parser` — **no external tools, no compiler, no
node** required.

| Crate | Purpose |
|-------|---------|
| `sluice-ir` | SCIR — typed IR with pre-classified calls, value-source labels, per-function effect summaries |
| `sluice-parse` | Native `solang-parser` → SCIR front-end (resilient per-file) |
| `sluice-dataflow` | Value-flow provenance (the entropy analog), interprocedural |
| `sluice-invariant` | Consensus-invariant mining (the ghost-state analog) |
| `sluice-frontier` | Trust-frontier / reentrancy analysis (the trust-boundary analog) |
| `sluice-engine` | Orchestration, the `Detector` trait, corroboration scoring, FP suppression |
| `sluice-verify` | Feasibility triage + Foundry PoC generation |
| `sluice-findings` | Finding model + Markdown / JSON / SARIF / HTML / console renderers |
| `sluice-config` | TOML config, protocol profiles, TP/FP feedback database |
| `sluice-cli` | The `sluice` binary |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Building

```bash
cargo build --release   # Rust 1.85+
cargo test --workspace
```

## License

MIT.

---

*Sluice is a defensive security-research tool for auditors and bug-bounty
hunters. Use it on code you are authorized to review.*
