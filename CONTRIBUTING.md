# Contributing to Sluice

Thanks for your interest. Sluice is a defensive security-research tool; please
use it only on code you are authorized to review.

## Building

```bash
cargo build --workspace
cargo test --workspace
```

Requires Rust 1.85+. No external tools — Solidity is parsed natively via
`solang-parser`.

## Adding a detector

Detectors are the main extension point. See
[docs/DETECTOR_AUTHORING.md](docs/DETECTOR_AUTHORING.md) for the full API. In
short:

1. Create `crates/sluice-engine/src/detectors/<name>.rs` with a unit struct
   implementing `Detector` (`id`, `category`, `description`, `run`).
2. Register it in `crates/sluice-engine/src/detectors/mod.rs` (`pub mod <name>;`
   and a `Box::new(...)` entry in `builtin_detectors()`).
3. Add a `#[cfg(test)]` module proving it fires on a vulnerable snippet and is
   silent on a safe one.
4. Add a fixture pair under `tests/fixtures/vuln/` and `tests/fixtures/safe/`
   and wire it into the corpus benchmark (`crates/sluice-engine/tests/corpus.rs`).

**Precision is the priority.** A detector that fires on safe code is worse than
one that misses an edge case. Always recognize the relevant mitigations
(OpenZeppelin `SafeERC20` / `ECDSA` / `ReentrancyGuard` / ERC-4626 virtual
shares / `_disableInitializers`, robust oracles, snapshots/timelocks) and
suppress accordingly. Lean on the corroboration scorer rather than inflating
confidence.

## Design principles

- **Three composed dimensions** (value-flow provenance, consensus invariants,
  trust frontiers) — a finding corroborated by more than one is scored higher.
- **Learn invariants from the code**, don't just match anti-patterns.
- **Frozen IR**: `sluice-ir` is the shared contract; keep it stable.

## Tests

`cargo test --workspace` must stay green, including the corpus benchmark. Run
`cargo test -p sluice-engine -- --nocapture` to see the precision/recall
scorecard.
