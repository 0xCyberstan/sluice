//! Missing storage gap in an upgradeable base contract.
//!
//! Upgradeable contracts share one storage layout across the proxy and every
//! implementation in the inheritance chain. A base contract that declares state
//! but reserves no trailing `__gap` cannot grow without shifting the slots of
//! any child contract that sits *below* it in the layout — appending a variable
//! to the base silently overwrites the child's first variable on the next
//! upgrade (the OpenZeppelin `__gap` convention exists precisely to prevent
//! this). This detector flags an upgradeable-like contract that declares at
//! least one mutable state variable but contains no storage gap.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::Contract;

pub struct StorageGapDetector;

impl Detector for StorageGapDetector {
    fn id(&self) -> &'static str {
        "storage-gap"
    }
    fn category(&self) -> Category {
        Category::StorageGap
    }
    fn description(&self) -> &'static str {
        "Upgradeable base contract declares state but reserves no storage gap (__gap)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        // A storage gap only protects a contract that other contracts INHERIT
        // from — appending state to a leaf/final implementation corrupts nothing
        // downstream. Collect the set of names used as a base anywhere.
        let inherited: std::collections::HashSet<&str> = cx
            .scir
            .iter_contracts()
            .flat_map(|c| c.bases.iter().map(|b| b.as_str()))
            .collect();

        for c in cx.scir.iter_contracts() {
            // Libraries and interfaces have no instance storage layout, so a gap
            // is meaningless for them.
            if c.is_library() || c.is_interface() {
                continue;
            }
            // Only base contracts (inherited by another contract) need a gap.
            if !inherited.contains(c.name.as_str()) {
                continue;
            }
            if !is_upgradeable_like(cx, c) {
                continue;
            }
            // Need >=1 mutable state variable: constants/immutables live in code,
            // not storage, so they never participate in the upgradeable layout.
            let mutable_state: Vec<&str> = c
                .state_vars
                .iter()
                .filter(|v| !v.constant && !v.immutable)
                .map(|v| v.name.as_str())
                .collect();
            if mutable_state.is_empty() {
                continue;
            }
            // A storage gap closes the layout-corruption channel. Match the
            // OpenZeppelin idioms (`uint256[50] private __gap;`, `_gap`).
            let src = contract_source(cx, c).to_ascii_lowercase();
            if src.contains("__gap") || src.contains("_gap") {
                continue;
            }

            let b = FindingBuilder::new(self.id(), Category::StorageGap)
                .title("Upgradeable base contract has no storage gap")
                .severity(Severity::Low)
                .confidence(0.4)
                .dimension(Dimension::Invariant)
                .message(format!(
                    "`{}` is an upgradeable contract that declares mutable state (e.g. `{}`) but reserves no \
                     storage gap. Upgradeable contracts share a single storage layout across the inheritance \
                     chain; without a trailing `uint256[N] private __gap;`, appending a variable to this base \
                     in a future version shifts every slot below it and silently corrupts the storage of any \
                     child contract.",
                    c.name,
                    mutable_state[0]
                ))
                .recommendation(
                    "Reserve a storage gap in the base, e.g. `uint256[50] private __gap;`, and shrink it by the \
                     number of slots each newly added variable consumes (the OpenZeppelin upgradeable convention).",
                );
            // Contract-level finding: report at the contract span (no single
            // function is responsible). Mirrors `upgradeable.rs`'s contract-level
            // emit by building the location directly from `Scir`.
            out.push(b.at(cx.scir, c.name.clone(), String::new(), c.span).build());
        }
        out
    }
}

/// An upgradeable-like contract: inherits an `Initializable` / `*Upgradeable` /
/// UUPS mixin, or defines an `initialize`-style entry point (many projects
/// inline the pattern without an OZ base). Mirrors the upgradeable detection in
/// `upgradeable.rs`.
fn is_upgradeable_like(cx: &AnalysisContext, c: &Contract) -> bool {
    if c.inherits_like("initializable")
        || c.inherits_like("uupsupgradeable")
        || c.inherits_like("upgradeable")
    {
        return true;
    }
    cx.scir
        .functions_of(c.id)
        .any(|f| cx.is_initializer(f) || f.name.to_ascii_lowercase().contains("initialize"))
}

fn contract_source<'a>(cx: &'a AnalysisContext, c: &Contract) -> &'a str {
    cx.scir.span_text(c.span)
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Upgradeable (Initializable + initialize), mutable state, NO __gap → fires.
    // `VaultBase` is an upgradeable BASE (inherited by `VaultV1`) that declares
    // state but reserves no gap — appending state to it would corrupt the child.
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        contract VaultBase is Initializable {
            address public owner;
            uint256 public totalAssets;
            function initialize(address o) public initializer {
                owner = o;
            }
            function deposit(uint256 amt) external {
                totalAssets += amt;
            }
        }
        contract VaultV1 is VaultBase {
            uint256 public extra;
        }
    "#;

    // Same shape but the base reserves the OpenZeppelin storage gap → suppressed.
    const SAFE: &str = r#"
        pragma solidity ^0.8.20;
        contract VaultBase is Initializable {
            address public owner;
            uint256 public totalAssets;
            function initialize(address o) public initializer {
                owner = o;
            }
            function deposit(uint256 amt) external {
                totalAssets += amt;
            }
            uint256[50] private __gap;
        }
        contract VaultV1 is VaultBase {
            uint256 public extra;
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "storage-gap"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "storage-gap"));
    }
}
