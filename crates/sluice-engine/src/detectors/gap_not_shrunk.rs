//! Storage gap not shrunk — a mutable state variable inserted *into* the region a
//! `__gap` reserves (mid-layout insertion), distinct from the sibling
//! [`StorageGap`](super::storage_gap) detector which flags an entirely **absent**
//! gap.
//!
//! ## The invariant
//!
//! Upgradeable contracts share one storage layout across the proxy and every
//! implementation in the inheritance chain, and slot order is *declaration*
//! order. The OpenZeppelin `uint256[N] private __gap;` convention reserves a
//! trailing block of empty slots so a future version can append state without
//! shifting the slots of any contract that sits *below* this one in the layout.
//! For that to hold, the `__gap` **must be the last storage member**: every real
//! variable lives at a slot *above* the gap, and growing the contract means
//! adding a variable and **shrinking the gap by the same number of slots** so the
//! contract's total slot footprint is unchanged.
//!
//! ## The bug this flags (structural mid-layout insertion)
//!
//! If a *mutable* state variable is declared **after** the `__gap` in declaration
//! order, the layout is broken in two equivalent ways:
//!
//! * the trailing variable now occupies a slot the previous version treated as
//!   reserved gap space — anything an inheriting contract (or a prior deployment)
//!   placed at that slot is silently aliased; and
//! * the gap can no longer be expanded for its intended purpose without colliding
//!   with the variable that follows it.
//!
//! This is the "gap not shrunk when state was appended" mistake: instead of
//! shrinking the `[N]` and keeping the gap last, a new variable was dropped in
//! below it. It is **single-snapshot detectable** (no version history needed) and
//! low-FP: a correctly written contract always keeps `__gap` as its final member,
//! so there is simply nothing after it to flag.
//!
//! ## What is *not* flagged (precision)
//!
//! * **The canonical safe shape** — `__gap` as the *last* state member. Nothing
//!   follows it, so it never trips.
//! * **Trailing `constant` / `immutable` declarations** — these live in contract
//!   *code*, not in a storage slot, so they do not shift the layout and a `__gap`
//!   followed only by constants/immutables is harmless.
//! * **Interfaces and libraries** — no instance storage layout, so a gap is
//!   meaningless for them.
//!
//! Heuristic strength: this is a structural fact read straight off the declared
//! storage layout, so confidence is held in the Medium band.

use crate::context::AnalysisContext;
use crate::detector::Detector;
// `report!` is the prelude's declarative FindingBuilder macro (defined in
// `super::prelude`); imported by name since the macro is re-exported at the crate
// root. This detector's reporting goes through it.
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::StateVar;

pub struct GapNotShrunkDetector;

impl Detector for GapNotShrunkDetector {
    fn id(&self) -> &'static str {
        "gap-not-shrunk"
    }
    fn category(&self) -> Category {
        Category::GapNotShrunk
    }
    fn description(&self) -> &'static str {
        "Mutable state variable declared after a storage `__gap` (mid-layout insertion; gap not shrunk)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for c in cx.scir.iter_contracts() {
            // Interfaces and libraries have no instance storage layout, so a
            // reserved gap is meaningless for them.
            if c.is_interface() || c.is_library() {
                continue;
            }

            // Find the FIRST OpenZeppelin-style `__gap` reservation in declaration
            // order. We require the array shape (`uintN[K]` / `bytesN[K]`) so we
            // match the reservation idiom rather than an unrelated variable that
            // merely contains "gap" in its name.
            let Some(gap_pos) = c.state_vars.iter().position(is_gap_reservation) else {
                continue;
            };
            let gap = &c.state_vars[gap_pos];

            // Any *mutable* (slot-consuming) state variable after the gap is a
            // mid-layout insertion. constant/immutable members live in code, not a
            // storage slot, so a gap trailed only by those is still safe.
            let Some(offender) = c.state_vars[gap_pos + 1..]
                .iter()
                .find(|v| !v.constant && !v.immutable)
            else {
                // Canonical safe shape: `__gap` is the last storage member (or only
                // constants/immutables follow it). Suppress.
                continue;
            };

            // Count how many mutable variables sit below the gap, for the message.
            let trailing = c.state_vars[gap_pos + 1..]
                .iter()
                .filter(|v| !v.constant && !v.immutable)
                .count();
            let extra = if trailing > 1 {
                format!(" (and {} other variable(s) below the gap)", trailing - 1)
            } else {
                String::new()
            };

            let b = report!(self, Category::GapNotShrunk,
                title = "Mutable state variable declared after a storage gap (mid-layout insertion)",
                severity = Severity::Medium,
                confidence = 0.6,
                dimensions = [Dimension::Invariant],
                message = format!(
                    "In `{}` the storage reservation `{} {}` is followed in declaration order by the \
                     mutable state variable `{}`{}. A `__gap` only protects the inheritance-chain storage \
                     layout when it is the LAST storage member: every real variable must sit at a slot \
                     ABOVE the gap, and growing the contract means SHRINKING the gap, not appending below \
                     it. Because `{}` is declared after the gap, it occupies a slot the gap was reserving \
                     — aliasing whatever an inheriting/previously-deployed layout placed there — and the \
                     gap can no longer be expanded without colliding with it. This is the \"gap not \
                     shrunk when state was appended\" storage-collision class (distinct from a missing \
                     gap).",
                    c.name, gap.ty, gap.name, offender.name, extra, offender.name
                ),
                recommendation =
                    "Keep the `__gap` as the final storage member: move the newly added variable(s) ABOVE \
                     the gap and reduce the gap's array size `[N]` by the number of slots they consume, so \
                     the contract's total slot footprint is unchanged (the OpenZeppelin upgradeable \
                     storage-gap convention).",
            );
            // Report at the offending variable's declaration — the precise
            // file:line of the mid-layout insertion.
            out.push(b.at(cx.scir, c.name.clone(), String::new(), offender.span).build());
        }

        out
    }
}

/// True if `v` is an OpenZeppelin-style storage-gap reservation: a name in the
/// `__gap` / `_gap` family declared as a fixed-size scalar array
/// (`uint256[50]`, `bytes32[10]`, ...). The array shape is required so an
/// unrelated variable that merely mentions "gap" (e.g. a `mapping(...) gap`) does
/// not anchor the layout check.
fn is_gap_reservation(v: &StateVar) -> bool {
    let name = v.name.to_ascii_lowercase();
    let named_gap = name == "__gap" || name == "_gap" || name.starts_with("__gap");
    if !named_gap {
        return false;
    }
    let ty = v.ty.trim_start();
    ty.contains('[')
        && ty.contains(']')
        && (ty.starts_with("uint") || ty.starts_with("int") || ty.starts_with("bytes"))
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    use sluice_findings::Severity;

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }
    fn hits(fs: &[sluice_findings::Finding]) -> Vec<&sluice_findings::Finding> {
        fs.iter().filter(|f| f.detector == "gap-not-shrunk").collect()
    }

    // VULN: a mutable variable (`newlyAdded`) was inserted BELOW the `__gap`
    // instead of shrinking the gap — the mid-layout-insertion storage collision.
    const VULN: &str = r#"
        pragma solidity ^0.8.20;
        abstract contract VaultStorage is Initializable {
            address public owner;
            uint256 public totalAssets;
            uint256[48] private __gap;
            // BUG: appended after the gap instead of shrinking [48] -> [47].
            uint256 public newlyAdded;
        }
    "#;

    // SAFE: identical state, but the gap is the LAST member (canonical OZ shape).
    const SAFE: &str = r#"
        pragma solidity ^0.8.20;
        abstract contract VaultStorage is Initializable {
            address public owner;
            uint256 public totalAssets;
            uint256 public newlyAdded;
            uint256[47] private __gap;
        }
    "#;

    // SAFE: a gap followed only by a `constant` / `immutable` — those live in
    // code, not a storage slot, so they do not shift the layout. Must NOT fire.
    const SAFE_TRAILING_CONST: &str = r#"
        pragma solidity ^0.8.20;
        abstract contract Base is Initializable {
            address public owner;
            uint256[49] private __gap;
            uint256 public constant VERSION = 2;
            address public immutable FACTORY;
            constructor(address f) { FACTORY = f; }
        }
    "#;

    #[test]
    fn fires_on_mid_layout_insertion() {
        let fs = run(VULN);
        let hs = hits(&fs);
        assert!(
            hs.iter().any(|f| f.severity == Severity::Medium),
            "expected a Medium gap-not-shrunk finding, got {hs:#?}"
        );
        // Reported at the offending variable, not the gap line.
        assert!(
            hs.iter().any(|f| f.message.contains("newlyAdded")),
            "finding should name the mid-layout-inserted variable: {hs:#?}"
        );
    }

    #[test]
    fn silent_on_canonical_gap_last() {
        let fs = run(SAFE);
        assert!(hits(&fs).is_empty(), "{:#?}", hits(&fs));
    }

    #[test]
    fn silent_on_trailing_constant_or_immutable() {
        let fs = run(SAFE_TRAILING_CONST);
        assert!(hits(&fs).is_empty(), "{:#?}", hits(&fs));
    }
}
