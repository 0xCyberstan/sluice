//! Index-registry pop-swap stale back-reference — a swap-and-pop array removal
//! that moves the **last** element into the vacated slot but leaves the moved
//! element's stored **id → index back-reference map** pointing at its *old*
//! (popped) position, so a later index lookup resolves to the wrong entry.
//!
//! ## The shape
//!
//! The canonical Solidity O(1) array removal is "swap the last element into the
//! hole, then pop the tail":
//!
//! ```solidity
//! uint256 idx = indexOf[id];                 // slot to vacate (read of the map)
//! arr[idx] = arr[arr.length - 1];            // move the LAST element into the hole
//! arr.pop();                                 // drop the now-duplicated tail
//! // BUG: indexOf[<moved element id>] is still its OLD index (arr.length), not `idx`
//! ```
//!
//! When the array's elements are *also* tracked by a separate `id → index`
//! mapping (an enumerable-set / operator-index / holder-index reverse map), the
//! moved element's entry in that map **must** be rewritten to its new slot in the
//! same block:
//!
//! ```solidity
//! address moved = arr[idx];
//! indexOf[moved] = idx;                      // <- the fix that this detector requires
//! ```
//!
//! If that rewrite is missing, the reverse map is stale: `indexOf[moved]` still
//! names the popped tail position. Anything that trusts the map — an
//! `arr[indexOf[moved]]` lookup, a "remove by id" that overwrites the wrong slot,
//! a historical-index accessor — now reads or clobbers the wrong element. In a
//! restaking/registry context (the EigenLayer `IndexRegistry` operator-index
//! swap-pop) that mis-points an *operator* index, corrupting the quorum's operator
//! list.
//!
//! ## What the detector matches (all required)
//!
//!   1. **A literal swap-pop** in one function body:
//!      * an assignment `arr[i] = arr[arr.length - 1]` — the target indexes a
//!        storage array `arr`, and the value indexes the **same** array `arr` at
//!        `arr.length - 1` (the move-last-into-hole); **and**
//!      * a `arr.pop()` on that same array elsewhere in the body (the tail drop).
//!   2. **A reverse `id → index` map exists** on the enclosing contract — a
//!      `mapping(... => <integer>)` state variable whose name reads as an
//!      index / position / slot back-reference (`*index*`, `*indices*`,
//!      `*position*`, `*slot*`, `idToIndex`, …).
//!   3. **The removal function reads that map** (`idxMap[...]` appears as an
//!      r-value — the lookup of the slot to vacate). This ties the map to *this*
//!      array's removal bookkeeping and is the hallmark of the pattern.
//!
//! ## SUPPRESS (the correct shape — EigenLayer `IndexRegistry.deregisterOperator`)
//!
//!   * **The moved element's map entry IS rewritten.** If the same function also
//!     *writes* the reverse map (`idxMap[...] = ...`, or hands the moved element +
//!     its new index to a helper that assigns it — the `_assignOperatorToIndex`
//!     indirection), the back-reference is maintained and nothing fires. This is
//!     exactly EigenLayer `IndexRegistry.deregisterOperator`, which moves the last
//!     operator into the removed slot via `_assignOperatorToIndex(lastOperatorId,
//!     …, operatorIndexToRemove)` — a write of `currentOperatorIndex[..][lastId]`.
//!   * **No reverse map at all.** A plain swap-pop on an array with no `id → index`
//!     map (the array is the sole source of truth, the index is caller-supplied —
//!     EigenLayer `StakeRegistry.removeStrategies`) has nothing to leave stale and
//!     is silent.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::report;
use sluice_findings::{Category, Dimension, Finding, Severity};
use sluice_ir::{BinOp, Builtin, CallKind, Contract, Expr, ExprKind, Function, Span};

use super::prelude::*;

pub struct IndexRegistryPopSwapStaleDetector;

/// A matched literal swap-pop on a storage array.
struct SwapPop {
    /// Root name of the array being swap-popped (`_strategyParams`, `arr`, …).
    array: String,
    /// Span of the swap assignment `arr[i] = arr[arr.length - 1]`.
    span: Span,
}

impl Detector for IndexRegistryPopSwapStaleDetector {
    fn id(&self) -> &'static str {
        "index-registry-pop-swap-stale"
    }
    fn category(&self) -> Category {
        Category::IndexRegistryPopSwapStale
    }
    fn description(&self) -> &'static str {
        "Swap-and-pop array removal moves the last element into the vacated slot but does not \
         rewrite the moved element's id->index back-reference map, leaving an index pointing at \
         the wrong (popped) entry (EigenLayer IndexRegistry operator-index swap-pop class)"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Resolve the enclosing contract; a pure interface declares no bodies.
            let Some(contract) = cx.contract_of(f.id) else { continue };
            if contract.is_interface() {
                continue;
            }

            // (1) A literal swap-pop on a storage array in this body.
            let Some(swap) = find_swap_pop(f) else { continue };

            // (2) The contract maintains a reverse id->index map (an enumerable-set /
            // operator-index back-reference). Collect the candidate map names.
            let idx_maps = reverse_index_maps(contract);
            if idx_maps.is_empty() {
                continue;
            }

            // (3) This removal function READS one of those maps (the lookup of the
            // slot to vacate) — the link between the map and this array's removal.
            // SUPPRESS if it also WRITES the map (the moved element's entry is
            // rewritten) — the correct `IndexRegistry.deregisterOperator` shape.
            let mut hit_map: Option<&str> = None;
            for m in &idx_maps {
                if index_map_is_read(f, m) && !index_map_is_written(cx, f, m) {
                    hit_map = Some(m.as_str());
                    break;
                }
            }
            let Some(map_name) = hit_map else { continue };

            let b = report!(self, Category::IndexRegistryPopSwapStale,
                title = "Swap-and-pop leaves a moved element's id->index back-reference map stale",
                severity = Severity::Medium,
                // Multi-anchor structural fingerprint: a literal `arr[i] =
                // arr[arr.length-1]; arr.pop()` swap-pop, a reverse id->index map on
                // the contract that this function *reads* (the slot lookup), and the
                // absence of any rewrite of that map for the moved element. The
                // write-of-the-map suppression makes the correct
                // `IndexRegistry.deregisterOperator` shape silent, and the "no map"
                // case makes a plain `StakeRegistry.removeStrategies` swap-pop silent.
                confidence = 0.55,
                dimensions = [Dimension::Invariant],
                message = format!(
                    "`{fname}` removes an element from `{arr}` with the swap-and-pop idiom \
                     (`{arr}[i] = {arr}[{arr}.length - 1]; {arr}.pop()`), moving the **last** \
                     element into the vacated slot. The contract also tracks element positions in \
                     the reverse `id -> index` map `{map}`, which this function reads to find the \
                     slot to vacate — but it never rewrites `{map}` for the element it just moved. \
                     The moved element's `{map}` entry therefore still names its **old** (popped) \
                     index, not its new slot, so any subsequent index lookup through `{map}` \
                     resolves to the wrong entry (or, on a later remove-by-id, overwrites the wrong \
                     slot). This is the index-registry swap-pop stale-back-reference class \
                     (EigenLayer `IndexRegistry` operator-index swap on deregister): the correct \
                     form updates the moved element's index in the same block \
                     (`currentOperatorIndex[..][lastOperatorId] = operatorIndexToRemove`).",
                    fname = f.name,
                    arr = swap.array,
                    map = map_name,
                ),
                recommendation = format!(
                    "After moving the last element into the vacated slot, rewrite its entry in \
                     `{map}` to the new index in the same block — e.g. `address moved = {arr}[i]; \
                     {map}[moved] = i;` (mirroring EigenLayer `IndexRegistry`'s \
                     `_assignOperatorToIndex(lastOperatorId, …, operatorIndexToRemove)`). \
                     Equivalently, delete the removed element's entry and re-point the moved \
                     element's, so no stored index ever names a popped position.",
                    arr = swap.array,
                    map = map_name,
                ),
            );
            out.push(finish_at(cx, b, f.id, swap.span));
        }

        out
    }
}

// --------------------------------------------------------------------- analysis

/// Find a literal swap-and-pop in `f`: an assignment `arr[i] = arr[arr.length-1]`
/// (move last element into the hole) **and** a `arr.pop()` on the same array.
/// Returns the array name + the span of the swap assignment.
fn find_swap_pop(f: &Function) -> Option<SwapPop> {
    // Arrays that get the "move last element into a slot" assignment, with the
    // assignment span.
    let mut moved_into: Vec<(String, Span)> = Vec::new();
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if let Some(arr) = swap_assign_array(e) {
                moved_into.push((arr, e.span));
            }
        });
    }
    if moved_into.is_empty() {
        return None;
    }

    // Arrays that are `.pop()`ed in this body.
    let mut popped: Vec<String> = Vec::new();
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if let Some(arr) = pop_array(e) {
                popped.push(arr);
            }
        });
    }

    // A swap-pop is a move-last-into-hole whose array is also popped.
    for (arr, span) in moved_into {
        if popped.contains(&arr) {
            return Some(SwapPop { array: arr, span });
        }
    }
    None
}

/// If `e` is `arr[i] = arr[arr.length - 1]` (a plain `=` assignment whose target
/// indexes array `arr` and whose value indexes the **same** array `arr` at
/// `arr.length - 1`), return the array's root name.
fn swap_assign_array(e: &Expr) -> Option<String> {
    let ExprKind::Assign { op: sluice_ir::AssignOp::Assign, target, value } = &e.kind else {
        return None;
    };
    // Target: `arr[i]` (an index into an array).
    let ExprKind::Index { base: tbase, index: Some(_) } = &target.kind else { return None };
    let tarr = root_ident_str(tbase)?;

    // Value: `arr[ <arr.length - 1> ]` — an index into the SAME array at the
    // last-element position.
    let ExprKind::Index { base: vbase, index: Some(vidx) } = &value.kind else { return None };
    let varr = root_ident_str(vbase)?;
    if tarr != varr {
        return None;
    }
    if !is_last_index(vidx, tarr) {
        return None;
    }
    Some(tarr.to_string())
}

/// Is `e` the last-element index of array `arr` — `arr.length - 1` (a `Sub`
/// whose lhs is `arr.length` and whose rhs is the literal `1`)?
fn is_last_index(e: &Expr, arr: &str) -> bool {
    let ExprKind::Binary { op: BinOp::Sub, lhs, rhs } = &e.kind else { return false };
    is_one(rhs) && is_length_of(lhs, arr)
}

/// Is `e` a `<arr>.length` member access whose array root is `arr`?
fn is_length_of(e: &Expr, arr: &str) -> bool {
    let ExprKind::Member { base, member } = &e.kind else { return false };
    member == "length" && root_ident_str(base) == Some(arr)
}

/// If `e` is a `arr.pop()` call (`ArrayPushPop` builtin named `pop`), return the
/// array's root name (the call receiver's root).
fn pop_array(e: &Expr) -> Option<String> {
    let ExprKind::Call(c) = &e.kind else { return None };
    if !matches!(c.kind, CallKind::Builtin(Builtin::ArrayPushPop)) {
        return None;
    }
    if c.func_name.as_deref() != Some("pop") {
        return None;
    }
    let recv = c.receiver.as_deref()?;
    Some(root_ident_str(recv)?.to_string())
}

/// State-variable names on `contract` that read as a reverse `id -> index`
/// back-reference map: a `mapping(... => <integer>)` whose name marks it as an
/// index / position / slot map. Names are returned with their original casing so
/// the read/write probes can match them against `root_ident_str` of an expression.
fn reverse_index_maps(contract: &Contract) -> Vec<String> {
    contract
        .state_vars
        .iter()
        .filter(|v| v.is_mapping() && mapping_value_is_integer(&v.ty) && name_is_index_map(&v.name))
        .map(|v| v.name.clone())
        .collect()
}

/// Does the (possibly nested) `mapping(...)` type bottom out in an integer value
/// type (`uintN` / `intN`)? We take the type string's final token after the last
/// `=>` and check it parses as an integer type. A nested
/// `mapping(uint8 => mapping(bytes32 => uint32))` ends in `uint32`.
fn mapping_value_is_integer(ty: &str) -> bool {
    // The value type is whatever follows the last `=>`, with trailing `)` /
    // visibility / name noise trimmed.
    let Some(after) = ty.rsplit("=>").next() else { return false };
    let val = after.trim().trim_matches(|c: char| c == ')' || c.is_whitespace());
    // Take the leading type token (e.g. `uint32` from `uint32 public foo`).
    let tok = val.split_whitespace().next().unwrap_or("").trim_end_matches(')');
    tok.starts_with("uint") || tok.starts_with("int")
}

/// Does `name` read as an index / position / slot back-reference map?
fn name_is_index_map(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    // `*index*`, `*indices*`, `*position*`, `*slot*`, or an explicit `idToIndex`.
    l.contains("index")
        || l.contains("indices")
        || l.contains("position")
        || (l.contains("slot") && !l.contains("eth"))
        || (l.contains("idto") && (l.contains("idx") || l.contains("pos")))
}

/// Does `f` reference the reverse map `map` at all — any indexed access
/// `map[...]` in the body (the slot lookup of the element being removed)? This is
/// the linkage anchor: it ties `map` to *this* array's removal logic. The call
/// site pairs it with `!index_map_is_written`, so a function that only *writes*
/// `map` (and reads it solely as the assignment lvalue) is still suppressed by the
/// write check; the read anchor on its own simply confirms `map` is in play here.
fn index_map_is_read(f: &Function, map: &str) -> bool {
    let mut read = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if read {
                return;
            }
            if let ExprKind::Index { base, index: Some(_) } = &e.kind {
                if root_ident_str(base) == Some(map) {
                    read = true;
                }
            }
        });
        if read {
            break;
        }
    }
    read
}

/// Does `f` **write** the reverse map `map` for a moved element — i.e. maintain
/// the back-reference? True if either:
///   * an assignment whose target roots at `map` (`map[...] = ...`,
///     `map[..][..] = ...`); or
///   * `f` calls an internal helper whose body assigns to `map` (the
///     `_assignOperatorToIndex` indirection that EigenLayer uses), passing along
///     the moved element — captured structurally by "a directly-called internal
///     callee writes `map`".
fn index_map_is_written(cx: &AnalysisContext, f: &Function, map: &str) -> bool {
    if body_writes_map(f, map) {
        return true;
    }
    // One level of internal-callee indirection: the helper that re-assigns the
    // moved element's index (EigenLayer `_assignOperatorToIndex`).
    for callee_id in &f.callees {
        let Some(callee) = cx.scir.function(*callee_id) else { continue };
        if callee.has_body && body_writes_map(callee, map) {
            return true;
        }
    }
    false
}

/// Does any assignment in `body` target the mapping `map` (`map[...] = ...`)?
/// Covers nested-index writes (`map[a][b] = ...`) and compound assigns.
fn body_writes_map(f: &Function, map: &str) -> bool {
    let mut wrote = false;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if wrote {
                return;
            }
            if let ExprKind::Assign { target, .. } = &e.kind {
                // The assignment target must be an index chain rooted at `map`
                // (`map[id]` / `map[q][id]`), not merely *mention* `map`.
                if matches!(&target.kind, ExprKind::Index { .. })
                    && root_ident_str(target) == Some(map)
                {
                    wrote = true;
                }
            }
        });
        if wrote {
            break;
        }
    }
    wrote
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::AnalysisContext;
    use crate::detector::Detector;
    use crate::Config;

    // Run ONLY this detector against `src`, building the analysis context directly
    // so the unit tests are independent of the shared `mod.rs` registry / sibling
    // detectors authored concurrently.
    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        let parsed = sluice_parse::parse_sources(vec![("t.sol".into(), src.into())]);
        let scir = parsed.scir;
        let dataflow = sluice_dataflow::DataflowFacts::analyze(&scir);
        let invariants = sluice_invariant::InvariantFacts::mine(&scir);
        let frontier = sluice_frontier::FrontierFacts::analyze(&scir);
        let cfg = Config::default();
        let cx = AnalysisContext::new(&scir, &dataflow, &invariants, &frontier, &cfg);
        IndexRegistryPopSwapStaleDetector.run(&cx)
    }
    fn fires(src: &str) -> bool {
        run(src).iter().any(|f| f.detector == "index-registry-pop-swap-stale")
    }

    // VULN — a holder registry with an `id -> index` reverse map (`holderIndex`).
    // `removeHolder` reads `holderIndex[holder]` to find the slot, swap-pops the
    // `holders` array, but NEVER rewrites `holderIndex` for the element it moved
    // into the hole. The moved holder's stored index is now stale (names the popped
    // tail), so a later `holders[holderIndex[moved]]` lookup is wrong.
    const VULN: &str = r#"
        contract Registry {
            address[] public holders;
            mapping(address => uint256) public holderIndex;

            function addHolder(address h) external {
                holderIndex[h] = holders.length;
                holders.push(h);
            }

            function removeHolder(address holder) external {
                uint256 i = holderIndex[holder];
                holders[i] = holders[holders.length - 1];
                holders.pop();
                delete holderIndex[holder];
                // BUG: holderIndex[movedHolder] not updated to `i`
            }
        }
    "#;

    // SAFE — the correct shape: same swap-pop, but the moved element's index map
    // entry IS rewritten in the same block (`holderIndex[moved] = i`).
    const SAFE_UPDATED: &str = r#"
        contract Registry {
            address[] public holders;
            mapping(address => uint256) public holderIndex;

            function addHolder(address h) external {
                holderIndex[h] = holders.length;
                holders.push(h);
            }

            function removeHolder(address holder) external {
                uint256 i = holderIndex[holder];
                address moved = holders[holders.length - 1];
                holders[i] = moved;
                holders.pop();
                holderIndex[moved] = i;
                delete holderIndex[holder];
            }
        }
    "#;

    // SAFE — EigenLayer `IndexRegistry.deregisterOperator` shape, abstracted: the
    // moved element's index is rewritten through an internal helper
    // (`_assignOperatorToIndex`) that writes the reverse map. The removal function
    // reads `currentOperatorIndex` for the slot but the write goes through the
    // callee — the one-level indirection suppression must catch this.
    const SAFE_HELPER_WRITE: &str = r#"
        contract IndexRegistry {
            mapping(uint8 => bytes32[]) operators;
            mapping(uint8 => mapping(bytes32 => uint32)) public currentOperatorIndex;

            function _assignOperatorToIndex(bytes32 operatorId, uint8 q, uint32 idx) internal {
                operators[q][idx] = operatorId;
                currentOperatorIndex[q][operatorId] = idx;
            }

            function deregisterOperator(bytes32 operatorId, uint8 q) external {
                uint32 i = currentOperatorIndex[q][operatorId];
                bytes32 lastId = operators[q][operators[q].length - 1];
                operators[q][i] = operators[q][operators[q].length - 1];
                operators[q].pop();
                if (operatorId != lastId) {
                    _assignOperatorToIndex(lastId, q, i);
                }
            }
        }
    "#;

    // SAFE — EigenLayer `StakeRegistry.removeStrategies` shape: a plain swap-pop on
    // two storage arrays with NO `id -> index` reverse map at all. The index to
    // remove is caller-supplied; the array is the sole source of truth, so there is
    // nothing to leave stale.
    const SAFE_NO_MAP: &str = r#"
        contract StakeRegistry {
            struct StrategyParams { address strategy; uint96 multiplier; }
            mapping(uint8 => StrategyParams[]) strategyParams;

            function removeStrategies(uint8 q, uint256[] memory indicesToRemove) external {
                StrategyParams[] storage _strategyParams = strategyParams[q];
                for (uint256 i = 0; i < indicesToRemove.length; i++) {
                    _strategyParams[indicesToRemove[i]] = _strategyParams[_strategyParams.length - 1];
                    _strategyParams.pop();
                }
            }
        }
    "#;

    // SAFE — a swap-pop and an unrelated index map exist on the contract, but the
    // removal function does NOT read the index map (no linkage). Avoids firing on a
    // coincidental `*index*`-named mapping the removal logic never touches.
    const SAFE_MAP_NOT_READ: &str = r#"
        contract Pool {
            address[] public items;
            mapping(address => uint256) public rewardIndexOf; // unrelated index map

            function remove(uint256 i) external {
                items[i] = items[items.length - 1];
                items.pop();
            }
            function setRewardIndex(address a, uint256 v) external { rewardIndexOf[a] = v; }
        }
    "#;

    // SAFE — no pop at all: `arr[i] = arr[arr.length-1]` with no following `pop()`
    // is not a removal (e.g. an in-place reorder), so the class does not apply.
    const SAFE_NO_POP: &str = r#"
        contract Reorder {
            uint256[] public arr;
            mapping(uint256 => uint256) public valueIndex;
            function bump(uint256 i) external {
                uint256 j = valueIndex[i];
                arr[j] = arr[arr.length - 1];
            }
        }
    "#;

    #[test]
    fn fires_on_stale_back_reference_swap_pop() {
        assert!(fires(VULN), "{:#?}", run(VULN));
        // The finding should name the swapped array and the stale map.
        let fs = run(VULN);
        let f = fs.iter().find(|f| f.detector == "index-registry-pop-swap-stale").unwrap();
        assert_eq!(f.function, "removeHolder");
    }

    #[test]
    fn silent_when_moved_index_rewritten_inline() {
        assert!(!fires(SAFE_UPDATED), "{:#?}", run(SAFE_UPDATED));
    }

    #[test]
    fn silent_when_moved_index_rewritten_via_helper() {
        assert!(!fires(SAFE_HELPER_WRITE), "{:#?}", run(SAFE_HELPER_WRITE));
    }

    #[test]
    fn silent_without_reverse_index_map() {
        assert!(!fires(SAFE_NO_MAP), "{:#?}", run(SAFE_NO_MAP));
    }

    #[test]
    fn silent_when_map_not_read_by_removal() {
        assert!(!fires(SAFE_MAP_NOT_READ), "{:#?}", run(SAFE_MAP_NOT_READ));
    }

    #[test]
    fn silent_without_pop() {
        assert!(!fires(SAFE_NO_POP), "{:#?}", run(SAFE_NO_POP));
    }
}
