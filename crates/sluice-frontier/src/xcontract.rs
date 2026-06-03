//! Cross-contract resolution: link an interface / contract *type* to the
//! concrete contract(s) that implement it, so a call like `IOracle(addr).price()`
//! or `pool.getReserves()` can be followed to the implementation. This is the
//! groundwork for cross-contract flow analysis (oracle-from-pool, read-only
//! reentrancy through a consumed view, bridge sender-trust) — the class of bug
//! that single-contract analysis structurally cannot see.

use rustc_hash::FxHashMap;
use sluice_ir::{ContractId, FunctionId, Scir};

/// Maps a type name (interface or base) to the concrete contracts implementing it.
#[derive(Debug, Default, Clone)]
pub struct ContractResolver {
    /// type name -> concrete contract ids implementing / inheriting it.
    impls: FxHashMap<String, Vec<ContractId>>,
}

impl ContractResolver {
    /// Build the resolver from a module.
    pub fn build(scir: &Scir) -> Self {
        let mut impls: FxHashMap<String, Vec<ContractId>> = FxHashMap::default();

        for c in scir.iter_contracts() {
            if !c.is_concrete() {
                continue;
            }
            // A concrete contract resolves to itself by name.
            push_unique(&mut impls, c.name.clone(), c.id);
            // ...and satisfies each of its base / interface names.
            for b in &c.bases {
                push_unique(&mut impls, b.clone(), c.id);
            }
        }

        // Interface naming convention: `IFoo` is implemented by a concrete `Foo`
        // even without an explicit `is IFoo`. Map it when such a contract exists.
        let concrete: Vec<(String, ContractId)> = scir
            .iter_contracts()
            .filter(|c| c.is_concrete())
            .map(|c| (c.name.clone(), c.id))
            .collect();
        for iface in scir.iter_contracts().filter(|c| c.is_interface()) {
            if let Some(stripped) = iface.name.strip_prefix('I') {
                if !stripped.is_empty() {
                    for (name, cid) in &concrete {
                        if name == stripped {
                            push_unique(&mut impls, iface.name.clone(), *cid);
                        }
                    }
                }
            }
        }

        ContractResolver { impls }
    }

    /// Concrete contracts implementing a type name.
    pub fn implementations(&self, type_name: &str) -> &[ContractId] {
        self.impls.get(type_name).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// The single implementation of a type, if unambiguous.
    pub fn resolve_unique(&self, type_name: &str) -> Option<ContractId> {
        match self.impls.get(type_name) {
            Some(v) if v.len() == 1 => Some(v[0]),
            _ => None,
        }
    }

    /// Resolve `type.method(...)` to the implementation's function, if a single
    /// implementing contract defines a function with that name.
    pub fn resolve_method(&self, scir: &Scir, type_name: &str, method: &str) -> Option<FunctionId> {
        for cid in self.implementations(type_name) {
            if let Some(c) = scir.contract(*cid) {
                for fid in &c.functions {
                    if scir.function(*fid).map(|f| f.name == method).unwrap_or(false) {
                        return Some(*fid);
                    }
                }
            }
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.impls.is_empty()
    }

    /// Cross-contract oracle dependency: does a `type.method(...)` call resolve to
    /// an in-repo implementation whose body reads a *manipulable spot price*
    /// (`getReserves`/`slot0`/`balanceOf`/`getPrice`/...)? If so, a consumer that
    /// trusts `type.method()` as a price is transitively exposed to spot
    /// manipulation even though its own body contains no spot read — a bug that
    /// single-contract analysis cannot see. Returns the implementing contract.
    pub fn resolves_to_spot_oracle(
        &self,
        scir: &Scir,
        type_name: &str,
        method: &str,
    ) -> Option<ContractId> {
        for cid in self.implementations(type_name) {
            let Some(c) = scir.contract(*cid) else { continue };
            for fid in &c.functions {
                let Some(f) = scir.function(*fid) else { continue };
                if f.name != method {
                    continue;
                }
                let mut spot = false;
                for s in &f.body {
                    s.visit_exprs(&mut |e| {
                        if let sluice_ir::ExprKind::Call(call) = &e.kind {
                            if sluice_dataflow::is_spot_price_call(call) {
                                spot = true;
                            }
                        }
                    });
                }
                if spot {
                    return Some(*cid);
                }
            }
        }
        None
    }
}

fn push_unique(map: &mut FxHashMap<String, Vec<ContractId>>, key: String, id: ContractId) {
    let v = map.entry(key).or_default();
    if !v.contains(&id) {
        v.push(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scir(src: &str) -> Scir {
        sluice_parse::parse_sources(vec![("t.sol".into(), src.into())]).scir
    }

    #[test]
    fn resolves_interface_and_inheritance() {
        let m = scir(
            "interface IOracle { function price() external view returns (uint256); }
             contract ChainlinkOracle is IOracle { function price() external view returns (uint256) { return 1; } }
             contract Other { function f() external {} }",
        );
        let r = ContractResolver::build(&m);
        // `is IOracle` inheritance link
        let chainlink = m.contract_named("ChainlinkOracle").unwrap().id;
        assert!(r.implementations("IOracle").contains(&chainlink));
        // resolve a method on the interface type to the implementation
        let fid = r.resolve_method(&m, "IOracle", "price").unwrap();
        assert_eq!(m.function(fid).unwrap().name, "price");
    }

    #[test]
    fn detects_cross_contract_spot_oracle() {
        // `PriceOracle.getPrice()` computes its price from a spot reserve read, so
        // a consumer trusting `IOracle(o).getPrice()` is cross-contract exposed.
        let m = scir(
            "interface IPair { function getReserves() external view returns (uint112, uint112, uint32); }
             interface IOracle { function getPrice() external view returns (uint256); }
             contract PriceOracle is IOracle {
                 IPair public pair;
                 function getPrice() external view returns (uint256) {
                     (uint112 r0, uint112 r1, ) = pair.getReserves();
                     return uint256(r1) * 1e18 / uint256(r0);
                 }
             }",
        );
        let r = ContractResolver::build(&m);
        let impl_cid = m.contract_named("PriceOracle").unwrap().id;
        assert_eq!(r.resolves_to_spot_oracle(&m, "IOracle", "getPrice"), Some(impl_cid));
        // A method that is not a spot read resolves to nothing.
        assert_eq!(r.resolves_to_spot_oracle(&m, "IOracle", "decimals"), None);
    }

    #[test]
    fn resolves_by_naming_convention() {
        // `IVault` with no explicit `is`, but a concrete `Vault` exists.
        let m = scir(
            "interface IVault { function totalAssets() external view returns (uint256); }
             contract Vault { function totalAssets() external view returns (uint256) { return 0; } }",
        );
        let r = ContractResolver::build(&m);
        let vault = m.contract_named("Vault").unwrap().id;
        assert_eq!(r.resolve_unique("IVault"), Some(vault));
    }
}
