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
