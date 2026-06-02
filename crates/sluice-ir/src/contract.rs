//! Contract / interface / library model.

use crate::func::Visibility;
use crate::ids::{ContractId, FunctionId, Span};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Contract {
    pub id: ContractId,
    pub name: String,
    pub kind: ContractKind,
    /// Inherited base names, in declaration order.
    pub bases: Vec<String>,
    pub state_vars: Vec<StateVar>,
    /// Functions defined directly in this contract (not inherited).
    pub functions: Vec<FunctionId>,
    /// `using L for T` directives (e.g. `using SafeERC20 for IERC20`), used for
    /// false-positive suppression of unchecked-transfer findings.
    pub using_for: Vec<UsingDirective>,
    /// Index into [`crate::Scir::files`].
    pub file: u32,
    pub span: Span,
}

impl Contract {
    pub fn is_interface(&self) -> bool {
        matches!(self.kind, ContractKind::Interface)
    }
    pub fn is_library(&self) -> bool {
        matches!(self.kind, ContractKind::Library)
    }
    pub fn is_concrete(&self) -> bool {
        matches!(self.kind, ContractKind::Contract)
    }
    /// True if a base name matches (case-insensitive substring) — used to detect
    /// OpenZeppelin mixins like `ReentrancyGuard`, `Ownable`, `ERC4626`.
    pub fn inherits_like(&self, needle: &str) -> bool {
        let n = needle.to_ascii_lowercase();
        self.bases.iter().any(|b| b.to_ascii_lowercase().contains(&n))
    }
    /// True if a `using X for ...` binds a library whose name matches `needle`.
    pub fn uses_library_like(&self, needle: &str) -> bool {
        let n = needle.to_ascii_lowercase();
        self.using_for.iter().any(|u| u.library.to_ascii_lowercase().contains(&n))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContractKind {
    Contract,
    Interface,
    Library,
    Abstract,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateVar {
    pub name: String,
    /// Textual declared type (`uint256`, `mapping(address => uint256)`, `IERC20`).
    pub ty: String,
    pub visibility: Visibility,
    pub constant: bool,
    pub immutable: bool,
    /// Has an inline initializer at declaration.
    pub initialized: bool,
    pub span: Span,
}

impl StateVar {
    /// Heuristic: looks like a numeric scalar that could be a state-machine flag
    /// or a counter (used by consensus-invariant mining).
    pub fn is_scalar_numeric(&self) -> bool {
        let t = self.ty.trim();
        t.starts_with("uint") || t.starts_with("int") || t == "bool" || t.starts_with("enum")
    }
    pub fn is_mapping(&self) -> bool {
        self.ty.trim_start().starts_with("mapping")
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsingDirective {
    /// Library name (`SafeERC20`, `SafeCast`, `Address`).
    pub library: String,
    /// The bound type (`IERC20`), or `None` for `using L for *`.
    pub ty: Option<String>,
}
