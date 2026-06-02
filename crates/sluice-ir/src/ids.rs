//! Stable identifier newtypes and source spans.
//!
//! All entity indices are wrapped in distinct newtypes so that a `FunctionId`
//! can never be silently used where a `ContractId` is expected — the same
//! discipline `vortex-ir` uses for `ValueId`/`BlockId`/`FuncId`.

use serde::{Deserialize, Serialize};

macro_rules! id_newtype {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(pub u32);

        impl $name {
            #[inline]
            pub const fn index(self) -> usize {
                self.0 as usize
            }
        }

        impl From<u32> for $name {
            #[inline]
            fn from(v: u32) -> Self {
                Self(v)
            }
        }
    };
}

id_newtype!(
    /// Identifies a contract / interface / library within a [`crate::Scir`].
    ContractId
);
id_newtype!(
    /// Identifies a function (or modifier) within a [`crate::Scir`].
    FunctionId
);

/// A byte-range location in a source file, mirroring `solang_parser::pt::Loc::File`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Span {
    /// Index into [`crate::Scir::files`].
    pub file: u32,
    /// Start byte offset (inclusive).
    pub start: u32,
    /// End byte offset (exclusive).
    pub end: u32,
}

impl Span {
    pub const fn new(file: u32, start: u32, end: u32) -> Self {
        Self { file, start, end }
    }

    /// A placeholder span with no real location (used for synthesized nodes).
    pub const fn dummy() -> Self {
        Self { file: 0, start: 0, end: 0 }
    }

    pub const fn is_dummy(&self) -> bool {
        self.start == 0 && self.end == 0
    }

    /// The smallest span enclosing both `self` and `other` (same file assumed).
    pub fn merge(self, other: Span) -> Span {
        Span {
            file: self.file,
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}
