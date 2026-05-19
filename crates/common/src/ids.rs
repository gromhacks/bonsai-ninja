//! Stable, compact identifiers.
//!
//! All IDs are `u32` newtypes. They are only meaningful inside the database
//! that issued them; never serialize them across workspace sessions.

use serde::{Deserialize, Serialize};

macro_rules! def_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(
            /// Raw u32 representation. `u32::MAX` is reserved as the
            /// `INVALID` sentinel.
            pub u32,
        );

        impl $name {
            /// Sentinel for "no valid id". Persisted in fields that
            /// may be absent, e.g. `Default::default()`.
            pub const INVALID: Self = Self(u32::MAX);

            /// Wrap a raw `u32` as this id type.
            #[inline]
            #[must_use]
            pub const fn new(raw: u32) -> Self {
                Self(raw)
            }

            /// Unwrap to the raw `u32` representation.
            #[inline]
            #[must_use]
            pub const fn raw(self) -> u32 {
                self.0
            }

            /// True iff this is not [`Self::INVALID`].
            #[inline]
            #[must_use]
            pub const fn is_valid(self) -> bool {
                self.0 != u32::MAX
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self::INVALID
            }
        }
    };
}

def_id!(
    /// Workspace-unique file identifier.
    FileId
);
def_id!(
    /// Language-adapter defined package identifier.
    PackageId
);
def_id!(
    /// Symbol (binding) identifier within a declaration index.
    SymbolId
);
def_id!(
    /// Function / method identifier. Alias shape of `SymbolId` for convenience.
    FuncId
);
def_id!(
    /// Type identifier (language-specific). Used by the abstract-value
    /// lattice in `bonsai_abstract_interp`.
    TypeId
);
def_id!(
    /// CFG basic block identifier.
    BasicBlockId
);
def_id!(
    /// SSA-like value identifier used by the CFG.
    ValueId
);
def_id!(
    /// Trace step identifier issued monotonically within one trace query.
    TraceStepId
);

#[cfg(test)]
#[path = "ids_tests.rs"]
mod tests;
