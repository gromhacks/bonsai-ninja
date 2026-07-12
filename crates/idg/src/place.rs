//! `Place` — every position a value can occupy in the workspace's
//! interprocedural dataflow graph.
//!
//! Every node in the IDG is a `(FuncId, PlaceId)` pair. The `PlaceId`
//! is a `u32` handle into a per-segment place dictionary. Two
//! identical Places (same kind + same data, e.g. `Read(sym, ["a"])`)
//! always resolve to the same `PlaceId` within one segment.
//!
//! ## Variants
//!
//! - [`Place::Param`] — entry's formal parameter at a specific
//!   positional index.
//! - [`Place::Return`] — the value returned from the entry function.
//! - [`Place::Read`] — a read of a local / global / captured name,
//!   with an optional field-path projection (`obj.field.sub`).
//! - [`Place::Write`] — a write to a local / global / captured name,
//!   with an optional field-path projection.
//! - [`Place::CallArg`] — the value at argument index `i` of a
//!   specific call site (identified by its byte span).
//! - [`Place::CallRet`] — the value returned from a specific call
//!   site (i.e. what the caller's destination would receive).
//! - [`Place::Throw`] — a value flowing into a `throw` statement
//!   tagged with the thrown type.
//! - [`Place::Catch`] — a value bound by a `catch` clause of a
//!   particular type.
//! - [`Place::Yield`] / [`Place::Await`] — coroutine yield / await
//!   sites; preserved so async flows stay accurate.
//!
//! ## Why this shape
//!
//! Places are integer-keyed end-to-end: `SymbolId` for named
//! storage, `StrId` for field-path segments and exception-type names,
//! `u32` for byte-offset call site identifiers. There are no `String`
//! fields anywhere; the IDG is purely numeric.

use bonsai_common::Span;
use bonsai_factstore::StrId;
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};
use std::fmt;

/// Sequence of field-projection segments interned as `StrId`s.
/// `obj.field.sub` materialises as `[StrId("field"), StrId("sub")]`.
/// Empty path means a bare access to the storage location itself.
///
/// Most field paths are 1-3 segments; the inline capacity of 4
/// keeps everyday accesses on the stack.
pub type FieldPath = SmallVec<[StrId; 4]>;

/// Stable identifier for a call site within a function. The byte
/// span uniquely identifies the call in the source file; same call
/// site across two builds maps to the same `CallSiteId` because the
/// span is content-stable.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CallSiteId(pub Span);

/// Stable identifier for an exception type at the engine layer.
/// Stored as an interned string id (the type's canonical name in the
/// pool). Type-name normalisation is handled at construction; the
/// IDG never compares names lexically.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TypeId(pub StrId);

/// Storage for a `Place`. Variants are repr-tagged so the on-disk
/// payload stays compact (1-byte tag + variant-specific fields).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Place {
    /// Entry's formal parameter at positional index `idx`.
    Param {
        /// 0-based positional index in the function's parameter list.
        idx: u32,
    },

    /// Value returned from the entry function.
    Return,

    /// Read of a named storage location with optional field path.
    /// `name` is the interned bare identifier; field path projections
    /// extend it (`obj.field.sub` → `name = "obj"`,
    /// `path = ["field", "sub"]`).
    ///
    /// Read nodes are *shared per (func, name, path)* — every read of
    /// `x` in one function maps to the same node. The CFG-narrowing
    /// pass routes around the shared Read node by emitting direct
    /// `Write → consumer` edges based on per-event `last_writer`
    /// tracking; the shared Read remains as a debug / introspection
    /// anchor only.
    Read {
        /// Interned bare identifier.
        name: StrId,
        /// Field-path projection; empty path means a bare-name read.
        path: FieldPath,
    },

    /// Write to a named storage location with optional field path.
    ///
    /// Each *distinct* write event in the program is its own node —
    /// the `span` field disambiguates writes that target the same
    /// `(name, path)` so the CFG-narrowing pass can make later
    /// writes "kill" earlier ones (clean-overwrite semantics).
    /// Without per-write spans, all assignments to a name would
    /// collapse onto a single node and the IDG forward-closure
    /// would smear taint across the entire function.
    Write {
        /// Interned bare identifier.
        name: StrId,
        /// Field-path projection; empty path means a bare-name write.
        path: FieldPath,
        /// Source span of the write event. Distinguishes multiple
        /// writes to the same `(name, path)` so CFG-narrowing kill
        /// semantics work.
        span: Span,
    },

    /// Argument value at index `idx` of a specific call site.
    CallArg {
        /// Call site this argument belongs to.
        site: CallSiteId,
        /// 0-based positional index in the call's argument list.
        idx: u32,
    },

    /// Return value reception from a specific call site.
    CallRet {
        /// Call site whose returned value is being received.
        site: CallSiteId,
    },

    /// A value flowing into a `throw` statement of type `ty`.
    Throw {
        /// Type of the value being thrown.
        ty: TypeId,
    },

    /// A value bound by a `catch` clause of type `ty`.
    Catch {
        /// Type the catch clause matches.
        ty: TypeId,
    },

    /// A value yielded from a coroutine (Python / Rust generators
    /// etc.). Distinct from `Return` so async-flow paths don't merge
    /// with sync return paths.
    Yield,

    /// A value awaited from a future / promise.
    Await,
}

impl Place {
    /// Construct a bare-name `Read` (no field projection). Common
    /// enough to deserve a constructor.
    #[must_use]
    pub fn read(name: StrId) -> Self {
        Self::Read {
            name,
            path: SmallVec::new(),
        }
    }

    /// Construct a bare-name `Write` (no field projection) at `span`.
    /// Per-event `span` lets CFG narrowing distinguish two writes to
    /// the same name (clean-overwrite kills earlier write).
    #[must_use]
    pub fn write(name: StrId, span: Span) -> Self {
        Self::Write {
            name,
            path: SmallVec::new(),
            span,
        }
    }

    /// Construct a `Read` with a single field segment.
    #[must_use]
    pub fn read_field(name: StrId, field: StrId) -> Self {
        Self::Read {
            name,
            path: smallvec![field],
        }
    }

    /// Construct a `Write` with a single field segment at `span`.
    #[must_use]
    pub fn write_field(name: StrId, field: StrId, span: Span) -> Self {
        Self::Write {
            name,
            path: smallvec![field],
            span,
        }
    }

    /// Discriminant tag used in the on-disk encoding. Numeric values
    /// are STABLE across format versions; new variants append.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Param { .. } => 0,
            Self::Return => 1,
            Self::Read { .. } => 2,
            Self::Write { .. } => 3,
            Self::CallArg { .. } => 4,
            Self::CallRet { .. } => 5,
            Self::Throw { .. } => 6,
            Self::Catch { .. } => 7,
            Self::Yield => 8,
            Self::Await => 9,
        }
    }

    /// True iff this place reads or writes a named storage location.
    /// Used by the consumer layer to filter "show me places named X"
    /// without enumerating the dictionary.
    #[must_use]
    pub fn is_named_storage(&self) -> bool {
        matches!(self, Self::Read { .. } | Self::Write { .. })
    }

    /// True iff this place is a call-site fact (arg or return).
    #[must_use]
    pub fn is_call_site(&self) -> bool {
        matches!(self, Self::CallArg { .. } | Self::CallRet { .. })
    }

    /// The call site span for [`Self::CallArg`] / [`Self::CallRet`],
    /// `None` otherwise. Used by renderers to anchor a place back
    /// in the source.
    #[must_use]
    pub fn call_site(&self) -> Option<Span> {
        match self {
            Self::CallArg { site, .. } | Self::CallRet { site } => Some(site.0),
            _ => None,
        }
    }
}

impl fmt::Display for Place {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Param { idx } => write!(f, "Param({idx})"),
            Self::Return => write!(f, "Return"),
            Self::Read { name, path } => {
                write!(f, "Read(s{name}")?;
                for segment in path {
                    write!(f, ".{segment}")?;
                }
                write!(f, ")")
            }
            Self::Write { name, path, span } => {
                write!(f, "Write(s{name}")?;
                for segment in path {
                    write!(f, ".{segment}")?;
                }
                write!(f, "@{}..{})", span.start, span.end)
            }
            Self::CallArg { site, idx } => write!(f, "CallArg({site:?}@{idx})"),
            Self::CallRet { site } => write!(f, "CallRet({site:?})"),
            Self::Throw { ty } => write!(f, "Throw(ty={})", ty.0),
            Self::Catch { ty } => write!(f, "Catch(ty={})", ty.0),
            Self::Yield => write!(f, "Yield"),
            Self::Await => write!(f, "Await"),
        }
    }
}

#[cfg(test)]
#[path = "place_tests.rs"]
mod tests;
