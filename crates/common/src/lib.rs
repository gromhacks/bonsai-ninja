#![deny(missing_docs)]
//! Shared primitives used across every crate.
//!
//! - Stable numeric IDs (`FileId`, `FuncId`, ...). Keep these u32 for cache
//!   friendliness; upgrade to u64 only if a workspace actually overflows.
//! - [`Span`] byte ranges anchored to a `FileId`.
//! - [`Precision`], the single vocabulary for "how sure are we about this
//!   fact?" that every analyser must emit.
//!
//! Nothing in this crate depends on Tree-sitter or any language adapter; it is
//! safe to depend on from every other crate.

pub mod atomic_file;
pub mod dependency_metadata;
pub mod ids;
pub mod names;
pub mod policy;
pub mod precision;
pub mod span;
pub mod span_cache;
pub mod wire;

pub use atomic_file::write_atomic_bytes;
pub use ids::{BasicBlockId, FileId, FuncId, PackageId, SymbolId, TraceStepId, TypeId, ValueId};
pub use names::{
    callable_reference_variants, is_bonsai_case_probe_path, qualified_names_match, short_qualified_tail,
    value_text_returns_self_constructor, workspace_bonsai_dir, ABSOLUTE_PATH_PREFIXES, ALL_NAME_PUNCTUATION,
    BONSAI_CASE_PROBE_PREFIX, IDENTIFIER_SIGILS, PROJECTION_CANONICALIZATION_VECTORS,
    QUALIFIED_NAME_SEPARATORS, REFERENCE_SIGILS, SELF_CONSTRUCTOR_HEADS, VALUE_TEXT_LEADING_KEYWORDS,
};
pub use policy::MATCHER_POLICY_FINGERPRINT;
pub use precision::Precision;
pub use span::{LineCol, Span, SpanMap};
pub use span_cache::{cached_span_map, cached_span_map_arc};

// Note: a previous version of this crate exposed `FxHasher`,
// `FxHashMap`, `FxHashSet`, `fx_hash_map`, `fx_hash_set` as a
// workspace-default hasher set. Every consumer in the workspace
// uses `ahash::AHashMap` / `ahash::AHashSet` directly, so the
// aliases were dead surface and have been removed. New code
// should keep using `ahash` types directly.
