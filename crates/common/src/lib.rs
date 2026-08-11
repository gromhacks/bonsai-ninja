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
pub mod path_filter;
pub mod policy;
pub mod precision;
pub mod resources;
pub mod span;
pub mod span_cache;
pub mod wire;

pub use atomic_file::write_atomic_bytes;
pub use ids::{BasicBlockId, FileId, FuncId, PackageId, SymbolId, TraceStepId, TypeId, ValueId};
pub use names::{
    ends_at_qualified_name_boundary, is_bonsai_case_probe_path, is_name_punctuation,
    normalize_qualified_name, qualified_name_owner, qualified_name_prefixes, qualified_name_segments,
    qualified_names_match, short_qualified_tail, split_qualified_name_head_tail,
    split_qualified_name_owner_tail, starts_at_qualified_name_boundary, trim_leading_name_punctuation,
    workspace_bonsai_dir, BONSAI_CASE_PROBE_PREFIX,
};
pub use path_filter::{
    canonicalize_path_or_existing_parent, filter_looks_like_absolute_path, normalize_path_for_filter,
    normalized_path_contains, path_filter_matches, path_filter_matches_with_root, scoped_path_filter_matches,
    workspace_relative_filter_path,
};
pub use policy::MATCHER_POLICY_FINGERPRINT;
pub use precision::Precision;
pub use resources::callgraph_worker_count;
pub use resources::candidate_index_worker_count;
pub use resources::compiler_weighted_batches;
pub use resources::compiler_worker_count;
pub use resources::current_process_resident_bytes;
pub use resources::effective_memory_limit_bytes;
pub use resources::memory_bounded_worker_count;
pub use resources::rooted_semantic_query_worker_count;
pub use resources::semantic_query_worker_count;
pub use resources::source_ingestion_batches;
pub use resources::syntax_weighted_batches;
pub use resources::syntax_worker_count;
pub use resources::syntax_worker_count_for_sources;
pub use resources::SyntaxMemoryPermitPool;
pub use span::{LineCol, Span, SpanMap};
pub use span_cache::{cached_span_map, cached_span_map_arc};

// Note: a previous version of this crate exposed `FxHasher`,
// `FxHashMap`, `FxHashSet`, `fx_hash_map`, `fx_hash_set` as a
// workspace-default hasher set. Every consumer in the workspace
// uses `ahash::AHashMap` / `ahash::AHashSet` directly, so the
// aliases were dead surface and have been removed. New code
// should keep using `ahash` types directly.
