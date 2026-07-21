//! On-disk content-addressed fact store with workspace-wide string
//! interning.
//!
//! ## What this crate is for
//!
//! bonsai-ninja's per-function analysis caches (dataflow facts,
//! value-flow graphs, flow-id labels, source-seeded taint graphs)
//! grow linearly with the number of callable functions in a
//! workspace. Today they live entirely in process memory and are
//! eagerly populated at workspace open. On large workspaces that
//! pushes total RSS past available RAM.
//!
//! This crate is the storage substrate for those caches:
//!
//! - **Lazy**: lookups read only the bytes for the requested entry.
//! - **Bounded**: only a header + index + string pool stay resident;
//!   payloads page through the OS file cache.
//! - **Lossless**: no caps on entry count, payload size, or analysis
//!   precision. The cache holds whatever the analysis layer computes.
//! - **Content-addressed**: every entry carries a `body_hash` so a
//!   stale entry can be detected without re-running the analysis.
//!
//! ## Three-layer API
//!
//! 1. [`FactStoreWriter`] — append entries through a bounded,
//!    backpressured pipeline and write the file atomically.
//! 2. [`FactStoreReader`] — open a written file, look up entries by
//!    key, iterate.
//! 3. [`FactCache`] — wraps a reader with an LRU of decoded values
//!    so the hot working set of a query stays in process memory.
//!
//! ## Workspace-wide string interning
//!
//! Every string a payload references (function names, identifier
//! names, file paths, etc.) is interned via [`StringPoolBuilder`]
//! at write time and embedded as a 4-byte [`StrId`] in the payload.
//! Readers resolve ids against [`StringPoolView`] in O(1). The
//! string pool itself is a single contiguous byte slice plus an
//! offsets table — no per-string heap allocations after open.
//!
//! See `crates/factstore/src/format.rs` for the on-disk byte layout.

#![deny(missing_docs)]

pub mod cache;
pub mod error;
pub mod format;
pub mod reader;
pub mod string_pool;
pub mod writer;

pub use cache::{CacheGet, FactCache};
pub use error::{FactStoreError, FactStoreResult};
pub use format::{Header, IndexEntry, FORMAT_VERSION, HEADER_SIZE, INDEX_ENTRY_SIZE, MAGIC};
pub use reader::{EntryIter, FactStoreReader, LookupHit, PayloadReader};
pub use string_pool::{StrId, StringPoolBuilder, StringPoolView};
pub use writer::FactStoreWriter;
