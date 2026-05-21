//! Error types surfaced by the fact store.

use std::io;
use thiserror::Error;

/// Errors a [`crate::FactStoreReader`] or [`crate::FactStoreWriter`] can produce.
#[derive(Debug, Error)]
pub enum FactStoreError {
    /// I/O error from the OS layer (file open, mmap, write, rename).
    #[error("io: {0}")]
    Io(#[from] io::Error),

    /// File header magic bytes did not match. The file is either not a
    /// fact store or has been truncated.
    #[error("invalid magic — file is not a bonsai fact store")]
    BadMagic,

    /// File is shorter than required for the bytes it claims to hold.
    /// Indicates truncation or corruption.
    #[error("truncated file: expected at least {expected} bytes, got {actual}")]
    Truncated {
        /// Bytes the format requires.
        expected: u64,
        /// Bytes the file actually has.
        actual: u64,
    },

    /// On-disk format version differs from this build's
    /// [`crate::format::FORMAT_VERSION`]. Callers should treat this
    /// like a missing file: drop the cache and rebuild.
    #[error("format version mismatch: file has {file}, this build expects {expected}")]
    VersionMismatch {
        /// Version stored in the file's header.
        file: u32,
        /// Version this build emits.
        expected: u32,
    },

    /// Caller-defined `pipeline_hash` differs from the one in the
    /// file. The cached entries were built against a different
    /// analysis pipeline configuration; treat as a miss.
    #[error("pipeline hash mismatch: file has {file:#x}, caller expects {expected:#x}")]
    PipelineMismatch {
        /// Hash stored in the file's header.
        file: u64,
        /// Hash the caller asserted.
        expected: u64,
    },

    /// `table_id` in the header doesn't match the caller's expected
    /// table. This usually means two fact stores got swapped on disk.
    #[error("table id mismatch: file has {file}, caller expects {expected}")]
    WrongTable {
        /// Table id stored in the file's header.
        file: u32,
        /// Table id the caller asserted.
        expected: u32,
    },

    /// String pool was structurally invalid — offsets section length
    /// disagreed with the count, or an offset pointed outside the
    /// bytes section, or a string was non-UTF-8.
    #[error("corrupt string pool: {0}")]
    BadStringPool(&'static str),

    /// Index entry with `payload_offset + payload_len` extending past
    /// the payload section. Indicates corruption.
    #[error("corrupt index: entry at row {row} has payload range outside payload section")]
    BadIndexEntry {
        /// Zero-based row in the index.
        row: usize,
    },

    /// Index entries were not sorted by `key` ascending. Lookups
    /// require sorted input for binary search.
    #[error("corrupt index: entries are not sorted by key ascending")]
    UnsortedIndex,

    /// Caller asked for a string id that's outside the pool.
    #[error("string id out of range: id={id}, pool has {count} strings")]
    BadStringId {
        /// The id the caller looked up.
        id: u32,
        /// How many strings exist in the pool.
        count: u32,
    },
}

/// Convenience alias used throughout the crate.
pub type FactStoreResult<T> = Result<T, FactStoreError>;
