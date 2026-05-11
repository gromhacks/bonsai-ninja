//! Errors surfaced by the IDG layer.

use thiserror::Error;

/// IDG-layer errors. Most map back to factstore I/O or to structural
/// invariants the storage format guarantees.
#[derive(Debug, Error)]
pub enum IdgError {
    /// Underlying factstore I/O. The factstore handles atomic-rename,
    /// magic / version mismatch, truncation, etc. — those bubble up
    /// here so callers don't import factstore directly.
    #[error("factstore: {0}")]
    FactStore(#[from] bonsai_factstore::FactStoreError),

    /// `std::io::Error` for paths the factstore layer doesn't own
    /// (segment directory creation, file enumeration, etc.).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A serialized [`crate::place::Place`] payload could not be
    /// decoded. The byte slice was truncated or written by an
    /// incompatible build.
    #[error("malformed place payload: {0}")]
    BadPlace(&'static str),

    /// A serialized [`crate::edge::IdgEdge`] payload could not be
    /// decoded.
    #[error("malformed edge payload: {0}")]
    BadEdge(&'static str),

    /// A `PlaceId` referenced from an edge or adjacency table points
    /// past the place dictionary's last id. Indicates corruption or
    /// a segmenter bug.
    #[error("place id {id} out of range (dict size {count})")]
    BadPlaceId {
        /// The id the lookup used.
        id: u32,
        /// Number of places in the dictionary.
        count: u32,
    },

    /// A `NodeId` referenced from an edge or adjacency table points
    /// past the node dictionary's last id. Indicates corruption or
    /// a builder bug.
    #[error("node id {id} out of range (graph size {count})")]
    BadNodeId {
        /// The id the lookup used.
        id: u32,
        /// Number of nodes in the graph.
        count: u32,
    },

    /// An IDG segment file's table id does not match the expected
    /// IDG segment table id. Either the wrong factstore was opened
    /// or the on-disk layout has been swapped externally.
    #[error("not an IDG segment: factstore table_id={got}, expected {expected}")]
    WrongTable {
        /// Table id stored in the file's header.
        got: u32,
        /// Table id this layer expected.
        expected: u32,
    },
}

/// Convenience alias used throughout the crate.
pub type IdgResult<T> = Result<T, IdgError>;
