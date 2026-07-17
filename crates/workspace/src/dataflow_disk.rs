//! On-disk encoding for `DataFlowCache` entries.
//!
//! Each per-function entry is the MessagePack-encoded triple
//! `(KindedTokens, EntryTaintGraph, Vec<FileId>)` — facts, the
//! per-entry semantic taint graph, and the transitive file
//! dependencies used for invalidation.
//!
//! Unlike `value_flow_disk`, this version does NOT yet intern strings
//! across entries — the dominant memory pressure for the dataflow
//! cache is the per-function `EntryTaintGraph` resident in RAM, and
//! moving those graphs out of process memory through the factstore
//! is the OOM fix. Cross-entry string interning is a future
//! enhancement that further shrinks the on-disk size; the file format
//! is opaque to the factstore so we can swap it in without changing
//! the storage layer.
//!
//! Decode errors surface as typed [`DecodeError`] so callers can
//! distinguish a corrupt blob from missing data.

use bonsai_common::{wire, FileId};
use bonsai_taint::{EntryTaintGraph, KindedTokens};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One per-function record persisted to a fact store.
///
/// `facts` and `graph` are the two values consumers ask for via
/// [`crate::dataflow::DataFlowCache::facts_for`] /
/// [`crate::dataflow::DataFlowCache::graph_for`]. `dependencies` is
/// the file-id set used for invalidation — when any of those files
/// changes, the entry must be recomputed.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DataFlowEntry {
    /// Per-kind taint reachability tokens for the entry function.
    pub facts: KindedTokens,
    /// Indexed semantic taint graph for the entry.
    pub graph: EntryTaintGraph,
    /// Transitive callee file dependencies. Stored as a `Vec<u32>`
    /// (raw `FileId`s) rather than `AHashSet<FileId>` because encoding
    /// an unsorted `AHashSet` is order-dependent and the resulting
    /// bytes would differ between runs even when the logical set is
    /// equal. The decoder reconstructs the set.
    pub dependency_files: Vec<u32>,
}

impl DataFlowEntry {
    /// Construct an entry from the in-memory values, sorting the
    /// dependency file ids so the encoded bytes are deterministic.
    #[must_use]
    pub fn from_owned(
        facts: KindedTokens,
        graph: EntryTaintGraph,
        dependencies: impl IntoIterator<Item = FileId>,
    ) -> Self {
        let mut dependency_files: Vec<u32> = dependencies.into_iter().map(|f| f.raw()).collect();
        dependency_files.sort_unstable();
        dependency_files.dedup();
        Self {
            facts,
            graph,
            dependency_files,
        }
    }

    /// Recover the dependency `FileId` set from the persisted vec.
    #[must_use]
    pub fn dependency_set(&self) -> ahash::AHashSet<FileId> {
        self.dependency_files.iter().copied().map(FileId::new).collect()
    }
}

/// Errors returned by [`decode`].
#[derive(Debug, Error)]
pub enum DecodeError {
    /// MessagePack could not parse the bytes — the file was truncated or
    /// corrupt.
    #[error("MessagePack: {0}")]
    Wire(#[from] wire::DecodeError),
}

/// Encode an entry into MessagePack bytes.
pub fn encode(entry: &DataFlowEntry) -> Vec<u8> {
    wire::encode(entry).expect("MessagePack encoding of DataFlowEntry never fails")
}

/// Decode bytes produced by [`encode`] back into a [`DataFlowEntry`].
pub fn decode(bytes: &[u8]) -> Result<DataFlowEntry, DecodeError> {
    let entry: DataFlowEntry = wire::decode(bytes)?;
    Ok(entry)
}

#[cfg(test)]
#[path = "dataflow_disk_tests.rs"]
mod tests;
