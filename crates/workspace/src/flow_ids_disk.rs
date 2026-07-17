//! On-disk encoding for [`super::flow_ids::FlowIdCache`] entries.
//!
//! Each per-function entry is the MessagePack-encoded `(labels,
//! truncated)` pair: the cached `Arc<[String]>` of hashed flow-id
//! labels and the flag indicating whether the chain enumeration hit
//! its cap. Strings are kept inline (not interned across entries)
//! because flow-id labels are short hex hashes (8-16 chars) and the
//! per-entry list is bounded at `MAX_LABELS_PER_FUNC`.

use bonsai_common::wire;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One per-function record persisted to a fact store.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FlowIdEntry {
    /// Hashed flow-id labels for this function — same shape as the
    /// in-memory `Arc<[String]>`.
    pub labels: Vec<String>,
    /// `true` when chain enumeration truncated for this function (the
    /// label set is a strict prefix of reality).
    pub truncated: bool,
}

/// Errors returned by [`decode`].
#[derive(Debug, Error)]
pub enum DecodeError {
    /// MessagePack could not parse the bytes.
    #[error("MessagePack: {0}")]
    Wire(#[from] wire::DecodeError),
}

/// Encode an entry into MessagePack bytes.
pub fn encode(entry: &FlowIdEntry) -> Vec<u8> {
    wire::encode(entry).expect("MessagePack encoding of FlowIdEntry never fails")
}

/// Decode bytes produced by [`encode`].
pub fn decode(bytes: &[u8]) -> Result<FlowIdEntry, DecodeError> {
    Ok(wire::decode(bytes)?)
}

#[cfg(test)]
#[path = "flow_ids_disk_tests.rs"]
mod tests;
