//! On-disk encoding for [`super::flow_ids::FlowIdCache`] entries.
//!
//! Each per-function entry is one MessagePack-encoded symbol-evidence id.

use bonsai_common::wire;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One per-function record persisted to a fact store.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FlowIdEntry {
    /// Hashed symbol-evidence id for this function.
    pub id: String,
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
