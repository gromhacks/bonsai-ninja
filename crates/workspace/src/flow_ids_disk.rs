//! On-disk encoding for [`super::flow_ids::FlowIdCache`] entries.
//!
//! Each per-function entry is the bincode-encoded `(labels,
//! truncated)` pair: the cached `Arc<[String]>` of hashed flow-id
//! labels and the flag indicating whether the chain enumeration hit
//! its cap. Strings are kept inline (not interned across entries)
//! because flow-id labels are short hex hashes (8-16 chars) and the
//! per-entry list is bounded at `MAX_LABELS_PER_FUNC`.

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
    /// Bincode could not parse the bytes.
    #[error("bincode: {0}")]
    Bincode(#[from] bincode::Error),
}

/// Encode an entry into bincode bytes.
pub fn encode(entry: &FlowIdEntry) -> Vec<u8> {
    bincode::serialize(entry).expect("bincode encoding of FlowIdEntry never fails")
}

/// Decode bytes produced by [`encode`].
pub fn decode(bytes: &[u8]) -> Result<FlowIdEntry, DecodeError> {
    Ok(bincode::deserialize(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_entry_roundtrips() {
        let entry = FlowIdEntry::default();
        let bytes = encode(&entry);
        let decoded = decode(&bytes).expect("decode");
        assert!(decoded.labels.is_empty());
        assert!(!decoded.truncated);
    }

    #[test]
    fn entry_with_labels_roundtrips() {
        let entry = FlowIdEntry {
            labels: vec!["F:abc123".to_string(), "F:def456".to_string()],
            truncated: true,
        };
        let bytes = encode(&entry);
        let decoded = decode(&bytes).expect("decode");
        assert_eq!(decoded.labels, entry.labels);
        assert!(decoded.truncated);
    }

    #[test]
    fn corrupt_bytes_surface_typed_error() {
        let bytes = vec![0xFFu8; 16];
        match decode(&bytes) {
            Err(DecodeError::Bincode(_)) => {}
            other => panic!("expected Bincode error, got {other:?}"),
        }
    }
}
