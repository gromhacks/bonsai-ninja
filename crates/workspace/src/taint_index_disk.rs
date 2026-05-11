//! On-disk encoding for [`super::taint_index::TaintGraphIndex`] entries.
//!
//! The taint graph index keys on `(FuncId, sorted_seed_key)` —
//! a compound key the fact-store layer can't represent natively
//! (factstore keys are `u64`). We hash the compound key with
//! `fnv1a_str_slice64` and store the **full key** inside each
//! payload. Lookups verify the full key after the binary-search
//! hit, so a hash collision (1 in 2^64) is a miss rather than a
//! false hit.
//!
//! Payload shape (bincode):
//!
//! ```ignore
//! struct OnDiskTaintGraphEntry {
//!     func_raw: u32,
//!     seeds: Vec<String>,
//!     graph: EntryTaintGraph,
//! }
//! ```

use bonsai_common::FuncId;
use bonsai_hash::Hasher;
use bonsai_taint::EntryTaintGraph;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One per-`(source_func, seeds)` record persisted to a fact store.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TaintGraphEntry {
    /// `FuncId.raw()` — the source function this graph was seeded
    /// from. Stored explicitly so [`decode`] callers can verify the
    /// hashed key didn't collide.
    pub func_raw: u32,
    /// Sorted seed-token list — same shape as the in-memory
    /// `Vec<String>` key.
    pub seeds: Vec<String>,
    /// The cached entry-taint graph itself.
    pub graph: EntryTaintGraph,
}

/// Errors returned by [`decode`] / key validation.
#[derive(Debug, Error)]
pub enum DecodeError {
    /// Bincode could not parse the bytes — the file was truncated or
    /// corrupt.
    #[error("bincode: {0}")]
    Bincode(#[from] bincode::Error),

    /// The decoded entry's `(func_raw, seeds)` did not match the
    /// caller's expected key. Most likely a hash collision with a
    /// different cache entry; treat as a miss.
    #[error("key mismatch: expected ({expected_func}, {expected_seeds:?}), got ({got_func}, {got_seeds:?})")]
    KeyMismatch {
        /// FuncId.raw() the caller looked up.
        expected_func: u32,
        /// Seed key the caller looked up.
        expected_seeds: Vec<String>,
        /// FuncId.raw() found in the payload.
        got_func: u32,
        /// Seed key found in the payload.
        got_seeds: Vec<String>,
    },
}

/// Encode an entry for the fact store.
pub fn encode(entry: &TaintGraphEntry) -> Vec<u8> {
    bincode::serialize(entry).expect("bincode encoding of TaintGraphEntry never fails")
}

/// Decode bytes produced by [`encode`] back into a [`TaintGraphEntry`].
pub fn decode(bytes: &[u8]) -> Result<TaintGraphEntry, DecodeError> {
    Ok(bincode::deserialize(bytes)?)
}

/// Decode and verify the entry's key matches the caller's
/// expectation. Used after a fact-store hit to catch the
/// astronomically rare hash collision.
pub fn decode_verified(
    bytes: &[u8],
    expected_func: FuncId,
    expected_seeds: &[String],
) -> Result<TaintGraphEntry, DecodeError> {
    let entry = decode(bytes)?;
    if entry.func_raw != expected_func.raw() || entry.seeds.as_slice() != expected_seeds {
        return Err(DecodeError::KeyMismatch {
            expected_func: expected_func.raw(),
            expected_seeds: expected_seeds.to_vec(),
            got_func: entry.func_raw,
            got_seeds: entry.seeds.clone(),
        });
    }
    Ok(entry)
}

/// Hash the compound `(FuncId, sorted_seed_key)` into the `u64`
/// fact-store key. Same hash algorithm as the rest of the project
/// (FNV-1a-64 via [`bonsai_hash`]).
pub fn factstore_key(func: FuncId, seeds: &[String]) -> u64 {
    let mut hasher = Hasher::new();
    hasher.absorb(&func.raw().to_le_bytes());
    hasher.absorb_separator();
    for seed in seeds {
        hasher.absorb(seed.as_bytes());
        hasher.absorb_separator();
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_entry_roundtrips() {
        let entry = TaintGraphEntry::default();
        let bytes = encode(&entry);
        let decoded = decode(&bytes).expect("decode");
        assert_eq!(decoded.func_raw, 0);
        assert!(decoded.seeds.is_empty());
    }

    #[test]
    fn entry_roundtrips_with_seeds() {
        let entry = TaintGraphEntry {
            func_raw: 42,
            seeds: vec!["request".to_string(), "user".to_string()],
            graph: EntryTaintGraph::default(),
        };
        let bytes = encode(&entry);
        let decoded = decode(&bytes).expect("decode");
        assert_eq!(decoded.func_raw, 42);
        assert_eq!(decoded.seeds, vec!["request".to_string(), "user".to_string()]);
    }

    #[test]
    fn decode_verified_accepts_matching_key() {
        let entry = TaintGraphEntry {
            func_raw: 42,
            seeds: vec!["a".to_string(), "b".to_string()],
            graph: EntryTaintGraph::default(),
        };
        let bytes = encode(&entry);
        let seeds: Vec<String> = vec!["a".to_string(), "b".to_string()];
        let decoded = decode_verified(&bytes, FuncId::new(42), &seeds).expect("verified decode");
        assert_eq!(decoded.func_raw, 42);
    }

    #[test]
    fn decode_verified_rejects_mismatched_func() {
        let entry = TaintGraphEntry {
            func_raw: 42,
            seeds: vec!["a".to_string()],
            graph: EntryTaintGraph::default(),
        };
        let bytes = encode(&entry);
        let seeds = vec!["a".to_string()];
        match decode_verified(&bytes, FuncId::new(99), &seeds) {
            Err(DecodeError::KeyMismatch { .. }) => {}
            other => panic!("expected KeyMismatch, got {other:?}"),
        }
    }

    #[test]
    fn decode_verified_rejects_mismatched_seeds() {
        let entry = TaintGraphEntry {
            func_raw: 42,
            seeds: vec!["a".to_string()],
            graph: EntryTaintGraph::default(),
        };
        let bytes = encode(&entry);
        let seeds = vec!["different".to_string()];
        match decode_verified(&bytes, FuncId::new(42), &seeds) {
            Err(DecodeError::KeyMismatch { .. }) => {}
            other => panic!("expected KeyMismatch, got {other:?}"),
        }
    }

    #[test]
    fn factstore_key_is_deterministic() {
        let a = factstore_key(FuncId::new(7), &["alpha".to_string(), "beta".to_string()]);
        let b = factstore_key(FuncId::new(7), &["alpha".to_string(), "beta".to_string()]);
        assert_eq!(a, b);
    }

    #[test]
    fn factstore_key_distinguishes_different_inputs() {
        let a = factstore_key(FuncId::new(7), &["alpha".to_string()]);
        let b = factstore_key(FuncId::new(7), &["beta".to_string()]);
        let c = factstore_key(FuncId::new(8), &["alpha".to_string()]);
        let d = factstore_key(FuncId::new(7), &["alpha".to_string(), "beta".to_string()]);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(b, c);
    }

    #[test]
    fn factstore_key_distinguishes_seed_partition() {
        // FNV-1a with null separators must distinguish list shapes.
        let a = factstore_key(FuncId::new(0), &["ab".to_string(), "c".to_string()]);
        let b = factstore_key(FuncId::new(0), &["a".to_string(), "bc".to_string()]);
        assert_ne!(a, b);
    }
}
