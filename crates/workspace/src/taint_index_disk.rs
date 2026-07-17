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
//! Payload shape (MessagePack):
//!
//! ```ignore
//! struct OnDiskTaintGraphEntry {
//!     func_raw: u32,
//!     seeds: Vec<String>,
//!     graph: EntryTaintGraph,
//! }
//! ```

use bonsai_common::{wire, FuncId};
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
    /// MessagePack could not parse the bytes — the file was truncated or
    /// corrupt.
    #[error("MessagePack: {0}")]
    Wire(#[from] wire::DecodeError),

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
    wire::encode(entry).expect("MessagePack encoding of TaintGraphEntry never fails")
}

/// Decode bytes produced by [`encode`] back into a [`TaintGraphEntry`].
pub fn decode(bytes: &[u8]) -> Result<TaintGraphEntry, DecodeError> {
    Ok(wire::decode(bytes)?)
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
#[path = "taint_index_disk_tests.rs"]
mod tests;
