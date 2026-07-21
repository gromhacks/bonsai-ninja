//! Workspace-wide string interner.
//!
//! At write time, [`StringPoolBuilder`] hands out compact `u32` ids for
//! each unique string and accumulates the underlying bytes. At read
//! time, [`StringPoolView`] borrows directly from the mmap'd file so
//! `get(id)` is a pointer add + bounds check — no allocation.
//!
//! The motivation is that bonsai-ninja's per-function caches are
//! dominated by repeated identifier names. A 100K-function workspace
//! has perhaps a few thousand unique names; with `String` everywhere
//! the same `"validate_input"` lives in memory thousands of times.
//! Replacing every name with a `StrId` collapses that to one stored
//! copy on disk and one pointer at read time.
//!
//! ## On-disk shape
//!
//! ```text
//! [bytes section]    contiguous UTF-8, no separators
//! [offsets section]  [u32; count + 1]   // sentinel last entry
//! ```
//!
//! The offsets section is `count + 1` entries: each string `i` covers
//! `bytes[offsets[i]..offsets[i + 1]]`. The trailing sentinel is the
//! total bytes length so the last string is sliced uniformly.

use crate::error::{FactStoreError, FactStoreResult};
use ahash::AHashMap;
use serde::{Deserialize, Serialize};

/// Interned string id. Stable within one fact-store file. Different
/// files can reuse the same id for different strings — never compare
/// ids across files.
pub type StrId = u32;

/// Builder that interns strings and accumulates the bytes / offsets
/// sections destined for an on-disk fact store.
///
/// `intern("foo")` returns a deterministic id: the first call inserts
/// the string and returns a fresh id; subsequent calls return the same
/// id without re-appending.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StringPoolBuilder {
    bytes: Vec<u8>,
    offsets: Vec<u32>,
    /// Reverse-lookup `string → StrId`. Skipped at serialise time so
    /// the on-disk shape stays compact; rebuilt by [`Self::rebuild_lookup`]
    /// after deserialise.
    #[serde(skip)]
    by_str: AHashMap<String, StrId>,
    /// Whether `by_str` covers the complete canonical pool. When false it is
    /// a small delta index for strings added after a compiler persistence
    /// phase released the full reverse map.
    #[serde(skip)]
    lookup_complete: bool,
}

impl Default for StringPoolBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl StringPoolBuilder {
    /// Construct an empty builder. The empty pool serializes to a
    /// `count = 0` header entry plus a 4-byte trailing sentinel of
    /// `0` (the total bytes length).
    #[must_use]
    pub fn new() -> Self {
        Self {
            bytes: Vec::new(),
            offsets: Vec::new(),
            by_str: AHashMap::new(),
            lookup_complete: true,
        }
    }

    /// Pre-allocate capacity hints for the bytes and offsets sections.
    /// Useful when the caller knows the rough scale of the pool.
    #[must_use]
    pub fn with_capacity(byte_capacity: usize, string_capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(byte_capacity),
            offsets: Vec::with_capacity(string_capacity),
            by_str: AHashMap::with_capacity(string_capacity),
            lookup_complete: true,
        }
    }

    /// Intern `s` and return its id. Subsequent calls with the same
    /// `s` return the same id without copying the bytes again.
    ///
    /// Panics on overflow of the 32-bit id space. A workspace with
    /// 2³² unique strings would require redesigning the id type, not
    /// a runtime fallback. (Same rationale as `SymbolId` / `FileId`.)
    pub fn intern(&mut self, s: &str) -> StrId {
        if let Some(&id) = self.by_str.get(s) {
            return id;
        }
        if !self.lookup_complete {
            if let Some(id) = (0..self.offsets.len())
                .map(|index| index as StrId)
                .find(|id| self.get(*id) == Some(s))
            {
                return id;
            }
        }
        let id_usize = self.offsets.len();
        let id = u32::try_from(id_usize).expect("string pool overflow: > 2^32 unique strings");
        let offset =
            u32::try_from(self.bytes.len()).expect("string pool overflow: > 4 GiB of interned bytes");
        self.offsets.push(offset);
        self.bytes.extend_from_slice(s.as_bytes());
        self.by_str.insert(s.to_string(), id);
        id
    }

    /// Number of unique strings in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    /// True iff the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }

    /// Total length in bytes of the bytes section.
    #[must_use]
    pub fn bytes_len(&self) -> usize {
        self.bytes.len()
    }

    /// Length in bytes of the offsets section as it will appear on
    /// disk: `(count + 1) * 4`.
    #[must_use]
    pub fn offsets_section_len(&self) -> usize {
        (self.offsets.len() + 1) * 4
    }

    /// Rebuild the `by_str` reverse-lookup map from the bytes +
    /// offsets vectors. Called after deserialise (where `by_str` is
    /// skipped) so subsequent [`Self::intern`] calls correctly
    /// dedupe against pre-existing strings.
    pub fn rebuild_lookup(&mut self) {
        self.by_str.clear();
        self.by_str.reserve(self.offsets.len());
        for i in 0..self.offsets.len() {
            let id = i as StrId;
            if let Some(s) = self.get(id) {
                self.by_str.insert(s.to_string(), id);
            }
        }
        self.lookup_complete = true;
    }

    /// Release the build/query reverse index while retaining the canonical
    /// serialized string vectors.
    ///
    /// This is useful at a compiler persistence boundary where the builder is
    /// being consumed. The reverse map is deliberately skipped by Serde, so
    /// dropping it cannot change the wire artifact; a subsequently decoded
    /// pool rebuilds the same index through [`Self::rebuild_lookup`].
    pub fn release_lookup(&mut self) {
        self.by_str = AHashMap::new();
        self.lookup_complete = false;
    }

    /// Look up `name`, returning its id if already interned.
    ///
    /// This is O(1) while the complete reverse index is present. A consumed
    /// compiler build can release that index before persistence; lookups then
    /// scan the canonical pool exactly and consult the small post-release
    /// delta map before returning a miss.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<StrId> {
        if let Some(id) = self.by_str.get(name) {
            return Some(*id);
        }
        if self.lookup_complete {
            return None;
        }
        (0..self.offsets.len())
            .map(|index| index as StrId)
            .find(|id| self.get(*id) == Some(name))
    }

    /// Look up an id back to its string. O(1). Returns `None` for
    /// unknown ids — useful for asserts but not normally needed by
    /// the writer.
    #[must_use]
    pub fn get(&self, id: StrId) -> Option<&str> {
        let idx = id as usize;
        let start = *self.offsets.get(idx)? as usize;
        let end = self
            .offsets
            .get(idx + 1)
            .copied()
            .unwrap_or_else(|| u32::try_from(self.bytes.len()).expect("u32 overflow"))
            as usize;
        let bytes = self.bytes.get(start..end)?;
        // Safety: every byte we appended originated from `&str` so
        // the slice is valid UTF-8 by construction. We use the safe
        // `from_utf8` here because the crate forbids `unsafe`.
        std::str::from_utf8(bytes).ok()
    }

    /// Borrowed view of the bytes section. Used by the writer.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Encode the offsets section into its on-disk byte form. The
    /// returned vector has `(count + 1) * 4` bytes: every offset
    /// followed by a sentinel = `bytes.len()` so readers can slice
    /// the last string uniformly.
    #[must_use]
    pub fn offsets_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.offsets_section_len());
        for &offset in &self.offsets {
            out.extend_from_slice(&offset.to_le_bytes());
        }
        let sentinel =
            u32::try_from(self.bytes.len()).expect("string pool overflow: > 4 GiB of interned bytes");
        out.extend_from_slice(&sentinel.to_le_bytes());
        out
    }
}

/// Borrowed read-only view of an on-disk string pool. Cheap to
/// construct (just bounds-checks the offsets section); cheap to use
/// (each `get` is a pair of u32 reads + a slice).
///
/// Construction validates structural invariants once; subsequent
/// `get` calls assume they hold.
#[derive(Copy, Clone, Debug)]
pub struct StringPoolView<'mmap> {
    bytes: &'mmap [u8],
    offsets: &'mmap [u8],
    count: u32,
}

impl<'mmap> StringPoolView<'mmap> {
    /// Construct a view over `bytes_section` + `offsets_section`,
    /// validating that every offset is in range and forms a
    /// non-decreasing sequence terminated by a sentinel = bytes_len.
    ///
    /// The `count` argument is the number of strings, not the number
    /// of offset entries (which is `count + 1` due to the sentinel).
    pub fn new(
        bytes_section: &'mmap [u8],
        offsets_section: &'mmap [u8],
        count: u32,
    ) -> FactStoreResult<Self> {
        let expected_offsets_len = (count as usize)
            .checked_add(1)
            .and_then(|n| n.checked_mul(4))
            .ok_or(FactStoreError::BadStringPool("offsets length overflow"))?;
        if offsets_section.len() != expected_offsets_len {
            return Err(FactStoreError::BadStringPool(
                "offsets section length disagrees with declared string count",
            ));
        }
        // Validate that every offset is within bytes_section and the
        // sequence is non-decreasing. We do this once at construction
        // so individual `get` calls can rely on it.
        let mut prev: u32 = 0;
        for i in 0..=count as usize {
            let raw = &offsets_section[i * 4..(i + 1) * 4];
            let offset = u32::from_le_bytes(raw.try_into().expect("4 bytes from a 4n slice"));
            if (offset as usize) > bytes_section.len() {
                return Err(FactStoreError::BadStringPool("offset points past bytes section"));
            }
            if i > 0 && offset < prev {
                return Err(FactStoreError::BadStringPool(
                    "offsets section is not non-decreasing",
                ));
            }
            prev = offset;
        }
        // Sentinel must equal bytes_section length so the last string
        // slices to a known endpoint.
        if (prev as usize) != bytes_section.len() {
            return Err(FactStoreError::BadStringPool(
                "trailing sentinel does not match bytes section length",
            ));
        }
        Ok(Self {
            bytes: bytes_section,
            offsets: offsets_section,
            count,
        })
    }

    /// Number of strings in the pool.
    #[must_use]
    pub fn len(&self) -> u32 {
        self.count
    }

    /// True iff the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Look up the string for `id`. Returns `None` if `id >= len()`.
    /// O(1) — two u32 reads + a slice.
    #[must_use]
    pub fn get(&self, id: StrId) -> Option<&'mmap str> {
        if id >= self.count {
            return None;
        }
        let i = id as usize;
        // Read offsets[i] and offsets[i + 1] (the sentinel guarantees
        // i + 1 is in range when i < count).
        let start_bytes = &self.offsets[i * 4..(i + 1) * 4];
        let end_bytes = &self.offsets[(i + 1) * 4..(i + 2) * 4];
        let start = u32::from_le_bytes(start_bytes.try_into().ok()?) as usize;
        let end = u32::from_le_bytes(end_bytes.try_into().ok()?) as usize;
        let slice = self.bytes.get(start..end)?;
        std::str::from_utf8(slice).ok()
    }

    /// Look up the string for `id`, returning a typed error if the id
    /// is out of range. Use this when callers care about distinguishing
    /// "id not in pool" from other failures.
    pub fn get_or_err(&self, id: StrId) -> FactStoreResult<&'mmap str> {
        self.get(id).ok_or(FactStoreError::BadStringId {
            id,
            count: self.count,
        })
    }
}

#[cfg(test)]
#[path = "string_pool_tests.rs"]
mod tests;
