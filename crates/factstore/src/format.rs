//! On-disk binary format for the fact store.
//!
//! ## Layout
//!
//! ```text
//! [Header: 96 bytes — fixed]
//! [String pool: variable]
//!   bytes_section:   contiguous UTF-8
//!   offsets_section: [u32; string_count + 1]   // sentinel last entry
//! [Index: index_count * 32 bytes — sorted by `key`]
//!   IndexEntry { key, body_hash, payload_offset, payload_len, _pad }
//! [Payloads: variable]
//!   raw bytes; each entry sliced via the index's (offset, len)
//! ```
//!
//! Every offset in the header is absolute from the start of the file.
//! Sections are tightly packed; readers verify each section's bounds
//! against the file length at open time.
//!
//! ## Endianness + alignment
//!
//! All multi-byte integers are little-endian (matches every platform
//! we ship on; we don't byte-swap on big-endian — the file format is
//! deliberately not portable across endianness, only across same-endian
//! machines).
//!
//! ## Versioning
//!
//! [`FORMAT_VERSION`] bumps when any layout, encoding, or invariant
//! changes. Readers reject any other version.

/// Magic bytes at offset 0. ASCII; not null-terminated. Spelling
/// chosen to be human-recognisable in `xxd` output.
pub const MAGIC: [u8; 8] = *b"BNSAIFC1";

/// Current on-disk format version. Bump on any layout change.
pub const FORMAT_VERSION: u32 = 1;

/// Fixed header size in bytes. The header is always exactly this many
/// bytes regardless of contents — readers can mmap and reinterpret.
pub const HEADER_SIZE: usize = 96;

/// Fixed index entry size in bytes. Entries are tightly packed and
/// sorted by `key` ascending so readers can binary-search.
pub const INDEX_ENTRY_SIZE: usize = 32;

/// Persisted file header. Repr-C + packed multiples of 8 so the
/// struct lays out the same on every same-endian platform we ship on.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Header {
    /// `MAGIC`. Validates this file is a fact store.
    pub magic: [u8; 8],
    /// `FORMAT_VERSION`.
    pub format_version: u32,
    /// Caller-defined table tag. Distinguishes a value-flow store from
    /// a dataflow store when multiple stores share a directory.
    pub table_id: u32,
    /// Caller-defined invalidation hash (typically the matcher policy
    /// fingerprint or analysis-pipeline hash). Reader rejects on
    /// mismatch.
    pub pipeline_hash: u64,
    /// Absolute byte offset of the string pool's bytes section.
    pub string_pool_offset: u64,
    /// Length in bytes of the string pool's bytes section.
    pub string_pool_bytes_len: u64,
    /// Number of interned strings. The offsets section that
    /// immediately follows the bytes section has `string_count + 1`
    /// `u32` entries (the trailing sentinel = `string_pool_bytes_len`).
    pub string_count: u64,
    /// Absolute byte offset of the index section.
    pub index_offset: u64,
    /// Number of [`IndexEntry`] records. The index occupies exactly
    /// `index_count * INDEX_ENTRY_SIZE` bytes.
    pub index_count: u64,
    /// Absolute byte offset of the payload section.
    pub payload_offset: u64,
    /// Length in bytes of the payload section.
    pub payload_len: u64,
    /// Reserved for future use; must be zero in v1.
    pub reserved: [u8; 8],
}

impl Header {
    /// Encode the header into its on-disk byte form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0..8].copy_from_slice(&self.magic);
        out[8..12].copy_from_slice(&self.format_version.to_le_bytes());
        out[12..16].copy_from_slice(&self.table_id.to_le_bytes());
        out[16..24].copy_from_slice(&self.pipeline_hash.to_le_bytes());
        out[24..32].copy_from_slice(&self.string_pool_offset.to_le_bytes());
        out[32..40].copy_from_slice(&self.string_pool_bytes_len.to_le_bytes());
        out[40..48].copy_from_slice(&self.string_count.to_le_bytes());
        out[48..56].copy_from_slice(&self.index_offset.to_le_bytes());
        out[56..64].copy_from_slice(&self.index_count.to_le_bytes());
        out[64..72].copy_from_slice(&self.payload_offset.to_le_bytes());
        out[72..80].copy_from_slice(&self.payload_len.to_le_bytes());
        out[80..88].copy_from_slice(&self.reserved);
        // Bytes 88..96 are padding; left zero so the struct stays a
        // round 96 bytes for `mmap` reinterpretation friendliness.
        out
    }

    /// Decode a header from raw bytes. Returns `None` if the slice is
    /// shorter than [`HEADER_SIZE`] or the magic bytes don't match.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_SIZE {
            return None;
        }
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[0..8]);
        if magic != MAGIC {
            return None;
        }
        Some(Self {
            magic,
            format_version: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
            table_id: u32::from_le_bytes(bytes[12..16].try_into().ok()?),
            pipeline_hash: u64::from_le_bytes(bytes[16..24].try_into().ok()?),
            string_pool_offset: u64::from_le_bytes(bytes[24..32].try_into().ok()?),
            string_pool_bytes_len: u64::from_le_bytes(bytes[32..40].try_into().ok()?),
            string_count: u64::from_le_bytes(bytes[40..48].try_into().ok()?),
            index_offset: u64::from_le_bytes(bytes[48..56].try_into().ok()?),
            index_count: u64::from_le_bytes(bytes[56..64].try_into().ok()?),
            payload_offset: u64::from_le_bytes(bytes[64..72].try_into().ok()?),
            payload_len: u64::from_le_bytes(bytes[72..80].try_into().ok()?),
            reserved: bytes[80..88].try_into().ok()?,
        })
    }
}

/// One row in the on-disk index. Index entries are written sorted by
/// `key` ascending so readers can binary-search.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct IndexEntry {
    /// Caller's lookup key. For the per-function caches this is the
    /// `FuncId.raw()` zero-extended to 64 bits.
    pub key: u64,
    /// Content-address hash for the underlying source state. Readers
    /// can use this to detect "the function exists at this id but its
    /// source has changed since this entry was cached."
    pub body_hash: u64,
    /// Absolute byte offset of the entry's payload.
    pub payload_offset: u64,
    /// Length in bytes of the payload.
    pub payload_len: u32,
    /// Padding to bring [`IndexEntry`] up to 32 bytes. Must be zero
    /// in this format version. Reserved for future use (e.g. an entry
    /// kind discriminant when one store carries multiple value
    /// shapes).
    pub reserved: u32,
}

impl IndexEntry {
    /// Encode one index entry into its on-disk byte form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; INDEX_ENTRY_SIZE] {
        let mut out = [0u8; INDEX_ENTRY_SIZE];
        out[0..8].copy_from_slice(&self.key.to_le_bytes());
        out[8..16].copy_from_slice(&self.body_hash.to_le_bytes());
        out[16..24].copy_from_slice(&self.payload_offset.to_le_bytes());
        out[24..28].copy_from_slice(&self.payload_len.to_le_bytes());
        out[28..32].copy_from_slice(&self.reserved.to_le_bytes());
        out
    }

    /// Decode one index entry from raw bytes. Returns `None` if the
    /// slice is shorter than [`INDEX_ENTRY_SIZE`].
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < INDEX_ENTRY_SIZE {
            return None;
        }
        Some(Self {
            key: u64::from_le_bytes(bytes[0..8].try_into().ok()?),
            body_hash: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            payload_offset: u64::from_le_bytes(bytes[16..24].try_into().ok()?),
            payload_len: u32::from_le_bytes(bytes[24..28].try_into().ok()?),
            reserved: u32::from_le_bytes(bytes[28..32].try_into().ok()?),
        })
    }
}

#[cfg(test)]
#[path = "format_tests.rs"]
mod tests;
