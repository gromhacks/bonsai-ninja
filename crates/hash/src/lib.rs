#![deny(missing_docs)]
//! Stable content-hash digests for bonsai-ninja IDs.
//!
//! Every persisted, user-facing identifier in the project (`S:`, `F:`,
//! `G:`, `E:`, `N:`, `R:`, `T:`, `P:`, dataflow cache content hashes,
//! span-cache keys, paging cursor ids) is built from FNV-1a-64. We
//! deliberately do not use `ahash` or `std::hash::DefaultHasher` for
//! these IDs: those seed from per-process randomness and would break
//! the "same input → same digest across runs and across hosts"
//! contract every cache reload, every fingerprint comparison, and
//! every cross-process workflow depends on.
//!
//! ## API surface
//!
//! - [`fnv1a_str_slice64`] — null-separated digest of `&[&str]`.
//! - [`fnv1a_names64`] — same digest, owned `&[String]` input. The
//!   legacy spelling kept for ergonomic call sites that already hold
//!   a `Vec<String>`.
//! - [`fnv1a_bytes64`] — digest of a single byte slice. Used for
//!   content fingerprints (file contents, package-set bytes).
//! - [`fnv1a_low32`] — low 32 bits of a 64-bit digest, kept for the
//!   legacy 8-hex IDs (`E:`, `N:`, `R:`, `T:`, `P:`).
//! - [`Hasher`] — streaming builder for composite digests where the
//!   input is built from heterogeneous parts (e.g. paging cursor IDs).

/// FNV-1a 64-bit offset basis (RFC-specified seed value).
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64-bit prime (RFC-specified multiplier).
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a-64 digest over a slice of strings, with a single null byte
/// separator between entries so `["ab", "c"]` and `["a", "bc"]`
/// produce different digests.
#[must_use]
pub fn fnv1a_str_slice64(parts: &[&str]) -> u64 {
    let mut hasher = Hasher::new();
    for part in parts {
        hasher.absorb(part.as_bytes());
        hasher.absorb_separator();
    }
    hasher.finish()
}

/// Convenience overload of [`fnv1a_str_slice64`] for callers that
/// already own a `&[String]`. Same digest as `fnv1a_str_slice64` over
/// the equivalent `&[&str]`.
#[must_use]
pub fn fnv1a_names64(names: &[String]) -> u64 {
    let mut hasher = Hasher::new();
    for name in names {
        hasher.absorb(name.as_bytes());
        hasher.absorb_separator();
    }
    hasher.finish()
}

/// Low 32 bits of [`fnv1a_names64`]. Used by legacy 8-hex IDs.
#[must_use]
pub fn fnv1a_names_low32(names: &[String]) -> u32 {
    fnv1a_low32(fnv1a_names64(names))
}

/// FNV-1a-64 digest of a single byte slice. No separators, no
/// preprocessing. Used for content fingerprints over arbitrary bytes.
#[must_use]
pub fn fnv1a_bytes64(bytes: &[u8]) -> u64 {
    let mut hasher = Hasher::new();
    hasher.absorb(bytes);
    hasher.finish()
}

/// Convert a 64-bit digest to its low 32 bits. Kept as a named helper
/// so the legacy 8-hex IDs (`E:`, `N:`, `R:`, `T:`, `P:`) all share
/// one explicit truncation point.
#[must_use]
pub fn fnv1a_low32(digest: u64) -> u32 {
    (digest & 0xFFFF_FFFF) as u32
}

/// Streaming FNV-1a-64 builder for composite digests.
///
/// Use [`Hasher::absorb`] to feed a byte slice and
/// [`Hasher::absorb_separator`] to delimit logical fields when the
/// input shape would otherwise be ambiguous (e.g. concatenating
/// `(callee, args)` digests).
#[derive(Clone, Copy, Debug)]
pub struct Hasher {
    digest: u64,
}

impl Hasher {
    /// Construct a fresh hasher seeded with the FNV-1a-64 offset basis.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            digest: FNV_OFFSET_BASIS,
        }
    }

    /// Absorb a byte slice into the running digest. Bytes are folded
    /// in order; absorbing in chunks vs. one shot produces the same
    /// final digest.
    pub fn absorb(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.digest ^= u64::from(byte);
            self.digest = self.digest.wrapping_mul(FNV_PRIME);
        }
    }

    /// Absorb a single null byte. Use to separate logical fields
    /// (entries in a list, key/value pairs, etc.) so the digest
    /// distinguishes shapes that share the same flattened bytes.
    pub fn absorb_separator(&mut self) {
        self.absorb(&[0]);
    }

    /// Return the final 64-bit digest. The hasher is consumed —
    /// callers that need to continue feeding bytes should clone the
    /// hasher first.
    #[must_use]
    pub const fn finish(self) -> u64 {
        self.digest
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_offset_basis() {
        assert_eq!(fnv1a_str_slice64(&[]), FNV_OFFSET_BASIS);
        assert_eq!(fnv1a_bytes64(&[]), FNV_OFFSET_BASIS);
        assert_eq!(fnv1a_names64(&[]), FNV_OFFSET_BASIS);
    }

    #[test]
    fn null_separator_distinguishes_partitions() {
        let a = fnv1a_str_slice64(&["ab", "c"]);
        let b = fnv1a_str_slice64(&["a", "bc"]);
        assert_ne!(a, b, "null separator must distinguish list shapes");
    }

    #[test]
    fn names_and_str_slice_match_for_same_input() {
        let names = vec!["alpha".to_string(), "beta".to_string()];
        let str_slice: Vec<&str> = names.iter().map(String::as_str).collect();
        assert_eq!(fnv1a_names64(&names), fnv1a_str_slice64(&str_slice));
    }

    #[test]
    fn bytes64_is_standard_fnv1a_64() {
        // Reference vector: FNV-1a-64 of "foobar" = 0x85944171f73967e8.
        // (RFC test vector.)
        assert_eq!(fnv1a_bytes64(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn low32_is_truncation_of_64() {
        let names = vec!["x".to_string(), "y".to_string()];
        let full = fnv1a_names64(&names);
        assert_eq!(fnv1a_names_low32(&names), (full & 0xFFFF_FFFF) as u32);
        assert_eq!(fnv1a_low32(full), (full & 0xFFFF_FFFF) as u32);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let one_shot = fnv1a_bytes64(b"abc");
        let mut hasher = Hasher::new();
        hasher.absorb(b"a");
        hasher.absorb(b"b");
        hasher.absorb(b"c");
        assert_eq!(hasher.finish(), one_shot);
    }

    #[test]
    fn streaming_with_separators_matches_str_slice() {
        let names = ["alpha", "beta", "gamma"];
        let mut hasher = Hasher::new();
        for name in &names {
            hasher.absorb(name.as_bytes());
            hasher.absorb_separator();
        }
        assert_eq!(hasher.finish(), fnv1a_str_slice64(&names));
    }
}
