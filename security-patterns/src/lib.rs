//! Source-controlled default rulepack compiled into bonsai-ninja releases.
//!
//! Security meaning remains in the YAML files beside this crate. The Rust
//! surface exposes only their deterministic, compressed archive and content
//! identity so downstream crates can embed the exact published rules without
//! depending on a repository-relative path.

/// Header that identifies the bundled rulepack archive format.
pub const ARCHIVE_MAGIC: &[u8; 8] = b"BNSRP001";

/// Deterministic zstd-compressed archive of `VERSION`, `metadata.yml`, and all
/// language rule YAML files in this package.
pub const ARCHIVE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bundled-rulepack.bin.zst"));

/// SHA-256 identity of the uncompressed archive's paths and bytes.
pub const IDENTITY: &str = include!(concat!(env!("OUT_DIR"), "/bundled-rulepack-id.rs"));
