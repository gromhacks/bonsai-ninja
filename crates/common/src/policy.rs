//! Shared analysis policy fingerprints.
//!
//! These constants are persisted in cache headers by lower layers that
//! cannot depend on higher-level crates. Bump the relevant fingerprint
//! whenever the named policy changes semantics.

/// Versioned fingerprint for security matcher policy that can affect
/// source/sink/sanitizer classification over cached graph facts.
///
/// Bump this when `bonsai_security::matcher` changes strict attribute
/// matching, import/package gating, or method-chain fallback semantics
/// in a way that can change matched rule sites. Also bump
/// when the resolver narrows in ways that can change which callees are
/// reachable from a call site (e.g. visibility / module_path filtering
/// per `docs/contributing/design-patterns.mdx::Semantic Resolution Always`),
/// or when IDG/taint propagation semantics change enough to affect
/// source-to-sink reachability.
pub const MATCHER_POLICY_FINGERPRINT: u128 = 0x4d41_5443_4845_525f_504f_4c49_4359_0034_u128;
const _: () = assert!(MATCHER_POLICY_FINGERPRINT != 0);
