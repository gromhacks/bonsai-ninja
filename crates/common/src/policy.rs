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
// v63: terminal guard rejection consumes typed exits, never callee spellings;
// loop transfers cannot be erased by unreachable later return/throw events.
// v62: required terminal guard proofs cannot be bypassed by tainted-call
// overlap or a value-flow attachment to an outer predicate-discarding call.
// v61: terminal predicate guards join exact call results, never nested calls;
// null comparisons use an explicit rule-owned result-domain contract.
// v60: configured regex passthroughs retain regex-engine semantics without an
// unsound source-text literal prefilter that suppressed valid transfer sites.
// Exact public transfer-site lists are normalized once before binary lookup.
// v59: CFG break/continue cleanup unwinds only finally scopes exited by the
// exact compiler-selected loop destination; classes without bases participate
// in receiver-ancestry collision checks rather than inheriting unrelated bases.
// Qualified type/call identities no longer fall back to unrelated leaf names;
// callback argument relations preserve every span and bind named/receiver
// formals through the same typed mapping as IDG stitching.
// v58: rule-declared imported/runtime-global callable identities fail closed
// on compiler-proven lexical/workspace collisions, and semantic decorator
// configuration no longer becomes a lossy raw-source anchor.
// v57: rules can require exact fields in a configured receiver's factory
// argument, and prototype guards prove membership against the collection's
// exact literal values rather than treating every membership test alike.
// v56: regex callees consume adapter-proven declared receiver types without
// collapsing fluent call receivers, nested receiver-call operands retain
// their input dependencies, and typed guard joins compare exact aggregate
// options and configured substitution maps.
// v54: typed receiver evidence is authoritative for receiver-constrained
// rules, and qualified/import candidates use structural compiler names rather
// than a shared source-separator vocabulary.
// v64: dependency evidence comes from parsed manifest fields or exact
// compiler declaration arguments; arbitrary manifest text is not proof.
// v65: code manifests retain workspace-local import ambiguity, and package
// context fingerprints include the exact projection and coverage state.
// v66: runtime/import identity retains exact nested callable scope, including
// recursion and unrelated owners; parameter/default and prefix constraints.
pub const MATCHER_POLICY_FINGERPRINT: u128 = 0x4d41_5443_4845_525f_504f_4c49_4359_0042_u128;
const _: () = assert!(MATCHER_POLICY_FINGERPRINT != 0);
