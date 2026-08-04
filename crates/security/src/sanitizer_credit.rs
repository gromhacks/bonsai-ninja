//! Rulepack-driven sanitizer-tag-to-sink-tag credit.
//!
//! Pure data: given a sanitizer's `tag` and a sink's `tag`, decide
//! whether the sanitizer's filtering applies to that sink. The answer
//! does NOT mean the value is safe — it means the developer attempted
//! to filter for the right context. Findings whose chain has a
//! credited sanitizer are surfaced as `status: sanitized` (review for
//! bypass), per `security-spec.mdx`.
//!
use crate::loader::RulepackMetadata;

/// True when a sanitizer with `san_tag` clears a sink with `sink_tag`.
///
/// Decision order:
///   1. If either tag is absent, return `false` (no claim either way).
///   2. If they match exactly, return `true` — same-class credit.
///   3. If rulepack metadata maps `san_tag` to `sink_tag`, return
///      `true` — cross-tag credit.
///   4. Otherwise `false` — wrong-context case.
#[must_use]
pub(crate) fn sanitizer_credits_sink_tag(
    metadata: &RulepackMetadata,
    san_tag: Option<&str>,
    sink_tag: Option<&str>,
) -> bool {
    let (Some(s), Some(k)) = (san_tag, sink_tag) else {
        return false;
    };
    if s == k {
        return true;
    }
    metadata
        .sanitizer_credits
        .get(s)
        .is_some_and(|sinks| sinks.iter().any(|sink| sink == k))
}

/// True when `san_tag` is a vocabulary entry the engine recognises but
/// whose credit list is intentionally empty. Status assembly uses this to
/// avoid mis-classifying rulepack-declared passthrough or inventory markers
/// as `WrongContext`: they made no claim of clearing taint to begin with, so
/// a chain that only contains them stays `Unsanitized`.
#[must_use]
pub(crate) fn sanitizer_tag_is_recognized_non_crediting(metadata: &RulepackMetadata, san_tag: &str) -> bool {
    metadata.sanitizer_credits.get(san_tag).is_some_and(Vec::is_empty)
}

#[cfg(test)]
#[path = "sanitizer_credit_tests.rs"]
mod tests;
