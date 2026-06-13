//! Secondary output filters (`--contains` / `--not-contains`).
//!
//! These are POST-query / POST-analysis filters: they shape which
//! result rows render, never what the engine computes. A command
//! builds its full row/finding set, then `SecondaryFilter::retain`
//! drops the rows whose searchable text fails the predicate. Because
//! the filter runs over an already-built (and, for the expensive
//! commands, cached) result, iterating on `--contains` re-renders
//! rather than re-analyzing.
//!
//! Matching is case-insensitive substring matching over the row's
//! string *values* (not its field names) — for a structured row this
//! is the set of string leaves of its JSON form, which is exactly the
//! file paths, names, code snippets, and rule ids a developer greps
//! for, without spurious hits on JSON keys.

use std::sync::OnceLock;

/// Process-wide secondary filter, set once at startup from the active
/// command's `--contains` / `--not-contains` flags. Defaults to an
/// inactive filter that keeps every row.
static SECONDARY_FILTER: OnceLock<SecondaryFilter> = OnceLock::new();

pub(crate) fn init(contains: &[String], not_contains: &[String]) {
    let _ = SECONDARY_FILTER.set(SecondaryFilter::new(contains, not_contains));
}

pub(crate) fn active() -> &'static SecondaryFilter {
    SECONDARY_FILTER.get_or_init(SecondaryFilter::inactive)
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SecondaryFilter {
    /// Every needle here must appear (AND). Lower-cased once.
    contains: Vec<String>,
    /// If any needle here appears, the row is dropped. Lower-cased once.
    not_contains: Vec<String>,
}

impl SecondaryFilter {
    fn inactive() -> Self {
        Self::default()
    }

    pub(crate) fn new(contains: &[String], not_contains: &[String]) -> Self {
        let lower = |xs: &[String]| {
            xs.iter()
                .map(|s| s.to_lowercase())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        };
        Self {
            contains: lower(contains),
            not_contains: lower(not_contains),
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        !self.contains.is_empty() || !self.not_contains.is_empty()
    }

    /// True when `haystack` (already the row's combined searchable
    /// text) satisfies every `--contains` and no `--not-contains`.
    pub(crate) fn matches_text(&self, haystack: &str) -> bool {
        if !self.is_active() {
            return true;
        }
        let lower = haystack.to_lowercase();
        self.contains.iter().all(|needle| lower.contains(needle.as_str()))
            && !self
                .not_contains
                .iter()
                .any(|needle| lower.contains(needle.as_str()))
    }

    /// Match a row by the string leaves of its JSON form. Field names
    /// are excluded so `--contains source` filters on values, not the
    /// `"source"` key. Falls back to keeping the row if it can't be
    /// serialized (never silently drops on an encode error).
    pub(crate) fn matches_value<T: serde::Serialize>(&self, row: &T) -> bool {
        if !self.is_active() {
            return true;
        }
        let Ok(value) = serde_json::to_value(row) else {
            return true;
        };
        let mut text = String::new();
        collect_string_leaves(&value, &mut text);
        self.matches_text(&text)
    }

    /// Drop the rows whose serialized string-values fail the filter.
    /// No-op when the filter is inactive.
    pub(crate) fn retain<T: serde::Serialize>(&self, rows: &mut Vec<T>) {
        if !self.is_active() {
            return;
        }
        rows.retain(|row| self.matches_value(row));
    }
}

/// Append every string leaf of `value` to `out`, separated by `\n` so
/// substrings can't bridge two unrelated leaves.
fn collect_string_leaves(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::String(s) => {
            out.push_str(s);
            out.push('\n');
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_string_leaves(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                collect_string_leaves(item, out);
            }
        }
        // Numbers / bools / null carry no developer-searchable text.
        _ => {}
    }
}

#[cfg(test)]
#[path = "filter_tests.rs"]
mod filter_tests;
