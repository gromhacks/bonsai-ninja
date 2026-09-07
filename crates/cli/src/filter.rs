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

pub(crate) fn init(contains: &[String], not_contains: &[String], regex: bool) -> Result<(), regex::Error> {
    let filter = if regex {
        SecondaryFilter::with_regex(contains, not_contains)?
    } else {
        SecondaryFilter::new(contains, not_contains)
    };
    let _ = SECONDARY_FILTER.set(filter);
    Ok(())
}

pub(crate) fn active() -> &'static SecondaryFilter {
    SECONDARY_FILTER.get_or_init(SecondaryFilter::inactive)
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SecondaryFilter {
    /// Every needle here must appear (AND). Lower-cased once.
    contains: Vec<String>,
    /// Opt-in regex alternatives to literal needles; still combined with AND.
    contains_regex: Vec<regex::Regex>,
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
            contains_regex: Vec::new(),
            not_contains: lower(not_contains),
        }
    }

    fn with_regex(contains: &[String], not_contains: &[String]) -> Result<Self, regex::Error> {
        let mut filter = Self::new(&[], not_contains);
        filter.contains_regex = contains
            .iter()
            .filter(|pattern| !pattern.is_empty())
            .map(|pattern| regex::Regex::new(pattern))
            .collect::<Result<_, _>>()?;
        Ok(filter)
    }

    pub(crate) fn is_active(&self) -> bool {
        !self.contains.is_empty() || !self.contains_regex.is_empty() || !self.not_contains.is_empty()
    }

    /// Stable view fingerprint for pagination/cursor identities. Secondary
    /// filters never belong in an analysis key, but two differently filtered
    /// views must not share page cursors.
    pub(crate) fn signature(&self) -> u64 {
        let mut hasher = bonsai_hash::Hasher::new();
        for value in &self.contains {
            hasher.absorb(b"contains");
            hasher.absorb_separator();
            hasher.absorb(value.as_bytes());
            hasher.absorb_separator();
        }
        for value in &self.not_contains {
            hasher.absorb(b"not-contains");
            hasher.absorb_separator();
            hasher.absorb(value.as_bytes());
            hasher.absorb_separator();
        }
        for pattern in &self.contains_regex {
            hasher.absorb(b"contains-regex");
            hasher.absorb_separator();
            hasher.absorb(pattern.as_str().as_bytes());
            hasher.absorb_separator();
        }
        hasher.finish()
    }

    /// Match one string leaf independently of unrelated row fields.
    #[cfg(test)]
    pub(crate) fn matches_text(&self, haystack: &str) -> bool {
        self.matches_parts(std::iter::once(haystack), &mut Vec::new(), &mut String::new())
    }

    fn matches_parts<'a>(
        &self,
        parts: impl Iterator<Item = &'a str>,
        matched: &mut Vec<bool>,
        lower: &mut String,
    ) -> bool {
        if !self.is_active() {
            return true;
        }
        matched.clear();
        matched.resize(self.contains.len() + self.contains_regex.len(), false);
        for part in parts {
            lower.clear();
            lower.extend(part.chars().flat_map(char::to_lowercase));
            if self
                .not_contains
                .iter()
                .any(|needle| lower.contains(needle.as_str()))
            {
                return false;
            }
            for (found, needle) in matched.iter_mut().zip(&self.contains) {
                *found |= lower.contains(needle.as_str());
            }
            for (found, pattern) in matched[self.contains.len()..]
                .iter_mut()
                .zip(&self.contains_regex)
            {
                *found |= pattern.is_match(part);
            }
        }
        matched.iter().all(|found| *found)
    }

    /// Match a row by the string leaves of its JSON form. Field names
    /// are excluded so `--contains source` filters on values, not the
    /// `"source"` key. Falls back to keeping the row if it can't be
    /// serialized (never silently drops on an encode error).
    pub(crate) fn matches_value<T: serde::Serialize>(&self, row: &T) -> bool {
        if !self.is_active() {
            return true;
        }
        let mut scratch = FilterScratch::default();
        self.matches_row(row, &mut scratch, None)
    }

    /// Match a serialized row without building a `serde_json::Value`: the
    /// JSON text is scanned for string values (object keys are skipped, the
    /// same leaf set `matches_value` sees) into a reusable buffer. `extra`
    /// adds one synthesized leaf (for example the rendered location) that
    /// is not a field of the row itself.
    pub(crate) fn matches_row<T: serde::Serialize>(
        &self,
        row: &T,
        scratch: &mut FilterScratch,
        extra: Option<&str>,
    ) -> bool {
        if !self.is_active() {
            return true;
        }
        scratch.json.clear();
        scratch.leaves.clear();
        scratch.ranges.clear();
        if serde_json::to_writer(&mut scratch.json, row).is_err() {
            // Never silently drop a row on an encode error.
            return true;
        }
        collect_json_string_values(&scratch.json, &mut scratch.leaves, &mut scratch.ranges);
        let parts = scratch
            .ranges
            .iter()
            .map(|range| &scratch.leaves[range.clone()])
            .chain(extra);
        self.matches_parts(parts, &mut scratch.matched, &mut scratch.lower)
    }

    /// Drop the rows whose serialized string-values fail the filter.
    /// No-op when the filter is inactive.
    pub(crate) fn retain<T: serde::Serialize>(&self, rows: &mut Vec<T>) {
        if !self.is_active() {
            return;
        }
        let mut scratch = FilterScratch::default();
        rows.retain(|row| self.matches_row(row, &mut scratch, None));
    }
}

/// Reusable buffers for [`SecondaryFilter::matches_row`] so filtering a
/// large row set allocates once, not per row.
#[derive(Default)]
pub(crate) struct FilterScratch {
    json: Vec<u8>,
    leaves: String,
    ranges: Vec<std::ops::Range<usize>>,
    lower: String,
    matched: Vec<bool>,
}

/// Append every JSON string *value* in `json` to `out` (one per line),
/// retaining exact leaf ranges so a multiline needle cannot bridge fields.
/// decoding escapes; object keys are skipped so `--contains name` filters on
/// values, not on the `"name"` key. Mirrors `collect_string_leaves` over a
/// `Value` tree without materializing the tree.
fn collect_json_string_values(json: &[u8], out: &mut String, ranges: &mut Vec<std::ops::Range<usize>>) {
    let mut index = 0usize;
    let len = json.len();
    while index < len {
        if json[index] != b'"' {
            index += 1;
            continue;
        }
        // Decode the string literal starting at `index`.
        let mut cursor = index + 1;
        let mut decoded = String::new();
        let mut closed = false;
        while cursor < len {
            match json[cursor] {
                b'"' => {
                    closed = true;
                    cursor += 1;
                    break;
                }
                b'\\' => {
                    cursor += 1;
                    let Some(&escaped) = json.get(cursor) else {
                        break;
                    };
                    match escaped {
                        b'"' => decoded.push('"'),
                        b'\\' => decoded.push('\\'),
                        b'/' => decoded.push('/'),
                        b'b' => decoded.push('\u{8}'),
                        b'f' => decoded.push('\u{c}'),
                        b'n' => decoded.push('\n'),
                        b'r' => decoded.push('\r'),
                        b't' => decoded.push('\t'),
                        b'u' => {
                            let hex = json.get(cursor + 1..cursor + 5);
                            let unit = hex
                                .and_then(|hex| std::str::from_utf8(hex).ok())
                                .and_then(|hex| u32::from_str_radix(hex, 16).ok());
                            if let Some(unit) = unit {
                                cursor += 4;
                                // Surrogate pairs arrive as two escapes; join them.
                                if (0xD800..0xDC00).contains(&unit)
                                    && json.get(cursor + 1..cursor + 3) == Some(b"\\u")
                                {
                                    let low = json
                                        .get(cursor + 3..cursor + 7)
                                        .and_then(|hex| std::str::from_utf8(hex).ok())
                                        .and_then(|hex| u32::from_str_radix(hex, 16).ok());
                                    if let Some(low) = low.filter(|low| (0xDC00..0xE000).contains(low)) {
                                        let combined = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                                        if let Some(ch) = char::from_u32(combined) {
                                            decoded.push(ch);
                                        }
                                        cursor += 6;
                                        cursor += 1;
                                        continue;
                                    }
                                }
                                if let Some(ch) = char::from_u32(unit) {
                                    decoded.push(ch);
                                }
                            }
                        }
                        other => decoded.push(other as char),
                    }
                    cursor += 1;
                }
                _ => {
                    // Copy a maximal run of plain bytes at once.
                    let start = cursor;
                    while cursor < len && json[cursor] != b'"' && json[cursor] != b'\\' {
                        cursor += 1;
                    }
                    decoded.push_str(&String::from_utf8_lossy(&json[start..cursor]));
                }
            }
        }
        if !closed {
            break;
        }
        // A string followed by ':' is an object key: skip it.
        let mut peek = cursor;
        while peek < len && json[peek].is_ascii_whitespace() {
            peek += 1;
        }
        let is_key = json.get(peek) == Some(&b':');
        if !is_key {
            let start = out.len();
            out.push_str(&decoded);
            ranges.push(start..out.len());
            out.push('\n');
        }
        index = cursor;
    }
}

/// Append every string leaf of `value` to `out`, separated by `\n` so
/// substrings can't bridge two unrelated leaves.
/// Reference leaf walk over a `Value` tree; the streaming scanner above is
/// checked against it in tests.
#[cfg(test)]
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
