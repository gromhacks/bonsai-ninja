//! Source spans and line/column lookup.

use crate::ids::FileId;
use serde::{Deserialize, Serialize};

/// A half-open byte range in a single file. `end >= start` always.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    /// File the span lives in.
    pub file: FileId,
    /// Inclusive start byte offset.
    pub start: u64,
    /// Exclusive end byte offset.
    pub end: u64,
}

impl Span {
    /// Construct a span from raw byte offsets.
    #[must_use]
    pub const fn new(file: FileId, start: u64, end: u64) -> Self {
        Self { file, start, end }
    }

    /// Construct an empty (zero-length) span at `at`.
    #[must_use]
    pub const fn empty(file: FileId, at: u64) -> Self {
        Self {
            file,
            start: at,
            end: at,
        }
    }

    /// Length of the span in bytes.
    #[must_use]
    pub const fn len(self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// True iff `start == end`.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.end == self.start
    }

    /// True iff `byte` falls inside the half-open range.
    #[must_use]
    pub const fn contains(self, byte: u64) -> bool {
        self.start <= byte && byte < self.end
    }

    /// Merge two spans that live in the same file.
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        debug_assert_eq!(self.file, other.file);
        Self {
            file: self.file,
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

impl core::fmt::Debug for Span {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Span({}, {}..{})", self.file, self.start, self.end)
    }
}

impl PartialOrd for Span {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Span {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.file
            .cmp(&other.file)
            .then(self.start.cmp(&other.start))
            .then(self.end.cmp(&other.end))
    }
}

/// One-based line/column pair for human-facing output.
///
/// Both fields are `u32`. Files with > 4 B lines or columns are not
/// practically reachable (no human reads them, no editor renders
/// them); the smaller integer keeps the JSON shape compact and
/// matches the LSP / Language Server Protocol convention that line
/// numbers fit a `u32`. Saturation here is a structural limit, not
/// a heuristic cap — any byte position in a `Span` (which is `u64`)
/// remains addressable through `Span::start`/`Span::end`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LineCol {
    /// 1-indexed line number.
    pub line: u32,
    /// 1-indexed byte column within the line.
    pub column: u32,
}

/// Lazy byte-offset to line-column lookup for a single file. Construct once
/// per file snapshot; all lookups are `O(log n)`.
#[derive(Debug, Clone)]
pub struct SpanMap {
    /// Byte offset of the start of every line. `line_starts[0] == 0`.
    line_starts: Vec<u64>,
}

impl SpanMap {
    /// Build a span map by scanning `text` once. `O(n)` in the file
    /// length; subsequent line/column lookups are `O(log n)`.
    #[must_use]
    pub fn new(text: &str) -> Self {
        let mut line_starts = Vec::with_capacity(text.len() / 40 + 1);
        line_starts.push(0);
        for (idx, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(u64::try_from(idx + 1).unwrap_or(u64::MAX));
            }
        }
        Self { line_starts }
    }

    /// Convert a byte offset to a one-based line/column. Columns are measured
    /// in bytes; callers that need grapheme columns should do their own
    /// conversion on the raw text.
    #[must_use]
    pub fn line_col(&self, byte: u64) -> LineCol {
        match self.line_starts.binary_search(&byte) {
            Ok(idx) => LineCol {
                line: u32::try_from(idx + 1).unwrap_or(u32::MAX),
                column: 1,
            },
            Err(idx) => {
                let line_start = self.line_starts[idx - 1];
                LineCol {
                    line: u32::try_from(idx).unwrap_or(u32::MAX),
                    column: u32::try_from(byte.saturating_sub(line_start).saturating_add(1))
                        .unwrap_or(u32::MAX),
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "span_tests.rs"]
mod tests;
