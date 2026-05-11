#![deny(missing_docs)]
//! Diagnostic reporting.
//!
//! Diagnostics are plain values, not panics. Every analyzer phase emits them
//! into a [`DiagnosticSink`]; the CLI and LSP consume them for display. The
//! diagnostic model is intentionally small — richer labels can be carried via
//! the `notes` field.

use bonsai_common::Span;
use serde::{Deserialize, Serialize};

pub mod debug;

/// Severity level for a [`Diagnostic`]. Ordered from least to most
/// urgent; consumers typically filter via `>= Severity::Warning`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Background hint.
    Hint,
    /// Not actionable; informational only.
    Info,
    /// Soft warning; analysis still usable.
    Warning,
    /// Hard error; the surrounding fact should be considered tainted.
    Error,
}

/// A self-contained diagnostic. `code` is a short machine-readable tag like
/// `"E0001"` or `"unsupported-construct"` that keeps stable across releases
/// and is safe to suppress on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Source location the diagnostic refers to.
    pub span: Span,
    /// Severity level.
    pub severity: Severity,
    /// Primary user-facing message.
    pub message: String,
    /// Optional stable tag (e.g. `"E0001"`) used for suppression.
    pub code: Option<String>,
    /// Secondary explanatory notes; rendered after the primary message.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl Diagnostic {
    /// Construct a diagnostic with empty `code` and no `notes`.
    #[must_use]
    pub fn new(span: Span, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            span,
            severity,
            message: message.into(),
            code: None,
            notes: Vec::new(),
        }
    }

    /// Builder helper: attach a `code` tag.
    #[must_use]
    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }
}

/// A mutable, ordered collector for diagnostics. Cheap to clone in
/// [`DiagnosticSink::snapshot`] for reporting without transferring ownership.
#[derive(Clone, Debug, Default)]
pub struct DiagnosticSink {
    items: Vec<Diagnostic>,
}

impl DiagnosticSink {
    /// Construct an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a single diagnostic.
    pub fn push(&mut self, diagnostic: Diagnostic) {
        self.items.push(diagnostic);
    }

    /// Append every diagnostic from an iterator.
    pub fn extend(&mut self, iter: impl IntoIterator<Item = Diagnostic>) {
        self.items.extend(iter);
    }

    /// True if no diagnostics have been pushed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Number of diagnostics collected.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Borrow the collected diagnostics in insertion order.
    #[must_use]
    pub fn items(&self) -> &[Diagnostic] {
        &self.items
    }

    /// Clone the collected diagnostics. Used by callers that need an
    /// owned snapshot independent of further sink mutation.
    #[must_use]
    pub fn snapshot(&self) -> Vec<Diagnostic> {
        self.items.clone()
    }

    /// True iff any diagnostic has [`Severity::Error`].
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.items.iter().any(|d| d.severity == Severity::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_common::FileId;

    #[test]
    fn sink_accumulates_and_reports_errors() {
        let mut sink = DiagnosticSink::new();
        assert!(sink.is_empty());
        sink.push(Diagnostic::new(
            Span::new(FileId::new(0), 0, 1),
            Severity::Error,
            "boom",
        ));
        assert!(sink.has_errors());
        assert_eq!(sink.len(), 1);
    }
}
