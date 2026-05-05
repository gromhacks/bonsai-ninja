//! Tree-sitter parse cache.
//!
//! Handles the "parse this file with the right grammar, incrementally if we
//! can" side of the pipeline. Parsing is not quite free — we keep the
//! previous [`tree_sitter::Tree`] around so the next reparse can use it as a
//! hint. The cache is keyed on `(FileId, version)`; stale entries fall out
//! naturally when a newer version lands.

use ahash::AHashMap;
use bonsai_common::FileId;
use bonsai_diagnostics::{Diagnostic, Severity};
use bonsai_lang_api::{AdapterArc, AdapterError};
use bonsai_vfs::Vfs;
use parking_lot::{Mutex, RwLock};
use std::{ops::ControlFlow, sync::Arc, time::Duration};
use thiserror::Error;
use tree_sitter::{Node, ParseOptions, Parser, Tree};

const MAX_PARSE_NODE_DIAGNOSTICS: usize = 100;
const DEFAULT_PARSE_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error(transparent)]
    Adapter(#[from] AdapterError),
    #[error("no language adapter handles file {0:?}")]
    NoAdapter(FileId),
    #[error("vfs: {0}")]
    Vfs(#[from] bonsai_vfs::VfsError),
}

#[derive(Clone)]
pub struct ParsedFile {
    pub file: FileId,
    pub version: u64,
    pub tree: Arc<Tree>,
    pub diagnostics: Vec<Diagnostic>,
    pub adapter_id: bonsai_lang_api::LanguageId,
}

impl std::fmt::Debug for ParsedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedFile")
            .field("file", &self.file)
            .field("version", &self.version)
            .field("adapter_id", &self.adapter_id)
            .field("diagnostics", &self.diagnostics.len())
            .finish()
    }
}

/// Parser-cache configuration.
///
/// The default parse timeout is 30 seconds. Set
/// `BONSAI_PARSE_TIMEOUT_MS=0` or pass a zero timeout through the SDK to
/// disable the guard for debugging.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ParserOptions {
    pub parse_timeout: Option<Duration>,
}

impl Default for ParserOptions {
    fn default() -> Self {
        Self {
            parse_timeout: parse_timeout_from_env().or_else(|| Some(default_parse_timeout())),
        }
    }
}

impl ParserOptions {
    #[must_use]
    pub fn with_parse_timeout(timeout: Option<Duration>) -> Self {
        Self {
            parse_timeout: timeout,
        }
    }
}

/// Concurrent parse cache. Cheap to clone; parser instances are locked per
/// language while parsed tree cache reads use an `RwLock`.
#[derive(Clone)]
pub struct ParserCache {
    parsers: Arc<Mutex<AHashMap<bonsai_lang_api::LanguageId, Arc<Mutex<Parser>>>>>,
    cache: Arc<RwLock<AHashMap<FileId, Arc<ParsedFile>>>>,
    options: ParserOptions,
}

impl Default for ParserCache {
    fn default() -> Self {
        Self::with_options(ParserOptions::default())
    }
}

impl std::fmt::Debug for ParserCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cache = self.cache.read();
        let parsers = self.parsers.lock();
        f.debug_struct("ParserCache")
            .field("cached_files", &cache.len())
            .field("live_parsers", &parsers.len())
            .field("parse_timeout", &self.options.parse_timeout)
            .finish()
    }
}

impl ParserCache {
    /// Construct a cache with the default [`ParserOptions`] (which
    /// reads `BONSAI_PARSE_TIMEOUT_MS` from the environment).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a cache with explicit options. Useful for tests or
    /// daemons that need to disable the parse timeout.
    #[must_use]
    pub fn with_options(options: ParserOptions) -> Self {
        Self {
            parsers: Arc::new(Mutex::new(AHashMap::new())),
            cache: Arc::new(RwLock::new(AHashMap::new())),
            options,
        }
    }

    /// Parse `file` with `adapter`, using any cached tree as a reparse hint.
    pub fn parse(
        &self,
        file: FileId,
        adapter: &AdapterArc,
        vfs: &Vfs,
    ) -> Result<Arc<ParsedFile>, ParseError> {
        let snapshot = vfs.snapshot(file)?;
        {
            let cache = self.cache.read();
            if let Some(entry) = cache.get(&file) {
                if entry.version == snapshot.version {
                    return Ok(entry.clone());
                }
            }
        }

        let language = adapter.tree_sitter_language()?;
        let parser = {
            let mut parsers = self.parsers.lock();
            parsers
                .entry(adapter.language_id())
                .or_insert_with(|| Arc::new(Mutex::new(Parser::new())))
                .clone()
        };
        let mut parser = parser.lock();
        // Re-check while holding this language parser. A peer thread for the
        // same language may have finished this file while we waited.
        if let Some(entry) = self.cache.read().get(&file).cloned() {
            if entry.version == snapshot.version {
                return Ok(entry);
            }
        }
        let old = self.cache.read().get(&file).cloned();
        parser
            .set_language(&language)
            .map_err(|e| AdapterError::ParserSetup(e.to_string()))?;

        let old_tree = old.as_ref().map(|p| p.tree.as_ref());
        let (tree, timed_out) = parse_with_timeout(
            &mut parser,
            snapshot.text.as_ref(),
            old_tree,
            self.options.parse_timeout,
        )?;
        drop(parser);

        let mut diagnostics = Vec::new();
        if let Some(timeout) = timed_out {
            diagnostics.push(parse_timeout_diagnostic(file, snapshot.text.len(), timeout));
        } else if tree.root_node().has_error() {
            // Walk the tree and emit one diagnostic per ERROR / MISSING
            // node so the user sees exactly where the parser choked
            // instead of a single opaque "syntax errors present" that
            // points at the whole file. The vector is capped so one
            // badly broken generated file cannot flood diagnostics.
            let mut stack = vec![tree.root_node()];
            let mut suppressed = 0usize;
            while let Some(node) = stack.pop() {
                let is_error = node.is_error();
                let is_missing = node.is_missing();
                if is_error || is_missing {
                    let span = span_for_node(file, node);
                    let msg = if is_missing {
                        format!("missing `{}`", node.kind())
                    } else {
                        "syntax error".to_string()
                    };
                    push_parser_diagnostic(
                        &mut diagnostics,
                        Diagnostic::new(span, Severity::Warning, msg).with_code("syntax-error"),
                        &mut suppressed,
                    );
                }
                if !is_error {
                    // Only recurse into non-error nodes — ERROR subtrees
                    // often contain nested ERRORs that don't add info.
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.has_error() || child.is_missing() {
                            stack.push(child);
                        }
                    }
                }
            }
            if suppressed > 0 {
                diagnostics.push(suppression_summary_diagnostic(
                    file,
                    snapshot.text.len(),
                    suppressed,
                ));
            }
            // Always include a file-level summary too so tooling that
            // only looks at the first diagnostic still learns there was
            // a problem.
            if diagnostics.is_empty() {
                diagnostics.push(
                    Diagnostic::new(
                        file_span(file, snapshot.text.len()),
                        Severity::Warning,
                        "syntax errors present",
                    )
                    .with_code("syntax-error"),
                );
            }
        }

        let parsed = Arc::new(ParsedFile {
            file,
            version: snapshot.version,
            tree: Arc::new(tree),
            diagnostics,
            adapter_id: adapter.language_id(),
        });
        // Don't overwrite a NEWER cache entry — a peer that
        // grabbed a fresher snapshot while we were parsing may
        // have already installed it. Only install our parse if
        // nothing exists for this file or the existing entry is
        // older than the snapshot we just parsed.
        let mut cache = self.cache.write();
        let install = !matches!(cache.get(&file), Some(existing) if existing.version >= parsed.version);
        if install {
            cache.insert(file, parsed.clone());
            Ok(parsed)
        } else {
            // Return the newer cached entry so callers see a
            // consistent "this is the freshest parse" result.
            Ok(cache.get(&file).cloned().unwrap_or(parsed))
        }
    }

    /// Invalidate a single file.
    pub fn invalidate(&self, file: FileId) {
        self.cache.write().remove(&file);
    }
}

fn default_parse_timeout() -> Duration {
    Duration::from_millis(DEFAULT_PARSE_TIMEOUT_MS)
}

/// Read the parse-timeout override from `BONSAI_PARSE_TIMEOUT_MS`.
/// Empty / unparseable values fall through to `None` (use default);
/// `0` explicitly disables the timeout.
fn parse_timeout_from_env() -> Option<Duration> {
    let Ok(raw) = std::env::var("BONSAI_PARSE_TIMEOUT_MS") else {
        return None;
    };
    parse_timeout_millis(raw.trim().parse().ok()?)
}

/// Convert a raw millisecond count to a `Duration`. `0` means
/// "no timeout"; everything else converts directly.
fn parse_timeout_millis(ms: u64) -> Option<Duration> {
    if ms == 0 {
        None
    } else {
        Some(Duration::from_millis(ms))
    }
}

/// Parse `text` under `parser`, falling back to an empty tree if the
/// parse exceeds `timeout`. Returns `(tree, Some(timeout))` when the
/// timeout fired so callers can attach a diagnostic.
fn parse_with_timeout(
    parser: &mut Parser,
    text: &str,
    old_tree: Option<&Tree>,
    timeout: Option<Duration>,
) -> Result<(Tree, Option<Duration>), ParseError> {
    let Some(timeout) = timeout.filter(|timeout| !timeout.is_zero()) else {
        let tree = parser
            .parse(text.as_bytes(), old_tree)
            .ok_or_else(|| AdapterError::Parse("tree-sitter returned None".to_string()))?;
        return Ok((tree, None));
    };

    let start = std::time::Instant::now();
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut timed_out = false;
    let tree = {
        let mut input = |byte_offset, _| {
            if byte_offset < len {
                &bytes[byte_offset..]
            } else {
                &[]
            }
        };
        let mut progress = |_: &tree_sitter::ParseState| {
            if start.elapsed() >= timeout {
                timed_out = true;
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        };
        let options = ParseOptions::new().progress_callback(&mut progress);
        parser.parse_with_options(&mut input, old_tree, Some(options))
    };
    match tree {
        Some(tree) => Ok((tree, None)),
        None if timed_out => {
            parser.reset();
            let empty_tree = parser.parse("", None).ok_or_else(|| {
                AdapterError::Parse("tree-sitter returned None after parse timeout".to_string())
            })?;
            Ok((empty_tree, Some(timeout)))
        }
        None => Err(AdapterError::Parse("tree-sitter returned None".to_string()).into()),
    }
}

/// Build a span covering a tree-sitter node, saturating byte offsets
/// past `u64::MAX` (defensive — real source files are nowhere near).
fn span_for_node(file: FileId, node: Node<'_>) -> bonsai_common::Span {
    bonsai_common::Span::new(
        file,
        saturating_byte_offset(node.start_byte()),
        saturating_byte_offset(node.end_byte()),
    )
}

/// Span covering the whole file. Used for file-level diagnostics
/// where a more specific node isn't applicable.
fn file_span(file: FileId, text_len: usize) -> bonsai_common::Span {
    bonsai_common::Span::new(file, 0, saturating_byte_offset(text_len))
}

fn saturating_byte_offset(byte: usize) -> u64 {
    u64::try_from(byte).unwrap_or(u64::MAX)
}

/// Append a parser diagnostic up to `MAX_PARSE_NODE_DIAGNOSTICS`,
/// counting the rest in `suppressed` for the trailing summary line.
fn push_parser_diagnostic(diagnostics: &mut Vec<Diagnostic>, diagnostic: Diagnostic, suppressed: &mut usize) {
    if diagnostics.len() < MAX_PARSE_NODE_DIAGNOSTICS {
        diagnostics.push(diagnostic);
    } else {
        *suppressed += 1;
    }
}

/// Trailing "(N more syntax errors suppressed)" diagnostic shown when
/// parser diagnostics exceeded the per-file cap.
fn suppression_summary_diagnostic(file: FileId, text_len: usize, suppressed: usize) -> Diagnostic {
    let noun = if suppressed == 1 { "error" } else { "errors" };
    Diagnostic::new(
        file_span(file, text_len),
        Severity::Warning,
        format!("{suppressed} more syntax {noun} suppressed"),
    )
    .with_code("syntax-error")
}

/// File-level diagnostic for "this file timed out during parsing."
fn parse_timeout_diagnostic(file: FileId, text_len: usize, timeout: Duration) -> Diagnostic {
    Diagnostic::new(
        file_span(file, text_len),
        Severity::Warning,
        format!("file skipped: parse timeout after {} ms", timeout.as_millis()),
    )
    .with_code("parse-timeout")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_offsets_saturate_instead_of_wrapping() {
        assert_eq!(saturating_byte_offset(u64::MAX as usize), u64::MAX);
    }

    #[test]
    fn zero_parse_timeout_disables_timeout() {
        assert_eq!(parse_timeout_millis(0), None);
        assert_eq!(parse_timeout_millis(5), Some(Duration::from_millis(5)));
    }

    #[test]
    fn parse_timeout_diagnostic_is_file_level_warning() {
        let diagnostic = parse_timeout_diagnostic(FileId::new(1), 42, Duration::from_millis(7));
        assert_eq!(diagnostic.severity, Severity::Warning);
        assert_eq!(diagnostic.code.as_deref(), Some("parse-timeout"));
        assert_eq!(diagnostic.span, bonsai_common::Span::new(FileId::new(1), 0, 42));
        assert_eq!(diagnostic.message, "file skipped: parse timeout after 7 ms");
    }

    #[test]
    fn parser_diagnostics_are_capped_with_suppression_count() {
        let mut diagnostics = Vec::new();
        let mut suppressed = 0usize;
        for _ in 0..(MAX_PARSE_NODE_DIAGNOSTICS + 5) {
            push_parser_diagnostic(
                &mut diagnostics,
                Diagnostic::new(
                    bonsai_common::Span::new(FileId::new(1), 0, 1),
                    Severity::Warning,
                    "syntax error",
                )
                .with_code("syntax-error"),
                &mut suppressed,
            );
        }

        assert_eq!(diagnostics.len(), MAX_PARSE_NODE_DIAGNOSTICS);
        assert_eq!(suppressed, 5);
        let summary = suppression_summary_diagnostic(FileId::new(1), 10, suppressed);
        assert_eq!(summary.message, "5 more syntax errors suppressed");
        assert_eq!(summary.code.as_deref(), Some("syntax-error"));
    }
}
