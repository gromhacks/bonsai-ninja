//! Tree-sitter parse cache.
//!
//! Handles the "parse this file with the right grammar, incrementally if we
//! can" side of the pipeline. Parsing is not quite free — we keep the
//! previous [`tree_sitter::Tree`] around so the next reparse can use it as a
//! hint. Cache identity includes the VFS instance, file, and language; each
//! entry retains the newest immutable source version it has parsed.

use ahash::AHashMap;
use bonsai_common::FileId;
use bonsai_diagnostics::{Diagnostic, Severity};
use bonsai_lang_api::{AdapterArc, AdapterError, LanguageId};
use bonsai_vfs::{FileSnapshot, Vfs};
use parking_lot::{Mutex, RwLock};
use std::{
    ops::{ControlFlow, Deref, DerefMut},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tree_sitter::{InputEdit, Node, ParseOptions, Parser, Point, Tree};

const MAX_PARSE_NODE_DIAGNOSTICS: usize = 100;
type ParseKey = (u64, FileId, LanguageId);
type ParserPool = Arc<Mutex<Vec<Parser>>>;

/// Exclusive checkout from a language parser pool. The pool lock is held only
/// while taking or returning a parser; tree-sitter parsing itself never holds
/// a global or per-language lock.
struct ParserLease {
    parser: Option<Parser>,
    pool: ParserPool,
}

impl Deref for ParserLease {
    type Target = Parser;

    fn deref(&self) -> &Self::Target {
        self.parser.as_ref().expect("parser lease is populated")
    }
}

impl DerefMut for ParserLease {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.parser.as_mut().expect("parser lease is populated")
    }
}

impl Drop for ParserLease {
    fn drop(&mut self) {
        if let Some(parser) = self.parser.take() {
            self.pool.lock().push(parser);
        }
    }
}

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
    source: Arc<str>,
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

impl ParsedFile {
    /// Source text corresponding exactly to [`Self::tree`].
    ///
    /// Consumers that interpret node byte ranges must use this text instead
    /// of taking a fresh VFS snapshot, which may already be a newer version.
    #[must_use]
    pub fn source_text(&self) -> &str {
        &self.source
    }
}

/// Parser-cache configuration.
///
/// Parsing runs to completion by default. Set `BONSAI_PARSE_TIMEOUT_MS` or
/// use the SDK/CLI override only when an explicitly incomplete diagnostic
/// run is desired; zero restores the uncapped behavior.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ParserOptions {
    pub parse_timeout: Option<Duration>,
}

impl Default for ParserOptions {
    fn default() -> Self {
        Self {
            parse_timeout: parse_timeout_from_env(),
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

/// Concurrent parse cache. Cheap to clone; parser instances are pooled by
/// language while parsed tree cache reads use an `RwLock`.
///
/// A checkout removes one parser from its pool (or creates one if every parser
/// is busy), then releases the pool lock before parsing. Concurrent files in
/// the same language therefore do not serialize behind one mutable parser,
/// while completed workers still make their parser reusable. The tree cache
/// is logically keyed by `(VFS instance, FileId, language, version)`.
#[derive(Clone)]
pub struct ParserCache {
    parsers: Arc<Mutex<AHashMap<LanguageId, ParserPool>>>,
    cache: Arc<RwLock<AHashMap<ParseKey, Arc<ParsedFile>>>>,
    options: ParserOptions,
}

impl Default for ParserCache {
    fn default() -> Self {
        Self::with_options(ParserOptions::default())
    }
}

impl std::fmt::Debug for ParserCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Snapshot each lock independently — never hold two locks
        // simultaneously here. `parse()` acquires (cache, parsers,
        // parser, cache) in distinct windows; `Debug::fmt`
        // previously held (cache, parsers) at the same time, an
        // AB-BA hazard if a peer ever held parsers then cache.
        let cached_files = self.cache.read().len();
        let pools = self.parsers.lock().values().cloned().collect::<Vec<_>>();
        let idle_parsers = pools.iter().map(|pool| pool.lock().len()).sum::<usize>();
        f.debug_struct("ParserCache")
            .field("cached_files", &cached_files)
            .field("parser_languages", &pools.len())
            .field("idle_parsers", &idle_parsers)
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

    /// Construct a cache with explicit options. Useful for tests or callers
    /// that deliberately need a bounded diagnostic parse.
    #[must_use]
    pub fn with_options(options: ParserOptions) -> Self {
        Self {
            parsers: Arc::new(Mutex::new(AHashMap::new())),
            cache: Arc::new(RwLock::new(AHashMap::new())),
            options,
        }
    }

    /// Parse `file` with `adapter`, using any cached tree as a correctly edited
    /// incremental reparse hint.
    pub fn parse(
        &self,
        file: FileId,
        adapter: &AdapterArc,
        vfs: &Vfs,
    ) -> Result<Arc<ParsedFile>, ParseError> {
        let snapshot = vfs.snapshot(file)?;
        self.parse_snapshot(&snapshot, adapter, vfs)
    }

    /// Parse an exact immutable snapshot.
    ///
    /// This is the adapter bridge used by the analyzer database. It prevents a
    /// concurrent VFS write from returning a tree for a different source
    /// version than the snapshot an adapter is currently walking.
    pub fn parse_snapshot(
        &self,
        snapshot: &FileSnapshot,
        adapter: &AdapterArc,
        vfs: &Vfs,
    ) -> Result<Arc<ParsedFile>, ParseError> {
        let file = snapshot.file_id;
        let key = (vfs.instance_id(), file, adapter.language_id());
        if let Some(entry) = self.cache.read().get(&key).cloned() {
            if parsed_matches_snapshot(&entry, snapshot) {
                return Ok(entry);
            }
        }

        let language = adapter.tree_sitter_language()?;
        let mut parser = self.checkout_parser(adapter.language_id());
        // Re-check after checkout. A peer may have finished this exact
        // snapshot between the initial cache read and parser lookup.
        if let Some(entry) = self.cache.read().get(&key).cloned() {
            if parsed_matches_snapshot(&entry, snapshot) {
                return Ok(entry);
            }
        }
        let old = self.cache.read().get(&key).cloned();
        parser
            .set_language(&language)
            .map_err(|e| AdapterError::ParserSetup(e.to_string()))?;

        let incremental_tree = old
            .as_deref()
            .and_then(|parsed| incremental_tree(parsed, &snapshot.text));
        let old_tree = incremental_tree.as_ref();
        let (tree, timed_out) = parse_with_timeout(
            &mut parser,
            snapshot.text.as_ref(),
            old_tree,
            self.options.parse_timeout,
        )?;
        drop(parser);
        drop(incremental_tree);

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
            source: Arc::clone(&snapshot.text),
        });
        // Cache the newest version, but always return the tree for the exact
        // snapshot requested by this caller. Returning a peer's newer entry
        // here would pair that newer tree with the caller's older source.
        let mut cache = self.cache.write();
        if let Some(existing) = cache.get(&key) {
            if parsed_matches_snapshot(existing, snapshot) {
                return Ok(existing.clone());
            }
            if existing.version >= parsed.version {
                return Ok(parsed);
            }
        }
        cache.insert(key, parsed.clone());
        Ok(parsed)
    }

    /// Invalidate a single file.
    pub fn invalidate(&self, file: FileId) {
        self.cache
            .write()
            .retain(|(_, cached_file, _), _| *cached_file != file);
    }

    fn checkout_parser(&self, language: LanguageId) -> ParserLease {
        let pool = self
            .parsers
            .lock()
            .entry(language)
            .or_insert_with(|| Arc::new(Mutex::new(Vec::new())))
            .clone();
        let parser = pool.lock().pop().unwrap_or_else(Parser::new);
        ParserLease {
            parser: Some(parser),
            pool,
        }
    }
}

fn parsed_matches_snapshot(parsed: &ParsedFile, snapshot: &FileSnapshot) -> bool {
    parsed.version == snapshot.version && Arc::ptr_eq(&parsed.source, &snapshot.text)
}

/// Clone and edit the previous tree so tree-sitter's incremental parser sees
/// coordinates for `new_source`. Passing an unedited old tree after source
/// changes is not a hint: tree-sitter treats unchanged ranges as authoritative
/// and may reuse stale syntax.
fn incremental_tree(parsed: &ParsedFile, new_source: &str) -> Option<Tree> {
    if parsed
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code.as_deref() == Some("parse-timeout"))
    {
        // A timeout stores an intentionally empty placeholder tree, which does
        // not describe `parsed.source` and therefore cannot be edited safely.
        return None;
    }
    let mut tree = parsed.tree.as_ref().clone();
    if parsed.source.as_ref() != new_source {
        tree.edit(&single_replacement_edit(&parsed.source, new_source));
    }
    Some(tree)
}

/// Describe an arbitrary source change as one replacement spanning the first
/// and last changed UTF-8 boundaries. This remains exact for tree-sitter even
/// when the VFS update arrived as a whole-file write rather than granular LSP
/// edits.
fn single_replacement_edit(old: &str, new: &str) -> InputEdit {
    let old_bytes = old.as_bytes();
    let new_bytes = new.as_bytes();
    let mut prefix = old_bytes
        .iter()
        .zip(new_bytes)
        .take_while(|(old, new)| old == new)
        .count();
    while prefix > 0 && (!old.is_char_boundary(prefix) || !new.is_char_boundary(prefix)) {
        prefix -= 1;
    }

    let max_suffix = old
        .len()
        .saturating_sub(prefix)
        .min(new.len().saturating_sub(prefix));
    let mut suffix = old_bytes[old.len() - max_suffix..]
        .iter()
        .rev()
        .zip(new_bytes[new.len() - max_suffix..].iter().rev())
        .take_while(|(old, new)| old == new)
        .count();
    while suffix > 0
        && (!old.is_char_boundary(old.len() - suffix) || !new.is_char_boundary(new.len() - suffix))
    {
        suffix -= 1;
    }

    let old_end = old.len() - suffix;
    let new_end = new.len() - suffix;
    InputEdit {
        start_byte: prefix,
        old_end_byte: old_end,
        new_end_byte: new_end,
        start_position: point_at_byte(old, prefix),
        old_end_position: point_at_byte(old, old_end),
        new_end_position: point_at_byte(new, new_end),
    }
}

fn point_at_byte(text: &str, byte: usize) -> Point {
    debug_assert!(byte <= text.len());
    debug_assert!(text.is_char_boundary(byte));
    let prefix = &text.as_bytes()[..byte];
    let row = prefix.iter().filter(|&&value| value == b'\n').count();
    let column = prefix
        .iter()
        .rposition(|&value| value == b'\n')
        .map_or(byte, |newline| byte - newline - 1);
    Point::new(row, column)
}

/// Read the parse-timeout override from `BONSAI_PARSE_TIMEOUT_MS`.
/// Empty / unparseable values fall through to the uncapped default; `0`
/// explicitly selects the same uncapped behavior.
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
#[path = "tests.rs"]
mod tests;
