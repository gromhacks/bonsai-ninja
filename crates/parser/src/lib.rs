//! Tree-sitter parse cache.
//!
//! Handles the "parse this file with the right grammar, incrementally if we
//! can" side of the pipeline. Parsing is not quite free — we keep the
//! previous [`tree_sitter::Tree`] around so the next reparse can use it as a
//! hint. Cache identity includes the VFS instance, file, adapter, and exact
//! grammar variant; each entry retains the newest immutable source version it
//! has parsed.

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

type ParseKey = (u64, FileId, LanguageId, &'static str);
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
    /// Exact adapter-selected grammar variant used for this source path.
    pub grammar_name: &'static str,
    source: Arc<str>,
    used_recovery: bool,
    /// Stable adapter-owned digest of compiler inputs outside `source` that
    /// can affect parsing/recovery (for example reachable preprocessor files).
    context_fingerprint: u64,
    /// Workspace revision observed for cache insertion ordering only.
    context_revision: u64,
}

impl std::fmt::Debug for ParsedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedFile")
            .field("file", &self.file)
            .field("version", &self.version)
            .field("adapter_id", &self.adapter_id)
            .field("grammar_name", &self.grammar_name)
            .field("diagnostics", &self.diagnostics.len())
            .field("used_recovery", &self.used_recovery)
            .finish()
    }
}

impl ParsedFile {
    /// Original source text addressed by every byte range in [`Self::tree`].
    ///
    /// Consumers that interpret node byte ranges must use this text instead
    /// of taking a fresh VFS snapshot, which may already be a newer version.
    /// Grammar recovery can normalize a same-width private parser buffer, but
    /// that buffer is never exposed and cannot alter these source slices.
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
/// exact grammar variant while parsed tree cache reads use an `RwLock`.
///
/// A checkout removes one parser from its pool (or creates one if every parser
/// is busy), then releases the pool lock before parsing. Concurrent files in
/// the same grammar therefore do not serialize behind one mutable parser,
/// while completed workers still make their parser reusable. The tree cache
/// is logically keyed by `(VFS instance, FileId, adapter, grammar, version)`.
#[derive(Clone)]
pub struct ParserCache {
    parsers: Arc<Mutex<AHashMap<&'static str, ParserPool>>>,
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
            .field("parser_grammars", &pools.len())
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
        let path = vfs.path(file)?;
        let grammar_name = adapter.grammar_name_for_path(&path);
        let context_fingerprint = adapter.parse_context_fingerprint(snapshot, vfs);
        let context_revision = vfs.revision();
        let key = (vfs.instance_id(), file, adapter.language_id(), grammar_name);
        if let Some(entry) = self.cache.read().get(&key).cloned() {
            if parsed_matches_snapshot(&entry, snapshot, context_fingerprint) {
                return Ok(entry);
            }
        }

        let language = adapter.tree_sitter_language_for_path(&path)?;
        let mut parser = self.checkout_parser(grammar_name);
        // Re-check after checkout. A peer may have finished this exact
        // snapshot between the initial cache read and parser lookup.
        if let Some(entry) = self.cache.read().get(&key).cloned() {
            if parsed_matches_snapshot(&entry, snapshot, context_fingerprint) {
                return Ok(entry);
            }
        }
        let old = self.cache.read().get(&key).cloned();
        parser
            .set_language(&language)
            .map_err(|e| AdapterError::ParserSetup(e.to_string()))?;

        let normalization_edits = adapter.parse_normalization_edits(snapshot, vfs);
        let mut normalized_source = None;
        if !normalization_edits.is_empty() {
            let mut candidate = Vec::from(snapshot.text.as_bytes());
            if apply_recovery_edits(snapshot.text.as_ref(), &mut candidate, &normalization_edits) {
                normalized_source = Some(candidate);
            }
        }
        let used_normalization = normalized_source.is_some();
        let parser_bytes = normalized_source
            .as_deref()
            .unwrap_or_else(|| snapshot.text.as_bytes());
        let parser_text =
            std::str::from_utf8(parser_bytes).expect("same-width parser normalization preserves UTF-8");
        let incremental_tree = (!used_normalization)
            .then(|| {
                old.as_deref()
                    .filter(|parsed| parsed.context_fingerprint == context_fingerprint)
                    .and_then(|parsed| incremental_tree(parsed, &snapshot.text))
            })
            .flatten();
        let old_tree = incremental_tree.as_ref();
        let (mut tree, timed_out) =
            parse_with_timeout(&mut parser, parser_text, old_tree, self.options.parse_timeout)?;
        let mut used_recovery = used_normalization;
        if timed_out.is_none() && tree.root_node().has_error() {
            // The common valid-source path never allocates a second source
            // buffer. Recovery needs mutable bytes only after Tree-sitter has
            // proven syntax damage or an adapter requested normalization.
            let mut recovery_source = normalized_source
                .take()
                .unwrap_or_else(|| Vec::from(snapshot.text.as_bytes()));
            loop {
                let current_score = bonsai_lang_api::syntax_damage_score(&tree);
                let current_recovery_key = recovery_ordering_key(current_score);
                let mut best = None;
                for (batch_index, edits) in adapter
                    .parse_recovery_edit_batches(snapshot, vfs, &tree)
                    .into_iter()
                    .enumerate()
                {
                    let mut candidate_source = recovery_source.clone();
                    if !apply_recovery_edits(snapshot.text.as_ref(), &mut candidate_source, &edits) {
                        continue;
                    }
                    let recovery_text = std::str::from_utf8(&candidate_source)
                        .expect("same-width recovery normalization preserves UTF-8");
                    let (candidate, candidate_timed_out) =
                        parse_with_timeout(&mut parser, recovery_text, None, self.options.parse_timeout)?;
                    let candidate_score = bonsai_lang_api::syntax_damage_score(&candidate);
                    let preserves_clean_nodes = candidate_timed_out.is_none()
                        && recovery_preserves_clean_compiler_nodes(
                            adapter.as_ref(),
                            &path,
                            &tree,
                            &candidate,
                            &edits,
                        );
                    bonsai_diagnostics::debug_log!(
                        "parse-recovery",
                        "file={} batch={} edits={} current_damage={:?} candidate_damage={:?} timed_out={} preserves_clean_nodes={}",
                        path.display(),
                        batch_index,
                        edits.len(),
                        current_score,
                        candidate_score,
                        candidate_timed_out.is_some(),
                        preserves_clean_nodes
                    );
                    if candidate_timed_out.is_some()
                        || recovery_ordering_key(candidate_score) >= current_recovery_key
                        || !preserves_clean_nodes
                        || best.as_ref().is_some_and(|(_, _, best_score)| {
                            recovery_ordering_key(*best_score) <= recovery_ordering_key(candidate_score)
                        })
                    {
                        continue;
                    }
                    best = Some((candidate_source, candidate, candidate_score));
                }
                let Some((candidate_source, candidate, _)) = best else {
                    break;
                };
                recovery_source = candidate_source;
                tree = candidate;
                used_recovery = true;
            }
        }
        drop(parser);
        drop(incremental_tree);

        let diagnostics = diagnostics_for_tree(file, snapshot.text.len(), &tree, timed_out);

        let parsed = Arc::new(ParsedFile {
            file,
            version: snapshot.version,
            tree: Arc::new(tree),
            diagnostics,
            adapter_id: adapter.language_id(),
            grammar_name,
            source: Arc::clone(&snapshot.text),
            used_recovery,
            context_fingerprint,
            context_revision,
        });
        // Cache the newest version, but always return the tree for the exact
        // snapshot requested by this caller. Returning a peer's newer entry
        // here would pair that newer tree with the caller's older source.
        let mut cache = self.cache.write();
        if let Some(existing) = cache.get(&key) {
            if parsed_matches_snapshot(existing, snapshot, context_fingerprint) {
                return Ok(existing.clone());
            }
            if existing.version > parsed.version
                || (existing.version == parsed.version && existing.context_revision > parsed.context_revision)
            {
                return Ok(parsed);
            }
        }
        cache.insert(key, parsed.clone());
        Ok(parsed)
    }

    /// Release the cached tree for this exact workspace/file/language key.
    ///
    /// Compiler lowering phases call this after all durable facts have been
    /// extracted. Exact removal keeps phase-local eviction O(1) and avoids
    /// serializing parallel workers behind a whole-cache scan. Edit
    /// invalidation remains broader because a file may have been parsed by
    /// more than one adapter over the cache's lifetime.
    pub fn release(&self, file: FileId, adapter: &AdapterArc, vfs: &Vfs) {
        let Ok(path) = vfs.path(file) else {
            return;
        };
        self.cache.write().remove(&(
            vfs.instance_id(),
            file,
            adapter.language_id(),
            adapter.grammar_name_for_path(&path),
        ));
    }

    /// Invalidate every cached language interpretation of a single file.
    pub fn invalidate(&self, file: FileId) {
        self.cache
            .write()
            .retain(|(_, cached_file, _, _), _| *cached_file != file);
    }

    fn checkout_parser(&self, grammar_name: &'static str) -> ParserLease {
        let pool = self
            .parsers
            .lock()
            .entry(grammar_name)
            .or_insert_with(|| Arc::new(Mutex::new(Vec::new())))
            .clone();
        let parser = pool.lock().pop().unwrap_or_default();
        ParserLease {
            parser: Some(parser),
            pool,
        }
    }
}

/// Rank fact-backed recovery candidates after clean-node preservation has
/// succeeded. Each remaining ERROR/MISSING node is one concrete failed
/// grammar production, so reducing that count is primary; uncovered bytes
/// break ties. A collapsed whole-file candidate cannot win merely by reducing
/// the count because [`recovery_preserves_clean_compiler_nodes`] rejects the
/// declarations/expressions it displaced.
const fn recovery_ordering_key((uncovered_bytes, concrete_errors): (usize, usize)) -> (usize, usize) {
    (concrete_errors, uncovered_bytes)
}

/// A recovery parse may add compiler evidence, but it must never replace or
/// delete a construct that the preceding CST had already parsed cleanly.
///
/// Syntax-damage scores alone are not a semantic ordering: on a damaged
/// translation unit Tree-sitter can trade one clean callable for another while
/// still reducing the number of `ERROR` bytes.  Recovery is therefore
/// monotone over the adapter's grammar contract.  Every clean structural node
/// that feeds declaration, call, parameter, control-flow, assignment, or
/// return lowering must retain the exact kind and byte span in the candidate
/// tree.  This is range-directed CST validation, not a source-text or API-name
/// heuristic.
fn recovery_preserves_clean_compiler_nodes(
    adapter: &dyn bonsai_lang_api::LanguageAdapter,
    path: &std::path::Path,
    current: &Tree,
    candidate: &Tree,
    edits: &[bonsai_lang_api::ParseRecoveryEdit],
) -> bool {
    let Some(handler) = adapter.grammar_handler_for_path(path) else {
        return true;
    };

    let protected_kinds = handler
        .declared_node_kinds()
        .into_iter()
        // Leaf/value/operator inventories help decode an already-protected
        // construct but are not independently emitted compiler structure.
        // Keeping them outside this set also permits a CST-proven recovery to
        // mask a declaration macro that Tree-sitter currently sees as an
        // identifier token. Every declaration, parameter/pattern, call,
        // argument, control, assignment, closure, exception, and projection
        // node remains protected.
        .filter(|(role, _)| {
            !matches!(
                *role,
                "literal_value_kinds"
                    | "string_literal_kinds"
                    | "comment_kinds"
                    | "doc_comment_kinds"
                    | "identifier_kinds"
                    | "binding_identifier_kinds"
                    | "static_field_name_kinds"
                    | "runtime_type_guard_operators"
                    | "runtime_typeof_operators"
                    | "runtime_type_equality_operators"
                    | "value_free_unary_operators"
                    | "sigil_variable_kinds"
                    | "global_variable_kinds"
            )
        })
        .map(|(_, kind)| kind)
        .collect::<ahash::AHashSet<_>>();

    let mut stack = vec![current.root_node()];
    while let Some(node) = stack.pop() {
        if node.is_named()
            && !node.has_error()
            && protected_kinds.contains(node.kind())
            && !clean_node_is_explicit_damaged_descendant_replacement(node, edits)
            && !tree_has_exact_clean_node(candidate, node.kind(), node.start_byte(), node.end_byte())
        {
            return false;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    true
}

fn clean_node_is_explicit_damaged_descendant_replacement(
    node: tree_sitter::Node<'_>,
    edits: &[bonsai_lang_api::ParseRecoveryEdit],
) -> bool {
    let has_error_ancestor =
        std::iter::successors(node.parent(), |parent| parent.parent()).any(|ancestor| ancestor.has_error());
    has_error_ancestor
        && edits.iter().any(|edit| {
            edit.damaged_descendant_owner().is_some_and(|(start, end)| {
                start <= edit.start_byte
                    && edit.end_byte <= end
                    && ((start >= node.start_byte() && end <= node.end_byte())
                        || (node.start_byte() >= start && node.end_byte() <= end))
            })
        })
}

fn tree_has_exact_clean_node(tree: &Tree, kind: &str, start: usize, end: usize) -> bool {
    let probe_end = end.max(start.saturating_add(1)).min(tree.root_node().end_byte());
    let mut node = tree.root_node().descendant_for_byte_range(start, probe_end);
    while let Some(current) = node {
        if current.start_byte() == start
            && current.end_byte() == end
            && current.kind() == kind
            && !current.has_error()
        {
            return true;
        }
        node = current.parent();
    }
    false
}

fn parsed_matches_snapshot(parsed: &ParsedFile, snapshot: &FileSnapshot, context_fingerprint: u64) -> bool {
    parsed.version == snapshot.version
        && Arc::ptr_eq(&parsed.source, &snapshot.text)
        && parsed.context_fingerprint == context_fingerprint
}

/// Clone and edit the previous tree so tree-sitter's incremental parser sees
/// coordinates for `new_source`. Passing an unedited old tree after source
/// changes is not a hint: tree-sitter treats unchanged ranges as authoritative
/// and may reuse stale syntax.
fn incremental_tree(parsed: &ParsedFile, new_source: &str) -> Option<Tree> {
    if parsed.used_recovery
        || parsed
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

fn apply_recovery_edits(
    source: &str,
    recovered: &mut [u8],
    edits: &[bonsai_lang_api::ParseRecoveryEdit],
) -> bool {
    let mut changed = false;
    for edit in edits {
        changed |= edit.apply_to(source, recovered);
    }
    changed
}

fn diagnostics_for_tree(
    file: FileId,
    text_len: usize,
    tree: &Tree,
    timed_out: Option<Duration>,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    if let Some(timeout) = timed_out {
        diagnostics.push(parse_timeout_diagnostic(file, text_len, timeout));
        return diagnostics;
    }
    if !tree.root_node().has_error() {
        return diagnostics;
    }

    // Walk the tree and emit one diagnostic per ERROR / MISSING node so the
    // user sees exactly where the parser choked instead of a single opaque
    // "syntax errors present" that points at the whole file. Diagnostics are
    // exhaustive; presentation layers may paginate them but
    // the compiler query never suppresses syntax facts.
    let mut stack = vec![tree.root_node()];
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
            diagnostics.push(Diagnostic::new(span, Severity::Warning, msg).with_code("syntax-error"));
        }
        // ERROR nodes may themselves contain narrower ERROR/MISSING nodes.
        // Descend through them as well: stopping at the outer recovery node
        // hid the precise nested compiler diagnostics. Push in reverse so
        // diagnostics remain in source order despite the LIFO work stack.
        let mut cursor = node.walk();
        let mut damaged_children = node
            .children(&mut cursor)
            .filter(|child| child.has_error() || child.is_error() || child.is_missing())
            .collect::<Vec<_>>();
        damaged_children.reverse();
        stack.extend(damaged_children);
    }
    if diagnostics.is_empty() {
        diagnostics.push(
            Diagnostic::new(
                file_span(file, text_len),
                Severity::Warning,
                "syntax errors present",
            )
            .with_code("syntax-error"),
        );
    }
    diagnostics
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
    let mut row = 0usize;
    let mut line_start = 0usize;
    for (index, value) in prefix.iter().enumerate() {
        if *value == b'\n' {
            row += 1;
            line_start = index + 1;
        }
    }
    let column = byte - line_start;
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
