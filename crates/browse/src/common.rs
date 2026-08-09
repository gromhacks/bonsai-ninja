//! Helpers shared across browse / dump command implementations.
//!
//! `format_span` is the canonical "Span → (path, line, column)"
//! resolver every command renders with. `make_name_filter` builds
//! the substring / regex predicate used by the many `--name` /
//! `--callee` / `--module` / etc. filters.
//!
//! [`Locator`] is the canonical "module + class + decl + file:line:col"
//! locator every connection-bearing row carries — `tree`'s
//! cross-file edges, `read-file`'s line marks, the inlined
//! caller/callee headers, and any other surface that needs to
//! cite a code location with full enclosing context. Rendered
//! through the same helpers `inspect` and `dump-edges` already use.

use bonsai_lang_api::DeclKind;
use bonsai_workspace::Workspace;
use serde::{Deserialize, Serialize};

/// Re-export of the common span type so callers don't need a
/// separate `bonsai_common` dependency.
pub type Span = bonsai_common::Span;

/// Boxed predicate over strings — used by every `--name` / `--callee`
/// / … filter. Named alias keeps `make_name_filter`'s return type
/// readable.
pub type NameFilter = Box<dyn Fn(&str) -> bool + Send + Sync>;

/// Stream one exact file-local compiler object after applying a workspace-
/// relative path filter. Filtering happens before body allocation.
pub(crate) fn filtered_file_decl_index(
    ws: &Workspace,
    file: bonsai_common::FileId,
    filter: Option<&str>,
) -> Option<bonsai_lang_api::DeclIndex> {
    if let Some(filter) = filter {
        let path = ws
            .vfs()
            .path(file)
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !file_path_matches_filter(ws, &path, filter) {
            return None;
        }
    }
    ws.db().decl_index_uncached(file)
}

/// Match a declaration or any compiler-owned lexical ancestor by name.
///
/// Lambda/local-function declarations remain the immediate owners of their
/// calls, but human filters such as `--in-fn outer` should include code nested
/// lexically inside `outer`. Parent SymbolIds are adapter facts; this never
/// infers ancestry from generated names or rendered source text.
pub(crate) fn decl_or_ancestor_name_matches(
    decl: &bonsai_lang_api::Decl,
    defs_by_symbol: &ahash::AHashMap<bonsai_common::SymbolId, &bonsai_lang_api::Decl>,
    matches: &(dyn Fn(&str) -> bool + Send + Sync),
) -> bool {
    let mut current = Some(decl);
    // A valid declaration tree is acyclic. The bound makes malformed adapter
    // output fail closed instead of looping forever.
    for _ in 0..=defs_by_symbol.len() {
        let Some(candidate) = current else {
            return false;
        };
        if matches(&candidate.name) {
            return true;
        }
        current = candidate
            .parent
            .and_then(|parent| defs_by_symbol.get(&parent).copied());
    }
    false
}

/// Build a name-matcher that respects `needle` + `regex`. Returns
/// a closure that returns `true` when `needle` is `None` OR the
/// candidate matches.
///
/// Returns an `Err` only when `is_regex` is set and the pattern
/// fails to compile.
pub fn make_name_filter(needle: Option<&str>, is_regex: bool) -> Result<NameFilter, regex::Error> {
    let Some(pattern) = needle else {
        // No filter requested: every candidate matches.
        return Ok(Box::new(|_| true));
    };
    if is_regex {
        let compiled = regex::Regex::new(pattern)?;
        Ok(Box::new(move |s: &str| compiled.is_match(s)))
    } else {
        // Own the substring so the closure outlives the caller's
        // borrow.
        let owned = pattern.to_string();
        Ok(Box::new(move |s: &str| s.contains(&owned)))
    }
}

/// Build a matcher for adapter-emitted callable names.
///
/// Call-site IR commonly stores the source spelling (`client.execute`) while
/// declarations and search results expose a compiler-qualified name
/// (`pkg.Service.execute`). A non-regex filter therefore admits either the
/// complete requested spelling or its parser-independent callable tail.
/// This is candidate matching for syntax inventories; semantic commands
/// continue to resolve exact symbol identities through the call graph.
pub(crate) fn make_callable_name_filter(
    needle: Option<&str>,
    is_regex: bool,
) -> Result<NameFilter, regex::Error> {
    let Some(pattern) = needle else {
        return Ok(Box::new(|_| true));
    };
    if is_regex {
        return make_name_filter(Some(pattern), true);
    }
    let qualified = pattern.to_string();
    let tail = bonsai_common::short_qualified_tail(pattern).to_string();
    Ok(Box::new(move |candidate: &str| {
        candidate.contains(&qualified) || (!tail.is_empty() && candidate.contains(&tail))
    }))
}

/// Match a user-facing file/path filter against the path relative to
/// the selected workspace. Explicit absolute filters are still
/// accepted for callers that pass a full path.
#[must_use]
pub fn file_path_matches_filter(ws: &Workspace, path: &str, filter: &str) -> bool {
    bonsai_common::path_filter_matches_with_root(ws.db().workspace_root().as_deref(), path, filter)
}

#[must_use]
pub fn file_path_excluded_by_filters(ws: &Workspace, path: &str, filters: &[String]) -> bool {
    filters
        .iter()
        .any(|filter| file_path_matches_filter(ws, path, filter))
}

/// Normalize a VFS or finding path relative to the selected workspace.
///
/// Compiler internals retain absolute paths for identity and cache safety, but
/// browse/SDK surfaces must not leak the host's ancestor directories into
/// locators or hierarchical views.
#[must_use]
pub fn workspace_relative_path(ws: &Workspace, path: &str) -> String {
    bonsai_common::workspace_relative_filter_path(ws.db().workspace_root().as_deref(), path)
}

/// Resolve either a workspace-relative rendered location or an explicit
/// absolute path back to its immutable compiler file identity.
///
/// Renderers must not depend on absolute host paths, while source hydration
/// must still join a displayed location to the VFS without basename guessing.
#[must_use]
pub fn workspace_file_id(ws: &Workspace, path: &str) -> Option<bonsai_common::FileId> {
    let requested = std::path::Path::new(path);
    if let Some(file) = ws.vfs().lookup(requested) {
        return Some(file);
    }
    if !requested.is_absolute() {
        if let Some(root) = ws.db().workspace_root().as_deref() {
            if let Some(file) = ws.vfs().lookup(&root.join(requested)) {
                return Some(file);
            }
        }
    }
    let requested = bonsai_common::normalize_path_for_filter(path);
    ws.vfs().all_files().into_iter().find(|file| {
        ws.vfs().path(*file).ok().is_some_and(|candidate| {
            let candidate = candidate.to_string_lossy();
            let absolute = bonsai_common::normalize_path_for_filter(&candidate);
            absolute == requested
                || workspace_relative_path(ws, &candidate)
                    == bonsai_common::workspace_relative_filter_path(None, &requested)
        })
    })
}

/// Query relevance key for browse rows. Lower is better.
///
/// Regex filters keep the pre-existing deterministic sort because a
/// regex does not have a stable notion of prefix/exact relevance
/// without re-running capture analysis per row. Plain-text filters
/// rank exact matches first, then prefix matches, then substring
/// matches, with shorter candidates winning inside each bucket.
#[must_use]
pub(crate) fn textual_relevance_key(candidate: &str, query: Option<&str>, regex: bool) -> (u8, usize) {
    let Some(query) = query.filter(|q| !q.is_empty()) else {
        return (u8::MAX, candidate.len());
    };
    if regex {
        return (u8::MAX, candidate.len());
    }
    let candidate_lower = candidate.to_lowercase();
    let query_lower = query.to_lowercase();
    let bucket = if candidate == query {
        0
    } else if candidate_lower == query_lower {
        1
    } else if candidate.starts_with(query) {
        2
    } else if candidate_lower.starts_with(&query_lower) {
        3
    } else if candidate.contains(query) {
        4
    } else if candidate_lower.contains(&query_lower) {
        5
    } else {
        6
    };
    (bucket, candidate.len())
}

/// Best relevance key across a row's candidate strings. Lower is better.
#[must_use]
pub(crate) fn best_textual_relevance_key<'a>(
    candidates: impl IntoIterator<Item = &'a str>,
    query: Option<&str>,
    regex: bool,
) -> (u8, usize) {
    candidates
        .into_iter()
        .map(|candidate| textual_relevance_key(candidate, query, regex))
        .min()
        .unwrap_or((u8::MAX, usize::MAX))
}

/// Canonical locator carried by every cross-row connection in
/// `tree` / `read-file` (and any other future browse surface that
/// surfaces cross-file edges or per-line marks).
///
/// Composes the same fields the existing browse rows already
/// carry separately: workspace-relative path, 1-indexed line +
/// column, enclosing module / class / decl, declaration kind,
/// adapter-emitted qualified name when present, and language id.
/// Renderers compose `module=… class=… fn=… (file:line:col)`
/// from these fields the same way `dump-edges` and `inspect`
/// already render decl headers.
///
/// `file = "external"` denotes an unresolved cross-file edge whose
/// callee is outside the workspace (stdlib, third-party, FFI).
/// In that case `line` / `column` are `0` and the renderer
/// formats it as `external` with the `ExternalKind` suffix the
/// caller supplies.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Locator {
    pub file: String,
    pub line: u32,
    pub column: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decl_kind: Option<DeclKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualified_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

impl Locator {
    /// External-locator constructor for unresolved cross-file edges.
    /// `decl` is the bare callee name (e.g. `"subprocess.call"`); no
    /// file or line numbers are attached because the target is
    /// outside the workspace.
    #[must_use]
    pub fn external(decl: impl Into<String>) -> Self {
        Self {
            file: "external".to_string(),
            line: 0,
            column: 0,
            decl: Some(decl.into()),
            ..Self::default()
        }
    }

    /// Build a [`Locator`] from a [`Span`] + workspace context.
    /// Pulls module from the file path's stem (or the adapter's
    /// path-to-module convention when one is documented), class /
    /// decl from the enclosing-decl lookup, and language from the
    /// adapter registry. Any field that can't be resolved cleanly
    /// stays `None` — the renderer falls back to whatever it has.
    #[must_use]
    pub fn from_span(span: Span, ws: &Workspace) -> Self {
        let (file, line, column) = format_span(&span, ws);
        let mut loc = Self {
            file,
            line,
            column,
            ..Self::default()
        };
        let db = ws.db();
        loc.language = db
            .adapter_for(span.file)
            .map(|a| a.language_id().as_str().to_string());
        let global = ws.compiler_linkage_index();
        let decls_in_file: &[bonsai_lang_api::Decl] = global.decls_in(span.file);
        let decls_ref: Vec<&bonsai_lang_api::Decl> = decls_in_file.iter().collect();
        if let Some((_func_id, decl_name)) = bonsai_inspect::find_enclosing_func(&decls_ref, span) {
            loc.decl = Some(decl_name);
            // Walk decls again to find the matching record so we
            // can fill in decl_kind, qualified_name, and class
            // (when the parent decl is a class-shape).
            for decl in decls_in_file {
                if loc.decl.as_deref() == Some(decl.name.as_str())
                    && decl.span.file == span.file
                    && decl.span.start <= span.start
                    && span.end <= decl.span.end
                {
                    loc.decl_kind = Some(decl.kind);
                    loc.qualified_name.clone_from(&decl.qualified_name);
                    // Only methods / constructors carry a class;
                    // bare functions live at module scope.
                    if matches!(decl.kind, DeclKind::Method | DeclKind::Constructor) {
                        if let Some(parent_sym) = decl.parent {
                            if let Some(parent_decl) = global.decl_of(parent_sym) {
                                if matches!(
                                    parent_decl.kind,
                                    DeclKind::Class
                                        | DeclKind::Struct
                                        | DeclKind::Trait
                                        | DeclKind::Interface
                                        | DeclKind::Enum
                                ) {
                                    loc.class = Some(parent_decl.name.clone());
                                }
                            }
                        }
                    }
                    break;
                }
            }
        }
        // module: prefer adapter-emitted qualified_name's prefix if
        // it's dotted; otherwise fall back to the file stem. This
        // mirrors how func_display_name composes module strings
        // for browse rows today.
        loc.module = match (&loc.qualified_name, &loc.decl) {
            (Some(qualified), Some(decl))
                if qualified.ends_with(decl.as_str()) && qualified.len() > decl.len() + 1 =>
            {
                bonsai_common::qualified_name_owner(qualified).map(str::to_string)
            }
            _ => derive_module_from_path(&loc.file),
        };
        loc
    }
}

/// Cheap path-to-module helper. Strips the file extension and
/// replaces `/` with `.` so `auth/verify_token.py` → `auth.verify_token`.
/// Languages where the adapter populates `Decl.qualified_name`
/// (Java/Kotlin/Scala) override this via `from_span`'s qualified-
/// name path.
fn derive_module_from_path(path: &str) -> Option<String> {
    if path.is_empty() || path == "external" || path == "<unknown>" {
        return None;
    }
    let without_ext = path.rsplit_once('.').map(|(stem, _)| stem).unwrap_or(path);
    let dotted = without_ext.replace(['/', '\\'], ".");
    if dotted.is_empty() {
        None
    } else {
        Some(dotted)
    }
}

/// Resolve `span` to its `(path, line, column)` triple.
/// Returns `("<unknown>", 0, 0)` if the span's file isn't in the
/// workspace's VFS — keeps every browse renderer crash-free even
/// when an adapter produces a stale FileId.
#[must_use]
pub fn format_span(span: &Span, ws: &Workspace) -> (String, u32, u32) {
    let path = ws
        .vfs()
        .path(span.file)
        .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
    let path = if path == "<unknown>" {
        path
    } else {
        workspace_relative_path(ws, &path)
    };
    let snapshot = ws.vfs().snapshot(span.file).ok();
    let (line, column) = if let Some(snap) = snapshot {
        // Share the line index across calls for the same immutable snapshot.
        let map = bonsai_common::cached_span_map_arc(span.file, snap.version, &snap.text);
        let line_col = map.line_col(span.start);
        (line_col.line, line_col.column)
    } else {
        (0, 0)
    };
    (path, line, column)
}

/// Truncate `s` to at most `max_bytes` bytes, rounding down to the
/// nearest UTF-8 char boundary so the returned slice is always
/// valid UTF-8. Append `ellipsis` when truncation actually happened.
///
/// Naively slicing with `&s[..n]` panics when `n` lands in the
/// middle of a multi-byte code point — a real prod hazard on
/// repos like the TypeScript compiler (box-drawing chars in
/// source) or anything with CJK / emoji identifiers. Every
/// renderer in this crate goes through this helper.
#[must_use]
pub(crate) fn truncate_at_char_boundary(s: &str, max_bytes: usize, ellipsis: &str) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    // Walk backward from max_bytes until we hit a valid char
    // boundary. `is_char_boundary(0)` is always true so this
    // always terminates.
    let mut cut = max_bytes;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{}", &s[..cut], ellipsis)
}

/// Walk a decl's `flow_events` and collect every textual call name
/// (including the qualified form like `authService.runAdminCommand`).
/// Recurses through every structural variant (`Branch`, `Loop`,
/// `Try`, `Defer`, `Using`).
#[must_use]
pub fn collect_callee_names(events: &[bonsai_lang_api::FlowEvent]) -> Vec<String> {
    let mut out = Vec::new();
    collect_callees(events, &mut out);
    out
}

pub(crate) fn collect_callees(events: &[bonsai_lang_api::FlowEvent], out: &mut Vec<String>) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Call { name, .. } => out.push(name.clone()),
            FlowEvent::Assign {
                source_call: Some(name),
                ..
            } => out.push(name.clone()),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_callees(then_events, out);
                collect_callees(else_events, out);
            }
            FlowEvent::Loop { body, .. } => collect_callees(body, out),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_callees(body, out);
                collect_callees(catch_events, out);
                collect_callees(finally_events, out);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_callees(body, out);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "common_relevance_tests.rs"]
mod relevance_tests;

#[cfg(test)]
#[path = "common_truncate_tests.rs"]
mod truncate_tests;
