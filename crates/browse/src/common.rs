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
        let global = db.global_index();
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
                // Drop the decl tail and the separator(s) before it.
                // `strip_suffix` + `trim_end_matches` is char-boundary-safe
                // (unlike a raw byte slice) and also handles multi-byte
                // separators like `::` cleanly — a fixed `len - decl - 1`
                // slice left a stray trailing `:` on `a::b::foo`.
                let prefix = qualified
                    .strip_suffix(decl.as_str())
                    .map_or(qualified.as_str(), |p| p.trim_end_matches(['.', ':']));
                Some(prefix.to_string())
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
#[path = "common_truncate_tests.rs"]
mod truncate_tests;
