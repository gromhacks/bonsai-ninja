//! Shared decorator / annotation attachment helpers.
//!
//! Adapters expose decorators as file-level refs. Analysis layers that
//! need declaration-scoped behavior must attach those refs back to a
//! declaration using source spans rather than treating the whole file as
//! decorated.

use crate::Workspace;
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{DeclIndex, RefKind};

/// Decorator / annotation names statically attached to a declaration.
///
/// Adapters use two valid shapes:
///
/// - Python-style decorators are refs immediately before the declaration
///   span.
/// - Java/Rust/C#/TypeScript-style annotations may be refs inside the
///   declaration span but before the declaration name.
///
/// Returned names include the full decorator name and qualified
/// segments, so `@app.route(...)` can match `app.route`, `app`, or
/// `route`.
#[must_use]
pub fn decl_decorator_names(
    ws: &Workspace,
    file: FileId,
    file_index: &DeclIndex,
    decl_span: Span,
    decl_name_span: Span,
) -> Vec<String> {
    let source_text = ws.vfs().snapshot(file).ok().map(|snapshot| snapshot.text);
    let mut out = Vec::new();
    for reference in &file_index.refs {
        if reference.kind != RefKind::Decorator || reference.span.end > decl_name_span.start {
            continue;
        }
        if !decorator_is_attached_to_decl(ws, file, reference.span, decl_span, decl_name_span) {
            continue;
        }
        for segment in decorator_name_segments(&reference.name) {
            push_unique(&mut out, segment);
        }
        if let Some(text) = source_text.as_deref() {
            let start = reference.span.start as usize;
            let end = reference.span.end as usize;
            if let Some(raw) = (start < end).then(|| text.get(start..end)).flatten() {
                let head = raw
                    .trim_start_matches('@')
                    .split(|ch: char| ch == '(' || ch.is_whitespace())
                    .next()
                    .unwrap_or("")
                    .trim_end_matches(',');
                for segment in decorator_name_segments(head) {
                    push_unique(&mut out, segment);
                }
            }
        }
    }
    out
}

fn decorator_is_attached_to_decl(
    ws: &Workspace,
    file: FileId,
    decorator_span: Span,
    decl_span: Span,
    decl_name_span: Span,
) -> bool {
    if decorator_span.end <= decl_span.start {
        if decl_span.start.saturating_sub(decorator_span.end) > 512 {
            return false;
        }
        return gap_has_only_decorator_prefix(ws, file, decorator_span.end, decl_span.start);
    }

    if decorator_span.start >= decl_span.start && decorator_span.end <= decl_name_span.start {
        if decl_name_span.start.saturating_sub(decorator_span.end) > 2048 {
            return false;
        }
        return gap_has_no_statement_boundary(ws, file, decorator_span.end, decl_name_span.start);
    }

    false
}

fn gap_has_only_decorator_prefix(ws: &Workspace, file: FileId, start: u64, end: u64) -> bool {
    let Ok(snapshot) = ws.vfs().snapshot(file) else {
        return false;
    };
    let text = snapshot.text.as_bytes();
    let start = start as usize;
    let end = end as usize;
    if start > end || end > text.len() {
        return false;
    }
    if start == end {
        return true;
    }
    let gap = &text[start..end];
    if gap.iter().any(|byte| {
        matches!(*byte, b'{' | b'}' | b';')
            || byte.is_ascii_control() && !matches!(*byte, b'\n' | b'\r' | b'\t')
    }) {
        return false;
    }
    let Ok(gap_text) = std::str::from_utf8(gap) else {
        return false;
    };
    gap_text.lines().all(|line| {
        let trimmed = line.trim();
        trimmed.is_empty()
            || trimmed.starts_with('@')
            || trimmed.starts_with("#[")
            || trimmed.starts_with('[')
            || trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
    })
}

fn gap_has_no_statement_boundary(ws: &Workspace, file: FileId, start: u64, end: u64) -> bool {
    let Ok(snapshot) = ws.vfs().snapshot(file) else {
        return false;
    };
    let text = snapshot.text.as_bytes();
    let start = start as usize;
    let end = end as usize;
    if start > end || end > text.len() {
        return false;
    }
    if start == end {
        return true;
    }
    !text[start..end].iter().any(|byte| {
        matches!(*byte, b'{' | b'}' | b';')
            || byte.is_ascii_control() && !matches!(*byte, b'\n' | b'\r' | b'\t')
    })
}

fn decorator_name_segments(raw: &str) -> Vec<String> {
    let trimmed = raw.trim().trim_start_matches('@').trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut segments = vec![trimmed.to_string()];
    for part in bonsai_common::qualified_name_segments(trimmed) {
        if !part.is_empty() && !segments.iter().any(|existing| existing == part) {
            segments.push(part.to_string());
        }
    }
    segments
}

fn push_unique(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_lang_api::LanguageRegistry;
    use std::sync::Arc;

    fn python_registry() -> Arc<LanguageRegistry> {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
        registry
    }

    fn rust_registry() -> Arc<LanguageRegistry> {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_rust::RustAdapter::new()));
        registry
    }

    #[test]
    fn attaches_decorator_to_decl_not_following_function_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            r#"
class App:
    def route(self, path):
        def deco(fn):
            return fn
        return deco

app = App()

@app.route("/x")
def decorated(request):
    return request

def helper(request):
    return request
"#,
        )
        .expect("write fixture");
        let ws = Workspace::index(dir.path(), python_registry()).expect("index fixture");
        let file = ws.vfs().all_files().into_iter().next().expect("file");
        let index = ws.db().decl_index(file).expect("decl index");

        let decorated = index
            .defs
            .iter()
            .find(|decl| decl.name == "decorated")
            .expect("decorated decl");
        let helper = index
            .defs
            .iter()
            .find(|decl| decl.name == "helper")
            .expect("helper decl");

        let decorated_names = decl_decorator_names(&ws, file, &index, decorated.span, decorated.name_span);
        assert!(decorated_names.iter().any(|name| name == "app.route"));
        assert!(decorated_names.iter().any(|name| name == "route"));
        assert!(decl_decorator_names(&ws, file, &index, helper.span, helper.name_span).is_empty());
    }

    #[test]
    fn attaches_attribute_inside_declaration_span_before_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("lib.rs"),
            r#"
#[derive(Debug)]
pub struct Decorated {
    value: String,
}

pub struct Helper {
    value: String,
}
"#,
        )
        .expect("write fixture");
        let ws = Workspace::index(dir.path(), rust_registry()).expect("index fixture");
        let file = ws.vfs().all_files().into_iter().next().expect("file");
        let index = ws.db().decl_index(file).expect("decl index");

        let decorated = index
            .defs
            .iter()
            .find(|decl| decl.name == "Decorated")
            .expect("decorated decl");
        let helper = index
            .defs
            .iter()
            .find(|decl| decl.name == "Helper")
            .expect("helper decl");

        let decorated_names = decl_decorator_names(&ws, file, &index, decorated.span, decorated.name_span);
        assert!(
            decorated_names.iter().any(|name| name == "derive"),
            "{decorated_names:?}"
        );
        assert!(decl_decorator_names(&ws, file, &index, helper.span, helper.name_span).is_empty());
    }
}
