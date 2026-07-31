//! `bonsai-ninja refs` data layer.

use crate::common::{file_path_matches_filter, format_span, textual_relevance_key};
use bonsai_common::short_qualified_tail;
use bonsai_lang_api::FlowEvent;
use bonsai_workspace::Workspace;
use serde::Serialize;

const SNIPPET_MAX_LINES: usize = 4;
const SNIPPET_MAX_CHARS: usize = 512;

/// Filter bundle for [`refs`].
#[derive(Copy, Clone, Default, Debug)]
pub struct RefsFilters<'a> {
    /// `--kind read|write|call|decorator|type` — exact (case-
    /// insensitive) match against the ref's kind tag.
    pub kind: Option<&'a str>,
    /// `--file substring` against the ref's source path.
    pub file: Option<&'a str>,
    /// `--in-fn X` — only keep refs whose enclosing function's
    /// name contains `X`.
    pub in_fn: Option<&'a str>,
    /// Treat the symbol query as a regex instead of an exact
    /// (or `.suffix`) match.
    pub regex: bool,
}

/// One row of `refs` output.
#[derive(Serialize, Clone, Debug)]
pub struct RefOut {
    pub symbol: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub kind: String,
    pub snippet: String,
}

/// All references to a `symbol` (or matching a regex when
/// `f.regex` is set), filtered by kind / file / enclosing fn.
///
/// Exact file-local compiler objects remain the source of truth. The CLI may
/// use the retrieval sidecar to narrow candidate files, but every rendered row
/// is hydrated from adapter-lowered reference or flow facts.
pub fn refs(ws: &Workspace, symbol: &str, f: &RefsFilters<'_>) -> Result<Vec<RefOut>, regex::Error> {
    use rayon::prelude::*;

    // Non-regex queries match either the bare name (`open`) or a
    // qualified suffix (`fs.open` matches when the user passes `open`).
    let symbol_match: Box<dyn Fn(&str) -> bool + Send + Sync> = if f.regex {
        let compiled = regex::Regex::new(symbol)?;
        Box::new(move |s: &str| compiled.is_match(s))
    } else {
        let needle = symbol.to_string();
        let lexical_name = short_qualified_tail(symbol).to_string();
        let dotted_suffix = format!(".{lexical_name}");
        let dotted_prefix = format!("{lexical_name}.");
        Box::new(move |s: &str| {
            s == needle || s == lexical_name || s.ends_with(&dotted_suffix) || s.starts_with(&dotted_prefix)
        })
    };
    let files = ws.vfs().all_files();
    let mut out: Vec<RefOut> = files
        .par_iter()
        .fold(Vec::new, |mut per_thread, &file| {
            let file_path = ws
                .vfs()
                .path(file)
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_default();
            if f.file
                .is_some_and(|needle| !file_path_matches_filter(ws, &file_path, needle))
            {
                return per_thread;
            }
            let Some(index) = ws.db().decl_index_uncached(file) else {
                return per_thread;
            };

            // A Call at the exact same span as a Read is the adapter's
            // subscript-DSL synthesis (`params[:x]`, `row[0]`). Keep the real
            // Read and omit the browse-only duplicate Call.
            let read_spans: ahash::AHashSet<(u64, u64)> = index
                .refs
                .iter()
                .filter(|reference| reference.kind == bonsai_lang_api::RefKind::Read)
                .map(|reference| (reference.span.start, reference.span.end))
                .collect();
            for reference in &index.refs {
                if !symbol_match(&reference.name)
                    || (reference.kind == bonsai_lang_api::RefKind::Call
                        && read_spans.contains(&(reference.span.start, reference.span.end)))
                {
                    continue;
                }
                let kind = format!("{:?}", reference.kind).to_lowercase();
                if f.kind.is_some_and(|wanted| !kind.eq_ignore_ascii_case(wanted))
                    || f.in_fn.is_some_and(|needle| {
                        !enclosing_function_for_span(&index, reference.span)
                            .is_some_and(|name| name.contains(needle))
                    })
                {
                    continue;
                }
                let (path, line, column) = format_span(&reference.span, ws);
                per_thread.push(RefOut {
                    symbol: reference.name.clone(),
                    file: path,
                    line,
                    column,
                    kind,
                    snippet: read_snippet(ws, &reference.span),
                });
            }

            if f.kind.is_none_or(|wanted| wanted.eq_ignore_ascii_case("read")) {
                for decl in &index.defs {
                    if f.in_fn.is_some_and(|needle| !decl.name.contains(needle)) {
                        continue;
                    }
                    walk_flow_source_reads(&decl.flow_events, &mut |name, span| {
                        if !symbol_match(name) {
                            return;
                        }
                        let span = refine_span_to_name(ws, span, name);
                        let (path, line, column) = format_span(&span, ws);
                        per_thread.push(RefOut {
                            symbol: name.to_string(),
                            file: path,
                            line,
                            column,
                            kind: "read".to_string(),
                            snippet: read_snippet(ws, &span),
                        });
                    });
                }
            }
            per_thread
        })
        .reduce(Vec::new, |mut larger, mut smaller| {
            if smaller.len() > larger.len() {
                std::mem::swap(&mut larger, &mut smaller);
            }
            larger.extend(smaller);
            larger
        });
    let mut seen = ahash::AHashSet::default();
    out.retain(|reference| {
        seen.insert((
            reference.symbol.clone(),
            reference.file.clone(),
            reference.line,
            reference.column,
            reference.kind.clone(),
        ))
    });
    // Rank the queried symbol before deterministic kind/file grouping
    // so exact and prefix hits survive small render budgets first.
    let symbol_rank = |reference: &RefOut| {
        if !f.regex {
            textual_relevance_key(&reference.symbol, Some(symbol), false)
        } else {
            (u8::MAX, usize::MAX)
        }
    };
    out.sort_by(|a, b| {
        symbol_rank(a)
            .cmp(&symbol_rank(b))
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.symbol.cmp(&b.symbol))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });
    Ok(out)
}

fn enclosing_function_for_span(
    index: &bonsai_lang_api::DeclIndex,
    span: bonsai_common::Span,
) -> Option<&str> {
    use bonsai_lang_api::DeclKind;
    index
        .defs
        .iter()
        .filter(|decl| {
            matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            )
        })
        .filter(|decl| {
            let body = decl.body_span.unwrap_or(decl.span);
            body.file == span.file && body.start <= span.start && span.end <= body.end
        })
        .min_by_key(|decl| {
            let body = decl.body_span.unwrap_or(decl.span);
            body.end.saturating_sub(body.start)
        })
        .map(|decl| decl.name.as_str())
}

fn refine_span_to_name(ws: &Workspace, span: bonsai_common::Span, name: &str) -> bonsai_common::Span {
    if name.is_empty() {
        return span;
    }
    let Ok(snapshot) = ws.vfs().snapshot(span.file) else {
        return span;
    };
    let bytes = snapshot.text.as_bytes();
    if bytes.is_empty() {
        return span;
    }
    let span_start = (span.start as usize).min(bytes.len());
    let span_end = (span.end as usize).min(bytes.len()).max(span_start);
    let line_start = bytes[..span_start]
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |idx| idx + 1);
    let line_end = bytes[span_end..]
        .iter()
        .position(|b| *b == b'\n')
        .map_or(bytes.len(), |idx| span_end + idx);
    let line = &snapshot.text[line_start..line_end];
    let Some(offset) = find_token_offset(line, name) else {
        return span;
    };
    bonsai_common::Span {
        file: span.file,
        start: (line_start + offset) as u64,
        end: (line_start + offset + name.len()) as u64,
    }
}

fn find_token_offset(line: &str, name: &str) -> Option<usize> {
    for (offset, _) in line.match_indices(name) {
        let before = line[..offset].chars().next_back();
        let after = line[offset + name.len()..].chars().next();
        let before_boundary = before.is_none_or(|ch| !is_ident_char(ch));
        let after_boundary = after.is_none_or(|ch| !is_ident_char(ch));
        if before_boundary && after_boundary {
            return Some(offset);
        }
    }
    line.find(name)
}

fn is_ident_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

fn walk_flow_source_reads(events: &[FlowEvent], visit: &mut impl FnMut(&str, bonsai_common::Span)) {
    for event in events {
        match event {
            FlowEvent::Call {
                span, receiver, args, ..
            } => {
                if let Some(receiver) = receiver.as_deref() {
                    visit(receiver, *span);
                }
                for arg in args {
                    if let Some(place) = arg.place.as_deref() {
                        visit(place, arg.span);
                    }
                    for source in &arg.source_names {
                        visit(source, arg.span);
                    }
                }
            }
            FlowEvent::Assign {
                span,
                source_name,
                source_names,
                source_call_args,
                ..
            } => {
                if let Some(source) = source_name.as_deref() {
                    visit(source, *span);
                }
                for source in source_names {
                    visit(source, *span);
                }
                for arg in source_call_args {
                    visit(arg, *span);
                }
            }
            FlowEvent::AggregateAssign { span, value_flow, .. } => {
                walk_expression_flow_reads(value_flow, &mut |source| visit(source, *span));
            }
            FlowEvent::Return { span, value_name, .. }
            | FlowEvent::Throw { span, value_name, .. }
            | FlowEvent::Await { span, value_name } => {
                if let Some(value) = value_name.as_deref() {
                    visit(value, *span);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk_flow_source_reads(then_events, visit);
                walk_flow_source_reads(else_events, visit);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_flow_source_reads(body, visit);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                walk_flow_source_reads(body, visit);
                walk_flow_source_reads(catch_events, visit);
                walk_flow_source_reads(finally_events, visit);
            }
            FlowEvent::Yield { .. }
            | FlowEvent::Break { .. }
            | FlowEvent::Continue { .. }
            | FlowEvent::Lifecycle { .. } => {}
        }
    }
}

fn walk_expression_flow_reads(flow: &bonsai_lang_api::ExpressionFlow, visit: &mut impl FnMut(&str)) {
    if let Some(place) = flow.place.as_deref() {
        visit(place);
    }
    for source in &flow.source_names {
        visit(source);
    }
    for field in &flow.aggregate_fields {
        walk_expression_flow_reads(&field.value, visit);
    }
    for item in &flow.tuple_items {
        walk_expression_flow_reads(item, visit);
    }
    for spread in &flow.spreads {
        walk_expression_flow_reads(spread, visit);
    }
}

/// Read the source line(s) covering `span`, widened to line edges.
/// Public so the CLI's renderer can re-use it when annotating
/// hits without re-implementing the line-widening logic.
#[must_use]
pub fn read_snippet(ws: &Workspace, span: &bonsai_common::Span) -> String {
    let Ok(snapshot) = ws.vfs().snapshot(span.file) else {
        return String::new();
    };
    let bytes = snapshot.text.as_bytes();
    let span_start = (span.start as usize).min(bytes.len());
    let span_end = (span.end as usize).min(bytes.len()).max(span_start);
    let start = bytes[..span_start]
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |i| i + 1);
    let end = bytes[span_end..]
        .iter()
        .position(|b| *b == b'\n')
        .map_or(bytes.len(), |i| span_end + i);
    let raw = String::from_utf8_lossy(&bytes[start..end]);
    bounded_snippet(&raw)
}

/// Cap a snippet at [`SNIPPET_MAX_LINES`] lines and
/// [`SNIPPET_MAX_CHARS`] chars, appending an ellipsis when either
/// limit fired.
fn bounded_snippet(raw: &str) -> String {
    let mut snippet: String = raw.lines().take(SNIPPET_MAX_LINES).collect::<Vec<_>>().join("\n");
    let line_truncated = raw.lines().nth(SNIPPET_MAX_LINES).is_some();

    let mut char_truncated = false;
    if snippet.chars().count() > SNIPPET_MAX_CHARS {
        snippet = snippet.chars().take(SNIPPET_MAX_CHARS).collect();
        char_truncated = true;
    }

    if line_truncated || char_truncated {
        if !snippet.ends_with('\n') && !snippet.is_empty() {
            snippet.push('\n');
        }
        snippet.push('…');
    }
    snippet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualified_symbol_query_matches_adapter_emitted_short_reference() {
        let root = tempfile::tempdir().expect("workspace tempdir");
        std::fs::write(
            root.path().join("service.py"),
            "def target(value):\n    return value\n\ndef caller(value):\n    return target(value)\n",
        )
        .expect("write fixture");
        let workspace =
            Workspace::index(root.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

        let rows = refs(&workspace, "package.service.target", &RefsFilters::default())
            .expect("qualified refs query");

        assert!(
            rows.iter().any(|row| row.symbol == "target"),
            "a compiler-qualified query must still match the adapter's short call reference"
        );
    }
}
