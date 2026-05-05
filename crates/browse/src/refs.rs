//! `bonsai-ninja refs` data layer.

use crate::common::format_span;
use crate::strings::enclosing_fn_for_file_line;
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
/// Non-regex queries first try the resolver-driven `refs_to(sym)`
/// lookup (fast, exact); they fall back to a full ref-table scan
/// when nothing comes back. Regex queries always scan.
pub fn refs(ws: &Workspace, symbol: &str, f: &RefsFilters<'_>) -> Result<Vec<RefOut>, regex::Error> {
    let global = ws.db().global_index();
    // Non-regex queries match either the bare name (`open`) or a
    // qualified suffix (`fs.open` matches when the user passes `open`).
    let symbol_match: Box<dyn Fn(&str) -> bool + Send + Sync> = if f.regex {
        let compiled = regex::Regex::new(symbol)?;
        Box::new(move |s: &str| compiled.is_match(s))
    } else {
        let needle = symbol.to_string();
        let dotted_suffix = format!(".{needle}");
        Box::new(move |s: &str| s == needle || s.ends_with(&dotted_suffix))
    };
    // Refs at a span where both a Read AND a Call exist are the DSL
    // subscript-synthesis signature (see `extract_call_refs` in
    // `lang_api::kit`): `params[:x]`, `row[0]`, `session['user']`
    // emit a `Read` at the subscript plus a synthetic `Call` so
    // security rules shaped as `kind: call callee.name: params` fire.
    // For the human-facing refs table this double-counts every
    // subscript with a misleading `call` row. Pre-build the set of
    // "spans with a Read ref" per file so we can drop the synthetic
    // Call without losing the real one.
    let subscript_call_spans: ahash::AHashMap<bonsai_common::FileId, ahash::AHashSet<(u64, u64)>> = {
        let mut map: ahash::AHashMap<bonsai_common::FileId, ahash::AHashSet<(u64, u64)>> =
            ahash::AHashMap::default();
        for file in global.all_files() {
            if let Some(idx) = global.file_index(file) {
                let read_spans: ahash::AHashSet<(u64, u64)> = idx
                    .refs
                    .iter()
                    .filter(|reference| reference.kind == bonsai_lang_api::RefKind::Read)
                    .map(|reference| (reference.span.start, reference.span.end))
                    .collect();
                if !read_spans.is_empty() {
                    map.insert(file, read_spans);
                }
            }
        }
        map
    };
    let is_synthetic_call = |file: bonsai_common::FileId, reference: &bonsai_lang_api::Ref| -> bool {
        reference.kind == bonsai_lang_api::RefKind::Call
            && subscript_call_spans
                .get(&file)
                .is_some_and(|set| set.contains(&(reference.span.start, reference.span.end)))
    };
    let mut out: Vec<RefOut> = Vec::new();
    // Fast path: exact-name lookup against the resolver's
    // symbol → refs table. Skipped for regex queries since that
    // table is indexed by exact name only.
    if !f.regex {
        let symbol_ids = global.find_by_name(symbol);
        for &sym_id in symbol_ids {
            for (file_id, reference) in global.refs_to(sym_id) {
                if is_synthetic_call(file_id, reference) {
                    continue;
                }
                let (path, line, column) = format_span(&reference.span, ws);
                let snippet = read_snippet(ws, &reference.span);
                out.push(RefOut {
                    symbol: reference.name.clone(),
                    file: path,
                    line,
                    column,
                    kind: format!("{:?}", reference.kind).to_lowercase(),
                    snippet,
                });
            }
        }
    }
    // Fallback: full ref-table scan. Always runs for regex queries;
    // also runs for substring queries when the fast path produced
    // nothing (callee names that are method-shaped — `socket.send` —
    // don't sit under the bare `send` symbol).
    if out.is_empty() || f.regex {
        use rayon::prelude::*;
        let files: Vec<_> = global.all_files().collect();
        let mut extra: Vec<RefOut> = files
            .par_iter()
            .flat_map_iter(|&file| {
                let mut per_file: Vec<RefOut> = Vec::new();
                let Some(idx) = global.file_index(file) else {
                    return per_file.into_iter();
                };
                for reference in &idx.refs {
                    if symbol_match(&reference.name) && !is_synthetic_call(file, reference) {
                        let (path, line, column) = format_span(&reference.span, ws);
                        per_file.push(RefOut {
                            symbol: reference.name.clone(),
                            file: path,
                            line,
                            column,
                            kind: format!("{:?}", reference.kind).to_lowercase(),
                            snippet: read_snippet(ws, &reference.span),
                        });
                    }
                }
                per_file.into_iter()
            })
            .collect();
        out.append(&mut extra);
    }
    // Group by ref kind (read / write / call / decorator / type) so
    // each kind clusters, then alphabetical by symbol, then
    // file/line for disambiguation.
    out.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.symbol.cmp(&b.symbol))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });
    out.retain(|reference| {
        if f.kind.is_some_and(|k| !reference.kind.eq_ignore_ascii_case(k)) {
            return false;
        }
        if f.file.is_some_and(|needle| !reference.file.contains(needle)) {
            return false;
        }
        if let Some(needle) = f.in_fn {
            let enclosing =
                enclosing_fn_for_file_line(ws, &reference.file, reference.line).unwrap_or_default();
            if !enclosing.contains(needle) {
                return false;
            }
        }
        true
    });
    Ok(out)
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
