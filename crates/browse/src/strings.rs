//! `bonsai-ninja strings` data layer.

use crate::common::{format_span, make_name_filter};
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Filter bundle for [`strings`].
#[derive(Copy, Clone, Default, Debug)]
pub struct StringsFilters<'a> {
    /// `--category sql|url|shell|...` — substring match against
    /// the adapter-emitted category tag.
    pub category: Option<&'a str>,
    /// `--contains X` — substring (or regex) over the literal's
    /// text body.
    pub contains: Option<&'a str>,
    /// `--file substring` against the literal's source path.
    pub file: Option<&'a str>,
    /// `--in-fn X` — only keep literals whose enclosing function's
    /// name contains `X`.
    pub in_fn: Option<&'a str>,
    /// Drop literals with fewer than this many chars (post strip).
    pub min_len: Option<usize>,
    /// Treat `contains` as a regex.
    pub regex: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct StringOut {
    pub text: String,
    pub category: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
}

/// Collect every string literal matching the filters.
pub fn strings(ws: &Workspace, f: &StringsFilters<'_>) -> Result<Vec<StringOut>, regex::Error> {
    use rayon::prelude::*;
    let global = ws.db().global_index();
    let contains_match = make_name_filter(f.contains, f.regex)?;
    let files: Vec<_> = global.all_files().collect();
    let mut out: Vec<StringOut> = files
        .par_iter()
        .flat_map_iter(|&file| {
            let mut per_file: Vec<StringOut> = Vec::new();
            let Some(idx) = global.file_index(file) else {
                return per_file.into_iter();
            };
            for s in &idx.strings {
                let cat = format!("{:?}", s.category).to_lowercase();
                if f.category.is_some_and(|c| !cat.contains(&c.to_lowercase())) {
                    continue;
                }
                if !contains_match(&s.text) {
                    continue;
                }
                if let Some(min_chars) = f.min_len {
                    // `chars().count()` is O(n) but strings are short
                    // and we only walk on cheap-checks-passed.
                    if s.text.chars().count() < min_chars {
                        continue;
                    }
                }
                let (path, line, col) = format_span(&s.span, ws);
                if f.file.is_some_and(|needle| !path.contains(needle)) {
                    continue;
                }
                if let Some(needle) = f.in_fn {
                    let enclosing = enclosing_fn_for_file_line(ws, &path, line).unwrap_or_default();
                    if !enclosing.contains(needle) {
                        continue;
                    }
                }
                per_file.push(StringOut {
                    text: s.text.clone(),
                    category: cat,
                    file: path,
                    line,
                    column: col,
                });
            }
            per_file.into_iter()
        })
        .collect();
    // Group by category (sql / url / shell / …) so each category's
    // strings cluster together, then alphabetical by text, then
    // file/line for stability.
    out.sort_by(|a, b| {
        a.category
            .cmp(&b.category)
            .then_with(|| a.text.cmp(&b.text))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });
    Ok(out)
}

/// Cache-aware shortcut over the workspace's snapshot + span-map
/// machinery. Returns `None` when the file isn't in the VFS.
fn cached_span_map(
    ws: &Workspace,
    file: bonsai_common::FileId,
) -> Option<std::sync::Arc<bonsai_common::SpanMap>> {
    let snap = ws.vfs().snapshot(file).ok()?;
    Some(bonsai_common::cached_span_map_arc(file, snap.version, &snap.text))
}

/// Find the enclosing function/method name for a given path + line.
/// Public so the CLI's renderer can surface the same information
/// alongside table rows without re-implementing the logic.
#[must_use]
pub fn enclosing_fn_for_file_line(ws: &Workspace, file_path: &str, line: u32) -> Option<String> {
    use bonsai_lang_api::DeclKind;
    let global = ws.db().global_index();
    // Look up the file by path string. Linear scan is fine — we
    // only call this once per browse-row's enclosing-fn check.
    let span_map_cache_file = global.all_files().find(|f| {
        ws.vfs()
            .path(*f)
            .map(|p| p.display().to_string())
            .is_ok_and(|p| p == file_path)
    })?;
    let span_map = cached_span_map(ws, span_map_cache_file)?;
    // Track the narrowest enclosing decl so a nested function /
    // method beats its containing module-level wrapper.
    let mut best: Option<(&bonsai_lang_api::Decl, u32)> = None;
    for d in global.decls_in(span_map_cache_file) {
        if !matches!(
            d.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        let body = d.body_span.unwrap_or(d.span);
        let start_line = span_map.line_col(body.start).line;
        let end_line = span_map.line_col(body.end.saturating_sub(1)).line;
        if start_line <= line && line <= end_line {
            let width = end_line.saturating_sub(start_line);
            if best.is_none_or(|(_, best_width)| width < best_width) {
                best = Some((d, width));
            }
        }
    }
    best.map(|(d, _)| d.name.clone())
}
