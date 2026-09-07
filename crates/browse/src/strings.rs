//! `bonsai-ninja strings` data layer.

use crate::common::{
    admitted_file_decl_index, file_path_matches_filter, format_span, make_name_filter,
    source_files_small_first, textual_relevance_key,
};
use crate::literal_filter::{matches_min_len, LiteralFilterError};
use bonsai_workspace::Workspace;
use serde::{Deserialize, Serialize};

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
    /// Minimum adapter-proven lexical body length in Unicode scalar values.
    /// Delimiters/prefixes are excluded; escapes and whitespace stay verbatim.
    pub min_len: Option<usize>,
    /// Treat `contains` as a regex.
    pub regex: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StringOut {
    pub text: String,
    /// Adapter-proven lexical body length; unknown is distinct from empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_len: Option<usize>,
    pub category: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
}

/// Collect every string literal matching the filters.
pub fn strings(ws: &Workspace, f: &StringsFilters<'_>) -> Result<Vec<StringOut>, LiteralFilterError> {
    use rayon::prelude::*;
    let contains_match = make_name_filter(f.contains, f.regex)?;
    let files = source_files_small_first(ws);
    let memory_permits = bonsai_common::SyntaxMemoryPermitPool::for_current_process();
    let mut out: Vec<StringOut> = files
        .par_iter()
        .map(|&file| -> Result<Vec<StringOut>, LiteralFilterError> {
            let mut per_file: Vec<StringOut> = Vec::new();
            if let Some(needle) = f.file {
                let path = ws
                    .vfs()
                    .path(file)
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if !file_path_matches_filter(ws, &path, needle) {
                    return Ok(per_file);
                }
            }
            // String inventory consumes only file-local compiler facts.
            let Some(idx) = admitted_file_decl_index(ws, file, &memory_permits) else {
                return Ok(per_file);
            };
            let enclosing = f.in_fn.map(|_| {
                bonsai_workspace::enclosing_index::EnclosingSpanIndex::from_callable_decls(&idx.defs)
            });
            for s in &idx.strings {
                let cat = format!("{:?}", s.category).to_lowercase();
                if f.category.is_some_and(|c| !cat.contains(&c.to_lowercase())) {
                    continue;
                }
                if !contains_match(&s.text) {
                    continue;
                }
                if let Some(needle) = f.in_fn {
                    if !enclosing
                        .as_ref()
                        .and_then(|index| index.enclosing(s.span.start))
                        .is_some_and(|entry| entry.end >= s.span.end && entry.name.contains(needle))
                    {
                        continue;
                    }
                }
                if !matches_min_len(s.content_len, f.min_len, || format_span(&s.span, ws))? {
                    continue;
                }
                let (path, line, col) = format_span(&s.span, ws);
                per_file.push(StringOut {
                    text: s.text.clone(),
                    content_len: s.content_len,
                    category: cat,
                    file: path,
                    line,
                    column: col,
                });
            }
            Ok(per_file)
        })
        .try_reduce(Vec::new, |mut left, mut right| {
            if right.len() > left.len() {
                std::mem::swap(&mut left, &mut right);
            }
            left.append(&mut right);
            Ok(left)
        })?;
    // Group by category (sql / url / shell / …) so each category's
    // strings cluster together, then alphabetical by text, then
    // file/line for stability.
    out.sort_by(|a, b| {
        string_relevance_key(a, f)
            .cmp(&string_relevance_key(b, f))
            .then_with(|| {
                a.category
                    .cmp(&b.category)
                    .then_with(|| a.text.cmp(&b.text))
                    .then_with(|| a.file.cmp(&b.file))
                    .then_with(|| a.line.cmp(&b.line))
            })
    });
    Ok(out)
}

fn string_relevance_key(row: &StringOut, f: &StringsFilters<'_>) -> ((u8, usize), (u8, usize)) {
    let category = f.category.map_or((u8::MAX, usize::MAX), |category| {
        textual_relevance_key(&row.category, Some(category), false)
    });
    let text = f
        .contains
        .filter(|_| !f.regex)
        .map_or((u8::MAX, usize::MAX), |contains| {
            textual_relevance_key(&row.text, Some(contains), false)
        });
    (category, text)
}

/// Find the enclosing function/method name for a given path + line.
/// Public so the CLI's renderer can surface the same information
/// alongside table rows without re-implementing the logic.
#[must_use]
pub fn enclosing_fn_for_file_line(ws: &Workspace, file_path: &str, line: u32) -> Option<String> {
    crate::summary_labels::SummaryAnnotator::new(ws).enclosing_function_name(file_path, line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_line_functions_keep_their_own_string_and_comment_inventory() {
        let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
        workspace.vfs().write("app.js", "function alpha() { /* first */ return \"first\"; } function beta() { /* second */ return \"second\"; }\n");
        for (function, text) in [("alpha", "first"), ("beta", "second")] {
            let rows = strings(
                &workspace,
                &StringsFilters {
                    in_fn: Some(function),
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(rows.len(), 1, "{function}: {rows:?}");
            assert!(rows[0].text.contains(text), "{function}: {rows:?}");
            let comments = crate::comments::comments(
                &workspace,
                &crate::comments::CommentsFilters {
                    in_fn: Some(function),
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(comments.len(), 1, "{function}: {comments:?}");
            assert!(comments[0].text.contains(text), "{function}: {comments:?}");
        }
    }
}
