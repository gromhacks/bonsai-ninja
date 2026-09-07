//! `bonsai-ninja comments` data layer.

use crate::common::{
    admitted_file_decl_index, file_path_matches_filter, format_span, make_name_filter,
    source_files_small_first, textual_relevance_key,
};
use crate::literal_filter::{matches_min_len, LiteralFilterError};
use bonsai_workspace::Workspace;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Default, Debug)]
pub struct CommentsFilters<'a> {
    /// Kind narrower — `todo`, `fixme`, `security`, `doc`, `disabled_code`, `generic`.
    pub kind: Option<&'a str>,
    /// Substring (or regex when `regex=true`) that must appear in
    /// the comment text.
    pub contains: Option<&'a str>,
    /// Workspace-relative file path filter. Explicit absolute paths are
    /// also accepted.
    pub file: Option<&'a str>,
    /// Restrict to comments whose enclosing function matches this
    /// substring.
    pub in_fn: Option<&'a str>,
    /// Minimum adapter-proven lexical body length in Unicode scalar values.
    /// Comment markers are excluded; whitespace is preserved.
    pub min_len: Option<usize>,
    /// Treat `contains` as a regex.
    pub regex: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CommentOut {
    pub text: String,
    /// Adapter-proven lexical body length; unknown is distinct from empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_len: Option<usize>,
    pub kind: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
}

/// Collect every comment matching the filters.
pub fn comments(ws: &Workspace, f: &CommentsFilters<'_>) -> Result<Vec<CommentOut>, LiteralFilterError> {
    use rayon::prelude::*;
    let contains_match = make_name_filter(f.contains, f.regex)?;
    let files = source_files_small_first(ws);
    let memory_permits = bonsai_common::SyntaxMemoryPermitPool::for_current_process();
    let mut out: Vec<CommentOut> = files
        .par_iter()
        .map(|&file| -> Result<Vec<CommentOut>, LiteralFilterError> {
            let mut per_file: Vec<CommentOut> = Vec::new();
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
            let Some(idx) = admitted_file_decl_index(ws, file, &memory_permits) else {
                return Ok(per_file);
            };
            let enclosing = f.in_fn.map(|_| {
                bonsai_workspace::enclosing_index::EnclosingSpanIndex::from_callable_decls(&idx.defs)
            });
            for comment in &idx.comments {
                // Use the compiler enum's canonical serde spelling for both
                // filtering and output (for example, `disabled_code`).
                let serde_json::Value::String(kind) =
                    serde_json::to_value(comment.kind).expect("comment kind serializes")
                else {
                    unreachable!("comment kind serializes as a string");
                };
                if f.kind.is_some_and(|k| !kind.contains(&k.to_lowercase())) {
                    continue;
                }
                if !contains_match(&comment.text) {
                    continue;
                }
                if let Some(needle) = f.in_fn {
                    if !enclosing
                        .as_ref()
                        .and_then(|index| index.enclosing(comment.span.start))
                        .is_some_and(|entry| entry.end >= comment.span.end && entry.name.contains(needle))
                    {
                        continue;
                    }
                }
                if !matches_min_len(comment.content_len, f.min_len, || format_span(&comment.span, ws))? {
                    continue;
                }
                let (path, line, column) = format_span(&comment.span, ws);
                per_file.push(CommentOut {
                    text: comment.text.clone(),
                    content_len: comment.content_len,
                    kind,
                    file: path,
                    line,
                    column,
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
    // Group attention-grabbing kinds together, then alphabetical by
    // text, then file/line for stability. `security` first, then
    // `fixme`, then `todo`, then doc, disabled-code, generic.
    let kind_priority = |kind: &str| -> u8 {
        match kind {
            "security" => 0,
            "fixme" => 1,
            "todo" => 2,
            "doc" => 3,
            "disabled_code" => 4,
            _ => 5,
        }
    };
    out.sort_by(|a, b| {
        comment_relevance_key(a, f)
            .cmp(&comment_relevance_key(b, f))
            .then_with(|| {
                kind_priority(&a.kind)
                    .cmp(&kind_priority(&b.kind))
                    .then_with(|| a.file.cmp(&b.file))
                    .then_with(|| a.line.cmp(&b.line))
                    .then_with(|| a.text.cmp(&b.text))
            })
    });
    Ok(out)
}

fn comment_relevance_key(row: &CommentOut, f: &CommentsFilters<'_>) -> ((u8, usize), (u8, usize)) {
    let kind = f.kind.map_or((u8::MAX, usize::MAX), |kind| {
        textual_relevance_key(&row.kind, Some(kind), false)
    });
    let text = f
        .contains
        .filter(|_| !f.regex)
        .map_or((u8::MAX, usize::MAX), |contains| {
            textual_relevance_key(&row.text, Some(contains), false)
        });
    (kind, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_code_uses_canonical_kind_for_filtering_and_output() {
        let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
        workspace
            .vfs()
            .write("app.py", "# ordinary\n# x = value;\n# TODO review\n");

        let all = comments(&workspace, &CommentsFilters::default()).expect("comment inventory");
        assert_eq!(
            all.iter().map(|row| row.kind.as_str()).collect::<Vec<_>>(),
            ["todo", "disabled_code", "generic"],
            "canonical kinds also preserve attention-priority ordering: {all:?}"
        );

        for kind in ["disabled_code", "DISABLED_CODE", "disabled_"] {
            let rows = comments(
                &workspace,
                &CommentsFilters {
                    kind: Some(kind),
                    ..Default::default()
                },
            )
            .expect("comment kind filter");
            assert_eq!(rows.len(), 1, "{kind}: {rows:?}");
            assert_eq!(rows[0].kind, "disabled_code");
            assert_eq!(rows[0].line, 2);
            assert_eq!(rows[0].text, "# x = value;");
        }
    }
}
