//! `bonsai-ninja comments` data layer.

use crate::common::{file_path_matches_filter, format_span, make_name_filter, textual_relevance_key};
use crate::strings::enclosing_fn_for_index_line;
use bonsai_workspace::Workspace;
use serde::Serialize;

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
    /// Minimum character length of the comment's stripped body.
    pub min_len: Option<usize>,
    /// Treat `contains` as a regex.
    pub regex: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct CommentOut {
    pub text: String,
    pub kind: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
}

/// Collect every comment matching the filters.
pub fn comments(ws: &Workspace, f: &CommentsFilters<'_>) -> Result<Vec<CommentOut>, regex::Error> {
    use rayon::prelude::*;
    let contains_match = make_name_filter(f.contains, f.regex)?;
    let files = ws.vfs().all_files();
    let mut out: Vec<CommentOut> = files
        .par_iter()
        .flat_map_iter(|&file| {
            let mut per_file: Vec<CommentOut> = Vec::new();
            if let Some(needle) = f.file {
                let path = ws
                    .vfs()
                    .path(file)
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if !file_path_matches_filter(ws, &path, needle) {
                    return per_file.into_iter();
                }
            }
            let Some(idx) = ws.db().decl_index_uncached(file) else {
                return per_file.into_iter();
            };
            for comment in &idx.comments {
                let kind = format!("{:?}", comment.kind).to_lowercase();
                if f.kind.is_some_and(|k| !kind.contains(&k.to_lowercase())) {
                    continue;
                }
                if !contains_match(&comment.text) {
                    continue;
                }
                if let Some(min_chars) = f.min_len {
                    if comment.text.chars().count() < min_chars {
                        continue;
                    }
                }
                let (path, line, column) = format_span(&comment.span, ws);
                if let Some(needle) = f.in_fn {
                    let enclosing = enclosing_fn_for_index_line(ws, file, &idx, line).unwrap_or_default();
                    if !enclosing.contains(needle) {
                        continue;
                    }
                }
                per_file.push(CommentOut {
                    text: comment.text.clone(),
                    kind,
                    file: path,
                    line,
                    column,
                });
            }
            per_file.into_iter()
        })
        .collect();
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
