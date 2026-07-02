//! `bonsai-ninja vars` data layer.
//!
//! Returns every assignment captured in any function's flow events,
//! filtered by name / file / enclosing-fn / source-identifier.

use crate::common::{file_path_matches_filter, format_span, make_name_filter, textual_relevance_key};
use bonsai_lang_api::FlowEvent;
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Filter bundle for [`vars`]. Every field is optional; `None`
/// skips the corresponding filter.
#[derive(Copy, Clone, Default, Debug)]
pub struct VarsFilters<'a> {
    /// `--name X` — substring (or regex) over the assignment
    /// target.
    pub name: Option<&'a str>,
    /// `--file substring` against the assignment's source path.
    pub file: Option<&'a str>,
    /// `--in-fn X` — substring over the enclosing function's name.
    pub in_fn: Option<&'a str>,
    /// `--source X` — substring over the RHS identifier captured
    /// during flow extraction.
    pub source: Option<&'a str>,
    /// Treat `name` as a regex instead of a substring.
    pub regex: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct VarOut {
    pub name: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub in_function: String,
    pub writes: u32,
    /// Best-effort RHS identifier captured during flow extraction
    /// — lets callers see `cb = some_callback` without re-reading
    /// the file.
    pub source_name: Option<String>,
}

/// Collect every assignment matching the filters. Sorted by
/// `(name, in_function, file, line)` after the dedup pass.
pub fn vars(ws: &Workspace, f: &VarsFilters<'_>) -> Result<Vec<VarOut>, regex::Error> {
    use rayon::prelude::*;
    let global = ws.db().global_index();
    let name_match = make_name_filter(f.name, f.regex)?;
    let files: Vec<_> = global.all_files().collect();
    let mut out: Vec<VarOut> = files
        .par_iter()
        .fold(Vec::new, |mut acc, &file| {
            for decl in global.decls_in(file) {
                walk_assigns(&decl.flow_events, &decl.name, ws, &mut acc);
            }
            acc
        })
        .reduce(Vec::new, |mut larger, mut smaller| {
            if smaller.len() > larger.len() {
                std::mem::swap(&mut larger, &mut smaller);
            }
            larger.extend(smaller);
            larger
        });
    out.retain(|var| {
        if !name_match(&var.name) {
            return false;
        }
        if f.file
            .is_some_and(|needle| !file_path_matches_filter(ws, &var.file, needle))
        {
            return false;
        }
        if let Some(needle) = f.in_fn {
            if !var.in_function.contains(needle) {
                return false;
            }
        }
        if let Some(needle) = f.source {
            if !var.source_name.as_deref().is_some_and(|s| s.contains(needle)) {
                return false;
            }
        }
        true
    });
    // Dedup: several grammars (C# `local_declaration_statement →
    // variable_declaration → variable_declarator`, Go `short_var_
    // declaration`) emit the same assignment at multiple nested
    // node kinds because each kind sits in `assignment_kinds`. The
    // rows differ only in column (each parent span starts a few
    // columns earlier). Collapse to one row per `(name,
    // in_function, file, line)` — take the innermost (largest
    // column) since it's the tightest span around the identifier.
    out.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.in_function.cmp(&b.in_function))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| b.column.cmp(&a.column))
    });
    out.dedup_by(|a, b| {
        a.name == b.name && a.in_function == b.in_function && a.file == b.file && a.line == b.line
    });
    // Final display order matches the old grouping.
    out.sort_by(|a, b| {
        var_relevance_key(a, f)
            .cmp(&var_relevance_key(b, f))
            .then_with(|| {
                a.name
                    .cmp(&b.name)
                    .then_with(|| a.in_function.cmp(&b.in_function))
                    .then_with(|| a.file.cmp(&b.file))
                    .then_with(|| a.line.cmp(&b.line))
            })
    });
    Ok(out)
}

fn var_relevance_key(row: &VarOut, f: &VarsFilters<'_>) -> ((u8, usize), (u8, usize), (u8, usize)) {
    let name = f.name.filter(|_| !f.regex).map_or((u8::MAX, usize::MAX), |name| {
        textual_relevance_key(&row.name, Some(name), false)
    });
    let source = f.source.map_or((u8::MAX, usize::MAX), |source| {
        row.source_name.as_deref().map_or((u8::MAX, usize::MAX), |value| {
            textual_relevance_key(value, Some(source), false)
        })
    });
    let in_fn = f.in_fn.map_or((u8::MAX, usize::MAX), |in_fn| {
        textual_relevance_key(&row.in_function, Some(in_fn), false)
    });
    (name, source, in_fn)
}

/// Walk a decl's flow events and emit one [`VarOut`] per
/// `FlowEvent::Assign`. RHS preference: explicit `source_name` >
/// RHS-call name > comma-joined `source_names` (multi-source
/// assignments).
fn walk_assigns(events: &[FlowEvent], in_fn: &str, ws: &Workspace, out: &mut Vec<VarOut>) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_call,
                source_names,
                ..
            } => {
                let (path, line, column) = format_span(span, ws);
                let source = source_name.clone().or_else(|| {
                    source_call
                        .clone()
                        .or_else(|| (!source_names.is_empty()).then(|| source_names.join(",")))
                });
                out.push(VarOut {
                    name: target.clone(),
                    file: path,
                    line,
                    column,
                    in_function: in_fn.to_string(),
                    writes: 1,
                    source_name: source,
                });
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk_assigns(then_events, in_fn, ws, out);
                walk_assigns(else_events, in_fn, ws, out);
            }
            FlowEvent::Loop { body, .. } => walk_assigns(body, in_fn, ws, out),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                walk_assigns(body, in_fn, ws, out);
                walk_assigns(catch_events, in_fn, ws, out);
                walk_assigns(finally_events, in_fn, ws, out);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_assigns(body, in_fn, ws, out);
            }
            _ => {}
        }
    }
}
