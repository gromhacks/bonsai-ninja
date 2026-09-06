//! `bonsai-ninja vars` data layer.
//!
//! Returns every assignment captured in any function's flow events,
//! filtered by name / file / enclosing-fn / source-identifier.

use crate::common::{
    admitted_file_decl_index, file_path_matches_filter, format_span, make_name_filter,
    source_files_small_first, textual_relevance_key,
};
use bonsai_lang_api::FlowEvent;
use bonsai_workspace::Workspace;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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
    /// `--source X` — substring over RHS identifiers and call names
    /// captured during flow extraction, including compound expressions.
    pub source: Option<&'a str>,
    /// Treat `name` as a regex instead of a substring.
    pub regex: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VarOut {
    pub name: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub in_function: String,
    pub writes: u32,
    /// Comma-separated display projection of `source_names`; retained for
    /// clients using the original single-field inventory contract.
    pub source_name: Option<String>,
    /// Sorted unique RHS identifiers and call names from every compiler
    /// projection of this exact write. These are syntax facts, not a claim
    /// that every operand reaches the assigned value through a callee.
    #[serde(default)]
    pub source_names: Vec<String>,
}

/// Collect every assignment matching the filters. Sorted by
/// relevance, then `(name, in_function, file, line, column)`.
pub fn vars(ws: &Workspace, f: &VarsFilters<'_>) -> Result<Vec<VarOut>, regex::Error> {
    use rayon::prelude::*;
    let name_match = make_name_filter(f.name, f.regex)?;
    let files = source_files_small_first(ws);
    let memory_permits = bonsai_common::SyntaxMemoryPermitPool::for_current_process();
    let mut out: Vec<VarOut> = files
        .par_iter()
        .fold(Vec::new, |mut acc, &file| {
            if let Some(needle) = f.file {
                let path = ws
                    .vfs()
                    .path(file)
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if !file_path_matches_filter(ws, &path, needle) {
                    return acc;
                }
            }
            let Some(index) = admitted_file_decl_index(ws, file, &memory_permits) else {
                return acc;
            };
            let assignment_targets = index
                .assignment_values
                .iter()
                .filter_map(|fact| Some(((fact.assignment_span, fact.target.as_deref()?), fact.target_span?)))
                .collect::<ahash::AHashMap<_, _>>();
            let mut assignments = ahash::AHashMap::new();
            for decl in &index.defs {
                if f.in_fn.is_some_and(|needle| !decl.name.contains(needle)) {
                    continue;
                }
                walk_assigns(
                    &decl.flow_events,
                    &decl.name,
                    &*name_match,
                    &assignment_targets,
                    &mut assignments,
                );
            }
            for ((span, target, in_function), sources) in assignments {
                if f.source
                    .is_some_and(|needle| !sources.iter().any(|source| source.contains(needle)))
                {
                    continue;
                }
                let (file, line, column) = format_span(&span, ws);
                let source_names: Vec<String> = sources.into_iter().map(str::to_owned).collect();
                acc.push(VarOut {
                    name: target.to_string(),
                    file,
                    line,
                    column,
                    in_function: in_function.to_string(),
                    writes: 1,
                    source_name: (!source_names.is_empty()).then(|| source_names.join(", ")),
                    source_names,
                });
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
    // Exact target spans unify wrapper projections before allocating rows;
    // same-line writes remain distinct. The source predicate selects a whole
    // write and cannot discard another RHS fact from that same assignment.
    out.sort_by(|a, b| {
        var_relevance_key(a, f)
            .cmp(&var_relevance_key(b, f))
            .then_with(|| {
                a.name
                    .cmp(&b.name)
                    .then_with(|| a.in_function.cmp(&b.in_function))
                    .then_with(|| a.file.cmp(&b.file))
                    .then_with(|| a.line.cmp(&b.line))
                    .then_with(|| a.column.cmp(&b.column))
            })
    });
    Ok(out)
}

fn var_relevance_key(row: &VarOut, f: &VarsFilters<'_>) -> ((u8, usize), (u8, usize), (u8, usize)) {
    let name = f.name.filter(|_| !f.regex).map_or((u8::MAX, usize::MAX), |name| {
        textual_relevance_key(&row.name, Some(name), false)
    });
    let source = f.source.map_or((u8::MAX, usize::MAX), |source| {
        row.source_names
            .iter()
            .map(|value| textual_relevance_key(value, Some(source), false))
            .min()
            .unwrap_or((u8::MAX, usize::MAX))
    });
    let in_fn = f.in_fn.map_or((u8::MAX, usize::MAX), |in_fn| {
        textual_relevance_key(&row.in_function, Some(in_fn), false)
    });
    (name, source, in_fn)
}

type AssignmentSources<'a> = ahash::AHashMap<(bonsai_common::Span, &'a str, &'a str), BTreeSet<&'a str>>;

/// Coalesce typed projections by the exact compiler target span. Borrow the
/// source facts until the complete write passes the user's source selector.
fn walk_assigns<'a>(
    events: &'a [FlowEvent],
    in_fn: &'a str,
    name_matches: &(dyn Fn(&str) -> bool + Send + Sync),
    assignment_targets: &ahash::AHashMap<(bonsai_common::Span, &str), bonsai_common::Span>,
    out: &mut AssignmentSources<'a>,
) {
    bonsai_lang_api::for_each_flow_event(events, &mut |event| {
        if let FlowEvent::Assign {
            span,
            target,
            source_name,
            source_call,
            source_names,
            ..
        } = event
        {
            if !name_matches(target) {
                return;
            }
            let target_span = assignment_targets.get(&(*span, target.as_str())).unwrap_or(span);
            let sources = out.entry((*target_span, target.as_str(), in_fn)).or_default();
            sources.extend(
                source_name
                    .iter()
                    .chain(source_call.iter())
                    .chain(source_names.iter())
                    .map(String::as_str),
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_assignment_projections_are_one_write_with_all_rhs_evidence() {
        let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
        workspace.vfs().write(
            "app.py",
            "def entry(request):\n    value: str = request.args.get('cmd', '')\n",
        );
        let all = vars(
            &workspace,
            &VarsFilters {
                name: Some("value"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(all.len(), 1, "one typed assignment is one write: {all:?}");
        assert_eq!(all[0].writes, 1);
        assert!(all[0]
            .source_names
            .iter()
            .any(|source| source == "request.args.cmd"));
        assert!(all[0]
            .source_names
            .iter()
            .any(|source| source == "request.args.get"));
        let filtered = vars(
            &workspace,
            &VarsFilters {
                name: Some("value"),
                source: Some("get"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(filtered.len(), 1, "RHS call remains searchable: {filtered:?}");
        assert_eq!(
            filtered[0].source_name, all[0].source_name,
            "a selector must not remove other facts from the same write"
        );
        assert_eq!(filtered[0].source_names, all[0].source_names);
    }

    #[test]
    fn separate_writes_on_one_line_remain_separate_rows() {
        let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
        workspace.vfs().write(
            "app.py",
            "def entry(first, second):\n    value = first; value = second\n",
        );
        let rows = vars(
            &workspace,
            &VarsFilters {
                name: Some("value"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(rows.len(), 2, "both writes are compiler facts: {rows:?}");
        assert!(rows
            .iter()
            .any(|row| row.column == 5 && row.source_name.as_deref() == Some("first")));
        assert!(rows
            .iter()
            .any(|row| row.column == 20 && row.source_name.as_deref() == Some("second")));
    }
}
