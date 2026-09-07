//! `bonsai-ninja vars` data layer.
//!
//! Returns every assignment captured in any function's flow events,
//! filtered by name / file / enclosing-fn / source-identifier.

use crate::common::{
    admitted_file_decl_index, file_path_matches_filter, format_span, make_name_filter,
    source_files_small_first, textual_relevance_key,
};
use bonsai_lang_api::{AssignmentValueFact, FlowEvent};
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
            let mut assignments = ahash::AHashMap::new();
            for decl in &index.defs {
                if f.in_fn.is_some_and(|needle| !decl.name.contains(needle)) {
                    continue;
                }
                walk_assigns(
                    &decl.flow_events,
                    &decl.name,
                    &*name_match,
                    &index.assignment_values,
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

/// Assignment spans are not unique keys: retain every exact target projection
/// in the equal-span range. An unnamed pattern fact supplies shared RHS syntax
/// only when there is no target-specific fact; it never supplies a binding's
/// location or an inferred tuple/field-to-binding relationship.
fn assignment_values_for_target<'a>(
    facts: &'a [AssignmentValueFact],
    span: bonsai_common::Span,
    target: &'a str,
) -> impl Iterator<Item = &'a AssignmentValueFact> + Clone {
    let start = facts.partition_point(|fact| fact.assignment_span < span);
    let remaining = &facts[start..];
    let end = remaining.partition_point(|fact| fact.assignment_span == span);
    let candidates = &remaining[..end];
    let has_target = candidates
        .iter()
        .any(|fact| fact.target.as_deref() == Some(target));
    candidates
        .iter()
        .filter(move |fact| fact.target.as_deref() == Some(target) || (!has_target && fact.target.is_none()))
}

/// Coalesce typed projections by the exact compiler target span. Borrow the
/// source facts until the complete write passes the user's source selector.
fn walk_assigns<'a>(
    events: &'a [FlowEvent],
    in_fn: &'a str,
    name_matches: &(dyn Fn(&str) -> bool + Send + Sync),
    assignment_values: &'a [AssignmentValueFact],
    out: &mut AssignmentSources<'a>,
) {
    // Calls nested in a compound RHS are separate events, not necessarily
    // Assign::source_call projections. Index this callable's typed events
    // once so each write visits only calls within its exact RHS byte range.
    let mut calls = Vec::new();
    bonsai_lang_api::for_each_flow_event(events, &mut |event| {
        if let FlowEvent::Call { span, name, .. } = event {
            calls.push((*span, name.as_str()));
        }
    });
    calls.sort_unstable_by_key(|(span, _)| *span);
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
            let values = assignment_values_for_target(assignment_values, *span, target);
            let target_span = values
                .clone()
                .filter(|fact| fact.target.as_deref() == Some(target.as_str()))
                .filter_map(|fact| fact.target_span)
                .last()
                .unwrap_or(*span);
            let sources = out.entry((target_span, target.as_str(), in_fn)).or_default();
            sources.extend(
                source_name
                    .iter()
                    .chain(source_call.iter())
                    .chain(source_names.iter())
                    .map(String::as_str),
            );
            for value in values {
                // Only the compiler-selected RHS owns these call names.
                // Assignment-wide or line-based overlap would also admit
                // target/index calls and neighboring statements. This is
                // syntax inventory, not an argument-to-return flow claim.
                let rhs = value.value_span;
                let start =
                    calls.partition_point(|(span, _)| (span.file, span.start) < (rhs.file, rhs.start));
                for (call_span, name) in calls.iter().skip(start) {
                    if call_span.file != rhs.file || call_span.start >= rhs.end {
                        break;
                    }
                    if call_span.end <= rhs.end {
                        sources.insert(*name);
                    }
                }
            }
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

    fn assert_compound_rhs_call_sources(path: &str, source: &str) {
        let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
        workspace.vfs().write(path, source);
        let all = vars(&workspace, &VarsFilters::default()).unwrap();
        let output: Vec<_> = all.iter().filter(|row| row.name == "output").collect();
        assert_eq!(output.len(), 2, "same-line writes stay separate: {all:?}");
        assert_eq!(output[0].line, output[1].line);
        assert_ne!(output[0].column, output[1].column);

        let filtered = vars(
            &workspace,
            &VarsFilters {
                source: Some("source"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(filtered.len(), 2, "compound and nested RHS calls: {filtered:?}");
        for name in ["output", "nested"] {
            let row = filtered.iter().find(|row| row.name == name).unwrap();
            assert_eq!(row.writes, 1);
            for expected in ["source", "value", "auxiliary"] {
                assert!(row.source_names.iter().any(|name| name == expected), "{row:?}");
            }
            assert_eq!(
                row.source_names.iter().filter(|name| *name == "source").count(),
                1
            );
            let unfiltered = all
                .iter()
                .find(|other| other.name == row.name && other.line == row.line && other.column == row.column)
                .unwrap();
            assert_eq!(row.source_names, unfiltered.source_names);
            assert_eq!(row.source_name, unfiltered.source_name);
        }
        let nested = filtered.iter().find(|row| row.name == "nested").unwrap();
        assert!(nested.source_names.iter().any(|name| name == "wrap"));
        let alternate = vars(
            &workspace,
            &VarsFilters {
                source: Some("alternate"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            alternate.len(),
            1,
            "neighboring RHS stays on its own write: {alternate:?}"
        );
        assert_eq!(alternate[0].name, "output");
        assert!(!alternate[0].source_names.iter().any(|name| name == "source"));
        for neighbor in ["before", "after"] {
            let rows = vars(
                &workspace,
                &VarsFilters {
                    source: Some(neighbor),
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(
                rows.is_empty(),
                "neighboring statement is not RHS evidence: {rows:?}"
            );
        }
    }

    #[test]
    fn compound_and_nested_rhs_calls_are_searchable_in_python() {
        assert_compound_rhs_call_sources(
            "app.py",
            concat!(
                "def entry(value, auxiliary):\n",
                "    before(value); output = source(value) + auxiliary; after(value); output = alternate(value) + auxiliary\n",
                "    nested = wrap(source(value)) + source(auxiliary)\n",
                "    alias = output\n",
                "    plain = 'source(value)'\n",
            ),
        );
    }

    #[test]
    fn compound_and_nested_rhs_calls_are_searchable_in_javascript() {
        assert_compound_rhs_call_sources(
            "app.js",
            "function entry(value, auxiliary) {\n\
                 before(value); let output = source(value) + auxiliary; after(value); output = alternate(value) + auxiliary;\n\
                 const nested = wrap(source(value)) + source(auxiliary);\n\
                 const alias = output;\n\
                 const plain = 'source(value)';\n\
             }\n",
        );
    }

    fn assert_rhs_excludes_assignment_target(path: &str, source: &str) {
        let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
        workspace.vfs().write(path, source);
        let rows = vars(
            &workspace,
            &VarsFilters {
                source: Some("source"),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!rows.is_empty(), "nested RHS call must remain searchable");
        for row in &rows {
            assert!(row.source_names.iter().any(|name| name == "wrap"), "{row:?}");
            assert!(row.source_names.iter().any(|name| name == "auxiliary"), "{row:?}");
        }
        for excluded in ["target_call", "items", "index", "before", "after"] {
            let rows = vars(
                &workspace,
                &VarsFilters {
                    source: Some(excluded),
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(rows.is_empty(), "{excluded} is outside the exact RHS: {rows:?}");
        }
    }

    #[test]
    fn rhs_call_sources_exclude_assignment_target_calls_and_reads_in_python() {
        assert_rhs_excludes_assignment_target(
            "app.py",
            "def entry(value, auxiliary, items, index):\n    before(value); items[target_call(index)] = wrap(source(value)) + auxiliary; after(value)\n    items[index] = value\n",
        );
    }

    #[test]
    fn rhs_call_sources_exclude_assignment_target_calls_and_reads_in_javascript() {
        assert_rhs_excludes_assignment_target(
            "app.js",
            "function entry(value, auxiliary, items, index) {\n\
                 before(value); items[target_call(index)] = wrap(source(value)) + auxiliary; after(value);\n\
                 items[index] = value;\n\
             }\n",
        );
    }

    #[test]
    fn shared_assignment_span_keeps_target_specific_rhs_and_locations() {
        use bonsai_common::{FileId, Span};
        use bonsai_lang_api::{CallKind, ExpressionFlow};

        let span = |start, end| Span::new(FileId::new(0), start, end);
        let assignment = span(10, 80);
        let fact = |assignment_span, target: Option<&str>, target_span, value_span| AssignmentValueFact {
            assignment_span,
            target: target.map(str::to_owned),
            target_is_immutable: false,
            target_owner: None,
            target_span,
            value_span,
            call_sites: Vec::new(),
            value_flow: ExpressionFlow::default(),
            static_value: None,
            exact_callable_return: None,
            inline_callback_static_return: None,
            inline_callback_fields: Vec::new(),
            exact_static_call_args: None,
            direct_call_name: None,
            direct_call_span: None,
            direct_call_receiver: None,
            direct_call_receiver_span: None,
            direct_call_receiver_flow: None,
        };
        let assign = |target: &str| FlowEvent::Assign {
            span: assignment,
            target: target.to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: None,
        };
        let call = |span, name: &str| FlowEvent::Call {
            span,
            name: name.to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: Vec::new(),
        };
        let events = vec![
            assign("a"),
            assign("b"),
            assign("c"),
            call(span(40, 45), "other"),
            call(span(20, 26), "source"),
        ];
        for include_pattern in [false, true] {
            let mut facts = vec![
                fact(span(0, 8), Some("a"), Some(span(0, 1)), span(4, 8)),
                fact(assignment, Some("a"), Some(span(10, 11)), span(20, 30)),
                fact(assignment, Some("b"), Some(span(13, 14)), span(40, 50)),
                fact(span(90, 120), Some("b"), Some(span(90, 91)), span(100, 120)),
            ];
            if include_pattern {
                // An earlier broad pattern projection must not shadow the
                // target-specific locations or admit another target's RHS.
                facts.insert(1, fact(assignment, None, Some(span(10, 17)), span(20, 50)));
            }
            let mut rows = AssignmentSources::default();
            walk_assigns(&events, "entry", &|_| true, &facts, &mut rows);
            assert_eq!(rows.len(), 3, "{rows:?}");
            assert_eq!(rows[&(span(10, 11), "a", "entry")], BTreeSet::from(["source"]));
            assert_eq!(rows[&(span(13, 14), "b", "entry")], BTreeSet::from(["other"]));
            assert_eq!(
                rows[&(assignment, "c", "entry")],
                if include_pattern {
                    BTreeSet::from(["source", "other"])
                } else {
                    BTreeSet::new()
                },
                "only an unnamed pattern supplies shared RHS syntax"
            );
        }
    }

    fn assert_destructured_rhs_call_sources(path: &str, source: &str) {
        let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
        workspace.vfs().write(path, source);
        let filters = VarsFilters {
            name: Some("^(a|b)$"),
            regex: true,
            ..Default::default()
        };
        let all = vars(&workspace, &filters).unwrap();
        assert_eq!(all.len(), 4, "two patterns each write two bindings: {all:?}");
        for target in ["a", "b"] {
            let rows: Vec<_> = all.iter().filter(|row| row.name == target).collect();
            assert_eq!(rows.len(), 2, "{target} has two distinct writes: {rows:?}");
            assert_eq!(rows[0].line, rows[1].line);
            assert_ne!(rows[0].column, rows[1].column);
        }
        // These frontends retain a shared pattern RHS. Its call inventory is
        // searchable for each binding without asserting a positional flow.
        for source in ["source", "other", "replacement", "alternate"] {
            let rows = vars(
                &workspace,
                &VarsFilters {
                    source: Some(source),
                    ..filters
                },
            )
            .unwrap();
            assert_eq!(rows.len(), 2, "{source} belongs to one pattern: {rows:?}");
            for target in ["a", "b"] {
                let row = rows.iter().find(|row| row.name == target).unwrap();
                assert_eq!(row.writes, 1);
                assert!(row.source_names.iter().any(|name| name == source), "{row:?}");
                let original = all
                    .iter()
                    .find(|other| {
                        other.name == row.name && other.line == row.line && other.column == row.column
                    })
                    .unwrap();
                assert_eq!(row.source_names, original.source_names);
                assert_eq!(row.source_name, original.source_name);
            }
        }
        let neighbors = vars(
            &workspace,
            &VarsFilters {
                source: Some("neighbor"),
                ..filters
            },
        )
        .unwrap();
        assert!(
            neighbors.is_empty(),
            "neighboring call is not a pattern RHS: {neighbors:?}"
        );
    }

    #[test]
    fn python_multi_assignment_keeps_shared_rhs_and_distinct_writes() {
        assert_destructured_rhs_call_sources(
            "app.py",
            "def entry(x, y):\n    a, b = source(x), other(y); neighbor(x); a, b = replacement(x), alternate(y)\n",
        );
    }

    #[test]
    fn javascript_destructuring_keeps_shared_rhs_and_distinct_writes() {
        assert_destructured_rhs_call_sources(
            "app.js",
            "function entry(x, y) {\n    const [a, b] = [source(x), other(y)]; neighbor(x); [a, b] = [replacement(x), alternate(y)];\n}\n",
        );
    }
}
