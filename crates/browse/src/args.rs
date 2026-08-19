//! `bonsai-ninja args` data layer.
//!
//! Returns every syntactic call-site argument captured in any
//! function's `flow_events`, with positional / keyword info and the
//! call's callee text. This is not a resolved semantic caller→callee
//! edge surface. Useful for security review ("which call sites pass
//! an `os.system` argument that came from `request.args`?") and for
//! refactor scoping.

use crate::common::{
    decl_or_ancestor_name_matches, filtered_file_decl_index, format_span, make_callable_name_filter,
    make_name_filter, source_files_small_first, textual_relevance_key,
};
use bonsai_common::Span;
use bonsai_lang_api::FlowEvent;
use bonsai_workspace::Workspace;
use serde::Serialize;

pub(crate) const ARG_RESOLUTION_SCOPE: &str = "syntactic-call-site-argument";

/// Filter bundle for [`args`]. Every field is optional; `None`
/// skips that filter. `regex` controls how `callee` and `value`
/// are interpreted.
#[derive(Copy, Clone, Default, Debug)]
pub struct ArgsFilters<'a> {
    /// `--callee X` — only keep args whose call site invokes a
    /// callee whose name contains (or matches the regex) `X`.
    pub callee: Option<&'a str>,
    /// `--file substring` against the call-site source path.
    pub file: Option<&'a str>,
    /// `--in-fn X` — only keep args whose enclosing function's
    /// name contains `X`.
    pub in_fn: Option<&'a str>,
    /// `--value X` — only keep args whose textual value contains
    /// (or matches the regex) `X`.
    pub value: Option<&'a str>,
    /// `--position N` — only keep args at positional index `N`.
    pub position: Option<usize>,
    /// `--keyword X` — only keep keyword args whose keyword name
    /// contains `X`.
    pub keyword: Option<&'a str>,
    /// Treat `callee` / `value` as regexes instead of substrings.
    pub regex: bool,
}

/// One row of `args` output. Every field maps directly to a
/// column in the CLI's table render and a key in its JSON output.
#[derive(Serialize, Clone, Debug)]
pub struct ArgOut {
    /// Explicitly declares that this row is call-site argument
    /// inventory, not a resolved semantic caller→callee edge.
    pub resolution_scope: &'static str,
    /// Callee name as it appears at the call site (qualified form
    /// like `os.system` or `cursor.execute`).
    pub callee: String,
    /// Zero-based positional index of the argument within the call.
    pub position: usize,
    /// Keyword name when the arg is a keyword arg
    /// (`session=request.session`); `None` for positional args.
    pub keyword: Option<String>,
    /// The argument's textual value as it appeared in source —
    /// either a literal (`"hello"`, `42`) or an identifier
    /// expression (`request.GET['name']`, `payload`).
    pub value: String,
    /// Source path of the call site.
    pub file: String,
    pub line: u32,
    pub column: u32,
}

/// Where an arg row came from. `RealCall` rows describe an actual
/// `FlowEvent::Call`; `AssignmentSourceCall` rows describe args
/// captured on an `Assign` whose RHS is a call. We track the
/// origin so the dedup pass can drop the assignment shadow when
/// an explicit call carries the same arg.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ArgOrigin {
    RealCall,
    AssignmentSourceCall,
}

#[derive(Clone, Debug)]
struct ArgFact {
    out: ArgOut,
    origin: ArgOrigin,
    /// Exact compiler span that produced this presentation row. Real call
    /// rows carry the argument expression; assignment fallbacks carry the
    /// containing assignment. Keeping the structural relation avoids
    /// line-based dedup bugs for multiline calls.
    source_span: Span,
}

/// Collect every call-site argument matching the filters.
/// Sorted by `(file, line, column, position)` for deterministic
/// output across runs and thread counts.
pub fn args(ws: &Workspace, f: &ArgsFilters<'_>) -> Result<Vec<ArgOut>, regex::Error> {
    use rayon::prelude::*;
    let callee_match = make_callable_name_filter(f.callee, f.regex)?;
    let value_match = make_name_filter(f.value, f.regex)?;
    let files = source_files_small_first(ws);
    let memory_permits = bonsai_common::SyntaxMemoryPermitPool::for_current_process();
    // Per-thread accumulator (not per-file) so we don't pay the
    // per-file Vec allocation cost. See `calls::calls` for the same
    // shape and rationale.
    let mut facts: Vec<ArgFact> = files
        .par_iter()
        .fold(Vec::new, |mut acc, &file| {
            // Argument inventory consumes file-local AST facts only. Avoid a
            // global symbol remap and stream the immutable compiler object.
            let Some(index) = filtered_file_decl_index(ws, file, f.file, &memory_permits) else {
                return acc;
            };
            let defs_by_symbol = index
                .defs
                .iter()
                .map(|decl| (decl.symbol, decl))
                .collect::<ahash::AHashMap<_, _>>();
            for decl in &index.defs {
                if f.in_fn.is_some_and(|needle| {
                    !decl_or_ancestor_name_matches(decl, &defs_by_symbol, &|name| name.contains(needle))
                }) {
                    continue;
                }
                walk_args(&decl.flow_events, ws, &*callee_match, &*value_match, f, &mut acc);
            }
            acc
        })
        .reduce(Vec::new, |mut larger, mut smaller| {
            // Cheaper to extend the bigger vec with the smaller one.
            if smaller.len() > larger.len() {
                std::mem::swap(&mut larger, &mut smaller);
            }
            larger.extend(smaller);
            larger
        });
    drop_shadowed_assignment_args(&mut facts);
    // Dedup: several adapters emit the same call expression
    // through multiple nested `call`-kind nodes (C and C++
    // `assignment_expression` wrapping a call, Scala / Elixir
    // macros), so the same `(callee, position, span)` tuple
    // surfaces twice. Collapse identical args at the same
    // location.
    facts.sort_by(|a, b| {
        a.out
            .file
            .cmp(&b.out.file)
            .then_with(|| a.out.line.cmp(&b.out.line))
            .then_with(|| a.out.column.cmp(&b.out.column))
            .then_with(|| a.out.position.cmp(&b.out.position))
            .then_with(|| a.out.callee.cmp(&b.out.callee))
            .then_with(|| a.out.value.cmp(&b.out.value))
    });
    facts.dedup_by(|a, b| {
        a.out.callee == b.out.callee
            && a.out.file == b.out.file
            && a.out.line == b.out.line
            && a.out.column == b.out.column
            && a.out.position == b.out.position
            && a.out.value == b.out.value
    });
    // Final display order: group by callee, then by position,
    // then by location.
    facts.sort_by(|a, b| {
        arg_relevance_key(&a.out, f)
            .cmp(&arg_relevance_key(&b.out, f))
            .then_with(|| {
                a.out
                    .callee
                    .cmp(&b.out.callee)
                    .then_with(|| a.out.position.cmp(&b.out.position))
                    .then_with(|| a.out.file.cmp(&b.out.file))
                    .then_with(|| a.out.line.cmp(&b.out.line))
                    .then_with(|| a.out.column.cmp(&b.out.column))
            })
    });
    Ok(facts.into_iter().map(|fact| fact.out).collect())
}

fn arg_relevance_key(row: &ArgOut, f: &ArgsFilters<'_>) -> ((u8, usize), (u8, usize), (u8, usize)) {
    let callee = f
        .callee
        .filter(|_| !f.regex)
        .map_or((u8::MAX, usize::MAX), |callee| {
            textual_relevance_key(&row.callee, Some(callee), false)
        });
    let value = f
        .value
        .filter(|_| !f.regex)
        .map_or((u8::MAX, usize::MAX), |value| {
            textual_relevance_key(&row.value, Some(value), false)
        });
    let keyword = f.keyword.map_or((u8::MAX, usize::MAX), |keyword| {
        row.keyword.as_deref().map_or((u8::MAX, usize::MAX), |value| {
            textual_relevance_key(value, Some(keyword), false)
        })
    });
    (callee, value, keyword)
}

/// Walk a decl's flow-event tree and append one [`ArgFact`] per
/// call-site argument we observe. Recurses through every structural
/// variant (`Branch`, `Loop`, `Try`, `Defer`, `Using`).
fn walk_args(
    events: &[FlowEvent],
    ws: &Workspace,
    callee_matches: &(dyn Fn(&str) -> bool + Send + Sync),
    value_matches: &(dyn Fn(&str) -> bool + Send + Sync),
    filters: &ArgsFilters<'_>,
    out: &mut Vec<ArgFact>,
) {
    for event in events {
        match event {
            FlowEvent::Call { name, args, .. } => {
                if !callee_matches(name) {
                    continue;
                }
                for (position, arg) in args.iter().enumerate() {
                    if filters.position.is_some_and(|wanted| wanted != position)
                        || filters.keyword.is_some_and(|needle| {
                            !arg.name.as_deref().is_some_and(|name| name.contains(needle))
                        })
                        || (filters.value.is_some() && !value_matches(&arg.value_text))
                    {
                        continue;
                    }
                    let (path, line, column) = format_span(&arg.span, ws);
                    out.push(ArgFact {
                        out: ArgOut {
                            resolution_scope: ARG_RESOLUTION_SCOPE,
                            callee: name.clone(),
                            position,
                            keyword: arg.name.clone(),
                            value: arg.value_text.clone(),
                            file: path,
                            line,
                            column,
                        },
                        origin: ArgOrigin::RealCall,
                        source_span: arg.span,
                    });
                }
            }
            FlowEvent::Assign {
                span,
                source_call: Some(name),
                source_call_args,
                ..
            } => {
                if !callee_matches(name) || filters.keyword.is_some() {
                    continue;
                }
                // RHS-of-assign call: `x = foo(a, b)` lets us recover
                // the args even when the adapter doesn't surface a
                // separate `Call` event for the call.
                let (path, line, column) = format_span(span, ws);
                for (position, value) in source_call_args.iter().enumerate() {
                    if filters.position.is_some_and(|wanted| wanted != position)
                        || (filters.value.is_some() && !value_matches(value))
                    {
                        continue;
                    }
                    out.push(ArgFact {
                        out: ArgOut {
                            resolution_scope: ARG_RESOLUTION_SCOPE,
                            callee: name.clone(),
                            position,
                            keyword: None,
                            value: value.clone(),
                            file: path.clone(),
                            line,
                            column,
                        },
                        origin: ArgOrigin::AssignmentSourceCall,
                        source_span: *span,
                    });
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk_args(then_events, ws, callee_matches, value_matches, filters, out);
                walk_args(else_events, ws, callee_matches, value_matches, filters, out);
            }
            FlowEvent::Loop { body, .. } => {
                walk_args(body, ws, callee_matches, value_matches, filters, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                walk_args(body, ws, callee_matches, value_matches, filters, out);
                walk_args(catch_events, ws, callee_matches, value_matches, filters, out);
                walk_args(finally_events, ws, callee_matches, value_matches, filters, out);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_args(body, ws, callee_matches, value_matches, filters, out);
            }
            _ => {}
        }
    }
}

/// Strip `AssignmentSourceCall` rows when an explicit `RealCall`
/// structurally inside the assignment already covers the arg. Without this
/// we'd double-count every assignment whose RHS is a call (`x = foo(a)`
/// produces both a `Call foo(a)` and an `Assign
/// source_call=foo, source_call_args=[a]`). Span containment is required:
/// line equality fails as soon as the argument list wraps onto later lines.
fn drop_shadowed_assignment_args(args: &mut Vec<ArgFact>) {
    let real_args: Vec<ArgFact> = args
        .iter()
        .filter(|fact| fact.origin == ArgOrigin::RealCall)
        .cloned()
        .collect();
    args.retain(|fact| {
        if fact.origin != ArgOrigin::AssignmentSourceCall {
            return true;
        }
        !real_args.iter().any(|real| {
            real.source_span.file == fact.source_span.file
                && real.source_span.start >= fact.source_span.start
                && real.source_span.end <= fact.source_span.end
                && real.out.position == fact.out.position
                && real.out.value == fact.out.value
                && arg_callees_shadow(&real.out.callee, &fact.out.callee)
        })
    });
}

/// True when two callee strings should be considered the same
/// physical call. Either equal verbatim, or sharing the trailing
/// segment after a member separator — `Runtime.exec` shadows
/// `exec`, `os::system` shadows `system`.
fn arg_callees_shadow(real: &str, assignment: &str) -> bool {
    bonsai_common::qualified_names_match(real, assignment)
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod tests;
