//! `bonsai-ninja args` data layer.
//!
//! Returns every call-site argument captured in any function's
//! `flow_events`, with positional / keyword info and the call's
//! callee. Useful for security review ("which call sites pass an
//! `os.system` argument that came from `request.args`?") and for
//! refactor scoping.

use crate::common::{format_span, make_name_filter};
use crate::strings::enclosing_fn_for_file_line;
use bonsai_lang_api::FlowEvent;
use bonsai_workspace::Workspace;
use serde::Serialize;

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
}

/// Collect every call-site argument matching the filters.
/// Sorted by `(file, line, column, position)` for deterministic
/// output across runs and thread counts.
pub fn args(ws: &Workspace, f: &ArgsFilters<'_>) -> Result<Vec<ArgOut>, regex::Error> {
    use rayon::prelude::*;
    let global = ws.db().global_index();
    let callee_match = make_name_filter(f.callee, f.regex)?;
    let value_match = make_name_filter(f.value, f.regex)?;
    let files: Vec<_> = global.all_files().collect();
    // Per-thread accumulator (not per-file) so we don't pay the
    // per-file Vec allocation cost. See `calls::calls` for the same
    // shape and rationale.
    let mut facts: Vec<ArgFact> = files
        .par_iter()
        .fold(Vec::new, |mut acc, &file| {
            for decl in global.decls_in(file) {
                walk_args(&decl.flow_events, ws, &mut acc);
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
    facts.retain(|fact| {
        let arg = &fact.out;
        if !callee_match(&arg.callee) {
            return false;
        }
        if f.file.is_some_and(|needle| !arg.file.contains(needle)) {
            return false;
        }
        if let Some(needle) = f.in_fn {
            let enclosing = enclosing_fn_for_file_line(ws, &arg.file, arg.line).unwrap_or_default();
            if !enclosing.contains(needle) {
                return false;
            }
        }
        if f.value.is_some() && !value_match(&arg.value) {
            return false;
        }
        if let Some(want_position) = f.position {
            if arg.position != want_position {
                return false;
            }
        }
        if let Some(needle) = f.keyword {
            if !arg.keyword.as_deref().is_some_and(|k| k.contains(needle)) {
                return false;
            }
        }
        true
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
        a.out
            .callee
            .cmp(&b.out.callee)
            .then_with(|| a.out.position.cmp(&b.out.position))
            .then_with(|| a.out.file.cmp(&b.out.file))
            .then_with(|| a.out.line.cmp(&b.out.line))
            .then_with(|| a.out.column.cmp(&b.out.column))
    });
    Ok(facts.into_iter().map(|fact| fact.out).collect())
}

/// Walk a decl's flow-event tree and append one [`ArgFact`] per
/// call-site argument we observe. Recurses through every structural
/// variant (`Branch`, `Loop`, `Try`, `Defer`, `Using`).
fn walk_args(events: &[FlowEvent], ws: &Workspace, out: &mut Vec<ArgFact>) {
    for event in events {
        match event {
            FlowEvent::Call { name, args, .. } => {
                for (position, arg) in args.iter().enumerate() {
                    let (path, line, column) = format_span(&arg.span, ws);
                    out.push(ArgFact {
                        out: ArgOut {
                            callee: name.clone(),
                            position,
                            keyword: arg.name.clone(),
                            value: arg.value_text.clone(),
                            file: path,
                            line,
                            column,
                        },
                        origin: ArgOrigin::RealCall,
                    });
                }
            }
            FlowEvent::Assign {
                span,
                source_call: Some(name),
                source_call_args,
                ..
            } => {
                // RHS-of-assign call: `x = foo(a, b)` lets us recover
                // the args even when the adapter doesn't surface a
                // separate `Call` event for the call.
                let (path, line, column) = format_span(span, ws);
                for (position, value) in source_call_args.iter().enumerate() {
                    out.push(ArgFact {
                        out: ArgOut {
                            callee: name.clone(),
                            position,
                            keyword: None,
                            value: value.clone(),
                            file: path.clone(),
                            line,
                            column,
                        },
                        origin: ArgOrigin::AssignmentSourceCall,
                    });
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk_args(then_events, ws, out);
                walk_args(else_events, ws, out);
            }
            FlowEvent::Loop { body, .. } => walk_args(body, ws, out),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                walk_args(body, ws, out);
                walk_args(catch_events, ws, out);
                walk_args(finally_events, ws, out);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_args(body, ws, out);
            }
            _ => {}
        }
    }
}

/// Strip `AssignmentSourceCall` rows when an explicit `RealCall`
/// at the same `(file, line, position, value)` already covers the
/// arg. Without this we'd double-count every assignment whose RHS
/// is a call (`x = foo(a)` produces both a `Call foo(a)` and an
/// `Assign source_call=foo, source_call_args=[a]`).
fn drop_shadowed_assignment_args(args: &mut Vec<ArgFact>) {
    let real_args: Vec<ArgOut> = args
        .iter()
        .filter(|fact| fact.origin == ArgOrigin::RealCall)
        .map(|fact| fact.out.clone())
        .collect();
    args.retain(|fact| {
        if fact.origin != ArgOrigin::AssignmentSourceCall {
            return true;
        }
        !real_args.iter().any(|real| {
            real.file == fact.out.file
                && real.line == fact.out.line
                && real.position == fact.out.position
                && real.value == fact.out.value
                && arg_callees_shadow(&real.callee, &fact.out.callee)
        })
    });
}

/// True when two callee strings should be considered the same
/// physical call. Either equal verbatim, or sharing the trailing
/// segment after a member separator — `Runtime.exec` shadows
/// `exec`, `os::system` shadows `system`.
fn arg_callees_shadow(real: &str, assignment: &str) -> bool {
    real == assignment
        || real
            .rsplit(['.', ':', '\\'])
            .next()
            .is_some_and(|tail| assignment.rsplit(['.', ':', '\\']).next() == Some(tail))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_assignment_args_shadowed_by_real_call_args() {
        let mut facts = vec![
            fact("eval", 0, "py_expr", 10, ArgOrigin::RealCall),
            fact("eval", 1, "{\"attributes\": attributes}", 19, ArgOrigin::RealCall),
            fact("eval", 0, "py_expr", 5, ArgOrigin::AssignmentSourceCall),
            fact(
                "eval",
                1,
                "{\"attributes\": attributes}",
                5,
                ArgOrigin::AssignmentSourceCall,
            ),
            fact("other", 0, "py_expr", 5, ArgOrigin::AssignmentSourceCall),
        ];

        drop_shadowed_assignment_args(&mut facts);

        assert_eq!(facts.len(), 3);
        assert_eq!(
            facts
                .iter()
                .map(|fact| (fact.out.callee.as_str(), fact.out.position, fact.origin))
                .collect::<Vec<_>>(),
            vec![
                ("eval", 0, ArgOrigin::RealCall),
                ("eval", 1, ArgOrigin::RealCall),
                ("other", 0, ArgOrigin::AssignmentSourceCall),
            ]
        );
    }

    fn fact(callee: &str, position: usize, value: &str, column: u32, origin: ArgOrigin) -> ArgFact {
        ArgFact {
            out: ArgOut {
                callee: callee.to_string(),
                position,
                keyword: None,
                value: value.to_string(),
                file: "app.py".to_string(),
                line: 42,
                column,
            },
            origin,
        }
    }
}
