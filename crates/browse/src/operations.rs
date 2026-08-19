//! `bonsai-ninja operations` data layer.
//!
//! Operations expose language-neutral use-site facts derived from the
//! shared `FlowEvent` contract: reads, writes, calls, returns, throws,
//! awaits, lifecycle transitions, resource scopes, and normalized place
//! shapes. The extraction lives in `bonsai_lang_api` so every consumer
//! sees the same facts.

use crate::common::{
    admitted_file_decl_index, best_textual_relevance_key, file_path_matches_filter, format_span,
    make_name_filter, source_files_small_first, textual_relevance_key,
};
use bonsai_lang_api::operations_from_flow_events;
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Filter bundle for [`operations`].
#[derive(Copy, Clone, Default, Debug)]
pub struct OperationsFilters<'a> {
    /// `--kind X` — operation-kind substring or regex.
    pub kind: Option<&'a str>,
    /// `--name X` — match operation target or operand name.
    pub name: Option<&'a str>,
    /// `--file substring` against the operation's source path.
    pub file: Option<&'a str>,
    /// `--in-fn X` — only keep operations inside functions whose
    /// name contains `X`.
    pub in_fn: Option<&'a str>,
    /// Treat `kind` and `name` as regexes instead of substrings.
    pub regex: bool,
}

/// One operand inside an [`OperationOut`] row.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct OperationOperandOut {
    pub role: String,
    pub name: String,
}

/// One operation fact row.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct OperationOut {
    pub kind: String,
    pub name: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub in_function: String,
    pub detail: Option<String>,
    pub operands: Vec<OperationOperandOut>,
}

/// Collect operation facts from every declaration's flow-event tree.
pub fn operations(ws: &Workspace, f: &OperationsFilters<'_>) -> Result<Vec<OperationOut>, regex::Error> {
    use rayon::prelude::*;

    let kind_match = make_name_filter(f.kind, f.regex)?;
    let name_match = make_name_filter(f.name, f.regex)?;
    let files = source_files_small_first(ws);
    let memory_permits = bonsai_common::SyntaxMemoryPermitPool::for_current_process();
    let mut out: Vec<OperationOut> = files
        .par_iter()
        .fold(Vec::new, |mut acc, &file| {
            let absolute_file_path = ws
                .vfs()
                .path(file)
                .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
            if f.file
                .is_some_and(|needle| !file_path_matches_filter(ws, &absolute_file_path, needle))
            {
                return acc;
            }
            // Browse rows use workspace-relative compiler paths. Besides
            // keeping JSON portable, this is the identity consumed by the
            // flow annotator's canonical FileId lookup. Feeding it the VFS's
            // absolute path made every operations-row flow label empty.
            let file_path = crate::common::workspace_relative_path(ws, &absolute_file_path);
            let Some(index) = admitted_file_decl_index(ws, file, &memory_permits) else {
                return acc;
            };
            for decl in &index.defs {
                if f.in_fn.is_some_and(|needle| !decl.name.contains(needle)) {
                    continue;
                }
                for op in operations_from_flow_events(&decl.flow_events) {
                    let kind = op.kind.as_str().to_string();
                    if !kind_match(&kind) {
                        continue;
                    }
                    let (_path, line, column) = format_span(&op.span, ws);
                    let operands: Vec<OperationOperandOut> = op
                        .operands
                        .into_iter()
                        .map(|operand| OperationOperandOut {
                            role: operand.role.as_str().to_string(),
                            name: operand.name,
                        })
                        .collect();
                    let name = op
                        .target
                        .clone()
                        .or_else(|| operands.first().map(|operand| operand.name.clone()))
                        .unwrap_or_else(|| op.kind.as_str().to_string());
                    if f.name.is_some()
                        && !name_match(&name)
                        && !operands.iter().any(|operand| name_match(&operand.name))
                    {
                        continue;
                    }
                    acc.push(OperationOut {
                        kind,
                        name,
                        file: file_path.clone(),
                        line,
                        column,
                        in_function: decl.name.clone(),
                        detail: op.detail,
                        operands,
                    });
                }
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
    drop_assignment_source_call_rows_shadowed_by_explicit_calls(&mut out);
    let kind_rank = |op: &OperationOut| {
        if f.kind.is_some() && !f.regex {
            textual_relevance_key(&op.kind, f.kind, false)
        } else {
            (u8::MAX, usize::MAX)
        }
    };
    let name_rank = |op: &OperationOut| {
        if f.name.is_some() && !f.regex {
            best_textual_relevance_key(
                std::iter::once(op.name.as_str())
                    .chain(op.operands.iter().map(|operand| operand.name.as_str())),
                f.name,
                false,
            )
        } else {
            (u8::MAX, usize::MAX)
        }
    };
    out.sort_by(|a, b| {
        kind_rank(a)
            .cmp(&kind_rank(b))
            .then_with(|| name_rank(a).cmp(&name_rank(b)))
            .then_with(|| {
                a.kind
                    .cmp(&b.kind)
                    .then_with(|| a.name.cmp(&b.name))
                    .then_with(|| a.in_function.cmp(&b.in_function))
                    .then_with(|| a.file.cmp(&b.file))
                    .then_with(|| a.line.cmp(&b.line))
                    .then_with(|| a.column.cmp(&b.column))
                    .then_with(|| a.detail.cmp(&b.detail))
            })
    });
    out.dedup();
    Ok(out)
}

fn drop_assignment_source_call_rows_shadowed_by_explicit_calls(out: &mut Vec<OperationOut>) {
    use std::collections::HashSet;
    let explicit_calls: HashSet<(String, String, u32, String)> = out
        .iter()
        .filter(|op| op.kind == "call" && op.detail.as_deref() != Some("assignment_source"))
        .map(|op| (op.name.clone(), op.file.clone(), op.line, op.in_function.clone()))
        .collect();
    out.retain(|op| {
        if op.kind != "call" || op.detail.as_deref() != Some("assignment_source") {
            return true;
        }
        !explicit_calls.contains(&(op.name.clone(), op.file.clone(), op.line, op.in_function.clone()))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_and_function_filters_scope_operation_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("keep.py"),
            "def target_fn():\n    action = source()\n    sink(action)\n",
        )
        .expect("write keep");
        std::fs::write(
            dir.path().join("skip.py"),
            "def skipped_fn():\n    other = source()\n    sink(other)\n",
        )
        .expect("write skip");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

        let rows = operations(
            &ws,
            &OperationsFilters {
                file: Some("keep.py"),
                in_fn: Some("target_fn"),
                ..OperationsFilters::default()
            },
        )
        .expect("operations");

        assert!(
            rows.iter().any(|row| row.name == "action" && row.kind == "write"),
            "scoped operations should include matching file/function facts: {rows:?}"
        );
        assert!(
            rows.iter()
                .all(|row| row.file.ends_with("keep.py") && row.in_function == "target_fn"),
            "file and function filters must exclude unrelated operation rows: {rows:?}"
        );
    }

    #[test]
    fn generator_yield_values_surface_as_read_operations() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("gen.py"),
            "def gen(payload):\n    yield payload[0]\n",
        )
        .expect("write generator fixture");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

        let rows = operations(
            &ws,
            &OperationsFilters {
                name: Some("payload"),
                ..OperationsFilters::default()
            },
        )
        .expect("operations");

        assert!(
            rows.iter()
                .any(|row| row.kind == "yield" && row.name == "payload[0]"),
            "yield operation should expose the yielded place: {rows:?}"
        );
        assert!(
            rows.iter().any(|row| row.kind == "read"
                && row.name == "payload[0]"
                && row.detail.as_deref() == Some("yield_value")),
            "yielded places should also surface as read operations: {rows:?}"
        );
        assert!(
            rows.iter()
                .any(|row| row.kind == "index" && row.name == "payload[0]"),
            "yielded indexed places should keep normalized index shape facts: {rows:?}"
        );
    }

    #[test]
    fn assignment_source_call_operations_do_not_shadow_explicit_call_operations() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            "def handler():\n    value = source()\n    return value\n",
        )
        .expect("write fixture");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

        let rows = operations(
            &ws,
            &OperationsFilters {
                kind: Some("call"),
                name: Some("source"),
                ..OperationsFilters::default()
            },
        )
        .expect("operations");

        let source_calls: Vec<&OperationOut> = rows
            .iter()
            .filter(|row| row.kind == "call" && row.name == "source")
            .collect();
        assert_eq!(
            source_calls.len(),
            1,
            "operations should keep the explicit call row and drop the assignment-source shadow: {rows:?}"
        );
        assert_ne!(
            source_calls[0].detail.as_deref(),
            Some("assignment_source"),
            "the kept call row should be the richer explicit call operation: {rows:?}"
        );
    }
}
