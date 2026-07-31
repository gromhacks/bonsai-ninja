//! `bonsai-ninja dump-ast` data layer.
//!
//! Tree-sitter parse tree dump per file (or per function with
//! `--function`). The first place to look when `dump-hir` /
//! `inspect` silently miss a construct.

use crate::common::file_path_matches_filter;
use bonsai_hash::fnv1a_names_low32;
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Filter bundle for [`dump_ast`].
#[derive(Copy, Clone, Default, Debug)]
pub struct AstFilters<'a> {
    pub file: Option<&'a str>,
    /// Scope to one function's subtree. Matches by exact decl-name
    /// equality (not substring).
    pub function: Option<&'a str>,
    /// Cap tree depth. `None` = unlimited.
    pub max_depth: Option<usize>,
    /// Drill into one node by its `N:`-prefixed id (returned in
    /// `node_id` on every node). When the id doesn't match any
    /// node in the filtered set, [`dump_ast`] returns
    /// [`AstOutcome::NodeIdNotFound`].
    pub node_id: Option<&'a str>,
}

#[derive(Serialize, Clone, Debug)]
pub struct AstNode {
    pub node_id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub children: Vec<AstNode>,
}

#[derive(Serialize, Clone, Debug)]
pub struct AstFileDump {
    pub path: String,
    pub root: AstNode,
}

#[derive(Serialize, Clone, Debug)]
pub struct AstFunctionCandidate {
    pub path: String,
    pub node_id: String,
    pub kind: String,
    pub line: u32,
    pub column: u32,
}

/// Outcome of a [`dump_ast`] call. The `NodeIdNotFound` variant
/// lets the CLI surface a precise error when `--node N:xx` doesn't
/// match anything; library consumers can pattern-match the same way.
#[derive(Debug)]
pub enum AstOutcome {
    Dumps(Vec<AstFileDump>),
    NodeIdNotFound,
    FunctionAmbiguous {
        function: String,
        candidates: Vec<AstFunctionCandidate>,
    },
}

/// Stable content-hash id for a tree-sitter node: `N:` + 8 hex
/// chars. Hash input is `(file_path, start_byte..end_byte, kind)`
/// — survives parse-cache rebuilds as long as source content +
/// grammar don't change.
#[must_use]
pub fn compute_node_id(file_path: &str, start_byte: usize, end_byte: usize, kind: &str) -> String {
    let byte_range_token = format!("{start_byte}..{end_byte}");
    let tokens = [file_path.to_string(), byte_range_token, kind.to_string()];
    format!("N:{:08x}", fnv1a_names_low32(&tokens))
}

/// Walk the workspace's parse trees and emit one [`AstFileDump`]
/// per file (or one per matching `--function` scope), filtering
/// to the optional `--node` drill-down.
pub fn dump_ast(ws: &Workspace, f: &AstFilters<'_>) -> AstOutcome {
    use rayon::prelude::*;
    enum FileResult {
        Dump(AstFileDump),
        Ambiguous(Vec<AstFunctionCandidate>),
    }

    let depth_cap = f.max_depth.unwrap_or(usize::MAX);
    let all_files = ws.vfs().all_files();
    // Parallel per-file tree walk. `tree_sitter::Node` isn't Send,
    // but every node we touch is created, walked, and converted to
    // an owned `AstNode` entirely within a single worker's stack —
    // nothing crosses thread boundaries. Each worker gets its own
    // `Arc<ParsedFile>` clone from `db.parse(file_id)`.
    let file_results: Vec<FileResult> = all_files
        .par_iter()
        .filter_map(|&file_id| {
            let display_path = ws
                .vfs()
                .path(file_id)
                .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
            if let Some(needle) = f.file {
                if !file_path_matches_filter(ws, &display_path, needle) {
                    return None;
                }
            }
            let parsed = ws.db().parse(file_id).ok()?;
            let snapshot = ws.vfs().snapshot(file_id).ok()?;
            let source = snapshot.text.as_ref();
            let tree_root = parsed.tree.root_node();

            // `--function` narrows to the smallest tree-sitter node
            // covering that decl's span.
            let scoped_node = if let Some(func_name) = f.function {
                let index = ws.db().decl_index_uncached(file_id)?;
                let matching_decls = index
                    .defs
                    .iter()
                    .filter(|decl| {
                        decl.name == func_name
                            && matches!(
                                decl.kind,
                                bonsai_lang_api::DeclKind::Function
                                    | bonsai_lang_api::DeclKind::Method
                                    | bonsai_lang_api::DeclKind::Constructor
                            )
                    })
                    .collect::<Vec<_>>();
                if matching_decls.len() > 1 {
                    let mut candidates = matching_decls
                        .into_iter()
                        .filter_map(|decl| {
                            let node = find_node_covering_span(tree_root, decl.span.start, decl.span.end)?;
                            let start = node.start_position();
                            Some(AstFunctionCandidate {
                                path: display_path.clone(),
                                node_id: compute_node_id(
                                    &display_path,
                                    node.start_byte(),
                                    node.end_byte(),
                                    node.kind(),
                                ),
                                kind: node.kind().to_string(),
                                line: u32::try_from(start.row).unwrap_or(u32::MAX).saturating_add(1),
                                column: u32::try_from(start.column).unwrap_or(u32::MAX).saturating_add(1),
                            })
                        })
                        .collect::<Vec<_>>();
                    candidates.sort_by(|left, right| {
                        left.path
                            .cmp(&right.path)
                            .then_with(|| left.line.cmp(&right.line))
                            .then_with(|| left.column.cmp(&right.column))
                            .then_with(|| left.node_id.cmp(&right.node_id))
                    });
                    candidates.dedup_by(|left, right| left.node_id == right.node_id);
                    return Some(FileResult::Ambiguous(candidates));
                }
                let matching_decl = matching_decls.into_iter().next()?;
                find_node_covering_span(tree_root, matching_decl.span.start, matching_decl.span.end)?
            } else {
                tree_root
            };

            let root_ast = build_ast_node(scoped_node, source, &display_path, None, 0, depth_cap);
            Some(FileResult::Dump(AstFileDump {
                path: display_path,
                root: root_ast,
            }))
        })
        .collect();
    let mut file_dumps = Vec::new();
    let mut ambiguities = Vec::new();
    for result in file_results {
        match result {
            FileResult::Dump(dump) => file_dumps.push(dump),
            FileResult::Ambiguous(candidates) => ambiguities.extend(candidates),
        }
    }
    if !ambiguities.is_empty() {
        ambiguities.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.line.cmp(&right.line))
                .then_with(|| left.column.cmp(&right.column))
                .then_with(|| left.node_id.cmp(&right.node_id))
        });
        ambiguities.dedup_by(|left, right| left.node_id == right.node_id);
        return AstOutcome::FunctionAmbiguous {
            function: f.function.unwrap_or_default().to_string(),
            candidates: ambiguities,
        };
    }
    // Deterministic file order (path-sorted) regardless of worker
    // completion order.
    file_dumps.sort_by(|a, b| a.path.cmp(&b.path));

    // `--node N:xx` drill: return only the matching subtree, or
    // signal NotFound so the CLI can give a precise error.
    if let Some(target_id) = f.node_id {
        let drilled = file_dumps.iter().find_map(|file_dump| {
            find_node_in_ast(&file_dump.root, target_id).map(|found| AstFileDump {
                path: file_dump.path.clone(),
                root: found.clone(),
            })
        });
        match drilled {
            Some(found) => return AstOutcome::Dumps(vec![found]),
            None => return AstOutcome::NodeIdNotFound,
        }
    }

    AstOutcome::Dumps(file_dumps)
}

/// Recursively build an [`AstNode`] from a tree-sitter node,
/// filtering out anonymous tokens. `depth_cap` is a safety knob
/// for deeply-nested expression-statement grammars (Ruby / Scala /
/// Kotlin); when hit, the node still lands in the tree but its
/// children are elided.
fn build_ast_node(
    ts_node: ::tree_sitter::Node<'_>,
    source: &str,
    file_path: &str,
    field_name: Option<&str>,
    depth: usize,
    depth_cap: usize,
) -> AstNode {
    let start_point = ts_node.start_position();
    let end_point = ts_node.end_position();
    let node_text = {
        let raw = ts_node.utf8_text(source.as_bytes()).unwrap_or("");
        let one_line = raw.replace('\n', "\\n");
        crate::common::truncate_at_char_boundary(&one_line, 120, "…")
    };
    let mut children: Vec<AstNode> = Vec::new();
    if depth < depth_cap {
        let mut cursor = ts_node.walk();
        for (child_idx, child) in ts_node.children(&mut cursor).enumerate() {
            if !child.is_named() {
                continue;
            }
            let child_field_name = ts_node.field_name_for_child(child_idx as u32);
            children.push(build_ast_node(
                child,
                source,
                file_path,
                child_field_name,
                depth + 1,
                depth_cap,
            ));
        }
    }
    AstNode {
        node_id: compute_node_id(
            file_path,
            ts_node.start_byte(),
            ts_node.end_byte(),
            ts_node.kind(),
        ),
        kind: ts_node.kind().to_string(),
        field: field_name.map(str::to_string),
        start_line: (start_point.row as u32) + 1,
        start_column: (start_point.column as u32) + 1,
        end_line: (end_point.row as u32) + 1,
        end_column: (end_point.column as u32) + 1,
        text: Some(node_text),
        children,
    }
}

/// Walk down from `current` to the smallest named tree-sitter node
/// that fully covers `[start_byte, end_byte)`. Used to scope
/// `--function` drilldowns so we render just the subtree the user
/// asked about, not the whole file.
fn find_node_covering_span(
    mut current: ::tree_sitter::Node<'_>,
    start_byte: u64,
    end_byte: u64,
) -> Option<::tree_sitter::Node<'_>> {
    let start_byte = usize::try_from(start_byte).unwrap_or(usize::MAX);
    let end_byte = usize::try_from(end_byte).unwrap_or(usize::MAX);
    loop {
        let mut deeper = None;
        let mut cursor = current.walk();
        for child in current.children(&mut cursor) {
            if child.start_byte() <= start_byte && child.end_byte() >= end_byte {
                deeper = Some(child);
                break;
            }
        }
        match deeper {
            // Only recurse into named children — anonymous tokens
            // never produce more useful subtrees.
            Some(child) if child.is_named() => current = child,
            Some(_) => break,
            None => break,
        }
    }
    Some(current)
}

/// Recursive search for an [`AstNode`] by its `N:`-prefixed id.
/// Linear in tree size; the AST output the CLI returns is small
/// enough (one file, capped depth) that a smarter index isn't worth
/// the extra state.
fn find_node_in_ast<'a>(root: &'a AstNode, target_id: &str) -> Option<&'a AstNode> {
    if root.node_id == target_id {
        return Some(root);
    }
    for child in &root.children {
        if let Some(hit) = find_node_in_ast(child, target_id) {
            return Some(hit);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_function_names_report_selectable_ast_nodes() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(
            dir.path().join("app.py"),
            "def render(value):\n    return value\n\ndef render(value, suffix):\n    return value + suffix\n",
        )
        .expect("write fixture");
        let workspace =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

        let candidates = match dump_ast(
            &workspace,
            &AstFilters {
                file: Some("app.py"),
                function: Some("render"),
                max_depth: Some(1),
                node_id: None,
            },
        ) {
            AstOutcome::FunctionAmbiguous { function, candidates } => {
                assert_eq!(function, "render");
                candidates
            }
            other => panic!("expected explicit overload ambiguity, got {other:?}"),
        };
        assert_eq!(candidates.len(), 2);
        assert_ne!(candidates[0].node_id, candidates[1].node_id);
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.line)
                .collect::<Vec<_>>(),
            vec![1, 4]
        );

        let selected = dump_ast(
            &workspace,
            &AstFilters {
                file: Some("app.py"),
                function: None,
                max_depth: None,
                node_id: Some(&candidates[1].node_id),
            },
        );
        match selected {
            AstOutcome::Dumps(dumps) => {
                assert_eq!(dumps.len(), 1);
                assert_eq!(dumps[0].root.node_id, candidates[1].node_id);
                assert_eq!(dumps[0].root.start_line, 4);
            }
            other => panic!("expected selected AST node, got {other:?}"),
        }
    }
}
