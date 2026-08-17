//! First-class source-to-target path query.
//!
//! This is a renderer/data layer over the canonical resolved callgraph:
//! it consumes FuncId-keyed semantic edges and never resolves by raw
//! text or invents missing call edges.

use crate::common::format_span;
use crate::edges::{edge_record_from_graph_nodes, EdgeRecord};
use crate::resolution::resolution_incomplete_reasons_for_funcs;
use bonsai_callgraph::{CallEdge, EdgeProvenance, ResolvedCallGraph};
use bonsai_common::{FuncId, Span};
use bonsai_idg::{CrossCallEdge, IdgQueryService};
use bonsai_inspect::{matching_func_ids_in_headers, Matcher};
use bonsai_lang_api::{DeclKind, FlowEvent};
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Filter bundle for [`paths`].
#[derive(Copy, Clone, Debug)]
pub struct PathFilters<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub regex: bool,
}

impl Default for PathFilters<'_> {
    fn default() -> Self {
        Self {
            from: "",
            to: "",
            regex: false,
        }
    }
}

/// Exact compressed source-to-target graph result.
#[derive(Serialize, Clone, Debug, Default)]
pub struct PathOutcome {
    pub from: String,
    pub to: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub backends: Vec<String>,
    pub idg_available: bool,
    pub idg_semantic_edges: usize,
    pub from_matches: usize,
    pub to_matches: usize,
    pub representation: &'static str,
    pub node_count: usize,
    pub edge_count: usize,
    pub analysis_complete: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub analysis_incomplete_reasons: Vec<String>,
    pub nodes: Vec<PathFunctionRow>,
    pub edges: Vec<EdgeRecord>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub terminal_calls: Vec<PathTerminalCallRow>,
}

/// Function node in the selected graph corridor.
#[derive(Serialize, Clone, Debug)]
pub struct PathFunctionRow {
    pub name: String,
    pub file: String,
    pub line: u32,
}

/// Syntax-backed call site that matched `--to` when no callable
/// declaration did. The semantic path ends at this call site's
/// enclosing function; this row is evidence for the terminal call
/// inside that function, not an invented edge to an external API.
#[derive(Serialize, Clone, Debug)]
pub struct PathTerminalCallRow {
    pub name: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub enclosing_function: String,
}

#[derive(Clone, Debug)]
struct TerminalCallTarget {
    func: FuncId,
    row: PathTerminalCallRow,
}

/// Project a source-to-target corridor over resolved semantic callgraph edges.
pub fn paths(ws: &Workspace, filters: &PathFilters<'_>) -> Result<PathOutcome, regex::Error> {
    // Retain one immutable graph generation for the complete query. Other
    // compiler phases may release the DB's resident service slot to reduce
    // peak memory, but that storage transition must not make endpoint lookup
    // and corridor projection observe different semantic backends.
    let warmed_idg = ws.db().idg_service();
    let from_matcher = Matcher::build(Some(filters.from), filters.regex)?;
    let to_matcher = Matcher::build(Some(filters.to), filters.regex)?;
    let fast_from = (!filters.regex)
        .then(|| matching_persisted_endpoint(ws, filters.from, &from_matcher))
        .flatten();
    let fast_to = (!filters.regex)
        .then(|| matching_persisted_endpoint(ws, filters.to, &to_matcher))
        .flatten();
    let complete_headers =
        (fast_from.is_none() || fast_to.is_none()).then(|| ws.complete_compiler_header_index());
    let from_funcs = fast_from.unwrap_or_else(|| {
        matching_func_ids_in_headers(
            ws,
            complete_headers
                .as_ref()
                .expect("complete headers loaded for fuzzy source endpoint")
                .as_ref(),
            &from_matcher,
        )
    });
    let to_funcs = fast_to.unwrap_or_else(|| {
        matching_func_ids_in_headers(
            ws,
            complete_headers
                .as_ref()
                .expect("complete headers loaded for fuzzy target endpoint")
                .as_ref(),
            &to_matcher,
        )
    });
    let terminal_targets = if to_funcs.is_empty() {
        matching_terminal_call_targets(ws, &to_matcher)
    } else {
        Vec::new()
    };
    let mut resolution_scope: ahash::AHashSet<FuncId> =
        from_funcs.iter().chain(to_funcs.iter()).copied().collect();
    let mut outcome = PathOutcome {
        from: filters.from.to_string(),
        to: filters.to.to_string(),
        from_matches: from_funcs.len(),
        to_matches: if to_funcs.is_empty() {
            terminal_targets.len()
        } else {
            to_funcs.len()
        },
        representation: "compressed_callgraph",
        ..PathOutcome::default()
    };
    if from_funcs.is_empty() {
        outcome
            .analysis_incomplete_reasons
            .push(format!("no callable source matched `{}`", filters.from));
    }
    if to_funcs.is_empty() {
        if terminal_targets.is_empty() {
            outcome.analysis_incomplete_reasons.push(format!(
                "no callable or call-site target matched `{}`",
                filters.to
            ));
        } else {
            outcome.analysis_incomplete_reasons.push(format!(
                "target `{}` matched call site(s), not callable declaration(s); paths end at enclosing callable and show terminal call evidence",
                filters.to
            ));
        }
    }
    if from_funcs.is_empty() || (to_funcs.is_empty() && terminal_targets.is_empty()) {
        resolution_scope.extend(terminal_targets.iter().map(|target| target.func));
        finalize_outcome(ws, &mut outcome, resolution_scope);
        return Ok(outcome);
    }

    let graph_targets = if to_funcs.is_empty() {
        terminal_targets
            .iter()
            .map(|target| target.func)
            .collect::<Vec<_>>()
    } else {
        to_funcs.clone()
    };
    let path_graph = semantic_path_graph(ws, &from_funcs, &graph_targets, warmed_idg.as_deref());
    outcome.backends.clone_from(&path_graph.backends);
    outcome.idg_available = path_graph.idg_available;
    outcome.idg_semantic_edges = path_graph.idg_semantic_edges;
    let mut hydration_reasons = Vec::new();
    outcome.nodes = path_graph
        .graph
        .nodes()
        .iter()
        .filter_map(|node| {
            resolution_scope.insert(node.func);
            let row = function_row(ws, &path_graph.graph, node.func);
            if row.is_none() {
                hydration_reasons.push(format!(
                    "corridor node F:{} was not present in the current compiler index",
                    node.func.raw()
                ));
            }
            row
        })
        .collect();
    outcome.nodes.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.name.cmp(&right.name))
    });
    outcome.edges = path_graph
        .graph
        .inner()
        .edges
        .iter()
        .filter(|edge| edge.precision.is_semantic())
        .filter_map(|edge| {
            let row = edge_record_from_graph_nodes(ws, &path_graph.graph, edge);
            if row.is_none() {
                hydration_reasons.push(format!(
                    "corridor edge F:{} -> F:{} could not be hydrated",
                    edge.from.raw(),
                    edge.to.raw()
                ));
            }
            row
        })
        .collect();
    outcome.edges.sort_by(|left, right| {
        left.caller_name
            .cmp(&right.caller_name)
            .then_with(|| left.callee_name.cmp(&right.callee_name))
            .then_with(|| left.call_file.cmp(&right.call_file))
            .then_with(|| left.call_line.cmp(&right.call_line))
    });
    outcome.terminal_calls = terminal_targets.into_iter().map(|target| target.row).collect();
    outcome.node_count = outcome.nodes.len();
    outcome.edge_count = outcome.edges.len();
    outcome.analysis_incomplete_reasons.extend(hydration_reasons);
    finalize_outcome(ws, &mut outcome, resolution_scope);
    Ok(outcome)
}

fn matching_persisted_endpoint(ws: &Workspace, query: &str, matcher: &Matcher) -> Option<Vec<FuncId>> {
    let leaf = query
        .rsplit(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
        .find(|part| !part.is_empty())?;
    let nodes = ws.persisted_callable_nodes_named(leaf)?.ok()?;
    let mut functions = nodes
        .into_iter()
        .filter(|node| {
            matcher.is_match(node.name.as_ref())
                || node
                    .qualified_name
                    .as_deref()
                    .is_some_and(|name| matcher.is_match(name))
        })
        .map(|node| node.func)
        .collect::<Vec<_>>();
    functions.sort_unstable_by_key(|func| func.raw());
    functions.dedup();
    (!functions.is_empty()).then_some(functions)
}

fn matching_terminal_call_targets(ws: &Workspace, matcher: &Matcher) -> Vec<TerminalCallTarget> {
    let mut targets = Vec::new();
    let mut files = ws.db().vfs().all_files();
    files.sort_unstable_by_key(|file| file.raw());
    for file in files {
        // This independently decodable compiler header contains every
        // adapter-emitted call target in the file. It is therefore an exact
        // rejection filter: only files that can contain the requested
        // terminal call need a declaration/flow body.
        let Some(syntax) = ws.db().compiler_syntax_header_uncached(file) else {
            continue;
        };
        if !syntax.calls.iter().any(|call| matcher.is_match(&call.name)) {
            continue;
        }
        let Some(index) = ws.exact_decl_index_shared(file) else {
            continue;
        };
        for decl in &index.defs {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            let format = |span: &Span| format_span(span, ws);
            collect_terminal_call_targets_for_events(
                FuncId::new(decl.symbol.raw()),
                &decl.name,
                &decl.flow_events,
                matcher,
                &format,
                &mut targets,
            );
        }
    }
    targets.sort_by(|a, b| {
        a.row
            .file
            .cmp(&b.row.file)
            .then_with(|| a.row.line.cmp(&b.row.line))
            .then_with(|| a.row.column.cmp(&b.row.column))
            .then_with(|| a.row.name.cmp(&b.row.name))
    });
    targets
}

fn collect_terminal_call_targets_for_events(
    func: FuncId,
    enclosing_function: &str,
    events: &[FlowEvent],
    matcher: &Matcher,
    format: &dyn Fn(&Span) -> (String, u32, u32),
    out: &mut Vec<TerminalCallTarget>,
) {
    for event in events {
        match event {
            FlowEvent::Call { name, span, .. } => {
                if matcher.is_match(name) {
                    let (file, line, column) = format(span);
                    out.push(TerminalCallTarget {
                        func,
                        row: PathTerminalCallRow {
                            name: name.clone(),
                            file,
                            line,
                            column,
                            enclosing_function: enclosing_function.to_string(),
                        },
                    });
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_terminal_call_targets_for_events(
                    func,
                    enclosing_function,
                    then_events,
                    matcher,
                    format,
                    out,
                );
                collect_terminal_call_targets_for_events(
                    func,
                    enclosing_function,
                    else_events,
                    matcher,
                    format,
                    out,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_terminal_call_targets_for_events(
                    func,
                    enclosing_function,
                    body,
                    matcher,
                    format,
                    out,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_terminal_call_targets_for_events(
                    func,
                    enclosing_function,
                    body,
                    matcher,
                    format,
                    out,
                );
                collect_terminal_call_targets_for_events(
                    func,
                    enclosing_function,
                    catch_events,
                    matcher,
                    format,
                    out,
                );
                collect_terminal_call_targets_for_events(
                    func,
                    enclosing_function,
                    finally_events,
                    matcher,
                    format,
                    out,
                );
            }
            FlowEvent::Assign { .. }
            | FlowEvent::AggregateAssign { .. }
            | FlowEvent::Return { .. }
            | FlowEvent::Throw { .. }
            | FlowEvent::Break { .. }
            | FlowEvent::Continue { .. }
            | FlowEvent::Yield { .. }
            | FlowEvent::Await { .. }
            | FlowEvent::Lifecycle { .. } => {}
        }
    }
}

struct SemanticPathGraph {
    graph: ResolvedCallGraph,
    backends: Vec<String>,
    idg_available: bool,
    idg_semantic_edges: usize,
}

fn semantic_path_graph(
    ws: &Workspace,
    starts: &[FuncId],
    targets: &[FuncId],
    warmed_idg: Option<&IdgQueryService>,
) -> SemanticPathGraph {
    if warmed_idg.is_none() {
        if let Some(Ok(graph)) = ws.persisted_resolved_call_graph_between(starts, targets) {
            return SemanticPathGraph {
                graph,
                backends: vec!["partitioned-resolved-callgraph-target-slice".to_string()],
                idg_available: false,
                idg_semantic_edges: 0,
            };
        }
    }
    let base = ws.cached_resolved_call_graph();
    let mut graph = base.inner().clone();
    let mut backends = vec!["resolved-callgraph".to_string()];
    let mut idg_available = false;
    let mut idg_semantic_edges = 0usize;
    if let Some(idg) = warmed_idg {
        idg_available = true;
        for edge in idg.semantic_cross_call_edges_with_max_precision(Some(bonsai_common::Precision::Narrowed))
        {
            if !idg_cross_call_is_structural_path_edge(edge) {
                continue;
            }
            graph.add_edge(call_edge_from_idg_cross_call(edge));
            idg_semantic_edges = idg_semantic_edges.saturating_add(1);
        }
        backends.push("warmed-idg-cross-call".to_string());
    }
    let graph = ResolvedCallGraph::from_persisted_parts(
        base.nodes().to_vec(),
        graph.edges,
        base.local_binding_records().to_vec(),
        base.unresolved_workspace_site_records().to_vec(),
    )
    .between(starts, targets, Some(bonsai_common::Precision::Narrowed));
    SemanticPathGraph {
        graph,
        backends,
        idg_available,
        idg_semantic_edges,
    }
}

fn idg_cross_call_is_structural_path_edge(edge: CrossCallEdge) -> bool {
    edge.relation.is_renderable_call()
        && edge.precision.is_semantic()
        && (edge.arg_idx != u32::MAX || edge.param_idx != u32::MAX)
}

fn call_edge_from_idg_cross_call(edge: CrossCallEdge) -> CallEdge {
    let evidence = if edge.arg_idx == u32::MAX {
        format!(
            "IDG callback/output edge into parameter {} at call site",
            edge.param_idx
        )
    } else if edge.param_idx == u32::MAX {
        format!("IDG call argument {} propagated through call site", edge.arg_idx)
    } else {
        format!(
            "IDG call argument {} propagated to parameter {}",
            edge.arg_idx, edge.param_idx
        )
    };
    CallEdge {
        from: edge.caller,
        to: edge.callee,
        span: edge.call_span,
        kind: edge.call_kind,
        precision: edge.precision,
        provenance: EdgeProvenance::new("idg_cross_call", evidence, 88),
    }
}

fn function_row(ws: &Workspace, graph: &ResolvedCallGraph, func: FuncId) -> Option<PathFunctionRow> {
    let index = graph
        .nodes()
        .binary_search_by_key(&func.raw(), |node| node.func.raw())
        .ok()?;
    let node = &graph.nodes()[index];
    let (file, line, _) = format_span(&node.name_span, ws);
    Some(PathFunctionRow {
        name: node.name.as_ref().to_string(),
        file,
        line,
    })
}

fn finalize_outcome(
    ws: &Workspace,
    outcome: &mut PathOutcome,
    resolution_scope: impl IntoIterator<Item = FuncId>,
) {
    outcome
        .analysis_incomplete_reasons
        .extend(resolution_incomplete_reasons_for_funcs(ws, resolution_scope));
    outcome.analysis_incomplete_reasons.sort();
    outcome.analysis_incomplete_reasons.dedup();
    outcome.analysis_complete = outcome.analysis_incomplete_reasons.is_empty();
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_callgraph::EdgeKind;
    use bonsai_common::{FileId, Precision, Span};

    fn cross_call(arg_idx: u32, param_idx: u32) -> CrossCallEdge {
        CrossCallEdge {
            caller: FuncId::new(1),
            callee: FuncId::new(2),
            call_span: Span::new(FileId::new(1), 10, 20),
            arg_idx,
            param_idx,
            precision: Precision::Narrowed,
            call_kind: EdgeKind::Direct,
            relation: bonsai_idg::CrossCallRelation::Argument,
        }
    }

    #[test]
    fn compressed_corridor_hydrates_complete_function_and_edge_facts() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            "def sink():\n    return 1\n\ndef entry():\n    return sink()\n",
        )
        .expect("write fixture");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

        let outcome = paths(
            &ws,
            &PathFilters {
                from: "entry",
                to: "sink",
                ..PathFilters::default()
            },
        )
        .expect("path query");
        assert_eq!(outcome.representation, "compressed_callgraph");
        assert!(outcome.nodes.iter().any(|func| func.name == "entry"));
        assert!(outcome.nodes.iter().any(|func| func.name == "sink"));
        assert_eq!(outcome.node_count, 2);
        assert_eq!(outcome.edge_count, 1);
        assert!(outcome.terminal_calls.is_empty());
    }

    #[test]
    fn twenty_layer_diamond_stays_linear_in_compiler_graph_size() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut source = String::from("def sink(x):\n    return x\n\n");
        for layer in (0..20).rev() {
            if layer == 19 {
                source.push_str(&format!("def join{layer}(x):\n    return sink(x)\n\n"));
            } else {
                source.push_str(&format!(
                    "def join{layer}(x):\n    return left{}(x) + right{}(x)\n\n",
                    layer + 1,
                    layer + 1
                ));
            }
            source.push_str(&format!(
                "def left{layer}(x):\n    return join{layer}(x)\n\ndef right{layer}(x):\n    return join{layer}(x)\n\n"
            ));
        }
        source.push_str("def root(x):\n    return left0(x) + right0(x)\n");
        std::fs::write(dir.path().join("diamond.py"), source).expect("write diamond fixture");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

        let outcome = paths(
            &ws,
            &PathFilters {
                from: "root",
                to: "sink",
                ..PathFilters::default()
            },
        )
        .expect("diamond corridor");

        // The route language contains 2^20 concrete combinations. The public
        // result must remain the exact O(V+E) compiler relation.
        assert_eq!(outcome.representation, "compressed_callgraph");
        assert_eq!(outcome.node_count, 62);
        assert_eq!(outcome.edge_count, 81);
        assert!(outcome.analysis_complete);
    }

    #[test]
    fn unrelated_workspace_resolution_gaps_do_not_pollute_a_scoped_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("path.py"),
            "def sink():\n    return 1\n\ndef entry():\n    return sink()\n",
        )
        .expect("write path fixture");
        std::fs::write(
            dir.path().join("unrelated.py"),
            "def unrelated(value):\n    return value.unknown_dynamic_method()\n",
        )
        .expect("write unrelated fixture");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

        let outcome = paths(
            &ws,
            &PathFilters {
                from: "entry",
                to: "sink",
                ..PathFilters::default()
            },
        )
        .expect("path query");

        assert!(
            outcome
                .analysis_incomplete_reasons
                .iter()
                .all(|reason| !reason.contains("unresolved call sites")),
            "unrelated.py must not affect entry -> sink completeness: {:?}",
            outcome.analysis_incomplete_reasons
        );
    }

    #[test]
    fn terminal_call_targets_collect_nested_syntax_call_facts() {
        let matcher = Matcher::build(Some("external_sink"), false).expect("matcher");
        let call_span = Span::new(FileId::new(7), 40, 44);
        let events = vec![FlowEvent::Branch {
            span: Span::new(FileId::new(7), 10, 12),
            condition: Some("ok".to_string()),
            then_events: vec![FlowEvent::Call {
                span: call_span,
                name: "external_sink".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: bonsai_lang_api::CallKind::Function,
                args: Vec::new(),
            }],
            else_events: vec![FlowEvent::Call {
                span: Span::new(FileId::new(7), 60, 64),
                name: "other_call".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: bonsai_lang_api::CallKind::Function,
                args: Vec::new(),
            }],
        }];
        let format = |span: &Span| {
            assert_eq!(*span, call_span);
            ("app.py".to_string(), 4, 5)
        };
        let mut out = Vec::new();

        collect_terminal_call_targets_for_events(
            FuncId::new(9),
            "run_admin_command",
            &events,
            &matcher,
            &format,
            &mut out,
        );

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].func, FuncId::new(9));
        assert_eq!(out[0].row.name, "external_sink");
        assert_eq!(out[0].row.file, "app.py");
        assert_eq!(out[0].row.line, 4);
        assert_eq!(out[0].row.column, 5);
        assert_eq!(out[0].row.enclosing_function, "run_admin_command");
    }

    #[test]
    fn terminal_call_query_uses_syntax_headers_without_losing_exact_flow() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("path.py"),
            "def helper(value):\n    return external_sink(value)\n\ndef entry(value):\n    return helper(value)\n",
        )
        .expect("write path fixture");
        std::fs::write(
            dir.path().join("unrelated.py"),
            "def unrelated(value):\n    return other_external(value)\n",
        )
        .expect("write unrelated fixture");
        let workspace =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

        let outcome = paths(
            &workspace,
            &PathFilters {
                from: "entry",
                to: "external_sink",
                ..PathFilters::default()
            },
        )
        .expect("terminal path query");
        assert_eq!(outcome.to_matches, 1);
        let names = outcome
            .nodes
            .iter()
            .map(|function| function.name.as_str())
            .collect::<ahash::AHashSet<_>>();
        assert_eq!(names, ahash::AHashSet::from_iter(["entry", "helper"]));
        assert_eq!(
            outcome.terminal_calls.first().map(|call| call.name.as_str()),
            Some("external_sink")
        );
    }

    #[test]
    fn idg_path_edges_keep_only_structural_call_shapes() {
        assert!(idg_cross_call_is_structural_path_edge(cross_call(0, 0)));
        assert!(idg_cross_call_is_structural_path_edge(cross_call(u32::MAX, 1)));
        assert!(!idg_cross_call_is_structural_path_edge(cross_call(
            u32::MAX,
            u32::MAX
        )));

        let mut over = cross_call(0, 0);
        over.precision = Precision::OverApproximate;
        assert!(!idg_cross_call_is_structural_path_edge(over));
    }
}
