//! Warm/cold IDG parity for `value_flow_for_function`.
//!
//! For each fixture, runs `value_flow_for_function` twice — once with
//! no workspace-default IDG and once after prewarming one. Prewarming is
//! a cache decision and must not select a different seed policy or graph
//! materializer.

mod common;

use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_common::{FuncId, Precision};
use bonsai_db::AnalyzerDb;
use bonsai_idg::{workspace_adapter, IdgQueryService};
use bonsai_lang_api::AdapterArc;
use bonsai_taint::{value_flow_for_function, InterTaintConfig, ValueFlowEdge, ValueFlowNodeKind};
use common::{build_db, func_id_or_none};
use std::sync::Arc;

/// Build the IDG service for `db` (using the same call-graph builder
/// the workspace open path uses) and seed it onto the db, mirroring
/// what `bonsai_workspace::Workspace::build_and_seed_idg_service`
/// does in production.
fn seed_idg_on(db: &AnalyzerDb) {
    let global = db.global_index();
    let cg = ResolvedCallGraph::build_with_file_info(
        global.as_ref(),
        |file| bonsai_resolve::semantic_import_binding_map_for_file(&db.imports_for(file)),
        |file| {
            bonsai_lang_api::alias_map_from_import_specs(&db.imports_for(file))
                .into_iter()
                .collect()
        },
        |file| {
            db.vfs()
                .path(file)
                .ok()
                .map(|path| path.to_string_lossy().into_owned())
        },
        |file| {
            db.adapter_for(file)
                .map(|adapter| adapter.capabilities().module_export_aliases)
                .unwrap_or(&[])
        },
        |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
    );
    let ws = workspace_adapter::build_with_file_info(
        global.as_ref(),
        &cg,
        |_| AHashMap::new(),
        |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
    );
    let svc = Arc::new(IdgQueryService::new(Arc::new(ws), global));
    db.set_idg_service(svc);
}

fn callee_param_pairs_from_graph(
    graph: &bonsai_taint::ValueFlowGraph,
    entry_func: FuncId,
    seeds: &[&str],
) -> AHashSet<(FuncId, String)> {
    let entry_seed_nodes: Vec<_> = graph
        .nodes
        .iter()
        .filter(|n| {
            n.func == entry_func
                && n.kind == ValueFlowNodeKind::Param
                && seeds.iter().any(|s| **s == n.value_text)
        })
        .cloned()
        .collect();
    let mut reached: AHashSet<(FuncId, String)> = AHashSet::default();
    for origin in &entry_seed_nodes {
        for r in graph.forward_closure(origin) {
            if r.kind == ValueFlowNodeKind::Param && r.func != entry_func {
                reached.insert((r.func, r.value_text.clone()));
            }
        }
    }
    reached
}

fn edges_from_graph(graph: &bonsai_taint::ValueFlowGraph) -> AHashSet<ValueFlowEdge> {
    graph
        .forward
        .values()
        .flat_map(|edges| edges.iter().cloned())
        .collect()
}

fn assert_warm_cold_parity(src: &str, entry: &str, seeds: &[&str]) {
    assert_warm_cold_parity_with_config(src, entry, seeds, &InterTaintConfig::default());
}

fn assert_warm_cold_parity_with_config(src: &str, entry: &str, seeds: &[&str], config: &InterTaintConfig) {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());

    // Cold run: the canonical IDG is provisioned on demand.
    let cold_db = build_db(adapter.clone(), &[("a.py", src)]);
    let entry_func = func_id_or_none(&cold_db, entry).unwrap_or_else(|| panic!("entry `{entry}` indexes"));
    let cold_graph = value_flow_for_function(entry_func, &cold_db, config);
    let cold_reached = callee_param_pairs_from_graph(&cold_graph, entry_func, seeds);

    // IDG run: fresh db, seed the IDG service before invoking.
    let warm_db = build_db(adapter, &[("a.py", src)]);
    let entry_warm =
        func_id_or_none(&warm_db, entry).unwrap_or_else(|| panic!("entry `{entry}` indexes (warm)"));
    seed_idg_on(&warm_db);
    let warm_graph = value_flow_for_function(entry_warm, &warm_db, config);
    let warm_reached = callee_param_pairs_from_graph(&warm_graph, entry_warm, seeds);

    assert_eq!(entry_func, entry_warm, "fixture FuncIds must be deterministic");
    assert_eq!(
        cold_reached, warm_reached,
        "prewarming changed reachable callee params"
    );
    assert_eq!(
        cold_graph.nodes, warm_graph.nodes,
        "prewarming changed value-flow nodes"
    );
    assert_eq!(
        edges_from_graph(&cold_graph),
        edges_from_graph(&warm_graph),
        "prewarming changed value-flow edges"
    );
    assert_eq!(cold_graph.precision, warm_graph.precision);
    assert_eq!(cold_graph.saturated, warm_graph.saturated);
}

#[test]
fn idg_parity_two_hop() {
    assert_warm_cold_parity(
        "def entry(args):\n    helper(args)\n\ndef helper(p):\n    sink(p)\n",
        "entry",
        &["args"],
    );
}

#[test]
fn idg_parity_three_hop_chain() {
    assert_warm_cold_parity(
        "def entry(args):\n    a = args\n    helper(a)\n\ndef helper(b):\n    deeper(b)\n\ndef deeper(c):\n    sink(c)\n",
        "entry",
        &["args"],
    );
}

#[test]
fn idg_parity_branch_merge() {
    assert_warm_cold_parity(
        "def entry(args):\n    if cond():\n        helper(args)\n    else:\n        helper(args)\n\ndef helper(p):\n    sink(p)\n",
        "entry",
        &["args"],
    );
}

#[test]
fn idg_parity_assigned_local_then_call() {
    assert_warm_cold_parity(
        "def entry(args):\n    local = args\n    helper(local)\n\ndef helper(p):\n    sink(p)\n",
        "entry",
        &["args"],
    );
}

// audit re-apply: H4

#[test]
fn idg_parity_call_nested_in_with_block() {
    // H4: a call nested in a `with` (FlowEvent::Using) body must still
    // reach the callee param independent of whether a workspace IDG was
    // prewarmed before the value-flow query.
    assert_warm_cold_parity(
        "def entry(args):\n    with open(\"f\") as fh:\n        helper(args)\n\ndef helper(p):\n    sink(p)\n",
        "entry",
        &["args"],
    );
}

#[test]
fn prewarmed_idg_preserves_paramless_local_assignment_seed() {
    let src = "def entry():\n    raw = source()\n    helper(raw)\n\ndef helper(p):\n    sink(p)\n";
    assert_warm_cold_parity(src, "entry", &[]);

    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let db = build_db(adapter, &[("a.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry indexes");
    seed_idg_on(&db);
    let graph = value_flow_for_function(entry, &db, &InterTaintConfig::default());
    let raw = graph
        .nodes
        .iter()
        .find(|node| {
            node.func == entry && node.kind == ValueFlowNodeKind::AssignTarget && node.value_text == "raw"
        })
        .expect("local assignment target is a canonical value-flow seed");
    assert!(
        graph.forward_closure(raw).iter().any(|node| node.func != entry
            && node.kind == ValueFlowNodeKind::Param
            && node.value_text == "p"),
        "prewarmed value-flow must propagate a local source-call assignment into the callee"
    );
}

#[test]
fn canonical_composer_keeps_local_seed_alongside_formal_param() {
    let src = "def entry(unrelated):\n    raw = source()\n    helper(raw)\n\ndef helper(p):\n    sink(p)\n";
    assert_warm_cold_parity(src, "entry", &["unrelated"]);

    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let db = build_db(adapter, &[("a.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry indexes");
    let graph = value_flow_for_function(entry, &db, &InterTaintConfig::default());
    let raw = graph
        .nodes
        .iter()
        .find(|node| {
            node.func == entry && node.kind == ValueFlowNodeKind::AssignTarget && node.value_text == "raw"
        })
        .expect("local assignment target is represented");
    assert!(
        graph.forward_closure(raw).iter().any(|node| node.func != entry
            && node.kind == ValueFlowNodeKind::Param
            && node.value_text == "p"),
        "resolving an unrelated formal param must not suppress the local's first-write seed"
    );
}

#[test]
fn prewarmed_idg_honors_configured_precision_ceiling() {
    let config = InterTaintConfig {
        max_edge_precision: Some(Precision::Exact),
        ..Default::default()
    };
    assert_warm_cold_parity_with_config(
        "def entry(args):\n    helper(args)\n\ndef helper(p):\n    sink(p)\n",
        "entry",
        &["args"],
        &config,
    );
}
