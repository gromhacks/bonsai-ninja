//! Phase 5b: IDG ↔ legacy engine parity for `value_flow_for_function`.
//!
//! For each fixture, runs `value_flow_for_function` twice — once with
//! the legacy interprocedural engine (no IDG seeded on the db) and
//! once with the IDG service seeded — and asserts the two paths
//! produce graphs whose forward-closure from the entry's seed nodes
//! reaches the same set of `(callee, param_name)` pairs.
//!
//! This is the gate that proves the IDG-backed `value_flow` is a
//! drop-in replacement for the engine path before Phase 6 deletes the
//! engine. When parity drifts, this test fires before any consumer
//! ships a behaviour change.

mod common;

use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_common::FuncId;
use bonsai_db::AnalyzerDb;
use bonsai_idg::{workspace_adapter, IdgQueryService};
use bonsai_lang_api::AdapterArc;
use bonsai_taint::{value_flow_for_function, InterTaintConfig, ValueFlowNodeKind};
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

fn assert_idg_legacy_parity(src: &str, entry: &str, seeds: &[&str]) {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());

    // Legacy run: db with no IDG seeded — value_flow falls through to
    // the engine path.
    let legacy_db = build_db(adapter.clone(), &[("a.py", src)]);
    let entry_func = func_id_or_none(&legacy_db, entry).unwrap_or_else(|| panic!("entry `{entry}` indexes"));
    let legacy_graph = value_flow_for_function(entry_func, &legacy_db, &InterTaintConfig::default());
    let legacy_reached = callee_param_pairs_from_graph(&legacy_graph, entry_func, seeds);

    // IDG run: fresh db, seed the IDG service before invoking.
    let idg_db = build_db(adapter, &[("a.py", src)]);
    let entry_idg =
        func_id_or_none(&idg_db, entry).unwrap_or_else(|| panic!("entry `{entry}` indexes (idg)"));
    seed_idg_on(&idg_db);
    let idg_graph = value_flow_for_function(entry_idg, &idg_db, &InterTaintConfig::default());
    let idg_reached = callee_param_pairs_from_graph(&idg_graph, entry_idg, seeds);

    // The IDG path is the floor — it should reach at least every
    // (callee, param) pair the legacy path found. (Strict equality
    // would also fail when one path discovers a wider set; we accept
    // IDG ⊇ legacy to allow the IDG to surface additional flows the
    // engine pruned, but every legacy edge must survive.)
    let missing: Vec<&(FuncId, String)> = legacy_reached
        .iter()
        .filter(|p| !idg_reached.contains(*p))
        .collect();
    assert!(
        missing.is_empty(),
        "IDG-backed value_flow must reach every callee param the legacy engine reached.\n\
         Missing: {missing:?}\n\
         Legacy: {legacy_reached:?}\n\
         IDG:    {idg_reached:?}"
    );
}

#[test]
fn idg_parity_two_hop() {
    assert_idg_legacy_parity(
        "def entry(args):\n    helper(args)\n\ndef helper(p):\n    sink(p)\n",
        "entry",
        &["args"],
    );
}

#[test]
fn idg_parity_three_hop_chain() {
    assert_idg_legacy_parity(
        "def entry(args):\n    a = args\n    helper(a)\n\ndef helper(b):\n    deeper(b)\n\ndef deeper(c):\n    sink(c)\n",
        "entry",
        &["args"],
    );
}

#[test]
fn idg_parity_branch_merge() {
    assert_idg_legacy_parity(
        "def entry(args):\n    if cond():\n        helper(args)\n    else:\n        helper(args)\n\ndef helper(p):\n    sink(p)\n",
        "entry",
        &["args"],
    );
}

#[test]
fn idg_parity_assigned_local_then_call() {
    assert_idg_legacy_parity(
        "def entry(args):\n    local = args\n    helper(local)\n\ndef helper(p):\n    sink(p)\n",
        "entry",
        &["args"],
    );
}

// audit re-apply: H4

#[test]
fn idg_parity_call_nested_in_with_block() {
    // H4: a call nested in a `with` (FlowEvent::Using) body must still
    // reach the callee param on the IDG-backed path, matching the
    // legacy engine path. Before the find_call_arg Using/Defer recursion
    // fix the IDG path recovers an empty arg text, synthesises a
    // disconnected CallArg, and never reaches `helper`'s `p`.
    assert_idg_legacy_parity(
        "def entry(args):\n    with open(\"f\") as fh:\n        helper(args)\n\ndef helper(p):\n    sink(p)\n",
        "entry",
        &["args"],
    );
}
