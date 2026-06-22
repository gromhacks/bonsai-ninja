use ahash::AHashSet;
use bonsai_common::{FuncId, SymbolId};
use bonsai_lang_api::{AdapterArc, DeclKind, LanguageRegistry};
use bonsai_workspace::{
    flow_query::{SyntaxFlowBackend, SyntaxFlowQuery},
    Workspace,
};
use std::sync::Arc;

fn python_ws(source: &str) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    registry.register(adapter);
    let ws = Workspace::new(registry);
    ws.vfs().write("/w/app.py".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    ws
}

fn func_id(ws: &Workspace, name: &str) -> FuncId {
    let global = ws.db().global_index();
    global
        .find_by_name(name)
        .iter()
        .find_map(|sym| {
            global.decl_of(*sym).and_then(|decl| {
                matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                )
                .then_some(FuncId::new(sym.raw()))
            })
        })
        .unwrap_or_else(|| panic!("missing callable `{name}`"))
}

fn graph_mentions_call(ws: &Workspace, graph: &bonsai_taint::EntryTaintGraph, name: &str) -> bool {
    let global = ws.db().global_index();
    graph.tainted_calls.iter().any(|call| call.name.contains(name))
        || graph.call_records.iter().any(|edge| {
            global
                .decl_of(SymbolId::new(edge.callee.raw()))
                .is_some_and(|decl| decl.name.contains(name))
        })
}

#[test]
fn syntax_flow_query_uses_cached_dataflow_when_idg_is_cold() {
    let ws = python_ws(
        "def entry(req):\n    helper(req)\n\n\
         def helper(value):\n    sink(value)\n\n\
         def sink(arg):\n    return arg\n",
    );
    let entry = func_id(&ws, "entry");
    assert!(ws.db().idg_service().is_none(), "fixture starts with cold IDG");

    let result = ws.syntax_flow_graph(SyntaxFlowQuery::new(entry).prefer_warmed_idg(true));

    assert_eq!(result.backend, SyntaxFlowBackend::CachedDataflow);
    assert!(
        ws.db().idg_service().is_none(),
        "syntax_flow_graph must not build IDG on the inspect hot path"
    );
    assert!(
        graph_mentions_call(&ws, result.graph.as_ref(), "sink"),
        "cached dataflow backend must preserve the syntax-shaped sink flow"
    );
}

#[test]
fn syntax_flow_query_uses_warmed_idg_target_cut() {
    let ws = python_ws(
        "def entry(req):\n    helper(req)\n\n\
         def helper(value):\n    sink(value)\n\n\
         def sink(arg):\n    return arg\n",
    );
    let entry = func_id(&ws, "entry");
    let sink = func_id(&ws, "sink");
    let mut targets = AHashSet::new();
    targets.insert(sink);
    let _ = ws.build_and_seed_idg_service();
    assert!(ws.db().idg_service().is_some(), "IDG should be warmed");

    let result = ws.syntax_flow_graph(
        SyntaxFlowQuery::new(entry)
            .target_funcs(Some(&targets))
            .prefer_warmed_idg(true),
    );

    assert_eq!(result.backend, SyntaxFlowBackend::WarmedIdgTargetCut);
    assert!(
        graph_mentions_call(&ws, result.graph.as_ref(), "sink"),
        "warmed IDG backend must preserve the target-cut sink flow"
    );
}
