mod common;

use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_db::AnalyzerDb;
use bonsai_idg::{workspace_adapter, IdgQueryService};
use bonsai_lang_api::AdapterArc;
use bonsai_taint::inspect_entry_taint_graph_from_idg_with_target_funcs;
use common::{build_db, func_id_or_none};
use std::sync::Arc;

fn seed_idg_on(db: &AnalyzerDb) -> Arc<IdgQueryService> {
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
    db.set_idg_service(Arc::clone(&svc));
    svc
}

fn call_name_ends_with_symbol(name: &str, symbol: &str) -> bool {
    name == symbol || name.rsplit('.').next() == Some(symbol)
}

#[test]
fn inspect_target_graph_cuts_tainted_calls_to_selected_functions() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let db = build_db(
        adapter,
        &[(
            "app.py",
            r#"
def entry(req):
    sink(req)
    helper(req)

def helper(value):
    other(value)
"#,
        )],
    );
    let entry = func_id_or_none(&db, "entry").expect("entry indexed");
    let helper = func_id_or_none(&db, "helper").expect("helper indexed");
    let idg = seed_idg_on(&db);
    let target_funcs: AHashSet<_> = [helper].into_iter().collect();

    let graph =
        inspect_entry_taint_graph_from_idg_with_target_funcs(entry, Some(&target_funcs), &db, idg.as_ref());
    let tainted_names: Vec<_> = graph
        .tainted_calls
        .iter()
        .map(|call| call.name.as_str())
        .collect();

    assert!(
        tainted_names
            .iter()
            .any(|name| call_name_ends_with_symbol(name, "other")),
        "targeted inspect graph should keep tainted calls inside helper; got {tainted_names:?}"
    );
    assert!(
        !tainted_names
            .iter()
            .any(|name| call_name_ends_with_symbol(name, "sink")),
        "targeted inspect graph should exclude unrelated terminal calls in entry; got {tainted_names:?}"
    );
}
