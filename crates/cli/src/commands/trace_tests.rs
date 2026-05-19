use super::load_trace_taint_graph;
use bonsai_sdk::Workspace;
use std::sync::Arc;

fn python_workspace(source: &str) -> Workspace {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write("fixture.py".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    ws
}

#[test]
fn trace_preload_populates_seed_taint_graph() {
    let ws = python_workspace(
        r"
def sink(payload):
os.system(payload)

def entry(user_input):
sink(user_input)
",
    );
    let before = ws.dataflow().pending_count(ws.db());
    assert!(before >= 2, "fixture should expose at least two callables");

    load_trace_taint_graph(&ws, Some("entry"));

    let after = ws.dataflow().pending_count(ws.db());
    assert_eq!(
        after + 1,
        before,
        "trace must load the indexed taint graph for the trace seed"
    );
}
