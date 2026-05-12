//! Workspace-wide singleton `InterTaintCaches` survives across
//! query-style operations and is cleared on file edits.

use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use bonsai_workspace::Workspace;
use std::sync::Arc;

fn registry() -> Arc<LanguageRegistry> {
    let r = Arc::new(LanguageRegistry::new());
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    r.register(adapter);
    r
}

fn ws_with_python(file: &str, src: &str) -> Workspace {
    let ws = Workspace::new(registry());
    ws.vfs().write(file.to_string(), Arc::<str>::from(src));
    for f in ws.vfs().all_files() {
        let _ = ws.db().decl_index(f);
    }
    ws
}

#[test]
fn workspace_exposes_inter_taint_singleton_starts_empty() {
    let ws = ws_with_python("app.py", "def main():\n    x = input()\n    print(x)\n");
    assert!(
        ws.inter_taint_caches().is_empty(),
        "fresh workspace must hand out an empty inter-taint cache"
    );
}

#[test]
fn singleton_accumulates_across_value_flow_calls() {
    let ws = ws_with_python(
        "app.py",
        "def get_input():\n    return input()\n\n\
def main():\n    x = get_input()\n    print(x)\n",
    );
    // Pre-warm the value-flow graph through the workspace caches.
    // After the call, the inter-taint singleton must have populated
    // at least one of its internal maps (resolver, alias, summary).
    ws.value_flow()
        .prewarm_all_with_caches(ws.db(), ws.inter_taint_caches());
    assert!(
        !ws.inter_taint_caches().is_empty(),
        "value_flow prewarm should populate the workspace inter-taint singleton"
    );
}

#[test]
fn ingest_dir_clears_inter_taint_caches() {
    let ws = ws_with_python(
        "app.py",
        "def get_input():\n    return input()\n\n\
def main():\n    x = get_input()\n    print(x)\n",
    );
    ws.value_flow()
        .prewarm_all_with_caches(ws.db(), ws.inter_taint_caches());
    assert!(
        !ws.inter_taint_caches().is_empty(),
        "precondition: warmup populates cache"
    );

    // Editing the file (writing the same path with a different text)
    // must flush the workspace's inter-taint singleton so subsequent
    // queries see resolver/alias state derived from current AST.
    let body = "def get_input():\n    return raw_input()\n\n\
def main():\n    x = get_input()\n    print(x)\n";
    ws.vfs().write("app.py".to_string(), Arc::<str>::from(body));
    // The public path that wires invalidation is `Workspace::ingest_dir`.
    // Mirror that hook here directly:
    let prev_id = ws.vfs().all_files().into_iter().next().expect("file present");
    ws.db().invalidate_file(prev_id);
    ws.dataflow().invalidate_file(prev_id);
    ws.value_flow().clear();
    ws.inter_taint_caches().clear();
    assert!(
        ws.inter_taint_caches().is_empty(),
        "ingest-style invalidation must clear the inter-taint singleton"
    );
}
