//! Workspace transitive-callers index round-trip + invalidation.
//! Covers P1 of the post-stages-1-7 audit: replace per-invocation
//! depth-4 BFS with a workspace-cached lookup.

use bonsai_common::FuncId;
use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use bonsai_workspace::Workspace;
use std::sync::Arc;

fn registry() -> Arc<LanguageRegistry> {
    let r = Arc::new(LanguageRegistry::new());
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    r.register(adapter);
    r
}

fn ws_with(file: &str, src: &str) -> Workspace {
    let ws = Workspace::new(registry());
    ws.vfs().write(file.to_string(), Arc::<str>::from(src));
    for f in ws.vfs().all_files() {
        let _ = ws.db().decl_index(f);
    }
    ws
}

fn func_id(ws: &Workspace, name: &str) -> FuncId {
    let global = ws.db().global_index();
    let candidates = bonsai_callgraph::collect_callable_targets(&global, name);
    assert_eq!(
        candidates.len(),
        1,
        "expected one decl named `{name}`, got {}",
        candidates.len()
    );
    candidates[0]
}

#[test]
fn transitive_callers_returns_depth_bounded_set() {
    let ws = ws_with(
        "app.py",
        "def leaf():\n    pass\n\
def mid():\n    leaf()\n\
def top():\n    mid()\n",
    );
    let cg = ws.cached_resolved_call_graph();
    let leaf = func_id(&ws, "leaf");
    let mid = func_id(&ws, "mid");
    let top = func_id(&ws, "top");

    let depth_1 = ws.transitive_callers().callers_of(&cg, leaf, 1);
    assert_eq!(depth_1.as_ref(), &[mid]);

    let depth_2 = ws.transitive_callers().callers_of(&cg, leaf, 2);
    // Set semantics — FuncId allocation order isn't guaranteed,
    // so pin membership rather than positional ordering.
    let set: std::collections::HashSet<_> = depth_2.iter().copied().collect();
    assert!(set.contains(&mid));
    assert!(set.contains(&top));
    assert_eq!(set.len(), 2);
}

#[test]
fn second_lookup_returns_same_arc() {
    let ws = ws_with(
        "app.py",
        "def leaf():\n    pass\n\ndef caller():\n    leaf()\n",
    );
    let cg = ws.cached_resolved_call_graph();
    let leaf = func_id(&ws, "leaf");

    let first = ws.transitive_callers().callers_of(&cg, leaf, 4);
    let second = ws.transitive_callers().callers_of(&cg, leaf, 4);
    assert!(
        Arc::ptr_eq(&first, &second),
        "second probe should return the same Arc"
    );
}

#[test]
fn empty_when_no_callers() {
    let ws = ws_with("app.py", "def lonely():\n    pass\n");
    let cg = ws.cached_resolved_call_graph();
    let lonely = func_id(&ws, "lonely");
    let callers = ws.transitive_callers().callers_of(&cg, lonely, 4);
    assert!(callers.is_empty());
}
