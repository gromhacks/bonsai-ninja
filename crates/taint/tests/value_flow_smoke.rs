//! End-to-end smoke tests for the seed-free value-flow pass.
//!
//! Phase 2 deliverable. Confirms `value_flow_for_function` returns a
//! non-trivial graph for a simple Python program and that
//! forward/backward closures work correctly.

mod common;

use bonsai_lang_api::AdapterArc;
use bonsai_taint::{value_flow_for_function, InterTaintConfig, ValueFlowNodeKind};
use common::{build_db, func_id_or_none};
use std::sync::Arc;

#[test]
fn value_flow_python_two_hop_chain() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let src = "
def entry(args):
    x = args
    helper(x)

def helper(p):
    sink(p)
";
    let db = build_db(adapter, &[("a.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry indexes");

    let graph = value_flow_for_function(entry, &db, &InterTaintConfig::default());

    assert!(
        !graph.nodes.is_empty(),
        "value-flow graph for non-trivial entry must have nodes; got {graph:?}"
    );
    assert!(
        !graph.forward.is_empty(),
        "value-flow graph must have forward edges; got {graph:?}"
    );

    // Find the entry param node.
    let param_node = graph
        .nodes
        .iter()
        .find(|n| n.func == entry && n.kind == ValueFlowNodeKind::Param && n.value_text == "args")
        .expect("entry param node 'args' must exist");

    // Forward closure should reach the helper's `p` param.
    let reachable = graph.forward_closure(param_node);
    assert!(
        reachable.iter().any(|n| n.value_text == "p"),
        "forward closure from `args` must reach helper param `p`; got {reachable:?}"
    );
}

#[test]
fn value_flow_empty_for_paramless_entry() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let src = "
def main():
    pass
";
    let db = build_db(adapter, &[("a.py", src)]);
    let main = func_id_or_none(&db, "main").expect("main indexes");
    let graph = value_flow_for_function(main, &db, &InterTaintConfig::default());
    // No params, no body assignments: no self-provenance seeds → empty graph.
    assert!(
        graph.nodes.is_empty() && graph.forward.is_empty(),
        "paramless empty function must produce empty value-flow graph; got {graph:?}"
    );
}

#[test]
fn value_flow_backward_closure_finds_origin() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let src = "
def entry(args):
    helper(args)

def helper(p):
    sink(p)
";
    let db = build_db(adapter, &[("a.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry indexes");

    let graph = value_flow_for_function(entry, &db, &InterTaintConfig::default());

    // Find the helper-side `p` param node.
    let helper_param = graph
        .nodes
        .iter()
        .find(|n| n.kind == ValueFlowNodeKind::Param && n.value_text == "p")
        .expect("helper param `p` must exist");

    // Backward closure should reach the entry's `args` param.
    let origins = graph.backward_closure(helper_param);
    assert!(
        origins.iter().any(|n| n.value_text == "args"),
        "backward closure from `p` must reach origin `args`; got {origins:?}"
    );
}
