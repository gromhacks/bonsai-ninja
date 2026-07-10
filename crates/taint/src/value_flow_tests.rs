use super::*;
use bonsai_common::FileId;
use bonsai_lang_api::{Decl, FlowEvent, ModulePath, Visibility};

fn span(file: FileId, start: u64, end: u64) -> Span {
    Span { file, start, end }
}

fn node(func: u32, start: u64, text: &str, kind: ValueFlowNodeKind) -> ValueFlowNode {
    ValueFlowNode {
        func: FuncId::new(func),
        span: span(FileId::new(0), start, start + text.len() as u64),
        value_text: text.to_string(),
        kind,
    }
}

fn assign(start: u64, target: &str, source: &str) -> FlowEvent {
    FlowEvent::Assign {
        span: span(FileId::new(0), start, start + 1),
        target: target.to_string(),
        source_name: Some(source.to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }
}

fn ret(start: u64, value: &str) -> FlowEvent {
    FlowEvent::Return {
        span: span(FileId::new(0), start, start + 1),
        value_text: Some(value.to_string()),
        value_name: Some(value.to_string()),
    }
}

fn call(start: u64, name: &str, arg: &str) -> FlowEvent {
    FlowEvent::Call {
        span: span(FileId::new(0), start, start + 1),
        name: name.to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: vec![bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: span(FileId::new(0), start, start + 1),
            name: None,
            value_text: arg.to_string(),
            place: Some(arg.to_string()),
            source_names: Vec::new(),
        }],
    }
}

fn decl(params: &[&str], flow_events: Vec<FlowEvent>) -> Decl {
    Decl {
        symbol: SymbolId::new(1),
        kind: DeclKind::Function,
        name: "entry".to_string(),
        qualified_name: None,
        module_path: ModulePath::default(),
        span: span(FileId::new(0), 0, 100),
        name_span: span(FileId::new(0), 0, 5),
        visibility: Visibility::Private,
        parent: None,
        body_span: Some(span(FileId::new(0), 5, 100)),
        flow_events,
        has_implicit_returns: false,
        params: params.iter().map(|param| (*param).to_string()).collect(),
        param_annotations: Vec::new(),
        type_aliases: Vec::new(),
        bases: Vec::new(),
        receiver_param_index: None,
        receiver_field_writes: Vec::new(),
        implicit_receiver_names: Vec::new(),
        receiver_state_sources: Vec::new(),
        return_type: None,
        is_variadic: false,
    }
}

fn only_return_node(graph: &ValueFlowGraph) -> ValueFlowNode {
    let returns: Vec<ValueFlowNode> = graph
        .nodes
        .iter()
        .filter(|node| matches!(node.kind, ValueFlowNodeKind::Return))
        .cloned()
        .collect();
    assert_eq!(returns.len(), 1, "expected one return node, got {returns:?}");
    returns.into_iter().next().expect("return node")
}

#[test]
fn forward_closure_reaches_descendants() {
    let mut g = ValueFlowGraph::new();
    let a = node(1, 0, "a", ValueFlowNodeKind::Param);
    let b = node(1, 4, "b", ValueFlowNodeKind::AssignTarget);
    let c = node(1, 8, "c", ValueFlowNodeKind::CallArg);
    g.add_edge(ValueFlowEdge {
        from: a.clone(),
        to: b.clone(),
        precision: Precision::Exact,
        via_span: span(FileId::new(0), 0, 1),
    });
    g.add_edge(ValueFlowEdge {
        from: b.clone(),
        to: c.clone(),
        precision: Precision::Exact,
        via_span: span(FileId::new(0), 4, 5),
    });
    let reach = g.forward_closure(&a);
    assert!(reach.contains(&b));
    assert!(reach.contains(&c));
    assert!(!reach.contains(&a));
}

#[test]
fn backward_closure_reaches_ancestors() {
    let mut g = ValueFlowGraph::new();
    let a = node(1, 0, "a", ValueFlowNodeKind::Param);
    let b = node(1, 4, "b", ValueFlowNodeKind::AssignTarget);
    g.add_edge(ValueFlowEdge {
        from: a.clone(),
        to: b.clone(),
        precision: Precision::Exact,
        via_span: span(FileId::new(0), 0, 1),
    });
    assert!(g.backward_closure(&b).contains(&a));
    assert!(g.forward_closure(&a).contains(&b));
}

#[test]
fn add_edge_meets_precision_to_worst() {
    let mut g = ValueFlowGraph::new();
    let a = node(1, 0, "a", ValueFlowNodeKind::Param);
    let b = node(1, 4, "b", ValueFlowNodeKind::AssignTarget);
    g.add_edge(ValueFlowEdge {
        from: a.clone(),
        to: b.clone(),
        precision: Precision::OverApproximate,
        via_span: span(FileId::new(0), 0, 1),
    });
    assert_eq!(g.precision, Precision::OverApproximate);
}

#[test]
fn closures_do_not_traverse_diagnostic_precision_edges() {
    let mut g = ValueFlowGraph::new();
    let a = node(1, 0, "a", ValueFlowNodeKind::Param);
    let b = node(1, 4, "b", ValueFlowNodeKind::AssignTarget);
    let c = node(1, 8, "c", ValueFlowNodeKind::CallArg);
    g.add_edge(ValueFlowEdge {
        from: a.clone(),
        to: b.clone(),
        precision: Precision::Narrowed,
        via_span: span(FileId::new(0), 0, 1),
    });
    g.add_edge(ValueFlowEdge {
        from: b.clone(),
        to: c.clone(),
        precision: Precision::OverApproximate,
        via_span: span(FileId::new(0), 4, 5),
    });

    let forward = g.forward_closure(&a);
    assert!(forward.contains(&b));
    assert!(
        !forward.contains(&c),
        "default value-flow closure must not traverse over-approximate evidence",
    );

    let backward = g.backward_closure(&c);
    assert!(
        backward.is_empty(),
        "backward closure must also stop at diagnostic precision edges",
    );
}

#[test]
fn lattice_mode_default_is_token_set() {
    assert_eq!(LatticeMode::default(), LatticeMode::TokenSet);
}

#[test]
fn return_edges_use_current_straight_line_definition() {
    let decl = decl(
        &["a", "b"],
        vec![assign(10, "x", "a"), assign(20, "x", "b"), ret(30, "x")],
    );
    let (graph, _) = build_intra_entry_graph(FuncId::new(1), &decl);
    let return_node = only_return_node(&graph);
    let back = graph.backward_closure(&return_node);

    assert!(
        back.iter().any(|node| {
            node.kind == ValueFlowNodeKind::AssignTarget && node.value_text == "x" && node.span.start == 20
        }),
        "return should depend on the latest x definition: {back:?}"
    );
    assert!(
        back.iter()
            .any(|node| node.kind == ValueFlowNodeKind::Param && node.value_text == "b"),
        "latest x definition should preserve its source param: {back:?}"
    );
    assert!(
        !back.iter().any(|node| {
            node.kind == ValueFlowNodeKind::AssignTarget && node.value_text == "x" && node.span.start == 10
        }),
        "stale straight-line x definition must not reach return: {back:?}"
    );
}

#[test]
fn return_edges_merge_branch_definitions() {
    let decl = decl(
        &["a", "b"],
        vec![
            FlowEvent::Branch {
                span: span(FileId::new(0), 10, 30),
                condition: Some("flag".to_string()),
                then_events: vec![assign(12, "x", "a")],
                else_events: vec![assign(22, "x", "b")],
            },
            ret(40, "x"),
        ],
    );
    let (graph, _) = build_intra_entry_graph(FuncId::new(1), &decl);
    let return_node = only_return_node(&graph);
    let back = graph.backward_closure(&return_node);

    for source in ["a", "b"] {
        assert!(
            back.iter()
                .any(|node| node.kind == ValueFlowNodeKind::Param && node.value_text == source),
            "branch return should preserve source param {source}: {back:?}"
        );
    }
    for start in [12, 22] {
        assert!(
            back.iter().any(|node| {
                node.kind == ValueFlowNodeKind::AssignTarget
                    && node.value_text == "x"
                    && node.span.start == start
            }),
            "branch return should include x definition at {start}: {back:?}"
        );
    }
}

#[test]
fn call_arg_edges_merge_branch_definitions_at_call_site() {
    let decl = decl(
        &["a", "b"],
        vec![
            FlowEvent::Branch {
                span: span(FileId::new(0), 10, 30),
                condition: Some("flag".to_string()),
                then_events: vec![assign(12, "x", "a")],
                else_events: vec![assign(22, "x", "b")],
            },
            call(40, "sink", "x"),
        ],
    );
    let (graph, _) = build_intra_entry_graph(FuncId::new(1), &decl);
    let call_arg =
        find_call_arg_node(&graph, FuncId::new(1), span(FileId::new(0), 40, 41), "x").expect("call arg node");
    let back = graph.backward_closure(&call_arg);

    for source in ["a", "b"] {
        assert!(
            back.iter()
                .any(|node| node.kind == ValueFlowNodeKind::Param && node.value_text == source),
            "call arg should preserve source param {source}: {back:?}"
        );
    }
    for start in [12, 22] {
        assert!(
            back.iter().any(|node| {
                node.kind == ValueFlowNodeKind::AssignTarget
                    && node.value_text == "x"
                    && node.span.start == start
            }),
            "call arg should include x definition at {start}: {back:?}"
        );
    }
}

// audit re-apply: R3

#[test]
fn try_catch_links_thrown_value_to_catch_binding() {
    // R3: `throw a; catch (e) { sink(e); }` — on the legacy value-flow
    // walker the thrown param must reach the catch binding `e` and
    // onward to the sink. Before the fix the Try arm seeded `e` with no
    // incoming edge from the body's thrown value, so the param `a` had
    // no forward lineage at all.
    let decl = decl(
        &["a"],
        vec![FlowEvent::Try {
            span: span(FileId::new(0), 10, 60),
            body: vec![FlowEvent::Throw {
                span: span(FileId::new(0), 12, 20),
                value_name: Some("a".to_string()),
                thrown_type: None,
            }],
            catch_events: vec![call(40, "sink", "e")],
            finally_events: Vec::new(),
            catch_param: Some("e".to_string()),
            catch_types: Vec::new(),
        }],
    );
    let (graph, _) = build_intra_entry_graph(FuncId::new(1), &decl);
    let param_a = graph
        .nodes
        .iter()
        .find(|n| n.kind == ValueFlowNodeKind::Param && n.value_text == "a")
        .expect("entry param `a` must exist")
        .clone();
    let reached = graph.forward_closure(&param_a);
    assert!(
        reached
            .iter()
            .any(|n| n.kind == ValueFlowNodeKind::Catch && n.value_text == "e"),
        "thrown param `a` must reach the catch binding `e`: {reached:?}"
    );
    assert!(
        reached
            .iter()
            .any(|n| n.kind == ValueFlowNodeKind::CallArg && n.value_text == "e"),
        "thrown param `a` must reach the sink arg `e`: {reached:?}"
    );
}

#[test]
fn yield_emits_return_node_for_yielded_value() {
    // R3: `yield a` must produce a Return-kind output node fed by the
    // yielded value's origins so backward lineage from a consumer can
    // reach `a`. Before the fix the Yield event hit the catch-all `_`
    // arm and produced no node or edge at all.
    let decl = decl(
        &["a"],
        vec![FlowEvent::Yield {
            span: span(FileId::new(0), 10, 18),
            value_text: Some("a".to_string()),
        }],
    );
    let (graph, _) = build_intra_entry_graph(FuncId::new(1), &decl);
    let param_a = graph
        .nodes
        .iter()
        .find(|n| n.kind == ValueFlowNodeKind::Param && n.value_text == "a")
        .expect("entry param `a` must exist")
        .clone();
    let reached = graph.forward_closure(&param_a);
    assert!(
        reached
            .iter()
            .any(|n| n.kind == ValueFlowNodeKind::Return && n.value_text == "a"),
        "yielded param `a` must reach a Return-kind output node: {reached:?}"
    );
}
