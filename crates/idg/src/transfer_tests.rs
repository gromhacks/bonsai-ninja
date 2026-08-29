use super::*;
use bonsai_common::{FileId, Span as CommonSpan, SymbolId};
use bonsai_lang_api::{CallArg, CatchArmFact, ModulePath, Visibility};

fn span(lo: u64, hi: u64) -> CommonSpan {
    CommonSpan::new(FileId::new(0), lo, hi)
}

fn empty_decl(sym: u32, name: &str) -> Decl {
    Decl {
        symbol: SymbolId::new(sym),
        kind: bonsai_lang_api::DeclKind::Function,
        name: name.to_string(),
        qualified_name: None,
        module_path: ModulePath::default(),
        span: span(0, 100),
        name_span: span(0, 10),
        visibility: Visibility::Public,
        parent: None,
        body_span: Some(span(10, 100)),
        flow_events: Vec::new(),
        has_implicit_returns: false,
        params: Vec::new(),
        param_annotations: Vec::new(),
        param_default_calls: Vec::new(),
        type_aliases: Vec::new(),
        bases: Vec::new(),
        receiver_param_index: None,
        receiver_field_writes: Vec::new(),
        receiver_field_initializers: Vec::new(),
        implicit_receiver_names: Vec::new(),
        receiver_state_sources: Vec::new(),
        return_type: None,
        is_variadic: false,
    }
}

#[test]
fn variadic_source_callback_indices_expand_only_to_exact_compiler_arity() {
    let shape = SourceCallbackArgSpec {
        callee: "source.callback".to_string(),
        callback_arg_index: 0,
        source_param_indices: vec![0, 4],
        source_param_indices_from: Some(1),
        resolved_call_sites: vec![span(10, 20)],
    };
    assert_eq!(shape.resolved_source_param_indices(4), [0, 1, 2, 3]);
    assert_eq!(shape.resolved_source_param_indices(1), [0]);
    assert!(
        shape.resolved_source_param_indices(0).is_empty(),
        "declarative variadic semantics must never invent callback parameters"
    );
}

fn count_edges_of(out: &TransferOutput, kind: IdgEdgeKind) -> usize {
    out.edges.iter().filter(|e| e.meta.kind == kind).count()
}

fn rendered_place_name(out: &TransferOutput, node_id: NodeId) -> String {
    let node = out.nodes.get(node_id).expect("node exists");
    let place = out.places.get(node.place).expect("place exists");
    match place {
        Place::Read { name, path } | Place::Write { name, path, .. } => {
            let mut rendered = out.names.get(*name).unwrap_or("").to_string();
            for part in path {
                rendered.push('.');
                rendered.push_str(out.names.get(*part).unwrap_or(""));
            }
            rendered
        }
        Place::CallArg { site, idx } => format!("CallArg({:?},{})", site.0, idx),
        Place::CallRet { site } => format!("CallRet({:?})", site.0),
        Place::Param { idx } => format!("Param({idx})"),
        Place::Return => "Return".to_string(),
        Place::Throw { .. } => "Throw".to_string(),
        Place::Catch { .. } => "Catch".to_string(),
        Place::Yield => "Yield".to_string(),
        Place::Await => "Await".to_string(),
    }
}

fn rendered_write_span(out: &TransferOutput, node_id: NodeId) -> Option<CommonSpan> {
    let node = out.nodes.get(node_id).expect("node exists");
    let place = out.places.get(node.place).expect("place exists");
    match place {
        Place::Write { span, .. } => Some(*span),
        _ => None,
    }
}

fn rendered_catch_type(out: &TransferOutput, node_id: NodeId) -> Option<&str> {
    let node = out.nodes.get(node_id).expect("node exists");
    let place = out.places.get(node.place).expect("place exists");
    let Place::Catch { ty } = place else {
        return None;
    };
    out.names.get(ty.0)
}

#[test]
fn empty_decl_emits_no_edges() {
    let decl = empty_decl(1, "f");
    let out = transfer_function_for(&decl);
    assert_eq!(out.edges.len(), 0);
    assert_eq!(out.call_sites.len(), 0);
    assert_eq!(out.throw_sites.len(), 0);
}

#[test]
fn parameter_seeding_creates_param_to_read_bridge() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["x".to_string(), "y".to_string()];
    let out = transfer_function_for(&decl);
    // Two Param→Read bridge edges, one per param.
    assert_eq!(out.edges.len(), 2);
    for edge in &out.edges {
        assert_eq!(edge.meta.kind, IdgEdgeKind::IntraAssign);
        assert_eq!(edge.meta.precision, Precision::Exact);
    }
}

#[test]
fn empty_param_name_skipped() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["x".to_string(), String::new(), "z".to_string()];
    let out = transfer_function_for(&decl);
    // Only x and z get bridge edges.
    assert_eq!(out.edges.len(), 2);
}

#[test]
fn property_read_argument_keeps_storage_and_accessor_return_inputs() {
    let mut decl = empty_decl(1, "handle");
    decl.params = vec!["token".to_string()];
    let assignment_span = span(10, 20);
    let property_call_span = span(30, 38);
    let sink_call_span = span(40, 44);
    let argument_span = span(45, 53);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: assignment_span,
            target: "this.cmd".to_string(),
            source_name: Some("token".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["token".to_string()],
            declares_new_binding: false,
            value_kind: Some(AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: property_call_span,
            name: "this.cmd".to_string(),
            receiver: Some("this".to_string()),
            receiver_types: vec!["Record".to_string()],
            call_kind: CallKind::Method,
            args: Vec::new(),
        },
        FlowEvent::Call {
            span: sink_call_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                span: argument_span,
                passing_mode: Default::default(),
                name: None,
                value_text: "this.cmd".to_string(),
                place: Some("this.cmd".to_string()),
                source_names: vec!["this.cmd".to_string()],
            }],
        },
    ];
    let argument_values = [CallArgumentValueFact {
        call_span: sink_call_span,
        argument_index: 0,
        argument_span,
        direct_call_span: Some(property_call_span),
        value_kind: Some(AssignValueKind::PropertyRead),
        inline_callback_params: Vec::new(),
        inline_callback_span: None,
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        value_flow: ExpressionFlow::from_place("this.cmd"),
        static_value: None,
        exact_static_aggregate_fields: Vec::new(),
        exact_static_sequence_values: None,
    }];
    let out = transfer_function_for_with_options_and_compiler_facts(
        &decl,
        &TransferOptions::default(),
        &[],
        &[],
        &argument_values,
        &[],
    );
    let sink_arg = out
        .places
        .places
        .iter()
        .position(|place| matches!(place, Place::CallArg { site, idx: 0 } if site.0 == sink_call_span))
        .and_then(|place| {
            out.nodes
                .nodes
                .iter()
                .position(|node| node.place.0 as usize == place)
                .map(|node| NodeId(u32::try_from(node).expect("node id")))
        })
        .expect("sink argument node");
    let incoming = out
        .edges
        .iter()
        .filter(|edge| edge.to == sink_arg)
        .map(|edge| rendered_place_name(&out, edge.from))
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        incoming.contains("this.cmd"),
        "property projection must retain exact storage input: {incoming:?}"
    );
    assert!(
        incoming.contains(&format!("CallRet({property_call_span:?})")),
        "computed accessor return must remain an independent input: {incoming:?}"
    );
}

#[test]
fn compiled_source_callback_span_is_authoritative_over_rendered_callee() {
    let mut decl = empty_decl(1, "module");
    let source_span = span(20, 48);
    let callback_span = span(49, 90);
    let sink_span = span(70, 74);
    decl.flow_events = vec![
        FlowEvent::Call {
            span: source_span,
            name: "t.procedure.input(schema).query".to_string(),
            receiver: Some("t.procedure.input(schema)".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: vec![CallArg {
                span: callback_span,
                passing_mode: Default::default(),
                name: None,
                value_text: "async ({ input }) => sink(input)".to_string(),
                place: None,
                source_names: vec!["input".to_string()],
            }],
        },
        FlowEvent::Assign {
            span: callback_span,
            target: "input".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["input".to_string()],
            declares_new_binding: false,
            value_kind: Some(AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: sink_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                span: span(75, 80),
                passing_mode: Default::default(),
                name: None,
                value_text: "\"prefix\" + input.column".to_string(),
                place: None,
                source_names: vec!["input".to_string(), "input.column".to_string()],
            }],
        },
    ];
    let callback_facts = [CallArgumentValueFact {
        call_span: source_span,
        argument_index: 0,
        argument_span: callback_span,
        direct_call_span: None,
        value_kind: None,
        inline_callback_params: vec!["input".to_string()],
        inline_callback_span: Some(callback_span),
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        value_flow: ExpressionFlow::default(),
        static_value: None,
        exact_static_aggregate_fields: Vec::new(),
        exact_static_sequence_values: None,
    }];
    let options = TransferOptions {
        source_callback_args: vec![SourceCallbackArgSpec {
            // Rule compilation may retain a provider/type-qualified identity
            // while the adapter renders the source expression at the call
            // site. The exact matched span, not this diagnostic spelling, is
            // the transfer contract.
            callee: "ExternalProcedure.query".to_string(),
            callback_arg_index: 0,
            source_param_indices: vec![0],
            source_param_indices_from: None,
            resolved_call_sites: vec![source_span],
        }],
        ..TransferOptions::default()
    };

    let out = transfer_function_for_with_options_and_compiler_facts(
        &decl,
        &options,
        &[],
        &[],
        &callback_facts,
        &[],
    );
    let source_ret = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallRet { site }) if site.0 == source_span
            )
            .then_some(NodeId(u32::try_from(index).expect("node id")))
        })
        .expect("source call result");
    let callback_binding = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::Write { span, .. }) if *span == callback_span
            )
            .then_some(NodeId(u32::try_from(index).expect("node id")))
        })
        .expect("inline callback binding");
    let sink_arg = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx: 0 }) if site.0 == sink_span
            )
            .then_some(NodeId(u32::try_from(index).expect("node id")))
        })
        .expect("sink argument");

    assert!(out
        .edges
        .iter()
        .any(|edge| edge.from == source_ret && edge.to == callback_binding));
    assert!(out
        .edges
        .iter()
        .any(|edge| edge.from == callback_binding && edge.to == sink_arg));

    let without_rule = transfer_function_for_with_options_and_compiler_facts(
        &decl,
        &TransferOptions::default(),
        &[],
        &[],
        &callback_facts,
        &[],
    );
    assert!(without_rule.edges.iter().all(|edge| {
        !(rendered_place_name(&without_rule, edge.from).starts_with("CallRet(")
            && rendered_place_name(&without_rule, edge.to) == "input")
    }));
}

#[test]
fn configured_source_call_replaces_generic_yield_result_binding_at_registration_site() {
    let mut decl = empty_decl(1, "module");
    let source_span = span(20, 28);
    let callback_span = span(29, 70);
    let sink_span = span(50, 54);
    decl.flow_events = vec![
        FlowEvent::Call {
            span: source_span,
            name: "register".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                span: callback_span,
                passing_mode: Default::default(),
                name: None,
                value_text: "do |payload| sink(payload) end".to_string(),
                place: None,
                source_names: vec!["payload".to_string()],
            }],
        },
        FlowEvent::Assign {
            // The generic closure walker keys yielded parameters to the
            // registration call so callgraph resolution can identify the
            // producer. Exact source-callback semantics must replace this
            // synthetic alias without overwriting the delivered binding.
            span: source_span,
            target: "payload".to_string(),
            source_name: None,
            source_call: Some("register".to_string()),
            source_call_args: vec!["do |payload| sink(payload) end".to_string()],
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(AssignValueKind::YieldResult),
        },
        FlowEvent::Call {
            span: sink_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                span: span(55, 62),
                passing_mode: Default::default(),
                name: None,
                value_text: "payload".to_string(),
                place: Some("payload".to_string()),
                source_names: vec!["payload".to_string()],
            }],
        },
    ];
    let callback_facts = [CallArgumentValueFact {
        call_span: source_span,
        argument_index: 0,
        argument_span: callback_span,
        direct_call_span: None,
        value_kind: None,
        inline_callback_params: vec!["payload".to_string()],
        inline_callback_span: Some(callback_span),
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        value_flow: ExpressionFlow::default(),
        static_value: None,
        exact_static_aggregate_fields: Vec::new(),
        exact_static_sequence_values: None,
    }];
    let options = TransferOptions {
        source_callback_args: vec![SourceCallbackArgSpec {
            callee: "register".to_string(),
            callback_arg_index: 0,
            source_param_indices: vec![0],
            source_param_indices_from: None,
            resolved_call_sites: vec![source_span],
        }],
        ..TransferOptions::default()
    };

    let out = transfer_function_for_with_options_and_compiler_facts(
        &decl,
        &options,
        &[],
        &[],
        &callback_facts,
        &[],
    );
    let delivered = out
        .edges
        .iter()
        .find(|edge| edge.meta.kind == IdgEdgeKind::InterSourceCallback)
        .expect("exact callback delivery edge");
    let sink_arg = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx: 0 }) if site.0 == sink_span
            )
            .then_some(NodeId(u32::try_from(index).expect("node id")))
        })
        .expect("sink argument");
    assert!(out
        .edges
        .iter()
        .any(|edge| edge.from == delivered.to && edge.to == sink_arg));
}

#[test]
fn source_callback_suppresses_only_the_selected_delivered_parameter() {
    let mut decl = empty_decl(1, "module");
    let source_span = span(20, 28);
    let callback_span = span(29, 74);
    let callback_text = "do |context, payload| sink(payload) end";
    decl.flow_events = vec![
        FlowEvent::Call {
            span: source_span,
            name: "register".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                span: callback_span,
                passing_mode: Default::default(),
                name: None,
                value_text: callback_text.to_string(),
                place: None,
                source_names: vec!["context".to_string(), "payload".to_string()],
            }],
        },
        FlowEvent::Assign {
            span: source_span,
            target: "context".to_string(),
            source_name: None,
            source_call: Some("register".to_string()),
            source_call_args: vec![callback_text.to_string()],
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(AssignValueKind::YieldResult),
        },
        FlowEvent::Assign {
            span: source_span,
            target: "payload".to_string(),
            source_name: None,
            source_call: Some("register".to_string()),
            source_call_args: vec![callback_text.to_string()],
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(AssignValueKind::YieldResult),
        },
    ];
    let callback_facts = [CallArgumentValueFact {
        call_span: source_span,
        argument_index: 0,
        argument_span: callback_span,
        direct_call_span: None,
        value_kind: None,
        inline_callback_params: vec!["context".to_string(), "payload".to_string()],
        inline_callback_span: Some(callback_span),
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        value_flow: ExpressionFlow::default(),
        static_value: None,
        exact_static_aggregate_fields: Vec::new(),
        exact_static_sequence_values: None,
    }];
    let options = TransferOptions {
        source_callback_args: vec![SourceCallbackArgSpec {
            callee: "register".to_string(),
            callback_arg_index: 0,
            source_param_indices: vec![1],
            source_param_indices_from: None,
            resolved_call_sites: vec![source_span],
        }],
        ..TransferOptions::default()
    };

    let out = transfer_function_for_with_options_and_compiler_facts(
        &decl,
        &options,
        &[],
        &[],
        &callback_facts,
        &[],
    );
    let write_at = |expected: &str, expected_span: Span| {
        out.nodes.nodes.iter().any(|node| {
            matches!(
                out.places.get(node.place),
                Some(Place::Write { name, span, .. })
                    if *span == expected_span && out.names.get(*name) == Some(expected)
            )
        })
    };
    assert!(
        write_at("context", source_span),
        "the unselected callback parameter must retain ordinary HOF lowering"
    );
    assert!(
        !write_at("payload", source_span),
        "the selected externally-delivered parameter must not be overwritten by generic HOF lowering"
    );
    assert!(
        write_at("payload", callback_span),
        "the selected callback parameter must receive the exact external-delivery binding"
    );
}

#[test]
fn distinct_source_callbacks_in_one_callable_do_not_alias_their_parameters() {
    let mut decl = empty_decl(1, "sockets");
    let text_call = span(10, 20);
    let text_closure = span(21, 40);
    let text_sink = span(31, 35);
    let binary_call = span(50, 62);
    let binary_closure = span(63, 84);
    let binary_sink = span(74, 80);
    let callback_arg = |closure_span: Span, rendered: &str, source_names: Vec<String>| CallArg {
        span: closure_span,
        passing_mode: Default::default(),
        name: None,
        value_text: rendered.to_string(),
        place: None,
        source_names,
    };
    let sink_arg = |value: &str, arg_span| CallArg {
        span: arg_span,
        passing_mode: Default::default(),
        name: None,
        value_text: value.to_string(),
        place: Some(value.to_string()),
        source_names: vec![value.to_string()],
    };
    let synthetic_binding = |closure_span, target: &str, sources: Vec<&str>| FlowEvent::Assign {
        span: closure_span,
        target: target.to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: sources.into_iter().map(str::to_string).collect(),
        declares_new_binding: false,
        value_kind: None,
    };
    decl.flow_events = vec![
        FlowEvent::Call {
            span: text_call,
            name: "socket.onText".to_string(),
            receiver: Some("socket".to_string()),
            receiver_types: vec!["WebSocket".to_string()],
            call_kind: CallKind::Method,
            args: vec![callback_arg(
                text_closure,
                "{ ws, text in sink(text) }",
                vec!["ws".to_string(), "text".to_string()],
            )],
        },
        synthetic_binding(text_closure, "ws", vec!["socket", "text", "ws"]),
        synthetic_binding(text_closure, "text", vec!["socket", "text", "ws"]),
        FlowEvent::Call {
            span: text_sink,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![sink_arg("text", span(36, 39))],
        },
        FlowEvent::Call {
            span: binary_call,
            name: "socket.onBinary".to_string(),
            receiver: Some("socket".to_string()),
            receiver_types: vec!["WebSocket".to_string()],
            call_kind: CallKind::Method,
            args: vec![callback_arg(
                binary_closure,
                "{ ws, data in sink(data) }",
                vec!["ws".to_string(), "data".to_string()],
            )],
        },
        synthetic_binding(binary_closure, "ws", vec!["socket", "data", "ws"]),
        synthetic_binding(binary_closure, "data", vec!["socket", "data", "ws"]),
        FlowEvent::Call {
            span: binary_sink,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![sink_arg("data", span(81, 83))],
        },
    ];
    let callback_facts = [
        CallArgumentValueFact {
            call_span: text_call,
            argument_index: 0,
            argument_span: text_closure,
            direct_call_span: None,
            value_kind: None,
            inline_callback_params: vec!["ws".to_string(), "text".to_string()],
            inline_callback_span: Some(text_closure),
            inline_callback_static_return: None,
            inline_callback_fields: Vec::new(),
            value_flow: ExpressionFlow::default(),
            static_value: None,
            exact_static_aggregate_fields: Vec::new(),
            exact_static_sequence_values: None,
        },
        CallArgumentValueFact {
            call_span: binary_call,
            argument_index: 0,
            argument_span: binary_closure,
            direct_call_span: None,
            value_kind: None,
            inline_callback_params: vec!["ws".to_string(), "data".to_string()],
            inline_callback_span: Some(binary_closure),
            inline_callback_static_return: None,
            inline_callback_fields: Vec::new(),
            value_flow: ExpressionFlow::default(),
            static_value: None,
            exact_static_aggregate_fields: Vec::new(),
            exact_static_sequence_values: None,
        },
    ];
    let options = TransferOptions {
        source_callback_args: vec![
            SourceCallbackArgSpec {
                callee: r"regex:\.onText$".to_string(),
                callback_arg_index: 0,
                source_param_indices: vec![1],
                source_param_indices_from: None,
                resolved_call_sites: vec![text_call],
            },
            SourceCallbackArgSpec {
                callee: r"regex:\.onBinary$".to_string(),
                callback_arg_index: 0,
                source_param_indices: vec![1],
                source_param_indices_from: None,
                resolved_call_sites: vec![binary_call],
            },
        ],
        ..TransferOptions::default()
    };
    let out = transfer_function_for_with_options_and_compiler_facts(
        &decl,
        &options,
        &[],
        &[],
        &callback_facts,
        &[],
    );
    let node_at = |name: &str, write_span: CommonSpan| {
        out.nodes
            .nodes
            .iter()
            .enumerate()
            .find_map(|(index, _)| {
                let node = NodeId(u32::try_from(index).expect("node id"));
                (rendered_place_name(&out, node) == name
                    && rendered_write_span(&out, node) == Some(write_span))
                .then_some(node)
            })
            .expect("callback binding")
    };
    let text = node_at("text", text_closure);
    let data = node_at("data", binary_closure);
    let binary_arg = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx: 0 }) if site.0 == binary_sink
            )
            .then_some(NodeId(u32::try_from(index).expect("node id")))
        })
        .expect("binary sink argument");

    assert!(out
        .edges
        .iter()
        .any(|edge| edge.from == data && edge.to == binary_arg));
    assert!(
        out.edges
            .iter()
            .all(|edge| !(edge.from == text && (edge.to == data || edge.to == binary_arg))),
        "the first external callback must not taint a later callback's parameter or sink"
    );
}

#[test]
fn assign_simple_emits_read_to_write_edge() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Assign {
        span: span(20, 30),
        target: "y".to_string(),
        source_name: Some("x".to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }];
    let out = transfer_function_for(&decl);
    // One IntraAssign edge: `Read(x) → Write(y, span=20..30)`.
    // The CFG-narrowing transfer pass routes any subsequent
    // reads of `y` directly from the new `Write(y, span)` to
    // the consumer (per-use last_writer bridge), so no shared
    // `Write→Read(y)` bridge is needed.
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 1);
}

#[test]
fn compound_assign_source_names_reach_target_writer() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Assign {
        span: span(20, 30),
        target: "RawTokens".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["Part".to_string(), "Cmd".to_string()],
        declares_new_binding: false,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
    }];

    let out = transfer_function_for(&decl);
    let raw_tokens_writes = out
        .edges
        .iter()
        .filter(|edge| rendered_place_name(&out, edge.to) == "RawTokens")
        .map(|edge| rendered_place_name(&out, edge.from))
        .collect::<Vec<_>>();

    assert!(
        raw_tokens_writes.iter().any(|source| source == "Cmd"),
        "Cmd should bridge to RawTokens writer: {raw_tokens_writes:?}"
    );
}

#[test]
fn assign_compound_emits_one_edge_per_source_name() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Assign {
        span: span(20, 40),
        target: "z".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["x".to_string(), "y".to_string()],
        declares_new_binding: false,
        value_kind: None,
    }];
    let out = transfer_function_for(&decl);
    // Two IntraAssign edges: one per source name into Write(z).
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 2);
}

#[test]
fn c_variadic_runtime_builtins_bridge_pack_to_extracted_value() {
    let mut decl = empty_decl(1, "helper");
    decl.params = vec![
        "first".to_string(),
        bonsai_lang_api::kit::SYNTHETIC_VARARGS_PARAM.to_string(),
    ];
    decl.flow_events = vec![
        FlowEvent::Call {
            span: span(20, 30),
            name: "va_start".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(25, 27),
                name: None,
                value_text: "ap".to_string(),
                place: Some("ap".to_string()),
                source_names: vec!["ap".to_string()],
            }],
        },
        FlowEvent::Assign {
            span: span(40, 55),
            target: "x".to_string(),
            source_name: None,
            source_call: Some("va_arg".to_string()),
            source_call_args: vec!["ap".to_string(), "const char *".to_string()],
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
    ];
    bonsai_lang_api::kit::normalize_variadic_builtin_flow(
        &mut decl.flow_events,
        true,
        &["va_start", "__builtin_va_start"],
        &["va_arg", "__builtin_va_arg"],
    );

    let out = transfer_function_for(&decl);
    assert!(out.edges.iter().any(|edge| {
        rendered_place_name(&out, edge.from) == bonsai_lang_api::kit::SYNTHETIC_VARARGS_PARAM
            && rendered_place_name(&out, edge.to) == "ap"
    }));
    assert!(out.edges.iter().any(|edge| {
        rendered_place_name(&out, edge.from) == "ap" && rendered_place_name(&out, edge.to) == "x"
    }));
}

#[test]
fn string_transform_call_result_is_not_hardcoded_passthrough() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["value".to_string()];
    decl.flow_events = vec![FlowEvent::Assign {
        span: span(20, 40),
        target: "upper".to_string(),
        source_name: None,
        source_call: Some("strings.ToUpper".to_string()),
        source_call_args: vec!["value".to_string()],
        source_names: vec!["strings.ToUpper".to_string(), "value".to_string()],
        declares_new_binding: false,
        value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
    }];
    let out = transfer_function_for(&decl);

    assert!(out.edges.iter().any(|edge| {
        rendered_place_name(&out, edge.from) == "value"
            && rendered_place_name(&out, edge.to).starts_with("CallArg")
            && edge.meta.kind == IdgEdgeKind::IntraRead
    }));
    assert!(out.edges.iter().any(|edge| {
        rendered_place_name(&out, edge.from).starts_with("CallRet")
            && rendered_place_name(&out, edge.to) == "upper"
            && edge.meta.kind == IdgEdgeKind::IntraAssign
    }));
    assert!(!out.edges.iter().any(|edge| {
        rendered_place_name(&out, edge.from) == "value"
            && rendered_place_name(&out, edge.to) == "upper"
            && edge.meta.kind == IdgEdgeKind::IntraAssign
    }));
}

#[test]
fn indexed_literal_element_write_does_not_overwrite_whole_buffer() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["value".to_string()];
    let copy_span = span(20, 30);
    let terminator_span = span(31, 40);
    let sink_span = span(50, 60);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: copy_span,
            target: "upper".to_string(),
            source_name: Some("value".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["value".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: terminator_span,
            target: "upper".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["upper".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: terminator_span,
            target: "upper.sizeof(upper)-1".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["upper".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: sink_span,
            name: "execute".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: sink_span,
                name: None,
                value_text: "upper".to_string(),
                place: Some("upper".to_string()),
                source_names: vec!["upper".to_string()],
            }],
        },
    ];
    let out = transfer_function_for(&decl);

    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "upper"
                && rendered_write_span(&out, edge.from) == Some(copy_span)
                && rendered_place_name(&out, edge.to).starts_with("CallArg")
                && edge.meta.kind == IdgEdgeKind::IntraRead
        }),
        "indexed literal element writes must not clean-overwrite the whole buffer before a later read: {:#?}",
        out.edges
    );
    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "upper"
                && rendered_write_span(&out, edge.from) == Some(terminator_span)
                && rendered_place_name(&out, edge.to).starts_with("CallArg")
        }),
        "the synthetic base target from `upper[sizeof(upper)-1] = '\\0'` must not become the live buffer writer: {:#?}",
        out.edges
    );
}

#[test]
fn field_precise_container_assignment_does_not_bridge_sources_to_base_write() {
    let mut decl = empty_decl(1, "f");
    let s = span(20, 80);
    let assignment_values = vec![bonsai_lang_api::AssignmentValueFact {
        assignment_span: s,
        target: Some("env".to_string()),
        target_is_immutable: false,
        target_owner: None,
        target_span: Some(span(20, 23)),
        value_span: span(26, 80),
        call_sites: Vec::new(),
        value_flow: bonsai_lang_api::ExpressionFlow {
            aggregate_fields: vec![
                bonsai_lang_api::ExpressionField {
                    name: "Cmd".to_string(),
                    value_span: Some(span(40, 43)),
                    value: bonsai_lang_api::ExpressionFlow::from_place("raw"),
                },
                bonsai_lang_api::ExpressionField {
                    name: "User".to_string(),
                    value_span: Some(span(50, 54)),
                    value: bonsai_lang_api::ExpressionFlow::from_place("user"),
                },
            ],
            ..Default::default()
        },
        static_value: None,
        exact_callable_return: None,
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        exact_static_call_args: None,
        direct_call_name: None,
        direct_call_span: None,
        direct_call_receiver: None,
        direct_call_receiver_span: None,
        direct_call_receiver_flow: None,
    }];
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: s,
            target: "env".to_string(),
            source_name: None,
            source_call: Some("len".to_string()),
            source_call_args: vec!["raw".to_string()],
            source_names: vec![
                "Cmd".to_string(),
                "Kind".to_string(),
                "User".to_string(),
                "raw".to_string(),
                "user".to_string(),
            ],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Assign {
            span: s,
            target: "env.Cmd".to_string(),
            source_name: Some("raw".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["raw".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: s,
            target: "env.User".to_string(),
            source_name: Some("user".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["user".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
    ];
    let out = transfer_function_for_with_options_and_assignment_values(
        &decl,
        &TransferOptions::default(),
        &assignment_values,
    );
    let place_for = |node_id: NodeId| {
        let node = out.nodes.get(node_id).expect("node exists");
        out.places.get(node.place).expect("place exists")
    };
    let place_name = |place: &Place| match place {
        Place::Read { name, path } | Place::Write { name, path, .. } => {
            let mut out_name = out.names.get(*name).unwrap_or("").to_string();
            for part in path {
                out_name.push('.');
                out_name.push_str(out.names.get(*part).unwrap_or(""));
            }
            out_name
        }
        _ => String::new(),
    };

    assert!(
        !out.edges.iter().any(|edge| {
            place_name(place_for(edge.from)) == "user" && place_name(place_for(edge.to)) == "env"
        }),
        "field-precise container write must not bridge user directly into env base: {:#?}",
        out.edges
    );
    assert!(
        out.edges.iter().any(|edge| {
            place_name(place_for(edge.from)) == "user" && place_name(place_for(edge.to)) == "env.User"
        }),
        "field-precise container write should still bridge matching user field: {:#?}",
        out.edges
    );
    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from).starts_with("CallRet")
                && rendered_place_name(&out, edge.to) == "env"
        }),
        "field-expanded container literals must not bind nested helper-call returns to the whole base: {:#?}",
        out.edges
    );
    assert!(
        out.nodes.nodes.iter().all(|node| {
            let name = place_name(out.places.get(node.place).expect("place exists"));
            name != "env.Cmd.User" && name != "env.User.Cmd"
        }),
        "the owning aggregate syntax fact must not be replayed beneath sibling field writes: {:#?}",
        out.edges
    );
}

#[test]
fn qualified_field_reads_do_not_bridge_structural_base_to_scalar_target() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["env".to_string()];
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: span(20, 30),
            target: "user".to_string(),
            source_name: Some("env.User".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["env".to_string(), "env.User".to_string()],
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: span(40, 50),
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(45, 49),
                name: None,
                value_text: "user".to_string(),
                place: Some("user".to_string()),
                source_names: Vec::new(),
            }],
        },
    ];
    let out = transfer_function_for(&decl);

    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "env" && rendered_place_name(&out, edge.to) == "user"
        }),
        "a qualified field read must not make the container base flow into the scalar copy: {:#?}",
        out.edges
    );
    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "env.User" && rendered_place_name(&out, edge.to) == "user"
        }),
        "the precise field value should still flow into the scalar copy: {:#?}",
        out.edges
    );
}

#[test]
fn static_subscript_return_bridges_precise_field_read() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["env".to_string()];
    decl.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(20, 40),
        value_name: None,
        value_text: Some("env[@\"cmd\"]".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("env.@cmd"),
    }];
    let out = transfer_function_for(&decl);

    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "env.@cmd"
                && rendered_place_name(&out, edge.to) == "__bonsai_return"
                && edge.meta.kind == IdgEdgeKind::IntraReturn
        }),
        "ObjC static string subscript returns must bridge the precise field: {:#?}",
        out.edges
    );
    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "env"
                && rendered_place_name(&out, edge.to) == "__bonsai_return"
                && edge.meta.kind == IdgEdgeKind::IntraReturn
        }),
        "static field returns must not promote the whole container base into the return: {:#?}",
        out.edges
    );
}

#[test]
fn php_this_scalar_return_projection_normalizes_receiver_sigil() {
    let mut decl = empty_decl(1, "cmd");
    decl.implicit_receiver_names = vec!["$this".to_string()];
    decl.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(20, 40),
        value_name: None,
        value_text: Some("$this->data['cmd']".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("$this.data.cmd"),
    }];
    let out = transfer_function_for(&decl);

    assert_eq!(
        out.return_field_projections,
        vec![ReturnFieldProjection {
            base: "this.data".to_string(),
            field: "cmd".to_string(),
        }]
    );
    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "this.data.cmd"
                && rendered_place_name(&out, edge.to) == "__bonsai_return"
                && edge.meta.kind == IdgEdgeKind::IntraReturn
        }),
        "PHP receiver field return must bridge the precise field read into Return: {:#?}",
        out.edges
    );
    assert!(out.edges.iter().any(|edge| {
        rendered_place_name(&out, edge.from) == "__bonsai_return"
            && rendered_place_name(&out, edge.to) == "Return"
            && edge.meta.kind == IdgEdgeKind::IntraReturn
    }));
}

#[test]
fn sigiled_implicit_receiver_writes_share_the_canonical_read_place() {
    let mut decl = empty_decl(1, "capture");
    decl.params = vec!["$request".to_string()];
    decl.implicit_receiver_names = vec!["$this".to_string(), "this".to_string()];
    decl.receiver_field_writes = vec![bonsai_lang_api::FieldWrite {
        span: span(20, 40),
        target: "$this.query".to_string(),
        source_param_indices: vec![0],
    }];
    decl.flow_events = vec![FlowEvent::Assign {
        span: span(20, 40),
        target: "$this.query".to_string(),
        source_name: Some("$request".to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }];

    let out = transfer_function_for(&decl);
    let write_names = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            matches!(out.places.get(node.place), Some(Place::Write { .. }))
                .then(|| rendered_place_name(&out, NodeId(index as u32)))
        })
        .collect::<Vec<_>>();
    assert!(write_names.iter().any(|name| name == "this.query"));
    assert!(
        !write_names.iter().any(|name| name == "$this.query"),
        "implicit receiver writes must use the same canonical storage identity as reads"
    );
    assert_eq!(
        normalize_implicit_receiver_place("$request.query", &decl.implicit_receiver_names),
        "$request.query",
        "ordinary sigiled variables are not implicit receivers"
    );
}

#[test]
fn indexed_reads_keep_array_base_value_bearing() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["argv".to_string()];
    decl.flow_events = vec![FlowEvent::Assign {
        span: span(20, 40),
        target: "raw".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["argv".to_string(), "argv.1".to_string()],
        declares_new_binding: false,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
    }];
    let out = transfer_function_for(&decl);

    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "argv" && rendered_place_name(&out, edge.to) == "raw"
        }),
        "array index reads like argv[1] must keep the array base value-bearing: {:#?}",
        out.edges
    );
}

#[test]
fn keyed_getter_sources_do_not_promote_sibling_container_fields() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["item".to_string()];
    let assign_span = span(20, 80);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: assign_span,
            target: "payload".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["item".to_string(), "item.get".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: assign_span,
            target: "payload".to_string(),
            source_name: Some("item.flag".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["item.flag".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: assign_span,
            target: "payload".to_string(),
            source_name: Some("item.arg".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["item.arg".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(30, 42),
            name: "item.get".to_string(),
            receiver: Some("item".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(39, 41),
                name: None,
                value_text: "\"flag\"".to_string(),
                place: None,
                source_names: Vec::new(),
            }],
        },
    ];
    let out = transfer_function_for(&decl);

    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "item" && rendered_place_name(&out, edge.to) == "payload"
        }),
        "keyed getters select a field and must not promote sibling fields through the receiver base: {:#?}",
        out.edges
    );
    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "item.arg"
                && rendered_place_name(&out, edge.to) == "payload"
        }),
        "precise selected fields should still flow into the scalar result: {:#?}",
        out.edges
    );
}

#[test]
fn assignment_method_projection_source_bridges_receiver_carrier() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["joined".to_string(), "env".to_string()];
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: span(20, 40),
            target: "routed".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["env.Kind".to_string(), "joined.trim".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(25, 38),
            name: "joined.trim".to_string(),
            receiver: Some("joined".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        },
        FlowEvent::Assign {
            span: span(50, 70),
            target: "user".to_string(),
            source_name: Some("env.User".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["env.User".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
    ];
    let out = transfer_function_for(&decl);

    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "joined" && rendered_place_name(&out, edge.to) == "routed"
        }),
        "a compiler-proven method projection must bridge its receiver even when the same expression reads an exact field: {:#?}",
        out.edges
    );
    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "env" && rendered_place_name(&out, edge.to) == "routed"
        }),
        "the mixed expression's genuine field read must remain field-scoped: {:#?}",
        out.edges
    );
    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "env" && rendered_place_name(&out, edge.to) == "user"
        }),
        "ordinary field projections must remain field-scoped and not promote their base: {:#?}",
        out.edges
    );
}

#[test]
fn assignment_method_projection_with_call_event_bridges_receiver() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["value".to_string()];
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: span(20, 40),
            target: "upper".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["value".to_string(), "value.toUpperCase".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: span(25, 38),
            name: "value.toUpperCase".to_string(),
            receiver: Some("value".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        },
    ];
    let out = transfer_function_for(&decl);

    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "value" && rendered_place_name(&out, edge.to) == "upper"
        }),
        "adapter-classified method calls must preserve their receiver: {:#?}",
        out.edges
    );
}

#[test]
fn arbitrary_property_projection_does_not_bridge_receiver_carrier() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["client".to_string()];
    decl.flow_events = vec![FlowEvent::Assign {
        span: span(20, 40),
        target: "size".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["client.capacity".to_string(), "client".to_string()],
        declares_new_binding: false,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
    }];
    let out = transfer_function_for(&decl);

    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "client" && rendered_place_name(&out, edge.to) == "size"
        }),
        "a syntax-classified field projection must not inherit whole-receiver taint: {:#?}",
        out.edges
    );
    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "client.capacity"
                && rendered_place_name(&out, edge.to) == "size"
        }),
        "the exact projected field must remain connected to the result: {:#?}",
        out.edges
    );
}

#[test]
fn property_read_binding_is_a_complete_value_for_later_projection() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: span(20, 40),
            target: "file".to_string(),
            source_name: Some("request.files.avatar".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["request.files.avatar".to_string()],
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::PropertyRead),
        },
        FlowEvent::Assign {
            span: span(50, 70),
            target: "destination".to_string(),
            source_name: Some("file.name".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["file.name".to_string()],
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::Compound),
        },
    ];
    let out = transfer_function_for(&decl);

    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "file"
                && rendered_place_name(&out, edge.to) == "destination"
        }),
        "the complete property value assigned to `file` must feed its later exact projection: {:#?}",
        out.edges
    );
}

#[test]
fn returned_container_spread_copies_known_fields_without_root_promotion() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["user".to_string()];
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: span(20, 35),
            target: "rest.user".to_string(),
            source_name: Some("user".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["user".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Return {
            value_kind: None,
            span: span(40, 70),
            value_name: None,
            value_text: Some("{\"cmd\": clean, **rest}".to_string()),
            value_flow: bonsai_lang_api::ExpressionFlow {
                aggregate_fields: vec![bonsai_lang_api::ExpressionField {
                    name: "cmd".to_string(),
                    value_span: None,
                    value: bonsai_lang_api::ExpressionFlow::from_place("clean"),
                }],
                spreads: vec![bonsai_lang_api::ExpressionFlow::from_place("rest")],
                ..Default::default()
            },
        },
    ];
    let out = transfer_function_for(&decl);

    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "rest.user"
                && rendered_place_name(&out, edge.to) == "__bonsai_return.user"
        }),
        "known spread fields must copy field-for-field into returned containers: {:#?}",
        out.edges
    );
    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "rest"
                && rendered_place_name(&out, edge.to) == "__bonsai_return"
        }),
        "spread copies must not promote the whole spread object into the whole return: {:#?}",
        out.edges
    );
}

#[test]
fn returned_nested_object_field_preserves_exact_descendants_without_sibling_promotion() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["cmd".to_string(), "safe".to_string()];
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: span(20, 30),
            target: "payload.command".to_string(),
            source_name: Some("cmd".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["cmd".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: span(31, 40),
            target: "payload.sibling".to_string(),
            source_name: Some("safe".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["safe".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Return {
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
            span: span(45, 75),
            value_name: None,
            value_text: None,
            value_flow: bonsai_lang_api::ExpressionFlow {
                aggregate_fields: vec![bonsai_lang_api::ExpressionField {
                    name: "payload".to_string(),
                    value_span: Some(span(60, 67)),
                    value: bonsai_lang_api::ExpressionFlow::from_place("payload"),
                }],
                ..Default::default()
            },
        },
    ];
    let out = transfer_function_for(&decl);

    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "payload.command"
                && rendered_place_name(&out, edge.to) == "__bonsai_return.payload.command"
        }),
        "a nested object-valued return field must retain its exact compiler-known descendant: {:#?}",
        out.edges
    );
    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "payload.sibling"
                && rendered_place_name(&out, edge.to) == "__bonsai_return.payload.sibling"
        }),
        "each real sibling descendant must be copied independently: {:#?}",
        out.edges
    );
    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "payload.command"
                && matches!(
                    rendered_place_name(&out, edge.to).as_str(),
                    "__bonsai_return" | "__bonsai_return.payload" | "__bonsai_return.payload.sibling"
                )
        }),
        "descendant preservation must not promote or cross-contaminate the tainted field: {:#?}",
        out.edges
    );
}

#[test]
fn tuple_return_emits_position_specific_fields() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["p".to_string()];
    decl.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(20, 35),
        value_name: None,
        value_text: Some("{p, \"ok\"}".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow {
            tuple_items: vec![
                bonsai_lang_api::ExpressionFlow::from_place("p"),
                Default::default(),
            ],
            ..Default::default()
        },
    }];
    let out = transfer_function_for(&decl);

    assert!(out.edges.iter().any(|edge| {
        rendered_place_name(&out, edge.from) == "p"
            && rendered_place_name(&out, edge.to) == "__bonsai_return.0"
    }));
    assert!(!out.edges.iter().any(|edge| {
        rendered_place_name(&out, edge.from) == "p"
            && rendered_place_name(&out, edge.to) == "__bonsai_return.1"
    }));
}

#[test]
fn qualified_call_args_do_not_bridge_structural_base_to_arg_slot() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["env".to_string()];
    decl.flow_events = vec![FlowEvent::Call {
        span: span(40, 60),
        name: "sink".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(45, 57),
            name: None,
            value_text: "env.User".to_string(),
            place: Some("env.User".to_string()),
            source_names: vec!["env".to_string(), "env.User".to_string()],
        }],
    }];
    let out = transfer_function_for(&decl);

    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "env"
                && rendered_place_name(&out, edge.to).starts_with("CallArg")
        }),
        "a qualified call argument must not read the whole container base: {:#?}",
        out.edges
    );
    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "env.User"
                && rendered_place_name(&out, edge.to).starts_with("CallArg")
        }),
        "the precise field value should still feed the call arg: {:#?}",
        out.edges
    );
}

#[test]
fn call_result_whole_value_writer_feeds_a_later_projection() {
    let mut decl = empty_decl(1, "f");
    let assignment_span = span(20, 35);
    let source_call_span = span(26, 33);
    let sink_call_span = span(50, 60);
    let projected_argument_span = span(55, 59);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: assignment_span,
            target: "header".to_string(),
            source_name: None,
            source_call: Some("reader.Next".to_string()),
            source_call_args: Vec::new(),
            source_names: vec!["__bonsai_tuple_result_0".to_string()],
            declares_new_binding: true,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: source_call_span,
            name: "reader.Next".to_string(),
            receiver: Some("reader".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        },
        FlowEvent::Assign {
            span: span(45, 65),
            target: "destination".to_string(),
            source_name: None,
            source_call: Some("filepath.Join".to_string()),
            source_call_args: vec!["base".to_string(), "header.Name".to_string()],
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: sink_call_span,
            name: "filepath.Join".to_string(),
            receiver: Some("filepath".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: vec![
                CallArg {
                    passing_mode: Default::default(),
                    span: span(52, 54),
                    name: None,
                    value_text: "base".to_string(),
                    place: Some("base".to_string()),
                    source_names: vec!["base".to_string()],
                },
                CallArg {
                    passing_mode: Default::default(),
                    span: projected_argument_span,
                    name: None,
                    value_text: "header.Name".to_string(),
                    place: Some("header.Name".to_string()),
                    source_names: vec!["header".to_string(), "header.Name".to_string()],
                },
            ],
        },
    ];
    let out = transfer_function_for(&decl);

    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "header.__bonsai_tuple_result_0"
                && rendered_place_name(&out, edge.to).starts_with("CallArg")
                && edge.meta.via_span == projected_argument_span
        }),
        "a field read from a whole call result must depend on the returned object: {:#?}",
        out.edges
    );
}

#[test]
fn whole_value_selection_alias_feeds_a_later_projection() {
    let mut decl = empty_decl(1, "handler");
    let assignment_span = span(20, 40);
    let sink_call_span = span(50, 70);
    let projected_argument_span = span(55, 67);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: assignment_span,
            target: "body".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["request".to_string(), "request.payload".to_string()],
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::WholeValueSelection),
        },
        FlowEvent::Call {
            span: sink_call_span,
            name: "consume".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: projected_argument_span,
                name: None,
                value_text: "body.command".to_string(),
                place: Some("body.command".to_string()),
                source_names: vec!["body".to_string(), "body.command".to_string()],
            }],
        },
    ];
    let out = transfer_function_for(&decl);

    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "body"
                && rendered_write_span(&out, edge.from) == Some(assignment_span)
                && rendered_place_name(&out, edge.to).starts_with("CallArg")
                && edge.meta.via_span == projected_argument_span
        }),
        "a projection of a complete selected value must depend on its exact root writer: {:#?}",
        out.edges
    );
}

#[test]
fn exact_projected_clean_overwrite_wins_over_whole_value_selection_alias() {
    let mut decl = empty_decl(1, "handler");
    let assignment_span = span(20, 40);
    let overwrite_span = span(41, 49);
    let sink_call_span = span(50, 70);
    let projected_argument_span = span(55, 67);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: assignment_span,
            target: "body".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["request".to_string(), "request.payload".to_string()],
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::WholeValueSelection),
        },
        FlowEvent::Assign {
            span: overwrite_span,
            target: "body.command".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(AssignValueKind::Literal),
        },
        FlowEvent::Call {
            span: sink_call_span,
            name: "consume".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: projected_argument_span,
                name: None,
                value_text: "body.command".to_string(),
                place: Some("body.command".to_string()),
                source_names: vec!["body".to_string(), "body.command".to_string()],
            }],
        },
    ];
    let out = transfer_function_for(&decl);

    assert!(
        out.edges.iter().all(|edge| {
            rendered_place_name(&out, edge.from) != "body"
                || rendered_write_span(&out, edge.from) != Some(assignment_span)
                || !rendered_place_name(&out, edge.to).starts_with("CallArg")
        }),
        "a later exact field overwrite must cut the earlier whole-value alias: {:#?}",
        out.edges
    );
    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "body.command"
                && rendered_write_span(&out, edge.from) == Some(overwrite_span)
                && rendered_place_name(&out, edge.to).starts_with("CallArg")
        }),
        "the projected sink read must bind only to the latest exact clean field writer: {:#?}",
        out.edges
    );
}

#[test]
fn exact_projection_overwrite_wins_over_whole_call_result() {
    let mut decl = empty_decl(1, "f");
    let assignment_span = span(20, 35);
    let source_call_span = span(26, 33);
    let overwrite_span = span(36, 45);
    let sink_call_span = span(50, 60);
    let projected_argument_span = span(55, 59);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: assignment_span,
            target: "header".to_string(),
            source_name: None,
            source_call: Some("reader.Next".to_string()),
            source_call_args: Vec::new(),
            source_names: vec!["__bonsai_tuple_result_0".to_string()],
            declares_new_binding: true,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: source_call_span,
            name: "reader.Next".to_string(),
            receiver: Some("reader".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        },
        FlowEvent::Assign {
            span: overwrite_span,
            target: "header.Name".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Literal),
        },
        FlowEvent::Call {
            span: sink_call_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: projected_argument_span,
                name: None,
                value_text: "header.Name".to_string(),
                place: Some("header.Name".to_string()),
                source_names: vec!["header".to_string(), "header.Name".to_string()],
            }],
        },
    ];
    let out = transfer_function_for(&decl);

    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "header.Name"
                && rendered_write_span(&out, edge.from) == Some(overwrite_span)
                && rendered_place_name(&out, edge.to).starts_with("CallArg")
                && edge.meta.via_span == projected_argument_span
        }),
        "the exact field overwrite must feed the projected read: {:#?}",
        out.edges
    );
    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "header.__bonsai_tuple_result_0"
                && rendered_place_name(&out, edge.to).starts_with("CallArg")
                && edge.meta.via_span == projected_argument_span
        }),
        "a clean exact field overwrite must block the earlier whole-result writer: {:#?}",
        out.edges
    );
}

#[test]
fn whole_container_call_arg_consumes_current_field_writers() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["input".to_string()];
    let field_span = span(20, 30);
    let call_span = span(40, 55);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: field_span,
            target: "opts.to".to_string(),
            source_name: Some("input".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["input".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: call_span,
            name: "send".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(45, 49),
                name: None,
                value_text: "opts".to_string(),
                place: Some("opts".to_string()),
                source_names: vec!["opts".to_string()],
            }],
        },
    ];
    let out = transfer_function_for(&decl);

    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "opts.to"
                && rendered_place_name(&out, edge.to).starts_with("CallArg")
                && edge.meta.kind == IdgEdgeKind::IntraAggregateConsume
        }),
        "passing a whole aggregate must consume its AST-known field values: {:#?}",
        out.edges
    );
}

#[test]
fn projected_call_arg_does_not_consume_sibling_field_writers() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["input".to_string()];
    let call_span = span(40, 60);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: span(20, 30),
            target: "$obj['value']".to_string(),
            source_name: Some("input".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["input".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: call_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(45, 58),
                name: None,
                value_text: "$obj['other']".to_string(),
                place: Some("$obj['other']".to_string()),
                source_names: vec!["$obj".to_string(), "$obj['other']".to_string()],
            }],
        },
    ];
    let out = transfer_function_for(&decl);

    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "$obj['value']"
                && rendered_place_name(&out, edge.to).starts_with("CallArg")
        }),
        "reading one projected field must not consume a sibling: {:#?}",
        out.edges
    );
}

#[test]
fn whole_container_overwrite_kills_prior_field_writers() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["input".to_string()];
    let field_span = span(20, 30);
    let clean_span = span(31, 39);
    let call_span = span(40, 55);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: field_span,
            target: "opts.to".to_string(),
            source_name: Some("input".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["input".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: clean_span,
            target: "opts".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Literal),
        },
        FlowEvent::Call {
            span: call_span,
            name: "send".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(45, 49),
                name: None,
                value_text: "opts".to_string(),
                place: Some("opts".to_string()),
                source_names: vec!["opts".to_string()],
            }],
        },
    ];
    let out = transfer_function_for(&decl);

    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "opts.to"
                && rendered_place_name(&out, edge.to).starts_with("CallArg")
        }),
        "a whole-container overwrite must kill older descendant values: {:#?}",
        out.edges
    );
}

#[test]
fn indexed_call_element_write_does_not_overwrite_whole_buffer() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["value".to_string()];
    let copy_span = span(20, 30);
    let terminator_span = span(31, 45);
    let sink_span = span(50, 60);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: copy_span,
            target: "buf".to_string(),
            source_name: Some("value".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["value".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        },
        FlowEvent::Assign {
            span: terminator_span,
            target: "buf".to_string(),
            source_name: None,
            source_call: Some("strcspn".to_string()),
            source_call_args: vec!["buf".to_string(), "\"\\n\"".to_string()],
            source_names: vec!["buf".to_string(), "buf.strcspn(buf, \\n)".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Assign {
            span: terminator_span,
            target: "buf.strcspn(buf".to_string(),
            source_name: None,
            source_call: Some("strcspn".to_string()),
            source_call_args: vec!["buf".to_string(), "\"\\n\"".to_string()],
            source_names: vec!["buf".to_string(), "buf.strcspn(buf, \\n)".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: sink_span,
            name: "execute".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: sink_span,
                name: None,
                value_text: "buf".to_string(),
                place: Some("buf".to_string()),
                source_names: vec!["buf".to_string()],
            }],
        },
    ];
    let out = transfer_function_for(&decl);

    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "buf"
                && rendered_write_span(&out, edge.from) == Some(copy_span)
                && rendered_place_name(&out, edge.to).starts_with("CallArg")
                && edge.meta.kind == IdgEdgeKind::IntraRead
        }),
        "indexed call-derived element writes must preserve the whole-buffer writer: {:#?}",
        out.edges
    );
    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "buf"
                && rendered_write_span(&out, edge.from) == Some(terminator_span)
                && rendered_place_name(&out, edge.to).starts_with("CallArg")
        }),
        "the synthetic base target from `buf[strcspn(buf, ...)] = 0` must not become the live buffer writer: {:#?}",
        out.edges
    );
}

#[test]
fn assign_call_rhs_records_call_site_and_emits_arg_and_ret_edges() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Assign {
        span: span(50, 70),
        target: "y".to_string(),
        source_name: None,
        source_call: Some("transform".to_string()),
        source_call_args: vec!["x".to_string()],
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }];
    let out = transfer_function_for(&decl);
    // Read(x) → CallArg(site, 0)
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraRead), 1);
    // CallRet(site) → Write(y).
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 1);
    assert_eq!(out.call_sites.len(), 1);
    assert_eq!(out.call_sites[0].callee_name, "transform");
    assert_eq!(out.call_sites[0].args_count, 1);
}

#[test]
fn configured_call_result_passthrough_is_materialized_for_assign_rhs() {
    let mut decl = empty_decl(1, "f");
    let call_span = span(50, 70);
    decl.flow_events = vec![FlowEvent::Assign {
        span: call_span,
        target: "decoded".to_string(),
        source_name: None,
        source_call: Some("project.decode".to_string()),
        source_call_args: vec!["input".to_string()],
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
    }];
    let options = TransferOptions {
        call_result_passthroughs: vec![CallResultPassthroughSpec {
            callee: "project.decode".to_string(),
            receiver_type: None,
            input_arg_indices: vec![0],
            input_arg_start_index: None,
            input_receiver: false,
            resolved_call_sites: Vec::new(),
        }],
        ..TransferOptions::default()
    };
    let out = transfer_function_for_with_options(&decl, &options);
    let place_for = |node_id: NodeId| {
        let node = out.nodes.get(node_id).expect("node exists");
        out.places.get(node.place).expect("place exists")
    };

    assert!(out.edges.iter().any(|edge| {
        matches!(place_for(edge.from), Place::CallArg { site, idx } if site.0 == call_span && *idx == 0)
            && matches!(place_for(edge.to), Place::CallRet { site } if site.0 == call_span)
            && edge.meta.precision == Precision::Narrowed
    }));
}

#[test]
fn configured_call_result_passthrough_is_materialized_for_call_event() {
    let mut decl = empty_decl(1, "f");
    let call_span = span(50, 70);
    decl.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "decode".to_string(),
        receiver: Some("codec".to_string()),
        receiver_types: vec!["ProjectCodec".to_string()],
        call_kind: CallKind::Method,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(58, 63),
            name: None,
            value_text: "input".to_string(),
            place: Some("input".to_string()),
            source_names: vec!["input".to_string()],
        }],
    }];
    let options = TransferOptions {
        call_result_passthroughs: vec![CallResultPassthroughSpec {
            callee: "decode".to_string(),
            receiver_type: Some("ProjectCodec".to_string()),
            input_arg_indices: vec![0],
            input_arg_start_index: None,
            input_receiver: true,
            resolved_call_sites: Vec::new(),
        }],
        ..TransferOptions::default()
    };
    let out = transfer_function_for_with_options(&decl, &options);
    let call_site = out.call_sites.first().expect("call site");
    let incoming = out
        .edges
        .iter()
        .filter(|edge| edge.to == call_site.call_ret_node)
        .map(|edge| edge.from)
        .collect::<ahash::AHashSet<_>>();

    assert!(incoming.contains(&call_site.call_arg_nodes[0]));
    assert!(incoming.contains(&call_site.receiver_arg_node.expect("receiver node")));
}

#[test]
fn variadic_call_result_passthrough_uses_actual_arity_without_a_cap() {
    let mut decl = empty_decl(1, "f");
    let call_span = span(50, 100);
    let args = (0..12)
        .map(|index| CallArg {
            passing_mode: Default::default(),
            span: span(60 + index, 61 + index),
            name: None,
            value_text: format!("value{index}"),
            place: Some(format!("value{index}")),
            source_names: vec![format!("value{index}")],
        })
        .collect::<Vec<_>>();
    decl.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "collect".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args,
    }];
    let options = TransferOptions {
        call_result_passthroughs: vec![CallResultPassthroughSpec {
            callee: "collect".to_string(),
            receiver_type: None,
            input_arg_indices: Vec::new(),
            input_arg_start_index: Some(1),
            input_receiver: false,
            resolved_call_sites: Vec::new(),
        }],
        ..TransferOptions::default()
    };
    let out = transfer_function_for_with_options(&decl, &options);
    let call_site = out.call_sites.first().expect("call site");
    let incoming = out
        .edges
        .iter()
        .filter(|edge| edge.to == call_site.call_ret_node)
        .map(|edge| edge.from)
        .collect::<ahash::AHashSet<_>>();

    assert!(!incoming.contains(&call_site.call_arg_nodes[0]));
    for node in &call_site.call_arg_nodes[1..] {
        assert!(incoming.contains(node), "every actual tail argument must flow");
    }
}

#[test]
fn matcher_compiled_call_result_passthrough_applies_only_at_approved_span() {
    let mut decl = empty_decl(1, "f");
    let approved = span(20, 30);
    let unrelated = span(40, 50);
    let call = |span, value: &str| FlowEvent::Call {
        span,
        name: "decode".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span,
            name: None,
            value_text: value.to_string(),
            place: Some(value.to_string()),
            source_names: vec![value.to_string()],
        }],
    };
    decl.flow_events = vec![call(approved, "external"), call(unrelated, "local")];
    let options = TransferOptions {
        call_result_passthroughs: vec![CallResultPassthroughSpec {
            callee: "decode".to_string(),
            receiver_type: None,
            input_arg_indices: vec![0],
            input_arg_start_index: None,
            input_receiver: false,
            resolved_call_sites: vec![approved],
        }],
        ..TransferOptions::default()
    };
    let out = transfer_function_for_with_options(&decl, &options);
    let has_passthrough = |target_span| {
        let site = out
            .call_sites
            .iter()
            .find(|site| site.site.0 == target_span)
            .expect("call site");
        out.edges
            .iter()
            .any(|edge| edge.from == site.call_arg_nodes[0] && edge.to == site.call_ret_node)
    };

    assert!(has_passthrough(approved));
    assert!(!has_passthrough(unrelated));
}

#[test]
fn self_receiver_call_result_reads_the_pre_assignment_value() {
    let mut decl = empty_decl(1, "f");
    let initial_span = span(20, 30);
    let assign_span = span(40, 70);
    let call_span = span(50, 60);
    decl.params = vec!["input".to_string()];
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: initial_span,
            target: "value".to_string(),
            source_name: Some("input".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["input".to_string()],
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::Compound),
        },
        // Adapter walkers emit the enclosing assignment before its nested
        // call event. Source-language evaluation still reads `value` before
        // committing the replacement write.
        FlowEvent::Assign {
            span: assign_span,
            target: "value".to_string(),
            source_name: None,
            source_call: Some("value.transform".to_string()),
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: call_span,
            name: "value.transform".to_string(),
            receiver: Some("value".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        },
    ];
    let options = TransferOptions {
        call_result_passthroughs: vec![CallResultPassthroughSpec {
            callee: "value.transform".to_string(),
            receiver_type: None,
            input_arg_indices: Vec::new(),
            input_arg_start_index: None,
            input_receiver: true,
            resolved_call_sites: Vec::new(),
        }],
        ..TransferOptions::default()
    };
    let out = transfer_function_for_with_options(&decl, &options);
    let site = out
        .call_sites
        .iter()
        .find(|site| site.site == CallSiteId(call_span))
        .expect("method call site");
    let receiver = site.receiver_arg_node.expect("method receiver node");

    assert!(out.edges.iter().any(|edge| {
        edge.to == receiver
            && rendered_place_name(&out, edge.from) == "value"
            && rendered_write_span(&out, edge.from) == Some(initial_span)
    }));
    assert!(
        !out.edges.iter().any(|edge| {
            edge.to == receiver
                && rendered_place_name(&out, edge.from) == "value"
                && rendered_write_span(&out, edge.from) == Some(assign_span)
        }),
        "the result write cannot feed the receiver that produced it: {:#?}",
        out.edges
    );
    assert!(out.edges.iter().any(|edge| {
        edge.from == site.call_ret_node
            && rendered_place_name(&out, edge.to) == "value"
            && rendered_write_span(&out, edge.to) == Some(assign_span)
    }));
}

#[test]
fn compiled_transfer_matchers_preserve_exact_tail_regex_order_and_invalid_regex_behavior() {
    let index = ConfiguredNameIndex::new([
        "decode",
        "project.codec.decode",
        r"regex:(?:^|\.)decode$",
        "regex:[",
        "other",
    ]);
    let observed = ObservedCallee::new("project.codec.decode");

    assert_eq!(index.matching_indices(&observed).as_slice(), &[0, 1, 2]);
}

#[test]
fn decode_call_result_is_not_hardcoded_passthrough_by_default() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["input".to_string()];
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: span(50, 80),
            target: "decoded".to_string(),
            source_name: None,
            source_call: Some("java.net.URLDecoder.decode".to_string()),
            source_call_args: vec!["input".to_string(), "\"UTF-8\"".to_string()],
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
        FlowEvent::Assign {
            span: span(90, 120),
            target: "other".to_string(),
            source_name: None,
            source_call: Some("codec.decode".to_string()),
            source_call_args: vec!["input".to_string()],
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        },
    ];
    let out = transfer_function_for(&decl);

    let url_decoder_preserved = out.edges.iter().any(|edge| {
        rendered_place_name(&out, edge.from) == "input"
            && rendered_place_name(&out, edge.to) == "decoded"
            && edge.meta.kind == IdgEdgeKind::IntraAssign
    });
    assert!(
        !url_decoder_preserved,
        "library decode passthrough belongs in rulepack semantics, not the IDG core: {:#?}",
        out.edges
    );

    let generic_decode_preserved = out.edges.iter().any(|edge| {
        rendered_place_name(&out, edge.from) == "input"
            && rendered_place_name(&out, edge.to) == "other"
            && edge.meta.kind == IdgEdgeKind::IntraAssign
    });
    assert!(
        !generic_decode_preserved,
        "unknown decode methods must not become generic CallArg->CallRet passthroughs: {:#?}",
        out.edges
    );
}

#[test]
fn qualified_uppercase_library_call_result_is_not_constructor_passthrough() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["cmd".to_string()];
    decl.flow_events = vec![FlowEvent::Assign {
        span: span(50, 80),
        target: "part".to_string(),
        source_name: None,
        source_call: Some("strings.Fields".to_string()),
        source_call_args: vec!["cmd".to_string()],
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
    }];
    let out = transfer_function_for(&decl);

    let arg_inherits_return = out.edges.iter().any(|edge| {
        rendered_place_name(&out, edge.from) == "cmd"
            && rendered_place_name(&out, edge.to) == "part"
            && edge.meta.kind == IdgEdgeKind::IntraAssign
    });
    assert!(
        !arg_inherits_return,
        "qualified exported library functions must not become constructor-style passthroughs: {:#?}",
        out.edges
    );
}

#[test]
fn assign_call_rhs_binds_syntax_classified_method_return() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["cmd".to_string()];
    let assign_span = span(50, 90);
    let call_span = span(55, 85);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: assign_span,
            target: "joined".to_string(),
            source_name: None,
            source_call: Some("cmd .split_whitespace() .map(|s| s.trim()) .fold".to_string()),
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: call_span,
            name: "cmd .split_whitespace() .map(|s| s.trim()) .fold".to_string(),
            receiver: Some("cmd".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        },
    ];
    let out = transfer_function_for(&decl);
    let place_for = |node_id: NodeId| {
        let node = out.nodes.get(node_id).expect("node exists");
        out.places.get(node.place).expect("place exists")
    };
    assert!(
        out.edges.iter().any(|edge| {
            let from = place_for(edge.from);
            let to = place_for(edge.to);
            matches!(from, Place::CallRet { site } if site.0 == call_span)
                && matches!(to, Place::Write { span, .. } if *span == assign_span)
        }),
        "the assignment must bind the AST call's result node: {:#?}",
        out.edges
    );
}

#[test]
fn assign_call_rhs_does_not_bridge_module_qualified_call_head() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["store".to_string()];
    decl.flow_events = vec![FlowEvent::Assign {
        span: span(50, 90),
        target: "out".to_string(),
        source_name: None,
        source_call: Some("store::persist".to_string()),
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }];
    let out = transfer_function_for(&decl);

    assert_eq!(
        count_edges_of(&out, IdgEdgeKind::IntraAssign),
        2,
        "module-qualified call heads are not value receivers; expected only param seed + CallRet binding"
    );
}

#[test]
fn assign_call_rhs_uses_sibling_call_span_for_return_binding() {
    let mut decl = empty_decl(1, "f");
    let assign_span = span(50, 70);
    let call_span = span(55, 64);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: assign_span,
            target: "y".to_string(),
            source_name: None,
            source_call: Some("transform".to_string()),
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: call_span,
            name: "transform".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: Vec::new(),
        },
    ];
    let out = transfer_function_for(&decl);

    // The sibling Call event already records the semantic call
    // site for Phase 3. The Assign should bind that same
    // CallRet to the target write, not create an assignment-span
    // CallRet that the resolved callgraph never stitches.
    assert_eq!(out.call_sites.len(), 1);
    assert_eq!(out.call_sites[0].site, CallSiteId(call_span));
    assert!(out.call_sites[0].is_assign_rhs);

    let place_for = |node_id: NodeId| {
        let node = out.nodes.get(node_id).expect("node exists");
        out.places.get(node.place).expect("place exists")
    };
    assert!(
        out.edges.iter().any(|edge| {
            matches!(place_for(edge.from), Place::CallRet { site } if site.0 == call_span)
                && matches!(place_for(edge.to), Place::Write { span, .. } if *span == assign_span)
        }),
        "expected CallRet(call span) -> Write(assign target) edge: {:#?}",
        out.edges
    );
    assert!(
        !out.edges
            .iter()
            .any(|edge| { matches!(place_for(edge.from), Place::CallRet { site } if site.0 == assign_span) }),
        "assignment span must not become a second call-return identity: {:#?}",
        out.edges
    );
}

#[test]
fn compound_assignment_binds_ast_indexed_rhs_call_result() {
    let mut decl = empty_decl(1, "f");
    let assign_span = span(50, 90);
    let call_name_span = span(58, 66);
    let call_expression_span = span(58, 82);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: assign_span,
            target: "raw".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(AssignValueKind::Compound),
        },
        FlowEvent::Call {
            span: call_name_span,
            name: "readline".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: Vec::new(),
        },
    ];
    let facts = [AssignmentValueFact {
        assignment_span: assign_span,
        target: Some("buf".to_string()),
        target_is_immutable: false,
        target_owner: None,
        target_span: Some(span(50, 53)),
        value_span: span(55, 88),
        call_sites: vec![call_expression_span],
        value_flow: ExpressionFlow::default(),
        static_value: None,
        exact_callable_return: None,
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        exact_static_call_args: None,
        direct_call_name: None,
        direct_call_span: None,
        direct_call_receiver: None,
        direct_call_receiver_span: None,
        direct_call_receiver_flow: None,
    }];
    let out =
        transfer_function_for_with_options_and_assignment_values(&decl, &TransferOptions::default(), &facts);
    let place_for = |node_id: NodeId| {
        let node = out.nodes.get(node_id).expect("node exists");
        out.places.get(node.place).expect("place exists")
    };
    assert!(
        out.edges.iter().any(|edge| {
            matches!(place_for(edge.from), Place::CallRet { site } if site.0 == call_name_span)
                && matches!(place_for(edge.to), Place::Write { span, .. } if *span == assign_span)
        }),
        "expected AST-indexed CallRet -> assignment Write edge: {:#?}",
        out.edges
    );
    assert!(out.call_sites[0].is_assign_rhs);
}

#[test]
fn finite_literal_selection_keeps_lookup_call_but_cleans_result_write() {
    let mut decl = empty_decl(1, "select");
    decl.params = vec!["key".to_string()];
    let assign_span = span(30, 70);
    let selection_span = span(39, 61);
    decl.flow_events = vec![FlowEvent::Assign {
        span: assign_span,
        target: "column".to_string(),
        source_name: Some("key".to_string()),
        source_call: Some("SORTABLE.get".to_string()),
        source_call_args: vec!["key".to_string()],
        source_names: vec!["key".to_string()],
        declares_new_binding: true,
        value_kind: Some(AssignValueKind::CallResult),
    }];
    let assignment_values = [AssignmentValueFact {
        assignment_span: assign_span,
        target: Some("column".to_string()),
        target_is_immutable: false,
        target_owner: None,
        target_span: Some(span(30, 36)),
        value_span: span(39, 68),
        call_sites: vec![selection_span],
        value_flow: ExpressionFlow::from_place("key"),
        static_value: None,
        exact_callable_return: None,
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        exact_static_call_args: None,
        direct_call_name: Some("get".to_string()),
        direct_call_span: None,
        direct_call_receiver: Some("SORTABLE".to_string()),
        direct_call_receiver_span: None,
        direct_call_receiver_flow: None,
    }];
    let selections = [FiniteLiteralSelectionFact {
        selection_span,
        assignment_span: Some(assign_span),
        target: Some("column".to_string()),
        call_span: None,
        argument_index: None,
    }];

    let out = transfer_function_for_with_options_and_compiler_facts(
        &decl,
        &TransferOptions::default(),
        &assignment_values,
        &[],
        &[],
        &selections,
    );
    let result_write = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::Write { span, .. }) if *span == assign_span
            )
            .then_some(NodeId(u32::try_from(index).expect("node id")))
        })
        .expect("selection result write");

    assert!(
        out.edges.iter().all(|edge| edge.to != result_write),
        "the dynamic lookup key/call result must not flow into the finite literal result: {:#?}",
        out.edges
    );
    assert_eq!(
        out.call_sites.len(),
        1,
        "lookup remains visible to callgraph/export"
    );
    assert!(
        out.edges.iter().any(|edge| {
            matches!(
                out.places.get(out.nodes.get(edge.to).expect("node").place),
                Some(Place::CallArg { idx: 0, .. })
            ) && rendered_place_name(&out, edge.from) == "key"
        }),
        "the lookup operation must still consume its dynamic key"
    );
}

#[test]
fn finite_literal_selection_used_inline_does_not_taint_the_sink_argument() {
    let mut decl = empty_decl(1, "execute");
    decl.params = vec!["key".to_string()];
    let call_span = span(30, 70);
    let selection_span = span(40, 56);
    decl.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "run".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            span: span(38, 62),
            passing_mode: Default::default(),
            name: None,
            value_text: "COMMANDS[key] ?? ['uptime']".to_string(),
            place: None,
            source_names: vec!["COMMANDS".to_string(), "key".to_string()],
        }],
    }];
    let selections = [FiniteLiteralSelectionFact {
        selection_span,
        assignment_span: None,
        target: None,
        call_span: Some(call_span),
        argument_index: Some(0),
    }];

    let out = transfer_function_for_with_options_and_compiler_facts(
        &decl,
        &TransferOptions::default(),
        &[],
        &[],
        &[],
        &selections,
    );
    let call_arg = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx: 0 }) if site.0 == call_span
            )
            .then_some(NodeId(u32::try_from(index).expect("node id")))
        })
        .expect("sink argument node");

    assert!(
        out.edges.iter().all(|edge| edge.to != call_arg),
        "the dynamic selector controls a finite literal choice but must not flow into the sink argument: {:#?}",
        out.edges
    );
}

#[test]
fn direct_call_argument_is_mediated_by_the_nested_call_return() {
    let mut decl = empty_decl(1, "review");
    decl.params = vec!["input".to_string()];
    let outer_span = span(20, 27);
    let inner_span = span(32, 41);
    let argument_span = span(32, 49);
    decl.flow_events = vec![
        FlowEvent::Call {
            span: outer_span,
            name: "consume".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                span: argument_span,
                passing_mode: Default::default(),
                name: None,
                value_text: "transform(input)".to_string(),
                place: None,
                source_names: vec!["input".to_string()],
            }],
        },
        FlowEvent::Call {
            span: inner_span,
            name: "transform".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                span: span(42, 47),
                passing_mode: Default::default(),
                name: None,
                value_text: "input".to_string(),
                place: Some("input".to_string()),
                source_names: vec!["input".to_string()],
            }],
        },
    ];
    let argument_values = [CallArgumentValueFact {
        call_span: outer_span,
        argument_index: 0,
        argument_span,
        direct_call_span: Some(inner_span),
        value_kind: Some(AssignValueKind::CallResult),
        inline_callback_params: Vec::new(),
        inline_callback_span: None,
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        value_flow: ExpressionFlow {
            source_names: vec!["input".to_string()],
            call_sites: vec![inner_span],
            ..Default::default()
        },
        static_value: None,
        exact_static_aggregate_fields: Vec::new(),
        exact_static_sequence_values: None,
    }];

    let out = transfer_function_for_with_options_and_compiler_facts(
        &decl,
        &TransferOptions::default(),
        &[],
        &[],
        &argument_values,
        &[],
    );
    let outer_argument = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx: 0 }) if site.0 == outer_span
            )
            .then_some(NodeId(u32::try_from(index).expect("node id")))
        })
        .expect("outer argument");

    assert!(out.edges.iter().any(|edge| {
        edge.to == outer_argument
            && matches!(
                out.places
                    .get(out.nodes.get(edge.from).expect("node").place),
                Some(Place::CallRet { site }) if site.0 == inner_span
            )
            && edge.meta.kind == IdgEdgeKind::IntraAssign
            && edge.meta.precision == Precision::Exact
    }));
    assert!(
        out.edges
            .iter()
            .filter(|edge| edge.to == outer_argument)
            .all(|edge| rendered_place_name(&out, edge.from) != "input"),
        "the nested callee's operand must not bypass its return contract: {:#?}",
        out.edges
    );
}

#[test]
fn adapter_proven_static_projection_bypasses_only_the_builtin_call_spelling() {
    let mut decl = empty_decl(1, "review");
    decl.params = vec!["record".to_string()];
    let outer_span = span(20, 27);
    let inner_span = span(32, 41);
    let argument_span = span(32, 49);
    decl.flow_events = vec![
        FlowEvent::Call {
            span: outer_span,
            name: "consume".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                span: argument_span,
                passing_mode: Default::default(),
                name: None,
                value_text: "record.item".to_string(),
                place: Some("record.item".to_string()),
                source_names: vec!["record".to_string(), "record.item".to_string()],
            }],
        },
        FlowEvent::Call {
            span: inner_span,
            name: "builtin_select".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                span: span(42, 47),
                passing_mode: Default::default(),
                name: None,
                value_text: "record".to_string(),
                place: Some("record".to_string()),
                source_names: vec!["record".to_string()],
            }],
        },
    ];
    let argument_values = [CallArgumentValueFact {
        call_span: outer_span,
        argument_index: 0,
        argument_span,
        direct_call_span: Some(inner_span),
        value_kind: Some(AssignValueKind::CallResult),
        inline_callback_params: Vec::new(),
        inline_callback_span: None,
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        value_flow: ExpressionFlow::from_place("record.item"),
        static_value: None,
        exact_static_aggregate_fields: Vec::new(),
        exact_static_sequence_values: None,
    }];

    let out = transfer_function_for_with_options_and_compiler_facts(
        &decl,
        &TransferOptions::default(),
        &[],
        &[],
        &argument_values,
        &[],
    );
    let outer_argument = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx: 0 }) if site.0 == outer_span
            )
            .then_some(NodeId(u32::try_from(index).expect("node id")))
        })
        .expect("outer argument");
    let incoming = out
        .edges
        .iter()
        .filter(|edge| edge.to == outer_argument)
        .collect::<Vec<_>>();

    assert!(
        incoming
            .iter()
            .any(|edge| rendered_place_name(&out, edge.from) == "record.item"),
        "the adapter-proven exact projection must feed the argument: {incoming:#?}"
    );
    assert!(
        incoming.iter().all(|edge| {
            !matches!(
                out.places.get(out.nodes.get(edge.from).expect("node").place),
                Some(Place::CallRet { site }) if site.0 == inner_span
            )
        }),
        "a compiler-proven static projection must not depend on an unresolved builtin return: {incoming:#?}"
    );
}

#[test]
fn method_shaped_projection_still_requires_the_nested_call_return() {
    let mut decl = empty_decl(1, "review");
    decl.params = vec!["record".to_string()];
    let outer_span = span(20, 27);
    let inner_span = span(32, 41);
    let argument_span = span(32, 49);
    decl.flow_events = vec![
        FlowEvent::Call {
            span: outer_span,
            name: "consume".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                span: argument_span,
                passing_mode: Default::default(),
                name: None,
                value_text: "record.transform".to_string(),
                place: Some("record.transform".to_string()),
                source_names: vec!["record.transform".to_string()],
            }],
        },
        FlowEvent::Call {
            span: inner_span,
            name: "record.transform".to_string(),
            receiver: Some("record".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        },
    ];
    let argument_values = [CallArgumentValueFact {
        call_span: outer_span,
        argument_index: 0,
        argument_span,
        direct_call_span: Some(inner_span),
        value_kind: Some(AssignValueKind::CallResult),
        inline_callback_params: Vec::new(),
        inline_callback_span: None,
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        value_flow: ExpressionFlow::from_place("record.transform"),
        static_value: None,
        exact_static_aggregate_fields: Vec::new(),
        exact_static_sequence_values: None,
    }];

    let out = transfer_function_for_with_options_and_compiler_facts(
        &decl,
        &TransferOptions::default(),
        &[],
        &[],
        &argument_values,
        &[],
    );
    let outer_argument = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx: 0 }) if site.0 == outer_span
            )
            .then_some(NodeId(u32::try_from(index).expect("node id")))
        })
        .expect("outer argument");

    assert!(out.edges.iter().any(|edge| {
        edge.to == outer_argument
            && matches!(
                out.places.get(out.nodes.get(edge.from).expect("node").place),
                Some(Place::CallRet { site }) if site.0 == inner_span
            )
    }));
    assert!(
        out.edges
            .iter()
            .filter(|edge| edge.to == outer_argument)
            .all(|edge| rendered_place_name(&out, edge.from) != "record.transform"),
        "method-shaped values must not bypass their return contract: {:#?}",
        out.edges
    );
}

#[test]
fn compound_nested_call_argument_retains_all_compiler_operands() {
    let mut decl = empty_decl(1, "review");
    decl.params = vec!["prefix".to_string(), "input".to_string()];
    let outer_span = span(20, 27);
    let inner_span = span(38, 47);
    let argument_span = span(32, 55);
    decl.flow_events = vec![FlowEvent::Call {
        span: outer_span,
        name: "consume".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            span: argument_span,
            passing_mode: Default::default(),
            name: None,
            value_text: "prefix + transform(input)".to_string(),
            place: None,
            source_names: vec!["prefix".to_string(), "input".to_string()],
        }],
    }];
    let argument_values = [CallArgumentValueFact {
        call_span: outer_span,
        argument_index: 0,
        argument_span,
        direct_call_span: None,
        value_kind: Some(AssignValueKind::Compound),
        inline_callback_params: Vec::new(),
        inline_callback_span: None,
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        value_flow: ExpressionFlow {
            source_names: vec!["prefix".to_string(), "input".to_string()],
            call_sites: vec![inner_span],
            ..Default::default()
        },
        static_value: None,
        exact_static_aggregate_fields: Vec::new(),
        exact_static_sequence_values: None,
    }];

    let out = transfer_function_for_with_options_and_compiler_facts(
        &decl,
        &TransferOptions::default(),
        &[],
        &[],
        &argument_values,
        &[],
    );
    let outer_argument = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx: 0 }) if site.0 == outer_span
            )
            .then_some(NodeId(u32::try_from(index).expect("node id")))
        })
        .expect("outer argument");
    let incoming: std::collections::BTreeSet<_> = out
        .edges
        .iter()
        .filter(|edge| edge.to == outer_argument)
        .map(|edge| rendered_place_name(&out, edge.from))
        .collect();

    assert!(incoming.contains("prefix"), "compound operand lost: {incoming:?}");
    assert!(incoming.contains("input"), "compound operand lost: {incoming:?}");
    assert!(
        !incoming.iter().any(|place| place.starts_with("CallRet(")),
        "a nested call inside a compound value is not the complete argument: {incoming:?}"
    );
}

#[test]
fn multiple_nested_calls_without_an_exact_direct_call_fail_closed() {
    let mut decl = empty_decl(1, "review");
    decl.params = vec!["left".to_string(), "right".to_string()];
    let outer_span = span(20, 27);
    let left_call = span(32, 37);
    let right_call = span(48, 54);
    let argument_span = span(32, 62);
    decl.flow_events = vec![FlowEvent::Call {
        span: outer_span,
        name: "consume".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            span: argument_span,
            passing_mode: Default::default(),
            name: None,
            value_text: "first(left) + second(right)".to_string(),
            place: None,
            source_names: vec!["left".to_string(), "right".to_string()],
        }],
    }];
    let argument_values = [CallArgumentValueFact {
        call_span: outer_span,
        argument_index: 0,
        argument_span,
        direct_call_span: None,
        value_kind: Some(AssignValueKind::Compound),
        inline_callback_params: Vec::new(),
        inline_callback_span: None,
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        value_flow: ExpressionFlow {
            source_names: vec!["left".to_string(), "right".to_string()],
            call_sites: vec![left_call, right_call],
            ..Default::default()
        },
        static_value: None,
        exact_static_aggregate_fields: Vec::new(),
        exact_static_sequence_values: None,
    }];

    let out = transfer_function_for_with_options_and_compiler_facts(
        &decl,
        &TransferOptions::default(),
        &[],
        &[],
        &argument_values,
        &[],
    );
    let outer_argument = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx: 0 }) if site.0 == outer_span
            )
            .then_some(NodeId(u32::try_from(index).expect("node id")))
        })
        .expect("outer argument");
    let incoming: std::collections::BTreeSet<_> = out
        .edges
        .iter()
        .filter(|edge| edge.to == outer_argument)
        .map(|edge| rendered_place_name(&out, edge.from))
        .collect();

    assert_eq!(incoming, ["left".to_string(), "right".to_string()].into());
}

#[test]
fn indexed_object_initializer_is_field_precise_without_duplicate_flow_event() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["userInput".to_string()];
    let assign_span = span(20, 60);
    decl.flow_events = vec![FlowEvent::Assign {
        span: assign_span,
        target: "cfg".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec![
            "command".to_string(),
            "label".to_string(),
            "userInput".to_string(),
        ],
        declares_new_binding: true,
        value_kind: Some(AssignValueKind::Compound),
    }];
    let facts = [AssignmentValueFact {
        assignment_span: assign_span,
        target: Some("cfg".to_string()),
        target_is_immutable: false,
        target_owner: None,
        target_span: Some(span(20, 23)),
        value_span: span(26, 60),
        call_sites: Vec::new(),
        value_flow: ExpressionFlow {
            aggregate_fields: vec![
                bonsai_lang_api::ExpressionField {
                    name: "command".to_string(),
                    value_span: None,
                    value: ExpressionFlow::from_place("userInput"),
                },
                bonsai_lang_api::ExpressionField {
                    name: "label".to_string(),
                    value_span: None,
                    value: ExpressionFlow::default(),
                },
            ],
            ..ExpressionFlow::default()
        },
        static_value: None,
        exact_callable_return: None,
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        exact_static_call_args: None,
        direct_call_name: None,
        direct_call_span: None,
        direct_call_receiver: None,
        direct_call_receiver_span: None,
        direct_call_receiver_flow: None,
    }];

    let out =
        transfer_function_for_with_options_and_assignment_values(&decl, &TransferOptions::default(), &facts);
    let edges = out
        .edges
        .iter()
        .map(|edge| {
            (
                rendered_place_name(&out, edge.from),
                rendered_place_name(&out, edge.to),
            )
        })
        .collect::<Vec<_>>();

    assert!(
        edges
            .iter()
            .any(|(from, to)| from == "userInput" && to == "cfg.command"),
        "indexed field carrier missing: {edges:?}"
    );
    assert!(
        edges
            .iter()
            .all(|(from, to)| !(from == "userInput" && to == "cfg.label")),
        "literal sibling must stay clean: {edges:?}"
    );
    assert!(
        edges
            .iter()
            .all(|(from, to)| !(from == "userInput" && to == "cfg")),
        "broad container edge defeats field precision: {edges:?}"
    );
}

#[test]
fn assign_source_names_use_previous_sibling_call_span_for_return_binding() {
    let mut decl = empty_decl(1, "f");
    let assign_span = span(50, 90);
    let call_span = span(58, 75);
    decl.flow_events = vec![
        FlowEvent::Call {
            span: call_span,
            name: "stream_batch".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(71, 79),
                name: None,
                value_text: "envelope".to_string(),
                place: Some("envelope".to_string()),
                source_names: Vec::new(),
            }],
        },
        FlowEvent::Assign {
            span: assign_span,
            target: "chunk".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["stream_batch".to_string(), "envelope".to_string()],
            declares_new_binding: false,
            value_kind: None,
        },
    ];
    let out = transfer_function_for(&decl);

    assert_eq!(out.call_sites.len(), 1);
    assert_eq!(out.call_sites[0].site, CallSiteId(call_span));

    let place_for = |node_id: NodeId| {
        let node = out.nodes.get(node_id).expect("node exists");
        out.places.get(node.place).expect("place exists")
    };
    assert!(
        out.edges.iter().any(|edge| {
            matches!(place_for(edge.from), Place::CallRet { site } if site.0 == call_span)
                && matches!(place_for(edge.to), Place::Write { span, .. } if *span == assign_span)
        }),
        "expected previous sibling CallRet(call span) -> Write(assign target) edge: {:#?}",
        out.edges
    );
}

#[test]
fn assign_source_names_do_not_bind_unmentioned_sibling_call() {
    let mut decl = empty_decl(1, "f");
    let assign_span = span(50, 90);
    let call_span = span(58, 75);
    decl.flow_events = vec![
        FlowEvent::Call {
            span: call_span,
            name: "stream_batch".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: Vec::new(),
        },
        FlowEvent::Assign {
            span: assign_span,
            target: "chunk".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["envelope".to_string()],
            declares_new_binding: false,
            value_kind: None,
        },
    ];
    let out = transfer_function_for(&decl);

    let place_for = |node_id: NodeId| {
        let node = out.nodes.get(node_id).expect("node exists");
        out.places.get(node.place).expect("place exists")
    };
    assert!(
        !out.edges.iter().any(|edge| {
            matches!(place_for(edge.from), Place::CallRet { site } if site.0 == call_span)
                && matches!(place_for(edge.to), Place::Write { span, .. } if *span == assign_span)
        }),
        "unmentioned sibling call must not bind to assignment target: {:#?}",
        out.edges
    );
}

#[test]
fn assign_call_rhs_skips_non_call_siblings_inside_assignment_span() {
    let mut decl = empty_decl(1, "f");
    let assign_span = span(50, 90);
    let await_span = span(55, 89);
    let call_span = span(62, 82);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: assign_span,
            target: "chunk".to_string(),
            source_name: None,
            source_call: Some("_identity".to_string()),
            source_call_args: vec!["chunk".to_string()],
            source_names: vec!["_identity".to_string(), "await".to_string()],
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Await {
            span: await_span,
            value_name: None,
        },
        FlowEvent::Call {
            span: call_span,
            name: "_identity".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(83, 88),
                name: None,
                value_text: "chunk".to_string(),
                place: Some("chunk".to_string()),
                source_names: Vec::new(),
            }],
        },
    ];
    let out = transfer_function_for(&decl);

    assert_eq!(out.call_sites.len(), 1);
    assert_eq!(out.call_sites[0].site, CallSiteId(call_span));

    let place_for = |node_id: NodeId| {
        let node = out.nodes.get(node_id).expect("node exists");
        out.places.get(node.place).expect("place exists")
    };
    assert!(
        out.edges.iter().any(|edge| {
            matches!(place_for(edge.from), Place::CallRet { site } if site.0 == call_span)
                && matches!(place_for(edge.to), Place::Write { span, .. } if *span == assign_span)
        }),
        "expected CallRet(call span) -> Write(assign target) through intervening Await: {:#?}",
        out.edges
    );
    assert!(
        !out.edges
            .iter()
            .any(|edge| { matches!(place_for(edge.from), Place::CallRet { site } if site.0 == assign_span) }),
        "assignment span must not become a stale call-return identity: {:#?}",
        out.edges
    );
}

/// Phase 8 SSA-style narrowing test: a clean overwrite of a
/// previously-tainted name should produce per-statement Write
/// nodes so closure analysis doesn't smear the original taint
/// into post-overwrite reads.
#[test]
fn clean_overwrite_kills_prior_writer() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![
        // t = source_local
        FlowEvent::Assign {
            span: span(10, 20),
            target: "t".to_string(),
            source_name: Some("source_local".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        // sink_a(t)
        FlowEvent::Call {
            span: span(25, 40),
            name: "sink_a".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(32, 33),
                name: None,
                value_text: "t".to_string(),
                place: Some("t".to_string()),
                source_names: Vec::new(),
            }],
        },
        // t = "literal" (clean overwrite, no source name)
        FlowEvent::Assign {
            span: span(45, 55),
            target: "t".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        // sink_b(t)
        FlowEvent::Call {
            span: span(60, 75),
            name: "sink_b".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(67, 68),
                name: None,
                value_text: "t".to_string(),
                place: Some("t".to_string()),
                source_names: Vec::new(),
            }],
        },
    ];
    let out = transfer_function_for(&decl);
    // Two distinct Write(t, span) nodes — one per assign event —
    // so post-overwrite reads bridge from the second writer
    // only. Without span-distinguished Writes the closure from
    // source_local would smear into sink_b too.
    let write_count = out
        .places
        .places
        .iter()
        .filter(|p| matches!(p, Place::Write { name: _, path, .. } if path.is_empty()))
        .count();
    // Two Write(t) variants (one per span).
    assert!(
        write_count >= 2,
        "expected per-statement Write(t) nodes, got {} write places",
        write_count
    );
    // sink_a should bridge from the FIRST writer (which was
    // bridged from Read(source_local)). sink_b should bridge
    // from the SECOND writer (no incoming flow). The closure
    // walker test in builder/service confirms this end-to-end.
}

#[test]
fn configured_clean_output_overwrite_commits_fresh_output_writer() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![
        FlowEvent::Call {
            span: span(10, 20),
            name: "read_source".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(12, 15),
                name: None,
                value_text: "buf".to_string(),
                place: Some("buf".to_string()),
                source_names: vec!["buf".to_string()],
            }],
        },
        FlowEvent::Call {
            span: span(30, 45),
            name: "clean_copy".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![
                CallArg {
                    passing_mode: Default::default(),
                    span: span(31, 34),
                    name: None,
                    value_text: "buf".to_string(),
                    place: Some("buf".to_string()),
                    source_names: vec!["buf".to_string()],
                },
                CallArg {
                    passing_mode: Default::default(),
                    span: span(36, 42),
                    name: None,
                    value_text: "\"safe\"".to_string(),
                    place: None,
                    source_names: Vec::new(),
                },
            ],
        },
        FlowEvent::Call {
            span: span(50, 60),
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(55, 58),
                name: None,
                value_text: "buf".to_string(),
                place: Some("buf".to_string()),
                source_names: vec!["buf".to_string()],
            }],
        },
    ];
    let options = TransferOptions {
        clean_output_overwrites: vec![CleanOutputOverwriteSpec {
            callee: "clean_copy".to_string(),
            output_arg_index: 0,
            value_start_arg_index: 1,
        }],
        clean_receiver_overwrites: Vec::new(),
        source_output_args: Vec::new(),
        source_callback_args: Vec::new(),
        callback_invocations: Vec::new(),
        call_result_passthroughs: Vec::new(),
        output_arg_flows: Vec::new(),
        receiver_state_propagations: Vec::new(),
        include_diagnostic_field_flows: true,
        include_receiver_method_propagation: true,
        include_field_argument_forwarding: true,
        symbolic_field_forwarding: false,
        symbolic_field_languages: Vec::new(),
        include_unresolved_call_result_passthrough: false,
        include_unresolved_receiver_result_passthrough: false,
    };
    let out = transfer_function_for_with_options(&decl, &options);

    let sink_span = span(50, 60);
    let clean_span = span(30, 45);
    let sink_arg_node = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(idx, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx }) if site.0 == sink_span && *idx == 0
            )
            .then_some(NodeId(idx as u32))
        })
        .expect("sink arg node");
    let incoming: Vec<_> = out.edges.iter().filter(|edge| edge.to == sink_arg_node).collect();
    assert!(
        incoming.iter().any(|edge| {
            matches!(
                rendered_write_span(&out, edge.from),
                Some(span) if span == clean_span
            )
        }),
        "post-overwrite read must bridge from the configured clean-copy writer: {incoming:#?}"
    );
    assert!(
        incoming
            .iter()
            .all(|edge| { !matches!(rendered_place_name(&out, edge.from).as_str(), "Read(buf)") }),
        "post-overwrite read must not fall back to stale buf read: {incoming:#?}"
    );
}

#[test]
fn clean_receiver_overwrite_requires_the_exact_matcher_approved_call_span() {
    let mut decl = empty_decl(1, "f");
    let mutation_span = span(20, 35);
    let sink_span = span(40, 50);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: span(10, 15),
            target: "$value".to_string(),
            source_name: Some("source".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["source".to_string()],
            declares_new_binding: true,
            value_kind: None,
        },
        FlowEvent::Call {
            span: mutation_span,
            name: "substitute".to_string(),
            receiver: Some("$value".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Operator,
            args: Vec::new(),
        },
        FlowEvent::Call {
            span: sink_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(42, 48),
                name: None,
                value_text: "$value".to_string(),
                place: Some("$value".to_string()),
                source_names: vec!["$value".to_string()],
            }],
        },
    ];
    let lower = |resolved_call_sites| {
        transfer_function_for_with_options(
            &decl,
            &TransferOptions {
                clean_receiver_overwrites: vec![CleanReceiverOverwriteSpec {
                    callee: "substitute".to_string(),
                    resolved_call_sites,
                }],
                ..TransferOptions::default()
            },
        )
    };
    let sink_incoming_spans = |out: &TransferOutput| {
        let sink = out
            .nodes
            .nodes
            .iter()
            .enumerate()
            .find_map(|(idx, node)| {
                matches!(
                    out.places.get(node.place),
                    Some(Place::CallArg { site, idx: 0 }) if site.0 == sink_span
                )
                .then_some(NodeId(idx as u32))
            })
            .expect("sink argument");
        out.edges
            .iter()
            .filter(|edge| edge.to == sink)
            .filter_map(|edge| rendered_write_span(out, edge.from))
            .collect::<Vec<_>>()
    };

    let matched = lower(vec![mutation_span]);
    assert_eq!(sink_incoming_spans(&matched), [mutation_span]);

    let collision = lower(vec![span(100, 110)]);
    assert!(
        !sink_incoming_spans(&collision).contains(&mutation_span),
        "same-named call outside approved spans must not clean its receiver"
    );
}

#[test]
fn sibling_call_result_assignment_does_not_replay_output_argument_reads() {
    let mut decl = empty_decl(1, "handle");
    let assign_span = span(15, 40);
    let call_span = span(20, 35);
    let call = FlowEvent::Call {
        span: call_span,
        name: "recv".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![
            CallArg {
                passing_mode: Default::default(),
                span: span(21, 23),
                name: None,
                value_text: "fd".to_string(),
                place: Some("fd".to_string()),
                source_names: vec!["fd".to_string()],
            },
            CallArg {
                passing_mode: Default::default(),
                span: span(25, 28),
                name: None,
                value_text: "buf".to_string(),
                place: Some("buf".to_string()),
                source_names: vec!["buf".to_string()],
            },
        ],
    };
    let assign = FlowEvent::Assign {
        span: assign_span,
        target: "count".to_string(),
        source_name: Some("recv".to_string()),
        source_call: Some("recv".to_string()),
        source_call_args: vec!["fd".to_string(), "buf".to_string()],
        source_names: vec!["recv".to_string(), "fd".to_string(), "buf".to_string()],
        declares_new_binding: true,
        value_kind: Some(AssignValueKind::CallResult),
    };
    let options = TransferOptions {
        source_output_args: vec![SourceOutputArgSpec {
            callee: "recv".to_string(),
            output_arg_indices: vec![1],
            output_arg_start_index: None,
            resolved_call_sites: vec![call_span],
        }],
        ..TransferOptions::default()
    };

    for events in [
        vec![call.clone(), assign.clone()],
        vec![assign.clone(), call.clone()],
    ] {
        decl.flow_events = events;
        let out = transfer_function_for_with_options(&decl, &options);
        let output_write = out
            .nodes
            .nodes
            .iter()
            .enumerate()
            .find_map(|(index, node)| {
                matches!(
                    out.places.get(node.place),
                    Some(Place::Write { span, .. })
                        if *span == call_span && rendered_place_name(&out, NodeId(index as u32)) == "buf"
                )
                .then_some(NodeId(index as u32))
            })
            .expect("source output writer");
        let output_call_arg = out
            .nodes
            .nodes
            .iter()
            .enumerate()
            .find_map(|(index, node)| {
                matches!(
                    out.places.get(node.place),
                    Some(Place::CallArg { site, idx: 1 }) if site.0 == call_span
                )
                .then_some(NodeId(index as u32))
            })
            .expect("output call argument");
        assert!(
            out.edges
                .iter()
                .all(|edge| !(edge.from == output_write && edge.to == output_call_arg)),
            "a sibling assignment must not feed a newly written output carrier back into its own call: {:#?}",
            out.edges
        );
    }
}

#[test]
fn configured_output_arg_flow_materializes_value_to_post_call_writer() {
    let mut decl = empty_decl(1, "f");
    let copy_span = span(20, 35);
    let sink_span = span(40, 50);
    decl.flow_events = vec![
        FlowEvent::Call {
            span: copy_span,
            name: "copy_out".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![
                CallArg {
                    passing_mode: Default::default(),
                    span: span(21, 24),
                    name: None,
                    value_text: "dst".to_string(),
                    place: Some("dst".to_string()),
                    source_names: vec!["dst".to_string()],
                },
                CallArg {
                    passing_mode: Default::default(),
                    span: span(26, 29),
                    name: None,
                    value_text: "src".to_string(),
                    place: Some("src".to_string()),
                    source_names: vec!["src".to_string()],
                },
            ],
        },
        FlowEvent::Call {
            span: sink_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(42, 45),
                name: None,
                value_text: "dst".to_string(),
                place: Some("dst".to_string()),
                source_names: vec!["dst".to_string()],
            }],
        },
    ];
    let options = TransferOptions {
        output_arg_flows: vec![OutputArgFlowSpec {
            callee: "copy_out".to_string(),
            output_arg_index: 0,
            input_receiver: false,
            value_arg_indices: vec![1],
            value_start_arg_index: None,
            resolved_call_sites: Vec::new(),
        }],
        ..TransferOptions::default()
    };
    let out = transfer_function_for_with_options(&decl, &options);
    let output_write = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(idx, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::Write { span, .. }) if *span == copy_span
            )
            .then_some(NodeId(idx as u32))
        })
        .expect("output writer");
    let source_argument = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(idx, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx }) if site.0 == copy_span && *idx == 1
            )
            .then_some(NodeId(idx as u32))
        })
        .expect("source argument");
    assert!(out
        .edges
        .iter()
        .any(|edge| edge.from == source_argument && edge.to == output_write));
    assert!(out
        .edges
        .iter()
        .any(|edge| edge.to == source_argument && rendered_place_name(&out, edge.from) == "src"));
    let sink_arg = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(idx, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx }) if site.0 == sink_span && *idx == 0
            )
            .then_some(NodeId(idx as u32))
        })
        .expect("sink arg");
    assert!(out
        .edges
        .iter()
        .any(|edge| edge.from == output_write && edge.to == sink_arg));
}

#[test]
fn exact_output_arg_flow_can_copy_receiver_state_without_name_widening() {
    let mut decl = empty_decl(1, "extract");
    let assign_span = span(10, 18);
    let extract_span = span(20, 35);
    let sink_span = span(40, 50);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: assign_span,
            target: "stream".to_string(),
            source_name: Some("raw".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["raw".to_string()],
            declares_new_binding: true,
            value_kind: None,
        },
        FlowEvent::Call {
            span: extract_span,
            name: ">>".to_string(),
            receiver: Some("stream".to_string()),
            receiver_types: vec!["istringstream".to_string()],
            call_kind: CallKind::Operator,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(30, 35),
                name: None,
                value_text: "token".to_string(),
                place: Some("token".to_string()),
                source_names: vec!["token".to_string()],
            }],
        },
        FlowEvent::Call {
            span: sink_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(42, 47),
                name: None,
                value_text: "token".to_string(),
                place: Some("token".to_string()),
                source_names: vec!["token".to_string()],
            }],
        },
    ];
    let lower = |resolved_call_sites| {
        transfer_function_for_with_options(
            &decl,
            &TransferOptions {
                output_arg_flows: vec![OutputArgFlowSpec {
                    callee: ">>".to_string(),
                    output_arg_index: 0,
                    input_receiver: true,
                    value_arg_indices: Vec::new(),
                    value_start_arg_index: None,
                    resolved_call_sites,
                }],
                ..TransferOptions::default()
            },
        )
    };
    let has_receiver_to_output = |out: &TransferOutput| {
        let output = out.nodes.nodes.iter().enumerate().find_map(|(index, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::Write { span, .. }) if *span == extract_span
            )
            .then_some(NodeId(index as u32))
        });
        output.is_some_and(|output| {
            out.edges
                .iter()
                .any(|edge| edge.to == output && rendered_place_name(out, edge.from) == "stream")
        })
    };

    assert!(has_receiver_to_output(&lower(vec![extract_span])));
    assert!(
        !has_receiver_to_output(&lower(vec![span(60, 70)])),
        "a same-named operator outside matcher-approved spans must not receive the transfer"
    );
}

#[test]
fn configured_whole_output_arg_flow_reaches_later_field_read() {
    let mut decl = empty_decl(1, "f");
    let copy_span = span(20, 35);
    let sink_span = span(40, 55);
    decl.flow_events = vec![
        FlowEvent::Call {
            span: copy_span,
            name: "copy_out".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![
                CallArg {
                    passing_mode: bonsai_lang_api::ArgumentPassingMode::WriteBack,
                    span: span(21, 25),
                    name: None,
                    value_text: "&record".to_string(),
                    place: Some("record".to_string()),
                    source_names: vec!["record".to_string()],
                },
                CallArg {
                    passing_mode: Default::default(),
                    span: span(27, 30),
                    name: None,
                    value_text: "raw".to_string(),
                    place: Some("raw".to_string()),
                    source_names: vec!["raw".to_string()],
                },
            ],
        },
        FlowEvent::Call {
            span: sink_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(45, 53),
                name: None,
                value_text: "record.field".to_string(),
                place: Some("record.field".to_string()),
                source_names: vec!["record".to_string(), "record.field".to_string()],
            }],
        },
    ];
    let options = TransferOptions {
        output_arg_flows: vec![OutputArgFlowSpec {
            callee: "copy_out".to_string(),
            output_arg_index: 0,
            input_receiver: false,
            value_arg_indices: vec![1],
            value_start_arg_index: None,
            resolved_call_sites: Vec::new(),
        }],
        ..TransferOptions::default()
    };
    let out = transfer_function_for_with_options(&decl, &options);
    let output_write = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(idx, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::Write { span, .. }) if *span == copy_span
            )
            .then_some(NodeId(idx as u32))
        })
        .expect("whole output writer");
    let field_argument = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(idx, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx: 0 }) if site.0 == sink_span
            )
            .then_some(NodeId(idx as u32))
        })
        .expect("projected sink argument");
    assert!(
        out.edges
            .iter()
            .any(|edge| edge.from == output_write && edge.to == field_argument),
        "a complete output write must feed later exact projections: {:#?}",
        out.edges
    );
}

#[test]
fn formal_parameter_entry_does_not_collapse_an_exact_field_read() {
    let mut decl = empty_decl(1, "inspect");
    decl.params = vec!["record".to_string()];
    let sink_span = span(40, 55);
    decl.flow_events = vec![FlowEvent::Call {
        span: sink_span,
        name: "consume".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(48, 54),
            name: None,
            value_text: "record.field".to_string(),
            place: Some("record.field".to_string()),
            source_names: vec!["record".to_string(), "record.field".to_string()],
        }],
    }];
    let out = transfer_function_for(&decl);
    let entry_write = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(idx, node)| {
            let node_id = NodeId(idx as u32);
            (matches!(
                out.places.get(node.place),
                Some(Place::Write { span, .. }) if *span == decl.name_span
            ) && rendered_place_name(&out, node_id) == "record")
                .then_some(node_id)
        })
        .expect("parameter entry writer");
    let field_argument = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(idx, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx: 0 }) if site.0 == sink_span
            )
            .then_some(NodeId(idx as u32))
        })
        .expect("projected call argument");
    assert!(
        !out.edges
            .iter()
            .any(|edge| edge.from == entry_write && edge.to == field_argument),
        "the scalar formal slot must not collapse an exact field into the whole object: {:#?}",
        out.edges
    );
    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "record.field" && edge.to == field_argument
        }),
        "the compiler-emitted exact field must still feed the argument: {:#?}",
        out.edges
    );
}

#[test]
fn configured_output_writer_consumes_the_exact_argument_value_not_nested_operands() {
    let mut decl = empty_decl(1, "render");
    decl.params = vec!["input".to_string()];
    let writer_span = span(20, 50);
    let nested_span = span(35, 46);
    let value_span = span(35, 46);
    decl.flow_events = vec![
        FlowEvent::Call {
            span: writer_span,
            name: "write_value".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![
                CallArg {
                    passing_mode: Default::default(),
                    span: span(21, 24),
                    name: None,
                    value_text: "dst".to_string(),
                    place: Some("dst".to_string()),
                    source_names: vec!["dst".to_string()],
                },
                CallArg {
                    passing_mode: Default::default(),
                    span: value_span,
                    name: None,
                    value_text: "select_value(input)".to_string(),
                    place: None,
                    source_names: vec!["input".to_string()],
                },
            ],
        },
        FlowEvent::Call {
            span: nested_span,
            name: "select_value".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(42, 47),
                name: None,
                value_text: "input".to_string(),
                place: Some("input".to_string()),
                source_names: vec!["input".to_string()],
            }],
        },
    ];
    let argument_values = [CallArgumentValueFact {
        call_span: writer_span,
        argument_index: 1,
        argument_span: value_span,
        direct_call_span: Some(nested_span),
        value_kind: Some(AssignValueKind::CallResult),
        inline_callback_params: Vec::new(),
        inline_callback_span: None,
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        value_flow: ExpressionFlow {
            source_names: vec!["input".to_string()],
            call_sites: vec![nested_span],
            ..Default::default()
        },
        static_value: None,
        exact_static_aggregate_fields: Vec::new(),
        exact_static_sequence_values: None,
    }];
    let options = TransferOptions {
        clean_output_overwrites: vec![CleanOutputOverwriteSpec {
            callee: "write_value".to_string(),
            output_arg_index: 0,
            value_start_arg_index: 1,
        }],
        ..TransferOptions::default()
    };
    let out = transfer_function_for_with_options_and_compiler_facts(
        &decl,
        &options,
        &[],
        &[],
        &argument_values,
        &[],
    );
    let output_write = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::Write { span, .. }) if *span == writer_span
            )
            .then_some(NodeId(index as u32))
        })
        .expect("output writer");
    let writer_argument = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx }) if site.0 == writer_span && *idx == 1
            )
            .then_some(NodeId(index as u32))
        })
        .expect("writer argument");

    assert!(out
        .edges
        .iter()
        .any(|edge| edge.from == writer_argument && edge.to == output_write));
    assert!(out
        .edges
        .iter()
        .all(|edge| { edge.to != output_write || rendered_place_name(&out, edge.from) != "input" }));
}

#[test]
fn configured_receiver_state_flow_materializes_argument_to_receiver_writer() {
    let mut decl = empty_decl(1, "f");
    let mutation_span = span(20, 35);
    let sink_span = span(40, 50);
    decl.flow_events = vec![
        FlowEvent::Call {
            span: mutation_span,
            name: "add".to_string(),
            receiver: Some("builder".to_string()),
            receiver_types: vec!["Builder".to_string()],
            call_kind: CallKind::Method,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(26, 29),
                name: None,
                value_text: "src".to_string(),
                place: Some("src".to_string()),
                source_names: vec!["src".to_string()],
            }],
        },
        FlowEvent::Call {
            span: sink_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(42, 47),
                name: None,
                value_text: "builder".to_string(),
                place: Some("builder".to_string()),
                source_names: vec!["builder".to_string()],
            }],
        },
    ];
    let options = TransferOptions {
        receiver_state_propagations: vec![ReceiverStatePropagationSpec {
            method: "add".to_string(),
            receiver_type: Some("Builder".to_string()),
            resolved_call_sites: Vec::new(),
        }],
        ..TransferOptions::default()
    };
    let out = transfer_function_for_with_options(&decl, &options);
    let receiver_write = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(idx, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::Write { span, .. }) if *span == mutation_span
            )
            .then_some(NodeId(idx as u32))
        })
        .expect("receiver writer");
    assert!(out
        .edges
        .iter()
        .any(|edge| edge.to == receiver_write && rendered_place_name(&out, edge.from) == "src"));
    assert!(out
        .edges
        .iter()
        .any(|edge| { edge.to == receiver_write && rendered_place_name(&out, edge.from) == "builder" }));
    let sink_arg = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(idx, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx }) if site.0 == sink_span && *idx == 0
            )
            .then_some(NodeId(idx as u32))
        })
        .expect("sink arg");
    assert!(out
        .edges
        .iter()
        .any(|edge| edge.from == receiver_write && edge.to == sink_arg));
}

#[test]
fn resolved_rule_call_site_supplies_receiver_type_proof() {
    let mut decl = empty_decl(1, "f");
    let mutation_span = span(20, 35);
    decl.flow_events = vec![FlowEvent::Call {
        span: mutation_span,
        name: "add".to_string(),
        receiver: Some("builder".to_string()),
        receiver_types: Vec::new(),
        call_kind: CallKind::Method,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(26, 29),
            name: None,
            value_text: "src".to_string(),
            place: Some("src".to_string()),
            source_names: vec!["src".to_string()],
        }],
    }];
    let options = TransferOptions {
        receiver_state_propagations: vec![ReceiverStatePropagationSpec {
            method: "add".to_string(),
            receiver_type: Some("ExternalBuilder".to_string()),
            resolved_call_sites: vec![mutation_span],
        }],
        ..TransferOptions::default()
    };

    let out = transfer_function_for_with_options(&decl, &options);
    let receiver_write = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(idx, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::Write { span, .. }) if *span == mutation_span
            )
            .then_some(NodeId(idx as u32))
        })
        .expect("resolved rule site should materialize a receiver writer");
    assert!(out
        .edges
        .iter()
        .any(|edge| edge.to == receiver_write && rendered_place_name(&out, edge.from) == "src"));
}

#[test]
fn resolved_rule_write_site_materializes_member_value_into_receiver_state() {
    let mut decl = empty_decl(1, "f");
    let mutation_span = span(20, 35);
    let sink_span = span(40, 50);
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: mutation_span,
            target: "builder.parts".to_string(),
            source_name: Some("src".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["src".to_string()],
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: sink_span,
            name: "finish".to_string(),
            receiver: Some("builder".to_string()),
            receiver_types: vec!["Builder".to_string()],
            call_kind: CallKind::Method,
            args: Vec::new(),
        },
    ];
    let options = TransferOptions {
        receiver_state_propagations: vec![ReceiverStatePropagationSpec {
            method: "parts".to_string(),
            receiver_type: Some("Builder".to_string()),
            resolved_call_sites: vec![mutation_span],
        }],
        ..TransferOptions::default()
    };

    let out = transfer_function_for_with_options(&decl, &options);
    let receiver_write = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(idx, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::Write { name, path, span })
                    if out.names.get(*name) == Some("builder") && path.is_empty() && *span == mutation_span
            )
            .then_some(NodeId(idx as u32))
        })
        .expect("resolved property write should materialize receiver state");
    assert!(out.edges.iter().any(|edge| {
        edge.to == receiver_write && rendered_place_name(&out, edge.from) == "builder.parts"
    }));
    let sink_receiver = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(idx, node)| {
            matches!(
                out.places.get(node.place),
                Some(Place::CallArg { site, idx }) if site.0 == sink_span && *idx == u32::MAX
            )
            .then_some(NodeId(idx as u32))
        })
        .expect("sink receiver");
    assert!(out
        .edges
        .iter()
        .any(|edge| edge.from == receiver_write && edge.to == sink_receiver));
}

#[test]
fn standalone_call_records_site_with_arg_nodes() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Call {
        span: span(10, 25),
        name: "log".to_string(),
        receiver: Some("logger".to_string()),
        receiver_types: vec!["Logger".to_string()],
        call_kind: CallKind::Method,
        args: vec![
            CallArg {
                passing_mode: Default::default(),
                span: span(11, 15),
                name: None,
                value_text: "user".to_string(),
                place: Some("user".to_string()),
                source_names: Vec::new(),
            },
            CallArg {
                passing_mode: Default::default(),
                span: span(17, 22),
                name: None,
                value_text: "level".to_string(),
                place: Some("level".to_string()),
                source_names: Vec::new(),
            },
        ],
    }];
    let out = transfer_function_for(&decl);
    // Three IntraRead edges: two for the explicit args (user,
    // level) plus one for the implicit receiver (logger) flowing
    // into the synthetic receiver slot.
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraRead), 3);
    assert_eq!(out.call_sites.len(), 1);
    let site = &out.call_sites[0];
    assert_eq!(site.callee_name, "log");
    assert_eq!(site.args_count, 2);
    assert_eq!(site.receiver.as_deref(), Some("logger"));
    assert_eq!(site.receiver_types, vec!["Logger".to_string()]);
    assert_eq!(site.call_kind, CallKind::Method);
    assert_eq!(site.call_arg_nodes.len(), 2);
    assert!(
        site.receiver_arg_node.is_some(),
        "method receiver should be recorded separately from positional args"
    );
}

#[test]
fn syntax_operator_flows_operands_to_result() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["input".to_string()];
    let operator_span = span(20, 31);
    decl.flow_events = vec![FlowEvent::Call {
        span: operator_span,
        name: "+".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Operator,
        args: vec![
            CallArg {
                passing_mode: Default::default(),
                span: span(20, 25),
                name: None,
                value_text: "input".to_string(),
                place: Some("input".to_string()),
                source_names: vec!["input".to_string()],
            },
            CallArg {
                passing_mode: Default::default(),
                span: span(28, 31),
                name: None,
                value_text: "\"x\"".to_string(),
                place: None,
                source_names: Vec::new(),
            },
        ],
    }];
    let out = transfer_function_for(&decl);

    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == format!("CallArg({operator_span:?},0)")
                && rendered_place_name(&out, edge.to) == format!("CallRet({operator_span:?})")
                && edge.meta.precision == Precision::Exact
        }),
        "an AST operator result must depend exactly on its operand: {:#?}",
        out.edges
    );
}

#[test]
fn projected_method_receiver_keeps_exact_storage_place() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Call {
        span: span(10, 25),
        name: "self.data.clone".to_string(),
        receiver: Some("self.data".to_string()),
        receiver_types: vec!["String".to_string()],
        call_kind: CallKind::Method,
        args: Vec::new(),
    }];
    let out = transfer_function_for(&decl);
    let receiver_node = out.call_sites[0].receiver_arg_node.expect("receiver node");
    assert!(
        out.edges
            .iter()
            .any(|edge| { edge.to == receiver_node && rendered_place_name(&out, edge.from) == "self.data" }),
        "projected receiver must remain one AST storage place: {:#?}",
        out.edges
    );
}

#[test]
fn method_argument_does_not_invent_receiver_state_write() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["obj".to_string(), "secret".to_string()];
    let call_span = span(20, 38);
    decl.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "obj.check".to_string(),
        receiver: Some("obj".to_string()),
        receiver_types: Vec::new(),
        call_kind: CallKind::Method,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(30, 36),
            name: None,
            value_text: "secret".to_string(),
            place: Some("secret".to_string()),
            source_names: vec!["secret".to_string()],
        }],
    }];
    let options = TransferOptions {
        include_unresolved_call_result_passthrough: true,
        include_unresolved_receiver_result_passthrough: true,
        ..TransferOptions::default()
    };
    let out = transfer_function_for_with_options(&decl, &options);

    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from).starts_with("CallArg(")
                && rendered_place_name(&out, edge.to) == "obj"
                && rendered_write_span(&out, edge.to) == Some(call_span)
        }),
        "a read-only method call must not turn its argument into an exact receiver mutation: {:#?}",
        out.edges
    );
}

#[test]
fn call_arg_without_place_still_records_arg_node() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Call {
        span: span(10, 25),
        name: "f".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(11, 25),
            name: None,
            // Quoted string-literal value_text — the adapter
            // passed a literal, not a name. The IDG should NOT
            // tokenise the inner text as an identifier.
            value_text: "\"literal_string\"".to_string(),
            place: None,
            source_names: Vec::new(),
        }],
    }];
    let out = transfer_function_for(&decl);
    // No Read edge (no place identifier, value_text is a quoted
    // literal), but the arg node is still interned for Phase 3.
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraRead), 0);
    assert_eq!(out.call_sites.len(), 1);
    assert_eq!(out.call_sites[0].call_arg_nodes.len(), 1);
}

#[test]
fn compound_call_arg_uses_only_ast_derived_sources() {
    // `value_text` is resolver/display spelling, never a second parser input.
    // Deliberately disagree with the AST-derived source fact: only `ast_tmp`
    // may become a read feeding the argument slot.
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Call {
        span: span(10, 30),
        name: "exec".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(11, 30),
            name: None,
            value_text: "\"-c \" + text_only_tmp".to_string(),
            place: None,
            source_names: vec!["ast_tmp".to_string()],
        }],
    }];
    let out = transfer_function_for(&decl);
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraRead), 1);
    assert!(out.edges.iter().any(|edge| {
        rendered_place_name(&out, edge.from) == "ast_tmp"
            && rendered_place_name(&out, edge.to).starts_with("CallArg")
    }));
    assert!(!out
        .edges
        .iter()
        .any(|edge| rendered_place_name(&out, edge.from) == "text_only_tmp"));
}

#[test]
fn return_with_value_name_emits_intra_return_edge() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(40, 50),
        value_name: Some("result".to_string()),
        value_text: Some("result".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("result"),
    }];
    let out = transfer_function_for(&decl);
    // Two intentional IntraReturn edges: the `value_name` read bridge
    // (`Read(result) -> Return`) plus the span-anchored return-base edge
    // (`__return__@span -> Return`) that `bridge_return_expression_calls`
    // emits for call-free return expressions so span-anchored source
    // seeding (`return os.environ["CMD"]`) lands on a live node instead
    // of a dead orphan.
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraReturn), 2);
}

#[test]
fn return_without_value_name_emits_no_edge() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(40, 50),
        value_name: None,
        value_text: None,
        value_flow: Default::default(),
    }];
    let out = transfer_function_for(&decl);
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraReturn), 0);
}

#[test]
fn throw_with_value_name_records_throw_site_and_emits_edge() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Throw {
        span: span(20, 35),
        value_name: Some("err".to_string()),
        thrown_type: Some("IOException".to_string()),
    }];
    let out = transfer_function_for(&decl);
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraThrow), 1);
    assert_eq!(out.throw_sites.len(), 1);
    assert!(out.throw_sites[0].thrown_type.is_some());
}

#[test]
fn try_catch_typed_match_emits_throw_to_catch_edge() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Try {
        span: span(0, 80),
        body: vec![FlowEvent::Throw {
            span: span(10, 25),
            value_name: Some("e".to_string()),
            thrown_type: Some("IOException".to_string()),
        }],
        catch_events: Vec::new(),
        finally_events: Vec::new(),
        catch_param: Some("ex".to_string()),
        catch_types: vec!["IOException".to_string()],
        catch_arms: Vec::new(),
    }];
    let out = transfer_function_for(&decl);
    // 1 IntraThrow from the body's Read(e) → Throw(IOException)
    // 1 IntraThrow from Throw(IOException) → Catch(IOException)
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraThrow), 2);
    // 1 IntraAssign from Catch(IOException) → Write(ex)
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 1);
}

#[test]
fn typed_throw_connects_only_to_its_own_catch_arm() {
    let mut decl = empty_decl(1, "f");
    let first_arm = span(30, 55);
    let second_arm = span(56, 80);
    decl.flow_events = vec![FlowEvent::Try {
        span: span(0, 90),
        body: vec![FlowEvent::Throw {
            span: span(10, 25),
            value_name: Some("payload".to_string()),
            thrown_type: Some("FirstException".to_string()),
        }],
        catch_events: vec![FlowEvent::Branch {
            span: first_arm,
            condition: None,
            then_events: vec![FlowEvent::Assign {
                span: span(40, 45),
                target: "first_copy".to_string(),
                source_name: Some("first".to_string()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: vec!["first".to_string()],
                declares_new_binding: true,
                value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
            }],
            else_events: vec![FlowEvent::Assign {
                span: span(65, 70),
                target: "second_copy".to_string(),
                source_name: Some("second".to_string()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: vec!["second".to_string()],
                declares_new_binding: true,
                value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
            }],
        }],
        finally_events: Vec::new(),
        catch_param: Some("first".to_string()),
        catch_types: vec!["FirstException".to_string(), "SecondException".to_string()],
        catch_arms: vec![
            CatchArmFact {
                span: first_arm,
                parameter: Some("first".to_string()),
                types: vec!["FirstException".to_string()],
            },
            CatchArmFact {
                span: second_arm,
                parameter: Some("second".to_string()),
                types: vec!["SecondException".to_string()],
            },
        ],
    }];

    let out = transfer_function_for(&decl);
    let reached_catches = out
        .edges
        .iter()
        .filter(|edge| edge.meta.kind == IdgEdgeKind::IntraThrow)
        .filter_map(|edge| rendered_catch_type(&out, edge.to))
        .collect::<Vec<_>>();
    assert_eq!(reached_catches, ["FirstException"]);
    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "first"
                && rendered_place_name(&out, edge.to) == "first_copy"
        }),
        "the matching arm binding must feed its own body"
    );
    assert!(
        !out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "first"
                && rendered_place_name(&out, edge.to) == "second_copy"
        }),
        "a sibling handler must never inherit another arm's binding"
    );
}

#[test]
fn sigiled_catch_param_read_uses_bare_binding_writer() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Try {
        span: span(0, 80),
        body: vec![FlowEvent::Throw {
            span: span(10, 25),
            value_name: Some("payload".to_string()),
            thrown_type: Some("Exception".to_string()),
        }],
        catch_events: vec![FlowEvent::Assign {
            span: span(40, 50),
            target: "$copy".to_string(),
            source_name: Some("$e".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["$e".to_string()],
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        }],
        finally_events: Vec::new(),
        catch_param: Some("e".to_string()),
        catch_types: vec!["Exception".to_string()],
        catch_arms: Vec::new(),
    }];
    let out = transfer_function_for(&decl);
    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "e"
                && rendered_place_name(&out, edge.to) == "$copy"
                && edge.meta.kind == IdgEdgeKind::IntraAssign
        }),
        "sigiled catch-body reads should resolve the adapter's bare catch binding: {:#?}",
        out.edges
    );
}

#[test]
fn try_catch_distinct_types_wait_for_workspace_hierarchy_resolution() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Try {
        span: span(0, 80),
        body: vec![FlowEvent::Throw {
            span: span(10, 25),
            value_name: Some("e".to_string()),
            thrown_type: Some("RuntimeException".to_string()),
        }],
        catch_events: Vec::new(),
        finally_events: Vec::new(),
        catch_param: Some("ex".to_string()),
        catch_types: vec!["Exception".to_string()],
        catch_arms: Vec::new(),
    }];
    let out = transfer_function_for(&decl);
    // Only Read(e) -> Throw(RuntimeException) is local. The transfer pass has
    // no global type hierarchy and must not treat the spelling `Exception`
    // as a magic root; workspace stitching adds the catch edge when a parsed
    // declaration proves the base relationship.
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraThrow), 1);
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 1);
}

#[test]
fn compound_throw_constructor_arg_bridges_to_throw_node() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Try {
        span: span(0, 100),
        body: vec![
            FlowEvent::Throw {
                span: span(10, 45),
                value_name: None,
                thrown_type: Some("RuntimeException".to_string()),
            },
            FlowEvent::Call {
                span: span(20, 40),
                name: "RuntimeException".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Constructor,
                args: vec![CallArg {
                    passing_mode: Default::default(),
                    span: span(37, 44),
                    name: None,
                    value_text: "payload".to_string(),
                    place: Some("payload".to_string()),
                    source_names: vec!["payload".to_string()],
                }],
            },
        ],
        catch_events: Vec::new(),
        finally_events: Vec::new(),
        catch_param: Some("ex".to_string()),
        catch_types: vec!["RuntimeException".to_string()],
        catch_arms: Vec::new(),
    }];
    let out = transfer_function_for(&decl);
    // 1 Read(payload) -> CallArg, 1 Read(payload) -> Throw,
    // 1 Throw -> Catch, 1 Catch -> Write(ex).
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraRead), 1);
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraThrow), 2);
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 1);
}

#[test]
fn call_arg_method_projection_bridges_receiver_carrier() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["e".to_string()];
    decl.flow_events = vec![
        FlowEvent::Call {
            span: span(20, 45),
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(25, 42),
                name: None,
                value_text: "e.getMessage()".to_string(),
                place: None,
                source_names: vec!["e.getMessage".to_string(), "e".to_string()],
            }],
        },
        FlowEvent::Call {
            span: span(25, 42),
            name: "e.getMessage".to_string(),
            receiver: Some("e".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        },
    ];
    let out = transfer_function_for(&decl);
    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "e"
                && rendered_place_name(&out, edge.to).starts_with("CallArg")
        }),
        "method projection should bridge the receiver carrier into the arg slot: {:#?}",
        out.edges
    );
}

#[test]
fn call_arg_property_projection_bridges_receiver_carrier() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Try {
        span: span(0, 80),
        body: vec![FlowEvent::Throw {
            span: span(10, 20),
            value_name: Some("err".to_string()),
            thrown_type: Some("Exception".to_string()),
        }],
        catch_events: vec![FlowEvent::Call {
            span: span(30, 55),
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(35, 44),
                name: None,
                value_text: "e.Message".to_string(),
                place: None,
                source_names: vec!["e.Message".to_string(), "e".to_string()],
            }],
        }],
        finally_events: Vec::new(),
        catch_param: Some("e".to_string()),
        catch_types: vec!["Exception".to_string()],
        catch_arms: Vec::new(),
    }];
    let out = transfer_function_for(&decl);
    assert!(
        out.edges.iter().any(|edge| {
            rendered_place_name(&out, edge.from) == "e"
                && rendered_place_name(&out, edge.to).starts_with("CallArg")
        }),
        "catch-param property projection should bridge the receiver carrier into the arg slot: {:#?}",
        out.edges
    );
}

#[test]
fn try_catch_all_matches_typed_throw_via_star_sentinel() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Try {
        span: span(0, 80),
        body: vec![FlowEvent::Throw {
            span: span(10, 25),
            value_name: Some("e".to_string()),
            thrown_type: None,
        }],
        catch_events: Vec::new(),
        finally_events: Vec::new(),
        catch_param: Some("ex".to_string()),
        catch_types: Vec::new(),
        catch_arms: Vec::new(),
    }];
    let out = transfer_function_for(&decl);
    // Body throw: Read(e) → Throw(*) (1 IntraThrow)
    // Catch-all: Throw(*) → Catch(*) (1 IntraThrow)
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraThrow), 2);
    // Catch(*) → Write(ex) (1 IntraAssign)
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 1);
}

#[test]
fn branch_walks_both_arms() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Branch {
        span: span(0, 100),
        condition: Some("flag".to_string()),
        then_events: vec![FlowEvent::Assign {
            span: span(10, 20),
            target: "x".to_string(),
            source_name: Some("a".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        }],
        else_events: vec![FlowEvent::Assign {
            span: span(30, 40),
            target: "x".to_string(),
            source_name: Some("b".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        }],
    }];
    let out = transfer_function_for(&decl);
    // Each arm emits one IntraAssign edge (Read(src) →
    // Write(x, arm_span)). Two distinct Write(x) nodes (per
    // span) so the SSA-style branch join unions them — both
    // are live for any read after the merge.
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 2);
}

#[test]
fn branch_return_in_one_arm_does_not_hide_yield_from_the_other_arm() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["input".to_string()];
    let send_span = span(40, 50);
    decl.flow_events = vec![
        FlowEvent::Defer {
            span: span(1, 5),
            body: vec![FlowEvent::Call {
                span: span(2, 4),
                name: "close".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args: Vec::new(),
            }],
        },
        FlowEvent::Assign {
            span: span(10, 20),
            target: "part".to_string(),
            source_name: Some("input".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: None,
        },
        FlowEvent::Loop {
            span: span(25, 60),
            loop_kind: bonsai_lang_api::LoopKind::ForEach,
            body: vec![FlowEvent::Branch {
                span: span(25, 60),
                condition: None,
                then_events: vec![FlowEvent::Return {
                    span: span(30, 35),
                    value_name: None,
                    value_text: None,
                    value_flow: bonsai_lang_api::ExpressionFlow::default(),
                    value_kind: None,
                }],
                else_events: vec![
                    FlowEvent::Call {
                        span: send_span,
                        name: "send".to_string(),
                        receiver: Some("out".to_string()),
                        receiver_types: Vec::new(),
                        call_kind: CallKind::ChannelSend,
                        args: vec![
                            CallArg {
                                span: span(40, 43),
                                passing_mode: Default::default(),
                                name: None,
                                value_text: "out".to_string(),
                                place: Some("out".to_string()),
                                source_names: vec!["out".to_string()],
                            },
                            CallArg {
                                span: span(47, 51),
                                passing_mode: Default::default(),
                                name: None,
                                value_text: "part".to_string(),
                                place: Some("part".to_string()),
                                source_names: vec!["part".to_string()],
                            },
                        ],
                    },
                    FlowEvent::Yield {
                        span: send_span,
                        value_text: Some("part".to_string()),
                        value_flow: bonsai_lang_api::ExpressionFlow::from_place("part"),
                    },
                ],
            }],
        },
        FlowEvent::Return {
            span: span(70, 75),
            value_name: Some("out".to_string()),
            value_text: Some("out".to_string()),
            value_flow: bonsai_lang_api::ExpressionFlow::from_place("out"),
            value_kind: None,
        },
    ];

    let out = transfer_function_for(&decl);
    let input_write = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            let Place::Write { name, span, .. } = out.places.get(node.place)? else {
                return None;
            };
            (out.names.get(*name) == Some("part") && *span == CommonSpan::new(FileId::new(0), 10, 20))
                .then_some(NodeId(index as u32))
        })
        .expect("part writer");
    let yield_node = out
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(out.places.get(node.place), Some(Place::Yield)).then_some(NodeId(index as u32))
        })
        .expect("yield endpoint");

    let mut reached = std::collections::HashSet::from([input_write]);
    loop {
        let before = reached.len();
        for edge in &out.edges {
            if reached.contains(&edge.from) {
                reached.insert(edge.to);
            }
        }
        if reached.len() == before {
            break;
        }
    }
    assert!(
        reached.contains(&yield_node),
        "the executable-flow normalizer and transfer walker must retain the non-returning branch"
    );
}

#[test]
fn loop_body_walks_through() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Loop {
        span: span(0, 60),
        loop_kind: bonsai_lang_api::LoopKind::While,
        body: vec![FlowEvent::Assign {
            span: span(10, 20),
            target: "x".to_string(),
            source_name: Some("y".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        }],
    }];
    let out = transfer_function_for(&decl);
    // Body is walked twice for loop-carried reads, but duplicate
    // edges from the same source event are suppressed.
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 1);
}

#[test]
fn loop_exit_preserves_zero_iteration_writers() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["x".to_string()];
    let loop_write = span(20, 30);
    let sink_site = span(50, 60);
    decl.flow_events = vec![
        FlowEvent::Loop {
            span: span(10, 40),
            loop_kind: bonsai_lang_api::LoopKind::While,
            body: vec![FlowEvent::Assign {
                span: loop_write,
                target: "x".to_string(),
                source_name: None,
                source_call: None,
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: false,
                value_kind: Some(bonsai_lang_api::AssignValueKind::Literal),
            }],
        },
        FlowEvent::Call {
            span: sink_site,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(55, 56),
                name: None,
                value_text: "x".to_string(),
                place: Some("x".to_string()),
                source_names: Vec::new(),
            }],
        },
    ];

    let out = transfer_function_for(&decl);
    let sink_arg = out
        .call_sites
        .iter()
        .find(|site| site.site.0 == sink_site)
        .and_then(|site| site.call_arg_nodes.first())
        .copied()
        .expect("sink arg node");
    let reaching_write_spans = out
        .edges
        .iter()
        .filter(|edge| edge.to == sink_arg && edge.meta.kind == IdgEdgeKind::IntraRead)
        .filter_map(|edge| rendered_write_span(&out, edge.from))
        .collect::<Vec<_>>();

    assert!(
        reaching_write_spans.contains(&decl.name_span),
        "the pre-loop parameter binding must reach code after a zero-iteration loop: {reaching_write_spans:?}"
    );
    assert!(
        reaching_write_spans.contains(&loop_write),
        "the may-run loop write must also reach code after the loop: {reaching_write_spans:?}"
    );
}

#[test]
fn deeply_nested_loops_establish_carry_edges_without_a_depth_ceiling() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["state".to_string(), "next".to_string()];
    let sink_site = span(40, 50);
    let carried_write = span(60, 70);
    let mut body = vec![
        FlowEvent::Call {
            span: sink_site,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(45, 46),
                name: None,
                value_text: "state".to_string(),
                place: Some("state".to_string()),
                source_names: Vec::new(),
            }],
        },
        FlowEvent::Assign {
            span: carried_write,
            target: "state".to_string(),
            source_name: Some("next".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
    ];
    for depth in 0..12_u64 {
        body = vec![FlowEvent::Loop {
            span: span(100 + depth, 200 + depth),
            loop_kind: bonsai_lang_api::LoopKind::While,
            body,
        }];
    }
    decl.flow_events = body;

    let out = transfer_function_for(&decl);
    let sink_arg = out
        .call_sites
        .iter()
        .find(|site| site.site.0 == sink_site)
        .and_then(|site| site.call_arg_nodes.first())
        .copied()
        .expect("nested-loop sink arg node");
    assert!(
        out.edges.iter().any(|edge| {
            edge.to == sink_arg
                && edge.meta.kind == IdgEdgeKind::IntraRead
                && rendered_write_span(&out, edge.from) == Some(carried_write)
        }),
        "the deepest loop's prior-iteration write must reach its next-iteration read"
    );
    assert_eq!(
        out.call_sites
            .iter()
            .filter(|site| site.site.0 == sink_site)
            .count(),
        1,
        "replay must retain one structural call site"
    );
}

#[test]
fn deep_return_projection_is_not_truncated() {
    let projection = return_field_projection(
        &bonsai_lang_api::ExpressionProjection {
            base: "root".to_string(),
            path: ["a", "b", "c", "d", "e", "f"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        },
        &[],
    )
    .expect("deep projection");
    assert_eq!(projection.base, "root.a.b.c.d.e");
    assert_eq!(projection.field, "f");
}

#[test]
fn zero_arg_method_name_is_not_invented_as_a_return_field() {
    let mut decl = empty_decl(1, "returns_call");
    decl.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(10, 40),
        value_name: None,
        value_text: Some("client.arbitrary_method()".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow {
            call_sites: vec![span(10, 40)],
            ..Default::default()
        },
    }];
    assert!(transfer_function_for(&decl).return_field_projections.is_empty());
}

#[test]
fn return_expression_full_span_joins_its_callee_token_call_site() {
    let mut decl = empty_decl(1, "returns_call");
    decl.flow_events = vec![
        FlowEvent::Call {
            span: span(10, 15),
            name: "factory".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: Vec::new(),
        },
        FlowEvent::Return {
            value_kind: None,
            span: span(10, 30),
            value_name: None,
            value_text: Some("factory()".to_string()),
            value_flow: bonsai_lang_api::ExpressionFlow {
                call_sites: vec![span(10, 30)],
                ..Default::default()
            },
        },
    ];
    let out = transfer_function_for(&decl);
    assert!(out.edges.iter().any(|edge| {
        rendered_place_name(&out, edge.from).starts_with("CallRet(")
            && rendered_place_name(&out, edge.to) == "__bonsai_return"
            && edge.meta.kind == IdgEdgeKind::IntraReturn
    }));
}

#[test]
fn zero_arg_calls_require_a_resolved_return_summary() {
    for (index, rendered_call) in [
        "self.data.cmd.arbitrary_method()",
        "self.data.cmd.clone()",
        "self.db.close()",
    ]
    .into_iter()
    .enumerate()
    {
        let call_span = span(50 + index as u64 * 20, 65 + index as u64 * 20);
        let mut decl = empty_decl(index as u32 + 1, "returns_call");
        decl.implicit_receiver_names = vec!["self".to_string()];
        decl.flow_events = vec![FlowEvent::Return {
            value_kind: None,
            span: call_span,
            value_name: None,
            value_text: Some(rendered_call.to_string()),
            value_flow: bonsai_lang_api::ExpressionFlow {
                call_sites: vec![call_span],
                ..Default::default()
            },
        }];
        assert!(
            transfer_function_for(&decl).return_field_projections.is_empty(),
            "rendered call text must not create a field projection: {rendered_call}"
        );
    }
}

#[test]
fn deep_implicit_receiver_prefixes_are_not_truncated() {
    assert_eq!(
        implicit_receiver_storage_prefixes("this.a.b.c.d.e", &["this".to_string()]),
        vec![
            "this",
            "this.a",
            "this.a.b",
            "this.a.b.c",
            "this.a.b.c.d",
            "this.a.b.c.d.e"
        ]
    );
}

#[test]
fn implicit_receiver_bases_follow_adapter_metadata() {
    let mut decl = empty_decl(1, "f");
    decl.implicit_receiver_names = vec!["me".to_string()];
    decl.flow_events = vec![
        FlowEvent::Assign {
            span: span(10, 20),
            target: "me.data.cmd".to_string(),
            source_name: Some("input".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Assign {
            span: span(30, 40),
            target: "ordinary.data.cmd".to_string(),
            source_name: Some("input".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
    ];

    let out = transfer_function_for(&decl);
    assert_eq!(out.receiver_names, vec!["me".to_string()]);
    assert!(out.implicit_receiver_bases.contains(&"me.data.cmd".to_string()));
    assert!(
        !out.implicit_receiver_bases
            .iter()
            .any(|base| base.starts_with("ordinary")),
        "ordinary identifiers must not become implicit receivers: {:?}",
        out.implicit_receiver_bases
    );
}

#[test]
fn defer_body_walks_through() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Defer {
        span: span(0, 30),
        body: vec![FlowEvent::Return {
            value_kind: None,
            span: span(10, 20),
            value_name: Some("x".to_string()),
            value_text: None,
            value_flow: bonsai_lang_api::ExpressionFlow::from_place("x"),
        }],
    }];
    let out = transfer_function_for(&decl);
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraReturn), 2);
}

#[test]
fn yield_with_bare_identifier_emits_yield_edge() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Yield {
        span: span(20, 30),
        value_text: Some("value".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("value"),
    }];
    let out = transfer_function_for(&decl);
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraYield), 1);
}

#[test]
fn yield_with_compound_expression_uses_structured_operands() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Yield {
        span: span(20, 30),
        // Complex expression — not a bare identifier.
        value_text: Some("x + 1".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_source_names(vec!["x".to_string()]),
    }];
    let out = transfer_function_for(&decl);
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraYield), 1);
}

#[test]
fn aggregate_yield_keeps_boundary_without_collapsing_field_precision() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Yield {
        span: span(20, 40),
        value_text: Some("{'value': raw}".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow {
            aggregate_fields: vec![bonsai_lang_api::ExpressionField {
                name: "value".to_string(),
                value_span: Some(span(30, 33)),
                value: bonsai_lang_api::ExpressionFlow::from_place("raw"),
            }],
            ..Default::default()
        },
    }];

    let out = transfer_function_for(&decl);
    assert!(out
        .nodes
        .lookup(out.func, out.places.lookup(&Place::Yield).expect("yield place"))
        .is_some());
    assert_eq!(
        count_edges_of(&out, IdgEdgeKind::IntraYield),
        0,
        "an exact yielded field must not taint the whole aggregate"
    );
}

#[test]
fn yielding_callback_binding_is_derived_from_flow_shape_not_constructor_name() {
    let outer = span(10, 50);
    let inner = span(25, 50);
    let events = vec![
        FlowEvent::Assign {
            span: outer,
            target: "callback".to_string(),
            source_name: None,
            source_call: Some("arbitrary_factory".to_string()),
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::CallResult),
        },
        FlowEvent::Assign {
            span: inner,
            target: "part".to_string(),
            source_name: None,
            source_call: Some("arbitrary_factory".to_string()),
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::YieldResult),
        },
        FlowEvent::Yield {
            span: span(35, 45),
            value_text: Some("part".to_string()),
            value_flow: bonsai_lang_api::ExpressionFlow::from_place("part"),
        },
    ];

    let names = collect_yield_callback_names(&events);
    assert_eq!(names, ahash::AHashSet::from_iter(["callback".to_string()]));
}

#[test]
fn await_with_value_name_emits_await_edge() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Await {
        span: span(20, 30),
        value_name: Some("promise".to_string()),
    }];
    let out = transfer_function_for(&decl);
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAwait), 1);
}

#[test]
fn break_continue_lifecycle_emit_no_edges() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![
        FlowEvent::Break {
            span: span(10, 15),
            label: None,
        },
        FlowEvent::Continue {
            span: span(20, 28),
            label: None,
        },
    ];
    let out = transfer_function_for(&decl);
    assert_eq!(out.edges.len(), 0);
}

#[test]
fn field_assign_creates_field_write_kind() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Assign {
        span: span(20, 30),
        target: "obj.field".to_string(),
        source_name: Some("x".to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }];
    let out = transfer_function_for(&decl);
    // The source-name → target edge should be an IntraFieldWrite,
    // not a plain IntraAssign, because the target is a field path.
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraFieldWrite), 1);
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 0);
}

#[test]
fn nested_branch_in_try_walks_all_arms() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![FlowEvent::Try {
        span: span(0, 100),
        body: vec![FlowEvent::Branch {
            span: span(10, 60),
            condition: None,
            then_events: vec![FlowEvent::Throw {
                span: span(20, 28),
                value_name: Some("a".to_string()),
                thrown_type: Some("E".to_string()),
            }],
            else_events: vec![FlowEvent::Throw {
                span: span(40, 48),
                value_name: Some("b".to_string()),
                thrown_type: Some("E".to_string()),
            }],
        }],
        catch_events: Vec::new(),
        finally_events: Vec::new(),
        catch_param: Some("ex".to_string()),
        catch_types: vec!["E".to_string()],
        catch_arms: Vec::new(),
    }];
    let out = transfer_function_for(&decl);
    // 2 body throws (Read(a)→Throw, Read(b)→Throw) + 2 throw→catch
    // = 4 IntraThrow.
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraThrow), 4);
    // 1 catch→write(ex)
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 1);
    assert_eq!(out.throw_sites.len(), 2);
}

#[test]
fn each_transfer_output_owns_its_name_pool() {
    // Each call to `transfer_function_for` returns a
    // `TransferOutput` whose `names` pool is independent. The
    // segment merge re-interns names into the segment-level
    // pool, so per-function pool isolation is the contract.
    let mut decl_a = empty_decl(1, "a");
    decl_a.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(0, 10),
        value_name: Some("x".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("x"),
    }];
    let mut decl_b = empty_decl(2, "b");
    decl_b.flow_events = vec![FlowEvent::Return {
        value_kind: None,
        span: span(0, 10),
        value_name: Some("x".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("x"),
    }];
    let out_a = transfer_function_for(&decl_a);
    let out_b = transfer_function_for(&decl_b);
    // Both pools have "x" as their first interned identifier.
    assert!(out_a.names.lookup("x").is_some());
    assert!(out_b.names.lookup("x").is_some());
}

#[test]
fn is_bare_identifier_acceptance() {
    assert!(is_bare_identifier("x"));
    assert!(is_bare_identifier("user_id"));
    assert!(is_bare_identifier("_internal"));
    assert!(is_bare_identifier("a1"));
    assert!(!is_bare_identifier(""));
    assert!(!is_bare_identifier("1abc"));
    assert!(!is_bare_identifier("x.y"));
    assert!(!is_bare_identifier("x + 1"));
    assert!(!is_bare_identifier("\"literal\""));
}

#[test]
fn transfer_for_many_processes_all_decls() {
    let decls: Vec<Decl> = (0..3).map(|i| empty_decl(i, &format!("f{i}"))).collect();
    let outs = transfer_for_many(decls.iter());
    assert_eq!(outs.len(), 3);
    for (i, o) in outs.iter().enumerate() {
        assert_eq!(o.func, FuncId::new(i as u32));
    }
}

#[test]
fn structured_receiver_fact_drives_receiver_flow() {
    let mut decl = empty_decl(1, "f");
    let call_span = span(40, 52);
    decl.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "rendered.receiver.send".to_string(),
        receiver: Some("rendered.receiver".to_string()),
        receiver_types: Vec::new(),
        call_kind: CallKind::Method,
        args: Vec::new(),
    }];
    let receiver_facts = vec![bonsai_lang_api::CallReceiverFact {
        call_span,
        receiver_span: call_span,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("state.client"),
        role: bonsai_lang_api::CallReceiverRole::Value,
        static_value: None,
    }];
    let out = transfer_function_for_with_options_and_syntax_facts(
        &decl,
        &TransferOptions::default(),
        &[],
        &receiver_facts,
    );
    let site = out.call_sites.first().expect("call site");
    let receiver_node = site.receiver_arg_node.expect("receiver node");

    assert_eq!(site.receiver_storage_base.as_deref(), Some("state.client"));
    assert!(out
        .edges
        .iter()
        .any(|edge| { edge.to == receiver_node && rendered_place_name(&out, edge.from) == "state.client" }));
    assert!(!out.edges.iter().any(|edge| {
        edge.to == receiver_node && rendered_place_name(&out, edge.from) == "rendered.receiver"
    }));
}

#[test]
fn namespace_receiver_fact_does_not_create_runtime_receiver_flow() {
    let mut decl = empty_decl(1, "f");
    let call_span = span(40, 52);
    decl.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "pickle.loads".to_string(),
        receiver: Some("pickle".to_string()),
        receiver_types: Vec::new(),
        call_kind: CallKind::Method,
        args: Vec::new(),
    }];
    let receiver_facts = vec![bonsai_lang_api::CallReceiverFact {
        call_span,
        receiver_span: span(40, 46),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("pickle"),
        role: bonsai_lang_api::CallReceiverRole::Namespace,
        static_value: None,
    }];
    let out = transfer_function_for_with_options_and_syntax_facts(
        &decl,
        &TransferOptions::default(),
        &[],
        &receiver_facts,
    );
    let site = out.call_sites.first().expect("call site");

    assert!(site.receiver_arg_node.is_none());
    assert!(site.receiver_storage_base.is_none());
    assert!(out
        .nodes
        .nodes
        .iter()
        .filter_map(|node| out.places.get(node.place))
        .all(|place| !matches!(place, Place::Read { name, .. } if out.names.get(*name) == Some("pickle"))));
}

#[test]
fn structured_implicit_receiver_fact_defers_storage_identity_to_stitching() {
    let mut decl = empty_decl(1, "method");
    decl.implicit_receiver_names = vec!["$this".to_string()];
    let call_span = span(40, 52);
    decl.flow_events = vec![FlowEvent::Call {
        span: call_span,
        name: "$this->value".to_string(),
        receiver: Some("$this".to_string()),
        receiver_types: Vec::new(),
        call_kind: CallKind::Method,
        args: Vec::new(),
    }];
    let receiver_facts = vec![bonsai_lang_api::CallReceiverFact {
        call_span,
        receiver_span: call_span,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("$this"),
        role: bonsai_lang_api::CallReceiverRole::Value,
        static_value: None,
    }];
    let out = transfer_function_for_with_options_and_syntax_facts(
        &decl,
        &TransferOptions::default(),
        &[],
        &receiver_facts,
    );
    let site = out.call_sites.first().expect("call site");

    assert_eq!(site.receiver_storage_base, None);
    assert!(site.receiver_arg_node.is_some());
}

#[test]
fn transfer_fingerprint_canonicalizes_symbolic_adapter_languages() {
    let left = TransferOptions {
        symbolic_field_forwarding: true,
        symbolic_field_languages: vec!["zeta".to_string(), "alpha".to_string(), "alpha".to_string()],
        ..TransferOptions::default()
    };
    let right = TransferOptions {
        symbolic_field_forwarding: true,
        symbolic_field_languages: vec!["alpha".to_string(), "zeta".to_string()],
        ..TransferOptions::default()
    };
    let narrower = TransferOptions {
        symbolic_field_forwarding: true,
        symbolic_field_languages: vec!["alpha".to_string()],
        ..TransferOptions::default()
    };

    assert_eq!(left.semantic_fingerprint(), right.semantic_fingerprint());
    assert_ne!(left.semantic_fingerprint(), narrower.semantic_fingerprint());
}

#[test]
fn transfer_excludes_calls_after_unconditional_return() {
    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![
        FlowEvent::Call {
            span: span(10, 11),
            name: "before".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: Vec::new(),
        },
        FlowEvent::Return {
            span: span(20, 21),
            value_kind: None,
            value_text: None,
            value_name: None,
            value_flow: Default::default(),
        },
        FlowEvent::Call {
            span: span(30, 31),
            name: "dead".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: Vec::new(),
        },
    ];

    let out = transfer_function_for(&decl);
    assert_eq!(
        out.call_sites
            .iter()
            .map(|site| site.callee_name.as_str())
            .collect::<Vec<_>>(),
        ["before"]
    );
}

#[test]
fn transfer_executes_defer_at_scope_exit_in_lifo_order() {
    fn call(at: u64, name: &str) -> FlowEvent {
        FlowEvent::Call {
            span: span(at, at + 1),
            name: name.to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: Vec::new(),
        }
    }

    let mut decl = empty_decl(1, "f");
    decl.flow_events = vec![
        FlowEvent::Defer {
            span: span(10, 11),
            body: vec![call(70, "first_cleanup")],
        },
        FlowEvent::Defer {
            span: span(20, 21),
            body: vec![call(60, "second_cleanup")],
        },
        call(30, "body"),
        FlowEvent::Return {
            span: span(40, 41),
            value_kind: None,
            value_text: None,
            value_name: None,
            value_flow: Default::default(),
        },
        call(50, "dead"),
    ];

    let out = transfer_function_for(&decl);
    assert_eq!(
        out.call_sites
            .iter()
            .map(|site| site.callee_name.as_str())
            .collect::<Vec<_>>(),
        ["body", "second_cleanup", "first_cleanup"]
    );
}
