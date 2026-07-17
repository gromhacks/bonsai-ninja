use super::*;
use bonsai_common::{FileId, Span as CommonSpan, SymbolId};
use bonsai_lang_api::{CallArg, ModulePath, Visibility};

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
    bonsai_lang_api::kit::normalize_c_variadic_builtin_flow(&mut decl.flow_events, true);

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
    let out = transfer_function_for(&decl);
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
            span: span(40, 70),
            value_name: None,
            value_text: Some("{\"cmd\": clean, **rest}".to_string()),
            value_flow: bonsai_lang_api::ExpressionFlow {
                aggregate_fields: vec![bonsai_lang_api::ExpressionField {
                    name: "cmd".to_string(),
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
fn tuple_return_emits_position_specific_fields() {
    let mut decl = empty_decl(1, "f");
    decl.params = vec!["p".to_string()];
    decl.flow_events = vec![FlowEvent::Return {
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
            input_receiver: false,
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
            input_receiver: true,
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
        target_span: Some(span(50, 53)),
        value_span: span(55, 88),
        call_sites: vec![call_expression_span],
        value_flow: ExpressionFlow::default(),
        direct_call_name: None,
        direct_call_receiver: None,
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
        target_span: Some(span(20, 23)),
        value_span: span(26, 60),
        call_sites: Vec::new(),
        value_flow: ExpressionFlow {
            aggregate_fields: vec![
                bonsai_lang_api::ExpressionField {
                    name: "command".to_string(),
                    value: ExpressionFlow::from_place("userInput"),
                },
                bonsai_lang_api::ExpressionField {
                    name: "label".to_string(),
                    value: ExpressionFlow::default(),
                },
            ],
            ..ExpressionFlow::default()
        },
        direct_call_name: None,
        direct_call_receiver: None,
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
        source_output_args: Vec::new(),
        source_callback_args: Vec::new(),
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
            value_arg_indices: vec![1],
            value_start_arg_index: None,
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
    assert!(out
        .edges
        .iter()
        .any(|edge| { edge.to == output_write && rendered_place_name(&out, edge.from) == "src" }));
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
    }];
    let out = transfer_function_for(&decl);
    // 1 IntraThrow from the body's Read(e) → Throw(IOException)
    // 1 IntraThrow from Throw(IOException) → Catch(IOException)
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraThrow), 2);
    // 1 IntraAssign from Catch(IOException) → Write(ex)
    assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 1);
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
        span: span(0, 10),
        value_name: Some("x".to_string()),
        value_text: None,
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("x"),
    }];
    let mut decl_b = empty_decl(2, "b");
    decl_b.flow_events = vec![FlowEvent::Return {
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
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("state.client"),
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
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("$this"),
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
