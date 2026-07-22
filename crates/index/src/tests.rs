use super::*;
use bonsai_common::{FileId, Span, SymbolId};
use bonsai_lang_api::Visibility;

fn decl(file: FileId, local_symbol: u32, name: &str) -> Decl {
    let span = Span::new(file, 0, u64::try_from(name.len()).unwrap());
    Decl {
        symbol: SymbolId::new(local_symbol),
        kind: DeclKind::Function,
        name: name.to_string(),
        qualified_name: Some(format!("file{}::{name}", file.raw())),
        module_path: bonsai_lang_api::ModulePath::default(),
        span,
        name_span: span,
        visibility: Visibility::Private,
        parent: None,
        body_span: Some(span),
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

#[test]
fn len_and_empty_track_live_decls_after_removal() {
    let file = FileId::new(7);
    let mut index = GlobalIndex::new();
    index.insert(DeclIndex {
        file,
        defs: vec![decl(file, 0, "one"), decl(file, 1, "two")],
        refs: Vec::new(),
        assignment_values: Vec::new(),
        aggregate_layouts: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
        call_receivers: Vec::new(),
        runtime_type_narrowings: Vec::new(),
        branch_conditions: Vec::new(),
    });

    assert_eq!(index.len(), 2);
    assert!(!index.is_empty());

    index.remove_file(file);

    assert_eq!(index.len(), 0);
    assert!(index.is_empty());
    assert!(index.find_by_name("file7::one").is_empty());
}

#[test]
fn insert_dedupes_identical_adapter_declarations() {
    let file = FileId::new(11);
    let mut index = GlobalIndex::new();
    index.insert(DeclIndex {
        file,
        defs: vec![decl(file, 0, "dupe"), decl(file, 1, "dupe")],
        refs: Vec::new(),
        assignment_values: Vec::new(),
        aggregate_layouts: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
        call_receivers: Vec::new(),
        runtime_type_narrowings: Vec::new(),
        branch_conditions: Vec::new(),
    });

    assert_eq!(index.len(), 1);
    assert_eq!(index.decls_in(file).len(), 1);
    assert_eq!(index.find_by_name("dupe").len(), 1);
    assert_eq!(index.find_by_name("file11::dupe").len(), 1);
}

#[test]
fn insert_merges_duplicate_declaration_facts() {
    let file = FileId::new(12);
    let fact_span = Span::new(file, 2, 7);
    let mut duplicate = decl(file, 1, "dupe");
    duplicate.flow_events.push(FlowEvent::Return {
        span: fact_span,
        value_text: Some("value".to_string()),
        value_name: Some("value".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("value"),
    });
    duplicate.has_implicit_returns = true;
    duplicate.params = vec!["value".to_string()];
    duplicate.param_annotations = vec![vec!["RequestParam".to_string()]];
    duplicate.type_aliases.push(bonsai_lang_api::TypeAliasBinding {
        name: "value".to_string(),
        type_name: "Payload".to_string(),
    });
    duplicate.bases.push("Base".to_string());
    duplicate.receiver_param_index = Some(0);
    duplicate.receiver_field_writes.push(bonsai_lang_api::FieldWrite {
        span: fact_span,
        target: "self.value".to_string(),
        source_param_indices: vec![0],
    });
    duplicate.implicit_receiver_names.push("this".to_string());
    duplicate.receiver_state_sources.push("self.value".to_string());
    duplicate.return_type = Some("String".to_string());

    let mut index = GlobalIndex::new();
    index.insert(DeclIndex {
        file,
        defs: vec![decl(file, 0, "dupe"), duplicate],
        refs: Vec::new(),
        assignment_values: Vec::new(),
        aggregate_layouts: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
        call_receivers: Vec::new(),
        runtime_type_narrowings: Vec::new(),
        branch_conditions: Vec::new(),
    });

    let decl = index
        .decls_in(file)
        .first()
        .expect("deduped declaration should remain");
    assert_eq!(index.decls_in(file).len(), 1);
    assert_eq!(decl.flow_events.len(), 1);
    assert!(decl.has_implicit_returns);
    assert_eq!(decl.params, vec!["value".to_string()]);
    assert_eq!(decl.param_annotations, vec![vec!["RequestParam".to_string()]]);
    assert_eq!(decl.type_aliases.len(), 1);
    assert_eq!(decl.bases, vec!["Base".to_string()]);
    assert_eq!(decl.receiver_param_index, Some(0));
    assert_eq!(decl.receiver_field_writes.len(), 1);
    assert_eq!(decl.implicit_receiver_names, vec!["this".to_string()]);
    assert_eq!(decl.receiver_state_sources, vec!["self.value".to_string()]);
    assert_eq!(decl.return_type.as_deref(), Some("String"));
}

#[test]
fn compiler_headers_rebind_streamed_bodies_to_stable_symbols() {
    let first_file = FileId::new(20);
    let body_file = FileId::new(21);
    let mut first = decl(first_file, 0, "first");
    first.flow_events.push(FlowEvent::Return {
        span: first.span,
        value_text: Some("value".to_string()),
        value_name: Some("value".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("value"),
    });
    let mut body = decl(body_file, 7, "body");
    body.flow_events.push(FlowEvent::Return {
        span: body.span,
        value_text: Some("input".to_string()),
        value_name: Some("input".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("input"),
    });
    let body_index = DeclIndex {
        file: body_file,
        defs: vec![body],
        ..DeclIndex::default()
    };

    let mut global = GlobalIndex::new();
    global.insert_header_preprocessed(DeclIndex {
        file: first_file,
        defs: vec![first],
        ..DeclIndex::default()
    });
    global.insert_header_preprocessed(body_index.clone());
    global.finalize_semantic_facts();

    let header = global.decls_in(body_file).first().expect("header");
    assert!(header.flow_events.is_empty());
    assert_eq!(header.symbol, SymbolId::new(1));

    let rebound = global.remap_file_to_existing_symbols(body_index);
    assert_eq!(rebound.defs[0].symbol, header.symbol);
    assert_eq!(rebound.defs[0].flow_events.len(), 1);
}

#[test]
fn linkage_headers_flatten_exact_ast_facts_and_drop_flow_bodies() {
    let file = FileId::new(22);
    let call_span = Span::new(file, 20, 35);
    let arg_span = Span::new(file, 30, 34);
    let return_span = Span::new(file, 40, 57);
    let mut function = decl(file, 9, "value");
    function.flow_events.push(FlowEvent::Branch {
        span: Span::new(file, 10, 60),
        condition: Some("ready".to_string()),
        then_events: vec![
            FlowEvent::Call {
                span: call_span,
                name: "receiver.run".to_string(),
                receiver: Some("receiver".to_string()),
                receiver_types: vec!["Runner".to_string()],
                call_kind: bonsai_lang_api::CallKind::Method,
                args: vec![bonsai_lang_api::CallArg {
                    span: arg_span,
                    passing_mode: bonsai_lang_api::ArgumentPassingMode::Value,
                    name: None,
                    value_text: "input".to_string(),
                    place: Some("input".to_string()),
                    source_names: vec!["input".to_string()],
                }],
            },
            FlowEvent::Assign {
                span: call_span,
                target: "output".to_string(),
                source_name: None,
                source_call: Some("run".to_string()),
                source_call_args: vec!["input".to_string()],
                source_names: Vec::new(),
                declares_new_binding: true,
                value_kind: None,
            },
            FlowEvent::Return {
                span: return_span,
                value_text: Some("self.value".to_string()),
                value_name: None,
                value_flow: bonsai_lang_api::ExpressionFlow::from_place("self.value"),
            },
        ],
        else_events: Vec::new(),
    });

    let mut global = GlobalIndex::new();
    global.insert_linkage_header_preprocessed(DeclIndex {
        file,
        defs: vec![function],
        ..DeclIndex::default()
    });

    let header = global.decls_in(file).first().expect("linkage header");
    assert!(header.flow_events.is_empty());
    let symbol = header.symbol;
    let facts = global.linkage_facts(symbol).expect("compact linkage facts");
    assert_eq!(facts.calls.len(), 1);
    assert_eq!(facts.calls[0].span, call_span);
    assert_eq!(&*facts.calls[0].name, "receiver.run");
    assert_eq!(facts.calls[0].receiver.as_deref(), Some("receiver"));
    assert_eq!(&*facts.calls[0].arg_spans, &[arg_span]);
    assert_eq!(facts.call_result_assignments.len(), 1);
    assert!(facts.call_result_assignments[0].has_explicit_args);
    assert_eq!(&*facts.returned_projection_tails[0], "value");
    assert!(facts.has_summary_output);

    global.remove_file(file);
    assert!(global.linkage_facts(symbol).is_none());
}

#[test]
fn linkage_wire_is_canonical_and_rebuilds_compiler_indexes() {
    let file = FileId::new(25);
    let call_span = Span::new(file, 10, 20);
    let mut function = decl(file, 1, "handler");
    function.flow_events.push(FlowEvent::Call {
        span: call_span,
        name: "consume".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: bonsai_lang_api::CallKind::Function,
        args: Vec::new(),
    });
    let body = DeclIndex {
        file,
        defs: vec![function],
        ..DeclIndex::default()
    };
    let mut global = GlobalIndex::new();
    global.insert_linkage_header_preprocessed(body.clone());
    global.finalize_semantic_facts();

    let first = bonsai_common::wire::encode_struct_map(&global).expect("encode linkage index");
    let second = bonsai_common::wire::encode_struct_map(&global).expect("repeat linkage encoding");
    assert_eq!(first, second, "linkage wire order must be deterministic");

    let mut restored: GlobalIndex = bonsai_common::wire::decode(&first).expect("decode linkage index");
    let symbol = restored.find_by_name("handler")[0];
    assert_eq!(restored.declaring_file(symbol), Some(file));
    assert_eq!(
        restored.linkage_facts(symbol).expect("persisted linkage").calls[0].span,
        call_span
    );
    let rebound = restored.remap_file_to_existing_symbols(body);
    assert_eq!(rebound.defs[0].symbol, symbol);
    restored.remove_file(file);
    assert!(restored.decl_of(symbol).is_none());
    assert!(restored.find_by_name("handler").is_empty());
}

#[test]
fn scalar_return_survives_as_a_compact_summary_fact() {
    let file = FileId::new(23);
    let mut function = decl(file, 1, "identity");
    function.flow_events.push(FlowEvent::Return {
        span: Span::new(file, 10, 22),
        value_text: Some("input".to_string()),
        value_name: Some("input".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("input"),
    });

    let mut global = GlobalIndex::new();
    global.insert_linkage_header_preprocessed(DeclIndex {
        file,
        defs: vec![function],
        ..DeclIndex::default()
    });

    let symbol = global.decls_in(file)[0].symbol;
    let facts = global.linkage_facts(symbol).expect("scalar return linkage fact");
    assert!(facts.has_summary_output);
    assert!(facts.calls.is_empty());
    assert!(facts.returned_projection_tails.is_empty());
}

#[test]
fn returned_constructor_survives_as_a_compact_type_fact() {
    let file = FileId::new(24);
    let call_span = Span::new(file, 40, 43);
    let return_span = Span::new(file, 40, 49);
    let mut factory = decl(file, 1, "wrap");
    factory.flow_events.extend([
        FlowEvent::Call {
            span: call_span,
            name: "new".to_string(),
            receiver: None,
            receiver_types: vec!["Repository".to_string()],
            call_kind: bonsai_lang_api::CallKind::Constructor,
            args: Vec::new(),
        },
        FlowEvent::Return {
            span: return_span,
            value_text: Some("new(data)".to_string()),
            value_name: None,
            value_flow: bonsai_lang_api::ExpressionFlow {
                call_sites: vec![return_span],
                ..Default::default()
            },
        },
    ]);

    let mut global = GlobalIndex::new();
    global.insert_linkage_header_preprocessed(DeclIndex {
        file,
        defs: vec![factory],
        ..DeclIndex::default()
    });

    let header = &global.decls_in(file)[0];
    assert!(header.flow_events.is_empty());
    let facts = global
        .linkage_facts(header.symbol)
        .expect("returned constructor linkage fact");
    assert_eq!(facts.returned_constructor_calls.len(), 1);
    let returned = &facts.returned_constructor_calls[0];
    assert_eq!(&*returned.name, "new");
    assert_eq!(returned.receiver, None);
    assert_eq!(
        returned
            .receiver_types
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<&str>>(),
        vec!["Repository"]
    );
}

#[test]
fn reinserting_file_replaces_name_lookup_entries() {
    let file = FileId::new(3);
    let mut index = GlobalIndex::new();
    index.insert(DeclIndex {
        file,
        defs: vec![decl(file, 0, "old")],
        refs: Vec::new(),
        assignment_values: Vec::new(),
        aggregate_layouts: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
        call_receivers: Vec::new(),
        runtime_type_narrowings: Vec::new(),
        branch_conditions: Vec::new(),
    });
    index.insert(DeclIndex {
        file,
        defs: vec![decl(file, 0, "new")],
        refs: Vec::new(),
        assignment_values: Vec::new(),
        aggregate_layouts: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
        call_receivers: Vec::new(),
        runtime_type_narrowings: Vec::new(),
        branch_conditions: Vec::new(),
    });

    assert_eq!(index.len(), 1);
    assert!(index.find_by_name("file3::old").is_empty());
    let new_symbols = index.find_by_name("file3::new");
    assert_eq!(new_symbols.len(), 1);
    assert_eq!(
        index.decl_of(new_symbols[0]).map(|d| d.name.as_str()),
        Some("new")
    );
}
