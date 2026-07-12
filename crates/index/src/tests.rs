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
        aggregate_layouts: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
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
        aggregate_layouts: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
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
        aggregate_layouts: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
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
fn reinserting_file_replaces_name_lookup_entries() {
    let file = FileId::new(3);
    let mut index = GlobalIndex::new();
    index.insert(DeclIndex {
        file,
        defs: vec![decl(file, 0, "old")],
        refs: Vec::new(),
        aggregate_layouts: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
    });
    index.insert(DeclIndex {
        file,
        defs: vec![decl(file, 0, "new")],
        refs: Vec::new(),
        aggregate_layouts: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
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
