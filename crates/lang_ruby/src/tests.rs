use super::*;

fn normalized_erb_tree(source: &str) -> (String, tree_sitter::Tree) {
    let edits = erb_parser_mask_edits(source).expect("balanced ERB tags");
    let mut normalized = source.as_bytes().to_vec();
    for edit in edits {
        let _ = edit.apply_to(source, &mut normalized);
    }
    let normalized = String::from_utf8(normalized).expect("same-width UTF-8");
    assert_eq!(normalized.len(), source.len());
    let language = language_from_pack(PACK_NAME).expect("ruby grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set ruby grammar");
    let tree = parser.parse(&normalized, None).expect("parse normalized ERB");
    (normalized, tree)
}

#[test]
fn erb_host_projection_preserves_embedded_control_flow_and_spans() {
    let source = "<html>\n<% if @visible %>\n  <%= raw @comment %>\n<% end %>\n</html>\n";
    let (_normalized, tree) = normalized_erb_tree(source);
    assert!(!tree.root_node().has_error());

    let raw_call = collect_kinds(&tree, &["call"])
        .into_iter()
        .find(|node| {
            node.child_by_field_name("method")
                .is_some_and(|method| node_text(&method, source.as_bytes()) == "raw")
        })
        .expect("embedded raw call");
    assert_eq!(raw_call.kind(), "call");
    assert_eq!(node_text(&raw_call, source.as_bytes()).trim(), "raw @comment");
}

#[test]
fn unclosed_erb_tag_is_not_normalized_away() {
    assert!(erb_parser_mask_edits("<p><%= value").is_none());
}

#[test]
fn adjacent_erb_expressions_receive_exact_statement_boundaries() {
    let source = "<div class=\"<%= \"hidden\" if hidden %>\" id=\"item-<%= first %>-<%= second -%>\">\n";
    let (normalized, tree) = normalized_erb_tree(source);
    assert!(!tree.root_node().has_error(), "{normalized:?}");
    assert_eq!(normalized.matches(';').count(), 3);
}

#[test]
fn method_symbol_reference_is_adapter_owned_and_rejects_ordinary_calls() {
    let language = language_from_pack(PACK_NAME).expect("ruby grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set ruby grammar");
    let src = "cb = method(:helper)\nvalue = method(name)\n";
    let tree = parser.parse(src, None).expect("parse ruby source");
    let symbol = collect_kinds(&tree, &["simple_symbol"])
        .into_iter()
        .next()
        .expect("method symbol");
    assert_eq!(symbol.kind(), "simple_symbol");
    let refs = collect_kinds(&tree, &["call"])
        .into_iter()
        .filter_map(|node| extract_ruby_callable_reference(node, src.as_bytes()))
        .collect::<Vec<_>>();
    assert_eq!(refs, vec!["helper"]);
}

#[test]
fn frozen_literal_constant_is_an_immutable_static_value() {
    let src = "class Store\n  ROOT = \"/srv/assets\".freeze\nend\n";
    let language = language_from_pack(PACK_NAME).expect("ruby grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set ruby grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse ruby source");
    let mut index = decl_index_from_tree_with_handler(FileId::new(0), src.as_bytes(), &tree, &HANDLER);
    populate_ruby_static_value_facts(&mut index, &tree, FileId::new(0), src.as_bytes());
    let fact = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("ROOT"))
        .expect("constant assignment fact");
    assert!(fact.target_is_immutable);
    assert_eq!(
        fact.static_value,
        Some(StaticScalarValue::String("/srv/assets".to_string()))
    );
}

#[test]
fn unparenthesized_single_arguments_keep_exact_scalar_and_aggregate_values() {
    let source = "take 'plain'\ntake ['item']\ntake({'key' => 'value'})\n";
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language_from_pack(PACK_NAME).unwrap())
        .unwrap();
    let tree = parser.parse(source, None).unwrap();
    let file = FileId::new(0);
    let mut index = decl_index_from_tree_with_handler(file, source.as_bytes(), &tree, &HANDLER);
    populate_ruby_static_value_facts(&mut index, &tree, file, source.as_bytes());
    let facts = &index.call_argument_values;
    assert!(
        facts
            .iter()
            .any(|fact| fact.static_value == Some(StaticScalarValue::String("plain".into()))),
        "{facts:?}"
    );
    assert!(
        facts
            .iter()
            .any(|fact| fact.exact_static_sequence_values.as_deref()
                == Some(&[Some(StaticScalarValue::String("item".into()))][..])),
        "{facts:?}"
    );
    assert!(
        facts
            .iter()
            .any(|fact| fact.exact_static_aggregate_fields.iter().any(
                |field| field.path == ["key"] && field.value == StaticScalarValue::String("value".into())
            )),
        "{facts:?}"
    );
}

#[test]
fn unless_modifier_marks_the_compiler_condition_as_negated() {
    let src = "def safe(path, root)\n  raise ArgumentError unless path.start_with?(root)\nend\n";
    let language = language_from_pack(PACK_NAME).expect("ruby grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set ruby grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse ruby source");
    let mut index = decl_index_from_tree_with_handler(FileId::new(0), src.as_bytes(), &tree, &HANDLER);
    populate_ruby_unless_condition_facts(&mut index.branch_conditions, &tree, FileId::new(0));
    let fact = index.branch_conditions.first().expect("branch condition fact");
    assert_eq!(fact.polarity, bonsai_lang_api::BranchConditionPolarity::Negated);
    assert!(matches!(
        fact.expression,
        Some(bonsai_lang_api::ConditionExpressionFact::Not { .. })
    ));
}

fn parse_import_specs(src: &str) -> Vec<ImportSpec> {
    let language = language_from_pack(PACK_NAME).expect("ruby grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set ruby grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse ruby source");
    parse_imports(&tree, src.as_bytes(), FileId::new(0))
}

#[test]
fn require_relative_emits_statement_import_and_local_wildcard_binding() {
    let imports = parse_import_specs("require_relative 'helpers'\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "helpers"
            && spec.alias.is_none()
            && !spec.is_wildcard
            && spec.original_name.is_none()
            && spec.scope == ImportScope::Module
    }));
    assert!(imports.iter().any(|spec| {
        spec.module == "helpers"
            && spec.alias.is_none()
            && spec.is_wildcard
            && spec.original_name.is_none()
            && spec.scope == ImportScope::Local
    }));
    assert!(imports.iter().any(|spec| {
        spec.module == "helpers"
            && spec.alias.as_deref() == Some("Helpers")
            && spec.is_wildcard
            && spec.original_name.is_none()
            && spec.scope == ImportScope::Local
    }));
    assert!(!imports.iter().any(|spec| {
        spec.module == "helpers"
            && spec.alias.as_deref() == Some("Helpers")
            && spec.scope == ImportScope::Module
    }));
}

#[test]
fn autoload_does_not_emit_wildcard_callable_import() {
    let imports = parse_import_specs("autoload :Helpers, 'helpers'\n");

    assert!(imports.iter().all(|spec| !spec.is_wildcard));
}
