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

    let raw_call = collect_kinds(&tree, &["call", "method_call"])
        .into_iter()
        .find(|node| {
            node.child_by_field_name("method")
                .is_some_and(|method| node_text(&method, source.as_bytes()) == "raw")
        })
        .expect("embedded raw call");
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
    let refs = collect_kinds(&tree, &["call", "method_call"])
        .into_iter()
        .filter_map(|node| extract_ruby_callable_reference(node, src.as_bytes()))
        .collect::<Vec<_>>();
    assert_eq!(refs, vec!["helper"]);
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
