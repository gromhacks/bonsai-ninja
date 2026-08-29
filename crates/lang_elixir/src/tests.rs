use super::*;

#[test]
fn callable_capture_is_adapter_owned_and_structural() {
    let language = language_from_pack(PACK_NAME).expect("elixir grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set elixir grammar");
    let src = "cb = &helper/1\nvalue = helper / other\n";
    let tree = parser.parse(src, None).expect("parse elixir source");
    let captures = collect_kinds(&tree, &["unary_operator"]);
    assert_eq!(captures.len(), 1);
    assert_eq!(
        extract_elixir_callable_reference(captures[0], src.as_bytes()).as_deref(),
        Some("helper")
    );
}

fn parse_import_specs(src: &str) -> Vec<ImportSpec> {
    let language = language_from_pack(PACK_NAME).expect("elixir grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set elixir grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse elixir source");
    parse_imports(&tree, src.as_bytes(), FileId::new(0))
}

#[test]
fn import_emits_statement_import_and_local_wildcard_binding() {
    let imports = parse_import_specs("import Helpers\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "Helpers"
            && spec.alias.is_none()
            && !spec.is_wildcard
            && spec.original_name.is_none()
            && spec.scope == ImportScope::Module
    }));
    assert!(imports.iter().any(|spec| {
        spec.module == "Helpers"
            && spec.alias.is_none()
            && spec.is_wildcard
            && spec.original_name.is_none()
            && spec.scope == ImportScope::Local
    }));
}

#[test]
fn import_only_emits_exact_local_member_bindings_not_a_wildcard() {
    let imports = parse_import_specs("import Plug.Conn, only: [read_body: 1, get_req_header: 2]\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "Plug.Conn"
            && spec.original_name.as_deref() == Some("read_body")
            && spec.alias.is_none()
            && !spec.is_wildcard
            && spec.scope == ImportScope::Local
    }));
    assert!(imports.iter().any(|spec| {
        spec.module == "Plug.Conn"
            && spec.original_name.as_deref() == Some("get_req_header")
            && spec.alias.is_none()
            && !spec.is_wildcard
            && spec.scope == ImportScope::Local
    }));
    assert!(
        imports.iter().all(|spec| !spec.is_wildcard),
        "an exact only-list must not also authorize every module member: {imports:?}"
    );
}

#[test]
fn require_does_not_emit_local_wildcard_binding() {
    let imports = parse_import_specs("require Helpers\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "Helpers"
            && spec.alias.is_none()
            && !spec.is_wildcard
            && spec.original_name.is_none()
            && spec.scope == ImportScope::Module
    }));
    assert!(
        imports.iter().all(|spec| spec.scope != ImportScope::Local),
        "require should not import callable members: {imports:?}"
    );
}

#[test]
fn grouped_alias_expands_each_parser_declared_module_binding() {
    let imports = parse_import_specs("alias MyApp.{Foo, Bar}\n");

    let modules = imports
        .iter()
        .map(|spec| (spec.module.as_str(), spec.alias.as_deref()))
        .collect::<Vec<_>>();
    assert_eq!(
        modules,
        vec![("MyApp.Foo", Some("Foo")), ("MyApp.Bar", Some("Bar"))]
    );
    assert!(imports.iter().all(|spec| {
        !spec.is_wildcard && spec.original_name.is_none() && spec.scope == ImportScope::Module
    }));
}

#[test]
fn alias_rename_is_selected_by_keyword_key_not_option_order() {
    let imports = parse_import_specs("alias MyApp.Service, warn: false, as: Svc\n");

    assert_eq!(imports.len(), 1);
    assert_eq!(imports[0].module, "MyApp.Service");
    assert_eq!(imports[0].alias.as_deref(), Some("Svc"));
}

#[test]
fn non_module_directive_argument_does_not_invent_an_import() {
    assert!(parse_import_specs("alias dynamic_module()\n").is_empty());
}

#[test]
fn guarded_head_is_a_definition_but_an_unrelated_binary_macro_argument_is_not() {
    let src = "def run(argv) when is_list(argv), do: consume(argv)\ncheck left + right\n";
    let language = language_from_pack(PACK_NAME).expect("elixir grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set elixir grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse elixir source");
    let definitions = collect_kinds(&tree, &["call"])
        .into_iter()
        .filter_map(|call| extract_elixir_function_definition(call, src.as_bytes()))
        .map(|definition| node_text(&definition.name, src.as_bytes()).trim().to_string())
        .collect::<Vec<_>>();

    assert_eq!(definitions, vec!["run"]);
}

#[test]
fn do_blocks_remain_block_syntax_and_do_not_invent_callable_declarations() {
    let src = r#"defmodule App do
  def h(input) do
    System.shell(input)
  end
end
"#;
    let language = language_from_pack(PACK_NAME).expect("elixir grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set elixir grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse elixir source");
    let index = decl_index_from_tree_with_handler(FileId::new(0), src.as_bytes(), &tree, &HANDLER);

    assert!(index.defs.iter().any(|decl| decl.name == "h"));
    assert!(
        index.defs.iter().all(|decl| !decl.name.starts_with("<lambda@")),
        "ordinary module/function do blocks are not anonymous callables: {:#?}",
        index.defs
    );
}

fn parse_field_reads(src: &str) -> Vec<Ref> {
    let language = language_from_pack(PACK_NAME).expect("elixir grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set elixir grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse elixir source");
    synthesize_elixir_value_field_reads(&tree, src.as_bytes(), FileId::new(0))
}

#[test]
fn conn_field_dot_access_emits_named_read_ref() {
    let reads = parse_field_reads(
        "defmodule App do\n  def index(conn) do\n    q = conn.query_params\n    q\n  end\nend\n",
    );
    assert!(
        reads
            .iter()
            .any(|r| r.name == "query_params" && r.kind == RefKind::Read),
        "expected a query_params Read ref, got {reads:?}"
    );
}

#[test]
fn every_value_dot_access_emits_a_read_ref_without_name_tables() {
    let reads = parse_field_reads(
        "defmodule App do\n  def index(conn) do\n    a = conn.assigns\n    System.version()\n    a\n  end\nend\n",
    );
    assert!(
        reads
            .iter()
            .any(|r| r.name == "assigns" && r.kind == RefKind::Read),
        "syntax-proven fields should emit Read refs, got {reads:?}"
    );
    assert!(
        reads.iter().all(|r| r.name != "version"),
        "a remote call must not be reclassified as a field read: {reads:?}"
    );
}

#[test]
fn interpolated_map_field_uses_interpolation_identifier_as_its_source() {
    let src = "defmodule App do\n  def build(raw) do\n    envelope = %{cmd: \"#{raw}\", clean: \"literal\"}\n    envelope\n  end\nend\n";
    let language = language_from_pack(PACK_NAME).expect("elixir grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set elixir grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse elixir source");
    let maps = collect_elixir_map_literal_field_assigns(&tree, src.as_bytes(), FileId::new(0));
    let fields = maps.iter().flat_map(|map| map.fields.iter()).collect::<Vec<_>>();

    assert!(fields.iter().any(|event| matches!(
        event,
        FlowEvent::Assign { target, source_names, .. }
            if target == "envelope.cmd" && source_names == &["raw".to_string()]
    )));
    assert!(fields.iter().any(|event| matches!(
        event,
        FlowEvent::Assign { target, source_names, .. }
            if target == "envelope.clean" && source_names.is_empty()
    )));
}

#[test]
fn function_value_dot_call_lowers_from_cst() {
    let src = "defmodule Main do\n  def run(args) do\n    closure = fn -> sink(args) end\n    closure.()\n  end\nend\n";
    let language = language_from_pack(PACK_NAME).expect("elixir grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set elixir grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse elixir source");

    let calls = collect_elixir_local_callable_invocations(&tree, src.as_bytes(), FileId::new(0));
    assert!(
        calls
            .iter()
            .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "closure")),
        "expected local callable Call fact, got {calls:?}"
    );
}

fn parsed_clause_params(src: &str, name: &str) -> (Vec<String>, Vec<(Vec<String>, String)>) {
    let language = language_from_pack(PACK_NAME).expect("elixir grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set elixir grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse elixir source");
    let span = bonsai_common::Span::new(FileId::new(0), 0, u64::try_from(src.len()).unwrap());
    let nodes = elixir_clause_param_nodes(&tree, src.as_bytes(), span, name).expect("parameter nodes");
    let slots = elixir_clause_param_slots(&nodes, src.as_bytes());
    let bindings = nodes
        .iter()
        .flat_map(|node| elixir_param_pattern_bindings(node, src.as_bytes()))
        .collect();
    (slots, bindings)
}

#[test]
fn short_clause_name_does_not_match_def_keyword() {
    let src = "def f(p, 0), do: sink(p)";
    let (params, _) = parsed_clause_params(src, "f");

    assert_eq!(params, vec!["p".to_string(), "_arg1".to_string()]);
}

#[test]
fn struct_pattern_parameter_has_a_distinct_slot_and_field_binding() {
    let src = "defp cmd_of(%Envelope{cmd: cmd}), do: cmd";
    let (params, bindings) = parsed_clause_params(src, "cmd_of");

    assert_eq!(params, vec!["_arg0".to_string()]);
    assert_eq!(bindings, vec![(vec!["cmd".to_string()], "cmd".to_string())]);
}

#[test]
fn keyword_pattern_parameter_keeps_its_binding_name() {
    let src = "def helper(name: name), do: sink(name)";
    let (params, _) = parsed_clause_params(src, "helper");

    assert_eq!(params, vec!["name".to_string()]);
}

#[test]
fn nested_map_tuple_and_list_patterns_retain_exact_projections() {
    let src = "def handle(%{event: {kind, [first | rest]}}), do: {kind, first, rest}";
    let (params, bindings) = parsed_clause_params(src, "handle");

    assert_eq!(params, vec!["_arg0".to_string()]);
    assert_eq!(
        bindings,
        vec![
            (vec!["event".to_string(), "0".to_string()], "kind".to_string()),
            (
                vec!["event".to_string(), "1".to_string(), "*".to_string()],
                "rest".to_string()
            ),
            (
                vec!["event".to_string(), "1".to_string(), "0".to_string()],
                "first".to_string()
            ),
        ]
    );
}

#[test]
fn aliased_pattern_uses_whole_value_binding_as_the_call_slot() {
    let src = "def handle(%{data: data} = message), do: {data, message}";
    let (params, bindings) = parsed_clause_params(src, "handle");

    assert_eq!(params, vec!["message".to_string()]);
    assert_eq!(bindings, vec![(vec!["data".to_string()], "data".to_string())]);
}

#[test]
fn piped_named_aggregate_retains_exact_call_argument_fields() {
    let src = "defmodule Example do\n  def send(value) do\n    %{target: value, safe: \"literal\"} |> consume()\n  end\nend\n";
    let language = language_from_pack(PACK_NAME).expect("elixir grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set elixir grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse elixir source");
    let file = FileId::new(0);
    let index = decl_index_from_tree_with_handler(file, src.as_bytes(), &tree, &HANDLER);

    let argument = index
        .call_argument_values
        .iter()
        .find(|fact| fact.argument_index == 0 && !fact.value_flow.aggregate_fields.is_empty())
        .expect("pipe-injected aggregate argument fact");
    assert_eq!(
        argument
            .value_flow
            .aggregate_fields
            .iter()
            .map(|field| (field.name.as_str(), field.value.place.as_deref()))
            .collect::<Vec<_>>(),
        vec![("target", Some("value")), ("safe", None)]
    );
}
