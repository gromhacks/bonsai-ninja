use super::*;

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

#[test]
fn short_clause_name_does_not_match_def_keyword() {
    let src = "def f(p, 0), do: sink(p)";
    let span = bonsai_common::Span::new(FileId::new(0), 0, u64::try_from(src.len()).unwrap());

    let params = elixir_clause_param_slots(src, span, "f").expect("params");

    assert_eq!(params, vec!["p".to_string(), "_arg1".to_string()]);
}
