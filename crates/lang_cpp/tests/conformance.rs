use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_cpp::CppAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("m.cpp", "int main() { return 0; }")]
    );
}

/// Drift guard for the semantic-identity contract
/// (`docs/contributing/design-patterns.mdx::Semantic Resolution Always`). The C++
/// adapter must:
///
/// - emit `Decl.qualified_name = Some("<file_stem>.<name>")` for
///   every function — never `None`;
/// - emit `Decl.module_path = ["<file_stem>"]`;
/// - mark `static` free functions AND functions inside an anonymous
///   namespace as `Visibility::Private` so the resolver's per-file
///   filter prevents cross-TU collisions.
#[test]
fn cpp_adapter_marks_static_and_anonymous_ns_private() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter, Visibility};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("vendor.cpp"),
        "static void error(const char *msg) {}\n\
         namespace { void helper(int x) {} }\n\
         void exposed(int x) {}\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);

    let by_name = |name: &str| {
        idx.defs
            .iter()
            .find(|d| d.name == name)
            .unwrap_or_else(|| panic!("expected decl {name} present"))
    };

    let error_decl = by_name("error");
    assert_eq!(
        error_decl.qualified_name.as_deref(),
        Some("vendor.error"),
        "qualified_name must be file-stem-prefixed"
    );
    assert_eq!(
        error_decl.module_path.segments,
        vec!["vendor".to_string()],
        "module_path is the file stem when no namespace applies"
    );
    assert!(
        matches!(error_decl.visibility, Visibility::Private),
        "static C++ functions must be Visibility::Private"
    );

    let helper_decl = by_name("helper");
    assert!(
        matches!(helper_decl.visibility, Visibility::Private),
        "anonymous-namespace C++ functions must be Visibility::Private"
    );

    let exposed_decl = by_name("exposed");
    assert!(
        matches!(exposed_decl.visibility, Visibility::Public),
        "non-static, non-anonymous-ns C++ functions are visible"
    );
}

#[test]
fn cpp_adapter_uses_ast_class_identity_for_constructors_and_return_fields() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, DeclKind, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("model.cpp"),
        "struct Model {\n\
             explicit Model(int value) : value_(value) {}\n\
             const int& value() const { return value_; }\n\
             int value_;\n\
         };\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);

    let constructor = idx
        .defs
        .iter()
        .find(|decl| decl.name == "Model" && decl.params == ["value"])
        .expect("constructor declaration");
    assert_eq!(constructor.kind, DeclKind::Constructor);
    assert!(
        constructor
            .receiver_field_writes
            .iter()
            .any(|write| write.target == "this.value_" && write.source_param_indices == [0]),
        "initializer-list field write must remain an AST fact: {constructor:#?}"
    );

    let accessor = idx
        .defs
        .iter()
        .find(|decl| decl.name == "value" && decl.params.is_empty())
        .expect("accessor declaration");
    assert!(
        accessor.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Return { value_flow, .. }
                if value_flow.place.as_deref() == Some("this.value_")
        )),
        "field return must be lowered from the return-expression CST: {accessor:#?}"
    );
}

#[test]
fn cpp_adapter_lowers_direct_initialization_as_a_constructor_call() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, CallKind, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("direct.cpp"),
        "struct Model { explicit Model(int value) {} };\n\
         int build(int value) { Model model(std::move(value)); return 0; }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let build = idx
        .defs
        .iter()
        .find(|decl| decl.name == "build")
        .expect("build declaration");
    assert!(
        build.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                call_kind: CallKind::Constructor,
                args,
                ..
            } if name == "Model"
                && args.len() == 1
                && args[0].place.as_deref() == Some("value")
        )),
        "direct initialization must retain its grammar-owned constructor boundary: {build:#?}"
    );
}

#[test]
fn cpp_adapter_lowers_base_initializer_as_a_constructor_call() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, CallKind, DeclKind, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("base.cpp"),
        "struct Base { explicit Base(int value) {} };\n\
         struct Model : Base { explicit Model(int value) : Base(value) {} };\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let model = idx
        .defs
        .iter()
        .find(|decl| decl.name == "Model" && decl.kind == DeclKind::Constructor)
        .expect("Model constructor");
    assert!(
        model.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                call_kind: CallKind::Constructor,
                args,
                ..
            } if name == "Base"
                && args.len() == 1
                && args[0].place.as_deref() == Some("value")
        )),
        "base initializer must retain its grammar-owned constructor boundary: {model:#?}"
    );
}

#[test]
fn cpp_adapter_preserves_positional_aggregate_syntax_facts() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let header = vfs.write(
        std::path::Path::new("envelope.hpp"),
        "struct Envelope { int kind; const char *cmd; const char *user; };\n",
    );
    let source = vfs.write(
        std::path::Path::new("app.cpp"),
        "int main(int argc, char **argv) { std::string raw = argv[1]; Envelope env{0, raw.size(), raw}; return 0; }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };

    let header_idx = adapter.extract_declarations(header, &ctx);
    assert_eq!(
        header_idx.aggregate_layouts,
        vec![bonsai_lang_api::AggregateLayout {
            type_name: "Envelope".to_string(),
            fields: vec!["kind".to_string(), "cmd".to_string(), "user".to_string()],
        }]
    );

    let source_idx = adapter.extract_declarations(source, &ctx);
    let main = source_idx
        .defs
        .iter()
        .find(|decl| decl.name == "main")
        .expect("main declaration");
    assert!(
        main.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::AggregateAssign {
                target,
                type_name: Some(type_name),
                value_flow,
                ..
            } if target == "env" && type_name == "Envelope" && value_flow.tuple_items.len() == 3
        )),
        "aggregate initializer must remain ordered AST data: {main:#?}"
    );
}
