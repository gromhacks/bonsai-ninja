use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_swift::SwiftAdapter::new());
    run_language_suite!(adapter, trace_from = "main", [("a.swift", "func main() {}")]);
}

#[test]
fn function_typed_parameters_do_not_emit_type_nodes_as_params() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_swift::SwiftAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("App.swift"),
        "func runCb(_ cb: (String) -> Void, _ value: String) {\n    cb(value)\n}\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);

    let run_cb = idx
        .defs
        .iter()
        .find(|decl| decl.name == "runCb")
        .expect("runCb declaration");
    assert_eq!(
        run_cb.params,
        vec!["cb".to_string(), "value".to_string()],
        "Swift parameter extraction must not treat function/user type annotation nodes as bound params"
    );
}

#[test]
fn single_expression_function_records_implicit_return() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_swift::SwiftAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("App.swift"),
        "func echo(_ x: String) -> String { x }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let echo = idx
        .defs
        .iter()
        .find(|decl| decl.name == "echo")
        .expect("echo declaration");

    assert!(echo.has_implicit_returns);
    assert!(
        echo.flow_events
            .iter()
            .any(|event| matches!(event, FlowEvent::Return { value_name, .. } if value_name.as_deref() == Some("x"))),
        "Swift single-expression functions should emit a Return event; events: {:?}",
        echo.flow_events
    );
}
