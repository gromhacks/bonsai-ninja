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
        tree_provider: None,
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
        tree_provider: None,
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

#[test]
fn class_inheritance_and_override_params_are_precise() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_swift::SwiftAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("Storage.swift"),
        r#"
class Repository {
    func run() -> String { "ok" }
}

class AuditedRepository: Repository {
    override func run() -> String {
        return super.run()
    }
}
"#,
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);

    let audited_class = idx
        .defs
        .iter()
        .find(|decl| decl.name == "AuditedRepository")
        .expect("AuditedRepository declaration");
    assert_eq!(
        audited_class.bases,
        vec!["Repository".to_string()],
        "Swift class inheritance must be available to super-call resolution"
    );

    let audited_run = idx
        .defs
        .iter()
        .find(|decl| decl.name == "run" && decl.parent == Some(audited_class.symbol))
        .expect("AuditedRepository.run declaration");
    assert!(
        audited_run.params.is_empty(),
        "Swift return type annotations must not be extracted as function params: {:?}",
        audited_run.params
    );
}

#[test]
fn swiftpm_target_files_share_module_identity() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter, ModulePath};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_swift::SwiftAdapter::new();
    let vfs = Vfs::new();
    let root = std::env::temp_dir().join("bonsai-swift-module-identity");
    let app_file = vfs.write(
        root.join("Sources/App/App.swift"),
        "struct Envelope { var cmd: String }\n",
    );
    let pipeline_file = vfs.write(
        root.join("Sources/App/Pipeline.swift"),
        "func orchestrate(cmd: String) { _ = Envelope(cmd: cmd) }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: Some(&root),
    };

    let app = adapter.extract_declarations(app_file, &ctx);
    let pipeline = adapter.extract_declarations(pipeline_file, &ctx);
    let envelope = app
        .defs
        .iter()
        .find(|decl| decl.name == "Envelope")
        .expect("Envelope declaration");
    let orchestrate = pipeline
        .defs
        .iter()
        .find(|decl| decl.name == "orchestrate")
        .expect("orchestrate declaration");

    assert_eq!(envelope.module_path, ModulePath::from_segments(["App"]));
    assert_eq!(orchestrate.module_path, envelope.module_path);
    assert!(
        envelope
            .qualified_name
            .as_deref()
            .is_some_and(|name| name.ends_with("App::Envelope")),
        "qualified names should retain file display identity: {:?}",
        envelope.qualified_name
    );
}

#[test]
fn swiftpm_sibling_package_targets_do_not_share_module_identity() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter, ModulePath};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_swift::SwiftAdapter::new();
    let vfs = Vfs::new();
    let root = std::env::temp_dir().join("bonsai-swift-sibling-packages");
    let first_file = vfs.write(
        root.join("FlowA/Sources/App/App.swift"),
        "struct Envelope { var cmd: String }\n",
    );
    let second_file = vfs.write(
        root.join("FlowB/Sources/App/App.swift"),
        "struct Envelope { var cmd: String }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: Some(&root),
    };

    let first = adapter.extract_declarations(first_file, &ctx);
    let second = adapter.extract_declarations(second_file, &ctx);
    let first_envelope = first
        .defs
        .iter()
        .find(|decl| decl.name == "Envelope")
        .expect("FlowA Envelope declaration");
    let second_envelope = second
        .defs
        .iter()
        .find(|decl| decl.name == "Envelope")
        .expect("FlowB Envelope declaration");

    assert_eq!(
        first_envelope.module_path,
        ModulePath::from_segments(["FlowA", "App"])
    );
    assert_eq!(
        second_envelope.module_path,
        ModulePath::from_segments(["FlowB", "App"])
    );
    assert_ne!(first_envelope.module_path, second_envelope.module_path);
}

#[test]
fn ad_hoc_sibling_directories_do_not_share_module_identity() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter, Visibility};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_swift::SwiftAdapter::new();
    let vfs = Vfs::new();
    let root = std::env::temp_dir().join("bonsai-swift-ad-hoc-sibling-modules");
    let first_file = vfs.write(
        root.join("FlowA/App.swift"),
        "func handle_request(_ cmd: String) { execute(cmd) }\nfunc execute(_ cmd: String) {}\n",
    );
    let second_file = vfs.write(
        root.join("FlowB/App.swift"),
        "func handle_request(_ cmd: String) { execute(cmd) }\nfunc execute(_ cmd: String) {}\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: Some(&root),
    };

    let first = adapter.extract_declarations(first_file, &ctx);
    let second = adapter.extract_declarations(second_file, &ctx);
    let first_handle = first
        .defs
        .iter()
        .find(|decl| decl.name == "handle_request")
        .expect("FlowA handle_request declaration");
    let second_handle = second
        .defs
        .iter()
        .find(|decl| decl.name == "handle_request")
        .expect("FlowB handle_request declaration");

    assert_eq!(first_handle.visibility, Visibility::Module);
    assert_eq!(second_handle.visibility, Visibility::Module);
    assert_ne!(first_handle.module_path, second_handle.module_path);
    assert_eq!(
        first_handle.module_path.segments.last().map(String::as_str),
        Some("FlowA")
    );
    assert_eq!(
        second_handle.module_path.segments.last().map(String::as_str),
        Some("FlowB")
    );
}

#[test]
fn memberwise_constructor_assignment_projects_fields() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_swift::SwiftAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("App.swift"),
        r#"
struct Envelope {
    var kind: String
    var cmd: String
}

func handle(raw: String) {
    let envelope = Envelope(kind: "run", cmd: raw)
    _ = envelope.cmd
}
"#,
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let handle = idx
        .defs
        .iter()
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");

    assert!(
        handle.flow_events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Assign {
                    target,
                    source_names,
                    ..
                } if target == "envelope.cmd" && source_names.iter().any(|name| name == "raw")
            )
        }),
        "Swift memberwise constructor assignments must project field writes: {:?}",
        handle.flow_events
    );
}

#[test]
fn member_assignment_array_rhs_carries_element_sources() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_swift::SwiftAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("Executor.swift"),
        r#"
func execute(_ input: String) {
    let process = Process()
    process.arguments = ["-c", input]
}
"#,
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let execute = idx
        .defs
        .iter()
        .find(|decl| decl.name == "execute")
        .expect("execute declaration");

    assert!(
        execute.flow_events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Assign {
                    target,
                    source_names,
                    ..
                } if target == "process.arguments" && source_names.iter().any(|name| name == "input")
            )
        }),
        "Swift member assignment array RHS must carry element sources: {:?}",
        execute.flow_events
    );
}

#[test]
fn bare_computed_property_read_is_an_implicit_self_method_call() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, CallKind, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_swift::SwiftAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("Repository.swift"),
        r#"
class Repository {
    let data: String
    init(_ data: String) { self.data = data }
    var cmd: String { data }
    func run() -> String {
        let value = cmd
        return value
    }
}
"#,
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let run = idx
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run declaration");

    assert!(
        run.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                receiver,
                call_kind: CallKind::Method,
                ..
            } if name == "self.cmd" && receiver.as_deref() == Some("self")
        )),
        "Swift bare property reads must retain their implicit self receiver: {:?}",
        run.flow_events
    );
    assert!(run.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Assign { source_call, .. }
            if source_call.as_deref() == Some("self.cmd")
    )));
}

#[test]
fn declared_typealias_canonicalizes_computed_property_receiver_type() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_swift::SwiftAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("Repository.swift"),
        r#"
struct Envelope { var cmd: String }
typealias RepoEnvelope = Envelope
class Repository {
    let data: RepoEnvelope
    init(_ data: RepoEnvelope) { self.data = data }
    var cmd: String { data.cmd }
}
"#,
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let getter = idx
        .defs
        .iter()
        .find(|decl| {
            decl.name == "cmd"
                && decl
                    .flow_events
                    .iter()
                    .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "data.cmd"))
        })
        .expect("computed cmd getter");
    assert!(
        getter.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { receiver_types, .. }
                if receiver_types == &["Envelope".to_string()]
        )),
        "declared typealias must resolve to its AST target: {:?}",
        getter.flow_events
    );
}
