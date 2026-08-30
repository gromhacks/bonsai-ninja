use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_swift::SwiftAdapter::new());
    run_language_suite!(adapter, trace_from = "main", [("a.swift", "func main() {}")]);
}

#[test]
fn unified_nominal_declaration_cst_keeps_exact_swift_kinds() {
    use bonsai_lang_api::DeclKind;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[(
            "Nominals.swift",
            "class Object {}\nstruct Envelope { let value: String }\nenum State { case ready }\nprotocol Payload {}\nextension Envelope { func render() {} }\n",
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Swift declaration index");

    for (name, kind) in [
        ("Object", DeclKind::Class),
        ("Envelope", DeclKind::Struct),
        ("State", DeclKind::Enum),
        ("Payload", DeclKind::Interface),
    ] {
        assert!(
            index
                .defs
                .iter()
                .any(|decl| decl.name == name && decl.kind == kind),
            "missing {name}: {kind:?}; declarations={:#?}",
            index.defs
        );
    }
    assert!(
        index.defs.iter().any(|decl| {
            decl.name == "render"
                && decl.kind == DeclKind::Method
                && decl.parent.and_then(|parent| {
                    index
                        .defs
                        .iter()
                        .find(|candidate| candidate.symbol == parent)
                        .map(|owner| owner.name.as_str())
                }) == Some("Envelope")
        }),
        "extension method lost its exact nominal parent: {:#?}",
        index.defs
    );
}

#[test]
fn class_stored_property_has_one_compiler_getter_and_computed_getter_is_not_duplicated() {
    use bonsai_lang_api::{DeclKind, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[(
            "Stored.swift",
            r#"
class Record {
    var value: String = ""
    var computed: String { value }
    func read() -> String { self.value }
}
protocol Contract { var value: String { get } }
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Swift declaration index");
    let record = index
        .defs
        .iter()
        .find(|decl| decl.name == "Record" && decl.kind == DeclKind::Class)
        .expect("Record class");
    let stored = index
        .defs
        .iter()
        .filter(|decl| decl.parent == Some(record.symbol) && decl.name == "value" && decl.params.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        stored.len(),
        1,
        "stored property must own one getter: {:#?}",
        index.defs
    );
    assert!(stored[0].flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Return { value_flow, .. }
            if value_flow.place.as_deref() == Some("self.value")
    )));
    assert_eq!(
        index
            .defs
            .iter()
            .filter(|decl| {
                decl.parent == Some(record.symbol) && decl.name == "computed" && decl.params.is_empty()
            })
            .count(),
        1,
        "computed property synthesis must remain unique"
    );
    let contract = index
        .defs
        .iter()
        .find(|decl| decl.name == "Contract" && decl.kind == DeclKind::Interface)
        .expect("Contract protocol");
    assert!(
        index.defs.iter().all(|decl| {
            decl.parent != Some(contract.symbol)
                || decl.name != "value"
                || !decl.flow_events.iter().any(|event| {
                    matches!(
                        event,
                        FlowEvent::Return { value_flow, .. }
                            if value_flow.place.as_deref() == Some("self.value")
                    )
                })
        }),
        "a protocol requirement must not invent concrete stored state"
    );
}

#[test]
fn navigation_calls_emit_one_exact_separator_and_receiver() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_swift::SwiftAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "App.swift",
            "func example(task: Task) { task.cancel(); task.result() }",
        )],
    );
    let global = ws.db().global_index();
    let example = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "example")
        .expect("example declaration");
    let calls = example
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, receiver, .. } => Some((name.as_str(), receiver.as_deref())),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(calls.contains(&("task.cancel", Some("task"))), "{calls:?}");
    assert!(calls.contains(&("task.result", Some("task"))), "{calls:?}");
    assert!(calls.iter().all(|(name, _)| !name.contains("..")), "{calls:?}");
}

#[test]
fn plain_module_imports_and_symbol_imports_keep_distinct_binding_scope() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[(
            "Imports.swift",
            "import Vapor\nimport struct Foundation.URL\nimport func Glibc.exit\n",
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let imports = workspace.db().import_index(file).expect("Swift import index");

    let vapor = imports
        .imports
        .iter()
        .find(|import| import.module == "Vapor")
        .expect("plain module import");
    assert!(vapor.is_wildcard, "plain module imports expose public members");

    for symbol in ["Foundation.URL", "Glibc.exit"] {
        let imported = imports
            .imports
            .iter()
            .find(|import| import.module == symbol)
            .unwrap_or_else(|| panic!("missing symbol import {symbol}: {:#?}", imports.imports));
        assert!(
            !imported.is_wildcard,
            "symbol-kind import {symbol} must not authorize unrelated bare bindings"
        );
    }
}

#[test]
fn labeled_call_arguments_keep_exact_compiler_names() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[(
            "Arguments.swift",
            r#"
func build(_ input: URL, _ bytes: [UInt8]) {
    _ = Data(contentsOf: input)
    _ = Data(bytes)
}
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Swift declaration index");
    let build = index
        .defs
        .iter()
        .find(|decl| decl.name == "build")
        .expect("build declaration");
    let arguments = build
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name == "Data" => args.first(),
            _ => None,
        })
        .map(|argument| (argument.name.as_deref(), argument.value_text.as_str()))
        .collect::<Vec<_>>();

    assert!(
        arguments.contains(&(Some("contentsOf"), "input")),
        "labeled argument missing its compiler name: {arguments:#?}"
    );
    assert!(
        arguments.contains(&(None, "bytes")),
        "ordinary positional construction must remain unlabeled: {arguments:#?}"
    );
}

#[test]
fn switch_value_binding_uses_the_switch_subject() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_swift::SwiftAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "A.swift",
            "func main(_ subject: String) { switch subject { case let value: sink(value) } }\nfunc sink(_ value: String) {}",
        )],
    );
    let global = ws.db().global_index();
    let main = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "main")
        .expect("main declaration");
    let mut facts = Vec::new();
    collect_assignments(&main.flow_events, &mut facts);
    assert!(
        facts
            .iter()
            .any(|(target, source)| target == "value" && source.as_deref() == Some("subject")),
        "missing value <- subject: {facts:#?}"
    );
    assert!(facts.iter().all(|(target, _)| target != "String"));

    fn collect_assignments(events: &[FlowEvent], out: &mut Vec<(String, Option<String>)>) {
        for event in events {
            match event {
                FlowEvent::Assign {
                    target, source_name, ..
                } => out.push((target.clone(), source_name.clone())),
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    collect_assignments(then_events, out);
                    collect_assignments(else_events, out);
                }
                _ => {}
            }
        }
    }
}

#[test]
fn guard_optional_binding_preserves_initializer_call_and_assignment() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_swift::SwiftAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Guard.swift",
            "struct Parsed { init?(_ raw: String) {} }\n\
             func consume(_ value: Parsed) {}\n\
             func handle(_ raw: String) {\n\
               guard let parsed = Parsed(raw) else { return }\n\
               consume(parsed)\n\
             }\n\
             func check(_ ready: Bool) { guard ready else { return } }",
        )],
    );
    let global = ws.db().global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");

    assert!(
        handle.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_call: Some(source_call),
                source_call_args,
                declares_new_binding: true,
                value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
                ..
            } if target == "parsed"
                && source_call == "Parsed"
                && source_call_args == &["raw"]
        )),
        "guard binding must retain its exact initializer call: {:#?}",
        handle.flow_events
    );
    assert!(
        handle
            .flow_events
            .iter()
            .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "Parsed")),
        "guard initializer call must remain independently matchable: {:#?}",
        handle.flow_events
    );

    let check = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "check")
        .expect("check declaration");
    assert!(
        check
            .flow_events
            .iter()
            .all(|event| !matches!(event, FlowEvent::Assign { .. })),
        "an ordinary boolean guard must not invent a binding: {:#?}",
        check.flow_events
    );
}

#[test]
fn lowercase_declared_types_remain_receiver_evidence() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_swift::SwiftAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "App.swift",
            "class lower { func run(_ value: String) {} }\n\
             func handle(_ value: String) {\n\
               let declared = lower(); declared.run(value)\n\
             }",
        )],
    );
    let global = ws.db().global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");
    assert!(
        handle.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, receiver_types, .. }
                if name.rsplit('.').next() == Some("run")
                    && receiver_types.iter().any(|ty| ty == "lower")
        )),
        "events: {:#?}",
        handle.flow_events
    );
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
fn parameter_attributes_are_parallel_with_parameter_bindings() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_swift::SwiftAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("App.swift"),
        "func handle(_ value: String, _ callback: @escaping (String) -> String) -> String { callback(value) }\n",
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
    assert_eq!(handle.params, ["value", "callback"]);
    assert_eq!(
        handle.param_annotations,
        [Vec::<String>::new(), vec!["escaping".to_string()]]
    );
}

#[test]
fn switch_expression_with_only_literal_results_emits_finite_selection() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[(
            "Selection.swift",
            r#"
func choose(_ key: String) -> String {
    return switch key {
    case "short": "s"
    case "long": "l"
    default: "fallback"
    }
}

func passthrough(_ key: String) -> String {
    return switch key {
    case "short": "s"
    default: key
    }
}
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Swift declaration index");
    let choose = index
        .defs
        .iter()
        .find(|decl| decl.name == "choose")
        .expect("choose declaration");
    let passthrough = index
        .defs
        .iter()
        .find(|decl| decl.name == "passthrough")
        .expect("passthrough declaration");

    assert!(
        index
            .finite_literal_selections
            .iter()
            .any(|fact| fact.selection_span.file == choose.span.file
                && choose.span.start <= fact.selection_span.start
                && fact.selection_span.end <= choose.span.end),
        "complete literal switch must be a finite selection: facts={:#?}; events={:#?}",
        index.finite_literal_selections,
        choose.flow_events
    );
    assert!(
        index
            .finite_literal_selections
            .iter()
            .all(|fact| !(passthrough.span.start <= fact.selection_span.start
                && fact.selection_span.end <= passthrough.span.end)),
        "a dynamic switch arm must fail closed: {:#?}",
        index.finite_literal_selections
    );
}

#[test]
fn immutable_dictionary_lookup_with_literal_fallback_is_finite() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[(
            "Selection.swift",
            r#"
struct OrderRepo {
    private static let sortable = ["total": "total", "created_at": "created_at"]
    private static var mutable = ["total": "total"]
    private static let dynamic = ["total": runtimeValue()]

    func choose(_ key: String) {
        let col = Self.sortable[key] ?? "id"
        let mutableCol = Self.mutable[key] ?? "id"
        let dynamicCol = Self.dynamic[key] ?? "id"
        let dynamicFallback = Self.sortable[key] ?? key
        let local = ["one": "first", "two": "second"]
        let localCol = local[key] ?? "fallback"
        consume(col, mutableCol, dynamicCol, dynamicFallback, localCol)
    }
}
func runtimeValue() -> String { "runtime" }
func consume(_: String, _: String, _: String, _: String, _: String) {}
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Swift declaration index");
    let targets = index
        .finite_literal_selections
        .iter()
        .filter_map(|fact| fact.target.as_deref())
        .collect::<Vec<_>>();
    assert_eq!(
        targets,
        vec!["col", "localCol"],
        "only immutable complete dictionaries with literal fallbacks are finite: {:#?}",
        index.finite_literal_selections
    );
}

#[test]
fn enum_associated_value_case_is_an_exact_constructor_boundary() {
    use bonsai_lang_api::{DeclKind, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[(
            "Events.swift",
            r#"
enum Event {
    case message(String)
    case empty
}

func wrap(_ value: String) -> Event { Event.message(value) }
func unwrap(_ event: Event) -> String {
    switch event {
    case .message(let value): return value
    case .empty: return ""
    }
}
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let parsed = workspace.db().parse(file).expect("parse Swift enum");
    let index = workspace.db().decl_index(file).expect("Swift declaration index");
    let event = index
        .defs
        .iter()
        .find(|decl| decl.name == "Event" && decl.kind == DeclKind::Enum)
        .expect("Event enum declaration");
    let constructor = index
        .defs
        .iter()
        .find(|decl| {
            decl.name == "message" && decl.kind == DeclKind::Constructor && decl.parent == Some(event.symbol)
        })
        .unwrap_or_else(|| {
            panic!(
                "associated-value case constructor; tree={}; decls={:#?}",
                parsed.tree.root_node().to_sexp(),
                index.defs
            )
        });
    assert_eq!(constructor.params, ["value0"]);
    assert_eq!(constructor.receiver_field_writes.len(), 1);
    assert_eq!(constructor.receiver_field_writes[0].source_param_indices, [0]);
    let unwrap = index
        .defs
        .iter()
        .find(|decl| decl.name == "unwrap")
        .expect("unwrap declaration");
    let projected_binding = unwrap.flow_events.iter().find_map(|event| {
        let FlowEvent::Branch { then_events, .. } = event else {
            return None;
        };
        let mut found = None;
        bonsai_lang_api::for_each_flow_event(then_events, &mut |nested| {
            if let FlowEvent::Assign {
                target, source_name, ..
            } = nested
            {
                if target == "value" {
                    found = source_name.clone();
                }
            }
        });
        found
    });
    assert_eq!(projected_binding.as_deref(), Some("event.value0"));
}

#[test]
fn scalar_member_writes_keep_exact_compiler_values() {
    use bonsai_lang_api::StaticScalarValue;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[(
            "State.swift",
            r#"
struct Worker { var mode: String; var enabled: Bool }
func configure(_ worker: Worker) {
    worker.mode = "/bin/sh"
    worker.enabled = false
}
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Swift declaration index");
    assert!(index.assignment_values.iter().any(|fact| {
        fact.target.as_deref() == Some("worker.mode")
            && fact.static_value == Some(StaticScalarValue::String("/bin/sh".to_string()))
    }));
    assert!(index.assignment_values.iter().any(|fact| {
        fact.target.as_deref() == Some("worker.enabled")
            && fact.static_value == Some(StaticScalarValue::Boolean(false))
    }));
}

#[test]
fn call_valued_member_writes_keep_exact_callee_and_scalar_arguments() {
    use bonsai_lang_api::StaticScalarValue;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[(
            "State.swift",
            r#"
import Foundation
func configure(_ process: Process) {
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
}
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Swift declaration index");
    let fact = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("process.executableURL"))
        .unwrap_or_else(|| panic!("executableURL assignment fact: {:#?}", index.assignment_values));
    assert_eq!(fact.direct_call_name.as_deref(), Some("URL"), "{fact:#?}");
    assert_eq!(
        fact.exact_static_call_args.as_deref(),
        Some(&[StaticScalarValue::String("/bin/sh".to_string())][..]),
        "{fact:#?}"
    );
}

#[test]
fn optional_try_initializer_keeps_exact_call_identity_and_input() {
    use bonsai_lang_api::{AssignValueKind, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[(
            "Restore.swift",
            r#"
import Foundation
func restore(_ blob: Data) {
    let optional = try? NSKeyedUnarchiver(forReadingFrom: blob)
    let forced = try! NSKeyedUnarchiver(forReadingFrom: blob)
    consume(optional)
    consume(forced)
}
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Swift declaration index");
    let restore = index
        .defs
        .iter()
        .find(|decl| decl.name == "restore")
        .expect("restore declaration");

    for target in ["optional", "forced"] {
        assert!(
            restore.flow_events.iter().any(|event| matches!(
                event,
                FlowEvent::Assign {
                    target: actual,
                    source_call: Some(call),
                    value_kind: Some(AssignValueKind::CallResult),
                    ..
                } if actual == target
                    && call == "NSKeyedUnarchiver"
            )),
            "{target} must retain the wrapped constructor identity and input: {:#?}",
            restore.flow_events
        );
        assert!(
            index.assignment_values.iter().any(|fact| {
                fact.target.as_deref() == Some(target)
                    && fact.direct_call_name.as_deref() == Some("NSKeyedUnarchiver")
            }),
            "{target} assignment fact lost the wrapped constructor: {:#?}",
            index.assignment_values
        );
    }
}

#[test]
fn typed_member_reads_retain_the_receiver_place_and_type() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_swift::SwiftAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Inputs.swift",
            "func read(board: UIPasteboard, req: Request) { let a = board.string; let b = req.body; consume(a); consume(b) }",
        )],
    );
    let global = ws.db().global_index();
    let read = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "read")
        .expect("read declaration");
    assert!(read
        .type_aliases
        .iter()
        .any(|alias| alias.name == "board" && alias.type_name == "UIPasteboard"));
    assert!(read
        .type_aliases
        .iter()
        .any(|alias| alias.name == "req" && alias.type_name == "Request"));
    let assignments = read
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign { source_names, .. } => Some(source_names),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(assignments
        .iter()
        .any(|names| names.iter().any(|name| name == "board.string")));
    assert!(assignments
        .iter()
        .any(|names| names.iter().any(|name| name == "req.body")));
}

#[test]
fn trailing_and_parenthesized_closures_are_exact_callback_argument_facts() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_swift::SwiftAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Sockets.swift",
            r#"
func trailing(socket: WebSocket) {
  socket.onText { ws, text in consume(text) }
}
func parenthesized(socket: WebSocket) {
  socket.onBinary({ ws, data in consume(data) })
}
func named(socket: WebSocket, handler: (WebSocket, String) -> Void) {
  socket.onText(handler)
}
"#,
        )],
    );
    let index = ws
        .db()
        .decl_index(bonsai_common::FileId::new(0))
        .expect("Swift index");
    for (decl_name, call_suffix, expected_params) in [
        ("trailing", "onText", vec!["ws", "text"]),
        ("parenthesized", "onBinary", vec!["ws", "data"]),
    ] {
        let decl = index
            .defs
            .iter()
            .find(|decl| decl.name == decl_name)
            .expect("callback host");
        let call_span = decl
            .flow_events
            .iter()
            .find_map(|event| match event {
                FlowEvent::Call {
                    name,
                    span,
                    receiver_types,
                    ..
                } if name.ends_with(call_suffix) => {
                    assert!(receiver_types.iter().any(|ty| ty == "WebSocket"));
                    Some(*span)
                }
                _ => None,
            })
            .expect("callback registration call");
        let callback = index
            .call_argument_values
            .iter()
            .find(|fact| fact.call_span == call_span && fact.argument_index == 0)
            .unwrap_or_else(|| {
                panic!(
                    "inline callback argument for {decl_name}; call={call_span:?}, facts={:#?}",
                    index.call_argument_values
                )
            });
        assert_eq!(callback.inline_callback_params, expected_params);
        assert!(callback.inline_callback_span.is_some());
    }

    let named = index
        .defs
        .iter()
        .find(|decl| decl.name == "named")
        .expect("named host");
    let named_span = named
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, span, .. } if name.ends_with("onText") => Some(*span),
            _ => None,
        })
        .expect("named callback call");
    let named_arg = index
        .call_argument_values
        .iter()
        .find(|fact| fact.call_span == named_span && fact.argument_index == 0)
        .expect("named callback argument");
    assert!(named_arg.inline_callback_params.is_empty());
    assert!(named_arg.inline_callback_span.is_none());
}

#[test]
fn computed_property_argument_records_exact_pseudo_call_result() {
    use bonsai_lang_api::FlowEvent;

    let ws = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[(
            "Clipboard.swift",
            "func forward(board: UIPasteboard) { consume(board.string) }\n",
        )],
    );
    let index = ws
        .db()
        .decl_index(bonsai_common::FileId::new(0))
        .expect("Swift index");
    let forward = index
        .defs
        .iter()
        .find(|decl| decl.name == "forward")
        .expect("forward declaration");
    let getter_span = forward
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, span, .. } if name == "board.string" => Some(*span),
            _ => None,
        })
        .expect("computed-property getter call");
    let getter_receiver = index
        .call_receivers
        .iter()
        .find(|fact| fact.call_span == getter_span)
        .expect("computed-property receiver fact");
    assert_eq!(
        getter_receiver.role,
        bonsai_lang_api::CallReceiverRole::Projection,
        "property syntax must not imply whole-receiver-to-result passthrough"
    );
    let consume_span = forward
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, span, .. } if name == "consume" => Some(*span),
            _ => None,
        })
        .expect("consumer call");
    let argument = index
        .call_argument_values
        .iter()
        .find(|fact| fact.call_span == consume_span && fact.argument_index == 0)
        .expect("consumer argument fact");
    assert_eq!(argument.direct_call_span, Some(getter_span));
    assert_eq!(
        argument.value_kind,
        Some(bonsai_lang_api::AssignValueKind::PropertyRead),
        "a Swift navigation value must retain its property-read semantics even when a getter pseudo-call is emitted"
    );
    assert_eq!(
        argument
            .value_flow
            .projection
            .as_ref()
            .map(bonsai_lang_api::ExpressionProjection::canonical_place)
            .as_deref(),
        Some("board.string"),
        "the exact projected storage identity must accompany the getter call"
    );
}

#[test]
fn terminal_property_getter_owns_assignment_over_nested_call() {
    use bonsai_lang_api::FlowEvent;

    let ws = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[(
            "Values.swift",
            r#"
struct Values {
    func build(base: Box, item: String) {
        let output = base.combine(item).normalized
        consume(output)
    }
}
"#,
        )],
    );
    let index = ws
        .db()
        .decl_index(bonsai_common::FileId::new(0))
        .expect("Swift index");
    let assignment = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("output"))
        .expect("output assignment fact");
    assert_eq!(
        assignment.direct_call_name.as_deref(),
        Some("base.combine(item).normalized")
    );
    assert_eq!(assignment.direct_call_span, Some(assignment.value_span));
    assert_eq!(
        assignment.direct_call_receiver.as_deref(),
        Some("base.combine(item)")
    );
    assert!(assignment.direct_call_receiver_span.is_some());
    assert!(assignment.direct_call_receiver_flow.is_some());

    let build = index
        .defs
        .iter()
        .find(|decl| decl.name == "build")
        .expect("build declaration");
    let source_call = build.flow_events.iter().find_map(|event| match event {
        FlowEvent::Assign {
            target, source_call, ..
        } if target == "output" => source_call.as_deref(),
        _ => None,
    });
    assert_eq!(source_call, Some("base.combine(item).normalized"));
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
fn implicit_class_initializer_preserves_cross_file_lowercase_constructor_fact() {
    use bonsai_lang_api::LanguageAdapter;
    use std::sync::Arc;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_swift::SwiftAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[
            ("Dependency.swift", "class lower {}\n"),
            (
                "Owner.swift",
                r#"
class Owner {
    let dependency = lower()
    func run() { dependency.work() }
}
"#,
            ),
        ],
    );
    let global = ws.db().global_index();
    let constructor = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Owner" && decl.kind == bonsai_lang_api::DeclKind::Constructor)
        .expect("implicit Owner constructor");
    assert!(
        constructor.receiver_field_initializers.iter().any(|initializer| {
            initializer.target == "self.dependency" && initializer.call_name == "lower"
        }),
        "cross-file property construction must remain an exact unresolved header fact: {:#?}",
        constructor.receiver_field_initializers
    );
}

#[test]
fn explicit_class_initializers_include_only_executable_instance_property_prefixes() {
    use bonsai_lang_api::{DeclKind, FlowEvent, LanguageAdapter};
    use std::sync::Arc;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_swift::SwiftAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[
            (
                "Dependencies.swift",
                "class lower {}\nclass static_lower {}\nclass nested_lower {}\n",
            ),
            (
                "Owner.swift",
                r#"
class Owner {
    let dependency = lower()
    static let shared = static_lower()
    init(_ seed: String) { _ = seed }
    func helper() { let ignored = nested_lower() }
}
"#,
            ),
        ],
    );
    let global = ws.db().global_index();
    let constructor = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Owner" && decl.kind == DeclKind::Constructor)
        .expect("explicit Owner constructor");

    assert!(constructor
        .receiver_field_initializers
        .iter()
        .any(|initializer| { initializer.target == "self.dependency" && initializer.call_name == "lower" }));
    let calls = constructor
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        calls.contains(&"lower"),
        "constructor events: {:#?}",
        constructor.flow_events
    );
    assert!(
        !calls.contains(&"static_lower") && !calls.contains(&"nested_lower"),
        "type properties and method bodies do not execute as instance initializer prefixes: {:#?}",
        constructor.flow_events
    );
}

#[test]
fn implicit_class_initializers_follow_swift_inheritance_and_default_rules() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, DeclKind, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_swift::SwiftAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("Constructors.swift"),
        r#"
class Base {
    let value: String
    init(_ value: String) { self.value = value }
}
class Child: Base {}
class InvalidRoot { let value: String }
class DefaultedRoot { let value = "ready" }
protocol Marker {}
class DefaultedConformer: Marker { let value = "ready" }
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
    let class_symbol = |name: &str| {
        idx.defs
            .iter()
            .find(|decl| decl.name == name && decl.kind == DeclKind::Class)
            .map(|decl| decl.symbol)
            .unwrap_or_else(|| panic!("missing class {name}"))
    };

    let child = class_symbol("Child");
    let invalid = class_symbol("InvalidRoot");
    let defaulted = class_symbol("DefaultedRoot");
    let conformer = class_symbol("DefaultedConformer");
    assert!(
        idx.defs
            .iter()
            .all(|decl| decl.kind != DeclKind::Constructor || decl.parent != Some(child)),
        "a subclass inherits its base designated initializer"
    );
    assert!(
        idx.defs
            .iter()
            .all(|decl| decl.kind != DeclKind::Constructor || decl.parent != Some(invalid)),
        "an uninitialized stored property prevents a synthesized initializer"
    );
    assert!(
        idx.defs
            .iter()
            .any(|decl| decl.kind == DeclKind::Constructor && decl.parent == Some(defaulted)),
        "a root class whose stored properties have defaults receives init()"
    );
    assert!(
        idx.defs
            .iter()
            .any(|decl| decl.kind == DeclKind::Constructor && decl.parent == Some(conformer)),
        "protocol conformance is not superclass inheritance"
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
fn computed_property_returns_exact_nested_field_place() {
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
                    .any(|event| matches!(event, FlowEvent::Return { value_flow, .. } if value_flow.place.as_deref() == Some("self.data.cmd")))
        })
        .expect("computed cmd getter");
    assert!(
        getter.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Return { value_flow, .. }
                if value_flow.place.as_deref() == Some("self.data.cmd")
        )),
        "computed getter must return its exact parsed field place: {:?}",
        getter.flow_events
    );
    assert!(
        getter
            .receiver_state_sources
            .iter()
            .any(|source| source == "self.data.cmd"),
        "computed getter must retain its AST-derived receiver field state: {:?}",
        getter.receiver_state_sources
    );
}

#[test]
fn nested_getter_does_not_replace_the_direct_outer_constructor() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[(
            "Envelope.swift",
            r#"
struct Envelope { var size: Int; var cmd: String }
func build(raw: String) {
    let envelope = Envelope(size: raw.count, cmd: raw)
    consume(envelope)
}
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Swift declaration index");
    let fact = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("envelope"))
        .expect("envelope assignment fact");
    assert_eq!(fact.direct_call_name.as_deref(), Some("Envelope"), "{fact:#?}");
}

#[test]
fn struct_stored_property_types_reach_method_receiver_calls() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_swift::SwiftAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("Controller.swift"),
        r#"
struct Store {
    func read(name: String) -> String { name }
}
struct Controller {
    let store: Store
    func handle(name: String) -> String { store.read(name: name) }
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
        handle
            .type_aliases
            .iter()
            .any(|alias| { alias.name == "store" && alias.type_name == "Store" }),
        "struct stored-property type must be visible in methods: {:?}",
        handle.type_aliases
    );
    assert!(handle.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Call { name, receiver_types, .. }
            if name == "store.read" && receiver_types.iter().any(|ty| ty == "Store")
    )));
}

#[test]
fn typed_stored_property_dispatches_to_exact_cross_file_swift_method() {
    let ws = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[
            (
                "Sources/App/Services/Formatter.swift",
                r#"
struct Formatter {
    func transform(_ value: String) -> String { value }
}
"#,
            ),
            (
                "Sources/App/Controllers/Controller.swift",
                r#"
struct Controller {
    let formatter: Formatter
    func handle(_ value: String) -> String { formatter.transform(value) }
}
"#,
            ),
        ],
    );
    let global = ws.db().global_index();
    let caller = bonsai_common::FuncId::new(global.find_by_name("handle")[0].raw());
    let expected = global
        .find_by_name("transform")
        .iter()
        .find_map(|symbol| {
            let decl = global.decl_of(*symbol)?;
            let parent = decl.parent.and_then(|parent| global.decl_of(parent))?;
            (parent.name == "Formatter").then(|| bonsai_common::FuncId::new(decl.symbol.raw()))
        })
        .expect("Formatter.transform");
    let graph = ws.cached_resolved_call_graph();
    let targets = graph.callees_of(caller).map(|edge| edge.to).collect::<Vec<_>>();
    assert_eq!(
        targets.iter().filter(|target| **target == expected).count(),
        1,
        "exact stored-property receiver type must resolve across files: {targets:?}"
    );
}

#[test]
fn typed_stored_property_does_not_dispatch_to_unrelated_same_named_method() {
    let ws = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[
            (
                "Sources/App/Services/Formatter.swift",
                "struct Formatter { func transform(_ value: String) -> String { value } }\n",
            ),
            (
                "Sources/App/Services/Unrelated.swift",
                "struct Unrelated { func transform(_ value: String) -> String { value } }\n",
            ),
            (
                "Sources/App/Controllers/Controller.swift",
                r#"
struct Controller {
    let formatter: Formatter
    func handle(_ value: String) -> String { formatter.transform(value) }
}
"#,
            ),
        ],
    );
    let global = ws.db().global_index();
    let caller = bonsai_common::FuncId::new(global.find_by_name("handle")[0].raw());
    let method_for_owner = |owner: &str| {
        global
            .find_by_name("transform")
            .iter()
            .find_map(|symbol| {
                let decl = global.decl_of(*symbol)?;
                let parent = decl.parent.and_then(|parent| global.decl_of(parent))?;
                (parent.name == owner).then(|| bonsai_common::FuncId::new(decl.symbol.raw()))
            })
            .unwrap_or_else(|| panic!("missing {owner}.transform"))
    };
    let expected = method_for_owner("Formatter");
    let collision = method_for_owner("Unrelated");
    let graph = ws.cached_resolved_call_graph();
    let targets = graph.callees_of(caller).map(|edge| edge.to).collect::<Vec<_>>();
    assert!(targets.contains(&expected), "missing exact target: {targets:?}");
    assert!(
        !targets.contains(&collision),
        "same-spelled method on another type must not be linked: {targets:?}"
    );
}

#[test]
fn ambiguous_public_swift_receiver_type_fails_closed_across_modules() {
    let ws = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
        &[
            (
                "Sources/First/Formatter.swift",
                "public struct Formatter { public func transform(_ value: String) -> String { value } }\n",
            ),
            (
                "Sources/Second/Formatter.swift",
                "public struct Formatter { public func transform(_ value: String) -> String { value } }\n",
            ),
            (
                "Sources/App/Controller.swift",
                r#"
struct Controller {
    let formatter: Formatter
    func handle(_ value: String) -> String { formatter.transform(value) }
}
"#,
            ),
        ],
    );
    let global = ws.db().global_index();
    let caller = bonsai_common::FuncId::new(global.find_by_name("handle")[0].raw());
    let graph = ws.cached_resolved_call_graph();
    let targets = graph.callees_of(caller).map(|edge| edge.to).collect::<Vec<_>>();
    for target in targets {
        let decl = global
            .decl_of(bonsai_common::SymbolId::new(target.raw()))
            .expect("target declaration");
        assert_ne!(
            decl.name, "transform",
            "an ambiguous declared receiver type must not select either module: {decl:#?}"
        );
    }
}
