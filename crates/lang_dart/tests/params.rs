use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{DeclKind, FlowEvent, LanguageAdapter, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_for(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("main.dart".to_string(), Arc::<str>::from(source));
    dart_db(vfs)
}

#[test]
fn qualified_parameter_types_are_recorded_for_receiver_matching() {
    let db = db_for(
        r#"
import 'package:http/http.dart' as http;
String consume(http.Response response) => response.body;
"#,
    );
    let index = db.global_index();
    let consume = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "consume")
        .expect("consume declaration should index");

    assert!(
        consume
            .type_aliases
            .iter()
            .any(|alias| alias.name == "response" && alias.type_name == "Response"),
        "qualified Dart parameter type must be available to receiver-typed rules: {:#?}",
        consume
    );
}

#[test]
fn generated_service_override_retains_class_and_complete_signature_facts() {
    let db = db_for(
        r#"
import 'package:grpc/grpc.dart';
class GreeterService extends GreeterServiceBase {
  @override
  Future<Reply> sayHello(ServiceCall context, HelloRequest payload) async => Reply();
}
"#,
    );
    let index = db.global_index();
    let class = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "GreeterService")
        .expect("generated service implementation class");
    assert_eq!(class.bases, ["GreeterServiceBase"]);
    let method = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "sayHello")
        .expect("generated service override method");
    assert_eq!(method.parent, Some(class.symbol));
    assert_eq!(method.params, ["context", "payload"]);
    assert!(method
        .type_aliases
        .iter()
        .any(|alias| alias.name == "context" && alias.type_name == "ServiceCall"));
    assert!(method
        .type_aliases
        .iter()
        .any(|alias| alias.name == "payload" && alias.type_name == "HelloRequest"));
}

fn db_for_files(files: &[(&str, String)]) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    for (path, source) in files {
        vfs.write((*path).to_string(), Arc::<str>::from(source.as_str()));
    }
    dart_db(vfs)
}

fn dart_db(vfs: Arc<Vfs>) -> AnalyzerDb {
    let registry = Arc::new(LanguageRegistry::new());
    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_dart::DartAdapter::new());
    registry.register(adapter);
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

#[test]
fn required_named_parameter_uses_binding_name() {
    let db = db_for("void helper({required String name}) { sink(name); }\n");
    let index = db.global_index();
    let helper = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "helper")
        .expect("helper declaration should index");

    assert_eq!(helper.params, vec!["name"]);
}

#[test]
fn switch_variable_pattern_binds_from_the_ast_subject() {
    let db = db_for("void entry(Object args) { switch (args) { case String value: sink(value); } }\n");
    let index = db.global_index();
    let entry = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "entry")
        .expect("entry declaration should index");

    let arm_events = entry
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Branch { then_events, .. } => Some(then_events.as_slice()),
            _ => None,
        })
        .expect("switch case must lower to an exclusive branch arm");
    let assignment = arm_events.iter().find(|event| {
        matches!(
            event,
            FlowEvent::Assign { target, source_name: Some(source), .. }
                if target == "value" && source == "args"
        )
    });
    assert!(
        assignment.is_some(),
        "pattern binding must be an ordinary compiler assignment before its case body: {:?}",
        entry.flow_events
    );
    let assign_index = arm_events
        .iter()
        .position(|event| matches!(event, FlowEvent::Assign { target, .. } if target == "value"))
        .unwrap();
    let sink_index = arm_events
        .iter()
        .position(|event| matches!(event, FlowEvent::Call { name, .. } if name == "sink"))
        .unwrap();
    assert!(assign_index < sink_index);
}

#[test]
fn initialized_variable_definition_records_source_call() {
    let db = db_for(
        r#"
String transform(String x) { return x; }

String handle(String x) {
  final y = transform(x);
  return y;
}
"#,
    );
    let index = db.global_index();
    let handle = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration should index");

    let assign = handle
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } if target == "y" => Some((source_name, source_call, source_call_args, source_names)),
            _ => None,
        })
        .expect("handle should contain assignment to y");

    assert_eq!(assign.0.as_deref(), None);
    assert_eq!(assign.1.as_deref(), Some("transform"));
    assert_eq!(assign.2.as_slice(), ["x"]);
    assert!(
        assign.3.is_empty(),
        "direct call assignment should not duplicate callee or bare arg carriers in source_names; events: {:?}",
        handle.flow_events
    );
}

#[test]
fn awaited_selector_and_constructor_cascade_preserve_exact_value_identity() {
    let db = db_for(
        r#"
class InputPort {
  Future<String> load() async => "";
}

class Carrier {
  String field = "";
  String expose() => field;
}

Future<String> fallback() async => "";

Future<String> assemble(InputPort input, dynamic existing, bool flag) async {
  final data = await input.load();
  final carrier = Carrier()..field = data;
  final unchanged = existing..field = data;
  final conditional = await (flag ? input.load() : fallback());
  return carrier.expose();
}
"#,
    );
    let index = db.global_index();
    let assemble = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "assemble")
        .expect("assemble declaration should index");

    let assignment = |target: &str| {
        assemble
            .flow_events
            .iter()
            .find_map(|event| match event {
                FlowEvent::Assign {
                    target: observed,
                    source_name,
                    source_call,
                    source_call_args,
                    source_names,
                    ..
                } if observed == target => Some((source_name, source_call, source_call_args, source_names)),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing {target} assignment: {:#?}", assemble.flow_events))
    };

    let data = assignment("data");
    assert_eq!(data.0.as_deref(), None);
    assert_eq!(data.1.as_deref(), Some("input.load"));
    assert!(data.2.is_empty());

    let carrier = assignment("carrier");
    assert_eq!(carrier.0.as_deref(), None);
    assert_eq!(carrier.1.as_deref(), Some("Carrier"));
    assert!(carrier.2.is_empty());
    assert!(carrier.3.is_empty());
    assert!(
        assemble
            .type_aliases
            .iter()
            .any(|alias| alias.name == "carrier" && alias.type_name == "Carrier"),
        "constructor cascade result must keep its declared type: {:#?}",
        assemble.type_aliases
    );

    let field_write = assignment("carrier.field");
    assert_eq!(field_write.0.as_deref(), Some("data"));
    assert!(
        assemble.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, receiver_types, .. }
                if name == "carrier.expose" && receiver_types.iter().any(|ty| ty == "Carrier")
        )),
        "the cascade result must retain its exact declared receiver type: {:#?}",
        assemble.flow_events
    );

    let unchanged = assignment("unchanged");
    assert_eq!(
        unchanged.1.as_deref(),
        None,
        "a cascade on an existing value is not construction"
    );
    let conditional = assignment("conditional");
    assert_eq!(
        conditional.1.as_deref(),
        None,
        "a conditional await value has no single value-producing call"
    );
}

#[test]
fn method_call_result_preserves_receiver_source_name() {
    let db = db_for(
        r#"
class Normalizer {
  String clean(String x) { return x; }
}

String handle(Normalizer normalizer, String x) {
  final y = normalizer.clean(x);
  return y;
}
"#,
    );
    let index = db.global_index();
    let handle = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration should index");

    let assign = handle
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } if target == "y" => Some((source_name, source_call, source_call_args, source_names)),
            _ => None,
        })
        .expect("handle should contain assignment to y");

    assert_eq!(assign.0.as_deref(), None);
    assert_eq!(assign.1.as_deref(), Some("normalizer.clean"));
    assert_eq!(assign.2.as_slice(), ["x"]);
    assert_eq!(assign.3.as_slice(), ["normalizer"]);
}

#[test]
fn direct_call_result_removes_argument_operands_from_assignment_sources() {
    let db = db_for(
        r#"
class User {
  String name = "";
}

String transform(String x) { return x; }

String handle(User user) {
  final y = transform(user.name);
  return y;
}
"#,
    );
    let index = db.global_index();
    let handle = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration should index");

    let assign = handle
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_call,
                source_call_args,
                source_names,
                ..
            } if target == "y" => Some((source_call, source_call_args, source_names)),
            _ => None,
        })
        .expect("handle should contain assignment to y");

    assert_eq!(assign.0.as_deref(), Some("transform"));
    assert_eq!(assign.1.as_slice(), ["user.name"]);
    assert!(
        assign.2.is_empty(),
        "argument operands should stay on source_call_args / Call.args, not assignment source_names; events: {:?}",
        handle.flow_events
    );
}

#[test]
fn static_factory_call_result_preserves_type_receiver() {
    let db = db_for(
        r#"
class Logger {
  static Logger getLogger(String name) { return Logger(); }
}

Logger handle(String name) {
  final logger = Logger.getLogger(name);
  return logger;
}
"#,
    );
    let index = db.global_index();
    let handle = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration should index");

    let assign = handle
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } if target == "logger" => Some((source_name, source_call, source_call_args, source_names)),
            _ => None,
        })
        .expect("handle should contain assignment to logger");

    assert_eq!(assign.0.as_deref(), None);
    assert_eq!(assign.1.as_deref(), Some("Logger.getLogger"));
    assert_eq!(assign.2.as_slice(), ["name"]);
    // `source_names` carries the receiver TYPE (`Logger`) so a tainted
    // receiver propagates — but NOT the method name `getLogger`, which is
    // a callee path component, not a value operand. The real argument
    // operand (`name`) is already captured in `source_call_args` above.
    assert_eq!(assign.3.as_slice(), ["Logger"]);
}

#[test]
fn constructor_field_formal_records_receiver_field_write() {
    let db = db_for(
        r#"
class Repo {
  String conn;
  Repo(this.conn);
}
"#,
    );
    let index = db.global_index();
    let ctor = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "Repo" && decl.params == ["conn"])
        .expect("constructor declaration should index");

    assert!(
        ctor.receiver_field_writes
            .iter()
            .any(|write| { write.target == "this.conn" && write.source_param_indices.as_slice() == [0] }),
        "Dart field-formal constructor params should populate receiver_field_writes; writes: {:?}",
        ctor.receiver_field_writes
    );
}

#[test]
fn named_constructor_field_formals_preserve_all_parameter_indices() {
    let db = db_for(
        r#"
enum Kind { run, eval }

class Envelope {
  final Kind kind;
  final String cmd;
  final String user;
  final int length;
  final List<String> extras;

  Envelope({
    required this.kind,
    required this.cmd,
    required this.user,
    required this.length,
    required this.extras,
  });
}
"#,
    );
    let index = db.global_index();
    let ctor = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "Envelope" && decl.kind == DeclKind::Constructor)
        .expect("constructor declaration should index");

    assert_eq!(ctor.params, vec!["kind", "cmd", "user", "length", "extras"]);
    for (idx, field) in ["kind", "cmd", "user", "length", "extras"].iter().enumerate() {
        assert!(
            ctor.receiver_field_writes.iter().any(|write| {
                write.target == format!("this.{field}") && write.source_param_indices.as_slice() == [idx]
            }),
            "missing receiver field write for {field} at index {idx}; writes: {:?}",
            ctor.receiver_field_writes
        );
    }
}

#[test]
fn named_constructors_keep_the_exact_member_identity() {
    let db = db_for(
        r#"
class Packet {
  final String value;

  Packet(this.value);
  Packet.checked(this.value);
  factory Packet.copy(Map<String, String> row) => Packet.checked(row['value'] ?? '');
}
"#,
    );
    let index = db.global_index();
    let constructors = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .filter(|decl| decl.kind == DeclKind::Constructor)
        .collect::<Vec<_>>();

    let unnamed = constructors
        .iter()
        .find(|decl| decl.name == "Packet")
        .expect("unnamed constructor should retain the type name");
    assert!(unnamed
        .qualified_name
        .as_deref()
        .is_some_and(|name| name.ends_with(".Packet.Packet")));

    for member in ["checked", "copy"] {
        let decl = constructors
            .iter()
            .find(|decl| decl.name == member)
            .unwrap_or_else(|| panic!("named constructor {member} should index independently"));
        assert!(
            decl.qualified_name
                .as_deref()
                .is_some_and(|name| name.ends_with(&format!(".Packet.{member}"))),
            "named constructor should use lexical owner plus member identity: {:?}",
            decl.qualified_name
        );
    }
}

#[test]
fn optional_named_method_parameters_preserve_all_names() {
    let db = db_for(
        r#"
class Envelope {
  Envelope copyWith({Kind? kind, String? cmd, String? user, int? length, List<String>? extras}) {
    return this;
  }
}

enum Kind { run, eval }
"#,
    );
    let index = db.global_index();
    let copy_with = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "copyWith")
        .expect("copyWith declaration should index");

    assert_eq!(copy_with.params, vec!["kind", "cmd", "user", "length", "extras"]);
}

#[test]
fn expression_bodied_method_records_return_event() {
    let db = db_for(
        r#"
class Envelope {
  Envelope copyWith({String? cmd}) => Envelope(cmd: cmd ?? this.cmd);
}
"#,
    );
    let index = db.global_index();
    let copy_with = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "copyWith")
        .expect("copyWith declaration should index");

    assert!(copy_with.has_implicit_returns);
    assert!(
        copy_with.flow_events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Return {
                    value_text: Some(value_text),
                    ..
                } if value_text.contains("Envelope") && value_text.contains("cmd")
            )
        }),
        "expression-bodied Dart methods should surface a semantic return; events: {:?}",
        copy_with.flow_events
    );
}

#[test]
fn language_gauntlet_constructor_field_formals_export_receiver_writes() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(
        manifest
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("examples/dart/language_gauntlet/lib/src/domain/envelope.dart"),
    )
    .expect("language_gauntlet envelope.dart fixture should be readable");
    let db = db_for(&source);
    let index = db.global_index();
    let ctor = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "Envelope" && decl.kind == DeclKind::Constructor)
        .expect("Envelope constructor declaration should index");

    assert_eq!(ctor.params, vec!["kind", "cmd", "user", "length", "extras"]);
    for (idx, field) in ["kind", "cmd", "user", "length", "extras"].iter().enumerate() {
        assert!(
            ctor.receiver_field_writes.iter().any(|write| {
                write.target == format!("this.{field}") && write.source_param_indices.as_slice() == [idx]
            }),
            "missing receiver field write for {field} at index {idx}; writes: {:?}",
            ctor.receiver_field_writes
        );
    }
}

#[test]
fn language_gauntlet_directory_constructor_field_formals_export_receiver_writes() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture = manifest
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples/dart/language_gauntlet");
    let db = db_for_files(&[
        (
            "bin/app.dart",
            std::fs::read_to_string(fixture.join("bin/app.dart")).expect("app.dart should be readable"),
        ),
        (
            "lib/src/http/handler.dart",
            std::fs::read_to_string(fixture.join("lib/src/http/handler.dart"))
                .expect("handler.dart should be readable"),
        ),
        (
            "lib/src/domain/envelope.dart",
            std::fs::read_to_string(fixture.join("lib/src/domain/envelope.dart"))
                .expect("envelope.dart should be readable"),
        ),
        (
            "lib/src/pipeline/pipeline.dart",
            std::fs::read_to_string(fixture.join("lib/src/pipeline/pipeline.dart"))
                .expect("pipeline.dart should be readable"),
        ),
        (
            "lib/src/routing/command_router.dart",
            std::fs::read_to_string(fixture.join("lib/src/routing/command_router.dart"))
                .expect("command_router.dart should be readable"),
        ),
        (
            "lib/src/storage/storage.dart",
            std::fs::read_to_string(fixture.join("lib/src/storage/storage.dart"))
                .expect("storage.dart should be readable"),
        ),
        (
            "lib/src/runtime/executor.dart",
            std::fs::read_to_string(fixture.join("lib/src/runtime/executor.dart"))
                .expect("executor.dart should be readable"),
        ),
    ]);
    let index = db.global_index();
    let ctor = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "Envelope" && decl.kind == DeclKind::Constructor)
        .expect("Envelope constructor declaration should index");

    assert_eq!(ctor.params, vec!["kind", "cmd", "user", "length", "extras"]);
    for (idx, field) in ["kind", "cmd", "user", "length", "extras"].iter().enumerate() {
        assert!(
            ctor.receiver_field_writes.iter().any(|write| {
                write.target == format!("this.{field}") && write.source_param_indices.as_slice() == [idx]
            }),
            "missing receiver field write for {field} at index {idx}; writes: {:?}",
            ctor.receiver_field_writes
        );
    }
}
