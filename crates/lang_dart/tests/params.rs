use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{DeclKind, FlowEvent, LanguageAdapter, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_for(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("main.dart".to_string(), Arc::<str>::from(source));
    dart_db(vfs)
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

    let has_source_call = handle.flow_events.iter().any(|event| {
        matches!(
            event,
            FlowEvent::Assign {
                target,
                source_call: Some(source_call),
                source_call_args,
                ..
            } if target == "y"
                && source_call == "transform"
                && source_call_args.as_slice() == ["x"]
        )
    });

    assert!(
        has_source_call,
        "Dart assignment from a split selector call should retain source_call metadata; events: {:?}",
        handle.flow_events
    );
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
fn mega_flow_constructor_field_formals_export_receiver_writes() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(
        manifest
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("examples/dart/mega_flow/app.dart"),
    )
    .expect("mega_flow app.dart fixture should be readable");
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
fn mega_flow_directory_constructor_field_formals_export_receiver_writes() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture = manifest
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples/dart/mega_flow");
    let db = db_for_files(&[
        (
            "app.dart",
            std::fs::read_to_string(fixture.join("app.dart")).expect("app.dart should be readable"),
        ),
        (
            "pipeline.dart",
            std::fs::read_to_string(fixture.join("pipeline.dart")).expect("pipeline.dart should be readable"),
        ),
        (
            "storage.dart",
            std::fs::read_to_string(fixture.join("storage.dart")).expect("storage.dart should be readable"),
        ),
        (
            "executor.dart",
            std::fs::read_to_string(fixture.join("executor.dart")).expect("executor.dart should be readable"),
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
