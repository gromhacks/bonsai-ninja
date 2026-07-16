use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("A.java", "class A { public static void main(String[] s) {} }")]
    );
}

#[test]
fn inherited_bare_member_call_has_explicit_receiver_fact() {
    use bonsai_lang_api::{CallKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Storage.java",
            r#"
class Base { String cmd() { return ""; } }
class Repository extends Base {
  String run() { return cmd(); }
}
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let run = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "run")
        .expect("run declaration");

    assert!(
        run.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                receiver: Some(receiver),
                call_kind: CallKind::Method,
                ..
            } if name == "this.cmd" && receiver == "this"
        )),
        "{:#?}",
        run.flow_events
    );
}

#[test]
fn explicit_super_invocation_remains_constructor_syntax() {
    use bonsai_lang_api::{CallKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Storage.java",
            r#"
class Base { Base(String data) {} }
class Derived extends Base {
  Derived(String data) { super(data); }
}
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let derived = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Derived" && decl.kind == bonsai_lang_api::DeclKind::Constructor)
        .expect("derived constructor");

    assert!(
        derived.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                receiver: Some(receiver),
                call_kind: CallKind::Constructor,
                ..
            } if name == "Base" && receiver == "super"
        )),
        "{:#?}",
        derived.flow_events
    );
}

#[test]
fn generic_receiver_carries_tree_sitter_upper_bound() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Box.java",
            r#"
class Payload { String cmd() { return ""; } }
class Box<T extends Payload> {
  T data;
  String read() { return data.cmd(); }
}
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let read = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "read")
        .expect("read method");

    assert!(
        read.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                receiver: Some(receiver),
                receiver_types,
                ..
            } if receiver == "data" && receiver_types.iter().any(|ty| ty == "Payload")
        )),
        "{:#?}",
        read.flow_events
    );
}
