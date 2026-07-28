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
fn url_guard_syntax_emits_typed_conditions_and_static_scalars() {
    use bonsai_lang_api::{ConditionExpressionFact, LanguageAdapter, StaticScalarValue};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "UrlGuard.java",
            r#"
import java.net.*;
import java.util.*;
class UrlGuard {
  private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com", "partner.example.com");
  void fetch(String raw) throws Exception {
    URL parsed = new URL(raw);
    if (!"https".equalsIgnoreCase(parsed.getProtocol())) throw new SecurityException();
    if (!ALLOWED_HOSTS.contains(parsed.getHost())) throw new SecurityException();
    InetAddress addr = InetAddress.getByName(parsed.getHost());
    if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()) throw new SecurityException();
    HttpURLConnection conn = (HttpURLConnection) parsed.openConnection();
    conn.setInstanceFollowRedirects(false);
  }
  void authenticate(Object email, Object password) {
    if (!(email instanceof String) || !(password instanceof String)) {
      throw new IllegalArgumentException();
    }
  }
}
"#,
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("Java declaration index");

    assert!(index
        .branch_conditions
        .iter()
        .any(|fact| matches!(&fact.expression, Some(ConditionExpressionFact::Not { .. }))));
    assert!(index.branch_conditions.iter().any(|fact| matches!(
        &fact.expression,
        Some(ConditionExpressionFact::Any { operands, .. }) if operands.len() == 2
    )));
    assert!(index.branch_conditions.iter().any(|fact| matches!(
        &fact.expression,
        Some(ConditionExpressionFact::Any { operands, .. })
            if operands.iter().all(|operand| matches!(
                operand,
                ConditionExpressionFact::Not { operand, .. }
                    if matches!(
                        operand.as_ref(),
                        ConditionExpressionFact::TypeTest { type_name, .. }
                            if type_name == "String"
                    )
            ))
    )));
    assert!(index
        .call_receivers
        .iter()
        .any(|fact| { fact.static_value == Some(StaticScalarValue::String("https".to_string())) }));
    assert!(index
        .call_argument_values
        .iter()
        .any(|fact| { fact.static_value == Some(StaticScalarValue::Boolean(false)) }));
    let allowlist = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("ALLOWED_HOSTS"))
        .expect("static Set.of assignment");
    assert_eq!(allowlist.exact_static_call_args.as_ref().map(Vec::len), Some(2));
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
