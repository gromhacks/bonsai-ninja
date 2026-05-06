use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{FlowEvent, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_with(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("C.java".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_java::JavaAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn collect_calls(events: &[FlowEvent], out: &mut Vec<(String, Vec<String>)>) {
    for event in events {
        match event {
            FlowEvent::Call {
                name, receiver_types, ..
            } => out.push((name.clone(), receiver_types.clone())),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_calls(then_events, out);
                collect_calls(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_calls(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_calls(body, out);
                collect_calls(catch_events, out);
                collect_calls(finally_events, out);
            }
            _ => {}
        }
    }
}

#[test]
fn enhanced_for_loop_variable_supplies_receiver_type() {
    let db = db_with(
        r#"
import javax.servlet.http.Cookie;

class C {
  void handle(Cookie[] cookies) {
    for (Cookie theCookie : cookies) {
      theCookie.getValue();
    }
  }
}
"#,
    );
    let global = db.global_index();
    let mut calls = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == "handle" {
                collect_calls(&decl.flow_events, &mut calls);
            }
        }
    }
    assert!(
        calls
            .iter()
            .any(|(name, receiver_types)| name == "theCookie.getValue"
                && receiver_types.iter().any(|ty| ty == "Cookie")),
        "enhanced-for receiver type should be attached to Cookie.getValue calls, got {calls:?}"
    );
}

#[test]
fn inline_constructor_receiver_supplies_receiver_type() {
    let db = db_with(
        r#"
class C {
  void handle() {
    new java.util.Random().nextFloat();
  }
}
"#,
    );
    let global = db.global_index();
    let mut calls = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == "handle" {
                collect_calls(&decl.flow_events, &mut calls);
            }
        }
    }
    assert!(
        calls
            .iter()
            .any(|(name, receiver_types)| name.ends_with("nextFloat")
                && receiver_types.iter().any(|ty| ty == "Random")),
        "inline constructor receiver type should be attached to Random.nextFloat calls, got {calls:?}"
    );
}

#[test]
fn typed_receiver_includes_same_file_base_types() {
    let db = db_with(
        r#"
class Base {
  void sink(String value) {}
}

class Child extends Base {}

class C {
  void handle(String value) {
    Child child = new Child();
    child.sink(value);
  }
}
"#,
    );
    let global = db.global_index();
    let mut calls = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == "handle" {
                collect_calls(&decl.flow_events, &mut calls);
            }
        }
    }
    assert!(
        calls.iter().any(|(name, receiver_types)| {
            name == "child.sink"
                && receiver_types.iter().any(|ty| ty == "Child")
                && receiver_types.iter().any(|ty| ty == "Base")
        }),
        "typed receiver should include its same-file base classes for rule matching, got {calls:?}"
    );
}
