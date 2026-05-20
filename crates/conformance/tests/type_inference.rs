//! Phase-6 lightweight type inference (spec §Phase-6).
//!
//! Validates that adapters which extract `Decl.return_type` propagate
//! the type onto the LHS of `let y = f()` shaped assignments via
//! `apply_assign_call_result_types`. The propagation lets downstream
//! receiver-type dispatch resolve `y.method()` against the inferred
//! type without re-walking the source.

use bonsai_lang_api::{Decl, FlowEvent, LanguageAdapter};
use bonsai_workspace::Workspace;
use std::sync::Arc;

fn adapter_for_lang(lang: &str) -> Option<Arc<dyn LanguageAdapter>> {
    bonsai_adapters::all_adapters()
        .into_iter()
        .find(|a| a.language_id().as_str() == lang)
}

fn find_decl(ws: &Workspace, name: &str) -> Option<Decl> {
    let global = ws.db().global_index();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == name {
                return Some(decl.clone());
            }
        }
    }
    None
}

fn find_call<'a>(events: &'a [FlowEvent], name: &str) -> Option<&'a FlowEvent> {
    for event in events {
        match event {
            FlowEvent::Call { name: call_name, .. } if call_name == name => return Some(event),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(call) = find_call(then_events, name).or_else(|| find_call(else_events, name)) {
                    return Some(call);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(call) = find_call(body, name) {
                    return Some(call);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(call) = find_call(body, name)
                    .or_else(|| find_call(catch_events, name))
                    .or_else(|| find_call(finally_events, name))
                {
                    return Some(call);
                }
            }
            _ => {}
        }
    }
    None
}

#[test]
fn python_return_type_propagates_to_call_result_assignment() {
    let src = r#"class Connection:
    def execute(self, sql: str) -> int:
        return 0

def open_db() -> Connection:
    return Connection()

def caller():
    conn = open_db()
    conn.execute("select 1")
"#;
    let adapter = adapter_for_lang("python").expect("python adapter present");
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("app.py", src)]);
    let caller = find_decl(&ws, "caller").expect("caller decl present");
    // The `apply_assign_call_result_types` pass should have added a
    // type alias `conn: Connection` based on `open_db`'s return_type.
    let conn_alias = caller
        .type_aliases
        .iter()
        .find(|a| a.name == "conn")
        .expect("conn type alias inferred from open_db return type");
    assert_eq!(conn_alias.type_name, "Connection");
}

#[test]
fn python_open_db_decl_has_return_type_extracted() {
    let src = r#"class Connection:
    pass

def open_db() -> Connection:
    return Connection()
"#;
    let adapter = adapter_for_lang("python").expect("python adapter present");
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("app.py", src)]);
    let open_db = find_decl(&ws, "open_db").expect("open_db decl present");
    assert_eq!(
        open_db.return_type.as_deref(),
        Some("Connection"),
        "open_db's return_type should be populated from the `-> Connection` annotation"
    );
}

#[test]
fn python_type_self_receiver_inherits_enclosing_class_type() {
    let src = r#"class Repository:
    @classmethod
    def build(cls):
        return Repository()

    def persist(self):
        return type(self).build()
"#;
    let adapter = adapter_for_lang("python").expect("python adapter present");
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("app.py", src)]);
    let persist = find_decl(&ws, "persist").expect("persist decl present");
    let call = find_call(&persist.flow_events, "type(self).build").expect("type(self).build call present");
    let FlowEvent::Call { receiver_types, .. } = call else {
        unreachable!("find_call only returns call events");
    };
    assert!(
        receiver_types.iter().any(|ty| ty == "Repository"),
        "type(self).build should carry Repository receiver type, got {receiver_types:?}"
    );
}

#[test]
fn python_dunder_class_receiver_inherits_enclosing_class_type() {
    let src = r#"class Repository:
    @classmethod
    def build(cls):
        return Repository()

    def persist(self):
        return self.__class__.build()
"#;
    let adapter = adapter_for_lang("python").expect("python adapter present");
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("app.py", src)]);
    let persist = find_decl(&ws, "persist").expect("persist decl present");
    let call =
        find_call(&persist.flow_events, "self.__class__.build").expect("self.__class__.build call present");
    let FlowEvent::Call { receiver_types, .. } = call else {
        unreachable!("find_call only returns call events");
    };
    assert!(
        receiver_types.iter().any(|ty| ty == "Repository"),
        "self.__class__.build should carry Repository receiver type, got {receiver_types:?}"
    );
}
