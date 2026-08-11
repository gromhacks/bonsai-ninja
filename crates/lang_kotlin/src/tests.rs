use super::*;

#[test]
fn function_reference_assignment_emits_clean_callable_alias() {
    use bonsai_lang_api::{AssignValueKind, LanguageAdapter};
    use std::sync::Arc;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Callbacks.kt",
            r#"
fun helper(value: String) = value

fun apply(value: String): String {
  val cb = ::helper
  return cb(value)
}
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let apply = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "apply")
        .expect("apply declaration");
    let aliases = apply
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_names,
                value_kind,
                ..
            } if target == "cb" => Some((source_name, source_call, source_names, value_kind)),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(
        aliases.len(),
        1,
        "callable reference should be one compiler fact: {:#?}",
        apply.flow_events
    );
    assert_eq!(aliases[0].0.as_deref(), Some("helper"));
    assert_eq!(aliases[0].1.as_deref(), None);
    assert!(aliases[0].2.is_empty());
    assert_eq!(aliases[0].3, &Some(AssignValueKind::CallableReference));
}

#[test]
fn initialized_and_type_only_properties_have_distinct_value_semantics() {
    use bonsai_lang_api::{AssignValueKind, LanguageAdapter};
    use std::sync::Arc;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Properties.kt",
            r#"
abstract class Base {
  abstract val deferred: String
  fun run() {
    val initialized = "ready"
    sink(initialized)
  }
}
"#,
        )],
    );
    let global = ws.db().global_index();
    let run = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "run")
        .expect("run declaration");

    assert!(
        run.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                value_kind: Some(AssignValueKind::Literal),
                ..
            } if target == "initialized"
        )),
        "events={:?}",
        run.flow_events
    );
    assert!(
        global
            .all_files()
            .flat_map(|file| global.decls_in(file))
            .flat_map(|decl| decl.flow_events.iter())
            .all(|event| !matches!(event, FlowEvent::Assign { target, .. } if target == "deferred")),
        "type-only abstract property must not invent a runtime assignment"
    );
}

#[test]
fn directly_assignable_navigation_preserves_the_complete_field_place() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};
    use std::sync::Arc;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[("Fields.kt", "fun update(c: Any, args: String) { c.cmd = args }")],
    );
    let global = ws.db().global_index();
    let update = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "update")
        .expect("update declaration");

    assert!(
        update.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign { target, source_name, .. }
                if target == "c.cmd" && source_name.as_deref() == Some("args")
        )),
        "events={:#?}",
        update.flow_events
    );
}

#[test]
fn singleton_object_owns_methods_and_types_class_side_dispatch() {
    use bonsai_lang_api::LanguageAdapter;
    use std::sync::Arc;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Singleton.kt",
            "object Box { fun helper(p: String) { sink(p) } }\n\
             fun entry(args: String) { Box.helper(args) }\n",
        )],
    );
    let global = ws.db().global_index();
    let object = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.kind == DeclKind::Class && decl.name == "Box")
        .expect("singleton object declaration");
    let helper = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "helper")
        .expect("object method declaration");
    assert_eq!(helper.kind, DeclKind::Method);
    assert_eq!(helper.parent, Some(object.symbol));

    let entry = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "entry")
        .expect("entry declaration");
    let call = entry
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call {
                name,
                receiver,
                receiver_types,
                ..
            } if name == "Box.helper" => Some((receiver, receiver_types)),
            _ => None,
        })
        .expect("class-side call fact");
    assert_eq!(call.0.as_deref(), Some("Box"));
    assert_eq!(call.1, &["Box"]);
}

#[test]
fn singleton_object_does_not_steal_nested_local_function_ownership() {
    use bonsai_lang_api::LanguageAdapter;
    use std::sync::Arc;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Nested.kt",
            "object Box {\n\
                 fun helper(p: String) {\n\
                   fun nested(q: String) { sink(q) }\n\
                   nested(p)\n\
                 }\n\
             }\n",
        )],
    );
    let global = ws.db().global_index();
    let object = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.kind == DeclKind::Class && decl.name == "Box")
        .expect("singleton object declaration");
    let helper = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "helper")
        .expect("direct object method");
    let nested = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "nested")
        .expect("nested local function");
    assert_eq!(helper.parent, Some(object.symbol));
    assert_eq!(nested.parent, Some(helper.symbol));
    assert_ne!(nested.parent, Some(object.symbol));
}
