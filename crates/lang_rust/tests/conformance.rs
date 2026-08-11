use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_rust::RustAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("a.rs", "fn main() { helper(); }\nfn helper() {}")]
    );
}

#[test]
fn match_let_and_foreach_bindings_follow_rust_ast_roles() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_rust::RustAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "a.rs",
            r#"fn main(subject: Option<(String, usize)>, rows: Vec<(String, usize)>) {
    if let Some((value, index)) = subject { sink(value, index); }
    match subject { Some((part, count)) => sink(part, count), None => (), }
    for (row, offset) in rows { sink(row, offset); }
}"#,
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
    for (target, source) in [
        ("value", "subject"),
        ("index", "subject"),
        ("part", "subject"),
        ("count", "subject"),
        ("row", "rows"),
        ("offset", "rows"),
    ] {
        assert!(
            facts
                .iter()
                .any(|(actual, actual_source)| actual == target && actual_source.as_deref() == Some(source)),
            "missing {target} <- {source}: {facts:#?}"
        );
    }
    for non_binding in ["Some", "String", "usize"] {
        assert!(
            facts.iter().all(|(target, _)| target != non_binding),
            "type/constructor syntax became a binding: {non_binding}: {facts:#?}"
        );
    }

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
                FlowEvent::Loop { body, .. } => collect_assignments(body, out),
                _ => {}
            }
        }
    }
}
