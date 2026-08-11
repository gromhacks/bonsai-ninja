use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_dart::DartAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("main.dart", "void main() { helper(); }\nvoid helper() {}\n")]
    );
}

#[test]
fn switch_variable_pattern_binds_the_subject_without_binding_its_type() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_dart::DartAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "app.dart",
            "void main(Object subject) { switch (subject) { case String value: sink(value); } }",
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
fn lowercase_declared_and_cast_types_remain_receiver_evidence() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_dart::DartAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "app.dart",
            "class lower { void run(String value) {} }\n\
             void handle(lower declared, dynamic input, String value) {\n\
               final casted = input as lower;\n\
               declared.run(value); casted.run(value);\n\
             }",
        )],
    );
    let global = ws.db().global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");
    let typed_calls = handle.flow_events.iter().filter(|event| {
        matches!(
            event,
            FlowEvent::Call { name, receiver_types, .. }
                if name.rsplit('.').next() == Some("run")
                    && receiver_types.iter().any(|ty| ty == "lower")
        )
    });
    assert_eq!(typed_calls.count(), 2, "events: {:#?}", handle.flow_events);
}

#[test]
fn nested_string_templates_expose_only_parsed_identifier_reads() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "app.dart",
            r#"
void run(String command, String unrelated) {
  Process.runSync('sh', ['-c', 'notify $command']);
  Process.runSync('sh', ['-c', 'the words command and unrelated are literals']);
}
"#,
        )],
    );
    let global = workspace.db().global_index();
    let run = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "run")
        .expect("run declaration");
    let calls = run
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name == "Process.runSync" => Some(args),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(calls.len(), 2, "events={:#?}", run.flow_events);
    assert_eq!(calls[0][1].source_names, ["command"]);
    assert!(calls[0][1].source_names.iter().all(|name| name != "unrelated"));
    assert!(
        calls[1][1].source_names.is_empty(),
        "literal text is not an identifier read"
    );
}

#[test]
fn assignment_targets_preserve_bare_and_qualified_assignable_places() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "tls.dart",
            "void configure(dynamic client, dynamic input) { onBadCertificate = input; client.badCertificateCallback = true; }",
        )],
    );
    let global = workspace.db().global_index();
    let configure = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "configure")
        .expect("configure declaration");
    let targets = configure
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign { target, .. } => Some(target.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        targets.contains(&"onBadCertificate"),
        "events={:?}",
        configure.flow_events
    );
    assert!(
        targets.contains(&"client.badCertificateCallback"),
        "events={:?}",
        configure.flow_events
    );
}

#[test]
fn positional_member_arguments_preserve_the_complete_selector_place() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[("app.dart", "void run(dynamic box) { sink(box.clean); }")],
    );
    let global = workspace.db().global_index();
    let run = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "run")
        .expect("run declaration");
    let argument = run
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name == "sink" => args.first(),
            _ => None,
        })
        .expect("sink argument");

    assert_eq!(argument.place.as_deref(), Some("box.clean"));
    assert_eq!(argument.value_text, "box.clean");
}
