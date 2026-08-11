use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_scala::ScalaAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("a.scala", "object A { def main(args: Array[String]): Unit = () }")]
    );
}

#[test]
fn match_case_binding_uses_the_match_subject_not_type_syntax() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_scala::ScalaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "A.scala",
            "object A { def main(args: String) = args match { case value: String => sink(value) } }",
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
            .any(|(target, source)| target == "value" && source.as_deref() == Some("args")),
        "missing value <- args: {facts:#?}"
    );
    assert!(
        facts.iter().all(|(target, _)| target != "String"),
        "type syntax became a binding: {facts:#?}"
    );

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
fn constructor_throw_carries_its_dynamic_payload_into_the_catch() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_scala::ScalaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "App.scala",
            "object App { def handle(token: String): Unit = { try { throw new RuntimeException(token) } catch { case e: Exception => sink(e.getMessage) } }; def sink(s: String): Unit = {} }",
        )],
    );
    let global = ws.db().global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");
    let body = handle.flow_events.iter().find_map(|event| match event {
        FlowEvent::Try { body, .. } => Some(body),
        _ => None,
    });
    assert!(
        body.is_some_and(|body| body.iter().any(
            |event| matches!(event, FlowEvent::Throw { value_name: Some(value), .. } if value == "token")
        )),
        "Scala throw payload was not lowered from the parsed throw expression: {:#?}",
        handle.flow_events
    );
}

#[test]
fn instance_expression_emits_the_exact_constructor_identity() {
    use bonsai_lang_api::{CallKind, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "App.scala",
            "object App { def handle(input: String): Unit = { new X509TrustManager(input) } }; class X509TrustManager(args: Any*)",
        )],
    );
    let global = workspace.db().global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");

    assert!(
        handle.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, call_kind: CallKind::Constructor, args, .. }
                if name == "X509TrustManager"
                    && args.first().is_some_and(|arg| arg.value_text == "input")
        )),
        "events={:#?}",
        handle.flow_events
    );
}

#[test]
fn postfix_operator_call_keeps_its_value_receiver_flow() {
    use bonsai_lang_api::{AssignValueKind, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "App.scala",
            r#"
object App {
  def run(command: String, unrelated: String): Unit = {
    val fullCommand = s"notify $command"
    fullCommand.!
  }
}
"#,
        )],
    );
    let file = workspace
        .db()
        .vfs()
        .all_files()
        .into_iter()
        .next()
        .expect("Scala file");
    let index = workspace.db().decl_index(file).expect("Scala compiler index");
    let run = index
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run declaration");
    let call_span = run
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                args,
                ..
            } if name == "fullCommand.!" && receiver.as_deref() == Some("fullCommand") && args.is_empty() => {
                Some(*span)
            }
            _ => None,
        })
        .expect("postfix operator call");
    assert!(
        run.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_names,
                value_kind: Some(AssignValueKind::Compound),
                ..
            } if target == "fullCommand"
                && source_names.iter().any(|name| name == "command")
                && source_names.iter().all(|name| name != "unrelated")
        )),
        "interpolated assignment must remain data-dependent: {:#?}",
        run.flow_events
    );
    let fact = index
        .call_receivers
        .iter()
        .find(|fact| fact.call_span == call_span)
        .expect("postfix receiver fact must join the semantic call span");

    assert_eq!(fact.value_flow.place.as_deref(), Some("fullCommand"));
    assert_eq!(fact.value_flow.source_names, ["fullCommand"]);
    assert!(fact
        .value_flow
        .source_names
        .iter()
        .all(|name| name != "unrelated"));
}
