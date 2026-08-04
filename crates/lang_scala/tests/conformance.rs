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
