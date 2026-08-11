use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_go::GoAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("a.go", "package main\nfunc main() {}")]
    );
}

#[test]
fn selector_writes_and_post_call_member_reads_keep_exact_places() {
    use bonsai_lang_api::{FlowEvent, RefKind};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_go::GoAdapter::new())],
        &[(
            "main.go",
            r#"package main
import (
    "encoding/xml"
    "github.com/labstack/echo"
)
func configure(dec *xml.Decoder, entities map[string]string, c echo.Context) {
    dec.Strict = false
    dec.Entity = entities
    _ = c.Request().Body
}
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Go declaration index");
    let configure = index
        .defs
        .iter()
        .find(|decl| decl.name == "configure")
        .expect("configure declaration");
    let assignments = configure
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign { target, .. } => Some(target.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        assignments.contains(&"dec.Strict"),
        "events={:?}",
        configure.flow_events
    );
    assert!(
        assignments.contains(&"dec.Entity"),
        "events={:?}",
        configure.flow_events
    );
    assert!(
        index
            .refs
            .iter()
            .any(|reference| reference.kind == RefKind::Read && reference.name == "c.Request().Body"),
        "refs={:?}; events={:?}",
        index.refs,
        configure.flow_events
    );
}
