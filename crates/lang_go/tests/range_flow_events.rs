use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{FlowEvent, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

type AssignSummary = (String, Option<String>, Option<String>, Vec<String>);

fn db_with(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("main.go".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_go::GoAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn collect_assigns(events: &[FlowEvent], out: &mut Vec<AssignSummary>) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_names,
                ..
            } => out.push((
                target.clone(),
                source_name.clone(),
                source_call.clone(),
                source_names.clone(),
            )),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assigns(then_events, out);
                collect_assigns(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_assigns(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assigns(body, out);
                collect_assigns(catch_events, out);
                collect_assigns(finally_events, out);
            }
            _ => {}
        }
    }
}

#[test]
fn range_clauses_emit_precise_iteration_value_assignments() {
    let db = db_with(
        r#"
package main

func tokenize(cmd string) <-chan string { return nil }

func entry(cmd string, tokens []string) {
    for tok := range tokenize(cmd) {
        use(tok)
    }
    for _, t := range tokens {
        use(t)
    }
}
"#,
    );
    let global = db.global_index();
    let mut assigns = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == "entry" {
                collect_assigns(&decl.flow_events, &mut assigns);
            }
        }
    }

    assert!(
        assigns
            .iter()
            .any(|(target, _, source_call, _)| target == "tok" && source_call.as_deref() == Some("tokenize")),
        "single-target channel range should bind tok from tokenize() return: {assigns:?}"
    );
    assert!(
        assigns.iter().any(|(target, source_name, _, source_names)| {
            target == "t"
                && (source_name.as_deref() == Some("tokens")
                    || source_names.iter().any(|name| name == "tokens"))
        }),
        "two-target range should bind value variable from ranged collection: {assigns:?}"
    );
    assert!(
        !assigns.iter().any(|(target, _, _, _)| target == "range"),
        "Go range lowering must not keep broad synthetic range assignments: {assigns:?}"
    );
}
