use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{DeclKind, FlowEvent, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

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

#[test]
fn embedded_struct_methods_have_parent_bases_and_concrete_receiver_type() {
    let db = db_with(
        r#"
package main

type Repository struct{}
func (r *Repository) Run() int { return 1 }

type AuditedRepository struct { *Repository }
func (a *AuditedRepository) Run() int { return a.Repository.Run() }

type Runner interface { Run() int }
func Persist() int {
    var repo Runner = &AuditedRepository{Repository: &Repository{}}
    return repo.Run()
}
"#,
    );
    let global = db.global_index();
    let mut audited_symbol = None;
    let mut repository_symbol = None;
    let mut persist_calls = Vec::new();
    let mut audited_run_parent = None;
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            match (decl.name.as_str(), decl.kind) {
                ("AuditedRepository", DeclKind::Class) => {
                    audited_symbol = Some(decl.symbol);
                    assert_eq!(decl.bases, vec!["Repository"]);
                }
                ("Repository", DeclKind::Class) => repository_symbol = Some(decl.symbol),
                ("Run", DeclKind::Method) if decl.params.first().is_some_and(|p| p == "a") => {
                    audited_run_parent = decl.parent;
                }
                ("Persist", _) => collect_calls(&decl.flow_events, &mut persist_calls),
                _ => {}
            }
        }
    }
    assert_eq!(audited_run_parent, audited_symbol);
    assert!(repository_symbol.is_some(), "Repository class should be indexed");
    assert!(
        persist_calls.iter().any(|(name, receiver_types)| {
            name == "repo.Run"
                && receiver_types.iter().any(|ty| ty == "AuditedRepository")
                && receiver_types.iter().any(|ty| ty == "Repository")
        }),
        "repo.Run should carry concrete allocation type plus embedded base for matching: {persist_calls:?}"
    );
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
fn field_chain_receiver_uses_root_parameter_type() {
    let db = db_with(
        r#"
package main

import "net/http"

func handle(r *http.Request) string {
    return r.Header.Get("X-User")
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
            .any(|(name, receiver_types)| name.ends_with("Header.Get")
                && receiver_types.iter().any(|ty| ty == "Request")),
        "field-chain receiver should inherit root *http.Request type, got {calls:?}"
    );
}
