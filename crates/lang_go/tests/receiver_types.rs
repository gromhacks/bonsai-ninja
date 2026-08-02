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
                ("AuditedRepository", DeclKind::Struct) => {
                    audited_symbol = Some(decl.symbol);
                    assert_eq!(decl.bases, vec!["Repository"]);
                }
                ("Repository", DeclKind::Struct) => repository_symbol = Some(decl.symbol),
                ("Run", DeclKind::Method) if decl.params.first().is_some_and(|p| p == "a") => {
                    audited_run_parent = decl.parent;
                }
                ("Persist", _) => collect_calls(&decl.flow_events, &mut persist_calls),
                _ => {}
            }
        }
    }
    assert_eq!(audited_run_parent, audited_symbol);
    assert!(repository_symbol.is_some(), "Repository struct should be indexed");
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

#[test]
fn func_literal_parameter_types_drive_receiver_matching() {
    let db = db_with(
        r##"
package main

import "github.com/gin-gonic/gin"

func Register(r *gin.RouterGroup) {
    r.GET("/:name", func(c *gin.Context) {
        _ = c.Param("name")
    })
}
"##,
    );
    let global = db.global_index();
    let mut calls = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == "Register" {
                collect_calls(&decl.flow_events, &mut calls);
            }
        }
    }
    assert!(
        calls.iter().any(|(name, receiver_types)| {
            name == "c.Param"
                && receiver_types.iter().any(|ty| ty == "Context")
                && receiver_types.iter().any(|ty| ty == "gin.Context")
        }),
        "func literal receiver c should carry *gin.Context aliases, got {calls:?}"
    );
}

#[test]
fn returned_func_literal_parameter_types_and_if_initializer_calls_are_preserved() {
    let db = db_with(
        r#"
package main

import "github.com/gin-gonic/gin"

func Login() gin.HandlerFunc {
    return func(c *gin.Context) {
        var body map[string]any
        if err := c.BindJSON(&body); err != nil {
            c.AbortWithStatus(400)
            return
        }
    }
}
"#,
    );
    let global = db.global_index();
    let mut calls = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name.starts_with("<lambda@") {
                collect_calls(&decl.flow_events, &mut calls);
            }
        }
    }
    assert!(
        calls.iter().any(|(name, receiver_types)| {
            name == "c.BindJSON"
                && receiver_types.iter().any(|ty| ty == "Context")
                && receiver_types.iter().any(|ty| ty == "gin.Context")
        }),
        "returned func literal should keep if-initializer calls and typed receiver aliases, got {calls:?}"
    );
}
