use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{DeclKind, FlowEvent, LanguageRegistry, StaticScalarValue};
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

#[test]
fn qualified_embedded_base_identity_reaches_promoted_method_calls() {
    let db = db_with(
        r#"
package main

import "example.net/web"

type Handler struct { web.Controller }
func (h *Handler) Get() string { return h.GetString("name") }
"#,
    );
    let global = db.global_index();
    let mut calls = Vec::new();
    let mut handler_bases = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == "Handler" {
                handler_bases = decl.bases.clone();
            }
            if decl.name == "Get" {
                collect_calls(&decl.flow_events, &mut calls);
            }
        }
    }
    assert!(
        handler_bases.iter().any(|base| base == "Controller")
            && handler_bases.iter().any(|base| base == "web.Controller"),
        "embedded bases must retain short and import-qualified identities: {handler_bases:?}"
    );
    assert!(
        calls.iter().any(|(name, receiver_types)| {
            name == "h.GetString"
                && receiver_types.iter().any(|ty| ty == "Controller")
                && receiver_types.iter().any(|ty| ty == "web.Controller")
        }),
        "promoted calls must carry the exact embedded-base identity: {calls:?}"
    );
}

#[test]
fn if_initializer_call_retains_literal_argument_value() {
    let db = db_with(
        r#"
package main

func Unpack(input any, root string) error { return nil }
func Handle(input any) error {
    if err := Unpack(input, "/srv/uploads"); err != nil {
        return err
    }
    return nil
}
"#,
    );
    let file = db.vfs().all_files().into_iter().next().expect("Go source");
    let index = db.decl_index(file).expect("Go declaration index");
    let argument = index
        .call_argument_values
        .iter()
        .find(|argument| {
            argument.argument_index == 1
                && matches!(
                    argument.static_value.as_ref(),
                    Some(StaticScalarValue::String(value)) if value == "/srv/uploads"
                )
        })
        .unwrap_or_else(|| {
            panic!(
                "if-initializer calls must retain exact literal arguments: {:#?}",
                index.call_argument_values
            )
        });
    assert_eq!(argument.argument_index, 1);
}

#[test]
fn const_initializer_retains_exact_immutable_scalar_value() {
    let db = db_with(
        r#"
package main

const baseDir = "/srv/data"

func Read(name string) string {
    return baseDir + "/" + name
}
"#,
    );
    let file = db.vfs().all_files().into_iter().next().expect("Go source");
    let index = db.decl_index(file).expect("Go declaration index");
    let fact = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("baseDir"))
        .unwrap_or_else(|| panic!("missing const value fact: {:#?}", index.assignment_values));
    assert!(
        fact.target_is_immutable,
        "const binding must be immutable: {fact:#?}"
    );
    assert_eq!(
        fact.static_value,
        Some(StaticScalarValue::String("/srv/data".to_string())),
        "const binding must retain the grammar-decoded scalar: {fact:#?}"
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
fn passed_func_literal_parameter_types_drive_receiver_matching_in_callback_scope() {
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
            // A passed function literal is a callable value, not executed by
            // Register itself. Its calls and typed parameter facts therefore
            // belong to the exact lambda declaration linked from r.GET's
            // callback argument.
            if decl.name.starts_with("<lambda@") {
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

#[test]
fn qualified_composite_literal_types_the_short_declared_receiver() {
    let db = db_with(
        r#"
package main

import "net/http"

func fetch(url string) {
    client := &http.Client{}
    _, _ = client.Get(url)
}
"#,
    );
    let global = db.global_index();
    let fetch = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "fetch")
        .expect("fetch declaration");
    assert!(
        fetch
            .type_aliases
            .iter()
            .any(|alias| alias.name == "client" && alias.type_name == "http.Client"),
        "qualified composite literal must retain the complete Go type: {:?}",
        fetch.type_aliases
    );
    let mut calls = Vec::new();
    collect_calls(&fetch.flow_events, &mut calls);
    assert!(
        calls.iter().any(|(name, receiver_types)| {
            name == "client.Get" && receiver_types.iter().any(|ty| ty == "http.Client")
        }),
        "client.Get must carry http.Client receiver evidence: {calls:?}"
    );
}

#[test]
fn package_scope_declared_receiver_type_is_retained_on_module_scope() {
    let db = db_with(
        r#"
package main

import "database/sql"

var Store *sql.DB

func query(value string) {
    _, _ = Store.Query(value)
}
"#,
    );
    let global = db.global_index();
    let query = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "query")
        .expect("query declaration");
    assert!(
        query
            .type_aliases
            .iter()
            .any(|alias| alias.name == "Store" && alias.type_name == "sql.DB"),
        "package-scope declared type must remain available to receiver matching: {:?}",
        query.type_aliases
    );
}

#[test]
fn named_struct_field_receiver_uses_its_declared_type_not_the_owner_type() {
    let db = db_with(
        r#"
package main

import "database/sql"

type Store struct { DB *sql.DB }
func (s *Store) Query(ctx any, query string) {
    s.DB.QueryContext(ctx, query)
}

type LocalDB struct{}
type LocalStore struct { DB *LocalDB }
func (s *LocalStore) Query(ctx any, query string) {
    s.DB.QueryContext(ctx, query)
}
"#,
    );
    let global = db.global_index();
    let mut external_calls = Vec::new();
    let mut local_calls = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name != "Query" {
                continue;
            }
            if decl
                .type_aliases
                .iter()
                .any(|alias| alias.name == "s" && alias.type_name == "Store")
            {
                assert!(
                    decl.type_aliases
                        .iter()
                        .any(|alias| alias.name == "s.DB" && alias.type_name == "sql.DB"),
                    "the field declaration must retain its imported type: {:?}",
                    decl.type_aliases
                );
                collect_calls(&decl.flow_events, &mut external_calls);
            } else {
                collect_calls(&decl.flow_events, &mut local_calls);
            }
        }
    }
    assert!(
        external_calls.iter().any(|(name, receiver_types)| {
            name == "s.DB.QueryContext"
                && receiver_types.iter().any(|ty| ty == "sql.DB")
                && !receiver_types.iter().any(|ty| ty == "Store")
        }),
        "external field call must use the field type, not the owner: {external_calls:?}"
    );
    assert!(
        local_calls.iter().any(|(name, receiver_types)| {
            name == "s.DB.QueryContext"
                && receiver_types.iter().any(|ty| ty == "LocalDB")
                && !receiver_types.iter().any(|ty| ty == "sql.DB")
        }),
        "a same-named local field type must not acquire provider identity: {local_calls:?}"
    );
}

#[test]
fn func_literal_captures_nearest_lexical_parameter_type() {
    let db = db_with(
        r#"
package main

import "example.net/store"

func Handler(client *store.Client) func(string) {
    return func(value string) {
        client.Write(value)
    }
}
"#,
    );
    let global = db.global_index();
    let closure = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name.starts_with("<lambda@"))
        .expect("function literal declaration");
    assert!(
        closure
            .type_aliases
            .iter()
            .any(|alias| alias.name == "client" && alias.type_name == "store.Client"),
        "closure must inherit the exact captured receiver type: {:?}",
        closure.type_aliases
    );
}
