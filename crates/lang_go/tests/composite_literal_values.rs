use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{FlowEvent, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_with(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("main.go".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_go::GoAdapter::new()));
    AnalyzerDb::new(vfs, registry)
}

#[test]
fn nested_keyed_composite_argument_emits_exact_aggregate_shape() {
    let db = db_with(
        r#"
package main

func find(filter any) {}

func login(email string, password string) {
    find(map[string]any{
        "email": map[string]any{"$eq": email},
        "password": map[string]any{"$eq": password},
    })
}
"#,
    );
    let file = *db.vfs().all_files().first().expect("fixture file");
    let index = db.decl_index(file).expect("Go declaration index");
    let argument = index
        .call_argument_values
        .iter()
        .find(|fact| fact.argument_index == 0 && fact.value_flow.aggregate_fields.len() == 2)
        .expect("keyed composite call argument");

    assert!(argument.value_flow.aggregate_fields.iter().all(|field| {
        field.value.aggregate_fields.len() == 1 && field.value.aggregate_fields[0].name == "$eq"
    }));

    let login = index
        .defs
        .iter()
        .find(|decl| decl.name == "login")
        .expect("login declaration");
    let find_argument = find_call_argument(&login.flow_events, "find", 0).expect("find filter argument");
    assert_eq!(
        find_argument.source_names,
        ["email", "password"],
        "nested aggregate dependencies must reach the call IR without reparsing rendered text"
    );
}

fn find_call_argument<'a>(
    events: &'a [FlowEvent],
    callee: &str,
    argument_index: usize,
) -> Option<&'a bonsai_lang_api::CallArg> {
    for event in events {
        match event {
            FlowEvent::Call { name, args, .. } if name == callee => {
                if let Some(argument) = args.get(argument_index) {
                    return Some(argument);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(argument) = find_call_argument(then_events, callee, argument_index)
                    .or_else(|| find_call_argument(else_events, callee, argument_index))
                {
                    return Some(argument);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(argument) = find_call_argument(body, callee, argument_index) {
                    return Some(argument);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(argument) = find_call_argument(body, callee, argument_index)
                    .or_else(|| find_call_argument(catch_events, callee, argument_index))
                    .or_else(|| find_call_argument(finally_events, callee, argument_index))
                {
                    return Some(argument);
                }
            }
            _ => {}
        }
    }
    None
}

#[test]
fn literal_nested_composite_argument_has_no_dynamic_sources() {
    let db = db_with(
        r#"
package main

func find(filter any) {}

func lookup() {
    find(map[string]any{"active": map[string]any{"$eq": true}})
}
"#,
    );
    let file = *db.vfs().all_files().first().expect("fixture file");
    let index = db.decl_index(file).expect("Go declaration index");
    let lookup = index
        .defs
        .iter()
        .find(|decl| decl.name == "lookup")
        .expect("lookup declaration");
    let argument = find_call_argument(&lookup.flow_events, "find", 0).expect("find filter argument");
    assert!(argument.source_names.is_empty());
}

#[test]
fn typed_pointer_struct_initializer_has_one_binding_and_exact_nested_fields() {
    let db = db_with(
        r#"
package main

type Envelope struct { Cmd string; User string }
type Repository struct { data Envelope }
type AuditedRepository struct { Repository *Repository }
type Runner interface { Run() int }

func Persist(data Envelope) int {
    var repo Runner = &AuditedRepository{Repository: &Repository{data: data}}
    return repo.Run()
}
"#,
    );
    let file = *db.vfs().all_files().first().expect("fixture file");
    let index = db.decl_index(file).expect("Go declaration index");
    let assignment = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("repo"))
        .expect("repo initializer compiler fact");
    let repository = assignment
        .value_flow
        .aggregate_fields
        .iter()
        .find(|field| field.name == "Repository")
        .expect("outer Repository field");
    let data = repository
        .value
        .aggregate_fields
        .iter()
        .find(|field| field.name == "data")
        .expect("nested data field");
    assert_eq!(data.value.place.as_deref(), Some("data"));

    let persist = index
        .defs
        .iter()
        .find(|decl| decl.name == "Persist")
        .expect("Persist declaration");
    let mut targets = Vec::new();
    collect_assignment_targets(&persist.flow_events, &mut targets);
    assert_eq!(
        targets,
        vec!["repo"],
        "the declaration wrapper, type, RHS identifiers, and aggregate fields are not independent assignments"
    );
}

fn collect_assignment_targets<'a>(events: &'a [FlowEvent], out: &mut Vec<&'a str>) {
    for event in events {
        match event {
            FlowEvent::Assign { target, .. } | FlowEvent::AggregateAssign { target, .. } => {
                out.push(target);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assignment_targets(then_events, out);
                collect_assignment_targets(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_assignment_targets(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assignment_targets(body, out);
                collect_assignment_targets(catch_events, out);
                collect_assignment_targets(finally_events, out);
            }
            _ => {}
        }
    }
}

#[test]
fn static_call_argument_is_preserved_without_expression_flow() {
    let db = db_with(
        r#"
package main

func unpack(src any, base string) error { return nil }

func upload(input any) {
    if err := unpack(input, "/var/data/uploads"); err != nil {
        return
    }
}
"#,
    );
    let file = *db.vfs().all_files().first().expect("fixture file");
    let index = db.decl_index(file).expect("Go declaration index");
    let argument = index
        .call_argument_values
        .iter()
        .find(|fact| fact.argument_index == 1)
        .expect("literal argument compiler fact");

    assert_eq!(
        argument.static_value,
        Some(bonsai_lang_api::StaticScalarValue::String(
            "/var/data/uploads".to_string()
        ))
    );
}

#[test]
fn url_guard_syntax_emits_membership_static_map_and_exact_callback_return() {
    use bonsai_lang_api::ConditionExpressionFact;

    let db = db_with(
        r#"
package main

import (
    "net/http"
    neturl "net/url"
)

var allowedHosts = map[string]bool{"api.example.com": true}

func fetch(raw string) {
    u, err := neturl.Parse(raw)
    if err != nil || u.Scheme != "https" || !allowedHosts[u.Hostname()] {
        return
    }
    client := &http.Client{
        CheckRedirect: func(*http.Request, []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }
    _, _ = client.Get(u.String())
}
"#,
    );
    let file = *db.vfs().all_files().first().expect("fixture file");
    let index = db.decl_index(file).expect("Go declaration index");
    let guard_expression = index
        .branch_conditions
        .iter()
        .find_map(|fact| fact.expression.as_ref())
        .expect("typed URL guard condition");
    let ConditionExpressionFact::Any { operands, .. } = guard_expression else {
        panic!("expected disjunction: {guard_expression:#?}");
    };
    assert!(operands.iter().any(|operand| matches!(
        operand,
        ConditionExpressionFact::Not { operand, .. }
            if matches!(operand.as_ref(), ConditionExpressionFact::Membership { then_contains: true, .. })
    )));
    let allowlist = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("allowedHosts"))
        .expect("static allowlist assignment");
    assert_eq!(allowlist.value_flow.aggregate_fields.len(), 1);
    let redirect = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("client.CheckRedirect"))
        .expect("exact callback field assignment");
    assert_eq!(
        redirect
            .exact_callable_return
            .as_ref()
            .and_then(|flow| flow.place.as_deref()),
        Some("http.ErrUseLastResponse")
    );
}
