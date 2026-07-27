use bonsai_db::AnalyzerDb;
use bonsai_lang_api::LanguageRegistry;
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
