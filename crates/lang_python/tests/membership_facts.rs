use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{ConditionExpressionFact, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

#[test]
fn membership_guards_and_literal_sets_are_compiler_facts() {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write(
        "guards.py".to_string(),
        Arc::<str>::from(
            r#"
ALLOWED = {"a", "b"}

def check(value):
    if value not in ALLOWED:
        return
    if not value in ALLOWED:
        return
    if value in ALLOWED:
        pass
"#,
        ),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let index = db.decl_index(file).expect("Python declaration index");

    let membership: Vec<_> = index
        .branch_conditions
        .iter()
        .filter_map(|fact| fact.membership.as_ref())
        .collect();
    assert_eq!(membership.len(), 3, "{membership:#?}");
    assert!(
        membership
            .iter()
            .all(|fact| fact.subject == "value" && fact.collection == "ALLOWED"),
        "{membership:#?}"
    );
    assert_eq!(
        membership
            .iter()
            .map(|fact| fact.then_contains)
            .collect::<Vec<_>>(),
        vec![false, false, true],
        "{membership:#?}"
    );

    let set_flow = index
        .assignment_values
        .iter()
        .find(|fact| !fact.value_flow.tuple_items.is_empty())
        .expect("literal set assignment flow");
    assert_eq!(set_flow.value_flow.tuple_items.len(), 2, "{set_flow:#?}");
    assert!(
        set_flow.value_flow.tuple_items.iter().all(|item| item.is_empty()),
        "literal set items must carry no value dependencies: {set_flow:#?}"
    );
}

#[test]
fn rejection_guard_boolean_structure_is_compiler_lowered() {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write(
        "types.py".to_string(),
        Arc::<str>::from(
            r#"
def authenticate(email, password):
    if not isinstance(email, str) or not isinstance(password, str):
        raise ValueError("strings required")
    return {"email": email, "password": password}
"#,
        ),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let index = db.decl_index(file).expect("Python declaration index");

    let expression = index
        .branch_conditions
        .iter()
        .find_map(|fact| fact.expression.as_ref())
        .expect("typed rejection-guard expression");
    let ConditionExpressionFact::Any { operands, .. } = expression else {
        panic!("expected disjunction, got {expression:#?}");
    };
    assert_eq!(operands.len(), 2, "{expression:#?}");
    assert!(
        operands.iter().all(|operand| {
            matches!(
                operand,
                ConditionExpressionFact::Not { operand, .. }
                    if matches!(
                        operand.as_ref(),
                        ConditionExpressionFact::TypeTest { type_name, .. }
                            if type_name == "str"
                    )
            )
        }),
        "{expression:#?}"
    );
}

#[test]
fn membership_falsey_fallback_retains_exact_dynamic_projection() {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write(
        "url_guard.py".to_string(),
        Arc::<str>::from(
            r#"
ALLOWED = {"example.com"}

def check(parsed):
    if (parsed.hostname or "") not in ALLOWED:
        raise ValueError("blocked")
"#,
        ),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let index = db.decl_index(file).expect("Python declaration index");

    let expression = index
        .branch_conditions
        .iter()
        .find_map(|fact| fact.expression.as_ref())
        .expect("typed host allowlist condition");
    let ConditionExpressionFact::Membership { subject, .. } = expression else {
        panic!("expected membership condition, got {expression:#?}");
    };
    let projection = subject
        .value_flow
        .projection
        .as_ref()
        .expect("falsey fallback preserves the dynamic projection");
    assert_eq!(projection.base, "parsed");
    assert_eq!(projection.path, ["hostname"]);
}

#[test]
fn boolean_property_disjunction_is_typed_truthy_ir() {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write(
        "address_guard.py".to_string(),
        Arc::<str>::from(
            r#"
def check(ip):
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError("blocked")
"#,
        ),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let index = db.decl_index(file).expect("Python declaration index");

    let expression = index
        .branch_conditions
        .iter()
        .find_map(|fact| fact.expression.as_ref())
        .expect("typed private-address condition");
    let ConditionExpressionFact::Any { operands, .. } = expression else {
        panic!("expected disjunction, got {expression:#?}");
    };
    let projections = operands
        .iter()
        .map(|operand| match operand {
            ConditionExpressionFact::Truthy { operand, .. } => operand
                .value_flow
                .projection
                .as_ref()
                .map(|projection| projection.canonical_place()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        projections,
        [
            Some("ip.is_private".to_string()),
            Some("ip.is_loopback".to_string()),
            Some("ip.is_link_local".to_string()),
        ]
    );
}
