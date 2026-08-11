use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_php::PhpAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("a.php", "<?php function main() {}")]
    );
}

#[test]
fn member_constructor_and_language_keyword_calls_have_exact_identities() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_php::PhpAdapter::new())],
        &[(
            "calls.php",
            r#"<?php
function inspect_calls($request, $stmt, $value) {
    $request->getContent();
    $stmt->bind_param('s', $value);
    new Twig\Environment($value, ['autoescape' => false]);
    unset($value);
}
"#,
        )],
    );
    let global = workspace.db().global_index();
    let declaration = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "inspect_calls")
        .expect("inspect_calls declaration");
    let calls = declaration
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for expected in [
        "$request.getContent",
        "$stmt.bind_param",
        "Twig\\Environment",
        "unset",
    ] {
        assert!(
            calls.contains(&expected),
            "missing {expected}: events={:?}",
            declaration.flow_events
        );
    }
}

#[test]
fn positional_variable_argument_retains_its_addressable_place() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_php::PhpAdapter::new())],
        &[("calls.php", "<?php function forward($value) { consume($value); }")],
    );
    let global = workspace.db().global_index();
    let declaration = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "forward")
        .expect("forward declaration");
    let argument = declaration
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name == "consume" => args.first(),
            _ => None,
        })
        .expect("consume argument");

    assert_eq!(argument.place.as_deref(), Some("$value"));
}
