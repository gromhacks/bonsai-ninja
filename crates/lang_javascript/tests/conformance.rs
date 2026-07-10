use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    run_language_suite!(adapter, trace_from = "main", [("a.js", "function main() {}")]);
}

#[test]
fn arrow_expression_records_implicit_return() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("app.js", "const echo = (x) => x;\n")]);
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let echo = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "echo")
        .expect("echo arrow declaration");

    assert!(echo.has_implicit_returns);
    assert!(
        echo.flow_events
            .iter()
            .any(|event| matches!(event, FlowEvent::Return { value_name, .. } if value_name.as_deref() == Some("x"))),
        "JavaScript arrow expression should emit a Return event; events: {:?}",
        echo.flow_events
    );
}

#[test]
fn commonjs_named_function_export_has_single_semantic_decl() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "service.js",
            "function sink(filter) {}\n\
             exports.search = function search(email, password) {\n  sink({ email, password });\n};\n",
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }

    let global = ws.db().global_index();
    let search_decls: Vec<_> = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .filter(|decl| decl.name == "search")
        .collect();

    assert_eq!(
        search_decls.len(),
        1,
        "CommonJS function export should not create duplicate search FuncIds: {search_decls:#?}"
    );
    assert_eq!(search_decls[0].params, ["email", "password"]);
}

#[test]
fn commonjs_export_alias_preserves_different_local_function_name() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "service.js",
            "exports.lookup = function search(term) {\n  return term;\n};\n",
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }

    let global = ws.db().global_index();
    let names: Vec<_> = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .map(|decl| decl.name.as_str())
        .collect();

    assert!(
        names.contains(&"search"),
        "same-file references should keep resolving the local function name: {names:?}"
    );
    assert!(
        names.contains(&"lookup"),
        "CommonJS import resolution should see the exported member name: {names:?}"
    );
}

#[test]
fn commonjs_object_export_alias_preserves_different_local_function_name() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "service.js",
            "function realSearch(term) {\n  return term;\n}\nmodule.exports = { lookup: realSearch };\n",
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }

    let global = ws.db().global_index();
    let names: Vec<_> = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .map(|decl| decl.name.as_str())
        .collect();

    assert!(
        names.contains(&"realSearch"),
        "same-file references should keep resolving the local function name: {names:?}"
    );
    assert!(
        names.contains(&"lookup"),
        "CommonJS object export should expose the public member name: {names:?}"
    );
}

#[test]
fn iife_body_contributes_to_module_flow() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "browser.js",
            "(function () {\n  const query = window.location.search;\n  document.write(query);\n})();\n",
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let module = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "__module__")
        .expect("module declaration");

    assert!(
        module.flow_events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Assign {
                    target,
                    source_names,
                    ..
                } if target == "query" && source_names.iter().any(|name| name == "window.location.search")
            )
        }),
        "IIFE assignment should be in module flow events: {:?}",
        module.flow_events
    );
    assert!(
        module.flow_events.iter().any(|event| {
            matches!(event, FlowEvent::Call { name, args, .. } if name == "document.write"
                && args.iter().any(|arg| arg.value_text == "query"))
        }),
        "IIFE sink call should be in module flow events: {:?}",
        module.flow_events
    );
}

#[test]
fn iife_params_bind_to_corresponding_arguments() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "browser.js",
            "(function (value) {\n  sink(value);\n})(request.body);\n",
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let module = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "__module__")
        .expect("module declaration");

    assert!(
        module.flow_events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Assign {
                    target,
                    source_names,
                    ..
                } if target == "value" && source_names.iter().any(|name| name == "request.body")
            )
        }),
        "IIFE parameter should bind to its positional argument: {:?}",
        module.flow_events
    );
    assert!(
        module.flow_events.iter().any(|event| {
            matches!(event, FlowEvent::Call { name, args, .. } if name == "sink"
                && args.iter().any(|arg| arg.value_text == "value"))
        }),
        "IIFE body call should be in module flow events: {:?}",
        module.flow_events
    );
}

#[test]
fn object_destructuring_preserves_aggregate_and_exact_field_sources() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "app.js",
            "function entry(args) {\n  const { v } = args;\n  sink(v);\n}\n",
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let entry = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "entry")
        .expect("entry declaration");

    let v_sources = entry
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign {
                target, source_name, ..
            } if target == "v" => source_name.as_deref(),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(v_sources, ["args", "args.v"]);
    assert!(entry.flow_events.iter().any(|event| {
        matches!(
            event,
            FlowEvent::Assign {
                target,
                source_name: Some(source),
                value_kind: Some(bonsai_lang_api::AssignValueKind::Destructure),
                ..
            } if target == "v" && source == "args"
        )
    }));
}

#[test]
fn esm_named_export_alias_preserves_different_local_function_name() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "service.js",
            "function realRender(value) {\n  return value;\n}\nexport { realRender as render };\n",
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }

    let global = ws.db().global_index();
    let names: Vec<_> = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .map(|decl| decl.name.as_str())
        .collect();

    assert!(
        names.contains(&"realRender"),
        "same-file references should keep resolving the local function name: {names:?}"
    );
    assert!(
        names.contains(&"render"),
        "ES named export should expose the public member name: {names:?}"
    );
}
