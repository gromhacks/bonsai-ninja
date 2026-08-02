use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    run_language_suite!(adapter, trace_from = "main", [("a.js", "function main() {}")]);
}

#[test]
fn typeof_rejection_guard_is_typed_condition_ir() {
    use bonsai_lang_api::{ConditionExpressionFact, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "auth.js",
            r#"
function authenticate(email, password) {
  if (typeof email !== "string" || typeof password !== "string") {
    throw new Error("strings required");
  }
}
"#,
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("JavaScript declaration index");
    assert!(index.branch_conditions.iter().any(|fact| matches!(
        &fact.expression,
        Some(ConditionExpressionFact::Any { operands, .. })
            if operands.iter().all(|operand| matches!(
                operand,
                ConditionExpressionFact::Not { operand, .. }
                    if matches!(
                        operand.as_ref(),
                        ConditionExpressionFact::TypeTest { type_name, .. }
                            if type_name == "string"
                    )
            ))
    )));
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
fn denylist_constructor_and_condition_emit_exact_compiler_facts() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "merge.js",
            "const BLOCKED = new Set([\"__proto__\", \"constructor\", \"prototype\"]);\n\
             function merge(target, source) {\n\
               for (const key of Object.keys(source)) {\n\
                 if (BLOCKED.has(key)) continue;\n\
                 target[key] = source[key];\n\
               }\n\
             }\n",
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("JavaScript declaration index");

    let constructor = index
        .assignment_values
        .iter()
        .find(|fact| fact.direct_call_name.as_deref() == Some("Set"))
        .expect("adapter-declared constructor assignment");
    assert_eq!(constructor.target.as_deref(), Some("BLOCKED"));
    let values = index
        .call_argument_values
        .iter()
        .find(|fact| {
            fact.argument_index == 0
                && fact.call_span.start >= constructor.value_span.start
                && fact.call_span.end <= constructor.value_span.end
        })
        .expect("constructor argument value fact");
    assert_eq!(values.value_flow.tuple_items.len(), 3);

    let decoded: Vec<_> = index
        .strings
        .iter()
        .filter_map(|literal| literal.static_value.as_deref())
        .collect();
    assert!(decoded.contains(&"__proto__"));
    assert!(decoded.contains(&"constructor"));
    assert!(decoded.contains(&"prototype"));
    assert!(index
        .branch_conditions
        .iter()
        .any(|fact| fact.expression.is_some()));
}

#[test]
fn recursive_dynamic_key_filter_is_a_typed_summary() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "merge.js",
            r#"
const BLOCKED = new Set(["__proto__", "constructor", "prototype"]);
function sanitize(value) {
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (BLOCKED.has(key)) continue;
      out[key] = sanitize(item);
    }
    return out;
  }
  return value;
}
function shallow(value) {
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    if (BLOCKED.has(key)) continue;
    out[key] = item;
  }
  return out;
}
"#,
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("JavaScript declaration index");
    let [fact] = index.dynamic_key_filters.as_slice() else {
        panic!(
            "expected only the recursive helper summary: {:?}",
            index.dynamic_key_filters
        );
    };
    assert_eq!(fact.collection_constructor, "Set");
    assert_eq!(fact.membership_check, "has");
    assert_eq!(fact.input_param_index, 0);
    assert!(fact.recursive);
    assert_eq!(
        fact.rejected_exact_values,
        ["__proto__", "constructor", "prototype"]
    );
}

#[test]
fn call_configuration_aggregate_uses_exact_language_decoded_scalars() {
    use bonsai_lang_api::{LanguageAdapter, StaticScalarValue};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "parser.js",
            r#"
function safe(libxml, xml) {
  return libxml.parseXml(xml, {
    noent: false,
    replaceEntities: false,
    nonet: true,
    dtdload: false,
  });
}
function inexact(libxml, xml, defaults) {
  return libxml.parseXml(xml, { ...defaults, noent: false });
}
"#,
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("JavaScript declaration index");
    let mut options: Vec<_> = index
        .call_argument_values
        .iter()
        .filter(|fact| fact.argument_index == 1)
        .collect();
    options.sort_by_key(|fact| fact.call_span.start);
    assert_eq!(options.len(), 2, "{:#?}", index.call_argument_values);
    assert_eq!(
        options[0].exact_static_aggregate_fields,
        vec![
            bonsai_lang_api::StaticAggregateFieldValue {
                path: vec!["noent".to_string()],
                value: StaticScalarValue::Boolean(false),
            },
            bonsai_lang_api::StaticAggregateFieldValue {
                path: vec!["replaceEntities".to_string()],
                value: StaticScalarValue::Boolean(false),
            },
            bonsai_lang_api::StaticAggregateFieldValue {
                path: vec!["nonet".to_string()],
                value: StaticScalarValue::Boolean(true),
            },
            bonsai_lang_api::StaticAggregateFieldValue {
                path: vec!["dtdload".to_string()],
                value: StaticScalarValue::Boolean(false),
            },
        ]
    );
    assert!(
        options[1].exact_static_aggregate_fields.is_empty(),
        "a spread can override a field and must fail closed: {:#?}",
        options[1]
    );
}

#[test]
fn finite_map_selection_requires_an_immutable_unshadowed_binding_and_literal_fallback() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "selection.js",
            r#"
const SORTABLE = new Map([["id", "id"], ["email", "email"]]);
function safe(key) {
  const column = SORTABLE.get(key) ?? "id";
  return column;
}
function dynamicFallback(key, fallback) {
  const dynamic = SORTABLE.get(key) ?? fallback;
  return dynamic;
}
function shadowed(SORTABLE, key) {
  const shadow = SORTABLE.get(key) ?? "id";
  return shadow;
}
function destructured({ SORTABLE }, key) {
  const destructuredValue = SORTABLE.get(key) ?? "id";
  return destructuredValue;
}
const arrow = SORTABLE => {
  const arrowValue = SORTABLE.get("id") ?? "id";
  return arrowValue;
};
function catchShadow(key) {
  try {
    throw new Error(key);
  } catch (SORTABLE) {
    const caught = SORTABLE.get(key) ?? "id";
    return caught;
  }
}
function declarationShadow(key) {
  function SORTABLE() {}
  const declared = SORTABLE.get(key) ?? "id";
  return declared;
}
function mutated(key, value) {
  const LOCAL = new Map([["id", "id"]]);
  LOCAL.set("id", value);
  const changed = LOCAL.get(key) ?? "id";
  return changed;
}
export const PUBLIC = new Map([["id", "id"]]);
function exported(key) {
  const publicValue = PUBLIC.get(key) ?? "id";
  return publicValue;
}
const LATE_MUTATION = new Map([["id", "id"]]);
function selectedBeforeMutation(key) {
  const late = LATE_MUTATION.get(key) ?? "id";
  return late;
}
function mutateFromElsewhere(value) {
  LATE_MUTATION.set("id", value);
}
"#,
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("JavaScript declaration index");

    assert_eq!(
        index
            .finite_literal_selections
            .iter()
            .map(|fact| fact.target.as_str())
            .collect::<Vec<_>>(),
        ["column"]
    );
}

#[test]
fn finite_map_selection_rejects_a_shadowed_map_constructor() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "shadow.js",
            r#"
class Map {
  constructor(entries) { this.entries = entries; }
  get(key) { return key; }
}
const LOOKUP = new Map([["id", "id"]]);
function unsafe(key) {
  const selected = LOOKUP.get(key) ?? "id";
  return selected;
}
"#,
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("JavaScript declaration index");
    assert!(index.finite_literal_selections.is_empty());
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
fn direct_default_export_modifier_creates_default_alias() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "service.js",
            "function handler(value) { return value; }\nexport default handler;\n",
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let names = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .map(|decl| decl.name.as_str())
        .collect::<Vec<_>>();

    assert!(names.contains(&"handler"));
    assert!(names.contains(&"default"));
}

#[test]
fn commonjs_callable_default_export_creates_default_alias() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "service.js",
            "module.exports = function render(el, html) { el.innerHTML = html; };\n",
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let decls = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .map(|decl| {
            (
                decl.name.as_str(),
                decl.kind,
                decl.span,
                decl.name_span,
                decl.body_span,
            )
        })
        .collect::<Vec<_>>();

    assert!(
        decls.iter().any(|(name, ..)| *name == "default"),
        "declarations: {decls:?}"
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
