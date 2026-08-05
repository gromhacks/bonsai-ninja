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
fn super_invocation_is_lowered_as_direct_parent_constructor_dispatch() {
    use bonsai_lang_api::{CallKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "classes.js",
            r#"
class Base {
  constructor(value) { this.value = value; }
}
class Child extends Base {
  constructor(value) { super(value); }
}
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("JavaScript declaration index");
    let child = index
        .defs
        .iter()
        .find(|decl| {
            decl.name == "constructor"
                && decl
                    .parent
                    .and_then(|parent| index.defs.iter().find(|owner| owner.symbol == parent))
                    .is_some_and(|owner| owner.name == "Child")
        })
        .expect("Child constructor");
    assert!(
        child.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                receiver: Some(receiver),
                call_kind: CallKind::Constructor,
                ..
            } if name == "Base" && receiver == "super"
        )),
        "super(value) must retain constructor semantics and the direct parent identity: {:#?}",
        child.flow_events
    );
}

#[test]
fn chained_global_replacements_emit_exact_escape_summary() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "escape.js",
            r#"
function escapeHtml(value) {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;");
}
function incomplete(value) {
  return value.replace(/</, "&lt;");
}
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("JavaScript declaration index");
    let [summary] = index.character_substitutions.as_slice() else {
        panic!(
            "expected only the global replacement summary: {:#?}",
            index.character_substitutions
        );
    };
    assert_eq!(summary.exact_mappings.len(), 2);
    assert!(summary
        .exact_mappings
        .iter()
        .any(|entry| entry.key == "<" && entry.value == "&lt;"));
}

#[test]
fn named_regex_escape_resolves_the_lexical_const_binding() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "scope.js",
            r#"
const CONTROL = /[\r\n]/g;
function safe(value) {
  return value.replace(CONTROL, "_");
}
function shadowed(value, CONTROL) {
  return value.replace(CONTROL, "_");
}
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("JavaScript declaration index");
    assert_eq!(
        index.character_substitutions.len(),
        1,
        "a parameter shadow must block the outer regex proof: {:#?}",
        index.character_substitutions
    );
    let safe = index
        .defs
        .iter()
        .find(|decl| decl.name == "safe")
        .expect("safe function");
    assert_eq!(index.character_substitutions[0].function_span, safe.span);
}

#[test]
fn replacement_runtime_and_string_composition_are_exact_compiler_facts() {
    use bonsai_lang_api::{LanguageAdapter, StringCompositionPart};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "escapes.js",
            r#"
function regex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function ldap(value) {
  return String(value).replace(/[\\*()\u0000]/g, (c) =>
    "\\" + c.charCodeAt(0).toString(16).padStart(2, "0"));
}
function header(value) {
  const rendered = "attachment=\"" + regex(value) + "\"";
  return rendered;
}
function templateHeader(value) {
  const templated = `attachment="${regex(value)}"`;
  return templated;
}
function query(value) {
  return products.find({ name: { $regex: ".*" + regex(value) + ".*", $options: "i" } });
}
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("JavaScript declaration index");
    let regex = index
        .character_substitutions
        .iter()
        .find(|fact| {
            index
                .defs
                .iter()
                .any(|decl| decl.name == "regex" && decl.span == fact.function_span)
        })
        .expect("regex replacement summary");
    for character in [
        ".", "*", "+", "?", "^", "$", "{", "}", "(", ")", "|", "[", "]", "\\",
    ] {
        assert!(
            regex
                .exact_mappings
                .iter()
                .any(|entry| entry.key == character && entry.value == format!("\\{character}")),
            "missing exact regex escape for {character:?}: {:#?}",
            regex.exact_mappings
        );
    }
    let ldap = index
        .character_substitutions
        .iter()
        .find(|fact| {
            index
                .defs
                .iter()
                .any(|decl| decl.name == "ldap" && decl.span == fact.function_span)
        })
        .expect("numeric hex replacement summary");
    assert!(ldap
        .exact_mappings
        .iter()
        .any(|entry| entry.key == "\0" && entry.value == "\\00"));
    assert!(index.string_compositions.iter().any(|fact| {
        fact.target.as_deref() == Some("rendered")
            && matches!(
                fact.parts.as_slice(),
                [
                    StringCompositionPart::Literal { .. },
                    StringCompositionPart::Call { .. },
                    StringCompositionPart::Literal { .. }
                ]
            )
    }));
    assert!(index.string_compositions.iter().any(|fact| {
        fact.target.as_deref() == Some("templated")
            && matches!(
                fact.parts.as_slice(),
                [
                    StringCompositionPart::Literal { .. },
                    StringCompositionPart::Call { .. },
                    StringCompositionPart::Literal { .. }
                ]
            )
    }));
    let query = index
        .call_argument_values
        .iter()
        .find(|fact| {
            fact.value_flow
                .aggregate_fields
                .iter()
                .any(|field| field.name == "name")
        })
        .expect("nested object argument flow");
    let regex_value_span = query.value_flow.aggregate_fields[0].value.aggregate_fields[0]
        .value_span
        .expect("nested field value span");
    assert!(index
        .string_compositions
        .iter()
        .any(|fact| fact.value_span == regex_value_span));
}

#[test]
fn same_origin_helper_requires_single_slash_and_static_fallback() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    for (body, expected) in [
        (
            r#"return typeof target === "string" && target.startsWith("/") && !target.startsWith("//") ? target : "/";"#,
            true,
        ),
        (r#"return target.startsWith("/") ? target : "/";"#, false),
        (
            r#"return target.startsWith("/") && !target.startsWith("//") ? target : target;"#,
            false,
        ),
    ] {
        let source = format!("function sameSite(target) {{ {body} }}\n");
        let ws = bonsai_testkit::workspace_with(vec![Arc::clone(&adapter)], &[("redirect.js", &source)]);
        let file = ws.db().vfs().all_files()[0];
        let index = ws.db().decl_index(file).expect("JavaScript declaration index");
        assert_eq!(
            !index.same_origin_path_constraints.is_empty(),
            expected,
            "{body}: {:#?}",
            index.same_origin_path_constraints
        );
    }

    let source =
        r#"const sameSite = (target) => target.startsWith("/") && !target.startsWith("//") ? target : "/";"#;
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("redirect.js", source)]);
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("JavaScript declaration index");
    assert_eq!(
        index.same_origin_path_constraints.len(),
        1,
        "expression-bodied arrows must lower the same exact guard fact: {:#?}",
        index.same_origin_path_constraints
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
    assert_eq!(fact.output_place.as_deref(), Some("out"));
    assert!(fact.recursive);
    assert_eq!(
        fact.rejected_exact_values,
        ["__proto__", "constructor", "prototype"]
    );
}

#[test]
fn property_path_segment_denylist_is_a_typed_summary() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "paths.js",
            r#"
const BLOCKED = new Set(["__proto__", "constructor", "prototype"]);
function apply(path, value) {
  const segments = String(path).split(/[.[\]]+/).filter((part) => part.length > 0);
  if (segments.some((part) => BLOCKED.has(part))) throw new Error("unsafe");
  set({}, segments, value);
}
function weak(path, value) {
  const segments = path.split(".");
  if (segments.some((part) => BLOCKED.has(part))) throw new Error("unsafe");
  segments.push("constructor");
  set({}, segments, value);
}
"#,
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("JavaScript declaration index");
    let facts = index
        .dynamic_key_filters
        .iter()
        .filter(|fact| !fact.recursive)
        .collect::<Vec<_>>();
    assert_eq!(facts.len(), 1, "{:#?}", index.dynamic_key_filters);
    assert_eq!(facts[0].output_place.as_deref(), Some("segments"));
    assert_eq!(facts[0].membership_check, "has");
    assert_eq!(
        facts[0].rejected_exact_values,
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
function safe(libxml, xml, timeout) {
  return libxml.parseXml(xml, {
    timeout: timeout,
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
            .filter_map(|fact| fact.target.as_deref())
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
