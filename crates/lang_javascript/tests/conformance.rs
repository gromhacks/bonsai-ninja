use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    run_language_suite!(adapter, trace_from = "main", [("a.js", "function main() {}")]);
}

#[test]
fn default_rest_and_destructured_parameters_follow_current_grammar_shapes() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new())],
        &[(
            "params.js",
            r#"
function variadic(value = source(), ...rest) { return rest; }
function destructured({ head, ...tail }, [first, ...remaining]) { return head; }
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace
        .db()
        .decl_index(file)
        .expect("JavaScript compiler index");
    let variadic = index
        .defs
        .iter()
        .find(|decl| decl.name == "variadic")
        .expect("variadic declaration");
    assert_eq!(variadic.params, ["value", "rest"]);
    assert!(variadic.is_variadic);

    let destructured = index
        .defs
        .iter()
        .find(|decl| decl.name == "destructured")
        .expect("destructured declaration");
    assert_eq!(destructured.params, ["head", "tail", "first", "remaining"]);
    assert!(
        !destructured.is_variadic,
        "rest inside an object/array pattern does not collect overflow arguments"
    );
}

#[test]
fn value_member_reads_are_property_facts_but_method_calls_are_call_results() {
    use bonsai_lang_api::{AssignValueKind, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new())],
        &[(
            "values.js",
            r#"
function bind(req) {
  const file = req.files.avatar;
  const name = file.name;
  const trimmed = file.name.trim();
  return trimmed;
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace
        .db()
        .decl_index(file)
        .expect("JavaScript compiler index");
    let bind = index
        .defs
        .iter()
        .find(|decl| decl.name == "bind")
        .expect("bind declaration");
    let kind_for = |target: &str| {
        bind.flow_events.iter().find_map(|event| match event {
            FlowEvent::Assign {
                target: actual,
                value_kind,
                ..
            } if actual == target => *value_kind,
            _ => None,
        })
    };
    assert_eq!(kind_for("file"), Some(AssignValueKind::PropertyRead));
    assert_eq!(kind_for("name"), Some(AssignValueKind::PropertyRead));
    assert_eq!(kind_for("trimmed"), Some(AssignValueKind::CallResult));
}

#[test]
fn logical_and_ternary_value_selection_is_exact_but_combining_binary_is_not() {
    use bonsai_lang_api::{AssignValueKind, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new())],
        &[(
            "selection.js",
            r#"
function bind(req, flag) {
  const fallback = req.body || {};
  const nullable = req.body ?? {};
  const gated = req.body && req.body.payload;
  const selected = flag ? req.body : {};
  const combined = req.body + "";
  return [fallback, nullable, gated, selected, combined];
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace
        .db()
        .decl_index(file)
        .expect("JavaScript compiler index");
    let bind = index
        .defs
        .iter()
        .find(|decl| decl.name == "bind")
        .expect("bind declaration");
    let kind_for = |target: &str| {
        bind.flow_events.iter().find_map(|event| match event {
            FlowEvent::Assign {
                target: actual,
                value_kind,
                ..
            } if actual == target => *value_kind,
            _ => None,
        })
    };

    for target in ["fallback", "nullable", "gated", "selected"] {
        assert_eq!(
            kind_for(target),
            Some(AssignValueKind::WholeValueSelection),
            "{target} must be classified from its exact selection operator"
        );
    }
    assert_eq!(kind_for("combined"), Some(AssignValueKind::Compound));
}

#[test]
fn nested_callback_keeps_parameter_and_free_write_in_its_own_compiler_scope() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new())],
        &[(
            "callback.js",
            r#"
function render() {
  let hash = window.location.hash || "";
  let output = "";
  hash.replace(/^#?/, "").split("&").forEach(function (part) {
    let values = part.split("=");
    if (values[0] === "display") output = decodeURIComponent(values[1] || "");
  });
  sink(output);
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace
        .db()
        .decl_index(file)
        .expect("JavaScript compiler index");
    let callback = index
        .defs
        .iter()
        .find(|decl| decl.name.starts_with("<lambda@"))
        .expect("inline callback declaration");
    let callback_argument = index
        .call_argument_values
        .iter()
        .find(|fact| !fact.inline_callback_params.is_empty())
        .unwrap_or_else(|| {
            panic!(
                "missing inline callback argument fact: {:#?}",
                index.call_argument_values
            )
        });
    assert_eq!(
        callback_argument.inline_callback_span,
        Some(callback.span),
        "the argument-value fact and callable declaration must share one exact compiler span"
    );
    assert!(
        callback.span.start >= callback_argument.argument_span.start
            && callback.span.end <= callback_argument.argument_span.end,
        "the compiler callback declaration must be contained by the exact host argument span: callback={:?}, argument={:?}",
        callback.span,
        callback_argument.argument_span
    );

    let for_each_receiver = index
        .call_receivers
        .iter()
        .find(|fact| !fact.value_flow.call_sites.is_empty())
        .unwrap_or_else(|| panic!("missing compiler receiver fact: {:#?}", index.call_receivers));
    assert!(
        !for_each_receiver.value_flow.call_sites.is_empty(),
        "a call-valued collection receiver must retain its exact nested call dependency: {for_each_receiver:#?}"
    );

    assert_eq!(callback.params, ["part"]);
    let mut writes_outer_output = false;
    bonsai_lang_api::for_each_flow_event(&callback.flow_events, &mut |event| {
        if matches!(
            event,
            FlowEvent::Assign {
                target,
                declares_new_binding: false,
                ..
            } if target == "output"
        ) {
            writes_outer_output = true;
        }
    });
    assert!(
        writes_outer_output,
        "the adapter must identify assignment to an outer lexical binding as a free write: {:#?}",
        callback.flow_events
    );

    let graph = workspace.resolved_call_graph();
    let render = index
        .defs
        .iter()
        .find(|decl| decl.name == "render")
        .expect("render declaration");
    assert!(
        graph.callable_arguments().any(|argument| {
            argument.caller.raw() == render.symbol.raw()
                && argument.target.raw() == callback.symbol.raw()
                && argument.span == callback_argument.argument_span
        }),
        "the compiler-resolved inline callable argument must survive in the call graph: {:#?}",
        graph.callable_argument_records()
    );
}

#[test]
fn nested_callback_local_shadow_is_not_an_outer_capture_write() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new())],
        &[(
            "callback-shadow.js",
            r#"
function render(input) {
  let output = "safe";
  input.split("&").forEach(function (part) {
    let output = part;
    consume(output);
  });
  sink(output);
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace
        .db()
        .decl_index(file)
        .expect("JavaScript compiler index");
    let callback = index
        .defs
        .iter()
        .find(|decl| decl.name.starts_with("<lambda@"))
        .expect("inline callback declaration");
    let mut declares_local_output = false;
    let mut writes_outer_output = false;
    bonsai_lang_api::for_each_flow_event(&callback.flow_events, &mut |event| {
        if let FlowEvent::Assign {
            target,
            declares_new_binding,
            ..
        } = event
        {
            if target == "output" {
                declares_local_output |= *declares_new_binding;
                writes_outer_output |= !*declares_new_binding;
            }
        }
    });
    assert!(
        declares_local_output,
        "the callback-local shadow must remain a declaration: {:#?}",
        callback.flow_events
    );
    assert!(
        !writes_outer_output,
        "a callback-local shadow must not be emitted as a write to enclosing storage"
    );
}

#[test]
fn commonjs_destructured_constructor_and_local_constructor_keep_exact_identities() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new())],
        &[(
            "database.js",
            r#"
const { MongoClient } = require("mongodb");
class Repository { findOne(value) { return value; } }
function load() {
  const client = new MongoClient("mongodb://localhost");
  const repository = new Repository();
  return repository.findOne(client);
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let imports = workspace
        .db()
        .import_index(file)
        .expect("JavaScript import index");
    assert!(imports.imports.iter().any(|import| {
        import.module == "mongodb"
            && import.alias.as_deref() == Some("MongoClient")
            && import.original_name.as_deref() == Some("MongoClient")
    }));

    let index = workspace
        .db()
        .decl_index(file)
        .expect("JavaScript compiler index");
    let load = index
        .defs
        .iter()
        .find(|decl| decl.name == "load")
        .expect("load declaration");
    assert!(load
        .type_aliases
        .iter()
        .any(|alias| alias.name == "client" && alias.type_name == "MongoClient"));
    assert!(load
        .type_aliases
        .iter()
        .any(|alias| alias.name == "repository" && alias.type_name == "Repository"));
    assert!(load.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Call { name, receiver_types, .. }
            if name == "repository.findOne"
                && receiver_types.iter().any(|ty| ty == "Repository")
    )));
}

#[test]
fn assigned_object_methods_resolve_implicit_receiver_calls() {
    use bonsai_common::FuncId;
    use bonsai_lang_api::{DeclKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "app.js",
            "const app = {};\n\
             app.init = function init() { this.configure(); };\n\
             app.configure = function configure() {};\n\
             app.arrow = () => this.configure();\n\
             app.publicName = function privateName() { privateName(); };\n",
        )],
    );
    let global = ws.db().global_index();
    let owner = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "app" && decl.kind == DeclKind::Struct)
        .expect("static object method family should have a structural owner");
    let init = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "init")
        .expect("assigned init method");
    let configure = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "configure")
        .expect("assigned configure method");

    assert_eq!(init.kind, DeclKind::Method);
    assert_eq!(configure.kind, DeclKind::Method);
    assert_eq!(init.parent, Some(owner.symbol));
    assert_eq!(configure.parent, Some(owner.symbol));
    assert!(init.implicit_receiver_names.iter().any(|name| name == "this"));
    assert!(init.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Call { name, receiver_types, .. }
            if name == "this.configure" && receiver_types.iter().any(|ty| ty == "app")
    )));

    let graph = ws.resolved_call_graph();
    assert!(
        graph
            .callees_of(FuncId::new(init.symbol.raw()))
            .any(|edge| edge.to == FuncId::new(configure.symbol.raw())),
        "AST-owned object methods should resolve this.configure()"
    );

    let arrow = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "app.arrow")
        .expect("assigned arrow");
    assert_ne!(
        arrow.kind,
        DeclKind::Method,
        "arrows must keep lexical-this semantics"
    );
    let private_name = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "privateName")
        .expect("named function expression");
    assert_ne!(
        private_name.kind,
        DeclKind::Method,
        "a differing inner function name must fail closed until alias identity is explicit"
    );
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
    let escape = index
        .defs
        .iter()
        .find(|decl| decl.name == "escapeHtml")
        .expect("escapeHtml declaration");
    let summary = index
        .character_constraints
        .iter()
        .find_map(|fact| match &fact.domain {
            bonsai_lang_api::CharacterConstraintDomain::ProviderBound {
                operation_call,
                domain,
                ..
            } if fact.function_span == escape.span && operation_call == "String.replace" => match domain
                .as_ref()
            {
                bonsai_lang_api::CharacterConstraintDomain::SubstitutesExact { mappings } => Some(mappings),
                _ => None,
            },
            _ => None,
        })
        .expect("global mapping candidate");
    assert_eq!(summary.len(), 2);
    assert!(summary
        .iter()
        .any(|entry| entry.key == "<" && entry.value == "&lt;"));
    assert!(index.character_substitutions.is_empty());
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
    let safe = index
        .defs
        .iter()
        .find(|decl| decl.name == "safe")
        .expect("safe function");
    assert!(
        index
            .character_constraints
            .iter()
            .all(|fact| fact.function_span == safe.span),
        "a parameter shadow must block the outer regex proof: {:#?}",
        index.character_constraints
    );
    assert_eq!(index.character_constraints.len(), 2);
    assert!(index.character_substitutions.is_empty());
}

#[test]
fn provider_bound_mapping_candidates_capture_neutral_operation_and_factory_without_semantics() {
    use bonsai_lang_api::{CharacterConstraintDomain, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "mapping.js",
            r#"
function direct(value) {
  return value.scrub(/&/g, "and").scrub(/</g, "less");
}
function converted(value) {
  return Coerce(value).scrub(/&/g, "and");
}
function mixed(value) {
  return value.scrub(/&/g, "and").other(/</g, "less");
}
function Scalar(value) {
  return value;
}
function shadowed(value) {
  return Scalar(value).scrub(/&/g, "and");
}
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("JavaScript declaration index");
    let span = |name: &str| {
        index
            .defs
            .iter()
            .find(|decl| decl.name == name)
            .map(|decl| decl.span)
            .expect("named declaration")
    };
    let providers = index
        .character_constraints
        .iter()
        .filter_map(|fact| match &fact.domain {
            CharacterConstraintDomain::ProviderBound {
                factory_call,
                operation_call,
                domain,
            } if matches!(
                domain.as_ref(),
                CharacterConstraintDomain::SubstitutesExact { .. }
            ) =>
            {
                Some((fact.function_span, factory_call.as_str(), operation_call.as_str()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(providers.contains(&(span("direct"), "", "scrub")));
    assert!(providers.contains(&(span("converted"), "Coerce", "Coerce.scrub")));
    assert!(
        !providers
            .iter()
            .any(|(function, _, _)| *function == span("mixed")),
        "mixed operations must fail closed: {providers:#?}"
    );
    assert!(
        !providers
            .iter()
            .any(|(function, _, _)| *function == span("shadowed")),
        "a locally declared factory must fail closed: {providers:#?}"
    );
    assert!(index.character_substitutions.is_empty());
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
    let mappings_for = |name: &str| {
        let function_span = index
            .defs
            .iter()
            .find(|decl| decl.name == name)
            .map(|decl| decl.span)
            .expect("named declaration");
        index.character_constraints.iter().find_map(|fact| {
            if fact.function_span != function_span {
                return None;
            }
            match &fact.domain {
                bonsai_lang_api::CharacterConstraintDomain::ProviderBound { domain, .. } => {
                    match domain.as_ref() {
                        bonsai_lang_api::CharacterConstraintDomain::SubstitutesExact { mappings } => {
                            Some(mappings)
                        }
                        _ => None,
                    }
                }
                _ => None,
            }
        })
    };
    let regex = mappings_for("regex").expect("regex replacement candidate");
    for character in [
        ".", "*", "+", "?", "^", "$", "{", "}", "(", ")", "|", "[", "]", "\\",
    ] {
        assert!(
            regex
                .iter()
                .any(|entry| entry.key == character && entry.value == format!("\\{character}")),
            "missing exact regex escape for {character:?}: {:#?}",
            regex
        );
    }
    let ldap = mappings_for("ldap").expect("numeric hex replacement candidate");
    assert!(ldap
        .iter()
        .any(|entry| entry.key == "\0" && entry.value == "\\00"));
    assert!(index.character_substitutions.is_empty());
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
fn guarded_value_helper_preserves_predicate_polarity_without_api_meaning() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    for (body, expected) in [
        (
            r#"return typeof target === "string" && target.startsWith("/") && !target.startsWith("//") ? target : "/";"#,
            true,
        ),
        (r#"return target.startsWith("/") ? target : "/";"#, true),
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
            !index.guarded_value_constraints.is_empty(),
            expected,
            "{body}: {:#?}",
            index.guarded_value_constraints
        );
    }

    let source =
        r#"const sameSite = (target) => target.startsWith("/") && !target.startsWith("//") ? target : "/";"#;
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("redirect.js", source)]);
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("JavaScript declaration index");
    assert_eq!(
        index.guarded_value_constraints.len(),
        1,
        "expression-bodied arrows must lower the same exact guard fact: {:#?}",
        index.guarded_value_constraints
    );
    let fact = &index.guarded_value_constraints[0];
    assert!(fact.accepted_prefixes.is_empty());
    assert!(fact.rejected_prefixes.is_empty());
    assert_eq!(fact.predicate_calls.len(), 2);
    assert!(fact.predicate_calls.iter().any(|call| call.required_result));
    assert!(fact.predicate_calls.iter().any(|call| !call.required_result));

    let source = r#"const select = (target) => target.isAccepted("local") && !target.isRejected("remote") ? target : "fallback";"#;
    let ws = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new())],
        &[("generic.js", source)],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("JavaScript declaration index");
    assert_eq!(index.guarded_value_constraints.len(), 1);
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
    assert!(
        constructor.target_is_immutable,
        "const constructor bindings must be adapter-proven immutable"
    );
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
fn shadowed_object_entries_is_not_a_runtime_intrinsic() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "shadowed.js",
            r#"
const BLOCKED = new Set(["__proto__"]);
function clean(value) {
  const Object = { entries(input) { return input; } };
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    if (BLOCKED.has(key)) continue;
    out[key] = clean(item);
  }
  return out;
}
"#,
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("JavaScript declaration index");
    assert!(
        index.dynamic_key_filters.is_empty(),
        "a local Object binding must shadow the runtime intrinsic: {:#?}",
        index.dynamic_key_filters
    );
}

#[test]
fn immutable_literal_set_membership_ternary_is_a_finite_selection() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "roles.js",
            r#"
const ROLES = new Set(["admin", "viewer", "editor"]);
function safe(input) {
  const role = ROLES.has(input) ? input : "viewer";
  return role;
}
function mutable(input) {
  const roles = new Set(["admin", "viewer"]);
  roles.add(input);
  const role = roles.has(input) ? input : "viewer";
  return role;
}
function mismatch(input, other) {
  const roles = new Set(["admin", "viewer"]);
  const role = roles.has(input) ? other : "viewer";
  return role;
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
        ["role"],
        "only the immutable exact-subject Set membership may constrain its output: {:#?}",
        index.finite_literal_selections
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
