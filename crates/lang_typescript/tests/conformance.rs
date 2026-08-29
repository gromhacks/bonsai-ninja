use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("a.ts", "function main(): void {}")]
    );
}

#[test]
fn typed_default_rest_and_destructured_parameters_follow_current_grammar_shapes() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new())],
        &[(
            "params.ts",
            r#"
function variadic(value: string = source(), ...rest: string[]): string[] { return rest; }
function destructured(
  { head, ...tail }: { head: string; tail?: unknown },
  [first, ...remaining]: string[],
): string { return head; }
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace
        .db()
        .decl_index(file)
        .expect("TypeScript compiler index");
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
        vec![Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new())],
        &[(
            "values.ts",
            r#"
function bind(req: { files: { avatar: { name: string } } }): string {
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
        .expect("TypeScript compiler index");
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
fn wrapped_logical_and_ternary_value_selection_is_exact_but_binary_addition_is_not() {
    use bonsai_lang_api::{AssignValueKind, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new())],
        &[(
            "selection.ts",
            r#"
function bind(req: any, flag: boolean) {
  const fallback = (req.body || {}) as Record<string, unknown>;
  const nullable = (req.body ?? {}) as Record<string, unknown>;
  const selected = (flag ? req.body : {}) satisfies Record<string, unknown>;
  const combined = (req.body as any) + "";
  return [fallback, nullable, selected, combined];
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace
        .db()
        .decl_index(file)
        .expect("TypeScript compiler index");
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

    for target in ["fallback", "nullable", "selected"] {
        assert_eq!(
            kind_for(target),
            Some(AssignValueKind::WholeValueSelection),
            "{target} must retain selection identity through TypeScript wrappers"
        );
    }
    assert_eq!(kind_for("combined"), Some(AssignValueKind::Compound));
}

#[test]
fn legacy_import_require_clause_preserves_module_alias_from_current_cst() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new())],
        &[(
            "imports.ts",
            "import Legacy = require(\"legacy-package\");\nLegacy.run();\n",
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let imports = workspace
        .db()
        .import_index(file)
        .expect("TypeScript import index");
    let matching = imports
        .imports
        .iter()
        .filter(|import| import.module == "legacy-package")
        .collect::<Vec<_>>();
    assert_eq!(
        matching.len(),
        1,
        "legacy require import must not duplicate: {matching:?}"
    );
    assert_eq!(matching[0].alias.as_deref(), Some("Legacy"));
    assert_eq!(matching[0].scope, bonsai_lang_api::ImportScope::Module);
}

#[test]
fn parameter_decorator_fact_does_not_confuse_an_identifier_with_the_decorator() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new())],
        &[(
            "controller.ts",
            r#"
import { Body } from "@nestjs/common";
class Controller {
  create(@Body("name") value: string): void {}
  ordinary(Body: string): void {}
}
"#,
        )],
    );
    let global = workspace.db().global_index();
    let create = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "create")
        .expect("decorated method");
    assert_eq!(create.params, ["value"]);
    assert_eq!(create.param_annotations, [vec!["Body".to_string()]]);

    let ordinary = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "ordinary")
        .expect("ordinary method");
    assert_eq!(ordinary.params, ["Body"]);
    assert_eq!(ordinary.param_annotations, [Vec::<String>::new()]);
}

#[test]
fn assigned_object_methods_share_receiver_identity() {
    use bonsai_common::FuncId;
    use bonsai_lang_api::{DeclKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "app.ts",
            "const app: Record<string, unknown> = {};\n\
             app.init = function init(): void { this.configure(); };\n\
             app.configure = function configure(): void {};\n",
        )],
    );
    let global = ws.db().global_index();
    let owner = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "app" && decl.kind == DeclKind::Struct)
        .expect("assigned TypeScript method family owner");
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
    assert_eq!(init.parent, Some(owner.symbol));
    assert_eq!(configure.parent, Some(owner.symbol));
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
        "TypeScript should reuse the ECMAScript object-method ownership model"
    );
}

#[test]
fn lowercase_declared_and_cast_types_remain_receiver_evidence() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "app.ts",
            "class lower { run(value: string): void {} }\n\
             function handle(input: unknown, value: string): void {\n\
               const declared: lower = new lower();\n\
               const casted = input as lower;\n\
               declared.run(value); casted.run(value);\n\
             }",
        )],
    );
    let global = ws.db().global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");
    let typed_calls = handle.flow_events.iter().filter(|event| {
        matches!(
            event,
            FlowEvent::Call { name, receiver_types, .. }
                if name.rsplit('.').next() == Some("run")
                    && receiver_types.iter().any(|ty| ty == "lower")
        )
    });
    assert_eq!(typed_calls.count(), 2, "events: {:#?}", handle.flow_events);
}

#[test]
fn tsx_uses_the_tsx_grammar_and_lowers_component_calls() {
    use bonsai_lang_api::{CallKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let workspace = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "view.tsx",
            "function render(value: string) { return <Widget value={value}/>; }",
        )],
    );
    let file = *workspace.db().vfs().all_files().first().expect("TSX fixture");
    let parsed = workspace.db().parse(file).expect("parse TSX");
    assert_eq!(parsed.grammar_name, "tsx");
    assert!(
        parsed.diagnostics.is_empty(),
        "valid TSX must be syntax-clean: {:?}",
        parsed.diagnostics
    );

    let index = workspace.db().decl_index(file).expect("TSX declaration index");
    assert!(index.defs.iter().flat_map(|decl| &decl.flow_events).any(|event| {
        matches!(
            event,
            FlowEvent::Call { name, call_kind: CallKind::Function, args, .. }
                if name == "Widget"
                    && args.len() == 1
                    && args[0].source_names.iter().any(|source| source == "value")
        )
    }));
}

#[test]
fn grammar_specific_handlers_lower_ts_and_tsx_assertion_forms() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new())],
        &[
            (
                "assertion.ts",
                "function fromTs(value: unknown) { sink(<string>value); }\n",
            ),
            (
                "assertion.tsx",
                "function fromTsx(value: unknown) { sink(value as string); }\n",
            ),
        ],
    );
    let global = workspace.db().global_index();
    for function in ["fromTs", "fromTsx"] {
        let decl = global
            .all_files()
            .flat_map(|file| global.decls_in(file))
            .find(|decl| decl.name == function)
            .unwrap_or_else(|| panic!("{function} declaration"));
        assert!(
            decl.flow_events.iter().any(|event| matches!(
                event,
                FlowEvent::Call { name, args, .. }
                    if name == "sink"
                        && args.len() == 1
                        && args[0].source_names.iter().any(|source| source == "value")
            )),
            "{function} assertion wrapper must preserve value flow: {:?}",
            decl.flow_events
        );
    }
}

#[test]
fn import_type_queries_are_syntax_clean_in_ts_and_tsx() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let workspace = bonsai_testkit::workspace_with(
        vec![adapter],
        &[
            (
                "store.ts",
                "interface Store { get: () => import('pkg').Value[]; }",
            ),
            (
                "view.tsx",
                "function view(value: import('pkg').Value) { return <Widget value={value}/>; }",
            ),
        ],
    );

    for file in workspace.db().vfs().all_files() {
        let parsed = workspace.db().parse(file).expect("parse TypeScript fixture");
        assert!(
            parsed.diagnostics.is_empty(),
            "valid import-type query must be syntax-clean in {}: {:?}",
            parsed.grammar_name,
            (&parsed.diagnostics, parsed.tree.root_node().to_sexp())
        );
        if workspace
            .db()
            .vfs()
            .path(file)
            .expect("fixture path")
            .ends_with("store.ts")
        {
            let source = parsed.source_text().as_bytes();
            let mut pending = vec![parsed.tree.root_node()];
            let mut retained_exact_import_type = false;
            while let Some(node) = pending.pop() {
                retained_exact_import_type |= source
                    .get(node.start_byte()..node.end_byte())
                    .is_some_and(|text| text == b"import('pkg').Value");
                let mut cursor = node.walk();
                pending.extend(node.named_children(&mut cursor));
            }
            assert!(
                retained_exact_import_type,
                "recovery must retain the complete source-level import-type identity"
            );
        }
    }
}

#[test]
fn typeof_rejection_guard_is_typed_condition_ir() {
    use bonsai_lang_api::{ConditionExpressionFact, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "auth.ts",
            r#"
function authenticate(email: unknown, password: unknown): void {
  if (typeof email !== "string" || typeof password !== "string") {
    throw new Error("strings required");
  }
}
"#,
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("TypeScript declaration index");
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

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[("app.ts", "const echo = (x: string): string => x;\n")],
    );
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
        "TypeScript arrow expression should emit a Return event; events: {:?}",
        echo.flow_events
    );
}

#[test]
fn inline_callback_argument_records_ast_parameter_bindings() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "router.ts",
            r#"
const route = procedure.input(schema).query(async ({ input }: Request, context: Context) => {
  return handle(input.column, context.user);
});
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("TypeScript declaration index");
    let callback = index
        .call_argument_values
        .iter()
        .find(|fact| !fact.inline_callback_params.is_empty())
        .expect("inline callback argument compiler fact");

    assert_eq!(callback.argument_index, 0);
    assert_eq!(callback.inline_callback_params, ["input", "context"]);
    assert!(
        index.call_argument_values.iter().all(|fact| {
            !fact.inline_callback_params.is_empty()
                || !fact
                    .value_flow
                    .source_names
                    .iter()
                    .any(|source| source.contains("=>"))
        }),
        "callback identity must come from parsed parameter nodes, not rendered source text"
    );
}

#[test]
fn ts_and_tsx_call_options_retain_exact_nested_aggregate_fields() {
    use bonsai_lang_api::{LanguageAdapter, StaticScalarValue};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[
            (
                "client.ts",
                "const timeout = dynamicTimeout; client.configure({ timeout, transport: { verify: false } });\n",
            ),
            (
                "component.tsx",
                "const element = <span />; client.configure({ element, transport: { verify: false } });\n",
            ),
        ],
    );

    for file in ws.db().vfs().all_files() {
        let index = ws.db().decl_index(file).expect("TypeScript declaration index");
        let options = index
            .call_argument_values
            .iter()
            .find(|fact| fact.argument_index == 0 && !fact.exact_static_aggregate_fields.is_empty())
            .unwrap_or_else(|| {
                panic!(
                    "missing exact TypeScript options aggregate for {:?}: {:#?}",
                    ws.db().vfs().path(file),
                    index.call_argument_values
                )
            });
        assert!(options.exact_static_aggregate_fields.iter().any(|field| {
            field.path.iter().map(String::as_str).eq(["transport", "verify"])
                && field.value == StaticScalarValue::Boolean(false)
        }));
        assert_eq!(
            options.exact_static_aggregate_fields.len(),
            1,
            "dynamic or JSX siblings must not become exact scalar fields: {options:#?}"
        );
    }
}

#[test]
fn static_escape_maps_and_character_transforms_are_exact_compiler_facts() {
    use bonsai_lang_api::{CharacterConstraintDomain, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "escape.ts",
            r#"
const LDAP: Record<string, string> = {
  "\\": "\\5c", "*": "\\2a", "(": "\\28", ")": "\\29", "\u0000": "\\00",
};
function ldapEscape(v: string): string {
  return [...v].map(c => LDAP[c] ?? c).join("");
}
const HTML: Record<string, string> = {
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
};
function htmlEscape(v: string): string {
  return v.replace(/[&<>"']/g, c => HTML[c]);
}
"#,
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("TypeScript declaration index");

    let ldap_map = index
        .static_string_maps
        .iter()
        .find(|fact| fact.target == "LDAP")
        .expect("decoded LDAP map");
    assert!(ldap_map
        .entries
        .iter()
        .any(|entry| entry.key == "\0" && entry.value == "\\00"));
    assert!(index.character_constraints.iter().any(|fact| {
        matches!(
            &fact.domain,
            CharacterConstraintDomain::ProviderBound {
                factory_call,
                operation_call,
                domain,
            } if factory_call == "map"
                && operation_call == "map.join"
                && matches!(
                    domain.as_ref(),
                    CharacterConstraintDomain::SubstitutesExact { mappings }
                        if mappings.iter().any(|entry| entry.key == "\0" && entry.value == "\\00")
                )
        )
    }));

    let html_map = index
        .static_string_maps
        .iter()
        .find(|fact| fact.target == "HTML")
        .expect("decoded HTML map");
    assert_eq!(html_map.entries.len(), 5);
    assert!(index.character_constraints.iter().any(|fact| {
        matches!(
            &fact.domain,
            CharacterConstraintDomain::ProviderBound {
                factory_call,
                operation_call,
                domain,
            } if factory_call.is_empty()
                && operation_call == "replace"
                && matches!(
                    domain.as_ref(),
                    CharacterConstraintDomain::SubstitutesExact { mappings }
                        if mappings.len() == 5
                            && mappings.iter().any(|entry| entry.key == "&" && entry.value == "&amp;")
                )
        )
    }));
    assert!(index.character_substitutions.is_empty());
}

#[test]
fn expression_arrow_replacement_chain_emits_exact_escape_summary() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "escape.ts",
            r#"
const escapeHtml = (value: string): string => value
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;")
  .replace(/'/g, "&#39;");
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("TypeScript declaration index");
    let summary = index.character_constraints.iter().find(|fact| {
        matches!(
            &fact.domain,
            bonsai_lang_api::CharacterConstraintDomain::ProviderBound {
                factory_call,
                operation_call,
                domain,
            } if factory_call.is_empty()
                && operation_call == "replace"
                && matches!(
                    domain.as_ref(),
                    bonsai_lang_api::CharacterConstraintDomain::SubstitutesExact { .. }
                )
        )
    });
    let Some(summary) = summary else {
        panic!(
            "expected provider-bound arrow summary: {:#?}",
            index.character_constraints
        );
    };
    let bonsai_lang_api::CharacterConstraintDomain::ProviderBound { domain, .. } = &summary.domain else {
        unreachable!("selected a provider-bound fact")
    };
    let bonsai_lang_api::CharacterConstraintDomain::SubstitutesExact { mappings } = domain.as_ref() else {
        unreachable!("selected a substitution fact")
    };
    assert_eq!(mappings.len(), 5);
    assert!(index.character_substitutions.is_empty());
}

#[test]
fn immutable_regex_binding_emits_character_constraint_summary() {
    use bonsai_lang_api::{CharacterConstraintDomain, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "header.ts",
            r#"
const UNSAFE = /[\r\n"\\]/g;
const safeFilename = (name: string): string => name.replace(UNSAFE, "_");
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("TypeScript declaration index");
    let helper = index
        .defs
        .iter()
        .find(|decl| decl.name == "safeFilename")
        .expect("safeFilename declaration");
    let summary = index
        .character_constraints
        .iter()
        .find(|fact| {
            fact.function_span == helper.span
                && matches!(
                    &fact.domain,
                    CharacterConstraintDomain::ProviderBound {
                        factory_call,
                        operation_call,
                        domain,
                    } if factory_call.is_empty()
                        && operation_call == "replace"
                        && matches!(
                            domain.as_ref(),
                            CharacterConstraintDomain::ExcludesExact { .. }
                        )
                )
        })
        .unwrap_or_else(|| {
            panic!(
                "expected provider-bound character constraint: {:#?}",
                index.character_constraints
            )
        });
    assert_eq!(summary.function_span, helper.span);
    assert!(matches!(
        &summary.domain,
        CharacterConstraintDomain::ProviderBound { domain, .. }
            if matches!(
                domain.as_ref(),
                CharacterConstraintDomain::ExcludesExact { characters }
                    if characters.contains(&"\r".to_string())
                        && characters.contains(&"\n".to_string())
            )
    ));
    assert!(index.character_substitutions.is_empty());
}

#[test]
fn provider_bound_mapping_candidates_keep_typescript_operations_generic_and_fail_closed() {
    use bonsai_lang_api::{CharacterConstraintDomain, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "mapping.ts",
            r#"
function direct(value: string): string {
  return value.scrub(/&/g, "and").scrub(/</g, "less");
}
function converted(value: string): string {
  return Coerce(value).scrub(/&/g, "and");
}
function mixed(value: string): string {
  return value.scrub(/&/g, "and").other(/</g, "less");
}
function Scalar(value: string): string {
  return value;
}
function shadowed(value: string): string {
  return Scalar(value).scrub(/&/g, "and");
}
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("TypeScript declaration index");
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
fn exported_property_path_guard_and_readonly_field_are_exact_facts() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "service.ts",
            r#"
const BLOCKED = new Set(["__proto__", "constructor", "prototype"]);
export function apply(path: string, value: unknown): void {
  const segments = path.split(/[.[\]]+/).filter((part) => part.length > 0);
  if (segments.some((part) => BLOCKED.has(part))) throw new Error("unsafe");
  set({}, segments, value);
}
class Store {
  private readonly BASE = "/srv/data";
  private mutable = "/tmp";
  read(name: string): string {
    return resolve(this.BASE, name);
  }
}
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("TypeScript declaration index");

    assert!(index.dynamic_key_filters.iter().any(|fact| {
        !fact.recursive
            && fact.output_place.as_deref() == Some("segments")
            && fact.rejected_exact_values == ["__proto__", "constructor", "prototype"]
    }));
    assert!(index.assignment_values.iter().any(|fact| {
        fact.target.as_deref() == Some("this.BASE")
            && fact.value_flow.is_empty()
            && fact.static_value
                == Some(bonsai_lang_api::StaticScalarValue::String(
                    "/srv/data".to_string(),
                ))
    }));
    assert!(!index
        .assignment_values
        .iter()
        .any(|fact| fact.target.as_deref() == Some("this.mutable")));
}

#[test]
fn const_binding_is_immutable_but_let_binding_is_not() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "parser.ts",
            r#"
const stable = new Parser({ enabled: true });
let mutable = new Parser({ enabled: true });
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("TypeScript declaration index");
    let stable = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("stable"))
        .expect("const assignment fact");
    let mutable = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("mutable"))
        .expect("let assignment fact");

    assert!(stable.target_is_immutable);
    assert!(!mutable.target_is_immutable);
}

#[test]
fn finite_object_selection_uses_typed_ast_shape_and_static_branches() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "commands.ts",
            r#"
const COMMANDS: Record<string, string[]> = {
  uptime: ["uptime"],
  disk: ["df", "-h"],
};
function command(name: string): string[] {
  const argv = Object.prototype.hasOwnProperty.call(COMMANDS, name)
    ? COMMANDS[name]
    : undefined;
  if (argv === undefined) throw new Error("unknown command");
  return argv;
}
function inline(name: string): unknown {
  return run(COMMANDS[name] ?? ["uptime"]);
}
function dynamic(name: string, fallback: string[]): string[] {
  const argv = Object.hasOwn(COMMANDS, name) ? COMMANDS[name] : fallback;
  return argv;
}
function destructured({ COMMANDS }: { COMMANDS: Map<string, string[]> }, name: string) {
  const local = COMMANDS.get(name) ?? ["local"];
  return local;
}
const shadowed = (COMMANDS: Map<string, string[]>) => {
  const local = COMMANDS.get("uptime") ?? ["local"];
  return local;
};
"#,
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("TypeScript declaration index");

    assert_eq!(
        index
            .finite_literal_selections
            .iter()
            .filter_map(|fact| fact.target.as_deref())
            .collect::<Vec<_>>(),
        ["argv"]
    );
    let inline = index
        .finite_literal_selections
        .iter()
        .find(|fact| fact.call_span.is_some())
        .expect("inline finite-map selection call argument");
    assert_eq!(inline.argument_index, Some(0));
    assert!(inline.assignment_span.is_none());
}

#[test]
fn finite_object_selection_rejects_shadowed_object_intrinsics() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "shadow.ts",
            r#"
const Object = {
  hasOwn(_map: unknown, _key: string): boolean { return true; },
};
const COMMANDS: Record<string, string[]> = { uptime: ["uptime"] };
function command(name: string): string[] | undefined {
  const argv = Object.hasOwn(COMMANDS, name) ? COMMANDS[name] : undefined;
  return argv;
}
"#,
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("TypeScript declaration index");
    assert!(index.finite_literal_selections.is_empty());
}

#[test]
fn inherited_getter_projection_adds_backing_field_source() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "storage.ts",
            r#"
abstract class BaseRepository<T extends { cmd: string }> {
  protected _data: T;
  constructor(data: T) { this._data = data; }
  get cmd(): string { return this._data.cmd; }
}
class Repository<T extends { cmd: string }> extends BaseRepository<T> {
  run(): unknown {
    const c: string = this.cmd;
    return execute(c);
  }
}
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let run = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "run")
        .expect("run declaration");

    assert!(
        run.flow_events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Assign {
                    target,
                    source_names,
                    ..
                } if target == "c"
                    && source_names.iter().any(|name| name == "this.cmd")
                    && source_names.iter().any(|name| name == "this._data.cmd")
            )
        }),
        "TypeScript inherited getter reads should project to backing receiver state: {:?}",
        run.flow_events
    );
}

#[test]
fn constructor_parameter_property_types_receiver_field() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "controller.ts",
            r#"
class Service {
  run(cmd: string): string { return cmd; }
}
class Controller {
  constructor(private readonly svc: Service) {}
  go(body: string): string {
    return this.svc.run(String(body));
  }
}
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let go = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "go")
        .expect("go declaration");

    assert!(
        go.type_aliases
            .iter()
            .any(|alias| alias.name == "this.svc" && alias.type_name == "Service"),
        "constructor parameter property should type the receiver field: {:?}",
        go.type_aliases
    );
    assert!(
        go.flow_events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Call {
                    name,
                    receiver,
                    receiver_types,
                    ..
                } if name == "this.svc.run"
                    && receiver.as_deref() == Some("this.svc")
                    && receiver_types.iter().any(|ty| ty == "Service")
            )
        }),
        "this.svc.run should carry Service receiver typing: {:?}",
        go.flow_events
    );
}

#[test]
fn ordinary_constructor_parameter_does_not_type_receiver_field() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "controller.ts",
            r#"
class Service {
  run(cmd: string): string { return cmd; }
}
class Controller {
  constructor(svc: Service) {}
  go(body: string): string {
    return this.svc.run(String(body));
  }
}
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let go = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "go")
        .expect("go declaration");

    assert!(
        !go.type_aliases.iter().any(|alias| alias.name == "this.svc"),
        "ordinary parameters must not declare receiver fields: {:?}",
        go.type_aliases
    );
    assert!(
        go.flow_events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Call {
                    name,
                    receiver,
                    receiver_types,
                    ..
                } if name == "this.svc.run"
                    && receiver.as_deref() == Some("this.svc")
                    && receiver_types.is_empty()
            )
        }),
        "unproven receiver fields must remain untyped: {:?}",
        go.flow_events
    );
}

#[test]
fn arrow_iife_body_contributes_to_module_flow() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "browser.ts",
            "(() => {\n  const query: string = window.location.search;\n  document.write(query);\n})();\n",
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
        "arrow IIFE assignment should be in module flow events: {:?}",
        module.flow_events
    );
    assert!(
        module.flow_events.iter().any(|event| {
            matches!(event, FlowEvent::Call { name, args, .. } if name == "document.write"
                && args.iter().any(|arg| arg.value_text == "query"))
        }),
        "arrow IIFE sink call should be in module flow events: {:?}",
        module.flow_events
    );
}

#[test]
fn arrow_iife_params_bind_to_corresponding_arguments() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "browser.ts",
            "((value: string) => {\n  sink(value);\n})(request.body);\n",
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
        "arrow IIFE parameter should bind to its positional argument: {:?}",
        module.flow_events
    );
    assert!(
        module.flow_events.iter().any(|event| {
            matches!(event, FlowEvent::Call { name, args, .. } if name == "sink"
                && args.iter().any(|arg| arg.value_text == "value"))
        }),
        "arrow IIFE body call should be in module flow events: {:?}",
        module.flow_events
    );
}

#[test]
fn external_dispatch_config_retains_syntax_without_inventing_execution() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "graphql.ts",
            r#"
import { graphql, buildSchema } from "graphql";
const schema = buildSchema("type Query { products(filter: String!): [String!]! }");
const root = {
  products: ({ filter }: { filter: string }) => findProducts(filter),
};
router.post("/query", async (req: any, res: any) => {
  const { query, variables } = req.body ?? {};
  const result = await graphql({ schema, source: query, rootValue: root, variableValues: variables });
  res.json(result);
});
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let file = ws.db().vfs().all_files()[0];
    let file_index = ws.db().decl_index(file).expect("TypeScript compiler index");
    let root_assignment = file_index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("root"))
        .expect("root resolver-map assignment");
    assert!(root_assignment.target_is_immutable);
    assert_eq!(root_assignment.inline_callback_fields.len(), 1);
    assert_eq!(root_assignment.inline_callback_fields[0].path, ["products"]);
    assert_eq!(root_assignment.inline_callback_fields[0].params, ["filter"]);
    let graphql_argument = file_index
        .call_argument_values
        .iter()
        .find(|fact| {
            fact.value_flow
                .aggregate_fields
                .iter()
                .any(|field| field.name == "rootValue")
        })
        .expect("GraphQL aggregate argument");
    assert!(graphql_argument
        .value_flow
        .aggregate_fields
        .iter()
        .any(|field| field.name == "variableValues" && field.value.place.as_deref() == Some("variables")));
    let global = ws.db().global_index();
    let module = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "__module__")
        .expect("module declaration");
    let products = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "products")
        .expect("resolver callable declaration");

    assert!(
        products.params.iter().any(|param| param == "filter"),
        "the frontend must retain the resolver's exact destructured parameter: {:?}",
        products.params
    );
    assert!(
        global
            .all_files()
            .flat_map(|file| global.decls_in(file))
            .any(|decl| flow_events_contain(&decl.flow_events, &|event| {
                matches!(event, FlowEvent::Call { name, .. } if name == "graphql")
            })),
        "the external call itself must remain owned by its exact nested callable"
    );
    assert!(
        !flow_events_contain(&module.flow_events, &|event| {
            matches!(event, FlowEvent::Call { name, .. } if name == "products")
        }),
        "passing an external dispatch configuration must not fabricate resolver execution: {:?}",
        module.flow_events
    );
}

fn flow_events_contain(
    events: &[bonsai_lang_api::FlowEvent],
    predicate: &dyn Fn(&bonsai_lang_api::FlowEvent) -> bool,
) -> bool {
    events.iter().any(|event| {
        if predicate(event) {
            return true;
        }
        match event {
            bonsai_lang_api::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => flow_events_contain(then_events, predicate) || flow_events_contain(else_events, predicate),
            bonsai_lang_api::FlowEvent::Loop { body, .. }
            | bonsai_lang_api::FlowEvent::Defer { body, .. }
            | bonsai_lang_api::FlowEvent::Using { body, .. } => flow_events_contain(body, predicate),
            bonsai_lang_api::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                flow_events_contain(body, predicate)
                    || flow_events_contain(catch_events, predicate)
                    || flow_events_contain(finally_events, predicate)
            }
            _ => false,
        }
    })
}
