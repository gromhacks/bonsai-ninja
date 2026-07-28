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
fn static_escape_maps_and_character_transforms_are_exact_compiler_facts() {
    use bonsai_lang_api::{CharacterSubstitutionDomain, LanguageAdapter};

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
    assert!(index.character_substitutions.iter().any(|fact| {
        fact.table == "LDAP" && fact.domain == CharacterSubstitutionDomain::TableKeysWithIdentityFallback
    }));

    let html_map = index
        .static_string_maps
        .iter()
        .find(|fact| fact.target == "HTML")
        .expect("decoded HTML map");
    assert_eq!(html_map.entries.len(), 5);
    assert!(index.character_substitutions.iter().any(|fact| {
        fact.table == "HTML"
            && matches!(
                &fact.domain,
                CharacterSubstitutionDomain::ExactCharacters { characters }
                    if characters == &vec![
                        "\"".to_string(),
                        "&".to_string(),
                        "'".to_string(),
                        "<".to_string(),
                        ">".to_string(),
                    ]
            )
    }));
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
            .map(|fact| fact.target.as_str())
            .collect::<Vec<_>>(),
        ["argv"]
    );
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
fn trpc_procedure_callback_input_gets_precise_source_token() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "router.ts",
            r#"
import { initTRPC } from "@trpc/server";
const t = initTRPC.create();
export const appRouter = t.router({
  list: t.procedure.input(z.object({ q: z.string() })).query(async ({ input }) => {
    return sink(input.q);
  }),
});
"#,
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
        flow_events_contain(&module.flow_events, &|event| {
            matches!(
                event,
                FlowEvent::Assign {
                    target,
                    source_names,
                    ..
                } if target == "input" && source_names.iter().any(|name| name == "trpc.input")
            )
        }),
        "tRPC callback input binding should carry the synthetic source token: {:?}",
        module.flow_events
    );
}

#[test]
fn graphql_root_value_dispatches_variable_values_to_resolver() {
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
    let global = ws.db().global_index();
    let module = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "__module__")
        .expect("module declaration");

    assert!(
        flow_events_contain(&module.flow_events, &|event| {
            matches!(
                event,
                FlowEvent::Call { name, args, .. }
                    if name == "products"
                        && args.iter().any(|arg| arg.value_text == "variables.filter")
            )
        }),
        "graphql({{ rootValue, variableValues }}) should dispatch variable values into root resolver calls: {:?}",
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
