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
