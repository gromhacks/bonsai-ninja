use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_c::CAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("m.c", "int main(void) { return 0; }")]
    );
}

/// Drift guard for the semantic-identity contract
/// (`docs/contributing/design-patterns.mdx::Semantic Resolution Always`). The C
/// adapter must:
///
/// - emit `Decl.qualified_name = Some("<file_stem>.<name>")` for
///   every function — never `None`;
/// - emit `Decl.module_path = ["<file_stem>"]`;
/// - mark `static` functions as `Visibility::Private` so the
///   resolver's per-file filter prevents cross-TU `error()` /
///   `init()` / `cleanup()` collisions.
#[test]
fn c_adapter_populates_qualified_name_and_visibility() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter, Visibility};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_c::CAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("hiredis_error.c"),
        "static void error(const char *msg) { /* hiredis-private */ }\nint main(void) { error(\"x\"); return 0; }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);

    let error_decl = idx
        .defs
        .iter()
        .find(|d| d.name == "error")
        .expect("error decl present");
    assert_eq!(
        error_decl.qualified_name.as_deref(),
        Some("hiredis_error.error"),
        "qualified_name must be file-stem-prefixed for C TU-private decls"
    );
    assert_eq!(
        error_decl.module_path.segments,
        vec!["hiredis_error".to_string()],
        "module_path is the file stem for C"
    );
    assert!(
        matches!(error_decl.visibility, Visibility::Private),
        "static C functions must be Visibility::Private, got {:?}",
        error_decl.visibility
    );

    let main_decl = idx
        .defs
        .iter()
        .find(|d| d.name == "main")
        .expect("main decl present");
    assert!(
        matches!(main_decl.visibility, Visibility::Public),
        "non-static C functions must be Visibility::Public, got {:?}",
        main_decl.visibility
    );
}

#[test]
fn c_nested_tags_do_not_gain_cpp_style_type_ownership() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_c::CAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("types.c"),
        "struct Outer { struct Inner { int value; } inner; };\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let index = adapter.extract_declarations(file, &ctx);
    let outer = index
        .defs
        .iter()
        .find(|decl| decl.name == "Outer")
        .expect("Outer tag");
    let inner = index
        .defs
        .iter()
        .find(|decl| decl.name == "Inner")
        .expect("Inner tag");

    assert_ne!(inner.parent, Some(outer.symbol));
    assert_eq!(inner.qualified_name.as_deref(), Some("types.Inner"));
}

#[test]
fn c_adapter_does_not_index_function_pointer_api_declarations_as_int() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_c::CAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("module_api.h"),
        "REDISMODULE_API int (*RedisModule_GetApi)(const char *, void *) REDISMODULE_ATTR;\n\
         REDISMODULE_API int (*RedisModule_CreateCommand)(void *ctx, const char *name) REDISMODULE_ATTR;\n\
         static int real_function(int x) { return x; }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);

    assert!(
        idx.defs.iter().all(|decl| decl.name != "int"),
        "function-pointer API declarations must not become an `int` function: {:?}",
        idx.defs.iter().map(|decl| &decl.name).collect::<Vec<_>>()
    );
    assert!(
        idx.defs.iter().any(|decl| decl.name == "real_function"),
        "real function definitions with compound bodies must still be indexed"
    );
}

#[test]
fn c_adapter_emits_function_pointer_callable_alias() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_c::CAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("callbacks.c"),
        "void helper(char *p) { sink(p); }\nvoid entry(char *args) { void (*cb)(char*) = helper; cb(args); }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let entry = idx
        .defs
        .iter()
        .find(|decl| decl.name == "entry")
        .expect("entry decl present");

    assert!(
        entry.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_name: Some(source),
                source_call: None,
                ..
            } if target == "cb" && source == "helper"
        )),
        "function-pointer initializer must emit exact cb -> helper alias, got {:?}",
        entry.flow_events
    );
}

#[test]
fn c_adapter_call_result_assignment_uses_call_metadata_only() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_c::CAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("call_result.c"),
        "const char *f(const char *a) { return a; }\n\
         const char *entry(const char *x) { const char *z = f(x); return z; }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let entry = idx
        .defs
        .iter()
        .find(|decl| decl.name == "entry")
        .expect("entry decl present");

    let assign = entry
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } if target == "z" => Some((source_name, source_call, source_call_args, source_names)),
            _ => None,
        })
        .expect("assignment to z present");

    assert_eq!(assign.0.as_deref(), None);
    assert_eq!(assign.1.as_deref(), Some("f"));
    assert_eq!(assign.2.as_slice(), ["x"]);
    assert!(
        assign.3.is_empty(),
        "call-result assignment should not duplicate callee/arg sources; events: {:?}",
        entry.flow_events
    );
}

fn c_index(source: &str) -> bonsai_lang_api::DeclIndex {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_c::CAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("filter.c"), source);
    let diagnostics = RwLock::new(DiagnosticSink::default());
    adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    )
}

#[test]
fn c_adapter_lowers_predicate_guarded_buffer_filter_without_provider_semantics() {
    let index = c_index(
        r#"void filter(const char *input) {
            char output[64] = {0};
            int j = 0;
            for (int i = 0; input[i]; i++) {
                if (predicate((unsigned char)input[i])) output[j++] = input[i];
            }
            output[j] = 0;
            consume(output);
        }"#,
    );
    let [fact] = index.guarded_value_filters.as_slice() else {
        panic!(
            "expected one guarded filter fact, got {:?}",
            index.guarded_value_filters
        );
    };
    assert_eq!(fact.input_place, "input");
    assert_eq!(fact.output_place, "output");
    assert_eq!(
        &c_index_source_slice(
            r#"void filter(const char *input) {
            char output[64] = {0};
            int j = 0;
            for (int i = 0; input[i]; i++) {
                if (predicate((unsigned char)input[i])) output[j++] = input[i];
            }
            output[j] = 0;
            consume(output);
        }"#,
            fact.predicate_call_span,
        ),
        "predicate"
    );
}

fn c_index_source_slice(source: &str, span: bonsai_common::Span) -> String {
    source[usize::try_from(span.start).unwrap()..usize::try_from(span.end).unwrap()].to_string()
}

#[test]
fn c_adapter_rejects_negated_predicate_filter() {
    let index = c_index(
        r#"void filter(const char *input) {
            char output[64] = {0}; int j = 0;
            for (int i = 0; input[i]; i++) {
                if (!predicate(input[i])) output[j++] = input[i];
            }
            output[j] = 0; consume(output);
        }"#,
    );
    assert!(index.guarded_value_filters.is_empty());
}

#[test]
fn c_adapter_rejects_unrelated_predicate_input() {
    let index = c_index(
        r#"void filter(const char *input, const char *other) {
            char output[64] = {0}; int j = 0;
            for (int i = 0; input[i]; i++) {
                if (predicate(other[i])) output[j++] = input[i];
            }
            output[j] = 0; consume(output);
        }"#,
    );
    assert!(index.guarded_value_filters.is_empty());
}

#[test]
fn c_adapter_rejects_additional_unguarded_dynamic_write() {
    let index = c_index(
        r#"void filter(const char *input) {
            char output[64] = {0}; int j = 0;
            for (int i = 0; input[i]; i++) {
                if (predicate(input[i])) output[j++] = input[i];
            }
            output[j++] = input[0];
            output[j] = 0; consume(output);
        }"#,
    );
    assert!(index.guarded_value_filters.is_empty());
}
