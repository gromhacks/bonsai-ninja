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

#[test]
fn c_call_arguments_use_ast_value_kinds_not_identifier_spelling() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, AssignValueKind, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_c::CAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("values.c"),
        "void emit(const char*, const char*, int);\n\
         void run(const char *USER_VALUE) { emit(\"literal\", USER_VALUE, 42); }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let kind = |argument_index| {
        index
            .call_argument_values
            .iter()
            .find(|fact| fact.argument_index == argument_index)
            .and_then(|fact| fact.value_kind)
    };

    assert_eq!(kind(0), Some(AssignValueKind::Literal));
    assert_eq!(kind(1), None, "ALL_CAPS is still a dynamic parameter");
    assert_eq!(kind(2), Some(AssignValueKind::Literal));
}

#[test]
fn c_address_of_complete_aggregate_is_a_distinct_argument_value_kind() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, AssignValueKind, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let source = r#"typedef struct { unsigned role; char name[32]; } session_t;
void consume(void *, const unsigned char *, unsigned);
void restore(const unsigned char *input, unsigned n) {
  session_t state;
  unsigned scalar = 0;
  unsigned char bytes[64];
  consume(&state, input, n);
  consume(&state.role, input, n);
  consume(&scalar, input, n);
  consume(bytes, input, n);
}
"#;
    let adapter = bonsai_lang_c::CAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("aggregate.c"), source);
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let aggregate_arguments = index
        .call_argument_values
        .iter()
        .filter(|fact| fact.value_kind == Some(AssignValueKind::AddressOfAggregate))
        .collect::<Vec<_>>();
    let [aggregate] = aggregate_arguments.as_slice() else {
        panic!(
            "expected only &state to be aggregate-address evidence: {:#?}",
            index.call_argument_values
        );
    };
    let argument = &source[aggregate.argument_span.start as usize..aggregate.argument_span.end as usize];
    assert_eq!(argument, "&state");
}

#[test]
fn c_nested_call_argument_records_exact_call_result_identity() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_c::CAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("nested.c"),
        "char *produce(void) { return \"\"; }\n\
         void consume(char *value) {}\n\
         void run(void) { consume(produce()); }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let run = index.defs.iter().find(|decl| decl.name == "run").expect("run");
    let outer = run
        .flow_events
        .iter()
        .find_map(|event| match event {
            bonsai_lang_api::FlowEvent::Call { span, name, .. } if name == "consume" => Some(*span),
            _ => None,
        })
        .expect("outer call");
    let inner = run
        .flow_events
        .iter()
        .find_map(|event| match event {
            bonsai_lang_api::FlowEvent::Call { span, name, .. } if name == "produce" => Some(*span),
            _ => None,
        })
        .expect("nested call");
    let argument = index
        .call_argument_values
        .iter()
        .find(|fact| fact.call_span == outer && fact.argument_index == 0)
        .expect("outer argument value fact");

    assert_eq!(argument.direct_call_span, Some(inner));
    assert!(argument.value_flow.source_names.is_empty());
}

#[test]
fn complete_literal_return_helpers_fail_closed_on_dynamic_or_fallthrough_paths() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_c::CAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("selectors.c"),
        "const char *closed(const char *key) {\n\
           if (key[0] == 'a') return \"alpha\";\n\
           if (key[0] == 'b') return \"beta\";\n\
           return \"fallback\";\n\
         }\n\
         const char *dynamic(const char *key) { if (key[0]) return \"fixed\"; return key; }\n\
         const char *fallthrough(const char *key) { if (key[0]) return \"fixed\"; }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let fact_owner = |name: &str| {
        let decl = index.defs.iter().find(|decl| decl.name == name).expect("helper");
        index.finite_literal_selections.iter().any(|fact| {
            decl.span.start <= fact.selection_span.start && fact.selection_span.end <= decl.span.end
        })
    };

    assert!(fact_owner("closed"));
    assert!(!fact_owner("dynamic"));
    assert!(!fact_owner("fallthrough"));
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
fn c_adapter_proves_exact_numeric_clamp_for_call_argument_storage() {
    let index = c_index(
        r#"typedef struct { char payload[128]; } packet_t;
        void restore(const unsigned char *input, unsigned long claimed) {
            packet_t packet;
            if (claimed > sizeof(packet.payload)) claimed = sizeof(packet.payload);
            char output[128];
            copy_bytes(output, input, claimed);
        }"#,
    );
    let [fact] = index.compiler_guards.as_slice() else {
        panic!(
            "expected one numeric upper-bound fact: {:#?}",
            index.compiler_guards
        );
    };
    assert_eq!(fact.capability, "call-argument.numeric-upper-bound");
    assert_eq!(fact.evidence, ["destination-argument:0", "length-argument:2"]);
}

#[test]
fn c_adapter_numeric_bound_fails_closed_for_observation_overwrite_and_small_destination() {
    for source in [
        r#"void restore(const char *input, unsigned long claimed) {
            char output[128];
            if (claimed > sizeof(output)) observe(claimed);
            copy_bytes(output, input, claimed);
        }"#,
        r#"void restore(const char *input, unsigned long claimed) {
            char output[128];
            if (claimed > sizeof(output)) claimed = sizeof(output);
            claimed = read_length();
            copy_bytes(output, input, claimed);
        }"#,
        r#"typedef struct { char payload[128]; } packet_t;
        void restore(const char *input, unsigned long claimed) {
            packet_t packet;
            if (claimed > sizeof(packet.payload)) claimed = sizeof(packet.payload);
            char output[64];
            copy_bytes(output, input, claimed);
        }"#,
    ] {
        let index = c_index(source);
        assert!(
            index.compiler_guards.is_empty(),
            "an incomplete numeric proof must not emit compiler guard facts: {:#?}",
            index.compiler_guards
        );
    }
}

#[test]
fn c_adapter_compound_predicate_guard_requires_complete_static_membership_and_configuration() {
    let safe = c_index(
        r#"static const char *TRUSTED[] = {"api.example", "hooks.example", NULL};
static int accepted(const char *value) {
  if (strncmp(value, "https://", 8) != 0) return 0;
  const char *token = value + 8;
  for (int i = 0; TRUSTED[i]; i++) {
    size_t n = text_len(TRUSTED[i]);
    if (strncmp(token, TRUSTED[i], n) == 0 &&
        (token[n] == '/' || token[n] == '\0')) return 1;
  }
  return 0;
}
void fetch(void *client, const char *value) {
  if (!accepted(value)) return;
  curl_easy_setopt(client, CURLOPT_URL, value);
  curl_easy_setopt(client, CURLOPT_FOLLOWLOCATION, 0L);
}
"#,
    );
    let guarded = safe
        .compiler_guards
        .iter()
        .find(|fact| {
            fact.capability == "terminal-predicate.compound-static-allowlist"
                && fact
                    .evidence
                    .contains(&"guarded-argument:2=predicate-argument:0".to_string())
        })
        .unwrap_or_else(|| panic!("missing compound predicate fact: {:#?}", safe.compiler_guards));
    for required in [
        "predicate-complete:true",
        "finite-static-string-membership:true",
        "prefix-call:strncmp",
        "prefix-value:string:https://",
        "membership-call:strncmp",
        "membership-token-boundary:true",
        "related-call:curl_easy_setopt:argument:0=guarded-argument:0",
        "related-call:curl_easy_setopt:argument:1=place:CURLOPT_FOLLOWLOCATION",
        "related-call:curl_easy_setopt:argument:2=number:0",
    ] {
        assert!(
            guarded.evidence.iter().any(|evidence| evidence == required),
            "missing {required}: {guarded:#?}"
        );
    }

    for unsafe_source in [
        r#"static int accepted(const char *value) {
  if (prefix_cmp(value, "https://", 8) != 0) return 0;
  return 1;
}
void fetch(void *client, const char *value) {
  if (!accepted(value)) return;
  configure(client, URL_OPTION, value);
}
"#,
        r#"static const char *TRUSTED[] = {"api.example", dynamic_host(), NULL};
static int accepted(const char *value) {
  if (prefix_cmp(value, "https://", 8) != 0) return 0;
  const char *token = value + 8;
  for (int i = 0; TRUSTED[i]; i++) {
    size_t n = text_len(TRUSTED[i]);
    if (token_cmp(token, TRUSTED[i], n) == 0 &&
        (token[n] == '/' || token[n] == '\0')) return 1;
  }
  return 0;
}
void fetch(void *client, const char *value) {
  if (!accepted(value)) return;
  configure(client, URL_OPTION, value);
}
"#,
    ] {
        let unsafe_index = c_index(unsafe_source);
        assert!(
            unsafe_index
                .compiler_guards
                .iter()
                .all(|fact| fact.capability != "terminal-predicate.compound-static-allowlist"),
            "incomplete or dynamic membership must fail closed: {:#?}",
            unsafe_index.compiler_guards
        );
    }
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

struct ExactTreeProvider(std::sync::Arc<tree_sitter::Tree>);

impl bonsai_lang_api::TreeProvider for ExactTreeProvider {
    fn tree_for_snapshot(
        &self,
        pack_name: &str,
        _snapshot: &bonsai_lang_api::FileSnapshot,
    ) -> Option<std::sync::Arc<tree_sitter::Tree>> {
        (pack_name == "c").then(|| self.0.clone())
    }
}

fn collect_call_names(events: &[bonsai_lang_api::FlowEvent], out: &mut Vec<String>) {
    for event in events {
        match event {
            bonsai_lang_api::FlowEvent::Call { name, .. } => out.push(name.clone()),
            bonsai_lang_api::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_call_names(then_events, out);
                collect_call_names(else_events, out);
            }
            bonsai_lang_api::FlowEvent::Loop { body, .. }
            | bonsai_lang_api::FlowEvent::Defer { body, .. }
            | bonsai_lang_api::FlowEvent::Using { body, .. } => collect_call_names(body, out),
            bonsai_lang_api::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_call_names(body, out);
                collect_call_names(catch_events, out);
                collect_call_names(finally_events, out);
            }
            _ => {}
        }
    }
}

#[test]
fn c_preprocessor_alternative_statement_bodies_are_never_joined_sequentially() {
    use bonsai_lang_api::AdapterArc;
    use bonsai_parser::{ParserCache, ParserOptions};
    use bonsai_vfs::Vfs;

    let source = r#"int choose(int value) {
#if FIRST_CONFIGURATION
    if (sanitize(value)) return value;
#else
    consume(value);
#endif
    return value;
}
"#;
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("alternative_bodies.c"), source);
    let adapter: AdapterArc = std::sync::Arc::new(bonsai_lang_c::CAdapter::new());
    let parsed = ParserCache::with_options(ParserOptions::with_parse_timeout(None))
        .parse(file, &adapter, &vfs)
        .expect("parse complete preprocessor statement alternatives");

    assert!(
        !parsed.tree.root_node().has_error(),
        "Tree-sitter can retain complete alternatives without recovery"
    );
    let sexp = parsed.tree.root_node().to_sexp();
    assert!(
        sexp.contains("preproc_if"),
        "sanitizing and sinking alternatives must remain exclusive: {sexp}"
    );
    assert_eq!(parsed.source_text(), source);
}

#[test]
fn c_unknown_identifier_type_pairs_remain_ambiguous_and_fail_closed() {
    use bonsai_lang_api::AdapterArc;
    use bonsai_parser::{ParserCache, ParserOptions};
    use bonsai_vfs::Vfs;

    let source = r#"FIRST_UNKNOWN SECOND_UNKNOWN transform(int value) {
    consume(value);
    return value;
}
"#;
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("ambiguous_specifiers.c"), source);
    let adapter: AdapterArc = std::sync::Arc::new(bonsai_lang_c::CAdapter::new());
    let parsed = ParserCache::with_options(ParserOptions::with_parse_timeout(None))
        .parse(file, &adapter, &vfs)
        .expect("parse ambiguous declaration specifiers");

    assert!(
        parsed.tree.root_node().has_error(),
        "syntax alone cannot decide which unknown identifier is the type: {}",
        parsed.tree.root_node().to_sexp()
    );
    assert_eq!(parsed.source_text(), source);
}

#[test]
fn c_builtin_words_inside_executable_errors_are_not_declaration_annotations() {
    use bonsai_lang_api::AdapterArc;
    use bonsai_parser::{ParserCache, ParserOptions};
    use bonsai_vfs::Vfs;

    let source = r#"int transform(int value) {
    value = unknown int;
    consume(value);
    return value;
}
"#;
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("body_error.c"), source);
    let adapter: AdapterArc = std::sync::Arc::new(bonsai_lang_c::CAdapter::new());
    let parsed = ParserCache::with_options(ParserOptions::with_parse_timeout(None))
        .parse(file, &adapter, &vfs)
        .expect("parse malformed executable expression");

    assert!(
        parsed.tree.root_node().has_error(),
        "recovery must never mask executable syntax damage"
    );
    assert_eq!(parsed.source_text(), source);
}

#[test]
fn c_complete_preprocessor_alternatives_are_not_flattened() {
    use bonsai_lang_api::AdapterArc;
    use bonsai_parser::{ParserCache, ParserOptions};
    use bonsai_vfs::Vfs;

    let source = r#"int choose(int first, int second) {
#ifdef FEATURE_A
    if (first) return 1;
#else
    if (second) return 2;
#endif
    return 0;
}
"#;
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("complete.c"), source);
    let adapter: AdapterArc = std::sync::Arc::new(bonsai_lang_c::CAdapter::new());
    let parsed = ParserCache::with_options(ParserOptions::with_parse_timeout(None))
        .parse(file, &adapter, &vfs)
        .expect("parse complete conditional alternatives");

    assert!(!parsed.tree.root_node().has_error());
    assert!(
        parsed.tree.root_node().to_sexp().contains("preproc_ifdef"),
        "complete alternative bodies must stay represented as preprocessor syntax"
    );
}

#[test]
fn c_conditional_statement_alternatives_are_not_treated_as_definitions() {
    use bonsai_lang_api::AdapterArc;
    use bonsai_parser::{ParserCache, ParserOptions};
    use bonsai_vfs::Vfs;

    let source = r#"void transform(int value) {
#if FAST_PATH
    consume(value);
#else
    preserve(value);
#endif
}
"#;
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("statement_alternatives.c"), source);
    let adapter: AdapterArc = std::sync::Arc::new(bonsai_lang_c::CAdapter::new());
    let parsed = ParserCache::with_options(ParserOptions::with_parse_timeout(None))
        .parse(file, &adapter, &vfs)
        .expect("parse ordinary statement alternatives");

    let sexp = parsed.tree.root_node().to_sexp();
    assert!(!parsed.tree.root_node().has_error(), "{sexp}");
    assert!(sexp.contains("preproc_if"));
    assert_eq!(parsed.source_text(), source);
}

#[test]
fn c_split_function_prefixes_fail_closed_instead_of_flattening_control_flow() {
    use bonsai_lang_api::AdapterArc;
    use bonsai_parser::{ParserCache, ParserOptions};
    use bonsai_vfs::Vfs;

    let source = r#"#if WIDE_SIGNATURE
static int decode(int value, int mode) {
    value = sanitize(value);
    return value;
#else
static int decode(int value) {
    consume(value);
#endif
    finish(value);
    return value;
}
"#;
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("split_function.c"), source);
    let adapter: AdapterArc = std::sync::Arc::new(bonsai_lang_c::CAdapter::new());
    let parsed = ParserCache::with_options(ParserOptions::with_parse_timeout(None))
        .parse(file, &adapter, &vfs)
        .expect("parse split function prefixes");
    assert!(
        parsed.tree.root_node().has_error(),
        "mutually exclusive definitions must not become one sequential body: {}",
        parsed.tree.root_node().to_sexp()
    );
    assert_eq!(parsed.source_text(), source);
}

#[test]
fn c_different_split_function_names_fail_closed() {
    use bonsai_lang_api::AdapterArc;
    use bonsai_parser::{ParserCache, ParserOptions};
    use bonsai_vfs::Vfs;

    let source = r#"#if FIRST_IMPLEMENTATION
int decode_first(int value) {
#else
int decode_second(int value) {
#endif
    return value;
}
"#;
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("different_functions.c"), source);
    let adapter: AdapterArc = std::sync::Arc::new(bonsai_lang_c::CAdapter::new());
    let parsed = ParserCache::with_options(ParserOptions::with_parse_timeout(None))
        .parse(file, &adapter, &vfs)
        .expect("parse different split functions");

    assert!(
        parsed.tree.root_node().has_error(),
        "different callable identities must not be merged"
    );
    assert_eq!(parsed.source_text(), source);
}

#[test]
fn c_branch_free_optional_parameters_are_retained() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterArc, AdapterContext, LanguageAdapter};
    use bonsai_parser::{ParserCache, ParserOptions};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let source = r#"int validate(int required
#if WITH_OPTIONAL_CONTEXT
    , int optional
#endif
) {
    consume(required, optional);
    return required;
}
"#;
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("optional_parameters.c"), source);
    let adapter: AdapterArc = std::sync::Arc::new(bonsai_lang_c::CAdapter::new());
    let parsed = ParserCache::with_options(ParserOptions::with_parse_timeout(None))
        .parse(file, &adapter, &vfs)
        .expect("parse optional parameters");
    assert!(!parsed.tree.root_node().has_error());

    let provider = ExactTreeProvider(parsed.tree.clone());
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = bonsai_lang_c::CAdapter::new().extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: Some(&provider),
            workspace_root: None,
        },
    );
    let validate = index
        .defs
        .iter()
        .find(|decl| decl.name == "validate")
        .expect("validate");
    assert_eq!(validate.params, ["required", "optional"]);
    assert_eq!(parsed.source_text(), source);
}

#[test]
fn c_comma_prefixed_trailing_parameters_recover_inside_a_damaged_translation_unit() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterArc, AdapterContext, LanguageAdapter};
    use bonsai_parser::{ParserCache, ParserOptions};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let source = r#"int validate(struct Context *context, struct State *state
#if WITH_TRAILING_PARAMETERS
    , unsigned *counter, struct Options options, unsigned char *scratch
#endif
) {
    consume(context, state, counter, options, scratch);
    return 1;
}
int unrelated(
"#;
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("damaged_optional_parameters.c"), source);
    let adapter: AdapterArc = std::sync::Arc::new(bonsai_lang_c::CAdapter::new());
    let parsed = ParserCache::with_options(ParserOptions::with_parse_timeout(None))
        .parse(file, &adapter, &vfs)
        .expect("parse optional trailing parameters amid unrelated damage");
    assert!(
        parsed.tree.root_node().has_error(),
        "the unrelated incomplete declaration must remain fail-closed"
    );

    let provider = ExactTreeProvider(parsed.tree.clone());
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = bonsai_lang_c::CAdapter::new().extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: Some(&provider),
            workspace_root: None,
        },
    );
    let validate = index
        .defs
        .iter()
        .find(|decl| decl.name == "validate")
        .expect("the recovered definition must survive unrelated damage");
    assert_eq!(
        validate.params,
        ["context", "state", "counter", "options", "scratch"]
    );
    let mut calls = Vec::new();
    collect_call_names(&validate.flow_events, &mut calls);
    assert_eq!(calls, ["consume"]);
    assert_eq!(parsed.source_text(), source);
}

#[test]
fn c_conditional_local_declarations_remain_preprocessor_syntax() {
    use bonsai_lang_api::AdapterArc;
    use bonsai_parser::{ParserCache, ParserOptions};
    use bonsai_vfs::Vfs;

    let source = r#"int validate(int value) {
#if WITH_LOCAL
    int local = value;
#endif
    return value;
}
"#;
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("conditional_local.c"), source);
    let adapter: AdapterArc = std::sync::Arc::new(bonsai_lang_c::CAdapter::new());
    let parsed = ParserCache::with_options(ParserOptions::with_parse_timeout(None))
        .parse(file, &adapter, &vfs)
        .expect("parse conditional local declaration");
    let sexp = parsed.tree.root_node().to_sexp();
    assert!(!parsed.tree.root_node().has_error(), "{sexp}");
    assert!(sexp.contains("preproc_if"));
    assert_eq!(parsed.source_text(), source);
}

#[test]
fn c_parser_cache_invalidates_when_reachable_header_macro_context_changes() {
    use bonsai_lang_api::AdapterArc;
    use bonsai_parser::{ParserCache, ParserOptions};
    use bonsai_vfs::Vfs;
    use std::sync::Arc;

    let vfs = Vfs::new();
    let header_path = std::path::PathBuf::from("/compiler-cache/api.h");
    let source_path = std::path::PathBuf::from("/compiler-cache/main.c");
    let header = vfs.write(&header_path, Arc::<str>::from("#define API\n"));
    let source = vfs.write(
        &source_path,
        Arc::<str>::from("#include \"api.h\"\nAPI int endpoint(void) { return 42; }\n"),
    );
    let adapter: AdapterArc = Arc::new(bonsai_lang_c::CAdapter::new());
    let cache = ParserCache::with_options(ParserOptions::with_parse_timeout(None));

    let with_macro = cache
        .parse(source, &adapter, &vfs)
        .expect("parse with reachable macro");
    assert!(
        !with_macro.tree.root_node().has_error(),
        "the exact reachable object macro should recover the declaration"
    );

    vfs.write(&header_path, Arc::<str>::from("#define OTHER\n"));
    let without_macro = cache
        .parse(source, &adapter, &vfs)
        .expect("parse after removing reachable macro");
    assert!(
        without_macro.tree.root_node().has_error(),
        "unchanged source must not reuse a recovery tree from stale header context"
    );

    vfs.write(&header_path, Arc::<str>::from("#define API\n"));
    let restored = cache
        .parse(source, &adapter, &vfs)
        .expect("parse after restoring reachable macro");
    assert!(
        !restored.tree.root_node().has_error(),
        "restored exact header context must be reparsed and recovered"
    );
    assert_eq!(
        vfs.snapshot(header).expect("current header snapshot").version,
        2,
        "fixture must exercise two external-context revisions"
    );
}

#[test]
fn c_recovery_requires_a_compiler_proven_declaration_macro() {
    use bonsai_lang_api::AdapterArc;
    use bonsai_parser::{ParserCache, ParserOptions};
    use bonsai_vfs::Vfs;

    let source = r#"#define DECL_ATTRIBUTE
DECL_ATTRIBUTE void transform(int value) {
    consume(value);
}
"#;
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("defined_attribute.c"), source);
    let adapter: AdapterArc = std::sync::Arc::new(bonsai_lang_c::CAdapter::new());
    let parsed = ParserCache::with_options(ParserOptions::with_parse_timeout(None))
        .parse(file, &adapter, &vfs)
        .expect("parse compiler-proven declaration macro");

    assert!(!parsed.tree.root_node().has_error());
    assert_eq!(parsed.source_text(), source);
    assert!(parsed.tree.root_node().to_sexp().contains("function_definition"));
}

#[test]
fn c_recovery_handles_conditionally_defined_declaration_macros() {
    use bonsai_lang_api::AdapterArc;
    use bonsai_parser::{ParserCache, ParserOptions};
    use bonsai_vfs::Vfs;

    let source = r#"#if BUILD_INTERNAL
#define API __attribute__((visibility("internal"))) extern
#else
#define API extern
#endif

#define RUN_STEP(out, input) \
  { out = compute(input); if (out == 0) fail(); }

API int transform(int value);

int handle(int value) {
    RUN_STEP(value, value);
    return transform(value);
}
"#;
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("conditional_attribute.c"), source);
    let adapter: AdapterArc = std::sync::Arc::new(bonsai_lang_c::CAdapter::new());
    let parsed = ParserCache::with_options(ParserOptions::with_parse_timeout(None))
        .parse(file, &adapter, &vfs)
        .expect("parse conditional declaration macro");

    assert!(
        !parsed.tree.root_node().has_error(),
        "{}",
        parsed.tree.root_node().to_sexp()
    );
    assert_eq!(parsed.source_text(), source);
    assert!(parsed.tree.root_node().to_sexp().contains("function_definition"));
}

#[test]
fn c_conditional_token_splice_remains_incomplete_without_configuration_facts() {
    use bonsai_lang_api::AdapterArc;
    use bonsai_parser::{ParserCache, ParserOptions};
    use bonsai_vfs::Vfs;

    let source = r#"int choose(int left, int right) {
#if FIRST_CONFIGURATION
    if (left ||
#else
    if (right ||
#endif
        ready()) {
        consume(left);
    }
    return 0;
}
"#;
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("conditional_splice.c"), source);
    let adapter: AdapterArc = std::sync::Arc::new(bonsai_lang_c::CAdapter::new());
    let parsed = ParserCache::with_options(ParserOptions::with_parse_timeout(None))
        .parse(file, &adapter, &vfs)
        .expect("parse configuration-dependent token splice");

    assert!(
        parsed.tree.root_node().has_error(),
        "the frontend must not invent one OR expression from mutually exclusive token streams"
    );
    assert_eq!(parsed.source_text(), source);
}

#[test]
fn c_conditional_declaration_or_definition_remains_configuration_scoped() {
    use bonsai_lang_api::AdapterArc;
    use bonsai_parser::{ParserCache, ParserOptions};
    use bonsai_vfs::Vfs;

    let source = r#"void transform(int value)
#if EXTERNAL_IMPLEMENTATION
;
#else
{
    consume(value);
}
#endif
"#;
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("conditional_definition.c"), source);
    let adapter: AdapterArc = std::sync::Arc::new(bonsai_lang_c::CAdapter::new());
    let parsed = ParserCache::with_options(ParserOptions::with_parse_timeout(None))
        .parse(file, &adapter, &vfs)
        .expect("parse configuration-scoped declaration or definition");

    assert!(
        parsed.tree.root_node().has_error(),
        "one configuration's definition must not replace another configuration's declaration"
    );
    assert_eq!(parsed.source_text(), source);
}

#[test]
fn c_recovery_preserves_a_large_prefix_of_clean_callables() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterArc, AdapterContext, LanguageAdapter};
    use bonsai_parser::{ParserCache, ParserOptions};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let mut source = String::new();
    for index in 0..128 {
        source.push_str(&format!("int helper_{index}(int value) {{ return value; }}\n"));
    }
    source.push_str(
        r#"int validate(int required
#if WITH_OPTIONAL_CONTEXT
    , int optional
#endif
) {
    consume(required, optional);
    return required;
}
"#,
    );

    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("many_callables.c"), source.as_str());
    let adapter: AdapterArc = std::sync::Arc::new(bonsai_lang_c::CAdapter::new());
    let parsed = ParserCache::with_options(ParserOptions::with_parse_timeout(None))
        .parse(file, &adapter, &vfs)
        .expect("parse large branch-free recovery fixture");
    assert!(!parsed.tree.root_node().has_error());

    let provider = ExactTreeProvider(parsed.tree.clone());
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = bonsai_lang_c::CAdapter::new().extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: Some(&provider),
            workspace_root: None,
        },
    );
    for helper in 0..128 {
        assert!(
            index
                .defs
                .iter()
                .any(|decl| decl.name == format!("helper_{helper}")),
            "recovery displaced helper_{helper}"
        );
    }
    assert!(index.defs.iter().any(|decl| decl.name == "validate"));
    assert_eq!(parsed.source_text(), source);
}
