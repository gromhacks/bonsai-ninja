use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_rust::RustAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("a.rs", "fn main() { helper(); }\nfn helper() {}")]
    );
}

#[test]
fn chained_method_assignment_retains_the_parsed_receiver_base() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_rust::RustAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "pipelines.rs",
            r#"
struct Factory;
struct Product;
struct Html<T>(T);
impl Factory { fn constant() -> Product { Product } }
impl Product { fn finish(self) -> String { String::new() } }

fn render(values: Vec<String>) {
    let items = values.into_iter().map(|value| format!("<li>{value}</li>")).collect::<String>();
    let fixed = Factory::constant().finish();
    let _page = Html(format!("<ul>{items}</ul>"));
    consume(items, fixed);
}
fn consume(_: String, _: String) {}
"#,
        )],
    );
    let global = ws.db().global_index();
    let render = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "render")
        .expect("render declaration");
    let assignment_sources = |target: &str| {
        render.flow_events.iter().find_map(|event| match event {
            FlowEvent::Assign {
                target: observed,
                source_names,
                ..
            } if observed == target => Some(source_names.clone()),
            _ => None,
        })
    };
    assert_eq!(assignment_sources("items"), Some(vec!["values".to_string()]));
    assert!(
        render.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, receiver, .. }
                if name.ends_with(".collect") && receiver.as_deref() == Some("values")
        )),
        "the outer chained call must retain its addressable receiver"
    );
    assert!(
        assignment_sources("fixed").is_some_and(|sources| sources.iter().all(|source| source != "values")),
        "an independent static factory chain must not inherit the iterator receiver"
    );

    let (html_span, html_arg_sources) = render
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { span, name, args, .. } if name == "Html" => {
                Some((*span, args.first().map(|arg| arg.source_names.clone())))
            }
            _ => None,
        })
        .expect("Html constructor call");
    assert_eq!(html_arg_sources, Some(vec!["items".to_string()]));
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Rust compiler index");
    let html_value = index
        .call_argument_values
        .iter()
        .find(|fact| fact.call_span == html_span && fact.argument_index == 0)
        .expect("Html argument value fact");
    assert_eq!(
        html_value.direct_call_span, None,
        "format macro operands are syntax-propagated values, not an unresolved call return"
    );
}

#[test]
fn explicitly_typed_iife_result_types_the_following_method_receiver() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_rust::RustAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "result.rs",
            r#"
struct Local;
impl Local { fn unwrap_or_else<F>(self, _: F) -> String where F: FnOnce(()) -> String { String::new() } }

fn typed(input: String) -> String {
    (|| -> Result<String, ()> { Ok(input) })().unwrap_or_else(|_| String::new())
}

fn untyped(local: Local) -> String {
    local.unwrap_or_else(|_| String::new())
}
"#,
        )],
    );
    let global = ws.db().global_index();
    let typed = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "typed")
        .expect("typed declaration");
    let typed_receiver = typed.flow_events.iter().find_map(|event| match event {
        FlowEvent::Call {
            name, receiver_types, ..
        } if name.ends_with(".unwrap_or_else") => Some(receiver_types),
        _ => None,
    });
    assert!(
        typed_receiver.is_some_and(|types| types.iter().any(|type_name| type_name == "Result")),
        "the explicit closure return type must type the IIFE method receiver: {:?}",
        typed.flow_events
    );

    let untyped = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "untyped")
        .expect("untyped declaration");
    let untyped_receiver = untyped.flow_events.iter().find_map(|event| match event {
        FlowEvent::Call {
            name, receiver_types, ..
        } if name.ends_with(".unwrap_or_else") => Some(receiver_types),
        _ => None,
    });
    assert!(
        untyped_receiver.is_some_and(|types| {
            types.iter().any(|type_name| type_name == "Local")
                && types.iter().all(|type_name| type_name != "Result")
        }),
        "an ordinary same-named local method must retain only its declared receiver type: {:?}",
        untyped.flow_events
    );
}

#[test]
fn match_let_and_foreach_bindings_follow_rust_ast_roles() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_rust::RustAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "a.rs",
            r#"fn main(
    subject: Option<(String, usize)>,
    rows: Vec<(String, usize)>,
    mut stream: impl Iterator<Item = (String, usize)>,
) {
    if let Some((value, index)) = subject { sink(value, index); }
    match subject { Some((part, count)) => sink(part, count), None => (), }
    for (row, offset) in rows { sink(row, offset); }
    while let Some((next, position)) = stream.next() { sink(next, position); }
}"#,
        )],
    );
    let global = ws.db().global_index();
    let main = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "main")
        .expect("main declaration");
    let mut facts = Vec::new();
    collect_assignments(&main.flow_events, &mut facts);
    for (target, source) in [
        ("value", "subject"),
        ("index", "subject"),
        ("part", "subject"),
        ("count", "subject"),
        ("row", "rows"),
        ("offset", "rows"),
        ("next", "stream"),
        ("position", "stream"),
    ] {
        assert!(
            facts
                .iter()
                .any(|(actual, actual_source)| actual == target && actual_source.as_deref() == Some(source)),
            "missing {target} <- {source}: {facts:#?}"
        );
    }
    for non_binding in ["Some", "String", "usize"] {
        assert!(
            facts.iter().all(|(target, _)| target != non_binding),
            "type/constructor syntax became a binding: {non_binding}: {facts:#?}"
        );
    }

    fn collect_assignments(events: &[FlowEvent], out: &mut Vec<(String, Option<String>)>) {
        for event in events {
            match event {
                FlowEvent::Assign {
                    target,
                    source_name,
                    source_names,
                    ..
                } => out.push((
                    target.clone(),
                    source_name.clone().or_else(|| source_names.first().cloned()),
                )),
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    collect_assignments(then_events, out);
                    collect_assignments(else_events, out);
                }
                FlowEvent::Loop { body, .. } => collect_assignments(body, out),
                _ => {}
            }
        }
    }
}

#[test]
fn tuple_struct_extractor_parameter_binds_inner_value_and_wrapper_type() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_rust::RustAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "a.rs",
            r#"struct Query<T>(T);
struct Json<T>(T);
struct Path<T>(T);
struct Form<T>(T);
struct Extension<T>(T);
struct TypedHeader<T>(T);
async fn ping(
    Query(query): Query<String>,
    Json(json): Json<String>,
    Path(path): Path<String>,
    Form(form): Form<String>,
    Extension(extension): Extension<String>,
    TypedHeader(header): TypedHeader<String>,
) {
    consume(query, json, path, form, extension, header);
}
fn consume(_: String, _: String, _: String, _: String, _: String, _: String) {}"#,
        )],
    );
    let global = ws.db().global_index();
    let ping = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "ping")
        .expect("ping declaration");
    assert_eq!(
        ping.params,
        ["query", "json", "path", "form", "extension", "header"],
        "tuple-struct constructor syntax is not the parameter binding: {ping:#?}"
    );
    for (binding_name, wrapper_type) in [
        ("query", "Query"),
        ("json", "Json"),
        ("path", "Path"),
        ("form", "Form"),
        ("extension", "Extension"),
        ("header", "TypedHeader"),
    ] {
        assert!(
            ping.type_aliases
                .iter()
                .any(|binding| binding.name == binding_name && binding.type_name == wrapper_type),
            "inner binding {binding_name} must retain declared extractor wrapper {wrapper_type}: {ping:#?}"
        );
    }
}

#[test]
fn nested_destructured_parameter_types_reach_receiver_dispatch() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_rust::RustAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "routes.rs",
            r#"struct State<T>(T);
trait Gateway { fn get(&self, url: &str); }
async fn fetch(
    State(gateway): State<std::sync::Arc<dyn Gateway>>,
    url: String,
) {
    gateway.get(&url);
}"#,
        )],
    );
    let global = ws.db().global_index();
    let fetch = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "fetch")
        .expect("fetch declaration");
    for expected_type in ["State", "std.sync.Arc", "Gateway"] {
        assert!(
            fetch
                .type_aliases
                .iter()
                .any(|binding| { binding.name == "gateway" && binding.type_name == expected_type }),
            "nested declared type {expected_type} must remain attached to the inner binding: {fetch:#?}"
        );
    }
    let receiver_types = fetch
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call {
                receiver,
                receiver_types,
                ..
            } if receiver.as_deref() == Some("gateway") => Some(receiver_types),
            _ => None,
        })
        .expect("gateway receiver call");
    assert!(
        receiver_types.iter().any(|ty| ty == "Gateway"),
        "trait identity must reach exact receiver dispatch: {receiver_types:#?}"
    );
}

#[test]
fn chained_filter_call_retains_exact_receiver_and_callback_parameters() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_rust::RustAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "routes.rs",
            r#"
use std::collections::HashMap;
use warp::Filter;
fn route() {
    warp::path("run")
        .and(warp::query::<HashMap<String, String>>())
        .and_then(|query| async move { consume(query) });
}
fn consume<T>(_: T) {}
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Rust compiler index");
    let route = index
        .defs
        .iter()
        .find(|decl| decl.name == "route")
        .expect("route declaration");
    let (call_span, receiver) = route
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call {
                span,
                name,
                receiver: Some(receiver),
                ..
            } if name.ends_with(".and_then") => Some((*span, receiver)),
            _ => None,
        })
        .expect("and_then compiler call");
    assert!(
        receiver.contains("warp::query"),
        "exact receiver must retain filter composition: {receiver}"
    );
    let callback = index
        .call_argument_values
        .iter()
        .find(|fact| fact.call_span == call_span && fact.argument_index == 0)
        .expect("callback compiler argument fact");
    assert_eq!(callback.inline_callback_params, ["query"]);
    assert!(
        route.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, .. } if name == "warp::query"
        )),
        "generic instantiation syntax must not become part of callable identity: {:#?}",
        route.flow_events
    );
}

#[test]
fn direct_call_assignments_retain_adapter_decoded_static_arguments() {
    use bonsai_lang_api::StaticScalarValue;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_rust::RustAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "builder.rs",
            r##"
use std::process::Command;
fn configure() {
    let normal = Command::new("sh");
    let raw = Command::new(r#"bash"#);
    let escaped = Command::new("\u{73}\x68");
    let dynamic = Command::new(program());
}
fn program() -> &'static str { "echo" }
"##,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Rust compiler index");
    let static_args = |target: &str| {
        index
            .assignment_values
            .iter()
            .find(|fact| fact.target.as_deref() == Some(target))
            .map(|fact| fact.exact_static_call_args.clone())
    };

    for target in ["normal", "raw", "escaped"] {
        assert_eq!(
            static_args(target),
            Some(Some(vec![StaticScalarValue::String(
                if target == "raw" { "bash" } else { "sh" }.to_string()
            )])),
            "{target} must retain the exact runtime string value"
        );
    }
    assert_eq!(
        static_args("dynamic"),
        Some(None),
        "a dynamic factory argument must fail closed"
    );
}

#[test]
fn turbofish_arguments_never_become_local_types_but_explicit_annotations_do() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_rust::RustAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "types.rs",
            r#"
struct Payload;
struct Client;
fn factory<T>() -> Client { Client }
fn route() {
    let inferred = factory::<Payload>();
    let explicit: Client = factory::<Payload>();
    let cast = make() as Client;
    let nested = wrap(make() as Payload);
    consume(inferred, explicit, cast, nested);
}
fn make() -> usize { 0 }
fn wrap<T>(value: T) -> Client { let _ = value; Client }
fn consume(_: Client, _: Client, _: Client, _: Client) {}
"#,
        )],
    );
    let global = ws.db().global_index();
    let route = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "route")
        .expect("route declaration");
    assert!(
        route
            .type_aliases
            .iter()
            .any(|alias| alias.name == "inferred" && alias.type_name == "Client"),
        "an inferred local should use the compiler-resolved function return type: {route:#?}"
    );
    assert!(
        route
            .type_aliases
            .iter()
            .all(|alias| alias.name != "inferred" || alias.type_name != "Payload"),
        "a factory type argument is not the result binding's type: {route:#?}"
    );
    assert!(
        route
            .type_aliases
            .iter()
            .any(|alias| alias.name == "explicit" && alias.type_name == "Client"),
        "explicit local annotation must remain a receiver type: {route:#?}"
    );
    assert!(
        route
            .type_aliases
            .iter()
            .any(|alias| alias.name == "cast" && alias.type_name == "Client"),
        "an exact `as`-cast initializer must type its local receiver: {route:#?}"
    );
    assert!(
        route
            .type_aliases
            .iter()
            .all(|alias| alias.name != "nested" || alias.type_name != "Payload"),
        "a cast nested in a call argument must not mistype the call result: {route:#?}"
    );
}

#[test]
fn rust_reference_modifiers_never_become_receiver_type_identities() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_rust::RustAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "receivers.rs",
            r#"
use provider::inner::Client as ProviderClient;
use application::inner::Client as OtherClient;

struct LocalClient;
impl LocalClient { fn execute(&self) {} }

fn by_value(value: ProviderClient) { value.execute(); }
fn by_shared_ref(value: &ProviderClient) { value.execute(); }
fn by_mut_ref(value: &mut ProviderClient) { value.execute(); }
fn wrong_provider(value: &mut OtherClient) { value.execute(); }
fn local_type(value: &mut LocalClient) { value.execute(); }
"#,
        )],
    );
    let global = ws.db().global_index();
    let decl = |name: &str| {
        global
            .all_files()
            .flat_map(|file| global.decls_in(file))
            .find(|decl| decl.name == name)
            .unwrap_or_else(|| panic!("missing {name} declaration"))
    };
    let receiver_types = |name: &str| {
        decl(name)
            .flow_events
            .iter()
            .find_map(|event| match event {
                FlowEvent::Call { receiver_types, .. } => Some(receiver_types.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing {name} receiver call"))
    };

    for name in ["by_value", "by_shared_ref", "by_mut_ref"] {
        let types = receiver_types(name);
        assert!(
            types.iter().any(|ty| ty == "ProviderClient"),
            "{name}: {types:#?}"
        );
        assert!(
            types.iter().any(|ty| ty == "provider.inner.Client"),
            "{name}: {types:#?}"
        );
        assert!(
            types.iter().all(|ty| !ty.chars().any(char::is_whitespace)),
            "reference modifiers are not nominal receiver identities: {name}: {types:#?}"
        );
    }

    let wrong = receiver_types("wrong_provider");
    assert!(
        wrong.iter().any(|ty| ty == "application.inner.Client"),
        "{wrong:#?}"
    );
    assert!(wrong.iter().all(|ty| ty != "provider.inner.Client"), "{wrong:#?}");

    let local = receiver_types("local_type");
    assert!(local.iter().any(|ty| ty == "LocalClient"), "{local:#?}");
    assert!(
        local.iter().all(|ty| !ty.ends_with(".LocalClient")),
        "a local type must not acquire provider identity: {local:#?}"
    );
}

#[test]
fn exhaustive_literal_match_return_is_finite_and_dynamic_arm_fails_closed() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_rust::RustAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "selection.rs",
            r#"
fn finite(value: &str) -> &'static str {
    match value {
        "total" => "total",
        "created_at" => "created_at",
        _ => "id",
    }
}
fn dynamic<'a>(value: &'a str) -> &'a str {
    match value {
        "total" => "total",
        _ => value,
    }
}
fn execute(input: &str) {
    let rendered = format!("{}", finite(input));
    consume(rendered);
}
fn consume(_: String) {}
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Rust compiler index");
    let finite = index
        .defs
        .iter()
        .find(|decl| decl.name == "finite")
        .expect("finite helper");
    let dynamic = index
        .defs
        .iter()
        .find(|decl| decl.name == "dynamic")
        .expect("dynamic helper");

    assert!(
        index.finite_literal_selections.iter().any(|fact| {
            fact.selection_span.file == finite.span.file
                && finite.span.start <= fact.selection_span.start
                && fact.selection_span.end <= finite.span.end
        }),
        "an exhaustive match whose every arm returns a literal must emit a finite-return fact: {:#?}",
        index.finite_literal_selections
    );
    assert!(
        index.finite_literal_selections.iter().all(|fact| {
            fact.selection_span.file != dynamic.span.file
                || fact.selection_span.start < dynamic.span.start
                || dynamic.span.end < fact.selection_span.end
        }),
        "one dynamic arm must prevent finite-return evidence: {:#?}",
        index.finite_literal_selections
    );

    let execute = index
        .defs
        .iter()
        .find(|decl| decl.name == "execute")
        .expect("execute caller");
    let nested_call_span = execute
        .flow_events
        .iter()
        .find_map(|event| match event {
            bonsai_lang_api::FlowEvent::Call { span, name, .. } if name == "finite" => Some(*span),
            _ => None,
        })
        .expect("format macro nested call event");
    let rendered = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("rendered"))
        .expect("rendered assignment fact");
    assert!(
        rendered.call_sites.contains(&nested_call_span)
            && rendered.value_flow.call_sites.contains(&nested_call_span),
        "the exact nested call must remain linked to the macro-produced value: {rendered:#?}"
    );
}
