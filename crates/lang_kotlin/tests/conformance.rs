use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    run_language_suite!(adapter, trace_from = "main", [("a.kt", "fun main() {}")]);
}

#[test]
fn multiline_if_else_when_arm_recovers_without_changing_source_spans() {
    let source = r#"
sealed class Probe {
  data class Ping(val host: String) : Probe()
  object SelfCheck : Probe()
}
object Dispatcher {
  fun handle(p: Probe): String = when (p) {
    is Probe.Ping ->
      if (allowed(p.host)) run(listOf("ping", p.host))
      else ""
    Probe.SelfCheck -> run(listOf("ping", "localhost"))
  }
}
"#;
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())],
        &[("Probe.kt", source)],
    );
    let file = workspace.db().vfs().all_files()[0];
    let parsed = workspace.db().parse(file).expect("recovered Kotlin parse");
    assert!(
        !parsed.tree.root_node().has_error(),
        "{}",
        parsed.tree.root_node().to_sexp()
    );
    assert_eq!(
        parsed.source_text(),
        source,
        "recovery must not rewrite the source snapshot"
    );
    let index = workspace.db().decl_index(file).expect("Kotlin declaration index");
    let handle = index
        .defs
        .iter()
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");
    assert!(
        format!("{:?}", handle.flow_events).contains("run"),
        "the recovered arm body must remain compiler-visible: {:?}",
        handle.flow_events
    );
}

#[test]
fn unrelated_kotlin_damage_is_not_masked_by_when_recovery() {
    let source = r#"
fun broken(p: String): String = when (p) {
  "x" -> if (p.isEmpty()) "x"
  this is not valid Kotlin
}
"#;
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())],
        &[("Broken.kt", source)],
    );
    let file = workspace.db().vfs().all_files()[0];
    let parsed = workspace.db().parse(file).expect("damaged Kotlin parse result");
    assert!(
        parsed.tree.root_node().has_error(),
        "unrelated syntax damage must remain visible"
    );
}

#[test]
fn inline_callbacks_expose_only_complete_exact_scalar_returns() {
    use bonsai_lang_api::StaticScalarValue;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())],
        &[(
            "Callbacks.kt",
            r#"
fun consume(check: (Boolean) -> Boolean) {}
fun consumePair(check: (Boolean, Boolean) -> Boolean) {}
fun named(value: Boolean): Boolean = true
fun namedPair(left: Boolean, right: Boolean): Boolean = true
fun configure() {
  consume { value -> true }
  consume { value -> false }
  consume { value -> return@consume true }
  consume { value -> if (value) true else false }
  consume(::named)
  consumePair { left, right -> true }
  consumePair { left, right -> false }
  consumePair { left, right -> if (left) true else false }
  consumePair(::namedPair)
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let source = workspace.db().vfs().snapshot(file).expect("fixture source");
    let index = workspace.db().decl_index(file).expect("Kotlin compiler index");
    let callback_return = |needle: &str| {
        index
            .call_argument_values
            .iter()
            .find(|fact| {
                &source.text[fact.argument_span.start as usize..fact.argument_span.end as usize] == needle
            })
            .map(|fact| fact.inline_callback_static_return.clone())
    };

    assert_eq!(
        callback_return("{ value -> true }"),
        Some(Some(StaticScalarValue::Boolean(true)))
    );
    assert_eq!(
        callback_return("{ value -> false }"),
        Some(Some(StaticScalarValue::Boolean(false)))
    );
    assert_eq!(
        callback_return("{ value -> return@consume true }"),
        Some(None),
        "labelled returns require control-flow proof"
    );
    assert_eq!(
        callback_return("{ value -> if (value) true else false }"),
        Some(None)
    );
    assert_eq!(callback_return("::named"), Some(None));
    assert_eq!(
        callback_return("{ left, right -> true }"),
        Some(Some(StaticScalarValue::Boolean(true)))
    );
    assert_eq!(
        callback_return("{ left, right -> false }"),
        Some(Some(StaticScalarValue::Boolean(false)))
    );
    assert_eq!(
        callback_return("{ left, right -> if (left) true else false }"),
        Some(None)
    );
    assert_eq!(callback_return("::namedPair"), Some(None));
}

#[test]
fn shared_class_node_refines_interfaces_and_enums_without_constructors() {
    use bonsai_lang_api::DeclKind;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())],
        &[(
            "Kinds.kt",
            r#"
interface Handler { fun handle(value: String) }
enum class Mode { READ, WRITE }
class Service
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Kotlin compiler index");

    let kind = |name: &str| {
        index
            .defs
            .iter()
            .find(|decl| decl.name == name && !matches!(decl.kind, DeclKind::Constructor))
            .map(|decl| decl.kind)
            .unwrap_or_else(|| panic!("missing declaration {name}: {:#?}", index.defs))
    };
    assert_eq!(kind("Handler"), DeclKind::Interface);
    assert_eq!(kind("Mode"), DeclKind::Enum);
    assert_eq!(kind("Service"), DeclKind::Class);
    assert!(
        index
            .defs
            .iter()
            .all(|decl| !(decl.name == "Handler" && decl.kind == DeclKind::Constructor)),
        "interfaces must not acquire synthetic constructors: {:#?}",
        index.defs
    );
}

#[test]
fn interface_implementation_preserves_the_declared_base_identity() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())],
        &[(
            "Probe.kt",
            r#"
interface Probe { fun run(value: String): String }
class LiveProbe : Probe { override fun run(value: String): String = value }
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Kotlin compiler index");
    let implementation = index
        .defs
        .iter()
        .find(|decl| decl.name == "LiveProbe" && decl.kind == bonsai_lang_api::DeclKind::Class)
        .unwrap_or_else(|| panic!("missing implementation: {:#?}", index.defs));
    assert_eq!(implementation.bases, ["Probe"]);
}

#[test]
fn trailing_call_lambdas_retain_one_independent_callable_owner() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())],
        &[(
            "Routes.kt",
            r#"fun orderRoutes(repo: Repo) {
    route("/orders") {
        get {
            val query = call.request.queryParameters["q"] ?: ""
            repo.listOrders(query)
        }
    }
}"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let parsed = workspace.db().parse(file).expect("parse Kotlin route");
    let index = workspace.db().decl_index(file).expect("Kotlin compiler index");
    let order_routes = index
        .defs
        .iter()
        .find(|decl| decl.name == "orderRoutes")
        .expect("orderRoutes declaration");
    let outer_calls = order_routes
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        outer_calls.iter().all(|name| !name.ends_with("listOrders")),
        "a nested callback body must not leak into orderRoutes: {outer_calls:?}"
    );
    let lambdas = index
        .defs
        .iter()
        .filter(|decl| decl.name.starts_with("<lambda@"))
        .collect::<Vec<_>>();
    assert_eq!(
        lambdas.len(),
        2,
        "route and get each own exactly one lambda_literal; annotated_lambda wrappers must not duplicate them; \
         tree={}; decls={:#?}",
        parsed.tree.root_node().to_sexp(),
        index.defs
    );
    assert_eq!(
        lambdas
            .iter()
            .filter(|decl| {
                decl.flow_events.iter().any(
                    |event| matches!(event, FlowEvent::Call { name, .. } if name.ends_with("listOrders")),
                )
            })
            .count(),
        1,
        "the innermost callback alone must own listOrders: {lambdas:#?}"
    );
}

#[test]
fn navigation_calls_emit_exact_receiver_and_member_facts() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "App.kt",
            "fun example(stream: Stream) { stream.close(); stream.read() }",
        )],
    );
    let global = ws.db().global_index();
    let example = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "example")
        .expect("example declaration");
    let calls = example
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, receiver, .. } => Some((name.as_str(), receiver.as_deref())),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(calls.contains(&("stream.close", Some("stream"))), "{calls:?}");
    assert!(calls.contains(&("stream.read", Some("stream"))), "{calls:?}");
    assert!(calls.iter().all(|(name, _)| !name.contains("..")), "{calls:?}");
}

#[test]
fn explicit_nested_types_preserve_their_import_alias_path() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())],
        &[(
            "Qualified.kt",
            r#"
import external.client.Provider as RemoteProvider
fun configure(builder: RemoteProvider.Builder) { builder.configure() }
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Kotlin compiler index");
    let configure = index
        .defs
        .iter()
        .find(|decl| decl.name == "configure")
        .unwrap_or_else(|| panic!("missing configure declaration: {:#?}", index.defs));

    assert!(
        configure
            .type_aliases
            .iter()
            .any(|alias| { alias.name == "builder" && alias.type_name == "RemoteProvider.Builder" }),
        "explicit nested receiver type lost its import-qualified source identity: {:#?}",
        configure.type_aliases
    );
}

#[test]
fn nested_lambda_dispatch_uses_lexically_captured_receiver_type() {
    use bonsai_common::FuncId;
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())],
        &[
            (
                "Routes.kt",
                r#"
import io.ktor.server.application.*
import io.ktor.server.routing.*

fun orderRoutes(repo: OrderRepo) {
    route("/orders") {
        get {
            repo.listOrders("query")
        }
    }
}
"#,
            ),
            (
                "OrderRepo.kt",
                r#"
import java.sql.Connection

class OrderRepo(private val connection: Connection) {
    fun listOrders(query: String) {
        connection.createStatement().executeQuery("SELECT * FROM orders WHERE name = '$query'")
    }
}
"#,
            ),
        ],
    );
    let global = workspace.db().global_index();
    let nested = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| {
            decl.name.starts_with("<lambda@")
                && decl.flow_events.iter().any(|event| {
                    matches!(
                        event,
                        FlowEvent::Call {
                            name,
                            receiver: Some(receiver),
                            ..
                        } if name.ends_with("listOrders") && receiver == "repo"
                    )
                })
        })
        .unwrap_or_else(|| panic!("missing nested lambda call: {global:#?}"));
    let mut lexical = Vec::new();
    let mut parent = nested.parent;
    while let Some(symbol) = parent {
        let decl = global.decl_of(symbol).expect("lexical parent header");
        lexical.push((decl.name.clone(), decl.type_aliases.clone()));
        parent = decl.parent;
    }
    assert!(
        lexical.iter().any(|(_, aliases)| aliases
            .iter()
            .any(|alias| alias.name == "repo" && alias.type_name == "OrderRepo")),
        "captured receiver type is absent from the exact lexical parent chain: {lexical:#?}"
    );

    let graph = workspace.resolved_call_graph();
    let targets = graph
        .callees_of(FuncId::new(nested.symbol.raw()))
        .filter_map(|edge| graph.node_name(edge.to))
        .collect::<Vec<_>>();
    assert!(
        targets.contains(&"listOrders"),
        "captured typed receiver did not resolve to OrderRepo.listOrders; nested={nested:#?}; lexical={lexical:#?}; targets={targets:#?}"
    );
}

#[test]
fn nested_method_chain_receivers_join_their_semantic_call_spans() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())],
        &[(
            "App.kt",
            r#"fun flow(command: String) = command.trim().lowercase().repeat(2)"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Kotlin compiler index");
    let flow = index
        .defs
        .iter()
        .find(|decl| decl.name == "flow")
        .expect("flow declaration");
    let mut calls = flow
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call {
                span,
                name,
                receiver: Some(_),
                ..
            } if ["trim", "lowercase", "repeat"]
                .iter()
                .any(|method| bonsai_common::short_qualified_tail(name) == *method) =>
            {
                Some((*span, name.as_str()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    calls.sort_by_key(|(span, _)| span.end - span.start);
    assert_eq!(calls.len(), 3, "events={:#?}", flow.flow_events);

    for (index_in_chain, (span, name)) in calls.into_iter().enumerate() {
        let fact = index
            .call_receivers
            .iter()
            .find(|fact| fact.call_span == span)
            .unwrap_or_else(|| panic!("missing receiver fact for {name} at {span:?}"));
        if index_in_chain == 0 {
            assert_eq!(fact.value_flow.place.as_deref(), Some("command"));
        } else {
            assert!(
                !fact.value_flow.call_sites.is_empty(),
                "nested receiver for {name} must retain its inner semantic call: {fact:#?}"
            );
        }
    }
}

#[test]
fn when_expression_emits_only_complete_finite_literal_selections() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())],
        &[(
            "Selection.kt",
            r#"
fun selected(key: String) = when (key) {
  "first" -> "alpha"
  else -> "omega"
}
fun assigned(key: String) {
  val output = when (key) { "first" -> 1; else -> 2 }
  consume(output)
}
fun incomplete(key: String) = when (key) {
  "first" -> "alpha"
  else -> key
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Kotlin compiler index");

    assert_eq!(index.finite_literal_selections.len(), 2);
    assert!(index
        .finite_literal_selections
        .iter()
        .any(|fact| fact.assignment_span.is_none() && fact.target.is_none()));
    assert!(index
        .finite_literal_selections
        .iter()
        .any(|fact| fact.target.as_deref() == Some("output")));
}

#[test]
fn static_mapping_call_chains_retain_provider_identity_without_assigning_semantics() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())],
        &[(
            "Escape.kt",
            r#"
fun encode(value: String) = value
  .replace("&", "&amp;")
  .replace("<", "&lt;")
fun remap(value: String) = value.scrub("&", "and").scrub("<", "lt")
fun constant(value: String) = "fixed".replace("f", "F")
fun dynamic(value: String, replacement: String) = value.replace("<", replacement)
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Kotlin compiler index");
    let [encode_fact, remap_fact] = index.character_constraints.as_slice() else {
        panic!(
            "expected both complete parameter-rooted provider candidates: {:#?}",
            index.character_constraints
        );
    };
    let encode = index
        .defs
        .iter()
        .find(|decl| decl.name == "encode")
        .expect("encode declaration");
    assert_eq!(encode_fact.function_span, encode.span);
    assert_eq!(encode_fact.input_param_index, Some(0));
    assert_eq!(
        encode_fact.domain,
        bonsai_lang_api::CharacterConstraintDomain::ProviderBound {
            factory_call: String::new(),
            operation_call: "replace".to_string(),
            domain: Box::new(bonsai_lang_api::CharacterConstraintDomain::SubstitutesExact {
                mappings: vec![
                    bonsai_lang_api::StaticStringMapEntry {
                        key: "&".to_string(),
                        value: "&amp;".to_string(),
                    },
                    bonsai_lang_api::StaticStringMapEntry {
                        key: "<".to_string(),
                        value: "&lt;".to_string(),
                    },
                ],
            }),
        }
    );
    assert!(matches!(
        &remap_fact.domain,
        bonsai_lang_api::CharacterConstraintDomain::ProviderBound { operation_call, .. }
            if operation_call == "scrub"
    ));
    assert!(index.character_substitutions.is_empty());
}

#[test]
fn terminal_property_reads_are_exact_storage_projections_not_receiver_calls() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())],
        &[(
            "Accessors.kt",
            r#"
class PathLike(val canonicalFile: PathLike)
class File(parent: PathLike, child: String) {
  val canonicalFile: PathLike = parent
}
class Store(private val base: PathLike) {
  fun read(name: String): PathLike {
    val root = base.canonicalFile
    val target = File(root, name).canonicalFile
    val invoked = base.canonicalFile()
    val bare = canonicalFile
    return target
  }
  fun PathLike.canonicalFile(): PathLike = this
  val canonicalFile: PathLike = base
}
fun returnCanonical(file: PathLike): PathLike = file.canonicalFile
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let parsed = workspace.db().decl_index(file).expect("Kotlin compiler index");
    let read = parsed
        .defs
        .iter()
        .find(|decl| decl.name == "read")
        .expect("read declaration");
    let assignment = |target: &str| {
        read.flow_events
            .iter()
            .find_map(|event| match event {
                FlowEvent::Assign {
                    target: actual,
                    source_call,
                    source_names,
                    value_kind,
                    ..
                } if actual == target => Some((source_call.clone(), source_names.clone(), *value_kind)),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing assignment to {target}"))
    };

    assert_eq!(assignment("root").0, None);
    assert!(assignment("root")
        .1
        .iter()
        .any(|source| source == "base.canonicalFile"));
    assert!(
        assignment("root").1.iter().all(|source| source != "base"),
        "an exact field read must not collapse to its carrier receiver"
    );
    assert_eq!(
        assignment("root").2,
        Some(bonsai_lang_api::AssignValueKind::PropertyRead)
    );
    assert_eq!(assignment("target").0.as_deref(), Some("File"));
    assert_eq!(
        assignment("target").2,
        Some(bonsai_lang_api::AssignValueKind::PropertyRead),
        "the enclosing constructor call and terminal property read must remain distinct compiler facts"
    );
    assert_eq!(
        assignment("invoked").0.as_deref(),
        Some("base.canonicalFile"),
        "an explicit call must retain its ordinary call identity"
    );
    assert_eq!(
        assignment("bare").0.as_deref(),
        Some("this.canonicalFile"),
        "a parsed unqualified read of an owned property has the exact implicit receiver"
    );
    assert!(read
        .flow_events
        .iter()
        .any(|event| { matches!(event, FlowEvent::Call { name, .. } if name == "File") }));
    let return_canonical = parsed
        .defs
        .iter()
        .find(|decl| decl.name == "returnCanonical")
        .expect("returnCanonical declaration");
    assert!(
        return_canonical.flow_events.iter().all(|event| !matches!(
            event,
            FlowEvent::Call { name, .. } if name == "file.canonicalFile"
        )),
        "a field projection must not become an unresolved receiver call: {:#?}",
        return_canonical.flow_events
    );
    assert!(return_canonical.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Return { value_flow, .. }
            if value_flow.place.as_deref() == Some("file.canonicalFile")
                && value_flow.source_names == ["file.canonicalFile"]
    )));

    let target_value = parsed
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("target"))
        .expect("target assignment value");
    assert_eq!(target_value.direct_call_name.as_deref(), Some("File"));
    assert_eq!(target_value.direct_call_receiver, None);
    assert_eq!(target_value.value_flow.place, None);
    assert_eq!(target_value.value_flow.projection, None);
    assert_eq!(target_value.value_flow.source_names, ["canonicalFile"]);
    assert!(
        !target_value.call_sites.is_empty(),
        "the constructor receiver must be one exact parsed call: {target_value:#?}"
    );
}

#[test]
fn stored_property_sink_argument_does_not_emit_an_unresolved_getter_call() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())],
        &[(
            "Fields.kt",
            "class Carrier(var payload: String, var capacity: Int)\nfun read(c: Carrier) { sink(c.capacity) }\n",
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Kotlin compiler index");
    let read = index.defs.iter().find(|decl| decl.name == "read").expect("read");
    assert!(read.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Call { name, args, .. }
            if name == "sink"
                && args.first().and_then(|arg| arg.place.as_deref()) == Some("c.capacity")
    )));
    assert!(read
        .flow_events
        .iter()
        .all(|event| !matches!(event, FlowEvent::Call { name, .. } if name == "c.capacity")));
}

#[test]
fn string_templates_expose_only_parsed_interpolation_reads() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "App.kt",
            r#"
fun render(cmd: String, unrelated: String) {
  sink("prefix $cmd")
  sink("the words cmd and unrelated are literals")
}
fun sink(value: String) {}
"#,
        )],
    );
    let global = ws.db().global_index();
    let render = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "render")
        .expect("render declaration");
    let calls = render
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name == "sink" => Some(args),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(calls.len(), 2, "events={:#?}", render.flow_events);
    assert_eq!(calls[0][0].source_names, ["cmd"]);
    assert!(calls[0][0].source_names.iter().all(|name| name != "unrelated"));
    assert!(
        calls[1][0].source_names.is_empty(),
        "literal text is not an identifier read"
    );
}

#[test]
fn escaped_dollar_template_text_is_not_a_value_read() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Templates.kt",
            r#"
class Ping(val host: String)
fun render(p: Ping) {
  sink("literal ${'$'}{p.host}")
  sink("dynamic ${p.host}")
}
fun sink(value: String) {}
"#,
        )],
    );
    let global = ws.db().global_index();
    let render = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "render")
        .expect("render declaration");
    let args = render
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name == "sink" => args.first(),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(args.len(), 2, "events={:#?}", render.flow_events);
    assert!(
        args[0].source_names.is_empty(),
        "an escaped dollar emits literal text rather than a value read: {:?}",
        args[0]
    );
    assert_eq!(args[1].source_names, ["p.host"]);
}

#[test]
fn string_template_composition_preserves_places_and_literal_fallbacks() {
    use bonsai_lang_api::StringCompositionPart;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Url.kt",
            r##"
class Parsed(val host: String?, val path: String?)
fun rebuild(parsed: Parsed) {
  val target = "https://${parsed.host}${parsed.path ?: "/"}"
  consume(target)
}
"##,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let parsed = ws.db().parse(file).expect("parse Kotlin string template");
    let index = ws.db().decl_index(file).expect("Kotlin declaration index");
    let fact = index
        .string_compositions
        .iter()
        .find(|fact| fact.target.as_deref() == Some("target"))
        .unwrap_or_else(|| {
            panic!(
                "string template composition; tree={}; facts={:#?}",
                parsed.tree.root_node().to_sexp(),
                index.string_compositions
            )
        });
    assert_eq!(
        fact.parts,
        [
            StringCompositionPart::Literal {
                value: "https://".to_string()
            },
            StringCompositionPart::Place {
                place: "parsed.host".to_string()
            },
            StringCompositionPart::PlaceOrLiteral {
                place: "parsed.path".to_string(),
                fallback: "/".to_string()
            },
        ]
    );
}

#[test]
fn branch_conditions_lower_exact_equality_and_rule_owned_predicate_atoms() {
    use bonsai_lang_api::{ConditionEquality, ConditionExpressionFact};

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Guard.kt",
            r#"
fun guarded(parsed: Parsed, allowed: Set<String>) {
  if (parsed.scheme != "https") { throw IllegalArgumentException() }
  if (!allowed.contains(parsed.host)) { throw IllegalArgumentException() }
}
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Kotlin declaration index");
    assert_eq!(index.branch_conditions.len(), 2, "{:#?}", index.branch_conditions);
    assert!(matches!(
        index.branch_conditions[0].expression.as_ref(),
        Some(ConditionExpressionFact::Equality {
            relation: ConditionEquality::NotEqual,
            left,
            right,
            ..
        }) if left.value_flow.place.as_deref() == Some("parsed.scheme")
            && right.static_string.as_deref() == Some("https")
    ));
    assert!(matches!(
        index.branch_conditions[1].expression.as_ref(),
        Some(ConditionExpressionFact::Not { operand, .. })
            if matches!(operand.as_ref(), ConditionExpressionFact::Atom { .. })
    ));
}

#[test]
fn when_subject_declaration_binds_the_subject_expression() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "A.kt",
            "fun main(subject: String) { when (val value = subject) { else -> sink(value) } }\nfun sink(value: String) {}",
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
    assert!(
        facts
            .iter()
            .any(|(target, source)| target == "value" && source.as_deref() == Some("subject")),
        "missing value <- subject: {facts:#?}"
    );
    assert!(facts.iter().all(|(target, _)| target != "String"));

    fn collect_assignments(events: &[FlowEvent], out: &mut Vec<(String, Option<String>)>) {
        for event in events {
            match event {
                FlowEvent::Assign {
                    target, source_name, ..
                } => out.push((target.clone(), source_name.clone())),
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    collect_assignments(then_events, out);
                    collect_assignments(else_events, out);
                }
                _ => {}
            }
        }
    }
}

#[test]
fn jump_expression_lowering_distinguishes_throw_and_return() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "App.kt",
            r#"
fun handle(token: String) {
  try { throw RuntimeException(token) }
  catch (e: Exception) { sink(e.message ?: "") }
}
fun identity(value: String): String { return value }
fun sink(value: String) {}
"#,
        )],
    );
    let global = ws.db().global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");
    let body = handle.flow_events.iter().find_map(|event| match event {
        FlowEvent::Try { body, .. } => Some(body),
        _ => None,
    });
    assert!(
        body.is_some_and(|body| body.iter().any(
            |event| matches!(event, FlowEvent::Throw { value_name: Some(value), .. } if value == "token")
        )),
        "Kotlin throw payload was not lowered from the parsed jump expression: {:#?}",
        handle.flow_events
    );

    let identity = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "identity")
        .expect("identity declaration");
    assert!(identity
        .flow_events
        .iter()
        .any(|event| matches!(event, FlowEvent::Return { value_name: Some(value), .. } if value == "value")));
}

#[test]
fn annotated_parameters_bind_annotation_to_value_name() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "App.kt",
            r#"
import javax.ws.rs.MatrixParam

class App {
  fun handle(@MatrixParam("id") value: String, stmt: Statement) {
    stmt.executeQuery(value)
  }
  fun ordinary(MatrixParam: String) {}
}
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }

    let global = ws.db().global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");

    assert_eq!(handle.params, ["value", "stmt"]);
    assert_eq!(handle.param_annotations.len(), handle.params.len());
    assert_eq!(handle.param_annotations[0], ["MatrixParam"]);
    assert!(handle.param_annotations[1].is_empty());

    let ordinary = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "ordinary")
        .expect("ordinary declaration");
    assert_eq!(ordinary.params, ["MatrixParam"]);
    assert_eq!(ordinary.param_annotations, [Vec::<String>::new()]);
}

#[test]
fn custom_getter_qualifies_constructor_property_as_receiver_state() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Storage.kt",
            r#"
data class Envelope(val cmd: String)

abstract class BaseRepository(val data: Envelope) {
  open val cmd: String get() = data.cmd
}
"#,
        )],
    );
    let global = ws.db().global_index();
    let getter = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "cmd" && decl.params.is_empty())
        .expect("custom property getter");
    let value_flow = getter
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Return { value_flow, .. } => Some(value_flow),
            _ => None,
        })
        .expect("getter return flow");
    assert_eq!(value_flow.place.as_deref(), Some("this.data.cmd"));
    assert_eq!(
        value_flow
            .projection
            .as_ref()
            .map(|projection| (projection.base.as_str(), projection.path.as_slice())),
        Some(("this", ["data".to_string(), "cmd".to_string()].as_slice()))
    );
    assert_eq!(value_flow.source_names, ["this.data.cmd"]);
}

#[test]
fn primary_constructor_records_only_exact_parameter_to_field_state() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Packet.kt",
            "data class Packet(val payload: String)\nclass Empty\n",
        )],
    );
    let global = ws.db().global_index();
    let packet = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Packet" && decl.kind == bonsai_lang_api::DeclKind::Constructor)
        .expect("Packet primary constructor");
    assert!(
        packet
            .receiver_field_writes
            .iter()
            .any(|write| { write.target == "this.payload" && write.source_param_indices == [0] }),
        "constructor must retain its exact parameter-to-field write: {:#?}",
        packet.receiver_field_writes
    );
    assert!(
        packet
            .flow_events
            .iter()
            .all(|event| !matches!(event, FlowEvent::Return { .. })),
        "constructor arguments initialize selected fields; they do not taint the whole allocation"
    );

    let empty = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Empty" && decl.kind == bonsai_lang_api::DeclKind::Constructor)
        .expect("Empty implicit constructor");
    assert!(
        empty
            .flow_events
            .iter()
            .all(|event| !matches!(event, FlowEvent::Return { .. })),
        "a zero-argument constructor must not invent parameter flow"
    );
}

#[test]
fn primary_constructor_delegation_is_an_exact_constructor_call() {
    use bonsai_lang_api::{CallKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Storage.kt",
            r#"
open class Base(val data: String)
class Child(data: String) : Base(data)
"#,
        )],
    );
    let global = ws.db().global_index();
    let child = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Child" && matches!(decl.kind, bonsai_lang_api::DeclKind::Constructor))
        .expect("Child primary constructor");
    assert!(
        child.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                call_kind: CallKind::Constructor,
                args,
                ..
            } if name == "Base"
                && args.first().and_then(|arg| arg.place.as_deref()) == Some("data")
        )),
        "base delegation must come from constructor_invocation syntax: {:#?}",
        child.flow_events
    );
}

#[test]
fn secondary_constructor_delegation_is_exact_and_precedes_its_body() {
    use bonsai_lang_api::{CallKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Storage.kt",
            r#"
open class Base(val value: String)

class Child(val value: String) : Base(value) {
  constructor(value: String, marker: Int) : this(value) { record(marker) }
}

class Direct : Base {
  private val ready = prepare()
  constructor(value: String) : super(value) { record(value) }
}

class Outer {
  class Nested(val value: String) {
    constructor() : this("")
  }
}
"#,
        )],
    );
    let global = ws.db().global_index();
    let constructors = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .filter(|decl| decl.kind == bonsai_lang_api::DeclKind::Constructor)
        .collect::<Vec<_>>();

    let child = constructors
        .iter()
        .copied()
        .find(|decl| decl.name == "Child" && decl.params.len() == 2)
        .expect("Child secondary constructor");
    assert!(matches!(
        child.flow_events.first(),
        Some(FlowEvent::Call {
            name,
            receiver: None,
            call_kind: CallKind::Constructor,
            args,
            ..
        }) if name == "Child"
            && args.first().and_then(|arg| arg.place.as_deref()) == Some("value")
    ));
    assert!(child
        .flow_events
        .iter()
        .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "record")));

    let direct = constructors
        .iter()
        .copied()
        .find(|decl| decl.name == "Direct" && decl.params.len() == 1)
        .expect("Direct secondary constructor");
    assert_eq!(
        constructors.iter().filter(|decl| decl.name == "Direct").count(),
        1,
        "a class with only secondary constructors has no implicit primary constructor"
    );
    assert!(matches!(
        direct.flow_events.first(),
        Some(FlowEvent::Call {
            name,
            receiver: Some(receiver),
            call_kind: CallKind::Constructor,
            args,
            ..
        }) if name == "super"
            && receiver == "super"
            && args.first().and_then(|arg| arg.place.as_deref()) == Some("value")
    ));
    let direct_calls = direct
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(direct_calls, ["super", "prepare", "record"]);

    assert_eq!(
        constructors.iter().filter(|decl| decl.name == "Outer").count(),
        1,
        "nested secondary constructors must not attach to their outer class"
    );
    assert_eq!(
        constructors.iter().filter(|decl| decl.name == "Nested").count(),
        2,
        "nested class owns its primary and secondary constructors"
    );
}

#[test]
fn property_declarations_use_declared_property_name_not_modifier() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Storage.kt",
            r#"
abstract class BaseRepository(val data: Envelope) {
  private val state: RepoState = RepoState.Active
  init { activate(state) }
  open val cmd: String get() = data.cmd
  fun ignored() { deactivate(state) }
}
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }

    let global = ws.db().global_index();
    let constructor = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "BaseRepository" && !decl.params.is_empty())
        .expect("synthetic BaseRepository constructor");

    let targets = constructor
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign { target, .. } => Some(target.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(targets.contains(&"this.state"));
    assert!(
        !targets.iter().any(|target| target.ends_with("cmd")),
        "a computed getter is not primary-constructor execution: {targets:?}"
    );
    assert!(!targets.contains(&"private"));
    assert!(!targets.contains(&"open"));

    let calls = constructor
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(calls.contains(&"activate"), "init blocks execute: {calls:?}");
    assert!(
        !calls.contains(&"deactivate"),
        "sibling method bodies do not execute during construction: {calls:?}"
    );
}

#[test]
fn constructor_classification_uses_declarations_not_capitalization() {
    use bonsai_lang_api::{CallKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "App.kt",
            r#"
import java.io.File

fun Factory(input: String): String = input
class lower

fun handle(input: String) {
  val f = File("/data", input)
  val text: String = Factory(input)
  val local = lower()
  f.readText()
  local.toString()
}
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }

    let global = ws.db().global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");
    let calls = handle
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, call_kind, .. } => Some((name.as_str(), *call_kind)),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(calls.contains(&("File", CallKind::Function)), "{calls:?}");
    assert!(calls.contains(&("Factory", CallKind::Function)), "{calls:?}");
    assert!(calls.contains(&("lower", CallKind::Constructor)), "{calls:?}");
}

#[test]
fn implicit_primary_constructor_owns_class_property_initializers() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[
            ("Dependency.kt", "package sample\nclass lower\n"),
            (
                "Owner.kt",
                r#"
package sample
class Owner {
  private val dependency = lower()
  fun run() { dependency.work() }
}
"#,
            ),
        ],
    );
    let global = ws.db().global_index();
    let constructor = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Owner" && decl.kind == bonsai_lang_api::DeclKind::Constructor)
        .expect("implicit Owner constructor");
    assert!(
        constructor.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_call: Some(source_call),
                ..
            } if target == "this.dependency" && source_call == "lower"
        )),
        "class property initializer must be receiver-qualified compiler IR: {:#?}",
        constructor.flow_events
    );
}
