use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_scala::ScalaAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("a.scala", "object A { def main(args: Array[String]): Unit = () }")]
    );
}

#[test]
fn repeated_parameter_type_marks_the_callable_variadic_without_changing_bindings() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "App.scala",
            "object App { def publish(topic: String, values: String*): Unit = consume(topic, values) }",
        )],
    );
    let global = workspace.db().global_index();
    let publish = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "publish")
        .expect("publish declaration");
    assert_eq!(publish.params, ["topic", "values"]);
    assert!(
        publish.is_variadic,
        "Scala's parsed repeated_parameter_type must mark the callable variadic: {publish:#?}"
    );
}

#[test]
fn concrete_stored_property_has_one_compiler_getter_with_exact_field_return() {
    use bonsai_lang_api::{DeclKind, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "Stored.scala",
            r#"
class Record {
  var value: String = ""
  def read(): String = this.value
}
trait Contract { var value: String }
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Scala declaration index");
    let record = index
        .defs
        .iter()
        .find(|decl| decl.name == "Record" && decl.kind == DeclKind::Class)
        .expect("Record class");
    let getters = index
        .defs
        .iter()
        .filter(|decl| {
            decl.parent == Some(record.symbol)
                && decl.name == "value"
                && decl.params.is_empty()
                && decl.kind == DeclKind::Method
        })
        .collect::<Vec<_>>();
    assert_eq!(
        getters.len(),
        1,
        "stored property must own one getter: {:#?}",
        index.defs
    );
    assert!(getters[0].flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Return { value_flow, .. }
            if value_flow.place.as_deref() == Some("this.value")
    )));
    let contract = index
        .defs
        .iter()
        .find(|decl| decl.name == "Contract" && decl.kind == DeclKind::Trait)
        .expect("Contract trait");
    assert!(
        index.defs.iter().all(|decl| {
            decl.parent != Some(contract.symbol)
                || decl.name != "value"
                || !decl.flow_events.iter().any(|event| {
                    matches!(
                        event,
                        FlowEvent::Return { value_flow, .. }
                            if value_flow.place.as_deref() == Some("this.value")
                    )
                })
        }),
        "an abstract trait member must not invent concrete stored state"
    );
}

#[test]
fn as_instance_of_types_only_the_direct_local_initializer() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "App.scala",
            r#"
import provider.api.Client
class App {
  def make(): Any = ???
  def wrap(value: Any): Any = value
  def run(input: String): Unit = {
    val typed = make().asInstanceOf[Client]
    val unrelated = wrap(make().asInstanceOf[Client])
    typed.send(input)
    unrelated.send(input)
  }
}
"#,
        )],
    );
    let global = workspace.db().global_index();
    let run = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "run")
        .expect("run declaration");

    assert!(run
        .type_aliases
        .iter()
        .any(|alias| alias.name == "typed" && alias.type_name == "Client"));
    assert!(
        run.type_aliases
            .iter()
            .all(|alias| alias.name != "unrelated" || alias.type_name != "Client"),
        "a cast nested inside another call must not give that call's result the cast type: {:?}",
        run.type_aliases
    );
    let receiver_types = run
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call {
                receiver,
                receiver_types,
                ..
            } => receiver.as_deref().map(|receiver| (receiver, receiver_types)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(receiver_types
        .iter()
        .any(|(receiver, types)| *receiver == "typed" && types.iter().any(|ty| ty == "Client")));
    assert!(receiver_types
        .iter()
        .any(|(receiver, types)| *receiver == "unrelated" && types.iter().all(|ty| ty != "Client")));
}

#[test]
fn match_case_binding_uses_the_match_subject_not_type_syntax() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_scala::ScalaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "A.scala",
            "object A { def main(args: String) = args match { case value: String => sink(value) } }",
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
            .any(|(target, source)| target == "value" && source.as_deref() == Some("args")),
        "missing value <- args: {facts:#?}"
    );
    assert!(
        facts.iter().all(|(target, _)| target != "String"),
        "type syntax became a binding: {facts:#?}"
    );
    assert!(
        main.flow_events.iter().any(|event| match event {
            FlowEvent::Branch { then_events, .. } => then_events
                .iter()
                .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "sink")),
            _ => false,
        }),
        "an evaluated match arm must retain its exact executable body: {:#?}",
        main.flow_events
    );

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
fn match_expression_emits_only_complete_finite_literal_selections() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "Selection.scala",
            r#"
object Selection {
  def selected(key: String): String = key match {
    case "first" => "alpha"
    case _ => "omega"
  }
  def assigned(key: String): Unit = {
    val output = key match { case "first" => 1; case _ => 2 }
    consume(output)
  }
  def incomplete(key: String): String = key match {
    case "first" => "alpha"
    case _ => key
  }
  def multiStatement(key: String): String = key match {
    case "first" => val value = "alpha"; value
    case _ => "omega"
  }
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Scala compiler index");

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
fn guarded_match_arm_retains_exact_boolean_condition_on_its_branch() {
    use bonsai_lang_api::{ConditionExpressionFact, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "Guarded.scala",
            r#"
import java.net.URI
import scala.util.Try
object Guarded {
  private val allowed = Set("api.example.test")
  def fetch(raw: String): Unit = {
    val parsed = Try(new URI(raw)).toOption
    parsed match {
      case Some(uri) if uri.getScheme == "https" && allowed.contains(uri.getHost) =>
        consume(raw)
      case _ => ()
    }
  }
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Scala compiler index");
    let fetch = index
        .defs
        .iter()
        .find(|decl| decl.name == "fetch")
        .expect("fetch declaration");
    let mut arm_spans = Vec::new();
    fn collect(events: &[FlowEvent], spans: &mut Vec<bonsai_common::Span>) {
        for event in events {
            if let FlowEvent::Branch {
                span,
                then_events,
                else_events,
                ..
            } = event
            {
                if then_events
                    .iter()
                    .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "consume"))
                {
                    spans.push(*span);
                }
                collect(then_events, spans);
                collect(else_events, spans);
            }
        }
    }
    collect(&fetch.flow_events, &mut arm_spans);
    assert_eq!(arm_spans.len(), 1, "events={:#?}", fetch.flow_events);
    let fact = index
        .branch_conditions
        .iter()
        .find(|fact| fact.branch_span == arm_spans[0])
        .unwrap_or_else(|| {
            panic!(
                "guard condition must key the exact arm branch: arms={arm_spans:#?}, facts={:#?}",
                index.branch_conditions
            )
        });
    assert!(
        matches!(fact.expression, Some(ConditionExpressionFact::All { ref operands, .. }) if operands.len() == 2),
        "guard conjunction must remain structured: {fact:#?}"
    );
}

#[test]
fn constructor_throw_carries_its_dynamic_payload_into_the_catch() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_scala::ScalaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "App.scala",
            "object App { def handle(token: String): Unit = { try { throw new RuntimeException(token) } catch { case e: Exception => sink(e.getMessage) } }; def sink(s: String): Unit = {} }",
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
        "Scala throw payload was not lowered from the parsed throw expression: {:#?}",
        handle.flow_events
    );
}

#[test]
fn instance_expression_emits_the_exact_constructor_identity() {
    use bonsai_lang_api::{CallKind, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "App.scala",
            "object App { def handle(input: String): Unit = { new X509TrustManager(input) } }; class X509TrustManager(args: Any*)",
        )],
    );
    let global = workspace.db().global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");

    assert!(
        handle.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, call_kind: CallKind::Constructor, args, .. }
                if name == "X509TrustManager"
                    && args.first().is_some_and(|arg| arg.value_text == "input")
        )),
        "events={:#?}",
        handle.flow_events
    );
}

#[test]
fn curried_call_retains_outer_callback_parameters_and_distinct_call_span() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "App.scala",
            r#"
import akka.http.scaladsl.server.Directives._
object App {
  def route = parameters("q", "page") { (q, page) => complete(q + page) }
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Scala compiler index");
    let route = index
        .defs
        .iter()
        .find(|decl| decl.name == "route")
        .expect("route declaration");
    let calls = route
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { span, name, args, .. } if name == "parameters" => Some((*span, args)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        calls.len(),
        2,
        "inner and outer curried calls: {:#?}",
        route.flow_events
    );
    assert_ne!(
        calls[0].0, calls[1].0,
        "curried call sites require distinct compiler spans"
    );
    let outer = calls
        .iter()
        .find(|(_, args)| args.len() == 1 && args[0].value_text.contains("=>"))
        .expect("outer callback parameter list");
    let callback = index
        .call_argument_values
        .iter()
        .find(|fact| fact.call_span == outer.0 && fact.argument_index == 0)
        .expect("callback argument value fact");
    assert_eq!(callback.inline_callback_params, ["q", "page"]);
}

#[test]
fn partial_function_argument_exposes_only_capture_bindings_as_callback_parameters() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "App.scala",
            r#"
import org.http4s._
import org.http4s.dsl.io._
object App {
  val routes = HttpRoutes.of[IO] {
    case request @ GET -> Root / "run" => consume(request)
  }
  def consume(value: Any): Unit = ()
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Scala compiler index");
    let call_span = index
        .defs
        .iter()
        .flat_map(|decl| decl.flow_events.iter())
        .find_map(|event| match event {
            FlowEvent::Call { span, name, .. } if name == "HttpRoutes.of" => Some(*span),
            _ => None,
        })
        .expect("generic partial-function call");
    let callback = index
        .call_argument_values
        .iter()
        .find(|fact| fact.call_span == call_span && fact.argument_index == 0)
        .expect("partial-function compiler argument fact");
    assert_eq!(callback.inline_callback_params, ["request"]);
    let callable = index
        .defs
        .iter()
        .find(|decl| decl.span == callback.argument_span && decl.name.starts_with("<lambda@"))
        .unwrap_or_else(|| panic!("partial-function callable declaration: {:#?}", index.defs));
    assert_eq!(callable.params, ["request"]);
    let owner = index
        .defs
        .iter()
        .find(|decl| {
            decl.flow_events
                .iter()
                .any(|event| matches!(event, FlowEvent::Call { span, .. } if *span == callback.call_span))
        })
        .expect("partial-function call owner");
    assert!(
        owner
            .flow_events
            .iter()
            .all(|event| !matches!(event, FlowEvent::Call { name, .. } if name == "consume")),
        "a PartialFunction argument is a dormant callable, not an eagerly executed match arm: {:#?}",
        owner.flow_events
    );
    let graph = workspace.resolved_call_graph();
    let relations = graph
        .callable_argument_records()
        .iter()
        .filter(|relation| {
            relation.caller.raw() == owner.symbol.raw() && relation.target.raw() == callable.symbol.raw()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        relations.len(),
        1,
        "the callgraph must retain the exact partial-function argument relation: {:#?}",
        graph.callable_argument_records()
    );
    assert_eq!(relations[0].span, callback.argument_span);
    assert!(
        !callback
            .inline_callback_params
            .iter()
            .any(|name| name == "GET" || name == "Root"),
        "extractor identities are syntax, not callback bindings: {callback:#?}"
    );
}

#[test]
fn catch_case_block_executes_in_try_scope_and_retains_its_exact_binding() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "App.scala",
            r#"
object App {
  def entry(args: String): Unit = {
    try { throw new RuntimeException(args) }
    catch { case error: Exception => sink(error) }
  }
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Scala compiler index");
    let entry = index
        .defs
        .iter()
        .find(|decl| decl.name == "entry")
        .expect("entry declaration");
    let try_event = entry
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Try {
                catch_events,
                catch_arms,
                ..
            } => Some((catch_events, catch_arms)),
            _ => None,
        })
        .expect("compiler-owned try event");
    assert_eq!(try_event.1.len(), 1, "exact catch arm: {:#?}", entry.flow_events);
    assert_eq!(try_event.1[0].parameter.as_deref(), Some("error"));
    assert!(
        try_event
            .0
            .iter()
            .any(|event| matches!(event, FlowEvent::Call { name, args, .. }
                if name == "sink" && args.iter().any(|arg| arg.place.as_deref() == Some("error")))),
        "catch handler calls must execute in the enclosing try scope: {:#?}",
        entry.flow_events
    );
}

#[test]
fn template_initializers_are_lowered_once_without_entering_method_bodies() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "App.scala",
            r#"
class ClassRoutes {
  val classRoute = source("class")
  def deferred = source("method")
}
trait TraitRoutes {
  val traitRoute = source("trait")
}
object ObjectRoutes {
  val objectRoute = source("object")
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Scala compiler index");
    let initializers = index
        .defs
        .iter()
        .filter(|decl| decl.name.starts_with("<template-init@"))
        .collect::<Vec<_>>();
    assert_eq!(
        initializers.len(),
        3,
        "each Scala template owns one exact initializer callable: {:#?}",
        index.defs
    );
    let values = initializers
        .iter()
        .flat_map(|decl| decl.flow_events.iter())
        .filter_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name == "source" => {
                args.first().map(|arg| arg.value_text.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(values, ["\"class\"", "\"trait\"", "\"object\""]);
    assert!(
        values.iter().all(|value| value != "\"method\""),
        "method bodies remain owned by their method declaration"
    );
}

#[test]
fn postfix_operator_call_keeps_its_value_receiver_flow() {
    use bonsai_lang_api::{AssignValueKind, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "App.scala",
            r#"
object App {
  def run(command: String, unrelated: String): Unit = {
    val fullCommand = s"notify $command"
    fullCommand.!
  }
}
"#,
        )],
    );
    let file = workspace
        .db()
        .vfs()
        .all_files()
        .into_iter()
        .next()
        .expect("Scala file");
    let index = workspace.db().decl_index(file).expect("Scala compiler index");
    let run = index
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run declaration");
    let call_span = run
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                args,
                ..
            } if name == "fullCommand.!" && receiver.as_deref() == Some("fullCommand") && args.is_empty() => {
                Some(*span)
            }
            _ => None,
        })
        .expect("postfix operator call");
    assert!(
        run.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_names,
                value_kind: Some(AssignValueKind::Compound),
                ..
            } if target == "fullCommand"
                && source_names.iter().any(|name| name == "command")
                && source_names.iter().all(|name| name != "unrelated")
        )),
        "interpolated assignment must remain data-dependent: {:#?}",
        run.flow_events
    );
    let fact = index
        .call_receivers
        .iter()
        .find(|fact| fact.call_span == call_span)
        .expect("postfix receiver fact must join the semantic call span");

    assert_eq!(fact.value_flow.place.as_deref(), Some("fullCommand"));
    assert_eq!(fact.value_flow.source_names, ["fullCommand"]);
    assert!(fact
        .value_flow
        .source_names
        .iter()
        .all(|name| name != "unrelated"));
}

#[test]
fn operator_calls_follow_scala_precedence_and_right_associativity() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "App.scala",
            r#"
object App {
  def precedence(a: Int, b: Int, c: Int): Int = a + b * c
  def association(a: List[Int], b: List[Int], c: List[Int]): List[Int] = a :: b :: c
}
"#,
        )],
    );
    let global = workspace.db().global_index();

    let call_args = |decl_name: &str, operator: &str| {
        let decl = global
            .all_files()
            .flat_map(|file| global.decls_in(file))
            .find(|decl| decl.name == decl_name)
            .unwrap_or_else(|| panic!("missing {decl_name} declaration"));
        decl.flow_events
            .iter()
            .filter_map(|event| match event {
                FlowEvent::Call { name, args, .. } if name == operator => {
                    Some(args.iter().map(|arg| arg.value_text.clone()).collect::<Vec<_>>())
                }
                _ => None,
            })
            .collect::<Vec<_>>()
    };

    assert_eq!(call_args("precedence", "+"), [["a", "b * c"]]);
    assert_eq!(
        call_args("association", "::"),
        [["b", "c"], ["a", "b :: c"]],
        "right-associated operands evaluate from the inner expression outward"
    );
}

#[test]
fn declared_types_and_constructor_results_do_not_cross_value_boundaries() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "App.scala",
            r#"
object App {
  def route = Action { request =>
    val explicit: Builder = make()
    val direct = new Outer(new Inner())
    val parsed = parser.parse(new InputSource(request.body.toString))
    request.body
  }

  def withDefault(value: Any = new DefaultType()): Any = value
}
"#,
        )],
    );
    let global = workspace.db().global_index();
    let route = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "route")
        .expect("route declaration");
    let callback = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.parent == Some(route.symbol) && decl.name.starts_with("<lambda@"))
        .expect("Action callback declaration");
    let type_of = |name: &str| {
        callback
            .type_aliases
            .iter()
            .find(|alias| alias.name == name)
            .map(|alias| alias.type_name.as_str())
    };
    assert_eq!(type_of("explicit"), Some("Builder"));
    assert_eq!(type_of("direct"), Some("Outer"));
    assert_eq!(
        type_of("request"),
        None,
        "an untyped callback parameter must stay untyped"
    );
    assert_eq!(
        type_of("parsed"),
        None,
        "a constructor nested in a call argument is not the call result type"
    );
    assert!(
        route.type_aliases.is_empty(),
        "callback-local receiver types must not leak into the enclosing method"
    );

    let with_default = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "withDefault")
        .expect("withDefault declaration");
    assert!(with_default
        .type_aliases
        .iter()
        .any(|alias| alias.name == "value" && alias.type_name == "Any"));
    assert!(with_default
        .type_aliases
        .iter()
        .all(|alias| alias.type_name != "DefaultType"));
}

#[test]
fn nested_declared_receiver_types_retain_exact_import_provider_identity() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[
            (
                "Exact.scala",
                r#"
import provider.api.Client
object Exact {
  def configure(builder: Client.Builder): Unit = builder.configure()
}
"#,
            ),
            (
                "Wrong.scala",
                r#"
import application.api.Client
object Wrong {
  def configureWrong(builder: Client.Builder): Unit = builder.configure()
}
"#,
            ),
            (
                "Local.scala",
                r#"
class Builder { def configure(): Unit = () }
object Local {
  def configureLocal(builder: Builder): Unit = builder.configure()
}
"#,
            ),
            (
                "Ambiguous.scala",
                r#"
import provider.api.Client as SharedClient
import application.api.Client as SharedClient
object Ambiguous {
  def configureAmbiguous(builder: SharedClient.Builder): Unit = builder.configure()
}
"#,
            ),
        ],
    );
    let global = workspace.db().global_index();
    let declaration = |name: &str| {
        global
            .all_files()
            .flat_map(|file| global.decls_in(file))
            .find(|decl| decl.name == name)
            .unwrap_or_else(|| panic!("missing {name} declaration"))
    };
    let receiver_types = |name: &str, binding: &str| {
        declaration(name)
            .type_aliases
            .iter()
            .filter(|alias| alias.name == binding)
            .map(|alias| alias.type_name.clone())
            .collect::<Vec<_>>()
    };

    let exact = receiver_types("configure", "builder");
    assert!(
        exact.contains(&"Builder".to_string()),
        "missing terminal type: {exact:#?}"
    );
    assert!(
        exact.contains(&"Client.Builder".to_string()),
        "missing complete source type: {exact:#?}"
    );
    assert!(
        exact.contains(&"provider.api.Client.Builder".to_string()),
        "missing exact imported provider identity: {exact:#?}"
    );

    let wrong = receiver_types("configureWrong", "builder");
    assert!(wrong.contains(&"application.api.Client.Builder".to_string()));
    assert!(
        !wrong.contains(&"provider.api.Client.Builder".to_string()),
        "same terminal type from another provider crossed identity: {wrong:#?}"
    );

    let local = receiver_types("configureLocal", "builder");
    assert!(local.contains(&"Builder".to_string()));
    assert!(
        local.iter().all(|type_name| !type_name.contains("provider.api")),
        "local type acquired an external provider: {local:#?}"
    );

    let ambiguous = receiver_types("configureAmbiguous", "builder");
    assert!(ambiguous.contains(&"SharedClient.Builder".to_string()));
    assert!(
        ambiguous
            .iter()
            .all(|type_name| !type_name.starts_with("provider.api.")
                && !type_name.starts_with("application.api.")),
        "ambiguous imports must not choose a provider identity: {ambiguous:#?}"
    );
}

#[test]
fn inline_callbacks_expose_only_complete_exact_scalar_returns() {
    use bonsai_lang_api::StaticScalarValue;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "Callbacks.scala",
            r#"
object Callbacks {
  def consume(check: Boolean => Boolean): Unit = ()
  def named(value: Boolean): Boolean = true
  def configure(): Unit = {
    consume(value => true)
    consume(value => false)
    consume(value => if (value) true else false)
    consume(named)
  }
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let source = workspace.db().vfs().snapshot(file).expect("fixture source");
    let index = workspace.db().decl_index(file).expect("Scala compiler index");
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
        callback_return("value => true"),
        Some(Some(StaticScalarValue::Boolean(true)))
    );
    assert_eq!(
        callback_return("value => false"),
        Some(Some(StaticScalarValue::Boolean(false)))
    );
    assert_eq!(
        callback_return("value => if (value) true else false"),
        Some(None),
        "conditional callback returns require complete control-flow proof"
    );
    assert_eq!(callback_return("named"), Some(None));
}

#[test]
fn ordered_for_generators_bind_each_value_before_the_next_generator() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_scala::ScalaAdapter::new())],
        &[(
            "Pipeline.scala",
            r#"
object Pipeline {
  def origin(value: String): Option[String] = Some(value)
  def transform(value: String): Option[String] = Some(value)
  def consume(value: String): Unit = ()

  def run(raw: String): Unit = {
    val result = for {
      first <- origin(raw)
      second <- transform(first)
    } yield second
    consume(result.getOrElse(""))
  }

  def plain(raw: String): Unit = {
    transform(raw)
    consume(raw)
  }
}
"#,
        )],
    );
    let global = workspace.db().global_index();
    let declaration = |name: &str| {
        global
            .all_files()
            .flat_map(|file| global.decls_in(file))
            .find(|decl| decl.name == name)
            .unwrap_or_else(|| panic!("missing {name} declaration"))
    };
    let run = declaration("run");

    let call_position = |callee: &str| {
        run.flow_events
            .iter()
            .position(|event| matches!(event, FlowEvent::Call { name, .. } if name.ends_with(callee)))
            .unwrap_or_else(|| panic!("missing {callee} call: {:#?}", run.flow_events))
    };
    let binding_position = |binding: &str| {
        let matches = run
            .flow_events
            .iter()
            .enumerate()
            .filter_map(|(position, event)| match event {
                FlowEvent::Assign {
                    target,
                    declares_new_binding,
                    ..
                } if target == binding => Some((position, *declares_new_binding)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "generator binding must be emitted once: {matches:#?}"
        );
        assert!(matches[0].1, "generator binding must declare its lexical name");
        matches[0].0
    };
    let loop_position = run
        .flow_events
        .iter()
        .position(|event| matches!(event, FlowEvent::Loop { .. }))
        .expect("for-comprehension loop event");

    let origin = call_position("origin");
    let first = binding_position("first");
    let transform = call_position("transform");
    let second = binding_position("second");
    assert!(
        origin < first && first < transform && transform < second && second < loop_position,
        "generator calls and bindings must preserve Scala execution order: {:#?}",
        run.flow_events
    );

    let plain = declaration("plain");
    assert!(
        plain.flow_events.iter().all(|event| !matches!(
            event,
            FlowEvent::Assign { target, .. } if target == "first" || target == "second"
        )),
        "ordinary call sequences must not acquire synthetic generator bindings: {:#?}",
        plain.flow_events
    );
}
