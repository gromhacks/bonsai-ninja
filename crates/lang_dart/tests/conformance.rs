use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_dart::DartAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("main.dart", "void main() { helper(); }\nvoid helper() {}\n")]
    );
}

#[test]
fn assignment_literals_preserve_exact_dart_runtime_strings() {
    use bonsai_lang_api::StaticScalarValue;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "strings.dart",
            r#"
const rootPath = '/srv/static';
const escaped = 'line\nnext';
String dynamicValue(String input) {
  final dynamic = '$input';
  return dynamic;
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Dart compiler index");
    let scalar = |target: &str| {
        index
            .assignment_values
            .iter()
            .find(|fact| fact.target.as_deref() == Some(target))
            .and_then(|fact| fact.static_value.clone())
    };
    assert_eq!(
        scalar("rootPath"),
        Some(StaticScalarValue::String("/srv/static".to_string()))
    );
    assert_eq!(
        scalar("escaped"),
        Some(StaticScalarValue::String("line\nnext".to_string()))
    );
    assert_eq!(scalar("dynamic"), None, "interpolated values must fail closed");
}

#[test]
fn enum_member_arguments_are_not_callable_references() {
    use bonsai_lang_api::AssignValueKind;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "values.dart",
            r#"
enum Kind { run }
class Envelope { Envelope({required Kind kind}); }
void entry() { Envelope(kind: Kind.run); }
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let source = workspace.db().vfs().snapshot(file).expect("fixture source");
    let index = workspace.db().decl_index(file).expect("Dart compiler index");
    let enum_argument = index
        .call_argument_values
        .iter()
        .find(|fact| {
            &source.text[fact.argument_span.start as usize..fact.argument_span.end as usize]
                == "kind: Kind.run"
        })
        .expect("named enum argument fact");

    assert_ne!(
        enum_argument.value_kind,
        Some(AssignValueKind::CallableReference),
        "a qualified enum value must remain ordinary compiler data"
    );
}

#[test]
fn flattened_property_prefixes_and_awaited_cascade_calls_retain_value_dependencies() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "transports.dart",
            r#"
class Request {
  Uri url = Uri();
  Future<String> read() async => '';
}
class Uri { Map<String, String> queryParameters = {}; }
class Carrier {
  String payload = '';
  String expose() => payload;
}

String query(Request request) => request.url.queryParameters['q'] ?? '';
Future<void> fill(Request request) async {
  final carrier = Carrier()..payload = await request.read();
  final clean = Carrier()..payload = '<safe/>';
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
            .unwrap_or_else(|| panic!("missing {name}"))
    };

    let query = declaration("query");
    let dependencies = query
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Return { value_flow, .. } => Some(&value_flow.source_names),
            _ => None,
        })
        .expect("query return");
    assert!(dependencies.iter().any(|source| source == "request.url"));
    assert!(dependencies
        .iter()
        .any(|source| source == "request.url.queryParameters"));

    let fill = declaration("fill");
    let assignment_call = |target: &str| {
        fill.flow_events.iter().find_map(|event| match event {
            FlowEvent::Assign {
                target: observed,
                source_call,
                ..
            } if observed == target => Some(source_call.as_deref()),
            _ => None,
        })
    };
    assert_eq!(assignment_call("carrier.payload"), Some(Some("request.read")));
    assert_eq!(assignment_call("clean.payload"), Some(None));

    let expose = declaration("expose");
    assert!(
        expose
            .receiver_state_sources
            .iter()
            .any(|source| source == "this.payload"),
        "receiver state read missing: {:#?}",
        expose.receiver_state_sources
    );
}

#[test]
fn assigned_inline_callbacks_expose_only_complete_exact_scalar_returns() {
    use bonsai_lang_api::StaticScalarValue;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "callbacks.dart",
            r#"
typedef Check = bool Function(bool value);
class Holder { late Check check; }
bool named(bool value) => true;
void configure(Holder holder) {
  holder.check = (value) => true;
  holder.check = (value) => false;
  holder.check = (value) { if (value) return true; return false; };
  holder.check = named;
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let source = workspace.db().vfs().snapshot(file).expect("fixture source");
    let index = workspace.db().decl_index(file).expect("Dart compiler index");
    let assigned_callback_return = |needle: &str| {
        index
            .assignment_values
            .iter()
            .find(|fact| &source.text[fact.value_span.start as usize..fact.value_span.end as usize] == needle)
            .map(|fact| fact.inline_callback_static_return.clone())
    };

    assert_eq!(
        assigned_callback_return("(value) => true"),
        Some(Some(StaticScalarValue::Boolean(true)))
    );
    assert_eq!(
        assigned_callback_return("(value) => false"),
        Some(Some(StaticScalarValue::Boolean(false)))
    );
    assert_eq!(
        assigned_callback_return("(value) { if (value) return true; return false; }"),
        Some(None)
    );
    assert_eq!(assigned_callback_return("named"), Some(None));
}

#[test]
fn named_function_argument_binds_only_to_an_invoked_callable_formal() {
    use bonsai_common::FuncId;
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "callbacks.dart",
            r#"
String callback(String value) => value;
String invoke(String Function(String) operation, String value) => operation(value);
String retain(String Function(String) operation, String value) => value;
void entry(String input) {
  final invoked = invoke(callback, input);
  final retained = retain(callback, input);
  sink(invoked);
  sink(retained);
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
            .unwrap_or_else(|| panic!("missing {name}"))
    };
    let entry = declaration("entry");
    let invoke = declaration("invoke");
    let retain = declaration("retain");
    let callback = declaration("callback");
    let callback_argument = entry
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name == "invoke" => args.first(),
            _ => None,
        })
        .expect("invoke callback argument");
    assert_eq!(callback_argument.value_text, "callback");
    assert_eq!(callback_argument.place.as_deref(), Some("callback"));
    let invocation_span = invoke
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, span, .. } if name == "operation" => Some(*span),
            _ => None,
        })
        .expect("callable-formal invocation");
    let returned_call_sites = invoke
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Return { value_flow, .. } => Some(&value_flow.call_sites),
            _ => None,
        })
        .expect("invoke return flow");
    assert!(
        returned_call_sites.contains(&invocation_span),
        "Dart return flow must identify the exact callback invocation result: invocation={invocation_span:?}, returns={returned_call_sites:?}, events={:#?}",
        invoke.flow_events
    );

    let graph = workspace.resolved_call_graph();
    let entry_id = FuncId::new(entry.symbol.raw());
    let invoke_id = FuncId::new(invoke.symbol.raw());
    let retain_id = FuncId::new(retain.symbol.raw());
    let callback_id = FuncId::new(callback.symbol.raw());
    assert!(
        graph
            .callable_arguments()
            .any(|relation| relation.caller == entry_id && relation.target == callback_id),
        "named Dart function arguments must retain exact callable identity: {:#?}",
        graph.callable_argument_records()
    );
    assert!(
        graph.callees_of(invoke_id).any(|edge| edge.to == callback_id),
        "invoking the bound formal must execute the exact callback"
    );
    assert!(
        graph.callees_of(retain_id).all(|edge| edge.to != callback_id),
        "merely receiving a callable must not execute it"
    );
}

#[test]
fn first_named_branch_condition_retains_typed_calls() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "condition.dart",
            r#"
bool accepts(String value) {
  if (value.contains("marker")) return true;
  return false;
}
"#,
        )],
    );
    let global = workspace.db().global_index();
    let accepts = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "accepts")
        .expect("accepts function should be indexed");

    assert!(
        accepts.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                receiver: Some(receiver),
                receiver_types,
                args,
                ..
            } if name == "value.contains"
                && receiver == "value"
                && receiver_types.iter().any(|ty| ty == "String")
                && args.len() == 1
                && args[0].value_text == "\"marker\""
        )),
        "the adapter-declared first branch child must be walked as the condition; events={:#?}",
        accepts.flow_events
    );
    assert!(
        accepts.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Branch {
                condition: Some(condition),
                ..
            } if condition == "value.contains(\"marker\")"
        )),
        "the full arm-bounded condition must be retained, not only its receiver; events={:#?}",
        accepts.flow_events
    );
}

#[test]
fn declared_instance_field_types_reach_calls_without_overriding_local_shadows() {
    use bonsai_lang_api::FlowEvent;

    let ws = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "fields.dart",
            r#"
class Collection {
  bool contains(String value) => false;
}
class Holder {
  String text = '';
  bool fieldCheck() => text.contains('marker');
  bool localCheck(Collection text) => text.contains('marker');
}
"#,
        )],
    );
    let global = ws.db().global_index();
    let receiver_types = |name: &str| {
        global
            .all_files()
            .flat_map(|file| global.decls_in(file))
            .find(|decl| decl.name == name)
            .and_then(|decl| {
                decl.flow_events.iter().find_map(|event| match event {
                    FlowEvent::Call {
                        name, receiver_types, ..
                    } if name.ends_with(".contains") => Some(receiver_types.clone()),
                    _ => None,
                })
            })
            .unwrap_or_default()
    };

    assert_eq!(receiver_types("fieldCheck"), ["String"]);
    assert_eq!(receiver_types("localCheck"), ["Collection"]);
}

#[test]
fn declared_instance_fields_are_receiver_places_but_lexical_shadows_remain_local() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "app.dart",
            r#"
class Holder {
  String payload = '';
  void consume() { sink(payload); }
  bool rejectsMarkup() => payload.contains('<!DOCTYPE');
  void parameterShadow(String payload) { sink(payload); }
  void localShadow() { final payload = 'local'; sink(payload); }
}
"#,
        )],
    );
    let global = workspace.db().global_index();
    let argument_place = |method_name: &str| {
        global
            .all_files()
            .flat_map(|file| global.decls_in(file))
            .find(|decl| decl.name == method_name)
            .and_then(|decl| {
                decl.flow_events.iter().find_map(|event| match event {
                    FlowEvent::Call { name, args, .. } if name == "sink" => {
                        args.first().and_then(|arg| arg.place.clone())
                    }
                    _ => None,
                })
            })
            .unwrap_or_else(|| panic!("missing sink argument in {method_name}"))
    };

    assert_eq!(argument_place("consume"), "this.payload");
    assert_eq!(argument_place("parameterShadow"), "payload");
    assert_eq!(argument_place("localShadow"), "payload");

    let rejects_markup = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "rejectsMarkup")
        .expect("rejectsMarkup declaration");
    let (receiver, receiver_types) = rejects_markup
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call {
                name,
                receiver,
                receiver_types,
                ..
            } if name.ends_with("contains") => Some((receiver.as_deref(), receiver_types.as_slice())),
            _ => None,
        })
        .expect("contains call");
    assert_eq!(receiver, Some("this.payload"));
    assert_eq!(receiver_types, ["String"]);
}

#[test]
fn typed_library_receivers_reach_callables_but_exact_local_shadows_win() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "receivers.dart",
            r#"
class RemoteClient { dynamic send(String value) => value; }
class LocalClient { dynamic send(String value) => value; }
late RemoteClient client;

void throughLibrary(String value) { client.send(value); }
void parameterShadow(LocalClient client, String value) { client.send(value); }
void localShadow(String value) {
  final client = LocalClient();
  client.send(value);
}
"#,
        )],
    );
    let global = workspace.db().global_index();
    let receiver_types = |name: &str| {
        global
            .all_files()
            .flat_map(|file| global.decls_in(file))
            .find(|decl| decl.name == name)
            .and_then(|decl| {
                decl.flow_events.iter().find_map(|event| match event {
                    FlowEvent::Call {
                        name, receiver_types, ..
                    } if name.rsplit('.').next() == Some("send") => Some(receiver_types.clone()),
                    _ => None,
                })
            })
            .unwrap_or_else(|| panic!("missing send call in {name}"))
    };

    assert_eq!(receiver_types("throughLibrary"), ["RemoteClient"]);
    assert_eq!(receiver_types("parameterShadow"), ["LocalClient"]);
    assert!(
        !receiver_types("localShadow")
            .iter()
            .any(|receiver| receiver == "RemoteClient"),
        "the local declaration must shadow module receiver evidence"
    );
}

#[test]
fn switch_variable_pattern_binds_the_subject_without_binding_its_type() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_dart::DartAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "app.dart",
            "void main(Object subject) { switch (subject) { case String value: sink(value); } }",
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
fn lowercase_declared_and_cast_types_remain_receiver_evidence() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_dart::DartAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "app.dart",
            "class lower { void run(String value) {} }\n\
             void handle(lower declared, dynamic input, String value) {\n\
               final casted = input as lower;\n\
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
fn nested_string_templates_expose_only_parsed_identifier_reads() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "app.dart",
            r#"
void run(String command, String unrelated) {
  Process.runSync('sh', ['-c', 'notify $command']);
  Process.runSync('sh', ['-c', 'the words command and unrelated are literals']);
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
    let calls = run
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name == "Process.runSync" => Some(args),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(calls.len(), 2, "events={:#?}", run.flow_events);
    assert_eq!(calls[0][1].source_names, ["command"]);
    assert!(calls[0][1].source_names.iter().all(|name| name != "unrelated"));
    assert!(
        calls[1][1].source_names.is_empty(),
        "literal text is not an identifier read"
    );
}

#[test]
fn assignment_targets_preserve_bare_and_qualified_assignable_places() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "tls.dart",
            "void configure(dynamic client, dynamic input) { onBadCertificate = input; client.badCertificateCallback = true; }",
        )],
    );
    let global = workspace.db().global_index();
    let configure = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "configure")
        .expect("configure declaration");
    let targets = configure
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign { target, .. } => Some(target.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        targets.contains(&"onBadCertificate"),
        "events={:?}",
        configure.flow_events
    );
    assert!(
        targets.contains(&"client.badCertificateCallback"),
        "events={:?}",
        configure.flow_events
    );
}

#[test]
fn positional_member_arguments_preserve_the_complete_selector_place() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[("app.dart", "void run(dynamic box) { sink(box.clean); }")],
    );
    let global = workspace.db().global_index();
    let run = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "run")
        .expect("run declaration");
    let argument = run
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name == "sink" => args.first(),
            _ => None,
        })
        .expect("sink argument");

    assert_eq!(argument.place.as_deref(), Some("box.clean"));
    assert_eq!(argument.value_text, "box.clean");
}

#[test]
fn every_dart_parameter_group_lowers_the_exact_binding_and_type() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "params.dart",
            "void positional(String value, [int count = 1]) { sink(value, count); }\n\
             void named({required String name, int count = 1}) { sink(name, count); }\n",
        )],
    );
    let global = workspace.db().global_index();
    let positional = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "positional")
        .expect("positional declaration");
    let named = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "named")
        .expect("named declaration");

    assert_eq!(positional.params, ["value", "count"]);
    assert_eq!(named.params, ["name", "count"]);
    for decl in [positional, named] {
        assert!(decl
            .type_aliases
            .iter()
            .any(|alias| alias.name == "count" && alias.type_name == "int"));
    }
}

#[test]
fn inferred_list_literal_preserves_core_receiver_type_through_a_cascade() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "lists.dart",
            "Iterable<String> parts(String input) sync* { yield input; }\n\
             String collect(String input) {\n\
               final values = <String>[]..addAll(parts(input));\n\
               return values.fold<String>('', (a, b) => '$a$b');\n\
             }\n",
        )],
    );
    let global = workspace.db().global_index();
    let collect = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "collect")
        .expect("collect declaration");

    assert!(
        collect
            .type_aliases
            .iter()
            .any(|alias| alias.name == "values" && alias.type_name == "List"),
        "a Dart list literal has the exact built-in List receiver type: {:#?}",
        collect.type_aliases
    );
    let typed_calls = collect
        .flow_events
        .iter()
        .filter_map(|event| match event {
            bonsai_lang_api::FlowEvent::Call {
                name, receiver_types, ..
            } if name.contains("values") => Some((name.as_str(), receiver_types.as_slice())),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        typed_calls
            .iter()
            .all(|(_, types)| types.iter().any(|ty| ty == "List")),
        "calls on the literal binding must retain List receiver evidence: {typed_calls:#?}"
    );
    let map_span = collect
        .flow_events
        .iter()
        .find_map(|event| match event {
            bonsai_lang_api::FlowEvent::Call { span, name, .. } if name == "values.fold" => Some(*span),
            _ => None,
        })
        .expect("values.fold call");
    let receiver = bonsai_lang_api::call_receiver_fact_for_span(
        &global.file_index(map_span.file).unwrap().call_receivers,
        map_span,
    )
    .expect("fold receiver fact");
    assert_eq!(receiver.value_flow.place.as_deref(), Some("values"));

    let cascade_assignment = collect
        .flow_events
        .iter()
        .find_map(|event| match event {
            bonsai_lang_api::FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_names,
                value_kind,
                ..
            } if target == "values" => Some((source_name, source_call, source_names, value_kind)),
            _ => None,
        })
        .expect("collection cascade binding");
    assert_eq!(cascade_assignment.0.as_deref(), Some("values"));
    assert_eq!(cascade_assignment.1, &None);
    assert_eq!(cascade_assignment.2.as_slice(), ["values"]);
    assert_eq!(
        cascade_assignment.3,
        &Some(bonsai_lang_api::AssignValueKind::Compound),
        "the outer binding consumes the exact post-cascade receiver state"
    );

    let file_index = global.file_index(map_span.file).expect("lists.dart index");
    let fact = file_index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("values"))
        .expect("cascade assignment fact");
    assert_eq!(fact.value_flow.place.as_deref(), Some("values"));
}

#[test]
fn typed_catch_uses_the_exception_field_not_the_type_or_stack_binding() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "catch.dart",
            "void run(Object input) {\n\
               try { throw input; }\n\
               on FormatException catch (error, stack) { sink(error); }\n\
             }\n",
        )],
    );
    let global = workspace.db().global_index();
    let run = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "run")
        .expect("run declaration");
    let catch_param = run.flow_events.iter().find_map(|event| match event {
        FlowEvent::Try { catch_param, .. } => catch_param.as_deref(),
        _ => None,
    });

    assert_eq!(catch_param, Some("error"), "events={:#?}", run.flow_events);
}

#[test]
fn dynamic_map_keys_remain_whole_object_while_literal_keys_are_field_precise() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "maps.dart",
            "void run(String key, String value) {\n\
               final dynamicMap = {?key: value};\n\
               final literalMap = {'safe': value};\n\
               sink(dynamicMap, literalMap);\n\
             }\n",
        )],
    );
    let global = workspace.db().global_index();
    let file = global.all_files().next().expect("maps file");
    let index = workspace.db().decl_index(file).expect("Dart declaration index");

    let dynamic_sources = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("dynamicMap"))
        .map(|fact| &fact.value_flow.source_names);
    assert_eq!(
        dynamic_sources,
        Some(&vec!["key".to_string(), "value".to_string()]),
        "dynamic map keys must not become exact fields: {:#?}",
        index.assignment_values
    );

    let literal_fields = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("literalMap"))
        .map(|fact| &fact.value_flow.aggregate_fields);
    let literal_fields = literal_fields.unwrap_or_else(|| {
        panic!(
            "literal-key map must retain field layout: {:#?}",
            index.assignment_values
        )
    });
    assert_eq!(literal_fields.len(), 1);
    assert_eq!(literal_fields[0].name, "safe");
    assert_eq!(literal_fields[0].value.source_names, ["value"]);
}

#[test]
fn module_constants_and_flattened_selector_initializers_retain_exact_value_facts() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "values.dart",
            r#"
const rootPath = '/srv/static';
String select(String input) {
  final normalized = module.build(rootPath);
  final chained = input.trim().toLowerCase();
  final compound = input + module.build(rootPath);
  return normalized + chained + compound;
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Dart compiler index");

    let root = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("rootPath"))
        .expect("module constant assignment fact");
    assert!(
        root.value_flow.source_names.is_empty() && root.value_flow.call_sites.is_empty(),
        "a parsed literal module binding must retain literal provenance: {root:#?}"
    );

    let normalized = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("normalized"))
        .expect("selector initializer fact");
    assert_eq!(normalized.direct_call_name.as_deref(), Some("module.build"));
    let [call_span] = normalized.call_sites.as_slice() else {
        panic!("complete selector initializer needs one exact call span: {normalized:#?}");
    };
    assert!(index.call_argument_values.iter().any(|argument| {
        argument.call_span == *call_span
            && argument.argument_index == 0
            && argument.value_flow.place.as_deref() == Some("rootPath")
    }));

    let chained = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("chained"))
        .expect("chained selector initializer fact");
    assert_eq!(
        chained.direct_call_name.as_deref(),
        Some("input.trim().toLowerCase")
    );
    let [outer_span] = chained.call_sites.as_slice() else {
        panic!("chained selector initializer needs one terminal call: {chained:#?}");
    };
    let outer_receiver = index
        .call_receivers
        .iter()
        .find(|fact| fact.call_span == *outer_span)
        .unwrap_or_else(|| panic!("missing outer receiver fact: {:#?}", index.call_receivers));
    let [inner_span] = outer_receiver.value_flow.call_sites.as_slice() else {
        panic!("outer selector must consume the previous call result: {outer_receiver:#?}");
    };
    let inner_receiver = index
        .call_receivers
        .iter()
        .find(|fact| fact.call_span == *inner_span)
        .unwrap_or_else(|| panic!("missing inner receiver fact: {:#?}", index.call_receivers));
    assert_eq!(inner_receiver.value_flow.place.as_deref(), Some("input"));

    let compound = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("compound"))
        .expect("compound initializer fact");
    assert_eq!(
        compound.direct_call_name, None,
        "a nested call in a compound expression is not the complete assignment value"
    );
}

#[test]
fn flattened_selector_arguments_retain_only_exact_direct_call_values() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "arguments.dart",
            r#"
String direct(String input) {
  return paths.canonical(paths.combine('/srv/static', input));
}

String compound(String input) {
  return paths.canonical('prefix/' + paths.combine('/srv/static', input));
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Dart compiler index");

    let direct_outer = index
        .refs
        .iter()
        .find(|reference| {
            reference.kind == bonsai_lang_api::RefKind::Call
                && reference.name == "paths.canonical"
                && reference.span.start < 70
        })
        .expect("direct outer selector call");
    let direct_argument = index
        .call_argument_values
        .iter()
        .find(|argument| argument.call_span == direct_outer.span && argument.argument_index == 0)
        .unwrap_or_else(|| {
            panic!(
                "direct outer argument fact; outer={direct_outer:#?}; refs={:#?}; args={:#?}",
                index.refs, index.call_argument_values
            )
        });
    let inner_span = direct_argument
        .direct_call_span
        .expect("complete nested selector call must retain its exact span");
    assert!(index
        .refs
        .iter()
        .any(|reference| reference.span == inner_span && reference.name == "paths.combine"));

    let compound_outer = index
        .refs
        .iter()
        .filter(|reference| {
            reference.kind == bonsai_lang_api::RefKind::Call && reference.name == "paths.canonical"
        })
        .max_by_key(|reference| reference.span.start)
        .expect("compound outer selector call");
    let compound_argument = index
        .call_argument_values
        .iter()
        .find(|argument| argument.call_span == compound_outer.span && argument.argument_index == 0)
        .expect("compound outer argument fact");
    assert_eq!(
        compound_argument.direct_call_span, None,
        "a nested call inside a compound argument is not the argument's direct value"
    );
}

#[test]
fn typed_string_operation_chains_emit_provider_bound_exact_substitutions() {
    use bonsai_lang_api::{CharacterConstraintDomain, CharacterConstraintOutput};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_dart::DartAdapter::new())],
        &[(
            "substitutions.dart",
            r#"
String encode(String value) => value
    .rewrite('<', '&lt;')
    .rewrite('>', '&gt;');

String alternate(AlternateText value) => value
    .rewrite('<', '&lt;')
    .rewrite('>', '&gt;');

String mixed(String value) => value
    .rewrite('<', '&lt;')
    .other('>', '&gt;');

String dynamicReplacement(String value, String replacement) => value
    .rewrite('<', replacement);
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Dart declaration index");

    assert_eq!(
        index.character_constraints.len(),
        2,
        "mixed operations and dynamic mappings must fail closed: {:#?}",
        index.character_constraints
    );
    let mut providers = index
        .character_constraints
        .iter()
        .map(|fact| {
            assert_eq!(fact.input_param_index, Some(0));
            assert!(matches!(fact.output, CharacterConstraintOutput::Return));
            let CharacterConstraintDomain::ProviderBound {
                factory_call,
                operation_call,
                domain,
            } = &fact.domain
            else {
                panic!("expected provider-bound substitution: {fact:#?}");
            };
            assert!(factory_call.is_empty());
            let CharacterConstraintDomain::SubstitutesExact { mappings } = domain.as_ref() else {
                panic!("expected exact mappings: {domain:#?}");
            };
            assert_eq!(mappings.len(), 2);
            operation_call.clone()
        })
        .collect::<Vec<_>>();
    providers.sort();
    assert_eq!(providers, ["AlternateText.rewrite", "String.rewrite"]);
}
