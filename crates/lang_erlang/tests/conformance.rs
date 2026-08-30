use bonsai_conformance::run_language_suite;
use bonsai_lang_api::FlowEvent;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [(
            "main.erl",
            "-module(main).\n-export([main/0]).\nmain() -> helper().\nhelper() -> ok.\n"
        )]
    );
}

#[test]
fn call_argument_lists_retain_exact_atom_and_string_values() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "options.erl".to_string(),
            "-module(options).\n-export([decode/1]).\ndecode(Value) ->\n  transform(Value, [safe, \"literal\"]),\n  configure(Value, [{enabled, false}, {callback, fun(Item) -> Item end}]).\n"
                .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Erlang compiler index");
    let options = index
        .call_argument_values
        .iter()
        .find(|fact| fact.argument_index == 1 && fact.exact_static_sequence_values.is_some())
        .expect("exact option-list fact");
    assert_eq!(
        options.exact_static_sequence_values.as_deref(),
        Some(
            [
                Some(bonsai_lang_api::StaticScalarValue::String("safe".to_string())),
                Some(bonsai_lang_api::StaticScalarValue::String("literal".to_string())),
            ]
            .as_slice()
        )
    );
    let configuration = index
        .call_argument_values
        .iter()
        .find(|fact| {
            fact.argument_index == 1
                && fact
                    .exact_static_aggregate_fields
                    .iter()
                    .any(|field| field.path == ["enabled"])
        })
        .expect("exact tuple-list option fact");
    assert!(configuration.exact_static_aggregate_fields.iter().any(|field| {
        field.path == ["enabled"]
            && field.value == bonsai_lang_api::StaticScalarValue::String("false".to_string())
    }));
    assert!(
        !configuration
            .exact_static_aggregate_fields
            .iter()
            .any(|field| field.path == ["callback"]),
        "dynamic callback values must not become exact scalar facts"
    );
}

#[test]
fn finite_pattern_membership_guard_requires_static_collection_and_guarded_arm() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let source = r#"-module(fetch).
-export([safe/1, dynamic/2, observed/1]).
-define(ALLOWED, ["api.example", "hooks.example"]).
safe(Url) ->
  case uri_string:parse(Url) of
    #{scheme := "https", host := Host} ->
      case lists:member(Host, ?ALLOWED) of
        true -> httpc:request(get, {Url, []}, [{autoredirect, false}], []);
        false -> denied
      end;
    _ -> denied
  end.
dynamic(Url, Allowed) ->
  case uri_string:parse(Url) of
    #{scheme := "https", host := Host} ->
      case lists:member(Host, Allowed) of
        true -> httpc:request(get, {Url, []}, [{autoredirect, false}], []);
        false -> denied
      end;
    _ -> denied
  end.
observed(Url) ->
  case uri_string:parse(Url) of
    #{scheme := "https", host := Host} ->
      Seen = lists:member(Host, ?ALLOWED),
      httpc:request(get, {Url, []}, [{autoredirect, false}], []),
      Seen;
    _ -> denied
  end.
"#;
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![("fetch.erl".to_string(), source.to_string())],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Erlang compiler index");
    let fact = index
        .compiler_guards
        .iter()
        .find(|fact| fact.capability == "case-arm.finite-pattern-membership")
        .expect("finite guarded case arm");
    for evidence in [
        "scrutinee-call:uri_string:parse",
        "membership-call:lists:member",
        "static-field:scheme=string:https",
        "finite-string-membership-field:host",
        "guarded-argument:1=scrutinee-argument:0",
        "guarded-static-field:2.autoredirect=string:false",
    ] {
        assert!(
            fact.evidence.iter().any(|item| item == evidence),
            "missing {evidence}: {fact:#?}"
        );
    }
    assert_eq!(
        index
            .compiler_guards
            .iter()
            .filter(|fact| fact.capability == "case-arm.finite-pattern-membership")
            .count(),
        1,
        "dynamic membership and observation without a guarded arm must fail closed: {:#?}",
        index.compiler_guards
    );
}

#[test]
fn literal_only_function_clauses_emit_finite_return_facts() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "selection.erl".to_string(),
            "-module(selection).\n-export([choose/1]).\nchoose(<<\"first\">>) -> \"one\";\nchoose(_) -> \"default\".\nidentity(Value) -> Value.\n"
                .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Erlang compiler index");
    let choose = index.defs.iter().filter(|decl| decl.name == "choose").count();
    assert_eq!(choose, 2, "each exact function clause remains addressable");
    assert_eq!(
        index.finite_literal_selections.len(),
        2,
        "both literal-only clauses must carry finite return facts"
    );
    let identity = index
        .defs
        .iter()
        .find(|decl| decl.name == "identity")
        .expect("dynamic identity clause");
    assert!(
        index.finite_literal_selections.iter().all(|fact| {
            fact.selection_span.file != identity.span.file
                || fact.selection_span.start < identity.span.start
                || fact.selection_span.end > identity.span.end
        }),
        "a parameter return must never become a finite literal selection"
    );
}

#[test]
fn export_attribute_atoms_define_module_visibility() {
    use bonsai_lang_api::{LanguageAdapter, Visibility};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "visibility.erl".to_string(),
            "-module(visibility).\n-export([public/0]).\npublic() -> private().\nprivate() -> ok.\n"
                .to_string(),
        )],
    );
    let ws = runner.workspace();
    let global = ws.db().global_index();
    let visibility = |name: &str| {
        global
            .all_files()
            .flat_map(|file| global.decls_in(file))
            .find(|decl| decl.name == name)
            .map(|decl| decl.visibility)
            .unwrap_or_else(|| panic!("missing {name}"))
    };

    assert_eq!(visibility("public"), Visibility::Public);
    assert_eq!(visibility("private"), Visibility::Module);
}

#[test]
fn functional_callback_case_and_tail_return_are_structured_in_their_own_scopes() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.erl".to_string(),
            "-module(main).\n-export([run/2, handle/2]).\nrun(Conn, Items) ->\n  try\n    lists:foreach(fun(It) ->\n      case It of\n        undefined -> ok;\n        _ -> handle(Conn, It)\n      end\n    end, Items)\n  catch\n    _:E -> {error, E}\n  end.\nhandle(Conn, X) ->\n  Y = transform(Conn, X),\n  Y.\ntransform(_Conn, X) -> X.\n".to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).expect("decl index should exist");
    let run = idx
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run decl should exist");
    let handle = idx
        .defs
        .iter()
        .find(|decl| decl.name == "handle")
        .expect("handle decl should exist");

    assert!(
        !contains_loop(&run.flow_events),
        "an external function identity cannot prove a language loop: {:?}",
        run.flow_events
    );
    // Passing an anonymous function does not execute it in the caller. The
    // callback therefore owns its Branch facts as a separate compiler
    // declaration, connected to `lists:foreach` by the exact argument span.
    let callback_span = idx
        .call_argument_values
        .iter()
        .find_map(|fact| fact.inline_callback_span)
        .expect("foreach inline callback span");
    let callback = idx
        .defs
        .iter()
        .find(|decl| decl.span == callback_span)
        .expect("inline callback declaration");
    assert!(
        !contains_branch(&run.flow_events),
        "callback control flow must not be inlined into the caller merely because it is passed as a value: {:?}",
        run.flow_events
    );
    assert!(
        contains_branch(&callback.flow_events),
        "expected Erlang callback case to emit Branch: {:?}",
        callback.flow_events
    );
    assert!(
        handle.flow_events.iter().any(|event| {
            matches!(event, FlowEvent::Return { value_name: Some(value_name), .. } if value_name == "Y")
        }),
        "expected Erlang tail expression to emit Return(value_name=Y): {:?}",
        handle.flow_events
    );
}

#[test]
fn tail_case_arms_are_explicit_return_paths() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "store.erl".to_string(),
            "-module(store).\n-export([read/1]).\nread(Path) ->\n  case allowed(Path) andalso local(Path) of\n    true -> file:read_file(Path);\n    false -> {error, eacces}\n  end.\n"
                .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Erlang compiler index");
    let read = index
        .defs
        .iter()
        .find(|decl| decl.name == "read")
        .expect("read declaration");
    let branch = read.flow_events.iter().find_map(|event| match event {
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => Some((then_events, else_events)),
        _ => None,
    });
    let (then_events, else_events) = branch.expect("tail case branch");
    assert!(
        then_events
            .iter()
            .any(|event| matches!(event, FlowEvent::Return { .. })),
        "the accepted arm must terminate with its implicit return: {then_events:#?}"
    );
    assert!(
        else_events
            .iter()
            .any(|event| matches!(event, FlowEvent::Return { .. })),
        "the rejected arm must terminate with its implicit return: {else_events:#?}"
    );
}

#[test]
fn assigned_case_arms_do_not_terminate_the_enclosing_function() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "app.erl".to_string(),
            "-module(app).\n-export([run/1]).\nrun(Input) ->\n  Value = case enabled() of true -> Input; false -> <<>> end,\n  sink(Value).\n"
                .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Erlang compiler index");
    let run = index
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run declaration");
    let branch = run.flow_events.iter().find_map(|event| match event {
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => Some((then_events, else_events)),
        _ => None,
    });
    let (then_events, else_events) = branch.expect("assigned case branch");
    assert!(
        !then_events
            .iter()
            .chain(else_events)
            .any(|event| matches!(event, FlowEvent::Return { .. })),
        "an assignment RHS returns to the assignment, not from run: {:#?}",
        run.flow_events
    );
    assert!(
        run.flow_events
            .iter()
            .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "sink")),
        "the call after the assigned case must remain executable: {:#?}",
        run.flow_events
    );
}

#[test]
fn map_literal_emits_field_scoped_assignments() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.erl".to_string(),
            "-module(main).\n-export([run/1]).\nrun(Args) -> B = #{tainted => Args, clean => \"safe\"}, sink(maps:get(clean, B)).\n".to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).expect("decl index should exist");
    let run = idx
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run decl should exist");

    let aggregate = run.flow_events.iter().find_map(|event| match event {
        FlowEvent::AggregateAssign {
            target, value_flow, ..
        } if target == "B" => Some(value_flow),
        _ => None,
    });
    let aggregate = aggregate.expect("map literal AggregateAssign");
    assert!(
        aggregate
            .aggregate_fields
            .iter()
            .any(|field| field.name == "tainted" && field.value.place.as_deref() == Some("Args")),
        "tainted field must come from the parsed map pair: {aggregate:#?}"
    );
    assert!(
        aggregate
            .aggregate_fields
            .iter()
            .any(|field| field.name == "clean" && field.value.is_empty()),
        "literal field must retain a clean-overwrite proof from its parsed value: {aggregate:#?}"
    );
    assert!(
        run.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, args, .. }
                if name == "sink"
                    && args.first().is_some_and(|arg| {
                        arg.place.as_deref() == Some("B.clean")
                            && arg.source_names.iter().any(|source| source == "B.clean")
                    })
        )),
        "maps:get/2 must lower to the exact field place: {:#?}",
        run.flow_events
    );
}

#[test]
fn map_match_binds_value_variables_to_the_exact_call_result() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.erl".to_string(),
            "-module(main).\n-export([run/0]).\nrun() -> #{host := Host} = request:query(), consume(Host).\n"
                .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Erlang compiler index");
    let run = index
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run declaration");

    assert!(
        run.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_call: Some(source_call),
                ..
            } if target == "Host" && source_call == "request:query"
        )),
        "map value binding must retain the parser-proven call result: {:#?}",
        run.flow_events
    );
    assert!(
        !run.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign { target, .. } if target == "host"
        )),
        "the literal map key must never become a local binding: {:#?}",
        run.flow_events
    );
}

#[test]
fn remote_call_list_argument_keeps_nested_call_operand_flow() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.erl".to_string(),
            "-module(main).\n-export([run/1]).\nrun(Input) -> os:cmd([\"ping \", uri_string:quote(Input)]).\n"
                .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Erlang compiler index");
    let run = index
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run declaration");
    let argument = run.flow_events.iter().find_map(|event| match event {
        FlowEvent::Call { name, args, .. } if name == "os:cmd" => args.first(),
        _ => None,
    });

    assert!(
        argument.is_some_and(|argument| argument.source_names == ["Input"]),
        "outer remote call must retain the nested quote(Input) operand: {:#?}",
        run.flow_events
    );
}

#[test]
fn module_behaviour_is_an_exact_owner_fact_for_callback_declarations() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "server.erl".to_string(),
            "-module(server).\n-behaviour(gen_server).\n-export([handle_call/3]).\nhandle_call(Request, From, State) -> {reply, Request, State}.\n"
                .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Erlang compiler index");
    let module = index
        .defs
        .iter()
        .find(|decl| decl.kind == bonsai_lang_api::DeclKind::Module && decl.name == "server")
        .expect("parsed module owner");
    assert_eq!(module.bases, ["gen_server"]);
    let callback = index
        .defs
        .iter()
        .find(|decl| decl.name == "handle_call")
        .expect("callback declaration");
    assert_eq!(callback.parent, Some(module.symbol));
    assert_eq!(callback.module_path.segments, ["server"]);
    assert_eq!(callback.qualified_name.as_deref(), Some("server.handle_call"));
    assert_eq!(callback.params, ["Request", "From", "State"]);
}

#[test]
fn map_generators_anonymous_funs_and_begin_groups_emit_exact_runtime_facts() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let runner = bonsai_conformance::ConformanceRunner::new(
        adapter,
        vec![(
            "main.erl".to_string(),
            "-module(main).\n-export([run/1]).\n\
             run(Map) ->\n\
               Values = [consume(K, V) || K := V <- Map],\n\
               F = fun(X) -> wrap(X) end,\n\
               begin pre(), F(Values) end.\n"
                .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Erlang compiler index");
    let run = index
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run declaration");
    let mut assignments = Vec::new();
    collect_assignments(&run.flow_events, &mut assignments);
    assert!(
        assignments
            .iter()
            .any(|(target, sources)| target == "K" && sources == &["Map"]),
        "map-generator key binding missing: {assignments:#?}\nevents={:#?}",
        run.flow_events
    );
    assert!(
        assignments
            .iter()
            .any(|(target, sources)| target == "V" && sources == &["Map"]),
        "map-generator value binding missing: {assignments:#?}"
    );

    let lambda = index
        .defs
        .iter()
        .find(|decl| decl.kind == bonsai_lang_api::DeclKind::Function && decl.name == "F")
        .expect("anonymous fun declaration");
    assert_eq!(lambda.params, ["X"]);
    assert!(lambda
        .flow_events
        .iter()
        .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "wrap")));

    let mut calls = Vec::new();
    collect_calls(&run.flow_events, &mut calls);
    let pre = calls.iter().position(|name| name == "pre").expect("pre call");
    let invoke = calls.iter().position(|name| name == "F").expect("F call");
    assert!(
        pre < invoke,
        "begin expressions must retain evaluation order: {calls:?}"
    );
}

fn collect_assignments(events: &[FlowEvent], out: &mut Vec<(String, Vec<String>)>) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_names,
                ..
            } => {
                let mut sources = source_names.clone();
                if let Some(source) = source_name {
                    if !sources.contains(source) {
                        sources.push(source.clone());
                    }
                }
                out.push((target.clone(), sources));
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assignments(then_events, out);
                collect_assignments(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_assignments(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assignments(body, out);
                collect_assignments(catch_events, out);
                collect_assignments(finally_events, out);
            }
            _ => {}
        }
    }
}

fn collect_calls(events: &[FlowEvent], out: &mut Vec<String>) {
    for event in events {
        match event {
            FlowEvent::Call { name, .. } => out.push(name.clone()),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_calls(then_events, out);
                collect_calls(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_calls(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_calls(body, out);
                collect_calls(catch_events, out);
                collect_calls(finally_events, out);
            }
            _ => {}
        }
    }
}

fn contains_branch(events: &[FlowEvent]) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Branch { .. } => true,
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            contains_branch(body)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => contains_branch(body) || contains_branch(catch_events) || contains_branch(finally_events),
        _ => false,
    })
}

fn contains_loop(events: &[FlowEvent]) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Loop { .. } => true,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => contains_loop(then_events) || contains_loop(else_events),
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => contains_loop(body) || contains_loop(catch_events) || contains_loop(finally_events),
        _ => false,
    })
}
