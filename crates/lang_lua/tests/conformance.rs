use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_lua::LuaAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("main.lua", "local function main()\n  return 1\nend\n")]
    );
}

#[test]
fn exact_lua_concatenations_lower_complete_string_composition_facts() {
    use bonsai_lang_api::StringCompositionPart;

    let source = r#"function restore(input, loader)
  local compiled = load("return " .. input)
  local nested = load(("return " .. input) .. loader:value())
  load(input)
end
"#;
    let runner = bonsai_conformance::ConformanceRunner::new(
        Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        vec![("restore.lua".to_string(), source.to_string())],
    );
    let workspace = runner.workspace();
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Lua declaration index");
    let first = index
        .string_compositions
        .iter()
        .find(|fact| {
            &source[fact.value_span.start as usize..fact.value_span.end as usize] == "\"return \" .. input"
        })
        .unwrap_or_else(|| panic!("missing exact Lua composition: {:#?}", index.string_compositions));
    assert_eq!(
        first.parts,
        vec![
            StringCompositionPart::Literal {
                value: "return ".to_string()
            },
            StringCompositionPart::Place {
                place: "input".to_string()
            }
        ]
    );
    assert_eq!(
        first
            .dynamic_anchor_span
            .map(|span| &source[span.start as usize..span.end as usize]),
        Some("input")
    );
    assert!(
        index.string_compositions.iter().any(|fact| {
            matches!(fact.parts.first(), Some(StringCompositionPart::Literal { value }) if value == "return ")
                && fact.parts.len() == 3
                && matches!(fact.parts.last(), Some(StringCompositionPart::Call { .. }))
        }),
        "nested exact composition was not fully lowered: {:#?}",
        index.string_compositions
    );
}

#[test]
fn generic_for_clause_is_lowered_as_foreach_from_the_for_statement_cst() {
    use bonsai_lang_api::{FlowEvent, LoopKind};

    let runner = bonsai_conformance::ConformanceRunner::new(
        Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        vec![(
            "loop.lua".to_string(),
            "function run(items)\n  for key, value in pairs(items) do\n    consume(key, value)\n  end\nend\n"
                .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Lua declaration index");
    let run = index
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run declaration");

    let body = run.flow_events.iter().find_map(|event| match event {
        FlowEvent::Loop {
            loop_kind: LoopKind::ForEach,
            body,
            ..
        } => Some(body),
        _ => None,
    });
    let body = body.unwrap_or_else(|| panic!("missing foreach: {:#?}", run.flow_events));
    assert!(
        ["key", "value"].into_iter().all(|binding| {
            run.flow_events.iter().any(|event| {
                matches!(
                    event,
                    FlowEvent::Assign {
                        target,
                        source_call: Some(source_call),
                        ..
                    } if target == binding && source_call == "pairs"
                )
            })
        }),
        "events={:#?}",
        run.flow_events
    );
    assert!(
        body.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, args, .. }
                if name == "consume"
                    && args.iter().any(|arg| arg.place.as_deref() == Some("key"))
                    && args.iter().any(|arg| arg.place.as_deref() == Some("value"))
        )),
        "foreach body={body:#?}"
    );
}

#[test]
fn provider_bound_table_substitution_requires_complete_exact_structure() {
    use bonsai_lang_api::{CharacterConstraintDomain, CharacterConstraintOutput};

    let runner = bonsai_conformance::ConformanceRunner::new(
        Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        vec![(
            "transform.lua".to_string(),
            r#"
local function complete(value)
  return (value:transform("[&<>\"']", {
    ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;",
    ['"'] = "&quot;", ["'"] = "&#39;",
  }))
end

local function partial(value)
  return value:transform("[&<>\"']", { ["&"] = "&amp;" })
end

local function dynamic(value, replacements)
  return value:transform("[&<>\"']", replacements)
end

local function unrelated(value)
  return value:other("[&<>\"']", {
    ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;",
    ['"'] = "&quot;", ["'"] = "&#39;",
  })
end
"#
            .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Lua declaration index");

    assert_eq!(
        index.character_constraints.len(),
        2,
        "only complete static substitution shapes should become provider-bound candidates: {:#?}",
        index.character_constraints
    );
    let facts = index
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
                panic!("expected provider-bound domain: {fact:#?}");
            };
            assert!(factory_call.is_empty());
            let CharacterConstraintDomain::SubstitutesExact { mappings } = domain.as_ref() else {
                panic!("expected exact substitutions: {domain:#?}");
            };
            assert_eq!(mappings.len(), 5);
            operation_call.clone()
        })
        .collect::<Vec<_>>();
    assert_eq!(facts, vec!["value.transform", "value.other"]);
}

#[test]
fn configuration_tables_emit_exact_static_scalars_and_reject_duplicate_keys() {
    use bonsai_lang_api::{StaticAggregateFieldValue, StaticScalarValue};

    let runner = bonsai_conformance::ConformanceRunner::new(
        Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        vec![(
            "config.lua".to_string(),
            r#"
local function configure(client, timeout)
  client:connect({ verify = false, mode = "client", fallback = nil, timeout = timeout })
  client:connect({ verify = false, verify = true })
end
"#
            .to_string(),
        )],
    );
    let ws = runner.workspace();
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Lua declaration index");
    let mut arguments = index
        .call_argument_values
        .iter()
        .filter(|fact| fact.argument_index == 0)
        .collect::<Vec<_>>();
    arguments.sort_by_key(|fact| fact.call_span.start);
    assert_eq!(arguments.len(), 2, "facts={:#?}", index.call_argument_values);
    assert_eq!(
        arguments[0].exact_static_aggregate_fields,
        vec![
            StaticAggregateFieldValue {
                path: vec!["verify".to_string()],
                value: StaticScalarValue::Boolean(false),
            },
            StaticAggregateFieldValue {
                path: vec!["mode".to_string()],
                value: StaticScalarValue::String("client".to_string()),
            },
            StaticAggregateFieldValue {
                path: vec!["fallback".to_string()],
                value: StaticScalarValue::Null,
            },
        ]
    );
    assert!(
        arguments[1].exact_static_aggregate_fields.is_empty(),
        "a duplicate key can override the earlier scalar and must fail closed: {:#?}",
        arguments[1]
    );
}

#[test]
fn finite_table_lookup_with_literal_fallback_is_exact_and_fails_closed() {
    let facts = |source: &str| {
        let runner = bonsai_conformance::ConformanceRunner::new(
            Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            vec![("selection.lua".to_string(), source.to_string())],
        );
        let workspace = runner.workspace();
        let file = workspace.vfs().all_files()[0];
        workspace
            .db()
            .decl_index(file)
            .expect("Lua declaration index")
            .finite_literal_selections
            .clone()
    };

    let assignment = facts(
        r#"
local choices = { alpha = "first", beta = "second" }
local unrelated = { alpha = external_value() }
local function choose(key)
  local selected = choices[key] or "fallback"
  return selected
end
"#,
    );
    let [assignment] = assignment.as_slice() else {
        panic!("one exact assignment selection expected: {assignment:#?}");
    };
    assert_eq!(assignment.target.as_deref(), Some("selected"));
    assert!(assignment.assignment_span.is_some());
    assert!(assignment.call_span.is_none());

    let argument = facts(
        r#"
local choices = { alpha = "first", beta = "second" }
local function emit(key)
  consume(choices[key] or "fallback")
end
"#,
    );
    let [argument] = argument.as_slice() else {
        panic!("one exact call-argument selection expected: {argument:#?}");
    };
    assert_eq!(argument.argument_index, Some(0));
    assert!(argument.call_span.is_some());
    assert!(argument.assignment_span.is_none());

    for (label, source) in [
        (
            "dynamic table value",
            r#"
local choices = { alpha = external_value() }
local function choose(key)
  return choices[key] or "fallback"
end
"#,
        ),
        (
            "dynamic fallback",
            r#"
local choices = { alpha = "first" }
local function choose(key, fallback)
  local selected = choices[key] or fallback
  return selected
end
"#,
        ),
        (
            "projected mutation",
            r#"
local choices = { alpha = "first" }
choices.beta = external_value()
local function choose(key)
  local selected = choices[key] or "fallback"
  return selected
end
"#,
        ),
        (
            "whole-table reassignment",
            r#"
local choices = { alpha = "first" }
choices = { alpha = "replacement" }
local function choose(key)
  local selected = choices[key] or "fallback"
  return selected
end
"#,
        ),
        (
            "same-name local shadow",
            r#"
local choices = { alpha = "first" }
local function choose(key)
  local choices = { alpha = external_value() }
  local selected = choices[key] or "fallback"
  return selected
end
"#,
        ),
        (
            "table escapes",
            r#"
local choices = { alpha = "first" }
consume(choices)
local function choose(key)
  local selected = choices[key] or "fallback"
  return selected
end
"#,
        ),
    ] {
        let facts = facts(source);
        assert!(facts.is_empty(), "{label} must fail closed: {facts:#?}");
    }
}

#[test]
fn compound_static_allowlist_guard_requires_complete_helper_and_terminal_rejection() {
    let facts = |source: &str| {
        let runner = bonsai_conformance::ConformanceRunner::new(
            Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            vec![("fetch.lua".to_string(), source.to_string())],
        );
        let workspace = runner.workspace();
        let file = workspace.vfs().all_files()[0];
        workspace
            .db()
            .decl_index(file)
            .expect("Lua declaration index")
            .compiler_guards
            .clone()
    };
    let safe = facts(
        r#"local ALLOWED = { ["api.example"] = true, ["hooks.example"] = true }
local function allowed(url)
  local host = url:match("^https://([^/]+)")
  return host ~= nil and ALLOWED[host] == true
end
local function run(input)
  if not allowed(input) then return "" end
  local c = http.new()
  return c:request_uri(input, { method = "GET", redirect = false })
end
"#,
    );
    let [fact] = safe.as_slice() else {
        panic!("one compound allowlist guard expected: {safe:#?}");
    };
    for evidence in [
        "predicate-complete:true",
        "extractor-call:match",
        "extractor-value:string:^https://([^/]+)",
        "finite-static-string-membership:true",
        "guarded-argument:0=predicate-argument:0",
        "guarded-static-field:1.redirect=boolean:false",
    ] {
        assert!(
            fact.evidence.iter().any(|item| item == evidence),
            "missing {evidence}: {fact:#?}"
        );
    }

    for (label, source) in [
        (
            "dynamic membership table",
            r#"local function allowed(url, allowed)
  local host = url:match("^https://([^/]+)")
  return host ~= nil and allowed[host] == true
end
local function run(input, allowed)
  if not allowed(input, allowed) then return "" end
  return c:request_uri(input, { redirect = false })
end
"#,
        ),
        (
            "observation without rejection",
            r#"local ALLOWED = { ["api.example"] = true }
local function allowed(url)
  local host = url:match("^https://([^/]+)")
  return host ~= nil and ALLOWED[host] == true
end
local function run(input)
  local observed = allowed(input)
  c:request_uri(input, { redirect = false })
  return observed
end
"#,
        ),
    ] {
        assert!(facts(source).is_empty(), "{label} must fail closed");
    }
}
