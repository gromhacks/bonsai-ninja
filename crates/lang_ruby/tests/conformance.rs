use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_ruby::RubyAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("a.rb", "def main\n  puts 1\nend\n")]
    );
}

#[test]
fn case_match_binds_values_but_not_map_keys_or_pins() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_ruby::RubyAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "a.rb",
            r#"def main(subject, expected)
  case subject
  in {value:, nested: {item:}, **rest}
    sink(value, item, rest)
  in ^expected
    sink(expected)
  end
end
"#,
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
    for target in ["value", "item", "rest"] {
        assert!(
            facts
                .iter()
                .any(|(actual, source)| actual == target && source.as_deref() == Some("subject")),
            "missing {target} <- subject: {facts:#?}"
        );
    }
    for non_binding in ["nested", "expected"] {
        assert!(
            facts.iter().all(|(target, _)| target != non_binding),
            "map key or pinned value became a binding: {non_binding}: {facts:#?}"
        );
    }

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
fn keyword_arguments_keep_their_ast_name_and_value() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_ruby::RubyAdapter::new())],
        &[(
            "jwt.rb",
            "def decode(input)\n  JWT.decode(input, input, verify: true)\nend\n",
        )],
    );
    let global = workspace.db().global_index();
    let decode = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "decode")
        .expect("decode declaration");

    assert!(
        decode.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, args, .. }
                if name == "JWT.decode"
                    && args.iter().any(|arg| {
                        arg.name.as_deref() == Some("verify") && arg.value_text.trim() == "true"
                    })
        )),
        "events={:#?}",
        decode.flow_events
    );
}

#[test]
fn bare_method_names_are_not_formal_parameters() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_ruby::RubyAdapter::new())],
        &[(
            "callbacks.rb",
            r#"class Store
  def show
    nil
  end

  def self.with_root
    yield "/srv/data"
  end
end
"#,
        )],
    );
    let global = workspace.db().global_index();
    let show = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "show")
        .expect("show declaration");
    assert!(show.params.is_empty(), "method name became a formal: {show:#?}");

    let with_root = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "with_root")
        .expect("with_root declaration");
    assert_eq!(
        with_root.params,
        vec!["<ruby-yield-block>"],
        "singleton method name shifted the compiler-owned block formal"
    );
}

#[test]
fn complete_local_string_maps_and_literal_call_arguments_are_exact_facts() {
    use bonsai_lang_api::{StaticScalarValue, StaticStringMapEntry};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_ruby::RubyAdapter::new())],
        &[(
            "maps.rb",
            r#"def choose(selector, runtime)
  choices = {"first" => "alpha", second: "beta"}
  dynamic_value = {"first" => runtime}
  spread_map = {"first" => "alpha", **runtime}
  choices.lookup(selector, "fallback")
  choices.lookup(selector, runtime)
end
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Ruby declaration index");

    assert_eq!(
        index.static_string_maps.len(),
        1,
        "only the complete string-to-string literal map is compiler-proven: {:#?}",
        index.static_string_maps
    );
    assert_eq!(index.static_string_maps[0].target, "choices");
    assert_eq!(
        index.static_string_maps[0].entries,
        vec![
            StaticStringMapEntry {
                key: "first".to_string(),
                value: "alpha".to_string(),
            },
            StaticStringMapEntry {
                key: "second".to_string(),
                value: "beta".to_string(),
            },
        ]
    );

    let mut lookup_arguments = index
        .call_argument_values
        .iter()
        .filter(|fact| {
            index.defs.iter().any(|decl| {
                decl.flow_events.iter().any(|event| {
                    matches!(
                        event,
                        bonsai_lang_api::FlowEvent::Call { span, name, .. }
                            if *span == fact.call_span && name == "choices.lookup"
                    )
                })
            }) && fact.argument_index == 1
        })
        .collect::<Vec<_>>();
    lookup_arguments.sort_by_key(|fact| fact.call_span.start);
    assert_eq!(lookup_arguments.len(), 2);
    assert_eq!(
        lookup_arguments[0].static_value,
        Some(StaticScalarValue::String("fallback".to_string()))
    );
    assert_eq!(lookup_arguments[1].static_value, None);
}

#[test]
fn frozen_constant_symbol_maps_are_exact_immutable_facts() {
    use bonsai_lang_api::{StaticScalarValue, StaticStringMapEntry};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_ruby::RubyAdapter::new())],
        &[(
            "maps.rb",
            r#"class OrderRepo
  SORTABLE = {"total" => :total, "created_at" => :created_at}.freeze
  MUTABLE = {"total" => :total}
  DYNAMIC = {"total" => runtime}.freeze

  def self.list(sort)
    SORTABLE.fetch(sort, :id)
  end
end
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Ruby declaration index");

    assert_eq!(
        index.static_string_maps,
        vec![bonsai_lang_api::StaticStringMapFact {
            assignment_span: index.static_string_maps[0].assignment_span,
            target: "SORTABLE".to_string(),
            target_is_immutable: true,
            entries: vec![
                StaticStringMapEntry {
                    key: "total".to_string(),
                    value: "total".to_string(),
                },
                StaticStringMapEntry {
                    key: "created_at".to_string(),
                    value: "created_at".to_string(),
                },
            ],
        }],
        "only a frozen complete constant map may become immutable selection evidence"
    );

    let fallback = index
        .call_argument_values
        .iter()
        .find(|fact| fact.argument_index == 1)
        .expect("fetch fallback argument");
    assert_eq!(
        fallback.static_value,
        Some(StaticScalarValue::String("id".to_string())),
        "a simple Ruby symbol is an exact static scalar, not runtime text"
    );
}
