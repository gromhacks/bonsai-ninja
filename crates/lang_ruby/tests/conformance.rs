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
