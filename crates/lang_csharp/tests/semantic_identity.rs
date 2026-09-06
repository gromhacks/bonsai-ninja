use bonsai_lang_api::{DeclIndex, DeclKind, FlowEvent};
use std::sync::Arc;

fn lower(source: &str) -> Arc<DeclIndex> {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_csharp::CSharpAdapter::new())],
        &[("Identity.cs", source)],
    );
    let file = workspace.vfs().all_files()[0];
    workspace.db().decl_index(file).expect("C# declarations")
}

#[test]
fn a_type_only_catch_does_not_declare_a_variable_named_after_the_type() {
    let index = lower("class App { void Run() { try { Work(); } catch (Failure) { Log(); } } }");
    let run = index.defs.iter().find(|decl| decl.name == "Run").unwrap();
    let (parameter, arms) = run
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Try {
                catch_param,
                catch_arms,
                ..
            } => Some((catch_param, catch_arms)),
            _ => None,
        })
        .unwrap();
    assert_eq!(*parameter, None);
    assert_eq!(arms.len(), 1);
    assert_eq!(arms[0].parameter, None);
    assert_eq!(arms[0].types, ["Failure"]);
}

#[test]
fn constructing_another_object_does_not_write_the_current_receiver() {
    let index = lower(
        r#"
class Other { public string stored; public Other(string value) { this.stored = value; } }
class Box { public Box(string input) { var other = new Other(input); } }
"#,
    );
    let constructor = index
        .defs
        .iter()
        .find(|decl| decl.name == "Box" && decl.kind == DeclKind::Constructor)
        .unwrap();
    assert!(
        constructor.receiver_field_writes.is_empty(),
        "{:?}",
        constructor.receiver_field_writes
    );
}

#[test]
fn mutable_or_optional_object_initializers_are_not_exact_argument_configuration() {
    for body in [
        "var options = new Options { Guard = null }; options.Guard = input;",
        "var options = new Options { Guard = null }; var alias = options; alias.Guard = input;",
        "Options options = GetOptions(); if (choose) options = new Options { Guard = null };",
        "var options = new Options { Guard = null }; Mutate(options);",
    ] {
        let index = lower(&format!("class Options {{ public object Guard; }} class App {{ void Run(object input, bool choose) {{ {body} Use(options); }} }}"));
        let run = index.defs.iter().find(|decl| decl.name == "Run").unwrap();
        let call = run
            .flow_events
            .iter()
            .find_map(|event| match event {
                FlowEvent::Call { name, span, .. } if name == "Use" => Some(*span),
                _ => None,
            })
            .unwrap();
        let fact = bonsai_lang_api::call_argument_value_fact(&index.call_argument_values, call, 0).unwrap();
        assert!(
            fact.exact_static_aggregate_fields.is_empty(),
            "{body}: {:?}",
            fact.exact_static_aggregate_fields
        );
    }
}

#[test]
fn later_arguments_can_mutate_an_earlier_object_argument_before_the_call() {
    let index = lower(
        r#"
class Options { public object Guard; }
class App { void Run() { var options = new Options { Guard = null }; Use(options, Mutate(options)); } }
"#,
    );
    let run = index.defs.iter().find(|decl| decl.name == "Run").unwrap();
    let call = run
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, span, .. } if name == "Use" => Some(*span),
            _ => None,
        })
        .unwrap();
    let argument = bonsai_lang_api::call_argument_value_fact(&index.call_argument_values, call, 0).unwrap();
    assert!(
        argument.exact_static_aggregate_fields.is_empty(),
        "{:?}",
        argument.exact_static_aggregate_fields
    );
}
