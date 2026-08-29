use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_csharp::CSharpAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "Main",
        [("A.cs", "class A { static void Main(string[] args) {} }")]
    );
}

#[test]
fn assignment_literals_preserve_exact_csharp_runtime_strings() {
    use bonsai_lang_api::StaticScalarValue;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_csharp::CSharpAdapter::new())],
        &[(
            "Strings.cs",
            r#"
class Paths {
  const string Root = "/srv/assets";
  const string Escaped = "line\nnext";
  const string Verbatim = @"C:\data";
  string Dynamic(string input) { var value = $"{input}"; return value; }
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("C# compiler index");
    let scalar = |target: &str| {
        index
            .assignment_values
            .iter()
            .find(|fact| fact.target.as_deref() == Some(target))
            .and_then(|fact| fact.static_value.clone())
    };
    assert_eq!(
        scalar("Root"),
        Some(StaticScalarValue::String("/srv/assets".to_string()))
    );
    assert_eq!(
        scalar("Escaped"),
        Some(StaticScalarValue::String("line\nnext".to_string()))
    );
    assert_eq!(
        scalar("Verbatim"),
        Some(StaticScalarValue::String(r"C:\data".to_string()))
    );
    assert_eq!(scalar("value"), None, "interpolated values must fail closed");
}

#[test]
fn inline_callbacks_expose_only_complete_exact_scalar_returns() {
    use bonsai_lang_api::StaticScalarValue;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_csharp::CSharpAdapter::new())],
        &[(
            "Callbacks.cs",
            r#"
delegate bool Check(bool value);
class Consumer { public static void Use(Check check) {} }
class Holder { public Check Check { get; set; } }
class App {
  static bool Named(bool value) => true;
  void Configure() {
    Consumer.Use(value => true);
    Consumer.Use(value => false);
    Consumer.Use(value => { return true; });
    Consumer.Use(value => { if (value) return true; return false; });
    Consumer.Use(value => value ? true : false);
    Consumer.Use(Named);
    var holder = new Holder();
    holder.Check = value => true;
    holder.Check = value => false;
    holder.Check = value => { if (value) return true; return false; };
    holder.Check = Named;
  }
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let source = workspace.db().vfs().snapshot(file).expect("fixture source");
    let index = workspace.db().decl_index(file).expect("C# compiler index");
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
        callback_return("value => { return true; }"),
        Some(Some(StaticScalarValue::Boolean(true)))
    );
    assert_eq!(
        callback_return("value => { if (value) return true; return false; }"),
        Some(None),
        "mixed callback paths must fail closed"
    );
    assert_eq!(
        callback_return("value => value ? true : false"),
        Some(None),
        "a conditional expression is not one exact static scalar"
    );
    assert_eq!(
        callback_return("Named"),
        Some(None),
        "named callbacks require a separate exact summary"
    );
    let assigned_callback_return = |needle: &str| {
        index
            .assignment_values
            .iter()
            .find(|fact| &source.text[fact.value_span.start as usize..fact.value_span.end as usize] == needle)
            .map(|fact| fact.inline_callback_static_return.clone())
    };
    assert_eq!(
        assigned_callback_return("value => true"),
        Some(Some(StaticScalarValue::Boolean(true)))
    );
    assert_eq!(
        assigned_callback_return("value => false"),
        Some(Some(StaticScalarValue::Boolean(false)))
    );
    assert_eq!(
        assigned_callback_return("value => { if (value) return true; return false; }"),
        Some(None)
    );
    assert_eq!(assigned_callback_return("Named"), Some(None));
}

#[test]
fn latest_local_object_initializer_fields_reach_only_the_matching_call_argument() {
    use bonsai_lang_api::{call_argument_value_fact, FlowEvent, StaticScalarValue};

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_csharp::CSharpAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Configured.cs",
            r#"
class Options { public object Guard { get; set; } public bool Enabled { get; set; } }
class Provider { public static object Build(object value, Options options) => value; }
class App {
  object Safe(object input) {
    var options = new Options { Guard = null, Enabled = true };
    return Provider.Build(input, options);
  }
  object Overwritten(object input) {
    var options = new Options { Guard = null, Enabled = true };
    options = GetOptions(input);
    return Provider.Build(input, options);
  }
  object SameSpellingElsewhere(object input) {
    var options = new Options { Enabled = false };
    return Provider.Build(input, options);
  }
  Options GetOptions(object value) => new Options { Guard = value, Enabled = true };
}
"#,
        )],
    );
    let file = ws.vfs().all_files().into_iter().next().expect("fixture file");
    let index = ws.db().decl_index(file).expect("C# declaration index");
    let call_span = |function: &str| {
        index
            .defs
            .iter()
            .find(|decl| decl.name == function)
            .and_then(|decl| {
                decl.flow_events.iter().find_map(|event| match event {
                    FlowEvent::Call { span, name, .. } if name == "Provider.Build" => Some(span.to_owned()),
                    _ => None,
                })
            })
            .unwrap_or_else(|| panic!("missing Provider.Build call in {function}"))
    };
    let fields = |function: &str| {
        call_argument_value_fact(&index.call_argument_values, call_span(function), 1)
            .expect("options argument fact")
            .exact_static_aggregate_fields
            .clone()
    };

    assert_eq!(
        fields("Safe"),
        vec![
            bonsai_lang_api::StaticAggregateFieldValue {
                path: vec!["Guard".to_string()],
                value: StaticScalarValue::Null,
            },
            bonsai_lang_api::StaticAggregateFieldValue {
                path: vec!["Enabled".to_string()],
                value: StaticScalarValue::Boolean(true),
            },
        ]
    );
    assert!(
        fields("Overwritten").is_empty(),
        "a later non-aggregate assignment must clear the initializer proof"
    );
    assert_eq!(
        fields("SameSpellingElsewhere"),
        vec![bonsai_lang_api::StaticAggregateFieldValue {
            path: vec!["Enabled".to_string()],
            value: StaticScalarValue::Boolean(false),
        }],
        "same-spelled locals in another callable must not collide"
    );
}

#[test]
fn direct_object_initializers_emit_qualified_member_writes_only_for_the_bound_receiver() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_csharp::CSharpAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Initializers.cs",
            r#"
class Config { public Choice Mode { get; set; } public object Provider { get; set; } }
enum Choice { Strict, Loose }
class Wrapper { public Wrapper(Config config) {} }
class App {
  object Configure(object dynamicValue) {
    var direct = new Config { Mode = Choice.Loose, Provider = dynamicValue };
    var nested = new Wrapper(new Config { Mode = Choice.Strict, Provider = dynamicValue });
    return direct;
  }
}
"#,
        )],
    );
    let global = ws.db().global_index();
    let configure = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Configure")
        .expect("Configure declaration");
    let targets = configure
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign { target, .. } => Some(target.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(
        targets.contains(&"direct.Mode"),
        "events: {:?}",
        configure.flow_events
    );
    assert!(
        targets.contains(&"direct.Provider"),
        "events: {:?}",
        configure.flow_events
    );
    assert!(
        targets
            .iter()
            .all(|target| *target != "nested.Mode" && *target != "nested.Provider"),
        "a constructor nested inside another call must not borrow the outer local as its receiver: {:?}",
        configure.flow_events
    );
}

#[test]
fn record_struct_uses_the_record_declaration_struct_discriminant() {
    use bonsai_lang_api::{DeclKind, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_csharp::CSharpAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Records.cs",
            "record class RefPacket(string Value); record struct ValuePacket(string Value);",
        )],
    );
    let global = ws.db().global_index();
    let declaration = |name: &str| {
        global
            .all_files()
            .flat_map(|file| global.decls_in(file))
            .find(|decl| decl.name == name)
            .unwrap_or_else(|| panic!("missing {name}"))
    };

    assert_eq!(declaration("RefPacket").kind, DeclKind::Class);
    assert_eq!(declaration("ValuePacket").kind, DeclKind::Struct);
}

#[test]
fn is_pattern_binds_the_designation_not_the_type() {
    use bonsai_lang_api::FlowEvent;

    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_csharp::CSharpAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "A.cs",
            "class A { void Main(object subject) { if (subject is string value) Sink(value); } void Sink(string value) {} }",
        )],
    );
    let global = ws.db().global_index();
    let main = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Main")
        .expect("Main declaration");
    let mut facts = Vec::new();
    collect_assignments(&main.flow_events, &mut facts);
    assert!(
        facts
            .iter()
            .any(|(target, source)| target == "value" && source.as_deref() == Some("subject")),
        "missing value <- subject: {facts:#?}"
    );
    assert!(facts.iter().all(|(target, _)| target != "string"));

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
fn base_constructor_compound_arg_uses_ast_facts() {
    use bonsai_lang_api::{DeclKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_csharp::CSharpAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "A.cs",
            "class Envelope { public string Command; }\n\
             class Parent { public Parent(string value) {} }\n\
             class Child : Parent { public Child(Envelope env) : base(env.Command) {} }",
        )],
    );
    let global = ws.db().global_index();
    let child_ctor = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.kind == DeclKind::Constructor && decl.name == "Child")
        .expect("Child constructor");
    let arg = child_ctor.flow_events.iter().find_map(|event| match event {
        FlowEvent::Call { name, args, .. } if name == "Parent" => args.first(),
        _ => None,
    });
    let arg = arg.unwrap_or_else(|| panic!("base constructor call: {:?}", child_ctor.flow_events));
    assert_eq!(arg.place.as_deref(), Some("env.Command"));
    assert!(arg.source_names.iter().any(|source| source == "env.Command"));
}

#[test]
fn argument_modifiers_distinguish_readonly_input_from_outbound_writeback() {
    use bonsai_lang_api::{ArgumentPassingMode, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_csharp::CSharpAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Arguments.cs",
            r#"
class Arguments {
  static void Helper(in string input, ref string changed, out string result) {
    result = changed;
  }

  static void Caller(string input) {
    string changed = "before";
    string result;
    Helper(in input, ref changed, out result);
  }
}
"#,
        )],
    );
    let global = ws.db().global_index();
    let caller = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Caller")
        .expect("Caller declaration");
    let args = caller
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name.ends_with("Helper") => Some(args),
            _ => None,
        })
        .unwrap_or_else(|| panic!("Helper call: {:?}", caller.flow_events));

    assert_eq!(args.len(), 3);
    assert_eq!(
        args[0].passing_mode,
        ArgumentPassingMode::Value,
        "a readonly `in` argument can flow into the callee but cannot write back"
    );
    assert_eq!(args[1].passing_mode, ArgumentPassingMode::WriteBack);
    assert_eq!(args[2].passing_mode, ArgumentPassingMode::WriteBack);
}

#[test]
fn constructors_expose_only_exact_receiver_field_writes_not_whole_object_returns() {
    use bonsai_lang_api::{DeclKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_csharp::CSharpAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Box.cs",
            r#"
class Box {
  private readonly string stored;
  private readonly string clean = "safe";

  public Box(string unused, string stored) {
    this.stored = stored;
  }
}
"#,
        )],
    );
    let global = ws.db().global_index();
    let constructor = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.kind == DeclKind::Constructor && decl.name == "Box")
        .expect("Box constructor");

    assert!(
        constructor
            .flow_events
            .iter()
            .all(|event| !matches!(event, FlowEvent::Return { .. })),
        "a constructor must not synthesize a whole-object return: {:?}",
        constructor.flow_events
    );
    assert!(
        constructor
            .receiver_field_writes
            .iter()
            .any(|write| { write.target == "this.stored" && write.source_param_indices.as_slice() == [1] }),
        "the stored parameter must retain its exact receiver-field write: {:?}",
        constructor.receiver_field_writes
    );
    assert!(
        constructor
            .receiver_field_writes
            .iter()
            .all(|write| !write.source_param_indices.contains(&0)),
        "the unused parameter must not taint any receiver field: {:?}",
        constructor.receiver_field_writes
    );
}

#[test]
fn expression_bodied_property_return_keeps_exact_projection_and_call_site() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_csharp::CSharpAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "A.cs",
            "record Envelope(string Cmd, string User);\n\
             class Repo { public Envelope Data { get; }\n\
             public string Cmd => Data.Cmd; }",
        )],
    );
    let global = ws.db().global_index();
    let getter = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| {
            decl.name == "Cmd"
                && decl.flow_events.iter().any(|event| {
                    matches!(
                        event,
                        FlowEvent::Return { value_flow, .. }
                            if value_flow.place.as_deref() == Some("this.Data.Cmd")
                    )
                })
        })
        .expect("expression-bodied Cmd getter");
    let value_flow = getter.flow_events.iter().find_map(|event| match event {
        FlowEvent::Return { value_flow, .. } => Some(value_flow),
        _ => None,
    });
    let value_flow = value_flow.unwrap_or_else(|| panic!("getter flow: {:?}", getter.flow_events));
    assert_eq!(value_flow.place.as_deref(), Some("this.Data.Cmd"));
    let projection = value_flow.projection.as_ref().expect("exact member projection");
    assert_eq!(projection.base, "this");
    assert_eq!(projection.path, ["Data", "Cmd"]);
    assert_eq!(value_flow.call_sites.len(), 1);
}

#[test]
fn lowercase_declared_and_cast_types_remain_receiver_evidence() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_csharp::CSharpAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "A.cs",
            "class lower { public void Run(string value) {} }\n\
             class App { public void Handle(object input, string value) {\n\
               lower declared = new lower();\n\
               var casted = (lower)input;\n\
               declared.Run(value); casted.Run(value);\n\
             } }",
        )],
    );
    let global = ws.db().global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Handle")
        .expect("Handle declaration");
    let typed_calls = handle.flow_events.iter().filter(|event| {
        matches!(
            event,
            FlowEvent::Call { name, receiver_types, .. }
                if name.rsplit('.').next() == Some("Run")
                    && receiver_types.iter().any(|ty| ty == "lower")
        )
    });
    assert_eq!(typed_calls.count(), 2, "events: {:#?}", handle.flow_events);
}

#[test]
fn switch_expression_emits_only_complete_finite_literal_selections() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_csharp::CSharpAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Selections.cs",
            r#"
class Selector {
  static string Choose(string key) => key switch {
    "first" => "First",
    _ => "Default",
  };
  static string Reflect(string key) => key switch {
    "first" => "First",
    _ => key,
  };
  static void Use(string key) {
    var chosen = key switch { "first" => "First", _ => "Default" };
    var reflected = key switch { "first" => "First", _ => key };
  }
}
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("C# declaration index");
    assert_eq!(
        index.finite_literal_selections.len(),
        2,
        "facts: {:#?}",
        index.finite_literal_selections
    );
    assert!(index
        .finite_literal_selections
        .iter()
        .any(|fact| fact.assignment_span.is_none() && fact.target.is_none()));
    assert!(index
        .finite_literal_selections
        .iter()
        .any(|fact| fact.target.as_deref() == Some("chosen")));
    assert!(index
        .finite_literal_selections
        .iter()
        .all(|fact| fact.target.as_deref() != Some("reflected")));
}

#[test]
fn namespace_using_is_an_unqualified_type_import_but_alias_is_exact() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_csharp::CSharpAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Imports.cs",
            "using System.Text.Encodings.Web;\nusing Net = System.Net;\nclass App { }",
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let imports = ws.db().import_index(file).expect("C# import index");
    let namespace = imports
        .imports
        .iter()
        .find(|spec| spec.module == "System.Text.Encodings.Web")
        .expect("namespace using");
    assert!(namespace.is_wildcard);
    assert_eq!(namespace.alias, None);
    let alias = imports
        .imports
        .iter()
        .find(|spec| spec.module == "System.Net")
        .expect("aliased using");
    assert!(!alias.is_wildcard);
    assert_eq!(alias.alias.as_deref(), Some("Net"));
}
