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
