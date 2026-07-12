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
