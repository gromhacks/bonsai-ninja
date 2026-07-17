use bonsai_lang_api::FlowEvent;
use bonsai_testkit::workspace_with;
use std::sync::Arc;

#[test]
fn tuple_assignment_uses_parsed_rhs_operands() {
    let workspace = workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[(
            "a.pl",
            "sub entry { my ($args) = @_; my ($a, $b) = ($args, 'ok'); sink($a); }\n",
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Perl declaration index");
    let entry = index
        .defs
        .iter()
        .find(|decl| decl.name == "entry")
        .expect("entry declaration");
    let sources = entry.flow_events.iter().find_map(|event| match event {
        FlowEvent::Assign {
            target,
            source_name,
            source_names,
            ..
        } if target == "$a" => Some((source_name.clone(), source_names.clone())),
        _ => None,
    });
    assert_eq!(
        sources,
        Some((None, vec!["$args".to_string(), "args".to_string()])),
        "tuple binding must retain its parsed RHS carrier; events={:?}",
        entry.flow_events
    );
}

#[test]
fn parameter_list_uses_the_complete_parsed_target_pattern() {
    let source = "sub entry { my ($user_id, $cmd) = @_; sink($cmd); }\n";
    let workspace = workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[("a.pl", source)],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Perl declaration index");
    let entry = index
        .defs
        .iter()
        .find(|decl| decl.name == "entry")
        .expect("entry declaration");
    let syntax = bonsai_lang_api::AssignmentValueIndex::new(&index.assignment_values);
    let target_renderings = index
        .assignment_values
        .iter()
        .filter_map(|fact| syntax.target_rendering(fact.assignment_span, source))
        .collect::<Vec<_>>();
    assert_eq!(
        entry.params,
        vec!["$user_id".to_string(), "$cmd".to_string()],
        "assignment targets={target_renderings:?}; events={:?}",
        entry.flow_events
    );
}

#[test]
fn implicit_argument_foreach_is_a_variadic_ast_binding() {
    let source = "sub helper { for my $x (@_) { sink($x); } }\n";
    let workspace = workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[("a.pl", source)],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Perl declaration index");
    let helper = index
        .defs
        .iter()
        .find(|decl| decl.name == "helper")
        .expect("helper declaration");
    assert_eq!(helper.params, vec!["@_".to_string()]);
    assert!(helper.is_variadic);
    assert!(
        helper.flow_events.iter().any(|event| {
            matches!(event, FlowEvent::Assign { target, source_names, .. }
            if target == "$x" && source_names.iter().any(|source| source == "@_"))
        }),
        "events={:?}",
        helper.flow_events
    );
}
