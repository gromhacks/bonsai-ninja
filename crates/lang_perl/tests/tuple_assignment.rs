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
