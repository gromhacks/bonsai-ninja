use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_perl::PerlAdapter::new());
    run_language_suite!(adapter, trace_from = "main", [("a.pl", "sub main { }")]);
}

#[test]
fn isa_assignment_bases_come_from_the_assignment_tree() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[(
            "Child.pm",
            "package Child;\nour @ISA = ('Base', Other::Role);\n1;\n",
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Perl declaration index");
    let child = index
        .defs
        .iter()
        .find(|decl| decl.name == "Child")
        .expect("Child package declaration");

    assert_eq!(child.bases, ["Base", "Role"]);
}

#[test]
fn inherited_bless_dispatch_has_structural_receiver_facts() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[
            (
                "Base.pm",
                "package Base;\nsub helper { my ($self, $p) = @_; sink($p); }\n1;\n",
            ),
            (
                "entry.pl",
                "use Base;\npackage Child;\nour @ISA = ('Base');\npackage main;\nsub entry { my ($args) = @_; my $obj = bless {}, 'Child'; $obj->helper($args); }\n",
            ),
        ],
    );
    for file in workspace.vfs().all_files() {
        let _ = workspace.db().decl_index(file);
    }
    let global = workspace.db().global_index();
    let child = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Child")
        .expect("Child package");
    assert_eq!(child.bases, ["Base"]);
    let entry = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "entry")
        .expect("entry declaration");
    assert!(
        entry
            .type_aliases
            .iter()
            .any(|alias| alias.name == "$obj" && alias.type_name == "Child"),
        "aliases={:?}",
        entry.type_aliases
    );
    assert!(
        entry.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, receiver_types, .. }
                if name.ends_with("helper") && receiver_types.iter().any(|ty| ty == "Child")
        )),
        "events={:?}",
        entry.flow_events
    );
}

#[test]
fn conditional_and_postfix_conditional_expressions_lower_to_branches() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[(
            "branches.pl",
            r#"
sub choose {
    my ($value, $flag) = @_;
    my $selected = $flag ? $value : '';
    sink($selected) if $flag;
    die "empty" unless length $selected;
    return $selected;
}
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Perl declaration index");
    let choose = index
        .defs
        .iter()
        .find(|decl| decl.name == "choose")
        .expect("choose declaration");
    let branches = choose
        .flow_events
        .iter()
        .filter(|event| matches!(event, FlowEvent::Branch { .. }))
        .count();
    assert!(
        branches >= 3,
        "ternary, postfix-if, and postfix-unless syntax must be explicit branches: {:#?}",
        choose.flow_events
    );
}
