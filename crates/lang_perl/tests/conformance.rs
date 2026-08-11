use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_perl::PerlAdapter::new());
    run_language_suite!(adapter, trace_from = "main", [("a.pl", "sub main { }")]);
}

#[test]
fn grammar_function_nodes_emit_ordinary_call_facts() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[("main.pl", "sub example { my ($handle) = @_; read($handle); }\n")],
    );
    let global = workspace.db().global_index();
    let example = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "example")
        .expect("example declaration");

    assert!(
        example.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, args, .. }
                if name == "read"
                    && args.first().is_some_and(|arg| {
                        arg.source_names.iter().any(|name| name == "$handle" || name == "handle")
                    })
        )),
        "events={:?}",
        example.flow_events
    );
}

#[test]
fn undef_operator_emits_an_exact_call_like_syntax_fact() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[("main.pl", "sub clear_value { my ($value) = @_; undef $value; }\n")],
    );
    let global = workspace.db().global_index();
    let clear = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "clear_value")
        .expect("clear_value declaration");

    assert!(
        clear.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, args, .. }
                if name == "undef"
                    && args.first().is_some_and(|arg| {
                        arg.place.as_deref() == Some("$value")
                            || arg.source_names.iter().any(|source| source == "$value")
                    })
        )),
        "events={:#?}",
        clear.flow_events
    );
}

#[test]
fn hash_element_reads_and_writes_use_one_field_sensitive_place() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[(
            "main.pl",
            "sub update { my ($c, $args) = @_; $c->{cmd} = $args; sink($c->{cmd}); }",
        )],
    );
    let global = workspace.db().global_index();
    let update = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "update")
        .expect("update declaration");

    assert!(
        update.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign { target, source_name, .. }
                if target == "$c.cmd" && source_name.as_deref() == Some("$args")
        )),
        "events={:#?}",
        update.flow_events
    );
    assert!(
        update.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, args, .. }
                if name == "sink"
                    && args.first().and_then(|arg| arg.place.as_deref()) == Some("$c.cmd")
        )),
        "events={:#?}",
        update.flow_events
    );
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

#[test]
fn quoted_assignment_is_a_literal_without_dynamic_carriers() {
    use bonsai_lang_api::{AssignValueKind, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[(
            "literal.pl",
            "sub example { my ($value) = @_; my $lit = \"abc\"; my $dynamic = \"prefix $value\"; return $lit; }\n",
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Perl declaration index");
    let example = index
        .defs
        .iter()
        .find(|decl| decl.name == "example")
        .expect("example declaration");
    assert!(
        example.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_call: None,
                source_names,
                value_kind: Some(AssignValueKind::Literal),
                ..
            } if target.trim_start_matches('$') == "lit" && source_names.is_empty()
        )),
        "Perl quoted assignment must use its parsed literal node; events={:#?}, value_facts={:#?}",
        example.flow_events,
        index.assignment_values
    );
    assert!(
        example.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_names,
                value_kind,
                ..
            } if target.trim_start_matches('$') == "dynamic"
                && source_names.iter().any(|source| source.trim_start_matches('$') == "value")
                && *value_kind != Some(AssignValueKind::Literal)
        )),
        "an interpolated Perl string must retain its parsed scalar carrier: {:#?}",
        example.flow_events
    );
}
