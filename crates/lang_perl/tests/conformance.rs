use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn substitution_operators_emit_exact_receiver_and_pattern_facts() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[(
            "clean.pl",
            "sub clean { my ($value) = @_; $value =~ s/[^A-Za-z0-9_-]//g; return $value; }\n\
             sub unrelated { my ($value) = @_; $value =~ s/foo/bar/g; return $value; }\n",
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Perl declaration index");
    let substitution = |name: &str| {
        index
            .defs
            .iter()
            .find(|decl| decl.name == name)
            .and_then(|decl| {
                decl.flow_events.iter().find_map(|event| match event {
                    FlowEvent::Call {
                        name,
                        receiver,
                        args,
                        call_kind,
                        ..
                    } if name == "s" => Some((receiver.clone(), args.clone(), *call_kind)),
                    _ => None,
                })
            })
            .unwrap_or_else(|| panic!("missing substitution event for {name}: {:#?}", index.defs))
    };

    let (receiver, args, kind) = substitution("clean");
    assert_eq!(receiver.as_deref(), Some("$value"));
    assert_eq!(kind, bonsai_lang_api::CallKind::Operator);
    assert_eq!(args.len(), 2);
    assert!(args[0].value_text.contains("[^A-Za-z0-9_-]"));
    assert_eq!(args[1].value_text, "g");

    let (_, unrelated_args, _) = substitution("unrelated");
    assert_eq!(unrelated_args.len(), 3);
    assert_eq!(unrelated_args[0].value_text, "foo");
    assert_eq!(unrelated_args[1].value_text, "bar");
    assert_eq!(unrelated_args[2].value_text, "g");
    assert!(
        unrelated_args
            .iter()
            .all(|argument| !argument.value_text.contains("[^")),
        "ordinary substitution must remain distinguishable: {unrelated_args:#?}"
    );
}

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_perl::PerlAdapter::new());
    run_language_suite!(adapter, trace_from = "main", [("a.pl", "sub main { }")]);
}

#[test]
fn anonymous_hash_aggregate_precedes_its_later_consumer_after_normalization() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[(
            "flow.pl",
            r#"
sub orchestrate { return $_[0]->{cmd}; }
sub handle {
    my ($raw, $user) = @_;
    my $envelope = {
        kind => 'run',
        cmd => "$raw",
        user => $user,
        length => length($raw),
    };
    return orchestrate($envelope);
}
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Perl declaration index");
    let handle = index
        .defs
        .iter()
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");
    let aggregate = handle
        .flow_events
        .iter()
        .position(|event| matches!(event, FlowEvent::AggregateAssign { target, .. } if target == "$envelope"))
        .expect("anonymous hash aggregate");
    let consumer = handle
        .flow_events
        .iter()
        .position(|event| matches!(event, FlowEvent::Call { name, .. } if name == "orchestrate"))
        .expect("consumer call");
    assert!(
        aggregate < consumer,
        "field writes must execute before the consumer: {:#?}",
        handle.flow_events
    );
}

#[test]
fn signature_parameters_use_the_current_parameter_node_kinds() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[(
            "signatures.pl",
            "sub signed ($first, $second = 1, @rest) { return $first; }\n",
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Perl declaration index");
    let signed = index
        .defs
        .iter()
        .find(|decl| decl.name == "signed")
        .expect("signed declaration");

    assert_eq!(signed.params, ["first", "second", "rest"]);
    assert!(signed.is_variadic, "declaration={signed:#?}");
}

#[test]
fn short_circuit_rhs_effects_are_conditional_compiler_flow() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[(
            "control.pl",
            r#"
sub guarded {
  my ($name) = @_;
  my $path = build_path($name) or return undef;
  open(my $fh, '<', $path);
}
sub accepted {
  my ($value) = @_;
  validate($value) and consume($value);
  after_effect();
}
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Perl declaration index");
    let declaration = |name: &str| {
        index
            .defs
            .iter()
            .find(|decl| decl.name == name)
            .unwrap_or_else(|| panic!("missing {name} declaration"))
    };

    let guarded = declaration("guarded");
    let branch_index = guarded
        .flow_events
        .iter()
        .position(|event| matches!(event, FlowEvent::Branch { .. }))
        .expect("short-circuit branch");
    let open_index = guarded
        .flow_events
        .iter()
        .position(|event| matches!(event, FlowEvent::Call { name, .. } if name == "open"))
        .expect("reachable open call");
    assert!(branch_index < open_index);
    let FlowEvent::Branch {
        condition,
        then_events,
        else_events,
        ..
    } = &guarded.flow_events[branch_index]
    else {
        unreachable!()
    };
    assert!(condition
        .as_deref()
        .is_some_and(|condition| condition.starts_with("!(")));
    assert!(then_events
        .iter()
        .any(|event| matches!(event, FlowEvent::Return { .. })));
    assert!(else_events.is_empty());
    assert!(guarded.flow_events[..open_index]
        .iter()
        .all(|event| !matches!(event, FlowEvent::Return { .. })));

    let accepted = declaration("accepted");
    let branch = accepted
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Branch {
                condition,
                then_events,
                ..
            } => Some((condition, then_events)),
            _ => None,
        })
        .expect("and short-circuit branch");
    assert_eq!(branch.0.as_deref(), Some("validate($value)"));
    assert!(branch
        .1
        .iter()
        .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "consume")));
    assert!(accepted
        .flow_events
        .iter()
        .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "after_effect")));
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
fn func1op_calls_are_lowered_from_cst_without_a_builtin_allowlist() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[(
            "main.pl",
            "sub example { my ($path, $handle) = @_; my $n = rand 10; close $handle; chdir $path; }\n",
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Perl declaration index");
    let example = index
        .defs
        .iter()
        .find(|decl| decl.name == "example")
        .expect("example declaration");
    let calls = example
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, args, .. } => Some((name.as_str(), args)),
            _ => None,
        })
        .collect::<Vec<_>>();

    for expected in ["rand", "close", "chdir"] {
        assert!(
            calls.iter().any(|(name, args)| *name == expected && !args.is_empty()),
            "every grammar-classified func1op call must be lowered, including previously unlisted `{expected}`: {calls:#?}"
        );
    }
}

#[test]
fn coderef_invocations_are_lowered_from_tree_sitter_nodes() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[(
            "main.pl",
            "sub example { my ($callback, $value) = @_; my $out = $callback->($value); return $out; }\n",
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
            FlowEvent::Call { name, args, .. }
                if name == "$callback"
                    && args.first().is_some_and(|argument| {
                        argument.place.as_deref() == Some("$value")
                            || argument.source_names.iter().any(|source| source == "$value")
                    })
        )),
        "coderef calls must come from the exact coderef_call_expression and its arguments: {:#?}",
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

#[test]
fn heredoc_assignment_uses_only_grammar_proven_interpolated_carriers() {
    use bonsai_lang_api::{AssignValueKind, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[(
            "heredoc.pl",
            "sub interpolated { my ($value) = @_; my $page = <<\"HTML\";\n<p>$value</p>\nHTML\n return $page; }\n\
             sub literal { my ($value) = @_; my $page = <<'HTML';\n<p>$value</p>\nHTML\n return $page; }\n",
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Perl declaration index");
    let assignment = |name: &str| {
        index
            .defs
            .iter()
            .find(|decl| decl.name == name)
            .and_then(|decl| {
                decl.flow_events.iter().find_map(|event| match event {
                    FlowEvent::Assign {
                        target,
                        source_names,
                        value_kind,
                        ..
                    } if target == "$page" => Some((source_names.clone(), *value_kind)),
                    _ => None,
                })
            })
            .unwrap_or_else(|| panic!("missing heredoc assignment for {name}: {:#?}", index.defs))
    };

    let (dynamic_sources, dynamic_kind) = assignment("interpolated");
    assert_eq!(dynamic_sources, ["$value"]);
    assert_eq!(dynamic_kind, Some(AssignValueKind::Compound));

    let (literal_sources, literal_kind) = assignment("literal");
    assert!(literal_sources.is_empty());
    assert_eq!(literal_kind, Some(AssignValueKind::Literal));
}

#[test]
fn finite_hash_lookup_is_compiler_proven_only_for_static_unmodified_maps() {
    let facts = |source: &str| {
        let workspace = bonsai_testkit::workspace_with(
            vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
            &[("finite.pl", source)],
        );
        let file = workspace.vfs().all_files()[0];
        workspace
            .db()
            .decl_index(file)
            .expect("Perl declaration index")
            .finite_literal_selections
            .clone()
    };

    let safe = facts(
        "my %COLUMNS = (name => 'name', created => 'created');\n\
         sub choose { my ($key) = @_; my $column = $COLUMNS{$key} // 'name'; return $column; }\n",
    );
    assert_eq!(safe.len(), 1, "exact finite lookup fact: {safe:#?}");
    assert_eq!(safe[0].target.as_deref(), Some("$column"));

    let mutated = facts(
        "my %COLUMNS = (name => 'name');\n\
         $COLUMNS{name} = external_value();\n\
         sub choose { my ($key) = @_; my $column = $COLUMNS{$key} // 'name'; return $column; }\n",
    );
    assert!(
        mutated.is_empty(),
        "a projected write must invalidate the finite-map proof: {mutated:#?}"
    );

    let dynamic = facts(
        "my %COLUMNS = (name => external_value());\n\
         sub choose { my ($key) = @_; my $column = $COLUMNS{$key} // 'name'; return $column; }\n",
    );
    assert!(
        dynamic.is_empty(),
        "a dynamic map value must not become a finite-literal proof: {dynamic:#?}"
    );
}
