use super::*;

fn parse_import_specs(src: &str) -> Vec<ImportSpec> {
    let language = language_from_pack(PACK_NAME).expect("perl grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set perl grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse perl source");
    parse_imports(&tree, src.as_bytes(), FileId::new(0))
}

#[test]
fn special_process_inputs_come_only_from_parsed_nodes() {
    let src = r#"
# $ARGV %ENV STDIN are comments, not reads.
my $ignored = '$ARGV %ENV STDIN';
my $arg = $ARGV[0];
my $home = $ENV{'HOME'};
my $line = <STDIN>;
"#;
    let language = language_from_pack(PACK_NAME).expect("perl grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set perl grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse perl source");
    let refs = extract_perl_special_variable_refs(&tree, src.as_bytes(), FileId::new(0));
    let names = refs
        .iter()
        .map(|reference| reference.name.as_str())
        .collect::<Vec<_>>();

    assert_eq!(names, ["ARGV", "ENV", "STDIN"]);
    for reference in refs {
        let start = usize::try_from(reference.span.start).expect("span start");
        let end = usize::try_from(reference.span.end).expect("span end");
        assert!(!src[start..end].contains(' '));
    }
}

#[test]
fn isa_assignment_shape_is_structured() {
    let src = "package Child;\nour @ISA = ('Base', Other::Role);\n";
    let language = language_from_pack(PACK_NAME).expect("perl grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set perl grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse perl source");
    let assignments = collect_kinds(&tree, &["assignment_expression"]);
    assert_eq!(assignments.len(), 1);
    let assignment = assignments[0];
    let left = assignment.child_by_field_name("left").expect("assignment left");
    let right = assignment
        .child_by_field_name("right")
        .filter(tree_sitter::Node::is_named)
        .or_else(|| {
            let mut cursor = assignment.walk();
            assignment.named_children(&mut cursor).last()
        })
        .expect("assignment right");
    let varnames = collect_kinds_below(left, &["varname"]);
    assert!(varnames.iter().any(|node| {
        node_text(node, src.as_bytes()) == "ISA"
            && node.parent().is_some_and(|parent| parent.kind() == "array")
    }));
    let base_nodes = collect_kinds_below(right, &["string_content", "bareword"])
        .into_iter()
        .map(|node| node_text(&node, src.as_bytes()).to_string())
        .collect::<Vec<_>>();
    assert_eq!(base_nodes, ["Base", "Other::Role"]);
}

fn collect_kinds_below<'tree>(
    node: tree_sitter::Node<'tree>,
    kinds: &[&str],
) -> Vec<tree_sitter::Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if kinds.contains(&current.kind()) {
            out.push(current);
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    out.sort_by_key(tree_sitter::Node::start_byte);
    out
}

fn assignment_fixture(src: &str) -> (Span, AssignmentValueIndex) {
    let language = language_from_pack(PACK_NAME).expect("perl grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set perl grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse perl source");
    let facts =
        bonsai_lang_api::extract_assignment_value_facts(&tree, FileId::new(0), &HANDLER, src.as_bytes());
    let span = facts.first().expect("assignment syntax fact").assignment_span;
    (span, AssignmentValueIndex::new(&facts))
}

fn parse_perl_tree(src: &str) -> Tree {
    let language = language_from_pack(PACK_NAME).expect("perl grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set perl grammar");
    parser.parse(src.as_bytes(), None).expect("parse perl source")
}

fn calls_below<'a>(events: &'a [FlowEvent], out: &mut Vec<&'a FlowEvent>) {
    for event in events {
        match event {
            FlowEvent::Call { .. } => out.push(event),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                calls_below(then_events, out);
                calls_below(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                calls_below(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                calls_below(body, out);
                calls_below(catch_events, out);
                calls_below(finally_events, out);
            }
            _ => {}
        }
    }
}

#[test]
fn defined_or_static_default_retains_the_exact_left_call_result() {
    let src = r#"
package Handler;
sub show ($self) {
    my $name = $self->param('name') // '';
    my $ambiguous = first() // second();
    return $name;
}
"#;
    let adapter: std::sync::Arc<dyn bonsai_lang_api::LanguageAdapter> =
        std::sync::Arc::new(PerlAdapter::new());
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("handler.pl", src)]);
    let global = ws.db().global_index();
    let show = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "show")
        .expect("show declaration");

    assert!(
        show.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_call: Some(call),
                ..
            } if target == "$name" && call == "self->param"
        )),
        "defined-or with a static default must retain the compiler-proven call result: {:#?}",
        show.flow_events
    );
    assert!(
        !show.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_call: Some(_),
                ..
            } if target == "$ambiguous"
        )),
        "two dynamic operands must not be collapsed to one call result: {:#?}",
        show.flow_events
    );
}

#[test]
fn synthesized_calls_are_restored_to_compiler_evaluation_order() {
    let src = r#"
package Store;
use File::Spec;
sub read_segments {
    my ($rel) = @_;
    my $path = File::Spec->catfile('/srv/assets', $rel);
    open(my $fh, '<', $path) or return undef;
    my $data = <$fh>;
    close($fh);
    return $data;
}
"#;
    let adapter: std::sync::Arc<dyn bonsai_lang_api::LanguageAdapter> =
        std::sync::Arc::new(PerlAdapter::new());
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("Store.pm", src)]);
    let global = ws.db().global_index();
    let decl = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "read_segments")
        .expect("read_segments declaration");

    let call_index = |name: &str| {
        decl.flow_events
            .iter()
            .position(|event| matches!(event, FlowEvent::Call { name: call, .. } if call == name))
            .unwrap_or_else(|| panic!("missing call {name}: {:#?}", decl.flow_events))
    };
    let path_assign = decl
        .flow_events
        .iter()
        .position(|event| matches!(event, FlowEvent::Assign { target, .. } if target == "$path"))
        .expect("path assignment");
    let terminal_return = decl
        .flow_events
        .iter()
        .rposition(
            |event| matches!(event, FlowEvent::Return { value_text: Some(value), .. } if value == "$data"),
        )
        .expect("terminal data return");

    assert!(
        call_index("File::Spec->catfile") < path_assign,
        "RHS call must evaluate before its write: {:#?}",
        decl.flow_events
    );
    assert!(
        path_assign < call_index("open"),
        "the path write must precede its consumer: {:#?}",
        decl.flow_events
    );
    assert!(
        call_index("open") < terminal_return,
        "an earlier synthesized call must not be discarded as post-return code: {:#?}",
        decl.flow_events
    );
}

#[test]
fn foreach_call_iterable_retains_binding_flow() {
    let src = r#"
sub index ($self) {
    my $raw = $self->param('sort') // 'id';
    my @keys;
    for my $k (split /,/, $raw) {
        $k =~ s/^\s+|\s+$//g;
        push @keys, $k;
    }
    $self->render(json => consume(\@keys));
}
"#;
    let adapter: std::sync::Arc<dyn bonsai_lang_api::LanguageAdapter> =
        std::sync::Arc::new(PerlAdapter::new());
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("handler.pl", src)]);
    let global = ws.db().global_index();
    let decl = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "index")
        .expect("index declaration");

    assert!(
        decl.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_call: Some(call),
                source_call_args,
                ..
            } if target == "$k" && call == "split" && source_call_args.iter().any(|arg| arg == "$raw")
        )),
        "the compiler-proven foreach binding must survive adapter post-processing: {:#?}",
        decl.flow_events
    );
    assert!(
        !decl.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, .. } if name == "m"
        )),
        "a split delimiter is not an implicit match operation: {:#?}",
        decl.flow_events
    );
}

#[test]
fn executable_match_regexp_remains_a_call_fact() {
    let src = r#"
sub allowed {
    my ($value) = @_;
    return $value =~ /safe/;
}
"#;
    let adapter: std::sync::Arc<dyn bonsai_lang_api::LanguageAdapter> =
        std::sync::Arc::new(PerlAdapter::new());
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("matcher.pl", src)]);
    let global = ws.db().global_index();
    let decl = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "allowed")
        .expect("allowed declaration");

    assert!(
        decl.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, .. } if name == "m"
        )),
        "an executable regex match must retain its compiler call fact: {:#?}",
        decl.flow_events
    );
}

#[test]
fn external_boundary_call_shapes_are_exact_compiler_facts() {
    let src = r#"
use DBI;
use Net::AMQP::RabbitMQ;
use Kafka::Consumer;
use Amazon::S3::Thin;
use Device::SerialPort;
use Device::BCM2835;
sub boundaries {
    my ($connection) = @_;
    my $dbh = DBI->connect('dbi:SQLite:dbname=app.db');
    my $sth = $dbh->prepare('select name from users');
    my $row = $sth->fetchrow_arrayref();
    my $rabbit = Net::AMQP::RabbitMQ->new();
    my $delivery = $rabbit->recv(5);
    my $consumer = Kafka::Consumer->new(Connection => $connection);
    my $messages = $consumer->fetch('events', 0, 0, 1048576);
    my $thin = Amazon::S3::Thin->new({ aws_access_key_id => 'key' });
    my $object = $thin->get_object('uploads', 'incoming.json');
    my $port = Device::SerialPort->new('/dev/ttyUSB0');
    my ($count, $bytes) = $port->read(128);
    my $gpio = Device::BCM2835::gpio_lev(7);
    return ($row, $delivery, $messages, $object, $bytes, $gpio);
}
"#;
    let adapter: std::sync::Arc<dyn bonsai_lang_api::LanguageAdapter> =
        std::sync::Arc::new(PerlAdapter::new());
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("boundaries.pl", src)]);
    let global = ws.db().global_index();
    let boundaries = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "boundaries")
        .expect("boundaries declaration");
    let mut calls = Vec::new();
    calls_below(&boundaries.flow_events, &mut calls);
    let actual = calls
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call {
                name,
                receiver,
                call_kind,
                args,
                ..
            } => Some((name.as_str(), receiver.as_deref(), *call_kind, args.len())),
            _ => None,
        })
        .collect::<Vec<_>>();

    for expected in [
        ("DBI->connect", Some("DBI"), CallKind::Method, 1),
        ("dbh->prepare", Some("dbh"), CallKind::Method, 1),
        ("sth->fetchrow_arrayref", Some("sth"), CallKind::Method, 0),
        (
            "Net::AMQP::RabbitMQ->new",
            Some("Net::AMQP::RabbitMQ"),
            CallKind::Constructor,
            0,
        ),
        ("rabbit->recv", Some("rabbit"), CallKind::Method, 1),
        (
            "Kafka::Consumer->new",
            Some("Kafka::Consumer"),
            CallKind::Constructor,
            1,
        ),
        ("consumer->fetch", Some("consumer"), CallKind::Method, 4),
        (
            "Amazon::S3::Thin->new",
            Some("Amazon::S3::Thin"),
            CallKind::Constructor,
            1,
        ),
        ("thin->get_object", Some("thin"), CallKind::Method, 2),
        (
            "Device::SerialPort->new",
            Some("Device::SerialPort"),
            CallKind::Constructor,
            1,
        ),
        ("port->read", Some("port"), CallKind::Method, 1),
        ("Device::BCM2835::gpio_lev", None, CallKind::Function, 1),
    ] {
        assert!(
            actual.contains(&expected),
            "missing exact call {expected:?}; got {actual:#?}"
        );
    }

    assert!(
        boundaries.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign { target, source_call: Some(call), .. }
                if target == "$bytes" && call == "port->read"
        )),
        "list-context assignment must bind the second result to $bytes: {:#?}",
        boundaries.flow_events
    );
}

#[test]
fn use_qw_exports_emit_resolution_local_member_imports() {
    let imports = parse_import_specs("use AuthService qw(verify_token run_admin_command);\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "AuthService"
            && spec.alias.is_none()
            && spec.original_name.is_none()
            && spec.scope == ImportScope::Module
    }));
    for exported in ["verify_token", "run_admin_command"] {
        assert!(
            imports.iter().any(|spec| {
                spec.module == "AuthService"
                    && spec.alias.is_none()
                    && spec.original_name.as_deref() == Some(exported)
                    && spec.scope == ImportScope::Local
            }),
            "missing resolver-local Perl import for {exported}"
        );
    }
}

#[test]
fn inheritance_pragmas_do_not_emit_callable_member_imports() {
    let imports = parse_import_specs("use parent qw(BaseRole OtherRole);\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "parent"
            && spec.alias.is_none()
            && spec.original_name.is_none()
            && spec.scope == ImportScope::Module
    }));
    assert!(
        imports.iter().all(|spec| spec.scope != ImportScope::Local),
        "inheritance pragmas should not create callable import aliases: {imports:?}"
    );
}

#[test]
fn coderef_assignment_emits_clean_callable_alias() {
    let src = "my $cb = \\&helper;";
    let (span, assignment_values) = assignment_fixture(src);
    let event = FlowEvent::Assign {
        span,
        target: "$cb".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["helper".to_string()],
        declares_new_binding: true,
        value_kind: None,
    };

    let alias = perl_coderef_alias_assignment(&event, src, &assignment_values).expect("coderef alias");

    assert!(matches!(
        alias,
        FlowEvent::Assign {
            target,
            source_name: Some(source),
            source_call: None,
            source_names,
            ..
        } if target == "$cb" && source == "helper" && source_names.is_empty()
    ));
}

#[test]
fn coderef_call_argument_emits_exact_callable_place() {
    let mut events = vec![FlowEvent::Call {
        span: Span::new(FileId::new(0), 0, 18),
        name: "invoke".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: Span::new(FileId::new(0), 7, 15),
            name: None,
            value_text: "\\&helper".to_string(),
            place: None,
            source_names: vec!["helper".to_string()],
        }],
    }];

    rewrite_perl_call_arg_texts(&mut events, "");

    assert!(matches!(
        events.as_slice(),
        [FlowEvent::Call { name, args, .. }]
            if name == "invoke"
                && args.first().is_some_and(|arg| {
                    arg.value_text == "helper"
                        && arg.place.as_deref() == Some("helper")
                        && arg.source_names == ["helper"]
                })
    ));
}

#[test]
fn direct_array_argv_binding_infers_perl_param() {
    let src = "my @items = @_;";
    let (span, assignment_values) = assignment_fixture(src);
    let event = FlowEvent::Assign {
        span,
        target: "items".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["_".to_string()],
        declares_new_binding: true,
        value_kind: None,
    };

    let (_, vars) = perl_list_binding_at(&event, src, &assignment_values).expect("direct @_ binding");

    assert_eq!(vars, vec!["@items".to_string()]);
}

#[test]
fn map_grep_topic_call_rewrites_topic_arg_to_collection() {
    let src = "sub handle { my @items = @_; map { step($_); } @items; }";
    let language = language_from_pack(PACK_NAME).expect("perl grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set perl grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse perl source");

    let events = synthesize_map_grep_topic_call_events(&tree, src.as_bytes(), FileId::new(0));

    assert!(events.iter().any(|(_, event)| {
        matches!(
            event,
            FlowEvent::Call { name, args, .. }
                if name == "step"
                    && args
                        .iter()
                        .any(|arg| arg.value_text == "@items"
                            && arg.source_names == vec!["@items".to_string(), "items".to_string()])
        )
    }));
}

#[test]
fn eval_die_dollar_at_rewrites_to_try_throw_alias_catch() {
    let src = "sub handle { my $token = shift; eval { die $token; }; if ($@) { my $e = $@; sink($e); } }\nsub sink { my ($s) = @_; }\n";
    let adapter: std::sync::Arc<dyn bonsai_lang_api::LanguageAdapter> =
        std::sync::Arc::new(PerlAdapter::new());
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("app.pl", src)]);
    let global = ws.db().global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle decl");
    let (_, assignment_values) = assignment_fixture(src);

    let (body, catch_events, catch_param) = handle
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Try {
                body,
                catch_events,
                catch_param,
                ..
            } => Some((body, catch_events, catch_param)),
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!(
                "eval/die should lower to Try; emitted events: {:#?}",
                handle.flow_events
            )
        });

    assert_eq!(
        catch_param.as_deref(),
        Some("$e"),
        "events={:#?}; assignments={:#?}",
        handle.flow_events,
        assignment_values
    );
    assert!(
        body.iter().any(|event| matches!(
            event,
            FlowEvent::Throw {
                value_name: Some(value),
                ..
            } if value == "$token"
        )),
        "try body should contain a Throw carrying $token: {body:#?}"
    );
    assert!(
        catch_events
            .iter()
            .all(|event| !matches!(event, FlowEvent::Assign { span, .. }
                if perl_assignment_rhs_is_dollar_at(src, *span, &assignment_values))),
        "the `$@` alias assignment should become the catch binding: {catch_events:#?}"
    );
    assert!(
        catch_events
            .iter()
            .any(|event| matches!(event, FlowEvent::Call { name, .. } if name == "sink")),
        "catch body should retain the sink call: {catch_events:#?}"
    );
}

#[test]
fn simple_scalar_assignment_rewrites_to_exact_source_name() {
    let src = "my $y = $x;";
    let (span, assignment_values) = assignment_fixture(src);
    let mut events = vec![FlowEvent::Assign {
        span,
        target: "$y".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["x".to_string()],
        declares_new_binding: true,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
    }];

    normalize_perl_simple_scalar_renames(&mut events, src, &assignment_values);

    // Normalizing `my $y = $x` to an EXACT scalar rename rewrites the
    // compound `source_names: ["x"]` shape into `source_name: Some("$x")`
    // and clears `value_kind` — it is no longer a compound expression but
    // a single-variable copy (see `normalize_perl_simple_scalar_renames`,
    // which sets `*value_kind = None`).
    assert!(matches!(
        &events[0],
        FlowEvent::Assign {
            source_name: Some(source),
            source_names,
            value_kind: None,
            ..
        } if source == "$x" && source_names.is_empty()
    ));
}

#[test]
fn scalar_deref_assignment_stays_compound() {
    let src = "my $y = $obj->{token};";
    let (span, assignment_values) = assignment_fixture(src);
    let mut events = vec![FlowEvent::Assign {
        span,
        target: "$y".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["$obj".to_string(), "$obj.token".to_string()],
        declares_new_binding: true,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
    }];

    normalize_perl_simple_scalar_renames(&mut events, src, &assignment_values);

    assert!(matches!(
        &events[0],
        FlowEvent::Assign {
            source_name: None,
            source_names,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
            ..
        } if !source_names.is_empty()
    ));
}

#[test]
fn anonymous_hash_assignment_emits_field_scoped_writes() {
    let src = "my $envelope = { kind => 'run', cmd => \"$raw\", user => $user, clean => 'ok' };";
    let (span, _) = assignment_fixture(src);
    let tree = parse_perl_tree(src);
    let mut events = vec![FlowEvent::Assign {
        span,
        target: "$envelope".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["raw".to_string(), "user".to_string()],
        declares_new_binding: true,
        value_kind: Some(AssignValueKind::Compound),
    }];

    expand_perl_anonymous_hash_field_assigns(&mut events, &tree, src.as_bytes());

    assert!(
        events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign { target, source_names, .. }
                if target == "$envelope.cmd"
                    && source_names.contains(&"$raw".to_string())
                    && source_names.contains(&"raw".to_string())
        )),
        "hash cmd field should retain only its exact value sources: {events:#?}"
    );
    assert!(events.iter().any(|event| matches!(
        event,
        FlowEvent::Assign { target, source_names, .. }
            if target == "$envelope.user"
                && source_names.contains(&"$user".to_string())
                && source_names.contains(&"user".to_string())
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        FlowEvent::Assign { target, source_names, value_kind, .. }
            if target == "$envelope.clean"
                && source_names.is_empty()
                && *value_kind == Some(AssignValueKind::Literal)
    )));
}

#[test]
fn uncaught_die_lowers_to_throw_in_sub_body() {
    // L1: a `die` outside any `eval {}; if ($@)` region must still
    // lower to a Throw so the catch param of a native try (and
    // cross-procedural exception propagation of an uncaught die) is
    // modelled. RED before: the whole-body lowering does not run, so
    // `die $msg` stays a plain Call and no Throw is emitted.
    let src = "sub risky { my ($msg) = @_; die $msg; }\n";
    let adapter: std::sync::Arc<dyn bonsai_lang_api::LanguageAdapter> =
        std::sync::Arc::new(PerlAdapter::new());
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("app.pl", src)]);
    let global = ws.db().global_index();
    let risky = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "risky")
        .expect("risky decl");

    assert!(
        risky.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Throw {
                value_name: Some(value),
                ..
            } if value == "$msg"
        )),
        "an uncaught die should lower to a Throw at sub-body top level: {:#?}",
        risky.flow_events
    );
}

#[test]
fn method_call_emits_single_call_event() {
    // L8: `$obj->method(...)` must produce exactly ONE Call event.
    // The kit emits a Call for the `method_call_expression`
    // (name-span = the `method` identifier) and the adapter's
    // `synthesize_method_call_events` emits a second over the whole
    // node. The dedup drops the synth duplicate (kit Call's name-span
    // is CONTAINED in the synth's whole-node span, same name +
    // receiver). RED before: two `obj->process` Call events.
    let src = "sub entry { my ($obj) = @_; $obj->process($obj); }\n";
    let adapter: std::sync::Arc<dyn bonsai_lang_api::LanguageAdapter> =
        std::sync::Arc::new(PerlAdapter::new());
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("app.pl", src)]);
    let global = ws.db().global_index();
    let entry = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "entry")
        .expect("entry decl");

    let process_calls = entry
        .flow_events
        .iter()
        .filter(|event| {
            matches!(
                event,
                FlowEvent::Call { name, .. } if name == "obj->process"
            )
        })
        .count();
    assert_eq!(
        process_calls, 1,
        "`$obj->process(...)` should emit exactly one Call event: {:#?}",
        entry.flow_events
    );
}

#[test]
fn package_subroutine_calls_are_static_functions_not_method_dispatch() {
    let app = r#"
require "./pipeline.pl";
sub entry {
    my ($obj, $value) = @_;
    Pipeline::orchestrate($value);
    $obj->orchestrate($value);
}
"#;
    let adapter: std::sync::Arc<dyn bonsai_lang_api::LanguageAdapter> =
        std::sync::Arc::new(PerlAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[
            ("app.pl", app),
            (
                "pipeline.pl",
                "package Pipeline; sub orchestrate { my ($value) = @_; return $value; }\n",
            ),
        ],
    );
    let global = ws.db().global_index();
    let entry = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "entry")
        .expect("entry decl");

    assert!(
        entry.flow_events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Call {
                    name,
                    receiver: None,
                    call_kind: CallKind::Function,
                    ..
                } if name == "Pipeline::orchestrate"
            )
        }),
        "qualified Perl subroutine calls must use static function semantics: {:#?}",
        entry.flow_events
    );
    assert!(
        entry.flow_events.iter().any(|event| {
            matches!(
                event,
                FlowEvent::Call {
                    name,
                    call_kind: CallKind::Method,
                    ..
                } if name == "obj->orchestrate"
            )
        }),
        "arrow dispatch must remain a Perl method call: {:#?}",
        entry.flow_events
    );

    let target = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "orchestrate")
        .expect("target decl");
    let package = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Pipeline")
        .expect("package declaration");
    assert_eq!(package.kind, DeclKind::Module);
    assert_eq!(target.kind, DeclKind::Function);
    let call_graph = ws.resolved_call_graph();
    assert!(
        call_graph
            .callees_of(bonsai_common::FuncId::new(entry.symbol.raw()))
            .any(|edge| edge.to == bonsai_common::FuncId::new(target.symbol.raw())),
        "the static package call must resolve to the declared Perl subroutine; target={target:#?}; events={:#?}",
        entry.flow_events
    );
}

#[test]
fn oo_package_and_isa_drive_typed_arrow_dispatch() {
    let adapter: std::sync::Arc<dyn bonsai_lang_api::LanguageAdapter> =
        std::sync::Arc::new(PerlAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[
            (
                "Base.pm",
                "package Base;\nsub helper { my ($self, $p) = @_; sink($p); }\n1;\n",
            ),
            (
                "entry.pl",
                "use Base;\npackage Child;\nour @ISA = ('Base');\npackage main;\n\
                 sub entry { my ($args) = @_; my $obj = bless {}, 'Child'; $obj->helper($args); }\n",
            ),
        ],
    );
    let global = ws.db().global_index();
    let base = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Base" && decl.kind == DeclKind::Class)
        .expect("method-bearing package should be a class");
    let helper = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "helper")
        .expect("base helper");
    assert_eq!(helper.parent, Some(base.symbol));

    let child = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Child" && decl.kind == DeclKind::Class)
        .expect("@ISA package should be a class");
    assert_eq!(child.bases, ["Base"]);
    let entry = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "entry")
        .expect("entry declaration");
    let call = entry
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call {
                name, receiver_types, ..
            } if name == "obj->helper" => Some(receiver_types),
            _ => None,
        })
        .expect("arrow call");
    assert_eq!(call, &["Child", "Base"]);

    let call_graph = ws.resolved_call_graph();
    assert!(
        call_graph
            .callees_of(bonsai_common::FuncId::new(entry.symbol.raw()))
            .any(|edge| edge.to == bonsai_common::FuncId::new(helper.symbol.raw())),
        "typed Perl inheritance should resolve the base method"
    );
}

#[test]
fn qualified_oo_package_assignment_alias_resolves_exact_method_dispatch() {
    let adapter: std::sync::Arc<dyn bonsai_lang_api::LanguageAdapter> =
        std::sync::Arc::new(PerlAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[
            (
                "lib/Domain/Repository.pm",
                "package Domain::Repository;\n\
                 sub new { my ($class, $value) = @_; return bless { value => $value }, $class; }\n\
                 sub run { my ($self) = @_; return $self->{value}; }\n1;\n",
            ),
            (
                "lib/Storage.pm",
                "use Domain::Repository;\n\
                 sub persist { my ($value) = @_; my $repository = Domain::Repository->new($value);\n\
                 my $alias = $repository; return $alias->run(); }\n1;\n",
            ),
        ],
    );
    let global = ws.db().global_index();
    let persist = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "persist")
        .expect("persist declaration");
    let run = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "run")
        .expect("run declaration");
    assert!(
        persist.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, receiver_types, .. }
                if name == "alias->run" && receiver_types == &["Domain::Repository"]
        )),
        "the exact assignment alias must retain the constructed receiver type: {:#?}",
        persist.flow_events
    );

    let call_graph = ws.resolved_call_graph();
    assert!(
        call_graph
            .callees_of(bonsai_common::FuncId::new(persist.symbol.raw()))
            .any(|edge| edge.to == bonsai_common::FuncId::new(run.symbol.raw())),
        "the exact typed alias must resolve to the qualified package method"
    );
}
