use super::{
    annotate_tuple_call_result_bindings, apply_assign_call_result_types, apply_call_receiver_types,
    apply_constructor_result_type_aliases, argument_place, build_call_event, canonical_simple_type_name,
    collect_kinds, expression_flow_from_node, extract_return_value_name, extract_rhs_expr_operands,
    language_from_pack, node_text, normalize_call_name_whitespace, normalize_call_result_assignment_sources,
    package_module_segments_with_workspace_prefix, receiver_projected_alias_matches, GENERIC_HANDLER,
    SYNTHETIC_TUPLE_RESULT_PREFIX,
};
use crate::{
    AssignValueKind, CallArg, CallKind, Decl, DeclIndex, DeclKind, FlowEvent, ModulePath, Visibility,
};
use bonsai_common::{FileId, Span, SymbolId};

#[test]
fn tuple_call_result_bindings_keep_source_positions() {
    let src = "{a, _b} = helper(x)";
    let span = Span::new(FileId::new(0), 0, src.len() as u64);
    let mut events = vec![
        FlowEvent::Assign {
            span,
            target: "_b".to_string(),
            source_name: None,
            source_call: Some("helper".to_string()),
            source_call_args: vec!["x".to_string()],
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::CallResult),
        },
        FlowEvent::Assign {
            span,
            target: "a".to_string(),
            source_name: None,
            source_call: Some("helper".to_string()),
            source_call_args: vec!["x".to_string()],
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::CallResult),
        },
    ];

    annotate_tuple_call_result_bindings(&mut events, src);
    assert!(matches!(
        &events[0],
        FlowEvent::Assign { source_names, .. }
            if source_names == &[format!("{SYNTHETIC_TUPLE_RESULT_PREFIX}1")]
    ));
    assert!(matches!(
        &events[1],
        FlowEvent::Assign { source_names, .. }
            if source_names == &[format!("{SYNTHETIC_TUPLE_RESULT_PREFIX}0")]
    ));
}

#[test]
fn receiver_projected_alias_matches_tuple_field_chains_only() {
    assert!(receiver_projected_alias_matches("repo.0", "repo"));

    assert!(!receiver_projected_alias_matches("r.Header", "r"));
    assert!(!receiver_projected_alias_matches("r.Header.Get", "r"));
    assert!(!receiver_projected_alias_matches("r", "r"));
    assert!(!receiver_projected_alias_matches("other.r", "r"));
    assert!(!receiver_projected_alias_matches("r.Header()", "r"));
}

#[test]
fn call_name_normalization_compacts_multiline_dotted_chains() {
    assert_eq!(
        normalize_call_name_whitespace(
            "org.owasp\n        .esapi\n        .ESAPI\n        .encoder()\n        .encodeForHTML"
        ),
        "org.owasp.esapi.ESAPI.encoder().encodeForHTML"
    );
    assert_eq!(
        normalize_call_name_whitespace("Command::new(\"sh\")\n    .arg(\"-c\")\n    .output"),
        "Command::new(\"sh\").arg(\"-c\").output"
    );
}

#[test]
fn call_result_assignment_pruning_removes_callee_and_arg_carriers() {
    let mut events = vec![assign_call(
        "z",
        "f",
        &["user.name"],
        &["f", "user.name", "user", "name"],
    )];

    normalize_call_result_assignment_sources(&mut events);

    let FlowEvent::Assign {
        source_name,
        source_names,
        ..
    } = &events[0]
    else {
        panic!("expected assign event")
    };
    assert_eq!(source_name.as_deref(), None);
    assert!(source_names.is_empty());
}

#[test]
fn call_result_assignment_pruning_preserves_method_receivers() {
    let mut events = vec![assign_call(
        "ok",
        "target.call",
        &["payload"],
        &["target.call", "target", "call", "payload"],
    )];

    normalize_call_result_assignment_sources(&mut events);

    let FlowEvent::Assign { source_names, .. } = &events[0] else {
        panic!("expected assign event")
    };
    assert_eq!(source_names.as_slice(), ["target"]);
}

#[test]
fn call_result_assignment_pruning_preserves_static_factory_type_hints() {
    let mut events = vec![assign_call(
        "logger",
        "Logger.getLogger",
        &["name"],
        &["Logger", "Logger.getLogger", "getLogger", "name"],
    )];

    normalize_call_result_assignment_sources(&mut events);

    let FlowEvent::Assign { source_names, .. } = &events[0] else {
        panic!("expected assign event")
    };
    assert_eq!(source_names.as_slice(), ["Logger", "getLogger"]);
}

#[test]
fn call_result_assignment_normalization_recovers_adjacent_call_args() {
    let mut events = vec![assign_call("z", "f", &[], &["f", "x"]), call("f", &["x"])];

    normalize_call_result_assignment_sources(&mut events);

    let FlowEvent::Assign {
        source_call_args,
        source_names,
        ..
    } = &events[0]
    else {
        panic!("expected assign event")
    };
    assert_eq!(source_call_args.as_slice(), ["x"]);
    assert!(source_names.is_empty());
}

#[test]
fn call_result_assignment_normalization_uses_assignment_span_not_event_window() {
    let mut events = vec![assign_call("z", "f", &[], &["f", "x"])];
    events.extend((0..4).map(|_| call("unrelated", &[])));
    events.push(call("f", &["x"]));

    normalize_call_result_assignment_sources(&mut events);

    let FlowEvent::Assign {
        source_call_args,
        source_names,
        ..
    } = &events[0]
    else {
        panic!("expected assign event")
    };
    assert_eq!(source_call_args.as_slice(), ["x"]);
    assert!(source_names.is_empty());
}

#[test]
fn return_value_name_uses_structured_syntax_before_text_fallback() {
    let language = language_from_pack("python").expect("python grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set python grammar");
    let src = b"def a(token):\n    return token\n\ndef b():\n    return None\n";
    let tree = parser.parse(src, None).expect("parse python");
    let mut returns = collect_kinds(&tree, &["return_statement"]);
    returns.sort_by_key(tree_sitter::Node::start_byte);

    assert_eq!(returns.len(), 2);
    assert_eq!(
        extract_return_value_name(&returns[0], src).as_deref(),
        Some("token")
    );
    assert_eq!(
        extract_return_value_name(&returns[1], src),
        None,
        "literal return nodes must not become value-bearing identifier reads"
    );
}

#[test]
fn literal_keywords_are_not_argument_places_or_return_value_names() {
    let swift = language_from_pack("swift").expect("swift grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&swift).expect("set swift grammar");
    let src = b"func f() -> String? { g(nil); return nil }\n";
    let tree = parser.parse(src, None).expect("parse swift");

    let returns = collect_kinds(&tree, &["control_transfer_statement"]);
    assert_eq!(returns.len(), 1);
    assert_eq!(extract_return_value_name(&returns[0], src), None);
    let nil_arg = collect_kinds(&tree, &["value_argument"])
        .into_iter()
        .find(|node| node_text(node, src).trim() == "nil")
        .expect("nil value_argument");
    assert_eq!(argument_place(&nil_arg, src), None);

    let cpp = language_from_pack("cpp").expect("cpp grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&cpp).expect("set cpp grammar");
    let src = b"void f() { g(nullptr); }\n";
    let tree = parser.parse(src, None).expect("parse cpp");
    let null_arg = collect_kinds(&tree, &["null"])
        .into_iter()
        .next()
        .expect("nullptr null node");
    assert_eq!(argument_place(&null_arg, src), None);
}

fn assign_call(target: &str, source_call: &str, args: &[&str], sources: &[&str]) -> FlowEvent {
    FlowEvent::Assign {
        span: Span::new(FileId::INVALID, 0, 0),
        target: target.to_string(),
        source_name: Some(source_call.to_string()),
        source_call: Some(source_call.to_string()),
        source_call_args: args.iter().map(|arg| (*arg).to_string()).collect(),
        source_names: sources.iter().map(|source| (*source).to_string()).collect(),
        declares_new_binding: false,
        value_kind: Some(AssignValueKind::CallResult),
    }
}

fn call(name: &str, args: &[&str]) -> FlowEvent {
    FlowEvent::Call {
        span: Span::new(FileId::INVALID, 0, 0),
        name: name.to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: args
            .iter()
            .map(|arg| CallArg {
                passing_mode: Default::default(),
                span: Span::new(FileId::INVALID, 0, 0),
                name: None,
                value_text: (*arg).to_string(),
                place: Some((*arg).to_string()),
                source_names: vec![(*arg).to_string()],
            })
            .collect(),
    }
}

// audit re-apply: H1 + H7-guard: pure-helper unit tests matching the existing

#[test]
fn compound_assignment_operators_detected() {
    use super::is_compound_assignment_operator;
    for op in [
        "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", "**=", ".=", "||=", "&&=", "??=",
    ] {
        assert!(is_compound_assignment_operator(op), "{op} should be compound");
    }
    for op in ["=", "==", "!=", "<=", ">=", ":=", "=>"] {
        assert!(
            !is_compound_assignment_operator(op),
            "{op} should NOT be compound"
        );
    }
}

#[test]
fn receiver_projection_base_extracts_leftmost_token() {
    use super::receiver_projection_base;
    assert_eq!(receiver_projection_base("this.conn"), "this");
    assert_eq!(receiver_projection_base("self.conn"), "self");
    assert_eq!(receiver_projection_base("pool.conn"), "pool");
    assert_eq!(receiver_projection_base("a->b->c"), "a");
    assert_eq!(receiver_projection_base("Foo::bar"), "Foo");
    assert_eq!(receiver_projection_base("conn"), "conn");
}

#[test]
fn package_module_segments_keep_sibling_projects_distinct() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let vfs = Vfs::new();
    let root = std::env::temp_dir().join("bonsai-package-module-prefix");
    let first = vfs.write(root.join("flow_a/src/main/java/mega/App.java"), "");
    let second = vfs.write(root.join("flow_b/src/main/java/mega/App.java"), "");
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = crate::AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: Some(&root),
    };

    assert_eq!(
        package_module_segments_with_workspace_prefix(first, &ctx, ["mega"]),
        vec!["flow_a".to_string(), "mega".to_string()]
    );
    assert_eq!(
        package_module_segments_with_workspace_prefix(second, &ctx, ["mega"]),
        vec!["flow_b".to_string(), "mega".to_string()]
    );
}

#[test]
fn package_module_segments_preserve_plain_fixture_packages() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let vfs = Vfs::new();
    let root = std::env::temp_dir().join("bonsai-package-module-plain");
    let file = vfs.write(root.join("App.java"), "");
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = crate::AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: Some(&root),
    };

    assert_eq!(
        package_module_segments_with_workspace_prefix(file, &ctx, ["mega"]),
        vec!["mega".to_string()]
    );
}

#[test]
fn parse_with_reuses_context_canonical_tree() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;
    use std::sync::Arc;

    struct Provider(Arc<crate::SyntaxTree>);
    impl crate::TreeProvider for Provider {
        fn tree_for_snapshot(
            &self,
            pack_name: &str,
            snapshot: &bonsai_vfs::FileSnapshot,
        ) -> Option<Arc<crate::SyntaxTree>> {
            assert_eq!(pack_name, "java");
            assert_eq!(snapshot.file_id, FileId::new(0));
            Some(Arc::clone(&self.0))
        }
    }

    let vfs = Vfs::new();
    let file = vfs.write("Cached.java", "class Cached {}");
    let snapshot = vfs.snapshot(file).expect("snapshot");
    let language = language_from_pack("java").expect("java grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set language");
    let canonical = Arc::new(
        parser
            .parse(snapshot.text.as_bytes(), None)
            .expect("canonical parse"),
    );
    let provider = Provider(Arc::clone(&canonical));
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = crate::AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: Some(&provider),
        workspace_root: None,
    };

    let (_, first) = super::parse_with("java", file, &ctx).expect("first parse");
    let (_, second) = super::parse_with("java", file, &ctx).expect("second parse");
    assert!(Arc::ptr_eq(&canonical, &first));
    assert!(Arc::ptr_eq(&canonical, &second));
}

// audit M9: `apply_assign_call_result_types` must fail closed when two
// same-named functions/overloads have differing return types -- a name-only
// lookup is then unknowable and a last-writer-wins alias drives bogus
// [Type, method] matching.
#[test]
fn call_result_types_fail_closed_on_same_name_overload_conflict() {
    let mut idx = DeclIndex::default();
    idx.defs.push(m9_func_decl(0, "make", Some("Foo"), Vec::new()));
    idx.defs.push(m9_func_decl(1, "make", Some("Bar"), Vec::new()));
    idx.defs.push(m9_func_decl(2, "single", Some("Baz"), Vec::new()));
    idx.defs.push(m9_func_decl(
        3,
        "consumer",
        None,
        vec![
            assign_call("y", "make", &[], &["make"]),
            assign_call("z", "single", &[], &["single"]),
        ],
    ));

    apply_assign_call_result_types(&mut idx);

    let consumer = idx.defs.iter().find(|d| d.name == "consumer").unwrap();
    assert!(
        !consumer.type_aliases.iter().any(|a| a.name == "y"),
        "ambiguous overload `make` must not stamp an alias on `y`, got {:?}",
        consumer.type_aliases
    );
    assert!(
        consumer
            .type_aliases
            .iter()
            .any(|a| a.name == "z" && a.type_name == "Baz"),
        "unique callee `single` must still stamp z -> Baz, got {:?}",
        consumer.type_aliases
    );
}

#[test]
fn constructor_result_typing_handles_source_call_and_adjacent_new_call() {
    let file = FileId::new(0);
    let sp = |lo: u64, hi: u64| Span::new(file, lo, hi);
    let assign = |target: &str, source_call: Option<&str>, span: Span| FlowEvent::Assign {
        span,
        target: target.to_string(),
        source_name: None,
        source_call: source_call.map(str::to_string),
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: Some(AssignValueKind::Compound),
    };
    let call = |name: &str, span: Span| FlowEvent::Call {
        span,
        name: name.to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: Vec::new(),
    };

    let mut idx = DeclIndex::default();
    idx.defs.push(m9_func_decl(
        0,
        "handler",
        None,
        vec![
            // `source_call` languages (Python/Java/C#/Go): `conn = Connection(...)`.
            assign("conn", Some("Connection"), sp(10, 30)),
            // Perl/Ruby-style class constructor methods should type the
            // receiver as the owner, not as the method call tail.
            assign("obj", Some("Util->new"), sp(31, 39)),
            // JS/TS shape: `const client = new ApolloClient({})` is an
            // Assign with no source_call plus a sibling constructor Call
            // whose span lies inside the assignment's RHS.
            assign("client", None, sp(40, 80)),
            call("ApolloClient", sp(56, 78)),
            // Negative: an Assign with no source_call followed by an
            // UNRELATED constructor call outside its span must not type it.
            assign("misc", None, sp(90, 100)),
            call("Helper", sp(120, 140)),
        ],
    ));

    apply_constructor_result_type_aliases(&mut idx);
    let decl = &idx.defs[0];
    let typed = |name: &str| {
        decl.type_aliases
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.type_name.as_str())
    };
    assert_eq!(typed("conn"), Some("Connection"), "{:?}", decl.type_aliases);
    assert_eq!(typed("obj"), Some("Util"), "{:?}", decl.type_aliases);
    assert_eq!(
        typed("client"),
        Some("ApolloClient"),
        "adjacent new-expr Call within assign span must type the receiver: {:?}",
        decl.type_aliases
    );
    assert_eq!(
        typed("misc"),
        None,
        "a constructor call outside the assign span must not type the target: {:?}",
        decl.type_aliases
    );
}

#[test]
fn receiver_type_uses_declared_class_facts_without_factory_name_knowledge() {
    let mut idx = DeclIndex::default();
    let mut child = m9_func_decl(0, "Child", None, Vec::new());
    child.kind = DeclKind::Class;
    let arbitrary_factory_call = |receiver: &str| FlowEvent::Call {
        span: Span::new(FileId::new(0), 10, 20),
        name: format!("{receiver}.consume"),
        receiver: Some(receiver.to_string()),
        receiver_types: Vec::new(),
        call_kind: CallKind::Method,
        args: Vec::new(),
    };
    idx.defs.push(child);
    idx.defs.push(m9_func_decl(
        1,
        "entry",
        None,
        vec![
            arbitrary_factory_call("Child()"),
            arbitrary_factory_call("Child.fabricate"),
            arbitrary_factory_call("package.Child(value)"),
        ],
    ));

    apply_call_receiver_types(&mut idx);
    let entry = idx.defs.iter().find(|decl| decl.name == "entry").unwrap();
    assert!(entry.flow_events.iter().all(|event| {
        matches!(
            event,
            FlowEvent::Call { receiver_types, .. } if receiver_types == &["Child"]
        )
    }));
}

#[test]
fn address_arguments_emit_writeback_mode_from_ast_nodes() {
    for (pack, source) in [
        ("c", "void f(void) { int out; helper(&out); }"),
        ("cpp", "void f() { int out; helper(&out); }"),
        (
            "csharp",
            "class C { void F() { string result; helper(out result); } }",
        ),
        ("go", "package p\nfunc f() { var out string; helper(&out) }"),
        ("objc", "void f(void) { id out; helper(&out); }"),
        (
            "rust",
            "fn f() { let mut out = String::new(); helper(&mut out); }",
        ),
    ] {
        let language = language_from_pack(pack).expect("language pack");
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("set language");
        let tree = parser.parse(source, None).expect("parse");
        let event = collect_kinds(&tree, &["call_expression", "invocation_expression", "call"])
            .into_iter()
            .filter_map(|node| {
                build_call_event(node, FileId::new(0), source.as_bytes(), &GENERIC_HANDLER, &[])
            })
            .find(|event| matches!(event, FlowEvent::Call { name, .. } if name == "helper"))
            .unwrap_or_else(|| panic!("{pack}: helper call"));
        let FlowEvent::Call { args, .. } = event else {
            unreachable!();
        };
        assert_eq!(args.len(), 1, "{pack}: {args:?}");
        assert_eq!(
            args[0].passing_mode,
            crate::ArgumentPassingMode::WriteBack,
            "{pack}: {args:?}"
        );
        let expected_place = if pack == "csharp" { "result" } else { "out" };
        assert_eq!(args[0].place.as_deref(), Some(expected_place), "{pack}: {args:?}");
    }
}

#[test]
fn rust_match_result_dependencies_come_from_arm_ast_values() {
    let source = r#"fn f(kind: Kind, joined: String) {
        let routed: String = match kind {
            Kind::Run => format!("{}", joined),
            Kind::Eval => joined.trim().to_string(),
        };
    }"#;
    let language = language_from_pack("rust").expect("Rust language pack");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set Rust language");
    let tree = parser.parse(source, None).expect("parse Rust match");
    let match_expr = collect_kinds(&tree, &["match_expression"])
        .into_iter()
        .next()
        .expect("match expression");

    let operands = extract_rhs_expr_operands(&match_expr, source.as_bytes());
    assert!(
        operands.iter().any(|operand| operand == "joined"),
        "both macro-token-tree and method-receiver arm values must retain the joined dependency: {operands:?}"
    );
}

#[test]
fn rust_shorthand_struct_initializer_is_an_exact_aggregate_field() {
    let source = "fn make(data: Envelope) -> Self { Self { data } }";
    let language = language_from_pack("rust").expect("Rust language pack");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set Rust language");
    let tree = parser.parse(source, None).expect("parse Rust struct expression");
    let expression = collect_kinds(&tree, &["struct_expression"])
        .into_iter()
        .next()
        .expect("struct expression");

    let flow = expression_flow_from_node(expression, FileId::new(0), source.as_bytes());
    assert_eq!(flow.aggregate_fields.len(), 1, "{flow:?}");
    assert_eq!(flow.aggregate_fields[0].name, "data");
    assert_eq!(flow.aggregate_fields[0].value.place.as_deref(), Some("data"));
}

fn m9_func_decl(raw: u32, name: &str, return_type: Option<&str>, flow_events: Vec<FlowEvent>) -> Decl {
    Decl {
        symbol: SymbolId::new(raw),
        kind: DeclKind::Function,
        name: name.to_string(),
        qualified_name: None,
        module_path: ModulePath::default(),
        span: Span::new(FileId::INVALID, 0, 0),
        name_span: Span::new(FileId::INVALID, 0, 0),
        visibility: Visibility::Public,
        parent: None,
        body_span: None,
        flow_events,
        has_implicit_returns: false,
        params: Vec::new(),
        param_annotations: Vec::new(),
        type_aliases: Vec::new(),
        bases: Vec::new(),
        receiver_param_index: None,
        receiver_field_writes: Vec::new(),
        implicit_receiver_names: Vec::new(),
        receiver_state_sources: Vec::new(),
        return_type: return_type.map(str::to_string),
        is_variadic: false,
    }
}

// audit L3: `canonical_simple_type_name` must strip array / nullable /
// force-unwrap / pointer / reference decorations (mirroring
// `canonical_short_type_name`) so a decorated return type resolves to the
// class indexed under its bare name for base-class expansion.
#[test]
fn canonical_simple_type_name_strips_array_nullable_pointer_suffixes() {
    // Generics + dotted prefixes (existing behavior, must stay green).
    assert_eq!(canonical_simple_type_name("java.io.IOException"), "IOException");
    assert_eq!(canonical_simple_type_name("List<Foo>"), "List");
    assert_eq!(
        canonical_simple_type_name("kotlin.collections.MutableList<E>"),
        "MutableList"
    );
    // New: array / nullable / force-unwrap / pointer / reference suffixes.
    assert_eq!(canonical_simple_type_name("User?"), "User");
    assert_eq!(canonical_simple_type_name("User!"), "User");
    assert_eq!(canonical_simple_type_name("byte[]"), "byte");
    assert_eq!(canonical_simple_type_name("com.acme.User[]"), "User");
    assert_eq!(canonical_simple_type_name("*const T"), "T");
    assert_eq!(canonical_simple_type_name("&User"), "User");
    assert_eq!(canonical_simple_type_name("Outer::Inner"), "Inner");
}
