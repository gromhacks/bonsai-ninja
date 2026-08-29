use bonsai_lang_api::{ArgumentPassingMode, CallKind, FlowEvent};
use bonsai_workspace::Workspace;

fn fixture_workspace(file_name: &str, source: &str) -> Workspace {
    bonsai_testkit::workspace_with(bonsai_adapters::all_adapters(), &[(file_name, source)])
}

fn helper_argument_mode(label: &str, file_name: &str, source: &str) -> ArgumentPassingMode {
    let workspace = fixture_workspace(file_name, source);
    let index = workspace.db().global_index();
    let mode = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .flat_map(|decl| decl.flow_events.iter())
        .find_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name == "helper" => {
                args.first().map(|argument| argument.passing_mode)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("{label}: helper argument"));
    mode
}

fn lowered_calls(_label: &str, file_name: &str, source: &str) -> Vec<(String, CallKind, usize)> {
    let workspace = fixture_workspace(file_name, source);
    let index = workspace.db().global_index();
    let calls = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .flat_map(|decl| decl.flow_events.iter())
        .filter_map(|event| match event {
            FlowEvent::Call {
                name,
                call_kind,
                args,
                ..
            } => Some((name.clone(), *call_kind, args.len())),
            _ => None,
        })
        .collect();
    calls
}

#[test]
fn adapters_lower_writeback_syntax_to_one_language_neutral_fact() {
    let cases = [
        ("c", "main.c", "void f(void) { int out; helper(&out); }"),
        ("cpp", "main.cpp", "void f() { int out; helper(&out); }"),
        (
            "csharp",
            "Main.cs",
            "class C { void F() { string result; helper(out result); } }",
        ),
        (
            "csharp-ref",
            "Main.cs",
            "class C { void F() { string result = \"\"; helper(ref result); } }",
        ),
        (
            "go",
            "main.go",
            "package p\nfunc f() { var out string; helper(&out) }",
        ),
        ("objc", "main.m", "void f(void) { id out; helper(&out); }"),
        (
            "rust",
            "main.rs",
            "fn f() { let mut out = String::new(); helper(&mut out); }",
        ),
        ("swift", "main.swift", "func f() { var out = \"\"; helper(&out) }"),
    ];

    for (label, file, source) in cases {
        assert_eq!(
            helper_argument_mode(label, file, source),
            ArgumentPassingMode::WriteBack,
            "{label} adapter must own its write-back syntax"
        );
    }
}

#[test]
fn ordinary_and_bitwise_arguments_remain_value_semantics() {
    let cases = [
        (
            "c-value",
            "main.c",
            "void f(void) { int left = 1, right = 2; helper(left & right); }",
        ),
        (
            "csharp-value",
            "Main.cs",
            "class C { void F() { string result = \"\"; helper(result); } }",
        ),
        (
            "csharp-readonly-in",
            "Main.cs",
            "class C { void F() { string result = \"\"; helper(in result); } }",
        ),
        (
            "rust-value",
            "main.rs",
            "fn f() { let out = String::new(); helper(out); }",
        ),
    ];

    for (label, file, source) in cases {
        assert_eq!(
            helper_argument_mode(label, file, source),
            ArgumentPassingMode::Value,
            "{label} must not over-classify a normal expression"
        );
    }
}

#[test]
fn pseudo_calls_are_lowered_by_their_owning_adapters() {
    let cases = [
        (
            "javascript-jsx",
            "view.jsx",
            "function render(value) { return <Widget value={value}/>; }",
            "Widget",
            CallKind::Function,
            1,
        ),
        (
            "typescript-tsx",
            "view.tsx",
            "function render(value: string) { return <Widget value={value}/>; }",
            "Widget",
            CallKind::Function,
            1,
        ),
        (
            "go-send",
            "main.go",
            "package p\nfunc f(ch chan string, value string) { ch <- value }",
            "send",
            CallKind::ChannelSend,
            2,
        ),
        (
            "cpp-delete",
            "main.cpp",
            "struct Box {}; void f(Box *box) { delete box; }",
            "delete",
            CallKind::Operator,
            1,
        ),
        (
            "perl-eval",
            "main.pl",
            "sub f { my ($value) = @_; eval $value; }",
            "eval",
            CallKind::Function,
            1,
        ),
        (
            "php-echo",
            "main.php",
            "<?php function f($value) { echo $value; }",
            "echo",
            CallKind::Function,
            1,
        ),
        (
            "ruby-subshell",
            "main.rb",
            "def f(command)\n  `#{command}`\nend\n",
            "`",
            // Ruby owns a post-lowering normalization that presents
            // backtick execution as the function-shaped shell sink
            // consumed by rule matching.
            CallKind::Function,
            1,
        ),
        (
            "scala-operator",
            "Main.scala",
            "object Main { def f(left: String, right: String) = left ++ right }",
            "++",
            CallKind::Operator,
            2,
        ),
    ];

    for (label, file, source, expected_name, expected_kind, expected_args) in cases {
        let calls = lowered_calls(label, file, source);
        assert!(
            calls.iter().any(|(name, kind, arg_count)| {
                name == expected_name && *kind == expected_kind && *arg_count == expected_args
            }),
            "{label}: missing adapter-owned pseudo call; calls={calls:?}"
        );
    }
}

#[test]
fn lookalike_non_pseudo_syntax_does_not_emit_pseudo_calls() {
    let perl = lowered_calls("perl-block-eval", "main.pl", "sub f { eval { helper(); }; }");
    assert!(
        perl.iter().all(|(name, _, _)| name != "eval"),
        "Perl block eval is control syntax, not scalar eval: {perl:?}"
    );

    let scala = lowered_calls(
        "scala-field",
        "Main.scala",
        "object Main { def f(value: Box) = value.field }",
    );
    assert!(
        scala.is_empty(),
        "ordinary Scala field access must not become a postfix method call: {scala:?}"
    );
}
