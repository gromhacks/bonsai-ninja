//! Cross-language conformance for destructured input boundaries.
//!
//! Security rules may assign meaning to a parameter position, but adapters
//! own the syntax that decides which value bindings that position creates.
//! These fixtures intentionally use neutral call and type names: the contract
//! is only that pattern leaves become bindings while keys, constructors,
//! types, computed selectors, and wildcards do not.

use bonsai_lang_api::{AssignValueKind, Decl, DeclIndex, FlowEvent, LanguageAdapter};
use std::sync::Arc;

fn adapter(language: &str) -> Arc<dyn LanguageAdapter> {
    bonsai_adapters::all_adapters()
        .into_iter()
        .find(|adapter| adapter.language_id().as_str() == language)
        .unwrap_or_else(|| panic!("missing bundled adapter for {language}"))
}

fn index(language: &str, path: &str, source: &str) -> Arc<DeclIndex> {
    let workspace = bonsai_testkit::workspace_with(vec![adapter(language)], &[(path, source)]);
    let diagnostics = workspace.diagnostics();
    assert!(
        diagnostics.is_empty(),
        "{language}: valid destructuring fixture emitted diagnostics: {diagnostics:#?}"
    );
    let file = workspace
        .vfs()
        .all_files()
        .into_iter()
        .next()
        .expect("fixture file");
    workspace
        .db()
        .decl_index(file)
        .unwrap_or_else(|| panic!("{language}: declaration index"))
}

fn declaration<'a>(index: &'a DeclIndex, name: &str) -> &'a Decl {
    index
        .defs
        .iter()
        .find(|decl| decl.name == name)
        .unwrap_or_else(|| panic!("missing declaration {name}: {:#?}", index.defs))
}

fn assert_exact_params(language: &str, declaration: &Decl, expected: &[&str], forbidden: &[&str]) {
    let actual = declaration.params.iter().map(String::as_str).collect::<Vec<_>>();
    assert_eq!(actual, expected, "{language}: declaration={declaration:#?}");
    for name in forbidden {
        assert!(
            actual.iter().all(|actual| actual != name),
            "{language}: non-binding syntax `{name}` leaked into parameters: {actual:?}"
        );
    }
}

fn collect_destructure_assignments<'a>(events: &'a [FlowEvent], output: &mut Vec<(&'a str, Vec<&'a str>)>) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_names,
                value_kind: Some(AssignValueKind::Destructure),
                ..
            } => {
                let mut sources = source_names.iter().map(String::as_str).collect::<Vec<_>>();
                if let Some(source) = source_name.as_deref() {
                    if !sources.contains(&source) {
                        sources.push(source);
                    }
                }
                output.push((target.as_str(), sources));
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_destructure_assignments(then_events, output);
                collect_destructure_assignments(else_events, output);
            }
            FlowEvent::Loop {
                condition_events,
                body,
                update_events,
                ..
            } => {
                collect_destructure_assignments(condition_events, output);
                collect_destructure_assignments(body, output);
                collect_destructure_assignments(update_events, output);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_destructure_assignments(body, output);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_destructure_assignments(body, output);
                collect_destructure_assignments(catch_events, output);
                collect_destructure_assignments(finally_events, output);
            }
            _ => {}
        }
    }
}

#[test]
fn declaration_patterns_keep_only_value_bindings() {
    let javascript = index(
        "javascript",
        "boundary.js",
        r#"
function boundary({ left: renamed, nested: { right }, ...rest }, [first, , last]) {
  return combine(renamed, right, rest, first, last);
}
function computed({ [selector]: value }) { return value; }
"#,
    );
    assert_exact_params(
        "javascript",
        declaration(&javascript, "boundary"),
        &["renamed", "right", "rest", "first", "last"],
        &["left", "nested", "selector"],
    );
    assert_exact_params(
        "javascript-computed",
        declaration(&javascript, "computed"),
        &["value"],
        &["selector"],
    );

    let typescript = index(
        "typescript",
        "boundary.ts",
        r#"
declare const selector: string;
function boundary(
  { left: renamed, nested: { right }, ...rest }:
    { left: string; nested: { right: string }; [key: string]: unknown },
  [first, , last]: string[],
): unknown { return combine(renamed, right, rest, first, last); }
function computed({ [selector]: value }: Record<string, string>): string { return value; }
"#,
    );
    assert_exact_params(
        "typescript",
        declaration(&typescript, "boundary"),
        &["renamed", "right", "rest", "first", "last"],
        &["left", "nested", "string", "unknown", "key", "selector"],
    );
    assert_exact_params(
        "typescript-computed",
        declaration(&typescript, "computed"),
        &["value"],
        &["selector", "Record", "string"],
    );

    let rust = index(
        "rust",
        "boundary.rs",
        r#"
struct Wrapper<T>(T);
fn boundary(
    (left, right): (String, String),
    Wrapper(inner): Wrapper<String>,
) { combine(left, right, inner); }
fn ignored(_: (String, String), Wrapper(_): Wrapper<String>) {}
"#,
    );
    assert_exact_params(
        "rust",
        declaration(&rust, "boundary"),
        &["left", "right", "inner"],
        &["Wrapper", "String", "_"],
    );
    assert_exact_params(
        "rust-wildcard",
        declaration(&rust, "ignored"),
        &[],
        &["Wrapper", "String", "_"],
    );

    let perl = index(
        "perl",
        "Boundary.pm",
        r#"
sub boundary {
  my ($left, $right, @rest) = @_;
  combine($left, $right, @rest);
}
"#,
    );
    assert_exact_params(
        "perl",
        declaration(&perl, "boundary"),
        &["$left", "$right", "@rest"],
        &["@_", "my"],
    );
}

#[test]
fn functional_parameter_patterns_project_only_bound_leaves() {
    let elixir = index(
        "elixir",
        "boundary.ex",
        r#"
defmodule Boundary do
  def split(%{left_key: left, nested_key: {right, [first | rest]}}) do
    combine(left, right, first, rest)
  end
end
"#,
    );
    let split = declaration(&elixir, "split");
    assert_exact_params(
        "elixir",
        split,
        &["_arg0"],
        &["left", "nested", "right", "first", "rest"],
    );
    let mut assignments = Vec::new();
    collect_destructure_assignments(&split.flow_events, &mut assignments);
    for (target, source) in [
        ("left", "_arg0.left_key"),
        ("right", "_arg0.nested_key.0"),
        ("first", "_arg0.nested_key.1.0"),
        ("rest", "_arg0.nested_key.1.*"),
    ] {
        assert!(
            assignments
                .iter()
                .any(|(actual, sources)| *actual == target && sources.contains(&source)),
            "elixir: missing {target} <- {source}: {assignments:#?}"
        );
    }
    for non_binding in ["left_key", "nested_key"] {
        assert!(
            assignments.iter().all(|(target, _)| *target != non_binding),
            "elixir: map key became an independent binding: {assignments:#?}"
        );
    }

    let erlang = index(
        "erlang",
        "boundary.erl",
        r#"
-module(boundary).
-export([split/2]).
split({Left, Right}, #{label := Label, nested := {Inner, _}}) ->
  combine(Left, Right, Label, Inner).
"#,
    );
    let split = declaration(&erlang, "split");
    assert_exact_params(
        "erlang",
        split,
        &["_Arg0", "_Arg1"],
        &["Left", "Right", "label", "Label", "nested", "Inner", "_"],
    );
    let mut assignments = Vec::new();
    collect_destructure_assignments(&split.flow_events, &mut assignments);
    for (target, source) in [
        ("Left", "_Arg0"),
        ("Right", "_Arg0"),
        ("Label", "_Arg1"),
        ("Inner", "_Arg1"),
    ] {
        assert!(
            assignments
                .iter()
                .any(|(actual, sources)| *actual == target && sources.contains(&source)),
            "erlang: missing {target} <- {source}: {assignments:#?}"
        );
    }
    for non_binding in ["label", "nested", "_"] {
        assert!(
            assignments.iter().all(|(target, _)| *target != non_binding),
            "erlang: key/wildcard became a binding: {assignments:#?}"
        );
    }
}

fn inline_parameter_sets(index: &DeclIndex) -> Vec<Vec<String>> {
    let mut sets = index
        .call_argument_values
        .iter()
        .filter(|fact| !fact.inline_callback_params.is_empty())
        .map(|fact| fact.inline_callback_params.clone())
        .collect::<Vec<_>>();
    sets.sort();
    sets.dedup();
    sets
}

fn assert_callback_sets(language: &str, index: &DeclIndex, expected: &[&[&str]], forbidden: &[&str]) {
    let actual = inline_parameter_sets(index);
    let mut expected = expected
        .iter()
        .map(|set| set.iter().map(|name| (*name).to_string()).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    expected.sort();
    expected.dedup();
    assert_eq!(
        actual, expected,
        "{language}: facts={:#?}",
        index.call_argument_values
    );
    for name in forbidden {
        assert!(
            actual.iter().flatten().all(|actual| actual != name),
            "{language}: non-binding syntax `{name}` leaked into callback parameters: {actual:?}"
        );
    }
}

#[test]
fn destructured_callback_parameters_are_exact_and_named_callbacks_stay_unexpanded() {
    let kotlin = index(
        "kotlin",
        "Boundary.kt",
        r#"
fun boundary(pairs: List<Pair<String, String>>) {
  apply { (left, right) -> combine(left, right) }
  apply(dynamicCallback)
}
"#,
    );
    assert_callback_sets(
        "kotlin",
        &kotlin,
        &[&["left", "right"]],
        &["Pair", "_", "dynamicCallback"],
    );

    let ruby = index(
        "ruby",
        "boundary.rb",
        r#"
def boundary(rows, dynamic_callback)
  apply do |(left, (right, rest))|
    combine(left, right, rest)
  end
  apply(&dynamic_callback)
end
"#,
    );
    assert_callback_sets(
        "ruby",
        &ruby,
        &[&["left", "right", "rest"]],
        &["dynamic_callback"],
    );

    let scala = index(
        "scala",
        "Boundary.scala",
        r#"
object Boundary {
  def boundary(dynamicCallback: ((String, String)) => String): Unit = {
    apply { (left, right) => combine(left, right) }
    apply { case (first, second) => combine(first, second) }
    apply(dynamicCallback)
  }
}
"#,
    );
    assert_callback_sets(
        "scala",
        &scala,
        &[&["first", "second"], &["left", "right"]],
        &["String", "Tuple2", "dynamicCallback"],
    );
}
