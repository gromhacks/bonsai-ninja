//! All-language dataflow conformance for abrupt structured-control exits.
//!
//! CFG-only tests prove that `break` has the right successor, but the IDG also
//! maintains reaching definitions while lowering structured HIR. A writer on
//! a breaking branch must not be merged into the fallthrough state consumed
//! by a later statement in the loop body. These fixtures compose the real
//! adapter, CFG normalizer, and production transfer pass for every language
//! with a native `break` statement.

use bonsai_idg::{transfer_function_for, NodeId, Place, TransferOutput};
use bonsai_lang_api::{Decl, LanguageAdapter};
use bonsai_workspace::Workspace;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

struct Fixture {
    language: &'static str,
    path: &'static str,
    function: &'static str,
    source: &'static str,
}

const FIXTURES: &[Fixture] = &[
    Fixture { language: "c", path: "flow.c", function: "branch_break", source: "void branch_break(char *input) { while (condition()) { char *value = \"clean\"; if (condition()) { value = input; break; } else { value = \"clean\"; } sink(value); break; } after_sink(input); }\n" },
    Fixture { language: "cpp", path: "flow.cpp", function: "branch_break", source: "void branch_break(const char *input) { while (condition()) { const char *value = \"clean\"; if (condition()) { value = input; break; } else { value = \"clean\"; } sink(value); break; } after_sink(input); }\n" },
    Fixture { language: "csharp", path: "Flow.cs", function: "BranchBreak", source: "class Flow { static void BranchBreak(string input) { while (Condition()) { string value = \"clean\"; if (Condition()) { value = input; break; } else { value = \"clean\"; } Sink(value); break; } AfterSink(input); } }\n" },
    Fixture { language: "dart", path: "flow.dart", function: "branchBreak", source: "void branchBreak(String input) { while (condition()) { var value = 'clean'; if (condition()) { value = input; break; } else { value = 'clean'; } sink(value); break; } afterSink(input); }\n" },
    Fixture { language: "go", path: "flow.go", function: "branchBreak", source: "package flow\nfunc branchBreak(input string) { for condition() { value := \"clean\"; if condition() { value = input; break } else { value = \"clean\" }; sink(value); break }; afterSink(input) }\n" },
    Fixture { language: "java", path: "Flow.java", function: "branchBreak", source: "class Flow { static void branchBreak(String input) { while (condition()) { String value = \"clean\"; if (condition()) { value = input; break; } else { value = \"clean\"; } sink(value); break; } afterSink(input); } }\n" },
    Fixture { language: "javascript", path: "flow.js", function: "branchBreak", source: "function branchBreak(input) { while (condition()) { let value = 'clean'; if (condition()) { value = input; break; } else { value = 'clean'; } sink(value); break; } afterSink(input); }\n" },
    Fixture { language: "kotlin", path: "flow.kt", function: "branchBreak", source: "fun branchBreak(input: String) { while (condition()) { var value = \"clean\"; if (condition()) { value = input; break } else { value = \"clean\" }; sink(value); break }; afterSink(input) }\n" },
    Fixture { language: "lua", path: "flow.lua", function: "branch_break", source: "local function branch_break(input)\n  while condition() do\n    local value = 'clean'\n    if condition() then value = input; break else value = 'clean' end\n    sink(value)\n    break\n  end\n  after_sink(input)\nend\n" },
    Fixture { language: "objc", path: "flow.m", function: "branch_break", source: "void branch_break(NSString *input) { while (condition()) { NSString *value = @\"clean\"; if (condition()) { value = input; break; } else { value = @\"clean\"; } sink(value); break; } after_sink(input); }\n" },
    Fixture { language: "perl", path: "flow.pl", function: "branch_break", source: "use feature 'signatures';\nsub branch_break ($input) { while (condition()) { my $value = 'clean'; if (condition()) { $value = $input; last; } else { $value = 'clean'; } sink($value); last; } after_sink($input); }\n" },
    Fixture { language: "php", path: "flow.php", function: "branch_break", source: "<?php\nfunction branch_break($input) { while (condition()) { $value = 'clean'; if (condition()) { $value = $input; break; } else { $value = 'clean'; } sink($value); break; } after_sink($input); }\n" },
    Fixture { language: "python", path: "flow.py", function: "branch_break", source: "def branch_break(input):\n    while condition():\n        value = 'clean'\n        if condition():\n            value = input\n            break\n        else:\n            value = 'clean'\n        sink(value)\n        break\n    after_sink(input)\n" },
    Fixture { language: "ruby", path: "flow.rb", function: "branch_break", source: "def branch_break(input)\n  while condition\n    value = 'clean'\n    if condition\n      value = input\n      break\n    else\n      value = 'clean'\n    end\n    sink(value)\n    break\n  end\n  after_sink(input)\nend\n" },
    Fixture { language: "rust", path: "flow.rs", function: "branch_break", source: "fn branch_break(input: &str) { while condition() { let mut value = \"clean\"; if condition() { value = input; break; } else { value = \"clean\"; } sink(value); break; } after_sink(input); }\n" },
    Fixture { language: "swift", path: "flow.swift", function: "branchBreak", source: "func branchBreak(input: String) { while condition() { var value = \"clean\"; if condition() { value = input; break } else { value = \"clean\" }; sink(value); break }; afterSink(input) }\n" },
    Fixture { language: "typescript", path: "flow.ts", function: "branchBreak", source: "function branchBreak(input: string): void { while (condition()) { let value = 'clean'; if (condition()) { value = input; break; } else { value = 'clean'; } sink(value); break; } afterSink(input); }\n" },
];

const NO_NATIVE_BREAK: &[&str] = &["elixir", "erlang", "scala"];

fn adapter_for(language: &str) -> Arc<dyn LanguageAdapter> {
    bonsai_adapters::all_adapters()
        .into_iter()
        .find(|adapter| adapter.language_id().as_str() == language)
        .unwrap_or_else(|| panic!("missing bundled adapter for {language}"))
}

fn find_decl(workspace: &Workspace, name: &str) -> Decl {
    let global = workspace.db().global_index();
    let declaration = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == name)
        .cloned();
    declaration.unwrap_or_else(|| panic!("missing `{name}` declaration"))
}

fn normalized_callee(name: &str) -> String {
    name.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn parameter_node(output: &TransferOutput) -> NodeId {
    output
        .nodes
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(output.places.get(node.place), Some(Place::Param { idx: 0 }))
                .then(|| NodeId(u32::try_from(index).expect("node index fits u32")))
        })
        .expect("first parameter node")
}

fn first_arg_node(output: &TransferOutput, callee: &str) -> NodeId {
    output
        .call_sites
        .iter()
        .find(|site| normalized_callee(&site.callee_name).ends_with(callee))
        .and_then(|site| site.call_arg_nodes.first().copied())
        .unwrap_or_else(|| panic!("missing first argument for {callee}"))
}

fn reaches(output: &TransferOutput, source: NodeId, target: NodeId) -> bool {
    let mut seen = BTreeSet::new();
    let mut pending = vec![source];
    while let Some(node) = pending.pop() {
        if !seen.insert(node.0) {
            continue;
        }
        if node == target {
            return true;
        }
        pending.extend(
            output
                .edges
                .iter()
                .filter_map(|edge| (edge.from == node).then_some(edge.to)),
        );
    }
    false
}

#[test]
fn breaking_branch_writer_never_reaches_loop_body_fallthrough_in_any_language() {
    let bundled = bonsai_adapters::all_adapters()
        .into_iter()
        .map(|adapter| adapter.language_id().as_str().to_string())
        .collect::<BTreeSet<_>>();
    let covered = FIXTURES
        .iter()
        .map(|fixture| fixture.language.to_string())
        .chain(NO_NATIVE_BREAK.iter().map(|language| (*language).to_string()))
        .collect::<BTreeSet<_>>();
    assert_eq!(covered, bundled, "every adapter must be covered or inapplicable");

    let mut failures = BTreeMap::new();
    for fixture in FIXTURES {
        let workspace = bonsai_testkit::workspace_with(
            vec![adapter_for(fixture.language)],
            &[(fixture.path, fixture.source)],
        );
        if !workspace.diagnostics().is_empty() {
            failures.insert(
                fixture.language,
                format!("diagnostics: {:#?}", workspace.diagnostics()),
            );
            continue;
        }
        let decl = find_decl(&workspace, fixture.function);
        let output = transfer_function_for(&decl);
        let source = parameter_node(&output);
        let sink = first_arg_node(&output, "sink");
        let after = first_arg_node(&output, "aftersink");
        if reaches(&output, source, sink) || !reaches(&output, source, after) {
            failures.insert(
                fixture.language,
                format!(
                    "breaking writer reached sink={} or positive control failed={}",
                    reaches(&output, source, sink),
                    !reaches(&output, source, after)
                ),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "abrupt-exit dataflow regressions:\n{failures:#?}"
    );
}
