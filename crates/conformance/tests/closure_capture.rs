//! Cross-language closure capture (spec §Phase-3).
//!
//! Verifies that closure bodies see enclosing-scope variables. The
//! kit's `is_closure_arg` inlines lambda / closure bodies into the
//! enclosing function's flow events, so the engine's per-function
//! `last_writer` map naturally extends across the closure boundary.
//! This test validates the inlining holds for every language with
//! syntactic closures.

use bonsai_lang_api::{Decl, FlowEvent, LanguageAdapter};
use bonsai_workspace::Workspace;
use std::sync::Arc;

struct Case {
    lang: &'static str,
    fixture_path: &'static str,
    fixture_source: &'static str,
    /// The outer function whose flow events are inspected. Closure
    /// body events should appear inlined under this decl.
    function_name: &'static str,
    /// A bare identifier the closure body reads. We assert at least
    /// one event under the function references this name.
    captured_name: &'static str,
}

fn adapter_for_lang(lang: &str) -> Option<Arc<dyn LanguageAdapter>> {
    bonsai_adapters::all_adapters()
        .into_iter()
        .find(|a| a.language_id().as_str() == lang)
}

fn find_decl(ws: &Workspace, name: &str) -> Option<Decl> {
    let global = ws.db().global_index();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == name {
                return Some(decl.clone());
            }
        }
    }
    None
}

/// True when the flow-event tree contains a reference to `name` via
/// any of: a Call arg whose value_text contains the name, an Assign
/// whose source_name/source_names mentions it, or a bare Call to it.
fn references_name(events: &[FlowEvent], name: &str) -> bool {
    for ev in events {
        if matches_name(ev, name) {
            return true;
        }
        let nested: &[&[FlowEvent]] = match ev {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => &[then_events.as_slice(), else_events.as_slice()],
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if references_name(body, name) {
                    return true;
                }
                continue;
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if references_name(body, name)
                    || references_name(catch_events, name)
                    || references_name(finally_events, name)
                {
                    return true;
                }
                continue;
            }
            _ => continue,
        };
        for group in nested {
            if references_name(group, name) {
                return true;
            }
        }
    }
    false
}

fn matches_name(event: &FlowEvent, name: &str) -> bool {
    match event {
        FlowEvent::Call { args, .. } => args.iter().any(|a| {
            a.value_text.contains(name)
                || a.source_names.iter().any(|s| s == name)
                || a.place.as_deref() == Some(name)
        }),
        FlowEvent::Assign {
            source_name,
            source_names,
            source_call_args,
            ..
        } => {
            source_name.as_deref() == Some(name)
                || source_names.iter().any(|s| s == name)
                || source_call_args.iter().any(|s| s == name)
        }
        _ => false,
    }
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            lang: "python",
            fixture_path: "closure.py",
            fixture_source: r#"def outer():
    captured = "secret"
    items = [1, 2, 3]
    list(map(lambda x: sink(captured, x), items))
    return 0
"#,
            function_name: "outer",
            captured_name: "captured",
        },
        Case {
            lang: "javascript",
            fixture_path: "closure.js",
            fixture_source: r#"function outer() {
  const captured = "secret";
  const items = [1, 2, 3];
  items.forEach(function(x) { sink(captured, x); });
  return 0;
}
"#,
            function_name: "outer",
            captured_name: "captured",
        },
        Case {
            lang: "typescript",
            fixture_path: "closure.ts",
            fixture_source: r#"function outer(): number {
  const captured: string = "secret";
  const items: number[] = [1, 2, 3];
  items.forEach((x) => { sink(captured, x); });
  return 0;
}
"#,
            function_name: "outer",
            captured_name: "captured",
        },
        Case {
            lang: "rust",
            fixture_path: "closure.rs",
            fixture_source: r#"fn outer() -> i32 {
    let captured = "secret";
    let items = [1, 2, 3];
    items.iter().for_each(|x| { sink(captured, x); });
    0
}
fn sink(_a: &str, _b: &i32) {}
"#,
            function_name: "outer",
            captured_name: "captured",
        },
        Case {
            lang: "ruby",
            fixture_path: "closure.rb",
            fixture_source: r#"def outer
  captured = "secret"
  items = [1, 2, 3]
  items.each do |x|
    sink(captured, x)
  end
  0
end
"#,
            function_name: "outer",
            captured_name: "captured",
        },
        Case {
            lang: "kotlin",
            fixture_path: "Closure.kt",
            fixture_source: r#"fun outer(): Int {
  val captured = "secret"
  val items = listOf(1, 2, 3)
  items.forEach { x -> sink(captured, x) }
  return 0
}
fun sink(a: String, b: Int) {}
"#,
            function_name: "outer",
            captured_name: "captured",
        },
        Case {
            lang: "swift",
            fixture_path: "Closure.swift",
            fixture_source: r#"func outer() -> Int {
    let captured = "secret"
    let items = [1, 2, 3]
    items.forEach { x in sink(captured, x) }
    return 0
}
func sink(_ a: String, _ b: Int) {}
"#,
            function_name: "outer",
            captured_name: "captured",
        },
    ]
}

#[test]
fn closure_capture_inlined_across_languages() {
    let mut failures: Vec<String> = Vec::new();
    for case in cases() {
        let Some(adapter) = adapter_for_lang(case.lang) else {
            failures.push(format!("{}: no adapter found", case.lang));
            continue;
        };
        let ws = bonsai_testkit::workspace_with(vec![adapter], &[(case.fixture_path, case.fixture_source)]);
        let Some(decl) = find_decl(&ws, case.function_name) else {
            failures.push(format!(
                "{}: function `{}` not found",
                case.lang, case.function_name
            ));
            continue;
        };
        if !references_name(&decl.flow_events, case.captured_name) {
            failures.push(format!(
                "{}: enclosing function `{}` does not surface closure-captured name `{}`",
                case.lang, case.function_name, case.captured_name
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "closure capture gaps ({} total):\n{}",
        failures.len(),
        failures.join("\n")
    );
}
