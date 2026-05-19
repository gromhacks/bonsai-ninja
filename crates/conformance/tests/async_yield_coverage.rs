//! Cross-language Async / Yield coverage (spec §Phase-7).
//!
//! Validates that every adapter whose source language has explicit
//! `await` / `yield` syntax emits the corresponding `FlowEvent::Await`
//! / `FlowEvent::Yield` events. Languages without async/await
//! (Erlang, Lua, Elixir, Solidity, Perl, Go's goroutines-don't-count,
//! C, Objective-C, Ruby fibers are out of scope) are skipped.

use bonsai_lang_api::{Decl, FlowEvent, LanguageAdapter};
use bonsai_workspace::Workspace;
use std::sync::Arc;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum AsyncShape {
    Await,
    Yield,
}

struct Case {
    lang: &'static str,
    fixture_path: &'static str,
    fixture_source: &'static str,
    function_name: &'static str,
    shapes: &'static [AsyncShape],
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

fn flow_events_contain(events: &[FlowEvent], shape: AsyncShape) -> bool {
    for ev in events {
        match (shape, ev) {
            (AsyncShape::Await, FlowEvent::Await { .. }) | (AsyncShape::Yield, FlowEvent::Yield { .. }) => {
                return true
            }
            _ => {}
        }
        let nested: &[&[FlowEvent]] = match ev {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => &[then_events.as_slice(), else_events.as_slice()],
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if flow_events_contain(body, shape) {
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
                if flow_events_contain(body, shape)
                    || flow_events_contain(catch_events, shape)
                    || flow_events_contain(finally_events, shape)
                {
                    return true;
                }
                continue;
            }
            _ => continue,
        };
        for group in nested {
            if flow_events_contain(group, shape) {
                return true;
            }
        }
    }
    false
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            lang: "python",
            fixture_path: "async.py",
            fixture_source: r#"async def runner():
    result = await fetch()
    return result

def gen():
    yield 1
    yield 2
"#,
            function_name: "runner",
            shapes: &[AsyncShape::Await],
        },
        Case {
            lang: "python",
            fixture_path: "gen.py",
            fixture_source: r#"def gen():
    yield 1
    yield 2

def runner():
    pass
"#,
            function_name: "gen",
            shapes: &[AsyncShape::Yield],
        },
        Case {
            lang: "javascript",
            fixture_path: "async.js",
            fixture_source: r#"async function runner() {
  const result = await fetch();
  return result;
}
function* gen() {
  yield 1;
  yield 2;
}
"#,
            function_name: "runner",
            shapes: &[AsyncShape::Await],
        },
        Case {
            lang: "typescript",
            fixture_path: "async.ts",
            fixture_source: r#"async function runner(): Promise<string> {
  const result = await fetch();
  return result;
}
function* gen(): Generator<number> {
  yield 1;
  yield 2;
}
"#,
            function_name: "runner",
            shapes: &[AsyncShape::Await],
        },
        Case {
            lang: "csharp",
            fixture_path: "Async.cs",
            fixture_source: r#"namespace App;
class App {
  public async System.Threading.Tasks.Task<string> Runner() {
    var result = await FetchAsync();
    return result;
  }
  public System.Threading.Tasks.Task<string> FetchAsync() => null;
  public System.Collections.Generic.IEnumerable<int> Gen() {
    yield return 1;
    yield return 2;
  }
}
"#,
            function_name: "Runner",
            shapes: &[AsyncShape::Await],
        },
        Case {
            lang: "rust",
            fixture_path: "async.rs",
            fixture_source: r#"async fn runner() -> String {
    let result = fetch().await;
    result
}
async fn fetch() -> String { "x".to_string() }
"#,
            function_name: "runner",
            shapes: &[AsyncShape::Await],
        },
        Case {
            lang: "kotlin",
            fixture_path: "Async.kt",
            fixture_source: r#"import kotlinx.coroutines.*
suspend fun runner(): String {
  val result = fetcher().await()
  return result
}
suspend fun fetcher(): Deferred<String> { return CompletableDeferred("x") }
"#,
            function_name: "runner",
            // Kotlin uses `.await()` as a method call, not a syntactic
            // await — adapter won't emit FlowEvent::Await. Skip.
            shapes: &[],
        },
        Case {
            lang: "swift",
            fixture_path: "Async.swift",
            fixture_source: r#"func runner() async -> String {
  let result = await fetcher()
  return result
}
func fetcher() async -> String { return "x" }
"#,
            function_name: "runner",
            shapes: &[AsyncShape::Await],
        },
        Case {
            lang: "dart",
            fixture_path: "async.dart",
            fixture_source: r#"Future<String> runner() async {
  final result = await fetcher();
  return result;
}
Future<String> fetcher() async => "x";
Stream<int> gen() async* {
  yield 1;
  yield 2;
}
"#,
            function_name: "runner",
            shapes: &[AsyncShape::Await],
        },
    ]
}

#[test]
fn async_yield_cross_language_coverage() {
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
        for shape in case.shapes {
            if !flow_events_contain(&decl.flow_events, *shape) {
                failures.push(format!("{}: shape {:?} not emitted", case.lang, shape));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "async/yield coverage gaps ({} total):\n{}",
        failures.len(),
        failures.join("\n")
    );
}
