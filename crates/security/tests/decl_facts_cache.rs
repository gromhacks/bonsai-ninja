//! Per-decl matcher-fact cache regression test.
//!
//! Stage 3 introduced a thread-local cache keyed on
//! `(FileId, version, text_hash)` that holds per-decl derived facts
//! (`collect_calls`, `collect_assignment_texts`, decorators, runtime
//! types, lifecycle transitions). This test pins the property that
//! matters: repeated `match_rules_against_facts` calls produce
//! identical `RuleMatch` lists, and editing a file invalidates the
//! cache so a stale result can never linger.
//!
//! Both properties are correctness-critical — a mistakenly held-over
//! entry would silently drop or duplicate matches.

use bonsai_security::{
    match_rules_against_facts,
    rule::{Rule, RuleKind},
};
use std::sync::Arc;

fn ws_with(file_name: &str, code: &str) -> bonsai_workspace::Workspace {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(file_name.to_string(), Arc::<str>::from(code));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn dangerous_call_rule() -> Rule {
    let mut rule: Rule = serde_yaml::from_str(
        r#"
id: test.dangerous_call
enabled: true
language: python
match:
  kind: call
  callee:
    name: dangerous
description: any call to `dangerous(...)`.
"#,
    )
    .expect("rule yaml parses");
    rule.kind = RuleKind::Sink;
    rule
}

#[test]
fn second_match_call_produces_same_results() {
    let ws = ws_with(
        "app.py",
        "def main():\n    dangerous(input())\n\n\
def helper():\n    dangerous(\"x\")\n",
    );
    let rule = dangerous_call_rule();

    // First call populates the cache; second call must hit it.
    let first = match_rules_against_facts(&ws, &[&rule]);
    let second = match_rules_against_facts(&ws, &[&rule]);

    assert_eq!(
        first.len(),
        second.len(),
        "cached and uncached match counts must agree (first: {} / second: {})",
        first.len(),
        second.len()
    );
    let first_spans: Vec<_> = first.iter().map(|m| (m.file.clone(), m.span)).collect();
    let second_spans: Vec<_> = second.iter().map(|m| (m.file.clone(), m.span)).collect();
    assert_eq!(
        first_spans, second_spans,
        "cached and uncached match spans must agree"
    );
    assert!(
        first.len() >= 2,
        "fixture should match at least two `dangerous(...)` calls; got {}",
        first.len()
    );
}

#[test]
fn rewriting_a_file_produces_fresh_results() {
    let ws = ws_with("app.py", "def main():\n    dangerous(input())\n");
    let rule = dangerous_call_rule();

    let baseline = match_rules_against_facts(&ws, &[&rule]);
    assert_eq!(baseline.len(), 1, "fixture has one call");

    // Rewrite the file with a different shape — the cache key
    // includes content_hash, so the next match must reflect the
    // edit, not return the stale `app.py` body's result.
    ws.vfs()
        .write("app.py".to_string(), Arc::<str>::from("def main():\n    pass\n"));
    let file_id = ws.vfs().lookup(std::path::Path::new("app.py")).expect("file id");
    ws.db().invalidate_file(file_id);
    let _ = ws.db().decl_index(file_id);

    let after_edit = match_rules_against_facts(&ws, &[&rule]);
    assert!(
        after_edit.is_empty(),
        "after rewriting the file with no `dangerous(...)` calls, the cache must drop the stale match: {after_edit:?}"
    );
}
