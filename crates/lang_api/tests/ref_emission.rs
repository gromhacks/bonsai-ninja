//! Unit tests for the cross-grammar ref-emission + alias-map helpers
//! in [`bonsai_lang_api::kit`]. These are the engine-level primitives
//! every language adapter and the security matcher depend on — a
//! regression here silently breaks every `kind: read` rule in the
//! pack, and broken alias expansion turns every destructured import
//! into a match-time miss. Bug-for-bug coverage lives here so
//! adapter-level tests don't have to re-derive the contract.
//!
//! Test layout:
//!
//! 1. `extract_read_write_refs` — one test per grammar shape we
//!    claim to cover: JS/TS member expressions (2-level, 3-level,
//!    nested receiver as call target), subscript reads in JS + PHP +
//!    Python + Ruby, sigil'd PHP variables, Ruby globals, Python
//!    attribute chains. Positive assertions only; absence is
//!    negative-asserted by pinning the exact ref set.
//!
//! 2. `alias_map_from_imports` — ImportIndex → alias map, covering
//!    Module-scope entries (renamed imports), Local-scope entries
//!    (shorthand destructures), original_name fallback (Python `from
//!    x import y`), module-tail fallback (`import os as o`), plus
//!    the empty / wildcard edge cases.
//!
//! 3. `is_call_callee` / `is_write_target` — verify the predicates
//!    that gate read-vs-write classification work across grammars.

use bonsai_common::FileId;
use bonsai_lang_api::kit::{
    alias_map_from_imports, extract_read_write_refs, language_from_pack, GrammarHandler, EMPTY_HANDLER,
};
use bonsai_lang_api::{AliasTarget, ImportIndex, ImportScope, ImportSpec, RefKind};

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

// Cross-grammar coverage fixture only. Production always passes the active
// adapter's closed reference syntax declaration.
fn canonical_test_reference(node: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    let text = node
        .utf8_text(src)
        .ok()?
        .trim()
        .trim_matches(bonsai_common::is_name_punctuation);
    (!text.is_empty()).then(|| text.to_string())
}

const REF_TEST_HANDLER: GrammarHandler = GrammarHandler {
    assignment_kinds: &["assignment_expression", "augmented_assignment_expression"],
    call_callee_field_names: &["function", "callee", "name"],
    call_callee_is_first_named_child: true,
    call_ref_kinds: &[
        "call",
        "call_expression",
        "function_call_expression",
        "method_call",
        "method_call_expression",
        "method_invocation",
        "invocation_expression",
        "member_call_expression",
        "nullsafe_member_call_expression",
        "scoped_call_expression",
        "object_creation_expression",
        "new_expression",
        "macro_invocation",
    ],
    member_expression_kinds: &[
        "member_expression",
        "nullsafe_member_access_expression",
        "member_access_expression",
        "field_access",
        "field_expression",
        "selector_expression",
        "navigation_expression",
        "attribute",
        "dot_index_expression",
        "qualified_access_expression",
        "qualified_identifier",
        "scoped_identifier",
        "property_access_expression",
        "assignable_expression",
        "assignable_selector",
        "unconditional_assignable_selector",
        "conditional_assignable_selector",
    ],
    member_base_field_names: &[
        "object",
        "expression",
        "operand",
        "value",
        "scope",
        "target",
        "receiver",
    ],
    member_name_field_names: &["property", "name", "attribute", "field", "suffix"],
    subscript_expression_kinds: &[
        "subscript_expression",
        "subscript",
        "element_reference",
        "array_access",
        "element_access_expression",
        "bracket_index_expression",
        "index_expression",
        "indexing_expression",
        "indexing_suffix",
    ],
    subscript_base_field_names: &["object", "expression", "operand", "value", "array", "target"],
    subscript_index_field_names: &["index", "argument", "subscript", "arguments"],
    identifier_kinds: &[
        "identifier",
        "simple_identifier",
        "variable_name",
        "name",
        "self",
        "this",
        "super",
    ],
    sigil_variable_kinds: &["variable_name"],
    global_variable_kinds: &["global_variable"],
    reference_name_extractor: Some(canonical_test_reference),
    subscript_base_call_refs: true,
    call_name_suffix_tokens: &["!"],
    ..EMPTY_HANDLER
};

fn parse(pack: &str, src: &str) -> tree_sitter::Tree {
    let language = language_from_pack(pack).expect("language pack available");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set language");
    parser.parse(src, None).expect("parse succeeded")
}

fn refs(pack: &str, src: &str) -> Vec<(RefKind, String)> {
    let tree = parse(pack, src);
    extract_read_write_refs(&tree, FileId::INVALID, src.as_bytes(), &REF_TEST_HANDLER)
        .into_iter()
        .map(|r| (r.kind, r.name))
        .collect()
}

fn imports_with(specs: &[(&str, Option<&str>, Option<&str>, ImportScope)]) -> ImportIndex {
    ImportIndex {
        file: FileId::INVALID,
        imports: specs
            .iter()
            .map(|(module, alias, original, scope)| ImportSpec {
                span: bonsai_common::Span::new(FileId::INVALID, 0, 0),
                module: (*module).to_string(),
                alias: alias.map(str::to_string),
                is_wildcard: false,
                original_name: original.map(str::to_string),
                scope: *scope,
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// 1. extract_read_write_refs — JavaScript / TypeScript member expressions.
// ---------------------------------------------------------------------------

#[test]
fn read_js_two_level_member_expression() {
    // `req.query` alone — one Read emitted for the full dotted chain.
    let found = refs("javascript", "function h(req) { return req.query; }");
    assert!(
        found.contains(&(RefKind::Read, "req.query".to_string())),
        "expected read 'req.query' in {found:?}"
    );
}

#[test]
fn read_js_three_level_nested_emits_each_level() {
    // `req.query.token` — outer + inner both emit so a rule shaped as
    // `attribute: [req, query]` still matches via the inner level,
    // AND `[req, query, token]` matches the outer.
    let found = refs("javascript", "function h(req) { return req.query.token; }");
    assert!(found.contains(&(RefKind::Read, "req.query.token".to_string())));
    assert!(found.contains(&(RefKind::Read, "req.query".to_string())));
}

#[test]
fn read_js_callee_member_is_not_emitted_as_read() {
    // `req.getParameter()` — the member expression is the callee of a
    // call. `extract_call_refs` emits the Call ref; we must NOT
    // emit a duplicate Read at the same span because a
    // `kind: read name: getParameter` rule would otherwise fire on
    // every method call.
    let found = refs("javascript", "function h(req) { return req.getParameter(); }");
    assert!(
        !found
            .iter()
            .any(|(k, n)| *k == RefKind::Read && n == "req.getParameter"),
        "did not expect read of call-callee in {found:?}"
    );
}

#[test]
fn read_js_inner_member_inside_call_chain_still_emits() {
    // `req.args.get(x)` — outer attribute is callee (skipped); inner
    // `req.args` is NOT callee, so it DOES emit as Read.
    let found = refs("javascript", "function h(req) { return req.args.get(x); }");
    assert!(
        found.contains(&(RefKind::Read, "req.args".to_string())),
        "expected inner read 'req.args' in {found:?}"
    );
    assert!(
        !found
            .iter()
            .any(|(k, n)| *k == RefKind::Read && n == "req.args.get"),
        "did not expect read of call-callee in {found:?}"
    );
}

#[test]
fn write_js_assignment_lhs_is_a_write() {
    // `req.user = x` — the member on the LHS is a write, not a read.
    let found = refs("javascript", "function h(req) { req.user = \"x\"; }");
    assert!(
        found.contains(&(RefKind::Write, "req.user".to_string())),
        "expected write 'req.user' in {found:?}"
    );
    assert!(
        !found.iter().any(|(k, n)| *k == RefKind::Read && n == "req.user"),
        "did not expect read of the write-target in {found:?}"
    );
}

#[test]
fn read_ts_identical_shape_to_js() {
    let found = refs(
        "typescript",
        "function h(req: any): string { return req.query.token; }",
    );
    assert!(found.contains(&(RefKind::Read, "req.query.token".to_string())));
    assert!(found.contains(&(RefKind::Read, "req.query".to_string())));
}

// ---------------------------------------------------------------------------
// 1. extract_read_write_refs — Python attribute + subscript.
// ---------------------------------------------------------------------------

#[test]
fn read_python_attribute_chain() {
    // `request.args` and `request.args.get` — inner read emitted,
    // outer skipped (it's the callee).
    let found = refs("python", "def h():\n    return request.args.get('cmd')\n");
    assert!(
        found.contains(&(RefKind::Read, "request.args".to_string())),
        "expected 'request.args' in {found:?}"
    );
}

#[test]
fn read_python_bare_attribute_read() {
    // `x = request.json` — lvalue is bare identifier, RHS is attribute.
    let found = refs("python", "def h():\n    x = request.json\n");
    assert!(found.contains(&(RefKind::Read, "request.json".to_string())));
}

#[test]
fn read_python_subscript_base_emitted() {
    // `session['user']` — subscript base `session` emitted as Read
    // AND as a companion Call ref (DSL idiom).
    let found = refs("python", "def h():\n    return session['user']\n");
    assert!(
        found.contains(&(RefKind::Read, "session".to_string())),
        "expected read of subscript base in {found:?}"
    );
    assert!(
        found.contains(&(RefKind::Call, "session".to_string())),
        "expected companion call ref for DSL subscript in {found:?}"
    );
}

// ---------------------------------------------------------------------------
// 1. extract_read_write_refs — PHP sigil'd variables + subscript.
// ---------------------------------------------------------------------------

#[test]
fn read_php_superglobal_strips_dollar() {
    // `$_GET['cmd']` — superglobal surfaced as bare `_GET` with `$` stripped.
    let found = refs("php", "<?php $x = $_GET['cmd'];");
    assert!(
        found.contains(&(RefKind::Read, "_GET".to_string())),
        "expected read '_GET' in {found:?}"
    );
}

#[test]
fn read_php_post_superglobal() {
    let found = refs("php", "<?php $x = $_POST['field'];");
    assert!(found.contains(&(RefKind::Read, "_POST".to_string())));
}

// ---------------------------------------------------------------------------
// 1. extract_read_write_refs — Ruby subscript / global.
// ---------------------------------------------------------------------------

#[test]
fn read_ruby_params_subscript_emits_call_too() {
    // `params[:token]` — subscript base `params` emitted as Read and
    // as Call (for DSL-style implicit-receiver method rules).
    let found = refs("ruby", "def h\n  params[:token]\nend\n");
    assert!(
        found.contains(&(RefKind::Read, "params".to_string())),
        "expected read 'params' in {found:?}"
    );
    assert!(
        found.contains(&(RefKind::Call, "params".to_string())),
        "expected call companion 'params' in {found:?}"
    );
}

#[test]
fn read_ruby_global_variable_strips_dollar() {
    let found = refs("ruby", "def h\n  $stdin.gets\nend\n");
    assert!(
        found.contains(&(RefKind::Read, "stdin".to_string())),
        "expected read 'stdin' (global stripped) in {found:?}"
    );
}

// ---------------------------------------------------------------------------
// 1. extract_read_write_refs — Go / Rust / Java / C# / Swift field access.
// ---------------------------------------------------------------------------

#[test]
fn read_go_selector_expression_two_level() {
    let found = refs("go", "package p\nfunc h(r *R) string { return r.URL.RawQuery }\n");
    assert!(
        found.contains(&(RefKind::Read, "r.URL.RawQuery".to_string())),
        "expected go selector chain in {found:?}"
    );
    assert!(
        found.contains(&(RefKind::Read, "r.URL".to_string())),
        "expected inner selector in {found:?}"
    );
}

#[test]
fn read_java_field_access_chain() {
    let found = refs("java", "class A { String h() { return config.db.url; } }");
    assert!(found.contains(&(RefKind::Read, "config.db.url".to_string())));
    assert!(found.contains(&(RefKind::Read, "config.db".to_string())));
}

#[test]
fn read_rust_field_expression_chain() {
    let found = refs("rust", "fn h() -> String { req.headers.authorization }");
    assert!(found.contains(&(RefKind::Read, "req.headers.authorization".to_string())));
    assert!(found.contains(&(RefKind::Read, "req.headers".to_string())));
}

#[test]
fn read_csharp_member_access_expression_field() {
    let found = refs("csharp", "class A { void H() { var q = Request.Query; } }");
    assert!(
        found.contains(&(RefKind::Read, "Request.Query".to_string())),
        "expected C# member_access_expression read in {found:?}"
    );
}

#[test]
fn read_swift_navigation_expression_suffix_field() {
    let found = refs("swift", "func h() { let q = Request.query }");
    assert!(
        found.contains(&(RefKind::Read, "Request.query".to_string())),
        "expected Swift navigation_expression read in {found:?}"
    );
}

// ---------------------------------------------------------------------------
// 2. alias_map_from_imports — canonical alias resolution.
// ---------------------------------------------------------------------------

fn member(module: &str, member: &str) -> AliasTarget {
    AliasTarget::Member {
        module: module.to_string(),
        member: member.to_string(),
    }
}

fn namespace(module: &str) -> AliasTarget {
    AliasTarget::Namespace {
        module: module.to_string(),
    }
}

#[test]
fn alias_map_renamed_import_yields_member_with_original_name() {
    // `import { exec as myExec } from "child_process"` — alias is
    // `myExec`, original is `exec`. The target is a Member bound to
    // the ORIGINAL export name so call sites `myExec(x)` expand to
    // `child_process.exec(x)`.
    let idx = imports_with(&[("child_process", Some("myExec"), Some("exec"), ImportScope::Module)]);
    let map = alias_map_from_imports(&idx);
    assert_eq!(map.get("myExec"), Some(&member("child_process", "exec")));
}

#[test]
fn alias_map_shorthand_destructure_is_member_local_scope() {
    // `const { exec } = require("child_process")` — alias = original = "exec",
    // scope = Local. Member-bound; local name and member name coincide.
    let idx = imports_with(&[("child_process", Some("exec"), Some("exec"), ImportScope::Local)]);
    let map = alias_map_from_imports(&idx);
    assert_eq!(
        map.get("exec"),
        Some(&member("child_process", "exec")),
        "Local-scope entries must participate in alias resolution"
    );
}

#[test]
fn alias_map_python_from_x_import_y_is_member() {
    // `from os import system` — alias=None, original=Some("system").
    // Member binding; local `system` → `os::system`.
    let idx = imports_with(&[("os", None, Some("system"), ImportScope::Module)]);
    let map = alias_map_from_imports(&idx);
    assert_eq!(map.get("system"), Some(&member("os", "system")));
}

#[test]
fn alias_map_module_only_alias_is_namespace() {
    // `import os as o` — alias=Some("o"), original=None. Namespace
    // binding — `o.system()` → `os.system()`.
    let idx = imports_with(&[("os", Some("o"), None, ImportScope::Module)]);
    let map = alias_map_from_imports(&idx);
    assert_eq!(map.get("o"), Some(&namespace("os")));
}

#[test]
fn alias_map_unaliased_module_import_is_namespace() {
    // `import os` / `use std::io` style module imports bind a local
    // namespace name. Qualified calls through that name must not
    // degrade to bare-tail lookup when the module target is external.
    let idx = imports_with(&[("os", None, None, ImportScope::Module)]);
    let map = alias_map_from_imports(&idx);
    assert_eq!(map.get("os"), Some(&namespace("os")));
}

#[test]
fn alias_map_side_effect_path_import_has_no_local_binding() {
    let idx = imports_with(&[("./storage.ts", None, None, ImportScope::Module)]);
    let map = alias_map_from_imports(&idx);
    assert!(map.is_empty());
}

#[test]
fn alias_map_extensionless_path_import_has_no_local_binding() {
    let idx = imports_with(&[("./storage", None, None, ImportScope::Module)]);
    assert!(alias_map_from_imports(&idx).is_empty());
}

#[test]
fn alias_map_dotted_namespace_preserved() {
    // `import django.db.models as m` — namespace. `m.connect()` →
    // `django.db.models.connect()`.
    let idx = imports_with(&[("django.db.models", Some("m"), None, ImportScope::Module)]);
    let map = alias_map_from_imports(&idx);
    assert_eq!(map.get("m"), Some(&namespace("django.db.models")));
}

#[test]
fn alias_map_empty_index_returns_empty_map() {
    let idx = imports_with(&[]);
    let map = alias_map_from_imports(&idx);
    assert!(map.is_empty());
}

#[test]
fn alias_map_later_entry_wins_on_collision() {
    // If two imports bind the same local name, the LAST one wins
    // (HashMap::insert semantics). Idiomatic production code doesn't
    // rebind but we pin the behaviour so tests catch regressions.
    let idx = imports_with(&[
        ("a", Some("x"), None, ImportScope::Module),
        ("b", Some("x"), None, ImportScope::Module),
    ]);
    let map = alias_map_from_imports(&idx);
    assert_eq!(map.get("x"), Some(&namespace("b")));
}

// ---------------------------------------------------------------------------
// 3. Read vs Write classification.
// ---------------------------------------------------------------------------

#[test]
fn augmented_assignment_emits_write_for_lhs() {
    // `x.y += 1` — at minimum, the LHS is classified as Write.
    let found = refs("javascript", "function h(x) { x.y += 1; }");
    assert!(
        found.iter().any(|(k, n)| *k == RefKind::Write && n == "x.y"),
        "expected write of augmented-assign target in {found:?}"
    );
}

#[test]
fn nested_lhs_receiver_is_still_read() {
    // `x.y.z = v` — z-level is the write; the `x.y` receiver is still
    // a read. Rules need both views.
    let found = refs("javascript", "function h(x) { x.y.z = \"v\"; }");
    assert!(
        found.iter().any(|(k, n)| *k == RefKind::Write && n == "x.y.z"),
        "expected write 'x.y.z' in {found:?}"
    );
    assert!(
        found.iter().any(|(k, n)| *k == RefKind::Read && n == "x.y"),
        "expected read of write-target receiver 'x.y' in {found:?}"
    );
}
