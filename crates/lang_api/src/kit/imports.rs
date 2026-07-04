//! Import-statement extraction.
//!
//! Surfaces `import` / `use` / `require` / `#include`-style statements
//! across the supported grammars as [`crate::ImportSpec`]s. The module
//! string is the node's text minus the leading keyword — good enough for
//! reporting and module-name matching, not a precise resolver.

use bonsai_common::FileId;

#[allow(clippy::wildcard_imports)]
use super::*;

/// Scan the tree for import-like statements across common grammars. The
/// text slice from the node (minus the leading keyword) becomes the
/// `module` string — good enough for reporting and for module-name
/// matching, not precise enough for real resolver use.
pub fn extract_generic_imports(tree: &tree_sitter::Tree, file: FileId, src: &[u8]) -> Vec<crate::ImportSpec> {
    const IMPORT_KINDS: &[&str] = &[
        "import_statement",
        "import_from_statement",
        "import_declaration",
        "import_directive",
        // Kotlin surfaces `import x.y.z` as an `import_header` inside an
        // `import_list`.
        "import_header",
        "preproc_include",
        "use_declaration",
        "use_list",
        "using_directive",
        // C++ `using namespace X;` is a using_declaration node.
        "using_declaration",
        "package_clause",
        "namespace_import",
        "namespace_use_declaration",
        // Perl's `use strict;` form.
        "use_statement",
        // Ruby's `require "x"` is a call-expression, not a dedicated node,
        // so we skip it here — the Ruby test covers it via `refs`.
    ];
    let nodes = collect_kinds(tree, IMPORT_KINDS);
    let mut out = Vec::new();
    for node in nodes {
        let text = node_text(&node, src).trim();
        let stripped = text
            .strip_prefix("import ")
            .or_else(|| text.strip_prefix("use "))
            .or_else(|| text.strip_prefix("#include "))
            .or_else(|| text.strip_prefix("using "))
            .or_else(|| text.strip_prefix("require "))
            .unwrap_or(text)
            .trim_end_matches(';')
            .trim();
        // Handle `from X import Y [as Z]` (Python). The logical module is X;
        // we do NOT split out Y into a separate entry — the file_index refs
        // cover per-symbol lookups and the import entry just points at X.
        // `from_original` records the Y part when an alias renames it
        // (Python `from x import y as z` → original="y", alias="z") so
        // the caller-map can add an edge under the original symbol name.
        let mut from_original: Option<String> = None;
        let (module_raw, from_alias): (String, Option<String>) =
            if let Some(rest) = text.strip_prefix("from ") {
                let rest = rest.trim_end_matches(';').trim();
                if let Some((module, imports)) = rest.split_once(" import ") {
                    let imports_trim = imports.trim();
                    // `from x import y as z` — pick the trailing alias and
                    // also remember the `y` piece that the alias rebinds.
                    let alias = imports_trim.rsplit_once(" as ").map(|(orig, a)| {
                        let orig_name = orig
                            .rsplit(',')
                            .next()
                            .unwrap_or(orig)
                            .trim()
                            .trim_matches('(')
                            .trim()
                            .to_string();
                        if !orig_name.is_empty() {
                            from_original = Some(orig_name);
                        }
                        a.trim().to_string()
                    });
                    (module.trim().to_string(), alias)
                } else {
                    (rest.to_string(), None)
                }
            } else if let Some((_before, tail)) = stripped.rsplit_once(" from ") {
                // JS / TS: `import <binding> from "mod"` or
                // `import { a, b } from "mod"` or
                // `import * as alias from "mod"`. Take the quoted module path
                // after the trailing `from`, strip quotes.
                let module = tail
                    .trim()
                    .trim_matches(|c: char| c == '"' || c == '\'')
                    .to_string();
                (module, None)
            } else {
                (stripped.to_string(), None)
            };
        if module_raw.is_empty() {
            continue;
        }
        let module_raw_s: &str = module_raw.as_str();
        // Parse trailing alias forms:
        //   Rust:   `std::fs as f`               → original = `fs`
        //   Kotlin: `kotlin.io.println as p`      → original = `println`
        //   PHP:    `App\Service as S`            → original = `Service`
        //   Scala 2/3: `x.{a => b}`               → original = `a`
        //   JS / TS: `import { a as b } from "x"` → original = `a`
        //   JS / TS: `import * as fs from "fs"`    → module alias (no symbol)
        //   Go:      `f "fmt"` where `f` is the alias preceding the path
        //                                           → module alias
        let mut original_name: Option<String> = from_original.clone();
        let (module_body, alias) = if let Some((alias, scala_orig)) = scala_brace_alias_pair(module_raw_s) {
            if original_name.is_none() {
                original_name = Some(scala_orig);
            }
            (module_raw.clone(), Some(alias))
        } else if let Some((alias, js_orig)) = js_named_rename_alias(text) {
            if original_name.is_none() {
                original_name = Some(js_orig);
            }
            (module_raw.clone(), Some(alias))
        } else if let Some(js_ns_alias) = js_namespace_alias(text) {
            // `import * as fs from "fs"` — namespace alias, no symbol.
            (module_raw.clone(), Some(js_ns_alias))
        } else if let Some((head, tail)) = module_raw_s.rsplit_once(" as ") {
            // Trailing `X as Y` on the module path. Original = last path
            // segment of head (`std::fs as f` → `fs`,
            // `kotlin.io.println as p` → `println`,
            // `App\Service as S` → `Service`).
            let head_trim = head.trim();
            if original_name.is_none() {
                let seg = head_trim
                    .rsplit_once("::")
                    .map(|(_, s)| s)
                    .or_else(|| head_trim.rsplit_once('.').map(|(_, s)| s))
                    .or_else(|| head_trim.rsplit_once('\\').map(|(_, s)| s))
                    .map(str::trim)
                    .unwrap_or(head_trim);
                if !seg.is_empty() && seg.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    original_name = Some(seg.to_string());
                }
            }
            (head_trim.to_string(), Some(tail.trim().to_string()))
        } else if let Some(from_alias) = from_alias {
            (module_raw.clone(), Some(from_alias))
        } else {
            // Go alias form: `alias "path"` where the alias is a bareword
            // preceding a quoted import path (module alias, no symbol).
            if let Some(quote_idx) = module_raw_s.find('"') {
                let before = module_raw_s[..quote_idx].trim();
                if !before.is_empty()
                    && before
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
                    && before != "_"
                {
                    let path_tail = module_raw_s[quote_idx..].trim().trim_matches('"').to_string();
                    (path_tail, Some(before.to_string()))
                } else {
                    (module_raw.clone(), None)
                }
            } else {
                (module_raw.clone(), None)
            }
        };
        // Wildcard detection — covers:
        //   Python  `from x import *`
        //   Java    `import x.*;`
        //   Kotlin  `import x.*`
        //   Rust    `use x::*;`
        //   Scala   `import x._` / `x.*`
        //   PHP     `use X\{A, B};` (braced list — not wildcard, just star)
        let is_wildcard = module_body.ends_with('*')
            || module_body.ends_with("._")
            || module_body.ends_with("::*")
            || from_alias_wildcard_hint(text);
        out.push(crate::ImportSpec {
            span: span_of(file, &node),
            module: module_body,
            alias,
            is_wildcard,
            original_name,
            scope: ImportScope::Module,
        });
    }
    // Post-pass: some languages surface imports as call expressions
    // rather than dedicated statement nodes:
    //   * JavaScript / CommonJS:  `const x = require("mod")`
    //   * Ruby:                   `require "mod"` / `require_relative "./mod"`
    //   * PHP:                    `require "file.php"` / `include "file.php"`
    // Tree-sitter emits these as `call_expression` / `call` nodes whose
    // function name is `require` / `require_relative` / `include` /
    // `include_once` / `require_once`. Walk them out and synthesize
    // ImportSpec entries so the `imports` browse command and alias
    // resolution see them.
    out.extend(scan_call_based_imports(tree, file, src));
    out
}

/// Scan the tree for `require(...)` / `require_relative(...)` /
/// `include(...)` call expressions and synthesize ImportSpec entries.
/// Targets JavaScript (`const x = require("y")`), Ruby (`require 'y'`),
/// and PHP (`require 'y';` / `include 'y';`). These don't surface as
/// dedicated import statement nodes in their Tree-sitter grammars.
fn scan_call_based_imports(tree: &tree_sitter::Tree, file: FileId, src: &[u8]) -> Vec<crate::ImportSpec> {
    const CALL_KINDS: &[&str] = &["call_expression", "call", "function_call_expression"];
    const IMPORT_FN_NAMES: &[&str] = &[
        "require",
        "require_relative",
        "require_once",
        "include",
        "include_once",
    ];
    let mut out: Vec<crate::ImportSpec> = Vec::new();
    let mut seen_spans: ahash::AHashSet<(u64, u64)> = ahash::AHashSet::new();
    for node in collect_kinds(tree, CALL_KINDS) {
        // Look for the function name — either child_by_field_name("function")
        // (JS) or the first identifier descendant (Ruby / PHP call).
        let fn_node = node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("method"))
            .or_else(|| first_identifier_descendant(node));
        let Some(fn_node) = fn_node else { continue };
        let fn_name = node_text(&fn_node, src);
        if !IMPORT_FN_NAMES.contains(&fn_name) {
            continue;
        }
        // The FIRST argument must itself be a string literal. This
        // distinguishes Ruby/JS/PHP `require("path")` (string first
        // arg = the module path) from Solidity's
        // `require(cond, "msg")` (boolean first arg, string in
        // position 2 is an assertion message, not an import). Without
        // this guard, Solidity assertion messages get mis-classified
        // as imports.
        let args_node = node.child_by_field_name("arguments").unwrap_or(node);
        let mut arg_cursor = args_node.walk();
        let first_arg = args_node
            .named_children(&mut arg_cursor)
            .find(|c| !matches!(c.kind(), "comment" | "line_comment" | "block_comment"));
        let Some(first_arg) = first_arg else { continue };
        let Some(module) = find_string_literal_text(first_arg, src) else {
            continue;
        };
        let module_clean = module
            .trim()
            .trim_matches(|c: char| c == '"' || c == '\'' || c == '`')
            .to_string();
        if module_clean.is_empty() {
            continue;
        }
        // Dedupe: JS's `const x = require("y")` can surface the same
        // call node twice if captured by multiple kinds.
        let span = span_of(file, &node);
        let key = (span.start, span.end);
        if !seen_spans.insert(key) {
            continue;
        }
        let declarator = node.parent().filter(|p| p.kind() == "variable_declarator");
        let name_node = declarator.and_then(|vd| vd.child_by_field_name("name"));
        let simple_alias = name_node
            .filter(|n| n.kind() == "identifier")
            .map(|n| node_text(&n, src).to_string());
        let mut rename_entries: Vec<(String, String)> = Vec::new();
        let mut shorthand_entries: Vec<String> = Vec::new();
        if let Some(obj) = name_node.filter(|n| n.kind() == "object_pattern") {
            let mut cur = obj.walk();
            for child in obj.named_children(&mut cur) {
                match child.kind() {
                    "pair_pattern" => {
                        let key = child.child_by_field_name("key");
                        let value = child.child_by_field_name("value");
                        if let (Some(k), Some(v)) = (key, value) {
                            let orig = node_text(&k, src).to_string();
                            let local = node_text(&v, src).to_string();
                            if !orig.is_empty() && !local.is_empty() && orig != local {
                                rename_entries.push((orig, local));
                            }
                        }
                    }
                    "shorthand_property_identifier_pattern" => {
                        let name = node_text(&child, src).to_string();
                        if !name.is_empty() {
                            shorthand_entries.push(name);
                        }
                    }
                    "object_assignment_pattern" => {
                        if let Some(left) = child.child_by_field_name("left") {
                            let name = node_text(&left, src).to_string();
                            if !name.is_empty() {
                                shorthand_entries.push(name);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        out.push(crate::ImportSpec {
            span,
            module: module_clean,
            alias: simple_alias,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
        let module_for_bindings = out.last().map(|spec| spec.module.clone()).unwrap_or_default();
        for (orig, local) in rename_entries {
            out.push(crate::ImportSpec {
                span,
                module: module_for_bindings.clone(),
                alias: Some(local),
                is_wildcard: false,
                original_name: Some(orig),
                scope: ImportScope::Module,
            });
        }
        for name in shorthand_entries {
            out.push(crate::ImportSpec {
                span,
                module: module_for_bindings.clone(),
                alias: Some(name.clone()),
                is_wildcard: false,
                original_name: Some(name),
                scope: ImportScope::Local,
            });
        }
    }
    out
}

fn find_string_literal_text<'a>(node: tree_sitter::Node<'_>, src: &'a [u8]) -> Option<String> {
    // Pre-order DFS for the first string-like descendant.
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        let kind = n.kind();
        if kind == "string"
            || kind == "string_literal"
            || kind == "raw_string_literal"
            || kind == "template_string"
            || kind.ends_with("_string")
        {
            let text = std::str::from_utf8(&src[n.byte_range()]).ok()?;
            return Some(text.to_string());
        }
        let mut cursor = n.walk();
        let children: Vec<tree_sitter::Node<'_>> = n.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    None
}

/// Quick check: `from x import *` surfaces a wildcard flag even though the
/// module text itself doesn't carry the star.
fn from_alias_wildcard_hint(text: &str) -> bool {
    text.contains(" import *") || text.contains("import . \"")
}

/// Scala rename imports use `{orig => alias}` inside the import path.
/// Returns the rightmost alias when the pattern is detected.
/// Scala 2/3 rename imports `import x.{a => b}`. Returns `(alias, original)`.
fn scala_brace_alias_pair(module_raw: &str) -> Option<(String, String)> {
    let open = module_raw.rfind('{')?;
    let close = module_raw[open..].find('}')? + open;
    let body = &module_raw[open + 1..close];
    let (orig, alias) = body.rsplit(',').next()?.split_once("=>")?;
    let alias = alias.trim().to_string();
    let orig = orig.trim().to_string();
    if alias.is_empty() || orig.is_empty() {
        None
    } else {
        Some((alias, orig))
    }
}

/// JS / TS `import * as alias from "mod"` — namespace alias. Returns
/// just the alias; no individual-symbol pair applies (the alias rebinds
/// the whole module, and downstream calls like `alias.foo()` short-tail
/// to `foo` automatically).
fn js_namespace_alias(text: &str) -> Option<String> {
    let rest = text.find("* as ").map(|i| &text[i + 5..])?;
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ',' || c == '}')
        .unwrap_or(rest.len());
    let alias = rest[..end].trim();
    if alias.is_empty() {
        None
    } else {
        Some(alias.to_string())
    }
}

/// JS / TS named-rename form `import { a as b } from "mod"` — returns
/// `(alias, original)` for the rightmost rename.
fn js_named_rename_alias(text: &str) -> Option<(String, String)> {
    let open = text.find('{')?;
    let close = text[open..].find('}')? + open;
    let body = &text[open + 1..close];
    let (orig, alias) = body.rsplit(',').find_map(|piece| piece.split_once(" as "))?;
    let alias = alias.trim().to_string();
    let orig = orig.trim().to_string();
    if alias.is_empty() || orig.is_empty() {
        None
    } else {
        Some((alias, orig))
    }
}
