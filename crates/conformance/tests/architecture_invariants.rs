//! Drift guards for the cross-crate architecture invariants documented
//! in `docs/contributing/architecture.mdx` and `docs/contributing/taint-engine-spec.mdx`.
//!
//! These tests are intentionally side-channel — they read source
//! files / Cargo manifests directly rather than going through any of
//! the analysis APIs. The point is to fail at `cargo test` time when
//! a refactor would otherwise compile and pass every behavioural
//! test while violating one of the spec's non-negotiables.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Engine crates per `docs/contributing/architecture.mdx` — the layer that must
/// remain language-agnostic. None of these may depend on any
/// `bonsai_lang_*` crate; concrete adapter registration belongs to
/// `bonsai_adapters`.
const ENGINE_CRATES: &[&str] = &[
    "taint",
    "callgraph",
    "resolve",
    "cfg",
    "index",
    "db",
    "abstract_interp",
    "trace",
    "diagnostics",
    "common",
    "vfs",
    "parser",
];

/// Non-adapter implementation crates whose runtime dependencies should
/// stay behind `bonsai_lang_api` and `bonsai_adapters`.
const CONCRETE_ADAPTER_DEP_FORBIDDEN_CRATES: &[&str] = &[
    "abstract_interp",
    "browse",
    "callgraph",
    "cfg",
    "common",
    "db",
    "diagnostics",
    "index",
    "inspect",
    "parser",
    "resolve",
    "security",
    "taint",
    "trace",
    "vfs",
    "workspace",
];

fn repo_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .ancestors()
        .find(|p| p.join("Cargo.toml").exists() && p.join("crates").exists())
        .map(Path::to_path_buf)
        .expect("locate workspace root")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn security_analysis_source(root: &Path) -> String {
    let mut source = read(&root.join("crates/security/src/analysis/mod.rs"));
    source.push('\n');
    source.push_str(&read(&root.join("crates/security/src/analysis/execution.rs")));
    source
}

fn production_source(source: &str) -> &str {
    source.split("#[cfg(test)]").next().unwrap_or(source)
}

fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let needle = format!("fn {name}");
    let start = source
        .match_indices(&needle)
        .find_map(|(start, _)| {
            source[start + needle.len()..]
                .chars()
                .next()
                .filter(|next| matches!(next, '(' | '<'))
                .map(|_| start)
        })
        .unwrap_or_else(|| panic!("missing {name}"));
    let open = source[start..]
        .find('{')
        .map(|idx| start + idx)
        .unwrap_or_else(|| panic!("missing body for {name}"));
    let mut depth = 0usize;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[open..=open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated body for {name}");
}

fn struct_body<'a>(source: &'a str, name: &str) -> &'a str {
    let needle = format!("struct {name}");
    let start = source.find(&needle).unwrap_or_else(|| panic!("missing {name}"));
    let open = source[start..]
        .find('{')
        .map(|idx| start + idx)
        .unwrap_or_else(|| panic!("missing body for {name}"));
    let mut depth = 0usize;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[open..=open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated body for {name}")
}

fn live_code(source: &str) -> String {
    source
        .lines()
        .map(|line| line.split("//").next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| panic!("read dir entry under {}: {e}", dir.display()));
        let path = entry.path();
        let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
        if matches!(file_name, ".git" | ".bonsai" | "target") {
            continue;
        }
        let file_type = entry
            .file_type()
            .unwrap_or_else(|e| panic!("file type for {}: {e}", path.display()));
        if file_type.is_dir() {
            collect_rs_files(&path, out);
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn is_test_rs_source(path: &Path) -> bool {
    let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
    path.components().any(|part| part.as_os_str() == "tests")
        || file_name == "tests.rs"
        || file_name.ends_with("_tests.rs")
}

fn production_analysis_complete_true_occurrences(root: &Path) -> BTreeSet<String> {
    let mut files = Vec::new();
    collect_rs_files(&root.join("crates"), &mut files);
    let mut occurrences = BTreeSet::new();
    for file in files {
        let rel = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let file_name = file.file_name().and_then(|name| name.to_str()).unwrap_or("");
        if file.components().any(|part| part.as_os_str() == "tests")
            || file_name == "tests.rs"
            || file_name.ends_with("_tests.rs")
        {
            continue;
        }
        let source = read(&file);
        let mut pending_cfg_test = false;
        let mut in_cfg_test_module = false;
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("#[cfg(test)]") {
                pending_cfg_test = true;
                continue;
            }
            if pending_cfg_test && trimmed.starts_with("mod ") {
                in_cfg_test_module = true;
            }
            pending_cfg_test = false;
            if in_cfg_test_module {
                continue;
            }
            if trimmed.contains("analysis_complete: true") || trimmed.contains("analysis_complete = true") {
                occurrences.insert(format!("{rel}:{trimmed}"));
            }
        }
    }
    occurrences
}

/// User-visible analysis results may not casually hard-code completeness.
/// The remaining production `analysis_complete=true` sites are reviewed
/// local facts: adapter-emitted HIR, CFG built from that HIR, and pattern-only
/// local rule matches. Taint/source/security flow findings derive completion
/// from their analysis context instead.
#[test]
fn production_analysis_complete_true_sites_are_reviewed() {
    let root = repo_root();
    let occurrences = production_analysis_complete_true_occurrences(&root);
    let expected = BTreeSet::from([
        "crates/browse/src/dumps.rs:analysis_complete: true,".to_string(),
        "crates/cfg/src/builder.rs:analysis_complete: true,".to_string(),
        "crates/security/src/analysis/findings_build.rs:analysis_complete: true,".to_string(),
    ]);
    assert_eq!(
        occurrences, expected,
        "new production `analysis_complete=true` sites require explicit audit; derive completion from real analysis metadata unless the fact is exact-local"
    );

    let findings_build = read(&root.join("crates/security/src/analysis/findings_build.rs"));
    assert!(
        function_body(&findings_build, "make_finding")
            .contains("analysis_complete: context.analysis_incomplete_reasons.is_empty()"),
        "taint/source security findings must derive completeness from analysis context"
    );
    assert!(
        function_body(&findings_build, "make_pattern_finding")
            .contains("Pattern-only findings are exact local rule matches"),
        "the pattern-only completeness exception must stay documented at the construction site"
    );

    let cfg = read(&root.join("crates/cfg/src/lib.rs"));
    assert!(
        function_body(&cfg, "default").contains("analysis_complete: false")
            && function_body(&cfg, "analysis_complete_default").contains("false"),
        "synthetic/default CFGs and deserialized legacy CFGs must not claim completion"
    );
}

#[derive(Copy, Clone)]
struct ImportContractCase {
    lang: &'static str,
    file_suffix: &'static str,
    module: &'static str,
    alias: Option<&'static str>,
    original_name: Option<&'static str>,
    is_wildcard: bool,
}

const IMPORT_CONTRACT_CASES: &[ImportContractCase] = &[
    ImportContractCase {
        lang: "c",
        file_suffix: "app.c",
        module: "stdio.h",
        alias: None,
        original_name: None,
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "cpp",
        file_suffix: "app.cpp",
        module: "envelope.hpp",
        alias: None,
        original_name: None,
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "csharp",
        file_suffix: "Pipeline.cs",
        module: "System.Threading.Tasks",
        alias: Some("Tasks"),
        original_name: None,
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "dart",
        file_suffix: "app.dart",
        module: "dart:io",
        alias: None,
        original_name: None,
        is_wildcard: true,
    },
    ImportContractCase {
        lang: "elixir",
        file_suffix: "pipeline.ex",
        module: "Mega.Storage",
        alias: Some("Store"),
        original_name: None,
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "erlang",
        file_suffix: "pipeline.erl",
        module: "storage",
        alias: None,
        original_name: None,
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "go",
        file_suffix: "executor.go",
        module: "os/exec",
        alias: Some("execpkg"),
        original_name: None,
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "java",
        file_suffix: "App.java",
        module: "jakarta.servlet.http.HttpServletRequest",
        alias: Some("HttpServletRequest"),
        original_name: None,
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "javascript",
        file_suffix: "pipeline.js",
        module: "./storage",
        alias: Some("persistEnvelope"),
        original_name: Some("persist"),
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "kotlin",
        file_suffix: "App.kt",
        module: "jakarta.servlet.http.HttpServletRequest",
        alias: Some("HttpServletRequest"),
        original_name: None,
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "lua",
        file_suffix: "storage.lua",
        module: "executor",
        alias: Some("Executor"),
        original_name: None,
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "objc",
        file_suffix: "App.m",
        module: "Foundation/Foundation.h",
        alias: None,
        original_name: None,
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "perl",
        file_suffix: "app.pl",
        module: "CGI",
        alias: None,
        original_name: None,
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "php",
        file_suffix: "pipeline.php",
        module: "Storage",
        alias: Some("Store"),
        original_name: None,
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "python",
        file_suffix: "app.py",
        module: "flask",
        alias: None,
        original_name: Some("request"),
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "ruby",
        file_suffix: "app.rb",
        module: "pipeline",
        alias: None,
        original_name: None,
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "rust",
        file_suffix: "src/main.rs",
        module: "std::io",
        alias: Some("io"),
        original_name: None,
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "scala",
        file_suffix: "Pipeline.scala",
        module: "mega",
        alias: Some("Store"),
        original_name: Some("Storage"),
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "swift",
        file_suffix: "App.swift",
        module: "Foundation",
        alias: None,
        original_name: None,
        is_wildcard: false,
    },
    ImportContractCase {
        lang: "typescript",
        file_suffix: "pipeline.ts",
        module: "./storage",
        alias: Some("persistEnvelope"),
        original_name: Some("persist"),
        is_wildcard: false,
    },
];

#[test]
fn engine_crates_have_no_language_adapter_deps() {
    // architecture.mdx: "Core analysis crates do not depend on
    // concrete language crates. Concrete adapter registration is
    // isolated in crates/adapters." A drift here means an engine
    // crate has acquired a `bonsai_lang_*` dependency, which lets
    // language semantics leak into a layer that's supposed to
    // operate purely on adapter-emitted facts.
    let root = repo_root();
    let mut violations: Vec<String> = Vec::new();
    for crate_name in ENGINE_CRATES {
        let manifest = root.join("crates").join(crate_name).join("Cargo.toml");
        let text = read(&manifest);
        // Walk the manifest line by line so we can distinguish
        // [dependencies] from [dev-dependencies]. Test fixtures
        // are allowed to register concrete adapters; runtime code
        // is not.
        let mut section = String::new();
        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.starts_with('[') && line.ends_with(']') {
                section = line.trim_matches(['[', ']']).to_string();
                continue;
            }
            if section != "dependencies" {
                continue;
            }
            // Strip comments and whitespace, then check whether the
            // crate name on the LHS of `=` starts with `bonsai_lang_`.
            let live = line.split('#').next().unwrap_or("").trim();
            let Some((dep, _)) = live.split_once('=') else {
                continue;
            };
            let dep = dep.trim();
            // `bonsai_lang_api` is the adapter trait + shared
            // types crate — the abstraction every adapter implements
            // and every engine crate consumes. It's the boundary
            // itself, not a concrete adapter, so it's allowed.
            // Forbidden pattern: `bonsai_lang_<concrete>` where
            // `<concrete>` is anything other than `api`.
            if dep.starts_with("bonsai_lang_") && dep != "bonsai_lang_api" {
                violations.push(format!(
                    "engine crate `bonsai_{crate_name}` depends on `{dep}` (manifest: {})",
                    manifest.display()
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "engine crates must not depend on bonsai_lang_* (per docs/contributing/architecture.mdx):\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn adapters_emit_documented_import_targets_for_mega_flow() {
    // ImportSpec.module is the rulepack package-gate key. This test
    // opens each supported mega_flow fixture with the bundled adapter
    // registry and pins one representative adapter-visible target per
    // language to the contract documented on ImportSpec.
    let root = repo_root();
    let mut langs: Vec<&str> = IMPORT_CONTRACT_CASES.iter().map(|case| case.lang).collect();
    langs.sort_unstable();
    langs.dedup();

    let mut violations = Vec::new();
    for lang in langs {
        let fixture_root = root.join("examples").join(lang).join("mega_flow");
        let ws =
            bonsai_workspace::Workspace::open_query(&fixture_root, bonsai_adapters::all_languages_registry())
                .unwrap_or_else(|e| panic!("open {}: {e}", fixture_root.display()));

        for case in IMPORT_CONTRACT_CASES.iter().filter(|case| case.lang == lang) {
            let mut saw_file = false;
            let mut saw_import = false;
            let mut actual = Vec::new();
            for file in ws.vfs().all_files() {
                let path = ws
                    .vfs()
                    .path(file)
                    .unwrap_or_else(|e| panic!("path for {file:?}: {e}"));
                if !path.ends_with(Path::new(case.file_suffix)) {
                    continue;
                }
                saw_file = true;
                let imports = ws
                    .db()
                    .import_index(file)
                    .unwrap_or_else(|| panic!("import_index for {}", path.display()));
                for spec in &imports.imports {
                    actual.push(format!(
                        "module={:?} alias={:?} original={:?} wildcard={}",
                        spec.module, spec.alias, spec.original_name, spec.is_wildcard
                    ));
                    if spec.module == case.module
                        && spec.alias.as_deref() == case.alias
                        && spec.original_name.as_deref() == case.original_name
                        && spec.is_wildcard == case.is_wildcard
                    {
                        saw_import = true;
                    }
                }
            }
            if !saw_file {
                violations.push(format!(
                    "{}: missing mega_flow fixture file {}",
                    case.lang, case.file_suffix
                ));
            } else if !saw_import {
                violations.push(format!(
                    "{} {}: expected module={:?} alias={:?} original={:?} wildcard={}; actual: [{}]",
                    case.lang,
                    case.file_suffix,
                    case.module,
                    case.alias,
                    case.original_name,
                    case.is_wildcard,
                    actual.join("; ")
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "adapter ImportSpec.module outputs drifted from the documented package-gate contract:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn taint_crate_has_no_language_name_branches() {
    // taint-engine-spec.mdx non-negotiable: "Language-name branches
    // in bonsai_taint that replace adapter facts" are forbidden.
    // Any `match`/`if`/identifier referencing a specific language
    // name (python, kotlin, erlang, ...) in non-test code is a
    // violation — the engine is supposed to be language-agnostic
    // and resolve everything via adapter-emitted facts.
    //
    // We allow:
    //   - `#[cfg(test)]` blocks (test fixtures register concrete
    //     adapters; that's fine).
    //   - Pure documentation comments (`//` / `///`).
    //   - References to `language_id` as a TYPE / FIELD name (the
    //     adapter API uses this generic identifier; the rule
    //     forbids matching ON its value).
    let root = repo_root();
    let taint_src = root.join("crates").join("taint").join("src");
    let language_words: &[&str] = &[
        "python",
        "kotlin",
        "java",
        "javascript",
        "typescript",
        "ruby",
        "rust",
        "scala",
        "perl",
        "lua",
        "elixir",
        "erlang",
        "swift",
        "csharp",
        "dart",
        "objc",
        "cpp",
        "php",
    ];
    let files = std::fs::read_dir(&taint_src)
        .unwrap_or_else(|e| panic!("read {}: {e}", taint_src.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect::<Vec<_>>();
    let mut violations: Vec<String> = Vec::new();
    for path in &files {
        if is_test_rs_source(path) {
            continue;
        }
        let text = read(path);
        // Strip everything after a `#[cfg(test)]` annotation — test
        // modules are allowed to mention concrete adapter crates
        // for fixture setup. We use a coarse heuristic: once we
        // see `#[cfg(test)]`, we ignore the rest of the file. This
        // is conservative (won't cleanly handle nested test
        // configs) but sufficient for the current taint codebase.
        let scan_end = text.find("#[cfg(test)]").unwrap_or(text.len());
        let live = &text[..scan_end];
        for (lineno, line) in live.lines().enumerate() {
            let stripped = line.trim_start();
            // Skip line comments — historical notes about removed
            // language branches are fine.
            if stripped.starts_with("//") {
                continue;
            }
            for word in language_words {
                // Word-boundary match (start-of-token / end-of-token).
                // Identifiers like `is_python_remote_call` or a match
                // arm `"python"` would trip; a doc comment that says
                // "python" wouldn't because comments are skipped above.
                if let Some(idx) = line.find(word) {
                    let before = idx == 0
                        || !line.as_bytes()[idx - 1].is_ascii_alphanumeric()
                            && line.as_bytes()[idx - 1] != b'_';
                    let after_idx = idx + word.len();
                    let after = after_idx >= line.len()
                        || !line.as_bytes()[after_idx].is_ascii_alphanumeric()
                            && line.as_bytes()[after_idx] != b'_';
                    if before && after {
                        violations.push(format!(
                            "{}:{}: language-name reference `{word}`: {}",
                            path.file_name().unwrap().to_string_lossy(),
                            lineno + 1,
                            line.trim()
                        ));
                    }
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "bonsai_taint must not contain language-name branches (per docs/contributing/taint-engine-spec.mdx):\n  {}",
        violations.join("\n  ")
    );
}

/// Resolver/callgraph/IDG/taint are compiler backends over adapter-emitted
/// facts. They may compare opaque language identities to prevent cross-language
/// edges, but they must not recognize a concrete language literal. Any syntax
/// or linkage distinction belongs in `LanguageCapabilities` on the adapter.
#[test]
fn compiler_engines_do_not_branch_on_concrete_languages() {
    let root = repo_root();
    let language_literals = [
        "c",
        "cpp",
        "csharp",
        "dart",
        "elixir",
        "erlang",
        "go",
        "java",
        "javascript",
        "kotlin",
        "lua",
        "objc",
        "perl",
        "php",
        "python",
        "ruby",
        "rust",
        "scala",
        "swift",
        "typescript",
    ];
    let mut violations = Vec::new();
    for crate_name in ["callgraph", "resolve", "idg", "taint"] {
        let mut files = Vec::new();
        collect_rs_files(&root.join("crates").join(crate_name).join("src"), &mut files);
        for path in files {
            let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
            if file_name == "tests.rs" || file_name.ends_with("_tests.rs") {
                continue;
            }
            let source = read(&path);
            let scan_end = source.find("#[cfg(test)]").unwrap_or(source.len());
            for (line_index, line) in source[..scan_end].lines().enumerate() {
                let live = line.split("//").next().unwrap_or("");
                for language in language_literals {
                    let literal = format!("\"{language}\"");
                    if live.contains(&literal) {
                        violations.push(format!(
                            "{}:{} contains concrete language literal {literal}",
                            path.strip_prefix(&root).unwrap_or(&path).display(),
                            line_index + 1,
                        ));
                    }
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "compiler engines must consume adapter capabilities instead of concrete language ids:\n  {}",
        violations.join("\n  ")
    );

    let callgraph = read(&root.join("crates/callgraph/src/lib.rs"));
    for capability in [
        "build_target_linkage",
        "callable_declaration_family",
        "quoted_callable_literals",
        "same_directory_unqualified_calls",
        "universal_type_names",
        "module_path_syntax",
    ] {
        assert!(
            callgraph.contains(capability),
            "callgraph must consume adapter-owned `{capability}`"
        );
    }
    for universal_type in ["Object", "Any", "AnyObject", "interface{}"] {
        assert!(
            !callgraph.contains(&format!("\"{universal_type}\"")),
            "callgraph must consume adapter-owned universal type `{universal_type}`"
        );
    }
    let resolver = read(&root.join("crates/resolve/src/lib.rs"));
    assert!(
        resolver.contains("same_directory_unqualified_calls")
            && !resolver.contains("strip_known_import_extension")
            && !resolver.contains("strip_suffix('!')")
            && !resolver.contains("strip_suffix(\"()\")")
            && !resolver.contains("format!(\"{module}.default\")"),
        "resolver must use adapter namespace capabilities and adapter-emitted import aliases"
    );
    let resolver_live = live_code(&resolver);
    let callgraph_live = live_code(&callgraph);
    for rooted_prefix in ["\"crate::\"", "\"self::\"", "\"super::\""] {
        assert!(
            !resolver_live.contains(rooted_prefix),
            "resolver must not own adapter rooted-name token {rooted_prefix}"
        );
        assert!(
            !callgraph_live.contains(rooted_prefix),
            "callgraph must not own adapter rooted-name token {rooted_prefix}"
        );
    }
    let common_names = read(&root.join("crates/common/src/names.rs"));
    assert!(
        !common_names.contains("ABSOLUTE_PATH_PREFIXES")
            && !common_names.contains("VALUE_TEXT_LEADING_KEYWORDS")
            && !common_names.contains("SELF_CONSTRUCTOR_HEADS")
            && !common_names.contains("value_text_returns_self_constructor"),
        "source keywords and rooted qualified-name syntax belong to concrete adapters, not common"
    );
    for adapter in ["lang_rust", "lang_cpp", "lang_php"] {
        let source = read(&root.join("crates").join(adapter).join("src/lib.rs"));
        assert!(
            source.contains("module_path_syntax:"),
            "{adapter} must declare its rooted qualified-name syntax"
        );
    }
    assert!(
        !callgraph.contains("strip_suffix('!')")
            && !callgraph.contains("AliasTarget::Namespace { .. } => Some(\"default\")"),
        "callgraph must preserve adapter-emitted callable names and default-export facts"
    );
    let cross_module = read(&root.join("crates/workspace/src/cross_module.rs"));
    assert!(
        !cross_module.contains("strip_suffix('!')")
            && !cross_module.contains("constructor_type_tail")
            && !cross_module.contains("is_ascii_uppercase"),
        "workspace semantic expansion must consume adapter-emitted callable/type facts"
    );
    let idg_adapter = read(&root.join("crates/idg/src/workspace_adapter.rs"));
    assert!(
        idg_adapter.contains("module_resolution_extensions_for_file")
            && idg_adapter.contains("file_to_module_resolution_extensions")
            && idg_adapter.contains("module_default_export_names")
            && idg_adapter.contains("file_to_module_default_export_names"),
        "IDG module stitching must consume adapter-owned module/export syntax"
    );
    assert!(
        !idg_adapter.contains("\"default\"") && !idg_adapter.contains("\"exports\""),
        "IDG core must not recognize JavaScript/TypeScript export declaration spellings"
    );
    for suffix in [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"] {
        assert!(
            !idg_adapter.contains(&format!("\"{suffix}\"")),
            "IDG core must not carry the concrete module suffix {suffix}"
        );
    }
    let idg_builder = read(&root.join("crates/idg/src/builder.rs"));
    let call_stitch = live_code(function_body(&idg_builder, "stitch_call_site"));
    assert!(
        call_stitch.contains(".position(|param| param == recv)")
            && call_stitch.contains(".position(|param| param == &site.callee_name)"),
        "IDG callback stitching must compare adapter-emitted binding identities exactly"
    );
    for syntax_normalizer in [
        "trim_start_matches",
        "trim_end_matches",
        "strip_prefix",
        "strip_suffix",
    ] {
        assert!(
            !call_stitch.contains(syntax_normalizer),
            "IDG callback stitching must not reinterpret adapter syntax with `{syntax_normalizer}`"
        );
    }

    let workspace = read(&root.join("crates/workspace/src/lib.rs"));
    let taint_idg_build = read(&root.join("crates/taint/src/idg_build.rs"));
    assert!(
        workspace.contains("bonsai_taint::build_resolved_call_graph_snapshot(db)")
            && workspace.contains("bonsai_taint::build_resolved_call_graph_snapshot_for_files(")
            && !workspace.contains("CallGraphFileSemantics::new"),
        "workspace callgraph construction must delegate to the canonical taint compiler facade"
    );
    assert_eq!(
        taint_idg_build.matches("CallGraphFileSemantics::new").count(),
        1,
        "the canonical workspace/IDG callgraph semantics must have one builder"
    );
}

#[test]
fn shared_ast_lowering_selects_adapter_capabilities_not_language_ids() {
    let root = repo_root();
    let walker = root.join("crates/lang_api/src/kit/walker");
    let mut files = Vec::new();
    collect_rs_files(&walker, &mut files);
    let forbidden = ["LanguageId::", "handler.id", "language_id ==", "language_id !="];
    let mut violations = Vec::new();

    for path in files {
        let source = live_code(&read(&path));
        for needle in forbidden {
            if source.contains(needle) {
                violations.push(format!("{} contains {needle}", path.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "shared Tree-sitter lowering must dispatch through GrammarHandler syntax capabilities:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn taint_crate_has_no_concrete_adapter_imports_in_runtime() {
    // Belt-and-braces with the engine-crate dep test: catches the
    // case where someone adds `bonsai_lang_python` as a dep AND
    // imports it directly in non-test code. The dep test would
    // already fail, but if a reviewer accepts the dep change
    // because it "looks like a test helper," this test catches
    // any non-#[cfg(test)] usage.
    let root = repo_root();
    let taint_src = root.join("crates").join("taint").join("src");
    let mut violations: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&taint_src).expect("read taint src") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_none_or(|x| x != "rs") || is_test_rs_source(&path) {
            continue;
        }
        let text = read(&path);
        let scan_end = text.find("#[cfg(test)]").unwrap_or(text.len());
        let live = &text[..scan_end];
        for (lineno, line) in live.lines().enumerate() {
            let stripped = line.trim_start();
            if stripped.starts_with("//") {
                continue;
            }
            // Allow `bonsai_lang_api::` (the adapter trait + types
            // crate); forbid any concrete `bonsai_lang_<name>` use.
            // Detection rule: a `bonsai_lang_` token followed by
            // anything other than `api` (followed by a non-ident
            // char, so we don't match e.g. `api_v2`).
            let mut search_from = 0;
            while let Some(rel) = stripped[search_from..].find("bonsai_lang_") {
                let abs = search_from + rel;
                let tail_start = abs + "bonsai_lang_".len();
                let tail = &stripped[tail_start..];
                let after_api = tail.strip_prefix("api");
                let is_api = after_api.is_some_and(|rest| {
                    rest.as_bytes()
                        .first()
                        .is_none_or(|c| !(c.is_ascii_alphanumeric() || *c == b'_'))
                });
                if !is_api {
                    violations.push(format!(
                        "{}:{}: imports concrete adapter crate: {}",
                        path.file_name().unwrap().to_string_lossy(),
                        lineno + 1,
                        line.trim()
                    ));
                    break;
                }
                search_from = abs + "bonsai_lang_".len();
            }
        }
    }
    assert!(
        violations.is_empty(),
        "non-test code in bonsai_taint must not reference bonsai_lang_*:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn concrete_adapter_runtime_deps_are_isolated_to_registry_and_facades() {
    // architecture.mdx: "Concrete adapter registration is isolated in
    // crates/adapters; both the CLI and SDK consumers can opt into
    // the same 20-language registry via
    // bonsai_adapters::all_languages_registry()." Runtime concrete
    // adapter deps outside these crates let language implementations
    // leak into service/engine crates. Dev-dependencies are allowed
    // for fixture tests.
    let root = repo_root();
    let crates_dir = root.join("crates");
    let mut violations: Vec<String> = Vec::new();
    for entry in fs::read_dir(&crates_dir).unwrap_or_else(|e| panic!("read {}: {e}", crates_dir.display())) {
        let crate_dir = entry.expect("crate dir entry").path();
        if !crate_dir.is_dir() {
            continue;
        }
        let Some(crate_name) = crate_dir.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let manifest = crate_dir.join("Cargo.toml");
        if !manifest.exists() || !CONCRETE_ADAPTER_DEP_FORBIDDEN_CRATES.contains(&crate_name) {
            continue;
        }
        let text = read(&manifest);
        let mut section = String::new();
        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.starts_with('[') && line.ends_with(']') {
                section = line.trim_matches(['[', ']']).to_string();
                continue;
            }
            if section != "dependencies" {
                continue;
            }
            let live = line.split('#').next().unwrap_or("").trim();
            let Some((dep, _)) = live.split_once('=') else {
                continue;
            };
            let dep = dep.trim();
            if dep.starts_with("bonsai_lang_") && dep != "bonsai_lang_api" {
                violations.push(format!(
                    "crate `bonsai_{crate_name}` has runtime concrete adapter dep `{dep}` ({})",
                    manifest.display()
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "concrete language adapter runtime deps must stay isolated to crates/adapters plus SDK/CLI facades:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn cli_dispatch_uses_sdk_facade_not_lower_analysis_crates() {
    // design-patterns.mdx: "CLI may depend only on bonsai_sdk for
    // analysis behaviour." This guard covers the top-level command
    // dispatcher specifically: main.rs should translate clap args
    // into command calls and SDK-facing option types, not reach into
    // workspace / browse / inspect / trace / taint / security crates
    // directly. Command renderer modules still have their own
    // migration path under the B-* boundary fixes.
    let root = repo_root();
    let main_rs = root.join("crates").join("cli").join("src").join("main.rs");
    let text = read(&main_rs);
    let forbidden = [
        "bonsai_workspace",
        "bonsai_security",
        "bonsai_browse",
        "bonsai_inspect",
        "bonsai_taint",
        "bonsai_trace",
    ];
    let mut violations = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let live = line.split("//").next().unwrap_or("").trim();
        if live.is_empty() {
            continue;
        }
        for crate_name in forbidden {
            if live.contains(crate_name) {
                violations.push(format!("main.rs:{}: {live}", lineno + 1));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "CLI dispatch must route analysis-facing types through bonsai_sdk, not lower crates:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn cli_manifest_uses_sdk_facade_not_lower_analysis_crates() {
    // design-patterns.mdx: "CLI may depend only on bonsai_sdk for
    // analysis behaviour." Renderer modules may consume SDK
    // re-exported data shapes, but the binary manifest must not
    // name service/engine crates directly.
    let root = repo_root();
    let manifest = root.join("crates").join("cli").join("Cargo.toml");
    let text = read(&manifest);
    let forbidden = [
        "bonsai_workspace",
        "bonsai_browse",
        "bonsai_inspect",
        "bonsai_security",
        "bonsai_taint",
        "bonsai_trace",
    ];
    let mut section = String::new();
    let mut violations = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = line.trim_matches(['[', ']']).to_string();
            continue;
        }
        if section != "dependencies" {
            continue;
        }
        let live = line.split('#').next().unwrap_or("").trim();
        let Some((dep, _)) = live.split_once('=') else {
            continue;
        };
        let dep = dep.trim();
        if forbidden.contains(&dep) {
            violations.push(format!(
                "crate `bonsai-ninja` depends on `{dep}` ({})",
                manifest.display()
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "CLI manifest must route analysis-facing dependencies through bonsai_sdk:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn cli_source_uses_sdk_facade_not_lower_analysis_paths() {
    // The manifest guard prevents direct dependency reintroduction;
    // this source guard catches drift before a future renderer starts
    // naming lower analysis crates in live code.
    let root = repo_root();
    let cli_src = root.join("crates").join("cli").join("src");
    let forbidden = [
        "bonsai_workspace::",
        "bonsai_browse::",
        "bonsai_inspect::",
        "bonsai_security::",
        "bonsai_taint::",
        "bonsai_trace::",
        "use bonsai_workspace",
        "use bonsai_browse",
        "use bonsai_inspect",
        "use bonsai_security",
        "use bonsai_taint",
        "use bonsai_trace",
    ];
    let mut stack = vec![cli_src.clone()];
    let mut files = Vec::new();
    while let Some(path) = stack.pop() {
        let meta = fs::metadata(&path).unwrap_or_else(|e| panic!("stat {}: {e}", path.display()));
        if meta.is_dir() {
            for entry in fs::read_dir(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display())) {
                stack.push(entry.expect("read cli src entry").path());
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }

    let mut violations = Vec::new();
    for file in files {
        let text = read(&file);
        let rel = file.strip_prefix(&root).unwrap_or(&file);
        for (lineno, line) in text.lines().enumerate() {
            let live = line.split("//").next().unwrap_or("").trim();
            if live.is_empty() {
                continue;
            }
            for pattern in forbidden {
                if live.contains(pattern) {
                    violations.push(format!("{}:{}: {live}", rel.display(), lineno + 1));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "CLI source must consume analysis-facing APIs through bonsai_sdk:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn cli_workspace_open_lifecycle_is_sdk_progress_wiring_only() {
    // docs/contributing/review-checklist.mdx B-2: CLI may own terminal progress chrome, but the
    // parse/index/dataflow lifecycle belongs behind bonsai_sdk.
    let root = repo_root();
    let mod_rs = root
        .join("crates")
        .join("cli")
        .join("src")
        .join("commands")
        .join("mod.rs");
    let text = read(&mod_rs);
    let forbidden = [
        "LanguageRegistry::new",
        "adapters::all_adapters",
        "Workspace::new",
        ".ingest_dir(",
        ".par_iter().for_each",
        ".decl_index(",
        "DataFlowCache::sidecar_path",
        ".load_from_disk(",
        ".prewarm_all_with_progress(",
        ".save_to_disk(",
    ];
    let mut violations = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let live = line.split("//").next().unwrap_or("").trim();
        if live.is_empty() {
            continue;
        }
        for pattern in forbidden {
            if live.contains(pattern) {
                violations.push(format!("commands/mod.rs:{}: {live}", lineno + 1));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "CLI workspace open must call bonsai_sdk progress APIs instead of hand-rolling lifecycle:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn cli_security_pack_validation_delegates_to_sdk() {
    // docs/contributing/review-checklist.mdx B-3 / H-4: pack validation is command-independent
    // security analysis. CLI security.rs may render the report, but
    // must not own the validator's example-workspace construction,
    // matcher execution, or issue model.
    let root = repo_root();
    let security_rs = root
        .join("crates")
        .join("cli")
        .join("src")
        .join("commands")
        .join("security.rs");
    let text = read(&security_rs);
    let forbidden = [
        "struct PackValidationReport",
        "struct PackValidationIssue",
        "fn validate_pack",
        "fn validate_rule_metadata",
        "fn rule_match_target_key",
        "fn validate_yaml_language_field",
        "fn example_workspace",
        "match-example-owner-miss",
        "match-example-collision",
        "match-example-missing-import",
    ];
    let mut violations = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let live = line.split("//").next().unwrap_or("").trim();
        if live.is_empty() {
            continue;
        }
        for pattern in forbidden {
            if live.contains(pattern) {
                violations.push(format!("commands/security.rs:{}: {live}", lineno + 1));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "CLI pack validation must delegate to bonsai_sdk/bonsai_security and only render reports:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn cli_security_command_uses_sdk_security_facade() {
    // docs/contributing/review-checklist.mdx B-5: the security command may own terminal
    // rendering, but command-independent security data types and
    // helper functions must cross through bonsai_sdk.
    let root = repo_root();
    let security_rs = root
        .join("crates")
        .join("cli")
        .join("src")
        .join("commands")
        .join("security.rs");
    let text = read(&security_rs);
    let mut violations = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let live = line.split("//").next().unwrap_or("").trim();
        if live.is_empty() {
            continue;
        }
        if live.contains("bonsai_security") {
            violations.push(format!("commands/security.rs:{}: {live}", lineno + 1));
        }
    }
    assert!(
        violations.is_empty(),
        "CLI security command must import analysis-facing security APIs through bonsai_sdk:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn cli_cache_command_uses_sdk_cache_facade_for_dataflow_sidecar() {
    // docs/contributing/review-checklist.mdx B-6: the CLI cache command may display sidecar
    // paths reported by the SDK, but it must not know the
    // workspace dataflow module's path convention.
    let root = repo_root();
    let cache_rs = root
        .join("crates")
        .join("cli")
        .join("src")
        .join("commands")
        .join("cache.rs");
    let text = read(&cache_rs);
    let forbidden = ["DataFlowCache::sidecar_path", "bonsai_workspace::dataflow"];
    let mut violations = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let live = line.split("//").next().unwrap_or("").trim();
        if live.is_empty() {
            continue;
        }
        for pattern in forbidden {
            if live.contains(pattern) {
                violations.push(format!("commands/cache.rs:{}: {live}", lineno + 1));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "CLI cache command must use bonsai_sdk cache APIs for dataflow sidecar paths:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn cli_trace_command_uses_sdk_trace_types() {
    // docs/contributing/review-checklist.mdx B-7: trace renderers may format SDK trace values,
    // but they should not import bonsai_trace directly.
    let root = repo_root();
    let trace_rs = root
        .join("crates")
        .join("cli")
        .join("src")
        .join("commands")
        .join("trace.rs");
    let text = read(&trace_rs);
    let mut violations = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let live = line.split("//").next().unwrap_or("").trim();
        if live.is_empty() {
            continue;
        }
        if live.contains("bonsai_trace") {
            violations.push(format!("commands/trace.rs:{}: {live}", lineno + 1));
        }
    }
    assert!(
        violations.is_empty(),
        "CLI trace command must consume trace result types through bonsai_sdk:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn cli_export_command_uses_sdk_export_cache_facade() {
    // docs/contributing/review-checklist.mdx B-8: export rendering and default-export cache
    // freshness/path logic belong behind the SDK export/cache
    // facade. A one-shot miss must stream the requested artifact once; only
    // the explicit cache command may publish a hidden default-export cache.
    let root = repo_root();
    let export_rs = root
        .join("crates")
        .join("cli")
        .join("src")
        .join("commands")
        .join("export.rs");
    let text = read(&export_rs);
    let forbidden = [
        "bonsai_workspace",
        "fn export_cache_path",
        "fn export_cache_is_fresh",
        "fn newest_workspace_mtime",
        "EXPORT_CACHE_FILE",
    ];
    let mut violations = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let live = line.split("//").next().unwrap_or("").trim();
        if live.is_empty() {
            continue;
        }
        for pattern in forbidden {
            if live.contains(pattern) {
                violations.push(format!("commands/export.rs:{}: {live}", lineno + 1));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "CLI export command must use bonsai_sdk export/cache APIs for export cache logic:\n  {}",
        violations.join("\n  ")
    );
    let command = function_body(&text, "cmd_export");
    assert!(
        command.contains("stream_default_export_cache_if_fresh")
            && command.contains("write_native_json(&export, options)")
            && !command.contains("warm_default_json_cache")
            && !command.contains("write_default_json_cache_streaming"),
        "one-shot export may reuse an explicit fresh cache but must stream a cache miss directly to the requested sink"
    );
    assert!(
        function_body(&text, "warm_export_cache_for_project").contains("warm_default_json_cache"),
        "default-export cache publication must remain an explicit cache-command operation"
    );
}

#[test]
fn cli_read_file_uses_sdk_rulepack_attachment() {
    // read-file may accept a --rules-dir flag, but rulepack loading and
    // attachment should be handled by the shared SDK project-opening helper.
    let root = repo_root();
    let files = ["read_file.rs"];
    let forbidden = ["bonsai_security", "load_rulepack", "discover_rulepack_root"];
    let mut violations = Vec::new();
    for file in files {
        let path = root
            .join("crates")
            .join("cli")
            .join("src")
            .join("commands")
            .join(file);
        let text = read(&path);
        for (lineno, line) in text.lines().enumerate() {
            let live = line.split("//").next().unwrap_or("").trim();
            if live.is_empty() {
                continue;
            }
            for pattern in forbidden {
                if live.contains(pattern) {
                    violations.push(format!("commands/{file}:{}: {live}", lineno + 1));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "CLI read-file must use SDK rulepack attachment instead of loading packs directly:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn plain_read_file_reuses_one_exact_compiler_body_without_semantic_graphs() {
    let root = repo_root();
    let sdk_read = read(&root.join("crates/sdk/src/read_file.rs"));
    let body = function_body(&sdk_read, "read_file_with_taint_options");
    let overlay_gate = body
        .find("if semantic_overlays_requested")
        .expect("read-file semantic overlay gate");
    let callgraph = body
        .find("cached_resolved_call_graph()")
        .expect("explicit read-file callgraph overlay");
    assert!(
        body.contains("rulepack.is_some()")
            && body.contains("filters.max_inlined_bodies.is_some()")
            && callgraph > overlay_gate,
        "plain read-file must not build a resolved callgraph; only explicit semantic overlays may enter that path"
    );

    let workspace = read(&root.join("crates/workspace/src/lib.rs"));
    let scoped_open = function_body(&workspace, "open_query_matching_path_with_options_and_events");
    assert!(
        scoped_open.contains("load_compiler_object_store_for_selected_path")
            && scoped_open.contains("write_with_id"),
        "path-scoped queries must preserve the selected file's full-workspace FileId and reuse its compiler object"
    );

    let architecture = read(&root.join("docs/contributing/architecture.mdx"));
    assert!(
        architecture.contains("default path never constructs a callgraph")
            && architecture.contains("full-workspace ordinal"),
        "read-file compiler-object and lightweight-overlay contracts must stay documented"
    );
}

#[test]
fn cli_tree_is_filesystem_only() {
    let root = repo_root();
    let path = root.join("crates/cli/src/commands/tree.rs");
    let text = read(&path);
    let forbidden = [
        "open_project",
        "TreeFilters",
        "run_taint_analysis",
        "cached_resolved_call_graph",
        "bonsai_sdk",
        "bonsai_security",
        "bonsai_workspace",
    ];
    let mut violations = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let live = line.split("//").next().unwrap_or("").trim();
        if live.is_empty() {
            continue;
        }
        for pattern in forbidden {
            if live.contains(pattern) {
                violations.push(format!("commands/tree.rs:{}: {live}", lineno + 1));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "CLI tree must remain a direct filesystem view with no compiler or security path:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn security_finding_workers_reuse_the_planners_resolved_callgraph() {
    let root = repo_root();
    let analysis = root.join("crates/security/src/analysis");
    let worker_files = [
        "chain_executor.rs",
        "execution.rs",
        "findings_build.rs",
        "guard_sanitizers.rs",
        "prototype_guard.rs",
    ];
    let mut violations = Vec::new();
    for file in worker_files {
        let source = read(&analysis.join(file));
        for (line, text) in production_source(&source).lines().enumerate() {
            if text.contains("cached_resolved_call_graph()") {
                violations.push(format!("{file}:{}: {}", line + 1, text.trim()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "security finding workers must receive the serial planner's immutable resolved callgraph instead of initializing a workspace-wide lazy cache from Rayon:\n  {}",
        violations.join("\n  ")
    );

    let findings = read(&analysis.join("findings_build.rs"));
    let guards = read(&analysis.join("guard_sanitizers.rs"));
    let execution = read(&analysis.join("execution.rs"));
    assert!(
        findings.contains("call_graph: &'a bonsai_callgraph::ResolvedCallGraph")
            && guards.contains("call_graph: &'a bonsai_callgraph::ResolvedCallGraph")
            && execution.contains("call_graph: chain_call_graph.as_ref()"),
        "the serial source/sink planner must thread one exact resolved callgraph through finding and compiler-guard attribution"
    );
}

#[test]
fn syntax_inventory_commands_never_materialize_workspace_bodies() {
    let root = repo_root();
    for relative in [
        "crates/browse/src/args.rs",
        "crates/browse/src/calls.rs",
        "crates/browse/src/classes.rs",
        "crates/browse/src/comments.rs",
        "crates/browse/src/defs.rs",
        "crates/browse/src/entrypoints.rs",
        "crates/browse/src/operations.rs",
        "crates/browse/src/refs.rs",
        "crates/browse/src/search.rs",
        "crates/browse/src/strings.rs",
        "crates/browse/src/vars.rs",
        "crates/sdk/src/read_file.rs",
        "crates/sdk/src/tree.rs",
    ] {
        let source = read(&root.join(relative));
        assert!(
            !source.contains(".global_index()"),
            "{relative} is a syntax/navigation surface and must stream exact compiler units or compact linkage, not retain every workspace body"
        );
    }

    let calls = read(&root.join("crates/browse/src/calls.rs"));
    let args = read(&root.join("crates/browse/src/args.rs"));
    for (name, source) in [("calls", calls), ("args", args)] {
        assert!(
            source.contains("filtered_file_decl_index(ws, file, f.file)")
                && source.contains(".filter(")
                && source.contains(".push("),
            "{name} must stream file-local Tree-sitter IR and apply query predicates before collecting output rows"
        );
    }
    let browse_common = read(&root.join("crates/browse/src/common.rs"));
    let filtered_index = function_body(&browse_common, "filtered_file_decl_index");
    let path_predicate = filtered_index
        .find("file_path_matches_filter")
        .expect("filtered compiler-object helper must apply the path predicate");
    let body_decode = filtered_index
        .find("decl_index_uncached(file)")
        .expect("filtered compiler-object helper must stream the exact file-local body");
    assert!(
        path_predicate < body_decode,
        "browse path predicates must run before a file-local compiler body is decoded"
    );

    let imports = read(&root.join("crates/browse/src/imports.rs"));
    let imports_body = function_body(&imports, "imports");
    let linkage_init = imports_body
        .find("then(|| ws.compiler_linkage_index())")
        .expect("imports with flow bindings must initialize linkage");
    let parallel_loop = imports_body
        .find(".par_iter()")
        .expect("imports must retain parallel file streaming");
    assert!(
        linkage_init < parallel_loop
            && !function_body(&imports, "resolve_workspace_module_bindings")
                .contains("compiler_linkage_index()"),
        "imports must initialize lazy workspace linkage before entering its Rayon file loop"
    );

    let cli_browse = read(&root.join("crates/cli/src/commands/browse.rs"));
    assert!(
        !function_body(&cli_browse, "read_line").contains("global_index"),
        "syntax renderers must read a requested source line directly from the VFS"
    );
    for function in [
        "cmd_calls",
        "cmd_imports",
        "cmd_vars",
        "cmd_args",
        "cmd_operations",
    ] {
        let body = function_body(&cli_browse, function);
        let json_cost = body
            .find("if !text_cost")
            .unwrap_or_else(|| panic!("{function} must have a JSON-only cost branch"));
        let source_cost = body
            .find("source_line_estimated_cell_cost()")
            .unwrap_or_else(|| panic!("{function} text cost must account for its source line"));
        assert!(
            json_cost < source_cost,
            "{function} must return its JSON row cost before text-only source-line hydration"
        );
    }
}

#[test]
fn interprocedural_taint_uses_db_cached_idg_services() {
    // docs/contributing/review-checklist.mdx BL-2: interprocedural taint must
    // reuse the database-owned semantic graph instead of rebuilding CFGs from
    // FlowEvents for each query.
    let root = repo_root();
    let idg_api = root.join("crates/taint/src/idg_api.rs");
    let text = read(&idg_api);
    let idg_build = read(&root.join("crates/taint/src/idg_build.rs"));
    assert!(
        text.contains("idg_service_for_inter_config(db, config)")
            && idg_build.contains("transfer_options.semantic_fingerprint()")
            && idg_build.contains("db.get_or_init_idg_service_for_semantics(fingerprint, ||")
            && !idg_build.contains("db.idg_service_for_semantics(fingerprint)")
            && !text.contains("build_cfg_from_flow"),
        "interprocedural taint must single-flight a semantics-keyed database IDG cache instead of rebuilding CFGs"
    );
}

#[test]
fn cli_and_sdk_do_not_depend_on_taint_for_rulepack_sanitizers() {
    // Sanitizer rules are report evidence, not CLI/SDK propagation
    // inputs. Keeping bonsai_taint out of the CLI/SDK manifests
    // prevents rulepack sanitizer tokens from leaking back into the
    // facade boundary.
    let root = repo_root();
    let mut violations = Vec::new();
    for crate_name in ["cli", "sdk"] {
        let manifest = root.join("crates").join(crate_name).join("Cargo.toml");
        let text = read(&manifest);
        let mut section = String::new();
        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.starts_with('[') && line.ends_with(']') {
                section = line.trim_matches(['[', ']']).to_string();
                continue;
            }
            if section != "dependencies" {
                continue;
            }
            let live = line.split('#').next().unwrap_or("").trim();
            let Some((dep, _)) = live.split_once('=') else {
                continue;
            };
            if dep.trim() == "bonsai_taint" {
                violations.push(format!(
                    "crate `bonsai_{crate_name}` depends on bonsai_taint ({})",
                    manifest.display()
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "CLI/SDK must not derive rulepack sanitizer propagation profiles:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn matcher_constraint_switches_are_exhaustive_for_arg_tainted() {
    let root = repo_root();
    let matcher = read(
        &root
            .join("crates")
            .join("security")
            .join("src")
            .join("matcher")
            .join("mod.rs"),
    );
    for name in ["compile_constraint_regexes", "constraints_pass_uncached"] {
        let body = function_body(&matcher, name);
        assert!(
            body.contains("ConstraintKind::ArgTainted"),
            "{name} must handle ConstraintKind::ArgTainted explicitly"
        );
        assert!(
            body.contains("ConstraintKind::AnyArgTainted"),
            "{name} must handle ConstraintKind::AnyArgTainted explicitly"
        );
        assert!(
            !body.contains("_ =>"),
            "{name} must not use a wildcard ConstraintKind arm"
        );
    }
}

#[test]
fn arg_tainted_is_not_used_by_sanitizer_rules() {
    let mut violations = Vec::new();
    for rule in rulepack_rules() {
        if rule.family == "sanitizers"
            && rule
                .constraints
                .iter()
                .any(|kind| kind == "arg_tainted" || kind == "any_arg_tainted")
        {
            violations.push(format!("{}: {}", rule.path.display(), rule.id));
        }
    }
    assert!(
        violations.is_empty(),
        "sanitizer rules cannot use arg_tainted:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn enabled_discriminating_constraints_have_negative_examples() {
    let discriminating = [
        "arg_tainted",
        "any_arg_tainted",
        "second_arg_equals",
        "arg_equals",
        "keyword_arg_equals",
        "arg_matches_regex",
        "arg_not_matches_regex",
        "any_arg_matches_regex",
        "format_arg_index",
    ];
    let mut violations = Vec::new();
    for rule in rulepack_rules() {
        if !rule.enabled
            || !rule
                .constraints
                .iter()
                .any(|kind| discriminating.contains(&kind.as_str()))
        {
            continue;
        }
        if !rule.has_negative_example {
            violations.push(format!("{}: {}", rule.path.display(), rule.id));
        }
    }
    assert!(
        violations.is_empty(),
        "enabled discriminating constraints need a negative example:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn arg_tainted_keyword_rules_use_kw_capable_adapters() {
    // Adapters that populate `CallArg.name` so `arg_tainted { kw }` can
    // match a named argument. Perl's `combine_perl_fat_comma_call_args`
    // collapses `f(key => $v)` into one CallArg with `name = Some("key")`,
    // so fat-comma named-arg sinks (Net::LDAP search filter, XML::LibXML
    // load_xml string, Mojolicious render text, ...) match via `kw`.
    let kw_capable = ["python", "dart", "perl"];
    let mut violations = Vec::new();
    for rule in rulepack_rules() {
        if rule.arg_tainted_kw && !kw_capable.contains(&rule.lang.as_str()) {
            violations.push(format!("{}: {}", rule.path.display(), rule.id));
        }
    }
    assert!(
        violations.is_empty(),
        "arg_tainted kw form is only allowed for adapters that populate CallArg.name:\n  {}",
        violations.join("\n  ")
    );
}

#[derive(Debug)]
struct RulepackRule {
    lang: String,
    family: String,
    path: PathBuf,
    id: String,
    enabled: bool,
    constraints: Vec<String>,
    has_negative_example: bool,
    arg_tainted_kw: bool,
}

fn rulepack_rules() -> Vec<RulepackRule> {
    let root = repo_root().join("security-patterns").join("langs");
    let mut out = Vec::new();
    for lang_dir in fs::read_dir(&root).expect("read langs") {
        let lang_dir = lang_dir.expect("lang dir");
        if !lang_dir.file_type().expect("lang file type").is_dir() {
            continue;
        }
        let lang = lang_dir.file_name().to_string_lossy().into_owned();
        for family in ["sources", "sinks", "sanitizers"] {
            let family_dir = lang_dir.path().join(family);
            if !family_dir.exists() {
                continue;
            }
            for entry in fs::read_dir(&family_dir).expect("read family dir") {
                let path = entry.expect("rule file").path();
                if path.extension().and_then(|ext| ext.to_str()) != Some("yml") {
                    continue;
                }
                let value: serde_yaml::Value = serde_yaml::from_str(&read(&path))
                    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
                let Some(rules) = value.as_sequence() else {
                    continue;
                };
                for rule in rules {
                    let id = rule
                        .get("id")
                        .and_then(serde_yaml::Value::as_str)
                        .unwrap_or("<missing-id>")
                        .to_string();
                    let enabled = rule
                        .get("enabled")
                        .and_then(serde_yaml::Value::as_bool)
                        .unwrap_or(false);
                    let constraints = constraint_kinds(rule);
                    let has_negative_example = rule
                        .get("match_examples")
                        .and_then(serde_yaml::Value::as_sequence)
                        .is_some_and(|examples| {
                            examples.iter().any(|example| {
                                example
                                    .get("expect_no_match")
                                    .and_then(serde_yaml::Value::as_bool)
                                    .unwrap_or(false)
                            })
                        });
                    let arg_tainted_kw = arg_tainted_uses_kw(rule);
                    out.push(RulepackRule {
                        lang: lang.clone(),
                        family: family.to_string(),
                        path: path.clone(),
                        id,
                        enabled,
                        constraints,
                        has_negative_example,
                        arg_tainted_kw,
                    });
                }
            }
        }
    }
    out
}

fn constraint_kinds(rule: &serde_yaml::Value) -> Vec<String> {
    rule.get("constraints")
        .and_then(serde_yaml::Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(|constraint| {
            constraint
                .as_mapping()
                .and_then(|mapping| mapping.keys().next())
                .and_then(serde_yaml::Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

fn arg_tainted_uses_kw(rule: &serde_yaml::Value) -> bool {
    rule.get("constraints")
        .and_then(serde_yaml::Value::as_sequence)
        .into_iter()
        .flatten()
        .any(|constraint| {
            constraint
                .get("arg_tainted")
                .and_then(|spec| spec.get("kw"))
                .is_some()
        })
}

/// Drift guard for `docs/contributing/design-patterns.mdx::Semantic Resolution Always`
/// and `docs/contributing/taint-engine-spec.mdx::Non-Negotiables` — the resolver,
/// callgraph, workspace tracer, taint engine, and security matcher must not call
/// raw `find_by_name` without a local justification. Runtime paths
/// that construct graph edges, taint edges, or security findings must
/// supply a `ResolveContext` (caller_file + caller_module) so
/// visibility / `module_path` filtering applies.
///
/// This is the cross-codebase regression the cautionary
/// `static void error(...)` example warns about: when hiredis and Lua
/// each define `error()` privately and the resolver matches by bare
/// name, taint flows into an unrelated codebase.
///
/// There is intentionally no central exception list here. Any raw
/// lookup that remains must carry a nearby
/// `CONTEXTLESS_LOOKUP_JUSTIFICATION:` comment at the call site, so
/// the safety rationale travels with the code being reviewed.
#[test]
fn engine_resolves_via_context_not_bare_name() {
    let root = repo_root();
    let scan_dirs = [
        root.join("crates").join("resolve").join("src"),
        root.join("crates").join("callgraph").join("src"),
        root.join("crates").join("workspace").join("src"),
        root.join("crates").join("taint").join("src"),
        root.join("crates").join("security").join("src"),
    ];

    let mut violations: Vec<String> = Vec::new();
    let mut per_file: Vec<(String, usize)> = Vec::new();
    for dir in &scan_dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if file_name == "tests.rs" || file_name.ends_with("_tests.rs") {
                continue;
            }
            let text = read(&path);
            // Strip #[cfg(test)] tail to ignore test-fixture lookups.
            let body = if let Some(idx) = text.find("#[cfg(test)]") {
                &text[..idx]
            } else {
                text.as_str()
            };
            let lines = body.lines().collect::<Vec<_>>();
            let mut count = 0usize;
            for (line_idx, line) in lines.iter().enumerate() {
                if !line.contains(".find_by_name(") {
                    continue;
                }
                count += 1;
                let start = line_idx.saturating_sub(5);
                let context = lines[start..=line_idx].join("\n");
                if !context.contains("CONTEXTLESS_LOOKUP_JUSTIFICATION:") {
                    let rel = path
                        .strip_prefix(root.join("crates"))
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .into_owned();
                    violations.push(format!(
                        "{rel}:{} calls `find_by_name` without a nearby \
                         CONTEXTLESS_LOOKUP_JUSTIFICATION comment. Use a \
                         context-aware resolver on graph/taint/security paths.",
                        line_idx + 1
                    ));
                }
            }
            if count == 0 {
                continue;
            }
            let rel = path
                .strip_prefix(root.join("crates"))
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            per_file.push((rel.clone(), count));
        }
    }
    assert!(
        violations.is_empty(),
        "raw find_by_name justification violations:\n  {}\n\nPer-file call counts:\n  {}",
        violations.join("\n  "),
        per_file
            .iter()
            .map(|(p, n)| format!("{p}: {n}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

#[test]
fn flow_surfaces_do_not_reintroduce_loose_resolution_or_fabricated_paths() {
    let root = repo_root();
    let checks = [
        (
            "crates/security/src/analysis/mod.rs",
            &[
                "enumerate_tainted_source_paths",
                "tainted_call_adjacency",
                "indexed_tainted_path_between",
                "taint_path_for_chain",
                "chain_precision(",
            ][..],
        ),
        (
            "crates/security/src/analysis/execution.rs",
            &[
                "enumerate_tainted_source_paths",
                "tainted_call_adjacency",
                "indexed_tainted_path_between",
                "taint_path_for_chain",
                "chain_precision(",
            ][..],
        ),
        (
            "crates/taint/src/idg_api.rs",
            &["candidates.first().map(|c| c.func)"][..],
        ),
        (
            "crates/browse/src/edges.rs",
            &[
                "collect_callable_targets(",
                "bonsai_resolve::resolve_callable(",
                ".find_by_name(",
            ][..],
        ),
        (
            "crates/browse/src/native_export.rs",
            &[
                "collect_callable_targets(",
                "bonsai_resolve::resolve_callable(",
                ".find_by_name(",
            ][..],
        ),
        (
            "crates/inspect/src/call_edges.rs",
            &[
                "collect_callable_targets(",
                "bonsai_resolve::resolve_callable(",
                ".find_by_name(",
            ][..],
        ),
        (
            "crates/cli/src/commands/inspect.rs",
            &[
                "collect_callable_targets(",
                "collect_callable_targets_with_context",
                "bonsai_resolve::resolve_callable(",
                ".find_by_name(",
            ][..],
        ),
    ];
    let mut violations = Vec::new();
    for (rel, forbidden) in checks {
        let text = read(&root.join(rel));
        for pattern in forbidden {
            if text.contains(pattern) {
                violations.push(format!("{rel} contains forbidden loose-flow pattern `{pattern}`"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "flow-facing surfaces must use caller-context resolution and lineage evidence only:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn class_constructor_lookup_preserves_ambiguity() {
    let root = repo_root();
    let workspace = read(&root.join("crates/workspace/src/lib.rs"));
    assert!(
        workspace.contains("fn find_constructor_symbols(&self, class_sym: SymbolId) -> Vec<SymbolId>"),
        "class-name constructor lookup must return every constructor candidate, not one arbitrary symbol"
    );
    let constructor_body = function_body(&workspace, "find_constructor_symbols");
    assert!(
        !constructor_body.contains(".first()"),
        "find_constructor_symbols must not pick the first constructor candidate"
    );
    assert!(
        constructor_body.contains("out.extend(") && constructor_body.contains("out.dedup()"),
        "fallback constructor-method lookup must preserve and deduplicate every candidate"
    );
    let resolver_body = function_body(&workspace, "resolve_function_symbol");
    assert!(
        resolver_body.contains("find_constructor_symbols") && resolver_body.contains("AmbiguousSymbol"),
        "resolve_function_symbol must feed all class-routed constructors into the ambiguity path"
    );
}

/// Drift guard for T-5 in docs/contributing/review-checklist.mdx::§4: `TaintedArg.index` must be
/// the call-site argument slot, NOT the callee parameter index.
///
/// The two diverge when the callee declares an implicit-receiver
/// parameter (Rust/Python `self`): a method call `obj.f(x, y)` has
/// args `[x, y]` (post-receiver-normalised) but the callee body sees
/// `self, x, y` so its parameter slots for `x` and `y` are 1 and 2.
/// Reviewers and rule authors expect "argument 0 is tainted" relative
/// to source position — this regression test pins that semantics by
/// inspecting the inter-procedural pass directly.
#[test]
fn tainted_args_index_is_call_site_position() {
    let root = repo_root();
    let text = read(&root.join("crates/taint/src/reachable.rs"));
    let body = function_body(&text, "tainted_args_for_cross_call_edge");
    let call_site_branch = body
        .split_once("`TaintedArg.index` is the call-site argument slot")
        .map(|(_, branch)| branch)
        .expect("the IDG conversion must document the call-site argument-slot contract");
    assert!(
        call_site_branch.contains("index: edge.arg_idx as usize")
            && !call_site_branch.contains("index: edge.param_idx as usize"),
        "TaintedArg.index must use the IDG call-site arg index, not the callee param index"
    );
}

/// Drift guard for Phase F (docs/contributing/review-checklist.mdx::§4 T-1/T-6): adapters must
/// not emit `qualified_name: None` outside the kit defaults that
/// are immediately overwritten by per-adapter post-processing.
///
/// We grep for residual `qualified_name: None,` lines in adapter
/// source under crates/lang_*/src/. The kit's pre-population sites
/// in crates/lang_api/src/kit.rs are allowed (they're overwritten
/// by every adapter's post-process call to
/// apply_file_stem_semantic_identity / apply_module_path_semantic_identity).
/// The Ruby adapter's synthetic __module__ ERB site is also
/// allowed — its qualified_name is patched by the same post-pass
/// applied to non-ERB Ruby files via apply_file_stem_semantic_identity.
///
/// New adapter code that hard-codes `qualified_name: None` without
/// a post-process patch is a regression and fails this test.
#[test]
fn adapters_do_not_emit_qualified_name_none_without_post_process() {
    let root = repo_root();
    let mut violations: Vec<String> = Vec::new();
    let lang_dir = root.join("crates");
    let entries = std::fs::read_dir(&lang_dir).unwrap_or_else(|e| panic!("read {}: {e}", lang_dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !file_name.starts_with("lang_") || file_name == "lang_api" {
            continue;
        }
        let lib_path = path.join("src").join("lib.rs");
        if !lib_path.exists() {
            continue;
        }
        let text = read(&lib_path);
        // Strip #[cfg(test)] tail.
        let body = if let Some(idx) = text.find("#[cfg(test)]") {
            &text[..idx]
        } else {
            text.as_str()
        };
        if !body.contains("qualified_name: None") {
            continue;
        }
        // The adapter must call one of the apply_*_semantic_identity
        // helpers somewhere in the body; otherwise the None will
        // persist into the global index.
        let post_processes = adapter_applies_semantic_identity(body);
        if !post_processes {
            violations.push(format!(
                "{}: emits qualified_name: None without semantic-identity post-process",
                lib_path.display()
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "adapters must not emit qualified_name: None without subsequent post-processing — \
         every Decl needs its qualified_name patched per docs/contributing/design-patterns.mdx::Semantic \
         Resolution Always:\n  {}",
        violations.join("\n  ")
    );
}

/// Every concrete language adapter needs local crate tests in
/// addition to workspace-level integration tests. The workspace
/// harness proves the tool can consume a language; the adapter-local
/// conformance test proves the adapter crate itself cannot regress
/// parse/declaration/trace wiring unnoticed.
#[test]
fn every_language_adapter_crate_has_local_tests() {
    let root = repo_root();
    let crates_dir = root.join("crates");
    let mut violations = Vec::new();
    for entry in fs::read_dir(&crates_dir).expect("read crates dir") {
        let path = entry.expect("crate entry").path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("lang_") || name == "lang_api" {
            continue;
        }
        let tests_dir = path.join("tests");
        let has_rust_test = fs::read_dir(&tests_dir)
            .ok()
            .into_iter()
            .flat_map(|entries| entries.flatten())
            .any(|entry| entry.path().extension().and_then(|s| s.to_str()) == Some("rs"));
        if !has_rust_test {
            violations.push(format!("{name}: missing tests/*.rs"));
        }
    }
    assert!(
        violations.is_empty(),
        "every concrete lang_* adapter crate must carry local Rust tests:\n  {}",
        violations.join("\n  ")
    );
}

/// Each supported language is a compiler frontend: its concrete adapter owns
/// the Tree-sitter grammar and grammar-node vocabulary, while the shared kit
/// only lowers the adapter-provided syntax contract into canonical facts.
/// Keeping these pieces together prevents callgraph/IDG/taint from growing
/// concrete language switches or reparsing source text independently.
#[test]
fn every_language_adapter_owns_its_tree_sitter_lowering() {
    let root = repo_root();
    let crates_dir = root.join("crates");
    let mut checked = 0_usize;
    let mut violations = Vec::new();

    for entry in fs::read_dir(&crates_dir).expect("read crates dir") {
        let path = entry.expect("crate entry").path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("lang_") || name == "lang_api" {
            continue;
        }
        let lib_path = path.join("src/lib.rs");
        if !lib_path.exists() {
            continue;
        }
        checked += 1;
        let source = live_code(&read(&lib_path));
        for required in [
            "const HANDLER: GrammarHandler",
            "impl LanguageAdapter for",
            "fn tree_sitter_language",
            "fn capabilities(",
            "module_default_export_names:",
            "universal_type_names:",
            "module_path_syntax:",
            "super_receiver_tokens:",
            "implicit_receiver_tokens:",
            "call_kinds:",
            "call_ref_kinds:",
            "argument_passing_mode_extractor:",
            "expression_value_kind_extractor:",
            "literal_value_",
            "string_literal_kinds:",
            "fn extract_imports",
        ] {
            if !source.contains(required) {
                violations.push(format!("{name}: missing adapter-owned `{required}`"));
            }
        }
        if !source.contains("decl_index_with_handler(")
            && !source.contains("decl_index_from_tree_with_handler(")
        {
            violations.push(format!(
                "{name}: missing adapter-owned Tree-sitter declaration lowering entrypoint"
            ));
        }
        for forbidden in ["GENERIC_HANDLER", "COMMON_CALL_KINDS", "with_fn_kinds"] {
            if source.contains(forbidden) {
                violations.push(format!(
                    "{name}: inherits shared syntax through forbidden `{forbidden}`"
                ));
            }
        }
    }

    let shared_kit = read(&root.join("crates/lang_api/src/kit/mod.rs"));
    let identifiers = read(&root.join("crates/lang_api/src/kit/identifiers.rs"));
    assert!(
        !shared_kit.contains("|| GENERIC_HANDLER"),
        "GrammarHandler classification must use only the active adapter's exact syntax inventory"
    );
    assert!(
        !shared_kit.contains("const STRING_KINDS") && !identifiers.contains("fn looks_like_literal_value"),
        "shared lowering must not restore a cross-language literal/token inventory"
    );

    assert_eq!(checked, 20, "expected every bundled language compiler frontend");
    assert!(
        violations.is_empty(),
        "each lang_* crate must own its Tree-sitter syntax lowering:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn grammar_variants_are_selected_by_the_owning_adapter() {
    let root = repo_root();
    let typescript = read(&root.join("crates/lang_typescript/src/lib.rs"));
    let parser = read(&root.join("crates/parser/src/lib.rs"));
    let highlighter_source = read(&root.join("crates/cli/src/syntax_highlight.rs"));
    let highlighter = production_source(&highlighter_source);

    assert!(
        typescript.contains("fn grammar_name_for_path")
            && typescript.contains("TSX_PACK_NAME")
            && typescript.contains("grammar_pack_for_file(file, ctx)"),
        "the TypeScript adapter must select its TSX grammar for every direct and cached parse"
    );
    assert!(
        parser.contains("adapter.grammar_name_for_path(&path)")
            && parser.contains("adapter.tree_sitter_language_for_path(&path)")
            && parser.contains("grammar_name: &'static str"),
        "the parser cache must key and load the adapter-selected grammar variant"
    );
    for forbidden in ["\"tsx\"", "\"mts\"", "\"cts\""] {
        assert!(
            !highlighter.contains(forbidden),
            "syntax highlighting must derive {forbidden} from adapter extensions, not a parallel CLI table"
        );
    }
}

// docs/contributing/review-checklist.mdx §2.8 drift guards. Each test asserts a specific
// adapter-fact contract that downstream resolution depends on.
// Without these, a reviewer accepting a partial migration would
// silently regress the whole-workspace identity guarantees the
// resolver relies on.

/// Every adapter must populate `Decl.qualified_name` for every
/// emitted Decl after post-processing — `None` would force the
/// resolver to fall back to bare-name lookup. Verified by checking
/// that every adapter calls one of the
/// `apply_*_semantic_identity` helpers, which patch every decl's
/// `qualified_name` via the kit. Adapters that emit a literal
/// `qualified_name: Some(...)` inline are also accepted.
#[test]
fn every_adapter_populates_qualified_name() {
    let root = repo_root();
    let crates_dir = root.join("crates");
    let mut violations: Vec<String> = Vec::new();
    for entry in fs::read_dir(&crates_dir).expect("read crates dir") {
        let path = entry.expect("crate entry").path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("lang_") || name == "lang_api" {
            continue;
        }
        let lib_path = path.join("src").join("lib.rs");
        if !lib_path.exists() {
            continue;
        }
        let text = read(&lib_path);
        let body = if let Some(idx) = text.find("#[cfg(test)]") {
            &text[..idx]
        } else {
            text.as_str()
        };
        let calls_post_process = adapter_applies_semantic_identity(body);
        let emits_inline_qualified = body.contains("qualified_name: Some(");
        if !calls_post_process && !emits_inline_qualified {
            violations.push(format!(
                "{}: adapter does not populate `qualified_name` (no apply_*_semantic_identity call \
                 and no inline `qualified_name: Some(...)`)",
                lib_path.display()
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "every adapter must populate Decl.qualified_name (per docs/contributing/design-patterns.mdx::Semantic \
         Resolution Always):\n  {}",
        violations.join("\n  ")
    );
}

/// Every adapter must populate `Decl.visibility` from real syntax
/// markers — never the kit `Public` default unaltered. We verify
/// each adapter EITHER calls `collect_modifier_visibility` /
/// `collect_csharp_visibility` / `collect_scala_visibility` /
/// `apply_ruby_scope_visibility` / a per-language equivalent, OR
/// the language doesn't expose syntactic visibility (Erlang
/// `-export([...])`, Lua `local`) and the adapter handles that
/// explicitly via its own pass.
#[test]
fn every_adapter_populates_visibility_from_syntax() {
    let root = repo_root();
    let crates_dir = root.join("crates");
    // Adapters whose languages don't carry per-decl visibility
    // syntax — visibility flows from the export list / module
    // structure / `local` keyword instead.
    let no_per_decl_syntax = ["lang_lua"];
    let mut violations: Vec<String> = Vec::new();
    for entry in fs::read_dir(&crates_dir).expect("read crates dir") {
        let path = entry.expect("crate entry").path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("lang_") || name == "lang_api" {
            continue;
        }
        if no_per_decl_syntax.contains(&name) {
            continue;
        }
        let lib_path = path.join("src").join("lib.rs");
        if !lib_path.exists() {
            continue;
        }
        let text = read(&lib_path);
        let body = if let Some(idx) = text.find("#[cfg(test)]") {
            &text[..idx]
        } else {
            text.as_str()
        };
        let has_visibility_pass = body.contains("collect_modifier_visibility")
            || body.contains("collect_csharp_visibility")
            || body.contains("collect_scala_visibility")
            || body.contains("apply_ruby_scope_visibility")
            || body.contains("Visibility::Private")
            || body.contains("Visibility::Module")
            || body.contains("Visibility::Protected")
            || body.contains("Visibility::Crate");
        if !has_visibility_pass {
            violations.push(format!(
                "{}: adapter does not derive visibility from syntax markers",
                lib_path.display()
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "every adapter must populate Decl.visibility from real syntax:\n  {}",
        violations.join("\n  ")
    );
}

/// Every adapter must populate `Decl.module_path` so the resolver
/// can apply `Visibility::Module` / `Visibility::Crate` filters.
/// Verified by the kit post-processing helpers — each adapter must
/// call one of `apply_file_stem_semantic_identity` (which sets
/// `module_path` to `[<file_stem>]`) or
/// `apply_module_path_semantic_identity` (which sets a richer
/// per-language path).
#[test]
fn every_adapter_populates_module_path() {
    let root = repo_root();
    let crates_dir = root.join("crates");
    let mut violations: Vec<String> = Vec::new();
    for entry in fs::read_dir(&crates_dir).expect("read crates dir") {
        let path = entry.expect("crate entry").path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("lang_") || name == "lang_api" {
            continue;
        }
        let lib_path = path.join("src").join("lib.rs");
        if !lib_path.exists() {
            continue;
        }
        let text = read(&lib_path);
        let body = if let Some(idx) = text.find("#[cfg(test)]") {
            &text[..idx]
        } else {
            text.as_str()
        };
        let has_module_path = adapter_applies_semantic_identity(body);
        if !has_module_path {
            violations.push(format!(
                "{}: adapter does not populate `module_path` (no apply_*_semantic_identity call)",
                lib_path.display()
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "every adapter must populate Decl.module_path:\n  {}",
        violations.join("\n  ")
    );
}

fn adapter_applies_semantic_identity(body: &str) -> bool {
    body.contains("apply_file_stem_semantic_identity")
        || body.contains("apply_module_path_semantic_identity")
        || body.contains("apply_swift_semantic_identity")
}

/// Call-arg indexing must be post-receiver-normalised across every
/// adapter — `obj.method(a, b)` indexes args as `[a, b]`, never
/// `[obj, a, b]`. The drift guard pins the contract by ensuring
/// adapters use the kit's `walk_flow_events` (which performs the
/// normalisation) rather than rolling their own arg extraction.
#[test]
fn call_args_are_post_receiver_normalized() {
    let root = repo_root();
    let crates_dir = root.join("crates");
    let mut violations: Vec<String> = Vec::new();
    for entry in fs::read_dir(&crates_dir).expect("read crates dir") {
        let path = entry.expect("crate entry").path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("lang_") || name == "lang_api" {
            continue;
        }
        let lib_path = path.join("src").join("lib.rs");
        if !lib_path.exists() {
            continue;
        }
        let text = read(&lib_path);
        let body = if let Some(idx) = text.find("#[cfg(test)]") {
            &text[..idx]
        } else {
            text.as_str()
        };
        // Adapters that hand-roll `args.push(receiver.clone())` or
        // similar receiver-prepending logic violate the contract.
        // The kit normalisation is the only allowed path.
        let prepends_receiver = body.contains("args.insert(0, ")
            || body.contains("args.push(receiver.")
            || body.contains("CallArg { value_text: receiver");
        if prepends_receiver {
            violations.push(format!(
                "{}: adapter prepends receiver to call args; use kit normalisation instead",
                lib_path.display()
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "call args must be post-receiver-normalised (per docs/contributing/design-patterns.mdx::Semantic \
         Resolution Always):\n  {}",
        violations.join("\n  ")
    );
}

/// `CallArg.value_text` is retained for exact display/callback/literal
/// resolver spelling. It must never become an alternate parser input for
/// taint propagation: argument carriers come exclusively from the adapter's
/// AST-derived `place` and `source_names` facts.
#[test]
fn idg_taint_does_not_reparse_call_arg_value_text() {
    let root = repo_root();
    let transfer = read(&root.join("crates").join("idg").join("src").join("transfer.rs"));
    let allowed_uses = [
        // Literal selector spelling is consumed as a field-resolution key,
        // not tokenised into taint carriers.
        "quoted_storage_selector(&arg.value_text)",
        // The callback resolver receives the exact source spelling.
        "arg_values.push(arg.value_text.clone())",
    ];
    let violations: Vec<_> = transfer
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("arg.value_text"))
        .filter(|(_, line)| !allowed_uses.iter().any(|allowed| line.contains(allowed)))
        .map(|(line, text)| format!("{}: {}", line + 1, text.trim()))
        .collect();
    assert!(
        violations.is_empty(),
        "IDG taint must consume CallArg.place/source_names, never parse value_text:\n  {}",
        violations.join("\n  ")
    );
}

/// Overlapping endpoint attribution must join the matcher's call argument to
/// taint evidence through adapter-lowered places and value carriers. Rendered
/// call text is diagnostic output, not a second language parser.
#[test]
fn security_taint_endpoint_join_uses_compiler_value_identities() {
    let root = repo_root();
    let matcher = read(&root.join("crates/security/src/matcher/mod.rs"));
    for retired_parser in [
        "fn quoted_literal",
        "fn expression_contains_identifier",
        "receiver.contains(arg_value)",
    ] {
        assert!(
            !matcher.contains(retired_parser),
            "security taint endpoint join must not restore rendered-text parser `{retired_parser}`"
        );
    }
    let join = function_body(&matcher, "tainted_call_has_arg");
    let argument_join = function_body(&matcher, "arg_matches_tainted_value");
    assert!(
        join.contains("arg_matches_tainted_value")
            && join.contains("tainted_receiver_source_names")
            && argument_join.contains("structured_argument_names")
            && argument_join.contains("tainted_argument_names")
            && !join.contains("value_text")
            && !argument_join.contains("value_text"),
        "security taint endpoint attribution must join typed argument/receiver carriers"
    );
}

/// Two private decls in different translation units that share a
/// bare name must NOT collide in the resolver. The motivating
/// regression: hiredis and Lua each defined `static void error()`,
/// and a bare-name resolver matched both. The resolver narrows by
/// `Visibility::Private` (decl_file == caller_file). This test
/// checks the resolver primitive's invariant directly — not the
/// adapters — by reading `crates/resolve/src/lib.rs` and asserting
/// the visibility filter is unconditional.
#[test]
fn same_name_tu_private_decls_do_not_collide() {
    let root = repo_root();
    let resolve_lib = root.join("crates").join("resolve").join("src").join("lib.rs");
    let text = read(&resolve_lib);
    // The `visibility_allows` predicate must check
    // `Visibility::Private` against `decl_file == ctx.caller_file`.
    // Removing this branch would make private decls cross TUs.
    let private_arm = text.contains("Visibility::Private =>");
    assert!(
        private_arm,
        "resolve/src/lib.rs::visibility_allows must explicitly handle Visibility::Private to \
         prevent same-name cross-TU collisions (the hiredis/Lua `static void error(...)` \
         regression in docs/contributing/design-patterns.mdx::Semantic Resolution Always)"
    );
    // The `resolve_callable_with_context` function must apply
    // `visibility_allows` to every candidate (no branches that bypass it).
    let body = function_body(&text, "resolve_callable_with_context");
    assert!(
        body.contains("visibility_allows("),
        "resolve_callable_with_context must filter every candidate through visibility_allows"
    );
}

/// `kind: param` rules with `in_class:` constraints must accept both a
/// direct class-name match AND any name in the enclosing class's `bases`
/// list, so `class Echo(WebSocketHandler):` matches
/// `in_class: [WebSocketHandler]` (docs/contributing/design-patterns.mdx
/// ::Semantic Resolution Always).
///
/// The in_class gate is shared across the param / call / read / write
/// scanners and lives in `decl_target_context_allows`, which
/// `scan_params_batch` delegates to — so this invariant pins the
/// ancestry consultation there (`enclosing_class.bases` checked against
/// `target.in_class`) AND verifies `scan_params_batch` routes through
/// that gate rather than re-implementing a name-only class check.
#[test]
fn param_in_class_constraint_consults_decl_bases() {
    let root = repo_root();
    let matcher = root
        .join("crates")
        .join("security")
        .join("src")
        .join("matcher")
        .join("mod.rs");
    let text = read(&matcher);
    // scan_params_batch must run params through the shared context gate.
    let params_body = function_body(&text, "scan_params_batch");
    assert!(
        params_body.contains("decl_target_context_allows("),
        "scan_params_batch must enforce in_class / in_method via decl_target_context_allows"
    );
    // The shared gate must match in_class against the enclosing class's
    // `bases` (ancestry), not only its own name.
    let gate_body = function_body(&text, "decl_target_context_allows");
    assert!(
        gate_body.contains("enclosing_class") && gate_body.contains(".bases"),
        "decl_target_context_allows must consult enclosing_class.bases for in_class ancestry matching"
    );
    assert!(
        gate_body.contains("in_class"),
        "decl_target_context_allows must match the enclosing class (or a base) against target.in_class"
    );
}

/// Receiver-method dispatch must narrow by receiver type when one
/// is known. `FlowEvent::Call::receiver_types` is the canonical
/// semantic fact; `Decl.type_aliases` is only the legacy derivation
/// fallback for callers that predate the shared index pass.
#[test]
fn receiver_method_dispatch_narrows_by_type() {
    let root = repo_root();
    let cg_lib = root.join("crates").join("callgraph").join("src").join("lib.rs");
    let text = read(&cg_lib);
    let body = function_body(&text, "collect_receiver_method_targets");
    assert!(
        body.contains("receiver_types.to_vec()"),
        "collect_receiver_method_targets must consume FlowEvent::Call::receiver_types before resolving methods"
    );
    assert!(
        body.contains("receiver_type_names_for_expr("),
        "collect_receiver_method_targets may only fall back to deriving receiver types when call facts are empty"
    );
    let receiver_type_names = function_body(&text, "receiver_type_names_for_expr");
    assert!(
        receiver_type_names.contains("type_alias_for_receiver("),
        "receiver_type_names_for_expr must consult adapter-declared receiver type aliases"
    );
    let type_alias_for_receiver = function_body(&text, "type_alias_for_receiver");
    assert!(
        type_alias_for_receiver.contains("type_aliases"),
        "type_alias_for_receiver must consult Decl.type_aliases for receiver narrowing"
    );
    assert!(
        body.contains("resolve_class("),
        "collect_receiver_method_targets must use resolve_class (context-aware) instead of bare \
         workspace-wide lookups"
    );
    // The fallback when caller_file is unavailable must NOT be a
    // bare `find_by_name` call — that would re-introduce the
    // cross-TU collision the semantic-resolution doctrine forbids.
    assert!(
        !body.contains("find_by_name"),
        "collect_receiver_method_targets must not contain `find_by_name`; bare lookup re-introduces \
         the cross-TU receiver-method collision"
    );
}

/// Visibility is not name resolution. A context-aware resolver must
/// never turn "the nearest public name in the workspace" into a
/// semantic edge; unqualified names need same lexical scope,
/// import/alias evidence, an explicit module qualifier, or
/// receiver/type evidence.
#[test]
fn resolver_does_not_use_nearest_public_name_as_semantic_evidence() {
    let root = repo_root();
    let resolve_lib = root.join("crates").join("resolve").join("src").join("lib.rs");
    let text = read(&resolve_lib);
    let body = function_body(&text, "resolve_callable_with_context");
    assert!(
        body.contains("collect_caller_lexical_scope"),
        "resolve_callable_with_context must restrict unqualified lookup to caller lexical scope"
    );
    assert!(
        !body.contains("retain_closest_module"),
        "resolve_callable_with_context must not choose a nearest public workspace name"
    );
    let class_body = function_body(&text, "resolve_class");
    assert!(
        class_body.contains("retain_caller_lexical_symbol_candidates"),
        "resolve_class must restrict unqualified type lookup to caller lexical scope"
    );
}

/// Method ownership must come from adapter-emitted semantic parent
/// links. Span containment was a temporary fallback that can bind
/// nested/local declarations to the wrong class in large workspaces.
#[test]
fn method_dispatch_does_not_use_span_containment_as_parent_fallback() {
    let root = repo_root();
    for rel in [
        "crates/callgraph/src/lib.rs",
        "crates/workspace/src/cross_module.rs",
        "crates/taint/src/idg_api.rs",
        "crates/security/src/matcher/mod.rs",
        "crates/browse/src/classes.rs",
        "crates/browse/src/native_export.rs",
        "crates/cli/src/commands/inspect.rs",
    ] {
        let text = read(&root.join(rel));
        assert!(
            !text.contains("span_contains(class_decl.span, decl.span)"),
            "{rel}: method dispatch must require Decl.parent == class_sym, not span containment"
        );
        assert!(
            !text.contains("span_contains(candidate.span, decl.span)"),
            "{rel}: declaring-class inference must not recover ownership by source span"
        );
    }
}

/// Public IDG-backed taint wrappers are evidence-producing APIs, so
/// they must default to the semantic precision ceiling. Diagnostic
/// callers can still opt into unscoped reachability through a typed
/// query request with `with_max_precision(None)`.
#[test]
fn public_idg_taint_wrappers_are_semantic_by_default() {
    let root = repo_root();
    let taint_reachable = read(&root.join("crates/taint/src/reachable.rs"));
    let taint_query = read(&root.join("crates/taint/src/idg_query.rs"));
    for (function, constructor) in [
        ("source_seed_reaches_return_from_idg", "IdgReturnQuery::semantic"),
        ("entry_taint_call_records_from_idg", "IdgTaintQuery::semantic"),
        ("entry_taint_graph_from_idg", "IdgTaintQuery::semantic"),
    ] {
        let body = function_body(&taint_reachable, function);
        assert!(
            body.contains(constructor),
            "{function} must construct the semantic typed IDG query"
        );
        assert!(
            !body.contains("\n        None,\n"),
            "{function} must not delegate to unscoped diagnostic reachability by default"
        );
    }
    assert!(
        function_body(&taint_query, "semantic").contains("max_precision: Some(Precision::Narrowed)"),
        "typed IDG taint queries must default to the semantic precision ceiling"
    );
    for legacy_ladder in [
        "source_seed_reaches_return_from_idg_with_max_precision",
        "entry_taint_call_records_from_idg_with_max_precision",
        "entry_taint_call_records_from_idg_with_target_filters_and_max_precision",
        "entry_taint_graph_from_idg_with_max_precision",
        "entry_taint_graph_from_idg_with_target_funcs_and_max_precision",
        "entry_taint_graph_from_idg_with_target_filters_and_max_precision",
        "entry_taint_graph_from_idg_with_target_nodes_and_filters_and_max_precision",
    ] {
        assert!(
            !taint_reachable.contains(legacy_ladder),
            "IDG taint query options must stay in typed requests, not regrow the positional `{legacy_ladder}` ladder"
        );
    }
    assert!(
        taint_reachable.contains("pub fn entry_taint_graph_from_idg_query(request: IdgTaintQuery<'_>)",)
            && taint_reachable
                .contains("pub fn entry_taint_call_records_from_idg_query(request: IdgTaintQuery<'_>)",),
        "advanced IDG taint surfaces must accept one typed query request"
    );
}

/// A canonical IDG query already owns the compact, exact compiler linkage
/// used to build or validate that graph. Query execution must reuse it rather
/// than materializing a second workspace-wide body index. Exact function
/// bodies are not required for rulepack-free inspect seeding or rendered call
/// attribution; function frames are decoded only for contributing evidence.
#[test]
fn idg_taint_queries_reuse_canonical_linkage_without_global_body_materialization() {
    let root = repo_root();
    let reachable = read(&root.join("crates/taint/src/reachable.rs"));
    let idg_api = read(&root.join("crates/taint/src/idg_api.rs"));
    let summaries = read(&root.join("crates/taint/src/idg_api/summary.rs"));

    for function in [
        "source_seed_reaches_return_from_idg_query",
        "entry_taint_call_records_from_idg_query",
        "entry_taint_graph_from_idg_query",
    ] {
        let body = function_body(&reachable, function);
        assert!(
            body.contains("global_linkage_index()"),
            "{function} must reuse the canonical IDG compiler linkage"
        );
        assert!(
            !body.contains("db.global_index()"),
            "{function} must not materialize every workspace body during an IDG query"
        );
    }
    let inspect_wrapper = function_body(&reachable, "inspect_entry_taint_graph_from_idg_with_target_funcs");
    let inspect_implementation = function_body(
        &reachable,
        "inspect_entry_taint_graph_from_idg_with_target_funcs_and_lineage_with_caches",
    );
    assert!(
        inspect_wrapper.contains("inspect_entry_taint_graph_from_idg_with_target_funcs_and_lineage")
            && inspect_implementation.contains("global_linkage_index()")
            && !inspect_implementation.contains("db.global_index()"),
        "rulepack-free inspect wrappers must terminate at the canonical IDG compiler linkage"
    );
    assert!(
        function_body(
            &reachable,
            "inspect_entry_taint_graph_from_idg_with_target_funcs_and_lineage_with_caches"
        )
        .contains("read_or_write_names_of_func")
            && function_body(
                &reachable,
                "inspect_entry_taint_graph_from_idg_with_target_funcs_and_lineage_with_caches"
            )
            .contains("IdgTaintSource::precomposed")
            && !function_body(
                &reachable,
                "inspect_entry_taint_graph_from_idg_with_target_funcs_and_lineage_with_caches"
            )
            .contains("exact_decl_for_func"),
        "rulepack-free inspect must seed from exact IDG places and compact params without reopening compiler bodies"
    );

    for function in [
        "idg_backed_interprocedural_taint_with_service",
        "idg_backed_call_site_receives_taint",
    ] {
        let body = function_body(&idg_api, function);
        assert!(
            body.contains("global_linkage_index()")
                && body.contains("exact_decl_for_func")
                && body.contains("compose_idg_seed_nodes_with_decl")
                && !body.contains("db.global_index()"),
            "{function} must compose public API seeds from IDG linkage plus one exact compiler body"
        );
    }
    let summary = function_body(&summaries, "function_summary");
    assert!(
        summary.contains("global_linkage_index()") && !summary.contains("db.global_index()"),
        "function summaries must not rebuild workspace bodies beside the IDG"
    );
}

/// IDG query-service defaults are evidence-producing APIs. They must
/// cap reachability at the semantic precision ceiling; unfiltered
/// reachability is reserved for explicit diagnostic callers.
#[test]
fn public_idg_query_defaults_are_semantic_by_default() {
    let root = repo_root();
    let idg_service = read(&root.join("crates/idg/src/service.rs"));
    for function in [
        "forward_closure",
        "tainted_call_args_in_closure",
        "cross_call_edges_in_closure",
        "cross_call_edges_in_reachable_nodes",
    ] {
        let body = function_body(&idg_service, function);
        assert!(
            body.contains("Some(SEMANTIC_MAX_PRECISION)"),
            "{function} must cap default IDG reachability at the semantic precision ceiling"
        );
        assert!(
            !body.contains(", None)") && !body.contains("(closure, None"),
            "{function} must not delegate to unscoped diagnostic reachability by default"
        );
    }
}

/// Source-analysis and dump-taint are user-visible evidence surfaces.
/// They may expose unresolved/capped conditions as incomplete
/// metadata, but the flows they do emit must stay inside the semantic
/// exact/narrowed precision scope.
#[test]
fn source_and_debug_flow_surfaces_are_semantic_only() {
    let root = repo_root();

    let security_analysis = security_analysis_source(&root);
    let browse_taint = read(&root.join("crates/browse/src/taint.rs"));
    let taint_idg_api = read(&root.join("crates/taint/src/idg_api.rs"));
    let taint_value_flow = read(&root.join("crates/taint/src/value_flow.rs"));
    let workspace_trace = read(&root.join("crates/workspace/src/cross_module.rs"));
    let trace_schema = read(&root.join("crates/trace/src/lib.rs"));
    let cli_args = read(&root.join("crates/cli/src/args.rs"));
    let cli_inspect = read(&root.join("crates/cli/src/commands/inspect.rs"));
    let cli_dump = read(&root.join("crates/cli/src/commands/dump.rs"));
    let cli_security = read(&root.join("crates/cli/src/commands/security.rs"));
    let inspect_call_edges = read(&root.join("crates/inspect/src/call_edges.rs"));
    let native_export = read(&root.join("crates/browse/src/native_export.rs"));

    assert!(
        taint_idg_api.contains("max_edge_precision: Some(Precision::Narrowed)"),
        "InterTaintConfig::default must cap flow evidence at the semantic precision ceiling"
    );

    let value_forward_body = function_body(&taint_value_flow, "forward_closure");
    assert!(
        value_forward_body.contains("SEMANTIC_FLOW_MAX_PRECISION"),
        "ValueFlowGraph::forward_closure must use the semantic precision ceiling by default"
    );
    let value_backward_body = function_body(&taint_value_flow, "backward_closure");
    assert!(
        value_backward_body.contains("SEMANTIC_FLOW_MAX_PRECISION"),
        "ValueFlowGraph::backward_closure must use the semantic precision ceiling by default"
    );
    let value_intra_body = function_body(&taint_value_flow, "build_intra_entry_graph");
    assert!(
        value_intra_body.contains("type FlowEnv")
            && value_intra_body.contains("fn merge_env")
            && value_intra_body.contains("FlowEvent::Branch")
            && value_intra_body.contains("FlowEvent::Call")
            && value_intra_body.contains("ValueFlowNodeKind::CallArg")
            && value_intra_body.contains("ValueFlowNodeKind::Return"),
        "value-flow graph construction must track definition environments, merge branch definitions, and emit call-site/return nodes"
    );
    assert!(
        !value_intra_body.contains(".take(1)"),
        "value-flow return/call lineage must not pick one arbitrary same-name definition"
    );
    let value_entry_body = function_body(&taint_value_flow, "value_flow_for_function_with_caches");
    let value_result_body = function_body(&taint_value_flow, "build_graph_from_result");
    assert!(
        value_entry_body.contains("interprocedural_taint_with_caches")
            && value_entry_body.contains("build_graph_from_result")
            && value_result_body.contains("find_call_arg_node"),
        "the single IDG-backed value-flow path must lift concrete call-site argument nodes from its canonical engine result"
    );

    let source_body = function_body(&security_analysis, "run_source_analysis_with_phase_progress");
    let source_scope_compilation_body = function_body(&security_analysis, "compile_source_lineage_scope");
    let source_group_body = function_body(&security_analysis, "build_source_group_candidates");
    assert!(
        source_body.contains("max_edge_precision: Some(Precision::Narrowed)"),
        "security source-analysis must build source-seeded graphs with a semantic precision ceiling"
    );
    assert!(
        source_body.contains("compile_source_lineage_scope")
            && source_body.contains("enumerate_source_candidates")
            && source_scope_compilation_body.contains("source_analysis_lineage_func_scope")
            && source_scope_compilation_body.contains("building source lineage scope")
            && source_scope_compilation_body.contains("append_taint_target_key(")
            && source_scope_compilation_body.contains("\"source_lineage\"")
            && source_scope_compilation_body.contains("group.lineage_funcs = Some")
            && source_group_body.contains("group.lineage_funcs.as_ref()"),
        "security source-analysis must scope default source path graphs through a semantic source-lineage corridor, not an unbounded source-only closure"
    );
    assert!(
        source_group_body.contains("if !precision.is_semantic()"),
        "security source-analysis must drop diagnostic precision classes before emitting candidates"
    );
    assert!(
        source_group_body.contains("entry_taint_call_records_from_idg_query")
            && source_group_body.contains("call_result_passthroughs")
            && source_group_body.contains("IdgTaintTargets")
            && source_group_body.contains("lineage_funcs")
            && source_group_body.contains("with_caches"),
        "security source-analysis must use the cached typed IDG call-record query; configured transfers are materialized into the shared IDG before attribution"
    );
    let source_lineage_scope_body = function_body(&security_analysis, "source_analysis_lineage_func_scope");
    assert!(
        source_lineage_scope_body.contains(".callees_of(func)")
            && source_lineage_scope_body.contains(".callers_of(func)")
            && source_lineage_scope_body.contains("summary_dependency_provider")
            && source_lineage_scope_body.contains("let mut stack")
            && source_lineage_scope_body.contains("while let Some(func) = stack.pop()")
            && !source_lineage_scope_body.contains("max_hops")
            && !source_lineage_scope_body.contains(".all_files()"),
        "source-analysis lineage scope must reach a cap-free semantic callgraph fixed point with source-origin summary-output support, not use a workspace file walk"
    );

    let taint_reachable = read(&root.join("crates/taint/src/reachable.rs"));
    let call_records_body = function_body(&taint_reachable, "entry_taint_call_records_from_idg_query");
    let closure_compiler_body = function_body(&taint_reachable, "compile_idg_taint_closure");
    let cross_call_compiler_body = function_body(&taint_reachable, "renderable_cross_calls_from_closure");
    assert!(
        call_records_body.contains("compile_idg_taint_closure")
            && call_records_body.contains("renderable_cross_calls_from_closure")
            && closure_compiler_body.contains("apply_configured_transfer_fixpoint")
            && closure_compiler_body.contains("closure_evidence_with_targets")
            && closure_compiler_body.contains("cross_calls: evidence.cross_calls")
            && cross_call_compiler_body.contains("let mut edges = cross_calls")
            && !cross_call_compiler_body.contains("cross_call_edges_in_reachable_nodes")
            && cross_call_compiler_body.contains("is_renderable_call")
            && cross_call_compiler_body.contains("lineage_funcs"),
        "IDG call-record export used by source-analysis must retain traversed scalar and symbolic provenance without a second workspace scan, support target/lineage cuts and configured transfers, and never render projected heap state as a call"
    );

    let trace_call_body = function_body(&workspace_trace, "emit_call");
    assert!(
        trace_call_body.contains("StepKind::Diagnostic")
            && trace_call_body.contains("unresolved-call:")
            && trace_call_body.contains("StepKind::BranchSplit")
            && trace_call_body.contains("Call target split")
            && trace_call_body.contains("max-branch-fanout"),
        "trace must mark unresolved calls incomplete, expand every semantic alternative by default, and expose explicit fanout truncation"
    );
    assert!(
        !trace_call_body.contains("Precision::Unknown"),
        "trace must not emit unresolved calls as unknown-precision call evidence"
    );
    let trace_finalize_body = function_body(&trace_schema, "finalize");
    assert!(
        trace_finalize_body.contains("public_semantic_step"),
        "trace finalization must normalize raw steps through the semantic public boundary"
    );
    let trace_public_step_body = function_body(&trace_schema, "public_semantic_step");
    assert!(
        trace_public_step_body.contains("!raw_step.precision.is_semantic()")
            && trace_public_step_body.contains("TraceStepKind::Diagnostic")
            && trace_public_step_body.contains("diagnostic-precision-step:")
            && trace_public_step_body.contains("precision: Precision::Exact"),
        "trace must suppress diagnostic precision as incomplete metadata, not public flow evidence"
    );

    let inspect_render_body = function_body(&cli_inspect, "render_flow_with_cached_call_spans");
    assert!(
        inspect_render_body.contains("if !precision.is_semantic()")
            && inspect_render_body.contains("return None;"),
        "inspect must drop diagnostic-precision chains before rendering public flow evidence"
    );
    assert!(
        cli_inspect.contains("analysis_complete: bool")
            && cli_inspect.contains("analysis_incomplete_reasons: Vec<String>")
            && cli_inspect.contains("refresh_inspect_completeness")
            && !cli_inspect.contains("inspect occurrence flow evidence capped by")
            && !cli_inspect.contains("inspect decl flow evidence capped by")
            && !cli_inspect.contains("inspect hit list capped by"),
        "inspect must expose top-level completeness metadata without semantic hit/flow caps"
    );
    let inspect_call_span_body = function_body(&inspect_call_edges, "find_call_span_to_func");
    assert!(
        inspect_call_span_body.contains("edge.to == target_func && edge.precision.is_semantic()"),
        "inspect call-site rendering must use semantic callgraph edge spans only"
    );
    assert!(
        !inspect_call_span_body.contains("find_call_span_resolved")
            && !inspect_call_span_body.contains("collect_local_callable_bindings"),
        "inspect call-site rendering must not fallback to re-resolving call names"
    );
    let inspect_uncached_call_span_body =
        function_body(&inspect_call_edges, "find_call_span_to_func_uncached");
    assert!(
        inspect_uncached_call_span_body.contains("edge.to == target_func && edge.precision.is_semantic()")
            && !inspect_uncached_call_span_body.contains("find_call_span_resolved")
            && !inspect_uncached_call_span_body.contains("collect_local_callable_bindings"),
        "uncached inspect call-site rendering must use semantic callgraph edge spans only"
    );
    let dump_edges_body = function_body(&cli_dump, "cmd_dump_edges");
    let precision_filter_start = cli_args
        .find("pub(crate) enum PrecisionFilter")
        .expect("missing CLI PrecisionFilter");
    let precision_filter_tail = &cli_args[precision_filter_start..];
    let precision_filter_end = precision_filter_tail
        .find("\n}")
        .map(|offset| offset + 2)
        .expect("unterminated CLI PrecisionFilter");
    let precision_filter_body = &precision_filter_tail[..precision_filter_end];
    assert!(
        precision_filter_body.contains("Exact")
            && precision_filter_body.contains("Narrowed")
            && !precision_filter_body.contains("OverApproximate")
            && !precision_filter_body.contains("Unknown")
            && !dump_edges_body.contains("OverApproximate")
            && !dump_edges_body.contains("Unknown"),
        "dump-edges must make diagnostic precision filters unrepresentable so clap rejects them before command dispatch"
    );
    let security_taint_body = function_body(&cli_security, "cmd_flows");
    assert!(
        security_taint_body.contains("max_precision = Some(Precision::Narrowed)")
            && !security_taint_body.contains("SemanticPrecisionFilter")
            && !security_taint_body.contains("OverApproximate")
            && !security_taint_body.contains("Unknown"),
        "security taint-analysis must run one semantic taint precision mode without exposing diagnostic precision filters"
    );
    let export_callgraph_body = function_body(&native_export, "export_structural_callgraph_count");
    assert!(
        export_callgraph_body.contains("edge.precision.is_semantic()"),
        "native export structural callgraph must emit semantic call edges only"
    );
    assert!(
        native_export.contains("struct ExportTaintCallEdgesStreaming")
            && native_export
                .matches("filter(|edge| edge.precision.is_semantic())")
                .count()
                >= 4,
        "native export taint call_edges must emit semantic call edges only"
    );

    let dump_taint_context_body = function_body(&browse_taint, "workspace_has_callable_named_in_context");
    assert!(
        dump_taint_context_body.contains("resolve_callable_with_context")
            && dump_taint_context_body.contains("ResolveContext::new"),
        "dump-taint unresolved-call completeness checks must use caller-context resolution"
    );
    assert!(
        !dump_taint_context_body.contains("resolve_callable(global"),
        "dump-taint completeness checks must not use contextless workspace-wide callable lookup"
    );

    let dump_taint_body = function_body(&browse_taint, "dump_taint");
    assert!(
        dump_taint_body.contains("ws.exact_decl(source_symbol)")
            && dump_taint_body.contains("default_entry_taint_seed(source_decl.as_ref())")
            && dump_taint_body.contains("compose_idg_seed_nodes_with_decl")
            && dump_taint_body.contains("source_decl.as_ref(),"),
        "dump-taint must stream the selected Tree-sitter body into default-seed derivation and canonical IDG seed composition"
    );
    assert!(
        dump_taint_body.contains("forward_closure_evidence_with_max_precision")
            && dump_taint_body.contains("closure_evidence.cross_calls")
            && dump_taint_body.contains("Some(SEMANTIC_FLOW_MAX_PRECISION)"),
        "dump-taint must compute its seed closure and traversed call provenance inside the semantic precision scope"
    );
    assert!(
        !dump_taint_body.contains("cross_call_edges_in_reachable_nodes_with_max_precision"),
        "dump-taint must consume provenance captured by the closure instead of rescanning the workspace IDG"
    );
    assert!(
        !dump_taint_body.contains("with_max_precision(&seed_nodes, None")
            && !dump_taint_body.contains("with_max_precision(\n            &seed_nodes,\n            None"),
        "dump-taint must not request unscoped diagnostic reachability"
    );
    let dump_taint_record_body = function_body(&browse_taint, "build_taint_record_from_cross_call");
    assert!(
        dump_taint_record_body.contains("ws.exact_decl")
            && dump_taint_record_body.contains("caller_flow_decl")
            && dump_taint_record_body.contains("if tainted_args.is_empty()")
            && dump_taint_record_body.contains("return None;"),
        "dump-taint records must hydrate exact AST argument/receiver facts and suppress relations with no renderable tainted value"
    );
    let dump_taint_call_name_body = function_body(&browse_taint, "caller_call_name");
    assert!(
        dump_taint_call_name_body.contains("ws.exact_decl(symbol)"),
        "dump-taint completeness checks must read call names from the streamed exact caller body"
    );

    let findings_build = read(&root.join("crates/security/src/analysis/findings_build.rs"));
    let chain_executor = read(&root.join("crates/security/src/analysis/chain_executor.rs"));
    let make_finding_body = function_body(&findings_build, "make_finding");
    assert!(
        make_finding_body.contains("analysis_complete: context.analysis_incomplete_reasons.is_empty()"),
        "security findings must not hard-code analysis_complete=true"
    );
    assert!(
        make_finding_body.contains("analysis_incomplete_reasons: context.analysis_incomplete_reasons"),
        "security findings must carry scoped incomplete reasons into the report"
    );
    assert!(
        chain_executor.contains("GraphUnresolvedCallIndex")
            && chain_executor.contains("reasons_for_terminal_call(call)")
            && !chain_executor.contains("graph_incomplete_reasons")
            && !security_analysis.contains("graph_incomplete_reasons"),
        "security findings must scope unresolved-call completeness to the terminal evidence path, not the whole source graph"
    );
    let merge_finding_body = function_body(&security_analysis, "merge_finding_into_group");
    assert!(
        merge_finding_body.contains("merge_analysis_completeness"),
        "combined security findings must preserve incomplete member-finding metadata"
    );

    let export_body = read(&root.join("crates/browse/src/native_export.rs"));
    let export_args = read(&root.join("crates/cli/src/args.rs"));
    let sdk = read(&root.join("crates/sdk/src/lib.rs"));
    let flow_sections = function_body(&export_body, "build_export_flow_sections");
    let taint_chain_rows = function_body(&export_body, "export_taint_chains_and_flow_labels");
    assert!(
        !export_body.contains("EXPORT_FLOW_CHAIN_MAX_CHAINS_PER_TARGET")
            && !export_body.contains("EXPORT_FLOW_CHAIN_MAX_ENTRY_PROBES")
            && !export_body.contains("pub complete_chains: bool")
            && !flow_sections.contains("chains_resolved")
            && !taint_chain_rows.contains("chains_resolved")
            && !taint_chain_rows.contains("labels_for_chain_sets")
            && flow_sections.contains("compressed_callgraph")
            && taint_chain_rows.contains("compressed_callgraph"),
        "native export must expose only the exact compressed call relation; capped/BFS path-prefix compatibility modes are forbidden"
    );
    let main_body = read(&root.join("crates/cli/src/main.rs"));
    assert!(
        !export_args.contains("max_flows:")
            && !export_args.contains("max_entry_probes:")
            && !export_args.contains("max_hits:")
            && !main_body.contains("usize::MAX / 16"),
        "inspect must not expose semantic max-flow, probe, or hit caps"
    );
    assert!(
        !export_args.contains("complete_chains: bool")
            && sdk.contains("impl Default for NativeExportOptions")
            && !sdk.contains("pub complete_chains: bool")
            && main_body.contains("cmd_export(&workspace, full_propagations, format)"),
        "CLI and default SDK export must always use the exact compressed chain relation without a cap-oriented mode switch"
    );
    let chain_enumerator_body = read(&root.join("crates/callgraph/src/chains.rs"));
    assert!(
        chain_enumerator_body.contains("visited_budget = visited_budget.saturating_add(1)")
            && chain_enumerator_body.contains("max_probes.saturating_mul(16)"),
        "chain enumeration must safely support usize::MAX as the uncapped probe budget"
    );
    assert!(
        export_body.contains("compressed_callgraph")
            && export_body.contains("flow_chains_mode")
            && export_body.contains("chains_mode")
            && export_body.contains("flow_id_labels_mode")
            && flow_sections.contains("flow_chains_truncated_targets: 0")
            && taint_chain_rows.contains("chains_truncated_targets: 0")
            && taint_chain_rows.contains("flow_id_labels_truncated_functions: 0"),
        "native export compressed mode must preserve exact semantic graph evidence and must not label omitted concrete rows complete"
    );
}

#[test]
fn public_security_and_dump_taint_renderers_preserve_completeness_metadata() {
    let root = repo_root();
    let security_report = read(&root.join("crates/security/src/report.rs"));
    let cli_dump = read(&root.join("crates/cli/src/commands/dump.rs"));
    let graph_export = read(&root.join("crates/browse/src/graph_export.rs"));
    let sdk = read(&root.join("crates/sdk/src/lib.rs"));

    let train_body = function_body(&security_report, "render_train_json");
    assert!(
        train_body.contains("analysis_complete: report.analysis_complete")
            && train_body.contains("analysis_incomplete_reasons: report.analysis_incomplete_reasons.clone()")
            && train_body.contains("runtime_disabled_rules: report.runtime_disabled_rules.clone()"),
        "training JSON must preserve scan completeness and runtime-disabled rule metadata even when examples is empty"
    );

    let grouped_body = function_body(&security_report, "render_grouped_text");
    assert!(
        grouped_body.contains("analysis: complete")
            && grouped_body.contains("analysis: incomplete")
            && grouped_body.contains("runtime-disabled rule:"),
        "grouped security text must distinguish complete empty reports from incomplete scans"
    );

    let dump_json_body = function_body(&cli_dump, "render_taint_report_json_paged");
    assert!(
        dump_json_body.contains("\"records\": records")
            && dump_json_body.contains("semantic_analysis_complete")
            && dump_json_body.contains("semantic_analysis_incomplete_reasons")
            && dump_json_body.contains("presentation_complete")
            && dump_json_body.contains("presentation_incomplete_reasons")
            && dump_json_body.contains("paged_json_incomplete_reasons(\"dump-taint\"")
            && !dump_json_body.contains("json_lines"),
        "paged dump-taint JSON must retain structured records and separate semantic coverage from presentation truncation"
    );

    assert!(
        graph_export.contains("analysis_complete")
            && graph_export.contains("analysis_incomplete_reasons")
            && graph_export.contains("GRAPH_EXPORT_INCOMPLETE_REASON"),
        "graph exports must explain that propagation evidence is unavailable instead of presenting an empty graph as complete"
    );

    let cache_sidecar_body = function_body(&sdk, "cache_manifest_sidecar");
    let cache_coverage_body = function_body(&sdk, "cache_manifest_coverage");
    assert!(
        cache_sidecar_body.contains("missing_reason")
            && cache_coverage_body.contains("missing_reasons")
            && cache_coverage_body.contains("sidecar has not been produced"),
        "SDK cache manifests must attach reasons to unavailable sidecars and incomplete semantic coverage"
    );
}

#[test]
fn production_taint_command_paths_use_filtered_semantic_idg_apis() {
    let root = repo_root();
    let checked_files = [
        "crates/security/src/analysis/mod.rs",
        "crates/security/src/analysis/execution.rs",
        "crates/cli/src/commands/security.rs",
        "crates/cli/src/commands/inspect.rs",
        "crates/cli/src/commands/export.rs",
        "crates/browse/src/native_export.rs",
    ];
    let forbidden_calls = [
        "entry_taint_call_records_from_idg(",
        "entry_taint_call_records_from_idg_with_max_precision(",
        "entry_taint_graph_from_idg(",
        "entry_taint_graph_from_idg_with_max_precision(",
        "forward_closure_with_max_precision(&seed_nodes, None",
        "forward_closure_with_max_precision(\n        &seed_nodes,\n        None",
    ];
    let allowlist = [
        "crates/security/src/analysis/mod.rs: exact_source_seed_graph",
        "crates/security/src/analysis/mod.rs: exact_source_path_graph",
    ];

    let mut violations = Vec::new();
    for rel in checked_files {
        let text = read(&root.join(rel));
        for forbidden in forbidden_calls {
            if text.contains(forbidden) {
                let allowed = allowlist.iter().any(|entry| {
                    rel == entry.split(':').next().unwrap_or("")
                        && entry
                            .split(": ")
                            .nth(1)
                            .is_some_and(|func| function_body(&text, func).contains(forbidden))
                });
                if !allowed {
                    violations.push(format!("{rel}: production command path references `{forbidden}`"));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "taint-related production commands must use filtered semantic IDG/corridor APIs; diagnostic wrappers are not allowed here:\n{}",
        violations.join("\n")
    );
}

#[test]
fn inspect_taint_flow_uses_workspace_syntax_flow_query_facade() {
    let root = repo_root();
    let inspect = read(&root.join("crates/cli/src/commands/inspect.rs"));
    let inspect_engine = read(&root.join("crates/inspect/src/lib.rs"));
    let workspace = read(&root.join("crates/workspace/src/lib.rs"));
    let body = function_body(&inspect, "inspect_taint_flows");
    assert!(
        body.contains("SyntaxFlowQuery::new")
            && body.contains("ws.syntax_flow_session")
            && body.contains("ws.syntax_flow_graph")
            && body.contains("semantic_flow_stats.record_plan(&plan)"),
        "inspect_taint_flows must ask the workspace syntax-flow facade for short-lived exact semantic sessions and retain planner metadata"
    );
    assert!(
        inspect.contains("SyntaxFlowPlan")
            && inspect.contains("semantic_flow_backend_counts")
            && inspect.contains("semantic_flow_cache_hits")
            && inspect.contains("semantic_flow_fallback_reasons"),
        "inspect must surface syntax-flow planner backend/cache/fallback metadata"
    );
    let command = function_body(&inspect, "cmd_inspect");
    let occurrence_scan = function_body(&inspect, "scan_occurrence_facts");
    let occurrence_file_scan = function_body(&inspect, "scan_occurrence_file");
    let decl_scan = function_body(&inspect, "collect_decl_hits");
    let render_flow = function_body(&inspect, "render_flow_with_cached_call_spans");
    let render_function = function_body(&inspect, "render_function_source");
    let render_report = function_body(&inspect, "render_inspect_report_text");
    assert!(
        command.contains("drop(edge_resolver)")
            && command.contains("drop(chain_cache)")
            && command.contains("ws.db().release_global_index()")
            && command.contains("ws.release_resolved_call_graph_cache()")
            && command.contains("ws.release_compiler_linkage_cache()")
            && command.contains("ws.release_exact_body_cache()")
            && command.contains("ws.release_decl_name_index_cache()")
            && function_body(&inspect_engine, "func_display_name")
                .contains("compiler_header_index()"),
        "inspect must end its whole-body navigation phase before opening a scoped IDG and render semantic names from shared compiler headers"
    );
    assert!(
        command.contains("let global = ws.compiler_header_index()")
            && decl_scan.contains("ws.compiler_header_index()")
            && !decl_scan.contains("global_index()")
            && occurrence_scan.contains("let _ = ws.compiler_header_index()")
            && occurrence_scan.contains("syntax_weighted_batches")
            && occurrence_scan.contains(".par_iter()")
            && occurrence_scan.contains("scan_occurrence_file(file, &file_scan)")
            && occurrence_file_scan.contains("ws.exact_decl_index_shared(file)")
            && !occurrence_scan.contains("resident_global")
            && !occurrence_scan.contains("global_index()")
            && !occurrence_file_scan.contains("resident_global")
            && !occurrence_file_scan.contains("global_index()")
            && render_flow.contains("ws.exact_decl(symbol)")
            && !render_flow.contains("global_index()")
            && render_function.contains("ws.exact_decl_index_shared(file)")
            && !render_function.contains("global_index()")
            && function_body(&workspace, "exact_decl_index_shared")
                .contains("compiler_index_for_exact_bodies()")
            && !function_body(&workspace, "exact_decl_index_shared")
                .contains("global_index()")
            && function_body(&workspace, "exact_decl").contains("compiler_index_for_exact_bodies()")
            && !function_body(&workspace, "exact_decl").contains("compiler_linkage_index()"),
        "inspect must use compact compiler headers for matching and hydrate selected exact file bodies through the active header/linkage generation"
    );
    assert!(
        render_report.contains("inspect_taint_flow_json_upper_bound")
            && render_report.contains("let taint_unit_costs")
            && inspect.contains("json_size_upper_bound")
            && inspect.contains("calculate_inspect_taint_flow_json_upper_bound")
            && !render_report.contains("serde_json::to_string(&report.taint_flows"),
        "inspect pagination must reuse worker-precomputed raw-flow costs without serializing or rescanning every exact result during rendering"
    );
    assert!(
        body.contains(".par_iter()")
            && body.contains("rooted_semantic_query_worker_count")
            && !body.contains("split_first()"),
        "memory-bounded inspect closures must schedule every independent entry together instead of leaving one arbitrary entry on the serial critical path"
    );
    assert!(
        inspect.contains("inspect_eager_window")
            && inspect.contains("!report.taint_flows.is_empty()")
            && function_body(&inspect, "inspect_eager_window").contains("if has_raw_taint"),
        "raw-taint inspect must render only the requested page instead of eagerly formatting unrelated future pages"
    );
    for forbidden in [
        "dataflow().graph_for",
        "idg_service().is_some",
        "inspect_entry_taint_graph_from_idg",
        "entry_taint_graph_from_idg",
        "build_and_seed_idg_service",
    ] {
        assert!(
            !body.contains(forbidden),
        "inspect_taint_flows must not bypass the syntax-flow facade or pre-check planner internals with `{forbidden}`"
    );
    }

    let flow_query = read(&root.join("crates/workspace/src/flow_query.rs"));
    let inspect_query = read(&root.join("crates/inspect/src/query.rs"));
    let session = function_body(&flow_query, "syntax_flow_session");
    let compile_session = function_body(&flow_query, "compile_syntax_flow_session");
    assert!(
        session.contains("target_emission_resolved_call_graph")
            && session.contains("source_reachable_resolved_call_graph")
            && session.contains("source_funcs.iter().all(|func| target_funcs.contains(func))")
            && session.contains("compile_syntax_flow_session(corridor)")
            && compile_session.contains("corridor.linkage_index.clone()")
            && compile_session.contains(
                "build_for_persistence_streaming_with_file_semantics_and_options_for_files_and_funcs",
            )
            && compile_session.contains("tempfile::Builder::new()")
            && compile_session.contains("IdgQueryService::load_from_disk")
            && !session.contains(".take(")
            && !session.contains(".truncate(")
            && !compile_session.contains(".take(")
            && !compile_session.contains(".truncate("),
        "cold targeted inspect must stream one exact source-to-target IDG corridor through an unpublished paged session without semantic work caps"
    );
    assert!(
        function_body(&inspect_query, "matching_decls").contains("compiler_header_index()")
            && !function_body(&inspect_query, "matching_decls").contains("compiler_linkage_index()"),
        "syntax-only inspect candidate lookup must retain declaration/type headers, not workspace-wide call linkage"
    );
    let target_emissions = function_body(&workspace, "target_emission_resolved_call_graph");
    let scoped_reach = function_body(&workspace, "source_reachable_resolved_call_graph_with_scope");
    assert!(
        target_emissions.contains("source_reachable_resolved_call_graph_with_scope")
            && scoped_reach.contains("target_set.contains(&edge.to)")
            && scoped_reach
                .contains("target_emission_requires_callee(global.as_ref(), &scoped_linkage, edge)")
            && function_body(&workspace, "target_emission_requires_callee")
                .contains("consumed_call_results")
            && function_body(&workspace, "target_emission_requires_callee")
                .contains("has_writeback_arg")
            && function_body(&workspace, "target_emission_requires_callee")
                .contains("receiver_field_writes")
            && !scoped_reach.contains("contains(\"")
            && !scoped_reach.contains("ends_with("),
        "inspect target slicing must be driven by compiler symbols and adapter-emitted output capability, never API names or source spelling"
    );
    assert!(
        body.contains("ws.syntax_flow_session")
            && body.contains("syntax_flow_target_nodes_by_source_with_session")
            && body.contains("syntax_flow_target_relevance_with_session")
            && body.contains("syntax_flow_relevant_sources_with_session")
            && body
                .find("let session")
                .zip(body.find("syntax_flow_target_nodes_by_source_with_session"))
                .zip(body.find("let analyze_entry"))
                .is_some_and(|((session, targets), analyze)| session < targets && targets < analyze),
        "inspect must share one paged exact corridor, resolve exact target nodes, and reject compiler-proven irrelevant sources before per-entry closure"
    );
}

#[test]
fn entrypoints_command_uses_canonical_semantic_callgraph_path() {
    let root = repo_root();
    let browse = read(&root.join("crates/cli/src/commands/browse.rs"));
    let body = function_body(&browse, "cmd_entrypoints");
    assert!(
        body.contains("open_project(root)")
            && body.contains("project")
            && body.contains(".browse()")
            && body.contains(".entrypoints(f)"),
        "entrypoints must use the canonical browse entrypoint API backed by the resolved semantic callgraph"
    );
    for forbidden in [
        "open_project_parse_only",
        "decl_index_uncached",
        "semantic_callers_not_loaded",
        "semantic caller exclusion omitted",
    ] {
        assert!(
            !body.contains(forbidden),
            "entrypoints must not render approximate syntax-only roots via `{forbidden}`"
        );
    }
    assert!(
        !browse.contains("render_entrypoints_streaming_first_page"),
        "entrypoints must not keep an approximate large-workspace first-page renderer"
    );
}

#[test]
fn production_callgraph_consumers_share_the_workspace_graph() {
    let root = repo_root();
    let mut files = Vec::new();
    collect_rs_files(&root.join("crates"), &mut files);
    let mut clone_sites = Vec::new();
    for file in files {
        let relative = file.strip_prefix(&root).unwrap_or(&file);
        let file_name = file.file_name().and_then(|name| name.to_str()).unwrap_or("");
        if file.components().any(|part| part.as_os_str() == "tests")
            || file_name == "tests.rs"
            || file_name.ends_with("_tests.rs")
        {
            continue;
        }
        for (line_index, line) in read(&file).lines().enumerate() {
            if line.contains(".resolved_call_graph()") {
                clone_sites.push(format!(
                    "{}:{}:{}",
                    relative.display(),
                    line_index + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        clone_sites.is_empty(),
        "read-only production consumers must use `cached_resolved_call_graph()`; cloning the full graph is prohibitive on large workspaces:\n  {}",
        clone_sites.join("\n  ")
    );
}

#[test]
fn retrieval_streams_callgraph_candidates_by_compiler_unit() {
    let root = repo_root();
    let retrieval = read(&root.join("crates/retrieval/src/lib.rs"));
    let index = function_body(&retrieval, "index_semantic_edges_by_file");
    let collect = function_body(&retrieval, "collect_edge_candidate_terms");
    let build = function_body(&retrieval, "build_persisted_candidate_snapshot");
    let batch_width = function_body(&retrieval, "retrieval_file_batch_width");

    assert!(
        retrieval.contains(") -> AHashMap<FileId, Vec<usize>> {")
            && index.contains("edges.iter().enumerate()")
            && index.contains(".push(index)")
            && !index.contains("FileCandidateTerms"),
        "retrieval may index the shared callgraph by compact ordinals, but must not materialize whole-workspace candidate strings"
    );
    assert!(
        retrieval.contains("edge_indices: &[usize]")
            && collect.contains("candidate_terms(groups, \"edge\")")
            && retrieval.contains("span_map: Option<&bonsai_common::SpanMap>")
            && !collect.contains("span_doc_fields")
            && !collect.contains("vfs()"),
        "retrieval must derive semantic edge terms from one file-local span map without repeating source hashing or VFS lookup per edge"
    );
    assert!(
        build.contains("edge_indices.remove(file)")
            && build.contains("compiler_browse_header_uncached(file)")
            && build.contains("release_global_index()")
            && build.contains("builder.push(doc)")
            && !build.contains("build_edge_candidate_groups")
            && !build.contains("syntax_indexes_uncached")
            && !build.contains("db().global_index()"),
        "retrieval must consume each independently decodable exact browse projection instead of retaining a global declaration body or second callgraph projection"
    );
    assert!(
        batch_width.contains("candidate_index_worker_count"),
        "retrieval candidate concurrency must honor its measured process memory profile without limiting semantic facts"
    );
}

#[test]
fn compiler_objects_are_exact_single_frontend_inputs() {
    let root = repo_root();
    let db = read(&root.join("crates/db/src/lib.rs"));
    let compiler_object = read(&root.join("crates/db/src/compiler_object.rs"));
    let sdk = read(&root.join("crates/sdk/src/lib.rs"));
    let service = read(&root.join("crates/idg/src/service.rs"));
    let csr = read(&root.join("crates/idg/src/csr.rs"));

    let load = function_body(&compiler_object, "compressed_payload");
    let load_object_payload = function_body(&compiler_object, "compressed_object_payload");
    let load_browse = function_body(&compiler_object, "load_browse");
    let metadata_for = function_body(&compiler_object, "metadata_for");
    let prepare = function_body(&compiler_object, "prepare_compiler_object");
    let save = function_body(&compiler_object, "save_compiler_object_sidecar");
    let write_generation = function_body(&compiler_object, "write_compiler_object_generation");
    let parallel_compiler_work = function_body(&compiler_object, "try_visit_parallel");
    let append_compiler_object = function_body(&compiler_object, "append_prepared_compiler_object");
    assert!(
        compiler_object.contains("pub struct CompiledFileObject")
            && compiler_object.contains("Sha256")
            && function_body(&compiler_object, "source_descriptor").contains("strip_prefix")
            && load.contains("self.metadata_for(descriptor)")
            && metadata_for.contains("metadata.path == descriptor.path")
            && metadata_for.contains("metadata.language == descriptor.language")
            && metadata_for.contains("metadata.source_digest == descriptor.source_digest")
            && load.contains("self.compressed_object_payload(descriptor, metadata)")
            && load_object_payload.contains("digest_bytes(&hit.payload)")
            && load_browse.contains("self.compressed_browse_payload(metadata)")
            && load_browse.contains("wire::decode")
            && prepare.contains("CompilerBrowseHeader::from_indexes")
            && prepare.contains("browse_payload_digest")
            && append_compiler_object.contains("browse_key(descriptor.file)")
            && prepare.matches("ensure_source_version").count() == 3
            && prepare.contains("Ok(Some(prepared)) => {")
            && save.contains("write_compiler_object_generation")
            && write_generation.contains("PreparedFactStorePayload")
            && write_generation.contains("syntax_worker_count_for_sources")
            && write_generation.contains("SyntaxMemoryPermitPool")
            && write_generation.contains("try_visit_parallel")
            && write_generation.contains("append_prepared_compiler_object")
            && write_generation.contains("collect::<Option<Vec<_>>>()")
            && parallel_compiler_work.contains("sync_channel")
            && parallel_compiler_work.contains("completed_count")
            && parallel_compiler_work.contains("visit(index, result?)")
            && parallel_compiler_work.contains("max_in_flight")
            && !parallel_compiler_work.contains("BTreeMap")
            && !parallel_compiler_work.contains("compiler_weighted_batches")
            && !write_generation.contains(".take(")
            && !write_generation.contains(".truncate("),
        "compiler objects must be atomic, strongly content-identified, continuously scheduled without physical head-of-line blocking, canonically indexed, relocatable by relative path, and complete"
    );
    assert!(
        function_body(&db, "decl_index_uncached").contains("compiler_file_object_uncached")
            && function_body(&db, "syntax_indexes_uncached").contains("compiler_file_object_uncached")
            && sdk.contains("\"compiler_objects\"")
            && function_body(&sdk, "cache_manifest_coverage")
                .contains("stats.compiler_object_sidecar_exists"),
        "broad syntax consumers and semantic readiness must share the canonical compiler-object generation"
    );
    let bulk_objects = function_body(&compiler_object, "visit_compiler_file_objects_uncached");
    assert!(
        bulk_objects.contains("compiler_weighted_batches")
            && bulk_objects.contains("compiler_file_object_uncached")
            && bulk_objects.contains("visit(file, object)")
            && !bulk_objects.contains("ThreadPoolBuilder")
            && !bulk_objects.contains(".take(")
            && !bulk_objects.contains(".truncate("),
        "bulk compiler-object visits must cover every requested file in order, release each batch, and reuse shared scheduling while memory changes only parallel width"
    );

    let build_reach = function_body(&service, "build_reach");
    let direct_csr = function_body(&csr, "bidirectional_from_pair_visitor");
    assert!(
        build_reach.contains("ReachabilityIndex::from_pair_visitor")
            && !build_reach.contains("Vec<(u32, u32)>")
            && direct_csr.matches("visit_pairs(").count() == 2
            && direct_csr.contains("forward_offsets")
            && direct_csr.contains("backward_offsets"),
        "query adjacency must be built directly from canonical numeric edges without a workspace-sized staging projection"
    );
}

#[test]
fn memory_budget_changes_compiler_scheduling_not_semantic_scope() {
    let root = repo_root();
    let resources = read(&root.join("crates/common/src/resources.rs"));
    let db = read(&root.join("crates/db/src/lib.rs"));
    let compiler_object = read(&root.join("crates/db/src/compiler_object.rs"));
    let callgraph = read(&root.join("crates/callgraph/src/lib.rs"));
    let idg = read(&root.join("crates/idg/src/workspace_adapter.rs"));
    let idg_builder = read(&root.join("crates/idg/src/builder.rs"));
    let idg_workspace = read(&root.join("crates/idg/src/workspace.rs"));
    let idg_service = read(&root.join("crates/idg/src/service.rs"));
    let factstore_writer = read(&root.join("crates/factstore/src/writer.rs"));
    let symbolic = read(&root.join("crates/idg/src/symbolic.rs"));
    let index = read(&root.join("crates/index/src/lib.rs"));
    let security_matcher = read(&root.join("crates/security/src/matcher/mod.rs"));
    let security_execution = read(&root.join("crates/security/src/analysis/execution.rs"));
    let taint_idg = read(&root.join("crates/taint/src/idg_build.rs"));
    let workspace = read(&root.join("crates/workspace/src/lib.rs"));
    for (phase, body, scheduler) in [
        (
            "syntax frontend",
            function_body(&workspace, "workspace_parse_worker_count"),
            "syntax_worker_count",
        ),
        (
            "global index",
            function_body(&db, "build_streaming_global_index"),
            "compiler_weighted_batches",
        ),
        (
            "compiler objects",
            function_body(&compiler_object, "write_compiler_object_generation"),
            "SyntaxMemoryPermitPool",
        ),
        (
            "callgraph",
            function_body(&callgraph, "callgraph_resolver_worker_count"),
            "callgraph_worker_count",
        ),
        (
            "IDG transfer",
            function_body(&idg, "build_with_file_info_and_options_scoped"),
            "SyntaxMemoryPermitPool",
        ),
        (
            "security matcher",
            function_body(
                &security_matcher,
                "match_rules_against_facts_with_progress_and_mode",
            ),
            "SyntaxMemoryPermitPool",
        ),
    ] {
        assert!(
            body.contains(scheduler),
            "{phase} concurrency must honor the effective process memory budget"
        );
        for forbidden in [".take(", ".truncate(", "max_files", "max_edges", "max_segments"] {
            assert!(
                !body.contains(forbidden),
                "{phase} memory policy must not impose semantic scope through `{forbidden}`"
            );
        }
    }
    let transfer_sizes = function_body(&idg, "idg_transfer_source_bytes");
    let transfer_window = function_body(&idg, "fill_window");
    assert!(
        transfer_sizes.contains("file_to_source_bytes")
            && transfer_window.contains("memory_permits.acquire")
            && transfer_window.contains("memory_permits.try_acquire")
            && transfer_window.contains("source_bytes[self.next_to_schedule]")
            && idg.contains("struct OrderedTransferBatches")
            && idg.contains("BTreeMap<usize, CompletedTransferWork")
            && function_body(&idg, "lower_transfer_segment").contains("body_for_file"),
        "IDG transfer concurrency must use exact compiler-unit size, bounded continuous admission, and canonical ordered publication"
    );
    let reachable_taint_scope = function_body(&security_execution, "compile_reachable_taint_scope");
    assert!(
        reachable_taint_scope.contains("source_reachable_resolved_call_graph")
            && reachable_taint_scope.contains("call_graph.graph.as_ref()")
            && !reachable_taint_scope.contains("cached_resolved_call_graph"),
        "taint scope compilation must derive callback edges from its exact scoped callgraph instead of retaining a duplicate whole-workspace graph"
    );
    assert!(
        function_body(&resources, "syntax_weighted_batches").contains("current_process_resident_bytes")
            && function_body(
                &security_matcher,
                "match_rules_against_facts_with_progress_and_mode"
            )
            .contains("snapshot.text.len()"),
        "broad syntax matching must schedule actual source-unit sizes against the live resident working set"
    );
    assert!(
        function_body(&workspace, "stream_supported_source_files").contains("source_ingestion_batches")
            && function_body(&resources, "source_ingestion_batches")
                .contains("current_process_resident_bytes"),
        "raw compiler input reads must use the live memory budget without changing VFS publication order"
    );
    let package_contexts = function_body(&security_matcher, "build_language_import_package_contexts");
    let package_context_prewarm =
        function_body(&security_matcher, "prewarm_language_import_package_contexts");
    let compiler_session_prewarm =
        function_body(&security_matcher, "prepare_compiler_object_session_for_body_scan");
    let compiler_session = function_body(&compiler_object, "ensure_compiler_object_session");
    let compiler_import_header = function_body(&compiler_object, "compiler_import_index_uncached");
    let compiler_syntax_header = function_body(&compiler_object, "compiler_syntax_header_uncached");
    let broad_matcher = function_body(
        &security_matcher,
        "match_rules_against_facts_with_progress_and_mode",
    );
    let remap_compiler_object = function_body(&db, "remap_decl_index_to_headers");
    assert!(
        package_contexts.contains("import_index_uncached")
            && package_contexts.contains("workspace: Arc::new(workspace)")
            && package_contexts.contains("workspace.packages.insert(spec.module.clone())")
            && !package_contexts.contains("insert_import_target_prefixes")
            && !package_contexts.contains("visit_compiler_file_objects_uncached")
            && package_context_prewarm.contains("language_import_package_contexts")
            && package_context_prewarm.contains("project_language_import_package_contexts")
            && package_context_prewarm.contains("include_workspace_package_context")
            && !package_context_prewarm.contains("has_package_text_anchors")
            && broad_matcher.contains("prewarm_language_import_package_contexts")
            && broad_matcher.contains("prepare_compiler_object_session_for_body_scan")
            && broad_matcher.contains("prewarmed_import_contexts.get(language.as_str())")
            && compiler_session_prewarm.contains("FactRetention::Transient")
            && compiler_session_prewarm.contains("ensure_compiler_object_session")
            && compiler_session.contains("store.covers(&descriptors)")
            && compiler_session.contains("CompilerObjectStore::open_reusable(&root)")
            && compiler_session.contains("workspace_root()")
            && compiler_session.contains("tempfile::Builder::new()")
            && compiler_session.contains("write_compiler_object_generation")
            && compiler_import_header.contains("store.load_imports(&descriptor)")
            && compiler_syntax_header.contains("store.load_syntax(&descriptor)")
            && compiler_object.contains("imports_digest")
            && compiler_object.contains("syntax_digest")
            && !compiler_session.contains("compiler_object_sidecar_path")
            && security_matcher.contains("new_with_oversized_singleton")
            && security_matcher
                .matches("static LANGUAGE_IMPORT_PACKAGE_CONTEXT_CACHE")
                .count()
                == 1
            && !security_matcher.contains("WORKSPACE_IMPORT_PACKAGE_CONTEXT_CACHE")
            && !security_matcher.contains("COMPONENT_IMPORT_PACKAGE_CONTEXT_CACHE"),
        "workspace/component package evidence must use exact import projections, while a scoped compiler-object session is reserved for files that survive header planning"
    );
    assert!(
        broad_matcher
            .matches("compiler_file_object_uncached(file)")
            .count()
            == 1
            && broad_matcher
                .matches("remap_decl_index_to_headers")
                .count()
                == 1
            && broad_matcher
                .matches("file_imports: file_imports.as_ref()")
                .count()
                == 1
            && broad_matcher.matches("scan_planned_file(").count() == 2
            && broad_matcher.contains("filtered_rule_refs_for_text")
            && broad_matcher.contains("filtered_rule_refs_for_syntax_header")
            && broad_matcher.contains("compiler_syntax_header_uncached(file)")
            && broad_matcher
                .find("let raw_scan_files")
                .zip(broad_matcher.find("prepare_compiler_object_session_for_body_scan"))
                .is_some_and(|(raw, compiler)| raw < compiler)
            && broad_matcher
                .split_once("let raw_scan_files")
                .and_then(|(_, tail)| tail.split_once("let imports_started"))
                .is_some_and(|(raw_plan, _)| raw_plan.contains(".par_iter()"))
            && broad_matcher
                .find("let mut scan_plan")
                .zip(broad_matcher.find("prepare_compiler_object_session_for_body_scan"))
                .is_some_and(|(headers, compiler)| headers < compiler)
            && broad_matcher.contains("imports_by_file.get(&file)")
            && !broad_matcher.contains("scan_decl_index")
            && remap_compiler_object.contains("headers.remap_file_to_existing_symbols(index)")
            && !remap_compiler_object.contains("decl_index_uncached")
            && !remap_compiler_object.contains("compiler_file_object"),
        "serial and parallel matcher schedules must share one exact compiler-object body scanner and reuse its imports without reparsing"
    );
    assert!(
        function_body(&workspace, "parser_incomplete_reasons_for_files")
            .contains("visit_parser_diagnostics_uncached")
            && function_body(&workspace, "parser_incomplete_reasons_for_files")
                .contains("compiler_diagnostics_are_current")
            && !function_body(&workspace, "parser_incomplete_reasons_for_files")
                .contains("visit_compiler_file_objects_uncached")
            && function_body(&workspace, "diagnostics")
                .contains("visit_compiler_file_objects_uncached"),
        "parser completeness must use exact syntax diagnostics without lowering semantic bodies; explicit whole-workspace diagnostics may stream compiler objects"
    );
    assert!(
        function_body(&security_execution, "build_findings_chain_aware")
            .contains("release_matcher_fact_caches()")
            && function_body(&security_matcher, "release_matcher_fact_caches")
                .matches("clear_retained()")
                .count()
                == 3
            && function_body(&security_matcher, "release_matcher_fact_caches")
                .matches("point_matcher_fact_cache_budget_share")
                .count()
                == 3
            && function_body(
                &security_matcher,
                "match_rules_against_facts_with_progress_and_mode"
            )
            .contains("prepare_matcher_fact_caches_for_broad_scan()"),
        "matcher projections must stay warm across broad AST scans, then be released and memory-narrowed before the semantic graph opens"
    );
    assert!(
        function_body(&resources, "compiler_weighted_batches").contains("cpu_workers.max(1)")
            && function_body(&resources, "compiler_weighted_batches")
                .contains("current_process_resident_bytes")
            && function_body(&resources, "compiler_weighted_batches_for_limit_and_resident")
                .contains("weighted_working_memory_bytes")
            && function_body(&resources, "weighted_batches_for_working_set")
                .contains("end - start < cpu_workers")
            && function_body(&resources, "weighted_working_memory_bytes").contains("resident_bytes")
            && function_body(&resources, "weighted_working_memory_bytes").contains("headroom"),
        "weighted compiler schedules must retain the CPU ceiling, subtract measured resident state, and retain safety headroom while allowing small exact units to share a batch"
    );
    assert!(
        function_body(&db, "build_global_header_index").contains("insert_header_preprocessed")
            && function_body(&taint_idg, "build_resolved_call_graph_snapshot_scoped")
                .contains("build_resolved_call_graph_snapshot_with_headers_scoped")
            && !function_body(&taint_idg, "build_resolved_call_graph_snapshot_scoped")
                .contains("global_index()")
            && function_body(
                &taint_idg,
                "build_resolved_call_graph_snapshot_with_headers_scoped"
            )
            .contains("decl_index_remapped_to_headers")
            && function_body(&workspace, "source_reachable_resolved_call_graph_with_scope")
                .contains("build_with_file_semantics_for_funcs_streaming_with_context")
            && function_body(&workspace, "source_reachable_resolved_call_graph_with_scope")
                .contains("build_with_file_semantics_for_files_streaming_with_context")
            && function_body(&workspace, "source_reachable_resolved_call_graph_with_scope")
                .contains("decl_index_remapped_to_headers")
            && function_body(&workspace, "source_reachable_resolved_call_graph_with_scope")
                .contains("queued_funcs")
            && function_body(&workspace, "source_reachable_resolved_call_graph_with_scope")
                .contains("take_exclusive_compiler_header_index()")
            && function_body(&workspace, "source_reachable_resolved_call_graph_with_scope")
                .contains("project_linkage_from_remapped_file")
            && function_body(&workspace, "source_reachable_resolved_call_graph_with_scope")
                .contains("install_projected_linkage")
            && function_body(
                &callgraph,
                "build_with_file_semantics_streaming_with_context_scoped"
            )
            .contains("index.defs.retain"),
        "callgraph construction must keep complete declaration/type headers and stream exact demand-selected callable bodies and linkage"
    );
    let source_reachable = function_body(&workspace, "source_reachable_resolved_call_graph_with_scope");
    assert!(
        source_reachable.contains("target_callers_by_callee")
            && source_reachable.contains("while let Some(callee) = pending.pop()")
            && source_reachable.contains("compiler_weighted_batches")
            && source_reachable.contains("pending_reached")
            && source_reachable.contains("pending_reverse_output")
            && !source_reachable.contains("while changed")
            && !source_reachable.contains(".take(")
            && !source_reachable.contains(".truncate("),
        "source/callback/return corridors must converge through exact indexed compiler worklists and memory-weighted file batches"
    );
    assert!(
        function_body(&workspace, "build_and_persist_idg_sidecar").contains("compiler_linkage_index()")
            && function_body(&workspace, "build_and_persist_idg_sidecar")
                .contains("build_for_persistence_streaming_with_callgraph_relation_and_file_semantics_and_options")
            && function_body(&workspace, "build_and_persist_idg_sidecar")
                .contains("CallgraphQueryService::open_checked")
            && function_body(&workspace, "build_and_persist_idg_sidecar")
                .contains("compile_default_query_accelerator")
            && function_body(&workspace, "build_and_persist_idg_sidecar")
                .contains("install_query_accelerator")
            && function_body(&workspace, "build_and_persist_idg_sidecar")
                .find("install_query_accelerator")
                .zip(
                    function_body(&workspace, "build_and_persist_idg_sidecar")
                        .find("save_into_disk")
                )
                .is_some_and(|(install, save)| install < save)
            && function_body(&idg_service, "load_from_disk")
                .contains("PersistedQueryAccelerator::decode")
            && function_body(&idg_workspace, "load_query_from_disk")
                .contains("metadata.func_segments")
            && !function_body(&idg_workspace, "load_query_from_disk")
                .contains("segment_view")
            && function_body(&idg, "lower_transfer_segment").contains("body_for_file")
            && function_body(&index, "insert_linkage_header_preprocessed")
                .contains("decl.flow_events.clear()")
            && function_body(&index, "insert_linkage_header_preprocessed").contains("function_linkage_facts")
            && function_body(&index, "insert_linkage_header_preprocessed")
                .contains("consumed_call_results_by_symbol")
            && function_body(&index, "insert_linkage_header_preprocessed")
                .contains("index.call_argument_values.clear()")
            && function_body(&index, "insert_linkage_header_preprocessed")
                .contains("index.static_string_maps.clear()")
            && function_body(&index, "insert_linkage_header_preprocessed")
                .contains("index.character_substitutions.clear()")
            && index.contains("pub consumed_call_results: Vec<Span>")
            && index.contains("pub has_writeback_arg: bool")
            && index.contains("pub has_summary_output: bool")
            && index.contains("pub returned_constructor_calls: Vec<ReturnedConstructorLinkageFact>")
            && function_body(&workspace, "has_summary_output").contains("linkage_facts")
            && function_body(&workspace, "target_emission_requires_callee")
                .contains("consumed_call_results")
            && function_body(&workspace, "target_emission_requires_callee")
                .contains("has_writeback_arg")
            && function_body(&workspace, "target_emission_requires_callee")
                .contains("receiver_field_writes")
            && function_body(&workspace, "call_edge_passes_target_callback")
                .contains("span_contains(*arg_span, *target_span)")
            && !function_body(&workspace, "call_edge_passes_target_callback")
                .contains("callable_reference_variants"),
        "IDG persistence must retain linkage headers, stream exact compiler-object bodies, consume the partitioned call relation at segment boundaries, and publish a validated query-ready fixed point that warm opens do not reconstruct from every body"
    );
    let stitch = function_body(&idg_builder, "stitch_idg_from_spooled_segment_batches");
    assert!(
        stitch.contains("extend_callee_endpoints_for_segment")
            && stitch.contains("segment.release_build_lookups()")
            && stitch.contains("segment.rebuild_build_lookups()")
            && stitch.contains("StitchSegmentRecord")
            && stitch.contains("stitch_spool.push")
            && stitch.contains("stitch_spool.into_visit")
            && stitch.contains("enable_segment_spool(spool_path)")
            && stitch.contains("spill_segment")
            && stitch.contains("begin_spool_generation()")
            && stitch.contains("finish_spool_generation()")
            && stitch.contains("schedule_to_workspace")
            && stitch.contains("canonical_function_count")
            && stitch.contains("stitched_function_count")
            && stitch.contains("disable_cross_file_indexes()")
            && function_body(&idg, "build_with_file_info_and_options_scoped")
                .contains("stitch_idg_from_spooled_segment_batches")
            && function_body(&idg, "build_with_file_info_and_options_scoped")
                .matches("lower_transfer_segment")
                .count()
                == 1
            && function_body(&idg_workspace, "rebuild_indexes").contains("self.maintain_indexes = true"),
        "sidecar IDG builds must lower each compiler unit once, spool typed stitch objects without semantic caps, release transient indexes at segment boundaries, and defer query-only edge indexes to warm load"
    );
    assert!(
        struct_body(&idg_workspace, "IdgSegmentSpool").contains("PreparedFactStorePayload")
            && struct_body(&idg_workspace, "WireChunkSpool").contains("PreparedFactStorePayload")
            && struct_body(&idg_workspace, "SymbolicFieldCompilerStorage")
                .contains("transform_spool")
            && function_body(&idg_builder, "place_inter_edge").contains("push_cross_file_edge")
            && function_body(&idg_builder, "from_workspace_for_segments_streaming")
                .contains("visit_cross_file_edges")
            && !function_body(&idg_builder, "field_place_keys_for_propagation")
                .contains("visit_transforms")
            && !function_body(&idg_builder, "stitch_field_argument_forwarding")
                .contains("stitch_symbolic_field_fallbacks")
            && function_body(&idg_service, "symbolic_forward_closure_nodes")
                .contains("self.workspace.symbolic_field()")
            && function_body(&idg_workspace, "save_workspace_parts")
                .contains("into_factstore_writer")
            && function_body(&idg_workspace, "save_workspace_parts").contains("spool.write_chunks")
            && function_body(&idg_workspace, "into_factstore_writer")
                .contains("FactStoreWriter::create_from_prepared")
            && function_body(&factstore_writer, "create_from_prepared").contains("prepared.relocate")
            && !idg_workspace.contains("fn streamed_entry"),
        "sidecar persistence must adopt already-encoded compiler segments, stream bounded cross-edge/symbolic-transform chunks, and never re-index the symbolic product as duplicate concrete fallback edges"
    );
    assert!(
        symbolic.contains("pub arg_idx: u32")
            && symbolic.contains("pub param_idx: u32")
            && function_body(&idg_service, "symbolic_cross_call_slots")
                .contains("(transform.arg_idx, transform.param_idx)")
            && !idg_service.contains("fn symbolic_call_shape"),
        "symbolic IDG transforms must persist resolved AST argument/formal slots instead of reopening function bodies during queries"
    );
    assert!(
        idg.contains("struct CallerCallSiteEdges")
            && idg.contains("call_edge_site_cache: RwLock<Option<CallerCallSiteEdges>>")
            && function_body(&idg, "with_call_edges_at_site").contains("visit(hit.rows_at_site(site))")
            && function_body(&idg, "call_edges_for_caller")
                .contains("call_graph.visit_callees(caller")
            && function_body(&idg, "call_edges_for_caller").contains("out.finish()")
            && function_body(&idg, "rows_at_site").contains("partition_point")
            && !idg.contains("struct CallSiteEdgeIndex")
            && !idg.contains("call_edges_by_site_for_funcs")
            && !idg.contains("AHashMap<CallSiteEdgeKey")
            && !function_body(&idg, "finish").contains("shrink_to_fit"),
        "exact call-site ownership must be retained as a sorted compiler index for only the active caller unit"
    );
    let maps = struct_body(&idg, "WorkspaceMaps");
    for duplicate in [
        "func_to_name",
        "func_to_language",
        "func_to_module",
        "func_to_directory",
        "func_to_file",
        "func_to_scope",
        "symbol_to_scope",
        "symbol_to_directory",
        "funcs_by_callback_name_module",
        "funcs_by_callback_name_directory",
        "funcs_by_callback_name_file",
    ] {
        assert!(
            !maps.contains(duplicate),
            "WorkspaceMaps must derive `{duplicate}` from GlobalIndex/file facts instead of cloning it per symbol"
        );
    }
}

#[test]
fn first_class_path_and_slice_use_syntax_derived_indexes_only() {
    let root = repo_root();
    let paths_rs = read(&root.join("crates/browse/src/paths.rs"));
    let cli_path = read(&root.join("crates/cli/src/commands/path.rs"));
    let path_body = live_code(function_body(&paths_rs, "paths"));
    let path_graph_body = live_code(function_body(&paths_rs, "semantic_path_graph"));
    let path_finalize_body = live_code(function_body(&paths_rs, "finalize_outcome"));
    assert!(
        path_body.contains("semantic_path_graph(ws, &from_funcs, &graph_targets, warmed_idg.as_deref())")
            && path_body.contains("enumerate_paths_resolved("),
        "path queries must enumerate the shared semantic path graph and report resolution coverage"
    );
    assert!(
        path_graph_body.contains("ws.cached_resolved_call_graph()")
            && path_graph_body.contains("persisted_resolved_call_graph_between")
            && path_graph_body.contains("idg.semantic_cross_call_edges_with_max_precision(")
            && path_graph_body.contains("call_edge_from_idg_cross_call("),
        "path semantic graph must prefer exact partitioned relations, fall back to the cached resolved graph, and augment with warmed IDG cross-call edges"
    );
    assert!(
        cli_path.matches("open_project_path_query(root)?").count() >= 2
            && !cli_path.contains("mark_endpoint_candidate_scope"),
        "retrieval path candidates must fall back to the complete lazy compiler snapshot unless an exact partitioned graph answered the query"
    );
    assert!(
        path_finalize_body.contains("resolution_incomplete_reasons_for_funcs(")
            && path_finalize_body.contains("resolution_scope"),
        "path query completeness must include resolver coverage gaps"
    );
    for forbidden in [
        "read_to_string",
        "std::fs",
        "source_text",
        "raw_text",
        ".contents(",
        ".text(",
    ] {
        assert!(
            !path_body.contains(forbidden),
            "path queries must not fall back to raw source/text search via `{forbidden}`"
        );
    }
    let idg_service = read(&root.join("crates/idg/src/service.rs"));
    assert!(
        idg_service.contains("semantic_cross_call_edges_with_max_precision")
            && idg_service.contains("Every semantic cross-call dataflow edge known to the IDG"),
        "IDG must expose renderable semantic cross-call edges for path/security/export consumers"
    );
    let cli_reference = read(&root.join("docs/cli-reference.mdx"));
    let sdk_reference = read(&root.join("docs/contributing/sdk.mdx"));
    let architecture = read(&root.join("docs/contributing/architecture.mdx"));
    assert!(
        cli_reference.contains("idg_semantic_edges")
            && sdk_reference.contains("PathOutcome.backends")
            && architecture.contains("warmed IDG cross-call edges"),
        "path docs must describe warmed-IDG backend metadata and semantic graph augmentation"
    );

    let slice_rs = read(&root.join("crates/browse/src/slice.rs"));
    let slice_body = live_code(function_body(&slice_rs, "slices"));
    let slice_decl_body = live_code(function_body(&slice_rs, "slice_decl"));
    assert!(
        slice_body.contains("global.all_files()")
            && slice_body.contains("exact_decl_index_shared(file)")
            && slice_body.contains("for decl in &index.defs")
            && slice_decl_body.contains("decl.flow_events"),
        "slice queries must stream exact compiler-object declarations selected by compact linkage and consume adapter-emitted FlowEvent facts"
    );
    assert!(
        slice_decl_body.contains("backward_slice_from_facts(")
            && slice_decl_body.contains("semantic_slice_from_value_flow(")
            && slice_decl_body.contains("analysis_incomplete_reasons"),
        "slice queries must merge local FlowEvent evidence with shared semantic value-flow evidence and expose bounded completeness"
    );
    let semantic_slice_body = live_code(function_body(&slice_rs, "semantic_slice_from_value_flow"));
    assert!(
        semantic_slice_body.contains("ws.value_flow()")
            && semantic_slice_body.contains("graph_for_with_caches(")
            && semantic_slice_body.contains("graph.backward_closure("),
        "slice semantic evidence must come from the shared value-flow graph, not command-local traversal"
    );
    let slice_live = live_code(&slice_rs);
    for forbidden in [
        "read_to_string",
        "std::fs",
        "source_text",
        "raw_text",
        ".contents(",
        ".text(",
        "regex::Regex",
    ] {
        assert!(
            !slice_live.contains(forbidden),
            "slice queries must not fall back to raw source/text search via `{forbidden}`"
        );
    }
}

/// Dependency manifests and lockfiles can affect semantic import/call
/// resolution without changing source files. Cache freshness must scan those
/// metadata files consistently across sidecars, SDK export cache, and CLI page
/// cache, and it must not miss deeply nested monorepo packages.
#[test]
fn cache_dependency_metadata_fingerprints_use_shared_unbounded_walk() {
    let root = repo_root();
    let common_dependency_metadata = read(&root.join("crates/common/src/dependency_metadata.rs"));
    let workspace_cache = read(&root.join("crates/workspace/src/cache_fingerprint.rs"));
    let sdk = read(&root.join("crates/sdk/src/lib.rs"));
    let page_cache = read(&root.join("crates/cli/src/page_cache.rs"));
    let security_deps = read(&root.join("crates/security/src/deps.rs"));

    let walk_body = function_body(&common_dependency_metadata, "walk_dependency_metadata_files");
    assert!(
        !walk_body.contains("depth"),
        "dependency metadata traversal must not be depth-limited; deep manifests affect semantics"
    );
    assert!(
        workspace_cache.contains("walk_dependency_metadata_files(root")
            || workspace_cache.contains("walk_dependency_metadata_files(root,"),
        "workspace sidecar fingerprints must use the shared dependency metadata walker"
    );
    assert!(
        sdk.contains("collect_dependency_metadata_fingerprints(root)")
            && page_cache.contains("collect_dependency_metadata_fingerprints(root)"),
        "SDK export and CLI page caches must use the shared dependency metadata collector"
    );
    assert!(
        !workspace_cache.contains(", 4,") && !sdk.contains(", 4,") && !page_cache.contains(", 4,"),
        "cache dependency metadata fingerprints must not reintroduce a depth-4 cap"
    );

    let deps_walk_body = function_body(&security_deps, "walk_dir");
    assert!(
        !deps_walk_body.contains("depth"),
        "security dependency inventory must not miss deep manifests behind a depth cap"
    );
    assert!(
        function_body(&security_deps, "scan_manifest_files").contains("manifest_target_names"),
        "security dependency inventory must bound memory with manifest-name filtering, not traversal depth"
    );
}

/// Persisted analysis caches are performance artifacts only. Every
/// sidecar that can replay structural or flow facts must reject stale
/// data when source content, dependency metadata, matcher policy, or
/// rule/config semantics change; rendered/export caches must also bind
/// to rulepack content and pipeline/build versions.
#[test]
fn persisted_analysis_caches_bind_all_freshness_inputs() {
    let root = repo_root();
    let dataflow = read(&root.join("crates/workspace/src/dataflow.rs"));
    let value_flow = read(&root.join("crates/workspace/src/value_flow.rs"));
    let flow_ids = read(&root.join("crates/workspace/src/flow_ids.rs"));
    let taint_index = read(&root.join("crates/workspace/src/taint_index.rs"));
    let retrieval = read(&root.join("crates/retrieval/src/lib.rs"));
    let workspace = read(&root.join("crates/workspace/src/lib.rs"));
    let workspace_build = read(&root.join("crates/workspace/build.rs"));
    let callgraph_sidecar = read(&root.join("crates/workspace/src/callgraph_sidecar.rs"));
    let security_analysis = security_analysis_source(&root);
    let taint_cache = read(&root.join("crates/security/src/analysis/taint_cache.rs"));
    let sdk = read(&root.join("crates/sdk/src/lib.rs"));
    let page_cache = read(&root.join("crates/cli/src/page_cache.rs"));

    for (label, source, function) in [
        ("dataflow", dataflow.as_str(), "dataflow_pipeline_hash"),
        ("value-flow", value_flow.as_str(), "value_flow_pipeline_hash"),
        ("flow-ids", flow_ids.as_str(), "flow_ids_pipeline_hash"),
    ] {
        // The hash is split across `X_pipeline_hash` (binds source
        // content) and `X_pipeline_hash_for_content` (binds matcher
        // policy + dependency metadata); check the combined body so the
        // invariant survives that refactor.
        let body = format!(
            "{} {}",
            function_body(source, function),
            function_body(source, &format!("{function}_for_content"))
        );
        assert!(
            body.contains("MATCHER_POLICY_FINGERPRINT")
                && body.contains("workspace_content_fingerprint(db)")
                && body.contains("dependency_metadata_fingerprint_for_sidecar(sidecar_path)")
                && !body.contains("build_fingerprint_hash()"),
            "{label} factstore pipeline hash must bind its semantic ABI, matcher policy, source content, and dependency metadata without whole-binary invalidation"
        );
    }

    let taint_graph_body = function_body(&taint_index, "taint_graph_pipeline_hash");
    assert!(
        taint_graph_body.contains("MATCHER_POLICY_FINGERPRINT")
            && taint_graph_body.contains("workspace_content_fingerprint(db)")
            && taint_graph_body.contains("dependency_metadata_fingerprint_for_sidecar(sidecar_path)")
            && taint_graph_body.contains("idg_stitching_semantic_fingerprint()")
            && taint_graph_body.contains("config_fingerprint")
            && !taint_graph_body.contains("build_fingerprint_hash()"),
        "taint graph sidecar must bind matcher policy, IDG semantics, source content, dependency metadata, and rule/config fingerprint without whole-binary invalidation"
    );
    let retrieval_pipeline_body = function_body(&retrieval, "pipeline_hash_for_source_fingerprints");
    let idg_pipeline_body = function_body(&workspace, "idg_pipeline_hash");
    assert!(
        retrieval_pipeline_body.contains("RETRIEVAL_SCHEMA_VERSION")
            && retrieval_pipeline_body.contains("source_fingerprints_content_fingerprint")
            && retrieval_pipeline_body.contains("dependency_metadata_fingerprint(root)")
            && !retrieval_pipeline_body.contains("build_fingerprint"),
        "retrieval sidecars must use their semantic/schema ABI and exact compiler inputs, not the whole binary identity"
    );
    assert!(
        idg_pipeline_body.contains("MATCHER_POLICY_FINGERPRINT")
            && idg_pipeline_body.contains("idg_stitching_semantic_fingerprint()")
            && !idg_pipeline_body.contains("build_fingerprint_hash()"),
        "IDG sidecars must use the IDG semantic ABI and exact compiler inputs, not the whole binary identity"
    );
    let git_rerun_body = function_body(&workspace_build, "emit_git_rerun_inputs");
    assert!(
        !workspace_build.contains("dirty_content_hash")
            && !workspace_build.contains("emit_source_rerun_inputs")
            && !workspace_build.contains("\"status\"")
            && !workspace_build.contains("\"diff\""),
        "producer provenance must not force a workspace rebuild for every source edit; semantic sidecars own exact invalidation"
    );
    assert!(
        git_rerun_body.contains("symbolic-ref")
            && git_rerun_body.contains("git_path")
            && workspace_build.contains("rev-parse\", \"--git-path"),
        "workspace build fingerprint must watch the resolved HEAD ref and support worktree/submodule git paths"
    );
    assert!(
        security_analysis.contains("mod taint_cache;")
            && security_analysis.contains("taint_cache::scoped_config_fingerprint(")
            && security_analysis.contains("\"source-analysis\"")
            && security_analysis.contains("\"taint-analysis\""),
        "security analysis must route source and taint analysis through the shared taint cache fingerprint"
    );
    let taint_config_body = function_body(&taint_cache, "config_fingerprint");
    assert!(
        taint_config_body.contains("pack.all_rules()")
            && taint_config_body.contains("rule.enabled")
            && taint_config_body.contains("serde_json::to_string(rule)"),
        "taint graph config fingerprint must include enabled rulepack content, not just rule ids"
    );

    // Metadata validation is shared by warm freshness probes and full graph
    // loads. Inspect both boundaries so this invariant continues to prove the
    // complete contract without requiring validation logic to be duplicated
    // inside `load_callgraph_sidecar`.
    let callgraph_load_body = function_body(&callgraph_sidecar, "load_callgraph_sidecar_checked");
    let callgraph_validation_body = function_body(&callgraph_sidecar, "validate_metadata");
    assert!(
        callgraph_sidecar.contains("matcher_policy_fingerprint: MATCHER_POLICY_FINGERPRINT")
            && callgraph_sidecar.contains("dependency_metadata_fingerprint_for_sidecar(path)")
            && callgraph_sidecar.contains("fnv1a_bytes64(snapshot.text.as_bytes())")
            && callgraph_load_body.contains("validate_metadata(path, &metadata)")
            && callgraph_validation_body
                .contains("metadata.matcher_policy_fingerprint != MATCHER_POLICY_FINGERPRINT")
            && callgraph_validation_body.contains(
                "metadata.dependency_metadata_fingerprint != dependency_metadata_fingerprint_for_sidecar(path)",
            )
            && !callgraph_validation_body.contains("build_fingerprint_hash()")
            && callgraph_load_body.contains("current_source_fingerprints(db) != metadata.files"),
        "callgraph sidecar must validate its semantic ABI, matcher policy, dependency metadata, and complete source set without whole-binary invalidation"
    );

    let export_metadata_body = function_body(&sdk, "build_export_cache_metadata");
    assert!(
        export_metadata_body.contains("build_fingerprint")
            && export_metadata_body.contains("pipeline_version")
            && export_metadata_body.contains("MATCHER_POLICY_FINGERPRINT")
            && export_metadata_body.contains("workspace_sources")
            && export_metadata_body.contains("dependency_metadata_fingerprint(root)")
            && export_metadata_body.contains("rulepack_content_fingerprint"),
        "export cache metadata must bind build/pipeline version, matcher policy, source content, dependency metadata, and rulepack content"
    );
    assert!(
        page_cache.contains("binary_version")
            && page_cache.contains("matcher_policy_fingerprint")
            && page_cache.contains("workspace_fingerprint")
            && page_cache.contains("dependency_metadata_fingerprint")
            && page_cache.contains("rulepack_fingerprint")
            && function_body(&page_cache, "read_cache").contains("current_exe_is_newer_than_cache(&metadata)"),
        "CLI page cache metadata must bind binary version, executable freshness, matcher policy, source content, dependency metadata, and rulepack content"
    );
}

/// `bonsai-ninja index <workspace>` is the syntax/construct warm-up path.
/// Semantic and dataflow prewarm are explicit modes; cache rebuild remains
/// bounded and must not become an accidental full semantic/dataflow prewarm.
#[test]
fn default_index_path_stays_structural_with_explicit_warm_modes() {
    let root = repo_root();
    let args = read(&root.join("crates/cli/src/args.rs"));
    let main = read(&root.join("crates/cli/src/main.rs"));
    let diagnostics = read(&root.join("crates/cli/src/commands/diagnostics.rs"));
    let commands_mod = read(&root.join("crates/cli/src/commands/mod.rs"));
    let workspace = read(&root.join("crates/workspace/src/lib.rs"));
    let cache_cmd = read(&root.join("crates/cli/src/commands/cache.rs"));

    assert!(
        args.contains("By default this is syntax/construct index-up-front behavior")
            && args.contains("prewarm_dataflow: bool")
            && args.contains("semantic: bool")
            && args.contains("structural_only: bool")
            && args.contains("conflicts_with = \"structural_only\""),
        "index CLI must document semantic prewarm default and expose structural/dataflow alternatives explicitly"
    );

    let index_body = function_body(&diagnostics, "cmd_index");
    assert!(
        diagnostics.contains("struct IndexCommandOptions")
            && diagnostics.contains("structural_only: bool")
            && diagnostics.contains("semantic_worker: Option<SemanticWorkerPhase>")
            && index_body.contains("if options.semantic")
            && index_body.contains("run_semantic_workers(root)?")
            && index_body.contains("if options.prewarm_dataflow")
            && index_body.contains("open_project_dataflow_prewarm(root)?")
            && index_body.contains("open_project_parse_only(root)?")
            && function_body(&diagnostics, "run_semantic_workers").contains("semantic_phase_plan")
            && function_body(&diagnostics, "run_semantic_workers")
                .contains("std::env::current_exe()")
            && function_body(&diagnostics, "semantic_phase_plan")
                .contains("SemanticWorkerPhase::Compiler")
            && function_body(&diagnostics, "semantic_phase_plan")
                .contains("SemanticWorkerPhase::Retrieval")
            && function_body(&diagnostics, "semantic_phase_plan")
                .contains("SemanticWorkerPhase::Callgraph")
            && function_body(&diagnostics, "semantic_phase_plan")
                .contains("SemanticWorkerPhase::Linkage")
            && function_body(&diagnostics, "semantic_phase_plan").contains("SemanticWorkerPhase::Idg"),
        "cmd_index must keep default/structural-only runs parse-only and isolate exact semantic phases in worker processes"
    );
    assert!(
        function_body(&commands_mod, "open_project_sidecar_validation_only")
            .contains("OpenOptions::sidecar_validation_only()"),
        "semantic workers must open immutable snapshots without hydrating unrelated semantic graphs"
    );
    assert!(
        main.contains("structural_only,")
            && main.contains("prewarm_dataflow,")
            && main.contains("semantic,")
            && main.contains("cmd_index("),
        "CLI dispatch must pass all index mode flags into cmd_index"
    );

    let parse_only_body = function_body(&workspace, "parse_only");
    assert!(
        parse_only_body.contains("load_callgraph_sidecar: false")
            && parse_only_body.contains("load_dataflow_sidecar: false")
            && parse_only_body.contains("prewarm_dataflow: false")
            && parse_only_body.contains("save_dataflow_sidecar: false")
            && parse_only_body.contains("load_value_flow_sidecar: false")
            && parse_only_body.contains("prewarm_value_flow: false")
            && parse_only_body.contains("load_idg_sidecar: false")
            && parse_only_body.contains("prewarm_flow_ids: false"),
        "WorkspaceOpenOptions::parse_only must not load or prewarm semantic analysis sidecars"
    );
    let full_prewarm_body = function_body(&workspace, "full_prewarm");
    assert!(
        full_prewarm_body.contains("prewarm_dataflow: true")
            && full_prewarm_body.contains("prewarm_flow_ids: true")
            && full_prewarm_body.contains("load_idg_sidecar: true")
            && full_prewarm_body.contains("prewarm_value_flow: false")
            && full_prewarm_body.contains("save_value_flow_sidecar: false"),
        "full prewarm must build canonical IDG/dataflow facts without eagerly projecting one legacy ValueFlowGraph per function"
    );
    assert!(
        function_body(&commands_mod, "open_project_parse_only").contains("OpenOptions::parse_only()"),
        "CLI parse-only open helper must use WorkspaceOpenOptions::parse_only"
    );
    assert!(
        function_body(&commands_mod, "open_project_dataflow_prewarm")
            .contains("options.prewarm_dataflow = true")
            && function_body(&commands_mod, "open_project_dataflow_prewarm")
                .contains("options.save_dataflow_sidecar = true"),
        "full dataflow prewarm helper must remain explicit and visibly side-effectful"
    );
    assert!(
        function_body(&cache_cmd, "cache_rebuild").contains("run_semantic_workers(&workspace_root)?")
            && !function_body(&cache_cmd, "cache_rebuild").contains("build_and_persist_idg_sidecar()")
            && !function_body(&cache_cmd, "cache_rebuild").contains("prewarm_dataflow"),
        "cache rebuild must use isolated structural compiler workers without regressing to full-workspace compatibility prewarm"
    );
}

#[test]
fn semantic_prewarm_isolates_workspace_phases_by_peak_memory() {
    let sdk = read(&repo_root().join("crates/sdk/src/lib.rs"));
    let diagnostics = read(&repo_root().join("crates/cli/src/commands/diagnostics.rs"));
    let idg_workspace = read(&repo_root().join("crates/idg/src/workspace.rs"));
    let idg_service = read(&repo_root().join("crates/idg/src/service.rs"));
    let idg_builder = read(&repo_root().join("crates/idg/src/builder.rs"));
    let idg_adapter = read(&repo_root().join("crates/idg/src/workspace_adapter.rs"));
    let linkage_sidecar = read(&repo_root().join("crates/workspace/src/linkage_sidecar.rs"));
    let index = read(&repo_root().join("crates/index/src/lib.rs"));
    let retrieval_crate = read(&repo_root().join("crates/retrieval/src/lib.rs"));
    let workspace = read(&repo_root().join("crates/workspace/src/lib.rs"));
    let db = read(&repo_root().join("crates/db/src/lib.rs"));
    let dataflow = read(&repo_root().join("crates/workspace/src/dataflow.rs"));
    let flow_ids = read(&repo_root().join("crates/workspace/src/flow_ids.rs"));
    let native_export = read(&repo_root().join("crates/browse/src/native_export.rs"));
    let warm = function_body(&sdk, "warm_structural_sidecars");
    assert!(
        warm.contains("warm_compiler_object_sidecar()?")
            && warm.contains("warm_retrieval_and_callgraph_sidecars()?")
            && warm.contains("warm_idg_sidecar_and_manifest()"),
        "SDK semantic warming must expose the same explicit compiler phase boundary"
    );
    let frontend = function_body(&sdk, "warm_retrieval_and_callgraph_sidecars");
    let compiler = function_body(&sdk, "warm_compiler_object_sidecar");
    let retrieval = function_body(&sdk, "warm_retrieval_sidecar");
    let callgraph = function_body(&sdk, "warm_callgraph_sidecar");
    let linkage = function_body(&sdk, "warm_compiler_linkage_sidecar");
    let idg = function_body(&sdk, "warm_idg_sidecar_and_manifest");
    assert!(
        compiler.contains("save_compiler_object_sidecar")
            && frontend.contains("warm_retrieval_sidecar()?")
            && frontend.contains("warm_callgraph_sidecar()?")
            && frontend.contains("warm_compiler_linkage_sidecar()")
            && retrieval.contains("bonsai_retrieval::ensure_sidecar")
            && callgraph.contains("save_callgraph_sidecar")
            && linkage.contains("save_compiler_linkage_sidecar")
            && !frontend.contains("build_and_persist_idg_sidecar")
            && idg.contains("validate_idg_sidecar_layout")
            && idg.contains("callgraph_sidecar_is_current")
            && idg.contains("save_callgraph_sidecar")
            && idg.contains("load_compiler_linkage_sidecar_checked")
            && idg.contains("build_and_persist_idg_sidecar")
            && idg.contains("write_manifest"),
        "compiler objects, retrieval, callgraph, linkage, and IDG persistence must be independently executable exact phases"
    );
    let workers = function_body(&diagnostics, "run_semantic_workers");
    let phase_plan = function_body(&diagnostics, "semantic_phase_plan");
    let phase_process = function_body(&diagnostics, "run_semantic_phase_process");
    assert!(
        workers.contains("semantic_phase_plan")
            && workers.contains("run_semantic_phase_process")
            && phase_plan.contains("SemanticWorkerPhase::Compiler")
            && phase_plan.contains("SemanticWorkerPhase::Retrieval")
            && phase_plan.contains("SemanticWorkerPhase::Callgraph")
            && phase_plan.contains("SemanticWorkerPhase::Linkage")
            && phase_plan.contains("SemanticWorkerPhase::Idg")
            && phase_process.contains("Command::new(executable)")
            && phase_process.contains("command.status()?")
            && phase_process.contains("if !status.success()"),
        "CLI semantic prewarm must run exact phases sequentially across OS-reclaimed process boundaries"
    );
    let generation_is_current = function_body(&diagnostics, "semantic_generation_is_current");
    assert!(
        workers.contains("loop")
            && workers.contains("semantic_generation_is_current")
            && generation_is_current.contains("validation.semantic_ready")
            && generation_is_current.contains("validation.manifest_status")
            && generation_is_current.contains("CacheFreshnessStatus::Fresh")
            && !workers.contains(".take(")
            && !workers.contains(".truncate("),
        "semantic workers must publish one coherent current generation without a retry or semantic-work cap"
    );
    assert!(
        phase_plan
            .find("SemanticWorkerPhase::Compiler")
            .zip(phase_plan.find("SemanticWorkerPhase::Callgraph"))
            .is_some_and(|(compiler, callgraph)| compiler < callgraph)
            && phase_plan
                .find("SemanticWorkerPhase::Callgraph")
                .zip(phase_plan.find("SemanticWorkerPhase::Retrieval"))
                .is_some_and(|(callgraph, retrieval)| callgraph < retrieval)
            && function_body(&retrieval_crate, "ensure_sidecar")
                .contains("ws.load_callgraph_sidecar(workspace_root)"),
        "retrieval compilation must reuse the exact callgraph phase artifact instead of recompiling its dependency"
    );
    assert!(
        linkage_sidecar.contains("files: Vec<(u32, String, u64)>")
            && linkage_sidecar.contains("wire::encode_struct_map_to_writer(output, linkage.as_ref())")
            && linkage_sidecar.contains("header_partition_key(file)")
            && linkage_sidecar.contains("index.file_index(FileId::new(file))")
            && linkage_sidecar.contains("header_files: Vec<u32>")
            && linkage_sidecar.contains("RECEIVER_ANCESTRY_KEY")
            && linkage_sidecar.contains("index.receiver_ancestry()")
            && index.contains("by_file.sort_unstable_by_key(|(file, _)| file.raw())")
            && index.contains("linkage_by_symbol.sort_unstable_by_key(|(symbol, _)| symbol.raw())")
            && function_body(&index, "header_projection").contains("GlobalIndexHeaderProjection")
            && index.contains("index.rebuild_persisted_indexes();"),
        "linkage phase artifacts must bind exact VFS identity and publish independently decodable canonical linkage, symbol-header, and receiver-ancestry payloads"
    );
    let compiler_headers = function_body(&workspace, "compiler_header_index");
    let exclusive_headers = function_body(&workspace, "take_exclusive_compiler_header_index");
    assert!(
        compiler_headers.contains("load_header_sidecar_checked")
            && compiler_headers
                .find("load_header_sidecar_checked")
                .zip(compiler_headers.find("build_global_header_index"))
                .is_some_and(|(load, fallback)| load < fallback)
            && !exclusive_headers.contains("build_global_header_index")
            && !exclusive_headers.contains("build_global_linkage_index"),
        "syntax lookup must deserialize the compiler symbol payload before its exact cold fallback and must never re-inflate file bodies at the scoped semantic phase boundary"
    );
    let load = function_body(&idg_workspace, "load_from_disk");
    assert!(
        load.contains("dictionary lookups fall back to an")
            && load.contains("disable_cross_file_indexes()")
            && !load.contains("cross_file.rebuild_indexes()")
            && !load.contains("segment.places.rebuild_lookup()")
            && !load.contains("segment.nodes.rebuild_lookup()")
            && !load.contains("segment.strings.rebuild_lookup()"),
        "warm IDG loads must keep canonical segment/cross-edge vectors and avoid eager workspace-wide reverse dictionaries"
    );
    let unified = function_body(&idg_service, "build_unified");
    let local_lookup = function_body(&idg_service, "local_node_for");
    assert!(
        unified.contains("let mut write_offsets = offsets[")
            && unified.contains("for (seg_id, segment) in self.workspace.segment_views()")
            && unified.contains("func_nodes[start..end].sort_unstable_by_key")
            && unified.contains("drop(write_offsets)")
            && local_lookup.contains("binary_search_by_key")
            && !idg_service.contains("segment.nodes.lookup(func, pid)"),
        "warm query lookup must use compact exact per-function ordering, not linear segment scans or full reverse hash tables"
    );
    assert!(
        idg_builder.contains("struct CalleeEndpointIndex")
            && idg_builder.contains("rows: Vec<CalleeEndpoints>")
            && idg_builder.contains("row_by_func: Vec<u32>")
            && idg_builder.contains("capture_funcs.is_none_or(|targets| targets.contains(&func))")
            && idg_adapter.contains("let capture_funcs = local_callable_bindings")
            && idg_adapter.contains("capture_funcs: Some(&capture_funcs)"),
        "cold IDG stitching must keep endpoint records packed and retain lexical captures only for AST/callgraph-proven local callables"
    );
    let hydrate = function_body(&workspace, "load_idg_sidecar");
    assert!(
        hydrate
            .find("compiler_header_index()")
            .is_some_and(|headers| hydrate
                .find("IdgQueryService::load_from_disk")
                .is_some_and(|idg| headers < idg))
            && !hydrate.contains("compiler_linkage_index()"),
        "warm query open must load stable compiler headers without retaining call-linkage beside the live IDG"
    );
    let streaming_imports = function_body(&db, "imports_for_uncached");
    let cached_imports = function_body(&db, "import_index");
    let seed_callgraph = function_body(&workspace, "seed_resolved_call_graph");
    let release_callgraph = function_body(&workspace, "release_resolved_call_graph_cache");
    let cached_callgraph = function_body(&workspace, "cached_resolved_call_graph");
    assert!(
        streaming_imports.contains("import_index_uncached(file)")
            && cached_imports.contains("compiler_import_index_uncached(file)")
            && !cached_imports.contains("extract_imports")
            && !streaming_imports.contains("build_import_index_uncached(file)")
            && seed_callgraph.contains("dataflow.seed_call_graph(graph.clone())")
            && seed_callgraph.contains("flow_ids.seed_call_graph(graph.clone())")
            && cached_callgraph.contains("seed_resolved_call_graph(graph.clone())")
            && cached_callgraph.contains("dataflow.seed_call_graph(arc.clone())")
            && cached_callgraph.contains("flow_ids.seed_call_graph(arc.clone())")
            && release_callgraph.contains("dataflow.release_call_graph()")
            && release_callgraph.contains("flow_ids.release_call_graph()")
            && function_body(&dataflow, "release_call_graph").contains("cached_call_graph.write()")
            && function_body(&flow_ids, "release_call_graph").contains("inner.write().cg = None"),
        "streaming compiler phases must reuse exact import headers and one canonical resolved callgraph across dataflow/flow-id consumers, then release every shared owner together"
    );
    let export_flow_labels = function_body(&native_export, "export_taint_chains_and_flow_labels");
    let indexed_flow_labels = function_body(&flow_ids, "labels_for_chain_sets_with_index_and_options");
    assert!(
        export_flow_labels.contains("compressed_callgraph")
            && !export_flow_labels.contains("labels_for_chain_sets")
            && !export_flow_labels.contains("chains_resolved")
            && indexed_flow_labels.contains("collect_flow_ids_for_chains(&cg, headers")
            && !indexed_flow_labels.contains("global_index()")
            && !flow_ids.contains("SharedCallPathResolver")
            && !function_body(&flow_ids, "collect_flow_ids_for_chains").contains("global_index()")
            && !function_body(&flow_ids, "enumerate_from").contains("global_index()"),
        "native export must not enumerate path labels, while query-time flow IDs reuse live compiler headers/callgraph without cloning whole-workspace adjacency/name tables, reopening body indexes, or reparsing sources"
    );
    let taint_graph_start = native_export
        .find("struct ExportTaintGraphStreaming")
        .expect("native export taint graph");
    let taint_graph_end = native_export[taint_graph_start..]
        .find("struct ExportTaintPropagationsStreaming")
        .map(|offset| taint_graph_start + offset)
        .expect("native export propagation renderer");
    let taint_graph = &native_export[taint_graph_start..taint_graph_end];
    let chains = taint_graph
        .find("map.serialize_entry(\"chains\"")
        .expect("chain rows");
    let release_bodies = taint_graph
        .find("release_exact_body_cache()")
        .expect("exact body phase release");
    let open_idg = taint_graph
        .find("export_projection_idg_service(self.ws)")
        .expect("projection IDG open");
    assert!(
        taint_graph.contains("RefCell<Option<ExportTaintChainsAndFlowLabels>>")
            && taint_graph.contains("self.chain_rows.borrow_mut().take()")
            && taint_graph.contains("flow_ids().release_resident_labels()")
            && taint_graph.contains("release_compiler_header_cache()")
            && taint_graph.contains("drop(return_taint_by_func)")
            && chains < release_bodies
            && release_bodies < open_idg,
        "native export must serialize/drop callgraph presentation rows and file-local compiler bodies before opening the exact IDG phase"
    );
}

#[test]
fn broad_security_scans_stream_exact_ast_bodies_beside_the_idg() {
    let matcher = read(&repo_root().join("crates/security/src/matcher/mod.rs"));
    let dependencies = read(&repo_root().join("crates/security/src/deps.rs"));
    let workspace = read(&repo_root().join("crates/workspace/src/lib.rs"));
    for path in [
        "crates/workspace/src/enclosing_index.rs",
        "crates/workspace/src/class_index.rs",
        "crates/workspace/src/decl_name_index.rs",
    ] {
        let metadata_index = read(&repo_root().join(path));
        assert!(
            metadata_index.contains("GlobalIndex")
                && !metadata_index.contains("AnalyzerDb")
                && !metadata_index.contains("global_index()"),
            "{path} must consume compact compiler declaration headers without materializing workspace bodies"
        );
    }
    let security_analysis = read(&repo_root().join("crates/security/src/analysis/mod.rs"));
    let func_lookup = function_body(&security_analysis, "func_id_for_match");
    assert!(
        func_lookup.contains("compiler_linkage_index()")
            && func_lookup.contains("enclosing_for(global.as_ref()")
            && !func_lookup.contains("db().global_index()"),
        "security finding attribution must use compact compiler linkage for enclosing declarations"
    );
    let completeness_scan = function_body(&security_analysis, "from_graph");
    assert!(
        completeness_scan.contains("unresolved_workspace_call_sites()")
            && completeness_scan.contains("analyzed_funcs.contains(caller)")
            && !completeness_scan.contains("exact_decl")
            && !completeness_scan.contains("global_index"),
        "whole-scope completeness checks must consume canonical compiler callgraph gaps for the analyzed function set, not rescan AST bodies"
    );
    let headers = function_body(&matcher, "streaming_global_headers");
    assert!(
        headers.contains("compiler_header_index()") && !headers.contains("compiler_linkage_index()"),
        "broad rule matching must load only the independent compiler symbol payload, not call linkage or workspace bodies"
    );
    let compiler_linkage = function_body(&workspace, "compiler_linkage_index");
    assert!(
        compiler_linkage.contains("idg_service()")
            && compiler_linkage.contains("global_linkage_index()")
            && compiler_linkage.contains("compiler_linkage.read()")
            && compiler_linkage.contains("compiler_linkage.write()")
            && compiler_linkage.contains("build_global_linkage_index()"),
        "Workspace must own the compact compiler linkage lifetime shared by IDG and streamed exact-body consumers"
    );
    let guarded_invalidation = function_body(&workspace, "invalidate_after_file_change");
    let invalidation = function_body(&workspace, "invalidate_after_file_change_locked");
    assert!(
        guarded_invalidation.contains("taint_analysis_serial.lock()")
            && guarded_invalidation.contains("idg_build_serial.lock()")
            && guarded_invalidation.contains("invalidate_after_file_change_locked(file)"),
        "source edits must own the complete semantic generation before invalidation"
    );
    assert!(
        invalidation.contains("compiler_linkage.write() = None")
            && invalidation.contains("compiler_headers.write() = None"),
        "locked source invalidation must clear the compact compiler symbol snapshot"
    );

    let broad_matcher = function_body(&matcher, "match_rules_against_facts_with_progress_and_mode");
    assert!(
        broad_matcher
            .matches("compiler_file_object_uncached(file)")
            .count()
            == 1
            && broad_matcher
                .matches("remap_decl_index_to_headers")
                .count()
                == 1
            && broad_matcher
                .matches("file_imports: file_imports.as_ref()")
                .count()
                == 1
            && broad_matcher.matches("scan_planned_file(").count() == 2
            && broad_matcher
                .matches("syntax_target_possible_in_text")
                .count()
                == 1
            && broad_matcher
                .find("syntax_target_possible_in_text")
                .zip(broad_matcher.find("filtered_rule_refs_for_text"))
                .zip(broad_matcher.find("if rules.is_empty()"))
                .zip(broad_matcher.find("filtered_rule_refs_for_syntax_header"))
                .zip(broad_matcher.find("compiler_file_object_uncached(file)"))
                .is_some_and(|((((text, packages), empty), syntax), body)| {
                    text < packages && packages < empty && empty < syntax && syntax < body
                })
            && broad_matcher.contains("compiler_receiver_ancestry()")
            && broad_matcher.contains("ancestry.apply_to_syntax_header")
            && broad_matcher.contains("ancestry.apply_to_decl_index")
            && !broad_matcher.contains("scan_decl_index"),
        "broad matcher scans must stop after an empty import/package result, filter exact text/import/call-target headers before body decode, preserve receiver ancestry for file-local inventory, and stream one compiler body per surviving file"
    );

    let inferred = function_body(&matcher, "infer_entry_point_sources_for_files_with_progress");
    assert!(
        inferred.contains("streaming_global_headers(ws)")
            && inferred.contains("decl_index_remapped_to_headers(global.as_ref(), file)")
            && !inferred.contains("global_index()"),
        "inferred entry-point analysis must stream exact file bodies instead of materializing a second workspace body index"
    );

    let execution = read(&repo_root().join("crates/security/src/analysis/execution.rs"));
    let shared_corridor = function_body(&execution, "shared_source_sink_corridor");
    let corridor_visitor = function_body(&execution, "visit_source_sink_corridors");
    assert!(
        shared_corridor.contains("visit_source_sink_corridors(")
            && shared_corridor.contains("source_corridors.insert(source, vec![corridor_index])"),
        "security must bind every reachable source to a complete exact per-source corridor"
    );
    assert!(
        corridor_visitor.contains("extend_corridor_with_summary_dependency_support")
            && corridor_visitor.contains("corridor.lineage_funcs.contains(source)")
            && corridor_visitor.contains("callgraph_source_sink_corridor("),
        "per-source corridor visitation must preserve exact callgraph and summary-dependency scope"
    );
    let source_scheduler = function_body(&execution, "schedule_source_groups");
    assert!(
        source_scheduler.contains("admitted_source_groups")
            && source_scheduler.contains("shared_source_sink_corridor(")
            && !source_scheduler.contains("group_corridor.extend(coarse_corridor"),
        "target admission must precede exact per-source corridor materialization, and a node slice must never be widened back to the workspace union"
    );
    let taint = read(&repo_root().join("crates/taint/src/reachable.rs"));
    let closure = function_body(&taint, "closure_evidence_with_targets");
    assert!(
        closure.contains("forward_closure_evidence_within_funcs_with_max_precision")
            && closure.contains(
                "forward_closure_evidence_within_funcs_and_relevance_with_max_precision"
            ),
        "taint closures must enforce both the compiler-proven function scope and reusable target demand during fixed-point propagation"
    );
    let source_relevance = function_body(&execution, "source_index_is_target_relevant");
    assert!(
        source_relevance.contains("target_relevance.admits_any(&seed_nodes)")
            && !source_relevance.contains("apply_configured_transfer_fixpoint"),
        "source scheduling must query the one materialized compiler graph instead of replaying an unindexed transfer engine"
    );
    let idg = read(&repo_root().join("crates/idg/src/service.rs"));
    let external_relation = read(&repo_root().join("crates/idg/src/external_relation.rs"));
    let fact_sources = read(&repo_root().join("crates/idg/src/fact_source_index.rs"));
    let function_summaries = read(&repo_root().join("crates/idg/src/function_summary.rs"));
    let reverse_scalar = read(&repo_root().join("crates/idg/src/reverse_scalar_index.rs"));
    let reverse_symbolic = read(&repo_root().join("crates/idg/src/reverse_symbolic_index.rs"));
    let target_relevance = function_body(&idg, "target_relevance_in_func_scope");
    assert!(
        target_relevance.contains("contextual.reach.visit_backward(node")
            && function_body(&idg, "visit_backward").contains("reach.backward_neighbours(node)")
            && target_relevance.contains("contextual.reverse_heap.visit(node")
            && target_relevance.contains("contextual.reverse_calls.visit(node")
            && target_relevance.contains("contextual.reverse_returns.visit(node")
            && target_relevance.contains("runtime.aggregate_inputs.get(&node)")
            && target_relevance.contains("Self::symbolic_facts_for_node(&unified, &runtime, node)")
            && target_relevance.contains("runtime.reverse_transforms.visit_incoming(base")
            && target_relevance.contains(".reverse_scalar_transforms")
            && target_relevance.contains(".visit_incoming(")
            && target_relevance.contains("node_is_allowed"),
        "IDG target demand must reverse ordinary, aggregate, access-path, and scalar-return compiler relations"
    );
    let target_relevance_relation = struct_body(&idg, "IdgTargetRelevance");
    let target_relevance_worklist = struct_body(&idg, "TargetRelevanceWorklist");
    assert!(
        target_relevance_relation.matches("SpillSet").count() == 2
            && target_relevance_worklist.matches("SpillStack").count() == 3
            && !target_relevance_relation.contains("AHashSet")
            && !target_relevance_worklist.contains("Vec<"),
        "backward target demand must spill exact symbolic relations and all work frontiers instead of growing with target fan-out"
    );
    let symbolic_runtime = struct_body(&idg, "SymbolicRuntimeIndex");
    let symbolic_fact_page = function_body(&idg, "build_symbolic_fact_page");
    let symbolic_fact_propagation = function_body(&idg, "propagate_symbolic_closure_fact");
    assert!(
        symbolic_runtime.contains("fact_sources: FactSourceIndex")
            && target_relevance.contains(".fact_sources")
            && target_relevance.contains(".visit_key(")
            && target_relevance.contains(".visit_base(")
            && fact_sources.contains("struct FactSourceSpool")
            && fact_sources.contains("ExternalSorter<FactSourceRecord>")
            && symbolic_runtime.contains("reverse_scalar_transforms: ReverseScalarTransformIndex")
            && reverse_scalar.contains("ExternalSorter<ReverseScalarRecord>")
            && symbolic_runtime.contains("reverse_transforms: ReverseSymbolicTransformIndex")
            && reverse_symbolic.contains("ExternalSorter<ReverseSymbolicRecord>")
            && external_relation.contains("struct RunMerger")
            && external_relation.contains("file: &'a File")
            && external_relation.contains("read_exact_at(self.file, self.offset")
            && external_relation.contains("merge_page_rows(runs.len(), R::BYTES, READ_ROWS)")
            && !external_relation.contains("clone exact compiler relation run spool"),
        "symbolic fact producers and both symbolic reverse relations must use exact external sorting with positioned range reads"
    );
    assert!(
        symbolic_runtime.contains("ordering_sensitive_bases: Box<[u64]>")
            && function_body(&idg, "local_provenance_id")
                .contains("retains_local_provenance(base)")
            && symbolic_fact_page.contains("runtime.local_provenance_id(base, span)")
            && symbolic_fact_propagation
                .contains("runtime.local_provenance_id(transform.target, transform.write_span)"),
        "symbolic fixed points must retain AST write provenance exactly where source-order transfer predicates consume it and canonicalize it everywhere else"
    );
    assert!(
        function_summaries.contains("file: Arc<std::fs::File>")
            && function_summaries.contains("read_exact_at(self.file.as_ref(), self.offset")
            && function_summaries
                .contains("merge_page_rows(runs.len(), BOUNDARY_PAIR_BYTES, BOUNDARY_READ_ROWS)")
            && !function_summaries.contains("clone call-boundary run spool")
            && idg.contains("file: Arc<std::fs::File>")
            && idg.contains("read_exact_at(self.file.as_ref(), self.offset")
            && idg.contains("merge_page_rows(")
            && !idg.contains("clone symbolic transform run spool"),
        "external sort mergers must share one positioned spool descriptor and one bounded page budget instead of scaling descriptors or buffers per run"
    );
    assert!(
        !execution.contains("may_forward_target_nodes_cut_within_funcs_with_max_precision"),
        "security scheduling must compile target demand once rather than rebuilding a forward closure per source"
    );
    let semantic_compile = function_body(&execution, "compile_taint_semantic_graph");
    assert!(
        semantic_compile.contains("seed_idg_service_for_rulepack_for_files")
            && semantic_compile.contains("building persisted scoped semantic graph"),
        "security must compile one reusable scoped IDG rather than rebuilding source/sink slices"
    );
    let scoped_seed = function_body(&security_analysis, "seed_idg_service_for_rulepack_for_files");
    assert!(
        scoped_seed
            .contains("build_and_seed_persisted_idg_service_with_transfer_options_for_files_and_call_graph"),
        "security transfer options must enter the persisted scoped compiler path"
    );
    let persisted_scope = function_body(
        &workspace,
        "build_and_seed_persisted_idg_service_with_transfer_options_for_files_and_call_graph",
    );
    assert!(
        persisted_scope.contains("idg_file_scope_fingerprint(included_files)")
            && persisted_scope.contains("idg_func_scope_fingerprint(included_funcs)")
            && persisted_scope.contains("idg_call_graph_fingerprint(call_graph)")
            && persisted_scope.contains("idg_scoped_semantics_fingerprint(")
            && persisted_scope.contains(
                "build_for_persistence_streaming_with_file_semantics_and_options_for_files_and_funcs"
            )
            && persisted_scope.contains("workspace.save_into_disk")
            && persisted_scope.contains("IdgQueryService::load_from_disk"),
        "large scoped IDGs must lower once into an exact keyed sidecar and reopen through the paged query service"
    );
    assert!(
        !execution.contains("execute_partitioned_source_groups")
            && !execution.contains("memory_scheduled_source_corridors"),
        "security must not regress to repeated per-source IDG compilation"
    );
    for function in ["source_analysis_worker_count", "security_taint_worker_count"] {
        let body = function_body(&execution, function);
        assert!(
            body.contains("compiler_worker_count(requested)")
                && body.contains(".min(available)"),
            "{function} must schedule every exact closure under the shared memory budget without oversubscribing CPUs"
        );
    }
    let source_plan = function_body(&execution, "plan_source_work");
    assert!(
        source_plan.contains("exact_decl_index_shared(file)")
            && source_plan.contains("source_seed_set(pack, source.source, source_decl)"),
        "taint source seed planning must derive carriers from exact AST bodies, not compact headers"
    );
    let analysis = read(&repo_root().join("crates/security/src/analysis/mod.rs"));
    assert!(
        function_body(&analysis, "begin_dependency_package_snapshot")
            .contains("begin_workspace_dependency_package_snapshot("),
        "the shared analysis snapshot helper must open one immutable workspace dependency snapshot"
    );
    for function in [
        "run_taint_analysis_with_phase_progress",
        "run_source_analysis_with_phase_progress",
        "source_inventory_with_progress",
        "sink_inventory_with_progress",
        "sanitizer_inventory_with_progress",
    ] {
        assert!(
            function_body(&analysis, function).contains("begin_dependency_package_snapshot(ws, pack)"),
            "{function} must retain one immutable dependency-manifest snapshot for the complete analysis"
        );
    }
    let source_graph_plan = function_body(&analysis, "schedule_source_graph_groups");
    assert!(
        source_graph_plan.contains("exact_decl_index_shared(file)")
            && source_graph_plan.contains("source_seed_set(pack, hit.hit, decl)"),
        "source-analysis seed planning must derive carriers from exact AST bodies, not compact headers"
    );

    let package_facts = function_body(&matcher, "build_file_package_set");
    let broad_match = function_body(&matcher, "match_rules_against_facts_with_progress_and_mode");
    assert!(
        package_facts.contains("insert_file_import_packages")
            && package_facts.contains("workspace_imports")
            && package_facts.contains("workspace_packages")
            && !package_facts.contains("decl_index")
            && !package_facts.contains("global_index()"),
        "framework package evidence must come from compiler imports/dependencies, not path or identifier guesses"
    );
    assert!(
        broad_match.contains("workspace_dependency_package_scan_lock(&root)")
            && broad_match.contains("workspace_dependency_package_context_for_scan(")
            && !dependencies.contains("refresh_workspace_dependency_package_context")
            && function_body(&dependencies, "begin_workspace_dependency_package_snapshot")
                .contains("build_workspace_dependency_package_context(root, &pack.metadata)"),
        "broad matcher phases must reuse the analysis-owned immutable, rulepack-derived dependency snapshot"
    );
    for forbidden in [
        "allows_without_package",
        "routed_controller_request_context",
        "FILE_USES_REQ_FILES_MARKER",
    ] {
        assert!(
            !matcher.contains(forbidden),
            "security matcher must not hardcode framework inference hook `{forbidden}`"
        );
    }

    assert_eq!(
        matcher.matches(".global_index()").count(),
        1,
        "security matcher may use the resident whole-workspace body index only in its explicit cached mode"
    );
}

#[test]
fn security_and_export_idg_consumers_never_materialize_workspace_bodies() {
    let workspace = read(&repo_root().join("crates/workspace/src/lib.rs"));
    let matcher = read(&repo_root().join("crates/security/src/matcher/mod.rs"));
    let security_chain = read(&repo_root().join("crates/security/src/analysis/chain_executor.rs"));
    let security_analysis = read(&repo_root().join("crates/security/src/analysis/mod.rs"));
    for function in [
        "build_and_seed_idg_service_with_transfer_options",
        "build_and_seed_idg_service_with_transfer_options_for_files",
        "build_idg_service_with_transfer_options_for_files_and_call_graph",
    ] {
        let body = function_body(&workspace, function);
        assert!(
            body.contains("compiler_linkage_index()")
                && body.contains("build_streaming_with_file_semantics_and_options")
                && body.contains("decl_index_remapped_to_headers")
                && !body.contains("global_index()"),
            "{function} must pair compact compiler linkage with disposable exact Tree-sitter bodies"
        );
    }

    for path in [
        "crates/browse/src/native_export.rs",
        "crates/browse/src/graph_export.rs",
    ] {
        let source = read(&repo_root().join(path));
        assert!(
            source.contains("exact_decl_index_shared(") && !source.contains("global_index()"),
            "{path} must stream exact AST facts through the memory-scheduled body cache without materializing every workspace body"
        );
    }
    let exact_body_headers = function_body(&workspace, "compiler_index_for_exact_bodies");
    assert!(
        exact_body_headers.contains("idg_service()")
            && exact_body_headers.contains("global_linkage_index()")
            && !exact_body_headers.contains("global_index()"),
        "exact-body export beside an open IDG must reuse the graph's compact linkage generation"
    );

    let exact_body_cache = read(&repo_root().join("crates/workspace/src/exact_body_cache.rs"));
    assert!(
        exact_body_cache.contains("effective_memory_limit_bytes()")
            && exact_body_cache.contains("estimated_bytes")
            && exact_body_cache.contains("LruCache")
            && exact_body_cache.contains("pop_lru()")
            && !exact_body_cache.contains("language_id")
            && !exact_body_cache.contains("match language"),
        "the exact-body cache must be byte-weighted, memory-aware, evictable, and language-agnostic"
    );
    assert!(
        matcher.contains("matcher_fact_cache_total_budget_bytes")
            && matcher.contains("effective_memory_limit_bytes()")
            && matcher.contains("MatcherFactCache")
            && matcher.contains("pop_lru()")
            && !matcher.contains("MATCHER_FILE_FACT_CACHE_CAP"),
        "derived matcher-fact caches must be byte-weighted, memory-aware, single-flight, and evictable"
    );
    let endpoint_recheck = function_body(&matcher, "rule_match_passes_constraints_with_taint_view");
    let taint_only_proof = function_body(&matcher, "endpoint_taint_constraints_pass_without_syntax");
    assert!(
        endpoint_recheck.contains("endpoint_taint_constraints_pass_without_syntax")
            && taint_only_proof.contains("!endpoint_identity_proven")
            && taint_only_proof.contains("spans_overlap(call.call_span, expected.span)")
            && taint_only_proof.contains("arg.index == index")
            && taint_only_proof.contains("call.tainted_receiver.is_none()")
            && !taint_only_proof.contains("file_package_set")
            && !taint_only_proof.contains("decl_match_facts"),
        "source-specific endpoint checks must reuse the initial static compiler proof instead of reparsing AST/package facts per flow"
    );
    let source_group_execute = function_body(&security_chain, "execute");
    let unique_overlap = function_body(&security_chain, "unique_named_overlap_span");
    assert!(
        source_group_execute.contains("unique_named_overlap_span")
            && source_group_execute.contains("endpoint_identity_proven"),
        "source attribution must carry a compiler-proven endpoint identity into taint-only constraint checks"
    );
    assert!(
        unique_overlap.contains("sink.match_text != call.name")
            && unique_overlap.contains("span != sink.span")
            && unique_overlap.contains("return None"),
        "overlapping adapter spans may reuse endpoint proofs only when the exact candidate identity is unique"
    );
    let evidence_kind = function_body(&security_chain, "tainted_call_kind_matches_sink");
    let candidate_validation = function_body(&security_chain, "sink_candidate_is_valid");
    assert!(
        evidence_kind.contains("MatchKind::Call | MatchKind::New")
            && evidence_kind.contains("TaintedCallKind::Call")
            && evidence_kind.contains("MatchKind::Write")
            && evidence_kind.contains("TaintedCallKind::Write")
            && evidence_kind.contains("MatchKind::Return")
            && evidence_kind.contains("TaintedCallKind::Return")
            && candidate_validation.contains("tainted_call_kind_matches_sink"),
        "sink attribution must join compiler evidence and rule endpoints by typed event kind before span correlation"
    );

    assert!(
        function_body(&security_chain, "compile_source_graph").contains("with_global_index(self.global.as_ref())")
            && function_body(&security_analysis, "build_source_group_candidates")
                .contains("with_global_index(context.global)"),
        "security taint closures must pass compact compiler linkage through the query boundary instead of reopening AnalyzerDb::global_index"
    );

    let taint_reachable = read(&repo_root().join("crates/taint/src/reachable.rs"));
    let compiler_object = read(&repo_root().join("crates/db/src/compiler_object.rs"));
    let attribution = function_body(&taint_reachable, "cached_function_attribution");
    let compiler_attribution = function_body(&compiler_object, "compiler_function_attribution_uncached");
    let attribution_load = function_body(&compiler_object, "load_function_attribution");
    assert!(
        attribution.contains("compiler_function_attribution_uncached(file, declaration.span)")
            && attribution.contains("build_function_call_event_summaries_from_attribution")
            && !attribution.contains("decl_index_remapped_to_headers")
            && attribution_load.contains("attribution_payload_range")
            && !attribution_load.contains("compressed_object_payload")
            && compiler_attribution.contains("load_attribution_index(&descriptor)")
            && compiler_attribution.contains("load_function_attribution")
            && compiler_attribution.contains("CompilerAttribution::from_decl_index"),
        "compact taint queries must range-decode one exact adapter attribution frame independently of sibling/full compiler bodies"
    );
    let distilled = function_body(&taint_reachable, "build_function_call_event_summaries");
    assert!(
        distilled.contains("collect_call_event_summaries")
            && distilled.contains("collect_return_spans")
            && distilled.contains("collect_write_event_summaries"),
        "the full-index compatibility path must preserve the same call/write/return evidence"
    );
    let attribution_cache = struct_body(&taint_reachable, "IdgAttributionCaches");
    let attribution_insert = function_body(&taint_reachable, "insert_attribution");
    assert!(
        attribution_cache.contains("budget_bytes")
            && attribution_cache.contains("AttributionCacheState")
            && taint_reachable.contains("LruCache")
            && attribution_insert.contains("estimated_function_call_event_summaries_bytes")
            && attribution_insert.contains("pop_lru()")
            && attribution_insert.contains("estimated_bytes > self.budget_bytes"),
        "shared compiler attribution must be byte-weighted and evictable; function counts are not a memory bound"
    );
    let taint_index = read(&repo_root().join("crates/workspace/src/taint_index.rs"));
    let resident_insert = function_body(&taint_index, "insert_resident");
    assert!(
        taint_index.contains("resident_budget_bytes")
            && taint_index.contains("resident_bytes")
            && resident_insert.contains("graph.estimated_resident_bytes()")
            && resident_insert.contains("estimated_bytes > inner.resident_budget_bytes")
            && resident_insert.contains("evict_oldest_resident(inner)"),
        "decoded source graphs must be retained by bytes; eviction may change reuse but never exact graph construction"
    );
}

#[test]
fn workspace_context_does_not_run_an_unneeded_compiler_pass() {
    let root = repo_root();
    let diagnostics = read(&root.join("crates/cli/src/commands/diagnostics.rs"));
    let body = function_body(&diagnostics, "cmd_context");
    assert!(
        body.contains("Workspace::new")
            && body.contains("semantic_context_for_root(root)")
            && !body.contains("open_workspace_syntax_only"),
        "context must derive metadata-only source paths without ingesting source contents"
    );
    assert!(
        !body.contains("open_project_parse_only")
            && !body.contains("global_index")
            && !body.contains(".ingest"),
        "context must not trigger declaration lowering or global semantic indexing"
    );
}

/// Receiver type enrichment must run after each adapter has finished
/// language-specific type_alias / base-class extraction. The DB cache
/// helper is the single shared indexing chokepoint used by cached
/// `decl_index`, large-repo uncached scans, inspect, trace,
/// source-analysis, security-analysis, export, and browse.
#[test]
fn db_applies_receiver_type_enrichment_centrally() {
    let root = repo_root();
    let db_lib = read(&root.join("crates/db/src/lib.rs"));
    let body = function_body(&db_lib, "build_decl_index_with_diagnostics");
    assert!(
        body.contains("adapter.extract_declarations(file, ctx)")
            && body.contains("apply_constructor_result_type_aliases")
            && body.contains("apply_expression_value_kinds")
            && body.contains("apply_assign_call_result_types")
            && body.contains("apply_call_receiver_types"),
        "AnalyzerDb::build_decl_index_with_diagnostics must centrally enrich FlowEvent::Call::receiver_types after adapter extraction"
    );

    let kit = read(&root.join("crates/lang_api/src/kit/mod.rs"));
    for function in [
        "extend_alias_map_with_flow_events",
        "proven_constructor_type_name",
        "resolved_declared_constructor_type",
        "collect_constructor_result_type_aliases_with_declared_types",
    ] {
        let body = function_body(&kit, function);
        assert!(
            !body.contains("is_ascii_uppercase") && !body.contains("is_ascii_lowercase"),
            "{function} must derive type facts from adapter call kinds and resolved declarations, not identifier casing"
        );
    }

    let python = read(&root.join("crates/lang_python/src/lib.rs"));
    assert!(
        !python.contains("constructor_type_from_call_name")
            && !python.contains("collect_constructor_result_type_aliases(&decl.flow_events"),
        "Python must use the central AST/declaration-driven constructor typing pass instead of an adapter-local name heuristic"
    );
}

/// Receiver syntax belongs to each tree-sitter adapter. An empty capability
/// is a closed "none" claim, not permission for a language-neutral layer to
/// inject spellings borrowed from unrelated grammars.
#[test]
fn receiver_token_capabilities_are_explicit_and_adapter_owned() {
    let root = repo_root();
    let capabilities = read(&root.join("crates/lang_api/src/capabilities.rs"));
    for (function, field) in [
        ("effective_super_receiver_tokens", "self.super_receiver_tokens"),
        (
            "effective_implicit_receiver_tokens",
            "self.implicit_receiver_tokens",
        ),
    ] {
        let body = function_body(&capabilities, function);
        assert!(
            body.contains(field) && !body.contains("bonsai_common::") && !body.contains("if self."),
            "LanguageCapabilities::{function} must return the adapter declaration directly without a global fallback"
        );
    }
    assert!(
        !capabilities.contains("NO_SUPER_RECEIVER_TOKENS"),
        "empty super_receiver_tokens now means none; a sentinel would reintroduce a second empty-state encoding"
    );

    let crates = root.join("crates");
    let mut violations = Vec::new();
    for entry in fs::read_dir(&crates).unwrap_or_else(|error| panic!("read {}: {error}", crates.display())) {
        let entry = entry.expect("read crate entry");
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("lang_") || name == "lang_api" {
            continue;
        }
        let lib_path = entry.path().join("src/lib.rs");
        if !lib_path.exists() {
            continue;
        }
        let source = read(&lib_path);
        let body = function_body(&source, "capabilities");
        if !body.contains("super_receiver_tokens:") || !body.contains("implicit_receiver_tokens:") {
            violations.push(format!(
                "{}: capabilities() must explicitly declare both receiver-token slices",
                lib_path.display()
            ));
        }
        if body.contains("NO_SUPER_RECEIVER_TOKENS") {
            violations.push(format!(
                "{}: empty super syntax must be written as &[]",
                lib_path.display()
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "receiver-token capability boundary violations:\n  {}",
        violations.join("\n  ")
    );
}

/// Every adapter that backs a typed language must populate
/// `Decl.type_aliases` for typed parameters. The matcher's
/// `attribute: [Type, method]` resolution depends on this fact —
/// adapters that ship without it silently drop receiver-narrowing
/// across the entire ecosystem (canonical regression: Python /
/// Dart / Go / ObjC ran for months with empty type_aliases until
/// the 2026-05 audit caught it). Each typed lang is exercised
/// through its real adapter on an inline fixture so the test
/// catches future adapter additions that forget the helper.
#[test]
fn typed_lang_adapters_emit_decl_type_aliases() {
    use bonsai_workspace::Workspace;
    use std::collections::BTreeMap;
    // Per-lang fixture: language id, file extension, source carrying
    // a parameter with a typed annotation that the adapter MUST
    // record as a TypeAliasBinding (`name → Type`).
    let cases: &[(&str, &str, &str)] = &[
        ("c", "fixture.c", "void handle(int code, char *name) {}\n"),
        (
            "cpp",
            "fixture.cpp",
            "void handle(int code, std::string name) {}\n",
        ),
        ("csharp", "F.cs", "class App { void Handle(string name) {} }\n"),
        ("dart", "f.dart", "class App { void handle(String name) {} }\n"),
        ("go", "f.go", "package main\nfunc Handle(name string) {}\n"),
        ("java", "App.java", "class App { void handle(String name) {} }\n"),
        ("kotlin", "f.kt", "fun handle(name: String) {}\n"),
        ("objc", "f.m", "void handle(NSString *name) {}\n"),
        ("php", "f.php", "<?php\nfunction handle(string $name) {}\n"),
        ("python", "f.py", "def handle(name: str) -> None:\n    pass\n"),
        ("rust", "f.rs", "fn handle(name: String) {}\n"),
        (
            "scala",
            "F.scala",
            "object F { def handle(name: String): Unit = () }\n",
        ),
        ("swift", "f.swift", "func handle(name: String) {}\n"),
        ("typescript", "f.ts", "function handle(name: string) {}\n"),
    ];
    let mut violations: BTreeMap<&str, String> = BTreeMap::new();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    for (lang, file, src) in cases.iter().copied() {
        let ws_dir = std::env::temp_dir().join(format!("bonsai-conf-typealiases-{lang}-{stamp}"));
        let _ = std::fs::remove_dir_all(&ws_dir);
        std::fs::create_dir_all(&ws_dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", ws_dir.display()));
        let path = ws_dir.join(file);
        std::fs::write(&path, src).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        let ws = Workspace::open_query(&ws_dir, bonsai_adapters::all_languages_registry())
            .unwrap_or_else(|e| panic!("open {}: {e}", ws_dir.display()));
        let mut found_type_alias = false;
        for f in ws.db().global_index().all_files() {
            for d in ws.db().global_index().decls_in(f) {
                if !d.type_aliases.is_empty() {
                    found_type_alias = true;
                    break;
                }
            }
            if found_type_alias {
                break;
            }
        }
        if !found_type_alias {
            violations.insert(
                lang,
                format!("{lang}: typed-param fixture {file:?} produced no Decl.type_aliases"),
            );
        }
        let _ = std::fs::remove_dir_all(&ws_dir);
    }
    assert!(
        violations.is_empty(),
        "adapters missing Decl.type_aliases extraction:\n{}",
        violations.values().cloned().collect::<Vec<_>>().join("\n")
    );
}

/// Syntax indexing is a compiler frontend pass: its default parallelism comes
/// from the host, not from arbitrary repository-size bands. File-count gates
/// made the same AST workload substantially slower as soon as a project crossed
/// a threshold and are particularly harmful on large monorepos.
#[test]
fn syntax_index_parallelism_is_not_project_size_capped() {
    let root = repo_root();
    let workspace = read(&root.join("crates/workspace/src/lib.rs"));
    let database = read(&root.join("crates/db/src/lib.rs"));
    let security_matcher = read(&root.join("crates/security/src/matcher/mod.rs"));
    let security_analysis = security_analysis_source(&root);

    for (source, function) in [
        (&workspace, "workspace_parse_worker_count"),
        (&database, "global_index_cpu_workers"),
        (&security_matcher, "matcher_worker_count"),
        (&security_analysis, "source_analysis_worker_count"),
        (&security_analysis, "security_taint_worker_count"),
    ] {
        let body = function_body(source, function);
        assert!(
            body.contains("available_parallelism"),
            "{function} must derive default syntax-index parallelism from the host"
        );
        assert!(
            !body.contains("file_count") && !body.contains("files.len()"),
            "{function} must not select workers from project size"
        );
        assert!(
            !body.contains(".clamp("),
            "{function} must honor an explicit worker override without a hidden ceiling"
        );
    }

    let retention = function_body(&database, "should_consume_decl_index_cache_for_global");
    assert!(
        !retention.contains("file_count") && !retention.contains("files.len()"),
        "global-index IR retention must not change at a project-size threshold"
    );
}

/// Security match semantics must consume the compiler IR emitted by language
/// adapters. Rendered expression text remains useful for diagnostics and
/// rule-owned literal/regex constraints, but it must never be reparsed to
/// rediscover calls, value reads, or runtime type guards.
#[test]
fn security_matcher_uses_compiler_expression_facts() {
    let root = repo_root();
    let matcher = read(&root.join("crates/security/src/matcher/mod.rs"));
    let language_types = read(&root.join("crates/lang_api/src/types.rs"));
    let language_kit = read(&root.join("crates/lang_api/src/kit/mod.rs"));
    let runtime_type_lowering = read(&root.join("crates/lang_api/src/kit/runtime_types.rs"));

    for retired_parser in [
        "fn final_call_callee",
        "fn receiver_call_with_args",
        "fn split_balanced_args",
        "fn split_read_token",
        "fn parse_type_test",
        "fn looks_like_type_anchor",
    ] {
        assert!(
            !matcher.contains(retired_parser),
            "security matcher must not restore rendered-expression parser `{retired_parser}`"
        );
    }

    let reads = function_body(&matcher, "collect_flow_read_sites");
    assert!(
        reads.contains("value_flow")
            && reads.contains("call_receiver_fact_for_span")
            && !reads.contains("value_text"),
        "flow-read identity must come from ExpressionFlow and call-receiver facts"
    );
    let factories = function_body(&matcher, "synth_factory_type_aliases");
    assert!(
        factories.contains("assignment_value_fact_for_span")
            && factories.contains("direct_call_name")
            && !factories.contains("rendering"),
        "factory typing must use the AST-selected assignment call fact"
    );
    let runtime_types = function_body(&matcher, "collect_runtime_type_narrowings");
    assert!(
        runtime_types.contains("fact.branch_span") && runtime_types.contains("fact.guarded_span"),
        "runtime type constraints must consume compiler guard facts"
    );
    assert!(
        language_types.contains("pub struct RuntimeTypeNarrowingFact")
            && language_types.contains("pub direct_call_name: Option<String>")
            && language_kit.contains("pub use runtime_types::extract_runtime_type_narrowing_facts")
            && runtime_type_lowering.contains("fn extract_runtime_type_narrowing_facts")
            && runtime_type_lowering.contains("handler.is_string_literal(type_node.kind())")
            && runtime_type_lowering.contains("handler.runtime_type_wrapper_kinds")
            && !runtime_type_lowering
                .contains("\"string\" | \"string_literal\" | \"interpreted_string_literal\""),
        "language IR must retain direct-call and runtime-guard relationships"
    );
}

/// Clean-overwrite suppression is security-sensitive and must fail closed.
/// Literal value identity comes from the active adapter's AST lowering, never
/// rendered source or a naming convention.
#[test]
fn clean_overwrite_uses_adapter_value_facts() {
    let root = repo_root();
    let source = read(&root.join("crates/security/src/analysis/clean_overwrite.rs"));
    let language_kit = read(&root.join("crates/lang_api/src/kit/mod.rs"));
    let language_types = read(&root.join("crates/lang_api/src/types.rs"));

    for retired_heuristic in [
        "fn looks_like_clean_constant",
        "fn clean_constant_assignment",
        "fn quoted_literal",
        "fn numeric_literal",
    ] {
        assert!(
            !source.contains(retired_heuristic),
            "clean-overwrite must not restore rendered-value heuristic `{retired_heuristic}`"
        );
    }

    let body = function_body(&source, "clean_output_call_overwrites_target");
    let argument = function_body(&source, "clean_output_overwrite_arg_is_clean");
    assert!(
        body.contains("output") && body.contains(".place") && !body.contains("value_text"),
        "clean output targets must use adapter-lowered places"
    );
    assert!(
        argument.contains("call_argument_value_fact")
            && argument.contains("value_kind")
            && argument.contains("static_value")
            && !argument.contains("value_text"),
        "clean output writes must be proven from adapter-lowered argument facts"
    );
    let fallback_classifier = function_body(&language_kit, "classify_flow_value_kinds");
    assert!(
        fallback_classifier.contains("AssignValueKind::Unknown")
            && !fallback_classifier.contains("AssignValueKind::Literal"),
        "missing carriers must remain unknown; only an adapter AST classifier may prove a literal"
    );
    assert!(
        language_types.contains("value_kind: Option<AssignValueKind>")
            && source.contains("Some(AssignValueKind::Literal)"),
        "return clean-value proofs must consume adapter-owned expression value shape"
    );
}

/// Library/API identities belong to rulepack semantics. Structured security
/// proofs may interpret compiler call/assignment/branch facts, but must not
/// select behavior from API spellings embedded in engine source.
#[test]
fn structured_security_guards_are_rulepack_driven() {
    let root = repo_root();
    let analysis = security_analysis_source(&root);
    let guards = read(&root.join("crates/security/src/analysis/guard_sanitizers.rs"));
    // Adapter/rulepack integration fixtures intentionally contain concrete API
    // spellings. The architecture invariant applies to production analysis,
    // not to test source that proves the generic machinery against real syntax.
    let guards_runtime = guards.split("#[cfg(test)]").next().unwrap_or(&guards);
    let rules = read(&root.join("crates/security/src/rule.rs"));
    let path_pack = read(&root.join("security-patterns/langs/python/sinks/path.yml"));
    let xxe_pack = read(&root.join("security-patterns/langs/python/sinks/xxe.yml"));
    let language_types = read(&root.join("crates/lang_api/src/types.rs"));
    let language_kit = read(&root.join("crates/lang_api/src/kit/mod.rs"));
    let ruby = read(&root.join("crates/lang_ruby/src/lib.rs"));
    let native_export = read(&root.join("crates/browse/src/native_export.rs"));
    let metadata = read(&root.join("security-patterns/metadata.yml"));
    let assignment_lowering = read(&root.join("crates/lang_api/src/kit/walker/assignment.rs"));
    let prototype_guard = read(&root.join("crates/security/src/analysis/prototype_guard.rs"));
    let idg_transfer = read(&root.join("crates/idg/src/transfer.rs"));

    for spelling in ["os.path.join", "realpath", "setLocation"] {
        assert!(
            !analysis.contains(spelling) && !guards_runtime.contains(spelling),
            "security analysis must obtain `{spelling}` roles from rulepack semantics"
        );
    }
    assert!(
        !analysis.contains("newdocumentbuilder")
            && metadata.contains("receiver_factory_lineage_builders:")
            && metadata.contains("name: newDocumentBuilder"),
        "factory-to-builder API identity must be rulepack metadata, never shared analysis policy"
    );
    assert!(
        !assignment_lowering.contains("__setitem__")
            && !prototype_guard.contains("__setitem__")
            && assignment_lowering.contains("CallKind::IndexWrite")
            && prototype_guard.contains("CallKind::IndexWrite"),
        "indexed writes must remain typed compiler operations, not provider pseudo-callees"
    );
    assert!(
        !language_kit.contains("trpc.input")
            && !language_kit.contains("@trpc/server")
            && !root.join("crates/lang_api/src/kit/imports.rs").exists(),
        "framework callback sources and import syntax must stay in rule data and concrete adapters"
    );

    let receiver_flow = function_body(&analysis, "guarded_variable_flows_into_receiver_before_sink");
    assert!(
        receiver_flow.contains("receiver_mutation_targets")
            && receiver_flow.contains("rule_target_matches_call"),
        "receiver mutation proofs must consume taint_receiver_from_args rule targets"
    );
    assert!(
        analysis.contains("fn compiled_receiver_state_propagations_for_languages")
            && analysis.contains("match_rules_against_facts_for_sink_inventory_with_progress_on_files",)
            && analysis.contains("propagation.resolved_call_sites"),
        "rulepack-only receiver typing must compile complete matcher proofs to exact AST call sites"
    );
    let transfer_fingerprint = function_body(&idg_transfer, "semantic_fingerprint");
    let receiver_transfer = function_body(&idg_transfer, "apply_receiver_state_propagation_call");
    assert!(
        transfer_fingerprint.contains("spec.resolved_call_sites")
            && receiver_transfer.contains("shape.resolved_call_sites.binary_search(&span)"),
        "IDG receiver transfer must consume exact typed sites and include them in graph identity"
    );
    let path_guard = function_body(guards_runtime, "path_containment_guard_sanitizer");
    assert!(
        path_guard.contains("GuardProfile::CanonicalPathContainment")
            && path_guard.contains("path_containment_guard"),
        "path containment must be selected by typed analysis semantics"
    );
    assert!(
        rules.contains("pub struct PathContainmentGuardSemantics")
            && path_pack.contains("guard_profile: python-path-containment")
            && path_pack.contains("path_containment_guard:"),
        "callable roles for path containment must be declared in the rule schema and rulepack"
    );
    let condition_proof = function_body(guards_runtime, "path_containment_guard_condition");
    assert!(
        condition_proof.contains("branch_condition_fact_for_span")
            && condition_proof.contains("BranchConditionPolarity::Negated")
            && !condition_proof.contains("compact_guard_text")
            && !condition_proof.contains("branch.condition"),
        "path containment polarity must come from Tree-sitter condition facts, not rendered text"
    );
    assert!(
        language_types.contains("pub struct BranchConditionFact")
            && language_kit.contains("extract_branch_condition_facts(tree, file, handler, src)")
            && ruby.contains("extract_branch_condition_facts(&tree")
            && native_export.contains("branch_conditions: index.branch_conditions.clone()"),
        "branch-condition compiler facts must be emitted by shared/custom frontend paths and preserved by export"
    );
    for spelling in ["XMLParser", "resolve_entities", "no_network"] {
        assert!(
            !guards.contains(spelling) && xxe_pack.contains(spelling),
            "configured factory role `{spelling}` must remain rulepack data"
        );
    }
    let configured_factory = function_body(&guards, "configured_argument_factory_guard_sanitizer");
    assert!(
        configured_factory.contains("assignment_values")
            && configured_factory.contains("call_argument_value_fact")
            && configured_factory.contains("static_value")
            && !configured_factory.contains("value_text"),
        "configured factory guards must consume typed assignment and scalar argument facts"
    );
    assert!(
        rules.contains("pub struct ConfiguredArgumentFactoryGuardSemantics")
            && xxe_pack.contains("configured_argument_factory_guard:"),
        "configured argument factory roles must be declared in the rule schema and rulepack"
    );
}

#[test]
fn python_parameter_default_calls_are_api_neutral_compiler_facts() {
    let root = repo_root();
    let adapter_source = read(&root.join("crates/lang_python/src/lib.rs"));
    let adapter = production_source(&adapter_source);
    for forbidden in [
        "FASTAPI_BINDER_MARKERS",
        "python_binder_call_marker",
        "merge_python_param_binder_annotations",
    ] {
        assert!(
            !adapter.contains(forbidden),
            "Python lowering must not interpret framework parameter binders through `{forbidden}`"
        );
    }
    assert!(
        adapter.contains("collect_python_param_default_calls") && adapter.contains("param_default_calls"),
        "Python must lower direct parameter-default calls as generic compiler facts"
    );

    let rule_schema = read(&root.join("crates/security/src/rule.rs"));
    let python_sources = format!(
        "{}\n{}",
        read(&root.join("security-patterns/langs/python/sources/web_extra.yml")),
        read(&root.join("security-patterns/langs/python/sources/remote.yml"))
    );
    assert!(
        rule_schema.contains("pub default_call: Option<String>")
            && python_sources.contains("default_call: Body")
            && python_sources.contains("default_call: Query")
            && python_sources.contains("default_call: Depends"),
        "framework binder identities must be declared by rulepack default_call selectors"
    );
}

/// The unified taint engine is compiler dataflow over the IDG. Semantic
/// closure must run to a fixed point with no breadth/depth/iteration budget;
/// bounded traversal belongs only to explicit diagnostic rendering APIs.
#[test]
fn unified_taint_closure_is_uncapped_compiler_dataflow() {
    let root = repo_root();
    let idg_query = read(&root.join("crates/idg/src/query.rs"));
    let idg_service = read(&root.join("crates/idg/src/service.rs"));
    let idg_spill = read(&root.join("crates/idg/src/spill_set.rs"));
    let taint_idg_api = read(&root.join("crates/taint/src/idg_api.rs"));

    for function in [
        "bitvector_closure",
        "bitvector_closure_within",
        "sparse_closure_nodes",
        "sparse_closure_nodes_within",
    ] {
        let body = function_body(&idg_query, function);
        assert!(
            body.contains("pending.pop()") && body.contains("reached"),
            "{function} must remain a sparse monotone stack fixed point"
        );
        for forbidden in [
            "VecDeque",
            "pop_front",
            "max_depth",
            "max_len",
            "max_paths",
            "k_hops",
            "iteration_limit",
            "round_limit",
        ] {
            assert!(
                !body.contains(forbidden),
                "semantic closure {function} must not contain `{forbidden}`"
            );
        }
    }

    for function in ["forward_closure", "backward_closure"] {
        let body = function_body(&idg_query, function);
        assert!(
            body.contains("bitvector_closure") && !body.contains("bitvector_bounded_closure"),
            "{function} must use the uncapped fixed-point kernel"
        );
    }
    assert!(
        function_body(&idg_query, "forward_neighbourhood").contains("bitvector_bounded_closure")
            && function_body(&idg_query, "backward_neighbourhood").contains("bitvector_bounded_closure"),
        "hop-bounded closure must remain isolated to explicit neighbourhood diagnostics"
    );
    let symbolic_closure = function_body(&idg_service, "symbolic_forward_closure_nodes");
    assert!(
        symbolic_closure.contains("while worklist.has_pending()")
            && symbolic_closure.contains("worklist.next_node()")
            && symbolic_closure.contains("worklist.next_fact()"),
        "symbolic/contextual closure must remain a monotone compiler fixed point"
    );
    for forbidden in [
        "VecDeque",
        "pop_front",
        "max_depth",
        "max_len",
        "max_paths",
        "iteration_limit",
        "round_limit",
    ] {
        assert!(
            !symbolic_closure.contains(forbidden),
            "symbolic semantic closure must not contain `{forbidden}`"
        );
    }
    assert!(
        idg_service.contains("facts: SpillSet")
            && idg_service.contains("states: SpillSet")
            && idg_service.contains("pending_nodes: SpillStack")
            && idg_service.contains("pending_facts: SpillStack")
            && {
                let worklist_impl = idg_service
                    .split_once("impl<'a> SymbolicClosureWorklist<'a>")
                    .map(|(_, implementation)| implementation)
                    .expect("missing SymbolicClosureWorklist implementation");
                function_body(worklist_impl, "enqueue_fact_state").contains("self.facts.insert(key)")
                    && function_body(worklist_impl, "enqueue_node")
                        .contains("self.reached.insert(node, context)")
            }
            && !idg_service.contains("fact_interner"),
        "exact symbolic closure node/fact states and frontiers must use external-memory compiler relations, not unbounded resident collections"
    );
    assert!(
        idg_service.contains("let mut cross_calls = AHashSet::new()")
            && function_body(&idg_service, "record_symbolic_cross_call")
                .contains("out.insert(CrossCallEdge"),
        "symbolic cross-call evidence must deduplicate when a transform fires, not retain one duplicate row per field/context state"
    );
    let context_replay = function_body(&idg_service, "register_context_call");
    assert!(
        context_replay.contains("loop")
            && context_replay.contains("returned_fact_batch(context, after)")
            && context_replay.contains("after = Some(")
            && idg_spill.contains("fn keys_with_prefix_batch("),
        "completed call summaries must replay through an exhaustive cursor, not one workspace-sized resident vector"
    );
    let recent_positives = struct_body(&idg_spill, "RecentPositiveCache");
    let recent_positive_impl = idg_spill
        .split_once("impl RecentPositiveCache")
        .map(|(_, implementation)| implementation)
        .expect("missing RecentPositiveCache implementation");
    let spill_set_impl = idg_spill
        .split_once("impl SpillSet")
        .map(|(_, implementation)| implementation)
        .expect("missing SpillSet implementation");
    let spill_insert = function_body(spill_set_impl, "insert");
    let spill_contains = function_body(spill_set_impl, "contains");
    let spill_flush = function_body(spill_set_impl, "flush");
    let spill_new = function_body(spill_set_impl, "new");
    assert!(
        recent_positives.contains("keys: Box<[u128]>")
            && recent_positives.contains("metadata: Box<[AtomicU8]>")
            && recent_positives.contains("hands: Box<[u8]>")
            && recent_positives.contains("set_count: usize")
            && recent_positives.contains("len: usize")
            && struct_body(&idg_spill, "SpillSet")
                .contains("recent_positives: RwLock<Option<RecentPositiveCache>>")
            && struct_body(&idg_spill, "SpillSet")
                .contains("recent_positive_budget_bytes: usize")
            && idg_spill.contains("RECENT_POSITIVE_ASSOCIATIVITY")
            && idg_spill.contains("RECENT_POSITIVE_SET_BYTES")
            && !recent_positives.contains("AHashMap")
            && spill_insert.contains(".as_ref()")
            && spill_insert.contains("cache.contains(key)")
            && spill_insert.contains("contains_in_runs(key)")
            && spill_insert.contains(".remember_absent(key)")
            && function_body(recent_positive_impl, "remember_absent")
                .contains("let set = self.set_index(key)"),
        "external fixed-point sets may use a compact memory-budget-derived cache of proven positives, but eviction must fall back to exact sorted-run membership"
    );
    assert!(
        spill_contains.contains("let cache = self.recent_positives.read()")
            && spill_contains.contains("cache.contains(key)")
            && spill_contains.contains("contains_in_runs(key)")
            && spill_contains.contains(".write()")
            && spill_contains.contains(".remember(key)")
            && function_body(recent_positive_impl, "contains")
                .contains("fetch_or(")
            && function_body(recent_positive_impl, "remember_absent")
                .contains("swap(RECENT_POSITIVE_OCCUPIED, Ordering::Relaxed)"),
        "read-only external-set membership must learn proven positives and refresh set-local CLOCK references through a bounded thread-safe cache"
    );
    let spill_set = struct_body(&idg_spill, "SpillSet");
    let exact_runs = function_body(spill_set_impl, "contains_in_runs");
    let spill_stack = struct_body(&idg_spill, "SpillStack");
    let spill_stack_impl = idg_spill
        .split_once("impl SpillStack")
        .map(|(_, implementation)| implementation)
        .expect("missing SpillStack implementation");
    assert!(
        spill_set.contains("membership_filter: Option<BloomFilter>")
            && spill_set.contains("membership_filter_budget_bytes: usize")
            && spill_new.contains("resident: AHashSet::new()")
            && spill_new.contains("recent_positives: RwLock::new(None)")
            && spill_new.contains("membership_filter: None")
            && spill_flush.contains("get_or_insert_with")
            && spill_flush.contains("RecentPositiveCache::new")
            && spill_flush.contains("membership_filter.is_none()")
            && spill_flush.contains("filter.insert(key)")
            && spill_stack.contains("file: Option<File>")
            && function_body(spill_stack_impl, "new").contains("resident: Vec::new()")
            && function_body(spill_stack_impl, "new").contains("file: None")
            && function_body(spill_stack_impl, "flush").contains("get_or_insert_with")
            && exact_runs.contains("self.levels.is_empty()")
            && exact_runs.contains("!filter.may_contain(key)")
            && exact_runs.contains("run.contains(key)")
            && !struct_body(&idg_spill, "SortedRun").contains("BloomFilter"),
        "external fixed-point acceleration must stay lazy for resident-only closures, then use bounded filters and exact sorted-run verification after spill"
    );

    assert!(
        root.join("crates/taint/src/idg_api.rs").exists()
            && !root.join("crates/taint/src/inter.rs").exists()
            && !root.join("crates/taint/src/inter/mod.rs").exists()
            && !root.join("crates/taint/src/inter/tests.rs").exists(),
        "the canonical IDG API must not be confused with the retired interprocedural worklist"
    );
    let entry = function_body(&taint_idg_api, "interprocedural_taint");
    assert!(
        entry.contains("idg_backed_interprocedural_taint")
            && !entry.contains("worklist")
            && !entry.contains("VecDeque"),
        "the public interprocedural API must delegate directly to the IDG engine"
    );
}

/// Public and contributor documentation is part of the architecture contract:
/// stale scheduler flags or retired module paths would direct callers back to
/// an engine that no longer exists.
#[test]
fn taint_documentation_names_only_the_idg_api() {
    let root = repo_root();
    let documents = [
        "docs/cli-reference.mdx",
        "docs/contributing/adapter-contract.mdx",
        "docs/contributing/architecture.mdx",
        "docs/contributing/design-patterns.mdx",
        "docs/contributing/sdk.mdx",
        "docs/contributing/specification.mdx",
        "docs/contributing/taint-engine-spec.mdx",
    ];
    let forbidden = [
        "interprocedural_taint_to_completion_with_caches",
        "crates/taint/src/inter.rs",
        "`inter/summary.rs`",
        "source_bearing_functions",
        "intra_worklist_cap",
        "callback_invocation_methods",
        "--intra-worklist-cap",
        "--taint-budget",
        "--taint-intra-worklist-cap",
        "--taint-sanitizer",
    ];
    let mut violations = Vec::new();
    for relative in documents {
        let source = read(&root.join(relative));
        for &retired in &forbidden {
            if source.contains(retired) {
                violations.push(format!("{relative}: retired `{retired}`"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "taint documentation must describe the canonical IDG API:\n  {}",
        violations.join("\n  ")
    );

    let engine_spec = read(&root.join("docs/contributing/taint-engine-spec.mdx"));
    assert!(
        engine_spec.contains("`interprocedural_taint_with_caches`")
            && engine_spec.contains("`crates/taint/src/idg_api.rs`")
            && engine_spec
                .contains("no breadth-first name search, depth bound, iteration limit, or result cap"),
        "taint engine documentation must name the IDG cache facade and uncapped fixed-point contract"
    );
}

/// Hundreds of integration-test executables otherwise each link full DWARF
/// for the entire compiler stack. That is host work, not useful test
/// coverage, and caused clean workspace gates to take tens of minutes.
#[test]
fn workspace_test_profile_keeps_debug_link_graphs_disabled() {
    let cargo = read(&repo_root().join("Cargo.toml"));
    let profile = cargo
        .split_once("[profile.test]")
        .map(|(_, rest)| rest.split_once("\n[").map_or(rest, |(section, _)| section))
        .expect("workspace Cargo.toml must define [profile.test]");
    assert!(
        profile.lines().any(|line| line.trim() == "debug = 0"),
        "[profile.test] must keep debug = 0 so exhaustive workspace gates do not relink full DWARF graphs"
    );
}

#[test]
fn hardcoded_audit_refuses_destructive_output_paths() {
    let root = repo_root();
    let output = root
        .join("target")
        .join(format!("hardcoded-audit-safety-{}", std::process::id()));
    let sentinel = output.join("sentinel");
    fs::create_dir_all(&output).expect("create audit safety fixture");
    fs::write(&sentinel, "must survive").expect("write audit safety sentinel");

    let script = root.join("scripts/audit-hardcoded.sh");
    let extra_argument = Command::new("bash")
        .arg(&script)
        .arg("--check")
        .arg(&output)
        .arg("security-patterns")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run hardcoded audit with an extra argument");
    assert!(!extra_argument.success(), "extra arguments must be rejected");
    assert!(sentinel.exists(), "argument errors must not remove output data");

    let repository_output = Command::new("bash")
        .arg(&script)
        .arg("--check")
        .arg(&output)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run hardcoded audit with a repository output path");
    assert!(
        !repository_output.success(),
        "repository-local audit output must be rejected"
    );
    assert!(sentinel.exists(), "rejected output paths must remain untouched");

    fs::remove_dir_all(output).expect("remove audit safety fixture");
}

/// External framework callback signatures are rulepack knowledge. The Java
/// frontend may prove that an argument is a lambda or that a binding has a
/// functional-interface type, but it must not compile framework callback
/// parameter types into the adapter.
#[test]
fn external_callback_signatures_are_rulepack_owned() {
    let root = repo_root();
    let java = live_code(&read(&root.join("crates/lang_java/src/lib.rs")));
    for provider_type in [
        "RoutingContext",
        "ServerRequest",
        "DataFetchingEnvironment",
        "DataFetcher",
    ] {
        assert!(
            !java.contains(provider_type),
            "Java adapter must not hardcode external callback type `{provider_type}`"
        );
    }

    let rule = read(&root.join("crates/security/src/rule.rs"));
    let matcher = read(&root.join("crates/security/src/matcher/mod.rs"));
    let typing = read(&root.join("security-patterns/langs/java/typing/callback_params.yml"));
    assert!(
        rule.contains("callback_param_types")
            && rule.contains("callback_arg_index")
            && matcher.contains("synth_callback_param_type_aliases")
            && typing.contains("RoutingContext")
            && typing.contains("ServerRequest")
            && typing.contains("DataFetchingEnvironment"),
        "external callback signatures must flow from typing YAML through the generic matcher"
    );
}
