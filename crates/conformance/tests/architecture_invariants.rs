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
        lang: "solidity",
        file_suffix: "App.sol",
        module: "./Pipeline.sol",
        alias: Some("FlowPipeline"),
        // `import {Pipeline as FlowPipeline} from "./Pipeline.sol"`
        // is a renamed import — the unaliased symbol IS "Pipeline",
        // matching the TypeScript `{ persist as persistEnvelope }`
        // shape directly below.
        original_name: Some("Pipeline"),
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
        "solidity",
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
        "solidity",
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
        if path.extension().is_none_or(|x| x != "rs") {
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
    // the same 21-language registry via
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
                "crate `bonsai_cli` depends on `{dep}` ({})",
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
    // facade. CLI may stream bytes to stdout only.
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
}

#[test]
fn cli_read_file_and_tree_use_sdk_rulepack_attachment() {
    // docs/contributing/review-checklist.mdx B-9: read-file/tree may accept a --rules-dir flag,
    // but rulepack loading and attachment should be handled by the
    // shared SDK project-opening helper.
    let root = repo_root();
    let files = ["read_file.rs", "tree.rs"];
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
        "CLI read-file/tree must use SDK rulepack attachment instead of loading packs directly:\n  {}",
        violations.join("\n  ")
    );
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
            "decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER)",
            "fn extract_imports",
        ] {
            if !source.contains(required) {
                violations.push(format!("{name}: missing adapter-owned `{required}`"));
            }
        }
    }

    assert_eq!(checked, 21, "expected every bundled language compiler frontend");
    assert!(
        violations.is_empty(),
        "each lang_* crate must own its Tree-sitter syntax lowering:\n  {}",
        violations.join("\n  ")
    );
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
    let no_per_decl_syntax = ["lang_lua", "lang_solidity"];
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
            || body.contains("Visibility::Crate")
            || body.contains("with_fn_kinds_and_implicit_receivers");
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
            && closure_compiler_body.contains("symbolic_cross_calls")
            && cross_call_compiler_body
                .contains("cross_call_edges_in_reachable_nodes_filtered_with_max_precision")
            && cross_call_compiler_body.contains("is_renderable_call")
            && cross_call_compiler_body.contains("lineage_funcs"),
        "IDG call-record export used by source-analysis must preserve symbolic provenance, support target/lineage cuts and configured transfers, and never render projected heap state as a call"
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
            && cli_inspect.contains("inspect occurrence flow evidence capped by")
            && cli_inspect.contains("inspect decl flow evidence capped by")
            && cli_inspect.contains("inspect hit list capped by"),
        "inspect must expose top-level completeness metadata for capped hit/flow evidence"
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
    assert!(
        dump_edges_body.contains("PrecisionFilter::OverApproximate | PrecisionFilter::Unknown")
            && dump_edges_body.contains("semantic-only")
            && dump_edges_body.find("PrecisionFilter::OverApproximate | PrecisionFilter::Unknown")
                < dump_edges_body.find("open_project(root)?"),
        "dump-edges must reject diagnostic precision filters before opening/analyzing the workspace"
    );
    let security_taint_body = function_body(&cli_security, "cmd_flows");
    assert!(
        security_taint_body.contains("max_precision = Some(Precision::Narrowed)")
            && !security_taint_body.contains("SemanticPrecisionFilter")
            && !security_taint_body.contains("OverApproximate")
            && !security_taint_body.contains("Unknown"),
        "security taint-analysis must run one semantic taint precision mode without exposing diagnostic precision filters"
    );
    let export_callgraph_body = function_body(&native_export, "export_structural_callgraph_indices");
    assert!(
        export_callgraph_body.contains("edge.precision.is_semantic()"),
        "native export structural callgraph must emit semantic call edges only"
    );
    let export_taint_call_edges_body = function_body(&native_export, "export_taint_call_edge_indices");
    assert!(
        export_taint_call_edges_body.contains("edge.precision.is_semantic()"),
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
        dump_taint_body.contains("forward_closure_evidence_with_max_precision")
            && dump_taint_body.contains("symbolic_cross_calls")
            && dump_taint_body.contains("Some(SEMANTIC_FLOW_MAX_PRECISION)"),
        "dump-taint must compute its seed closure and symbolic provenance inside the semantic precision scope"
    );
    assert!(
        dump_taint_body.contains("cross_call_edges_in_reachable_nodes_with_max_precision")
            && dump_taint_body.contains("Some(SEMANTIC_FLOW_MAX_PRECISION)"),
        "dump-taint must filter cross-call evidence to semantic precision"
    );
    assert!(
        !dump_taint_body.contains("with_max_precision(&seed_nodes, None")
            && !dump_taint_body.contains("with_max_precision(\n            &seed_nodes,\n            None"),
        "dump-taint must not request unscoped diagnostic reachability"
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
    let chain_limits_body = function_body(&export_body, "bounded_materialization");
    assert!(
        chain_limits_body.contains("EXPORT_FLOW_CHAIN_MAX_CHAINS_PER_TARGET")
            && chain_limits_body.contains("EXPORT_FLOW_CHAIN_MAX_ENTRY_PROBES")
            && !export_body.contains("FlowIdLabelOptions::exhaustive")
            && !export_body.contains("EXPORT_COMPLETE_CHAIN_ENUMERATION_EDGE_LIMIT"),
        "native export must keep rendered path rows bounded and use graph compression for exact complete mode"
    );
    let main_body = read(&root.join("crates/cli/src/main.rs"));
    assert!(
        main_body.contains("(usize::MAX, usize::MAX, usize::MAX)") && !main_body.contains("usize::MAX / 16"),
        "inspect --all must pass uncapped max_flows/max_entry_probes/max_hits"
    );
    let chain_enumerator_body = read(&root.join("crates/callgraph/src/chains.rs"));
    assert!(
        chain_enumerator_body.contains("visited_budget = visited_budget.saturating_add(1)")
            && chain_enumerator_body.contains("max_probes.saturating_mul(16)"),
        "chain enumeration must safely support usize::MAX as the uncapped probe budget"
    );
    assert!(
        export_body.matches("let compressed_chains = complete_chains;").count() >= 2
            && export_body.contains("compressed_callgraph")
            && export_body.contains("flow_chains_mode")
            && export_body.contains("chains_mode")
            && export_body.contains("flow_id_labels_mode")
            && export_body.contains("!compressed_chains && truncated_targets == 0")
            && export_body.contains("!compressed_chains && truncated_functions == 0"),
        "native export complete mode must always use compressed semantic graph evidence and must not label omitted rows complete"
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
    let body = function_body(&inspect, "inspect_taint_flows");
    assert!(
        body.contains("SyntaxFlowQuery::new")
            && body.contains("ws.syntax_flow_graph")
            && body.contains("semantic_flow_stats.record_plan(&graph.plan)"),
        "inspect_taint_flows must ask the workspace syntax-flow facade for taint graphs and retain planner metadata"
    );
    assert!(
        inspect.contains("SyntaxFlowPlan")
            && inspect.contains("semantic_flow_backend_counts")
            && inspect.contains("semantic_flow_cache_hits")
            && inspect.contains("semantic_flow_fallback_reasons"),
        "inspect must surface syntax-flow planner backend/cache/fallback metadata"
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
        retrieval.contains("edge_indices: &[usize]") && collect.contains("candidate_terms(groups, \"edge\")"),
        "retrieval must derive semantic edge terms while processing one compiler unit"
    );
    assert!(
        build.contains("edge_indices.remove(file)")
            && build.contains("syntax_indexes_uncached(file)")
            && build.contains("release_global_index()")
            && build.contains("builder.push(doc)")
            && !build.contains("build_edge_candidate_groups")
            && !build.contains("db().global_index()"),
        "retrieval must consume and intern each exact per-file compiler unit instead of retaining a global declaration body or second callgraph projection"
    );
    assert!(
        batch_width.contains("compiler_worker_count"),
        "retrieval compiler-unit concurrency must honor the process memory budget without limiting semantic facts"
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
    let prepare = function_body(&compiler_object, "prepare_compiler_object");
    let save = function_body(&compiler_object, "save_compiler_object_sidecar");
    assert!(
        compiler_object.contains("pub struct CompiledFileObject")
            && compiler_object.contains("Sha256")
            && function_body(&compiler_object, "source_descriptor").contains("strip_prefix")
            && load.contains("metadata.path != descriptor.path")
            && load.contains("metadata.language != descriptor.language")
            && load.contains("metadata.source_digest != descriptor.source_digest")
            && load.contains("digest_bytes(&hit.payload)")
            && prepare.matches("ensure_source_version").count() == 3
            && prepare.contains("Ok(Some(prepared)) => {")
            && save.contains("PreparedFactStorePayload")
            && save.contains("compiler_weighted_batches")
            && !save.contains(".take(")
            && !save.contains(".truncate("),
        "compiler objects must be atomic, strongly content-identified, relocatable by relative path, and complete"
    );
    assert!(
        function_body(&db, "decl_index_uncached").contains("compiler_file_object_uncached")
            && function_body(&db, "syntax_indexes_uncached").contains("compiler_file_object_uncached")
            && sdk.contains("\"compiler_objects\"")
            && function_body(&sdk, "cache_manifest_coverage")
                .contains("stats.compiler_object_sidecar_exists"),
        "broad syntax consumers and semantic readiness must share the canonical compiler-object generation"
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
            function_body(&db, "global_index_worker_count"),
            "compiler_worker_count",
        ),
        (
            "compiler objects",
            function_body(&compiler_object, "save_compiler_object_sidecar"),
            "compiler_weighted_batches",
        ),
        (
            "callgraph",
            function_body(&callgraph, "callgraph_resolver_worker_count"),
            "compiler_worker_count",
        ),
        (
            "IDG transfer",
            function_body(&idg, "idg_transfer_batches"),
            "compiler_weighted_batches",
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
    assert!(
        function_body(&idg, "idg_transfer_batches").contains("file_to_source_bytes")
            && function_body(&idg, "idg_transfer_batches").contains("compiler_weighted_batches"),
        "IDG transfer concurrency must use exact compiler-unit size where the syntax provider exposes it"
    );
    assert!(
        function_body(&resources, "compiler_weighted_batches").contains("compiler_worker_count")
            && function_body(&resources, "compiler_weighted_batches")
                .contains("current_process_resident_bytes")
            && function_body(&resources, "compiler_weighted_batches_for_limit_and_resident")
                .contains("weighted_working_memory_bytes")
            && function_body(&resources, "weighted_working_memory_bytes").contains("resident_bytes")
            && function_body(&resources, "weighted_working_memory_bytes").contains("headroom"),
        "weighted compiler schedules must apply the conservative worker profile, subtract measured resident state, and retain safety headroom"
    );
    assert!(
        function_body(&db, "build_global_header_index").contains("insert_header_preprocessed")
            && function_body(&taint_idg, "build_resolved_call_graph_snapshot_scoped")
                .contains("decl_index_remapped_to_headers")
            && !function_body(&taint_idg, "build_resolved_call_graph_snapshot_scoped")
                .contains("global_index()")
            && function_body(&workspace, "source_reachable_resolved_call_graph")
                .contains("build_with_file_semantics_for_files_streaming_with_context")
            && function_body(&workspace, "source_reachable_resolved_call_graph")
                .contains("decl_index_remapped_to_headers"),
        "callgraph construction must keep global declaration headers and stream exact per-file bodies"
    );
    assert!(
        function_body(&workspace, "build_and_persist_idg_sidecar").contains("compiler_linkage_index()")
            && function_body(&workspace, "build_and_persist_idg_sidecar")
                .contains("build_for_persistence_streaming_with_file_semantics_and_options")
            && function_body(&idg, "lower_transfer_segment_batch").contains("body_for_file")
            && function_body(&index, "insert_linkage_header_preprocessed")
                .contains("decl.flow_events.clear()")
            && function_body(&index, "insert_linkage_header_preprocessed").contains("function_linkage_facts")
            && index.contains("pub has_summary_output: bool")
            && index.contains("pub returned_constructor_calls: Vec<ReturnedConstructorLinkageFact>")
            && function_body(&workspace, "has_summary_output").contains("linkage_facts")
            && function_body(&workspace, "call_edge_passes_target_callback")
                .contains("span_contains(*arg_span, *target_span)")
            && !function_body(&workspace, "call_edge_passes_target_callback")
                .contains("callable_reference_variants"),
        "IDG persistence must retain linkage headers and stream exact compiler-object bodies at segment boundaries"
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
                .matches("lower_transfer_segment_batch")
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
            && function_body(&idg_builder, "field_place_keys_for_propagation")
                .contains("visit_transforms")
            && function_body(&idg_workspace, "save_workspace_parts")
                .contains("into_factstore_writer")
            && function_body(&idg_workspace, "save_workspace_parts").contains("spool.write_chunks")
            && function_body(&idg_workspace, "into_factstore_writer")
                .contains("FactStoreWriter::create_from_prepared")
            && function_body(&factstore_writer, "create_from_prepared").contains("prepared.relocate")
            && !idg_workspace.contains("fn streamed_entry"),
        "sidecar persistence must adopt already-encoded compiler segments and stream bounded cross-edge and symbolic-transform chunks instead of retaining or recopying the complete graph"
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
            && function_body(&idg, "call_edges_for_caller").contains("call_graph.callees_of(caller)")
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
    let path_body = live_code(function_body(&paths_rs, "paths"));
    let path_graph_body = live_code(function_body(&paths_rs, "semantic_path_graph"));
    let path_finalize_body = live_code(function_body(&paths_rs, "finalize_outcome"));
    assert!(
        path_body.contains("semantic_path_graph(ws)") && path_body.contains("enumerate_paths_resolved("),
        "path queries must enumerate the shared semantic path graph and report resolution coverage"
    );
    assert!(
        path_graph_body.contains("ws.cached_resolved_call_graph()")
            && path_graph_body.contains("idg.semantic_cross_call_edges_with_max_precision(")
            && path_graph_body.contains("call_edge_from_idg_cross_call("),
        "path semantic graph must start from the cached resolved callgraph and augment with warmed IDG cross-call edges"
    );
    assert!(
        path_finalize_body.contains("resolution_coverage(")
            && path_finalize_body.contains("unresolved call site(s)"),
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
        slice_body.contains("global.decls_in(file)") && slice_decl_body.contains("decl.flow_events"),
        "slice queries must start from indexed declarations and adapter-emitted FlowEvent facts"
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
    let dirty_hash_body = function_body(&workspace_build, "dirty_content_hash");
    assert!(
        dirty_hash_body.contains("diff")
            && dirty_hash_body.contains("--binary")
            && dirty_hash_body.contains("ls-files")
            && dirty_hash_body.contains("std::fs::read"),
        "workspace build fingerprint must hash tracked diffs and untracked contents, not only dirty file names"
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
            && function_body(&diagnostics, "run_semantic_workers").contains("std::env::current_exe()")
            && function_body(&diagnostics, "run_semantic_workers")
                .contains("SemanticWorkerPhase::Compiler")
            && function_body(&diagnostics, "run_semantic_workers")
                .contains("SemanticWorkerPhase::Retrieval")
            && function_body(&diagnostics, "run_semantic_workers")
                .contains("SemanticWorkerPhase::Callgraph")
            && function_body(&diagnostics, "run_semantic_workers")
                .contains("SemanticWorkerPhase::Linkage")
            && function_body(&diagnostics, "run_semantic_workers").contains("SemanticWorkerPhase::Idg"),
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
            && idg.contains("load_callgraph_sidecar_checked")
            && idg.contains("load_compiler_linkage_sidecar_checked")
            && idg.contains("build_and_persist_idg_sidecar")
            && idg.contains("write_manifest"),
        "compiler objects, retrieval, callgraph, linkage, and IDG persistence must be independently executable exact phases"
    );
    let workers = function_body(&diagnostics, "run_semantic_workers");
    assert!(
        workers.contains("Command::new(&executable)")
            && workers.contains("SemanticWorkerPhase::Compiler")
            && workers.contains("SemanticWorkerPhase::Retrieval")
            && workers.contains("SemanticWorkerPhase::Callgraph")
            && workers.contains("SemanticWorkerPhase::Linkage")
            && workers.contains("SemanticWorkerPhase::Idg")
            && workers.contains("command.status()?")
            && workers.contains("if !status.success()"),
        "CLI semantic prewarm must run exact phases sequentially across OS-reclaimed process boundaries"
    );
    assert!(
        workers.contains("loop")
            && workers.contains("structural_sidecars_are_current")
            && !workers.contains(".take(")
            && !workers.contains(".truncate("),
        "semantic workers must publish one coherent current generation without a retry or semantic-work cap"
    );
    assert!(
        workers
            .find("SemanticWorkerPhase::Compiler")
            .zip(workers.find("SemanticWorkerPhase::Callgraph"))
            .is_some_and(|(compiler, callgraph)| compiler < callgraph)
            && workers
            .find("SemanticWorkerPhase::Callgraph")
            .zip(workers.find("SemanticWorkerPhase::Retrieval"))
            .is_some_and(|(callgraph, retrieval)| callgraph < retrieval)
            && function_body(&retrieval_crate, "ensure_sidecar")
                .contains("ws.load_callgraph_sidecar(workspace_root)"),
        "retrieval compilation must reuse the exact callgraph phase artifact instead of recompiling its dependency"
    );
    assert!(
        linkage_sidecar.contains("files: Vec<(u32, String, u64)>")
            && linkage_sidecar.contains("wire::encode_struct_map_to_writer(output, index.as_ref())")
            && function_body(&index, "serialize").contains("sort_unstable_by_key")
            && function_body(&index, "deserialize").contains("rebuild_persisted_indexes"),
        "linkage phase artifacts must bind exact VFS identity and use canonical compiler wire order"
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
        unified.contains("func_nodes[start..end].sort_unstable_by_key")
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
            .find("compiler_linkage_index()")
            .is_some_and(|linkage| hydrate
                .find("IdgQueryService::load_from_disk")
                .is_some_and(|idg| linkage < idg)),
        "warm query open must finish streamed Tree-sitter linkage before hydrating the live IDG"
    );
}

#[test]
fn broad_security_scans_stream_exact_ast_bodies_beside_the_idg() {
    let matcher = read(&repo_root().join("crates/security/src/matcher/mod.rs"));
    let workspace = read(&repo_root().join("crates/workspace/src/lib.rs"));
    let headers = function_body(&matcher, "streaming_global_linkage");
    assert!(
        headers.contains("compiler_linkage_index()"),
        "broad security phases must reuse compact IDG compiler linkage with an exact compact-header fallback"
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
    let invalidation = function_body(&workspace, "invalidate_after_file_change");
    assert!(
        invalidation.contains("compiler_linkage.write() = None"),
        "source edits must invalidate the compact compiler symbol snapshot"
    );

    let scan = function_body(&matcher, "scan_decl_index");
    assert!(
        scan.contains("FactRetention::Transient")
            && scan.contains("decl_index_remapped_to_headers(global, file)"),
        "transient matcher scans must stream one exact compiler body and bind it to stable workspace symbols"
    );

    let inferred = function_body(&matcher, "infer_entry_point_sources_for_files_with_progress");
    assert!(
        inferred.contains("streaming_global_linkage(ws)")
            && inferred.contains("decl_index_remapped_to_headers(global.as_ref(), file)")
            && !inferred.contains("global_index()"),
        "inferred entry-point analysis must stream exact file bodies instead of materializing a second workspace body index"
    );

    let execution = read(&repo_root().join("crates/security/src/analysis/execution.rs"));
    let source_plan = function_body(&execution, "plan_source_work");
    assert!(
        source_plan.contains("exact_decl_index(file)")
            && source_plan.contains("source_seed_set(pack, source.source, source_decl)"),
        "taint source seed planning must derive carriers from exact AST bodies, not compact headers"
    );
    let analysis = read(&repo_root().join("crates/security/src/analysis/mod.rs"));
    let source_graph_plan = function_body(&analysis, "schedule_source_graph_groups");
    assert!(
        source_graph_plan.contains("exact_decl_index(file)")
            && source_graph_plan.contains("source_seed_set(pack, hit.hit, decl)"),
        "source-analysis seed planning must derive carriers from exact AST bodies, not compact headers"
    );

    let package_facts = function_body(&matcher, "build_file_package_set");
    assert!(
        package_facts.contains("decl_index_uncached(file)") && !package_facts.contains("global_index()"),
        "file-local package heuristics must consume file-local AST facts without opening the workspace body index"
    );

    assert_eq!(
        matcher.matches(".global_index()").count(),
        1,
        "security matcher may use the resident whole-workspace body index only in its explicit cached mode"
    );
}

#[test]
fn security_and_export_idg_consumers_never_materialize_workspace_bodies() {
    let workspace = read(&repo_root().join("crates/workspace/src/lib.rs"));
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
            source.contains("compiler_linkage_index()")
                && source.contains("exact_decl_index(")
                && !source.contains("global_index()"),
            "{path} must export exact AST facts without retaining every lowered workspace body"
        );
    }

    assert!(
        function_body(&security_chain, "compile_source_graph").contains("with_global_index(self.global.as_ref())")
            && function_body(&security_analysis, "build_source_group_candidates")
                .contains("with_global_index(context.global)"),
        "security taint closures must pass compact compiler linkage through the query boundary instead of reopening AnalyzerDb::global_index"
    );

    let taint_reachable = read(&repo_root().join("crates/taint/src/reachable.rs"));
    let attribution = function_body(&taint_reachable, "cached_function_attribution");
    assert!(
        attribution.contains("decl_index_remapped_to_headers(global, file)")
            && attribution.contains("build_function_call_event_summaries")
            && attribution.contains("let built = file_index")
            && attribution.contains(".defs"),
        "compact taint queries must distill exact per-file AST call attribution and release the body"
    );
    let distilled = function_body(&taint_reachable, "build_function_call_event_summaries");
    assert!(
        distilled.contains("collect_call_event_summaries")
            && distilled.contains("collect_return_spans")
            && distilled.contains("collect_write_event_summaries"),
        "all rendered call/write/return evidence must survive the transient exact-body boundary"
    );
}

#[test]
fn workspace_context_does_not_run_an_unneeded_compiler_pass() {
    let root = repo_root();
    let diagnostics = read(&root.join("crates/cli/src/commands/diagnostics.rs"));
    let body = function_body(&diagnostics, "cmd_context");
    assert!(
        body.contains("open_workspace_syntax_only(root)?") && body.contains("workspace.semantic_context()"),
        "context must derive filesystem metadata without parsing every source file"
    );
    assert!(
        !body.contains("open_project_parse_only") && !body.contains("global_index"),
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
            && body.contains("apply_assign_value_kind")
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
        (&database, "global_index_worker_count"),
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
            && runtime_type_lowering.contains("fn extract_runtime_type_narrowing_facts"),
        "language IR must retain direct-call and runtime-guard relationships"
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
    let rules = read(&root.join("crates/security/src/rule.rs"));
    let path_pack = read(&root.join("security-patterns/langs/python/sinks/path.yml"));
    let language_types = read(&root.join("crates/lang_api/src/types.rs"));
    let language_kit = read(&root.join("crates/lang_api/src/kit/mod.rs"));
    let ruby = read(&root.join("crates/lang_ruby/src/lib.rs"));
    let native_export = read(&root.join("crates/browse/src/native_export.rs"));

    for spelling in ["os.path.join", "realpath", "setLocation"] {
        assert!(
            !analysis.contains(spelling) && !guards.contains(spelling),
            "security analysis must obtain `{spelling}` roles from rulepack semantics"
        );
    }

    let receiver_flow = function_body(&analysis, "guarded_variable_flows_into_receiver_before_sink");
    assert!(
        receiver_flow.contains("receiver_mutation_targets")
            && receiver_flow.contains("rule_target_matches_call"),
        "receiver mutation proofs must consume taint_receiver_from_args rule targets"
    );
    let path_guard = function_body(&guards, "path_containment_guard_sanitizer");
    assert!(
        path_guard.contains("GuardProfile::PythonPathContainment")
            && path_guard.contains("path_containment_guard"),
        "path containment must be selected by typed analysis semantics"
    );
    assert!(
        rules.contains("pub struct PathContainmentGuardSemantics")
            && path_pack.contains("guard_profile: python-path-containment")
            && path_pack.contains("path_containment_guard:"),
        "callable roles for path containment must be declared in the rule schema and rulepack"
    );
    let condition_proof = function_body(&guards, "path_containment_guard_condition");
    assert!(
        condition_proof.contains("branch_condition_fact_for_span")
            && condition_proof.contains("BranchConditionPolarity::Negated")
            && !condition_proof.contains("compact_guard_text")
            && !condition_proof.contains("branch.condition"),
        "path containment polarity must come from Tree-sitter condition facts, not rendered text"
    );
    assert!(
        language_types.contains("pub struct BranchConditionFact")
            && language_kit.contains("extract_branch_condition_facts(&tree")
            && ruby.contains("extract_branch_condition_facts(&tree")
            && native_export.contains("branch_conditions: index.branch_conditions.clone()"),
        "branch-condition compiler facts must be emitted by shared/custom frontend paths and preserved by export"
    );
}

/// The unified taint engine is compiler dataflow over the IDG. Semantic
/// closure must run to a fixed point with no breadth/depth/iteration budget;
/// bounded traversal belongs only to explicit diagnostic rendering APIs.
#[test]
fn unified_taint_closure_is_uncapped_compiler_dataflow() {
    let root = repo_root();
    let idg_query = read(&root.join("crates/idg/src/query.rs"));
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
