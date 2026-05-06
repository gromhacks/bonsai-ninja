//! Drift guards for the cross-crate architecture invariants documented
//! in `docs/contributing/architecture.mdx` and `docs/contributing/taint-engine-spec.mdx`.
//!
//! These tests are intentionally side-channel — they read source
//! files / Cargo manifests directly rather than going through any of
//! the analysis APIs. The point is to fail at `cargo test` time when
//! a refactor would otherwise compile and pass every behavioural
//! test while violating one of the spec's non-negotiables.

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

fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let needle = format!("fn {name}");
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
    panic!("unterminated body for {name}");
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
        is_wildcard: false,
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
        alias: None,
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
        alias: None,
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
        original_name: None,
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
fn interprocedural_taint_uses_db_cached_cfgs() {
    // docs/contributing/review-checklist.mdx BL-2: the interprocedural taint pass revisits the
    // same function for different seeds, so it must use
    // AnalyzerDb::cfg instead of rebuilding CFGs from FlowEvents on
    // every work item.
    let root = repo_root();
    let inter_rs = root
        .join("crates")
        .join("taint")
        .join("src")
        .join("inter")
        .join("mod.rs");
    let text = read(&inter_rs);
    let scan_end = text.find("#[cfg(test)]").unwrap_or(text.len());
    let live_text = &text[..scan_end];
    let mut violations = Vec::new();
    for (lineno, line) in live_text.lines().enumerate() {
        let live = line.split("//").next().unwrap_or("").trim();
        if live.contains("build_cfg_from_flow") {
            violations.push(format!("taint/src/inter.rs:{}: {live}", lineno + 1));
        }
    }
    assert!(
        violations.is_empty(),
        "interprocedural taint must use AnalyzerDb::cfg instead of rebuilding CFGs:\n  {}",
        violations.join("\n  ")
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
    let kw_capable = ["python", "dart"];
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
/// callgraph, workspace tracer, taint engine, and security matcher must NOT call
/// `find_by_name` outside an explicit display-only allowlist. Every
/// non-allowlisted call site is required to be on a path that supplies
/// a `ResolveContext` (caller_file + caller_module) so visibility /
/// `module_path` filtering applies.
///
/// This is the cross-codebase regression the cautionary
/// `static void error(...)` example warns about: when hiredis and Lua
/// each define `error()` privately and the resolver matches by bare
/// name, taint flows into an unrelated codebase.
///
/// The allowlist is enumerated explicitly — a numeric ceiling lets
/// new bare-name calls slip in under the cap. Each entry below
/// is paired with the file it's allowed in plus a one-line
/// justification. Adding a new bare-name site requires updating
/// this allowlist explicitly (so the diff is visible in code review).
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

    // Per-file allowlist of `find_by_name` occurrences with their
    // justifications. The TOTAL count per file is what matters —
    // adding a new call requires bumping the count AND adding a
    // justification line. Removing a call requires lowering the
    // count.
    //
    // Display-only / framework sites (browse output, kit primitives)
    // live in other crates and aren't scanned by this guard.
    let allowlist: &[(&str, usize, &str)] = &[
        // resolve/src/lib.rs — `find_by_name` is the canonical
        // index lookup; both `resolve_callable_with_context`
        // (semantic) and the legacy `resolve_callable` (display)
        // consume it. The wrappers ABOVE them are what graph-
        // construction code is required to use; the index lookup
        // itself is unavoidable.
        ("resolve/src/lib.rs", 3, "canonical index lookup primitives"),
        // callgraph/src/lib.rs — residual site:
        //   - `collect_callable_targets_exact` (display-only entry
        //     point's underlying call). The local-binding pre-pass
        //     (`resolve_callable_symbol`) now routes through the
        //     context-aware resolver, killing the cross-TU
        //     `static error()` regression observed against Redis.
        ("callgraph/src/lib.rs", 1, "display-only entry point only"),
        // workspace/src/lib.rs — display / CLI entry lookup by user-
        // supplied function name. The cross-module tracer itself
        // (`workspace/src/cross_module.rs`) must remain at zero bare
        // index lookups; it receives a concrete entry symbol and must
        // route every edge through context-aware resolution.
        (
            "workspace/src/lib.rs",
            3,
            "display-only trace entry lookup by user-supplied name",
        ),
        // taint/src/inter.rs — residual site:
        //   - `find_by_name` inside the head-is-workspace-symbol
        //     probe (workspace-wide existence check, parallels
        //     callgraph's probe — not an edge constructor).
        ("taint/src/inter.rs", 1, "head-is-workspace-symbol probe"),
        // security/src/matcher.rs — residual site is the
        // workspace-existence probe inside the head-is-workspace-
        // symbol heuristic. The other previous sites
        // (`collect_callee_symbols`, `collect_callable_name_symbols`)
        // were migrated to `resolve_callable_with_context`.
        (
            "security/src/matcher.rs",
            1,
            "workspace-existence probe (caller-independent)",
        ),
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
            let text = read(&path);
            // Strip #[cfg(test)] tail to ignore test-fixture lookups.
            let body = if let Some(idx) = text.find("#[cfg(test)]") {
                &text[..idx]
            } else {
                text.as_str()
            };
            let count = body.matches("find_by_name").count();
            if count == 0 {
                continue;
            }
            // Compute the relative path to match against allowlist
            // entries (they're keyed by `<crate>/src/<file>.rs`).
            let rel = path
                .strip_prefix(root.join("crates"))
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            per_file.push((rel.clone(), count));
            let allowed = allowlist
                .iter()
                .find(|(suffix, _, _)| rel.ends_with(suffix))
                .map(|(_, expected, _)| *expected);
            match allowed {
                Some(expected) if count == expected => {}
                Some(expected) => {
                    violations.push(format!(
                        "{rel}: expected {expected} `find_by_name` occurrences (per allowlist), \
                         found {count}. Update the allowlist entry with a justification, or \
                         migrate the new call to a context-aware resolver primitive."
                    ));
                }
                None => {
                    violations.push(format!(
                        "{rel}: contains {count} `find_by_name` occurrences but is not in \
                         the allowlist. Either route the lookup through `resolve_callable_with_context` \
                         / `collect_callable_targets_with_context`, or add an explicit allowlist \
                         entry with justification (per docs/contributing/design-patterns.mdx::Semantic Resolution Always)."
                    ));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "find_by_name allowlist violations:\n  {}\n\nPer-file counts:\n  {}",
        violations.join("\n  "),
        per_file
            .iter()
            .map(|(p, n)| format!("{p}: {n}"))
            .collect::<Vec<_>>()
            .join("\n  ")
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
    let inter = root
        .join("crates")
        .join("taint")
        .join("src")
        .join("inter")
        .join("mod.rs");
    let text = read(&inter);
    // The fix lives at `TaintedArg { index: *arg_index, ... }`.
    // Catching the regression by string-match is sufficient: the
    // pre-fix shape was `index: param_index`. If a future refactor
    // re-introduces that exact line we want to fail before behavior
    // changes.
    assert!(
        !text.contains("TaintedArg {\n                index: param_index"),
        "TaintedArg.index regressed to callee param index — see docs/contributing/review-checklist.mdx::§4 T-5. \
         The field's docstring and contract require call-site arg index."
    );
    assert!(
        text.contains("// `TaintedArg.index` is the call-site argument slot"),
        "the regression-prevention comment in inter.rs::propagate_call_event must \
         remain — it documents the contract and references the drift guard."
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
        let post_processes = body.contains("apply_file_stem_semantic_identity")
            || body.contains("apply_module_path_semantic_identity");
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
        let calls_post_process = body.contains("apply_file_stem_semantic_identity")
            || body.contains("apply_module_path_semantic_identity");
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
        let has_module_path = body.contains("apply_file_stem_semantic_identity")
            || body.contains("apply_module_path_semantic_identity");
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

/// `kind: param` rules with `in_class:` constraints must accept
/// both direct class-name match AND any name listed in the
/// enclosing class's `bases` list. Pinning the matcher's gate to
/// `enclosing_class_bases` so a `class Echo(WebSocketHandler):`
/// matches `in_class: [WebSocketHandler]` per
/// docs/contributing/design-patterns.mdx::Semantic Resolution Always.
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
    let body = function_body(&text, "scan_params_batch");
    assert!(
        body.contains("enclosing_class_bases"),
        "scan_params_batch must consult Decl.bases for in_class ancestry matching"
    );
    assert!(
        body.contains("base_match"),
        "scan_params_batch must accept either a direct class match OR a bases match"
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
    let root = repo_root();
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
        let _ = lang; // silence unused warning if no adapter found
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
    let _ = root; // suppress unused-variable warning
}
