//! Runtime-truth coverage matrix.
//!
//! Iterates every registered language adapter and reads its
//! `LanguageCapabilities` declaration. Combines that with a curated
//! per-language *applicability* table (does the language even have
//! the construct?) so the rendered matrix can show `n/a` rather than
//! a misleading `Unsupported` for things like "macros in JavaScript"
//! or "coroutines in C".
//!
//! Two snapshot files:
//!   - `.snapshots/COVERAGE_BASELINE.snapshot` — the runtime levels alone
//!     (raw drift gate).
//!   - `.snapshots/COVERAGE_BASELINE.rendered.snapshot` — the rendered
//!     human-readable table with applicability + levels combined.
//!
//! Bless both with: `BLESS_BASELINE=1 cargo test -p bonsai-ninja-conformance
//! --test coverage_baseline -- --nocapture`.

use std::path::PathBuf;

use bonsai_lang_api::{CapabilityLevel, LanguageCapabilities};

fn workspace_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

fn level_cell(level: CapabilityLevel) -> &'static str {
    match level {
        CapabilityLevel::Exact => "Exact",
        CapabilityLevel::Partial => "Partial",
        CapabilityLevel::Unsupported => "Unsupported",
    }
}

/// Per-language applicability flags. `true` means the construct exists
/// in the language; `false` means the language has no equivalent and
/// the runtime level should be rendered as `n/a` rather than its
/// nominal `Unsupported`/`Partial` value (which is meaningless when
/// the construct doesn't exist).
///
/// Order matches the column order in `render_*` functions.
struct Applicability {
    modules: bool,
    generics: bool,
    macros: bool,
    dynamic_dispatch: bool,
    exceptions: bool,
    async_await: bool,
    coroutines: bool,
    reflection: bool,
    ffi: bool,
    pattern_matching: bool,
    /// Whether the language has CommonJS-style export aliasing (i.e.
    /// `module.exports = X`). Most languages don't.
    export_aliases: bool,
}

impl Applicability {
    /// Conservative starting point: every construct present.
    const fn all() -> Self {
        Self {
            modules: true,
            generics: true,
            macros: true,
            dynamic_dispatch: true,
            exceptions: true,
            async_await: true,
            coroutines: true,
            reflection: true,
            ffi: true,
            pattern_matching: true,
            export_aliases: false,
        }
    }
}

/// Curated applicability per language id. Edits here become user-
/// visible `n/a` cells in the doc — keep the rationale trivially
/// defensible (does the language have the construct, yes/no).
fn applicability_for(language_id: &str) -> Applicability {
    use Applicability as A;
    match language_id {
        "c" => A {
            generics: false,
            dynamic_dispatch: false,
            exceptions: false,
            async_await: false,
            coroutines: false,
            reflection: false,
            pattern_matching: false,
            ..A::all()
        },
        "cpp" => A {
            async_await: false,
            pattern_matching: false,
            ..A::all()
        },
        "csharp" => A {
            macros: false,
            ..A::all()
        },
        "dart" => A {
            macros: false,
            reflection: false,
            ffi: false,
            ..A::all()
        },
        "elixir" => A {
            generics: false,
            dynamic_dispatch: true,
            exceptions: false,
            async_await: false,
            reflection: false,
            ffi: false,
            ..A::all()
        },
        "erlang" => A {
            generics: false,
            dynamic_dispatch: false,
            exceptions: false,
            async_await: false,
            reflection: false,
            ffi: false,
            ..A::all()
        },
        "go" => A {
            macros: false,
            exceptions: false,
            async_await: false,
            pattern_matching: false,
            ..A::all()
        },
        "java" => A {
            macros: false,
            coroutines: false,
            ..A::all()
        },
        "javascript" => A {
            generics: false,
            macros: false,
            reflection: false,
            ffi: false,
            pattern_matching: false,
            export_aliases: true,
            ..A::all()
        },
        "kotlin" => A {
            macros: false,
            ..A::all()
        },
        "lua" => A {
            generics: false,
            macros: false,
            async_await: false,
            reflection: false,
            pattern_matching: false,
            ..A::all()
        },
        "objc" => A {
            generics: false,
            async_await: false,
            coroutines: false,
            pattern_matching: false,
            ..A::all()
        },
        "perl" => A {
            generics: false,
            macros: false,
            async_await: false,
            coroutines: false,
            ffi: false,
            pattern_matching: false,
            ..A::all()
        },
        "php" => A {
            generics: false,
            macros: false,
            async_await: false,
            ffi: false,
            pattern_matching: false,
            ..A::all()
        },
        "python" => A {
            generics: false,
            macros: false,
            ..A::all()
        },
        "ruby" => A {
            generics: false,
            macros: false,
            async_await: false,
            ffi: false,
            ..A::all()
        },
        "rust" => A {
            exceptions: false,
            coroutines: false,
            reflection: false,
            ..A::all()
        },
        "scala" => A {
            macros: false,
            ffi: false,
            ..A::all()
        },
        "swift" => A {
            macros: false,
            ffi: false,
            ..A::all()
        },
        "typescript" => A {
            macros: false,
            reflection: false,
            ffi: false,
            pattern_matching: false,
            export_aliases: true,
            ..A::all()
        },
        // Default to "construct exists" so a missing entry surfaces a
        // visible level rather than silently hiding a gap.
        _ => Applicability::all(),
    }
}

fn cell(applicable: bool, level: CapabilityLevel) -> &'static str {
    if !applicable {
        "n/a"
    } else {
        level_cell(level)
    }
}

fn render_runtime_only() -> String {
    let registry = bonsai_adapters::all_languages_registry();
    let mut adapters: Vec<(String, LanguageCapabilities)> = registry
        .all()
        .into_iter()
        .map(|adapter| (adapter.language_id().as_str().to_string(), adapter.capabilities()))
        .collect();
    adapters.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = String::new();
    out.push_str("| Language | Modules | Generics | Macros | Dynamic dispatch | Exceptions | Async / await | Coroutines | Reflection | FFI | Pattern matching | Receiver types | Module export aliases |\n");
    out.push_str("|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for (id, caps) in &adapters {
        let LanguageCapabilities {
            modules,
            generics,
            macros,
            dynamic_dispatch,
            exceptions,
            async_await,
            coroutines,
            reflection,
            ffi,
            pattern_matching,
            receiver_types,
            module_export_aliases,
            // The capability struct grew per-adapter slices for
            // constructor names and receiver tokens; the markdown
            // baseline doesn't render them yet — destructure-and-
            // ignore to keep the table contract stable.
            constructor_method_names: _,
            module_default_export_names: _,
            universal_type_names: _,
            module_path_syntax: _,
            bare_call_constructor_syntax: _,
            super_receiver_tokens: _,
            implicit_receiver_tokens: _,
            receiver_type_syntax: _,
            field_places_complete: _,
            same_directory_unqualified_calls: _,
            build_target_linkage: _,
            callable_declaration_family: _,
            quoted_callable_literals: _,
            callable_reference_syntax: _,
            call_text_prefilter: _,
            module_resolution_extensions: _,
            workspace_manifest_context_extensions: _,
        } = caps;
        let aliases = if module_export_aliases.is_empty() {
            "—".to_string()
        } else {
            module_export_aliases.join(", ")
        };
        out.push_str(&format!(
            "| {id} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {aliases} |\n",
            level_cell(*modules),
            level_cell(*generics),
            level_cell(*macros),
            level_cell(*dynamic_dispatch),
            level_cell(*exceptions),
            level_cell(*async_await),
            level_cell(*coroutines),
            level_cell(*reflection),
            level_cell(*ffi),
            level_cell(*pattern_matching),
            level_cell(*receiver_types),
        ));
    }
    out
}

fn render_with_applicability() -> String {
    let registry = bonsai_adapters::all_languages_registry();
    let mut adapters: Vec<(String, LanguageCapabilities)> = registry
        .all()
        .into_iter()
        .map(|adapter| (adapter.language_id().as_str().to_string(), adapter.capabilities()))
        .collect();
    adapters.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = String::new();
    out.push_str("| Language | Modules | Generics | Macros | Dyn dispatch | Exceptions | Async / await | Coroutines | Reflection | FFI | Pattern matching | Receiver types | Module export aliases |\n");
    out.push_str("|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for (id, caps) in &adapters {
        let app = applicability_for(id);
        let aliases = if !app.export_aliases {
            "n/a".to_string()
        } else if caps.module_export_aliases.is_empty() {
            "—".to_string()
        } else {
            caps.module_export_aliases.join(", ")
        };
        out.push_str(&format!(
            "| {id} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {aliases} |\n",
            cell(app.modules, caps.modules),
            cell(app.generics, caps.generics),
            cell(app.macros, caps.macros),
            cell(app.dynamic_dispatch, caps.dynamic_dispatch),
            cell(app.exceptions, caps.exceptions),
            cell(app.async_await, caps.async_await),
            cell(app.coroutines, caps.coroutines),
            cell(app.reflection, caps.reflection),
            cell(app.ffi, caps.ffi),
            cell(app.pattern_matching, caps.pattern_matching),
            cell(true, caps.receiver_types),
        ));
    }
    out
}

fn check_or_bless(snapshot_relative: &str, live: &str) {
    let snapshot_path = workspace_root().join(snapshot_relative);

    if std::env::var("BLESS_BASELINE").is_ok() {
        std::fs::write(&snapshot_path, live).expect("write coverage baseline snapshot");
        eprintln!("blessed {}", snapshot_path.display());
        return;
    }

    let snapshot = std::fs::read_to_string(&snapshot_path).unwrap_or_else(|err| {
        panic!(
            "snapshot missing at {}: {err}\n\
             regenerate with: BLESS_BASELINE=1 cargo test -p bonsai-ninja-conformance \
             --test coverage_baseline -- --nocapture",
            snapshot_path.display()
        )
    });

    let snapshot_normalized = snapshot.replace("\r\n", "\n").replace('\r', "\n");
    let live_normalized = live.replace("\r\n", "\n").replace('\r', "\n");
    if snapshot_normalized.trim() != live_normalized.trim() {
        eprintln!("--- snapshot ({snapshot_relative}) ---\n{snapshot}\n--- live ---\n{live}");
        panic!(
            "{snapshot_relative} drift — regenerate with: \
             BLESS_BASELINE=1 cargo test -p bonsai-ninja-conformance \
             --test coverage_baseline -- --nocapture"
        );
    }
}

#[test]
fn coverage_baseline_matches_snapshot() {
    check_or_bless(".snapshots/COVERAGE_BASELINE.snapshot", &render_runtime_only());
}

#[test]
fn rendered_baseline_matches_snapshot() {
    check_or_bless(
        ".snapshots/COVERAGE_BASELINE.rendered.snapshot",
        &render_with_applicability(),
    );
}
