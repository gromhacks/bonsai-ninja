//! `bonsai-ninja imports` data layer.
//!
//! Returns every `import` / `use` / `include` in the workspace.
//! Falls back to the parser's generic extractor (`bonsai_lang_api::
//! kit::extract_generic_imports`) for adapters that don't ship a
//! dedicated import index, so coverage is uniform across the
//! supported languages.

use crate::common::{
    best_textual_relevance_key, file_path_matches_filter, format_span, make_name_filter,
    textual_relevance_key,
};
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Filter bundle for [`imports`].
#[derive(Copy, Clone, Default, Debug)]
pub struct ImportsFilters<'a> {
    /// `--file substring` against the importing file's path.
    pub file: Option<&'a str>,
    /// `--module X` — substring (or regex) over the imported
    /// module name (`os`, `django.db.models`, `react`).
    pub module: Option<&'a str>,
    /// `--alias X` — substring over the local alias when one is
    /// declared (`from x import y as z` → alias is `z`).
    pub alias: Option<&'a str>,
    /// `--wildcard` — only keep wildcard imports
    /// (`from x import *`, `use std::sync::*`).
    pub wildcard: bool,
    /// Treat `module` as a regex instead of a substring.
    pub regex: bool,
    /// Populate workspace-local function/method bindings for whole-module
    /// imports. This is only needed by the CLI `flows` column; plain import
    /// inventory should not pay the workspace-module resolution cost.
    pub resolve_workspace_bindings: bool,
}

/// One row of `imports` output.
#[derive(Serialize, Clone, Debug)]
pub struct ImportOut {
    pub file: String,
    /// Imported module name as written in source.
    pub module: String,
    /// Local alias when declared (`as z`), else `None`.
    pub alias: Option<String>,
    /// Name of the specific symbol imported from `module` — e.g.
    /// `verify_token` in `from .auth_service import verify_token`.
    /// `None` for whole-module imports (`import sqlite3`).
    /// Without this field, multi-symbol `from x import a, b` lines
    /// produce visually-duplicate rows (same module + same span)
    /// and the reader has no way to tell which symbol each row
    /// represents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_name: Option<String>,
    /// `true` for wildcard imports (`from x import *`).
    pub is_wildcard: bool,
    pub line: u32,
    /// Extra local bindings attached to this import statement. Used
    /// by the browse layer to aggregate flow-id labels across
    /// destructure shorthands — `const { a, b } = require("x")`
    /// surfaces one Module-scope ImportOut whose `local_bindings`
    /// is `["a", "b"]`. Labels for each are union'd so the import
    /// row shows every downstream chain the user cares about.
    /// Also seeded from the module's short tail (`java.lang.String`
    /// → `String`) for grammars where imports are whole-module and
    /// the "symbol" is the tail name by convention.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub local_bindings: Vec<String>,
}

/// Convert `PascalCase.Segments` → `pascal_case/segments`. Elixir's
/// file-naming convention derives each filename from the module
/// name this way — `alias MyApp.AuthService` lands in
/// `auth_service.ex` (the `MyApp` prefix becomes the directory or
/// is elided for flat test fixtures). We preserve `.` as a path
/// separator, `::` likewise, so downstream candidate resolution
/// can join `importer_dir` + this string when the module string
/// is module-style rather than path-style.
fn pascal_to_snake(module: &str) -> String {
    let mut out = String::with_capacity(module.len() + 8);
    for (segment_idx, segment) in bonsai_common::qualified_name_segments(module)
        .into_iter()
        .enumerate()
    {
        // Module separators become path separators.
        if segment_idx > 0 {
            out.push('/');
        }
        let mut prev_was_lower = false;
        for ch in segment.chars() {
            if ch.is_uppercase() {
                // Only insert `_` between two letter classes — not
                // at the start of a segment.
                if prev_was_lower {
                    out.push('_');
                }
                for lc in ch.to_lowercase() {
                    out.push(lc);
                }
                prev_was_lower = false;
            } else {
                out.push(ch);
                prev_was_lower = ch.is_lowercase() || ch.is_numeric();
            }
        }
    }
    out
}

/// Resolve a require/include-style module path against the workspace
/// filesystem and populate `out` with every function/method the
/// resolved file declares. The module string comes straight from the
/// grammar — `require_relative 'user_service'` → `"user_service"`,
/// `require_once "/path/auth_service.php"` → `"/path/auth_service.php"`,
/// `import "./x"` → `"./x"`. We try each extension the workspace
/// adapter recognises, plus the module string verbatim, resolving
/// both absolute-in-workspace and relative-to-importer paths.
/// Leaves `out` unchanged for library modules (Ruby `sinatra`, Java
/// `java.sql.Connection`, Go `net/http`) that don't resolve to a
/// workspace file.
struct WorkspaceModuleResolver {
    /// Index from `path-suffix → FileIds`. Built once per CLI run
    /// so each resolve query is a single map lookup.
    suffix_to_files: ahash::AHashMap<String, Vec<bonsai_common::FileId>>,
    /// FileId → full path. Used when widening `.h` includes to
    /// their sibling `.c` / `.cpp` implementation files.
    path_by_file: ahash::AHashMap<bonsai_common::FileId, std::path::PathBuf>,
    /// Source suffixes present in this workspace. Candidate expansion is
    /// therefore driven by registered workspace files rather than a shared
    /// cross-language extension inventory.
    extensions: Vec<String>,
    /// Exact directory+stem siblings, used only when an imported declaration
    /// file has no callable bodies of its own.
    siblings_by_stem: ahash::AHashMap<String, Vec<bonsai_common::FileId>>,
}

impl WorkspaceModuleResolver {
    /// Build the path-suffix index over every file in the workspace.
    /// Each path produces an entry for every contiguous tail
    /// (`a/b/c.py`, `b/c.py`, `c.py`) so a relative `require "c"`
    /// can match a deeply-nested file.
    fn new(ws: &Workspace) -> Self {
        let mut suffix_to_files: ahash::AHashMap<String, Vec<bonsai_common::FileId>> =
            ahash::AHashMap::default();
        let mut path_by_file: ahash::AHashMap<bonsai_common::FileId, std::path::PathBuf> =
            ahash::AHashMap::default();
        let mut extensions = Vec::new();
        let mut siblings_by_stem: ahash::AHashMap<String, Vec<bonsai_common::FileId>> =
            ahash::AHashMap::default();
        for file in ws.vfs().all_files() {
            if ws.db().adapter_for(file).is_none() {
                continue;
            }
            let Ok(path) = ws.vfs().path(file) else { continue };
            path_by_file.insert(file, (*path).clone());
            if let Some(extension) = path.extension().and_then(|extension| extension.to_str()) {
                let extension = format!(".{extension}");
                if !extensions.contains(&extension) {
                    extensions.push(extension);
                }
            }
            if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
                let key = normalize_path_key(
                    &path
                        .parent()
                        .unwrap_or_else(|| std::path::Path::new(""))
                        .join(stem)
                        .to_string_lossy(),
                );
                siblings_by_stem.entry(key).or_default().push(file);
            }
            let normalized = normalize_path_key(&path.to_string_lossy());
            let parts: Vec<&str> = normalized.split('/').filter(|p| !p.is_empty()).collect();
            // Index every contiguous tail.
            for part_index in 0..parts.len() {
                suffix_to_files
                    .entry(parts[part_index..].join("/"))
                    .or_default()
                    .push(file);
            }
            suffix_to_files.entry(normalized).or_default().push(file);
        }
        extensions.sort();
        Self {
            suffix_to_files,
            path_by_file,
            extensions,
            siblings_by_stem,
        }
    }

    /// Look up FileIds whose normalised path matches `candidate`.
    /// Empty result means the candidate is library / external.
    fn files_for_candidate(&self, candidate: &std::path::Path) -> Vec<bonsai_common::FileId> {
        let want = normalize_path_key(&candidate.to_string_lossy());
        self.suffix_to_files.get(&want).cloned().unwrap_or_default()
    }

    fn files_with_same_stem(&self, path: &std::path::Path) -> &[bonsai_common::FileId] {
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            return &[];
        };
        let key = normalize_path_key(
            &path
                .parent()
                .unwrap_or_else(|| std::path::Path::new(""))
                .join(stem)
                .to_string_lossy(),
        );
        self.siblings_by_stem.get(&key).map(Vec::as_slice).unwrap_or(&[])
    }
}

/// Canonicalise a path string into the form used as a lookup key:
/// forward slashes only, no leading `./`, no Windows-prefix junk.
/// Parent (`..`) components survive because we never want a
/// relative `require "../auth"` to match a sibling file.
fn normalize_path_key(path: &str) -> String {
    let path = path.replace('\\', "/");
    let mut parts: Vec<String> = Vec::new();
    for component in std::path::Path::new(&path).components() {
        match component {
            std::path::Component::Normal(seg) => {
                if let Some(s) = seg.to_str() {
                    if !s.is_empty() {
                        parts.push(s.to_string());
                    }
                }
            }
            std::path::Component::ParentDir => parts.push("..".to_string()),
            std::path::Component::CurDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {}
        }
    }
    if parts.is_empty() {
        path
    } else {
        parts.join("/")
    }
}

/// Push `file` onto `files` only if `seen` hasn't seen it yet —
/// dedupes the multi-stage candidate resolution below where the
/// same file can match through both `verbatim` and `with_ext`
/// candidates.
fn push_unique_file(
    files: &mut Vec<bonsai_common::FileId>,
    seen: &mut ahash::AHashSet<bonsai_common::FileId>,
    file: bonsai_common::FileId,
) {
    if seen.insert(file) {
        files.push(file);
    }
}

/// Resolve `module` against the workspace, then append every
/// function/method name the resolved file (or sibling source file)
/// declares to `out`. No-op when the module string doesn't map to
/// a workspace file (library / stdlib / FFI).
fn resolve_workspace_module_bindings(
    global: &bonsai_index::GlobalIndex,
    resolver: &WorkspaceModuleResolver,
    importer_path: &str,
    module: &str,
    out: &mut Vec<String>,
) {
    // Strip any quote characters the grammar kept on the module
    // literal (`"./x"` / `'sinatra'` / `` `pkg` ``).
    let stripped = module.trim_matches(|c: char| matches!(c, '"' | '\'' | '`'));
    if stripped.is_empty() {
        return;
    }
    let importer_dir = std::path::Path::new(importer_path)
        .parent()
        .map(std::path::Path::to_path_buf);
    // Candidate paths are verbatim plus the source suffixes actually present
    // in this workspace. The browse layer never owns a language extension
    // inventory; adapters and the VFS determine which files exist.
    // Also consider the module's snake_case form for ecosystems
    // whose file-naming convention differs from the module-name
    // convention. Elixir `alias MyApp.AuthService` resolves to
    // `my_app/auth_service.ex` in a canonical layout but often
    // just `auth_service.ex` in flat test fixtures — so we try
    // both the full snake_case path and the tail-only form.
    // Java's `ClassName` is already filename-matching
    // (`ClassName.java`); Ruby already passes the snake_case
    // filename directly; the extra candidates beyond the
    // workspace's actual files simply don't match.
    //
    // Filename-style modules (`AuthService.h`, `foo.py`, `x/y.rb`)
    // skip the snake_case / tail transforms entirely — splitting
    // on `.` treats the file extension as a module segment and
    // produces nonsense tails like `"h"`. We detect a filename by
    // the presence of a suffix that exists in the current workspace.
    let has_filename_ext = resolver.extensions.iter().any(|ext| stripped.ends_with(ext));
    let mut module_bases: Vec<String> = vec![stripped.to_string()];
    if !has_filename_ext {
        let snake_case = pascal_to_snake(stripped);
        if snake_case != stripped {
            module_bases.push(snake_case.clone());
            // Tail-only form for flat fixtures: last path segment
            // of the snake_case conversion.
            if let Some(tail) = snake_case.rsplit('/').next() {
                if !tail.is_empty() && tail != snake_case {
                    module_bases.push(tail.to_string());
                }
            }
        }
        // Also try the raw module tail (`MyApp.AuthService` →
        // `AuthService`) for Java / C# / Scala conventions that
        // keep the filename matching the class name.
        let tail = bonsai_common::short_qualified_tail(stripped);
        if !tail.is_empty() && tail != stripped && !module_bases.iter().any(|b| b == tail) {
            module_bases.push(tail.to_string());
        }
    } else {
        // Filename-style: the module string IS already the file
        // path (or the file's basename). For C/C++ `#include
        // "AuthService.h"` / Obj-C `#import "AuthService.h"`, also
        // add the stem (without extension) so the sibling `.c` /
        // `.m` lookup below runs against the right candidate.
        if let Some(stem) = std::path::Path::new(stripped)
            .file_stem()
            .and_then(|s| s.to_str())
        {
            if !stem.is_empty() && stem != stripped {
                module_bases.push(stem.to_string());
            }
        }
    }
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    for base in &module_bases {
        for ext in std::iter::once("").chain(resolver.extensions.iter().map(String::as_str)) {
            let with_ext = if ext.is_empty() || base.ends_with(ext) {
                base.clone()
            } else {
                format!("{base}{ext}")
            };
            candidates.push(std::path::PathBuf::from(&with_ext));
            if let Some(dir) = importer_dir.as_ref() {
                candidates.push(dir.join(&with_ext));
            }
        }
    }
    // Resolve each candidate against the VFS's known files. Match
    // on suffix of the stored path so absolute VFS paths can be
    // looked up via relative module strings. Collect multiple
    // matches (not just the first) — C/C++ `#include "x.h"`
    // resolves to `x.h` whose prototype decls the adapter doesn't
    // surface as function decls, but the sibling `x.c` / `x.cpp`
    // contains the bodies whose names the flow annotator needs.
    // Whole-module imports in other ecosystems usually match one
    // file, so de-duping on FileId keeps this a pure superset.
    let mut resolved: Vec<bonsai_common::FileId> = Vec::new();
    let mut seen: ahash::AHashSet<bonsai_common::FileId> = ahash::AHashSet::default();
    for candidate in &candidates {
        for file in resolver.files_for_candidate(candidate) {
            push_unique_file(&mut resolved, &mut seen, file);
        }
    }
    // Declaration-only files may resolve an import but carry no callable
    // bodies. In that case, include exact same-directory/same-stem siblings
    // that do carry bodies. This is compiler-fact driven and works for any
    // adapter without naming header/source extensions here.
    let initial: Vec<bonsai_common::FileId> = resolved.clone();
    for file in initial {
        let Some(path) = resolver.path_by_file.get(&file) else {
            continue;
        };
        if global.decls_in(file).iter().any(|decl| {
            matches!(
                decl.kind,
                bonsai_lang_api::DeclKind::Function
                    | bonsai_lang_api::DeclKind::Method
                    | bonsai_lang_api::DeclKind::Constructor
            )
        }) {
            continue;
        }
        for &other in resolver.files_with_same_stem(path) {
            if global.decls_in(other).iter().any(|decl| {
                matches!(
                    decl.kind,
                    bonsai_lang_api::DeclKind::Function
                        | bonsai_lang_api::DeclKind::Method
                        | bonsai_lang_api::DeclKind::Constructor
                )
            }) {
                push_unique_file(&mut resolved, &mut seen, other);
            }
        }
    }
    for file in resolved {
        for decl in global.decls_in(file) {
            if !matches!(
                decl.kind,
                bonsai_lang_api::DeclKind::Function
                    | bonsai_lang_api::DeclKind::Method
                    | bonsai_lang_api::DeclKind::Constructor
            ) {
                continue;
            }
            if decl.name.is_empty() {
                continue;
            }
            if !out.iter().any(|n| n == &decl.name) {
                out.push(decl.name.clone());
            }
        }
    }
}

/// Collect every import statement matching the filters. Falls
/// back to the parser's generic extractor for languages without a
/// dedicated import index, so coverage is uniform.
pub fn imports(ws: &Workspace, f: &ImportsFilters<'_>) -> Result<Vec<ImportOut>, regex::Error> {
    use rayon::prelude::*;
    let module_match = make_name_filter(f.module, f.regex)?;
    // Only build the path-index when the caller asked for
    // workspace-binding resolution — most call sites just want the
    // raw import inventory.
    let resolver = f
        .resolve_workspace_bindings
        .then(|| WorkspaceModuleResolver::new(ws));
    // Lazy workspace-wide cache construction must finish before the Rayon
    // file loop. Initializing linkage recursively from a worker can exhaust
    // the same pool while holding its write lock and deadlock peer workers.
    let global = f.resolve_workspace_bindings.then(|| ws.compiler_linkage_index());
    let files: Vec<_> = ws.vfs().all_files();
    let mut out: Vec<ImportOut> = files
        .par_iter()
        .flat_map_iter(|&file_id| {
            let path = ws
                .vfs()
                .path(file_id)
                .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
            let mut per_file: Vec<ImportOut> = Vec::new();
            if f.file
                .is_some_and(|needle| !file_path_matches_filter(ws, &path, needle))
            {
                return per_file.into_iter();
            }
            let pairs: Vec<bonsai_lang_api::ImportSpec> = ws.db().imports_for_uncached(file_id);
            // Pre-index sibling ImportSpec entries by span so
            // Module-scope rows can carry every Local-scope binding
            // attached to the same import statement. JS / TS
            // destructure shorthands (`const { a, b } = require("x")`)
            // produce a Module entry + N Local entries at the same
            // span — we group them so flow-id annotation covers all
            // destructured symbols at once.
            let mut local_by_span: std::collections::HashMap<u64, Vec<String>> =
                std::collections::HashMap::new();
            for imp in &pairs {
                if !imp.scope.is_local() {
                    continue;
                }
                let key = imp.span.start;
                if let Some(name) = imp.alias.as_deref().or(imp.original_name.as_deref()) {
                    if !name.is_empty() {
                        local_by_span.entry(key).or_default().push(name.to_string());
                    }
                }
            }
            for imp in &pairs {
                // `imports` browse shows statement-level bindings, not
                // resolver-only destructure shorthands. `ImportScope::
                // Local` entries live in ImportIndex for the security
                // matcher and resolver; the browse row rolls them
                // into the parent Module-scope entry via
                // `local_bindings`.
                if imp.scope.is_local() {
                    continue;
                }
                if !module_match(&imp.module) {
                    continue;
                }
                if let Some(needle) = f.alias {
                    if !imp.alias.as_deref().is_some_and(|a| a.contains(needle)) {
                        continue;
                    }
                }
                if f.wildcard && !imp.is_wildcard {
                    continue;
                }
                let (_, line, _) = format_span(&imp.span, ws);
                let mut local_bindings = local_by_span.get(&imp.span.start).cloned().unwrap_or_default();
                // For whole-module imports without a named symbol
                // (`import java.lang.String` / `import "os"` /
                // `require 'sinatra'` / `const cp = require("x")`),
                // seed `local_bindings` from the module's tail and
                // the simple alias so the browse layer can still
                // surface flows that terminate at that name. The
                // Python `from x import y` case already carries `y`
                // in `original_name` — left alone by this block.
                if imp.original_name.is_none() {
                    if let Some(alias) = imp.alias.as_deref() {
                        if !alias.is_empty() && !local_bindings.iter().any(|n| n == alias) {
                            local_bindings.push(alias.to_string());
                        }
                    }
                    // Module-tail heuristic — split on the last
                    // `.`, `/`, or `::` separator the grammar used.
                    let tail = bonsai_common::short_qualified_tail(&imp.module)
                        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`'))
                        .trim();
                    if !tail.is_empty() && tail != imp.module && !local_bindings.iter().any(|n| n == tail) {
                        local_bindings.push(tail.to_string());
                    }
                    // Whole-module imports of workspace files
                    // (Ruby `require_relative 'user_service'`, PHP
                    // `require_once "auth_service.php"`, Python
                    // `from .auth_service import *`): resolve the
                    // module path against the workspace's files and
                    // pull every function/method the file declares
                    // into `local_bindings` so the import row's
                    // flow labels cover every downstream chain
                    // rooted in the imported module's functions.
                    // Uniform across adapters — the module string
                    // is whatever the grammar surfaced verbatim.
                    if let (Some(resolver), Some(global)) = (resolver.as_ref(), global.as_ref()) {
                        resolve_workspace_module_bindings(
                            global,
                            resolver,
                            &path,
                            &imp.module,
                            &mut local_bindings,
                        );
                    }
                }
                per_file.push(ImportOut {
                    file: path.clone(),
                    module: imp.module.clone(),
                    alias: imp.alias.clone(),
                    original_name: imp.original_name.clone(),
                    is_wildcard: imp.is_wildcard,
                    line,
                    local_bindings,
                });
            }
            per_file.into_iter()
        })
        .collect();
    // Deterministic sort — file iteration order from `vfs.all_files()`
    // is already sorted, but we're now collecting in parallel so the
    // explicit sort guarantees output is stable regardless of worker
    // completion order.
    // Group by kind (wildcard imports bubble below the alphabetical
    // named list), then alphabetical by module, then by file/line to
    // stabilise ties.
    out.sort_by(|a, b| {
        import_relevance_key(a, f)
            .cmp(&import_relevance_key(b, f))
            .then_with(|| {
                a.is_wildcard
                    .cmp(&b.is_wildcard)
                    .then_with(|| a.module.cmp(&b.module))
                    .then_with(|| a.alias.cmp(&b.alias))
                    .then_with(|| a.file.cmp(&b.file))
                    .then_with(|| a.line.cmp(&b.line))
            })
    });
    Ok(out)
}

fn import_relevance_key(row: &ImportOut, f: &ImportsFilters<'_>) -> ((u8, usize), (u8, usize)) {
    let module = f
        .module
        .filter(|_| !f.regex)
        .map_or((u8::MAX, usize::MAX), |module| {
            best_textual_relevance_key(
                [
                    Some(row.module.as_str()),
                    row.original_name.as_deref(),
                    row.alias.as_deref(),
                ]
                .into_iter()
                .flatten(),
                Some(module),
                false,
            )
        });
    let alias = f.alias.map_or((u8::MAX, usize::MAX), |alias| {
        row.alias.as_deref().map_or((u8::MAX, usize::MAX), |value| {
            textual_relevance_key(value, Some(alias), false)
        })
    });
    (module, alias)
}
