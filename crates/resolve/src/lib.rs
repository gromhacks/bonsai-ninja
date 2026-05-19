//! Module + name resolution.
//!
//! Resolution is inherently language-specific; this crate provides the
//! shared data model and a simple import-graph traversal that most
//! adapters can reuse.

use ahash::{AHashMap, AHashSet};
use bonsai_common::{short_qualified_tail, FileId, SymbolId};
use bonsai_index::GlobalIndex;
use bonsai_lang_api::{AliasTarget, ImportSpec, ModulePath, Visibility, WILDCARD_IMPORT_ALIAS_PREFIX};

/// Caller-side context the resolver consults when narrowing a
/// candidate set. Built by callgraph / taint / matcher at edge-
/// construction or propagation time. See
/// `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
///
/// Required fields:
///
/// - `caller_file`: which file the call site lives in. Used to
///   filter `Visibility::Private` candidates declared in other files.
/// - `caller_module`: the caller's module / package / crate path.
///   Used to filter `Visibility::Module` and `Visibility::Crate`
///   candidates whose `module_path` does not match.
///
/// Optional narrowings:
///
/// - `receiver_type`: when the call site is `obj.method(...)` and
///   `typeof(obj)` is known, the resolver retains only candidates
///   whose `Decl.parent` is the receiver type (or in its subtype
///   chain). When `None`, no receiver-type filter applies.
/// - `alias_map`: caller-local imports; the resolver may rewrite
///   `name` through this map before lookup.
/// - `file_path_lookup`: workspace file paths used only as a
///   semantic backstop when an import path is more precise than an
///   adapter-populated module path.
#[derive(Clone, Debug)]
pub struct ResolveContext<'a> {
    pub caller_file: FileId,
    pub caller_module: &'a ModulePath,
    pub receiver_type: Option<SymbolId>,
    pub alias_map: Option<&'a AHashMap<String, AliasTarget>>,
    pub file_path_lookup: Option<FilePathLookup<'a>>,
}

impl<'a> ResolveContext<'a> {
    #[must_use]
    pub fn new(caller_file: FileId, caller_module: &'a ModulePath) -> Self {
        Self {
            caller_file,
            caller_module,
            receiver_type: None,
            alias_map: None,
            file_path_lookup: None,
        }
    }

    #[must_use]
    pub fn with_receiver_type(mut self, receiver_type: SymbolId) -> Self {
        self.receiver_type = Some(receiver_type);
        self
    }

    #[must_use]
    pub fn with_alias_map(mut self, alias_map: &'a AHashMap<String, AliasTarget>) -> Self {
        self.alias_map = Some(alias_map);
        self
    }

    #[must_use]
    pub fn with_file_path_lookup(mut self, lookup: &'a dyn Fn(FileId) -> Option<String>) -> Self {
        self.file_path_lookup = Some(FilePathLookup { lookup });
        self
    }
}

#[derive(Clone, Copy)]
pub struct FilePathLookup<'a> {
    lookup: &'a dyn Fn(FileId) -> Option<String>,
}

impl<'a> FilePathLookup<'a> {
    fn path_for(self, file: FileId) -> Option<String> {
        (self.lookup)(file)
    }
}

impl std::fmt::Debug for FilePathLookup<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FilePathLookup(..)")
    }
}

/// Returns true when `decl` is reachable from the caller described
/// by `ctx`, given the decl's `Visibility` and `module_path`. This
/// is the central semantic-identity filter: it never inspects
/// identifier text.
#[must_use]
pub fn visibility_allows(
    decl: &bonsai_lang_api::Decl,
    decl_file: FileId,
    decl_module: &ModulePath,
    ctx: &ResolveContext<'_>,
) -> bool {
    match decl.visibility {
        Visibility::Public | Visibility::Protected | Visibility::Internal => true,
        Visibility::Private => {
            // Private is file-scoped. When the adapter has not yet
            // populated `module_path`, both sides are empty and we
            // treat private as file-only — the strictest correct
            // interpretation. Once `module_path` is populated,
            // file-equality is still the right test for `Private`
            // in every supported language.
            decl_file == ctx.caller_file
        }
        Visibility::Module => {
            // Module-private. Empty caller_module or empty
            // decl_module means "no module boundary applicable" —
            // we fall back to file-equality so we never widen a
            // private candidate to the whole workspace.
            if decl_module.is_empty() || ctx.caller_module.is_empty() {
                decl_file == ctx.caller_file
            } else {
                decl_module.matches(ctx.caller_module)
            }
        }
        Visibility::Crate => {
            // Crate-private. Reuse the top-level segment as the
            // crate boundary (Rust `pub(crate)`, Kotlin
            // `internal`). Empty falls back to file-equality.
            if decl_module.is_empty() || ctx.caller_module.is_empty() {
                decl_file == ctx.caller_file
            } else {
                decl_module.shares_top_segment(ctx.caller_module)
            }
        }
    }
}

/// Resolve a callee identifier to every matching callable decl in
/// the workspace, narrowed by caller context.
///
/// This is the semantic-identity entry point. It consults
/// `Decl.visibility`, `Decl.module_path`, and (when `ctx.receiver_type`
/// is `Some`) `Decl.parent` to drop candidates that are not reachable
/// from the call site. Empty result means the call escapes the
/// workspace; the inter pass treats that as external.
///
/// See `docs/contributing/design-patterns.mdx::Semantic Resolution Always`. Drift
/// guard `engine_resolves_via_context_not_bare_name` enforces that
/// no engine path bypasses this primitive.
#[must_use]
pub fn resolve_callable_with_context(
    global: &GlobalIndex,
    name: &str,
    ctx: &ResolveContext<'_>,
) -> Vec<bonsai_common::FuncId> {
    use bonsai_lang_api::DeclKind;
    let collect = |lookup: &str| {
        global
            // CONTEXTLESS_LOOKUP_JUSTIFICATION: this is the semantic
            // resolver primitive; ResolveContext filtering is applied
            // immediately below before any candidate leaves the
            // function.
            .find_by_name(lookup)
            .iter()
            .filter_map(|symbol| {
                let decl = global.decl_of(*symbol)?;
                let decl_file = global.declaring_file(*symbol)?;
                Some((decl, decl_file))
            })
            .filter(|(decl, _)| {
                matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                )
            })
            .filter(|(decl, decl_file)| visibility_allows(decl, *decl_file, &decl.module_path, ctx))
            .filter(|(decl, _)| match ctx.receiver_type {
                Some(recv) => method_parent_matches_receiver_type(global, decl.parent, recv, ctx),
                None => true,
            })
            .map(|(decl, _)| bonsai_common::FuncId::new(decl.symbol.raw()))
            .collect::<Vec<_>>()
    };
    let collect_caller_lexical_scope = |lookup: &str| {
        let mut out = collect(lookup);
        retain_caller_lexical_func_candidates(global, &mut out, ctx);
        out
    };
    let resolve_alias = |lookup: &str| {
        let mut out = Vec::new();
        if let Some(rewrite) = rewrite_through_alias_map_with_target(lookup, ctx) {
            out = collect(&rewrite.rewritten);
            if out.is_empty() {
                // Only module/namespace aliases get a bare-tail retry,
                // and even then candidates are retained only when they
                // live in that module. Type aliases such as
                // `value -> String` must not turn `value.equals` into a
                // workspace-wide `equals` lookup.
                if let (Some(target_module), Some((_, tail))) = (
                    rewrite.target_module.as_deref(),
                    rewrite.rewritten.rsplit_once(['.', ':']),
                ) {
                    out = collect(tail);
                    out.retain(|func| candidate_in_alias_target(global, *func, target_module, ctx));
                }
            }
        }
        out
    };

    let mut out = collect_caller_lexical_scope(name);
    if out.is_empty() {
        if let Some(no_bang) = name.strip_suffix('!') {
            out = collect_caller_lexical_scope(no_bang);
        }
    }
    // Walk the alias map: `cp.exec` where `cp = require("child_process")`
    // should resolve to `child_process.exec`. Without this rewrite,
    // in-workspace aliased calls miss and entry-point inference
    // flags called functions as unreferenced sources. The exact
    // rewrite trusts the rewrite — if the resolver finds a decl
    // by the rewritten name, that IS the match. The bare-name
    // fallback (when the exact rewrite doesn't hit) is the only
    // path that needs the alias-target filter, because
    // `collect(tail)` is a workspace-wide leaf lookup that would
    // otherwise stitch together unrelated workspace functions.
    if out.is_empty() {
        out = resolve_alias(name);
    }
    if out.is_empty() {
        if let Some(no_bang) = name.strip_suffix('!') {
            out = resolve_alias(no_bang);
        }
    }
    if out.is_empty() && unqualified_lookup_name(name) {
        for target_module in wildcard_import_modules(ctx) {
            let mut candidates = collect(name);
            candidates.retain(|func| candidate_in_alias_target(global, *func, target_module, ctx));
            out.extend(candidates);
        }
        dedup_func_ids(&mut out);
    }
    if out.is_empty() {
        if let Some((receiver, method)) = split_member_head_tail(name) {
            out = resolve_callable_member_with_context(global, receiver, method, ctx);
        }
    }
    // Workspace-rooted qualified call: `crate::X::Y` (Rust),
    // `\Foo\Bar::baz` (PHP global namespace), `::ns::fn` (C++) —
    // strip the language-specific absolute-path prefix and treat
    // the remainder as `<module_path>::<fn>` against workspace
    // decls whose canonical `module_path` matches. This is the
    // catch-all for languages where the path itself names the
    // target without going through an `import` or `use` alias.
    if out.is_empty() {
        out = resolve_workspace_rooted_call(global, name, ctx);
    }
    out
}

fn unqualified_lookup_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty()
        && !trimmed.contains('.')
        && !trimmed.contains("::")
        && !trimmed.contains(':')
        && !trimmed.contains('\\')
}

fn wildcard_import_modules<'a>(ctx: &'a ResolveContext<'_>) -> Vec<&'a str> {
    let Some(map) = ctx.alias_map else {
        return Vec::new();
    };
    let mut modules = Vec::new();
    for (key, target) in map {
        if !key.starts_with(WILDCARD_IMPORT_ALIAS_PREFIX) {
            continue;
        }
        if let AliasTarget::Namespace { module } = target {
            if !module.is_empty() && !modules.iter().any(|seen| seen == module) {
                modules.push(module.as_str());
            }
        }
    }
    modules
}

/// Retain only declarations that an unqualified reference can reach
/// without import / receiver / module-qualifier evidence. A public
/// declaration elsewhere in the workspace is not enough: visibility
/// answers "may this be called once named", not "does this call name
/// that declaration".
fn retain_caller_lexical_func_candidates(
    global: &GlobalIndex,
    candidates: &mut Vec<bonsai_common::FuncId>,
    ctx: &ResolveContext<'_>,
) {
    candidates.retain(|func| {
        let sym = SymbolId::new(func.raw());
        let Some(decl) = global.decl_of(sym) else {
            return false;
        };
        let Some(decl_file) = global.declaring_file(sym) else {
            return false;
        };
        candidate_in_caller_lexical_scope(decl, decl_file, ctx)
    });
}

fn retain_caller_lexical_symbol_candidates(
    global: &GlobalIndex,
    candidates: &mut Vec<SymbolId>,
    ctx: &ResolveContext<'_>,
) {
    candidates.retain(|symbol| {
        let Some(decl) = global.decl_of(*symbol) else {
            return false;
        };
        let Some(decl_file) = global.declaring_file(*symbol) else {
            return false;
        };
        candidate_in_caller_lexical_scope(decl, decl_file, ctx)
    });
}

fn candidate_in_caller_lexical_scope(
    decl: &bonsai_lang_api::Decl,
    decl_file: FileId,
    ctx: &ResolveContext<'_>,
) -> bool {
    if matches!(
        decl.kind,
        bonsai_lang_api::DeclKind::Method | bonsai_lang_api::DeclKind::Constructor
    ) {
        return decl_file == ctx.caller_file;
    }
    decl_file == ctx.caller_file
        || (!decl.module_path.is_empty() && decl.module_path.matches(ctx.caller_module))
        || same_directory_unqualified_module_candidate(decl, decl_file, ctx)
}

fn same_directory_unqualified_module_candidate(
    decl: &bonsai_lang_api::Decl,
    decl_file: FileId,
    ctx: &ResolveContext<'_>,
) -> bool {
    if decl_file == ctx.caller_file {
        return false;
    }
    let Some(lookup) = ctx.file_path_lookup else {
        return false;
    };
    let Some(decl_path) = lookup.path_for(decl_file) else {
        return false;
    };
    let Some(caller_path) = lookup.path_for(ctx.caller_file) else {
        return false;
    };
    if (!decl.module_path.is_empty() || !ctx.caller_module.is_empty())
        && !same_directory_global_namespace_extension(&caller_path)
    {
        return false;
    }
    file_parent_dir(&decl_path).is_some_and(|decl_dir| file_parent_dir(&caller_path) == Some(decl_dir))
}

fn file_parent_dir(path: &str) -> Option<&str> {
    let trimmed = path.trim();
    let idx = trimmed.rfind(['/', '\\'])?;
    Some(&trimmed[..idx])
}

fn same_directory_global_namespace_extension(path: &str) -> bool {
    matches!(
        path.rsplit('.').next().unwrap_or_default(),
        "c" | "h"
            | "cc"
            | "cpp"
            | "cxx"
            | "hpp"
            | "hh"
            | "hxx"
            | "m"
            | "mm"
            | "kt"
            | "kts"
            | "swift"
            | "pl"
            | "pm"
    )
}

/// Final-fallback resolver for fully-qualified workspace paths
/// that don't go through the alias map. Handles Rust `crate::`,
/// PHP / C++ `\Foo\Bar` / `::ns::fn`, and bare `<mod>::<fn>` calls
/// where the head segment IS a workspace module identifier.
///
/// The search is constrained by
/// [`module_target_matches_decl_module_path`] so a workspace decl
/// is only returned when its `module_path` actually suffix-matches
/// the call's module head — no bare-name fan-out across unrelated
/// workspace functions.
fn resolve_workspace_rooted_call(
    global: &GlobalIndex,
    name: &str,
    ctx: &ResolveContext<'_>,
) -> Vec<bonsai_common::FuncId> {
    use bonsai_lang_api::DeclKind;
    let stripped = strip_absolute_path_prefix(name);
    if stripped.is_empty() {
        return Vec::new();
    }
    let Some((mod_path, fn_name)) = split_module_call_tail(stripped) else {
        return Vec::new();
    };
    if mod_path.is_empty() || fn_name.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    // CONTEXTLESS_LOOKUP_JUSTIFICATION: workspace-rooted resolver
    // primitive. Caller already split a `<mod_path>::<fn_name>`
    // shape; the candidate list is then narrowed by
    // `module_target_matches_decl_module_path` + `visibility_allows`
    // so no bare-name fan-out leaves this function.
    for sym in global.find_by_name(fn_name) {
        let Some(decl) = global.decl_of(*sym) else {
            continue;
        };
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        let Some(decl_file) = global.declaring_file(*sym) else {
            continue;
        };
        if !visibility_allows(decl, decl_file, &decl.module_path, ctx) {
            continue;
        }
        if !module_target_matches_decl_module_path(mod_path, &decl.module_path)
            && !ctx
                .file_path_lookup
                .and_then(|lookup| lookup.path_for(decl_file))
                .is_some_and(|path| module_target_matches_path(mod_path, &path))
        {
            continue;
        }
        out.push(bonsai_common::FuncId::new(decl.symbol.raw()));
    }
    dedup_func_ids(&mut out);
    out
}

/// Strip absolute-path prefixes from a fully-qualified call name so
/// the remainder is a plain `<module>::<fn>` shape. The non-repeating
/// prefixes (`crate::`, `self::`, `::`, `\`) come from the
/// cross-language constant [`bonsai_common::ABSOLUTE_PATH_PREFIXES`];
/// `super::` is handled inline because it can repeat
/// (`super::super::foo`).
fn strip_absolute_path_prefix(name: &str) -> &str {
    let trimmed = name.trim();
    let mut rest = trimmed;
    let mut stripped_super = false;
    while let Some(next) = rest.strip_prefix("super::") {
        rest = next;
        stripped_super = true;
    }
    if stripped_super {
        return rest;
    }
    for prefix in bonsai_common::ABSOLUTE_PATH_PREFIXES {
        if let Some(rest) = trimmed.strip_prefix(*prefix) {
            return rest;
        }
    }
    trimmed
}

/// Split `<module_path>::<fn_name>` into its parts using the
/// rightmost separator from the supported set.
fn split_module_call_tail(name: &str) -> Option<(&str, &str)> {
    if let Some((head, tail)) = name.rsplit_once("::") {
        return Some((head, tail));
    }
    if let Some((head, tail)) = name.rsplit_once('\\') {
        return Some((head, tail));
    }
    if let Some((head, tail)) = name.rsplit_once('.') {
        if !head.is_empty() && !tail.is_empty() {
            return Some((head, tail));
        }
    }
    None
}

fn resolve_callable_member_with_context(
    global: &GlobalIndex,
    receiver: &str,
    method: &str,
    ctx: &ResolveContext<'_>,
) -> Vec<bonsai_common::FuncId> {
    use bonsai_lang_api::DeclKind;
    if receiver.trim().is_empty() || method.trim().is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for class_sym in resolve_class(global, receiver, ctx) {
        let Some(class_file) = global.declaring_file(class_sym) else {
            continue;
        };
        for decl in global.decls_in(class_file) {
            if decl.parent != Some(class_sym) {
                continue;
            }
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            if decl.name != method && short_qualified_tail(&decl.name) != method {
                continue;
            }
            let Some(decl_file) = global.declaring_file(decl.symbol) else {
                continue;
            };
            if !visibility_allows(decl, decl_file, &decl.module_path, ctx) {
                continue;
            }
            out.push(bonsai_common::FuncId::new(decl.symbol.raw()));
        }
    }
    dedup_func_ids(&mut out);
    out
}

fn split_member_head_tail(name: &str) -> Option<(&str, &str)> {
    let name = name.trim();
    name.rsplit_once("::")
        .or_else(|| name.rsplit_once('.'))
        .or_else(|| name.rsplit_once(':'))
        .or_else(|| name.rsplit_once('\\'))
}

fn method_parent_matches_receiver_type(
    global: &GlobalIndex,
    method_parent: Option<SymbolId>,
    receiver_type: SymbolId,
    ctx: &ResolveContext<'_>,
) -> bool {
    let Some(method_parent) = method_parent else {
        return false;
    };
    if method_parent == receiver_type {
        return true;
    }
    let mut seen = AHashSet::new();
    let mut stack = vec![receiver_type];
    while let Some(class_sym) = stack.pop() {
        if !seen.insert(class_sym) {
            continue;
        }
        let Some(class_decl) = global.decl_of(class_sym) else {
            continue;
        };
        for base in &class_decl.bases {
            for base_sym in resolve_class(global, base, ctx) {
                if base_sym == method_parent {
                    return true;
                }
                stack.push(base_sym);
            }
        }
    }
    false
}

/// Rewrite `name` through `ctx.alias_map` and return both the
/// qualified rewrite (e.g. `child_process.exec`) and the alias
/// target descriptor so callers can constrain the bare-name
/// fallback to the workspace location the alias actually points
/// at — closing the hole that would otherwise stitch together any
/// workspace function with a matching leaf identifier.
///
/// The head/tail split is `::`-aware so qualified-call shapes like
/// Rust / C++'s `pipeline::orchestrate` yield the right tail
/// (`orchestrate`) instead of being chopped at the first `:`. The
/// dotted/colon fallback covers JS / Python / PHP shapes.
fn rewrite_through_alias_map_with_target(name: &str, ctx: &ResolveContext<'_>) -> Option<AliasRewrite> {
    let map = ctx.alias_map?;
    // Whole-name alias: `req` → `flask.request`.
    if let Some(target) = map.get(name) {
        return Some(AliasRewrite::from_target(target, target.target_text()));
    }
    let (head, tail) = split_alias_head_tail(name)?;
    let target = map.get(head)?;
    Some(AliasRewrite::from_target(target, target.rewrite_with_tail(tail)))
}

/// Split `name` into (head, tail) using the longest-form module
/// separator first so `pipeline::orchestrate` yields `("pipeline",
/// "orchestrate")` rather than `("pipeline", ":orchestrate")`.
fn split_alias_head_tail(name: &str) -> Option<(&str, &str)> {
    if let Some((head, tail)) = name.split_once("::") {
        return Some((head, tail));
    }
    if let Some((head, tail)) = name.split_once('.') {
        return Some((head, tail));
    }
    if let Some((head, tail)) = name.split_once(':') {
        return Some((head, tail));
    }
    None
}

/// Result of an alias-map rewrite, including the workspace target
/// the alias points at (when it's a module-path target) so callers
/// can constrain the bare-name fallback to that target.
#[derive(Clone, Debug)]
struct AliasRewrite {
    rewritten: String,
    /// `Some(module)` for [`AliasTarget::Namespace`] and
    /// [`AliasTarget::Member`] aliases — the dotted module identity
    /// the alias points at. `None` for [`AliasTarget::Type`] aliases
    /// so unresolved external types cannot fall back to a bare method
    /// name elsewhere in the workspace.
    target_module: Option<String>,
}

impl AliasRewrite {
    fn from_target(target: &AliasTarget, rewritten: String) -> Self {
        let target_module = match target {
            AliasTarget::Namespace { module } if !module.trim().is_empty() => Some(module.clone()),
            AliasTarget::Member { module, .. } if !module.trim().is_empty() => Some(module.clone()),
            _ => None,
        };
        Self {
            rewritten,
            target_module,
        }
    }
}

trait AliasTargetExt {
    fn target_text(&self) -> String;
    fn rewrite_with_tail(&self, tail: &str) -> String;
}

impl AliasTargetExt for AliasTarget {
    fn target_text(&self) -> String {
        match self {
            AliasTarget::Member { module, member } => format!("{module}.{member}"),
            AliasTarget::Namespace { module } => module.clone(),
            AliasTarget::Type { type_name } => type_name.clone(),
        }
    }

    fn rewrite_with_tail(&self, tail: &str) -> String {
        let prefix = match self {
            AliasTarget::Namespace { module } => module.clone(),
            AliasTarget::Member { module, member } => format!("{module}.{member}"),
            AliasTarget::Type { type_name } => type_name.clone(),
        };
        format!("{prefix}.{tail}")
    }
}

/// True when `target_module` (a dotted module identity from an
/// alias target) is a suffix of `decl_module`'s segments. A bare
/// leaf alias (`AuthService`) hits a decl declared inside
/// `MyApp.AuthService`; a fully-qualified alias is matched by the
/// equality case of the same suffix test.
///
/// The check is tolerant of two divergences between the alias
/// text and the decl's canonical module identity:
///
/// 1. Path-style separators (`/`) and dot-style separators (`.`)
///    both split into segments, so Dart `package:foo/foo.dart`
///    (after the `package:` strip) and Java `com.example.Utils`
///    both decompose correctly.
/// 2. A trailing segment that doesn't appear in the decl's
///    module_path is dropped before retrying the suffix match.
///    This handles two real shapes uniformly:
///     - file-extension-only trailers (Dart `storage.dart` vs
///       decl `storage`),
///     - class-name trailers in dotted package-qualified imports
///       (Java `com.example.Utils` vs decl module `com.example`,
///       since the class name lives in `decl.name`/`decl.parent`,
///       not the module_path).
///
///    The drop is unconditional rather than driven by a
///    file-extension allow-list — the suffix match itself
///    enforces the constraint.
#[must_use]
pub fn module_target_matches_decl_module_path(
    target_module: &str,
    decl_module: &bonsai_lang_api::ModulePath,
) -> bool {
    if target_module.is_empty() || decl_module.is_empty() {
        return false;
    }
    // Split on every common module-separator: `.` (dotted modules
    // — Java, Python, Elixir), `/` (path-style URIs — Dart pub
    // packages, JS specifiers), `\` (PHP namespaces), `::` (Rust /
    // C++ qualified-id, handled below by collapsing the literal
    // `::` bytes before splitting). The decl's `module_path`
    // is already canonical-segment-form so the only normalization
    // needed here is on the alias text.
    let normalized: String = target_module.replace("::", ".");
    let target_segments: Vec<&str> = normalized
        .split(['.', '/', '\\'])
        .map(str::trim)
        .filter(|seg| !seg.is_empty() && *seg != "." && *seg != "..")
        .collect();
    if target_segments.is_empty() {
        return false;
    }
    let decl_segments = &decl_module.segments;
    if try_suffix_match(&target_segments, decl_segments) {
        return true;
    }
    if target_segments.len() > 1 {
        let trimmed = &target_segments[..target_segments.len() - 1];
        if try_suffix_match(trimmed, decl_segments) {
            return true;
        }
    }
    false
}

fn try_suffix_match(target: &[&str], decl: &[String]) -> bool {
    if target.is_empty() || target.len() > decl.len() {
        return false;
    }
    let suffix_start = decl.len() - target.len();
    decl[suffix_start..]
        .iter()
        .zip(target.iter())
        .all(|(decl_seg, target_seg)| decl_seg == target_seg)
}

/// Filter the alias-rewrite bare-name fallback candidates to those
/// whose decl actually lives in the alias's target module. Without
/// this constraint the `collect(tail)` retry inside the rewrite
/// path would stitch together any workspace function with a
/// matching leaf identifier — turning `Envelope::method` (where
/// `Envelope` was a type-only import) into an entry pointing at
/// some unrelated `method()` decl elsewhere in the workspace.
fn candidate_in_alias_target(
    global: &GlobalIndex,
    func: bonsai_common::FuncId,
    target_module: &str,
    ctx: &ResolveContext<'_>,
) -> bool {
    symbol_in_alias_target(global, SymbolId::new(func.raw()), target_module, ctx)
}

fn symbol_in_alias_target(
    global: &GlobalIndex,
    symbol: SymbolId,
    target_module: &str,
    ctx: &ResolveContext<'_>,
) -> bool {
    let Some(decl) = global.decl_of(symbol) else {
        return false;
    };
    if module_target_matches_decl_module_path_from_context(
        target_module,
        &decl.module_path,
        ctx.caller_module,
    ) {
        return true;
    }
    let Some(decl_file) = global.declaring_file(symbol) else {
        return false;
    };
    ctx.file_path_lookup
        .and_then(|lookup| lookup.path_for(decl_file))
        .is_some_and(|path| module_target_matches_path(target_module, &path))
}

fn module_target_matches_decl_module_path_from_context(
    target_module: &str,
    decl_module: &bonsai_lang_api::ModulePath,
    caller_module: &bonsai_lang_api::ModulePath,
) -> bool {
    if let Some(target_segments) = relative_module_target_segments(target_module, caller_module) {
        return decl_module.segments == target_segments;
    }
    module_target_matches_decl_module_path(target_module, decl_module)
}

fn relative_module_target_segments(
    target_module: &str,
    caller_module: &bonsai_lang_api::ModulePath,
) -> Option<Vec<String>> {
    let target = target_module.trim();
    if !(target == "."
        || target == ".."
        || target.starts_with("./")
        || target.starts_with("../")
        || target.starts_with(".\\")
        || target.starts_with("..\\"))
    {
        return None;
    }
    if caller_module.segments.is_empty() {
        return None;
    }
    let normalized = target.replace('\\', "/");
    let mut segments = caller_module.segments.clone();
    segments.pop();
    for raw in normalized.split('/') {
        let part = raw.trim();
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            segments.pop()?;
            continue;
        }
        segments.push(strip_extension(part).to_string());
    }
    (!segments.is_empty()).then_some(segments)
}

/// Trim the call-argument list off a callee text. `Foo(arg)` →
/// `Foo`, `pkg::Bar(x, y)` → `pkg::Bar`. Used at sites that want to
/// compare the callee identifier to a workspace symbol without
/// being thrown off by inline arguments.
#[must_use]
pub fn callee_without_call_args(callee: &str) -> &str {
    callee.split('(').next().unwrap_or(callee).trim()
}

/// Append `func` to `out` only when it isn't already present. Tiny
/// helper but called from enough hot loops that hand-inlining the
/// `contains` check obscures intent at every call site.
pub fn push_unique_func(out: &mut Vec<bonsai_common::FuncId>, func: bonsai_common::FuncId) {
    if !out.contains(&func) {
        out.push(func);
    }
}

/// String version of [`push_unique_func`] — append `value` only if
/// not already in `out`. Used by helpers that accumulate type
/// names / candidate identifiers without producing duplicates.
pub fn push_unique_string(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
}

/// Strip qualified prefix and any of `IDENTIFIER_SIGILS` /
/// `REFERENCE_SIGILS`, then drop a trailing `()`. Produces the bare
/// type-identifier form used for cross-class dispatch comparison.
/// Mirrors what callgraph and taint both used to compute inline.
#[must_use]
pub fn canonical_dispatch_type_name(name: &str) -> String {
    short_tail(name)
        .trim_start_matches(bonsai_common::ALL_NAME_PUNCTUATION)
        .trim_end_matches("()")
        .trim()
        .to_string()
}

/// Split a dotted/scoped qualified name on the *first* separator
/// (`::`, `.`, or `:` in priority order). Returns `(head, tail)`
/// where `head` is everything before the separator. Used by alias-
/// target lookups to decide whether `head` names a known import
/// alias.
#[must_use]
pub fn split_qualified_head_tail(name: &str) -> Option<(&str, &str)> {
    if let Some((head, tail)) = name.split_once("::") {
        return Some((head, tail));
    }
    if let Some((head, tail)) = name.split_once('.') {
        return Some((head, tail));
    }
    if let Some((head, tail)) = name.split_once(':') {
        return Some((head, tail));
    }
    None
}

/// When `name`'s head segment names a `Namespace` alias, return
/// `(module, tail)` so the caller can resolve `tail` against the
/// alias's target module. Returns `None` for any other shape.
#[must_use]
pub fn namespace_alias_target_tail<'a>(
    name: &'a str,
    alias_targets: &'a AHashMap<String, AliasTarget>,
) -> Option<(&'a str, &'a str)> {
    let (head, tail) = split_qualified_head_tail(name)?;
    match alias_targets.get(head)? {
        AliasTarget::Namespace { module } if !module.is_empty() && !tail.is_empty() => {
            Some((module.as_str(), tail))
        }
        _ => None,
    }
}

/// True when `name` is a `module_or_alias.tail` shape AND the head
/// is a known import alias. Used at edge-construction time to
/// detect calls that must be expanded through the file's alias map
/// before any direct candidate lookup.
#[must_use]
pub fn qualified_module_alias_call(name: &str, aliases: &AHashMap<String, String>) -> bool {
    let Some((head, _)) = split_qualified_head_tail(name) else {
        return false;
    };
    aliases.contains_key(head)
}

/// Expand a bare exported name into every receiver-qualified form
/// the caller's adapter declares via
/// `LanguageCapabilities::module_export_aliases`. JS/TS declare
/// `["exports", "module.exports"]`, so `foo` becomes
/// `[foo, exports.foo, module.exports.foo]`. Languages without the
/// convention pass `&[]` and the result is a single-element vec.
#[must_use]
pub fn export_name_variants(alias_tail: &str, caller_export_aliases: &[&'static str]) -> Vec<String> {
    let mut variants = vec![alias_tail.to_string()];
    for receiver in caller_export_aliases {
        variants.push(format!("{receiver}.{alias_tail}"));
    }
    variants
}

/// True when `receiver` is a super-call keyword (`super`, `parent`,
/// `base`) — possibly wrapped in reference sigils or a trailing
/// `()`. Used by both the callgraph and the taint engine when
/// resolving `super.method(...)` to the parent class's method
/// without falling back to bare-name candidate enumeration.
///
/// Defaults to the cross-language `bonsai_common::SUPER_RECEIVER_TOKENS`.
/// Callers that have adapter context should prefer
/// [`is_super_receiver_with_tokens`] so the adapter's narrowed set
/// (declared via `LanguageCapabilities::super_receiver_tokens`)
/// dominates.
#[must_use]
pub fn is_super_receiver(receiver: &str) -> bool {
    is_super_receiver_with_tokens(receiver, bonsai_common::SUPER_RECEIVER_TOKENS)
}

/// Adapter-aware variant of [`is_super_receiver`]: uses the supplied
/// token slice (typically
/// `LanguageCapabilities::effective_super_receiver_tokens()`).
#[must_use]
pub fn is_super_receiver_with_tokens(receiver: &str, tokens: &[&str]) -> bool {
    let receiver = receiver
        .trim()
        .trim_start_matches(bonsai_common::REFERENCE_SIGILS);
    let receiver = receiver.strip_suffix("()").unwrap_or(receiver).trim();
    tokens.contains(&receiver)
}

/// True when `decl`'s parent in the global index is a class-like
/// kind (Class / Struct / Trait / Interface). Helper used by both
/// the callgraph and the taint engine when deciding whether a
/// method belongs to a virtual-dispatch hierarchy.
#[must_use]
pub fn enclosing_class_for_decl<'a>(
    global: &'a GlobalIndex,
    decl: &bonsai_lang_api::Decl,
) -> Option<&'a bonsai_lang_api::Decl> {
    use bonsai_lang_api::DeclKind;
    if let Some(parent) = decl.parent {
        if let Some(parent_decl) = global.decl_of(parent) {
            if matches!(
                parent_decl.kind,
                DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface
            ) {
                return Some(parent_decl);
            }
        }
    }
    None
}

/// Walk every transitive base of `class_sym`, accumulating canonical
/// type names into `out`. Used to detect when one element of a
/// receiver-type set inherits from another so the more-specific
/// receiver can be retained while the broader one is dropped.
pub fn collect_transitive_base_type_names(
    global: &GlobalIndex,
    class_sym: bonsai_common::SymbolId,
    ctx: &ResolveContext<'_>,
    out: &mut AHashSet<String>,
) {
    let Some(class_decl) = global.decl_of(class_sym) else {
        return;
    };
    for base in &class_decl.bases {
        let canonical = canonical_dispatch_type_name(base);
        if !out.insert(canonical) {
            continue;
        }
        for base_sym in resolve_class(global, base, ctx) {
            collect_transitive_base_type_names(global, base_sym, ctx, out);
        }
    }
}

/// Drop receiver type names that are super-types of another
/// receiver in the same set. When `[Child, Base]` are both
/// candidates, virtual dispatch should prefer `Child` because the
/// base is reachable transitively through the inheritance chain.
#[must_use]
pub fn prune_receiver_type_names_for_dispatch(
    type_names: Vec<String>,
    global: &GlobalIndex,
    ctx: &ResolveContext<'_>,
) -> Vec<String> {
    if type_names.len() < 2 {
        return type_names;
    }
    let canonical_types: Vec<String> = type_names
        .iter()
        .map(|name| canonical_dispatch_type_name(name))
        .collect();
    let mut inherited = AHashSet::new();
    for type_name in &type_names {
        for class_sym in resolve_class(global, type_name, ctx) {
            collect_transitive_base_type_names(global, class_sym, ctx, &mut inherited);
        }
    }
    let mut out = Vec::new();
    for (idx, type_name) in type_names.into_iter().enumerate() {
        if inherited.contains(&canonical_types[idx])
            && canonical_types
                .iter()
                .enumerate()
                .any(|(other_idx, other)| other_idx != idx && other != &canonical_types[idx])
        {
            continue;
        }
        push_unique_string(&mut out, type_name);
    }
    out
}

/// Walk a class's hierarchy, accumulating callable candidates that
/// share `method_name`. The initial method visibility is filtered
/// through the call-site `ctx`, while base-class names are resolved
/// from each class declaration's own file/module context. That keeps
/// inherited dispatch semantic for imported subclasses:
/// `pipeline.py` may know `AuditedRepository`, but
/// `AuditedRepository(Repository)` must resolve `Repository` in
/// `storage.py`, not in the caller's lexical scope. Memoisation
/// across both methods and classes prevents cycles in `bases` from
/// looping. Stops walking up the chain once a class declares the
/// method locally — the parent class's same-named method is shadowed.
pub fn collect_method_candidates_for_class(
    global: &GlobalIndex,
    class_sym: bonsai_common::SymbolId,
    method_name: &str,
    ctx: &ResolveContext<'_>,
    seen: &mut AHashSet<bonsai_common::SymbolId>,
    out: &mut Vec<bonsai_common::FuncId>,
) {
    let mut seen_classes = AHashSet::new();
    collect_method_candidates_for_class_inner(
        global,
        class_sym,
        method_name,
        ctx,
        seen,
        &mut seen_classes,
        out,
    );
}

fn collect_method_candidates_for_class_inner(
    global: &GlobalIndex,
    class_sym: bonsai_common::SymbolId,
    method_name: &str,
    ctx: &ResolveContext<'_>,
    seen_methods: &mut AHashSet<bonsai_common::SymbolId>,
    seen_classes: &mut AHashSet<bonsai_common::SymbolId>,
    out: &mut Vec<bonsai_common::FuncId>,
) {
    use bonsai_lang_api::DeclKind;
    if !seen_classes.insert(class_sym) {
        return;
    }
    let Some(class_decl) = global.decl_of(class_sym) else {
        return;
    };
    if !matches!(
        class_decl.kind,
        DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface
    ) {
        return;
    }
    let Some(class_file) = global.declaring_file(class_sym) else {
        return;
    };
    let mut matched_local_method = false;
    for decl in global.decls_in(class_file) {
        if decl.name != method_name {
            continue;
        }
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        let Some(decl_file) = global.declaring_file(decl.symbol) else {
            continue;
        };
        if !visibility_allows(decl, decl_file, &decl.module_path, ctx) {
            continue;
        }
        if decl_belongs_to_class(decl, class_sym, class_decl) && seen_methods.insert(decl.symbol) {
            matched_local_method = true;
            out.push(bonsai_common::FuncId::new(decl.symbol.raw()));
        }
    }
    if matched_local_method {
        return;
    }
    let base_ctx = ResolveContext::new(class_file, &class_decl.module_path);
    for base in &class_decl.bases {
        for base_sym in resolve_class(global, base, &base_ctx) {
            collect_method_candidates_for_class_inner(
                global,
                base_sym,
                method_name,
                ctx,
                seen_methods,
                seen_classes,
                out,
            );
        }
    }
}

fn decl_belongs_to_class(
    decl: &bonsai_lang_api::Decl,
    class_sym: SymbolId,
    class_decl: &bonsai_lang_api::Decl,
) -> bool {
    if decl.parent == Some(class_sym) {
        return true;
    }
    let class_span = class_decl.body_span.unwrap_or(class_decl.span);
    decl.name_span.file == class_span.file
        && decl.name_span.start >= class_span.start
        && decl.name_span.end <= class_span.end
}

/// Lift each `TypeAliasBinding` into the alias-target map as a
/// `Type` entry, but only when the local name isn't already bound.
/// Adapters surface decl `type_aliases`, the resolver consumes them
/// here so `var.method()` dispatches into the declared type's
/// methods even when `var`'s binding isn't otherwise threaded into
/// the alias map.
pub fn extend_alias_targets_with_declared_types(
    alias_targets: &mut AHashMap<String, AliasTarget>,
    type_aliases: &[bonsai_lang_api::TypeAliasBinding],
) {
    for alias in type_aliases {
        if alias.name.is_empty() || alias.type_name.is_empty() {
            continue;
        }
        alias_targets
            .entry(alias.name.clone())
            .or_insert_with(|| AliasTarget::Type {
                type_name: alias.type_name.clone(),
            });
    }
}

/// True when `alias_target` (a dotted / slashed module reference
/// from an import alias) plausibly identifies the file `file_path`.
/// Used by both the taint engine and the callgraph as a backstop
/// when [`module_target_matches_decl_module_path`] doesn't resolve —
/// e.g. workspace files that haven't yet had their module path
/// populated. Compares dotted-form parts to slash-form parts with
/// extension stripping, supporting Java-style `com.example.Utils`
/// matching `com/example/Utils.java`.
#[must_use]
pub fn module_target_matches_path(alias_target: &str, file_path: &str) -> bool {
    let target = alias_target.replace('\\', "/");
    let path = file_path.replace('\\', "/");
    let target_parts = module_import_parts(&target);
    let path_parts = module_path_parts(&path);
    let Some(target_leaf) = target_parts.last() else {
        return false;
    };
    if target_parts.len() > 1 {
        if path_parts
            .windows(target_parts.len())
            .any(|window| window == target_parts)
        {
            return true;
        }
        for stripped in absolute_module_prefix_variants(&target_parts) {
            if !stripped.is_empty()
                && stripped.len() <= path_parts.len()
                && path_parts
                    .windows(stripped.len())
                    .any(|window| window == stripped)
            {
                return true;
            }
        }
        // Workspaces are often opened below their language-level
        // module root (`import "app/util"` while the checked-out
        // target path is just `util/util.go`). Keep the match
        // semantic by requiring a real suffix of the import target to
        // appear in the candidate file path; this is path evidence,
        // not a bare callee-name fallback.
        for suffix_start in 1..target_parts.len() {
            let suffix = &target_parts[suffix_start..];
            if !suffix.is_empty()
                && suffix.len() <= path_parts.len()
                && path_parts_contains_workspace_suffix(&path_parts, suffix)
            {
                return true;
            }
        }
        return false;
    }
    if path_parts
        .last()
        .is_some_and(|file| strip_extension(file) == target_leaf.as_str())
    {
        return true;
    }
    if path_parts
        .iter()
        .rev()
        .nth(1)
        .is_some_and(|parent| parent == target_leaf)
    {
        return true;
    }
    false
}

fn path_parts_contains_workspace_suffix(path_parts: &[String], suffix: &[String]) -> bool {
    if suffix.is_empty() || suffix.len() > path_parts.len() {
        return false;
    }
    if suffix.len() > 1 {
        return path_parts.windows(suffix.len()).any(|window| window == suffix);
    }
    let Some(leaf) = suffix.first() else {
        return false;
    };
    path_parts
        .iter()
        .take(path_parts.len().saturating_sub(1))
        .any(|part| part == leaf)
}

/// Split a module import target (`com.example.Utils`,
/// `mod/path/file.dart`) into its identifier segments. Files with
/// dotted shape are split on `.`, slash-shaped paths on `/`.
/// Trailing extensions and `.` / `..` segments are dropped.
#[must_use]
pub fn module_import_parts(text: &str) -> Vec<String> {
    let normalized = text.replace("::", ".");
    let parts: Vec<&str> = if normalized.contains('/') {
        normalized.split('/').collect()
    } else {
        normalized.split('.').collect()
    };
    parts
        .into_iter()
        .filter_map(|part| {
            let part = part.trim();
            (!part.is_empty() && part != "." && part != "..").then(|| strip_extension(part).to_string())
        })
        .collect()
}

fn absolute_module_prefix_variants(parts: &[String]) -> Vec<&[String]> {
    let mut out = Vec::new();
    if matches!(parts.first().map(String::as_str), Some("crate" | "self")) {
        out.push(&parts[1..]);
    }
    let mut start = 0usize;
    while parts.get(start).is_some_and(|part| part == "super") {
        start += 1;
    }
    if start > 0 {
        out.push(&parts[start..]);
    }
    out
}

/// Split an absolute or relative file path (`/abs/dir/file.py`,
/// `dir/file.py`) into its identifier segments. Each segment is
/// extension-stripped so `module_target_matches_path` can compare
/// dotted module form against slash-formed file path.
#[must_use]
pub fn module_path_parts(text: &str) -> Vec<String> {
    text.split('/')
        .filter_map(|part| {
            let part = part.trim();
            (!part.is_empty() && part != "." && part != "..").then(|| strip_extension(part).to_string())
        })
        .collect()
}

/// Drop the last `.<ext>` from a path part. Idempotent on bare
/// segments (`Utils` → `Utils`).
#[must_use]
pub fn strip_extension(part: &str) -> &str {
    part.rsplit_once('.').map_or(part, |(stem, _)| stem)
}

/// Resolve a class / type identifier to every matching class-like
/// decl reachable from the caller's context. Used by callgraph and
/// matcher when locating receiver classes for `[Type, method]`
/// rules. Same semantic-identity contract as
/// [`resolve_callable_with_context`].
#[must_use]
pub fn resolve_class(
    global: &GlobalIndex,
    name: &str,
    ctx: &ResolveContext<'_>,
) -> Vec<bonsai_common::SymbolId> {
    use bonsai_lang_api::DeclKind;
    let collect = |lookup: &str| {
        global
            // CONTEXTLESS_LOOKUP_JUSTIFICATION: this is the semantic
            // class/type resolver primitive; ResolveContext filtering
            // is applied immediately below before candidates leave
            // the function.
            .find_by_name(lookup)
            .iter()
            .filter_map(|symbol| {
                let decl = global.decl_of(*symbol)?;
                let decl_file = global.declaring_file(*symbol)?;
                Some((decl, decl_file))
            })
            .filter(|(decl, _)| {
                matches!(
                    decl.kind,
                    DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface
                )
            })
            .filter(|(decl, decl_file)| visibility_allows(decl, *decl_file, &decl.module_path, ctx))
            .map(|(decl, _)| decl.symbol)
            .collect::<Vec<_>>()
    };
    let mut out = Vec::new();
    for lookup in type_lookup_variants(name) {
        out.extend(collect(&lookup));
        retain_caller_lexical_symbol_candidates(global, &mut out, ctx);
        if !out.is_empty() {
            dedup_symbols(&mut out);
            return out;
        }
    }
    if out.is_empty() {
        if let Some(rewrite) = rewrite_through_alias_map_with_target(name, ctx) {
            for lookup in type_lookup_variants(&rewrite.rewritten) {
                // Exact rewrite trusts the alias map — if the
                // resolver finds a class decl named exactly this,
                // that IS the alias's target.
                out.extend(collect(&lookup));
                if !out.is_empty() {
                    dedup_symbols(&mut out);
                    return out;
                }
                if let Some((_, tail)) = lookup.rsplit_once(['.', ':']) {
                    // Bare-name fallback: workspace-wide lookup of
                    // the leaf identifier. Constrain to the alias
                    // target's module so an unrelated class with
                    // the same leaf identifier doesn't get stitched
                    // in as a spurious candidate.
                    let mut candidates: Vec<SymbolId> = collect(tail);
                    if let Some(target_module) = rewrite.target_module.as_deref() {
                        candidates.retain(|sym| {
                            global.decl_of(*sym).is_some_and(|decl| {
                                let path_match = global
                                    .declaring_file(*sym)
                                    .and_then(|file| {
                                        ctx.file_path_lookup.and_then(|lookup| lookup.path_for(file))
                                    })
                                    .is_some_and(|path| module_target_matches_path(target_module, &path));
                                module_target_matches_decl_module_path_from_context(
                                    target_module,
                                    &decl.module_path,
                                    ctx.caller_module,
                                ) || path_match
                            })
                        });
                    }
                    out.extend(candidates);
                    if !out.is_empty() {
                        dedup_symbols(&mut out);
                        return out;
                    }
                }
            }
        }
    }
    if out.is_empty() && unqualified_lookup_name(name) {
        for lookup in type_lookup_variants(name) {
            for target_module in wildcard_import_modules(ctx) {
                let mut candidates = collect(&lookup);
                candidates.retain(|symbol| symbol_in_alias_target(global, *symbol, target_module, ctx));
                out.extend(candidates);
            }
            if !out.is_empty() {
                dedup_symbols(&mut out);
                return out;
            }
        }
    }
    dedup_symbols(&mut out);
    out
}

fn type_lookup_variants(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    push_unique(&mut out, trimmed.to_string());
    let without_array = strip_trailing_array_suffixes(trimmed);
    push_unique(&mut out, without_array.to_string());
    let without_nullable = without_array.trim_end_matches('?').trim();
    push_unique(&mut out, without_nullable.to_string());
    let erased = erase_angle_generics(without_nullable);
    push_unique(&mut out, erased.trim().to_string());
    out
}

fn strip_trailing_array_suffixes(mut text: &str) -> &str {
    loop {
        let trimmed = text.trim_end();
        if let Some(rest) = trimmed.strip_suffix("[]") {
            text = rest.trim_end();
            continue;
        }
        return trimmed;
    }
}

fn erase_angle_generics(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut depth = 0usize;
    for ch in text.chars() {
        match ch {
            '<' => depth = depth.saturating_add(1),
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    out
}

fn push_unique(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
}

fn dedup_symbols(out: &mut Vec<SymbolId>) {
    let mut seen = AHashSet::new();
    out.retain(|symbol| seen.insert(*symbol));
}

fn dedup_func_ids(out: &mut Vec<bonsai_common::FuncId>) {
    let mut seen = AHashSet::new();
    out.retain(|func| seen.insert(func.raw()));
}

/// Legacy bare-name resolver.
///
/// **Do not use in new code in `crates/resolve`, `crates/callgraph`,
/// `crates/taint`, or `crates/security/src/matcher.rs`.** This entry
/// point exists only for incremental migration to
/// [`resolve_callable_with_context`] and for display-only callers
/// (browse output, tracer printing) where cross-context candidate
/// expansion is acceptable. See
/// `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
#[doc(hidden)]
#[must_use]
pub fn resolve_callable(global: &GlobalIndex, name: &str) -> Vec<bonsai_common::FuncId> {
    use bonsai_lang_api::DeclKind;
    let collect = |lookup: &str| {
        global
            // CONTEXTLESS_LOOKUP_JUSTIFICATION: legacy display-only
            // resolver retained for callers that intentionally list
            // every name match; graph/taint/security edge builders
            // use resolve_callable_with_context instead.
            .find_by_name(lookup)
            .iter()
            .filter_map(|symbol| global.decl_of(*symbol))
            .filter(|decl| {
                matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                )
            })
            .map(|decl| bonsai_common::FuncId::new(decl.symbol.raw()))
            .collect::<Vec<_>>()
    };
    let mut out = collect(name);
    if out.is_empty() {
        if let Some(no_bang) = name.strip_suffix('!') {
            out = collect(no_bang);
        }
    }
    out
}

/// Short tail after the last path separator in a qualified call /
/// reference name. Mirrors the CLI's `short_callee` helper so
/// resolver-driven lookups stay identical regardless of caller.
#[must_use]
pub fn short_tail(name: &str) -> &str {
    short_qualified_tail(name)
}

/// Build a `{local_name → resolved}` alias map from `ImportSpec`s.
/// Covers every symbol- and module-level alias shape adapters emit
/// (`from x import y as z`, `import os as o`, unaliased module
/// bindings such as `import os` / `use std::io`, Go `import "fmt"`
/// self-binding, Scala `{a => b}`, PHP / Kotlin renaming, etc.).
///
/// Source `imports` from `bonsai_db::AnalyzerDb::imports_for` so
/// every downstream pass (browse, matcher, taint reachability)
/// shares the adapter's canonical shape.
#[must_use]
pub fn alias_map_for_file(imports: &[ImportSpec]) -> AHashMap<String, String> {
    let mut map: AHashMap<String, String> = AHashMap::new();
    for import in imports {
        // Symbol-level alias: `from x import y as z` / Kotlin
        // `import x.y.z as Z` — bind `z` → `y`.
        if let (Some(local), Some(original)) = (import.alias.as_deref(), import.original_name.as_deref()) {
            if local != original && !local.is_empty() && !original.is_empty() {
                map.insert(local.to_string(), original.to_string());
            }
        }
        // Module-level alias: `import os as o` (no `original_name`)
        // → `o` → `os`. Self-binding aliases (Go's `import "fmt"`
        // emits `alias=Some("fmt")`) are kept so the taint engine
        // recognises `fmt` as an external package head.
        if let Some(local) = import.alias.as_deref() {
            if import.original_name.is_none() && !local.is_empty() && !import.module.is_empty() {
                map.entry(local.to_string())
                    .or_insert_with(|| import.module.clone());
            }
        }
        // Unaliased module import: derive the local binding from the
        // module path so qualified calls (`os.system`, `std::io::read`)
        // are treated as import-qualified. If the alias target cannot
        // resolve semantically, callers leave the edge unresolved
        // instead of retrying the bare tail.
        if !import.is_wildcard && import.alias.is_none() && import.original_name.is_none() {
            if let Some(local) = module_local_binding(&import.module) {
                map.entry(local).or_insert_with(|| import.module.clone());
            }
        }
    }
    map
}

fn module_local_binding(module: &str) -> Option<String> {
    let trimmed = module
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'))
        .trim_end_matches(['/', '\\'])
        .trim();
    if trimmed.is_empty() {
        return None;
    }
    let path_like = trimmed.contains('/') || trimmed.contains('\\') || trimmed.starts_with('.');
    let mut candidate = if path_like {
        trimmed
            .rsplit(['/', '\\'])
            .next()
            .and_then(strip_known_import_extension)
            .or_else(|| trimmed.rsplit(['/', '\\']).next())
            .unwrap_or(trimmed)
    } else if let Some(stem) = strip_known_import_extension(trimmed) {
        stem.rsplit(['.', ':']).next().unwrap_or(stem)
    } else if let Some((_, tail)) = trimmed.rsplit_once("::") {
        tail
    } else if let Some((_, tail)) = trimmed.rsplit_once(':') {
        tail
    } else if let Some((_, tail)) = trimmed.rsplit_once('.') {
        tail
    } else {
        trimmed
    };
    candidate = candidate.trim();
    let mut chars = candidate.chars();
    let first = chars.next()?;
    if !(first == '_' || first == '$' || first.is_ascii_alphabetic()) {
        return None;
    }
    if !chars.all(|ch| ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()) {
        return None;
    }
    Some(candidate.to_string())
}

fn strip_known_import_extension(module: &str) -> Option<&str> {
    let (stem, ext) = module.rsplit_once('.')?;
    let ext = ext.trim();
    if matches!(
        ext,
        "c" | "cc"
            | "cpp"
            | "cs"
            | "cxx"
            | "dart"
            | "erl"
            | "ex"
            | "exs"
            | "h"
            | "hh"
            | "hpp"
            | "hrl"
            | "java"
            | "js"
            | "kt"
            | "kts"
            | "lua"
            | "m"
            | "mm"
            | "php"
            | "pl"
            | "pm"
            | "py"
            | "rb"
            | "rs"
            | "scala"
            | "sol"
            | "swift"
            | "ts"
    ) {
        Some(stem)
    } else {
        None
    }
}

// Note: a previous version of this file shipped a Go-stdlib package
// allow-list (`looks_like_go_stdlib_subpackage`) plus an
// `add_go_stdlib_import_aliases` pass that re-scanned the source by
// regex to bind unaliased path-tails locally. Both have been deleted.
// The Go adapter (`crates/lang_go/src/lib.rs::parse_imports`) now
// emits `ImportSpec.alias = path_tail` for every unaliased Go import,
// which the standard alias block above handles uniformly. The fix
// keeps `crates/resolve` library/stdlib-agnostic per the
// `docs/contributing/taint-engine-spec.mdx` non-negotiable on hard-coded
// library/API tables in engine crates.

#[cfg(test)]
mod tests;
