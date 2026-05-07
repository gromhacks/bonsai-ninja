//! Module + name resolution.
//!
//! Resolution is inherently language-specific; this crate provides the
//! shared data model and a simple import-graph traversal that most
//! adapters can reuse.

use ahash::{AHashMap, AHashSet};
use bonsai_common::{short_qualified_tail, FileId, SymbolId};
use bonsai_index::GlobalIndex;
use bonsai_lang_api::{AliasTarget, ImportSpec, ModulePath, Visibility};

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
#[derive(Clone, Debug)]
pub struct ResolveContext<'a> {
    pub caller_file: FileId,
    pub caller_module: &'a ModulePath,
    pub receiver_type: Option<SymbolId>,
    pub alias_map: Option<&'a AHashMap<String, AliasTarget>>,
}

impl<'a> ResolveContext<'a> {
    #[must_use]
    pub fn new(caller_file: FileId, caller_module: &'a ModulePath) -> Self {
        Self {
            caller_file,
            caller_module,
            receiver_type: None,
            alias_map: None,
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
    let mut out = collect(name);
    if out.is_empty() {
        if let Some(no_bang) = name.strip_suffix('!') {
            out = collect(no_bang);
        }
    }
    if out.is_empty() {
        if let Some((receiver, method)) = split_member_head_tail(name) {
            out = resolve_callable_member_with_context(global, receiver, method, ctx);
        }
    }
    // Walk the alias map: `cp.exec` where `cp = require("child_process")`
    // should resolve to `child_process.exec`. Without this rewrite,
    // in-workspace aliased calls miss and entry-point inference
    // flags called functions as unreferenced sources.
    if out.is_empty() {
        if let Some(rewritten) = rewrite_through_alias_map(name, ctx) {
            out = collect(&rewritten);
            // Many adapters index decls only by the bare name —
            // retry with the leaf segment.
            if out.is_empty() {
                if let Some((_, tail)) = rewritten.rsplit_once(['.', ':']) {
                    out = collect(tail);
                }
            }
        }
    }
    out
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

/// Rewrite `name` through `ctx.alias_map`. Returns the
/// qualified form (e.g. `child_process.exec`) so the caller can
/// retry the lookup against the workspace decl table.
fn rewrite_through_alias_map(name: &str, ctx: &ResolveContext<'_>) -> Option<String> {
    let map = ctx.alias_map?;
    // Whole-name alias: `req` → `flask.request`.
    if let Some(target) = map.get(name) {
        return Some(match target {
            AliasTarget::Member { module, member } => format!("{module}.{member}"),
            AliasTarget::Namespace { module } => module.clone(),
            AliasTarget::Type { type_name } => type_name.clone(),
        });
    }
    // Qualified-prefix alias: `cp.exec` → `child_process.exec`.
    let (head, tail) = name.split_once(['.', ':'])?;
    let target = map.get(head)?;
    let prefix = match target {
        AliasTarget::Namespace { module } => module.clone(),
        AliasTarget::Member { module, member } => format!("{module}.{member}"),
        AliasTarget::Type { type_name } => type_name.clone(),
    };
    Some(format!("{prefix}.{tail}"))
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
        if !out.is_empty() {
            dedup_symbols(&mut out);
            return out;
        }
    }
    if out.is_empty() {
        if let Some(rewritten) = rewrite_through_alias_map(name, ctx) {
            for lookup in type_lookup_variants(&rewritten) {
                out.extend(collect(&lookup));
                if !out.is_empty() {
                    dedup_symbols(&mut out);
                    return out;
                }
                if let Some((_, tail)) = lookup.rsplit_once(['.', ':']) {
                    out.extend(collect(tail));
                    if !out.is_empty() {
                        dedup_symbols(&mut out);
                        return out;
                    }
                }
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
/// (`from x import y as z`, `import os as o`, Go `import "fmt"` self-
/// binding, Scala `{a => b}`, PHP / Kotlin renaming, etc.).
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
    }
    map
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
mod tests {
    // Path-tail aliasing for unaliased Go imports (`import "io/fs"`
    // → local `fs`) is now an adapter responsibility — see
    // `crates/lang_go/src/lib.rs::parse_imports`. Resolve simply
    // honors `ImportSpec.alias` whether the adapter populated it
    // explicitly or implicitly. Coverage for the path-tail rule
    // lives in the lang_go and per-lang CLI conformance tests.

    use super::*;
    use bonsai_common::{FileId, Span, SymbolId};
    use bonsai_lang_api::{AliasTarget, DeclIndex, ImportScope, ImportSpec, ModulePath};

    fn span() -> Span {
        Span::new(FileId::new(0), 0, 0)
    }

    fn spec(module: &str, alias: Option<&str>, original: Option<&str>) -> ImportSpec {
        ImportSpec {
            span: span(),
            module: module.to_string(),
            alias: alias.map(str::to_string),
            is_wildcard: false,
            original_name: original.map(str::to_string),
            scope: ImportScope::Module,
        }
    }

    #[test]
    fn aliased_member_binds_local_to_original_symbol() {
        // The kotlin double-tail drift guard at the unit level: an
        // adapter that produces `module="x.y", alias="Z",
        // original_name="z"` (the corrected pass-8 shape) must
        // produce `Z → z`, NOT `Z → "x.y.z"`. If a future change
        // re-routes alias resolution through the generic
        // extractor — which would emit `module="x.y.z",
        // alias="Z", original_name=None` — `Z` would map to the
        // dotted module path and downstream callee resolution
        // would expand `Z(...)` to `"x.y.z.z(...)"`.
        let map = alias_map_for_file(&[spec("x.y", Some("Z"), Some("z"))]);
        assert_eq!(map.get("Z").map(String::as_str), Some("z"));
        assert!(
            !map.values().any(|v| v.contains('.')),
            "alias must not be dotted: {map:?}"
        );
    }

    #[test]
    fn from_x_import_y_as_z_binds_z_to_y() {
        // Python `from flask import request as req` → req → request.
        let map = alias_map_for_file(&[spec("flask", Some("req"), Some("request"))]);
        assert_eq!(map.get("req").map(String::as_str), Some("request"));
    }

    #[test]
    fn module_only_alias_binds_local_to_module() {
        // Python `import os as o` → o → os.
        let map = alias_map_for_file(&[spec("os", Some("o"), None)]);
        assert_eq!(map.get("o").map(String::as_str), Some("os"));
    }

    #[test]
    fn member_alias_whole_name_rewrites_to_module_member() {
        let mut map = ahash::AHashMap::new();
        map.insert(
            "u".to_string(),
            AliasTarget::Member {
                module: "pkg".to_string(),
                member: "util".to_string(),
            },
        );
        let module = ModulePath::default();
        let ctx = ResolveContext::new(FileId::new(0), &module).with_alias_map(&map);

        assert_eq!(rewrite_through_alias_map("u", &ctx).as_deref(), Some("pkg.util"));
    }

    #[test]
    fn member_alias_prefix_preserves_imported_member() {
        let mut map = ahash::AHashMap::new();
        map.insert(
            "u".to_string(),
            AliasTarget::Member {
                module: "pkg".to_string(),
                member: "util".to_string(),
            },
        );
        let module = ModulePath::default();
        let ctx = ResolveContext::new(FileId::new(0), &module).with_alias_map(&map);

        assert_eq!(
            rewrite_through_alias_map("u.run", &ctx).as_deref(),
            Some("pkg.util.run")
        );
    }

    #[test]
    fn self_binding_alias_kept_for_external_head_detection() {
        // Go `import "fmt"` (adapter sets alias = path tail)
        // → fmt → fmt. The taint engine relies on this entry
        // existing so `fmt.Println` is recognised as an external-
        // package head instead of bare-tailing into a workspace
        // function literally named `Println`.
        let map = alias_map_for_file(&[spec("fmt", Some("fmt"), None)]);
        assert_eq!(map.get("fmt").map(String::as_str), Some("fmt"));
    }

    #[test]
    fn class_resolution_rewrites_alias_map() {
        let mut global = GlobalIndex::new();
        let file = FileId::new(1);
        let span = Span::new(file, 0, 20);
        let class = bonsai_lang_api::Decl {
            symbol: SymbolId::new(0),
            kind: bonsai_lang_api::DeclKind::Class,
            name: "Service".to_string(),
            qualified_name: Some("pkg.Service".to_string()),
            module_path: ModulePath::from_segments(["pkg"]),
            span,
            name_span: span,
            visibility: bonsai_lang_api::Visibility::Public,
            parent: None,
            body_span: None,
            flow_events: Vec::new(),
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
        };
        global.insert(DeclIndex {
            file,
            defs: vec![class],
            refs: Vec::new(),
            strings: Vec::new(),
            comments: Vec::new(),
        });

        let caller_module = ModulePath::from_segments(["pkg"]);
        let mut aliases = AHashMap::new();
        aliases.insert(
            "Svc".to_string(),
            AliasTarget::Type {
                type_name: "pkg.Service".to_string(),
            },
        );
        let ctx = ResolveContext::new(file, &caller_module).with_alias_map(&aliases);
        let hits = resolve_class(&global, "Svc", &ctx);
        assert_eq!(hits.len(), 1, "aliased type should resolve by rewritten tail");
    }

    #[test]
    fn redundant_alias_equal_to_original_is_skipped() {
        // `from x import y as y` would produce a no-op binding.
        // We skip redundant entries to keep the map tight.
        let map = alias_map_for_file(&[spec("x", Some("y"), Some("y"))]);
        assert!(map.is_empty(), "redundant alias should not emit: {map:?}");
    }

    #[test]
    fn empty_inputs_produce_empty_map() {
        assert!(alias_map_for_file(&[]).is_empty());
    }

    #[test]
    fn first_alias_wins_on_collision() {
        // `import os as o` followed by `import "other" as o` —
        // first entry wins for the module-alias case (insert via
        // `entry().or_insert_with`).
        let map = alias_map_for_file(&[spec("os", Some("o"), None), spec("other", Some("o"), None)]);
        assert_eq!(map.get("o").map(String::as_str), Some("os"));
    }

    #[test]
    fn unaliased_import_produces_no_entry() {
        // `import os` (no alias, no original_name) — nothing to
        // bind locally; downstream callee lookup falls through to
        // bare-name resolution.
        let map = alias_map_for_file(&[spec("os", None, None)]);
        assert!(map.is_empty(), "unaliased import should not emit: {map:?}");
    }
}
