//! `bonsai-ninja search` data layer — prefix-first fuzzy search
//! across every browse-fact kind in the workspace (not just decls).
//!
//! A search hit can originate from any of the browse surfaces
//! `bonsai-ninja` exposes: source file, function / method / class / struct decl,
//! call-site callee, import module / alias, variable assignment
//! target, string literal, comment text, call-site argument value,
//! class decl, reference (read / write / call). Every hit carries a uniform
//! `kind` tag plus its source location so scripts can filter and
//! humans can see in one glance which surface surfaced the match.
//!
//! Ranking is prefix-match first, then shortest name, then
//! `(file, line)` — preserving the de-duplication behavior from the
//! original declaration search
//! for name-shaped facts, extended to the other kinds.

use crate::common::{file_path_matches_filter, format_span};
use crate::refs::read_snippet;
use ahash::AHashSet;
use bonsai_lang_api::{FlowEvent, RefKind};
use bonsai_workspace::Workspace;
use serde::Serialize;
use std::collections::HashSet;

/// Filter bundle for [`search`].
#[derive(Copy, Clone, Default, Debug)]
pub struct SearchFilters<'a> {
    /// Restrict to one fact-kind tag (e.g. `function`, `call`,
    /// `import`, `var`, `string`, `comment`, `arg`, `class`, `ref`). Matches
    /// case-insensitively against the hit's `kind` field.
    pub kind: Option<&'a str>,
    /// Keep only hits whose workspace-relative source file path matches this text.
    /// Explicit absolute paths are also accepted.
    pub file: Option<&'a str>,
    /// Interpret `query` as a regex instead of a substring.
    pub regex: bool,
}

/// One ranked search result. Shape is uniform across every fact
/// kind — callers don't have to destructure an enum to render.
#[derive(Clone, Debug, Serialize)]
pub struct SearchHit {
    /// Text the matcher matched (decl name / callee / module /
    /// assign target / string body / arg value / ref name).
    pub name: String,
    /// Fact-kind tag: `file` / `function` / `method` / `class` / `struct` /
    /// `trait` / `interface` / `enum` / `constructor` / `call` /
    /// `import` / `import-alias` / `var` / `string` / `arg` /
    /// `comment` / `ref-read` / `ref-write` / `ref-call` / `ref-decorator`.
    pub kind: String,
    /// Only present for decl-kind hits; otherwise `None`.
    pub qualified_name: Option<String>,
    /// Signature / context depending on kind: the function's
    /// params, the import's alias, the ref's enclosing function,
    /// etc. `None` when the kind has no natural context snippet.
    pub context: Option<String>,
    pub file: String,
    pub line: u32,
    pub column: u32,
    /// Source line at `(file, line)`, widened to line edges — so
    /// humans can see the actual code that produced the hit without
    /// re-opening the file. Empty when the VFS can't read the file.
    pub code: String,
}

/// Search the workspace across every browse-fact kind for hits
/// matching `query`. Results are ranked prefix-first, shortest
/// name next, then `(file, line)` for stable ordering. `limit`
/// caps the returned count.
pub fn search(
    ws: &Workspace,
    query: &str,
    f: &SearchFilters<'_>,
    limit: usize,
) -> Result<Vec<SearchHit>, regex::Error> {
    if !f.regex {
        if let Ok(index) = bonsai_retrieval::load_or_build_sidecar(ws) {
            let candidates = index.query(&bonsai_retrieval::RetrievalQuery {
                text: query,
                kind: f.kind,
                file: f.file,
                workspace_root: ws.db().workspace_root().as_deref(),
                regex: false,
                limit: 0,
            })?;
            if candidates.is_empty() {
                return Ok(Vec::new());
            }
            let candidate_files: HashSet<String> =
                candidates.iter().map(|doc| doc.file_path.clone()).collect();
            // Retrieval is only a conservative file-candidate lookup. An
            // explicitly warmed sidecar stores one compact projection per
            // `(file, fact kind)`, while the small-workspace on-demand path
            // can hold individual fact documents. Neither representation is
            // public evidence, and their ids are intentionally not required
            // to equal the ids of canonical rendered rows. Hydrate every
            // exact substring match in the candidate files through the AST
            // facts instead of treating candidate metadata as an allow-list
            // of renderable fact identities.
            let mut hydrated = search_canonical(ws, query, f, usize::MAX, Some(&candidate_files))?;
            hydrated.truncate(limit);
            return Ok(hydrated);
        }
    }
    search_canonical(ws, query, f, limit, None)
}

fn search_canonical(
    ws: &Workspace,
    query: &str,
    f: &SearchFilters<'_>,
    limit: usize,
    candidate_files: Option<&HashSet<String>>,
) -> Result<Vec<SearchHit>, regex::Error> {
    use rayon::prelude::*;
    let q_lower = query.to_lowercase();
    // `Send + Sync` matcher shared across rayon workers.
    let matcher: Box<dyn Fn(&str) -> bool + Send + Sync> = if f.regex {
        let re = regex::Regex::new(query)?;
        Box::new(move |s: &str| re.is_match(s))
    } else {
        let needle = q_lower.clone();
        Box::new(move |s: &str| s.to_lowercase().contains(&needle))
    };
    let kind_filter = f.kind.map(str::to_lowercase);
    let file_filter = f.file;
    let files = ws.vfs().all_files();

    let mut hits: Vec<SearchHit> = files
        .par_iter()
        .flat_map_iter(|&file_id| {
            let mut per_file: Vec<SearchHit> = Vec::new();
            let file_path = ws
                .vfs()
                .path(file_id)
                .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
            if candidate_files.is_some_and(|files| !files.contains(&file_path)) {
                return per_file.into_iter();
            }
            if let Some(needle) = file_filter {
                if !file_path_matches_filter(ws, &file_path, needle) {
                    return per_file.into_iter();
                }
            }
            // Closure pushed by every fact-collector below — keeps
            // the kind filter centralised so each surface doesn't
            // re-check it.
            let push = |out: &mut Vec<SearchHit>, hit: SearchHit| {
                if let Some(kind_needle) = kind_filter.as_deref() {
                    if !hit.kind.to_lowercase().contains(kind_needle) {
                        return;
                    }
                }
                out.push(hit);
            };
            let Some(object) = ws.db().compiler_file_object_uncached(file_id) else {
                return per_file.into_iter();
            };
            let Some(index) = object.declarations.as_ref() else {
                return per_file.into_iter();
            };

            // 1. Source files. Retrieval persists `kind=file` docs,
            // and canonical search must expose the same row shape so
            // retrieval candidates hydrate instead of rendering from
            // candidate metadata.
            let file_name = std::path::Path::new(&file_path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(file_path.as_str());
            if matcher(&file_path) || matcher(file_name) {
                let language = ws
                    .db()
                    .adapter_for(file_id)
                    .map(|adapter| adapter.language_id().as_str().to_string());
                let code = ws
                    .vfs()
                    .snapshot(file_id)
                    .ok()
                    .and_then(|snapshot| snapshot.text.lines().next().map(str::to_string))
                    .unwrap_or_default();
                push(
                    &mut per_file,
                    SearchHit {
                        name: file_name.to_string(),
                        kind: "file".to_string(),
                        qualified_name: Some(file_path.clone()),
                        context: language,
                        file: file_path.clone(),
                        line: 1,
                        column: 1,
                        code,
                    },
                );
            }

            // 2. Decls (functions / methods / classes / structs / ...).
            for decl in &index.defs {
                let name_hit = matcher(&decl.name);
                let qname_hit = decl.qualified_name.as_ref().is_some_and(|n| matcher(n));
                if name_hit || qname_hit {
                    let (path, line, col) = format_span(&decl.name_span, ws);
                    let kind_str = format!("{:?}", decl.kind).to_lowercase();
                    // Display "name(params)" for callables, bare
                    // name for everything else.
                    let signature = if decl.params.is_empty() {
                        decl.name.clone()
                    } else {
                        format!("{}({})", decl.name, decl.params.join(", "))
                    };
                    let code = read_snippet(ws, &decl.name_span);
                    push(
                        &mut per_file,
                        SearchHit {
                            name: decl.name.clone(),
                            kind: kind_str,
                            qualified_name: decl.qualified_name.clone(),
                            context: Some(signature),
                            file: path,
                            line,
                            column: col,
                            code,
                        },
                    );
                }

                // 3. Flow-event facts INSIDE each decl: calls, assigns,
                //    arg values, string literals.
                walk_flow_events(&decl.flow_events, &decl.name, ws, &matcher, |hit| {
                    push(&mut per_file, hit);
                });
            }

            // 4. Imports. Search is a browse/display surface, so it
            // uses the same generic syntax fallback as inspect and
            // retrieval when an adapter returns no import rows. This
            // does not change resolver/taint alias semantics, where
            // the adapter ImportIndex remains authoritative.
            for imp in object
                .imports
                .as_ref()
                .into_iter()
                .flat_map(|imports| imports.imports.iter())
            {
                let mod_hit = matcher(&imp.module);
                let alias_hit = imp.alias.as_ref().is_some_and(|a| matcher(a));
                let orig_hit = imp.original_name.as_ref().is_some_and(|o| matcher(o));
                if !(mod_hit || alias_hit || orig_hit) {
                    continue;
                }
                let (path, line, col) = format_span(&imp.span, ws);
                let kind = if imp.alias.is_some() {
                    "import-alias"
                } else {
                    "import"
                }
                .to_string();
                let context = imp
                    .alias
                    .as_ref()
                    .map(|a| format!("{} as {a}", imp.module))
                    .or_else(|| {
                        imp.original_name
                            .as_ref()
                            .map(|o| format!("{} from {}", o, imp.module))
                    });
                let code = read_snippet(ws, &imp.span);
                push(
                    &mut per_file,
                    SearchHit {
                        name: imp.module.clone(),
                        kind,
                        qualified_name: None,
                        context,
                        file: path,
                        line,
                        column: col,
                        code,
                    },
                );
            }

            // 5. Refs (read / write / call / decorator references
            //    captured by the adapter's ref extractor).
            {
                for r in &index.refs {
                    if !matcher(&r.name) {
                        continue;
                    }
                    let (path, line, col) = format_span(&r.span, ws);
                    let kind = match r.kind {
                        RefKind::Read => "ref-read",
                        RefKind::Write => "ref-write",
                        RefKind::Call => "ref-call",
                        RefKind::Decorator => "ref-decorator",
                        _ => "ref",
                    }
                    .to_string();
                    let code = read_snippet(ws, &r.span);
                    push(
                        &mut per_file,
                        SearchHit {
                            name: r.name.clone(),
                            kind,
                            qualified_name: None,
                            context: None,
                            file: path,
                            line,
                            column: col,
                            code,
                        },
                    );
                }
                // 6. File-scoped string literals. (Call-arg strings
                //    are covered by the in-decl flow walk above; this
                //    block picks up top-level string facts the
                //    adapter exposes at file scope.)
                for s in &index.strings {
                    if !matcher(&s.text) {
                        continue;
                    }
                    let (path, line, col) = format_span(&s.span, ws);
                    let code = read_snippet(ws, &s.span);
                    push(
                        &mut per_file,
                        SearchHit {
                            name: s.text.clone(),
                            kind: "string".to_string(),
                            qualified_name: None,
                            context: Some(format!("{:?}", s.category).to_lowercase()),
                            file: path,
                            line,
                            column: col,
                            code,
                        },
                    );
                }
                // 7. Comments. Comments are a first-class browse
                //    surface, so search includes their stripped text
                //    and exposes the adapter's comment category as
                //    context.
                for c in &index.comments {
                    if !matcher(&c.text) {
                        continue;
                    }
                    let (path, line, col) = format_span(&c.span, ws);
                    let code = read_snippet(ws, &c.span);
                    push(
                        &mut per_file,
                        SearchHit {
                            name: c.text.clone(),
                            kind: "comment".to_string(),
                            qualified_name: None,
                            context: Some(format!("{:?}", c.kind).to_lowercase()),
                            file: path,
                            line,
                            column: col,
                            code,
                        },
                    );
                }
            }

            per_file.into_iter()
        })
        .collect();

    // Dedup: the adapter's ref table and the in-decl flow walk
    // frequently describe the same site — e.g. a `FlowEvent::Call`
    // and a `RefKind::Call` pointing at the same `(name, file,
    // line, column)`. Collapse those pairs so the UI shows each
    // source site exactly once. The "richer" kind (non-`ref-`)
    // wins: `call` beats `ref-call`, `var` beats `ref-write`,
    // decl kinds beat `ref-read`. Ties keep the first seen.
    //
    // Sort key puts richer kinds first within each `(file, line,
    // column, name)` cluster so `dedup_by` keeps the richest row.
    hits.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
            .then(a.name.cmp(&b.name))
            .then(kind_rank(&a.kind).cmp(&kind_rank(&b.kind)))
    });
    hits.dedup_by(|a, b| a.name == b.name && a.file == b.file && a.line == b.line && a.column == b.column);

    // Deterministic ranking: prefix match first, then shorter
    // names, then (file, line). Same discipline as the old decl-
    // only path so existing tests keep their ordering semantics.
    hits.sort_by(|a, b| {
        let aprefix = a.name.to_lowercase().starts_with(&q_lower);
        let bprefix = b.name.to_lowercase().starts_with(&q_lower);
        bprefix
            .cmp(&aprefix)
            .then(a.name.len().cmp(&b.name.len()))
            .then(a.file.cmp(&b.file))
            .then(a.line.cmp(&b.line))
            .then(a.kind.cmp(&b.kind))
    });
    hits.truncate(limit);
    Ok(hits)
}

/// Lower rank = more informative, so wins when dedupping a
/// `(name, file, line, column)` collision. Decl kinds are the
/// most specific; the `ref-*` family is a catch-all adapter
/// output that typically duplicates a flow-event fact, so it
/// ranks last.
fn kind_rank(kind: &str) -> u8 {
    match kind {
        "function" | "method" | "class" | "struct" | "trait" | "interface" | "enum" | "constructor" => 0,
        "call" | "var" | "arg" | "string" | "comment" | "import" | "import-alias" | "file" => 1,
        k if k.starts_with("ref-") => 2,
        _ => 3,
    }
}

/// Recurse through a decl's `flow_events` collecting Call / Assign /
/// Arg / Yield-expression / String hits. The caller's `push`
/// closure handles the final kind-filter check + append.
fn walk_flow_events<M, P>(events: &[FlowEvent], in_fn: &str, ws: &Workspace, matcher: &M, mut push: P)
where
    M: Fn(&str) -> bool,
    P: FnMut(SearchHit),
{
    walk_flow_events_inner(events, in_fn, ws, matcher, &mut push);
}

fn walk_flow_events_inner<M>(
    events: &[FlowEvent],
    in_fn: &str,
    ws: &Workspace,
    matcher: &M,
    push: &mut dyn FnMut(SearchHit),
) where
    M: Fn(&str) -> bool,
{
    let explicit_shadows = explicit_flow_shadows(events, in_fn, ws);
    for e in events {
        match e {
            FlowEvent::Call { name, args, span, .. } => {
                if matcher(name) {
                    let (path, line, col) = format_span(span, ws);
                    let code = read_snippet(ws, span);
                    push(SearchHit {
                        name: name.clone(),
                        kind: "call".to_string(),
                        qualified_name: None,
                        context: Some(format!("in {in_fn}")),
                        file: path,
                        line,
                        column: col,
                        code,
                    });
                }
                for arg in args {
                    if matcher(&arg.value_text) {
                        let (path, line, col) = format_span(&arg.span, ws);
                        let code = read_snippet(ws, &arg.span);
                        push(SearchHit {
                            name: arg.value_text.clone(),
                            kind: "arg".to_string(),
                            qualified_name: None,
                            context: Some(format!("{name}(...) in {in_fn}")),
                            file: path,
                            line,
                            column: col,
                            code,
                        });
                    }
                }
            }
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } => {
                if matcher(target) {
                    let (path, line, col) = format_span(span, ws);
                    let code = read_snippet(ws, span);
                    let ctx = source_name
                        .as_deref()
                        .map(|s| format!("{target} = {s} in {in_fn}"))
                        .unwrap_or_else(|| format!("in {in_fn}"));
                    push(SearchHit {
                        name: target.clone(),
                        kind: "var".to_string(),
                        qualified_name: None,
                        context: Some(ctx),
                        file: path,
                        line,
                        column: col,
                        code,
                    });
                }
                if let Some(name) = source_call {
                    if matcher(name) {
                        let (path, line, col) = format_span(span, ws);
                        let shadow_key = (name.clone(), path.clone(), line, in_fn.to_string());
                        if !explicit_shadows.calls.contains(&shadow_key) {
                            let code = read_snippet(ws, span);
                            push(SearchHit {
                                name: name.clone(),
                                kind: "call".to_string(),
                                qualified_name: None,
                                context: Some(format!("in {in_fn}")),
                                file: path,
                                line,
                                column: col,
                                code,
                            });
                        }
                    }
                    for arg in source_call_args {
                        if matcher(arg) {
                            let (path, line, col) = format_span(span, ws);
                            let shadow_key =
                                (name.clone(), arg.clone(), path.clone(), line, in_fn.to_string());
                            if explicit_shadows.args.contains(&shadow_key) {
                                continue;
                            }
                            let code = read_snippet(ws, span);
                            push(SearchHit {
                                name: arg.clone(),
                                kind: "arg".to_string(),
                                qualified_name: None,
                                context: Some(format!("{name}(...) in {in_fn}")),
                                file: path,
                                line,
                                column: col,
                                code,
                            });
                        }
                    }
                }
                for source in source_names {
                    if matcher(source) {
                        let (path, line, col) = format_span(span, ws);
                        let code = read_snippet(ws, span);
                        push(SearchHit {
                            name: source.clone(),
                            kind: "ref-read".to_string(),
                            qualified_name: None,
                            context: Some(format!("in {in_fn}")),
                            file: path,
                            line,
                            column: col,
                            code,
                        });
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk_flow_events_inner(then_events, in_fn, ws, matcher, push);
                walk_flow_events_inner(else_events, in_fn, ws, matcher, push);
            }
            FlowEvent::Loop { body, .. } => {
                walk_flow_events_inner(body, in_fn, ws, matcher, push);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                walk_flow_events_inner(body, in_fn, ws, matcher, push);
                walk_flow_events_inner(catch_events, in_fn, ws, matcher, push);
                walk_flow_events_inner(finally_events, in_fn, ws, matcher, push);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_flow_events_inner(body, in_fn, ws, matcher, push);
            }
            _ => {}
        }
    }
}

type ExplicitCallShadowKey = (String, String, u32, String);
type ExplicitArgShadowKey = (String, String, String, u32, String);

struct ExplicitFlowShadows {
    calls: AHashSet<ExplicitCallShadowKey>,
    args: AHashSet<ExplicitArgShadowKey>,
}

fn explicit_flow_shadows(events: &[FlowEvent], in_fn: &str, ws: &Workspace) -> ExplicitFlowShadows {
    let mut shadows = ExplicitFlowShadows {
        calls: AHashSet::new(),
        args: AHashSet::new(),
    };
    collect_explicit_flow_shadows(events, in_fn, ws, &mut shadows);
    shadows
}

fn collect_explicit_flow_shadows(
    events: &[FlowEvent],
    in_fn: &str,
    ws: &Workspace,
    shadows: &mut ExplicitFlowShadows,
) {
    for event in events {
        match event {
            FlowEvent::Call { name, args, span, .. } => {
                let (path, line, _) = format_span(span, ws);
                shadows
                    .calls
                    .insert((name.clone(), path.clone(), line, in_fn.to_string()));
                for arg in args {
                    shadows.args.insert((
                        name.clone(),
                        arg.value_text.clone(),
                        path.clone(),
                        line,
                        in_fn.to_string(),
                    ));
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_explicit_flow_shadows(then_events, in_fn, ws, shadows);
                collect_explicit_flow_shadows(else_events, in_fn, ws, shadows);
            }
            FlowEvent::Loop { body, .. } => {
                collect_explicit_flow_shadows(body, in_fn, ws, shadows);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_explicit_flow_shadows(body, in_fn, ws, shadows);
                collect_explicit_flow_shadows(catch_events, in_fn, ws, shadows);
                collect_explicit_flow_shadows(finally_events, in_fn, ws, shadows);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_explicit_flow_shadows(body, in_fn, ws, shadows);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_common::FileId;
    use bonsai_lang_api::{
        AdapterContext, AdapterError, DeclIndex, ImportIndex, LanguageAdapter, LanguageCapabilities,
        LanguageId, LanguageRegistry,
    };
    use std::sync::Arc;

    struct EmptyImportPythonAdapter;

    impl LanguageAdapter for EmptyImportPythonAdapter {
        fn language_id(&self) -> LanguageId {
            LanguageId::new("python")
        }

        fn display_name(&self) -> &'static str {
            "Python with empty import index"
        }

        fn file_extensions(&self) -> &'static [&'static str] {
            &["py"]
        }

        fn tree_sitter_language(&self) -> Result<tree_sitter::Language, AdapterError> {
            bonsai_lang_python::PythonAdapter::new().tree_sitter_language()
        }

        fn capabilities(&self) -> LanguageCapabilities {
            LanguageCapabilities::unsupported()
        }

        fn extract_declarations(&self, file: FileId, _ctx: &AdapterContext<'_>) -> DeclIndex {
            DeclIndex {
                file,
                ..DeclIndex::default()
            }
        }

        fn extract_imports(&self, file: FileId, _ctx: &AdapterContext<'_>) -> ImportIndex {
            ImportIndex {
                file,
                imports: Vec::new(),
            }
        }
    }

    fn hit_signature(hit: &SearchHit) -> (String, String, String, u32, u32) {
        (
            hit.kind.clone(),
            hit.name.clone(),
            hit.file.clone(),
            hit.line,
            hit.column,
        )
    }

    fn signatures(hits: &[SearchHit]) -> Vec<(String, String, String, u32, u32)> {
        hits.iter().map(hit_signature).collect()
    }

    fn assignment_verify_token_call_hits(hits: &[SearchHit]) -> Vec<&SearchHit> {
        hits.iter()
            .filter(|hit| {
                hit.kind == "call"
                    && hit.name == "verify_token"
                    && hit.code.contains("user_id = verify_token(token)")
            })
            .collect()
    }

    fn assignment_verify_token_arg_hits<'a>(hits: &'a [SearchHit], arg: &str) -> Vec<&'a SearchHit> {
        hits.iter()
            .filter(|hit| {
                hit.kind == "arg"
                    && hit.name == arg
                    && hit.context.as_deref() == Some("verify_token(...) in get_user")
                    && hit.code.contains("user_id = verify_token(token)")
            })
            .collect()
    }

    #[test]
    fn search_imports_respect_authoritative_adapter_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = "from os import system as run_command\n";
        std::fs::write(dir.path().join("app.py"), source).expect("write fixture");
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(EmptyImportPythonAdapter));
        let ws = Workspace::index(dir.path(), registry).expect("index fixture");
        let filters = SearchFilters {
            kind: Some("import"),
            ..SearchFilters::default()
        };

        assert!(
            ws.db()
                .import_index(ws.vfs().all_files()[0])
                .expect("adapter import index")
                .imports
                .is_empty(),
            "test fixture must provide an authoritative empty adapter index"
        );

        let canonical =
            search_canonical(&ws, "run_command", &filters, usize::MAX, None).expect("canonical search");
        let retrieved = search(&ws, "run_command", &filters, usize::MAX).expect("retrieval search");

        assert!(
            canonical.is_empty(),
            "canonical search must not override an adapter's authoritative empty import index"
        );
        assert_eq!(
            signatures(&retrieved),
            signatures(&canonical),
            "retrieval search must hydrate through the same canonical import facts"
        );
    }

    #[test]
    fn retrieval_backed_search_matches_canonical_search_and_writes_sidecar() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = r#"
import os as operating_system

# notify-admin/audit marker
def handle_request(token):
    command = "notify-admin/audit"
    os.system(command)
    return command
"#;
        std::fs::write(dir.path().join("app.py"), source).expect("write fixture");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");
        let filters = SearchFilters::default();

        let canonical = search_canonical(&ws, "notify-admin/audit", &filters, usize::MAX, None)
            .expect("canonical search");
        let retrieved = search(&ws, "notify-admin/audit", &filters, usize::MAX).expect("retrieval search");

        assert!(
            bonsai_retrieval::retrieval_sidecar_path(dir.path()).is_file(),
            "retrieval-backed search should build the missing sidecar on demand"
        );
        assert_eq!(
            signatures(&retrieved),
            signatures(&canonical),
            "retrieval candidates must hydrate back to the canonical search rows"
        );
    }

    #[test]
    fn persisted_file_candidate_sidecar_hydrates_prefix_matches() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("gateway.py"),
            "def handle_request():\n    return 1\n",
        )
        .expect("write fixture");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");
        bonsai_retrieval::ensure_sidecar(&ws, dir.path()).expect("persist compact candidate sidecar");
        let filters = SearchFilters::default();

        let canonical =
            search_canonical(&ws, "hand", &filters, usize::MAX, None).expect("canonical prefix search");
        let retrieved = search(&ws, "hand", &filters, usize::MAX).expect("retrieval prefix search");

        assert!(canonical.iter().any(|hit| hit.name == "handle_request"));
        assert_eq!(
            signatures(&retrieved),
            signatures(&canonical),
            "compact file candidates must narrow hydration without filtering canonical AST rows by candidate id"
        );
    }

    #[test]
    fn retrieval_backed_search_matches_canonical_across_search_surfaces() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = r#"
from os import system as run_command
from flask import request

# REVIEW: notify-admin audit marker
def helper(user_value):
    copied_value = user_value
    command = "notify-admin/audit"
    run_command(command)
    return copied_value
"#;
        std::fs::write(dir.path().join("app.py"), source).expect("write fixture");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");
        let filters = SearchFilters::default();

        for query in [
            "helper",
            "system",
            "run_command",
            "request",
            "copied_value",
            "user_value",
            "notify-admin/audit",
            "REVIEW",
            "command",
        ] {
            let canonical =
                search_canonical(&ws, query, &filters, usize::MAX, None).expect("canonical search");
            let retrieved = search(&ws, query, &filters, usize::MAX).expect("retrieval search");
            assert_eq!(
                signatures(&retrieved),
                signatures(&canonical),
                "retrieval candidates must preserve canonical search rows for query {query:?}"
            );
        }
    }

    #[test]
    fn retrieval_backed_search_hydrates_file_candidates_through_canonical_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("app.py"), "def unrelated():\n    return 1\n").expect("write app");
        std::fs::write(
            dir.path().join("service.py"),
            "def handle_request(request):\n    return request\n",
        )
        .expect("write service");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");
        let filters = SearchFilters {
            kind: Some("file"),
            ..SearchFilters::default()
        };

        let canonical =
            search_canonical(&ws, "service.py", &filters, usize::MAX, None).expect("canonical file search");
        let retrieved = search(&ws, "service.py", &filters, usize::MAX).expect("retrieval file search");

        assert_eq!(
            signatures(&retrieved),
            signatures(&canonical),
            "retrieval file candidates must hydrate through canonical file rows"
        );
        assert_eq!(retrieved.len(), 1);
        let hit = &retrieved[0];
        assert_eq!(hit.kind, "file");
        assert_eq!(hit.name, "service.py");
        assert_eq!(hit.line, 1);
        assert_eq!(hit.column, 1);
        assert_eq!(
            hit.qualified_name.as_deref(),
            Some(hit.file.as_str()),
            "file rows should carry the full path as qualified_name"
        );
    }

    #[test]
    fn retrieval_backed_search_rebuilds_stale_sidecar_after_source_edit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("app.py");
        std::fs::write(
            &path,
            r#"
def old_symbol():
    return "old"
"#,
        )
        .expect("write initial fixture");
        let filters = SearchFilters::default();
        let first_ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

        let old_hits = search(&first_ws, "old_symbol", &filters, usize::MAX).expect("first search");
        assert!(
            old_hits.iter().any(|hit| hit.name == "old_symbol"),
            "initial search should find the original symbol"
        );
        assert!(
            bonsai_retrieval::retrieval_sidecar_path(dir.path()).is_file(),
            "first retrieval-backed search should write the sidecar"
        );

        std::fs::write(
            &path,
            r#"
def new_symbol():
    return "new"
"#,
        )
        .expect("write edited fixture");
        let second_ws = Workspace::index(dir.path(), bonsai_adapters::all_languages_registry())
            .expect("re-index fixture");

        let stale_hits = search(&second_ws, "old_symbol", &filters, usize::MAX).expect("stale query");
        assert!(
            stale_hits.is_empty(),
            "retrieval-backed search must reject and rebuild a sidecar whose source fingerprint is stale"
        );
        let new_hits = search(&second_ws, "new_symbol", &filters, usize::MAX).expect("new query");
        assert!(
            new_hits.iter().any(|hit| hit.name == "new_symbol"),
            "rebuilt retrieval sidecar should expose the edited symbol"
        );
    }

    #[test]
    fn scoped_literal_search_does_not_write_whole_workspace_retrieval_sidecar() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            r#"
def scoped_marker():
    return "needle"
"#,
        )
        .expect("write fixture");
        std::fs::write(
            dir.path().join("other.py"),
            r#"
def unrelated():
    return "other"
"#,
        )
        .expect("write second fixture");

        let ws = Workspace::open_query_matching_literal(
            dir.path(),
            bonsai_adapters::all_languages_registry(),
            "needle",
        )
        .expect("open literal-scoped workspace");
        assert!(
            !ws.is_complete_workspace_index(),
            "literal-scoped workspaces must be marked incomplete for sidecar persistence"
        );

        let filters = SearchFilters::default();
        let hits = search(&ws, "scoped_marker", &filters, usize::MAX).expect("scoped search");

        assert!(
            hits.iter().any(|hit| hit.name == "scoped_marker"),
            "scoped search should still render canonical syntax facts"
        );
        assert!(
            !bonsai_retrieval::retrieval_sidecar_path(dir.path()).exists(),
            "scoped query workspaces must not write reusable whole-workspace retrieval sidecars"
        );
    }

    #[test]
    fn large_search_falls_back_without_query_time_retrieval_build() {
        let dir = tempfile::tempdir().expect("tempdir");
        for idx in 0..513 {
            let body = if idx == 512 {
                "def needle_symbol():\n    return 'needle'\n".to_string()
            } else {
                format!("def helper_{idx}():\n    return {idx}\n")
            };
            std::fs::write(dir.path().join(format!("file_{idx}.py")), body).expect("write fixture");
        }
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");
        assert!(
            ws.is_complete_workspace_index(),
            "full workspace opens remain eligible for explicit sidecar producers"
        );

        let filters = SearchFilters::default();
        let hits = search(&ws, "needle_symbol", &filters, usize::MAX).expect("large search");

        assert!(
            hits.iter().any(|hit| hit.name == "needle_symbol"),
            "large search should fall back to canonical syntax facts when retrieval is not warm"
        );
        assert!(
            !bonsai_retrieval::retrieval_sidecar_path(dir.path()).exists(),
            "large query-time search should not build retrieval; index --semantic/cache rebuild owns that cost"
        );
    }

    #[test]
    fn search_drops_assignment_call_shadow_when_explicit_call_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = r#"
def verify_token(token):
    return token

def get_user(token):
    user_id = verify_token(token)
    return user_id
"#;
        std::fs::write(dir.path().join("app.py"), source).expect("write fixture");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");
        let filters = SearchFilters::default();

        let canonical =
            search_canonical(&ws, "verify_token", &filters, usize::MAX, None).expect("canonical search");
        let retrieved = search(&ws, "verify_token", &filters, usize::MAX).expect("retrieval search");

        for hits in [&canonical, &retrieved] {
            let call_hits = assignment_verify_token_call_hits(hits);
            assert_eq!(
                call_hits.len(),
                1,
                "search should render the explicit call-site row and drop the assignment-source shadow"
            );
            let expected_column = u32::try_from(
                call_hits[0]
                    .code
                    .find("verify_token")
                    .expect("callee in source line")
                    + 1,
            )
            .expect("column fits u32");
            assert_eq!(
                call_hits[0].column, expected_column,
                "the kept call hit should point at the callee token, not the assignment target"
            );
        }
    }

    #[test]
    fn search_drops_assignment_arg_shadow_when_explicit_call_arg_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = r#"
def verify_token(token):
    return token

def get_user(token):
    user_id = verify_token(token)
    return user_id
"#;
        std::fs::write(dir.path().join("app.py"), source).expect("write fixture");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");
        let filters = SearchFilters {
            kind: Some("arg"),
            ..SearchFilters::default()
        };

        let canonical = search_canonical(&ws, "token", &filters, usize::MAX, None).expect("canonical search");
        let retrieved = search(&ws, "token", &filters, usize::MAX).expect("retrieval search");

        for hits in [&canonical, &retrieved] {
            let arg_hits = assignment_verify_token_arg_hits(hits, "token");
            assert_eq!(
                arg_hits.len(),
                1,
                "search should render the explicit call-arg row and drop the assignment-source arg shadow"
            );
            let expected_column =
                u32::try_from(arg_hits[0].code.rfind("token").expect("arg in source line") + 1)
                    .expect("column fits u32");
            assert_eq!(
                arg_hits[0].column, expected_column,
                "the kept arg hit should point at the argument token, not the assignment target"
            );
        }
    }
}
