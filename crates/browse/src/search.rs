//! `bonsai-ninja search` data layer — prefix-first fuzzy search
//! across every browse-fact kind in the workspace (not just decls).
//!
//! A search hit can originate from any of the browse surfaces
//! `bonsai-ninja` exposes: function / method / class / struct decl,
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

use crate::common::format_span;
use crate::refs::read_snippet;
use bonsai_lang_api::{FlowEvent, RefKind};
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Filter bundle for [`search`].
#[derive(Copy, Clone, Default, Debug)]
pub struct SearchFilters<'a> {
    /// Restrict to one fact-kind tag (e.g. `function`, `call`,
    /// `import`, `var`, `string`, `comment`, `arg`, `class`, `ref`). Matches
    /// case-insensitively against the hit's `kind` field.
    pub kind: Option<&'a str>,
    /// Keep only hits whose source file path contains the needle.
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
    /// Fact-kind tag: `function` / `method` / `class` / `struct` /
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
    use rayon::prelude::*;
    let global = ws.db().global_index();
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
    let files: Vec<_> = global.all_files().collect();

    let mut hits: Vec<SearchHit> = files
        .par_iter()
        .flat_map_iter(|&file_id| {
            let mut per_file: Vec<SearchHit> = Vec::new();
            let file_path = ws
                .vfs()
                .path(file_id)
                .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
            if let Some(needle) = file_filter {
                if !file_path.contains(needle) {
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

            // 1. Decls (functions / methods / classes / structs / ...).
            for decl in global.decls_in(file_id) {
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

                // 2. Flow-event facts INSIDE each decl: calls, assigns,
                //    arg values, string literals.
                walk_flow_events(&decl.flow_events, &decl.name, ws, &matcher, |hit| {
                    push(&mut per_file, hit);
                });
            }

            // 3. Imports (via the per-adapter extractor).
            if let Some(idx) = ws.db().import_index(file_id) {
                for imp in &idx.imports {
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
            }

            // 4. Refs (read / write / call / decorator references
            //    captured by the adapter's ref extractor).
            if let Some(idx) = global.file_index(file_id) {
                for r in &idx.refs {
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
                // 5. File-scoped string literals. (Call-arg strings
                //    are covered by the in-decl flow walk above; this
                //    block picks up top-level string facts the
                //    adapter exposes at file scope.)
                for s in &idx.strings {
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
                // 6. Comments. Comments are a first-class browse
                //    surface, so search includes their stripped text
                //    and exposes the adapter's comment category as
                //    context.
                for c in &idx.comments {
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
        "call" | "var" | "arg" | "string" | "comment" | "import" | "import-alias" => 1,
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
                    for arg in source_call_args {
                        if matcher(arg) {
                            let (path, line, col) = format_span(span, ws);
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
