//! Per-file module connections: the compiler facts that say how one source
//! file is wired to the rest of the workspace.
//!
//! For every requested file this projects, from already-lowered compiler
//! objects and the resolved callgraph:
//!
//! - its declarations (name, kind, line),
//! - its imports, each bound name, how many syntax uses the file makes of
//!   that binding, and the workspace files the import resolves to,
//! - the resolved cross-file call edges leaving the file (`calls_out`) and
//!   entering it (`callers_in`), grouped by the other file and carrying the
//!   stable `E:` edge id of every hop.
//!
//! The projection is one pass over the persisted callgraph partitions (or
//! the direct neighborhood of a few files) plus one decode of each file's
//! compiler object. No path enumeration, no name-string resolution: edges
//! come from the resolver, import targets from an indexed module-path
//! suffix table over workspace paths.

use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::{CallEdge, CallGraphNode, ResolvedCallGraph};
use bonsai_common::{FileId, FuncId};
use bonsai_lang_api::{DeclKind, FlowEvent, ImportSpec, RefKind};
use bonsai_workspace::Workspace;
use serde::Serialize;

use crate::edges::compute_edge_id;

/// One declaration in the file.
#[derive(Clone, Debug, Serialize)]
pub struct ModuleDecl {
    pub name: String,
    pub kind: String,
    pub line: u32,
}

/// One import statement, bound names, uses, and resolved workspace files.
#[derive(Clone, Debug, Serialize)]
pub struct ModuleImport {
    pub module: String,
    /// Names this import binds in the file (alias, imported name, or the
    /// module tail for a plain module import).
    pub names: Vec<String>,
    pub line: u32,
    pub wildcard: bool,
    /// Workspace-relative files the module path resolves to; empty for an
    /// external (dependency / standard library) module.
    pub resolved_files: Vec<String>,
    /// Number of call / read / write syntax facts in the file that go
    /// through one of the bound names.
    pub uses: usize,
    /// Sorted, distinct source lines where a bound name is used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub use_lines: Vec<u32>,
}

/// One resolved cross-file call edge.
#[derive(Clone, Debug, Serialize)]
pub struct ModuleEdge {
    /// Compiler identities for exact in-process joins; source names are display only.
    #[serde(skip)]
    pub caller_func: FuncId,
    #[serde(skip)]
    pub callee_func: FuncId,
    pub edge_id: String,
    pub caller: String,
    /// Line of the caller's declaration in its file.
    pub caller_line: u32,
    pub callee: String,
    /// Line of the callee's declaration in its file.
    pub callee_line: u32,
    /// Call-site line and column in the caller's file.
    pub line: u32,
    pub column: u32,
}

/// Cross-file edges grouped by the other file.
#[derive(Clone, Debug, Serialize)]
pub struct ModuleEdgeGroup {
    pub file: String,
    pub edges: Vec<ModuleEdge>,
}

/// Everything that connects one file to the rest of the workspace.
#[derive(Clone, Debug, Serialize)]
pub struct FileConnections {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    pub decls: Vec<ModuleDecl>,
    pub imports: Vec<ModuleImport>,
    /// Resolved calls from this file into other workspace files.
    pub calls_out: Vec<ModuleEdgeGroup>,
    /// Resolved calls from other workspace files into this file.
    pub callers_in: Vec<ModuleEdgeGroup>,
    /// False when a scoped session has no complete, validated callgraph evidence.
    pub calls_complete: bool,
    #[serde(skip)]
    pub file_id: FileId,
}

impl FileConnections {
    /// Number of cross-file edges leaving the file.
    #[must_use]
    pub fn calls_out_count(&self) -> usize {
        self.calls_out.iter().map(|group| group.edges.len()).sum()
    }

    /// Number of cross-file edges entering the file.
    #[must_use]
    pub fn callers_in_count(&self) -> usize {
        self.callers_in.iter().map(|group| group.edges.len()).sum()
    }
}

/// Module-path suffix table over workspace paths: `pkg.mod`, `pkg::mod`,
/// `./pkg/mod`, or `com.acme.Mod` resolve to every workspace file whose
/// extension-less path ends with those segments.
struct ModulePathIndex {
    by_tail: AHashMap<String, Vec<(FileId, Vec<String>)>>,
}

impl ModulePathIndex {
    fn build_from_paths(paths: &WorkspacePaths) -> Self {
        let mut by_tail: AHashMap<String, Vec<(FileId, Vec<String>)>> = AHashMap::new();
        for (file, path) in &paths.by_file {
            let segments = path_segments(path);
            if let Some(tail) = segments.last() {
                by_tail.entry(tail.clone()).or_default().push((*file, segments));
            }
        }
        for files in by_tail.values_mut() {
            files.sort_by_key(|(file, _)| file.raw());
        }
        Self { by_tail }
    }

    /// Files whose path ends with the import's module segments. When several
    /// match, the ones sharing the longest directory prefix with the
    /// importing file win (relative imports resolve inside their package).
    fn resolve(&self, module: &str, importing: &[String]) -> Vec<FileId> {
        let mut segments = module_segments(module);
        while !segments.is_empty() {
            let candidates = self
                .by_tail
                .get(segments.last().expect("non-empty segments"))
                .map(|files| {
                    files
                        .iter()
                        .filter(|(_, path)| path.ends_with(&segments))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !candidates.is_empty() {
                let rank = |path: &[String]| {
                    path.iter()
                        .zip(importing.iter())
                        .take_while(|(left, right)| left == right)
                        .count()
                };
                let best = candidates.iter().map(|(_, path)| rank(path)).max().unwrap_or(0);
                let mut files: Vec<FileId> = candidates
                    .into_iter()
                    .filter(|(_, path)| rank(path) == best)
                    .map(|(file, _)| *file)
                    .collect();
                files.sort_unstable_by_key(|file| file.raw());
                files.dedup();
                return files;
            }
            // `import a.b.C` where `C` is a declaration inside `b`: retry
            // with the parent module path.
            segments.pop();
        }
        Vec::new()
    }
}

fn path_segments(path: &str) -> Vec<String> {
    let without_extension = match path.rsplit_once('.') {
        Some((stem, extension)) if !extension.contains('/') && !extension.contains('\\') => stem,
        _ => path,
    };
    without_extension
        .split(['/', '\\'])
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .map(str::to_string)
        .collect()
}

fn module_segments(module: &str) -> Vec<String> {
    let trimmed = module
        .trim()
        .trim_matches(|ch| ch == '"' || ch == '\'' || ch == '<' || ch == '>');
    trimmed
        .split(['.', ':', '/', '\\'])
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            // `foo.rs` / `foo.js` style module spellings keep their stem.
            segment.to_string()
        })
        .collect()
}

/// Names an import binds in the file.
fn bound_names(import: &ImportSpec) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(alias) = import.alias.as_deref().filter(|alias| !alias.is_empty()) {
        names.push(alias.to_string());
    } else if let Some(original) = import.original_name.as_deref().filter(|name| !name.is_empty()) {
        names.push(original.to_string());
    } else if let Some(tail) = module_segments(&import.module).last() {
        names.push(tail.clone());
    }
    if let Some(original) = import.original_name.as_deref().filter(|name| !name.is_empty()) {
        if !names.iter().any(|name| name == original) {
            names.push(original.to_string());
        }
    }
    names
}

/// `callee` up to its first member separator, or the whole name.
fn qualified_head(callee: &str) -> &str {
    let bytes = callee.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'.' | b':' => return if index > 0 { &callee[..index] } else { callee },
            b'-' if bytes.get(index + 1) == Some(&b'>') => {
                return if index > 0 { &callee[..index] } else { callee }
            }
            _ => index += 1,
        }
    }
    callee
}

fn count_uses(events: &[FlowEvent], uses: &mut AHashMap<String, Vec<u64>>) {
    for event in events {
        match event {
            FlowEvent::Call {
                name, receiver, span, ..
            } => {
                let head = receiver
                    .as_deref()
                    .map_or_else(|| qualified_head(name), qualified_head);
                if let Some(offsets) = uses.get_mut(head) {
                    offsets.push(span.start);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                count_uses(then_events, uses);
                count_uses(else_events, uses);
            }
            FlowEvent::Loop {
                condition_events,
                update_events,
                body,
                ..
            } => {
                count_uses(condition_events, uses);
                count_uses(update_events, uses);
                count_uses(body, uses);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                count_uses(body, uses);
                count_uses(catch_events, uses);
                count_uses(finally_events, uses);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => count_uses(body, uses),
            _ => {}
        }
    }
}

fn decl_kind_label(kind: DeclKind) -> String {
    format!("{kind:?}").to_lowercase()
}

/// Path table for every workspace file, including files a scoped session
/// did not ingest, plus on-demand line lookup for spans in those files.
struct WorkspacePaths {
    root: Option<std::path::PathBuf>,
    by_file: AHashMap<FileId, String>,
    hashes: AHashMap<FileId, u64>,
    line_cache: std::cell::RefCell<AHashMap<FileId, Option<bonsai_common::SpanMap>>>,
}

impl WorkspacePaths {
    fn build(ws: &Workspace) -> Self {
        let root = ws.db().workspace_root();
        let mut by_file: AHashMap<FileId, String> = AHashMap::new();
        for file in ws.vfs().all_files() {
            if let Ok(path) = ws.vfs().path(file) {
                by_file.insert(file, path.to_string_lossy().into_owned());
            }
        }
        let mut hashes = AHashMap::new();
        if let Some(inputs) = ws.complete_source_inputs() {
            for (raw, path, hash) in inputs.iter() {
                by_file.entry(FileId::new(*raw)).or_insert_with(|| path.clone());
                hashes.insert(FileId::new(*raw), *hash);
            }
        }
        Self {
            root,
            by_file,
            hashes,
            line_cache: std::cell::RefCell::new(AHashMap::new()),
        }
    }

    fn display(&self, file: FileId) -> String {
        self.by_file.get(&file).map_or_else(
            || format!("file#{}", file.raw()),
            |path| bonsai_common::workspace_relative_filter_path(self.root.as_deref(), path),
        )
    }

    /// 1-based location from compiler line tables, or an exact fingerprint-
    /// checked source read for a file outside this session. A changed remote
    /// file is unavailable, never a new source location attached to an old edge.
    fn line_of(&self, ws: &Workspace, file: FileId, offset: u64) -> u32 {
        self.line_col(ws, file, offset).map_or(0, |at| at.line)
    }

    fn line_col(&self, ws: &Workspace, file: FileId, offset: u64) -> Option<bonsai_common::LineCol> {
        if let Some(map) = ws.db().span_map(file) {
            return Some(map.line_col(offset));
        }
        let mut cache = self.line_cache.borrow_mut();
        let map = cache.entry(file).or_insert_with(|| {
            let path = self.by_file.get(&file)?;
            let absolute = self
                .root
                .as_deref()
                .map_or_else(|| std::path::PathBuf::from(path), |root| root.join(path));
            let text = std::fs::read(absolute).ok()?;
            if self.hashes.get(&file).copied() != Some(bonsai_hash::fnv1a_bytes64(&text)) {
                return None;
            }
            Some(bonsai_common::SpanMap::new(std::str::from_utf8(&text).ok()?))
        });
        map.as_ref().map(|map| map.line_col(offset))
    }
}

struct EdgeEndpoints {
    name: AHashMap<FuncId, String>,
    file: AHashMap<FuncId, FileId>,
    name_span: AHashMap<FuncId, bonsai_common::Span>,
}

impl EdgeEndpoints {
    fn note(&mut self, node: &CallGraphNode) {
        self.name
            .entry(node.func)
            .or_insert_with(|| node.name.as_ref().to_string());
        self.file.entry(node.func).or_insert(node.file);
        self.name_span.entry(node.func).or_insert(node.name_span);
    }
}

/// Project the module connections of `files`.
///
/// `files` empty means every workspace file. Cross-file edges come from one
/// pass over the persisted callgraph partitions when most files are
/// requested, or from the direct resolved neighborhood of the requested
/// callables otherwise; both are exact resolver facts. Endpoint names and
/// files come from the callgraph nodes themselves, so a scoped session that
/// ingested only the requested file still sees its cross-file edges.
#[must_use]
pub fn file_connections(ws: &Workspace, files: &[FileId]) -> Vec<FileConnections> {
    let all_files = ws.vfs().all_files();
    let requested: Vec<FileId> = if files.is_empty() {
        let mut all = all_files.clone();
        all.sort_unstable_by_key(|file| file.raw());
        all
    } else {
        let mut requested = files.to_vec();
        requested.sort_unstable_by_key(|file| file.raw());
        requested.dedup();
        requested
    };
    let requested_set: AHashSet<FileId> = requested.iter().copied().collect();
    let headers = ws.compiler_header_index();
    let paths = WorkspacePaths::build(ws);
    let module_index = ModulePathIndex::build_from_paths(&paths);

    // ---- cross-file edges: nodes first (func → name/file), then edges.
    let mut endpoints = EdgeEndpoints {
        name: AHashMap::new(),
        file: AHashMap::new(),
        name_span: AHashMap::new(),
    };
    let mut edges: Vec<CallEdge> = Vec::new();
    let broad = requested.len().saturating_mul(4) >= all_files.len() && ws.is_complete_workspace_index();
    let mut visited_partitions = false;
    if broad {
        let visited = ws.visit_persisted_callgraph_partitions(|_, nodes, outgoing, _, _| {
            for node in nodes {
                endpoints.note(node);
            }
            edges.extend(outgoing.iter().cloned());
        });
        visited_partitions = matches!(visited, Some(Ok(())));
        if !visited_partitions {
            edges.clear();
            endpoints.name.clear();
            endpoints.file.clear();
            endpoints.name_span.clear();
        }
    }
    // A few files (a single `read-file`, or a scoped session): the persisted
    // partition of each requested file carries every edge in and out of it,
    // and the other endpoints' nodes resolve one at a time from the same
    // sidecar. This never needs the other files' source text or headers.
    let mut partitions_used = false;
    let mut missing_partitions = false;
    if !visited_partitions {
        for file in &requested {
            let Some(Ok((nodes, outgoing, incoming))) = ws.persisted_callgraph_file_edges(*file) else {
                missing_partitions = true;
                continue;
            };
            partitions_used = true;
            for node in &nodes {
                endpoints.note(node);
            }
            edges.extend(outgoing);
            edges.extend(incoming);
        }
        if partitions_used {
            let mut missing: Vec<FuncId> = edges
                .iter()
                .flat_map(|edge| [edge.from, edge.to])
                .filter(|func| !endpoints.file.contains_key(func))
                .collect();
            missing.sort_unstable_by_key(|func| func.raw());
            missing.dedup();
            for func in missing {
                if let Some(Ok(node)) = ws.persisted_callgraph_node(func) {
                    endpoints.note(&node);
                }
            }
            edges.sort_by_key(|edge| (edge.from.raw(), edge.to.raw(), edge.span.start, edge.span.end));
            edges.dedup_by(|left, right| {
                left.from == right.from && left.to == right.to && left.span == right.span
            });
        }
    }
    let mut calls_complete = visited_partitions || (partitions_used && !missing_partitions);
    if !calls_complete && ws.is_complete_workspace_index() {
        edges.clear();
        endpoints.name.clear();
        endpoints.file.clear();
        endpoints.name_span.clear();
        let funcs: Vec<FuncId> = requested
            .iter()
            .flat_map(|file| headers.decls_in(*file).iter())
            .filter(|decl| {
                matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                )
            })
            .map(|decl| FuncId::new(decl.symbol.raw()))
            .collect();
        let graph: std::sync::Arc<ResolvedCallGraph> = if broad {
            ws.cached_resolved_call_graph()
        } else {
            ws.resolved_call_graph_direct_neighborhood(&funcs)
        };
        for node in graph.nodes() {
            endpoints.note(node);
        }
        edges.extend(graph.inner().edges.iter().cloned());
        calls_complete = true;
    }
    let mut calls_out: AHashMap<FileId, AHashMap<FileId, Vec<ModuleEdge>>> = AHashMap::new();
    let mut callers_in: AHashMap<FileId, AHashMap<FileId, Vec<ModuleEdge>>> = AHashMap::new();
    for edge in &edges {
        let (Some(&caller_file), Some(&callee_file)) =
            (endpoints.file.get(&edge.from), endpoints.file.get(&edge.to))
        else {
            calls_complete = false;
            continue;
        };
        if caller_file == callee_file
            || (!requested_set.contains(&caller_file) && !requested_set.contains(&callee_file))
        {
            continue;
        }
        let (Some(caller_name), Some(callee_name)) =
            (endpoints.name.get(&edge.from), endpoints.name.get(&edge.to))
        else {
            calls_complete = false;
            continue;
        };
        let call_file = paths.display(edge.span.file);
        let Some(at) = paths.line_col(ws, edge.span.file, edge.span.start) else {
            calls_complete = false;
            continue;
        };
        let (line, column) = (at.line, at.column);
        let caller_line = endpoints
            .name_span
            .get(&edge.from)
            .map_or(0, |span| paths.line_of(ws, span.file, span.start));
        let callee_line = endpoints
            .name_span
            .get(&edge.to)
            .map_or(0, |span| paths.line_of(ws, span.file, span.start));
        if caller_line == 0 || callee_line == 0 {
            calls_complete = false;
            continue;
        }
        let make = || ModuleEdge {
            caller_func: edge.from,
            callee_func: edge.to,
            edge_id: compute_edge_id(caller_name, callee_name, &call_file, line, column),
            caller: caller_name.clone(),
            caller_line,
            callee: callee_name.clone(),
            callee_line,
            line,
            column,
        };
        if requested_set.contains(&caller_file) {
            calls_out
                .entry(caller_file)
                .or_default()
                .entry(callee_file)
                .or_default()
                .push(make());
        }
        if requested_set.contains(&callee_file) {
            callers_in
                .entry(callee_file)
                .or_default()
                .entry(caller_file)
                .or_default()
                .push(make());
        }
    }

    // ---- per-file declarations and imports.
    let mut out = Vec::with_capacity(requested.len());
    for file in requested {
        let file_display = paths.display(file);
        let importing_segments = path_segments(&file_display);
        let language = ws
            .db()
            .adapter_for(file)
            .map(|adapter| adapter.language_id().as_str().to_string());
        let mut decls: Vec<ModuleDecl> = headers
            .decls_in(file)
            .iter()
            .map(|decl| ModuleDecl {
                name: decl.name.clone(),
                kind: decl_kind_label(decl.kind),
                line: paths.line_of(ws, decl.name_span.file, decl.name_span.start),
            })
            .collect();
        decls.sort_by(|left, right| {
            left.line
                .cmp(&right.line)
                .then_with(|| left.name.cmp(&right.name))
        });

        let object = ws.db().compiler_file_object_uncached(file);
        let mut imports: Vec<ModuleImport> = Vec::new();
        let mut uses: AHashMap<String, Vec<u64>> = AHashMap::new();
        if let Some(index) = object.as_ref().and_then(|object| object.imports.as_ref()) {
            for import in &index.imports {
                let names = bound_names(import);
                for name in &names {
                    uses.entry(name.clone()).or_default();
                }
                let line = paths.line_of(ws, import.span.file, import.span.start);
                let mut resolved_files: Vec<String> = module_index
                    .resolve(&import.module, &importing_segments)
                    .into_iter()
                    .filter(|target| *target != file)
                    .map(|target| paths.display(target))
                    .collect();
                resolved_files.sort();
                imports.push(ModuleImport {
                    module: import.module.clone(),
                    names,
                    line,
                    wildcard: import.is_wildcard,
                    resolved_files,
                    uses: 0,
                    use_lines: Vec::new(),
                });
            }
        }
        if !uses.is_empty() {
            if let Some(index) = object.as_ref().and_then(|object| object.declarations.as_ref()) {
                for decl in &index.defs {
                    count_uses(&decl.flow_events, &mut uses);
                }
                for reference in &index.refs {
                    // Module-scope calls are represented in the canonical
                    // reference inventory rather than a named callable's
                    // flow events. Count them as import uses too: `from x
                    // import app; app.run()` must not be rendered as an
                    // unused import merely because the call is top-level.
                    if matches!(reference.kind, RefKind::Read | RefKind::Write | RefKind::Call) {
                        if let Some(offsets) = uses.get_mut(qualified_head(&reference.name)) {
                            offsets.push(reference.span.start);
                        }
                    }
                }
            }
            for import in &mut imports {
                let mut offsets: Vec<u64> = import
                    .names
                    .iter()
                    .filter_map(|name| uses.get(name))
                    .flatten()
                    .copied()
                    .collect();
                offsets.sort_unstable();
                offsets.dedup();
                // The import statement itself is not a use.
                let mut lines: Vec<u32> = offsets
                    .iter()
                    .map(|offset| paths.line_of(ws, file, *offset))
                    .filter(|line| *line != import.line)
                    .collect();
                lines.sort_unstable();
                lines.dedup();
                import.uses = offsets.len();
                import.use_lines = lines;
            }
        }
        imports.sort_by(|left, right| {
            left.line
                .cmp(&right.line)
                .then_with(|| left.module.cmp(&right.module))
        });

        let group = |map: Option<AHashMap<FileId, Vec<ModuleEdge>>>| -> Vec<ModuleEdgeGroup> {
            let mut groups: Vec<ModuleEdgeGroup> = map
                .unwrap_or_default()
                .into_iter()
                .map(|(other, mut edges)| {
                    edges.sort_by(|left, right| {
                        left.line
                            .cmp(&right.line)
                            .then_with(|| left.column.cmp(&right.column))
                            .then_with(|| left.callee.cmp(&right.callee))
                    });
                    edges.dedup_by(|left, right| left.edge_id == right.edge_id);
                    ModuleEdgeGroup {
                        file: paths.display(other),
                        edges,
                    }
                })
                .collect();
            groups.sort_by(|left, right| left.file.cmp(&right.file));
            groups
        };
        out.push(FileConnections {
            file: file_display,
            language,
            decls,
            imports,
            calls_out: group(calls_out.remove(&file)),
            callers_in: group(callers_in.remove(&file)),
            calls_complete,
            file_id: file,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{module_segments, path_segments, qualified_head};

    #[test]
    fn remote_locations_preserve_byte_columns_and_reject_changed_source() {
        let dir = tempfile::tempdir().unwrap();
        let source = "// header\n  β(); target();\n";
        std::fs::write(dir.path().join("caller.js"), source).unwrap();
        let file = bonsai_common::FileId::new(0);
        let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
        let paths = || super::WorkspacePaths {
            root: Some(dir.path().to_path_buf()),
            by_file: [(file, "caller.js".to_string())].into_iter().collect(),
            hashes: [(file, bonsai_hash::fnv1a_bytes64(source.as_bytes()))]
                .into_iter()
                .collect(),
            line_cache: Default::default(),
        };
        let offset = source.find("target").unwrap() as u64;
        let at = paths().line_col(&ws, file, offset).unwrap();
        assert_eq!((at.line, at.column), (2, 9));
        std::fs::write(dir.path().join("caller.js"), "target();\n").unwrap();
        assert!(paths().line_col(&ws, file, offset).is_none());
    }

    #[test]
    fn module_segments_normalize_every_separator_style() {
        assert_eq!(module_segments(".user_service"), vec!["user_service"]);
        assert_eq!(
            module_segments("com.acme.Service"),
            vec!["com", "acme", "Service"]
        );
        assert_eq!(
            module_segments("crate::auth::service"),
            vec!["crate", "auth", "service"]
        );
        assert_eq!(module_segments("./lib/x"), vec!["lib", "x"]);
        assert_eq!(module_segments("\"stdio.h\""), vec!["stdio", "h"]);
    }

    #[test]
    fn path_segments_drop_the_extension_only() {
        assert_eq!(path_segments("src/lib/x.ts"), vec!["src", "lib", "x"]);
        assert_eq!(path_segments("a/b.c/d"), vec!["a", "b.c", "d"]);
    }

    #[test]
    fn qualified_head_takes_the_receiver_spelling() {
        assert_eq!(qualified_head("os.system"), "os");
        assert_eq!(qualified_head("std::fs::read"), "std");
        assert_eq!(qualified_head("ptr->run"), "ptr");
        assert_eq!(qualified_head("plain"), "plain");
    }
}
