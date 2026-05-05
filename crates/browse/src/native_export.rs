//! Native JSON export SDK.
//!
//! This module owns the command-independent data shape emitted by
//! `bonsai-ninja export` in its default JSON format. The CLI is only
//! responsible for opening the workspace, cache/stdout handling, and
//! selecting this renderer.

use crate::common::collect_callees;
use crate::ClassOut;
use bonsai_common::{FileId, Span, SpanMap};
use bonsai_inspect::{chain_to_names, func_display_name, ChainCache};
use bonsai_lang_api::{DeclKind, FlowEvent, RefKind};
use bonsai_workspace::Workspace;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct ExportOut<'a> {
    engine_version: &'a str,
    workspace_root: String,
    generated_at_unix_ms: u128,
    summary: ExportSummary,
    files: Vec<ExportFile>,
    classes: Vec<ClassOut>,
    /// One edge per call-site inside a function body. Caller is the enclosing
    /// decl's name; callee is the short name at the call-site. Precision is
    /// `narrowed` if the callee resolves workspace-globally, `unknown`
    /// otherwise.
    callgraph: Vec<CallEdgeOut>,
    /// Workspace-wide flow chains: for every decl that is reachable from
    /// some entry point, the list of chains that lead to it. Each chain
    /// reads top-down `[entry, …, target]` — the same data `inspect`
    /// renders inline. Enables downstream tooling / dashboards to reason
    /// about reachable sinks without re-running the tracer.
    flow_chains: Vec<ExportFlowChain>,
    /// Workspace flow graph summary: one entry per callable decl with
    /// caller / callee counts and an `entry_point` flag. Analogous to
    /// `dump-callgraph` but structured for programmatic consumption.
    flow_graph: Vec<ExportFlowNode>,
    /// Complete taint graph — the engine's taint-analysis state
    /// materialised as a document. Downstream tooling can reconstruct
    /// source→sink reasoning without re-running the taint passes:
    /// per-function summaries, alias resolution, class field-taint,
    /// inferred entry-points, and interprocedural propagation edges
    /// from every entry's interprocedural pass.
    taint_graph: ExportTaintGraph,
}

/// Complete raw taint graph for the workspace — the analyzer's
/// engine state materialised as JSON. Inspect and security are thin
/// queries over this graph (inspect = pattern-less traversal,
/// security = pattern-matching wrapper). Anything either surface
/// depends on MUST be reconstructible from this section alone.
#[derive(Serialize)]
struct ExportTaintGraph {
    /// Every callable decl's FuncId → display name + file/line.
    /// The single authoritative mapping other sections (edges,
    /// propagations, chains) reference by `func_id`. Raw `u32`
    /// FuncId preserved so graph consumers can rebuild the adjacency
    /// structure without re-resolving names.
    functions: Vec<ExportTaintFunction>,
    /// Resolved workspace call graph. Every edge is a concrete
    /// `FuncId → FuncId` link with the resolver's precision /
    /// kind tag. Consumers rebuild reachability / chain
    /// enumeration from this slice.
    call_edges: Vec<ExportCallEdge>,
    /// Per-function return-value taint summaries (G1): which
    /// parameter indices transit to the return, so downstream
    /// `y = f(tainted)` propagation is a table lookup.
    function_summaries: Vec<ExportFunctionSummary>,
    /// Per-function kinded taint reachability facts — every token
    /// each function contributes to a chain's visible-name set,
    /// split by `FactKind` (decl, call, read, write, arg,
    /// string_lit, import, class). This is the raw reachability
    /// pass output `inspect --from` / `--to` filters consult.
    reachable_facts: Vec<ExportReachableFacts>,
    /// Per-function assign-chain expansion: every identifier that
    /// becomes tainted when each individual parameter is seeded.
    /// The monotonic (grows-only) pass downstream from which the
    /// intra/inter passes inherit their base taint set.
    assign_chains: Vec<ExportAssignChain>,
    /// Per-function intraprocedural CFG dataflow: per-block in/out
    /// taint state when each parameter is seeded. Captures the
    /// CFG-ordered reassignment semantics the intra pass adds over
    /// plain assign-chain.
    intra_taint: Vec<ExportIntraTaint>,
    /// Per-file alias resolution: `local_name → { module, member? }`
    /// derived from the adapter's `ImportIndex`. Matches the
    /// resolver's alias map — so a consumer reading `Call.name`
    /// through this table resolves callees identically to the
    /// resolved call graph.
    alias_maps: Vec<ExportAliasMap>,
    /// Per-class field-taint (G3 cross-method): adapter-declared
    /// receiver-field writes from method params collected across a
    /// class's methods. A sibling method's read of the same field
    /// inherits this taint.
    class_fields: Vec<ExportClassFields>,
    /// Inferred entry-point sources — every seed the security
    /// matcher feeds into the interprocedural pass. G5 framework
    /// decorators, unreferenced public functions, and G3 class-
    /// field inheritance. The same set `security taint-analysis`
    /// augments its rule-derived sources with, so a consumer replaying
    /// the pipeline produces the same findings.
    entry_points: Vec<ExportEntryPoint>,
    /// Per-entry interprocedural propagation: every
    /// caller→callee taint edge the `interprocedural_taint` pass
    /// records for each inferred entry. Raw output of the cross-
    /// function pass — `security taint-analysis` is this plus
    /// rule-pattern filtering, `inspect` is this plus `--from`/`--to` text
    /// filtering.
    propagations: Vec<ExportTaintPropagations>,
    /// Whether `propagations` is exhaustive. Large workspaces skip
    /// exhaustive record materialization by default; pass
    /// `export --full-propagations` to force it.
    propagations_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    propagations_omitted_reason: Option<String>,
    /// Per-target resolved chains (FuncId list per chain). Same
    /// structure rendered by `inspect --query` — surfaced here so
    /// tooling doesn't have to re-run chain enumeration.
    chains: Vec<ExportChain>,
    /// Per-function flow-id labels (`F:<16-hex>` / `G:<16-hex>`).
    /// The stable identifiers `inspect` prints and `security`
    /// joins on. Reusing these verbatim in tooling keeps cross-
    /// invocation references stable.
    flow_id_labels: Vec<ExportFlowIdLabels>,
}

#[derive(Serialize)]
struct ExportTaintFunction {
    func_id: u32,
    name: String,
    qualified_name: Option<String>,
    file: String,
    line: u32,
    params: Vec<String>,
    kind: String,
}

#[derive(Serialize)]
struct ExportCallEdge {
    from: u32,
    to: u32,
    kind: String,
    precision: String,
}

#[derive(Serialize)]
struct ExportReachableFacts {
    func_id: u32,
    function: String,
    /// Tokens keyed by `FactKind` name (`decl`, `call`, `read`,
    /// `write`, `arg`, `string_lit`, `import`, `class`). Flattened
    /// to sorted vectors so the JSON is diff-friendly.
    by_kind: std::collections::BTreeMap<String, Vec<String>>,
}

#[derive(Serialize)]
struct ExportAssignChain {
    func_id: u32,
    function: String,
    /// One entry per parameter: seeding the param name, this is
    /// the full set of identifiers the monotonic assign-chain
    /// pass reaches.
    per_param: Vec<ExportAssignChainParam>,
}

#[derive(Serialize)]
struct ExportAssignChainParam {
    param_index: usize,
    param_name: String,
    tainted: Vec<String>,
}

#[derive(Serialize)]
struct ExportIntraTaint {
    func_id: u32,
    function: String,
    /// Per-parameter CFG dataflow results.
    per_param: Vec<ExportIntraTaintParam>,
}

#[derive(Serialize)]
struct ExportIntraTaintParam {
    param_index: usize,
    param_name: String,
    iterations: u32,
    saturated: bool,
    /// One entry per basic block. `block_in` / `block_out` are
    /// the taint set at entry / exit of the block.
    blocks: Vec<ExportIntraBlock>,
}

#[derive(Serialize)]
struct ExportIntraBlock {
    #[serde(rename = "block_id")]
    id: u32,
    #[serde(rename = "block_in")]
    taint_in: Vec<String>,
    #[serde(rename = "block_out")]
    taint_out: Vec<String>,
}

#[derive(Serialize)]
struct ExportChain {
    target_func_id: u32,
    target: String,
    /// One chain per entry: ordered list of FuncIds top-down
    /// (entry first, target last).
    chains: Vec<Vec<u32>>,
}

#[derive(Serialize)]
struct ExportFlowIdLabels {
    func_id: u32,
    function: String,
    labels: Vec<String>,
    truncated: bool,
}

#[derive(Serialize)]
struct ExportFunctionSummary {
    function: String,
    file: String,
    line: u32,
    /// Parameter indices that flow to the function's return value.
    /// `[0, 2]` means taint on param 0 or param 2 produces a tainted
    /// return.
    returns_taint_of: Vec<usize>,
}

#[derive(Serialize)]
struct ExportAliasMap {
    file: String,
    entries: Vec<ExportAliasEntry>,
}

#[derive(Serialize)]
struct ExportAliasEntry {
    local: String,
    /// `member` — local name binds a specific module export
    /// (`import { exec } from "child_process"` → local `exec` →
    /// module `child_process`, member `exec`).
    /// `namespace` — local name binds the whole module (`import os
    /// as o` → local `o` → module `os`, no member).
    target_kind: &'static str,
    module: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    member: Option<String>,
}

#[derive(Serialize)]
struct ExportClassFields {
    class: String,
    file: String,
    line: u32,
    /// Adapter-normalized receiver field/container places that any
    /// method of the class writes from one of its own params.
    tainted_fields: Vec<String>,
}

#[derive(Serialize)]
struct ExportEntryPoint {
    function: String,
    file: String,
    line: u32,
    kind: &'static str,
    params: Vec<String>,
}

#[derive(Serialize)]
struct ExportTaintPropagations {
    entry: String,
    entry_file: String,
    entry_line: u32,
    /// Worst precision observed across any traversed resolver edge
    /// during the interprocedural pass from this entry.
    precision: String,
    pairs_analyzed: u32,
    saturated: bool,
    records: Vec<ExportTaintRecord>,
}

#[derive(Serialize)]
struct ExportTaintRecord {
    caller: String,
    callee: String,
    call_line: u32,
    edge_kind: String,
    edge_precision: String,
    /// One entry per positional argument that was tainted at the
    /// call site. Lets consumers correlate caller-local identifiers
    /// to the callee's parameter names they ended up in.
    tainted_args: Vec<ExportTaintedArg>,
}

#[derive(Serialize)]
struct ExportTaintedArg {
    index: usize,
    value_text: String,
    param_name: String,
}

/// One entry per target function: every enumerated upstream chain that
/// reaches it. Matches the `chain` structure rendered inline by
/// `inspect`.
#[derive(Serialize)]
struct ExportFlowChain {
    target: String,
    chains: Vec<Vec<String>>,
}

/// One entry per callable decl: its caller/outgoing counts plus a flag
/// indicating whether it's a workspace entry point (no callers).
#[derive(Serialize)]
struct ExportFlowNode {
    function: String,
    callers: Vec<String>,
    outgoing: Vec<String>,
    entry_point: bool,
}

#[derive(Serialize)]
struct ExportSummary {
    file_count: usize,
    decl_count: usize,
    class_count: usize,
    function_count: usize,
    method_count: usize,
    call_site_count: usize,
    call_edge_count: usize,
    import_count: usize,
    string_count: usize,
    strings_by_category: serde_json::Value,
    languages: Vec<String>,
}

#[derive(Serialize)]
struct ExportFile {
    path: String,
    language: String,
    decls: Vec<ExportDecl>,
    imports: Vec<ExportImport>,
    refs: Vec<ExportRef>,
    strings: Vec<ExportString>,
}

#[derive(Serialize)]
struct ExportDecl {
    symbol_id: u32,
    name: String,
    qualified_name: Option<String>,
    kind: String,
    visibility: String,
    line: u32,
    column: u32,
    end_line: u32,
    params: Vec<String>,
    /// Nested control-flow tree (calls, branches, loops, assigns, returns,
    /// throws). Consumers can walk this directly to reconstruct traces.
    flow_events: Vec<bonsai_lang_api::FlowEvent>,
    parent_symbol_id: Option<u32>,
}

#[derive(Serialize)]
struct ExportImport {
    module: String,
    alias: Option<String>,
    is_wildcard: bool,
    line: u32,
}

#[derive(Serialize)]
struct ExportRef {
    name: String,
    kind: String,
    line: u32,
    column: u32,
    resolved_symbol_id: Option<u32>,
}

#[derive(Serialize)]
struct ExportString {
    text: String,
    category: String,
    line: u32,
    column: u32,
}

#[derive(Serialize)]
struct CallEdgeOut {
    caller: String,
    caller_file: String,
    caller_line: u32,
    callee: String,
    callee_kind: String,
    call_site_line: u32,
    call_site_column: u32,
    precision: &'static str,
}

/// Per-export cache of `(path, SpanMap)` keyed on FileId. We
/// build each file's span-map once at export start and reuse it
/// for every span we render — large workspaces would otherwise
/// rebuild the same maps thousands of times.
struct ExportSpanCache {
    files: ahash::AHashMap<FileId, (String, SpanMap)>,
}

impl ExportSpanCache {
    fn new(ws: &Workspace) -> Self {
        let mut files = ahash::AHashMap::default();
        for file in ws.db().global_index().all_files() {
            let path = ws
                .vfs()
                .path(file)
                .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
            if let Ok(snap) = ws.vfs().snapshot(file) {
                files.insert(file, (path, SpanMap::new(snap.text.as_ref())));
            }
        }
        Self { files }
    }

    /// Resolve `span` to `(path, line, column)`. Falls back to
    /// `("<unknown>", 0, 0)` if the file's snapshot wasn't readable
    /// at cache-build time.
    fn format(&self, span: Span) -> (String, u32, u32) {
        let Some((path, map)) = self.files.get(&span.file) else {
            return ("<unknown>".to_string(), 0, 0);
        };
        let line_col = map.line_col(span.start);
        (path.clone(), line_col.line, line_col.column)
    }
}

/// Build the native `export` JSON value from an indexed workspace.
pub fn native_export_json(
    ws: &Workspace,
    root: &Path,
    full_propagations: bool,
) -> serde_json::Result<serde_json::Value> {
    serde_json::to_value(native_export(ws, root, full_propagations)?)
}

/// Render the native `export` JSON document from an indexed workspace.
pub fn render_native_export_json(
    ws: &Workspace,
    root: &Path,
    full_propagations: bool,
) -> serde_json::Result<String> {
    serde_json::to_string(&native_export_json(ws, root, full_propagations)?)
}

fn native_export(
    ws: &Workspace,
    root: &Path,
    full_propagations: bool,
) -> serde_json::Result<ExportOut<'static>> {
    let global = ws.db().global_index();
    let spans = ExportSpanCache::new(ws);

    let mut files: Vec<ExportFile> = Vec::new();
    let mut classes: Vec<ClassOut> = Vec::new();
    let mut callgraph: Vec<CallEdgeOut> = Vec::new();

    let mut callable_names: ahash::AHashSet<String> = ahash::AHashSet::new();
    let mut class_names_set: ahash::AHashSet<String> = ahash::AHashSet::new();
    for file in global.all_files() {
        for d in global.decls_in(file) {
            match d.kind {
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor => {
                    callable_names.insert(d.name.clone());
                }
                DeclKind::Class | DeclKind::Struct => {
                    class_names_set.insert(d.name.clone());
                }
                _ => {}
            }
        }
    }

    let mut languages_set: ahash::AHashSet<String> = ahash::AHashSet::new();
    let mut function_count = 0usize;
    let mut method_count = 0usize;
    let mut call_site_count = 0usize;
    let mut import_count = 0usize;
    let mut string_count = 0usize;
    let mut decl_count = 0usize;
    // BTreeMap (not ahash) so the serialised JSON object has a
    // deterministic key order across runs — `serde_json::to_value`
    // on an `AHashMap` would expose the per-process random seed
    // and break Stable-IDs-From-Content for `export` JSON.
    let mut by_cat: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();

    // Iterate VFS files in path-sorted order so the JSON `files`
    // array is deterministic across runs (matches the sibling
    // sections `decls`/`callgraph` which iterate
    // `global.all_files()` — itself path-sorted because
    // `ingest_dir` allocates FileIds in path order).
    //
    // Materialise `(FileId, path_string)` once instead of
    // re-resolving `vfs.path()` inside the cmp closure — the
    // closure runs O(N log N) times and would otherwise hit the
    // VFS read lock 2N log N times on every export.
    let mut all_files: Vec<(FileId, String)> = ws
        .vfs()
        .all_files()
        .into_iter()
        .map(|f| {
            let path = ws
                .vfs()
                .path(f)
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            (f, path)
        })
        .collect();
    all_files.sort_by(|a, b| a.1.cmp(&b.1));
    for (file, materialised_path) in all_files {
        // Reuse the path string we already resolved for the sort
        // key. The previous version re-called `vfs.path(file)` per
        // iteration, taking the VFS read lock N more times and
        // defeating half the sort optimisation. Empty paths fall
        // back to `<unknown>` so JSON rows never carry an empty
        // string for the file column.
        let path = if materialised_path.is_empty() {
            "<unknown>".to_string()
        } else {
            materialised_path
        };
        let language = ws
            .db()
            .adapter_for(file)
            .map(|a| a.language_id().as_str().to_string())
            .unwrap_or_default();
        if !language.is_empty() {
            languages_set.insert(language.clone());
        }

        let Some(idx) = global.file_index(file) else {
            files.push(ExportFile {
                path,
                language,
                decls: Vec::new(),
                imports: Vec::new(),
                refs: Vec::new(),
                strings: Vec::new(),
            });
            continue;
        };

        let mut decls_out: Vec<ExportDecl> = Vec::with_capacity(idx.defs.len());
        for d in &idx.defs {
            decl_count += 1;
            match d.kind {
                DeclKind::Function => function_count += 1,
                DeclKind::Method | DeclKind::Constructor => method_count += 1,
                _ => {}
            }
            let (_, line, col) = spans.format(d.name_span);
            let (_, end_line, _) = spans.format(d.body_span.unwrap_or(d.span));
            collect_call_edges_for_export(
                &d.flow_events,
                &d.name,
                &path,
                line,
                &ExportWalkCtx {
                    callables: &callable_names,
                    classes: &class_names_set,
                    spans: &spans,
                },
                &mut callgraph,
                &mut call_site_count,
            );
            decls_out.push(ExportDecl {
                symbol_id: d.symbol.raw(),
                name: d.name.clone(),
                qualified_name: d.qualified_name.clone(),
                kind: format!("{:?}", d.kind).to_lowercase(),
                visibility: format!("{:?}", d.visibility).to_lowercase(),
                line,
                column: col,
                end_line,
                params: d.params.clone(),
                flow_events: d.flow_events.clone(),
                parent_symbol_id: d.parent.map(|s| s.raw()),
            });
            if matches!(
                d.kind,
                DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface | DeclKind::Enum
            ) {
                let methods: Vec<String> = idx
                    .defs
                    .iter()
                    .filter(|m| {
                        matches!(
                            m.kind,
                            DeclKind::Method | DeclKind::Constructor | DeclKind::Function
                        )
                    })
                    .filter(|m| span_contains(d.span, m.span))
                    .map(|m| m.name.clone())
                    .collect();
                classes.push(ClassOut {
                    name: d.name.clone(),
                    kind: format!("{:?}", d.kind).to_lowercase(),
                    file: path.clone(),
                    line,
                    method_count: methods.len(),
                    methods,
                });
            }
        }

        let imports_vec = ws
            .db()
            .import_index(file)
            .map(|i| i.imports.clone())
            .filter(|i| !i.is_empty())
            .unwrap_or_else(|| {
                ws.db()
                    .parse(file)
                    .ok()
                    .and_then(|parsed| {
                        ws.vfs().snapshot(file).ok().map(|snap| {
                            bonsai_lang_api::kit::extract_generic_imports(
                                &parsed.tree,
                                file,
                                snap.text.as_bytes(),
                            )
                        })
                    })
                    .unwrap_or_default()
            });
        import_count += imports_vec.len();
        let imports_out: Vec<ExportImport> = imports_vec
            .iter()
            .map(|imp| {
                let (_, line, _) = spans.format(imp.span);
                ExportImport {
                    module: imp.module.clone(),
                    alias: imp.alias.clone(),
                    is_wildcard: imp.is_wildcard,
                    line,
                }
            })
            .collect();

        let refs_out: Vec<ExportRef> = idx
            .refs
            .iter()
            .map(|r| {
                let (_, line, col) = spans.format(r.span);
                ExportRef {
                    name: r.name.clone(),
                    kind: format!("{:?}", r.kind).to_lowercase(),
                    line,
                    column: col,
                    resolved_symbol_id: r.resolved.map(|s| s.raw()),
                }
            })
            .collect();

        let strings_out: Vec<ExportString> = idx
            .strings
            .iter()
            .map(|s| {
                let (_, line, col) = spans.format(s.span);
                let cat = format!("{:?}", s.category).to_lowercase();
                *by_cat.entry(cat.clone()).or_insert(0) += 1;
                string_count += 1;
                ExportString {
                    text: s.text.clone(),
                    category: cat,
                    line,
                    column: col,
                }
            })
            .collect();

        files.push(ExportFile {
            path,
            language,
            decls: decls_out,
            imports: imports_out,
            refs: refs_out,
            strings: strings_out,
        });
    }

    let mut languages: Vec<String> = languages_set.into_iter().collect();
    languages.sort();
    let summary = ExportSummary {
        file_count: files.len(),
        decl_count,
        class_count: classes.len(),
        function_count,
        method_count,
        call_site_count,
        call_edge_count: callgraph.len(),
        import_count,
        string_count,
        strings_by_category: serde_json::to_value(&by_cat)?,
        languages,
    };

    let chain_cache = ChainCache::new(ws);
    let (flow_chains, flow_graph) = build_export_flow_sections(ws, global.as_ref(), &chain_cache);
    let taint_graph = build_taint_graph(ws, &spans, full_propagations, &chain_cache);

    Ok(ExportOut {
        engine_version: env!("CARGO_PKG_VERSION"),
        workspace_root: root.display().to_string(),
        generated_at_unix_ms: generated_at_unix_ms(),
        summary,
        files,
        classes,
        callgraph,
        flow_chains,
        flow_graph,
        taint_graph,
    })
}

/// Wall-clock unix-ms timestamp for the export header. Falls back
/// to `0` rather than panicking on systems with a clock before
/// the Unix epoch.
fn generated_at_unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

fn build_export_flow_sections(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    chain_cache: &ChainCache<'_>,
) -> (Vec<ExportFlowChain>, Vec<ExportFlowNode>) {
    // Flow graph + per-function upstream chains. These are the same
    // edges / chains `inspect` walks. Chain enumeration is bounded so
    // high-fan-in hubs don't dominate export.
    const EXPORT_MAX_CHAINS_PER_TARGET: usize = 16;
    const EXPORT_MAX_ENTRY_PROBES: usize = 64;
    let mut flow_chains: Vec<ExportFlowChain> = Vec::new();
    let mut flow_graph: Vec<ExportFlowNode> = Vec::new();
    let flow_files: Vec<_> = global.all_files().collect();
    for file in flow_files {
        for d in global.functions_in(file) {
            let func = bonsai_common::FuncId::new(d.symbol.raw());
            let (chains_r, _) =
                chain_cache.chains_resolved(func, EXPORT_MAX_CHAINS_PER_TARGET, EXPORT_MAX_ENTRY_PROBES);
            let meaningful_chains: Vec<Vec<String>> = chains_r
                .iter()
                .filter(|c| c.funcs.len() > 1)
                .map(|c| chain_to_names(ws, &c.funcs))
                .collect();
            if !meaningful_chains.is_empty() {
                flow_chains.push(ExportFlowChain {
                    target: d.name.clone(),
                    chains: meaningful_chains,
                });
            }
            let mut callers_vec: Vec<String> = chain_cache
                .resolved_graph()
                .callers_of(func)
                .map(|e| func_display_name(ws, e.from))
                .collect();
            callers_vec.sort();
            callers_vec.dedup();
            let mut outgoing: Vec<String> = Vec::new();
            collect_callees(&d.flow_events, &mut outgoing);
            outgoing.sort();
            outgoing.dedup();
            flow_graph.push(ExportFlowNode {
                entry_point: callers_vec.is_empty(),
                function: d.name.clone(),
                callers: callers_vec,
                outgoing,
            });
        }
    }
    flow_chains.sort_by(|a, b| a.target.cmp(&b.target));
    flow_graph.sort_by(|a, b| a.function.cmp(&b.function));
    (flow_chains, flow_graph)
}

fn build_taint_graph(
    ws: &Workspace,
    spans: &ExportSpanCache,
    force_full_propagations: bool,
    chain_cache: &ChainCache<'_>,
) -> ExportTaintGraph {
    use bonsai_common::{FuncId, SymbolId};
    use rayon::prelude::*;

    let db = ws.db();
    let global = db.global_index();

    // ---- functions: FuncId → display name mapping (the single
    // authoritative table other sections reference by `func_id`). ----
    let mut functions: Vec<ExportTaintFunction> = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            let (path, line, _) = spans.format(decl.name_span);
            functions.push(ExportTaintFunction {
                func_id: decl.symbol.raw(),
                name: decl.name.clone(),
                qualified_name: decl.qualified_name.clone(),
                file: path,
                line,
                params: decl.params.clone(),
                kind: format!("{:?}", decl.kind).to_lowercase(),
            });
        }
    }
    functions.sort_by_key(|f| f.func_id);

    // ---- call_edges: every resolved FuncId→FuncId link ----
    let resolved = ws.resolved_call_graph();
    let mut call_edges: Vec<ExportCallEdge> = resolved
        .inner()
        .edges
        .iter()
        .map(|e| ExportCallEdge {
            from: e.from.raw(),
            to: e.to.raw(),
            kind: format!("{:?}", e.kind).to_lowercase(),
            precision: format!("{:?}", e.precision).to_lowercase(),
        })
        .collect();
    call_edges.sort_by(|a, b| a.from.cmp(&b.from).then_with(|| a.to.cmp(&b.to)));

    // ---- function_summaries: G1 return-value taint ----
    let mut function_summaries: Vec<ExportFunctionSummary> = Vec::new();
    for f in &functions {
        let func = FuncId::new(f.func_id);
        let summary = bonsai_taint::function_summary(db, func);
        if summary.returns_taint_of.is_empty() {
            continue;
        }
        function_summaries.push(ExportFunctionSummary {
            function: f.name.clone(),
            file: f.file.clone(),
            line: f.line,
            returns_taint_of: summary.returns_taint_of,
        });
    }
    function_summaries.sort_by(|a, b| a.function.cmp(&b.function));

    // ---- reachable_facts: per-function kinded tokens ----
    let mut reachable_facts: Vec<ExportReachableFacts> = Vec::new();
    for f in &functions {
        let func = FuncId::new(f.func_id);
        let kinded = bonsai_taint::name_reachable_through_func_kinded(func, db);
        if kinded.by_kind.is_empty() {
            continue;
        }
        let mut by_kind: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
        for (kind, tokens) in &kinded.by_kind {
            let mut v: Vec<String> = tokens.iter().cloned().collect();
            v.sort();
            by_kind.insert(format!("{kind:?}").to_lowercase(), v);
        }
        reachable_facts.push(ExportReachableFacts {
            func_id: f.func_id,
            function: f.name.clone(),
            by_kind,
        });
    }
    reachable_facts.sort_by_key(|r| r.func_id);

    // ---- assign_chains: per-function monotonic assign-chain ----
    let mut assign_chains: Vec<ExportAssignChain> = Vec::new();
    for f in &functions {
        let Some(decl) = global.decl_of(SymbolId::new(f.func_id)) else {
            continue;
        };
        if decl.params.is_empty() {
            continue;
        }
        let mut per_param: Vec<ExportAssignChainParam> = Vec::new();
        for (idx, param) in decl.params.iter().enumerate() {
            if param.is_empty() {
                continue;
            }
            let mut seed = bonsai_taint::TokenSet::default();
            seed.insert(param.clone());
            let tainted = bonsai_taint::assign_chain_taints(&seed, &decl.flow_events);
            // Drop the seed-only case (no propagation happened) to
            // keep the export compact.
            if tainted.len() <= 1 {
                continue;
            }
            let mut names: Vec<String> = tainted.into_iter().collect();
            names.sort();
            per_param.push(ExportAssignChainParam {
                param_index: idx,
                param_name: param.clone(),
                tainted: names,
            });
        }
        if per_param.is_empty() {
            continue;
        }
        assign_chains.push(ExportAssignChain {
            func_id: f.func_id,
            function: f.name.clone(),
            per_param,
        });
    }
    assign_chains.sort_by_key(|c| c.func_id);

    // ---- intra_taint: per-function CFG dataflow ----
    let mut intra_taint: Vec<ExportIntraTaint> = Vec::new();
    for f in &functions {
        let Some(decl) = global.decl_of(SymbolId::new(f.func_id)) else {
            continue;
        };
        if decl.params.is_empty() {
            continue;
        }
        let cfg = bonsai_cfg::build_cfg_from_flow(&decl.name, &decl.flow_events);
        let mut per_param: Vec<ExportIntraTaintParam> = Vec::new();
        for (idx, param) in decl.params.iter().enumerate() {
            if param.is_empty() {
                continue;
            }
            let mut seed = bonsai_taint::TokenSet::default();
            seed.insert(param.clone());
            let cfg_config = bonsai_taint::TaintConfig {
                sources: seed,
                sanitizers: bonsai_taint::TokenSet::default(),
                worklist_cap: None,
            };
            let result = bonsai_taint::intraprocedural_taint(&cfg, &cfg_config);
            let mut blocks: Vec<ExportIntraBlock> = Vec::new();
            // Emit blocks whose in OR out is non-empty — the entry
            // always has the seeded param so it appears; blocks the
            // taint never reaches are elided.
            let mut block_ids: Vec<u32> = cfg.blocks.iter().map(|b| b.id.raw()).collect();
            block_ids.sort_unstable();
            for bid_raw in block_ids {
                let bid = bonsai_common::BasicBlockId::new(bid_raw);
                let block_in = result.block_in.get(&bid).cloned().unwrap_or_default();
                let block_out = result.block_out.get(&bid).cloned().unwrap_or_default();
                if block_in.is_empty() && block_out.is_empty() {
                    continue;
                }
                let mut in_vec: Vec<String> = block_in.into_iter().collect();
                let mut out_vec: Vec<String> = block_out.into_iter().collect();
                in_vec.sort();
                out_vec.sort();
                blocks.push(ExportIntraBlock {
                    id: bid_raw,
                    taint_in: in_vec,
                    taint_out: out_vec,
                });
            }
            if blocks.is_empty() {
                continue;
            }
            per_param.push(ExportIntraTaintParam {
                param_index: idx,
                param_name: param.clone(),
                iterations: result.iterations,
                saturated: result.saturated,
                blocks,
            });
        }
        if per_param.is_empty() {
            continue;
        }
        intra_taint.push(ExportIntraTaint {
            func_id: f.func_id,
            function: f.name.clone(),
            per_param,
        });
    }
    intra_taint.sort_by_key(|t| t.func_id);

    // ---- alias_maps: per-file alias resolution ----
    let mut alias_maps: Vec<ExportAliasMap> = Vec::new();
    for file in global.all_files() {
        let Some(imports) = db.import_index(file) else {
            continue;
        };
        let map = bonsai_lang_api::kit::alias_map_from_imports(&imports);
        if map.is_empty() {
            continue;
        }
        let path = ws
            .vfs()
            .path(file)
            .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
        let mut entries: Vec<ExportAliasEntry> = map
            .into_iter()
            .map(|(local, target)| match target {
                bonsai_lang_api::AliasTarget::Member { module, member } => ExportAliasEntry {
                    local,
                    target_kind: "member",
                    module,
                    member: Some(member),
                },
                bonsai_lang_api::AliasTarget::Namespace { module } => ExportAliasEntry {
                    local,
                    target_kind: "namespace",
                    module,
                    member: None,
                },
                bonsai_lang_api::AliasTarget::Type { type_name } => ExportAliasEntry {
                    local,
                    target_kind: "type",
                    module: type_name,
                    member: None,
                },
            })
            .collect();
        entries.sort_by(|a, b| a.local.cmp(&b.local));
        alias_maps.push(ExportAliasMap { file: path, entries });
    }
    alias_maps.sort_by(|a, b| a.file.cmp(&b.file));

    // ---- class_fields: per-class G3 field-taint ----
    let mut class_fields: Vec<ExportClassFields> = Vec::new();
    for file in global.all_files() {
        let decls = global.decls_in(file);
        let classes: Vec<&bonsai_lang_api::Decl> = decls
            .iter()
            .filter(|d| {
                matches!(
                    d.kind,
                    DeclKind::Class
                        | DeclKind::Struct
                        | DeclKind::Trait
                        | DeclKind::Interface
                        | DeclKind::Enum
                )
            })
            .collect();
        for class in &classes {
            let mut tainted: ahash::AHashSet<String> = ahash::AHashSet::default();
            for decl in decls.iter() {
                if !matches!(
                    decl.kind,
                    DeclKind::Method | DeclKind::Constructor | DeclKind::Function
                ) {
                    continue;
                }
                let method_inside_class = decl.parent == Some(class.symbol) || {
                    let body = class.body_span.unwrap_or(class.span);
                    decl.name_span.start >= body.start && decl.name_span.end <= body.end
                };
                if !method_inside_class {
                    continue;
                }
                tainted.extend(
                    decl.receiver_field_writes
                        .iter()
                        .map(|write| write.target.clone()),
                );
            }
            if tainted.is_empty() {
                continue;
            }
            let (path, line, _) = spans.format(class.name_span);
            let mut fields: Vec<String> = tainted.into_iter().collect();
            fields.sort();
            class_fields.push(ExportClassFields {
                class: class.name.clone(),
                file: path,
                line,
                tainted_fields: fields,
            });
        }
    }
    class_fields.sort_by(|a, b| a.class.cmp(&b.class));

    // ---- entry_points: inferred source seeds used by security ----
    let mut entry_points = infer_entry_points_for_export(ws, spans);
    entry_points.sort_by(|a, b| a.function.cmp(&b.function));

    // ---- propagations: interprocedural pass from every entry ----
    let mut decl_by_entry: ahash::AHashMap<(String, u32), bonsai_lang_api::Decl> = ahash::AHashMap::default();
    for file in global.all_files() {
        for d in global.decls_in(file) {
            if !matches!(
                d.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            let (_, line, _) = spans.format(d.name_span);
            decl_by_entry.insert((d.name.clone(), line), d.clone());
        }
    }
    const DEFAULT_FULL_PROPAGATION_MAX_FUNCTIONS: usize = 512;
    const DEFAULT_FULL_PROPAGATION_MAX_ENTRIES: usize = 128;
    let should_materialize_propagations = force_full_propagations
        || (functions.len() <= DEFAULT_FULL_PROPAGATION_MAX_FUNCTIONS
            && entry_points.len() <= DEFAULT_FULL_PROPAGATION_MAX_ENTRIES);
    let propagation_omitted_reason = if should_materialize_propagations {
        None
    } else {
        Some(format!(
            "omitted by default for large workspace (functions={}, inferred_entry_points={}); rerun with --full-propagations for exhaustive records",
            functions.len(),
            entry_points.len()
        ))
    };
    let config = bonsai_taint::InterTaintConfig::default();
    let mut propagations: Vec<ExportTaintPropagations> = if should_materialize_propagations {
        entry_points
            .par_iter()
            .filter_map(|ep| {
                let entry_decl = decl_by_entry.get(&(ep.function.clone(), ep.line))?;
                let entry_func = FuncId::new(entry_decl.symbol.raw());
                let mut seed = bonsai_taint::TokenSet::default();
                for p in &ep.params {
                    seed.insert(p.clone());
                }
                let result = bonsai_taint::interprocedural_taint(entry_func, &seed, &config, db);
                let records: Vec<ExportTaintRecord> = result
                    .call_records
                    .iter()
                    .map(|p| {
                        let caller_name = global
                            .decl_of(SymbolId::new(p.caller.raw()))
                            .map(|d| d.name.clone())
                            .unwrap_or_default();
                        let callee_name = global
                            .decl_of(SymbolId::new(p.callee.raw()))
                            .map(|d| d.name.clone())
                            .unwrap_or_default();
                        let (_, line, _) = spans.format(p.call_span);
                        ExportTaintRecord {
                            caller: caller_name,
                            callee: callee_name,
                            call_line: line,
                            edge_kind: format!("{:?}", p.edge_kind).to_lowercase(),
                            edge_precision: format!("{:?}", p.edge_precision).to_lowercase(),
                            tainted_args: p
                                .tainted_args
                                .iter()
                                .map(|a| ExportTaintedArg {
                                    index: a.index,
                                    value_text: a.value_text.clone(),
                                    param_name: a.param_name.clone(),
                                })
                                .collect(),
                        }
                    })
                    .collect();
                Some(ExportTaintPropagations {
                    entry: ep.function.clone(),
                    entry_file: ep.file.clone(),
                    entry_line: ep.line,
                    precision: format!("{:?}", result.precision).to_lowercase(),
                    pairs_analyzed: result.pairs_analyzed,
                    saturated: result.saturated,
                    records,
                })
            })
            .collect()
    } else {
        Vec::new()
    };
    propagations.sort_by(|a, b| {
        a.entry
            .cmp(&b.entry)
            .then_with(|| a.entry_line.cmp(&b.entry_line))
            .then_with(|| a.entry_file.cmp(&b.entry_file))
    });

    // ---- chains: per-target FuncId chain list ----
    //
    // Bound chain enumeration like the top-level `flow_chains`
    // section does — a runaway hub would otherwise dominate the
    // export's runtime.
    const MAX_CHAINS_PER_TARGET: usize = 16;
    const MAX_ENTRY_PROBES: usize = 64;
    let mut chains: Vec<ExportChain> = Vec::new();
    for f in &functions {
        let target = FuncId::new(f.func_id);
        let (resolved_chains, _) =
            chain_cache.chains_resolved(target, MAX_CHAINS_PER_TARGET, MAX_ENTRY_PROBES);
        let nontrivial: Vec<Vec<u32>> = resolved_chains
            .iter()
            .filter(|c| c.funcs.len() > 1)
            .map(|c| c.funcs.iter().map(|fid| fid.raw()).collect())
            .collect();
        if nontrivial.is_empty() {
            continue;
        }
        chains.push(ExportChain {
            target_func_id: f.func_id,
            target: f.name.clone(),
            chains: nontrivial,
        });
    }
    chains.sort_by_key(|c| c.target_func_id);

    // ---- flow_id_labels: per-function F:/G: labels ----
    let flow_id_cache = ws.flow_ids();
    let mut flow_id_labels: Vec<ExportFlowIdLabels> = Vec::new();
    for f in &functions {
        let func = FuncId::new(f.func_id);
        let labels = flow_id_cache.labels_for_func(func, db, ws.vfs());
        if labels.is_empty() {
            continue;
        }
        flow_id_labels.push(ExportFlowIdLabels {
            func_id: f.func_id,
            function: f.name.clone(),
            labels: labels.iter().cloned().collect(),
            truncated: flow_id_cache.was_truncated(func),
        });
    }
    flow_id_labels.sort_by_key(|l| l.func_id);

    ExportTaintGraph {
        functions,
        call_edges,
        function_summaries,
        reachable_facts,
        assign_chains,
        intra_taint,
        alias_maps,
        class_fields,
        entry_points,
        propagations,
        propagations_complete: should_materialize_propagations,
        propagations_omitted_reason: propagation_omitted_reason,
        chains,
        flow_id_labels,
    }
}

fn infer_entry_points_for_export(ws: &Workspace, spans: &ExportSpanCache) -> Vec<ExportEntryPoint> {
    type EntryParamMap =
        std::collections::BTreeMap<(String, u32), (String, String, Vec<String>, &'static str)>;

    let db = ws.db();
    let global = db.global_index();

    let mut callees_seen: ahash::AHashSet<bonsai_common::SymbolId> = ahash::AHashSet::default();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            collect_callee_symbols(&decl.flow_events, global.as_ref(), &mut callees_seen);
        }
    }

    let class_field_writes = collect_class_field_taints_for_entries(global.as_ref());
    let mut entry_params: EntryParamMap = std::collections::BTreeMap::new();

    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            if is_generated_callable_name(&decl.name) {
                continue;
            }
            let has_callers = callees_seen.contains(&decl.symbol);
            let decorator_entry = detect_framework_decorator(ws, file, decl.name_span);
            let entry_kind = if decorator_entry {
                Some("decorator")
            } else if !has_callers && matches!(decl.kind, DeclKind::Function | DeclKind::Method) {
                Some("unreferenced")
            } else {
                None
            };
            if let Some(kind) = entry_kind {
                let (file_path, line, _) = spans.format(decl.name_span);
                let entry = entry_params
                    .entry((decl.name.clone(), line))
                    .or_insert_with(|| (decl.name.clone(), file_path, Vec::new(), kind));
                for (idx, param) in decl.params.iter().enumerate() {
                    if decl.receiver_param_index == Some(idx) {
                        continue;
                    }
                    if !entry.2.iter().any(|p| p == param) {
                        entry.2.push(param.clone());
                    }
                }
                if kind == "decorator" {
                    entry.3 = "decorator";
                }
            }

            let class_symbol = decl.parent.or_else(|| {
                let probe = decl.name_span;
                global
                    .decls_in(file)
                    .iter()
                    .find(|class| {
                        matches!(
                            class.kind,
                            DeclKind::Class
                                | DeclKind::Struct
                                | DeclKind::Trait
                                | DeclKind::Interface
                                | DeclKind::Enum
                        ) && {
                            let body = class.body_span.unwrap_or(class.span);
                            probe.start >= body.start && probe.end <= body.end
                        }
                    })
                    .map(|class| class.symbol)
            });
            let Some(class_symbol) = class_symbol else {
                continue;
            };
            let Some(fields) = class_field_writes.get(&class_symbol) else {
                continue;
            };
            let mut sorted: Vec<&String> = fields.iter().collect();
            sorted.sort();
            for field_name in sorted {
                if !flow_reads_token(&decl.flow_events, field_name) {
                    continue;
                }
                let (file_path, line, _) = spans.format(decl.name_span);
                let entry = entry_params
                    .entry((decl.name.clone(), line))
                    .or_insert_with(|| (decl.name.clone(), file_path, Vec::new(), "class_field"));
                if !entry.2.iter().any(|p| p == field_name) {
                    entry.2.push(field_name.clone());
                }
                if entry.3 != "decorator" {
                    entry.3 = "class_field";
                }
            }
        }
    }

    entry_params
        .into_iter()
        .filter(|((_function, _line), (function, _file, _params, _kind))| {
            !is_generated_callable_name(function)
        })
        .map(
            |((_function, line), (function, file, params, kind))| ExportEntryPoint {
                function,
                file,
                line,
                kind,
                params,
            },
        )
        .collect()
}

/// True when `name` looks like an adapter-synthesised pseudo-name
/// (`<lambda>`, `<closure>`) rather than a real user-declared
/// function. We exclude these from entry-point inference because
/// they're never the entry to a real chain.
fn is_generated_callable_name(name: &str) -> bool {
    name.starts_with('<') && name.ends_with('>')
}

fn flow_reads_token(events: &[FlowEvent], token: &str) -> bool {
    for event in events {
        match event {
            FlowEvent::Call { receiver, args, .. } => {
                if receiver.as_deref() == Some(token)
                    || args
                        .iter()
                        .any(|arg| arg.place.as_deref() == Some(token) || arg.value_text.trim() == token)
                {
                    return true;
                }
            }
            FlowEvent::Assign {
                source_name,
                source_names,
                source_call_args,
                ..
            } => {
                if source_name.as_deref() == Some(token)
                    || source_names.iter().any(|name| name == token)
                    || source_call_args.iter().any(|arg| arg.trim() == token)
                {
                    return true;
                }
            }
            FlowEvent::Return {
                value_text,
                value_name,
                ..
            } => {
                if value_text.as_deref() == Some(token) || value_name.as_deref() == Some(token) {
                    return true;
                }
            }
            FlowEvent::Throw { value_name, .. } => {
                if value_name.as_deref() == Some(token) {
                    return true;
                }
            }
            FlowEvent::Yield { value_text, .. } => {
                if value_text.as_deref() == Some(token) {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if flow_reads_token(then_events, token) || flow_reads_token(else_events, token) {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if flow_reads_token(body, token) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if flow_reads_token(body, token)
                    || flow_reads_token(catch_events, token)
                    || flow_reads_token(finally_events, token)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn collect_class_field_taints_for_entries(
    global: &bonsai_index::GlobalIndex,
) -> ahash::AHashMap<bonsai_common::SymbolId, ahash::AHashSet<String>> {
    let mut out: ahash::AHashMap<bonsai_common::SymbolId, ahash::AHashSet<String>> =
        ahash::AHashMap::default();
    for file in global.all_files() {
        let decls = global.decls_in(file);
        let classes: Vec<&bonsai_lang_api::Decl> = decls
            .iter()
            .filter(|decl| {
                matches!(
                    decl.kind,
                    DeclKind::Class
                        | DeclKind::Struct
                        | DeclKind::Trait
                        | DeclKind::Interface
                        | DeclKind::Enum
                )
            })
            .collect();
        for decl in decls {
            if !matches!(
                decl.kind,
                DeclKind::Method | DeclKind::Constructor | DeclKind::Function
            ) {
                continue;
            }
            let class_symbol = decl.parent.or_else(|| {
                let probe = decl.name_span;
                classes
                    .iter()
                    .find(|class| {
                        let body = class.body_span.unwrap_or(class.span);
                        probe.start >= body.start && probe.end <= body.end
                    })
                    .map(|class| class.symbol)
            });
            let Some(class_symbol) = class_symbol else {
                continue;
            };
            let entry = out.entry(class_symbol).or_default();
            entry.extend(
                decl.receiver_field_writes
                    .iter()
                    .map(|write| write.target.clone()),
            );
            collect_receiver_field_writes_from_events(&decl.flow_events, &decl.params, entry);
        }
    }
    out
}

fn collect_receiver_field_writes_from_events(
    events: &[FlowEvent],
    params: &[String],
    out: &mut ahash::AHashSet<String>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_names,
                ..
            } => {
                if receiver_field_target(target)
                    && (source_name
                        .as_deref()
                        .is_some_and(|name| param_name_matches(params, name))
                        || source_names.iter().any(|name| param_name_matches(params, name)))
                {
                    out.insert(target.clone());
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_receiver_field_writes_from_events(then_events, params, out);
                collect_receiver_field_writes_from_events(else_events, params, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_receiver_field_writes_from_events(body, params, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_receiver_field_writes_from_events(body, params, out);
                collect_receiver_field_writes_from_events(catch_events, params, out);
                collect_receiver_field_writes_from_events(finally_events, params, out);
            }
            _ => {}
        }
    }
}

/// True when `target` looks like a write to a receiver field —
/// `this.x`, `self.x`, `$this->x` (PHP), `@x` (Ruby), nested
/// member access. Used to detect class-field taint when one method
/// writes a field from a parameter.
fn receiver_field_target(target: &str) -> bool {
    let target = target.trim();
    target.starts_with("this.")
        || target.starts_with("self.")
        || target.starts_with("$this->")
        || target.starts_with('@')
        || target.starts_with("this->")
        || target.contains('.')
        || target.contains("->")
}

/// Case-insensitive-ish param matcher: strips PHP `$`, Rust /
/// C++ reference / pointer prefixes (`&`, `*`) so an adapter
/// emitting raw source text still matches the canonical param
/// name list.
fn param_name_matches(params: &[String], name: &str) -> bool {
    let normalized = normalize_param_name(name);
    params
        .iter()
        .any(|param| normalize_param_name(param) == normalized)
}

/// Strip leading sigils (PHP `$`, ref/pointer `&`/`*`) that
/// adapters sometimes leave on raw param names.
fn normalize_param_name(name: &str) -> &str {
    name.trim().trim_start_matches(['$', '&', '*'])
}

/// True when a Decorator ref appears immediately before
/// `decl_span` with no statement-terminator in between — the same
/// signal `security` uses to call a function "framework-exposed".
fn detect_framework_decorator(ws: &Workspace, file: FileId, decl_span: Span) -> bool {
    let Some(idx) = ws.db().decl_index(file) else {
        return false;
    };
    idx.refs.iter().any(|reference| {
        if reference.kind != RefKind::Decorator || reference.span.end > decl_span.start {
            return false;
        }
        // Bound the decorator-to-decl gap so an unrelated decorator
        // higher up in the file doesn't wrongly attach.
        if decl_span.start.saturating_sub(reference.span.end) > 512 {
            return false;
        }
        if !decorator_is_attached_to_decl(ws, file, reference.span, decl_span) {
            return false;
        }
        true
    })
}

/// Confirm the bytes between the decorator and the decl don't
/// contain any statement-terminator signals (`{ } ;` or stray
/// control chars). Without this check we'd attach a decorator to
/// the wrong decl when the file has structural braces between
/// them.
fn decorator_is_attached_to_decl(
    ws: &Workspace,
    file: FileId,
    decorator_span: Span,
    decl_span: Span,
) -> bool {
    let Ok(snapshot) = ws.vfs().snapshot(file) else {
        // Snapshot failure: fall through optimistically — a missed
        // attach is worse than a false attach for this signal.
        return true;
    };
    let text = snapshot.text.as_bytes();
    let start = decorator_span.end as usize;
    let end = decl_span.start as usize;
    if start >= end || end > text.len() {
        return false;
    }
    let gap = &text[start..end];
    !gap.iter().any(|b| {
        matches!(*b, b'{' | b'}' | b';') || b.is_ascii_control() && *b != b'\n' && *b != b'\r' && *b != b'\t'
    })
}

fn collect_callee_symbols(
    events: &[FlowEvent],
    global: &bonsai_index::GlobalIndex,
    out: &mut ahash::AHashSet<bonsai_common::SymbolId>,
) {
    for event in events {
        match event {
            FlowEvent::Call { name, .. } => collect_callable_name_symbols(name, global, out),
            FlowEvent::Assign {
                source_name,
                source_call,
                source_names,
                ..
            } => {
                if let Some(name) = source_name.as_deref() {
                    collect_callable_name_symbols(name, global, out);
                }
                if let Some(name) = source_call.as_deref() {
                    collect_callable_name_symbols(name, global, out);
                }
                for name in source_names {
                    collect_callable_name_symbols(name, global, out);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_callee_symbols(then_events, global, out);
                collect_callee_symbols(else_events, global, out);
            }
            FlowEvent::Loop { body, .. } => collect_callee_symbols(body, global, out),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_callee_symbols(body, global, out);
                collect_callee_symbols(catch_events, global, out);
                collect_callee_symbols(finally_events, global, out);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_callee_symbols(body, global, out);
            }
            _ => {}
        }
    }
}

/// Resolve a textual call/assign callee name to every callable
/// SymbolId it could refer to. We try both the qualified form
/// (`Foo.bar`) and the bare suffix (`bar`) so the callee-seen set
/// catches both `direct` and `virtual` resolutions.
fn collect_callable_name_symbols(
    name: &str,
    global: &bonsai_index::GlobalIndex,
    out: &mut ahash::AHashSet<bonsai_common::SymbolId>,
) {
    let trimmed = name.trim().trim_start_matches('&').trim_start_matches('*');
    if trimmed.is_empty() {
        return;
    }
    let tail = trimmed.rsplit(&['.', ':'][..]).next().unwrap_or(trimmed).trim();
    for candidate in [trimmed, tail] {
        for symbol in global.find_by_name(candidate) {
            if global.decl_of(*symbol).is_some_and(|decl| {
                matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                )
            }) {
                out.insert(*symbol);
            }
        }
    }
}

struct ExportWalkCtx<'a> {
    callables: &'a ahash::AHashSet<String>,
    classes: &'a ahash::AHashSet<String>,
    spans: &'a ExportSpanCache,
}

fn collect_call_edges_for_export(
    events: &[bonsai_lang_api::FlowEvent],
    caller: &str,
    caller_file: &str,
    caller_line: u32,
    ctx: &ExportWalkCtx<'_>,
    out: &mut Vec<CallEdgeOut>,
    call_site_count: &mut usize,
) {
    let callables = ctx.callables;
    let classes = ctx.classes;
    let spans = ctx.spans;
    let push_call = |name: &str,
                     span: bonsai_common::Span,
                     kind_str_hint: Option<String>,
                     out: &mut Vec<CallEdgeOut>,
                     call_site_count: &mut usize| {
        *call_site_count += 1;
        let (_, line, col) = spans.format(span);
        let short = bonsai_lang_api::kit::short_name_of(name);
        let (precision, kind_str) = if callables.contains(name) || callables.contains(short) {
            (
                "narrowed",
                kind_str_hint.unwrap_or_else(|| "function".to_string()),
            )
        } else if classes.contains(name) || classes.contains(short) {
            ("narrowed", "constructor".to_string())
        } else {
            ("unknown", kind_str_hint.unwrap_or_else(|| "function".to_string()))
        };
        out.push(CallEdgeOut {
            caller: caller.to_string(),
            caller_file: caller_file.to_string(),
            caller_line,
            callee: name.to_string(),
            callee_kind: kind_str,
            call_site_line: line,
            call_site_column: col,
            precision,
        });
    };
    for e in events {
        match e {
            bonsai_lang_api::FlowEvent::Call {
                name,
                span,
                call_kind,
                ..
            } => {
                push_call(
                    name,
                    *span,
                    Some(format!("{:?}", call_kind).to_lowercase()),
                    out,
                    call_site_count,
                );
            }
            bonsai_lang_api::FlowEvent::Assign {
                source_call: Some(name),
                span,
                ..
            } => {
                push_call(name, *span, Some("function".to_string()), out, call_site_count);
            }
            bonsai_lang_api::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_call_edges_for_export(
                    then_events,
                    caller,
                    caller_file,
                    caller_line,
                    ctx,
                    out,
                    call_site_count,
                );
                collect_call_edges_for_export(
                    else_events,
                    caller,
                    caller_file,
                    caller_line,
                    ctx,
                    out,
                    call_site_count,
                );
            }
            bonsai_lang_api::FlowEvent::Loop { body, .. } => collect_call_edges_for_export(
                body,
                caller,
                caller_file,
                caller_line,
                ctx,
                out,
                call_site_count,
            ),
            bonsai_lang_api::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_call_edges_for_export(
                    body,
                    caller,
                    caller_file,
                    caller_line,
                    ctx,
                    out,
                    call_site_count,
                );
                collect_call_edges_for_export(
                    catch_events,
                    caller,
                    caller_file,
                    caller_line,
                    ctx,
                    out,
                    call_site_count,
                );
                collect_call_edges_for_export(
                    finally_events,
                    caller,
                    caller_file,
                    caller_line,
                    ctx,
                    out,
                    call_site_count,
                );
            }
            bonsai_lang_api::FlowEvent::Defer { body, .. }
            | bonsai_lang_api::FlowEvent::Using { body, .. } => {
                collect_call_edges_for_export(
                    body,
                    caller,
                    caller_file,
                    caller_line,
                    ctx,
                    out,
                    call_site_count,
                );
            }
            _ => {}
        }
    }
}

/// True when `inner` lives entirely inside `outer` (same file,
/// same byte range). Used to attach methods to their containing
/// class span.
fn span_contains(outer: bonsai_common::Span, inner: bonsai_common::Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}
