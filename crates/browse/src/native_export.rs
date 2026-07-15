//! Native JSON export SDK.
//!
//! This module owns the command-independent data shape emitted by
//! `bonsai-ninja export` in its default JSON format. The CLI is only
//! responsible for opening the workspace, cache/stdout handling, and
//! selecting this renderer.

use crate::ClassOut;
use bonsai_common::{FileId, FuncId, Precision, Span, SpanMap, SymbolId};
use bonsai_idg::CrossCallEdge;
use bonsai_inspect::{chain_to_names, func_display_name, ChainCache};
use bonsai_lang_api::{DeclKind, FlowEvent};
use bonsai_workspace::{decl_decorator_names, flow_ids::FlowIdLabelOptions, Workspace};
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

#[derive(Copy, Clone, Debug, Default)]
pub struct NativeExportConfig {
    /// Materialize exhaustive interprocedural propagation records.
    /// This is explicit because full-workspace propagation exports
    /// can be much larger than the structural taint graph.
    pub full_propagations: bool,
    /// Request complete semantic chain/flow-label evidence.
    /// Defaults stay bounded for routine exports; this mode is
    /// explicit because dense semantic graphs can have exponentially
    /// many exact paths and may need the compressed callgraph
    /// representation instead of materialized path rows.
    pub complete_chains: bool,
    /// Keep the complete propagation relation in compiler form rather than
    /// materializing its potentially quadratic per-entry transitive product.
    pub compiled_propagations: bool,
}

#[derive(Serialize)]
struct ExportOut<'a> {
    engine_version: &'a str,
    workspace_root: String,
    generated_at_unix_ms: u128,
    /// Declares the exact analysis scope represented by this export.
    /// User-visible analysis facts are semantic only: exact or narrowed
    /// resolver evidence, never broad unresolved fan-out.
    analysis_scope: ExportAnalysisScope,
    /// Whole-document completeness. `false` means one or more exported
    /// evidence sections is intentionally omitted or capped; the exact
    /// missing scope is listed in `analysis_incomplete_reasons` and in
    /// the relevant section-level metadata.
    analysis_complete: bool,
    analysis_incomplete_reasons: Vec<String>,
    summary: ExportSummary,
    files: Vec<ExportFile>,
    classes: Vec<ClassOut>,
    /// Resolved semantic workspace call edges. Unresolved external
    /// lexical call sites are counted in `summary.call_site_count`
    /// and remain visible in per-file refs/flow events, but they are
    /// not exported as analysis callgraph facts.
    callgraph: Vec<CallEdgeOut>,
    /// Workspace-wide flow chains: for every decl that is reachable from
    /// some entry point, the list of chains that lead to it. Each chain
    /// reads top-down `[entry, …, target]` — the same data `inspect`
    /// renders inline. Enables downstream tooling / dashboards to reason
    /// about reachable sinks without re-running the tracer.
    flow_chains: Vec<ExportFlowChain>,
    /// Whether `flow_chains` itself materialized every upstream chain.
    /// `false` means rows were capped or complete mode represented the exact
    /// chain language in `compressed_callgraph` form instead.
    flow_chains_complete: bool,
    /// `enumerated_paths` means `flow_chains` contains concrete
    /// entry-to-target paths. `compressed_callgraph` means the exact
    /// chain language is represented by the semantic `callgraph` /
    /// `flow_graph` sections rather than materializing every path.
    flow_chains_mode: &'static str,
    flow_chains_truncated_targets: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    flow_chains_incomplete_reason: Option<String>,
    /// Workspace flow graph summary: one entry per callable decl with
    /// caller / callee counts and an `entry_point` flag. Analogous to
    /// `dump-callgraph` but structured for programmatic consumption.
    flow_graph: Vec<ExportFlowNode>,
    /// Taint graph — the engine's taint-analysis state materialised
    /// as a document for the requested export scope. Section-level
    /// completeness fields state whether optional or capped evidence is
    /// exhaustive.
    taint_graph: ExportTaintGraph,
}

#[derive(Copy, Clone, Debug, Serialize)]
struct ExportAnalysisScope {
    semantic_max_precision: &'static str,
    full_propagations: bool,
    complete_chains: bool,
    propagations_mode: &'static str,
}

struct ExportCompleteness {
    complete: bool,
    incomplete_reasons: Vec<String>,
}

/// Taint/dataflow document for the workspace. Interprocedural answers and
/// assignment projections come from the canonical IDG. Stable compatibility
/// sections backed by another compiler-local representation identify that
/// backend explicitly; optional and rendered evidence sections carry
/// completeness metadata.
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
    /// Projected from a per-parameter, function-local IDG closure.
    assign_chains: Vec<ExportAssignChain>,
    /// Per-function local CFG presentation: per-block in/out taint
    /// state when each parameter is seeded. This compatibility section
    /// is explicitly labelled `cfg_local`; it is not a second
    /// interprocedural engine or a claim that IDG nodes carry block ids.
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
    /// Whether `propagations` is exhaustive. When false, the export
    /// either omitted concrete rows or represents the exact relation in
    /// compiler form, as declared by `propagations_mode`.
    propagations_complete: bool,
    /// `materialized_entries` contains every derived per-entry row;
    /// `compiled_idg` keeps the exact relation in the function, call-edge,
    /// summary, assignment, field, and entry-point compiler tables without
    /// expanding their transitive product; `omitted` is the bounded default.
    propagations_mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    propagations_omitted_reason: Option<String>,
    /// Per-target resolved chains (FuncId list per chain). Same
    /// structure rendered by `inspect --query` — surfaced here so
    /// tooling doesn't have to re-run chain enumeration.
    chains: Vec<ExportChain>,
    /// Whether `chains` itself materialized every path. `false` means rows
    /// were capped or exact complete mode used the compressed call graph.
    chains_complete: bool,
    chains_mode: &'static str,
    chains_truncated_targets: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    chains_incomplete_reason: Option<String>,
    /// Per-function flow-id labels (`F:<16-hex>` / `G:<16-hex>`).
    /// The stable identifiers `inspect` prints and `security`
    /// joins on. Reusing these verbatim in tooling keeps cross-
    /// invocation references stable.
    flow_id_labels: Vec<ExportFlowIdLabels>,
    /// Whether every concrete flow-id label was materialized. `false` means
    /// rows were capped or exact complete mode used the compressed relation.
    flow_id_labels_complete: bool,
    flow_id_labels_mode: &'static str,
    flow_id_labels_truncated_functions: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    flow_id_labels_incomplete_reason: Option<String>,
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
    resolver_stage: String,
    evidence: String,
    confidence: u8,
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
    /// Compatibility backend for the block-oriented presentation. The
    /// canonical interprocedural engine is the IDG; block ids currently live
    /// only in the local CFG.
    backend: &'static str,
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
    truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    truncation_reason: Option<String>,
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
    /// Canonical symbol identity from the global index. Names and source
    /// positions are presentation only and may collide across declarations.
    func_id: u32,
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
struct ExportTaintPropagationsRef<'a> {
    entry: &'a str,
    entry_file: &'a str,
    entry_line: u32,
    /// Worst precision observed across any traversed resolver edge
    /// during the interprocedural pass from this entry.
    precision: &'static str,
    pairs_analyzed: u32,
    saturated: bool,
    records: Vec<&'a ExportTaintRecord>,
}

#[derive(Clone, Serialize)]
struct ExportTaintRecord {
    caller: String,
    callee: String,
    call_line: u32,
    edge_kind: &'static str,
    edge_precision: &'static str,
    /// One entry per positional argument that was tainted at the
    /// call site. Lets consumers correlate caller-local identifiers
    /// to the callee's parameter names they ended up in.
    tainted_args: Vec<ExportTaintedArg>,
}

#[derive(Clone, Serialize)]
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
    truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    truncation_reason: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    original_name: Option<String>,
    is_wildcard: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    line: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    local_bindings: Vec<String>,
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
    resolver_stage: String,
    evidence: String,
    confidence: u8,
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

    fn line_col(&self, span: Span) -> (u32, u32) {
        let Some((_, map)) = self.files.get(&span.file) else {
            return (0, 0);
        };
        let line_col = map.line_col(span.start);
        (line_col.line, line_col.column)
    }

    fn end_line(&self, span: Span) -> u32 {
        let Some((_, map)) = self.files.get(&span.file) else {
            return 0;
        };
        let end = if span.end > span.start {
            span.end.saturating_sub(1)
        } else {
            span.start
        };
        map.line_col(end).line
    }
}

/// Build the native `export` JSON value from an indexed workspace.
pub fn native_export_json(
    ws: &Workspace,
    root: &Path,
    full_propagations: bool,
) -> serde_json::Result<serde_json::Value> {
    native_export_json_with_config(
        ws,
        root,
        NativeExportConfig {
            full_propagations,
            complete_chains: false,
            compiled_propagations: false,
        },
    )
}

/// Build the native `export` JSON value with explicit renderer
/// options.
pub fn native_export_json_with_config(
    ws: &Workspace,
    root: &Path,
    config: NativeExportConfig,
) -> serde_json::Result<serde_json::Value> {
    serde_json::to_value(native_export(ws, root, config)?)
}

/// Render the native `export` JSON document from an indexed workspace.
pub fn render_native_export_json(
    ws: &Workspace,
    root: &Path,
    full_propagations: bool,
) -> serde_json::Result<String> {
    render_native_export_json_with_config(
        ws,
        root,
        NativeExportConfig {
            full_propagations,
            complete_chains: false,
            compiled_propagations: false,
        },
    )
}

/// Render the native `export` JSON document with explicit renderer
/// options.
pub fn render_native_export_json_with_config(
    ws: &Workspace,
    root: &Path,
    config: NativeExportConfig,
) -> serde_json::Result<String> {
    serde_json::to_string(&native_export(ws, root, config)?)
}

/// Stream the native `export` JSON document to a writer. This serializes
/// top-level sections as they are produced so large structural and taint
/// sections are not retained together in one full export object.
pub fn write_native_export_json_with_config<W: Write + ?Sized>(
    ws: &Workspace,
    root: &Path,
    config: NativeExportConfig,
    writer: &mut W,
) -> serde_json::Result<()> {
    write_native_export_streaming(ws, root, config, writer)
}

fn native_export(
    ws: &Workspace,
    root: &Path,
    config: NativeExportConfig,
) -> serde_json::Result<ExportOut<'static>> {
    let total_started = Instant::now();
    let global = ws.db().global_index();
    let spans = ExportSpanCache::new(ws);
    let structural = build_export_structural_sections(ws, global.as_ref(), &spans, &total_started)?;

    let chain_cache = ChainCache::new(ws);
    let phase_started = Instant::now();
    let chain_limits = ExportChainLimits::bounded_materialization();
    let flow_sections = build_export_flow_sections(
        ws,
        global.as_ref(),
        &chain_cache,
        chain_limits,
        config.complete_chains,
    );
    export_phase_log(format_args!(
        "flow sections: {:.3}s chains={} graph_nodes={} truncated_targets={} mode={}",
        phase_started.elapsed().as_secs_f64(),
        flow_sections.flow_chains.len(),
        flow_sections.flow_graph.len(),
        flow_sections.flow_chains_truncated_targets,
        flow_sections.flow_chains_mode
    ));
    let phase_started = Instant::now();
    let taint_graph = build_taint_graph(ws, &spans, config, chain_limits, &chain_cache);
    let completeness = export_analysis_completeness(
        config,
        flow_sections.flow_chains_truncated_targets,
        taint_graph.chains_truncated_targets,
        taint_graph.flow_id_labels_truncated_functions,
        chain_limits,
    );
    export_phase_log(format_args!(
        "taint graph: {:.3}s total={:.3}s",
        phase_started.elapsed().as_secs_f64(),
        total_started.elapsed().as_secs_f64()
    ));

    Ok(ExportOut {
        engine_version: env!("CARGO_PKG_VERSION"),
        workspace_root: root.display().to_string(),
        generated_at_unix_ms: generated_at_unix_ms(),
        analysis_scope: export_analysis_scope(config),
        analysis_complete: completeness.complete,
        analysis_incomplete_reasons: completeness.incomplete_reasons,
        summary: structural.summary,
        files: structural.files,
        classes: structural.classes,
        callgraph: structural.callgraph,
        flow_chains: flow_sections.flow_chains,
        flow_chains_complete: flow_sections.flow_chains_complete,
        flow_chains_mode: flow_sections.flow_chains_mode,
        flow_chains_truncated_targets: flow_sections.flow_chains_truncated_targets,
        flow_chains_incomplete_reason: flow_sections.flow_chains_incomplete_reason,
        flow_graph: flow_sections.flow_graph,
        taint_graph,
    })
}

fn write_native_export_streaming<W: Write + ?Sized>(
    ws: &Workspace,
    root: &Path,
    config: NativeExportConfig,
    writer: &mut W,
) -> serde_json::Result<()> {
    let total_started = Instant::now();
    let global = ws.db().global_index();
    let spans = ExportSpanCache::new(ws);

    let mut serializer = serde_json::Serializer::new(writer);
    let mut map = serializer.serialize_map(None)?;

    map.serialize_entry("engine_version", env!("CARGO_PKG_VERSION"))?;
    map.serialize_entry("workspace_root", &root.display().to_string())?;
    map.serialize_entry("generated_at_unix_ms", &generated_at_unix_ms())?;
    map.serialize_entry("analysis_scope", &export_analysis_scope(config))?;

    let structural = build_export_structural_sections(ws, global.as_ref(), &spans, &total_started)?;
    map.serialize_entry("summary", &structural.summary)?;
    map.serialize_entry("files", &structural.files)?;
    map.serialize_entry("classes", &structural.classes)?;
    map.serialize_entry("callgraph", &structural.callgraph)?;
    drop(structural);

    let chain_cache = ChainCache::new(ws);
    let chain_limits = ExportChainLimits::bounded_materialization();
    let phase_started = Instant::now();
    let flow_sections = build_export_flow_sections(
        ws,
        global.as_ref(),
        &chain_cache,
        chain_limits,
        config.complete_chains,
    );
    export_phase_log(format_args!(
        "flow sections: {:.3}s chains={} graph_nodes={} truncated_targets={} mode={}",
        phase_started.elapsed().as_secs_f64(),
        flow_sections.flow_chains.len(),
        flow_sections.flow_graph.len(),
        flow_sections.flow_chains_truncated_targets,
        flow_sections.flow_chains_mode
    ));
    map.serialize_entry("flow_chains", &flow_sections.flow_chains)?;
    map.serialize_entry("flow_chains_complete", &flow_sections.flow_chains_complete)?;
    map.serialize_entry("flow_chains_mode", &flow_sections.flow_chains_mode)?;
    map.serialize_entry(
        "flow_chains_truncated_targets",
        &flow_sections.flow_chains_truncated_targets,
    )?;
    if let Some(reason) = &flow_sections.flow_chains_incomplete_reason {
        map.serialize_entry("flow_chains_incomplete_reason", &reason)?;
    }
    map.serialize_entry("flow_graph", &flow_sections.flow_graph)?;
    let flow_chains_truncated_targets = flow_sections.flow_chains_truncated_targets;
    drop(flow_sections);

    let phase_started = Instant::now();
    let functions = export_taint_functions(ws, &spans);
    let chain_rows = export_taint_chains_and_flow_labels(
        ws,
        chain_limits,
        &chain_cache,
        &functions,
        config.complete_chains,
    );
    let completeness = export_analysis_completeness(
        config,
        flow_chains_truncated_targets,
        chain_rows.chains_truncated_targets,
        chain_rows.flow_id_labels_truncated_functions,
        chain_limits,
    );
    map.serialize_entry("analysis_complete", &completeness.complete)?;
    map.serialize_entry("analysis_incomplete_reasons", &completeness.incomplete_reasons)?;
    let taint_graph = ExportTaintGraphStreaming {
        ws,
        spans: &spans,
        functions: &functions,
        chain_rows: &chain_rows,
        config,
    };
    map.serialize_entry("taint_graph", &taint_graph)?;
    export_phase_log(format_args!(
        "taint graph: {:.3}s total={:.3}s",
        phase_started.elapsed().as_secs_f64(),
        total_started.elapsed().as_secs_f64()
    ));
    map.end()
}

struct ExportStructuralSections {
    summary: ExportSummary,
    files: Vec<ExportFile>,
    classes: Vec<ClassOut>,
    callgraph: Vec<CallEdgeOut>,
}

fn build_export_structural_sections(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    spans: &ExportSpanCache,
    total_started: &Instant,
) -> serde_json::Result<ExportStructuralSections> {
    let mut files: Vec<ExportFile> = Vec::new();
    let mut classes: Vec<ClassOut> = Vec::new();
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
        // key. Empty paths fall back to `<unknown>` so JSON rows
        // never carry an empty string for the file column.
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
            let end_line = spans.end_line(d.body_span.unwrap_or(d.span));
            count_call_sites_for_export(&d.flow_events, &mut call_site_count);
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
                    .filter(|m| m.parent == Some(d.symbol))
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
        let mut local_bindings_by_span: ahash::AHashMap<u64, Vec<String>> = ahash::AHashMap::default();
        for imp in &imports_vec {
            if !imp.scope.is_local() {
                continue;
            }
            let Some(name) = imp.alias.as_deref().or(imp.original_name.as_deref()) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let bindings = local_bindings_by_span.entry(imp.span.start).or_default();
            if !bindings.iter().any(|existing| existing == name) {
                bindings.push(name.to_string());
            }
        }
        import_count += imports_vec.iter().filter(|imp| !imp.scope.is_local()).count();
        let imports_out: Vec<ExportImport> = imports_vec
            .iter()
            .filter(|imp| !imp.scope.is_local())
            .map(|imp| {
                let (_, line, _) = spans.format(imp.span);
                ExportImport {
                    module: imp.module.clone(),
                    alias: imp.alias.clone(),
                    original_name: imp.original_name.clone(),
                    is_wildcard: imp.is_wildcard,
                    scope: (!imp.scope.is_module()).then(|| format!("{:?}", imp.scope).to_lowercase()),
                    line,
                    local_bindings: local_bindings_by_span
                        .get(&imp.span.start)
                        .cloned()
                        .unwrap_or_default(),
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
    export_phase_log(format_args!(
        "files/classes/callgraph: {:.3}s files={} decls={} calls={}",
        total_started.elapsed().as_secs_f64(),
        files.len(),
        decl_count,
        call_site_count
    ));

    let callgraph = export_structural_callgraph(ws, global, spans);

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

    Ok(ExportStructuralSections {
        summary,
        files,
        classes,
        callgraph,
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

fn export_phase_enabled() -> bool {
    bonsai_diagnostics::debug::is_enabled("export-phase")
}

fn export_phase_log(args: std::fmt::Arguments<'_>) {
    if export_phase_enabled() {
        let message = bonsai_diagnostics::debug::render_message(&args.to_string());
        eprintln!("[export-phase] {message}");
    }
}

const EXPORT_FLOW_CHAIN_MAX_CHAINS_PER_TARGET: usize = 16;
const EXPORT_FLOW_CHAIN_MAX_ENTRY_PROBES: usize = 64;
const EXPORT_SEMANTIC_FLOW_MAX_PRECISION: Precision = Precision::Narrowed;
const COMPRESSED_CHAIN_ROWS_REASON: &str = "concrete path rows are not materialized in compressed_callgraph mode; the complete semantic chain language is represented by the exported function and resolved call-edge graph";
const COMPRESSED_FLOW_ID_ROWS_REASON: &str = "concrete flow-id label rows are not materialized in compressed_callgraph mode; the complete semantic flow relation is represented by the exported function and resolved call-edge graph";

/// Reuse the canonical compiler IDG for native export projections.
///
/// Adapter capability metadata selects symbolic versus eager field places in
/// the workspace builder. Export does not maintain a second seed/graph policy.
fn export_projection_idg_service(ws: &Workspace) -> Arc<bonsai_idg::IdgQueryService> {
    ws.build_and_seed_idg_service()
}

fn export_analysis_scope(config: NativeExportConfig) -> ExportAnalysisScope {
    ExportAnalysisScope {
        semantic_max_precision: export_precision_label(EXPORT_SEMANTIC_FLOW_MAX_PRECISION),
        full_propagations: config.full_propagations,
        complete_chains: config.complete_chains,
        propagations_mode: propagation_mode(config),
    }
}

fn export_analysis_completeness(
    config: NativeExportConfig,
    flow_chains_truncated_targets: usize,
    taint_chains_truncated_targets: usize,
    flow_id_labels_truncated_functions: usize,
    chain_limits: ExportChainLimits,
) -> ExportCompleteness {
    let mut incomplete_reasons = Vec::new();
    if let Some(reason) = propagation_omitted_reason(config) {
        incomplete_reasons.push(format!("taint_graph.propagations: {reason}"));
    }
    if let Some(reason) = chain_export_incomplete_reason(
        flow_chains_truncated_targets,
        chain_limits.max_chains_per_target,
        chain_limits.max_entry_probes,
        config.complete_chains,
    ) {
        incomplete_reasons.push(format!("flow_chains: {reason}"));
    }
    if let Some(reason) = chain_export_incomplete_reason(
        taint_chains_truncated_targets,
        chain_limits.max_chains_per_target,
        chain_limits.max_entry_probes,
        config.complete_chains,
    ) {
        incomplete_reasons.push(format!("taint_graph.chains: {reason}"));
    }
    if let Some(reason) =
        flow_id_labels_incomplete_reason(flow_id_labels_truncated_functions, config.complete_chains)
    {
        incomplete_reasons.push(format!("taint_graph.flow_id_labels: {reason}"));
    }
    ExportCompleteness {
        complete: incomplete_reasons.is_empty(),
        incomplete_reasons,
    }
}

#[derive(Copy, Clone, Debug)]
struct ExportChainLimits {
    max_chains_per_target: usize,
    max_entry_probes: usize,
}

impl ExportChainLimits {
    #[must_use]
    fn bounded_materialization() -> Self {
        Self {
            max_chains_per_target: EXPORT_FLOW_CHAIN_MAX_CHAINS_PER_TARGET,
            max_entry_probes: EXPORT_FLOW_CHAIN_MAX_ENTRY_PROBES,
        }
    }
}

fn export_flow_label_options() -> FlowIdLabelOptions {
    FlowIdLabelOptions::default()
}

#[allow(clippy::struct_field_names)] // Serialized field names intentionally mirror export JSON keys.
struct ExportFlowSections {
    flow_chains: Vec<ExportFlowChain>,
    flow_chains_complete: bool,
    flow_chains_mode: &'static str,
    flow_chains_truncated_targets: usize,
    flow_chains_incomplete_reason: Option<String>,
    flow_graph: Vec<ExportFlowNode>,
}

fn chain_rows_complete(compressed_chains: bool, truncated_targets: usize) -> bool {
    !compressed_chains && truncated_targets == 0
}

fn chain_rows_incomplete_reason(
    compressed_chains: bool,
    truncated_targets: usize,
    max_chains_per_target: usize,
    max_entry_probes: usize,
    complete_chains_requested: bool,
) -> Option<String> {
    if compressed_chains {
        return Some(COMPRESSED_CHAIN_ROWS_REASON.to_string());
    }
    chain_export_incomplete_reason(
        truncated_targets,
        max_chains_per_target,
        max_entry_probes,
        complete_chains_requested,
    )
}

fn flow_id_rows_complete(compressed_chains: bool, truncated_functions: usize) -> bool {
    !compressed_chains && truncated_functions == 0
}

fn flow_id_rows_incomplete_reason(
    compressed_chains: bool,
    truncated_functions: usize,
    complete_chains_requested: bool,
) -> Option<String> {
    if compressed_chains {
        return Some(COMPRESSED_FLOW_ID_ROWS_REASON.to_string());
    }
    flow_id_labels_incomplete_reason(truncated_functions, complete_chains_requested)
}

fn chain_export_incomplete_reason(
    truncated_targets: usize,
    max_chains_per_target: usize,
    max_entry_probes: usize,
    complete_chains_requested: bool,
) -> Option<String> {
    (truncated_targets > 0).then(|| {
        if complete_chains_requested {
            format!(
                "{truncated_targets} target(s) did not fully enumerate in complete-chain mode \
                 (max_chains_per_target={max_chains_per_target}, max_entry_probes={max_entry_probes}); \
                 rows with truncated=true are prefixes, not complete chain sets; \
                 graph facts and taint facts are still exported, but chain evidence is explicitly incomplete"
            )
        } else {
            format!(
                "{truncated_targets} target(s) hit export chain enumeration limits \
                 (max_chains_per_target={max_chains_per_target}, max_entry_probes={max_entry_probes}); \
                 rows with truncated=true are prefixes, not complete chain sets; \
                 rerun with complete_chains=true for exhaustive semantic chain enumeration"
            )
        }
    })
}

fn flow_id_labels_incomplete_reason(
    truncated_functions: usize,
    complete_chains_requested: bool,
) -> Option<String> {
    (truncated_functions > 0).then(|| {
        if complete_chains_requested {
            format!(
                "{truncated_functions} function(s) did not fully enumerate in complete-chain mode; \
                 rows with truncated=true are prefixes, not complete label sets; \
                 graph facts and taint facts are still exported, but flow-id evidence is explicitly incomplete"
            )
        } else {
            format!(
                "{truncated_functions} function(s) hit flow-id label limits; rows with truncated=true are prefixes, not complete label sets; rerun with complete_chains=true for exhaustive semantic flow-id label enumeration"
            )
        }
    })
}

fn build_export_flow_sections(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    chain_cache: &ChainCache<'_>,
    chain_limits: ExportChainLimits,
    complete_chains: bool,
) -> ExportFlowSections {
    // Flow graph + per-function upstream chains. Default export emits
    // bounded path rows with explicit truncation metadata. Complete
    // complete export always uses the exact compressed semantic callgraph.
    // Selecting unbounded simple-path materialization from a graph-size
    // threshold is unsafe: a small graph can still have exponentially many
    // paths (or cycles), while the compressed graph remains linear in facts.
    let compressed_chains = complete_chains;
    let mut flow_chains: Vec<ExportFlowChain> = Vec::new();
    let mut flow_chains_truncated_targets = 0usize;
    let mut flow_graph: Vec<ExportFlowNode> = Vec::new();
    let flow_files: Vec<_> = global.all_files().collect();
    for file in flow_files {
        for d in global.functions_in(file) {
            let func = bonsai_common::FuncId::new(d.symbol.raw());
            if !compressed_chains {
                let (chains_r, truncation) = chain_cache.chains_resolved(
                    func,
                    chain_limits.max_chains_per_target,
                    chain_limits.max_entry_probes,
                );
                let truncated = truncation.is_truncated();
                if truncated {
                    flow_chains_truncated_targets += 1;
                }
                let meaningful_chains: Vec<Vec<String>> = chains_r
                    .iter()
                    .filter(|c| c.funcs.len() > 1)
                    .map(|c| chain_to_names(ws, &c.funcs))
                    .collect();
                if !meaningful_chains.is_empty() {
                    flow_chains.push(ExportFlowChain {
                        target: d.name.clone(),
                        chains: meaningful_chains,
                        truncated,
                        truncation_reason: truncation.label().map(str::to_string),
                    });
                }
            }
            let mut callers_vec: Vec<String> = chain_cache
                .resolved_graph()
                .callers_of(func)
                .map(|e| func_display_name(ws, e.from))
                .collect();
            callers_vec.sort();
            callers_vec.dedup();
            let mut outgoing: Vec<String> = chain_cache
                .resolved_graph()
                .callees_of(func)
                .map(|e| func_display_name(ws, e.to))
                .collect();
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
    ExportFlowSections {
        flow_chains,
        flow_chains_complete: chain_rows_complete(compressed_chains, flow_chains_truncated_targets),
        flow_chains_mode: if compressed_chains {
            "compressed_callgraph"
        } else {
            "enumerated_paths"
        },
        flow_chains_truncated_targets,
        flow_chains_incomplete_reason: chain_rows_incomplete_reason(
            compressed_chains,
            flow_chains_truncated_targets,
            chain_limits.max_chains_per_target,
            chain_limits.max_entry_probes,
            complete_chains,
        ),
        flow_graph,
    }
}

fn build_taint_graph(
    ws: &Workspace,
    spans: &ExportSpanCache,
    config: NativeExportConfig,
    chain_limits: ExportChainLimits,
    chain_cache: &ChainCache<'_>,
) -> ExportTaintGraph {
    let functions = export_taint_functions(ws, spans);
    let call_edges = export_taint_call_edges(ws);
    let projection_idg = export_projection_idg_service(ws);
    let function_summaries = export_function_summaries_from_idg(&projection_idg, &functions);
    let reachable_facts = export_reachable_facts(ws, &functions);
    let assign_chains = export_assign_chains_from_idg(&projection_idg, &functions);
    let intra_taint = export_intra_taint(ws, &functions);
    let alias_maps = export_alias_maps(ws);
    let class_fields = export_class_fields(ws, spans);
    let entry_points = export_entry_points(ws, spans);
    let propagation_rows =
        export_taint_propagations_from_idg(ws, spans, &projection_idg, &entry_points, config);
    let chain_rows = export_taint_chains_and_flow_labels(
        ws,
        chain_limits,
        chain_cache,
        &functions,
        config.complete_chains,
    );

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
        propagations: propagation_rows.propagations,
        propagations_complete: propagation_rows.complete,
        propagations_mode: propagation_rows.mode,
        propagations_omitted_reason: propagation_rows.omitted_reason,
        chains: chain_rows.chains,
        chains_complete: chain_rows.chains_complete,
        chains_mode: chain_rows.chains_mode,
        chains_truncated_targets: chain_rows.chains_truncated_targets,
        chains_incomplete_reason: chain_rows.chains_incomplete_reason,
        flow_id_labels: chain_rows.flow_id_labels,
        flow_id_labels_complete: chain_rows.flow_id_labels_complete,
        flow_id_labels_mode: chain_rows.flow_id_labels_mode,
        flow_id_labels_truncated_functions: chain_rows.flow_id_labels_truncated_functions,
        flow_id_labels_incomplete_reason: chain_rows.flow_id_labels_incomplete_reason,
    }
}

struct ExportTaintGraphStreaming<'a> {
    ws: &'a Workspace,
    spans: &'a ExportSpanCache,
    functions: &'a [ExportTaintFunction],
    chain_rows: &'a ExportTaintChainsAndFlowLabels,
    config: NativeExportConfig,
}

impl Serialize for ExportTaintGraphStreaming<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;

        let functions = self.functions;
        map.serialize_entry("functions", functions)?;

        let call_edges = export_taint_call_edges(self.ws);
        map.serialize_entry("call_edges", &call_edges)?;
        drop(call_edges);

        let projection_idg = export_projection_idg_service(self.ws);
        let function_summaries = export_function_summaries_from_idg(&projection_idg, functions);
        map.serialize_entry("function_summaries", &function_summaries)?;
        drop(function_summaries);

        let reachable_facts = export_reachable_facts(self.ws, functions);
        map.serialize_entry("reachable_facts", &reachable_facts)?;
        drop(reachable_facts);

        let assign_chains = export_assign_chains_from_idg(&projection_idg, functions);
        map.serialize_entry("assign_chains", &assign_chains)?;
        drop(assign_chains);

        let intra_taint = export_intra_taint(self.ws, functions);
        map.serialize_entry("intra_taint", &intra_taint)?;
        drop(intra_taint);

        let alias_maps = export_alias_maps(self.ws);
        map.serialize_entry("alias_maps", &alias_maps)?;
        drop(alias_maps);

        let class_fields = export_class_fields(self.ws, self.spans);
        map.serialize_entry("class_fields", &class_fields)?;
        drop(class_fields);

        let entry_points = export_entry_points(self.ws, self.spans);
        map.serialize_entry("entry_points", &entry_points)?;

        let propagation_rows = ExportTaintPropagationsStreaming {
            ws: self.ws,
            spans: self.spans,
            idg: &projection_idg,
            entry_points: &entry_points,
            full_propagations: self.config.full_propagations,
        };
        map.serialize_entry("propagations", &propagation_rows)?;
        map.serialize_entry("propagations_complete", &self.config.full_propagations)?;
        map.serialize_entry("propagations_mode", propagation_mode(self.config))?;
        if let Some(reason) = propagation_omitted_reason(self.config) {
            map.serialize_entry("propagations_omitted_reason", &reason)?;
        }
        drop(entry_points);
        drop(projection_idg);

        let chain_rows = self.chain_rows;
        map.serialize_entry("chains", &chain_rows.chains)?;
        map.serialize_entry("chains_complete", &chain_rows.chains_complete)?;
        map.serialize_entry("chains_mode", &chain_rows.chains_mode)?;
        map.serialize_entry("chains_truncated_targets", &chain_rows.chains_truncated_targets)?;
        if let Some(reason) = &chain_rows.chains_incomplete_reason {
            map.serialize_entry("chains_incomplete_reason", &reason)?;
        }
        map.serialize_entry("flow_id_labels", &chain_rows.flow_id_labels)?;
        map.serialize_entry("flow_id_labels_complete", &chain_rows.flow_id_labels_complete)?;
        map.serialize_entry("flow_id_labels_mode", &chain_rows.flow_id_labels_mode)?;
        map.serialize_entry(
            "flow_id_labels_truncated_functions",
            &chain_rows.flow_id_labels_truncated_functions,
        )?;
        if let Some(reason) = &chain_rows.flow_id_labels_incomplete_reason {
            map.serialize_entry("flow_id_labels_incomplete_reason", &reason)?;
        }

        map.end()
    }
}

struct ExportTaintPropagationsSection {
    propagations: Vec<ExportTaintPropagations>,
    complete: bool,
    mode: &'static str,
    omitted_reason: Option<String>,
}

struct ExportTaintPropagationsStreaming<'a> {
    ws: &'a Workspace,
    spans: &'a ExportSpanCache,
    idg: &'a bonsai_idg::IdgQueryService,
    entry_points: &'a [ExportEntryPoint],
    full_propagations: bool,
}

impl Serialize for ExportTaintPropagationsStreaming<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let phase_started = Instant::now();
        if !self.full_propagations {
            let seq = serializer.serialize_seq(Some(0))?;
            export_phase_log(format_args!(
                "taint.propagations: {:.3}s count=0 complete=false",
                phase_started.elapsed().as_secs_f64()
            ));
            return serde::ser::SerializeSeq::end(seq);
        }

        let db = self.ws.db();
        let global = db.global_index();
        let mut render_cache = ExportTaintRecordRenderCache::default();
        let mut seq = serializer.serialize_seq(None)?;
        let mut count = 0usize;
        let progress_stride = self.entry_points.len().div_ceil(100).max(1);
        for ep in self.entry_points {
            let entry_func = FuncId::new(ep.func_id);
            let row_started = Instant::now();
            bonsai_diagnostics::debug_log!(
                "export-row",
                "taint propagation start index={} func={} name={}",
                count,
                ep.func_id,
                ep.function
            );
            {
                let row = export_taint_propagation_row_ref(
                    self.spans,
                    global.as_ref(),
                    self.idg,
                    &mut render_cache,
                    ep,
                    entry_func,
                );
                serde::ser::SerializeSeq::serialize_element(&mut seq, &row)?;
            }
            count += 1;
            bonsai_diagnostics::debug_log!(
                "export-row",
                "taint propagation complete index={} func={} name={} elapsed={:.6}s",
                count - 1,
                ep.func_id,
                ep.function,
                row_started.elapsed().as_secs_f64()
            );
            if count % progress_stride == 0 || count == self.entry_points.len() {
                export_phase_log(format_args!(
                    "taint.propagations progress={}/{} elapsed={:.3}s",
                    count,
                    self.entry_points.len(),
                    phase_started.elapsed().as_secs_f64()
                ));
            }
        }
        let result = serde::ser::SerializeSeq::end(seq);
        export_phase_log(format_args!(
            "taint.propagations: {:.3}s count={} complete=true",
            phase_started.elapsed().as_secs_f64(),
            count
        ));
        result
    }
}

struct ExportTaintChainsAndFlowLabels {
    chains: Vec<ExportChain>,
    chains_complete: bool,
    chains_mode: &'static str,
    chains_truncated_targets: usize,
    chains_incomplete_reason: Option<String>,
    flow_id_labels: Vec<ExportFlowIdLabels>,
    flow_id_labels_complete: bool,
    flow_id_labels_mode: &'static str,
    flow_id_labels_truncated_functions: usize,
    flow_id_labels_incomplete_reason: Option<String>,
}

fn export_taint_functions(ws: &Workspace, spans: &ExportSpanCache) -> Vec<ExportTaintFunction> {
    let db = ws.db();
    let global = db.global_index();

    // ---- functions: FuncId → display name mapping (the single
    // authoritative table other sections reference by `func_id`). ----
    let mut functions: Vec<ExportTaintFunction> = Vec::new();
    let phase_started = Instant::now();
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
    export_phase_log(format_args!(
        "taint.functions: {:.3}s count={}",
        phase_started.elapsed().as_secs_f64(),
        functions.len()
    ));
    functions
}

fn export_structural_callgraph(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    spans: &ExportSpanCache,
) -> Vec<CallEdgeOut> {
    let phase_started = Instant::now();
    let resolved = ws.resolved_call_graph();
    let mut out: Vec<CallEdgeOut> = Vec::new();
    for edge in resolved
        .inner()
        .edges
        .iter()
        .filter(|edge| edge.precision.is_semantic())
    {
        let Some(caller_decl) = global.decl_of(SymbolId::new(edge.from.raw())) else {
            continue;
        };
        let Some(callee_decl) = global.decl_of(SymbolId::new(edge.to.raw())) else {
            continue;
        };
        let (caller_file, caller_line, _) = spans.format(caller_decl.name_span);
        let (_, call_site_line, call_site_column) = spans.format(edge.span);
        out.push(CallEdgeOut {
            caller: caller_decl.name.clone(),
            caller_file,
            caller_line,
            callee: callee_decl.name.clone(),
            callee_kind: format!("{:?}", callee_decl.kind).to_lowercase(),
            call_site_line,
            call_site_column,
            precision: export_precision_label(edge.precision),
            resolver_stage: edge.provenance.resolver_stage.clone(),
            evidence: edge.provenance.evidence.clone(),
            confidence: edge.provenance.confidence,
        });
    }
    out.sort_by(|a, b| {
        a.caller_file
            .cmp(&b.caller_file)
            .then_with(|| a.caller_line.cmp(&b.caller_line))
            .then_with(|| a.call_site_line.cmp(&b.call_site_line))
            .then_with(|| a.call_site_column.cmp(&b.call_site_column))
            .then_with(|| a.caller.cmp(&b.caller))
            .then_with(|| a.callee.cmp(&b.callee))
    });
    export_phase_log(format_args!(
        "structural.callgraph: {:.3}s count={}",
        phase_started.elapsed().as_secs_f64(),
        out.len()
    ));
    out
}

fn export_taint_call_edges(ws: &Workspace) -> Vec<ExportCallEdge> {
    // ---- call_edges: every resolved FuncId→FuncId link ----
    let phase_started = Instant::now();
    let resolved = ws.resolved_call_graph();
    let mut call_edges: Vec<ExportCallEdge> = resolved
        .inner()
        .edges
        .iter()
        .filter(|edge| edge.precision.is_semantic())
        .map(|e| ExportCallEdge {
            from: e.from.raw(),
            to: e.to.raw(),
            kind: format!("{:?}", e.kind).to_lowercase(),
            precision: format!("{:?}", e.precision).to_lowercase(),
            resolver_stage: e.provenance.resolver_stage.clone(),
            evidence: e.provenance.evidence.clone(),
            confidence: e.provenance.confidence,
        })
        .collect();
    call_edges.sort_by(|a, b| a.from.cmp(&b.from).then_with(|| a.to.cmp(&b.to)));
    export_phase_log(format_args!(
        "taint.call_edges: {:.3}s count={}",
        phase_started.elapsed().as_secs_f64(),
        call_edges.len()
    ));
    call_edges
}

fn export_function_summaries_from_idg(
    idg: &bonsai_idg::IdgQueryService,
    functions: &[ExportTaintFunction],
) -> Vec<ExportFunctionSummary> {
    use bonsai_common::FuncId;

    // ---- function_summaries: G1 return-value taint ----
    let phase_started = Instant::now();
    let funcs: Vec<FuncId> = functions
        .iter()
        .map(|function| FuncId::new(function.func_id))
        .collect();
    let return_taint_by_func = idg.return_taint_param_indices_for_funcs_with_max_precision(
        &funcs,
        Some(EXPORT_SEMANTIC_FLOW_MAX_PRECISION),
    );
    let mut function_summaries: Vec<ExportFunctionSummary> = functions
        .iter()
        .filter_map(|f| {
            let func = FuncId::new(f.func_id);
            let returns_taint_of: Vec<usize> = return_taint_by_func
                .get(&func)?
                .iter()
                .copied()
                .take_while(|idx| (*idx as usize) < f.params.len())
                .map(|idx| idx as usize)
                .collect();
            if returns_taint_of.is_empty() {
                return None;
            }
            Some(ExportFunctionSummary {
                function: f.name.clone(),
                file: f.file.clone(),
                line: f.line,
                returns_taint_of,
            })
        })
        .collect();
    function_summaries.sort_by(|a, b| a.function.cmp(&b.function));
    export_phase_log(format_args!(
        "taint.function_summaries: {:.3}s count={}",
        phase_started.elapsed().as_secs_f64(),
        function_summaries.len()
    ));
    function_summaries
}

fn export_reachable_facts(ws: &Workspace, functions: &[ExportTaintFunction]) -> Vec<ExportReachableFacts> {
    use bonsai_common::FuncId;

    // ---- reachable_facts: per-function kinded tokens ----
    let phase_started = Instant::now();
    let mut reachable_facts: Vec<ExportReachableFacts> = Vec::new();
    for f in functions {
        let func = FuncId::new(f.func_id);
        // Workspace-cached structural reachability — same content
        // as `bonsai_taint::name_reachable_through_func_kinded`
        // but memoised across the export pass so two functions
        // sharing a hop don't compute it twice.
        let kinded = ws.name_reachable_kinded_for(func);
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
    export_phase_log(format_args!(
        "taint.reachable_facts: {:.3}s count={}",
        phase_started.elapsed().as_secs_f64(),
        reachable_facts.len()
    ));
    reachable_facts
}

fn export_assign_chains_from_idg(
    idg: &bonsai_idg::IdgQueryService,
    functions: &[ExportTaintFunction],
) -> Vec<ExportAssignChain> {
    use bonsai_common::FuncId;

    let funcs: Vec<FuncId> = functions
        .iter()
        .map(|function| FuncId::new(function.func_id))
        .collect();
    let storage_by_func = idg.local_storage_taint_by_param_for_funcs_with_max_precision(
        &funcs,
        Some(EXPORT_SEMANTIC_FLOW_MAX_PRECISION),
    );

    // ---- assign_chains: per-param function-local IDG projection ----
    let phase_started = Instant::now();
    let mut assign_chains: Vec<ExportAssignChain> = functions
        .iter()
        .filter_map(|f| {
            if f.params.is_empty() {
                return None;
            }
            let func = FuncId::new(f.func_id);
            let storage_by_param = storage_by_func.get(&func)?;
            let mut per_param: Vec<ExportAssignChainParam> = Vec::new();
            for (idx, param) in f.params.iter().enumerate() {
                if param.is_empty() {
                    continue;
                }
                let mut tainted: ahash::AHashSet<String> =
                    storage_by_param.get(idx).into_iter().flatten().cloned().collect();
                tainted.insert(param.clone());
                // Drop the seed-only case (no propagation happened)
                // to keep the export compact.
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
                return None;
            }
            Some(ExportAssignChain {
                func_id: f.func_id,
                function: f.name.clone(),
                per_param,
            })
        })
        .collect();
    assign_chains.sort_by_key(|c| c.func_id);
    export_phase_log(format_args!(
        "taint.assign_chains: {:.3}s count={}",
        phase_started.elapsed().as_secs_f64(),
        assign_chains.len()
    ));
    assign_chains
}

fn export_intra_taint(ws: &Workspace, functions: &[ExportTaintFunction]) -> Vec<ExportIntraTaint> {
    use bonsai_common::SymbolId;
    use rayon::prelude::*;

    let db = ws.db();
    let global = db.global_index();

    // ---- intra_taint: per-function CFG dataflow ----
    let phase_started = Instant::now();
    let mut intra_taint: Vec<ExportIntraTaint> = functions
        .par_iter()
        .filter_map(|f| {
            let decl = global.decl_of(SymbolId::new(f.func_id))?;
            if decl.params.is_empty() {
                return None;
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
                // Emit blocks whose in OR out is non-empty — the
                // entry always has the seeded param so it appears;
                // blocks the taint never reaches are elided.
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
                return None;
            }
            Some(ExportIntraTaint {
                func_id: f.func_id,
                function: f.name.clone(),
                backend: "cfg_local",
                per_param,
            })
        })
        .collect();
    intra_taint.sort_by_key(|t| t.func_id);
    export_phase_log(format_args!(
        "taint.intra_taint: {:.3}s count={}",
        phase_started.elapsed().as_secs_f64(),
        intra_taint.len()
    ));
    intra_taint
}

fn export_alias_maps(ws: &Workspace) -> Vec<ExportAliasMap> {
    let db = ws.db();
    let global = db.global_index();

    // ---- alias_maps: per-file alias resolution ----
    let phase_started = Instant::now();
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
    export_phase_log(format_args!(
        "taint.alias_maps: {:.3}s count={}",
        phase_started.elapsed().as_secs_f64(),
        alias_maps.len()
    ));
    alias_maps
}

fn export_class_fields(ws: &Workspace, spans: &ExportSpanCache) -> Vec<ExportClassFields> {
    let db = ws.db();
    let global = db.global_index();

    // ---- class_fields: per-class G3 field-taint ----
    let phase_started = Instant::now();
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
                let method_inside_class = decl.parent == Some(class.symbol);
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
    export_phase_log(format_args!(
        "taint.class_fields: {:.3}s count={}",
        phase_started.elapsed().as_secs_f64(),
        class_fields.len()
    ));
    class_fields
}

fn export_entry_points(ws: &Workspace, spans: &ExportSpanCache) -> Vec<ExportEntryPoint> {
    // ---- entry_points: inferred source seeds used by security ----
    let phase_started = Instant::now();
    let mut entry_points = infer_entry_points_for_export(ws, spans);
    entry_points.sort_by(|a, b| {
        a.function
            .cmp(&b.function)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.func_id.cmp(&b.func_id))
    });
    export_phase_log(format_args!(
        "taint.entry_points: {:.3}s count={}",
        phase_started.elapsed().as_secs_f64(),
        entry_points.len()
    ));
    entry_points
}

fn export_taint_propagations_from_idg(
    ws: &Workspace,
    spans: &ExportSpanCache,
    idg: &bonsai_idg::IdgQueryService,
    entry_points: &[ExportEntryPoint],
    config: NativeExportConfig,
) -> ExportTaintPropagationsSection {
    let db = ws.db();
    let global = db.global_index();
    let should_materialize_propagations = config.full_propagations;
    let propagation_omitted_reason = propagation_omitted_reason(config);
    let phase_started = Instant::now();
    let mut propagations: Vec<ExportTaintPropagations> = if should_materialize_propagations {
        export_taint_propagation_rows(spans, global.as_ref(), idg, entry_points)
    } else {
        Vec::new()
    };
    sort_taint_propagations(&mut propagations);
    export_phase_log(format_args!(
        "taint.propagations: {:.3}s count={} complete={}",
        phase_started.elapsed().as_secs_f64(),
        propagations.len(),
        should_materialize_propagations
    ));
    ExportTaintPropagationsSection {
        propagations,
        complete: should_materialize_propagations,
        mode: propagation_mode(config),
        omitted_reason: propagation_omitted_reason,
    }
}

fn propagation_mode(config: NativeExportConfig) -> &'static str {
    if config.full_propagations {
        "materialized_entries"
    } else if config.compiled_propagations {
        "compiled_idg"
    } else {
        "omitted"
    }
}

fn propagation_omitted_reason(config: NativeExportConfig) -> Option<String> {
    (propagation_mode(config) == "omitted").then(|| {
        "interprocedural propagation records are omitted by default; rerun export --full-propagations for exhaustive propagation records".to_string()
    })
}

fn export_taint_propagation_rows(
    spans: &ExportSpanCache,
    global: &bonsai_index::GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
    entry_points: &[ExportEntryPoint],
) -> Vec<ExportTaintPropagations> {
    let mut render_cache = ExportTaintRecordRenderCache::default();
    let mut rows: Vec<_> = entry_points
        .iter()
        .map(|ep| {
            export_taint_propagation_row(spans, global, idg, &mut render_cache, ep, FuncId::new(ep.func_id))
        })
        .collect();
    sort_taint_propagations(&mut rows);
    rows
}

fn sort_taint_propagations(rows: &mut [ExportTaintPropagations]) {
    rows.sort_by(|a, b| {
        a.entry
            .cmp(&b.entry)
            .then_with(|| a.entry_line.cmp(&b.entry_line))
            .then_with(|| a.entry_file.cmp(&b.entry_file))
    });
}

#[derive(Clone)]
struct ExportFuncRender {
    name: String,
    params: Vec<String>,
}

#[derive(Default)]
struct ExportTaintRecordRenderCache {
    records: ahash::AHashMap<CrossCallEdge, Option<ExportTaintRecord>>,
    funcs: ahash::AHashMap<FuncId, Option<ExportFuncRender>>,
    call_lines: ahash::AHashMap<Span, u32>,
    call_arg_texts: ahash::AHashMap<FuncId, Option<CallArgTextBySite>>,
}

type CallArgTextBySite = ahash::AHashMap<(Span, u32), String>;

fn export_taint_propagation_row(
    spans: &ExportSpanCache,
    global: &bonsai_index::GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
    render_cache: &mut ExportTaintRecordRenderCache,
    ep: &ExportEntryPoint,
    entry_func: bonsai_common::FuncId,
) -> ExportTaintPropagations {
    let seed_nodes = canonical_legacy_seed_nodes(idg, entry_func, &ep.params, global);
    let mut cross_calls = idg.cross_call_edges_in_closure_with_max_precision(
        &seed_nodes,
        Some(EXPORT_SEMANTIC_FLOW_MAX_PRECISION),
    );
    sort_cross_call_edges_for_export(&mut cross_calls);
    let records: Vec<ExportTaintRecord> = cross_calls
        .iter()
        .filter_map(|ce| cached_export_taint_record(render_cache, ce, global, spans))
        .collect();
    let aggregate_precision =
        crate::taint::aggregate_flow_precision(cross_calls.iter().map(|ce| ce.precision));
    let unique_pairs: ahash::AHashSet<(bonsai_common::FuncId, bonsai_common::FuncId)> =
        cross_calls.iter().map(|ce| (ce.caller, ce.callee)).collect();
    let pairs_analyzed = std::cmp::max(1, unique_pairs.len());
    ExportTaintPropagations {
        entry: ep.function.clone(),
        entry_file: ep.file.clone(),
        entry_line: ep.line,
        precision: crate::taint::precision_display(aggregate_precision),
        pairs_analyzed: u32::try_from(pairs_analyzed).unwrap_or(u32::MAX),
        saturated: false,
        records,
    }
}

fn export_taint_propagation_row_ref<'a>(
    spans: &ExportSpanCache,
    global: &bonsai_index::GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
    render_cache: &'a mut ExportTaintRecordRenderCache,
    ep: &'a ExportEntryPoint,
    entry_func: bonsai_common::FuncId,
) -> ExportTaintPropagationsRef<'a> {
    let seed_nodes = canonical_legacy_seed_nodes(idg, entry_func, &ep.params, global);
    let mut cross_calls = idg.cross_call_edges_in_closure_with_max_precision(
        &seed_nodes,
        Some(EXPORT_SEMANTIC_FLOW_MAX_PRECISION),
    );
    sort_cross_call_edges_for_export(&mut cross_calls);
    let aggregate_precision =
        crate::taint::aggregate_flow_precision(cross_calls.iter().map(|ce| ce.precision));
    let unique_pairs: ahash::AHashSet<(bonsai_common::FuncId, bonsai_common::FuncId)> =
        cross_calls.iter().map(|ce| (ce.caller, ce.callee)).collect();
    let pairs_analyzed = std::cmp::max(1, unique_pairs.len());
    cross_calls.retain(|ce| ensure_cached_export_taint_record(render_cache, ce, global, spans));
    let records: Vec<&ExportTaintRecord> = cross_calls
        .iter()
        .filter_map(|ce| render_cache.records.get(ce).and_then(Option::as_ref))
        .collect();
    ExportTaintPropagationsRef {
        entry: &ep.function,
        entry_file: &ep.file,
        entry_line: ep.line,
        precision: export_precision_label(aggregate_precision),
        pairs_analyzed: u32::try_from(pairs_analyzed).unwrap_or(u32::MAX),
        saturated: false,
        records,
    }
}

fn canonical_legacy_seed_nodes(
    idg: &bonsai_idg::IdgQueryService,
    entry_func: bonsai_common::FuncId,
    names: &[String],
    global: &bonsai_index::GlobalIndex,
) -> Vec<bonsai_idg::WsNodeId> {
    let seeds: bonsai_taint::TokenSet = names.iter().cloned().collect();
    bonsai_taint::compose_idg_seed_nodes(
        bonsai_taint::IdgSeedRequest::legacy_tokens(entry_func, &seeds),
        global,
        idg,
    )
}

fn sort_cross_call_edges_for_export(cross_calls: &mut [CrossCallEdge]) {
    cross_calls.sort_unstable_by_key(|ce| {
        (
            ce.caller.raw(),
            ce.callee.raw(),
            ce.call_span.file.raw(),
            ce.call_span.start,
            export_edge_kind_rank(ce.call_kind),
            export_precision_rank(ce.precision),
            ce.arg_idx,
            ce.param_idx,
        )
    });
}

fn cached_export_taint_record(
    cache: &mut ExportTaintRecordRenderCache,
    edge: &CrossCallEdge,
    global: &bonsai_index::GlobalIndex,
    spans: &ExportSpanCache,
) -> Option<ExportTaintRecord> {
    ensure_cached_export_taint_record(cache, edge, global, spans)
        .then(|| cache.records.get(edge).cloned().flatten())
        .flatten()
}

fn ensure_cached_export_taint_record(
    cache: &mut ExportTaintRecordRenderCache,
    edge: &CrossCallEdge,
    global: &bonsai_index::GlobalIndex,
    spans: &ExportSpanCache,
) -> bool {
    if let Some(cached) = cache.records.get(edge) {
        return cached.is_some();
    }
    let rendered = export_taint_record_from_cross_call(cache, edge, global, spans);
    let present = rendered.is_some();
    cache.records.insert(*edge, rendered);
    present
}

fn export_taint_record_from_cross_call(
    cache: &mut ExportTaintRecordRenderCache,
    edge: &CrossCallEdge,
    global: &bonsai_index::GlobalIndex,
    spans: &ExportSpanCache,
) -> Option<ExportTaintRecord> {
    if !edge.relation.is_renderable_call() {
        return None;
    }
    let caller = cached_export_func_render(cache, global, edge.caller)?;
    let callee = cached_export_func_render(cache, global, edge.callee)?;
    let call_line = cached_export_call_line(cache, spans, edge.call_span);
    let value_text = cached_export_call_arg_text(cache, global, edge.caller, edge.call_span, edge.arg_idx)
        .unwrap_or_default();
    let param_name = callee
        .params
        .get(edge.param_idx as usize)
        .cloned()
        .unwrap_or_default();

    Some(ExportTaintRecord {
        caller: caller.name,
        callee: callee.name,
        call_line,
        edge_kind: export_edge_kind_label(edge.call_kind),
        edge_precision: export_precision_label(edge.precision),
        tainted_args: vec![ExportTaintedArg {
            index: edge.arg_idx as usize,
            value_text,
            param_name,
        }],
    })
}

fn cached_export_func_render(
    cache: &mut ExportTaintRecordRenderCache,
    global: &bonsai_index::GlobalIndex,
    func: FuncId,
) -> Option<ExportFuncRender> {
    if !cache.funcs.contains_key(&func) {
        let rendered = global
            .decl_of(SymbolId::new(func.raw()))
            .map(|decl| ExportFuncRender {
                name: decl.name.clone(),
                params: decl.params.clone(),
            });
        cache.funcs.insert(func, rendered);
    }
    cache.funcs.get(&func).and_then(Clone::clone)
}

fn cached_export_call_line(
    cache: &mut ExportTaintRecordRenderCache,
    spans: &ExportSpanCache,
    span: Span,
) -> u32 {
    if let Some(line) = cache.call_lines.get(&span) {
        return *line;
    }
    let (line, _) = spans.line_col(span);
    cache.call_lines.insert(span, line);
    line
}

fn cached_export_call_arg_text(
    cache: &mut ExportTaintRecordRenderCache,
    global: &bonsai_index::GlobalIndex,
    caller: FuncId,
    call_span: Span,
    arg_idx: u32,
) -> Option<String> {
    if !cache.call_arg_texts.contains_key(&caller) {
        let rendered = export_call_arg_texts_for_func(global, caller);
        cache.call_arg_texts.insert(caller, rendered);
    }
    cache
        .call_arg_texts
        .get(&caller)
        .and_then(Option::as_ref)
        .and_then(|arg_texts| arg_texts.get(&(call_span, arg_idx)).cloned())
}

fn export_call_arg_texts_for_func(
    global: &bonsai_index::GlobalIndex,
    func: FuncId,
) -> Option<ahash::AHashMap<(Span, u32), String>> {
    let decl = global.decl_of(SymbolId::new(func.raw()))?;
    let mut arg_texts = ahash::AHashMap::default();
    collect_export_call_arg_texts(&decl.flow_events, &mut arg_texts);
    Some(arg_texts)
}

fn collect_export_call_arg_texts(events: &[FlowEvent], out: &mut ahash::AHashMap<(Span, u32), String>) {
    for event in events {
        match event {
            FlowEvent::Call { span, args, .. } => {
                for (idx, arg) in args.iter().enumerate() {
                    let Ok(idx) = u32::try_from(idx) else {
                        continue;
                    };
                    out.insert((*span, idx), arg.value_text.clone());
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_export_call_arg_texts(then_events, out);
                collect_export_call_arg_texts(else_events, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_export_call_arg_texts(body, out);
                collect_export_call_arg_texts(catch_events, out);
                collect_export_call_arg_texts(finally_events, out);
            }
            FlowEvent::Loop { body, .. } => {
                collect_export_call_arg_texts(body, out);
            }
            _ => {}
        }
    }
}

fn export_edge_kind_label(kind: bonsai_callgraph::EdgeKind) -> &'static str {
    match kind {
        bonsai_callgraph::EdgeKind::Direct => "direct",
        bonsai_callgraph::EdgeKind::Virtual => "virtual",
        bonsai_callgraph::EdgeKind::Indirect => "indirect",
        bonsai_callgraph::EdgeKind::Unknown => "unknown",
    }
}

fn export_edge_kind_rank(kind: bonsai_callgraph::EdgeKind) -> u8 {
    match kind {
        bonsai_callgraph::EdgeKind::Direct => 0,
        bonsai_callgraph::EdgeKind::Virtual => 1,
        bonsai_callgraph::EdgeKind::Indirect => 2,
        bonsai_callgraph::EdgeKind::Unknown => 3,
    }
}

fn export_precision_label(precision: Precision) -> &'static str {
    match precision {
        Precision::Exact => "exact",
        Precision::Narrowed => "narrowed",
        Precision::OverApproximate => "over-approximate",
        Precision::Unknown => "unknown",
    }
}

fn export_precision_rank(precision: Precision) -> u8 {
    match precision {
        Precision::Exact => 0,
        Precision::Narrowed => 1,
        Precision::OverApproximate => 2,
        Precision::Unknown => 3,
    }
}

fn export_taint_chains_and_flow_labels(
    ws: &Workspace,
    chain_limits: ExportChainLimits,
    chain_cache: &ChainCache<'_>,
    functions: &[ExportTaintFunction],
    complete_chains: bool,
) -> ExportTaintChainsAndFlowLabels {
    use bonsai_common::FuncId;

    let db = ws.db();
    let compressed_chains = complete_chains;

    // ---- chains: per-target FuncId chain list ----
    let phase_started = Instant::now();
    let mut chains: Vec<ExportChain> = Vec::new();
    let mut chains_truncated_targets = 0usize;
    let mut flow_label_chain_sets: Vec<(FuncId, Vec<Vec<FuncId>>, bool)> =
        Vec::with_capacity(functions.len());
    if !compressed_chains {
        for f in functions {
            let target = FuncId::new(f.func_id);
            let (resolved_chains, truncation) = chain_cache.chains_resolved(
                target,
                chain_limits.max_chains_per_target,
                chain_limits.max_entry_probes,
            );
            let truncated = truncation.is_truncated();
            if truncated {
                chains_truncated_targets += 1;
            }
            flow_label_chain_sets.push((
                target,
                resolved_chains.iter().map(|c| c.funcs.clone()).collect(),
                truncated,
            ));
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
                truncated,
                truncation_reason: truncation.label().map(str::to_string),
            });
        }
    }
    chains.sort_by_key(|c| c.target_func_id);
    export_phase_log(format_args!(
        "taint.chains: {:.3}s count={} truncated_targets={} mode={}",
        phase_started.elapsed().as_secs_f64(),
        chains.len(),
        chains_truncated_targets,
        if compressed_chains {
            "compressed_callgraph"
        } else {
            "enumerated_paths"
        }
    ));

    // ---- flow_id_labels: per-function F:/G: labels ----
    let phase_started = Instant::now();
    let flow_label_options = export_flow_label_options();
    let flow_label_rows = if compressed_chains {
        Vec::new()
    } else {
        ws.flow_ids().labels_for_chain_sets_with_options(
            flow_label_chain_sets,
            db,
            ws.vfs(),
            flow_label_options,
        )
    };
    let function_names: ahash::AHashMap<u32, &str> =
        functions.iter().map(|f| (f.func_id, f.name.as_str())).collect();
    let mut flow_id_labels: Vec<ExportFlowIdLabels> = Vec::new();
    let mut flow_id_labels_truncated_functions = 0usize;
    for (func, labels, truncated) in flow_label_rows {
        if truncated {
            flow_id_labels_truncated_functions += 1;
        }
        if labels.is_empty() {
            continue;
        }
        let func_id = func.raw();
        flow_id_labels.push(ExportFlowIdLabels {
            func_id,
            function: function_names
                .get(&func_id)
                .copied()
                .unwrap_or_default()
                .to_string(),
            labels: labels.iter().cloned().collect(),
            truncated,
        });
    }
    flow_id_labels.sort_by_key(|l| l.func_id);
    export_phase_log(format_args!(
        "taint.flow_id_labels: {:.3}s count={} truncated_functions={} mode={}",
        phase_started.elapsed().as_secs_f64(),
        flow_id_labels.len(),
        flow_id_labels_truncated_functions,
        if compressed_chains {
            "compressed_callgraph"
        } else {
            "materialized_flow_ids"
        }
    ));

    ExportTaintChainsAndFlowLabels {
        chains,
        chains_complete: chain_rows_complete(compressed_chains, chains_truncated_targets),
        chains_mode: if compressed_chains {
            "compressed_callgraph"
        } else {
            "enumerated_paths"
        },
        chains_truncated_targets,
        chains_incomplete_reason: chain_rows_incomplete_reason(
            compressed_chains,
            chains_truncated_targets,
            chain_limits.max_chains_per_target,
            chain_limits.max_entry_probes,
            complete_chains,
        ),
        flow_id_labels,
        flow_id_labels_complete: flow_id_rows_complete(compressed_chains, flow_id_labels_truncated_functions),
        flow_id_labels_mode: if compressed_chains {
            "compressed_callgraph"
        } else {
            "materialized_flow_ids"
        },
        flow_id_labels_truncated_functions,
        flow_id_labels_incomplete_reason: flow_id_rows_incomplete_reason(
            compressed_chains,
            flow_id_labels_truncated_functions,
            complete_chains,
        ),
    }
}

fn infer_entry_points_for_export(ws: &Workspace, spans: &ExportSpanCache) -> Vec<ExportEntryPoint> {
    type EntryParamMap = std::collections::BTreeMap<u32, (String, String, u32, Vec<String>, &'static str)>;

    let db = ws.db();
    let global = db.global_index();

    let callees_seen: ahash::AHashSet<bonsai_common::SymbolId> = ws
        .resolved_call_graph()
        .inner()
        .edges
        .iter()
        .filter(|edge| edge.precision.is_semantic())
        .map(|edge| bonsai_common::SymbolId::new(edge.to.raw()))
        .collect();

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
            let decorator_entry =
                detect_framework_decorator(ws, global.as_ref(), file, decl.span, decl.name_span);
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
                    .entry(decl.symbol.raw())
                    .or_insert_with(|| (decl.name.clone(), file_path, line, Vec::new(), kind));
                for (idx, param) in decl.params.iter().enumerate() {
                    if decl.receiver_param_index == Some(idx) {
                        continue;
                    }
                    if !entry.3.iter().any(|p| p == param) {
                        entry.3.push(param.clone());
                    }
                }
                if kind == "decorator" {
                    entry.4 = "decorator";
                }
            }

            let class_symbol = decl.parent;
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
                    .entry(decl.symbol.raw())
                    .or_insert_with(|| (decl.name.clone(), file_path, line, Vec::new(), "class_field"));
                if !entry.3.iter().any(|p| p == field_name) {
                    entry.3.push(field_name.clone());
                }
                if entry.4 != "decorator" {
                    entry.4 = "class_field";
                }
            }
        }
    }

    entry_params
        .into_iter()
        .filter(|(_func_id, (function, _file, _line, _params, _kind))| !is_generated_callable_name(function))
        .map(
            |(func_id, (function, file, line, params, kind))| ExportEntryPoint {
                func_id,
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
        for decl in decls {
            if !matches!(
                decl.kind,
                DeclKind::Method | DeclKind::Constructor | DeclKind::Function
            ) {
                continue;
            }
            let class_symbol = decl.parent;
            let Some(class_symbol) = class_symbol else {
                continue;
            };
            let entry = out.entry(class_symbol).or_default();
            entry.extend(
                decl.receiver_field_writes
                    .iter()
                    .map(|write| write.target.clone()),
            );
        }
    }
    out
}

/// True when a Decorator ref is statically attached to `decl_span`.
///
/// Keep this routed through the same helper as `defs --has-decorator`
/// so export entrypoint inference cannot drift into a broader
/// file-scoped or gap-only heuristic.
fn detect_framework_decorator(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    file: FileId,
    decl_span: Span,
    decl_name_span: Span,
) -> bool {
    let Some(idx) = global.file_index(file) else {
        return false;
    };
    !decl_decorator_names(ws, file, idx, decl_span, decl_name_span).is_empty()
}

fn count_call_sites_for_export(events: &[bonsai_lang_api::FlowEvent], call_site_count: &mut usize) {
    for e in events {
        match e {
            bonsai_lang_api::FlowEvent::Call { .. }
            | bonsai_lang_api::FlowEvent::Assign {
                source_call: Some(_), ..
            } => *call_site_count += 1,
            bonsai_lang_api::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                count_call_sites_for_export(then_events, call_site_count);
                count_call_sites_for_export(else_events, call_site_count);
            }
            bonsai_lang_api::FlowEvent::Loop { body, .. } => {
                count_call_sites_for_export(body, call_site_count);
            }
            bonsai_lang_api::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                count_call_sites_for_export(body, call_site_count);
                count_call_sites_for_export(catch_events, call_site_count);
                count_call_sites_for_export(finally_events, call_site_count);
            }
            bonsai_lang_api::FlowEvent::Defer { body, .. }
            | bonsai_lang_api::FlowEvent::Using { body, .. } => {
                count_call_sites_for_export(body, call_site_count);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "native_export_tests.rs"]
mod tests;
