//! `bonsai-ninja inspect` — render every call chain that reaches a
//! target symbol, each with source-inlined function bodies and step
//! annotations. JSON output is structurally the same, keyed by
//! `InspectReport`.

use anyhow::{Context, Result};
use bonsai_lang_api::{DeclKind, FlowEvent, RefKind};
use bonsai_sdk::Workspace;
use bonsai_sdk::{
    compute_flow_labels_from, compute_structural_flow_id, compute_structural_group_id, compute_taint_flow_id,
    file_path_matches_filter, find_call_span_to_func_uncached, func_display_name, CallEdgeResolver,
    ChainCache, EntryTaintGraph, ResolvedChain, SyntaxFlowPlan, SyntaxFlowQuery, TaintFlowIdentityStep,
    TaintedCall, TaintedCallEdge, TaintedCallKind,
};
use comfy_table::Cell;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::args::{BrowseFormat, InspectView, GROUPED_VIEW_AUTO_THRESHOLD};
use crate::footer::render_paging_footer;
use crate::out_count;
use crate::page_cache;
use crate::paging;
use crate::ui::Ui;
use crate::{cli_println, progress, ui, NO_CACHE};

use crate::args::FactKindFilter;
use bonsai_sdk::refs::read_snippet;
use bonsai_sdk::RefOut;

use super::{
    format_span, nearest_names, open_project_index_matching_literal, open_project_index_matching_path,
    open_project_index_only as open_project, open_project_index_retrieval_candidate_union,
    open_project_index_retrieval_candidates, page_info_to_json, paged_json_incomplete_reasons, short_file,
    truncate, workspace_file_count_exceeds,
};

/// Above this size, default inspect stays on the indexed syntax surface.
/// Graph work is requested explicitly with `--graph-flow`, `--flow`,
/// `--group`, or an endpoint pair. Building a workspace call graph merely
/// because output paging is disabled would be the wrong scaling shape on
/// repositories like Elasticsearch.
const INSPECT_GRAPH_FLOW_FILE_LIMIT: usize = 5_000;
const FLOW_LABEL_PLACEHOLDER: &str = "__BONSAI_FLOW_LABEL__";

#[derive(Serialize, Clone)]
struct InspectOut {
    symbol: String,
    kind: String,
    file: String,
    line: u32,
    column: u32,
    params: Vec<String>,
    direct_callers: Vec<RefOut>,
    callees: Vec<String>,
    /// Whether static entry-point chains were actually evaluated for this
    /// declaration. Plain large-workspace inspect is intentionally a syntax
    /// query; an empty `flows` list in that mode must not be presented as
    /// proof that no caller reaches the symbol.
    graph_flows_evaluated: bool,
    flows: Vec<InspectFlowRendered>,
    /// Longest-shared-suffix grouping of `flows`. Always populated
    /// alongside `flows` so JSON consumers can pick either view.
    /// The text renderer honors `--view trace|grouped|auto`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    groups: Vec<InspectFlowGroup>,
    summary: InspectSummary,
}

#[derive(Serialize, Clone)]
struct InspectSummary {
    total_flows: u32,
    max_chain_depth: u32,
    unique_entry_points: u32,
}

/// One start→sink execution flow, with the full call chain and, for each
/// function in the chain, its source code with numbered annotations on the
/// chain-advancing lines.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct InspectFlowRendered {
    /// Numeric flow index (for sorting / programmatic access).
    pub(crate) flow_number: u32,
    /// Display label. Chains that share a prefix and only diverge in their
    /// last step are grouped: the first gets `"2"`, siblings get `"2a"`,
    /// `"2b"` etc. so the inspect view can show a branch split.
    pub(crate) flow_label: String,
    /// Stable content-hash id of this flow's structural shape
    /// (`F:` + 16 hex). Hash inputs are the chain's display names
    /// joined with a separator — precision, annotations, cache
    /// state, and render mode are intentionally excluded so the
    /// id is identical across `--compact`, `--view`, `--no-cache`,
    /// and theme choices. Lets users / tools cite a specific flow
    /// across runs with `inspect --flow <flow_id>`.
    pub(crate) flow_id: String,
    pub(crate) chain: Vec<String>,
    pub(crate) chain_display: String,
    /// Worst-case precision of any semantic edge along the chain.
    /// Public inspect output is filtered to `Exact` / `Narrowed`
    /// chains before rendering.
    pub(crate) precision: bonsai_common::Precision,
    pub(crate) functions: Vec<InspectFunctionRendered>,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct InspectFunctionRendered {
    pub(crate) module_path: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub(crate) owners: Vec<InspectOwnerRendered>,
    pub(crate) name: String,
    pub(crate) signature: String,
    pub(crate) start_line: u32,
    pub(crate) end_line: u32,
    pub(crate) lines: Vec<InspectLine>,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct InspectOwnerRendered {
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) line: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct InspectLine {
    pub(crate) line_no: u32,
    pub(crate) text: String,
    /// Step number in the current flow (1-based); `None` for unannotated
    /// context lines.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) step: Option<u32>,
    /// `[FLOW N SOURCE]` / `[FLOW N -> next]` / `[FLOW N MATCH]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) annotation: Option<String>,
}

#[derive(Serialize, Default)]
struct InspectReport {
    query: String,
    regex: bool,
    kind_filter: Vec<String>,
    /// Top-level completion verdict for the semantic result set. False means
    /// a compiler/graph backend explicitly reported incomplete evidence;
    /// output-page coverage is reported separately by paged JSON wrappers.
    analysis_complete: bool,
    analysis_incomplete_reasons: Vec<String>,
    /// Per-decl flow rendering: each matching decl gets its own
    /// `InspectOut` with chain-enumerated flows.
    decl_hits: Vec<InspectOut>,
    /// Non-decl occurrences (calls, strings, vars, imports, args, refs,
    /// decorators) with the enclosing function and a chain preview.
    hits: Vec<HitOut>,
    /// Raw taint-engine paths matching the inspect query / filters.
    /// Populated only by explicit `--taint-flow`/`T:` requests; no rulepack
    /// source/sink/sanitizer semantics are involved.
    #[serde(default)]
    taint_flows: Vec<InspectTaintFlow>,
    summary: InspectReportSummary,
}

#[derive(Clone)]
enum InspectJsonPageUnit<'a> {
    Decl {
        index: usize,
        hit: &'a InspectOut,
        flow: Option<&'a InspectFlowRendered>,
    },
    Hit {
        index: usize,
        hit: &'a HitOut,
        flow: Option<&'a InspectFlowRendered>,
    },
    Taint(&'a InspectTaintFlow),
}

impl Serialize for InspectJsonPageUnit<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct("InspectJsonPageUnit", 2)?;
        match self {
            Self::Decl { hit, flow, .. } => {
                state.serialize_field("section", "decl_hits")?;
                state.serialize_field("value", &paged_decl_hit(hit, *flow))?;
            }
            Self::Hit { hit, flow, .. } => {
                state.serialize_field("section", "hits")?;
                state.serialize_field("value", &paged_occurrence_hit(hit, *flow))?;
            }
            Self::Taint(flow) => {
                state.serialize_field("section", "taint_flows")?;
                state.serialize_field("value", flow)?;
            }
        }
        state.end()
    }
}

#[derive(Serialize, Default)]
struct InspectReportSummary {
    total_decl_hits: usize,
    total_hits: usize,
    #[serde(default)]
    total_taint_flows: usize,
    hit_counts_by_kind: serde_json::Value,
    /// Number of entry graphs requested through the shared semantic flow
    /// facade while building raw inspect taint-flow evidence.
    #[serde(skip_serializing_if = "is_zero_usize", default)]
    semantic_flow_entry_queries: usize,
    /// Backend counts reported by `Workspace::syntax_flow_graph`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    semantic_flow_backend_counts: BTreeMap<String, usize>,
    /// Number of semantic flow queries answered from an already-hot
    /// backend.
    #[serde(skip_serializing_if = "is_zero_usize", default)]
    semantic_flow_cache_hits: usize,
    /// Number of semantic flow queries that computed a missing graph.
    #[serde(skip_serializing_if = "is_zero_usize", default)]
    semantic_flow_cache_misses: usize,
    /// Target-cut size used by the semantic flow planner when it is
    /// stable across the inspected entry set.
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic_flow_target_cut_size: Option<usize>,
    /// Planner fallback reasons, such as a preferred warmed-IDG query
    /// falling back to cached dataflow.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    semantic_flow_fallback_reasons: Vec<String>,
    /// Explicit incompleteness reasons reported by the shared semantic
    /// flow planner.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    semantic_flow_incomplete_reasons: Vec<String>,
    /// Explicit incompleteness reasons for structural graph evidence.
    /// This is distinct from output truncation: no partial graph is ever
    /// presented as complete merely because a reusable reverse index is
    /// unavailable.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    graph_flow_incomplete_reasons: Vec<String>,
}

#[derive(Serialize, Clone)]
struct InspectTaintFlow {
    taint_id: String,
    entry: String,
    #[serde(skip)]
    entry_kind: Option<DeclKind>,
    terminal: String,
    terminal_kind: String,
    precision: String,
    #[serde(skip)]
    func_ids: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    chain_display: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    steps: Vec<InspectTaintStep>,
    /// Conservative serialized-size estimate computed while the owning
    /// closure worker already has this row hot. Paging reads it in O(1)
    /// instead of walking every step in the complete result set again.
    #[serde(skip)]
    json_size_upper_bound: u64,
}

#[derive(Serialize, Clone)]
struct InspectTaintStep {
    caller: String,
    callee: String,
    file: String,
    line: u32,
    column: u32,
    kind: String,
    precision: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tainted_args: Vec<InspectTaintedArg>,
}

#[derive(Serialize, Clone)]
struct InspectTaintedArg {
    index: usize,
    value_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    param_name: Option<String>,
}

impl TaintFlowIdentityStep for InspectTaintStep {
    fn caller(&self) -> &str {
        &self.caller
    }

    fn callee(&self) -> &str {
        &self.callee
    }

    fn file(&self) -> &str {
        &self.file
    }

    fn line(&self) -> u32 {
        self.line
    }

    fn column(&self) -> u32 {
        self.column
    }

    fn for_each_tainted_arg(&self, visit: &mut dyn FnMut(usize, &str, Option<&str>)) {
        for arg in &self.tainted_args {
            visit(arg.index, &arg.value_text, arg.param_name.as_deref());
        }
    }
}

#[derive(Clone, Serialize)]
struct HitOut {
    kind: String,
    text: String,
    file: String,
    line: u32,
    column: u32,
    in_function: Option<String>,
    chains_preview: Vec<String>,
    /// Full source-inlined flows reaching this hit, identical in shape to
    /// decl flows. Empty for hits that have no enclosing function (e.g.
    /// top-level imports) or for which we can't find a chain.
    flows: Vec<InspectFlowRendered>,
    /// Suffix-clustered view of `flows`. Populated alongside `flows`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    groups: Vec<InspectFlowGroup>,
    /// When `--from` is set, the first reachable name that matched the
    /// `--from` needle on this hit's chain plus its source location
    /// (`name (file:line:col)`). Lets users see not just which
    /// upstream satisfied the filter but where that upstream lives,
    /// so the table row summarises the hit's chain at a glance.
    #[serde(skip_serializing_if = "Option::is_none")]
    from_match: Option<FilterMatch>,
    /// When `--to` is set, the first reachable name that matched the
    /// `--to` needle. Mirror of `from_match`.
    #[serde(skip_serializing_if = "Option::is_none")]
    to_match: Option<FilterMatch>,
}

/// A single `--from` / `--to` needle match — the matched name plus
/// where it lives in the workspace. Rendered as `name (file:line:col)`
/// in the occurrence-hits table so the row summarises the full flow
/// without the user having to dig into the rendered body below.
#[derive(Clone, Serialize)]
struct FilterMatch {
    /// The matched symbol / text (e.g. `handleRequest`, `Process`).
    name: String,
    /// Source location of the matched symbol, or `None` when the
    /// match came from the hit's own text (not a named decl).
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    column: Option<u32>,
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
/// Chain / hit filters passed through `inspect`. The `--from` /
/// `--to` needles are substring matches against the visible tokens
/// of a rendered chain; `--from-kind` / `--to-kind` (when set)
/// narrow the match to a single browse-fact kind so `--from-kind
/// read` only fires when the needle appears as a read reference
/// (not as a call site, import, or string literal).
#[derive(Copy, Clone, Default)]
pub(crate) struct InspectFilters<'a> {
    pub(crate) from: Option<&'a str>,
    pub(crate) from_kind: Option<FactKindFilter>,
    pub(crate) to: Option<&'a str>,
    pub(crate) to_kind: Option<FactKindFilter>,
    pub(crate) file: Option<&'a str>,
    pub(crate) in_fn: Option<&'a str>,
}

impl<'a> InspectFilters<'a> {
    /// Convert the CLI-facing struct (with clap-derived
    /// [`FactKindFilter`]) into the SDK struct that
    /// [`bonsai_sdk::chain_matches_filters`] consumes. Same
    /// shape, different kind-enum.
    fn to_sdk(self) -> bonsai_sdk::InspectFilters<'a> {
        bonsai_sdk::InspectFilters {
            from: self.from,
            from_kind: self.from_kind.map(FactKindFilter::to_sdk),
            to: self.to,
            to_kind: self.to_kind.map(FactKindFilter::to_sdk),
            file: self.file,
            in_fn: self.in_fn,
        }
    }
}

// Filter helpers for `inspect`. `--from` / `--to` do fuzzy
// substring match over the whole chain (any hop or hit text); the
// from/to distinction is just a naming convention. Matching is
// case-insensitive at identifier-token boundaries (split on
// non-alnum + camel-case lower→upper) so short prefixes like `os`
// match `os.system` / `OsConfig` but not `conn.close`. The
// implementation lives in `bonsai_sdk::name_token_match` /
// `bonsai_sdk::chain_matches_filters`.
use bonsai_sdk::name_token_match;

// `chain_matches_filters` lives in `bonsai_sdk::filter` — the
// CLI just calls `bonsai_sdk::chain_matches_filters(...)` after
// converting its `InspectFilters` to the SDK struct via `to_sdk()`.

/// View / lookup knobs passed into [`cmd_inspect`] that affect what
/// gets rendered but not what chains get enumerated. Separated from
/// the chain-enumeration + filter state so the chain-walker doesn't
/// need to know whether the user is in compact mode, or whether they
/// pinned a specific flow id.
#[derive(Clone)]
pub(crate) struct InspectRenderOptions {
    /// Drop inlined source bodies and render a step list instead.
    /// Same chains, same hits, shorter output.
    pub(crate) compact: bool,
    /// When `Some(id)`, keep only the flow(s) whose `flow_id` matches
    /// this string (format `F:` + 16 hex). When the id doesn't resolve
    /// to any enumerated flow, `cmd_inspect` exits with a clear
    /// error rather than silent empty output.
    pub(crate) flow_id_filter: Option<String>,
    /// Output shape: per-flow `trace`, clustered `grouped`, or
    /// `auto` (grouped once there are more than
    /// [`GROUPED_VIEW_AUTO_THRESHOLD`] flows). Purely cosmetic —
    /// the underlying data set is identical across modes.
    pub(crate) view: InspectView,
    /// When `Some(id)`, keep only the flow(s) that belong to the
    /// group whose `group_id` matches this string (`G:` + 16 hex).
    /// Like `flow_id_filter` but one level up: selects every
    /// member of a suffix-cluster rather than a single chain.
    pub(crate) group_id_filter: Option<String>,
    /// True when a `show F:` / `show G:` structural drilldown invoked
    /// this render. The id IS the query there, so the whole-workspace
    /// occurrence scan is skipped regardless of workspace size —
    /// `show` stays a pure structural-chain view. `inspect --flow`
    /// keeps the folded occurrence context on small workspaces.
    pub(crate) structural_drilldown: bool,
}

impl Default for InspectRenderOptions {
    /// No filters, trace view, full source bodies. Matches the
    /// historical `inspect` behavior — the flag-free invocation
    /// someone gets when they just run `bonsai-ninja inspect
    /// <workspace> --query <pattern>`.
    fn default() -> Self {
        Self {
            compact: false,
            flow_id_filter: None,
            view: InspectView::Trace,
            group_id_filter: None,
            structural_drilldown: false,
        }
    }
}

#[cfg(test)]
fn retrieval_prefilter_for_inspect_with_limit(
    root: &std::path::Path,
    pattern: Option<&str>,
    is_regex: bool,
    filters: InspectFilters<'_>,
    _graph_flows_enabled: bool,
    group_id_filter_active: bool,
    large_workspace_limit: usize,
) -> Result<Option<Vec<String>>> {
    let Some(pattern) = pattern else {
        return Ok(None);
    };
    if is_regex
        || pattern.len() < 3
        || group_id_filter_active
        || !workspace_file_count_exceeds(root, large_workspace_limit)
    {
        return Ok(None);
    }
    super::bonsai_for_cli().retrieval_hydration_include_filters(
        root,
        pattern,
        bonsai_sdk::SearchFilters {
            file: filters.file,
            ..Default::default()
        },
    )
}

pub(crate) struct InspectCommandOptions<'a> {
    pub(crate) pattern: Option<&'a str>,
    pub(crate) is_regex: bool,
    pub(crate) kind_filter: &'a [String],
    pub(crate) filters: InspectFilters<'a>,
    pub(crate) render: InspectRenderOptions,
    pub(crate) graph_flow: bool,
    pub(crate) taint_flow: bool,
    pub(crate) paging_cfg: paging::PagingConfig,
    pub(crate) format: BrowseFormat,
}

struct TaintCandidates {
    entries: ahash::AHashSet<bonsai_common::FuncId>,
    target_spans: Vec<(bonsai_common::FuncId, bonsai_common::Span)>,
    declaration_targets: ahash::AHashSet<bonsai_common::FuncId>,
    declaration_targets_complete: bool,
}

impl TaintCandidates {
    fn new(entries: ahash::AHashSet<bonsai_common::FuncId>) -> Self {
        Self {
            entries,
            target_spans: Vec::new(),
            declaration_targets: ahash::AHashSet::default(),
            declaration_targets_complete: false,
        }
    }

    fn insert(&mut self, entry: bonsai_common::FuncId) {
        self.entries.insert(entry);
    }

    fn insert_target(&mut self, entry: bonsai_common::FuncId, span: bonsai_common::Span) {
        self.entries.insert(entry);
        self.target_spans.push((entry, span));
    }

    fn record_complete_declaration_targets(
        &mut self,
        declarations: impl IntoIterator<Item = bonsai_common::FuncId>,
    ) {
        self.declaration_targets.extend(declarations);
        self.declaration_targets_complete = true;
    }
}

struct DeclHitPass<'a> {
    enabled: bool,
    files_in_path_order: &'a [bonsai_common::FileId],
    matcher: &'a Matcher,
    filters: InspectFilters<'a>,
    taint_flow: bool,
    graph_flows_enabled: bool,
    full_source_for_large_bodies: bool,
}

struct InspectKindSelection {
    requested: ahash::AHashSet<String>,
    endpoint_kind: Option<bonsai_sdk::FactKindFilter>,
    exclude_lexical_by_default: bool,
}

impl InspectKindSelection {
    fn wants(&self, kind: &str) -> bool {
        if self
            .endpoint_kind
            .is_some_and(|filter| !inspect_kind_matches_filter(kind, filter))
        {
            return false;
        }
        if self.requested.is_empty() {
            !self.exclude_lexical_by_default || !matches!(kind, "decorator" | "ref")
        } else {
            self.requested.contains(kind)
        }
    }
}

fn collect_decl_hits(
    ws: &Workspace,
    chain_cache: &ChainCache<'_>,
    edge_resolver: &mut CallEdgeResolver<'_>,
    options: DeclHitPass<'_>,
    taint_candidates: &mut TaintCandidates,
) -> Vec<InspectOut> {
    if !options.enabled {
        return Vec::new();
    }

    // Declaration matching is a header query even when the caller later asks
    // for graph evidence. Exact bodies are hydrated only for the selected
    // chains below; retaining every workspace body here made a narrow inspect
    // pay whole-program memory before it knew its targets.
    let global = ws.compiler_header_index();
    let mut matched_decls = Vec::new();
    for file in options.files_in_path_order.iter().copied() {
        for decl in global.decls_in(file) {
            if options.matcher.is_declaration_match(decl) {
                matched_decls.push(decl.clone());
            }
        }
    }
    // Prefer callables first so the most interesting flows land on top.
    matched_decls.sort_by_key(|decl| match decl.kind {
        DeclKind::Function | DeclKind::Method | DeclKind::Constructor => 0,
        DeclKind::Class | DeclKind::Struct => 1,
        _ => 2,
    });
    if options.taint_flow {
        // This header pass already found every callable declaration matched by
        // the query. Preserve that exact compiler result for the later IDG
        // lineage phase instead of rescanning every workspace declaration.
        taint_candidates.record_complete_declaration_targets(
            matched_decls
                .iter()
                .filter(|decl| {
                    matches!(
                        decl.kind,
                        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                    )
                })
                .map(|decl| bonsai_common::FuncId::new(decl.symbol.raw())),
        );
    }

    let mut hits = Vec::new();
    let decl_bar = progress::progress_bar("inspecting decls", matched_decls.len() as u64);
    for decl in &matched_decls {
        decl_bar.inc(1);
        let (path, line, col) = format_span(&decl.name_span, ws);
        if options
            .filters
            .file
            .is_some_and(|filter| !file_path_matches_filter(ws, &path, filter))
        {
            continue;
        }

        let target_func = bonsai_common::FuncId::new(decl.symbol.raw());
        if options.taint_flow
            && matches!(
                decl.kind,
                DeclKind::Module
                    | DeclKind::Function
                    | DeclKind::Method
                    | DeclKind::Constructor
                    | DeclKind::Global
            )
        {
            taint_candidates.insert_target(target_func, decl.name_span);
        }
        if !options.graph_flows_enabled {
            hits.push(InspectOut {
                symbol: decl.name.clone(),
                kind: format!("{:?}", decl.kind).to_lowercase(),
                file: path,
                line,
                column: col,
                params: decl.params.clone(),
                direct_callers: Vec::new(),
                callees: Vec::new(),
                graph_flows_evaluated: false,
                flows: Vec::new(),
                groups: Vec::new(),
                summary: InspectSummary {
                    total_flows: 0,
                    max_chain_depth: 0,
                    unique_entry_points: 0,
                },
            });
            continue;
        }

        let (chains, _) = chain_cache.chains_resolved(target_func, usize::MAX, usize::MAX);
        let _downstream = chain_cache.downstream_resolved(target_func, usize::MAX, usize::MAX);
        let chains: Vec<ResolvedChain> = chains
            .into_iter()
            .filter(|chain| {
                matches!(
                    chain.precision,
                    bonsai_common::Precision::Exact | bonsai_common::Precision::Narrowed,
                ) && edge_resolver.chain_edges_resolvable(&chain.funcs)
            })
            .collect();
        if chains.is_empty() {
            continue;
        }

        let mut extended_chains = Vec::new();
        for chain in &chains {
            let (paths, _) = edge_resolver.enumerate_call_paths_from_with_truncation(
                chain_cache,
                &chain.funcs,
                usize::MAX,
                usize::MAX,
            );
            extended_chains.extend(paths.into_iter().map(|path| (path, chain.precision)));
        }
        if options.filters.from.is_some() || options.filters.to.is_some() {
            extended_chains.retain(|(path, _)| {
                let mut chain_names: Vec<String> =
                    path.iter().map(|&func| func_display_name(ws, func)).collect();
                if let Some(&tail) = path.last() {
                    for callee in chain_cache.callees_of_resolved(tail) {
                        let name = func_display_name(ws, callee);
                        if !name.is_empty() && !chain_names.contains(&name) {
                            chain_names.push(name);
                        }
                    }
                }
                let taint_facts = || chain_cache.chain_structural_tokens(path);
                bonsai_sdk::chain_matches_filters_for_hit(
                    Some(bonsai_sdk::FilterHit::new(
                        &decl.name,
                        bonsai_sdk::FactKindFilter::Decl,
                    )),
                    &chain_names,
                    &taint_facts,
                    options.filters.to_sdk(),
                )
            });
            if extended_chains.is_empty() {
                continue;
            }
        }
        if options.taint_flow {
            for (path, _) in &extended_chains {
                if let Some(&entry) = path.first() {
                    taint_candidates.insert(entry);
                }
            }
        }

        let call_spans: Vec<Vec<Option<bonsai_common::Span>>> = extended_chains
            .iter()
            .map(|(chain, _)| edge_resolver.call_spans_for_chain(chain))
            .collect();
        use rayon::prelude::*;
        let mut flows: Vec<InspectFlowRendered> = extended_chains
            .par_iter()
            .zip(call_spans.par_iter())
            .filter_map(|((extended, precision), spans)| {
                let match_idx = extended
                    .iter()
                    .position(|&func| func == target_func)
                    .unwrap_or(extended.len().saturating_sub(1));
                render_flow_with_cached_call_spans(
                    ws,
                    extended,
                    spans,
                    0,
                    FLOW_LABEL_PLACEHOLDER,
                    *precision,
                    Some((
                        match_idx,
                        MatchOverride {
                            span: decl.name_span,
                            label: format!("MATCH: enter {}", decl.name),
                            marker_subjects: vec![decl.name.clone()],
                        },
                    )),
                    options.filters,
                    true,
                    options.full_source_for_large_bodies,
                )
            })
            .collect();
        dedup_structural_flows(&mut flows);
        let direct_callers = semantic_direct_callers(ws, chain_cache.resolved_graph(), target_func);
        let callees = semantic_callees(ws, chain_cache.resolved_graph(), target_func);
        let unique_entries: ahash::AHashSet<&String> =
            flows.iter().filter_map(|flow| flow.chain.first()).collect();
        let summary = InspectSummary {
            total_flows: flows.len() as u32,
            max_chain_depth: flows
                .iter()
                .map(|flow| flow.chain.len() as u32)
                .max()
                .unwrap_or(0),
            unique_entry_points: unique_entries.len() as u32,
        };
        let groups = group_flows_by_suffix(&flows);
        hits.push(InspectOut {
            symbol: decl.name.clone(),
            kind: format!("{:?}", decl.kind).to_lowercase(),
            file: path,
            line,
            column: col,
            params: decl.params.clone(),
            direct_callers,
            callees,
            graph_flows_evaluated: true,
            flows,
            groups,
            summary,
        });
    }
    decl_bar.finish_and_clear();
    hits
}

struct OccurrenceHitPass<'a> {
    files_in_path_order: &'a [bonsai_common::FileId],
    occurrence_matcher: &'a Matcher,
    kind_selection: &'a InspectKindSelection,
    filter_only_occurrence_kind: Option<bonsai_sdk::FactKindFilter>,
    filters: InspectFilters<'a>,
    full_source_for_large_bodies: bool,
    graph_flows_enabled: bool,
    syntax_fast_path: bool,
    taint_flow: bool,
    occurrence_scan_skipped_for_id_lookup: bool,
    partial_workspace: bool,
    large_syntax_scan: bool,
}

struct OccurrenceChainResolution {
    chains: Vec<ResolvedChain>,
    call_targets: Vec<(bonsai_common::FuncId, bonsai_common::Precision)>,
    from_match: Option<FilterMatch>,
    to_match: Option<FilterMatch>,
}

struct OccurrenceChainContext<'query, 'workspace> {
    ws: &'workspace Workspace,
    chain_cache: &'query ChainCache<'workspace>,
    edge_resolver: &'query mut CallEdgeResolver<'workspace>,
    filters: InspectFilters<'query>,
}

fn resolve_occurrence_chains(
    context: &mut OccurrenceChainContext<'_, '_>,
    kind: &str,
    text: &str,
    span: bonsai_common::Span,
    containing_id: Option<bonsai_common::FuncId>,
) -> OccurrenceChainResolution {
    let mut resolution = OccurrenceChainResolution {
        chains: Vec::new(),
        call_targets: Vec::new(),
        from_match: None,
        to_match: None,
    };
    let Some(containing_id) = containing_id else {
        return resolution;
    };

    let containing_downstream =
        context
            .chain_cache
            .downstream_resolved(containing_id, usize::MAX, usize::MAX);
    let mut seed = Vec::new();
    let mut seed_from_call_target = false;
    if kind == "call" {
        resolution.call_targets = resolve_call_hit_targets(context.chain_cache, containing_id, span);
        for (target, direct_precision) in resolution.call_targets.iter().copied() {
            let (raw, _) = context
                .chain_cache
                .chains_resolved(target, usize::MAX, usize::MAX);
            let target_seed = if raw.is_empty() {
                vec![ResolvedChain {
                    funcs: vec![target],
                    precision: bonsai_common::Precision::Exact,
                }]
            } else {
                raw
            };
            let mut target_seed: Vec<ResolvedChain> = target_seed
                .into_iter()
                .filter(|chain| chain.funcs.contains(&containing_id))
                .collect();
            if target_seed.is_empty() && target != containing_id {
                target_seed.push(ResolvedChain {
                    funcs: vec![containing_id, target],
                    precision: direct_precision,
                });
            }
            seed.extend(target_seed);
        }
        seed = dedupe_chains_keep_best_precision(seed);
        seed_from_call_target = !seed.is_empty();
    }
    if seed.is_empty() {
        let (raw, _) = context
            .chain_cache
            .chains_resolved(containing_id, usize::MAX, usize::MAX);
        seed = if raw.is_empty() {
            vec![ResolvedChain {
                funcs: vec![containing_id],
                precision: bonsai_common::Precision::Exact,
            }]
        } else {
            raw
        };
    }
    let seed: Vec<ResolvedChain> = seed
        .into_iter()
        .filter(|chain| {
            let precise = matches!(
                chain.precision,
                bonsai_common::Precision::Exact | bonsai_common::Precision::Narrowed,
            );
            precise && (seed_from_call_target || context.edge_resolver.chain_edges_resolvable(&chain.funcs))
        })
        .collect();

    if (context.filters.from.is_some() || context.filters.to.is_some()) && kind != "call" {
        let mut seen_from = None;
        let mut seen_to = None;
        context
            .chain_cache
            .prewarm_taint_facts(seed.iter().filter_map(|chain| chain.funcs.first().copied()));
        resolution.chains = seed
            .into_iter()
            .filter(|chain| {
                let mut extended = chain.funcs.clone();
                for downstream in &containing_downstream {
                    if !extended.contains(downstream) {
                        extended.push(*downstream);
                    }
                }
                let chain_names: Vec<String> = extended
                    .iter()
                    .map(|&func| func_display_name(context.ws, func))
                    .collect();
                let taint_facts = || context.chain_cache.chain_taint_facts(&extended);
                if !bonsai_sdk::chain_matches_filters_for_hit(
                    inspect_filter_hit(text, kind),
                    &chain_names,
                    &taint_facts,
                    context.filters.to_sdk(),
                ) {
                    return false;
                }

                let reachable = context.chain_cache.reachable_resolved(&extended);
                let func_names: Vec<String> = reachable
                    .iter()
                    .map(|&func| func_display_name(context.ws, func))
                    .collect();
                if seen_from.is_none() {
                    if let Some(needle) = context.filters.from {
                        seen_from = reachable
                            .iter()
                            .zip(func_names.iter())
                            .find(|(_, name)| name_token_match(name, needle))
                            .map(|(&func, name)| build_filter_match(context.ws, Some(func), name.clone()))
                            .or_else(|| {
                                let facts = taint_facts();
                                let mut tokens: Vec<&String> =
                                    facts.by_kind.values().flat_map(|tokens| tokens.iter()).collect();
                                tokens.sort();
                                tokens
                                    .into_iter()
                                    .find(|token| name_token_match(token, needle))
                                    .map(|token| build_filter_match(context.ws, None, token.clone()))
                            });
                    }
                }
                if seen_to.is_none() {
                    if let Some(needle) = context.filters.to {
                        seen_to = name_token_match(text, needle)
                            .then(|| build_filter_match(context.ws, None, needle.to_string()))
                            .or_else(|| {
                                let facts = taint_facts();
                                let mut tokens: Vec<&String> =
                                    facts.by_kind.values().flat_map(|tokens| tokens.iter()).collect();
                                tokens.sort();
                                tokens
                                    .into_iter()
                                    .find(|token| name_token_match(token, needle))
                                    .map(|token| build_filter_match(context.ws, None, token.clone()))
                            })
                            .or_else(|| {
                                reachable
                                    .iter()
                                    .zip(func_names.iter())
                                    .find(|(_, name)| name_token_match(name, needle))
                                    .map(|(&func, name)| {
                                        build_filter_match(context.ws, Some(func), name.clone())
                                    })
                            });
                    }
                }
                true
            })
            .collect();
        resolution.from_match = seen_from;
        resolution.to_match = seen_to;
    } else {
        resolution.chains = seed;
    }
    resolution
}

struct OccurrenceHitResult {
    hits: Vec<HitOut>,
}

struct OccurrenceScan<'a> {
    files_in_path_order: &'a [bonsai_common::FileId],
    matcher: &'a Matcher,
    kind_selection: &'a InspectKindSelection,
    endpoint_kind: Option<bonsai_sdk::FactKindFilter>,
    syntax_fast_path: bool,
    large_syntax_scan: bool,
    skip: bool,
    partial_workspace: bool,
}

fn scan_occurrence_facts(
    ws: &Workspace,
    chain_cache: &ChainCache<'_>,
    options: OccurrenceScan<'_>,
    hits: &mut Vec<HitOut>,
    push_hit: &mut impl FnMut(
        &str,
        String,
        bonsai_common::Span,
        Option<(bonsai_common::FuncId, String)>,
        bool,
        &mut Vec<HitOut>,
    ),
) {
    let OccurrenceScan {
        files_in_path_order,
        matcher: occurrence_matcher,
        kind_selection,
        endpoint_kind: filter_only_occurrence_kind,
        syntax_fast_path,
        large_syntax_scan,
        skip: occurrence_scan_skipped_for_id_lookup,
        partial_workspace,
    } = options;
    if !occurrence_scan_skipped_for_id_lookup {
        let hit_phase = if partial_workspace {
            "hydrating verified facts"
        } else {
            "scanning files"
        };
        let hit_bar = progress::progress_bar(hit_phase, files_in_path_order.len() as u64);
        for file in files_in_path_order.iter().copied() {
            hit_bar.inc(1);
            // Occurrence facts are file-local Tree-sitter IR. Stream the
            // exact compiler object in every mode instead of retaining a
            // whole-workspace body index for semantic inspections.
            let Some(streamed_index) = ws.exact_decl_index_shared(file) else {
                continue;
            };
            let idx = streamed_index.as_ref();
            // Preload decls in this file for enclosing-function lookup.
            let decls_in_file: Vec<&bonsai_lang_api::Decl> = idx.defs.iter().collect();

            // Calls + Assigns + Args live in flow_events.
            for d in &decls_in_file {
                if !matches!(
                    d.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) {
                    continue;
                }
                walk_flow_hits(
                    &d.flow_events,
                    bonsai_common::FuncId::new(d.symbol.raw()),
                    &d.name,
                    FlowHitWalkContext {
                        workspace: Some(ws),
                        matcher: occurrence_matcher,
                        endpoint_kind_filter: filter_only_occurrence_kind,
                        kinds: &kind_selection.requested,
                    },
                    hits,
                    push_hit,
                );
            }

            // Strings.
            if kind_selection.wants("string") {
                for s in &idx.strings {
                    if occurrence_matcher.is_match(&s.text) {
                        let enclosing = chain_cache.enclosing_func(file, &decls_in_file, s.span);
                        push_hit("string", s.text.clone(), s.span, enclosing, false, hits);
                    }
                }
            }

            // Refs (covers decorators via RefKind::Decorator, plus residual
            // module-level call refs). On large syntax-fast inspections,
            // call facts from function bodies already came from flow_events
            // above; avoid an O(refs × enclosing lookup) pass just to
            // rediscover the same calls.
            let scan_refs = kind_selection.wants("decorator")
                || kind_selection.wants("ref")
                || (kind_selection.wants("call") && (!syntax_fast_path || !large_syntax_scan));
            if scan_refs {
                for r in &idx.refs {
                    let kind_tag = match r.kind {
                        RefKind::Decorator => "decorator",
                        RefKind::Call => {
                            // Skip call-refs that correspond to a call already
                            // surfaced by the flow-event walker above. Module-
                            // level calls (JS `const x = require(...)` at file
                            // top, Python top-level script statements, etc.)
                            // have NO enclosing function — they're not in any
                            // decl's flow_events — so we must emit them here or
                            // they become invisible to inspect.
                            let enclosing = chain_cache.enclosing_func(file, &decls_in_file, r.span);
                            if enclosing.is_some() {
                                continue;
                            }
                            "call"
                        }
                        _ => "ref",
                    };
                    if !kind_selection.wants(kind_tag) {
                        continue;
                    }
                    if occurrence_matcher.is_match(&r.name) {
                        let enclosing = chain_cache.enclosing_func(file, &decls_in_file, r.span);
                        push_hit(kind_tag, r.name.clone(), r.span, enclosing, false, hits);
                    }
                }
            }

            // Imports (fallback to generic scan when the adapter didn't provide any).
            if kind_selection.wants("import") {
                let imports_vec = ws.db().imports_for(file);
                for imp in &imports_vec {
                    let alias_match = imp
                        .alias
                        .as_deref()
                        .is_some_and(|alias| occurrence_matcher.is_match(alias));
                    let original_match = imp
                        .original_name
                        .as_deref()
                        .is_some_and(|original| occurrence_matcher.is_match(original));
                    if occurrence_matcher.is_match(&imp.module) || alias_match || original_match {
                        push_hit("import", import_hit_text(imp), imp.span, None, false, hits);
                    }
                }
            }
        }
        hit_bar.finish_and_clear();
    }
}

fn collect_occurrence_hits<'workspace>(
    ws: &'workspace Workspace,
    chain_cache: &ChainCache<'workspace>,
    edge_resolver: &mut CallEdgeResolver<'workspace>,
    options: OccurrenceHitPass<'_>,
    taint_candidates: &mut TaintCandidates,
) -> OccurrenceHitResult {
    let OccurrenceHitPass {
        files_in_path_order,
        occurrence_matcher,
        kind_selection,
        filter_only_occurrence_kind,
        filters,
        full_source_for_large_bodies,
        graph_flows_enabled,
        syntax_fast_path,
        taint_flow,
        occurrence_scan_skipped_for_id_lookup,
        partial_workspace,
        large_syntax_scan,
    } = options;
    // ----- 2. Non-decl hits: calls, assignments, strings, imports, args, decorators, refs.
    let mut hits: Vec<HitOut> = Vec::new();
    // Warm the resolved graph only when this invocation is actually
    // going to render structural graph flows. Large-workspace default
    // inspect stays syntax-index based; eagerly building the graph is
    // what makes broad Elasticsearch queries run for minutes.
    if graph_flows_enabled {
        let _ = chain_cache.resolved_graph();
    }
    let endpoint_corridor_funcs =
        (partial_workspace && graph_flows_enabled && filters.from.is_some() && filters.to.is_some()).then(
            || {
                chain_cache
                    .resolved_graph()
                    .nodes()
                    .iter()
                    .map(|node| node.func)
                    .collect::<ahash::AHashSet<_>>()
            },
        );
    type OccurrenceHitKey = (String, String, String, u32, u32, Option<String>);
    let mut seen_hits = ahash::AHashSet::<OccurrenceHitKey>::default();
    let mut push_hit = |kind: &str,
                        text: String,
                        span: bonsai_common::Span,
                        containing: Option<(bonsai_common::FuncId, String)>,
                        assignment_source_call: bool,
                        out: &mut Vec<HitOut>| {
        let (path, line, col) = format_span(&span, ws);
        // `--file` filter (substring) on the hit's source path.
        if filters
            .file
            .is_some_and(|f| !file_path_matches_filter(ws, &path, f))
        {
            return;
        }
        // `--in-fn` filter: hit must live inside a function whose name
        // contains the needle.
        if let Some(needle) = filters.in_fn {
            if !containing.as_ref().is_some_and(|(_, name)| name.contains(needle)) {
                return;
            }
        }
        let containing_name: Option<&str> = containing.as_ref().map(|(_, n)| n.as_str());
        let containing_id: Option<bonsai_common::FuncId> = containing.as_ref().map(|(f, _)| *f);
        if endpoint_corridor_funcs
            .as_ref()
            .is_some_and(|corridor| containing_id.is_none_or(|func| !corridor.contains(&func)))
        {
            return;
        }
        let hit_key = (
            kind.to_string(),
            text.clone(),
            path.clone(),
            line,
            col,
            containing_name.map(str::to_string),
        );
        if seen_hits.contains(&hit_key) {
            return;
        }
        if taint_flow {
            if let Some(entry) = containing_id {
                taint_candidates.insert_target(entry, span);
            }
        }
        if !graph_flows_enabled {
            let filter_hit = inspect_filter_hit(&text, kind);
            let visible_match = |needle: &str, requested_kind: Option<bonsai_sdk::FactKindFilter>| -> bool {
                let hit_matches = filter_hit.is_some_and(|hit| {
                    requested_kind.is_none_or(|kind| hit.kind == Some(kind))
                        && name_token_match(hit.text, needle)
                });
                let containing_matches = requested_kind
                    .is_none_or(|kind| kind == bonsai_sdk::FactKindFilter::Decl)
                    && containing_name.is_some_and(|name| name_token_match(name, needle));
                hit_matches || containing_matches
            };
            if filters
                .from
                .is_some_and(|from| !visible_match(from, filters.from_kind.map(FactKindFilter::to_sdk)))
                || filters
                    .to
                    .is_some_and(|to| !visible_match(to, filters.to_kind.map(FactKindFilter::to_sdk)))
            {
                return;
            }
            seen_hits.insert(hit_key);
            out.push(HitOut {
                kind: kind.to_string(),
                text,
                file: path,
                line,
                column: col,
                in_function: containing_name.map(str::to_string),
                chains_preview: containing_name
                    .map(|name| vec![name.to_string()])
                    .unwrap_or_default(),
                flows: Vec::new(),
                groups: Vec::new(),
                from_match: None,
                to_match: None,
            });
            return;
        }

        let resolution = resolve_occurrence_chains(
            &mut OccurrenceChainContext {
                ws,
                chain_cache,
                edge_resolver: &mut *edge_resolver,
                filters,
            },
            kind,
            &text,
            span,
            containing_id,
        );
        let OccurrenceChainResolution {
            chains: chains_r,
            call_targets: call_hit_targets,
            from_match: hit_from_match,
            to_match: hit_to_match,
        } = resolution;
        // If chain filters rejected every chain AND the user explicitly
        // asked for --from / --to, drop this hit entirely (they didn't
        // want to see it).
        if chains_r.is_empty() && (filters.from.is_some() || filters.to.is_some()) {
            return;
        }
        let chains_preview: Vec<String> = chains_r
            .iter()
            .take(6)
            .map(|c| disambiguated_func_names_for_output(ws, &c.funcs).join(" -> "))
            .collect();
        // Build full source-inlined flows for this hit, overriding the
        // target function's MATCH annotation to point at the hit span.
        let sink_label = match kind {
            "call" => format!("MATCH: call {}", truncate(&text, 40)),
            "string" => format!("MATCH: string {}", truncate(&text, 40)),
            "var" => format!("MATCH: {} {}", kind, truncate(&text, 40)),
            "decorator" => format!("MATCH: @{}", truncate(&text, 40)),
            "arg" => format!("MATCH: arg {}", truncate(&text, 40)),
            _ => format!("MATCH: {} {}", kind, truncate(&text, 40)),
        };
        let match_override = MatchOverride {
            span,
            label: sink_label,
            marker_subjects: vec![text.clone()],
        };
        // If there are no upstream chains (the containing function is a
        // root, or there's no enclosing function) still emit one flow
        // starting at the containing function itself. The synthetic
        // chain's precision is `Exact` because it crosses no edges.
        let working_chains_r: Vec<ResolvedChain> = if chains_r.is_empty() {
            if let Some(c_id) = containing_id {
                vec![ResolvedChain {
                    funcs: vec![c_id],
                    precision: bonsai_common::Precision::Exact,
                }]
            } else {
                Vec::new()
            }
        } else {
            chains_r.clone()
        };
        // Extend each chain along the syntactic call path from its
        // tail — same contract as the decl-hit branch. Unresolvable
        // downstream hops terminate the extension rather than getting
        // appended as bogus `(over-approx)` edges.
        let mut extended_chains_r: Vec<(Vec<bonsai_common::FuncId>, bonsai_common::Precision)> = Vec::new();
        let extend_downstream = kind != "call" || !call_hit_targets.is_empty() || assignment_source_call;
        if extend_downstream {
            for chain in &working_chains_r {
                let (paths, _) = edge_resolver.enumerate_call_paths_from_with_truncation(
                    chain_cache,
                    &chain.funcs,
                    usize::MAX,
                    usize::MAX,
                );
                extended_chains_r.extend(paths.into_iter().map(|path| (path, chain.precision)));
            }
        } else {
            extended_chains_r.extend(
                working_chains_r
                    .iter()
                    .map(|chain| (chain.funcs.clone(), chain.precision)),
            );
        }
        if filters.from.is_some() || filters.to.is_some() {
            // Filter enumerated paths, not the raw upstream chains:
            // only paths that reach the `--to` sink (or contain the
            // `--from` source) survive. The earlier raw-chain filter
            // already passed each upstream stem; this second pass
            // drops DFS branches that go somewhere the filter doesn't
            // care about.
            extended_chains_r.retain(|(path, _)| {
                let mut chain_names: Vec<String> = path.iter().map(|&f| func_display_name(ws, f)).collect();
                if extend_downstream {
                    if let Some(&tail) = path.last() {
                        for c in chain_cache.callees_of_resolved(tail) {
                            let name = func_display_name(ws, c);
                            if !name.is_empty() && !chain_names.contains(&name) {
                                chain_names.push(name);
                            }
                        }
                    }
                }
                // Path-only structural facts avoid sibling-branch
                // leakage while preserving kind-filter matches on
                // intermediate arguments/calls.
                let taint_facts_fn = || chain_cache.chain_structural_tokens(path);
                bonsai_sdk::chain_matches_filters_for_hit(
                    inspect_filter_hit(&text, kind),
                    &chain_names,
                    &taint_facts_fn,
                    filters.to_sdk(),
                )
            });
            if extended_chains_r.is_empty() {
                return;
            }
        }
        if taint_flow {
            for (path, _) in &extended_chains_r {
                if let Some(&entry) = path.first() {
                    taint_candidates.insert(entry);
                }
            }
        }
        let call_spans: Vec<Vec<Option<bonsai_common::Span>>> = extended_chains_r
            .iter()
            .map(|(chain, _)| edge_resolver.call_spans_for_chain(chain))
            .collect();
        // Parallel render — see the decl-hit path above for the
        // determinism argument. Same shape, same guarantee.
        use rayon::prelude::*;
        let mut flows: Vec<InspectFlowRendered> = extended_chains_r
            .par_iter()
            .zip(call_spans.par_iter())
            .enumerate()
            .filter_map(|(_i, ((extended_r, prec), spans))| {
                let match_idx = containing_id
                    .and_then(|f| extended_r.iter().position(|&g| g == f))
                    .unwrap_or(extended_r.len().saturating_sub(1));
                render_flow_with_cached_call_spans(
                    ws,
                    extended_r,
                    spans,
                    0,
                    FLOW_LABEL_PLACEHOLDER,
                    *prec,
                    Some((match_idx, match_override.clone())),
                    filters,
                    true,
                    full_source_for_large_bodies,
                )
            })
            .collect();
        dedup_structural_flows(&mut flows);
        if flows.is_empty() && (filters.from.is_some() || filters.to.is_some()) {
            return;
        }
        let groups = group_flows_by_suffix(&flows);
        seen_hits.insert(hit_key);
        out.push(HitOut {
            kind: kind.to_string(),
            text,
            file: path,
            line,
            column: col,
            in_function: containing_name.map(str::to_string),
            chains_preview,
            flows,
            groups,
            from_match: hit_from_match,
            to_match: hit_to_match,
        });
    };

    scan_occurrence_facts(
        ws,
        chain_cache,
        OccurrenceScan {
            files_in_path_order,
            matcher: occurrence_matcher,
            kind_selection,
            endpoint_kind: filter_only_occurrence_kind,
            syntax_fast_path,
            large_syntax_scan,
            skip: occurrence_scan_skipped_for_id_lookup,
            partial_workspace,
        },
        &mut hits,
        &mut push_hit,
    );

    OccurrenceHitResult { hits }
}

struct InspectFinish<'a> {
    pattern: Option<&'a str>,
    is_regex: bool,
    kind_filter: &'a [String],
    filters: InspectFilters<'a>,
    render: InspectRenderOptions,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
    taint_flow: bool,
    graph_flows_enabled: bool,
    graph_flow_incomplete_reason: Option<&'a str>,
}

fn finish_inspect(
    root: &std::path::Path,
    ws: &Workspace,
    options: InspectFinish<'_>,
    mut decl_hits: Vec<InspectOut>,
    occurrence_hits: OccurrenceHitResult,
    taint_candidates: TaintCandidates,
) -> Result<()> {
    let InspectFinish {
        pattern,
        is_regex,
        kind_filter,
        filters,
        render,
        paging_cfg,
        format,
        taint_flow,
        graph_flows_enabled,
        graph_flow_incomplete_reason,
    } = options;
    let mut hits = occurrence_hits.hits;
    // Determinism: `global.all_files()` iterates an AHashMap, so discovery
    // order varies run-to-run. Sort hits and decl_hits by a stable key
    // (file, line, column, kind, text) so two back-to-back runs produce
    // identical output.
    hits.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
            .then(a.kind.cmp(&b.kind))
            .then(a.text.cmp(&b.text))
    });
    decl_hits.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
            .then(a.symbol.cmp(&b.symbol))
    });

    // ----- 3. Summary.
    let summary = InspectReportSummary {
        total_decl_hits: decl_hits.len(),
        total_hits: hits.len(),
        total_taint_flows: 0,
        hit_counts_by_kind: sorted_hit_counts_json(&hits),
        semantic_flow_entry_queries: 0,
        semantic_flow_backend_counts: BTreeMap::new(),
        semantic_flow_cache_hits: 0,
        semantic_flow_cache_misses: 0,
        semantic_flow_target_cut_size: None,
        semantic_flow_fallback_reasons: Vec::new(),
        semantic_flow_incomplete_reasons: Vec::new(),
        graph_flow_incomplete_reasons: graph_flow_incomplete_reason
            .into_iter()
            .map(str::to_string)
            .collect(),
    };

    let mut report = InspectReport {
        query: pattern.unwrap_or("").to_string(),
        regex: is_regex,
        kind_filter: kind_filter.iter().map(String::from).collect(),
        analysis_complete: false,
        analysis_incomplete_reasons: Vec::new(),
        decl_hits,
        hits,
        taint_flows: Vec::new(),
        summary,
    };
    if taint_flow {
        let (taint_flows, semantic_flow_stats) = inspect_taint_flows(
            ws,
            &taint_candidates,
            InspectTaintFlowOptions {
                pattern,
                is_regex,
                filters,
                kind_filter,
                prefer_warmed_idg: true,
                flow_id_filter: render.flow_id_filter.as_deref(),
            },
        )?;
        report.taint_flows = taint_flows;
        report.summary.total_taint_flows = report.taint_flows.len();
        apply_semantic_flow_stats(&mut report.summary, semantic_flow_stats);
    }
    refresh_inspect_completeness(&mut report);

    // A structural F:/G: hash is intentionally content-stable but not
    // invertible. Preserve the exact query that produced each id so `show`
    // can reopen the same compiler-scoped graph instead of enumerating the
    // workspace or speculatively invoking security analysis.
    if graph_flows_enabled {
        if let Some(query) = pattern.filter(|query| !query.is_empty()) {
            let ids = report
                .decl_hits
                .iter()
                .flat_map(|hit| {
                    hit.flows
                        .iter()
                        .map(|flow| flow.flow_id.as_str())
                        .chain(hit.groups.iter().map(|group| group.group_id.as_str()))
                })
                .chain(report.hits.iter().flat_map(|hit| {
                    hit.flows
                        .iter()
                        .map(|flow| flow.flow_id.as_str())
                        .chain(hit.groups.iter().map(|group| group.group_id.as_str()))
                }))
                .collect::<Vec<_>>();
            crate::page_cache::remember_structural_id_hints(root, ids, query, is_regex);
        }
    }

    // Secondary `--contains` / `--not-contains`: keep only the decl /
    // occurrence records whose text (name, file, code, flow bodies)
    // matches. A render-time narrow like `--flow` below — the analysis
    // already ran; this just shapes what surfaces.
    let secondary = crate::filter::active();
    if secondary.is_active() {
        report.decl_hits.retain(|hit| secondary.matches_value(hit));
        report.hits.retain(|hit| secondary.matches_value(hit));
        report.taint_flows.retain(|flow| secondary.matches_value(flow));
        report.summary.total_decl_hits = report.decl_hits.len();
        report.summary.total_hits = report.hits.len();
        report.summary.total_taint_flows = report.taint_flows.len();
        refresh_inspect_completeness(&mut report);
    }

    // `--flow <id>`: keep only flows whose stable id matches, then
    // drop hit / decl records that no longer have any flows. Runs
    // AFTER chain enumeration so the filter is purely a render-time
    // narrow — it can't lose a flow that was already caught by
    // max-flows truncation, but that's an intentional trade (the
    // truncation banner will still surface in that case).
    if let Some(target_id) = render.flow_id_filter.as_deref() {
        apply_flow_id_filter(&mut report, target_id);
        if report.decl_hits.is_empty() && report.hits.is_empty() && report.taint_flows.is_empty() {
            anyhow::bail!(
                "no flow matching `{target_id}` in this workspace + query \
                 combination. Flow ids are printed next to every `FLOW N` \
                 header in text output and in `flow_id` in JSON output; \
                 raw taint paths match their taint_id."
            );
        }
    }
    // `--group <id>`: mirror of `--flow <id>` at the group level. Must
    // run after flow-id filtering (so combining `--flow` and `--group`
    // narrows to the intersection) and before render so the text /
    // JSON paths see the reduced set.
    if let Some(target_id) = render.group_id_filter.as_deref() {
        apply_group_id_filter(&mut report, target_id);
        if report.decl_hits.is_empty() && report.hits.is_empty() && report.taint_flows.is_empty() {
            anyhow::bail!(
                "no flow group matching `{target_id}` in this workspace + \
                 query combination. Group ids are printed next to every \
                 `GROUP N` header in grouped view (`--view grouped` / \
                 `--view auto`) and in `group_id` in JSON output."
            );
        }
    }

    if graph_flows_enabled && filters.from.is_some() && filters.to.is_some() {
        report.hits.retain(|hit| !hit.flows.is_empty());
        rebuild_report_summary(&mut report);
    }
    finalize_report_flow_labels(&mut report);
    // No matches? Print a friendly zero-hits line with close-name
    // suggestions — don't raise an error. Zero hits is a legit outcome
    // for a substring / regex query; only commands that take a concrete
    // symbol (trace, dump-hir, refs) should treat it as usage error.
    //
    // JSON output stays machine-parseable with the same InspectReport
    // shape used for non-empty results.
    if report.decl_hits.is_empty() && report.hits.is_empty() && report.taint_flows.is_empty() {
        if matches!(format, BrowseFormat::Json) {
            cli_println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }
        let kind_label = if kind_filter.is_empty() {
            String::new()
        } else {
            format!("kinds: {} ", format_kind_filter(kind_filter))
        };
        // Build a human label for the active filter set — when there's
        // no query we still want the message to explain what the user
        // asked for (e.g. "no flows from handle_request to os.system").
        let mut filter_label = Vec::new();
        if let Some(p) = pattern {
            if is_regex {
                filter_label.push(format!("regex /{p}/"));
            } else {
                filter_label.push(format!("`{p}`"));
            }
        }
        if let Some(from) = filters.from {
            filter_label.push(format!("--from `{from}`"));
        }
        if let Some(to) = filters.to {
            filter_label.push(format!("--to `{to}`"));
        }
        if let Some(f) = filters.file {
            filter_label.push(format!("--file `{f}`"));
        }
        if let Some(f) = filters.in_fn {
            filter_label.push(format!("--in-fn `{f}`"));
        }
        let joined = if filter_label.is_empty() {
            "the current filter set".to_string()
        } else {
            filter_label.join(" + ")
        };
        cli_println!("no matches for {kind_label}{joined} across decls / calls / vars / strings / imports / refs / decorators");
        if let Some(p) = pattern.filter(|_| !is_regex) {
            let suggestions = nearest_names(ws, p, 5);
            if !suggestions.is_empty() {
                let u = ui();
                cli_println!(
                    "{}",
                    u.dim(&format!("  did you mean: {}", suggestions.join(", ")))
                );
            }
        }
        return Ok(());
    }

    match format {
        BrowseFormat::Json => {
            // Programmatic inspect is token-budgeted by default. When
            // the full report fits the first page we keep the native
            // InspectReport shape; otherwise we page across every
            // scalable evidence section and emit only the current
            // page's decl_hits / hits / taint_flows slices.
            if paging_cfg.json_wrapped() {
                let filters_hash = inspect_filters_hash(pattern, is_regex);
                let units = inspect_json_page_units(&report);
                let force_wrapper = paging_cfg.context.is_some()
                    || !matches!(paging_cfg.page, paging::PageArg::First)
                    || crate::filter::active().is_active();
                page_cache::emit_paged_text(
                    root,
                    &units,
                    &paging_cfg,
                    "inspect",
                    filters_hash,
                    inspect_json_unit_cost,
                    |slice, info, _cfg| {
                        if !force_wrapper && info.page_number == 1 && info.is_last {
                            cli_println!("{}", serde_json::to_string_pretty(&report)?);
                            return Ok(());
                        }
                        let mut analysis_incomplete_reasons = report.analysis_incomplete_reasons.clone();
                        analysis_incomplete_reasons.extend(paged_json_incomplete_reasons("inspect", info));
                        analysis_incomplete_reasons.sort();
                        analysis_incomplete_reasons.dedup();
                        let mut decl_hits = BTreeMap::<usize, InspectOut>::new();
                        let mut hits = BTreeMap::<usize, HitOut>::new();
                        let mut taint_flows: Vec<&InspectTaintFlow> = Vec::new();
                        for unit in slice {
                            match unit {
                                InspectJsonPageUnit::Decl { index, hit, flow } => {
                                    let entry = decl_hits
                                        .entry(*index)
                                        .or_insert_with(|| paged_decl_hit(hit, None));
                                    if let Some(flow) = flow {
                                        entry.flows.push((*flow).clone());
                                    }
                                }
                                InspectJsonPageUnit::Hit { index, hit, flow } => {
                                    let entry = hits
                                        .entry(*index)
                                        .or_insert_with(|| paged_occurrence_hit(hit, None));
                                    if let Some(flow) = flow {
                                        entry.flows.push((*flow).clone());
                                    }
                                }
                                InspectJsonPageUnit::Taint(flow) => taint_flows.push(*flow),
                            }
                        }
                        for hit in decl_hits.values_mut() {
                            hit.groups = group_flows_by_suffix(&hit.flows);
                        }
                        for hit in hits.values_mut() {
                            hit.groups = group_flows_by_suffix(&hit.flows);
                        }
                        let decl_hits = decl_hits.into_values().collect::<Vec<_>>();
                        let hits = hits.into_values().collect::<Vec<_>>();
                        let wrapped = serde_json::json!({
                            "analysis_complete": analysis_incomplete_reasons.is_empty(),
                            "analysis_incomplete_reasons": analysis_incomplete_reasons,
                            "query": &report.query,
                            "regex": report.regex,
                            "kind_filter": &report.kind_filter,
                            "decl_hits": decl_hits,
                            "hits": hits,
                            "taint_flows": taint_flows,
                            "summary": &report.summary,
                            "page": page_info_to_json(info),
                        });
                        cli_println!("{}", serde_json::to_string_pretty(&wrapped)?);
                        Ok(())
                    },
                )?;
            } else {
                cli_println!("{}", serde_json::to_string_pretty(&report)?);
            }
        }
        BrowseFormat::Text => {
            let filters_hash = inspect_filters_hash(pattern, is_regex);
            let mut current_info = None;
            let current_text = page_cache::capture(|| {
                current_info = Some(render_inspect_report_text(
                    ws,
                    &report,
                    &render,
                    &paging_cfg,
                    pattern,
                    is_regex,
                )?);
                Ok(())
            })?;
            let Some(current_info) = current_info else {
                page_cache::emit_cached_text(&current_text)?;
                return Ok(());
            };
            let output_text = current_text.clone();
            let mut cached_pages = vec![page_cache::CachedPage {
                number: current_info.page_number,
                cursor: current_info.cursor.clone(),
                text: current_text,
            }];
            for page_number in inspect_eager_window(
                current_info.page_number,
                current_info.total_pages,
                !report.taint_flows.is_empty(),
            ) {
                if page_number == current_info.page_number {
                    continue;
                }
                let mut page_cfg = paging_cfg.clone();
                page_cfg.page = paging::PageArg::Number(page_number);
                let mut page_info = None;
                let text = page_cache::capture(|| {
                    page_info = Some(render_inspect_report_text(
                        ws, &report, &render, &page_cfg, pattern, is_regex,
                    )?);
                    Ok(())
                })?;
                if let Some(info) = page_info {
                    cached_pages.push(page_cache::CachedPage {
                        number: info.page_number,
                        cursor: info.cursor,
                        text,
                    });
                }
            }
            if let Err(e) = page_cache::save_pages(root, "inspect", filters_hash, cached_pages) {
                tracing::debug!("page cache save failed: {e}");
            }
            paging::write_last_cursor("inspect", filters_hash, &current_info.cursor);
            page_cache::emit_cached_text(&output_text)?;
        }
    }
    Ok(())
}

/// Pages worth rendering into the opportunistic text cache.
///
/// Raw taint reports can contain hundreds of thousands of exact paths. Their
/// current page is already cached above; eagerly formatting future pages adds
/// unrelated work to the requested command and repeatedly walks the complete
/// pagination plan. Structural reports remain cheap enough to retain the
/// normal look-ahead window. This affects cached presentation only.
fn inspect_eager_window(current_page: u64, total_pages: u64, has_raw_taint: bool) -> BTreeSet<u64> {
    if has_raw_taint {
        return BTreeSet::from([current_page.clamp(1, total_pages.max(1))]);
    }
    page_cache::eager_window(current_page, total_pages)
}

/// Pick a source-literal candidate for a semantic inspect name.
///
/// Qualified declaration identities are compiler products: source contains
/// `class RestSearchAction { ... prepareRequest(...) ... }`, not the joined
/// string `RestSearchAction.prepareRequest`. Candidate lookup therefore uses
/// the AST name tail and canonical declaration matching applies the complete
/// qualified identity after the scoped files are hydrated.
fn inspect_literal_candidate(pattern: &str) -> &str {
    bonsai_common::short_qualified_tail(pattern)
}

fn source_contains_inspect_literal(source: &str, literal: &str) -> bool {
    if source.contains(literal) {
        return true;
    }
    if literal.is_ascii() {
        let needle = literal.as_bytes();
        return !needle.is_empty()
            && source
                .as_bytes()
                .windows(needle.len())
                .any(|candidate| candidate.eq_ignore_ascii_case(needle));
    }
    source.to_lowercase().contains(&literal.to_lowercase())
}

#[cfg(test)]
mod inspect_literal_candidate_tests {
    use super::{inspect_literal_candidate, source_contains_inspect_literal};

    #[test]
    fn semantic_qualified_names_prefilter_by_source_level_tail() {
        assert_eq!(
            inspect_literal_candidate("RestSearchAction.prepareRequest"),
            "prepareRequest"
        );
        assert_eq!(
            inspect_literal_candidate("crate::module::Dispatcher::dispatch"),
            "dispatch"
        );
        assert_eq!(inspect_literal_candidate("prepareRequest"), "prepareRequest");
    }

    #[test]
    fn short_qualified_tails_do_not_search_for_a_synthesized_identity() {
        assert_eq!(inspect_literal_candidate("pkg.io"), "io");
    }

    #[test]
    fn source_literal_anchor_matches_without_allocating_ascii_lowercase_copies() {
        assert!(source_contains_inspect_literal(
            "void executeQuery() {}",
            "execute"
        ));
        assert!(source_contains_inspect_literal(
            "void EXECUTEQUERY() {}",
            "execute"
        ));
        assert!(!source_contains_inspect_literal("void dispatch() {}", "execute"));
    }
}

pub(crate) fn cmd_inspect(root: &std::path::Path, options: InspectCommandOptions<'_>) -> Result<()> {
    let InspectCommandOptions {
        pattern,
        is_regex,
        kind_filter,
        filters,
        render,
        graph_flow,
        taint_flow,
        paging_cfg,
        format,
    } = options;
    // Taint-aware default for `--query X` combined with standalone
    // `--from Y` or `--to Y`: synthesize the OPPOSITE endpoint from
    // the pattern so the filter enters the dual-mode matcher
    // (`Some(from), Some(to)`) which enforces real taint connectivity
    // across the chain. Matches the user's mental model from
    // `--from X --to Y` where one endpoint must land on the hit and
    // the other must be flow-connected. Pure-regex queries skip this
    // — a regex won't cleanly match a taint-fact name. Plain
    // `--query X` with neither `--from` nor `--to` keeps its current
    // behavior (filter is a no-op; every chain for every matched hit
    // surfaces).
    let explicit_endpoint_graph_flow = filters.from.is_some() && filters.to.is_some();
    let mut filters = filters;
    if !is_regex {
        if let Some(p) = pattern {
            match (filters.from, filters.to) {
                (Some(_), None) => filters.to = Some(p),
                (None, Some(_)) => filters.from = Some(p),
                _ => {}
            }
        }
    }
    let exact_file_path = filters.file.and_then(|file| {
        let requested = std::path::Path::new(file);
        let absolute = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            root.join(requested)
        };
        absolute.is_file().then_some(requested)
    });
    let workspace_is_large = workspace_file_count_exceeds(root, INSPECT_GRAPH_FLOW_FILE_LIMIT);
    let large_workspace = exact_file_path.is_none() && workspace_is_large;
    let structural_flow_lookup = render
        .flow_id_filter
        .as_deref()
        .is_some_and(|id| id.starts_with("F:"))
        || render.group_id_filter.is_some();
    // A from→to pair explicitly asks a relational question, so structural
    // graph evidence is part of that command's job. A plain query remains a
    // syntax/index lookup unless the caller opts into graph or taint facts.
    let graph_flows_enabled = graph_flow || structural_flow_lookup || explicit_endpoint_graph_flow;
    // A broad large-repository target query and an explicitly file-scoped
    // query both need the complete reverse caller relation. The latter is
    // easy to miss: opening only that file gives exact local syntax, but
    // cannot prove callers in sibling files. Publish/reuse the compact graph
    // generation for both shapes so `--file ... --graph-flow` is exact even
    // on a cold small workspace.
    let requires_persisted_graph_scope = (workspace_is_large || exact_file_path.is_some())
        && graph_flows_enabled
        && !taint_flow
        && (pattern.is_some() || explicit_endpoint_graph_flow);
    if requires_persisted_graph_scope {
        // Exact target/corridor queries need compact reverse-callgraph and
        // compiler-header partitions, not every workspace body resident in
        // this process. Isolated workers publish one coherent generation;
        // candidate lookup below then opens only the AST-derived target cut.
        super::diagnostics::run_graph_query_workers(root)?;
    }
    let literal_prefilter = pattern.map(inspect_literal_candidate).filter(|p| {
        !is_regex && p.len() >= 3 && !taint_flow && render.group_id_filter.is_none() && large_workspace
    });
    let retrieval_project = if !taint_flow
        && exact_file_path.is_none()
        && !is_regex
        && pattern.is_some_and(|pattern| pattern.len() >= 3)
        && render.group_id_filter.is_none()
        && large_workspace
    {
        open_project_index_retrieval_candidates(
            root,
            pattern.expect("retrieval eligibility requires a pattern"),
            bonsai_sdk::SearchFilters {
                file: filters.file,
                ..Default::default()
            },
        )?
    } else {
        None
    };
    let endpoint_retrieval_project = if !taint_flow
        && exact_file_path.is_none()
        && !is_regex
        && explicit_endpoint_graph_flow
        && large_workspace
    {
        open_project_index_retrieval_candidate_union(
            root,
            &[
                filters.from.expect("explicit endpoint query has a source"),
                filters.to.expect("explicit endpoint query has a target"),
            ],
            bonsai_sdk::SearchFilters {
                file: filters.file,
                ..Default::default()
            },
        )?
    } else {
        None
    };
    let endpoint_retrieval_used = endpoint_retrieval_project.is_some();
    let direct_file_scope = exact_file_path.is_some() && !taint_flow;
    let large_target_header_scope = requires_persisted_graph_scope
        && !explicit_endpoint_graph_flow
        && (is_regex || retrieval_project.is_none());
    let large_endpoint_header_scope = requires_persisted_graph_scope
        && explicit_endpoint_graph_flow
        && endpoint_retrieval_project.is_none();
    let target_inspect_scope = graph_flows_enabled
        && !explicit_endpoint_graph_flow
        && pattern.is_some()
        && (direct_file_scope
            || retrieval_project.is_some()
            || literal_prefilter.is_some()
            || large_target_header_scope);
    let partial_workspace = direct_file_scope
        || retrieval_project.is_some()
        || endpoint_retrieval_used
        || literal_prefilter.is_some()
        || large_target_header_scope
        || large_endpoint_header_scope;
    let (project, _footer) = if taint_flow {
        // Keep syntax candidate discovery and semantic closure as separate
        // compiler phases. The persisted IDG is opened only after exact body
        // caches are released below, so a broad query never retains its
        // syntax working set beside the graph.
        open_project(root)?
    } else if direct_file_scope {
        open_project_index_matching_path(root, exact_file_path.expect("checked exact file path"))?
    } else if let Some(project) = endpoint_retrieval_project {
        project
    } else if let Some(project) = retrieval_project {
        project
    } else if large_target_header_scope || large_endpoint_header_scope {
        // Regex and short-name retrieval are intentionally unsupported. Scan
        // only compact persisted declaration headers to identify exact target
        // FuncIds; the query workspace then streams their callgraph cut.
        (
            super::open_project_sidecar_validation_only(root)?,
            super::WorkspaceFooter::new(),
        )
    } else if let Some(literal) = literal_prefilter {
        open_project_index_matching_literal(root, literal)?
    } else {
        open_project(root)?
    };
    let prepare_stage = progress::ScopedSpinner::new("preparing inspect query");
    let initial_ws = project.workspace();
    let target_inspect_funcs = if target_inspect_scope {
        let matcher = Matcher::build(pattern, is_regex)?;
        let candidate_files = initial_ws.vfs().all_files();
        let headers = initial_ws.compiler_header_index_for_files(&candidate_files);
        let mut targets = headers
            .all_files()
            .flat_map(|file| headers.decls_in(file))
            .filter(|decl| {
                matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) && matcher.is_declaration_match(decl)
            })
            .map(|decl| bonsai_common::FuncId::new(decl.symbol.raw()))
            .collect::<Vec<_>>();
        targets.sort_unstable_by_key(|func| func.raw());
        targets.dedup();
        Some(targets)
    } else {
        None
    };
    let target_inspect_workspace = target_inspect_funcs.as_ref().and_then(|targets| {
        initial_ws.target_inspect_query_workspace(targets, Some(bonsai_common::Precision::Narrowed))
    });
    bonsai_diagnostics::debug_log!(
        "compiler-cache",
        "inspect target scope: requested={} matches={} scoped={}",
        target_inspect_scope,
        target_inspect_funcs.as_ref().map_or(0, Vec::len),
        target_inspect_workspace.is_some()
    );
    let endpoint_funcs = if explicit_endpoint_graph_flow && partial_workspace {
        let candidate_files = initial_ws.vfs().all_files();
        let resolve = |query: &str| {
            if !is_regex {
                return initial_ws.lookup_functions_in_persisted_headers(query, &candidate_files);
            }
            let matcher = Matcher::build(Some(query), true).ok()?;
            let headers = initial_ws.compiler_header_index_for_files(&candidate_files);
            let mut funcs = headers
                .all_files()
                .flat_map(|file| headers.decls_in(file))
                .filter(|decl| {
                    matches!(
                        decl.kind,
                        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                    ) && matcher.is_declaration_match(decl)
                })
                .map(|decl| bonsai_common::FuncId::new(decl.symbol.raw()))
                .collect::<Vec<_>>();
            funcs.sort_unstable_by_key(|func| func.raw());
            funcs.dedup();
            Some(funcs)
        };
        let from = filters.from.and_then(resolve);
        let to = filters.to.and_then(resolve);
        bonsai_diagnostics::debug_log!(
            "compiler-cache",
            "inspect endpoint candidates: files={} from_matches={} to_matches={}",
            candidate_files.len(),
            from.as_ref().map_or(0, Vec::len),
            to.as_ref().map_or(0, Vec::len)
        );
        from.zip(to)
    } else {
        None
    };
    let endpoint_workspace = endpoint_funcs.as_ref().and_then(|(from, to)| {
        initial_ws.source_target_query_workspace(from, to, Some(bonsai_common::Precision::Narrowed))
    });
    bonsai_diagnostics::debug_log!(
        "compiler-cache",
        "inspect endpoint corridor: retrieval={} resolved={} scoped={}",
        endpoint_retrieval_used,
        endpoint_funcs.is_some(),
        endpoint_workspace.is_some()
    );
    let exact_endpoint_absent = endpoint_funcs
        .as_ref()
        .is_some_and(|(from, to)| from.is_empty() || to.is_empty());
    let endpoint_fallback_project = if explicit_endpoint_graph_flow
        && endpoint_workspace.is_none()
        && endpoint_retrieval_used
        && !exact_endpoint_absent
    {
        Some(open_project(root)?)
    } else {
        None
    };
    let target_graph_index_unavailable = target_inspect_funcs
        .as_ref()
        .is_some_and(|targets| !targets.is_empty() && target_inspect_workspace.is_none());
    let ws = if let Some(workspace) = target_inspect_workspace.as_ref() {
        workspace
    } else if let Some(workspace) = endpoint_workspace.as_ref() {
        workspace
    } else if let Some((project, _)) = endpoint_fallback_project.as_ref() {
        project.workspace()
    } else {
        initial_ws
    };
    // A missing/stale partitioned callgraph is an acceleration miss, not a
    // reason to hydrate the complete resident graph. Compile the exact
    // uncapped source-reachable worklist and seed only this invocation's
    // presentation cache. Stable workspace FuncIds from the retrieval
    // candidate workspace remain valid in the complete fallback workspace.
    let endpoint_fallback_graph = if exact_endpoint_absent {
        Some(std::sync::Arc::new(bonsai_callgraph::ResolvedCallGraph::default()))
    } else if explicit_endpoint_graph_flow && endpoint_workspace.is_none() {
        let endpoint_funcs = endpoint_funcs.clone().or_else(|| {
            filters
                .from
                .and_then(|from| ws.lookup_function(from))
                .zip(filters.to.and_then(|to| ws.lookup_function(to)))
                .map(|(from, to)| (vec![from], vec![to]))
        });
        endpoint_funcs.map(|(from, to)| {
            let corridor =
                ws.source_reachable_query_call_graph(&from, &to, Some(bonsai_common::Precision::Narrowed));
            tracing::debug!(
                target: "compiler-cache",
                sources = from.len(),
                targets = to.len(),
                reached_targets = corridor.reached_targets,
                files = corridor.files.len(),
                funcs = corridor.funcs.len(),
                nodes = corridor.graph.nodes().len(),
                edges = corridor.graph.inner().edges.len(),
                "inspect endpoint fallback compiled"
            );
            corridor.graph
        })
    } else {
        None
    };
    // A target-oriented graph query needs the complete reverse caller
    // relation. If no validated partitioned callgraph exists, opening the
    // whole workspace here makes an exact-file request compile every body in
    // the repository. On Elasticsearch that accidental fallback consumed
    // multiple GiB before producing its first row. Keep the syntax result
    // available, seed an explicitly incomplete empty relation, and report the
    // missing reverse index instead of silently doing unrelated broad work.
    // `index --semantic` persists the uncapped reverse relation; a subsequent
    // query then materializes only the exact target cut.
    let target_fallback_graph = target_graph_index_unavailable
        .then(|| std::sync::Arc::new(bonsai_callgraph::ResolvedCallGraph::default()));
    let query_graph = endpoint_fallback_graph
        .clone()
        .or_else(|| target_fallback_graph.clone());
    if endpoint_workspace.is_some() || endpoint_fallback_graph.is_some() {
        // The compiler corridor already resolved both qualified endpoints to
        // exact FuncIds. Inspect's presentation matcher operates on short
        // Tree-sitter callable names, so compare lexical tails inside that
        // proven graph rather than requiring each rendered hop to repeat its
        // full module/class qualification.
        filters.from = filters.from.map(bonsai_lang_api::kit::short_name_of);
        filters.to = filters.to.map(bonsai_lang_api::kit::short_name_of);
    }
    let global = ws.compiler_header_index();
    let full_source_for_large_bodies =
        paging_cfg.all || render.flow_id_filter.is_some() || render.group_id_filter.is_some();
    // One cache per `inspect` run. `inspect --query system` in Redis
    // resolves 50+ hits to the same handful of enclosing functions, so
    // per-target memoization here turns an N × call-graph walk into
    // single-shot lookups after the first hit on each function.
    // `--no-cache` / `BONSAI_NO_CACHE` swaps this for a pass-through
    // variant that always takes the cold path.
    let chain_cache = build_chain_cache(ws, query_graph.clone());
    // Edge resolvability is queried heavily when `inspect` extends raw
    // upstream chains into concrete downstream call paths. Cache the
    // per-file alias maps and per-edge span lookups for this invocation;
    // otherwise hub queries such as Redis's `--query system` repeatedly
    // rescan the same parse trees while checking the same edges.
    let mut edge_resolver = query_graph.map_or_else(
        || CallEdgeResolver::new(ws),
        |graph| CallEdgeResolver::with_resolved_graph(ws, graph),
    );

    // When no query is supplied, `inspect` becomes a filter-driven
    // enumeration. Declaration hits stay opt-in in this mode, but
    // occurrence hits should still be seeded by the concrete endpoint
    // when the user provides one. Otherwise `inspect --to pickle`
    // treats every string/arg/var in any function that reaches pickle
    // as a match point.
    let matcher: Matcher = match pattern {
        Some(p) => build_matcher(p, is_regex)?,
        None => Matcher::MatchAll,
    };
    let filter_only_occurrence_pattern = if pattern.is_none() {
        filters
            .to
            .or(filters.from)
            .map(bonsai_lang_api::kit::short_name_of)
    } else {
        None
    };
    let occurrence_matcher: Matcher = match filter_only_occurrence_pattern {
        Some(p) => build_matcher(p, false)?,
        None => matcher.clone(),
    };
    let filter_only_target_scan = filter_only_occurrence_pattern.is_some();
    let filter_only_occurrence_kind = if pattern.is_none() {
        filters.to_kind.or(filters.from_kind).map(FactKindFilter::to_sdk)
    } else {
        None
    };
    prepare_stage.finish();
    let kinds: ahash::AHashSet<String> = kind_filter.iter().map(|s| s.to_lowercase()).collect();
    // When a `--query` is active but `--kind` is left unset, exclude
    // purely lexical hit kinds (`decorator`, `ref`) from the default
    // set. Decorators and bare refs aren't part of the taint-analysis
    // view — they're syntactic annotations that shadow the same
    // location as a `call` / `read` / `write` fact and inflate the
    // "other hits" count with duplicates (e.g. `request.args.get(...)`
    // emits BOTH a `call` and a `decorator`/`ref` hit for `request`).
    // Users who explicitly want those kinds pass `--kind decorator`
    // / `--kind ref` and get them back. When no query is supplied
    // we keep every kind available — the filter-driven enumeration
    // mode deliberately surfaces everything the matchers let through.
    let kind_selection = InspectKindSelection {
        requested: kinds,
        endpoint_kind: filter_only_occurrence_kind,
        exclude_lexical_by_default: pattern.is_some() || filter_only_target_scan,
    };

    // ----- 1. Decl hits: keep the existing chain-enumerated flow render.
    //
    // When the matcher is universal (no `--query`), listing every decl
    // as a hit floods the output. Skip decl hits in that case *unless*
    // the user explicitly asked for them via `--kind decl`. The
    // `--from` / `--to` / `--file` / `--in-fn` filters still narrow
    // the per-hit flow enumeration below.
    // Enumerate decls when the user either gave us a non-universal
    // matcher, explicitly opted in via `--kind decl`, OR asked for a
    // specific flow / group id (`--flow F:<16-hex>` /
    // `--group G:<16-hex>`). The id paths need every decl's chains
    // enumerated because they target a chain by hash, not by name
    // — without that, a query-less `inspect --flow F:<16-hex>`
    // would find nothing.
    let emit_decls = kind_selection.wants("decl")
        && (!matcher.is_universal()
            || kind_selection.requested.contains("decl")
            || render.flow_id_filter.is_some()
            || render.group_id_filter.is_some());
    // Iterate files by PATH order (not FileId). This matches the final
    // display sort, which keeps discovery and final label assignment
    // deterministic across cache state and hash-map iteration order.
    // A literal syntax fact must have a spelling in its source file. On a
    // complete workspace opened for a persisted taint IDG, apply that exact
    // raw-source anchor before decoding compiler bodies. This retains the
    // full IDG/header universe for semantics while making body hydration
    // proportional to candidate files rather than repository size.
    let taint_source_literal = taint_flow
        .then(|| pattern.map(inspect_literal_candidate))
        .flatten()
        .filter(|literal| !is_regex && literal.len() >= 3);
    let files_in_path_order: Vec<bonsai_common::FileId> = {
        let mut v: Vec<(String, bonsai_common::FileId)> = global
            .all_files()
            .filter(|file| {
                taint_source_literal.is_none_or(|literal| {
                    ws.vfs()
                        .snapshot(*file)
                        .is_ok_and(|snapshot| source_contains_inspect_literal(&snapshot.text, literal))
                })
            })
            .map(|f| {
                let path = ws
                    .vfs()
                    .path(f)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                (path, f)
            })
            .collect();
        v.sort();
        v.into_iter().map(|(_, f)| f).collect()
    };
    let large_syntax_scan = partial_workspace || files_in_path_order.len() > INSPECT_GRAPH_FLOW_FILE_LIMIT;
    let syntax_fast_path = !graph_flows_enabled;
    let structural_id_only_lookup = structural_flow_lookup
        && pattern.is_none()
        && kind_filter.is_empty()
        && filters.from.is_none()
        && filters.from_kind.is_none()
        && filters.to.is_none()
        && filters.to_kind.is_none()
        && filters.file.is_none()
        && filters.in_fn.is_none();
    // A bare `--flow F:` / `--group G:` open skips the whole-workspace
    // occurrence scan only when that scan would be expensive: with a
    // MatchAll matcher every var/call/arg in the workspace becomes a
    // hit whose chains get enumerated — the exact blowup direct id
    // lookups exist to avoid. Small workspaces keep the folded
    // occurrence context (vars/calls sharing the flow id); dropping it
    // everywhere lost render context the folding contract pins. The
    // large-workspace skip is safe because the stable structural id itself
    // defines the requested relation; occurrence matches are optional query
    // context, not part of that graph result.
    // `show F:` / `show G:` drilldowns skip the occurrence scan
    // unconditionally — they are pure structural-chain views; the id
    // IS the query. `inspect --flow` keeps the folded occurrence
    // context except on large workspaces.
    let occurrence_scan_skipped_for_id_lookup =
        structural_id_only_lookup && (large_syntax_scan || render.structural_drilldown);
    // Raw inspect taint-flow is query-bounded by default: syntax hits add
    // their enclosing callable to this set, then we ask the taint graph
    // only for those entries. The only workspace-wide fallback is a
    // direct `--flow T:...` lookup without any query/filter signal,
    // because the `T:` id is derived from taint row content rather
    // than a persisted index key.
    let taint_flow_id_lookup = taint_flow
        && render
            .flow_id_filter
            .as_deref()
            .is_some_and(|id| id.starts_with("T:"));
    let direct_taint_id_lookup = taint_flow_id_lookup
        && pattern.is_none()
        && filters.from.is_none()
        && filters.to.is_none()
        && filters.file.is_none()
        && filters.in_fn.is_none()
        && kind_filter.is_empty();
    let initial_taint_candidates = if direct_taint_id_lookup {
        all_callable_entries(ws, &files_in_path_order)
            .into_iter()
            .collect()
    } else {
        ahash::AHashSet::default()
    };
    // Raw taint evidence is semantic output, not a preview budget. Analyze
    // every syntax-derived candidate and retain every matching path; the
    // text/JSON renderers page the owned rows afterward. `--all` therefore
    // changes presentation only and can never change taint results.
    let mut taint_candidates = TaintCandidates::new(initial_taint_candidates);
    let syntax_inspect_started = std::time::Instant::now();
    let decl_hits = collect_decl_hits(
        ws,
        &chain_cache,
        &mut edge_resolver,
        DeclHitPass {
            enabled: emit_decls,
            files_in_path_order: &files_in_path_order,
            matcher: &matcher,
            filters,
            taint_flow,
            graph_flows_enabled,
            full_source_for_large_bodies,
        },
        &mut taint_candidates,
    );
    let occurrence_hits = collect_occurrence_hits(
        ws,
        &chain_cache,
        &mut edge_resolver,
        OccurrenceHitPass {
            files_in_path_order: &files_in_path_order,
            occurrence_matcher: &occurrence_matcher,
            kind_selection: &kind_selection,
            filter_only_occurrence_kind,
            filters,
            full_source_for_large_bodies,
            graph_flows_enabled,
            syntax_fast_path,
            taint_flow,
            occurrence_scan_skipped_for_id_lookup,
            partial_workspace,
            large_syntax_scan,
        },
        &mut taint_candidates,
    );
    bonsai_diagnostics::debug_log!(
        "compiler-cache",
        "inspect syntax hydration: files={} decl_hits={} occurrence_hits={} taint_entries={} targets={} elapsed={:.3}s",
        files_in_path_order.len(),
        decl_hits.len(),
        occurrence_hits.hits.len(),
        taint_candidates.entries.len(),
        taint_candidates.target_spans.len(),
        syntax_inspect_started.elapsed().as_secs_f64()
    );
    drop(edge_resolver);
    drop(chain_cache);
    drop(global);
    if taint_flow {
        // Syntax navigation has already been rendered into owned rows and
        // stable FuncIds. End that compiler phase before the scoped semantic
        // graph opens so whole-body/chain working sets do not overlap the
        // exact IDG. Every released cache is reproducible from the immutable
        // VFS/compiler objects; this changes allocation lifetime, never
        // analysis scope.
        ws.db().release_global_index();
        ws.release_resolved_call_graph_cache();
        ws.release_compiler_linkage_cache();
        ws.release_exact_body_cache();
        ws.release_decl_name_index_cache();
        // Reuse a fresh complete semantic generation only after the syntax
        // phase has relinquished its body/cache owners. A miss remains an
        // ordinary acceleration miss: `syntax_flow_session` compiles the
        // exact source/target corridor without changing query scope.
        let semantic_stage = progress::ScopedSpinner::new("loading semantic index");
        if let Err(error) = ws.load_idg_sidecar(root) {
            bonsai_diagnostics::debug_log!(
                "idg-build",
                "inspect persisted IDG load failed at {}: {}",
                root.display(),
                error
            );
        }
        semantic_stage.finish();
    }
    finish_inspect(
        root,
        ws,
        InspectFinish {
            pattern,
            is_regex,
            kind_filter,
            filters,
            render,
            paging_cfg,
            format,
            taint_flow,
            graph_flows_enabled,
            graph_flow_incomplete_reason: target_graph_index_unavailable.then_some(
                "the complete reverse-call index is not warmed; run `bonsai-ninja index <workspace> --semantic`",
            ),
        },
        decl_hits,
        occurrence_hits,
        taint_candidates,
    )
}

fn import_hit_text(imp: &bonsai_lang_api::ImportSpec) -> String {
    match (imp.original_name.as_deref(), imp.alias.as_deref()) {
        (Some(original), Some(alias)) => format!("{original} from {} as {alias}", imp.module),
        (Some(original), None) => format!("{original} from {}", imp.module),
        (None, Some(alias)) => format!("{} as {alias}", imp.module),
        (None, None) => imp.module.clone(),
    }
}

struct InspectTaintFlowOptions<'a> {
    pattern: Option<&'a str>,
    is_regex: bool,
    filters: InspectFilters<'a>,
    kind_filter: &'a [String],
    prefer_warmed_idg: bool,
    flow_id_filter: Option<&'a str>,
}

struct TaintFlowMatchContext<'a> {
    matcher: Option<&'a Matcher>,
    filters: InspectFilters<'a>,
    kind_filter: &'a [String],
    /// When reopening a single raw taint id (`show T:`), skip building
    /// the expensive display for every candidate whose id doesn't match.
    flow_id_filter: Option<&'a str>,
}

#[derive(Clone, Debug)]
struct TaintFunctionDisplay {
    short_name: String,
    qualified_name: String,
    kind: Option<DeclKind>,
}

/// Immutable display metadata for the exact function scope of one raw-taint
/// query. Elasticsearch-sized queries can materialize many paths through the
/// same functions. Looking each name up through `compiler_header_index()` for
/// every rendered path needlessly reacquires the workspace cache lock millions
/// of times. Build this small projection once from the compiler headers and
/// reuse it while the semantic workers render their results.
struct TaintDisplayIndex {
    functions: ahash::AHashMap<bonsai_common::FuncId, TaintFunctionDisplay>,
}

impl TaintDisplayIndex {
    fn new(ws: &Workspace, funcs: impl IntoIterator<Item = bonsai_common::FuncId>) -> Self {
        let headers = ws.compiler_header_index();
        let mut functions = ahash::AHashMap::default();
        for func in funcs {
            functions.entry(func).or_insert_with(|| {
                let symbol = bonsai_common::SymbolId::new(func.raw());
                let Some(decl) = headers.decl_of(symbol) else {
                    return TaintFunctionDisplay {
                        short_name: "<unknown>".to_string(),
                        qualified_name: "<unknown>".to_string(),
                        kind: None,
                    };
                };

                let mut owner_names = Vec::new();
                let mut parent = decl.parent;
                while let Some(parent_symbol) = parent {
                    let Some(parent_decl) = headers.decl_of(parent_symbol) else {
                        break;
                    };
                    if is_renderable_owner(parent_decl.kind) {
                        owner_names.push(parent_decl.name.clone());
                    }
                    parent = parent_decl.parent;
                }
                owner_names.reverse();
                let qualified_name = if owner_names.is_empty() {
                    decl.qualified_name
                        .as_ref()
                        .filter(|qualified| qualified.as_str() != decl.name)
                        .cloned()
                        .unwrap_or_else(|| decl.name.clone())
                } else {
                    format!("{}.{}", owner_names.join("."), decl.name)
                };
                TaintFunctionDisplay {
                    short_name: decl.name.clone(),
                    qualified_name,
                    kind: Some(decl.kind),
                }
            });
        }
        Self { functions }
    }

    fn short_name(&self, ws: &Workspace, func: bonsai_common::FuncId) -> String {
        self.functions
            .get(&func)
            .map(|display| display.short_name.clone())
            .unwrap_or_else(|| func_display_name(ws, func))
    }

    fn kind(&self, ws: &Workspace, func: bonsai_common::FuncId) -> Option<DeclKind> {
        self.functions.get(&func).map_or_else(
            || {
                ws.compiler_header_index()
                    .decl_of(bonsai_common::SymbolId::new(func.raw()))
                    .map(|decl| decl.kind)
            },
            |display| display.kind,
        )
    }

    fn disambiguated_names(&self, ws: &Workspace, funcs: &[bonsai_common::FuncId]) -> Vec<String> {
        let short_names: Vec<String> = funcs.iter().map(|&func| self.short_name(ws, func)).collect();
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for name in short_names.iter().filter(|name| !name.is_empty()) {
            *counts.entry(name.clone()).or_default() += 1;
        }
        funcs
            .iter()
            .zip(short_names)
            .filter_map(|(&func, short_name)| {
                if short_name.is_empty() {
                    None
                } else if counts.get(short_name.as_str()).copied().unwrap_or(0) > 1 {
                    Some(
                        self.functions
                            .get(&func)
                            .map(|display| display.qualified_name.clone())
                            .unwrap_or_else(|| func_disambiguated_display_name(ws, func, &short_name)),
                    )
                } else {
                    Some(short_name)
                }
            })
            .collect()
    }
}

#[derive(Clone, Debug, Default)]
struct InspectSemanticFlowStats {
    entry_queries: usize,
    backend_counts: BTreeMap<String, usize>,
    cache_hits: usize,
    cache_misses: usize,
    target_cut_size: Option<usize>,
    fallback_reasons: Vec<String>,
    incomplete_reasons: Vec<String>,
}

impl InspectSemanticFlowStats {
    fn record_plan(&mut self, plan: &SyntaxFlowPlan) {
        self.entry_queries += 1;
        *self
            .backend_counts
            .entry(plan.backend.label().to_string())
            .or_default() += 1;
        match plan.cache_status {
            bonsai_sdk::SyntaxFlowCacheStatus::Hit => self.cache_hits += 1,
            bonsai_sdk::SyntaxFlowCacheStatus::MissComputed => self.cache_misses += 1,
        }
        match (self.target_cut_size, plan.target_cut_size) {
            (None, Some(size)) => self.target_cut_size = Some(size),
            (Some(existing), Some(size)) if existing == size => {}
            (Some(_), Some(_) | None) => self.target_cut_size = None,
            (None, None) => {}
        }
        extend_unique_sorted(&mut self.fallback_reasons, &plan.fallback_reasons);
        extend_unique_sorted(&mut self.incomplete_reasons, &plan.analysis_incomplete_reasons);
    }
}

fn inspect_taint_flows(
    ws: &Workspace,
    candidates: &TaintCandidates,
    options: InspectTaintFlowOptions<'_>,
) -> Result<(Vec<InspectTaintFlow>, InspectSemanticFlowStats)> {
    let inspect_taint_started = std::time::Instant::now();
    let InspectTaintFlowOptions {
        pattern,
        is_regex,
        filters,
        kind_filter,
        prefer_warmed_idg,
        flow_id_filter,
    } = options;
    let matcher = pattern.map(|p| build_matcher(p, is_regex)).transpose()?;
    let kind_filter: Vec<String> = kind_filter.iter().map(|kind| kind.to_lowercase()).collect();
    let match_context = TaintFlowMatchContext {
        matcher: matcher.as_ref(),
        filters,
        kind_filter: &kind_filter,
        flow_id_filter,
    };
    let candidate_entries = &candidates.entries;
    let mut entries: Vec<bonsai_common::FuncId> = candidate_entries.iter().copied().collect();
    entries.sort_by_key(|func| func.raw());
    let fallback_target_funcs = if prefer_warmed_idg {
        candidate_entries.clone()
    } else {
        ahash::AHashSet::default()
    };
    let lineage_started = std::time::Instant::now();
    let lineage_targets = if prefer_warmed_idg && pattern.is_some() {
        let mut targets = if candidates.declaration_targets_complete {
            candidates.declaration_targets.iter().copied().collect::<Vec<_>>()
        } else {
            let headers = ws.compiler_header_index();
            headers
                .all_files()
                .flat_map(|file| headers.decls_in(file))
                .filter(|decl| {
                    matches!(
                        decl.kind,
                        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                    ) && matcher
                        .as_ref()
                        .is_some_and(|matcher| matcher.is_declaration_match(decl))
                })
                .map(|decl| bonsai_common::FuncId::new(decl.symbol.raw()))
                .collect::<Vec<_>>()
        };
        targets.sort_unstable_by_key(|func| func.raw());
        targets.dedup();
        Some(targets)
    } else {
        None
    };
    let lineage_funcs = if prefer_warmed_idg {
        lineage_targets.as_ref().and_then(|targets| {
            if targets.is_empty() {
                // A query with no callable declaration target is an exact
                // local syntax question (for example, a variable or external
                // API call). Its owning functions contain every matching
                // compiler point; no invented callee/name search is needed.
                return Some(candidate_entries.clone());
            }
            let mut funcs =
                ws.target_inspect_lineage_funcs(targets, Some(bonsai_common::Precision::Narrowed))?;
            // Unresolved call sites and non-call syntax matches may not occur
            // in the resolved reverse graph. Their exact local bodies remain
            // part of the query by construction.
            funcs.extend(candidate_entries.iter().copied());
            Some(funcs)
        })
    } else {
        None
    };
    bonsai_diagnostics::debug_log!(
        "compiler-cache",
        "inspect taint scope: entries={} declaration_targets={} lineage_funcs={} fallback_global={} elapsed={:.3}s",
        entries.len(),
        lineage_targets.as_ref().map_or(0, Vec::len),
        lineage_funcs.as_ref().map_or(0, |funcs| funcs.len()),
        prefer_warmed_idg && lineage_funcs.is_none(),
        lineage_started.elapsed().as_secs_f64()
    );
    let display_started = std::time::Instant::now();
    let display_stage = progress::ScopedSpinner::new("preparing taint symbol display");
    let mut display_funcs = lineage_funcs
        .as_ref()
        .map(|funcs| funcs.iter().copied().collect::<Vec<_>>())
        .unwrap_or_else(|| entries.clone());
    display_funcs.extend(candidate_entries.iter().copied());
    if let Some(targets) = lineage_targets.as_ref() {
        display_funcs.extend(targets.iter().copied());
    }
    let display_index = TaintDisplayIndex::new(ws, display_funcs);
    display_stage.finish();
    bonsai_diagnostics::debug_log!(
        "compiler-cache",
        "inspect taint display index: functions={} elapsed={:.3}s",
        display_index.functions.len(),
        display_started.elapsed().as_secs_f64()
    );
    let target_nodes_started = std::time::Instant::now();
    let session = if prefer_warmed_idg {
        (!fallback_target_funcs.is_empty())
            .then(|| ws.syntax_flow_session(&entries, &fallback_target_funcs))
            .flatten()
    } else {
        None
    };
    let target_stage = progress::ScopedSpinner::new("preparing taint target cut");
    let (target_nodes_by_source, unresolved_target_funcs) = if prefer_warmed_idg {
        ws.syntax_flow_target_nodes_by_source_with_session(&candidates.target_spans, session.as_ref())
            .unwrap_or_else(|| (ahash::AHashMap::new(), fallback_target_funcs.clone()))
    } else {
        (ahash::AHashMap::new(), fallback_target_funcs.clone())
    };
    let mut target_nodes: Vec<_> = target_nodes_by_source.values().flatten().copied().collect();
    target_nodes.sort_unstable();
    target_nodes.dedup();
    // Exact syntax endpoints are the strongest compiler target. Retain a
    // whole-function fallback only for a span that the adapter/IDG could not
    // represent. If no endpoint resolved (notably direct T: lookup), the
    // complete candidate function set remains the conservative surface.
    let target_funcs = if target_nodes.is_empty() {
        fallback_target_funcs
    } else {
        unresolved_target_funcs.clone()
    };
    // Broad syntax queries can produce many independent target owners. Build
    // the conservative backward target-demand fixed point once for their
    // exact union, then reuse it for every owner-specific forward closure.
    // The forward solver still receives only that owner's concrete target
    // nodes and preserves call contexts, so shared demand can admit extra
    // candidates but cannot manufacture a path or cross-contaminate owners.
    // This is the same compiler dataflow shape used by security batches and
    // avoids N identical walks over the persisted reverse relations.
    let source_rooted_targets = prefer_warmed_idg
        && !candidates.target_spans.is_empty()
        && lineage_funcs.as_ref().is_some_and(|funcs| !funcs.is_empty());
    bonsai_diagnostics::debug_log!(
        "compiler-cache",
        "inspect taint target attribution: target_nodes={} unresolved_funcs={} elapsed={:.3}s",
        target_nodes.len(),
        target_funcs.len(),
        target_nodes_started.elapsed().as_secs_f64()
    );
    let target_relevance_started = std::time::Instant::now();
    let target_relevance = if prefer_warmed_idg {
        ws.syntax_flow_target_relevance_with_session(
            &target_nodes,
            &target_funcs,
            lineage_funcs.as_ref(),
            session.as_ref(),
        )
    } else {
        None
    };
    bonsai_diagnostics::debug_log!(
        "compiler-cache",
        "inspect taint target relevance: available={} elapsed={:.3}s",
        target_relevance.is_some(),
        target_relevance_started.elapsed().as_secs_f64()
    );
    let unfiltered_entry_count = entries.len();
    let source_filter_started = std::time::Instant::now();
    if let Some(relevance) = target_relevance.as_ref() {
        // An entry that owns an exact target node (or the conservative
        // unresolved-function fallback for one of its target spans) is
        // already admitted by construction: those nodes/functions seeded the
        // backward relation immediately above. Rechecking every node owned by
        // those entries against the external-memory relevance set is pure
        // duplicate work on broad syntax queries. Ask the header prefilter
        // only about entries that do not themselves own a target, then merge
        // that proof with the direct compiler ownership facts. This changes
        // neither target demand nor forward-closure scope.
        let owns_direct_target = |entry: &bonsai_common::FuncId| {
            source_rooted_targets
                && (target_nodes_by_source
                    .get(entry)
                    .is_some_and(|nodes| !nodes.is_empty())
                    || unresolved_target_funcs.contains(entry))
        };
        let entries_needing_proof = entries
            .iter()
            .copied()
            .filter(|entry| !owns_direct_target(entry))
            .collect::<Vec<_>>();
        if !entries_needing_proof.is_empty() {
            if let Some(relevant_entries) = ws.syntax_flow_relevant_sources_with_session(
                &entries_needing_proof,
                relevance,
                session.as_ref(),
            ) {
                let relevant_entries = relevant_entries.into_iter().collect::<ahash::AHashSet<_>>();
                entries.retain(|entry| owns_direct_target(entry) || relevant_entries.contains(entry));
            }
        }
    }
    bonsai_diagnostics::debug_log!(
        "compiler-cache",
        "inspect taint source demand: candidates={} relevant={} elapsed={:.3}s",
        unfiltered_entry_count,
        entries.len(),
        source_filter_started.elapsed().as_secs_f64()
    );
    target_stage.finish();
    let mut flows = Vec::new();
    let mut semantic_flow_stats = InspectSemanticFlowStats::default();
    let entry_bar = progress::progress_bar("tracing taint entries", entries.len() as u64);
    let analyze_entry = |entry: bonsai_common::FuncId| {
        entry_bar.inc(1);
        let entry_target_nodes = if source_rooted_targets {
            target_nodes_by_source
                .get(&entry)
                .map(Vec::as_slice)
                .unwrap_or_default()
        } else {
            target_nodes.as_slice()
        };
        let entry_target_funcs = if source_rooted_targets {
            let needs_fallback = entry_target_nodes.is_empty() || unresolved_target_funcs.contains(&entry);
            needs_fallback.then(|| ahash::AHashSet::from([entry]))
        } else {
            None
        };
        let entry_target_funcs_ref = entry_target_funcs.as_ref().unwrap_or(&target_funcs);
        let query = SyntaxFlowQuery::new(entry)
            .target_nodes((!entry_target_nodes.is_empty()).then_some(entry_target_nodes))
            .target_funcs((!entry_target_funcs_ref.is_empty()).then_some(entry_target_funcs_ref))
            .lineage_funcs(lineage_funcs.as_ref())
            .target_relevance(target_relevance.as_ref())
            .prefer_warmed_idg(prefer_warmed_idg)
            .session(session.as_ref());
        let graph = ws.syntax_flow_graph(query);
        let mut entry_flows = Vec::new();
        collect_taint_flows_for_entry(
            ws,
            &display_index,
            entry,
            graph.graph.as_ref(),
            &match_context,
            &mut entry_flows,
        );
        (entry_flows, graph.plan)
    };
    let workers = bonsai_common::rooted_semantic_query_worker_count(rayon::current_num_threads());
    bonsai_diagnostics::debug_log!("compiler-cache", "inspect rooted taint workers: {}", workers);
    let closures_started = std::time::Instant::now();
    let results = if workers == 1 {
        entries.iter().copied().map(&analyze_entry).collect::<Vec<_>>()
    } else {
        use rayon::prelude::*;
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .thread_name(|index| format!("bonsai-inspect-flow-{index}"))
            .build()
            .expect("build memory-bounded inspect flow pool")
            .install(|| {
                entries
                    .par_iter()
                    .copied()
                    .map(&analyze_entry)
                    .collect::<Vec<_>>()
            })
    };
    bonsai_diagnostics::debug_log!(
        "compiler-cache",
        "inspect taint closures: entries={} elapsed={:.3}s",
        results.len(),
        closures_started.elapsed().as_secs_f64()
    );
    for (mut entry_flows, plan) in results {
        semantic_flow_stats.record_plan(&plan);
        flows.append(&mut entry_flows);
    }
    entry_bar.finish_and_clear();
    let flow_count_before_dedup = flows.len();
    let finalize_started = std::time::Instant::now();
    dedup_taint_flows(&mut flows);
    flows.sort_by(|a, b| {
        a.steps
            .last()
            .map(|step| (&step.file, step.line, step.column))
            .cmp(&b.steps.last().map(|step| (&step.file, step.line, step.column)))
            .then(a.entry.cmp(&b.entry))
            .then(a.terminal.cmp(&b.terminal))
            .then(a.taint_id.cmp(&b.taint_id))
    });
    bonsai_diagnostics::debug_log!(
        "compiler-cache",
        "inspect taint finalize: raw_flows={} unique_flows={} elapsed={:.3}s total={:.3}s",
        flow_count_before_dedup,
        flows.len(),
        finalize_started.elapsed().as_secs_f64(),
        inspect_taint_started.elapsed().as_secs_f64()
    );
    Ok((flows, semantic_flow_stats))
}

fn all_callable_entries(
    ws: &Workspace,
    files_in_path_order: &[bonsai_common::FileId],
) -> Vec<bonsai_common::FuncId> {
    let global = ws.compiler_header_index();
    let mut seen = ahash::AHashSet::default();
    let mut entries = Vec::new();
    for file in files_in_path_order {
        for decl in global.decls_in(*file) {
            if !matches!(
                decl.kind,
                DeclKind::Module
                    | DeclKind::Function
                    | DeclKind::Method
                    | DeclKind::Constructor
                    | DeclKind::Global
            ) {
                continue;
            }
            let func = bonsai_common::FuncId::new(decl.symbol.raw());
            if seen.insert(func) {
                entries.push(func);
            }
        }
    }
    entries
}

fn collect_taint_flows_for_entry(
    ws: &Workspace,
    display_index: &TaintDisplayIndex,
    entry: bonsai_common::FuncId,
    graph: &EntryTaintGraph,
    match_context: &TaintFlowMatchContext<'_>,
    out: &mut Vec<InspectTaintFlow>,
) {
    let trace_index = trace_record_index_for_inspect(&graph.call_records);
    let edge_steps = edge_step_index_for_inspect(ws, display_index, &graph.call_records);
    let build_context = TaintFlowBuildContext {
        ws,
        display_index,
        entry,
        trace_index: &trace_index,
        edge_steps: &edge_steps,
        flow_id_filter: match_context.flow_id_filter,
    };
    for call in &graph.tainted_calls {
        if let Some(flow) = taint_flow_for_terminal_call(&build_context, call, graph.precision) {
            if taint_flow_matches(
                ws,
                &flow,
                match_context.matcher,
                match_context.filters,
                match_context.kind_filter,
            ) {
                out.push(flow);
            }
        }
    }
    for record in &graph.call_records {
        if let Some(flow) = taint_flow_for_terminal_edge(&build_context, record) {
            if taint_flow_matches(
                ws,
                &flow,
                match_context.matcher,
                match_context.filters,
                match_context.kind_filter,
            ) {
                out.push(flow);
            }
        }
    }
}

struct TaintFlowBuildContext<'a> {
    ws: &'a Workspace,
    display_index: &'a TaintDisplayIndex,
    entry: bonsai_common::FuncId,
    trace_index: &'a ahash::AHashMap<u64, &'a TaintedCallEdge>,
    edge_steps: &'a ahash::AHashMap<u64, InspectTaintStep>,
    flow_id_filter: Option<&'a str>,
}

fn taint_flow_for_terminal_call(
    context: &TaintFlowBuildContext<'_>,
    call: &TaintedCall,
    graph_precision: bonsai_common::Precision,
) -> Option<InspectTaintFlow> {
    let records = match call.parent_trace_id {
        Some(trace_id) => lineage_records_for_trace_id_inspect(context.trace_index, trace_id)?,
        None => Vec::new(),
    };
    let mut steps: Vec<InspectTaintStep> = records
        .iter()
        .filter_map(|record| {
            cached_taint_step_for_edge(context.ws, context.display_index, context.edge_steps, record)
        })
        .collect();
    steps.push(taint_step_for_terminal_call(
        context.ws,
        context.display_index,
        call,
        graph_precision,
    ));
    build_inspect_taint_flow(
        context.ws,
        context.display_index,
        context.entry,
        &records,
        Some(call),
        terminal_kind_label(&call.kind),
        graph_precision,
        steps,
        context.flow_id_filter,
    )
}

fn taint_flow_for_terminal_edge(
    context: &TaintFlowBuildContext<'_>,
    record: &TaintedCallEdge,
) -> Option<InspectTaintFlow> {
    let records = if record.trace_id == 0 {
        vec![record]
    } else {
        lineage_records_for_trace_id_inspect(context.trace_index, record.trace_id)?
    };
    let steps: Vec<InspectTaintStep> = records
        .iter()
        .filter_map(|record| {
            cached_taint_step_for_edge(context.ws, context.display_index, context.edge_steps, record)
        })
        .collect();
    build_inspect_taint_flow(
        context.ws,
        context.display_index,
        context.entry,
        &records,
        None,
        "propagation",
        record.precision,
        steps,
        context.flow_id_filter,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_inspect_taint_flow(
    ws: &Workspace,
    display_index: &TaintDisplayIndex,
    entry: bonsai_common::FuncId,
    records: &[&TaintedCallEdge],
    terminal_call: Option<&TaintedCall>,
    terminal_kind: &str,
    precision: bonsai_common::Precision,
    steps: Vec<InspectTaintStep>,
    flow_id_filter: Option<&str>,
) -> Option<InspectTaintFlow> {
    let mut funcs = vec![entry];
    for record in records {
        if funcs.last().copied() != Some(record.caller) {
            funcs.push(record.caller);
        }
        if funcs.last().copied() != Some(record.callee) {
            funcs.push(record.callee);
        }
    }
    if let Some(call) = terminal_call {
        if funcs.last().copied() != Some(call.caller) {
            funcs.push(call.caller);
        }
    }
    let entry_name = display_index.short_name(ws, entry);
    let terminal = terminal_call
        .map(|call| call.name.clone())
        .or_else(|| steps.last().map(|step| step.callee.clone()))
        .unwrap_or_default();
    // The taint id depends only on entry / terminal / steps — NOT on the
    // (expensive, per-chain) name disambiguation below. When reopening a
    // single id (`show T:`), compute the id first and skip the
    // disambiguation for every non-matching candidate. This is what keeps
    // `show T:` from disambiguating every flow in the workspace just to
    // keep one — an O(flows × chain) sweep that hangs on wide/deep graphs.
    let taint_id = compute_taint_flow_id(&entry_name, &terminal, &steps);
    if let Some(target) = flow_id_filter {
        if taint_id != target {
            return None;
        }
    }
    let func_ids: Vec<u32> = funcs.iter().map(|func| func.raw()).collect();
    let chain_display = display_index.disambiguated_names(ws, &funcs);
    let entry_kind = display_index.kind(ws, entry);
    let mut flow = InspectTaintFlow {
        taint_id,
        entry: entry_name,
        entry_kind,
        terminal,
        terminal_kind: terminal_kind.to_string(),
        precision: precision_label(precision).to_string(),
        func_ids,
        chain_display,
        steps,
        json_size_upper_bound: 0,
    };
    flow.json_size_upper_bound = calculate_inspect_taint_flow_json_upper_bound(&flow);
    Some(flow)
}

fn taint_step_for_edge(
    ws: &Workspace,
    display_index: &TaintDisplayIndex,
    record: &TaintedCallEdge,
) -> Option<InspectTaintStep> {
    if record.caller == record.callee {
        return None;
    }
    let (file, line, column) = format_span(&record.call_span, ws);
    Some(InspectTaintStep {
        caller: display_index.short_name(ws, record.caller),
        callee: display_index.short_name(ws, record.callee),
        file,
        line,
        column,
        kind: "propagation".to_string(),
        precision: precision_label(record.precision).to_string(),
        tainted_args: record
            .tainted_args
            .iter()
            .map(|arg| InspectTaintedArg {
                index: arg.index,
                value_text: arg.value_text.clone(),
                param_name: (!arg.param_name.is_empty()).then(|| arg.param_name.clone()),
            })
            .collect(),
    })
}

fn cached_taint_step_for_edge(
    ws: &Workspace,
    display_index: &TaintDisplayIndex,
    edge_steps: &ahash::AHashMap<u64, InspectTaintStep>,
    record: &TaintedCallEdge,
) -> Option<InspectTaintStep> {
    if record.trace_id != 0 {
        return edge_steps.get(&record.trace_id).cloned();
    }
    taint_step_for_edge(ws, display_index, record)
}

fn taint_step_for_terminal_call(
    ws: &Workspace,
    display_index: &TaintDisplayIndex,
    call: &TaintedCall,
    precision: bonsai_common::Precision,
) -> InspectTaintStep {
    let (file, line, column) = format_span(&call.call_span, ws);
    let mut tainted_args: Vec<InspectTaintedArg> = call
        .tainted_args
        .iter()
        .map(|arg| InspectTaintedArg {
            index: arg.index,
            value_text: arg.value_text.clone(),
            param_name: None,
        })
        .collect();
    if let Some(receiver) = call.tainted_receiver.as_deref() {
        tainted_args.push(InspectTaintedArg {
            index: usize::MAX,
            value_text: receiver.to_string(),
            param_name: Some("receiver".to_string()),
        });
    }
    InspectTaintStep {
        caller: display_index.short_name(ws, call.caller),
        callee: call.name.clone(),
        file,
        line,
        column,
        kind: terminal_kind_label(&call.kind).to_string(),
        precision: precision_label(precision).to_string(),
        tainted_args,
    }
}

fn trace_record_index_for_inspect(records: &[TaintedCallEdge]) -> ahash::AHashMap<u64, &TaintedCallEdge> {
    let mut by_id = ahash::AHashMap::default();
    for record in records {
        if record.trace_id != 0 {
            by_id.entry(record.trace_id).or_insert(record);
        }
    }
    by_id
}

fn edge_step_index_for_inspect(
    ws: &Workspace,
    display_index: &TaintDisplayIndex,
    records: &[TaintedCallEdge],
) -> ahash::AHashMap<u64, InspectTaintStep> {
    records
        .iter()
        .filter(|record| record.trace_id != 0)
        .filter_map(|record| {
            taint_step_for_edge(ws, display_index, record).map(|step| (record.trace_id, step))
        })
        .collect()
}

fn lineage_records_for_trace_id_inspect<'a>(
    by_id: &ahash::AHashMap<u64, &'a TaintedCallEdge>,
    trace_id: u64,
) -> Option<Vec<&'a TaintedCallEdge>> {
    let mut current = Some(trace_id);
    let mut lineage = Vec::new();
    let mut seen = ahash::AHashSet::default();
    while let Some(id) = current {
        if !seen.insert(id) {
            return None;
        }
        let record = *by_id.get(&id)?;
        lineage.push(record);
        current = record.parent_trace_id;
    }
    lineage.reverse();
    Some(lineage)
}

fn taint_flow_matches(
    ws: &Workspace,
    flow: &InspectTaintFlow,
    matcher: Option<&Matcher>,
    filters: InspectFilters<'_>,
    kind_filter: &[String],
) -> bool {
    if !taint_flow_matches_kind_filter(flow, kind_filter) {
        return false;
    }
    if let Some(matcher) = matcher {
        if !taint_flow_matches_query(flow, matcher) {
            return false;
        }
    }
    if let Some(file) = filters.file {
        if !flow
            .steps
            .iter()
            .any(|step| file_path_matches_filter(ws, &step.file, file))
        {
            return false;
        }
    }
    if let Some(in_fn) = filters.in_fn {
        if !flow
            .steps
            .iter()
            .any(|step| name_token_match(&step.caller, in_fn) || name_token_match(&step.callee, in_fn))
        {
            return false;
        }
    }
    if let Some(from) = filters.from {
        if !taint_flow_contains_needle_with_kind(flow, from, filters.from_kind) {
            return false;
        }
    }
    if let Some(to) = filters.to {
        if !taint_flow_contains_needle_with_kind(flow, to, filters.to_kind) {
            return false;
        }
    }
    true
}

fn taint_flow_matches_query(flow: &InspectTaintFlow, matcher: &Matcher) -> bool {
    matcher.is_match(&flow.taint_id)
        || matcher.is_match(&flow.entry)
        || matcher.is_match(&flow.terminal)
        || flow.chain_display.iter().any(|name| matcher.is_match(name))
        || flow.steps.iter().any(|step| {
            matcher.is_match(&step.caller)
                || matcher.is_match(&step.callee)
                || step.tainted_args.iter().any(|arg| {
                    matcher.is_match(&arg.value_text)
                        || arg
                            .param_name
                            .as_deref()
                            .is_some_and(|param| matcher.is_match(param))
                })
        })
}

fn taint_flow_matches_kind_filter(flow: &InspectTaintFlow, kind_filter: &[String]) -> bool {
    kind_filter.is_empty()
        || kind_filter
            .iter()
            .any(|kind| taint_flow_has_kind(flow, kind.as_str()))
}

fn taint_flow_has_kind(flow: &InspectTaintFlow, kind: &str) -> bool {
    match kind {
        "decl" => !flow.entry.is_empty() || !flow.chain_display.is_empty(),
        "call" => {
            flow.terminal_kind == "call"
                || flow
                    .steps
                    .iter()
                    .any(|step| matches!(step.kind.as_str(), "call" | "propagation"))
        }
        "write" => flow.terminal_kind == "write" || flow.steps.iter().any(|step| step.kind == "write"),
        "return" => flow.terminal_kind == "return" || flow.steps.iter().any(|step| step.kind == "return"),
        "propagation" => {
            flow.terminal_kind == "propagation" || flow.steps.iter().any(|step| step.kind == "propagation")
        }
        "arg" => flow.steps.iter().any(|step| !step.tainted_args.is_empty()),
        "read" | "var" => flow.steps.iter().any(|step| {
            step.tainted_args
                .iter()
                .any(|arg| !arg.value_text.trim().is_empty())
        }),
        "string" => flow.steps.iter().any(|step| {
            step.tainted_args
                .iter()
                .any(|arg| looks_like_string_literal(&arg.value_text))
        }),
        // Raw taint traces do not currently preserve import, class,
        // decorator, or ref browse facts. Returning false keeps these
        // filters strict instead of inventing syntax facts from a
        // value-flow row.
        "import" | "class" | "decorator" | "ref" => false,
        _ => false,
    }
}

fn taint_flow_contains_needle_with_kind(
    flow: &InspectTaintFlow,
    needle: &str,
    kind: Option<FactKindFilter>,
) -> bool {
    match kind {
        None => taint_flow_contains_needle(flow, needle),
        Some(FactKindFilter::Decl) => {
            name_token_match(&flow.entry, needle)
                || flow
                    .chain_display
                    .iter()
                    .any(|name| name_token_match(name, needle))
                || flow.steps.iter().any(|step| {
                    name_token_match(&step.caller, needle)
                        || (step.kind == "propagation" && name_token_match(&step.callee, needle))
                })
        }
        Some(FactKindFilter::Call) => {
            (flow.terminal_kind == "call" && name_token_match(&flow.terminal, needle))
                || flow.steps.iter().any(|step| {
                    matches!(step.kind.as_str(), "call" | "propagation")
                        && name_token_match(&step.callee, needle)
                })
        }
        Some(FactKindFilter::Read) => tainted_arg_values_match(flow, needle),
        Some(FactKindFilter::Write) => {
            (flow.terminal_kind == "write" && name_token_match(&flow.terminal, needle))
                || flow.steps.iter().any(|step| {
                    step.kind == "write"
                        && (name_token_match(&step.callee, needle)
                            || step
                                .tainted_args
                                .iter()
                                .any(|arg| name_token_match(&arg.value_text, needle)))
                })
        }
        Some(FactKindFilter::Arg) => flow.steps.iter().any(|step| {
            step.tainted_args.iter().any(|arg| {
                name_token_match(&arg.value_text, needle)
                    || arg
                        .param_name
                        .as_deref()
                        .is_some_and(|param| name_token_match(param, needle))
            })
        }),
        Some(FactKindFilter::StringLit) => flow.steps.iter().any(|step| {
            step.tainted_args.iter().any(|arg| {
                looks_like_string_literal(&arg.value_text) && name_token_match(&arg.value_text, needle)
            })
        }),
        Some(FactKindFilter::Import | FactKindFilter::Class) => false,
    }
}

fn taint_flow_contains_needle(flow: &InspectTaintFlow, needle: &str) -> bool {
    name_token_match(&flow.taint_id, needle)
        || (!matches!(flow.entry_kind, Some(DeclKind::Constructor)) && name_token_match(&flow.entry, needle))
        || name_token_match(&flow.terminal, needle)
        || flow.steps.iter().any(|step| {
            let step_name_match = taint_step_exposes_untyped_name(step)
                && (name_token_match(&step.caller, needle) || name_token_match(&step.callee, needle));
            step_name_match
                || step.tainted_args.iter().any(|arg| {
                    name_token_match(&arg.value_text, needle)
                        || arg
                            .param_name
                            .as_deref()
                            .is_some_and(|param| name_token_match(param, needle))
                })
        })
}

fn taint_step_exposes_untyped_name(step: &InspectTaintStep) -> bool {
    !step.tainted_args.is_empty() || step.kind != "propagation"
}

fn tainted_arg_values_match(flow: &InspectTaintFlow, needle: &str) -> bool {
    flow.steps.iter().any(|step| {
        step.tainted_args
            .iter()
            .any(|arg| name_token_match(&arg.value_text, needle))
    })
}

fn looks_like_string_literal(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < 2 {
        return false;
    }
    let literal = trimmed.trim_start_matches(['r', 'R', 'b', 'B', 'f', 'F', 'u', 'U']);
    matches!(
        (literal.as_bytes().first(), literal.as_bytes().last()),
        (Some(b'\''), Some(b'\'')) | (Some(b'"'), Some(b'"')) | (Some(b'`'), Some(b'`'))
    )
}

fn dedup_taint_flows(flows: &mut Vec<InspectTaintFlow>) {
    let mut seen = ahash::AHashSet::default();
    flows.retain(|flow| seen.insert(flow.taint_id.clone()));
}

/// Callgraph resolution can discover the same exact FuncId path through
/// several equivalent evidence edges (for example, an override edge plus an
/// inherited receiver edge). The compiler-identity `F:` id proves those
/// rendered paths are the same; retain the first deterministic occurrence so
/// paging, summaries, and output size represent unique execution paths.
fn dedup_structural_flows(flows: &mut Vec<InspectFlowRendered>) {
    let mut seen = ahash::AHashSet::with_capacity(flows.len());
    flows.retain(|flow| seen.insert(flow.flow_id.clone()));
}

fn precision_label(precision: bonsai_common::Precision) -> &'static str {
    match precision {
        bonsai_common::Precision::Exact => "exact",
        bonsai_common::Precision::Narrowed => "narrowed",
        bonsai_common::Precision::OverApproximate => "over-approximate",
        bonsai_common::Precision::Unknown => "unknown",
    }
}

fn terminal_kind_label(kind: &TaintedCallKind) -> &'static str {
    match kind {
        TaintedCallKind::Call => "call",
        TaintedCallKind::Write => "write",
        TaintedCallKind::Return => "return",
    }
}

/// Build a `ChainCache` respecting the global `--no-cache` setting.
/// Returns a cache with memoization enabled unless the user opted out.
fn build_chain_cache(
    ws: &Workspace,
    resolved_graph: Option<std::sync::Arc<bonsai_callgraph::ResolvedCallGraph>>,
) -> ChainCache<'_> {
    match (*NO_CACHE.get().unwrap_or(&false), resolved_graph) {
        (true, Some(graph)) => ChainCache::without_cache_with_resolved_graph(ws, graph),
        (false, Some(graph)) => ChainCache::with_resolved_graph(ws, graph),
        (true, None) => ChainCache::without_cache(ws),
        (false, None) => ChainCache::new(ws),
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // Serde skip_serializing_if requires `fn(&T) -> bool`.
fn is_zero_usize(n: &usize) -> bool {
    usize::eq(n, &0)
}

fn semantic_direct_callers(
    ws: &Workspace,
    graph: &bonsai_callgraph::ResolvedCallGraph,
    target: bonsai_common::FuncId,
) -> Vec<RefOut> {
    let global = ws.compiler_header_index();
    let target_name = global
        .decl_of(bonsai_common::SymbolId::new(target.raw()))
        .map(|decl| decl.name.clone())
        .unwrap_or_default();
    let mut callers: Vec<RefOut> = graph
        .callers_of(target)
        .filter(|edge| edge.precision.is_semantic())
        .filter_map(|edge| {
            let caller_decl = ws.exact_decl(bonsai_common::SymbolId::new(edge.from.raw()))?;
            let span =
                find_call_span_to_func_uncached(ws, &caller_decl, target, &target_name).unwrap_or(edge.span);
            let (file, line, column) = format_span(&span, ws);
            Some(RefOut {
                symbol: func_display_name(ws, edge.from),
                file,
                line,
                column,
                kind: edge_kind_label(edge.kind).to_string(),
                snippet: read_snippet(ws, &span),
            })
        })
        .collect();
    callers.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.column.cmp(&b.column))
            .then_with(|| a.symbol.cmp(&b.symbol))
    });
    callers.dedup_by(|a, b| {
        a.symbol == b.symbol && a.file == b.file && a.line == b.line && a.column == b.column
    });
    callers
}

fn semantic_callees(
    ws: &Workspace,
    graph: &bonsai_callgraph::ResolvedCallGraph,
    source: bonsai_common::FuncId,
) -> Vec<String> {
    let mut callees: Vec<String> = graph
        .callees_of(source)
        .filter(|edge| edge.precision.is_semantic())
        .map(|edge| func_display_name(ws, edge.to))
        .filter(|name| !name.is_empty())
        .collect();
    callees.sort();
    callees.dedup();
    callees
}

fn edge_kind_label(kind: bonsai_callgraph::EdgeKind) -> &'static str {
    match kind {
        bonsai_callgraph::EdgeKind::Direct => "call",
        bonsai_callgraph::EdgeKind::Virtual => "virtual-call",
        bonsai_callgraph::EdgeKind::Indirect => "indirect-call",
        bonsai_callgraph::EdgeKind::Unknown => "unknown-call",
    }
}

fn sorted_hit_counts_json(hits: &[HitOut]) -> serde_json::Value {
    let mut by_kind: ahash::AHashMap<String, usize> = ahash::AHashMap::new();
    for h in hits {
        *by_kind.entry(h.kind.clone()).or_insert(0) += 1;
    }
    let mut by_kind_sorted: Vec<(String, usize)> = by_kind.into_iter().collect();
    by_kind_sorted.sort_by(|a, b| a.0.cmp(&b.0));
    serde_json::Value::Object(
        by_kind_sorted
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::from(v)))
            .collect(),
    )
}

fn inspect_json_page_units(report: &InspectReport) -> Vec<InspectJsonPageUnit<'_>> {
    let flow_units = report
        .decl_hits
        .iter()
        .map(|hit| hit.flows.len().max(1))
        .sum::<usize>()
        + report
            .hits
            .iter()
            .map(|hit| hit.flows.len().max(1))
            .sum::<usize>();
    let mut units = Vec::with_capacity(flow_units + report.taint_flows.len());
    for (index, hit) in report.decl_hits.iter().enumerate() {
        if hit.flows.is_empty() {
            units.push(InspectJsonPageUnit::Decl {
                index,
                hit,
                flow: None,
            });
        } else {
            units.extend(hit.flows.iter().map(|flow| InspectJsonPageUnit::Decl {
                index,
                hit,
                flow: Some(flow),
            }));
        }
    }
    for (index, hit) in report.hits.iter().enumerate() {
        if hit.flows.is_empty() {
            units.push(InspectJsonPageUnit::Hit {
                index,
                hit,
                flow: None,
            });
        } else {
            units.extend(hit.flows.iter().map(|flow| InspectJsonPageUnit::Hit {
                index,
                hit,
                flow: Some(flow),
            }));
        }
    }
    units.extend(report.taint_flows.iter().map(InspectJsonPageUnit::Taint));
    units
}

fn paged_decl_hit(hit: &InspectOut, flow: Option<&InspectFlowRendered>) -> InspectOut {
    let mut page = InspectOut {
        symbol: hit.symbol.clone(),
        kind: hit.kind.clone(),
        file: hit.file.clone(),
        line: hit.line,
        column: hit.column,
        params: hit.params.clone(),
        direct_callers: hit.direct_callers.clone(),
        callees: hit.callees.clone(),
        graph_flows_evaluated: hit.graph_flows_evaluated,
        flows: flow.into_iter().cloned().collect(),
        groups: Vec::new(),
        summary: hit.summary.clone(),
    };
    page.groups = group_flows_by_suffix(&page.flows);
    page
}

fn paged_occurrence_hit(hit: &HitOut, flow: Option<&InspectFlowRendered>) -> HitOut {
    let mut page = HitOut {
        kind: hit.kind.clone(),
        text: hit.text.clone(),
        file: hit.file.clone(),
        line: hit.line,
        column: hit.column,
        in_function: hit.in_function.clone(),
        chains_preview: hit.chains_preview.clone(),
        flows: flow.into_iter().cloned().collect(),
        groups: Vec::new(),
        from_match: hit.from_match.clone(),
        to_match: hit.to_match.clone(),
    };
    page.groups = group_flows_by_suffix(&page.flows);
    page
}

fn inspect_json_unit_cost(unit: &InspectJsonPageUnit<'_>) -> u64 {
    serde_json::to_string(unit)
        .map(|s| s.len() as u64 + 64)
        .unwrap_or(512)
}

/// Filter-signature hash for `inspect`. Shared between the JSON
/// and text paths so a cursor minted in one resolves in the other.
fn inspect_filters_hash(pattern: Option<&str>, is_regex: bool) -> u64 {
    paging::hash_filters(&[
        ("query", pattern.unwrap_or("")),
        ("regex", if is_regex { "1" } else { "0" }),
    ])
}

/// Drop every flow from a report whose `flow_id` doesn't equal
/// `target_flow_id`, then drop any `InspectOut` / `HitOut` that has
/// no remaining flows. Simple in-place pass — the filter happens
/// after enumeration because that's where `flow_id`s exist. Also
/// recomputes the summary so counts and kind breakdown reflect
/// only the kept hits (otherwise the top-of-output "by kind" line
/// lies about what's still shown).
fn apply_flow_id_filter(report: &mut InspectReport, target_flow_id: &str) {
    for decl_hit in &mut report.decl_hits {
        decl_hit.flows.retain(|flow| flow.flow_id == target_flow_id);
        decl_hit.groups = group_flows_by_suffix(&decl_hit.flows);
    }
    report.decl_hits.retain(|decl_hit| !decl_hit.flows.is_empty());
    for occurrence_hit in &mut report.hits {
        occurrence_hit.flows.retain(|flow| flow.flow_id == target_flow_id);
        occurrence_hit.groups = group_flows_by_suffix(&occurrence_hit.flows);
    }
    report
        .hits
        .retain(|occurrence_hit| !occurrence_hit.flows.is_empty());
    report.taint_flows.retain(|flow| flow.taint_id == target_flow_id);
    rebuild_report_summary(report);
}

/// Drop every flow from a report that's not a member of the given
/// group, then drop any `InspectOut` / `HitOut` that has no
/// remaining flows. Mirror of [`apply_flow_id_filter`], one level
/// up: a group selects a whole suffix-cluster.
fn apply_group_id_filter(report: &mut InspectReport, target_group_id: &str) {
    // Closure: given a decl/hit's groups, collect the flow_ids of
    // every member that belongs to a group with the target id.
    // Implemented as a closure so the same loop body works for
    // both `decl_hits` and `hits` without a second helper fn.
    let collect_member_flow_ids = |groups: &[InspectFlowGroup]| -> ahash::AHashSet<String> {
        groups
            .iter()
            .filter(|group| group.group_id == target_group_id)
            .flat_map(|group| group.member_flow_ids.iter().cloned())
            .collect()
    };
    for decl_hit in &mut report.decl_hits {
        let flow_ids_to_keep = collect_member_flow_ids(&decl_hit.groups);
        decl_hit
            .flows
            .retain(|flow| flow_ids_to_keep.contains(&flow.flow_id));
        decl_hit.groups = group_flows_by_suffix(&decl_hit.flows);
    }
    report.decl_hits.retain(|decl_hit| !decl_hit.flows.is_empty());
    for occurrence_hit in &mut report.hits {
        let flow_ids_to_keep = collect_member_flow_ids(&occurrence_hit.groups);
        occurrence_hit
            .flows
            .retain(|flow| flow_ids_to_keep.contains(&flow.flow_id));
        occurrence_hit.groups = group_flows_by_suffix(&occurrence_hit.flows);
    }
    report
        .hits
        .retain(|occurrence_hit| !occurrence_hit.flows.is_empty());
    // Raw taint rows do not have structural suffix-group membership.
    // Keep `--group` strict by clearing them instead of showing rows
    // unrelated to the requested structural group id.
    report.taint_flows.clear();
    rebuild_report_summary(report);
}

/// Recompute the report summary after a filter pass so the top-of-
/// output counts + `by kind:` line match the kept hits. Shared
/// between the flow-id and group-id filters.
fn rebuild_report_summary(report: &mut InspectReport) {
    report.summary.total_decl_hits = report.decl_hits.len();
    report.summary.total_hits = report.hits.len();
    report.summary.total_taint_flows = report.taint_flows.len();
    report.summary.hit_counts_by_kind = sorted_hit_counts_json(&report.hits);
    refresh_inspect_completeness(report);
}

/// Assign final human-facing flow labels once the report has its
/// filtered shape. Structural flow rendering intentionally uses
/// `FLOW_LABEL_PLACEHOLDER` in annotations so duplicate discoveries of
/// the same stable `F:` id cannot produce conflicting labels and this
/// pass never has to parse or rewrite an already-rendered label.
fn finalize_report_flow_labels(report: &mut InspectReport) {
    let order = final_flow_label_order(report);
    if order.is_empty() {
        return;
    }

    let chains: Vec<Vec<String>> = order.iter().map(|(_, chain)| chain.clone()).collect();
    let mut next_number = 1_u32;
    let labels = compute_flow_labels_from(&chains, &mut next_number);
    let mut label_by_id: ahash::AHashMap<String, (u32, String)> = ahash::AHashMap::default();
    for ((flow_id, _), label) in order.into_iter().zip(labels.into_iter()) {
        let ordinal = label_by_id.len() as u32 + 1;
        label_by_id.insert(flow_id, (ordinal, label));
    }

    for decl_hit in &mut report.decl_hits {
        assign_flow_labels(&mut decl_hit.flows, &label_by_id);
        decl_hit.groups = group_flows_by_suffix(&decl_hit.flows);
    }
    for hit in &mut report.hits {
        assign_flow_labels(&mut hit.flows, &label_by_id);
        hit.groups = group_flows_by_suffix(&hit.flows);
    }
}

fn final_flow_label_order(report: &InspectReport) -> Vec<(String, Vec<String>)> {
    let mut seen: ahash::AHashSet<String> = ahash::AHashSet::default();
    let mut order: Vec<(String, Vec<String>)> = Vec::new();
    for decl_hit in &report.decl_hits {
        for flow in &decl_hit.flows {
            if seen.insert(flow.flow_id.clone()) {
                order.push((flow.flow_id.clone(), flow.chain.clone()));
            }
        }
    }
    for hit in &report.hits {
        for flow in &hit.flows {
            if seen.insert(flow.flow_id.clone()) {
                order.push((flow.flow_id.clone(), flow.chain.clone()));
            }
        }
    }
    order
}

fn assign_flow_labels(
    flows: &mut [InspectFlowRendered],
    label_by_id: &ahash::AHashMap<String, (u32, String)>,
) {
    for flow in flows {
        let Some((flow_number, flow_label)) = label_by_id.get(&flow.flow_id) else {
            continue;
        };
        flow.flow_number = *flow_number;
        flow.flow_label.clone_from(flow_label);
        for function in &mut flow.functions {
            for line in &mut function.lines {
                if let Some(annotation) = line.annotation.as_mut() {
                    *annotation = fill_flow_label_placeholder(annotation, flow_label);
                }
            }
        }
    }
}

fn fill_flow_label_placeholder(annotation: &str, flow_label: &str) -> String {
    debug_assert!(
        !annotation.contains("[FLOW ") || annotation.contains(FLOW_LABEL_PLACEHOLDER),
        "structural inspect flow annotation was rendered with a concrete label before final assignment: {annotation}"
    );
    if annotation.contains(FLOW_LABEL_PLACEHOLDER) {
        annotation.replace(FLOW_LABEL_PLACEHOLDER, flow_label)
    } else {
        annotation.to_string()
    }
}

fn apply_semantic_flow_stats(summary: &mut InspectReportSummary, stats: InspectSemanticFlowStats) {
    summary.semantic_flow_entry_queries = stats.entry_queries;
    summary.semantic_flow_backend_counts = stats.backend_counts;
    summary.semantic_flow_cache_hits = stats.cache_hits;
    summary.semantic_flow_cache_misses = stats.cache_misses;
    summary.semantic_flow_target_cut_size = stats.target_cut_size;
    summary.semantic_flow_fallback_reasons = stats.fallback_reasons;
    summary.semantic_flow_incomplete_reasons = stats.incomplete_reasons;
}

fn refresh_inspect_completeness(report: &mut InspectReport) {
    let mut reasons = Vec::new();
    for reason in &report.summary.semantic_flow_incomplete_reasons {
        reasons.push(format!("inspect semantic flow query incomplete: {reason}"));
    }
    for reason in &report.summary.graph_flow_incomplete_reasons {
        reasons.push(format!("inspect graph flow query incomplete: {reason}"));
    }
    reasons.sort();
    reasons.dedup();
    report.analysis_complete = reasons.is_empty();
    report.analysis_incomplete_reasons = reasons;
}

fn extend_unique_sorted(out: &mut Vec<String>, items: &[String]) {
    out.extend(items.iter().filter(|item| !item.trim().is_empty()).cloned());
    out.sort();
    out.dedup();
}

/// Concrete view mode after [`InspectView::Auto`] has been resolved
/// against the actual flow count. Only these two shapes reach the
/// renderers — Auto never does.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ResolvedView {
    Trace,
    Grouped,
}

/// Resolve `InspectView::Auto` against the total rendered-flow count
/// in the report. Trace stays for small result sets where the
/// GROUP-wrapping tax isn't paid off; Grouped kicks in past the
/// threshold where repeated suffixes become visual noise.
fn resolve_view(render: &InspectRenderOptions, report: &InspectReport) -> ResolvedView {
    match render.view {
        InspectView::Trace => ResolvedView::Trace,
        InspectView::Grouped => ResolvedView::Grouped,
        InspectView::Auto => {
            let total_rendered_flows: usize = report
                .decl_hits
                .iter()
                .map(|decl_hit| decl_hit.flows.len())
                .chain(
                    report
                        .hits
                        .iter()
                        .map(|occurrence_hit| occurrence_hit.flows.len()),
                )
                .sum();
            if total_rendered_flows > GROUPED_VIEW_AUTO_THRESHOLD {
                ResolvedView::Grouped
            } else {
                ResolvedView::Trace
            }
        }
    }
}

fn format_kind_filter(kinds: &[String]) -> String {
    kinds.join(", ")
}

/// Render an `InspectReport` to stdout in text mode and return the
/// `PageInfo` the caller writes into the footer. Owns header chrome,
/// per-decl / per-hit blocks, and the final paging math; delegates
/// per-flow rendering to `render_flow_block` / `render_group_block`.
fn render_inspect_header(u: &Ui, report: &InspectReport, view: ResolvedView) {
    cli_println!(
        "{} {} {} {} {}{}{}",
        u.label("inspect"),
        display_query_colored(&report.query, report.regex),
        u.dim("—"),
        u.name(&report.summary.total_decl_hits.to_string()),
        u.dim("decl hit(s),"),
        format!(
            " {} {}",
            u.name(&report.summary.total_hits.to_string()),
            u.dim("other hit(s)")
        ),
        if report.summary.total_taint_flows > 0 {
            format!(
                ", {} {}",
                u.name(&report.summary.total_taint_flows.to_string()),
                u.dim("taint flow(s)")
            )
        } else {
            String::new()
        },
    );
    if view == ResolvedView::Grouped {
        // Make the view mode visible at the top of the output so
        // the reader knows group ids + shared-suffix blocks are
        // coming instead of per-flow blocks. Especially matters
        // for `--view auto` users who didn't explicitly ask for it.
        cli_println!("  {} grouped", u.dim("view:"));
    }
    if !report.kind_filter.is_empty() {
        cli_println!(
            "  {} {}",
            u.dim("kinds:"),
            format_kind_filter(&report.kind_filter)
        );
    }
    if let Some(by_kind_obj) = report.summary.hit_counts_by_kind.as_object() {
        if !by_kind_obj.is_empty() {
            let mut kind_count_parts: Vec<String> = by_kind_obj
                .iter()
                .map(|(kind, count)| format!("{}: {}", u.kind(kind), u.name(&count.to_string())))
                .collect();
            kind_count_parts.sort();
            cli_println!("  {} {}", u.dim("by kind:"), kind_count_parts.join(", "));
        }
    }
    if report.summary.semantic_flow_entry_queries > 0 {
        let backend_counts = report
            .summary
            .semantic_flow_backend_counts
            .iter()
            .map(|(backend, count)| format!("{backend} {count}"))
            .collect::<Vec<_>>()
            .join(" · ");
        let target_cut = report
            .summary
            .semantic_flow_target_cut_size
            .map(|size| format!(" · target cut {size}"))
            .unwrap_or_default();
        cli_println!(
            "  {} {} entries · cache {} hit / {} miss · backends {}{}",
            u.dim("semantic flow:"),
            report.summary.semantic_flow_entry_queries,
            report.summary.semantic_flow_cache_hits,
            report.summary.semantic_flow_cache_misses,
            backend_counts,
            target_cut
        );
    }
    if !report.analysis_complete {
        let reasons = if report.analysis_incomplete_reasons.is_empty() {
            "unknown reason".to_string()
        } else {
            report.analysis_incomplete_reasons.join("; ")
        };
        cli_println!("  {} {}", u.warn("analysis incomplete:"), u.dim(&reasons));
    }
    for reason in &report.summary.semantic_flow_fallback_reasons {
        cli_println!("  {}", u.dim(&format!("[semantic-flow] {reason}")));
    }
}

struct InspectPageContext<'a> {
    ws: &'a Workspace,
    ui: &'a Ui,
    report: &'a InspectReport,
    render: &'a InspectRenderOptions,
    view: ResolvedView,
    flowless_hits: &'a [&'a HitOut],
    folded_order: &'a [&'a InspectFlowRendered],
    taint_units: usize,
    structural_base: usize,
    total_decls: usize,
    total_units: usize,
    page_starts: &'a [usize],
    start_offset: usize,
    budget_bytes: Option<u64>,
    unit_budget_bytes: Option<u64>,
    filters_hash: u64,
    paging_info: paging::PageInfo,
}

fn render_inspect_page(
    context: InspectPageContext<'_>,
    unit_full_cost: &impl Fn(usize) -> u64,
    unit_compact_cost: &impl Fn(usize) -> u64,
) -> paging::PageInfo {
    let InspectPageContext {
        ws,
        ui: u,
        report,
        render,
        view,
        flowless_hits,
        folded_order,
        taint_units,
        structural_base,
        total_decls,
        total_units,
        page_starts,
        start_offset,
        budget_bytes,
        unit_budget_bytes,
        filters_hash,
        mut paging_info,
    } = context;
    const HITS_ROW_AVG_BYTES: u64 = 220;
    const HITS_TABLE_BUDGET_PCT: u64 = 10;
    let bytes_before_payload = out_count::bytes();

    // Determine which units will render on THIS page (simulate).
    // Used to build a per-page OCCURRENCE HITS table that only
    // shows hits whose flows appear on this page. Page 1's table
    // covers page 1's flows; page 2's table covers page 2's
    // flows — the reader always has a local index for the blocks
    // they're looking at.
    let page_end_unit: usize = {
        let next_start = page_starts
            .iter()
            .copied()
            .find(|&s| s > start_offset)
            .unwrap_or(total_units);
        next_start
    };
    let taint_start = start_offset.min(taint_units);
    let taint_end = page_end_unit.min(taint_units);
    let page_taint_flows = &report.taint_flows[taint_start..taint_end];
    if !page_taint_flows.is_empty() {
        render_taint_flows_table(u, page_taint_flows);
        if should_render_raw_taint_bodies(render, total_units.saturating_sub(structural_base)) {
            // Raw T: drilldowns can contain very large source bodies. Under
            // a token budget render the exact chain/step evidence compactly;
            // `--all` retains the full source-body transcript.
            render_raw_taint_flow_bodies(
                ws,
                u,
                page_taint_flows,
                taint_start,
                render.compact || budget_bytes.is_some(),
            );
        }
    }

    let page_flow_ids: ahash::AHashSet<String> = {
        let mut ids = ahash::AHashSet::new();
        for unit_index in start_offset..page_end_unit {
            if unit_index < structural_base {
                continue;
            }
            let structural_index = unit_index - structural_base;
            if structural_index < total_decls {
                for f in &report.decl_hits[structural_index].flows {
                    ids.insert(f.flow_id.clone());
                }
            } else {
                ids.insert(folded_order[structural_index - total_decls].flow_id.clone());
            }
        }
        ids
    };
    // Flow-less syntax facts are first-class pageable units. Flow-associated
    // hits are a compact index for structural blocks on this page; their full
    // match-point details are also rendered with those blocks.
    let flowless_page_start = start_offset.max(taint_units).min(structural_base);
    let flowless_page_end = page_end_unit.max(taint_units).min(structural_base);
    let mut page_hits: Vec<(&HitOut, bool)> = flowless_hits
        [flowless_page_start - taint_units..flowless_page_end - taint_units]
        .iter()
        .map(|hit| (*hit, true))
        .collect();
    if !render.structural_drilldown {
        page_hits.extend(
            report
                .hits
                .iter()
                .filter(|hit| {
                    !hit.flows.is_empty()
                        && hit.flows.iter().any(|flow| page_flow_ids.contains(&flow.flow_id))
                })
                .map(|hit| (hit, false)),
        );
    }

    // OCCURRENCE HITS table — per-page, filtered to the flows
    // rendered on THIS page. Every hit in this table points at a
    // FLOW block that appears below.
    if !page_hits.is_empty() {
        cli_println!();
        cli_println!("{}", u.heading("══ OCCURRENCE HITS"));
        let show_from_column = page_hits.iter().any(|(hit, _)| hit.from_match.is_some());
        let show_to_column = page_hits.iter().any(|(hit, _)| hit.to_match.is_some());
        let mut table_headers: Vec<&str> = vec!["flow", "kind", "location", "in"];
        if show_from_column {
            table_headers.push("from");
        }
        if show_to_column {
            table_headers.push("to");
        }
        table_headers.push("text");
        let mut hits_table = u.table(&table_headers);
        let hits_budget_bytes = budget_bytes.map(|b| (b * HITS_TABLE_BUDGET_PCT) / 100);
        let mut rendered_hits = 0usize;
        let mut rendered_optional_hits = 0usize;
        for (hit, required_page_unit) in &page_hits {
            if !required_page_unit
                && hits_budget_bytes.is_some_and(|budget| {
                    (rendered_optional_hits as u64).saturating_mul(HITS_ROW_AVG_BYTES) >= budget
                })
            {
                continue;
            }
            let location = format!("{}:{}:{}", short_file(&hit.file), hit.line, hit.column);
            let enclosing = hit.in_function.clone().unwrap_or_else(|| "—".into());
            let text_preview = truncate(&hit.text, 80);
            // Restrict the label list to the flows shown on THIS
            // page. A hit that belongs to two flows (one on this
            // page, one on a later page) only shows the on-page
            // label; the reader never sees a label for a block
            // they can't find below.
            let flow_labels = {
                let labels: Vec<String> = hit
                    .flows
                    .iter()
                    .filter(|flow| page_flow_ids.contains(&flow.flow_id))
                    .map(|flow| flow.flow_label.clone())
                    .collect();
                if labels.is_empty() {
                    "—".to_string()
                } else {
                    labels.join(", ")
                }
            };
            let mut row = vec![
                Cell::new(u.annotation(&flow_labels)),
                Cell::new(u.annotation(&hit.kind)),
                Cell::new(u.path(&location)),
                Cell::new(u.kind(&enclosing)),
            ];
            if show_from_column {
                row.push(Cell::new(format_filter_match_cell(u, hit.from_match.as_ref())));
            }
            if show_to_column {
                row.push(Cell::new(format_filter_match_cell(u, hit.to_match.as_ref())));
            }
            row.push(Cell::new(u.name(&text_preview)));
            hits_table.add_row(row);
            rendered_hits += 1;
            if !required_page_unit {
                rendered_optional_hits += 1;
            }
        }
        cli_println!("{hits_table}");
        if rendered_hits < page_hits.len() {
            let skipped = page_hits.len() - rendered_hits;
            cli_println!(
                "{}",
                u.dim(&format!(
                    "[{skipped} flow-associated hit summary row(s) omitted from this page; every match point remains in the flow blocks below]",
                ))
            );
        }
    }

    // After-table anchor so the structural unit loop measures only the
    // payload it emits. Taint and flow-less-hit units were already priced by
    // the common page simulator and rendered above.
    let bytes_before_units = out_count::bytes();
    let emitted_so_far = |anchor: u64| (out_count::bytes() as u64).saturating_sub(anchor);
    let fits = |cost: u64| -> bool {
        unit_budget_bytes.is_none_or(|b| emitted_so_far(bytes_before_units as u64) + cost <= b)
    };
    // Walk the unit stream from `start_offset`. Policy:
    //
    //   1. Full render preferred — pack as many expanded flows per
    //      page as fit.
    //   2. When a flow's full render won't fit the REMAINING budget
    //      on this page, defer it to the next page (one expanded
    //      flow alone is a valid page).
    //   3. Compact is reserved for the pathological case where a
    //      SINGLE flow is larger than the ENTIRE budget (not just
    //      the remaining slice). Only then do we downgrade its
    //      render, on its own page, so the user sees chain shape
    //      rather than a dead page.
    //
    // Key difference from the old hybrid: compact isn't a
    // "squeeze in on this page" tool, it's a "too big for any
    // page" tool. Users walking pages get the full source bodies
    // in almost every case.
    let special_page_end = page_end_unit.min(structural_base);
    let mut unit_cursor = if start_offset < structural_base {
        special_page_end
    } else {
        start_offset
    };
    let mut rendered_units = 0usize;
    let mut compact_fallback_used = false;
    // Strict cap measured against the render budget after the
    // chrome reserve. The footer/truncation hints are emitted after
    // the live unit walk, so allowing payload to consume the full
    // stated budget can still print `tokens > budget` by a handful
    // of footer tokens. Keep the same reserve used by the
    // simulator as the absolute payload ceiling.
    let strict_budget_bytes = budget_bytes;
    let strict_emitted = || emitted_so_far(bytes_before_payload as u64);
    let strict_remaining =
        || -> Option<u64> { strict_budget_bytes.map(|b| b.saturating_sub(strict_emitted())) };
    let first_unit = unit_cursor;
    for unit_index in first_unit..page_end_unit {
        let is_first_on_page = rendered_units == 0;
        // Budget-exhaustion breaks only apply after the first unit.
        // A page must always advance the cursor by at least one unit
        // (rendered, compact, or a stub) — when the taint/hits tables
        // consume the whole budget before any unit renders, breaking
        // here minted a next-cursor equal to this page's own start:
        // an infinite pagination loop, with numeric page walkers
        // silently skipping the never-rendered units.
        if !is_first_on_page {
            if let Some(b) = unit_budget_bytes {
                if emitted_so_far(bytes_before_units as u64) >= b {
                    break;
                }
            }
            if let Some(strict) = strict_budget_bytes {
                if strict_emitted() >= strict {
                    break;
                }
            }
        }
        let full_estimate = unit_full_cost(unit_index);
        let compact_estimate = unit_compact_cost(unit_index);
        let mut effective_render = render.clone();
        let fits_unit_slice = fits(full_estimate);
        let fits_strict_page = strict_remaining().is_none_or(|rem| full_estimate <= rem);
        if !fits_unit_slice || !fits_strict_page {
            if is_first_on_page {
                // Pre-render proactive check: even compact must
                // fit the strict remaining budget. If it doesn't,
                // emit a one-line "too large" stub so the user
                // knows the flow exists but can't fit at this
                // `--context`. This keeps total stdout strictly
                // within budget — no reactive cleanup needed.
                if let Some(rem) = strict_remaining() {
                    if compact_estimate > rem {
                        let structural_index = unit_index - structural_base;
                        let flow_id_label = if structural_index < total_decls {
                            report.decl_hits[structural_index]
                                .flows
                                .first()
                                .map(|f| f.flow_id.clone())
                                .unwrap_or_else(|| report.decl_hits[structural_index].symbol.clone())
                        } else {
                            folded_order[structural_index - total_decls].flow_id.clone()
                        };
                        let est_tokens = paging::bytes_to_tokens(full_estimate);
                        cli_println!();
                        cli_println!(
                            "{}",
                            u.dim(&format!(
                                "[{} too large for --context (~{} tokens needed) — pass --all or a larger --context to view]",
                                flow_id_label, est_tokens,
                            ))
                        );
                        // Treat as rendered for cursor purposes so
                        // the next page advances past it.
                        rendered_units += 1;
                        unit_cursor = unit_index + 1;
                        continue;
                    }
                }
                effective_render.compact = true;
                compact_fallback_used = true;
            } else {
                break;
            }
        }
        let structural_index = unit_index - structural_base;
        if structural_index < total_decls {
            let decl_hit = &report.decl_hits[structural_index];
            cli_println!();
            render_inspect_text(decl_hit, &effective_render, view);
        } else {
            let flow = folded_order[structural_index - total_decls];
            cli_println!();
            let header_name = flow
                .chain
                .last()
                .cloned()
                .unwrap_or_else(|| flow.flow_label.clone());
            let mut local_seen_bodies: BodySet = BodySet::default();
            render_flow_block(u, &effective_render, flow, &header_name, &mut local_seen_bodies);
            // Find the fold's match points for this flow by scanning
            // `report.hits` for entries whose flows list contains
            // this flow_id.
            if !render.structural_drilldown {
                let matches: Vec<FoldMatch<'_>> = report
                    .hits
                    .iter()
                    .filter(|hit| hit.flows.iter().any(|f| f.flow_id == flow.flow_id))
                    .map(|hit| FoldMatch {
                        kind: &hit.kind,
                        text: &hit.text,
                        file: &hit.file,
                        line: hit.line,
                        column: hit.column,
                    })
                    .collect();
                render_match_points(u, &matches);
            }
        }
        rendered_units += 1;
        unit_cursor = unit_index + 1;
    }
    if compact_fallback_used {
        cli_println!();
        cli_println!(
            "{}",
            u.dim("[some flow(s) above rendered in compact mode to fit --context; pass --all or a larger --context for full bodies]"),
        );
    }
    let units_fully_rendered = unit_cursor >= total_units;
    if !units_fully_rendered {
        let remaining = total_units - unit_cursor;
        cli_println!();
        cli_println!(
            "{}",
            u.dim(&format!(
                "[{remaining} inspect unit(s) not shown — context budget reached; pass --page {} or --all to continue]",
                paging_info.page_number + 1,
            ))
        );
    }

    // Page metadata counts canonical pageable units. Optional
    // flow-associated hit summary rows are chrome for their structural unit,
    // not independent rows; flow-less hits and taint rows are units and are
    // therefore reachable on later pages.
    let shown_units = unit_cursor.saturating_sub(start_offset);
    paging_info.shown_rows = shown_units as u64;
    paging_info.page_size = shown_units as u64;
    paging_info.start_offset = start_offset as u64;
    paging_info.total_rows = total_units as u64;
    let any_truncation = !units_fully_rendered;
    if any_truncation {
        paging_info.is_last = false;
        if paging_info.total_pages <= paging_info.page_number {
            paging_info.total_pages = paging_info.page_number + 1;
        }
        paging_info.next_cursor = Some(paging::cursor_id("inspect", filters_hash, unit_cursor as u64));
    } else {
        paging_info.is_last = true;
        paging_info.next_cursor = None;
    }
    let payload_bytes = if let Some(bytes) = page_cache::captured_bytes() {
        bytes as u64
    } else {
        (out_count::bytes() as u64).saturating_sub(bytes_before_payload as u64)
    };
    paging_info.tokens_used = paging::bytes_to_tokens(payload_bytes);
    render_paging_footer(&paging_info, "bonsai-ninja inspect <workspace>");
    paging_info
}

fn render_inspect_report_text(
    ws: &Workspace,
    report: &InspectReport,
    render: &InspectRenderOptions,
    paging_cfg: &paging::PagingConfig,
    pattern: Option<&str>,
    is_regex: bool,
) -> Result<paging::PageInfo> {
    let u = ui();
    let view = resolve_view(render, report);
    render_inspect_header(u, report, view);
    // Paginate over one lossless unit stream: raw taint rows, syntax hits
    // without a structural flow, declaration blocks, then unique folded
    // occurrence flows. Every independently visible result is therefore
    // reachable by walking `--page`; table previews are never hidden caps.
    let filters_hash = inspect_filters_hash(pattern, is_regex);
    let flowless_hits = report
        .hits
        .iter()
        .filter(|hit| hit.flows.is_empty())
        .collect::<Vec<_>>();
    let folded_order: Vec<&InspectFlowRendered> = collect_folded_flow_order(&report.hits);
    let taint_units = report.taint_flows.len();
    let structural_base = taint_units + flowless_hits.len();
    let total_decls = report.decl_hits.len();
    let total_units = structural_base + total_decls + folded_order.len();

    // Safety factor on full-body byte estimates. The raw estimate
    // already matches actual output to within ~20 %. A 1.2× cushion
    // covers per-line chrome (annotation
    // prefix, step number, indent) that `func_full_cost` doesn't
    // model exactly. Stored as numerator/denominator so we can
    // express fractional factors without rationals.
    const COST_SAFETY_NUM: u64 = 8;
    const COST_SAFETY_DEN: u64 = 5;
    // A flow/render unit carries more chrome than its source-body
    // bytes alone: FLOW headers, chain displays, match-point rows,
    // annotation prefixes, and owner context.
    // The per-function estimator intentionally stays cheap, so put
    // a floor on each unit. Without this, the planner could predict
    // one page while the live renderer stopped after a handful of
    // units, producing a next-page cursor with no stable page start.
    const UNIT_RENDER_FLOOR_BYTES: u64 = 1_600;
    let scale = |raw: u64| (raw * COST_SAFETY_NUM / COST_SAFETY_DEN).max(UNIT_RENDER_FLOOR_BYTES);
    // A broad raw-flow query can contain hundreds of thousands of exact
    // paths. Serializing every row just to estimate page boundaries made
    // rendering slower than the IDG closure itself. Compute one conservative
    // allocation-free cost per flow and reuse it for full/compact simulation,
    // page totals, and the live renderer. This changes presentation cost only;
    // every flow remains in the canonical pageable unit stream.
    let taint_unit_costs = report
        .taint_flows
        .iter()
        .map(|flow| scale(inspect_taint_flow_json_upper_bound(flow)))
        .collect::<Vec<_>>();
    fn func_full_cost(f: &InspectFunctionRendered) -> u64 {
        // Module path + def line + every body line. Mirrors what
        // `render_full_source_bodies` actually emits.
        let body: u64 = f.lines.iter().map(|l| (l.text.len() as u64) + 8).sum();
        (f.module_path.len() as u64) + (f.signature.len() as u64) + body + 64
    }
    let flow_full_cost = |flow: &InspectFlowRendered| -> u64 {
        // Chain header (`══` + name + chain display) + every
        // function in the chain.
        let chain_header = 64 + (flow.chain.iter().map(|n| n.len() as u64 + 4).sum::<u64>());
        chain_header + flow.functions.iter().map(func_full_cost).sum::<u64>()
    };
    let decl_full_cost = |decl: &InspectOut| -> u64 {
        let header = (decl.symbol.len() as u64) + (decl.file.len() as u64) + 32;
        header + decl.flows.iter().map(&flow_full_cost).sum::<u64>()
    };
    let unit_full_cost = |idx: usize| -> u64 {
        if idx < taint_units {
            return taint_unit_costs[idx];
        }
        let raw = if idx < structural_base {
            let hit = flowless_hits[idx - taint_units];
            (hit.text.len() + hit.file.len() + hit.kind.len() + 256) as u64
        } else {
            let structural_index = idx - structural_base;
            if structural_index < total_decls {
                decl_full_cost(&report.decl_hits[structural_index])
            } else {
                flow_full_cost(folded_order[structural_index - total_decls])
            }
        };
        scale(raw)
    };
    let unit_compact_cost = |idx: usize| -> u64 {
        if idx < taint_units {
            return taint_unit_costs[idx];
        }
        let raw = if idx < structural_base {
            let hit = flowless_hits[idx - taint_units];
            (hit.text.len() + hit.file.len() + hit.kind.len() + 256) as u64
        } else {
            let structural_index = idx - structural_base;
            if structural_index < total_decls {
                report.decl_hits[structural_index]
                    .flows
                    .iter()
                    .map(|f| 64 + (f.chain.len() as u64) * 80)
                    .sum::<u64>()
                    + 128
            } else {
                64 + (folded_order[structural_index - total_decls].chain.len() as u64) * 80
            }
        };
        scale(raw)
    };
    // Budget after a 12 % chrome reserve. Covers the closing
    // truncation hint + paging footer bytes that count toward
    // `out_count::bytes()` but aren't part of the per-unit
    // budget check, plus width-dependent table wrapping at common
    // terminal sizes.
    let budget_bytes = paging_cfg.effective_budget().map(|tokens| {
        let raw = tokens.saturating_mul(paging::BYTES_PER_TOKEN);
        raw.saturating_sub(raw * 12 / 100)
    });
    // Reserve a modest 12 % of budget for the OCCURRENCE HITS
    // table on each page. That's enough for ~25 rows at the
    // measured 200-byte-per-row cost, which covers most pages
    // (the per-page table only holds rows whose flows are on
    // the current page — typically 2-10 rows after the per-page
    // filter introduced earlier). Was 35 %; the over-reservation
    // capped pages at ~50 % budget fill — closing the gap so
    // pages now hit ~70-75 % of the stated budget.
    let unit_budget_bytes: Option<u64> = budget_bytes.map(|b| b - (b * 12 / 100));
    let page_starts: Vec<usize> = simulate_page_starts(
        total_units,
        unit_budget_bytes,
        unit_budget_bytes,
        &unit_full_cost,
        &unit_compact_cost,
    );
    let total_pages = page_starts.len().max(1);
    // Resolve the requested page → start_offset (stable).
    let requested_start_offset: usize = match &paging_cfg.page {
        paging::PageArg::First => page_starts.first().copied().unwrap_or(0),
        paging::PageArg::Number(n) => {
            let idx = (*n as usize).saturating_sub(1).min(total_pages.saturating_sub(1));
            page_starts.get(idx).copied().unwrap_or(0)
        }
        // Cursors are minted from the ACTUAL unit the previous render
        // stopped at (`unit_cursor`), which lands mid-page whenever the
        // real render outpaces `simulate_page_starts`' estimates. Resolve
        // against every unit offset — matching only simulated page starts
        // silently replayed page 1 whenever the two disagreed.
        paging::PageArg::Cursor(c) => paging::resolve_cursor_offset(
            c,
            "inspect",
            filters_hash,
            (0..=total_units).map(|offset| offset as u64),
        )? as usize,
        paging::PageArg::Next => {
            // `--page next` advances past the page recorded in the
            // last-cursor history; falls back to page 1 with no history.
            // The recorded cursor can sit mid-page (see Cursor arm), so
            // resolve it over unit offsets and advance to the first
            // simulated page start after it.
            paging::last_cursor("inspect", filters_hash)
                .and_then(|cur| {
                    (0..=total_units)
                        .find(|off| paging::cursor_id("inspect", filters_hash, *off as u64) == cur)
                        .map(|off| {
                            page_starts
                                .iter()
                                .copied()
                                .find(|&s| s > off)
                                .unwrap_or(total_units)
                        })
                })
                .unwrap_or_else(|| page_starts.first().copied().unwrap_or(0))
        }
    };
    // 1-based page number for display. Exact page starts get their
    // canonical number; a mid-page cursor-resume offset rounds UP to
    // the next page number so cursor-following readers always see the
    // number advance instead of repeating the page they just left.
    let page_number = (page_starts
        .iter()
        .take_while(|&&s| s < requested_start_offset)
        .count()
        + 1) as u64;
    let start_offset = requested_start_offset;
    // Persist this page's cursor so a subsequent `--page next` advances
    // from here, matching `paging::paginate`'s behavior.
    paging::write_last_cursor(
        "inspect",
        filters_hash,
        &paging::cursor_id("inspect", filters_hash, start_offset as u64),
    );
    // Estimate uncapped render size: sum every unit's full-cost
    // estimate (chain bodies + headers). Gives the user an honest
    // "the full inspect output would be ~N tokens if you passed
    // --all" figure in the footer.
    let total_uncapped_bytes: u64 = (0..total_units).map(&unit_full_cost).sum();
    let total_tokens_uncapped = paging::bytes_to_tokens(total_uncapped_bytes);
    let paging_info = paging::PageInfo {
        page_number,
        total_pages: total_pages as u64,
        page_size: 0,
        shown_rows: 0,
        total_rows: total_units as u64,
        budget: paging_cfg.effective_budget(),
        tokens_used: 0,
        cursor: paging::cursor_id("inspect", filters_hash, start_offset as u64),
        next_cursor: None,
        is_last: true,
        start_offset: start_offset as u64,
        total_tokens_uncapped,
    };
    Ok(render_inspect_page(
        InspectPageContext {
            ws,
            ui: u,
            report,
            render,
            view,
            flowless_hits: &flowless_hits,
            folded_order: &folded_order,
            taint_units,
            structural_base,
            total_decls,
            total_units,
            page_starts: &page_starts,
            start_offset,
            budget_bytes,
            unit_budget_bytes,
            filters_hash,
            paging_info,
        },
        &unit_full_cost,
        &unit_compact_cost,
    ))
}

/// Conservative serialized-size estimate for one raw inspect flow.
///
/// Paging uses this only as a presentation cost. Fixed object/field overheads
/// deliberately exceed serde_json punctuation, and string sizes account for
/// JSON escaping without allocating an intermediate serialized row.
fn inspect_taint_flow_json_upper_bound(flow: &InspectTaintFlow) -> u64 {
    flow.json_size_upper_bound
}

fn calculate_inspect_taint_flow_json_upper_bound(flow: &InspectTaintFlow) -> u64 {
    fn escaped_string_bytes(value: &str) -> u64 {
        // JSON's largest expansion is a one-byte control character written
        // as `\u00XX` (six bytes). Multiplying the UTF-8 byte length is a
        // deliberately loose upper bound, but makes planning O(1) per string
        // instead of rescanning every character in hundreds of thousands of
        // exact flow rows.
        (value.len() as u64).saturating_mul(6).saturating_add(2)
    }

    let mut bytes = 256
        + escaped_string_bytes(&flow.taint_id)
        + escaped_string_bytes(&flow.entry)
        + escaped_string_bytes(&flow.terminal)
        + escaped_string_bytes(&flow.terminal_kind)
        + escaped_string_bytes(&flow.precision);
    bytes += flow
        .chain_display
        .iter()
        .map(|value| escaped_string_bytes(value) + 1)
        .sum::<u64>();
    for step in &flow.steps {
        bytes += 192
            + escaped_string_bytes(&step.caller)
            + escaped_string_bytes(&step.callee)
            + escaped_string_bytes(&step.file)
            + escaped_string_bytes(&step.kind)
            + escaped_string_bytes(&step.precision);
        for argument in &step.tainted_args {
            bytes += 96 + escaped_string_bytes(&argument.value_text);
            if let Some(parameter) = argument.param_name.as_deref() {
                bytes += escaped_string_bytes(parameter);
            }
        }
    }
    bytes
}

/// Build the ordered, deduplicated list of folded occurrence flows
/// — first-seen order across `hits`. Mirrors what
/// `render_folded_occurrence_flows` would have built internally,
/// exposed here so the caller can reason about total unit count
/// for paging.
/// Simulate the live render loop to produce stable page boundaries.
/// Returns a list of unit indices where each page begins. Uses the
/// SAME fit logic as the real loop so `--page N` lands exactly
/// where the live render would have stopped page N-1.
///
/// Empty-budget case: every unit fits on page 1, returns `vec![0]`.
type UnitCostFn<'a> = dyn Fn(usize) -> u64 + 'a;

fn simulate_page_starts(
    total_units: usize,
    first_page_budget_bytes: Option<u64>,
    budget_bytes: Option<u64>,
    full_cost: &UnitCostFn<'_>,
    compact_cost: &UnitCostFn<'_>,
) -> Vec<usize> {
    if total_units == 0 {
        return vec![0];
    }
    let mut starts = vec![0usize];
    let mut unit_index = 0usize;
    while unit_index < total_units {
        let page_budget = if starts.len() == 1 {
            first_page_budget_bytes
        } else {
            budget_bytes
        };
        let Some(b) = page_budget else {
            return vec![0];
        };
        let mut emitted: u64 = 0;
        let mut rendered_on_page = 0usize;
        let mut next_unit_index = unit_index;
        while next_unit_index < total_units {
            if emitted >= b {
                break;
            }
            let cost = full_cost(next_unit_index);
            let is_first_on_page = rendered_on_page == 0;
            let unit_cost = if emitted + cost <= b {
                cost
            } else if is_first_on_page && cost > b {
                // The flow is bigger than the entire window — render
                // compact, on its own page.
                compact_cost(next_unit_index)
            } else {
                break;
            };
            emitted += unit_cost;
            rendered_on_page += 1;
            next_unit_index += 1;
        }
        if rendered_on_page == 0 {
            next_unit_index = (unit_index + 1).min(total_units);
        }
        if next_unit_index >= total_units {
            break;
        }
        starts.push(next_unit_index);
        unit_index = next_unit_index;
    }
    starts
}

fn collect_folded_flow_order(hits: &[HitOut]) -> Vec<&InspectFlowRendered> {
    struct Candidate<'a> {
        flow: &'a InspectFlowRendered,
        kind_rank: u8,
        discovery_index: usize,
    }

    let mut best_by_id: ahash::AHashMap<String, Candidate<'_>> = ahash::AHashMap::default();
    let mut discovery_index = 0usize;
    for hit in hits {
        let kind_rank = folded_flow_hit_kind_rank(&hit.kind);
        for flow in &hit.flows {
            let candidate = Candidate {
                flow,
                kind_rank,
                discovery_index,
            };
            match best_by_id.get_mut(&flow.flow_id) {
                Some(existing)
                    if (candidate.kind_rank, candidate.discovery_index)
                        < (existing.kind_rank, existing.discovery_index) =>
                {
                    *existing = candidate;
                }
                None => {
                    best_by_id.insert(flow.flow_id.clone(), candidate);
                }
                _ => {}
            }
            discovery_index += 1;
        }
    }
    let mut candidates: Vec<Candidate<'_>> = best_by_id.into_values().collect();
    candidates.sort_by(|a, b| {
        a.flow
            .flow_number
            .cmp(&b.flow.flow_number)
            .then(a.flow.flow_label.cmp(&b.flow.flow_label))
            .then(a.discovery_index.cmp(&b.discovery_index))
    });
    let order: Vec<&InspectFlowRendered> = candidates.into_iter().map(|candidate| candidate.flow).collect();
    order
}

fn folded_flow_hit_kind_rank(kind: &str) -> u8 {
    match kind {
        // If a call fact and its enclosing assignment both match the
        // same endpoint, render the direct call as the folded body
        // annotation. The assignment remains visible in match points.
        "call" => 0,
        "arg" => 1,
        "var" => 2,
        "string" => 3,
        "import" => 4,
        "decorator" => 5,
        "ref" => 6,
        _ => 7,
    }
}

fn render_taint_flows_table(u: &Ui, flows: &[InspectTaintFlow]) {
    cli_println!();
    cli_println!("{}", u.heading("══ TAINT FLOWS"));
    cli_println!(
        "  {}",
        u.dim("rulepack-free taint-engine paths containing this inspect query / filters")
    );
    let mut table = u.table(&["taint", "entry", "terminal", "location", "args", "chain"]);
    for flow in flows {
        table.add_row(vec![
            Cell::new(u.annotation(&flow.taint_id)),
            Cell::new(u.kind(&flow.entry)),
            Cell::new(u.name(&flow.terminal)),
            Cell::new(format_taint_terminal_location(flow)),
            Cell::new(format_taint_args(flow)),
            Cell::new(format_taint_chain(flow)),
        ]);
    }
    cli_println!("{table}");
}

fn should_render_raw_taint_bodies(render: &InspectRenderOptions, structural_units: usize) -> bool {
    !render.compact
        && render.group_id_filter.is_none()
        && (structural_units == 0
            || render
                .flow_id_filter
                .as_deref()
                .is_some_and(|id| id.starts_with("T:")))
}

fn render_raw_taint_flow_bodies(
    ws: &Workspace,
    u: &Ui,
    flows: &[InspectTaintFlow],
    first_flow_number: usize,
    compact: bool,
) {
    let render_opts = InspectRenderOptions {
        compact,
        ..InspectRenderOptions::default()
    };
    for (idx, flow) in flows.iter().enumerate() {
        let Some(rendered) = rendered_flow_from_raw_taint(ws, flow, (first_flow_number + idx + 1) as u32)
        else {
            continue;
        };
        let header_name = if flow.terminal.is_empty() {
            flow.entry.as_str()
        } else {
            flow.terminal.as_str()
        };
        let mut local_seen = BodySet::default();
        render_flow_block_with_heading(
            u,
            &render_opts,
            &rendered,
            header_name,
            &mut local_seen,
            "TAINT FLOW",
        );
    }
}

fn rendered_flow_from_raw_taint(
    ws: &Workspace,
    flow: &InspectTaintFlow,
    flow_number: u32,
) -> Option<InspectFlowRendered> {
    let funcs: Vec<bonsai_common::FuncId> = flow
        .func_ids
        .iter()
        .copied()
        .map(bonsai_common::FuncId::new)
        .collect();
    if funcs.is_empty() {
        return None;
    }
    let call_spans = vec![None; funcs.len().saturating_sub(1)];
    let flow_label = flow_number.to_string();
    let precision = precision_from_label(&flow.precision);
    let mut rendered = render_flow_with_cached_call_spans(
        ws,
        &funcs,
        &call_spans,
        flow_number,
        &flow_label,
        precision,
        None,
        InspectFilters::default(),
        true,
        true,
    )?;
    rendered.flow_id.clone_from(&flow.taint_id);
    if !flow.chain_display.is_empty() {
        rendered.chain.clone_from(&flow.chain_display);
        rendered.chain_display = flow.chain_display.join(" -> ");
    }
    Some(rendered)
}

fn precision_from_label(label: &str) -> bonsai_common::Precision {
    match label {
        "exact" => bonsai_common::Precision::Exact,
        "narrowed" => bonsai_common::Precision::Narrowed,
        "over-approximate" | "over_approximate" => bonsai_common::Precision::OverApproximate,
        "unknown" => bonsai_common::Precision::Unknown,
        _ => bonsai_common::Precision::Unknown,
    }
}

fn format_taint_terminal_location(flow: &InspectTaintFlow) -> String {
    flow.steps
        .last()
        .map(|step| format!("{}:{}:{}", short_file(&step.file), step.line, step.column))
        .unwrap_or_else(|| "—".to_string())
}

fn format_taint_args(flow: &InspectTaintFlow) -> String {
    let args: Vec<String> = flow
        .steps
        .last()
        .map(|step| {
            step.tainted_args
                .iter()
                .map(|arg| {
                    arg.param_name
                        .as_ref()
                        .filter(|param| !param.is_empty())
                        .map(|param| format!("{}->{}", truncate(&arg.value_text, 32), truncate(param, 32)))
                        .unwrap_or_else(|| truncate(&arg.value_text, 32))
                })
                .collect()
        })
        .unwrap_or_default();
    if args.is_empty() {
        "—".to_string()
    } else {
        args.join(", ")
    }
}

fn format_taint_chain(flow: &InspectTaintFlow) -> String {
    if !flow.chain_display.is_empty() {
        return truncate(&flow.chain_display.join(" -> "), 90);
    }
    "—".to_string()
}

/// One match point inside a folded flow/group — a borrowed slice
/// of the hit's display fields. Rendered as a single compact line
/// below the flow block so the reader can see every origin
/// without re-rendering the chain.
struct FoldMatch<'a> {
    kind: &'a str,
    text: &'a str,
    file: &'a str,
    line: u32,
    column: u32,
}

/// Compact `n match points:` block rendered under a folded flow
/// / group. Preserves the same `(kind, text, location)` fields the
/// per-hit header used to show — no information lost, just one
/// line per match instead of a full chain re-render per match.
fn render_match_points(u: &Ui, matches: &[FoldMatch<'_>]) {
    if matches.is_empty() {
        return;
    }
    cli_println!();
    cli_println!(
        "  {} {}",
        u.dim("match points:"),
        u.annotation(&format!("{}", matches.len()))
    );
    for m in matches {
        let loc = format!("{}:{}:{}", short_file(m.file), m.line, m.column);
        cli_println!(
            "    {} {} {}",
            u.annotation(m.kind),
            u.name(&truncate(m.text, 80)),
            u.dim(&format!("({loc})"))
        );
    }
}

/// Render a single FLOW block — the `══` ruler, the `FLOW <label>
/// <flow_id> <header_name> [precision: ...]` header line, the
/// colorized chain display, the trailing `══` ruler, then either
/// the compact step list or the full source bodies depending on
/// `render.compact`.
///
/// `header_name` is the rightmost token on the header line — the
/// decl name for a decl-flow render, the hit's text for an
/// occurrence-hit render. This is the only place the two render
/// paths differ per flow, so extracting it lets both sites share
/// identical formatting.
pub(crate) fn render_flow_block(
    u: &Ui,
    render: &InspectRenderOptions,
    flow: &InspectFlowRendered,
    header_name: &str,
    seen_bodies: &mut BodySet,
) {
    render_flow_block_with_heading(u, render, flow, header_name, seen_bodies, "FLOW");
}

pub(crate) fn render_flow_block_with_heading(
    u: &Ui,
    render: &InspectRenderOptions,
    flow: &InspectFlowRendered,
    header_name: &str,
    seen_bodies: &mut BodySet,
    heading: &str,
) {
    cli_println!();
    cli_println!("{}", u.ruler('═', 70));
    cli_println!(
        "{} {} {}{}",
        u.annotation(&format!("{heading} {}", flow.flow_label)),
        u.dim(&flow.flow_id),
        u.name(header_name),
        precision_header_suffix(u, flow.precision),
    );
    let chain_hops: Vec<&str> = if flow.chain_display.is_empty() {
        flow.chain.iter().map(String::as_str).collect()
    } else {
        flow.chain_display.split(" -> ").collect()
    };
    let chain_line = chain_hops
        .iter()
        .map(|hop_name| u.name(hop_name))
        .collect::<Vec<_>>()
        .join(&u.dim(" → "));
    cli_println!("{chain_line}");
    cli_println!("{}", u.ruler('═', 70));
    if render.compact {
        render_compact_step_list(u, flow);
    } else {
        render_full_source_bodies(u, flow, seen_bodies);
    }
}

/// Render a single GROUP block — the wrapper that replaces multiple
/// FLOW blocks when the result is in grouped view. The block:
///
/// - opens with `══ GROUP <n> <group_id>  <k> flow(s)` and the
///   shared-suffix chain display,
/// - lists each member flow's unique prefix and flow_id on its own
///   line, so users can `--flow <id>` back into the full render,
/// - when `--compact` is NOT set AND the group has more than one
///   member, falls back to per-member FLOW blocks inside the group
///   so the user can still see full source bodies. With `--compact`
///   the group block stays compact (just the prefix list).
fn render_group_block(
    u: &Ui,
    render: &InspectRenderOptions,
    group: &InspectFlowGroup,
    members: &[&InspectFlowRendered],
    group_number: usize,
    header_name: &str,
    _seen_bodies: &mut BodySet,
) {
    cli_println!();
    cli_println!("{}", u.ruler('═', 70));
    cli_println!(
        "{} {} {} {}{}",
        u.annotation(&format!("GROUP {group_number}")),
        u.dim(&group.group_id),
        u.name(&format!("{} flow(s)", group.member_count)),
        u.name(header_name),
        precision_header_suffix(u, group.precision),
    );
    let shared_suffix_line = group
        .shared_suffix
        .iter()
        .map(|hop_name| u.name(hop_name))
        .collect::<Vec<_>>()
        .join(&u.dim(" → "));
    cli_println!("{} {shared_suffix_line}", u.dim("shared:"));
    cli_println!("{}", u.ruler('═', 70));
    // Per-member line: `FLOW <label> <flow_id>  prefix: a → b`.
    // Empty-prefix members print `(no unique prefix)` so the line
    // shape stays consistent.
    for (member_idx, flow) in members.iter().enumerate() {
        let unique_prefix = &group.unique_prefixes[member_idx];
        let prefix_display = if unique_prefix.is_empty() {
            u.dim("(no unique prefix)")
        } else {
            unique_prefix
                .iter()
                .map(|hop_name| u.name(hop_name))
                .collect::<Vec<_>>()
                .join(&u.dim(" → "))
        };
        cli_println!(
            "  {} {} {} {prefix_display}",
            u.annotation(&format!("FLOW {}", flow.flow_label)),
            u.dim(&flow.flow_id),
            u.dim("prefix:"),
        );
    }
    // Full-source mode: render each member's body below the group
    // header so users can still see the inlined source. In compact
    // mode the per-member prefix list above is the whole render.
    if !render.compact {
        for flow in members {
            let mut local_seen_bodies = BodySet::default();
            render_flow_block(u, render, flow, header_name, &mut local_seen_bodies);
        }
    }
}

/// Text-mode render of a flow's inlined source bodies — the
/// classic `[module] ... [def] ... <line-by-line-source>` shape.
/// Used when `--compact` is NOT set; compact mode calls
/// [`render_compact_step_list`] instead.
/// Shared "already-rendered function body" set. Key is the
/// `(module path, start line, annotation fingerprint)` triple:
/// two flows that both pass through `handle_request` at
/// `gateway.py:10` share a key *only when* they produce the same
/// annotation set on the same source lines. Flows that annotate
/// different steps (distinct MATCH / FROM / TO / `-> callee`
/// markers) render independently so per-flow markers are never
/// lost — dedup fires specifically on the truly-identical
/// repeats (e.g. several flows inside a shared-suffix group that
/// all annotate the same call-advance line the same way).
pub(crate) type BodyKey = (String, u32, u64);
pub(crate) type BodySet = ahash::AHashSet<BodyKey>;

/// Content-hash of a function body's per-line *semantic*
/// annotations. Strips the flow label prefix (`FLOW 3 → foo`
/// becomes `→ foo`) so two flows with different numbering but
/// the same MATCH / FROM / TO / advance-call markers hash to the
/// same key. Line numbers + step labels + the semantic tail are
/// absorbed so distinct annotation placements stay distinguishable.
fn annotation_fingerprint(func: &InspectFunctionRendered) -> u64 {
    let mut hasher = bonsai_hash::Hasher::new();
    for line in &func.lines {
        hasher.absorb(&line.line_no.to_le_bytes());
        if let Some(a) = line.annotation.as_deref() {
            hasher.absorb(strip_flow_label(a).as_bytes());
        }
        hasher.absorb_separator();
    }
    hasher.finish()
}

/// Normalise an annotation by removing every `FLOW N[x]` label so
/// fingerprinting keys on semantic content, not per-flow numbering.
/// `"[FLOW 3 -> get_user]"` and `"[FLOW 5 -> get_user]"` both yield
/// `"[-> get_user]"`. Also drops any stray whitespace the removed
/// label leaves behind. Multiple labels per annotation (when the
/// filter marker piggy-backs on the advance annotation) are all
/// stripped.
fn strip_flow_label(annotation: &str) -> String {
    use std::borrow::Cow;
    let mut out: Cow<'_, str> = Cow::Borrowed(annotation);
    while let Some(start) = out.find("FLOW ") {
        let after = &out[start + "FLOW ".len()..];
        let label_len = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .map(char::len_utf8)
            .sum::<usize>();
        if label_len == 0 {
            break;
        }
        let end = start + "FLOW ".len() + label_len;
        // Also eat the trailing space that separated the label from
        // the rest (e.g. `"FLOW 3 MATCH"` → `"MATCH"`).
        let end = end + out[end..].chars().next().map_or(0, |c| usize::from(c == ' '));
        let mut s = out.into_owned();
        s.replace_range(start..end, "");
        out = Cow::Owned(s);
    }
    out.into_owned().trim().to_string()
}

/// Pick the step number + annotation that represents this function
/// as a flow hop when its body is folded. Priority: the line that
/// carries an advance / MATCH / SOURCE annotation with a step number
/// wins — that's the "this is the one visible thing the reader cares
/// about in this hop" line. Falls back to the first annotated line,
/// then to no step. Returned pieces are pre-styled so the caller
/// just concatenates them into the placeholder row.
fn steps_and_markers_for_folded(func: &InspectFunctionRendered, u: &Ui) -> Vec<(String, String)> {
    let Some(first_line) = func.lines.first() else {
        return vec![("   ".to_string(), String::new())];
    };
    let mut picks: Vec<&InspectLine> = func
        .lines
        .iter()
        .filter(|l| {
            l.step.is_some()
                && l.annotation.as_deref().is_some_and(|a| {
                    a.contains("->") || a.contains("MATCH") || a.contains("SOURCE") || a.contains("REACHES")
                })
        })
        .collect();
    if picks.is_empty() {
        picks = func
            .lines
            .iter()
            .filter(|l| l.step.is_some() && l.annotation.is_some())
            .collect();
    }
    if picks.is_empty() {
        picks = func.lines.iter().filter(|l| l.step.is_some()).collect();
    }
    if picks.is_empty() {
        picks.push(
            func.lines
                .iter()
                .find(|l| l.annotation.is_some())
                .unwrap_or(first_line),
        );
    }

    let mut rows: Vec<(String, String)> = picks
        .into_iter()
        .map(|line| {
            let step_label = match line.step {
                Some(n) => u.step(&format!("{n:>3}")),
                None => "   ".to_string(),
            };
            let marker = line.annotation.as_deref().unwrap_or("").to_string();
            (step_label, marker)
        })
        .collect();

    // Harvest every unique FROM: / TO: filter marker that landed on
    // any body line. Folded bodies otherwise hide filter evidence. If
    // the marker is not already on one of the preserved step anchors,
    // attach it to the first folded row.
    let mut seen_markers: Vec<String> = Vec::new();
    for line in &func.lines {
        let Some(ann) = line.annotation.as_deref() else {
            continue;
        };
        let mut cursor = ann;
        while let Some(pos) = cursor.find("[FLOW ") {
            let rest = &cursor[pos..];
            let Some(end) = rest.find(']') else {
                break;
            };
            let tag = &rest[..=end];
            let already_visible = rows.iter().any(|(_, marker)| marker.contains(tag));
            if (tag.contains("FROM:") || tag.contains("TO:"))
                && !already_visible
                && !seen_markers.iter().any(|m| m == tag)
            {
                seen_markers.push(tag.to_string());
            }
            cursor = &rest[end + 1..];
        }
    }
    if !seen_markers.is_empty() {
        let combined = seen_markers.join(" ");
        if let Some((_, first_marker)) = rows.first_mut() {
            if first_marker.is_empty() {
                *first_marker = combined;
            } else {
                first_marker.push(' ');
                first_marker.push_str(&combined);
            }
        }
    }

    rows.into_iter()
        .map(|(step_label, marker)| {
            let marker = if marker.is_empty() {
                String::new()
            } else {
                u.annotation(&format!("# {marker}"))
            };
            (step_label, marker)
        })
        .collect()
}

/// Render every function body in `flow`. Bodies whose
/// `(module_path, start_line)` is already in `seen` get a single
/// reference line `(body already rendered above)`; fresh bodies
/// print in full and update `seen`. Zero context lost — the full
/// body is still visible earlier in the output, and the
/// reference line includes the same location the reader would use
/// to find it by `file:line`.
fn render_full_source_bodies(u: &Ui, flow: &InspectFlowRendered, seen: &mut BodySet) {
    for func in &flow.functions {
        let key: BodyKey = (
            func.module_path.clone(),
            func.start_line,
            annotation_fingerprint(func),
        );
        cli_println!();
        cli_println!("{} {}", u.dim("[module]"), u.path(&short_file(&func.module_path)));
        render_owner_context(u, func);
        if seen.contains(&key) {
            // Body already rendered earlier in this section — just
            // reference it. Pull the hop's step number and its
            // advance annotation (`[FLOW N -> next]` / MATCH /
            // FROM / TO markers) off the skipped body so the step
            // counter stays continuous across the whole chain and
            // filter markers don't get swallowed by the fold.
            let base = format!(
                "{} {} {} {}",
                u.dim("└─ [def]"),
                u.name(&func.signature),
                u.loc(&format!(":{}", func.start_line)),
                u.dim("(body already rendered above)"),
            );
            for (step_label, marker_suffix) in steps_and_markers_for_folded(func, u) {
                if marker_suffix.is_empty() {
                    cli_println!("  {step_label}  {base}");
                } else {
                    cli_println!("  {step_label}  {base}  {marker_suffix}");
                }
            }
            continue;
        }
        seen.insert(key);
        cli_println!(
            "{} {} {}",
            u.dim("└─ [def]"),
            u.name(&func.signature),
            u.loc(&format!(":{}", func.start_line))
        );
        let file_extension = ui::extension_for(&func.module_path);
        for line in &func.lines {
            let step_label = match line.step {
                Some(n) => u.step(&format!("{:>3}", n)),
                None => "   ".to_string(),
            };
            let highlighted_text = u.highlight(&line.text, file_extension);
            if let Some(annotation) = line.annotation.as_deref() {
                let inline_annotation = format!("# {annotation}");
                if line.text.len().saturating_add(inline_annotation.len()) <= 110 {
                    cli_println!(
                        "  {step_label}  {}  {}",
                        highlighted_text,
                        u.annotation(&inline_annotation)
                    );
                } else {
                    cli_println!("  {step_label}  {highlighted_text}");
                    for wrapped in u.wrapped_annotation_prefixed_lines(
                        "       ",
                        "       ",
                        "       ",
                        &inline_annotation,
                    ) {
                        cli_println!("{wrapped}");
                    }
                }
            } else {
                cli_println!("  {step_label}  {highlighted_text}");
            }
        }
    }
}

fn render_owner_context(u: &Ui, func: &InspectFunctionRendered) {
    for owner in &func.owners {
        cli_println!(
            "{} {} {}",
            u.dim(&format!("├─ [{}]", owner.kind)),
            u.name(&owner.name),
            u.loc(&format!(":{}", owner.line)),
        );
    }
}

/// Text-mode render of a flow's compact step list. Each row is an actual
/// annotated source line, so step numbering matches the same SOURCE /
/// TAINT / SINK / MATCH events shown in the full source-body render.
fn render_compact_step_list(u: &Ui, flow: &InspectFlowRendered) {
    let annotated_lines: Vec<(&InspectFunctionRendered, &InspectLine)> = flow
        .functions
        .iter()
        .flat_map(|func| {
            func.lines
                .iter()
                .filter(|line| line.step.is_some() || line.annotation.is_some())
                .map(move |line| (func, line))
        })
        .collect();

    if annotated_lines.is_empty() {
        for (index, func) in flow.functions.iter().enumerate() {
            let step_no = index + 1;
            let location = u.loc(&format!("{}:{}", short_file(&func.module_path), func.start_line));
            cli_println!(
                "  {} {} {}{}  {}",
                u.step(&format!("{:>3}", step_no)),
                u.kind("def"),
                compact_owner_prefix(func),
                u.name(&func.signature),
                location,
            );
        }
        return;
    }

    for (func, line) in annotated_lines {
        let step_no = line.step.unwrap_or(0);
        let step_label = if step_no == 0 {
            "   ".to_string()
        } else {
            u.step(&format!("{:>3}", step_no))
        };
        let location = u.loc(&format!("{}:{}", short_file(&func.module_path), line.line_no));
        let annotation = line.annotation.as_deref().unwrap_or("");
        if annotation.len() > 90 {
            cli_println!(
                "  {} {} {}{}  {}",
                step_label,
                u.kind("line"),
                compact_owner_prefix(func),
                u.name(&func.signature),
                location,
            );
            for wrapped in u.wrapped_annotation_prefixed_lines("       ", "       ", "       ", annotation) {
                cli_println!("{wrapped}");
            }
        } else {
            cli_println!(
                "  {} {} {}{}  {}  {}",
                step_label,
                u.kind("line"),
                compact_owner_prefix(func),
                u.name(&func.signature),
                location,
                u.dim(annotation),
            );
        }
        let text = line.text.trim();
        if !text.is_empty() && text != "..." {
            cli_println!("       {}", u.dim(&truncate(text, 140)));
        }
    }
}

/// Recursively find the smallest source line whose structured flow
/// event mentions `needle`. Matches the same per-event fact fields as
/// `bonsai_taint`'s chain-token collector (call names, keyword/arg
/// text, assign writes/reads/call args) — never raw line text — so a
/// chain selected via a propagated taint fact can anchor its filter
/// marker on the exact line that carries the fact.
fn find_fact_anchor_line(
    events: &[bonsai_lang_api::FlowEvent],
    needle: &str,
    span_map: &bonsai_common::SpanMap,
    best: &mut Option<u32>,
) {
    use bonsai_lang_api::FlowEvent as E;
    for event in events {
        let matched_span = match event {
            E::Call { span, name, args, .. } => (name_token_match(name, needle)
                || args.iter().any(|arg| {
                    arg.name.as_deref().is_some_and(|n| name_token_match(n, needle))
                        || name_token_match(&arg.value_text, needle)
                }))
            .then_some(*span),
            E::Assign {
                span,
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } => (name_token_match(target, needle)
                || source_name
                    .as_deref()
                    .is_some_and(|s| name_token_match(s, needle))
                || source_call
                    .as_deref()
                    .is_some_and(|c| name_token_match(c, needle))
                || source_call_args.iter().any(|a| name_token_match(a, needle))
                || source_names.iter().any(|s| name_token_match(s, needle)))
            .then_some(*span),
            E::Branch {
                then_events,
                else_events,
                ..
            } => {
                find_fact_anchor_line(then_events, needle, span_map, best);
                find_fact_anchor_line(else_events, needle, span_map, best);
                None
            }
            E::Loop { body, .. } => {
                find_fact_anchor_line(body, needle, span_map, best);
                None
            }
            E::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                find_fact_anchor_line(body, needle, span_map, best);
                find_fact_anchor_line(catch_events, needle, span_map, best);
                find_fact_anchor_line(finally_events, needle, span_map, best);
                None
            }
            E::Defer { body, .. } | E::Using { body, .. } => {
                find_fact_anchor_line(body, needle, span_map, best);
                None
            }
            _ => None,
        };
        if let Some(span) = matched_span {
            let line = span_map.line_col(span.start).line;
            if best.is_none_or(|b| line < b) {
                *best = Some(line);
            }
        }
    }
}

/// Append a `[FLOW N FROM: X]` / `[FLOW N TO: Y]` marker to the
/// rendered line at `anchor_line` when no line in this def render
/// already carries that exact marker. Post-pass companion to
/// [`build_filter_marker`] for chains selected via structured taint
/// facts, which have no decl-name / hit subject for the marker to
/// land on during the main loop.
fn attach_fact_anchored_marker(
    lines: &mut [InspectLine],
    tag: &str,
    needle: Option<&str>,
    anchor_line: Option<u32>,
    flow_label: &str,
) {
    let (Some(needle), Some(anchor)) = (needle, anchor_line) else {
        return;
    };
    let marker = format!("[FLOW {flow_label} {tag} {needle}]");
    if lines
        .iter()
        .any(|l| l.annotation.as_deref().is_some_and(|a| a.contains(&marker)))
    {
        return;
    }
    let Some(line) = lines.iter_mut().find(|l| l.line_no == anchor && l.text != "...") else {
        return;
    };
    line.annotation = Some(match line.annotation.take() {
        Some(existing) => format!("{existing} {marker}"),
        None => marker,
    });
}

/// Build the `[FLOW N FROM: X]` / `[FLOW N TO: Y]` annotation suffix
/// for a rendered line. `subjects` are the identifiers the line's
/// existing annotation is about (decl name at SOURCE, advance callee
/// at `->` lines, sink text at MATCH). A filter fires on a line only
/// when one of its subjects contains the needle, so the marker lands
/// precisely on the hop the filter targeted and does not scatter
/// across every line whose raw source happens to mention the word.
///
/// Returns `""` when no filter is set or none of the filter needles
/// appear on this line.
fn build_filter_marker(filters: InspectFilters<'_>, subjects: &[&str], flow_label: &str) -> String {
    // Token-boundary match — mirrors `chain_matches_filters` without
    // falling back to arbitrary raw source text. Raw line matching made
    // `--to pickle` label `def load_from_pickle(...)` and unrelated
    // string/arg lines as destination evidence.
    let matches = |needle: &str| -> bool { subjects.iter().any(|s| name_token_match(s, needle)) };
    let mut pieces: Vec<String> = Vec::new();
    if let Some(from) = filters.from {
        if matches(from) {
            pieces.push(format!("[FLOW {flow_label} FROM: {from}]"));
        }
    }
    if let Some(to) = filters.to {
        if matches(to) {
            pieces.push(format!("[FLOW {flow_label} TO: {to}]"));
        }
    }
    pieces.join(" ")
}

fn inspect_filter_hit<'a>(text: &'a str, kind: &str) -> Option<bonsai_sdk::FilterHit<'a>> {
    inspect_hit_kind(kind).map(|kind| bonsai_sdk::FilterHit::new(text, kind))
}

fn inspect_hit_kind(kind: &str) -> Option<bonsai_sdk::FactKindFilter> {
    match kind {
        "decl" => Some(bonsai_sdk::FactKindFilter::Decl),
        "call" => Some(bonsai_sdk::FactKindFilter::Call),
        "arg" => Some(bonsai_sdk::FactKindFilter::Arg),
        "var" => Some(bonsai_sdk::FactKindFilter::Write),
        "string" => Some(bonsai_sdk::FactKindFilter::StringLit),
        "import" => Some(bonsai_sdk::FactKindFilter::Import),
        "class" => Some(bonsai_sdk::FactKindFilter::Class),
        "ref" => Some(bonsai_sdk::FactKindFilter::Read),
        _ => None,
    }
}

fn inspect_kind_matches_filter(kind: &str, filter: bonsai_sdk::FactKindFilter) -> bool {
    inspect_hit_kind(kind) == Some(filter)
}

fn display_query_colored(q: &str, is_regex: bool) -> String {
    let u = ui();
    if q.is_empty() {
        // No explicit query — inspect was driven by filters alone.
        u.dim("(filters only)")
    } else if is_regex {
        format!("{}/{}/", u.dim("regex "), u.name(q))
    } else {
        u.name(&format!("`{q}`"))
    }
}

// `Matcher` + the `build_matcher` factory live in
// `bonsai_sdk::query`. CLI re-exports so the existing call
// sites stay readable.
use bonsai_sdk::Matcher;

fn build_matcher(pattern: &str, is_regex: bool) -> Result<Matcher> {
    Matcher::build(Some(pattern), is_regex).with_context(|| format!("invalid regex: {pattern}"))
}

// `find_enclosing_func` lives in `bonsai_sdk::find_enclosing_func`.
// CLI doesn't reach for it directly today — the cache surface
// (`ChainCache::enclosing_func`) is what every code path uses.

#[derive(Copy, Clone)]
struct FlowHitWalkContext<'a> {
    workspace: Option<&'a Workspace>,
    matcher: &'a Matcher,
    endpoint_kind_filter: Option<bonsai_sdk::FactKindFilter>,
    kinds: &'a ahash::AHashSet<String>,
}

impl FlowHitWalkContext<'_> {
    fn want(self, kind: &str) -> bool {
        self.endpoint_kind_filter
            .is_none_or(|filter| inspect_kind_matches_filter(kind, filter))
            && (self.kinds.is_empty() || self.kinds.contains(kind))
    }
}

fn refine_hit_span(
    workspace: Option<&Workspace>,
    span: bonsai_common::Span,
    text: &str,
) -> bonsai_common::Span {
    let Some(workspace) = workspace else {
        return span;
    };
    if text.is_empty() {
        return span;
    }
    let Ok(snapshot) = workspace.vfs().snapshot(span.file) else {
        return span;
    };
    let bytes = snapshot.text.as_bytes();
    if bytes.is_empty() {
        return span;
    }
    let span_start = (span.start as usize).min(bytes.len());
    let span_end = (span.end as usize).min(bytes.len()).max(span_start);
    let line_start = bytes[..span_start]
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |idx| idx + 1);
    let line_end = bytes[span_end..]
        .iter()
        .position(|b| *b == b'\n')
        .map_or(bytes.len(), |idx| span_end + idx);
    let line = &snapshot.text[line_start..line_end];
    let Some(offset) = find_hit_text_offset(line, text) else {
        return span;
    };
    bonsai_common::Span {
        file: span.file,
        start: (line_start + offset) as u64,
        end: (line_start + offset + text.len()) as u64,
    }
}

fn find_hit_text_offset(line: &str, text: &str) -> Option<usize> {
    for (offset, _) in line.match_indices(text) {
        let before = line[..offset].chars().next_back();
        let after = line[offset + text.len()..].chars().next();
        let before_boundary = before.is_none_or(|ch| !is_hit_ident_char(ch));
        let after_boundary = after.is_none_or(|ch| !is_hit_ident_char(ch));
        if before_boundary && after_boundary {
            return Some(offset);
        }
    }
    line.find(text)
}

fn is_hit_ident_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

fn walk_flow_hits<F>(
    events: &[FlowEvent],
    in_fn_id: bonsai_common::FuncId,
    in_fn: &str,
    context: FlowHitWalkContext<'_>,
    out: &mut Vec<HitOut>,
    push_hit: &mut F,
) where
    F: FnMut(
        &str,
        String,
        bonsai_common::Span,
        Option<(bonsai_common::FuncId, String)>,
        bool,
        &mut Vec<HitOut>,
    ),
{
    let mut explicit_calls = Vec::new();
    collect_explicit_call_hits(events, &mut explicit_calls);
    walk_flow_hits_inner(events, in_fn_id, in_fn, context, &explicit_calls, out, push_hit);
}

fn collect_explicit_call_hits<'a>(events: &'a [FlowEvent], out: &mut Vec<(&'a str, bonsai_common::Span)>) {
    for event in events {
        match event {
            FlowEvent::Call { name, span, .. } => out.push((name, *span)),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_explicit_call_hits(then_events, out);
                collect_explicit_call_hits(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_explicit_call_hits(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_explicit_call_hits(body, out);
                collect_explicit_call_hits(catch_events, out);
                collect_explicit_call_hits(finally_events, out);
            }
            _ => {}
        }
    }
}

fn walk_flow_hits_inner<F>(
    events: &[FlowEvent],
    in_fn_id: bonsai_common::FuncId,
    in_fn: &str,
    context: FlowHitWalkContext<'_>,
    explicit_calls: &[(&str, bonsai_common::Span)],
    out: &mut Vec<HitOut>,
    push_hit: &mut F,
) where
    F: FnMut(
        &str,
        String,
        bonsai_common::Span,
        Option<(bonsai_common::FuncId, String)>,
        bool,
        &mut Vec<HitOut>,
    ),
{
    let containing = |id: bonsai_common::FuncId, name: &str| Some((id, name.to_string()));
    for e in events {
        match e {
            FlowEvent::Call { span, name, args, .. } => {
                if context.want("call") && context.matcher.is_match(name) {
                    push_hit(
                        "call",
                        name.clone(),
                        *span,
                        containing(in_fn_id, in_fn),
                        false,
                        out,
                    );
                }
                if context.want("arg") {
                    for a in args {
                        if context.matcher.is_match(&a.value_text)
                            || a.name.as_deref().is_some_and(|n| context.matcher.is_match(n))
                        {
                            // Hit text stays semantic: just the value for
                            // positional args, `name=value` for named. The
                            // previous `(pos)=value` prefix leaked the
                            // placeholder "pos" into filter matches
                            // (e.g. `--to os` spuriously hitting every
                            // positional arg because "(pos)" contains "os").
                            let text = if let Some(n) = a.name.as_deref() {
                                format!("{n}={}", a.value_text)
                            } else {
                                a.value_text.clone()
                            };
                            push_hit("arg", text, a.span, containing(in_fn_id, in_fn), false, out);
                        }
                    }
                }
            }
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_names,
                source_call,
                source_call_args,
                ..
            } => {
                if let Some(call) = source_call {
                    let shadowed_by_explicit_call = explicit_calls.iter().any(|(name, call_span)| {
                        *name == call
                            && call_span.file == span.file
                            && call_span.start >= span.start
                            && call_span.end <= span.end
                    });
                    if !shadowed_by_explicit_call && context.want("call") && context.matcher.is_match(call) {
                        let call_span = refine_hit_span(context.workspace, *span, call);
                        push_hit(
                            "call",
                            call.clone(),
                            call_span,
                            containing(in_fn_id, in_fn),
                            true,
                            out,
                        );
                    }
                    if context.want("arg") {
                        for arg in source_call_args {
                            if context.matcher.is_match(arg) {
                                let arg_span = refine_hit_span(context.workspace, *span, arg);
                                push_hit(
                                    "arg",
                                    arg.clone(),
                                    arg_span,
                                    containing(in_fn_id, in_fn),
                                    false,
                                    out,
                                );
                            }
                        }
                    }
                }
                if context.want("var")
                    && (context.matcher.is_match(target)
                        || source_name
                            .as_deref()
                            .is_some_and(|s| context.matcher.is_match(s))
                        || source_names.iter().any(|s| context.matcher.is_match(s))
                        || source_call
                            .as_deref()
                            .is_some_and(|s| context.matcher.is_match(s)))
                {
                    let display_source = source_name
                        .as_deref()
                        .or(source_call.as_deref())
                        .or_else(|| source_names.first().map(String::as_str));
                    push_hit(
                        "var",
                        format!(
                            "{target}{}",
                            display_source.map(|s| format!(" = {s}")).unwrap_or_default()
                        ),
                        *span,
                        containing(in_fn_id, in_fn),
                        false,
                        out,
                    );
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk_flow_hits_inner(
                    then_events,
                    in_fn_id,
                    in_fn,
                    context,
                    explicit_calls,
                    out,
                    push_hit,
                );
                walk_flow_hits_inner(
                    else_events,
                    in_fn_id,
                    in_fn,
                    context,
                    explicit_calls,
                    out,
                    push_hit,
                );
            }
            FlowEvent::Loop { body, .. } => {
                walk_flow_hits_inner(body, in_fn_id, in_fn, context, explicit_calls, out, push_hit);
            }
            // Recurse into every event that carries nested flow events.
            // Previously this list stopped at Branch/Loop so any call /
            // var / arg / string buried inside a try-catch, defer,
            // using/with block silently disappeared from inspect.
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                walk_flow_hits_inner(body, in_fn_id, in_fn, context, explicit_calls, out, push_hit);
                walk_flow_hits_inner(
                    catch_events,
                    in_fn_id,
                    in_fn,
                    context,
                    explicit_calls,
                    out,
                    push_hit,
                );
                walk_flow_hits_inner(
                    finally_events,
                    in_fn_id,
                    in_fn,
                    context,
                    explicit_calls,
                    out,
                    push_hit,
                );
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_flow_hits_inner(body, in_fn_id, in_fn, context, explicit_calls, out, push_hit);
            }
            _ => {}
        }
    }
}

fn render_inspect_text(out: &InspectOut, render: &InspectRenderOptions, view: ResolvedView) {
    let u = ui();
    cli_println!(
        "{} {}",
        u.heading(&format!("══ {}", out.symbol)),
        u.kind(&format!("({})", out.kind)),
    );
    cli_println!(
        "   {} {}:{}:{}",
        u.dim("at"),
        u.path(&out.file),
        u.loc(&out.line.to_string()),
        u.loc(&out.column.to_string()),
    );
    if !out.params.is_empty() {
        cli_println!("   {} {}", u.dim("params:"), out.params.join(", "));
    }
    if !out.direct_callers.is_empty() {
        cli_println!(
            "   {} {}:",
            u.dim("direct callers"),
            u.loc(&format!("({})", out.direct_callers.len())),
        );
        for c in out.direct_callers.iter().take(10) {
            cli_println!(
                "     {}:{}:{}  {}",
                u.path(&short_file(&c.file)),
                u.loc(&c.line.to_string()),
                u.loc(&c.column.to_string()),
                c.snippet.trim(),
            );
        }
        if out.direct_callers.len() > 10 {
            cli_println!(
                "     {}",
                u.dim(&format!("... ({} more)", out.direct_callers.len() - 10))
            );
        }
    }
    if !out.callees.is_empty() {
        cli_println!("   {} {}", u.dim("outgoing calls:"), out.callees.join(", "));
    }
    if !out.graph_flows_evaluated {
        cli_println!(
            "\n   {}",
            u.dim("(static entry-point chains not requested; pass --graph-flow to evaluate them)")
        );
        return;
    }
    if out.flows.is_empty() {
        cli_println!(
            "\n   {}",
            u.dim("(no entry-point call chain reaches this symbol statically)")
        );
        return;
    }
    cli_println!(
        "\n   {}",
        u.dim(&format!(
            "{} flow(s) reaching {} — {} unique entry points, max depth {}",
            out.summary.total_flows, out.symbol, out.summary.unique_entry_points, out.summary.max_chain_depth
        ))
    );
    match view {
        ResolvedView::Trace => {
            for flow in &out.flows {
                let mut local_seen_bodies = BodySet::default();
                render_flow_block(u, render, flow, &out.symbol, &mut local_seen_bodies);
            }
        }
        ResolvedView::Grouped => {
            // Resolve each group's member_flow_ids back to the actual
            // `&InspectFlowRendered` in input order so the group block
            // renders members in the same sequence the flat view would.
            for (group_idx, group) in out.groups.iter().enumerate() {
                let members: Vec<&InspectFlowRendered> = group
                    .member_flow_ids
                    .iter()
                    .filter_map(|member_flow_id| {
                        out.flows.iter().find(|flow| &flow.flow_id == member_flow_id)
                    })
                    .collect();
                let mut local_seen_bodies = BodySet::default();
                render_group_block(
                    u,
                    render,
                    group,
                    &members,
                    group_idx + 1,
                    &out.symbol,
                    &mut local_seen_bodies,
                );
            }
        }
    }
}

/// Resolve a call occurrence to the workspace callee(s) it invokes.
///
/// Occurrence hits must use the already-built semantic graph, keyed by
/// the exact call-site span. Re-resolving by name here can bind a hit
/// like `external.helper()` to an unrelated sibling call `helper()` in
/// the same function.
fn resolve_call_hit_targets(
    chain_cache: &ChainCache<'_>,
    caller_func: bonsai_common::FuncId,
    call_span: bonsai_common::Span,
) -> Vec<(bonsai_common::FuncId, bonsai_common::Precision)> {
    let mut targets: Vec<(bonsai_common::FuncId, bonsai_common::Precision)> = chain_cache
        .resolved_graph()
        .callees_of(caller_func)
        .filter(|edge| edge.precision.is_semantic() && spans_overlap(edge.span, call_span))
        .map(|edge| (edge.to, edge.precision))
        .collect();
    targets.sort_by(|a, b| a.0.raw().cmp(&b.0.raw()).then_with(|| a.1.cmp(&b.1)));
    targets.dedup_by_key(|target| target.0);
    targets
}

fn spans_overlap(left: bonsai_common::Span, right: bonsai_common::Span) -> bool {
    left.file == right.file && left.start < right.end && right.start < left.end
}

fn dedupe_chains_keep_best_precision(mut chains: Vec<ResolvedChain>) -> Vec<ResolvedChain> {
    chains.sort_by(|a, b| a.funcs.cmp(&b.funcs).then_with(|| a.precision.cmp(&b.precision)));
    let mut deduped: Vec<ResolvedChain> = Vec::with_capacity(chains.len());
    for chain in chains {
        if deduped
            .last()
            .is_some_and(|previous| previous.funcs == chain.funcs)
        {
            continue;
        }
        deduped.push(chain);
    }
    deduped
}

fn format_filter_match_cell(ui: &Ui, matched: Option<&FilterMatch>) -> String {
    let Some(matched) = matched else {
        return ui.dim("—");
    };
    match (&matched.file, matched.line, matched.column) {
        (Some(file), Some(line), Some(col)) => {
            let short_path = short_file(file);
            format!(
                "{} {}",
                ui.name(&matched.name),
                ui.dim(&format!("({short_path}:{line}:{col})"))
            )
        }
        _ => ui.name(&matched.name),
    }
}

/// Render a chain's precision as a short, colorized suffix for the
/// `FLOW N` header. Public inspect flows are semantic-only, so exact
/// and narrowed chains need no suffix. Non-semantic chains are dropped
/// before rendering.
fn precision_header_suffix(_ui: &Ui, precision: bonsai_common::Precision) -> String {
    debug_assert!(
        precision.is_semantic(),
        "inspect render received diagnostic-precision flow evidence: {precision:?}"
    );
    match precision {
        bonsai_common::Precision::Exact | bonsai_common::Precision::Narrowed => String::new(),
        bonsai_common::Precision::OverApproximate | bonsai_common::Precision::Unknown => String::new(),
    }
}

/// Build a [`FilterMatch`] from an optional FuncId and a display
/// name. When `func_id` is `Some`, resolves the decl's file and
/// `name_span` so the occurrence-hits table can render
/// `name (file:line:col)`. When `None`, emits a name-only match —
/// used when `--to` fuzzy-matches the hit's own text rather than a
/// reachable decl (the hit's location column already shows the file).
fn build_filter_match(
    workspace: &Workspace,
    func_id: Option<bonsai_common::FuncId>,
    display_name: String,
) -> FilterMatch {
    let Some(func_id) = func_id else {
        return FilterMatch {
            name: display_name,
            file: None,
            line: None,
            column: None,
        };
    };
    let global = workspace.compiler_header_index();
    let symbol = bonsai_common::SymbolId::new(func_id.raw());
    match global.decl_of(symbol) {
        Some(decl) => {
            let (file, line, column) = format_span(&decl.name_span, workspace);
            FilterMatch {
                name: display_name,
                file: Some(file),
                line: Some(line),
                column: Some(column),
            }
        }
        None => FilterMatch {
            name: display_name,
            file: None,
            line: None,
            column: None,
        },
    }
}

/// Where the search term is actually located within the flow.
/// Carries the exact span inside the containing function and a
/// human label like `"call os.system"`. `marker_subjects` are the
/// structured fact strings allowed to satisfy FROM/TO markers on this
/// rendered line; callers must not pass raw source lines.
#[derive(Clone)]
pub(crate) struct MatchOverride {
    pub(crate) span: bonsai_common::Span,
    pub(crate) label: String,
    pub(crate) marker_subjects: Vec<String>,
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
pub(crate) fn render_flow_with_cached_call_spans(
    ws: &Workspace,
    chain: &[bonsai_common::FuncId],
    call_spans: &[Option<bonsai_common::Span>],
    flow_number: u32,
    flow_label: &str,
    precision: bonsai_common::Precision,
    match_at: Option<(usize, MatchOverride)>,
    filters: InspectFilters<'_>,
    resolve_missing_call_spans: bool,
    full_source_for_large_bodies: bool,
) -> Option<InspectFlowRendered> {
    if !precision.is_semantic() {
        return None;
    }
    // An empty chain has nothing to render and would underflow the
    // `chain_len - 1` default match index below.
    if chain.is_empty() {
        return None;
    }
    // Chains now carry FuncIds all the way from enumeration, so each
    // hop resolves to exactly one decl — no name collision, no fallback
    // picker for "the candidate that calls the next hop." `decl_of` is
    // a direct SymbolId lookup.
    // Clone only the declarations in the selected chain so their file-body
    // cache pages may be released independently while rendering continues.
    let mut decls: Vec<bonsai_lang_api::Decl> = Vec::with_capacity(chain.len());
    let mut chain_names: Vec<String> = Vec::with_capacity(chain.len());
    for &func in chain {
        let symbol = bonsai_common::SymbolId::new(func.raw());
        let decl = (*ws.exact_decl(symbol)?).clone();
        chain_names.push(decl.name.clone());
        decls.push(decl);
    }
    let mut functions: Vec<InspectFunctionRendered> = Vec::new();
    let mut step_counter: u32 = 0;
    let chain_len = chain.len();

    // If no explicit match index, the match defaults to the last function
    // (decl-hit semantics: annotate the target's def line).
    let match_idx = match_at
        .as_ref()
        .map_or(chain_len - 1, |(function_index, _)| *function_index);
    let match_label = match_at.as_ref().map(|(_, o)| o.clone());

    for (function_index, decl) in decls.iter().enumerate() {
        let next_name: Option<String> = chain_names.get(function_index + 1).cloned();
        let is_root = function_index == 0;
        let is_match_fn = function_index == match_idx;

        // Find the specific call-site span for the chain-advancing call.
        let call_span = {
            let cached = call_spans.get(function_index).copied().flatten();
            if resolve_missing_call_spans {
                cached.or_else(|| {
                    chain
                        .get(function_index + 1)
                        .copied()
                        .zip(next_name.as_deref())
                        .and_then(|(next_func, n)| find_call_span_to_func_uncached(ws, decl, next_func, n))
                })
            } else {
                cached
            }
        };

        let match_here = if is_match_fn { match_label.clone() } else { None };
        let rendered = render_function_source(
            ws,
            decl,
            &mut step_counter,
            flow_label,
            call_span,
            next_name,
            is_root,
            is_match_fn,
            &decl.name,
            match_here,
            filters,
            full_source_for_large_bodies,
        )?;
        functions.push(rendered);
    }

    let chain_display = disambiguate_func_display_names(ws, chain, &chain_names).join(" -> ");
    let headers = ws.compiler_header_index();
    let flow_id = compute_structural_flow_id(headers.as_ref(), ws.db(), ws.vfs(), chain);
    Some(InspectFlowRendered {
        flow_number,
        flow_label: flow_label.to_string(),
        flow_id,
        precision,
        chain: chain_names,
        chain_display,
        functions,
    })
}

fn disambiguated_func_names_for_output(ws: &Workspace, funcs: &[bonsai_common::FuncId]) -> Vec<String> {
    let short_names: Vec<String> = funcs.iter().map(|&func| func_display_name(ws, func)).collect();
    disambiguate_func_display_names(ws, funcs, &short_names)
}

fn disambiguate_func_display_names(
    ws: &Workspace,
    funcs: &[bonsai_common::FuncId],
    short_names: &[String],
) -> Vec<String> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for name in short_names.iter().filter(|name| !name.is_empty()) {
        *counts.entry(name.as_str()).or_default() += 1;
    }
    funcs
        .iter()
        .zip(short_names.iter())
        .filter_map(|(&func, short_name)| {
            if short_name.is_empty() {
                None
            } else if counts.get(short_name.as_str()).copied().unwrap_or(0) > 1 {
                Some(func_disambiguated_display_name(ws, func, short_name))
            } else {
                Some(short_name.clone())
            }
        })
        .collect()
}

fn func_disambiguated_display_name(ws: &Workspace, func: bonsai_common::FuncId, fallback: &str) -> String {
    let global = ws.compiler_header_index();
    let symbol = bonsai_common::SymbolId::new(func.raw());
    let Some(decl) = global.decl_of(symbol) else {
        return fallback.to_string();
    };
    if let Some(owner_name) = owner_qualified_decl_name(ws, decl) {
        return owner_name;
    }
    decl.qualified_name
        .as_ref()
        .filter(|qualified| qualified.as_str() != decl.name)
        .cloned()
        .unwrap_or_else(|| fallback.to_string())
}

fn owner_qualified_decl_name(ws: &Workspace, decl: &bonsai_lang_api::Decl) -> Option<String> {
    let global = ws.compiler_header_index();
    let mut owner_names: Vec<String> = Vec::new();
    let mut parent = decl.parent;
    while let Some(parent_symbol) = parent {
        let Some(parent_decl) = global.decl_of(parent_symbol) else {
            break;
        };
        if is_renderable_owner(parent_decl.kind) {
            owner_names.push(parent_decl.name.clone());
        }
        parent = parent_decl.parent;
    }
    if owner_names.is_empty() {
        return None;
    }
    owner_names.reverse();
    Some(format!("{}.{}", owner_names.join("."), decl.name))
}

/// Stable `F:` flow_id from a chain's display names (joined with
/// `\0`). Hashed via fixed-seed FNV-1a-64 (low 32 bits, hex) so the
/// id stays identical across runs / cache modes / themes /
/// precision upgrades. `group_id` is a pure function of the shared
/// suffix.
#[derive(Serialize, Clone, Debug)]
struct InspectFlowGroup {
    /// Stable content-hash id (`G:` + 16 hex).
    group_id: String,
    /// flow_ids of the member flows, in group order.
    member_flow_ids: Vec<String>,
    /// The names every member shares (sink at the end). Always ≥ 1.
    shared_suffix: Vec<String>,
    /// Per-member prefix (what varies). `unique_prefixes[i]` is the
    /// slice of member `i`'s chain before `shared_suffix`.
    unique_prefixes: Vec<Vec<String>>,
    /// Worst-case precision across members (`meet` over each
    /// member's chain precision).
    precision: bonsai_common::Precision,
    /// Number of member flows. Stored redundantly so JSON consumers
    /// don't have to compute it.
    member_count: usize,
}

/// Group a flat flow list by longest shared suffix.
///
/// The algorithm:
/// 1. Bucket flows by their final chain element (the sink name).
///    Chains that end at different sinks can't share a suffix that
///    contains the sink, so they form separate groups.
/// 2. Within each bucket, extend the shared suffix one element at a
///    time from the right: `shared_suffix = [sink]` initially, then
///    try adding `chain[len-2]` if every member has the same name
///    there, then `chain[len-3]`, until members disagree or a
///    chain runs out.
/// 3. Emit one `InspectFlowGroup` per bucket with the computed
///    suffix and per-member unique prefixes.
///
/// Bucket order follows the first encounter of each sink in `flows`.
/// Within a bucket, member order matches the input order. Both
/// choices keep the render deterministic + stable against cache
/// state, which matters for the `--group <id>` flag — consumers must
/// be able to round-trip a group_id across two runs.
fn group_flows_by_suffix(flows: &[InspectFlowRendered]) -> Vec<InspectFlowGroup> {
    if flows.is_empty() {
        return Vec::new();
    }
    // Bucket flows by the final element of their chain (the sink name),
    // preserving first-encounter order. A parallel map from sink name
    // to bucket index in `buckets` lets us append a flow to an existing
    // bucket in O(1) without sorting `buckets` alphabetically (which
    // would change the group_id emission order across workspaces).
    let mut bucket_index_by_sink: ahash::AHashMap<String, usize> = ahash::AHashMap::new();
    let mut buckets: Vec<(String, Vec<&InspectFlowRendered>)> = Vec::new();
    for flow in flows {
        // Empty chains can't be grouped (the suffix math below subtracts
        // from `chain.len()`) and have no sink to bucket on — skip them.
        let Some(sink_name) = flow.chain.last().cloned() else {
            continue;
        };
        let bucket_idx = *bucket_index_by_sink.entry(sink_name.clone()).or_insert_with(|| {
            buckets.push((sink_name.clone(), Vec::new()));
            buckets.len() - 1
        });
        buckets[bucket_idx].1.push(flow);
    }

    let mut groups: Vec<InspectFlowGroup> = Vec::with_capacity(buckets.len());
    for (_sink_name, members) in buckets {
        // Find the longest shared suffix by walking the rightmost
        // elements of every member's chain in lockstep. Every member
        // has ≥1 element (the sink, by bucketing on chain.last()), so
        // `suffix_len` starts at 1 and grows while all members agree.
        let shortest_member_chain_len = members.iter().map(|member| member.chain.len()).min().unwrap_or(1);
        let mut suffix_len = 1usize;
        while suffix_len < shortest_member_chain_len {
            // Candidate suffix element = the `suffix_len`-th-from-the-
            // end element of the first member's chain. If every member
            // has the same name at that position, extend the suffix by
            // one; otherwise stop.
            let candidate_idx_in_first = members[0].chain.len() - 1 - suffix_len;
            let candidate_name = &members[0].chain[candidate_idx_in_first];
            let every_member_agrees = members.iter().all(|member| {
                let candidate_idx = member.chain.len() - 1 - suffix_len;
                &member.chain[candidate_idx] == candidate_name
            });
            if every_member_agrees {
                suffix_len += 1;
            } else {
                break;
            }
        }
        let first_member_chain = &members[0].chain;
        let shared_suffix: Vec<String> = first_member_chain[first_member_chain.len() - suffix_len..].to_vec();

        let mut member_flow_ids: Vec<String> = Vec::with_capacity(members.len());
        let mut unique_prefixes: Vec<Vec<String>> = Vec::with_capacity(members.len());
        let mut precision = bonsai_common::Precision::Exact;
        for member in &members {
            member_flow_ids.push(member.flow_id.clone());
            let prefix_end = member.chain.len() - suffix_len;
            unique_prefixes.push(member.chain[..prefix_end].to_vec());
            precision = precision.meet(member.precision);
        }

        groups.push(InspectFlowGroup {
            group_id: compute_structural_group_id(&member_flow_ids),
            member_flow_ids,
            shared_suffix,
            unique_prefixes,
            precision,
            member_count: members.len(),
        });
    }
    groups
}

const LARGE_BODY_LINE_THRESHOLD: usize = 200;
const LARGE_BODY_CONTEXT_LINES: u32 = 2;

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
fn render_function_source(
    ws: &Workspace,
    decl: &bonsai_lang_api::Decl,
    step_counter: &mut u32,
    flow_label: &str,
    advance_span: Option<bonsai_common::Span>,
    next_name: Option<String>,
    is_root: bool,
    is_target: bool,
    target_name: &str,
    sink_override: Option<MatchOverride>,
    filters: InspectFilters<'_>,
    full_source_for_large_bodies: bool,
) -> Option<InspectFunctionRendered> {
    let file = decl.span.file;
    let snapshot = ws.vfs().snapshot(file).ok()?;
    let src = snapshot.text.as_ref();
    let module_path = snapshot.path.display().to_string();

    let span_map = bonsai_common::cached_span_map_arc(file, snapshot.version, &snapshot.text);
    let body_span = decl.body_span.unwrap_or(decl.span);
    let start_line = span_map.line_col(body_span.start).line;
    let end_line = span_map.line_col(body_span.end.saturating_sub(1)).line;
    // Also include the def/header line if it sits above start_line.
    let header_line = span_map.line_col(decl.name_span.start).line;
    let first_line = header_line.min(start_line);

    // Line index of the advance span (the chain-relevant call).
    let advance_line = advance_span.map(|s| span_map.line_col(s.start).line);
    // Line index of the def header (for SOURCE / MATCH).
    let def_line = header_line;
    // Override MATCH line when the hit is a specific span inside the target
    // body (call/string/var/decorator hits).
    let sink_line = sink_override
        .as_ref()
        .map(|s| span_map.line_col(s.span.start).line);

    let lines_in_src: Vec<&str> = src.split('\n').collect();
    let mut rendered_lines: Vec<InspectLine> = Vec::new();
    // Clamp to file size.
    let end_clamped = end_line.min(lines_in_src.len() as u32);
    let local_index = ws.exact_decl_index_shared(file)?;

    // Structured-fact anchor lines for `--from` / `--to` markers.
    // Chain selection can match a needle via a propagated taint fact
    // that no SOURCE/MATCH/advance subject carries (a parameter read,
    // a concat operand, a call arg). Resolve the first in-range line
    // whose structured events mention the needle so the post-pass can
    // land the marker there. Nested decls are scanned too — for a
    // rendered `__module__` body the facts live in the functions the
    // module encloses. FROM anchors only on the chain's entry def and
    // TO only on the target def, so markers never scatter across hops.
    let fact_anchor = |needle: Option<&str>| -> Option<u32> {
        let needle = needle?;
        let mut best: Option<u32> = None;
        for nested in &local_index.defs {
            if nested.span.start < decl.span.start || nested.span.end > decl.span.end {
                continue;
            }
            find_fact_anchor_line(&nested.flow_events, needle, &span_map, &mut best);
        }
        best.filter(|line| *line >= first_line && *line <= end_clamped)
    };
    let from_anchor = if is_root { fact_anchor(filters.from) } else { None };
    let to_anchor = if is_target { fact_anchor(filters.to) } else { None };

    let large_body_elision = !full_source_for_large_bodies
        && end_clamped.saturating_sub(first_line) as usize > LARGE_BODY_LINE_THRESHOLD;
    let line_plan: Vec<Option<u32>> = if large_body_elision {
        let mut keep: ahash::AHashSet<u32> = ahash::AHashSet::new();
        let mut mark_window = |line: u32| {
            if line < first_line || line > end_clamped {
                return;
            }
            let start = line.saturating_sub(LARGE_BODY_CONTEXT_LINES).max(first_line);
            let end = line.saturating_add(LARGE_BODY_CONTEXT_LINES).min(end_clamped);
            for ln in start..=end {
                keep.insert(ln);
            }
        };
        mark_window(first_line);
        mark_window(def_line);
        if let Some(line) = advance_line {
            mark_window(line);
        }
        if let Some(line) = sink_line {
            mark_window(line);
        }
        if let Some(line) = from_anchor {
            mark_window(line);
        }
        if let Some(line) = to_anchor {
            mark_window(line);
        }
        let mut sorted: Vec<u32> = keep.into_iter().collect();
        sorted.sort_unstable();
        let mut plan = Vec::with_capacity(sorted.len() * 2);
        let mut prev: Option<u32> = None;
        for line in sorted {
            if let Some(prev_line) = prev {
                if line > prev_line + 1 {
                    plan.push(None);
                }
            }
            plan.push(Some(line));
            prev = Some(line);
        }
        plan
    } else {
        (first_line..=end_clamped).map(Some).collect()
    };

    for planned in line_plan {
        let Some(ln) = planned else {
            rendered_lines.push(InspectLine {
                line_no: rendered_lines
                    .last()
                    .map(|line| line.line_no.saturating_add(1))
                    .unwrap_or(first_line),
                text: "...".to_string(),
                step: None,
                annotation: None,
            });
            continue;
        };
        let idx = (ln.saturating_sub(1)) as usize;
        let text = lines_in_src
            .get(idx)
            .copied()
            .unwrap_or("")
            .trim_end()
            .to_string();

        let mut annotation: Option<String> = None;
        let mut step: Option<u32> = None;
        // Collect the "subjects" for this line — the identifiers the
        // annotation is about. Used to decide whether `--from` /
        // `--to` matched on THIS line so the marker lands somewhere
        // visible.
        let mut subjects: Vec<&str> = Vec::new();

        // Precedence: explicit sink span > target def-line sink > chain
        // advance > root source.
        if is_target && sink_line == Some(ln) {
            *step_counter += 1;
            step = Some(*step_counter);
            let label = sink_override
                .as_ref()
                .map(|s| s.label.clone())
                .unwrap_or_else(|| format!("MATCH: enter {target_name}"));
            annotation = Some(format!("[FLOW {flow_label} {label}]"));
            if let Some(ov) = sink_override.as_ref() {
                // Sub-hit MATCH (var / call / arg / string / decorator /
                // import): the target function's name is not the
                // subject of this line — only the hit's own structured
                // fact text is. Pushing `target_name` or the raw source
                // line here would cause filters to fire on incidental
                // text in the containing function instead of the
                // matched fact.
                for subject in &ov.marker_subjects {
                    subjects.push(subject.as_str());
                }
            } else {
                // Full-function entry MATCH — the target name IS the
                // subject.
                subjects.push(target_name);
            }
        } else if is_target && sink_line.is_none() && ln == def_line {
            *step_counter += 1;
            step = Some(*step_counter);
            annotation = Some(format!("[FLOW {flow_label} MATCH: enter {target_name}]"));
            subjects.push(target_name);
        } else if is_root && ln == def_line && advance_line.is_some() && advance_line != Some(ln) {
            *step_counter += 1;
            step = Some(*step_counter);
            annotation = Some(format!("[FLOW {flow_label} SOURCE: entry {}]", decl.name));
            subjects.push(&decl.name);
            // The def line also declares the entry's parameters — a
            // `--from` that selected this chain via a parameter name
            // must land its marker on the signature that declares it.
            for param in &decl.params {
                subjects.push(param.as_str());
            }
        } else if let (Some(al), Some(next)) = (advance_line, &next_name) {
            if ln == al {
                *step_counter += 1;
                step = Some(*step_counter);
                annotation = Some(format!("[FLOW {flow_label} -> {next}]"));
                // For advance lines the interesting subject is the
                // callee being advanced to — NOT the enclosing decl
                // name, which would fire the FROM marker on every
                // line in the function's body.
                subjects.push(next);
            }
        } else if advance_line.is_none() && !is_root && !is_target && ln == def_line {
            *step_counter += 1;
            step = Some(*step_counter);
            if let Some(next) = &next_name {
                // A MIDDLE function whose advance-call to `next` has no
                // single call line — this happens when the canonical
                // chain folds an INDIRECT edge (e.g. an inherited
                // `super.run()` hop collapsed into one `run`, so this
                // function reaches `next` through a base method rather
                // than a direct call here). The chain is still valid;
                // render the body with an advance marker at the def line
                // instead of dropping the ENTIRE flow render to the
                // compact same-file fallback (which would hide every
                // function body the reader came for).
                annotation = Some(format!("[FLOW {flow_label} -> {next} (indirect)]"));
                subjects.push(next);
            } else {
                // Chain TAIL that isn't the match target (happens
                // when the match point is an upstream function and
                // the chain runs past it to the natural leaf). The
                // step counter would otherwise stall at the caller's
                // advance — print an arrival marker so the tail's
                // body still has a numbered anchor and the folded
                // placeholder picks it up.
                annotation = Some(format!("[FLOW {flow_label} REACHES {}]", decl.name));
                subjects.push(&decl.name);
            }
        }

        // Append FROM: / TO: markers when the active filter needles
        // match something on this line. Works even if `annotation` is
        // None (we emit a standalone `[FLOW N FROM: X]` bracket), so
        // users can see exactly which line each filter landed on.
        let filter_marker = build_filter_marker(filters, &subjects, flow_label);
        if !filter_marker.is_empty() {
            annotation = Some(match annotation {
                Some(existing) => format!("{existing} {filter_marker}"),
                None => filter_marker,
            });
            if step.is_none() {
                *step_counter += 1;
                step = Some(*step_counter);
            }
        }

        rendered_lines.push(InspectLine {
            line_no: ln,
            text,
            step,
            annotation,
        });
    }

    attach_fact_anchored_marker(
        &mut rendered_lines,
        "FROM:",
        filters.from,
        from_anchor,
        flow_label,
    );
    attach_fact_anchored_marker(&mut rendered_lines, "TO:", filters.to, to_anchor, flow_label);

    // Collapse long runs of blank/unannotated lines between the first and
    // last annotated line: keep 1 blank line maximum between annotations so
    // the output stays readable on large bodies. Always keep the def line
    // and the annotated lines.
    let compressed = if large_body_elision {
        rendered_lines
    } else {
        compress_context(&rendered_lines)
    };

    let signature = build_signature(decl);
    Some(InspectFunctionRendered {
        module_path,
        owners: owner_context_for_decl(ws, decl, &span_map),
        name: decl.name.clone(),
        signature,
        start_line: first_line,
        end_line: end_clamped,
        lines: compressed,
    })
}

fn build_signature(decl: &bonsai_lang_api::Decl) -> String {
    if decl.params.is_empty() {
        format!("{}()", decl.name)
    } else {
        format!("{}({})", decl.name, decl.params.join(", "))
    }
}

fn compact_owner_prefix(func: &InspectFunctionRendered) -> String {
    if func.owners.is_empty() {
        String::new()
    } else {
        let names = func
            .owners
            .iter()
            .map(|owner| owner.name.as_str())
            .collect::<Vec<_>>()
            .join("::");
        format!("{names}::")
    }
}

fn owner_context_for_decl(
    ws: &Workspace,
    decl: &bonsai_lang_api::Decl,
    span_map: &bonsai_common::SpanMap,
) -> Vec<InspectOwnerRendered> {
    let global = ws.compiler_header_index();
    let mut owners: Vec<&bonsai_lang_api::Decl> = Vec::new();

    let mut parent = decl.parent;
    while let Some(parent_symbol) = parent {
        let Some(parent_decl) = global.decl_of(parent_symbol) else {
            break;
        };
        if is_renderable_owner(parent_decl.kind) {
            owners.push(parent_decl);
        }
        parent = parent_decl.parent;
    }

    owners.sort_by(|a, b| {
        let a_span = a.body_span.unwrap_or(a.span);
        let b_span = b.body_span.unwrap_or(b.span);
        a_span
            .start
            .cmp(&b_span.start)
            .then_with(|| (b_span.end - b_span.start).cmp(&(a_span.end - a_span.start)))
            .then_with(|| a.name.cmp(&b.name))
    });
    owners.dedup_by_key(|d| d.symbol);

    owners
        .into_iter()
        .map(|owner| InspectOwnerRendered {
            kind: owner_kind_label(owner.kind).to_string(),
            name: owner.name.clone(),
            line: span_map.line_col(owner.name_span.start).line,
        })
        .collect()
}

fn is_renderable_owner(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Module
            | DeclKind::Namespace
            | DeclKind::Class
            | DeclKind::Struct
            | DeclKind::Trait
            | DeclKind::Interface
            | DeclKind::Enum
    )
}

fn owner_kind_label(kind: DeclKind) -> &'static str {
    match kind {
        DeclKind::Module => "module",
        DeclKind::Namespace => "namespace",
        DeclKind::Class => "class",
        DeclKind::Struct => "struct",
        DeclKind::Trait => "trait",
        DeclKind::Interface => "interface",
        DeclKind::Enum => "enum",
        _ => "owner",
    }
}

/// Compress runs of >3 consecutive unannotated lines into a single "..." row,
/// so big function bodies stay readable without hiding annotated context.
fn compress_context(lines: &[InspectLine]) -> Vec<InspectLine> {
    let mut out: Vec<InspectLine> = Vec::with_capacity(lines.len());
    let mut run = 0usize;
    for l in lines {
        if l.annotation.is_none() && l.text.trim().is_empty() {
            if run >= 1 {
                continue; // skip extra blanks
            }
            run += 1;
            out.push(l.clone());
        } else {
            run = 0;
            out.push(l.clone());
        }
    }
    out
}

#[cfg(test)]
#[path = "inspect_tests.rs"]
mod tests;
