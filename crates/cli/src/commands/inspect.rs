//! `bonsai-ninja inspect` — render every call chain that reaches a
//! target symbol, each with source-inlined function bodies and step
//! annotations. JSON output is structurally the same, keyed by
//! `InspectReport`.

use anyhow::{Context, Result};
use bonsai_lang_api::{DeclKind, FlowEvent, RefKind};
use bonsai_sdk::Workspace;
use bonsai_sdk::{
    chain_to_names, compute_flow_id, compute_flow_labels_from, compute_group_id,
    find_call_span_to_func_uncached, func_display_name, CallEdgeResolver, CallPathTruncation, ChainCache,
    ResolvedChain,
};
use comfy_table::Cell;
use serde::Serialize;

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
    format_span, nearest_names, open_project_index_only as open_project, page_info_to_json,
    paged_json_incomplete_reasons, short_file, truncate,
};

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
    /// `Some("max-flows cap")` / `Some("entry-probe budget")` when chain
    /// enumeration hit a cap and dropped at least one flow that exists
    /// in the call graph; `None` when every reachable chain was
    /// enumerated. Surfaced in the text output so users know to re-run
    /// with `--all` (or a higher `--max-flows`) when chains were lost.
    #[serde(skip_serializing_if = "Option::is_none")]
    truncated_by: Option<String>,
}

/// One start→sink execution flow, with the full call chain and, for each
/// function in the chain, its source code with numbered annotations on the
/// chain-advancing lines.
#[derive(Serialize, Clone)]
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

#[derive(Serialize, Clone)]
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

#[derive(Serialize, Clone)]
pub(crate) struct InspectOwnerRendered {
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) line: u32,
}

#[derive(Serialize, Clone)]
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

#[derive(Serialize)]
struct InspectReport {
    query: String,
    regex: bool,
    kind_filter: Vec<String>,
    /// Top-level completion verdict for the inspect result set. False
    /// means at least one requested occurrence or flow evidence set is
    /// a capped prefix and downstream tooling must not treat the JSON
    /// as complete.
    analysis_complete: bool,
    analysis_incomplete_reasons: Vec<String>,
    /// Per-decl flow rendering: each matching decl gets its own
    /// `InspectOut` with chain-enumerated flows.
    decl_hits: Vec<InspectOut>,
    /// Non-decl occurrences (calls, strings, vars, imports, args, refs,
    /// decorators) with the enclosing function and a chain preview.
    hits: Vec<HitOut>,
    summary: InspectReportSummary,
}

#[derive(Serialize)]
struct InspectReportSummary {
    total_decl_hits: usize,
    total_hits: usize,
    hit_counts_by_kind: serde_json::Value,
    /// Number of non-decl hits whose flow evidence is known to be a
    /// capped prefix rather than a complete chain/path set.
    #[serde(skip_serializing_if = "is_zero_usize", default)]
    flow_truncated_hits: usize,
    /// Stable, human-readable set of truncation reasons observed
    /// across occurrence-hit flow evidence.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    flow_truncation_reasons: Vec<String>,
    /// `true` when the non-decl-hit pass hit `--max-hits` and dropped
    /// at least one occurrence. Surfaced in the text output so users
    /// know to re-run with `--all` (or a higher `--max-hits`).
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    hits_truncated: bool,
    /// Exact bounded-mode reason(s) for `hits_truncated`. The normal
    /// result cap and the filtered-candidate attempt cap are separate
    /// so machine consumers can distinguish "shown hit list is full"
    /// from "the query rejected too many candidates before reaching
    /// the shown-hit cap".
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    hit_truncation_reasons: Vec<String>,
    /// Number of non-decl candidates that reached the flow/filter
    /// phase. Present only when truncation happened so capped runs are
    /// auditable without noisy default metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    hit_candidates_attempted: Option<usize>,
    /// The candidate-attempt cap in effect for this run. Present only
    /// when truncation happened.
    #[serde(skip_serializing_if = "Option::is_none")]
    hit_attempt_cap: Option<usize>,
}

#[derive(Serialize)]
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
    /// Present when this hit's flow list is known to be incomplete
    /// because chain or downstream path enumeration hit a cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    flow_truncated_by: Option<String>,
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
        }
    }
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
pub(crate) fn cmd_inspect(
    root: &std::path::Path,
    pattern: Option<&str>,
    is_regex: bool,
    kind_filter: &[String],
    filters: InspectFilters<'_>,
    max_flows: usize,
    max_entry_probes: usize,
    max_hits: usize,
    render: InspectRenderOptions,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
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
    let (project, _footer) = open_project(root)?;
    let ws = project.workspace();
    let global = ws.db().global_index();
    let full_source_for_large_bodies =
        paging_cfg.all || render.flow_id_filter.is_some() || render.group_id_filter.is_some();
    // One cache per `inspect` run. `inspect --query system` in Redis
    // resolves 50+ hits to the same handful of enclosing functions, so
    // per-target memoization here turns an N × call-graph walk into
    // single-shot lookups after the first hit on each function.
    // `--no-cache` / `BONSAI_NO_CACHE` swaps this for a pass-through
    // variant that always takes the cold path.
    let chain_cache = build_chain_cache(ws);
    let (downstream_max_extra, downstream_max_paths) = if paging_cfg.all {
        (usize::MAX, usize::MAX)
    } else {
        (6, 12)
    };
    // Edge resolvability is queried heavily when `inspect` extends raw
    // upstream chains into concrete downstream call paths. Cache the
    // per-file alias maps and per-edge span lookups for this invocation;
    // otherwise hub queries such as Redis's `--query system` repeatedly
    // rescan the same parse trees while checking the same edges.
    let mut edge_resolver = CallEdgeResolver::new(ws);

    // When no query is supplied, `inspect` becomes a filter-driven
    // enumeration: every fact matches the primary matcher, and the
    // `--from` / `--to` / `--file` / `--in-fn` / `--kind` filters do
    // the narrowing.
    let matcher: Matcher = match pattern {
        Some(p) => build_matcher(p, is_regex)?,
        None => Matcher::MatchAll,
    };
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
    let default_exclude_kinds: &[&str] = if pattern.is_some() {
        &["decorator", "ref"]
    } else {
        &[]
    };
    let want = |k: &str| {
        if kinds.is_empty() {
            !default_exclude_kinds.contains(&k)
        } else {
            kinds.contains(k)
        }
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
    let emit_decls = want("decl")
        && (!matcher.is_universal()
            || kinds.contains("decl")
            || render.flow_id_filter.is_some()
            || render.group_id_filter.is_some());
    let mut decl_hits: Vec<InspectOut> = Vec::new();
    // Global flow counter — advances as each hit's flows are labeled so
    // "FLOW 1", "FLOW 2", "FLOW 3", … stay sequential across every hit
    // in the output rather than every hit restarting at "FLOW 1".
    let mut flow_counter: u32 = 1;
    // Iterate files by PATH order (not FileId). This matches the final
    // display sort, so the flow counter advances in the same order hits
    // are displayed — keeping `FLOW 1`, `FLOW 2`, … sequential top-to-
    // bottom in the output.
    let files_in_path_order: Vec<bonsai_common::FileId> = {
        let mut v: Vec<(String, bonsai_common::FileId)> = global
            .all_files()
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
    if emit_decls {
        let mut matched_decls: Vec<bonsai_lang_api::Decl> = Vec::new();
        for file in files_in_path_order.iter().copied() {
            for d in global.decls_in(file) {
                if matcher.is_match(&d.name) {
                    matched_decls.push(d.clone());
                }
            }
        }
        // Prefer callables first so the most interesting flows land on top.
        matched_decls.sort_by_key(|d| match d.kind {
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor => 0,
            DeclKind::Class | DeclKind::Struct => 1,
            _ => 2,
        });
        let decl_bar = progress::progress_bar("inspecting decls", matched_decls.len() as u64);
        for decl in &matched_decls {
            decl_bar.inc(1);
            let (path, line, col) = format_span(&decl.name_span, ws);
            // `--file` filters out decl hits whose file path doesn't
            // match; skip early so we don't enumerate chains for dropped
            // decls.
            if filters.file.is_some_and(|f| !path.contains(f)) {
                continue;
            }
            // Resolved-graph traversal: enumerate chains in `FuncId`
            // space so name collisions across classes / modules can't
            // stitch unrelated decls into the same chain.
            let target_func = bonsai_common::FuncId::new(decl.symbol.raw());
            let (chains_r, decl_truncation) =
                chain_cache.chains_resolved(target_func, max_flows, max_entry_probes);
            // Precompute the downstream user-fn closure of the decl once.
            // Each chain is extended with this so the filter match space
            // equals what the renderer will inline.
            let _decl_downstream_r =
                chain_cache.downstream_resolved(target_func, downstream_max_extra, downstream_max_paths);
            // For decl hits the "hit text" is the decl name itself; pass
            // it so `--to <decl>` still matches even when the chain has
            // just one element (the decl is a root).
            //
            // When neither `--from` nor `--to` is set, `chain_matches_filters`
            // is a no-op — every chain passes. Skip the whole
            // extend + reachable-names compute in that case. This is
            // loss-free: the filter result is guaranteed to be `true`,
            // so we'd have kept every chain anyway.
            // Semantic-only default: drop chains whose worst-case
            // precision is outside `Exact` / `Narrowed`, and drop
            // chains with any unresolvable edge. Those shapes are not
            // semantic evidence for inspect flows.
            let chains_r: Vec<ResolvedChain> = chains_r
                .into_iter()
                .filter(|c| {
                    matches!(
                        c.precision,
                        bonsai_common::Precision::Exact | bonsai_common::Precision::Narrowed,
                    ) && edge_resolver.chain_edges_resolvable(&c.funcs)
                })
                .collect();
            if chains_r.is_empty() {
                continue;
            }
            // Enumerate every resolvable downstream call path per raw
            // chain — each DFS leaf becomes its own extended chain.
            // Only paths with actual syntactic edges survive; no
            // reachability-bag `(over-approx)` annotations make it
            // into render.
            let mut decl_truncation_labels = Vec::new();
            push_chain_truncation(&mut decl_truncation_labels, decl_truncation);
            let mut extended_chains_r: Vec<(Vec<bonsai_common::FuncId>, bonsai_common::Precision)> =
                Vec::new();
            for chain in &chains_r {
                let (paths, path_truncation) = edge_resolver.enumerate_call_paths_from_with_truncation(
                    &chain_cache,
                    &chain.funcs,
                    downstream_max_extra,
                    downstream_max_paths,
                );
                push_call_path_truncation(&mut decl_truncation_labels, path_truncation);
                extended_chains_r.extend(paths.into_iter().map(|path| (path, chain.precision)));
            }
            if filters.from.is_some() || filters.to.is_some() {
                chain_cache
                    .prewarm_taint_facts(extended_chains_r.iter().filter_map(|(c, _)| c.first().copied()));
                extended_chains_r.retain(|(path, _)| {
                    // Chain function names — the syntactically
                    // connected hops. Taint facts — tokens the
                    // interprocedural / structural pass actually
                    // surfaced for the chain's entry. The filter
                    // runs on the already-extended path so a
                    // `--to X` query only keeps chains where the
                    // call-path tail actually reaches X (not just
                    // the raw caller chain).
                    let mut chain_names: Vec<String> =
                        path.iter().map(|&f| func_display_name(ws, f)).collect();
                    // Extend with tail's direct callees — `--to
                    // <external-sink>` (`system`, `exec`,
                    // `os.system`) must land when the sink is a
                    // callee of the chain tail rather than a user-
                    // defined hop. Taint facts alone leak sibling
                    // branches; direct callees of the tail are
                    // strict to this exact call path.
                    if let Some(&tail) = path.last() {
                        for c in chain_cache.callees_of_resolved(tail) {
                            let name = func_display_name(ws, c);
                            if !name.is_empty() && !chain_names.contains(&name) {
                                chain_names.push(name);
                            }
                        }
                    }
                    // Path-only structural facts avoid sibling-branch
                    // leakage while still allowing kind filters to land
                    // on args/calls/reads/writes in intermediate hops.
                    let taint_facts_fn = || chain_cache.chain_structural_tokens(path);
                    bonsai_sdk::chain_matches_filters(
                        Some(&decl.name),
                        &chain_names,
                        &taint_facts_fn,
                        filters.to_sdk(),
                    )
                });
                if extended_chains_r.is_empty() {
                    continue;
                }
            }
            // Compute flow labels on display-name projections so
            // branch-split grouping stays stable with what users see.
            let extended_names_for_labels: Vec<Vec<String>> = extended_chains_r
                .iter()
                .map(|(c, _)| chain_to_names(ws, c))
                .collect();
            let labels = compute_flow_labels_from(&extended_names_for_labels, &mut flow_counter);
            let call_spans: Vec<Vec<Option<bonsai_common::Span>>> = extended_chains_r
                .iter()
                .map(|(chain, _)| edge_resolver.call_spans_for_chain(chain))
                .collect();
            // Parallel render across chains. Source inlining +
            // FROM/TO-marker walks dominate inspect's wall time on
            // hub-sink queries (TS compiler `inspect parse` spends
            // ~120 s here). Each chain's render is pure — reads
            // workspace VFS (`Sync`), writes no shared state — so
            // rayon's `par_iter` gives a near-linear core speedup.
            //
            // Determinism: flow labels were assigned serially above
            // (`compute_flow_labels_from` increments a counter in
            // order), and `.collect()` on a parallel iterator
            // preserves iteration order. Output is byte-identical
            // to the serial loop regardless of thread count.
            use rayon::prelude::*;
            let flows: Vec<InspectFlowRendered> = extended_chains_r
                .par_iter()
                .zip(labels.par_iter())
                .zip(call_spans.par_iter())
                .enumerate()
                .filter_map(|(i, (((extended_r, prec), label), spans))| {
                    let match_idx = extended_r
                        .iter()
                        .position(|&f| f == target_func)
                        .unwrap_or(extended_r.len().saturating_sub(1));
                    let match_at = Some((
                        match_idx,
                        MatchOverride {
                            span: decl.name_span,
                            label: format!("MATCH: enter {}", decl.name),
                        },
                    ));
                    render_flow_with_cached_call_spans(
                        ws,
                        extended_r,
                        spans,
                        (i + 1) as u32,
                        label,
                        *prec,
                        match_at,
                        filters,
                        true,
                        full_source_for_large_bodies,
                    )
                })
                .collect();
            let direct_callers = semantic_direct_callers(ws, chain_cache.resolved_graph(), target_func);
            let callees_out = semantic_callees(ws, chain_cache.resolved_graph(), target_func);
            let unique_entries: ahash::AHashSet<&String> =
                flows.iter().filter_map(|f| f.chain.first()).collect();
            let summary = InspectSummary {
                total_flows: flows.len() as u32,
                max_chain_depth: flows.iter().map(|f| f.chain.len() as u32).max().unwrap_or(0),
                unique_entry_points: unique_entries.len() as u32,
                truncated_by: truncation_summary(&decl_truncation_labels),
            };
            let groups = group_flows_by_suffix(&flows);
            decl_hits.push(InspectOut {
                symbol: decl.name.clone(),
                kind: format!("{:?}", decl.kind).to_lowercase(),
                file: path,
                line,
                column: col,
                params: decl.params.clone(),
                direct_callers,
                callees: callees_out,
                flows,
                groups,
                summary,
            });
        }
        decl_bar.finish_and_clear();
    }

    // ----- 2. Non-decl hits: calls, assignments, strings, imports, args, decorators, refs.
    let mut hits: Vec<HitOut> = Vec::new();
    // Warm the resolved graph eagerly so each `chain_cache.chains_resolved(...)`
    // below is a pure memoized lookup (no lazy-init check).
    let _ = chain_cache.resolved_graph();
    // Counts candidates we silently dropped because `max_hits` was
    // already saturated. An overestimate (some of these would also
    // have been filtered out by `--from`/`--to`/etc.) but the right
    // semantics for the truncation flag: "at least one candidate was
    // not given a chance to land in the output."
    let hits_truncated_by_output_cap = std::cell::Cell::new(false);
    let hits_truncated_by_attempt_cap = std::cell::Cell::new(false);
    // Independent attempt counter: every call that passed the
    // pre-filter checks (file / in-fn) bumps it, regardless of
    // whether the chain filter later accepts or rejects the hit.
    // Without an attempt cap, `--from X` queries can walk an
    // unbounded portion of the workspace before the `out.len()`
    // cap fires — on large repos (zod, jackson) this turns a
    // 200-hit budget into a 5000-hit walk and minutes of render
    // time. The 5x multiplier on `max_hits` is a soft headroom
    // so the filter still has room to skip rejected hits without
    // exploding into the worst case.
    let attempt_cap = max_hits.saturating_mul(5).max(max_hits);
    let hits_attempted = std::cell::Cell::new(0_usize);
    let mut push_hit = |kind: &str,
                        text: String,
                        span: bonsai_common::Span,
                        containing: Option<(bonsai_common::FuncId, String)>,
                        assignment_source_call: bool,
                        out: &mut Vec<HitOut>| {
        if out.len() >= max_hits {
            hits_truncated_by_output_cap.set(true);
            return;
        }
        if hits_attempted.get() >= attempt_cap {
            hits_truncated_by_attempt_cap.set(true);
            return;
        }
        let (path, line, col) = format_span(&span, ws);
        // `--file` filter (substring) on the hit's source path.
        if filters.file.is_some_and(|f| !path.contains(f)) {
            return;
        }
        // `--in-fn` filter: hit must live inside a function whose name
        // contains the needle.
        if let Some(needle) = filters.in_fn {
            if !containing.as_ref().is_some_and(|(_, name)| name.contains(needle)) {
                return;
            }
        }
        // Count this candidate toward the cap regardless of whether
        // the chain filter accepts or rejects it. See the
        // `hits_attempted` declaration for why.
        hits_attempted.set(hits_attempted.get() + 1);
        let containing_name: Option<&str> = containing.as_ref().map(|(_, n)| n.as_str());
        let containing_id: Option<bonsai_common::FuncId> = containing.as_ref().map(|(f, _)| *f);

        // Resolved-graph traversal: enumerate chains in `FuncId`
        // space so name collisions across classes / modules can't
        // stitch unrelated decls into the same chain.
        let containing_downstream_r: Vec<bonsai_common::FuncId> = containing_id
            .map(|f| chain_cache.downstream_resolved(f, downstream_max_extra, downstream_max_paths))
            .unwrap_or_default();
        // Populated by the filter pass below when `--from` / `--to`
        // is set — the specific reachable name (or hit text) that
        // matched each needle, along with its source location.
        // Threaded into `HitOut` so the occurrence-hits table can
        // summarise each flow at a glance: "this hit connects
        // `handleRequest (gateway.swift:5:3)` → `Process
        // (AuthService.swift:23:24)` on line 23:24".
        let mut hit_from_match: Option<FilterMatch> = None;
        let mut hit_to_match: Option<FilterMatch> = None;
        let mut flow_truncation_labels: Vec<&'static str> = Vec::new();
        let mut call_hit_targets: Vec<(bonsai_common::FuncId, bonsai_common::Precision)> = Vec::new();
        let chains_r: Vec<ResolvedChain> = if let Some(c_id) = containing_id {
            let mut seed = Vec::new();
            let mut seed_from_call_target = false;
            if kind == "call" {
                call_hit_targets = resolve_call_hit_targets(&chain_cache, c_id, span);
                for (target, direct_precision) in call_hit_targets.iter().copied() {
                    let (raw, truncation) = chain_cache.chains_resolved(target, max_flows, max_entry_probes);
                    push_chain_truncation(&mut flow_truncation_labels, truncation);
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
                        .filter(|chain| chain.funcs.contains(&c_id))
                        .collect();
                    if target_seed.is_empty() && target != c_id {
                        target_seed.push(ResolvedChain {
                            funcs: vec![c_id, target],
                            precision: direct_precision,
                        });
                    }
                    seed.extend(target_seed);
                }
                seed = dedupe_chains_keep_best_precision(seed);
                seed_from_call_target = !seed.is_empty();
            }
            if seed.is_empty() {
                let (raw, truncation) = chain_cache.chains_resolved(c_id, max_flows, max_entry_probes);
                push_chain_truncation(&mut flow_truncation_labels, truncation);
                // Ensure the containing function itself is a candidate
                // chain even when it's an entry point (no upstream
                // callers). Without this synthetic chain, a sink that
                // lives in an entry function would have zero chains and
                // get dropped by the filter below. The synthetic seed is
                // `Exact` because there's no upstream edge to introduce
                // uncertainty.
                seed = if raw.is_empty() {
                    vec![ResolvedChain {
                        funcs: vec![c_id],
                        precision: bonsai_common::Precision::Exact,
                    }]
                } else {
                    raw
                };
            }
            // Semantic-only default: drop chains whose worst-case
            // precision is outside `Exact` / `Narrowed`, and drop
            // chains with any unresolvable edge. See the decl-hit
            // branch above for the rationale.
            let seed: Vec<ResolvedChain> = seed
                .into_iter()
                .filter(|c| {
                    let precise = matches!(
                        c.precision,
                        bonsai_common::Precision::Exact | bonsai_common::Precision::Narrowed,
                    );
                    precise && (seed_from_call_target || edge_resolver.chain_edges_resolvable(&c.funcs))
                })
                .collect();
            // Per-chain filter: extend with the containing function's
            // downstream (what the renderer will inline), compute the set
            // of names that extended chain visibly touches, and require
            // both `--from` and `--to` to appear there (or in the hit
            // text). Scoped strictly to the rendered flow — no sibling
            // branches leak in.
            //
            // When neither `--from` nor `--to` is set, the filter is a
            // no-op. Skip the extend + reachable compute entirely: the
            // output is identical, we just save per-hit cost on the
            // cold path where the user didn't ask for filtering.
            if (filters.from.is_some() || filters.to.is_some()) && kind != "call" {
                // Track the first reachable FuncId per chain whose
                // display name satisfies `--from` / `--to`, then
                // resolve back to a location so the hits table can
                // show `name (file:line:col)`. First match wins —
                // the row is a single line; multiple matches collapse
                // to the nearest upstream/downstream respectively.
                let mut seen_from: Option<FilterMatch> = None;
                let mut seen_to: Option<FilterMatch> = None;
                // The interprocedural per-entry compute is
                // independent across entries and CPU-bound. Pre-warm
                // the cache in parallel so the serial filter loop
                // that follows sees a hot cache on every reachability
                // miss. On requests's `--from session` (~5k chains,
                // ~100 unique entries) this cuts wall time roughly
                // in half.
                chain_cache.prewarm_taint_facts(seed.iter().filter_map(|c| c.funcs.first().copied()));
                let kept: Vec<ResolvedChain> = seed
                    .into_iter()
                    .filter(|chain_r| {
                        let mut extended = chain_r.funcs.clone();
                        for d in &containing_downstream_r {
                            if !extended.contains(d) {
                                extended.push(*d);
                            }
                        }
                        // Chain function names — syntactically
                        // connected hops. Taint facts — tokens the
                        // interprocedural pass actually propagated.
                        // Lexical reachability was removed — it
                        // matched unrelated imports in the same file.
                        let chain_names: Vec<String> =
                            extended.iter().map(|&f| func_display_name(ws, f)).collect();
                        let taint_facts_fn = || chain_cache.chain_taint_facts(&extended);
                        if !bonsai_sdk::chain_matches_filters(
                            Some(&text),
                            &chain_names,
                            &taint_facts_fn,
                            filters.to_sdk(),
                        ) {
                            return false;
                        }
                        // Parallel FuncId list for resolving the
                        // matched FROM/TO to a `(file, line)` for the
                        // hits table — we only need FuncIds for
                        // names that happen to be function-valued,
                        // so walk the resolved reachable set and
                        // find the first matching name.
                        let reachable_r = chain_cache.reachable_resolved(&extended);
                        let func_names: Vec<String> =
                            reachable_r.iter().map(|&f| func_display_name(ws, f)).collect();
                        if seen_from.is_none() {
                            if let Some(needle) = filters.from {
                                // Prefer a function-valued match on
                                // the chain itself (file:line can be
                                // resolved via FuncId). Fall back to
                                // a taint-fact token when the needle
                                // is a propagated value rather than a
                                // function on the path.
                                seen_from = reachable_r
                                    .iter()
                                    .zip(func_names.iter())
                                    .find(|(_, n)| name_token_match(n, needle))
                                    .map(|(&f, n)| build_filter_match(ws, Some(f), n.clone()))
                                    .or_else(|| {
                                        // Sort token candidates
                                        // before picking the "first"
                                        // match. AHashMap iteration
                                        // depends on the process's
                                        // random hash seed — sorting
                                        // restores a stable choice.
                                        let taint = taint_facts_fn();
                                        let mut tokens: Vec<&String> =
                                            taint.by_kind.values().flat_map(|t| t.iter()).collect();
                                        tokens.sort();
                                        tokens
                                            .into_iter()
                                            .find(|t| name_token_match(t, needle))
                                            .map(|t| build_filter_match(ws, None, t.clone()))
                                    });
                            }
                        }
                        if seen_to.is_none() {
                            if let Some(needle) = filters.to {
                                seen_to = reachable_r
                                    .iter()
                                    .zip(func_names.iter())
                                    .find(|(_, n)| name_token_match(n, needle))
                                    .map(|(&f, n)| build_filter_match(ws, Some(f), n.clone()))
                                    .or_else(|| {
                                        let taint = taint_facts_fn();
                                        let mut tokens: Vec<&String> =
                                            taint.by_kind.values().flat_map(|t| t.iter()).collect();
                                        tokens.sort();
                                        tokens
                                            .into_iter()
                                            .find(|t| name_token_match(t, needle))
                                            .map(|t| build_filter_match(ws, None, t.clone()))
                                    })
                                    .or_else(|| {
                                        // `--to` also matches the hit
                                        // text itself.
                                        if name_token_match(&text, needle) {
                                            Some(build_filter_match(ws, None, text.clone()))
                                        } else {
                                            None
                                        }
                                    });
                            }
                        }
                        true
                    })
                    .collect();
                hit_from_match = seen_from;
                hit_to_match = seen_to;
                kept
            } else {
                seed
            }
        } else {
            Vec::new()
        };
        // If chain filters rejected every chain AND the user explicitly
        // asked for --from / --to, drop this hit entirely (they didn't
        // want to see it).
        if chains_r.is_empty() && (filters.from.is_some() || filters.to.is_some()) {
            return;
        }
        let chains_preview: Vec<String> = chains_r
            .iter()
            .take(6)
            .map(|c| chain_to_names(ws, &c.funcs).join(" -> "))
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
        if working_chains_r.len() > max_flows {
            push_truncation_label(&mut flow_truncation_labels, "max-flows cap");
        }
        let mut extended_chains_r: Vec<(Vec<bonsai_common::FuncId>, bonsai_common::Precision)> = Vec::new();
        let extend_downstream = kind != "call" || !call_hit_targets.is_empty() || assignment_source_call;
        if extend_downstream {
            for chain in working_chains_r.iter().take(max_flows) {
                let (paths, path_truncation) = edge_resolver.enumerate_call_paths_from_with_truncation(
                    &chain_cache,
                    &chain.funcs,
                    downstream_max_extra,
                    downstream_max_paths,
                );
                push_call_path_truncation(&mut flow_truncation_labels, path_truncation);
                extended_chains_r.extend(paths.into_iter().map(|path| (path, chain.precision)));
            }
        } else {
            extended_chains_r.extend(
                working_chains_r
                    .iter()
                    .take(max_flows)
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
                bonsai_sdk::chain_matches_filters(
                    Some(&text),
                    &chain_names,
                    &taint_facts_fn,
                    filters.to_sdk(),
                )
            });
            if extended_chains_r.is_empty() {
                return;
            }
        }
        let extended_names_for_labels: Vec<Vec<String>> = extended_chains_r
            .iter()
            .map(|(c, _)| chain_to_names(ws, c))
            .collect();
        let labels = compute_flow_labels_from(&extended_names_for_labels, &mut flow_counter);
        let call_spans: Vec<Vec<Option<bonsai_common::Span>>> = extended_chains_r
            .iter()
            .map(|(chain, _)| edge_resolver.call_spans_for_chain(chain))
            .collect();
        // Parallel render — see the decl-hit path above for the
        // determinism argument. Same shape, same guarantee.
        use rayon::prelude::*;
        let flows: Vec<InspectFlowRendered> = extended_chains_r
            .par_iter()
            .zip(labels.par_iter())
            .zip(call_spans.par_iter())
            .enumerate()
            .filter_map(|(i, (((extended_r, prec), label), spans))| {
                let match_idx = containing_id
                    .and_then(|f| extended_r.iter().position(|&g| g == f))
                    .unwrap_or(extended_r.len().saturating_sub(1));
                render_flow_with_cached_call_spans(
                    ws,
                    extended_r,
                    spans,
                    (i + 1) as u32,
                    label,
                    *prec,
                    Some((match_idx, match_override.clone())),
                    filters,
                    true,
                    full_source_for_large_bodies,
                )
            })
            .collect();
        if flows.is_empty() && (filters.from.is_some() || filters.to.is_some()) {
            return;
        }
        let groups = group_flows_by_suffix(&flows);
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
            flow_truncated_by: truncation_summary(&flow_truncation_labels),
            from_match: hit_from_match,
            to_match: hit_to_match,
        });
    };

    let hit_bar = progress::progress_bar("scanning files", files_in_path_order.len() as u64);
    for file in files_in_path_order.iter().copied() {
        hit_bar.inc(1);
        let Some(idx) = global.file_index(file) else {
            continue;
        };
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
                &matcher,
                &kinds,
                &mut hits,
                &mut push_hit,
            );
        }

        // Strings.
        if want("string") {
            for s in &idx.strings {
                if matcher.is_match(&s.text) {
                    let enclosing = chain_cache.enclosing_func(file, &decls_in_file, s.span);
                    push_hit("string", s.text.clone(), s.span, enclosing, false, &mut hits);
                }
            }
        }

        // Refs (covers decorators via RefKind::Decorator, plus residual call refs).
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
            if !want(kind_tag) {
                continue;
            }
            if matcher.is_match(&r.name) {
                let enclosing = chain_cache.enclosing_func(file, &decls_in_file, r.span);
                push_hit(kind_tag, r.name.clone(), r.span, enclosing, false, &mut hits);
            }
        }

        // Imports (fallback to generic scan when the adapter didn't provide any).
        if want("import") {
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
            for imp in &imports_vec {
                if matcher.is_match(&imp.module) {
                    push_hit("import", imp.module.clone(), imp.span, None, false, &mut hits);
                }
            }
        }
    }
    hit_bar.finish_and_clear();

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
    let (flow_truncated_hits, flow_truncation_reasons) = occurrence_flow_truncation_summary(&hits);
    let hits_truncated = hits_truncated_by_output_cap.get() || hits_truncated_by_attempt_cap.get();
    let summary = InspectReportSummary {
        total_decl_hits: decl_hits.len(),
        total_hits: hits.len(),
        hit_counts_by_kind: sorted_hit_counts_json(&hits),
        flow_truncated_hits,
        flow_truncation_reasons,
        hits_truncated,
        hit_truncation_reasons: inspect_hit_truncation_reasons(
            hits_truncated_by_output_cap.get(),
            hits_truncated_by_attempt_cap.get(),
        ),
        hit_candidates_attempted: hits_truncated.then_some(hits_attempted.get()),
        hit_attempt_cap: hits_truncated.then_some(attempt_cap),
    };

    let mut report = InspectReport {
        query: pattern.unwrap_or("").to_string(),
        regex: is_regex,
        kind_filter: kind_filter.iter().map(String::from).collect(),
        analysis_complete: false,
        analysis_incomplete_reasons: Vec::new(),
        decl_hits,
        hits,
        summary,
    };
    refresh_inspect_completeness(&mut report);

    // `--flow <id>`: keep only flows whose stable id matches, then
    // drop hit / decl records that no longer have any flows. Runs
    // AFTER chain enumeration so the filter is purely a render-time
    // narrow — it can't lose a flow that was already caught by
    // max-flows truncation, but that's an intentional trade (the
    // truncation banner will still surface in that case).
    if let Some(target_id) = render.flow_id_filter.as_deref() {
        apply_flow_id_filter(&mut report, target_id);
        if report.decl_hits.is_empty() && report.hits.is_empty() {
            anyhow::bail!(
                "no flow matching `{target_id}` in this workspace + query \
                 combination. Flow ids are printed next to every `FLOW N` \
                 header in text output and in `flow_id` in JSON output."
            );
        }
    }
    // `--group <id>`: mirror of `--flow <id>` at the group level. Must
    // run after flow-id filtering (so combining `--flow` and `--group`
    // narrows to the intersection) and before render so the text /
    // JSON paths see the reduced set.
    if let Some(target_id) = render.group_id_filter.as_deref() {
        apply_group_id_filter(&mut report, target_id);
        if report.decl_hits.is_empty() && report.hits.is_empty() {
            anyhow::bail!(
                "no flow group matching `{target_id}` in this workspace + \
                 query combination. Group ids are printed next to every \
                 `GROUP N` header in grouped view (`--view grouped` / \
                 `--view auto`) and in `group_id` in JSON output."
            );
        }
    }

    if filters.from.is_some() && filters.to.is_some() {
        report.hits.retain(|hit| !hit.flows.is_empty());
        rebuild_report_summary(&mut report);
    }

    // No matches? Print a friendly zero-hits line with close-name
    // suggestions — don't raise an error. Zero hits is a legit outcome
    // for a substring / regex query; only commands that take a concrete
    // symbol (trace, dump-hir, refs) should treat it as usage error.
    //
    // JSON / SARIF output stays machine-parseable: emit `[]` (or the
    // empty wrapped page) instead of the human-readable
    // "no matches for ..." line so downstream tools that pipe through
    // `jq` / programmatic consumers don't have to special-case empty
    // results.
    if report.decl_hits.is_empty() && report.hits.is_empty() {
        if matches!(format, BrowseFormat::Json | BrowseFormat::Sarif) {
            cli_println!("[]");
            return Ok(());
        }
        let kind_label = if kind_filter.is_empty() {
            String::new()
        } else {
            format!("kinds={:?} ", kind_filter)
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
        BrowseFormat::Json | BrowseFormat::Sarif => {
            // `--context` / `--page` on JSON emits a paged view
            // of `decl_hits` (the structural boundary). The hits
            // table stays whole — it's the index into the flow
            // blocks, and indexes don't paginate meaningfully.
            // Without explicit paging flags, emit the bare
            // `InspectReport` shape for back-compat.
            if paging_cfg.json_wrapped() {
                let filters_hash = inspect_filters_hash(pattern, is_regex);
                page_cache::emit_paged_text(
                    root,
                    &report.decl_hits,
                    &paging_cfg,
                    "inspect",
                    filters_hash,
                    inspect_decl_cost,
                    |slice, info, _cfg| {
                        let mut analysis_incomplete_reasons = report.analysis_incomplete_reasons.clone();
                        analysis_incomplete_reasons.extend(paged_json_incomplete_reasons("inspect", info));
                        analysis_incomplete_reasons.sort();
                        analysis_incomplete_reasons.dedup();
                        let wrapped = serde_json::json!({
                            "analysis_complete": analysis_incomplete_reasons.is_empty(),
                            "analysis_incomplete_reasons": analysis_incomplete_reasons,
                            "query": &report.query,
                            "regex": report.regex,
                            "kind_filter": &report.kind_filter,
                            "decl_hits": slice,
                            "hits": &report.hits,
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
            let mut current_info = None;
            let current_text = page_cache::capture(|| {
                current_info = Some(render_inspect_report_text(
                    &report,
                    &render,
                    &paging_cfg,
                    pattern,
                    is_regex,
                ));
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
            for page_number in page_cache::eager_window(current_info.page_number, current_info.total_pages) {
                if page_number == current_info.page_number {
                    continue;
                }
                let mut page_cfg = paging_cfg.clone();
                page_cfg.page = paging::PageArg::Number(page_number);
                let mut page_info = None;
                let text = page_cache::capture(|| {
                    page_info = Some(render_inspect_report_text(
                        &report, &render, &page_cfg, pattern, is_regex,
                    ));
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
            if let Err(e) = page_cache::save_pages(root, cached_pages) {
                tracing::debug!("page cache save failed: {e}");
            }
            page_cache::emit_cached_text(&output_text)?;
        }
    }
    Ok(())
}

/// Build a `ChainCache` respecting the global `--no-cache` setting.
/// Returns a cache with memoization enabled unless the user opted out.
fn build_chain_cache(ws: &Workspace) -> ChainCache<'_> {
    if *NO_CACHE.get().unwrap_or(&false) {
        ChainCache::without_cache(ws)
    } else {
        ChainCache::new(ws)
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // Serde skip_serializing_if requires `fn(&T) -> bool`.
fn is_zero_usize(n: &usize) -> bool {
    usize::eq(n, &0)
}

fn inspect_hit_truncation_reasons(output_cap: bool, attempt_cap: bool) -> Vec<String> {
    let mut reasons = Vec::new();
    if output_cap {
        reasons.push("max-hits output cap".to_string());
    }
    if attempt_cap {
        reasons.push("candidate-attempt cap derived from max-hits".to_string());
    }
    reasons
}

fn push_truncation_label(labels: &mut Vec<&'static str>, label: &'static str) {
    if !labels.contains(&label) {
        labels.push(label);
    }
}

fn push_chain_truncation(labels: &mut Vec<&'static str>, truncation: bonsai_callgraph::ChainTruncation) {
    if let Some(label) = truncation.label() {
        push_truncation_label(labels, label);
    }
}

fn push_call_path_truncation(labels: &mut Vec<&'static str>, truncation: CallPathTruncation) {
    if let Some(label) = truncation.label() {
        push_truncation_label(labels, label);
    }
}

fn truncation_summary(labels: &[&'static str]) -> Option<String> {
    if labels.is_empty() {
        return None;
    }
    let mut ordered = Vec::new();
    for known in [
        "max-flows cap",
        "entry-probe budget",
        "downstream-depth cap",
        "downstream-path cap",
    ] {
        if labels.contains(&known) {
            ordered.push(known);
        }
    }
    for label in labels {
        if !ordered.contains(label) {
            ordered.push(label);
        }
    }
    Some(ordered.join(", "))
}

fn semantic_direct_callers(
    ws: &Workspace,
    graph: &bonsai_callgraph::ResolvedCallGraph,
    target: bonsai_common::FuncId,
) -> Vec<RefOut> {
    let global = ws.db().global_index();
    let target_name = global
        .decl_of(bonsai_common::SymbolId::new(target.raw()))
        .map(|decl| decl.name.clone())
        .unwrap_or_default();
    let mut callers: Vec<RefOut> = graph
        .callers_of(target)
        .filter(|edge| edge.precision.is_semantic())
        .filter_map(|edge| {
            let caller_decl = global.decl_of(bonsai_common::SymbolId::new(edge.from.raw()))?;
            let span =
                find_call_span_to_func_uncached(ws, caller_decl, target, &target_name).unwrap_or(edge.span);
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

fn occurrence_flow_truncation_summary(hits: &[HitOut]) -> (usize, Vec<String>) {
    let mut reasons: Vec<&'static str> = Vec::new();
    let mut truncated_hits = 0usize;
    for hit in hits {
        let Some(reason) = hit.flow_truncated_by.as_deref() else {
            continue;
        };
        truncated_hits += 1;
        for part in reason.split(", ") {
            match part {
                "max-flows cap" => push_truncation_label(&mut reasons, "max-flows cap"),
                "entry-probe budget" => push_truncation_label(&mut reasons, "entry-probe budget"),
                "downstream-depth cap" => push_truncation_label(&mut reasons, "downstream-depth cap"),
                "downstream-path cap" => push_truncation_label(&mut reasons, "downstream-path cap"),
                _ => {}
            }
        }
    }
    let reason_vec = truncation_summary(&reasons)
        .map(|s| s.split(", ").map(str::to_string).collect())
        .unwrap_or_default();
    (truncated_hits, reason_vec)
}

/// Byte-cost heuristic for one rendered `InspectFlowRendered`,
/// used by the paging engine when `--context` is set on `inspect`.
/// Counts the display-chain names plus one line per function in
/// the chain plus the source lines that would be inlined. Rough
/// but monotonic — sufficient for the pager to partition flows
/// into budget-fitting pages.
pub(crate) fn inspect_flow_cost(flow: &InspectFlowRendered) -> u64 {
    // Per-flow fixed chrome: `══` top ruler + `FLOW N F:id <header>`
    // line + chain-display line + `══` bottom ruler. ~300 bytes
    // themed. Per-function: `[module] path` + `└─ [def] sig :line`
    // + one line per source byte with `LINENO  text` prefix +
    // `# [FLOW N SOURCE/->/MATCH: …]` annotations (~50 bytes each,
    // one per annotated line) + a trailing blank line. Per-line
    // overhead bumped from 8 → 32 to cover the line-number gutter,
    // themed comment block, and ANSI escape burst.
    let chain_bytes: usize = flow.chain.iter().map(|n| n.len() + 4).sum();
    let body_bytes: usize = flow
        .functions
        .iter()
        .map(|f| {
            f.module_path.len()
                + f.signature.len()
                + f.owners
                    .iter()
                    .map(|owner| owner.kind.len() + owner.name.len() + 32)
                    .sum::<usize>()
                + 80 // `[module] / [def] / trailing newline` scaffolding
                + f.lines
                    .iter()
                    .map(|l| l.text.len() + l.annotation.as_deref().map_or(0, str::len) + 32)
                    .sum::<usize>()
        })
        .sum();
    (chain_bytes + body_bytes + 320) as u64
}

/// Byte-cost heuristic for one `InspectOut` (decl hit) — header fields
/// plus the rolled-up cost of every flow it hosts. Feeds the same pager
/// as `inspect_flow_cost`.
fn inspect_decl_cost(d: &InspectOut) -> u64 {
    (d.symbol.len() as u64) + (d.file.len() as u64) + 32 + d.flows.iter().map(inspect_flow_cost).sum::<u64>()
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
    rebuild_report_summary(report);
}

/// Recompute the report summary after a filter pass so the top-of-
/// output counts + `by kind:` line match the kept hits. Shared
/// between the flow-id and group-id filters.
fn rebuild_report_summary(report: &mut InspectReport) {
    report.summary.total_decl_hits = report.decl_hits.len();
    report.summary.total_hits = report.hits.len();
    report.summary.hit_counts_by_kind = sorted_hit_counts_json(&report.hits);
    let (flow_truncated_hits, flow_truncation_reasons) = occurrence_flow_truncation_summary(&report.hits);
    report.summary.flow_truncated_hits = flow_truncated_hits;
    report.summary.flow_truncation_reasons = flow_truncation_reasons;
    refresh_inspect_completeness(report);
}

fn refresh_inspect_completeness(report: &mut InspectReport) {
    let mut reasons = Vec::new();
    for reason in &report.summary.hit_truncation_reasons {
        reasons.push(format!("inspect hit list capped by {reason}"));
    }
    for reason in &report.summary.flow_truncation_reasons {
        reasons.push(format!("inspect occurrence flow evidence capped by {reason}"));
    }
    for reason in report
        .decl_hits
        .iter()
        .filter_map(|decl| decl.summary.truncated_by.as_deref())
    {
        reasons.push(format!("inspect decl flow evidence capped by {reason}"));
    }
    reasons.sort();
    reasons.dedup();
    report.analysis_complete = reasons.is_empty();
    report.analysis_incomplete_reasons = reasons;
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

/// Render an `InspectReport` to stdout in text mode and return the
/// `PageInfo` the caller writes into the footer. Owns header chrome,
/// per-decl / per-hit blocks, and the final paging math; delegates
/// per-flow rendering to `render_flow_block` / `render_group_block`.
fn render_inspect_report_text(
    report: &InspectReport,
    render: &InspectRenderOptions,
    paging_cfg: &paging::PagingConfig,
    pattern: Option<&str>,
    is_regex: bool,
) -> paging::PageInfo {
    let u = ui();
    let view = resolve_view(render, report);
    cli_println!(
        "{} {} {} {} {}{}",
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
    );
    if view == ResolvedView::Grouped {
        // Make the view mode visible at the top of the output so
        // the reader knows group ids + shared-suffix blocks are
        // coming instead of per-flow blocks. Especially matters
        // for `--view auto` users who didn't explicitly ask for it.
        cli_println!("  {} grouped", u.dim("view:"));
    }
    if !report.kind_filter.is_empty() {
        cli_println!("  {} {:?}", u.dim("kinds:"), report.kind_filter);
    }
    if let Some(by_kind_obj) = report.summary.hit_counts_by_kind.as_object() {
        if !by_kind_obj.is_empty() {
            let mut kind_count_parts: Vec<String> = by_kind_obj
                .iter()
                .map(|(kind, count)| format!("{}={}", u.kind(kind), u.name(&count.to_string())))
                .collect();
            kind_count_parts.sort();
            cli_println!("  {} {}", u.dim("by kind:"), kind_count_parts.join(", "));
        }
    }
    if !report.analysis_complete {
        let reasons = if report.analysis_incomplete_reasons.is_empty() {
            "unknown reason".to_string()
        } else {
            report.analysis_incomplete_reasons.join("; ")
        };
        cli_println!("  {} {}", u.warn("analysis incomplete:"), u.dim(&reasons));
    }
    if report.summary.hits_truncated {
        // Loud warning: at least one occurrence was dropped. Include
        // the exact bounded-mode reason so this is never a silent or
        // misleading miss.
        let reasons = if report.summary.hit_truncation_reasons.is_empty() {
            "unknown cap".to_string()
        } else {
            report.summary.hit_truncation_reasons.join(", ")
        };
        let attempted = report
            .summary
            .hit_candidates_attempted
            .map(|n| format!("; {n} candidate(s) attempted"))
            .unwrap_or_default();
        let attempt_cap = report
            .summary
            .hit_attempt_cap
            .map(|n| format!("; candidate-attempt cap {n}"))
            .unwrap_or_default();
        cli_println!(
            "  {}",
            u.warn(&format!(
                "[truncated] hit list capped by {reasons} ({} shown{attempted}{attempt_cap}); re-run with --all or larger inspect caps to see every occurrence",
                report.hits.len(),
            ))
        );
    }
    if report.summary.flow_truncated_hits > 0 {
        let reasons = if report.summary.flow_truncation_reasons.is_empty() {
            "unknown cap".to_string()
        } else {
            report.summary.flow_truncation_reasons.join(", ")
        };
        cli_println!(
            "  {}",
            u.warn(&format!(
                "[truncated] flow evidence capped for {} occurrence hit(s) by {}; re-run with --all or larger inspect caps to enumerate every chain/path",
                report.summary.flow_truncated_hits, reasons
            ))
        );
    }
    // Paginate over a UNIFIED render-unit list: every decl_hit
    // followed by every unique folded occurrence flow. This way
    // `--page 2` truly advances — when page 1 renders decls + a
    // handful of folded flows, page 2 picks up from the next
    // folded flow, not re-render the same decls. The cursor
    // offset is a position in that combined list.
    let filters_hash = inspect_filters_hash(pattern, is_regex);
    let folded_order: Vec<&InspectFlowRendered> = collect_folded_flow_order(&report.hits);
    let total_decls = report.decl_hits.len();
    let total_units = total_decls + folded_order.len();

    // Safety factor on dedup-aware byte estimates. With the
    // per-page seen-set tracking the same way the renderer does,
    // the raw estimate already matches actual output to within
    // ~20 %. A 1.2× cushion covers per-line chrome (annotation
    // prefix, step number, indent) that `func_full_cost` doesn't
    // model exactly. Stored as numerator/denominator so we can
    // express fractional factors without rationals.
    const COST_SAFETY_NUM: u64 = 8;
    const COST_SAFETY_DEN: u64 = 5; // 8/5 = 1.6×
    let scale = |raw: u64| raw * COST_SAFETY_NUM / COST_SAFETY_DEN;
    // Per-function dedup-aware cost. Functions whose body has
    // already been rendered earlier on the same page collapse to
    // a one-line `(body already rendered above)` placeholder —
    // the chain placeholder still appears, just the body is
    // skipped. Tracking this in the cost estimator lets the pager
    // pack flows that share functions (e.g. multiple chains
    // ending in the same sink) onto the same page; the user gets
    // more flows per page without losing any.
    const PLACEHOLDER_BYTES: u64 = 120; // [module]+[def] header + "(body already rendered above)"
    fn func_full_cost(f: &InspectFunctionRendered) -> u64 {
        // Module path + def line + every body line. Mirrors what
        // `render_full_source_bodies` actually emits.
        let body: u64 = f.lines.iter().map(|l| (l.text.len() as u64) + 8).sum();
        (f.module_path.len() as u64) + (f.signature.len() as u64) + body + 64
    }
    type SeenSet = ahash::AHashSet<(String, u32)>;
    let func_dedup_cost = |func: &InspectFunctionRendered, seen: &SeenSet| -> u64 {
        if seen.contains(&(func.module_path.clone(), func.start_line)) {
            PLACEHOLDER_BYTES
        } else {
            func_full_cost(func)
        }
    };
    let flow_dedup_cost = |flow: &InspectFlowRendered, seen: &SeenSet| -> u64 {
        // Chain header (`══` + name + chain display) + every
        // function in the chain (full or placeholder).
        let chain_header = 64 + (flow.chain.iter().map(|n| n.len() as u64 + 4).sum::<u64>());
        chain_header
            + flow
                .functions
                .iter()
                .map(|f| func_dedup_cost(f, seen))
                .sum::<u64>()
    };
    let decl_dedup_cost = |decl: &InspectOut, seen: &SeenSet| -> u64 {
        let header = (decl.symbol.len() as u64) + (decl.file.len() as u64) + 32;
        header + decl.flows.iter().map(|f| flow_dedup_cost(f, seen)).sum::<u64>()
    };
    let unit_dedup_cost = |idx: usize, seen: &SeenSet| -> u64 {
        let raw = if idx < total_decls {
            decl_dedup_cost(&report.decl_hits[idx], seen)
        } else {
            flow_dedup_cost(folded_order[idx - total_decls], seen)
        };
        scale(raw)
    };
    let add_unit_keys = |idx: usize, seen: &mut SeenSet| {
        let funcs: &[InspectFunctionRendered] = if idx < total_decls {
            // Decl-hit unit: union of every flow's functions.
            // Each gets added once.
            for flow in &report.decl_hits[idx].flows {
                for f in &flow.functions {
                    seen.insert((f.module_path.clone(), f.start_line));
                }
            }
            return;
        } else {
            &folded_order[idx - total_decls].functions
        };
        for f in funcs {
            seen.insert((f.module_path.clone(), f.start_line));
        }
    };
    let unit_compact_cost = |idx: usize| -> u64 {
        let raw = if idx < total_decls {
            report.decl_hits[idx]
                .flows
                .iter()
                .map(|f| 64 + (f.chain.len() as u64) * 80)
                .sum::<u64>()
                + 128
        } else {
            64 + (folded_order[idx - total_decls].chain.len() as u64) * 80
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
        &unit_dedup_cost,
        &add_unit_keys,
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
        paging::PageArg::Cursor(c) => page_starts
            .iter()
            .copied()
            .find(|off| paging::cursor_id("inspect", filters_hash, *off as u64) == *c)
            .unwrap_or_else(|| page_starts.first().copied().unwrap_or(0)),
        paging::PageArg::Next => page_starts.first().copied().unwrap_or(0),
    };
    let page_number = page_starts
        .iter()
        .position(|&s| s == requested_start_offset)
        .map(|i| (i + 1) as u64)
        .unwrap_or(1);
    let start_offset = requested_start_offset;
    // Estimate uncapped render size: sum every unit's full-cost
    // estimate (chain bodies + headers). Gives the user an honest
    // "the full inspect output would be ~N tokens if you passed
    // --all" figure in the footer.
    let empty_seen: SeenSet = SeenSet::default();
    let total_uncapped_bytes: u64 = (0..total_units).map(|i| unit_dedup_cost(i, &empty_seen)).sum();
    let total_tokens_uncapped = paging::bytes_to_tokens(total_uncapped_bytes);
    let mut paging_info = paging::PageInfo {
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
    let page_flow_ids: ahash::AHashSet<String> = {
        let mut ids = ahash::AHashSet::new();
        for unit_index in start_offset..page_end_unit {
            if unit_index < total_decls {
                for f in &report.decl_hits[unit_index].flows {
                    ids.insert(f.flow_id.clone());
                }
            } else {
                ids.insert(folded_order[unit_index - total_decls].flow_id.clone());
            }
        }
        ids
    };
    // Flow-matching hits go on the page whose flow set they belong
    // to. Flow-less hits (module-level calls, imports, top-of-file
    // strings — no enclosing function so no chain) stay on page 1
    // where they're always visible.
    let page_hits: Vec<&HitOut> = report
        .hits
        .iter()
        .filter(|hit| {
            if hit.flows.is_empty() {
                start_offset == 0
            } else {
                hit.flows.iter().any(|f| page_flow_ids.contains(&f.flow_id))
            }
        })
        .collect();

    // OCCURRENCE HITS table — per-page, filtered to the flows
    // rendered on THIS page. Every hit in this table points at a
    // FLOW block that appears below.
    const HITS_ROW_AVG_BYTES: u64 = 220;
    let mut occurrence_hits_truncated = false;
    if !page_hits.is_empty() {
        cli_println!();
        cli_println!("{}", u.heading("══ OCCURRENCE HITS"));
        let show_from_column = page_hits.iter().any(|hit| hit.from_match.is_some());
        let show_to_column = page_hits.iter().any(|hit| hit.to_match.is_some());
        let mut table_headers: Vec<&str> = vec!["flow", "kind", "location", "in"];
        if show_from_column {
            table_headers.push("from");
        }
        if show_to_column {
            table_headers.push("to");
        }
        table_headers.push("text");
        let mut hits_table = u.table(&table_headers);
        let hits_budget_bytes = budget_bytes.map(|b| (b * 35) / 100);
        let mut rendered_hits = 0usize;
        for hit in &page_hits {
            if let Some(b) = hits_budget_bytes {
                if rendered_hits > 0 && (rendered_hits as u64).saturating_mul(HITS_ROW_AVG_BYTES) >= b {
                    break;
                }
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
        }
        cli_println!("{hits_table}");
        if rendered_hits < page_hits.len() {
            let skipped = page_hits.len() - rendered_hits;
            occurrence_hits_truncated = true;
            cli_println!(
                "{}",
                u.dim(&format!(
                    "[{skipped} occurrence hit(s) not shown on this page — pass --all for the full table]",
                ))
            );
        }
    }

    // After-table anchor so the unit-loop's budget check matches
    // the simulator's view (which doesn't see the table). Total
    // stdout still respects `budget_bytes` overall — that's
    // enforced by `unit_budget_bytes = budget_bytes - 35%` (the
    // table cap); units never get more than the remaining 65 %.
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
    let mut seen_bodies: BodySet = BodySet::default();
    // Per-page dedup-key set used by the COST estimator (coarser
    // than `seen_bodies`, just `(file, start_line)`). Mirrors the
    // simulator so the live walk's fit decisions match what
    // `simulate_page_starts` predicted.
    let mut page_seen_keys: SeenSet = SeenSet::default();
    let mut unit_cursor = start_offset;
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
    for unit_index in start_offset..total_units {
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
        let is_first_on_page = rendered_units == 0;
        let dedup_aware = unit_dedup_cost(unit_index, &page_seen_keys);
        let compact_estimate = unit_compact_cost(unit_index);
        let mut effective_render = render.clone();
        if !fits(dedup_aware) {
            let oversized_vs_total = unit_budget_bytes.is_some_and(|b| dedup_aware > b);
            if is_first_on_page && oversized_vs_total {
                // Pre-render proactive check: even compact must
                // fit the strict remaining budget. If it doesn't,
                // emit a one-line "too large" stub so the user
                // knows the flow exists but can't fit at this
                // `--context`. This keeps total stdout strictly
                // within budget — no reactive cleanup needed.
                if let Some(rem) = strict_remaining() {
                    if compact_estimate > rem {
                        let flow_id_label = if unit_index < total_decls {
                            report.decl_hits[unit_index]
                                .flows
                                .first()
                                .map(|f| f.flow_id.clone())
                                .unwrap_or_else(|| report.decl_hits[unit_index].symbol.clone())
                        } else {
                            folded_order[unit_index - total_decls].flow_id.clone()
                        };
                        let est_tokens = paging::bytes_to_tokens(dedup_aware);
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
                        add_unit_keys(unit_index, &mut page_seen_keys);
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
        if unit_index < total_decls {
            let decl_hit = &report.decl_hits[unit_index];
            cli_println!();
            render_inspect_text(decl_hit, &effective_render, view);
        } else {
            let flow = folded_order[unit_index - total_decls];
            cli_println!();
            let header_name = flow
                .chain
                .last()
                .cloned()
                .unwrap_or_else(|| flow.flow_label.clone());
            render_flow_block(u, &effective_render, flow, &header_name, &mut seen_bodies);
            // Find the fold's match points for this flow by scanning
            // `report.hits` for entries whose flows list contains
            // this flow_id.
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
        // Update the cost-estimator dedup set so the NEXT unit's
        // cost reflects what's already on the page. Mirrors the
        // simulator's add_unit_keys.
        add_unit_keys(unit_index, &mut page_seen_keys);
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
                "[{remaining} flow(s) not shown — context budget reached; pass --page {} or --all to continue]",
                paging_info.page_number + 1,
            ))
        );
    }

    // Patch paging metadata to reflect what actually rendered.
    paging_info.shown_rows = rendered_units as u64;
    paging_info.page_size = rendered_units as u64;
    paging_info.start_offset = start_offset as u64;
    paging_info.total_rows = total_units as u64;
    let any_truncation = !units_fully_rendered || occurrence_hits_truncated;
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
type PageSeenSet = ahash::AHashSet<(String, u32)>;
type DedupCostFn<'a> = dyn Fn(usize, &PageSeenSet) -> u64 + 'a;
type AddKeysFn<'a> = dyn Fn(usize, &mut PageSeenSet) + 'a;
type UnitCostFn<'a> = dyn Fn(usize) -> u64 + 'a;

fn simulate_page_starts(
    total_units: usize,
    budget_bytes: Option<u64>,
    dedup_cost: &DedupCostFn<'_>,
    add_unit_keys: &AddKeysFn<'_>,
    compact_cost: &UnitCostFn<'_>,
) -> Vec<usize> {
    if total_units == 0 {
        return vec![0];
    }
    let Some(b) = budget_bytes else {
        return vec![0];
    };
    let mut starts = vec![0usize];
    let mut unit_index = 0usize;
    while unit_index < total_units {
        // Per-page dedup state — functions seen on the current
        // page collapse to placeholders for subsequent units, so
        // packing flows that share functions onto one page lets
        // every flow show its full chain at low marginal cost.
        let mut seen: ahash::AHashSet<(String, u32)> = ahash::AHashSet::new();
        let mut emitted: u64 = 0;
        let mut rendered_on_page = 0usize;
        let mut next_unit_index = unit_index;
        while next_unit_index < total_units {
            if emitted >= b {
                break;
            }
            let cost = dedup_cost(next_unit_index, &seen);
            let is_first_on_page = rendered_on_page == 0;
            let unit_cost = if emitted + cost <= b {
                cost
            } else if is_first_on_page && cost > b {
                // Even with no dedup, the flow is bigger than the
                // entire window — render compact, on its own page.
                compact_cost(next_unit_index)
            } else {
                break;
            };
            emitted += unit_cost;
            add_unit_keys(next_unit_index, &mut seen);
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
    let mut seen: ahash::AHashSet<String> = ahash::AHashSet::new();
    let mut order: Vec<&InspectFlowRendered> = Vec::new();
    for hit in hits {
        for flow in &hit.flows {
            if seen.insert(flow.flow_id.clone()) {
                order.push(flow);
            }
        }
    }
    order
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
    let chain_line = flow
        .chain
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
    seen_bodies: &mut BodySet,
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
            render_flow_block(u, render, flow, header_name, seen_bodies);
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
            let annotation_suffix = match line.annotation.as_deref() {
                Some(a) => format!("  {}", u.annotation(&format!("# {a}"))),
                None => String::new(),
            };
            cli_println!("  {step_label}  {highlighted_text}{annotation_suffix}");
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
        cli_println!(
            "  {} {} {}{}  {}  {}",
            step_label,
            u.kind("line"),
            compact_owner_prefix(func),
            u.name(&func.signature),
            location,
            u.dim(annotation),
        );
        let text = line.text.trim();
        if !text.is_empty() && text != "..." {
            cli_println!("       {}", u.dim(&truncate(text, 140)));
        }
    }
}

/// Build the `[FLOW N FROM: X]` / `[FLOW N TO: Y]` annotation suffix
/// for a rendered line. `subjects` are the identifiers the line's
/// existing annotation is about (decl name at SOURCE, advance callee
/// at `->` lines, sink text at MATCH). A filter fires on a line only
/// when one of its subjects contains the needle — NOT when the raw
/// line text happens to mention it — so the marker lands precisely on
/// the hop the filter targeted and doesn't scatter across every line
/// of the enclosing function.
///
/// Returns `""` when no filter is set or none of the filter needles
/// appear on this line.
fn build_filter_marker(
    filters: InspectFilters<'_>,
    subjects: &[&str],
    line_text: &str,
    flow_label: &str,
) -> String {
    // Token-boundary match — mirrors `chain_matches_filters`. Also
    // scans the raw `line_text` so a TO/FROM marker can land on
    // ANY source line where the needle naturally appears (e.g. the
    // `os.system(...)` line inside `run_admin_command` gets a
    // `[TO: os]` marker even when the hit being inspected is
    // upstream in `handle_request`). Users want to see *both* the
    // FROM and TO markers somewhere in every flow, pinned to the
    // exact lines that motivated each needle.
    let matches = |needle: &str| -> bool {
        subjects.iter().any(|s| name_token_match(s, needle)) || name_token_match(line_text, needle)
    };
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

fn walk_flow_hits<F>(
    events: &[FlowEvent],
    in_fn_id: bonsai_common::FuncId,
    in_fn: &str,
    matcher: &Matcher,
    kinds: &ahash::AHashSet<String>,
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
    let want = |k: &str| kinds.is_empty() || kinds.contains(k);
    let containing = |id: bonsai_common::FuncId, name: &str| Some((id, name.to_string()));
    for e in events {
        match e {
            FlowEvent::Call { span, name, args, .. } => {
                if want("call") && matcher.is_match(name) {
                    push_hit(
                        "call",
                        name.clone(),
                        *span,
                        containing(in_fn_id, in_fn),
                        false,
                        out,
                    );
                }
                if want("arg") {
                    for a in args {
                        if matcher.is_match(&a.value_text)
                            || a.name.as_deref().is_some_and(|n| matcher.is_match(n))
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
                    if want("call") && matcher.is_match(call) {
                        push_hit(
                            "call",
                            call.clone(),
                            *span,
                            containing(in_fn_id, in_fn),
                            true,
                            out,
                        );
                    }
                    if want("arg") {
                        for arg in source_call_args {
                            if matcher.is_match(arg) {
                                push_hit("arg", arg.clone(), *span, containing(in_fn_id, in_fn), false, out);
                            }
                        }
                    }
                }
                if want("var")
                    && (matcher.is_match(target)
                        || source_name.as_deref().is_some_and(|s| matcher.is_match(s))
                        || source_names.iter().any(|s| matcher.is_match(s))
                        || source_call.as_deref().is_some_and(|s| matcher.is_match(s)))
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
                walk_flow_hits(then_events, in_fn_id, in_fn, matcher, kinds, out, push_hit);
                walk_flow_hits(else_events, in_fn_id, in_fn, matcher, kinds, out, push_hit);
            }
            FlowEvent::Loop { body, .. } => {
                walk_flow_hits(body, in_fn_id, in_fn, matcher, kinds, out, push_hit);
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
                walk_flow_hits(body, in_fn_id, in_fn, matcher, kinds, out, push_hit);
                walk_flow_hits(catch_events, in_fn_id, in_fn, matcher, kinds, out, push_hit);
                walk_flow_hits(finally_events, in_fn_id, in_fn, matcher, kinds, out, push_hit);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_flow_hits(body, in_fn_id, in_fn, matcher, kinds, out, push_hit);
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
    if out.flows.is_empty() {
        cli_println!(
            "\n   {}",
            u.dim("(no entry-point call chain reaches this symbol statically)")
        );
        return;
    }
    let truncation_suffix = match out.summary.truncated_by.as_deref() {
        Some(why) => format!(" [truncated by {why} — re-run with --all to enumerate all chains]"),
        None => String::new(),
    };
    cli_println!(
        "\n   {}",
        u.dim(&format!(
            "{} flow(s) reaching {} — {} unique entry points, max depth {}{}",
            out.summary.total_flows,
            out.symbol,
            out.summary.unique_entry_points,
            out.summary.max_chain_depth,
            truncation_suffix
        ))
    );
    // One body-dedup set per decl-hit render. A decl whose
    // upstream chain has many branches will re-pass through the
    // same intermediate function on every flow; the dedup makes
    // those intermediates render once per decl hit instead of per
    // flow, while still preserving every per-flow header + chain
    // line so flow_ids stay self-citable.
    let mut seen_bodies: BodySet = BodySet::default();
    match view {
        ResolvedView::Trace => {
            for flow in &out.flows {
                render_flow_block(u, render, flow, &out.symbol, &mut seen_bodies);
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
                render_group_block(
                    u,
                    render,
                    group,
                    &members,
                    group_idx + 1,
                    &out.symbol,
                    &mut seen_bodies,
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
    let global = workspace.db().global_index();
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
/// human label like `"call os.system"`.
#[derive(Clone)]
pub(crate) struct MatchOverride {
    pub(crate) span: bonsai_common::Span,
    pub(crate) label: String,
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
    let global = ws.db().global_index();
    // Chains now carry FuncIds all the way from enumeration, so each
    // hop resolves to exactly one decl — no name collision, no fallback
    // picker for "the candidate that calls the next hop." `decl_of` is
    // a direct SymbolId lookup.
    let mut decls: Vec<bonsai_lang_api::Decl> = Vec::with_capacity(chain.len());
    let mut chain_names: Vec<String> = Vec::with_capacity(chain.len());
    for &func in chain {
        let symbol = bonsai_common::SymbolId::new(func.raw());
        let decl = global.decl_of(symbol).cloned()?;
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

    let chain_display = chain_names.join(" -> ");
    let flow_id = compute_flow_id(&chain_names);
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
        let sink_name = flow
            .chain
            .last()
            .cloned()
            .unwrap_or_else(|| "<empty>".to_string());
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
            group_id: compute_group_id(&shared_suffix),
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
                // subject of this line — only the hit's own label
                // (`MATCH: var user_id`) and the hit text are. Pushing
                // `target_name` here would cause `--from update` to
                // fire on every body line of `update_user`, scattering
                // the marker across unrelated lines.
                subjects.push(&ov.label);
                subjects.push(&text);
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
        let filter_marker = build_filter_marker(filters, &subjects, &text, flow_label);
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
    let global = ws.db().global_index();
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
