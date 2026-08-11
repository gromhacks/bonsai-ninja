//! `bonsai-ninja dump-taint` data layer.
//!
//! Computes an IDG-backed, source-seeded taint closure, applies any
//! rulepack-declared semantic transfers supplied by the caller, then
//! performs the same filtering / sorting / id-stamping the CLI uses.
//! The result is a [`TaintReport`] consumers can render or further
//! process.

use crate::common::format_span;
use bonsai_hash::fnv1a_names_low32;
use bonsai_lang_api::FlowEvent;
use bonsai_workspace::Workspace;
use serde::Serialize;

const SEMANTIC_FLOW_MAX_PRECISION: bonsai_common::Precision = bonsai_common::Precision::Narrowed;

/// Filter bundle for [`dump_taint`]. Mirrors the CLI flag surface.
#[derive(Clone, Debug)]
pub struct TaintFilters<'a> {
    /// Entry-point function name (`--source`).
    pub source: &'a str,
    /// Override seed identifiers. Empty = derive from the source's
    /// params + assigned locals.
    pub seeds: Vec<String>,
    /// `--sink X` — keep only records whose callee contains `X`.
    pub sink: Option<&'a str>,
    /// `--taint T:id` — drill into one propagation by stable id.
    pub taint_id: Option<&'a str>,
    /// Rulepack-declared method/receiver state transfers to apply
    /// before rendering propagation records.
    pub receiver_state_propagations: Vec<bonsai_taint::ReceiverStatePropagation>,
    /// Rulepack-declared call-result passthroughs to apply before
    /// rendering propagation records.
    pub call_result_passthroughs: Vec<bonsai_taint::CallResultPassthrough>,
    /// Rulepack-declared output-argument flows to apply before
    /// rendering propagation records.
    pub output_arg_flows: Vec<bonsai_taint::OutputArgFlow>,
}

impl<'a> Default for TaintFilters<'a> {
    fn default() -> Self {
        Self {
            source: "",
            seeds: Vec::new(),
            sink: None,
            taint_id: None,
            receiver_state_propagations: Vec::new(),
            call_result_passthroughs: Vec::new(),
            output_arg_flows: Vec::new(),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct TaintReport {
    pub source: String,
    pub seeds: Vec<String>,
    pub analysis_complete: bool,
    pub analysis_incomplete_reasons: Vec<String>,
    pub precision: String,
    pub pairs_analyzed: u32,
    pub records: Vec<TaintRecord>,
}

#[derive(Serialize, Clone, Debug)]
pub struct TaintRecord {
    pub taint_id: String,
    pub caller_name: String,
    pub caller_file: String,
    pub caller_line: u32,
    pub callee_name: String,
    pub callee_file: String,
    pub callee_line: u32,
    pub call_file: String,
    pub call_line: u32,
    pub call_column: u32,
    /// Source text of the call-site line - the code at this propagation
    /// edge, so the JSON dump carries the edge's code, not just its
    /// coordinates. Empty when the line can't be read.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub call_code: String,
    pub tainted_args: Vec<TaintedArgRecord>,
    pub edge_kind: String,
    pub edge_precision: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct TaintSourceCandidate {
    pub name: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub func_id: u32,
}

#[derive(Serialize, Clone, Debug)]
pub struct TaintedArgRecord {
    pub index: usize,
    pub value_text: String,
    pub param_name: String,
}

/// Outcome of a [`dump_taint`] call. The variants distinguish "no
/// matching source decl" from "everything filtered out by --taint
/// id" so the CLI can emit a different error message for each.
#[derive(Debug)]
pub enum TaintOutcome {
    /// Successful run — return the full report.
    Report(TaintReport),
    /// `--source X` didn't resolve to any callable decl.
    SourceNotFound,
    /// `--source X` matched multiple callable decls. The caller must
    /// disambiguate instead of letting the engine pick a workspace-order
    /// winner.
    SourceAmbiguous {
        source: String,
        candidates: Vec<TaintSourceCandidate>,
    },
    /// `--taint T:id` didn't match any propagation in the report.
    TaintIdNotFound,
}

/// True when `decl_file` matches the user-supplied `qualifier` from a
/// `path:name` `--source` spec. We accept three shapes so callers can
/// pass whatever they have on hand:
///
/// * exact equality (absolute path === absolute path)
/// * `decl_file` ends with `qualifier` as a path suffix (handles
///   relative-vs-absolute mismatches)
/// * basename equality (`main.c` matches `/abs/dir/main.c`)
fn file_matches_qualifier(
    decl_file: &str,
    qualifier: &str,
    workspace_root: Option<&std::path::Path>,
) -> bool {
    let path = std::path::Path::new(decl_file);
    let rooted = workspace_root
        .filter(|_| !path.is_absolute())
        .map_or_else(|| path.to_path_buf(), |root| root.join(path));
    bonsai_common::path_filter_matches_with_root(workspace_root, &rooted.to_string_lossy(), qualifier)
}

/// Parsed `--source` spec — bare callable name with optional path /
/// line qualifiers used to disambiguate when several decls share a
/// name (multiple `__module__` synthetics, multiple `__init__`s in
/// one Python file, four C `main`s, etc.).
#[derive(Debug, Default)]
struct SourceSpec<'a> {
    file: Option<&'a str>,
    line: Option<u32>,
    name: &'a str,
}

/// Split a `--source` spec. Accepted shapes:
///
/// * `"foo"`                     — bare name
/// * `"path/to/file.py:foo"`     — file-qualified
/// * `"path/to/file.py:32:foo"`  — file + line-qualified
///
/// The trailing `:`-segment is always the bare name. If the segment
/// before it parses as `u32`, it's the line; the rest is the path.
/// File paths may themselves contain colons (Windows drive letters),
/// so we walk segments from the right rather than splitting on every
/// `:`.
fn split_source_spec(spec: &str) -> SourceSpec<'_> {
    let Some(name_idx) = spec.rfind(':') else {
        return SourceSpec {
            name: spec,
            ..Default::default()
        };
    };
    let (head, name) = (&spec[..name_idx], &spec[name_idx + 1..]);
    if name.is_empty() || head.is_empty() {
        return SourceSpec {
            name: spec,
            ..Default::default()
        };
    }
    if name.contains('/') || name.contains('\\') {
        return SourceSpec {
            name: spec,
            ..Default::default()
        };
    }
    let (file, line) = match head.rsplit_once(':') {
        Some((path, maybe_line)) if !path.is_empty() => match maybe_line.parse::<u32>() {
            Ok(n) => (Some(path), Some(n)),
            Err(_) => (Some(head), None),
        },
        _ => (Some(head), None),
    };
    SourceSpec { file, line, name }
}

/// Run the intraprocedural + interprocedural taint passes from
/// `filters.source` with the given seeds, applying the
/// configured filters to the result.
pub fn dump_taint(ws: &Workspace, f: &TaintFilters<'_>) -> TaintOutcome {
    let spec = split_source_spec(f.source);
    let persisted_candidates = ws.persisted_callable_nodes_named(spec.name).and_then(Result::ok);
    let mut source_candidates: Vec<(bonsai_common::FuncId, TaintSourceCandidate)> =
        if let Some(candidates) = persisted_candidates {
            candidates
                .into_iter()
                .filter_map(|node| {
                    let (file, line, column) = format_span(&node.name_span, ws);
                    if let Some(qualifier) = spec.file {
                        if !file_matches_qualifier(&file, qualifier, ws.db().workspace_root().as_deref()) {
                            return None;
                        }
                    }
                    if let Some(want_line) = spec.line {
                        if line != want_line {
                            return None;
                        }
                    }
                    Some((
                        node.func,
                        TaintSourceCandidate {
                            name: node.name.into(),
                            file,
                            line,
                            column,
                            func_id: node.func.raw(),
                        },
                    ))
                })
                .collect()
        } else {
            let global = ws.compiler_linkage_index();
            bonsai_resolve::resolve_callable(&global, spec.name)
                .into_iter()
                .filter_map(|func| {
                    let symbol = bonsai_common::SymbolId::new(func.raw());
                    let decl = global.decl_of(symbol)?;
                    let (file, line, column) = format_span(&decl.name_span, ws);
                    if let Some(qualifier) = spec.file {
                        if !file_matches_qualifier(&file, qualifier, ws.db().workspace_root().as_deref()) {
                            return None;
                        }
                    }
                    if let Some(want_line) = spec.line {
                        if line != want_line {
                            return None;
                        }
                    }
                    Some((
                        func,
                        TaintSourceCandidate {
                            name: decl.name.clone(),
                            file,
                            line,
                            column,
                            func_id: func.raw(),
                        },
                    ))
                })
                .collect()
        };
    if source_candidates.is_empty() {
        return TaintOutcome::SourceNotFound;
    }
    source_candidates.sort_by(|(_, a), (_, b)| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.column.cmp(&b.column))
            .then_with(|| a.func_id.cmp(&b.func_id))
    });
    if source_candidates.len() > 1 {
        return TaintOutcome::SourceAmbiguous {
            source: f.source.to_string(),
            candidates: source_candidates
                .into_iter()
                .map(|(_, candidate)| candidate)
                .collect(),
        };
    }
    let source_func = source_candidates[0].0;
    let expanded_workspace =
        ws.source_reachable_query_workspace(&[source_func], Some(SEMANTIC_FLOW_MAX_PRECISION));
    let ws = expanded_workspace.as_ref().unwrap_or(ws);
    let db = ws.db();
    let source_symbol = bonsai_common::SymbolId::new(source_func.raw());
    let exact_source = ws.exact_decl(source_symbol);
    let header_source = exact_source
        .is_none()
        .then(|| ws.compiler_header_index().decl_of(source_symbol).cloned());
    let source_decl = exact_source
        .as_deref()
        .cloned()
        .or_else(|| header_source.flatten());

    let effective_seed: bonsai_taint::TokenSet = if f.seeds.is_empty() {
        bonsai_taint::default_entry_taint_seed(source_decl.as_ref())
    } else {
        f.seeds.iter().cloned().collect()
    };
    // IDG-driven path. The legacy interprocedural engine has been
    // replaced by an IDG forward-closure walk: each
    // `(CallArg{site, idx} → Param{idx})` cross-call edge whose
    // source endpoint is reachable from `effective_seed`'s seed
    // nodes surfaces as one [`TaintRecord`]. Build the service on
    // demand when running through `open_query`, which intentionally
    // skips open-time prewarm; the closure itself still runs to
    // completion for the requested source.
    let scoped_session = if db.idg_service().is_none() {
        ws.source_flow_session(&[source_func], Some(SEMANTIC_FLOW_MAX_PRECISION))
    } else {
        None
    };
    let resident_idg = db.idg_service();
    let idg = resident_idg.as_deref().or_else(|| {
        scoped_session
            .as_ref()
            .map(bonsai_workspace::flow_query::SyntaxFlowSession::idg)
    });
    let fallback_idg;
    let idg = if let Some(idg) = idg {
        idg
    } else {
        // Synthetic/scoped workspaces without a root can fail to allocate the
        // temporary query factstore. Preserve exact semantics with the
        // canonical resident builder; never return a partial result.
        fallback_idg = ws.build_and_seed_idg_service();
        fallback_idg.as_ref()
    };
    let global = idg.global_linkage_index();
    let mut seed_nodes = bonsai_taint::compose_idg_seed_nodes_with_decl(
        bonsai_taint::IdgSeedRequest::token_api(source_func, &effective_seed),
        global.as_ref(),
        idg,
        source_decl.as_ref(),
    );
    bonsai_taint::apply_configured_transfer_fixpoint(
        &mut seed_nodes,
        &f.receiver_state_propagations,
        &f.call_result_passthroughs,
        &f.output_arg_flows,
        global.as_ref(),
        idg,
        Some(SEMANTIC_FLOW_MAX_PRECISION),
        None,
    );

    let closure_evidence =
        idg.forward_closure_evidence_with_max_precision(&seed_nodes, Some(SEMANTIC_FLOW_MAX_PRECISION));
    let closure_nodes = closure_evidence.nodes;
    let mut cross_calls = closure_evidence.cross_calls;
    cross_calls.sort_unstable_by_key(|edge| {
        (
            edge.caller.raw(),
            edge.callee.raw(),
            edge.call_span,
            edge.arg_idx,
            edge.param_idx,
            edge.precision,
            edge.relation,
        )
    });
    cross_calls.dedup();
    if bonsai_diagnostics::debug::is_enabled("idg-closure-detail") {
        for edge in &cross_calls {
            bonsai_diagnostics::debug_log!(
                "idg-closure-detail",
                "dump-taint cross-call caller={} callee={} span={:?} arg={} param={} relation={:?} precision={:?}",
                edge.caller.raw(),
                edge.callee.raw(),
                edge.call_span,
                edge.arg_idx,
                edge.param_idx,
                edge.relation,
                edge.precision
            );
        }
    }
    let tainted_arg_sites = idg.tainted_call_args_in_reachable_nodes(&closure_nodes);
    let mut records: Vec<TaintRecord> = cross_calls
        .iter()
        .filter_map(|ce| build_taint_record_from_cross_call(ce, &global, ws))
        .collect();
    dedup_taint_records(&mut records);

    if let Some(needle) = f.sink {
        records.retain(|r| r.callee_name.contains(needle));
    }
    if let Some(target_id) = f.taint_id {
        records.retain(|r| r.taint_id == target_id);
        if records.is_empty() {
            return TaintOutcome::TaintIdNotFound;
        }
    }

    // Weakest precision first so review-worthy edges sit at the
    // top — same ordering `dump-edges` uses.
    fn precision_sort_key(p: &str) -> u8 {
        match p {
            "unknown" => 0,
            "over-approximate" => 1,
            "narrowed" => 2,
            "exact" => 3,
            _ => 4,
        }
    }
    records.sort_by(|a, b| {
        precision_sort_key(&a.edge_precision)
            .cmp(&precision_sort_key(&b.edge_precision))
            .then_with(|| a.caller_name.cmp(&b.caller_name))
            .then_with(|| a.callee_name.cmp(&b.callee_name))
            .then_with(|| a.call_line.cmp(&b.call_line))
    });

    // Sort `seeds` so the JSON `seeds` array order is
    // deterministic across runs — `TokenSet` is `AHashSet`-backed
    // and would otherwise expose the per-process random seed in
    // serialised output, breaking Stable-IDs-From-Content.
    let mut seeds: Vec<String> = effective_seed.iter().cloned().collect();
    seeds.sort();
    // Worst precision across recorded cross-call edges. The legacy
    // engine returned a per-run aggregate; we compute the same shape
    // here from the IDG cross-call edges' precision tags.
    let aggregate_precision = aggregate_flow_precision(cross_calls.iter().map(|ce| ce.precision));
    // `pairs_analyzed` reports the count of distinct `(caller,
    // callee)` function pairs the IDG closure walked when seeding
    // from this source. Legacy engine semantics were "total
    // `(func, seed)` pairs analysed" — the IDG doesn't enumerate
    // per-seed pairs (one forward closure handles all seeds at
    // once), so the field is repurposed to a structural metric
    // that's still useful as a "how wide did this analysis spread"
    // signal AND remains non-zero whenever the source resolved
    // (so e2e harnesses can read it as "did the pass run?"). Floor
    // at 1 when seeds resolved but no cross-call edges fired — the
    // source-function itself was still analysed.
    let unique_pairs: ahash::AHashSet<(bonsai_common::FuncId, bonsai_common::FuncId)> =
        cross_calls.iter().map(|ce| (ce.caller, ce.callee)).collect();
    let pairs_analyzed = std::cmp::max(1, unique_pairs.len());
    let mut analysis_incomplete_reasons = Vec::new();
    analysis_incomplete_reasons.extend(tainted_unresolved_workspace_call_reasons(
        ws,
        global.as_ref(),
        &cross_calls,
        &tainted_arg_sites,
    ));
    analysis_incomplete_reasons.sort();
    analysis_incomplete_reasons.dedup();
    TaintOutcome::Report(TaintReport {
        source: f.source.to_string(),
        seeds,
        analysis_complete: analysis_incomplete_reasons.is_empty(),
        analysis_incomplete_reasons,
        precision: precision_display(aggregate_precision),
        pairs_analyzed: u32::try_from(pairs_analyzed).unwrap_or(u32::MAX),
        records,
    })
}

fn dedup_taint_records(records: &mut Vec<TaintRecord>) {
    let mut seen = ahash::AHashSet::new();
    records.retain(|record| {
        let tainted_args = record
            .tainted_args
            .iter()
            .map(|arg| TaintRecordArgDedupKey {
                index: arg.index,
                value_text: arg.value_text.clone(),
                param_name: arg.param_name.clone(),
            })
            .collect::<Vec<_>>();
        seen.insert(TaintRecordDedupKey {
            taint_id: record.taint_id.clone(),
            caller_name: record.caller_name.clone(),
            caller_file: record.caller_file.clone(),
            caller_line: record.caller_line,
            callee_name: record.callee_name.clone(),
            callee_file: record.callee_file.clone(),
            callee_line: record.callee_line,
            call_file: record.call_file.clone(),
            call_line: record.call_line,
            call_column: record.call_column,
            edge_kind: record.edge_kind.clone(),
            edge_precision: record.edge_precision.clone(),
            tainted_args,
        })
    });
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct TaintRecordDedupKey {
    taint_id: String,
    caller_name: String,
    caller_file: String,
    caller_line: u32,
    callee_name: String,
    callee_file: String,
    callee_line: u32,
    call_file: String,
    call_line: u32,
    call_column: u32,
    edge_kind: String,
    edge_precision: String,
    tainted_args: Vec<TaintRecordArgDedupKey>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct TaintRecordArgDedupKey {
    index: usize,
    value_text: String,
    param_name: String,
}

fn tainted_unresolved_workspace_call_reasons(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    cross_calls: &[bonsai_idg::CrossCallEdge],
    tainted_arg_sites: &[(bonsai_common::FuncId, bonsai_common::Span, u32)],
) -> Vec<String> {
    let resolved_sites: ahash::AHashSet<(bonsai_common::FuncId, bonsai_common::Span)> = cross_calls
        .iter()
        .map(|edge| (edge.caller, edge.call_span))
        .collect();
    let mut seen_sites = ahash::AHashSet::new();
    let mut reasons = Vec::new();
    for (caller, span, _) in tainted_arg_sites {
        if resolved_sites.contains(&(*caller, *span)) || !seen_sites.insert((*caller, *span)) {
            continue;
        }
        let Some(call_name) = caller_call_name(ws, global, *caller, *span) else {
            continue;
        };
        if workspace_call_site_has_semantic_resolution(ws, global, *caller, *span, &call_name) {
            continue;
        }
        if workspace_has_callable_named_in_context(ws, global, *caller, &call_name) {
            reasons.push(format!("unresolved-call:{call_name}"));
        }
    }
    reasons
}

fn workspace_call_site_has_semantic_resolution(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    caller: bonsai_common::FuncId,
    call_span: bonsai_common::Span,
    call_name: &str,
) -> bool {
    ws.cached_resolved_call_graph().callees_of(caller).any(|edge| {
        edge.precision.is_semantic()
            && call_site_spans_match(edge.span, call_span)
            && global
                .decl_of(bonsai_common::SymbolId::new(edge.to.raw()))
                .is_some_and(|decl| call_names_match(&decl.name, call_name))
    })
}

fn workspace_has_callable_named_in_context(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    caller: bonsai_common::FuncId,
    name: &str,
) -> bool {
    let caller_sym = bonsai_common::SymbolId::new(caller.raw());
    let Some(caller_decl) = global.decl_of(caller_sym) else {
        return false;
    };
    let Some(caller_file) = global.declaring_file(caller_sym) else {
        return false;
    };
    let alias_map: ahash::AHashMap<_, _> =
        bonsai_lang_api::alias_map_from_import_specs(&ws.db().imports_for(caller_file))
            .into_iter()
            .collect();
    let ctx =
        bonsai_resolve::ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(&alias_map);
    let short = bonsai_lang_api::kit::short_name_of(name);
    [name, short].into_iter().any(|candidate| {
        !candidate.is_empty()
            && !bonsai_resolve::resolve_callable_with_context(global, candidate, &ctx).is_empty()
    })
}

fn call_site_spans_match(edge_span: bonsai_common::Span, event_span: bonsai_common::Span) -> bool {
    edge_span == event_span
        || (edge_span.file == event_span.file
            && (span_contains(edge_span, event_span) || span_contains(event_span, edge_span)))
}

fn span_contains(outer: bonsai_common::Span, inner: bonsai_common::Span) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

fn call_names_match(decl_name: &str, event_name: &str) -> bool {
    bonsai_common::qualified_names_match(decl_name, event_name)
}

/// Stable content-hash id for a taint propagation: `T:` + 8
/// lowercase hex. Hash input mirrors the inspect / dump-edges
/// formats so a tooling layer can use one parser for all of them.
#[must_use]
pub fn compute_taint_id(
    caller_name: &str,
    callee_name: &str,
    call_file: &str,
    call_line: u32,
    call_column: u32,
    params: &[String],
) -> String {
    let call_site = format!("{call_file}:{call_line}:{call_column}");
    let mut tokens: Vec<String> = vec![caller_name.to_string(), callee_name.to_string(), call_site];
    tokens.extend(params.iter().cloned());
    format!("T:{:08x}", fnv1a_names_low32(&tokens))
}

/// Translate one IDG [`bonsai_idg::CrossCallEdge`] into the
/// externally-rendered [`TaintRecord`]. Returns `None` when the
/// caller or callee FuncId no longer resolves to a decl (stale id
/// after a workspace reload, etc).
pub(crate) fn build_taint_record_from_cross_call(
    ce: &bonsai_idg::CrossCallEdge,
    global: &bonsai_index::GlobalIndex,
    ws: &Workspace,
) -> Option<TaintRecord> {
    if !ce.relation.is_renderable_call() {
        return None;
    }
    let caller_decl = global.decl_of(bonsai_common::SymbolId::new(ce.caller.raw()))?;
    let callee_decl = global.decl_of(bonsai_common::SymbolId::new(ce.callee.raw()))?;
    let (caller_file, caller_line, _) = format_span(&caller_decl.name_span, ws);
    let (callee_file, callee_line, _) = format_span(&callee_decl.name_span, ws);
    let (call_file, call_line, call_column) = format_span(&ce.call_span, ws);

    let exact_caller = ws.exact_decl(bonsai_common::SymbolId::new(ce.caller.raw()));
    let caller_flow_decl = exact_caller.as_deref().unwrap_or(caller_decl);
    let tainted_args = tainted_args_from_cross_call(ce, caller_flow_decl, callee_decl)?;
    if tainted_args.is_empty() {
        return None;
    }
    let id_args: Vec<String> = tainted_args
        .iter()
        .map(|arg| {
            if arg.param_name.is_empty() {
                arg.value_text.clone()
            } else {
                arg.param_name.clone()
            }
        })
        .collect();

    let taint_id = compute_taint_id(
        &caller_decl.name,
        &callee_decl.name,
        &call_file,
        call_line,
        call_column,
        &id_args,
    );

    let call_code = source_line_text(ws, &ce.call_span);

    Some(TaintRecord {
        taint_id,
        caller_name: caller_decl.name.clone(),
        caller_file,
        caller_line,
        callee_name: callee_decl.name.clone(),
        callee_file,
        callee_line,
        call_file,
        call_line,
        call_column,
        call_code,
        tainted_args,
        edge_kind: edge_kind_display(ce.call_kind),
        edge_precision: precision_display(ce.precision),
    })
}

/// Trimmed source text of the line a span starts on. Empty when the file
/// can't be read - the call-site coordinates still carry the location.
fn source_line_text(ws: &Workspace, span: &bonsai_common::Span) -> String {
    let Ok(snapshot) = ws.vfs().snapshot(span.file) else {
        return String::new();
    };
    let src = snapshot.text.as_ref();
    let span_map = bonsai_common::cached_span_map_arc(span.file, snapshot.version, &snapshot.text);
    let line = span_map.line_col(span.start).line;
    src.split('\n')
        .nth(line.saturating_sub(1) as usize)
        .unwrap_or("")
        .trim()
        .to_string()
}

fn tainted_args_from_cross_call(
    ce: &bonsai_idg::CrossCallEdge,
    caller_decl: &bonsai_lang_api::Decl,
    callee_decl: &bonsai_lang_api::Decl,
) -> Option<Vec<TaintedArgRecord>> {
    if ce.arg_idx == u32::MAX {
        if matches!(
            ce.relation,
            bonsai_idg::CrossCallRelation::Argument | bonsai_idg::CrossCallRelation::Capture
        ) {
            if let Some((receiver, arg_count)) = caller_call_receiver_and_arg_count(caller_decl, ce.call_span)
                .filter(|(receiver, _)| !receiver.trim().is_empty())
            {
                let (index, param_name) = if arg_count == 0 {
                    (usize::MAX, "receiver".to_string())
                } else if ce.param_idx != u32::MAX {
                    (
                        ce.param_idx as usize,
                        callee_decl
                            .params
                            .get(ce.param_idx as usize)
                            .cloned()
                            .unwrap_or_default(),
                    )
                } else {
                    return Some(Vec::new());
                };
                return Some(vec![TaintedArgRecord {
                    index,
                    value_text: receiver,
                    param_name,
                }]);
            }
        }
        if matches!(
            ce.relation,
            bonsai_idg::CrossCallRelation::Callback | bonsai_idg::CrossCallRelation::Capture
        ) && ce.param_idx != u32::MAX
        {
            let param_name = callee_decl
                .params
                .get(ce.param_idx as usize)
                .cloned()
                .unwrap_or_default();
            return Some(vec![TaintedArgRecord {
                index: ce.param_idx as usize,
                value_text: param_name.clone(),
                param_name,
            }]);
        }
        return Some(Vec::new());
    }
    let value_text = caller_arg_value_text(caller_decl, ce.call_span, ce.arg_idx).unwrap_or_default();
    let param_name = if ce.param_idx == u32::MAX {
        String::new()
    } else {
        callee_decl
            .params
            .get(ce.param_idx as usize)
            .cloned()
            .unwrap_or_default()
    };
    Some(vec![TaintedArgRecord {
        index: ce.arg_idx as usize,
        value_text,
        param_name,
    }])
}

/// Look up the textual form of the `arg_idx`-th argument of the
/// `Call` event whose span is `call_span` inside `caller`. Returns
/// `None` when the caller isn't in the index, isn't callable, or no
/// Call event matches the span / index.
fn caller_arg_value_text(
    caller_decl: &bonsai_lang_api::Decl,
    call_span: bonsai_common::Span,
    arg_idx: u32,
) -> Option<String> {
    fn find_call_arg<'a>(
        events: &'a [FlowEvent],
        target_span: bonsai_common::Span,
        idx: usize,
    ) -> Option<&'a bonsai_lang_api::CallArg> {
        for event in events {
            match event {
                FlowEvent::Call { span, args, .. } if *span == target_span => {
                    return args.get(idx);
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    if let Some(found) = find_call_arg(then_events, target_span, idx) {
                        return Some(found);
                    }
                    if let Some(found) = find_call_arg(else_events, target_span, idx) {
                        return Some(found);
                    }
                }
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    if let Some(found) = find_call_arg(body, target_span, idx) {
                        return Some(found);
                    }
                    if let Some(found) = find_call_arg(catch_events, target_span, idx) {
                        return Some(found);
                    }
                    if let Some(found) = find_call_arg(finally_events, target_span, idx) {
                        return Some(found);
                    }
                }
                FlowEvent::Loop { body, .. } => {
                    if let Some(found) = find_call_arg(body, target_span, idx) {
                        return Some(found);
                    }
                }
                _ => {}
            }
        }
        None
    }
    let arg = find_call_arg(&caller_decl.flow_events, call_span, arg_idx as usize)?;
    Some(arg.value_text.clone())
}

fn caller_call_receiver_and_arg_count(
    caller_decl: &bonsai_lang_api::Decl,
    call_span: bonsai_common::Span,
) -> Option<(String, usize)> {
    fn find_call_receiver(events: &[FlowEvent], target_span: bonsai_common::Span) -> Option<(&str, usize)> {
        for event in events {
            match event {
                FlowEvent::Call {
                    span, receiver, args, ..
                } if *span == target_span => {
                    return receiver.as_deref().map(|receiver| (receiver, args.len()));
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    if let Some(found) = find_call_receiver(then_events, target_span) {
                        return Some(found);
                    }
                    if let Some(found) = find_call_receiver(else_events, target_span) {
                        return Some(found);
                    }
                }
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    if let Some(found) = find_call_receiver(body, target_span) {
                        return Some(found);
                    }
                    if let Some(found) = find_call_receiver(catch_events, target_span) {
                        return Some(found);
                    }
                    if let Some(found) = find_call_receiver(finally_events, target_span) {
                        return Some(found);
                    }
                }
                FlowEvent::Loop { body, .. } => {
                    if let Some(found) = find_call_receiver(body, target_span) {
                        return Some(found);
                    }
                }
                _ => {}
            }
        }
        None
    }
    find_call_receiver(&caller_decl.flow_events, call_span)
        .map(|(receiver, arg_count)| (receiver.to_string(), arg_count))
}

fn caller_call_name(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    caller: bonsai_common::FuncId,
    call_span: bonsai_common::Span,
) -> Option<String> {
    let symbol = bonsai_common::SymbolId::new(caller.raw());
    let exact_caller = ws.exact_decl(symbol);
    let decl = exact_caller.as_deref().or_else(|| global.decl_of(symbol))?;
    fn find_call_name(events: &[FlowEvent], target_span: bonsai_common::Span) -> Option<&str> {
        for event in events {
            match event {
                FlowEvent::Call { span, name, .. } if *span == target_span => return Some(name),
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    if let Some(found) = find_call_name(then_events, target_span) {
                        return Some(found);
                    }
                    if let Some(found) = find_call_name(else_events, target_span) {
                        return Some(found);
                    }
                }
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    if let Some(found) = find_call_name(body, target_span) {
                        return Some(found);
                    }
                    if let Some(found) = find_call_name(catch_events, target_span) {
                        return Some(found);
                    }
                    if let Some(found) = find_call_name(finally_events, target_span) {
                        return Some(found);
                    }
                }
                FlowEvent::Loop { body, .. } => {
                    if let Some(found) = find_call_name(body, target_span) {
                        return Some(found);
                    }
                }
                _ => {}
            }
        }
        None
    }
    find_call_name(&decl.flow_events, call_span).map(str::to_string)
}

/// `bonsai_callgraph::EdgeKind` → public string form. Keeps
/// JSON output stable across engine refactors.
fn edge_kind_display(kind: bonsai_callgraph::EdgeKind) -> String {
    match kind {
        bonsai_callgraph::EdgeKind::Direct => "direct",
        bonsai_callgraph::EdgeKind::Virtual => "virtual",
        bonsai_callgraph::EdgeKind::Indirect => "indirect",
        bonsai_callgraph::EdgeKind::Unknown => "unknown",
    }
    .to_string()
}

/// `bonsai_common::Precision` → public string form. Same wording the
/// CLI surfaces in JSON output, so library consumers and CLI users
/// see the same labels.
#[must_use]
pub fn precision_display(precision: bonsai_common::Precision) -> String {
    match precision {
        bonsai_common::Precision::Exact => "exact",
        bonsai_common::Precision::Narrowed => "narrowed",
        bonsai_common::Precision::OverApproximate => "over-approximate",
        bonsai_common::Precision::Unknown => "unknown",
    }
    .to_string()
}

pub(crate) fn aggregate_flow_precision(
    precisions: impl IntoIterator<Item = bonsai_common::Precision>,
) -> bonsai_common::Precision {
    precisions
        .into_iter()
        .fold(bonsai_common::Precision::Exact, |acc, precision| {
            acc.meet(precision)
        })
}

#[cfg(test)]
#[path = "taint_tests.rs"]
mod tests;
