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
    /// Sanitizer identifiers (currently unused by the engine but
    /// echoed to the report for parity with the CLI flag set).
    pub sanitizers: Vec<String>,
    /// `--sink X` — keep only records whose callee contains `X`.
    pub sink: Option<&'a str>,
    /// `--budget N` — accepted for compatibility with the legacy
    /// interprocedural engine. The IDG-backed dump path computes its
    /// requested closure exactly and does not use this as a result cap.
    pub budget: Option<u32>,
    /// `--intra-worklist-cap N` — per-function worklist cap inside
    /// the intraprocedural CFG pass.
    pub intra_worklist_cap: Option<u32>,
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
            sanitizers: Vec::new(),
            sink: None,
            budget: None,
            intra_worklist_cap: None,
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
    pub sanitizers: Vec<String>,
    pub analysis_complete: bool,
    pub analysis_incomplete_reasons: Vec<String>,
    pub precision: String,
    pub pairs_analyzed: u32,
    pub saturated: bool,
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
fn file_matches_qualifier(decl_file: &str, qualifier: &str) -> bool {
    if decl_file == qualifier {
        return true;
    }
    if decl_file.ends_with(qualifier)
        && decl_file
            .as_bytes()
            .get(decl_file.len() - qualifier.len() - 1)
            .is_some_and(|b| *b == b'/' || *b == b'\\')
    {
        return true;
    }
    let decl_basename = decl_file
        .rsplit_once(['/', '\\'])
        .map(|(_, tail)| tail)
        .unwrap_or(decl_file);
    decl_basename == qualifier
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
/// `filters.source` with the given seeds / sanitizers, applying the
/// configured filters to the result.
pub fn dump_taint(ws: &Workspace, f: &TaintFilters<'_>) -> TaintOutcome {
    let db = ws.db();
    let global = db.global_index();

    let spec = split_source_spec(f.source);
    let candidates = bonsai_resolve::resolve_callable(&global, spec.name);
    let mut source_candidates: Vec<(bonsai_common::FuncId, TaintSourceCandidate)> = candidates
        .into_iter()
        .filter_map(|func| {
            let symbol = bonsai_common::SymbolId::new(func.raw());
            let decl = global.decl_of(symbol)?;
            let (file, line, column) = format_span(&decl.name_span, ws);
            if let Some(qualifier) = spec.file {
                if !file_matches_qualifier(&file, qualifier) {
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
        .collect();
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

    let effective_seed: bonsai_taint::TokenSet = if f.seeds.is_empty() {
        let symbol = bonsai_common::SymbolId::new(source_func.raw());
        let decl = global.decl_of(symbol);
        let mut seed: bonsai_taint::TokenSet = decl
            .as_ref()
            .map(|d| d.params.iter().filter(|p| !p.is_empty()).cloned().collect())
            .unwrap_or_default();
        // Augment the seed with every local the entry binds. Covers
        // two gaps:
        //   * Param-less entries (Flask / Django views, top-level
        //     scripts) — params alone would give an empty seed.
        //   * Entries that receive their taint via a param-derived
        //     local (e.g. JS `let token = req.query.token`). The
        //     Tree-sitter adapters don't always populate
        //     `source_name` on the Assign, so without this fallback
        //     `token` never picks up taint from `req` and the chain
        //     dies at the first call site.
        // Mirrors `bonsai_taint::taint_facts_for_entry`'s seeding so
        // `dump-taint` and `inspect`'s taint view agree on the seed
        // set across every language.
        if let Some(d) = decl.as_ref() {
            collect_assign_targets(&d.flow_events, &mut seed);
        }
        seed
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
    let idg = db
        .idg_service()
        .unwrap_or_else(|| ws.build_and_seed_idg_service());
    let global = db.global_index();
    let seed_names: Vec<String> = effective_seed.iter().cloned().collect();
    let mut seed_nodes = idg_seed_nodes_for_names(idg.as_ref(), source_func, &seed_names, global.as_ref());
    bonsai_taint::apply_configured_transfer_fixpoint(
        &mut seed_nodes,
        &f.receiver_state_propagations,
        &f.call_result_passthroughs,
        &f.output_arg_flows,
        global.as_ref(),
        idg.as_ref(),
        Some(SEMANTIC_FLOW_MAX_PRECISION),
        None,
    );

    let closure_nodes =
        idg.forward_closure_with_max_precision(&seed_nodes, Some(SEMANTIC_FLOW_MAX_PRECISION));
    let cross_calls = idg
        .cross_call_edges_in_reachable_nodes_with_max_precision(
            &closure_nodes,
            Some(SEMANTIC_FLOW_MAX_PRECISION),
        )
        .into_iter()
        .collect::<Vec<_>>();
    let tainted_arg_sites = idg.tainted_call_args_in_reachable_nodes(&closure_nodes);
    // Legacy worklist knobs have no exactness-preserving surface on
    // the IDG path: the closure is a complete bitset walk rather than
    // a resumable chunked worklist. Keep accepting the flags for CLI
    // compatibility, but never use them to cap emitted evidence.
    let _ = (f.budget, f.intra_worklist_cap);
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
    let mut analysis_incomplete_reasons = dump_taint_incomplete_reasons(false);
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
        sanitizers: f.sanitizers.clone(),
        analysis_complete: analysis_incomplete_reasons.is_empty(),
        analysis_incomplete_reasons,
        precision: precision_display(aggregate_precision),
        pairs_analyzed: u32::try_from(pairs_analyzed).unwrap_or(u32::MAX),
        saturated: false,
        records,
    })
}

fn dump_taint_incomplete_reasons(saturated: bool) -> Vec<String> {
    if saturated {
        vec!["taint propagation saturated before semantic fixed point".to_string()]
    } else {
        Vec::new()
    }
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
    tainted_arg_sites: &[(bonsai_common::FuncId, bonsai_common::Span, u8)],
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
        let Some(call_name) = caller_call_name(global, *caller, *span) else {
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
    if decl_name == event_name {
        return true;
    }
    let mut tail = event_name;
    if let Some(idx) = tail.rfind("->") {
        tail = &tail[idx + 2..];
    }
    if let Some((_, rest)) = tail.rsplit_once(['.', ':']) {
        tail = rest;
    }
    if let Some(idx) = tail.find('/') {
        if tail[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
            tail = &tail[..idx];
        }
    }
    decl_name == tail
        || decl_name
            .rsplit_once(['.', ':'])
            .map(|(_, suffix)| suffix == tail)
            .unwrap_or(false)
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
    let caller_decl = global.decl_of(bonsai_common::SymbolId::new(ce.caller.raw()))?;
    let callee_decl = global.decl_of(bonsai_common::SymbolId::new(ce.callee.raw()))?;
    let (caller_file, caller_line, _) = format_span(&caller_decl.name_span, ws);
    let (callee_file, callee_line, _) = format_span(&callee_decl.name_span, ws);
    let (call_file, call_line, call_column) = format_span(&ce.call_span, ws);

    let tainted_args = tainted_args_from_cross_call(ce, callee_decl, global)?;
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
    callee_decl: &bonsai_lang_api::Decl,
    global: &bonsai_index::GlobalIndex,
) -> Option<Vec<TaintedArgRecord>> {
    if ce.arg_idx == u8::MAX {
        return caller_call_receiver(global, ce.caller, ce.call_span)
            .filter(|receiver| !receiver.trim().is_empty())
            .map(|receiver| {
                vec![TaintedArgRecord {
                    index: usize::MAX,
                    value_text: receiver,
                    param_name: "receiver".to_string(),
                }]
            });
    }
    let value_text = caller_arg_value_text(global, ce.caller, ce.call_span, ce.arg_idx).unwrap_or_default();
    let param_name = if ce.param_idx == u8::MAX {
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

/// Build the exact IDG seed node set for a source function and
/// source-token names. This includes formal parameter slots plus
/// read/write nodes matching the caller-selected seed names.
pub(crate) fn idg_seed_nodes_for_names(
    idg: &bonsai_idg::IdgQueryService,
    source_func: bonsai_common::FuncId,
    seed_names: &[String],
    global: &bonsai_index::GlobalIndex,
) -> Vec<bonsai_idg::WsNodeId> {
    let mut seed_nodes: Vec<bonsai_idg::WsNodeId> =
        idg.param_nodes_for_names(source_func, seed_names, global);
    // Augment with explicit seeds the user supplied (or the
    // assign-target augment built for dump-taint). The
    // `read_or_write_nodes_for_names` helper looks each seed name
    // up in the source func's segment string pool.
    seed_nodes.extend(idg.read_or_write_nodes_for_names(source_func, seed_names));
    seed_nodes.sort();
    seed_nodes.dedup();
    seed_nodes
}

/// Look up the textual form of the `arg_idx`-th argument of the
/// `Call` event whose span is `call_span` inside `caller`. Returns
/// `None` when the caller isn't in the index, isn't callable, or no
/// Call event matches the span / index.
fn caller_arg_value_text(
    global: &bonsai_index::GlobalIndex,
    caller: bonsai_common::FuncId,
    call_span: bonsai_common::Span,
    arg_idx: u8,
) -> Option<String> {
    let decl = global.decl_of(bonsai_common::SymbolId::new(caller.raw()))?;
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
    let arg = find_call_arg(&decl.flow_events, call_span, arg_idx as usize)?;
    Some(arg.value_text.clone())
}

fn caller_call_receiver(
    global: &bonsai_index::GlobalIndex,
    caller: bonsai_common::FuncId,
    call_span: bonsai_common::Span,
) -> Option<String> {
    let decl = global.decl_of(bonsai_common::SymbolId::new(caller.raw()))?;
    fn find_call_receiver(events: &[FlowEvent], target_span: bonsai_common::Span) -> Option<&str> {
        for event in events {
            match event {
                FlowEvent::Call { span, receiver, .. } if *span == target_span => {
                    return receiver.as_deref();
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
    find_call_receiver(&decl.flow_events, call_span).map(str::to_string)
}

fn caller_call_name(
    global: &bonsai_index::GlobalIndex,
    caller: bonsai_common::FuncId,
    call_span: bonsai_common::Span,
) -> Option<String> {
    let decl = global.decl_of(bonsai_common::SymbolId::new(caller.raw()))?;
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

/// Walk the entry's flow events and harvest every name it physically
/// binds or touches as a call-site argument. Used as a permissive seed
/// augmentation for param-less or param-adjacent entries so taint has
/// every candidate carrier already in its initial state — specifically:
///   * `Assign { target }` — locals the entry writes.
///   * `Call { args[*].value_text }` — locals the entry passes to a
///     callee. Catches pointer-out patterns like C's `sscanf(qs, fmt,
///     token, action)` where the adapter can't see `token` / `action`
///     as assignment targets but they carry taint at the call site.
///
/// Mirrors the same helper in `bonsai_taint::reachable` (kept here to
/// avoid a cycle through the taint crate's private helpers).
fn collect_assign_targets(events: &[FlowEvent], out: &mut bonsai_taint::TokenSet) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_call_args,
                ..
            } => {
                if !target.is_empty() {
                    out.insert(target.clone());
                }
                // RHS args: bare identifiers might pick up taint
                // through aliasing — `let token = req.cookies.token`
                // needs `token` in the seed set.
                for arg in source_call_args {
                    let trimmed = arg.trim();
                    if is_bare_identifier(trimmed) {
                        out.insert(trimmed.to_string());
                    }
                }
            }
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    // Bare identifiers only — keep `token` but skip
                    // string literals / expressions like `"token=%s"`
                    // or `a + b`. Bare-id check: first char is an
                    // identifier-start char (letter / `_`) and the
                    // rest is all identifier chars.
                    let trimmed = arg.value_text.trim();
                    if is_bare_identifier(trimmed) {
                        out.insert(trimmed.to_string());
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assign_targets(then_events, out);
                collect_assign_targets(else_events, out);
            }
            FlowEvent::Loop { body, .. } => collect_assign_targets(body, out),
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_assign_targets(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assign_targets(body, out);
                collect_assign_targets(catch_events, out);
                collect_assign_targets(finally_events, out);
            }
            _ => {}
        }
    }
}

/// True when `s` is a bare identifier (letter/underscore start,
/// ascii-alphanumeric/underscore tail). Used to gate call-arg
/// tokens into the taint seed: we want `token`, not string
/// literals or compound expressions.
fn is_bare_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
#[path = "taint_tests.rs"]
mod tests;
