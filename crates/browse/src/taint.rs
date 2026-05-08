//! `bonsai-ninja dump-taint` data layer.
//!
//! Wraps `bonsai_taint::interprocedural_taint_to_completion_with_caches` with the same
//! filtering / sorting / id-stamping the CLI applies, returning a
//! [`TaintReport`] consumers can render or further process.

use crate::common::format_span;
use bonsai_hash::fnv1a_names_low32;
use bonsai_lang_api::FlowEvent;
use bonsai_workspace::Workspace;
use serde::Serialize;

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
    /// `--budget N` — interprocedural worklist chunk size. Default
    /// 512. The CLI can resume chunks when it needs complete flow
    /// evidence.
    pub budget: Option<u32>,
    /// `--intra-worklist-cap N` — per-function worklist cap inside
    /// the intraprocedural CFG pass.
    pub intra_worklist_cap: Option<u32>,
    /// `--taint T:id` — drill into one propagation by stable id.
    pub taint_id: Option<&'a str>,
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
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct TaintReport {
    pub source: String,
    pub seeds: Vec<String>,
    pub sanitizers: Vec<String>,
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
        .rsplit_once(|c: char| c == '/' || c == '\\')
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
        return SourceSpec { name: spec, ..Default::default() };
    };
    let (head, name) = (&spec[..name_idx], &spec[name_idx + 1..]);
    if name.is_empty() || head.is_empty() {
        return SourceSpec { name: spec, ..Default::default() };
    }
    if name.contains('/') || name.contains('\\') {
        return SourceSpec { name: spec, ..Default::default() };
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

    let config = bonsai_taint::InterTaintConfig {
        sanitizers: bonsai_taint::TokenSet::default(),
        budget: f.budget.unwrap_or(512),
        intra_worklist_cap: f.intra_worklist_cap,
        ..Default::default()
    };

    let caches = bonsai_taint::InterTaintCaches::default();
    let result = bonsai_taint::interprocedural_taint_to_completion_with_caches(
        source_func,
        &effective_seed,
        &config,
        db,
        &caches,
    );

    let mut records: Vec<TaintRecord> = result
        .call_records
        .iter()
        .filter_map(|prop| build_taint_record(prop, ws))
        .collect();

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
    TaintOutcome::Report(TaintReport {
        source: f.source.to_string(),
        seeds,
        sanitizers: f.sanitizers.clone(),
        precision: precision_display(result.precision),
        pairs_analyzed: result.pairs_analyzed,
        saturated: result.saturated,
        records,
    })
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

/// Translate one engine-level [`bonsai_taint::CallPropagation`]
/// into the externally-rendered [`TaintRecord`]. Returns `None`
/// when either the caller or callee FuncId no longer maps to a
/// decl (stale FuncId after a workspace reload, etc).
fn build_taint_record(prop: &bonsai_taint::CallPropagation, ws: &Workspace) -> Option<TaintRecord> {
    let global = ws.db().global_index();
    let caller_decl = global.decl_of(bonsai_common::SymbolId::new(prop.caller.raw()))?;
    let callee_decl = global.decl_of(bonsai_common::SymbolId::new(prop.callee.raw()))?;
    let (caller_file, caller_line, _) = format_span(&caller_decl.name_span, ws);
    let (callee_file, callee_line, _) = format_span(&callee_decl.name_span, ws);
    let (call_file, call_line, call_column) = format_span(&prop.call_span, ws);

    let tainted_args: Vec<TaintedArgRecord> = prop
        .tainted_args
        .iter()
        .map(|arg| TaintedArgRecord {
            index: arg.index,
            value_text: arg.value_text.clone(),
            param_name: arg.param_name.clone(),
        })
        .collect();

    // Param names go into the taint id so two propagations that
    // hit the same call site but taint different params get
    // distinct ids.
    let param_names: Vec<String> = tainted_args.iter().map(|a| a.param_name.clone()).collect();
    let taint_id = compute_taint_id(
        &caller_decl.name,
        &callee_decl.name,
        &call_file,
        call_line,
        call_column,
        &param_names,
    );

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
        tainted_args,
        edge_kind: edge_kind_display(prop.edge_kind),
        edge_precision: precision_display(prop.edge_precision),
    })
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
