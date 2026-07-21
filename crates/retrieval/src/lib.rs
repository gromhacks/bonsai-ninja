//! Fact-backed candidate retrieval for bonsai-ninja.
//!
//! Retrieval is deliberately not an evidence engine. It stores
//! syntax/semantic fact *documents* and deterministic lexical indexes so
//! callers can find candidate fact ids quickly. Callers must hydrate
//! candidates back through canonical browse / resolver / graph / taint APIs
//! before rendering public analysis facts.

use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_common::{cached_span_map_arc, wire, workspace_bonsai_dir, FileId, Precision, Span, SymbolId};
use bonsai_factstore::{FactStoreReader, FactStoreWriter, LookupHit};
use bonsai_hash::{fnv1a_bytes64, fnv1a_str_slice64, Hasher as StableHasher};
use bonsai_lang_api::{
    operations_from_flow_events, Decl, DeclKind, FlowEvent, ImportSpec, Operation, RefKind,
};
use bonsai_workspace::Workspace;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Retrieval sidecar schema version. Bump when [`FactDoc`] or
/// [`FactSnapshot`] persistence semantics change.
// v2 (2026-06-29): import candidate text/identity coverage was tightened
// for named imports, so older retrieval.v1 sidecars can miss hydrated import
// rows even when canonical search would render them.
// v3 (2026-06-30): call argument docs index keyword/place/source operand
// metadata as candidate text, so older retrieval.v2 sidecars can miss
// inspect prefilter candidates that canonical inspect would hydrate.
// v4 (2026-06-30): inspect display text for named call args and
// assignment-source summaries is candidate text, so older retrieval.v3
// sidecars can miss large-workspace inspect prefilter candidates for
// queries such as `host=endpoint` or `result = verify_token`.
// v5 (2026-06-30): file documents are persisted as first-class retrieval
// candidates, so older retrieval.v4 sidecars can miss file-kind lookups.
// v6 (2026-06-30): import fallback and alias/original-symbol metadata are
// persisted as retrieval candidate text, so older retrieval.v5 sidecars can
// miss import candidates that canonical inspect/import rendering can hydrate.
// v7 (2026-07-01): language-neutral operation documents and enclosing
// function candidate text for file-scoped facts are persisted so filtered
// browse commands can use warmed sidecars for file narrowing without
// rendering retrieval docs as evidence.
// v8 (2026-07-13): persisted documents use an interned string dictionary and
// streaming zstd compression. Canonical FactDoc semantics are unchanged; the
// representation removes workspace-scale repetition from the sidecar.
// v9 (2026-07-16): MessagePack replaces the retired binary codec.
// v10 (2026-07-16): compact string/comment candidate rows retain their
// enclosing AST callable names, restoring the v7 candidate contract.
pub const RETRIEVAL_SCHEMA_VERSION: u32 = 10;

/// Factstore table id for retrieval snapshots.
pub const RETRIEVAL_TABLE_ID: u32 = 0x5254_5631;

const SNAPSHOT_KEY: u64 = 0x5254_5249_4556_414c;
const PIPELINE_SALT: u64 = 0x7a91_5f4c_2d31_8870;
const DEFAULT_ON_DEMAND_BUILD_FILE_LIMIT: usize = 512;

/// Conventional retrieval sidecar path under `<workspace>/.bonsai/`.
#[must_use]
pub fn retrieval_sidecar_path(workspace_root: &Path) -> PathBuf {
    workspace_bonsai_dir(workspace_root).join(format!("retrieval.v{RETRIEVAL_SCHEMA_VERSION}.factstore"))
}

/// Stable source span embedded in a [`FactDoc`].
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct FactSpan {
    pub line: u32,
    pub column: u32,
    pub start: u64,
    pub end: u64,
}

/// Persisted retrieval document. This is candidate metadata only; public
/// renderers must rehydrate through canonical facts before display.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FactDoc {
    pub fact_id: String,
    pub kind: String,
    pub language: Option<String>,
    pub file_path: String,
    pub span: FactSpan,
    pub symbol_name: Option<String>,
    pub qualified_name: Option<String>,
    pub enclosing_function: Option<String>,
    pub enclosing_class: Option<String>,
    pub stable_ids: Vec<String>,
    pub resolver_precision: Option<String>,
    pub resolver_stage: Option<String>,
    pub provenance: Option<String>,
    pub confidence: Option<u8>,
    pub static_limits: Vec<String>,
    pub incomplete_reasons: Vec<String>,
    pub normalized_search_text: String,
    pub content_fingerprint: u64,
    pub pipeline_fingerprint: u64,
}

/// Versioned persisted retrieval payload.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FactSnapshot {
    pub schema_version: u32,
    pub pipeline_fingerprint: u64,
    pub docs: Vec<FactDoc>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CompactFactSnapshot {
    schema_version: u32,
    pipeline_fingerprint: u64,
    strings: Vec<String>,
    docs: Vec<CompactFactDoc>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CompactFactDoc {
    fact_id: u32,
    kind: u32,
    language: Option<u32>,
    file_path: u32,
    span: FactSpan,
    symbol_name: Option<u32>,
    qualified_name: Option<u32>,
    enclosing_function: Option<u32>,
    enclosing_class: Option<u32>,
    stable_ids: Vec<u32>,
    resolver_precision: Option<u32>,
    resolver_stage: Option<u32>,
    provenance: Option<u32>,
    confidence: Option<u8>,
    static_limits: Vec<u32>,
    incomplete_reasons: Vec<u32>,
    normalized_search_text: u32,
    content_fingerprint: u64,
    pipeline_fingerprint: u64,
}

/// Result of ensuring the persisted retrieval sidecar exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetrievalSidecarStatus {
    Reused { docs: usize },
    Rebuilt { docs: usize },
}

/// Candidate returned by a retrieval/ranking provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    pub fact_id: String,
    pub rank: u32,
    /// False for future vector-only candidates. Renderers must ignore
    /// candidates that are not backed by a [`FactDoc`].
    pub fact_backed: bool,
}

/// Abstraction for future rankers. Implementations may rank candidates,
/// but cannot provide evidence.
pub trait CandidateRanker {
    fn candidates(&self, query: &str) -> Vec<Candidate>;
}

/// Explicit marker for vector-like candidate providers. It returns ids
/// only and is never displayable evidence.
#[derive(Clone, Debug, Default)]
pub struct VectorCandidateIds {
    candidates: Vec<Candidate>,
}

impl VectorCandidateIds {
    #[must_use]
    pub fn new(fact_ids: impl IntoIterator<Item = String>) -> Self {
        Self {
            candidates: fact_ids
                .into_iter()
                .enumerate()
                .map(|(idx, fact_id)| Candidate {
                    fact_id,
                    rank: idx as u32,
                    fact_backed: false,
                })
                .collect(),
        }
    }
}

impl CandidateRanker for VectorCandidateIds {
    fn candidates(&self, _query: &str) -> Vec<Candidate> {
        self.candidates.clone()
    }
}

/// Deterministic in-memory indexes over [`FactDoc`] values.
#[derive(Clone, Debug, Default)]
pub struct FactIndex {
    docs: Vec<FactDoc>,
    by_fact_id: AHashMap<String, usize>,
    by_stable_id: AHashMap<String, Vec<usize>>,
    by_kind: AHashMap<String, Vec<usize>>,
    by_file: AHashMap<String, Vec<usize>>,
    by_symbol: AHashMap<String, Vec<usize>>,
    by_prefix: AHashMap<String, Vec<usize>>,
    by_token: AHashMap<String, Vec<usize>>,
    by_trigram: AHashMap<String, Vec<usize>>,
    by_caller: AHashMap<String, Vec<usize>>,
    by_callee: AHashMap<String, Vec<usize>>,
    by_source_sink: AHashMap<String, Vec<usize>>,
}

/// Query against a [`FactIndex`].
#[derive(Clone, Debug, Default)]
pub struct RetrievalQuery<'a> {
    pub text: &'a str,
    pub kind: Option<&'a str>,
    pub file: Option<&'a str>,
    pub workspace_root: Option<&'a Path>,
    pub regex: bool,
    pub limit: usize,
}

impl FactIndex {
    #[must_use]
    pub fn from_docs(docs: Vec<FactDoc>) -> Self {
        let mut index = Self {
            docs: dedup_docs(docs),
            ..Self::default()
        };
        index.rebuild();
        index
    }

    #[must_use]
    pub fn docs(&self) -> &[FactDoc] {
        &self.docs
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.docs.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    #[must_use]
    pub fn get(&self, fact_id: &str) -> Option<&FactDoc> {
        self.by_fact_id.get(fact_id).and_then(|idx| self.docs.get(*idx))
    }

    #[must_use]
    pub fn stable_id(&self, stable_id: &str) -> Vec<&FactDoc> {
        self.lookup_many(&self.by_stable_id, stable_id)
    }

    #[must_use]
    pub fn kind(&self, kind: &str) -> Vec<&FactDoc> {
        self.lookup_many(&self.by_kind, &kind.to_lowercase())
    }

    #[must_use]
    pub fn file(&self, file: &str) -> Vec<&FactDoc> {
        self.lookup_many(&self.by_file, file)
    }

    #[must_use]
    pub fn symbol(&self, symbol: &str) -> Vec<&FactDoc> {
        self.lookup_many(&self.by_symbol, &symbol.to_lowercase())
    }

    #[must_use]
    pub fn caller(&self, caller: &str) -> Vec<&FactDoc> {
        self.lookup_many(&self.by_caller, &caller.to_lowercase())
    }

    #[must_use]
    pub fn callee(&self, callee: &str) -> Vec<&FactDoc> {
        self.lookup_many(&self.by_callee, &callee.to_lowercase())
    }

    /// Return fact-backed candidates for a lexical query.
    pub fn query(&self, query: &RetrievalQuery<'_>) -> Result<Vec<&FactDoc>, regex::Error> {
        let mut candidate_idxs = self.candidate_indices(query)?;
        candidate_idxs.retain(|idx| Self::matches_filters(&self.docs[*idx], query));
        candidate_idxs.sort_by(|a, b| {
            let a_doc = &self.docs[*a];
            let b_doc = &self.docs[*b];
            relevance_key(a_doc, query.text)
                .cmp(&relevance_key(b_doc, query.text))
                .then_with(|| a_doc.file_path.cmp(&b_doc.file_path))
                .then_with(|| a_doc.span.line.cmp(&b_doc.span.line))
                .then_with(|| a_doc.kind.cmp(&b_doc.kind))
                .then_with(|| a_doc.fact_id.cmp(&b_doc.fact_id))
        });
        candidate_idxs.dedup();
        if query.limit > 0 && candidate_idxs.len() > query.limit {
            candidate_idxs.truncate(query.limit);
        }
        Ok(candidate_idxs
            .into_iter()
            .filter_map(|idx| self.docs.get(idx))
            .collect())
    }

    /// Hydrate ranker candidates by fact id. Candidates without a
    /// backing [`FactDoc`] are dropped.
    #[must_use]
    pub fn hydrate_candidates(&self, candidates: &[Candidate]) -> Vec<&FactDoc> {
        let mut out = Vec::new();
        for candidate in candidates {
            if !candidate.fact_backed {
                continue;
            }
            if let Some(doc) = self.get(&candidate.fact_id) {
                out.push(doc);
            }
        }
        out
    }

    fn lookup_many(&self, map: &AHashMap<String, Vec<usize>>, key: &str) -> Vec<&FactDoc> {
        map.get(key)
            .into_iter()
            .flatten()
            .filter_map(|idx| self.docs.get(*idx))
            .collect()
    }

    fn candidate_indices(&self, query: &RetrievalQuery<'_>) -> Result<Vec<usize>, regex::Error> {
        let text = query.text.trim();
        if text.is_empty() {
            return Ok((0..self.docs.len()).collect());
        }
        if let Some(idxs) = self.by_fact_id.get(text) {
            return Ok(vec![*idxs]);
        }
        if let Some(idxs) = self.by_stable_id.get(text) {
            return Ok(idxs.clone());
        }
        if query.regex {
            let re = regex::Regex::new(text)?;
            return Ok(self
                .docs
                .iter()
                .enumerate()
                .filter_map(|(idx, doc)| re.is_match(&doc.normalized_search_text).then_some(idx))
                .collect());
        }
        let lower = text.to_lowercase();
        let mut sets = Vec::new();
        if lower.len() >= 3 {
            for tri in trigrams(&lower) {
                if let Some(idxs) = self.by_trigram.get(&tri) {
                    sets.push(idxs.iter().copied().collect::<AHashSet<_>>());
                }
            }
        }
        if sets.is_empty() {
            let prefix_key = prefix_key(&lower);
            if let Some(idxs) = self.by_prefix.get(&prefix_key) {
                return Ok(idxs.clone());
            }
            let token = token_key(&lower);
            if let Some(idxs) = self.by_token.get(&token) {
                return Ok(idxs.clone());
            }
            return Ok(self
                .docs
                .iter()
                .enumerate()
                .filter_map(|(idx, doc)| doc.normalized_search_text.contains(&lower).then_some(idx))
                .collect());
        }
        let mut iter = sets.into_iter();
        let Some(mut acc) = iter.next() else {
            return Ok(Vec::new());
        };
        for set in iter {
            acc.retain(|idx| set.contains(idx));
        }
        Ok(acc.into_iter().collect())
    }

    fn matches_filters(doc: &FactDoc, query: &RetrievalQuery<'_>) -> bool {
        if query
            .kind
            .is_some_and(|kind| !doc.kind.to_lowercase().contains(&kind.to_lowercase()))
        {
            return false;
        }
        if query
            .file
            .is_some_and(|file| !file_path_matches_query(&doc.file_path, file, query.workspace_root))
        {
            return false;
        }
        let text = query.text.trim();
        if !text.is_empty()
            && !query.regex
            && (doc.fact_id == text || doc.stable_ids.iter().any(|stable_id| stable_id == text))
        {
            return true;
        }
        if text.is_empty() || query.regex {
            return true;
        }
        doc.normalized_search_text.contains(&text.to_lowercase())
    }

    fn rebuild(&mut self) {
        for (idx, doc) in self.docs.iter().enumerate() {
            self.by_fact_id.insert(doc.fact_id.clone(), idx);
            push_idx(&mut self.by_kind, doc.kind.to_lowercase(), idx);
            push_idx(&mut self.by_file, doc.file_path.clone(), idx);
            if let Some(symbol) = &doc.symbol_name {
                push_idx(&mut self.by_symbol, symbol.to_lowercase(), idx);
                push_idx(&mut self.by_prefix, prefix_key(symbol), idx);
            }
            for stable_id in &doc.stable_ids {
                push_idx(&mut self.by_stable_id, stable_id.clone(), idx);
            }
            for token in tokens(&doc.normalized_search_text) {
                push_idx(&mut self.by_token, token.clone(), idx);
                push_idx(&mut self.by_prefix, prefix_key(&token), idx);
            }
            for tri in trigrams(&doc.normalized_search_text) {
                push_idx(&mut self.by_trigram, tri, idx);
            }
            if doc.kind == "edge" {
                if let Some((caller, callee)) = edge_terms(doc) {
                    push_idx(&mut self.by_caller, caller, idx);
                    push_idx(&mut self.by_callee, callee, idx);
                }
            }
            for key in source_sink_keys(doc) {
                push_idx(&mut self.by_source_sink, key, idx);
            }
        }
        dedup_map(&mut self.by_stable_id);
        dedup_map(&mut self.by_kind);
        dedup_map(&mut self.by_file);
        dedup_map(&mut self.by_symbol);
        dedup_map(&mut self.by_prefix);
        dedup_map(&mut self.by_token);
        dedup_map(&mut self.by_trigram);
        dedup_map(&mut self.by_caller);
        dedup_map(&mut self.by_callee);
        dedup_map(&mut self.by_source_sink);
    }
}

/// Build a retrieval index from canonical workspace facts.
#[must_use]
pub fn build_fact_index(ws: &Workspace) -> FactIndex {
    FactIndex::from_docs(build_fact_docs(ws))
}

/// Build persisted fact documents from canonical workspace facts.
#[must_use]
pub fn build_fact_docs(ws: &Workspace) -> Vec<FactDoc> {
    let pipeline = pipeline_hash_for_workspace(ws);
    let global = ws.db().global_index();
    let mut docs = Vec::new();
    for file in global.all_files() {
        // Fact ids include the source file. Deduplicate one file at a time so
        // a large workspace never retains and globally sorts the duplicate
        // operation/ref/event projections for every file at once.
        let mut file_docs = Vec::new();
        let file_path = ws
            .vfs()
            .path(file)
            .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
        let language = ws
            .db()
            .adapter_for(file)
            .map(|adapter| adapter.language_id().as_str().to_string());
        push_file_doc(
            ws,
            &mut file_docs,
            file,
            &file_path,
            language.as_deref(),
            pipeline,
        );
        for decl in global.decls_in(file) {
            push_decl_doc(ws, &mut file_docs, decl, language.as_deref(), pipeline);
            let ctx = FlowDocContext {
                in_fn: &decl.name,
                language: language.as_deref(),
                pipeline,
            };
            for op in operations_from_flow_events(&decl.flow_events) {
                push_operation_doc(ws, &mut file_docs, &op, &ctx);
            }
            walk_flow_events(
                ws,
                &mut file_docs,
                &decl.flow_events,
                &decl.name,
                language.as_deref(),
                pipeline,
            );
        }
        for import in import_specs_for_retrieval(ws, file) {
            push_import_doc(ws, &mut file_docs, &import, language.as_deref(), pipeline);
        }
        if let Some(idx) = global.file_index(file) {
            for reference in &idx.refs {
                let (span, content) = span_doc_fields(ws, reference.span);
                let kind = match reference.kind {
                    RefKind::Read => "ref-read",
                    RefKind::Write => "ref-write",
                    RefKind::Call => "ref-call",
                    RefKind::Decorator => "ref-decorator",
                    _ => "ref",
                };
                let enclosing_function = enclosing_function_for_span(ws, reference.span);
                let mut search_parts = vec![reference.name.as_str(), kind];
                if let Some(function) = enclosing_function.as_deref() {
                    search_parts.push(function);
                }
                file_docs.push(new_doc(DocInput {
                    kind,
                    language: language.as_deref(),
                    file_path: &file_path,
                    span,
                    symbol_name: Some(reference.name.as_str()),
                    qualified_name: None,
                    enclosing_function: enclosing_function.as_deref(),
                    enclosing_class: None,
                    stable_ids: Vec::new(),
                    precision: None,
                    resolver_stage: None,
                    provenance: None,
                    confidence: None,
                    static_limits: Vec::new(),
                    incomplete_reasons: Vec::new(),
                    search_parts: &search_parts,
                    content_fingerprint: content,
                    pipeline_fingerprint: pipeline,
                }));
            }
            for string in &idx.strings {
                let (span, content) = span_doc_fields(ws, string.span);
                let category = format!("{:?}", string.category).to_lowercase();
                let enclosing_function = enclosing_function_for_span(ws, string.span);
                let mut search_parts = vec![string.text.as_str(), category.as_str()];
                if let Some(function) = enclosing_function.as_deref() {
                    search_parts.push(function);
                }
                file_docs.push(new_doc(DocInput {
                    kind: "string",
                    language: language.as_deref(),
                    file_path: &file_path,
                    span,
                    symbol_name: Some(string.text.as_str()),
                    qualified_name: None,
                    enclosing_function: enclosing_function.as_deref(),
                    enclosing_class: None,
                    stable_ids: Vec::new(),
                    precision: None,
                    resolver_stage: None,
                    provenance: Some(category.as_str()),
                    confidence: None,
                    static_limits: Vec::new(),
                    incomplete_reasons: Vec::new(),
                    search_parts: &search_parts,
                    content_fingerprint: content,
                    pipeline_fingerprint: pipeline,
                }));
            }
            for comment in &idx.comments {
                let (span, content) = span_doc_fields(ws, comment.span);
                let category = format!("{:?}", comment.kind).to_lowercase();
                let enclosing_function = enclosing_function_for_span(ws, comment.span);
                let mut search_parts = vec![comment.text.as_str(), category.as_str()];
                if let Some(function) = enclosing_function.as_deref() {
                    search_parts.push(function);
                }
                file_docs.push(new_doc(DocInput {
                    kind: "comment",
                    language: language.as_deref(),
                    file_path: &file_path,
                    span,
                    symbol_name: Some(comment.text.as_str()),
                    qualified_name: None,
                    enclosing_function: enclosing_function.as_deref(),
                    enclosing_class: None,
                    stable_ids: Vec::new(),
                    precision: None,
                    resolver_stage: None,
                    provenance: Some(category.as_str()),
                    confidence: None,
                    static_limits: Vec::new(),
                    incomplete_reasons: Vec::new(),
                    search_parts: &search_parts,
                    content_fingerprint: content,
                    pipeline_fingerprint: pipeline,
                }));
            }
        }
        docs.extend(dedup_docs(file_docs));
    }
    let mut edge_docs = Vec::new();
    push_edge_docs(ws, &mut edge_docs, pipeline);
    docs.extend(dedup_docs(edge_docs));
    docs
}

#[derive(Default)]
struct FileCandidateTerms {
    terms: AHashSet<String>,
    stable_ids: AHashSet<String>,
}

impl FileCandidateTerms {
    fn add(&mut self, value: &str) {
        let raw = value.trim().to_lowercase();
        if !raw.is_empty() {
            self.terms.insert(raw);
        }
        self.terms.extend(tokens(value));
    }

    fn add_stable_id(&mut self, value: String) {
        self.add(&value);
        self.stable_ids.insert(value);
    }
}

fn candidate_terms<'a>(
    groups: &'a mut AHashMap<String, FileCandidateTerms>,
    kind: &str,
) -> &'a mut FileCandidateTerms {
    groups.entry(kind.to_string()).or_default()
}

fn collect_flow_candidate_terms(
    groups: &mut AHashMap<String, FileCandidateTerms>,
    events: &[FlowEvent],
    in_fn: &str,
) {
    for event in events {
        match event {
            FlowEvent::Call { name, args, .. } => {
                let calls = candidate_terms(groups, "call");
                calls.add(name);
                calls.add(in_fn);
                for arg in args {
                    let args = candidate_terms(groups, "arg");
                    args.add(&arg.value_text);
                    args.add(in_fn);
                    if let Some(name) = arg.name.as_deref() {
                        args.add(name);
                        args.add(&format!("{name}={}", arg.value_text));
                    }
                    if let Some(place) = arg.place.as_deref() {
                        args.add(place);
                    }
                    for source in &arg.source_names {
                        args.add(source);
                    }
                }
            }
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } => {
                let vars = candidate_terms(groups, "var");
                vars.add(target);
                vars.add(in_fn);
                let display_source = source_name
                    .as_deref()
                    .or(source_call.as_deref())
                    .or_else(|| source_names.first().map(String::as_str));
                if let Some(source) = display_source {
                    vars.add(source);
                    vars.add(&format!("{target} = {source}"));
                }
                if let Some(call) = source_call {
                    let calls = candidate_terms(groups, "call");
                    calls.add(call);
                    calls.add(in_fn);
                    for arg in source_call_args {
                        candidate_terms(groups, "arg").add(arg);
                    }
                }
                for source in source_names {
                    let reads = candidate_terms(groups, "ref-read");
                    reads.add(source);
                    reads.add(in_fn);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_flow_candidate_terms(groups, then_events, in_fn);
                collect_flow_candidate_terms(groups, else_events, in_fn);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_flow_candidate_terms(groups, body, in_fn);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_flow_candidate_terms(groups, body, in_fn);
                collect_flow_candidate_terms(groups, catch_events, in_fn);
                collect_flow_candidate_terms(groups, finally_events, in_fn);
            }
            _ => {}
        }
    }
}

fn finish_file_candidate_groups(
    docs: &mut Vec<FactDoc>,
    file_path: &str,
    language: Option<&str>,
    span: FactSpan,
    content_fingerprint: u64,
    pipeline_fingerprint: u64,
    groups: AHashMap<String, FileCandidateTerms>,
) {
    let mut groups: Vec<_> = groups.into_iter().collect();
    groups.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    for (kind, group) in groups {
        let mut terms: Vec<_> = group.terms.into_iter().collect();
        terms.sort_unstable();
        let mut stable_ids: Vec<_> = group.stable_ids.into_iter().collect();
        stable_ids.sort_unstable();
        let normalized_search_text = terms.join(" ");
        docs.push(FactDoc {
            fact_id: fact_id_for_parts(&kind, file_path, span.line, span.column, "file-candidates"),
            kind,
            language: language.map(str::to_string),
            file_path: file_path.to_string(),
            span: span.clone(),
            symbol_name: None,
            qualified_name: None,
            enclosing_function: None,
            enclosing_class: None,
            stable_ids,
            resolver_precision: None,
            resolver_stage: None,
            provenance: Some("file-candidate-index".to_string()),
            confidence: None,
            static_limits: Vec::new(),
            incomplete_reasons: Vec::new(),
            normalized_search_text,
            content_fingerprint,
            pipeline_fingerprint,
        });
    }
}

fn index_semantic_edges_by_file(
    call_graph: &ResolvedCallGraph,
    global: &bonsai_index::GlobalIndex,
) -> AHashMap<FileId, Vec<usize>> {
    let mut edge_indices = AHashMap::default();
    for (index, edge) in call_graph.inner().edges.iter().enumerate() {
        if edge.precision.is_semantic()
            && global.decl_of(SymbolId::new(edge.from.raw())).is_some()
            && global.decl_of(SymbolId::new(edge.to.raw())).is_some()
        {
            edge_indices
                .entry(edge.span.file)
                .or_insert_with(Vec::new)
                .push(index);
        }
    }
    edge_indices
}

fn collect_edge_candidate_terms(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    call_graph: &ResolvedCallGraph,
    groups: &mut AHashMap<String, FileCandidateTerms>,
    edge_indices: &[usize],
) {
    for &index in edge_indices {
        // These ordinals and endpoints were validated against the same
        // immutable graph/index immediately before file batching. Treat a
        // violation as corruption rather than silently omitting a compiler
        // fact from the candidate projection.
        let edge = &call_graph.inner().edges[index];
        let caller = global
            .decl_of(SymbolId::new(edge.from.raw()))
            .expect("indexed retrieval caller must remain in the immutable global index");
        let callee = global
            .decl_of(SymbolId::new(edge.to.raw()))
            .expect("indexed retrieval callee must remain in the immutable global index");
        let edges = candidate_terms(groups, "edge");
        edges.add(&caller.name);
        edges.add(&callee.name);
        edges.add(&format!("{} -> {}", caller.name, callee.name));
        let file_path = ws
            .vfs()
            .path(edge.span.file)
            .map_or_else(|_| "<unknown>".to_string(), |path| path.display().to_string());
        let (span, _) = span_doc_fields(ws, edge.span);
        edges.add_stable_id(edge_id_for_parts(
            &caller.name,
            &callee.name,
            &file_path,
            span.line,
            span.column,
        ));
    }
}

fn collect_decl_candidate_terms(groups: &mut AHashMap<String, FileCandidateTerms>, decl: &Decl) {
    let kind = format!("{:?}", decl.kind).to_lowercase();
    let declarations = candidate_terms(groups, &kind);
    declarations.add(&decl.name);
    if let Some(qualified) = decl.qualified_name.as_deref() {
        declarations.add(qualified);
    }
    for param in &decl.params {
        declarations.add(param);
    }
    for op in operations_from_flow_events(&decl.flow_events) {
        let operations = candidate_terms(groups, "operation");
        operations.add(op.kind.as_str());
        operations.add(&decl.name);
        if let Some(target) = op.target.as_deref() {
            operations.add(target);
        }
        if let Some(detail) = op.detail.as_deref() {
            operations.add(detail);
        }
        for operand in op.operands {
            operations.add(&operand.name);
            operations.add(operand.role.as_str());
            operations.add(&format!("{}:{}", operand.role.as_str(), operand.name));
        }
    }
    collect_flow_candidate_terms(groups, &decl.flow_events, &decl.name);
}

fn collect_import_candidate_terms(groups: &mut AHashMap<String, FileCandidateTerms>, import: &ImportSpec) {
    let kind = if import.alias.is_some() {
        "import-alias"
    } else {
        "import"
    };
    let imports = candidate_terms(groups, kind);
    imports.add(&import.module);
    if let Some(alias) = import.alias.as_deref() {
        imports.add(alias);
    }
    if let Some(original) = import.original_name.as_deref() {
        imports.add(original);
    }
}

fn collect_index_candidate_terms(
    ws: &Workspace,
    groups: &mut AHashMap<String, FileCandidateTerms>,
    index: &bonsai_lang_api::DeclIndex,
) {
    for reference in &index.refs {
        let kind = match reference.kind {
            RefKind::Read => "ref-read",
            RefKind::Write => "ref-write",
            RefKind::Call => "ref-call",
            RefKind::Decorator => "ref-decorator",
            _ => "ref",
        };
        candidate_terms(groups, kind).add(&reference.name);
    }
    for string in &index.strings {
        let enclosing_function = enclosing_function_for_span(ws, string.span);
        let strings = candidate_terms(groups, "string");
        strings.add(&string.text);
        strings.add(&format!("{:?}", string.category).to_lowercase());
        if let Some(function) = enclosing_function.as_deref() {
            strings.add(function);
        }
    }
    for comment in &index.comments {
        let enclosing_function = enclosing_function_for_span(ws, comment.span);
        let comments = candidate_terms(groups, "comment");
        comments.add(&comment.text);
        comments.add(&format!("{:?}", comment.kind).to_lowercase());
        if let Some(function) = enclosing_function.as_deref() {
            comments.add(function);
        }
    }
}

fn build_file_candidate_docs(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    call_graph: &ResolvedCallGraph,
    file: FileId,
    file_path: &str,
    pipeline: u64,
    edge_indices: &[usize],
) -> Vec<FactDoc> {
    let language = ws
        .db()
        .adapter_for(file)
        .map(|adapter| adapter.language_id().as_str().to_string());
    let (file_span, content_fingerprint) = ws.vfs().snapshot(file).map_or_else(
        |_| {
            (
                FactSpan {
                    line: 1,
                    column: 1,
                    ..FactSpan::default()
                },
                0,
            )
        },
        |snapshot| {
            (
                FactSpan {
                    line: 1,
                    column: 1,
                    start: 0,
                    end: snapshot.text.len() as u64,
                },
                fnv1a_bytes64(snapshot.text.as_bytes()),
            )
        },
    );
    let mut groups = AHashMap::default();
    let file_name = Path::new(file_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(file_path);
    let files = candidate_terms(&mut groups, "file");
    files.add(file_path);
    files.add(file_name);
    if let Some(language) = language.as_deref() {
        files.add(language);
    }

    for decl in global.decls_in(file) {
        collect_decl_candidate_terms(&mut groups, decl);
    }
    for import in import_specs_for_retrieval(ws, file) {
        collect_import_candidate_terms(&mut groups, &import);
    }
    if let Some(index) = global.file_index(file) {
        collect_index_candidate_terms(ws, &mut groups, index);
    }
    collect_edge_candidate_terms(ws, global, call_graph, &mut groups, edge_indices);
    let mut docs = Vec::with_capacity(groups.len());
    finish_file_candidate_groups(
        &mut docs,
        file_path,
        language.as_deref(),
        file_span,
        content_fingerprint,
        pipeline,
        groups,
    );
    docs
}

fn retrieval_file_batch_width() -> usize {
    // Candidate terms temporarily duplicate strings from one lowered compiler
    // unit. The estimate controls concurrency only: every file and semantic
    // edge is still processed when constrained machines choose one worker.
    const TRANSIENT_BYTES_PER_FILE: u64 = 1024 * 1024 * 1024;
    const RESIDENT_COMPILER_BYTES: u64 = 2 * 1024 * 1024 * 1024;
    bonsai_common::memory_bounded_worker_count(
        rayon::current_num_threads().max(1),
        TRANSIENT_BYTES_PER_FILE,
        RESIDENT_COMPILER_BYTES,
    )
}

/// Build the persisted candidate-only projection used to narrow files before
/// canonical hydration. The callgraph is indexed by compact edge ordinals;
/// candidate strings are derived and interned one bounded file batch at a
/// time instead of materializing a second whole-workspace graph. The batch
/// width is a scheduling choice only and never limits files or facts.
fn build_persisted_candidate_snapshot(ws: &Workspace) -> CompactFactSnapshot {
    let pipeline = pipeline_hash_for_workspace(ws);
    let global = ws.db().global_index();
    let call_graph = ws.cached_resolved_call_graph();
    let mut edge_indices = index_semantic_edges_by_file(&call_graph, &global);
    let mut file_ids: Vec<_> = global.all_files().collect();
    file_ids.extend(edge_indices.keys().copied());
    file_ids.sort_unstable_by_key(|file| file.raw());
    file_ids.dedup();
    let mut files: Vec<_> = file_ids
        .into_iter()
        .map(|file| {
            let path = ws
                .vfs()
                .path(file)
                .map_or_else(|_| "<unknown>".to_string(), |path| path.display().to_string());
            (path, file)
        })
        .collect();
    files.sort_unstable_by(|left, right| left.0.cmp(&right.0));

    let mut builder = CompactFactSnapshotBuilder::new(RETRIEVAL_SCHEMA_VERSION, pipeline);
    let batch_width = retrieval_file_batch_width();
    for batch in files.chunks(batch_width) {
        let inputs: Vec<_> = batch
            .iter()
            .map(|(path, file)| {
                (
                    *file,
                    path.as_str(),
                    edge_indices.remove(file).unwrap_or_default(),
                )
            })
            .collect();
        let lowered: Vec<Vec<FactDoc>> = inputs
            .into_par_iter()
            .map(|(file, path, edges)| {
                build_file_candidate_docs(ws, &global, &call_graph, file, path, pipeline, &edges)
            })
            .collect();
        for docs in lowered {
            for doc in docs {
                builder.push(doc);
            }
        }
    }

    builder.finish()
}

/// Save a retrieval sidecar for `ws` under `workspace_root`.
pub fn save_sidecar(ws: &Workspace, workspace_root: &Path) -> std::io::Result<usize> {
    require_complete_workspace(ws)?;
    let path = retrieval_sidecar_path(workspace_root);
    save_compact_snapshot(build_persisted_candidate_snapshot(ws), &path)
}

/// Validate an existing retrieval sidecar or build it when stale/missing.
pub fn ensure_sidecar(ws: &Workspace, workspace_root: &Path) -> std::io::Result<RetrievalSidecarStatus> {
    require_complete_workspace(ws)?;
    let pipeline = pipeline_hash_for_workspace(ws);
    match validate_sidecar_file_with_pipeline(&retrieval_sidecar_path(workspace_root), pipeline) {
        Ok(docs) => Ok(RetrievalSidecarStatus::Reused { docs }),
        Err(_) => save_sidecar(ws, workspace_root).map(|docs| RetrievalSidecarStatus::Rebuilt { docs }),
    }
}

/// Load a retrieval sidecar for `ws` from `workspace_root`.
pub fn load_sidecar(ws: &Workspace, workspace_root: &Path) -> std::io::Result<FactIndex> {
    require_complete_workspace(ws)?;
    let pipeline = pipeline_hash_for_workspace(ws);
    load_sidecar_with_pipeline(workspace_root, pipeline)
}

/// Load a retrieval sidecar using a caller-computed pipeline hash.
///
/// This is for query frontends that can cheaply compute source fingerprints
/// from disk and want to consult a warmed retrieval sidecar before opening a
/// full workspace. The returned docs are still candidates only; callers must
/// hydrate through canonical browse / resolver / graph / taint APIs.
pub fn load_sidecar_with_pipeline(workspace_root: &Path, pipeline: u64) -> std::io::Result<FactIndex> {
    let path = retrieval_sidecar_path(workspace_root);
    let reader = FactStoreReader::open(&path, RETRIEVAL_TABLE_ID, pipeline).map_err(map_factstore_io)?;
    let hit = reader
        .get(SNAPSHOT_KEY)
        .map_err(map_factstore_io)?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "retrieval snapshot missing"))?;
    let snapshot = decode_snapshot_hit(hit, pipeline)?;
    Ok(FactIndex::from_docs(snapshot.docs))
}

/// Query a persisted retrieval sidecar for candidate file paths without
/// expanding its compact documents into the heavyweight in-memory
/// [`FactIndex`].
///
/// Large-workspace CLI frontends use retrieval only to narrow the files they
/// subsequently parse and hydrate through canonical compiler APIs. Building
/// trigram/token/prefix indexes over every persisted file/kind document for
/// each one-shot command defeats that purpose: the transient indexes can be
/// orders of magnitude larger than the sidecar itself. This path validates
/// the same pipeline and payload hash, scans the compact string ids directly,
/// and returns only workspace file paths. It never exposes candidate metadata
/// as public evidence.
///
/// Regex lookup remains an in-memory/full-workspace operation because the CLI
/// deliberately does not use a persisted prefilter for regex queries.
pub fn query_sidecar_file_paths_with_pipeline(
    workspace_root: &Path,
    pipeline: u64,
    query: &RetrievalQuery<'_>,
) -> std::io::Result<Vec<String>> {
    if query.regex {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "persisted retrieval file prefilter does not support regex queries",
        ));
    }
    let path = retrieval_sidecar_path(workspace_root);
    let reader = FactStoreReader::open(&path, RETRIEVAL_TABLE_ID, pipeline).map_err(map_factstore_io)?;
    let hit = reader
        .get(SNAPSHOT_KEY)
        .map_err(map_factstore_io)?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "retrieval snapshot missing"))?;
    let snapshot = decode_compact_snapshot_hit(hit, pipeline)?;
    snapshot.query_file_paths(query)
}

/// Validate that a retrieval factstore is structurally readable and carries
/// a current retrieval snapshot. This intentionally does not prove the
/// sidecar is fresh for a workspace; callers combine it with their own
/// source/dependency/build freshness checks.
pub fn validate_sidecar_file(path: &Path) -> std::io::Result<usize> {
    let reader = FactStoreReader::open_relaxed(path).map_err(map_factstore_io)?;
    if reader.header().table_id != RETRIEVAL_TABLE_ID {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "retrieval factstore table id mismatch: file={} expected={}",
                reader.header().table_id,
                RETRIEVAL_TABLE_ID
            ),
        ));
    }
    let hit = reader
        .get(SNAPSHOT_KEY)
        .map_err(map_factstore_io)?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "retrieval snapshot missing"))?;
    let snapshot = decode_compact_snapshot_hit(hit, reader.header().pipeline_hash)?;
    Ok(snapshot.docs.len())
}

/// Validate that a retrieval factstore is structurally readable and fresh for
/// the exact pipeline hash query frontends use before candidate lookup.
pub fn validate_sidecar_file_with_pipeline(path: &Path, pipeline: u64) -> std::io::Result<usize> {
    let reader = FactStoreReader::open(path, RETRIEVAL_TABLE_ID, pipeline).map_err(map_factstore_io)?;
    let hit = reader
        .get(SNAPSHOT_KEY)
        .map_err(map_factstore_io)?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "retrieval snapshot missing"))?;
    let snapshot = decode_compact_snapshot_hit(hit, pipeline)?;
    Ok(snapshot.docs.len())
}

/// Load a fresh sidecar or build/save one on demand.
pub fn load_or_build_sidecar(ws: &Workspace) -> std::io::Result<FactIndex> {
    require_complete_workspace(ws)?;
    let root = ws.db().workspace_root().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "workspace root unavailable for retrieval sidecar",
        )
    })?;
    match load_sidecar(ws, &root) {
        Ok(index) => Ok(index),
        Err(_) => {
            let file_count = ws.vfs().all_files().len();
            if file_count > on_demand_build_file_limit() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    format!(
                        "retrieval sidecar missing or stale and on-demand build is disabled for {file_count} files",
                    ),
                ));
            }
            let index = build_fact_index(ws);
            let snapshot = FactSnapshot {
                schema_version: RETRIEVAL_SCHEMA_VERSION,
                pipeline_fingerprint: pipeline_hash_for_workspace(ws),
                docs: index.docs.clone(),
            };
            let _ = save_snapshot(&snapshot, &retrieval_sidecar_path(&root));
            Ok(index)
        }
    }
}

fn require_complete_workspace(ws: &Workspace) -> std::io::Result<()> {
    if ws.is_complete_workspace_index() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "retrieval sidecars require a complete workspace index",
        ))
    }
}

fn on_demand_build_file_limit() -> usize {
    std::env::var("BONSAI_RETRIEVAL_ON_DEMAND_FILE_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_ON_DEMAND_BUILD_FILE_LIMIT)
}

#[derive(Default)]
struct PersistedStringInterner {
    ids: AHashMap<String, u32>,
}

struct CompactFactSnapshotBuilder {
    schema_version: u32,
    pipeline_fingerprint: u64,
    strings: PersistedStringInterner,
    docs: Vec<CompactFactDoc>,
}

impl PersistedStringInterner {
    fn intern(&mut self, value: String) -> u32 {
        if let Some(id) = self.ids.get(value.as_str()).copied() {
            return id;
        }
        let id = u32::try_from(self.ids.len()).expect("retrieval string dictionary exceeds u32");
        self.ids.insert(value, id);
        id
    }

    fn intern_option(&mut self, value: Option<String>) -> Option<u32> {
        value.map(|value| self.intern(value))
    }

    fn intern_many(&mut self, values: Vec<String>) -> Vec<u32> {
        values.into_iter().map(|value| self.intern(value)).collect()
    }

    fn finish(self) -> Vec<String> {
        let mut strings = vec![String::new(); self.ids.len()];
        for (value, id) in self.ids {
            strings[id as usize] = value;
        }
        strings
    }
}

impl CompactFactSnapshotBuilder {
    fn new(schema_version: u32, pipeline_fingerprint: u64) -> Self {
        Self {
            schema_version,
            pipeline_fingerprint,
            strings: PersistedStringInterner::default(),
            docs: Vec::new(),
        }
    }

    fn push(&mut self, doc: FactDoc) {
        self.docs.push(CompactFactDoc {
            fact_id: self.strings.intern(doc.fact_id),
            kind: self.strings.intern(doc.kind),
            language: self.strings.intern_option(doc.language),
            file_path: self.strings.intern(doc.file_path),
            span: doc.span,
            symbol_name: self.strings.intern_option(doc.symbol_name),
            qualified_name: self.strings.intern_option(doc.qualified_name),
            enclosing_function: self.strings.intern_option(doc.enclosing_function),
            enclosing_class: self.strings.intern_option(doc.enclosing_class),
            stable_ids: self.strings.intern_many(doc.stable_ids),
            resolver_precision: self.strings.intern_option(doc.resolver_precision),
            resolver_stage: self.strings.intern_option(doc.resolver_stage),
            provenance: self.strings.intern_option(doc.provenance),
            confidence: doc.confidence,
            static_limits: self.strings.intern_many(doc.static_limits),
            incomplete_reasons: self.strings.intern_many(doc.incomplete_reasons),
            normalized_search_text: self.strings.intern(doc.normalized_search_text),
            content_fingerprint: doc.content_fingerprint,
            pipeline_fingerprint: doc.pipeline_fingerprint,
        });
    }

    fn finish(self) -> CompactFactSnapshot {
        CompactFactSnapshot {
            schema_version: self.schema_version,
            pipeline_fingerprint: self.pipeline_fingerprint,
            strings: self.strings.finish(),
            docs: self.docs,
        }
    }
}

impl CompactFactSnapshot {
    fn from_docs(schema_version: u32, pipeline_fingerprint: u64, docs: Vec<FactDoc>) -> Self {
        let mut builder = CompactFactSnapshotBuilder::new(schema_version, pipeline_fingerprint);
        for doc in docs {
            builder.push(doc);
        }
        builder.finish()
    }

    fn expand(self) -> std::io::Result<FactSnapshot> {
        fn text(strings: &[String], id: u32) -> std::io::Result<String> {
            strings.get(id as usize).cloned().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("retrieval string id out of range: {id}"),
                )
            })
        }
        fn optional(strings: &[String], id: Option<u32>) -> std::io::Result<Option<String>> {
            id.map(|id| text(strings, id)).transpose()
        }
        fn many(strings: &[String], ids: Vec<u32>) -> std::io::Result<Vec<String>> {
            ids.into_iter().map(|id| text(strings, id)).collect()
        }

        let Self {
            schema_version,
            pipeline_fingerprint,
            strings,
            docs,
        } = self;
        let docs = docs
            .into_iter()
            .map(|doc| {
                Ok(FactDoc {
                    fact_id: text(&strings, doc.fact_id)?,
                    kind: text(&strings, doc.kind)?,
                    language: optional(&strings, doc.language)?,
                    file_path: text(&strings, doc.file_path)?,
                    span: doc.span,
                    symbol_name: optional(&strings, doc.symbol_name)?,
                    qualified_name: optional(&strings, doc.qualified_name)?,
                    enclosing_function: optional(&strings, doc.enclosing_function)?,
                    enclosing_class: optional(&strings, doc.enclosing_class)?,
                    stable_ids: many(&strings, doc.stable_ids)?,
                    resolver_precision: optional(&strings, doc.resolver_precision)?,
                    resolver_stage: optional(&strings, doc.resolver_stage)?,
                    provenance: optional(&strings, doc.provenance)?,
                    confidence: doc.confidence,
                    static_limits: many(&strings, doc.static_limits)?,
                    incomplete_reasons: many(&strings, doc.incomplete_reasons)?,
                    normalized_search_text: text(&strings, doc.normalized_search_text)?,
                    content_fingerprint: doc.content_fingerprint,
                    pipeline_fingerprint: doc.pipeline_fingerprint,
                })
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        Ok(FactSnapshot {
            schema_version,
            pipeline_fingerprint,
            docs,
        })
    }

    fn validate(&self, pipeline: u64) -> std::io::Result<()> {
        validate_snapshot_version(self.schema_version, self.pipeline_fingerprint, pipeline)?;
        let string_count = self.strings.len();
        let validate_id = |id: u32| {
            ((id as usize) < string_count).then_some(()).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("retrieval string id out of range: {id}"),
                )
            })
        };
        for doc in &self.docs {
            validate_id(doc.fact_id)?;
            validate_id(doc.kind)?;
            validate_id(doc.file_path)?;
            validate_id(doc.normalized_search_text)?;
            for id in [
                doc.language,
                doc.symbol_name,
                doc.qualified_name,
                doc.enclosing_function,
                doc.enclosing_class,
                doc.resolver_precision,
                doc.resolver_stage,
                doc.provenance,
            ]
            .into_iter()
            .flatten()
            {
                validate_id(id)?;
            }
            for &id in doc
                .stable_ids
                .iter()
                .chain(&doc.static_limits)
                .chain(&doc.incomplete_reasons)
            {
                validate_id(id)?;
            }
        }
        Ok(())
    }

    fn query_file_paths(&self, query: &RetrievalQuery<'_>) -> std::io::Result<Vec<String>> {
        let text = query.text.trim().to_lowercase();
        let kind = query.kind.map(str::to_lowercase);
        let mut paths = Vec::new();
        for doc in &self.docs {
            let doc_kind = self.string(doc.kind)?;
            if kind
                .as_deref()
                .is_some_and(|filter| !doc_kind.to_lowercase().contains(filter))
            {
                continue;
            }
            let file_path = self.string(doc.file_path)?;
            if query
                .file
                .is_some_and(|filter| !file_path_matches_query(file_path, filter, query.workspace_root))
            {
                continue;
            }
            if !text.is_empty() {
                let searchable = self.string(doc.normalized_search_text)?;
                let fact_id_matches = self.string(doc.fact_id)? == query.text.trim();
                let stable_id_matches = doc
                    .stable_ids
                    .iter()
                    .any(|&id| self.string(id).is_ok_and(|value| value == query.text.trim()));
                if !fact_id_matches && !stable_id_matches && !searchable.contains(&text) {
                    continue;
                }
            }
            paths.push(file_path.to_string());
        }
        paths.sort_unstable();
        paths.dedup();
        if query.limit > 0 {
            paths.truncate(query.limit);
        }
        Ok(paths)
    }

    fn string(&self, id: u32) -> std::io::Result<&str> {
        self.strings.get(id as usize).map(String::as_str).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("retrieval string id out of range: {id}"),
            )
        })
    }
}

fn save_docs_snapshot(
    schema_version: u32,
    pipeline: u64,
    docs: Vec<FactDoc>,
    path: &Path,
) -> std::io::Result<usize> {
    let snapshot = CompactFactSnapshot::from_docs(schema_version, pipeline, docs);
    save_compact_snapshot(snapshot, path)
}

fn save_compact_snapshot(snapshot: CompactFactSnapshot, path: &Path) -> std::io::Result<usize> {
    let doc_count = snapshot.docs.len();
    let pipeline = snapshot.pipeline_fingerprint;
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), 1)?;
    wire::encode_to_writer(&mut encoder, &snapshot).map_err(invalid_data)?;
    let bytes = encoder.finish()?;
    let body_hash = fnv1a_bytes64(&bytes);
    let writer = FactStoreWriter::create(path, RETRIEVAL_TABLE_ID, pipeline).map_err(map_factstore_io)?;
    writer
        .add(SNAPSHOT_KEY, body_hash, &bytes)
        .map_err(map_factstore_io)?;
    writer.finish().map_err(map_factstore_io)?;
    Ok(doc_count)
}

fn save_snapshot(snapshot: &FactSnapshot, path: &Path) -> std::io::Result<usize> {
    save_docs_snapshot(
        snapshot.schema_version,
        snapshot.pipeline_fingerprint,
        snapshot.docs.clone(),
        path,
    )
}

fn decode_snapshot_hit(hit: LookupHit, pipeline: u64) -> std::io::Result<FactSnapshot> {
    decode_compact_snapshot_hit(hit, pipeline)?.expand()
}

fn decode_compact_snapshot_hit(hit: LookupHit, pipeline: u64) -> std::io::Result<CompactFactSnapshot> {
    let actual_hash = fnv1a_bytes64(&hit.payload);
    if hit.body_hash != actual_hash {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "retrieval snapshot body hash mismatch: file={:016x} actual={:016x}",
                hit.body_hash, actual_hash
            ),
        ));
    }
    let decoder = zstd::stream::Decoder::new(std::io::Cursor::new(&hit.payload))?;
    let compact: CompactFactSnapshot = wire::decode_from_reader(decoder).map_err(invalid_data)?;
    compact.validate(pipeline)?;
    Ok(compact)
}

#[cfg(test)]
fn validate_snapshot(snapshot: &FactSnapshot, pipeline: u64) -> std::io::Result<()> {
    validate_snapshot_version(snapshot.schema_version, snapshot.pipeline_fingerprint, pipeline)
}

fn validate_snapshot_version(
    schema_version: u32,
    pipeline_fingerprint: u64,
    pipeline: u64,
) -> std::io::Result<()> {
    if schema_version != RETRIEVAL_SCHEMA_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "retrieval schema version mismatch",
        ));
    }
    if pipeline_fingerprint != pipeline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "retrieval pipeline fingerprint mismatch",
        ));
    }
    Ok(())
}

/// Stable fact id shared by retrieval docs and browse hydration.
#[must_use]
pub fn fact_id_for_parts(kind: &str, file: &str, line: u32, column: u32, name: &str) -> String {
    let digest = fnv1a_str_slice64(&[kind, file, &line.to_string(), &column.to_string(), name]);
    format!("FD:{digest:016x}")
}

/// Pipeline hash for retrieval sidecars. Includes source content,
/// dependency metadata, build fingerprint, and schema version.
#[must_use]
pub fn pipeline_hash_for_workspace(ws: &Workspace) -> u64 {
    let fingerprints = ws.vfs().all_files().into_iter().filter_map(|file| {
        let path = ws.vfs().path(file).ok()?.as_ref().clone();
        let snap = ws.vfs().snapshot(file).ok()?;
        Some((path, fnv1a_bytes64(snap.text.as_bytes())))
    });
    pipeline_hash_for_source_fingerprints(ws.db().workspace_root().as_deref(), fingerprints)
}

/// Pipeline hash from already-known source file content hashes.
///
/// The digest intentionally matches [`pipeline_hash_for_workspace`]. It lets
/// callers validate a full-workspace retrieval sidecar after walking source
/// files, without building parser/adapter facts just to decide whether the
/// sidecar is fresh.
#[must_use]
pub fn pipeline_hash_for_source_fingerprints<I, P>(workspace_root: Option<&Path>, fingerprints: I) -> u64
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    let mut h = StableHasher::new();
    h.absorb(&PIPELINE_SALT.to_le_bytes());
    h.absorb(&RETRIEVAL_SCHEMA_VERSION.to_le_bytes());
    h.absorb(&source_fingerprints_content_fingerprint(fingerprints).to_le_bytes());
    if let Some(root) = workspace_root {
        h.absorb(&dependency_metadata_fingerprint(root).to_le_bytes());
    }
    h.absorb(&build_fingerprint_hash().to_le_bytes());
    h.finish()
}

fn import_specs_for_retrieval(ws: &Workspace, file: bonsai_common::FileId) -> Vec<ImportSpec> {
    ws.db().imports_for(file)
}

fn push_import_doc(
    ws: &Workspace,
    docs: &mut Vec<FactDoc>,
    import: &ImportSpec,
    language: Option<&str>,
    pipeline: u64,
) {
    let (span, content) = span_doc_fields(ws, import.span);
    let file_path = ws
        .vfs()
        .path(import.span.file)
        .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
    let symbol = import.module.clone();
    let kind = if import.alias.is_some() {
        "import-alias"
    } else {
        "import"
    };
    docs.push(new_doc(DocInput {
        kind,
        language,
        file_path: &file_path,
        span,
        symbol_name: Some(symbol.as_str()),
        qualified_name: Some(import.module.as_str()),
        enclosing_function: None,
        enclosing_class: None,
        stable_ids: Vec::new(),
        precision: None,
        resolver_stage: None,
        provenance: import.original_name.as_deref(),
        confidence: None,
        static_limits: Vec::new(),
        incomplete_reasons: Vec::new(),
        search_parts: &[
            &symbol,
            &import.module,
            import.alias.as_deref().unwrap_or(""),
            import.original_name.as_deref().unwrap_or(""),
        ],
        content_fingerprint: content,
        pipeline_fingerprint: pipeline,
    }));
}

fn push_decl_doc(
    ws: &Workspace,
    docs: &mut Vec<FactDoc>,
    decl: &Decl,
    language: Option<&str>,
    pipeline: u64,
) {
    let (span, content) = span_doc_fields(ws, decl.name_span);
    let file_path = ws
        .vfs()
        .path(decl.name_span.file)
        .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
    let kind = format!("{:?}", decl.kind).to_lowercase();
    let class = class_name_for_decl(ws, decl);
    let mut search_parts = vec![decl.name.as_str(), kind.as_str()];
    if let Some(q) = decl.qualified_name.as_deref() {
        search_parts.push(q);
    }
    for param in &decl.params {
        search_parts.push(param.as_str());
    }
    docs.push(new_doc(DocInput {
        kind: kind.as_str(),
        language,
        file_path: &file_path,
        span,
        symbol_name: Some(decl.name.as_str()),
        qualified_name: decl.qualified_name.as_deref(),
        enclosing_function: Some(decl.name.as_str()),
        enclosing_class: class.as_deref(),
        stable_ids: Vec::new(),
        precision: None,
        resolver_stage: None,
        provenance: None,
        confidence: None,
        static_limits: Vec::new(),
        incomplete_reasons: Vec::new(),
        search_parts: &search_parts,
        content_fingerprint: content,
        pipeline_fingerprint: pipeline,
    }));
}

fn push_file_doc(
    ws: &Workspace,
    docs: &mut Vec<FactDoc>,
    file: bonsai_common::FileId,
    file_path: &str,
    language: Option<&str>,
    pipeline: u64,
) {
    let (span, content) = match ws.vfs().snapshot(file) {
        Ok(snapshot) => (
            FactSpan {
                line: 1,
                column: 1,
                start: 0,
                end: snapshot.text.len() as u64,
            },
            fnv1a_bytes64(snapshot.text.as_bytes()),
        ),
        Err(_) => (
            FactSpan {
                line: 1,
                column: 1,
                ..FactSpan::default()
            },
            0,
        ),
    };
    let file_name = Path::new(file_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(file_path);
    let language_text = language.unwrap_or("");
    docs.push(new_doc(DocInput {
        kind: "file",
        language,
        file_path,
        span,
        symbol_name: Some(file_name),
        qualified_name: Some(file_path),
        enclosing_function: None,
        enclosing_class: None,
        stable_ids: Vec::new(),
        precision: None,
        resolver_stage: None,
        provenance: None,
        confidence: None,
        static_limits: Vec::new(),
        incomplete_reasons: Vec::new(),
        search_parts: &[file_path, file_name, language_text],
        content_fingerprint: content,
        pipeline_fingerprint: pipeline,
    }));
}

fn walk_flow_events(
    ws: &Workspace,
    docs: &mut Vec<FactDoc>,
    events: &[FlowEvent],
    in_fn: &str,
    language: Option<&str>,
    pipeline: u64,
) {
    let ctx = FlowDocContext {
        in_fn,
        language,
        pipeline,
    };
    for event in events {
        match event {
            FlowEvent::Call { name, args, span, .. } => {
                push_simple_doc(ws, docs, "call", name, *span, &ctx);
                for arg in args {
                    push_call_arg_doc(ws, docs, arg, &ctx);
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
                push_assignment_doc(
                    ws,
                    docs,
                    AssignmentDocInput {
                        target,
                        source_name: source_name.as_deref(),
                        source_call: source_call.as_deref(),
                        source_call_args,
                        source_names,
                        source_span: *span,
                    },
                    &ctx,
                );
                if let Some(call) = source_call {
                    push_simple_doc(ws, docs, "call", call, *span, &ctx);
                    for arg in source_call_args {
                        push_simple_doc(ws, docs, "arg", arg, *span, &ctx);
                    }
                }
                for source in source_names {
                    push_simple_doc(ws, docs, "ref-read", source, *span, &ctx);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk_flow_events(ws, docs, then_events, in_fn, language, pipeline);
                walk_flow_events(ws, docs, else_events, in_fn, language, pipeline);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_flow_events(ws, docs, body, in_fn, language, pipeline);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                walk_flow_events(ws, docs, body, in_fn, language, pipeline);
                walk_flow_events(ws, docs, catch_events, in_fn, language, pipeline);
                walk_flow_events(ws, docs, finally_events, in_fn, language, pipeline);
            }
            _ => {}
        }
    }
}

struct FlowDocContext<'a> {
    in_fn: &'a str,
    language: Option<&'a str>,
    pipeline: u64,
}

struct AssignmentDocInput<'a> {
    target: &'a str,
    source_name: Option<&'a str>,
    source_call: Option<&'a str>,
    source_call_args: &'a [String],
    source_names: &'a [String],
    source_span: Span,
}

fn push_assignment_doc(
    ws: &Workspace,
    docs: &mut Vec<FactDoc>,
    input: AssignmentDocInput<'_>,
    ctx: &FlowDocContext<'_>,
) {
    let (span, content) = span_doc_fields(ws, input.source_span);
    let file_path = ws
        .vfs()
        .path(input.source_span.file)
        .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
    let mut search_parts = vec![input.target, "var", ctx.in_fn];
    let display_source = input
        .source_name
        .or(input.source_call)
        .or_else(|| input.source_names.first().map(String::as_str));
    let display_text = display_source.map(|source| format!("{} = {source}", input.target));
    if let Some(display_text) = display_text.as_deref() {
        search_parts.push(display_text);
    }
    if let Some(source) = input.source_name {
        search_parts.push(source);
    }
    if let Some(call) = input.source_call {
        search_parts.push(call);
    }
    for arg in input.source_call_args {
        search_parts.push(arg.as_str());
    }
    for source in input.source_names {
        search_parts.push(source.as_str());
    }
    docs.push(new_doc(DocInput {
        kind: "var",
        language: ctx.language,
        file_path: &file_path,
        span,
        symbol_name: Some(input.target),
        qualified_name: None,
        enclosing_function: Some(ctx.in_fn),
        enclosing_class: None,
        stable_ids: Vec::new(),
        precision: None,
        resolver_stage: None,
        provenance: None,
        confidence: None,
        static_limits: Vec::new(),
        incomplete_reasons: Vec::new(),
        search_parts: &search_parts,
        content_fingerprint: content,
        pipeline_fingerprint: ctx.pipeline,
    }));
}

fn push_call_arg_doc(
    ws: &Workspace,
    docs: &mut Vec<FactDoc>,
    arg: &bonsai_lang_api::CallArg,
    ctx: &FlowDocContext<'_>,
) {
    let (span, content) = span_doc_fields(ws, arg.span);
    let file_path = ws
        .vfs()
        .path(arg.span.file)
        .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
    let mut search_parts = vec![arg.value_text.as_str(), "arg", ctx.in_fn];
    let display_text = arg
        .name
        .as_deref()
        .map(|name| format!("{name}={}", arg.value_text));
    if let Some(display_text) = display_text.as_deref() {
        search_parts.push(display_text);
    }
    if let Some(name) = arg.name.as_deref() {
        search_parts.push(name);
    }
    if let Some(place) = arg.place.as_deref() {
        search_parts.push(place);
    }
    for source in &arg.source_names {
        search_parts.push(source.as_str());
    }
    docs.push(new_doc(DocInput {
        kind: "arg",
        language: ctx.language,
        file_path: &file_path,
        span,
        symbol_name: Some(arg.value_text.as_str()),
        qualified_name: None,
        enclosing_function: Some(ctx.in_fn),
        enclosing_class: None,
        stable_ids: Vec::new(),
        precision: None,
        resolver_stage: None,
        provenance: arg.name.as_deref(),
        confidence: None,
        static_limits: Vec::new(),
        incomplete_reasons: Vec::new(),
        search_parts: &search_parts,
        content_fingerprint: content,
        pipeline_fingerprint: ctx.pipeline,
    }));
}

fn push_operation_doc(ws: &Workspace, docs: &mut Vec<FactDoc>, op: &Operation, ctx: &FlowDocContext<'_>) {
    let (span, content) = span_doc_fields(ws, op.span);
    let file_path = ws
        .vfs()
        .path(op.span.file)
        .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
    let kind = op.kind.as_str();
    let target = op
        .target
        .as_deref()
        .or_else(|| op.operands.first().map(|operand| operand.name.as_str()))
        .unwrap_or(kind);
    let mut search_parts = vec![
        target.to_string(),
        "operation".to_string(),
        kind.to_string(),
        ctx.in_fn.to_string(),
    ];
    if let Some(detail) = op.detail.as_deref().filter(|detail| !detail.is_empty()) {
        search_parts.push(detail.to_string());
    }
    for operand in &op.operands {
        search_parts.push(operand.name.clone());
        search_parts.push(operand.role.as_str().to_string());
        search_parts.push(format!("{}:{}", operand.role.as_str(), operand.name));
    }
    let search_refs: Vec<&str> = search_parts.iter().map(String::as_str).collect();
    docs.push(new_doc(DocInput {
        kind: "operation",
        language: ctx.language,
        file_path: &file_path,
        span,
        symbol_name: Some(target),
        qualified_name: None,
        enclosing_function: Some(ctx.in_fn),
        enclosing_class: None,
        stable_ids: Vec::new(),
        precision: None,
        resolver_stage: None,
        provenance: op.detail.as_deref(),
        confidence: None,
        static_limits: Vec::new(),
        incomplete_reasons: Vec::new(),
        search_parts: &search_refs,
        content_fingerprint: content,
        pipeline_fingerprint: ctx.pipeline,
    }));
}

fn push_simple_doc(
    ws: &Workspace,
    docs: &mut Vec<FactDoc>,
    kind: &str,
    symbol: &str,
    source_span: Span,
    ctx: &FlowDocContext<'_>,
) {
    let (span, content) = span_doc_fields(ws, source_span);
    let file_path = ws
        .vfs()
        .path(source_span.file)
        .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
    docs.push(new_doc(DocInput {
        kind,
        language: ctx.language,
        file_path: &file_path,
        span,
        symbol_name: Some(symbol),
        qualified_name: None,
        enclosing_function: Some(ctx.in_fn),
        enclosing_class: None,
        stable_ids: Vec::new(),
        precision: None,
        resolver_stage: None,
        provenance: None,
        confidence: None,
        static_limits: Vec::new(),
        incomplete_reasons: Vec::new(),
        search_parts: &[symbol, kind, ctx.in_fn],
        content_fingerprint: content,
        pipeline_fingerprint: ctx.pipeline,
    }));
}

fn push_edge_docs(ws: &Workspace, docs: &mut Vec<FactDoc>, pipeline: u64) {
    let global = ws.db().global_index();
    for edge in &ws.cached_resolved_call_graph().inner().edges {
        if !edge.precision.is_semantic() {
            continue;
        }
        let Some(caller) = global.decl_of(SymbolId::new(edge.from.raw())) else {
            continue;
        };
        let Some(callee) = global.decl_of(SymbolId::new(edge.to.raw())) else {
            continue;
        };
        let (span, content) = span_doc_fields(ws, edge.span);
        let file_path = ws
            .vfs()
            .path(edge.span.file)
            .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
        let edge_id = edge_id_for_parts(&caller.name, &callee.name, &file_path, span.line, span.column);
        let evidence = format!("{} -> {}", caller.name, callee.name);
        let language = ws
            .db()
            .adapter_for(edge.span.file)
            .map(|adapter| adapter.language_id().as_str().to_string());
        docs.push(new_doc(DocInput {
            kind: "edge",
            language: language.as_deref(),
            file_path: &file_path,
            span,
            symbol_name: Some(callee.name.as_str()),
            qualified_name: callee.qualified_name.as_deref(),
            enclosing_function: Some(caller.name.as_str()),
            enclosing_class: class_name_for_decl(ws, caller).as_deref(),
            stable_ids: vec![edge_id],
            precision: Some(precision_label(edge.precision)),
            resolver_stage: Some(edge.provenance.resolver_stage()),
            provenance: Some(edge.provenance.evidence()),
            confidence: Some(edge.provenance.confidence()),
            static_limits: Vec::new(),
            incomplete_reasons: Vec::new(),
            search_parts: &[
                caller.name.as_str(),
                callee.name.as_str(),
                evidence.as_str(),
                "edge",
            ],
            content_fingerprint: content,
            pipeline_fingerprint: pipeline,
        }));
    }
}

struct DocInput<'a> {
    kind: &'a str,
    language: Option<&'a str>,
    file_path: &'a str,
    span: FactSpan,
    symbol_name: Option<&'a str>,
    qualified_name: Option<&'a str>,
    enclosing_function: Option<&'a str>,
    enclosing_class: Option<&'a str>,
    stable_ids: Vec<String>,
    precision: Option<&'a str>,
    resolver_stage: Option<&'a str>,
    provenance: Option<&'a str>,
    confidence: Option<u8>,
    static_limits: Vec<String>,
    incomplete_reasons: Vec<String>,
    search_parts: &'a [&'a str],
    content_fingerprint: u64,
    pipeline_fingerprint: u64,
}

fn new_doc(input: DocInput<'_>) -> FactDoc {
    let symbol = input.symbol_name.unwrap_or("");
    let fact_id = fact_id_for_parts(
        input.kind,
        input.file_path,
        input.span.line,
        input.span.column,
        symbol,
    );
    FactDoc {
        fact_id,
        kind: input.kind.to_string(),
        language: input.language.map(str::to_string),
        file_path: input.file_path.to_string(),
        span: input.span,
        symbol_name: input.symbol_name.map(str::to_string),
        qualified_name: input.qualified_name.map(str::to_string),
        enclosing_function: input.enclosing_function.map(str::to_string),
        enclosing_class: input.enclosing_class.map(str::to_string),
        stable_ids: input.stable_ids,
        resolver_precision: input.precision.map(str::to_string),
        resolver_stage: input.resolver_stage.map(str::to_string),
        provenance: input.provenance.map(str::to_string),
        confidence: input.confidence,
        static_limits: input.static_limits,
        incomplete_reasons: input.incomplete_reasons,
        normalized_search_text: normalize_search_text(input.search_parts),
        content_fingerprint: input.content_fingerprint,
        pipeline_fingerprint: input.pipeline_fingerprint,
    }
}

fn span_doc_fields(ws: &Workspace, span: Span) -> (FactSpan, u64) {
    let snapshot = ws.vfs().snapshot(span.file).ok();
    let Some(snapshot) = snapshot else {
        return (
            FactSpan {
                start: span.start,
                end: span.end,
                ..FactSpan::default()
            },
            0,
        );
    };
    let map = cached_span_map_arc(span.file, snapshot.version, &snapshot.text);
    let lc = map.line_col(span.start);
    (
        FactSpan {
            line: lc.line,
            column: lc.column,
            start: span.start,
            end: span.end,
        },
        fnv1a_bytes64(snapshot.text.as_bytes()),
    )
}

fn class_name_for_decl(ws: &Workspace, decl: &Decl) -> Option<String> {
    if !matches!(decl.kind, DeclKind::Method | DeclKind::Constructor) {
        return None;
    }
    let parent = decl.parent?;
    let global = ws.db().global_index();
    let parent_decl = global.decl_of(parent)?;
    matches!(
        parent_decl.kind,
        DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface | DeclKind::Enum
    )
    .then(|| parent_decl.name.clone())
}

fn enclosing_function_for_span(ws: &Workspace, span: Span) -> Option<String> {
    let global = ws.db().global_index();
    global
        .decls_in(span.file)
        .iter()
        .filter(|decl| {
            matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) && decl.span.start <= span.start
                && span.end <= decl.span.end
        })
        .min_by_key(|decl| decl.span.end.saturating_sub(decl.span.start))
        .map(|decl| decl.name.clone())
}

fn precision_label(precision: Precision) -> &'static str {
    match precision {
        Precision::Exact => "exact",
        Precision::Narrowed => "narrowed",
        Precision::OverApproximate => "over-approximate",
        Precision::Unknown => "unknown",
    }
}

fn edge_id_for_parts(caller: &str, callee: &str, file: &str, line: u32, column: u32) -> String {
    let site = format!("{file}:{line}:{column}");
    let digest = fnv1a_str_slice64(&[caller, callee, &site]);
    format!("E:{:08x}", digest & 0xffff_ffff)
}

fn normalize_search_text(parts: &[&str]) -> String {
    let mut terms = BTreeSet::new();
    for part in parts {
        let raw = part.trim().to_lowercase();
        if !raw.is_empty() {
            terms.insert(raw);
        }
        for token in tokens(part) {
            terms.insert(token);
        }
    }
    terms.into_iter().collect::<Vec<_>>().join(" ")
}

fn tokens(value: &str) -> Vec<String> {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$' | '@' | ':' | '.')))
        .filter(|part| !part.is_empty())
        .map(|part| part.to_lowercase())
        .collect()
}

fn trigrams(value: &str) -> Vec<String> {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < 3 {
        return Vec::new();
    }
    chars
        .windows(3)
        .map(|win| win.iter().collect::<String>())
        .collect()
}

fn prefix_key(value: &str) -> String {
    value.to_lowercase().chars().take(3).collect()
}

fn token_key(value: &str) -> String {
    tokens(value)
        .into_iter()
        .next()
        .unwrap_or_else(|| value.to_lowercase())
}

fn relevance_key(doc: &FactDoc, query: &str) -> (u8, usize) {
    let query = query.to_lowercase();
    let name = doc
        .symbol_name
        .as_deref()
        .or(doc.qualified_name.as_deref())
        .unwrap_or("")
        .to_lowercase();
    let bucket = if name == query {
        0
    } else if name.starts_with(&query) {
        1
    } else if doc.normalized_search_text.contains(&query) {
        2
    } else {
        3
    };
    (bucket, name.len())
}

fn push_idx(map: &mut AHashMap<String, Vec<usize>>, key: String, idx: usize) {
    if key.is_empty() {
        return;
    }
    map.entry(key).or_default().push(idx);
}

fn dedup_map(map: &mut AHashMap<String, Vec<usize>>) {
    for values in map.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
}

fn edge_terms(doc: &FactDoc) -> Option<(String, String)> {
    Some((
        doc.enclosing_function.as_ref()?.to_lowercase(),
        doc.symbol_name.as_ref()?.to_lowercase(),
    ))
}

fn source_sink_keys(doc: &FactDoc) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(id) = doc.stable_ids.iter().find(|id| id.starts_with("S:")) {
        keys.push(format!("source:{id}"));
    }
    if doc.kind == "finding" {
        keys.push("finding".to_string());
    }
    keys
}

fn dedup_docs(mut docs: Vec<FactDoc>) -> Vec<FactDoc> {
    docs.sort_by(|a, b| a.fact_id.cmp(&b.fact_id));
    let mut deduped: Vec<FactDoc> = Vec::with_capacity(docs.len());
    for doc in docs {
        if let Some(existing) = deduped
            .last_mut()
            .filter(|existing| existing.fact_id == doc.fact_id)
        {
            merge_fact_doc(existing, doc);
        } else {
            deduped.push(doc);
        }
    }
    deduped
}

fn merge_fact_doc(existing: &mut FactDoc, doc: FactDoc) {
    fill_option(&mut existing.language, doc.language);
    fill_option(&mut existing.symbol_name, doc.symbol_name);
    fill_option(&mut existing.qualified_name, doc.qualified_name);
    fill_option(&mut existing.enclosing_function, doc.enclosing_function);
    fill_option(&mut existing.enclosing_class, doc.enclosing_class);
    fill_option(&mut existing.resolver_precision, doc.resolver_precision);
    fill_option(&mut existing.resolver_stage, doc.resolver_stage);
    fill_option(&mut existing.provenance, doc.provenance);
    existing.confidence = match (existing.confidence, doc.confidence) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (None, right) => right,
        (left, None) => left,
    };
    merge_string_vec(&mut existing.stable_ids, doc.stable_ids);
    merge_string_vec(&mut existing.static_limits, doc.static_limits);
    merge_string_vec(&mut existing.incomplete_reasons, doc.incomplete_reasons);
    existing.normalized_search_text = normalize_search_text(&[
        existing.normalized_search_text.as_str(),
        doc.normalized_search_text.as_str(),
    ]);
    if existing.content_fingerprint == 0 {
        existing.content_fingerprint = doc.content_fingerprint;
    }
    if existing.pipeline_fingerprint == 0 {
        existing.pipeline_fingerprint = doc.pipeline_fingerprint;
    }
}

fn fill_option<T>(target: &mut Option<T>, candidate: Option<T>) {
    if target.is_none() {
        *target = candidate;
    }
}

fn merge_string_vec(target: &mut Vec<String>, source: Vec<String>) {
    target.extend(source);
    target.sort();
    target.dedup();
}

fn source_fingerprints_content_fingerprint<I, P>(fingerprints: I) -> u64
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    let mut entries: Vec<(String, u64)> = fingerprints
        .into_iter()
        .map(|(path, hash)| (path.as_ref().display().to_string(), hash))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = StableHasher::new();
    for (path, content) in entries {
        h.absorb(path.as_bytes());
        h.absorb_separator();
        h.absorb(&content.to_le_bytes());
        h.absorb_separator();
    }
    h.finish()
}

fn dependency_metadata_fingerprint(root: &Path) -> u64 {
    let mut entries = Vec::new();
    let _ = bonsai_common::dependency_metadata::walk_dependency_metadata_files(root, |path, rel| {
        let Ok(bytes) = std::fs::read(path) else {
            return Ok(());
        };
        entries.push((rel.to_string(), fnv1a_bytes64(&bytes)));
        Ok(())
    });
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = StableHasher::new();
    for (path, digest) in entries {
        h.absorb(path.as_bytes());
        h.absorb_separator();
        h.absorb(&digest.to_le_bytes());
        h.absorb_separator();
    }
    h.finish()
}

fn build_fingerprint_hash() -> u64 {
    const FINGERPRINT_HEX: &str = env!(
        "BONSAI_BUILD_FINGERPRINT_HASH",
        "build.rs must emit BONSAI_BUILD_FINGERPRINT_HASH"
    );
    u64::from_str_radix(FINGERPRINT_HEX, 16).unwrap_or(0)
}

fn map_factstore_io(err: bonsai_factstore::FactStoreError) -> std::io::Error {
    match err {
        bonsai_factstore::FactStoreError::Io(err) => err,
        other => std::io::Error::new(std::io::ErrorKind::InvalidData, other.to_string()),
    }
}

fn invalid_data(err: impl std::error::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
}

fn file_path_matches_query(path: &str, filter: &str, workspace_root: Option<&Path>) -> bool {
    let Some(root) = workspace_root else {
        if filter_looks_like_absolute_path(filter) {
            return normalized_path_contains(path, filter);
        }
        return path_filter_matches(path, filter);
    };
    let relative = workspace_relative_filter_path(root, path);
    if path_filter_matches(&relative, filter) {
        return true;
    }
    filter_looks_like_absolute_path(filter) && normalized_path_contains(path, filter)
}

fn workspace_relative_filter_path(root: &Path, path: &str) -> String {
    let normalized_path = normalize_path_for_filter(path);
    let path_obj = Path::new(path);
    if let Ok(relative) = path_obj.strip_prefix(root) {
        return normalize_path_for_filter(&relative.to_string_lossy());
    }
    if let Some(canonical_path) = canonicalize_path_or_existing_parent(path_obj) {
        if let Ok(relative) = canonical_path.strip_prefix(root) {
            return normalize_path_for_filter(&relative.to_string_lossy());
        }
        if let Some(canonical_root) = canonicalize_path_or_existing_parent(root) {
            if let Ok(relative) = canonical_path.strip_prefix(canonical_root) {
                return normalize_path_for_filter(&relative.to_string_lossy());
            }
        }
    }
    let normalized_root = normalize_path_for_filter(&root.to_string_lossy());
    let normalized_root = normalized_root.trim_end_matches('/');
    if normalized_root.is_empty() {
        return normalized_path;
    }
    if normalized_path == normalized_root {
        return String::new();
    }
    let root_prefix = format!("{normalized_root}/");
    normalized_path
        .strip_prefix(&root_prefix)
        .map(ToOwned::to_owned)
        .unwrap_or(normalized_path)
}

fn normalized_path_contains(path: &str, filter: &str) -> bool {
    let filter = normalize_path_for_filter(filter);
    !filter.is_empty() && normalize_path_for_filter(path).contains(&filter)
}

fn path_filter_matches(path: &str, filter: &str) -> bool {
    let path = normalize_path_for_filter(path);
    let filter = normalize_path_for_filter(filter);
    if filter.is_empty() {
        return false;
    }
    if filter.contains('/') {
        return path_filter_with_separator_matches(&path, &filter);
    }
    path.contains(filter.as_str())
}

fn path_filter_with_separator_matches(path: &str, filter: &str) -> bool {
    let trimmed = filter.trim_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    let is_component_filter = filter.starts_with('/') || filter.ends_with('/');
    if is_component_filter {
        return path == trimmed
            || path.starts_with(&format!("{trimmed}/"))
            || path.contains(&format!("/{trimmed}/"));
    }
    path.contains(filter)
}

fn filter_looks_like_absolute_path(filter: &str) -> bool {
    let normalized = normalize_path_for_filter(filter);
    if normalized.len() >= 3 && normalized.as_bytes()[1] == b':' && normalized.as_bytes()[2] == b'/' {
        return true;
    }
    Path::new(filter).is_absolute() && normalized.trim_matches('/').contains('/')
}

fn normalize_path_for_filter(value: &str) -> String {
    value.replace('\\', "/").trim_start_matches("./").to_string()
}

fn canonicalize_path_or_existing_parent(path: &Path) -> Option<PathBuf> {
    if let Ok(canonical) = path.canonicalize() {
        return Some(canonical);
    }
    let parent = path.parent()?;
    let canonical_parent = parent.canonicalize().ok()?;
    Some(match path.file_name() {
        Some(file_name) => canonical_parent.join(file_name),
        None => canonical_parent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_doc(name: &str, kind: &str, line: u32) -> FactDoc {
        new_doc(DocInput {
            kind,
            language: Some("python"),
            file_path: "app.py",
            span: FactSpan {
                line,
                column: 1,
                start: u64::from(line),
                end: u64::from(line + 1),
            },
            symbol_name: Some(name),
            qualified_name: None,
            enclosing_function: Some("handler"),
            enclosing_class: None,
            stable_ids: Vec::new(),
            precision: Some("exact"),
            resolver_stage: Some("exact-symbol"),
            provenance: Some("unit"),
            confidence: Some(100),
            static_limits: Vec::new(),
            incomplete_reasons: Vec::new(),
            search_parts: &[name, kind, "handler"],
            content_fingerprint: 7,
            pipeline_fingerprint: 11,
        })
    }

    #[test]
    fn fact_doc_round_trips_through_snapshot() {
        let snapshot = FactSnapshot {
            schema_version: RETRIEVAL_SCHEMA_VERSION,
            pipeline_fingerprint: 11,
            docs: vec![sample_doc("handle_request", "function", 1)],
        };
        let encoded = wire::encode(&snapshot).expect("serialize");
        let decoded: FactSnapshot = wire::decode(&encoded).expect("deserialize");
        assert_eq!(decoded.docs[0].fact_id, snapshot.docs[0].fact_id);
        assert_eq!(
            decoded.docs[0].normalized_search_text,
            "function handle_request handler"
        );
    }

    #[test]
    fn deterministic_indexes_support_exact_prefix_and_trigram_lookup() {
        let index = FactIndex::from_docs(vec![
            sample_doc("handle_request", "function", 1),
            sample_doc("run_admin_command", "call", 2),
        ]);

        assert_eq!(
            index
                .get(&index.docs()[0].fact_id)
                .unwrap()
                .symbol_name
                .as_deref(),
            Some("handle_request")
        );
        assert_eq!(index.kind("call").len(), 1);
        assert_eq!(index.symbol("handle_request").len(), 1);
        assert_eq!(
            index
                .query(&RetrievalQuery {
                    text: "admin",
                    ..RetrievalQuery::default()
                })
                .expect("query")
                .len(),
            1
        );
    }

    #[test]
    fn retrieval_file_filter_matches_workspace_relative_path_when_root_is_known() {
        let root = Path::new("/tmp/tests/chosen-workspace");
        let mut app = sample_doc("app_marker", "function", 1);
        app.file_path = "/tmp/tests/chosen-workspace/app.py".to_string();
        let mut helper = sample_doc("test_marker", "function", 2);
        helper.file_path = "/tmp/tests/chosen-workspace/tests/helper.py".to_string();
        let index = FactIndex::from_docs(vec![app, helper]);

        let hits = index
            .query(&RetrievalQuery {
                text: "marker",
                kind: Some("function"),
                file: Some("tests/"),
                workspace_root: Some(root),
                regex: false,
                limit: 0,
            })
            .expect("query");
        let symbols: Vec<&str> = hits.iter().filter_map(|doc| doc.symbol_name.as_deref()).collect();

        assert_eq!(symbols, vec!["test_marker"]);
    }

    #[test]
    fn retrieval_directory_file_filter_matches_path_components() {
        let root = Path::new("/tmp/chosen-workspace");
        let mut latest = sample_doc("latest_marker", "function", 1);
        latest.file_path = "/tmp/chosen-workspace/latest/app.py".to_string();
        let mut unit_tests = sample_doc("unit_tests_marker", "function", 2);
        unit_tests.file_path = "/tmp/chosen-workspace/unit-tests/helper.py".to_string();
        let mut tests = sample_doc("tests_marker", "function", 3);
        tests.file_path = "/tmp/chosen-workspace/tests/helper.py".to_string();
        let index = FactIndex::from_docs(vec![latest, unit_tests, tests]);

        let hits = index
            .query(&RetrievalQuery {
                text: "marker",
                kind: Some("function"),
                file: Some("tests/"),
                workspace_root: Some(root),
                regex: false,
                limit: 0,
            })
            .expect("query");
        let symbols: Vec<&str> = hits.iter().filter_map(|doc| doc.symbol_name.as_deref()).collect();

        assert_eq!(symbols, vec!["tests_marker"]);
    }

    #[test]
    fn retrieval_file_filter_keeps_absolute_filter_without_workspace_root() {
        let mut app = sample_doc("app_marker", "function", 1);
        app.file_path = "/tmp/chosen-workspace/app.py".to_string();
        let index = FactIndex::from_docs(vec![app]);

        let hits = index
            .query(&RetrievalQuery {
                text: "marker",
                kind: Some("function"),
                file: Some("/tmp/chosen-workspace/app.py"),
                workspace_root: None,
                regex: false,
                limit: 0,
            })
            .expect("query");

        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn build_fact_docs_emits_first_class_file_documents() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            "def handle_request(request):\n    return request\n",
        )
        .expect("write source");
        let ws = Workspace::new(bonsai_adapters::all_languages_registry());
        ws.ingest_dir(dir.path()).expect("ingest");

        let docs = build_fact_docs(&ws);
        let file_docs: Vec<&FactDoc> = docs.iter().filter(|doc| doc.kind == "file").collect();
        assert_eq!(
            file_docs.len(),
            ws.vfs().all_files().len(),
            "retrieval must persist one first-class file doc per indexed source"
        );
        let file_doc = file_docs
            .iter()
            .find(|doc| doc.file_path.ends_with("app.py"))
            .expect("app.py file doc");
        assert_eq!(file_doc.symbol_name.as_deref(), Some("app.py"));
        assert_eq!(
            file_doc.qualified_name.as_deref(),
            Some(file_doc.file_path.as_str())
        );
        assert_eq!(file_doc.span.line, 1);
        assert_eq!(file_doc.span.column, 1);
        assert!(
            file_doc.normalized_search_text.contains("app.py"),
            "file path/name must be candidate text"
        );
        let file_path = file_doc.file_path.clone();

        let index = FactIndex::from_docs(docs);
        assert_eq!(index.kind("file").len(), 1);
        assert!(
            index.file(&file_path).iter().any(|doc| doc.kind == "file"),
            "file lookup should include the first-class file doc without hiding other docs in that file"
        );
        assert_eq!(
            index
                .query(&RetrievalQuery {
                    text: "app.py",
                    kind: Some("file"),
                    ..RetrievalQuery::default()
                })
                .expect("file query")
                .len(),
            1,
            "file docs must be queryable as retrieval candidates"
        );
    }

    #[test]
    fn decl_docs_index_parameters_as_candidate_text() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            "def handle_request(session_token):\n    return session_token\n",
        )
        .expect("write source");
        let ws = Workspace::new(bonsai_adapters::all_languages_registry());
        ws.ingest_dir(dir.path()).expect("ingest");

        let index = FactIndex::from_docs(build_fact_docs(&ws));
        let hits = index
            .query(&RetrievalQuery {
                text: "session_token",
                kind: Some("function"),
                ..RetrievalQuery::default()
            })
            .expect("parameter query");

        assert!(
            hits.iter()
                .any(|doc| doc.symbol_name.as_deref() == Some("handle_request")),
            "parameter text should narrow to the owning declaration candidate"
        );
    }

    #[test]
    fn operation_docs_are_candidate_metadata_not_rendered_fact_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            "def gen(payload):\n    yield payload[0]\n",
        )
        .expect("write source");
        let ws = Workspace::new(bonsai_adapters::all_languages_registry());
        ws.ingest_dir(dir.path()).expect("ingest");

        let index = FactIndex::from_docs(build_fact_docs(&ws));
        let hits = index
            .query(&RetrievalQuery {
                text: "payload[0]",
                kind: Some("operation"),
                ..RetrievalQuery::default()
            })
            .expect("operation query");

        assert!(
            hits.iter().any(|doc| {
                doc.kind == "operation"
                    && doc.symbol_name.as_deref() == Some("payload[0]")
                    && doc.normalized_search_text.contains("yield")
            }),
            "operation documents should index operation target/kind as candidate text: {hits:?}"
        );
        assert!(
            hits.iter().all(|doc| doc.stable_ids.is_empty()),
            "operation candidate docs must not claim stable graph/finding ids"
        );
    }

    #[test]
    fn file_scoped_docs_include_enclosing_function_candidate_text() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            "def audit_handler():\n    # security marker\n    return \"audit literal\"\n",
        )
        .expect("write source");
        let ws = Workspace::new(bonsai_adapters::all_languages_registry());
        ws.ingest_dir(dir.path()).expect("ingest");

        let index = FactIndex::from_docs(build_fact_docs(&ws));
        for kind in ["string", "comment"] {
            let hits = index
                .query(&RetrievalQuery {
                    text: "audit_handler",
                    kind: Some(kind),
                    ..RetrievalQuery::default()
                })
                .expect("function-context query");
            assert!(
                hits.iter()
                    .any(|doc| doc.enclosing_function.as_deref() == Some("audit_handler")),
                "{kind} docs should be narrowable by enclosing function: {hits:?}"
            );
        }
    }

    #[test]
    fn canonical_import_query_extracts_renamed_import_candidates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = "from os import system as run_command\n";
        std::fs::write(dir.path().join("app.py"), source).expect("write source");
        let ws = Workspace::new(bonsai_adapters::all_languages_registry());
        ws.ingest_dir(dir.path()).expect("ingest");
        let file = ws.vfs().all_files().into_iter().next().expect("fixture file");

        let imports = ws.db().imports_for(file);

        assert!(
            imports.iter().any(|spec| {
                spec.module == "os"
                    && spec.alias.as_deref() == Some("run_command")
                    && spec.original_name.as_deref() == Some("system")
            }),
            "canonical import facts must preserve module, alias, and original symbol metadata: {imports:?}"
        );
    }

    #[test]
    fn import_docs_index_alias_and_original_symbol_as_candidate_text() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = "from os import system as run_command\n";
        std::fs::write(dir.path().join("app.py"), source).expect("write source");
        let ws = Workspace::new(bonsai_adapters::all_languages_registry());
        ws.ingest_dir(dir.path()).expect("ingest");
        let file = ws.vfs().all_files().into_iter().next().expect("fixture file");
        let import = ImportSpec {
            span: Span::new(file, 0, source.len() as u64),
            module: "os".to_string(),
            alias: Some("run_command".to_string()),
            is_wildcard: false,
            original_name: Some("system".to_string()),
            scope: bonsai_lang_api::ImportScope::Module,
        };
        let mut docs = Vec::new();
        push_import_doc(&ws, &mut docs, &import, Some("python"), 11);
        let index = FactIndex::from_docs(docs);

        let alias_hits = index
            .query(&RetrievalQuery {
                text: "run_command",
                kind: Some("import"),
                ..RetrievalQuery::default()
            })
            .expect("alias query");
        assert_eq!(alias_hits.len(), 1);
        assert_eq!(alias_hits[0].symbol_name.as_deref(), Some("os"));
        assert_eq!(alias_hits[0].qualified_name.as_deref(), Some("os"));
        assert_eq!(alias_hits[0].provenance.as_deref(), Some("system"));

        let original_hits = index
            .query(&RetrievalQuery {
                text: "system",
                kind: Some("import"),
                ..RetrievalQuery::default()
            })
            .expect("original-symbol query");
        assert_eq!(
            original_hits.len(),
            1,
            "renamed import original symbol must be candidate text"
        );
        assert_eq!(
            original_hits[0].fact_id, alias_hits[0].fact_id,
            "alias/original candidate text must hydrate the same canonical import fact"
        );
    }

    #[test]
    fn fact_index_deduplicates_duplicate_fact_ids_and_merges_candidate_metadata() {
        let first = sample_doc("handle_request", "function", 1);
        let mut duplicate = first.clone();
        duplicate.stable_ids.push("F:merged".to_string());
        duplicate.normalized_search_text = normalize_search_text(&["only_in_duplicate"]);
        duplicate.confidence = Some(70);

        let index = FactIndex::from_docs(vec![first.clone(), duplicate]);

        assert_eq!(
            index.len(),
            1,
            "duplicate fact ids must not create ambiguous docs"
        );
        assert_eq!(
            index.get(&first.fact_id).expect("fact id lookup").fact_id,
            first.fact_id
        );
        assert_eq!(
            index.stable_id("F:merged").len(),
            1,
            "merged stable ids should still hydrate to the canonical fact"
        );
        assert_eq!(
            index
                .query(&RetrievalQuery {
                    text: "only_in_duplicate",
                    ..RetrievalQuery::default()
                })
                .expect("merged lexical query")
                .len(),
            1,
            "merged search metadata should remain queryable"
        );
    }

    #[test]
    fn query_exact_fact_and_stable_ids_are_not_filtered_as_lexical_text() {
        let mut doc = sample_doc("run_admin_command", "edge", 9);
        doc.stable_ids.push("E:deadbeef".to_string());
        let fact_id = doc.fact_id.clone();
        let index = FactIndex::from_docs(vec![doc]);

        let by_fact_id = index.query(&RetrievalQuery {
            text: &fact_id,
            ..RetrievalQuery::default()
        });
        assert_eq!(
            by_fact_id.expect("fact-id query").len(),
            1,
            "exact fact-id lookup must not require the id text to appear in normalized lexical text"
        );

        let by_stable_id = index.query(&RetrievalQuery {
            text: "E:deadbeef",
            kind: Some("edge"),
            ..RetrievalQuery::default()
        });
        assert_eq!(
            by_stable_id.expect("stable-id query").len(),
            1,
            "exact stable-id lookup must survive canonical kind/file filtering"
        );

        let filtered_out = index.query(&RetrievalQuery {
            text: "E:deadbeef",
            kind: Some("call"),
            ..RetrievalQuery::default()
        });
        assert!(
            filtered_out.expect("kind-filtered stable-id query").is_empty(),
            "exact stable-id lookup should still honor explicit kind filters"
        );
    }

    #[test]
    fn call_arg_keyword_metadata_is_candidate_text_not_fact_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            "def handler(endpoint):\n    connect(host=endpoint)\n",
        )
        .expect("write source");
        let ws = Workspace::new(bonsai_adapters::all_languages_registry());
        ws.ingest_dir(dir.path()).expect("ingest");
        let file = ws.vfs().all_files().into_iter().next().expect("fixture file");
        let arg = bonsai_lang_api::CallArg {
            passing_mode: Default::default(),
            span: Span {
                file,
                start: 33,
                end: 46,
            },
            name: Some("host".to_string()),
            value_text: "endpoint".to_string(),
            place: Some("endpoint".to_string()),
            source_names: vec!["endpoint".to_string()],
        };
        let mut docs = Vec::new();
        let ctx = FlowDocContext {
            in_fn: "handler",
            language: Some("python"),
            pipeline: 11,
        };
        push_call_arg_doc(&ws, &mut docs, &arg, &ctx);
        let index = FactIndex::from_docs(docs);

        let keyword_hits = index
            .query(&RetrievalQuery {
                text: "host",
                kind: Some("arg"),
                ..RetrievalQuery::default()
            })
            .expect("keyword query");
        assert_eq!(keyword_hits.len(), 1);
        assert_eq!(keyword_hits[0].symbol_name.as_deref(), Some("endpoint"));
        assert_eq!(keyword_hits[0].provenance.as_deref(), Some("host"));
        assert_eq!(
            keyword_hits[0].fact_id,
            fact_id_for_parts(
                "arg",
                &keyword_hits[0].file_path,
                keyword_hits[0].span.line,
                keyword_hits[0].span.column,
                "endpoint"
            ),
            "keyword metadata must not replace the canonical arg-value fact identity"
        );

        let display_hits = index
            .query(&RetrievalQuery {
                text: "host=endpoint",
                kind: Some("arg"),
                ..RetrievalQuery::default()
            })
            .expect("display-text query");
        assert_eq!(
            display_hits.len(),
            1,
            "inspect display text for named args must be indexed as candidate text"
        );
        assert_eq!(
            display_hits[0].fact_id, keyword_hits[0].fact_id,
            "display-text candidate indexing must hydrate the same canonical arg fact"
        );
    }

    #[test]
    fn persisted_file_candidates_preserve_kind_and_compound_argument_lookup() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            "def handler(endpoint):\n    connect(host=endpoint)\n",
        )
        .expect("write source");
        let ws = Workspace::new(bonsai_adapters::all_languages_registry());
        ws.ingest_dir(dir.path()).expect("ingest");

        let docs = save_sidecar(&ws, dir.path()).expect("save candidate sidecar");
        let index = load_sidecar(&ws, dir.path()).expect("load candidate sidecar");
        assert_eq!(docs, index.len());
        assert!(
            docs < 32,
            "persisted retrieval should be bounded by file/kind groups, not AST event count: {docs}"
        );
        let hits = index
            .query(&RetrievalQuery {
                text: "host=endpoint",
                kind: Some("arg"),
                workspace_root: Some(dir.path()),
                ..RetrievalQuery::default()
            })
            .expect("query candidate sidecar");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].file_path.ends_with("app.py"));

        let pipeline = pipeline_hash_for_workspace(&ws);
        let direct_paths = query_sidecar_file_paths_with_pipeline(
            dir.path(),
            pipeline,
            &RetrievalQuery {
                text: "host=endpoint",
                kind: Some("arg"),
                workspace_root: Some(dir.path()),
                ..RetrievalQuery::default()
            },
        )
        .expect("query compact candidate sidecar directly");
        assert_eq!(direct_paths, vec![hits[0].file_path.clone()]);

        let filtered_out = query_sidecar_file_paths_with_pipeline(
            dir.path(),
            pipeline,
            &RetrievalQuery {
                text: "host=endpoint",
                kind: Some("class"),
                workspace_root: Some(dir.path()),
                ..RetrievalQuery::default()
            },
        )
        .expect("query compact candidate sidecar with kind filter");
        assert!(filtered_out.is_empty());

        let regex_error = query_sidecar_file_paths_with_pipeline(
            dir.path(),
            pipeline,
            &RetrievalQuery {
                text: "host.*endpoint",
                regex: true,
                ..RetrievalQuery::default()
            },
        )
        .expect_err("compact candidate query must reject regex lookup");
        assert_eq!(regex_error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn persisted_compiler_is_deterministic_and_keeps_semantic_edges() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("z.py"),
            "def caller(value):\n    return callee(value)\n\ndef callee(value):\n    return value\n",
        )
        .expect("write calling source");
        std::fs::write(dir.path().join("a.py"), "def alpha(value):\n    return value\n")
            .expect("write alphabetic source");
        let ws = Workspace::new(bonsai_adapters::all_languages_registry());
        ws.ingest_dir(dir.path()).expect("ingest");

        let first_docs = save_sidecar(&ws, dir.path()).expect("first candidate sidecar");
        let path = retrieval_sidecar_path(dir.path());
        let first_bytes = std::fs::read(&path).expect("read first sidecar");
        let second_docs = save_sidecar(&ws, dir.path()).expect("second candidate sidecar");
        let second_bytes = std::fs::read(&path).expect("read second sidecar");
        assert_eq!(first_docs, second_docs);
        assert_eq!(
            first_bytes, second_bytes,
            "parallel file lowering must preserve deterministic path/kind ordering"
        );

        let index = load_sidecar(&ws, dir.path()).expect("load candidate sidecar");
        let edge_docs: Vec<_> = index.docs().iter().filter(|doc| doc.kind == "edge").collect();
        assert_eq!(
            edge_docs.len(),
            1,
            "resolved edge groups must be retained in the compact snapshot: {edge_docs:#?}"
        );
        let edges = index
            .query(&RetrievalQuery {
                text: "caller",
                kind: Some("edge"),
                workspace_root: Some(dir.path()),
                ..RetrievalQuery::default()
            })
            .expect("query semantic edge candidates");
        assert_eq!(
            edges.len(),
            1,
            "edge groups must merge into their source file batch"
        );
    }

    #[test]
    fn assignment_display_text_is_candidate_text_not_fact_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            "def handler(token):\n    result = verify_token(token)\n",
        )
        .expect("write source");
        let ws = Workspace::new(bonsai_adapters::all_languages_registry());
        ws.ingest_dir(dir.path()).expect("ingest");
        let file = ws.vfs().all_files().into_iter().next().expect("fixture file");
        let source_call_args = vec!["token".to_string()];
        let source_names = Vec::new();
        let mut docs = Vec::new();
        let ctx = FlowDocContext {
            in_fn: "handler",
            language: Some("python"),
            pipeline: 11,
        };
        push_assignment_doc(
            &ws,
            &mut docs,
            AssignmentDocInput {
                target: "result",
                source_name: None,
                source_call: Some("verify_token"),
                source_call_args: &source_call_args,
                source_names: &source_names,
                source_span: Span {
                    file,
                    start: 24,
                    end: 52,
                },
            },
            &ctx,
        );
        let index = FactIndex::from_docs(docs);

        let display_hits = index
            .query(&RetrievalQuery {
                text: "result = verify_token",
                kind: Some("var"),
                ..RetrievalQuery::default()
            })
            .expect("display-text query");
        assert_eq!(
            display_hits.len(),
            1,
            "inspect display text for assignment summaries must be indexed as candidate text"
        );
        assert_eq!(display_hits[0].symbol_name.as_deref(), Some("result"));
        assert_eq!(
            display_hits[0].fact_id,
            fact_id_for_parts(
                "var",
                &display_hits[0].file_path,
                display_hits[0].span.line,
                display_hits[0].span.column,
                "result"
            ),
            "assignment display text must not replace the canonical target fact identity"
        );
    }

    #[test]
    fn vector_candidates_are_not_hydrated_as_fact_evidence() {
        let doc = sample_doc("handle_request", "function", 1);
        let index = FactIndex::from_docs(vec![doc.clone()]);
        let vector = VectorCandidateIds::new([doc.fact_id]);

        assert!(index.hydrate_candidates(&vector.candidates("handle")).is_empty());
    }

    #[test]
    fn stale_pipeline_snapshot_is_rejected() {
        let snapshot = FactSnapshot {
            schema_version: RETRIEVAL_SCHEMA_VERSION,
            pipeline_fingerprint: 1,
            docs: vec![sample_doc("handle_request", "function", 1)],
        };
        assert!(validate_snapshot(&snapshot, 2).is_err());
    }

    #[test]
    fn sidecar_rejects_pipeline_change() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("retrieval.factstore");
        let snapshot = FactSnapshot {
            schema_version: RETRIEVAL_SCHEMA_VERSION,
            pipeline_fingerprint: 101,
            docs: vec![sample_doc("handle_request", "function", 1)],
        };
        save_snapshot(&snapshot, &path).expect("save");
        let stale = FactStoreReader::open(&path, RETRIEVAL_TABLE_ID, 202);
        assert!(stale.is_err());
        assert!(
            validate_sidecar_file_with_pipeline(&path, 202).is_err(),
            "strict retrieval validation must reject a sidecar from a different pipeline"
        );
        assert_eq!(
            validate_sidecar_file_with_pipeline(&path, 101).expect("matching pipeline"),
            1
        );
    }

    #[test]
    fn sidecar_rejects_previous_schema_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("retrieval.factstore");
        let snapshot = FactSnapshot {
            schema_version: RETRIEVAL_SCHEMA_VERSION - 1,
            pipeline_fingerprint: 101,
            docs: vec![sample_doc("handle_request", "function", 1)],
        };
        save_snapshot(&snapshot, &path).expect("save old schema snapshot");

        assert!(
            validate_sidecar_file_with_pipeline(&path, 101).is_err(),
            "retrieval validation must reject sidecars whose persisted doc semantics predate the current schema"
        );
        assert!(
            validate_sidecar_file(&path).is_err(),
            "relaxed retrieval validation still decodes the snapshot and must reject old schemas"
        );
    }

    #[test]
    fn compact_sidecar_validation_rejects_invalid_string_references() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("retrieval.factstore");
        let mut compact = CompactFactSnapshot::from_docs(
            RETRIEVAL_SCHEMA_VERSION,
            101,
            vec![sample_doc("handle_request", "function", 1)],
        );
        compact.docs[0].fact_id = u32::MAX;
        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 1).expect("zstd encoder");
        wire::encode_to_writer(&mut encoder, &compact).expect("encode compact snapshot");
        let bytes = encoder.finish().expect("finish compact snapshot");
        let writer = FactStoreWriter::create(&path, RETRIEVAL_TABLE_ID, 101).expect("create factstore");
        writer
            .add(SNAPSHOT_KEY, fnv1a_bytes64(&bytes), &bytes)
            .expect("write compact snapshot");
        writer.finish().expect("finish factstore");

        assert!(
            validate_sidecar_file_with_pipeline(&path, 101).is_err(),
            "compact validation must prove every interned string reference before reuse"
        );
    }

    #[test]
    fn sidecar_file_validator_rejects_corrupt_payload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("retrieval.factstore");
        let snapshot = FactSnapshot {
            schema_version: RETRIEVAL_SCHEMA_VERSION,
            pipeline_fingerprint: 101,
            docs: vec![sample_doc("handle_request", "function", 1)],
        };
        save_snapshot(&snapshot, &path).expect("save");
        assert_eq!(validate_sidecar_file(&path).expect("valid sidecar"), 1);

        let len = std::fs::metadata(&path).expect("metadata").len();
        std::fs::write(&path, vec![0_u8; len as usize]).expect("corrupt same-size sidecar");
        assert!(
            validate_sidecar_file(&path).is_err(),
            "same-size corrupt retrieval factstore must not validate"
        );
    }

    #[test]
    fn sidecar_file_validator_rejects_body_hash_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("retrieval.factstore");
        let snapshot = FactSnapshot {
            schema_version: RETRIEVAL_SCHEMA_VERSION,
            pipeline_fingerprint: 101,
            docs: vec![sample_doc("handle_request", "function", 1)],
        };
        let bytes = wire::encode(&snapshot).expect("serialize");
        let writer = FactStoreWriter::create(&path, RETRIEVAL_TABLE_ID, snapshot.pipeline_fingerprint)
            .expect("create factstore");
        writer
            .add(SNAPSHOT_KEY, 0, &bytes)
            .expect("write mismatched hash entry");
        writer.finish().expect("finish factstore");

        assert!(
            validate_sidecar_file(&path).is_err(),
            "retrieval validator must reject payloads whose stored body hash does not match the bytes"
        );
        assert!(
            validate_sidecar_file_with_pipeline(&path, 101).is_err(),
            "strict retrieval validation must also reject body-hash mismatches"
        );
    }

    #[test]
    fn disk_source_fingerprints_match_workspace_pipeline_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            "def handle_request(request):\n    return request\n",
        )
        .expect("write source");
        let ws = Workspace::new(bonsai_adapters::all_languages_registry());
        ws.ingest_dir(dir.path()).expect("ingest");

        let fingerprints = ws.source_file_fingerprints(dir.path()).expect("fingerprints");
        let disk_pipeline = pipeline_hash_for_source_fingerprints(
            ws.db().workspace_root().as_deref(),
            fingerprints.iter().map(|file| (file.path.as_path(), file.hash)),
        );

        assert_eq!(disk_pipeline, pipeline_hash_for_workspace(&ws));
    }
}
