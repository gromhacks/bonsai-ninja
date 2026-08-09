//! Cross-function call graph + cached summaries (spec §15, §16).
//!
//! The call graph is a directed multi-graph from `FuncId` to `FuncId`. Each
//! edge carries its precision so downstream queries can decide how much to
//! trust it. Summaries are compositional cached facts derived from a
//! function's CFG plus the summaries of every target it calls.

pub mod chains;

pub use chains::{
    downstream_funcs_set, enumerate_chains_resolved, enumerate_paths_resolved, is_precise_chain,
    ChainTruncation, PathTruncation, ResolvedChain, ResolvedPath,
};

use ahash::{AHashMap, AHashSet};
use bonsai_common::{qualified_names_match, short_qualified_tail, FileId, FuncId, Precision, Span, SymbolId};
use bonsai_index::GlobalIndex;
use bonsai_lang_api::{
    collect_return_spans, AliasTarget, AssignValueKind, CallArg, CallKind, CallableDeclarationFamily, Decl,
    DeclKind, FlowEvent, LanguageCapabilities, ModulePath,
};
use bonsai_resolve::{
    build_shared_peer_class_index, callee_without_call_args, class_symbols_share_semantic_identity,
    collect_method_candidates_for_class_cached, enclosing_class_for_decl, export_name_variants,
    extend_alias_targets_with_declared_types, is_super_receiver_with_tokens, module_path_parts,
    module_target_exactly_matches_decl_module_path_with_syntax,
    module_target_matches_decl_module_path_with_syntax, module_target_matches_path, module_target_parts,
    module_target_parts_match_path_parts, namespace_alias_target_tail,
    prune_receiver_type_names_for_dispatch, push_unique_func, push_unique_string,
    qualified_module_alias_call, resolve_callable_with_context, resolve_class, split_qualified_head_tail,
    strip_module_path_prefix, visibility_allows, MethodCandidateCache, PeerClassIndex, ResolveContext,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// What kind of dispatch produced a call edge. The resolver
/// classifies every edge during graph construction so downstream
/// passes can choose how much to trust each one.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Name uniquely resolved to one callee (single matching
    /// decl in the global index). Carries [`Precision::Narrowed`].
    Direct,
    /// Name resolved to multiple semantically explained candidate
    /// callees, such as typed virtual dispatch or C preprocessor
    /// declaration families. Ambiguous broad sets are not emitted.
    Virtual,
    /// Indirect dispatch through a function pointer / dynamic
    /// `getattr` / reflection. Adapter-emitted; analyses treat
    /// these as "may call any function with matching signature."
    Indirect,
    /// The call escapes to something outside the workspace
    /// (FFI, runtime-only symbol). Recorded so caller-count
    /// summaries reflect "this many calls were unresolved" but
    /// without a concrete target.
    Unknown,
}

/// One resolved edge in the call graph: a single
/// `FuncId → FuncId` link with the kind, precision, and provenance the
/// resolver assigned at build time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallEdge {
    pub from: FuncId,
    pub to: FuncId,
    pub span: Span,
    pub kind: EdgeKind,
    pub precision: Precision,
    #[serde(default)]
    pub provenance: EdgeProvenance,
}

/// Why the resolver accepted a call edge.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EdgeProvenanceKind {
    Unknown,
    DirectSymbol,
    ReceiverDispatch,
    DeclarationFamily,
    CallableBindingCall,
    CallableBindingAssignment,
    CallableArgument,
    Custom,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CustomEdgeProvenance {
    resolver_stage: Box<str>,
    evidence: Box<str>,
    confidence: u8,
}

/// Compact compiler provenance for one resolved edge.
///
/// Production resolver stages are a closed numeric vocabulary. Rendering
/// expands them to stable strings at the API boundary, so millions of edges do
/// not each allocate identical stage/evidence strings. `Custom` remains
/// available for diagnostic projections that intentionally carry novel text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeProvenance {
    kind: EdgeProvenanceKind,
    custom: Option<Box<CustomEdgeProvenance>>,
}

#[derive(Serialize)]
struct RenderedEdgeProvenance<'a> {
    resolver_stage: &'a str,
    evidence: &'a str,
    confidence: u8,
}

#[derive(Deserialize)]
struct RenderedEdgeProvenanceOwned {
    resolver_stage: String,
    evidence: String,
    confidence: u8,
}

#[derive(Serialize)]
struct CompactEdgeProvenance<'a> {
    kind: EdgeProvenanceKind,
    custom: &'a Option<Box<CustomEdgeProvenance>>,
}

#[derive(Deserialize)]
struct CompactEdgeProvenanceOwned {
    kind: EdgeProvenanceKind,
    custom: Option<Box<CustomEdgeProvenance>>,
}

impl Serialize for EdgeProvenance {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            return RenderedEdgeProvenance {
                resolver_stage: self.resolver_stage(),
                evidence: self.evidence(),
                confidence: self.confidence(),
            }
            .serialize(serializer);
        }
        CompactEdgeProvenance {
            kind: self.kind,
            custom: &self.custom,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EdgeProvenance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let rendered = RenderedEdgeProvenanceOwned::deserialize(deserializer)?;
            return Ok(Self::from_rendered(
                rendered.resolver_stage,
                rendered.evidence,
                rendered.confidence,
            ));
        }
        let compact = CompactEdgeProvenanceOwned::deserialize(deserializer)?;
        Ok(Self {
            kind: compact.kind,
            custom: compact.custom,
        })
    }
}

impl Default for EdgeProvenance {
    fn default() -> Self {
        Self::known(EdgeProvenanceKind::Unknown)
    }
}

impl EdgeProvenance {
    fn from_rendered(stage: String, evidence: String, confidence: u8) -> Self {
        let known = match (stage.as_str(), evidence.as_str(), confidence) {
            ("unknown", "legacy edge without resolver provenance", 0) => Some(EdgeProvenanceKind::Unknown),
            ("exact_symbol", "unique callable resolved in caller visibility/module/import context", 90) => {
                Some(EdgeProvenanceKind::DirectSymbol)
            }
            (
                "receiver_type",
                "receiver type, assigned receiver, or class ancestry evidence narrowed dispatch",
                82,
            ) => Some(EdgeProvenanceKind::ReceiverDispatch),
            ("decl_family", "multiple candidates share a semantic declaration family", 72) => {
                Some(EdgeProvenanceKind::DeclarationFamily)
            }
            (
                "callable_value",
                "local or receiver-projected callable binding matched call expression",
                86,
            ) => Some(EdgeProvenanceKind::CallableBindingCall),
            (
                "callable_value",
                "local or receiver-projected callable binding matched assignment call",
                86,
            ) => Some(EdgeProvenanceKind::CallableBindingAssignment),
            ("callable_value", "call argument resolved as callable reference", 86) => {
                Some(EdgeProvenanceKind::CallableArgument)
            }
            _ => None,
        };
        known.map_or_else(|| Self::new(stage, evidence, confidence), Self::known)
    }

    #[must_use]
    pub fn new(stage: impl Into<String>, evidence: impl Into<String>, confidence: u8) -> Self {
        Self {
            kind: EdgeProvenanceKind::Custom,
            custom: Some(Box::new(CustomEdgeProvenance {
                resolver_stage: stage.into().into_boxed_str(),
                evidence: evidence.into().into_boxed_str(),
                confidence: confidence.min(100),
            })),
        }
    }

    #[must_use]
    pub fn resolver_stage(&self) -> &str {
        match self.kind {
            EdgeProvenanceKind::Unknown => "unknown",
            EdgeProvenanceKind::DirectSymbol => "exact_symbol",
            EdgeProvenanceKind::ReceiverDispatch => "receiver_type",
            EdgeProvenanceKind::DeclarationFamily => "decl_family",
            EdgeProvenanceKind::CallableBindingCall
            | EdgeProvenanceKind::CallableBindingAssignment
            | EdgeProvenanceKind::CallableArgument => "callable_value",
            EdgeProvenanceKind::Custom => self
                .custom
                .as_deref()
                .map_or("custom", |custom| &custom.resolver_stage),
        }
    }

    #[must_use]
    pub fn evidence(&self) -> &str {
        match self.kind {
            EdgeProvenanceKind::Unknown => "legacy edge without resolver provenance",
            EdgeProvenanceKind::DirectSymbol => {
                "unique callable resolved in caller visibility/module/import context"
            }
            EdgeProvenanceKind::ReceiverDispatch => {
                "receiver type, assigned receiver, or class ancestry evidence narrowed dispatch"
            }
            EdgeProvenanceKind::DeclarationFamily => {
                "multiple candidates share a semantic declaration family"
            }
            EdgeProvenanceKind::CallableBindingCall => {
                "local or receiver-projected callable binding matched call expression"
            }
            EdgeProvenanceKind::CallableBindingAssignment => {
                "local or receiver-projected callable binding matched assignment call"
            }
            EdgeProvenanceKind::CallableArgument => "call argument resolved as callable reference",
            EdgeProvenanceKind::Custom => self
                .custom
                .as_deref()
                .map_or("custom resolver evidence", |custom| &custom.evidence),
        }
    }

    #[must_use]
    pub fn confidence(&self) -> u8 {
        match self.kind {
            EdgeProvenanceKind::Unknown => 0,
            EdgeProvenanceKind::DirectSymbol => 90,
            EdgeProvenanceKind::ReceiverDispatch => 82,
            EdgeProvenanceKind::DeclarationFamily => 72,
            EdgeProvenanceKind::CallableBindingCall
            | EdgeProvenanceKind::CallableBindingAssignment
            | EdgeProvenanceKind::CallableArgument => 86,
            EdgeProvenanceKind::Custom => self.custom.as_deref().map_or(0, |custom| custom.confidence),
        }
    }

    const fn known(kind: EdgeProvenanceKind) -> Self {
        Self { kind, custom: None }
    }

    #[must_use]
    pub fn direct_symbol() -> Self {
        Self::known(EdgeProvenanceKind::DirectSymbol)
    }

    #[must_use]
    pub fn receiver_dispatch() -> Self {
        Self::known(EdgeProvenanceKind::ReceiverDispatch)
    }

    #[must_use]
    pub fn callable_value(evidence: impl AsRef<str>) -> Self {
        let evidence = evidence.as_ref();
        let kind = match evidence {
            "local or receiver-projected callable binding matched call expression" => {
                EdgeProvenanceKind::CallableBindingCall
            }
            "local or receiver-projected callable binding matched assignment call" => {
                EdgeProvenanceKind::CallableBindingAssignment
            }
            "call argument resolved as callable reference" => EdgeProvenanceKind::CallableArgument,
            _ => return Self::new("callable_value", evidence, 86),
        };
        Self::known(kind)
    }

    #[must_use]
    pub fn decl_family() -> Self {
        Self::known(EdgeProvenanceKind::DeclarationFamily)
    }
}

/// Generic callgraph container — a multi-graph of `FuncId → FuncId`
/// edges with O(1) `callers_of` / `callees_of` lookups via per-node
/// adjacency vectors. Distinct call-site starts remain distinct edges,
/// but duplicate facts for the same source call token are ignored at
/// insertion time so overlapping adapter events cannot inflate
/// downstream walks.
///
/// Most callers want [`ResolvedCallGraph`], which wraps this with the
/// resolver-driven build pipeline. `CallGraph` itself is exposed for
/// callers that want to build edges from a different source (HIR
/// walker, trace replay, fixture data).
#[derive(Clone, Debug, Default, Serialize)]
pub struct CallGraph {
    pub edges: Vec<CallEdge>,
    /// `caller → indices into `edges`` where the caller is `from`.
    #[serde(skip)]
    outgoing: AHashMap<FuncId, Vec<u32>>,
    /// `callee → indices into `edges`` where the callee is `to`.
    #[serde(skip)]
    incoming: AHashMap<FuncId, Vec<u32>>,
}

#[derive(Deserialize)]
struct CallGraphWire {
    edges: Vec<CallEdge>,
}

impl<'de> Deserialize<'de> for CallGraph {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CallGraphWire::deserialize(deserializer)?;
        Ok(Self::from_unique_edges(wire.edges))
    }
}

impl CallGraph {
    /// Empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an edge and update both adjacency indexes. Duplicate
    /// facts for the same source token are ignored; separate call
    /// sites or separate semantic edge shapes are still kept.
    pub fn add_edge(&mut self, edge: CallEdge) {
        if self.outgoing.get(&edge.from).is_some_and(|ids| {
            ids.iter().any(|&idx| {
                let existing = &self.edges[idx as usize];
                existing.to == edge.to
                    && existing.span.file == edge.span.file
                    && existing.span.start == edge.span.start
                    && existing.kind == edge.kind
                    && existing.precision == edge.precision
            })
        }) {
            return;
        }
        let idx = u32::try_from(self.edges.len()).expect("callgraph overflow: > 2^32 edges");
        self.outgoing.entry(edge.from).or_default().push(idx);
        self.incoming.entry(edge.to).or_default().push(idx);
        self.edges.push(edge);
    }

    /// Build adjacency indexes over an already de-duplicated edge vector.
    ///
    /// The resolved-callgraph compiler first builds one `CallGraph` per
    /// source file, so [`Self::add_edge`] has already removed overlapping
    /// adapter facts for every possible duplicate key: that key includes the
    /// source `FileId`, and therefore cannot collide across file partitions.
    /// Reusing the flattened edge vector avoids both a second edge allocation
    /// and a second, potentially quadratic, per-caller duplicate scan.
    pub fn from_unique_edges(edges: Vec<CallEdge>) -> Self {
        assert!(
            u32::try_from(edges.len()).is_ok(),
            "callgraph overflow: > 2^32 edges"
        );
        let mut outgoing: AHashMap<FuncId, Vec<u32>> = AHashMap::new();
        let mut incoming: AHashMap<FuncId, Vec<u32>> = AHashMap::new();
        for (idx, edge) in edges.iter().enumerate() {
            let idx = idx as u32;
            outgoing.entry(edge.from).or_default().push(idx);
            incoming.entry(edge.to).or_default().push(idx);
        }
        Self {
            edges,
            outgoing,
            incoming,
        }
    }

    /// Edges where `func` is the caller.
    pub fn callees(&self, func: FuncId) -> impl Iterator<Item = &CallEdge> {
        self.outgoing
            .get(&func)
            .into_iter()
            .flat_map(move |ids| ids.iter().map(move |i| &self.edges[*i as usize]))
    }

    /// Edges where `func` is the callee.
    pub fn callers(&self, func: FuncId) -> impl Iterator<Item = &CallEdge> {
        self.incoming
            .get(&func)
            .into_iter()
            .flat_map(move |ids| ids.iter().map(move |i| &self.edges[*i as usize]))
    }

    /// Depth-first reachability from `start`. Cycles are broken by a
    /// visited set; order is DFS pre-order and deterministic.
    pub fn reachable(&self, start: FuncId) -> Vec<FuncId> {
        let mut visited: AHashSet<FuncId> = AHashSet::new();
        let mut stack = vec![start];
        let mut order = Vec::new();
        while let Some(func) = stack.pop() {
            if !visited.insert(func) {
                continue;
            }
            order.push(func);
            if let Some(ids) = self.outgoing.get(&func) {
                // Reverse so the first listed callee is popped first
                // (stable pre-order regardless of edge insertion order).
                for &idx in ids.iter().rev() {
                    stack.push(self.edges[idx as usize].to);
                }
            }
        }
        order
    }
}

/// Build-target membership inferred from checked-in Makefiles.
///
/// This is deliberately narrow: it only records object-list groups
/// that map back to adapter-declared native-linkage source files. Resolution uses it to
/// avoid crossing link targets when two global functions have the
/// same name but belong to different executables/libraries.
#[derive(Clone, Debug, Default)]
pub struct BuildTargetIndex {
    groups_by_file: AHashMap<FileId, Vec<u32>>,
}

impl BuildTargetIndex {
    #[must_use]
    pub fn from_file_paths<I>(paths: I) -> Self
    where
        I: IntoIterator<Item = (FileId, String)>,
    {
        let mut source_by_object_path: AHashMap<PathBuf, Vec<FileId>> = AHashMap::new();
        let mut source_dirs: AHashSet<PathBuf> = AHashSet::new();
        for (file, path) in paths {
            let path = normalize_fs_path(PathBuf::from(path));
            if let Some(parent) = path.parent() {
                source_dirs.insert(parent.to_path_buf());
            }
            source_by_object_path
                .entry(path.with_extension("o"))
                .or_default()
                .push(file);
        }
        if source_by_object_path.is_empty() {
            return Self::default();
        }

        let source_paths = source_by_object_path.keys().cloned().collect::<Vec<_>>();
        let Some(root) = common_source_root(source_paths.iter()) else {
            return Self::default();
        };
        let makefiles = discover_makefiles_from_source_dirs(&source_dirs, &root);
        if makefiles.is_empty() {
            return Self::default();
        }

        let mut groups_by_file: AHashMap<FileId, Vec<u32>> = AHashMap::new();
        let mut next_group = 0u32;
        for makefile in makefiles {
            let Some(make_dir) = makefile.parent() else {
                continue;
            };
            for object_tokens in parse_makefile_object_groups(&makefile) {
                let mut members = AHashSet::new();
                for token in object_tokens {
                    if let Some(file) = object_token_to_source_file(make_dir, &token, &source_by_object_path)
                    {
                        members.insert(file);
                    }
                }
                if members.len() < 2 {
                    continue;
                }
                let group_id = next_group;
                next_group = next_group.saturating_add(1);
                for file in members {
                    groups_by_file.entry(file).or_default().push(group_id);
                }
            }
        }
        for groups in groups_by_file.values_mut() {
            groups.sort_unstable();
            groups.dedup();
        }
        Self { groups_by_file }
    }

    /// Retain only candidates linked into at least one build target
    /// with `caller_file`. Returns true only when the candidate set
    /// was actually narrowed. If any candidate lacks build-group
    /// metadata, this leaves the set unchanged so missing build facts
    /// cannot silently drop a real edge.
    pub fn retain_candidates_linked_with(
        &self,
        global: &GlobalIndex,
        caller_file: FileId,
        candidates: &mut Vec<FuncId>,
    ) -> bool {
        if candidates.len() <= 1 {
            return false;
        }
        let Some(caller_groups) = self.groups_by_file.get(&caller_file) else {
            return false;
        };
        if caller_groups.is_empty() {
            return false;
        }

        let mut retained = Vec::new();
        for func in candidates.iter().copied() {
            let Some(decl_file) = global.declaring_file(SymbolId::new(func.raw())) else {
                return false;
            };
            let Some(candidate_groups) = self.groups_by_file.get(&decl_file) else {
                return false;
            };
            if sorted_slices_intersect(caller_groups, candidate_groups) {
                retained.push(func);
            }
        }
        if retained.is_empty() || retained.len() == candidates.len() {
            return false;
        }
        *candidates = retained;
        true
    }
}

#[derive(Debug, Default)]
struct WorkspaceModuleTargetCache {
    targets: AHashMap<WorkspaceModuleTargetKey, Vec<FuncId>>,
    path_matches: AHashMap<(String, FileId), bool>,
    target_parts: AHashMap<String, Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct WorkspaceModuleTargetKey {
    alias_target: String,
    alias_tail: String,
    caller_file: FileId,
    caller_module: ModulePath,
    allow_terminal_trailer: bool,
}

#[derive(Debug, Default)]
struct CallableTargetCache {
    targets: AHashMap<CallableTargetKey, Vec<FuncId>>,
    path_matches: AHashMap<(String, FileId), bool>,
    target_parts: AHashMap<String, Vec<String>>,
}

#[derive(Clone, Copy)]
struct CallableLookupSemantics<'a> {
    alias_targets: &'a AHashMap<String, AliasTarget>,
    path_for_file: &'a dyn Fn(FileId) -> Option<String>,
    file_path_parts: &'a AHashMap<FileId, Vec<String>>,
    same_directory_unqualified_calls: bool,
    module_path_syntax: bonsai_lang_api::ModulePathSyntax,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CallableTargetKey {
    name: String,
    caller_file: FileId,
    caller_module: ModulePath,
}

#[derive(Clone, Debug, Default)]
struct WorkspaceCallableBindingIndex {
    by_module: AHashMap<(String, ModulePath), Option<FuncId>>,
    by_file: AHashMap<(String, FileId), Option<FuncId>>,
}

impl WorkspaceCallableBindingIndex {
    fn build(global: &GlobalIndex) -> Self {
        let mut index = Self::default();
        for file in global.all_files() {
            for decl in global.decls_in(file) {
                if !matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) {
                    continue;
                }
                for name in callable_binding_index_names(decl) {
                    index.insert(file, &decl.module_path, name, FuncId::new(decl.symbol.raw()));
                }
            }
        }
        index
    }

    fn insert(&mut self, file: FileId, module: &ModulePath, name: String, func: FuncId) {
        if !module.is_empty() {
            insert_unique_callable_binding(&mut self.by_module, (name.clone(), module.clone()), func);
        }
        insert_unique_callable_binding(&mut self.by_file, (name, file), func);
    }

    fn unique_local(&self, name: &str, caller_file: FileId, caller_module: &ModulePath) -> Option<FuncId> {
        if !caller_module.is_empty() {
            if let Some(func) = self.by_module.get(&(name.to_string(), caller_module.clone())) {
                return *func;
            }
        }
        self.by_file
            .get(&(name.to_string(), caller_file))
            .and_then(|func| *func)
    }
}

fn insert_unique_callable_binding<K>(map: &mut AHashMap<K, Option<FuncId>>, key: K, func: FuncId)
where
    K: Eq + std::hash::Hash,
{
    if let Some(slot) = map.get_mut(&key) {
        if slot.is_some_and(|existing| existing != func) {
            *slot = None;
        }
    } else {
        map.insert(key, Some(func));
    }
}

fn callable_binding_index_names(decl: &Decl) -> Vec<String> {
    let mut names = Vec::new();
    push_unique_string(&mut names, decl.name.clone());
    if let Some(qualified) = decl.qualified_name.as_ref() {
        push_unique_string(&mut names, qualified.clone());
        push_unique_string(&mut names, short_callee(qualified).to_string());
    }
    names
}

impl CallableTargetKey {
    fn new(name: &str, caller_file: FileId, caller_module: &ModulePath) -> Self {
        Self {
            name: name.to_string(),
            caller_file,
            caller_module: caller_module.clone(),
        }
    }
}

impl WorkspaceModuleTargetKey {
    fn new(
        alias_target: &str,
        alias_tail: &str,
        caller_file: FileId,
        caller_module: &ModulePath,
        allow_terminal_trailer: bool,
    ) -> Self {
        Self {
            alias_target: alias_target.to_string(),
            alias_tail: alias_tail.to_string(),
            caller_file,
            caller_module: caller_module.clone(),
            allow_terminal_trailer,
        }
    }
}

impl WorkspaceModuleTargetCache {
    fn path_matches(
        &mut self,
        alias_target: &str,
        file: FileId,
        file_path_parts: &AHashMap<FileId, Vec<String>>,
        path_for_file: &dyn Fn(FileId) -> Option<String>,
    ) -> bool {
        cached_module_target_path_match(
            &mut self.path_matches,
            &mut self.target_parts,
            alias_target,
            file,
            file_path_parts,
            path_for_file,
        )
    }
}

impl CallableTargetCache {
    fn path_matches(
        &mut self,
        alias_target: &str,
        file: FileId,
        file_path_parts: &AHashMap<FileId, Vec<String>>,
        path_for_file: &dyn Fn(FileId) -> Option<String>,
    ) -> bool {
        cached_module_target_path_match(
            &mut self.path_matches,
            &mut self.target_parts,
            alias_target,
            file,
            file_path_parts,
            path_for_file,
        )
    }
}

fn cached_module_target_path_match(
    path_matches: &mut AHashMap<(String, FileId), bool>,
    target_parts_cache: &mut AHashMap<String, Vec<String>>,
    alias_target: &str,
    file: FileId,
    file_path_parts: &AHashMap<FileId, Vec<String>>,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
) -> bool {
    let key = (alias_target.to_string(), file);
    if let Some(cached) = path_matches.get(&key) {
        return *cached;
    }
    let target_parts = target_parts_cache
        .entry(alias_target.to_string())
        .or_insert_with(|| module_target_parts(alias_target));
    let matched = match file_path_parts.get(&file) {
        Some(path_parts) => module_target_parts_match_path_parts(target_parts, path_parts),
        None => path_for_file(file).is_some_and(|path| {
            let path_parts = module_path_parts(&path);
            module_target_parts_match_path_parts(target_parts, &path_parts)
        }),
    };
    path_matches.insert(key, matched);
    matched
}

fn normalize_fs_path(path: PathBuf) -> PathBuf {
    std::fs::canonicalize(&path).unwrap_or(path)
}

fn common_source_root<'a, I>(paths: I) -> Option<PathBuf>
where
    I: IntoIterator<Item = &'a PathBuf>,
{
    let mut iter = paths.into_iter();
    let first = iter.next()?;
    let mut root = first.parent()?.to_path_buf();
    for path in iter {
        while !path.starts_with(&root) {
            if !root.pop() {
                return None;
            }
        }
    }
    Some(root)
}

fn discover_makefiles_from_source_dirs(source_dirs: &AHashSet<PathBuf>, root: &Path) -> Vec<PathBuf> {
    let mut out = AHashSet::new();
    for source_dir in source_dirs {
        let mut current = Some(source_dir.as_path());
        while let Some(dir) = current {
            if !dir.starts_with(root) {
                break;
            }
            for name in ["Makefile", "makefile", "GNUmakefile"] {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    out.insert(normalize_fs_path(candidate));
                }
            }
            if dir == root {
                break;
            }
            current = dir.parent();
        }
    }
    let mut out = out.into_iter().collect::<Vec<_>>();
    out.sort();
    out
}

fn parse_makefile_object_groups(makefile: &Path) -> Vec<Vec<String>> {
    let Ok(contents) = std::fs::read_to_string(makefile) else {
        return Vec::new();
    };
    let assignments = parse_makefile_assignments(&contents);
    let mut groups = Vec::new();
    let mut names = assignments.keys().cloned().collect::<Vec<_>>();
    names.sort();
    for name in names {
        let upper = name.to_ascii_uppercase();
        if !upper.contains("OBJ") && !upper.contains("OBJECT") {
            continue;
        }
        let mut visiting = AHashSet::new();
        let mut tokens = expand_make_tokens(&name, &assignments, &mut visiting);
        tokens.retain(|token| object_token_is_resolved(token));
        tokens.sort();
        tokens.dedup();
        if tokens.len() >= 2 {
            groups.push(tokens);
        }
    }
    groups
}

fn parse_makefile_assignments(contents: &str) -> AHashMap<String, Vec<String>> {
    let mut assignments: AHashMap<String, Vec<String>> = AHashMap::new();
    let mut logical = String::new();
    for raw_line in contents.lines() {
        let trimmed_end = raw_line.trim_end();
        let continued = trimmed_end.ends_with('\\');
        let piece = if continued {
            trimmed_end.trim_end_matches('\\')
        } else {
            trimmed_end
        };
        if !logical.is_empty() {
            logical.push(' ');
        }
        logical.push_str(piece);
        if continued {
            continue;
        }
        parse_makefile_assignment_line(&logical, &mut assignments);
        logical.clear();
    }
    if !logical.trim().is_empty() {
        parse_makefile_assignment_line(&logical, &mut assignments);
    }
    assignments
}

fn parse_makefile_assignment_line(line: &str, assignments: &mut AHashMap<String, Vec<String>>) {
    let line = strip_make_comment(line).trim();
    if line.is_empty() || line.starts_with('\t') {
        return;
    }
    let Some(eq_idx) = line.find('=') else {
        return;
    };
    let lhs = line[..eq_idx].trim();
    let rhs = line[eq_idx + 1..].trim();
    let Some(name) = make_assignment_name(lhs) else {
        return;
    };
    assignments
        .entry(name)
        .or_default()
        .extend(rhs.split_whitespace().map(str::to_string));
}

fn strip_make_comment(line: &str) -> &str {
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if ch == '#' && !escaped {
            return &line[..idx];
        }
        escaped = ch == '\\' && !escaped;
        if ch != '\\' {
            escaped = false;
        }
    }
    line
}

fn make_assignment_name(lhs: &str) -> Option<String> {
    let name = lhs
        .trim_end_matches(|ch: char| ch.is_whitespace())
        .trim_end_matches(['+', '?', ':'])
        .trim();
    if name.is_empty()
        || name.contains(char::is_whitespace)
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return None;
    }
    Some(name.to_string())
}

fn expand_make_tokens(
    name: &str,
    assignments: &AHashMap<String, Vec<String>>,
    visiting: &mut AHashSet<String>,
) -> Vec<String> {
    if !visiting.insert(name.to_string()) {
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Some(tokens) = assignments.get(name) {
        for token in tokens {
            if let Some(var) = make_variable_reference(token) {
                out.extend(expand_make_tokens(&var, assignments, visiting));
            } else {
                out.push(token.clone());
            }
        }
    }
    visiting.remove(name);
    out
}

fn make_variable_reference(token: &str) -> Option<String> {
    let inner = token
        .strip_prefix("$(")
        .and_then(|rest| rest.strip_suffix(')'))
        .or_else(|| token.strip_prefix("${").and_then(|rest| rest.strip_suffix('}')))?;
    if inner.is_empty()
        || !inner
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return None;
    }
    Some(inner.to_string())
}

fn object_token_is_resolved(token: &str) -> bool {
    let token = token.trim_matches(|ch| matches!(ch, '"' | '\'' | ','));
    !token.contains('$')
        && !token.contains('%')
        && Path::new(token)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("o"))
}

fn object_token_to_source_file(
    make_dir: &Path,
    token: &str,
    source_by_object_path: &AHashMap<PathBuf, Vec<FileId>>,
) -> Option<FileId> {
    let token = token.trim_matches(|ch| matches!(ch, '"' | '\'' | ','));
    if !object_token_is_resolved(token) {
        return None;
    }
    let object_path = normalize_fs_path(make_dir.join(token));
    let candidates = source_by_object_path.get(&object_path)?;
    (candidates.len() == 1).then_some(candidates[0])
}

fn sorted_slices_intersect(left: &[u32], right: &[u32]) -> bool {
    let (mut i, mut j) = (0, 0);
    while i < left.len() && j < right.len() {
        match left[i].cmp(&right[j]) {
            std::cmp::Ordering::Equal => return true,
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
        }
    }
    false
}

// ---------------------------------------------------------------------------
// ResolvedCallGraph — workspace-wide, name-resolved, FuncId-keyed graph.
//
// `CallGraph` above is a generic add-edges container; `ResolvedCallGraph`
// wraps it with the build pass that walks every decl's `flow_events` and
// resolves each `Call.name` to one or more concrete `FuncId`s via the
// global index + per-file alias map. This is the spine `bonsai_inspect`
// (and the CLI's `inspect` command) walks for chain enumeration.
//
// Build is closure-based on the per-file alias map so this crate stays
// independent of `bonsai_resolve` / `bonsai_db` / `bonsai_workspace` —
// any caller (today: `bonsai_workspace::resolved_call_graph`) plugs in
// the alias source it has access to.
// ---------------------------------------------------------------------------

/// Workspace-wide, name-resolved call graph keyed on `FuncId`.
///
/// Every edge corresponds to a textual `Call.name` somewhere in a
/// function's `flow_events` that the resolver mapped to one or more
/// concrete `FuncId`s. Resolution rules:
///
/// - exactly one candidate → [`EdgeKind::Direct`] / [`Precision::Narrowed`]
/// - semantically explained multiple candidates (typed virtual dispatch,
///   build-compatible C declaration families) →
///   [`EdgeKind::Virtual`] / [`Precision::Narrowed`]
/// - unresolved broad multiple candidates → not recorded
/// - zero candidates → not recorded (the call escapes to an unknown
///   target — the caller's flow events still surface the textual call
///   site for `inspect`'s render layer)
///
/// Walking the graph by `FuncId` means name collisions can no longer
/// stitch chains across unrelated decls (the `Pool::__construct` vs
/// `CurlFactory::__construct` problem) — they are different symbols
/// and therefore different graph nodes.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResolvedCallGraph {
    cg: CallGraph,
    /// Deterministic metadata for graph endpoints. Persisting the node name
    /// beside resolved edges lets later compiler phases consume a warm graph
    /// without retaining or rebuilding every file's lowered declaration body.
    // These vectors are encoded by the positional binary wire format used by
    // workspace sidecars. Do not skip empty middle fields: doing so shifts a
    // later field into the previous field's type during deserialization.
    #[serde(default)]
    nodes: Vec<CallGraphNode>,
    /// Compiler-resolved file-local callable aliases (`let f = target;`).
    /// IDG construction consumes this compact linkage result instead of
    /// retaining every assignment event in every function body.
    #[serde(default)]
    local_bindings: Vec<CallGraphLocalBinding>,
    /// Call expressions or callable arguments for which the compiler found
    /// workspace candidates but could not select a semantically justified
    /// edge. Unknown external calls are intentionally absent: a coincidental
    /// short-name match elsewhere in the workspace is not resolution
    /// evidence.
    #[serde(default)]
    unresolved_workspace_sites: Vec<UnresolvedWorkspaceCallSite>,
}

/// Compact declaration identity retained beside partitioned callgraph edges.
///
/// It is compiler metadata, not a browse result: consumers use it to select
/// the exact file partition for a symbol before hydrating declaration bodies.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallGraphNode {
    pub func: FuncId,
    pub name: Box<str>,
    pub qualified_name: Option<Box<str>>,
    pub kind: DeclKind,
    pub file: FileId,
    pub name_span: Span,
}

/// Compiler-resolved file-local callable alias persisted with its caller
/// partition.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CallGraphLocalBinding {
    pub caller: FuncId,
    pub name: Box<str>,
    pub target: FuncId,
}

/// Exact workspace call site for which candidates existed but no semantic
/// edge could be selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnresolvedWorkspaceCallSite {
    pub caller: FuncId,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct ResolvedCallGraphBuildContext {
    alias_index: WorkspaceAliasIndex,
    callable_index: WorkspaceCallableBindingIndex,
    file_paths: AHashMap<FileId, String>,
    file_path_parts: AHashMap<FileId, Vec<String>>,
    build_targets: BuildTargetIndex,
    file_languages: AHashMap<FileId, Option<&'static str>>,
    file_capabilities: AHashMap<FileId, LanguageCapabilities>,
    peer_class_index: Arc<PeerClassIndex>,
    constructor_index: Arc<ConstructorIndex>,
}

struct FileCallgraphInfo {
    file: FileId,
    aliases: AHashMap<String, String>,
    alias_targets: AHashMap<String, AliasTarget>,
    language: Option<&'static str>,
    capabilities: LanguageCapabilities,
}

/// Compiler-facing callbacks used to derive per-file call-resolution facts.
///
/// Keeping these capabilities together prevents production call sites from
/// accidentally swapping two same-shaped callbacks while preserving static
/// dispatch and monomorphization.
pub struct CallGraphFileSemantics<F, T, P, G, C> {
    aliases: F,
    alias_targets: T,
    path: P,
    language: G,
    capabilities: C,
}

impl<F, T, P, G, C> CallGraphFileSemantics<F, T, P, G, C> {
    pub fn new(
        aliases_for_file: F,
        alias_targets_for_file: T,
        path_for_file: P,
        language_for_file: G,
        capabilities_for_file: C,
    ) -> Self {
        Self {
            aliases: aliases_for_file,
            alias_targets: alias_targets_for_file,
            path: path_for_file,
            language: language_for_file,
            capabilities: capabilities_for_file,
        }
    }
}

type ConstructorIndex = AHashMap<SymbolId, Vec<FuncId>>;

fn build_constructor_index(global: &GlobalIndex) -> Arc<ConstructorIndex> {
    let mut index = ConstructorIndex::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if matches!(decl.kind, DeclKind::Constructor) {
                if let Some(parent) = decl.parent {
                    index
                        .entry(parent)
                        .or_default()
                        .push(FuncId::new(decl.symbol.raw()));
                }
            }
        }
    }
    Arc::new(index)
}

impl ResolvedCallGraph {
    /// Wrap a pre-built call graph when the caller already has
    /// semantically resolved edges.
    ///
    /// Production workspace builds should prefer [`Self::build_with`]
    /// or [`Self::build_with_file_info`]. This constructor exists for
    /// adapters, tests, and importers that intentionally separate
    /// edge resolution from graph storage.
    #[must_use]
    pub fn from_call_graph(cg: CallGraph) -> Self {
        Self {
            cg,
            nodes: Vec::new(),
            local_bindings: Vec::new(),
            unresolved_workspace_sites: Vec::new(),
        }
    }

    /// Reconstruct the canonical graph from independently decoded compiler
    /// partitions. The edge set is the outgoing union; incoming adjacency is
    /// rebuilt deterministically by [`CallGraph::from_unique_edges`].
    #[must_use]
    pub fn from_persisted_parts(
        mut nodes: Vec<CallGraphNode>,
        edges: Vec<CallEdge>,
        mut local_bindings: Vec<CallGraphLocalBinding>,
        mut unresolved_workspace_sites: Vec<UnresolvedWorkspaceCallSite>,
    ) -> Self {
        nodes.sort_unstable_by_key(|node| node.func.raw());
        nodes.dedup_by_key(|node| node.func.raw());
        local_bindings.sort();
        local_bindings.dedup();
        unresolved_workspace_sites.sort_unstable();
        unresolved_workspace_sites.dedup();
        Self {
            cg: CallGraph::from_unique_edges(edges),
            nodes,
            local_bindings,
            unresolved_workspace_sites,
        }
    }

    /// Project this resolved graph to every edge lying on a directed path
    /// from `starts` to `targets`.
    ///
    /// This is an exact graph projection, not path enumeration: reverse
    /// reachability proves which nodes can reach a target, then forward
    /// reachability admits only those nodes from the source set. Work is
    /// linear in the selected graph and has no depth, path, or result cap.
    #[must_use]
    pub fn between(&self, starts: &[FuncId], targets: &[FuncId], max_precision: Option<Precision>) -> Self {
        if starts.is_empty() || targets.is_empty() {
            return Self::default();
        }

        let edge_allowed = |edge: &CallEdge| max_precision.is_none_or(|max| edge.precision <= max);
        let mut can_reach_target = AHashSet::new();
        let mut reverse = Vec::new();
        for &target in targets {
            if can_reach_target.insert(target) {
                reverse.push(target);
            }
        }
        while let Some(func) = reverse.pop() {
            for edge in self.callers_of(func).filter(|edge| edge_allowed(edge)) {
                if can_reach_target.insert(edge.from) {
                    reverse.push(edge.from);
                }
            }
        }

        let mut included = AHashSet::new();
        let mut forward = Vec::new();
        for &start in starts {
            if can_reach_target.contains(&start) && included.insert(start) {
                forward.push(start);
            }
        }
        while let Some(func) = forward.pop() {
            for edge in self
                .callees_of(func)
                .filter(|edge| edge_allowed(edge) && can_reach_target.contains(&edge.to))
            {
                if included.insert(edge.to) {
                    forward.push(edge.to);
                }
            }
        }

        let nodes = self
            .nodes
            .iter()
            .filter(|node| included.contains(&node.func))
            .cloned()
            .collect();
        let edges = self
            .cg
            .edges
            .iter()
            .filter(|edge| edge_allowed(edge) && included.contains(&edge.from) && included.contains(&edge.to))
            .cloned()
            .collect();
        let local_bindings = self
            .local_bindings
            .iter()
            .filter(|binding| included.contains(&binding.caller) && included.contains(&binding.target))
            .cloned()
            .collect();
        let unresolved_workspace_sites = self
            .unresolved_workspace_sites
            .iter()
            .filter(|site| included.contains(&site.caller))
            .copied()
            .collect();
        Self::from_persisted_parts(nodes, edges, local_bindings, unresolved_workspace_sites)
    }

    /// Build the workspace's resolved call graph from every decl's
    /// flow events. Single-pass: O(total flow events × candidates per call).
    ///
    /// `aliases_for_file` is invoked once per file to obtain the
    /// `{local_name → original_name}` alias map. Pass `|_| AHashMap::new()`
    /// when alias rewriting isn't relevant (tests, single-file fixtures).
    pub fn build_with<F>(global: &GlobalIndex, aliases_for_file: F) -> Self
    where
        F: FnMut(FileId) -> AHashMap<String, String>,
    {
        Self::build_with_paths(global, aliases_for_file, |_| None)
    }

    /// Build with an additional `path_for_file` callback. Namespace
    /// imports whose module path points at a workspace file/package can
    /// then resolve `ns.fn()` to the function declared in that module
    /// without also turning external package calls like `fmt.Println`
    /// into bare-tail matches.
    pub fn build_with_paths<F, P>(global: &GlobalIndex, aliases_for_file: F, path_for_file: P) -> Self
    where
        F: FnMut(FileId) -> AHashMap<String, String>,
        P: Fn(FileId) -> Option<String>,
    {
        Self::build_with_file_info(
            global,
            aliases_for_file,
            |_| AHashMap::new(),
            path_for_file,
            |_| &[],
            |_| None,
        )
    }

    /// Build with path and export-aliases callbacks. The aliases
    /// callback returns the language's `module_export_aliases`
    /// capability (`&[]` for languages that don't declare any). The
    /// call graph uses the slice to expand a bare alias-tail into
    /// every fully-qualified shape that resolves to the same callee
    /// (e.g. JS/TS expose `exports.<n>` and `module.exports.<n>`).
    pub fn build_with_file_info<F, T, P, L, G>(
        global: &GlobalIndex,
        aliases_for_file: F,
        alias_targets_for_file: T,
        path_for_file: P,
        export_aliases_for_file: L,
        language_for_file: G,
    ) -> Self
    where
        F: FnMut(FileId) -> AHashMap<String, String>,
        T: FnMut(FileId) -> AHashMap<String, AliasTarget>,
        P: Fn(FileId) -> Option<String>,
        L: Fn(FileId) -> &'static [&'static str],
        G: Fn(FileId) -> Option<&'static str>,
    {
        Self::build_with_file_semantics(
            global,
            CallGraphFileSemantics::new(
                aliases_for_file,
                alias_targets_for_file,
                path_for_file,
                language_for_file,
                move |file| LanguageCapabilities {
                    module_export_aliases: export_aliases_for_file(file),
                    ..LanguageCapabilities::unsupported()
                },
            ),
        )
    }

    /// Build with the complete per-file compiler semantics supplied by each
    /// adapter. Production callers should use this variant so syntax and
    /// linkage decisions cannot drift across parallel callbacks.
    pub fn build_with_file_semantics<F, T, P, G, C>(
        global: &GlobalIndex,
        file_semantics: CallGraphFileSemantics<F, T, P, G, C>,
    ) -> Self
    where
        F: FnMut(FileId) -> AHashMap<String, String>,
        T: FnMut(FileId) -> AHashMap<String, AliasTarget>,
        P: Fn(FileId) -> Option<String>,
        G: Fn(FileId) -> Option<&'static str>,
        C: Fn(FileId) -> LanguageCapabilities,
    {
        Self::build_with_file_semantics_scoped(global, file_semantics, None)
    }

    /// Build the exact resolved graph from a compact workspace declaration
    /// header plus disposable per-file bodies.
    ///
    /// `body_for_file` must return the same normalized declaration sequence
    /// whose headers were inserted into `global`; callers normally use
    /// `AnalyzerDb::decl_index_remapped_to_headers`. Each body is dropped as
    /// soon as that file's outgoing edges have been resolved, so graph
    /// semantics are unchanged while resident memory is independent of total
    /// source body size.
    pub fn build_with_file_semantics_streaming<F, T, P, G, C, D>(
        global: &GlobalIndex,
        file_semantics: CallGraphFileSemantics<F, T, P, G, C>,
        body_for_file: D,
    ) -> Self
    where
        F: FnMut(FileId) -> AHashMap<String, String>,
        T: FnMut(FileId) -> AHashMap<String, AliasTarget>,
        P: Fn(FileId) -> Option<String>,
        G: Fn(FileId) -> Option<&'static str>,
        C: Fn(FileId) -> LanguageCapabilities,
        D: Fn(FileId) -> Option<bonsai_lang_api::DeclIndex> + Sync,
    {
        let CallGraphFileSemantics {
            aliases: aliases_for_file,
            alias_targets: alias_targets_for_file,
            path: path_for_file,
            language: language_for_file,
            capabilities: capabilities_for_file,
        } = file_semantics;
        let context = Self::build_context(global, path_for_file, language_for_file, capabilities_for_file);
        let files = global.all_files().collect::<Vec<_>>();
        Self::build_with_file_semantics_for_files_streaming_with_context(
            global,
            aliases_for_file,
            alias_targets_for_file,
            &files,
            &context,
            body_for_file,
        )
    }

    /// Build the resolved call graph for a subset of caller files.
    ///
    /// Resolution still consults the workspace-wide symbol, path, and
    /// language indexes, but only declarations in `included_files`
    /// contribute outgoing call edges. Security scans use this to keep
    /// production-scope runs from walking tests, fixtures, and generated
    /// trees before the file-scoped IDG build.
    pub fn build_with_file_semantics_for_files<F, T, P, G, C>(
        global: &GlobalIndex,
        file_semantics: CallGraphFileSemantics<F, T, P, G, C>,
        included_files: &[FileId],
    ) -> Self
    where
        F: FnMut(FileId) -> AHashMap<String, String>,
        T: FnMut(FileId) -> AHashMap<String, AliasTarget>,
        P: Fn(FileId) -> Option<String>,
        G: Fn(FileId) -> Option<&'static str>,
        C: Fn(FileId) -> LanguageCapabilities,
    {
        Self::build_with_file_semantics_scoped(global, file_semantics, Some(included_files))
    }

    pub fn build_context<P, G, C>(
        global: &GlobalIndex,
        path_for_file: P,
        language_for_file: G,
        capabilities_for_file: C,
    ) -> ResolvedCallGraphBuildContext
    where
        P: Fn(FileId) -> Option<String>,
        G: Fn(FileId) -> Option<&'static str>,
        C: Fn(FileId) -> LanguageCapabilities,
    {
        let alias_index = WorkspaceAliasIndex::build(global);
        let callable_index = WorkspaceCallableBindingIndex::build(global);
        let all_files = global.all_files().collect::<Vec<_>>();
        let file_paths: AHashMap<FileId, String> = all_files
            .iter()
            .filter_map(|&file| path_for_file(file).map(|path| (file, path)))
            .collect();
        let file_path_parts: AHashMap<FileId, Vec<String>> = file_paths
            .iter()
            .map(|(&file, path)| (file, module_path_parts(path)))
            .collect();
        let file_languages: AHashMap<FileId, Option<&'static str>> = all_files
            .iter()
            .map(|&file| (file, language_for_file(file)))
            .collect();
        let file_capabilities: AHashMap<FileId, LanguageCapabilities> = all_files
            .iter()
            .map(|&file| (file, capabilities_for_file(file)))
            .collect();
        let build_targets = BuildTargetIndex::from_file_paths(
            file_paths
                .iter()
                .filter(|(file, _)| {
                    file_capabilities
                        .get(file)
                        .is_some_and(|capabilities| capabilities.build_target_linkage)
                })
                .map(|(&file, path)| (file, path.clone())),
        );
        let peer_class_index = build_shared_peer_class_index(global);
        let constructor_index = build_constructor_index(global);
        ResolvedCallGraphBuildContext {
            alias_index,
            callable_index,
            file_paths,
            file_path_parts,
            build_targets,
            file_languages,
            file_capabilities,
            peer_class_index,
            constructor_index,
        }
    }

    pub fn build_with_file_semantics_for_files_with_context<F, T>(
        global: &GlobalIndex,
        mut aliases_for_file: F,
        mut alias_targets_for_file: T,
        included_files: &[FileId],
        context: &ResolvedCallGraphBuildContext,
    ) -> Self
    where
        F: FnMut(FileId) -> AHashMap<String, String>,
        T: FnMut(FileId) -> AHashMap<String, AliasTarget>,
    {
        let mut files = included_files.to_vec();
        files.sort_by_key(|file| file.raw());
        files.dedup();
        let file_infos = files
            .into_iter()
            .map(|file| FileCallgraphInfo {
                file,
                aliases: aliases_for_file(file),
                alias_targets: alias_targets_for_file(file),
                language: context.file_languages.get(&file).copied().flatten(),
                capabilities: context
                    .file_capabilities
                    .get(&file)
                    .copied()
                    .unwrap_or_else(LanguageCapabilities::unsupported),
            })
            .collect::<Vec<_>>();
        let resolve_file = |info: &FileCallgraphInfo| {
            resolve_file_call_edges(global, context, info, global.decls_in(info.file))
        };
        let resolution = collect_resolved_file_edges(&file_infos, resolve_file);
        let cg = CallGraph::from_unique_edges(resolution.edges);
        let nodes = callgraph_nodes(global, &cg);
        Self {
            cg,
            nodes,
            local_bindings: resolution.local_bindings,
            unresolved_workspace_sites: resolution.unresolved_workspace_sites,
        }
    }

    /// Resolve a selected set of caller files from disposable exact bodies
    /// while sharing one workspace-wide header resolution context.
    pub fn build_with_file_semantics_for_files_streaming_with_context<F, T, D>(
        global: &GlobalIndex,
        aliases_for_file: F,
        alias_targets_for_file: T,
        included_files: &[FileId],
        context: &ResolvedCallGraphBuildContext,
        body_for_file: D,
    ) -> Self
    where
        F: FnMut(FileId) -> AHashMap<String, String>,
        T: FnMut(FileId) -> AHashMap<String, AliasTarget>,
        D: Fn(FileId) -> Option<bonsai_lang_api::DeclIndex> + Sync,
    {
        Self::build_with_file_semantics_streaming_with_context_scoped(
            global,
            aliases_for_file,
            alias_targets_for_file,
            included_files,
            None,
            context,
            body_for_file,
        )
    }

    /// Resolve only the selected callable compiler bodies.
    ///
    /// Workspace headers remain complete, so every call receives the same
    /// import, type, visibility, and overload resolution as a file-wide
    /// build. Only outgoing bodies are demand-selected. A monotone caller can
    /// therefore request newly discovered functions until its fixed point
    /// converges without retaining unrelated functions that happen to share a
    /// source file.
    pub fn build_with_file_semantics_for_funcs_streaming_with_context<F, T, D>(
        global: &GlobalIndex,
        aliases_for_file: F,
        alias_targets_for_file: T,
        included_funcs: &[FuncId],
        context: &ResolvedCallGraphBuildContext,
        body_for_file: D,
    ) -> Self
    where
        F: FnMut(FileId) -> AHashMap<String, String>,
        T: FnMut(FileId) -> AHashMap<String, AliasTarget>,
        D: Fn(FileId) -> Option<bonsai_lang_api::DeclIndex> + Sync,
    {
        let included_symbols: AHashSet<SymbolId> = included_funcs
            .iter()
            .map(|func| SymbolId::new(func.raw()))
            .collect();
        let mut included_files: Vec<FileId> = included_symbols
            .iter()
            .filter_map(|symbol| global.declaring_file(*symbol))
            .collect();
        included_files.sort_unstable_by_key(|file| file.raw());
        included_files.dedup();
        Self::build_with_file_semantics_streaming_with_context_scoped(
            global,
            aliases_for_file,
            alias_targets_for_file,
            &included_files,
            Some(&included_symbols),
            context,
            body_for_file,
        )
    }

    fn build_with_file_semantics_streaming_with_context_scoped<F, T, D>(
        global: &GlobalIndex,
        mut aliases_for_file: F,
        mut alias_targets_for_file: T,
        included_files: &[FileId],
        included_symbols: Option<&AHashSet<SymbolId>>,
        context: &ResolvedCallGraphBuildContext,
        body_for_file: D,
    ) -> Self
    where
        F: FnMut(FileId) -> AHashMap<String, String>,
        T: FnMut(FileId) -> AHashMap<String, AliasTarget>,
        D: Fn(FileId) -> Option<bonsai_lang_api::DeclIndex> + Sync,
    {
        let mut files = included_files.to_vec();
        files.sort_by_key(|file| file.raw());
        files.dedup();
        let file_infos = files
            .into_iter()
            .map(|file| FileCallgraphInfo {
                file,
                aliases: aliases_for_file(file),
                alias_targets: alias_targets_for_file(file),
                language: context.file_languages.get(&file).copied().flatten(),
                capabilities: context
                    .file_capabilities
                    .get(&file)
                    .copied()
                    .unwrap_or_else(LanguageCapabilities::unsupported),
            })
            .collect::<Vec<_>>();
        let resolve_file = |info: &FileCallgraphInfo| {
            body_for_file(info.file).map_or_else(FileCallgraphResolution::default, |mut index| {
                if let Some(included) = included_symbols {
                    index.defs.retain(|decl| included.contains(&decl.symbol));
                }
                resolve_file_call_edges(global, context, info, &index.defs)
            })
        };
        let resolution = collect_resolved_file_edges(&file_infos, resolve_file);
        let cg = CallGraph::from_unique_edges(resolution.edges);
        let nodes = callgraph_nodes(global, &cg);
        Self {
            cg,
            nodes,
            local_bindings: resolution.local_bindings,
            unresolved_workspace_sites: resolution.unresolved_workspace_sites,
        }
    }

    fn build_with_file_semantics_scoped<F, T, P, G, C>(
        global: &GlobalIndex,
        file_semantics: CallGraphFileSemantics<F, T, P, G, C>,
        included_files: Option<&[FileId]>,
    ) -> Self
    where
        F: FnMut(FileId) -> AHashMap<String, String>,
        T: FnMut(FileId) -> AHashMap<String, AliasTarget>,
        P: Fn(FileId) -> Option<String>,
        G: Fn(FileId) -> Option<&'static str>,
        C: Fn(FileId) -> LanguageCapabilities,
    {
        let CallGraphFileSemantics {
            aliases: aliases_for_file,
            alias_targets: alias_targets_for_file,
            path: path_for_file,
            language: language_for_file,
            capabilities: capabilities_for_file,
        } = file_semantics;
        let context = Self::build_context(global, path_for_file, language_for_file, capabilities_for_file);
        let files = included_files
            .map(<[FileId]>::to_vec)
            .unwrap_or_else(|| global.all_files().collect());
        Self::build_with_file_semantics_for_files_with_context(
            global,
            aliases_for_file,
            alias_targets_for_file,
            &files,
            &context,
        )
    }

    /// All `(caller, edge)` pairs that target `func`. Exposes the edge
    /// so chain enumeration can carry precision through the walk.
    pub fn callers_of(&self, func: FuncId) -> impl Iterator<Item = &CallEdge> + '_ {
        self.cg.callers(func)
    }

    /// All `(callee, edge)` pairs `func` invokes.
    pub fn callees_of(&self, func: FuncId) -> impl Iterator<Item = &CallEdge> + '_ {
        self.cg.callees(func)
    }

    /// Underlying `CallGraph` — mostly an escape hatch for callers that
    /// want to use `CallGraph::reachable` or iterate every edge.
    #[must_use]
    pub fn inner(&self) -> &CallGraph {
        &self.cg
    }

    /// Grammar-derived declaration name for a resolved graph endpoint.
    ///
    /// Production graphs persist this compact node table so consumers that
    /// only need graph identity do not have to hydrate whole-file flow IR.
    #[must_use]
    pub fn node_name(&self, func: FuncId) -> Option<&str> {
        self.nodes
            .binary_search_by_key(&func.raw(), |node| node.func.raw())
            .ok()
            .map(|index| self.nodes[index].name.as_ref())
    }

    /// Deterministic callable declaration table used by partitioned sidecars.
    #[must_use]
    pub fn nodes(&self) -> &[CallGraphNode] {
        &self.nodes
    }

    /// Exact local callable bindings in canonical order.
    #[must_use]
    pub fn local_binding_records(&self) -> &[CallGraphLocalBinding] {
        &self.local_bindings
    }

    /// Exact unresolved workspace call sites in canonical order.
    #[must_use]
    pub fn unresolved_workspace_site_records(&self) -> &[UnresolvedWorkspaceCallSite] {
        &self.unresolved_workspace_sites
    }

    /// Iterate compiler-resolved local callable aliases in deterministic
    /// `(caller, name, target)` order.
    pub fn local_callable_bindings(&self) -> impl Iterator<Item = (FuncId, &str, FuncId)> {
        self.local_bindings
            .iter()
            .map(|binding| (binding.caller, binding.name.as_ref(), binding.target))
    }

    /// Iterate exact resolver gaps in deterministic caller/span order.
    ///
    /// Each row had workspace candidates but no semantically justified call
    /// edge. Calls with no workspace evidence are external/unknown and do not
    /// make a workspace scan incomplete merely because their short name
    /// collides with an unrelated declaration.
    pub fn unresolved_workspace_call_sites(&self) -> impl Iterator<Item = (FuncId, Span)> + '_ {
        self.unresolved_workspace_sites
            .iter()
            .map(|site| (site.caller, site.span))
    }
}

fn resolve_file_call_edges(
    global: &GlobalIndex,
    context: &ResolvedCallGraphBuildContext,
    info: &FileCallgraphInfo,
    decls: &[Decl],
) -> FileCallgraphResolution {
    let path_lookup = |file| context.file_paths.get(&file).cloned();
    let language_lookup = |file| context.file_languages.get(&file).copied().flatten();
    let mut method_candidate_cache =
        MethodCandidateCache::with_peer_class_index(context.peer_class_index.clone());
    let mut workspace_module_cache = WorkspaceModuleTargetCache::default();
    let mut callable_target_cache = CallableTargetCache::default();
    let mut local_cg = CallGraph::new();
    let mut resolved_bindings = Vec::new();
    let mut unresolved_workspace_sites = Vec::new();
    for decl in decls {
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        let from = FuncId::new(decl.symbol.raw());
        let alias_targets = alias_targets_for_decl(&info.alias_targets, decl);
        let local_bindings = collect_local_callable_bindings_with_alias_index(
            &decl.flow_events,
            global,
            decl,
            &alias_targets,
            &context.alias_index,
            Some(&context.callable_index),
            info.capabilities,
        );
        resolved_bindings.extend(
            local_bindings
                .iter()
                .map(|(name, &target)| CallGraphLocalBinding {
                    caller: from,
                    name: name.clone().into_boxed_str(),
                    target,
                }),
        );
        let resolution = CallResolutionContext {
            from,
            caller_decl: decl,
            global,
            aliases: &info.aliases,
            alias_targets: &alias_targets,
            local_bindings: &local_bindings,
            path_for_file: &path_lookup,
            file_path_parts: &context.file_path_parts,
            caller_language: info.language,
            caller_capabilities: info.capabilities,
            language_for_file: &language_lookup,
            alias_index: &context.alias_index,
            build_targets: &context.build_targets,
            constructor_index: &context.constructor_index,
        };
        add_resolved_call_edges(
            &decl.flow_events,
            &resolution,
            &mut CallGraphBuildState {
                method_candidate_cache: &mut method_candidate_cache,
                workspace_module_cache: &mut workspace_module_cache,
                callable_target_cache: &mut callable_target_cache,
                graph: &mut local_cg,
                unresolved_workspace_sites: &mut unresolved_workspace_sites,
            },
        );
    }
    unresolved_workspace_sites.sort_unstable();
    unresolved_workspace_sites.dedup();
    FileCallgraphResolution {
        edges: local_cg.edges,
        local_bindings: resolved_bindings,
        unresolved_workspace_sites,
    }
}

#[derive(Default)]
struct FileCallgraphResolution {
    edges: Vec<CallEdge>,
    local_bindings: Vec<CallGraphLocalBinding>,
    unresolved_workspace_sites: Vec<UnresolvedWorkspaceCallSite>,
}

fn collect_resolved_file_edges<R>(
    file_infos: &[FileCallgraphInfo],
    resolve_file: R,
) -> FileCallgraphResolution
where
    R: Fn(&FileCallgraphInfo) -> FileCallgraphResolution + Sync,
{
    let workers = callgraph_resolver_worker_count();
    let file_results = if rayon::current_thread_index().is_some() {
        // A cold semantic service may be requested by several workers in an
        // existing Rayon batch. Building and synchronously joining a nested
        // pool there can form a lock cycle with the service's single-flight
        // guard. Resolve serially on that worker instead; the fact set is
        // identical and nested concurrency remains bounded by the caller's
        // compiler scheduler.
        file_infos.iter().map(&resolve_file).collect()
    } else {
        match rayon::ThreadPoolBuilder::new().num_threads(workers).build() {
            Ok(pool) => pool.install(|| {
                use rayon::prelude::*;
                file_infos.par_iter().map(&resolve_file).collect::<Vec<_>>()
            }),
            Err(_) => file_infos.iter().map(resolve_file).collect(),
        }
    };
    let edge_count = file_results.iter().map(|result| result.edges.len()).sum();
    let binding_count = file_results
        .iter()
        .map(|result| result.local_bindings.len())
        .sum();
    let unresolved_count = file_results
        .iter()
        .map(|result| result.unresolved_workspace_sites.len())
        .sum();
    let mut out = FileCallgraphResolution {
        edges: Vec::with_capacity(edge_count),
        local_bindings: Vec::with_capacity(binding_count),
        unresolved_workspace_sites: Vec::with_capacity(unresolved_count),
    };
    for result in file_results {
        out.edges.extend(result.edges);
        out.local_bindings.extend(result.local_bindings);
        out.unresolved_workspace_sites
            .extend(result.unresolved_workspace_sites);
    }
    out.local_bindings.sort();
    out.local_bindings.dedup();
    out.unresolved_workspace_sites.sort_unstable();
    out.unresolved_workspace_sites.dedup();
    out
}

fn callgraph_nodes(global: &GlobalIndex, _graph: &CallGraph) -> Vec<CallGraphNode> {
    let mut nodes = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            nodes.push(CallGraphNode {
                func: FuncId::new(decl.symbol.raw()),
                name: decl.name.clone().into_boxed_str(),
                qualified_name: decl
                    .qualified_name
                    .as_deref()
                    .map(|name| name.to_string().into_boxed_str()),
                kind: decl.kind,
                file: decl.name_span.file,
                name_span: decl.name_span,
            });
        }
    }
    nodes.sort_unstable_by_key(|node| node.func.raw());
    nodes.dedup_by_key(|node| node.func.raw());
    nodes
}

fn callgraph_resolver_worker_count() -> usize {
    let available = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .max(1);
    let requested = std::env::var("BONSAI_CALLGRAPH_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .or_else(|| {
            std::env::var("RAYON_NUM_THREADS")
                .ok()
                .and_then(|raw| raw.parse::<usize>().ok())
        })
        .unwrap_or(available)
        .max(1)
        .min(available);
    // Resolver workers share immutable compiler indexes and own only one
    // file's candidate/callable-binding caches. Use their measured resource
    // profile instead of the heavier parser/lowering profile; scheduling
    // changes concurrency only and every caller is still resolved.
    bonsai_common::callgraph_worker_count(requested)
}

/// Walk one decl's `flow_events` and emit a [`CallEdge`] per resolved
/// call site. Recurses through every structural variant (`Branch`,
/// `Loop`, `Try`, `Defer`, `Using`).
#[derive(Clone, Copy)]
struct CallResolutionContext<'a> {
    from: FuncId,
    caller_decl: &'a Decl,
    global: &'a GlobalIndex,
    aliases: &'a AHashMap<String, String>,
    alias_targets: &'a AHashMap<String, AliasTarget>,
    local_bindings: &'a AHashMap<String, FuncId>,
    path_for_file: &'a dyn Fn(FileId) -> Option<String>,
    file_path_parts: &'a AHashMap<FileId, Vec<String>>,
    caller_language: Option<&'static str>,
    caller_capabilities: LanguageCapabilities,
    language_for_file: &'a dyn Fn(FileId) -> Option<&'static str>,
    alias_index: &'a WorkspaceAliasIndex,
    build_targets: &'a BuildTargetIndex,
    constructor_index: &'a ConstructorIndex,
}

impl<'a> CallResolutionContext<'a> {
    fn callable_lookup_semantics(&self) -> CallableLookupSemantics<'a> {
        CallableLookupSemantics {
            alias_targets: self.alias_targets,
            path_for_file: self.path_for_file,
            file_path_parts: self.file_path_parts,
            same_directory_unqualified_calls: self.caller_capabilities.same_directory_unqualified_calls,
            module_path_syntax: self.caller_capabilities.module_path_syntax,
        }
    }
}

struct CallGraphBuildState<'a> {
    method_candidate_cache: &'a mut MethodCandidateCache,
    workspace_module_cache: &'a mut WorkspaceModuleTargetCache,
    callable_target_cache: &'a mut CallableTargetCache,
    graph: &'a mut CallGraph,
    unresolved_workspace_sites: &'a mut Vec<UnresolvedWorkspaceCallSite>,
}

/// Adapter-emitted syntax facts for one call site plus the receiver identity
/// derived from those facts. Candidate discovery and narrowing consume this
/// immutable compiler input in separate phases.
struct CallSiteFacts<'a> {
    name: &'a str,
    receiver: Option<&'a str>,
    receiver_types: &'a [String],
    call_kind: CallKind,
    span: Span,
    args: &'a [CallArg],
    semantic_receiver: Option<&'a str>,
    alias_qualified: bool,
    local_value_shadow: bool,
    explicit_ancestor_constructor: bool,
}

struct CallCandidateSet {
    values: Vec<FuncId>,
    from_callable_binding: bool,
    from_dynamic_param_receiver: bool,
}

fn add_call_event_edges(
    event: &FlowEvent,
    context: &CallResolutionContext<'_>,
    state: &mut CallGraphBuildState<'_>,
) {
    let FlowEvent::Call {
        name,
        receiver,
        receiver_types,
        call_kind,
        span,
        args,
        ..
    } = event
    else {
        return;
    };
    // Operator applications are compiler-known expression flow, not
    // workspace call targets. Their operand -> result edges live in the IDG.
    if matches!(call_kind, CallKind::Operator | CallKind::IndexWrite) {
        return;
    }
    // Callback arguments are independent callgraph facts. Resolve
    // them before the outer callee pipeline so an ambiguous or
    // unresolved external API cannot suppress a compiler-resolved
    // local callback edge via an early `continue` below.
    add_callback_arg_edges(
        args,
        context,
        state.method_candidate_cache,
        state.callable_target_cache,
        state.graph,
        state.unresolved_workspace_sites,
    );
    let short = short_callee(name);
    let alias_qualified = qualified_module_alias_call(name, context.aliases)
        || module_alias_target_qualified_name(name, context.alias_targets);
    let folded_receiver = receiver_name_from_call_name(name).filter(|candidate| {
        folded_call_name_receiver_is_instance(
            candidate,
            context.caller_decl,
            context.caller_capabilities.effective_super_receiver_tokens(),
        )
    });
    let semantic_receiver = receiver.as_deref().or(folded_receiver);
    let facts = CallSiteFacts {
        name,
        receiver: receiver.as_deref(),
        receiver_types,
        call_kind: *call_kind,
        span: *span,
        args,
        semantic_receiver,
        alias_qualified,
        local_value_shadow: semantic_receiver.is_none()
            && local_value_binding_shadows_callable(&context.caller_decl.flow_events, short, *span),
        explicit_ancestor_constructor: *call_kind == CallKind::Constructor
            && semantic_receiver.is_some_and(|receiver| {
                is_super_receiver_with_tokens(
                    receiver,
                    context.caller_capabilities.effective_super_receiver_tokens(),
                )
            }),
    };
    resolve_and_emit_call_site(&facts, context, state);
}

fn collect_ast_bound_call_candidates(
    facts: &CallSiteFacts<'_>,
    context: &CallResolutionContext<'_>,
    state: &mut CallGraphBuildState<'_>,
) -> CallCandidateSet {
    let constructor_context = ConstructorResolutionContext {
        global: context.global,
        caller_decl: context.caller_decl,
        alias_targets: context.alias_targets,
        path_for_file: context.path_for_file,
        constructor_index: Some(context.constructor_index),
    };
    let mut values = collect_local_callable_binding_targets(
        context.local_bindings,
        facts.name,
        facts.semantic_receiver,
        facts.alias_qualified,
    );
    let from_callable_binding = !values.is_empty();
    if values.is_empty() && facts.semantic_receiver.is_none() && !facts.alias_qualified {
        values = collect_nested_local_callable_targets(
            context.global,
            context.caller_decl,
            facts.name,
            facts.span,
        );
    }
    if values.is_empty() && facts.explicit_ancestor_constructor {
        values =
            collect_constructor_targets_for_class_call(&constructor_context, facts.name, None, &[], false);
    }
    if values.is_empty() && facts.call_kind == CallKind::Constructor {
        let constructor_tail = short_callee(facts.name);
        let implicit_enclosing_constructor = context
            .caller_capabilities
            .effective_constructor_method_names()
            .contains(&constructor_tail)
            || context
                .caller_capabilities
                .effective_implicit_receiver_tokens()
                .contains(&constructor_tail);
        values = collect_constructor_targets_for_class_call(
            &constructor_context,
            facts.name,
            facts.receiver,
            facts.receiver_types,
            implicit_enclosing_constructor,
        );
    }
    if values.is_empty() {
        values = collect_receiver_method_targets(
            context.global,
            context.caller_decl,
            context.alias_targets,
            context.path_for_file,
            facts.semantic_receiver,
            facts.receiver_types,
            facts.call_kind,
            facts.name,
            facts.span,
            context.caller_capabilities.effective_super_receiver_tokens(),
            state.method_candidate_cache,
        );
    }
    if values.is_empty() {
        values = collect_type_qualified_method_targets(
            context.global,
            context.caller_decl,
            context.alias_targets,
            context.path_for_file,
            facts.name,
            state.method_candidate_cache,
        );
    }
    let mut from_dynamic_param_receiver = false;
    if values.is_empty() {
        values = collect_dynamic_param_receiver_method_target(
            context.global,
            context.caller_decl,
            facts.semantic_receiver,
            facts.name,
        );
        from_dynamic_param_receiver = !values.is_empty();
    }
    CallCandidateSet {
        values,
        from_callable_binding,
        from_dynamic_param_receiver,
    }
}

fn collect_workspace_call_candidates(
    mut values: Vec<FuncId>,
    facts: &CallSiteFacts<'_>,
    context: &CallResolutionContext<'_>,
    state: &mut CallGraphBuildState<'_>,
) -> (Vec<FuncId>, bool) {
    if values.is_empty()
        && facts.semantic_receiver.is_none()
        && !facts.local_value_shadow
        && fast_local_callable_reference_name(facts.name)
    {
        values = collect_callable_targets_with_context_aliases_paths_and_method_cache(
            context.global,
            facts.name,
            context.caller_decl,
            context.callable_lookup_semantics(),
            state.callable_target_cache,
            state.method_candidate_cache,
        );
    }
    let typed_receiver_method = facts.semantic_receiver.is_some() && !facts.receiver_types.is_empty();
    if values.is_empty() && !typed_receiver_method {
        values = collect_qualified_workspace_targets(
            context.global,
            facts.name,
            Some(context.aliases),
            context.alias_targets,
            context.path_for_file,
            context.file_path_parts,
            context.caller_capabilities,
            context.caller_decl,
            state.workspace_module_cache,
        );
    }
    let unresolved_method_receiver = values.is_empty()
        && facts.call_kind == CallKind::Method
        && facts.semantic_receiver.is_some()
        && !facts.alias_qualified;
    if values.is_empty() && !unresolved_method_receiver && !facts.local_value_shadow {
        values = collect_callable_targets_with_context_aliases_paths_and_method_cache(
            context.global,
            facts.name,
            context.caller_decl,
            context.callable_lookup_semantics(),
            state.callable_target_cache,
            state.method_candidate_cache,
        );
    }
    if values.is_empty()
        && context.caller_capabilities.build_target_linkage
        && facts.semantic_receiver.is_none()
        && !facts.local_value_shadow
    {
        values = collect_build_target_linked_callable_targets(
            context.global,
            facts.name,
            context.caller_decl,
            context.alias_targets,
            context.build_targets,
        );
    }
    if values.is_empty() && !unresolved_method_receiver {
        if let Some((alias_target, alias_tail)) = qualified_alias_target_tail(facts.name, context.aliases) {
            values = collect_workspace_module_targets(
                context.global,
                alias_target,
                alias_tail,
                context.path_for_file,
                context.file_path_parts,
                context.caller_capabilities,
                context.caller_decl,
                context.alias_targets,
                state.workspace_module_cache,
                true,
            );
        }
    }
    (values, unresolved_method_receiver)
}

enum QualifiedCallFallback {
    Candidates(Vec<FuncId>),
    Stop,
}

fn collect_qualified_call_fallback(
    facts: &CallSiteFacts<'_>,
    context: &CallResolutionContext<'_>,
    state: &mut CallGraphBuildState<'_>,
) -> QualifiedCallFallback {
    if facts.alias_qualified {
        return QualifiedCallFallback::Stop;
    }
    let short = short_callee(facts.name);
    let qualified_owner_in_workspace =
        bonsai_common::split_qualified_name_head_tail(facts.name).is_none_or(|(qualifier, _)| {
            context
                .alias_targets
                .get(qualifier)
                .is_some_and(|target| match target {
                    AliasTarget::Namespace { module } => is_workspace_alias_target(
                        context.alias_index,
                        module,
                        context.caller_capabilities.module_path_syntax,
                    ),
                    AliasTarget::Member { module, member } => {
                        is_workspace_alias_target(
                            context.alias_index,
                            module,
                            context.caller_capabilities.module_path_syntax,
                        ) || is_workspace_alias_target(
                            context.alias_index,
                            member,
                            context.caller_capabilities.module_path_syntax,
                        )
                    }
                    AliasTarget::Type { .. } => true,
                })
        });
    let mut values = Vec::new();
    if qualified_owner_in_workspace {
        let resolved_name = context.aliases.get(short).map(String::as_str).unwrap_or(short);
        if resolved_name != facts.name {
            values = collect_callable_targets_with_context_aliases_paths_and_method_cache(
                context.global,
                resolved_name,
                context.caller_decl,
                context.callable_lookup_semantics(),
                state.callable_target_cache,
                state.method_candidate_cache,
            );
        }
    }
    if values.is_empty()
        && (bonsai_common::qualified_name_owner(facts.name).is_some()
            || qualified_module_alias_call(facts.name, context.aliases))
    {
        QualifiedCallFallback::Stop
    } else {
        QualifiedCallFallback::Candidates(values)
    }
}

fn discover_call_site_candidates(
    facts: &CallSiteFacts<'_>,
    context: &CallResolutionContext<'_>,
    state: &mut CallGraphBuildState<'_>,
) -> Option<CallCandidateSet> {
    let CallCandidateSet {
        values: mut candidates,
        from_callable_binding: candidates_from_callable_binding,
        from_dynamic_param_receiver: candidates_from_dynamic_param_receiver,
    } = collect_ast_bound_call_candidates(facts, context, state);
    let constructor_context = ConstructorResolutionContext {
        global: context.global,
        caller_decl: context.caller_decl,
        alias_targets: context.alias_targets,
        path_for_file: context.path_for_file,
        constructor_index: Some(context.constructor_index),
    };
    let (workspace_candidates, unresolved_method_receiver) =
        collect_workspace_call_candidates(candidates, facts, context, state);
    candidates = workspace_candidates;
    if candidates.is_empty() && !unresolved_method_receiver {
        match collect_qualified_call_fallback(facts, context, state) {
            QualifiedCallFallback::Candidates(values) => candidates = values,
            QualifiedCallFallback::Stop => return None,
        }
    }
    // A capability-declared ambiguous grammar may use a bare
    // call for both functions and class construction. Refine
    // only after ordinary callable lookup fails and exact scoped
    // class resolution succeeds; spelling and casing are never
    // constructor evidence.
    if candidates.is_empty()
        && context.caller_capabilities.bare_call_constructor_syntax
        && facts.call_kind == CallKind::Function
        && facts.semantic_receiver.is_none()
    {
        candidates =
            collect_constructor_targets_for_class_call(&constructor_context, facts.name, None, &[], false);
    }
    Some(CallCandidateSet {
        values: candidates,
        from_callable_binding: candidates_from_callable_binding,
        from_dynamic_param_receiver: candidates_from_dynamic_param_receiver,
    })
}

fn resolve_and_emit_call_site(
    facts: &CallSiteFacts<'_>,
    context: &CallResolutionContext<'_>,
    state: &mut CallGraphBuildState<'_>,
) {
    let Some(candidate_set) = discover_call_site_candidates(facts, context, state) else {
        return;
    };
    let CallCandidateSet {
        values: mut candidates,
        from_callable_binding: candidates_from_callable_binding,
        from_dynamic_param_receiver: candidates_from_dynamic_param_receiver,
    } = candidate_set;
    let CallResolutionContext {
        caller_decl,
        global,
        alias_targets,
        path_for_file,
        caller_language,
        caller_capabilities,
        language_for_file,
        build_targets,
        ..
    } = *context;
    let CallSiteFacts {
        receiver_types,
        call_kind,
        span,
        args,
        semantic_receiver,
        alias_qualified: alias_qualified_call,
        ..
    } = *facts;
    let CallGraphBuildState {
        method_candidate_cache,
        graph: cg,
        unresolved_workspace_sites,
        ..
    } = state;
    if !candidates.is_empty() {
        retain_same_language_candidates(global, caller_language, language_for_file, &mut candidates);
    }
    if !candidates.is_empty() {
        retain_local_scope_candidates_when_present(global, caller_decl, path_for_file, &mut candidates);
    }
    if caller_capabilities.build_target_linkage && !candidates.is_empty() {
        build_targets.retain_candidates_linked_with(global, caller_decl.name_span.file, &mut candidates);
    }
    if !candidates.is_empty() && !candidates_from_callable_binding {
        let assigned_receiver_context = AssignedReceiverNarrowingContext {
            global,
            caller_decl,
            alias_targets,
            universal_type_names: caller_capabilities.universal_type_names,
        };
        retain_assigned_receiver_method_candidates(
            &assigned_receiver_context,
            semantic_receiver,
            span,
            method_candidate_cache,
            &mut candidates,
        );
    }
    if !candidates.is_empty() && !candidates_from_callable_binding && !candidates_from_dynamic_param_receiver
    {
        retain_semantic_receiver_evidenced_candidates(
            global,
            caller_decl,
            alias_targets,
            semantic_receiver,
            receiver_types,
            call_kind,
            span,
            alias_qualified_call,
            path_for_file,
            caller_capabilities.effective_super_receiver_tokens(),
            caller_capabilities.module_path_syntax,
            method_candidate_cache,
            &mut candidates,
        );
    }
    if !candidates.is_empty() {
        // A namespace/package qualifier is syntax ownership, not an instance
        // argument. Go `extract.UnpackTar(src, base)`, Rust
        // `store::persist(value)`, and equivalent module calls may be lowered
        // with a receiver-shaped qualifier by their grammar, but the imported
        // module does not consume parameter zero. Alias-target evidence is the
        // compiler distinction; spelling/capitalisation is deliberately not.
        let receiver_supplied = !candidates_from_callable_binding
            && !alias_qualified_call
            && (semantic_receiver.is_some() || call_kind == CallKind::Method);
        retain_signature_compatible_candidates(
            global,
            caller_decl,
            &mut candidates,
            args,
            receiver_supplied,
            caller_capabilities.universal_type_names,
        );
    }
    let resolved_call_kind = if caller_capabilities.bare_call_constructor_syntax
        && call_kind == CallKind::Function
        && !candidates.is_empty()
        && candidates.iter().all(|func| {
            global
                .decl_of(SymbolId::new(func.raw()))
                .is_some_and(|decl| decl.kind == DeclKind::Constructor)
        }) {
        CallKind::Constructor
    } else {
        call_kind
    };
    retain_call_kind_compatible_candidates(global, resolved_call_kind, &mut candidates);
    dedup_func_ids(&mut candidates);
    dedup_semantic_candidate_decls(global, &mut candidates);
    emit_call_site_candidate_edges(
        candidates,
        candidates_from_callable_binding,
        facts,
        context,
        cg,
        unresolved_workspace_sites,
    );
}

fn emit_call_site_candidate_edges(
    candidates: Vec<FuncId>,
    from_callable_binding: bool,
    facts: &CallSiteFacts<'_>,
    context: &CallResolutionContext<'_>,
    graph: &mut CallGraph,
    unresolved_workspace_sites: &mut Vec<UnresolvedWorkspaceCallSite>,
) {
    if candidates.is_empty() {
        return;
    }
    // No fan-out cap: every surviving candidate has semantic identity
    // evidence. A numeric cap here would silently discard compiler edges;
    // overly broad sets must instead be narrowed by richer adapter facts.
    let semantic_virtual = candidates.len() > 1
        && facts.call_kind == CallKind::Method
        && facts.semantic_receiver.is_some()
        && !facts.receiver_types.is_empty();
    let same_decl_family = candidate_set_is_same_decl_family(
        context.global,
        &candidates,
        context.caller_capabilities.callable_declaration_family,
    );
    let Some((kind, precision)) = semantic_edge_shape(candidates.len(), semantic_virtual || same_decl_family)
    else {
        unresolved_workspace_sites.push(UnresolvedWorkspaceCallSite {
            caller: context.from,
            span: facts.span,
        });
        return;
    };
    let provenance = edge_provenance_for_resolved_call(
        kind,
        semantic_virtual
            || (!from_callable_binding
                && facts.call_kind == CallKind::Method
                && facts.semantic_receiver.is_some()),
        same_decl_family,
        from_callable_binding
            .then_some("local or receiver-projected callable binding matched call expression"),
    );
    for to in candidates {
        graph.add_edge(CallEdge {
            from: context.from,
            to,
            span: facts.span,
            kind,
            precision,
            provenance: provenance.clone(),
        });
    }
}

fn add_assignment_call_edges(
    events: &[FlowEvent],
    event: &FlowEvent,
    context: &CallResolutionContext<'_>,
    state: &mut CallGraphBuildState<'_>,
) {
    let FlowEvent::Assign {
        source_call: Some(name),
        source_call_args,
        span,
        value_kind,
        ..
    } = event
    else {
        return;
    };
    // A YieldResult assignment binds a Ruby/block-style yielded value to the
    // block parameter. The outer Call event already represents the one real
    // invocation. Treating this binding as another call fabricates a second
    // edge at the block span and an empty tainted argument.
    if matches!(value_kind, Some(bonsai_lang_api::AssignValueKind::YieldResult)) {
        return;
    }
    let CallResolutionContext {
        from,
        caller_decl,
        global,
        alias_targets,
        local_bindings,
        path_for_file,
        file_path_parts,
        caller_language,
        caller_capabilities,
        language_for_file,
        build_targets,
        ..
    } = *context;
    let CallGraphBuildState {
        method_candidate_cache,
        workspace_module_cache,
        callable_target_cache,
        graph: cg,
        unresolved_workspace_sites,
    } = state;
    if assign_source_call_shadowed_by_explicit_call(events, name, *span) {
        return;
    }
    let source_call_from_callable_binding = !collect_local_callable_binding_targets(
        local_bindings,
        name,
        receiver_name_from_call_name(name),
        false,
    )
    .is_empty();
    let mut candidates = collect_assign_source_call_targets(
        global,
        name,
        caller_decl,
        alias_targets,
        local_bindings,
        path_for_file,
        file_path_parts,
        caller_capabilities,
        *span,
        method_candidate_cache,
        workspace_module_cache,
        callable_target_cache,
    );
    if !candidates.is_empty() {
        retain_same_language_candidates(global, caller_language, language_for_file, &mut candidates);
    }
    if !candidates.is_empty() {
        retain_local_scope_candidates_when_present(global, caller_decl, path_for_file, &mut candidates);
    }
    if caller_capabilities.build_target_linkage && !candidates.is_empty() {
        build_targets.retain_candidates_linked_with(global, caller_decl.name_span.file, &mut candidates);
    }
    if !candidates.is_empty() {
        retain_assigned_receiver_constructor_candidates(
            global,
            caller_decl,
            alias_targets,
            span,
            caller_capabilities.universal_type_names,
            method_candidate_cache,
            &mut candidates,
        );
    }
    if !candidates.is_empty() && assign_source_call_member_like(name) && !source_call_from_callable_binding {
        let receiver = receiver_name_from_call_name(name);
        let alias_qualified_call = module_alias_target_qualified_name(name, alias_targets);
        retain_semantic_receiver_evidenced_candidates(
            global,
            caller_decl,
            alias_targets,
            receiver,
            &[],
            CallKind::Method,
            *span,
            alias_qualified_call,
            path_for_file,
            caller_capabilities.effective_super_receiver_tokens(),
            caller_capabilities.module_path_syntax,
            method_candidate_cache,
            &mut candidates,
        );
    }
    if !candidates.is_empty() {
        let receiver_supplied = assign_source_call_member_like(name) && !source_call_from_callable_binding;
        retain_raw_signature_compatible_candidates(
            global,
            caller_decl,
            &mut candidates,
            source_call_args,
            receiver_supplied,
            caller_capabilities.universal_type_names,
        );
    }
    candidates.retain(|func| {
        global
            .decl_of(SymbolId::new(func.raw()))
            .is_some_and(|decl| !matches!(decl.kind, DeclKind::Constructor))
    });
    dedup_func_ids(&mut candidates);
    dedup_semantic_candidate_decls(global, &mut candidates);
    if !candidates.is_empty() {
        let same_decl_family = candidate_set_is_same_decl_family(
            global,
            &candidates,
            caller_capabilities.callable_declaration_family,
        );
        let Some((kind, precision)) = semantic_edge_shape(candidates.len(), same_decl_family) else {
            unresolved_workspace_sites.push(UnresolvedWorkspaceCallSite {
                caller: from,
                span: *span,
            });
            return;
        };
        let provenance = edge_provenance_for_resolved_call(
            kind,
            assign_source_call_member_like(name) && !source_call_from_callable_binding,
            same_decl_family,
            source_call_from_callable_binding
                .then_some("local or receiver-projected callable binding matched assignment call"),
        );
        for to in candidates {
            cg.add_edge(CallEdge {
                from,
                to,
                span: *span,
                kind,
                precision,
                provenance: provenance.clone(),
            });
        }
    }
    let args = source_call_args
        .iter()
        .map(|value_text| CallArg {
            passing_mode: Default::default(),
            span: *span,
            name: None,
            value_text: value_text.clone(),
            place: None,
            source_names: Vec::new(),
        })
        .collect::<Vec<_>>();
    add_callback_arg_edges(
        &args,
        context,
        method_candidate_cache,
        callable_target_cache,
        cg,
        unresolved_workspace_sites,
    );
}

fn add_resolved_call_edges(
    events: &[FlowEvent],
    context: &CallResolutionContext<'_>,
    state: &mut CallGraphBuildState<'_>,
) {
    for event in events {
        match event {
            FlowEvent::Call { .. } => add_call_event_edges(event, context, state),
            FlowEvent::Assign {
                source_call: Some(_), ..
            } => add_assignment_call_edges(events, event, context, state),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                add_resolved_call_edges(then_events, context, state);
                add_resolved_call_edges(else_events, context, state);
            }
            FlowEvent::Loop { body, .. } => {
                add_resolved_call_edges(body, context, state);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                add_resolved_call_edges(body, context, state);
                add_resolved_call_edges(catch_events, context, state);
                add_resolved_call_edges(finally_events, context, state);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                add_resolved_call_edges(body, context, state);
            }
            _ => {}
        }
    }
}

fn add_callback_arg_edges(
    args: &[CallArg],
    context: &CallResolutionContext<'_>,
    method_candidate_cache: &mut MethodCandidateCache,
    callable_target_cache: &mut CallableTargetCache,
    cg: &mut CallGraph,
    unresolved_workspace_sites: &mut Vec<UnresolvedWorkspaceCallSite>,
) {
    let CallResolutionContext {
        from,
        caller_decl,
        global,
        alias_targets,
        local_bindings,
        caller_language,
        caller_capabilities,
        language_for_file,
        path_for_file,
        file_path_parts,
        ..
    } = *context;
    let mut resolver = CallableArgResolutionContext {
        global,
        alias_targets,
        local_bindings,
        caller_decl,
        caller_language,
        quoted_callable_literals: caller_capabilities.quoted_callable_literals,
        callable_reference_syntax: caller_capabilities.callable_reference_syntax,
        same_directory_unqualified_calls: caller_capabilities.same_directory_unqualified_calls,
        module_path_syntax: caller_capabilities.module_path_syntax,
        path_for_file,
        file_path_parts,
        method_candidate_cache,
        callable_target_cache,
    };
    let mut seen = AHashSet::new();
    for arg in args {
        let targets = resolver.resolve(arg);
        let [to] = targets.as_slice() else {
            if targets.len() > 1 {
                unresolved_workspace_sites.push(UnresolvedWorkspaceCallSite {
                    caller: from,
                    span: arg.span,
                });
            }
            continue;
        };
        let to = *to;
        if !func_language_matches(resolver.global, resolver.caller_language, language_for_file, to) {
            continue;
        }
        if !seen.insert(to) {
            continue;
        }
        cg.add_edge(CallEdge {
            from,
            to,
            span: arg.span,
            kind: EdgeKind::Indirect,
            precision: Precision::Narrowed,
            provenance: EdgeProvenance::callable_value("call argument resolved as callable reference"),
        });
    }
}

fn assign_source_call_shadowed_by_explicit_call(
    events: &[FlowEvent],
    source_call: &str,
    assign_span: Span,
) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Call { name, span, .. } => {
            qualified_names_match(source_call, name) && spans_overlap(assign_span, *span)
        }
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            assign_source_call_shadowed_by_explicit_call(then_events, source_call, assign_span)
                || assign_source_call_shadowed_by_explicit_call(else_events, source_call, assign_span)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            assign_source_call_shadowed_by_explicit_call(body, source_call, assign_span)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            assign_source_call_shadowed_by_explicit_call(body, source_call, assign_span)
                || assign_source_call_shadowed_by_explicit_call(catch_events, source_call, assign_span)
                || assign_source_call_shadowed_by_explicit_call(finally_events, source_call, assign_span)
        }
        _ => false,
    })
}

fn spans_overlap(left: Span, right: Span) -> bool {
    left.file == right.file && left.start < right.end && right.start < left.end
}

#[allow(clippy::too_many_arguments)] // mirrors the graph-build context needed for exact resolution
fn collect_assign_source_call_targets(
    global: &GlobalIndex,
    name: &str,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    file_path_parts: &AHashMap<FileId, Vec<String>>,
    caller_capabilities: LanguageCapabilities,
    call_span: Span,
    method_candidate_cache: &mut MethodCandidateCache,
    workspace_module_cache: &mut WorkspaceModuleTargetCache,
    callable_target_cache: &mut CallableTargetCache,
) -> Vec<FuncId> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let member_like = assign_source_call_member_like(trimmed);
    let receiver = receiver_name_from_call_name(trimmed);
    let short = short_callee(trimmed);
    let lookup_semantics = CallableLookupSemantics {
        alias_targets,
        path_for_file,
        file_path_parts,
        same_directory_unqualified_calls: caller_capabilities.same_directory_unqualified_calls,
        module_path_syntax: caller_capabilities.module_path_syntax,
    };
    let mut targets = collect_local_callable_binding_targets(local_bindings, trimmed, receiver, false);
    if targets.is_empty() && !member_like {
        targets = collect_nested_local_callable_targets(global, caller_decl, trimmed, call_span);
    }
    if targets.is_empty() {
        targets = collect_callable_targets_with_context_aliases_paths_and_method_cache(
            global,
            trimmed,
            caller_decl,
            lookup_semantics,
            callable_target_cache,
            method_candidate_cache,
        );
    }
    if targets.is_empty() {
        if let Some((alias_target, alias_tail)) = namespace_alias_target_tail(trimmed, alias_targets) {
            targets = collect_workspace_module_targets(
                global,
                alias_target,
                alias_tail,
                path_for_file,
                file_path_parts,
                caller_capabilities,
                caller_decl,
                alias_targets,
                workspace_module_cache,
                true,
            );
        }
    }
    if targets.is_empty() && !member_like && short != trimmed {
        targets = collect_callable_targets_with_context_aliases_paths_and_method_cache(
            global,
            short,
            caller_decl,
            lookup_semantics,
            callable_target_cache,
            method_candidate_cache,
        );
    }
    targets
}

fn assign_source_call_member_like(name: &str) -> bool {
    bonsai_common::qualified_name_owner(name).is_some()
}

fn collect_nested_local_callable_targets(
    global: &GlobalIndex,
    caller_decl: &Decl,
    name: &str,
    call_span: Span,
) -> Vec<FuncId> {
    let short = short_callee(name);
    let caller_body = caller_decl.body_span.unwrap_or(caller_decl.span);
    let mut candidates: Vec<(FuncId, u64)> = Vec::new();
    // CONTEXTLESS_LOOKUP_JUSTIFICATION: nested-local resolver. The
    // raw name inventory is immediately constrained to declarations
    // in the caller file and caller body span, excluding the active
    // call's own enclosing declaration, before any candidate leaves
    // this helper.
    for symbol in global.find_by_name(short) {
        if *symbol == caller_decl.symbol {
            continue;
        }
        let Some(decl) = global.decl_of(*symbol) else {
            continue;
        };
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        if decl.name_span.file != caller_decl.name_span.file {
            continue;
        }
        if decl.name_span.start < caller_body.start || decl.name_span.end > caller_body.end {
            continue;
        }
        if call_span.file == decl.name_span.file
            && call_span.start >= decl.span.start
            && call_span.end <= decl.span.end
        {
            continue;
        }
        let distance = if decl.name_span.start <= call_span.start {
            call_span.start.saturating_sub(decl.name_span.start)
        } else {
            decl.name_span.start.saturating_sub(call_span.start)
        };
        candidates.push((FuncId::new(decl.symbol.raw()), distance));
    }
    if candidates.is_empty() {
        return Vec::new();
    }
    candidates.sort_by_key(|(func, distance)| (*distance, func.raw()));
    let best_distance = candidates[0].1;
    candidates
        .into_iter()
        .take_while(|(_, distance)| *distance == best_distance)
        .map(|(func, _)| func)
        .collect()
}

fn local_value_binding_shadows_callable(events: &[FlowEvent], name: &str, call_span: Span) -> bool {
    let target_name = normalize_receiver_alias_text(short_callee(name));
    if target_name.is_empty() {
        return false;
    }
    events.iter().any(|event| match event {
        FlowEvent::Assign { target, span, .. } => {
            span.end <= call_span.start && normalized_receiver_alias_matches(target, &target_name)
        }
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            local_value_binding_shadows_callable(then_events, &target_name, call_span)
                || local_value_binding_shadows_callable(else_events, &target_name, call_span)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            local_value_binding_shadows_callable(body, &target_name, call_span)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            local_value_binding_shadows_callable(body, &target_name, call_span)
                || local_value_binding_shadows_callable(catch_events, &target_name, call_span)
                || local_value_binding_shadows_callable(finally_events, &target_name, call_span)
        }
        _ => false,
    })
}

fn retain_signature_compatible_candidates(
    global: &GlobalIndex,
    caller_decl: &Decl,
    candidates: &mut Vec<FuncId>,
    args: &[CallArg],
    receiver_supplied: bool,
    universal_type_names: &[&str],
) {
    if candidates.len() <= 1 {
        return;
    }
    retain_candidates_by_arity(global, candidates, args.len(), receiver_supplied);
    if candidates.len() <= 1 {
        return;
    }

    let mut scored = Vec::new();
    let mut best_score = 0usize;
    for func in candidates.iter().copied() {
        let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
            continue;
        };
        let params = effective_param_names(decl, receiver_supplied);
        if params.len() != args.len() {
            continue;
        }
        let mut score = 0usize;
        let mut incompatible = false;
        for (arg, param_name) in args.iter().zip(params.iter()) {
            let actual_types = type_names_for_call_arg(global, caller_decl, arg);
            let expected_types = type_names_for_binding(global, decl, param_name);
            if actual_types.is_empty() || expected_types.is_empty() {
                continue;
            }
            if let Some(match_score) =
                type_sets_match_score(&actual_types, &expected_types, universal_type_names)
            {
                score += match_score;
            } else {
                incompatible = true;
                break;
            }
        }
        if !incompatible {
            best_score = best_score.max(score);
            scored.push((func, score));
        }
    }
    if best_score > 0 {
        let narrowed: Vec<FuncId> = scored
            .into_iter()
            .filter_map(|(func, score)| (score == best_score).then_some(func))
            .collect();
        if !narrowed.is_empty() {
            *candidates = narrowed;
        }
    }
}

fn retain_candidates_by_arity(
    global: &GlobalIndex,
    candidates: &mut Vec<FuncId>,
    arg_count: usize,
    receiver_supplied: bool,
) {
    let mut matches: Vec<FuncId> = candidates
        .iter()
        .copied()
        .filter(|func| {
            global
                .decl_of(SymbolId::new(func.raw()))
                .is_some_and(|decl| effective_param_names(decl, receiver_supplied).len() == arg_count)
        })
        .collect();
    if !matches.is_empty() {
        std::mem::swap(candidates, &mut matches);
    }
}

fn dedup_func_ids(candidates: &mut Vec<FuncId>) {
    let mut seen = AHashSet::new();
    candidates.retain(|func| seen.insert(*func));
}

fn retain_call_kind_compatible_candidates(
    global: &GlobalIndex,
    call_kind: CallKind,
    candidates: &mut Vec<FuncId>,
) {
    candidates.retain(|func| {
        global.decl_of(SymbolId::new(func.raw())).is_some_and(|decl| {
            matches!(decl.kind, DeclKind::Constructor) == matches!(call_kind, CallKind::Constructor)
        })
    });
}

fn dedup_symbols(candidates: &mut Vec<SymbolId>) {
    let mut seen = AHashSet::new();
    candidates.retain(|symbol| seen.insert(*symbol));
}

fn dedup_semantic_candidate_decls(global: &GlobalIndex, candidates: &mut Vec<FuncId>) {
    let mut seen = AHashSet::new();
    candidates.retain(|func| {
        let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
            return true;
        };
        seen.insert((
            decl.name_span.file.raw(),
            decl.name_span.start,
            decl.name_span.end,
            decl.kind,
            decl.name.clone(),
        ))
    });
}

fn candidate_set_is_same_decl_family(
    global: &GlobalIndex,
    candidates: &[FuncId],
    family: CallableDeclarationFamily,
) -> bool {
    type DeclFamilyKey = (
        u32,
        DeclKind,
        Option<SymbolId>,
        Option<String>,
        String,
        Vec<String>,
    );

    if candidates.len() <= 1 {
        return false;
    }

    match family {
        CallableDeclarationFamily::None => return false,
        CallableDeclarationFamily::FunctionClauses => {
            return candidate_set_is_function_clause_family(global, candidates);
        }
        CallableDeclarationFamily::SameSignature => {}
    }

    let mut first: Option<DeclFamilyKey> = None;
    for func in candidates {
        let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
            return false;
        };
        let key = (
            decl.name_span.file.raw(),
            decl.kind,
            decl.parent,
            decl.qualified_name.clone(),
            decl.name.clone(),
            decl.params.clone(),
        );
        match &first {
            Some(existing) if existing != &key => return false,
            Some(_) => {}
            None => first = Some(key),
        }
    }
    true
}

fn candidate_set_is_function_clause_family(global: &GlobalIndex, candidates: &[FuncId]) -> bool {
    let mut first: Option<(DeclKind, ModulePath, Option<String>, String, usize)> = None;
    for func in candidates {
        let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
            return false;
        };
        if decl.kind != DeclKind::Function {
            return false;
        }
        let key = (
            decl.kind,
            decl.module_path.clone(),
            decl.qualified_name.clone(),
            decl.name.clone(),
            decl.params.len(),
        );
        match &first {
            Some(existing) if existing != &key => return false,
            Some(_) => {}
            None => first = Some(key),
        }
    }
    first.is_some()
}

fn semantic_edge_shape(
    candidate_count: usize,
    semantically_explained_multi_candidate: bool,
) -> Option<(EdgeKind, Precision)> {
    match candidate_count {
        0 => None,
        1 => Some((EdgeKind::Direct, Precision::Narrowed)),
        _ if semantically_explained_multi_candidate => Some((EdgeKind::Virtual, Precision::Narrowed)),
        _ => None,
    }
}

fn edge_provenance_for_resolved_call(
    kind: EdgeKind,
    receiver_dispatch: bool,
    same_decl_family: bool,
    callable_value_evidence: Option<&'static str>,
) -> EdgeProvenance {
    if let Some(evidence) = callable_value_evidence {
        return EdgeProvenance::callable_value(evidence);
    }
    if receiver_dispatch {
        return EdgeProvenance::receiver_dispatch();
    }
    if same_decl_family || kind == EdgeKind::Virtual {
        return EdgeProvenance::decl_family();
    }
    EdgeProvenance::direct_symbol()
}

fn retain_raw_signature_compatible_candidates(
    global: &GlobalIndex,
    caller_decl: &Decl,
    candidates: &mut Vec<FuncId>,
    arg_texts: &[String],
    receiver_supplied: bool,
    universal_type_names: &[&str],
) {
    if candidates.len() <= 1 {
        return;
    }

    let mut arity_matches: Vec<FuncId> = candidates
        .iter()
        .copied()
        .filter(|func| {
            global
                .decl_of(SymbolId::new(func.raw()))
                .is_some_and(|decl| effective_param_names(decl, receiver_supplied).len() == arg_texts.len())
        })
        .collect();
    if !arity_matches.is_empty() {
        std::mem::swap(candidates, &mut arity_matches);
    }
    if candidates.len() <= 1 {
        return;
    }

    let mut scored: Vec<(FuncId, usize)> = Vec::new();
    let mut best_score = 0usize;
    for func in candidates.iter().copied() {
        let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
            continue;
        };
        let params = effective_param_names(decl, receiver_supplied);
        if params.len() != arg_texts.len() {
            continue;
        }
        let mut score = 0usize;
        let mut incompatible = false;
        for (arg_text, param_name) in arg_texts.iter().zip(params.iter()) {
            let actual_types = type_names_for_binding(global, caller_decl, arg_text);
            let expected_types = type_names_for_binding(global, decl, param_name);
            if actual_types.is_empty() || expected_types.is_empty() {
                continue;
            }
            if let Some(match_score) =
                type_sets_match_score(&actual_types, &expected_types, universal_type_names)
            {
                score += match_score;
            } else {
                incompatible = true;
                break;
            }
        }
        if !incompatible {
            best_score = best_score.max(score);
            scored.push((func, score));
        }
    }
    if best_score == 0 {
        return;
    }
    let narrowed: Vec<FuncId> = scored
        .into_iter()
        .filter_map(|(func, score)| (score == best_score).then_some(func))
        .collect();
    if !narrowed.is_empty() {
        *candidates = narrowed;
    }
}

fn effective_param_names(decl: &Decl, receiver_supplied: bool) -> Vec<&str> {
    decl.params
        .iter()
        .enumerate()
        .filter_map(|(idx, param)| {
            if receiver_supplied && decl.receiver_param_index == Some(idx) {
                None
            } else {
                Some(param.as_str())
            }
        })
        .collect()
}

fn type_names_for_binding(global: &GlobalIndex, decl: &Decl, binding: &str) -> Vec<String> {
    let binding = normalize_receiver_alias_text(binding);
    let binding = binding.trim();
    if binding.is_empty() {
        return Vec::new();
    }
    let tail = short_callee(binding);
    let mut out = Vec::new();
    for alias in &decl.type_aliases {
        let alias_name = normalize_receiver_alias_text(&alias.name);
        if alias_name == binding || alias_name == tail {
            push_unique_type_name(&mut out, &alias.type_name);
            collect_declared_supertypes(global, decl, &alias.type_name, &mut out);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn type_names_for_call_arg(global: &GlobalIndex, caller_decl: &Decl, arg: &CallArg) -> Vec<String> {
    let mut out = Vec::new();
    for binding in arg.place.iter().chain(&arg.source_names) {
        for type_name in type_names_for_binding(global, caller_decl, binding) {
            push_unique_type_name(&mut out, &type_name);
        }
    }
    let alias_targets = alias_targets_for_decl(&AHashMap::new(), caller_decl);
    let mut nested_calls = Vec::new();
    collect_call_events_within(&caller_decl.flow_events, arg.span, &mut nested_calls);
    for event in nested_calls {
        let FlowEvent::Call {
            name,
            receiver,
            receiver_types,
            call_kind: CallKind::Constructor,
            ..
        } = event
        else {
            continue;
        };
        for type_name in constructor_type_names_from_call_fact(
            global,
            caller_decl,
            &alias_targets,
            name,
            receiver.as_deref(),
            receiver_types,
        ) {
            push_unique_type_name(&mut out, &type_name);
            collect_declared_supertypes(global, caller_decl, &type_name, &mut out);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn push_unique_type_name(out: &mut Vec<String>, type_name: &str) {
    let normalized = normalize_type_name(type_name);
    if !normalized.is_empty() && !out.iter().any(|existing| existing == &normalized) {
        out.push(normalized);
    }
}

fn collect_declared_supertypes(
    global: &GlobalIndex,
    context_decl: &Decl,
    type_name: &str,
    out: &mut Vec<String>,
) {
    let mut stack = vec![normalize_type_name(type_name)];
    let mut seen = AHashSet::new();
    let ctx = ResolveContext::new(context_decl.name_span.file, &context_decl.module_path);
    while let Some(current) = stack.pop() {
        if !seen.insert(current.clone()) {
            continue;
        }
        for symbol in resolve_class(global, &current, &ctx) {
            let Some(decl) = global.decl_of(symbol) else {
                continue;
            };
            if !matches!(
                decl.kind,
                DeclKind::Class | DeclKind::Struct | DeclKind::Interface
            ) {
                continue;
            }
            for base in &decl.bases {
                let normalized_base = normalize_type_name(base);
                if normalized_base.is_empty() {
                    continue;
                }
                push_unique_type_name(out, &normalized_base);
                stack.push(normalized_base);
            }
        }
    }
}

fn type_sets_match_score(
    actual: &[String],
    expected: &[String],
    universal_type_names: &[&str],
) -> Option<usize> {
    let best = actual
        .iter()
        .filter_map(|left| {
            expected
                .iter()
                .filter_map(|right| type_name_match_score(left, right, universal_type_names))
                .max()
        })
        .max();
    best
}

fn type_name_match_score(left: &str, right: &str, universal_type_names: &[&str]) -> Option<usize> {
    let left = normalize_type_name(left);
    let right = normalize_type_name(right);
    if is_universal_type_name(&left, universal_type_names) {
        return None;
    }
    if is_universal_type_name(&right, universal_type_names) {
        return Some(1);
    }
    if left == right {
        return Some(2);
    }
    (short_callee(&left) == short_callee(&right)).then_some(2)
}

fn type_name_matches(left: &str, right: &str, universal_type_names: &[&str]) -> bool {
    type_name_match_score(left, right, universal_type_names).is_some()
}

fn is_universal_type_name(name: &str, universal_type_names: &[&str]) -> bool {
    let short = short_callee(name);
    universal_type_names.contains(&name) || universal_type_names.contains(&short)
}

fn normalize_type_name(name: &str) -> String {
    let mut out = name.trim();
    if let Some(generic_start) = out.find('<') {
        out = &out[..generic_start];
    }
    out.trim_end_matches("[]").trim().to_string()
}

/// Resolve an argument expression that might be a callable reference
/// (`&fn_name`, `Module::fn`, `:method_symbol`, …) to the workspace
/// functions it could point at.
struct CallableArgResolutionContext<'a> {
    global: &'a GlobalIndex,
    alias_targets: &'a AHashMap<String, AliasTarget>,
    local_bindings: &'a AHashMap<String, FuncId>,
    caller_decl: &'a Decl,
    caller_language: Option<&'static str>,
    quoted_callable_literals: bool,
    callable_reference_syntax: bonsai_lang_api::CallableReferenceSyntax,
    same_directory_unqualified_calls: bool,
    module_path_syntax: bonsai_lang_api::ModulePathSyntax,
    path_for_file: &'a dyn Fn(FileId) -> Option<String>,
    file_path_parts: &'a AHashMap<FileId, Vec<String>>,
    method_candidate_cache: &'a mut MethodCandidateCache,
    callable_target_cache: &'a mut CallableTargetCache,
}

impl CallableArgResolutionContext<'_> {
    fn resolve(&mut self, arg: &CallArg) -> Vec<FuncId> {
        let Self {
            global,
            alias_targets,
            local_bindings,
            caller_decl,
            caller_language: _,
            quoted_callable_literals,
            callable_reference_syntax,
            same_directory_unqualified_calls,
            module_path_syntax,
            path_for_file,
            file_path_parts,
            method_candidate_cache,
            callable_target_cache,
        } = self;
        if !call_arg_can_be_callable_reference(arg, *quoted_callable_literals) {
            return Vec::new();
        }
        let raw = arg.value_text.as_str();
        let arg_span = arg.span;
        let variants = bonsai_lang_api::callable_reference_variants(
            raw,
            *callable_reference_syntax,
            *quoted_callable_literals,
        );
        let Some(first) = variants.first() else {
            return Vec::new();
        };
        // Lambda / template literals aren't callable references that
        // resolve to a workspace function — bail before we try.
        if first.contains("=>") || first.starts_with('`') {
            return Vec::new();
        }
        let lookup_semantics = CallableLookupSemantics {
            alias_targets,
            path_for_file: *path_for_file,
            file_path_parts,
            same_directory_unqualified_calls: *same_directory_unqualified_calls,
            module_path_syntax: *module_path_syntax,
        };
        let original_alias_qualified = variants.iter().any(|variant| {
            let trimmed = bonsai_common::trim_leading_name_punctuation(variant.trim());
            alias_target_qualified_name(trimmed, alias_targets)
        });
        for variant in &variants {
            let trimmed = bonsai_common::trim_leading_name_punctuation(variant.trim());
            if trimmed.is_empty() {
                continue;
            }
            let short = short_callee(trimmed);
            let alias_qualified_reference = alias_target_qualified_name(trimmed, alias_targets);
            if original_alias_qualified && !alias_qualified_reference {
                continue;
            }
            let receiver = receiver_name_from_call_name(trimmed);
            let local_targets = collect_local_callable_binding_targets(
                local_bindings,
                trimmed,
                receiver,
                alias_qualified_reference,
            );
            if !local_targets.is_empty() {
                return local_targets;
            }
            // Lexical values shadow same-spelled declarations. A simple argument
            // such as `analyzer` or `envelope` is not a callable merely because a
            // workspace method or constructor has a matching name; the compiler
            // resolves the parameter/local binding first. Explicit callable
            // bindings above remain eligible, while ordinary parameters and
            // earlier value assignments stop global callable lookup here.
            if !alias_qualified_reference
                && (caller_decl.params.iter().any(|param| param == trimmed)
                    || local_value_binding_shadows_callable(&caller_decl.flow_events, trimmed, arg_span))
            {
                continue;
            }
            let mut targets = collect_callable_targets_with_context_aliases_paths_and_method_cache(
                global,
                trimmed,
                caller_decl,
                lookup_semantics,
                callable_target_cache,
                method_candidate_cache,
            );
            if targets.is_empty() && short != trimmed && !alias_qualified_reference {
                targets = collect_callable_targets_with_context_aliases_paths_and_method_cache(
                    global,
                    short,
                    caller_decl,
                    lookup_semantics,
                    callable_target_cache,
                    method_candidate_cache,
                );
            }
            if !targets.is_empty() {
                return targets;
            }
        }
        Vec::new()
    }
}

fn call_arg_can_be_callable_reference(arg: &CallArg, quoted_callable_literals: bool) -> bool {
    let trimmed = arg.value_text.trim();
    if trimmed.is_empty() {
        return false;
    }
    if is_exact_quoted_literal(trimmed) {
        return quoted_callable_literals && quoted_bare_callable_reference(trimmed).is_some();
    }
    if trimmed.contains("=>") || trimmed.starts_with('`') {
        return false;
    }
    if trimmed.starts_with("method(") {
        return true;
    }
    // `CallArg::place` is the adapter's AST proof that the argument is one
    // exact storable reference. A compound expression has no exact place but
    // still carries its constituent `source_names`; looking up its rendered
    // text as a symbol can fabricate callback edges (for example Python
    // `self.prefix + path` resolving to an unrelated method named `path`).
    // Synthetic assignment-call arguments predate `CallArg` and carry neither
    // fact, so keep accepting their simple spellings until that producer is
    // migrated to the full compiler argument IR.
    if arg.place.is_none() && !arg.source_names.is_empty() {
        return false;
    }
    !(trimmed.contains('(') || trimmed.contains(')'))
}

fn is_exact_quoted_literal(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && matches!(bytes[0], b'\'' | b'"' | b'`') && bytes.last().copied() == Some(bytes[0])
}

fn quoted_bare_callable_reference(value: &str) -> Option<&str> {
    let quote = value.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') || value.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    let inner = value.get(1..value.len().saturating_sub(1))?.trim();
    if inner.is_empty()
        || inner
            .chars()
            .any(|ch| !(ch == '_' || ch == '\\' || ch == ':' || ch.is_ascii_alphanumeric()))
        || inner.chars().next().is_some_and(|ch| ch.is_ascii_digit())
    {
        return None;
    }
    Some(inner)
}

/// Build a `local_name → FuncId` map for callable assignments
/// inside `caller_decl`'s body. Resolution narrows by the caller's
/// `Visibility` / `module_path` context per
/// `docs/contributing/design-patterns.mdx::Semantic Resolution Always`. Without
/// this filter, two unrelated codebases that each declare a
/// `static error(...)` (hiredis vs Lua) would collide on bare name.
pub fn collect_local_callable_bindings(
    events: &[FlowEvent],
    global: &GlobalIndex,
    caller_decl: &Decl,
) -> AHashMap<String, FuncId> {
    let alias_targets = alias_targets_for_decl(&AHashMap::new(), caller_decl);
    collect_local_callable_bindings_with_aliases(events, global, caller_decl, &alias_targets)
}

/// Build local callable assignment maps for every callable decl in
/// the workspace while sharing the expensive workspace alias index.
///
/// This is semantically equivalent to calling
/// [`collect_local_callable_bindings`] for each function with no
/// file-level aliases, but avoids rebuilding `WorkspaceAliasIndex`
/// for every unresolved RHS. The IDG workspace adapter uses this to
/// mirror function-pointer / closure aliases from the callgraph
/// without turning large C workspaces into O(functions * decls)
/// alias-index scans.
pub fn collect_workspace_local_callable_bindings(
    global: &GlobalIndex,
    capabilities_for_file: impl Fn(FileId) -> bonsai_lang_api::LanguageCapabilities,
) -> AHashMap<FuncId, AHashMap<String, FuncId>> {
    let alias_index = WorkspaceAliasIndex::build(global);
    let callable_index = WorkspaceCallableBindingIndex::build(global);
    let empty_file_alias_targets: AHashMap<String, AliasTarget> = AHashMap::new();
    let mut out: AHashMap<FuncId, AHashMap<String, FuncId>> = AHashMap::new();
    for file in global.all_files() {
        let decls = global.decls_in(file);
        for decl in decls {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            // Cheap pre-filter: only run the binding collector for decls
            // that can actually bind a callable. A callable-reference
            // assignment (`let f = some_func`) is detectable from the
            // events alone; a LAMBDA binding (`let f = x -> sink(x)`) is
            // not — its Assign often surfaces the lambda body's calls as
            // `source_call` (a non-callable RHS shape) — so also admit any
            // decl that hosts a nested function decl inside its span,
            // which is exactly the shape `resolve_assigned_lambda_binding`
            // resolves. Without this, locally-bound lambdas invoked as
            // `f.accept(x)` / `f.call(x)` never enter the workspace
            // binding map and lambda bodies go unreachable.
            let hosts_nested_callable =
                decls.iter().any(|other| {
                    other.symbol != decl.symbol
                        && other.kind == DeclKind::Function
                        && span_contains_or_equal(decl.span, other.span)
                }) || flow_event_assignment_hosts_nested_callable(&decl.flow_events, decls, decl.symbol);
            if !hosts_nested_callable && !flow_events_contain_callable_reference_assignment(&decl.flow_events)
            {
                continue;
            }
            let alias_targets = alias_targets_for_decl(&empty_file_alias_targets, decl);
            let bindings = collect_local_callable_bindings_with_alias_index(
                &decl.flow_events,
                global,
                decl,
                &alias_targets,
                &alias_index,
                Some(&callable_index),
                capabilities_for_file(file),
            );
            if !bindings.is_empty() {
                out.insert(FuncId::new(decl.symbol.raw()), bindings);
            }
        }
    }
    out
}

fn flow_event_assignment_hosts_nested_callable(
    events: &[FlowEvent],
    decls: &[Decl],
    caller: bonsai_common::SymbolId,
) -> bool {
    for event in events {
        match event {
            FlowEvent::Assign { span, .. } => {
                if decls.iter().any(|candidate| {
                    candidate.symbol != caller
                        && candidate.kind == DeclKind::Function
                        && span_contains_or_equal(*span, candidate.span)
                }) {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if flow_event_assignment_hosts_nested_callable(then_events, decls, caller)
                    || flow_event_assignment_hosts_nested_callable(else_events, decls, caller)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if flow_event_assignment_hosts_nested_callable(body, decls, caller) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if flow_event_assignment_hosts_nested_callable(body, decls, caller)
                    || flow_event_assignment_hosts_nested_callable(catch_events, decls, caller)
                    || flow_event_assignment_hosts_nested_callable(finally_events, decls, caller)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn flow_events_contain_callable_reference_assignment(events: &[FlowEvent]) -> bool {
    for event in events {
        match event {
            FlowEvent::Assign {
                source_call,
                source_name,
                source_names,
                value_kind,
                ..
            } => {
                if source_call.is_none()
                    && assign_rhs_is_callable_reference(source_name.as_deref(), source_names, *value_kind)
                {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if flow_events_contain_callable_reference_assignment(then_events)
                    || flow_events_contain_callable_reference_assignment(else_events)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if flow_events_contain_callable_reference_assignment(body) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if flow_events_contain_callable_reference_assignment(body)
                    || flow_events_contain_callable_reference_assignment(catch_events)
                    || flow_events_contain_callable_reference_assignment(finally_events)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

pub fn collect_local_callable_bindings_with_aliases(
    events: &[FlowEvent],
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> AHashMap<String, FuncId> {
    let mut bindings = AHashMap::new();
    let mut callable_uses = AHashSet::new();
    let capabilities = bonsai_lang_api::LanguageCapabilities::unsupported();
    collect_local_callable_binding_uses(events, capabilities, &mut callable_uses);
    collect_local_callable_bindings_into(
        events,
        global,
        caller_decl,
        alias_targets,
        None,
        None,
        capabilities,
        &callable_uses,
        &mut bindings,
    );
    bindings
}

/// Same shape as [`collect_local_callable_bindings_with_aliases`]
/// but threads a precomputed [`WorkspaceAliasIndex`] for the
/// `Type::method` short-tail gate. `build_with_file_info` calls
/// this so the index is built once per callgraph build rather
/// than once per decl. External callers stick with the public
/// non-indexed variant above; the indexed form is internal to the
/// callgraph crate.
fn collect_local_callable_bindings_with_alias_index(
    events: &[FlowEvent],
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    alias_index: &WorkspaceAliasIndex,
    callable_index: Option<&WorkspaceCallableBindingIndex>,
    capabilities: bonsai_lang_api::LanguageCapabilities,
) -> AHashMap<String, FuncId> {
    let mut bindings = AHashMap::new();
    let mut callable_uses = AHashSet::new();
    collect_local_callable_binding_uses(events, capabilities, &mut callable_uses);
    collect_local_callable_bindings_into(
        events,
        global,
        caller_decl,
        alias_targets,
        Some(alias_index),
        callable_index,
        capabilities,
        &callable_uses,
        &mut bindings,
    );
    bindings
}

fn collect_local_callable_binding_uses(
    events: &[FlowEvent],
    capabilities: bonsai_lang_api::LanguageCapabilities,
    out: &mut AHashSet<String>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                name, receiver, args, ..
            } => {
                insert_local_callable_binding_use(out, name, capabilities);
                if let Some(receiver) = receiver.as_deref() {
                    insert_local_callable_binding_use(out, receiver, capabilities);
                }
                for arg in args {
                    if call_arg_can_be_callable_reference(arg, false) {
                        insert_local_callable_binding_use(out, &arg.value_text, capabilities);
                    }
                    for source_name in &arg.source_names {
                        insert_local_callable_binding_use(out, source_name, capabilities);
                    }
                }
            }
            FlowEvent::Assign {
                source_call: Some(source_call),
                ..
            } => {
                insert_local_callable_binding_use(out, source_call, capabilities);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_local_callable_binding_uses(then_events, capabilities, out);
                collect_local_callable_binding_uses(else_events, capabilities, out);
            }
            FlowEvent::Loop { body, .. } => collect_local_callable_binding_uses(body, capabilities, out),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_local_callable_binding_uses(body, capabilities, out);
                collect_local_callable_binding_uses(catch_events, capabilities, out);
                collect_local_callable_binding_uses(finally_events, capabilities, out);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_local_callable_binding_uses(body, capabilities, out);
            }
            _ => {}
        }
    }
}

fn insert_local_callable_binding_use(
    out: &mut AHashSet<String>,
    raw: &str,
    capabilities: bonsai_lang_api::LanguageCapabilities,
) {
    for variant in bonsai_lang_api::callable_reference_variants(
        raw,
        capabilities.callable_reference_syntax,
        capabilities.quoted_callable_literals,
    ) {
        let trimmed = variant
            .trim()
            .trim_start_matches(|ch: char| !ch.is_alphanumeric() && ch != '_')
            .trim();
        if trimmed.is_empty() {
            continue;
        }
        out.insert(trimmed.to_string());
        let short = short_callee(trimmed);
        if short != trimmed {
            out.insert(short.to_string());
        }
    }
}

#[allow(clippy::too_many_arguments)] // Recursive collector threads resolver context without allocating a wrapper per event group.
fn collect_local_callable_bindings_into(
    events: &[FlowEvent],
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    alias_index: Option<&WorkspaceAliasIndex>,
    callable_index: Option<&WorkspaceCallableBindingIndex>,
    capabilities: bonsai_lang_api::LanguageCapabilities,
    callable_uses: &AHashSet<String>,
    bindings: &mut AHashMap<String, FuncId>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_names,
                span,
                value_kind,
                ..
            } => {
                if !local_callable_binding_target_is_used(target, callable_uses) {
                    continue;
                }
                if let Some(sym) = resolve_assigned_lambda_binding(global, caller_decl, target, *span) {
                    insert_local_callable_binding(bindings, target, sym);
                    continue;
                }
                if let Some(factory_call) = source_call.as_deref().filter(|call| !call.trim().is_empty()) {
                    // Bind `cb = makeCallback()` only when the factory's
                    // returned lambda can be identified uniquely. This keeps
                    // indirect-call edges semantic instead of treating every
                    // call result as an arbitrary callable.
                    if let Some(sym) = resolve_returned_lambda_factory_with_alias_index(
                        global,
                        factory_call,
                        caller_decl,
                        alias_targets,
                        alias_index,
                        callable_index,
                        capabilities,
                    ) {
                        insert_local_callable_binding(bindings, target, sym);
                        continue;
                    }
                }
                // Skip RHS that is itself a call or compound value —
                // we only bind names pointing at a callable reference
                // (e.g. `let f = some_func`). Constructor/object
                // expressions sometimes surface a class name as
                // `source_name` plus many `source_names`; treating the
                // target as a callback alias fabricates indirect edges
                // when that object is later passed as ordinary data.
                if source_call.is_some()
                    || !assign_rhs_is_callable_reference(source_name.as_deref(), source_names, *value_kind)
                {
                    continue;
                }
                if let Some(sym) = source_name
                    .as_deref()
                    .and_then(|name| {
                        resolve_callable_symbol_with_alias_index(
                            global,
                            name,
                            caller_decl,
                            alias_targets,
                            alias_index,
                            callable_index,
                            capabilities,
                        )
                    })
                    .or_else(|| {
                        source_names.iter().find_map(|name| {
                            resolve_callable_symbol_with_alias_index(
                                global,
                                name,
                                caller_decl,
                                alias_targets,
                                alias_index,
                                callable_index,
                                capabilities,
                            )
                        })
                    })
                {
                    insert_local_callable_binding(bindings, target, sym);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_local_callable_bindings_into(
                    then_events,
                    global,
                    caller_decl,
                    alias_targets,
                    alias_index,
                    callable_index,
                    capabilities,
                    callable_uses,
                    bindings,
                );
                collect_local_callable_bindings_into(
                    else_events,
                    global,
                    caller_decl,
                    alias_targets,
                    alias_index,
                    callable_index,
                    capabilities,
                    callable_uses,
                    bindings,
                );
            }
            FlowEvent::Loop { body, .. } => {
                collect_local_callable_bindings_into(
                    body,
                    global,
                    caller_decl,
                    alias_targets,
                    alias_index,
                    callable_index,
                    capabilities,
                    callable_uses,
                    bindings,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_local_callable_bindings_into(
                    body,
                    global,
                    caller_decl,
                    alias_targets,
                    alias_index,
                    callable_index,
                    capabilities,
                    callable_uses,
                    bindings,
                );
                collect_local_callable_bindings_into(
                    catch_events,
                    global,
                    caller_decl,
                    alias_targets,
                    alias_index,
                    callable_index,
                    capabilities,
                    callable_uses,
                    bindings,
                );
                collect_local_callable_bindings_into(
                    finally_events,
                    global,
                    caller_decl,
                    alias_targets,
                    alias_index,
                    callable_index,
                    capabilities,
                    callable_uses,
                    bindings,
                );
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_local_callable_bindings_into(
                    body,
                    global,
                    caller_decl,
                    alias_targets,
                    alias_index,
                    callable_index,
                    capabilities,
                    callable_uses,
                    bindings,
                );
            }
            _ => {}
        }
    }
}

fn local_callable_binding_target_is_used(target: &str, callable_uses: &AHashSet<String>) -> bool {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return false;
    }
    let bare = bonsai_common::trim_leading_name_punctuation(trimmed);
    callable_uses.contains(trimmed)
        || callable_uses.contains(short_callee(trimmed))
        || (!bare.is_empty() && callable_uses.contains(bare))
}

fn insert_local_callable_binding(bindings: &mut AHashMap<String, FuncId>, target: &str, symbol: FuncId) {
    let target = target.trim();
    if target.is_empty() {
        return;
    }
    bindings.insert(target.to_string(), symbol);
    let canonical = bonsai_common::normalize_qualified_name(target);
    if canonical != target {
        bindings.insert(canonical, symbol);
    }
}

fn collect_local_callable_binding_targets(
    local_bindings: &AHashMap<String, FuncId>,
    name: &str,
    receiver: Option<&str>,
    alias_qualified_call: bool,
) -> Vec<FuncId> {
    let mut targets = Vec::new();
    for key in local_callable_binding_lookup_keys(name, receiver, alias_qualified_call) {
        if let Some(func) = local_bindings.get(&key) {
            push_unique_func(&mut targets, *func);
        }
    }
    targets
}

fn local_callable_binding_lookup_keys(
    name: &str,
    receiver: Option<&str>,
    alias_qualified_call: bool,
) -> Vec<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut keys = Vec::new();
    let Some(receiver) = receiver.map(str::trim).filter(|receiver| !receiver.is_empty()) else {
        push_unique_string(&mut keys, trimmed.to_string());
        let short = short_callee(trimmed).trim();
        if !alias_qualified_call && short != trimmed {
            push_unique_string(&mut keys, short.to_string());
        }
        return keys;
    };

    if assign_source_call_member_like(trimmed) || receiver_name_from_call_name(trimmed).is_some() {
        push_unique_string(&mut keys, trimmed.to_string());
        push_unique_string(&mut keys, bonsai_common::normalize_qualified_name(trimmed));
    }
    let short = short_callee(trimmed).trim();
    if short.is_empty() {
        return keys;
    }
    let receiver = bonsai_common::normalize_qualified_name(receiver);
    push_unique_string(&mut keys, format!("{receiver}.{short}"));
    keys
}

fn resolve_assigned_lambda_binding(
    global: &GlobalIndex,
    caller_decl: &Decl,
    target: &str,
    assign_span: Span,
) -> Option<FuncId> {
    let target = target.trim();
    if target.is_empty() {
        return None;
    }
    let mut exact_candidates = Vec::new();
    let mut anonymous_candidates = Vec::new();
    for decl in global.decls_in(caller_decl.span.file) {
        if decl.symbol == caller_decl.symbol || decl.kind != DeclKind::Function {
            continue;
        }
        if !span_contains_or_equal(assign_span, decl.span) {
            continue;
        }
        if decl.name == target {
            exact_candidates.push(FuncId::new(decl.symbol.raw()));
        } else if decl.name.starts_with("<lambda@") {
            anonymous_candidates.push(FuncId::new(decl.symbol.raw()));
        }
    }
    let candidates = if exact_candidates.is_empty() {
        anonymous_candidates
    } else {
        exact_candidates
    };
    let [candidate] = candidates.as_slice() else {
        return None;
    };
    Some(*candidate)
}

fn resolve_returned_lambda_factory_with_alias_index(
    global: &GlobalIndex,
    raw: &str,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    alias_index: Option<&WorkspaceAliasIndex>,
    callable_index: Option<&WorkspaceCallableBindingIndex>,
    capabilities: bonsai_lang_api::LanguageCapabilities,
) -> Option<FuncId> {
    let factory = resolve_callable_symbol_with_alias_index(
        global,
        raw,
        caller_decl,
        alias_targets,
        alias_index,
        callable_index,
        capabilities,
    )?;
    let factory_decl = global.decl_of(SymbolId::new(factory.raw()))?;
    if factory_decl.kind != DeclKind::Function {
        return None;
    }
    let mut return_spans = Vec::new();
    collect_return_spans(&factory_decl.flow_events, &mut return_spans);
    if return_spans.is_empty() {
        return None;
    }
    let mut candidates = Vec::new();
    for decl in global.decls_in(factory_decl.span.file) {
        if decl.symbol == factory_decl.symbol
            || decl.kind != DeclKind::Function
            || !decl.name.starts_with("<lambda@")
        {
            continue;
        }
        if return_spans
            .iter()
            .any(|span| span_contains_or_equal(*span, decl.span))
        {
            candidates.push(FuncId::new(decl.symbol.raw()));
        }
    }
    let [candidate] = candidates.as_slice() else {
        return None;
    };
    Some(*candidate)
}

fn span_contains_or_equal(outer: Span, inner: Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}

fn assign_rhs_is_callable_reference(
    source_name: Option<&str>,
    source_names: &[String],
    value_kind: Option<AssignValueKind>,
) -> bool {
    let Some(source_name) = source_name.map(str::trim).filter(|name| !name.is_empty()) else {
        return false;
    };
    if matches!(
        value_kind,
        Some(AssignValueKind::Literal | AssignValueKind::CallResult)
    ) {
        return false;
    }
    source_names.is_empty() || source_names.iter().all(|name| name.trim() == source_name)
}

/// Resolve a local-binding RHS like `let f = some_func;` to a
/// callable [`FuncId`] in the caller's scope.
///
/// Per `docs/contributing/design-patterns.mdx::Semantic Resolution Always`,
/// resolution narrows by the caller's `Visibility` / `module_path`
/// context. This is what prevents the canonical cross-TU regression
/// where hiredis's `static error()` and Lua's `static error()`
/// collide on bare name — each is `Visibility::Private` and the
/// resolver filters by `decl_file == caller_file`. Returns `None`
/// (sound under-approximation) when no candidate matches the caller's
/// scope.
///
/// `alias_index` is a precomputed [`WorkspaceAliasIndex`] for the
/// `Type::method` short-tail gate. `build_with_file_info` builds the
/// index once at the start of the callgraph pass and passes
/// `Some(&idx)`; standalone resolver callers and individual
/// `dump-resolve` lookups) pass `None` and pay the O(decls) scan that
/// the helper falls back to.
fn resolve_callable_symbol_with_alias_index(
    global: &GlobalIndex,
    raw: &str,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    alias_index: Option<&WorkspaceAliasIndex>,
    callable_index: Option<&WorkspaceCallableBindingIndex>,
    capabilities: bonsai_lang_api::LanguageCapabilities,
) -> Option<FuncId> {
    let variants = bonsai_lang_api::callable_reference_variants(
        raw,
        capabilities.callable_reference_syntax,
        capabilities.quoted_callable_literals,
    );
    if variants.is_empty() {
        return None;
    }
    let original_alias_qualified = variants.iter().any(|variant| {
        let trimmed = bonsai_common::trim_leading_name_punctuation(variant.trim());
        alias_target_qualified_name(trimmed, alias_targets)
    });
    let caller_file = caller_decl_file(global, caller_decl)?;
    let caller_module = caller_decl.module_path.clone();
    if let Some(index) = callable_index {
        for variant in &variants {
            let trimmed = bonsai_common::trim_leading_name_punctuation(variant.trim());
            if fast_local_callable_reference_name(trimmed)
                && !alias_target_qualified_name(trimmed, alias_targets)
                && !original_alias_qualified
            {
                if let Some(func) = index.unique_local(trimmed, caller_file, &caller_module) {
                    return Some(func);
                }
            }
        }
    }
    let ctx = ResolveContext::new(caller_file, &caller_module)
        .with_alias_map(alias_targets)
        .with_module_path_syntax(capabilities.module_path_syntax);
    let owned_index;
    let alias_index = match alias_index {
        Some(index) => index,
        None => {
            owned_index = WorkspaceAliasIndex::build(global);
            &owned_index
        }
    };
    for variant in variants {
        let trimmed = bonsai_common::trim_leading_name_punctuation(variant.trim());
        if trimmed.is_empty() {
            continue;
        }
        let short = short_callee(trimmed);
        let alias_qualified_reference = alias_target_qualified_name(trimmed, alias_targets);
        if original_alias_qualified && !alias_qualified_reference {
            continue;
        }
        // Try the qualified variant first. For Rust-style
        // `Type::method` qualified calls, allow the bare-tail
        // fallback ONLY when the qualifier resolves to an in-
        // workspace alias target; otherwise external types like
        // `Command::new` (`Command` aliases `std::process::Command`)
        // would collapse onto a user-defined `Repository::new`
        // that shares the bare suffix `new`.
        let allow_short_fallback = if alias_qualified_reference {
            false
        } else if let Some(idx) = trimmed.find("::") {
            let qualifier = &trimmed[..idx];
            alias_targets
                .get(qualifier)
                .map(|t| match t {
                    AliasTarget::Namespace { module } => {
                        is_workspace_alias_target(alias_index, module, capabilities.module_path_syntax)
                    }
                    AliasTarget::Member { module, member } => {
                        is_workspace_alias_target(alias_index, module, capabilities.module_path_syntax)
                            || is_workspace_alias_target(alias_index, member, capabilities.module_path_syntax)
                    }
                    AliasTarget::Type { .. } => true,
                })
                .unwrap_or(false)
        } else {
            true
        };
        let candidates: &[&str] = if allow_short_fallback {
            &[trimmed, short]
        } else {
            &[trimmed]
        };
        for candidate in candidates {
            let resolved = resolve_callable_with_context(global, candidate, &ctx);
            if let [func] = resolved.as_slice() {
                return Some(*func);
            }
        }
    }
    None
}

fn alias_target_qualified_name(name: &str, alias_targets: &AHashMap<String, AliasTarget>) -> bool {
    qualified_alias_target_entry_tail(name, alias_targets).is_some()
}

/// True only when the first qualifier is an imported module/member alias.
///
/// `AliasTarget::Type` represents an AST value binding (`context:
/// ThreadContextStruct`), not a module namespace. Treating it as a module
/// alias disables unresolved-receiver protection and lets a field chain fall
/// through to unrelated workspace callables that merely share its leaf name.
fn module_alias_target_qualified_name(name: &str, alias_targets: &AHashMap<String, AliasTarget>) -> bool {
    qualified_alias_target_entry_tail(name, alias_targets).is_some_and(|(target, _)| {
        matches!(target, AliasTarget::Namespace { .. } | AliasTarget::Member { .. })
    })
}

fn fast_local_callable_reference_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty()
        && bonsai_common::qualified_name_owner(trimmed).is_none()
        && !trimmed.contains('(')
        && !trimmed.contains(')')
}

/// Resolve a typed-receiver method call (`obj.method(...)`) to every
/// candidate method in the workspace. The receiver's type is read
/// from `caller_decl.type_aliases`; class lookup goes through the
/// semantic-identity resolver so visibility and module-path filters
/// apply. Empty when the caller's declaring file or the receiver
/// type is unavailable — sound under-approximation per
/// `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
#[allow(clippy::too_many_arguments)] // Mirrors FlowEvent::Call plus caller context.
fn collect_receiver_method_targets(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    receiver: Option<&str>,
    receiver_types: &[String],
    call_kind: CallKind,
    call_name: &str,
    call_span: Span,
    super_receiver_tokens: &[&str],
    method_candidate_cache: &mut MethodCandidateCache,
) -> Vec<FuncId> {
    if call_kind != CallKind::Method {
        return Vec::new();
    }
    let Some(receiver) = receiver else {
        return Vec::new();
    };
    let method_name = short_callee(call_name);
    if is_super_receiver_with_tokens(receiver, super_receiver_tokens) {
        return collect_super_method_targets(
            global,
            caller_decl,
            alias_targets,
            path_for_file,
            method_name,
            method_candidate_cache,
        );
    }
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let caller_module = caller_decl.module_path.clone();
    let ctx = ResolveContext::new(caller_file, &caller_module)
        .with_alias_map(alias_targets)
        .with_file_path_lookup(path_for_file);
    let mut receiver_type_names = receiver_types.to_vec();
    if receiver_type_names.is_empty() {
        receiver_type_names = assigned_receiver_type_names(
            global,
            caller_decl,
            alias_targets,
            receiver,
            Some(call_span),
            method_candidate_cache,
        );
        for type_name in receiver_type_names_for_expr(caller_decl, alias_targets, receiver) {
            push_unique_string(&mut receiver_type_names, type_name);
        }
        for type_name in receiver_class_type_names_for_expr(global, &ctx, receiver) {
            push_unique_string(&mut receiver_type_names, type_name);
        }
        for type_name in receiver_call_return_type_names(
            global,
            caller_decl,
            alias_targets,
            receiver,
            Some(call_span),
            method_candidate_cache,
        ) {
            push_unique_string(&mut receiver_type_names, type_name);
        }
    }
    if receiver_type_names.is_empty() {
        return Vec::new();
    }
    receiver_type_names = prune_receiver_type_names_for_dispatch(receiver_type_names, global, &ctx);
    let mut seen = AHashSet::new();
    let mut class_candidates = Vec::new();
    for receiver_type in receiver_type_names {
        for class_sym in resolve_class(global, &receiver_type, &ctx) {
            if seen.insert(class_sym) {
                class_candidates.push(class_sym);
            }
        }
    }
    let mut targets = Vec::new();
    let mut seen = AHashSet::new();
    for class_sym in class_candidates {
        collect_method_candidates_for_class_cached(
            global,
            class_sym,
            method_name,
            &ctx,
            &mut seen,
            &mut targets,
            method_candidate_cache,
        );
    }
    targets
}

fn collect_super_method_targets(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    method_name: &str,
    method_candidate_cache: &mut MethodCandidateCache,
) -> Vec<FuncId> {
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let Some(class_decl) = enclosing_class_for_decl(global, caller_decl) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path)
        .with_alias_map(alias_targets)
        .with_file_path_lookup(path_for_file);
    let mut targets = Vec::new();
    let mut seen = AHashSet::new();
    for base in &class_decl.bases {
        for class_sym in resolve_class(global, base, &ctx) {
            collect_method_candidates_for_class_cached(
                global,
                class_sym,
                method_name,
                &ctx,
                &mut seen,
                &mut targets,
                method_candidate_cache,
            );
        }
    }
    targets
}

fn collect_type_qualified_method_targets(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    call_name: &str,
    method_candidate_cache: &mut MethodCandidateCache,
) -> Vec<FuncId> {
    let Some((type_name, method_name)) = type_qualified_method_tail(call_name) else {
        return Vec::new();
    };
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path)
        .with_alias_map(alias_targets)
        .with_file_path_lookup(path_for_file);
    let class_candidates = resolve_class(global, type_name, &ctx);
    if class_candidates.is_empty() {
        return Vec::new();
    }
    let mut targets = Vec::new();
    let mut seen = AHashSet::new();
    for class_sym in class_candidates {
        collect_method_candidates_for_class_cached(
            global,
            class_sym,
            method_name,
            &ctx,
            &mut seen,
            &mut targets,
            method_candidate_cache,
        );
    }
    targets
}

#[derive(Clone, Copy)]
struct ConstructorResolutionContext<'a> {
    global: &'a GlobalIndex,
    caller_decl: &'a Decl,
    alias_targets: &'a AHashMap<String, AliasTarget>,
    path_for_file: &'a dyn Fn(FileId) -> Option<String>,
    constructor_index: Option<&'a ConstructorIndex>,
}

fn collect_constructor_targets_for_class_call(
    resolution: &ConstructorResolutionContext<'_>,
    call_name: &str,
    receiver: Option<&str>,
    receiver_types: &[String],
    allow_implicit_enclosing_class: bool,
) -> Vec<FuncId> {
    let ConstructorResolutionContext {
        global,
        caller_decl,
        alias_targets,
        path_for_file,
        constructor_index,
    } = *resolution;
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path)
        .with_alias_map(alias_targets)
        .with_file_path_lookup(path_for_file);
    let mut class_candidates = Vec::new();
    let mut seen_classes = AHashSet::new();
    let mut declared_factory_name = None;
    // `Type::factory(args)` carries two independent compiler facts: the
    // qualified owner and the declared constructor member. Resolve that
    // owner before considering adapter-enriched receiver ancestry. The
    // ancestry is useful for later virtual dispatch, but it must not turn
    // one construction into every ancestor constructor.
    if receiver.is_none() {
        if let Some((owner, member)) = type_qualified_method_tail(call_name) {
            let mut resolved_owner = false;
            for class_sym in resolve_class(global, owner, &ctx) {
                if seen_classes.insert(class_sym) {
                    class_candidates.push(class_sym);
                }
                resolved_owner = true;
            }
            if resolved_owner {
                declared_factory_name = Some(member);
            }
        }
    }
    // Prefer the class named by the AST constructor expression. Adapter
    // receiver types may include its complete ancestry for later virtual
    // dispatch; treating that enrichment as co-equal constructor targets
    // would fan one `Repository(...)` expression out to `Repository` and
    // every base initializer.
    for candidate in receiver
        .into_iter()
        .chain(class_candidates.is_empty().then_some(call_name))
    {
        for type_name in receiver_type_names_for_expr(caller_decl, alias_targets, candidate) {
            for class_sym in resolve_class(global, &type_name, &ctx) {
                if seen_classes.insert(class_sym) {
                    class_candidates.push(class_sym);
                }
            }
        }
        for class_sym in resolve_class(global, candidate, &ctx) {
            if seen_classes.insert(class_sym) {
                class_candidates.push(class_sym);
            }
        }
    }
    if class_candidates.is_empty() {
        for type_name in receiver_types {
            for class_sym in resolve_class(global, type_name, &ctx) {
                if seen_classes.insert(class_sym) {
                    class_candidates.push(class_sym);
                }
            }
        }
    }
    // A receiver-less constructor expression inside a class body denotes
    // construction of the lexically enclosing class in languages whose
    // adapter classifies that syntax as `CallKind::Constructor` (for
    // example Ruby's `new(args)` inside a class method).  Use the AST's
    // owning declaration identity only after explicit receiver/callee type
    // resolution failed, so a named class expression such as `Other(args)`
    // keeps its normal lexical binding.
    if allow_implicit_enclosing_class && class_candidates.is_empty() && receiver.is_none() {
        if let Some(parent) = caller_decl.parent {
            if global
                .decl_of(parent)
                .is_some_and(|decl| matches!(decl.kind, DeclKind::Class | DeclKind::Struct | DeclKind::Enum))
                && seen_classes.insert(parent)
            {
                class_candidates.push(parent);
            }
        }
    }
    let mut targets = declared_constructor_targets(global, &class_candidates, constructor_index);
    if let Some(factory_name) = declared_factory_name {
        let mut exact = targets
            .iter()
            .copied()
            .filter(|func| {
                global
                    .decl_of(SymbolId::new(func.raw()))
                    .is_some_and(|decl| decl.name == factory_name)
            })
            .collect::<Vec<_>>();
        if !exact.is_empty() {
            std::mem::swap(&mut targets, &mut exact);
        }
    }
    if targets.is_empty() {
        // Constructor inheritance is declaration semantics, not a spelling
        // heuristic. When the constructed class declares no initializer,
        // walk each resolved base-class branch until its nearest declared
        // constructor. This mirrors compiler member lookup and ensures the
        // semantic graph includes the initializer body before the IDG is
        // scoped (for example, Swift subclasses that inherit `init`).
        let mut stack = class_candidates.clone();
        let mut seen = class_candidates.iter().copied().collect::<AHashSet<_>>();
        while let Some(class_sym) = stack.pop() {
            let Some(class_decl) = global.decl_of(class_sym) else {
                continue;
            };
            for base_name in class_decl.bases.iter().rev() {
                for base_sym in resolve_class(global, base_name, &ctx).into_iter().rev() {
                    if !seen.insert(base_sym) {
                        continue;
                    }
                    let inherited = declared_constructor_targets(global, &[base_sym], constructor_index);
                    if inherited.is_empty() {
                        stack.push(base_sym);
                    } else {
                        for constructor in inherited {
                            push_unique_func(&mut targets, constructor);
                        }
                    }
                }
            }
        }
    }
    if targets.is_empty() {
        for func in resolve_callable_with_context(global, call_name, &ctx) {
            let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
                continue;
            };
            if matches!(decl.kind, DeclKind::Constructor) {
                push_unique_func(&mut targets, func);
            }
        }
    }
    targets
}

fn declared_constructor_targets(
    global: &GlobalIndex,
    class_symbols: &[SymbolId],
    constructor_index: Option<&ConstructorIndex>,
) -> Vec<FuncId> {
    if let Some(index) = constructor_index {
        let mut out = Vec::new();
        for class_symbol in class_symbols {
            if let Some(constructors) = index.get(class_symbol) {
                for &constructor in constructors {
                    push_unique_func(&mut out, constructor);
                }
            }
        }
        return out;
    }
    let class_symbols: AHashSet<SymbolId> = class_symbols.iter().copied().collect();
    let mut out = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if matches!(decl.kind, DeclKind::Constructor)
                && decl.parent.is_some_and(|parent| class_symbols.contains(&parent))
            {
                push_unique_func(&mut out, FuncId::new(decl.symbol.raw()));
            }
        }
    }
    out
}

fn type_qualified_method_tail(call_name: &str) -> Option<(&str, &str)> {
    let (head, tail) = bonsai_common::split_qualified_name_owner_tail(call_name)?;
    let head = head.trim();
    let tail = callee_without_call_args(tail).trim();
    if head.is_empty() || tail.is_empty() {
        return None;
    }
    Some((head, tail))
}

fn receiver_call_return_type_names(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    _receiver: &str,
    call_span: Option<Span>,
    method_candidate_cache: &mut MethodCandidateCache,
) -> Vec<String> {
    let Some(call_span) = call_span else {
        return Vec::new();
    };
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(alias_targets);
    let mut inner_calls = Vec::new();
    collect_call_events_strictly_inside(&caller_decl.flow_events, call_span, &mut inner_calls);
    let mut argument_spans = Vec::new();
    collect_call_argument_spans_at_site(&caller_decl.flow_events, call_span, &mut argument_spans);
    inner_calls.retain(|event| {
        let span = event.span();
        !argument_spans
            .iter()
            .any(|arg| arg.file == span.file && arg.start <= span.start && span.end <= arg.end)
    });
    let mut out = Vec::new();
    for inner in inner_calls {
        let FlowEvent::Call {
            name,
            receiver,
            receiver_types,
            call_kind,
            ..
        } = inner
        else {
            continue;
        };
        if matches!(call_kind, CallKind::Function | CallKind::Constructor) {
            let constructed_types = constructor_type_names_from_call_fact(
                global,
                caller_decl,
                alias_targets,
                name,
                receiver.as_deref(),
                receiver_types,
            );
            for type_name in &constructed_types {
                push_unique_string(&mut out, type_name.clone());
            }
            // A function-shaped inner call whose declaration identity is a
            // class is construction in expression-oriented grammars. Its
            // exact AST type is sufficient; do not reinterpret it as an
            // ordinary callable return below.
            if !constructed_types.is_empty() {
                continue;
            }
            if matches!(call_kind, CallKind::Constructor) {
                continue;
            }
        }
        let mut funcs = resolve_callable_with_context(global, name, &ctx);
        if funcs.is_empty() {
            if let Some((type_name, method_name)) = type_qualified_method_tail(name) {
                let mut seen = AHashSet::new();
                for class_sym in resolve_class(global, type_name, &ctx) {
                    collect_method_candidates_for_class_cached(
                        global,
                        class_sym,
                        method_name,
                        &ctx,
                        &mut seen,
                        &mut funcs,
                        method_candidate_cache,
                    );
                }
            }
        }
        for func in funcs {
            let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
                continue;
            };
            collect_constructed_return_type_names(global, caller_decl, alias_targets, decl, &mut out);
        }
    }
    out
}

fn collect_call_argument_spans_at_site(events: &[FlowEvent], site: Span, out: &mut Vec<Span>) {
    for event in events {
        match event {
            FlowEvent::Call { span, args, .. } if *span == site => {
                out.extend(args.iter().map(|arg| arg.span));
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_call_argument_spans_at_site(then_events, site, out);
                collect_call_argument_spans_at_site(else_events, site, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_call_argument_spans_at_site(body, site, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_call_argument_spans_at_site(body, site, out);
                collect_call_argument_spans_at_site(catch_events, site, out);
                collect_call_argument_spans_at_site(finally_events, site, out);
            }
            _ => {}
        }
    }
}

fn collect_call_events_strictly_inside<'a>(
    events: &'a [FlowEvent],
    outer: Span,
    out: &mut Vec<&'a FlowEvent>,
) {
    for event in events {
        match event {
            FlowEvent::Call { span, .. }
                if span.file == outer.file
                    && outer.start <= span.start
                    && span.end <= outer.end
                    && *span != outer =>
            {
                out.push(event);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_call_events_strictly_inside(then_events, outer, out);
                collect_call_events_strictly_inside(else_events, outer, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_call_events_strictly_inside(body, outer, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_call_events_strictly_inside(body, outer, out);
                collect_call_events_strictly_inside(catch_events, outer, out);
                collect_call_events_strictly_inside(finally_events, outer, out);
            }
            _ => {}
        }
    }
}

fn collect_call_events_within<'a>(events: &'a [FlowEvent], outer: Span, out: &mut Vec<&'a FlowEvent>) {
    for event in events {
        match event {
            FlowEvent::Call { span, .. }
                if span.file == outer.file && outer.start <= span.start && span.end <= outer.end =>
            {
                out.push(event);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_call_events_within(then_events, outer, out);
                collect_call_events_within(else_events, outer, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_call_events_within(body, outer, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_call_events_within(body, outer, out);
                collect_call_events_within(catch_events, outer, out);
                collect_call_events_within(finally_events, outer, out);
            }
            _ => {}
        }
    }
}

fn receiver_name_from_call_name(call_name: &str) -> Option<&str> {
    bonsai_common::qualified_name_owner(call_name)
}

fn folded_call_name_receiver_is_instance(
    receiver: &str,
    caller_decl: &Decl,
    super_receiver_tokens: &[&str],
) -> bool {
    let receiver = normalize_receiver_alias_text(receiver);
    let bare = short_callee(&receiver);
    let declared_receiver = caller_decl.implicit_receiver_names.iter().any(|declared| {
        let declared = normalize_receiver_alias_text(declared);
        receiver == declared
            || bare == declared
            || receiver
                .strip_prefix(&declared)
                .is_some_and(|tail| tail.starts_with('.'))
    });
    let declared_super = super_receiver_tokens.iter().any(|declared| {
        let declared = normalize_receiver_alias_text(declared);
        receiver == declared
            || bare == declared
            || receiver
                .strip_prefix(&declared)
                .is_some_and(|tail| tail.starts_with('.'))
    });
    declared_receiver || declared_super
}

fn collect_constructed_return_type_names(
    global: &GlobalIndex,
    _caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    decl: &Decl,
    out: &mut Vec<String>,
) {
    if matches!(decl.kind, DeclKind::Constructor) {
        if let Some(class_decl) = enclosing_class_for_decl(global, decl) {
            push_unique_string(out, class_decl.name.clone());
        }
    }
    if let Some(facts) = global.linkage_facts(decl.symbol) {
        for returned in &facts.returned_constructor_calls {
            for type_name in constructor_type_names_from_call_fact(
                global,
                decl,
                alias_targets,
                &returned.name,
                returned.receiver.as_deref(),
                &returned.receiver_types,
            ) {
                push_unique_string(out, type_name);
            }
        }
    }
    let mut returned_call_sites = AHashSet::new();
    collect_return_expression_call_sites(&decl.flow_events, &mut returned_call_sites);
    collect_returned_constructor_type_names(
        global,
        decl,
        alias_targets,
        &decl.flow_events,
        &returned_call_sites,
        out,
    );
}

fn collect_return_expression_call_sites(events: &[FlowEvent], out: &mut AHashSet<Span>) {
    for event in events {
        match event {
            FlowEvent::Return { value_flow, .. } => out.extend(value_flow.call_sites.iter().copied()),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_return_expression_call_sites(then_events, out);
                collect_return_expression_call_sites(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_return_expression_call_sites(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_return_expression_call_sites(body, out);
                collect_return_expression_call_sites(catch_events, out);
                collect_return_expression_call_sites(finally_events, out);
            }
            _ => {}
        }
    }
}

fn collect_returned_constructor_type_names(
    global: &GlobalIndex,
    decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    events: &[FlowEvent],
    returned_call_sites: &AHashSet<Span>,
    out: &mut Vec<String>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                receiver_types,
                call_kind: CallKind::Constructor,
                ..
            } if returned_call_sites.iter().any(|returned| {
                returned.file == span.file && returned.start <= span.start && span.end <= returned.end
            }) =>
            {
                for type_name in constructor_type_names_from_call_fact(
                    global,
                    decl,
                    alias_targets,
                    name,
                    receiver.as_deref(),
                    receiver_types,
                ) {
                    push_unique_string(out, type_name);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_returned_constructor_type_names(
                    global,
                    decl,
                    alias_targets,
                    then_events,
                    returned_call_sites,
                    out,
                );
                collect_returned_constructor_type_names(
                    global,
                    decl,
                    alias_targets,
                    else_events,
                    returned_call_sites,
                    out,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_returned_constructor_type_names(
                    global,
                    decl,
                    alias_targets,
                    body,
                    returned_call_sites,
                    out,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_returned_constructor_type_names(
                    global,
                    decl,
                    alias_targets,
                    body,
                    returned_call_sites,
                    out,
                );
                collect_returned_constructor_type_names(
                    global,
                    decl,
                    alias_targets,
                    catch_events,
                    returned_call_sites,
                    out,
                );
                collect_returned_constructor_type_names(
                    global,
                    decl,
                    alias_targets,
                    finally_events,
                    returned_call_sites,
                    out,
                );
            }
            _ => {}
        }
    }
}

fn constructor_type_names_from_call_fact<I, S>(
    global: &GlobalIndex,
    context_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    call_name: &str,
    receiver: Option<&str>,
    receiver_types: I,
) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let Some(file) = caller_decl_file(global, context_decl) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(file, &context_decl.module_path).with_alias_map(alias_targets);
    let mut class_symbols = Vec::new();
    let mut seen = AHashSet::new();
    for type_name in receiver_types {
        for class_sym in resolve_class(global, type_name.as_ref(), &ctx) {
            if seen.insert(class_sym) {
                class_symbols.push(class_sym);
            }
        }
    }
    for candidate in receiver.into_iter().chain(std::iter::once(call_name)) {
        for class_sym in resolve_class(global, candidate, &ctx) {
            if seen.insert(class_sym) {
                class_symbols.push(class_sym);
            }
        }
    }
    let implicit_receiver_call = receiver
        .into_iter()
        .chain(std::iter::once(call_name))
        .any(|candidate| {
            context_decl.implicit_receiver_names.iter().any(|declared| {
                normalize_receiver_alias_text(candidate) == normalize_receiver_alias_text(declared)
            })
        });
    if implicit_receiver_call {
        if let Some(class_decl) = enclosing_class_for_decl(global, context_decl) {
            if seen.insert(class_decl.symbol) {
                class_symbols.push(class_decl.symbol);
            }
        }
    }
    let mut out = Vec::new();
    for class_sym in class_symbols {
        if let Some(class_decl) = global.decl_of(class_sym) {
            push_unique_string(&mut out, class_decl.name.clone());
        }
    }
    for func in resolve_callable_with_context(global, call_name, &ctx) {
        let Some(constructor) = global.decl_of(SymbolId::new(func.raw())) else {
            continue;
        };
        if !matches!(constructor.kind, DeclKind::Constructor) {
            continue;
        }
        if let Some(class_decl) = enclosing_class_for_decl(global, constructor) {
            push_unique_string(&mut out, class_decl.name.clone());
        }
    }
    out
}

fn type_alias_for_receiver<'a>(decl: &'a Decl, receiver: &str) -> Option<&'a str> {
    let keys = receiver_alias_keys(decl, receiver);
    decl.type_aliases
        .iter()
        .find(|alias| keys.contains(&alias.name))
        .map(|alias| alias.type_name.as_str())
}

fn receiver_alias_keys(decl: &Decl, receiver: &str) -> Vec<String> {
    let normalized = normalize_receiver_alias_text(receiver);
    let tail = short_callee(&normalized).to_string();
    let mut keys = vec![receiver.to_string(), normalized, tail.clone()];
    for declared in &decl.implicit_receiver_names {
        let declared = normalize_receiver_alias_text(declared);
        if !declared.is_empty() {
            keys.push(format!("{declared}.{tail}"));
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

fn receiver_type_names_for_expr(
    decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    receiver: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(type_name) = type_alias_for_receiver(decl, receiver) {
        push_unique_string(&mut out, type_name.to_string());
    }
    for key in receiver_alias_keys(decl, receiver) {
        if let Some(AliasTarget::Type { type_name }) = alias_targets.get(&key) {
            push_unique_string(&mut out, type_name.clone());
        }
    }
    out
}

fn receiver_class_type_names_for_expr(
    global: &GlobalIndex,
    ctx: &ResolveContext<'_>,
    receiver: &str,
) -> Vec<String> {
    let normalized = normalize_receiver_alias_text(receiver);
    let tail = short_callee(&normalized);
    let mut out = Vec::new();
    for candidate in [receiver.trim(), normalized.as_str(), tail] {
        if candidate.is_empty() {
            continue;
        }
        if !resolve_class(global, candidate, ctx).is_empty() {
            push_unique_string(&mut out, candidate.to_string());
        }
    }
    out
}

fn assigned_receiver_type_names(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    receiver: &str,
    call_span: Option<Span>,
    method_candidate_cache: &mut MethodCandidateCache,
) -> Vec<String> {
    let receiver = normalize_receiver_alias_text(receiver);
    let mut out = Vec::new();
    let mut best_distance = None;
    collect_assigned_receiver_type_names(
        global,
        caller_decl,
        alias_targets,
        &caller_decl.flow_events,
        &receiver,
        call_span,
        method_candidate_cache,
        &mut out,
        &mut best_distance,
    );
    out
}

struct AssignedReceiverNarrowingContext<'a> {
    global: &'a GlobalIndex,
    caller_decl: &'a Decl,
    alias_targets: &'a AHashMap<String, AliasTarget>,
    universal_type_names: &'a [&'a str],
}

fn retain_assigned_receiver_method_candidates(
    context: &AssignedReceiverNarrowingContext<'_>,
    receiver: Option<&str>,
    call_span: Span,
    method_candidate_cache: &mut MethodCandidateCache,
    candidates: &mut Vec<FuncId>,
) {
    if candidates.len() <= 1 {
        return;
    }
    let Some(receiver) = receiver else {
        return;
    };
    let assigned = assigned_receiver_type_names(
        context.global,
        context.caller_decl,
        context.alias_targets,
        receiver,
        Some(call_span),
        method_candidate_cache,
    );
    if assigned.is_empty() {
        return;
    }
    let mut narrowed = Vec::new();
    for func in candidates.iter().copied() {
        let Some(decl) = context.global.decl_of(SymbolId::new(func.raw())) else {
            continue;
        };
        let Some(class_decl) = enclosing_class_for_decl(context.global, decl) else {
            continue;
        };
        if assigned
            .iter()
            .any(|type_name| type_name_matches(type_name, &class_decl.name, context.universal_type_names))
        {
            narrowed.push(func);
        }
    }
    if !narrowed.is_empty() {
        *candidates = narrowed;
    }
}

#[allow(clippy::too_many_arguments)] // mirrors FlowEvent::Call plus caller context
fn retain_semantic_receiver_evidenced_candidates(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    receiver: Option<&str>,
    receiver_types: &[String],
    call_kind: CallKind,
    call_span: Span,
    alias_qualified_call: bool,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    super_receiver_tokens: &[&str],
    module_path_syntax: bonsai_lang_api::ModulePathSyntax,
    method_candidate_cache: &mut MethodCandidateCache,
    candidates: &mut Vec<FuncId>,
) {
    if candidates.is_empty() || call_kind != CallKind::Method || alias_qualified_call {
        return;
    }
    let Some(receiver) = receiver
        .map(normalize_receiver_alias_text)
        .filter(|receiver| !receiver.is_empty())
    else {
        return;
    };
    if is_super_receiver_with_tokens(&receiver, super_receiver_tokens) {
        return;
    }
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        candidates.clear();
        return;
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path)
        .with_alias_map(alias_targets)
        .with_file_path_lookup(path_for_file)
        .with_module_path_syntax(module_path_syntax);
    let mut receiver_class_symbols = semantic_receiver_class_symbols(
        global,
        caller_decl,
        alias_targets,
        &ctx,
        &receiver,
        receiver_types,
        call_span,
        method_candidate_cache,
    );
    dedup_symbols(&mut receiver_class_symbols);
    let receiver_parent_symbols: AHashSet<SymbolId> = receiver_class_symbols
        .iter()
        .flat_map(|class_sym| receiver_class_ancestors(global, *class_sym))
        .collect();
    candidates.retain(|func| {
        let sym = SymbolId::new(func.raw());
        let Some(decl) = global.decl_of(sym) else {
            return false;
        };
        let Some(file) = global.declaring_file(sym) else {
            return false;
        };
        if decl.parent.is_some_and(|method_parent| {
            receiver_parent_symbols.contains(&method_parent)
                || receiver_parent_symbols.iter().any(|receiver_parent| {
                    class_symbols_share_semantic_identity(global, *receiver_parent, method_parent)
                })
        }) {
            return true;
        }
        receiver_matches_decl_module(&receiver, decl, file, path_for_file, module_path_syntax)
    });
}

#[allow(clippy::too_many_arguments)] // Semantic narrowing carries caller, alias, type, span, and cache context.
fn semantic_receiver_class_symbols(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    ctx: &ResolveContext<'_>,
    receiver: &str,
    receiver_types: &[String],
    call_span: Span,
    method_candidate_cache: &mut MethodCandidateCache,
) -> Vec<SymbolId> {
    let mut type_names = assigned_receiver_type_names(
        global,
        caller_decl,
        alias_targets,
        receiver,
        Some(call_span),
        method_candidate_cache,
    );
    for type_name in receiver_types {
        push_unique_string(&mut type_names, type_name.clone());
    }
    for type_name in receiver_type_names_for_expr(caller_decl, alias_targets, receiver) {
        push_unique_string(&mut type_names, type_name);
    }
    for type_name in receiver_class_type_names_for_expr(global, ctx, receiver) {
        push_unique_string(&mut type_names, type_name);
    }
    for type_name in receiver_call_return_type_names(
        global,
        caller_decl,
        alias_targets,
        receiver,
        Some(call_span),
        method_candidate_cache,
    ) {
        push_unique_string(&mut type_names, type_name);
    }
    let mut out = Vec::new();
    for type_name in type_names {
        out.extend(resolve_class(global, &type_name, ctx));
    }
    out.extend(resolve_class(global, receiver, ctx));
    out
}

fn receiver_matches_decl_module(
    receiver: &str,
    decl: &Decl,
    file: FileId,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    module_path_syntax: bonsai_lang_api::ModulePathSyntax,
) -> bool {
    module_target_exactly_matches_decl_module_path_with_syntax(
        receiver,
        &decl.module_path,
        module_path_syntax,
    ) || path_for_file(file).is_some_and(|path| {
        module_target_matches_path(strip_module_path_prefix(receiver, module_path_syntax), &path)
    })
}

fn receiver_class_ancestors(global: &GlobalIndex, receiver_class: SymbolId) -> AHashSet<SymbolId> {
    let mut out = AHashSet::new();
    let mut seen = AHashSet::new();
    let mut stack = vec![receiver_class];
    while let Some(class_sym) = stack.pop() {
        if !seen.insert(class_sym) {
            continue;
        }
        out.insert(class_sym);
        let Some(class_decl) = global.decl_of(class_sym) else {
            continue;
        };
        let Some(class_file) = global.declaring_file(class_sym) else {
            continue;
        };
        let base_ctx = ResolveContext::new(class_file, &class_decl.module_path);
        for base in &class_decl.bases {
            for base_sym in resolve_class(global, base, &base_ctx) {
                stack.push(base_sym);
            }
        }
    }
    out
}

fn retain_assigned_receiver_constructor_candidates(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    assign_span: &Span,
    universal_type_names: &[&str],
    method_candidate_cache: &mut MethodCandidateCache,
    candidates: &mut Vec<FuncId>,
) {
    if candidates.len() <= 1 {
        return;
    }
    let assigned = assigned_receiver_type_names(
        global,
        caller_decl,
        alias_targets,
        "",
        Some(*assign_span),
        method_candidate_cache,
    );
    if assigned.is_empty() {
        return;
    }
    let mut narrowed = Vec::new();
    for func in candidates.iter().copied() {
        let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
            continue;
        };
        if !matches!(decl.kind, DeclKind::Constructor) {
            continue;
        }
        let Some(class_decl) = enclosing_class_for_decl(global, decl) else {
            continue;
        };
        if assigned
            .iter()
            .any(|type_name| type_name_matches(type_name, &class_decl.name, universal_type_names))
        {
            narrowed.push(func);
        }
    }
    if !narrowed.is_empty() {
        *candidates = narrowed;
    }
}

#[allow(clippy::too_many_arguments)] // Recursive flow-event walk carries shared receiver-search state.
fn collect_assigned_receiver_type_names(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    events: &[FlowEvent],
    receiver: &str,
    call_span: Option<Span>,
    method_candidate_cache: &mut MethodCandidateCache,
    out: &mut Vec<String>,
    best_distance: &mut Option<u64>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_call,
                source_name,
                source_names,
                span,
                ..
            } => {
                if call_span.is_some_and(|call_span| span.start > call_span.start) {
                    continue;
                }
                if !receiver.is_empty() && !normalized_receiver_alias_matches(target, receiver) {
                    continue;
                }
                let distance = call_span.map(|call_span| call_span.start.saturating_sub(span.start));
                if let Some(source_call) = source_call {
                    for type_name in receiver_call_return_type_names(
                        global,
                        caller_decl,
                        alias_targets,
                        &format!("{source_call}()"),
                        Some(*span),
                        method_candidate_cache,
                    ) {
                        push_assigned_receiver_type(out, best_distance, type_name, distance);
                    }
                    // Some adapters encode a direct class construction only
                    // on the assignment (`x = DeclaredType(...)`) without a
                    // nested Call event. Resolve the source call against the
                    // global class index; exact declaration identity, not
                    // spelling or casing, proves the result type.
                    for type_name in constructor_type_names_from_call_fact(
                        global,
                        caller_decl,
                        alias_targets,
                        source_call,
                        None,
                        std::iter::empty::<&str>(),
                    ) {
                        push_assigned_receiver_type(out, best_distance, type_name, distance);
                    }
                }
                for candidate in source_call
                    .iter()
                    .chain(source_name.iter())
                    .chain(source_names.iter())
                {
                    for type_name in type_names_for_binding(global, caller_decl, candidate) {
                        push_assigned_receiver_type(out, best_distance, type_name, distance);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assigned_receiver_type_names(
                    global,
                    caller_decl,
                    alias_targets,
                    then_events,
                    receiver,
                    call_span,
                    method_candidate_cache,
                    out,
                    best_distance,
                );
                collect_assigned_receiver_type_names(
                    global,
                    caller_decl,
                    alias_targets,
                    else_events,
                    receiver,
                    call_span,
                    method_candidate_cache,
                    out,
                    best_distance,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_assigned_receiver_type_names(
                    global,
                    caller_decl,
                    alias_targets,
                    body,
                    receiver,
                    call_span,
                    method_candidate_cache,
                    out,
                    best_distance,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assigned_receiver_type_names(
                    global,
                    caller_decl,
                    alias_targets,
                    body,
                    receiver,
                    call_span,
                    method_candidate_cache,
                    out,
                    best_distance,
                );
                collect_assigned_receiver_type_names(
                    global,
                    caller_decl,
                    alias_targets,
                    catch_events,
                    receiver,
                    call_span,
                    method_candidate_cache,
                    out,
                    best_distance,
                );
                collect_assigned_receiver_type_names(
                    global,
                    caller_decl,
                    alias_targets,
                    finally_events,
                    receiver,
                    call_span,
                    method_candidate_cache,
                    out,
                    best_distance,
                );
            }
            _ => {}
        }
    }
}

fn push_assigned_receiver_type(
    out: &mut Vec<String>,
    best_distance: &mut Option<u64>,
    type_name: String,
    distance: Option<u64>,
) {
    if let Some(distance) = distance {
        match *best_distance {
            Some(best) if distance > best => return,
            Some(best) if distance < best => {
                out.clear();
                *best_distance = Some(distance);
            }
            None => {
                *best_distance = Some(distance);
            }
            _ => {}
        }
    }
    push_unique_string(out, type_name);
}

fn alias_targets_for_decl(
    file_alias_targets: &AHashMap<String, AliasTarget>,
    decl: &Decl,
) -> AHashMap<String, AliasTarget> {
    let mut map = file_alias_targets.clone();
    extend_alias_targets_with_declared_types(&mut map, &decl.type_aliases);
    bonsai_lang_api::extend_alias_map_with_flow_events(&mut map, &decl.flow_events);
    map
}

/// Receiver-alias normalisation used at callgraph build time.
/// Strips outer parentheses (`(repo).run()` → `repo.run()`),
/// identifier/reference sigils (`$value`, `@items`, `&str`, `*ptr`),
/// and rewrites C/C++/PHP `->` member access to `.` form.
///
/// Intentionally simpler than `bonsai_taint::text::normalise_qualified_text`
/// — the taint engine's variant additionally handles bracket-depth-
/// aware string-literal masking and subscript rewriting (`obj['k']`
/// → `obj.k`) because it normalises arbitrary FlowEvent expression
/// texts. Callgraph's input is the structured `FlowEvent::Call.callee`
/// or `Call.receiver` field, which the adapter has already split out
/// of any subscript expression — so the simpler helper covers every
/// real shape that reaches edge construction.
fn normalize_receiver_alias_text(receiver: &str) -> String {
    let mut text = receiver.trim();
    while text.starts_with('(') && text.ends_with(')') && text.len() > 1 {
        text = text[1..text.len() - 1].trim();
    }
    bonsai_common::normalize_qualified_name(text.trim_start_matches(bonsai_common::is_name_punctuation))
        .trim()
        .trim_matches('.')
        .to_string()
}

/// Allocation-free equivalent of
/// `normalize_receiver_alias_text(candidate) == expected`, where
/// `expected` is an already-normalized alias key. The recursive
/// per-event walkers (`local_value_binding_shadows_callable`,
/// `collect_assigned_receiver_type_names`) run once per call site and
/// visit every flow event in the enclosing function, so normalizing each
/// assignment target into a fresh `String` is an O(calls × assignments)
/// allocation storm on large functions. This mirrors the normalizer's
/// trim/paren/punctuation steps over borrowed slices and only falls back to
/// structural qualified-name normalization when the borrowed form differs.
fn normalized_receiver_alias_matches(candidate: &str, expected: &str) -> bool {
    let mut text = candidate.trim();
    while text.starts_with('(') && text.ends_with(')') && text.len() > 1 {
        text = text[1..text.len() - 1].trim();
    }
    let normalized = text
        .trim_start_matches(bonsai_common::is_name_punctuation)
        .trim()
        .trim_matches('.');
    normalized == expected || bonsai_common::normalize_qualified_name(normalized) == expected
}

fn caller_decl_file(global: &GlobalIndex, caller_decl: &Decl) -> Option<FileId> {
    global.declaring_file(caller_decl.symbol)
}

fn retain_same_language_candidates(
    global: &GlobalIndex,
    caller_language: Option<&'static str>,
    language_for_file: &dyn Fn(FileId) -> Option<&'static str>,
    candidates: &mut Vec<FuncId>,
) {
    candidates.retain(|func| func_language_matches(global, caller_language, language_for_file, *func));
}

fn func_language_matches(
    global: &GlobalIndex,
    caller_language: Option<&'static str>,
    language_for_file: &dyn Fn(FileId) -> Option<&'static str>,
    func: FuncId,
) -> bool {
    let Some(caller_language) = caller_language else {
        return true;
    };
    let Some(file) = global.declaring_file(SymbolId::new(func.raw())) else {
        return true;
    };
    let Some(callee_language) = language_for_file(file) else {
        return true;
    };
    caller_language == callee_language
}

fn retain_local_scope_candidates_when_present(
    global: &GlobalIndex,
    caller_decl: &Decl,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    candidates: &mut Vec<FuncId>,
) {
    if retain_same_module_candidates_when_present(global, caller_decl, candidates) {
        return;
    }
    retain_same_directory_candidates_when_present(global, caller_decl, path_for_file, candidates);
}

fn retain_same_module_candidates_when_present(
    global: &GlobalIndex,
    caller_decl: &Decl,
    candidates: &mut Vec<FuncId>,
) -> bool {
    if candidates.len() <= 1 || caller_decl.module_path.is_empty() {
        return false;
    }
    let same_module = candidates
        .iter()
        .filter(|func| {
            global
                .decl_of(SymbolId::new(func.raw()))
                .is_some_and(|decl| decl.module_path.matches(&caller_decl.module_path))
        })
        .count();
    if same_module == 0 || same_module == candidates.len() {
        return false;
    }
    candidates.retain(|func| {
        global
            .decl_of(SymbolId::new(func.raw()))
            .is_some_and(|decl| decl.module_path.matches(&caller_decl.module_path))
    });
    true
}

fn retain_same_directory_candidates_when_present(
    global: &GlobalIndex,
    caller_decl: &Decl,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    candidates: &mut Vec<FuncId>,
) -> bool {
    if candidates.len() <= 1 {
        return false;
    }
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return false;
    };
    let Some(caller_path) = path_for_file(caller_file) else {
        return false;
    };
    let Some(caller_dir) = parent_dir_key(&caller_path) else {
        return false;
    };

    let same_directory = candidates
        .iter()
        .filter(|func| candidate_in_directory(global, path_for_file, **func, caller_dir.as_str()))
        .count();
    if same_directory == 0 || same_directory == candidates.len() {
        return false;
    }
    candidates.retain(|func| candidate_in_directory(global, path_for_file, *func, caller_dir.as_str()));
    true
}

fn candidate_in_directory(
    global: &GlobalIndex,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    func: FuncId,
    directory: &str,
) -> bool {
    let Some(file) = global.declaring_file(SymbolId::new(func.raw())) else {
        return false;
    };
    let Some(path) = path_for_file(file) else {
        return false;
    };
    parent_dir_key(&path).is_some_and(|candidate_dir| candidate_dir == directory)
}

fn parent_dir_key(path: &str) -> Option<String> {
    let parent = Path::new(path.trim()).parent()?;
    let rendered = parent.to_string_lossy();
    if rendered.is_empty() {
        return None;
    }
    Some(rendered.into_owned())
}

fn qualified_alias_target_tail<'a>(
    name: &'a str,
    aliases: &'a AHashMap<String, String>,
) -> Option<(&'a str, &'a str)> {
    let (head, tail) = split_qualified_head_tail(name)?;
    aliases.get(head).map(String::as_str).map(|target| (target, tail))
}

fn qualified_alias_target_entry_tail<'a>(
    name: &'a str,
    alias_targets: &'a AHashMap<String, AliasTarget>,
) -> Option<(&'a AliasTarget, &'a str)> {
    let (head, tail) = split_qualified_head_tail(name)?;
    if tail.is_empty() {
        return None;
    }
    alias_targets.get(head).map(|target| (target, tail))
}

fn qualified_workspace_target_tail(name: &str) -> Option<(&str, &str)> {
    bonsai_common::split_qualified_name_owner_tail(name)
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
/// Resolve a `module.fn` call where `module` is a local alias for a
/// workspace file or package. Returns every workspace function that
/// (a) has a name matching `alias_tail` (or one of the language's
/// export-alias prefixes), and (b) lives in a file whose path
/// matches the alias target.
fn collect_workspace_module_targets(
    global: &GlobalIndex,
    alias_target: &str,
    alias_tail: &str,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    file_path_parts: &AHashMap<FileId, Vec<String>>,
    caller_capabilities: LanguageCapabilities,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    workspace_module_cache: &mut WorkspaceModuleTargetCache,
    allow_terminal_trailer: bool,
) -> Vec<FuncId> {
    if alias_target.is_empty() || alias_tail.is_empty() {
        return Vec::new();
    }
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let cache_key = WorkspaceModuleTargetKey::new(
        alias_target,
        alias_tail,
        caller_file,
        &caller_decl.module_path,
        allow_terminal_trailer,
    );
    if let Some(cached) = workspace_module_cache.targets.get(&cache_key) {
        return cached.clone();
    }
    let caller_ctx = ResolveContext::new(caller_file, &caller_decl.module_path)
        .with_alias_map(alias_targets)
        .with_module_path_syntax(caller_capabilities.module_path_syntax);
    let mut seen_spans = AHashSet::new();
    let mut targets = Vec::new();
    for func in export_name_variants(alias_tail, caller_capabilities.module_export_aliases)
        .into_iter()
        .flat_map(|name| collect_callable_targets(global, &name))
    {
        let sym = SymbolId::new(func.raw());
        let Some(file) = global.declaring_file(sym) else {
            continue;
        };
        let Some(decl) = global.decl_of(sym) else {
            continue;
        };
        if !visibility_allows(decl, file, &decl.module_path, &caller_ctx) {
            continue;
        }
        // Module-namespace match: prefer the decl's canonical
        // `module_path` (the adapter's semantic-identity fact) before
        // falling back to file-path heuristics. Required for
        // languages whose modules and files use different
        // conventions — Elixir's `MyApp.AuthService` vs.
        // `my_app/auth_service.ex` is the canonical example: the
        // file-path match would silently miss the cross-module
        // edge. The semantic match is always sufficient when
        // adapters populate `module_path`.
        let semantic_match = if allow_terminal_trailer {
            module_target_matches_decl_module_path_with_syntax(
                alias_target,
                &decl.module_path,
                caller_capabilities.module_path_syntax,
            )
        } else {
            module_target_exactly_matches_decl_module_path_with_syntax(
                alias_target,
                &decl.module_path,
                caller_capabilities.module_path_syntax,
            )
        };
        let path_target = strip_module_path_prefix(alias_target, caller_capabilities.module_path_syntax);
        let in_target_file = semantic_match
            || workspace_module_cache.path_matches(path_target, file, file_path_parts, path_for_file);
        if !in_target_file {
            continue;
        }
        if seen_spans.insert((file, decl.span.start, decl.span.end)) {
            targets.push(func);
        }
    }
    workspace_module_cache.targets.insert(cache_key, targets.clone());
    targets
}

#[allow(clippy::too_many_arguments)] // mirrors collect_workspace_module_targets
fn collect_workspace_targets_for_alias_entry(
    global: &GlobalIndex,
    alias_target: &AliasTarget,
    alias_tail: &str,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    file_path_parts: &AHashMap<FileId, Vec<String>>,
    caller_capabilities: LanguageCapabilities,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    workspace_module_cache: &mut WorkspaceModuleTargetCache,
) -> Vec<FuncId> {
    match alias_target {
        AliasTarget::Namespace { module } => collect_workspace_module_targets(
            global,
            module,
            alias_tail,
            path_for_file,
            file_path_parts,
            caller_capabilities,
            caller_decl,
            alias_targets,
            workspace_module_cache,
            true,
        ),
        AliasTarget::Member { module, member } => {
            let mut targets = collect_workspace_module_targets(
                global,
                module,
                alias_tail,
                path_for_file,
                file_path_parts,
                caller_capabilities,
                caller_decl,
                alias_targets,
                workspace_module_cache,
                true,
            );
            if targets.is_empty() {
                targets = collect_workspace_module_targets(
                    global,
                    member,
                    alias_tail,
                    path_for_file,
                    file_path_parts,
                    caller_capabilities,
                    caller_decl,
                    alias_targets,
                    workspace_module_cache,
                    true,
                );
            }
            targets
        }
        AliasTarget::Type { .. } => Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)] // shared resolver helper mirrors build inputs
fn collect_qualified_workspace_targets(
    global: &GlobalIndex,
    name: &str,
    aliases: Option<&AHashMap<String, String>>,
    alias_targets: &AHashMap<String, AliasTarget>,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    file_path_parts: &AHashMap<FileId, Vec<String>>,
    caller_capabilities: LanguageCapabilities,
    caller_decl: &Decl,
    workspace_module_cache: &mut WorkspaceModuleTargetCache,
) -> Vec<FuncId> {
    if let Some(alias_target) = alias_targets.get(name) {
        let alias_tails: Vec<&str> = match alias_target {
            AliasTarget::Namespace { .. } => caller_capabilities.module_default_export_names.to_vec(),
            AliasTarget::Member { member, .. } => vec![member.as_str()],
            AliasTarget::Type { .. } => Vec::new(),
        };
        let mut candidates = Vec::new();
        for alias_tail in alias_tails {
            candidates.extend(collect_workspace_targets_for_alias_entry(
                global,
                alias_target,
                alias_tail,
                path_for_file,
                file_path_parts,
                caller_capabilities,
                caller_decl,
                alias_targets,
                workspace_module_cache,
            ));
        }
        dedup_func_ids(&mut candidates);
        if !candidates.is_empty() {
            return candidates;
        }
    }
    if let Some((alias_target, alias_tail)) = namespace_alias_target_tail(name, alias_targets) {
        let candidates = collect_workspace_module_targets(
            global,
            alias_target,
            alias_tail,
            path_for_file,
            file_path_parts,
            caller_capabilities,
            caller_decl,
            alias_targets,
            workspace_module_cache,
            true,
        );
        if !candidates.is_empty() {
            return candidates;
        }
    }
    if let Some((alias_target, alias_tail)) = qualified_alias_target_entry_tail(name, alias_targets) {
        let candidates = collect_workspace_targets_for_alias_entry(
            global,
            alias_target,
            alias_tail,
            path_for_file,
            file_path_parts,
            caller_capabilities,
            caller_decl,
            alias_targets,
            workspace_module_cache,
        );
        if !candidates.is_empty() {
            return candidates;
        }
    }
    if let Some((alias_target, alias_tail)) =
        aliases.and_then(|aliases| qualified_alias_target_tail(name, aliases))
    {
        let candidates = collect_workspace_module_targets(
            global,
            alias_target,
            alias_tail,
            path_for_file,
            file_path_parts,
            caller_capabilities,
            caller_decl,
            alias_targets,
            workspace_module_cache,
            true,
        );
        if !candidates.is_empty() {
            return candidates;
        }
    }
    if let Some((module_target, module_tail)) = qualified_workspace_target_tail(name) {
        let candidates = collect_workspace_module_targets(
            global,
            module_target,
            module_tail,
            path_for_file,
            file_path_parts,
            caller_capabilities,
            caller_decl,
            alias_targets,
            workspace_module_cache,
            false,
        );
        if !candidates.is_empty() {
            return candidates;
        }
    }
    Vec::new()
}

// `module_target_matches_decl_module_path` lives in
// `bonsai_resolve` and is re-used here so callgraph and taint
// share the same canonical match. See `bonsai_resolve` for the
// suffix-aware semantic.

// Path / module-shape helpers live in `bonsai_resolve` so the
// callgraph and taint engine share one source of truth.

/// Resolve `name` against the global index and return every matching
/// callable (function, method, constructor) as a [`FuncId`]. Empty
/// when the name doesn't match any declared function in the workspace.
///
/// **Display-only.** Bypasses caller `Visibility` / `module_path`
/// narrowing and may return cross-TU collisions
/// (`docs/contributing/design-patterns.mdx::Semantic Resolution Always`). Reserve
/// for browse/dump/inspect display paths that already enumerate
/// every name match by design. Graph-construction paths must use
/// [`collect_callable_targets_with_context`].
pub fn collect_callable_targets(global: &GlobalIndex, name: &str) -> Vec<FuncId> {
    collect_callable_targets_exact(global, name)
}

/// Caller-context-aware version of [`collect_callable_targets`]. Use
/// this from any path that builds graph edges, taint edges, or
/// findings. Returns empty when caller context is unavailable so the
/// caller can treat the call as external — see
/// `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
pub fn collect_callable_targets_with_context(
    global: &GlobalIndex,
    name: &str,
    caller_decl: &Decl,
) -> Vec<FuncId> {
    collect_callable_targets_with_context_and_aliases(global, name, caller_decl, &AHashMap::new())
}

pub fn collect_callable_targets_with_context_and_aliases(
    global: &GlobalIndex,
    name: &str,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> Vec<FuncId> {
    let mut callable_target_cache = CallableTargetCache::default();
    let path_for_file = |_| None;
    let file_path_parts = AHashMap::new();
    collect_callable_targets_with_context_aliases_and_paths(
        global,
        name,
        caller_decl,
        CallableLookupSemantics {
            alias_targets,
            path_for_file: &path_for_file,
            file_path_parts: &file_path_parts,
            same_directory_unqualified_calls: false,
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
        },
        &mut callable_target_cache,
    )
}

fn collect_callable_targets_with_context_aliases_and_paths(
    global: &GlobalIndex,
    name: &str,
    caller_decl: &Decl,
    semantics: CallableLookupSemantics<'_>,
    callable_target_cache: &mut CallableTargetCache,
) -> Vec<FuncId> {
    let mut method_candidate_cache = MethodCandidateCache::default();
    collect_callable_targets_with_context_aliases_paths_and_method_cache(
        global,
        name,
        caller_decl,
        semantics,
        callable_target_cache,
        &mut method_candidate_cache,
    )
}

fn collect_callable_targets_with_context_aliases_paths_and_method_cache(
    global: &GlobalIndex,
    name: &str,
    caller_decl: &Decl,
    semantics: CallableLookupSemantics<'_>,
    callable_target_cache: &mut CallableTargetCache,
    method_candidate_cache: &mut MethodCandidateCache,
) -> Vec<FuncId> {
    let CallableLookupSemantics {
        alias_targets,
        path_for_file,
        file_path_parts,
        same_directory_unqualified_calls,
        module_path_syntax,
    } = semantics;
    let mut targets = collect_implicit_receiver_method_targets(
        global,
        caller_decl,
        name,
        alias_targets,
        path_for_file,
        method_candidate_cache,
    );
    if !targets.is_empty() {
        return targets;
    }
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let key = CallableTargetKey::new(name, caller_file, &caller_decl.module_path);
    if let Some(cached) = callable_target_cache.targets.get(&key) {
        return cached.clone();
    }
    {
        let path_match_cache = std::cell::RefCell::new(&mut *callable_target_cache);
        let path_matches = |target_module: &str, file: FileId| {
            path_match_cache
                .borrow_mut()
                .path_matches(target_module, file, file_path_parts, path_for_file)
        };
        let ctx = ResolveContext::new(caller_file, &caller_decl.module_path)
            .with_alias_map(alias_targets)
            .with_file_path_lookup(path_for_file)
            .with_same_directory_unqualified_calls(same_directory_unqualified_calls)
            .with_module_path_syntax(module_path_syntax)
            .with_file_path_match_lookup(&path_matches);
        targets = resolve_callable_with_context(global, name, &ctx);
    }
    callable_target_cache.targets.insert(key, targets.clone());
    targets
}

fn collect_build_target_linked_callable_targets(
    global: &GlobalIndex,
    name: &str,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    build_targets: &BuildTargetIndex,
) -> Vec<FuncId> {
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(alias_targets);
    let mut targets = collect_callable_targets(global, name);
    targets.retain(|func| {
        let sym = SymbolId::new(func.raw());
        let Some(decl) = global.decl_of(sym) else {
            return false;
        };
        let Some(file) = global.declaring_file(sym) else {
            return false;
        };
        visibility_allows(decl, file, &decl.module_path, &ctx)
    });
    build_targets.retain_candidates_linked_with(global, caller_file, &mut targets);
    targets
}

/// Resolve a method invoked on an untyped function parameter when adapter
/// declaration facts still prove a unique local method target.
///
/// This is deliberately narrower than a bare method-name fallback: the
/// receiver must be a declared parameter, the candidate must be the sole
/// `DeclKind::Method` declaration with that name in the caller's own file.
/// This uses adapter-emitted semantic kinds instead of a language-name table
/// and does not connect an opaque receiver to a same-named function elsewhere
/// in the workspace.
fn collect_dynamic_param_receiver_method_target(
    global: &GlobalIndex,
    caller_decl: &Decl,
    receiver: Option<&str>,
    name: &str,
) -> Vec<FuncId> {
    let Some(receiver) = receiver else {
        return Vec::new();
    };
    let receiver = normalize_receiver_alias_text(receiver);
    if receiver.is_empty()
        || !caller_decl
            .params
            .iter()
            .any(|param| normalized_receiver_alias_matches(param, &receiver))
    {
        return Vec::new();
    }
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let method_name = short_callee(name);
    let mut candidates = global
        .decls_in(caller_file)
        .iter()
        .filter(|decl| decl.name == method_name && matches!(decl.kind, DeclKind::Method))
        .map(|decl| FuncId::new(decl.symbol.raw()))
        .collect::<Vec<_>>();
    dedup_func_ids(&mut candidates);
    if candidates.len() == 1 {
        candidates
    } else {
        Vec::new()
    }
}

fn collect_implicit_receiver_method_targets(
    global: &GlobalIndex,
    caller_decl: &Decl,
    name: &str,
    alias_targets: &AHashMap<String, AliasTarget>,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    method_cache: &mut MethodCandidateCache,
) -> Vec<FuncId> {
    if caller_decl.implicit_receiver_names.is_empty() {
        return Vec::new();
    }
    if !implicit_receiver_call_name(name) {
        return Vec::new();
    }
    let Some(parent) = caller_decl.parent else {
        return Vec::new();
    };
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path)
        .with_alias_map(alias_targets)
        .with_file_path_lookup(path_for_file);
    let mut targets = Vec::new();
    let mut seen = AHashSet::new();
    collect_method_candidates_for_class_cached(
        global,
        parent,
        name,
        &ctx,
        &mut seen,
        &mut targets,
        method_cache,
    );
    targets
}

fn implicit_receiver_call_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty() && bonsai_common::qualified_name_owner(trimmed).is_none()
}

#[allow(clippy::too_many_arguments)] // Public resolver hook mirrors FlowEvent::Call plus workspace callbacks.
pub fn collect_call_event_targets_with_context_and_aliases(
    global: &GlobalIndex,
    name: &str,
    receiver: Option<&str>,
    receiver_types: &[String],
    call_kind: CallKind,
    call_span: Span,
    args: &[CallArg],
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    caller_export_aliases: &'static [&'static str],
) -> Vec<FuncId> {
    collect_call_event_targets_with_context_aliases_and_super_tokens(
        global,
        name,
        receiver,
        receiver_types,
        call_kind,
        call_span,
        args,
        caller_decl,
        alias_targets,
        path_for_file,
        caller_export_aliases,
        &[],
        &[],
    )
}

#[allow(clippy::too_many_arguments)] // Public resolver hook mirrors FlowEvent::Call plus workspace callbacks.
pub fn collect_call_event_targets_with_context_aliases_and_super_tokens(
    global: &GlobalIndex,
    name: &str,
    receiver: Option<&str>,
    receiver_types: &[String],
    call_kind: CallKind,
    call_span: Span,
    args: &[CallArg],
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    caller_export_aliases: &'static [&'static str],
    caller_default_export_names: &'static [&'static str],
    caller_super_receiver_tokens: &'static [&'static str],
) -> Vec<FuncId> {
    let caller_capabilities = LanguageCapabilities {
        module_export_aliases: caller_export_aliases,
        module_default_export_names: caller_default_export_names,
        super_receiver_tokens: caller_super_receiver_tokens,
        ..LanguageCapabilities::unsupported()
    };
    let folded_receiver = receiver_name_from_call_name(name).filter(|candidate| {
        folded_call_name_receiver_is_instance(candidate, caller_decl, caller_super_receiver_tokens)
    });
    let semantic_receiver = receiver.or(folded_receiver);
    let explicit_ancestor_constructor = call_kind == CallKind::Constructor
        && semantic_receiver
            .is_some_and(|receiver| is_super_receiver_with_tokens(receiver, caller_super_receiver_tokens));
    let local_value_shadow = semantic_receiver.is_none()
        && local_value_binding_shadows_callable(&caller_decl.flow_events, name, call_span);
    let mut targets = if semantic_receiver.is_none() {
        collect_nested_local_callable_targets(global, caller_decl, name, call_span)
    } else {
        Vec::new()
    };
    let mut method_candidate_cache = MethodCandidateCache::default();
    let mut workspace_module_cache = WorkspaceModuleTargetCache::default();
    let mut callable_target_cache = CallableTargetCache::default();
    let file_path_parts: AHashMap<FileId, Vec<String>> = AHashMap::new();
    let lookup_semantics = CallableLookupSemantics {
        alias_targets,
        path_for_file,
        file_path_parts: &file_path_parts,
        same_directory_unqualified_calls: false,
        module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
    };
    let constructor_context = ConstructorResolutionContext {
        global,
        caller_decl,
        alias_targets,
        path_for_file,
        constructor_index: None,
    };
    if targets.is_empty() && explicit_ancestor_constructor {
        targets = collect_constructor_targets_for_class_call(&constructor_context, name, None, &[], false);
    }
    if targets.is_empty() && call_kind == CallKind::Constructor {
        targets = collect_constructor_targets_for_class_call(
            &constructor_context,
            name,
            receiver,
            receiver_types,
            false,
        );
    }
    if targets.is_empty() {
        targets = collect_receiver_method_targets(
            global,
            caller_decl,
            alias_targets,
            path_for_file,
            semantic_receiver,
            receiver_types,
            call_kind,
            name,
            call_span,
            caller_super_receiver_tokens,
            &mut method_candidate_cache,
        );
    }
    if targets.is_empty() {
        targets = collect_type_qualified_method_targets(
            global,
            caller_decl,
            alias_targets,
            path_for_file,
            name,
            &mut method_candidate_cache,
        );
    }
    if targets.is_empty()
        && semantic_receiver.is_none()
        && !local_value_shadow
        && fast_local_callable_reference_name(name)
    {
        targets = collect_callable_targets_with_context_aliases_and_paths(
            global,
            name,
            caller_decl,
            lookup_semantics,
            &mut callable_target_cache,
        );
    }
    let typed_receiver_method = semantic_receiver.is_some() && !receiver_types.is_empty();
    if targets.is_empty() && !typed_receiver_method {
        targets = collect_qualified_workspace_targets(
            global,
            name,
            None,
            alias_targets,
            path_for_file,
            &file_path_parts,
            caller_capabilities,
            caller_decl,
            &mut workspace_module_cache,
        );
    }
    let unresolved_method_receiver =
        targets.is_empty() && call_kind == CallKind::Method && semantic_receiver.is_some();
    if targets.is_empty() && !unresolved_method_receiver && !local_value_shadow {
        targets = collect_callable_targets_with_context_aliases_and_paths(
            global,
            name,
            caller_decl,
            lookup_semantics,
            &mut callable_target_cache,
        );
    }
    if targets.is_empty() && !unresolved_method_receiver && !local_value_shadow {
        let short = short_callee(name);
        // For Rust-style `Type::method` qualified calls, allow the
        // bare-tail fallback ONLY when the qualifier resolves to
        // an in-workspace alias. See the matching guard at the
        // build-time call site above for the full rationale.
        let allow_short_fallback = if let Some(idx) = name.find("::") {
            // Standalone resolver consumers still route through this entry and
            // doesn't share the callgraph build's WorkspaceAliasIndex, so we
            // build a local one. Build it lazily inside this `::` arm only:
            // the no-qualifier majority (the `else` below) never consults it,
            // and an unconditional per-call-site build is the rewalk pattern
            // the project forbids.
            let local_alias_index = WorkspaceAliasIndex::build(global);
            let qualifier = &name[..idx];
            alias_targets
                .get(qualifier)
                .map(|t| match t {
                    AliasTarget::Namespace { module } => is_workspace_alias_target(
                        &local_alias_index,
                        module,
                        caller_capabilities.module_path_syntax,
                    ),
                    AliasTarget::Member { module, member } => {
                        is_workspace_alias_target(
                            &local_alias_index,
                            module,
                            caller_capabilities.module_path_syntax,
                        ) || is_workspace_alias_target(
                            &local_alias_index,
                            member,
                            caller_capabilities.module_path_syntax,
                        )
                    }
                    AliasTarget::Type { .. } => true,
                })
                .unwrap_or(false)
        } else {
            true
        };
        if targets.is_empty() && short != name && allow_short_fallback {
            targets = collect_callable_targets_with_context_aliases_and_paths(
                global,
                short,
                caller_decl,
                lookup_semantics,
                &mut callable_target_cache,
            );
        }
    }
    if !targets.is_empty() {
        let assigned_receiver_context = AssignedReceiverNarrowingContext {
            global,
            caller_decl,
            alias_targets,
            universal_type_names: &[],
        };
        retain_assigned_receiver_method_candidates(
            &assigned_receiver_context,
            semantic_receiver,
            call_span,
            &mut method_candidate_cache,
            &mut targets,
        );
        let receiver_supplied = semantic_receiver.is_some() || call_kind == CallKind::Method;
        retain_signature_compatible_candidates(
            global,
            caller_decl,
            &mut targets,
            args,
            receiver_supplied,
            &[],
        );
    }
    retain_call_kind_compatible_candidates(global, call_kind, &mut targets);
    dedup_func_ids(&mut targets);
    dedup_semantic_candidate_decls(global, &mut targets);
    targets
}

fn collect_callable_targets_exact(global: &GlobalIndex, name: &str) -> Vec<FuncId> {
    global
        // CONTEXTLESS_LOOKUP_JUSTIFICATION: display-only helper for
        // callers that intentionally enumerate every matching name;
        // callgraph construction uses collect_callable_targets_with_context.
        .find_by_name(name)
        .iter()
        .filter_map(|symbol| {
            global.decl_of(*symbol).and_then(|decl| {
                if matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) {
                    Some(FuncId::new(symbol.raw()))
                } else {
                    None
                }
            })
        })
        .collect()
}

/// Tail of a qualified call name. `"a.b.c"` → `"c"`; `"std::fs::read"`
/// → `"read"`; `"a->b"` → `"b"`. A plain identifier is returned
/// unchanged. Public so the resolver and inspect filter use the same
/// short-name semantics.
#[must_use]
pub fn short_callee(name: &str) -> &str {
    short_qualified_tail(name)
}

/// Precomputed index used by [`is_workspace_alias_target`] so the
/// `Type::method` short-tail gate doesn't pay an O(decls) scan per
/// call site. The two sets are built once per callgraph build (or
/// once per `resolve_callable_symbol` call when entered standalone)
/// and trusted across every alias lookup inside that pass.
///
/// * `class_names` — every class-like type decl's bare name
///   (`Class`/`Struct`/`Trait`/`Interface`/`Enum`). Covers
///   `AliasTarget::Type` rebindings (`let r: Repository`) and
///   Rust-style `Foo::method` where `Foo` is a user struct, trait,
///   or enum — not just a `class`.
/// * `module_names` — every suffix of every declaration's
///   `module_path.segments`, joined with both `::` and `.` separators.
///   Alias targets spelled `crate::storage`, `storage`, or `app.storage`
///   therefore resolve with one hash lookup. Materialising the compiler's
///   module-name index once is crucial on large Java workspaces: scanning
///   every known module for every imported call turns callgraph construction
///   into quadratic work.
#[derive(Clone, Debug, Default)]
struct WorkspaceAliasIndex {
    class_names: ahash::AHashSet<String>,
    module_names: ahash::AHashSet<String>,
}

impl WorkspaceAliasIndex {
    fn build(global: &GlobalIndex) -> Self {
        let mut class_names: ahash::AHashSet<String> = ahash::AHashSet::default();
        let mut module_names: ahash::AHashSet<String> = ahash::AHashSet::default();
        for file in global.all_files() {
            for decl in global.decls_in(file) {
                if matches!(
                    decl.kind,
                    DeclKind::Class
                        | DeclKind::Struct
                        | DeclKind::Trait
                        | DeclKind::Interface
                        | DeclKind::Enum
                ) {
                    class_names.insert(decl.name.clone());
                }
                if !decl.module_path.is_empty() {
                    let segs = &decl.module_path.segments;
                    for start in 0..segs.len() {
                        let suffix = &segs[start..];
                        module_names.insert(suffix.join("."));
                    }
                }
            }
        }
        Self {
            class_names,
            module_names,
        }
    }

    fn contains(&self, module: &str, syntax: bonsai_lang_api::ModulePathSyntax) -> bool {
        let trimmed = module.trim();
        if trimmed.is_empty() {
            return false;
        }
        if self.class_names.contains(trimmed) {
            return true;
        }
        let stripped = strip_module_path_prefix(trimmed, syntax);
        let normalized = bonsai_common::normalize_qualified_name(trimmed);
        let normalized_stripped = bonsai_common::normalize_qualified_name(stripped);
        self.module_names.contains(&normalized) || self.module_names.contains(&normalized_stripped)
    }
}

/// True when `module` names something the workspace recognises —
/// either a known module path or a declared type / class name.
/// Memoised against a precomputed [`WorkspaceAliasIndex`] so the
/// short-tail gate is O(1) per call instead of O(decls). See the
/// index's docs for the rationale.
fn is_workspace_alias_target(
    idx: &WorkspaceAliasIndex,
    module: &str,
    syntax: bonsai_lang_api::ModulePathSyntax,
) -> bool {
    idx.contains(module, syntax)
}

/// True when `call_name` resolves to `target_func` from `caller_decl`'s
/// site context. Threads alias map + local callable bindings + global
/// resolver narrowing — same shape `inspect`'s chain-edge renderer
/// uses, exposed here so `bonsai_workspace::flow_ids` can answer the
/// same question without depending on `bonsai_inspect`.
///
/// Without this, syntactic `name == target || name.ends_with(".target")`
/// quietly drops aliased import calls — `from os.path import join as j;
/// j(req)` doesn't string-match `os.path.join`, so flow-id consumers
/// undercount chains while inspect renders them.
#[must_use]
pub fn call_resolves_to_func(
    global: &GlobalIndex,
    aliases: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    caller_decl: &Decl,
    call_name: &str,
    target_func: FuncId,
) -> bool {
    call_resolves_to_func_with_receiver(
        global,
        aliases,
        local_bindings,
        caller_decl,
        call_name,
        None,
        target_func,
    )
}

fn call_resolves_to_func_with_receiver(
    global: &GlobalIndex,
    aliases: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    caller_decl: &Decl,
    call_name: &str,
    receiver: Option<&str>,
    target_func: FuncId,
) -> bool {
    let short = short_qualified_tail(call_name);
    let alias_qualified_call = module_alias_target_qualified_name(call_name, aliases);
    if collect_local_callable_binding_targets(local_bindings, call_name, receiver, alias_qualified_call)
        .into_iter()
        .any(|func| func == target_func)
    {
        return true;
    }
    let mut candidates =
        collect_callable_targets_with_context_and_aliases(global, call_name, caller_decl, aliases);
    if candidates.is_empty() && short != call_name {
        candidates = collect_callable_targets_with_context_and_aliases(global, short, caller_decl, aliases);
    }
    candidates.contains(&target_func)
}

/// Walk `events` (recursing into Branch/Loop/Try/Defer/Using) and
/// return the span of the first `Call` (or `Assign::source_call`)
/// whose name resolves to `target_func`. Returns `None` when no
/// resolvable edge exists.
///
/// `aliases` is the caller's alias map (file-level imports + decl-
/// level type aliases + flow-event-extended aliases);
/// `local_bindings` is the result of [`collect_local_callable_bindings`].
#[must_use]
pub fn find_call_span_resolved(
    events: &[FlowEvent],
    target_func: FuncId,
    target_name: &str,
    global: &GlobalIndex,
    aliases: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    caller_decl: &Decl,
) -> Option<Span> {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                span,
                receiver,
                args,
                ..
            } if call_event_matches_target_func(
                name,
                receiver.as_deref(),
                args,
                target_func,
                target_name,
                global,
                aliases,
                local_bindings,
                caller_decl,
            ) =>
            {
                return Some(*span);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(span) = find_call_span_resolved(
                    then_events,
                    target_func,
                    target_name,
                    global,
                    aliases,
                    local_bindings,
                    caller_decl,
                ) {
                    return Some(span);
                }
                if let Some(span) = find_call_span_resolved(
                    else_events,
                    target_func,
                    target_name,
                    global,
                    aliases,
                    local_bindings,
                    caller_decl,
                ) {
                    return Some(span);
                }
            }
            FlowEvent::Loop { body, .. } => {
                if let Some(span) = find_call_span_resolved(
                    body,
                    target_func,
                    target_name,
                    global,
                    aliases,
                    local_bindings,
                    caller_decl,
                ) {
                    return Some(span);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(span) = find_call_span_resolved(
                    body,
                    target_func,
                    target_name,
                    global,
                    aliases,
                    local_bindings,
                    caller_decl,
                )
                .or_else(|| {
                    find_call_span_resolved(
                        catch_events,
                        target_func,
                        target_name,
                        global,
                        aliases,
                        local_bindings,
                        caller_decl,
                    )
                })
                .or_else(|| {
                    find_call_span_resolved(
                        finally_events,
                        target_func,
                        target_name,
                        global,
                        aliases,
                        local_bindings,
                        caller_decl,
                    )
                }) {
                    return Some(span);
                }
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(span) = find_call_span_resolved(
                    body,
                    target_func,
                    target_name,
                    global,
                    aliases,
                    local_bindings,
                    caller_decl,
                ) {
                    return Some(span);
                }
            }
            FlowEvent::Assign {
                source_call: Some(name),
                span,
                ..
            } if !assign_source_call_shadowed_by_explicit_call(events, name, *span)
                && call_resolves_to_func(global, aliases, local_bindings, caller_decl, name, target_func) =>
            {
                return Some(*span);
            }
            _ => {}
        }
    }
    None
}

#[allow(clippy::too_many_arguments)] // matches the per-call narrowing primitive
fn call_event_matches_target_func(
    name: &str,
    receiver: Option<&str>,
    args: &[CallArg],
    target_func: FuncId,
    _target_name: &str,
    global: &GlobalIndex,
    aliases: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    caller_decl: &Decl,
) -> bool {
    if call_resolves_to_func_with_receiver(
        global,
        aliases,
        local_bindings,
        caller_decl,
        name,
        receiver,
        target_func,
    ) {
        return true;
    }
    receiver.is_some()
        && args.iter().any(|arg| {
            call_resolves_to_func(
                global,
                aliases,
                local_bindings,
                caller_decl,
                arg.value_text.trim(),
                target_func,
            )
        })
}

#[cfg(test)]
mod tests;
